"""Bounded CIMD discovery. Original URL remains the TLS/HTTP identity.

Only the TCP destination is pinned to a vetted public address. No proxy,
redirect, shared client secret, stale fallback, or unauthenticated grant.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import timezone
from email.utils import parsedate_to_datetime
from functools import partial
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from urllib.parse import unquote, urlsplit

import certifi
import httpcore2
from mcp.shared.auth import OAuthClientInformationFull
from .oauth_diagnostics import note_lookup
from .metadata_cache import boot_session

MAX_DOCUMENT_BYTES = 16 * 1024
FETCH_SECONDS = 5
MAX_CACHE_SECONDS = 600
_DNS = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cimd-dns")


class MetadataFetchRejected(ValueError):
    """Safe rejection details; URL, body and headers are never retained."""
    def __init__(self, reason, http_status=None):
        messages = {'destination_rejected': 'Client metadata destination must be public',
            'ambiguous_headers': 'Ambiguous client metadata response headers',
            'http_status': 'Expected an uncompressed JSON metadata response',
            'content_type': 'Expected an uncompressed JSON metadata response',
            'content_encoding': 'Expected an uncompressed JSON metadata response',
            'size_limit': 'Client metadata too large'}
        super().__init__(messages.get(reason, 'Client metadata retrieval rejected'))
        self.reason, self.http_status = reason, http_status


class MetadataUnavailable(Exception):
    """Temporary discovery failure, never a grant or a valid stale client."""
    def __init__(self, reason):
        super().__init__('Client metadata temporarily unavailable')
        self.reason = reason


def tls_validation_failure(error):
    seen = set()
    for _ in range(8):
        if error is None or id(error) in seen:
            return False
        seen.add(id(error))
        if isinstance(error, ssl.SSLCertVerificationError):
            return True
        error = error.__cause__ or error.__context__
    return False


def temporary_resolution(lookup, detail):
    if lookup in {'cimd_timeout', 'cimd_network_error', 'cimd_pending_limit'}:
        return True
    status = detail.get('http_status')
    return (lookup == 'cimd_fetch_rejected' and detail.get('rejection') == 'http_status'
            and type(status) is int and (status == 429 or 500 <= status <= 599))


def metadata_url(value: str):
    if (not isinstance(value, str) or len(value) > 2048 or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value):
        raise ValueError("Invalid client metadata URL")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or "?" in value or "#" in value
            or parsed.path in {"", "/"} or "%" in parsed.hostname):
        raise ValueError("Client metadata requires an HTTPS document URL")
    if any(part in {".", ".."} for part in unquote(parsed.path).split("/")):
        raise ValueError("Client metadata URL contains a dot segment")
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("Invalid metadata port")
    return parsed


def public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_unspecified or address.is_loopback or address.is_link_local):
        return False
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            return public_address(str(address.ipv4_mapped))
        if address.sixtofour or address.teredo:
            return False
        if address in ipaddress.ip_network("64:ff9b::/96"):
            return public_address(str(ipaddress.IPv4Address(int(address) & 0xffffffff)))
    return True


class PublicBackend(httpcore2.AsyncNetworkBackend):
    """Resolve once, reject mixed/private answers, connect only to numeric IPs."""
    def __init__(self):
        self.backend = httpcore2.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        answers = await asyncio.get_running_loop().run_in_executor(_DNS,
            partial(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM))
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses or not all(public_address(address) for address in addresses):
            raise MetadataFetchRejected('destination_rejected')
        for address in addresses:
            try:
                return await self.backend.connect_tcp(address, port, timeout=timeout,
                    local_address=local_address, socket_options=socket_options)
            except (httpcore2.ConnectError, httpcore2.ConnectTimeout):
                continue
        raise httpcore2.ConnectError("Client metadata connection failed")

    async def connect_unix_socket(self, *args, **kwargs):
        raise ValueError("Unix sockets are not metadata destinations")

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate metadata field")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-JSON numeric constant")


def parse_client(document: bytes, client_id: str, scopes: list[str]):
    metadata_url(client_id)
    if len(document) > MAX_DOCUMENT_BYTES:
        raise ValueError("Client metadata too large")
    data = json.loads(document.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(data, dict) or data.get("client_id") != client_id:
        raise ValueError("Client metadata identity does not match its URL")
    name = data.get("client_name")
    if (not isinstance(name, str) or not name.strip() or len(name) > 200
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError("Client metadata requires a valid client name")
    name.encode("utf-8")
    if any(key in data for key in ("client_secret", "client_secret_expires_at", "client_id_issued_at")):
        raise ValueError("CIMD does not accept shared client credentials")
    # SEP-3149 transition: plural is the client's supported set; singular is
    # only a legacy preference. Choose none only when explicitly supported.
    methods = data.get("token_endpoint_auth_methods_supported")
    if methods is not None:
        if (not isinstance(methods, list) or not 1 <= len(methods) <= 8
                or not all(isinstance(x, str) for x in methods)
                or len(set(methods)) != len(methods) or "none" not in methods):
            raise ValueError("No supported CIMD token authentication method")
    elif data.get("token_endpoint_auth_method") != "none":
        raise ValueError("CIMD requires explicit public-client authentication")
    redirects = data.get("redirect_uris")
    if (not isinstance(redirects, list) or not 1 <= len(redirects) <= 10
            or not all(isinstance(uri, str) and len(uri) <= 2048 for uri in redirects)):
        raise ValueError("Invalid client redirect URIs")
    for uri in redirects:
        parsed = urlsplit(uri)
        if (parsed.username is not None or parsed.password is not None or parsed.fragment
                or not parsed.hostname or "\\" in uri or any(ord(c) <= 32 for c in uri)
                or not (parsed.scheme == "https" or parsed.scheme == "http"
                    and parsed.hostname in {"127.0.0.1", "localhost", "::1"})):
            raise ValueError("Redirects require HTTPS or loopback HTTP")
    grants = data.get("grant_types", ["authorization_code"])
    if (not isinstance(grants, list) or not 1 <= len(grants) <= 2
            or not all(isinstance(x, str) for x in grants) or len(set(grants)) != len(grants)
            or "authorization_code" not in grants
            or not all(x in {"authorization_code", "refresh_token"} for x in grants)):
        raise ValueError("Unsupported CIMD grant type")
    if data.get("response_types", ["code"]) != ["code"]:
        raise ValueError("Unsupported CIMD response type")
    client = OAuthClientInformationFull(client_id=client_id, client_name=name,
        redirect_uris=redirects, grant_types=grants, response_types=["code"],
        token_endpoint_auth_method="none", scope=" ".join(scopes))
    if [str(uri) for uri in client.redirect_uris] != redirects:
        raise ValueError("Redirect URIs must use canonical URL spelling")
    return client


def cache_seconds(headers: dict[str, str], *, now=None) -> float:
    control = headers.get("cache-control", "").lower()
    if any(x.split("=", 1)[0].strip() in {"no-store", "no-cache"} for x in control.split(",")):
        return 0
    if headers.get("vary", "").strip() == "*":
        return 0
    matches = re.findall(r'(?:^|,)\s*max-age\s*=\s*"?(\d+)"?(?=\s*,|$)', control)
    if len(matches) > 1 or not matches and any(x.split("=", 1)[0].strip() == "max-age" for x in control.split(",")):
        return 0
    match = matches[0] if matches else None
    if match:
        lifetime = min(int(match), MAX_CACHE_SECONDS)
    elif "expires" in headers:
        try:
            expires = parsedate_to_datetime(headers["expires"])
            lifetime = min(MAX_CACHE_SECONDS, (expires.replace(tzinfo=timezone.utc) if expires.tzinfo is None
                                               else expires).timestamp() - (time.time() if now is None else now))
        except (TypeError, ValueError, OverflowError):
            return 0
    else:
        lifetime = 60
    try:
        age = max(0, int(headers.get("age", "0")))
    except ValueError:
        return 0
    return max(0, lifetime - age)


async def fetch_document(client_id: str):
    metadata_url(client_id)
    context = ssl.create_default_context(cafile=certifi.where())
    async with httpcore2.AsyncConnectionPool(ssl_context=context, network_backend=PublicBackend(),
            max_connections=1, max_keepalive_connections=0, retries=0) as pool:
        async with pool.stream("GET", client_id,
                headers={"Accept": "application/json", "Accept-Encoding": "identity",
                         "User-Agent": "LocalWorkbench/0.1"},
                extensions={"timeout": {"connect": 3, "read": 3, "write": 3, "pool": 3}}) as response:
            headers = {}
            for key, value in response.headers:
                key, value = key.decode("ascii").lower(), value.decode("latin1")
                if key in headers and key in {"content-type", "content-encoding"}:
                    raise MetadataFetchRejected('ambiguous_headers', response.status)
                headers[key] = headers[key] + "," + value if key in headers else value
            if response.status != 200:
                raise MetadataFetchRejected('http_status', response.status)
            if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise MetadataFetchRejected('content_type', response.status)
            if headers.get("content-encoding", "identity").lower() != "identity":
                raise MetadataFetchRejected('content_encoding', response.status)
            body = bytearray()
            async for chunk in response.aiter_stream():
                body.extend(chunk)
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise MetadataFetchRejected('size_limit', response.status)
            return bytes(body), headers


class ClientMetadataResolver:
    def __init__(self, scopes, *, fetcher=fetch_document, cache_store=None,
                 boot_id=None, wall_clock=None, monotonic_clock=None):
        self.scopes, self.fetcher = list(scopes), fetcher
        self.cache = OrderedDict()
        self.cache_times = {}
        self.pending = {}
        self.slots = asyncio.Semaphore(4)
        self.cache_store = cache_store
        self.boot_id = (boot_id or boot_session()) if cache_store else None
        self.wall_clock = wall_clock or time.time
        self.monotonic_clock = monotonic_clock or time.monotonic
        self.restoration = None
        self.closed = False
        if self.cache_store:
            self.cache_store.attach()

    async def _restore(self):
        if not self.boot_id:
            return
        for record in await self.cache_store.load():
            try:
                cid = record['client_id']
                if record.get('schema_version') != 1 or record.get('boot_id') != self.boot_id:
                    continue
                fetched_wall, expires_wall = record['fetched_wall'], record['expires_wall']
                fetched_mono, expires_mono = record['fetched_mono'], record['expires_mono']
                values = [fetched_wall, expires_wall, fetched_mono, expires_mono]
                if any(type(v) not in {int, float} or not math.isfinite(v) for v in values):
                    continue
                wall, mono = self.wall_clock(), self.monotonic_clock()
                lifetime = expires_mono - fetched_mono
                if (not 0 < lifetime <= MAX_CACHE_SECONDS or fetched_wall > wall or fetched_mono > mono
                        or expires_wall <= wall or expires_mono <= mono
                        or abs((expires_wall - fetched_wall) - lifetime) > .001):
                    continue
                client = parse_client(json.dumps(record['document']).encode(), cid, self.scopes)
                self.cache[cid] = client, min(expires_mono, mono + expires_wall - wall)
                self.cache_times[cid] = fetched_wall, expires_wall, fetched_mono
                while len(self.cache) > 128:
                    removed, _ = self.cache.popitem(last=False)
                    self.cache_times.pop(removed, None)
            except (KeyError, ValueError, TypeError, UnicodeError, RecursionError):
                continue

    async def resolve(self, client_id: str, *, report_unavailable=False):
        if self.closed:
            raise RuntimeError('Client metadata resolver is closed')
        try:
            metadata_url(client_id)
        except ValueError:
            note_lookup('cimd_invalid_url')
            return None
        if self.cache_store and self.restoration is None:
            self.restoration = asyncio.create_task(self._restore())
        if self.restoration:
            await asyncio.shield(self.restoration)
        if self.closed:
            raise RuntimeError('Client metadata resolver is closed')
        cached = self.cache.get(client_id)
        clocks = self.cache_times.get(client_id)
        wall, mono = self.wall_clock(), self.monotonic_clock()
        clock_valid = (clocks is None or clocks[0] <= wall < clocks[1] and clocks[2] <= mono)
        if cached and cached[1] > mono and clock_valid:
            note_lookup('cimd_cache_hit')
            self.cache.move_to_end(client_id)
            return cached[0].model_copy(deep=True)
        if client_id not in self.pending:
            if len(self.pending) >= 16:
                note_lookup('cimd_pending_limit')
                if report_unavailable:
                    raise MetadataUnavailable('cimd_pending_limit')
                return None
            self.pending[client_id] = asyncio.create_task(self._load(client_id))
        result, lookup, detail = await asyncio.shield(self.pending[client_id])
        note_lookup(lookup, **detail)
        if report_unavailable and result is None and temporary_resolution(lookup, detail):
            raise MetadataUnavailable(lookup)
        return result.model_copy(deep=True) if result else None

    async def _load(self, client_id):
        phase = 'fetch'
        detail = {}
        try:
            async with asyncio.timeout(FETCH_SECONDS), self.slots:
                body, headers = await self.fetcher(client_id)
                mono, wall = self.monotonic_clock(), self.wall_clock()
            phase = 'parse'
            detail = {'http_status': 200}
            client = parse_client(body, client_id, self.scopes)
            lifetime = cache_seconds(headers, now=wall)
            if lifetime:
                self.cache[client_id] = client, mono + lifetime
                self.cache_times[client_id] = wall, wall + lifetime, mono
                self.cache.move_to_end(client_id)
                while len(self.cache) > 128:
                    removed, _ = self.cache.popitem(last=False)
                    self.cache_times.pop(removed, None)
                if self.cache_store and self.boot_id:
                    # Only normalized public fields, never opaque extensions
                    # or credentials, enter authenticated private persistence.
                    document = {k: getattr(client, k) for k in ['client_id', 'client_name',
                        'grant_types', 'response_types', 'token_endpoint_auth_method']}
                    document['redirect_uris'] = [str(uri) for uri in client.redirect_uris]
                    await self.cache_store.put(client_id, {'schema_version': 1,
                        'boot_id': self.boot_id, 'document': document,
                        'fetched_wall': wall, 'expires_wall': wall + lifetime,
                        'fetched_mono': mono, 'expires_mono': mono + lifetime})
            else:
                self.cache.pop(client_id, None)
                self.cache_times.pop(client_id, None)
                if self.cache_store:
                    await self.cache_store.remove(client_id)
            return client, 'cimd_fetched', detail
        except (ValueError, UnicodeError, OSError, TimeoutError, RecursionError, httpcore2.NetworkError,
                httpcore2.ProtocolError, httpcore2.TimeoutException) as error:
            # Errors/invalid documents are never cached, and stale data is not
            # returned on failure. Token admission distinguishes availability
            # from definite invalidity without consuming a grant.
            self.cache.pop(client_id, None)
            self.cache_times.pop(client_id, None)
            if self.cache_store:
                await self.cache_store.remove(client_id)
            lookup = ('cimd_tls_rejected' if tls_validation_failure(error) else
                'cimd_timeout' if isinstance(error, (TimeoutError, httpcore2.TimeoutException)) else
                'cimd_network_error' if isinstance(error, (OSError, httpcore2.NetworkError, httpcore2.ProtocolError)) else
                'cimd_fetch_rejected' if phase == 'fetch' else 'cimd_invalid_document')
            if isinstance(error, MetadataFetchRejected):
                detail = {'http_status': error.http_status, 'rejection': error.reason}
            return None, lookup, detail
        finally:
            self.pending.pop(client_id, None)

    async def close(self):
        if self.closed:
            return
        self.closed = True
        tasks = list(self.pending.values())
        if self.restoration and not self.restoration.done():
            tasks.append(self.restoration)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.cache_store:
            await self.cache_store.close()
