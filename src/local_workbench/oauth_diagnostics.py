"""Bounded, private OAuth receipts. Diagnostics never decide authorization."""
from contextlib import contextmanager
from contextvars import ContextVar
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

_CURRENT = ContextVar('workbench_oauth_diagnostic', default=None)
LOOKUPS = frozenset({'stored_client', 'stored_decryption_failed', 'cimd_invalid_url',
    'cimd_cache_hit', 'cimd_pending_limit', 'cimd_fetched', 'cimd_fetch_rejected',
    'cimd_invalid_document', 'cimd_timeout', 'cimd_network_error', 'cimd_tls_rejected'})
ERRORS = frozenset({'invalid_client', 'invalid_grant', 'invalid_request', 'invalid_scope',
    'unsupported_grant_type', 'invalid_target', 'unauthorized_client', 'server_error',
    'temporarily_unavailable', 'rate_limited', 'untrusted_origin', 'request_timeout', 'request_too_large'})
DESCRIPTIONS = {
    'Missing client_id': 'missing_client_id', 'Invalid client_id': 'invalid_client_id',
    'Client secret is required': 'missing_client_secret', 'Invalid client_secret': 'invalid_client_secret',
    'Client secret has expired': 'expired_client_secret',
    'Missing or invalid Basic authentication in Authorization header': 'basic_required',
    'Invalid Basic authentication header': 'invalid_basic',
    'Client ID mismatch in Basic auth': 'basic_client_mismatch',
    'Client is registered for secret-based authentication but has no stored secret': 'stored_secret_missing',
}


def note_lookup(state, *, http_status=None, rejection=None):
    current = _CURRENT.get()
    if current is not None and state in LOOKUPS:
        rows = current.setdefault('client_lookup', [])
        if len(rows) < 4:
            rows.append(state)
        if type(http_status) is int and 100 <= http_status <= 599:
            current['metadata_http_status'] = http_status
        if rejection in {'http_status', 'content_type', 'content_encoding', 'ambiguous_headers',
                         'size_limit', 'destination_rejected'}:
            current['metadata_rejection'] = rejection


def note_authorize_client(client_id):
    """Provider lookup identity only; never inspect authorization parameters."""
    current = _CURRENT.get()
    if current is None or current.get('endpoint') != '/authorize':
        return
    if not isinstance(client_id, str) or len(client_id) > 16384:
        return
    try:
        identity = hashlib.sha256(client_id.encode('utf-8')).hexdigest()
    except (UnicodeError, ValueError):
        return
    current.setdefault('client_id_sha256', identity)


def note_token_fields(fields, authorization):
    current = _CURRENT.get()
    if current is None:
        return
    client_ids = fields.get('client_id', [])
    current['client_id_sha256'] = (hashlib.sha256(client_ids[0].encode()).hexdigest()
                                   if len(client_ids) == 1 else None)
    grant = fields.get('grant_type', [])
    current['grant_type'] = grant[0] if len(grant) == 1 and grant[0] in {
        'authorization_code', 'refresh_token', 'client_credentials'} else 'missing_or_other'
    current['authorization_scheme'] = ('none' if not authorization else
        'basic' if authorization.startswith(b'Basic ') else
        'bearer' if authorization.startswith(b'Bearer ') else 'other')
    current['client_secret_present'] = any(bool(x) for x in fields.get('client_secret', []))
    current['assertion_present'] = 'client_assertion' in fields or 'client_assertion_type' in fields


def note_guard(reason):
    current = _CURRENT.get()
    if current is not None and reason in {'basic_malformed', 'basic_client_mismatch', 'cimd_credentials_forbidden'}:
        current['guard_rejection'] = reason


def note_grant(stage):
    current = _CURRENT.get()
    if current is not None and stage in {'authorization_code_unknown_expired_consumed',
        'authorization_code_exchanged_committed', 'refresh_found', 'refresh_unknown_expired',
        'refresh_replay_family_revoked', 'refresh_already_consumed', 'refresh_rotated_committed'}:
        rows = current.setdefault('grant_stages', [])
        if len(rows) < 4:
            rows.append(stage)


class OAuthDiagnostics:
    maximum_bytes = 1024 * 1024

    def __init__(self, state_dir):
        self.path = Path(state_dir) / 'oauth-diagnostics.jsonl'
        self.last_write_success = None
        self.instance_id = uuid.uuid4().hex

    def append(self, record):
        # Only bounded closed-vocabulary fields reach here. Preserve old evidence
        # when full; no automatic rotation/deletion and no auth dependency on I/O.
        encoded = json.dumps(record, separators=(',', ':'), sort_keys=True).encode() + b'\n'
        if len(encoded) > 2048:
            return False
        import fcntl
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_nlink != 1 or info.st_mode & 0o077
                        or info.st_size + len(encoded) > self.maximum_bytes):
                    return False
                return os.write(fd, encoded) == len(encoded)
            finally:
                os.close(fd)
        except OSError:
            return False

    @contextmanager
    def trace(self, endpoint='/token'):
        if endpoint not in {'/token', '/authorize'}:
            raise ValueError('Unsupported diagnostic endpoint')
        record = {'schema_version': 1, 'trace_id': uuid.uuid4().hex,
                  'diagnostic_instance_id': self.instance_id, 'pid': os.getpid(),
                  'started_at': time.time(), 'endpoint': endpoint}
        started = time.monotonic()
        token = _CURRENT.set(record)
        try:
            yield record
        finally:
            _CURRENT.reset(token)
            record['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
            record['finished_at'] = time.time()
            try:
                self.last_write_success = self.append(record)
            except Exception:
                self.last_write_success = False

    async def run(self, handler, scope, receive, send):
        if scope['type'] != 'http' or scope['path'] not in {'/token', '/authorize'}:
            return await handler(scope, receive, send)
        with self.trace(scope['path']) as record:
            error_body = bytearray()
            oversized = False
            async def observe_receive():
                message = await receive()
                if message['type'] == 'http.disconnect':
                    record['request_disconnected'] = True
                return message
            async def observe_send(message):
                nonlocal oversized
                if message['type'] == 'http.response.start':
                    record['status'] = message['status']
                elif message['type'] == 'http.response.body':
                    # Success bodies contain credentials: never copy them.
                    # Authorization errors can echo state/client/redirect data.
                    # Never copy or parse any authorize body, success or error.
                    if record['endpoint'] == '/token' and record.get('status', 0) >= 400 and not oversized:
                        chunk = message.get('body', b'')
                        if len(error_body) + len(chunk) > 4096:
                            error_body.clear(); oversized = True
                        else:
                            error_body.extend(chunk)
                try:
                    await send(message)
                except Exception:
                    record['response_send_failed'] = True
                    raise
                if message['type'] == 'http.response.start':
                    record['response_started'] = True
                elif message['type'] == 'http.response.body' and not message.get('more_body'):
                    record['response_complete'] = True
            try:
                result = await handler(scope, observe_receive, observe_send)
                record['handler_outcome'] = 'returned'
                return result
            except asyncio.CancelledError:
                record['handler_outcome'] = 'caller_cancelled'
                raise
            except Exception:
                record['handler_outcome'] = 'exception'
                raise
            finally:
                if error_body and not oversized:
                    try:
                        value = json.loads(error_body)
                        if isinstance(value, dict):
                            code = value.get('error')
                            record['oauth_error'] = code if isinstance(code, str) and code in ERRORS else 'other'
                            description = value.get('error_description')
                            record['error_description_category'] = (DESCRIPTIONS.get(description, 'other')
                                if isinstance(description, str) else 'absent')
                    except (ValueError, RecursionError):
                        record['oauth_error'] = 'unparseable'
