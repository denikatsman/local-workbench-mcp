"""Single-owner OAuth provider; MCP's SDK implements the protocol endpoints.

The owner secret is entered only in the explicit browser consent form. OAuth
codes and bearer tokens are stored as hashes; confidential client metadata is
encrypted with a key derived from that high-entropy owner secret.
"""
from __future__ import annotations

import base64
import asyncio
import hashlib
import hmac
import html
import json
import os
import secrets
import stat
import re
import sqlite3
import time
import threading
from contextlib import closing, contextmanager
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from cryptography.fernet import Fernet, InvalidToken
from pydantic import AnyHttpUrl
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
    OAuthAuthorizationServerProvider, RefreshToken, RegistrationError, TokenError,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .request_lifetime import RequestLifetime, SCOPE_KEY as _REQUEST_LIFETIME_SCOPE
from .client_metadata import ClientMetadataResolver, MetadataUnavailable
from .oauth_diagnostics import OAuthDiagnostics, note_authorize_client, note_grant, note_guard, note_lookup, note_token_fields

SCOPES = ["workbench.read", "workbench.write", "workbench.execute"]
_TOKEN_CLIENT = ContextVar('workbench_token_client_snapshot', default=None)


# Observation only: never consulted by authentication, dispatch or cancellation.
_mcp_cancel_receipt = ContextVar('workbench_mcp_cancel_receipt', default=None)
_MCP_CANCEL_SCOPE = 'local_workbench.cancel_receipt'


class MCPCancelDiagnostics(OAuthDiagnostics):
    """One locally armed, five-minute experiment; private bounded metadata only."""
    maximum_bytes = 65536

    def __init__(self, state_dir):
        super().__init__(state_dir)
        self.path = Path(state_dir) / 'mcp-cancel-diagnostic.jsonl'
        self.arm_path = Path(state_dir) / 'mcp-cancel-diagnostic-arm.json'
        self.salt = secrets.token_hex(16)
        self._write_lock = threading.Lock()

    def append(self, record):
        with self._write_lock:
            return super().append(record)

    def begin(self, body, headers):
        # Called only from body replay inside the SDK authenticated endpoint.
        from mcp.server.auth.middleware.auth_context import get_access_token
        try:
            access = get_access_token()
            if access is None:
                return None
            fd = os.open(self.arm_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 512):
                    return None
                arm = json.loads(os.read(fd, 513))
            finally:
                os.close(fd)
            expires = arm['expires_at']
            target = arm['request_id']
            if (type(expires) not in (int, float) or not 0 < expires - time.time() <= 300
                    or not isinstance(target, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}', target)):
                return None
            envelope = json.loads(body)
            if not isinstance(envelope, dict):
                return None
            params = envelope.get('params')
            if not isinstance(params, dict):
                return None
            method = envelope.get('method')
            if method == 'tools/call':
                args = params.get('arguments')
                if params.get('name') != 'native_app' or not isinstance(args, dict) or args.get('request_id') != target:
                    return None
                wire_id = envelope.get('id')
            elif method == 'notifications/cancelled':
                wire_id = params.get('requestId')
            else:
                return None
            def fingerprint(value):
                if type(value) not in (str, int) or len(str(value)) > 256:
                    return None
                return hashlib.sha256((self.salt + json.dumps(value)).encode()).hexdigest()
            protocol = headers.get(b'mcp-protocol-version', b'').decode('latin1')
            protocol = protocol if re.fullmatch(r'\d{4}-\d{2}-\d{2}', protocol) else 'absent_or_other'
            session = headers.get(b'mcp-session-id', b'').decode('latin1')
            record = {'instance': self.instance_id, 'exchange': secrets.token_hex(12), 'method': method, 'protocol_header': protocol,
                      'wire': fingerprint(wire_id), 'session': fingerprint(session) if session else None,
                      'principal': fingerprint(access.client_id)}
            if method == 'tools/call':
                record['request_id'] = target
            receipt = _MCPCancelReceipt(self, record, expires)
            receipt.note('authenticated_ingress')
            return receipt
        except Exception:
            return None  # Diagnostics must not change routing, effects or errors.


class _MCPCancelReceipt:
    def __init__(self, diagnostics, record, expires):
        self.diagnostics, self.record, self.expires = diagnostics, record, expires

    def note(self, stage, **fields):
        try:
            if time.time() <= self.expires:
                self.diagnostics.append({**self.record, 'at': time.time(), 'stage': stage, **fields})
        except Exception:
            pass


class _TokenClientResolution:
    def __init__(self, oauth, client_id, client):
        self.oauth, self.client_id, self.client = oauth, client_id, client
        self.active = True


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OwnerOAuth(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, state_dir: Path, public_url: str, owner_secret: str, *, oauth_discovery_mode='client_metadata'):
        from .config import OAUTH_DISCOVERY_MODES
        if type(oauth_discovery_mode) is not str or oauth_discovery_mode not in OAUTH_DISCOVERY_MODES:
            raise ValueError('Unknown OAuth discovery mode.')
        self.oauth_discovery_mode = oauth_discovery_mode
        parsed = urlsplit(public_url)
        if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}
                or (parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"})):
            raise ValueError("public-url must be an HTTPS origin (HTTP is allowed only on loopback).")
        if len(owner_secret) < 32:
            raise ValueError("The owner secret must contain at least 32 characters; generate a random secret.")
        self.issuer = str(AnyHttpUrl(public_url)).rstrip("/")
        self.resource = self.issuer + "/mcp"
        self.owner_hash = digest("owner verification\0" + owner_secret)
        self.fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(("client storage\0" + owner_secret).encode()).digest()))
        from .store import prepare_state
        prepare_state(state_dir)
        self.db_path = state_dir / "oauth.sqlite3"
        # Preserve the legacy realm and its connections. A different public
        # origin gets separate auth state rather than deleting previous grants.
        if self.db_path.exists():
            with closing(sqlite3.connect(self.db_path.resolve().as_uri() + "?mode=ro", uri=True)) as legacy:
                owner = legacy.execute("SELECT value FROM metadata WHERE key='owner'").fetchone()
                previous = legacy.execute("SELECT value FROM metadata WHERE key='issuer'").fetchone()
            if owner and not hmac.compare_digest(owner[0], self.owner_hash):
                raise ValueError("Owner secret differs from the existing OAuth state; use the original secret.")
            if previous and previous[0] != self.issuer:
                realms = state_dir / "oauth-issuers"
                realms.mkdir(mode=0o700, exist_ok=True)
                self.db_path = realms / (digest(self.issuer) + ".sqlite3")
        from .metadata_cache import MetadataCache
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, data BLOB NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS grants (
                    hash TEXT PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL,
                    expires REAL NOT NULL, family TEXT NOT NULL);
            """)
            if "created" not in {column[1] for column in db.execute("PRAGMA table_info(clients)")}:
                db.execute("ALTER TABLE clients ADD COLUMN created REAL NOT NULL DEFAULT 0")
            # Persist approval separately from short-lived grants, without a
            # schema change that would break an older server's client inserts.
            db.execute("INSERT OR IGNORE INTO metadata (key,value) SELECT 'approved:'||id,'1' FROM clients "
                       "WHERE id IN (SELECT json_extract(data, '$.client_id') FROM grants "
                       "WHERE kind IN ('code','access','refresh','spent_refresh'))")
            row = db.execute("SELECT value FROM metadata WHERE key='owner'").fetchone()
            if row and not hmac.compare_digest(row[0], self.owner_hash):
                raise ValueError("Owner secret differs from the existing OAuth state; use the original secret.")
            old_issuer = db.execute("SELECT value FROM metadata WHERE key='issuer'").fetchone()
            if old_issuer and old_issuer[0] != self.issuer:
                raise ValueError("OAuth state belongs to another issuer; preserve it for inspection.")
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('owner', ?)", (self.owner_hash,))
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('issuer', ?)", (self.issuer,))
            cache_generation = MetadataCache.begin_epoch(db)
        os.chmod(self.db_path, 0o600)
        self.client_metadata = ClientMetadataResolver(SCOPES,
            cache_store=MetadataCache(self.db_path, self.fernet, self.issuer, generation=cache_generation))
        self.diagnostics = OAuthDiagnostics(self.db_path.parent)

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.db_path, timeout=10)) as db:
            with db:
                db.execute("PRAGMA busy_timeout=10000")
                yield db

    def settings(self) -> AuthSettings:
        return AuthSettings(
            issuer_url=self.issuer, resource_server_url=self.resource,
            validate_token_resource=True, required_scopes=["workbench.read"],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=SCOPES, default_scopes=SCOPES),
            revocation_options=RevocationOptions(enabled=True),
        )

    def authorization_metadata(self):
        from mcp.server.auth.routes import build_metadata
        settings = self.settings()
        metadata = build_metadata(settings.issuer_url, settings.service_documentation_url,
            settings.client_registration_options, settings.revocation_options).model_dump(mode="json", exclude_none=True)
        metadata.update(issuer=self.issuer, client_id_metadata_document_supported=True,
                        authorization_response_iss_parameter_supported=True,
                        token_endpoint_auth_methods_supported=["none", "client_secret_post", "client_secret_basic"],
                        revocation_endpoint_auth_methods_supported=["none", "client_secret_post", "client_secret_basic"])
        # Discovery preference only: existing URL clients/grants still use the
        # unchanged resolver. Registration is not consent or a token grant.
        if self.oauth_discovery_mode == 'dynamic_registration':
            metadata.pop('client_id_metadata_document_supported')
        return metadata

    async def get_client(self, client_id: str, *, report_unavailable=False):
        note_authorize_client(client_id)
        snapshot = _TOKEN_CLIENT.get()
        if snapshot is not None and snapshot.active and snapshot.oauth is self and snapshot.client_id == client_id:
            return snapshot.client.model_copy(deep=True) if snapshot.client is not None else None
        with self.db() as db:
            row = db.execute("SELECT data FROM clients WHERE id=?", (client_id,)).fetchone()
        if not row:
            return await self.client_metadata.resolve(client_id, report_unavailable=report_unavailable)
        try:
            client = OAuthClientInformationFull.model_validate_json(self.fernet.decrypt(row[0]))
            note_lookup('stored_client')
            return client
        except InvalidToken:
            note_lookup('stored_decryption_failed')
            return None

    async def register_client(self, client_info: OAuthClientInformationFull):
        if client_info.token_endpoint_auth_method not in {"none", "client_secret_post", "client_secret_basic"}:
            raise RegistrationError("invalid_client_metadata", "Unsupported token authentication method.")
        if not client_info.redirect_uris or len(client_info.redirect_uris) > 10:
            raise RegistrationError("invalid_redirect_uri", "Register between one and ten redirect URIs.")
        for uri in client_info.redirect_uris:
            parsed = urlsplit(str(uri))
            if (parsed.fragment or parsed.username or parsed.password or not parsed.hostname
                    or not (parsed.scheme == "https" or
                            parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"})):
                raise RegistrationError("invalid_redirect_uri", "Redirects require HTTPS or loopback HTTP.")
        # DCR describes what the client may REQUEST, not what the owner has
        # granted. Return the assigned scope set so a read-first registration
        # can later request write/execute through a new, explicit consent flow.
        # Token scopes below remain exactly those approved by the owner.
        client_info.scope = " ".join(SCOPES)
        capacity_reached = False
        with self.db() as db:
            db.execute("DELETE FROM grants WHERE expires <= ?", (time.time(),))
            if db.execute("SELECT count(*) FROM clients").fetchone()[0] >= 200:
                # Never evict a client with pending consent or a live authorization.
                # Unused public registrations must not permanently fill the registry.
                db.execute("DELETE FROM clients WHERE id IN (SELECT c.id FROM clients c WHERE NOT EXISTS "
                           "(SELECT 1 FROM metadata m WHERE m.key='approved:'||c.id) AND NOT EXISTS "
                           "(SELECT 1 FROM grants g WHERE json_extract(g.data, '$.client_id')=c.id) "
                           "ORDER BY created LIMIT 1)")
                capacity_reached = db.execute("SELECT count(*) FROM clients").fetchone()[0] >= 200
            if capacity_reached:
                # Preserve rejection rollback, but raise the frozen SDK error
                # outside the generator context manager.
                db.rollback()
            else:
                db.execute("INSERT INTO clients (id,data,created) VALUES (?, ?, ?)",
                           (client_info.client_id, self.fernet.encrypt(client_info.model_dump_json().encode()), time.time()))
        if capacity_reached:
            raise RegistrationError("invalid_client_metadata", "Local active-client capacity reached.")

    def _insert(self, db, raw: str, kind: str, data: dict, expires: float, family=""):
        db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, ?)",
                   (digest(raw), kind, json.dumps(data), expires, family))

    def _load(self, raw: str, kind: str):
        with self.db() as db:
            row = db.execute("SELECT data, expires, family FROM grants WHERE hash=? AND kind=?",
                             (digest(raw), kind)).fetchone()
        if not row or row[1] <= time.time():
            return None
        return json.loads(row[0]), row[1], row[2]

    async def authorize(self, client, params: AuthorizationParams):
        if params.resource != self.resource:
            raise AuthorizeError("invalid_target", "Use the exact MCP resource URL.")
        if not params.scopes or not set(params.scopes) <= set(SCOPES) or "workbench.read" not in params.scopes:
            raise AuthorizeError("invalid_scope", "A supported scope including workbench.read is required.")
        ticket = secrets.token_urlsafe(32)
        capacity_reached = False
        with self.db() as db:
            db.execute("DELETE FROM grants WHERE expires <= ?", (time.time(),))
            capacity_reached = db.execute("SELECT count(*) FROM grants WHERE kind='pending'").fetchone()[0] >= 100
            if capacity_reached:
                db.rollback()
            else:
                self._insert(db, ticket, "pending", {
                    "client_id": client.client_id, "client_name": client.client_name or client.client_id,
                    "params": params.model_dump(mode="json"), "csrf": secrets.token_urlsafe(32),
                }, time.time() + 300)
        if capacity_reached:
            raise AuthorizeError("temporarily_unavailable", "Too many pending consent requests.")
        return self.issuer + "/consent?" + urlencode({"ticket": ticket})

    async def consent(self, request: Request):
        if request.method == "GET":
            ticket = request.query_params.get("ticket", "")
            pending = self._load(ticket, "pending")
            if not pending:
                return HTMLResponse("Consent request expired. Start linking again.", status_code=400)
            data = pending[0]
            scopes = data["params"]["scopes"]
            execution = ("<p><strong>Commands run as your macOS user, with access beyond the configured "
                         "workspace. This is not a sandbox.</strong></p>" if "workbench.execute" in scopes else "")
            body = f"""<!doctype html><meta charset="utf-8"><title>Connect Local Workbench</title>
<meta name="viewport" content="width=device-width"><style>body{{font:16px system-ui;max-width:42rem;margin:3rem auto;padding:1rem}}input{{width:100%;padding:.6rem;box-sizing:border-box}}button{{padding:.7rem;margin-top:1rem}}</style>
<h1>Connect Local Workbench</h1><p>Approve access for <strong>{html.escape(data['client_name'])}</strong>.</p>
<p>Client identifier: <code>{html.escape(data['client_id'])}</code></p>
<p>Requested permissions: {html.escape(', '.join(scopes))}.</p>{execution}
<p>Return address: <code>{html.escape(data['params']['redirect_uri'])}</code></p>
<p>Enter the owner secret configured on your computer. Never paste it into a chat.</p>
<form method="post" action="/consent"><input type="hidden" name="ticket" value="{html.escape(ticket)}">
<input type="hidden" name="csrf" value="{html.escape(data['csrf'])}">
<label>Owner secret<input type="password" name="secret" required autocomplete="off"></label>
<button name="decision" value="approve">Approve connection</button> <button name="decision" value="deny" formnovalidate>Deny</button></form>"""
            return HTMLResponse(body, headers=self._browser_headers(data['params']['redirect_uri']))
        form = await request.form()
        ticket = str(form.get("ticket", ""))
        pending = self._load(ticket, "pending")
        if not pending or not hmac.compare_digest(str(form.get("csrf", "")).encode(), pending[0]["csrf"].encode()):
            return HTMLResponse("Invalid or expired consent request.", status_code=400, headers=self._browser_headers())
        data = pending[0]
        params = AuthorizationParams.model_validate(data["params"])
        if form.get("decision") == "deny":
            with self.db() as db:
                db.execute("DELETE FROM grants WHERE hash=?", (digest(ticket),))
            return self._redirect(params, error="access_denied")
        if form.get("decision") != "approve":
            return HTMLResponse("Choose approve or deny.", status_code=400, headers=self._browser_headers())
        if not hmac.compare_digest(digest("owner verification\0" + str(form.get("secret", ""))), self.owner_hash):
            return HTMLResponse("Incorrect owner secret.", status_code=403, headers=self._browser_headers())
        code = secrets.token_urlsafe(32)
        record = AuthorizationCode(
            code="", client_id=data["client_id"], scopes=params.scopes or [], expires_at=time.time() + 120,
            code_challenge=params.code_challenge, redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=self.resource, subject="owner",
        )
        with self.db() as db:
            if db.execute("DELETE FROM grants WHERE hash=? AND kind='pending'", (digest(ticket),)).rowcount != 1:
                return HTMLResponse("Consent already used.", status_code=400)
            self._insert(db, code, "code", record.model_dump(mode="json", exclude={"code"}), record.expires_at)
            db.execute("INSERT OR IGNORE INTO metadata (key,value) SELECT 'approved:'||id,'1' "
                       "FROM clients WHERE id=?", (data["client_id"],))
        return self._redirect(params, code=code)

    @staticmethod
    def _browser_headers(redirect_uri: str | None = None):
        form_targets = "'self'"
        if redirect_uri:
            # Browsers also enforce form-action on the POST's redirect chain.
            # Permit only this registered callback's origin, never a wildcard.
            # Quote netloc characters so client metadata cannot inject CSP.
            callback = urlsplit(redirect_uri)
            form_targets += f" {callback.scheme}://{quote(callback.netloc, safe='[]:.-')}"
        # no-referrer makes navigation-mode form POSTs send Origin: null, which
        # our origin guard correctly rejects. strict-origin retains the origin
        # while withholding the consent ticket in the path/query string.
        return {"Cache-Control": "no-store", "Referrer-Policy": "strict-origin", "X-Frame-Options": "DENY",
                "Content-Security-Policy": f"default-src 'none'; style-src 'unsafe-inline'; form-action {form_targets}; frame-ancestors 'none'"}

    def _redirect(self, params, **values):
        if params.state is not None:
            values["state"] = params.state
        values["iss"] = self.issuer
        parsed = urlsplit(str(params.redirect_uri))
        query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key not in values]
        query.extend((key, value) for key, value in values.items() if value is not None)
        return RedirectResponse(urlunsplit(parsed._replace(query=urlencode(query))), status_code=302,
                                headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    async def load_authorization_code(self, client, authorization_code):
        row = self._load(authorization_code, "code")
        if not row or row[0]["client_id"] != client.client_id:
            return None
        return AuthorizationCode(code=authorization_code, **row[0])

    def _issue(self, db, client_id, scopes, family=None, *, allow_refresh=True):
        family = family or secrets.token_hex(16)
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        common = {"client_id": client_id, "scopes": scopes, "resource": self.resource, "subject": "owner"}
        self._insert(db, access, "access", common, int(time.time()) + 900, family)
        if allow_refresh:
            self._insert(db, refresh, "refresh", common, int(time.time()) + 30 * 86400, family)
        return OAuthToken(access_token=access, refresh_token=refresh if allow_refresh else None,
                          expires_in=900, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client, authorization_code):
        issued = None
        with self.db() as db:
            count = db.execute("DELETE FROM grants WHERE hash=? AND kind='code' AND expires>?",
                               (digest(authorization_code.code), time.time())).rowcount
            if count == 1:
                issued = self._issue(db, client.client_id, authorization_code.scopes,
                                     allow_refresh="refresh_token" in client.grant_types)
        # SDK TokenError is frozen: raise outside the generator context manager,
        # which may otherwise try to assign its traceback and mask the error.
        if issued is None:
            note_grant('authorization_code_unknown_expired_consumed')
            raise TokenError("invalid_grant", "Code expired or already consumed.")
        note_grant('authorization_code_exchanged_committed')
        return issued

    async def load_refresh_token(self, client, refresh_token):
        row = self._load(refresh_token, "refresh")
        if not row or row[0]["client_id"] != client.client_id:
            spent = self._load(refresh_token, "spent_refresh")
            if spent and spent[0]["client_id"] == client.client_id:
                # A second use can be a stolen predecessor: revoke its descendants.
                with self.db() as db:
                    db.execute("DELETE FROM grants WHERE family=?", (spent[2],))
                note_grant('refresh_replay_family_revoked')
            else:
                note_grant('refresh_unknown_expired')
            return None
        note_grant('refresh_found')
        return RefreshToken(token=refresh_token, expires_at=int(row[1]), **row[0])

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        issued, replay = None, False
        with self.db() as db:
            # Serialize the read/consume/replay decision across provider instances.
            # No network or other awaited work occurs while holding this lock.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT family FROM grants WHERE hash=? AND kind='refresh' AND expires>? "
                             "AND json_extract(data, '$.client_id')=?",
                             (digest(refresh_token.token), time.time(), client.client_id)).fetchone()
            if row is None:
                spent = db.execute("SELECT family FROM grants WHERE hash=? AND kind='spent_refresh' AND expires>? "
                                   "AND json_extract(data, '$.client_id')=?",
                                   (digest(refresh_token.token), time.time(), client.client_id)).fetchone()
                if spent:
                    # Another authenticated request may have loaded this token
                    # before its predecessor was consumed. Revoke on that replay
                    # just as load_refresh_token does, and commit before rejecting.
                    db.execute("DELETE FROM grants WHERE family=?", (spent[0],))
                    replay = True
            elif db.execute("DELETE FROM grants WHERE hash=? AND kind='refresh'",
                            (digest(refresh_token.token),)).rowcount == 1:
                # Normal rotation preserves still-valid access; security replay
                # and explicit revocation still remove the complete family.
                db.execute("DELETE FROM grants WHERE family=? AND kind!='spent_refresh' "
                           "AND (kind!='access' OR expires<=?)", (row[0], time.time()))
                self._insert(db, refresh_token.token, "spent_refresh",
                             {"client_id": client.client_id}, refresh_token.expires_at, row[0])
                issued = self._issue(db, client.client_id, scopes, row[0])
        if issued is None:
            note_grant('refresh_replay_family_revoked' if replay else 'refresh_already_consumed')
            raise TokenError("invalid_grant", "Refresh token expired or already consumed.")
        note_grant('refresh_rotated_committed')
        return issued

    async def load_access_token(self, token):
        row = self._load(token, "access")
        if not row or row[0].get("resource") != self.resource:
            return None
        return AccessToken(token=token, expires_at=int(row[1]), **row[0])

    async def revoke_token(self, token):
        with self.db() as db:
            db.execute("DELETE FROM grants WHERE family IN (SELECT family FROM grants WHERE hash=?)",
                       (digest(token.token),))


class HTTPGuard:
    """Bound auth bodies and validate audience fields the SDK provider does not see."""
    def __init__(self, app: ASGIApp, oauth: OwnerOAuth, port: int):
        self.app, self.oauth = app, oauth
        self.cancel_diagnostics = MCPCancelDiagnostics(oauth.db_path.parent)
        self.hosts = {urlsplit(oauth.issuer).netloc, f"127.0.0.1:{port}", f"localhost:{port}"}
        self.origins = {oauth.issuer, f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        self.rate: dict[str, tuple[int, float]] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        return await self.oauth.diagnostics.run(self._handle, scope, receive, send)

    async def _handle(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        host = headers.get(b"host", b"").decode("latin1")
        origin = headers.get(b"origin", b"").decode("latin1")
        if host not in self.hosts or origin and origin not in self.origins:
            return await JSONResponse({"error": "untrusted_origin"}, status_code=403)(scope, receive, send)
        if scope["path"] == "/.well-known/oauth-authorization-server" and scope["method"] == "GET":
            return await JSONResponse(self.oauth.authorization_metadata(),
                headers={"Cache-Control": "public, max-age=60"})(scope, receive, send)

        async def issuer_send(message):
            # SDK error redirects lack RFC9207 iss. Add it to callback responses
            # while leaving the internal consent navigation unchanged.
            if (scope["path"] == "/authorize" and message["type"] == "http.response.start"
                    and message["status"] in {302, 303}):
                updated = []
                for key, value in message["headers"]:
                    if key.lower() == b"location":
                        location = value.decode("latin1")
                        parsed = urlsplit(location)
                        query = parse_qsl(parsed.query, keep_blank_values=True)
                        internal = (location.startswith(self.oauth.issuer + "/consent?")
                                    and {k for k, _ in query} == {"ticket"})
                        if not internal:
                            query = [(k, v) for k, v in query if k != "iss"] + [("iss", self.oauth.issuer)]
                            value = urlunsplit(parsed._replace(query=urlencode(query))).encode("latin1")
                    updated.append((key, value))
                message = {**message, "headers": updated}
            await send(message)
        auth_path = scope["path"] in {"/token", "/register", "/consent", "/authorize", "/revoke"}
        if auth_path or scope["path"] == "/mcp" and scope["method"] == "POST":
            # Global per-route budget is intentional: tunnel peer IP is not the end user's identity.
            now = time.monotonic()
            key = scope["path"]
            count, started = self.rate.get(key, (0, now))
            if now - started >= 60:
                count, started = 0, now
            self.rate[key] = count + 1, started
            if auth_path and count >= 60:
                return await JSONResponse({"error": "rate_limited"}, status_code=429,
                                          headers={"Retry-After": "60"})(scope, receive, send)
            body = bytearray()
            limit = 65536 if auth_path else 4 * 1024 * 1024
            try:
                async with asyncio.timeout(30):
                    while True:
                        event = await receive()
                        if event["type"] == "http.disconnect":
                            return
                        body.extend(event.get("body", b""))
                        if len(body) > limit:
                            return await JSONResponse({"error": "request_too_large"}, status_code=413)(scope, receive, send)
                        if not event.get("more_body"):
                            break
            except TimeoutError:
                return await JSONResponse({"error": "request_timeout"}, status_code=408)(scope, receive, send)
            if scope["path"] == "/authorize":
                raw = scope.get("query_string", b"") if scope["method"] == "GET" else bytes(body)
                if len(raw) > 16384:
                    return await JSONResponse({"error": "invalid_request"}, status_code=400)(scope, receive, send)
                fields = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
                if any(len(values) != 1 for values in fields.values()):
                    return await JSONResponse({"error": "invalid_request"}, status_code=400)(scope, receive, send)
                if "client_id" in fields and "redirect_uri" in fields:
                    client = await self.oauth.get_client(fields["client_id"][0])
                    if client and fields["redirect_uri"][0] not in [str(uri) for uri in client.redirect_uris or []]:
                        return await JSONResponse({"error": "invalid_request"}, status_code=400)(scope, receive, send)
            if scope["path"] in {"/token", "/revoke"}:
                if not headers.get(b"content-type", b"").lower().startswith(b"application/x-www-form-urlencoded"):
                    return await JSONResponse({"error": "invalid_request"}, status_code=415)(scope, receive, send)
                fields = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
                if scope["path"] == "/token":
                    note_token_fields(fields, headers.get(b"authorization", b""))
                if any(len(values) != 1 for values in fields.values()):
                    return await JSONResponse({"error": "invalid_request"}, status_code=400)(scope, receive, send)
                if "resource" in fields and fields["resource"] != [self.oauth.resource]:
                    return await JSONResponse({"error": "invalid_target"}, status_code=400)(scope, receive, send)
                # SDK 2.2.0 requires form client_id even for RFC6749 Basic auth.
                # Supply only its decoded ID; the SDK still verifies the secret.
                authorization = headers.get(b"authorization", b"")
                if authorization.startswith(b"Basic "):
                    try:
                        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
                        basic_id, _ = decoded.split(":", 1)
                        basic_id = unquote(basic_id)
                    except (ValueError, UnicodeDecodeError):
                        note_guard('basic_malformed')
                        return await JSONResponse({"error": "invalid_client"}, status_code=401)(scope, receive, send)
                    if "client_id" in fields and fields["client_id"] != [basic_id]:
                        note_guard('basic_client_mismatch')
                        return await JSONResponse({"error": "invalid_client"}, status_code=401)(scope, receive, send)
                    fields["client_id"] = [basic_id]
                    if scope["path"] == "/token":
                        note_token_fields(fields, authorization)
                client_id = fields.get("client_id", [""])[0]
                if client_id.lower().startswith("https://") and (authorization
                        or fields.get("client_secret", [""])[0]
                        or "client_assertion" in fields or "client_assertion_type" in fields):
                    note_guard('cimd_credentials_forbidden')
                    return await JSONResponse({"error": "invalid_client"}, status_code=401)(scope, receive, send)
                if scope["path"] == "/token" and fields.get("grant_type") == ["authorization_code"]:
                    code = self.oauth._load(fields.get("code", [""])[0], "code")
                    if code and code[0]["client_id"] == client_id:
                        expected = code[0]["redirect_uri"] if code[0]["redirect_uri_provided_explicitly"] else None
                        if fields.get("redirect_uri", [None])[0] != expected:
                            return await JSONResponse({"error": "invalid_grant"}, status_code=400)(scope, receive, send)
                # SDK 2.2.0's revoke model has no default for optional client_secret.
                if scope["path"] == "/revoke":
                    fields.setdefault("client_secret", [""])
                body = bytearray(urlencode(fields, doseq=True).encode())
                scope = dict(scope)
                scope["headers"] = [(k, v) for k, v in scope["headers"] if k != b"content-length"] + [
                    (b"content-length", str(len(body)).encode())]
            delivered = False
            cancel_receipt = None
            lifetime = RequestLifetime() if scope['path'] == '/mcp' else None
            if lifetime is not None:
                scope[_REQUEST_LIFETIME_SCOPE] = lifetime
            async def diagnostic_send(message):
                if cancel_receipt is not None and message['type'] == 'http.response.start':
                    cancel_receipt.note('http_result', status=message['status'])
                await issuer_send(message)
            async def replay():
                nonlocal delivered, cancel_receipt
                if not delivered:
                    delivered = True
                    if scope['path'] == '/mcp':
                        cancel_receipt = self.cancel_diagnostics.begin(bytes(body), headers)
                        if cancel_receipt is not None:
                            scope[_MCP_CANCEL_SCOPE] = cancel_receipt
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                if lifetime is not None:
                    await lifetime.disconnected.wait()
                    return {'type': 'http.disconnect'}
                return await receive()
            if scope['path'] == '/token' and scope['method'] == 'POST' and fields.get('client_id', [''])[0]:
                # Resolve before entering Starlette's general500 handler. A
                # request-scoped snapshot lets the SDK still authenticate the
                # exact form client/secret once, including no-store metadata,
                # without a second network fetch or cross-request fallback.
                client_id = fields['client_id'][0]
                try:
                    client = await self.oauth.get_client(client_id, report_unavailable=True)
                except MetadataUnavailable:
                    response = JSONResponse({'error': 'temporarily_unavailable'}, status_code=503,
                        headers={'Retry-After': '2', 'Cache-Control': 'no-store'})
                    # Same token-route CORS policy as the installed SDK. The
                    # outer origin allowlist has already accepted this request.
                    return await CORSMiddleware(response, allow_origins=['*'],
                        allow_methods=['POST', 'OPTIONS'], allow_headers=['MCP-Protocol-Version'])(scope, replay, issuer_send)
                snapshot = _TokenClientResolution(self.oauth, client_id, client)
                token = _TOKEN_CLIENT.set(snapshot)
                try:
                    return await self.app(scope, replay, issuer_send)
                finally:
                    # Tasks inherit context values. Retire the shared admission
                    # before resetting this caller so an inherited child cannot
                    # reuse no-store metadata after the request has ended.
                    snapshot.active = False
                    _TOKEN_CLIENT.reset(token)
            def observed_disconnect():
                if cancel_receipt is not None:
                    cancel_receipt.note('http_disconnect')
            watcher = asyncio.create_task(lifetime.watch(receive, observed_disconnect)) if lifetime is not None else None
            try:
                return await self.app(scope, replay, diagnostic_send)
            finally:
                if lifetime is not None:
                    lifetime.close()
                    watcher.cancel()
                    try:
                        await watcher
                    except asyncio.CancelledError:
                        pass
                if cancel_receipt is not None:
                    cancel_receipt.note('http_handler_exit')
        return await self.app(scope, receive, issuer_send)
