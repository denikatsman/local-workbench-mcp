"""Authenticated browser bridge; durable setup originates only in local extension UI."""
import base64
import contextlib
import copy
import hashlib
import hmac
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import socket
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit

from .browser_wire import MAX_FRAME, MAX_TRANSFER, ProtocolError, frame, peer_uid, receive_frame
from ._relay_fingerprint import RELAY_CODE_SCHEME, relay_code_sha256
from .context import work_context
from .errors import WorkbenchError
from .persistence import atomic_json
from .response_diagnostics import merge as merge_response_diagnostics
from . import __version__
from . import interaction_contract
from .browser_upload import BrowserUploads
from .views import add_result_continuation


def extension_identity(extension_dir):
    directory = Path(extension_dir)
    manifest = json.loads((directory / 'manifest.json').read_text())
    digest = hashlib.sha256(base64.b64decode(manifest['key'], validate=True)).hexdigest()[:32]
    identifier = ''.join(chr(97 + int(value, 16)) for value in digest)
    return {'extension_id': identifier, 'extension_version': manifest['version'],
            'manifest_sha256': hashlib.sha256((directory / 'manifest.json').read_bytes()).hexdigest()}


def valid_id(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{32}', value) is not None


def claim_history_packets(header, rows):
    """Keep authoritative history complete within the native frame limit."""
    base_bytes = len(frame({**header, 'claims': []})) - 4
    packets, current, size = [], [], base_bytes
    for row in rows:
        row_bytes = len(frame(row)) - 4
        addition = row_bytes + bool(current)
        if current and size + addition > 65536:
            packets.append({**header, 'claims': current})
            current, size, addition = [], base_bytes, row_bytes
        if size + addition > MAX_FRAME:
            raise ProtocolError('frame_size')
        current.append(row)
        size += addition
    if current:
        packets.append({**header, 'claims': current})
    return packets


def rejected_extension_diagnostic(identity, expected):
    """Bounded code-identity metadata only; never retain an untrusted hello."""
    if not isinstance(identity, dict):
        return {'mismatched_fields': ['extension_object']}
    mismatched = [key for key in ('extension_id', 'extension_version', 'manifest_sha256')
                  if identity.get(key) != expected[key]]
    mismatched.extend(key for key in ('worker_generation', 'profile_id') if not valid_id(identity.get(key)))
    if type(identity.get('private_context')) is not bool:
        mismatched.append('private_context')
    version, digest = identity.get('extension_version'), identity.get('manifest_sha256')
    return {'mismatched_fields': mismatched,
            'received_extension_version': version if isinstance(version, str) and re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){0,3}', version) else None,
            'received_manifest_sha256': digest if isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) else None}


def origin(value):
    if not isinstance(value, str):
        raise ProtocolError('origin_required')
    url = urlsplit(value)
    if url.scheme not in ('https', 'http') or not url.hostname or url.username or url.password:
        raise ProtocolError('http_origin_required')
    port = url.port
    host = '[' + url.hostname + ']' if ':' in url.hostname else url.hostname
    default = 443 if url.scheme == 'https' else 80
    return url.scheme + '://' + host + (':' + str(port) if port and port != default else '')


class Peer:
    def __init__(self, connection, identity):
        self.socket, self.identity = connection, identity
        self.id = uuid.uuid4().hex
        self.send_lock = threading.Lock()
        self.pending = {}
        self.transfers = {}
        self.last_sequence = -1
        self.connected = True

    def send(self, packet, *, deadline=None, will_send=None):
        if deadline is None:
            with self.send_lock:
                if will_send is not None: will_send()
                self.socket.sendall(frame(packet))
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self.send_lock.acquire(timeout=max(0, remaining)):
            raise WorkbenchError('selected_browser_control_send_timeout', 'Control writer admission expired.',
                                 effect_state='none', control_delivery='not_sent')
        sent = 0
        try:
            if will_send is not None: will_send()
            try:encoded = frame(packet)
            except ProtocolError as error:
                raise WorkbenchError('selected_browser_command_limit','Control frame exceeds protocol budget.',
                                     effect_state='none',control_delivery='not_sent',bytes_sent=0)from error
            if os.get_blocking(self.socket.fileno()):
                raise OSError('control transport has no nonblocking socket mode')
            while sent < len(encoded):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('control frame deadline')
                if not select.select([], [self.socket], [], remaining)[1]:
                    raise TimeoutError('control frame deadline')
                try:
                    # Python's timed socket.send performs its own timeout wait.
                    # The serving socket already has nonblocking fd mode; write
                    # it directly so this control deadline governs every wait.
                    written = os.write(self.socket.fileno(),encoded[sent:])
                except BlockingIOError:
                    continue
                if written <= 0: raise OSError('control connection closed')
                sent += written
            if time.monotonic() >= deadline:
                raise WorkbenchError('selected_browser_control_send_timeout','Complete frame exceeded control deadline.',
                                     effect_state='unknown',control_delivery='complete_frame_deadline_expired',bytes_sent=sent)
        except (OSError, TimeoutError) as error:
            if sent:
                # A partial frame cannot be resumed or followed by another frame.
                self.connected = False
                with contextlib.suppress(OSError): self.socket.shutdown(socket.SHUT_RDWR)
                for pending in list(self.pending.values()):
                    if not pending['event'].is_set():
                        pending['error'] = 'partial_control_frame'; pending['event'].set()
            raise WorkbenchError('selected_browser_control_send_timeout', 'Control frame delivery is incomplete.',
                                 effect_state='unknown' if sent else 'none',
                                 control_delivery='partial_frame' if sent else 'not_sent', bytes_sent=sent) from error
        finally:
            self.send_lock.release()


class SelectedTabs:
    def __init__(self, config, store, journal, instance_id, extension_dir=None, registry=None, files=None):
        self.config, self.store, self.journal, self.instance_id = config, store, journal, instance_id
        self.extension_dir = Path(extension_dir or Path(__file__).resolve().parents[2] / 'browser-extension')
        self.expected = extension_identity(self.extension_dir)
        self.root = config.state_dir / 'selected-browser'
        self.root.mkdir(mode=0o700, exist_ok=True)
        installation = self.root / 'installation.json'
        if installation.exists():
            from .browser_wire import read_private_json
            saved = read_private_json(installation)
            if not valid_id(saved.get('install_id')) or saved.get('extension_id') != self.expected['extension_id']:
                raise WorkbenchError('browser_installation_changed', 'Selected-tab installation identity changed; review the local setup.')
            self.install_id = saved['install_id']
        else:
            self.install_id = uuid.uuid4().hex
            atomic_json(installation, {'install_id': self.install_id, **self.expected})
        self.registry = Path(registry or self.root / 'connection.json')
        self.lock = threading.RLock()
        self.peers, self.leases, self.lease_locks = {}, {}, {}
        self.claims, self.claim_locks = {}, {}
        self.incomplete_initializations, self.initialization_locks = {}, {}
        self.pending_drags = {}
        self.pending_uploads = {}
        self.input_fences = {}
        self.control_cache = {}
        self.cache_observed_at = {}
        self.cache_sequences = {}
        self.legacy_key_history = {}
        self.trust_path = self.root / 'profile-trust.json'
        if self.trust_path.exists():
            from .browser_wire import read_private_json
            saved_trust = read_private_json(self.trust_path)
            if type(saved_trust.get('interaction_version')) is not int or saved_trust['interaction_version'] != interaction_contract.VERSION or not isinstance(saved_trust.get('profiles'), dict):
                raise WorkbenchError('browser_trust_schema', 'Review the local browser setup schema.')
            self.trust_document = saved_trust
        else:
            self.trust_document = {'interaction_version': interaction_contract.VERSION, 'profiles': {}}
        self.trust_records = self.trust_document['profiles']
        self.listener = self.directory = None
        self.stopped = threading.Event()
        self.token = secrets.token_hex(32)
        self.transfer_bytes = 0
        self.clients = threading.BoundedSemaphore(8)
        self.diagnostics = {'connections_rejected': 0, 'protocol_failures': 0, 'stale_responses': 0}
        self.disabled_reason = None
        self.uploads = BrowserUploads(config, store, journal)
        from .selected_downloads import SelectedDownloads
        self.downloads = SelectedDownloads(self, files)
        self.sessions = self.activity_gate = None
        from .browser_evaluations import BrowserEvaluations
        self.evaluations = BrowserEvaluations(self)
        from .web_diagnostics import WebDiagnostics, DiagnosticController
        self.web_diagnostics = WebDiagnostics(self.root, store)
        self.diagnostic_controller = DiagnosticController(self)

    def start(self):
        with self.lock:
            if self.listener is not None:
                return
            self.directory = tempfile.TemporaryDirectory(prefix='lwb-tabs-')
            path = str(Path(self.directory.name) / 's')
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path); os.chmod(path, 0o600); listener.listen(8); listener.settimeout(.5)
            self.listener = listener
            try:
                atomic_json(self.registry, {'version': 2, 'interaction_version': 1, 'socket': path, 'token': self.token,
                    'server_generation': self.instance_id, 'install_id': self.install_id, **self.expected})
            except OSError as error:
                self.disabled_reason = type(error).__name__
                listener.close(); self.listener = None
                self.directory.cleanup(); self.directory = None
                return
            self.thread = threading.Thread(target=self._accept, daemon=True, name='selected-tab-broker')
            self.thread.start()

    def _accept(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.clients.acquire(blocking=False):
                connection.close()
                with self.lock: self.diagnostics['connections_rejected'] += 1
            else:
                threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        peer = None
        packet = None
        identity_diagnostic = None
        try:
            connection.settimeout(3)
            if peer_uid(connection) != os.getuid():
                raise ProtocolError('peer_uid')
            packet = receive_frame(connection.recv)
            if not isinstance(packet, dict) or packet.get('type') != 'hello':
                raise ProtocolError('hello_required')
            if (not isinstance(packet.get('token'), str) or not hmac.compare_digest(packet['token'], self.token)
                    or packet.get('server_generation') != self.instance_id or packet.get('install_id') != self.install_id
                    or not valid_id(packet.get('native_generation'))):
                raise ProtocolError('stale_capability')
            identity = packet.get('extension')
            from .browser_host import relay
            native_digest = relay_code_sha256(relay.__code__)
            if (packet.get('native_version') != __version__
                    or type(packet.get('native_relay_code_scheme')) is not str
                    or packet['native_relay_code_scheme'] != RELAY_CODE_SCHEME
                    or packet.get('native_relay_code_sha256') != native_digest):
                raise ProtocolError('native_component_version')
            if (not isinstance(identity, dict) or any(identity.get(key) != value for key, value in self.expected.items())
                    or not valid_id(identity.get('worker_generation')) or not valid_id(identity.get('profile_id'))
                    or type(identity.get('private_context')) is not bool):
                identity_diagnostic = rejected_extension_diagnostic(identity, self.expected)
                raise ProtocolError('extension_identity')
            if 'managed_download_version' in identity and (type(identity['managed_download_version']) is not int
                    or identity['managed_download_version'] != 1):
                raise ProtocolError('managed_download_version')
            if 'blob_download_version' in identity and (type(identity['blob_download_version']) is not int
                    or identity['blob_download_version'] != 1):
                raise ProtocolError('blob_download_version')
            if 'page_download_version' in identity and (type(identity['page_download_version']) is not int
                    or identity['page_download_version'] != 1):
                raise ProtocolError('page_download_version')
            if 'diagnostics_version' in identity and (type(identity['diagnostics_version']) is not int or identity['diagnostics_version'] != 1):
                raise ProtocolError('diagnostics_version')
            if 'diagnostics_stream_buffer_version' in identity and (type(identity['diagnostics_stream_buffer_version']) is not int
                    or identity['diagnostics_stream_buffer_version'] != 1):
                raise ProtocolError('diagnostics_stream_buffer_version')
            if 'private_page_download_version' in identity and (type(identity['private_page_download_version']) is not int
                    or identity['private_page_download_version'] != 1):
                raise ProtocolError('private_page_download_version')
            if 'interaction_version' in identity and (type(identity['interaction_version']) is not int
                    or identity['interaction_version'] != interaction_contract.VERSION or not valid_id(identity.get('context_id'))):
                raise ProtocolError('interaction_version')
            with self.lock:
                if len(self.peers) >= 8 or any(p.identity['worker_generation'] == identity['worker_generation'] for p in self.peers.values()):
                    raise ProtocolError('connection_limit')
                peer = Peer(connection, {**identity, 'native_generation': packet['native_generation'],
                    'native_version': packet['native_version'], 'native_relay_code_sha256': native_digest})
                self.peers[peer.id] = peer
            peer.send({'type': 'ready', 'server_generation': self.instance_id, 'peer_id': peer.id,
                       'install_id': self.install_id, 'interaction_version': interaction_contract.VERSION,
                       'control_cache_version':1, 'managed_download_version':1})
            connection.settimeout(30)
            while not self.stopped.is_set():
                packet = receive_frame(connection.recv)
                if packet is None:
                    break
                self._message(peer, packet)
        except (OSError, ValueError, KeyError, TypeError) as error:
            with self.lock:
                self.diagnostics['protocol_failures' if peer else 'connections_rejected'] += 1
                # Keep only a bounded category, never packet contents or generic
                # exception text (which may contain selected page data).
                code = str(error) if isinstance(error, ProtocolError) else type(error).__name__
                if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,95}', code):
                    code = type(error).__name__
                kind = packet.get('type') if isinstance(packet, dict) else None
                if kind not in ('hello', 'control_cache', 'local_setup', 'trust_state', 'local_revoke',
                                'claims_state', 'state', 'response', 'transfer_begin', 'transfer_chunk',
                                'transfer_end', 'heartbeat', 'upload_admission',
                                'managed_download_observation', 'managed_download_state'):
                    kind = 'unknown'
                self.diagnostics['last_channel_failure'] = {
                    'code': code, 'packet_type': kind, 'authenticated': peer is not None,
                    'checked_at': time.time(),
                }
                if code == 'extension_identity' and identity_diagnostic is not None:
                    self.diagnostics['last_channel_failure']['extension_identity'] = identity_diagnostic
        finally:
            with self.lock:
                if peer:
                    peer.connected = False
                    self.peers.pop(peer.id, None)
                    for lease in self.leases.values():
                        if lease['peer_id'] == peer.id and lease['state'] == 'active':
                            lease.update(state='disconnected', reason='native_connection_lost', ended_at=time.time())
                    for row in self.claims.values():
                        if row['peer_id'] == peer.id and row['state'] == 'active':
                            row.update(state='suspended_transport', reason='native_connection_lost')
                    for pending in peer.pending.values():
                        pending['error'] = 'native_connection_lost'; pending['event'].set()
                    for transfer in peer.transfers.values():
                        self.transfer_bytes -= transfer['total_bytes']
            connection.close()
            self.clients.release()

    def _upload_binding(self, current, peer, owner, expected_origin, expected_generation, parameters):
        return {'owner_session': owner, 'runtime_generation': current['runtime_generation'],
            'installation_id': current['installation_id'], 'claim_id': current['claim_id'],
            'claim_epoch': current['claim_epoch'], 'target_generation': current['target']['target_generation'],
            'browser_target_id': current['target']['browser_target_id'], 'expected_origin': expected_origin,
            'expected_generation': expected_generation, 'observation_id': parameters.get('observation_id'),
            'target_id': parameters.get('target_id'), 'peer_id': peer.id,
            'trust_id': self.trust_records[peer.trust_key]['trust_id']}

    def _upload_current(self, peer, binding):
        with self.lock:
            row = self.claims.get(binding['claim_id'])
            trust = self.trust_records.get(getattr(peer, 'trust_key', None), {})
            if (not peer.connected or peer.id != binding['peer_id'] or not row or row['state'] != 'active'
                    or row['peer_id'] != peer.id or row['runtime_generation'] != self.instance_id
                    or row['owner_session'] != binding['owner_session'] or row['claim_epoch'] != binding['claim_epoch']
                    or row['installation_id'] != binding['installation_id']
                    or row['target']['target_generation'] != binding['target_generation']
                    or row['target']['browser_target_id'] != binding['browser_target_id']
                    or row['target']['origin'] != binding['expected_origin']
                    or row['target']['document_epoch'] != binding['expected_generation']
                    or not row.get('control') or not trust.get('enabled') or trust.get('file_upload') is not True
                    or trust['trust_id'] != binding['trust_id']):
                raise WorkbenchError('upload_authority_changed', 'The exact upload claim or local grant changed.', effect_state='none')

    def _upload_admission(self, peer, packet):
        nonce = packet.get('nonce')
        if not valid_id(nonce): raise ProtocolError('upload_admission_shape')
        try:
            binding = packet.get('binding')
            if not isinstance(binding, dict): raise WorkbenchError('upload_authority_invalid', 'Invalid upload authority.', effect_state='none')
            with self.lock:
                if packet.get('request_id') not in peer.pending:
                    raise WorkbenchError('upload_authority_invalid', 'The upload request is no longer pending.', effect_state='none')
            def current():
                with self.lock:
                    if packet.get('request_id') not in peer.pending:
                        raise WorkbenchError('upload_authority_invalid', 'The upload request ended during validation.', effect_state='none')
                self._upload_current(peer, binding)
                if packet.get('carrier') == 'supplied_content':
                    self._upload_content_current(peer, packet)
            authority = self.uploads.consume(packet.get('token'), packet.get('request_id'), binding,
                packet.get('backend_node_id'), current, carrier=packet.get('carrier', 'native_path'),
                worker_generation=packet.get('worker_generation'))
            peer.send({'type': 'upload_admission_result', 'nonce': nonce, 'ok': True, 'authority': authority,
                       **({'request_id': packet['request_id'], 'worker_generation': packet['worker_generation'],
                           'peer_id': peer.id} if packet.get('carrier') == 'supplied_content' else {})})
        except (WorkbenchError, OSError, ValueError, KeyError) as error:
            peer.send({'type': 'upload_admission_result', 'nonce': nonce, 'ok': False,
                'error': {'code': getattr(error, 'code', 'upload_stage_unavailable'), 'effect_state': 'none'},
                **({'request_id': packet.get('request_id'), 'worker_generation': peer.identity.get('worker_generation'),
                    'peer_id': peer.id} if packet.get('carrier') == 'supplied_content' else {})})

    def _upload_content_current(self, peer, packet):
        with self.lock:
            binding = packet.get('binding', {})
            if (self.peers.get(peer.id) is not peer or not peer.connected
                    or packet.get('peer_id') != peer.id
                    or packet.get('worker_generation') != peer.identity.get('worker_generation')
                    or packet.get('carrier') != 'supplied_content'
                    or packet.get('request_id') not in peer.pending
                    or binding.get('claim_id') in self.input_fences
                    or self.trust_records.get(peer.trust_key, {}).get('control') is not True):
                raise WorkbenchError('upload_authority_changed', 'Content channel or control admission changed.', effect_state='none')

    def _upload_content_read(self, peer, packet):
        nonce = packet.get('nonce')
        if not valid_id(nonce): raise ProtocolError('upload_content_shape')
        reply = {'type': 'upload_content_result', 'nonce': nonce, 'request_id': packet.get('request_id'),
                 'peer_id': peer.id, 'worker_generation': peer.identity.get('worker_generation')}
        try:
            if not isinstance(packet.get('binding'), dict):
                raise WorkbenchError('upload_authority_invalid', 'Invalid content binding.', effect_state='none')
            def current():
                self._upload_content_current(peer, packet)
                self._upload_current(peer, packet['binding'])
            current()
            chunk = self.uploads.read_content(packet.get('token'), packet.get('request_id'), packet['binding'],
                packet.get('backend_node_id'), packet.get('offset'), packet.get('worker_generation'), current)
            peer.send({**reply, 'ok': True, 'content': chunk})
        except (WorkbenchError, OSError, ValueError, KeyError) as error:
            peer.send({**reply, 'ok': False, 'error': {
                'code': getattr(error, 'code', 'upload_stage_unavailable'), 'effect_state': 'none'}})

    def _upload_cleanup(self, workspace, owner, expected_origin, expected_generation, parameters):
        claim_id, stage_id = parameters.get('claim_id'), parameters.get('upload_stage_id')
        with self.lock:
            current = self.claims.get(claim_id)
            if (not current or current['owner_session'] != owner
                    or current['claim_epoch'] != parameters.get('claim_epoch')
                    or current['target']['target_generation'] != parameters.get('target_generation')):
                raise WorkbenchError('upload_cleanup_owner_mismatch', 'Use the exact current original claim.', effect_state='none')
            binding = {'owner_session': owner, 'runtime_generation': current['runtime_generation'],
                'installation_id': current['installation_id'], 'claim_id': claim_id,
                'claim_epoch': current['claim_epoch'], 'target_generation': current['target']['target_generation'],
                'browser_target_id': current['target']['browser_target_id'], 'expected_origin': expected_origin,
                'expected_generation': expected_generation}
            terminal = current['state'] in ('released', 'revoked', 'target_closed')
            if not terminal and current['runtime_generation'] != self.instance_id:
                raise WorkbenchError('upload_cleanup_unverified', 'The original runtime input is unavailable.', effect_state='none')
            peers = [p for p in self.peers.values() if p.connected and p.id == current['peer_id']]
        row = self.uploads.record(stage_id)
        if terminal:
            return self.uploads.cleanup(stage_id, binding, {'condition': 'terminal_claim', 'stage_id': stage_id})
        if len(peers) != 1 or not valid_id(parameters.get('observation_id')) or not valid_id(parameters.get('target_id')):
            raise WorkbenchError('upload_cleanup_unverified', 'Keep the stage until its original input is verified cleared.', effect_state='none')
        peer = peers[0]
        with self.claim_locks[claim_id]:
            result = self._rpc(peer, 'cleanup', {'interaction_version': 1, 'runtime_generation': self.instance_id,
                'profile_id': current['target']['profile_id'], 'context_id': current['target']['context_id'],
                'context_kind': current['target']['context_kind'], 'trust_id': self.trust_records[peer.trust_key]['trust_id'],
                'owner_session': owner, 'claim_id': claim_id, 'claim_epoch': current['claim_epoch'],
                'target_generation': current['target']['target_generation'], 'expected_origin': expected_origin,
                'expected_generation': expected_generation, 'parameters': parameters,
                'upload_cleanup': {'stage_id': stage_id, 'backend_node_id': row.get('input_backend_node_id')}})
            with self.lock:
                latest = self.claims.get(claim_id)
                if not latest or latest['state'] != 'active' or latest['claim_epoch'] != binding['claim_epoch']:
                    raise WorkbenchError('upload_cleanup_unverified', 'The input owner changed during cleanup verification.', effect_state='none')
            return self.uploads.cleanup(stage_id, binding, result['upload_cleanup_proof'])

    @staticmethod
    def _capture_policy_valid(peer, row, trust):
        requested = row.get('capture_responses')
        if requested is not None:
            if (type(requested) is not bool or type(peer.identity.get('capture_responses_version')) is not int
                    or peer.identity['capture_responses_version'] != 1 or row.get('passive_diagnostics') is True
                    or row.get('network') is not requested):
                return False
        # Historical records preserve original authority even after local trust changes.
        expected_network = trust.get('network') if requested is None else trust.get('network') and requested
        return row.get('state') != 'active' or row.get('network') is expected_network

    def _record_claim_binding_rejection(self, peer, row, trust):
        """Last rejection only: fixed predicates and safe identity atoms, never page data."""
        target = row.get('target') if isinstance(row.get('target'), dict) else {}
        active = row.get('state') == 'active'
        expected_control = False if row.get('passive_diagnostics') is True else trust.get('control')
        checks = (
            ('installation_id', row.get('installation_id') == self.install_id),
            ('profile_id', target.get('profile_id') == peer.identity.get('profile_id')),
            ('context_id', target.get('context_id') == peer.identity.get('context_id')),
            ('context_kind', target.get('context_kind') == trust.get('context_kind')),
            ('control_type', type(row.get('control')) is bool),
            ('network_type', type(row.get('network')) is bool),
            ('active_control', not active or row.get('control') == expected_control),
            ('active_network', self._capture_policy_valid(peer, row, trust)),
            ('active_runtime_generation', not active or row.get('runtime_generation') == self.instance_id),
            ('active_connection_generation', not active or target.get('connection_generation') == peer.id),
        )
        def identifier(value):
            return value if type(value) is str and valid_id(value) else '[invalid_or_missing]'
        def boolean(value):
            return value if type(value) is bool else '[invalid_or_missing]'
        def kind(value):
            return value if type(value) is str and value in ('ordinary', 'private') else '[invalid_or_missing]'
        state = row.get('state')
        epoch = row.get('claim_epoch')
        self.diagnostics['last_claim_binding_rejection'] = {
            'version': 1, 'code': 'browser_claim_binding', 'packet_type': 'claims_state',
            'authenticated': True, 'checked_at': time.time(),
            'failed_predicates': [name for name, matches in checks if not matches],
            'claim': {
                'claim_id': identifier(row.get('claim_id')),
                'claim_epoch': epoch if type(epoch) is int and 0 < epoch <= 9007199254740991 else '[invalid_or_missing]',
                'state': state if type(state) is str and state in interaction_contract.CLAIM_STATES else '[invalid_or_missing]',
                'installation_id': identifier(row.get('installation_id')),
                'runtime_generation': identifier(row.get('runtime_generation')),
                'profile_id': identifier(target.get('profile_id')),
                'context_id': identifier(target.get('context_id')),
                'context_kind': kind(target.get('context_kind')),
                'connection_generation': identifier(target.get('connection_generation')),
                'control': boolean(row.get('control')), 'network': boolean(row.get('network')),
            },
            'peer': {
                'peer_id': identifier(peer.id),
                'profile_id': identifier(peer.identity.get('profile_id')),
                'context_id': identifier(peer.identity.get('context_id')),
                'context_kind': 'private' if peer.identity.get('private_context') is True else 'ordinary',
                'worker_generation': identifier(peer.identity.get('worker_generation')),
            },
            'expected': {
                'installation_id': identifier(self.install_id), 'runtime_generation': identifier(self.instance_id),
                'context_kind': kind(trust.get('context_kind')),
                'control': boolean(expected_control),
                'network': boolean(False if row.get('capture_responses') is False else trust.get('network')),
            },
        }

    def _message(self, peer, packet):
        kind = packet.get('type')
        if kind == 'browser_diagnostic_event':
            with self.lock:
                row = self.claims.get(packet.get('claim_id'))
                if (not peer.connected or self.peers.get(peer.id) is not peer or not row
                        or row.get('peer_id') != peer.id or row.get('passive_diagnostics') is not True
                        or row.get('owner_session') != packet.get('owner_session')):
                    raise ProtocolError('diagnostic_event_authority')
                binding = self._binding(row)
            try:
                self.web_diagnostics.ingest(packet.get('record_id'), packet.get('owner_session'), binding, packet.get('event'))
            except OSError:
                # Recording failure is evidence loss, never a reason to interrupt the subject page/other claims.
                self.web_diagnostics.storage_failed(packet.get('record_id'),packet.get('owner_session'))
                self.diagnostics['web_diagnostic_storage_failure'] = time.time()
            peer.send({'type':'browser_diagnostic_ack','record_id':packet['record_id'],'claim_id':packet['claim_id'],
                'sequence':packet['event']['sequence'],
                'capture_active':self.web_diagnostics._owned(packet['record_id'],packet['owner_session'])['status']=='recording'})
            return
        if kind == 'managed_download_blob_admission':
            self.downloads.observe_blob(peer, packet)
            return
        if kind == 'managed_download_observation':
            self.downloads.observe(peer, packet)
            return
        if kind == 'managed_download_state':
            self.downloads.message(peer, packet)
            return
        if kind == 'upload_admission':
            self._upload_admission(peer, packet)
            return
        if kind == 'upload_content_read':
            self._upload_content_read(peer, packet)
            return
        with self.lock:
            if kind == 'control_cache':
                self._control_cache_message(peer, packet)
            elif kind in ('local_setup', 'trust_state', 'local_revoke'):
                if peer.identity.get('interaction_version') != interaction_contract.VERSION or type(packet.get('interaction_version')) is not int or packet['interaction_version'] != interaction_contract.VERSION:
                    raise ProtocolError('interaction_version')
                key = peer.identity['profile_id'] + ':' + peer.identity['context_id']
                current = self.trust_records.get(key)
                if kind == 'local_revoke':
                    if not current or current['trust_id'] != packet.get('trust_id'):
                        raise ProtocolError('browser_trust_binding')
                    self.trust_records[key] = {**current, 'enabled': False, 'revoked_at': time.time()}
                    atomic_json(self.trust_path, self.trust_document)
                    for row in self.claims.values():
                        if row['target']['context_id'] == peer.identity['context_id'] and row['state'] not in ('released', 'revoked', 'target_closed'):
                            row.update(state='revoked', reason='local_setup_revoked')
                else:
                    trust = packet.get('trust')
                    if (not isinstance(trust, dict) or type(trust.get('interaction_version')) is not int or trust['interaction_version'] != interaction_contract.VERSION
                            or trust.get('installation_id') != self.install_id or not valid_id(trust.get('trust_id'))
                            or trust.get('profile_id') != peer.identity['profile_id'] or trust.get('context_id') != peer.identity['context_id']
                            or trust.get('context_kind') != ('private' if peer.identity['private_context'] else 'ordinary')
                            or trust.get('enabled') is not True or type(trust.get('control')) is not bool or type(trust.get('network')) is not bool):
                        raise ProtocolError('browser_trust_binding')
                    if type(trust.get('file_upload', False)) is not bool or type(trust.get('file_download', False)) is not bool:
                        raise ProtocolError('browser_trust_binding')
                    trust = {**trust, 'file_upload': trust.get('file_upload', False), 'file_download': trust.get('file_download', False)}
                    if kind == 'trust_state':
                        if not current or not current.get('enabled') or any(current.get(k, False if k in ('file_upload','file_download') else None) != trust.get(k) for k in trust):
                            raise ProtocolError('browser_setup_required')
                    else:
                        if len(self.trust_records) >= 32 and key not in self.trust_records:
                            raise ProtocolError('browser_profile_limit')
                        self.trust_records[key] = {**trust, 'extension_id': peer.identity['extension_id']}
                        atomic_json(self.trust_path, self.trust_document)
                peer.trust_key = key
                if kind != 'local_revoke':
                    peer.send({'type': 'trust_ready', 'trust_id': trust['trust_id'], 'interaction_version': 1})
            elif kind == 'claims_state':
                rows = packet.get('claims')
                history = packet.get('incomplete_initializations', [])
                trust = self.trust_records.get(getattr(peer, 'trust_key', None))
                # The first ready snapshot may be empty before local setup.
                if rows == [] and history == []:
                    return
                if (type(packet.get('interaction_version')) is not int or packet['interaction_version'] != interaction_contract.VERSION or not trust or not trust.get('enabled')
                        or not isinstance(rows, list) or len(rows) > 1000):
                    raise ProtocolError('browser_setup_required')
                if not isinstance(history, list) or len(history) > 100:
                    raise ProtocolError('browser_initialization_history_shape')
                for row in history:
                    try: interaction_contract.browser_initialization_record(row)
                    except WorkbenchError as error: raise ProtocolError('browser_initialization_history_shape') from error
                    target = row['target']
                    if (row['installation_id'] != self.install_id or target['profile_id'] != peer.identity['profile_id']
                            or target['context_id'] != peer.identity['context_id'] or target['context_kind'] != trust['context_kind']
                            or row['claim_id'] in self.claims):
                        raise ProtocolError('browser_initialization_history_binding')
                    old = self.incomplete_initializations.get(row['claim_id'])
                    if old and (any(old[k] != row[k] for k in ('owner_session','installation_id','runtime_generation','provenance','cleanup_policy'))
                            or old['target'] != target
                            or old.get('initialization_request_id') != row.get('initialization_request_id')
                            or old['claim_epoch'] > row['claim_epoch']
                            or old['claim_epoch'] == row['claim_epoch'] and old['resource_unsettled'] and not row['resource_unsettled']):
                        raise ProtocolError('rebound_browser_initialization')
                    self._publish_initialization_history(peer, row)
                    self.initialization_locks.setdefault(row['claim_id'], threading.Lock())
                if len(self.incomplete_initializations) > 1000:
                    raise ProtocolError('browser_initialization_history_limit')
                reconciled = []
                for row in rows:
                    self._validate_keyboard_metadata(row)
                    self._validate_dialog_metadata(row)
                    if row.get('claim_id') in self.incomplete_initializations:
                        raise ProtocolError('browser_initialization_history_binding')
                    try:
                        interaction_contract.claim(row, backend='browser', runtime_generation=row.get('runtime_generation'), owner_session=row.get('owner_session'))
                    except (WorkbenchError, AttributeError) as error:
                        raise ProtocolError('browser_claim_shape') from error
                    target = row['target']
                    if (row['installation_id'] != self.install_id or target['profile_id'] != peer.identity['profile_id']
                            or target['context_id'] != peer.identity['context_id'] or target['context_kind'] != trust['context_kind']
                            or type(row.get('control')) is not bool or type(row.get('network')) is not bool
                            or not self._capture_policy_valid(peer, row, trust)
                            or row['state'] == 'active' and row['control'] != (False if row.get('passive_diagnostics') is True else trust['control'])
                            or row['state'] == 'active' and (row['runtime_generation'] != self.instance_id or target['connection_generation'] != peer.id)):
                        self._record_claim_binding_rejection(peer, row, trust)
                        raise ProtocolError('browser_claim_binding')
                    if row.get('passive_diagnostics') is not None and (row['passive_diagnostics'] is not True
                            or row['control'] is not False or row.get('input_eligible') is not False
                            or target['context_kind'] != 'ordinary' or row['network'] is not True):
                        raise ProtocolError('diagnostic_claim_binding')
                    existing = self.claims.get(row['claim_id'])
                    if existing and existing.get('passive_diagnostics') != row.get('passive_diagnostics'):
                        raise ProtocolError('diagnostic_claim_binding')
                    if existing and (existing.get('capture_responses') != row.get('capture_responses')
                            or existing.get('network') != row.get('network')):
                        raise ProtocolError('browser_capture_policy_binding')
                    if row.get('restored_history') is True:
                        if row['state'] not in ('suspended_transport','suspended_contention','released','revoked','target_closed'):
                            raise ProtocolError('rebound_browser_claim')
                        if existing:
                            immutable = ('owner_session','installation_id','runtime_generation','provenance','cleanup_policy')
                            identity = ('target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind')
                            if (any(existing.get(k) != row.get(k) for k in immutable)
                                    or any(existing['target'].get(k) != target.get(k) for k in identity)
                                    or existing['state']=='active'):
                                raise ProtocolError('rebound_browser_claim')
                            # Neither durable endpoint necessarily saw the last
                            # phase. Union original IDs before selecting claim
                            # state; only explicit recorded outcomes can settle
                            # uncertainty. Incompatible facts stay on their
                            # original endpoints, without overwriting either.
                            receipts = {r['phase_id']: dict(r) for r in existing.get('response_capture_receipts', [])}
                            for receipt in row.get('response_capture_receipts', []):
                                old = receipts.get(receipt['phase_id'])
                                if old:
                                    if any(old[k] != receipt[k] for k in ('claim_epoch','fetch_id','session_id')):
                                        raise ProtocolError('browser_response_history_conflict')
                                    for field, uncertain in (('continuation', ('not_attempted','attempted','unverified')),
                                                             ('resource_cleanup', ('pending','unverified'))):
                                        before, after = old[field], receipt[field]
                                        if before == after:
                                            continue
                                        if before not in uncertain and after not in uncertain:
                                            raise ProtocolError('browser_response_history_conflict')
                                        if before in uncertain and (after not in uncertain or uncertain.index(after) > uncertain.index(before)):
                                            old[field] = after
                                else:
                                    receipts[receipt['phase_id']] = dict(receipt)
                            if len(receipts) > 32:
                                raise ProtocolError('browser_response_history_limit')
                            capture_flags = {k: True for k in ('response_capture_overflow',)
                                             if existing.get(k) or row.get(k)}
                            if 'response_capture_diagnostics' in existing or 'response_capture_diagnostics' in row:
                                capture_flags['response_capture_diagnostics'] = merge_response_diagnostics(
                                    existing.get('response_capture_diagnostics'), row.get('response_capture_diagnostics'))
                            if existing.get('response_history_persistence') or row.get('response_history_persistence'):
                                capture_flags['response_history_persistence'] = 'unsaved'
                            # A local storage snapshot can precede the last
                            # browser close event. Ended history never regains
                            # resource/input authority during restoration.
                            if existing['state'] in ('released','revoked','target_closed'):
                                row = {k:v for k,v in existing.items() if k != 'peer_id'}
                                target = row['target']
                            elif existing['claim_epoch'] > row['claim_epoch'] or existing['target']['document_epoch'] > target['document_epoch']:
                                row = {k:v for k,v in existing.items() if k != 'peer_id'}
                                target = row['target']
                            row = {**row, **capture_flags, 'response_capture_receipts': list(receipts.values())}
                            try:
                                if interaction_contract.browser_response_capture(row):
                                    row['cleanup_state'] = 'unverified'
                            except WorkbenchError as error:
                                raise ProtocolError('browser_response_history_conflict') from error
                        # Pending cleanup belonged to the previous worker. It
                        # remains a resource, but needs explicit reconciliation;
                        # never restore a dead in-memory operation as pending.
                        if row.get('cleanup_state') == 'pending':
                            row = {**row, 'cleanup_state': 'unverified'}
                        reconciled.append(row)
                    if existing and (existing['owner_session'] != row['owner_session'] or existing['target']['target_id'] != target['target_id']
                            or existing['target']['target_generation'] != target['target_generation'] or existing['claim_epoch'] > row['claim_epoch']
                            or existing['target']['document_epoch'] > target['document_epoch']
                            or existing['target']['document_epoch'] == target['document_epoch'] and any(existing['target'].get(k) != target.get(k) for k in ('frame_id', 'loader_id'))
                            or existing['state'] != row['state'] and row['claim_epoch'] <= existing['claim_epoch']
                            or existing['state'] in ('released', 'revoked', 'target_closed', 'suspended_transport') and row['state'] == 'active'):
                        raise ProtocolError('rebound_browser_claim')
                    if row['state'] == 'active' and any(other['target']['target_id'] == target['target_id'] and other['state'] == 'active'
                            and other['claim_id'] != row['claim_id'] for other in self.claims.values()):
                        raise ProtocolError('browser_target_owned')
                    self.claims[row['claim_id']] = {**row, 'peer_id': peer.id}
                    self.cache_observed_at[row['claim_id']] = time.monotonic()
                    self.claim_locks.setdefault(row['claim_id'], threading.Lock())
                if reconciled:
                    header = {'type':'claim_history_reconciled','interaction_version':1,'peer_id':peer.id,
                        'server_generation':self.instance_id,'trust_id':trust['trust_id']}
                    for response in claim_history_packets(header, reconciled):
                        peer.send(response)
                if len(self.claims) > 1000:
                    raise ProtocolError('browser_claim_history_limit')
            elif kind == 'state':
                if 'legacy_key_history'in packet:self._legacy_history_message(peer,packet['legacy_key_history'])
                sequence, rows = packet.get('sequence'), packet.get('leases')
                if type(sequence) is not int or sequence <= peer.last_sequence or not isinstance(rows, list) or len(rows) > 32:
                    raise ProtocolError('stale_state')
                validated = []
                for row in rows:
                    if (not isinstance(row, dict) or not valid_id(row.get('lease_id'))
                            or type(row.get('document_generation')) is not int or row['document_generation'] < 1
                            or type(row.get('expires_at')) not in (int, float)
                            or not time.time() - 86400 <= row['expires_at'] <= time.time() + 901
                            or type(row.get('tab_id')) is not int or type(row.get('window_id')) is not int
                            or type(row.get('control')) is not bool or type(row.get('network')) is not bool
                            or row.get('state') not in ('active', 'detached')):
                        raise ProtocolError('invalid_lease')
                    if origin(row.get('origin')) != row['origin']:
                        raise ProtocolError('origin_scope')
                    existing = self.leases.get(row['lease_id'])
                    if existing and (existing['peer_id'] != peer.id or existing['origin'] != row['origin']
                                     or existing['tab_id'] != row['tab_id'] or existing['document_generation'] > row['document_generation']
                                     or existing['expires_at'] != row['expires_at'] or existing['control'] != row['control']
                                     or existing['network'] != row['network']
                                     or existing['state'] != 'active' and row['state'] == 'active'):
                        raise ProtocolError('rebound_lease')
                    validated.append({key: row[key] for key in ('lease_id', 'document_generation', 'expires_at', 'tab_id',
                        'window_id', 'control', 'network', 'state', 'origin')})
                    extra = ('browser_target_id','grant_generation','installation_id','runtime_generation','peer_id',
                             'profile_id','context_id','context_kind','input_eligible','keyboard_release_state','keyboard_receipt',
                             'debuggerAttached','cleanup_state','cleanup_error','operation_owner')
                    if any(key in row for key in extra):
                        self._validate_legacy_lifetime(peer, row)
                        if existing and any(existing.get(key) != row.get(key) for key in extra[:8] if key in existing):
                            raise ProtocolError('rebound_lease')
                        if existing and existing.get('operation_owner') is not None and existing['operation_owner'] != row.get('operation_owner'):
                            raise ProtocolError('rebound_lease_owner')
                        validated[-1].update({key:copy.deepcopy(row[key]) for key in extra if key in row})
                if len(self.leases) + sum(row['lease_id'] not in self.leases for row in validated) > 1000:
                    raise ProtocolError('lease_history_limit')
                seen = {row['lease_id'] for row in validated}
                for lease in self.leases.values():
                    if lease['peer_id'] == peer.id and lease['state'] == 'active' and lease['lease_id'] not in seen:
                        lease.update(state='detached', reason='local_grant_removed')
                for row in validated:
                    old = self.leases.get(row['lease_id'], {})
                    self.leases[row['lease_id']] = {**old, **row, 'peer_id': peer.id,
                        'profile_id': peer.identity['profile_id'], 'worker_generation': peer.identity['worker_generation'],
                        'private_context': peer.identity['private_context'], 'checked_at': time.time()}
                    self.lease_locks.setdefault(row['lease_id'], threading.Lock())
                    self.cache_observed_at[row['lease_id']] = time.monotonic()
                peer.last_sequence = sequence
            elif kind == 'response':
                self._response(peer, packet.get('request_id'), packet.get('result'))
            elif kind == 'transfer_begin':
                request_id, total = packet.get('request_id'), packet.get('total_bytes')
                if (request_id not in peer.pending or type(total) is not int or not 1 <= total <= MAX_TRANSFER
                        or not valid_id(packet.get('transfer_id')) or len(peer.transfers) >= 2
                        or self.transfer_bytes + total > 2 * MAX_TRANSFER
                        or not isinstance(packet.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', packet['sha256'])):
                    raise ProtocolError('transfer_limit')
                transfer_id = packet['transfer_id']
                if transfer_id in peer.transfers:
                    raise ProtocolError('duplicate_transfer')
                peer.transfers[transfer_id] = {**packet, 'buffer': io.BytesIO(), 'offset': 0}
                self.transfer_bytes += total
            elif kind == 'transfer_chunk':
                transfer = peer.transfers.get(packet.get('transfer_id'))
                if transfer is None or packet.get('offset') != transfer['offset']:
                    raise ProtocolError('transfer_cursor')
                raw = base64.b64decode(packet.get('data', ''), validate=True)
                if not 1 <= len(raw) <= 32768 or transfer['offset'] + len(raw) > transfer['total_bytes']:
                    raise ProtocolError('transfer_size')
                transfer['buffer'].write(raw); transfer['offset'] += len(raw)
            elif kind == 'transfer_end':
                transfer = peer.transfers.pop(packet.get('transfer_id'), None)
                if transfer is None:
                    raise ProtocolError('transfer_unknown')
                self.transfer_bytes -= transfer['total_bytes']
                raw = transfer['buffer'].getvalue()
                if len(raw) != transfer['total_bytes'] or hashlib.sha256(raw).hexdigest() != transfer['sha256']:
                    raise ProtocolError('transfer_integrity')
                self._response(peer, transfer['request_id'], json.loads(raw))
            elif kind != 'heartbeat':
                raise ProtocolError('message_type')

    def _response(self, peer, request_id, result):
        pending = peer.pending.get(request_id)
        if pending is None:
            self.diagnostics['stale_responses'] += 1
            return
        if pending['event'].is_set():
            self.diagnostics['stale_responses'] += 1
            return
        if not isinstance(result, dict) or type(result.get('ok')) is not bool:
            raise ProtocolError('response_shape')
        pending['result'] = result; pending['event'].set()

    @staticmethod
    def _control_action(action, parameters):
        return action in ('diagnostics_begin', 'diagnostics_mark', 'diagnostics_stop', 'stop', 'release', 'detach', 'claim_status', 'events', 'dialog_read', 'dialog_handle',
                         'managed_download_state', 'managed_download_cancel') or (
            action == 'cleanup' and not parameters.get('upload_cleanup')
            and parameters.get('upload_stage_id') is None
            and (parameters.get('parameters') or {}).get('upload_stage_id') is None)

    def _legacy_history_message(self,peer,rows):
        if not peer.connected or self.peers.get(peer.id)is not peer or not isinstance(rows,list)or len(rows)>32:
            raise ProtocolError('legacy_key_history_shape')
        accepted={}
        for row in rows:
            if (not isinstance(row,dict)or row.get('authority')!='cleanup_only'or row.get('history_only')is not True
                    or row.get('state')!='detached'or row.get('input_eligible')is not False
                    or row.get('keyboard_release_state')not in ('prepared','held','unverified')
                    or any(not valid_id(row.get(k))for k in ('lease_id','grant_generation','installation_id','runtime_generation','peer_id','profile_id','context_id'))
                    or row['installation_id']!=self.install_id or row['profile_id']!=peer.identity['profile_id']
                    or row['context_id']!=peer.identity.get('context_id')
                    or row.get('context_kind')!=('private'if peer.identity['private_context']else'ordinary')
                    or not isinstance(row.get('browser_target_id'),str)or not 1<=len(row['browser_target_id'])<=256
                    or any(type(row.get(k))is not int for k in ('tab_id','window_id','document_generation'))
                    or row['document_generation']<1 or type(row.get('expires_at'))not in (int,float)
                    or not math.isfinite(row['expires_at'])or type(row.get('control'))is not bool or type(row.get('network'))is not bool
                    or len(json.dumps(row).encode())>8192):raise ProtocolError('legacy_key_history_binding')
            if row.get('operation_owner')is not None and (not isinstance(row['operation_owner'],str)or not 1<=len(row['operation_owner'].encode())<=128):
                raise ProtocolError('legacy_key_history_owner')
            self._validate_keyboard_metadata(row)
            old=self.legacy_key_history.get(row['grant_generation'])
            if old and (self._binding(old)!=self._binding(row)
                    or old.get('operation_owner')!=row.get('operation_owner')):
                raise ProtocolError('rebound_legacy_key_history')
            accepted[row['grant_generation']]={**copy.deepcopy(row),'history_published_peer':peer.id,'history_received_at':time.time()}
        # Missing rows are not proof of release; retain unresolved originals.
        if len(set(self.legacy_key_history)|set(accepted))>32:raise ProtocolError('legacy_key_history_limit')
        self.legacy_key_history.update(accepted)

    def _history_target_guard(self,target):
        if any(row['browser_target_id']==target.get('browser_target_id')and row['profile_id']==target.get('profile_id')
               and row['context_id']==target.get('context_id')for row in self.legacy_key_history.values()):
            raise WorkbenchError('browser_key_history_unsettled','Original target has cleanup-only key history.',effect_state='none')

    def _binding(self, row):
        if 'claim_id' in row:
            t = row['target']
            return {**{k:row.get(k) for k in ('claim_id','claim_epoch','owner_session','installation_id','runtime_generation','peer_id')},
                    **{k:t.get(k) for k in ('target_id','target_generation','browser_target_id','tab_id','profile_id','context_id',
                                         'context_kind','connection_generation','frame_id','loader_id','document_epoch','origin')}}
        return {k:row.get(k) for k in ('lease_id','grant_generation','browser_target_id','installation_id','runtime_generation',
                    'peer_id','profile_id','context_id','context_kind','tab_id','document_generation','origin')}

    def _validate_legacy_lifetime(self, peer, row):
        if (not isinstance(row.get('browser_target_id'), str) or not 1 <= len(row['browser_target_id']) <= 256
                or not valid_id(row.get('grant_generation')) or row.get('installation_id') != self.install_id
                or row.get('runtime_generation') != self.instance_id or row.get('peer_id') != peer.id
                or row.get('profile_id') != peer.identity['profile_id'] or row.get('context_id') != peer.identity.get('context_id')
                or row.get('context_kind') != ('private' if peer.identity['private_context'] else 'ordinary')
                or type(row.get('input_eligible')) is not bool
                or row.get('keyboard_release_state') not in ('not_needed','prepared','held','pending','acknowledged','unverified','not_recorded')
                or row.get('keyboard_receipt') is not None and not isinstance(row.get('keyboard_receipt'),dict)):
            raise ProtocolError('legacy_control_binding')
        self._validate_keyboard_metadata(row)
        if row.get('operation_owner') is not None and (not isinstance(row['operation_owner'], str)
                or not 1 <= len(row['operation_owner'].encode()) <= 128):
            raise ProtocolError('legacy_control_owner')
        if ('debuggerAttached'in row and type(row['debuggerAttached'])is not bool
                or 'cleanup_state'in row and row['cleanup_state']not in ('not_attempted','pending','completed','unverified','target_gone','not_owned')
                or row.get('cleanup_error')is not None and (not isinstance(row['cleanup_error'],str)or len(row['cleanup_error'])>256)):
            raise ProtocolError('legacy_cleanup_metadata')

    @staticmethod
    def _validate_keyboard_metadata(row):
        if not isinstance(row,dict): raise ProtocolError('browser_key_receipt')
        if 'keyboard_release_state' not in row and 'keyboard_receipt' not in row: return
        receipt=row.get('keyboard_receipt')
        if (row.get('keyboard_release_state') not in ('not_needed','prepared','held','pending','acknowledged','unverified','not_recorded')
                or receipt is not None and (not isinstance(receipt,dict) or len(json.dumps(receipt).encode())>4096)): raise ProtocolError('browser_key_receipt')
        def private_text(value):
            if isinstance(value,dict):return any(k in ('text','unmodifiedText','expression','value') or private_text(v)for k,v in value.items())
            if isinstance(value,list):return any(private_text(v)for v in value)
            return False
        if private_text(receipt): raise ProtocolError('browser_key_receipt')

    def _validate_operation_keyboard(self, receipt, parameters, binding, request_id, historical=False):
        self._validate_keyboard_metadata({'keyboard_release_state': 'unverified', 'keyboard_receipt': receipt})
        lifetime = receipt.get('binding') if isinstance(receipt, dict) else None
        operation = receipt.get('operation_request_id') if isinstance(receipt, dict) else None
        if (not binding or not isinstance(lifetime, dict) or not isinstance(operation, str) or not 1 <= len(operation.encode()) <= 128
                or not isinstance(receipt.get('hold_id'), str) or not 1 <= len(receipt['hold_id']) <= 128
                or receipt.get('browser_target_id') != binding.get('browser_target_id')
                or any(not isinstance(receipt.get(key), str) or not 1 <= len(receipt[key]) <= 256
                       for key in ('frame_id', 'loader_id', 'execution_context_unique_id'))
                or receipt.get('frame_session_id') is not None and (not isinstance(receipt['frame_session_id'], str) or not 1 <= len(receipt['frame_session_id']) <= 256)
                or type(lifetime.get('document_generation')) is not int or lifetime['document_generation'] < 1):
            raise ProtocolError('browser_key_operation_binding')
        for key in ('installation_id', 'runtime_generation', 'peer_id'):
            if lifetime.get(key) != binding.get(key): raise ProtocolError('browser_key_operation_binding')
        if 'claim_id' in binding:
            for key in ('claim_id', 'owner_session', 'target_generation'):
                if lifetime.get(key) != binding.get(key): raise ProtocolError('browser_key_operation_binding')
            epoch = lifetime.get('claim_epoch')
            if (type(epoch) is not int or epoch < 1 or (epoch > binding['claim_epoch'] if historical else epoch != binding['claim_epoch'])):
                raise ProtocolError('browser_key_operation_binding')
        elif (lifetime.get('lease_id') != binding.get('lease_id') or lifetime.get('grant_generation') != binding.get('grant_generation')
                or lifetime.get('owner_session') != parameters.get('operation_owner')):
            raise ProtocolError('browser_key_operation_binding')
        if historical:
            generation = binding.get('document_epoch', binding.get('document_generation'))
            if type(generation) is int and lifetime['document_generation'] > generation: raise ProtocolError('browser_key_operation_binding')
        else:
            if operation != (parameters.get('operation_request_id') or request_id) or lifetime.get('document_generation') != parameters.get('expected_generation'):
                raise ProtocolError('browser_key_operation_binding')
            frame_id = parameters.get('parameters', {}).get('frame_id') or binding.get('frame_id')
            if frame_id is not None and receipt.get('frame_id') != frame_id: raise ProtocolError('browser_key_operation_binding')
            if frame_id is not None and frame_id == binding.get('frame_id') and receipt.get('loader_id') != binding.get('loader_id'):
                raise ProtocolError('browser_key_operation_binding')

    def _effect_binding(self, row):
        return {k:v for k,v in self._binding(row).items() if k not in (
            'frame_id','loader_id','document_epoch','document_generation','origin')}

    @staticmethod
    def _retired_absent_resource(row):
        proof = row.get('resource_retirement')
        if proof is None: return False
        target = row.get('target', {})
        if (not isinstance(proof, dict) or set(proof) != {'disposition','source','tab_id','browser_target_id',
                'target_generation','peer_id','runtime_generation','checked_at'}
                or proof.get('disposition') != 'target_absent' or proof.get('source') != 'chrome.tabs.get'
                or row.get('state') != 'target_closed' or row.get('debuggerAttached') is not False
                or row.get('input_eligible') is not False
                or any(proof.get(k) != target.get(k) for k in ('tab_id','browser_target_id','target_generation'))
                or not valid_id(proof.get('peer_id')) or not valid_id(proof.get('runtime_generation'))
                or type(proof.get('checked_at')) not in (int,float) or not math.isfinite(proof['checked_at'])
                or proof['checked_at'] <= 0):
            raise ProtocolError('browser_resource_retirement')
        return True

    @staticmethod
    def _validate_dialog_metadata(row):
        SelectedTabs._retired_absent_resource(row)
        if not any(key in row for key in ('dialog_resolution_state','dialog_receipt','pending_dialog')): return
        if row.get('dialog_resolution_state') not in ('not_needed','pending','acknowledged','unverified','target_gone'):
            raise ProtocolError('browser_dialog_receipt')
        pending = row.get('pending_dialog')
        if pending is not None:
            fields = {'sequence','type','has_browser_handler','opened_at','browser_target_id',
                      'document_generation','frame_session_id','frame_id','state'}
            if (not isinstance(pending,dict) or set(pending) != fields or len(json.dumps(pending).encode()) > 4096
                    or type(pending['sequence']) is not int or not 1 <= pending['sequence'] <= 2**53-1
                    or pending['type'] not in ('alert','confirm','prompt','beforeunload')
                    or type(pending['has_browser_handler']) is not bool
                    or type(pending['opened_at']) not in (int,float) or not math.isfinite(pending['opened_at']) or pending['opened_at'] < 0
                    or type(pending['document_generation']) is not int or not 1 <= pending['document_generation'] <= 2**53-1
                    or pending['state'] not in ('unresolved','unverified')
                    or row.get('dialog_resolution_state') not in ('pending','unverified')
                    or not isinstance(pending['browser_target_id'],str) or not 1 <= len(pending['browser_target_id']) <= 256
                    or any(pending[k] is not None and (not isinstance(pending[k],str) or not 1 <= len(pending[k]) <= 256)
                           for k in ('frame_id','frame_session_id'))
                    or row.get('target') and pending['browser_target_id'] != row['target']['browser_target_id']):
                raise ProtocolError('browser_pending_dialog')
        receipt = row.get('dialog_receipt')
        if receipt is None: return
        allowed = {'dialog_sequence','dialog_type','browser_target_id','frame_id','frame_session_id',
                   'operation_request_id','dispatch_attempted','dispatch_acknowledged','close_observed',
                   'close_identity_verified','requested_accept','accepted','prompt_input_matches','dialog_transition_observed'}
        if (not isinstance(receipt, dict) or set(receipt) != allowed or len(json.dumps(receipt).encode()) > 8192
                or type(receipt['dialog_sequence']) is not int or not 1 <= receipt['dialog_sequence'] <= 2**53-1
                or receipt['dialog_type'] not in ('alert','confirm','prompt','beforeunload')
                or any(type(receipt[k]) is not bool for k in ('dispatch_attempted','dispatch_acknowledged',
                    'close_observed','close_identity_verified','requested_accept','dialog_transition_observed'))
                or any(receipt[k] is not None and type(receipt[k]) is not bool for k in ('accepted','prompt_input_matches'))
                or any(not isinstance(receipt[k], str) or not 1 <= len(receipt[k]) <= 256
                       for k in ('browser_target_id','operation_request_id'))
                or any(receipt[k] is not None and (not isinstance(receipt[k],str) or not 1 <= len(receipt[k]) <= 256)
                       for k in ('frame_id','frame_session_id'))):
            raise ProtocolError('browser_dialog_receipt')
        if row.get('target') and receipt['browser_target_id'] != row['target']['browser_target_id']:
            raise ProtocolError('browser_dialog_receipt_binding')

    def _control_replay(self, request_id, payload):
        recovered=self.journal.recover(request_id,payload)
        if recovered is None:return None
        if recovered['state']=='pending':raise WorkbenchError('operation_uncertain','Original control remains pending; inspect its receipt.',request_id=request_id,effect_state='unknown')
        result=recovered['result']
        if recovered['state']=='failed':
            error=result['error'];details={k:v for k,v in error.items()if k not in ('code','message')}
            details.update(replayed=True,applied_this_call=False,original_request_id=request_id)
            raise WorkbenchError(error['code'],error['message'],**details)
        return {**result,'replayed':True,**({'applied_this_call':False}if'applied_this_call'in result else{})}

    def _publish_initialization_history(self, peer, row):
        """Fence one absence-only settlement until its correlated proof validates."""
        if row['claim_id'] not in self.input_fences and row['claim_id'] not in self.incomplete_initializations:
            self._restore_absence_intent(row)
        fence = self.input_fences.get(row['claim_id'], {})
        if not fence.get('absence_only'):
            self.incomplete_initializations[row['claim_id']] = {**row, 'peer_id': peer.id}
            return
        pending = fence.get('absence_pending')
        # Late/unrequested publications cannot settle this fenced history.
        if pending is None: return
        original = pending['original']
        if (self.incomplete_initializations.get(row['claim_id']) != original
                or pending['binding']['peer_id'] != peer.id
                or pending['binding']['current_runtime_generation'] != self.instance_id):
            raise ProtocolError('browser_absence_publication_fence')
        if row['claim_epoch'] == original['claim_epoch']: return
        if (row['claim_epoch'] != original['claim_epoch'] + 1 or row['cleanup_state'] != 'target_gone'
                or row['resource_unsettled'] is not False):
            raise ProtocolError('browser_absence_publication_state')
        published = {**copy.deepcopy(row), 'peer_id': peer.id}
        if pending.get('publication') is not None and pending['publication'] != published:
            raise ProtocolError('browser_absence_publication_changed')
        pending['publication'] = published

    def _restore_absence_intent(self, published):
        """Cold publication cannot outrun a durable unresolved original intent."""
        with self.journal._db() as db:
            matches = db.execute("""SELECT request_id,
                COALESCE(json_extract(result,'$.absence_recovery'),json_extract(result,'$.error.absence_recovery'))
                FROM operations WHERE (state='pending' OR (state='failed' AND
                COALESCE(json_extract(result,'$.error.effect_state'),'unknown')!='none')) AND
                (json_extract(result,'$.absence_recovery.binding.claim_id')=? OR
                 json_extract(result,'$.error.absence_recovery.binding.claim_id')=?) LIMIT 1001""",
                (published['claim_id'], published['claim_id'])).fetchall()
        if not matches:
            return
        if len(matches) != 1:
            raise ProtocolError('browser_absence_intent_ambiguous')
        request_id, raw = matches[0]
        if not isinstance(raw, str) or len(raw.encode()) > 65536:
            raise ProtocolError('browser_absence_intent_unverified')
        intent = json.loads(raw)
        original, binding = intent.get('original'), intent.get('binding')
        if (not isinstance(original, dict) or not isinstance(binding, dict)
                or intent.get('request_id') != request_id or binding.get('claim_id') != published['claim_id']
                or binding.get('action') != 'cleanup' or binding.get('absence_only') is not True
                or not valid_id(binding.get('nonce')) or original.get('authority') != 'cleanup_only'
                or original.get('installation_id') != self.install_id
                or binding.get('claim_epoch') != original.get('claim_epoch')
                or binding.get('original_runtime_generation') != original.get('runtime_generation')
                or any(original.get(k) != published.get(k) for k in
                    ('claim_id','owner_session','installation_id','runtime_generation','target','provenance','cleanup_policy','initialization_request_id'))
                or any(binding.get(k) != original.get(k) for k in ('owner_session','installation_id'))
                or any(binding.get(k) != original['target'].get(k) for k in
                    ('profile_id','context_id','context_kind','target_id','target_generation','tab_id','browser_target_id'))
                or published['claim_epoch'] not in (original['claim_epoch'], original['claim_epoch'] + 1)):
            raise ProtocolError('browser_absence_intent_unverified')
        interaction_contract.browser_initialization_record({k:v for k,v in original.items() if k != 'peer_id'})
        # Restore only quarantined history and its no-input fence, never a claim.
        self.incomplete_initializations[original['claim_id']] = copy.deepcopy(original)
        self.input_fences[original['claim_id']] = {'binding':self._effect_binding(original),
            'request_id':request_id, 'absence_only':True, 'absence_recovery':intent}

    def _initialization_collision(self, row):
        return any(other['claim_id'] != row['claim_id']
            and other['target']['target_id'] == row['target']['target_id']
            and other['target']['target_generation'] == row['target']['target_generation']
            and other['state'] not in ('released','revoked','target_closed') for other in self.claims.values())

    def _control_preflight(self, action, identifier, owner, parameters, *, absence_only=False):
        with self.lock:
            row = self.claims.get(identifier) or self.incomplete_initializations.get(identifier)
            if (row is None or row.get('owner_session') != owner or row.get('installation_id') != self.install_id
                    or row.get('runtime_generation') != self.instance_id and action not in ('cleanup','claim_status')):
                raise WorkbenchError('browser_claim_owner_mismatch', 'Control does not own the exact claim.', effect_state='none')
            if action != 'claim_status' and (type(parameters.get('claim_epoch')) is not int
                    or parameters['claim_epoch'] != row['claim_epoch']
                    or parameters.get('target_generation') != row['target']['target_generation']):
                raise WorkbenchError('stale_browser_claim', 'Control requires both claim_epoch and target_generation from the current exact claim; no control was dispatched.', effect_state='none')
            if action in ('stop','release') and row['state'] in ('released','revoked','target_closed'):
                raise WorkbenchError('browser_claim_ended', 'An ended claim cannot control its old target.', effect_state='none')
            peer = self.peers.get(row['peer_id'])
            trust = self.trust_records.get(getattr(peer, 'trust_key', None)) if peer else None
            if peer is None:
                raise WorkbenchError('browser_claim_owner_mismatch', 'The original control peer no longer matches this claim.', effect_state='none')
            if (not peer or not peer.connected or not trust or not trust.get('enabled')
                    or row['target']['profile_id'] != peer.identity['profile_id']
                    or row['target']['context_id'] != peer.identity.get('context_id')
                    or row['target']['context_kind'] != ('private' if peer.identity['private_context'] else 'ordinary')):
                raise WorkbenchError('browser_profile_unavailable', 'The exact control peer is unavailable.', effect_state='none')
            collision = self._initialization_collision(row)
            if collision and not (absence_only and action == 'cleanup'
                    and self.incomplete_initializations.get(identifier) is row
                    and row.get('authority') == 'cleanup_only'):
                raise WorkbenchError('browser_claim_owner_mismatch', 'Another claim owns this exact target.', effect_state='none')
            return copy.deepcopy(self._effect_binding(row))

    def _fence(self, identifier, binding, request_id, *, absence_only=False):
        with self.lock:
            row = self.claims.get(identifier) or self.incomplete_initializations.get(identifier) or self.leases.get(identifier)
            if row is None or self._effect_binding(row) != binding:
                raise WorkbenchError('browser_claim_owner_mismatch', 'Control identity changed before reservation.', effect_state='none')
            if 'lease_id'in row:
                self._authorize_legacy_owner(row,work_context.get())
                row.setdefault('control_owner',work_context.get())
            if absence_only or identifier in self.incomplete_initializations:
                with self.downloads.lock:
                    if any(self.downloads.unsettled(download) and (download.get('page_binding') or download.get('source_binding') or {}).get('claim_id') == identifier
                            for download in self.downloads.records.values()):
                        raise WorkbenchError('browser_cleanup_auxiliary_unverified', 'Absence-only cleanup cannot settle a pending download.', effect_state='none')
            else:
                self.downloads.fence_claim(identifier)
            self.input_fences[identifier] = {'binding':copy.deepcopy(binding), 'request_id':request_id,
                                             'requested_at':time.time(), **({'absence_only':True} if absence_only else {})}
        self.journal.checkpoint(request_id, {'phase':'browser_control_reserved','control_binding':binding,
                                           'input_eligible':False,'effect_state':'unknown'})

    @staticmethod
    def _validate_text_replacement_receipt(result, text):
        def refuse():
            raise WorkbenchError('selected_browser_protocol', 'The range replacement receipt changed its intent or did not establish bounded native readback.', effect_state='unknown')
        def units(value):
            return len(value.encode('utf-16-le', errors='surrogatepass')) // 2
        samples = [result.get(key) for key in ('before', 'setter_readback', 'readback')]
        for sample in samples:
            if (not isinstance(sample, dict) or type(sample.get('value')) is not str or units(sample['value']) > 4096
                    or any(type(sample.get(key)) is not int or not 0 <= sample[key] <= 4096
                           for key in ('selection_start', 'selection_length', 'selection_end', 'value_length'))
                    or sample['selection_start'] + sample['selection_length'] != sample['selection_end']
                    or sample['selection_end'] > sample['value_length'] or sample['value_length'] != units(sample['value'])
                    or type(sample.get('max_length')) is not int or not -1 <= sample['max_length'] <= 2147483647
                    or sample.get('state_verified') is not True):
                refuse()
        before, setter, after = samples
        start, end = before['selection_start'], before['selection_end']
        original = before['value'].encode('utf-16-le', errors='surrogatepass')
        expected_raw = original[:start * 2] + text.encode('utf-16-le', errors='surrogatepass') + original[end * 2:]
        no_op = expected_raw == original
        max_length = before['max_length']
        if max_length >= 0 and len(expected_raw) // 2 > max_length:
            refuse()
        for sample in samples:
            literal = sample['value'].encode('utf-16-le', errors='surrogatepass') == expected_raw
            limit_unchanged = sample['max_length'] == max_length
            within_limit = max_length < 0 or sample['value_length'] <= max_length
            exact = literal and limit_unchanged and sample['selection_start'] == (start if no_op else start + units(text)) and sample['selection_end'] == (end if no_op else start + units(text))
            if (sample.get('literal_value_matches') is not literal or sample.get('desired_state_achieved') is not exact
                    or sample.get('field_limit_unchanged') is not limit_unchanged
                    or sample.get('within_observed_field_limit') is not within_limit):
                refuse()
        dispatched = result.get('replacement_dispatched')
        if (type(dispatched) is not bool or dispatched is not (not no_op)
                or result.get('requested_text') != text
                or result.get('observed_max_length') != max_length
                or result.get('field_limit_verified') is not after['field_limit_unchanged']
                or result.get('original_selection') != {key: before[key] for key in ('selection_start', 'selection_length')}
                or result.get('setter_literal_value_matches') is not setter['literal_value_matches']
                or result.get('state_verified') is not True
                or any(result.get(key) is not after['desired_state_achieved'] for key in ('exact_requested_state', 'desired_state_achieved'))
                or result.get('mechanism') != ('public_text_control_set_range_text' if dispatched else 'verified_state_no_op')
                or result.get('dispatch_state') != ('acknowledged' if dispatched else 'not_needed')
                or result.get('dispatch_effect_state') != ('applied' if dispatched else 'none')
                or result.get('effect_state') != (('applied' if dispatched else 'none') if after['desired_state_achieved'] else 'unknown')
                or result.get('actionability_revalidated_before_dispatch') is not True
                or any(result.get(key) is not False for key in ('workbench_normalization_performed', 'events_dispatched', 'input_dispatched', 'native_input_dispatched'))
                or result.get('offset_units') != 'UTF-16 code units'
                or result.get('task_completion') != 'not_established'
                or not isinstance(result.get('normalization_policy'), str) or not result['normalization_policy']):
            refuse()

    @staticmethod
    def _input_action(action):
        return action in ('evaluate','click','click_point','fill','insert_text','press','check','select','select_text','replace_selection','scroll','drag','upload','navigate')

    @staticmethod
    def _authorize_legacy_owner(row,owner):
        if ('control_owner'in row and row['control_owner']!=owner
                or row.get('operation_owner') not in (None, owner)
                or row.get('work_session_id') not in (None,owner)):
            raise WorkbenchError('browser_claim_owner_mismatch','Original grant control belongs to another task.',effect_state='none')

    def _normal_guard(self, identifier, binding, *, input_action=True):
        # Called under the framed writer lock: do not invert broker/send locks.
        row = self.claims.get(identifier) or self.leases.get(identifier)
        if (row is None or row.get('state') != 'active'
                or input_action and (row.get('input_eligible',True)is not True
                    or row.get('dialog_resolution_state') in ('pending','unverified')
                    or row.get('keyboard_release_state')in ('prepared','held','pending','unverified','not_recorded'))
                or identifier in self.input_fences or self._binding(row) != binding
                or 'lease_id'in row and row['expires_at']<=time.time()):
            raise WorkbenchError('browser_input_revoked', 'Input eligibility changed before transport.', effect_state='none')

    def _control_cache_message(self, peer, packet):
        if not peer.connected or self.peers.get(peer.id) is not peer:raise ProtocolError('control_cache_peer')
        sequence, checked, records = packet.get('sequence'), packet.get('checked_at'), packet.get('records')
        if (type(packet.get('interaction_version'))is not int or packet['interaction_version'] != 1 or type(sequence) is not int or not 1 <= sequence <= 2**53-1
                or type(checked) not in (int,float) or not math.isfinite(checked) or checked < 0
                or not isinstance(records,list) or len(records)>32 or len(json.dumps(packet).encode())>131072):
            raise ProtocolError('control_cache_shape')
        if sequence <= self.cache_sequences.get(peer.id, 0): return
        validated = []
        for entry in records:
            if not isinstance(entry,dict) or ('claim_id' in entry) == ('lease_id' in entry): raise ProtocolError('control_cache_identity')
            identifier = entry.get('claim_id') or entry.get('lease_id')
            if not valid_id(identifier) or 'claim_id'in entry and not isinstance(entry.get('target'),dict):raise ProtocolError('control_cache_identity')
            row = self.claims.get(identifier) or self.leases.get(identifier)
            if row is None or row.get('peer_id') != peer.id: raise ProtocolError('control_cache_identity')
            self._validate_keyboard_metadata(entry)
            self._validate_dialog_metadata(entry)
            incoming, expected = self._binding({**entry,'peer_id':entry.get('peer_id',peer.id)}), self._binding(row)
            if any(type(incoming.get(k)) is not type(v) for k,v in expected.items()):raise ProtocolError('control_cache_binding_type')
            mutable = {'claim_epoch','frame_id','loader_id','document_epoch','document_generation','origin'}
            if any(incoming.get(k) != v for k,v in expected.items() if k not in mutable): raise ProtocolError('control_cache_binding')
            if incoming != expected: continue  # Honest old document/epoch publication is a gap, never repaired.
            events, last, dropped, first = entry.get('events'), entry.get('event_sequence'), entry.get('event_dropped'), entry.get('cache_retained_first')
            modal = entry.get('modal')
            if (not isinstance(events,list) or len(events)>1000 or type(last) is not int or not 0<=last<=2**53-1
                    or type(dropped) is not int or dropped<0 or type(first) not in (int,type(None))
                    or isinstance(first,bool) or len(json.dumps(entry).encode())>65536
                    or modal is not None and (not isinstance(modal,dict) or len(json.dumps(modal).encode())>4096)):
                raise ProtocolError('control_cache_budget')
            if any(not isinstance(e,dict) or type(e.get('sequence')) is not int or not 1<=e['sequence']<=last for e in events):
                raise ProtocolError('control_cache_events')
            if any(events[i]['sequence'] >= events[i+1]['sequence'] for i in range(len(events)-1)):
                raise ProtocolError('control_cache_events')
            if first != (events[0]['sequence'] if events else None): raise ProtocolError('control_cache_events')
            validated.append((identifier, {'binding':expected,'events':copy.deepcopy(events),'event_sequence':last,
                'dropped':dropped,'retained_first':first,'modal':copy.deepcopy(modal),'sequence':sequence,
                'source_checked_at':checked,'received_monotonic':time.monotonic(),'received_at':time.time()}))
        self.cache_sequences[peer.id] = sequence
        for identifier, cache in validated: self.control_cache[identifier] = cache

    def _bounded_cache(self, result, max_bytes):
        result = copy.deepcopy(result)
        while len(json.dumps(result,ensure_ascii=True).encode())>max_bytes:
            candidates = [key for key in ('events','claims','leases','legacy_key_history','incomplete_initializations','profile_trust','connections')
                          if isinstance(result.get(key),list) and result[key]]
            if not candidates: raise WorkbenchError('browser_cache_result_limit','Cached metadata exceeds the requested bound.',effect_state='none')
            key = max(candidates,key=lambda k:len(json.dumps(result[k]).encode()));result[key].pop()
            result['cache_truncated']=True;result[key+'_omitted']=result.get(key+'_omitted',0)+1
            if key=='events': result['next_sequence']=result[key][-1]['sequence'] if result[key] else result.get('requested_after_sequence',0)
        return result

    def _cached(self, identifier, action, owner, parameters, max_bytes, legacy=False):
        with self.lock:
            row = self.leases.get(identifier) if legacy else self.claims.get(identifier) or self.incomplete_initializations.get(identifier)
            if row is None: raise WorkbenchError('unknown_browser_lease' if legacy else 'browser_claim_owner_mismatch','Cached identity is absent.',effect_state='none')
            if not legacy and row.get('owner_session') != owner:
                raise WorkbenchError('browser_claim_owner_mismatch','Cached metadata belongs to another task.',effect_state='none')
            if legacy:self._authorize_legacy_owner(row,owner)
            cache = self.control_cache.get(identifier)
            if cache and cache['binding'] != self._binding(row): cache = None
            age = max(0,(time.monotonic()-cache['received_monotonic'])*1000) if cache else None
            observed = self.cache_observed_at.get(identifier)
            current_peer = self.peers.get(row.get('peer_id'))
            live_input = (row.get('state') == 'active' and current_peer is not None and current_peer.connected
                          and row.get('runtime_generation', self.instance_id) == self.instance_id
                          and row.get('input_eligible', True) is True)
            if legacy:
                live_input = live_input and row['expires_at'] > time.time()
            else:
                current_trust = self.trust_records.get(getattr(current_peer, 'trust_key', None), {})
                live_input = live_input and current_trust.get('enabled') is True
            meta = {'execution_scope':'host_cache_only','cache_available':cache is not None,'cache_age_ms':age,
                    'cache_publication_sequence':cache['sequence'] if cache else None,
                    'cache_gap':None if cache else 'control_cache_not_published_or_stale',
                    'claim_publication_age_ms':max(0,(time.monotonic()-observed)*1000) if observed else None,
                    'input_eligible':live_input and identifier not in self.input_fences,
                    'control_request_id':self.input_fences.get(identifier,{}).get('request_id'),
                    'modal':copy.deepcopy(cache['modal']) if cache else None,'server_generation':self.instance_id}
            meta['potentially_sensitive']=True
            meta['published_input_eligible']=row.get('input_eligible')
            meta['keyboard_release_state']=row.get('keyboard_release_state')
            meta['keyboard_receipt']=copy.deepcopy(row.get('keyboard_receipt'))
            if row.get('keyboard_release_state')in ('prepared','held','pending','unverified','not_recorded'):meta['input_eligible']=False
            if row.get('dialog_resolution_state') in ('pending','unverified'):meta['input_eligible']=False
            if action=='claim_status':
                public={k:copy.deepcopy(v)for k,v in row.items()if k not in ('peer_id',)}
                if 'record_kind'in row: result={'ok':True,'record_kind':row['record_kind'],'initialization_record':public,**meta}
                else: result={**public,**meta,'ok':True}
            else:
                after, limit = parameters.get('after_sequence',0),parameters.get('limit',20)
                if type(after)is not int or after<0 or type(limit)is not int or not 1<=limit<=100: raise WorkbenchError('invalid_event_cursor','Use bounded event cursor.',effect_state='none')
                events=[copy.deepcopy(e)for e in cache['events']if e['sequence']>after][:limit]if cache else []
                result={'ok':True,'lease_id':identifier,'events':events,'retained_first':cache['retained_first']if cache else None,
                    'dropped':cache['dropped']if cache else None,'gap_before_cursor':bool(cache and cache['retained_first']is not None and after<cache['retained_first']-1),
                    'next_sequence':events[-1]['sequence']if events else after,'requested_after_sequence':after,'pre_attach_gap':True,**meta}
                if not legacy: result['claim']={k:copy.deepcopy(v)for k,v in row.items()if k!='peer_id'}
        return self._bounded_cache(result,max_bytes)

    @staticmethod
    def _validate_readiness_diagnostics(value, error):
        """Fixed vocabulary only; enclosing acquisition receipt owns correlation."""
        commands = {'Emulation.setFocusEmulationEnabled': 'focus', 'Page.enable': 'domains',
                    'Runtime.enable': 'domains', 'Network.enable': 'network', 'Fetch.enable': 'body_capture',
                    'Target.setAutoAttach': 'auto_attach', 'Page.getFrameTree': 'document'}
        local_stages = {'target_identity', 'creation_persistence', 'document_poll'}
        stages = set(commands.values()) | local_stages

        def timing(number):
            return type(number) in (int, float) and 0 <= number <= 9007199254740991 and math.isfinite(number)

        def entry(row, fields):
            return (isinstance(row, dict) and set(row) == fields and isinstance(row.get('stage'), str)
                    and row['stage'] in stages
                    and (row.get('command') is None and row['stage'] in local_stages
                         or isinstance(row.get('command'), str) and commands.get(row['command']) == row['stage']))

        if (not isinstance(value, dict) or set(value) != {'stage', 'started_count', 'completed_count',
                                                        'elapsed_ms', 'pending', 'last_completed'}
                or not isinstance(value['stage'], str) or value['stage'] not in stages
                or type(value['started_count']) is not int or not 0 <= value['started_count'] <= 1000000
                or type(value['completed_count']) is not int
                or not 0 <= value['completed_count'] <= value['started_count']
                or not timing(value['elapsed_ms']) or not isinstance(value['pending'], list)
                or len(value['pending']) > 8
                or len(value['pending']) > value['started_count'] - value['completed_count']):
            raise error
        for row in value['pending']:
            if (not entry(row, {'stage', 'command', 'elapsed_ms'}) or not timing(row['elapsed_ms'])
                    or row['elapsed_ms'] > value['elapsed_ms']):
                raise error
        last = value['last_completed']
        if last is None:
            if value['completed_count'] != 0:
                raise error
        elif (not value['completed_count'] or not entry(last, {'stage', 'command', 'state'})
              or last['state'] != ('completed' if last['command'] is None else 'protocol_acknowledged')):
            raise error

    def _validate_acquisition_failure(self, receipt, *, peer, action, parameters, request_id):
        """Correlated cleanup-only history; never a claim or retry permission."""
        error = ProtocolError('browser_initialization_failure_binding')
        try:
            request_bytes = len(receipt.get('request_id', '').encode()) if isinstance(receipt, dict) and isinstance(receipt.get('request_id'), str) else 0
            receipt_bytes = len(json.dumps(receipt, ensure_ascii=True).encode())
        except (UnicodeError, TypeError, ValueError, RecursionError):
            raise error
        required = {'transport_request_id', 'request_id', 'initialization_record', 'input_authority', 'page_effects'}
        if (action != 'acquire' or not isinstance(receipt, dict)
                or not required <= set(receipt) or set(receipt) - required - {'readiness_diagnostics'}
                or receipt.get('transport_request_id') != request_id
                or not valid_id(receipt.get('transport_request_id'))
                or receipt.get('request_id') != parameters.get('operation_request_id')
                or not isinstance(receipt.get('request_id'), str)
                or not 1 <= request_bytes <= 256
                or receipt.get('input_authority') != 'never_published'
                or receipt.get('page_effects') != 'not_established'
                or receipt_bytes > 32768):
            raise error
        if 'readiness_diagnostics' in receipt:
            self._validate_readiness_diagnostics(receipt['readiness_diagnostics'], error)
        row = receipt.get('initialization_record')
        try:
            interaction_contract.browser_initialization_record(row)
        except (WorkbenchError, UnicodeError):
            raise error
        allowed = {'interaction_version', 'record_kind', 'authority', 'claim_id', 'claim_epoch',
                   'installation_id', 'runtime_generation', 'owner_session', 'state', 'target',
                   'cleanup_state', 'pointer_release_state', 'keyboard_release_state',
                   'resource_unsettled', 'debugger_attachment', 'provenance', 'cleanup_policy',
                   'response_capture_receipts', 'response_capture_overflow', 'initialization_request_id'}
        fields = {'backend', 'target_id', 'browser_target_id', 'tab_id', 'target_generation',
                  'profile_id', 'context_id', 'context_kind', 'connection_generation'}
        target = parameters.get('target')
        if (not isinstance(target, dict) or set(row) - allowed or set(row['target']) != fields
                or row['owner_session'] != parameters.get('owner_session')
                or row.get('initialization_request_id') != receipt['request_id']
                or row['installation_id'] != self.install_id
                or row['runtime_generation'] != self.instance_id
                or parameters.get('runtime_generation') != self.instance_id
                or any(row['target'][key] != target.get(key) for key in fields)
                or row['target']['connection_generation'] != peer.id):
            raise error
        with self.lock:
            published = self.incomplete_initializations.get(row['claim_id'])
            if (not peer.connected or self.peers.get(peer.id) is not peer
                    or row['claim_id'] in self.claims or published is None
                    or published.get('peer_id') != peer.id
                    or {key: value for key, value in published.items() if key != 'peer_id'} != row):
                raise error
        return copy.deepcopy(receipt)

    def _rpc(self, peer, action, parameters, timeout=None, before_send=None, _absence_receipt=False):
        if _absence_receipt:
            if action != 'claim_status' or not isinstance(parameters.get('absence_receipt_binding'), dict) or before_send is None:
                raise WorkbenchError('browser_absence_receipt_unavailable', 'Invalid internal receipt lookup.', effect_state='unknown')
            before_send()
        # Observation patience is separate from input authority and control
        # deadlines. Explicit internal overrides still retain their own bound.
        if timeout is None:
            timeout = 20 if action in ('snapshot', 'inspect') else 10
        request_id = uuid.uuid4().hex
        control = self._control_action(action, parameters)
        deadline = time.monotonic() + min(timeout,2.0) if control else None
        pending = {'event': threading.Event(),'lane':'control' if control else 'normal'}
        with self.lock:
            used = sum(p.get('lane','normal')==pending['lane'] for p in peer.pending.values())
            if not peer.connected or used >= (2 if control else 4) or len(peer.pending)>=6:
                raise WorkbenchError('selected_browser_busy', 'The selected browser connection is unavailable or busy.', effect_state='none')
            peer.pending[request_id] = pending
            identifier = parameters.get('claim_id') or parameters.get('lease_id')
            row = self.claims.get(identifier) or self.leases.get(identifier) or self.incomplete_initializations.get(identifier)
            binding = copy.deepcopy(self._binding(row)) if row else None
            admitted_keyboard = copy.deepcopy(row.get('keyboard_receipt')) if row else None
            if row and row.get('peer_id') != peer.id and not _absence_receipt:
                peer.pending.pop(request_id,None)
                raise WorkbenchError('browser_claim_owner_mismatch','Original record peer changed.',effect_state='none')
            if row and 'claim_id'in row and (parameters.get('owner_session') != row['owner_session']
                    or parameters.get('runtime_generation') != self.instance_id
                    or type(parameters.get('claim_epoch')) is not int or parameters['claim_epoch'] != row['claim_epoch']
                    or parameters.get('target_generation') != row['target']['target_generation']):
                peer.pending.pop(request_id,None)
                raise WorkbenchError('browser_claim_owner_mismatch','RPC no longer owns the current record.',effect_state='none')
            if row and not control and 'claim_id'in row and (
                    parameters.get('expected_generation') != row['target']['document_epoch']
                    or parameters.get('expected_origin') != row['target']['origin']):
                peer.pending.pop(request_id,None)
                raise WorkbenchError('stale_browser_document','RPC document changed before admission.',effect_state='none')
        def will_send():
            if before_send is not None:
                before_send()
            if not peer.connected: raise WorkbenchError('selected_browser_disconnected','Original peer disconnected.',effect_state='none')
            self.downloads.guard(action, parameters)
            if identifier and binding is not None:
                if control:
                    latest=self.claims.get(identifier)or self.leases.get(identifier)or self.incomplete_initializations.get(identifier)
                    wanted=parameters.get('control_binding') or (parameters.get('cleanup_binding') if parameters.get('lease_id') else None)
                    if wanted is None:wanted={k:v for k,v in binding.items()if k not in ('frame_id','loader_id','document_epoch','document_generation','origin')} if binding else None
                    if latest is None or self._effect_binding(latest)!=wanted: raise WorkbenchError('browser_claim_owner_mismatch','Control identity changed before send.',effect_state='none')
                else:self._normal_guard(identifier,binding,input_action=self._input_action(action))
        def historical_keyboard(receipt):
            self._validate_operation_keyboard(receipt, parameters, binding, request_id, True)
            if admitted_keyboard:
                for key in ('hold_id', 'operation_request_id', 'browser_target_id', 'frame_id', 'loader_id',
                            'frame_session_id', 'execution_context_unique_id', 'binding'):
                    if receipt.get(key) != admitted_keyboard.get(key): raise ProtocolError('browser_key_operation_binding')

        cleanup_control = action in ('stop', 'release', 'detach') or action == 'cleanup' and not parameters.get('upload_cleanup')

        def keyboard_details(payload, historical_result=False):
            details = {}
            receipt = payload.get('keyboard_receipt')
            if receipt is not None and not (historical_result and receipt == {}):
                if historical_result: historical_keyboard(receipt)
                else: self._validate_operation_keyboard(receipt, parameters, binding, request_id)
                if historical_result:
                    details['keyboard_cleanup_receipt'] = {'cleanup_request_id': parameters.get('operation_request_id') or request_id,
                        'scope': 'historical_held_key_cleanup', 'keyboard_receipt': copy.deepcopy(receipt)}
                else: details['keyboard_receipt'] = copy.deepcopy(receipt)
            cleanup = payload.get('keyboard_cleanup_receipt')
            if cleanup is not None:
                if (not cleanup_control or not isinstance(cleanup, dict) or set(cleanup) != {'cleanup_request_id', 'scope', 'keyboard_receipt'}
                        or cleanup['cleanup_request_id'] != (parameters.get('operation_request_id') or request_id)
                        or cleanup['scope'] != 'historical_held_key_cleanup'):
                    raise ProtocolError('browser_key_operation_binding')
                historical_keyboard(cleanup['keyboard_receipt'])
                details['keyboard_cleanup_receipt'] = copy.deepcopy(cleanup)
            return details

        def control_timeout(message, delivery):
            # A sampled late reply may contain cleanup evidence, but cannot
            # turn an elapsed deadline into success or authorize another effect.
            details = {'effect_state': 'unknown', 'control_delivery': delivery}
            sampled = pending.get('result')
            if isinstance(sampled, dict):
                error = sampled.get('error')
                try:
                    details.update(keyboard_details(error if isinstance(error, dict) else sampled, historical_result=not isinstance(error, dict) and cleanup_control))
                except ProtocolError:
                    details['keyboard_diagnostics'] = 'invalid'
                dialog = error.get('dialog_receipt') if isinstance(error, dict) else sampled.get('dialog_receipt')
                if dialog is not None:
                    try: self._validate_dialog_metadata({'dialog_resolution_state':'unverified','dialog_receipt':dialog})
                    except ProtocolError: details['dialog_diagnostics'] = 'invalid'
                    else: details['dialog_receipt'] = copy.deepcopy(dialog)
            return WorkbenchError('selected_browser_timeout', message, **details)
        try:
            if action == 'upload':
                self.uploads.bind_transport(parameters['upload_authority']['token'], request_id, peer.id)
            try:
                peer.send({'type': 'command', 'request_id': request_id, 'action': action, **parameters},deadline=deadline,will_send=will_send)
            except WorkbenchError as error:
                if control and error.details.get('control_delivery') == 'complete_frame_deadline_expired':
                    sampled = control_timeout('Delivered control exceeded its deadline.', 'complete_frame_deadline_expired')
                    error.details.update(sampled.details)
                raise
            if deadline is not None and time.monotonic() >= deadline:
                raise control_timeout('Delivered control exceeded its deadline.', 'complete_frame_deadline_expired')
            remaining = max(0,deadline-time.monotonic()) if deadline is not None else timeout
            if not pending['event'].wait(remaining):
                if control:
                    raise control_timeout('No correlated browser result arrived. Observe before repeating an action.', 'complete_frame_reply_unavailable')
                raise WorkbenchError('selected_browser_timeout', 'No correlated browser result arrived. Observe before repeating an action.', effect_state='unknown')
            if deadline is not None and time.monotonic() >= deadline:
                raise control_timeout('Control reply crossed its elapsed deadline.', 'complete_frame_reply_late')
            if pending.get('error'):
                raise WorkbenchError('selected_browser_disconnected', 'The selected browser disconnected during the operation.', effect_state='unknown')
            result = pending['result']
            if not result['ok']:
                code = result.get('error', {}).get('code', 'selected_browser_operation_failed')
                if not isinstance(code, str) or not re.fullmatch(r'[a-z_]{1,80}', code): code = 'selected_browser_operation_failed'
                input_error = {}
                try:
                    original_input = interaction_contract.browser_input_error_receipt(
                        result.get('error', {}), action, parameters, binding, request_id)
                    if original_input is not None:
                        input_error['input_error_receipt'] = original_input
                except WorkbenchError:
                    # An invalid additive extension cannot replace the original
                    # refusal or become evidence for retrying uncertain input.
                    input_error['input_error_receipt_status'] = 'rejected'
                dialog = result.get('error',{}).get('dialog_receipt')
                if dialog is not None:
                    try: self._validate_dialog_metadata({'dialog_resolution_state':'unverified','dialog_receipt':dialog})
                    except ProtocolError as error: raise WorkbenchError('selected_browser_protocol','Invalid bounded dialog receipt.',effect_state='unknown') from error
                try: keyboard = keyboard_details(result.get('error', {}))
                except ProtocolError as error: raise WorkbenchError('selected_browser_protocol', 'Invalid or uncorrelated keyboard receipt.', effect_state='unknown') from error
                pointer = result.get('error', {}).get('pointer_receipt')
                if pointer is not None:
                    if action != 'click_point':
                        raise WorkbenchError('selected_browser_protocol', 'Unexpected image pointer receipt.', effect_state='unknown')
                    self._validate_image_pointer_receipt(pointer)
                clicks = result.get('error', {}).get('click_receipt')
                if clicks is not None:
                    if action != 'click':
                        raise WorkbenchError('selected_browser_protocol', 'Unexpected click sequence receipt.', effect_state='unknown')
                    self._validate_click_receipt(clicks, parameters.get('parameters', {}).get('click_count', 1), completed=False)
                acquisition = result.get('error', {}).get('acquisition_failure')
                if acquisition is not None:
                    try:
                        acquisition = self._validate_acquisition_failure(acquisition, peer=peer,
                            action=action, parameters=parameters, request_id=request_id)
                    except ProtocolError as error:
                        raise WorkbenchError('selected_browser_protocol',
                            'Invalid or uncorrelated acquisition cleanup history.', effect_state='unknown') from error
                message = ('Browser acquisition failed before input authority was published. Use its initialization record only for fresh cleanup, '
                           'then rediscover before acquiring again. Page effects of setup are not established.' if acquisition is not None
                           else 'The browser refused or could not verify this operation. Inspect the selected tab.')
                if (action == 'upload' and code == 'browser_local_file_access_not_enabled'
                        and result.get('error', {}).get('effect_state') == 'none'):
                    message = ('Browser local-file access is not enabled for this extension. No file selection was attempted. '
                               'Changing this browser setting requires your explicit choice and grants access beyond Workbench folders; '
                               'Workbench Folder access and exact upload authority are still required.')
                raise WorkbenchError(code, message,
                    effect_state=result.get('error', {}).get('effect_state', 'unknown'),
                    **input_error,
                    **keyboard,
                    **({'acquisition_failure': acquisition} if acquisition is not None else {}),
                    **({'pointer_receipt':copy.deepcopy(pointer)} if pointer is not None else {}),
                    **({'click_receipt':copy.deepcopy(clicks)} if clicks is not None else {}),
                    **({'dialog_receipt':copy.deepcopy(dialog)}if dialog is not None else{}),
                    **({'drag_receipt': result['error']['drag_receipt']} if action == 'drag' and isinstance(result.get('error', {}).get('drag_receipt'), dict) else {}),
                    **({'upload_receipt': result['error']['upload_receipt']} if action == 'upload' and isinstance(result.get('error', {}).get('upload_receipt'), dict) else {}))
            if action in ('fill', 'insert_text', 'press'):
                try: keyboard_details(result)
                except ProtocolError as error: raise WorkbenchError('selected_browser_protocol', 'Invalid or uncorrelated keyboard receipt.', effect_state='unknown') from error
            if action == 'click' and (parameters.get('parameters', {}).get('click_count') is not None or result.get('click_receipt') is not None):
                self._validate_click_receipt(result.get('click_receipt'), parameters.get('parameters', {}).get('click_count', 1), completed=True)
            return result
        finally:
            with self.lock: peer.pending.pop(request_id, None)

    def active_ids(self, work_session_id=None):
        with self.lock:
            return [key for key, row in self.leases.items() if (row['state'] == 'active' and row['expires_at'] > time.time()
                    or row.get('cleanup_state') in ('pending', 'unverified')
                    or row.get('keyboard_release_state') in ('prepared','held','pending','unverified','not_recorded'))
                    and (work_session_id is None or row.get('work_session_id') == work_session_id)] + [
                    'legacy-key-history:'+key for key,row in self.legacy_key_history.items()
                    if work_session_id is None or row.get('operation_owner')==work_session_id]

    def _evaluation_preflight(self, owner, expected_origin, expected_generation, parameters):
        identifier = parameters.get('claim_id')
        self._control_preflight('evaluate_start', identifier, owner, parameters)
        with self.lock:
            row = self.claims[identifier]
            peer = self.peers[row['peer_id']]
            if (not owner or row.get('control') is not True or self.trust_records[peer.trust_key].get('control') is not True):
                raise WorkbenchError('browser_control_not_granted', 'Evaluator admission requires current browser control.', effect_state='none')
            if (type(expected_generation) is not int or expected_generation != row['target']['document_epoch']
                    or expected_origin != row['target']['origin']):
                raise WorkbenchError('stale_browser_document', 'Evaluator admission requires the original current document.', effect_state='none')
            binding = copy.deepcopy(self._binding(row))
            self._normal_guard(identifier, binding)
            return binding

    def _evaluation_current(self, task, after_dispatch=False):
        # Also runs under the framed writer lock; never acquire broker locks here.
        self.evaluations.check(task, after_dispatch=after_dispatch)
        row = self.claims.get(task['claim_id'])
        peer = self.peers.get(row.get('peer_id')) if row else None
        trust = self.trust_records.get(getattr(peer, 'trust_key', None)) if peer else None
        if (not row or row.get('state') != 'active' or self._binding(row) != task['binding']
                or row.get('control') is not True or not peer or not peer.connected
                or not trust or trust.get('enabled') is not True or trust.get('control') is not True):
            raise WorkbenchError('browser_evaluation_authority_changed', 'The original evaluator authority changed.',
                                 effect_state='unknown' if after_dispatch else 'none')

    def active_claim_ids(self, work_session_id=None):
        """Suspended claims still hold task ownership; legacy resource IDs stay separate."""
        with self.lock:
            return self.downloads.active_ids(work_session_id) + [key for key, row in self.claims.items()
                    if not self._retired_absent_resource(row) and (row['state'] in ('active', 'suspended_transport', 'suspended_contention', 'modal_blocked')
                        or row.get('cleanup_state') in ('pending', 'unverified')
                        or row.get('keyboard_release_state') in ('prepared','held','pending','unverified','not_recorded')
                        or row.get('dialog_resolution_state') in ('pending','unverified'))
                    and (work_session_id is None or row['owner_session'] == work_session_id)] + [key for key, row in self.incomplete_initializations.items()
                    if row['resource_unsettled'] and (work_session_id is None or row['owner_session'] == work_session_id)]

    def session_resource_diagnostics(self, owner, workspace, resources):
        """Classify accounted IDs without retrieving saved payloads or contacting peers.

        The legacy selected_tab_claims slot also holds downloads and incomplete
        claims. Keep that drain contract unchanged. Expose only fixed labels and
        current local-finalizer membership, never saved producer/cancel metadata.
        """
        items = []
        identifiers = (self.active_claim_ids(owner) if resources is None
                       else resources.get('selected_tab_claims', ()))
        with self.lock, self.downloads.lock:
            for identifier in identifiers:
                if len(items) == 4:
                    break
                if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier):
                    continue
                download = self.downloads.records.get(identifier)
                claim = self.claims.get(identifier)
                initial = self.incomplete_initializations.get(identifier)
                item = {'resource_id': identifier, 'legacy_slot': 'selected_tab_claims',
                        'obligation': 'owned_close_obligation'}
                if (download and download.get('owner_session') == owner
                        and download.get('workspace') == workspace):
                    item.update(kind='selected_download',
                                local_capture_in_progress=identifier in self.downloads.finalizing,
                                external_producer_liveness='not_checked')
                elif claim and claim.get('owner_session') == owner:
                    item['kind'] = 'browser_claim'
                elif initial and initial.get('owner_session') == owner:
                    item['kind'] = 'browser_claim_initialization'
                else:
                    continue
                items.append(item)
        return {'available': True, 'authority': 'diagnostic_only',
                'scope': 'current_owner_close_accounting_only', 'items': items,
                'truncated': len(items) < len(identifiers)}

    @staticmethod
    def _validate_image_pointer_receipt(receipt):
        fields = {'down_attempted', 'down_acknowledged', 'up_attempted', 'up_acknowledged', 'pointer_release_state'}
        if (not isinstance(receipt, dict) or set(receipt) != fields
                or any(type(receipt.get(k)) is not bool for k in fields - {'pointer_release_state'})
                or receipt.get('pointer_release_state') not in {'not_needed', 'acknowledged', 'held', 'unverified'}
                or receipt['down_acknowledged'] and not receipt['down_attempted']
                or receipt['up_attempted'] and not receipt['down_attempted']
                or receipt['up_acknowledged'] and not receipt['up_attempted']
                or receipt['pointer_release_state'] == 'acknowledged' and not receipt['up_acknowledged']
                or receipt['pointer_release_state'] == 'not_needed' and receipt['down_attempted']):
            raise WorkbenchError('selected_browser_protocol', 'Invalid bounded image pointer receipt.', effect_state='unknown')

    @staticmethod
    def _validate_snapshot_options(parameters):
        for key in ('include_accessibility', 'include_screenshot'):
            if parameters.get(key) is not None and type(parameters[key]) is not bool:
                raise WorkbenchError('invalid_snapshot_options', 'Select bounded AX and image options explicitly.')
        depth, nodes, scale = parameters.get('ax_depth', 5), parameters.get('ax_max_nodes', 500), parameters.get('screenshot_scale', 1)
        depth = 5 if depth is None else depth; nodes = 500 if nodes is None else nodes; scale = 1 if scale is None else scale
        if (type(depth) is not int or not 1 <= depth <= 10 or type(nodes) is not int or not 1 <= nodes <= 2000
                or type(scale) not in (int, float) or not math.isfinite(scale) or not .1 <= scale <= 1):
            raise WorkbenchError('invalid_snapshot_options', 'Use AX depth 1..10, nodes 1..2000, and image scale .1..1.')
        clip = parameters.get('screenshot_clip')
        if clip is not None and (not isinstance(clip, dict) or set(clip) != {'x', 'y', 'width', 'height'}
                or any(type(clip[k]) not in (int, float) or not math.isfinite(clip[k]) for k in clip)
                or clip['x'] < 0 or clip['y'] < 0 or clip['width'] <= 0 or clip['height'] <= 0):
            raise WorkbenchError('invalid_snapshot_options', 'Use a positive CSS viewport crop with x, y, width and height.')

    def _snapshot_frame_chain(self, result, parameters, metadata):
        """Validate and preserve the complete descendant observation binding."""
        chain = result.get('frame_chain')
        claim = result.get('claim')
        top = claim.get('target', {}) if isinstance(claim, dict) else {}
        selected = parameters.get('frame_id') or top.get('frame_id')
        def reject():
            raise WorkbenchError('selected_browser_protocol', 'The descendant frame binding was malformed or mismatched.', effect_state='none')
        if chain is None:
            if top.get('frame_id') and selected != top['frame_id']: reject()
            return None
        if not isinstance(chain, dict) or set(chain) != {'identities', 'geometry'}: reject()
        rows, geometry = chain['identities'], chain['geometry']
        if not isinstance(rows, list) or not 2 <= len(rows) <= 20 or not isinstance(geometry, dict): reject()
        if set(geometry) != {'viewports', 'boundaries'}: reject()
        def string(value): return isinstance(value, str) and 0 < len(value) <= 200
        def number(value):
            try: return type(value) in (int, float) and math.isfinite(value)
            except (TypeError, OverflowError): return False
        ids, by_id, renderer_by_session = [], {}, {}
        fields = {'frame_id', 'parent_id', 'loader_id', 'origin', 'url', 'allowed', 'session_id',
                  'renderer_root_id', 'session_epoch', 'execution_context_unique_id'}
        for index, row in enumerate(rows):
            if not isinstance(row, dict) or set(row) != fields: reject()
            if not all(string(row[k]) for k in ('frame_id', 'loader_id', 'renderer_root_id', 'execution_context_unique_id')): reject()
            if row['frame_id'] in by_id or row['allowed'] is not True: reject()
            if row['session_id'] is not None and not string(row['session_id']): reject()
            if type(row['session_epoch']) is not int or row['session_epoch'] < 0: reject()
            if not isinstance(row['url'], str) or len(row['url']) > 4096: reject()
            if not isinstance(row['origin'], str) or len(row['origin']) > 4096: reject()
            try:
                if origin(row['origin']) != row['origin']: reject()
            except (WorkbenchError, ProtocolError, ValueError, TypeError): reject()
            if index == 0:
                if row['parent_id'] is not None or row['session_id'] is not None or row['session_epoch'] != 0: reject()
                if row['renderer_root_id'] != row['frame_id'] or row['origin'] != result.get('origin'): reject()
                if top and (row['frame_id'] != top.get('frame_id') or row['loader_id'] != top.get('loader_id') or row['origin'] != top.get('origin')): reject()
            elif row['parent_id'] != rows[index-1]['frame_id']: reject()
            ids.append(row['frame_id']); by_id[row['frame_id']] = row
            renderer_by_session.setdefault(row['session_id'], row['frame_id'])
            if row['renderer_root_id'] != renderer_by_session[row['session_id']]: reject()
            renderer = by_id.get(row['renderer_root_id'])
            if not renderer or renderer['session_id'] != row['session_id'] or renderer['session_epoch'] != row['session_epoch']: reject()
            if row['session_id'] is None and row['session_epoch'] != 0: reject()
            if row['session_id'] is not None and row['session_epoch'] == 0: reject()
        last = rows[-1]
        if selected and last['frame_id'] != selected: reject()
        if any(last[a] != result.get(b) for a,b in [('frame_id','frame_id'), ('loader_id','loader_id'),
                ('session_id','frame_session_id'), ('execution_context_unique_id','execution_context_unique_id')]): reject()
        viewports, boundaries = geometry['viewports'], geometry['boundaries']
        if not isinstance(viewports, dict) or set(viewports) != set(ids): reject()
        for viewport in viewports.values():
            if not isinstance(viewport, dict) or set(viewport) != {'width','height','scroll_x','scroll_y','visual'}: reject()
            if not all(number(viewport[k]) for k in ('width','height','scroll_x','scroll_y')) or viewport['width'] <= 0 or viewport['height'] <= 0: reject()
            visual = viewport['visual']
            if not isinstance(visual, dict) or set(visual) != {'x','y','scale'} or not all(number(visual[k]) for k in visual): reject()
            if visual != {'x':0,'y':0,'scale':1}: reject()
        if not isinstance(boundaries, list) or len(boundaries) != len(rows)-1: reject()
        for index, boundary in enumerate(boundaries):
            expected = {'child_frame_id','parent_frame_id','parent_session_id','owner_backend_node_id','owner_state',
                        'content_quad_renderer_css','content_quad_root_css'}
            if not isinstance(boundary, dict) or set(boundary) != expected: reject()
            parent, child = rows[index:index+2]
            if boundary['child_frame_id'] != child['frame_id'] or boundary['parent_frame_id'] != parent['frame_id'] or boundary['parent_session_id'] != parent['session_id']: reject()
            if type(boundary['owner_backend_node_id']) is not int or boundary['owner_backend_node_id'] <= 0: reject()
            for key in ('content_quad_renderer_css','content_quad_root_css'):
                quad = boundary[key]
                if not isinstance(quad,list) or len(quad)!=8 or not all(number(v) for v in quad): reject()
                try:
                    area = sum(quad[i]*quad[(i+3)%8]-quad[(i+2)%8]*quad[(i+1)%8] for i in (0,2,4,6))
                    if not math.isfinite(area) or abs(area) < 1e-6: reject()
                except (OverflowError, ValueError): reject()
            owner = boundary['owner_state']
            if not isinstance(owner,dict) or set(owner) != {'connected','tag','rect','width','height','visibility','pointer_events'}: reject()
            if owner['connected'] is not True or owner['tag'] not in ('iframe','frame') or owner['visibility'] != 'visible' or owner['pointer_events'] == 'none': reject()
            if not isinstance(owner['pointer_events'],str) or len(owner['pointer_events'])>80: reject()
            rect = owner['rect']
            if not isinstance(rect,dict) or set(rect) != {'x','y','width','height','top','right','bottom','left'} or not all(number(v) for v in rect.values()): reject()
            if not all(number(owner[k]) and owner[k]>0 for k in ('width','height')) or rect['width']<=0 or rect['height']<=0: reject()
            if any(abs(a-b)>1e-6 for a,b in [(rect['x'],rect['left']),(rect['y'],rect['top']),
                    (rect['right']-rect['left'],rect['width']),(rect['bottom']-rect['top'],rect['height'])]): reject()
        raw = json.dumps(chain,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()
        if len(raw)>65536: reject()
        return {'frame_chain':chain,'frame_chain_sha256':hashlib.sha256(raw).hexdigest(),'raw':raw}

    @staticmethod
    def _validate_screenshot_mapping(result, parameters, screenshot, chain):
        """Bind PNG-local CSS and the actual root crop to one captured geometry."""
        def reject():
            raise WorkbenchError('selected_browser_protocol', 'The image coordinate mapping did not match its captured frame geometry.', effect_state='none')
        def finite(value):
            try: return type(value) in (int, float) and math.isfinite(value)
            except (TypeError, OverflowError): return False
        def rectangle(value):
            if (not isinstance(value, dict) or set(value) != {'x', 'y', 'width', 'height'}
                    or not all(finite(v) for v in value.values()) or value['width'] <= 0 or value['height'] <= 0): reject()
            return value
        clip = rectangle(screenshot.get('clip_css'))
        document_clip = rectangle(screenshot.get('document_clip_css'))
        scale = parameters.get('screenshot_scale')
        scale = 1 if scale is None else scale
        if (clip['x'] < 0 or clip['y'] < 0
                or not finite(screenshot.get('pixel_per_css_x')) or not finite(screenshot.get('pixel_per_css_y'))
                or screenshot['pixel_per_css_x'] != screenshot['width'] / clip['width']
                or screenshot['pixel_per_css_y'] != screenshot['height'] / clip['height']
                or not finite(screenshot.get('requested_scale')) or not .1 <= screenshot['requested_scale'] <= 1
                or screenshot['requested_scale'] != scale): reject()
        consistency = result.get('capture_consistency')
        viewport = consistency.get('viewport_before') if isinstance(consistency, dict) else None
        if (not isinstance(viewport, dict) or not all(finite(viewport.get(k)) for k in ('width', 'height', 'device_scale', 'scroll_x', 'scroll_y'))
                or any(viewport[k] <= 0 for k in ('width', 'height', 'device_scale'))
                or consistency.get('viewport_at_scan') != viewport or consistency.get('viewport_after') != viewport): reject()
        expected_clip = parameters.get('screenshot_clip')
        if expected_clip is None:
            expected_clip = {'x':0, 'y':0, 'width':viewport['width'], 'height':viewport['height']}
        if (clip != expected_clip or clip['x'] + clip['width'] > viewport['width'] or clip['y'] + clip['height'] > viewport['height']
                or document_clip != {**clip, 'x':clip['x'] + viewport['scroll_x'], 'y':clip['y'] + viewport['scroll_y']}): reject()
        root_fields = {'root_clip_css', 'root_document_clip_css'}
        if chain is None:
            if root_fields & screenshot.keys(): reject()
            return
        if not root_fields <= screenshot.keys(): reject()
        root_clip = rectangle(screenshot['root_clip_css'])
        root_document_clip = rectangle(screenshot['root_document_clip_css'])
        rows, geometry = chain['identities'], chain['geometry']
        viewports = geometry['viewports']
        selected_viewport = viewports[rows[-1]['frame_id']]
        if any(viewport[k] != selected_viewport[k] for k in ('width', 'height', 'scroll_x', 'scroll_y')): reject()
        for key in ('viewport_at_scan', 'viewport_before', 'viewport_after'):
            visual = consistency[key].get('visual_viewport')
            if (not isinstance(visual, dict) or set(visual) != {'width', 'height', 'offset_x', 'offset_y', 'page_x', 'page_y', 'scale'}
                    or not all(finite(v) for v in visual.values()) or visual['width'] <= 0 or visual['height'] <= 0
                    or any(visual[a] != selected_viewport['visual'][b] for a,b in (('offset_x','x'), ('offset_y','y'), ('scale','scale')))
                    or visual['page_x'] != viewport['scroll_x'] + visual['offset_x']
                    or visual['page_y'] != viewport['scroll_y'] + visual['offset_y']): reject()
        offsets = {rows[0]['frame_id']:(0, 0)}
        for index, boundary in enumerate(geometry['boundaries']):
            parent, child = rows[index:index+2]
            q = boundary['content_quad_root_css']
            renderer_quad = boundary['content_quad_renderer_css']
            width, height = (viewports[child['frame_id']][k] for k in ('width', 'height'))
            # The worker admits only translations for image authority. Match
            # its numerical tolerance without admitting scale/skew/rotation.
            if any(abs(v) >= 1e-7 for v in (q[2]-q[0]-width, q[4]-q[0]-width, q[6]-q[0],
                                           q[3]-q[1], q[5]-q[1]-height, q[7]-q[1]-height)): reject()
            renderer_offset = offsets[parent['renderer_root_id']]
            if any(abs(q[n] - (renderer_quad[n] + renderer_offset[n % 2])) >= 1e-7 for n in range(8)): reject()
            offsets[child['frame_id']] = (q[0], q[1])
        offset = offsets[rows[-1]['frame_id']]
        if root_clip != {**clip, 'x':clip['x'] + offset[0], 'y':clip['y'] + offset[1]}: reject()
        for row in rows:
            x, y = offsets[row['frame_id']]
            local_x, local_y = root_clip['x'] - x, root_clip['y'] - y
            ancestor_viewport = viewports[row['frame_id']]
            if (local_x < 0 or local_y < 0 or local_x + clip['width'] > ancestor_viewport['width']
                    or local_y + clip['height'] > ancestor_viewport['height']): reject()
        root_viewport = viewports[rows[0]['frame_id']]
        if root_document_clip != {**root_clip, 'x':root_clip['x'] + root_viewport['scroll_x'],
                                  'y':root_clip['y'] + root_viewport['scroll_y']}: reject()

    def _snapshot_artifacts(self, result, parameters, metadata):
        """Keep exact available privacy-filtered AX and PNG representations off the inline lane."""
        chain_metadata = self._snapshot_frame_chain(result, parameters, metadata)
        identity = result.get('observation_identity')
        requested_capture = parameters.get('include_accessibility') or parameters.get('include_screenshot')
        if not requested_capture:
            if 'accessibility' in result or 'screenshot' in result:
                raise WorkbenchError('selected_browser_protocol', 'The snapshot returned an unrequested capture.', effect_state='none')
            if not chain_metadata: return
        expected_identity = {key: result.get(key) for key in ('observation_id', 'document_generation', 'frame_id', 'loader_id',
                                                            'frame_session_id', 'execution_context_unique_id')}
        if (not isinstance(identity, dict) or identity != expected_identity or not valid_id(identity.get('observation_id'))
                or type(identity.get('document_generation')) is not int or identity['document_generation'] <= 0):
            raise WorkbenchError('selected_browser_protocol', 'The capture identity did not match its DOM observation.', effect_state='none')
        claim = result.get('claim')
        if claim:
            expected_frame = parameters.get('frame_id') or claim['target']['frame_id']
            if (identity['document_generation'] != claim['target']['document_epoch'] or identity['frame_id'] != expected_frame
                    or identity['frame_id'] == claim['target']['frame_id'] and (
                        identity['loader_id'] != claim['target']['loader_id'] or identity['frame_session_id'] is not None)):
                raise WorkbenchError('selected_browser_protocol', 'The capture changed its claimed document or selected frame.', effect_state='none')
            identity.update({key: claim[key] for key in ('claim_id', 'claim_epoch', 'owner_session', 'runtime_generation')})
            identity.update({key: claim['target'][key] for key in ('target_id', 'target_generation', 'connection_generation',
                                                                'profile_id', 'context_id', 'context_kind')})
        metadata = {**metadata, 'observation_identity': identity, 'potentially_sensitive': True}
        tree = result.get('accessibility')
        tree_raw = None
        if parameters.get('include_accessibility'):
            if not isinstance(tree, dict) or not isinstance(tree.get('nodes'), list) or len(tree['nodes']) > (parameters.get('ax_max_nodes') or 500):
                raise WorkbenchError('selected_browser_protocol', 'The AX capture exceeded its selected bound.', effect_state='none')
            tree_raw = json.dumps({'observation_identity': identity, 'accessibility': tree}, ensure_ascii=True).encode()
            if len(tree_raw) > 2097152:
                raise WorkbenchError('accessibility_result_limit', 'The available AX representation exceeds 2 MiB.', effect_state='none')
        elif tree is not None:
            raise WorkbenchError('selected_browser_protocol', 'The snapshot returned an unrequested AX capture.', effect_state='none')
        screenshot = result.get('screenshot')
        screenshot_raw = None
        if parameters.get('include_screenshot'):
            if not isinstance(screenshot, dict) or not isinstance(screenshot.get('screenshot_base64'), str) or len(screenshot['screenshot_base64']) > 2796204:
                raise WorkbenchError('selected_browser_protocol', 'The PNG capture exceeded its bound.', effect_state='none')
            screenshot = dict(screenshot)
            try: screenshot_raw = base64.b64decode(screenshot.pop('screenshot_base64'), validate=True)
            except (ValueError, TypeError):
                raise WorkbenchError('selected_browser_protocol', 'The PNG capture was malformed.', effect_state='none')
            if (len(screenshot_raw) > 2097152 or len(screenshot_raw) < 24 or not screenshot_raw.startswith(b'\x89PNG\r\n\x1a\n')
                    or hashlib.sha256(screenshot_raw).hexdigest() != screenshot.get('screenshot_sha256')
                    or len(screenshot_raw) != screenshot.get('screenshot_bytes')
                    or int.from_bytes(screenshot_raw[16:20], 'big') != screenshot.get('width')
                    or int.from_bytes(screenshot_raw[20:24], 'big') != screenshot.get('height')
                    or type(screenshot.get('width')) is not int or type(screenshot.get('height')) is not int
                    or not 0 < screenshot['width'] * screenshot['height'] <= 4194304):
                raise WorkbenchError('selected_browser_protocol', 'The PNG bytes did not match their bounded receipt.', effect_state='none')
            self._validate_screenshot_mapping(result, parameters, screenshot,
                chain_metadata['frame_chain'] if chain_metadata else None)
        elif screenshot is not None:
            raise WorkbenchError('selected_browser_protocol', 'The snapshot returned an unrequested image capture.', effect_state='none')

        # No artifact publication occurs until every requested representation is valid.
        if chain_metadata:
            chain = chain_metadata['frame_chain']
            capture = self.store.put_bytes(chain_metadata['raw'], json.dumps({**metadata,
                'kind':'selected_browser_frame_chain','observation_id':result['observation_id']}))
            result.update(frame_chain_sha256=chain_metadata['frame_chain_sha256'], frame_chain_artifact=capture['artifact_id'])
            metadata = {**metadata,'frame_chain':chain,'frame_chain_sha256':result['frame_chain_sha256'],
                'frame_chain_artifact':result['frame_chain_artifact']}
        if tree_raw is not None:
            capture = self.store.put_bytes(tree_raw, json.dumps({**metadata, 'kind': 'selected_browser_accessibility'}))
            result['accessibility'] = {key: value for key, value in tree.items() if key != 'nodes'}
            result['accessibility'].update(node_count=len(tree['nodes']), artifact=capture, inline_complete=False)
            result['accessibility_artifact'] = capture['artifact_id']
        if screenshot_raw is not None:
            capture = self.store.put_bytes(screenshot_raw, json.dumps({**metadata, 'kind': 'selected_browser_screenshot', 'mapping': screenshot}))
            result.update(screenshot=screenshot, screenshot_artifact=capture['artifact_id'], screenshot_capture=capture, mime_type='image/png')

    def _dialog_operation(self, workspace, action, request_id, max_bytes, parameters, _journaled=False):
        owner = work_context.get()
        identifier = parameters.get('claim_id')
        sequence = parameters.get('dialog_sequence')
        if not valid_id(identifier) or type(sequence) is not int or not 1 <= sequence <= 2**53-1:
            raise WorkbenchError('invalid_dialog_sequence', 'Use the exact claim and dialog_sequence from cached status.', effect_state='none')
        prompt = parameters.get('dialog_prompt_text')
        if action == 'dialog_handle':
            if type(parameters.get('dialog_accept')) is not bool:
                raise WorkbenchError('invalid_dialog_choice', 'Choose dialog_accept explicitly.', effect_state='none')
            try: prompt_bytes = len(prompt.encode()) if isinstance(prompt,str) else 0
            except UnicodeEncodeError as error:
                raise WorkbenchError('invalid_dialog_prompt','Use valid UTF-8 prompt text.',effect_state='none') from error
            if prompt is not None and (not isinstance(prompt,str) or prompt_bytes > 8192):
                raise WorkbenchError('invalid_dialog_prompt','Use at most8192 UTF-8 bytes of prompt text.',effect_state='none')
            if not _journaled:
                if request_id is None: raise WorkbenchError('request_id_required','Dialog effects require a stable request_id.')
                payload = {'tool':'selected_browser','workspace':workspace,'action':action,'owner_session':owner,
                           'parameters':parameters}
                replay = self._control_replay(request_id,payload)
                if replay is not None: return replay
                self._control_preflight(action,identifier,owner,parameters)
                return self.journal.run(request_id,payload,
                    lambda:self._dialog_operation(workspace,action,request_id,max_bytes,parameters,True),
                    resource='browser-dialog:'+identifier,
                    initial_checkpoint={'phase':'before_dialog_control','claim_id':identifier,'dialog_sequence':sequence,'effect_state':'unknown'})
        binding = self._control_preflight(action,identifier,owner,parameters)
        with self.lock:
            row = self.claims[identifier];peer = self.peers[row['peer_id']]
            if row['state'] != 'active' or identifier in self.input_fences or row['runtime_generation'] != self.instance_id:
                raise WorkbenchError('browser_claim_suspended','Dialog control requires this current active claim.',effect_state='none')
            if action == 'dialog_handle' and (row.get('control') is not True or self.trust_records[peer.trust_key].get('control') is not True):
                raise WorkbenchError('browser_control_not_granted','Dialog effects need the existing browser control approval.',effect_state='none')
            command = {'claim_id':identifier,'claim_epoch':row['claim_epoch'],'target_generation':row['target']['target_generation'],
                'interaction_version':1,'runtime_generation':self.instance_id,'owner_session':owner,'control_binding':binding,
                'profile_id':row['target']['profile_id'],'context_id':row['target']['context_id'],'context_kind':row['target']['context_kind'],
                'trust_id':self.trust_records[peer.trust_key]['trust_id'],'operation_request_id':request_id,'parameters':parameters}
        result = self._rpc(peer,action,command)
        if (result.get('claim_id') != identifier or result.get('owner_session') != owner
                or result.get('installation_id') != self.install_id or result.get('runtime_generation') != self.instance_id
                or result.get('target',{}).get('browser_target_id') != binding['browser_target_id']):
            raise WorkbenchError('selected_browser_protocol','Dialog result changed its original claim binding.',effect_state='unknown')
        self._validate_dialog_metadata(result)
        if action == 'dialog_read':
            dialog = result.get('dialog')
            if (not isinstance(dialog,dict) or dialog.get('sequence') != sequence
                    or any(not isinstance(dialog.get(k),str) or len(dialog[k].encode())>8192 for k in ('message','default_prompt'))):
                raise WorkbenchError('selected_browser_protocol','Dialog read exceeded its selected-content bound.',effect_state='unknown')
        else:
            receipt = result.get('dialog_receipt')
            if not receipt or receipt['dialog_sequence'] != sequence or receipt['operation_request_id'] != request_id:
                raise WorkbenchError('selected_browser_protocol','Dialog receipt did not match the original request.',effect_state='unknown')
        result.update(server_generation=self.instance_id,checked_at=time.time(),potentially_sensitive=True)
        raw = json.dumps(result,ensure_ascii=True).encode()
        if len(raw)>max_bytes:
            raise WorkbenchError('dialog_result_limit','Increase max_bytes to read this bounded dialog result inline.',
                required_max_bytes=len(raw),effect_state='none' if action=='dialog_read' else 'unknown',
                **({'dialog_receipt':result['dialog_receipt']} if action=='dialog_handle' else{}))
        return result

    def _durable_operation(self, workspace, action, expected_origin, expected_generation,
                           request_id, max_bytes, _journaled=False, _evaluation_admission=None, _initialization_absence_only=False, **parameters):
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes 4096..262144.')
        owner = work_context.get()
        if action != 'discover' and (not isinstance(owner, str) or not owner or len(owner.encode()) > 128):
            raise WorkbenchError('work_session_required', 'Browser claims require an explicit work session.')
        if action in ('dialog_read','dialog_handle'):
            return self._dialog_operation(workspace,action,request_id,max_bytes,parameters)
        if action == 'acquire':
            interaction_contract.browser_identity(parameters.get('target'))
            with self.lock:self._history_target_guard(parameters['target'])
        if parameters.get('claim_id') and action in ('claim_status','events'):
            recovered = self._recover_absence_receipt(owner, parameters['claim_id'], request_id) if action == 'claim_status' else None
            cached = self._cached(parameters['claim_id'],action,owner,parameters,max_bytes)
            return {**cached, **({'absence_receipt_reconciliation':recovered} if recovered else {})}
        effects = ('acquire', 'create', 'release', 'stop', 'cleanup', 'evaluate', 'click', 'click_point', 'fill', 'insert_text', 'press', 'check', 'select', 'select_text', 'replace_selection', 'scroll', 'drag', 'upload', 'navigate')
        if action in effects and not _journaled:
            if request_id is None:
                raise WorkbenchError('request_id_required', 'Effects require a stable request_id.')
            payload = {'tool': 'selected_browser', 'interaction_version': 1, 'workspace': workspace, 'action': action,
                       'owner_session': owner, 'expected_origin': expected_origin, 'expected_generation': expected_generation,
                       'parameters': parameters}
            if self._input_action(action):
                replay = self._control_replay(request_id, payload)
                if replay is not None: return replay
                with self.lock:
                    row = self.claims.get(parameters.get('claim_id'))
                    if (row and row.get('owner_session') == owner and row.get('runtime_generation') == self.instance_id
                            and row.get('installation_id') == self.install_id):
                        # Fresh input refuses quarantine before normal lock
                        # waits. Exact receipt recovery above has no new effect.
                        self._normal_guard(parameters['claim_id'], self._binding(row))
            def dispatch():
                self.journal.checkpoint(request_id, {**(self.evaluations.checkpoint(_evaluation_admission) if _evaluation_admission else {}),
                    'phase': 'before_browser_claim_dispatch', 'effect_state': 'unknown'})
                result = self._durable_operation(workspace, action, expected_origin, expected_generation,
                    request_id, max_bytes, True, _evaluation_admission=_evaluation_admission,
                    _initialization_absence_only=absence_only, **parameters)
                if action == 'cleanup' and result.get('resource_retirement'):
                    witnesses = self.evaluations.absence_witnesses(result, request_id, payload)
                    if witnesses:
                        result['browser_evaluation_retirements'] = witnesses
                return result
            resource = parameters.get('claim_id') or (parameters.get('target') or {}).get('target_id') or parameters.get('context_id', '')
            if not isinstance(resource, str):
                raise WorkbenchError('invalid_browser_claim', 'Use an exact browser claim or target identity.')
            with self.lock:
                current = self.claims.get(resource, {})
                pending_input = (action in ('drag', 'upload') and parameters.get('claim_id') == resource
                    and current.get('owner_session') == owner and current.get('runtime_generation') == self.instance_id
                    and current.get('state') == 'active' and type(parameters.get('claim_epoch')) is int
                    and parameters['claim_epoch'] == current.get('claim_epoch')
                    and parameters.get('target_generation') == current.get('target', {}).get('target_generation')
                    and type(expected_generation) is int and expected_generation == current.get('target', {}).get('document_epoch')
                    and expected_origin == current.get('target', {}).get('origin'))
                pending = self.pending_uploads if action == 'upload' else self.pending_drags
                if pending_input:
                    pending[resource] = pending.get(resource, 0) + 1
                control = action in ('stop','release','cleanup') and parameters.get('upload_stage_id') is None
            if control:
                replay=self._control_replay(request_id,payload)
                if replay is not None:return replay
            with self.lock:
                history = self.incomplete_initializations.get(resource)
                absence_only = bool(control and action == 'cleanup' and history and self._initialization_collision(history))
            control_binding = self._control_preflight(action,resource,owner,parameters,**({"absence_only":True} if absence_only else {})) if control else None
            try:
                result = self.journal.run(request_id,payload,dispatch,
                    resource=('browser-control:' if control else 'browser-claim:')+resource,
                    initial_checkpoint=self.evaluations.checkpoint(_evaluation_admission) if _evaluation_admission else None,
                    on_reserved=(lambda:self.evaluations.reserved(_evaluation_admission)) if _evaluation_admission else (lambda:self._fence(resource,control_binding,request_id,**({"absence_only":True} if absence_only else {}))) if control else None)
                if action == 'cleanup' and result.get('browser_evaluation_retirements'):
                    self.evaluations.active_ids()  # Release accounting pins only after this cleanup receipt committed.
                return result
            finally:
                if pending_input:
                    with self.lock:
                        remaining = pending[resource] - 1
                        if remaining: pending[resource] = remaining
                        else: pending.pop(resource)
        if action == 'cleanup' and parameters.get('upload_stage_id') is not None:
            return self._upload_cleanup(workspace, owner, expected_origin, expected_generation, parameters)
        if action not in ('discover', 'acquire', 'create', 'release', 'stop', 'cleanup', 'claim_status', 'inspect', 'snapshot', 'events', 'body', 'document', 'evaluate', 'click', 'click_point', 'fill', 'insert_text', 'press', 'check', 'select', 'select_text', 'replace_selection', 'scroll', 'drag', 'upload', 'navigate'):
            raise WorkbenchError('invalid_browser_action', 'Use a supported browser claim action.')
        claim_id = parameters.get('claim_id')
        with self.lock:
            initialization = claim_id not in self.claims and claim_id in self.incomplete_initializations
        if initialization:
            if action not in ('claim_status', 'cleanup'):
                raise WorkbenchError('browser_initialization_cleanup_only', 'This historical initialization permits status and cleanup only.', effect_state='none')
            return self._initialization_operation(owner, action, claim_id, parameters, absence_only=_initialization_absence_only, control_request_id=request_id)
        target = parameters.get('target')
        selected_lock = contextlib.nullcontext()
        with self.lock:
            if action == 'acquire':
                interaction_contract.browser_identity(target)
                binding = target
            elif claim_id is not None:
                if not valid_id(claim_id):
                    raise WorkbenchError('invalid_browser_claim', 'Use the claim returned by browser acquisition.')
                current = self.claims.get(claim_id)
                if (current is None or current['owner_session'] != owner
                        or current['runtime_generation'] != self.instance_id and action not in ('cleanup', 'claim_status')):
                    raise WorkbenchError('browser_claim_owner_mismatch', 'The claim does not belong to this task and runtime.', effect_state='none')
                binding = current['target']
                selected_lock = contextlib.nullcontext() if action in ('stop','release','cleanup') else self.claim_locks[claim_id]
            else:
                binding = dict(parameters)
                # Optional caller context defaults to ordinary; exact discovered
                # targets and retained claims must keep their validated identity.
                if binding.get('context_kind') is None:
                    binding['context_kind'] = 'ordinary'
            profile_id, context_id = binding.get('profile_id'), binding.get('context_id')
            context_kind = binding.get('context_kind', 'ordinary')
            if not valid_id(profile_id) or not valid_id(context_id) or context_kind not in ('ordinary', 'private'):
                raise WorkbenchError('invalid_browser_profile', 'Select an exact paired profile and context from browser status.')
            candidates = [p for p in self.peers.values() if p.connected and p.identity.get('interaction_version') == 1
                          and p.identity['profile_id'] == profile_id and p.identity.get('context_id') == context_id
                          and p.identity['private_context'] == (context_kind == 'private')]
            if len(candidates) != 1:
                raise WorkbenchError('browser_profile_unavailable', 'The paired browser context is unavailable or ambiguous.', effect_state='none')
            peer = candidates[0]
            trust = self.trust_records.get(getattr(peer, 'trust_key', None))
            if not trust or not trust.get('enabled') or trust['context_kind'] != context_kind:
                raise WorkbenchError('browser_setup_required', 'Complete initial local browser setup for this context.', effect_state='none')
            if action in ('create', 'acquire'):
                capture = parameters.get('capture_responses')
                if capture is not None:
                    if type(peer.identity.get('capture_responses_version')) is not int or peer.identity['capture_responses_version'] != 1:
                        raise WorkbenchError('browser_capture_policy_unsupported', 'This paired browser producer cannot narrow response capture.', effect_state='none')
                    if capture and trust.get('network') is not True:
                        raise WorkbenchError('network_capture_not_granted', 'Response capture requires existing local network permission.', effect_state='none')
                effective_network = trust['network'] if capture is None else trust['network'] and capture
                if action == 'acquire':
                    for existing in self.claims.values():
                        if (existing['state'] == 'active' and existing['owner_session'] == owner and existing['peer_id'] == peer.id
                                and existing['target']['target_id'] == target['target_id']
                                and existing['target']['target_generation'] == target['target_generation']
                                and existing.get('network') is not effective_network):
                            raise WorkbenchError('browser_capture_policy_conflict', 'Release the existing claim before choosing another response-capture policy.', effect_state='none')
            command = {'interaction_version': 1, 'runtime_generation': self.instance_id, 'profile_id': profile_id,
                       'context_id': context_id, 'context_kind': context_kind, 'trust_id': trust['trust_id'],
                       'owner_session': owner, 'parameters': {k: v for k, v in parameters.items() if k not in ('target', 'claim_id')}}
            command['operation_request_id'] = request_id
            if claim_id and action in ('stop','release','cleanup') and parameters.get('upload_stage_id') is None:
                command['control_binding'] = copy.deepcopy(self.input_fences.get(claim_id,{}).get('binding') or self._effect_binding(current))
            cleanup_binding = None
            if claim_id and current['runtime_generation'] != self.instance_id:
                if current['peer_id'] != peer.id:
                    raise WorkbenchError('browser_claim_owner_mismatch', 'Read the original claim from the current paired browser peer before cleanup.', effect_state='none')
                cleanup_binding = {'action': action, 'claim_id': claim_id, 'claim_epoch': current['claim_epoch'],
                    'original_runtime_generation': current['runtime_generation'], 'current_runtime_generation': self.instance_id,
                    'peer_id': peer.id, 'installation_id': self.install_id, 'owner_session': owner, 'profile_id': profile_id,
                    'context_id': context_id, 'context_kind': context_kind, 'target_id': current['target']['target_id'],
                    'target_generation': current['target']['target_generation'], 'nonce': uuid.uuid4().hex}
                command['cleanup_binding'] = cleanup_binding
            if action == 'acquire':
                if target['connection_generation'] != peer.id:
                    raise WorkbenchError('stale_browser_target', 'Discover the current browser connection before acquisition.', effect_state='none')
                command['target'] = target
            if action == 'create':
                url = parameters.get('url')
                if not isinstance(url, str) or len(url.encode()) > 8192:
                    raise WorkbenchError('invalid_url', 'Use a bounded HTTP or HTTPS URL.')
                try:
                    origin(url)
                except (ProtocolError, ValueError) as error:
                    raise WorkbenchError('invalid_url', 'Use a valid HTTP or HTTPS URL and port.', effect_state='none') from error
                if parameters.get('cleanup_policy') not in ('keep', 'close_on_release'):
                    raise WorkbenchError('invalid_cleanup_policy', 'Choose keep or close_on_release for an agent-created tab.')
                command.update(url=url, cleanup_policy=parameters['cleanup_policy'])
            if claim_id:
                command.update(claim_id=claim_id, claim_epoch=parameters.get('claim_epoch'),
                               target_generation=parameters.get('target_generation'), expected_origin=expected_origin,
                               expected_generation=expected_generation)
                if action in ('release', 'stop') and current['state'] in ('released', 'revoked', 'target_closed'):
                    raise WorkbenchError('browser_claim_ended', 'The ended claim no longer owns this browser target.', effect_state='none')
                if action != 'claim_status' and (type(command['claim_epoch']) is not int or command['claim_epoch'] != current['claim_epoch']
                        or command['target_generation'] != current['target']['target_generation']):
                    raise WorkbenchError('stale_browser_claim', 'Use both claim_epoch and target_generation from the current exact claim; no control was dispatched.', effect_state='none')
                if action == 'cleanup' and current.get('cleanup_state') != 'unverified' and current['state'] not in ('suspended_transport','suspended_contention'):
                    raise WorkbenchError('browser_cleanup_not_pending', 'This claim has no unverified cleanup to recover.', effect_state='none')
                if action not in ('release', 'stop', 'cleanup', 'claim_status'):
                    if current['state'] != 'active' or current['peer_id'] != peer.id:
                        raise WorkbenchError('browser_claim_suspended', 'Reconcile this target before further actions.', effect_state='none')
                    if type(expected_generation) is not int or expected_generation != current['target']['document_epoch']:
                        raise WorkbenchError('stale_browser_document',
                            'Use expected_generation=claim.target.document_epoch and expected_origin=claim.target.origin from current claim_status, then observe before acting.',
                            effect_state='none', required_arguments=['expected_generation', 'expected_origin'],
                            current_document_binding={'expected_generation': current['target']['document_epoch'],
                                                      'expected_origin': current['target']['origin']})
        with selected_lock:
            if claim_id and action not in ('stop','release','cleanup','claim_status'):
                self._normal_guard(claim_id,self._binding(current),input_action=self._input_action(action))
            if claim_id and action in ('release', 'stop'):
                with self.lock:
                    latest = self.claims[claim_id]
                    if latest['state'] in ('released', 'revoked', 'target_closed'):
                        raise WorkbenchError('browser_claim_ended', 'The ended claim no longer owns this browser target.', effect_state='none')
                    if (latest['claim_epoch'] != command['claim_epoch'] or latest['target']['target_generation'] != command['target_generation']
                            or any(other['claim_id'] != claim_id and other['target']['target_id'] == latest['target']['target_id']
                                and other['target']['target_generation'] == latest['target']['target_generation']
                                and other['state'] not in ('released', 'revoked', 'target_closed') for other in self.claims.values())):
                        raise WorkbenchError('browser_claim_owner_mismatch', 'This claim no longer owns the exact browser target.', effect_state='none')
            if action == 'upload':
                if not current.get('control') or trust.get('file_upload') is not True:
                    raise WorkbenchError('browser_file_upload_not_granted', 'Enable file uploads explicitly in the local extension popup.', effect_state='none')
                upload_binding = self._upload_binding(current, peer, owner, expected_origin, expected_generation, parameters)
                self._upload_current(peer, upload_binding)
                authority = self.uploads.prepare(workspace, parameters['file_path'], parameters['expected_sha256'], parameters['expected_bytes'], upload_binding, request_id)
                command['upload_authority'] = authority
                command['parameters'] = {k: v for k, v in command['parameters'].items() if k not in ('file_path', 'expected_sha256', 'expected_bytes')}
                self.journal.checkpoint(request_id, {'phase': 'before_upload_dispatch', 'upload_stage': authority['file'], 'effect_state': 'unknown'})
                try:
                    result = self._rpc(peer, action, command)
                except WorkbenchError as error:
                    retained = self.uploads.outcome(authority['stage_id'], 'selection_unknown' if error.details.get('effect_state') == 'unknown' else 'refused')
                    error.details['upload_stage'] = retained
                    raise
                result['upload_stage'] = self.uploads.outcome(authority['stage_id'], 'selected')
            else:
                if _evaluation_admission:
                    self._evaluation_current(_evaluation_admission)
                    result = self._rpc(peer, action, command, before_send=lambda:self._evaluation_current(_evaluation_admission))
                    self._evaluation_current(_evaluation_admission, after_dispatch=True)
                else:
                    result = self._rpc(peer, action, command)
            if action in ('acquire', 'create', 'release', 'stop', 'cleanup', 'claim_status'):
                expected_runtime = current['runtime_generation'] if cleanup_binding else self.instance_id
                interaction_contract.claim(result, backend='browser', runtime_generation=expected_runtime, owner_session=owner,
                    expected_claim_id=claim_id, require_active=action in ('acquire', 'create'))
                if action in ('acquire','create'):
                    if result.get('network') is not effective_network or not self._capture_policy_valid(peer, result, trust):
                        raise WorkbenchError('selected_browser_protocol', 'The acquired capture policy differs from admission.', effect_state='unknown')
                    try:self._history_target_guard(result['target'])
                    except WorkbenchError as error:raise WorkbenchError('browser_key_history_unsettled','Acquisition result intersects retained cleanup-only history.',effect_state='unknown')from error
                if cleanup_binding and result.get('cleanup_binding') != cleanup_binding:
                    raise WorkbenchError('selected_browser_protocol', 'The cleanup result changed its original-claim/current-peer binding.', effect_state='unknown')
                if result['installation_id'] != self.install_id or any(result['target'].get(k) != binding.get(k) for k in ('profile_id', 'context_id', 'context_kind')):
                    raise WorkbenchError('selected_browser_protocol', 'The result changed browser context.', effect_state='unknown')
                if action == 'acquire' and any(result['target'].get(k) != target.get(k) for k in ('target_id', 'target_generation', 'browser_target_id', 'tab_id', 'connection_generation')):
                    raise WorkbenchError('selected_browser_protocol', 'The acquired target changed its discovered identity.', effect_state='unknown')
                with self.lock:
                    published = self.claims.get(result['claim_id'])
                    if (published is None or any(published.get(k) != result.get(k) for k in ('state', 'claim_epoch', 'owner_session', 'installation_id', 'runtime_generation', 'cleanup_state', 'network', 'control', 'capture_responses'))
                            or published['target'] != result['target']):
                        raise WorkbenchError('selected_browser_protocol', 'The returned claim was not published by this browser connection.', effect_state='unknown')
            elif action == 'discover':
                if result.get('interaction_version') != 1 or not isinstance(result.get('targets'), list) or len(result['targets']) > 100:
                    raise WorkbenchError('selected_browser_protocol', 'The browser inventory was malformed.', effect_state='unknown')
                for row in result['targets']:
                    interaction_contract.browser_identity(row)
                    if row['connection_generation'] != peer.id or any(row.get(k) != binding.get(k, 'ordinary' if k == 'context_kind' else None) for k in ('profile_id', 'context_id', 'context_kind')):
                        raise WorkbenchError('selected_browser_protocol', 'The inventory crossed its authenticated context.', effect_state='unknown')
            else:
                returned_claim = interaction_contract.claim(result.get('claim'), backend='browser', runtime_generation=self.instance_id,
                    owner_session=owner, expected_claim_id=claim_id)
                # Validate immutable context as well as opaque target IDs before
                # returning observations or assigning capture privacy labels.
                identity_fields = ('target_id', 'target_generation', 'profile_id', 'context_id',
                                   'context_kind', 'browser_target_id', 'tab_id', 'connection_generation')
                if (returned_claim['installation_id'] != self.install_id
                        or any(returned_claim['target'][key] != current['target'][key] for key in identity_fields)):
                    raise WorkbenchError('selected_browser_protocol', 'The response changed the claimed target or browser context.', effect_state='unknown')
                if action == 'replace_selection':
                    self._validate_text_replacement_receipt(result, parameters['text'])
                if action == 'select_text':
                    readback = result.get('readback', {})
                    requested = {key: parameters[key] for key in ('selection_start', 'selection_length')}
                    exact = isinstance(readback, dict) and (readback.get('selection_start') == requested['selection_start']
                             and readback.get('selection_length') == requested['selection_length'])
                    if (not isinstance(readback, dict) or result.get('requested_selection') != requested
                            or any(type(readback.get(key)) is not int or not 0 <= readback[key] <= 32768
                                   for key in ('selection_start', 'selection_length', 'selection_end', 'value_length'))
                            or readback['selection_start'] + readback['selection_length'] != readback['selection_end']
                            or readback['selection_end'] > readback['value_length']
                            or readback.get('state_verified') is not True or readback.get('value_unchanged') is not True
                            or result.get('state_verified') is not True
                            or any(result.get(key) is not exact for key in ('exact_requested_state', 'desired_state_achieved'))
                            or readback.get('desired_state_achieved') is not exact
                            or result.get('offset_units') != 'UTF-16 code units'
                            or result.get('native_input_dispatched') is not False or result.get('input_dispatched') is not False
                            or result.get('selected_contents_returned') is not False
                            or result.get('task_completion') != 'not_established'):
                        raise WorkbenchError('selected_browser_protocol', 'The text selection receipt did not establish its exact sampled range or changed its intent.', effect_state='unknown')
                if action == 'click_point':
                    self._validate_image_pointer_receipt(result.get('pointer_receipt'))
                    if (result.get('screenshot_sha256') != parameters['screenshot_sha256']
                            or result.get('image_point') != {'x':parameters['image_x'], 'y':parameters['image_y']}
                            or result.get('content_frozen') is not False or result.get('task_completion') != 'not_established'
                            or result.get('effect_state') != 'unknown'
                            or result.get('dispatch_effect_state') != ('unknown' if 'input_evidence' in result else 'applied')):
                        raise WorkbenchError('selected_browser_protocol', 'The image click receipt changed its original intent or claimed an unverified task effect.', effect_state='unknown')
                result['operation_receipt'] = interaction_contract.receipt(request_id, returned_claim, action, result)
                if action == 'snapshot':
                    self._snapshot_artifacts(result, parameters, {'claim_id': claim_id, 'context_id': context_id,
                        'private_context': context_kind == 'private', 'origin': expected_origin})
                encoded = result.pop('body_base64', None)
                if encoded is not None:
                    raw_body = base64.b64decode(encoded, validate=True)
                    if len(raw_body) > 2097152:
                        raise WorkbenchError('response_body_limit', 'The browser body exceeds its capture bound.', effect_state='unknown')
                    capture = self.store.put_bytes(raw_body, json.dumps({'kind': 'browser_claim_body', 'claim_id': claim_id,
                        'context_id': context_id, 'private_context': context_kind == 'private', 'potentially_sensitive': True,
                        'origin': expected_origin, 'document_generation': expected_generation, 'representation': result.get('representation')}))
                    result.update(body_artifact=capture['artifact_id'], capture_id=capture['capture_id'], body_bytes=len(raw_body))
            result.update(server_generation=self.instance_id, potentially_sensitive=True)
            raw = json.dumps(result, ensure_ascii=True).encode()
            if len(raw) > max_bytes:
                capture = self.store.put_bytes(raw, json.dumps({'kind': 'browser_claim_result', 'context_id': context_id,
                    'private_context': context_kind == 'private', 'potentially_sensitive': True}))
                wrapper = {'ok': True, 'result_artifact': capture['artifact_id'], 'capture_id': capture['capture_id'], 'inline_complete': False,
                    **{key: result[key] for key in ('observation_identity', 'accessibility_artifact', 'screenshot_artifact', 'mime_type',
                        'frame_chain_sha256', 'frame_chain_artifact', 'operation_receipt', 'effect_state',
                        'verification_state', 'task_completion') if key in result}}
                return add_result_continuation(wrapper, capture, max_bytes)
            return result

    def _recover_absence_receipt(self, owner, claim_id, original_request_id=None):
        """Read one original persisted absence receipt; never replay its probe."""
        with self.lock:
            row = self.incomplete_initializations.get(claim_id)
            fence = self.input_fences.get(claim_id, {})
            if row is None or row.get('owner_session') != owner:
                return  # The ordinary cached owner check remains authoritative.
            if fence.get('absence_reconciled'):
                return copy.deepcopy(fence['absence_reconciled'])
            fence_before = copy.deepcopy(fence)
            locator = original_request_id or fence.get('request_id')
        if not locator:
            return
        status = self.journal.status(locator)
        result = status.get('result') or {}
        intent = result.get('absence_recovery') or result.get('error', {}).get('absence_recovery')
        if intent is None:
            return
        error = lambda: WorkbenchError('browser_absence_receipt_unavailable',
            'Original absence receipt is missing, changed or not authenticated; retain UNKNOWN.', effect_state='unknown')
        if (not isinstance(intent, dict) or intent.get('request_id') != locator
                or status['state'] not in ('pending', 'failed') or len(json.dumps(intent).encode()) > 65536):
            raise error()
        original = intent.get('original')
        binding = intent.get('binding')
        if (fence and (fence.get('request_id') != locator or fence.get('absence_recovery') != intent)):
            raise error()
        if (not isinstance(original, dict) or not isinstance(binding, dict)
                or original != row or row.get('authority') != 'cleanup_only'
                or row.get('installation_id') != self.install_id or claim_id in self.claims
                or binding.get('action') != 'cleanup' or binding.get('absence_only') is not True
                or binding.get('claim_id') != claim_id or binding.get('claim_epoch') != row['claim_epoch']
                or binding.get('owner_session') != owner or binding.get('installation_id') != self.install_id
                or binding.get('original_runtime_generation') != row['runtime_generation']
                or any(binding.get(k) != row['target'].get(k) for k in
                    ('profile_id','context_id','context_kind','target_id','target_generation','tab_id','browser_target_id'))
                or not valid_id(binding.get('nonce'))):
            raise error()
        target = row['target']
        def peers():
            return [p for p in list(self.peers.values()) if p.connected
                and p.identity.get('profile_id') == target['profile_id']
                and p.identity.get('context_id') == target['context_id']
                and ('private' if p.identity.get('private_context') else 'ordinary') == target['context_kind']
                and self.trust_records.get(p.trust_key, {}).get('enabled') is True
                and self.trust_records.get(p.trust_key, {}).get('trust_id') == binding.get('trust_id')]
        with self.lock:
            candidates = peers()
            if len(candidates) != 1:
                raise error()
            peer = candidates[0]
            fresh = {**binding, 'action':'claim_status', 'current_runtime_generation':self.instance_id,
                     'peer_id':peer.id, 'nonce':uuid.uuid4().hex}
            fresh.pop('absence_only')
        def current():
            # Also runs under the framed writer lock; do not acquire broker lock.
            if (self.incomplete_initializations.get(claim_id) != original or claim_id in self.claims
                    or peers() != [peer] or self.peers.get(peer.id) is not peer
                    or self.input_fences.get(claim_id, {}) != fence_before):
                raise error()
        command = {'interaction_version':1, 'runtime_generation':self.instance_id,
            'profile_id':target['profile_id'], 'context_id':target['context_id'], 'context_kind':target['context_kind'],
            'trust_id':fresh['trust_id'], 'owner_session':owner, 'claim_id':claim_id,
            'claim_epoch':row['claim_epoch'], 'target_generation':target['target_generation'],
            'cleanup_binding':fresh, 'absence_receipt_binding':binding, 'absence_receipt_request_id':locator}
        with self.initialization_locks[claim_id]:
            try:
                reply = self._rpc(peer, 'claim_status', command, before_send=current, _absence_receipt=True)
            except WorkbenchError as missing:
                raise WorkbenchError(missing.code, missing.message, **{**missing.details, 'effect_state':'unknown'}) from missing
            current()
            history = reply.get('initialization_record')
            try:
                interaction_contract.browser_initialization_record(history)
            except (WorkbenchError, TypeError, KeyError, ValueError):
                raise error()
            receipt = reply.get('cleanup_receipt') or {}
            expected = {k:v for k,v in original.items() if k != 'peer_id'}
            expected.update(claim_epoch=original['claim_epoch']+1, cleanup_state='target_gone',
                            resource_unsettled=False, debugger_attachment='not_attached_at_last_record')
            if (reply.get('cleanup_binding') != fresh or reply.get('absence_original_binding') != binding
                    or reply.get('absence_original_request_id') != locator or history != expected
                    or receipt != {'detach_attempted':False,'detach_acknowledged':False,'target_presence':'original_absent',
                        'attachment_verification':'unknown','pointer_release_state':original['pointer_release_state'],
                        'tab_closed':False,'task_completion':'not_established','absence_only':True,
                        'source':'chrome.debugger.getTargets+chrome.tabs.get','effect_state':'none','prior_effects':'not_reconciled'}):
                raise error()
            with self.lock:
                current()
                self.incomplete_initializations[claim_id] = {**copy.deepcopy(history), 'peer_id':peer.id}
                fence['absence_reconciled'] = {'original_request_id':locator,
                    'from_epoch':original['claim_epoch'], 'to_epoch':history['claim_epoch'],
                    'source':'persisted_original_absence_receipt', 'absence_probe_replayed':False,
                    'prior_effects':'not_reconciled', 'original_journal_unchanged':True}
                self.input_fences[claim_id] = fence
                return copy.deepcopy(fence['absence_reconciled'])

    def _initialization_operation(self, owner, action, claim_id, parameters, *, absence_only=False, control_request_id=None):
        """Separate history lane; ordinary claim/document validation stays strict."""
        row = self.incomplete_initializations[claim_id]
        if row['owner_session'] != owner or row['installation_id'] != self.install_id:
            raise WorkbenchError('browser_claim_owner_mismatch', 'Initialization history belongs to another task or installation.', effect_state='none')
        if action == 'cleanup' and (type(parameters.get('claim_epoch')) is not int or parameters['claim_epoch'] != row['claim_epoch']
                or parameters.get('target_generation') != row['target']['target_generation']):
            raise WorkbenchError('stale_browser_claim', 'Use the current historical cleanup epoch and target generation.', effect_state='none')
        if any(parameters.get(k) is not None for k in ('upload_stage_id','upload_cleanup','file_path','parameters','target')):
            raise WorkbenchError('browser_initialization_cleanup_only', 'Initialization history has no document or upload authority.', effect_state='none')
        peer = self.peers.get(row['peer_id'])
        trust = self.trust_records.get(getattr(peer, 'trust_key', None)) if peer else None
        if not peer or not peer.connected or not trust or not trust['enabled']:
            raise WorkbenchError('browser_profile_unavailable', 'Reconnect the exact paired context before historical cleanup.', effect_state='none')
        target = row['target']
        with self.lock:
            # Admission can only become more restrictive if a collision appears.
            absence_only = action == 'cleanup' and (absence_only or self._initialization_collision(row))
        binding = {'record_kind':row['record_kind'],'action':action,'claim_id':claim_id,'claim_epoch':row['claim_epoch'],
            'original_runtime_generation':row['runtime_generation'],'current_runtime_generation':self.instance_id,
            'peer_id':peer.id,'installation_id':self.install_id,'owner_session':owner,'profile_id':target['profile_id'],
            'context_id':target['context_id'],'context_kind':target['context_kind'],'target_id':target['target_id'],
            'target_generation':target['target_generation'],'tab_id':target['tab_id'],'browser_target_id':target['browser_target_id'],
            'trust_id':trust['trust_id'],'nonce':uuid.uuid4().hex}
        if absence_only: binding['absence_only'] = True
        command = {'interaction_version':1,'runtime_generation':self.instance_id,'profile_id':target['profile_id'],
            'context_id':target['context_id'],'context_kind':target['context_kind'],'trust_id':trust['trust_id'],
            'owner_session':owner,'claim_id':claim_id,'claim_epoch':row['claim_epoch'],
            'target_generation':target['target_generation'],'cleanup_binding':binding}
        if absence_only:
            command['absence_only'] = True
            command['operation_request_id'] = control_request_id
        if action == 'cleanup' and parameters.get('cleanup_policy') is not None:
            if parameters['cleanup_policy'] not in ('keep', 'close_on_release'):
                raise WorkbenchError('invalid_cleanup_policy', 'Choose keep or close_on_release.', effect_state='none')
            command['retire_owned_creation'] = parameters['cleanup_policy'] == 'close_on_release'
        with self.initialization_locks[claim_id]:
            pending = None
            fence = None
            def stage_current():
                if (self.input_fences.get(claim_id) is not fence or fence.get('absence_pending') is not pending
                        or fence.get('request_id') != control_request_id or pending['binding'] != binding
                        or self.incomplete_initializations.get(claim_id) != pending['original']
                        or self.peers.get(peer.id) is not peer or not peer.connected
                        or not self.trust_records.get(peer.trust_key, {}).get('enabled')
                        or self.trust_records.get(peer.trust_key, {}).get('trust_id') != binding['trust_id']
                        or peer.identity.get('profile_id') != binding['profile_id']
                        or peer.identity.get('context_id') != binding['context_id']
                        or ('private' if peer.identity.get('private_context') else 'ordinary') != binding['context_kind']):
                    raise WorkbenchError('browser_claim_owner_mismatch', 'Absence-only proof lost its original fence.', effect_state='unknown')
            intent = None
            proof_reply_received = False
            try:
                if absence_only:
                    with self.lock:
                        fence = self.input_fences.get(claim_id)
                        if (not fence or fence.get('request_id') != control_request_id
                                or fence.get('binding') != self._effect_binding(row)):
                            raise WorkbenchError('browser_claim_owner_mismatch', 'Absence-only cleanup lost reservation.', effect_state='none')
                        fence['absence_only'] = True
                        pending = {'binding':copy.deepcopy(binding), 'original':copy.deepcopy(row), 'publication':None}
                        fence['absence_pending'] = pending
                        intent = {'binding':copy.deepcopy(binding), 'request_id':control_request_id,
                                  'original':copy.deepcopy(row)}
                        fence['absence_recovery'] = intent
                    if len(json.dumps(intent).encode()) > 65536:
                        raise WorkbenchError('browser_absence_receipt_unavailable', 'Original absence binding exceeds its bound.', effect_state='none')
                    self.journal.checkpoint(control_request_id, {'phase':'before_absence_cleanup_dispatch',
                        'absence_recovery':intent, 'effect_state':'unknown'})
                result = self._rpc(peer, action, command, **({"before_send":stage_current} if absence_only else {}))
                proof_reply_received = True
                history = result.get('initialization_record')
                interaction_contract.browser_initialization_record(history)
                if (result.get('record_kind') != row['record_kind'] or result.get('cleanup_binding') != binding
                        or history['claim_id'] != claim_id or history['owner_session'] != owner
                        or history['installation_id'] != self.install_id or history['runtime_generation'] != row['runtime_generation']
                        or history['target'] != target):
                    raise WorkbenchError('selected_browser_protocol', 'Historical cleanup changed its exact identity binding.', effect_state='unknown')
                if absence_only:
                    receipt = result.get('cleanup_receipt')
                    if (not isinstance(receipt, dict) or history['claim_epoch'] != row['claim_epoch'] + 1 or history['cleanup_state'] != 'target_gone'
                            or history['resource_unsettled'] is not False or history['debugger_attachment'] != 'not_attached_at_last_record'
                            or receipt.get('absence_only') is not True or receipt.get('source') != 'chrome.debugger.getTargets+chrome.tabs.get'
                            or receipt.get('target_presence') != 'original_absent' or receipt.get('detach_attempted') is not False
                            or receipt.get('detach_acknowledged') is not False or receipt.get('tab_closed') is not False
                            or receipt.get('attachment_verification') != 'unknown' or receipt.get('effect_state') != 'none'
                            or receipt.get('prior_effects') != 'not_reconciled' or receipt.get('task_completion') != 'not_established'):
                        raise WorkbenchError('selected_browser_protocol', 'Absence-only cleanup did not prove its non-effecting exact absence.', effect_state='unknown')
                if absence_only: stage_current()
                published = pending.get('publication') if absence_only else self.incomplete_initializations.get(claim_id)
                if published is None or any(published.get(k) != v for k,v in history.items()):
                    raise WorkbenchError('selected_browser_protocol', 'Historical cleanup result was not published by its paired peer.', effect_state='unknown')
                if absence_only:
                    with self.lock:
                        stage_current()
                        self.incomplete_initializations[claim_id] = copy.deepcopy(published)
                return result
            except WorkbenchError as error:
                if absence_only:
                    raise WorkbenchError(error.code, error.message, **{**error.details,
                        **({'absence_recovery':intent} if intent else {}), **({'effect_state':'unknown'} if proof_reply_received else {})}) from error
                raise
            finally:
                if absence_only:
                    with self.lock:
                        latest = self.input_fences.get(claim_id, {})
                        if (pending is not None and latest.get('absence_pending') is pending
                                and pending.get('binding') == binding):
                            latest.pop('absence_pending', None)

    def status(self, workspace, max_bytes=8192):
        if not self.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Selected browser access requires an executable workspace.')
        with self.lock:
            result = {'ok': True, 'available': bool(self.peers), 'server_generation': self.instance_id,
                'expected_extension': self.expected, 'connections': [{**p.identity, 'peer_id': p.id} for p in self.peers.values()],
                'leases': list(self.leases.values())[-100:], 'history_omitted': max(0, len(self.leases) - 100),
                'interaction_version': interaction_contract.VERSION, 'profile_trust': list(self.trust_records.values()),
                'claims': list(self.claims.values())[-100:],
                'incomplete_initializations': list(self.incomplete_initializations.values())[-100:],
                'legacy_key_history':list(self.legacy_key_history.values()),
                'diagnostics': dict(self.diagnostics), 'checked_at': time.time(),
                'unavailable_reason': self.disabled_reason,
                'identity_scope': 'Native relay function bytecode and extension loaded manifest version/resource hash; not whole-process attestation.',
                'scope': 'Durable locally paired profile/context discovery and task claims; legacy popup grants remain separate.'}
            result=copy.deepcopy(result)
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes 4096..262144.')
        result.update(execution_scope='host_cache_only',cache_gap='status_is_last_published_metadata')
        return self._bounded_cache(result,max_bytes)

    @staticmethod
    def _validate_click_receipt(receipt, count, *, completed):
        """Validate dispatch accounting, never application completion or event timing."""
        invalid = lambda: WorkbenchError('selected_browser_protocol', 'Invalid or mismatched click sequence receipt.', effect_state='unknown')
        if (type(receipt) is not dict or set(receipt) != {'version', 'requested_click_count', 'clicks', 'completed_clicks'}
                or type(receipt.get('version')) is not int or receipt['version'] != 1
                or type(count) is not int or count not in (1, 2)
                or type(receipt.get('requested_click_count')) is not int or receipt['requested_click_count'] != count
                or type(receipt.get('clicks')) is not list or len(receipt['clicks']) > count):
            raise invalid()
        done = 0
        fields = {'click_count', 'down_attempted', 'down_acknowledged', 'up_attempted', 'up_acknowledged'}
        prior_complete = True
        for index, row in enumerate(receipt['clicks'], 1):
            if (type(row) is not dict or set(row) != fields or type(row.get('click_count')) is not int
                    or row['click_count'] != index or not prior_complete
                    or any(type(row.get(key)) is not bool for key in fields - {'click_count'})
                    or row['down_acknowledged'] and not row['down_attempted']
                    or row['up_attempted'] and not row['down_attempted']
                    or row['up_acknowledged'] and not row['up_attempted']):
                raise invalid()
            prior_complete = row['down_acknowledged'] and row['up_acknowledged']
            done += int(prior_complete)
        if (type(receipt.get('completed_clicks')) is not int or receipt['completed_clicks'] != done
                or completed and done != count):
            raise invalid()

    def operation(self, workspace, action, lease_id=None, expected_origin=None, expected_generation=None,
                  request_id=None, max_bytes=8192, _journaled=False, **parameters):
        capture = parameters.get('capture_responses')
        if capture is None:
            parameters.pop('capture_responses', None)
        elif (type(capture) is not bool or action not in ('create', 'acquire') or lease_id is not None
                or parameters.get('claim_id') is not None or parameters.get('diagnostic_scope') is not None):
            raise WorkbenchError('invalid_browser_capture_policy', 'Use boolean capture_responses only with durable create/acquire.', effect_state='none')
        self.config.workspace(workspace)
        if not self.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Selected browser access requires an executable workspace.')
        if action == 'evaluate_start':
            if lease_id is not None or _journaled:
                raise WorkbenchError('browser_claim_required', 'Evaluator admission requires an original durable claim.', effect_state='none')
            cancel = parameters.pop('_evaluation_cancel', None)
            disconnect = parameters.pop('_evaluation_disconnect', None)
            if cancel is False:
                raise WorkbenchError('browser_evaluation_cancellation_unavailable', 'This request cannot bind evaluator cancellation.', effect_state='none')
            return self.evaluations.start(workspace, request_id, expected_origin, expected_generation, max_bytes, parameters, cancel, disconnect)
        if parameters.get('click_count') is not None:
            count = parameters['click_count']
            if action != 'click' or type(count) is not int or count not in (1, 2):
                raise WorkbenchError('invalid_browser_click_count', 'Use integer click_count 1 or 2 only with click.', effect_state='none')
            if count == 2 and not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Double-click requires an exact task claim.', effect_state='none')
        if action == 'click_point':
            if not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Image input requires an exact task claim.', effect_state='none')
            digest = parameters.get('screenshot_sha256')
            if (not valid_id(parameters.get('observation_id')) or parameters.get('target_id') is not None
                    or not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest)
                    or any(type(parameters.get(key)) not in (int, float) or not math.isfinite(parameters[key])
                           or parameters[key] < 0 for key in ('image_x', 'image_y'))):
                raise WorkbenchError('invalid_image_point', 'Use the exact screenshot hash and observation with finite nonnegative image-pixel coordinates, without target_id.', effect_state='none')
        if action == 'upload':
            if (not parameters.get('claim_id') or not valid_id(parameters.get('observation_id')) or not valid_id(parameters.get('target_id'))
                    or any(key in parameters for key in ('upload_authority', 'files', 'object_id'))):
                raise WorkbenchError('invalid_upload_parameters', 'Use an exact claim and fresh file-input observation.', effect_state='none')
            self.uploads.validate(parameters.get('file_path'), parameters.get('expected_sha256'), parameters.get('expected_bytes'), self.config.max_artifact_bytes)
        if action == 'drag':
            if not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Drag requires an exact task claim.', effect_state='none')
            steps = parameters.get('steps', 8)
            if (type(steps) is not int or not 2 <= steps <= 16 or not valid_id(parameters.get('end_target_id'))
                    or parameters.get('end_target_id') == parameters.get('target_id')):
                raise WorkbenchError('invalid_drag_parameters', 'Use distinct fresh endpoints and integer steps 2..16.', effect_state='none')
        if action == 'scroll':
            if not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Wheel input requires an exact task claim.', effect_state='none')
            dx, dy = parameters.get('delta_x', 0), parameters.get('delta_y', 0)
            if (any(type(delta) not in (int, float) or not math.isfinite(delta) or abs(delta) > 2000 for delta in (dx, dy))
                    or dx == dy == 0):
                raise WorkbenchError('invalid_scroll_delta', 'Use finite CSS deltas -2000..2000 with at least one nonzero axis.', effect_state='none')
        if action == 'insert_text' or action == 'press' and parameters.get('key') in ('Undo', 'Redo', 'Shift+ArrowLeft', 'Shift+ArrowRight'):
            if not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Literal insertion, history and fixed Shift-arrow selection require an exact task claim.', effect_state='none')
            if not valid_id(parameters.get('observation_id')) or not valid_id(parameters.get('target_id')):
                raise WorkbenchError('invalid_browser_editing_target', 'Use a fresh exact observed editing recipient.', effect_state='none')
            if action == 'insert_text' and (type(parameters.get('text')) is not str
                    or len(parameters['text'].encode('utf-8', errors='surrogatepass')) > 32768):
                raise WorkbenchError('invalid_input', 'Use literal text within 32 KiB.', effect_state='none')
        if action == 'replace_selection':
            if not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Range replacement requires an exact task claim.', effect_state='none')
            text = parameters.get('text')
            if (not valid_id(parameters.get('observation_id')) or not valid_id(parameters.get('target_id'))
                    or type(text) is not str or len(text.encode('utf-16-le', errors='surrogatepass')) // 2 > 4096
                    or len(text.encode('utf-8', errors='surrogatepass')) > 32768
                    or any(parameters.get(key) is not None for key in ('selection_start', 'selection_length'))):
                raise WorkbenchError('invalid_browser_replacement', 'Use literal bounded text and a fresh observed selection, without a new range.', effect_state='none')
        if action == 'select_text':
            if not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Text selection requires an exact task claim.', effect_state='none')
            if (not valid_id(parameters.get('observation_id')) or not valid_id(parameters.get('target_id'))
                    or any(type(parameters.get(key)) is not int or not 0 <= parameters[key] <= 32768
                           for key in ('selection_start', 'selection_length'))
                    or parameters['selection_start'] + parameters['selection_length'] > 32768):
                raise WorkbenchError('invalid_browser_text_range', 'Use a fresh target and integer selection_start/selection_length in UTF-16 code units within 32768.', effect_state='none')
        if action in ('check', 'select'):
            if not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Form state actions require an exact task claim.', effect_state='none')
            if action == 'check' and type(parameters.get('checked', True)) is not bool:
                raise WorkbenchError('invalid_checkbox_state', 'Use a boolean checked state.', effect_state='none')
            values = parameters.get('selected_values')
            if action == 'select' and (not isinstance(values, list) or len(values) > 100
                    or any(not isinstance(value, str) or len(value.encode()) > 4096 for value in values)
                    or len(set(values)) != len(values) or len(json.dumps(values, ensure_ascii=False).encode()) > 32768):
                raise WorkbenchError('invalid_select_options', 'Use at most 100 exact, distinct option values within 32 KiB.', effect_state='none')
        if action == 'snapshot':
            self._validate_snapshot_options(parameters)
            if (parameters.get('include_accessibility') or parameters.get('include_screenshot')) and not parameters.get('claim_id'):
                raise WorkbenchError('browser_claim_required', 'Paired AX and image captures require an exact task claim.', effect_state='none')
        if action == 'status':
            return self.status(workspace, max_bytes)
        if action in ('discover', 'acquire', 'create', 'release', 'stop', 'cleanup', 'claim_status') or parameters.get('claim_id'):
            if lease_id is not None:
                raise WorkbenchError('mixed_browser_authority', 'Use either a legacy grant or a task claim.')
            return self._durable_operation(workspace, action, expected_origin, expected_generation,
                request_id, max_bytes, _journaled, **parameters)
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes 4096..262144.')
        if action not in ('inspect', 'snapshot', 'events', 'body', 'document', 'evaluate', 'click', 'fill', 'press', 'navigate', 'detach'):
            raise WorkbenchError('invalid_browser_action', 'Use a supported selected-browser action.')
        if not valid_id(lease_id):
            raise WorkbenchError('invalid_browser_lease', 'Select a lease returned after a local browser grant.')
        if action=='events': return self._cached(lease_id,action,work_context.get(),parameters,max_bytes,legacy=True)
        if action in ('evaluate', 'click', 'fill', 'press', 'navigate', 'detach') and not _journaled:
            if request_id is None:
                raise WorkbenchError('request_id_required', 'Effects require a stable request_id.')
            payload = {'tool': 'selected_browser', 'workspace': workspace, 'action': action,
                       'operation_owner': work_context.get(),
                       'lease_id': lease_id, 'expected_origin': expected_origin,
                       'expected_generation': expected_generation, 'parameters': parameters}
            if self._input_action(action):
                with self.lock:
                    row = self.leases.get(lease_id)
                    if row: self._authorize_legacy_owner(row, work_context.get())
                replay = self._control_replay(request_id, payload)
                if replay is not None: return replay
                with self.lock:
                    row = self.leases.get(lease_id)
                    if row: self._normal_guard(lease_id, self._binding(row))
            def dispatch():
                self.journal.checkpoint(request_id, {'lease_id': lease_id, 'phase': 'before_selected_browser_dispatch', 'effect_state': 'unknown'})
                return self.operation(workspace, action, lease_id, expected_origin, expected_generation,
                    request_id, max_bytes, _journaled=True, **parameters)
            control = action=='detach'
            if control:
                with self.lock:
                    original=self.leases.get(lease_id)
                    if original is None:raise WorkbenchError('unknown_browser_lease','Original grant is unavailable for receipt authorization.',effect_state='none')
                    self._authorize_legacy_owner(original,work_context.get())
                replay=self._control_replay(request_id,payload)
                if replay is not None:return replay
            with self.lock:
                original=self.leases.get(lease_id)
                if control:
                    if original is None or not original.get('browser_target_id') or not original.get('grant_generation'):
                        raise WorkbenchError('browser_control_identity_unavailable','Original grant lifetime is not published.',effect_state='none')
                    if original.get('work_session_id') not in (None,work_context.get()):
                        raise WorkbenchError('browser_claim_owner_mismatch','Original grant belongs to another task.',effect_state='none')
                control_binding=copy.deepcopy(self._effect_binding(original)) if control else None
            return self.journal.run(request_id,payload,dispatch,resource=('selected-browser-control:' if control else 'selected-browser:')+lease_id,
                on_reserved=(lambda:self._fence(lease_id,control_binding,request_id)) if control else None)
        with self.lock:
            lease = self.leases.get(lease_id)
            if lease is None:
                raise WorkbenchError('unknown_browser_lease', 'No tab in this server generation has that lease.')
            selected_lock = contextlib.nullcontext() if action=='detach' else self.lease_locks[lease_id]
        with selected_lock:
            with self.lock:
                lease = self.leases[lease_id]
                peer = self.peers.get(lease['peer_id'])
                if (action!='detach' and (lease['state'] != 'active' or lease['expires_at'] <= time.time())) or peer is None or not peer.connected:
                    raise WorkbenchError('browser_lease_ended', 'The tab grant expired or was detached. Grant the tab again locally.', effect_state='none')
                if action!='detach' and expected_origin != lease['origin']:
                    raise WorkbenchError('browser_origin_changed', 'Use the exact origin of the explicitly granted tab.', effect_state='none')
                if action!='detach' and (type(expected_generation) is not int or expected_generation != lease['document_generation']):
                    raise WorkbenchError('stale_browser_document', 'Observe the current document before acting.', effect_state='none')
                if work_context.get() is not None:
                    if lease.get('work_session_id') not in (None,work_context.get()):
                        raise WorkbenchError('browser_claim_owner_mismatch','This original grant belongs to another task.',effect_state='none')
                    lease.setdefault('work_session_id', work_context.get())
                command = {'lease_id': lease_id, 'expected_origin': expected_origin,
                           'expected_generation': expected_generation, 'parameters': parameters}
                command.update(operation_request_id=request_id,operation_owner=work_context.get())
                if action=='detach':command['cleanup_binding']=copy.deepcopy(self.input_fences[lease_id]['binding'])
                normal_binding=copy.deepcopy(self._binding(lease))

            def perform():
                if action!='detach':self._normal_guard(lease_id,normal_binding,input_action=self._input_action(action))
                result = self._rpc(peer, action, command)
                if result.get('lease_id') != lease_id:
                    raise WorkbenchError('selected_browser_protocol', 'The browser result did not match its selected lease.', effect_state='unknown')
                if action == 'snapshot':
                    self._snapshot_artifacts(result, parameters, {'lease_id': lease_id, 'profile_id': lease['profile_id'],
                        'private_context': lease['private_context'], 'origin': expected_origin})
                if action == 'body' or action == 'document':
                    encoded = result.pop('body_base64', None)
                    if encoded is not None:
                        raw = base64.b64decode(encoded, validate=True)
                        capture = self.store.put_bytes(raw, json.dumps({'kind': 'selected_browser_body', 'lease_id': lease_id,
                            'origin': expected_origin, 'document_generation': expected_generation,
                            'representation': result.get('representation'), 'potentially_sensitive': True}))
                        result.update(body_artifact=capture['artifact_id'], capture_id=capture['capture_id'], body_bytes=len(raw))
                result.update(server_generation=self.instance_id, profile_id=lease['profile_id'],
                              private_context=lease['private_context'], checked_at=time.time(), potentially_sensitive=True)
                raw = json.dumps(result, ensure_ascii=True).encode()
                if len(raw) > max_bytes:
                    capture = self.store.put_bytes(raw, json.dumps({'kind': 'selected_browser_result', 'lease_id': lease_id,
                        'origin': expected_origin, 'potentially_sensitive': True}))
                    return {'ok': True, 'lease_id': lease_id, 'result_artifact': capture['artifact_id'],
                            'capture_id': capture['capture_id'], 'inline_complete': False,
                            'potentially_sensitive': True,
                            'document_generation': result.get('document_generation'), 'server_generation': self.instance_id}
                return result

            return perform()

    def close(self):
        self.stopped.set()
        with self.lock:
            peers = list(self.peers.values())
        for peer in peers:
            with contextlib.suppress(OSError): peer.send({'type': 'shutdown'})
            with contextlib.suppress(OSError): peer.socket.shutdown(socket.SHUT_RDWR)
        if self.listener:
            self.listener.close(); self.thread.join(2)
        self.evaluations.close()
        if self.directory:
            self.directory.cleanup()
        self.uploads.close()


class UnavailableSelectedTabs:
    def __init__(self, config, reason): self.config, self.reason = config, reason
    def start(self): pass
    def close(self): pass
    def active_ids(self, work_session_id=None): return []
    def active_claim_ids(self, work_session_id=None): return []
    def session_resource_diagnostics(self, owner, workspace, resources):
        return {'available': True, 'authority': 'diagnostic_only',
                'scope': 'current_owner_close_accounting_only', 'items': [], 'truncated': False}
    @property
    def evaluations(self): return self
    @property
    def web_diagnostics(self): return self
    def operation(self, workspace, action, **kwargs):
        if not self.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Selected browser access requires an executable workspace.')
        if action == 'status':
            return {'ok': True, 'available': False, 'reason': self.reason,
                    'checked_at': time.time(), 'prerequisite': 'Complete the local selected-browser installation.'}
        raise WorkbenchError('selected_browser_unavailable', 'Selected browser setup is unavailable; ordinary file/job use remains available.')


def create_selected_tabs(config, store, journal, instance_id, **kwargs):
    try: return SelectedTabs(config, store, journal, instance_id, **kwargs)
    except (OSError, ValueError, KeyError, WorkbenchError) as error:
        return UnavailableSelectedTabs(config, getattr(error, 'code', type(error).__name__))
