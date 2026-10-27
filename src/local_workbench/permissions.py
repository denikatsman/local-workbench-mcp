"""Read-only native permission reporting and an atomic idle/restart boundary.

The GUI alone requests OS approvals. Its private socket capability is inherited
by the service, never sent through the public MCP or into command jobs.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import socket
import threading
import uuid

from .errors import WorkbenchError

MAX_FRAME = 262144
BRIDGE_KEYS = ('LOCAL_WORKBENCH_NATIVE_SOCKET', 'LOCAL_WORKBENCH_NATIVE_TOKEN',
               'LOCAL_WORKBENCH_NATIVE_GENERATION', 'LOCAL_WORKBENCH_NATIVE_LAUNCH')


def catalogue():
    return json.loads(Path(__file__).with_name('permissions_catalogue.json').read_text())


class ActivityGate:
    def __init__(self):
        self.lock = threading.RLock()
        self.active = 0
        self.ticket = None
        self.maintenance_reason = None

    @contextlib.contextmanager
    def admission(self, control=False):
        with self.lock:
            if self.ticket is not None:
                raise WorkbenchError('restart_pending', 'Workbench is applying a user-requested restart. Retry after reconnecting.', effect_state='none')
            if self.maintenance_reason is not None and not control:
                raise WorkbenchError('storage_maintenance', 'Workbench is applying an explicit storage cleanup. Retry when it completes.', effect_state='none')
            self.active += 1
        try:
            yield
        finally:
            with self.lock:
                self.active -= 1

    @contextlib.contextmanager
    def maintenance(self, reason):
        with self.lock:
            if self.active != 1 or self.ticket is not None or self.maintenance_reason is not None:
                raise WorkbenchError('storage_busy', 'Storage cleanup requires other tool calls to finish first.', effect_state='none')
            self.maintenance_reason = reason
        try:
            yield
        finally:
            with self.lock:
                self.maintenance_reason = None

    def activity(self, resources):
        with self.lock:
            return {'in_flight_calls': self.active, **resources()}

    def drain_if_idle(self, ticket, resources):
        with self.lock:
            if self.ticket is not None:
                return self.ticket == ticket
            if self.active:
                return False
            state = resources()
            if state['job_count'] or state['browser_count'] or state.get('native_count', 0):
                return False
            self.ticket = ticket
            return True

    def cancel_drain(self, ticket):
        with self.lock:
            if self.ticket == ticket:
                self.ticket = None


class NativePermissions:
    def __init__(self, instance_id, gate, resources, environ=None):
        env = os.environ if environ is None else environ
        self.connection = {k: env.get(k, '') for k in BRIDGE_KEYS}
        self.instance_id, self.gate, self.resources = instance_id, gate, resources
        self.stopped = threading.Event()
        self.thread = None
        self.committed = False

    @property
    def configured(self):
        return all(self.connection.values())

    def request(self, method, _timeout=3, _allow_failure=False, **params):
        if not self.configured:
            raise WorkbenchError('native_app_unavailable', 'Start the installed Mac app to inspect its permission state.', effect_state='none')
        request_id = uuid.uuid4().hex
        packet = {'version': 1, 'request_id': request_id, 'method': method,
                  'token': self.connection[BRIDGE_KEYS[1]],
                  'app_generation': self.connection[BRIDGE_KEYS[2]],
                  'launch_id': self.connection[BRIDGE_KEYS[3]],
                  'runtime_generation': self.instance_id, **params}
        encoded = json.dumps(packet, separators=(',', ':')).encode() + b'\n'
        if len(encoded) > MAX_FRAME:
            raise WorkbenchError('native_protocol_error', 'Native request exceeds its bounded frame.', effect_state='none')
        send_attempted = False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(_timeout)
                client.connect(self.connection[BRIDGE_KEYS[0]])
                # sendall may send a prefix before raising; only failures before
                # this boundary establish that this request sent no native work.
                send_attempted = True
                client.sendall(encoded)
                raw = bytearray()
                while b'\n' not in raw and len(raw) <= MAX_FRAME:
                    chunk = client.recv(min(8192, MAX_FRAME + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
            if len(raw) > MAX_FRAME or not raw.endswith(b'\n'):
                raise ValueError('incomplete or oversized frame')
            response = json.loads(raw)
            if (not isinstance(response, dict) or response.get('version') != 1
                    or response.get('request_id') != request_id
                    or response.get('app_generation') != packet['app_generation']
                    or response.get('launch_id') != packet['launch_id']
                    or response.get('runtime_generation') != self.instance_id):
                raise ValueError('uncorrelated response')
            if not response.get('ok') and not _allow_failure:
                raise WorkbenchError('native_protocol_error', 'The native app rejected a stale or unsupported request.')
            return response
        except (OSError, ValueError, TypeError) as exc:
            if method == 'operation':
                details = {'effect_state': 'unknown' if send_attempted else 'none',
                           'dispatch_state': 'possibly_sent' if send_attempted else 'not_sent'}
                operation_id = params.get('operation_id')
                if operation_id is not None:
                    details.update(original_request_id=operation_id, request_id=operation_id)
                if send_attempted:
                    details.update(retry_allowed=False,
                        recovery='Inspect the original operation receipt and target. Do not replay uncertain input or use a new request ID to repeat it.')
                raise WorkbenchError('native_app_unavailable',
                    'The native app did not return a current authenticated operation result. '
                    + ('Its effect is unknown; inspect the original receipt without replaying input.' if send_attempted
                       else 'This request failed before sending native work.'), **details) from exc
            raise WorkbenchError('native_app_unavailable', 'The native app did not return a current authenticated result. Permission state is unknown.') from exc

    def status(self, config, workspace, category_ids=None, offset=0, limit=10, max_bytes=8192):
        if not config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Host permission reporting requires an executable workspace.')
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 25 or type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use a nonnegative offset, limit 1..25 and max_bytes 4096..262144.')
        catalog = catalogue()
        ids = {x['id'] for x in catalog['entries']}
        if category_ids is not None and (not isinstance(category_ids, list) or len(category_ids) > 55
                or any(not isinstance(x, str) or x not in ids for x in category_ids)):
            raise WorkbenchError('invalid_categories', 'Use category IDs from permissions_status.')
        try:
            native = self.request('snapshot')
        except WorkbenchError as exc:
            native = {'available': False, 'observations': {}, 'reason': exc.message}
        selected = [x for x in catalog['entries'] if category_ids is None or x['id'] in category_ids]
        result = {'ok': True, 'catalogue_version': catalog['catalogue_version'], 'total_categories': len(selected),
                  'native_available': native.get('available', False), 'owner': native.get('owner'),
                  'observed_at': native.get('observed_at'), 'reason': native.get('reason'),
                  'restart': native.get('restart'), 'request_in_progress': native.get('request_in_progress'),
                  'entries': [], 'next_offset': None,
                  'scope': 'native app and explicitly selected targets; not a grant for arbitrary subprocesses',
                  'prompts_triggered': False}
        observations = native.get('observations', {})
        for entry in selected[offset:offset + limit]:
            item = {**entry, 'observation': observations.get(entry['id'], {
                'approval': 'unknown', 'readiness': 'unverified', 'note': 'Native observation unavailable.'})}
            candidate = {**result, 'entries': [*result['entries'], item], 'next_offset': offset + len(result['entries']) + 1}
            if len(json.dumps(candidate, ensure_ascii=True).encode()) > max_bytes - 512:
                break
            result['entries'].append(item)
        end = offset + len(result['entries'])
        if end < len(selected):
            result['next_offset'] = end
        return result

    def start(self):
        if self.configured:
            self.thread = threading.Thread(target=self._poll, daemon=True, name='native-readiness')
            self.thread.start()

    def _poll(self):
        while not self.stopped.is_set() and not self.committed:
            try:
                activity = self.gate.activity(self.resources)
                response = self.request('poll', activity=activity)
                ticket = response.get('restart_ticket')
                native_ids = response.get('native_lease_ids', [])
                if not isinstance(native_ids, list) or native_ids:
                    self.stopped.wait(1)
                    continue
                if isinstance(ticket, str) and len(ticket) == 32 and self.gate.drain_if_idle(ticket, self.resources):
                    # On an ambiguous response keep admission closed. The GUI
                    # may already have accepted the commit and be stopping us.
                    decision = self.request('commit_restart', ticket=ticket)
                    if decision.get('committed') is True:
                        self.committed = True
                    elif decision.get('committed') is False:
                        self.gate.cancel_drain(ticket)
                elif ticket is None and self.gate.ticket is not None:
                    # Only an authenticated current GUI response can cancel an
                    # uncertain commit. The GUI never cancels after committing.
                    self.gate.cancel_drain(self.gate.ticket)
            except WorkbenchError:
                pass
            self.stopped.wait(1)

    def close(self):
        self.stopped.set()
        if self.thread:
            self.thread.join(4)
