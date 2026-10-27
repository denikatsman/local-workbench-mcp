"""Owned PTY sessions: raw transcripts, framed input and separately derived VT screens."""
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import time
import uuid

from .context import work_context
from .errors import WorkbenchError
from .persistence import atomic_json
from .runtime import DEFAULT_PATH
from .views import response_size


class Terminals:
    def __init__(self, jobs):
        self.jobs, self.config, self.journal = jobs, jobs.config, jobs.journal
        self.root = self.config.state_dir / 'terminals'
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.native_input = None
        if self.root.is_symlink():
            raise WorkbenchError('unsafe_terminal_store', 'Terminal storage may not be a symlink.')

    @staticmethod
    def child(request_id, phase):
        return 'terminal:' + hashlib.sha256((request_id + ':' + phase).encode()).hexdigest()

    def load(self, terminal_id):
        if not isinstance(terminal_id, str) or not re.fullmatch(r'[0-9a-f]{32}', terminal_id):
            raise WorkbenchError('invalid_terminal', 'Use an existing terminal ID.')
        directory = self.root / terminal_id
        marker = directory / 'owner.json'
        if directory.is_symlink() or marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 16384:
            raise WorkbenchError('unknown_terminal', 'This owned terminal manifest is unavailable.')
        record = json.loads(marker.read_text())
        if work_context.get() is not None and work_context.get() != record['work_session_id']:
            raise WorkbenchError('work_session_mismatch', 'This terminal belongs to another work context.')
        return record, directory

    def start(self, workspace, argv, request_id, cwd='.', rows=24, columns=80, timeout_seconds=3600):
        selected = self.config.workspace(workspace)
        if not selected.executable:
            raise WorkbenchError('execution_denied', 'Terminals require an executable workspace.')
        if not isinstance(argv, list) or not argv or len(argv) > 4096 or any(not isinstance(value, str) or '\0' in value for value in argv):
            raise WorkbenchError('invalid_argv', 'Use a bounded literal command argument array.')
        if type(rows) is not int or type(columns) is not int or not 2 <= rows <= 100 or not 10 <= columns <= 240:
            raise WorkbenchError('invalid_terminal_dimensions', 'Use rows 2..100 and columns 10..240.')
        directory = (selected.root / cwd).resolve(strict=True)
        if not directory.is_relative_to(selected.root) or not directory.is_dir():
            raise WorkbenchError('invalid_cwd', 'Terminal cwd must stay inside the selected workspace.')
        driver = shutil.which(argv[0], path=DEFAULT_PATH)
        if driver is None:
            raise WorkbenchError('executable_unavailable', 'Select an absolute installed terminal executable.')
        def start():
            identifier, generation = uuid.uuid4().hex, uuid.uuid4().hex
            owned = self.root / identifier
            owned.mkdir(mode=0o700)
            launch = {'terminal_id': identifier, 'generation': generation, 'argv': [driver, *argv[1:]],
                      'cwd': str(directory), 'rows': rows, 'columns': columns}
            atomic_json(owned / 'launch.json', launch)
            child = self.child(request_id, 'job')
            self.journal.checkpoint(request_id, {'terminal_id': identifier, 'job_request_id': child,
                'phase': 'before_terminal_launch', 'effect_state': 'metadata_created'})
            job = self.jobs.start(workspace, [sys.executable, '-I', '-B', '-m', 'local_workbench.pty_worker', str(owned)], child,
                                  cwd=cwd, timeout_seconds=timeout_seconds, keep_stdin=True)
            record = {'terminal_id': identifier, 'generation': generation, 'workspace': workspace, 'job_id': job['job_id'],
                'work_session_id': work_context.get(), 'created_at': time.time(), 'rows': rows, 'columns': columns,
                'scope': 'Owned real controlling PTY; raw output streams are merged by terminal semantics. Server shutdown stops the owned job.'}
            atomic_json(owned / 'owner.json', record)
            return {'ok': True, **record, 'effect_state': 'process_started'}
        return self.journal.run(request_id, {'tool': 'terminal_start', 'workspace': workspace, 'argv': argv,
            'cwd': cwd, 'rows': rows, 'columns': columns, 'timeout_seconds': timeout_seconds, 'work_session_id': work_context.get()}, start)

    def state(self, terminal_id):
        record, directory = self.load(terminal_id)
        status = self.jobs.status(record['job_id'], detail=False)
        path = directory / 'state.json'
        if path.is_symlink() or path.exists() and path.stat().st_size > 65536:
            raise WorkbenchError('terminal_state_invalid', 'The terminal state message is invalid.')
        observed = json.loads(path.read_text()) if path.exists() else None
        if observed and (observed.get('terminal_id') != terminal_id or observed.get('generation') != record['generation']):
            raise WorkbenchError('terminal_generation', 'A stale terminal state message was rejected.')
        local_receipts = directory / 'local-input-receipts.json'
        receipts = None
        if local_receipts.exists() and not local_receipts.is_symlink() and local_receipts.stat().st_size <= 65536:
            value = json.loads(local_receipts.read_text())
            if value.get('terminal_id') == terminal_id and value.get('generation') == record['generation']:
                receipts = value.get('submissions')
        return {'ok': True, **record, 'job': status, 'native_state': observed, 'local_submissions': receipts,
                'local_sensitive_input_required': bool(observed and observed.get('sensitive_input'))}

    def request_local_input(self, terminal_id, request_id):
        record, directory = self.load(terminal_id)
        if not self.config.workspace(record['workspace']).executable:
            raise WorkbenchError('execution_denied', 'Local terminal input requires execute authority.')
        if self.native_input is None or not self.native_input.channel.configured:
            raise WorkbenchError('native_app_unavailable', 'Start the signed Workbench app with local terminal input support.')
        prompt_id = hashlib.sha256(('local-terminal:' + request_id).encode()).hexdigest()[:32]
        def request():
            observed = self.state(terminal_id)
            if not observed['local_sensitive_input_required']:
                raise WorkbenchError('terminal_echo_enabled', 'The local sensitive-input path requires terminal echo to be disabled.', effect_state='none')
            from .browser_wire import read_private_json
            descriptor = read_private_json(directory / 'local-input.json')
            if (descriptor.get('terminal_id') != terminal_id or descriptor.get('generation') != record['generation']
                    or not self.jobs.owns_live_process(record['job_id'], descriptor.get('worker_pid'))):
                raise WorkbenchError('terminal_generation', 'The local input endpoint does not belong to the current owned terminal process.')
            spec = read_private_json(directory / 'launch.json')
            self.journal.checkpoint(request_id, {'terminal_id': terminal_id, 'prompt_id': prompt_id,
                'phase': 'before_local_input_request', 'effect_state': 'none'})
            response = self.native_input._request('terminal_prompt', prompt_id=prompt_id, terminal_id=terminal_id,
                generation=record['generation'], local_socket=descriptor['socket'], local_token=descriptor['token'],
                program=spec['argv'][0], workspace=spec['cwd'])
            public_prompt = self._public_local_prompt(response.get('prompt'), terminal_id, prompt_id)
            return {'ok': True, 'terminal_id': terminal_id, 'prompt_id': prompt_id, 'local_input_required': True,
                'prompt': public_prompt, 'scope': 'User types in the local app; no secret is accepted by this tool.'}
        return self.journal.run(request_id, {'tool': 'terminal_local_input', 'terminal_id': terminal_id}, request,
                                resource='terminal:' + terminal_id)

    def local_input_status(self, terminal_id, prompt_id):
        record, _ = self.load(terminal_id)
        if self.native_input is None:
            raise WorkbenchError('native_app_unavailable', 'Local terminal input requires the signed app.')
        response = self.native_input._request('terminal_prompt_status', prompt_id=prompt_id)
        return {'ok': True, 'terminal_id': terminal_id,
                'prompt': self._public_local_prompt(response.get('prompt'), terminal_id, prompt_id)}

    @staticmethod
    def _public_local_prompt(value, terminal_id, prompt_id):
        if not isinstance(value, dict) or value.get('terminal_id') != terminal_id or value.get('prompt_id') != prompt_id:
            raise WorkbenchError('terminal_generation', 'The native prompt response has a different terminal or prompt identity.')
        result = {key: value[key] for key in ('prompt_id', 'terminal_id', 'generation', 'program', 'workspace',
                                            'expires_at', 'state', 'replayed') if key in value}
        if isinstance(value.get('receipt'), dict):
            result['receipt'] = {key: value['receipt'][key] for key in ('ok', 'error', 'effect_state', 'accepted_bytes',
                'terminal_id', 'generation', 'submission_id', 'checked_at', 'replayed') if key in value['receipt']}
        return result

    def control(self, terminal_id, operation, request_id, text='', rows=None, columns=None):
        record, _ = self.load(terminal_id)
        if operation not in ('input', 'interrupt', 'eof', 'resize', 'stop'):
            raise WorkbenchError('invalid_terminal_operation', 'Use input, interrupt, eof, resize or stop.')
        if operation == 'stop':
            return {**self.jobs.cancel(record['job_id'], request_id), 'terminal_id': terminal_id}
        if not isinstance(text, str) or len(text.encode()) > 32768:
            raise WorkbenchError('terminal_input_limit', 'Use at most 32 KiB of UTF-8 terminal input.')
        command = {'request_id': request_id, 'operation': operation, 'data_base64': base64.b64encode(text.encode()).decode(),
                   'rows': rows, 'columns': columns}
        def send():
            before = self.state(terminal_id)
            if operation == 'input' and before['local_sensitive_input_required']:
                raise WorkbenchError('local_sensitive_input_required', 'Terminal echo is disabled. Use the local user input path; remote text was not sent.', effect_state='none')
            frame = json.dumps(command, separators=(',', ':')) + '\n'
            self.journal.checkpoint(request_id, {'terminal_id': terminal_id, 'job_id': record['job_id'],
                'phase': 'before_terminal_frame', 'effect_state': 'none'})
            self.jobs.input(record['job_id'], self.child(request_id, 'input'), frame)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                state = self.state(terminal_id)['native_state']
                acknowledgement = state.get('acknowledgements', {}).get(request_id) if state else None
                if acknowledgement:
                    if acknowledgement.get('error'):
                        raise WorkbenchError(acknowledgement['error'], 'Terminal input/control was refused or partial; inspect the correlated acknowledgement.',
                            terminal_id=terminal_id, acknowledgement=acknowledgement, effect_state=acknowledgement['effect_state'])
                    return {'ok': True, 'terminal_id': terminal_id, 'acknowledgement': acknowledgement,
                            'verification_state': 'terminal_transport_observed; application postcondition not established'}
                time.sleep(.02)
            raise WorkbenchError('terminal_control_uncertain', 'The frame may have been applied; inspect terminal state by this request ID before retrying.',
                terminal_id=terminal_id, control_request_id=request_id, effect_state='unknown')
        return self.journal.run(request_id, {'tool': 'terminal_control', 'terminal_id': terminal_id, 'operation': operation,
            'text_sha256': hashlib.sha256(text.encode()).hexdigest(), 'rows': rows, 'columns': columns}, send,
            resource='terminal:' + terminal_id)

    def observe(self, terminal_id, offset=0, max_bytes=8192, include_screen=False):
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes 4096..262144.')
        record, _ = self.load(terminal_id)
        result = self.state(terminal_id)
        if result.get('native_state'):
            result['native_state'] = {key: value for key, value in result['native_state'].items() if key != 'acknowledgements'}
        page = self.jobs.read(record['job_id'], 'stdout', offset, max_bytes // 4)
        result['raw_transcript'] = page
        result['raw_coordinate_units'] = 'Exact terminal bytes; CRLF and escape sequences are preserved.'
        if include_screen:
            import pyte
            native = result['native_state'] or record
            screen = pyte.Screen(native['columns'], native['rows'])
            stream = pyte.ByteStream(screen)
            position, scanned = 0, 0
            while scanned < 8388608:
                raw_page = self.jobs.read(record['job_id'], 'stdout', position, 65536)
                raw = raw_page['data'].encode() if raw_page['encoding'] == 'utf-8' else base64.b64decode(raw_page['data'])
                stream.feed(raw)
                scanned += len(raw); position += len(raw)
                if raw_page['eof']:
                    break
            result['screen'] = {'emulator': 'pyte 0.8.2', 'lines': screen.display, 'cursor': {'x': screen.cursor.x, 'y': screen.cursor.y},
                'raw_bytes_interpreted': scanned, 'caught_up_to_captured_output': raw_page['eof'],
                'scope': 'Derived VT interpretation; raw transcript is the source of truth. Unsupported terminal graphics/sequences are not claimed.'}
        if response_size(result) > max_bytes:
            artifact = self.jobs.store.put_bytes(json.dumps(result).encode(), 'terminal-observation:' + terminal_id)
            return {'ok': True, 'terminal_id': terminal_id, 'job_id': record['job_id'], 'observation_artifact': artifact,
                    'view_complete': False, 'local_sensitive_input_required': result['local_sensitive_input_required']}
        return {**result, 'view_complete': True}
