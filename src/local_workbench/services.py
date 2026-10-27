"""Owned services reuse job lifecycle and prove listener ownership before readiness."""
import contextlib
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import time
import uuid
from urllib.parse import urlsplit

from .context import work_context
from .errors import WorkbenchError
from .runtime import DEFAULT_PATH


class Services:
    def __init__(self, jobs):
        self.jobs, self.config, self.journal = jobs, jobs.config, jobs.journal
        self.path = self.config.state_dir / 'services.sqlite3'
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS services (service_id TEXT PRIMARY KEY,workspace TEXT NOT NULL,name TEXT NOT NULL,payload TEXT NOT NULL)')

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db

    @staticmethod
    def child(request_id):
        return 'service-job:' + hashlib.sha256(request_id.encode()).hexdigest()

    def load(self, service_id):
        if not isinstance(service_id, str) or not re.fullmatch(r'[0-9a-f]{32}', service_id):
            raise WorkbenchError('invalid_service', 'Use a service ID returned by Workbench.')
        with self.db() as db:
            row = db.execute('SELECT payload FROM services WHERE service_id=?', (service_id,)).fetchone()
        if row is None:
            raise WorkbenchError('unknown_service', 'No owned service has this ID.')
        record = json.loads(row[0])
        if work_context.get() is not None and work_context.get() != record['work_session_id']:
            raise WorkbenchError('work_session_mismatch', 'This service belongs to another work context.')
        return record

    def start(self, workspace, name, argv, port, request_id, readiness_path='/', expected_sha256=None,
              lease_seconds=3600, wait_ms=0, environment_profile_id=None, reuse=False):
        if not self.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Services require an executable workspace.')
        if not isinstance(name, str) or not 1 <= len(name.encode()) <= 100 or type(port) is not int or not 1 <= port <= 65535:
            raise WorkbenchError('invalid_service', 'Use a name of 1..100 bytes and port 1..65535.')
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86400 or type(wait_ms) is not int or not 0 <= wait_ms <= 10000:
            raise WorkbenchError('invalid_service', 'Use lease_seconds 1..86400 and wait_ms 0..10000.')
        if not isinstance(readiness_path, str) or not readiness_path.startswith('/') or len(readiness_path) > 4096 or '\r' in readiness_path or '\n' in readiness_path:
            raise WorkbenchError('invalid_service', 'Readiness is a bounded relative path on the declared loopback port.')
        if expected_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
            raise WorkbenchError('invalid_service', 'Expected response identity must be a complete SHA-256.')
        spec = {'workspace': workspace, 'name': name, 'argv': argv, 'port': port, 'readiness_path': readiness_path,
                'expected_sha256': expected_sha256, 'lease_seconds': lease_seconds,
                'environment_profile_id': environment_profile_id, 'work_session_id': work_context.get()}
        def start():
            with self.db() as db:
                rows = db.execute('SELECT payload FROM services WHERE workspace=? AND name=?', (workspace, name)).fetchall()
            for row in rows:
                previous = json.loads(row[0])
                job = self.jobs.status(previous['job_id'], detail=False)
                if job['status'] in ('starting', 'running'):
                    if reuse and previous['spec'] == spec:
                        return {**self.status(previous['service_id']), 'reused': True}
                    raise WorkbenchError('service_name_in_use', 'This named service is already active; explicit identical reuse or stop is required.', effect_state='none')
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', port))
                except OSError as error:
                    raise WorkbenchError('port_occupied', 'The requested port is already occupied; no process was started.', effect_state='none') from error
            identifier = uuid.uuid4().hex
            child = self.child(request_id)
            self.journal.checkpoint(request_id, {'service_id': identifier, 'job_request_id': child,
                'phase': 'before_service_launch', 'effect_state': 'none'})
            receipt = self.jobs.start(workspace, argv, child, timeout_seconds=lease_seconds, environment_profile_id=environment_profile_id)
            record = {'service_id': identifier, 'workspace': workspace, 'name': name, 'job_id': receipt['job_id'],
                'work_session_id': work_context.get(), 'port': port, 'readiness_url': 'http://127.0.0.1:' + str(port) + readiness_path,
                'expected_sha256': expected_sha256, 'created_at': time.time(), 'expires_at': time.time() + lease_seconds,
                'lifetime': 'owned job; bounded lease; stopped on server shutdown', 'spec': spec}
            with self.db() as db:
                db.execute('INSERT INTO services VALUES (?,?,?,?)', (identifier, workspace, name, json.dumps(record)))
            self.journal.checkpoint(request_id, {'service_id': identifier, 'job_id': receipt['job_id'],
                'phase': 'service_started', 'effect_state': 'process_started'})
            deadline = time.monotonic() + wait_ms / 1000
            readiness_deadline = deadline if wait_ms else None
            result = self.status(identifier, _deadline=readiness_deadline)
            while wait_ms and not result['ready'] and result['job']['status'] in ('starting', 'running') and time.monotonic() < deadline:
                time.sleep(min(.05, max(0, deadline - time.monotonic())))
                if time.monotonic() >= deadline:
                    break
                result = self.status(identifier, _deadline=readiness_deadline)
            return {**result, 'reused': False, 'wait_expired': not result['ready'] and bool(wait_ms), 'effect_state': 'process_started'}
        return self.journal.run(request_id, {'tool': 'service_start', **spec, 'reuse': reuse}, start,
                                resource='service-name:' + workspace + ':' + name)

    def listener(self, job_id, port, *, _deadline=None):
        executable = shutil.which('lsof', path=DEFAULT_PATH)
        if executable is None:
            return {'verified': False, 'reason': 'listener_inspector_unavailable'}
        with self.jobs._lock:
            runtime = self.jobs._running.get(job_id)
            if runtime is None or not runtime.signalable:
                return {'verified': False, 'reason': 'owned_live_handle_unavailable'}
            group = runtime.process.pid
        try:
            timeout = 2 if _deadline is None else min(2, _deadline - time.monotonic())
            if timeout <= 0:
                return {'verified': False, 'reason': 'readiness_wait_expired'}
            result = subprocess.run([executable, '-nP', '-a', '-g', str(group), '-iTCP:' + str(port), '-sTCP:LISTEN', '-Fp'],
                env={'PATH': DEFAULT_PATH}, capture_output=True, timeout=timeout)
            pids = [int(line[1:]) for line in result.stdout.decode('ascii', 'replace').splitlines() if re.fullmatch(r'p[0-9]+', line)]
            pids = [pid for pid in pids if os.getpgid(pid) == group]
        except (OSError, subprocess.TimeoutExpired):
            return {'verified': False, 'reason': 'listener_inspection_failed'}
        with self.jobs._lock:
            current = self.jobs._running.get(job_id)
            stable = current is runtime and runtime.signalable
        return {'verified': bool(pids) and stable, 'listener_pids': pids if stable else [],
                'reason': 'owned_process_group_listener' if pids and stable else 'no_owned_listener'}

    def status(self, service_id, *, _deadline=None):
        record = self.load(service_id)
        job = self.jobs.status(record['job_id'], detail=False)
        listener = self.listener(record['job_id'], record['port'], _deadline=_deadline)
        readiness = {'observed': False, 'status': None, 'body_sha256': None}
        deadline = time.monotonic() + .5
        if _deadline is not None:
            deadline = min(deadline, _deadline)
        if listener['verified'] and time.monotonic() < deadline:
            try:
                status, raw = _readiness_http(record, deadline)
                digest = hashlib.sha256(raw).hexdigest()
                readiness = {'observed': True, 'status': status, 'body_sha256': digest,
                    'expected_body_matched': record['expected_sha256'] is None or digest == record['expected_sha256']}
            except (OSError, ValueError, http.client.HTTPException):
                pass
        ready = (listener['verified'] and readiness['observed'] and readiness['status'] == 200
                 and readiness.get('expected_body_matched', False)
                 and (_deadline is None or time.monotonic() < _deadline))
        return {'ok': True, 'service_id': service_id, 'name': record['name'], 'workspace': record['workspace'],
                'job_id': record['job_id'], 'port': record['port'], 'ready': ready, 'listener': listener, 'readiness': readiness,
                'job': job, 'expires_at': record['expires_at'], 'lifetime': record['lifetime'], 'checked_at': time.time(),
                'scope': 'Owned process-group listener and bounded HTTP readiness; no all-day availability guarantee.'}

    def stop(self, service_id, request_id):
        record = self.load(service_id)
        result = self.jobs.cancel(record['job_id'], request_id)
        return {**result, 'service_id': service_id, 'stop_scope': 'Owned live job process group only; no PID reattachment after restart.'}


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Readiness deadline expired')
    return remaining


class _DeadlineReader(io.RawIOBase):
    """Bound every socket read, including HTTP parser header/chunk reads."""
    def __init__(self, sock, deadline):
        super().__init__()
        # HTTPConnection can close its handle as soon as it receives a
        # close-delimited response; this reader owns its separate handle.
        self.sock, self.deadline = sock.dup(), deadline

    def readable(self):
        return True

    def makefile(self, mode):
        assert mode == 'rb'
        return io.BufferedReader(self)

    def readinto(self, buffer):
        self.sock.settimeout(_remaining(self.deadline))
        count = self.sock.recv_into(buffer)
        _remaining(self.deadline)
        return count

    def close(self):
        try:
            self.sock.close()
        finally:
            super().close()


class _ReadinessConnection(http.client.HTTPConnection):
    def __init__(self, port, deadline):
        super().__init__('127.0.0.1', port, timeout=_remaining(deadline))
        self.deadline = deadline

    def connect(self):
        # A literal IPv4 loopback target needs no resolver, proxy or alternate
        # address. The HTTP connection context owns this socket even on error.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(_remaining(self.deadline))
        self.sock.connect(('127.0.0.1', self.port))
        _remaining(self.deadline)

    def send(self, data):
        if self.sock is None:
            self.connect()
        self.sock.settimeout(_remaining(self.deadline))
        super().send(data)
        _remaining(self.deadline)

    def response_class(self, sock, **options):
        return http.client.HTTPResponse(_DeadlineReader(sock, self.deadline), **options)


def _readiness_http(record, deadline):
    parsed = urlsplit(record['readiness_url'])
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
            or parsed.port != record['port'] or parsed.username is not None or parsed.password is not None):
        raise ValueError('Readiness must target the declared loopback listener')
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    connection = _ReadinessConnection(record['port'], deadline)
    # HTTPConnection is not a context manager. Always close it ourselves;
    # HTTPResponse also owns its buffered reader after Connection: close.
    try:
        connection.request('GET', path, headers={'Connection': 'close'})
        with connection.getresponse() as response:
            if response.status >= 300:
                raise ValueError('Readiness response refused; redirects are never followed')
            raw = response.read(65537)
            # Sized HTTPResponse.read can return a short content-length body
            # without raising. Such bytes must never become a completed hash.
            if len(raw) > 65536 or response.length not in (None, 0):
                raise ValueError('Readiness body oversized or incomplete')
            _remaining(deadline)
            return response.status, raw
    finally:
        connection.close()
