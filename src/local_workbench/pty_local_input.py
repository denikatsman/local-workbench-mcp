"""Local-user sensitive PTY input; model arguments and tool histories carry no text."""
import base64
import contextlib
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import socket
import tempfile
import termios
import threading
import time

from .browser_wire import ProtocolError, frame, peer_uid, receive_frame
from .persistence import atomic_json


class LocalPTYInput:
    def __init__(self, root, terminal_id, generation, master, slave, alive, write_lock=None):
        self.root, self.terminal_id, self.generation = Path(root), terminal_id, generation
        self.master, self.slave, self.alive = master, slave, alive
        self.write_lock = write_lock or threading.Lock()
        self.lock = threading.Lock()
        self.records = {}
        self.stopped = threading.Event()
        self.clients = threading.BoundedSemaphore(4)
        self.token = secrets.token_hex(32)
        self.directory = tempfile.TemporaryDirectory(prefix='lwb-pty-input-', dir='/tmp')
        self.path = str(Path(self.directory.name) / 's')
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path); os.chmod(self.path, 0o600); self.listener.listen(4); self.listener.settimeout(.25)
        atomic_json(self.root / 'local-input.json', {'version': 1, 'socket': self.path, 'token': self.token,
            'terminal_id': terminal_id, 'generation': generation, 'worker_pid': os.getpid()})
        self.thread = threading.Thread(target=self._accept, daemon=True, name='local-pty-input')
        self.thread.start()

    def _accept(self):
        while not self.stopped.is_set():
            try: connection, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            if not self.clients.acquire(blocking=False): connection.close(); continue
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        try:
            connection.settimeout(2)
            if peer_uid(connection) != os.getuid(): raise ProtocolError('peer_identity')
            result = self.submit(receive_frame(connection.recv))
            connection.sendall(frame(result))
        except (OSError, ValueError, TypeError, KeyError):
            with contextlib.suppress(OSError):
                connection.sendall(frame({'ok': False, 'error': 'local_input_protocol', 'effect_state': 'unknown'}))
        finally:
            connection.close(); self.clients.release()

    def submit(self, packet):
        if (not isinstance(packet, dict) or type(packet.get('version')) is not int or packet['version'] != 1
                or packet.get('terminal_id') != self.terminal_id or packet.get('generation') != self.generation
                or not isinstance(packet.get('token'), str) or not hmac.compare_digest(packet['token'], self.token)):
            raise ProtocolError('local_input_identity')
        identifier = packet.get('submission_id')
        if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier):
            raise ProtocolError('local_submission_id')
        raw = base64.b64decode(packet.get('data', ''), validate=True)
        if not 1 <= len(raw) <= 4096:
            raise ProtocolError('local_input_limit')
        digest = hmac.new(self.token.encode(), raw, hashlib.sha256).digest()
        with self.lock:
            old = self.records.get(identifier)
            if old:
                if not hmac.compare_digest(old['digest'], digest):
                    return {'ok': False, 'error': 'local_submission_conflict', 'effect_state': 'none'}
                return {**old['receipt'], 'replayed': True}
            if len(self.records) >= 100:
                return {'ok': False, 'error': 'local_submission_limit', 'effect_state': 'none'}
            receipt = {'ok': False, 'terminal_id': self.terminal_id, 'generation': self.generation,
                'submission_id': identifier, 'accepted_bytes': 0, 'effect_state': 'unknown', 'error': 'local_submission_pending'}
            self.records[identifier] = {'digest': digest, 'receipt': receipt}
        if not self.write_lock.acquire(timeout=.25):
            receipt.update(error='terminal_input_busy', effect_state='none'); return dict(receipt)
        try:
            if not self.alive() or self.stopped.is_set():
                receipt.update(error='terminal_ended', effect_state='none'); return dict(receipt)
            if termios.tcgetattr(self.slave)[3] & termios.ECHO:
                receipt.update(error='terminal_echo_enabled', effect_state='none'); return dict(receipt)
            view, deadline = memoryview(raw), time.monotonic() + 2
            while view:
                if not self.alive() or termios.tcgetattr(self.slave)[3] & termios.ECHO:
                    receipt.update(error='terminal_echo_or_process_changed'); break
                try: count = os.write(self.master, view)
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        receipt.update(error='terminal_input_backpressure'); break
                    time.sleep(.01); continue
                receipt['accepted_bytes'] += count; view = view[count:]
            if not view:
                receipt.update(ok=True); receipt.pop('error', None)
            receipt['effect_state'] = 'bytes_written' if receipt['accepted_bytes'] else 'none'
            receipt['checked_at'] = time.time()
            with self.lock: public = {key: dict(row['receipt']) for key, row in self.records.items()}
            atomic_json(self.root / 'local-input-receipts.json', {'terminal_id': self.terminal_id, 'generation': self.generation,
                'submissions': public, 'scope': 'Local transport receipts; application output/postcondition is separate.'})
            return dict(receipt)
        except OSError:
            receipt.update(error='terminal_input_unavailable', effect_state='unknown'); return dict(receipt)
        finally: self.write_lock.release()

    def close(self):
        self.stopped.set(); self.listener.close(); self.thread.join(1)
        self.directory.cleanup()
