"""Fresh owned session leader: real controlling PTY, bounded framed input and raw output."""
import base64
import errno
import fcntl
import json
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import sys
import termios
import time
import threading

from .persistence import atomic_json


def apply_command(command, master, slave, write_lock, state):
    operation = command['operation']
    acknowledgement = {'operation': operation, 'accepted_bytes': 0, 'effect_state': 'none'}
    if operation not in ('input', 'interrupt', 'eof', 'resize'):
        return {**acknowledgement, 'error': 'unsupported_terminal_operation'}
    # Share ownership with local secret submissions. Read echo state only after
    # admission; a stale pre-lock observation cannot authorize a later write.
    if not write_lock.acquire(timeout=.25):
        return {**acknowledgement, 'error': 'terminal_input_busy'}
    try:
        if operation == 'input' and not termios.tcgetattr(slave)[3] & termios.ECHO:
            return {**acknowledgement, 'error': 'local_sensitive_input_required'}
        if operation in ('input', 'interrupt', 'eof'):
            payload = base64.b64decode(command['data_base64'], validate=True) if operation == 'input' else b'\x03' if operation == 'interrupt' else termios.tcgetattr(slave)[6][termios.VEOF]
            view = memoryview(payload)
            deadline = time.monotonic() + 2
            while view:
                if operation == 'input' and not termios.tcgetattr(slave)[3] & termios.ECHO:
                    acknowledgement['error'] = 'local_sensitive_input_required'
                    break
                try:
                    count = os.write(master, view)
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        acknowledgement['error'] = 'terminal_input_backpressure'
                        break
                    time.sleep(.01)
                    continue
                acknowledgement['accepted_bytes'] += count
                view = view[count:]
            acknowledgement['effect_state'] = 'bytes_written' if acknowledgement['accepted_bytes'] else 'none'
            if operation == 'eof':
                acknowledgement['scope'] = 'Terminal VEOF character; line discipline/program determines its meaning.'
        else:
            rows, columns = command['rows'], command['columns']
            if type(rows) is not int or type(columns) is not int or not 2 <= rows <= 100 or not 10 <= columns <= 240:
                acknowledgement['error'] = 'invalid_terminal_dimensions'
            else:
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))
                state.update(rows=rows, columns=columns)
                acknowledgement['effect_state'] = 'resized'
        return acknowledgement
    finally:
        write_lock.release()


def main(path):
    root = Path(path)
    spec = json.loads((root / 'launch.json').read_text())
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.tcsetpgrp(slave, os.getpgrp())
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', spec['rows'], spec['columns'], 0, 0))
    environment = {**os.environ, 'TERM': 'xterm', 'COLUMNS': str(spec['columns']), 'LINES': str(spec['rows'])}
    child = subprocess.Popen(spec['argv'], cwd=spec['cwd'], env=environment,
        stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    # Install after spawn: the actual terminal program retains ordinary signal
    # handling, while its transport proxy survives foreground Ctrl-C and final
    # controlling-terminal hangup long enough to publish acknowledgements/status.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    from .pty_local_input import LocalPTYInput
    write_lock = threading.Lock()
    local_input = LocalPTYInput(root, spec['terminal_id'], spec['generation'], master, slave,
                              lambda: child.poll() is None, write_lock)
    os.set_blocking(master, False)
    os.set_blocking(0, False)
    selector = selectors.DefaultSelector()
    selector.register(master, selectors.EVENT_READ, 'terminal')
    selector.register(0, selectors.EVENT_READ, 'commands')
    buffer, acknowledgements, output_bytes = b'', {}, 0
    state = {'schema_version': 1, 'terminal_id': spec['terminal_id'], 'generation': spec['generation'],
             'rows': spec['rows'], 'columns': spec['columns'], 'sensitive_input': False, 'acknowledgements': {}}
    last = 0
    def save():
        state.update(checked_at=time.time(), sensitive_input=not bool(termios.tcgetattr(slave)[3] & termios.ECHO),
                     acknowledgements=acknowledgements, output_bytes=output_bytes)
        atomic_json(root / 'state.json', state)
    try:
        save()
        while selector.get_map():
            for key, _ in selector.select(.05):
                if key.data == 'terminal':
                    try:
                        data = os.read(master, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            data = b''
                        else:
                            raise
                    if not data:
                        selector.unregister(master)
                        continue
                    # Output is the exact PTY stream. Terminal interpretation lives separately.
                    view = memoryview(data)
                    while view:
                        count = os.write(1, view)
                        view = view[count:]
                    output_bytes += len(data)
                else:
                    data = os.read(0, 65536)
                    if not data:
                        selector.unregister(0)
                        continue
                    buffer += data
                    if len(buffer) > 65536:
                        raise ValueError('Terminal command frame exceeds 64 KiB')
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        command = json.loads(line)
                        identifier = command['request_id']
                        if identifier in acknowledgements:
                            continue
                        acknowledgement = apply_command(command, master, slave, write_lock, state)
                        acknowledgements[identifier] = acknowledgement
                        if len(acknowledgements) > 100:
                            acknowledgements.pop(next(iter(acknowledgements)))
                        save()
            if time.monotonic() - last > .1:
                save(); last = time.monotonic()
            if child.poll() is not None:
                try:
                    while data := os.read(master, 65536):
                        view = memoryview(data)
                        while view:
                            written = os.write(1, view)
                            view = view[written:]
                        output_bytes += len(data)
                except (BlockingIOError, OSError):
                    pass
                state.update(exit_code=child.returncode, process_state='exited')
                save()
                break
        return child.wait()
    finally:
        local_input.close()
        selector.close()
        os.close(master)
        os.close(slave)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1]))
