"""Chrome-started relay. Capabilities stay local and never enter browser packets."""
import argparse
from contextlib import closing
import errno
import fcntl
import json
import io
import os
from pathlib import Path
import select
import selectors
import socket
import struct
import stat
import time
import sys
import uuid

from .browser_wire import MAX_FRAME, ProtocolError, frame, peer_uid, read_private_json, receive_frame
from ._relay_fingerprint import RELAY_CODE_SCHEME, relay_code_sha256
from . import __version__


_ATTEMPT_NAME = 'native-relay-last-attempt.json'
_ATTEMPT_KIND = 'local_workbench.browser_relay_attempt'
_STAGES = frozenset(('registry_read', 'registry_validate', 'caller_validate', 'native_pipes',
    'native_hello', 'broker_connect', 'broker_peer', 'broker_hello', 'broker_ready',
    'native_ready', 'relay_wait', 'native_read', 'broker_read', 'browser_frame',
    'server_frame', 'broker_write', 'native_write'))
_PROTOCOL_CATEGORIES = frozenset(('registry_version', 'extension_origin_mismatch',
    'native_input_pipe_required', 'native_output_pipe_required', 'native_eof_watch_required', 'extension_identity_mismatch', 'interaction_version',
    'peer_identity_mismatch', 'server_generation_mismatch', 'truncated_frame',
    'frame_size', 'incomplete_frame', 'invalid_json', 'object_required',
    'private_descriptor_required', 'duplicate_field', 'nonfinite_number',
    'peer_identity_unavailable'))
_CATEGORIES = _PROTOCOL_CATEGORIES | frozenset(('protocol_error', 'broken_pipe',
    'would_block', 'bad_descriptor', 'permission_denied', 'not_found',
    'connection_refused', 'connection_reset', 'timeout', 'io_error', 'missing_field', 'value_error'))


def _failure_category(error):
    if isinstance(error, ProtocolError):
        return str(error) if str(error) in _PROTOCOL_CATEGORIES else 'protocol_error'
    if isinstance(error, TimeoutError): return 'timeout'
    if isinstance(error, OSError):
        return {errno.EPIPE: 'broken_pipe', errno.EAGAIN: 'would_block',
            errno.EBADF: 'bad_descriptor', errno.EACCES: 'permission_denied',
            errno.EPERM: 'permission_denied', errno.ENOENT: 'not_found',
            errno.ECONNREFUSED: 'connection_refused', errno.ECONNRESET: 'connection_reset',
            errno.ETIMEDOUT: 'timeout'}.get(error.errno, 'io_error')
    return 'missing_field' if isinstance(error, KeyError) else 'value_error'


def _valid_attempt(value):
    return (isinstance(value, dict)
        and set(value) == {'kind', 'version', 'stage', 'category', 'time', 'pid', 'outcome', 'input_blocking', 'output_blocking'}
        and value['kind'] == _ATTEMPT_KIND and type(value['version']) is int and value['version'] == 1
        and value['stage'] in _STAGES and value['outcome'] in ('started', 'ready', 'closed', 'failed')
        and (value['category'] in _CATEGORIES if value['outcome'] == 'failed' else value['category'] is None)
        and (value['input_blocking'] is None or type(value['input_blocking']) is bool)
        and (value['output_blocking'] is None or type(value['output_blocking']) is bool)
        and type(value['time']) is int and value['time'] >= 0
        and type(value['pid']) is int and value['pid'] > 0)


def _record_attempt(registry, stage, error=None, *, outcome='failed', input_blocking=None, output_blocking=None):
    """One private, bounded last attempt; diagnostics must never affect relay exit.

    The sibling lock serializes relay writers. Creation is exclusive; updates
    validate and write the same inode through its descriptor, so a concurrent
    unknown replacement at the path is preserved. No path replacement occurs.
    This diagnostic is deliberately non-atomic: concurrent readers or interrupted
    writes may see incomplete JSON. It is not an authority or operation receipt.
    """
    directory_fd = lock_fd = record_fd = None
    try:
        if stage not in _STAGES: return
        directory = Path(registry).absolute().parent
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory_fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077: return
        lock_fd = os.open('native-relay-failure.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600, dir_fd=directory_fd)
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size != 0): return
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            record_fd = os.open(_ATTEMPT_NAME, flags | os.O_CREAT | os.O_EXCL,
                0o600, dir_fd=directory_fd)
            created = True
        except FileExistsError:
            record_fd = os.open(_ATTEMPT_NAME, flags, dir_fd=directory_fd)
            created = False
        info = os.fstat(record_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > MAX_FRAME): return
        if created:
            if info.st_size != 0: return
        elif not _valid_attempt(json.loads(os.pread(record_fd, MAX_FRAME + 1, 0))):
            return
        record = {'kind': _ATTEMPT_KIND, 'version': 1, 'stage': stage,
            'category': _failure_category(error) if outcome == 'failed' else None,
            'time': int(time.time()), 'pid': os.getpid(), 'outcome': outcome,
            'input_blocking': input_blocking, 'output_blocking': output_blocking}
        if not _valid_attempt(record): return
        encoded = json.dumps(record, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()
        offset = 0
        while offset < len(encoded):
            written = os.pwrite(record_fd, encoded[offset:], offset)
            if written <= 0: raise OSError('diagnostic_write_incomplete')
            offset += written
        os.ftruncate(record_fd, len(encoded))
        os.fsync(record_fd)
        if created: os.fsync(directory_fd)
    except Exception:
        pass
    finally:
        for fd in (record_fd, lock_fd, directory_fd):
            if fd is not None:
                try: os.close(fd)
                except OSError: pass


def relay(registry, caller, incoming, outgoing, *, _progress=None):
    progress = _progress if _progress is not None else [None, None, None]
    progress[0] = 'registry_read'
    descriptor = read_private_json(registry)
    progress[0] = 'registry_validate'
    if (type(descriptor.get('version')) is not int or descriptor['version'] not in (1, 2)
            or descriptor['version'] == 2 and (type(descriptor.get('interaction_version')) is not int or descriptor['interaction_version'] != 1)):
        raise ProtocolError('registry_version')
    progress[0] = 'caller_validate'
    expected = 'chrome-extension://' + descriptor['extension_id'] + '/'
    if caller != expected:
        raise ProtocolError('extension_origin_mismatch')
    # Chrome provides a pipe. Read its descriptor directly so BufferedReader
    # cannot prefetch bytes that the readiness loop then misses.
    progress[0] = 'native_pipes'
    try: input_fd = incoming.fileno()
    except (AttributeError, OSError, ValueError): raise ProtocolError('native_input_pipe_required')
    # Native-messaging pipes may inherit O_NONBLOCK. The framing reader and
    # buffered stdout require blocking descriptors; normalize before any I/O.
    try: output_fd = outgoing.fileno()
    except (AttributeError, OSError, ValueError): raise ProtocolError('native_output_pipe_required')
    progress[1] = os.get_blocking(input_fd)
    progress[2] = os.get_blocking(output_fd)
    _record_attempt(registry, 'native_pipes', outcome='started',
        input_blocking=progress[1], output_blocking=progress[2])
    os.set_blocking(input_fd, True)
    os.set_blocking(output_fd, True)
    progress[0] = 'native_hello'
    hello = receive_frame(lambda count: os.read(input_fd, count))
    if hello is None or hello.get('type') != 'hello' or hello.get('extension_id') != descriptor['extension_id']:
        raise ProtocolError('extension_identity_mismatch')
    if 'interaction_version' in hello and (type(hello['interaction_version']) is not int or hello['interaction_version'] != 1):
        raise ProtocolError('interaction_version')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        progress[0] = 'broker_connect'
        connection.connect(descriptor['socket'])
        progress[0] = 'broker_peer'
        if peer_uid(connection) != os.getuid():
            raise ProtocolError('peer_identity_mismatch')
        progress[0] = 'broker_hello'
        connection.sendall(frame({'type': 'hello', 'token': descriptor['token'],
            'server_generation': descriptor['server_generation'], 'install_id': descriptor['install_id'],
            'native_generation': uuid.uuid4().hex, 'native_version': __version__,
            'native_relay_code_scheme': RELAY_CODE_SCHEME,
            'native_relay_code_sha256': relay_code_sha256(relay.__code__), 'extension': hello}))
        progress[0] = 'broker_ready'
        accepted = receive_frame(connection.recv)
        if accepted is None or accepted.get('type') != 'ready' or accepted.get('server_generation') != descriptor['server_generation']:
            raise ProtocolError('server_generation_mismatch')
        # Pairing is bounded; ordinary traffic must drain both directions even
        # while the broker replies to a burst of browser history. Blocking a
        # write here can deadlock both peers despite every frame being valid.
        connection.setblocking(False)
        os.set_blocking(input_fd, False)
        os.set_blocking(output_fd, False)
        progress[0] = 'native_ready'
        _record_attempt(registry, 'native_ready', outcome='ready',
            input_blocking=progress[1], output_blocking=progress[2])
        # One selector owns reads and writes. Reserve one complete maximum
        # frame before reading, and never read beyond the current frame. Each
        # direction retains at most two queued frames plus one input frame.
        # No thread, timer, history pruning or unbounded output queue is needed.
        frame_bytes = MAX_FRAME + 4
        queue_limit = 2 * frame_bytes
        buffers = {'browser': bytearray(), 'server': bytearray()}
        pending = {'browser': bytearray(frame(accepted)), 'server': bytearray()}
        server_closed = False
        browser_closed = False
        server_fd = connection.fileno()
        # A saturated input queue cannot retain a normal READ watch: pending
        # bytes would spin the selector. Observe pipe closure independently,
        # without consuming or buffering more input. The edge-cleared kqueue
        # monitor and HUP-only epoll monitor also wake through their own FD.
        if hasattr(select, 'kqueue'):
            eof_watch = select.kqueue()
            try:
                eof_watch.control([select.kevent(input_fd, filter=select.KQ_FILTER_READ,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR)], 0, 0)
            except BaseException:
                eof_watch.close()
                raise
            def browser_eof():
                return any(event.flags & select.KQ_EV_EOF for event in eof_watch.control(None, 1, 0))
        elif hasattr(select, 'epoll'):
            eof_watch = select.epoll()
            try: eof_watch.register(input_fd, select.EPOLLHUP | select.EPOLLERR)
            except BaseException:
                eof_watch.close()
                raise
            def browser_eof():
                return any(mask & (select.EPOLLHUP | select.EPOLLERR) for _, mask in eof_watch.poll(0, 1))
        else:
            raise ProtocolError('native_eof_watch_required')
        with closing(eof_watch), selectors.DefaultSelector() as selector:
            def read_packet(kind, fd):
                progress[0] = 'native_read' if kind == 'browser' else 'broker_read'
                buffer = buffers[kind]
                count = 4 - len(buffer) if len(buffer) < 4 else 4 + struct.unpack('=I', buffer[:4])[0] - len(buffer)
                try: chunk = os.read(fd, count)
                except BlockingIOError: return True
                if not chunk:
                    if buffer: raise ProtocolError('truncated_frame')
                    return False
                buffer.extend(chunk)
                if len(buffer) >= 4:
                    progress[0] = 'browser_frame' if kind == 'browser' else 'server_frame'
                    size = struct.unpack('=I', buffer[:4])[0]
                    if not 1 <= size <= MAX_FRAME: raise ProtocolError('frame_size')
                    if len(buffer) == 4 + size:
                        packet = receive_frame(io.BytesIO(buffer).read)
                        destination = 'server' if kind == 'browser' else 'browser'
                        pending[destination].extend(frame(packet))
                        buffer.clear()
                return True

            def write_pending(kind, fd):
                progress[0] = 'native_write' if kind == 'browser' else 'broker_write'
                try: count = os.write(fd, memoryview(pending[kind])[:frame_bytes])
                except BlockingIOError: return
                if count <= 0: raise BrokenPipeError(errno.EPIPE, 'relay_write_closed')
                del pending[kind][:count]

            while True:
                if server_closed and not pending['browser']: return
                if browser_closed and (server_closed or len(pending['server']) > queue_limit - frame_bytes): return
                wanted = {eof_watch.fileno(): (selectors.EVENT_READ, 'browser_eof')}
                if server_closed or len(pending['server']) <= queue_limit - frame_bytes:
                    wanted[input_fd] = (selectors.EVENT_READ, 'browser')
                if pending['browser']:
                    wanted[output_fd] = (selectors.EVENT_WRITE, 'output')
                if not server_closed:
                    mask = (selectors.EVENT_READ if len(pending['browser']) <= queue_limit - frame_bytes else 0)
                    if pending['server']: mask |= selectors.EVENT_WRITE
                    if mask: wanted[server_fd] = (mask, 'server')
                for fd in list(selector.get_map()):
                    if fd not in wanted: selector.unregister(fd)
                for fd, (mask, kind) in wanted.items():
                    if fd in selector.get_map(): selector.modify(fd, mask, kind)
                    else: selector.register(fd, mask, kind)
                progress[0] = 'relay_wait'
                for key, mask in selector.select():
                    kind = key.data
                    if kind == 'browser_eof':
                        # Normally the framed reader consumes final bytes and
                        # diagnoses truncation. The closure latch bypasses only
                        # a backpressured reader that cannot otherwise wake.
                        browser_closed = browser_closed or browser_eof()
                    elif kind == 'output':
                        write_pending('browser', output_fd)
                    elif kind == 'browser':
                        if server_closed:
                            # Drain only already validated broker replies. New
                            # browser input cannot reach a disconnected broker;
                            # still notice its EOF while stdout is backpressured.
                            try: chunk = os.read(input_fd, frame_bytes)
                            except BlockingIOError: continue
                            if not chunk: return
                        elif not read_packet('browser', input_fd): return
                    elif not server_closed:
                        if mask & selectors.EVENT_READ and not read_packet('server', server_fd):
                            server_closed = True
                            pending['server'].clear()
                        if not server_closed and mask & selectors.EVENT_WRITE:
                            write_pending('server', server_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Local Workbench selected-tab native messaging relay')
    parser.add_argument('--registry', required=True)
    parser.add_argument('caller')
    args = parser.parse_args(argv)
    progress = ['registry_read', None, None]
    try:
        relay(args.registry, args.caller, sys.stdin.buffer, sys.stdout.buffer, _progress=progress)
        _record_attempt(args.registry, progress[0], outcome='closed',
            input_blocking=progress[1], output_blocking=progress[2])
        return 0
    except (OSError, ValueError, KeyError) as error:
        _record_attempt(args.registry, progress[0], error,
            input_blocking=progress[1], output_blocking=progress[2])
        # Raw packets, keys, URLs and document contents never enter diagnostics.
        code = str(error) if isinstance(error, ProtocolError) else type(error).__name__
        sys.stderr.write('Local Workbench browser relay unavailable: ' + code + '\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
