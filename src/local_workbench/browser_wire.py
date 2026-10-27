"""Bounded native-messaging frames and private user-session IPC helpers."""
import ctypes
import json
import os
import socket
import stat
import struct
import sys

MAX_FRAME = 131072
MAX_TRANSFER = 8388608


class ProtocolError(ValueError):
    pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ProtocolError('duplicate_field')
        result[key] = value
    return result


def _constant(_):
    raise ProtocolError('nonfinite_number')


def read_exact(reader, count, allow_eof=False):
    data = bytearray()
    while len(data) < count:
        part = reader(count - len(data))
        if not part:
            if not data and allow_eof:
                return None
            raise ProtocolError('incomplete_frame')
        data.extend(part)
    return bytes(data)


def receive_frame(reader):
    header = read_exact(reader, 4, allow_eof=True)
    if header is None:
        return None
    count, = struct.unpack('=I', header)
    if not 1 <= count <= MAX_FRAME:
        raise ProtocolError('frame_size')
    raw = read_exact(reader, count)
    try:
        packet = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ProtocolError('invalid_json') from error
    if not isinstance(packet, dict):
        raise ProtocolError('object_required')
    return packet


def frame(packet):
    raw = json.dumps(packet, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    if not 1 <= len(raw) <= MAX_FRAME:
        raise ProtocolError('frame_size')
    return struct.pack('=I', len(raw)) + raw


def read_private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_FRAME):
            raise ProtocolError('private_descriptor_required')
        raw = source.read(MAX_FRAME + 1)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ProtocolError('object_required')
    return value


def peer_uid(connection):
    if sys.platform == 'darwin':
        library = ctypes.CDLL(None, use_errno=True)
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if library.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
            raise OSError(ctypes.get_errno(), 'peer_identity_unavailable')
        return uid.value
    if hasattr(socket, 'SO_PEERCRED'):
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return uid
    raise ProtocolError('peer_identity_unavailable')
