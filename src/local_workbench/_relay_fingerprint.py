"""Deterministic identity of relay code, not an attestation of its globals/process.

Unlike marshal's reference-table encoding, this value encoding never observes
object identity or reference counts. Keep the field order and tags bound to the
scheme; a new encoding requires a new scheme and rejects older helpers.
"""
import hashlib
import struct
import sys
from types import CodeType


RELAY_CODE_SCHEME = 'lwb-relay-code-v1'
_CODE_FIELDS = (
    'co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
    'co_stacksize', 'co_flags', 'co_code', 'co_consts', 'co_names',
    'co_varnames', 'co_freevars', 'co_cellvars', 'co_filename', 'co_name',
    'co_qualname', 'co_firstlineno', 'co_linetable', 'co_exceptiontable',
)


def _encode(value):
    kind = type(value)
    if value is None: tag, payload = b'n', b''
    elif value is Ellipsis: tag, payload = b'e', b''
    elif kind is bool: tag, payload = b'b', b'1' if value else b'0'
    elif kind is int: tag, payload = b'i', str(value).encode('ascii')
    elif kind is float: tag, payload = b'f', struct.pack('!d', value)
    elif kind is complex: tag, payload = b'j', struct.pack('!dd', value.real, value.imag)
    elif kind is bytes: tag, payload = b'y', value
    elif kind is str: tag, payload = b's', value.encode('utf-8', errors='surrogatepass')
    elif kind is slice: tag, payload = b'l', _encode((value.start, value.stop, value.step))
    elif kind is tuple: tag, payload = b't', b''.join(_encode(item) for item in value)
    elif kind is frozenset:
        tag, payload = b'z', b''.join(sorted(_encode(item) for item in value))
    elif kind is CodeType:
        tag, payload = b'c', _encode(tuple(getattr(value, field) for field in _CODE_FIELDS))
    else:
        raise TypeError('unsupported_relay_code_constant')
    return tag + struct.pack('!Q', len(payload)) + payload


def relay_code_sha256(code):
    """Hash code and all nested code/constants, including location/debug fields.

    Python bytecode is runtime-specific. Bind implementation and interpreter
    version explicitly rather than claiming cross-runtime equivalence.
    Unsupported constant types fail closed; source bytes are never a fallback.
    """
    if type(code) is not CodeType:
        raise TypeError('relay_code_required')
    runtime = (sys.implementation.name, sys.implementation.cache_tag, tuple(sys.version_info[:3]))
    return hashlib.sha256(_encode((RELAY_CODE_SCHEME, runtime, code))).hexdigest()
