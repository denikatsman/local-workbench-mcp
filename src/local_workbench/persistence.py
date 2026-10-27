"""Small durable publication helpers shared by journals and process records."""
import json
import os
import uuid
import ctypes
import sys


def rename_exclusive(source_directory, source_name, target_directory, target_name):
    """Publish a name without replacing any concurrently created destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        function, flag = libc.renameatx_np, 0x00000004  # Public SDK: RENAME_EXCL.
    elif sys.platform.startswith('linux') and hasattr(libc, 'renameat2'):
        function, flag = libc.renameat2, 1  # RENAME_NOREPLACE.
    else:
        raise OSError('Atomic no-replace rename is unavailable on this platform.')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_directory, os.fsencode(source_name), target_directory, os.fsencode(target_name), flag) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target_name)


def atomic_json(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            os.chmod(temporary, 0o600)
            json.dump(value, output, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
