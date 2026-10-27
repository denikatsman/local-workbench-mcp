import errno
import sqlite3


class WorkbenchError(Exception):
    """A stable, actionable tool error (never a success-shaped partial result)."""

    def __init__(self, code: str, message: str, **details):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message, **self.details}}


def storage_failure(error):
    """Classify allocation refusal without echoing private filenames or guessing effects."""
    reason = None
    if isinstance(error, OSError):
        reason = {errno.ENOSPC: 'volume_full', errno.EDQUOT: 'quota_exceeded'}.get(error.errno)
    elif isinstance(error, sqlite3.Error):
        code = getattr(error, 'sqlite_errorcode', None)
        if isinstance(code, int) and code & 0xff == sqlite3.SQLITE_FULL:
            reason = 'catalogue_full'
    if reason is None:
        return None
    return WorkbenchError('storage_unavailable',
        'The operating system or catalogue refused storage allocation. Free space or resolve the volume quota before continuing.',
        reason=reason, phase='execution', effect_state='unknown', durability='unknown',
        recovery='For a mutation, inspect the original request ID and current target before retrying. A new request ID can repeat an effect.').as_dict()
