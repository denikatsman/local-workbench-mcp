"""Read-only state inspection, independent of normal service construction."""
from __future__ import annotations

import json
import math
import os
import re
import stat
from pathlib import Path


JOB_STATES = {"starting", "running", "completed", "cancelled", "timed_out", "output_limited",
              "storage_limited", "failed", "interrupted"}


def read_job_record(path: Path) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise ValueError("Job metadata must be a regular file within 8 MiB")
        with os.fdopen(fd, "rb", closefd=False) as source:
            record = json.loads(source.read(8 * 1024 * 1024 + 1))
    finally:
        os.close(fd)
    if not isinstance(record, dict) or record.get("job_id") != path.stem or not re.fullmatch(r"[0-9a-f]{32}", path.stem):
        raise ValueError("Job identity does not match its record")
    if record.get("status") not in JOB_STATES:
        raise ValueError("Unknown job lifecycle state")
    if not isinstance(record.get("workspace"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", record["workspace"]):
        raise ValueError("Invalid recorded workspace")
    argv = record.get("argv")
    if not isinstance(argv, list) or not 1 <= len(argv) <= 4096 or any(not isinstance(arg, str) for arg in argv):
        raise ValueError("Invalid recorded command")
    if type(record.get("output_complete")) is not bool or not isinstance(record.get("artifacts"), dict):
        raise ValueError("Invalid recorded output metadata")
    created = record.get("created_at")
    if type(created) not in (int, float) or not math.isfinite(created):
        raise ValueError("Invalid job creation timestamp")
    for stream in ("stdout", "stderr"):
        spool = path.with_suffix("." + stream)
        info = spool.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{stream} spool is not a regular file")
        record[f"{stream}_bytes"] = info.st_size
    return record


def inspect_state(state_dir: Path, offset=0, limit=10) -> dict:
    """No creation, chmod, journal/database writes, repair, or process signals."""
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 20:
        from .errors import WorkbenchError
        raise WorkbenchError("invalid_range", "offset must be nonnegative and limit must be 1..20.")
    root = Path(state_dir)
    marker = root / ".local-workbench-state"
    try:
        if not stat.S_ISREG(marker.lstat().st_mode):
            raise ValueError("State marker is not a regular file")
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            if source.read(128) != b"local-workbench-state-v1\n":
                raise ValueError("Unrecognized state marker")
    except FileNotFoundError:
        return {"ok": True, "state": "unrecognized", "checked": "state marker only", "repair_performed": False}
    except (OSError, ValueError):
        return {"ok": True, "state": "unavailable", "checked": "state marker only", "repair_performed": False}
    healthy, errors = 0, []
    directory = root / "jobs"
    try:
        if directory.is_symlink():
            raise ValueError("Job directory is a symlink")
        paths = sorted(path for path in directory.iterdir() if path.suffix == ".json") if directory.exists() else []
    except (OSError, ValueError) as exc:
        return {"ok": True, "state": "unavailable", "inspection_complete": False,
                "error": {"code": "state_unreadable", "reason": str(exc)[:240]}, "repair_performed": False}
    for path in paths:
        try:
            read_job_record(path)
            healthy += 1
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            errors.append({"record": path.name, "code": "job_state_invalid", "reason": str(exc)[:240]})
    return {"ok": True, "state": "degraded" if errors else "healthy", "healthy_jobs": healthy,
            "damaged_jobs": len(errors), "errors": errors[offset:offset + limit],
            "next_offset": offset + limit if offset + limit < len(errors) else None,
            "repair_performed": False, "snapshot_atomic": False,
            "checked": "job metadata and spool presence/type; artifact bytes and SQLite integrity not checked",
            "process_ownership": "not inferred from saved PIDs"}
