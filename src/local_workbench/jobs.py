"""Durable host processes with exact, independently paged output streams.

Workspace execution is an explicit grant of host-user authority, not a sandbox.
The output ceiling is a stop trigger: the final pipe drain can exceed it, and
every byte successfully captured is retained. Detached descendants can escape
a process group; bounded drain failures are reported rather than hidden.
"""
from __future__ import annotations

import base64
import copy
import fcntl
import json
import math
import os
import re
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field

from .errors import WorkbenchError
from .diagnostics import read_job_record
from .persistence import atomic_json as _atomic_json
from .runtime import DEFAULT_PATH
from .context import work_context, capture_sensitive


TERMINAL = {"completed", "cancelled", "timed_out", "output_limited", "storage_limited", "failed", "interrupted"}
MAX_PAGE = 256 * 1024
MAX_INPUT = 64 * 1024


@dataclass
class _Running:
    process: subprocess.Popen
    thread: threading.Thread | None = None
    reason: str | None = None
    stop_at: float | None = None
    stdin_closed: bool = False
    # Keep the leader unreaped while its group is signalable so the PID cannot
    # be recycled for an unrelated process group during output drain.
    signalable: bool = True
    input_lock: threading.Lock = field(default_factory=threading.Lock)


class JobManager:
    def active_ids(self, work_session_id=None):
        with self._lock:
            # _running remains populated while final output is being retained.
            return [identifier for identifier in self._running if work_session_id is None
                    or self._records[identifier].get('work_session_id') == work_session_id]

    def __init__(self, config, store, journal, *, allow_degraded=False):
        self.config, self.store, self.journal = config, store, journal
        self.directory = config.state_dir / "jobs"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._closed = False
        self._running: dict[str, _Running] = {}
        self._records: dict[str, dict] = {}
        self.profiles = None
        self.recovery_errors = []
        self._owner = (self.directory / "owner.lock").open("a+b")
        os.chmod(self.directory / "owner.lock", 0o600)
        try:
            fcntl.flock(self._owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._owner.close()
            raise WorkbenchError("jobs_already_owned", "Another process owns this job directory.") from None
        try:
            for path in sorted(self.directory.glob("*.json")):
                try:
                    record = read_job_record(path)
                except (OSError, ValueError, TypeError, RecursionError) as exc:
                    if not allow_degraded:
                        raise
                    self.recovery_errors.append({"record": path.name, "reason": str(exc)[:240]})
                    continue
                job_id = record["job_id"]
                if record.get("status") not in TERMINAL:
                    record.update(status="interrupted", termination_reason="server_restarted", finished_at=time.time(),
                                  output_complete=False, process_state="unknown", stdin_open=False)
                    record["recovery_note"] = "The previous process may still exist. Its persisted PID is never signalled or reattached."
                    # Retain original metadata in degraded mode. A read-only
                    # diagnostic must not rewrite the only surviving record.
                    if not allow_degraded:
                        self._save(record)
                self._records[job_id] = record
            self._spool_bytes = sum(p.stat().st_size for p in self.directory.iterdir() if p.suffix in {".stdout", ".stderr"})
        except Exception as exc:
            fcntl.flock(self._owner, fcntl.LOCK_UN)
            self._owner.close()
            raise WorkbenchError("job_state_invalid", "Cannot recover job state; preserve the state directory for inspection.", reason=str(exc)) from exc

    def _spool(self, job_id: str, stream: str) -> Path:
        return self.directory / f"{job_id}.{stream}"

    def _save(self, record: dict) -> None:
        _atomic_json(self.directory / f"{record['job_id']}.json", record)

    def _record(self, job_id: str) -> dict:
        if not isinstance(job_id, str) or job_id not in self._records:
            if any(error["record"] == str(job_id) + ".json" for error in self.recovery_errors):
                raise WorkbenchError("job_state_invalid", "This job's evidence is damaged; inspect state before repair.", job_id=job_id)
            raise WorkbenchError("unknown_job", "Unknown job ID.")
        return self._records[job_id]

    def _public(self, record: dict, *, detail=True) -> dict:
        if detail:
            result = copy.deepcopy(record)
        else:
            keys = ("job_id", "workspace", "status", "created_at", "started_at", "finished_at", "exit_code",
                    "termination_reason", "stdout_bytes", "stderr_bytes", "output_complete", "stdin_open",
                    "process_state", "publication_state", "sequence", "output_stop_after_bytes", "work_session_id")
            result = {key: record[key] for key in keys if key in record}
            result["command_available"] = True
            result["warning_count"] = len(record.get("warnings", []))
            result["error_present"] = bool(record.get("error"))
            result["artifact_error_streams"] = list(record.get("artifact_errors", {}))
            result["details_operation"] = "job_status(detail=true)"
        return {"ok": True, **result, "completion_scope": "leader_and_captured_pipes",
                "descendant_quiescence": "not_established", "verification_state": "not_requested"}

    def _notify(self, record):
        record["sequence"] = record.get("sequence", 0) + 1
        self._changed.notify_all()  # Caller holds self._lock.

    @staticmethod
    def _check_owner(record):
        owner=record.get('work_session_id')
        if owner is not None and work_context.get()!=owner:
            raise WorkbenchError('work_session_mismatch','This job belongs to a different work context; use its matching context deliberately.',
                                 owner_work_session_id=owner,effect_state='none')

    def start(self, workspace: str, argv: list[str], request_id: str, cwd: str = ".",
              timeout_seconds: float = 300, env: dict[str, str] | None = None,
              keep_stdin: bool = False, output_stop_after_bytes: int | None = None,
              environment_profile_id: str | None = None) -> dict:
        workspace_config = self.config.workspace(workspace)
        if not workspace_config.executable:
            raise WorkbenchError("execution_denied", "Command execution is disabled for this workspace.")
        if not isinstance(argv, list) or not argv or len(argv) > 4096 or any(not isinstance(v, str) or "\0" in v for v in argv) or not argv[0]:
            raise WorkbenchError("invalid_argv", "argv must be a nonempty array of strings without NUL bytes.")
        if sum(len(v.encode("utf-8")) for v in argv) > 1024 * 1024:
            raise WorkbenchError("invalid_argv", "Command arguments exceed the 1 MiB input limit.")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 86400:
            raise WorkbenchError("invalid_timeout", "timeout_seconds must be greater than zero and at most 86400.")
        if type(keep_stdin) is not bool:
            raise WorkbenchError("invalid_stdin", "keep_stdin must be a boolean.")
        if output_stop_after_bytes is not None and (type(output_stop_after_bytes) is not int or
                not 1 <= output_stop_after_bytes <= self.config.max_job_output_bytes):
            raise WorkbenchError("invalid_output_limit", "Output stop trigger must be positive and within the configured ceiling.")
        if not isinstance(cwd, str) or "\0" in cwd or Path(cwd).is_absolute():
            raise WorkbenchError("invalid_cwd", "cwd must be a relative directory inside the workspace.")
        try:
            directory = (workspace_config.root / cwd).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise WorkbenchError("invalid_cwd", "Cannot resolve command working directory.", reason=str(exc)) from exc
        if not directory.is_relative_to(workspace_config.root) or not directory.is_dir():
            raise WorkbenchError("invalid_cwd", "cwd must be a directory inside the workspace.")
        additions = {} if env is None else env
        if not isinstance(additions, dict) or any(not isinstance(k, str) or not k or "=" in k or "\0" in k or not isinstance(v, str) or "\0" in v for k, v in additions.items()):
            raise WorkbenchError("invalid_environment", "Environment additions must be string pairs without NUL bytes or '=' in names.")
        if sum(len(k.encode()) + len(v.encode()) for k, v in additions.items()) > 1024 * 1024:
            raise WorkbenchError("invalid_environment", "Environment additions exceed 1 MiB.")
        payload = dict(operation="job_start", workspace=workspace, argv=argv, cwd=cwd,
                       timeout_seconds=timeout_seconds, env=additions, keep_stdin=keep_stdin)
        if environment_profile_id is not None:
            payload['environment_profile_id'] = environment_profile_id
        if work_context.get() is not None:payload['work_session_id']=work_context.get()
        sensitive = capture_sensitive.get() is True
        if sensitive: payload['potentially_sensitive'] = True
        if output_stop_after_bytes is not None:
            payload["output_stop_after_bytes"] = output_stop_after_bytes

        def launch():
            launch_argv, launch_env, profile = list(argv), dict(additions), None
            if environment_profile_id is not None:
                if self.profiles is None:
                    raise WorkbenchError('environment_profile_unavailable', 'No runtime-profile registry is attached.')
                launch_argv, launch_env, profile = self.profiles.prepare(workspace, environment_profile_id, argv, additions)
            with self._lock:
                if self._closed:
                    raise WorkbenchError("jobs_closed", "The job manager is shutting down.")
                if self.recovery_errors:
                    raise WorkbenchError("state_degraded", "New execution is disabled while job history is damaged; use state_inspect and preserve the original state.",
                                         damaged_records=len(self.recovery_errors))
                if len(self._running) >= self.config.max_jobs:
                    raise WorkbenchError("job_limit", "The concurrent job limit is reached.", max_jobs=self.config.max_jobs)
                if self.store.storage_bytes() >= self.config.max_storage_bytes:
                    raise WorkbenchError("storage_limit", "State storage is full; no new process was started.")
                job_id = uuid.uuid4().hex
                record = dict(job_id=job_id, start_request_id=request_id, workspace=workspace, argv=launch_argv, cwd=cwd,
                              status="starting", created_at=time.time(), started_at=None, finished_at=None,
                              timeout_seconds=timeout_seconds, exit_code=None, termination_reason=None,
                              stdout_bytes=0, stderr_bytes=0, output_complete=False, artifacts={},
                              stdin_open=keep_stdin, environment_names=sorted(launch_env),
                              sequence=0, publication_state="capturing",
                              output_stop_after_bytes=output_stop_after_bytes or self.config.max_job_output_bytes,
                              execution_scope="host_user_not_sandboxed")
                record['work_session_id']=work_context.get()
                if sensitive: record['potentially_sensitive'] = True
                if profile is not None:
                    record['environment_profile'] = profile
                for stream in ("stdout", "stderr"):
                    descriptor = os.open(self._spool(job_id, stream), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(descriptor)
                self._records[job_id] = record
                self._save(record)
                # Never inherit service tokens, tunnel credentials, or loader
                # hooks from the MCP server environment. HOME retains its real
                # meaning; host commands can read user files and configuration.
                self.journal.checkpoint(request_id, {"job_id": job_id, "phase": "before_spawn", "effect_state": "none"})
                process_env = {"PATH": DEFAULT_PATH,
                               "HOME": str(Path.home()), "LANG": "en_US.UTF-8", "TMPDIR": "/tmp"}
                process_env.update(launch_env)
                try:
                    process = subprocess.Popen(launch_argv, cwd=directory, env=process_env,
                                               stdin=subprocess.PIPE if keep_stdin else subprocess.DEVNULL,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               start_new_session=True, close_fds=True, bufsize=0)
                except (OSError, ValueError) as exc:
                    record.update(status="failed", termination_reason="spawn_failed", finished_at=time.time(),
                                  stdin_open=False, output_complete=True, error=str(exc))
                    self._save(record)
                    raise WorkbenchError("spawn_failed", "The command could not be started.", job_id=job_id, reason=str(exc)) from exc
                runtime = _Running(process)
                self._running[job_id] = runtime
                record.update(status="running", started_at=time.time(), pid=process.pid)
                try:
                    self._save(record)
                    if process.stdin is not None:
                        os.set_blocking(process.stdin.fileno(), False)
                    thread = threading.Thread(target=self._monitor, args=(job_id, runtime), name=f"job-{job_id[:8]}", daemon=True)
                    runtime.thread = thread
                    thread.start()
                except Exception:
                    self._signal(runtime, signal.SIGKILL)
                    runtime.signalable = False
                    process.wait(timeout=5)
                    for pipe in (process.stdin, process.stdout, process.stderr):
                        if pipe is not None:
                            pipe.close()
                    self._running.pop(job_id, None)
                    record.update(status="failed", termination_reason="monitor_start_failed", finished_at=time.time(), stdin_open=False)
                    self._save(record)
                    raise
                return self._public(record)

        return self.journal.run(request_id, payload, launch)

    def _leader_exited(self, runtime: _Running) -> bool:
        """Observe without reaping; a zombie leader still reserves its PID."""
        with self._lock:
            if not runtime.signalable or runtime.process.returncode is not None:
                runtime.signalable = False
                return True
            try:
                result = os.waitid(os.P_PID, runtime.process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            except ChildProcessError:
                # An external reaper removed ownership. Never signal that PID.
                runtime.signalable = False
                return True
            return result is not None

    def _signal(self, runtime: _Running, signum: int) -> None:
        with self._lock:
            # Check external reaping too; normal exits remain waitable zombies.
            self._leader_exited(runtime)
            if not runtime.signalable:
                return
            try:
                os.killpg(runtime.process.pid, signum)
            except ProcessLookupError:
                pass

    def _retire_and_wait(self, runtime: _Running, timeout: float = 1) -> int:
        # This transition precedes every final reap and is serialized with
        # cancel/close/input. Artifact publication may continue afterward.
        with self._lock:
            runtime.signalable = False
        return runtime.process.wait(timeout=timeout)

    def _stop(self, runtime: _Running, reason: str) -> None:
        if runtime.signalable and runtime.reason is None:
            runtime.reason, runtime.stop_at = reason, time.monotonic()
            # A producer ignoring SIGTERM must not generate unlimited extra
            # output during the normal cancellation grace period.
            force = reason in {"output_limit", "storage_limit", "capture_failed"}
            self._signal(runtime, signal.SIGKILL if force else signal.SIGTERM)

    def _monitor(self, job_id: str, runtime: _Running) -> None:
        process = runtime.process
        selector = selectors.DefaultSelector()
        spools = {}
        deadline = time.monotonic() + self._records[job_id]["timeout_seconds"]
        errors = []
        complete = True
        killed = False
        last_save = time.monotonic()
        try:
            for stream in ("stdout", "stderr"):
                pipe = getattr(process, stream)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, stream)
                spools[stream] = self._spool(job_id, stream).open("ab", buffering=0)
            while selector.get_map() or not self._leader_exited(runtime):
                now = time.monotonic()
                with self._lock:
                    if now >= deadline:
                        self._stop(runtime, "timeout")
                    if runtime.stop_at is not None and now - runtime.stop_at >= 0.5 and not killed:
                        self._signal(runtime, signal.SIGKILL)
                        killed = True
                    if runtime.stop_at is not None and now - runtime.stop_at >= 3:
                        if selector.get_map():
                            complete = False
                            errors.append("pipe_drain_timeout: a descendant may have escaped the process group")
                        break
                for key, _ in selector.select(timeout=0.05):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    stream = key.data
                    # FileIO.write may return a short count; retain all captured bytes.
                    view = memoryview(chunk)
                    while view:
                        written = spools[stream].write(view)
                        if not written:
                            raise OSError("Output spool write made no progress")
                        view = view[written:]
                        with self._lock:
                            self._records[job_id][f"{stream}_bytes"] += written
                            self._spool_bytes += written
                            self._notify(self._records[job_id])
                    with self._lock:
                        record = self._records[job_id]
                        if record["stdout_bytes"] + record["stderr_bytes"] >= record["output_stop_after_bytes"]:
                            self._stop(runtime, "output_limit")
                        if self._spool_bytes >= self.config.max_storage_bytes:
                            self._stop(runtime, "storage_limit")
                if time.monotonic() - last_save > 0.5:
                    for spool in spools.values():
                        os.fsync(spool.fileno())
                    with self._lock:
                        if self.store.storage_bytes() >= self.config.max_storage_bytes:
                            self._stop(runtime, "storage_limit")
                        self._save(self._records[job_id])
                    last_save = time.monotonic()
            try:
                exit_code = self._retire_and_wait(runtime)
            except subprocess.TimeoutExpired:
                complete = False
                errors.append("process_exit_unconfirmed")
                exit_code = None
        except Exception as exc:
            complete = False
            errors.append(f"capture_failed: {type(exc).__name__}: {exc}")
            with self._lock:
                self._stop(runtime, "capture_failed")
                runtime.reason = runtime.reason or "capture_failed"
                self._signal(runtime, signal.SIGKILL)
            try:
                exit_code = self._retire_and_wait(runtime)
            except subprocess.TimeoutExpired:
                exit_code = None
        finally:
            selector.close()
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
            with self._lock:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                runtime.stdin_closed = True
                self._records[job_id]["stdin_open"] = False
            for spool in spools.values():
                try:
                    os.fsync(spool.fileno())
                except OSError as exc:
                    complete = False
                    errors.append(f"spool_sync_failed: {exc}")
                finally:
                    spool.close()

        with self._lock:
            record = self._records[job_id]
            record.update(process_state="exited" if exit_code is not None else "unknown", exit_code=exit_code,
                          publication_state="finalizing_output")
            self._notify(record)
        artifacts, artifact_errors = {}, {}
        for stream in ("stdout", "stderr"):
            try:
                source = (json.dumps({'kind': 'job-output', 'job_id': job_id, 'stream': stream, 'potentially_sensitive': True})
                          if record.get('potentially_sensitive') is True else f"job:{job_id}:{stream}")
                artifacts[stream] = self.store.put_file(self._spool(job_id, stream), source=source)
            except Exception as exc:
                artifact_errors[stream] = {"code": getattr(exc, "code", "artifact_failed"), "message": str(exc), "spool_retained": True}
                errors.append(f"{stream}_artifact_failed: {type(exc).__name__}: {exc}; spool retained")
        with self._lock:
            record = self._records[job_id]
            state = {"cancelled": "cancelled", "shutdown": "cancelled", "timeout": "timed_out",
                     "output_limit": "output_limited", "storage_limit": "storage_limited", "capture_failed": "failed"}.get(runtime.reason, "completed")
            record.update(status=state, finished_at=time.time(), exit_code=exit_code,
                          termination_reason=runtime.reason or "exit", output_complete=complete,
                          publication_state="retained_spool" if artifact_errors else "published",
                          artifacts=artifacts, process_state="exited" if exit_code is not None else "unknown")
            if errors:
                record["warnings"] = errors
            if artifact_errors:
                record["artifact_errors"] = artifact_errors
            try:
                self._save(record)
            except Exception as exc:
                record.setdefault("warnings", []).append(f"job_metadata_save_failed: {exc}")
            self._running.pop(job_id, None)
            self._notify(record)

    def status(self, job_id: str, detail=True) -> dict:
        with self._lock:
            return self._public(self._record(job_id), detail=detail)

    def owns_live_process(self, job_id, pid):
        with self._lock:
            runtime = self._running.get(job_id)
            return bool(runtime is not None and type(pid) is int and runtime.process.pid == pid
                        and not self._leader_exited(runtime))

    def evidence(self, job_id: str) -> dict:
        with self._lock:
            record = self._record(job_id)
            return {**self._public(record, detail=False), 'artifacts': copy.deepcopy(record.get('artifacts', {}))}

    def wait_terminal(self, job_id, wait_ms):
        with self._changed:
            record = self._record(job_id)
            self._changed.wait_for(lambda: record["status"] in TERMINAL, timeout=wait_ms / 1000)

    def observe(self, job_id: str, stdout_offset=0, stderr_offset=0, wait_ms=1500,
                max_bytes=8192, after_sequence=None) -> dict:
        if type(wait_ms) is not int or not 0 <= wait_ms <= 10000:
            raise WorkbenchError("invalid_wait", "wait_ms must be 0..10000; wait expiry does not cancel the job.")
        if type(max_bytes) is not int or not 4096 <= max_bytes <= MAX_PAGE:
            raise WorkbenchError("invalid_range", "max_bytes must be 4096..262144 including response overhead.")
        if after_sequence is not None and (type(after_sequence) is not int or after_sequence < 0):
            raise WorkbenchError("invalid_sequence", "after_sequence must be nonnegative.")
        offsets = {"stdout": stdout_offset, "stderr": stderr_offset}
        with self._changed:
            record = self._record(job_id)
            for stream, offset in offsets.items():
                if type(offset) is not int or not 0 <= offset <= self._spool(job_id, stream).stat().st_size:
                    raise WorkbenchError("invalid_range", "Offset exceeds captured output or is negative.", stream=stream)
            sequence = record.get("sequence", 0) if after_sequence is None else after_sequence
            def progressed():
                return (record["status"] in TERMINAL or record.get("sequence", 0) != sequence or
                        any(record[f"{stream}_bytes"] > offset for stream, offset in offsets.items()))
            self._changed.wait_for(progressed, timeout=wait_ms / 1000)
            summary = self._public(record, detail=False)
        # Do not hold the process-control lock across spool I/O or encoding.
        captured = {stream: self.read(job_id, stream, offset, max_bytes // 2) for stream, offset in offsets.items()}
        raw = {stream: base64.b64decode(page["data"]) if page["encoding"] == "base64" else page["data"].encode()
               for stream, page in captured.items()}
        def view(raw_budget):
            result = {**summary, "terminal": summary["status"] in TERMINAL,
                      "observation_atomic": False, "wait_does_not_cancel": True,
                      "max_response_bytes": max_bytes}
            for stream, offset in offsets.items():
                page = dict(captured[stream])
                chunk = raw[stream][:raw_budget]
                try:
                    data, encoding = chunk.decode("utf-8"), "utf-8"
                except UnicodeDecodeError:
                    data, encoding = base64.b64encode(chunk).decode("ascii"), "base64"
                end = offset + len(chunk)
                page.update(data=data, encoding=encoding, bytes_returned=len(chunk), resume_offset=end,
                            next_offset=end if end < page["total_bytes"] else None, eof=end == page["total_bytes"])
                result[stream] = page
            return result
        # Compatibility JSON is inside TextContent. Measure that nested shape,
        # reserving 1 KiB for invocation identity/protocol fields added upstream.
        def size(result):
            text = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
            return len(json.dumps({"content": [{"type": "text", "text": text}], "isError": False},
                                  ensure_ascii=True, separators=(",", ":")).encode()) + 1024
        low, high = 0, max_bytes // 2
        result = view(0)
        if size(result) > max_bytes:
            raise WorkbenchError("response_budget", "Increase max_bytes to hold the required status and stream metadata.")
        while low <= high:
            middle = (low + high) // 2
            candidate = view(middle)
            if size(candidate) <= max_bytes:
                result, low = candidate, middle + 1
            else:
                high = middle - 1
        return result

    def list(self, offset: int = 0, limit: int = 50, *, detail=True, max_bytes=None,
             workspace=None, status=None, created_before=None, work_session_id=None, query_id=None) -> dict:
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise WorkbenchError("invalid_range", "offset must be nonnegative and limit must be 1..100.")
        if max_bytes is not None and (type(max_bytes) is not int or not 4096 <= max_bytes <= MAX_PAGE):
            raise WorkbenchError("invalid_range", "max_bytes must be 4096..262144.")
        if created_before is not None and (type(created_before) not in (int, float) or not math.isfinite(created_before)):
            raise WorkbenchError("invalid_range", "created_before must be a finite timestamp.")
        with self._lock:
            cutoff = time.time() if created_before is None else created_before
            directory = self.config.state_dir / 'job-queries'
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.is_symlink():
                raise WorkbenchError('unsafe_job_query', 'Job query storage may not be a symlink.')
            if query_id is None:
                records = sorted((r for r in self._records.values() if r['created_at'] <= cutoff
                                  and (workspace is None or r['workspace'] == workspace)
                                  and (work_session_id is None or r.get('work_session_id') == work_session_id)
                                  and (status is None or r['status'] == status)), key=lambda r: (r['created_at'], r['job_id']))
                if len(records) > 100000:
                    raise WorkbenchError('job_query_limit', 'Narrow queries exceeding 100000 jobs; membership was not truncated.')
                query_id = uuid.uuid4().hex
                membership = {'schema_version': 1, 'query_id': query_id, 'ids': [record['job_id'] for record in records],
                              'workspace': workspace, 'status': status, 'work_session_id': work_session_id,
                              'created_before': cutoff, 'created_at': time.time(), 'expires_at': time.time() + 1800}
                _atomic_json(directory / (query_id + '.json'), membership)
            else:
                if not isinstance(query_id, str) or not re.fullmatch(r'[0-9a-f]{32}', query_id):
                    raise WorkbenchError('invalid_job_query', 'Use a query ID returned by job_list.')
                path = directory / (query_id + '.json')
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 8388608:
                    raise WorkbenchError('unknown_job_query', 'This membership snapshot is unavailable.')
                try:
                    membership = json.loads(path.read_text())
                    if time.time() > membership['expires_at']:
                        raise WorkbenchError('job_query_expired', 'This membership snapshot expired; begin a new query.')
                    if membership['work_session_id'] != work_session_id:
                        raise WorkbenchError('work_session_mismatch', 'The query belongs to a different retrieval context.')
                    if workspace is not None and workspace != membership['workspace'] or status is not None and status != membership['status']:
                        raise WorkbenchError('job_query_conflict', 'A continuation cannot change the frozen membership filters.')
                    if created_before is not None and created_before != membership['created_before']:
                        raise WorkbenchError('job_query_conflict', 'Use the snapshot cutoff unchanged.')
                    records = [self._record(identifier) for identifier in membership['ids']]
                    cutoff = membership['created_before']
                except (ValueError, KeyError, TypeError) as error:
                    raise WorkbenchError('job_query_invalid', 'The saved query metadata is damaged; no membership was inferred.') from error
            result = {"ok": True, "jobs": [], "offset": offset, "total": len(records), "next_offset": None,
                      "running": len(self._running), "max_jobs": self.config.max_jobs, "created_before": cutoff,
                      "snapshot_atomic": False, 'query_id': query_id, 'membership_frozen': True,
                      'membership_created_at': membership['created_at'],
                      "note": "Reuse query_id and next_offset for exact membership; job statuses are observed when each page is read."}
            result['work_session_filter']=work_session_id
            for record in records[offset:offset + limit]:
                item = self._public(record, detail=detail)
                candidate = {**result, "jobs": result["jobs"] + [item]}
                encoded = json.dumps(candidate, ensure_ascii=True, separators=(",", ":"))
                wire_size = len(json.dumps({"content": [{"type": "text", "text": encoded}]}).encode()) + 1024
                if max_bytes is not None and wire_size > max_bytes:
                    if not result["jobs"]:
                        raise WorkbenchError("response_budget", "Use compact listing or inspect this job separately.", job_id=record["job_id"])
                    break
                result["jobs"].append(item)
            end = offset + len(result["jobs"])
            result["next_offset"] = end if end < len(records) else None
            return result

    def read(self, job_id: str, stream: str = "stdout", offset: int = 0, max_bytes: int = 16384) -> dict:
        if stream not in {"stdout", "stderr"}:
            raise WorkbenchError("invalid_stream", "stream must be stdout or stderr.")
        if type(offset) is not int or offset < 0 or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_PAGE:
            raise WorkbenchError("invalid_range", f"offset must be nonnegative; max_bytes must be 1..{MAX_PAGE}.")
        with self._lock:
            record = self._record(job_id)
            total = self._spool(job_id, stream).stat().st_size
            if offset > total:
                raise WorkbenchError("invalid_range", "offset exceeds the currently captured output.", total_bytes=total)
            terminal = record["status"] in TERMINAL
            artifact = record.get("artifacts", {}).get(stream)
            complete = record["output_complete"]
        with self._spool(job_id, stream).open("rb") as source:
            source.seek(offset)
            chunk = source.read(min(max_bytes, total - offset))
        try:
            text, encoding = chunk.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            text, encoding = base64.b64encode(chunk).decode("ascii"), "base64"
        result = dict(ok=True, job_id=job_id, stream=stream, encoding=encoding, data=text, offset=offset,
                      next_offset=offset + len(chunk) if offset + len(chunk) < total else None,
                      resume_offset=offset + len(chunk),
                      bytes_returned=len(chunk), total_bytes=total,
                      eof=offset + len(chunk) == total, terminal=terminal,
                      output_complete=complete, sha256=artifact["sha256"] if artifact else None)
        if artifact:
            result["artifact_id"] = artifact["artifact_id"]
        return result

    def input(self, job_id: str, request_id: str, text: str = "", eof: bool = False, encoding: str = "utf-8") -> dict:
        if not isinstance(text, str) or type(eof) is not bool:
            raise WorkbenchError("invalid_input", "text must be a string and eof must be a boolean.")
        try:
            if encoding == "utf-8":
                data = text.encode("utf-8")
            elif encoding == "base64":
                data = base64.b64decode(text, validate=True)
            else:
                raise WorkbenchError("invalid_input", "encoding must be utf-8 or base64.")
        except (UnicodeEncodeError, ValueError) as exc:
            raise WorkbenchError("invalid_input", "text is not valid for the chosen encoding.") from exc
        if len(data) > MAX_INPUT:
            raise WorkbenchError("input_too_large", f"Each input call accepts at most {MAX_INPUT} UTF-8 bytes.")
        payload = dict(operation="job_input", job_id=job_id, text=text, eof=eof, encoding=encoding)
        if work_context.get() is not None:payload['work_session_id']=work_context.get()

        def deliver():
            with self._lock:
                self._check_owner(self._record(job_id))
                runtime = self._running.get(job_id)
                if runtime is None or runtime.process.stdin is None or runtime.stdin_closed or self._leader_exited(runtime):
                    raise WorkbenchError("stdin_closed", "The job has no open stdin.")
            with runtime.input_lock:
                sent = 0
                deadline = time.monotonic() + 1
                def incomplete(code,message):
                    return {"ok":False,"job_id":job_id,"bytes_written":sent,"bytes_requested":len(data),
                            "eof_sent":False,"remaining_base64":base64.b64encode(data[sent:]).decode('ascii'),
                            "error":{"code":code,"message":message}}
                # Serialize one job's input, but never hold the manager lock
                # while waiting for pipe capacity. Other jobs stay controllable.
                while sent < len(data):
                    try:
                        with self._lock:
                            if runtime.stdin_closed or runtime.process.stdin.closed or self._running.get(job_id) is not runtime:
                                return incomplete('stdin_closed','Input closed while delivering bytes; inspect the exact retained delivery count.')
                            sent += os.write(runtime.process.stdin.fileno(), data[sent:])
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            return incomplete('stdin_backpressure','Retry this request ID to recover its receipt; send only the undelivered suffix with a new ID.')
                        time.sleep(0.01)
                    except (BrokenPipeError, OSError) as exc:
                        return incomplete('stdin_write_failed',str(exc))
                if eof:
                    with self._lock:
                        if runtime.stdin_closed:return incomplete('stdin_closed','Input closed before this EOF request was delivered.')
                        runtime.process.stdin.close()
                        runtime.stdin_closed = True
                        self._records[job_id]["stdin_open"] = False
                return {"ok": True, "job_id": job_id, "bytes_written": sent, "eof_sent": eof}

        return self.journal.run(request_id, payload, deliver)

    def cancel(self, job_id: str, request_id: str) -> dict:
        def stop():
            with self._lock:
                record = self._record(job_id)
                self._check_owner(record)
                runtime = self._running.get(job_id)
                requested = runtime is not None and runtime.signalable
                if requested:
                    self._stop(runtime, "cancelled")
                return {"ok": True, "job_id": job_id, "cancellation_requested": requested,
                        "status": record["status"], "termination_reason": runtime.reason if runtime else record.get("termination_reason")}
        payload=dict(operation='job_cancel',job_id=job_id)
        if work_context.get() is not None:payload['work_session_id']=work_context.get()
        return self.journal.run(request_id,payload,stop)

    def close(self) -> None:
        with self._lock:
            if self._owner.closed:
                return
            self._closed = True
            active = list(self._running.values())
            for runtime in active:
                self._stop(runtime, "shutdown")
        for runtime in active:
            if runtime.thread:
                runtime.thread.join(timeout=8)
        if any(runtime.thread and runtime.thread.is_alive() for runtime in active):
            # Keep ownership if a worker is still using the state directory.
            raise WorkbenchError("job_shutdown_incomplete", "A job monitor has not stopped; state-directory ownership is retained.")
        fcntl.flock(self._owner, fcntl.LOCK_UN)
        self._owner.close()
