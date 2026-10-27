from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .config import Config
from .errors import WorkbenchError, storage_failure
from .persistence import atomic_json

MAX_PAGE_BYTES = 256 * 1024


def prepare_state(path: Path) -> None:
    """Never chmod or adopt an unrelated directory supplied as state storage."""
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = path / ".local-workbench-state"
    if not marker.exists():
        if any(path.iterdir()):
            raise WorkbenchError("invalid_state", "State directory is not empty and is not a Local Workbench store.")
        try:
            with marker.open("x") as stream:
                stream.write("local-workbench-state-v1\n")
        except FileExistsError:
            pass
    if marker.read_text() != "local-workbench-state-v1\n":
        raise WorkbenchError("invalid_state", "Unrecognized state directory marker.")
    os.chmod(path, 0o700)


def validate_page(offset: int, max_bytes: int) -> None:
    if type(offset) is not int or offset < 0:
        raise WorkbenchError("invalid_range", "offset must be a nonnegative byte offset.")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_PAGE_BYTES:
        raise WorkbenchError("invalid_range", f"max_bytes must be between 1 and {MAX_PAGE_BYTES}.")


def encode_page(data: bytes, offset: int, total_bytes: int) -> dict:
    """Byte-exact pages: even split UTF-8 code points survive via base64."""
    try:
        content = data.decode("utf-8", errors="strict")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = base64.b64encode(data).decode("ascii")
        encoding = "base64"
    end = offset + len(data)
    return {
        "offset": offset,
        "bytes_returned": len(data),
        "total_bytes": total_bytes,
        "next_offset": end if end < total_bytes else None,
        "eof": end >= total_bytes,
        "encoding": encoding,
        "data": content,
    }


class ArtifactStore:
    def __init__(self, config: Config):
        self.config = config
        self.root = config.state_dir
        prepare_state(self.root)
        self.blobs = self.root / "artifacts"
        self.temporary = self.root / "temporary"
        self.uploads = self.root / "uploads"
        for path in (self.blobs, self.temporary, self.uploads):
            path.mkdir(mode=0o700, exist_ok=True)
        self._lock = threading.RLock()
        self.reservations = self.root / 'reservations'
        self.reader_locks = self.root / 'artifact-reader-locks'
        for directory in (self.reservations, self.reader_locks):
            directory.mkdir(mode=0o700, exist_ok=True)
        self._database = self.root / "artifacts.sqlite3"
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS artifacts (sha256 TEXT PRIMARY KEY, bytes INTEGER NOT NULL, source TEXT NOT NULL, created REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS artifact_captures (capture_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, source TEXT NOT NULL, created REAL NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS captures_by_artifact ON artifact_captures(sha256,created)")
            db.execute('CREATE TABLE IF NOT EXISTS artifact_retirements (sha256 TEXT PRIMARY KEY,request_id TEXT NOT NULL,retired REAL NOT NULL)')

    @contextlib.contextmanager
    def _db(self):
        with contextlib.closing(sqlite3.connect(self._database, timeout=30)) as db:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db

    @contextlib.contextmanager
    def locked(self):
        with self._lock, (self.root / "artifacts.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def storage_bytes(self) -> int:
        total = 0
        for directory, _, files in os.walk(self.root, followlinks=False):
            for filename in files:
                try:
                    info = os.stat(Path(directory) / filename, follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode):
                        total += info.st_size
                except FileNotFoundError:
                    pass
        return total

    def put_bytes(self, data: bytes, source: str = "") -> dict:
        return self.put_stream(io.BytesIO(data), source)

    def put_file(self, path: Path, source: str = "") -> dict:
        with Path(path).open("rb") as stream:
            return self.put_stream(stream, source)

    def _capture(self, sha, count, source):
        with self._db() as db:
            db.execute('INSERT OR IGNORE INTO artifacts VALUES (?, ?, ?, ?)', (sha, count, source, time.time()))
            capture_id = uuid.uuid4().hex
            db.execute('INSERT INTO artifact_captures VALUES (?,?,?,?)', (capture_id, sha, source, time.time()))
        return {'artifact_id': 'sha256:' + sha, 'sha256': sha, 'bytes': count, 'capture_id': capture_id}

    def _sync_blob_directory(self, sha):
        descriptor = None
        try:
            descriptor = os.open(self.blobs, os.O_RDONLY | os.O_DIRECTORY)
            os.fsync(descriptor)
        except OSError as error:
            raise WorkbenchError('storage_error', 'Artifact directory durability could not be confirmed; inspect the retained candidate before retrying.',
                                 candidate_artifact='sha256:' + sha, durability='unknown', artifact_phase='directory_fsync') from error
        finally:
            if descriptor is not None: os.close(descriptor)

    def _reader_fd(self, artifact_id):
        if not isinstance(artifact_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact_id):
            raise WorkbenchError('invalid_artifact', 'Expected an artifact_id returned by this server.')
        return os.open(self.reader_locks / artifact_id[7:], os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)

    @contextlib.contextmanager
    def reading(self, artifact_id):
        """A cross-process lease held until the immutable stream is closed."""
        lock = self._reader_fd(artifact_id)
        try:
            fcntl.flock(lock, fcntl.LOCK_SH)
            descriptor = os.open(self.path(artifact_id), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise WorkbenchError('artifact_corrupt', 'The artifact is not a regular file.')
                yield source
        finally:
            os.close(lock)

    def put_stream(self, stream, source: str = "") -> dict:
        expected = None
        if getattr(stream, 'seekable', lambda: False)():
            start, expected_count = stream.tell(), 0
            expected_digest = hashlib.sha256()
            while chunk := stream.read(1048576):
                expected_count += len(chunk)
                if expected_count > self.config.max_artifact_bytes:
                    raise WorkbenchError('artifact_limit', 'Complete snapshot exceeds the artifact limit; nothing was staged.', observed_bytes=expected_count)
                expected_digest.update(chunk)
            stream.seek(start)
            expected = expected_digest.hexdigest()
            with self.locked():
                if (self.blobs / expected).exists():
                    verified = self.verify('sha256:' + expected)
                    if not verified['verified'] or verified['bytes'] != expected_count:
                        raise WorkbenchError('artifact_corrupt', 'An existing duplicate did not verify; it was not reused.')
                    self._sync_blob_directory(expected)
                    return self._capture(expected, expected_count, source)
        digest = hashlib.sha256()
        count = 0
        descriptor, name = tempfile.mkstemp(dir=self.temporary, prefix="snapshot-")
        temp = Path(name)
        reservation = self.reservations / temp.name
        try:
            with os.fdopen(descriptor, "wb") as target:
                while data := stream.read(1024 * 1024):
                    count += len(data)
                    if count > self.config.max_artifact_bytes:
                        raise WorkbenchError("artifact_limit", "Snapshot rejected; no shortened artifact was published.", limit_bytes=self.config.max_artifact_bytes, observed_bytes=count)
                    with self.locked():
                        reservation_payload = {'schema_version': 1, 'staging_name': temp.name,
                            'reserved_bytes': len(data), 'observed_at': time.time(), 'state': 'writing_chunk'}
                        reservation_bytes = len(json.dumps(reservation_payload, separators=(',', ':')).encode())
                        if self.storage_bytes() + len(data) + reservation_bytes > self.config.max_storage_bytes:
                            raise WorkbenchError('storage_limit', 'Complete staging needs additional headroom; no shortened artifact was published.',
                                limit_bytes=self.config.max_storage_bytes, required_staging_bytes=expected_count if expected else count,
                                retained_staging_bytes=count - len(data))
                        atomic_json(reservation, reservation_payload)
                        target.write(data)
                        target.flush()
                        reservation.unlink()
                    digest.update(data)
                target.flush()
                os.fsync(target.fileno())
            sha = digest.hexdigest()
            if expected is not None and sha != expected:
                raise WorkbenchError('source_changed', 'The source changed between duplicate discovery and snapshot capture; no artifact was published.')
            destination = self.blobs / sha
            with self.locked():
                if destination.exists():
                    verified = self.verify('sha256:' + sha)
                    if not verified['verified'] or verified['bytes'] != count:
                        raise WorkbenchError("artifact_corrupt", "Stored content does not match its digest metadata.")
                    temp.unlink()
                else:
                    # Current temporary bytes are already counted, rename adds none.
                    if self.storage_bytes() > self.config.max_storage_bytes:
                        raise WorkbenchError("storage_limit", "Storage budget exhausted before committing the snapshot.")
                    os.replace(temp, destination)
                    os.chmod(destination, 0o400)
                self._sync_blob_directory(sha)
                result = self._capture(sha, count, source)
            return result

        except OSError as error:
            raise WorkbenchError("storage_error", "Could not persist complete artifact.", reason=str(error)) from error
        finally:
            reservation.unlink(missing_ok=True)
            temp.unlink(missing_ok=True)

    def path(self, artifact_id: str) -> Path:
        if not isinstance(artifact_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id):
            raise WorkbenchError("invalid_artifact", "Expected an artifact_id returned by this server.")
        path = self.blobs / artifact_id[7:]
        if not path.is_file() or path.is_symlink():
            with self._db() as db:
                retired = db.execute('SELECT request_id,retired FROM artifact_retirements WHERE sha256=?', (artifact_id[7:],)).fetchone()
            if retired and not path.exists():
                raise WorkbenchError('artifact_reclaimed', 'These bytes were deliberately reclaimed; capture history and the cleanup receipt remain.',
                                     cleanup_request_id=retired[0], retired_at=retired[1])
            raise WorkbenchError("unknown_artifact", "Artifact is not available in this state directory.")
        return path

    def read(self, artifact_id: str, offset: int = 0, max_bytes: int = 16384) -> dict:
        validate_page(offset, max_bytes)
        with self.reading(artifact_id) as stream:
            size = os.fstat(stream.fileno()).st_size
            if offset > size:
                raise WorkbenchError("invalid_range", "offset exceeds artifact size.", total_bytes=size)
            stream.seek(offset)
            data = stream.read(max_bytes)
        return {"ok": True, "artifact_id": artifact_id, "sha256": artifact_id[7:], **encode_page(data, offset, size)}

    def verify(self, artifact_id: str) -> dict:
        path = self.path(artifact_id)
        with self.reading(artifact_id) as source:
            before = os.fstat(source.fileno())
            actual = hashlib.file_digest(source, "sha256").hexdigest()
            after = os.fstat(source.fileno())
        stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        try:
            current = path.lstat()
            stable = stable and (current.st_dev, current.st_ino) == (after.st_dev, after.st_ino)
        except FileNotFoundError:
            stable = False
        return {"ok": True, "artifact_id": artifact_id, "expected_sha256": artifact_id[7:],
                "actual_sha256": actual, "bytes": after.st_size, "verified": stable and actual == artifact_id[7:],
                "source_stable": stable, "verified_at": time.time(), "scope": "bytes read from the host-controlled store"}

    def provenance(self, artifact_id, after=0, through=None, limit=20, max_bytes=8192):
        from .views import response_size
        try:
            self.path(artifact_id)
            content_state = 'available'
        except WorkbenchError as error:
            if error.code != 'artifact_reclaimed':
                raise
            content_state = 'reclaimed'
        if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=100 or type(max_bytes) is not int or not 4096<=max_bytes<=262144:
            raise WorkbenchError('invalid_range','Use a nonnegative cursor, limit 1..100 and max_bytes 4096..262144.')
        with self._db() as db:
            high=db.execute('SELECT COALESCE(MAX(rowid),0) FROM artifact_captures').fetchone()[0]
            if through is None:through=high
            if type(through) is not int or not 0<=through<=high or after>through:
                raise WorkbenchError('invalid_cursor','Capture cursor is outside the current catalog.')
            rows=db.execute('SELECT rowid,capture_id,source,created FROM artifact_captures WHERE sha256=? AND rowid>? AND rowid<=? ORDER BY rowid LIMIT ?',
                            (artifact_id[7:],after,through,limit+1)).fetchall()
        result={'ok':True,'artifact_id':artifact_id,'content_state':content_state,'captures':[],'through':through,'next_after':None,
                'scope':'capture events recorded since core 0.3; equal content does not imply common origin or ownership'}
        for row in rows[:limit]:
            item=dict(zip(['sequence','capture_id','source','created_at'],row))
            candidate={**result,'captures':result['captures']+[item],'next_after':row[0]}
            if response_size(candidate)>max_bytes:
                if not result['captures']:
                    raise WorkbenchError('response_budget','Increase max_bytes for this capture record.',capture_id=row[1])
                break
            result['captures'].append(item)
        if len(rows)>len(result['captures']):result['next_after']=result['captures'][-1]['sequence']
        return result

    def upload(self, journal, request_id: str, upload_id: str | None = None, offset: int = 0,
               content: str | None = None, data_base64: str | None = None,
               finalize: bool = False, expected_sha256: str | None = None) -> dict:
        journal.validate_id(request_id)
        if not any(w.writable for w in self.config.workspaces.values()):
            raise WorkbenchError("read_only", "Artifact uploads require an enabled writable workspace.")
        if (content is None) == (data_base64 is None):
            raise WorkbenchError("invalid_input", "Supply exactly one of content or data_base64 (empty content is allowed).")
        try:
            chunk = content.encode("utf-8") if content is not None else base64.b64decode(data_base64, validate=True)
        except (ValueError, UnicodeError) as error:
            raise WorkbenchError("invalid_input", "Chunk must be valid UTF-8 text or base64.") from error
        validate_page(offset, max(1, len(chunk)))
        payload = {"tool": "artifact_upload", "upload_id": upload_id, "offset": offset,
                   "chunk_sha256": hashlib.sha256(chunk).hexdigest(), "finalize": finalize, "expected_sha256": expected_sha256}

        # A request's allocation can be recovered even if the process dies before
        # returning it. This is an identifier, not an authorization credential.
        identifier = upload_id or hashlib.sha256(("upload:" + request_id).encode()).hexdigest()[:32]

        def perform():
            if not re.fullmatch(r"[0-9a-f]{32}", identifier):
                raise WorkbenchError("invalid_upload", "Expected an upload_id returned by this server.")
            path = self.uploads / identifier
            if (self.uploads / (identifier + '.abandoned')).exists():
                raise WorkbenchError('upload_abandoned', 'This staging upload was deliberately abandoned; allocate a new upload ID.')
            if upload_id is not None and not path.exists():
                raise WorkbenchError("unknown_upload", "No upload exists with that ID.")
            if (self.uploads / (identifier + ".complete")).exists():
                raise WorkbenchError("upload_finalized", "This upload has already been finalized.")
            current_size = path.stat().st_size if path.exists() else 0
            if offset != current_size:
                raise WorkbenchError("offset_conflict", "Upload offset does not match retained bytes.", expected_offset=current_size)
            if current_size + len(chunk) > self.config.max_artifact_bytes:
                raise WorkbenchError("artifact_limit", "Upload exceeds the artifact limit.")
            if self.storage_bytes() + len(chunk) > self.config.max_storage_bytes:
                raise WorkbenchError("storage_limit", "Insufficient storage for this complete chunk.")
            phase, durable, artifact = "append", False, {}
            journal.checkpoint(request_id, {"phase": "allocated", "upload_id": identifier,
                                           "next_offset": current_size, "effect_state": "none"})
            try:
                # Different uploads may now execute concurrently. Keep their
                # capacity check and bounded append coordinated with commits.
                with self.locked():
                    if self.storage_bytes() + len(chunk) > self.config.max_storage_bytes:
                        raise WorkbenchError("storage_limit", "Insufficient storage for this complete chunk.")
                    with path.open("ab") as target:
                        target.write(chunk)
                        target.flush()
                        phase = "upload_fsync"
                        os.fsync(target.fileno())
                    phase = "upload_directory_fsync"
                    directory_fd = os.open(self.uploads, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                durable = True
                result = {"ok": True, "upload_id": identifier, "bytes": current_size + len(chunk),
                          "next_offset": current_size + len(chunk), "finalized": False,
                          "effect_state": "staged", "durability": "confirmed", "applied_this_call": bool(chunk)}
                journal.checkpoint(request_id, result)
                if finalize:
                    phase = "verify_hash"
                    with path.open("rb") as stream:
                        actual = hashlib.file_digest(stream, "sha256").hexdigest()
                    if expected_sha256 is None or actual != expected_sha256:
                        raise WorkbenchError("hash_mismatch", "Finalization needs the complete expected SHA-256. Retained bytes can be finalized with an empty chunk.", actual_sha256=actual)
                    phase = "publish_artifact"
                    artifact = self.put_file(path, "upload:" + identifier)
                    journal.checkpoint(request_id, {**result, **artifact, "phase": "artifact_published"})
                    phase = "publish_upload_receipt"
                    atomic_json(self.uploads / (identifier + ".complete"), artifact)
                    result.update(artifact, finalized=True, effect_state="published", applied_this_call=True)
                return result
            except (WorkbenchError, OSError) as exc:
                details = dict(exc.details) if isinstance(exc, WorkbenchError) else {}
                details.update(upload_id=identifier, next_offset=path.stat().st_size if path.exists() else 0,
                               phase=phase, durability="unknown" if phase.startswith("publish_") or not durable else "confirmed",
                               upload_durability="confirmed" if durable else "unknown",
                               artifact_publication="published" if artifact else "unknown" if phase == "publish_artifact" else "not_started",
                               effect_state="artifact_published" if artifact else "staged" if path.exists() else "none",
                               recovery="inspect upload status; do not resend retained bytes", **artifact)
                raise WorkbenchError(getattr(exc, "code", "upload_error"),
                                     exc.message if isinstance(exc, WorkbenchError) else "Upload persistence failed.",
                                     **details) from exc

        return journal.run(request_id, payload, perform, resource="upload:" + identifier)

    def upload_status(self, upload_id: str) -> dict:
        if not isinstance(upload_id, str) or not re.fullmatch(r"[0-9a-f]{32}", upload_id):
            raise WorkbenchError("invalid_upload", "Expected an upload_id returned by this server.")
        abandoned = self.uploads / (upload_id + '.abandoned')
        if abandoned.exists():
            if abandoned.is_symlink() or abandoned.stat().st_size > 16384:
                raise WorkbenchError('upload_state_invalid', 'Upload abandonment metadata is invalid.')
            value = json.loads(abandoned.read_text())
            return {'ok': True, **value, 'abandoned': True, 'retained_staging_bytes': 0,
                    'observation': 'Historical accepted bytes are recorded; staging was explicitly reclaimed.'}
        path = self.uploads / upload_id
        if not path.is_file() or path.is_symlink():
            raise WorkbenchError("unknown_upload", "No retained upload exists with that ID.")
        marker = self.uploads / (upload_id + ".complete")
        result = {"ok": True, "upload_id": upload_id, "next_offset": path.stat().st_size,
                  "finalized": marker.is_file(), "observation": "retained bytes now; consult operation receipt for durability"}
        if marker.is_file():
            try:
                artifact = json.loads(marker.read_text())
                self.path(artifact["artifact_id"])
                result.update(artifact)
            except (ValueError, KeyError, WorkbenchError) as exc:
                raise WorkbenchError("upload_state_invalid", "Upload receipt or artifact is damaged; retain the staging bytes.",
                                     upload_id=upload_id, next_offset=result["next_offset"]) from exc
        return result


class Journal:
    def __init__(self, state_dir: Path):
        self.root = Path(state_dir)
        prepare_state(self.root)
        self.path = self.root / "operations.sqlite3"
        self._lock = threading.RLock()
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (request_id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL, state TEXT NOT NULL, result TEXT, started REAL NOT NULL, finished REAL)")

    @contextlib.contextmanager
    def _db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=30)) as db:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db

    @staticmethod
    def validate_id(request_id):
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", request_id):
            raise WorkbenchError("invalid_request_id", "Use a unique 1–128 character request_id (letters, numbers, dot, dash, colon, underscore).")

    def status(self, request_id: str) -> dict:
        self.validate_id(request_id)
        with self._db() as db:
            row = db.execute("SELECT state,result,started,finished FROM operations WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return {"ok": True, "request_id": request_id, "state": "not_found"}
        return {"ok": True, "request_id": request_id, "state": row[0], "result": json.loads(row[1]) if row[1] else None, "started": row[2], "finished": row[3], "note": "pending means in progress or interrupted; do not repeat the side effect with a new ID until inspected" if row[0] == "pending" else None}

    @contextlib.contextmanager
    def _key_lock(self, namespace, key):
        directory = self.root / "operation-locks"
        directory.mkdir(mode=0o700, exist_ok=True)
        name = hashlib.sha256((namespace + ":" + key).encode()).hexdigest()
        fd = os.open(directory / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)
        # Never unlink lock files: existing waiters must share the same inode.

    def checkpoint(self, request_id, result):
        """Record recovery locators before effects; a checkpoint is not success."""
        with self._db() as db:
            changed = db.execute("UPDATE operations SET result=? WHERE request_id=? AND state='pending'",
                                 (json.dumps(result, ensure_ascii=True), request_id)).rowcount
            if changed != 1:
                raise WorkbenchError("operation_uncertain", "Cannot save a recovery checkpoint for this request.", request_id=request_id)

    def _finalize(self, request_id, state, result):
        with self._db() as db:
            db.execute("UPDATE operations SET state=?,result=?,finished=? WHERE request_id=?",
                       (state, json.dumps(result, ensure_ascii=True), time.time(), request_id))

    def recover(self, request_id, payload):
        """Read an identity-checked receipt without waiting on an effect's lock."""
        self.validate_id(request_id)
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        with self._db() as db:
            row = db.execute("SELECT payload_hash,state,result FROM operations WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return None
        if row[0] != payload_hash:
            raise WorkbenchError('request_conflict', 'This request_id was already used with different arguments.')
        return {'state': row[1], 'result': json.loads(row[2]) if row[2] else None}

    def run(self, request_id: str, payload: dict, fn, *, resource: str | None = None,
            initial_checkpoint: dict | None = None, on_reserved=None, preserve_uncertain=False) -> dict:
        self.validate_id(request_id)
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        with self._key_lock("request", request_id):
            # Only reservation uses the old global journal lock. Resource I/O
            # never owns it; unrelated cancellation can reserve/finalize freely.
            with self._lock, (self.root / "operations.lock").open("a+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with self._db() as db:
                    row = db.execute("SELECT payload_hash,state,result FROM operations WHERE request_id=?", (request_id,)).fetchone()
                    if row:
                        if row[0] != payload_hash:
                            raise WorkbenchError("request_conflict", "This request_id was already used with different arguments.")
                        if row[1] == "pending":
                            raise WorkbenchError("operation_uncertain", "A previous attempt may have changed state. Inspect operation_status and the target before deciding the next action.", request_id=request_id)
                        result = json.loads(row[2])
                        if row[1] == "failed":
                            error = result["error"]
                            details = {k: v for k, v in error.items() if k not in ("code", "message")}
                            details.update(replayed=True, applied_this_call=False, original_request_id=request_id)
                            raise WorkbenchError(error["code"], error["message"], **details)
                        replay = {**result, "replayed": True}
                        if "applied_this_call" in replay:
                            replay["applied_this_call"] = False
                        return replay
                    db.execute("INSERT INTO operations VALUES (?, ?, 'pending', ?, ?, NULL)",
                               (request_id, payload_hash, json.dumps(initial_checkpoint, ensure_ascii=True) if initial_checkpoint is not None else None, time.time()))
            try:
                if on_reserved is not None:
                    on_reserved()
                with self._key_lock("resource", resource) if resource else contextlib.nullcontext():
                    result = fn()
            except WorkbenchError as error:
                preserve = preserve_uncertain(error) if callable(preserve_uncertain) else preserve_uncertain
                if preserve and error.details.get('effect_state') != 'none':
                    checkpoint = self.status(request_id).get('result') or {}
                    self.checkpoint(request_id, {**checkpoint, 'phase': 'native_response_uncertain',
                                                 'transport_outcome': error.as_dict()})
                    raise
                try:
                    self._finalize(request_id, "failed", error.as_dict())
                except Exception as commit_error:
                    raise WorkbenchError("operation_uncertain", "Error receipt could not be persisted; inspect the retained checkpoint and target.",
                                         request_id=request_id, outcome=error.as_dict()) from commit_error
                raise
            except Exception as error:
                allocation = storage_failure(error)
                if allocation is not None:
                    details = allocation['error']
                    raise WorkbenchError(details['code'], details['message'],
                        **{key: value for key, value in details.items() if key not in ('code', 'message')},
                        request_id=request_id, operation_state='pending') from error
                raise WorkbenchError("operation_uncertain", "Unexpected failure after reserving an operation; inspect its target before retrying.", request_id=request_id, reason=str(error)) from error
            try:
                self._finalize(request_id, "completed", result)
            except Exception as error:
                raise WorkbenchError("operation_uncertain", "Effects may have completed but the receipt was not committed; reconcile before retrying.",
                                     request_id=request_id, phase="receipt_commit", outcome=result) from error
            return {**result, "replayed": False}
