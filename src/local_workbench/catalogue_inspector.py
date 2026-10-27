"""Offline-capable catalogue checks which never open source SQLite in write mode."""
import contextlib
import hashlib
import fcntl
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
from pathlib import Path

from .diagnostics import inspect_state, read_job_record
from .errors import WorkbenchError
from .persistence import atomic_json, rename_exclusive


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


class RecoveryBudget:
    def __init__(self, max_bytes, max_members, timeout_ms):
        if (type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024**3
                or type(max_members) is not int or not 1 <= max_members <= 100000
                or type(timeout_ms) is not int or not 1 <= timeout_ms <= 3600000):
            raise WorkbenchError('invalid_recovery_limits', 'Use max_bytes 1..64 GiB, max_members 1..100000 and timeout_ms 1..3600000.')
        self.max_bytes, self.max_members = max_bytes, max_members
        self.deadline = time.monotonic() + timeout_ms / 1000

    def check(self):
        if time.monotonic() >= self.deadline:
            raise WorkbenchError('recovery_limit', 'Recovery exceeded its selected time budget; no generation was accepted.')


def _walk_recovery_source(root, budget):
    """Stream a bounded descriptor-relative tree; never follow a source symlink."""
    count, total = 0, 0

    def walk(fd, relative, depth):
        nonlocal count, total
        budget.check()
        if depth > 64:
            raise WorkbenchError('recovery_limit', 'Recovery source exceeds its directory-depth limit.')
        info_at_start = os.fstat(fd)
        yield relative, 'directory', info_at_start, fd, None
        with os.scandir(fd) as entries:
            for entry in entries:
                budget.check()
                count += 1
                if count > budget.max_members:
                    raise WorkbenchError('recovery_limit', 'Recovery source exceeds its selected entry limit.')
                info = entry.stat(follow_symlinks=False)
                child = relative / entry.name
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if _stamp(os.fstat(child_fd)) != _stamp(info):
                            raise WorkbenchError('recovery_source_changed', 'A source directory changed during inspection.')
                        yield from walk(child_fd, child, depth + 1)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    if total > budget.max_bytes:
                        raise WorkbenchError('recovery_limit', 'Recovery source exceeds its selected byte limit.')
                    yield child, 'file', info, fd, entry.name
                else:
                    code = 'recovery_symlink' if stat.S_ISLNK(info.st_mode) else 'recovery_special_file'
                    raise WorkbenchError(code, 'State recovery refuses symlinks and nonregular files.')
        if _stamp(os.fstat(fd)) != _stamp(info_at_start):
            raise WorkbenchError('recovery_source_changed', 'A source directory changed during its traversal.')

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield from walk(fd, Path('.'), 0)
    finally:
        os.close(fd)


def _stream_verified(source_fd, expected, budget, output=None):
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or _stamp(before) != expected:
        raise WorkbenchError('recovery_source_changed', 'A recovery member changed before it was read.')
    digest, copied = hashlib.sha256(), 0
    while True:
        budget.check()
        chunk = os.read(source_fd, 1048576)
        if not chunk:
            break
        copied += len(chunk)
        if copied > before.st_size:
            raise WorkbenchError('recovery_source_changed', 'A recovery member grew during its read.')
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    if copied != before.st_size or _stamp(os.fstat(source_fd)) != expected:
        raise WorkbenchError('recovery_source_changed', 'A recovery member changed during its read.')
    return digest.hexdigest()


def copy_database_snapshot(database, destination, max_bytes=268435456, deadline=None):
    stamps, components, total = {}, [], 0
    for suffix in ('', '-wal'):
        path = Path(str(database) + suffix)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if suffix:
                continue
            raise
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('Database component is not regular')
            total += before.st_size
            if total > max_bytes:
                raise ValueError('Database snapshot exceeds 256 MiB')
            digest = hashlib.sha256()
            target = Path(str(destination) + suffix)
            with target.open('xb') as output:
                os.chmod(target, 0o600)
                copied = 0
                while chunk := source.read(1048576):
                    if deadline is not None and time.monotonic() >= deadline:
                        raise ValueError('Database snapshot exceeded its inspection deadline')
                    copied += len(chunk)
                    if copied > before.st_size:
                        raise ValueError('Database component grew during capture')
                    digest.update(chunk)
                    output.write(chunk)
            after = os.fstat(source.fileno())
        stamp = lambda value: [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
        if stamp(before) != stamp(after):
            raise ValueError('Database component changed during capture')
        stamps[path] = stamp(after)
        components.append({'component': 'database' if not suffix else 'wal', 'bytes': copied, 'sha256': digest.hexdigest()})
    for path, expected in stamps.items():
        current = path.lstat()
        observed = [current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns]
        if observed != expected:
            raise ValueError('Database snapshot bracket changed')
    if Path(str(database) + '-wal') not in stamps and Path(str(database) + '-wal').exists():
        raise ValueError('WAL appeared during capture')
    return components


def inspect_catalogues(state_dir, verify_blobs=False, offset=0, limit=20):
    if type(verify_blobs) is not bool or type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise WorkbenchError('invalid_range', 'Use verify_blobs boolean, nonnegative offset and limit 1..100.')
    root = Path(state_dir)
    baseline = inspect_state(root)
    if baseline['state'] in ('unrecognized', 'unavailable'):
        return {**baseline, 'catalogues': [], 'source_files_modified': False}
    catalogues, errors, expected_blobs, retired, checked = [], [], {}, set(), 0
    metadata_complete = False
    deadline = time.monotonic() + 10
    complete = baseline.get('inspection_complete', True)
    with tempfile.TemporaryDirectory(prefix='workbench-catalogue-check-') as temporary:
        for index, path in enumerate(sorted(root.glob('*.sqlite3'))):
            if index >= 100 or time.monotonic() >= deadline:
                complete = False
                break
            item = {'name': path.name, 'state': 'unavailable'}
            try:
                copied = Path(temporary) / (str(index) + '.sqlite3')
                components = copy_database_snapshot(path, copied, deadline=deadline)
                with contextlib.closing(sqlite3.connect(copied.as_uri() + '?mode=ro', uri=True, timeout=1)) as connection:
                    connection.enable_load_extension(False)
                    connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                    rows = connection.execute('PRAGMA quick_check').fetchmany(21)
                    healthy = rows == [('ok',)]
                    item.update(state='healthy' if healthy else 'damaged', components=components,
                        quick_check_errors=[row[0] for row in rows[:20] if row[0] != 'ok'])
                    if path.name == 'artifacts.sqlite3' and healthy:
                        rows = connection.execute('SELECT sha256,bytes FROM artifacts LIMIT 100001').fetchall()
                        metadata_complete = len(rows) <= 100000
                        if len(rows) > 100000:
                            complete = False
                        expected_blobs = dict(rows[:100000])
                        table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifact_retirements'").fetchone()
                        if table:
                            retired_rows = connection.execute('SELECT sha256 FROM artifact_retirements LIMIT 100001').fetchall()
                            retired = {row[0] for row in retired_rows[:100000]}
                            if len(retired_rows) > 100000:
                                complete = False
            except (OSError, ValueError, sqlite3.Error) as error:
                if time.monotonic() >= deadline:
                    complete = False
                    item.update(state='unverified', error_type=type(error).__name__, reason='inspection_deadline')
                else:
                    item.update(state='damaged', error_type=type(error).__name__)
            catalogues.append(item)
        if not metadata_complete:
            complete = False
        artifacts = root / 'artifacts'
        if artifacts.is_symlink():
            errors.append({'code': 'artifact_directory_symlink'})
            complete = False
        elif artifacts.is_dir():
            paths = sorted(artifacts.iterdir())
            existing = set()
            for index, path in enumerate(paths):
                if index >= 100000 or time.monotonic() >= deadline:
                    complete = False
                    break
                if not re.fullmatch(r'[0-9a-f]{64}', path.name):
                    errors.append({'code': 'unrecognized_blob_name', 'entry': path.name[:100]})
                    continue
                existing.add(path.name)
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError('Blob is not regular')
                    if path.name not in expected_blobs and metadata_complete:
                        errors.append({'code': 'orphan_blob', 'artifact_id': 'sha256:' + path.name})
                    elif path.name in expected_blobs and info.st_size != expected_blobs[path.name]:
                        errors.append({'code': 'blob_size_mismatch', 'artifact_id': 'sha256:' + path.name})
                    if verify_blobs:
                        if info.st_size > 536870912:
                            raise ValueError('Blob exceeds verification bound')
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, 'rb') as source:
                            before = os.fstat(source.fileno())
                            if _stamp(before) != _stamp(info):
                                raise ValueError('Blob changed before verification')
                            hashed, observed_bytes = hashlib.sha256(), 0
                            while chunk := source.read(1048576):
                                if time.monotonic() >= deadline:
                                    raise TimeoutError('Blob inspection deadline')
                                observed_bytes += len(chunk)
                                if observed_bytes > info.st_size:
                                    raise ValueError('Blob grew during verification')
                                hashed.update(chunk)
                            if observed_bytes != info.st_size or _stamp(os.fstat(source.fileno())) != _stamp(before):
                                raise ValueError('Blob changed during verification')
                            digest = hashed.hexdigest()
                        checked += 1
                        if digest != path.name:
                            errors.append({'code': 'blob_integrity_mismatch', 'artifact_id': 'sha256:' + path.name})
                except (OSError, ValueError) as error:
                    if isinstance(error, TimeoutError):
                        complete = False
                        errors.append({'code': 'blob_unverified', 'reason': 'inspection_deadline', 'artifact_id': 'sha256:' + path.name})
                    else:
                        errors.append({'code': 'blob_unavailable', 'artifact_id': 'sha256:' + path.name})
            if complete:
                errors.extend({'code': 'missing_blob', 'artifact_id': 'sha256:' + sha} for sha in sorted(set(expected_blobs) - existing - retired))
    damaged = (any(item['state'] in ('damaged', 'unavailable') for item in catalogues)
               or any(item['code'] != 'blob_unverified' for item in errors) or baseline['state'] == 'degraded')
    return {'ok': True, 'state': 'degraded' if damaged else 'healthy' if complete else 'unverified',
            'catalogues': catalogues, 'jobs': baseline, 'errors': errors[offset:offset + limit],
            'error_count': len(errors), 'next_offset': offset + limit if offset + limit < len(errors) else None,
            'inspection_complete': complete, 'blob_integrity_verified_count': checked, 'verify_blobs_requested': verify_blobs,
            'source_files_modified': False, 'repair_performed': False,
            'consistency': 'Captured DB/WAL copies and live filesystem metadata; no cross-catalogue atomic snapshot is claimed.',
            'process_ownership': 'Never inferred from saved PIDs; no process signals.'}


def build_job_recovery_generation(state_dir, destination, max_bytes=1073741824, max_members=100000, timeout_ms=120000):
    source = Path(state_dir)
    budget = RecoveryBudget(max_bytes, max_members, timeout_ms)
    lock = None
    try:
        if (source / 'server.lock').exists():
            lock = os.open(source / 'server.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise WorkbenchError('recovery_special_file', 'The existing server lock is not a regular file.')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise WorkbenchError('recovery_not_idle', 'The active server owns this state. Drain and stop it before building a recovery generation.') from error
        return _build_job_recovery_generation(source, destination, budget, lock is not None)
    finally:
        if lock is not None:
            os.close(lock)


def _build_job_recovery_generation(state_dir, destination, budget, server_lock_held):
    """Preserve source; quarantine damaged copied job records rather than invent data."""
    source, target = Path(state_dir), Path(destination)
    selected = {str(relative): (kind, _stamp(info)) for relative, kind, info, _, _ in _walk_recovery_source(source, budget)}
    budget.check()
    report = inspect_catalogues(source)
    budget.check()
    if report['state'] in ('unrecognized', 'unavailable'):
        raise WorkbenchError('unrecognized_state', 'Recovery requires a recognized Workbench state.')
    if any(item['state'] != 'healthy' for item in report['catalogues']):
        raise WorkbenchError('offline_catalogue_recovery', 'A damaged SQLite catalogue requires explicit offline recovery; no replacement journal was invented.')
    if not report['inspection_complete']:
        raise WorkbenchError('recovery_unverified', 'Catalogue inspection was incomplete; recovery requires verified source catalogues.')
    if target.exists() or target.is_symlink() or target.resolve().is_relative_to(source.resolve()):
        raise WorkbenchError('recovery_destination', 'Choose an absent destination outside the source state.')
    reserved = {'recovery-generation.json', 'recovery-generation-failed.json'}
    if any(name in selected for name in reserved):
        raise WorkbenchError('recovery_destination', 'This source is already a recovery generation. Inspect its original manifest before requesting another recovery.')
    for path in (source / 'jobs').glob('*.json'):
        budget.check()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as metadata:
                info = os.fstat(metadata.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
                    raise ValueError('Invalid job metadata')
                record = json.loads(metadata.read(8 * 1024 * 1024 + 1))
            if isinstance(record, dict) and record.get('status') in ('starting', 'queued', 'running', 'finalizing'):
                raise WorkbenchError('recovery_not_idle', 'Job metadata is nonterminal; establish an idle/offline source before recovery.')
        except (ValueError, OSError, TypeError, RecursionError):
            pass
    target.mkdir(mode=0o700)
    manifest = {'schema_version': 1, 'source_preserved': True, 'activated': False, 'members': [], 'quarantined_jobs': [], 'created_at': time.time(),
                'limits': {'max_bytes': budget.max_bytes, 'max_members': budget.max_members, 'max_depth': 64},
                'server_lock_held': server_lock_held,
                'consistency': 'Source member identities and bytes were bracketed and rechecked; no atomic snapshot against arbitrary external writers is claimed.'}
    try:
        copied_members = {}
        seen = set()
        for relative, kind, info, directory_fd, name in _walk_recovery_source(source, budget):
            key = str(relative)
            if selected.get(key) != (kind, _stamp(info)):
                raise WorkbenchError('recovery_source_changed', 'The source tree changed after selection.')
            seen.add(key)
            if kind == 'directory':
                if key != '.':
                    (target / relative).mkdir(mode=0o700)
                continue
            source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                output_fd = os.open(target / relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(output_fd, 'wb') as output:
                    digest = _stream_verified(source_fd, selected[key][1], budget, output)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                os.close(source_fd)
            copied_members[key] = digest
            manifest['members'].append({'path': key, 'sha256': digest, 'bytes': info.st_size})
        if seen != set(selected):
            raise WorkbenchError('recovery_source_changed', 'A selected source entry disappeared during copying.')
        verified = set()
        for relative, kind, info, directory_fd, name in _walk_recovery_source(source, budget):
            key = str(relative)
            if selected.get(key) != (kind, _stamp(info)):
                raise WorkbenchError('recovery_source_changed', 'The source tree changed during copying.')
            verified.add(key)
            if kind == 'file':
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                try:
                    if _stream_verified(fd, selected[key][1], budget) != copied_members[key]:
                        raise WorkbenchError('recovery_source_changed', 'A source member no longer matches its preserved copy.')
                finally:
                    os.close(fd)
        if verified != set(selected):
            raise WorkbenchError('recovery_source_changed', 'The source membership changed during final verification.')
        quarantine = target / 'quarantined-jobs'
        for path in list((target / 'jobs').glob('*.json')):
            try:
                read_job_record(path)
            except (OSError, ValueError, TypeError):
                quarantine.mkdir(mode=0o700, exist_ok=True)
                with contextlib.ExitStack() as directories:
                    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    source_fd = os.open(path.parent, flags)
                    directories.callback(os.close, source_fd)
                    quarantine_fd = os.open(quarantine, flags)
                    directories.callback(os.close, quarantine_fd)
                    for suffix in ('.json', '.stdout', '.stderr'):
                        candidate = path.with_suffix(suffix)
                        if candidate.exists():
                            try:
                                rename_exclusive(source_fd, candidate.name, quarantine_fd, candidate.name)
                            except FileExistsError as error:
                                raise WorkbenchError('recovery_quarantine_conflict',
                                    'Quarantine already contains this name. Both copied records were preserved; inspect the rejected generation.') from error
                            original = str(candidate.relative_to(target))
                            for item in manifest['members']:
                                if item['path'] == original:
                                    item['preserved_original_path'] = original
                                    item['path'] = 'quarantined-jobs/' + candidate.name
                manifest['quarantined_jobs'].append(path.stem)
        for item in manifest['members']:
            member = target / item['path']
            fd = os.open(member, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if info.st_size != item['bytes'] or _stream_verified(fd, _stamp(info), budget) != item['sha256']:
                    raise WorkbenchError('recovery_integrity', 'A copied generation member failed final verification.')
            finally:
                os.close(fd)
        for directory, _, _ in os.walk(target, topdown=False, followlinks=False):
            budget.check()
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        atomic_json(target / 'recovery-generation.json', manifest)
    except BaseException as error:
        # Retain the failed generation for inspection; never alter or erase the source.
        with contextlib.suppress(OSError):
            atomic_json(target / 'recovery-generation-failed.json', {'source_preserved': True, 'accepted': False,
                        'error_code': getattr(error, 'code', type(error).__name__)})
        if isinstance(error, (OSError, WorkbenchError)):
            raise WorkbenchError(getattr(error, 'code', 'recovery_failed'),
                f'Recovery generation was not accepted. The source is preserved; inspect {target}.',
                generation_path=str(target), source_preserved=True, accepted=False, effect_state='partial') from error
        raise
    return {'ok': True, 'generation_path': str(target), 'source_preserved': True, 'activated': False,
            'quarantined_jobs': manifest['quarantined_jobs'], 'manifest_sha256': hashlib.sha256((target / 'recovery-generation.json').read_bytes()).hexdigest(),
            'server_lock_held': server_lock_held, 'consistency': manifest['consistency'],
            'scope': 'Copied job recovery generation; original catalogues/receipts remain byte-preserved. Activation is a separate reviewed operation.'}


def read_job_evidence(state_dir, job_id, stream='stdout', offset=0, max_bytes=16384):
    from .store import encode_page, validate_page
    if not isinstance(job_id, str) or not re.fullmatch(r'[0-9a-f]{32}', job_id) or stream not in ('stdout', 'stderr'):
        raise WorkbenchError('invalid_job', 'Use an existing job ID and stdout/stderr.')
    validate_page(offset, max_bytes)
    root = Path(state_dir)
    marker = root / '.local-workbench-state'
    if marker.is_symlink() or not marker.is_file() or marker.read_text() != 'local-workbench-state-v1\n':
        raise WorkbenchError('unrecognized_state', 'The source is not a recognized Workbench store.')
    directory = root / 'jobs'
    if directory.is_symlink():
        raise WorkbenchError('unsafe_job_state', 'Job evidence storage may not be a symlink.')
    try:
        record = read_job_record(directory / (job_id + '.json'))
        fd = os.open(directory / (job_id + '.' + stream), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if offset > before.st_size:
                raise WorkbenchError('invalid_range', 'The byte cursor exceeds the retained spool.')
            source.seek(offset)
            raw = source.read(max_bytes)
            after = os.fstat(source.fileno())
    except (OSError, ValueError) as error:
        raise WorkbenchError('job_evidence_unavailable', 'This record/spool is damaged; other healthy records remain inspectable.') from error
    return {'ok': True, 'job_id': job_id, 'stream': stream, 'status': record['status'],
            **encode_page(raw, offset, before.st_size), 'source_files_modified': False,
            'source_stable_during_read': [before.st_size, before.st_mtime_ns, before.st_ctime_ns] == [after.st_size, after.st_mtime_ns, after.st_ctime_ns],
            'scope': 'Direct retained spool page; no snapshot/capture was created, and live EOF does not establish process completion.'}
