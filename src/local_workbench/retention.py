"""Explicit storage accounting, evidence pins and generation-bound reclamation."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import uuid

from .context import work_context
from .errors import WorkbenchError
from .persistence import atomic_json
from .sessions import WorkSessions


class StorageControl:
    def __init__(self, store, journal):
        self.store, self.journal, self.config = store, journal, store.config
        self.maintenance = contextlib.nullcontext
        with store._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS evidence_pins (pin_id TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,owner TEXT,label TEXT NOT NULL,created REAL NOT NULL,state TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS cleanup_plans (plan_id TEXT PRIMARY KEY,generation TEXT NOT NULL,payload TEXT NOT NULL,created REAL NOT NULL)')

    def status(self):
        classes, seen, complete, entries, job_states = {}, set(), True, 0, {}
        deadline = time.monotonic() + 5
        for directory, _, names in os.walk(self.store.root, followlinks=False):
            for name in names:
                path = os.path.join(directory, name)
                try:
                    info = os.stat(path, follow_symlinks=False)
                except FileNotFoundError:
                    complete = False
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                entries += 1
                if entries > 200000 or time.monotonic() > deadline:
                    complete = False
                    break
                relative = os.path.relpath(path, self.store.root).split(os.sep)
                top = relative[0]
                category = {'artifacts': 'blobs', 'uploads': 'uploads', 'temporary': 'staging',
                            'reservations': 'reservations', 'jobs': 'job_metadata',
                            'browser-sessions': 'browser_metadata'}.get(top, 'journals_indexes_and_control')
                if top == 'jobs' and name.endswith(('.stdout', '.stderr')):
                    job_id = name.rsplit('.', 1)[0]
                    if job_id not in job_states:
                        record_path = self.store.root / 'jobs' / (job_id + '.json')
                        try:
                            if record_path.is_symlink() or record_path.stat().st_size > 1048576:
                                raise ValueError('Invalid metadata')
                            job_states[job_id] = json.loads(record_path.read_text()).get('status')
                        except (OSError, ValueError, TypeError):
                            job_states[job_id] = None
                    category = 'spools_unknown' if job_states[job_id] is None else 'spools_live' if job_states[job_id] in ('starting', 'running') else 'spools_terminal'
                group = classes.setdefault(category, {'logical_bytes': 0, 'physical_bytes': 0, 'files': 0})
                group['logical_bytes'] += info.st_size
                group['files'] += 1
                identity = (info.st_dev, info.st_ino)
                if identity not in seen:
                    group['physical_bytes'] += info.st_blocks * 512
                    seen.add(identity)
            if entries > 200000 or time.monotonic() > deadline:
                break
        logical = sum(group['logical_bytes'] for group in classes.values())
        with self.store._db() as db:
            pins = db.execute("SELECT COUNT(DISTINCT artifact_id) FROM evidence_pins WHERE state='active'").fetchone()[0]
        return {'ok': True, 'checked_at': time.time(), 'classes': classes, 'logical_bytes': logical,
                'physical_bytes': sum(group['physical_bytes'] for group in classes.values()),
                'accounting_complete': complete, 'snapshot_atomic': False, 'limit_bytes': self.config.max_storage_bytes,
                'available_logical_headroom': max(0, self.config.max_storage_bytes - logical) if complete else None,
                'pinned_artifacts': pins, 'automatic_pruning': False,
                'headroom_policy': 'Unique ingestion needs complete staging plus reservation metadata. Verified duplicates reuse existing bytes. Journals and recovery receipts also need space.',
                'physical_scope': 'Allocated blocks, counted once per device/inode; APFS shared extents and compression are not fully observable here.'}

    def pin(self, artifact_id, label, request_id):
        if not isinstance(label, str) or not 1 <= len(label.encode()) <= 200:
            raise WorkbenchError('invalid_pin', 'Use a pin label of 1..200 UTF-8 bytes.')
        def pin():
            with self.store.locked():
                if not self.store.verify(artifact_id)['verified']:
                    raise WorkbenchError('artifact_corrupt', 'Corrupt evidence cannot be pinned as verified.')
                identifier = uuid.uuid4().hex
                with self.store._db() as db:
                    db.execute('INSERT INTO evidence_pins VALUES (?,?,?,?,?,?)',
                        (identifier, artifact_id, work_context.get(), label, time.time(), 'active'))
            return {'ok': True, 'pin_id': identifier, 'artifact_id': artifact_id,
                    'owner_work_session_id': work_context.get(), 'state': 'active', 'storage_administration': True}
        return self.journal.run(request_id, {'tool': 'storage_pin', 'artifact_id': artifact_id, 'label': label,
            'work_session_id': work_context.get()}, pin)

    def unpin(self, pin_id, request_id):
        WorkSessions.validate(pin_id)
        def unpin():
            with self.store.locked(), self.store._db() as db:
                row = db.execute('SELECT owner,artifact_id FROM evidence_pins WHERE pin_id=?', (pin_id,)).fetchone()
                if row is None:
                    raise WorkbenchError('unknown_pin', 'No evidence pin has this ID.')
                if work_context.get() is not None and row[0] != work_context.get():
                    raise WorkbenchError('work_session_mismatch', 'This pin belongs to another work context.')
                db.execute("UPDATE evidence_pins SET state='released' WHERE pin_id=?", (pin_id,))
            return {'ok': True, 'pin_id': pin_id, 'artifact_id': row[1], 'state': 'released',
                    'content_deleted': False, 'storage_administration': True}
        return self.journal.run(request_id, {'tool': 'storage_unpin', 'pin_id': pin_id,
            'work_session_id': work_context.get()}, unpin)

    def _dependencies(self, exclude_request=None):
        artifacts, uploads, global_blockers = {}, {}, []
        deadline = time.monotonic() + 5
        def link(value, reason, protect_upload=True):
            if isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value):
                artifacts.setdefault(value, set()).add(reason)
            elif isinstance(value, dict):
                identifier = value.get('upload_id')
                if isinstance(identifier, str) and protect_upload:
                    uploads.setdefault(identifier, set()).add(reason)
                for child in value.values():
                    link(child, reason, protect_upload)
            elif isinstance(value, list):
                for child in value:
                    link(child, reason, protect_upload)
        try:
            with self.journal._db() as db:
                rows = db.execute('SELECT request_id,state,result FROM operations LIMIT 100001').fetchall()
            if len(rows) > 100000:
                global_blockers.append('operation_dependency_scan_limit')
            for request, state, raw in rows:
                if time.monotonic() >= deadline:
                    global_blockers.append('dependency_scan_deadline')
                    break
                if request == exclude_request:
                    continue
                if raw is None:
                    if state == 'pending':
                        global_blockers.append('unresolved_operation:' + request)
                    continue
                value = json.loads(raw)
                if value.get('storage_administration'):
                    continue
                if state == 'failed' and value.get('error', {}).get('effect_state') == 'none':
                    continue
                link(value, 'operation:' + request, protect_upload=state == 'pending')
            path = self.store.root / 'work-sessions.sqlite3'
            if path.exists():
                if path.is_symlink():
                    raise ValueError('Session database is a symlink')
                with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
                    rows = db.execute('SELECT e.session_id,s.state,e.payload FROM events e JOIN sessions s ON e.session_id=s.session_id LIMIT 100001').fetchall()
                if len(rows) > 100000:
                    global_blockers.append('session_dependency_scan_limit')
                for identifier, state, raw in rows:
                    if time.monotonic() >= deadline:
                        global_blockers.append('dependency_scan_deadline')
                        break
                    link(json.loads(raw), 'session:' + identifier, protect_upload=state == 'open')
            job_directory = self.store.root / 'jobs'
            if job_directory.is_symlink():
                raise ValueError('Job directory is a symlink')
            for index, path in enumerate(job_directory.glob('*.json')):
                if index >= 100000 or time.monotonic() >= deadline:
                    global_blockers.append('job_dependency_scan_limit')
                    break
                if path.is_symlink() or path.stat().st_size > 1048576:
                    raise ValueError('Invalid job metadata')
                with path.open() as source:
                    record = json.load(source)
                link(record.get('artifacts', {}), 'job:' + record.get('job_id', path.stem))
                if record.get('status') in ('starting', 'running') or record.get('publication_state') == 'finalizing_output':
                    global_blockers.append('active_job:' + record.get('job_id', path.stem))
            change_database = self.store.root / 'change-sets.sqlite3'
            if change_database.exists():
                if change_database.is_symlink():
                    raise ValueError('Change-set database is a symlink')
                with contextlib.closing(sqlite3.connect(change_database.as_uri() + '?mode=ro', uri=True)) as db:
                    rows = db.execute('SELECT change_set_id,payload FROM change_sets LIMIT 100001').fetchall()
                if len(rows) > 100000:
                    global_blockers.append('change_set_dependency_scan_limit')
                for identifier, raw in rows:
                    if time.monotonic() >= deadline:
                        global_blockers.append('dependency_scan_deadline')
                        break
                    link(json.loads(raw), 'change-set:' + identifier)
            with self.store._db() as db:
                pins = db.execute("SELECT artifact_id,pin_id FROM evidence_pins WHERE state='active'").fetchall()
            for artifact, pin in pins:
                artifacts.setdefault(artifact, set()).add('pin:' + pin)
        except (OSError, sqlite3.Error, ValueError, TypeError):
            global_blockers.append('dependency_catalogue_unavailable')
        return artifacts, uploads, sorted(set(global_blockers))

    @staticmethod
    def _fingerprint(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise WorkbenchError('unsafe_storage_target', 'Cleanup only accepts regular owned storage files.')
        return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    def _targets(self, artifact_ids, upload_ids, exclude_request=None):
        artifacts, uploads, global_blockers = self._dependencies(exclude_request)
        targets = []
        for identifier in artifact_ids:
            path = self.store.path(identifier)
            targets.append({'kind': 'artifact', 'id': identifier, 'fingerprint': self._fingerprint(path),
                            'blocked_by': sorted(artifacts.get(identifier, set())) + global_blockers})
        for identifier in upload_ids:
            if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier):
                raise WorkbenchError('invalid_upload', 'Use an existing upload ID.')
            path = self.store.uploads / identifier
            if not path.exists():
                raise WorkbenchError('unknown_upload', 'No staging upload exists with this ID.')
            marker = self.store.uploads / (identifier + '.complete')
            targets.append({'kind': 'upload', 'id': identifier, 'fingerprint': self._fingerprint(path),
                'marker_fingerprint': self._fingerprint(marker) if marker.exists() else None,
                'blocked_by': sorted(uploads.get(identifier, set())) + global_blockers})
        return targets

    def plan(self, artifact_ids, upload_ids, request_id):
        if not isinstance(artifact_ids, list) or not isinstance(upload_ids, list) or not 1 <= len(artifact_ids) + len(upload_ids) <= 100:
            raise WorkbenchError('invalid_cleanup', 'Select 1..100 explicit artifact/upload IDs; there is no automatic sweep.')
        if any(not isinstance(identifier, str) for identifier in artifact_ids + upload_ids):
            raise WorkbenchError('invalid_cleanup', 'Storage IDs must be strings.')
        if len(set(artifact_ids)) != len(artifact_ids) or len(set(upload_ids)) != len(upload_ids):
            raise WorkbenchError('invalid_cleanup', 'Select each target once.')
        def preview():
            with self.store.locked():
                targets = self._targets(artifact_ids, upload_ids, request_id)
                generation = hashlib.sha256(json.dumps(targets, sort_keys=True).encode()).hexdigest()
                identifier = uuid.uuid4().hex
                with self.store._db() as db:
                    db.execute('INSERT INTO cleanup_plans VALUES (?,?,?,?)', (identifier, generation, json.dumps(targets), time.time()))
            return {'ok': True, 'plan_id': identifier, 'generation': generation, 'targets': targets,
                    'eligible': not any(target['blocked_by'] for target in targets), 'applied': False,
                    'storage_administration': True, 'scope': 'Only these selected storage objects. Journals, pins, session evidence and pending operations are preserved.'}
        return self.journal.run(request_id, {'tool': 'storage_cleanup_plan', 'artifact_ids': artifact_ids,
                                            'upload_ids': upload_ids}, preview)

    def apply(self, plan_id, expected_generation, request_id):
        WorkSessions.validate(plan_id)
        def remove():
            with self.store._db() as db:
                row = db.execute('SELECT generation,payload FROM cleanup_plans WHERE plan_id=?', (plan_id,)).fetchone()
            if row is None or row[0] != expected_generation:
                raise WorkbenchError('cleanup_generation', 'Use the exact generation from a known cleanup preview.')
            selected = json.loads(row[1])
            artifact_ids = [target['id'] for target in selected if target['kind'] == 'artifact']
            upload_ids = [target['id'] for target in selected if target['kind'] == 'upload']
            with contextlib.ExitStack() as locks:
                locks.enter_context(self.maintenance())
                for identifier in sorted(upload_ids):
                    locks.enter_context(self.journal._key_lock('resource', 'upload:' + identifier))
                locks.enter_context(self.store.locked())
                try:
                    current = self._targets(artifact_ids, upload_ids, request_id)
                except FileNotFoundError as error:
                    raise WorkbenchError('cleanup_stale', 'A selected storage object disappeared after preview.', effect_state='none') from error
                except WorkbenchError as error:
                    if error.code in ('unknown_artifact', 'unknown_upload'):
                        raise WorkbenchError('cleanup_stale', 'A selected storage object disappeared after preview.', effect_state='none') from error
                    raise
                generation = hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest()
                if generation != expected_generation:
                    raise WorkbenchError('cleanup_stale', 'A target or its dependencies changed after preview; nothing was removed.')
                if any(target['blocked_by'] for target in current):
                    raise WorkbenchError('storage_protected', 'The selected objects have retained dependencies; nothing was removed.')
                for identifier in artifact_ids:
                    fd = self.store._reader_fd(identifier)
                    locks.callback(os.close, fd)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError as error:
                        raise WorkbenchError('artifact_in_use', 'An active reader holds this artifact; nothing was removed.', artifact_id=identifier, effect_state='none') from error
                result = {'ok': True, 'plan_id': plan_id, 'targets': current, 'removed': [], 'storage_administration': True}
                self.journal.checkpoint(request_id, {**result, 'phase': 'before_cleanup', 'effect_state': 'none'})
                for target in current:
                    if target['kind'] == 'artifact':
                        with self.store._db() as db:
                            db.execute('INSERT OR REPLACE INTO artifact_retirements VALUES (?,?,?)', (target['id'][7:], request_id, time.time()))
                        self.store.path(target['id']).unlink()
                    else:
                        identifier = target['id']
                        marker = self.store.uploads / (identifier + '.complete')
                        original = json.loads(marker.read_text()) if marker.exists() else None
                        atomic_json(self.store.uploads / (identifier + '.abandoned'),
                            {'upload_id': identifier, 'accepted_bytes': target['fingerprint'][2], 'abandoned_at': time.time(), 'original_artifact': original})
                        (self.store.uploads / identifier).unlink()
                        marker.unlink(missing_ok=True)
                    result['removed'].append({'kind': target['kind'], 'id': target['id']})
                    self.journal.checkpoint(request_id, {**result, 'phase': 'cleanup_in_progress', 'effect_state': 'removed'})
                for directory in (self.store.blobs, self.store.uploads):
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                return {**result, 'applied': True, 'effect_state': 'removed', 'durability': 'confirmed'}
        return self.journal.run(request_id, {'tool': 'storage_cleanup_apply', 'plan_id': plan_id,
            'expected_generation': expected_generation}, remove, resource='storage-cleanup')

    def inspect_plan(self, plan_id):
        WorkSessions.validate(plan_id)
        with self.store._db() as db:
            row = db.execute('SELECT generation,payload,created FROM cleanup_plans WHERE plan_id=?', (plan_id,)).fetchone()
        if row is None:
            raise WorkbenchError('unknown_cleanup_plan', 'No cleanup plan has this ID.')
        return {'ok': True, 'plan_id': plan_id, 'generation': row[0], 'targets': json.loads(row[1]),
                'created_at': row[2], 'observation': 'The preserved preview; apply independently rechecks the current generation.'}
