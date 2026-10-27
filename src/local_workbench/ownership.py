"""Explicit, persistent compare-and-restore leases over managed files."""
from __future__ import annotations

import hashlib
import json
import time
import unicodedata
import uuid

from .errors import WorkbenchError


class FileLeases:
    def __init__(self, sessions, files):
        self.sessions, self.files = sessions, files
        self.store, self.journal = sessions.store, sessions.journal
        with sessions.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS file_leases (lease_id TEXT PRIMARY KEY,session_id TEXT NOT NULL,resource_key TEXT NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL)')
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS active_file_lease ON file_leases(resource_key) WHERE state IN ('prepared','active','uncertain')")

    def active_ids(self, session_id):
        with self.sessions.db() as db:
            return [row[0] for row in db.execute("SELECT lease_id FROM file_leases WHERE session_id=? AND state IN ('prepared','active','uncertain')", (session_id,))]

    @staticmethod
    def child_request(request_id, action):
        return 'lease-' + action + ':' + hashlib.sha256(request_id.encode()).hexdigest()

    def _load(self, session_id, lease_id):
        self.sessions.ensure(session_id, allow_closed=True)
        self.sessions.validate(lease_id)
        with self.sessions.db() as db:
            row = db.execute('SELECT session_id,state,payload FROM file_leases WHERE lease_id=?', (lease_id,)).fetchone()
        if row is None:
            raise WorkbenchError('unknown_lease', 'No file lease has this ID.')
        if row[0] != session_id:
            raise WorkbenchError('work_session_mismatch', 'This lease belongs to a different work session.')
        return {**json.loads(row[2]), 'state': row[1]}

    def _state(self, lease_id, state, record):
        with self.sessions.db() as db:
            db.execute('UPDATE file_leases SET state=?,payload=? WHERE lease_id=?',
                       (state, json.dumps(record, ensure_ascii=True), lease_id))

    def acquire(self, session_id, path, artifact_id, request_id, lifetime_seconds=300):
        session = self.sessions.ensure(session_id)
        self.files._writable(session['workspace'])
        parts = self.files._parts(path)
        path = '/'.join(parts)
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 3600:
            raise WorkbenchError('invalid_lease', 'Lease lifetime must be 1..3600 seconds; expiry never silently restores files.')
        if not self.store.verify(artifact_id)['verified']:
            raise WorkbenchError('artifact_corrupt', 'The temporary replacement did not verify.')
        resource = self.files._resource(session['workspace'], path) + ':' + unicodedata.normalize('NFC', parts[-1]).casefold()
        payload = {'tool': 'file_lease_acquire', 'session_id': session_id, 'path': path,
                   'artifact_id': artifact_id, 'lifetime_seconds': lifetime_seconds}
        def apply():
            with self.journal._key_lock('file-lease', resource):
                with self.sessions.db() as db:
                    if db.execute("SELECT 1 FROM file_leases WHERE resource_key=? AND state IN ('prepared','active','uncertain')", (resource,)).fetchone():
                        raise WorkbenchError('resource_leased', 'This file already has an unreleased lease.', effect_state='none')
                before = self.files.read_file(session['workspace'], path, max_bytes=1)
                identifier = uuid.uuid4().hex
                record = {'lease_id': identifier, 'work_session_id': session_id, 'workspace': session['workspace'],
                          'path': path, 'resource_key': resource, 'before_artifact': before['artifact_id'],
                          'before_capture_id': before['capture_id'],
                          'after_artifact': artifact_id, 'created_at': time.time(),
                          'expires_at': time.time() + lifetime_seconds,
                          'apply_request_id': self.child_request(request_id, 'apply'),
                          'scope': 'Managed file content; external writers are not atomically locked, and filesystem metadata is not universally restored.'}
                with self.sessions.db() as db:
                    db.execute('INSERT INTO file_leases VALUES (?,?,?,?,?)',
                               (identifier, session_id, resource, 'prepared', json.dumps(record)))
                self.journal.checkpoint(request_id, {**record, 'phase': 'before_lease_write', 'effect_state': 'none'})
                try:
                    result = self.files.write_file(session['workspace'], path, record['apply_request_id'],
                                                   expected_sha256=before['revision_sha256'], artifact_id=artifact_id)
                except WorkbenchError as error:
                    state = 'failed' if error.code == 'revision_conflict' or error.details.get('effect_state') == 'none' else 'uncertain'
                    self._state(identifier, state, record)
                    raise WorkbenchError(error.code, error.message, **{**error.details, 'lease_id': identifier,
                        'work_session_id': session_id,
                        'before_artifact': record['before_artifact'], 'after_artifact': record['after_artifact'],
                        'lease_state': state}) from error
                except Exception as error:
                    self._state(identifier, 'uncertain', record)
                    raise WorkbenchError('lease_operation_uncertain', 'Inspect the allocated lease and apply receipt before restoring or releasing it.',
                                         lease_id=identifier, work_session_id=session_id,
                                         apply_request_id=record['apply_request_id'], effect_state='unknown') from error
                self._state(identifier, 'active', record)
                self.sessions._append(session_id, 'lease:' + request_id, {'kind': 'file_lease_acquired', **record})
                return {**record, 'ok': True, 'state': 'active', 'effect_state': result['effect_state']}
        return self.journal.run(request_id, payload, apply, resource='work-session:' + session_id)

    def inspect(self, session_id, lease_id):
        record = self._load(session_id, lease_id)
        return {'ok': True, **record, 'expired': time.time() >= record['expires_at'],
                'restore_requires': 'Current file content must still equal after_artifact; expiry does not grant permission to overwrite later changes.'}

    def restore(self, session_id, lease_id, request_id):
        record = self._load(session_id, lease_id)
        def restore():
            with self.journal._key_lock('file-lease', record['resource_key']):
                current = self._load(session_id, lease_id)
                if current['state'] not in ('active', 'prepared', 'uncertain'):
                    raise WorkbenchError('lease_inactive', 'This lease is already restored or explicitly released.')
                parts = self.files._parts(current['path'])
                resource = self.files._resource(current['workspace'], current['path']) + ':' + unicodedata.normalize('NFC', parts[-1]).casefold()
                if resource != current['resource_key']:
                    raise WorkbenchError('lease_target_changed', 'The leased parent directory changed identity; no restoration was attempted.')
                if not self.store.verify(current['before_artifact'])['verified']:
                    raise WorkbenchError('artifact_corrupt', 'The original bytes did not verify; no restoration was attempted.')
                self.journal.checkpoint(request_id, {**current, 'phase': 'before_lease_restore', 'effect_state': 'none'})
                result = self.files.write_file(current['workspace'], current['path'], self.child_request(request_id, 'restore'),
                    expected_sha256=current['after_artifact'][7:], artifact_id=current['before_artifact'])
                self._state(lease_id, 'restored', current)
                self.sessions._append(session_id, 'lease-restore:' + request_id,
                    {'kind': 'file_lease_restored', 'lease_id': lease_id, 'receipt': result})
                return {'ok': True, 'lease_id': lease_id, 'work_session_id': session_id, 'state': 'restored',
                        'before_artifact': current['after_artifact'], 'after_artifact': current['before_artifact'],
                        'effect_state': result['effect_state'], 'external_writer_atomic_cas': False}
        return self.journal.run(request_id, {'tool': 'file_lease_restore', 'session_id': session_id, 'lease_id': lease_id},
                                restore, resource='work-session:' + session_id)

    def release(self, session_id, lease_id, request_id):
        record = self._load(session_id, lease_id)
        def release():
            with self.journal._key_lock('file-lease', record['resource_key']):
                current = self._load(session_id, lease_id)
                self._state(lease_id, 'released', current)
                self.sessions._append(session_id, 'lease-release:' + request_id,
                    {'kind': 'file_lease_released', 'lease_id': lease_id, 'restoration_performed': False})
                return {'ok': True, 'lease_id': lease_id, 'work_session_id': session_id, 'state': 'released',
                        'restoration_performed': False, 'history_preserved': True}
        return self.journal.run(request_id, {'tool': 'file_lease_release', 'session_id': session_id, 'lease_id': lease_id},
                                release, resource='work-session:' + session_id)
