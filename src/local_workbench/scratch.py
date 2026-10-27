"""Owned scratch manifests and reversible retirement without replacing user paths."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import uuid

from .errors import WorkbenchError
from .persistence import rename_exclusive


class ScratchSpaces:
    def __init__(self, sessions, files):
        self.sessions, self.files, self.store, self.journal = sessions, files, sessions.store, sessions.journal
        with sessions.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS scratch_spaces (scratch_id TEXT PRIMARY KEY,session_id TEXT NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL)')

    def active_ids(self, session_id):
        with self.sessions.db() as db:
            return [row[0] for row in db.execute("SELECT scratch_id FROM scratch_spaces WHERE session_id=? AND state IN ('active','uncertain')", (session_id,))]

    def _load(self, session_id, scratch_id):
        self.sessions.ensure(session_id, allow_closed=True)
        self.sessions.validate(scratch_id)
        with self.sessions.db() as db:
            row = db.execute('SELECT session_id,state,payload FROM scratch_spaces WHERE scratch_id=?', (scratch_id,)).fetchone()
        if row is None:
            raise WorkbenchError('unknown_scratch', 'No scratch manifest has this ID.')
        if row[0] != session_id:
            raise WorkbenchError('work_session_mismatch', 'This scratch directory belongs to another work session.')
        return {**json.loads(row[2]), 'state': row[1]}

    def create(self, session_id, request_id):
        session = self.sessions.ensure(session_id)
        self.files._writable(session['workspace'])
        def create():
            identifier = uuid.uuid4().hex
            path = '.workbench-scratch-' + identifier
            marker = json.dumps({'schema_version': 1, 'scratch_id': identifier, 'session_id': session_id}, sort_keys=True).encode()
            self.journal.checkpoint(request_id, {'scratch_id': identifier, 'workspace': session['workspace'],
                'work_session_id': session_id, 'path': path, 'phase': 'before_scratch_creation', 'effect_state': 'none'})
            with self.files._parent(session['workspace'], path) as (parent, name):
                os.mkdir(name, 0o700, dir_fd=parent)
                directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    identity = os.fstat(directory)
                    record = {'scratch_id': identifier, 'work_session_id': session_id, 'workspace': session['workspace'],
                        'path': path, 'original_path': path, 'retired_path': '.workbench-retired-' + identifier,
                        'directory_identity': [identity.st_dev, identity.st_ino],
                        'marker_sha256': hashlib.sha256(marker).hexdigest(), 'created_at': time.time()}
                    self.journal.checkpoint(request_id, {**record, 'phase': 'scratch_directory_created', 'effect_state': 'directory_created'})
                    with self.sessions.db() as db:
                        db.execute('INSERT INTO scratch_spaces VALUES (?,?,?,?)', (identifier, session_id, 'uncertain', json.dumps(record)))
                    fd = os.open('.workbench-owner.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(marker)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.fsync(directory)
                    os.fsync(parent)
                finally:
                    os.close(directory)
            with self.sessions.db() as db:
                db.execute("UPDATE scratch_spaces SET state='active' WHERE scratch_id=?", (identifier,))
            self.sessions._append(session_id, 'scratch:' + request_id, {'kind': 'scratch_created', **record})
            return {'ok': True, **record, 'state': 'active'}
        return self.journal.run(request_id, {'tool': 'scratch_create', 'session_id': session_id}, create,
                                resource='work-session:' + session_id)

    def _tree(self, record):
        with self.files._parent(record['workspace'], record['path']) as (parent, name):
            identity = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(identity.st_mode) or [identity.st_dev, identity.st_ino] != record['directory_identity']:
                raise WorkbenchError('scratch_identity_changed', 'The owned scratch directory has been replaced.')
        with self.files._regular(record['workspace'], record['path'] + '/.workbench-owner.json') as (source, _):
            marker = source.read(4097)
        if hashlib.sha256(marker).hexdigest() != record['marker_sha256']:
            raise WorkbenchError('scratch_identity_changed', 'The scratch ownership marker no longer matches.')
        entries, byte_count, deadline = [], 0, time.monotonic() + 10
        for item in self.files._walk(record['workspace'], record['path'], recursive=True):
            path = item['path']
            if item['type'] == 'error':
                raise WorkbenchError('scratch_incomplete', 'The entire scratch tree could not be checked.', path=path)
            if len(entries) >= 10000 or time.monotonic() >= deadline:
                raise WorkbenchError('scratch_limit', 'Scratch validation supports at most 10000 entries and ten seconds.')
            with self.files._parent(record['workspace'], path) as (parent, name):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            entry = {'path': path[len(record['path']) + 1:], 'identity': [info.st_dev, info.st_ino], 'mode': info.st_mode,
                     'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
            if stat.S_ISREG(info.st_mode):
                byte_count += info.st_size
                if byte_count > 67108864:
                    raise WorkbenchError('scratch_limit', 'Scratch validation supports at most 64 MiB of file bytes.')
                with self.files._regular(record['workspace'], path) as (stream, before):
                    digest, observed_bytes = hashlib.sha256(), 0
                    while chunk := stream.read(1048576):
                        observed_bytes += len(chunk)
                        if observed_bytes > info.st_size or time.monotonic() >= deadline:
                            raise WorkbenchError('scratch_changed', 'A scratch file grew or exceeded the validation deadline.', path=path)
                        digest.update(chunk)
                    entry['sha256'] = digest.hexdigest()
                    after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise WorkbenchError('scratch_changed', 'A scratch file changed during validation.', path=path)
            elif stat.S_ISLNK(info.st_mode):
                raise WorkbenchError('scratch_links', 'Scratch retirement refuses symlinks; no target was followed.', path=path)
            elif not stat.S_ISDIR(info.st_mode):
                raise WorkbenchError('scratch_special_file', 'Scratch retirement refuses special files.', path=path)
            entries.append(entry)
        with self.files._parent(record['workspace'], record['path']) as (parent, name):
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (identity.st_dev, identity.st_ino, identity.st_mtime_ns, identity.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
            raise WorkbenchError('scratch_changed', 'The scratch directory changed during validation.')
        entries.sort(key=lambda item: item['path'])
        raw = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
        return entries, hashlib.sha256(raw).hexdigest()

    def inspect(self, session_id, scratch_id):
        record = self._load(session_id, scratch_id)
        matches = []
        for candidate in (record['original_path'], record['retired_path']):
            with self.files._parent(record['workspace'], candidate) as (parent, name):
                try:
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
            if stat.S_ISDIR(info.st_mode) and [info.st_dev, info.st_ino] == record['directory_identity']:
                matches.append(candidate)
        if len(matches) != 1:
            raise WorkbenchError('scratch_identity_changed', 'No unique owned scratch directory remains at its recorded locations.')
        record['path'] = matches[0]
        entries, digest = self._tree(record)
        manifest = self.store.put_bytes(json.dumps(entries, ensure_ascii=True).encode(), 'scratch-manifest:' + scratch_id)
        return {'ok': True, **record, 'tree_sha256': digest, 'entry_count': len(entries), 'manifest_artifact': manifest,
                'observed_state': 'active' if record['path'] == record['original_path'] else 'retired',
                'path_base': 'Paths in the manifest are relative to this owned scratch directory.',
                'cleanup': 'Retirement moves the complete owned directory to a recoverable sibling; it does not delete content.'}

    def reconcile(self, session_id, scratch_id, expected_tree_sha256, request_id):
        def reconcile():
            observed = self.inspect(session_id, scratch_id)
            if observed['tree_sha256'] != expected_tree_sha256:
                raise WorkbenchError('scratch_changed', 'The observed scratch tree changed after inspection.')
            record = self._load(session_id, scratch_id)
            record['path'] = observed['path']
            with self.sessions.db() as db:
                db.execute('UPDATE scratch_spaces SET state=?,payload=? WHERE scratch_id=?',
                    (observed['observed_state'], json.dumps(record), scratch_id))
            self.sessions._append(session_id, 'scratch-reconcile:' + request_id,
                {'kind': 'scratch_reconciled', 'scratch_id': scratch_id, 'observed_state': observed['observed_state'],
                 'tree_sha256': observed['tree_sha256'], 'filesystem_changed': False})
            return {'ok': True, **record, 'state': observed['observed_state'], 'filesystem_changed': False}
        return self.journal.run(request_id, {'tool': 'scratch_reconcile', 'session_id': session_id,
            'scratch_id': scratch_id, 'expected_tree_sha256': expected_tree_sha256}, reconcile,
            resource='work-session:' + session_id)

    def move(self, session_id, scratch_id, expected_tree_sha256, request_id, restore=False):
        self.sessions.ensure(session_id)
        record = self._load(session_id, scratch_id)
        def move():
            current = self._load(session_id, scratch_id)
            expected_state = 'retired' if restore else 'active'
            if current['state'] != expected_state:
                raise WorkbenchError('scratch_state', 'This scratch directory is not in the required state.')
            _, digest = self._tree(current)
            if digest != expected_tree_sha256:
                raise WorkbenchError('scratch_changed', 'The scratch tree changed after the preview; no move was attempted.')
            target = current['original_path'] if restore else current['retired_path']
            self.journal.checkpoint(request_id, {**current, 'target_path': target, 'phase': 'before_scratch_move', 'effect_state': 'none'})
            with self.files._parent(current['workspace'], current['path']) as (source, name):
                with self.files._parent(current['workspace'], target) as (destination, target_name):
                    try:
                        rename_exclusive(source, name, destination, target_name)
                    except FileExistsError as error:
                        raise WorkbenchError('already_exists', 'The destination is occupied; nothing was replaced.') from error
                    current.update(path=target, moved_at=time.time())
                    self.journal.checkpoint(request_id, {**current, 'phase': 'scratch_moved', 'effect_state': 'moved'})
                    _, after_digest = self._tree(current)
                    if after_digest != digest:
                        with self.sessions.db() as db:
                            db.execute("UPDATE scratch_spaces SET state='uncertain',payload=? WHERE scratch_id=?", (json.dumps(current), scratch_id))
                        raise WorkbenchError('scratch_changed', 'The directory moved, but its content changed; inspect and reconcile before further action.',
                                             scratch_id=scratch_id, observed_path=target, effect_state='moved')
                    try:
                        os.fsync(source)
                        os.fsync(destination)
                    except OSError as error:
                        current['state'] = 'uncertain'
                        with self.sessions.db() as db:
                            db.execute("UPDATE scratch_spaces SET state='uncertain',payload=? WHERE scratch_id=?", (json.dumps(current), scratch_id))
                        raise WorkbenchError('scratch_durability_unknown', 'The directory moved, but syncing its parent failed. Inspect and reconcile; do not repeat the move.',
                            **current, phase='directory_fsync', effect_state='moved', durability='unknown') from error
            state = 'active' if restore else 'retired'
            with self.sessions.db() as db:
                db.execute('UPDATE scratch_spaces SET state=?,payload=? WHERE scratch_id=?', (state, json.dumps(current), scratch_id))
            self.sessions._append(session_id, 'scratch-move:' + request_id, {'kind': 'scratch_moved', **current, 'state': state})
            return {'ok': True, **current, 'state': state, 'content_deleted': False, 'no_replace': True}
        return self.journal.run(request_id, {'tool': 'scratch_restore' if restore else 'scratch_retire',
            'session_id': session_id, 'scratch_id': scratch_id, 'expected_tree_sha256': expected_tree_sha256}, move,
            resource='work-session:' + session_id)
