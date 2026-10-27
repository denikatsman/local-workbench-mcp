"""Named, revision-bound executable selections without shell startup or version probes."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

from .errors import WorkbenchError
from .runtime import DEFAULT_PATH


class EnvironmentProfiles:
    def __init__(self, config, journal):
        self.config, self.journal = config, journal
        self.path = config.state_dir / 'environments.sqlite3'
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS profiles (profile_id TEXT PRIMARY KEY,workspace TEXT NOT NULL,name TEXT NOT NULL,created REAL NOT NULL,payload TEXT NOT NULL)')

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db

    def _workspace(self, workspace):
        selected = self.config.workspace(workspace)
        if not selected.executable:
            raise WorkbenchError('execution_denied', 'Runtime profiles require an executable workspace.')
        info = selected.root.stat()
        return {'path': str(selected.root), 'device': info.st_dev, 'inode': info.st_ino}

    @staticmethod
    def fingerprint(value):
        if not isinstance(value, str) or not Path(value).is_absolute() or '\0' in value:
            raise WorkbenchError('invalid_executable', 'Select an absolute executable path.')
        selected = Path(value)
        try:
            entry = selected.lstat()
            resolved = selected.resolve(strict=True)
            if not os.access(selected, os.X_OK):
                raise WorkbenchError('executable_denied', 'The selected file is not executable.')
            fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > 268435456:
                    raise WorkbenchError('unsupported_executable', 'Select a regular executable of at most 256 MiB.')
                digest, observed, deadline = hashlib.sha256(), 0, time.monotonic() + 10
                while chunk := source.read(1048576):
                    observed += len(chunk)
                    if observed > 268435456 or time.monotonic() > deadline:
                        raise WorkbenchError('executable_limit', 'Executable identity capture exceeded 256 MiB or ten seconds.')
                    digest.update(chunk)
                digest = digest.hexdigest()
                after = os.fstat(source.fileno())
            stamp = lambda info: [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
            if stamp(before) != stamp(after) or stamp(entry) != stamp(selected.lstat()) or selected.resolve(strict=True) != resolved:
                raise WorkbenchError('executable_changed', 'The executable changed during identity capture.')
            configuration = selected.parent.parent / 'pyvenv.cfg'
            config_digest = None
            if configuration.exists():
                if configuration.stat().st_size > 65536:
                    raise WorkbenchError('environment_config_limit', 'The virtual-environment configuration exceeds 64 KiB.')
                config_digest = hashlib.sha256(configuration.read_bytes()).hexdigest()
            return {'selected_path': str(selected), 'resolved_path': str(resolved), 'sha256': digest,
                    'entry_identity': stamp(entry), 'binary_identity': stamp(after), 'pyvenv_cfg_sha256': config_digest}
        except OSError as error:
            raise WorkbenchError('executable_unavailable', 'The selected executable could not be inspected.', reason=str(error)) from error

    def create(self, workspace, name, executables, request_id):
        root = self._workspace(workspace)
        if not isinstance(name, str) or not 1 <= len(name.encode()) <= 100:
            raise WorkbenchError('invalid_environment_profile', 'Use a name of 1..100 UTF-8 bytes.')
        if not isinstance(executables, dict) or not 1 <= len(executables) <= 32 or any(
                not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}', key) for key in executables):
            raise WorkbenchError('invalid_environment_profile', 'Select 1..32 named executable paths.')
        def create():
            identities = {key: self.fingerprint(value) for key, value in executables.items()}
            prefixes = list(dict.fromkeys(str(Path(item['selected_path']).parent) for item in identities.values()))
            record = {'profile_id': uuid.uuid4().hex, 'workspace': workspace, 'name': name, 'root_identity': root,
                      'executables': identities, 'path': ':'.join(prefixes + DEFAULT_PATH.split(':')),
                      'created_at': time.time(), 'version_probes_executed': False, 'shell_startup_executed': False,
                      'scope': 'Selected driver bytes, paths and virtualenv configuration; not OS containment or whole dependency attestation.'}
            with self.db() as db:
                db.execute('INSERT INTO profiles VALUES (?,?,?,?,?)', (record['profile_id'], workspace, name,
                            record['created_at'], json.dumps(record)))
            return {'ok': True, **record}
        return self.journal.run(request_id, {'tool': 'environment_profile_create', 'workspace': workspace,
            'name': name, 'executables': executables}, create)

    def load(self, workspace, profile_id):
        self._workspace(workspace)
        if not isinstance(profile_id, str) or not re.fullmatch(r'[0-9a-f]{32}', profile_id):
            raise WorkbenchError('invalid_environment_profile', 'Use a profile ID returned by this service.')
        with self.db() as db:
            row = db.execute('SELECT payload FROM profiles WHERE profile_id=? AND workspace=?', (profile_id, workspace)).fetchone()
        if row is None:
            raise WorkbenchError('unknown_environment_profile', 'This runtime profile is not bound to the selected workspace.')
        return json.loads(row[0])

    def inspect(self, workspace, profile_id):
        record = self.load(workspace, profile_id)
        drift = []
        if self._workspace(workspace) != record['root_identity']:
            drift.append({'component': 'workspace', 'reason': 'identity_changed'})
        for name, expected in record['executables'].items():
            try:
                if self.fingerprint(expected['selected_path']) != expected:
                    drift.append({'component': name, 'reason': 'executable_or_configuration_changed'})
            except WorkbenchError as error:
                drift.append({'component': name, 'reason': error.code})
        return {'ok': True, **record, 'checked_at': time.time(), 'ready': not drift, 'drift': drift}

    def listing(self, workspace, offset=0, limit=20):
        self._workspace(workspace)
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50:
            raise WorkbenchError('invalid_range', 'Use a nonnegative offset and limit 1..50.')
        with self.db() as db:
            rows = db.execute('SELECT profile_id,name,created FROM profiles WHERE workspace=? ORDER BY created,profile_id LIMIT ? OFFSET ?',
                              (workspace, limit + 1, offset)).fetchall()
        return {'ok': True, 'workspace': workspace, 'profiles': [dict(zip(('profile_id', 'name', 'created_at'), row)) for row in rows[:limit]],
                'next_offset': offset + limit if len(rows) > limit else None, 'identities_checked': False}

    def prepare(self, workspace, profile_id, argv, additions):
        observed = self.inspect(workspace, profile_id)
        if not observed['ready']:
            raise WorkbenchError('environment_profile_drift', 'The selected runtime changed. Inspect it and explicitly create a new profile before executing.',
                                 profile_id=profile_id, drift=observed['drift'], effect_state='none')
        if 'PATH' in additions and additions['PATH'] != observed['path']:
            raise WorkbenchError('environment_profile_conflict', 'A conflicting PATH override cannot be labelled as this runtime profile.', effect_state='none')
        driver = observed['executables'].get(argv[0])
        if driver is None:
            driver = next((entry for entry in observed['executables'].values() if entry['selected_path'] == argv[0]), None)
        if driver is None:
            raise WorkbenchError('profile_program_not_selected', 'The initial executable is not selected in this profile.', effect_state='none')
        return [driver['selected_path'], *argv[1:]], {**additions, 'PATH': observed['path']}, {
            'profile_id': profile_id, 'name': observed['name'], 'driver': driver, 'checked_at': observed['checked_at'],
            'identity_scope': 'Observed before launch; external executable replacement is not atomically prevented.'}
