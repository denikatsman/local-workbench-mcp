"""Only explicitly created private automation profiles; never adopt ordinary Chrome."""
import json
import re
import time
import uuid

from .errors import WorkbenchError
from .persistence import atomic_json


class BrowserProfiles:
    def __init__(self, config, journal):
        self.config, self.journal = config, journal
        self.root = config.state_dir / 'browser-profiles'
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.is_symlink():
            raise WorkbenchError('unsafe_browser_profile', 'Automation profile storage may not be a symlink.')

    def create(self, workspace, name, request_id):
        if not self.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Owned automation profiles require an executable workspace.')
        if not isinstance(name, str) or not 1 <= len(name.encode()) <= 100:
            raise WorkbenchError('invalid_browser_profile', 'Use a name of 1..100 UTF-8 bytes.')
        def create():
            identifier = uuid.uuid4().hex
            directory = self.root / identifier
            directory.mkdir(mode=0o700)
            data = directory / 'data'
            data.mkdir(mode=0o700)
            record = {'schema_version': 1, 'profile_id': identifier, 'workspace': workspace, 'name': name,
                'created_at': time.time(), 'ownership': 'explicit private automation profile',
                'ordinary_user_profile_accessed': False, 'data_identity': [data.stat().st_dev, data.stat().st_ino]}
            root = self.config.workspace(workspace).root
            record['workspace_identity'] = [str(root), root.stat().st_dev, root.stat().st_ino]
            self.journal.checkpoint(request_id, {**record, 'phase': 'profile_directory_created', 'effect_state': 'directory_created'})
            atomic_json(directory / 'owner.json', record)
            return {'ok': True, **record}
        return self.journal.run(request_id, {'tool': 'browser_profile_create', 'workspace': workspace, 'name': name}, create)

    def load(self, workspace, profile_id):
        self.config.workspace(workspace)
        if not isinstance(profile_id, str) or not re.fullmatch(r'[0-9a-f]{32}', profile_id):
            raise WorkbenchError('invalid_browser_profile', 'Use a profile ID created by this Workbench store, not a filesystem path.')
        directory = self.root / profile_id
        marker, data = directory / 'owner.json', directory / 'data'
        if directory.is_symlink() or marker.is_symlink() or data.is_symlink() or not marker.is_file() or marker.stat().st_size > 4096:
            raise WorkbenchError('unsafe_browser_profile', 'The owned profile marker or data path is unavailable or replaced.')
        try:
            record = json.loads(marker.read_text())
            info = data.stat()
            root = self.config.workspace(workspace).root
            if record['profile_id'] != profile_id or record['workspace'] != workspace or record['data_identity'] != [info.st_dev, info.st_ino]:
                raise ValueError('Identity mismatch')
            if record['workspace_identity'] != [str(root), root.stat().st_dev, root.stat().st_ino]:
                raise ValueError('Workspace identity changed')
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise WorkbenchError('unsafe_browser_profile', 'The automation profile identity did not verify.') from error
        return record, data

    def listing(self, workspace, offset=0, limit=20):
        self.config.workspace(workspace)
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50:
            raise WorkbenchError('invalid_range', 'Use nonnegative offset and limit 1..50.')
        profiles, errors = [], []
        for directory in sorted(self.root.iterdir()):
            if not re.fullmatch(r'[0-9a-f]{32}', directory.name):
                continue
            try:
                marker = directory / 'owner.json'
                if marker.is_symlink() or marker.stat().st_size > 4096:
                    raise ValueError('Invalid marker')
                record = json.loads(marker.read_text())
                if record.get('workspace') == workspace:
                    checked, _ = self.load(workspace, directory.name)
                    profiles.append(checked)
            except (WorkbenchError, OSError, ValueError):
                errors.append({'profile_id': directory.name, 'state': 'unavailable'})
            if len(profiles) + len(errors) > 10000:
                raise WorkbenchError('profile_list_limit', 'Automation profile listing exceeds 10000 entries.')
        return {'ok': True, 'profiles': profiles[offset:offset + limit], 'errors': errors[:20],
                'next_offset': offset + limit if offset + limit < len(profiles) else None,
                'ordinary_user_profile_accessed': False}
