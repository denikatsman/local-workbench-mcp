"""Managed filesystem operations with explicit revisions and no-replace moves."""
import errno
import hashlib
import os
import stat
import time
import uuid

from .errors import WorkbenchError
from .persistence import rename_exclusive


class FilesystemOperations:
    def __init__(self, files):
        self.files, self.store, self.journal = files, files.store, files.journal

    @staticmethod
    def child(request_id, phase):
        return 'filesystem:' + hashlib.sha256((request_id + ':' + phase).encode()).hexdigest()

    def inspect(self, workspace, path):
        with self.files._parent(workspace, path) as (parent, name):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        return {'ok': True, 'workspace': workspace, 'path': path, 'checked_at': time.time(),
                'type': 'file' if stat.S_ISREG(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'symlink' if stat.S_ISLNK(info.st_mode) else 'special',
                'device': info.st_dev, 'inode': info.st_ino, 'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
                'links': info.st_nlink, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
                'symlink_followed': False, 'content_verified': False}

    def mkdir(self, workspace, path, request_id, recursive=False, exist_ok=False):
        self.files._writable(workspace)
        parts = self.files._parts(path)
        if type(recursive) is not bool or type(exist_ok) is not bool:
            raise WorkbenchError('invalid_mkdir', 'recursive and exist_ok must be booleans.')
        def create():
            created = []
            targets = ['/'.join(parts[:index]) for index in range(1, len(parts) + 1)] if recursive else ['/'.join(parts)]
            for index, target in enumerate(targets):
                self.journal.checkpoint(request_id, {'workspace': workspace, 'path': path, 'created_paths': created,
                    'phase': 'before_directory_creation', 'effect_state': 'partial' if created else 'none'})
                with self.files._parent(workspace, target) as (parent, name):
                    try:
                        os.mkdir(name, mode=0o755, dir_fd=parent)
                        created.append(target)
                    except FileExistsError as error:
                        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if not stat.S_ISDIR(info.st_mode) or (index == len(targets) - 1 and not exist_ok):
                            raise WorkbenchError('already_exists', 'The existing target does not satisfy these mkdir options.',
                                created_paths=created, effect_state='partial' if created else 'none') from error
                    try:
                        os.fsync(parent)
                    except OSError as error:
                        raise WorkbenchError('directory_durability_unknown', 'Directories were created, but their durability is unknown.',
                            created_paths=created, effect_state='partial', durability='unknown') from error
            return {'ok': True, 'workspace': workspace, 'path': path, 'created_paths': created,
                    'applied_this_call': bool(created), 'effect_state': 'published' if created else 'none', 'durability': 'confirmed'}
        return self.journal.run(request_id, {'tool': 'filesystem_mkdir', 'workspace': workspace, 'path': path,
            'recursive': recursive, 'exist_ok': exist_ok}, create, resource='filesystem:' + workspace)

    def copy(self, workspace, path, destination_workspace, destination, expected_sha256, request_id, destination_sha256=None):
        self.files._writable(destination_workspace)
        self.files._revision(expected_sha256)
        self.files._revision(destination_sha256)
        if expected_sha256 is None:
            raise WorkbenchError('revision_required', 'Copy requires the exact source revision.')
        def copy():
            snapshot = self.files.read_file(workspace, path, max_bytes=1)
            if snapshot['revision_sha256'] != expected_sha256:
                raise WorkbenchError('revision_conflict', 'The source changed before acquisition.', effect_state='none')
            self.journal.checkpoint(request_id, {'workspace': destination_workspace, 'path': destination,
                'source_artifact': snapshot['artifact_id'], 'phase': 'before_copy_publication', 'effect_state': 'none'})
            receipt = self.files.write_file(destination_workspace, destination, self.child(request_id, 'copy'),
                expected_sha256=destination_sha256, artifact_id=snapshot['artifact_id'])
            return {**receipt, 'source_workspace': workspace, 'source_path': path, 'source_artifact': snapshot['artifact_id'],
                'metadata_policy': 'Content copy using managed-write mode policy; ACLs/xattrs/hardlink identity are not copied.'}
        return self.journal.run(request_id, {'tool': 'filesystem_copy', 'workspace': workspace, 'path': path,
            'destination_workspace': destination_workspace, 'destination': destination,
            'expected_sha256': expected_sha256, 'destination_sha256': destination_sha256}, copy)

    def move(self, workspace, path, destination_workspace, destination, expected_sha256, request_id):
        self.files._writable(workspace)
        self.files._writable(destination_workspace)
        self.files._revision(expected_sha256)
        if expected_sha256 is None:
            raise WorkbenchError('revision_required', 'Move requires the exact regular-file source revision.')
        def move():
            snapshot = self.files.read_file(workspace, path, max_bytes=1)
            if snapshot['revision_sha256'] != expected_sha256:
                raise WorkbenchError('revision_conflict', 'The source changed; no move was attempted.', effect_state='none')
            locator = {'source_workspace': workspace, 'source_path': path, 'workspace': destination_workspace,
                'path': destination, 'source_artifact': snapshot['artifact_id']}
            self.journal.checkpoint(request_id, {**locator, 'phase': 'before_move', 'effect_state': 'none'})
            with self.files._parent(workspace, path) as (source, name):
                with self.files._parent(destination_workspace, destination) as (target, target_name):
                    try:
                        rename_exclusive(source, name, target, target_name)
                    except FileExistsError as error:
                        raise WorkbenchError('already_exists', 'The destination is occupied; it was not replaced.', effect_state='none') from error
                    except OSError as error:
                        if error.errno == errno.EXDEV:
                            raise WorkbenchError('cross_volume_move', 'Atomic move is unavailable across these volumes. Use copy, verify, then an explicit Trash operation.', effect_state='none') from error
                        raise
                    self.journal.checkpoint(request_id, {**locator, 'phase': 'moved', 'effect_state': 'moved'})
                    try:
                        os.fsync(source)
                        os.fsync(target)
                    except OSError as error:
                        raise WorkbenchError('move_durability_unknown', 'The file moved, but syncing its directories failed.',
                                             **locator, effect_state='moved', durability='unknown') from error
            observed = self.files.read_file(destination_workspace, destination, max_bytes=1)
            return {'ok': True, **locator, 'effect_state': 'moved', 'durability': 'confirmed', 'no_replace': True,
                    'content_verified': observed['revision_sha256'] == expected_sha256,
                    'external_writer_atomic_cas': False, 'metadata_policy': 'Same-volume rename preserves the moved inode; verify current metadata with stat.'}
        return self.journal.run(request_id, {'tool': 'filesystem_move', 'workspace': workspace, 'path': path,
            'destination_workspace': destination_workspace, 'destination': destination, 'expected_sha256': expected_sha256}, move,
            resource='filesystem:' + workspace)

    def trash(self, workspace, path, expected_sha256, request_id):
        self.files._writable(workspace)
        self.files._parts(path)
        self.files._revision(expected_sha256)
        if expected_sha256 is None:
            raise WorkbenchError('revision_required', 'Trash requires the exact source revision.')
        def trash():
            before = self.files.read_file(workspace, path, max_bytes=1)
            if before['revision_sha256'] != expected_sha256:
                raise WorkbenchError('revision_conflict', 'The source changed before Trash preparation.', effect_state='none')
            directory = '.workbench-trash-' + uuid.uuid4().hex
            self.journal.checkpoint(request_id, {'workspace': workspace, 'source_path': path,
                'trash_directory': directory, 'phase': 'before_owned_trash_creation', 'effect_state': 'none'})
            self.files.make_directory(workspace, directory, self.child(request_id, 'directory'))
            destination = directory + '/item'
            self.journal.checkpoint(request_id, {'workspace': workspace, 'source_path': path,
                'trash_path': destination, 'phase': 'before_trash_move', 'effect_state': 'source_untouched'})
            receipt = self.move(workspace, path, workspace, destination, expected_sha256, self.child(request_id, 'move'))
            return {**receipt, 'trash_path': destination, 'content_deleted': False,
                    'restore': 'Move this exact revision back to the original path with filesystem_operation; an occupied destination is refused.',
                    'trash_kind': 'Recoverable managed workspace storage, separate from Finder Trash.'}
        return self.journal.run(request_id, {'tool': 'filesystem_trash', 'workspace': workspace, 'path': path,
                                            'expected_sha256': expected_sha256}, trash)
