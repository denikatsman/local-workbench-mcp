"""Private workspace snapshots for selected-browser upload; no automatic pruning."""
import contextlib
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
import uuid

from .browser_wire import read_private_json
from .errors import WorkbenchError
from .files import FileTools, _same_file
from .persistence import atomic_json

_KEY = object()
CONTENT_LIMIT = 1024 * 1024
CONTENT_CHUNK = 32768
_BINDING = ('owner_session', 'runtime_generation', 'installation_id', 'claim_id',
            'claim_epoch', 'target_generation', 'browser_target_id', 'expected_origin',
            'expected_generation', 'observation_id', 'target_id', 'peer_id', 'trust_id')


class _Authority:
    def __init__(self, key, stage_id, binding, operation_id, expires):
        if key is not _KEY:
            raise WorkbenchError('upload_authority_invalid', 'Upload authority is host-created.')
        self.stage_id, self.binding = stage_id, dict(binding)
        self.operation_id, self.expires = operation_id, expires
        self.transport = None
        self.carrier = 'native_path'
        self.worker_generation = None
        self.content_offset = 0
        self.content_node = None
        self.content_complete = False


class BrowserUploads:
    def __init__(self, config, store, journal, clock=time.time):
        self.config, self.store, self.journal, self.clock = config, store, journal, clock
        self.files = FileTools(config, store, journal)
        self.root = config.state_dir / 'browser-upload-stages'
        self.records = config.state_dir / 'browser-upload-records'
        for directory in (self.root, self.records):
            if directory.is_symlink():
                raise WorkbenchError('upload_storage_changed', 'Upload storage may not be a symlink.')
            directory.mkdir(mode=0o700, exist_ok=True)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.lock, self.authorities = threading.RLock(), {}

    def close(self):
        with self.lock:
            if self.root_fd is None: return
            self.files.close()
            os.close(self.root_fd)
            self.root_fd = None

    @staticmethod
    def validate(path, digest, count, limit):
        FileTools._parts(path)
        if (not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None
                or type(count) is not int or not 0 <= count <= limit):
            raise WorkbenchError('invalid_upload_file', 'Use an exact SHA256 and configured bounded byte count.', effect_state='none')

    @staticmethod
    def signature(info):
        return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    def _root_check(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            a, b = os.fstat(fd), os.fstat(self.root_fd)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise WorkbenchError('upload_storage_changed', 'Upload storage identity changed.', effect_state='none')
        finally:
            os.close(fd)

    def _read_record(self, stage_id):
        if not isinstance(stage_id, str) or not re.fullmatch(r'[0-9a-f]{32}', stage_id):
            raise WorkbenchError('invalid_upload_stage', 'Use the retained exact upload stage.', effect_state='none')
        row = read_private_json(self.records / (stage_id + '.json'))
        if row.get('stage_id') != stage_id or len(FileTools._parts(row.get('filename'))) != 1:
            raise WorkbenchError('upload_storage_changed', 'Upload stage metadata is invalid.', effect_state='none')
        return row

    def descriptor(self, row):
        return {key: row[key] for key in ('stage_id', 'operation_id', 'workspace', 'file_path',
            'workspace_root', 'root_identity', 'filename', 'bytes', 'sha256', 'state', 'created_at')} | {
                'retained': row['state'] != 'cleaned', 'cleanup_required': row['state'] != 'cleaned',
                'retention': 'explicit cleanup; delayed browser use may need these bytes',
                'potentially_sensitive': True}

    def _verify_source(self, row):
        self.files._check_root(row['workspace'])
        with self.files._regular(row['workspace'], row['file_path']) as (stream, before):
            if self.signature(before) != row['source_signature']:
                raise WorkbenchError('upload_source_changed', 'Source file identity or metadata changed.', effect_state='none')
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if not _same_file(before, os.fstat(stream.fileno())) or digest != row['sha256']:
                raise WorkbenchError('upload_source_changed', 'Source bytes changed.', effect_state='none')
        self.files._check_root(row['workspace'])

    @contextlib.contextmanager
    def _stage(self, row):
        self._root_check()
        directory = os.open(row['stage_id'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.root_fd)
        try:
            info = os.fstat(directory)
            if [info.st_dev, info.st_ino] != row['stage_directory_identity']:
                raise WorkbenchError('upload_stage_changed', 'Stage directory identity changed.', effect_state='none')
            fd = os.open(row['filename'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or stat.S_IMODE(before.st_mode) != 0o400 or self.signature(before) != row['stage_signature']):
                    raise WorkbenchError('upload_stage_changed', 'Stage file identity or mode changed.', effect_state='none')
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != row['sha256'] or not _same_file(before, os.fstat(fd)):
                        raise WorkbenchError('upload_stage_changed', 'Stage bytes changed.', effect_state='none')
                yield directory
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def prepare(self, workspace, path, digest, count, binding, operation_id, *, carrier='native_path', worker_generation=None):
        # Internal opt-in only. Public upload continues to prepare native_path.
        if carrier not in ('native_path', 'supplied_content') or carrier == 'supplied_content' and (
                type(count) is not int or count > CONTENT_LIMIT or not isinstance(worker_generation, str)
                or re.fullmatch(r'[0-9a-f]{32}', worker_generation) is None):
            raise WorkbenchError('upload_content_unsupported', 'Content carrier requires bounded host admission.', effect_state='none')
        self.validate(path, digest, count, self.config.max_artifact_bytes)
        stage_id, token = uuid.uuid4().hex, secrets.token_hex(32)
        filename = FileTools._parts(path)[-1]
        with self.lock, self.store.locked():
            self._root_check()
            # Only live private stage directories consume the retention count.
            # Cleaned metadata remains audit history and is never scanned here.
            retained = 0
            with os.scandir(self.root_fd) as entries:
                for entry in entries:
                    if not entry.is_dir(follow_symlinks=False) or not re.fullmatch(r'[0-9a-f]{32}', entry.name):
                        raise WorkbenchError('upload_storage_changed', 'Unexpected upload storage entry.', effect_state='none')
                    retained += 1
                    if retained >= 1000:
                        raise WorkbenchError('upload_stage_limit', 'Explicitly clean retained upload stages.', effect_state='none')
            self.files._check_root(workspace)
            with contextlib.ExitStack() as source:
                try:
                    stream, before = source.enter_context(self.files._regular(workspace, path))
                except WorkbenchError as error:
                    cause = error.__cause__
                    if (error.code == 'filesystem_error' and isinstance(cause, PermissionError)
                            and cause.errno in (errno.EACCES, errno.EPERM)):
                        # Only source-context entry is covered: no stage or
                        # browser authority exists yet. Later errors keep their
                        # original cleanup/effect semantics and exception chain.
                        error.details.update(effect_state='none', phase='upload_source_open')
                    raise
                if before.st_size != count:
                    raise WorkbenchError('upload_source_changed', 'Source byte count changed.', effect_state='none')
                # Includes stage and metadata publication headroom; all stages
                # are under the existing store root and counted by storage_bytes.
                if self.store.storage_bytes() + count + 65536 > self.config.max_storage_bytes:
                    raise WorkbenchError('storage_limit', 'Upload stage exceeds configured storage quota.', effect_state='none')
                os.mkdir(stage_id, 0o700, dir_fd=self.root_fd)
                directory = os.open(stage_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.root_fd)
                temporary = '.copy-' + uuid.uuid4().hex
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    calculated, observed = hashlib.sha256(), 0
                    with os.fdopen(fd, 'wb') as output:
                        while chunk := stream.read(65536):
                            observed += len(chunk)
                            if observed > count:
                                raise WorkbenchError('upload_source_changed', 'Source grew during staging.', effect_state='none')
                            calculated.update(chunk); output.write(chunk)
                        output.flush(); os.fsync(output.fileno())
                    if (observed != count or calculated.hexdigest() != digest
                            or not _same_file(before, os.fstat(stream.fileno()))):
                        raise WorkbenchError('upload_source_changed', 'Source snapshot changed.', effect_state='none')
                    os.chmod(temporary, 0o400, dir_fd=directory, follow_symlinks=False)
                    os.rename(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory)
                    os.fsync(directory)
                    root_info = os.fstat(self.files._roots[workspace])
                    row = {'stage_id': stage_id, 'operation_id': operation_id, 'workspace': workspace,
                        'file_path': path, 'workspace_root': str(self.config.workspace(workspace).root),
                        'root_identity': [root_info.st_dev, root_info.st_ino], 'filename': filename,
                        'bytes': count, 'sha256': digest, 'source_signature': self.signature(before),
                        'stage_signature': self.signature(os.stat(filename, dir_fd=directory, follow_symlinks=False)),
                        'stage_directory_identity': [os.fstat(directory).st_dev, os.fstat(directory).st_ino],
                        'binding': {key: binding[key] for key in _BINDING},
                        'created_at': self.clock(), 'state': 'prepared'}
                    self._verify_source(row)
                    atomic_json(self.records / (stage_id + '.json'), row)
                except BaseException:
                    for leaf in (temporary, filename):
                        with contextlib.suppress(FileNotFoundError): os.unlink(leaf, dir_fd=directory)
                    os.rmdir(stage_id, dir_fd=self.root_fd)
                    raise
                finally:
                    os.close(directory)
            permit = _Authority(_KEY, stage_id, binding, operation_id, self.clock() + 30)
            permit.carrier, permit.worker_generation = carrier, worker_generation
            self.authorities[token] = permit
            return {'stage_id': stage_id, 'token': token, 'expires_at': permit.expires,
                    'binding': dict(permit.binding), 'file': self.descriptor(row),
                    **({'carrier': carrier, 'worker_generation': worker_generation,
                        'chunk_bytes': CONTENT_CHUNK} if carrier == 'supplied_content' else {})}

    def bind_transport(self, token, transport, peer_id):
        with self.lock:
            permit = self.authorities.get(token)
            if not permit or permit.binding['peer_id'] != peer_id:
                raise WorkbenchError('upload_authority_invalid', 'The upload authority changed.', effect_state='none')
            permit.transport = transport

    def _content_permit(self, token, transport, binding, node_id, worker_generation, validate):
        permit = self.authorities.get(token)
        if (not permit or permit.carrier != 'supplied_content' or permit.transport != transport
                or self.clock() >= permit.expires or permit.worker_generation != worker_generation
                or any(binding.get(key) != permit.binding[key] for key in _BINDING)
                or type(node_id) is not int or node_id <= 0
                or permit.content_node not in (None, node_id)):
            raise WorkbenchError('upload_authority_invalid', 'The exact content authority is unavailable.', effect_state='none')
        validate()
        return permit

    def read_content(self, token, transport, binding, node_id, offset, worker_generation, validate):
        """One bounded sequential private read; never a path or page admission."""
        with self.lock:
            permit = self._content_permit(token, transport, binding, node_id, worker_generation, validate)
            if type(offset) is not int or offset != permit.content_offset or permit.content_complete:
                raise WorkbenchError('upload_content_sequence', 'Use the exact next content offset once.', effect_state='none')
            active = sum(p.carrier == 'supplied_content' and p.content_node is not None
                         and self.clock() < p.expires for p in self.authorities.values())
            if permit.content_node is None and active >= 4:
                raise WorkbenchError('browser_upload_pending', 'Content transfer capacity is occupied.', effect_state='none')
            row = self._read_record(permit.stage_id)
            if row['bytes'] > CONTENT_LIMIT or not 0 <= offset <= row['bytes']:
                raise WorkbenchError('upload_content_sequence', 'Content size or offset is invalid.', effect_state='none')
            self._verify_source(row)
            with self._stage(row) as directory:
                fd = os.open(row['filename'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    before = os.fstat(fd)
                    if self.signature(before) != row['stage_signature']:
                        raise WorkbenchError('upload_stage_changed', 'Stage identity changed.', effect_state='none')
                    os.lseek(fd, offset, os.SEEK_SET)
                    raw = os.read(fd, min(CONTENT_CHUNK, row['bytes'] - offset))
                    if len(raw) != min(CONTENT_CHUNK, row['bytes'] - offset) or not _same_file(before, os.fstat(fd)):
                        raise WorkbenchError('upload_stage_changed', 'Stage changed during content read.', effect_state='none')
                finally:
                    os.close(fd)
                self._content_permit(token, transport, binding, node_id, worker_generation, validate)
                permit.content_node, permit.content_offset = node_id, offset + len(raw)
                permit.content_complete = permit.content_offset == row['bytes']
                return {'stage_id': row['stage_id'], 'offset': offset, 'next_offset': permit.content_offset,
                        'eof': permit.content_complete, 'data_base64': base64.b64encode(raw).decode('ascii'),
                        'bytes': row['bytes'], 'sha256': row['sha256']}

    def consume(self, token, transport, binding, node_id, validate, *, carrier='native_path', worker_generation=None):
        with self.lock:
            candidate = self.authorities.get(token)
            if not candidate or candidate.carrier != carrier:
                raise WorkbenchError('upload_authority_invalid', 'Upload carrier does not match admission.', effect_state='none')
            if carrier == 'supplied_content':
                permit = self._content_permit(token, transport, binding, node_id, worker_generation, validate)
                if not permit.content_complete or permit.content_node != node_id:
                    raise WorkbenchError('upload_content_incomplete', 'Content must be fully verified before admission.', effect_state='none')
                row = self._read_record(permit.stage_id)
                self._verify_source(row)
                with self._stage(row):
                    self._content_permit(token, transport, binding, node_id, worker_generation, validate)
                    self.authorities.pop(token)
                    row.update(state='consumed', authority_consumed=True, carrier=carrier,
                               consumed_at=self.clock(), input_backend_node_id=node_id)
                    atomic_json(self.records / (row['stage_id'] + '.json'), row)
                    self.journal.checkpoint(permit.operation_id, {'phase': 'before_content_file_input_send',
                        'upload_stage': self.descriptor(row), 'effect_state': 'unknown'})
                    return {'stage_id': row['stage_id'], 'carrier': carrier, 'worker_generation': worker_generation,
                            'filename': row['filename'], 'bytes': row['bytes'], 'sha256': row['sha256']}
            permit = self.authorities.pop(token, None)
            if (not permit or permit.transport != transport or self.clock() >= permit.expires
                    or any(binding.get(key) != permit.binding[key] for key in _BINDING)
                    or type(node_id) is not int or node_id <= 0):
                raise WorkbenchError('upload_authority_invalid', 'The exact upload authority is unavailable or consumed.', effect_state='none')
            validate()
            row = self._read_record(permit.stage_id)
            self._verify_source(row)
            with self._stage(row):
                validate()
                if self.clock() >= permit.expires:
                    raise WorkbenchError('upload_authority_expired', 'Upload authority expired during validation.', effect_state='none')
                row.update(state='consumed', authority_consumed=True, consumed_at=self.clock(), input_backend_node_id=node_id)
                atomic_json(self.records / (row['stage_id'] + '.json'), row)
                self.journal.checkpoint(permit.operation_id, {'phase': 'before_file_input_send',
                    'upload_stage': self.descriptor(row), 'effect_state': 'unknown'})
                return {'stage_id': row['stage_id'], 'files': [str(self.root / row['stage_id'] / row['filename'])],
                        'filename': row['filename'], 'bytes': row['bytes'], 'sha256': row['sha256']}

    def record(self, stage_id):
        with self.lock:
            return self._read_record(stage_id)

    def outcome(self, stage_id, state):
        with self.lock:
            row = self._read_record(stage_id)
            if row['state'] != 'cleaned':
                row['state'] = state
                atomic_json(self.records / (stage_id + '.json'), row)
            for token, permit in list(self.authorities.items()):
                if permit.stage_id == stage_id and permit.carrier == 'supplied_content':
                    self.authorities.pop(token)
            return self.descriptor(row)

    def cleanup(self, stage_id, owner_binding, proof):
        with self.lock, self.store.locked():
            row = self._read_record(stage_id)
            keys = ('owner_session', 'runtime_generation', 'installation_id', 'claim_id', 'target_generation', 'browser_target_id')
            if any(owner_binding.get(key) != row['binding'][key] for key in keys):
                raise WorkbenchError('upload_cleanup_owner_mismatch', 'The stage belongs to a different exact claim.', effect_state='none')
            if proof.get('stage_id') != row['stage_id']:
                raise WorkbenchError('upload_cleanup_unverified', 'The cleanup proof names another stage.', effect_state='none')
            if proof.get('condition') == 'input_cleared':
                if (proof.get('empty') is not True or proof.get('input_backend_node_id') != row.get('input_backend_node_id')
                        or owner_binding.get('claim_epoch') != row['binding']['claim_epoch']
                        or owner_binding.get('expected_origin') != row['binding']['expected_origin']
                        or owner_binding.get('expected_generation') != row['binding']['expected_generation']):
                    raise WorkbenchError('upload_cleanup_unverified', 'The original input is not verified cleared.', effect_state='none')
            elif proof.get('condition') != 'terminal_claim':
                raise WorkbenchError('upload_cleanup_unverified', 'Keep the stage until explicit verified cleanup.', effect_state='none')
            if row['state'] == 'cleaned':
                return {'ok': True, 'upload_stage': self.descriptor(row), 'already_cleaned': True}
            with self._stage(row) as directory:
                os.unlink(row['filename'], dir_fd=directory)
            os.rmdir(stage_id, dir_fd=self.root_fd)
            row.update(state='cleaned', cleaned_at=self.clock(), cleanup_condition=proof['condition'])
            atomic_json(self.records / (stage_id + '.json'), row)
            for token, permit in list(self.authorities.items()):
                if permit.stage_id == stage_id: self.authorities.pop(token)
            return {'ok': True, 'upload_stage': self.descriptor(row), 'released_bytes': row['bytes'],
                    'browser_input_modified': False, 'effect_state': 'applied', 'task_completion': 'not_established'}
