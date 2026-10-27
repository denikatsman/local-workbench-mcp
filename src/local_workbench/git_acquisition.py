"""Owned Git acquisition with phase evidence and atomic no-replace publication."""
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import time
import uuid
from urllib.parse import urlsplit

from .context import work_context
from .errors import WorkbenchError
from .persistence import rename_exclusive
from .runtime import DEFAULT_PATH


class GitAcquisition:
    PHASES = ('runtime', 'transport', 'identity', 'scope', 'configuration', 'refs', 'integrity', 'tree', 'checkout')

    def __init__(self, files, jobs):
        self.files, self.jobs, self.config, self.store, self.journal = files, jobs, files.config, files.store, files.journal
        self.path = self.config.state_dir / 'git-acquisitions.sqlite3'
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS acquisitions(id TEXT PRIMARY KEY,payload TEXT NOT NULL)')

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute('PRAGMA synchronous=FULL')
            with db: yield db

    def save(self, record):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO acquisitions VALUES (?,?)', (record['acquisition_id'], json.dumps(record)))

    def load(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier):
            raise WorkbenchError('invalid_acquisition', 'Use an acquisition ID returned by this profile.')
        with self.db() as db: row = db.execute('SELECT payload FROM acquisitions WHERE id=?', (identifier,)).fetchone()
        if row is None: raise WorkbenchError('unknown_acquisition', 'No acquisition has this ID.')
        record = json.loads(row[0])
        if work_context.get() is not None and work_context.get() != record['work_session_id']:
            raise WorkbenchError('work_session_mismatch', 'Use this acquisition\'s recorded work context.')
        return record

    def active_ids(self, session_id=None):
        with self.db() as db: records = [json.loads(row[0]) for row in db.execute('SELECT payload FROM acquisitions')]
        return [row['acquisition_id'] for row in records if row['state'] not in ('published', 'released')
                and (session_id is None or row['work_session_id'] == session_id)]

    @staticmethod
    def source(url):
        if not isinstance(url, str) or not 1 <= len(url.encode()) <= 8192 or '\0' in url or '\n' in url or '\r' in url or url.startswith('-'):
            raise WorkbenchError('invalid_git_source', 'Use a bounded literal repository source.')
        parsed = urlsplit(url)
        if parsed.scheme in ('https', 'ssh'):
            if not parsed.hostname or parsed.password or parsed.query or parsed.fragment or parsed.scheme == 'https' and parsed.username:
                raise WorkbenchError('git_source_credentials', 'Use a repository URL without embedded credentials, query or fragment; configure transport authentication separately.')
            return {'url': url, 'transport': parsed.scheme}
        if parsed.scheme == 'file':
            if parsed.netloc not in ('', 'localhost') or parsed.query or parsed.fragment:
                raise WorkbenchError('invalid_git_source', 'Use an explicit local file URI.')
            return {'url': url, 'transport': 'file_git_protocol'}
        if url.startswith('/'):
            return {'url': str(Path(url).resolve(strict=True)), 'transport': 'local_git_protocol'}
        if re.fullmatch(r'[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+', url):
            return {'url': url, 'transport': 'ssh_scp'}
        raise WorkbenchError('unsupported_git_transport', 'Supported acquisition transports are HTTPS, SSH and explicitly selected local repositories.')

    @staticmethod
    def child(identifier, phase):
        return 'git-acquire:' + hashlib.sha256((identifier + ':' + phase).encode()).hexdigest()

    def _environment(self):
        return {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
                'GIT_LFS_SKIP_SMUDGE': '1', 'GIT_OPTIONAL_LOCKS': '0',
                'GIT_SSH_COMMAND': '/usr/bin/ssh -o BatchMode=yes -o StrictHostKeyChecking=yes'}

    def _arguments(self, record, args):
        return [record['git'], '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false',
                '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.process=', '-c', 'filter.lfs.required=false', *args]

    def _owned(self, record):
        with self.files._parent(record['workspace'], record['stage']) as (parent, name):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or [info.st_dev, info.st_ino] != record['stage_identity']:
                raise WorkbenchError('acquisition_stage_changed', 'The owned acquisition stage was replaced.')
        with self.files._regular(record['workspace'], record['stage'] + '/.workbench-owner.json') as (source, _):
            raw = source.read(4097)
        if hashlib.sha256(raw).hexdigest() != record['marker_sha256']:
            raise WorkbenchError('acquisition_stage_changed', 'The acquisition ownership marker changed.')

    def _launch(self, record, phase):
        self._owned(record)
        request = self.child(record['acquisition_id'], phase)
        if phase == 'runtime':
            args, cwd = ['--version'], record['stage']
        elif phase == 'transport':
            args = ['clone', '--no-checkout', '--no-local', '--no-hardlinks', '--template=' + str(self.config.workspace(record['workspace']).root / record['stage'] / 'empty-template')]
            if record['ref'] is not None: args += ['--branch', record['ref']]
            if record['depth'] is not None: args += ['--depth', str(record['depth']), '--single-branch']
            if record['filter'] is not None: args += ['--filter=' + record['filter']]
            args += ['--', record['source']['url'], 'repository']
            cwd = record['stage']
        else:
            cwd = record['repository']
            if phase == 'identity': args = ['show', '-s', '--format=%H%n%T', 'HEAD', '--']
            elif phase == 'scope': args = ['rev-parse', '--is-shallow-repository', '--show-object-format=storage']
            elif phase == 'configuration': args = ['config', '--local', '--null', '--get-regexp', r'^remote\.origin\.(url|fetch|promisor|partialclonefilter)$']
            elif phase == 'refs': args = ['for-each-ref', '--format=%(refname) %(objectname)']
            elif phase == 'integrity': args = ['fsck', '--full', '--strict']
            elif phase == 'tree': args = ['ls-tree', '-rz', '--full-tree', record['commit']]
            elif phase == 'checkout': args = ['checkout', '--detach', '--force', record['commit']]
            else: raise WorkbenchError('invalid_git_phase', 'Unsupported acquisition phase.')
        phase_record = {'state': 'launch_unknown', 'request_id': request, 'argv': self._arguments(record, args), 'cwd': cwd}
        record['phases'][phase] = phase_record; self.save(record)
        job = self.jobs.start(record['workspace'], phase_record['argv'], request, cwd=cwd,
            env=self._environment(), timeout_seconds=record['timeout_seconds'], output_stop_after_bytes=16777216)
        phase_record.update(state='running', job_id=job['job_id']); self.save(record)

    def start(self, workspace, url, destination, request_id, expected_commit=None, ref=None, depth=None, filter=None, timeout_seconds=300):
        self.files._writable(workspace)
        if not self.config.workspace(workspace).executable: raise WorkbenchError('execution_denied', 'Git acquisition requires execute authority.')
        source = self.source(url)
        destination = '/'.join(self.files._parts(destination))
        if expected_commit is not None and (not isinstance(expected_commit, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', expected_commit)):
            raise WorkbenchError('invalid_git_revision', 'Pin a full 40/64-character lowercase commit ID.')
        if ref is not None and (not isinstance(ref, str) or not ref or len(ref.encode()) > 1024 or ref.startswith('-') or any(char in ref for char in ('\0', '\n', '\r'))):
            raise WorkbenchError('invalid_git_ref', 'Use a bounded literal branch or tag name.')
        if depth is not None and (type(depth) is not int or not 1 <= depth <= 100000):
            raise WorkbenchError('invalid_git_depth', 'Use depth 1..100000 or full available history.')
        if filter is not None and (not isinstance(filter, str) or not re.fullmatch(r'blob:none|blob:limit=[0-9]+|tree:[0-9]+', filter)):
            raise WorkbenchError('invalid_git_filter', 'Use an explicit supported object filter.')
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
            raise WorkbenchError('invalid_git_timeout', 'Use timeout_seconds 1..3600.')
        git = shutil.which('git', path=DEFAULT_PATH)
        if git is None: raise WorkbenchError('git_unavailable', 'Install/select Git before acquisition.')
        def prepare():
            identifier = uuid.uuid4().hex
            with self.files._parent(workspace, destination) as (parent, name):
                parent_info = os.fstat(parent)
                try: os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: pass
                else: raise WorkbenchError('acquisition_destination_exists', 'An occupied destination was preserved; select an absent path.')
                stage_name = '.workbench-acquire-' + identifier
                stage = '/'.join([*destination.split('/')[:-1], stage_name])
                marker = json.dumps({'acquisition_id': identifier, 'schema_version': 1}, sort_keys=True).encode()
                record = {'acquisition_id': identifier, 'workspace': workspace, 'work_session_id': work_context.get(),
                    'source': source, 'destination': destination, 'stage': stage, 'repository': stage + '/repository',
                    'destination_parent': [parent_info.st_dev, parent_info.st_ino], 'state': 'preparing', 'phases': {},
                    'expected_commit': expected_commit, 'ref': ref, 'depth': depth, 'filter': filter, 'timeout_seconds': timeout_seconds,
                    'git': git, 'created_at': time.time(), 'submodule_policy': 'record_gitlinks_without_fetch',
                    'lfs_policy': 'retain_and_report_pointers_without_claiming_external_content',
                    'metadata_policy': 'Git file modes/link payloads; no ACL/xattr/hardlink identity restoration claim'}
                self.journal.checkpoint(request_id, {'acquisition_id': identifier, 'stage': stage, 'phase': 'before_stage_creation', 'effect_state': 'none'})
                os.mkdir(stage_name, 0o700, dir_fd=parent)
                directory = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(directory); record['stage_identity'] = [info.st_dev, info.st_ino]
                    fd = os.open('.workbench-owner.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    with os.fdopen(fd, 'wb') as output: output.write(marker); output.flush(); os.fsync(output.fileno())
                    os.mkdir('empty-template', 0o700, dir_fd=directory); os.fsync(directory); os.fsync(parent)
                finally: os.close(directory)
                record['marker_sha256'] = hashlib.sha256(marker).hexdigest()
                record['state'] = 'acquiring'; self.save(record)
            self.journal.checkpoint(request_id, {'acquisition_id': identifier, 'stage': stage, 'phase': 'before_transport', 'effect_state': 'stage_created'})
            self._launch(record, 'runtime')
            return {'ok': True, 'acquisition_id': identifier, 'stage': stage, 'phase': 'runtime',
                    'job_id': record['phases']['runtime']['job_id'], 'destination_modified': False}
        return self.journal.run(request_id, {'tool': 'git_acquire_start', 'workspace': workspace, 'source': source,
            'destination': destination, 'expected_commit': expected_commit, 'ref': ref, 'depth': depth, 'filter': filter,
            'timeout_seconds': timeout_seconds}, prepare,
            resource='git-destination:' + workspace + ':' + destination.casefold())

    def _output(self, phase):
        evidence = self.jobs.evidence(phase['job_id'])
        artifact = evidence.get('artifacts', {}).get('stdout')
        if not artifact: raise WorkbenchError('git_output_unavailable', 'The phase\'s complete original output is unavailable.')
        identifier = artifact['artifact_id'] if isinstance(artifact, dict) else artifact
        with self.store.reading(identifier) as source: raw = source.read(16777217)
        if len(raw) > 16777216: raise WorkbenchError('git_output_limit', 'Phase output exceeded the declared structured-processing budget.')
        phase['output_artifacts'] = evidence['artifacts']
        return raw

    def inspect(self, identifier):
        record = self.load(identifier)
        for phase in record['phases'].values():
            if phase.get('job_id'): phase['job'] = self.jobs.status(phase['job_id'], detail=False)
        return {'ok': True, **record, 'inspection_performed_no_effects': True,
                'scope': 'Transport, identity, available-object integrity and worktree phases are distinct. Git fsck is not publisher authentication.'}

    def advance(self, identifier, request_id, wait_ms=0):
        if type(wait_ms) is not int or not 0 <= wait_ms <= 10000: raise WorkbenchError('invalid_wait', 'Use wait_ms 0..10000.')
        def advance():
            record = self.load(identifier); self._owned(record)
            if record['state'] != 'acquiring': return {'ok': True, **record}
            for phase_name in self.PHASES:
                phase = record['phases'].get(phase_name)
                if phase is None:
                    self._launch(record, phase_name)
                    return {'ok': True, 'acquisition_id': identifier, 'phase': phase_name, 'job_id': record['phases'][phase_name]['job_id']}
                if not phase.get('job_id'):
                    receipt = self.journal.status(phase['request_id'])
                    if receipt['state'] == 'completed' and isinstance(receipt.get('result'), dict) and receipt['result'].get('job_id'):
                        phase['job_id'] = receipt['result']['job_id']; self.save(record)
                    else: raise WorkbenchError('git_launch_uncertain', 'Inspect the original phase request before another launch.', acquisition_id=identifier, phase_request_id=phase['request_id'])
                self.jobs.wait_terminal(phase['job_id'], wait_ms)
                job = self.jobs.status(phase['job_id'], detail=False)
                if job['status'] in ('starting', 'running'):
                    return {'ok': True, 'acquisition_id': identifier, 'phase': phase_name, 'job_id': phase['job_id'], 'waiting': True}
                if phase['state'] == 'verified': continue
                if job.get('exit_code') != 0 or not job.get('output_complete'):
                    phase.update(state='failed', outcome=job); record['state'] = 'failed'; self.save(record)
                    return {'ok': True, 'acquisition_id': identifier, 'state': 'failed', 'failed_phase': phase_name, 'job': job, 'destination_modified': False}
                raw = self._output(phase)
                if phase_name == 'runtime':
                    value = raw.decode('utf-8').strip()
                    if not value.startswith('git version '): raise WorkbenchError('git_runtime_identity', 'The Git runtime did not report its version.')
                    record['git_version'] = value
                elif phase_name == 'identity':
                    lines = raw.decode('ascii').splitlines()
                    if len(lines) != 2 or any(not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', line) for line in lines):
                        raise WorkbenchError('git_identity_invalid', 'Git did not return exact commit/tree IDs.')
                    record['commit'], record['tree'] = lines
                    if record['expected_commit'] and record['commit'] != record['expected_commit']:
                        record['state'] = 'revision_mismatch'; self.save(record)
                        raise WorkbenchError('git_revision_mismatch', 'The acquired commit differs from its required pin; no destination was published.', acquisition_id=identifier)
                elif phase_name == 'scope':
                    lines = raw.decode('ascii').splitlines()
                    if len(lines) != 2 or lines[0] not in ('true', 'false') or lines[1] not in ('sha1', 'sha256'):
                        raise WorkbenchError('git_scope_invalid', 'Git did not return its observed shallow/object-format scope.')
                    record['observed_scope'] = {'shallow': lines[0] == 'true', 'object_format': lines[1],
                        'requested_filter': record['filter'], 'history_scope': 'reachable fetched history; not all remote history attested'}
                elif phase_name == 'refs':
                    refs = []
                    for line in raw.decode('utf-8').splitlines():
                        name, oid = line.rsplit(' ', 1)
                        if not name.startswith('refs/') or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', oid):
                            raise WorkbenchError('git_refs_invalid', 'Git reference evidence is malformed.')
                        if len(refs) >= 10000: raise WorkbenchError('git_refs_limit', 'The reference listing exceeds 10000 entries.')
                        refs.append({'ref': name, 'oid': oid})
                    record['fetched_refs'] = refs
                elif phase_name == 'configuration':
                    remote = {}
                    for item in raw.split(b'\0'):
                        if not item: continue
                        key, value = item.split(b'\n', 1)
                        remote.setdefault(key.decode('utf-8'), []).append(value.decode('utf-8'))
                    record['remote_configuration'] = remote
                    record['observed_scope']['promisor'] = remote.get('remote.origin.promisor') == ['true']
                    record['observed_scope']['configured_filter'] = (remote.get('remote.origin.partialclonefilter') or [None])[0]
                elif phase_name == 'tree':
                    entries = []
                    for part in raw.split(b'\0'):
                        if not part: continue
                        header, path = part.split(b'\t', 1); mode, kind, oid = header.decode('ascii').split(' ')
                        try: decoded = path.decode('utf-8', errors='strict')
                        except UnicodeError as error:
                            raise WorkbenchError('git_path_encoding', 'A tracked filename is not UTF-8; original ls-tree bytes remain available.') from error
                        self.files._parts(decoded)
                        if len(entries) >= 10000: raise WorkbenchError('git_tree_limit', 'Acquisition verification supports up to 10000 tracked entries.')
                        entries.append({'path': decoded, 'mode': mode, 'kind': kind, 'oid': oid})
                    record['entries'] = entries
                phase.update(state='verified', observed_at=time.time(), exit_code=0); self.save(record)
            manifest = self._verify_worktree(record)
            record.update(state='ready', worktree_manifest=manifest, git_metadata=self._git_metadata(record), verified_at=time.time()); self.save(record)
            return {'ok': True, 'acquisition_id': identifier, 'state': 'ready', 'commit': record['commit'], 'tree': record['tree'],
                    'verification': manifest, 'destination_modified': False}
        return self.journal.run(request_id, {'tool': 'git_acquire_advance', 'acquisition_id': identifier, 'wait_ms': wait_ms}, advance,
                                resource='git-acquisition:' + identifier)

    def release(self, identifier, request_id):
        def release():
            record = self.load(identifier)
            if any(self.jobs.status(p['job_id'], detail=False)['status'] in ('starting', 'running') for p in record['phases'].values() if p.get('job_id')):
                raise WorkbenchError('acquisition_busy', 'Finish or cancel owned phase jobs before releasing the acquisition.')
            record['state'] = 'released'; record['released_at'] = time.time(); self.save(record)
            return {'ok': True, 'acquisition_id': identifier, 'released': True, 'files_modified': False,
                    'retained_stage': record['stage'], 'history_preserved': True}
        return self.journal.run(request_id, {'tool': 'git_acquire_release', 'acquisition_id': identifier}, release,
                                resource='git-acquisition:' + identifier)

    def _verify_worktree(self, record):
        total, deadline, files, gitlinks, lfs = 0, time.monotonic() + 10, [], [], []
        algorithm = 'sha256' if len(record['commit']) == 64 else 'sha1'
        for entry in record['entries']:
            path = record['repository'] + '/' + entry['path']
            if entry['mode'] == '160000': gitlinks.append(entry); continue
            if time.monotonic() >= deadline: raise WorkbenchError('git_worktree_limit', 'Worktree verification exceeded ten seconds.')
            with self.files._parent(record['workspace'], path) as (parent, name):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if entry['mode'] == '120000':
                    if not stat.S_ISLNK(info.st_mode): raise WorkbenchError('git_worktree_changed', 'A Git symlink changed type.')
                    raw = os.fsencode(os.readlink(name, dir_fd=parent)); size = len(raw)
                    digest = hashlib.new(algorithm, b'blob ' + str(size).encode() + b'\0' + raw).hexdigest()
                else:
                    if not stat.S_ISREG(info.st_mode): raise WorkbenchError('git_worktree_changed', 'A tracked regular file changed type.')
                    size = info.st_size; total += size
                    if total > 536870912: raise WorkbenchError('git_worktree_limit', 'Worktree verification exceeded 512 MiB.')
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    with os.fdopen(fd, 'rb') as source:
                        digest_object = hashlib.new(algorithm, b'blob ' + str(size).encode() + b'\0')
                        preview = b''
                        while chunk := source.read(1048576):
                            if time.monotonic() >= deadline: raise WorkbenchError('git_worktree_limit', 'Worktree verification exceeded its deadline.')
                            digest_object.update(chunk)
                            if len(preview) < 1024: preview += chunk[:1024 - len(preview)]
                        after = os.fstat(source.fileno())
                    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise WorkbenchError('git_worktree_changed', 'A tracked file changed during verification.')
                    digest = digest_object.hexdigest()
                    executable = bool(info.st_mode & 0o111)
                    if executable != (entry['mode'] == '100755'): raise WorkbenchError('git_worktree_mode', 'The tracked executable-bit policy does not match checkout.')
                    if preview.startswith(b'version https://git-lfs.github.com/spec/v1\n'):
                        match = re.search(rb'oid sha256:([0-9a-f]{64})\nsize ([0-9]+)', preview)
                        if match: lfs.append({'path': entry['path'], 'oid_sha256': match[1].decode(), 'declared_bytes': int(match[2]), 'external_content_verified': False})
                if digest != entry['oid']: raise WorkbenchError('git_worktree_integrity', 'A checked-out file/link does not match its Git blob.')
                files.append({'path': entry['path'], 'oid': digest, 'mode': entry['mode'], 'bytes': size,
                    'identity': [info.st_dev, info.st_ino], 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns})
        return {'verified_files': files, 'tracked_bytes': total, 'gitlinks_not_fetched': gitlinks, 'lfs_pointers': lfs,
                'symlinks_followed': False, 'external_lfs_content_verified': False,
                'scope': 'Tracked checkout bytes/link payloads and Git executable bits; no ACL/xattr or publisher-authentication claim.'}

    def _git_metadata(self, record):
        result, total, deadline = {}, 0, time.monotonic() + 10
        root = record['repository'] + '/.git'
        for item in self.files._walk(record['workspace'], root, recursive=True):
            if len(result) >= 10000 or time.monotonic() >= deadline:
                raise WorkbenchError('git_metadata_limit', 'Git metadata verification exceeded 10000 entries or ten seconds.')
            if item['type'] == 'error': raise WorkbenchError('git_metadata_unavailable', 'Git metadata could not be checked completely.')
            with self.files._parent(record['workspace'], item['path']) as (parent, name):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            relative = item['path'][len(root) + 1:]
            if stat.S_ISDIR(info.st_mode):
                result[relative] = {'kind': 'directory', 'identity': [info.st_dev, info.st_ino]}
            elif stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256()
                with self.files._regular(record['workspace'], item['path']) as (source, before):
                    while chunk := source.read(1048576):
                        total += len(chunk)
                        if total > 536870912 or time.monotonic() >= deadline: raise WorkbenchError('git_metadata_limit', 'Git metadata exceeded 512 MiB or its deadline.')
                        digest.update(chunk)
                    after = os.fstat(source.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise WorkbenchError('git_metadata_changed', 'Git metadata changed during verification.')
                result[relative] = {'kind': 'file', 'identity': [info.st_dev, info.st_ino], 'sha256': digest.hexdigest(), 'bytes': info.st_size}
            else:
                raise WorkbenchError('git_metadata_type', 'Git metadata links/special files are not adopted.')
        return result

    def publish(self, identifier, request_id):
        def publish():
            record = self.load(identifier)
            if record['state'] == 'published': return {'ok': True, **record, 'applied_this_call': False}
            if record['state'] != 'ready': raise WorkbenchError('git_acquisition_not_ready', 'Every acquisition phase and checkout verification must complete before publication.')
            self._owned(record)
            current = self._verify_worktree(record)
            if current != record['worktree_manifest']: raise WorkbenchError('git_stage_changed', 'The verified acquisition worktree changed.')
            if self._git_metadata(record) != record['git_metadata']:
                raise WorkbenchError('git_metadata_changed', 'Verified repository metadata changed; no destination was published.')
            with self.files._parent(record['workspace'], record['destination']) as (target_parent, target_name):
                parent_info = os.fstat(target_parent)
                if [parent_info.st_dev, parent_info.st_ino] != record['destination_parent']:
                    raise WorkbenchError('git_destination_parent_changed', 'The chosen destination parent changed identity.')
                with self.files._parent(record['workspace'], record['repository']) as (source_parent, source_name):
                    source_info = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
                    record['published_directory_identity'] = [source_info.st_dev, source_info.st_ino]
                    self.journal.checkpoint(request_id, {'acquisition_id': identifier, 'destination': record['destination'],
                        'directory_identity': record['published_directory_identity'], 'phase': 'before_no_replace_publish', 'effect_state': 'unknown'})
                    record['publish_request_id'] = request_id; record['state'] = 'publication_unknown'; self.save(record)
                    try: rename_exclusive(source_parent, source_name, target_parent, target_name)
                    except OSError as error:
                        record['state'] = 'ready'; self.save(record)
                        if error.errno == errno.EEXIST:
                            raise WorkbenchError('acquisition_destination_exists', 'A newly occupied destination was preserved; the owned stage is retained.', effect_state='none') from error
                        raise
                    try: os.fsync(source_parent); os.fsync(target_parent)
                    except OSError as error:
                        raise WorkbenchError('git_publication_durability_unknown', 'The directory was published but directory syncing failed; inspect its recorded identity before any retry.',
                            acquisition_id=identifier, destination=record['destination'], effect_state='applied', durability='unknown') from error
            record['state'] = 'published'; record['published_at'] = time.time(); self.save(record)
            return {'ok': True, 'acquisition_id': identifier, 'destination': record['destination'], 'commit': record['commit'],
                    'tree': record['tree'], 'directory_identity': record['published_directory_identity'],
                    'effect_state': 'applied', 'applied_this_call': True, 'durability': 'directory_synced'}
        return self.journal.run(request_id, {'tool': 'git_acquire_publish', 'acquisition_id': identifier}, publish,
                                resource='git-acquisition:' + identifier)

    def reconcile(self, identifier, request_id):
        def reconcile():
            record = self.load(identifier)
            if record['state'] != 'publication_unknown':
                return {'ok': True, 'acquisition_id': identifier, 'state': record['state'], 'metadata_changed': False, 'files_modified': False}
            with self.files._parent(record['workspace'], record['destination']) as (parent, name):
                try: info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return {'ok': True, 'acquisition_id': identifier, 'state': 'unknown', 'files_modified': False,
                            'reason': 'Expected publication was not found; the original receipt remains uncertain.'}
                if not stat.S_ISDIR(info.st_mode) or [info.st_dev, info.st_ino] != record['published_directory_identity']:
                    return {'ok': True, 'acquisition_id': identifier, 'state': 'unknown', 'files_modified': False,
                            'reason': 'The observed destination has another identity.'}
            observed = {**record, 'repository': record['destination']}
            manifest = self._verify_worktree(observed)
            if manifest != record['worktree_manifest']:
                raise WorkbenchError('git_published_content_changed', 'The published tracked contents changed; no corrective write was performed.')
            if self._git_metadata(observed) != record['git_metadata']:
                raise WorkbenchError('git_published_metadata_changed', 'Published Git metadata changed; no corrective write was performed.')
            record.update(state='published', reconciliation_request_id=request_id, durability='historical_sync_not_attested')
            self.save(record)
            return {'ok': True, 'acquisition_id': identifier, 'state': 'published', 'files_modified': False,
                    'metadata_changed': True, 'original_receipt_unchanged': True, 'durability': 'historical_sync_not_attested'}
        return self.journal.run(request_id, {'tool': 'git_acquire_reconcile', 'acquisition_id': identifier}, reconcile,
                                resource='git-acquisition:' + identifier)
