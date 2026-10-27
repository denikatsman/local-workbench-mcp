"""Exact staged inputs, observed validation and per-file publication receipts."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
import unicodedata

from .context import work_context
from .environments import EnvironmentProfiles
from .errors import WorkbenchError
from .runtime import DEFAULT_PATH


class ChangeSets:
    def __init__(self, files, sessions, scratch, jobs):
        self.files, self.sessions, self.scratch, self.jobs = files, sessions, scratch, jobs
        self.config, self.store, self.journal = files.config, files.store, files.journal
        self.path = self.config.state_dir / 'change-sets.sqlite3'
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS change_sets (change_set_id TEXT PRIMARY KEY,payload TEXT NOT NULL)')

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db

    @staticmethod
    def child(request_id, step):
        return 'changeset:' + hashlib.sha256((request_id + ':' + step).encode()).hexdigest()

    def save(self, record):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO change_sets VALUES (?,?)', (record['change_set_id'], json.dumps(record)))

    def load(self, change_set_id):
        self.sessions.validate(change_set_id)
        with self.db() as db:
            row = db.execute('SELECT payload FROM change_sets WHERE change_set_id=?', (change_set_id,)).fetchone()
        if row is None:
            raise WorkbenchError('unknown_change_set', 'No change set has this ID.')
        record = json.loads(row[0])
        if work_context.get() is not None and work_context.get() != record['work_session_id']:
            raise WorkbenchError('work_session_mismatch', 'Use this change set\'s recorded work context deliberately.')
        return record

    def _staged_hashes(self, record):
        result, total, deadline = {}, 0, time.monotonic() + 10
        for item in record['inputs']:
            with self.files._regular(record['workspace'], item['staged_path']) as (source, before):
                if before.st_size > self.config.max_artifact_bytes:
                    raise WorkbenchError('stage_limit', 'A staged input exceeds the artifact limit.')
                digest = hashlib.sha256()
                while chunk := source.read(1048576):
                    total += len(chunk)
                    if total > 268435456 or time.monotonic() > deadline:
                        raise WorkbenchError('stage_limit', 'Staged input verification exceeded 256 MiB or ten seconds.')
                    digest.update(chunk)
                result[item['path']] = digest.hexdigest()
                after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise WorkbenchError('stage_changed', 'A staged input changed during verification.')
        return result

    def prepare(self, workspace, changes, request_id, validation_inputs=None):
        self.files._writable(workspace)
        if not isinstance(changes, list) or not 1 <= len(changes) <= 100:
            raise WorkbenchError('invalid_change_set', 'Prepare 1..100 explicit file changes.')
        validation_inputs = {} if validation_inputs is None else validation_inputs
        if not isinstance(validation_inputs, dict) or len(validation_inputs) > 500:
            raise WorkbenchError('invalid_change_set', 'Use at most 500 explicit extra validation input paths/artifacts.')
        normalized, aliases = [], set()
        for item in changes:
            if not isinstance(item, dict) or set(item) != {'path', 'expected_sha256', 'artifact_id'}:
                raise WorkbenchError('invalid_change_set', 'Each change needs path, expected_sha256 and artifact_id.')
            path = '/'.join(self.files._parts(item['path']))
            alias = unicodedata.normalize('NFC', path).casefold()
            if alias in aliases:
                raise WorkbenchError('duplicate_target', 'A change set may not publish two aliases of the same target.')
            aliases.add(alias)
            self.files._revision(item['expected_sha256'])
            if not self.store.verify(item['artifact_id'])['verified']:
                raise WorkbenchError('artifact_corrupt', 'A candidate artifact failed verification.')
            normalized.append({**item, 'path': path})
        allocated = {}
        def stage():
            identifier = uuid.uuid4().hex
            session = work_context.get() or self.sessions.open(workspace, 'Staged changes', self.child(request_id, 'session'))['work_session_id']
            if self.sessions.ensure(session)['workspace'] != workspace:
                raise WorkbenchError('work_session_mismatch', 'The work session belongs to another workspace.')
            record = {'change_set_id': identifier, 'workspace': workspace, 'work_session_id': session,
                'created_at': time.time(), 'state': 'preparing',
                'files': [{**item, 'publication': 'untouched', 'precondition_checked': False} for item in normalized],
                'inputs': [], 'validation': None,
                'metadata_policy': 'Managed file content and current mode; no universal ACL/xattr/hardlink rollback.',
                'atomicity': 'Each file publication is atomic; the entire change set is not externally atomic.'}
            self.save(record)
            allocated.update(change_set_id=identifier, work_session_id=session)
            self.journal.checkpoint(request_id, {**record, 'phase': 'before_staging', 'effect_state': 'metadata_created'})
            owned = self.scratch.create(session, self.child(request_id, 'scratch'))
            record.update(scratch_id=owned['scratch_id'], stage_root=owned['path'])
            self.save(record)
            self.journal.checkpoint(request_id, {**record, 'phase': 'owned_scratch_created', 'effect_state': 'targets_untouched'})
            inputs = dict(validation_inputs)
            for item in record['files']:
                with self.files._parent(workspace, item['path']) as (parent, name):
                    before, _ = self.files._current(parent, name)
                    self.files._check_revision(before, item['expected_sha256'])
                    parent_info = os.fstat(parent)
                item.update(before_artifact=before['artifact_id'] if before else None,
                    parent_identity=[parent_info.st_dev, parent_info.st_ino], precondition_checked=True)
                self.save(record)
                if item['path'] in inputs:
                    raise WorkbenchError('duplicate_target', 'A candidate path cannot also be a different validation input.')
                inputs[item['path']] = item['artifact_id']
            total = 0
            made = set()
            staged_aliases = set()
            for index, (path, artifact) in enumerate(inputs.items()):
                parts = self.files._parts(path)
                path = '/'.join(parts)
                alias = unicodedata.normalize('NFC', path).casefold()
                if alias in staged_aliases or parts[0] == '.workbench-owner.json':
                    raise WorkbenchError('duplicate_target', 'Staged inputs have duplicate aliases or a reserved ownership path.')
                staged_aliases.add(alias)
                verified = self.store.verify(artifact)
                if not verified['verified']:
                    raise WorkbenchError('artifact_corrupt', 'A validation input did not verify.')
                total += verified['bytes']
                if total > 268435456:
                    raise WorkbenchError('stage_limit', 'Selected staged inputs exceed 256 MiB.')
                for depth in range(1, len(parts)):
                    prefix = record['stage_root'] + '/' + '/'.join(parts[:depth])
                    if prefix not in made:
                        self.files.make_directory(workspace, prefix, self.child(request_id, 'directory:' + prefix))
                        made.add(prefix)
                staged = record['stage_root'] + '/' + path
                self.files.write_file(workspace, staged, self.child(request_id, 'input:' + str(index)), artifact_id=artifact)
                record['inputs'].append({'path': path, 'artifact_id': artifact, 'staged_path': staged})
                self.save(record)
            record['staged_hashes'] = self._staged_hashes(record)
            record['state'] = 'prepared'
            self.save(record)
            manifest = self.store.put_bytes(json.dumps(record, ensure_ascii=True).encode(), 'changeset:' + identifier)
            self.sessions._append(session, 'change-set-prepared:' + request_id, {'kind': 'change_set_prepared', **record})
            return {'ok': True, 'change_set_id': identifier, 'work_session_id': session, 'state': record['state'],
                    'stage_root': record['stage_root'], 'scratch_id': record['scratch_id'], 'manifest_artifact': manifest,
                    'targets_changed': False, 'atomicity': record['atomicity']}
        def guarded_stage():
            try:
                return stage()
            except WorkbenchError as error:
                raise WorkbenchError(error.code, error.message, **{**error.details, **allocated,
                    'effect_state': 'targets_untouched'}) from error
        return self.journal.run(request_id, {'tool': 'change_set_prepare', 'workspace': workspace,
            'changes': normalized, 'validation_inputs': validation_inputs, 'work_session_id': work_context.get()}, guarded_stage)

    def validate(self, change_set_id, argv, request_id, environment_profile_id=None, timeout_seconds=300, wait_ms=0):
        record = self.load(change_set_id)
        self.sessions.ensure(record['work_session_id'])
        if record['state'] not in ('prepared', 'validating') or type(wait_ms) is not int or not 0 <= wait_ms <= 10000:
            raise WorkbenchError('change_set_state', 'Validate a prepared set; wait_ms must be 0..10000.')
        if not self.config.workspace(record['workspace']).executable:
            raise WorkbenchError('execution_denied', 'Validation is host execution and requires an executable workspace.')
        def validate():
            if record['validation'] and record['validation'].get('job_id') in self.jobs.active_ids():
                raise WorkbenchError('validation_running', 'Observe the existing validator before starting another one.', effect_state='none')
            if self._staged_hashes(record) != record['staged_hashes']:
                raise WorkbenchError('stage_changed', 'The staged bytes changed after preparation; prepare a new set.')
            token = work_context.set(record['work_session_id'])
            try:
                driver = None
                if environment_profile_id is None:
                    if not isinstance(argv, list) or not argv or not isinstance(argv[0], str):
                        raise WorkbenchError('invalid_argv', 'Provide the exact validator argument array.')
                    selected = shutil.which(argv[0], path=DEFAULT_PATH)
                    if selected is None:
                        raise WorkbenchError('executable_unavailable', 'Choose an absolute validator or a named runtime profile.')
                    driver = EnvironmentProfiles.fingerprint(selected)
                    argv_selected = [selected, *argv[1:]]
                else:
                    argv_selected = argv
                child_request = self.child(request_id, 'job')
                record['validation'] = {'job_request_id': child_request, 'driver': driver, 'argv': list(argv_selected),
                    'environment_profile_id': environment_profile_id, 'input_hashes': dict(record['staged_hashes']),
                    'expected_exit': 0, 'started_at': time.time(), 'scope': 'This command against these exact staged inputs; broader application criteria need separate evidence.'}
                record['state'] = 'validating'
                self.save(record)
                self.journal.checkpoint(request_id, {'change_set_id': change_set_id, 'validation_job_request_id': child_request,
                    'work_session_id': record['work_session_id'], 'phase': 'before_validation_launch', 'effect_state': 'none'})
                receipt = self.jobs.start(record['workspace'], argv_selected, child_request,
                    cwd=record['stage_root'], timeout_seconds=timeout_seconds, environment_profile_id=environment_profile_id)
                observed = self.jobs.status(receipt['job_id'])
                driver = driver or observed['environment_profile']['driver']
                record['validation'].update(job_id=receipt['job_id'], driver=driver)
                self.save(record)
                self.journal.checkpoint(request_id, {'change_set_id': change_set_id, 'job_id': receipt['job_id'],
                    'work_session_id': record['work_session_id'], 'phase': 'validation_started', 'effect_state': 'process_started'})
                if wait_ms:
                    self.jobs.wait_terminal(receipt['job_id'], wait_ms)
                return self.inspect(change_set_id)
            finally:
                work_context.reset(token)
        return self.journal.run(request_id, {'tool': 'change_set_validate', 'change_set_id': change_set_id,
            'argv': argv, 'environment_profile_id': environment_profile_id, 'timeout_seconds': timeout_seconds}, validate,
            resource='change-set:' + change_set_id)

    def inspect(self, change_set_id):
        record = self.load(change_set_id)
        validation = record['validation']
        state = record['state']
        outcome = None
        if validation and state in ('prepared', 'validating'):
            receipt = self.journal.status(validation['job_request_id'])
            job_id = validation.get('job_id') or (receipt.get('result') or {}).get('job_id')
            if job_id is None:
                job = None
                outcome = 'launch_not_established'
            else:
                job = self.jobs.evidence(job_id)
            if job is None:
                pass
            elif job['status'] in ('starting', 'running'):
                outcome = 'running'
            elif job['status'] != 'completed' or job['exit_code'] != 0 or not job['output_complete']:
                outcome = 'failed'
            elif self._staged_hashes(record) != validation['input_hashes']:
                outcome = 'staged_inputs_changed'
            elif validation['driver'] is None:
                outcome = 'runtime_identity_not_recorded'
            elif EnvironmentProfiles.fingerprint(validation['driver']['selected_path']) != validation['driver']:
                outcome = 'validator_changed'
            else:
                outcome = 'passed'
            validation = {**validation, 'outcome': outcome, 'job': job}
        targets = []
        for item in record['files']:
            observation = {'path': item['path'], 'publication': item['publication']}
            try:
                with self.files._parent(record['workspace'], item['path']) as (parent, name):
                    parent_info = os.fstat(parent)
                try:
                    with self.files._regular(record['workspace'], item['path']) as (source, before):
                        digest = hashlib.file_digest(source, 'sha256').hexdigest()
                        after = os.fstat(source.fileno())
                    stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                except WorkbenchError as error:
                    if error.code != 'not_found':
                        raise
                    digest, stable = None, True
                observation.update(current_sha256=digest, source_stable=stable,
                    matches_original=digest == item['expected_sha256'], matches_candidate=digest == item['artifact_id'][7:],
                    parent_matches=[parent_info.st_dev, parent_info.st_ino] == item.get('parent_identity'))
            except WorkbenchError as error:
                observation['error'] = error.as_dict()['error']
            targets.append(observation)
        targets_ready = all(item.get('matches_original') and item.get('source_stable') and item.get('parent_matches') for item in targets)
        return {'ok': True, **record, 'validation': validation, 'ready_to_publish': outcome == 'passed' and targets_ready,
                'current_targets': targets,
                'targets_ready': targets_ready,
                'inspection_performed_at': time.time(), 'targets_changed': any(item['publication'] != 'untouched' for item in record['files'])}

    def publish(self, change_set_id, request_id):
        record = self.load(change_set_id)
        self.sessions.ensure(record['work_session_id'])
        self.files._writable(record['workspace'])
        def publish():
            checked = self.inspect(change_set_id)
            if checked['validation'] is None or checked['validation'].get('outcome') != 'passed':
                raise WorkbenchError('validation_not_passed', 'The exact staged inputs have not passed a complete validator.', effect_state='none')
            for item in record['files']:
                with self.files._parent(record['workspace'], item['path']) as (parent, name):
                    info = os.fstat(parent)
                    if [info.st_dev, info.st_ino] != item['parent_identity']:
                        raise WorkbenchError('target_parent_changed', 'A publication parent changed identity; nothing was published.', path=item['path'], effect_state='none')
                    before, _ = self.files._current(parent, name)
                    self.files._check_revision(before, item['expected_sha256'])
            record['state'] = 'publishing'
            self.save(record)
            self.journal.checkpoint(request_id, {**record, 'phase': 'before_publication', 'effect_state': 'none'})
            for index, item in enumerate(record['files']):
                inner = self.child(request_id, 'publish:' + str(index))
                item['publication_request_id'] = inner
                item['publication'] = 'unknown'
                self.save(record)
                self.journal.checkpoint(request_id, {**record, 'phase': 'publishing_file', 'effect_state': 'partial_or_unknown'})
                try:
                    receipt = self.files.write_file(record['workspace'], item['path'], inner,
                        expected_sha256=item['expected_sha256'], artifact_id=item['artifact_id'])
                except WorkbenchError as error:
                    item['publication'] = 'untouched' if error.code == 'revision_conflict' or error.details.get('effect_state') == 'none' else 'unknown'
                    record['state'] = 'publication_incomplete'
                    self.save(record)
                    raise WorkbenchError(error.code, error.message, **{**error.details, 'change_set_id': change_set_id,
                        'work_session_id': record['work_session_id'], 'file_outcomes': record['files'], 'effect_state': 'partial_or_unknown'}) from error
                item['publication'] = 'applied'
                item['receipt'] = receipt
                self.save(record)
                self.journal.checkpoint(request_id, {**record, 'phase': 'file_published', 'effect_state': 'partial'})
            record['state'] = 'published'
            self.save(record)
            self.sessions._append(record['work_session_id'], 'change-set:' + request_id, {'kind': 'change_set_published', **record})
            return {'ok': True, 'change_set_id': change_set_id, 'work_session_id': record['work_session_id'],
                    'state': 'published', 'files': record['files'], 'effect_state': 'applied', 'atomicity': record['atomicity']}
        return self.journal.run(request_id, {'tool': 'change_set_publish', 'change_set_id': change_set_id}, publish,
                                resource='change-set:' + change_set_id)

    def reconcile(self, change_set_id, request_id):
        def reconcile():
            record = self.load(change_set_id)
            validation = record['validation']
            if validation and not validation.get('job_id'):
                receipt = self.journal.status(validation['job_request_id'])
                value = receipt.get('result') or {}
                if value.get('ok') is False:
                    value = value.get('error', {})
                if value.get('job_id'):
                    job = self.jobs.status(value['job_id'])
                    validation['job_id'] = job['job_id']
                    if validation.get('driver') is None:
                        validation['driver'] = job.get('environment_profile', {}).get('driver')
            for item in record['files']:
                if item['publication'] != 'unknown' or not item.get('publication_request_id'):
                    continue
                receipt = self.journal.status(item['publication_request_id'])
                value = receipt.get('result') or {}
                if receipt['state'] == 'completed' and value.get('after_artifact') == item['artifact_id']:
                    item.update(publication='applied', receipt=value)
                elif receipt['state'] == 'failed' and value.get('error', {}).get('effect_state') == 'none':
                    item['publication'] = 'untouched'
                item['reconciliation_receipt_state'] = receipt['state']
            if record['state'] == 'publishing':
                record['state'] = 'published' if all(item['publication'] == 'applied' for item in record['files']) else 'publication_incomplete'
            self.save(record)
            observed = self.inspect(change_set_id)
            self.sessions._append(record['work_session_id'], 'change-set-reconcile:' + request_id,
                {'kind': 'change_set_reconciled', 'change_set_id': change_set_id,
                 'file_outcomes': record['files'], 'validation': validation, 'targets_mutated': False})
            return {**observed, 'reconciliation_performed': True, 'targets_mutated': False, 'original_receipts_changed': False}
        return self.journal.run(request_id, {'tool': 'change_set_reconcile', 'change_set_id': change_set_id}, reconcile,
                                resource='change-set:' + change_set_id)
