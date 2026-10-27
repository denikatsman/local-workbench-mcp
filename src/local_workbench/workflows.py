"""Versioned deterministic steps; uncertain effects stop instead of being replayed."""
import contextlib
import hashlib
import json
import re
import sqlite3
import time
import uuid

from .context import work_context
from .errors import WorkbenchError
from .views import response_size


class Workflows:
    def __init__(self, files, jobs):
        self.files, self.jobs, self.store, self.journal = files, jobs, files.store, files.journal
        self.path = files.config.state_dir / 'workflows.sqlite3'
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS workflows (workflow_id TEXT PRIMARY KEY,payload TEXT NOT NULL)')

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db

    def save(self, record):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO workflows VALUES (?,?)', (record['workflow_id'], json.dumps(record)))

    def load(self, workflow_id):
        if not isinstance(workflow_id, str) or not re.fullmatch(r'[0-9a-f]{32}', workflow_id):
            raise WorkbenchError('invalid_workflow', 'Use an existing workflow ID.')
        with self.db() as db:
            row = db.execute('SELECT payload FROM workflows WHERE workflow_id=?', (workflow_id,)).fetchone()
        if row is None:
            raise WorkbenchError('unknown_workflow', 'No workflow has this ID.')
        record = json.loads(row[0])
        if work_context.get() is not None and work_context.get() != record['work_session_id']:
            raise WorkbenchError('work_session_mismatch', 'This workflow belongs to another work context.')
        return record

    def create(self, workspace, steps, request_id):
        self.files.config.workspace(workspace)
        if not isinstance(steps, list) or not 1 <= len(steps) <= 100 or len(json.dumps(steps).encode()) > 1048576:
            raise WorkbenchError('invalid_workflow', 'Use 1..100 steps within a 1 MiB definition.')
        names = set()
        for step in steps:
            if not isinstance(step, dict) or set(step) - {'id', 'operation', 'arguments'} or not {'id', 'operation', 'arguments'} <= set(step):
                raise WorkbenchError('invalid_workflow', 'Each step takes id, operation and arguments only.')
            if not isinstance(step['id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', step['id']) or step['id'] in names:
                raise WorkbenchError('invalid_workflow', 'Step IDs must be unique simple names.')
            if step['operation'] not in ('write_file', 'job', 'verify_artifact') or not isinstance(step['arguments'], dict):
                raise WorkbenchError('invalid_workflow', 'Supported steps are write_file, job and verify_artifact with structured arguments.')
            names.add(step['id'])
        def create():
            identifier = uuid.uuid4().hex
            record = {'schema_version': 1, 'workflow_id': identifier, 'workspace': workspace,
                'work_session_id': work_context.get(), 'created_at': time.time(), 'state': 'prepared',
                'steps': [{**step, 'state': 'unexecuted', 'result': None,
                           'operation_request_id': 'workflow-step:' + hashlib.sha256((identifier + ':' + step['id']).encode()).hexdigest()} for step in steps],
                'scope': 'Deterministic declared steps; no model scheduling, hidden chat identity or automatic uncertain-effect retry.'}
            self.save(record)
            return {'ok': True, 'workflow_id': identifier, 'state': 'prepared', 'step_count': len(steps)}
        return self.journal.run(request_id, {'tool': 'workflow_create', 'workspace': workspace, 'steps': steps,
            'work_session_id': work_context.get()}, create)

    @staticmethod
    def resolve(value, completed):
        if isinstance(value, dict) and set(value) == {'$step', 'field'}:
            if not isinstance(value['$step'], str) or not isinstance(value['field'], str) or value['$step'] not in completed:
                raise WorkbenchError('workflow_reference', 'Only a completed earlier step may supply a result reference.')
            result = completed[value['$step']]
            for part in value['field'].split('.'):
                if not isinstance(result, dict) or part not in result:
                    raise WorkbenchError('workflow_reference', 'The referenced result field is unavailable.')
                result = result[part]
            return result
        if isinstance(value, dict):
            return {key: Workflows.resolve(item, completed) for key, item in value.items()}
        if isinstance(value, list):
            return [Workflows.resolve(item, completed) for item in value]
        return value

    def inspect(self, workflow_id):
        record = self.load(workflow_id)
        result = {'ok': True, **record, 'step_counts': {state: sum(step['state'] == state for step in record['steps'])
            for state in ('unexecuted', 'unknown', 'waiting', 'completed', 'failed')}}
        if response_size(result) > 8192:
            artifact = self.store.put_bytes(json.dumps(result).encode(), 'workflow-inspection:' + workflow_id)
            return {'ok': True, 'workflow_id': workflow_id, 'state': record['state'], 'step_counts': result['step_counts'],
                    'result_artifact': artifact, 'view_complete': False}
        return {**result, 'view_complete': True}

    def run(self, workflow_id, request_id):
        self.load(workflow_id)  # Validate ownership before the journal can replay a receipt.
        def run():
            # Another resumer may have advanced while this request waited for the resource lock.
            record = self.load(workflow_id)
            completed = {}
            token = work_context.set(record['work_session_id'])
            try:
                for step in record['steps']:
                    if step['state'] == 'completed':
                        completed[step['id']] = step['result']
                        continue
                    if step['state'] == 'failed':
                        record['state'] = 'failed'
                        break
                    if step['state'] == 'unknown':
                        original = self.journal.status(step['operation_request_id'])
                        if original['state'] == 'completed':
                            step.update(result=original['result'], state='waiting' if step['operation'] == 'job' else 'completed')
                            if step['operation'] == 'verify_artifact' and not original['result'].get('verified'):
                                step['state'] = 'failed'
                                record['state'] = 'failed'; self.save(record); break
                            self.save(record)
                        elif original['state'] == 'failed':
                            step.update(result=original['result'], state='failed')
                            record['state'] = 'failed'; self.save(record); break
                        elif original['state'] == 'pending':
                            record['state'] = 'reconciliation_required'; self.save(record); break
                        else:
                            # The durable child reservation never began, so this step has no child effect.
                            step['state'] = 'unexecuted'
                    if step['state'] == 'waiting':
                        observed = self.jobs.evidence(step['result']['job_id'])
                        if observed['status'] in ('starting', 'running'):
                            record['state'] = 'waiting'; self.save(record); break
                        if observed['status'] != 'completed' or observed['exit_code'] != 0 or not observed['output_complete']:
                            step.update(state='failed', observation=observed)
                            record['state'] = 'failed'; self.save(record); break
                        step.update(state='completed', result={**step['result'], 'terminal_observation': observed})
                        completed[step['id']] = step['result']; self.save(record); continue
                    if step['state'] == 'completed':
                        completed[step['id']] = step['result']; continue
                    arguments = self.resolve(step['arguments'], completed)
                    if set(arguments) & {'workspace', 'request_id', 'work_session_id'}:
                        raise WorkbenchError('workflow_argument', 'Workspace, request identity and ownership are fixed by the workflow.')
                    step['state'] = 'unknown'; record['state'] = 'running'; self.save(record)
                    self.journal.checkpoint(request_id, {'workflow_id': workflow_id, 'step_id': step['id'],
                        'operation_request_id': step['operation_request_id'], 'phase': 'before_step', 'effect_state': 'unknown'})
                    try:
                        if step['operation'] == 'write_file':
                            result = self.files.write_file(record['workspace'], request_id=step['operation_request_id'], **arguments)
                        elif step['operation'] == 'job':
                            result = self.jobs.start(record['workspace'], request_id=step['operation_request_id'], **arguments)
                        else:
                            if set(arguments) != {'artifact_id'}:
                                raise WorkbenchError('workflow_argument', 'verify_artifact takes only artifact_id.')
                            result = self.journal.run(step['operation_request_id'], {'tool': 'workflow_verify', **arguments},
                                                      lambda: self.store.verify(arguments['artifact_id']))
                            if not result['verified']:
                                raise WorkbenchError('artifact_corrupt', 'A workflow evidence verification failed.')
                    except WorkbenchError as error:
                        child = self.journal.status(step['operation_request_id'])
                        step.update(error=error.as_dict()['error'], state='unknown' if child['state'] == 'pending' else 'failed')
                        record['state'] = 'reconciliation_required' if step['state'] == 'unknown' else 'failed'
                        self.save(record); break
                    step.update(result=result, state='waiting' if step['operation'] == 'job' else 'completed')
                    self.save(record)
                    if step['state'] == 'waiting':
                        record['state'] = 'waiting'; self.save(record); break
                    completed[step['id']] = result
                else:
                    record['state'] = 'completed'; self.save(record)
                return self.inspect(workflow_id)
            finally:
                work_context.reset(token)
        return self.journal.run(request_id, {'tool': 'workflow_run', 'workflow_id': workflow_id}, run,
                                resource='workflow:' + workflow_id)
