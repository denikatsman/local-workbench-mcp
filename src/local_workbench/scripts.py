"""Execute an immutable script with argument arrays and an owned materialization."""
import hashlib
import sys

from .context import work_context, capture_sensitive
from .errors import WorkbenchError


class ScriptRunner:
    def __init__(self, files, sessions, scratch, jobs):
        self.files, self.sessions, self.scratch, self.jobs = files, sessions, scratch, jobs
        self.journal, self.store = files.journal, files.store

    @staticmethod
    def child(request_id, phase):
        return 'script:' + hashlib.sha256((request_id + ':' + phase).encode()).hexdigest()

    def start(self, workspace, artifact_id, arguments, request_id, interpreter=None, environment_profile_id=None,
              cwd='.', timeout_seconds=300, keep_stdin=False):
        self.files._writable(workspace)
        if not self.files.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Script execution requires an executable workspace.')
        if not isinstance(arguments, list) or any(not isinstance(value, str) or '\0' in value for value in arguments):
            raise WorkbenchError('invalid_argv', 'Script arguments must be literal strings without NUL bytes.')
        if len(arguments) > 4090 or sum(len(value.encode()) for value in arguments) > 1000000:
            raise WorkbenchError('invalid_argv', 'Script arguments exceed the bounded argv budget.')
        if interpreter is not None and (not isinstance(interpreter, list) or not interpreter or any(
                not isinstance(value, str) or '\0' in value for value in interpreter)):
            raise WorkbenchError('invalid_interpreter', 'Use an explicit interpreter argument array.')
        if not self.store.verify(artifact_id)['verified']:
            raise WorkbenchError('artifact_corrupt', 'The script source did not verify.')
        command = [sys.executable] if interpreter is None else interpreter
        def run():
            session = work_context.get() or self.sessions.open(workspace, 'Script execution', self.child(request_id, 'session'))['work_session_id']
            if self.sessions.ensure(session)['workspace'] != workspace:
                raise WorkbenchError('work_session_mismatch', 'The script context belongs to a different workspace.')
            self.journal.checkpoint(request_id, {'work_session_id': session, 'script_artifact': artifact_id,
                'phase': 'before_script_materialization', 'effect_state': 'none'})
            owned = self.scratch.create(session, self.child(request_id, 'scratch'))
            relative = owned['path'] + '/script'
            self.files.write_file(workspace, relative, self.child(request_id, 'materialize'), artifact_id=artifact_id)
            absolute = str(self.files.config.workspace(workspace).root / relative)
            job_request = self.child(request_id, 'job')
            self.journal.checkpoint(request_id, {'work_session_id': session, 'scratch_id': owned['scratch_id'],
                'script_artifact': artifact_id, 'script_path': relative, 'job_request_id': job_request,
                'phase': 'before_script_execution', 'effect_state': 'source_materialized'})
            token = work_context.set(session)
            try:
                job = self.jobs.start(workspace, [*command, absolute, *arguments], job_request,
                    cwd=cwd, timeout_seconds=timeout_seconds, keep_stdin=keep_stdin,
                    environment_profile_id=environment_profile_id)
            except WorkbenchError as error:
                raise WorkbenchError(error.code, error.message, **{**error.details, 'work_session_id': session,
                    'scratch_id': owned['scratch_id'], 'script_artifact': artifact_id,
                    'script_path': relative, 'job_request_id': job_request, 'effect_state': 'source_materialized'}) from error
            finally:
                work_context.reset(token)
            result = {'ok': True, 'job_id': job['job_id'], 'work_session_id': session, 'scratch_id': owned['scratch_id'],
                'script_artifact': artifact_id, 'script_path': relative, 'actual_argv': job['argv'],
                'effect_state': 'process_started', 'scope': 'Exact source and argument transport; execution is as the host user, without sandboxing.'}
            if capture_sensitive.get() is True:
                result['potentially_sensitive'] = True
            self.sessions._append(session, 'script:' + request_id, {'kind': 'script_started',
                **{key: value for key, value in result.items() if key != 'actual_argv'},
                'request_id': request_id,
                'references': {key: result[key] for key in ('job_id', 'scratch_id', 'script_artifact')},
                'argument_count': len(job['argv']), 'argument_sha256': hashlib.sha256(repr(job['argv']).encode()).hexdigest()})
            return result
        return self.journal.run(request_id, {'tool': 'script_run', 'workspace': workspace, 'artifact_id': artifact_id,
            'arguments': arguments, 'interpreter': command, 'environment_profile_id': environment_profile_id,
            'cwd': cwd, 'timeout_seconds': timeout_seconds, 'keep_stdin': keep_stdin,
            'work_session_id': work_context.get(),
            **({'potentially_sensitive': True} if capture_sensitive.get() is True else {})}, run)
