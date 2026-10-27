"""Owned Python syntax/pytest runs with source revisions and raw evidence."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import xml.etree.ElementTree as ET

from .context import work_context, capture_sensitive
from .errors import WorkbenchError
from .files import _same_file
from .views import response_size


HARNESS = '''
import base64, hashlib, importlib.metadata, json, pathlib, subprocess, sys
payload = PAYLOAD
root = pathlib.Path(__file__).parent
metadata = {"schema_version": 1, "adapter": payload["adapter"],
            "python_version": sys.version, "python_executable": sys.executable,
            "sources": [{"path": x["path"], "sha256": x["sha256"]} for x in payload["sources"]]}
if payload["adapter"] == "python_syntax":
    diagnostics = []
    for source in payload["sources"]:
        try:
            compile(base64.b64decode(source["data"]), source["path"], "exec", dont_inherit=True)
        except SyntaxError as error:
            diagnostics.append({"path": source["path"], "message": error.msg,
                "line": error.lineno, "column": error.offset,
                "end_line": error.end_lineno, "end_column": error.end_offset,
                "coordinate_units": "Python-reported 1-based lines and columns; f-string offsets may refer to constructed expression text"})
        except (ValueError, UnicodeError) as error:
            diagnostics.append({"path": source["path"], "message": str(error),
                "coordinate_units": "unavailable"})
    metadata.update(tool_version=sys.version, diagnostics=diagnostics, exit_code=1 if diagnostics else 0)
    print(json.dumps(metadata, ensure_ascii=True))
else:
    try:
        version = importlib.metadata.version("pytest")
    except importlib.metadata.PackageNotFoundError:
        metadata.update(tool_version=None, unavailable="pytest_not_installed", exit_code=2)
    else:
        command = [sys.executable, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                   "--junitxml=" + str(root / "report.xml"), "--", *[x["path"] for x in payload["sources"]]]
        result = subprocess.run(command)
        report = root / "report.xml"
        report_hash = hashlib.sha256(report.read_bytes()).hexdigest() if report.exists() and report.stat().st_size <= 2097152 else None
        metadata.update(tool_version=version, exit_code=result.returncode, report_sha256=report_hash)
encoded = json.dumps(metadata, ensure_ascii=True, sort_keys=True).encode()
temporary = root / "metadata.tmp"
with temporary.open("xb") as output:
    output.write(encoded)
temporary.replace(root / "metadata.json")
print("\\nLWB_DIAGNOSTIC_METADATA_SHA256:" + hashlib.sha256(encoded).hexdigest(), flush=True)
sys.exit(metadata["exit_code"])
'''


class CodeDiagnostics:
    def __init__(self, files, scripts, jobs):
        self.files, self.scripts, self.jobs = files, scripts, jobs
        self.store, self.journal = files.store, files.journal

    def start(self, workspace, adapter, paths, request_id, expected_hashes=None, expected_exit=0, timeout_seconds=300):
        self.files._writable(workspace)
        if not self.files.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Diagnostics require an executable workspace.')
        if adapter not in ('python_syntax', 'pytest'):
            raise WorkbenchError('unsupported_diagnostic', 'Supported adapters are python_syntax and pytest.')
        if not isinstance(paths, list) or not 1 <= len(paths) <= 32 or any(
                not isinstance(path, str) or not path.endswith('.py') for path in paths) or len(set(paths)) != len(paths):
            raise WorkbenchError('unsupported_language', 'Select 1..32 distinct Python source/test files.')
        expected_hashes = {} if expected_hashes is None else expected_hashes
        if not isinstance(expected_hashes, dict) or set(expected_hashes) - set(paths) or any(
                not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in expected_hashes.values()):
            raise WorkbenchError('invalid_revision', 'Expected revisions must be selected paths mapped to full SHA-256 hashes.')
        if type(expected_exit) is not int or not 0 <= expected_exit <= 255:
            raise WorkbenchError('invalid_exit', 'Use an integer expected exit 0..255.')
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
            raise WorkbenchError('invalid_timeout', 'Use a timeout 1..3600 seconds.')

        def run():
            sources, total = [], 0
            for path in paths:
                with self.files._regular(workspace, path) as (stream, before):
                    if before.st_size > 4 * 1024 * 1024 - total:
                        raise WorkbenchError('diagnostic_limit', 'Selected source snapshots exceed 4 MiB.')
                    data = stream.read(4 * 1024 * 1024 - total + 1)
                    if len(data) != before.st_size or not _same_file(before, os.fstat(stream.fileno())):
                        raise WorkbenchError('source_changed', 'A selected source changed during capture.')
                total += len(data)
                digest = hashlib.sha256(data).hexdigest()
                if path in expected_hashes and digest != expected_hashes[path]:
                    raise WorkbenchError('source_revision_conflict', 'A selected source does not match its expected revision.',
                                         path=path, actual_sha256=digest, effect_state='none')
                capture = self.store.put_bytes(data, json.dumps({'kind': 'diagnostic-source', 'path': path,
                    'potentially_sensitive': True}))
                sources.append({'path': path, 'sha256': digest, 'artifact_id': capture['artifact_id'],
                                'capture_id': capture['capture_id'],
                                'data': base64.b64encode(data).decode()})
            payload = {'adapter': adapter, 'sources': sources}
            script = self.store.put_bytes(HARNESS.replace('PAYLOAD', repr(payload), 1).encode(),
                json.dumps({'kind': 'diagnostic-harness', 'potentially_sensitive': True}))['artifact_id']
            public_sources = [{key: value for key, value in source.items() if key != 'data'} for source in sources]
            script_request_id = self.scripts.child(request_id, 'diagnostic')
            self.journal.checkpoint(request_id, {'tool': 'diagnostic_run', 'phase': 'before_diagnostic_execution',
                'workspace': workspace, 'adapter': adapter, 'expected_exit': expected_exit,
                'source_artifacts': public_sources, 'script_artifact': script, 'script_request_id': script_request_id,
                'scope': 'Selected source captures and an owned runner; pytest executes host-user code and may change files.',
                'effect_state': 'source_captured', 'potentially_sensitive': True})
            sensitivity = capture_sensitive.set(True)
            try:
                execution = self.scripts.start(workspace, script, [], script_request_id,
                    interpreter=[sys.executable, '-I', '-B'], timeout_seconds=timeout_seconds)
            finally:
                capture_sensitive.reset(sensitivity)
            return {**execution, 'tool': 'diagnostic_run', 'workspace': workspace, 'adapter': adapter,
                    'start_request_id': request_id, 'expected_exit': expected_exit, 'source_artifacts': public_sources,
                    'script_request_id': script_request_id,
                    'potentially_sensitive': True,
                    'scope': 'Selected source captures and an owned runner; pytest executes host-user code and may change files.'}
        return self.journal.run(request_id, {'tool': 'diagnostic_run', 'workspace': workspace, 'adapter': adapter,
            'paths': paths, 'expected_hashes': expected_hashes, 'expected_exit': expected_exit,
            'timeout_seconds': timeout_seconds, 'work_session_id': work_context.get()}, run)

    def _capture(self, workspace, path, max_bytes):
        with self.files._regular(workspace, path) as (stream, info):
            if info.st_size > max_bytes:
                raise WorkbenchError('diagnostic_report_limit', 'The runner report exceeds its parser budget.')
            data = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
            if len(data) != info.st_size or not _same_file(info, after):
                raise WorkbenchError('source_changed', 'The runner report changed during capture.')
        artifact = self.store.put_bytes(data, json.dumps({'kind': 'diagnostic-report', 'potentially_sensitive': True}))
        return data, artifact

    @staticmethod
    def junit(data):
        class NoDTD(ET.TreeBuilder):
            def doctype(self, name, pubid, system):
                raise WorkbenchError('unsupported_report', 'DTD/entity-bearing reports are not parsed.')
        try:
            root = ET.fromstring(data, parser=ET.XMLParser(target=NoDTD()))
        except (ET.ParseError, ValueError) as error:
            raise WorkbenchError('malformed_report', 'The JUnit report is not valid XML.') from error
        if root.tag not in ('testsuites', 'testsuite'):
            raise WorkbenchError('unsupported_report', 'Expected a JUnit testsuite/testsuites root.')
        cases = list(root.iter('testcase'))
        if len(cases) > 10000 or sum(1 for _ in root.iter()) > 20000:
            raise WorkbenchError('diagnostic_report_limit', 'JUnit entry limit exceeded.')
        counts = {'tests': len(cases), 'failures': 0, 'errors': 0, 'skipped': 0}
        for case in cases:
            for key in ('failures', 'errors', 'skipped'):
                if case.find({'failures': 'failure', 'errors': 'error', 'skipped': 'skipped'}[key]) is not None:
                    counts[key] += 1
        for suite in [root, *[x for x in root.iter('testsuite') if x is not root]]:
            descendants = list(suite.iter('testcase'))
            for attribute, tag in (('tests', None), ('failures', 'failure'), ('errors', 'error'), ('skipped', 'skipped')):
                if attribute in suite.attrib:
                    actual = len(descendants) if tag is None else sum(case.find(tag) is not None for case in descendants)
                    if not suite.attrib[attribute].isdigit() or int(suite.attrib[attribute]) != actual:
                        raise WorkbenchError('inconsistent_report', 'JUnit declared counts do not match its cases.')
        return counts

    def inspect(self, start_request_id, max_bytes=8192):
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes 4096..262144.')
        receipt = self.journal.status(start_request_id)
        run = receipt.get('result')
        if receipt['state'] == 'pending' and isinstance(run, dict) and run.get('tool') == 'diagnostic_run' and run.get('script_request_id'):
            child = self.journal.status(run['script_request_id'])
            if child['state'] == 'completed' and isinstance(child.get('result'), dict) and child['result'].get('ok'):
                run = {**run, **child['result']}
        if not isinstance(run, dict) or run.get('tool') != 'diagnostic_run' or not run.get('ok'):
            raise WorkbenchError('diagnostic_unavailable', 'Inspect the original operation receipt; a diagnostic start is not established.',
                                 request_id=start_request_id, operation_state=receipt['state'], effect_state='none')
        owner = run['work_session_id']
        if work_context.get() is not None and work_context.get() != owner:
            raise WorkbenchError('work_session_mismatch', 'Use this diagnostic run\'s matching work context.')
        token = work_context.set(owner)
        try:
            job = self.jobs.evidence(run['job_id'])
        finally:
            work_context.reset(token)
        result = {'ok': True, 'start_request_id': start_request_id, 'job_id': run['job_id'],
            'checked_at': time.time(),
            'work_session_id': owner, 'adapter': run['adapter'], 'job': job,
            'source_artifacts': run['source_artifacts'], 'scope': run['scope'],
            'expected_exit': run['expected_exit'], 'command_expectation_met': None,
            'tests_passed': None, 'current_sources_verified': False, 'potentially_sensitive': True}
        result.update(start_operation_state=receipt['state'], historical_receipt_preserved=True,
                      script_request_id=run['script_request_id'])
        if job['status'] in ('starting', 'running') or not job['output_complete']:
            result.update(state='waiting' if job['status'] in ('starting', 'running') else 'unverified',
                          reason='Job or output publication is not complete.')
            return self._bounded(result, run, max_bytes)
        result['command_expectation_met'] = job['status'] == 'completed' and job['exit_code'] == run['expected_exit']
        directory = str(Path(run['script_path']).parent)
        try:
            data, artifact = self._capture(run['workspace'], directory + '/metadata.json', 1048576)
            result['metadata_artifact'] = artifact
            stdout = job['artifacts']['stdout']['artifact_id']
            with self.store.path(stdout).open('rb') as stream:
                stream.seek(max(0, self.store.path(stdout).stat().st_size - 4096))
                markers = re.findall(rb'(?:^|\n)LWB_DIAGNOSTIC_METADATA_SHA256:([0-9a-f]{64})\r?\n', stream.read(4096))
            if len(markers) != 1 or markers[0].decode() != hashlib.sha256(data).hexdigest():
                raise WorkbenchError('inconsistent_report', 'The runner metadata does not match its completed output digest.')
            result['metadata_digest_scope'] = 'Digest in the owned stdout tail; not a hostile-process or whole-runtime attestation.'
            metadata = json.loads(data)
            if isinstance(metadata, dict) and metadata.get('unavailable'):
                raise WorkbenchError('diagnostic_prerequisite', 'The selected runner is not installed; no package was installed automatically.')
            expected_sources = [{'path': x['path'], 'sha256': x['sha256']} for x in run['source_artifacts']]
            if (not isinstance(metadata, dict) or metadata.get('schema_version') != 1 or metadata.get('adapter') != run['adapter']
                    or metadata.get('sources') != expected_sources or metadata.get('exit_code') != job['exit_code']
                    or not isinstance(metadata.get('tool_version'), str)):
                raise WorkbenchError('inconsistent_report', 'The runner metadata does not match its owned job/source receipt.')
            result['tool_version'] = metadata['tool_version']
            result['python_version'] = metadata.get('python_version')
            changed, current_hashes = [], {}
            for source in run['source_artifacts']:
                try:
                    with self.files._regular(run['workspace'], source['path']) as (stream, before):
                        if before.st_size > 4 * 1024 * 1024:
                            raise WorkbenchError('diagnostic_limit', 'Current source exceeds the comparison budget.')
                        data = stream.read(4 * 1024 * 1024 + 1)
                        stable = len(data) == before.st_size and _same_file(before, os.fstat(stream.fileno()))
                        current_hashes[source['path']] = hashlib.sha256(data).hexdigest() if stable else None
                    if not stable or current_hashes[source['path']] != source['sha256']:
                        changed.append(source['path'])
                except (OSError, WorkbenchError):
                    current_hashes[source['path']] = None
                    changed.append(source['path'])
            result.update(changed_sources=changed, current_source_sha256=current_hashes, current_sources_verified=not changed,
                          source_consistency='Selected source hashes before/after; no atomic snapshot or dependency-closure attestation.')
            if run['adapter'] == 'python_syntax':
                diagnostics = metadata.get('diagnostics')
                if not isinstance(diagnostics, list) or len(diagnostics) > len(run['source_artifacts']) or any(not isinstance(x, dict) for x in diagnostics):
                    raise WorkbenchError('malformed_report', 'Invalid syntax diagnostic records.')
                result['diagnostics'] = diagnostics
                passed = not diagnostics and job['exit_code'] == 0
                result['verification_method'] = 'compile immutable captured Python bytes without executing their source'
            else:
                data, artifact = self._capture(run['workspace'], directory + '/report.xml', 2097152)
                result['report_artifact'] = artifact
                if hashlib.sha256(data).hexdigest() != metadata.get('report_sha256'):
                    raise WorkbenchError('inconsistent_report', 'The JUnit report changed after its runner recorded it.')
                counts = self.junit(data); result['reported_counts'] = counts
                passed = counts['tests'] > counts['skipped'] and counts['failures'] == counts['errors'] == 0 and job['exit_code'] == 0
                result['verification_method'] = 'owned pytest process and bounded JUnit report; selected file revision brackets'
            result['tests_passed'] = passed if not changed and job['status'] == 'completed' else None
            result['state'] = 'verified' if not changed and job['status'] == 'completed' else 'unverified'
        except (OSError, ValueError, KeyError, TypeError, WorkbenchError) as error:
            result.update(state='unverified', reason=getattr(error, 'message', 'Runner report is unavailable or malformed.'),
                          error_code=getattr(error, 'code', type(error).__name__))
        return self._bounded(result, run, max_bytes)

    def _bounded(self, result, run, max_bytes):
        if response_size(result) <= max_bytes - 512:
            return result
        artifact = self.store.put_bytes(json.dumps(result, ensure_ascii=True).encode(),
            json.dumps({'kind': 'diagnostic-result', 'potentially_sensitive': True}))
        return {'ok': True, 'job_id': run['job_id'], 'start_request_id': result['start_request_id'],
                'work_session_id': run['work_session_id'],
                'result_artifact': artifact, 'inline_complete': False, 'potentially_sensitive': True}
