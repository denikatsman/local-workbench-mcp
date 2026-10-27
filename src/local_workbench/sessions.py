"""Durable work context and distinct evidence links for a single-owner profile."""
from __future__ import annotations

import contextlib
import hashlib
import json
import re
import sqlite3
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path

from .errors import WorkbenchError
from .views import response_size
from .context import work_admission


class WorkSessions:
    def __init__(self,config,store,journal):
        self.config,self.store,self.journal=config,store,journal
        self.path=config.state_dir/'work-sessions.sqlite3'
        self._lock = threading.RLock()
        self._inflight = {}
        self.resource_status = lambda session_id: {}
        self.resource_diagnostics = None
        self.jobs = None
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY,workspace TEXT NOT NULL,label TEXT NOT NULL,created REAL NOT NULL,state TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT,session_id TEXT NOT NULL,event_id TEXT UNIQUE NOT NULL,created REAL NOT NULL,payload TEXT NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS session_events ON events(session_id,sequence)')

    @contextlib.contextmanager
    def retain(self, session_id):
        """An independent resource pin, releasable by its owning worker."""
        identifier = uuid.uuid4().hex
        with self._lock:
            self.ensure(session_id)
            self._inflight.setdefault(session_id, set()).add(identifier)
        try:
            yield
        finally:
            with self._lock:
                self._inflight[session_id].discard(identifier)
                if not self._inflight[session_id]:
                    del self._inflight[session_id]

    @contextlib.contextmanager
    def admission(self, session_id, allow_closed=False):
        if session_id is None:
            yield
            return
        identifier = uuid.uuid4().hex
        with self._lock:
            self.ensure(session_id, allow_closed=allow_closed)
            self._inflight.setdefault(session_id, set()).add(identifier)
        token = work_admission.set(identifier)
        try:
            yield
        finally:
            work_admission.reset(token)
            with self._lock:
                self._inflight[session_id].discard(identifier)
                if not self._inflight[session_id]:
                    del self._inflight[session_id]

    def close(self, session_id, request_id):
        session = self.ensure(session_id, allow_closed=True)
        def finish():
            with self._lock:
                active = self._inflight.get(session_id, set()) - {work_admission.get()}
                resources = self.resource_status(session_id)
                if active or any(resources.values()):
                    raise WorkbenchError('work_session_busy', 'Finish or explicitly close the owned resources before closing this work session.',
                                         active_calls=len(active), resources=resources, effect_state='none',
                                         **self._resource_details(session_id, session['workspace'], resources))
                self._append(session_id, 'close:' + request_id, {'kind': 'session_closed'})
                with self.db() as db:
                    db.execute("UPDATE sessions SET state='closed' WHERE session_id=?", (session_id,))
            return {'ok': True, 'work_session_id': session_id, 'state': 'closed', 'history_preserved': True}
        return self.journal.run(request_id, {'tool': 'work_session_close', 'session_id': session_id}, finish,
                                resource='work-session:' + session_id)

    def _resource_details(self, session_id, workspace, resources=None, max_bytes=1536):
        """Optional best-effort explanation; never an admission or retirement input."""
        if self.resource_diagnostics is None:
            return {}
        unavailable = {'available': False, 'reason': 'resource_diagnostics_unavailable'}
        try:
            result = self.resource_diagnostics(session_id, workspace, resources)
            if not isinstance(result, dict) or len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) > max_bytes:
                result = unavailable
        except Exception:
            # The original busy refusal/inspection must survive observer failure;
            # neither exception strings nor saved producer payloads are echoed.
            result = unavailable
        return {'resource_diagnostics': result}

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path,timeout=5)) as db:
            db.execute('PRAGMA synchronous=FULL')
            with db:yield db

    @staticmethod
    def validate(session_id):
        if not isinstance(session_id,str) or not re.fullmatch(r'[0-9a-f]{32}',session_id):
            raise WorkbenchError('invalid_work_session','Expected a work-session ID returned by this profile.')

    def ensure(self,session_id,allow_closed=False):
        self.validate(session_id)
        with self.db() as db:
            row=db.execute('SELECT workspace,label,created,state FROM sessions WHERE session_id=?',(session_id,)).fetchone()
        if row is None:raise WorkbenchError('unknown_work_session','No work session has this ID in this profile.')
        if row[3]!='open' and not allow_closed:raise WorkbenchError('work_session_closed','This work session is closed; open a new context for new work.')
        return {'session_id':session_id,'workspace':row[0],'label':row[1],'created_at':row[2],'state':row[3]}

    def open(self,workspace,label,request_id):
        self.config.workspace(workspace)
        if not isinstance(label,str) or not 1<=len(label.encode())<=200:raise WorkbenchError('invalid_label','Use a label of 1..200 UTF-8 bytes.')
        def create():
            session_id=uuid.uuid4().hex
            self.journal.checkpoint(request_id,{'work_session_id':session_id,'phase':'before_context_creation','effect_state':'unknown'})
            with self.db() as db:
                db.execute('INSERT INTO sessions VALUES (?,?,?,?,?)',(session_id,workspace,label,time.time(),'open'))
            return {'ok':True,'work_session_id':session_id,'workspace':workspace,'state':'open',
                    'scope':'attribution and continuation; not an authorization boundary or hosted-model scheduler'}
        return self.journal.run(request_id,{'tool':'work_session_open','workspace':workspace,'label':label},create)

    def _append(self,session_id,event_id,payload):
        self.ensure(session_id,allow_closed=True)
        with self.db() as db:
            db.execute('INSERT OR IGNORE INTO events(session_id,event_id,created,payload) VALUES (?,?,?,?)',
                       (session_id,event_id,time.time(),json.dumps(payload,ensure_ascii=True,separators=(',',':'))))

    def record(self,session_id,trace_id,tool,request_id,result):
        refs={key:result[key] for key in ('workspace','path','job_id','download_id','download','artifact_id','artifact','artifacts','source_artifact','source_artifacts','metadata_artifact','report_artifact','before_artifact',
              'after_artifact','capture_id','session_id','generation','observation_id','result_artifact','screenshot_artifact',
              'preview_artifact','export_artifact','manifest_artifact','observation_artifact','text_artifact',
              'diff_artifact','candidate_artifact','script_artifact','change_set_id','upload_id','lease_id','scratch_id',
              'body_artifact','profile_id','document_generation','potentially_sensitive') if key in result}
        refs.update({key: result[key] for key in ('image_artifact', 'clipboard_lease_id', 'native_operation_id', 'acquisition_id') if key in result})
        self._append(session_id,trace_id,{'kind':'tool_result','tool':tool,'trace_id':trace_id,'request_id':request_id,
            'ok':result.get('ok',True),'error_code':result.get('error',{}).get('code'),'replayed':result.get('replayed'),
            'references':refs,'source':'server_observed_return','verification':result.get('verification_state','not_established')})

    def note(self,session_id,text,artifact_ids,request_id):
        self.ensure(session_id)
        if not isinstance(text,str) or not 1<=len(text.encode())<=16384:
            raise WorkbenchError('invalid_note','Use a note up to 16 KiB.')
        if not isinstance(artifact_ids,list) or len(artifact_ids)>100:
            raise WorkbenchError('invalid_evidence','Use at most 100 artifact references.')
        for artifact in artifact_ids:self.store.path(artifact)
        def append():
            self._append(session_id,'note:'+request_id,{'kind':'caller_note','text':text,'artifacts':artifact_ids,
                                                      'verification':'caller_provided; not a server-verified claim'})
            return {'ok':True,'work_session_id':session_id,'event_id':'note:'+request_id,'recorded':True}
        return self.journal.run(request_id,{'tool':'work_session_note','session_id':session_id,'text':text,'artifacts':artifact_ids},append,
                                resource='work-session:'+session_id)

    def list(self, workspace, state='all', label_query=None, after=0, through=None,
             limit=20, max_bytes=8192):
        """Read metadata in persistent creation order; never restore authority.

        Session rows are append-only under the supported lifecycle, so their
        SQLite rowids provide creation cursors without timestamp ties or a
        list-time schema/history write. State filters are observed per page;
        through bounds creation only, not a frozen operational-state snapshot.
        """
        self.config.workspace(workspace)
        if (type(after) is not int or not 0 <= after <= 2**63 - 1
                or type(limit) is not int or not 1 <= limit <= 100
                or type(max_bytes) is not int or not 4096 <= max_bytes <= 262144):
            raise WorkbenchError('invalid_range', 'Use a nonnegative creation cursor, limit 1..100 and max_bytes 4096..262144.')
        if state not in ('all', 'open', 'closed'):
            raise WorkbenchError('invalid_session_state', 'Choose all, open or closed.')
        if label_query is not None:
            try:
                valid_label = type(label_query) is str and 1 <= len(label_query.encode()) <= 200
            except UnicodeEncodeError:
                valid_label = False
            if not valid_label:
                raise WorkbenchError('invalid_label_query', 'Use a literal label query of 1..200 UTF-8 bytes.')
        # URI read-only also prevents accidentally adding a list-time write.
        with contextlib.closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
            db.execute('BEGIN')
            high = db.execute('SELECT COALESCE(MAX(rowid),0) FROM sessions WHERE workspace=?', (workspace,)).fetchone()[0]
            if through is None:
                through = high
            if type(through) is not int or not 0 <= after <= through <= high:
                raise WorkbenchError('invalid_cursor', 'Creation cursors must satisfy 0 <= after <= through <= the workspace creation high-water mark.')
            filters = ['workspace=?', 'rowid>?', 'rowid<=?']
            values = [workspace, after, through]
            if state != 'all':
                filters.append('state=?'); values.append(state)
            if label_query is not None:
                filters.append('instr(label,?)>0'); values.append(label_query)
            rows = db.execute('SELECT rowid,session_id,workspace,label,created,state FROM sessions WHERE '
                              + ' AND '.join(filters) + ' ORDER BY rowid LIMIT ?', (*values, limit + 1)).fetchall()
        result = {'ok': True, 'workspace': workspace, 'sessions': [], 'through': through,
                  'next_after': None, 'state_filter': state, 'label_query': label_query,
                  'snapshot_atomic': False, 'scope': 'creation_bounded_metadata_state_observed_per_page',
                  'authority': 'discovery_only',
                  'continuation': 'Keep workspace, state_filter, label_query and through unchanged; use next_after as after. State changes can change filtered membership.'}
        if response_size(result) > max_bytes:
            raise WorkbenchError('response_budget', 'The listing metadata exceeds this response budget; increase max_bytes.')
        for row in rows[:limit]:
            item = dict(zip(('creation_cursor', 'session_id', 'workspace', 'label', 'created_at', 'state'), row))
            candidate = {**result, 'sessions': result['sessions'] + [item], 'next_after': row[0]}
            # The terminal null cursor can be longer than a small integer;
            # long continuation cursors can instead be larger than null.
            if max(response_size(candidate), response_size({**candidate, 'next_after': None})) > max_bytes:
                if not result['sessions']:
                    raise WorkbenchError('response_budget', 'One session metadata row exceeds this response budget; increase max_bytes.')
                break
            result['sessions'].append(item)
        if len(rows) > len(result['sessions']):
            result['next_after'] = result['sessions'][-1]['creation_cursor']
        return result

    def inspect(self,session_id,after=0,through=None,limit=20,max_bytes=8192):
        session=self.ensure(session_id,allow_closed=True)
        if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=100 or type(max_bytes) is not int or not 4096<=max_bytes<=262144:
            raise WorkbenchError('invalid_range','Use a nonnegative cursor, limit 1..100 and max_bytes 4096..262144.')
        with self.db() as db:
            high=db.execute('SELECT COALESCE(MAX(sequence),0) FROM events WHERE session_id=?',(session_id,)).fetchone()[0]
            if through is None:through=high
            if type(through) is not int or not 0<=after<=through<=high:
                raise WorkbenchError('invalid_cursor','Work-session cursor is outside its current event history.')
            rows=db.execute('SELECT sequence,event_id,created,payload FROM events WHERE session_id=? AND sequence>? AND sequence<=? ORDER BY sequence LIMIT ?',
                            (session_id,after,through,limit+1)).fetchall()
        result={'ok':True,**session,'events':[],'through':through,'next_after':None,
                'scope':'explicitly attributed calls and caller notes; unrelated or pre-upgrade history is not inferred'}
        result.update(self._resource_details(session_id, session['workspace']))
        for row in rows[:limit]:
            event={'sequence':row[0],'event_id':row[1],'created_at':row[2],'event':json.loads(row[3])}
            candidate={**result,'events':result['events']+[event],'next_after':row[0]}
            if response_size(candidate)>max_bytes:
                if result['events']:break
                artifact=self.store.put_bytes(json.dumps(event,ensure_ascii=True).encode(),'work-session-event:'+row[1])
                event={'sequence':row[0],'event_id':row[1],'event_artifact':artifact,'view_complete':False}
            result['events'].append(event)
        if len(rows)>len(result['events']):result['next_after']=result['events'][-1]['sequence']
        return result

    @staticmethod
    def _artifact_ids(value, field=None):
        if isinstance(value, str) and (field in ('artifact', 'artifact_id', 'artifacts', 'artifact_ids', 'reference') or
                isinstance(field, str) and field.endswith('_artifact')) and re.fullmatch(r'sha256:[0-9a-f]{64}', value):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                if key not in ('text', 'data', 'value', 'content', 'argv', 'env'):
                    yield from WorkSessions._artifact_ids(item, key)
        elif isinstance(value, list):
            for item in value:
                yield from WorkSessions._artifact_ids(item, field)

    @staticmethod
    def _capture_ids(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key == 'capture_id' or key.endswith('_capture_id')) and isinstance(item, str) and re.fullmatch(r'[0-9a-f]{32}', item):
                    yield item
                elif isinstance(item, (dict, list)) and key not in ('text', 'data', 'value', 'content', 'argv', 'env'):
                    yield from WorkSessions._capture_ids(item)
        elif isinstance(value, list):
            for item in value:
                yield from WorkSessions._capture_ids(item)

    def _events(self, session_id):
        with self.db() as db:
            rows = db.execute('SELECT sequence,event_id,created,payload FROM events WHERE session_id=? ORDER BY sequence LIMIT 10001',
                              (session_id,)).fetchall()
        if len(rows) > 10000:
            raise WorkbenchError('history_limit', 'This operation supports at most 10000 events. Read the full history through work_session_inspect; no evidence was silently omitted.')
        return [{'sequence': row[0], 'event_id': row[1], 'created_at': row[2], 'event': json.loads(row[3])}
                for row in rows]

    def verify(self, session_id, criterion, method, reference, expected, request_id, revision_artifact=None):
        self.ensure(session_id)
        if not isinstance(criterion, str) or not 1 <= len(criterion.encode()) <= 2000:
            raise WorkbenchError('invalid_criterion', 'Use a criterion of 1..2000 UTF-8 bytes.')
        if method not in ('artifact_sha256', 'job_exit'):
            raise WorkbenchError('invalid_verification', 'Choose artifact_sha256 or job_exit; caller notes cannot establish a verified pass.')
        if revision_artifact is not None:
            revision = self.store.verify(revision_artifact)
            if not revision['verified']:
                raise WorkbenchError('artifact_corrupt', 'The supplied test revision did not verify.')
        events = self._events(session_id)
        if method == 'artifact_sha256':
            if reference not in set(self._artifact_ids(events)):
                raise WorkbenchError('evidence_not_linked', 'Link this artifact to the selected session before verifying it.')
            if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
                raise WorkbenchError('invalid_verification', 'Expected a full SHA-256 digest.')
        elif type(expected) is not int or not -255 <= expected <= 255:
            raise WorkbenchError('invalid_verification', 'Expected an explicit integer exit code.')
        def check():
            if method == 'artifact_sha256':
                observation = self.store.verify(reference)
                passed = observation['verified'] and observation['actual_sha256'] == expected
                state = 'passed' if passed else 'failed'
            else:
                if self.jobs is None:
                    raise WorkbenchError('verification_unavailable', 'No job observer is attached.')
                observation = self.jobs.status(reference, detail=True)
                if observation.get('work_session_id') != session_id:
                    raise WorkbenchError('work_session_mismatch', 'The test job is not attributed to this session.')
                if observation['status'] in ('starting', 'running') or not observation.get('output_complete'):
                    state = 'pending'
                else:
                    state = 'passed' if observation['status'] == 'completed' and observation['exit_code'] == expected else 'failed'
                observation = {key: observation.get(key) for key in
                    ('job_id', 'status', 'exit_code', 'output_complete', 'artifacts', 'finished_at', 'termination_reason')}
            event = {'kind': 'criterion_observation', 'criterion': criterion, 'implementation_state': 'evidence_observed',
                     'method': method, 'method_version': 1, 'reference': reference, 'expected': expected,
                     'revision_artifact': revision_artifact, 'observed_at': time.time(), 'outcome': state,
                     'observation': observation, 'scope': 'Only the named hash or exit condition; broader application behavior requires its own evidence.'}
            self._append(session_id, 'criterion:' + request_id, event)
            return {'ok': True, 'work_session_id': session_id, 'event_id': 'criterion:' + request_id,
                    'outcome': state, 'observation': observation, 'scope': event['scope']}
        return self.journal.run(request_id, {'tool': 'work_session_verify', 'session_id': session_id,
            'criterion': criterion, 'method': method, 'reference': reference, 'expected': expected,
            'revision_artifact': revision_artifact}, check, resource='work-session:' + session_id)

    def export(self, session_id, request_id, redact_terms=None, max_bytes=67108864, include_sensitive=False):
        session = self.ensure(session_id, allow_closed=True)
        terms = [] if redact_terms is None else redact_terms
        if not isinstance(terms, list) or len(terms) > 100 or any(not isinstance(term, str) or not 1 <= len(term.encode()) <= 1024 for term in terms):
            raise WorkbenchError('invalid_redaction', 'Use at most 100 nonempty literal redaction terms of at most 1024 bytes.')
        if type(max_bytes) is not int or not 4096 <= max_bytes <= self.config.max_artifact_bytes:
            raise WorkbenchError('invalid_range', 'Export budget must be 4096 bytes through the configured artifact limit.')
        if type(include_sensitive) is not bool:
            raise WorkbenchError('invalid_export_scope', 'include_sensitive must be an explicit Boolean.')
        terms = [term.encode() for term in terms]
        def build():
            events = self._events(session_id)
            def redact_text(value):
                raw = value.encode()
                for term in terms:
                    raw = raw.replace(term, b'[REDACTED]')
                return raw.decode()
            session['label'] = redact_text(session['label'])
            manifest = {'schema_version': 1, 'work_session': session, 'created_at': time.time(),
                        'through': events[-1]['sequence'] if events else 0, 'members': [], 'captures': [], 'gaps': [],
                        'redaction_term_count': len(terms), 'scope': 'Selected attributed lineage; unknown legacy ownership is not inferred.'}
            manifest['sensitive_results_included'] = include_sensitive
            receipts = {event['event']['request_id']: self.journal.status(event['event']['request_id'])
                        for event in events if event['event'].get('request_id')}
            original_receipts = json.dumps(receipts, ensure_ascii=False).encode()
            receipts_limited = False
            if not include_sensitive:
                for identifier, receipt in receipts.items():
                    result = receipt.get('result')
                    if isinstance(result, dict) and result.get('potentially_sensitive') is True:
                        receipt['result'] = {key: result[key] for key in ('ok', 'lease_id', 'profile_id', 'document_generation',
                            'server_generation', 'effect_state', 'potentially_sensitive') if key in result}
                        receipt['result']['details_omitted'] = 'sensitive_result'
                        receipts_limited = True
                        manifest['gaps'].append({'request_id': identifier, 'reason': 'sensitive_receipt_details_omitted'})
            job_ids = {event['event'].get('references', {}).get('job_id') for event in events}
            job_ids.discard(None)
            jobs = {}
            for identifier in sorted(job_ids):
                if self.jobs is None:
                    manifest['gaps'].append({'job_id': identifier, 'reason': 'job_observer_unavailable'})
                    continue
                try:
                    observed = self.jobs.evidence(identifier)
                    if observed.get('work_session_id') != session_id:
                        raise WorkbenchError('work_session_mismatch', 'The job ownership does not match this session.')
                    if observed.get('publication_state') != 'published':
                        manifest['gaps'].append({'job_id': identifier, 'reason': 'job_output_not_fully_published'})
                    jobs[identifier] = observed
                except WorkbenchError as error:
                    manifest['gaps'].append({'job_id': identifier, 'reason': error.code})
            capture_ids = set(self._capture_ids(events)) | set(self._capture_ids(jobs))
            manifest['receipt_observation_scope'] = 'Journal and job status observed during export; the event cutoff is through. This is not an atomic cross-database snapshot.'
            budget = 0
            def member(packet, name, raw, source_sha256=None, privacy_limited=False):
                nonlocal budget
                original_digest = hashlib.sha256(raw).hexdigest()
                changes = 0
                for term in terms:
                    changes += raw.count(term)
                    raw = raw.replace(term, b'[REDACTED]')
                budget += len(raw)
                if budget > max_bytes:
                    raise WorkbenchError('export_limit', 'The complete packet exceeds its declared budget; increase it rather than silently omitting evidence.',
                                         observed_bytes=budget, max_bytes=max_bytes)
                packet.writestr(name, raw)
                manifest['members'].append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                    'source_sha256': source_sha256 or original_digest,
                    'variant': ('privacy_limited_redacted' if changes else 'privacy_limited') if privacy_limited else 'redacted' if changes else 'original',
                    'redaction_count': changes})
            with tempfile.TemporaryFile(dir=self.store.temporary) as temp:
                with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_STORED) as packet:
                    member(packet, 'events.json', json.dumps(events, ensure_ascii=False).encode())
                    member(packet, 'receipts.json', json.dumps(receipts, ensure_ascii=False).encode(),
                           hashlib.sha256(original_receipts).hexdigest(), receipts_limited)
                    member(packet, 'jobs.json', json.dumps(jobs, ensure_ascii=False).encode())
                    for artifact_id in sorted(set(self._artifact_ids(events)) | set(self._artifact_ids(receipts)) | set(self._artifact_ids(jobs))):
                        try:
                            with self.store._db() as db:
                                captures = db.execute('SELECT capture_id,source,created FROM artifact_captures WHERE sha256=? ORDER BY created,capture_id',
                                                      (artifact_id[7:],)).fetchall()
                            selected_captures = [row for row in captures if row[0] in capture_ids] or captures
                            sensitive = False
                            for row in selected_captures:
                                try: source_metadata = json.loads(row[1])
                                except (ValueError, TypeError): continue
                                if isinstance(source_metadata, dict) and source_metadata.get('potentially_sensitive') is True:
                                    sensitive = True
                            if sensitive and not include_sensitive:
                                manifest['gaps'].append({'artifact_id': artifact_id, 'reason': 'sensitive_artifact_omitted'})
                                continue
                            with self.store.reading(artifact_id) as source:
                                raw = source.read(max_bytes + 1)
                            if len(raw) > max_bytes:
                                raise WorkbenchError('export_limit', 'One artifact exceeds the packet budget.', artifact_id=artifact_id)
                            if hashlib.sha256(raw).hexdigest() != artifact_id[7:]:
                                manifest['gaps'].append({'artifact_id': artifact_id, 'reason': 'integrity_mismatch'})
                                continue
                            member(packet, 'artifacts/' + artifact_id[7:], raw, artifact_id[7:])
                            # Captures are only included when their explicit IDs occur in this session.
                            manifest['captures'].extend({'capture_id': row[0], 'artifact_id': artifact_id,
                                'source': redact_text(row[1]), 'created_at': row[2]} for row in captures if row[0] in capture_ids)
                        except WorkbenchError as error:
                            if error.code not in ('unknown_artifact', 'artifact_reclaimed'):
                                raise
                            manifest['gaps'].append({'artifact_id': artifact_id, 'reason': 'reclaimed' if error.code == 'artifact_reclaimed' else 'missing'})
                    manifest['packet_complete'] = not manifest['gaps']
                    manifest_bytes = json.dumps(manifest, ensure_ascii=True, sort_keys=True).encode()
                    if budget + len(manifest_bytes) > max_bytes:
                        raise WorkbenchError('export_limit', 'Packet metadata exceeds the complete export budget.')
                    packet.writestr('manifest.json', manifest_bytes)
                temp.seek(0)
                with zipfile.ZipFile(temp) as packet:
                    for item in manifest['members']:
                        raw = packet.read(item['path'])
                        if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                            raise WorkbenchError('export_integrity', 'A packet member failed its integrity check.')
                temp.seek(0)
                artifact = self.store.put_stream(temp, 'work-session-export:' + session_id)
            return {'ok': True, 'work_session_id': session_id, 'export_artifact': artifact,
                    'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(), 'through': manifest['through'],
                    'member_count': len(manifest['members']), 'packet_complete': manifest['packet_complete'],
                    'gaps': manifest['gaps'], 'redaction_term_count': len(terms),
                    'delivery': 'ZIP artifact; retrieve exact bytes with artifact_read. No client-download attachment is implied.'}
        return self.journal.run(request_id, {'tool': 'work_session_export', 'session_id': session_id,
            'redaction_term_hashes': [hashlib.sha256(term).hexdigest() for term in terms], 'max_bytes': max_bytes,
            'include_sensitive': include_sensitive}, build,
            resource='work-session:' + session_id)
