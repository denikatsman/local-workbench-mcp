"""Bounded, retained admission for one ordinary browser evaluator per claim."""
import contextlib
import contextvars
import copy
import hashlib
import json
import sqlite3
import threading
import time
import uuid

from .context import work_context, work_admission
from .errors import WorkbenchError
from .browser_wire import ProtocolError


class BrowserEvaluations:
    LIMIT = 4

    def __init__(self, browser):
        self.browser = browser
        self.lock = threading.RLock()
        self.tasks = {}
        self.closing = False

    @staticmethod
    def payload_hash(payload):
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

    def _custody(self, task, workspace, origin, generation, parameters):
        child_payload = {'tool':'selected_browser', 'interaction_version':1, 'workspace':workspace,
                         'action':'evaluate', 'owner_session':task['owner'], 'expected_origin':origin,
                         'expected_generation':generation, 'parameters':parameters}
        return {'version':1, 'parent_request_id':task['parent'], 'operation_request_id':task['child'],
                'workspace':workspace, 'owner_session':task['owner'], 'binding':copy.deepcopy(task['binding']),
                'parent_payload_hash':self.payload_hash(task['payload']), 'child_payload_hash':self.payload_hash(child_payload)}

    def _validate_custody(self, custody, parent, payload_hash):
        fields = {'version','parent_request_id','operation_request_id','workspace','owner_session',
                  'binding','parent_payload_hash','child_payload_hash'}
        if (not isinstance(custody,dict) or set(custody)!=fields or custody['version']!=1
                or custody['parent_request_id']!=parent or custody['parent_payload_hash']!=payload_hash
                or not isinstance(custody['binding'],dict) or not isinstance(custody['owner_session'],str) or not custody['owner_session']
                or not isinstance(custody['workspace'],str)
                or custody['binding'].get('owner_session')!=custody['owner_session']
                or not all(custody['binding'].get(k) is not None for k in ('claim_id','claim_epoch',
                    'installation_id','runtime_generation','peer_id','target_id','target_generation',
                    'browser_target_id','tab_id','profile_id','context_id','context_kind','connection_generation',
                    'frame_id','loader_id','document_epoch','origin'))):
            raise WorkbenchError('browser_evaluation_history_invalid','Preserve the original typed evaluator custody.',effect_state='none')
        self.browser.journal.validate_id(custody['operation_request_id'])
        return custody

    def _replayed(self, request_id, payload, record):
        result = record['result']
        if record['state']=='failed' and isinstance(result,dict) and isinstance(result.get('error'),dict):
            error=result['error']; details={k:v for k,v in error.items() if k not in ('code','message')}
            raise WorkbenchError(error['code'],error['message'],**{**details,'replayed':True,
                'applied_this_call':False,'original_request_id':request_id})
        if not isinstance(result,dict):
            raise WorkbenchError('browser_evaluation_history_invalid','The original admission has no typed receipt.',effect_state='unknown')
        self._validate_custody(result.get('evaluation_custody'),request_id,self.payload_hash(payload))
        if record['state']=='pending':
            raise WorkbenchError('operation_uncertain','Inspect the original pending admission and child; never restart it.',
                                 request_id=request_id,operation_request_id=result['evaluation_custody']['operation_request_id'])
        if record['state']!='completed' or result.get('kind')!='browser_evaluation_admission' or result.get('admission')!='durable':
            raise WorkbenchError('browser_evaluation_history_invalid','The original admission is not a valid completed receipt.',effect_state='unknown')
        return {**result,'replayed':True}

    @contextlib.contextmanager
    def _history_rows(self, query):
        # One read-only snapshot, including child lookups. A streaming outer
        # reader plus a second connection can deadlock a waiting journal writer.
        # Do not change synchronous mode or materialize all historical receipts.
        uri = self.browser.journal.path.resolve().as_uri() + '?mode=ro'
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=30)) as db:
            yield db, db.execute(query)

    def _entries(self):
        # Ownership comes from typed durable parents, never a caller-controlled ID prefix.
        entries={}
        with self._history_rows("SELECT request_id,payload_hash,state,result FROM operations WHERE result LIKE '%\"evaluation_custody\"%' OR result LIKE '%\"child_state_at_admission\"%' OR result LIKE '%\"browser_evaluation_admission\"%'") as (db, parents):
            for parent,payload_hash,state,raw in parents:
                value=json.loads(raw)
                custody=value.get('evaluation_custody') if value.get('kind')=='browser_evaluation_admission' else value.get('error',{}).get('evaluation_custody')
                if custody is None:
                    # Unshipped524 records lack full custody: retain attribution, never upgrade it.
                    if (value.get('kind')=='browser_evaluation_admission' or value.get('admission')=='durable' and value.get('child_state_at_admission')=='pending'):
                        child=value.get('operation_request_id')
                        child_record=db.execute('SELECT state FROM operations WHERE request_id=?',(child,)).fetchone()
                        if child_record and child_record[0]=='pending':
                            entries[child]={'custody':None,'owner':value['owner_session'],'claim_id':value['claim_id'],'corrupt':True,'linked':False}
                    continue
                custody=self._validate_custody(custody,parent,payload_hash); child=custody['operation_request_id']
                row=db.execute('SELECT payload_hash,state,result FROM operations WHERE request_id=?',(child,)).fetchone()
                if row and row[1]=='pending':
                    try:
                        child_value=json.loads(row[2]) if row[2] else {}
                    except (ValueError,TypeError):
                        child_value={}
                    linked=row[0]==custody['child_payload_hash']
                    child_typed=linked and child_value.get('kind')=='browser_evaluation_child' and child_value.get('evaluation_custody')==custody
                    reserved = state=='completed' or value.get('child_reserved') is True or value.get('error',{}).get('child_reserved') is True
                    if not reserved and not child_typed:
                        continue  # A declared ID whose reservation conflicted never owned the unrelated operation.
                    entries[child]={'custody':custody,'owner':custody['owner_session'],'claim_id':custody['binding']['claim_id'],
                        'linked':linked,'corrupt':not child_typed}
        return entries

    def _absence_matches(self, custody, row):
        try:
            valid = self.browser._retired_absent_resource(row)
        except (ProtocolError, KeyError, TypeError):
            return False
        if custody is None or not valid: return False
        binding=custody['binding']; proof=row['resource_retirement']; target=row['target']
        if (any(row.get(k)!=binding[k] for k in ('claim_id','owner_session','installation_id','runtime_generation'))
                or type(row.get('claim_epoch')) is not int or row['claim_epoch']<binding['claim_epoch']
                or any(target.get(k)!=binding[k] for k in ('target_id','target_generation','browser_target_id',
                    'tab_id','profile_id','context_id','context_kind','connection_generation'))): return False
        if proof['peer_id']==binding['peer_id'] and proof['runtime_generation']==binding['runtime_generation']: return True
        historical=row.get('cleanup_binding')
        return (isinstance(historical,dict) and historical.get('action')=='cleanup'
            and all(historical.get(k)==binding[k] for k in ('claim_id','owner_session','installation_id',
                'target_id','target_generation','profile_id','context_id','context_kind'))
            and historical.get('original_runtime_generation')==binding['runtime_generation']
            and historical.get('current_runtime_generation')==proof['runtime_generation']
            and historical.get('peer_id')==proof['peer_id'])

    def absence_witnesses(self, result, cleanup_request_id, payload):
        if not result.get('resource_retirement'): return []
        witnesses=[]
        for entry in self._entries().values():
            custody=entry['custody']
            if (entry['linked'] and custody['workspace']==payload['workspace']
                    and self._absence_matches(custody,result)):
                witnesses.append({'version':1,'custody':custody,'cleanup_request_id':cleanup_request_id,
                                  'cleanup_payload_hash':self.payload_hash(payload)})
        return witnesses

    def _retired(self, entries):
        retired=set()
        with self._history_rows("SELECT request_id,payload_hash,result FROM operations WHERE state='completed' AND result LIKE '%\"browser_evaluation_retirements\"%'") as (_, rows):
            for identifier,payload_hash,raw in rows:
                row=json.loads(raw)
                for witness in row.get('browser_evaluation_retirements',[]):
                    custody=witness.get('custody'); child=custody.get('operation_request_id') if isinstance(custody,dict) else None
                    entry=entries.get(child)
                    if (entry and entry['linked'] and witness.get('version')==1 and entry['custody']==custody
                            and witness.get('cleanup_request_id')==identifier and witness.get('cleanup_payload_hash')==payload_hash
                            and self._absence_matches(custody,row)):
                        retired.add(child)
        return retired

    def _active_snapshot(self, owner=None):
        entries=self._entries(); retired=self._retired(entries); close=[]
        result={child for child,entry in entries.items() if child not in retired and (owner is None or entry['owner']==owner)}
        with self.lock:
            for parent,task in list(self.tasks.items()):
                thread=task.get('thread')
                if task['child'] in retired and thread is not None and not thread.is_alive():
                    self.tasks.pop(parent); close.append(task['pins'])
                elif owner is None or task['owner']==owner: result.add(task['child'])
        # No evaluator lock may be held while releasing session/activity pins.
        for pins in close: pins.close()
        return sorted(result), entries

    def active_ids(self, owner=None):
        return self._active_snapshot(owner)[0]

    def start(self, workspace, request_id, expected_origin, expected_generation, max_bytes, parameters, cancel=None, disconnect=None):
        b = self.browser
        b.journal.validate_id(request_id)
        owner = work_context.get()
        parameters = copy.deepcopy(parameters)
        payload = {'tool': 'browser_evaluate_start', 'workspace': workspace, 'owner_session': owner,
                   'expected_origin': expected_origin, 'expected_generation': expected_generation,
                   'max_bytes': max_bytes, 'parameters': parameters}
        recovered = b.journal.recover(request_id, payload)
        if recovered is not None:
            # Reuse the Journal's exact conflict/error/pending semantics, never a new child.
            return self._replayed(request_id,payload,recovered)
        try:
            expression_bytes = parameters['expression'].encode('utf-8') if isinstance(parameters.get('expression'), str) else None
        except UnicodeEncodeError:
            expression_bytes = None
        if expression_bytes is None or len(expression_bytes) > 65536:
            raise WorkbenchError('invalid_expression', 'Use a bounded evaluator expression.', effect_state='none')
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes4096..262144.', effect_state='none')
        if any(event is not None and event.is_set() for event in (cancel, disconnect)):
            raise WorkbenchError('browser_evaluation_interrupted', 'The admission was cancelled before reservation.', effect_state='none')
        binding = b._evaluation_preflight(owner, expected_origin, expected_generation, parameters)
        pins = contextlib.ExitStack()
        task = None
        reused = False
        try:
            if b.activity_gate is not None:
                pins.enter_context(b.activity_gate.admission())
            if b.sessions is not None:
                pins.enter_context(b.sessions.retain(owner))
            active, entries = self._active_snapshot()
            with self.lock:
                task = self.tasks.get(request_id)
                if task is not None:
                    if task['payload'] != payload:
                        raise WorkbenchError('request_conflict', 'This request_id was already used with different arguments.')
                    reused = True
                else:
                    if self.closing or b.stopped.is_set():
                        raise WorkbenchError('browser_evaluation_stopping', 'The evaluator is stopping.', effect_state='none')
                    # Include admissions registered since the durable snapshot.
                    active = set(active) | {t['child'] for t in self.tasks.values()}
                    if any(entries[child]['claim_id']==parameters['claim_id'] for child in active
                           if child in entries and child not in {t['child'] for t in self.tasks.values()}):
                        raise WorkbenchError('browser_evaluation_pending', 'Reconcile this claim original interrupted evaluator.', effect_state='none')
                    if len(active) >= self.LIMIT:
                        raise WorkbenchError('browser_evaluation_capacity', 'Finish existing evaluators before admitting another.', effect_state='none')
                    if any(t['claim_id'] == parameters['claim_id'] for t in self.tasks.values()):
                        raise WorkbenchError('browser_evaluation_pending', 'This claim already has a retained evaluator.', effect_state='none')
                    task = {'parent': request_id, 'child': 'browser-evaluate:' + uuid.uuid4().hex,
                            'owner': owner, 'claim_id': parameters['claim_id'], 'payload': payload, 'binding': binding,
                            'ready': threading.Event(), 'gate': threading.Event(), 'abort': threading.Event(),
                            'parent_done': threading.Event(), 'pins': pins, 'cancel': cancel, 'disconnect': disconnect}
                    task['custody']=self._custody(task,workspace,expected_origin,expected_generation,parameters)
                    self.tasks[request_id] = task
            if reused:
                pins.close()
                if not task['parent_done'].wait(3):
                    raise WorkbenchError('browser_evaluation_admission_pending', 'Inspect the original admission request.', request_id=request_id, effect_state='unknown')
                recovered=b.journal.recover(request_id,payload)
                if recovered is None:
                    if task.get('parent_error') is not None: raise task['parent_error']
                    raise WorkbenchError('browser_evaluation_admission_failed','The original admission was not reserved.',effect_state='none')
                return self._replayed(request_id,payload,recovered)
            checkpoint = self.checkpoint(task)
            def admit():
                b.journal.checkpoint(request_id, {**checkpoint, 'kind': 'browser_evaluation_admission'})
                context = contextvars.copy_context()
                context.run(work_admission.set, None)
                thread = threading.Thread(target=context.run, args=(self._run, task, workspace, expected_origin,
                    expected_generation, max_bytes, parameters), name='browser-evaluation-' + task['child'][-12:], daemon=False)
                task['thread'] = thread
                thread.start()
                if not task['ready'].wait(3) or not task.get('reserved') or task.get('reservation_error') is not None:
                    raise WorkbenchError('browser_evaluation_admission_failed', 'The evaluator was not durably admitted.',
                                         operation_request_id=task['child'], evaluation_custody=task['custody'],
                                         child_reserved=task.get('reserved') is True, effect_state='none')
                b.journal.checkpoint(request_id, {**checkpoint,'kind':'browser_evaluation_admission','child_reserved':True})
                return {'ok': True, 'kind':'browser_evaluation_admission', 'evaluation_custody':task['custody'], 'request_id': request_id, 'operation_request_id': task['child'],
                        'admission': 'durable', 'child_state_at_admission': 'pending', 'effect_state': 'not_established',
                        'task_completion': 'not_established', 'owner_session': owner, 'claim_id': task['claim_id'],
                        'server_generation': b.instance_id,
                        'scope': 'Admission only; inspect the original child operation_status. Never redispatch after uncertainty.'}
            result = b.journal.run(request_id, payload, admit,
                                   initial_checkpoint={**checkpoint, 'kind': 'browser_evaluation_admission'})
            self.check(task)
            task['gate'].set()  # Parent receipt has committed; only now may child dispatch.
            return result
        except BaseException as error:
            if task is not None and not reused: task['parent_error']=error
            if task is not None and not reused:
                task['abort'].set(); task['gate'].set()
                if 'thread' not in task or not task['thread'].is_alive():
                    with self.lock:
                        self.tasks.pop(request_id, None)
                    pins.close()
            else:
                pins.close()
            raise
        finally:
            if task is not None and not reused:
                task['parent_done'].set()

    def checkpoint(self, task):
        return {'evaluation_custody':task['custody'], 'kind': 'browser_evaluation_child', 'phase': 'browser_evaluate_reserved',
                'parent_request_id': task['parent'], 'operation_request_id': task['child'],
                'owner_session': task['owner'], 'claim_id': task['claim_id'],
                'runtime_generation': self.browser.instance_id, 'effect_state': 'unknown'}

    def check(self, task, after_dispatch=False):
        if (task['abort'].is_set() or self.closing or self.browser.stopped.is_set()
                or any(event is not None and event.is_set() for event in (task['cancel'], task['disconnect']))):
            raise WorkbenchError('browser_evaluation_interrupted', 'The original evaluator was interrupted; inspect its child receipt.',
                                 effect_state='unknown' if after_dispatch else 'none')

    def reserved(self, task):
        task['reserved']=True
        task['ready'].set()
        if not task['gate'].wait(5):
            task['abort'].set()
        self.check(task)

    def _run(self, task, workspace, origin, generation, max_bytes, parameters):
        try:
            self.browser._durable_operation(workspace, 'evaluate', origin, generation, task['child'], max_bytes,
                                            _evaluation_admission=task, **parameters)
        except BaseException as error:
            if not task['ready'].is_set():
                task['reservation_error'] = str(error)
        finally:
            task['ready'].set()
            try:
                durable = self.browser.journal.status(task['child'])['state'] in ('completed', 'failed', 'not_found')
            except Exception:
                durable = False
            if durable:
                with self.lock:
                    self.tasks.pop(task['parent'], None)
                task['pins'].close()
            # A pending/ambiguous finalization keeps ownership pins and history.

    def close(self):
        with self.lock:
            self.closing = True
            tasks = list(self.tasks.values())
            for task in tasks:
                task['abort'].set(); task['gate'].set()
        deadline = time.monotonic() + 12
        for task in tasks:
            if thread := task.get('thread'):
                thread.join(max(0, deadline - time.monotonic()))
        if any(task.get('thread') and task['thread'].is_alive() for task in tasks):
            raise WorkbenchError('browser_evaluation_unsettled', 'Evaluator shutdown did not settle; preserve its original history.', effect_state='unknown')
