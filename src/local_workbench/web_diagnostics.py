"""Durable opt-in test-chat evidence. No network client or page-control code."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .errors import WorkbenchError
from .persistence import atomic_json

CHAT = re.compile(r'/c/[0-9a-fA-F-]{36}/?\Z')
PROJECT_CHAT = re.compile(r'/g/g-p-[a-f0-9]{32}(?:-[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?)?/c/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/?\Z', re.I)
IMMUTABLE = ('claim_id','owner_session','installation_id','runtime_generation','peer_id',
             'target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind')
SECRET = re.compile(r'^token$|authorization|cookie|password|secret|access.?token|refresh.?token|id.?token|api.?key|csrf|credential|session.?token',re.I)


def chat_scope(url):
    try:
        u=urlsplit(url)
        project=PROJECT_CHAT.fullmatch(u.path)
        if project and url!='https://chatgpt.com'+u.path:raise ValueError()
        if u.scheme!='https' or u.netloc!='chatgpt.com' or u.query or u.fragment or not (u.path=='/' or CHAT.fullmatch(u.path) or project):raise ValueError()
    except (ValueError,TypeError):
        raise WorkbenchError('diagnostic_chat_scope','Opt in to one exact ordinary ChatGPT test-chat URL.',effect_state='none')
    return 'https://chatgpt.com'+('/c/'+project[1].lower() if project else '/' if u.path=='/' else u.path.rstrip('/'))


def clean(value, depth=0):
    """Defense in depth for worker redaction; never copy header dictionaries."""
    if depth>20:return '[depth limit]'
    if isinstance(value,dict):
        return {str(k):('[redacted]' if SECRET.search(str(k)) or str(k).lower().endswith('headers')
                        else clean(v,depth+1))for k,v in value.items()}
    if isinstance(value,list):return [clean(v,depth+1)for v in value]
    if isinstance(value,str):
        # Serialized public results need structural filtering before URL
        # normalization can consume their escaped JSON quote boundaries.
        if value.lstrip().startswith(('{','[')):
            try:nested=json.loads(value)
            except (ValueError,RecursionError):pass
            else:
                if isinstance(nested,(dict,list)):
                    return json.dumps(clean(nested,depth+1),ensure_ascii=True,separators=(',',':'))
        value=re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+','Bearer [redacted]',value)
        def url(match):
            try:
                u=urlsplit(match[0]); host=u.hostname or ''
                if u.port:host+=':'+str(u.port)
                query=urlencode([(k,'[redacted]' if re.search(r'^(?:sig|googleaccessid|policy)$|token|key|auth|secret|password|cookie|signature|credential|csrf',k,re.I) else v)for k,v in parse_qsl(u.query,keep_blank_values=True)])
                return urlunsplit((u.scheme,host,u.path,query,''))
            except ValueError:return '[invalid URL]'
        return re.sub(r'https?://[^\s<>\"\']+',url,value,flags=re.I)
    return value


class WebDiagnostics:
    def __init__(self, root, store):
        self.root=Path(root)/'web-diagnostics';self.store=store;self.lock=threading.RLock();self.records={};self.pending_bodies={}
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        mode=self.root.lstat()
        if not stat.S_ISDIR(mode.st_mode)or mode.st_mode&0o077 or mode.st_uid!=os.getuid():
            raise WorkbenchError('diagnostic_storage_private','Diagnostic storage must be an owned private directory.',effect_state='none')
        for file in self.root.glob('*.json'):
            row=self._read_private(file)
            if row.get('record_id')!=file.stem or not re.fullmatch('[0-9a-f]{32}',file.stem):
                raise WorkbenchError('diagnostic_history_invalid','Preserve diagnostic history.',effect_state='none')
            # Startup restores evidence, never a recording process/claim.
            if row['status']in('starting','recording'):
                row['status']='interrupted';row['gaps'].append({'kind':'collector_restart_capture_not_resumed'})
            journal=self.root/(file.stem+'.jsonl')
            info=journal.lstat()
            if not stat.S_ISREG(info.st_mode)or info.st_mode&0o077 or info.st_uid!=os.getuid():
                raise WorkbenchError('diagnostic_storage_private','Original journal must remain private.',effect_state='none')
            row['event_count']=0;row['stored_bytes']=info.st_size
            with journal.open('rb')as stream:
                while line:=stream.readline(120001):
                    try:
                        if len(line)>120000:raise ValueError()
                        event=json.loads(line);row['last_sequence']=max(row['last_sequence'],event['sequence']);row['event_count']+=1
                        row['last_source_sequence']=max(row.get('last_source_sequence',0),event.get('source_sequence',event['sequence']))
                    except (ValueError,KeyError,TypeError):
                        row['gaps'].append({'kind':'partial_journal'});break
            self.records[file.stem]=row

    @staticmethod
    def _read_private(path):
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_mode&0o077 or info.st_uid!=os.getuid():
            raise WorkbenchError('diagnostic_storage_private','Evidence must be owned private regular files.',effect_state='none')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb')as stream:return json.load(stream)

    def _owned(self, identifier, owner):
        row=self.records.get(identifier)
        if row is None or row['owner_session']!=owner:
            raise WorkbenchError('diagnostic_owner_mismatch','Use the original diagnostic owner and record.',effect_state='none')
        return row

    def _save(self,row):atomic_json(self.root/(row['record_id']+'.json'),row)

    def create(self, identifier, owner, workspace, target, url, max_bytes, start_request, body_bytes=8388608, stream_buffer_bytes=None):
        chat=chat_scope(url)
        if stream_buffer_bytes is not None and (type(stream_buffer_bytes)is not int or not 8192<=stream_buffer_bytes<=67108864):
            raise WorkbenchError('diagnostic_stream_limit','Use an aggregate retained-prefix budget from 8192 through 67108864 bytes.',effect_state='none')
        if (target.get('context_kind')!='ordinary' or target.get('origin')!='https://chatgpt.com'
                or not re.fullmatch('[0-9a-f]{32}',identifier)or max_bytes is not None and (type(max_bytes)is not int or max_bytes<1024*1024)):
            raise WorkbenchError('diagnostic_scope','Use an opted-in ordinary test target and an optional explicit storage budget.',effect_state='none')
        with self.lock:
            if identifier in self.records:raise WorkbenchError('diagnostic_exists','Recover the original start request.',effect_state='none')
            path=self.root/(identifier+'.jsonl')
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
            row={'record_id':identifier,'owner_session':owner,'workspace':workspace,'chat_url':chat,
                 'target':target,'binding':None,'start_request_id':start_request,'status':'starting',
                 'created_at':time.time(),'last_sequence':0,'stored_bytes':0,'event_count':0,
                 'max_bytes':max_bytes,'body_bytes':body_bytes,'cdp_resource_buffer_bytes':min(body_bytes,2147483647),'cleanup_required':True,'gaps':[],'pre_attach_gap':True,'causality':'not_established'}
            budget=2097152 if stream_buffer_bytes is None else stream_buffer_bytes
            row.update(stream_buffer_bytes=budget,stream_prefix_byte_limit=min(body_bytes,budget//2),
                       stream_retained_raw_budget_bytes=2*min(body_bytes,budget//2),stream_collector_limit=2,
                       stream_budget_scope='retained_raw_prefix_arrays_including_finalization_not_process_ram')
            if PROJECT_CHAT.fullmatch(urlsplit(url).path):row['observed_document_url']=url
            self.records[identifier]=row;self._save(row)
            return dict(row)

    def bind(self, identifier, owner, binding):
        with self.lock:
            row=self._owned(identifier,owner)
            if row['binding']is not None:raise WorkbenchError('diagnostic_binding_exists','Original binding is immutable.',effect_state='none')
            if binding['context_kind']!='ordinary'or any(binding[k]!=row['target'].get(k)for k in
                    ('target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind')):
                raise WorkbenchError('diagnostic_binding','The observed exact target changed.',effect_state='none')
            row['binding']={k:binding[k]for k in IMMUTABLE};row['status']='recording';self._save(row)

    def ingest(self, identifier, owner, binding, event):
        with self.lock:
            row=self._owned(identifier,owner)
            if row['binding']is None or any(binding.get(k)!=v for k,v in row['binding'].items()):
                raise WorkbenchError('diagnostic_binding','Event changed its original target/owner.',effect_state='none')
            if row['status']!='recording':return False
            if len(json.dumps(event,ensure_ascii=True).encode())>120000:raise WorkbenchError('diagnostic_frame_limit','Event exceeds the native evidence bound.',effect_state='none')
            if not isinstance(event,dict)or type(event.get('sequence'))is not int or event['sequence']<1:
                raise WorkbenchError('diagnostic_event','Invalid event sequence.',effect_state='none')
            sequence=event['sequence'];previous=row.get('last_source_sequence',row['last_sequence'])
            if sequence<=previous:return False
            if sequence!=previous+1:
                gap={'kind':'sequence_gap','after':previous,'next':sequence}
                row['gaps'].append(gap);row['gaps']=row['gaps'][-128:]
                event={**event,'source_sequence_gap':gap}
            row['last_source_sequence']=sequence
            event={**event,'source_sequence':sequence}
            kind=event.get('kind');key=(identifier,event.get('body_id'))
            if kind=='body_begin':
                # Never persist opaque base64 before checking/redacting decoded content.
                if len([k for k in self.pending_bodies if k[0]==identifier])>=2:
                    event={'kind':'body_gap','reason':'host_body_inflight_limit','source_sequence':sequence,'body_id':event.get('body_id')}
                elif (type(event.get('variant_bytes'))is not int or not 0<=event['variant_bytes']<=row.get('body_bytes',8388608)
                      or type(event.get('chunks'))is not int or not 0<=event['chunks']<=1+(event['variant_bytes']+16383)//16384):
                    event={'kind':'body_gap','reason':'host_body_working_memory_limit','source_sequence':sequence,'body_id':event.get('body_id')}
                else:
                    self.pending_bodies[key]={'begin':event,'parts':[],'bytes':0}
                    event={**event,'kind':'body_pending_host_validation'}
            elif kind=='body_chunk':
                pending=self.pending_bodies.get(key)
                if pending is None:return False
                try:
                    part=base64.b64decode(event['data'],validate=True)
                    if event['index']!=len(pending['parts']) or len(part)>16384 or pending['bytes']+len(part)>pending['begin']['variant_bytes']:raise ValueError()
                except (ValueError,KeyError,TypeError):
                    self.pending_bodies.pop(key,None)
                    return self._append(row,{'kind':'body_gap','reason':'invalid_body_chunk','source_sequence':sequence,'body_id':event.get('body_id')})
                pending['parts'].append(part);pending['bytes']+=len(part);return True
            elif kind=='body_end':
                pending=self.pending_bodies.pop(key,None)
                if pending is None:return False
                begin=pending['begin'];raw=b''.join(pending['parts'])
                if (len(pending['parts'])!=begin['chunks'] or len(raw)!=begin['variant_bytes']
                        or hashlib.sha256(raw).hexdigest()!=begin['variant_sha256']):
                    return self._append(row,{'kind':'body_gap','body_id':event.get('body_id'),'reason':'unverified_worker_variant','source_sequence':sequence})
                try:
                    text=raw.decode('utf-8')
                    try:variant=json.dumps(clean(json.loads(text)),ensure_ascii=True,separators=(',',':'))
                    except ValueError:
                        lines=[]
                        for line in text.split('\n'):
                            prefix='data:' if line.startswith('data:') else ''
                            try:line=prefix+json.dumps(clean(json.loads(line[len(prefix):])),ensure_ascii=True,separators=(',',':'))
                            except ValueError:line=clean(line)
                            lines.append(line)
                        variant='\n'.join(lines)
                    cooked=variant.encode();chunks=[cooked[i:i+16384]for i in range(0,len(cooked),16384)]
                except UnicodeError:
                    return self._append(row,{'kind':'body_gap','reason':'invalid_utf8_variant','source_sequence':sequence})
                self._append(row,{**begin,'kind':'body_begin','variant_bytes':len(cooked),'variant_sha256':hashlib.sha256(cooked).hexdigest(),
                    'chunks':len(chunks),'worker_variant_sha256':begin['variant_sha256'],'representation':'worker_and_host_credential_redacted_utf8','source_sequence':sequence})
                for index,part in enumerate(chunks):self._append(row,{'kind':'body_chunk','body_id':event['body_id'],'index':index,'data':base64.b64encode(part).decode(),'source_sequence':sequence})
            return self._append(row,event)

    def _append(self,row,event):
        if row['status']!='recording':return False
        identifier=row['record_id'];event={**event,'sequence':row['last_sequence']+1}
        payload=(json.dumps(clean(event),ensure_ascii=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        if len(payload)>120000:raise WorkbenchError('diagnostic_frame_limit','Event exceeds the native evidence bound.',effect_state='none')
        if row['max_bytes'] is not None and row['stored_bytes']+len(payload)>row['max_bytes']-4096:
            row['status']='storage_limit';row['gaps'].append({'kind':'configured_storage_limit','last_sequence':row['last_sequence']});self._save(row);return False
        path=self.root/(identifier+'.jsonl')
        fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
        try:
            with os.fdopen(fd,'ab')as stream:
                stream.write(payload);stream.flush();os.fsync(stream.fileno())
        except OSError:
            row['status']='interrupted_write';row['gaps'].append({'kind':'write_interrupted'});raise
        row['last_sequence']=event['sequence'];row['stored_bytes']+=len(payload);row['event_count']+=1
        if event.get('kind')=='gap' and event.get('capture_ended')is True:
            self.pending_bodies={k:v for k,v in self.pending_bodies.items()if k[0]!=identifier}
            row['status']='capture_ended';row['gaps'].append({'kind':event['reason']});self._save(row)
        # The append is the durable original; status can be reconstructed.
        return True

    def storage_failed(self, identifier, owner):
        with self.lock:
            row=self._owned(identifier,owner);row['status']='interrupted_write'
            row['gaps'].append({'kind':'write_interrupted'})
            try:self._save(row)
            except OSError:pass # Original journal bytes remain; cold restore reports interruption.

    def end(self, identifier, owner, status, details=None):
        with self.lock:
            row=self._owned(identifier,owner);row['status']=status;row['ended_at']=time.time()
            self.pending_bodies={k:v for k,v in self.pending_bodies.items()if k[0]!=identifier}
            row['end_details']=clean(details or {});row['cleanup_required']=False;self._save(row)
            return self.status(identifier,owner)

    def status(self, identifier, owner):
        with self.lock:
            row=self._owned(identifier,owner);self._save(row)
            return {'ok':True,**json.loads(json.dumps(row)),'scope':'Opted-in test-tab evidence; linkage/causality may be unproven.'}

    def active_ids(self, owner=None):
        with self.lock:return [k for k,v in self.records.items()if (v['status']in('starting','recording')or v.get('cleanup_required',False))and(owner is None or v['owner_session']==owner)]

    def export(self, identifier, owner, offset=0, page_bytes=1048576):
        with self.lock:
            row=self._owned(identifier,owner);path=self.root/(identifier+'.jsonl')
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode)or info.st_mode&0o077:raise WorkbenchError('diagnostic_storage_private','Evidence file changed.',effect_state='none')
            if type(offset)is not int or offset<0 or type(page_bytes)is not int or not 120000<=page_bytes<=4194304:
                raise WorkbenchError('diagnostic_export_range','Use a page byte budget 120000..4194304 and an original byte offset.',effect_state='none')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb')as stream:
                if offset:
                    stream.seek(offset-1)
                    if stream.read(1)!=b'\n':raise WorkbenchError('diagnostic_export_range','Offset must be an original journal line boundary.',effect_state='none')
                stream.seek(offset);raw=stream.read(page_bytes)
                if offset+len(raw)<info.st_size:
                    boundary=raw.rfind(b'\n')
                    if boundary<0:raise WorkbenchError('diagnostic_frame_limit','Preserve the oversized original journal line.',effect_state='none')
                    raw=raw[:boundary+1]
            next_offset=offset+len(raw) if offset+len(raw)<info.st_size else None
            lines=raw.splitlines();events=[];gap=not raw.endswith(b'\n')and bool(raw)
            for line in lines:
                try:events.append(json.loads(line))
                except (ValueError,UnicodeError):gap=True;break
            manifest=json.loads(json.dumps(row))
            original=self.store.put_bytes(raw,'web-diagnostics:original-redacted-event-journal:'+identifier)
            packet={'schema_version':2,'offset':offset,'next_offset':next_offset,'snapshot_bytes':info.st_size,'manifest':manifest,'events':events,'original_journal':original,
                    'journal_sha256':hashlib.sha256(raw).hexdigest(),'journal_bytes':len(raw),
                    'partial_journal_gap':gap,'causality':'not_established',
                    'body_representation':'Credential-redacted variants; original digests cover CDP-decoded UTF-8, not compressed HTTP wire bytes. Bodies may be unavailable, capped or incomplete. Only root-frame requests of the opted-in document are observed; no prior traffic, workers or child-frame coverage is claimed.'}
            result=self.store.put_bytes(json.dumps(packet,ensure_ascii=True,separators=(',',':')).encode(),'web-diagnostics:review-packet:'+identifier)
            return {'ok':True,'record_id':identifier,'review_packet':result,'original_journal':original,
                    'offset':offset,'next_offset':next_offset,'snapshot_bytes':info.st_size,'partial_journal_gap':gap,'event_count':len(events),'causality':'not_established'}


def review_packet(packet):
    """Offline analyst role: correlate evidence, inventory gaps, never infer cause."""
    counts={};errors=[];marks=[];bodies={};requests=[]
    for e in packet['events']:
        kind=e.get('kind','unknown');counts[kind]=counts.get(kind,0)+1
        if kind in('loading_failed','exception','console')or kind=='response'and e.get('status',0)>=400:
            errors.append({k:e[k]for k in('sequence','kind','request_id','status','error','level','line','column','script_url')if k in e})
        if kind=='mark':marks.append(e)
        if kind=='request'and e.get('category')=='api_document':
            requests.append({k:e[k]for k in('sequence','request_id','method','url','frame_id','loader_id','document','redirect_hop')if k in e})
        if kind=='body_begin':bodies[e['body_id']]={'begin':e,'chunks':{},'ended':False}
        if kind=='body_chunk'and e.get('body_id')in bodies:
            bodies[e['body_id']]['chunks'][e['index']]=e['data']
        if kind=='body_end'and e.get('body_id')in bodies:bodies[e['body_id']]['ended']=True
    coverage=[]
    for key,b in bodies.items():
        begin=b['begin'];complete=b['ended']and set(b['chunks'])==set(range(begin['chunks']))
        valid=False
        if complete:
            try:
                raw=b''.join(base64.b64decode(b['chunks'][i],validate=True)for i in range(begin['chunks']))
                valid=len(raw)==begin['variant_bytes']and hashlib.sha256(raw).hexdigest()==begin['variant_sha256']
            except (ValueError,TypeError):pass
        coverage.append({'body_id':key,'request_id':begin['request_id'],'direction':begin.get('direction'),
                         'complete':complete,'complete_scope':'redacted_variant_transfer_only',
                         'variant_digest_verified':valid,'original_digest_only':begin.get('raw_sha256'),
                         'original_request_outcome':begin.get('original_request_outcome'),
                         **{k:begin[k]for k in('body_coverage','raw_digest_scope','stream_terminal','stream_enable',
                            'stream_gaps','observed_stream_bytes','retained_stream_bytes','stream_byte_count_basis',
                            'stream_buffer_bytes','stream_prefix_byte_limit','stream_retained_raw_budget_bytes','stream_collector_limit','stream_budget_scope')if k in begin}})
    return {'record_id':packet['manifest']['record_id'],'chat_url':packet['manifest']['chat_url'],
            'page':{k:packet.get(k)for k in('offset','next_offset','snapshot_bytes')},'page_local_analysis':True,
            'event_counts':counts,'error_event_count':len(errors),'errors':errors,'markers':marks,
            'api_document_requests':requests,'body_coverage':coverage,
            'incomplete_body_count':sum(not b['complete']or not b['variant_digest_verified']for b in coverage),
            'gaps':packet['manifest']['gaps'],'partial_journal_gap':packet['partial_journal_gap'],
            'finding':'Compare exact original request/document/message/MCP IDs and before/after observations. HTTP errors, absence and temporal overlap do not establish cause.',
            'causality':'not_established'}


class DiagnosticController:
    """Independent collector owner; never accepts a subject task's authority."""
    def __init__(self, broker):self.broker=broker

    def operation(self, workspace, action, record_id=None, target=None, chat_url=None,
                  opt_in_project_chat=False, request_id=None, max_bytes=None,
                  body_bytes=8388608, label=None, mcp_ids=None, offset=0, page_bytes=1048576, stream_buffer_bytes=None):
        from .context import work_context
        b=self.broker;owner=work_context.get();b.config.workspace(workspace)
        if not owner:raise WorkbenchError('work_session_required','Use a separate explicit recorder work session.',effect_state='none')
        if not b.config.workspace(workspace).executable:raise WorkbenchError('workspace_read_only','Diagnostics require an executable workspace.',effect_state='none')
        if action=='status':return b.web_diagnostics.status(record_id,owner)
        if action=='export':return b.web_diagnostics.export(record_id,owner,offset,page_bytes)
        if action not in ('start','mark','stop')or not isinstance(request_id,str)or not 1<=len(request_id.encode())<=240:
            raise WorkbenchError('diagnostic_request_required','Use start/mark/stop with an original stable request ID.',effect_state='none')
        if action=='start':
            if opt_in_project_chat is not True or not isinstance(target,dict)or target.get('cleanup_policy')!='keep':
                raise WorkbenchError('diagnostic_opt_in','Explicitly opt in an exact ordinary project test chat with KEEP lifecycle.',effect_state='none')
            original_chat_url=chat_url
            chat_url=chat_scope(chat_url)
            diagnostic_scope={'chat_url':chat_url,'body_bytes':body_bytes}
            observed_document_url=original_chat_url if PROJECT_CHAT.fullmatch(urlsplit(original_chat_url).path) else None
            if observed_document_url:diagnostic_scope['observed_document_url']=observed_document_url
            if type(body_bytes)is not int or not 4096<=body_bytes<=9007199254740991:
                raise WorkbenchError('diagnostic_body_limit','Use a positive body working-memory budget of at least 4096 bytes.',effect_state='none')
            if stream_buffer_bytes is not None:
                if type(stream_buffer_bytes)is not int or not 8192<=stream_buffer_bytes<=67108864:
                    raise WorkbenchError('diagnostic_stream_limit','Use an aggregate retained-prefix budget from 8192 through 67108864 bytes.',effect_state='none')
                diagnostic_scope['stream_buffer_bytes']=stream_buffer_bytes
            record_id=hashlib.sha256((owner+'\0'+request_id).encode()).hexdigest()[:32]
            with b.lock:
                peer=b.peers.get(target.get('connection_generation'))
                trust=b.trust_records.get(getattr(peer,'trust_key',None))if peer else None
                if not peer or peer.identity.get('diagnostics_version')!=1 or not trust or trust.get('network')is not True:
                    raise WorkbenchError('diagnostic_capability','The exact ordinary peer requires diagnostics v1 and existing network trust.',effect_state='none')
                if stream_buffer_bytes is not None and (type(peer.identity.get('diagnostics_stream_buffer_version'))is not int or peer.identity['diagnostics_stream_buffer_version']!=1):
                    raise WorkbenchError('diagnostic_stream_capability','The exact peer must advertise diagnostics_stream_buffer_version 1 for an explicit stream budget.',effect_state='none')
        else:
            row=b.web_diagnostics._owned(record_id,owner)
            if row['workspace']!=workspace:raise WorkbenchError('diagnostic_scope','Use original recorder workspace.',effect_state='none')
            if action=='mark'and(not isinstance(label,str)or len(label.encode())>1024 or not isinstance(mcp_ids,list)
                    or len(mcp_ids)>32 or any(not isinstance(i,str)or len(i.encode())>256 for i in mcp_ids)):
                raise WorkbenchError('diagnostic_marker','Supply a bounded label and original MCP invocation IDs.',effect_state='none')
        b.journal.validate_id(request_id)
        for suffix in ((':claim',':initialization-cleanup')if action=='start' else (':release',':cleanup')if action=='stop' else ()):
            b.journal.validate_id(request_id+suffix)
        payload={'tool':'browser_diagnostics','workspace':workspace,'action':action,'owner_session':owner,
                 'record_id':record_id,'target':target,'chat_url':chat_url,'max_bytes':max_bytes,
                 'body_bytes':body_bytes,'label':label,'mcp_ids':mcp_ids,'opt_in_project_chat':opt_in_project_chat}
        if action=='start' and observed_document_url:payload['observed_document_url']=observed_document_url
        if stream_buffer_bytes is not None:payload['stream_buffer_bytes']=stream_buffer_bytes
        def run():
            if action=='start':
                b.web_diagnostics.create(record_id,owner,workspace,target,observed_document_url or chat_url,max_bytes,request_id,body_bytes,stream_buffer_bytes)
                b.journal.checkpoint(request_id,{'record_id':record_id,'acquire_request_id':request_id+':claim','phase':'diagnostic_reserved'})
                try:
                    result=b._durable_operation(workspace,'acquire',None,None,request_id+':claim',262144,
                        target=target,diagnostic_scope=diagnostic_scope)
                except WorkbenchError as error:
                    child_id=request_id+':claim'
                    # These two pure guards precede the shared acquire Journal.
                    # Represent their proven no-dispatch refusal under the exact
                    # original child ID; the callback can only persist a failure.
                    if (error.code in ('browser_key_history_unsettled','invalid_browser_target')
                            and error.details.get('effect_state') in (None,'none')
                            and b.journal.status(child_id)['state']=='not_found'):
                        child_payload={'tool':'selected_browser','interaction_version':1,'workspace':workspace,'action':'acquire',
                            'owner_session':owner,'expected_origin':None,'expected_generation':None,
                            'parameters':{'target':target,'diagnostic_scope':diagnostic_scope}}
                        def reject_admission():
                            raise WorkbenchError(error.code,error.message,**{**error.details,'effect_state':'none','phase':'before_acquire_journal_admission'})
                        try:b.journal.run(child_id,child_payload,reject_admission)
                        except WorkbenchError as child_error:
                            if child_error.code!=error.code or child_error.details.get('effect_state')!='none':raise
                    self._reconcile_start(record_id,owner)
                    raise
                claim_id=result['claim_id']
                with b.lock:
                    current=b.claims.get(claim_id)
                    if not current or current.get('control')is not False or current.get('passive_diagnostics')is not True:
                        raise WorkbenchError('diagnostic_authority','Original passive claim publication is missing; recover its original receipt.',effect_state='unknown',record_id=record_id)
                    b.web_diagnostics.bind(record_id,owner,b._binding(current))
                return self._control(record_id,owner,'diagnostics_begin',{'record_id':record_id,'max_bytes':max_bytes,'body_bytes':body_bytes,
                    **({'stream_buffer_bytes':stream_buffer_bytes}if stream_buffer_bytes is not None else {})})
            if action=='mark':return self._control(record_id,owner,'diagnostics_mark',{'record_id':record_id,'label':label,'mcp_ids':mcp_ids})
            row=b.web_diagnostics._owned(record_id,owner)
            if row['binding']is None:
                resolved=self._reconcile_start(record_id,owner,cleanup=True)
                if resolved:return resolved
                row=b.web_diagnostics._owned(record_id,owner)
                if row['binding']is None:
                    raise WorkbenchError('diagnostic_start_unresolved','Recover the exact original child receipt or initialization cleanup; never reacquire.',effect_state='unknown',record_id=record_id,acquire_request_id=row['start_request_id']+':claim')
            with b.lock: current=b.claims.get(row['binding']['claim_id'])
            if current and current['state']in('released','revoked','target_closed'):
                if current.get('cleanup_state')not in('completed','target_gone'):
                    raise WorkbenchError('diagnostic_cleanup_unresolved','Preserve original claim cleanup obligation.',effect_state='unknown',record_id=record_id)
                return b.web_diagnostics.end(record_id,owner,'stopped',{'original_terminal_claim':current})
            if current and (current['state']in('suspended_transport','suspended_contention')or current.get('cleanup_state')=='unverified'):
                cleaned=b._durable_operation(workspace,'cleanup',None,None,request_id+':cleanup',262144,
                    claim_id=current['claim_id'],claim_epoch=current['claim_epoch'],target_generation=current['target']['target_generation'])
                if cleaned.get('cleanup_state')not in('completed','target_gone'):
                    raise WorkbenchError('diagnostic_cleanup_unresolved','Preserve original claim cleanup obligation.',effect_state='unknown',record_id=record_id)
                return b.web_diagnostics.end(record_id,owner,'stopped',{'original_cleanup_receipt':cleaned})
            # End passive evidence then use the established exact-claim KEEP release.
            result=self._control(record_id,owner,'diagnostics_stop',{'record_id':record_id})
            with b.lock:current=dict(b.claims[row['binding']['claim_id']])
            released=b._durable_operation(workspace,'release',None,None,request_id+':release',262144,
                claim_id=current['claim_id'],claim_epoch=current['claim_epoch'],target_generation=current['target']['target_generation'])
            b.web_diagnostics.end(record_id,owner,'stopped',{'release_receipt':released})
            return {'ok':True,'record_id':record_id,'capture':result,'release':released}
        return b.journal.run(request_id,payload,run,resource='browser-diagnostic:'+record_id)

    def _reconcile_start(self, identifier, owner, cleanup=False):
        b=self.broker;row=b.web_diagnostics._owned(identifier,owner)
        receipt=b.journal.status(row['start_request_id']+':claim')
        result=receipt.get('result')or {};error=result.get('error')or {}
        matches=[r for r in b.incomplete_initializations.values()if r.get('initialization_request_id')==row['start_request_id']+':claim' and r.get('owner_session')==owner]
        if receipt['state']=='failed' and error.get('effect_state')=='none' and not error.get('acquisition_failure') and not matches:
            return b.web_diagnostics.end(identifier,owner,'start_refused',{'original_acquire_receipt':receipt})
        claim_id=result.get('claim_id') if receipt['state']=='completed' else None
        failure=error.get('acquisition_failure')or {}
        history=failure.get('initialization_record')or (matches[0]if len(matches)==1 else {})
        if history and cleanup:
            claim_id=history.get('claim_id')
            with b.lock:current=b.incomplete_initializations.get(claim_id)
            if (current and current.get('initialization_request_id')==row['start_request_id']+':claim'
                    and current.get('owner_session')==owner and all(current['target'].get(k)==row['target'].get(k)for k in
                        ('target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind'))):
                # No document authority is manufactured for initialization history.
                fresh=b._durable_operation(row['workspace'],'claim_status',None,None,None,262144,claim_id=claim_id)
                current=fresh['initialization_record']
                cleaned=b._durable_operation(row['workspace'],'cleanup',None,None,row['start_request_id']+':initialization-cleanup',262144,
                    claim_id=claim_id,claim_epoch=current['claim_epoch'],target_generation=current['target']['target_generation'])
                if cleaned['initialization_record'].get('cleanup_state')in('completed','target_gone'):
                    return b.web_diagnostics.end(identifier,owner,'start_failed_cleaned',{'original_acquire_receipt':receipt,'cleanup':cleaned})
        if claim_id and not history:
            with b.lock:current=b.claims.get(claim_id)
            if current and current.get('owner_session')==owner and current.get('control')is False and current.get('passive_diagnostics')is True:
                b.web_diagnostics.bind(identifier,owner,b._binding(current))
        return None

    def _control(self, identifier, owner, action, parameters):
        b=self.broker;row=b.web_diagnostics._owned(identifier,owner)
        if row['binding']is None:raise WorkbenchError('diagnostic_binding_missing','Recover the original acquisition.',effect_state='none')
        with b.lock:
            claim=b.claims.get(row['binding']['claim_id'])
            if not claim:raise WorkbenchError('diagnostic_claim_missing','Keep original evidence and recover original claim cleanup.',effect_state='none')
            epoch=claim['claim_epoch'];generation=claim['target']['target_generation']
            peer=b.peers.get(claim['peer_id']);trust=b.trust_records.get(getattr(peer,'trust_key',None))if peer else None
            if not trust or not trust.get('network'):raise WorkbenchError('diagnostic_network_not_granted','Original network grant is unavailable.',effect_state='none')
            binding=b._control_preflight(action,claim['claim_id'],owner,{'claim_epoch':epoch,'target_generation':generation})
            command={'interaction_version':1,'runtime_generation':b.instance_id,'profile_id':claim['target']['profile_id'],
                     'context_id':claim['target']['context_id'],'context_kind':'ordinary','trust_id':trust['trust_id'],
                     'owner_session':owner,'claim_id':claim['claim_id'],'claim_epoch':epoch,'target_generation':generation,
                     'control_binding':binding,'parameters':parameters}
        return b._rpc(peer,action,command,timeout=10)
