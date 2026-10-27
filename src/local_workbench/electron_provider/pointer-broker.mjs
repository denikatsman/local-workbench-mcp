import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {DurableSession,productionConnect,validateEnvelope,contextHash,hash,exact,insist,WORKBENCH_URL} from './provider-core.mjs';
import {pointerPlan,validateResolvedPointerMapping} from './pointer-contract.mjs';
import {ManagedPointerProvider,pointerMetadataExpression} from './pointer-provider.mjs';
import {strictJSON} from './json.mjs';
const code=e=>/^electron_[a-z0-9_]+$/.test(e?.message)?e.message:'electron_pointer_broker_unknown';
// One immutable operation, one original connection. No reattachment on cleanup.
export class OriginalPointerBroker {
 constructor(envelope,{connect=productionConnect,journalFactory=root=>new DurableSession(root),now=()=>process.hrtime.bigint()}={}){
  this.e=validateEnvelope(envelope);insist(envelope.method==='pointer','electron_pointer_broker_method');
  this.p=envelope.payload;this.plan=pointerPlan(this.p);this.connect=connect;this.journalFactory=journalFactory;this.now=now;this.born=now();
  this.sessions=new Map();this.targets=new Set();this.rpc=new Set();this.pair=0;this.move=0;this.held=null;this.sequence=0;this.allowed=false;this.ending=false;this.attempted=0;this.returned=0;this.releaseReturned=false;this.inspectProvider=new ManagedPointerProvider();this.inspectProvider.targetForSession=this.sessions;
 }
 withJournal(work){const j=this.journalFactory(this.e.managed.session_root);try{return work(j);}finally{j.close();}}
 base(){const p=this.p,m=this.e.managed;return {version:1,pointer_contract:1,owner:p.owner,context_hash:contextHash(m),boot_id:m.boot_id,binding_id:p.binding_id,once_id:p.once_id,operation_id:p.operation_id,capture_id:p.capture.capture_id,authority_hash:p.capture.authority_hash,gesture_hash:hash(p.gesture),target_id:this.mapping.target_id,window_id:p.mapping.cg_window_id,action:p.gesture.action};}
 journals(dispatch=false){this.withJournal(j=>{
  const b=j.read(this.p.binding_id,'pointer-binding'),i=j.read(this.p.once_id,'pointer-intent'),base=this.base();
  insist(exact(b,[...Object.keys(base),'payload','mapping','observed_node_ns'])&&exact(i,[...Object.keys(base),'release_required','contract'])&&Object.keys(base).every(k=>hash(b[k])===hash(base[k])&&hash(i[k])===hash(base[k]))&&hash(b.payload)===hash(this.p)&&hash(b.mapping)===hash(this.mapping)&&/^\d{1,30}$/.test(b.observed_node_ns)&&i.release_required===!this.plan.wheel&&i.contract==='missing_terminal_is_unknown_never_replay'&&!j.exists(this.p.once_id,'pointer-terminal'),'electron_pointer_broker_journal');
  j.assertKeyboardRelease(this.e.managed,this.mapping.target_id,this.p.once_id);
  if(dispatch){const mark=j.read(this.p.once_id,'pointer-dispatch');insist(exact(mark,[...Object.keys(base),'release_required'])&&Object.keys(base).every(k=>hash(mark[k])===hash(base[k]))&&mark.release_required===!this.plan.wheel,'electron_pointer_broker_dispatch');}
 });}
 async admit(record,allowed){
  insist(!this.ending&&typeof allowed==='boolean'&&exact(record,['event','request_id','nonce','context_hash','pointer_contract','owner','binding_id','once_id','operation_id','purpose','sequence','capture','gesture_hash','mapping'])&&record.event==='authorise'&&record.request_id===this.e.request_id&&/^[0-9a-f-]{36}$/i.test(record.nonce)&&record.context_hash===contextHash(this.e.managed)&&record.pointer_contract===1&&hash(record.owner)===hash(this.p.owner)&&record.binding_id===this.p.binding_id&&record.once_id===this.p.once_id&&record.operation_id===this.p.operation_id&&hash(record.capture)===hash(this.p.capture)&&record.gesture_hash===hash(this.p.gesture)&&Number.isSafeInteger(record.sequence)&&record.sequence>this.sequence&&record.sequence<=1024,'electron_pointer_broker_admission');
  insist(this.sequence===0?record.purpose==='pointer_begin':['pointer_step','pointer_hold'].includes(record.purpose),'electron_pointer_broker_phase');this.sequence=record.sequence;this.allowed=false;
  if(!allowed)return false;
  const mapping=validateResolvedPointerMapping(record.mapping,this.p),session=[...this.sessions].filter(([,t])=>t===mapping.target_id);
  insist(session.length===1&&(!this.mapping||hash(this.mapping)===hash(mapping)),'electron_pointer_broker_mapping');
  const actual=await this.inspectProvider.inspect(this.cdp,session[0][0],this.p,this.e.managed);insist(hash(actual)===hash(mapping),'electron_pointer_broker_mapping');
  this.mapping=mapping;this.session=session[0][0];this.journals();
  if(record.purpose!=='pointer_hold')insist(this.e.host_uptime+Number(this.now()-this.born)/1e9<this.p.capture.deadline_host_monotonic,'electron_pointer_capture_expired');
  insist(!this.ending,'electron_pointer_broker_closed');this.allowed=record.purpose!=='pointer_hold';return true;
 }
 invoke(event){this.attempted++;try{return Promise.resolve(this.cdp.call('Input.dispatchMouseEvent',event,this.session,2000)).then(value=>{this.returned++;return {ok:true,value};},()=>({ok:false}));}catch{return Promise.resolve({ok:false});}}
 persistRelease(){const record={...this.base(),session_id:this.session,up_returned:true,original_transport:true};this.withJournal(j=>{if(j.exists(this.p.once_id,'pointer-release'))insist(hash(j.read(this.p.once_id,'pointer-release'))===hash(record),'electron_pointer_release_record_mismatch');else j.write(this.p.once_id,'pointer-release',record);});}
 async release(){
  const slot=this.held;if(!slot)return {};
  if(!slot.promise){const pair=this.pair;slot.promise=this.invoke(slot.event).then(ack=>{
   if(!ack.ok)throw Error('electron_pointer_release_unverified');this.releaseReturned=true;slot.acknowledged=true;
   if(this.ending||pair===this.plan.pairs.length-1)this.persistRelease();return ack.value;
  });slot.promise.catch(()=>{});}
  return slot.promise;
 }
 async call(method,params,session,timeout,pointerDeadline){
  insist(this.cdp&&!this.ending,'electron_pointer_broker_closed');
  if(method==='Input.dispatchMouseEvent'){
   insist(session===this.session,'electron_pointer_broker_session');
   if(params.type==='mouseReleased'){
    insist(this.held&&hash(params)===hash(this.held.event),'electron_pointer_broker_release');
    const promise=this.release();if(!this.held.claimed){this.held.claimed=true;this.pair++;this.move=0;this.allowed=false;}return promise;
   }
   insist(this.allowed,'electron_pointer_broker_unadmitted');insist(this.e.host_uptime+Number(this.now()-this.born)/1e9<this.p.capture.deadline_host_monotonic,'electron_pointer_capture_expired');this.journals(true);
   // Same bundled Node/host monotonic clock as the planner. Its conservative
   // deadline was anchored BEFORE host admission, not at late broker startup.
   // Check after journal I/O, before arming a possible send; expired preflight
   // must not create a held slot or cause a spurious UP during shutdown.
   const fresh=()=>insist(typeof pointerDeadline==='string'&&/^[0-9]{1,30}$/.test(pointerDeadline)&&this.now()<BigInt(pointerDeadline),'electron_pointer_capture_expired');
   const plan=this.plan.pairs[this.pair];
   if(this.plan.wheel){insist(this.attempted===0&&hash(params)===hash(this.plan.wheel),'electron_pointer_broker_plan');fresh();this.allowed=false;const ack=await this.invoke(this.plan.wheel);insist(ack.ok,'electron_pointer_dispatch_unknown');return ack.value;}
   insist(plan,'electron_pointer_broker_plan');
   if(params.type==='mousePressed'){
    insist((!this.held||this.held.claimed&&this.held.acknowledged)&&hash(params)===hash(plan.down),'electron_pointer_broker_plan');
    fresh();
    this.held={event:plan.ups[0],promise:null,claimed:false};this.move=0;this.releaseReturned=false;
   }else{
    insist(params.type==='mouseMoved'&&this.held&&!this.held.promise&&!this.held.claimed&&hash(params)===hash(plan.moves[this.move]),'electron_pointer_broker_plan');
    fresh();
    this.held.event=plan.ups[++this.move];
   }
   // Synchronous immutable release arm precedes any possible socket send.
   this.allowed=false;const ack=await this.invoke(params);insist(ack.ok,'electron_pointer_dispatch_unknown');return ack.value;
  }
  insist(['Target.getTargets','Target.attachToTarget','Target.detachFromTarget','Page.getFrameTree','Page.getLayoutMetrics','Runtime.evaluate'].includes(method),'electron_pointer_broker_command');
  if(method==='Target.getTargets')insist(exact(params,[])&&session===null,'electron_pointer_broker_command');
  else if(method==='Target.attachToTarget')insist(exact(params,['targetId','flatten'])&&params.flatten===true&&this.targets.has(params.targetId)&&session===null&&!this.sessions.size,'electron_pointer_broker_target');
  else if(method==='Target.detachFromTarget'){
   insist(exact(params,['sessionId'])&&this.sessions.has(params.sessionId)&&session===null,'electron_pointer_broker_session');
   if(this.held&&params.sessionId===this.session)await this.release();
  }else{
   insist(this.sessions.has(session),'electron_pointer_broker_session');
   insist(method==='Runtime.evaluate'?exact(params,['expression','returnByValue'])&&params.expression===pointerMetadataExpression&&params.returnByValue===true:exact(params,[]),'electron_pointer_broker_command');
  }
  const result=await this.cdp.call(method,params,session??undefined,timeout);
  if(method==='Target.getTargets'){
   insist(Array.isArray(result.targetInfos)&&result.targetInfos.length<=128,'electron_targets_invalid');const w=this.e.managed.windows.find(w=>w.cg_window_id===this.p.mapping.cg_window_id);
   this.targets=new Set(result.targetInfos.filter(t=>t.type==='page'&&t.url===WORKBENCH_URL&&t.title===w.native_title&&(!w.target_id||w.target_id===t.targetId)).map(t=>t.targetId));
  }
  if(method==='Target.attachToTarget'){insist(typeof result.sessionId==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(result.sessionId),'electron_pointer_broker_session');this.sessions.set(result.sessionId,params.targetId);}
  if(method==='Target.detachFromTarget')this.sessions.delete(params.sessionId);
  return result;
 }
 async request(r){
  insist(r&&r.event==='pointer_transport'&&r.request_id===this.e.request_id&&Number.isSafeInteger(r.rpc_id)&&r.rpc_id>0&&r.rpc_id<=1024&&!this.rpc.has(r.rpc_id)&&['connect','call','close'].includes(r.command),'electron_pointer_broker_rpc');
  const timed=r.command==='call'&&r.method==='Input.dispatchMouseEvent'&&r.params?.type!=='mouseReleased';
  insist(exact(r,['event','request_id','rpc_id','command',...(r.command==='call'?['method','params','session_id','timeout']:[]),...(timed?['pointer_deadline_ns']:[])]),'electron_pointer_broker_rpc');this.rpc.add(r.rpc_id);
  if(r.command==='connect'){insist(!this.connecting&&!this.cdp&&!this.ending,'electron_pointer_broker_connect');this.connecting=true;this.cdp=await this.connect(this.e.managed);if(this.ending){this.cdp.close();throw Error('electron_pointer_broker_closed');}return {};}
  if(r.command==='close'){await this.finish();return {};}
  insist(typeof r.method==='string'&&r.params&&typeof r.params==='object'&&!Array.isArray(r.params)&&(r.session_id===null||typeof r.session_id==='string')&&Number.isInteger(r.timeout)&&r.timeout>0&&r.timeout<=2000,'electron_pointer_broker_rpc');return this.call(r.method,r.params,r.session_id,r.timeout,r.pointer_deadline_ns);
 }
 finish(){
  if(this.finishPromise)return this.finishPromise;this.ending=true;this.allowed=false;
  this.finishPromise=(async()=>{let reason=null;try{await this.release();if(this.releaseReturned)this.persistRelease();}catch(e){reason=code(e);}
   for(const sessionId of this.sessions.keys())try{await this.cdp.call('Target.detachFromTarget',{sessionId},undefined,500);}catch{reason??='electron_pointer_detach_unknown';}
   this.sessions.clear();try{this.cdp?.close();}catch{reason??='electron_pointer_transport_close_unknown';}
   return {possibly_sent:this.attempted>0,up_attempted:!!this.held?.promise,up_returned:this.releaseReturned,sent_events:this.returned,release_state:!this.held?'not_eligible':this.releaseReturned?'acknowledged':'unverified',effect_state:this.attempted?'unknown':'none',retry_allowed:false,reason};})();return this.finishPromise;
 }
}
// stdin is owned only by signed host. No argv/env endpoint or public registration.
export async function runPointerBroker({input=process.stdin,output=process.stdout,brokerFactory=e=>new OriginalPointerBroker(e)}={}){
 let broker,buffer='',total=0,outputTotal=0,inflight=0,stopping=false;const tasks=new Set();
 const emit=r=>new Promise(resolve=>{const bytes=JSON.stringify(r)+'\n';outputTotal+=Buffer.byteLength(bytes);if(Buffer.byteLength(bytes)>65536||outputTotal>262144){queueMicrotask(stop);return resolve(false);}const timer=setTimeout(()=>resolve(false),200);try{output.write(bytes,()=>{clearTimeout(timer);resolve(true);});}catch{clearTimeout(timer);resolve(false);}});
 let settleResolve;const done=new Promise(r=>settleResolve=r);
 const stop=()=>{if(stopping)return;stopping=true;(async()=>{const result=broker?await broker.finish():{possibly_sent:false,effect_state:'none',retry_allowed:false,reason:'electron_pointer_broker_no_envelope'};await emit({event:'broker_settled',request_id:broker?.e.request_id??null,result});input.destroy();settleResolve(result);})();};
 const frame=r=>{
  if(!broker){broker=brokerFactory(r);return;}
  if(r.event==='stop'){insist(exact(r,['event','request_id'])&&r.request_id===broker.e.request_id,'electron_pointer_broker_stop');stop();return;}
  insist(!stopping&&inflight<32,'electron_pointer_broker_limit');inflight++;
  let task;
  if(r.event==='pointer_admission'){
   insist(exact(r,['event','request_id','record','allowed'])&&r.request_id===broker.e.request_id,'electron_pointer_broker_admission');
   task=broker.admit(r.record,r.allowed).then(allowed=>emit({event:'pointer_admitted',request_id:r.request_id,sequence:r.record.sequence,allowed}));
  }else task=broker.request(r).then(result=>emit({event:'pointer_transport_result',request_id:r.request_id,rpc_id:r.rpc_id,response:{ok:true,result}}),e=>emit({event:'pointer_transport_result',request_id:r.request_id,rpc_id:r.rpc_id,response:{ok:false,error:{code:code(e)}}})).then(()=>{if(r.command==='close')stop();});
  tasks.add(task);task.catch(stop).finally(()=>{inflight--;tasks.delete(task);});
 };
 const decoder=new TextDecoder('utf8',{fatal:true});input.on('data',bytes=>{try{total+=bytes.length;insist(total<=1048576,'electron_pointer_broker_limit');buffer+=decoder.decode(bytes,{stream:true});insist(Buffer.byteLength(buffer)<=131072,'electron_pointer_broker_limit');let n;while((n=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,n);buffer=buffer.slice(n+1);frame(strictJSON(line));}}catch{stop();}});
 input.on('end',stop);input.on('error',stop);output.on('error',stop);process.on('SIGTERM',stop);process.on('SIGINT',stop);
 const timer=setTimeout(stop,12000);
 try{return await done;}finally{clearTimeout(timer);process.off('SIGTERM',stop);process.off('SIGINT',stop);}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){if(process.argv.length!==2)process.exit(2);else runPointerBroker().then(()=>process.exit(0),()=>process.exit(1));}
