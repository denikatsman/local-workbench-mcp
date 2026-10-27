import {actionArguments} from './key-map.mjs';
import {DurableSession,contextHash,hash,exact,UUID,insist,productionConnect} from './provider-core.mjs';

// One signed-host-admitted key operation. The validation child never owns the
// socket that carries its original pair. No retry, reconnect or replacement UP.
export class OriginalKeyTransport {
 constructor(envelope,{connect=productionConnect,stopped=()=>false,journalFactory=root=>new DurableSession(root),now=()=>process.hrtime.bigint()}={}){
  insist(['key_pair','key_chord'].includes(envelope.method),'electron_guard_method');
  this.e=envelope;this.connect=connect;this.stopped=stopped;this.journalFactory=journalFactory;this.now=now;this.started=now();
  const a=envelope.payload;
  this.args=Object.fromEntries(Object.entries(a).filter(([k])=>!['owner','binding_id','once_id'].includes(k)));
  this.action=actionArguments(envelope.method,this.args);this.sessions=new Map();this.admitted=false;this.pair=null;this.closing=false;
 }
 fresh(){const b=this.binding,n=this.now(),born=BigInt(b.observed_node_ns);
  insist(b.boot_id===this.e.managed.boot_id&&b.context_hash===contextHash(this.e.managed)&&n>=born&&n-born<30000000000n&&
   this.e.host_uptime+Number(n-this.started)/1e9<b.deadline_monotonic,'electron_binding_expired');}
 async open(){insist(!this.cdp&&!this.closing&&!this.stopped(),'electron_guard_closed');this.cdp=await this.connect(this.e.managed);}
 authorise(record){
  const e=this.e,a=e.payload;
  insist(!this.binding&&!this.admitted&&!this.pair&&!this.closing&&!this.stopped()&&
   exact(record,['event','request_id','nonce','context_hash','binding_id','once_id','owner','cg_window_id','document_uri','target_id','renderer_state_hash'])&&
   record.event==='authorise'&&record.request_id===e.request_id&&UUID.test(record.nonce)&&record.context_hash===contextHash(e.managed)&&
   record.binding_id===a.binding_id&&record.once_id===a.once_id&&hash(record.owner)===hash(a.owner)&&
   /^[0-9a-f]{64}$/.test(record.renderer_state_hash),'electron_guard_authorisation');
  const journal=this.journalFactory(e.managed.session_root);
  try{
   const b=journal.read(a.binding_id,'binding'),i=journal.read(a.once_id,'intent');
   insist(b.binding_id===a.binding_id&&b.once_id===a.once_id&&hash(b.owner)===hash(a.owner)&&b.context_hash===record.context_hash&&
    b.target_id===record.target_id&&b.window.cg_window_id===record.cg_window_id&&b.window.document_uri===record.document_uri&&
    i.binding_id===b.binding_id&&i.once_id===b.once_id&&hash(i.owner)===hash(b.owner)&&i.context_hash===b.context_hash&&
    i.target_id===b.target_id&&i.window_id===b.window.cg_window_id&&i.method===e.method&&i.argument_sha256===hash(this.args)&&
    i.keyboard_release_contract===1&&!journal.exists(a.once_id,'terminal'),'electron_guard_binding');
   this.binding=b;this.intent=i;this.fresh();
  }finally{journal.close();}
 }
 grant(allowed){insist(this.binding&&!this.granted&&!this.pair,'electron_guard_authorisation');this.granted=true;this.admitted=allowed===true;}
 async call(method,params={},sessionId,timeout=1500){
  insist(this.cdp&&!this.closing,'electron_guard_closed');
  const allowed=['Target.getTargets','Target.attachToTarget','Target.detachFromTarget','Page.getFrameTree','Runtime.evaluate','Input.dispatchKeyEvent'];
  insist(allowed.includes(method),'electron_guard_command');
  if(method==='Input.dispatchKeyEvent'){
   if(params.type==='keyUp'){
    insist(this.pair&&!this.pair.upClaimed&&sessionId===this.pair.session&&hash(params)===hash(this.action.up),'electron_guard_up_mismatch');
    this.pair.upClaimed=true;const r=await this.pair.up;if(!r.ok)throw Error(r.code);return r.value;
   }
   insist(!this.pair&&this.admitted&&!this.stopped()&&params.type===this.action.down.type&&
    hash(params)===hash(this.action.down)&&this.sessions.get(sessionId)===this.binding.target_id,'electron_guard_down_mismatch');
   this.fresh();const journal=this.journalFactory(this.e.managed.session_root);
   try{
    const b=journal.read(this.e.payload.binding_id,'binding'),i=journal.read(this.e.payload.once_id,'intent'),m=journal.read(this.e.payload.once_id,'keyboard-dispatch');
    insist(hash(b)===hash(this.binding)&&hash(i)===hash(this.intent)&&
     exact(m,['version','owner','context_hash','binding_id','once_id','method','target_id','window_id','boot_id'])&&m.version===1&&
     hash(m.owner)===hash(i.owner)&&m.context_hash===i.context_hash&&m.binding_id===i.binding_id&&m.once_id===i.once_id&&
     m.method===i.method&&m.target_id===i.target_id&&m.window_id===i.window_id&&m.boot_id===i.boot_id&&
     !journal.exists(i.once_id,'terminal')&&!journal.exists(i.once_id,'keyboard-release'),'electron_guard_dispatch_marker');
   }finally{journal.close();}
   this.fresh();insist(!this.stopped(),'electron_guard_closed');
   // Admission, original pair and session are fixed before the first possible
   // DOWN. Attach rejection handlers immediately. Never await DOWN before UP.
   const invoke=event=>{try{return Promise.resolve(this.cdp.call('Input.dispatchKeyEvent',event,sessionId,2000)).then(
    value=>({ok:true,value}),()=>({ok:false,code:'electron_cdp_release_unknown'}));}
    catch{return Promise.resolve({ok:false,code:'electron_cdp_release_unknown'});}};
   const pair={session:sessionId,upClaimed:false};this.pair=pair;
   pair.down=invoke(this.action.down);
   pair.up=invoke(this.action.up).then(r=>{
    if(r.ok){const journal=this.journalFactory(this.e.managed.session_root);try{
     journal.write(this.e.payload.once_id,'keyboard-release',{version:1,owner:this.intent.owner,context_hash:this.intent.context_hash,
      binding_id:this.intent.binding_id,once_id:this.intent.once_id,method:this.intent.method,target_id:this.intent.target_id,
      window_id:this.intent.window_id,boot_id:this.intent.boot_id,argument_sha256:this.intent.argument_sha256,
      session_id:sessionId,up_returned:true,original_transport:true});
    }finally{journal.close();}}
    return r;
   }).catch(()=>({ok:true,value:{},release_record_unavailable:true}));
   const r=await pair.down;if(!r.ok)throw Error(r.code);return r.value;
  }
  if(method==='Target.detachFromTarget'){
   if(this.pair&&params.sessionId===this.pair.session)await this.pair.up;
   const r=await this.cdp.call(method,params,sessionId,timeout);this.sessions.delete(params.sessionId);return r;
  }
  const r=await this.cdp.call(method,params,sessionId,timeout);
  if(method==='Target.attachToTarget')this.sessions.set(r.sessionId,params.targetId);
  return r;
 }
 async close(){
  if(this.closePromise)return this.closePromise;this.closing=true;
  this.closePromise=(async()=>{if(this.pair)await Promise.allSettled([this.pair.down,this.pair.up]);this.cdp?.close();})();
  return this.closePromise;
 }
}
