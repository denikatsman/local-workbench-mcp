import {randomUUID} from 'node:crypto';
import {DurableSession,contextHash,hash,exact,insist,ownerValid,WORKBENCH_URL,fileURI,validateEnvelope} from './provider-core.mjs';
import {validatePointerPayload,pointerPlan,validateResolvedPointerMapping,validPointerResult} from './pointer-contract.mjs';

export const pointerMetadataExpression=`(()=>({href:location.href,title:document.title,labels:[...document.querySelectorAll('.tab.active .monaco-icon-label[aria-label]')].map(x=>x.getAttribute('aria-label')),time_origin:performance.timeOrigin,screen_x:screenX,screen_y:screenY,inner_width:innerWidth,inner_height:innerHeight,outer_width:outerWidth,outer_height:outerHeight,dpr:devicePixelRatio,visual:{width:visualViewport.width,height:visualViewport.height,scale:visualViewport.scale,offset_x:visualViewport.offsetLeft,offset_y:visualViewport.offsetTop}}))()`;
const reason=e=>/^electron_[a-z0-9_]+$/.test(e?.message)?e.message:'electron_pointer_exception';
const finite=v=>typeof v==='number'&&Number.isFinite(v);
const baseKeys=['version','pointer_contract','owner','context_hash','boot_id','binding_id','once_id','operation_id','capture_id','authority_hash','gesture_hash','target_id','window_id','action'];
function initialResult(p){return {ready:false,binding_id:p.binding_id,once_id:p.once_id,operation_id:p.operation_id??'',receiver_kind:'electron_renderer_pointer',action:p.gesture?.action??'unknown',target_id:null,window_id:p.mapping?.cg_window_id??0,dispatch_attempted:false,down_attempted:false,down_returned:false,up_attempted:false,up_returned:false,sent_events:0,possibly_sent:false,release_state:'not_eligible',effect_state:'none',outcome:'not_dispatched',retry_allowed:false,receipt_durable:false,receipt_recovered:false,requested_hold_ms:p.gesture?.hold_ms??null,elapsed_hold_ms:null,reason:null,session_detached:false};}


// One guardian-owned finite operation. All native/claim decisions remain signed-host checks.
export class ManagedPointerProvider {
 constructor({connect,authorise,progress=()=>{},stopped=()=>false,now=()=>process.hrtime.bigint(),sleep=ns=>new Promise(r=>setTimeout(r,Number(ns)/1e6)),journalFactory=root=>new DurableSession(root)}={}){
  this.connect=connect;this.authorise=authorise;this.progress=progress;this.stopped=stopped;this.now=now;this.sleep=sleep;this.journalFactory=journalFactory;
 }
 async run(e){
  validateEnvelope(e);if(e.method==='pointer_receipt')return this.receipt(e);
  insist(e.method==='pointer','electron_pointer_method');const p=validatePointerPayload(e.payload),m=e.managed,plan=pointerPlan(p),result=initialResult(p);
  let journal,cdp,chosen,intentWritten=false,marked=false,held=null,holdStarted=null,lastClock=null,deadline=null,sequence=0,dispatchOrdinal=0,acknowledgedOrdinal=0;
  const pending=[],downPromises=[],context=contextHash(m),gestureHash=hash(p.gesture);
  const clock=()=>{const n=this.now();insist(typeof n==='bigint'&&(lastClock===null||n>=lastClock),'electron_pointer_clock_invalid');lastClock=n;return n;};
  const fresh=()=>insist(deadline!==null&&clock()<deadline,'electron_pointer_capture_expired');
  const globalPoint=event=>({x:event.x+p.mapping.native_bounds.x,y:event.y+p.mapping.native_bounds.y});
  const notify=(phase,event=null,why=null)=>{
   const point=event?globalPoint(event):p.gesture.point;
   const row={event:'pointer_progress',request_id:e.request_id,pointer_contract:1,owner:p.owner,binding_id:p.binding_id,once_id:p.once_id,sequence:++sequence,phase,point,event_type:event?.type??'none',button:event?.button??'none',sent_events:result.sent_events,possibly_sent:result.possibly_sent,release_state:result.release_state,elapsed_ms:null,reason:why};
   if(holdStarted!==null){try{row.elapsed_ms=Number(clock()-holdStarted)/1e6;}catch{}}
   if(row.sequence<=1024)try{Promise.resolve(this.progress(row)).catch(()=>{});}catch{}
  };
  const identityBase=()=>({version:1,pointer_contract:1,owner:p.owner,context_hash:context,boot_id:m.boot_id,binding_id:p.binding_id,once_id:p.once_id,operation_id:p.operation_id,capture_id:p.capture.capture_id,authority_hash:p.capture.authority_hash,gesture_hash:gestureHash,target_id:chosen.mapping.target_id,window_id:p.mapping.cg_window_id,action:p.gesture.action});
  const verify=async()=>{
   insist(cdp&&!cdp.closed&&chosen,'electron_pointer_original_transport_unavailable');
   const current=await this.inspect(cdp,chosen.session,p,m);
   insist(hash(current)===hash(chosen.mapping),'electron_pointer_mapping_changed');
  };
  const check=async purpose=>{
   insist(!this.stopped(),'electron_pointer_stopped');await verify();insist(!this.stopped(),'electron_pointer_stopped');
   const started=clock(),record={event:'authorise',request_id:e.request_id,nonce:randomUUID(),context_hash:context,pointer_contract:1,owner:p.owner,binding_id:p.binding_id,once_id:p.once_id,operation_id:p.operation_id,purpose,sequence:++sequence,capture:p.capture,gesture_hash:gestureHash,mapping:chosen.mapping};
   insist(sequence<=1024,'electron_pointer_check_limit');
   const ack=await this.authorise(record);
   insist(ack&&exact(ack,['allowed','pointer_remaining_seconds'])&&ack.allowed===true&&finite(ack.pointer_remaining_seconds)&&ack.pointer_remaining_seconds>=0&&ack.pointer_remaining_seconds<=30&&!this.stopped(),'electron_pointer_authorisation_refused');
   if(purpose!=='pointer_hold'){
    insist(ack.pointer_remaining_seconds>0,'electron_pointer_capture_expired');
    const candidate=started+BigInt(Math.floor(ack.pointer_remaining_seconds*1e9));deadline=deadline===null||candidate<deadline?candidate:deadline;fresh();
   }
   clock();
  };
  const send=(event,phase,nextRelease=null)=>{
   // No native/AX waits or ACK wait lies between possible DOWN and original UP.
   if(!marked){journal.write(p.once_id,'pointer-dispatch',{...identityBase(),release_required:!plan.wheel});marked=true;}
   const started=phase==='press'&&p.gesture.hold_ms!==undefined?clock():null;
   if(phase==='press'){holdStarted=started;held=nextRelease;result.down_attempted=true;result.release_state='eligible';}
   else if(nextRelease)held=nextRelease;
   result.dispatch_attempted=true;result.possibly_sent=true;result.effect_state='unknown';result.outcome='dispatched_unverified';
   const ordinal=++dispatchOrdinal;
   // The private proxy carries this already-conservative absolute Node clock
   // deadline through queueing; only the original UP bypasses freshness.
   let promise;try{promise=Promise.resolve(cdp.call('Input.dispatchMouseEvent',event,chosen.session,2000,phase==='release'?undefined:deadline.toString())).then(()=>({ok:true}),()=>({ok:false}));}catch{promise=Promise.resolve({ok:false});}
   promise=promise.then(r=>{if(r.ok){result.sent_events++;if(phase==='press')result.down_returned=true;
    // ACKs may arrive out of order; an older event cannot repaint after a newer one.
    if(ordinal>acknowledgedOrdinal){acknowledgedOrdinal=ordinal;notify(phase,event);}
   }return r;});pending.push(promise);if(phase==='press')downPromises.push(promise);return promise;
  };
  const release=async()=>{
   if(!held)return;
   const original=held;held=null;result.up_attempted=true;result.release_state='possibly_sent';
   if(holdStarted!==null){try{result.elapsed_hold_ms=Number(clock()-holdStarted)/1e6;}catch{}}
   // Existing live opaque session is the identity-bound cleanup authority. No
   // reconnect, target lookup, fresh action grant or reconstructed event.
   let ack;try{ack=await send(original,'release');}catch{ack={ok:false};}
   result.up_returned=ack.ok;result.release_state=ack.ok?'acknowledged':'unverified';
   if(!ack.ok)throw Error('electron_pointer_release_unverified');
  };
  try{
   insist(p.capture.deadline_host_monotonic>=e.host_uptime&&p.capture.deadline_host_monotonic<=e.host_uptime+30,'electron_pointer_capture_expired');
   journal=this.journalFactory(m.session_root);
   insist(!journal.exists(p.binding_id,'pointer-binding')&&!journal.exists(p.once_id,'pointer-intent')&&!journal.exists(p.once_id,'pointer-terminal'),'electron_pointer_once_consumed_never_replay');
   cdp=await this.connect(m);chosen=await this.choose(cdp,p,m);
   result.target_id=chosen.mapping.target_id;
   journal.assertKeyboardRelease(m,result.target_id,p.once_id); // Includes pointer debt; attribution is checked before target filtering.
   journal.write(p.binding_id,'pointer-binding',{...identityBase(),payload:p,mapping:chosen.mapping,observed_node_ns:clock().toString()});
   journal.write(p.once_id,'pointer-intent',{...identityBase(),release_required:!plan.wheel,contract:'missing_terminal_is_unknown_never_replay'});intentWritten=true;
   await check('pointer_begin');await verify();fresh();
   if(plan.wheel){const r=await send(plan.wheel,'wheel');insist(r.ok,'electron_pointer_dispatch_unknown');}
   else for(let index=0;index<plan.pairs.length;index++){
    const pair=plan.pairs[index];if(index){await check('pointer_step');fresh();}
    const down=send(pair.down,'press',pair.ups[0]);
    if(pair.hold_ms){
     let previous=clock(),refresh=previous,checks=0;
     while(clock()-holdStarted<BigInt(pair.hold_ms)*1000000n){
      insist(!this.stopped()&&++checks<=1024,'electron_pointer_stopped');
      const remaining=BigInt(pair.hold_ms)*1000000n-(clock()-holdStarted);if(remaining<=0n)break;await this.sleep(remaining<20000000n?remaining:20000000n);
      const current=clock();insist(current>previous,'electron_pointer_clock_invalid');previous=current;
      if(current-refresh>=100000000n&&current-holdStarted<BigInt(pair.hold_ms)*1000000n){await check('pointer_hold');refresh=clock();notify('hold');}
     }
    }
    for(let n=0;n<pair.moves.length;n++){await check('pointer_step');fresh();send(pair.moves[n],'move',pair.ups[n+1]);}
    await release();const acknowledged=await down;insist(acknowledged.ok,'electron_pointer_dispatch_unknown');
   }
  }catch(error){result.reason=reason(error);const prior=result.reason==='electron_pointer_once_consumed_never_replay';result.outcome=result.possibly_sent||prior?'unknown_after_attempt':'not_dispatched';if(prior)result.effect_state='unknown';notify('failure',null,result.reason);}
  finally{
   try{await release();}catch(error){result.reason=reason(error);result.outcome='unknown_after_attempt';}
   if(intentWritten&&result.up_returned){try{const releaseRecord={...identityBase(),session_id:chosen.session,up_returned:true,original_transport:true};if(journal.exists(p.once_id,'pointer-release'))insist(hash(journal.read(p.once_id,'pointer-release'))===hash(releaseRecord),'electron_pointer_release_record_mismatch');else journal.write(p.once_id,'pointer-release',releaseRecord);}catch{result.reason='electron_pointer_release_record_unavailable';}}
   // Consume only original ACK promises; never replay a release after possible send.
   const acknowledgements=await Promise.all(pending);if(downPromises.length)result.down_returned=(await Promise.all(downPromises)).every(r=>r.ok);if(acknowledgements.some(r=>!r.ok)&&!result.reason){result.reason='electron_pointer_dispatch_unknown';result.outcome='unknown_after_attempt';}
   if(result.up_attempted&&!result.up_returned)result.reason='electron_pointer_release_unverified';
   if(result.possibly_sent)result.effect_state='unknown';
   if(cdp&&chosen)try{await cdp.call('Target.detachFromTarget',{sessionId:chosen.session},undefined,500);result.session_detached=true;}catch{result.reason??='electron_pointer_detach_unknown';}
   try{await cdp?.close();}catch{result.reason??='electron_pointer_transport_close_unknown';}
   result.ready=result.reason===null&&result.dispatch_attempted&&result.session_detached&&(!!plan.wheel||result.up_returned);
   if(result.reason&&result.possibly_sent)result.outcome='unknown_after_attempt';
   notify('timing');
   if(intentWritten)try{journal.write(p.once_id,'pointer-terminal',{version:1,pointer_contract:1,owner:p.owner,context_hash:context,result:{...result,receipt_durable:false,receipt_recovered:false}});result.receipt_durable=true;}catch{result.reason??='electron_pointer_terminal_unavailable';result.ready=false;if(result.possibly_sent)result.outcome='unknown_after_attempt';}
   journal?.close();
  }
  return result;
 }
 async inspect(cdp,session,p,managed){
  const frame=(await cdp.call('Page.getFrameTree',{},session)).frameTree?.frame;
  const response=await cdp.call('Runtime.evaluate',{expression:pointerMetadataExpression,returnByValue:true},session);
  insist(!response.exceptionDetails&&frame?.url===WORKBENCH_URL&&typeof frame.id==='string'&&typeof frame.loaderId==='string','electron_pointer_frame_unavailable');
  const v=response.result?.value,b=p.mapping.native_bounds,w=managed.windows.find(w=>w.cg_window_id===p.mapping.cg_window_id);
  insist(v&&v.href===WORKBENCH_URL&&v.title===w.native_title&&Array.isArray(v.labels)&&v.labels.length===1&&fileURI(v.labels[0],managed.user_home)===p.mapping.document_uri&&finite(v.time_origin),'electron_pointer_document_changed');
  const raw=(await cdp.call('Page.getLayoutMetrics',{},session)).cssVisualViewport;
  insist(v.screen_x===b.x&&v.screen_y===b.y&&v.inner_width===b.width&&v.outer_width===b.width&&v.inner_height===b.height&&v.outer_height===b.height&&v.dpr===1&&v.visual?.width===b.width&&v.visual.height===b.height&&v.visual.scale===1&&v.visual.offset_x===0&&v.visual.offset_y===0&&raw?.clientWidth===b.width&&raw.clientHeight===b.height&&raw.offsetX===0&&raw.offsetY===0&&raw.pageX===0&&raw.pageY===0&&raw.scale===1&&raw.zoom===1,'electron_pointer_unit_mapping_required');
  return validateResolvedPointerMapping({...p.mapping,target_id:session===undefined?'':this.targetForSession?.get(session)??'',frame_id:frame.id,loader_id:frame.loaderId,time_origin:v.time_origin,metrics:{screen_origin:{x:v.screen_x,y:v.screen_y},inner_size:{width:v.inner_width,height:v.inner_height},outer_size:{width:v.outer_width,height:v.outer_height},device_pixel_ratio:v.dpr,visual_viewport:{width:v.visual.width,height:v.visual.height,scale:v.visual.scale,offset_x:v.visual.offset_x,offset_y:v.visual.offset_y},css_viewport:{width:raw.clientWidth,height:raw.clientHeight,offset_x:raw.offsetX,offset_y:raw.offsetY,page_x:raw.pageX,page_y:raw.pageY,scale:raw.scale,zoom:raw.zoom}}},p);
 }
 async choose(cdp,p,managed){
  const window=managed.windows.find(w=>w.cg_window_id===p.mapping.cg_window_id);insist(window&&window.document_uri===p.mapping.document_uri,'electron_pointer_window_unknown');
  const infos=(await cdp.call('Target.getTargets')).targetInfos;insist(Array.isArray(infos)&&infos.length<=128,'electron_targets_invalid');
  const matches=[];this.targetForSession=new Map();
  for(const info of infos.filter(t=>t.type==='page'&&t.url===WORKBENCH_URL&&t.title===window.native_title&&(!window.target_id||window.target_id===t.targetId))){
   const session=(await cdp.call('Target.attachToTarget',{targetId:info.targetId,flatten:true})).sessionId;this.targetForSession.set(session,info.targetId);
   try{const mapping=await this.inspect(cdp,session,p,managed);matches.push({session,mapping});}catch(error){try{await cdp.call('Target.detachFromTarget',{sessionId:session});}catch{};if(reason(error)==='electron_pointer_document_changed')continue;throw error;}
  }
  if(matches.length!==1){for(const x of matches)try{await cdp.call('Target.detachFromTarget',{sessionId:x.session});}catch{};throw Error('electron_pointer_target_ambiguous');}
  return matches[0];
 }
 receipt(e){
  const p=e.payload,result=initialResult(p);result.effect_state='unknown';result.outcome='unknown_after_attempt';let j;
  try{
   j=this.journalFactory(e.managed.session_root);const b=j.read(p.binding_id,'pointer-binding'),i=j.read(p.once_id,'pointer-intent'),t=j.read(p.once_id,'pointer-terminal');
   insist(hash(b.payload.owner)===hash(p.owner)&&hash(i.owner)===hash(p.owner)&&hash(t.owner)===hash(p.owner)&&b.payload.once_id===p.once_id&&i.binding_id===p.binding_id&&i.once_id===p.once_id&&t.context_hash===contextHash(e.managed)&&validPointerResult(t.result)&&t.result.binding_id===p.binding_id&&t.result.once_id===p.once_id,'electron_pointer_receipt_owner_mismatch');
   j.assertPointerRelease(e.managed,i.target_id,p.once_id);return {...t.result,receipt_recovered:true,receipt_durable:true};
  }catch(error){result.reason=reason(error);return result;}finally{j?.close();}
 }
}

export {validPointerResult} from './pointer-contract.mjs';
