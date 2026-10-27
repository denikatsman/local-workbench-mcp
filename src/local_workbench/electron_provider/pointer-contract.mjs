// Private, closed managed-pointer wire contract. No endpoint/target override in public input.
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...k].sort().join(',');
const insist=(v,c)=>{if(!v)throw Error(c);};
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(v);
const bounded=v=>typeof v==='string'&&v.length>0&&v.length<=128&&!v.includes('\0');
export const pointerOwner=v=>exact(v,['claim_id','owner_session','runtime_generation','target_generation','window_id'])&&Object.values(v).every(bounded);
export const rect=v=>exact(v,['x','y','width','height'])&&Object.values(v).every(Number.isFinite)&&v.width>0&&v.height>0;
const point=v=>exact(v,['x','y'])&&Number.isFinite(v.x)&&Number.isFinite(v.y);
const within=(p,b)=>p.x>=b.x&&p.y>=b.y&&p.x<b.x+b.width&&p.y<b.y+b.height;
export function validatePointerPayload(p){
 insist(exact(p,['pointer_contract','owner','binding_id','once_id','operation_id','capture','mapping','gesture'])&&p.pointer_contract===1&&pointerOwner(p.owner)&&uuid(p.binding_id)&&uuid(p.once_id)&&bounded(p.operation_id)&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(p.operation_id),'electron_pointer_payload_invalid');
 const c=p.capture,m=p.mapping,g=p.gesture;
 insist(exact(c,['capture_id','observation_id','authority_hash','deadline_host_monotonic','clock_generation'])&&bounded(c.capture_id)&&bounded(c.observation_id)&&/^[0-9a-f]{64}$/.test(c.authority_hash)&&Number.isFinite(c.deadline_host_monotonic)&&c.deadline_host_monotonic>=0&&typeof c.clock_generation==='string'&&/^\d{1,20}$/.test(c.clock_generation),'electron_pointer_capture_invalid');
 insist(exact(m,['native_bounds','webarea_bounds','cg_window_id','document_uri'])&&rect(m.native_bounds)&&rect(m.webarea_bounds)&&Number.isInteger(m.cg_window_id)&&m.cg_window_id>0&&m.cg_window_id<=0x7fffffff&&typeof m.document_uri==='string'&&m.document_uri.length<=8192&&m.document_uri.startsWith('file:'),'electron_pointer_mapping_invalid');
 insist(['x','y','width','height'].every(k=>m.native_bounds[k]===m.webarea_bounds[k]),'electron_pointer_unit_mapping_required');
 const actions=['click','double_click','right_click','hold','right_hold','drag','scroll'];
 insist(g&&actions.includes(g.action)&&point(g.point)&&within(g.point,m.native_bounds),'electron_pointer_gesture_invalid');
 const keys=['action','point',...(g.action==='scroll'?['wheel']:[]),...(['hold','right_hold'].includes(g.action)?['hold_ms']:[]),...(g.action==='drag'?['drag']:[])];
 insist(exact(g,keys),'electron_pointer_gesture_fields');
 if(g.action==='scroll')insist(exact(g.wheel,['x','y'])&&[g.wheel.x,g.wheel.y].every(x=>Number.isInteger(x)&&x>=-2000&&x<=2000)&&(g.wheel.x!==0||g.wheel.y!==0),'electron_pointer_wheel_invalid');
 if(['hold','right_hold'].includes(g.action))insist(Number.isInteger(g.hold_ms)&&g.hold_ms>=1&&g.hold_ms<=5000,'electron_pointer_hold_invalid');
 if(g.action==='drag')insist(exact(g.drag,['end','steps'])&&point(g.drag.end)&&within(g.drag.end,m.native_bounds)&&Number.isInteger(g.drag.steps)&&g.drag.steps>=2&&g.drag.steps<=16&&(g.drag.end.x!==g.point.x||g.drag.end.y!==g.point.y),'electron_pointer_drag_invalid');
 return p;
}
export function pointerPlan(p){
 validatePointerPayload(p);const g=p.gesture,b=p.mapping.native_bounds,toViewport=q=>Object.freeze({x:q.x-b.x,y:q.y-b.y});
 const start=toViewport(g.point),right=['right_click','right_hold'].includes(g.action),button=right?'right':'left',buttons=right?2:1;
 const event=(type,q,count=1)=>Object.freeze({type,...q,button,buttons:type==='mouseReleased'?0:buttons,clickCount:count,modifiers:0});
 if(g.action==='scroll')return Object.freeze({wheel:Object.freeze({type:'mouseWheel',...start,deltaX:g.wheel.x,deltaY:g.wheel.y,modifiers:0}),pairs:[]});
 const pairs=[];
 for(let count=1;count<=(g.action==='double_click'?2:1);count++){
  const points=[start];if(g.action==='drag')for(let i=1;i<=g.drag.steps;i++){const t=i/g.drag.steps;points.push(toViewport(i===g.drag.steps?g.drag.end:{x:(1-t)*g.point.x+t*g.drag.end.x,y:(1-t)*g.point.y+t*g.drag.end.y}));}
  pairs.push(Object.freeze({down:event('mousePressed',start,count),moves:Object.freeze(points.slice(1).map(q=>event('mouseMoved',q,count))),ups:Object.freeze(points.map(q=>event('mouseReleased',q,count))),hold_ms:g.hold_ms??0}));
 }
 return Object.freeze({wheel:null,pairs:Object.freeze(pairs)});
}

// Pure attribution/held-release fence. Callers supply their existing journal/hash policy.
export function assertPointerHistory(j,managed,target,exclude,{hash,contextHash}){
 const names=j.names(),intents=names.filter(n=>/^[0-9a-f-]{36}\.pointer-intent\.json$/.test(n));
 for(const stage of ['pointer-dispatch','pointer-release'])for(const n of names.filter(n=>n.endsWith('.'+stage+'.json')))insist(intents.includes(n.replace('.'+stage+'.json','.pointer-intent.json')),'electron_pointer_history_invalid');
 const baseKeys=['version','pointer_contract','owner','context_hash','boot_id','binding_id','once_id','operation_id','capture_id','authority_hash','gesture_hash','target_id','window_id','action'];
 for(const name of intents){
  const id=name.slice(0,36),i=j.read(id,'pointer-intent');
  insist(exact(i,[...baseKeys,'release_required','contract'])&&i.version===1&&i.pointer_contract===1&&pointerOwner(i.owner)&&i.context_hash===contextHash(managed)&&i.boot_id===managed.boot_id&&uuid(i.binding_id)&&uuid(i.once_id)&&i.once_id.toLowerCase()===id&&bounded(i.operation_id)&&bounded(i.target_id)&&Number.isInteger(i.window_id)&&i.window_id>0&&/^[0-9a-f]{64}$/.test(i.gesture_hash)&&/^[0-9a-f]{64}$/.test(i.authority_hash)&&typeof i.release_required==='boolean'&&i.contract==='missing_terminal_is_unknown_never_replay','electron_pointer_history_invalid');
  const b=j.read(i.binding_id,'pointer-binding');
  insist(exact(b,[...baseKeys,'payload','mapping','observed_node_ns'])&&baseKeys.every(k=>hash(b[k])===hash(i[k]))&&/^\d{1,30}$/.test(b.observed_node_ns),'electron_pointer_history_invalid');
  validatePointerPayload(b.payload);validateResolvedPointerMapping(b.mapping,b.payload);
  insist(hash(b.payload.owner)===hash(i.owner)&&b.payload.binding_id===i.binding_id&&b.payload.once_id===i.once_id&&b.payload.operation_id===i.operation_id&&b.payload.capture.capture_id===i.capture_id&&b.payload.capture.authority_hash===i.authority_hash&&hash(b.payload.gesture)===i.gesture_hash&&b.mapping.target_id===i.target_id&&b.mapping.cg_window_id===i.window_id&&b.payload.gesture.action===i.action&&i.release_required===(i.action!=='scroll'),'electron_pointer_history_invalid');
  const marked=j.exists(id,'pointer-dispatch'),released=j.exists(id,'pointer-release');
  if(marked){const m=j.read(id,'pointer-dispatch');insist(exact(m,[...baseKeys,'release_required'])&&baseKeys.every(k=>hash(m[k])===hash(i[k]))&&m.release_required===i.release_required,'electron_pointer_history_invalid');}
  if(released){const r=j.read(id,'pointer-release');insist(marked&&i.release_required&&exact(r,[...baseKeys,'session_id','up_returned','original_transport'])&&baseKeys.every(k=>hash(r[k])===hash(i[k]))&&bounded(r.session_id)&&r.up_returned===true&&r.original_transport===true,'electron_pointer_history_invalid');}
  let terminal=null;
  if(j.exists(id,'pointer-terminal')){
   const t=j.read(id,'pointer-terminal');terminal=t.result;
   insist(exact(t,['version','pointer_contract','owner','context_hash','result'])&&t.version===1&&t.pointer_contract===1&&hash(t.owner)===hash(i.owner)&&t.context_hash===i.context_hash&&validPointerResult(terminal)&&terminal.receipt_durable===false&&terminal.receipt_recovered===false&&terminal.binding_id===i.binding_id&&terminal.once_id===i.once_id&&terminal.operation_id===i.operation_id&&terminal.target_id===i.target_id&&terminal.window_id===i.window_id&&terminal.action===i.action&&terminal.receiver_kind==='electron_renderer_pointer'&&terminal.retry_allowed===false&&terminal.receipt_durable===false&&typeof terminal.dispatch_attempted==='boolean'&&typeof terminal.up_returned==='boolean'&&['none','unknown'].includes(terminal.effect_state),'electron_pointer_history_invalid');
   insist(!terminal.dispatch_attempted||marked,'electron_pointer_history_invalid');
   insist(terminal.dispatch_attempted||!released&&terminal.possibly_sent===false&&terminal.effect_state==='none','electron_pointer_history_invalid');
  }
  // Validate all attribution first; corrupt data cannot move debt to a sibling.
  if(i.target_id!==target||i.once_id===exclude)continue;
  if(marked&&i.release_required)insist(released,'electron_pointer_release_unverified');
 }
}

export function validateResolvedPointerMapping(m,p){
 insist(exact(m,['native_bounds','webarea_bounds','cg_window_id','document_uri','target_id','frame_id','loader_id','time_origin','metrics'])&&rect(m.native_bounds)&&rect(m.webarea_bounds)&&['x','y','width','height'].every(k=>m.native_bounds[k]===p.mapping.native_bounds[k]&&m.webarea_bounds[k]===p.mapping.webarea_bounds[k])&&m.cg_window_id===p.mapping.cg_window_id&&m.document_uri===p.mapping.document_uri&&[m.target_id,m.frame_id,m.loader_id].every(x=>typeof x==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(x))&&Number.isFinite(m.time_origin),'electron_pointer_history_invalid');
 const v=m.metrics,b=m.native_bounds;
 insist(exact(v,['screen_origin','inner_size','outer_size','device_pixel_ratio','visual_viewport','css_viewport'])&&point(v.screen_origin)&&v.screen_origin.x===b.x&&v.screen_origin.y===b.y&&v.device_pixel_ratio===1,'electron_pointer_history_invalid');
 for(const q of [v.inner_size,v.outer_size])insist(exact(q,['width','height'])&&q.width===b.width&&q.height===b.height,'electron_pointer_history_invalid');
 const a=v.visual_viewport,c=v.css_viewport;
 insist(exact(a,['width','height','scale','offset_x','offset_y'])&&a.width===b.width&&a.height===b.height&&a.scale===1&&a.offset_x===0&&a.offset_y===0&&exact(c,['width','height','offset_x','offset_y','page_x','page_y','scale','zoom'])&&c.width===b.width&&c.height===b.height&&c.offset_x===0&&c.offset_y===0&&c.page_x===0&&c.page_y===0&&c.scale===1&&c.zoom===1,'electron_pointer_history_invalid');return m;
}

export const pointerResultKeys=['ready','binding_id','once_id','operation_id','receiver_kind','action','target_id','window_id','dispatch_attempted','down_attempted','down_returned','up_attempted','up_returned','sent_events','possibly_sent','release_state','effect_state','outcome','retry_allowed','receipt_durable','receipt_recovered','requested_hold_ms','elapsed_hold_ms','reason','session_detached'];
export function validPointerResult(r){
 if(!exact(r,pointerResultKeys)||r.receiver_kind!=='electron_renderer_pointer'||!uuid(r.binding_id)||!uuid(r.once_id)||typeof r.ready!=='boolean'||!['none','unknown'].includes(r.effect_state)||r.retry_allowed!==false||!['not_eligible','eligible','possibly_sent','acknowledged','unverified'].includes(r.release_state)||!['not_dispatched','dispatched_unverified','unknown_after_attempt'].includes(r.outcome)||!['dispatch_attempted','down_attempted','down_returned','up_attempted','up_returned','possibly_sent','receipt_durable','receipt_recovered','session_detached'].every(k=>typeof r[k]==='boolean')||!Number.isInteger(r.sent_events)||r.sent_events<0||r.sent_events>64||!(r.reason===null||typeof r.reason==='string'&&r.reason.length<=128&&/^electron_[a-z0-9_]+$/.test(r.reason))||!(r.requested_hold_ms===null||Number.isInteger(r.requested_hold_ms)&&r.requested_hold_ms>=1&&r.requested_hold_ms<=5000)||!(r.elapsed_hold_ms===null||typeof r.elapsed_hold_ms==='number'&&Number.isFinite(r.elapsed_hold_ms)&&r.elapsed_hold_ms>=0&&r.elapsed_hold_ms<=1e12))return false;
 if(r.ready&&(r.reason!==null||!r.dispatch_attempted||!r.session_detached||r.action!=='scroll'&&!r.up_returned))return false;
 if(r.ready&&(!bounded(r.operation_id)||!bounded(r.target_id)||!Number.isInteger(r.window_id)||r.window_id<=0||!['click','double_click','right_click','hold','right_hold','drag','scroll'].includes(r.action)))return false;
 if(r.down_returned&&!r.down_attempted||r.up_returned&&(!r.up_attempted||r.release_state!=='acknowledged'))return false;
 if(r.dispatch_attempted!==r.possibly_sent||r.possibly_sent&&r.effect_state!=='unknown')return false;
 if(!r.ready&&r.effect_state==='unknown')return true;
 if(!r.possibly_sent&&(r.effect_state!=='none'||r.down_attempted||r.up_attempted||r.sent_events!==0||r.release_state!=='not_eligible'||r.outcome!=='not_dispatched'))return false;
 return true;
}
