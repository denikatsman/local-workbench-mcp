import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {randomUUID,createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {actionArguments,wellFormed} from './key-map.mjs';
import {strictJSON} from './json.mjs';
import {validatePointerPayload,assertPointerHistory} from './pointer-contract.mjs';

export const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OWNER=['claim_id','owner_session','runtime_generation','target_generation','window_id'];
const PROCESS=['pid','start_seconds','start_microseconds','uid','real_uid','pid_version','audit_token_base64','executable','bundle_identifier','signing_identifier','team_identifier','cdhash','designated_requirement'];
const MANAGED=['session_id','generation','boot_id','user_home','session_root','profile_path','port','browser_websocket_path','process','windows'];
export const WORKBENCH_URL='vscode-file://vscode-app/Applications/Visual%20Studio%20Code.app/Contents/Resources/app/out/vs/code/electron-browser/workbench/workbench.html';
export function insist(ok,code){if(!ok)throw Error(code);}
export function exact(o,keys){return o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===[...keys].sort().join(',');}
export const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export const hash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
export const contextHash=m=>hash(Object.fromEntries(Object.entries(m).filter(([k])=>k!=='windows')));
const text=(v,max)=>wellFormed(v,max,max*4)&&v.length>0&&!v.includes('\0');
const integer=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const absolute=p=>text(p,4096)&&path.isAbsolute(p)&&path.normalize(p)===p;
export function ownerValid(o){return exact(o,OWNER)&&OWNER.every(k=>text(o[k],128));}
export function fileURI(value,home){
 insist(text(value,8192),'electron_document_identity_unavailable');let candidate=value;
 if(candidate.startsWith('~/'))candidate=home+candidate.slice(1);
 if(candidate.startsWith('/')){insist(path.normalize(candidate)===candidate,'electron_document_path_invalid');return pathToFileURL(candidate).href;}
 let u;try{u=new URL(candidate);}catch{throw Error('electron_document_identity_unavailable');}
 insist(u.protocol==='file:'&&u.hostname===''&&u.search===''&&u.hash==='','electron_document_not_file');
 let decoded;try{decoded=decodeURIComponent(u.pathname);}catch{throw Error('electron_document_path_invalid');}
 insist(decoded.startsWith('/')&&path.normalize(decoded)===decoded&&pathToFileURL(decoded).href===candidate,'electron_document_path_invalid');
 return candidate;
}
export function validateEnvelope(e,{parentPID=process.ppid,home=os.homedir()}={}){
 insist(exact(e,['version','request_id','host_pid','host_uptime','method','managed','payload'])&&e.version===1&&UUID.test(e.request_id),'electron_envelope_invalid');
 insist(e.host_pid===parentPID&&integer(e.host_pid,1,0x7fffffff),'electron_host_parent_mismatch');
 insist(Number.isFinite(e.host_uptime)&&e.host_uptime>=0,'electron_host_clock_invalid');
 insist(['observe','key_pair','consume_plain_text','key_chord','receipt','refresh_for_capture','pointer','pointer_receipt'].includes(e.method),'electron_method_unavailable');
 const m=e.managed;insist(exact(m,MANAGED)&&[m.session_id,m.generation,m.boot_id].every(v=>typeof v==='string'&&UUID.test(v)),'electron_managed_context_invalid');
 insist(m.user_home===home&&absolute(m.user_home)&&absolute(m.session_root)&&
  m.session_root.endsWith('/native-operations/electron-sessions/'+m.session_id.toLowerCase()),'electron_session_root_invalid');
 insist(absolute(m.profile_path)&&integer(m.port,1025,65535)&&/^\/devtools\/browser\/[A-Za-z0-9_-]{1,128}$/.test(m.browser_websocket_path),'electron_endpoint_invalid');
 const p=m.process;insist(exact(p,PROCESS)&&integer(p.pid,1,0x7fffffff)&&integer(p.pid_version,-0x80000000,0x7fffffff)&&
  integer(p.start_seconds,1,Number.MAX_SAFE_INTEGER)&&integer(p.start_microseconds,0,999999)&&p.uid===process.getuid()&&p.real_uid===process.getuid(),
  'electron_process_identity_invalid');
 insist(p.executable==='/Applications/Visual Studio Code.app/Contents/MacOS/Code'&&p.bundle_identifier==='com.microsoft.VSCode'&&
  p.signing_identifier==='com.microsoft.VSCode'&&p.team_identifier==='UBF8T346G9'&&/^[0-9a-f]{40,128}$/.test(p.cdhash)&&
  text(p.designated_requirement,16384),'electron_signing_pin_invalid');
 const token=Buffer.from(p.audit_token_base64||'','base64');insist(token.length===32&&token.toString('base64')===p.audit_token_base64&&
  token.readUInt32LE(4)===p.uid&&token.readUInt32LE(12)===p.real_uid&&token.readUInt32LE(20)===p.pid&&token.readInt32LE(28)===p.pid_version,'electron_audit_pin_invalid');
 insist(Array.isArray(m.windows)&&(m.windows.length>0||['receipt','pointer_receipt'].includes(e.method))&&m.windows.length<=32,'electron_window_mapping_invalid');
 const ids=new Set();for(const w of m.windows){insist(exact(w,['cg_window_id','native_title',...(w.document_uri!==undefined?['document_uri']:[]),...(w.target_id!==undefined?['target_id']:[])])&&
  integer(w.cg_window_id,1,0x7fffffff)&&text(w.native_title,512)&&!ids.has(w.cg_window_id),'electron_window_mapping_invalid');ids.add(w.cg_window_id);
  if(w.document_uri!==undefined)insist(text(w.document_uri,8192),'electron_window_mapping_invalid');
  if(w.target_id!==undefined)insist(/^[A-Za-z0-9_-]{1,128}$/.test(w.target_id),'electron_target_pin_invalid');}
 const a=e.payload;insist(ownerValid(a?.owner),'electron_owner_invalid');
 if(e.method==='refresh_for_capture')insist(exact(a,['owner','cg_window_id','deadline_monotonic'])&&ids.has(a.cg_window_id)&&
  Number.isFinite(a.deadline_monotonic)&&a.deadline_monotonic>=e.host_uptime&&a.deadline_monotonic<=e.host_uptime+30,'electron_capture_refresh_invalid');
 else if(e.method==='observe')insist(exact(a,['owner','cg_window_id','include_text'])&&ids.has(a.cg_window_id)&&typeof a.include_text==='boolean','electron_observe_invalid');
 else if(e.method==='pointer_receipt')insist(exact(a,['owner','binding_id','once_id'])&&UUID.test(a.binding_id)&&UUID.test(a.once_id),'electron_pointer_receipt_invalid');
 else if(e.method==='pointer'){validatePointerPayload(a);insist(ids.has(a.mapping.cg_window_id),'electron_pointer_window_unknown');}
 else if(e.method==='receipt')insist(exact(a,['owner','once_id'])&&UUID.test(a.once_id),'electron_receipt_invalid');
 else{const keys=e.method==='consume_plain_text'?['text']:['key_code','characters','characters_ignoring_modifiers',...(e.method==='key_chord'?['modifiers']:[])];
  insist(exact(a,['owner','binding_id','once_id',...keys])&&UUID.test(a.binding_id)&&UUID.test(a.once_id),'electron_action_invalid');
  actionArguments(e.method,Object.fromEntries(keys.map(k=>[k,a[k]])));}
 return e;
}

// Node has no portable openat API. One job anchors its private cwd to an opened
// directory inode, then uses only UUID-derived relative names and O_NOFOLLOW.
// This avoids ancestor-path races for journal reads/writes after admission.
export class DurableSession {
 constructor(root){this.root=root;this.oldCwd=process.cwd();let current=path.parse(root).root;
  for(const c of root.slice(current.length).split('/')){current=path.join(current,c);const s=fs.lstatSync(current);insist(s.isDirectory()&&!s.isSymbolicLink(),'electron_unsafe_ancestor');}
  for(const d of [root,path.dirname(root),path.dirname(path.dirname(root))]){const s=fs.lstatSync(d);insist(s.uid===process.getuid()&&(s.mode&0o7777)===0o700,'electron_private_directory_required');}
  const before=fs.lstatSync(root);this.fd=fs.openSync(root,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);this.pin=fs.fstatSync(this.fd);
  try{insist(before.ino===this.pin.ino&&before.dev===this.pin.dev,'electron_journal_directory_changed');process.chdir(root);this.check();}
  catch(error){process.chdir(this.oldCwd);fs.closeSync(this.fd);this.fd=undefined;throw error;}
 }
 check(){const s=fs.statSync('.'),r=fs.fstatSync(this.fd);insist(s.dev===this.pin.dev&&s.ino===this.pin.ino&&r.dev===s.dev&&r.ino===s.ino&&
  s.uid===process.getuid()&&(s.mode&0o7777)===0o700,'electron_journal_directory_changed');}
 name(id,stage){insist(UUID.test(id)&&['binding','intent','terminal','keyboard-dispatch','keyboard-release','pointer-binding','pointer-intent','pointer-dispatch','pointer-release','pointer-terminal'].includes(stage),'electron_record_name_invalid');return id.toLowerCase()+'.'+stage+'.json';}
 exists(id,stage){this.check();try{fs.lstatSync(this.name(id,stage));return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
 read(id,stage){this.check();const fd=fs.openSync(this.name(id,stage),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{const s=fs.fstatSync(fd);insist(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o7777)===0o600&&s.nlink===1&&s.size>0&&s.size<=262144,'electron_private_record_invalid');
   const bytes=fs.readFileSync(fd);const end=fs.fstatSync(fd),named=fs.lstatSync(this.name(id,stage));
   insist(s.dev===end.dev&&s.ino===end.ino&&s.size===end.size&&s.mtimeMs===end.mtimeMs&&s.ctimeMs===end.ctimeMs&&s.ino===named.ino&&s.dev===named.dev&&bytes.length===s.size,'electron_record_changed');
   return strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes),262144);}finally{fs.closeSync(fd);}
 }
 write(id,stage,record){this.check();const bytes=Buffer.from(JSON.stringify(record)+'\n');insist(bytes.length<=262144,'electron_record_limit');
  const fd=fs.openSync(this.name(id,stage),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{const s=fs.fstatSync(fd);insist(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o7777)===0o600&&s.nlink===1,'electron_new_record_invalid');fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.fsyncSync(this.fd);this.check();
 }
 names(){this.check();const names=fs.readdirSync('.');
  const markers=names.filter(n=>/^[0-9a-f-]{36}\.keyboard-dispatch\.json$/.test(n)).length;
  const releases=names.filter(n=>/^[0-9a-f-]{36}\.keyboard-release\.json$/.test(n)).length;
  // Preserve the existing base-record budget. Each keyboard marker belongs to
  // an original binding+intent, so auxiliary records have a separate hard cap.
  insist(names.length<=16384&&names.length-markers-releases<=8192&&markers<=4096&&releases<=4096,'electron_journal_capacity');return names;
 }
 active(now){const names=this.names();let count=0;
  for(const name of names)if(/^[0-9a-f-]{36}\.binding\.json$/.test(name)){const b=this.read(name.slice(0,36),'binding');
   if(typeof b.observed_node_ns==='string'&&now-BigInt(b.observed_node_ns)<30000000000n&&!this.exists(b.once_id,'intent')&&!this.exists(b.once_id,'terminal'))count++;}
  return count;
 }
 // A new claim or observation cannot erase an unresolved original key-up.
 // This reads the existing immutable journal; it never reconnects or sends input.
 assertKeyboardRelease(managed,target,excludeOnce){
  this.assertPointerRelease(managed,target,excludeOnce);
  try{
   const names=this.names();
   const intents=names.filter(n=>/^[0-9a-f-]{36}\.intent\.json$/.test(n));
   for(const name of names.filter(n=>/^[0-9a-f-]{36}\.keyboard-dispatch\.json$/.test(n)))
    insist(intents.includes(name.replace('.keyboard-dispatch.json','.intent.json')),'electron_release_history_invalid');
   for(const name of names.filter(n=>/^[0-9a-f-]{36}\.keyboard-release\.json$/.test(n)))
    insist(intents.includes(name.replace('.keyboard-release.json','.intent.json')),'electron_release_history_invalid');
   const context=contextHash(managed),intentKeys=['version','owner','context_hash','binding_id','once_id','method','argument_sha256',
    'target_id','window_id','boot_id','original_node_ns','contract'];
   const markerKeys=['version','owner','context_hash','binding_id','once_id','method','target_id','window_id','boot_id'];
   for(const name of intents){
    const id=name.slice(0,36),intent=this.read(id,'intent'),versioned=Object.hasOwn(intent,'keyboard_release_contract');
    insist(exact(intent,[...intentKeys,...(versioned?['keyboard_release_contract']:[])])&&intent.version===1&&ownerValid(intent.owner)&&
     intent.context_hash===context&&UUID.test(intent.binding_id)&&UUID.test(intent.once_id)&&intent.once_id.toLowerCase()===id&&
     ['key_pair','key_chord','consume_plain_text'].includes(intent.method)&&/^[0-9a-f]{64}$/.test(intent.argument_sha256)&&
     /^[A-Za-z0-9_-]{1,128}$/.test(intent.target_id)&&integer(intent.window_id,1,0x7fffffff)&&intent.boot_id===managed.boot_id&&
     typeof intent.original_node_ns==='string'&&/^\d{1,30}$/.test(intent.original_node_ns)&&
     intent.contract==='missing_terminal_is_unknown_never_replay'&&(!versioned||intent.keyboard_release_contract===1&&intent.method!=='consume_plain_text'),
     'electron_release_history_invalid');
    if(intent.method==='consume_plain_text'){
     insist(!this.exists(id,'keyboard-dispatch')&&!this.exists(id,'keyboard-release'),'electron_release_history_invalid');continue;
    }
    const binding=this.read(intent.binding_id,'binding');
    insist(exact(binding,['version','owner','context_hash','boot_id','binding_id','once_id','window','target_id','marker','frame_id','loader_id',
     'dom','editor_state_hash','include_text','observed_host_uptime','deadline_monotonic','observed_node_ns'])&&binding.version===1&&
     ownerValid(binding.owner)&&hash(binding.owner)===hash(intent.owner)&&binding.context_hash===context&&binding.boot_id===managed.boot_id&&
     binding.binding_id===intent.binding_id&&binding.once_id===intent.once_id&&binding.target_id===intent.target_id&&
     binding.window?.cg_window_id===intent.window_id&&UUID.test(binding.marker),'electron_release_history_invalid');
    const marked=this.exists(id,'keyboard-dispatch');
    if(marked){const marker=this.read(id,'keyboard-dispatch');
     insist(versioned&&exact(marker,markerKeys)&&marker.version===1&&ownerValid(marker.owner)&&hash(marker.owner)===hash(intent.owner)&&
      marker.context_hash===context&&marker.binding_id===intent.binding_id&&marker.once_id===intent.once_id&&marker.method===intent.method&&
      marker.target_id===intent.target_id&&marker.window_id===intent.window_id&&marker.boot_id===managed.boot_id,'electron_release_history_invalid');}
    const released=this.exists(id,'keyboard-release');
    if(released){const proof=this.read(id,'keyboard-release');
     insist(marked&&versioned&&exact(proof,[...markerKeys,'argument_sha256','session_id','up_returned','original_transport'])&&proof.version===1&&
      ownerValid(proof.owner)&&hash(proof.owner)===hash(intent.owner)&&proof.context_hash===context&&proof.binding_id===intent.binding_id&&
      proof.once_id===intent.once_id&&proof.method===intent.method&&proof.target_id===intent.target_id&&proof.window_id===intent.window_id&&
      proof.boot_id===managed.boot_id&&proof.argument_sha256===intent.argument_sha256&&/^[A-Za-z0-9_-]{1,128}$/.test(proof.session_id)&&
      proof.up_returned===true&&proof.original_transport===true,'electron_release_history_invalid');}
    // Validate attribution before filtering: corrupt history cannot move debt to a sibling.
    if(intent.target_id!==target||intent.once_id===excludeOnce)continue;
    if(!this.exists(id,'terminal')){
     // New producers durably mark dispatch after authorisation. Legacy intent
     // alone cannot prove whether DOWN was sent, so it remains conservative.
     insist(released||versioned&&!marked,'electron_keyboard_release_unverified');continue;
    }
    const terminal=this.read(id,'terminal'),r=terminal.result;
    const required=['ready','binding_id','once_id','receiver_kind','action','dispatch_attempted','down_attempted','up_attempted',
     'effect_state','outcome','retry_allowed','before','receipt_durable'];
    const optional=['down_returned','up_returned','cleanup_unknown','after','readback_completed','complete_document_verified','visible_changed',
     'input_context_changed','reason','cleanup_deferred_unknown','renderer_binding_released','session_detached'];
    insist(exact(terminal,['version','owner','context_hash','result'])&&terminal.version===1&&ownerValid(terminal.owner)&&
     hash(terminal.owner)===hash(intent.owner)&&terminal.context_hash===context&&r&&typeof r==='object'&&!Array.isArray(r)&&
     required.every(k=>Object.hasOwn(r,k))&&Object.keys(r).every(k=>required.includes(k)||optional.includes(k))&&
     r.ready===true&&r.binding_id===intent.binding_id&&r.once_id===intent.once_id&&r.receiver_kind==='electron_renderer'&&r.action===intent.method&&
     r.retry_allowed===false&&r.receipt_durable===false&&r.before&&typeof r.before==='object'&&!Array.isArray(r.before)&&
     ['none','unknown','bounded_renderer_readback'].includes(r.effect_state)&&
     ['not_dispatched','dispatched_unverified','unknown_after_attempt','bounded_readback'].includes(r.outcome)&&
     ['dispatch_attempted','down_attempted','up_attempted','down_returned','up_returned','cleanup_unknown','readback_completed',
      'complete_document_verified','visible_changed','input_context_changed','cleanup_deferred_unknown','renderer_binding_released','session_detached']
      .every(k=>!Object.hasOwn(r,k)||typeof r[k]==='boolean'),'electron_release_history_invalid');
    if(!r.dispatch_attempted){
     insist(!released&&!r.down_attempted&&!r.up_attempted&&r.down_returned!==true&&r.up_returned!==true&&r.effect_state==='none',
      'electron_release_history_invalid');continue;
    }
    insist(!versioned||marked,'electron_release_history_invalid');
    insist(r.down_attempted&&r.up_attempted&&(released||r.up_returned===true&&r.cleanup_unknown!==true)&&r.effect_state!=='none',
     'electron_keyboard_release_unverified');
   }
  }catch(error){if(error.message==='electron_keyboard_release_unverified')throw error;
   throw Error('electron_keyboard_release_history_unverified');}
 }
 assertPointerRelease(managed,target,excludeOnce){
  try{assertPointerHistory(this,managed,target,excludeOnce,{hash,contextHash});}
  catch(error){if(error.message==='electron_pointer_release_unverified')throw error;throw Error('electron_pointer_release_history_unverified');}
 }
 close(){if(this.fd!==undefined){process.chdir(this.oldCwd);fs.closeSync(this.fd);this.fd=undefined;}}
}

export class CDP {
 constructor(url){this.socket=new WebSocket(url);this.next=0;this.pending=new Map();this.closed=false;
  this.socket.addEventListener('message',event=>{try{insist(typeof event.data==='string'&&Buffer.byteLength(event.data)<=12582912,'electron_cdp_frame_limit');const r=JSON.parse(event.data);
   const pending=this.pending.get(r.id),large=pending?.method==='Page.captureScreenshot'&&!r.method&&r.sessionId===pending.sessionId;
   insist(Buffer.byteLength(event.data)<=(large?12582912:262144),'electron_cdp_frame_limit');
   if(r.id&&this.pending.has(r.id)){const p=this.pending.get(r.id);
    insist(r.sessionId===p.sessionId,'electron_cdp_session_mismatch');
    this.pending.delete(r.id);clearTimeout(p.timer);r.error?p.reject(Error('electron_cdp_refused')):p.resolve(r.result);}}
   catch{this.fail('electron_cdp_protocol_unknown');}});
  this.socket.addEventListener('close',()=>this.fail('electron_cdp_closed_unknown'));this.socket.addEventListener('error',()=>this.fail('electron_cdp_error_unknown'));
 }
 fail(code){this.closed=true;for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(Error(code));}this.pending.clear();}
 async open(){if(this.closed)throw Error('electron_cdp_connect_failed');await new Promise((resolve,reject)=>{
  const t=setTimeout(()=>reject(Error('electron_cdp_connect_timeout')),1500);this.socket.addEventListener('open',()=>{clearTimeout(t);resolve();},{once:true});
  this.socket.addEventListener('error',()=>{clearTimeout(t);reject(Error('electron_cdp_connect_failed'));},{once:true});});}
 call(method,params={},sessionId,timeout=1500){insist(!this.closed,'electron_cdp_closed_unknown');const id=++this.next;
  return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending.delete(id);reject(Error('electron_cdp_timeout_unknown'));},timeout);
   this.pending.set(id,{resolve,reject,timer,method,sessionId});try{this.socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));}
   catch{clearTimeout(timer);this.pending.delete(id);reject(Error('electron_cdp_send_unknown'));}});
 }
 close(){this.socket.close();this.fail('electron_cdp_closed_unknown');}
}

// Observation only: no DOM/clipboard setters, focus calls or layout inference.
// Weak receiver/editor identities live for the original renderer document only.
export function rendererExpression(marker,mode,expectedLabel=null){return `(()=>{const a=document.activeElement,e=a?.closest('.monaco-editor'),g=e?.closest('.editor-group-container'),
 tabs=[...(g||document).querySelectorAll('.tab.active .monaco-icon-label[aria-label]')],label=a?.getAttribute('aria-label')||'',
 plain=!!e&&!!g&&(a.tagName==='TEXTAREA'||(a.tagName==='DIV'&&a.classList.contains('native-edit-context')&&!!a.editContext)),
 sensitive=a?.type==='password'||/password|secret|token|credential/i.test(label),readonly=!!a?.readOnly||!!a?.disabled||!!e?.classList.contains('read-only')||!!e?.classList.contains('readonly')||a?.getAttribute('aria-readonly')==='true'||e?.getAttribute('aria-readonly')==='true';
 const documentLabel=tabs.length===1?tabs[0].getAttribute('aria-label'):null;let root=globalThis.__lwbRendererProvider106;
 if(!root&&${JSON.stringify(mode)}==='bind'&&documentLabel===${JSON.stringify(expectedLabel)}){root={entries:new Map()};Object.defineProperty(globalThis,'__lwbRendererProvider106',{value:root,configurable:true});}
 for(const [k,v]of root?.entries||[])if(performance.now()-v.at>=30000||!v.editor.deref())root.entries.delete(k);
 let original=root?.entries.get(${JSON.stringify(marker)}),same=!!original&&original.receiver.deref()===a&&original.editor.deref()===e;
 if(${JSON.stringify(mode)}==='bind'&&plain&&!sensitive&&!readonly&&documentLabel===${JSON.stringify(expectedLabel)}){if(root.entries.size>=64)throw Error('renderer_binding_capacity');
  root.entries.set(${JSON.stringify(marker)},{receiver:new WeakRef(a),editor:new WeakRef(e),at:performance.now(),timeOrigin:performance.timeOrigin});same=true;}
 const result={href:location.href,time_origin:performance.timeOrigin,title:document.title,document_label:documentLabel,
 active_label:label,active_tag:a?.tagName||'',active_class:typeof a?.className==='string'?a.className:'',plain,sensitive,readonly,same_receiver:same,has_focus:document.hasFocus(),
 selection:a?.editContext?{start:a.editContext.selectionStart,end:a.editContext.selectionEnd}:a?.tagName==='TEXTAREA'?{start:a.selectionStart,end:a.selectionEnd}:null};
 if(plain&&!sensitive&&!readonly&&documentLabel===${JSON.stringify(expectedLabel)}&&['bind','check'].includes(${JSON.stringify(mode)})){const lines=[...e.querySelectorAll('.view-lines')];const view=lines.length===1?lines[0].textContent:null;
  const context=a.editContext?.text??(a.tagName==='TEXTAREA'?a.value:null);
  result.visible_text=typeof view==='string'&&view.length<=4096?view:null;result.context_text=typeof context==='string'&&context.length<=4096?context:null;}
 if(${JSON.stringify(mode)}==='release')root?.entries.delete(${JSON.stringify(marker)});return result;})()`;}

function qualifyDOM(dom,m,window,binding,after=false,requireSame=true,literalText=false){
 insist(dom&&dom.href===WORKBENCH_URL&&Number.isFinite(dom.time_origin),'electron_renderer_document_invalid');
 // Security remains first, including when the focused control is outside the editor.
 insist(dom.sensitive===false&&dom.readonly===false,'electron_secure_or_readonly_editor');
 insist(dom.plain===true,'electron_receiver_changed');
 insist(fileURI(dom.document_label,m.user_home)===window.document_uri,'electron_document_changed');
 if(requireSame)insist(dom.same_receiver===true,'electron_receiver_changed');
 if(binding){
  // Literal input can finish an existing textarea composition. Admit only the
  // observed terminal class removal during readback; this is not IME proof.
  const priorClass=binding.dom.active_class,textareaClass='inputarea monaco-mouse-cursor-text';
  const sameClass=dom.active_class===priorClass||(after&&literalText&&binding.dom.active_tag==='TEXTAREA'&&
   priorClass===textareaClass+' ime-input'&&dom.active_class===textareaClass);
  insist(dom.time_origin===binding.dom.time_origin&&dom.active_label===binding.dom.active_label&&dom.active_tag===binding.dom.active_tag&&
   sameClass&&(!after?dom.title===binding.dom.title:true),'electron_receiver_metadata_changed');
 }
 for(const key of ['visible_text','context_text'])if(dom[key]!==null&&dom[key]!==undefined)insist(wellFormed(dom[key],4096,16384),'electron_editor_readback_limit');
}
const snapshot=(dom,include)=>({scope:'exact_renderer_visible_lines_and_input_context_not_complete_document',complete_document:false,
 visible_sha256:typeof dom.visible_text==='string'?hash(dom.visible_text):null,context_sha256:typeof dom.context_text==='string'?hash(dom.context_text):null,
 visible_utf16_units:dom.visible_text?.length??null,context_utf16_units:dom.context_text?.length??null,selection:dom.selection,
 ...(include?{visible_text:dom.visible_text??null,context_text:dom.context_text??null}:{}),renderer_focus:dom.has_focus});
const editorHash=dom=>hash({visible:dom.visible_text,context:dom.context_text,selection:dom.selection});
const metadataOnly=dom=>Object.fromEntries(Object.entries(dom).filter(([k])=>!['visible_text','context_text'].includes(k)));

// Pure metadata only: capture does not create/retire input bindings or read editor content.
export const captureMetadataExpression=`(()=>{const a=document.activeElement,g=a?.closest('.editor-group-container'),
 tabs=[...(g||document).querySelectorAll('.tab.active .monaco-icon-label[aria-label]')];
 return {href:location.href,time_origin:performance.timeOrigin,title:document.title,
 document_label:tabs.length===1?tabs[0].getAttribute('aria-label'):null};})()`;

export class RendererProvider {
 constructor({connect,authorise,stopped=()=>false,now=()=>process.hrtime.bigint(),journalFactory=root=>new DurableSession(root)}){
  this.connect=connect;this.authorise=authorise;this.stopped=stopped;this.now=now;this.journalFactory=journalFactory;}
 freshness(binding,e){const now=this.now(),born=BigInt(binding.observed_node_ns);insist(now>=born&&now-born<30000000000n&&
  e.host_uptime>=binding.observed_host_uptime&&e.host_uptime<binding.deadline_monotonic,'electron_binding_expired');
  insist(binding.context_hash===contextHash(e.managed)&&binding.boot_id===e.managed.boot_id,'electron_context_changed');}
 async refreshForCapture(e){
  const started=this.now(),a=e.payload,m=e.managed,result={ready:false,receiver_kind:'electron_renderer',refresh_for_capture:true,
   dispatch_attempted:false,screenshot_acknowledged:false,frame_age_known:false,session_detached:false,effect_state:'none',retry_allowed:false};
  let cdp,authorisedDeadline;const attached=[];
  const fresh=()=>{const current=this.now(),elapsed=current-started;insist(elapsed>=0n&&e.host_uptime+Number(elapsed)/1e9<a.deadline_monotonic&&
   (authorisedDeadline===undefined||current<authorisedDeadline),'electron_capture_refresh_expired');
   insist(!this.stopped(),'electron_stopped_before_capture');};
  try{
   validateEnvelope(e);fresh();const window=m.windows.find(w=>w.cg_window_id===a.cg_window_id);
   insist(window?.document_uri&&fileURI(window.document_uri,m.user_home)===window.document_uri,'electron_document_identity_unavailable');
   cdp=await this.connect(m);fresh();
   const targets=async()=>{const infos=(await cdp.call('Target.getTargets')).targetInfos;insist(Array.isArray(infos)&&infos.length<=128,'electron_targets_invalid');return infos;};
   const infos=await targets(),matches=[];
   const read=async(session,target)=>{
    fresh();const current=(await targets()).find(t=>t.targetId===target);
    insist(current?.type==='page'&&current.url===WORKBENCH_URL&&current.title===window.native_title,'electron_capture_target_changed');
    const r=await cdp.call('Runtime.evaluate',{expression:captureMetadataExpression,returnByValue:true},session);
    insist(!r.exceptionDetails,'electron_renderer_observation_failed');const dom=r.result?.value;
    insist(dom?.href===WORKBENCH_URL&&dom.title===window.native_title&&Number.isFinite(dom.time_origin)&&
     fileURI(dom.document_label,m.user_home)===window.document_uri,'electron_capture_document_changed');
    const frame=(await cdp.call('Page.getFrameTree',{},session)).frameTree?.frame;
    insist(text(frame?.id,128)&&text(frame?.loaderId,128)&&frame.url===WORKBENCH_URL,'electron_frame_identity_unavailable');
    fresh();return {time_origin:dom.time_origin,frame_id:frame.id,loader_id:frame.loaderId};
   };
   for(const info of infos.filter(t=>t.type==='page'&&t.url===WORKBENCH_URL&&t.title===window.native_title&&(!window.target_id||t.targetId===window.target_id))){
    fresh();const session=(await cdp.call('Target.attachToTarget',{targetId:info.targetId,flatten:true})).sessionId;
    insist(text(session,128),'electron_capture_session_invalid');attached.push(session);
    try{matches.push({session,target:info.targetId,identity:await read(session,info.targetId)});}catch(error){
     // A same-title sibling may be a different document. It is never selected by order.
     if(error.message!=='electron_capture_document_changed'&&error.message!=='electron_document_not_file')throw error;
    }
   }
   insist(matches.length===1,'electron_document_mapping_unavailable_or_ambiguous');const chosen=matches[0];
   const verify=async()=>{insist(hash(await read(chosen.session,chosen.target))===hash(chosen.identity),'electron_capture_document_changed');fresh();};
   fresh();const auth={event:'authorise',request_id:e.request_id,nonce:randomUUID(),context_hash:contextHash(m),owner:a.owner,
    cg_window_id:window.cg_window_id,document_uri:window.document_uri,target_id:chosen.target,...chosen.identity,purpose:'capture_refresh'};
   const authorisationStarted=this.now(),approval=await this.authorise(auth);
   insist(exact(approval,['allowed','capture_remaining_seconds'])&&approval.allowed===true&&Number.isFinite(approval.capture_remaining_seconds)&&
    approval.capture_remaining_seconds>=0&&approval.capture_remaining_seconds<=30,'electron_capture_authorisation_refused');
   authorisedDeadline=authorisationStarted+BigInt(Math.floor(approval.capture_remaining_seconds*1e9));fresh();await verify();fresh();
   result.dispatch_attempted=true;
   const shot=await cdp.call('Page.captureScreenshot',{format:'png',fromSurface:true,captureBeyondViewport:false},chosen.session);
   result.screenshot_acknowledged=true;fresh();
   insist(typeof shot?.data==='string'&&shot.data.length>0&&shot.data.length<=11184812&&/^[A-Za-z0-9+/]*={0,2}$/.test(shot.data),'electron_capture_png_limit');
   const bytes=Buffer.from(shot.data,'base64');insist(bytes.length<=8388608&&bytes.length>=8&&bytes.toString('base64')===shot.data&&
    bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])),'electron_capture_png_invalid');
   await verify();result.ready=true;result.effect_state='renderer_capture_requested';
  }catch(error){result.reason=/^electron_[a-z0-9_]+$/.test(error.message)?error.message:'electron_capture_refresh_failed';
   result.ready=false;result.effect_state=result.dispatch_attempted?'unknown':'none';
  }finally{
   // Expiry forbids publication, never cleanup of an already attached session.
   try{fresh();}catch(error){result.ready=false;result.reason=error.message;result.effect_state=result.dispatch_attempted?'unknown':'none';}
   let detached=attached.length>0;const cleanupStarted=this.now();
   for(const session of attached){if(this.now()-cleanupStarted>1000000000n){detached=false;break;}
    try{await cdp.call('Target.detachFromTarget',{sessionId:session},undefined,500);}catch{detached=false;}}
   result.session_detached=detached;
   if(attached.length&&!detached){result.ready=false;result.reason='electron_capture_detach_unknown';result.effect_state=result.dispatch_attempted?'unknown':'none';}
   try{fresh();}catch(error){result.ready=false;result.reason=error.message;result.effect_state=result.dispatch_attempted?'unknown':'none';}
   cdp?.close();
  }
  return result;
 }
 async run(e){if(e.method==='refresh_for_capture')return this.refreshForCapture(e);const startedNode=this.now(),m=e.managed,a=e.payload,pinsHash=contextHash(m),journal=this.journalFactory(m.session_root);let cdp,session,binding,marker,attempted=false,result,published=false;const attached=[];
  const fresh=()=>{this.freshness(binding,e);insist(e.host_uptime+Number(this.now()-startedNode)/1e9<binding.deadline_monotonic,'electron_binding_expired');};
  try{
   if(e.method==='receipt'){
    let terminal;try{terminal=journal.read(a.once_id,'terminal');}catch{return {ready:false,receipt_recovered:false,effect_state:'unknown',retry_allowed:false,reason:'electron_original_receipt_unavailable'};}
    insist(exact(terminal,['version','owner','context_hash','result'])&&terminal.version===1&&ownerValid(terminal.owner)&&
     hash(terminal.owner)===hash(a.owner)&&terminal.context_hash===pinsHash&&terminal.result?.once_id===a.once_id&&UUID.test(terminal.result?.binding_id),'electron_receipt_owner_mismatch');
    return {...terminal.result,receipt_recovered:true,receipt_read_verified:true,receipt_durable:false};
   }
   insist(!this.stopped(),'electron_stopped_before_admission');
   cdp=await this.connect(m);const infos=(await cdp.call('Target.getTargets')).targetInfos;
   insist(Array.isArray(infos)&&infos.length<=128,'electron_targets_invalid');
   let window;
   if(e.method==='observe'){
    insist(journal.active(this.now())<64,'electron_active_binding_limit');window=m.windows.find(w=>w.cg_window_id===a.cg_window_id);
    insist(window.document_uri,'electron_document_identity_unavailable');
    insist(fileURI(window.document_uri,m.user_home)===window.document_uri,'electron_document_identity_unavailable');
    const candidates=infos.filter(t=>t.type==='page'&&t.url===WORKBENCH_URL&&t.title===window.native_title&&(!window.target_id||t.targetId===window.target_id));
    // Same-name windows are resolved by their actual document URI, never index,
    // geometry or guessed captions. Temporary exact sessions inspect candidates.
    const matches=[];for(const info of candidates){insist(!this.stopped(),'electron_stopped_before_admission');const s=(await cdp.call('Target.attachToTarget',{targetId:info.targetId,flatten:true})).sessionId;
     const token=randomUUID();attached.push({session:s,marker:token});try{const meta=await cdp.call('Runtime.evaluate',{expression:rendererExpression(token,'metadata'),returnByValue:true},s);
      insist(!meta.exceptionDetails,'electron_renderer_observation_failed');qualifyDOM(meta.result?.value,m,window,undefined,false,false);
      const r=await cdp.call('Runtime.evaluate',{expression:rendererExpression(token,'bind',meta.result.value.document_label),returnByValue:true},s);
      insist(!r.exceptionDetails,'electron_renderer_observation_failed');const dom=r.result?.value;qualifyDOM(dom,m,window);
      insist(dom.title===info.title&&dom.title===window.native_title,'electron_window_title_changed');matches.push({info,s,token,dom});}
     catch{try{await cdp.call('Target.detachFromTarget',{sessionId:s});}catch{}}}
    insist(matches.length===1,'electron_document_mapping_unavailable_or_ambiguous');({s:session,token:marker}=matches[0]);const {info,dom}=matches[0];
    journal.assertKeyboardRelease(m,info.targetId);
    const frame=(await cdp.call('Page.getFrameTree',{},session)).frameTree?.frame;insist(frame?.id&&frame.loaderId&&frame.url===WORKBENCH_URL,'electron_frame_identity_unavailable');
    binding={version:1,owner:a.owner,context_hash:pinsHash,boot_id:m.boot_id,binding_id:randomUUID(),once_id:randomUUID(),window,
     target_id:info.targetId,marker,frame_id:frame.id,loader_id:frame.loaderId,dom:metadataOnly(dom),editor_state_hash:editorHash(dom),include_text:a.include_text,
     observed_host_uptime:e.host_uptime,deadline_monotonic:e.host_uptime+30,observed_node_ns:this.now().toString()};
    insist(!this.stopped(),'electron_stopped_before_binding');journal.write(binding.binding_id,'binding',binding);published=true;
    return {ready:true,binding_id:binding.binding_id,once_id:binding.once_id,deadline_monotonic:binding.deadline_monotonic,freshness_clock:'system_uptime_v1',
     receiver_kind:'electron_renderer',capabilities:{key_pair:true,consume_plain_text:true,key_chord:true},state:{window_id:window.cg_window_id,
      receiver_kind:'electron_renderer',renderer_target_id:info.targetId,document_uri:window.document_uri,renderer_focus:dom.has_focus},text_snapshot:snapshot(dom,a.include_text)};
   }
   binding=journal.read(a.binding_id,'binding');marker=binding.marker;window=binding.window;
   insist(exact(binding,['version','owner','context_hash','boot_id','binding_id','once_id','window','target_id','marker','frame_id','loader_id','dom','editor_state_hash','include_text','observed_host_uptime','deadline_monotonic','observed_node_ns'])&&
    binding.version===1&&ownerValid(binding.owner)&&binding.binding_id===a.binding_id&&binding.once_id===a.once_id&&UUID.test(marker)&&
    typeof binding.observed_node_ns==='string'&&/^\d{1,30}$/.test(binding.observed_node_ns)&&hash(binding.owner)===hash(a.owner),'electron_binding_owner_mismatch');
   const freshWindow=m.windows.find(w=>w.cg_window_id===window.cg_window_id);insist(freshWindow&&freshWindow.document_uri===window.document_uri&&
    (!freshWindow.target_id||freshWindow.target_id===binding.target_id),'electron_native_window_document_changed');
   fresh();insist(!journal.exists(a.once_id,'intent')&&!journal.exists(a.once_id,'terminal'),'electron_once_consumed_never_replay');
   journal.assertKeyboardRelease(m,binding.target_id);
   const info=infos.find(t=>t.targetId===binding.target_id);insist(info&&info.type==='page'&&info.url===WORKBENCH_URL,'electron_target_changed');
   session=(await cdp.call('Target.attachToTarget',{targetId:binding.target_id,flatten:true})).sessionId;attached.push({session,marker});
   const read=async after=>{const frame=(await cdp.call('Page.getFrameTree',{},session)).frameTree?.frame;
    insist(frame?.id===binding.frame_id&&frame.loaderId===binding.loader_id&&frame.url===WORKBENCH_URL,'electron_frame_document_changed');
    const r=await cdp.call('Runtime.evaluate',{expression:rendererExpression(marker,'check',binding.dom.document_label),returnByValue:true},session);
    insist(!r.exceptionDetails,'electron_renderer_observation_failed');const dom=r.result?.value;qualifyDOM(dom,m,window,binding,after,true,e.method==='consume_plain_text');return dom;};
   let before=await read(false);insist(editorHash(before)===binding.editor_state_hash,'electron_editor_changed_since_observation');
   fresh();insist(!this.stopped(),'electron_stopped_before_intent');
   const keys=Object.keys(a).filter(k=>!['owner','binding_id','once_id'].includes(k)),args=Object.fromEntries(keys.map(k=>[k,a[k]]));const action=actionArguments(e.method,args);
   result={ready:true,binding_id:a.binding_id,once_id:a.once_id,receiver_kind:'electron_renderer',action:e.method,dispatch_attempted:false,
    down_attempted:false,up_attempted:false,effect_state:'none',outcome:'not_dispatched',retry_allowed:false,before:snapshot(before,binding.include_text),receipt_durable:false};
   journal.write(a.once_id,'intent',{version:1,owner:a.owner,context_hash:pinsHash,binding_id:a.binding_id,once_id:a.once_id,method:e.method,
    argument_sha256:hash(args),target_id:binding.target_id,window_id:window.cg_window_id,boot_id:m.boot_id,
    original_node_ns:this.now().toString(),contract:'missing_terminal_is_unknown_never_replay',
    ...(e.method==='consume_plain_text'?{}:{keyboard_release_contract:1})});
   const nonce=randomUUID(),auth={event:'authorise',request_id:e.request_id,nonce,context_hash:pinsHash,binding_id:a.binding_id,once_id:a.once_id,
    owner:a.owner,cg_window_id:window.cg_window_id,document_uri:window.document_uri,target_id:binding.target_id,renderer_state_hash:hash(before)};
   const allowed=await this.authorise(auth);insist(allowed===true&&!this.stopped(),'electron_host_authorisation_refused');
   fresh();before=await read(false);insist(editorHash(before)===binding.editor_state_hash,'electron_editor_changed_during_authorisation');
   fresh();insist(!this.stopped(),'electron_stopped_before_effect');
   journal.assertKeyboardRelease(m,binding.target_id,a.once_id);
   if(e.method!=='consume_plain_text')journal.write(a.once_id,'keyboard-dispatch',{version:1,owner:a.owner,context_hash:pinsHash,
    binding_id:a.binding_id,once_id:a.once_id,method:e.method,target_id:binding.target_id,window_id:window.cg_window_id,boot_id:m.boot_id});
   fresh();insist(!this.stopped(),'electron_stopped_before_effect');
   attempted=true;result.dispatch_attempted=true;result.effect_state='unknown';result.outcome='dispatched_unverified';
   if(e.method==='consume_plain_text')await cdp.call('Input.insertText',{text:action.text},session);
   else{
    // Queue the bounded pair in the original transport/session order. Waiting
    // for down's ACK must not withhold its cleanup up. Attach down rejection
    // handling immediately; both ACKs remain independently required evidence.
    let down;result.down_attempted=true;
    try{down=Promise.resolve(cdp.call('Input.dispatchKeyEvent',action.down,session)).then(
      ()=>{result.down_returned=true;return {returned:true};},error=>({returned:false,error}));}
    catch(error){down=Promise.resolve({returned:false,error});}
    result.up_attempted=true;try{await cdp.call('Input.dispatchKeyEvent',action.up,session,2000);result.up_returned=true;}
    catch{result.up_returned=false;result.cleanup_unknown=true;}
    const acknowledged=await down;if(!acknowledged.returned)throw acknowledged.error;
   }
   // No further input occurs during readback. Native focus remains host evidence
   // and dispatch acknowledgements alone never upgrade effect state.
   try{insist(!this.stopped(),'electron_readback_after_stop_unavailable');const after=await read(true);result.after=snapshot(after,binding.include_text);
    insist(typeof after.visible_text==='string'||typeof after.context_text==='string','electron_bounded_readback_unavailable');result.readback_completed=true;
    result.effect_state=result.cleanup_unknown?'unknown':'bounded_renderer_readback';result.outcome=result.cleanup_unknown?'unknown_after_attempt':'bounded_readback';result.complete_document_verified=false;
    result.visible_changed=hash(before.visible_text)!==hash(after.visible_text);result.input_context_changed=hash(before.context_text)!==hash(after.context_text);}
   catch{result.reason='electron_bounded_readback_unavailable';result.outcome='unknown_after_attempt';}
   return result;
  }catch(error){const reason=/^electron_[a-z0-9_]+$/.test(error.message)?error.message:'electron_provider_exception';
   if(result){result.reason=reason;result.outcome=attempted?'unknown_after_attempt':'not_dispatched';result.effect_state=attempted?'unknown':'none';return result;}
   return {ready:false,reason,effect_state:e.method==='receipt'||reason==='electron_once_consumed_never_replay'?'unknown':'none',retry_allowed:false,
    ...(reason==='electron_once_consumed_never_replay'?{outcome:'unknown_original_never_replay'}:{}),...(binding?{binding_id:binding.binding_id,once_id:binding.once_id}:{} )};
  }finally{
   const cleanupStarted=this.now();if(cdp)for(const item of attached){if(this.now()-cleanupStarted>1000000000n){if(result)result.cleanup_deferred_unknown=true;break;}
    if(item.marker&&!(published&&item.marker===marker))try{
     await cdp.call('Runtime.evaluate',{expression:rendererExpression(item.marker,'release'),returnByValue:true},item.session,500);if(result)result.renderer_binding_released=true;}
    catch{if(result)result.renderer_binding_released=false;}
    try{await cdp.call('Target.detachFromTarget',{sessionId:item.session},undefined,500);if(result)result.session_detached=true;}
    catch{if(result)result.session_detached=false;}}
   if(result&&binding){try{journal.write(binding.once_id,'terminal',{version:1,owner:binding.owner,context_hash:pinsHash,result:{...result,receipt_durable:false}});
     result.receipt_durable=true;}catch{result.receipt_durable=false;result.receipt_state='unknown';}}
   cdp?.close();journal.close();
  }
 }
}

export async function productionConnect(m){
 const endpoint='http://127.0.0.1:'+m.port;const response=await fetch(endpoint+'/json/version',{signal:AbortSignal.timeout(1500)});
 insist(response.ok,'electron_endpoint_unavailable');const body=await response.text();insist(Buffer.byteLength(body)<=16384,'electron_endpoint_metadata_limit');
 const metadata=JSON.parse(body),url='ws://127.0.0.1:'+m.port+m.browser_websocket_path;
 insist(metadata.webSocketDebuggerUrl===url,'electron_endpoint_identity_changed');const cdp=new CDP(url);await cdp.open();return cdp;
}
