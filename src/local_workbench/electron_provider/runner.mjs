import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {RendererProvider,productionConnect,validateEnvelope,exact,insist} from './provider-core.mjs';

export {strictJSON} from './json.mjs';
import {strictJSON} from './json.mjs';

const captureAck=record=>record?.purpose==='capture_refresh';
const pointerAck=record=>['pointer_begin','pointer_step','pointer_hold'].includes(record?.purpose)&&record.pointer_contract===1;
const ackKeys=record=>['event','request_id','nonce','context_hash','allowed',...(captureAck(record)?['capture_remaining_seconds']:[]),...(pointerAck(record)?['pointer_remaining_seconds']:[])];
const validPointerRemaining=ack=>Number.isFinite(ack.pointer_remaining_seconds)&&ack.pointer_remaining_seconds>=0&&ack.pointer_remaining_seconds<=30;
const validCaptureRemaining=ack=>Number.isFinite(ack.capture_remaining_seconds)&&ack.capture_remaining_seconds>=0&&ack.capture_remaining_seconds<=30;

export class AnonymousChannel {
 constructor(input,output){this.input=input;this.output=output;this.buffer='';this.frames=[];this.waiter=null;this.closed=false;this.stop=false;this.requestID=null;this.envelopeSeen=false;this.ackExpected=null;this.transportPending=new Map();this.transportID=0;
  const decoder=new TextDecoder('utf-8',{fatal:true});input.on('data',bytes=>{try{this.buffer+=decoder.decode(bytes,{stream:true});insist(Buffer.byteLength(this.buffer)<=131072,'electron_input_buffer_limit');let n;
   while((n=this.buffer.indexOf('\n'))>=0){const line=this.buffer.slice(0,n);this.buffer=this.buffer.slice(n+1);const frame=strictJSON(line);
    if(frame.event==='pointer_transport_result'){
     insist(this.envelopeSeen&&exact(frame,['event','request_id','rpc_id','response'])&&frame.request_id===this.requestID&&this.transportPending.has(frame.rpc_id),'electron_pointer_transport_reply');
     const response=frame.response,entry=this.transportPending.get(frame.rpc_id);
     insist(response&&((exact(response,['ok','result'])&&response.ok===true&&response.result&&typeof response.result==='object'&&!Array.isArray(response.result))||(exact(response,['ok','error'])&&response.ok===false&&exact(response.error,['code'])&&/^electron_[a-z0-9_]+$/.test(response.error.code))),'electron_pointer_transport_reply');
     this.transportPending.delete(frame.rpc_id);clearTimeout(entry.timer);response.ok?entry.resolve(response.result):entry.reject(Error(response.error.code));continue;
    }
    if(frame.event==='stop'){insist(exact(frame,['event','request_id'])&&frame.request_id===this.requestID,'electron_stop_frame_invalid');this.stop=true;
     if(this.waiter){this.waiter.reject(Error('electron_stopped'));this.waiter=null;}continue;}
    if(this.envelopeSeen){const r=this.ackExpected;insist(r&&exact(frame,ackKeys(r))&&(!captureAck(r)||validCaptureRemaining(frame))&&(!pointerAck(r)||validPointerRemaining(frame))&&
      frame.event==='authorised'&&frame.request_id===r.request_id&&frame.nonce===r.nonce&&frame.context_hash===r.context_hash&&typeof frame.allowed==='boolean','electron_unexpected_frame');this.ackExpected=null;}
    else this.envelopeSeen=true;
    insist(this.frames.length<2,'electron_multiple_envelopes');if(this.waiter){const w=this.waiter;this.waiter=null;w.resolve(frame);}else this.frames.push(frame);}}
   catch{this.stop=true;this.failTransport();if(this.waiter){this.waiter.reject(Error('electron_input_invalid'));this.waiter=null;}}});
  input.on('end',()=>{try{decoder.decode();if(this.buffer.length)this.stop=true;}catch{this.stop=true;}this.closed=true;this.failTransport();if(this.waiter){this.waiter.reject(Error('electron_parent_closed'));this.waiter=null;}});
  input.on('error',()=>{this.closed=true;this.stop=true;this.failTransport();if(this.waiter){this.waiter.reject(Error('electron_parent_closed'));this.waiter=null;}});
  output.on('error',()=>{this.closed=true;this.stop=true;this.failTransport();});
 }
 failTransport(){for(const p of this.transportPending.values()){clearTimeout(p.timer);p.reject(Error('electron_pointer_transport_closed'));}this.transportPending.clear();}
 transport(command,fields={}){
  if(this.closed||this.transportPending.size>=32||this.transportID>=1024)return Promise.reject(Error('electron_pointer_transport_closed'));
  const rpc_id=++this.transportID,frame={event:'pointer_transport',request_id:this.requestID,rpc_id,command,...fields};
  return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.transportPending.delete(rpc_id);reject(Error('electron_pointer_transport_timeout'));},command==='close'?5000:3500);
   this.transportPending.set(rpc_id,{resolve,reject,timer});this.emit(frame).then(ok=>{if(!ok){const p=this.transportPending.get(rpc_id);if(p){clearTimeout(p.timer);this.transportPending.delete(rpc_id);p.reject(Error('electron_pointer_transport_closed'));}}});});
 }
 stopped(){return this.stop||this.closed;}
 next(timeout=1500){if(this.frames.length)return Promise.resolve(this.frames.shift());if(this.closed||this.stop)return Promise.reject(Error('electron_parent_closed'));
  return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.waiter=null;reject(Error('electron_parent_ack_timeout'));},timeout);
   this.waiter={resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}};});}
 emit(frame){return new Promise(resolve=>{const bytes=JSON.stringify(frame)+'\n';if(Buffer.byteLength(bytes)>65536){this.stop=true;resolve(false);return;}
  const timer=setTimeout(()=>resolve(false),1000);try{this.output.write(bytes,error=>{clearTimeout(timer);resolve(!error);});}catch{clearTimeout(timer);resolve(false);}});}
 async authorise(record){if(this.stopped())return false;this.requestID=record.request_id;this.ackExpected=record;if(!await this.emit(record))return false;
  let ack;try{ack=await this.next(1500);}catch{return false;}
  const allowed=!this.stopped()&&exact(ack,ackKeys(record))&&ack.event==='authorised'&&
   ack.request_id===record.request_id&&ack.nonce===record.nonce&&ack.context_hash===record.context_hash&&ack.allowed===true;
  if(!allowed)return false;
  if(pointerAck(record))return validPointerRemaining(ack)?{allowed:true,pointer_remaining_seconds:ack.pointer_remaining_seconds}:false;
  return captureAck(record)?(validCaptureRemaining(ack)?{allowed:true,capture_remaining_seconds:ack.capture_remaining_seconds}:false):true;
 }
}

export async function runCLI({input=process.stdin,output=process.stdout,connect=productionConnect}={}){
 const channel=new AnonymousChannel(input,output);let envelope,response;
 const signal=()=>{channel.stop=true;if(channel.waiter){channel.waiter.reject(Error('electron_stopped'));channel.waiter=null;}};
 process.on('SIGTERM',signal);process.on('SIGINT',signal);
 try{envelope=validateEnvelope(await channel.next(1500));channel.requestID=envelope.request_id;
  const provider=new RendererProvider({connect,authorise:r=>channel.authorise(r),stopped:()=>channel.stopped()});
  response={ok:true,result:await provider.run(envelope)};
 }catch(error){response={ok:false,error:{code:/^electron_[a-z0-9_]+$/.test(error.message)?error.message:'electron_provider_exception',effect_state:'none',retry_allowed:false}};}
 finally{if(Buffer.byteLength(JSON.stringify(response))>65000){const old=response.result;response={ok:true,result:{ready:false,
    binding_id:old?.binding_id,once_id:old?.once_id,receipt_recovered:old?.receipt_recovered??false,receipt_durable:old?.receipt_durable??false,
    outcome:'unknown_after_attempt',effect_state:old?.effect_state==='none'?'none':'unknown',reason:'electron_response_limit',retry_allowed:false}};}
  await channel.emit({event:'result',request_id:envelope?.request_id??null,response});
  process.off('SIGTERM',signal);process.off('SIGINT',signal);input.destroy();}
 return response;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 // One anonymous-stdin job only. No argv/env endpoint/root registration path.
 if(process.argv.length!==2){process.stderr.write('electron_arguments_refused\n');process.exitCode=2;}
 else runCLI().then(()=>process.exit(0),()=>process.exit(1));
}

export async function pointerHostConnect(channel){
 await channel.transport('connect');
 return {closed:false,call(method,params={},session_id,timeout=1500,pointer_deadline_ns){return channel.transport('call',{method,params,session_id:session_id??null,timeout,...(method==='Input.dispatchMouseEvent'&&params.type!=='mouseReleased'?{pointer_deadline_ns}: {})});},
  async close(){if(this.closed)return;this.closed=true;await channel.transport('close');}};
}
