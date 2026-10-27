import {spawn} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {AnonymousChannel,pointerHostConnect} from './runner.mjs';
import {strictJSON} from './json.mjs';
import {validateEnvelope,contextHash,exact,insist,productionConnect} from './provider-core.mjs';
import {OriginalKeyTransport} from './key-transport.mjs';
import {ManagedPointerProvider} from './pointer-provider.mjs';

// Native Flight and inherited fd2 ownership belong to this process. A killed
// validation child cannot close its original transport before matching UP.
export async function runGuardian({input=process.stdin,output=process.stdout,spawnChild,transportFactory,
 validate=validateEnvelope,pointerOptions={}}={}){
 const channel=new AnonymousChannel(input,output);let envelope,child,transport,response,admitted=false,ending=false,authorisationSeen=false;
 let killTimer;
 const stop=()=>{channel.stop=true;if(channel.waiter){channel.waiter.reject(Error('electron_stopped'));channel.waiter=null;}if(child?.exitCode===null&&child?.signalCode===null){
  child.kill('SIGTERM');
  // The transport/lease remain in this guardian. A wedged validation child
  // cannot hold shutdown forever or become the sole owner of release.
  if(!killTimer)killTimer=setTimeout(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');},500);
 }};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);input.on('end',stop);input.on('error',stop);output.on('error',stop);
 try{
  envelope=validate(await channel.next(1500));channel.requestID=envelope.request_id;
  if(['pointer','pointer_receipt'].includes(envelope.method)){
   const provider=new ManagedPointerProvider({connect:()=>pointerHostConnect(channel),...pointerOptions,
    authorise:r=>channel.authorise(r),progress:r=>channel.emit(r),stopped:()=>channel.stopped()||ending});
   response={ok:true,result:await provider.run(envelope)};ending=true;return response;
  }
  const envelopeAt=process.hrtime.bigint();
  insist(['key_pair','key_chord'].includes(envelope.method),'electron_guard_method');
  transport=transportFactory?transportFactory(envelope,()=>channel.stopped()||ending):new OriginalKeyTransport(envelope,{stopped:()=>channel.stopped()||ending});
  const environment={...process.env};for(const k of ['NODE_OPTIONS','NODE_PATH','ELECTRON_RUN_AS_NODE','VSCODE_IPC_HOOK_CLI'])delete environment[k];
  const entry=path.join(path.dirname(fileURLToPath(import.meta.url)),'guarded-child.mjs');
  child=spawnChild?spawnChild():spawn(process.execPath,[entry],{env:environment,stdio:['pipe','pipe',2,'ipc']});
  let buffer='',total=0,frames=Promise.resolve(),calls=new Set(),inFlight=0,connected=false;
  const decoder=new TextDecoder('utf-8',{fatal:true});
  const send=record=>{if(child.connected)try{child.send(record,e=>{if(e)stop();});}catch{stop();}};
  child.on('message',r=>{
   let valid=false;
   try{valid=r&&Number.isSafeInteger(r.id)&&r.id>0&&r.id<=1024&&calls.size<1024&&inFlight<32&&Buffer.byteLength(JSON.stringify(r))<=262144&&
    (r.kind==='connect'?exact(r,['kind','id','context_hash']):r.kind==='call'&&exact(r,['kind','id','method','params','session_id','timeout']));}catch{}
   if(!valid||calls.has(r.id)){stop();return;}
   calls.add(r.id);inFlight++;
   const call=async()=>{
    if(r.kind==='connect'){
     insist(!connected&&r.context_hash===contextHash(envelope.managed),'electron_guard_context');connected=true;await transport.open();return {};
    }
    insist(connected&&typeof r.method==='string'&&r.params&&typeof r.params==='object'&&!Array.isArray(r.params)&&
     (r.session_id===null||typeof r.session_id==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(r.session_id))&&
     Number.isInteger(r.timeout)&&r.timeout>0&&r.timeout<=2000,'electron_guard_call');
    return transport.call(r.method,r.params,r.session_id??undefined,r.timeout);
   };
   call().then(result=>send({id:r.id,ok:true,result}),e=>send({id:r.id,ok:false,
    code:/^electron_[a-z0-9_]+$/.test(e.message)?e.message:'electron_guard_call_failed'})).finally(()=>{inFlight--;});
  });
  child.stdout.on('data',bytes=>{
   total+=bytes.length;if(total>262144){stop();return;}try{buffer+=decoder.decode(bytes,{stream:true});}catch{stop();return;}let n;
   while((n=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,n);buffer=buffer.slice(n+1);
    frames=frames.then(async()=>{
     const r=strictJSON(line);insist(r.request_id===envelope.request_id,'electron_guard_child_request');
     if(r.event==='authorise'){
      insist(!authorisationSeen&&!ending,'electron_guard_duplicate_admission');authorisationSeen=true;
      // Validate against the original envelope/journal BEFORE asking signed host.
      transport.authorise(r);
      const allowed=await channel.authorise(r);admitted=allowed===true;transport.grant(admitted);
      const ack={event:'authorised',request_id:r.request_id,nonce:r.nonce,context_hash:r.context_hash,allowed:admitted};
      child.stdin.write(JSON.stringify(ack)+'\n');
     }else{
      insist(r.event==='result'&&exact(r,['event','request_id','response'])&&!ending,'electron_guard_child_frame');
      ending=true;response=r.response;
     }
    }).catch(()=>{stop();});
   }
  });
  child.stdin.on('error',stop);
  const exit=new Promise(resolve=>{child.once('error',()=>resolve({error:true}));child.once('close',(code,signal)=>resolve({code,signal}));});
  const timer=setTimeout(stop,10500);
  try{
   child.stdin.write(JSON.stringify({...envelope,host_pid:process.pid,
    host_uptime:envelope.host_uptime+Number(process.hrtime.bigint()-envelopeAt)/1e9})+'\n');
   await exit;await frames;
  }finally{clearTimeout(timer);clearTimeout(killTimer);}
  await transport.close();
  if(!response)response={ok:false,error:{code:'electron_validation_worker_closed',effect_state:admitted?'unknown':'none',retry_allowed:false}};
  else if(response.ok===false&&admitted)response={ok:false,error:{...response.error,effect_state:'unknown',retry_allowed:false}};
 }catch(e){response={ok:false,error:{code:/^electron_[a-z0-9_]+$/.test(e.message)?e.message:'electron_guard_exception',effect_state:admitted?'unknown':'none',retry_allowed:false}};}
 finally{
  if(child?.exitCode===null&&child?.signalCode===null)stop();
  await transport?.close();
  await channel.emit({event:'result',request_id:envelope?.request_id??null,response});
  process.off('SIGTERM',stop);process.off('SIGINT',stop);input.off('end',stop);input.off('error',stop);output.off('error',stop);
  input.destroy();
  if(child?.exitCode!==null||child?.signalCode!==null)clearTimeout(killTimer);
 }
 return response;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==2)process.exit(2);
 else runGuardian().then(()=>process.exit(0),()=>process.exit(1));
}
