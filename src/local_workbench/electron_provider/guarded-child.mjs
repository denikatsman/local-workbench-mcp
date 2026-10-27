import {runCLI} from './runner.mjs';
import {exact,insist,contextHash} from './provider-core.mjs';

// Fixed sealed entry point, launched only by guardian.mjs. No endpoint/root in
// argv or env; all context comes through the original anonymous envelope.
const pending=new Map();let next=0,closed=false;
function fail(){closed=true;for(const p of pending.values()){clearTimeout(p.timer);p.reject(Error('electron_guard_channel_closed'));}pending.clear();}
process.on('disconnect',fail);
process.on('message',r=>{
 if(!r||!exact(r,['id','ok',...(r.ok===true?['result']:['code'])])||!Number.isSafeInteger(r.id)||!pending.has(r.id)){fail();return;}
 const p=pending.get(r.id);pending.delete(r.id);clearTimeout(p.timer);r.ok?p.resolve(r.result):p.reject(Error(r.code));
});
const rpc=packet=>new Promise((resolve,reject)=>{
 if(closed||!process.connected)return reject(Error('electron_guard_channel_closed'));
 const id=++next,timer=setTimeout(()=>{pending.delete(id);reject(Error('electron_guard_rpc_timeout'));},4500);
 pending.set(id,{resolve,reject,timer});
 try{process.send({...packet,id},e=>{if(e){const p=pending.get(id);if(p){pending.delete(id);clearTimeout(timer);p.reject(Error('electron_guard_channel_closed'));}}});}
 catch{clearTimeout(timer);pending.delete(id);reject(Error('electron_guard_channel_closed'));}
});
async function connect(managed){
 await rpc({kind:'connect',context_hash:contextHash(managed)});
 return {call:(method,params={},sessionId,timeout=1500)=>rpc({kind:'call',method,params,session_id:sessionId??null,timeout}),
  close(){/* The guardian retains original cleanup ownership through exit. */}};
}
if(process.argv.length!==2||typeof process.send!=='function')process.exit(2);
else runCLI({connect}).then(()=>process.exit(0),()=>process.exit(1));
