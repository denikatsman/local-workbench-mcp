import {Buffer} from 'node:buffer';
const insist=(ok,code)=>{if(!ok)throw Error(code);};
// Bounded JSON with duplicate-key, depth, key-count, total-value and number
// checks. Both anonymous-pipe frames and private records use this grammar.
export function strictJSON(bytes,max=65536){
 insist(Buffer.byteLength(bytes,'utf8')<=max,'electron_json_limit');let i=0,values=0;
 const white=()=>{while(/[\t\r\n ]/.test(bytes[i]||'!'))i++;};
 function string(){const start=i++;while(i<bytes.length){const c=bytes[i++];if(c==='"')return JSON.parse(bytes.slice(start,i));
  if(c==='\\')i++;else if(c.charCodeAt(0)<32)throw Error('electron_json_invalid');}throw Error('electron_json_invalid');}
 function value(depth){white();insist(depth<=32&&++values<=4096,'electron_json_structure_limit');const c=bytes[i];
  if(c==='"')return string();
  if(c==='{'){i++;white();const result={},keys=new Set();if(bytes[i]==='}'){i++;return result;}while(true){white();insist(bytes[i]==='"','electron_json_invalid');
   const key=string();insist(!keys.has(key)&&keys.size<256,'electron_json_duplicate_or_key_limit');keys.add(key);white();insist(bytes[i++]===':','electron_json_invalid');
   Object.defineProperty(result,key,{value:value(depth+1),enumerable:true,writable:true,configurable:true});white();if(bytes[i]==='}'){i++;return result;}insist(bytes[i++]===',','electron_json_invalid');}}
  if(c==='['){i++;white();const result=[];if(bytes[i]===']'){i++;return result;}while(true){result.push(value(depth+1));white();if(bytes[i]===']'){i++;return result;}insist(bytes[i++]===',','electron_json_invalid');}}
  for(const [word,v]of [['true',true],['false',false],['null',null]])if(bytes.startsWith(word,i)){i+=word.length;return v;}
  const token=bytes.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);insist(token,'electron_json_invalid');i+=token[0].length;
  const n=Number(token[0]);insist(Number.isFinite(n)&&(!Number.isInteger(n)||Number.isSafeInteger(n)),'electron_json_number_invalid');return n;
 }
 const result=value(0);white();insist(i===bytes.length,'electron_json_trailing_data');return result;
}
