// Explicit Mac hardware position -> CDP code/fallback VK table. This does not
// read or change the user's layout. Characters/key identity are supplied explicitly.
const rows = [
 [0,'KeyA',65],[1,'KeyS',83],[2,'KeyD',68],[3,'KeyF',70],[4,'KeyH',72],[5,'KeyG',71],
 [6,'KeyZ',90],[7,'KeyX',88],[8,'KeyC',67],[9,'KeyV',86],[11,'KeyB',66],[12,'KeyQ',81],
 [13,'KeyW',87],[14,'KeyE',69],[15,'KeyR',82],[16,'KeyY',89],[17,'KeyT',84],
 [18,'Digit1',49],[19,'Digit2',50],[20,'Digit3',51],[21,'Digit4',52],[22,'Digit6',54],[23,'Digit5',53],
 [24,'Equal',187],[25,'Digit9',57],[26,'Digit7',55],[27,'Minus',189],[28,'Digit8',56],[29,'Digit0',48],
 [30,'BracketRight',221],[31,'KeyO',79],[32,'KeyU',85],[33,'BracketLeft',219],[34,'KeyI',73],[35,'KeyP',80],
 [37,'KeyL',76],[38,'KeyJ',74],[39,'Quote',222],[40,'KeyK',75],[41,'Semicolon',186],[42,'Backslash',220],
 [43,'Comma',188],[44,'Slash',191],[45,'KeyN',78],[46,'KeyM',77],[47,'Period',190],[49,'Space',32],
 [50,'Backquote',192],[65,'NumpadDecimal',110],[67,'NumpadMultiply',106],[69,'NumpadAdd',107],
 [75,'NumpadDivide',111],[78,'NumpadSubtract',109],[81,'NumpadEqual',187],
 [82,'Numpad0',96],[83,'Numpad1',97],[84,'Numpad2',98],[85,'Numpad3',99],
 [86,'Numpad4',100],[87,'Numpad5',101],[88,'Numpad6',102],[89,'Numpad7',103],[91,'Numpad8',104],[92,'Numpad9',105],
 [36,'Enter',13,'Enter','\r'],[48,'Tab',9,'Tab','\t'],[51,'Backspace',8,'Backspace','\u0008'],
 [53,'Escape',27,'Escape','\u001b'],[76,'NumpadEnter',13,'Enter','\r'],
 [115,'Home',36,'Home','\uf729'],[116,'PageUp',33,'PageUp','\uf72c'],[117,'Delete',46,'Delete','\uf728'],
 [119,'End',35,'End','\uf72b'],[121,'PageDown',34,'PageDown','\uf72d'],
 [123,'ArrowLeft',37,'ArrowLeft','\uf702'],[124,'ArrowRight',39,'ArrowRight','\uf703'],
 [125,'ArrowDown',40,'ArrowDown','\uf701'],[126,'ArrowUp',38,'ArrowUp','\uf700'],
 [122,'F1',112,'F1','\uf704'],[120,'F2',113,'F2','\uf705'],[99,'F3',114,'F3','\uf706'],
 [118,'F4',115,'F4','\uf707'],[96,'F5',116,'F5','\uf708'],[97,'F6',117,'F6','\uf709'],
 [98,'F7',118,'F7','\uf70a'],[100,'F8',119,'F8','\uf70b'],[101,'F9',120,'F9','\uf70c'],
 [109,'F10',121,'F10','\uf70d'],[103,'F11',122,'F11','\uf70e'],[111,'F12',123,'F12','\uf70f'],
];
const TABLE = new Map(rows.map(([native,code,vk,key,character])=>[native,{native,code,vk,key,character}]));
const fail=code=>{throw Error(code);};
const PUNCTUATION_VK=new Map([
 [';:',186],['=+',187],[',<',188],['-_',189],['.>',190],['/?',191],
 ['`~',192],['[{',219],['\\|',220],[']}',221],['\'"',222],
].flatMap(([characters,vk])=>[...characters].map(character=>[character,vk])));
function characterVirtualKey(value) {
 const first=value.charCodeAt(0);
 if(first>=97&&first<=122)return first-32;
 if((first>=65&&first<=90)||(first>=48&&first<=57))return first;
 return PUNCTUATION_VK.get(value[0]);
}
function logicalVirtualKey(row,args) {
 // Chromium's Mac KeyboardCodeFromNSEvent uses effective characters first,
 // then charactersIgnoringModifiers, except for numeric/keypad positions.
 // Keep physical code/native VK distinct from the legacy logical keyCode.
 // Source: chromium@0d4dcd4ffc1d23d05eea824a8462be66288d2528,
 // ui/events/keycodes/keyboard_code_conversion_mac.mm.
 if(row.key||row.code.startsWith('Digit')||row.code.startsWith('Numpad'))return row.vk;
 return characterVirtualKey(args.characters)??characterVirtualKey(args.characters_ignoring_modifiers)??row.vk;
}
export function wellFormed(value,utf16,utf8) {
 if(typeof value!=='string'||value.length>utf16||Buffer.byteLength(value,'utf8')>utf8)return false;
 for(let i=0;i<value.length;i++){const c=value.charCodeAt(i);if(c>=0xd800&&c<=0xdbff){const d=value.charCodeAt(++i);if(!(d>=0xdc00&&d<=0xdfff))return false;}
  else if(c>=0xdc00&&c<=0xdfff)return false;}
 return true;
}
export function keyEvents(method,args) {
 const keys=Object.keys(args).sort().join(',');
 const expected=method==='key_chord'?'characters,characters_ignoring_modifiers,key_code,modifiers':'characters,characters_ignoring_modifiers,key_code';
 if(keys!==expected||!Number.isInteger(args.key_code)||!TABLE.has(args.key_code))fail('electron_key_not_reviewed');
 if(![args.characters,args.characters_ignoring_modifiers].every(v=>wellFormed(v,8,32)&&v.length&&!v.includes('\0')))fail('electron_key_characters_invalid');
 const row=TABLE.get(args.key_code);let modifiers=0,names=[];
 if(method==='key_chord'){
  names=args.modifiers;if(!Array.isArray(names)||!names.length||names.length>4||new Set(names).size!==names.length)fail('electron_modifiers_invalid');
  const bits={command:4,control:2,option:1,shift:8};for(const n of names){if(!Object.hasOwn(bits,n))fail('electron_modifiers_invalid');modifiers|=bits[n];}
 }
 const aliases=[row.key,row.character,...(row.key==='Enter'?['\n']:[]),
  ...(row.key==='Backspace'?['\u007f']:[]),...(row.native===76?['\u0003']:[])];
 if(row.key&&![args.characters,args.characters_ignoring_modifiers].every(value=>aliases.includes(value)))fail('electron_special_key_mismatch');
 if(!row.key&&/[\u0000-\u001f\u007f\uf700-\uf8ff]/u.test(args.characters+args.characters_ignoring_modifiers))fail('electron_printable_key_mismatch');
 const common={key:row.key||args.characters,code:row.code,nativeVirtualKeyCode:row.native,windowsVirtualKeyCode:logicalVirtualKey(row,args),
  ...(row.code.startsWith('Numpad')?{isKeypad:true}:{})};
 const down={...common,type:'keyDown',modifiers};
 // Meta/control/option are shortcut flags. They do not implicitly insert text
 // or synthesize IME/dead-key composition. Shift-only printable chords carry
 // the caller's explicit character; up always clears synthetic flags.
 if(!row.key&&(modifiers&7)===0){
  // CDP SetKeyboardEventText requires fewer than WebKeyboardEvent's four
  // UTF-16 units. Refuse before original DOWN admission; never trim, split or
  // silently switch a key operation to literal/IME input.
  if(args.characters.length>=4||args.characters_ignoring_modifiers.length>=4)fail('electron_key_text_too_long_use_insert_text');
  down.text=args.characters;down.unmodifiedText=args.characters_ignoring_modifiers;
 }
 return {down,up:{...common,type:'keyUp',modifiers:0},modifiers:names};
}
export function actionArguments(method,payload) {
 if(method==='consume_plain_text'){
  if(Object.keys(payload).join(',')!=='text'||!wellFormed(payload.text,4096,16384)||payload.text.includes('\0'))fail('electron_text_invalid');
  return {text:payload.text};
 }
 if(!['key_pair','key_chord'].includes(method))fail('electron_method_unavailable');
 return keyEvents(method,payload);
}
