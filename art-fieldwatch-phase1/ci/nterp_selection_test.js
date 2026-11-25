'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');

const file = fs.readFileSync(path.join(__dirname, '..', 'nterp-field-probe.js'), 'utf8');
const softFile = fs.readFileSync(
  path.join(__dirname,'..','nterp-software-probe.js'),'utf8');
const begin = file.indexOf('function selectFieldSites(data, selectors) {');
const end = file.indexOf('\nfunction install() {', begin);
assert(begin >= 0 && end > begin, 'Cannot find actual Frida selector');
function selectForGroup(group) {
  const ctx = vm.createContext({});
  const opcodeGroups = {
    scalar32: [0x52,0x59,0x60,0x67],
    wide64: [0x53,0x5a,0x61,0x68],
    boolean8: [0x55,0x5c,0x63,0x6a],
    byte8: [0x56,0x5d,0x64,0x6b],
    char16: [0x57,0x5e,0x65,0x6c],
    short16: [0x58,0x5f,0x66,0x6d],
    allPrimitives: [0x52,0x53,0x55,0x56,0x57,0x58,0x59,0x5a,
      0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x63,0x64,0x65,
      0x66,0x67,0x68,0x6a,0x6b,0x6c,0x6d]
  };
  const ops = opcodeGroups[group];
  const source = group === 'allPrimitives' ? softFile : file;
  const selectorBegin=source.indexOf('function selectFieldSites(data, selectors) {');
  const selectorEnd=source.indexOf('\nfunction install() {',selectorBegin);
  assert(selectorBegin >= 0 && selectorEnd > selectorBegin);
  vm.runInContext(
    'const opcodeGroup=' + JSON.stringify(group) + ';\n' +
    'const fieldOps=new Set(' + JSON.stringify(ops) + ');\n' +
    'const readOps=new Set([0x52,0x53,0x55,0x56,0x57,0x58,' +
      '0x60,0x61,0x63,0x64,0x65,0x66]);\n' +
    source.slice(selectorBegin, selectorEnd) + '\nglobalThis.select=selectFieldSites;', ctx);
  return ctx.select;
}
const select = selectForGroup('scalar32');
const selectWide = selectForGroup('wide64');
const selectAll = selectForGroup('allPrimitives');
const cls = 'Lexample/Sample;';
const mk = (methodName, methodIndex, fieldName, fieldIndex, dexPc, opcode, operation, access) => ({
  methodClass: cls, methodName, methodIndex, fieldName, fieldIndex, dexPc,
  declaringClass:cls, fieldType:'I',valueKind:'int',opcode,
  operation,access,sourceFile:'Sample.java',sourceLine:12
});
const fields = [
  mk('writeA', 10, 'a', 1, 0, '0x59', 'write', 'instance'),
  mk('readA', 11, 'a', 1, 0, '0x52', 'read', 'instance'),
  mk('writeB', 12, 'b', 2, 0, '0x67', 'write', 'static'),
  mk('readB', 13, 'b', 2, 0, '0x60', 'read', 'static')
];
const codeFor = f => f.opcode.slice(2).toLowerCase() + '00' +
  f.fieldIndex.toString(16).padStart(2,'0') + '00';
const fieldMethods = fields.map(f => ({methodIndex:f.methodIndex,
  methodClass:f.methodClass,methodName:f.methodName,
  insnsSize:2,insnsHex:codeFor(f)}));
const dex = {dexId:0,sha256:'a'.repeat(64),fieldAccesses:fields,fieldMethods};
const catalog = {dexFiles:[dex]};
assert.equal(select(catalog).count, 4);
assert.equal(select(catalog, [
  {methodClass:cls,methodName:'writeA',fieldName:'a'}
]).count, 1);
assert.equal(select(catalog,[
  {methodClass:cls,methodName:'writeA',fieldName:'a'},
  {methodClass:cls,methodName:'readA',fieldName:'a'}
]).count, 2);
assert.equal(select(catalog).methods.get(10)[0].sites.get(0).fieldName,'a');
// Identical opcode/field ID twice inside one method is not ambiguous when the
// live instruction pointer is bound to the verified method instruction bytes.
const repeated = [
  mk('repeat',20,'a',1,0,'0x59','write','instance'),
  mk('repeat',20,'a',1,2,'0x52','read','instance'),
  mk('repeat',20,'a',1,4,'0x59','write','instance'),
  mk('repeat',20,'a',1,6,'0x52','read','instance')
];
const repeatedDex={...dex,
  fieldAccesses:[...fields,...repeated],
  fieldMethods:[...fieldMethods, {
    methodIndex:20,methodClass:cls,methodName:'repeat',insnsSize:8,
    insnsHex:repeated.map(codeFor).join('')
  }]};
const floatField={...fields[0],methodName:'writeFloat',methodIndex:14,
  fieldName:'floating',fieldType:'F',fieldIndex:3};
const floatDex={...dex,fieldAccesses:[...fields,floatField],
  fieldMethods:[...fieldMethods,{
    methodIndex:14,methodClass:cls,methodName:'writeFloat',
    insnsSize:2,insnsHex:codeFor(floatField)
  }]};
assert.equal(select({dexFiles:[floatDex]}).count,5);
assert.equal(select({dexFiles:[floatDex]}).methods.get(14)[0].sites.get(0).fieldType,'F');
const wideFields = [
  {...fields[0],methodName:'writeLong',methodIndex:21,fieldName:'long',
    fieldType:'J',valueKind:'wide',opcode:'0x5a'},
  {...fields[1],methodName:'readLong',methodIndex:22,fieldName:'long',
    fieldType:'J',valueKind:'wide',opcode:'0x53'},
  {...fields[2],methodName:'writeDouble',methodIndex:23,fieldName:'double',
    fieldType:'D',valueKind:'wide',opcode:'0x68'},
  {...fields[3],methodName:'readDouble',methodIndex:24,fieldName:'double',
    fieldType:'D',valueKind:'wide',opcode:'0x61'}
];
const wideDex={...dex,fieldAccesses:wideFields,
  fieldMethods:wideFields.map(f=>({
    methodIndex:f.methodIndex,methodClass:f.methodClass,methodName:f.methodName,
    insnsSize:2,insnsHex:codeFor(f)
  }))};
assert.equal(selectWide({dexFiles:[wideDex]}).count,4);
assert.equal(selectAll({dexFiles:[wideDex]}).count,4);
assert.equal(selectAll({dexFiles:[floatDex]}).count,5);
assert.equal(selectWide({dexFiles:[wideDex]}).methods.get(23)[0].sites.get(0).fieldType,'D');

const narrowFamilies = {
  boolean8: ['Z','boolean',0x55,0x5c,0x63,0x6a],
  byte8: ['B','byte',0x56,0x5d,0x64,0x6b],
  char16: ['C','char',0x57,0x5e,0x65,0x6c],
  short16: ['S','short',0x58,0x5f,0x66,0x6d]
};
for (const [group,[descriptor,valueKind,iget,iput,sget,sput]] of
     Object.entries(narrowFamilies)) {
  const selectNarrow=selectForGroup(group);
  const opcodes=[iput,sput,iget,sget];
  const narrow=fields.map((f,i)=>({
    ...f,methodIndex:30+i,methodName:group+'Site'+i,
    fieldType:descriptor,valueKind,
    operation:i<2?'write':'read',
    access:i%2===0?'instance':'static',
    opcode:'0x'+opcodes[i].toString(16)
  }));
  const narrowDex={...dex,fieldAccesses:narrow,
    fieldMethods:narrow.map(f=>({
      methodIndex:f.methodIndex,methodClass:f.methodClass,
      methodName:f.methodName,insnsSize:2,insnsHex:codeFor(f)
    }))};
  assert.equal(selectNarrow({dexFiles:[narrowDex]}).count,4);
  assert.equal(selectAll({dexFiles:[narrowDex]}).count,4);
  for (let i=0;i<4;i++) {
    const site=selectNarrow({dexFiles:[narrowDex]}).methods
      .get(30+i)[0].sites.get(0);
    assert.equal(site.kind,i<2?2:1);
    assert.equal(site.fieldType,descriptor);
  }
  const wrongDescriptor={...narrowDex,
    fieldAccesses:[{...narrow[0],fieldType:'I'},...narrow.slice(1)]};
  assert.equal(selectNarrow({dexFiles:[wrongDescriptor]}).count,3);
  assert.throws(()=>select({dexFiles:[narrowDex]}));
}
const second = {...dex,dexId:1,sha256:'b'.repeat(64),
  fieldAccesses:[{...fields[0],methodName:'otherMethod',
    methodIndex:10,fieldName:'c',fieldIndex:7}],
  fieldMethods:[{methodIndex:10,methodClass:cls,methodName:'otherMethod',
    insnsSize:2,insnsHex:codeFor({...fields[0],fieldIndex:7})}]};
const crossDex = select({dexFiles:[dex,second]});
assert.equal(crossDex.count,5);
assert.equal(crossDex.methods.get(10).length,2);
assert.equal(crossDex.methods.get(10)[0].dexId,0);
assert.equal(crossDex.methods.get(10)[1].dexId,1);
assert.equal(crossDex.methods.get(10)[1].sites.get(0).fieldName,'c');
assert.throws(()=>select({dexFiles:[second,dex]})); // Order/IDs must match.
assert.throws(()=>select({dexFiles:[dex,{...second,sha256:'bad'}]}));

assert.throws(()=>select({dexFiles:[wideDex]}));
assert.throws(()=>selectWide({dexFiles:[floatDex]}));
const invalidWide = {...wideDex,
  fieldAccesses:[{...wideFields[0],fieldType:'F'},...wideFields.slice(1)]};
assert.equal(selectWide({dexFiles:[invalidWide]}).count,3);
const selected=select({dexFiles:[repeatedDex]});
assert.equal(selected.count,8);
assert.equal(selected.methods.get(20)[0].sites.size,4);
assert.equal(selected.methods.get(20)[0].sites.get(4).dexPc,4);
for (const invalid of [
  {dexFiles:[dex,dex]},
  {dexFiles:[{...dex,sha256:'invalid'}]},
  {dexFiles:[{...dex,fieldAccesses:[...fields,{...fields[0],dexPc:16}]}]},
  {dexFiles:[{...dex,fieldMethods:fieldMethods.slice(1)}]},
  {dexFiles:[{...dex,fieldMethods:[{...fieldMethods[0],insnsHex:'00000000'},...fieldMethods.slice(1)]}]},
  {dexFiles:[{...dex,fieldAccesses:[...fields,{...fields[0],methodIndex:11}]}]},
  {dexFiles:[{...dex,fieldAccesses:[{...fields[0],operation:'read'}]}]}
]) assert.throws(()=>select(invalid));
assert.throws(()=>select(catalog,[]));
assert.throws(()=>select(catalog,[{methodClass:cls,methodName:'notFound',fieldName:'a'}]));
assert.throws(()=>select(catalog,[{methodClass:cls,methodName:'writeA'}]));
// Execute the complete agent with a deliberately missing ART profile. The
// initialization must fail closed, but RPC methods must remain usable. This
// catches lexical-scope mistakes in snapshot()/stop() before emulator CI.
const smoke = vm.createContext({
  rpc: {exports:{}},
  send() {}
});
vm.runInContext(file, smoke);
const initial = smoke.rpc.exports.snapshot();
assert.equal(initial.ready, false);
assert.equal(initial.verifiedRuntimeMethods, 0);
assert.equal(initial.unverifiedSites, 0);
assert.equal(initial.events.length, 0);
assert.deepEqual(JSON.parse(JSON.stringify(smoke.rpc.exports.stop())),
  {removed:0,failures:0,recorded:0});
const softContext=vm.createContext({rpc:{exports:{}},send() {}});
vm.runInContext(softFile,softContext);
const softSnapshot=softContext.rpc.exports.snapshot();
assert.equal(softSnapshot.ready,false);
assert.equal(softSnapshot.mode,'stalker-callout');
assert.equal(softSnapshot.attachedHooks,0);
assert.equal(softSnapshot.unverifiedSites,0);
assert.equal(softSnapshot.events.length,0);
assert.deepEqual(JSON.parse(JSON.stringify(softContext.rpc.exports.stop())),
  {removed:0,failures:0,recorded:0});
console.log('Nterp hardware and software field selector self-tests passed');
