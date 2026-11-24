'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');

const file = fs.readFileSync(path.join(__dirname, '..', 'nterp-field-probe.js'), 'utf8');
const begin = file.indexOf('function selectFieldSites(data, selectors) {');
const end = file.indexOf('\nfunction install() {', begin);
assert(begin >= 0 && end > begin, 'Cannot find actual Frida selector');
const context = vm.createContext({});
vm.runInContext('const fieldOps = new Set([0x52, 0x59, 0x60, 0x67]);\n' +
  file.slice(begin, end) + '\nglobalThis.select = selectFieldSites;', context);
const select = context.select;
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
assert.equal(select(catalog).methods.get(10).sites.get(0).fieldName,'a');
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
assert.equal(select({dexFiles:[floatDex]}).methods.get(14).sites.get(0).fieldType,'F');
const selected=select({dexFiles:[repeatedDex]});
assert.equal(selected.count,8);
assert.equal(selected.methods.get(20).sites.size,4);
assert.equal(selected.methods.get(20).sites.get(4).dexPc,4);
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
console.log('Nterp data-driven field selector self-tests passed');
