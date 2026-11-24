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
  mk('writeB', 12, 'b', 2, 4, '0x67', 'write', 'static'),
  mk('readB', 13, 'b', 2, 6, '0x60', 'read', 'static')
];
const dex = {dexId:0,sha256:'a'.repeat(64),fieldAccesses:fields};
const catalog = {dexFiles:[dex]};
assert.equal(select(catalog).count, 4);
assert.equal(select(catalog, [
  {methodClass:cls,methodName:'writeA',fieldName:'a'}
]).count, 1);
assert.equal(select(catalog,[
  {methodClass:cls,methodName:'writeA',fieldName:'a'},
  {methodClass:cls,methodName:'readA',fieldName:'a'}
]).count, 2);
assert.equal(select(catalog).methods.get(10).sites.get('89:1').fieldName,'a');
for (const invalid of [
  {dexFiles:[dex,dex]},
  {dexFiles:[{...dex,sha256:'invalid'}]},
  {dexFiles:[{...dex,fieldAccesses:[...fields,{...fields[0],dexPc:16}]}]},
  {dexFiles:[{...dex,fieldAccesses:[...fields,{...fields[0],methodIndex:11}]}]},
  {dexFiles:[{...dex,fieldAccesses:[{...fields[0],operation:'read'}]}]}
]) assert.throws(()=>select(invalid));
assert.throws(()=>select(catalog,[]));
assert.throws(()=>select(catalog,[{methodClass:cls,methodName:'notFound',fieldName:'a'}]));
assert.throws(()=>select(catalog,[{methodClass:cls,methodName:'writeA'}]));
console.log('Nterp data-driven field selector self-tests passed');
