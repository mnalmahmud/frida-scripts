'use strict';

// Actual stock ART nterp opcode entry instrumentation, not Java method hooks.
// Initial profile: Android 13 API33 x86_64, exact ELF Build ID, 32-bit ints.
// It observes only executing nterp code. JIT/AOT/switch are NOT covered.
//
// x86_64 ART nterp ABI: r12=DEX instruction pointer, r13=4-byte vreg base,
// rsp[0]=ArtMethod*, ArtMethod.dex_method_index at +8 (specific build).
// Field opcode width: two 16-bit code units. A successful instruction reaches
// the following handler at pc+4; failed null/resolution never reaches it.
// The result is sampled at that next opcode, never by re-reading the field.
const profile = globalThis.__artwatchNterpProfile;
const catalog = globalThis.__artwatchNterpCatalog;
const MAX_RECORDS = 512;
const active = new Map();
const records = [];
const diagnostics = [];
const hooks = [];
let dropped = 0;
let callbacks = 0;
let ready = false;
let armed = false;
let attachVerifiedHooks = null;
const fieldOps = new Set([0x52, 0x59, 0x60, 0x67]);
const continuationOps = [0x0e, 0x0f];
// The first continuation after a field access may be a move, nop, or return.
// A larger watcher must subscribe to every opcode or a shared dispatch edge.

function recordDiagnostic(s) {
  if (diagnostics.length < 16) diagnostics.push(String(s));
}
function readLiveBuildId(module) {
  const base = module.base;
  if (base.readU32() !== 0x464c457f || base.add(4).readU8() !== 2 ||
      base.add(5).readU8() !== 1 || base.add(16).readU16() !== 3) {
    throw new Error('Unexpected ELF64 little-endian ET_DYN image');
  }
  const phoff = Number(base.add(32).readU64().toString());
  const entsize = base.add(54).readU16();
  const count = base.add(56).readU16();
  if (phoff > 65536 || entsize < 56 || entsize > 256 || count > 512)
    throw new Error('Invalid loaded ELF program headers');
  for (let i = 0; i < count; i++) {
    const ph = base.add(phoff + i * entsize);
    if (ph.readU32() !== 4) continue;  // PT_NOTE
    const vaddr = Number(ph.add(16).readU64().toString());
    const len = Number(ph.add(32).readU64().toString());
    if (!Number.isSafeInteger(vaddr) || len > 65536) continue;
    const notes = base.add(vaddr);
    for (let p = 0; p + 12 <= len;) {
      const namesz = notes.add(p).readU32();
      const descsz = notes.add(p + 4).readU32();
      const typ = notes.add(p + 8).readU32();
      const desc = p + 12 + ((namesz + 3) & ~3);
      const next = desc + ((descsz + 3) & ~3);
      if (next > len) break;
      if (typ === 3 && namesz >= 4 && descsz >= 16 && descsz <= 20 &&
          notes.add(p + 12).readUtf8String(3) === 'GNU') {
        const bytes = new Uint8Array(notes.add(desc).readByteArray(descsz));
        return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
      }
      p = next;
    }
  }
  throw new Error('Loaded libart GNU Build ID not found');
}
function selectFixtures(data) {
  const picked = new Map();
  if (!data || !Array.isArray(data.fixtureMethods))
    throw new Error('Missing packaged DEX fixture catalog');
  const expected = new Map([
    ['writeInstance', [0x59, 2]],
    ['readInstance', [0x52, 1]],
    ['writeStatic', [0x67, 2]],
    ['readStatic', [0x60, 1]]
  ]);
  for (const m of data.fixtureMethods) {
    const pair = expected.get(m.methodName);
    if (!pair || !m.methodClass.startsWith('Lcom/example/artfieldwatch/') ||
        m.dexId !== 0 || !Array.isArray(m.fields) || m.fields.length !== 1 ||
        !Number.isInteger(m.methodIndex) || !Number.isInteger(m.fields[0].fieldIndex))
      throw new Error('Invalid fixture method in packaged DEX');
    const f = m.fields[0];
    if (f.opcode !== '0x' + pair[0].toString(16) ||
        (pair[1] === 1 ? f.operation !== 'read' : f.operation !== 'write'))
      throw new Error('Fixture opcode mismatch');
    if (picked.has(m.methodIndex)) throw new Error('Duplicate DEX method ID');
    picked.set(m.methodIndex, {
      name: m.methodName, opcode: pair[0], kind: pair[1],
      dexPc: f.dexPc, fieldId: f.fieldIndex,
      fieldName: f.fieldName
    });
  }
  if (picked.size !== 4) throw new Error('Expected four fixture field methods');
  return picked;
}
function install() {
  if (!profile || profile.api !== 33 || profile.architecture !== 'x86_64' ||
      Process.arch !== 'x64' || Process.pointerSize !== 8 ||
      profile.handlerSize !== 128 || profile.opcodeCount !== 256)
    throw new Error('Unsupported nterp interpreter profile');
  const methods = selectFixtures(catalog);
  const art = Process.findModuleByName('libart.so');
  if (!art) throw new Error('ART runtime module not loaded');
  const buildId = readLiveBuildId(art);
  if (buildId !== profile.buildId ||
      buildId !== 'c8b6a2df9893030c07b3b96dc24a7d30')
    throw new Error('Mapped ART build ID does not match verified ELF profile');
  if (!Number.isInteger(profile.startOffset) ||
      !Number.isInteger(profile.endOffset) ||
      profile.endOffset - profile.startOffset !== 128 * 256 ||
      profile.startOffset <= 0 || profile.endOffset > art.size)
    throw new Error('Invalid nterp table offsets');
  const base = art.base.add(profile.startOffset);
  const installed = [...new Set([...fieldOps, ...continuationOps])];
  function callback(opcode, context, tid) {
    if (!armed || (!fieldOps.has(opcode) && !active.has(tid))) return;
    callbacks++;
    const pc = context.r12, fp = context.r13;
    if (pc.isNull() || fp.isNull()) return;
    const method = context.rsp.readPointer();
    if (method.isNull()) return;
    const prev = active.get(tid);
    if (prev) {
      active.delete(tid);
      if (method.equals(prev.method) && fp.equals(prev.fp) &&
          pc.equals(prev.nextPc)) {
        const value = prev.kind === 1
          ? fp.add(prev.vreg * 4).readS32() : prev.value;
        if (records.length === MAX_RECORDS) {
          dropped++;
        } else {
          records.push({seq: records.length + 1, method: prev.name,
            methodIndex: prev.methodIndex, fieldIndex: prev.fieldId,
            dexPc: prev.dexPc, opcode: prev.opcode, kind: prev.kind,
            value, instructionAddress: prev.pc,
            provenance: 'nterp opcode and successor (DEX PC mapped from catalog)'});
        }
      }
    }
    if (!fieldOps.has(opcode)) return;
    const methodIndex = method.add(8).readU32();
    const target = methods.get(methodIndex);
    if (!target || target.opcode !== opcode) return;
    const rawOp = pc.readU8();
    const high = pc.add(1).readU8();
    const fieldIdx = pc.add(2).readU16();
    // At nterp handler entry rbx.low8 is the first DEX word's high byte.
    if (rawOp !== opcode || fieldIdx !== target.fieldId ||
        (context.rbx.toUInt32() & 0xff) !== high) return;
    const vregA = opcode >= 0x60 ? high : (high & 0xf);
    const value = target.kind === 2 ? fp.add(vregA * 4).readS32() : null;
    active.set(tid, {method, fp, name: target.name,
      methodIndex, fieldId: fieldIdx, dexPc: target.dexPc,
      opcode, kind: target.kind, pc: pc.toString(),
      nextPc: pc.add(4), vreg: vregA, value});
  }
  // Do not patch nterp before Android's process initialization finishes.
  // The isolated test activity starts idle; the host explicitly arms before
  // triggering its first field operation.
  attachVerifiedHooks = function () {
    for (const opcode of installed) {
      const address = base.add(opcode * 128);
      const range = Process.findRangeByAddress(address);
      if (!range || !range.protection.includes('x'))
        throw new Error('nterp handler not executable: 0x' + opcode.toString(16));
      hooks.push(Interceptor.attach(address, {
        onEnter() {
          try { callback(opcode, this.context, this.threadId); }
          catch (e) { recordDiagnostic('opcode 0x' + opcode.toString(16) + ': ' + e); }
        }
      }));
    }
  };
  ready = true;
  send({type: 'artwatch-nterp-init', ready: true,
    buildId, candidateHandlers: installed.length, attachedHandlers: 0,
    moduleBase: art.base.toString(), handlerTable: base.toString()});
}
rpc.exports = {
  arm() {
    if (!ready || armed || attachVerifiedHooks === null) return false;
    try {
      attachVerifiedHooks();
      armed = true;
      send({type:'artwatch-nterp-armed',handlerCount:hooks.length});
      return true;
    } catch (e) {
      hooks.forEach(h => h.detach());
      hooks.length = 0;
      recordDiagnostic('Failed to arm nterp: ' + e);
      return false;
    }
  },
  snapshot() {
    return {ready, armed, callbacks, events: records.slice(), dropped,
      errors: diagnostics.slice(), pending: active.size};
  }
};
try { install(); }
catch (e) {
  hooks.forEach(h => h.detach());
  recordDiagnostic(e.stack || e);
  send({type: 'artwatch-nterp-init', ready: false, error: String(e)});
}
