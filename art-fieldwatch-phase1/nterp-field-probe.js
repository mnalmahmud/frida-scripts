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
const observedThreads = new Map();
let threadObserver = null;
let hardwareHits = 0;
let fieldHits = 0;
let completedHits = 0;
let firstTrapDiagnostics = 0;
let dropped = 0;
let callbacks = 0;
let ready = false;
let armed = false;
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
    throw new Error('Unsupported ART / nterp ABI');
  const methods = selectFixtures(catalog);
  const art = Process.findModuleByName('libart.so');
  if (!art) throw new Error('libart.so is not mapped');
  const buildId = readLiveBuildId(art);
  if (buildId !== profile.buildId ||
      buildId !== 'c8b6a2df9893030c07b3b96dc24a7d30')
    throw new Error('Unrecognized live ART Build ID');
  if (!Number.isInteger(profile.startOffset) ||
      !Number.isInteger(profile.endOffset) ||
      profile.endOffset - profile.startOffset !== 32768 ||
      profile.startOffset <= 0 || profile.endOffset > art.size)
    throw new Error('Invalid nterp opcode table');
  const base = art.base.add(profile.startOffset);
  const ops = [0x52, 0x59, 0x60, 0x67]; // iget, iput, sget, sput
  const bpIds = new Map(ops.map((opcode, index) => [opcode, index]));
  for (const opcode of ops) {
    const site = base.add(opcode * 128);
    const range = Process.findRangeByAddress(site);
    if (!range || !range.protection.includes('x'))
      throw new Error('nterp opcode address not executable: ' + opcode);
  }

  function installForThread(t) {
    if (!armed || t.name !== 'NterpFieldProbe' ||
        observedThreads.has(t.id)) return;
    const state = {thread:t, slots:new Map(), pending:null};
    try {
      for (const op of ops) {
        const id=bpIds.get(op), at=base.add(op*128);
        t.setHardwareBreakpoint(id, at);
        state.slots.set(id, at);
      }
      observedThreads.set(t.id,state);
      send({type:'artwatch-nterp-hardware-thread',tid:t.id,
        installed:state.slots.size});
    } catch(e) {
      for (const id of state.slots.keys())
        try {t.unsetHardwareBreakpoint(id);} catch(_){}
      recordDiagnostic('Hardware breakpoints unavailable: '+e);
    }
  }

  function switchBreakpoint(state,id,to) {
    const old=state.slots.get(id);
    if (!old || old.equals(to))
      throw new Error('Cannot advance debug breakpoint id='+id);
    state.thread.unsetHardwareBreakpoint(id);
    state.slots.delete(id);
    state.thread.setHardwareBreakpoint(id,to);
    state.slots.set(id,to);
  }

  function beginField(context,state,opcode) {
    const pc=context.r12, fp=context.r13;
    const method=context.rsp.readPointer();
    if (pc.isNull() || fp.isNull() || method.isNull() || pc.readU8()!==opcode)
      throw new Error('Invalid nterp interpreter state');
    // All DEX field opcodes are 2 code units long.
    const nextPc=pc.add(4), successorOpcode=nextPc.readU8();
    const destination=base.add(successorOpcode*128);
    const id=bpIds.get(opcode);
    const methodIndex=method.add(8).readU32();
    const target=methods.get(methodIndex);
    const high=pc.add(1).readU8(), fieldId=pc.add(2).readU16();
    let sampled=null;
    if (target && target.opcode===opcode && target.fieldId===fieldId &&
        (context.rbx.toUInt32()&255)===high &&
        successorOpcode===(target.kind===1 ? 0x0f : 0x0e)) {
      const vreg=opcode>=0x60 ? high : high&15;
      sampled={name:target.name,kind:target.kind,opcode,
        fieldId,methodIndex,dexPc:target.dexPc,
        vreg,preValue:target.kind===2 ? fp.add(vreg*4).readS32() : null,
        pc:pc.toString()};
      fieldHits++;
    }
    // Hardware breakpoint is raised BEFORE opcode execution. Redirect the
    // same slot to the successor opcode; that trap occurs after the field
    // operation on the normal (nonthrowing) path. We never patch ART code.
    switchBreakpoint(state,id,destination);
    state.pending={id,original:base.add(opcode*128),destination,
      nextPc,method,fp,sampled};
  }

  function completeField(context,state) {
    const p=state.pending;
    state.pending=null;
    switchBreakpoint(state,p.id,p.original);
    if (!context.r12.equals(p.nextPc) || !context.r13.equals(p.fp) ||
        !context.rsp.readPointer().equals(p.method)) return;
    completedHits++;
    if (!p.sampled) return;
    const f=p.sampled;
    const value=f.kind===1
      ? context.r13.add(f.vreg*4).readS32() : f.preValue;
    if (records.length>=MAX_RECORDS) {dropped++;return;}
    if (records.length < 8) send({type:'artwatch-nterp-record-sample',
      number:records.length+1, method:f.name, value});
    records.push({seq:records.length+1,method:f.name,
      methodIndex:f.methodIndex,fieldIndex:f.fieldId,dexPc:f.dexPc,
      opcode:f.opcode,kind:f.kind,value,instructionAddress:f.pc,
      provenance:'nterp hardware breakpoint and succeeding opcode'});
  }

  function handleException(details) {
    const tid=Process.getCurrentThreadId();
    const state=observedThreads.get(tid);
    if (firstTrapDiagnostics++ < 24) {
      send({type:'artwatch-nterp-trap-diagnostic',
        exceptionType: details.type, tid, tracked:!!state,
        pc:details.context.pc.toString(),
        address:details.address ? details.address.toString() : null,
        hardwareSlots:state ? Array.from(state.slots.entries()).map(
          ([slot,at]) => ({slot,address:at.toString()})) : []});
    }
    if (!armed || !['breakpoint','single-step'].includes(details.type))
      return false;
    if (!state) return false;
    const hit=details.context.pc;
    let id=null;
    for (const [slot,address] of state.slots) {
      if (hit.equals(address) ||
          (details.address && details.address.equals(address))) {
        id=slot;break;
      }
    }
    if (id===null) {
      send({type:'artwatch-nterp-unhandled-trap',tid,
        exceptionType:details.type,pc:hit.toString(),
        reason:'No matching hardware breakpoint slot'});
      return false;
    } // Not our hardware debug trap.
    hardwareHits++;callbacks++;
    try {
      if (state.pending) {
        if (state.pending.id!==id ||
            !state.pending.destination.equals(state.slots.get(id)))
          throw new Error('Unexpected overlapping nterp exception');
        completeField(details.context,state);
      } else {
        if (!state.slots.get(id).equals(base.add(ops[id]*128)))
          throw new Error('Hardware breakpoint slot identity changed');
        beginField(details.context,state,ops[id]);
      }
      return true;
    } catch(e) {
      const message='Hardware debug trap error tid='+tid+': '+(e.stack||e);
      recordDiagnostic(message);
      send({type:'artwatch-nterp-exception-error',tid,error:message,
        slot:id,pending:!!state.pending,
        pc:hit.toString(),recorded:records.length});
      return false;
    }
  }

  function armThreads() {
    // Only the synthetic Java worker is instrumented in this first proof.
    // Process.attachThreadObserver sees existing threads and future renames.
    Process.setExceptionHandler(handleException);
    armed=true;
    threadObserver=Process.attachThreadObserver({
      onAdded(t){installForThread(t);},
      onRenamed(t){installForThread(t);},
      onRemoved(t){observedThreads.delete(t.id);}
    });
    return true;
  }

  ready=true;
  send({type:'artwatch-nterp-init',ready:true,mode:'hardware-breakpoint',
    buildId,candidateHandlers:ops.length,attachedHandlers:0,
    moduleBase:art.base.toString(),handlerTable:base.toString()});
  return armThreads;
}
let armBackend=null;
rpc.exports={
  arm(){
    if (!ready || armed || !armBackend) return false;
    try{return armBackend();}
    catch(e){
      recordDiagnostic('Failed to enable nterp hardware breakpoints: '+e);
      armed=false;
      if(threadObserver){threadObserver.detach();threadObserver=null;}
      return false;
    }
  },
  snapshot(){
    return {ready,armed,callbacks,hardwareHits,fieldHits,completedHits,
      watchedThreads:Array.from(observedThreads.keys()),events:records.slice(),
      dropped,errors:diagnostics.slice(),
      pending:Array.from(observedThreads.values()).filter(t=>t.pending).length};
  }
};
try{armBackend=install();}
catch(e){
  recordDiagnostic(e.stack||e);
  send({type:'artwatch-nterp-init',ready:false,error:String(e)});
}
