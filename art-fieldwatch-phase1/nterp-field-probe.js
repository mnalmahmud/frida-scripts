'use strict';

// Actual stock ART nterp opcode entry instrumentation, not Java method hooks.
// Pinned profile: Android 13 API33 x86_64, exact ELF Build ID, 32-bit and 64-bit fields.
// It observes only executing nterp code. JIT/AOT/switch are NOT covered.
//
// x86_64 ART nterp ABI: r12=DEX instruction pointer, r13=4-byte vreg base,
// rsp[0]=ArtMethod*, ArtMethod.dex_method_index at +8 (specific build).
// Field opcode width: two 16-bit code units. A successful instruction reaches
// the following handler at pc+4; failed null/resolution never reaches it.
// The result is sampled at that next opcode, never by re-reading the field.
const profile = globalThis.__artwatchNterpProfile;
const catalog = globalThis.__artwatchNterpCatalog;
const selectors = globalThis.__artwatchNterpSelectors;
const threadFilter = globalThis.__artwatchNterpThreadFilter;
const opcodeGroup = globalThis.__artwatchNterpOpcodeGroup ?? 'scalar32';
// x86_64 has four hardware execution slots. Subscribe to ONE opcode family
// per run, without pretending a partial family provides app-wide coverage.
const opcodeGroups = Object.freeze({
  scalar32: Object.freeze([0x52, 0x59, 0x60, 0x67]),
  wide64: Object.freeze([0x53, 0x5a, 0x61, 0x68]),
  boolean8: Object.freeze([0x55, 0x5c, 0x63, 0x6a]),
  byte8: Object.freeze([0x56, 0x5d, 0x64, 0x6b]),
  char16: Object.freeze([0x57, 0x5e, 0x65, 0x6c]),
  short16: Object.freeze([0x58, 0x5f, 0x66, 0x6d])
});
const opcodes = opcodeGroups[opcodeGroup];
const MAX_RECORDS = 4096;
const active = new Map();
const records = [];
const diagnostics = [];
const observedThreads = new Map();
let threadObserver = null;
let hardwareHits = 0;
let fieldHits = 0;
let completedHits = 0;
let unverifiedSites = 0;
// Read by the exported snapshot method; do not declare this inside install().
const liveBases = new Map();
let abandonedFieldAttempts = 0;
let firstTrapDiagnostics = 0;
let dropped = 0;
let callbacks = 0;
let ready = false;
let armed = false;
const fieldOps = new Set(opcodes || []);
const readOps = new Set([0x52, 0x53, 0x55, 0x56, 0x57, 0x58,
  0x60, 0x61, 0x63, 0x64, 0x65, 0x66]);
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
function selectFieldSites(data, selectors) {
  if (!data || !Array.isArray(data.dexFiles) || data.dexFiles.length === 0)
    throw new Error('Missing packaged DEX catalog');
  const wanted = selectors == null ? null : selectors;
  if (wanted !== null &&
      (!Array.isArray(wanted) || wanted.length === 0 ||
       wanted.some(s => !s || typeof s.methodClass !== 'string' ||
         typeof s.methodName !== 'string' ||
         typeof s.fieldName !== 'string')))
    throw new Error('Expected methodClass/methodName/fieldName selectors');
  const identities = wanted === null ? null :
    new Set(wanted.map(s => [s.methodClass,s.methodName,s.fieldName].join('\0')));
  const matched = new Set();
  // A method index is only unique INSIDE its DexFile. Each index maps to
  // candidate methods in different DEXs. Runtime byte validation must select
  // exactly one candidate, otherwise no event is published.
  const methods = new Map();
  let count = 0;
  for (let dexIndex = 0; dexIndex < data.dexFiles.length; dexIndex++) {
    const dex = data.dexFiles[dexIndex];
    if (!dex || dex.dexId !== dexIndex || typeof dex.sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/i.test(dex.sha256) ||
        !Array.isArray(dex.fieldMethods) ||
        !Array.isArray(dex.fieldAccesses))
      throw new Error('Invalid ordered DEX catalog identity');
    const sources = new Map();
    for (const m of dex.fieldMethods) {
      if (!Number.isInteger(m.methodIndex) || m.methodIndex < 0 ||
          typeof m.methodClass !== 'string' || typeof m.methodName !== 'string' ||
          !Number.isInteger(m.insnsSize) || m.insnsSize < 1 ||
          m.insnsSize > 65536 || typeof m.insnsHex !== 'string' ||
          m.insnsHex.length !== m.insnsSize * 4 ||
          !/^[0-9a-f]+$/i.test(m.insnsHex) || sources.has(m.methodIndex))
        throw new Error('Invalid per-DEX method instruction stream');
      sources.set(m.methodIndex, m);
    }
    for (const field of dex.fieldAccesses) {
      const opcode = Number.parseInt(field.opcode,16);
      const expected = {
        scalar32: [['int'], ['I','F']],
        wide64: [['wide'], ['J','D']],
        boolean8: [['boolean'], ['Z']],
        byte8: [['byte'], ['B']],
        char16: [['char'], ['C']],
        short16: [['short'], ['S']]
      }[opcodeGroup];
      if (!fieldOps.has(opcode) || !expected ||
          !expected[0].includes(field.valueKind) ||
          !expected[1].includes(field.fieldType))
        continue;
      const identity=[field.methodClass,field.methodName,field.fieldName].join('\0');
      if (identities !== null && !identities.has(identity)) continue;
      if (!Number.isInteger(field.methodIndex) || field.methodIndex < 0 ||
          !Number.isInteger(field.fieldIndex) || field.fieldIndex < 0 ||
          !Number.isInteger(field.dexPc) || field.dexPc < 0 ||
          typeof field.methodClass !== 'string' ||
          typeof field.methodName !== 'string' ||
          typeof field.declaringClass !== 'string' ||
          typeof field.fieldName !== 'string')
        throw new Error('Invalid DEX field site');
      const kind = readOps.has(opcode) ? 1 : 2;
      if (field.operation !== (kind === 1 ? 'read' : 'write') ||
          field.access !== (opcode < 0x60 ? 'instance' : 'static'))
        throw new Error('Field opcode metadata disagrees with DEX semantics');
      const src=sources.get(field.methodIndex);
      if (!src || src.methodClass !== field.methodClass ||
          src.methodName !== field.methodName)
        throw new Error('Missing method instruction stream for field');
      let group=methods.get(field.methodIndex);
      if (!group) { group=[];methods.set(field.methodIndex,group); }
      let method=group.find(m=>m.dexId===dex.dexId);
      if (!method) {
        const codeBytes=new Uint8Array(src.insnsSize*2);
        for (let i=0;i<codeBytes.length;i++)
          codeBytes[i]=Number.parseInt(src.insnsHex.slice(2*i,2*i+2),16);
        method={methodIndex:field.methodIndex,dexId:dex.dexId,
          dexSha256:dex.sha256,methodClass:field.methodClass,
          methodName:field.methodName,codeBytes,sites:new Map()};
        group.push(method);
      }
      const p=field.dexPc*2;
      if (p+4>method.codeBytes.length ||
          method.codeBytes[p]!==opcode ||
          (method.codeBytes[p+2] | (method.codeBytes[p+3]<<8))!==field.fieldIndex ||
          method.sites.has(field.dexPc))
        throw new Error('DEX opcode site disagrees with exact method bytes');
      method.sites.set(field.dexPc,{
        name:field.methodName,methodClass:field.methodClass,
        declaringClass:field.declaringClass,fieldName:field.fieldName,
        fieldType:field.fieldType,opcode,kind,fieldId:field.fieldIndex,
        methodIndex:field.methodIndex,dexPc:field.dexPc,
        dexId:dex.dexId,dexSha256:dex.sha256,
        sourceFile:field.sourceFile ?? null,
        sourceLine:field.sourceLine ?? null
      });
      if (identities !== null) matched.add(identity);
      count++;
    }
  }
  if (identities !== null && matched.size !== identities.size)
    throw new Error('Requested field selector not found in packaged DEX');
  if (count===0) throw new Error('No supported '+opcodeGroup+' field sites selected');
  return {methods,count};
}
function install() {
  if (!opcodes || !Object.hasOwn(opcodeGroups,opcodeGroup))
    throw new Error('Unrecognized or missing nterp opcode group');
  if (!profile || profile.api !== 33 || profile.architecture !== 'x86_64' ||
      Process.arch !== 'x64' || Process.pointerSize !== 8 ||
      profile.handlerSize !== 128 || profile.opcodeCount !== 256)
    throw new Error('Unsupported ART / nterp ABI');
  if (typeof threadFilter !== 'string' || threadFilter.length === 0 ||
      threadFilter.length > 128)
    throw new Error('Provide an exact thread name or * to watch all threads');
  const selected = selectFieldSites(catalog,selectors);
  const methods = selected.methods;
  // ArtMethod address distinguishes loaded runtime methods; a DEX method index
  // alone does NOT distinguish the framework, secondary DEX, or class loaders.
  function liveFieldSite(artMethod,instruction,methodGroup,opcode,fieldId) {
    const methodKey=artMethod.toString();
    const cached=liveBases.get(methodKey);
    if (cached) {
      if (!methodGroup.includes(cached.method)) return null;
      for (const site of cached.method.sites.values()) {
        if (site.opcode===opcode && site.fieldId===fieldId &&
            cached.base.add(site.dexPc*2).equals(instruction))
          return site;
      }
      return null;
    }
    const matches=[];
    for (const method of methodGroup) {
      for (const site of method.sites.values()) {
        if (site.opcode!==opcode || site.fieldId!==fieldId) continue;
        const start=instruction.sub(site.dexPc*2);
        const range=Process.findRangeByAddress(start);
        const end=start.add(method.codeBytes.length);
        if (!range || !range.protection.includes('r') ||
            start.compare(range.base)<0 ||
            end.compare(range.base.add(range.size))>0) continue;
        let bytes;
        try {bytes=new Uint8Array(start.readByteArray(method.codeBytes.length));}
        catch (_) {continue;}
        let identical=true;
        for (let i=0;i<bytes.length;i++)
          if (bytes[i]!==method.codeBytes[i]) {identical=false;break;}
        if (identical) matches.push({base:start,site,method});
      }
    }
    if (matches.length!==1) {
      unverifiedSites++;
      if (unverifiedSites<=8)
        recordDiagnostic('Ambiguous/unverified live DEX method: index='+
          methodGroup[0].methodIndex+' candidates='+matches.length);
      return null; // Never ascribe a field to a guessed DEX.
    }
    const match=matches[0];
    if (liveBases.size>=4096) liveBases.delete(liveBases.keys().next().value);
    liveBases.set(methodKey,{base:match.base,method:match.method});
    return match.site;
  }
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
  const ops = opcodes; // four slots, selected scalar32 or wide64 field family
  const bpIds = new Map(ops.map((opcode, index) => [opcode, index]));
  for (const opcode of ops) {
    const site = base.add(opcode * 128);
    const range = Process.findRangeByAddress(site);
    if (!range || !range.protection.includes('x'))
      throw new Error('nterp opcode address not executable: ' + opcode);
  }

  function installForThread(t) {
    if (!armed || (threadFilter !== '*' && t.name !== threadFilter) ||
        observedThreads.has(t.id)) return;
    if (observedThreads.size >= 64) {
      recordDiagnostic('Thread watch limit exceeded (64)');
      return;
    }
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
    if (!old) throw new Error('Missing debug breakpoint id='+id);
    if (old.equals(to)) return; // Consecutive identical field opcodes.
    state.thread.unsetHardwareBreakpoint(id);
    state.slots.delete(id);
    state.thread.setHardwareBreakpoint(id,to);
    state.slots.set(id,to);
  }

  // A DEX wide value occupies two consecutive 32-bit vregs in this
  // build's x86_64 nterp shadow frame. Reconstruct raw bits without JS
  // Number or a floating-point conversion (which may canonicalize NaNs).
  function readVreg(fp, vreg, descriptor) {
    const slot = fp.add(vreg * 4);
    if (descriptor === 'J' || descriptor === 'D') {
      const lo = slot.readU32().toString(16).padStart(8, '0');
      const hi = slot.add(4).readU32().toString(16).padStart(8, '0');
      return '0x' + hi + lo;
    }
    if (descriptor === 'F') return slot.readU32();
    const value = slot.readS32();
    // For writes, the DEX handler stores the narrow field width; sample
    // exactly that width, not untruncated source vreg bits. For reads, the
    // handler sign/zero extends into the 32-bit destination vreg.
    if (descriptor === 'Z') return value & 0xff;
    if (descriptor === 'B') return (value << 24) >> 24;
    if (descriptor === 'C') return value & 0xffff;
    if (descriptor === 'S') return (value << 16) >> 16;
    return value;
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
    // Borrow the already-subscribed successor handler instead of putting two
    // hardware breakpoints at the same address.
    const borrowedSlot=bpIds.has(successorOpcode) ?
      bpIds.get(successorOpcode) : id;
    const moved=borrowedSlot===id && !destination.equals(base.add(opcode*128));
    const methodIndex=method.add(8).readU32();
    const methodCandidates=methods.get(methodIndex);
    const high=pc.add(1).readU8(), fieldId=pc.add(2).readU16();
    const target=methodCandidates &&
      liveFieldSite(method,pc,methodCandidates,opcode,fieldId);
    let sampled=null;
    if (target && target.opcode===opcode && target.fieldId===fieldId &&
        (context.rbx.toUInt32()&255)===high) {
      const vreg=opcode>=0x60 ? high : high&15;
      sampled={...target, vreg,
        preValue:target.kind===2 ?
          readVreg(fp,vreg,target.fieldType) : null,
        pc:pc.toString()};
      fieldHits++;
    }
    // Hardware breakpoint is raised BEFORE opcode execution. Redirect the
    // same slot to the successor opcode; that trap occurs after the field
    // operation on the normal (nonthrowing) path. We never patch ART code.
    if (moved) switchBreakpoint(state,id,destination);
    state.pending={id,borrowedSlot,moved,
      original:base.add(opcode*128),destination,
      nextPc,method,fp,sampled};
  }

  function completeField(context,state) {
    const p=state.pending;
    state.pending=null;
    if (p.moved) switchBreakpoint(state,p.id,p.original);
    if (!context.r12.equals(p.nextPc) || !context.r13.equals(p.fp) ||
        !context.rsp.readPointer().equals(p.method)) return;
    completedHits++;
    if (!p.sampled) return;
    const f=p.sampled;
    const value=f.kind===1 ?
      readVreg(context.r13,f.vreg,f.fieldType) : f.preValue;
    if (records.length>=MAX_RECORDS) {dropped++;return;}
    if (records.length < 8) send({type:'artwatch-nterp-record-sample',
      number:records.length+1, method:f.name, value});
    records.push({seq:records.length+1,method:f.name,
      methodClass:f.methodClass,declaringClass:f.declaringClass,
      fieldName:f.fieldName,fieldType:f.fieldType,
      valueRepresentation:
        f.fieldType==='F'?'raw-u32-ieee754':
        f.fieldType==='D'?'raw-u64-ieee754':
        f.fieldType==='J'?'raw-u64-le':
        f.fieldType==='Z'?'unsigned-boolean-byte':
        f.fieldType==='B'?'signed-int8':
        f.fieldType==='C'?'unsigned-int16':
        f.fieldType==='S'?'signed-int16':'signed-int32',
      dexId:f.dexId,dexSha256:f.dexSha256,
      methodIndex:f.methodIndex,fieldIndex:f.fieldId,dexPc:f.dexPc,
      dexPcSource:'live instruction base verified against packaged DEX bytes',
      runtimeMethodAddress:p.method.toString(),
      sourceFile:f.sourceFile,sourceLine:f.sourceLine,
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
      const pending=state.pending;
      const succeeded=pending && pending.borrowedSlot===id &&
        state.slots.get(id).equals(pending.destination) &&
        details.context.r12.equals(pending.nextPc) &&
        details.context.r13.equals(pending.fp) &&
        details.context.rsp.readPointer().equals(pending.method);
      if (succeeded) {
        // The successor may itself be another watched field instruction.
        // Finish the previous access, then begin the new one at this trap.
        completeField(details.context,state);
        if (bpIds.has(details.context.r12.readU8()))
          beginField(details.context,state,ops[id]);
      } else {
        if (pending) {
          if (pending.moved) {
            if (!state.slots.get(pending.id).equals(pending.destination))
              throw new Error('Pending breakpoint identity corrupted');
            switchBreakpoint(state,pending.id,pending.original);
          }
          state.pending=null;
          abandonedFieldAttempts++;
        }
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
    // Watch the configured thread name, or explicitly * for every thread.
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
    buildId,candidateHandlers:ops.length,selectedFieldSites:selected.count,
    threadFilter,opcodeGroup,
    attachedHandlers:0,
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
  stop(){
    if(threadObserver){threadObserver.detach();threadObserver=null;}
    let removed=0,failures=0;
    for(const state of observedThreads.values()){
      for(const id of state.slots.keys()){
        try{state.thread.unsetHardwareBreakpoint(id);removed++;}
        catch(_){failures++;}
      }
      state.pending=null;
      state.slots.clear();
    }
    observedThreads.clear();
    armed=false;
    return {removed,failures,recorded:records.length};
  },
  snapshot(){
    return {ready,armed,opcodeGroup,callbacks,hardwareHits,fieldHits,completedHits,
      unverifiedSites,verifiedRuntimeMethods:liveBases.size,
      watchedThreads:Array.from(observedThreads.keys()),abandonedFieldAttempts,
      events:records.slice(),
      dropped,errors:diagnostics.slice(),
      pending:Array.from(observedThreads.values()).filter(t=>t.pending).length};
  }
};
try{armBackend=install();}
catch(e){
  recordDiagnostic(e.stack||e);
  send({type:'artwatch-nterp-init',ready:false,error:String(e)});
}
