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
const selectors = globalThis.__artwatchNterpSelectors;
const threadFilter = globalThis.__artwatchNterpThreadFilter;
const MAX_RECORDS = 2048;
const active = new Map();
const records = [];
const diagnostics = [];
const observedThreads = new Map();
let threadObserver = null;
let hardwareHits = 0;
let fieldHits = 0;
let completedHits = 0;
let unverifiedSites = 0;
let abandonedFieldAttempts = 0;
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
function selectFieldSites(data, selectors) {
  if (!data || !Array.isArray(data.dexFiles) ||
      data.dexFiles.length !== 1 ||
      !Array.isArray(data.dexFiles[0].fieldAccesses) ||
      !Array.isArray(data.dexFiles[0].fieldMethods)) {
    throw new Error('This version requires a single verified DEX file');
  }
  // A plain DEX method index is NOT globally unique. Cross-DEX and
  // class-loader identity require an additional runtime discriminator.
  const dex = data.dexFiles[0];
  if (dex.dexId !== 0 || typeof dex.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(dex.sha256))
    throw new Error('Invalid DEX catalog identity');
  const sourceMethods = new Map();
  for (const m of dex.fieldMethods) {
    if (!Number.isInteger(m.methodIndex) || m.methodIndex < 0 ||
        typeof m.methodClass !== 'string' || typeof m.methodName !== 'string' ||
        !Number.isInteger(m.insnsSize) || m.insnsSize < 1 ||
        m.insnsSize > 65536 || typeof m.insnsHex !== 'string' ||
        m.insnsHex.length !== m.insnsSize * 4 ||
        !/^[0-9a-f]+$/i.test(m.insnsHex) || sourceMethods.has(m.methodIndex))
      throw new Error('Invalid field method code item in DEX catalog');
    sourceMethods.set(m.methodIndex, m);
  }
  const validSelectors = selectors === null || selectors === undefined ? null : selectors;
  if (validSelectors !== null &&
      (!Array.isArray(validSelectors) || validSelectors.length === 0 ||
       validSelectors.some(s => !s || typeof s !== 'object' ||
         typeof s.methodClass !== 'string' ||
         typeof s.methodName !== 'string' ||
         typeof s.fieldName !== 'string'))) {
    throw new Error('Expected an array of exact methodClass/methodName/fieldName selectors');
  }
  const wanted = validSelectors === null ? null :
    new Set(validSelectors.map(s =>
      [s.methodClass, s.methodName, s.fieldName].join('\0')));
  const matched = new Set();
  const methods = new Map();
  let count = 0;
  for (const field of dex.fieldAccesses) {
    const opcode = Number.parseInt(field.opcode, 16);
    if (!fieldOps.has(opcode) || field.valueKind !== 'int' ||
        field.fieldType !== 'I') continue;
    const identity = [field.methodClass, field.methodName, field.fieldName].join('\0');
    if (wanted !== null && !wanted.has(identity)) continue;
    if (!Number.isInteger(field.methodIndex) || field.methodIndex < 0 ||
        !Number.isInteger(field.fieldIndex) || field.fieldIndex < 0 ||
        !Number.isInteger(field.dexPc) || field.dexPc < 0 ||
        typeof field.methodClass !== 'string' ||
        typeof field.methodName !== 'string' ||
        typeof field.declaringClass !== 'string') {
      throw new Error('Invalid DEX field site metadata');
    }
    const kind = (opcode === 0x52 || opcode === 0x60) ? 1 : 2;
    if (field.operation !== (kind === 1 ? 'read' : 'write') ||
        field.access !== (opcode < 0x60 ? 'instance' : 'static'))
      throw new Error('Field opcode semantics disagree with catalog');
    if (wanted !== null) matched.add(identity);
    let method = methods.get(field.methodIndex);
    if (method === undefined) {
      const source = sourceMethods.get(field.methodIndex);
      if (!source || source.methodClass !== field.methodClass ||
          source.methodName !== field.methodName)
        throw new Error('Missing exact DEX method code for field');
      const codeBytes = new Uint8Array(source.insnsSize * 2);
      for (let i = 0; i < codeBytes.length; i++)
        codeBytes[i] = Number.parseInt(source.insnsHex.slice(2*i, 2*i+2),16);
      method = {methodClass:field.methodClass,
        methodName:field.methodName,sites:new Map(),codeBytes};
      methods.set(field.methodIndex,method);
    } else if (method.methodClass !== field.methodClass ||
               method.methodName !== field.methodName) {
      throw new Error('DEX method ID collision');
    }
    // Validate both operand field ID and opcode against the raw packaged
    // method bytes. Sites are keyed by PC; repeated field IDs are legal.
    const p = field.dexPc * 2;
    if (p + 4 > method.codeBytes.length ||
        method.codeBytes[p] !== opcode ||
        (method.codeBytes[p+2] | (method.codeBytes[p+3] << 8)) !== field.fieldIndex ||
        method.sites.has(field.dexPc))
      throw new Error('Field site does not match DEX method instruction bytes');
    method.sites.set(field.dexPc,{
      name:field.methodName, methodClass:field.methodClass,
      declaringClass:field.declaringClass,fieldName:field.fieldName,
      opcode,kind,fieldId:field.fieldIndex,methodIndex:field.methodIndex,
      dexPc:field.dexPc,dexId:dex.dexId,dexSha256:dex.sha256,
      sourceFile:field.sourceFile ?? null,sourceLine:field.sourceLine ?? null
    });
    count++;
  }
  if (wanted !== null && matched.size !== wanted.size)
    throw new Error('A requested field selector was not found in packaged DEX');
  if (count === 0) throw new Error('No supported int DEX field sites selected');
  return {methods, count};
}

function install() {
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
  const liveBases = new Map();

  function liveFieldSite(artMethod, instruction, method, opcode, fieldId) {
    const candidates = Array.from(method.sites.values()).filter(s =>
      s.opcode === opcode && s.fieldId === fieldId);
    if (candidates.length === 0) return null;
    const methodKey = artMethod.toString();
    const cached = liveBases.get(methodKey);
    if (cached) {
      for (const site of candidates)
        if (cached.base.add(site.dexPc * 2).equals(instruction))
          return site;
      return null;
    }
    const matches = [];
    for (const site of candidates) {
      const start = instruction.sub(site.dexPc * 2);
      const range = Process.findRangeByAddress(start);
      const end = start.add(method.codeBytes.length);
      if (!range || !range.protection.includes('r') ||
          start.compare(range.base) < 0 ||
          end.compare(range.base.add(range.size)) > 0) continue;
      let actual;
      try { actual = new Uint8Array(start.readByteArray(method.codeBytes.length)); }
      catch (_) { continue; }
      let equal = true;
      for (let i = 0; i < actual.length; i++)
        if (actual[i] !== method.codeBytes[i]) {equal = false; break;}
      if (equal) matches.push({site,base:start});
    }
    if (matches.length !== 1) {
      unverifiedSites++;
      if (unverifiedSites <= 8)
        recordDiagnostic('Unverified runtime DEX instruction base: method=' +
          method.methodName + ' fieldId=' + fieldId +
          ' matches=' + matches.length);
      return null; // Never fabricate a DEX PC.
    }
    if (liveBases.size >= 4096)
      liveBases.delete(liveBases.keys().next().value);
    liveBases.set(methodKey,{base:matches[0].base});
    return matches[0].site;
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
  const ops = [0x52, 0x59, 0x60, 0x67]; // iget, iput, sget, sput
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
    const methodSites=methods.get(methodIndex);
    const high=pc.add(1).readU8(), fieldId=pc.add(2).readU16();
    const target=methodSites &&
      liveFieldSite(method,pc,methodSites,opcode,fieldId);
    let sampled=null;
    if (target && target.opcode===opcode && target.fieldId===fieldId &&
        (context.rbx.toUInt32()&255)===high) {
      const vreg=opcode>=0x60 ? high : high&15;
      sampled={...target, vreg,
        preValue:target.kind===2 ? fp.add(vreg*4).readS32() : null,
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
    const value=f.kind===1
      ? context.r13.add(f.vreg*4).readS32() : f.preValue;
    if (records.length>=MAX_RECORDS) {dropped++;return;}
    if (records.length < 8) send({type:'artwatch-nterp-record-sample',
      number:records.length+1, method:f.name, value});
    records.push({seq:records.length+1,method:f.name,
      methodClass:f.methodClass,declaringClass:f.declaringClass,
      fieldName:f.fieldName,fieldType:'I',
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
    threadFilter,
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
    return {ready,armed,callbacks,hardwareHits,fieldHits,completedHits,
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
