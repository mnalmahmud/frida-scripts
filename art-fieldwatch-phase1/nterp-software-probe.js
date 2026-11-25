'use strict';

// EXPERIMENTAL stock ART nterp software handler instrumentation, not Java hooks.
// Pinned profile: Android 13 API33 x86_64, exact ELF Build ID, 32-bit and 64-bit fields.
// Per-worker-thread Stalker callouts observe selected field and successor handlers.
// It observes nterp only. JIT/AOT/switch and native field accesses are not covered.
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
const opcodeGroup = globalThis.__artwatchNterpOpcodeGroup ?? 'allPrimitives';
// x86_64 has four hardware execution slots. Subscribe to ONE opcode family
// per run, without pretending a partial family provides app-wide coverage.
const opcodeGroups = Object.freeze({
  scalar32: Object.freeze([0x52, 0x59, 0x60, 0x67]),
  wide64: Object.freeze([0x53, 0x5a, 0x61, 0x68]),
  boolean8: Object.freeze([0x55, 0x5c, 0x63, 0x6a]),
  byte8: Object.freeze([0x56, 0x5d, 0x64, 0x6b]),
  char16: Object.freeze([0x57, 0x5e, 0x65, 0x6c]),
  short16: Object.freeze([0x58, 0x5f, 0x66, 0x6d]),
  allPrimitives: Object.freeze([
    0x52,0x53,0x55,0x56,0x57,0x58,0x59,0x5a,0x5c,0x5d,0x5e,0x5f,
    0x60,0x61,0x63,0x64,0x65,0x66,0x67,0x68,0x6a,0x6b,0x6c,0x6d
  ])
});
const opcodes = opcodeGroups[opcodeGroup];
const MAX_RECORDS = 8192;
const stalkedThreads = new Set();
let followedCount=0;
let knownHookCount=0;
const watchedThreadIds = new Set();
const pendingByThread = new Map();
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
        short16: [['short'], ['S']],
        allPrimitives: [
          ['int','wide','boolean','byte','char','short'],
          ['I','F','J','D','Z','B','C','S']
        ]
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
  if (opcodeGroup !== 'allPrimitives' || !profile ||
      profile.api !== 33 || profile.architecture !== 'x86_64' ||
      Process.arch !== 'x64' || Process.pointerSize !== 8 ||
      profile.handlerSize !== 128 || profile.opcodeCount !== 256)
    throw new Error('Unsupported nterp software dispatcher ABI');
  if (typeof threadFilter !== 'string' || threadFilter.length === 0 ||
      threadFilter.length > 128)
    throw new Error('Provide exact target thread name or *');
  const selected=selectFieldSites(catalog,selectors);
  const methods=selected.methods;
  const art=Process.findModuleByName('libart.so');
  if (!art) throw new Error('No live libart.so module');
  const buildId=readLiveBuildId(art);
  if (buildId!==profile.buildId ||
      buildId!=='c8b6a2df9893030c07b3b96dc24a7d30')
    throw new Error('Unsupported exact stock ART build ID');
  if (!Number.isInteger(profile.startOffset) ||
      !Number.isInteger(profile.endOffset) ||
      profile.endOffset-profile.startOffset!==32768 ||
      profile.startOffset<=0 || profile.endOffset>art.size)
    throw new Error('Invalid nterp table shape');
  const handlerBase=art.base.add(profile.startOffset);
  const hookOpcodes=new Set();
  let expectedSites=0;
  for (const candidates of methods.values()) {
    for (const method of candidates) {
      for (const site of method.sites.values()) {
        hookOpcodes.add(site.opcode);
        const next=(site.dexPc+2)*2;
        if (next>=method.codeBytes.length)
          throw new Error('Field site missing a packaged successor opcode');
        hookOpcodes.add(method.codeBytes[next]);
        expectedSites++;
      }
    }
  }
  if (hookOpcodes.size===0 || hookOpcodes.size>256 ||
      expectedSites!==selected.count)
    throw new Error('Invalid selected handler coverage');
  const hookAddresses=new Map();
  for (const opcode of hookOpcodes) {
    const at=handlerBase.add(opcode*128);
    const range=Process.findRangeByAddress(at);
    if (!range || !range.protection.includes('x'))
      throw new Error('nterp opcode handler is not executable: '+opcode);
    hookAddresses.set(opcode,at);
  }

  function liveFieldSite(artMethod,instruction,methodGroup,opcode,fieldId) {
    const key=artMethod.toString();
    const cached=liveBases.get(key);
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
    let eligible=0;
    for (const method of methodGroup) {
      for (const site of method.sites.values()) {
        if (site.opcode!==opcode || site.fieldId!==fieldId) continue;
        eligible++;
        const start=instruction.sub(site.dexPc*2);
        const range=Process.findRangeByAddress(start);
        const end=start.add(method.codeBytes.length);
        if (!range || !range.protection.includes('r') ||
            start.compare(range.base)<0 ||
            end.compare(range.base.add(range.size))>0) continue;
        let bytes;
        try {bytes=new Uint8Array(start.readByteArray(method.codeBytes.length));}
        catch (_) {continue;}
        let same=true;
        for (let i=0;i<bytes.length;i++)
          if (bytes[i]!==method.codeBytes[i]) {same=false;break;}
        if (same) matches.push({base:start,site,method});
      }
    }
    if (eligible===0) return null;
    if (matches.length!==1) {
      unverifiedSites++;
      if (unverifiedSites<=8)
        recordDiagnostic('Ambiguous live DEX candidate methodIndex='+
          methodGroup[0].methodIndex+' matches='+matches.length);
      return null;
    }
    const match=matches[0];
    if (liveBases.size>=4096) liveBases.delete(liveBases.keys().next().value);
    liveBases.set(key,{base:match.base,method:match.method});
    return match.site;
  }

  function readVreg(frame,vreg,descriptor) {
    const slot=frame.add(vreg*4);
    if (descriptor==='J' || descriptor==='D') {
      const lo=slot.readU32().toString(16).padStart(8,'0');
      const hi=slot.add(4).readU32().toString(16).padStart(8,'0');
      return '0x'+hi+lo;
    }
    if (descriptor==='F') return slot.readU32();
    const value=slot.readS32();
    if (descriptor==='Z') return value&255;
    if (descriptor==='B') return (value<<24)>>24;
    if (descriptor==='C') return value&65535;
    if (descriptor==='S') return (value<<16)>>16;
    return value;
  }
  function representation(descriptor) {
    return {I:'signed-int32',F:'raw-u32-ieee754',J:'raw-u64-le',
      D:'raw-u64-ieee754',Z:'unsigned-boolean-byte',B:'signed-int8',
      C:'unsigned-int16',S:'signed-int16'}[descriptor];
  }
  function complete(p,ctx) {
    if (!p.sampled) return;
    completedHits++;
    const f=p.sampled;
    const value=f.kind===1 ?
      readVreg(ctx.r13,f.vreg,f.fieldType) : f.preValue;
    if (records.length>=MAX_RECORDS) {dropped++;return;}
    if (records.length<8)
      send({type:'artwatch-nterp-software-record-sample',
        number:records.length+1,method:f.name,value});
    records.push({
      seq:records.length+1,method:f.name,
      methodClass:f.methodClass,declaringClass:f.declaringClass,
      fieldName:f.fieldName,fieldType:f.fieldType,
      valueRepresentation:representation(f.fieldType),
      dexId:f.dexId,dexSha256:f.dexSha256,
      methodIndex:f.methodIndex,fieldIndex:f.fieldId,dexPc:f.dexPc,
      dexPcSource:'live instruction base verified against packaged DEX bytes',
      runtimeMethodAddress:p.method.toString(),
      sourceFile:f.sourceFile,sourceLine:f.sourceLine,
      opcode:f.opcode,kind:f.kind,value,instructionAddress:p.pc.toString(),
      provenance:'nterp Stalker opcode callout and succeeding opcode'
    });
  }
  function opcodeEnter(ctx,opcode) {
    const pc=ctx.r12,fp=ctx.r13,method=ctx.rsp.readPointer();
    if (pc.isNull() || fp.isNull() || method.isNull() || pc.readU8()!==opcode)
      return; // Do not attribute unknown interpreter register state.
    const tid=Process.getCurrentThreadId();
    callbacks++;
    const old=pendingByThread.get(tid);
    if (old) {
      pendingByThread.delete(tid);
      if (pc.equals(old.nextPc) && fp.equals(old.fp) &&
          method.equals(old.method)) complete(old,ctx);
      else abandonedFieldAttempts++;
    }
    if (!fieldOps.has(opcode)) return;
    const high=pc.add(1).readU8(), fieldId=pc.add(2).readU16();
    const methodIndex=method.add(8).readU32();
    const methodCandidates=methods.get(methodIndex);
    const target=methodCandidates &&
      liveFieldSite(method,pc,methodCandidates,opcode,fieldId);
    let sampled=null;
    if (target && target.opcode===opcode && target.fieldId===fieldId &&
        (ctx.rbx.toUInt32()&255)===high) {
      const vreg=opcode>=0x60 ? high : high&15;
      sampled={...target,vreg,
        preValue:target.kind===2 ? readVreg(fp,vreg,target.fieldType) : null};
      fieldHits++;
    }
    if (sampled)
      pendingByThread.set(tid,{method,fp,pc,nextPc:pc.add(4),sampled});
  }
  const handlerByAddress=new Map(
    Array.from(hookAddresses,([op,address])=>[address.toString(),op]));
  function transform(iterator) {
    let instruction;
    while ((instruction=iterator.next())!==null) {
      const opcode=handlerByAddress.get(instruction.address.toString());
      if (opcode!==undefined) {
        // Callout executes on copied worker-thread instructions. The
        // process-wide ART handler code remains entirely untouched.
        iterator.putCallout(context=>{
          if (!armed) return;
          try {opcodeEnter(context,opcode);}
          catch(e) {
            const message='nterp Stalker opcode '+opcode+': '+(e.stack||e);
            recordDiagnostic(message);
            if (diagnostics.length<=8)
              send({type:'artwatch-nterp-stalker-error',error:message});
          }
        });
      }
      iterator.keep();
    }
  }
  function followThread(t) {
    if (!armed || (threadFilter!=='*' && t.name!==threadFilter) ||
        stalkedThreads.has(t.id)) return;
    if (stalkedThreads.size>=64) {
      recordDiagnostic('Stalker thread cap exceeded (64)');
      return;
    }
    try {
      Stalker.follow(t.id,{transform});
      stalkedThreads.add(t.id);
      followedCount++;
      send({type:'artwatch-nterp-stalker-thread',tid:t.id,
        opcodeHandlers:hookAddresses.size});
    } catch(e) {
      recordDiagnostic('Cannot follow field thread tid='+t.id+': '+e);
    }
  }
  function start() {
    // Follow only the explicitly named worker. Unlike process-global
    // software hooks, this does not redirect unrelated UI/GC threads.
    try {
      armed=true;
      threadObserver=Process.attachThreadObserver({
        onAdded(t){followThread(t);},
        onRenamed(t){followThread(t);},
        onRemoved(t){
          pendingByThread.delete(t.id);
          stalkedThreads.delete(t.id);
        }
      });
      return true;
    } catch(e) {
      recordDiagnostic('Cannot start thread-limited nterp Stalker: '+e);
      armed=false;
      if (threadObserver) {threadObserver.detach();threadObserver=null;}
      for (const tid of stalkedThreads)
        try {Stalker.unfollow(tid);} catch(_){}
      stalkedThreads.clear();
      return false;
    }
  }
  knownHookCount=hookAddresses.size;
  ready=true;
  send({type:'artwatch-nterp-software-init',ready:true,
    buildId,mode:'stalker-callout',
    hookOpcodes:Array.from(hookOpcodes).sort((a,b)=>a-b),
    candidateHandlers:hookAddresses.size,selectedFieldSites:selected.count,
    threadFilter,opcodeGroup});
  return start;
}
let armBackend=null;
rpc.exports={
  arm() {
    if (!ready || armed || !armBackend) return false;
    return armBackend();
  },
  stop() {
    armed=false;
    if (threadObserver) {threadObserver.detach();threadObserver=null;}
    let failures=0,removed=0;
    for (const tid of stalkedThreads) {
      try {Stalker.unfollow(tid);removed++;}
      catch(e){failures++;recordDiagnostic('Stalker unfollow: '+e);}
    }
    stalkedThreads.clear();
    try {Stalker.garbageCollect();} catch(_){}
    watchedThreadIds.clear();
    pendingByThread.clear();
    return {removed,failures,recorded:records.length};
  },
  snapshot() {
    return {
      ready,armed,opcodeGroup,mode:'stalker-callout',
      callbacks,fieldHits,completedHits,hardwareHits,
      unverifiedSites,verifiedRuntimeMethods:liveBases.size,
      abandonedFieldAttempts,pending:pendingByThread.size,
      dropped,events:records,errors:diagnostics,
      threadsFollowed:followedCount,
      attachedHooks:stalkedThreads.size?knownHookCount:0
    };
  }
};
try {armBackend=install();}
catch(e){recordDiagnostic('nterp Stalker initialization failed: '+(e.stack||e));}
