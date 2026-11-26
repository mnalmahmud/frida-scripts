'use strict';
// ART field-node *compiler emission* observer on stock, unmodified API33 x64.
// This does not see instruction execution or capture runtime field values.
// No Java hooks, no JVMTI, no debugger, no ART or compiled-code mutation.
// Exact runtime/compiler GNU Build IDs and Itanium x64 HInstruction vtable
// gate every private-layout read; unmatched builds fail closed.
const BUILD_IDS = Object.freeze({
  runtime: 'c8b6a2df9893030c07b3b96dc24a7d30',
  compiler: '0b33b00205f7151b4fce7490c3715d99'
});
const SYMBOLS = Object.freeze({
  compile: '_ZN3art3jit11JitCompiler13CompileMethodEPNS_6ThreadEPNS0_15JitMemoryRegionEPNS_9ArtMethodENS_15CompilationKindE',
  get: '_ZN3art6x86_6430InstructionCodeGeneratorX86_6421VisitInstanceFieldGetEPNS_17HInstanceFieldGetE',
  set: '_ZN3art6x86_6430InstructionCodeGeneratorX86_6421VisitInstanceFieldSetEPNS_17HInstanceFieldSetE',
  getVtable: '_ZTVN3art17HInstanceFieldGetE',
  setVtable: '_ZTVN3art17HInstanceFieldSetE'
});
let ready=false;
let installed=false;
let compilerObserver=null;
let compiled=0;
let emitted=0;
let matched=0;
let rawFieldVisits=0;
let selectedCompilations=0;
const errors=[];
const active=new Map();
const methodsWithCode=new Map();
const records=[];
const MAX_RECORDS=512;
const catalog=globalThis.__artwatchJitFieldCatalog;
function fail(message) {
  if (errors.length<16) errors.push(String(message));
  send({type:'artwatch-jit-field-error',message:String(message)});
}
function buildId(module) {
  const base=module.base;
  if (base.readU32()!==0x464c457f || base.add(4).readU8()!==2 ||
      base.add(5).readU8()!==1 || base.add(16).readU16()!==3)
    throw new Error('Expected ELF64 little-endian ET_DYN');
  const phoff=Number(base.add(32).readU64().toString());
  const entsize=base.add(54).readU16();
  const count=base.add(56).readU16();
  if (phoff>65536 || entsize<56 || entsize>256 || count>512)
    throw new Error('Bad ELF program headers');
  for (let i=0;i<count;i++) {
    const ph=base.add(phoff+i*entsize);
    if (ph.readU32()!==4) continue;
    const vaddr=Number(ph.add(16).readU64().toString());
    const len=Number(ph.add(32).readU64().toString());
    if (!Number.isSafeInteger(vaddr) || len>65536) continue;
    const notes=base.add(vaddr);
    for (let p=0;p+12<=len;) {
      const namesz=notes.add(p).readU32(),descsz=notes.add(p+4).readU32();
      const kind=notes.add(p+8).readU32();
      const desc=p+12+((namesz+3)&~3);
      const next=desc+((descsz+3)&~3);
      if (next>len) break;
      if (kind===3 && namesz>=4 && descsz>=16 && descsz<=20 &&
          notes.add(p+12).readUtf8String(3)==='GNU') {
        const bytes=new Uint8Array(notes.add(desc).readByteArray(descsz));
        return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
      }
      p=next;
    }
  }
  throw new Error('ELF GNU Build ID unavailable');
}
function compileCatalog(input) {
  if (!input || !Array.isArray(input.dexFiles) || input.dexFiles.length===0)
    throw new Error('Missing DEX catalog');
  const byIndex=new Map();
  for (const dex of input.dexFiles) {
    if (!Number.isInteger(dex.dexId) || !/^[0-9a-f]{64}$/i.test(dex.sha256))
      throw new Error('Bad DEX provenance');
    const candidates=new Map();
    for (const m of dex.fieldMethods) {
      if (!Number.isInteger(m.methodIndex) || typeof m.insnsHex!=='string' ||
          !Number.isInteger(m.insnsSize) || m.insnsHex.length!==m.insnsSize*4)
        throw new Error('Invalid DEX method bytes');
      candidates.set(m.methodIndex,m);
    }
    for (const f of dex.fieldAccesses) {
      if (!['0x52','0x59'].includes(f.opcode) ||
          f.fieldType!=='I' || f.valueKind!=='int' ||
          !Number.isInteger(f.dexPc) || !Number.isInteger(f.fieldIndex))
        continue;
      const method=candidates.get(f.methodIndex);
      const p=f.dexPc*4;
      if (!method || p+8>method.insnsHex.length ||
          method.insnsHex.slice(p,p+2).toLowerCase()!==f.opcode.slice(2) ||
          Number.parseInt(method.insnsHex.slice(p+4,p+8).match(/../g).reverse().join(''),16)!==f.fieldIndex)
        throw new Error('Catalog field site does not match exact opcode bytes');
      const site={
        dexId:dex.dexId,dexSha256:dex.sha256,
        methodClass:f.methodClass,methodName:f.methodName,
        methodPrototype:f.methodPrototype,methodIndex:f.methodIndex,
        fieldName:f.fieldName,fieldIndex:f.fieldIndex,
        dexPc:f.dexPc,operation:f.operation
      };
      if (!byIndex.has(f.methodIndex)) byIndex.set(f.methodIndex,new Map());
      const pcs=byIndex.get(f.methodIndex);
      if (!pcs.has(f.dexPc)) pcs.set(f.dexPc,[]);
      pcs.get(f.dexPc).push(site);
    }
  }
  return byIndex;
}
function addRecord(record) {
  if (records.length<MAX_RECORDS) records.push(record);
  send({type:'artwatch-jit-field-emission',...record});
}
// ART13 x64 ArtMethod layout validated by pinned libart Build ID:
// declaring_class_ +0, access_flags_ +4, dex_method_index_ +8,
// method_index_ +12, hotness_count_ +14, ptr_sized_fields_.data_ +16,
// entry_point_from_quick_compiled_code_ +24. This is a read-only
// *method entrypoint* inventory, NOT a native field opcode offset map.
function quickEntrypoint(method) {
  if (!method || method.isNull()) return {valid:false};
  try {
    const pointer=method.add(24).readPointer();
    const range=Process.findRangeByAddress(pointer);
    const module=Process.findModuleByAddress(pointer);
    const file=range?.file?.path ?? null;
    const executable=!!range && range.protection.includes('x');
    let category='unknown-or-trampoline';
    if (executable && module?.name==='libart.so') category='art-runtime-stub';
    else if (executable && file && /\.(oat|odex|art)(?:$|\.)/.test(file))
      category='oat-or-odex-executable';
    else if (executable && !module)
      category='anonymous-executable-candidate';
    else if (executable) category='mapped-native-module';
    return {valid:executable,address:pointer.toString(),
      category,rangeProtection:range?.protection ?? null,
      module:module?.name ?? null,file};
  } catch(e) {return {valid:false,error:String(e)};}
}
function install() {
  if (installed) return;
  if (Process.arch!=='x64' || Process.pointerSize!==8)
    throw new Error('Only x86_64 compiler ABI verified');
  const art=Process.findModuleByName('libart.so');
  const compiler=Process.findModuleByName('libart-compiler.so');
  if (!art) throw new Error('Missing loaded libart.so');
  if (!compiler) return;  // The compiler can be lazily dlopened after injection.
  if (buildId(art)!==BUILD_IDS.runtime ||
      buildId(compiler)!==BUILD_IDS.compiler)
    throw new Error('Exact stock ART compiler/runtime ELF mismatch');
  const selected=compileCatalog(catalog);
  function symbol(name) {
    const p=compiler.findExportByName(SYMBOLS[name]);
    if (p===null) throw new Error('Missing exact compiler symbol '+name);
    return p;
  }
  const compile=symbol('compile'),get=symbol('get'),set=symbol('set');
  const vtableGet=symbol('getVtable').add(16);
  const vtableSet=symbol('setVtable').add(16);
  Interceptor.attach(compile,{
    onEnter(args) {
      this.tid=Process.getCurrentThreadId();
      this.prev=active.get(this.tid);
      const method=args[3];
      const methodIndex=method.isNull() ? -1 : method.add(8).readU32();
      const state={pointer:method,methodIndex,sites:selected.get(methodIndex),
                   emissions:0,records:[]};
      active.set(this.tid,state);
      this.state=state;
      if (state.sites) {
        selectedCompilations++;
        if (!method.isNull())
          methodsWithCode.set(method.toString(),
            {pointer:method,methodIndex,selectedPcs:Array.from(state.sites.keys())});
      }
      if (records.length<120) addRecord({
        phase:'compile-start',methodIndex,
        artMethod:method.toString(),selected:!!state.sites,
        selectedSitePcs:state.sites ? Array.from(state.sites.keys()) : []
      });
    },
    onLeave(ret) {
      if (this.state.emissions>0)
        addRecord({phase:'compile-finished',artMethod:this.state.pointer.toString(),
          methodIndex:this.state.methodIndex,
          emittedFields:this.state.emissions,
          compilationSucceeded:ret.toInt32()!==0});
      compiled++;
      if (this.prev===undefined) active.delete(this.tid);
      else active.set(this.tid,this.prev);
    }
  });
  function fieldEmission(kind,vtable,addr) {
    Interceptor.attach(addr,{
      onEnter(args) {
        const state=active.get(Process.getCurrentThreadId());
        if (!state) return;
        const node=args[1];
        if (node.isNull()) return;
        // Source-matched ART HInstruction: vptr [0], previous [8],
        // next [16], owning HBasicBlock [24], dex_pc_ [32].
        const verified=node.readPointer().equals(vtable);
        rawFieldVisits++;
        const pc=verified ? node.add(32).readU32() : null;
        if (records.length<120) addRecord({
          phase:'field-codegen-inventory',kind,
          methodIndex:state.methodIndex,
          selectedMethod:!!state.sites,
          nodeVtableVerified:verified,
          dexPc:pc
        });
        if (!verified || !state.sites) return;
        const candidates=state.sites.get(pc) || [];
        const sites=candidates.filter(c=>c.operation===kind);
        if (!sites.length) return;
        state.emissions++;
        emitted++;
        const evidence={
          phase:'field-codegen',kind,dexPc:pc,
          artMethod:state.pointer.toString(),
          methodIndex:state.methodIndex,
          candidateCount:sites.length,
          // A method index + DEX PC is not yet a runtime DexFile binding.
          dexFileRuntimeVerified:false,
          nodeVtableVerified:true,
          nativeInstructionOffsetKnown:false,
          valueAvailable:false,
          candidates:sites
        };
        matched+=Number(sites.length===1);
        addRecord(evidence);
      }
    });
  }
  fieldEmission('read',vtableGet,get);
  fieldEmission('write',vtableSet,set);
  installed=true;
  ready=true;
  send({type:'artwatch-jit-field-init',ready:true,
    mode:'compiler-field-codegen-observer',buildIds:BUILD_IDS,
    selectedMethods:selected.size});
}
rpc.exports={
  snapshot() {return {ready,compiled,emitted,matched,
                    selectedCompilations,rawFieldVisits,errors,records,
                    quickEntrypoints:Array.from(methodsWithCode.values(),m=>({
                      artMethod:m.pointer.toString(),methodIndex:m.methodIndex,
                      selectedPcs:m.selectedPcs,
                      entrypoint:quickEntrypoint(m.pointer)
                    }))};}
};
try {
  // ART typically loads libart-compiler.so on demand. Receive load
  // notifications rather than forcing a compiler dlopen from Frida.
  compilerObserver=Process.attachModuleObserver({
    onAdded(module) {
      if (module.name!=='libart-compiler.so' || installed) return;
      try {install();} catch(e) {
        fail('JIT field emission observer unavailable: '+(e.stack||e));
      }
    }
  });
  install();
} catch(e) {
  fail('JIT field emission observer unavailable: '+(e.stack||e));
}
