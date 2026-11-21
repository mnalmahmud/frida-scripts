'use strict';
// Read-only ART JIT interception probe; no field interception or IR mutation.
const TAG = '[art-fieldwatch/phase1] ';
const SAMPLE_LIMIT = 60;
const artLibraries = new Set(['libart.so', 'libartd.so', 'libart-compiler.so', 'libartd-compiler.so']);
const log = s => console.log(TAG + s);
const count = {runtime_internal: 0, compiler: 0, graph_builder: 0, pre_opt: 0};
// Track the method being compiled per native thread, only while compilation runs.
const compiling = new Map();
const builtByThread = new Map();
const activeGraphBuild = new Map();
const FIELD_SAMPLE_LIMIT = 140;
const fieldCounts = {instance: 0, static: 0};
const activeFieldBuilder = new Map();
const FIELD_NODE_SAMPLE_LIMIT = 180;
let observedFieldNodeCandidates = 0;
let observedFieldAccepts = 0;
const insertionCounts = {append: 0, 'basic-block': 0};
const optimizationByThread = new Map();
// Scoped to an actual out-of-line HGraphVisitor::VisitBasicBlock call.
const activeVisitorBlockByThread = new Map();
const knownFieldVtables = new Map();
// Read-only SSA producer classification from actual exported primary vtables.
// A missing symbol produces an explicit unknown kind; no ART methods are called.
const knownValueVtables = new Map();
const SSA_VALUE_KINDS = [
  'HParameterValue', 'HIntConstant', 'HLongConstant', 'HNullConstant',
  'HFloatConstant', 'HDoubleConstant', 'HPhi', 'HAdd', 'HSub',
  'HSelect', 'HNullCheck', 'HBoundsCheck', 'HLoadClass',
  'HInvokeStaticOrDirect', 'HInvokeVirtual', 'HNewInstance',
  'HInstanceFieldGet', 'HStaticFieldGet', 'HArrayGet',
  'HTypeConversion', 'HAnd', 'HOr', 'HNeg', 'HNot', 'HReturn'
];
const MAX_FIELD_PASSES = 20;
const MAX_FIELDS_PER_PASS = 20;
function discoverValueVtables(compiler) {
  const available = [];
  for (const kind of SSA_VALUE_KINDS) {
    const symbol = '_ZTVN3art' + kind.length + kind + 'E';
    const site = getExport(compiler, symbol);
    if (!site) continue;
    knownValueVtables.set(site.address.add(2 * Process.pointerSize).toString(),kind);
    available.push(kind);
  }
  log('ssa-value-vtables=' + available.join(','));
  send({type:'artwatch-ssa-vtables',available});
}
function classifySSAValue(value) {
  if (!value || value.isNull()) return null;
  try {
    const range = Process.findRangeByAddress(value);
    if (!range || !range.protection.includes('r')) return null;
    return knownValueVtables.get(value.readPointer().toString()) || null;
  } catch (_) { return null; }
}
let shadowShim = null;
let shadowModuleAttempted = false;
let shadowGraphLogged = 0;
let shadowNodeLogged = 0;
// Real compiler-built invoke nodes are our ABI oracle; no mutation here.
const INVOKE_ACCEPT = '_ZN3art21HInvokeStaticOrDirect6AcceptEPNS_13HGraphVisitorE';
const INVOKE_VTABLE = '_ZTVN3art21HInvokeStaticOrDirectE';
const MAX_EXISTING_INVOKES = 80;
let existingInvokeCount = 0;
const targetDexByMethod = new Map();
let backendVisitOrdinal = 0;
const BACKEND_VISIT_LIMIT = 160;
const backendCounts = {locations: 0, emission: 0};
const targetMethodPointers = new Set();
const targetStates = new Map();
const targetReportLimit = 36;
const lseByThread = new Map();
const mutationHookCounts = {replace: 0, replace_remove: 0, remove: 0, remove_or_phi: 0, lse: 0};
let lseTraceEmitted = 0;
const LSE_TRACE_LIMIT = 80;
let fieldMutationTraceEmitted = 0;
const FIELD_MUTATION_TRACE_LIMIT = 160;
function fieldKind(ptr) {
  try { return knownFieldVtables.get(ptr.readPointer().toString()) || null; }
  catch (_) { return null; }
}
function reportTargetEvent(state, event) {
  if (state.reported++ >= targetReportLimit) return;
  send(event);
  log('TARGET_IR ' + JSON.stringify(event));
}
const FIELD_VTABLE_SYMBOLS = [
  ['HInstanceFieldGet', '_ZTVN3art17HInstanceFieldGetE'],
  ['HInstanceFieldSet', '_ZTVN3art17HInstanceFieldSetE'],
  ['HStaticFieldGet', '_ZTVN3art15HStaticFieldGetE'],
  ['HStaticFieldSet', '_ZTVN3art15HStaticFieldSetE'],
  ['HUnresolvedInstanceFieldGet', '_ZTVN3art27HUnresolvedInstanceFieldGetE'],
  ['HUnresolvedInstanceFieldSet', '_ZTVN3art27HUnresolvedInstanceFieldSetE'],
  ['HUnresolvedStaticFieldGet', '_ZTVN3art25HUnresolvedStaticFieldGetE'],
  ['HUnresolvedStaticFieldSet', '_ZTVN3art25HUnresolvedStaticFieldSetE']
];
function sdkLevel() {
  try {
    const p = Process.getModuleByName('libc.so').findExportByName('__system_property_get');
    if (p === null) return NaN;
    const get = new NativeFunction(p, 'int', ['pointer', 'pointer']);
    const buf = Memory.alloc(128);
    const rc = get(Memory.allocUtf8String('ro.build.version.sdk'), buf);
    return rc > 0 ? Number(buf.readUtf8String()) : NaN;
  } catch (e) { log('sdk-error=' + e); return NaN; }
}
const NAMES = {
  internal: '_ZN3art3jit3Jit21CompileMethodInternalEPNS_9ArtMethodEPNS_6ThreadENS_15CompilationKindEb',
  publicCompile: '_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadENS_15CompilationKindEb',
  compiler: '_ZN3art3jit11JitCompiler13CompileMethodEPNS_6ThreadEPNS0_15JitMemoryRegionEPNS_9ArtMethodENS_15CompilationKindE',
  instance: '_ZN3art3jit3Jit13jit_compiler_E',
  buildGraph: '_ZN3art13HGraphBuilder10BuildGraphEv',
  runOptimizations: '_ZNK3art18OptimizingCompiler16RunOptimizationsEPNS_6HGraphEPNS_13CodeGeneratorERKNS_18DexCompilationUnitEPNS_12PassObserverE',
  graphAddBlock: '_ZN3art6HGraph8AddBlockEPNS_11HBasicBlockE',
  graphCheckerBlock: '_ZN3art12GraphChecker15VisitBasicBlockEPNS_11HBasicBlockE',
  // Ordinary graph visitor exports are stronger evidence of traversal
  // than GraphChecker, which is not necessarily run on release builds.
  graphVisitorBlock: '_ZN3art13HGraphVisitor15VisitBasicBlockEPNS_11HBasicBlockE',
  graphVisitorInsertion: '_ZN3art13HGraphVisitor19VisitInsertionOrderEv',
  graphVisitorRpo: '_ZN3art13HGraphVisitor21VisitReversePostOrderEv',
  // Candidate exported signatures from instruction_builder.cc. Only use if
  // this exact ELF symbol exists on the running device.
  fieldInstance: '_ZN3art19HInstructionBuilder24BuildInstanceFieldAccessERKNS_11InstructionEjb',
  fieldStatic: '_ZN3art19HInstructionBuilder22BuildStaticFieldAccessERKNS_11InstructionEjb',
  appendInstruction: '_ZN3art19HInstructionBuilder17AppendInstructionEPNS_12HInstructionE',
  addInstruction: '_ZN3art11HBasicBlock14AddInstructionEPNS_12HInstructionE',
  // ABI candidates; check exact runtime exports and archive matching ELF names.
  // All are read-only observers, no replacement or mutation is performed.
  replaceWith: '_ZN3art12HInstruction11ReplaceWithEPS0_',
  replaceAndRemove: '_ZN3art11HBasicBlock31ReplaceAndRemoveInstructionWithEPNS_12HInstructionES2_',
  removeInstruction: '_ZN3art11HBasicBlock17RemoveInstructionEPNS_12HInstructionEb',
  removeInstructionOrPhi: '_ZN3art11HBasicBlock22RemoveInstructionOrPhiEPNS_12HInstructionEb',
  x64LocationsFieldGet: '_ZN3art6x86_6422LocationsBuilderX86_6421VisitInstanceFieldGetEPNS_17HInstanceFieldGetE',
  x64LocationsFieldSet: '_ZN3art6x86_6422LocationsBuilderX86_6421VisitInstanceFieldSetEPNS_17HInstanceFieldSetE',
  x64EmitFieldGet: '_ZN3art6x86_6430InstructionCodeGeneratorX86_6421VisitInstanceFieldGetEPNS_17HInstanceFieldGetE',
  x64EmitFieldSet: '_ZN3art6x86_6430InstructionCodeGeneratorX86_6421VisitInstanceFieldSetEPNS_17HInstanceFieldSetE',
  lseRun: '_ZN3art20LoadStoreElimination3RunEv',
  lseRunBool: '_ZN3art20LoadStoreElimination3RunEb'
};
function getExport(module, exactName) {
  const address = module.findExportByName(exactName);
  return address === null ? null : {name: exactName, address};
}
// Passive P1: only the CI script can opt in to loading the exact shim.
// It contains no ART write API; invalid build IDs fail closed.
function loadPassiveShadow() {
  if (typeof globalThis.__artwatchShadowPath !== 'string' ||
      Process.arch !== 'x64') return;
  try {
    // Do not dlopen from Frida's namespace or from /data/local/tmp.
    // The Android app loads its own library via System.loadLibrary() first.
    const module = Process.findModuleByName(globalThis.__artwatchShadowPath);
    if (module === null) return;
    if (shadowModuleAttempted) return;
    shadowModuleAttempted = true;
    function exported(name, ret, args) {
      const address = module.findExportByName(name);
      if (address === null) throw new Error('missing native shadow export=' + name);
      return new NativeFunction(address, ret, args);
    }
    if (exported('artwatch_shadow_init','int',[])() !== 1) {
      send({type:'artwatch-shadow-init', ready:false,
        reason:'SDK or mapped ART ELF build-ID verification failed'});
      return;
    }
    shadowShim = {
      graph: exported('artwatch_shadow_graph','int',['pointer','pointer']),
      node: exported('artwatch_shadow_node','int',['pointer','pointer','int']),
      report: exported('artwatch_shadow_report','int',['pointer','uint']),
      scopeBegin: exported('artwatch_shadow_scope_begin','int',['pointer']),
      scopeEnd: exported('artwatch_shadow_scope_end','int',['pointer','uint']),
      block: exported('artwatch_shadow_block','int',['pointer','pointer','pointer'])
    };
    send({type:'artwatch-shadow-init',ready:true,source:'native',
      buildIdVerified:true,mutable:false});
    log('native-shadow=ready with verified ART build IDs');
  } catch(e) {
    log('native-shadow-load-error=' + (e.stack || e));
    send({type:'artwatch-shadow-init',ready:false,reason:String(e)});
  }
}
function reportPassiveShadow() {
  if (!shadowShim) return;
  try {
    const buf = Memory.alloc(384);
    if (shadowShim.report(buf, 384) !== 1) return;
    send({type:'artwatch-shadow-stats',...JSON.parse(buf.readUtf8String())});
  } catch(e) { log('native-shadow-report-error=' + e); }
}
function compilerViaVtable(runtime, compiler) {
  // This is an ABI-specific experiment, NOT a generic C++ vtable scanner.
  // In the AOSP JitCompilerInterface declaration, virtual ~JitCompilerInterface()
  // is followed by virtual CompileMethod(). For the Itanium C++ ABI used by
  // Android x86_64/arm64, the destructor occupies slots 0/1 and CompileMethod slot 2.
  const symbol = getExport(runtime, NAMES.instance);
  if (!symbol) { log('compiler-vtable=unavailable (jit_compiler_ not exported)'); return null; }
  try {
    const instance = symbol.address.readPointer(); // Existing compiler instance; NEVER call jit_load().
    if (instance.isNull()) { log('compiler-vtable=unavailable (instance null)'); return null; }
    const vtable = instance.readPointer();
    const vtableOwner = Process.findModuleByAddress(vtable);
    if (!vtableOwner || vtableOwner.name !== compiler.name) {
      log('compiler-vtable=rejected (vtable outside ' + compiler.name + ')');
      return null;
    }
    const fn = vtable.add(2 * Process.pointerSize).readPointer();
    const fnOwner = Process.findModuleByAddress(fn);
    if (!fnOwner || fnOwner.name !== compiler.name) {
      log('compiler-vtable=rejected (slot2 outside ' + compiler.name + ')');
      return null;
    }
    log('compiler-vtable instance=' + instance + ' vtable=' + vtable + ' slot2=' + fn);
    return {address: fn, name: 'JitCompilerInterface::CompileMethod [vtable slot2]',
      source: 'vtable-slot2'};
  } catch (e) { log('compiler-vtable-error=' + e); return null; }
}
function attach(layer, site) {
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        // x86_64/arm64 non-static member calls: args[0] is this.
        // Internal: (this, ArtMethod*, Thread*, CompilationKind, bool).
        // Compiler: (this, Thread*, JitMemoryRegion*, ArtMethod*, CompilationKind).
        this.method = (layer === 'compiler' ? args[3] : args[1]).toString();
        this.compilationKind = (layer === 'compiler' ? args[4] : args[3]).toInt32();
        this.ordinal = ++count[layer];
        if (layer === 'compiler') {
          this.nativeThread = this.threadId;
          this.previousCompilation = compiling.get(this.nativeThread);
          this.previousTargetState = targetStates.get(this.nativeThread);
          this.mutationCountsAtEnter = {...mutationHookCounts};
          targetStates.set(this.nativeThread, {
            method: this.method, kind: this.compilationKind,
            seenVisits: new Set(), seenKinds: new Set(), uniqueNodes: new Set(),
            visitsByPhase: {}, mutations: [], reported: 0,
            optimizationEntries: 0, lseInvocations: 0,
            backendLocations: new Set(), backendEmitted: new Set(),
            constructionGraph: null, constructedBlocks: new Set(),
            checkerBlocks: new Set(), visitorBlocks: new Set(),
            visitorBlocksUnknown: new Set(),
            visitorFieldNodes: new Map(), visitorFieldPairs: new Map(),
            visitorFieldVisits: 0, visitorFieldGetVisits: 0,
            visitorFieldSetVisits: 0, visitorPointerMismatch: 0,
            blockVisitOrdinal: 0, fieldPassesObserved: 0,
            fieldVisitOrderSamples: [], fieldOrderTruncated: 0,
            blockInstructionMap: new Map(), fieldNodeInserts: 0,
            graphAddInstructionCalls: 0, fieldVisitBlockMatches: 0,
            unmatchedBlockCalls: 0
          });
          compiling.set(this.nativeThread, {method: this.method, kind: this.compilationKind});
          builtByThread.delete(this.nativeThread);
        }
        if (this.ordinal <= SAMPLE_LIMIT)
          log('JIT enter layer=' + layer + ' method=' + this.method +
              ' kind=' + this.compilationKind);
      },
      onLeave(ret) {
        if (layer === 'compiler') {
          const state = targetStates.get(this.nativeThread);
          if (state && targetMethodPointers.has(this.method)) {
            send({type: 'artwatch-target-summary',
              method: this.method, compilationKind: this.compilationKind,
              kinds: [...state.seenKinds].sort(),
              uniqueNodeCount: state.uniqueNodes.size,
              visitsByPhase: state.visitsByPhase,
              mutations: state.mutations,
              locationsNodes: [...state.backendLocations],
              codeEmittedNodes: [...state.backendEmitted],
              compilationSucceeded: ret.toInt32() !== 0
            });
            log('TARGET_SUMMARY method=' + this.method + ' kind=' +
                this.compilationKind + ' nodes=' + state.uniqueNodes.size +
                ' kinds=' + [...state.seenKinds].join(',') +
                ' mutations=' + state.mutations.length);
          }
          // Validate elimination on the same compilation and exact node.
          // Only string identities are retained; node memory is never dereferenced
          // after removal or after the JIT compilation returns.
          if (state && targetMethodPointers.has(this.method) && state.mutations.length) {
            const lifecycleByNode = new Map();
            for (const mutation of state.mutations) {
              if (!mutation.duringLse) continue;
              const identity = mutation.kind + '@' + mutation.node;
              let entry = lifecycleByNode.get(identity);
              if (!entry) {
                entry = {kind: mutation.kind, node: mutation.node,
                  operations: [], replacement: null,
                  visitedBeforeMutation: false};
                lifecycleByNode.set(identity, entry);
              }
              entry.operations.push(mutation.op);
              entry.visitedBeforeMutation ||= mutation.visitedBeforeMutation === true;
              if (mutation.op === 'replace') {
                entry.replacement = mutation.substitute;
                entry.replacementKind = mutation.substituteKind;
              }
            }
            const entries = Array.from(lifecycleByNode.values()).map(entry => {
              const identity = entry.kind + '@' + entry.node;
              // Historical evidence from actual ART block visitor
              // callbacks, joined by exact instruction pointer. A node
              // can be moved between blocks by optimizer passes; this
              // does not claim a live GetBlock() after removal.
              const observedBlocks = [];
              for (const pair of state.visitorFieldPairs.values()) {
                if (pair.kind === entry.kind && pair.node === entry.node) {
                  observedBlocks.push({
                    block: pair.block, visits: pair.visits,
                    constructed: pair.constructed
                  });
                }
              }
              return {...entry, observedBlocks,
                lowered: state.backendLocations.has(identity),
                emitted: state.backendEmitted.has(identity)};
            });
            if (entries.length) {
              const event = {type: 'artwatch-field-lifecycle',
                method: this.method, compilationKind: this.compilationKind,
                compilationSucceeded: ret.toInt32() !== 0,
                entries};
              send(event);
              log('FIELD_LIFECYCLE ' + JSON.stringify(event));
            }
          }
          if (state && this.ordinal <= SAMPLE_LIMIT) {
            const mutationCallDeltas = {};
            for (const [op, value] of Object.entries(mutationHookCounts)) {
              mutationCallDeltas[op] = value - (this.mutationCountsAtEnter[op] || 0);
            }
            send({type: 'artwatch-mutation-call-summary', method:this.method,
              compilationKind:this.compilationKind, calls:mutationCallDeltas});
            send({type: 'artwatch-phase-summary', method: this.method,
              compilationKind: this.compilationKind,
              isFieldTarget: targetMethodPointers.has(this.method),
              optimizationEntries: state.optimizationEntries,
              lseInvocations: state.lseInvocations,
              success: ret.toInt32() !== 0});
          }
          if (shadowShim && this.ordinal <= SAMPLE_LIMIT) reportPassiveShadow();
          if (this.previousTargetState) targetStates.set(this.nativeThread, this.previousTargetState);
          else targetStates.delete(this.nativeThread);
          if (this.previousCompilation) compiling.set(this.nativeThread, this.previousCompilation);
          else compiling.delete(this.nativeThread);
          builtByThread.delete(this.nativeThread);
        }
        const event = {type: 'artwatch-jit', layer, method: this.method,
          kind: this.compilationKind, success: ret.toInt32() !== 0,
          ordinal: this.ordinal};
        if (this.ordinal <= SAMPLE_LIMIT) {
          send(event);
          log('JIT leave ' + JSON.stringify(event));
        }
      }
    });
    log('Attached compilation observer: ' + layer + ' via=' + site.source +
      ' at=' + site.address + ' name=' + site.name);
    send({type: 'artwatch-hook-attached', layer, source: site.source, address: site.address.toString()});
    return true;
  } catch (e) {
    log('JIT hook failed for ' + layer + ': ' + (e.stack || e));
    return false;
  }
}
// API 33 x86_64 only. Exact exported symbols were confirmed by readelf
// on the emulator binary. Observe graph identities; never mutate ART memory.
function attachGraphBoundary(layer, site) {
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        this.nativeThread = this.threadId;
        this.ordinal = ++count[layer];
        const active = compiling.get(this.nativeThread);
        this.method = active ? active.method : null;
        this.kind = active ? active.kind : null;
        if (layer === 'graph_builder') {
          this.builder = args[0].toString();
          // AOSP HGraphBuilder derives from ValueObject and its first member is
          // graph_. This is an ABI-specific C++ layout hypothesis to validate.
          try { this.graphCandidate = args[0].readPointer().toString(); }
          catch (_) { this.graphCandidate = null; }
          this.previousGraphBuild = activeGraphBuild.get(this.nativeThread);
          activeGraphBuild.set(this.nativeThread, this.graphCandidate);
          const state = targetStates.get(this.nativeThread);
          if (state) state.constructionGraph = this.graphCandidate;
        } else {
          if (!shadowShim) loadPassiveShadow();
          // const OptimizingCompiler* this, HGraph*, CodeGenerator*, ...
          this.previousOptimization = optimizationByThread.get(this.nativeThread);
          optimizationByThread.set(this.nativeThread, args[1].toString());
          const state = targetStates.get(this.nativeThread);
          if (state) state.optimizationEntries++;
          this.graph = args[1].toString();
          const previous = builtByThread.get(this.nativeThread);
          const matches = previous && previous.graphCandidate !== null
            ? previous.graphCandidate === this.graph : null;
          if (state && matches === true) {
            const observation = {type:'artwatch-block-discovery',
              method:this.method,compilationKind:this.kind,thread:this.nativeThread,
              graph:this.graph,source:'HGraph::AddBlock',
              uniqueBlocks:state.constructedBlocks.size,
              unmatched:state.unmatchedBlockCalls,
              samples:[...state.constructedBlocks].slice(0,12)};
            send(observation);
            if (this.ordinal <= SAMPLE_LIMIT)
              log('BLOCK_DISCOVERY ' + JSON.stringify(observation));
          }
          if (state && matches === true) {
            const event = {type:'artwatch-block-instruction-evidence',
              method:this.method,compilationKind:this.kind,thread:this.nativeThread,
              graph:this.graph,
              addInstructionCalls:state.graphAddInstructionCalls,
              fieldNodeInserts:state.fieldNodeInserts,
              mappedFieldNodes:state.blockInstructionMap.size,
              mappedExamples:[...state.blockInstructionMap.entries()].slice(0,8)};
            send(event);
            if (this.ordinal <= SAMPLE_LIMIT)
              log('BLOCK_INSTRUCTIONS ' + JSON.stringify(event));
          }
          this.shadowScopeStarted = false;
          if (shadowShim && matches === true) {
            try {
              const range = Process.findRangeByAddress(args[1]);
              if (range && range.protection.includes('r') &&
                  shadowShim.graph(args[1], ptr(previous.graphCandidate)) === 1) {
                this.shadowScopeStarted = shadowShim.scopeBegin(args[1]) === 1;
                if (!this.shadowScopeStarted)
                  log('native-shadow-scope-start-rejected graph=' + this.graph);
                if (shadowGraphLogged++ < 14)
                  send({type:'artwatch-shadow-graph',method:this.method,
                    graph:this.graph,matched:true});
              }
            } catch(e) { log('native-shadow-graph-error=' + e); }
          }
          const event = {type: 'artwatch-graph', phase: 'pre-opt',
            ordinal: this.ordinal, thread: this.nativeThread,
            method: this.method, kind: this.kind, graph: this.graph,
            builderGraph: previous ? previous.graphCandidate : null,
            graphMatchesBuilder: matches};
          if (this.ordinal <= SAMPLE_LIMIT) {
            send(event);
            log('GRAPH ' + JSON.stringify(event));
          }
        }
      },
      onLeave(_retval) {
        if (layer === 'pre_opt') {
          const state = targetStates.get(this.nativeThread);
          if (state && state.visitorBlocks.size > 0) {
            const orderEvent = {type:'artwatch-field-visit-order',
              method:this.method,compilationKind:this.kind,
              thread:this.nativeThread,graph:this.graph,
              visitedBlockCalls:state.blockVisitOrdinal,
              passesWithFields:state.fieldPassesObserved,
              passesCaptured:state.fieldVisitOrderSamples.length,
              truncatedFieldEntries:state.fieldOrderTruncated,
              passes:state.fieldVisitOrderSamples};
            send(orderEvent);
            if (this.ordinal <= SAMPLE_LIMIT)
              log('FIELD_VISIT_ORDER ' + JSON.stringify({
                ...orderEvent,passes:orderEvent.passes.slice(0,3)}));
            const fieldExamples = [...state.visitorFieldPairs.values()].slice(0,24);
            const blockFieldEvent = {type:'artwatch-field-block-ownership',
              method:this.method,compilationKind:this.kind,
              thread:this.nativeThread,graph:this.graph,
              correlatedVisits:state.visitorFieldVisits,
              getVisits:state.visitorFieldGetVisits,
              setVisits:state.visitorFieldSetVisits,
              uniqueFieldNodes:state.visitorFieldNodes.size,
              uniqueFieldBlockPairs:state.visitorFieldPairs.size,
              visitorPointerMismatches:state.visitorPointerMismatch,
              examples:fieldExamples};
            send(blockFieldEvent);
            if (this.ordinal <= SAMPLE_LIMIT)
              log('FIELD_BLOCK_OWNERSHIP ' + JSON.stringify(blockFieldEvent));
            const event = {type:'artwatch-block-visitor',
              method:this.method,compilationKind:this.kind,thread:this.nativeThread,
              graph:this.graph,uniqueBlocks:state.visitorBlocks.size,
              newlySeenBlocks:state.visitorBlocksUnknown.size,
              fieldVisitBlockMatches:state.fieldVisitBlockMatches,
              samples:[...state.visitorBlocks].slice(0,12)};
            send(event);
            if (this.ordinal <= SAMPLE_LIMIT)
              log('BLOCK_VISITOR ' + JSON.stringify(event));
          }
          if (state && state.checkerBlocks.size > 0) {
            const event = {type:'artwatch-block-checker',
              method:this.method,compilationKind:this.kind,thread:this.nativeThread,
              graph:this.graph,uniqueBlocks:state.checkerBlocks.size,
              samples:[...state.checkerBlocks].slice(0,12)};
            send(event);
            if (this.ordinal <= SAMPLE_LIMIT)
              log('BLOCK_CHECKER ' + JSON.stringify(event));
          }
          if (this.shadowScopeStarted && shadowShim) {
            try {
              const buffer = Memory.alloc(512);
              if (shadowShim.scopeEnd(buffer, 512) === 1) {
                const result = JSON.parse(buffer.readUtf8String());
                const event = {type:'artwatch-shadow-scope',
                  method:this.method,compilationKind:this.kind,
                  thread:this.nativeThread, ...result};
                send(event);
                if (this.ordinal <= SAMPLE_LIMIT)
                  log('SHADOW_SCOPE ' + JSON.stringify(event));
              } else {
                log('native-shadow-scope-end-rejected method=' + this.method);
              }
            } catch(e) { log('native-shadow-scope-error=' + e); }
          }
          if (this.previousOptimization === undefined) optimizationByThread.delete(this.nativeThread);
          else optimizationByThread.set(this.nativeThread, this.previousOptimization);
          return;
        }
        if (layer !== 'graph_builder') return;
        if (this.previousGraphBuild === undefined) activeGraphBuild.delete(this.nativeThread);
        else activeGraphBuild.set(this.nativeThread, this.previousGraphBuild);
        builtByThread.set(this.nativeThread, {graphCandidate: this.graphCandidate});
        const event = {type: 'artwatch-graph', phase: 'build-complete',
          ordinal: this.ordinal, thread: this.nativeThread,
          method: this.method, kind: this.kind, builder: this.builder,
          graphCandidate: this.graphCandidate};
        if (this.ordinal <= SAMPLE_LIMIT) {
          send(event);
          log('GRAPH ' + JSON.stringify(event));
        }
      }
    });
    log('Attached graph observer: ' + layer + ' via=export at=' + site.address);
    send({type: 'artwatch-hook-attached', layer, source: 'export',
      address: site.address.toString()});
    return true;
  } catch (e) {
    log('Graph hook failed for ' + layer + ': ' + (e.stack || e));
    return false;
  }
}
// Source-backed and optional read-only graph/block function hooks.
 // The two entry points are probes, not required compiler ABI exports.
function attachBlockBoundary(layer, site) {
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        const thread = this.threadId;
        const state = targetStates.get(thread);
        if (!state || !compiling.has(thread)) return;
        if (layer === 'graph_add_block') {
          const graph = args[0].toString();
          const candidate = state.constructionGraph;
          if (candidate === null || graph !== candidate) {
            state.unmatchedBlockCalls++;
            return;
          }
          const block = args[1];
          if (block.isNull() || !Process.findRangeByAddress(block)) return;
          if (!shadowShim) loadPassiveShadow();
          if (shadowShim && shadowShim.block(args[0], ptr(candidate), block) !== 1) {
            log('native-shadow-block-validation-rejected');
            return;
          }
          if (state.constructedBlocks.size < 4096)
            state.constructedBlocks.add(block.toString());
        } else {
          if (!optimizationByThread.has(thread)) return;
          const block = args[1];
          if (block.isNull() || !Process.findRangeByAddress(block)) return;
          if (layer === 'graph_checker_block') {
            if (state.checkerBlocks.size < 4096)
              state.checkerBlocks.add(block.toString());
          } else {
            // Keep the active visitor+block pair only for the dynamic
            // extent of this exact HGraphVisitor::VisitBasicBlock call.
            // Frida onLeave restores nested calls without leaking state.
            this.visitorBlockThread = thread;
            this.previousVisitorBlock = activeVisitorBlockByThread.get(thread);
            this.visitorBlockActive = true;
            this.visitorBlockRecord = {
              visitor: args[0].toString(), block: block.toString(),
              callOrdinal: ++state.blockVisitOrdinal,
              fieldCount: 0, fields: []
            };
            activeVisitorBlockByThread.set(thread,this.visitorBlockRecord);
            if (state.visitorBlocks.size < 4096)
              state.visitorBlocks.add(block.toString());
            // Inlining or loop transformations can add blocks after the
            // construction boundary; log them, do not assume corruption.
            if (!state.constructedBlocks.has(block.toString()) &&
                state.visitorBlocksUnknown.size < 4096)
              state.visitorBlocksUnknown.add(block.toString());
          }
        }
      },
      onLeave() {
        if (this.visitorBlockActive !== true) return;
        const state = targetStates.get(this.visitorBlockThread);
        const sample = this.visitorBlockRecord;
        if (state && sample && sample.fieldCount > 0) {
          state.fieldPassesObserved++;
          if (state.fieldVisitOrderSamples.length < MAX_FIELD_PASSES) {
            state.fieldVisitOrderSamples.push({
              block:sample.block, visitor:sample.visitor,
              callOrdinal:sample.callOrdinal,
              fieldCount:sample.fieldCount,fields:sample.fields,
              constructed:state.constructedBlocks.has(sample.block)
            });
          }
        }
        if (this.previousVisitorBlock === undefined)
          activeVisitorBlockByThread.delete(this.visitorBlockThread);
        else
          activeVisitorBlockByThread.set(this.visitorBlockThread,
            this.previousVisitorBlock);
      }
    });
    send({type:'artwatch-hook-attached',layer,source:'export',
      address:site.address.toString()});
    log('Attached read-only block boundary=' + layer + ' at=' + site.address);
    return true;
  } catch(e) {
    log('block-boundary-attach-error=' + layer + ' ' + (e.stack || e));
    return false;
  }
}
// Observe DEX field operations as the compiler builds their IR.
// This does NOT identify HInstanceFieldGet/HInstanceFieldSet objects yet.
// It only provides a pre-optimization DEX PC + access-direction signal.
function attachFieldBuilder(access, site) {
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        const thread = this.threadId;
        const active = compiling.get(thread);
        if (!active) return;
        const ordinal = ++fieldCounts[access];
        this.fieldThread = thread;
        this.previousFieldBuilder = activeFieldBuilder.get(thread);
        this.hasFieldBuilder = true;
        const instruction = args[1];
        let opcode = null;
        let fieldIndexRaw = null;
        try {
          // DEX formats 22c (iget/iput) and 21c (sget/sput):
          // opcode is byte 0; the two-byte C/B index occupies code unit 1.
          opcode = instruction.readU8();
          fieldIndexRaw = instruction.add(2).readU16();
        } catch (e) {
          log('field-instruction-read-failed=' + e);
        }
        const event = {type: 'artwatch-field-build', access,
          method: active.method, compilationKind: active.kind, thread,
          graphCandidate: activeGraphBuild.get(thread) || null,
          dexPc: args[2].toUInt32(), isPut: args[3].toInt32() !== 0,
          opcode, fieldIndexRaw, ordinal};
        activeFieldBuilder.set(thread, {...event, builder: args[0].toString()});
        // Identify self-contained field read/write methods from DEX patterns,
        // not only the old iput@0/iget@2 pattern. The release fixture adds
        // identity(this) between iput and iget so both survive D8.
        if (access === 'instance' && fieldIndexRaw !== null &&
            (opcode === 0x59 || opcode === 0x52)) {
          let byField = targetDexByMethod.get(active.method);
          if (!byField) {
            byField = new Map();
            targetDexByMethod.set(active.method, byField);
          }
          const prior = byField.get(fieldIndexRaw) || {bits: 0, putPc: null, getPc: null};
          const updated = {
            bits: prior.bits | (opcode === 0x59 ? 1 : 2),
            putPc: opcode === 0x59 ? event.dexPc : prior.putPc,
            getPc: opcode === 0x52 ? event.dexPc : prior.getPc
          };
          byField.set(fieldIndexRaw, updated);
          if (updated.bits === 3 && !targetMethodPointers.has(active.method)) {
            targetMethodPointers.add(active.method);
            const identified = {type: 'artwatch-target-dex',
              method: active.method, fieldIndexRaw,
              dexPattern: 'iput+iget,same-field-index',
              putPc: updated.putPc, getPc: updated.getPc};
            send(identified);
            log('TARGET_DEX ' + JSON.stringify(identified));
          }
        }
        if (ordinal <= FIELD_SAMPLE_LIMIT) {
          send(event);
          log('FIELD_BUILD ' + JSON.stringify(event));
        }
      },
      onLeave(_ret) {
        if (!this.hasFieldBuilder) return;
        if (this.previousFieldBuilder === undefined) activeFieldBuilder.delete(this.fieldThread);
        else activeFieldBuilder.set(this.fieldThread, this.previousFieldBuilder);
      }
    });
    log('Attached field-builder observer: ' + access + ' at=' + site.address);
    send({type: 'artwatch-hook-attached', layer: 'field_' + access,
      source: 'export', address: site.address.toString()});
    return true;
  } catch (e) {
    log('field-builder-hook-error=' + access + ': ' + (e.stack || e));
    return false;
  }
}
// Itanium C++ ABI: a complete-object vptr normally points 2 words past
// its exported primary vtable symbol. This is a candidate ABI mapping,
// validated by observed matches; not an assumed type ID or a layout parser.
function discoverFieldVtables(compiler) {
  for (const [kind, symbol] of FIELD_VTABLE_SYMBOLS) {
    const site = getExport(compiler, symbol);
    if (site === null) {
      log('field-vtable-not-exported=' + kind);
      continue;
    }
    const addressPoint = site.address.add(2 * Process.pointerSize).toString();
    knownFieldVtables.set(addressPoint, kind);
    log('field-vtable=' + kind + ' addressPoint=' + addressPoint);
  }
  send({type: 'artwatch-ir-vtables', available: Array.from(knownFieldVtables.values())});
}
// The HInstructionBuilder::AppendInstruction argument is a constructed
// HInstruction*. HBasicBlock::AddInstruction is a version-specific fallback.
// Capture it only within active field-building calls and never mutate it.
function attachFieldNodeCandidate(site, source) {
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        const thread = this.threadId;
        insertionCounts[source]++;
        // Independent out-of-line AddInstruction experiment. This call
        // supplies HBasicBlock* and HInstruction* without decoding either.
        // The original field-builder-context experiment remains below.
        if (source === 'basic-block') {
          const state = targetStates.get(thread);
          const block = args[0].toString();
          if (state && state.constructedBlocks.has(block)) {
            state.graphAddInstructionCalls++;
            const kind = fieldKind(args[1]);
            if (kind !== null && /Field(Get|Set)$/.test(kind)) {
              state.fieldNodeInserts++;
              if (state.blockInstructionMap.size < 4096)
                state.blockInstructionMap.set(kind + '@' + args[1].toString(), block);
            }
          }
        }
        const field = activeFieldBuilder.get(thread);
        if (!field) return;
        if (source === 'append' && args[0].toString() !== field.builder) return;
        const node = args[1].toString();
        // An append forwarding into AddInstruction is one logical insertion.
        if (!field.seenNodes) field.seenNodes = new Set();
        if (field.seenNodes.has(node)) return;
        field.seenNodes.add(node);
        const ordinal = ++observedFieldNodeCandidates;
        if (ordinal > FIELD_NODE_SAMPLE_LIMIT) return;
        let vtable = null;
        let kind = null;
        try {
          vtable = args[1].readPointer().toString();
          kind = knownFieldVtables.get(vtable) || null;
        } catch (e) {
          log('field-node-vtable-read-failed=' + e);
        }
        const event = {type: 'artwatch-ir-node', source,
          access: field.access, isPut: field.isPut, fieldIndexRaw: field.fieldIndexRaw,
          dexPc: field.dexPc, opcode: field.opcode, graphCandidate: field.graphCandidate,
          method: field.method, compilationKind: field.compilationKind,
          thread, ordinal, node, vtable, kind};
        send(event);
        log('IR_NODE ' + JSON.stringify(event));
      }
    });
    log('Attached field IR append observer via=' + source + ' at=' + site.address);
    send({type: 'artwatch-hook-attached', layer: 'ir_append',
      source, address: site.address.toString()});
    return true;
  } catch (e) {
    log('field-node-hook-error=' + source + ': ' + (e.stack || e));
    return false;
  }
}
// Every HInstruction field subclass has a virtual Accept(HGraphVisitor*).
// On this API 33 ELF some of those functions are exported even when the
// builder's call to AppendInstruction has been inlined into its caller.
// These are observation-only callbacks during normal ART visitor passes.
function attachFieldAccept(compiler) {
  let attached = 0;
  for (const [kind, symbol] of FIELD_VTABLE_SYMBOLS) {
    const acceptName = symbol.replace('_ZTVN', '_ZN').replace(/E$/, '6AcceptEPNS_13HGraphVisitorE');
    const site = getExport(compiler, acceptName);
    if (!site) {
      log('field-accept-not-exported=' + kind);
      continue;
    }
    try {
      Interceptor.attach(site.address, {
        onEnter(args) {
          const thread = this.threadId;
          const compilation = compiling.get(thread);
          if (!compilation) return;
          const ordinal = ++observedFieldAccepts;
          const node = args[0].toString();
          const visitor = args[1].toString();
          let vtable = null;
          try { vtable = args[0].readPointer().toString(); }
          catch (e) { log('field-accept-vtable-read-failed=' + e); }
          const inferred = vtable ? knownFieldVtables.get(vtable) || null : null;
          if (!shadowShim) loadPassiveShadow();
          if (shadowShim && inferred === kind &&
              (kind === 'HInstanceFieldGet' || kind === 'HInstanceFieldSet')) {
            try {
              const vt = getExport(compiler, symbol);
              if (vt && shadowShim.node(args[0], vt.address,
                  kind === 'HInstanceFieldGet' ? 1 : 2) === 1 &&
                  shadowNodeLogged++ < 16) {
                send({type:'artwatch-shadow-node',kind,node,thread,
                  method:compilation.method,compilationKind:compilation.kind});
              }
            } catch(e) { log('native-shadow-node-error=' + e); }
          }
          const phase = optimizationByThread.has(thread) ? 'optimizing' :
            (activeGraphBuild.has(thread) ? 'building' : 'other');
          // Join a vtable-confirmed instruction with its containing block
          // only when a real AddInstruction callback supplied both pointers.
          const blockState = targetStates.get(thread);
          if (blockState &&
              blockState.blockInstructionMap.has(kind + '@' + node)) {
            blockState.fieldVisitBlockMatches++;
          }
          // ART's source-backed VisitBasicBlock iterates the instruction
          // list and invokes instruction->Accept(this). Match the actual
          // visitor object (args[1]) rather than guessing HInstruction
          // block_ offsets. This is only a *visited* block ownership record,
          // not construction-time insertion or a stable post-pass layout.
          const currentBlock = activeVisitorBlockByThread.get(thread);
          if (blockState && currentBlock &&
              phase === 'optimizing' && inferred === kind) {
            if (currentBlock.visitor === visitor) {
              const isGet = /FieldGet$/.test(kind);
              const isSet = /FieldSet$/.test(kind);
              if (isGet || isSet) {
                // Captures only relative order of *field* instructions
                // encountered by one real VisitBasicBlock traversal.
                // Other IR instructions and phi nodes are omitted.
                const position = currentBlock.fieldCount++;
                if (currentBlock.fields.length < MAX_FIELDS_PER_PASS) {
                  currentBlock.fields.push({kind,node,ordinal:position});
                } else {
                  blockState.fieldOrderTruncated++;
                }
                const id = kind + '@' + node;
                const pairId = id + '|block=' + currentBlock.block;
                blockState.visitorFieldVisits++;
                if (isGet) blockState.visitorFieldGetVisits++;
                if (isSet) blockState.visitorFieldSetVisits++;
                if (blockState.visitorFieldNodes.size < 4096 &&
                    !blockState.visitorFieldNodes.has(id))
                  blockState.visitorFieldNodes.set(id, currentBlock.block);
                if (blockState.visitorFieldPairs.size < 4096) {
                  const existing = blockState.visitorFieldPairs.get(pairId);
                  if (existing) existing.visits++;
                  else blockState.visitorFieldPairs.set(pairId, {
                    kind,node,block:currentBlock.block,visits:1,
                    constructed: blockState.constructedBlocks.has(currentBlock.block)
                  });
                }
              }
            } else {
              blockState.visitorPointerMismatch++;
            }
          }
          if (targetMethodPointers.has(compilation.method)) {
            const state = targetStates.get(thread);
            if (state) {
              state.seenKinds.add(kind);
              state.uniqueNodes.add(kind + '@' + node);
              const key = kind + '@' + node + '/' + phase;
              if (!state.seenVisits.has(key)) {
                state.seenVisits.add(key);
                state.visitsByPhase[phase] = (state.visitsByPhase[phase] || 0) + 1;
                reportTargetEvent(state, {type:'artwatch-target-ir',
                  kind, node, phase, method: compilation.method,
                  compilationKind: compilation.kind, thread,
                  vtableMatches: inferred === kind});
              }
            }
          }
          if (ordinal > FIELD_NODE_SAMPLE_LIMIT) return;
          const event = {type: 'artwatch-ir-visit', source: 'accept',
            ordinal, kind, vtableKind: inferred, vtableMatches: inferred === kind,
            node, vtable, visitor, thread, method: compilation.method,
            compilationKind: compilation.kind,
            phase};
          send(event);
          log('IR_VISIT ' + JSON.stringify(event));
        }
      });
      attached++;
      log('Attached field Accept observer kind=' + kind + ' at=' + site.address);
      send({type: 'artwatch-hook-attached', layer: 'ir_accept', kind,
        source: 'export', address: site.address.toString()});
    } catch (e) { log('field-accept-hook-error=' + kind + ': ' + e); }
  }
  log('field-accept-hooks=' + attached);
}
// Candidate mutation boundaries. Only inspect a field node's vptr on an
// active JIT thread, and never call ReplaceWith/RemoveInstruction ourselves.
function attachMutationObserver(site, op) {
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        const thread = this.threadId;
        const compilation = compiling.get(thread);
        const state = targetStates.get(thread);
        if (!compilation || !state) return;
        mutationHookCounts[op]++;
        if (op === 'lse') {
          this.lseThread = thread;
          this.lseMethod = compilation.method;
          this.lseKind = compilation.kind;
          this.lsePrevious = lseByThread.get(thread);
          lseByThread.set(thread, true);
          state.lseInvocations++;
          this.lseReport = lseTraceEmitted++ < LSE_TRACE_LIMIT;
          if (this.lseReport) {
            const event = {type:'artwatch-lse', phase:'enter',
              method:compilation.method, compilationKind:compilation.kind,
              thread, isFieldTarget:targetMethodPointers.has(compilation.method),
              partialMode: args[1].toInt32() !== 0};
            send(event);
            log('LSE ' + JSON.stringify(event));
          }
          if (targetMethodPointers.has(compilation.method)) {
            reportTargetEvent(state, {type:'artwatch-target-lse-enter',
              method:compilation.method, compilationKind:compilation.kind,
              thread});
          }
          return;
        }
        // Observe all field instructions, not just a fixture method whose
        // redundant load may already have disappeared in release DEX.
        const instruction = op === 'replace' ? args[0] : args[1];
        const kind = fieldKind(instruction);
        if (!kind) return;
        const replacement = op === 'replace' ? args[1] :
          (op === 'replace_remove' ? args[2] : null);
        const record = {op, kind, node: instruction.toString(),
          substitute: replacement === null ? null : replacement.toString(),
          substituteKind: replacement === null ? null : classifySSAValue(replacement),
          duringLse: lseByThread.has(thread),
          duringOptimizations: optimizationByThread.has(thread),
          visitedBeforeMutation: targetMethodPointers.has(compilation.method)
            ? state.uniqueNodes.has(kind + '@' + instruction.toString()) : null};
        if (fieldMutationTraceEmitted++ < FIELD_MUTATION_TRACE_LIMIT) {
          const event = {type:'artwatch-field-ir-mutation',
            method:compilation.method, compilationKind:compilation.kind,
            thread, isFieldTarget:targetMethodPointers.has(compilation.method),
            ...record};
          send(event);
          log('FIELD_MUTATION ' + JSON.stringify(event));
        }
        if (targetMethodPointers.has(compilation.method)) {
          state.mutations.push(record);
          reportTargetEvent(state, {type:'artwatch-ir-mutation',
            method:compilation.method, compilationKind:compilation.kind,
            thread, ...record});
        }
      },
      onLeave(retval) {
        if (op !== 'lse' || this.lseThread === undefined) return;
        if (this.lseReport) {
          const event = {type:'artwatch-lse', phase:'exit',
            method:this.lseMethod, compilationKind:this.lseKind,
            thread:this.lseThread, result:retval.and(0xff).toInt32() !== 0};
          send(event);
          log('LSE ' + JSON.stringify(event));
        }
        if (this.lsePrevious === undefined) lseByThread.delete(this.lseThread);
        else lseByThread.set(this.lseThread, this.lsePrevious);
      }
    });
    log('Attached mutation observer=' + op + ' at=' + site.address);
    send({type:'artwatch-hook-attached',layer:'ir_mutation_' + op,
      source:'export',address:site.address.toString()});
    return true;
  } catch (e) { log('mutation-observer-error=' + op + ': ' + e); return false; }
}
// ART x86_64 backend visitors receive a concrete field HInstruction*.
 // LocationsBuilder runs after IR optimizations; InstructionCodeGenerator
 // emits machine instructions for the surviving nodes. This is a
 // read-only estimate of which field nodes reach the lowering boundary.
function attachBackendFieldVisitor(compiler, symbol, stage, expectedKind) {
  const site = getExport(compiler, symbol);
  if (!site) {
    log('backend-field-export-not-found stage=' + stage + ' kind=' + expectedKind);
    return false;
  }
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        const thread = this.threadId;
        const active = compiling.get(thread);
        if (!active) return;
        const node = args[1].toString();
        const observedKind = fieldKind(args[1]);
        if (observedKind !== expectedKind) {
          log('backend-kind-mismatch expected=' + expectedKind +
              ' observed=' + observedKind);
          return;
        }
        const state = targetStates.get(thread);
        if (state) {
          const key = expectedKind + '@' + node;
          if (stage === 'locations') state.backendLocations.add(key);
          else state.backendEmitted.add(key);
        }
        backendCounts[stage]++;
        const ordinal = ++backendVisitOrdinal;
        if (ordinal > BACKEND_VISIT_LIMIT) return;
        const event = {type: 'artwatch-backend-field',
          stage, expectedKind, node, ordinal, thread,
          method: active.method, compilationKind: active.kind,
          isFieldTarget: targetMethodPointers.has(active.method)};
        send(event);
        log('BACKEND_FIELD ' + JSON.stringify(event));
      }
    });
    send({type:'artwatch-hook-attached',layer:'backend_field_' + stage,
      kind:expectedKind,source:'export',address:site.address.toString()});
    log('Attached backend field=' + stage + ' kind=' + expectedKind +
        ' at=' + site.address);
    return true;
  } catch (e) {
    log('backend-field-hook-error=' + stage + ' ' + expectedKind + ': ' + e);
    return false;
  }
}
function attachExistingInvokeObserver(compiler) {
  const site = getExport(compiler, INVOKE_ACCEPT);
  const vt = getExport(compiler, INVOKE_VTABLE);
  send({type:'artwatch-existing-invoke-abi',acceptExported:site !== null,
    vtableExported:vt !== null,writesArtMemory:false});
  if (!site || !vt) return false;
  const expected = vt.address.add(2 * Process.pointerSize);
  try {
    Interceptor.attach(site.address, {
      onEnter(args) {
        const thread = this.threadId;
        const active = compiling.get(thread);
        if (!active) return;
        try {
          if (!args[0].readPointer().equals(expected)) return;
        } catch (_) { return; }
        const scope = activeVisitorBlockByThread.get(thread);
        const ordinal = ++existingInvokeCount;
        if (ordinal > MAX_EXISTING_INVOKES) return;
        send({type:'artwatch-existing-invoke',node:args[0].toString(),
          method:active.method,compilationKind:active.kind,thread,ordinal,
          inOptimization:optimizationByThread.has(thread),
          block:scope && scope.visitor === args[1].toString()
            ? scope.block : null});
      }
    });
    send({type:'artwatch-hook-attached',layer:'existing_invoke_accept',
      source:'export',address:site.address.toString()});
    return true;
  } catch(e) {
    log('existing-invoke-hook-error=' + e);
    return false;
  }
}
function main() {
  const api = sdkLevel();
  log('pid=' + Process.id + ' arch=' + Process.arch +
      ' pointerSize=' + Process.pointerSize + ' api=' + api);
  const modules = Process.enumerateModules().filter(m => artLibraries.has(m.name));
  for (const module of modules) {
    log('module=' + module.name + ' base=' + module.base + ' path=' + module.path);
    // Targeted export lookup avoids potentially fragile full export-table scans
    // in injected processes (especially API 33 in earlier CI attempts).
    for (const name of [NAMES.internal, NAMES.publicCompile,
                        NAMES.compiler, NAMES.instance, NAMES.buildGraph,
                        NAMES.runOptimizations, NAMES.graphAddBlock,
                        NAMES.graphCheckerBlock, NAMES.graphVisitorBlock,
                        NAMES.graphVisitorInsertion, NAMES.graphVisitorRpo,
                        NAMES.fieldInstance,
                        NAMES.fieldStatic, NAMES.appendInstruction,
                        NAMES.addInstruction, NAMES.replaceWith,
                        NAMES.replaceAndRemove, NAMES.removeInstruction,
                        NAMES.removeInstructionOrPhi, NAMES.lseRun,
                        NAMES.x64LocationsFieldGet, NAMES.x64LocationsFieldSet,
                        NAMES.x64EmitFieldGet, NAMES.x64EmitFieldSet,
                        NAMES.lseRunBool, 'jit_load']) {
      try {
        const site = getExport(module, name);
        if (site) log('export=' + module.name + ' name=' + name +
                      ' address=' + site.address);
      } catch (e) { log('export-lookup-error ' + name + ': ' + e); }
    }
  }
  // Only claim argument decoding for the tested, architecture-specific ABI profiles.
  if (Process.pointerSize !== 8 || !['x64', 'arm64'].includes(Process.arch) ||
      ![33, 34].includes(api)) {
    log('Inventory only: ABI profile not enabled'); return;
  }
  const runtime = modules.find(m => m.name === 'libart.so' || m.name === 'libartd.so');
  const compiler = modules.find(m => m.name === 'libart-compiler.so' ||
                                     m.name === 'libartd-compiler.so');
  let hooked = 0;
  if (runtime) {
    const internal = getExport(runtime, NAMES.internal);
    if (internal) {
      hooked += Number(attach('runtime_internal',
        {address: internal.address, name: internal.name, source: 'export'}));
    } else {
      log('runtime-internal-export=not-found');
    }
  }
  if (runtime && compiler) {
    const exported = getExport(compiler, NAMES.compiler);
    const fromVtable = compilerViaVtable(runtime, compiler);
    if (exported && fromVtable && !exported.address.equals(fromVtable.address))
      log('compiler-export-vtable-address-mismatch export=' + exported.address +
          ' vtable=' + fromVtable.address);
    const site = exported
      ? {address: exported.address, name: exported.name, source: 'export'}
      : fromVtable;
    if (site) hooked += Number(attach('compiler', site));
    else log('compiler-boundary=not-found');
  }
  // Strictly gate read-only compiler IR observation to the tested export profile.
  if (api === 33 && Process.arch === 'x64' && compiler) {
    for (const [layer, name] of [
      ['graph_builder', NAMES.buildGraph],
      ['pre_opt', NAMES.runOptimizations]
    ]) {
      const site = getExport(compiler, name);
      if (site) attachGraphBoundary(layer, site);
      else log('graph-boundary-not-exported=' + layer);
    }
    for (const [access, name] of [
      ['instance', NAMES.fieldInstance],
      ['static', NAMES.fieldStatic]
    ]) {
      const site = getExport(compiler, name);
      if (site) attachFieldBuilder(access, site);
      else log('field-builder-not-exported=' + access);
    }
    for (const [layer, name] of [
      ['graph_add_block', NAMES.graphAddBlock],
      ['graph_checker_block', NAMES.graphCheckerBlock],
      ['graph_visitor_block', NAMES.graphVisitorBlock]
    ]) {
      const site = getExport(compiler, name);
      if (site) attachBlockBoundary(layer, site);
      else log('block-boundary-not-exported=' + layer);
    }
    for (const [role, symbol] of [
      ['insertion-order', NAMES.graphVisitorInsertion],
      ['reverse-post-order', NAMES.graphVisitorRpo]
    ]) {
      const site = getExport(compiler, symbol);
      // Only record export availability. Calling these methods ourselves
      // would require constructing a valid ART visitor object.
      log('graph-traversal-export ' + role + '=' +
          (site ? site.address : 'not-exported'));
    }
    discoverFieldVtables(compiler);
    discoverValueVtables(compiler);
    attachExistingInvokeObserver(compiler);
    // The app's onCreate() has not run at agent load time. Resolve the
    // already-loaded shim lazily from compiler callbacks instead.
    loadPassiveShadow();
    // Do not assume the builder's exported AppendInstruction is called.
    // Both out-of-line functions can coexist with inlined call sites.
    const append = getExport(compiler, NAMES.appendInstruction);
    const add = getExport(compiler, NAMES.addInstruction);
    const appendHook = append ? attachFieldNodeCandidate(append, 'append') : false;
    const addHook = add ? attachFieldNodeCandidate(add, 'basic-block') : false;
    log('ir-insertion-hooks=' + JSON.stringify({append: appendHook, add: addHook}));
    attachFieldAccept(compiler);
    for (const [stage, kind, symbol] of [
      ['locations', 'HInstanceFieldGet', NAMES.x64LocationsFieldGet],
      ['locations', 'HInstanceFieldSet', NAMES.x64LocationsFieldSet],
      ['emission', 'HInstanceFieldGet', NAMES.x64EmitFieldGet],
      ['emission', 'HInstanceFieldSet', NAMES.x64EmitFieldSet]
    ]) attachBackendFieldVisitor(compiler, symbol, stage, kind);
    for (const [op, names] of [
      ['replace', [NAMES.replaceWith]],
      ['replace_remove', [NAMES.replaceAndRemove]],
      ['remove', [NAMES.removeInstruction]],
      ['remove_or_phi', [NAMES.removeInstructionOrPhi]],
      ['lse', [NAMES.lseRun, NAMES.lseRunBool]]
    ]) {
      const site = names.map(n => getExport(compiler, n)).find(p => p !== null);
      if (site) attachMutationObserver(site, op);
      else log('mutation-boundary-not-exported=' + op);
    }
  } else {
    log('graph-boundaries=disabled (unverified binary profile)');
  }
  log('compile-hooks=' + hooked);
  log('No field interception or compiler IR mutation implemented');
}
// Host-facing runtime event transport. Does not rely on compiler tracing.
// This is a real JNI event recorder populated by executed application code.
rpc.exports = {
  runtimeevents() {
    const module = Process.findModuleByName('libartwatch_events.so');
    if (!module) return {ready:false,reason:'native event module not loaded'};
    const address = module.findExportByName('artwatch_events_snapshot');
    if (address === null) return {ready:false,reason:'snapshot export absent'};
    const snapshot = new NativeFunction(address,'int',['pointer','uint']);
    const buffer = Memory.alloc(65536);
    if (snapshot(buffer,65536) !== 1)
      return {ready:false,reason:'event publication incomplete or buffer insufficient'};
    return {ready:true,...JSON.parse(buffer.readUtf8String())};
  }
};
main();
