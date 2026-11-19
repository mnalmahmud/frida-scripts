'use strict';
// Read-only ART JIT interception probe; no field interception or IR mutation.
const TAG = '[art-fieldwatch/phase1] ';
const SAMPLE_LIMIT = 60;
const artLibraries = new Set(['libart.so', 'libartd.so', 'libart-compiler.so', 'libartd-compiler.so']);
const log = s => console.log(TAG + s);
const count = {runtime_internal: 0, compiler: 0};
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
  instance: '_ZN3art3jit3Jit13jit_compiler_E'
};
function getExport(module, exactName) {
  const address = module.findExportByName(exactName);
  return address === null ? null : {name: exactName, address};
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
        if (this.ordinal <= SAMPLE_LIMIT)
          log('JIT enter layer=' + layer + ' method=' + this.method +
              ' kind=' + this.compilationKind);
      },
      onLeave(ret) {
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
                        NAMES.compiler, NAMES.instance, 'jit_load']) {
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
  log('compile-hooks=' + hooked);
  log('No field interception or compiler IR mutation implemented');
}
main();
