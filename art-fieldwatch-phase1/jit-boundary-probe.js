'use strict';
/* Read-only JIT-boundary discovery. Does NOT intercept field reads/writes. */
const LIMIT = 40;
const counts = {attempts: 0, successes: 0, failures: 0};
const hooks = [];
const artNames = new Set(['libart.so','libartd.so','libart-compiler.so','libartd-compiler.so']);
const log = x => console.log('[art-fieldwatch/phase1] ' + x);
function sdkLevel() {
  try {
    const p = Process.getModuleByName('libc.so').findExportByName('__system_property_get');
    if (p === null) return '?';
    const fn = new NativeFunction(p,'int',['pointer','pointer']);
    const out = Memory.alloc(128);
    return fn(Memory.allocUtf8String('ro.build.version.sdk'),out) > 0
      ? out.readUtf8String() : '?';
  } catch (_) { return '?'; }
}
function kind(n) {
  if (/\bJit::CompileMethodInternal\(/.test(n)) return 'jit_dispatch_internal';
  if (/\bJit::CompileMethod\(/.test(n)) return 'jit_dispatch';
  if (/\bOptimizingCompiler::JitCompile\(/.test(n)) return 'optimizing_jit';
  if (/\bOptimizingCompiler::TryCompile\(/.test(n)) return 'optimizing_preopt_candidate';
  if (/\bHGraphBuilder::BuildGraph\(/.test(n)) return 'graph_builder';
  if (/\bJitCodeCache::Commit\(/.test(n)) return 'code_publication';
  if (n === 'jit_load') return 'jit_load';
  return null;
}
function discover(m) {
  const result = [];
  const seen = new Set();
  const add = (name,address,source) => {
    const type = kind(name);
    if (type === null) return;
    const key = type + ':' + address;
    if (seen.has(key)) return;
    seen.add(key);
    result.push({type,name,address,source,module:m.name});
  };
  const exp = m.findExportByName('jit_load');
  if (exp !== null) add('jit_load',exp,'export');
  try {
    for (const s of m.enumerateSymbols()) {
      if (s.type === 'function' || s.type === undefined)
        add(s.name,s.address,'symbol');
    }
  } catch (e) { log('Cannot enumerate symbols in ' + m.name + ': ' + e.message); }
  return result;
}
function attachDispatch(site) {
  hooks.push(Interceptor.attach(site.address, {
    onEnter(args) {
      this.method = args[1];
      this.kind = args[3].toInt32();
      counts.attempts++;
      this.print = counts.attempts <= LIMIT;
    },
    onLeave(ret) {
      const ok = ret.toInt32() !== 0;
      counts[ok ? 'successes' : 'failures']++;
      if (this.print) log('JIT ' + (ok?'success':'failed') +
         ' method=' + this.method + ' kind=' + this.kind);
    }
  }));
  log('Attached compilation observer at ' + site.address + ' (' + site.name + ')');
}
function main() {
  const api = Number(sdkLevel());
  log('pid='+Process.id+' arch='+Process.arch+' pointerSize='+Process.pointerSize+' api='+api);
  const modules = Process.enumerateModules().filter(m => artNames.has(m.name));
  if (modules.length === 0) { log('No ART library found'); return; }
  for (const m of modules) {
    log('module='+m.name+' base='+m.base+' path='+m.path);
    // Dynamic exports only. Unlike enumerateSymbols(), this avoids scanning
    // the full ELF symbol table on production ART.
    try {
      const candidates = m.enumerateExports().filter(e =>
        /jit_load|jit_compile_method|jit_compiler_|CompileMethod/.test(e.name));
      log('exports=' + m.name + ' matches=' + candidates.length);
      for (const e of candidates.slice(0, 30))
        log('export=' + m.name + ' name=' + e.name + ' address=' + e.address);
      if (candidates.length > 30) log('export-list-truncated=' + m.name);
    } catch (e) { log('export-enumeration-error=' + m.name + ': ' + e.message); }
  }

  // Observe exported C++ compilation functions, using mangled ELF names.
  const candidates = [];
  for (const m of modules) {
    for (const e of m.enumerateExports()) {
      if (e.type !== 'function') continue;
      let layer = null;
      if (e.name.startsWith('_ZN3art3jit3Jit13CompileMethodE'))
        layer = 'runtime';
      else if (e.name.startsWith('_ZN3art3jit11JitCompiler13CompileMethodE'))
        layer = 'compiler';
      if (layer !== null) {
        candidates.push({layer,address:e.address,name:e.name,module:m.name});
        log('compilation-export=' + layer + ' name=' + e.name + ' at=' + e.address);
      }
    }
  }
  if (!['x64','arm64'].includes(Process.arch) || ![33,34].includes(api)) {
    log('Inventory only: compiler ABI not yet validated for this profile');
    return;
  }
  const limits = {runtime:0,compiler:0};
  let hooked = 0;
  for (const layer of ['runtime','compiler']) {
    const site = candidates.find(c => c.layer === layer);
    if (!site) continue;
    try {
      Interceptor.attach(site.address, {
        onEnter(args) {
          // Runtime: this, ArtMethod*, Thread*, CompilationKind, bool
          // Compiler: this, Thread*, JitMemoryRegion*, ArtMethod*, CompilationKind
          this.method = (layer === 'runtime' ? args[1] : args[3]).toString();
          this.compilationKind = (layer === 'runtime' ? args[3] : args[4]).toInt32();
        },
        onLeave(ret) {
          limits[layer]++;
          const event = {type:'artwatch-jit',layer,method:this.method,
            kind:this.compilationKind,success:ret.toInt32() !== 0};
          send(event);
          if (limits[layer] <= 25) log('JIT ' + JSON.stringify(event));
        }
      });
      hooked++;
      log('Attached compilation observer: ' + layer + ' at=' + site.address);
      send({type:'artwatch-hook-attached',layer,name:site.name});
    } catch (e) {
      log('JIT hook failed for ' + layer + ': ' + e.stack);
    }
  }
  log('compile-hooks=' + hooked);
  log('No field interception or compiler IR mutation implemented');

}
main();
