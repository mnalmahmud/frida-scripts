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
  // x86_64 CI is an ART/Frida smoke test, not a native JIT symbol test.
  // Avoid enumerateSymbols() here: on API 34 the previous probe disconnected
  // immediately after printing the ART module list. The exact cause is
  // unconfirmed; this keeps potentially unsafe symbol enumeration isolated.
  if (Process.arch !== 'arm64' || (api !== 33 && api !== 34)) {
    log('Inventory complete; skipping deep symbol scan on this platform');
    log('This probe does NOT capture field accesses or modify compiler IR');
    return;
  }
  log('ARM64 experimental symbol discovery starting');
  const sites = modules.flatMap(discover);
  for (const s of sites) log('candidate='+s.type+' at='+s.address+
    ' module='+s.module+' source='+s.source+' symbol='+s.name);
  if (Process.arch !== 'arm64' || (api !== 33 && api !== 34)) {
    log('Inventory only: JIT callback requires API 33/34 arm64');
    return;
  }
  const pick = t => sites.find(s => s.type === t);
  const chosen = api === 34
    ? (pick('jit_dispatch_internal') || pick('jit_dispatch'))
    : (pick('jit_dispatch') || pick('jit_dispatch_internal'));
  try {
    if (chosen) attachDispatch(chosen);
    else log('No ABI-checked C++ JIT dispatch symbol discovered');
  } catch(e) { log('Hook installation failed: '+e.stack); }
  log('This probe does NOT capture field accesses or modify compiler IR');
  let before = 0;
  setInterval(() => {
    if (counts.attempts !== before) {
      before = counts.attempts;
      log('summary '+JSON.stringify(counts));
    }
  }, 5000);
}
main();
