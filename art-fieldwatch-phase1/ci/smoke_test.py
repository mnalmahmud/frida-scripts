#!/usr/bin/env python3
"""Frida + Android fixture integration smoke, NOT field-hook coverage."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import frida

BASE = Path(__file__).resolve().parents[1]
LOG_DIR = Path(os.environ.get('ARTWATCH_LOG_DIR','/tmp/artwatch-logs'))
LOG_DIR.mkdir(parents=True,exist_ok=True)
messages, errors = [], []

def record(kind,content):
    messages.append({'kind':kind,'text':str(content)})
    print(f'[{kind}] {content}',flush=True)

def on_message(message,data):
    if message.get('type') == 'error':
        errors.append(message.get('stack') or message.get('description') or str(message))
        record('error',errors[-1])
    else:
        record('frida',json.dumps(message,sort_keys=True))

def main():
    device = frida.get_usb_device(timeout=30)
    record('host','frida-device='+device.name)
    record('host','frida-process-count='+str(len(device.enumerate_processes())))
    pid = device.spawn(['com.example.artfieldwatch'])
    record('host','spawned-pid='+str(pid))
    session = device.attach(pid)
    runtime_snapshot = None
    p3_snapshot = None
    field_snapshot = None
    direct_abi_snapshot = None
    try:
        source = (BASE/'jit-boundary-probe.js').read_text()
        sink_inventory = LOG_DIR / ('p3-sink-method-' +
                                     os.environ.get('ARTWATCH_BUILD_VARIANT','debug') +
                                     '.json')
        if sink_inventory.is_file() and os.environ.get('ARTWATCH_SHADOW_SHIM') == '1':
            sink_info = json.loads(sink_inventory.read_text())
            if not str(sink_info.get('dex','')).startswith('classes'):
                raise AssertionError('P3 sink was not found in a packaged DEX')
            source = ('globalThis.__artwatchP3Fixture = ' +
                      json.dumps(sink_info) + ';\n' +
                      'globalThis.__artwatchP3Inject = ' +
                      json.dumps(os.environ.get('ARTWATCH_P3_INJECT') == '1') +
                      ';\n' + source)
        if os.environ.get('ARTWATCH_SHADOW_SHIM') == '1':
            source = ('globalThis.__artwatchShadowPath = ' +
                      json.dumps('libartwatch_shadow.so') +
                      ';\n' + source)
        script = session.create_script(source)
        script.on('message',on_message)
        script.set_log_handler(lambda level, line: record('console-'+level, line))
        script.load()
        device.resume(pid)
        # Staged release warmup gives natural JIT workers time to compile
        # all three independently hot field-read/write workloads.
        time.sleep(30 if os.environ.get('ARTWATCH_BUILD_VARIANT') == 'release' else 20)
        if os.environ.get('ARTWATCH_SHADOW_SHIM') == '1':
            runtime_snapshot = script.exports_sync.runtimeevents()
            direct_abi_snapshot = script.exports_sync.fieldmeta()
            (LOG_DIR/'direct-abi-events.json').write_text(
                json.dumps(direct_abi_snapshot,indent=2))
            if os.environ.get('ARTWATCH_P3_INJECT') == '1':
                p3_snapshot = script.exports_sync.p3events()
                field_snapshot = script.exports_sync.p3fieldmeta()
                (LOG_DIR/'p3-field-metadata.json').write_text(
                    json.dumps(field_snapshot,indent=2))
                record('host',f'P3 metadata events ready={field_snapshot.get("ready")} '
                       f'total={field_snapshot.get("total")}')
                (LOG_DIR/'p3-injected-events.json').write_text(
                    json.dumps(p3_snapshot,indent=2))
                record('host',f'P3 compiled events ready={p3_snapshot.get("ready")} '
                       f'total={p3_snapshot.get("total")} '
                       f'dropped={p3_snapshot.get("dropped")}')
            (LOG_DIR/'runtime-events.json').write_text(
                json.dumps(runtime_snapshot,indent=2))
            record('host',f'Native runtime events ready={runtime_snapshot.get("ready")} '
                   f'total={runtime_snapshot.get("total")} '
                   f'dropped={runtime_snapshot.get("dropped")}')
    finally:
        try: session.detach()
        except frida.InvalidOperationError: pass
    logs = subprocess.run(['adb','logcat','-d','-s','ARTWATCH_CI:I','*:S'],
      capture_output=True,text=True,check=False)
    (LOG_DIR/'logcat.txt').write_text(logs.stdout+logs.stderr)
    (LOG_DIR/'frida-messages.json').write_text(json.dumps(messages,indent=2))
    text = '\n'.join(m['text'] for m in messages)
    if 'module=libart' not in text: raise AssertionError('libart not discovered')
    if 'arch=' not in text: raise AssertionError('No Frida process header')
    if errors: raise AssertionError('Frida errors: '+'; '.join(errors))
    variant = os.environ.get('ARTWATCH_BUILD_VARIANT','debug')
    expected_debug = 'true' if variant == 'debug' else 'false'
    if f'APP_DEBUGGABLE={expected_debug}' not in logs.stdout:
        raise AssertionError(f'Unexpected app debuggable flag for {variant} build')
    if os.environ.get('ARTWATCH_SHADOW_SHIM') == '1':
        if 'SHADOW_LIB_LOADED=true' not in logs.stdout or (
             'EVENT_LIB_LOADED=true' not in logs.stdout):
            raise AssertionError('App failed to load packaged native observer/event libraries')
        p3_inject = os.environ.get('ARTWATCH_P3_INJECT') == '1'
        if p3_inject:
            template_marker = 'P3_TEMPLATE_DONE count=256 checksum=25280 nullCheck=true injected=true'
        else:
            template_marker = 'P3_TEMPLATE_DONE count=0 checksum=25280 nullCheck=true injected=false'
        if template_marker not in logs.stdout:
            raise AssertionError('P3 compiler-insertion result mismatch: ' + template_marker)
        if p3_inject:
            if not p3_snapshot or p3_snapshot.get('ready') is not True or (
                 p3_snapshot.get('total') != 256 or p3_snapshot.get('dropped') != 0):
                raise AssertionError(f'Independent P3 runtime snapshot unavailable: {p3_snapshot}')
            p3_events = p3_snapshot.get('events',[])
            if len(p3_events) != 256:
                raise AssertionError(f'Expected 256 P3 events, got {len(p3_events)}')
            for i in range(128):
                expected = 7 + 3 * i
                write, read = p3_events[2*i], p3_events[2*i+1]
                if write != {'seq':2*i+1,'site':9001,'kind':2,'value':expected}:
                    raise AssertionError(f'P3 incorrect write event at {i}: {write}')
                if read != {'seq':2*i+2,'site':9002,'kind':1,'value':expected}:
                    raise AssertionError(f'P3 incorrect read event at {i}: {read}')
            if not field_snapshot or field_snapshot.get('ready') is not True:
                raise AssertionError('P3 detailed event metadata snapshot unavailable')
            fixture = json.loads((LOG_DIR / (
                'p3-sink-method-' + variant + '.json')).read_text())
            records = field_snapshot.get('events', [])
            if field_snapshot.get('total') != 256 or (
                 field_snapshot.get('dropped') != 0 or len(records) != 256):
                raise AssertionError('P3 field metadata event count/drops invalid')
            for i in range(128):
                expected = 7 + 3*i
                for ordinal, kind, pc in (
                    (2*i, 2, fixture['setDexPc']),
                    (2*i+1, 1, fixture['getDexPc'])):
                    e = records[ordinal]
                    expected_bits = f'0x{expected:016x}'
                    if (e.get('seq') != ordinal+1 or
                        e.get('dexId') != fixture['dexId'] or
                        e.get('methodId') != fixture['carrierMethodIndex'] or
                        e.get('fieldId') != fixture['fieldIndex'] or
                        e.get('dexPc') != pc or e.get('kind') != kind or
                        e.get('type') != 5 or e.get('valueBits') != expected_bits):
                        raise AssertionError(f'P3 metadata/value mismatch: {e}')
            record('host','PASS: 256 field events joined to exact DEX method, '
                   'field, PC, direction, int type and value bits')
            record('host','PASS: independently archived 256 P3 injected-context '
                   'events with exact values/order and zero drops')
        if logs.stdout.index(template_marker) >= logs.stdout.find('P3_CANARY_DONE'):
            raise AssertionError('P3 template did not run before the silent canary')
        canary_marker = 'P3_CANARY_DONE count=0 checksum=25280 nullCheck=true'
        if canary_marker not in logs.stdout:
            raise AssertionError('P3 raw-field canary must produce zero native events')
        if logs.stdout.index(canary_marker) >= logs.stdout.find('RUNTIME_EVENTS_DONE'):
            raise AssertionError('P3 negative control did not precede the P2 fixture')
        if 'DIRECT_ABI_DONE count=4 checksum=103' not in logs.stdout:
            raise AssertionError('Direct six-int native ABI fixture failed')
        if not direct_abi_snapshot or direct_abi_snapshot.get('ready') is not True:
            raise AssertionError('Direct six-int native ABI snapshot unavailable')
        records_abi = direct_abi_snapshot.get('events',[])
        values_abi = [(-11,2,17,3,7),(-11,1,17,3,9),
                      (42,2,18,4,11),(42,1,18,4,13)]
        if direct_abi_snapshot.get('total') != 4 or (
             direct_abi_snapshot.get('dropped') != 0 or len(records_abi) != 4):
            raise AssertionError('Direct six-int native ABI count mismatch')
        for i,(value,kind,field_id,method_id,dex_pc) in enumerate(values_abi):
            expected_abi = {
                'seq':i+1,'dexId':0,'methodId':method_id,'fieldId':field_id,
                'dexPc':dex_pc,'kind':kind,'type':5,
                'valueBits':f'0x{value & ((1<<64)-1):016x}'}
            if records_abi[i] != expected_abi:
                raise AssertionError(f'Direct JNI ABI record invalid: {records_abi[i]}')
        record('host','PASS: direct six-int JNI ABI, four exact field records')
        if 'RUNTIME_EVENTS_DONE count=256' not in logs.stdout or (
             'nullCheck=true' not in logs.stdout):
            raise AssertionError('Native runtime field event workload did not complete')
        if not runtime_snapshot or runtime_snapshot.get('ready') is not True:
            raise AssertionError(f'Native runtime event snapshot unavailable: {runtime_snapshot}')
        observed = runtime_snapshot.get('events',[])
        if (runtime_snapshot.get('total') != 256 or len(observed) != 256 or
            runtime_snapshot.get('dropped') != 0):
            raise AssertionError('Runtime event count, capacity or delivery mismatch')
        for i in range(128):
            expected = 7 + 3 * i
            write, read = observed[2*i], observed[2*i+1]
            if write != {'seq':2*i+1,'site':9001,'kind':2,'value':expected}:
                raise AssertionError(f'Incorrect executed write event at index {i}: {write}')
            if read != {'seq':2*i+2,'site':9002,'kind':1,'value':expected}:
                raise AssertionError(f'Incorrect executed read event at index {i}: {read}')
        record('host','PASS: 256 real native field events, 128 read/write pairs, '
               'exact values/order, zero drops, no event on null access')
    if 'WARMUP_FAILED' in logs.stdout or 'WARMUP_DONE' not in logs.stdout:
        raise AssertionError('APK fixture warmup failed or timed out')
    if variant == 'release':
        markers = [f'LSE_STAGE_DONE={i}' for i in range(5)]
        missing_stages = [marker for marker in markers if marker not in logs.stdout]
        if missing_stages:
            raise AssertionError(f'Incomplete staged LSE warmup: {missing_stages}')
        record('host','Five staged release warmups completed before JIT assertions')
    hooked = [e['text'] for e in messages if e['kind']=='frida' and
              '"artwatch-hook-attached"' in e['text']]
    compiled = [e['text'] for e in messages if e['kind']=='frida' and
                '"artwatch-jit"' in e['text']]
    record('host',f'JIT hooks={len(hooked)} compilation events={len(compiled)}')
    required = os.environ.get('ARTWATCH_REQUIRE_JIT') == '1'
    if required:
        # Assert the actual worker entry, not the exported Jit::CompileMethod()
        # path bypassed by ordinary JitCompileTask execution.
        # API 33 did not export CompileMethodInternal in earlier CI inventory.
        # The compiler vtable boundary is the essential shared capability.
        if not any('"compiler"' in h for h in hooked):
            raise AssertionError('JitCompilerInterface::CompileMethod interceptor not installed')
        internal = [e for e in compiled if '"runtime_internal"' in e]
        compiler = [e for e in compiled if '"compiler"' in e]
        record('host',f'JIT runtime_internal events={len(internal)} compiler events={len(compiler)}')
        if not compiler:
            raise AssertionError('No JIT compiler callbacks observed')
        # When an internal hook exists, it must actually execute.
        if any('"runtime_internal"' in h for h in hooked) and not internal:
            raise AssertionError('Internal runtime hook installed but did not execute')
    if required and 'api=33' in text and 'arch=x64' in text:
        # This binary exports both boundaries; require actual callbacks.
        shadow_enabled = os.environ.get('ARTWATCH_SHADOW_SHIM') == '1'
        payloads = []
        for e in messages:
            if e['kind'] != 'frida':
                continue
            try:
                m = json.loads(e['text'])
                if m.get('type') == 'send' and isinstance(m.get('payload'), dict):
                    payloads.append(m['payload'])
            except (ValueError, TypeError):
                continue
        # P3 must prove the exact two native-cloned invoke nodes reached
        # BOTH location assignment and code emission in one compilation.
        # Counts and fixture assertions alone are not clone provenance.
        p3_clones = [v for v in payloads if v.get('type') == 'artwatch-p3-clone']
        p3_compiled = [v for v in payloads if v.get('type') == 'artwatch-p3-compiled']
        p3_errors = [v for v in payloads if v.get('type') == 'artwatch-p3-clone-error']
        if p3_inject:
            attached = [v for v in payloads if v.get('type') == 'artwatch-hook-attached'
                        and v.get('layer') == 'p3_clone_canary']
            successful = [v for v in p3_clones if v.get('rc') == 1]
            if not attached or p3_errors or len(successful) != 2:
                raise AssertionError(f'P3 clone hook/errors/attempts invalid: '
                                     f'{len(attached)}, {p3_errors}, {p3_clones}')
            nodes = {v.get('clonedNode') for v in successful}
            if {v.get('kind') for v in successful} != {'write','read'} or (
                 None in nodes or len(nodes) != 2):
                raise AssertionError(f'P3 did not return two distinct typed clone nodes: {successful}')
            if len(p3_compiled) != 1 or p3_compiled[0].get('codegenSuccess') is not True or (
                 p3_compiled[0].get('metadataConfigured') is not True):
                raise AssertionError(f'P3 compiler completion not proven: {p3_compiled}')
            proof = p3_compiled[0].get('cloneProof', [])
            if (len(proof) != 2 or {v.get('node') for v in proof} != nodes or
                {v.get('kind') for v in proof} != {'write','read'} or
                not all(v.get('locations') is True and v.get('emitted') is True
                        for v in proof)):
                raise AssertionError(f'P3 exact clone nodes missing from backend: {proof}')
            if any(v.get('method') != p3_compiled[0].get('method')
                   for v in successful):
                raise AssertionError('P3 cloned invokes came from different JIT methods')
            record('host','PASS: P3 write/read clone IDs reached location assignment '
                   'and code emission in the successful ART compilation')
        elif p3_clones or p3_compiled or p3_errors:
            raise AssertionError('P3 mutation occurred while opt-in is disabled')
        # Source-backed ABI oracle: compiler-created HInvokeStaticOrDirect
        # nodes must be observed, not merely a successfully hooked export.
        # This remains passive and does not imply an injected invoke.
        invoke_abi = [v for v in payloads
                      if v.get('type') == 'artwatch-existing-invoke-abi']
        invoke_samples = [v for v in payloads
                          if v.get('type') == 'artwatch-existing-invoke']
        invoke_summaries = [v for v in payloads
                            if v.get('type') == 'artwatch-existing-invoke-summary']
        if not any(v.get('acceptExported') is True and
                   v.get('vtableExported') is True and
                   v.get('writesArtMemory') is False for v in invoke_abi):
            raise AssertionError('API 33 compiler invoke ABI exports not verified')
        if not invoke_samples or not invoke_summaries:
            raise AssertionError('No real compiler-created invoke-node observations')
        if not any(v.get('compilationSucceeded') is True and
                   v.get('visits', 0) >= v.get('uniqueNodes', 0) > 0
                   for v in invoke_summaries):
            raise AssertionError('No successful compilation containing invoke IR')
        if not all(v.get('blockCorrelated', 0) <= v.get('visits', 0)
                   for v in invoke_summaries):
            raise AssertionError('Invalid invoke visitor/block correlation count')
        backend_layers = {v.get('layer') for v in payloads
                          if v.get('type') == 'artwatch-hook-attached'
                          and v.get('layer') in
                          ('existing_invoke_locations','existing_invoke_emission')}
        if backend_layers != {'existing_invoke_locations',
                              'existing_invoke_emission'}:
            raise AssertionError('API33 invoke codegen hooks missing')
        if not any(v.get('compilationSucceeded') is True and
                   v.get('backendEmitted', 0) > 0 and
                   v.get('backendLocations', 0) >= v.get('backendEmitted', 0)
                   for v in invoke_summaries):
            raise AssertionError('No successful JIT with an emitted invoke node')
        if not all(v.get('backendEmitted',0) >=
                   len(v.get('emittedInvokeNodes',[])) for v in invoke_summaries):
            raise AssertionError('Invoke emission sample exceeds observed count')
        if shadow_enabled and any(v.get('adjacencyRejected',0) > 0
                                  for v in invoke_summaries):
            raise AssertionError('Build-ID-gated instruction adjacency probe rejected live nodes')
        probe_count = sum(v.get('adjacencyProbes',0) for v in invoke_summaries)
        direct_count = sum(v.get('adjacencyMatches',0) for v in invoke_summaries)
        nearby_count = sum(v.get('adjacencyWithin8',0) for v in invoke_summaries)
        mismatched = sum(v.get('adjacencyBlockMismatch',0) for v in invoke_summaries)
        broken = sum(v.get('adjacencyBrokenLinks',0) for v in invoke_summaries)
        no_get = sum(v.get('adjacencyNoGetWithin8',0) for v in invoke_summaries)
        rejected = sum(v.get('adjacencyRejected',0) for v in invoke_summaries)
        record('host',f'ART P3 invoke predecessors: probes={probe_count} '
               f'direct={direct_count} within8={nearby_count} '
               f'blockMismatch={mismatched} brokenLinks={broken} '
               f'noGetWithin8={no_get} rejected={rejected}')
        if shadow_enabled:
            if probe_count == 0:
                raise AssertionError('P3 invoke predecessor observer never ran')
            if probe_count != (direct_count + nearby_count + mismatched +
                               broken + no_get + rejected):
                raise AssertionError('P3 invoke predecessor tallies inconsistent')
            field_target_summaries = [
                v for v in invoke_summaries if v.get('fieldTarget') is True]
            field_target_probes = sum(
                v.get('targetAdjacencyProbes',0) for v in field_target_summaries)
            record('host',f'P3 field-target predecessor probes={field_target_probes} '
                   f'compilations={len(field_target_summaries)}')
            if not field_target_summaries or field_target_probes == 0:
                raise AssertionError('No baseline field-target invoke predecessor scans')
            matched_get_pcs = sum(v.get('targetGetPcMatches',0)
                                  for v in field_target_summaries)
            unmatched_get_pcs = sum(v.get('targetGetPcMismatches',0)
                                    for v in field_target_summaries)
            unavailable_get_pcs = sum(v.get('targetGetPcUnavailable',0)
                                      for v in field_target_summaries)
            target_gets_found = sum(
                v.get('adjacencyMatches',0) + v.get('adjacencyWithin8',0)
                for v in field_target_summaries)
            record('host',f'P3 target get identity: matched={matched_get_pcs} '
                   f'unmatched={unmatched_get_pcs} unavailable={unavailable_get_pcs} '
                   f'adjacent-or-nearby={target_gets_found}')
            if matched_get_pcs + unmatched_get_pcs + unavailable_get_pcs != target_gets_found:
                raise AssertionError('Inconsistent P3 get DEX-PC identity counters')
            if matched_get_pcs == 0:
                raise AssertionError('No live field-get DEX PC matched a field-builder target')
        record('host',f'Invoke x64 backend: code-emission nodes=' +
               str(sum(v.get('backendEmitted',0) for v in invoke_summaries)))
        record('host',f'Existing invoke ABI: samples={len(invoke_samples)} '
               f'compilations={len(invoke_summaries)} '
               f'correlated={sum(v.get("blockCorrelated",0) for v in invoke_summaries)}')
        graph_hooks = {v.get('layer') for v in payloads
                       if v.get('type') == 'artwatch-hook-attached'
                       and v.get('layer') in ('graph_builder','pre_opt')}
        built = [v for v in payloads if v.get('type') == 'artwatch-graph'
                 and v.get('phase') == 'build-complete']
        preopt = [v for v in payloads if v.get('type') == 'artwatch-graph'
                  and v.get('phase') == 'pre-opt']
        matched = [v for v in preopt if v.get('graphMatchesBuilder') is True]
        record('host',f'graph hooks={sorted(graph_hooks)} built={len(built)} '
               f'pre-opt={len(preopt)} pointer-matches={len(matched)}')
        if graph_hooks != {'graph_builder','pre_opt'}:
            raise AssertionError('API 33 graph boundaries not both attached')
        if not built or not preopt:
            raise AssertionError('API 33 graph construction/pre-optimization callback missing')
        if not matched:
            raise AssertionError('No graph pointer correlation between the boundaries')
        field_hooks = {v.get('layer') for v in payloads
                       if v.get('type') == 'artwatch-hook-attached'
                       and v.get('layer') in ('field_instance','field_static')}
        field_events = [v for v in payloads
                        if v.get('type') == 'artwatch-field-build']
        instance_reads = [v for v in field_events
                          if v.get('access') == 'instance' and v.get('isPut') is False]
        instance_writes = [v for v in field_events
                           if v.get('access') == 'instance' and v.get('isPut') is True]
        linked = [v for v in field_events
                  if v.get('graphCandidate') and v.get('method') and
                     isinstance(v.get('dexPc'), int)]
        record('host',f'field hooks={sorted(field_hooks)} events={len(field_events)} '
               f'instance-reads={len(instance_reads)} instance-writes={len(instance_writes)} '
               f'graph-linked={len(linked)}')
        if 'field_instance' not in field_hooks:
            raise AssertionError('API 33 instance field-builder hook not installed')
        if not instance_reads or not instance_writes:
            raise AssertionError('Missing compiled instance-field get/set DEX build callbacks')
        if not linked:
            raise AssertionError('No field-builder event correlated with a live HGraph')
        append_hooks = [v for v in payloads
                        if v.get('type') == 'artwatch-hook-attached'
                        and v.get('layer') == 'ir_append']
        nodes = [v for v in payloads if v.get('type') == 'artwatch-ir-node']
        typed = [v for v in nodes if v.get('kind') is not None]
        observed_kinds = sorted({v['kind'] for v in typed})
        record('host', f'IR append hooks={len(append_hooks)} '
               f'candidate nodes={len(nodes)} typed={len(typed)} kinds={observed_kinds}')
        visits = [v for v in payloads if v.get('type') == 'artwatch-ir-visit']
        visit_kinds = sorted({v.get('kind') for v in visits if v.get('kind')})
        matching_visits = [v for v in visits if v.get('vtableMatches') is True]
        instance_types = [v for v in visits if v.get('kind') in
                          ('HInstanceFieldGet','HInstanceFieldSet')]
        record('host',f'IR visits={len(visits)} visit kinds={visit_kinds} '
               f'vtable-matched={len(matching_visits)} '
               f'instance-typed={len(instance_types)}')
        if nodes and not any(v.get('fieldIndexRaw') == 0 and
                             v.get('access') == 'instance' for v in nodes):
            raise AssertionError('No FieldIRTarget field IR append candidates')
        vtables = [v for v in payloads if v.get('type') == 'artwatch-ir-vtables']
        if vtables:
            record('host', f'IR vtables available={vtables[-1].get("available",[])}')
        if not nodes and not instance_types:
            raise AssertionError('No field IR nodes observed through insertion or Accept()')
        if visits and not matching_visits:
            raise AssertionError('Field Accept callback vtables did not match class identity')
        targets = [v for v in payloads if v.get('type') == 'artwatch-target-dex']
        target_ir = [v for v in payloads if v.get('type') == 'artwatch-target-ir']
        summaries = [v for v in payloads
                     if v.get('type') == 'artwatch-target-summary']
        mutations = [v for v in payloads
                     if v.get('type') == 'artwatch-ir-mutation']
        mutation_hooks = sorted({v.get('layer') for v in payloads
                                 if v.get('type') == 'artwatch-hook-attached'
                                 and str(v.get('layer','')).startswith('ir_mutation_')})
        target_kinds = sorted({v.get('kind') for v in target_ir})
        record('host',f'target DEX identified={len(targets)} '
               f'target IR={len(target_ir)} kinds={target_kinds} '
               f'target summaries={len(summaries)} '
               f'mutation hooks={mutation_hooks} mutation events={len(mutations)}')
        if variant == 'debug':
            if not targets:
                raise AssertionError('Debug FieldIRTarget.test DEX pattern not identified')
            if not summaries:
                raise AssertionError('No debug compiler summary for FieldIRTarget.test')
            if not {'HInstanceFieldGet','HInstanceFieldSet'}.issubset(set(target_kinds)):
                raise AssertionError('Debug FieldIRTarget.test get/set IR nodes not both seen')
        else:
            record('host', 'Release DEX target fingerprint is diagnostic: '
                   'the missing iget may have been eliminated by D8 before ART JIT')
        # Mutation/LSE hookability is a new hypothesis; missing exports are
        # recorded, but do not invalidate the verified field-node capture.
        phases = [v for v in payloads
                  if v.get('type') == 'artwatch-phase-summary']
        lse = [v for v in payloads if v.get('type') == 'artwatch-lse'
               and v.get('phase') == 'enter']
        optimized = [v for v in phases if v.get('compilationKind') == 2]
        record('host',f'variant={variant} compilations={len(phases)} '
               f'optimized={len(optimized)} lse-enter={len(lse)} '
               f'target-phases={[v for v in phases if v.get("isFieldTarget")]}')
        if variant == 'release' and not optimized:
            raise AssertionError('Non-debuggable release fixture did not trigger optimized JIT')
        if variant == 'release' and not lse:
            raise AssertionError('No LSE::Run invocation observed in non-debuggable optimized JIT')
        backend_hooks = [v for v in payloads
                         if v.get('type') == 'artwatch-hook-attached'
                         and str(v.get('layer','')).startswith('backend_field_')]
        backend_events = [v for v in payloads
                          if v.get('type') == 'artwatch-backend-field']
        lowered = [v for v in backend_events if v.get('stage') == 'locations']
        emitted = [v for v in backend_events if v.get('stage') == 'emission']
        record('host', f'backend field hooks={len(backend_hooks)} '
               f'locations={len(lowered)} emission={len(emitted)} '
               f'emitted kinds={sorted({v.get("expectedKind") for v in emitted})}')
        if len(backend_hooks) != 4:
            raise AssertionError('Expected four API33 x86_64 backend field visitor hooks')
        if not lowered and not emitted:
            raise AssertionError('No instance-field IR nodes reached backend field visitors')
        if variant == 'release' and not targets:
            raise AssertionError('Release fixture did not produce any method with iget+iput DEX')
        positive_lse = [v for v in payloads
                        if v.get('type') == 'artwatch-lse'
                        and v.get('phase') == 'exit'
                        and v.get('compilationKind') == 2
                        and v.get('result') is True]
        field_mutations = [v for v in payloads
                           if v.get('type') == 'artwatch-field-ir-mutation']
        mutation_calls = [v for v in payloads
                          if v.get('type') == 'artwatch-mutation-call-summary']
        record('host', f'variant={variant} optimized-LSE-changes={len(positive_lse)} '
               f'field-IR-mutations={len(field_mutations)} '
               f'mutation-call-summaries={len(mutation_calls)}')
        if variant == 'release' and not positive_lse:
            raise AssertionError('Release optimized JIT saw LSE but no Run() returned true')

        # Exact-node evidence: source-level DEX read was present, and ART
        # visited its HInstanceFieldGet before LSE replaced and removed it.
        # The removed pointer must not appear in this compilation's backend.
        lifecycles = [v for v in payloads
                      if v.get('type') == 'artwatch-field-lifecycle']
        eliminated_gets = [(lc, entry) for lc in lifecycles
                           if lc.get('compilationKind') == 2
                           and lc.get('compilationSucceeded') is True
                           for entry in lc.get('entries', [])
                           if entry.get('kind') == 'HInstanceFieldGet'
                           and {'replace', 'remove'}.issubset(
                               set(entry.get('operations', [])))
                           and entry.get('visitedBeforeMutation') is True
                           and entry.get('lowered') is False
                           and entry.get('emitted') is False]
        block_traced_gets = [(lc, entry) for lc, entry in eliminated_gets
                             if entry.get('observedBlocks')
                             and any(v.get('constructed') is True
                                     for v in entry.get('observedBlocks',[]))]
        baseline_reads = [v for v in summaries
                          if v.get('compilationKind') == 1 and
                          v.get('compilationSucceeded') is True and
                          any(str(k).startswith('HInstanceFieldGet@')
                              for k in v.get('codeEmittedNodes', []))]
        record('host', f'variant={variant} lifecycle-compilations={len(lifecycles)} '
               f'optimized-removed-gets={len(eliminated_gets)} '
               f'block-traced-eliminated-gets={len(block_traced_gets)} '
               f'baseline-emitted-gets={len(baseline_reads)}')
        if variant == 'release' and not eliminated_gets:
            raise AssertionError('No exact HInstanceFieldGet visited, replaced and '
                                 'removed during LSE without backend emission')
        if variant == 'release' and not baseline_reads:
            raise AssertionError('No baseline JIT get node observed at code emission')
        if variant == 'release' and len(block_traced_gets) != len(eliminated_gets):
            raise AssertionError('LSE-eliminated field get lacked prior '
                                 'observed HGraph basic-block ownership')
        for lc, entry in block_traced_gets:
            if not all(b.get('block') and b.get('visits',0) >= 1
                       for b in entry['observedBlocks']):
                raise AssertionError('Malformed historical field block membership')
        producer_types = sorted({e.get('replacementKind') for _,e in eliminated_gets
                                 if e.get('replacementKind')})
        record('host',f'Replaced instance-field SSA producer kinds={producer_types}')
        visit_order = [v for v in payloads
                       if v.get('type') == 'artwatch-field-visit-order']
        sampled_passes = [item for event in visit_order
                          for item in event.get('passes',[])]
        order_field_count = sum(p.get('fieldCount',0) for p in sampled_passes)
        order_truncated = sum(v.get('truncatedFieldEntries',0)
                              for v in visit_order)
        record('host',f'Field visit order scopes={len(visit_order)} '
               f'passes={len(sampled_passes)} fields={order_field_count} '
               f'truncated={order_truncated}')
        if not sampled_passes or order_field_count <= 0:
            raise AssertionError('No field visitation order from real ART blocks')
        for event in visit_order:
            if event.get('passesCaptured') != len(event.get('passes',[])):
                raise AssertionError('Incorrect captured visitor pass count')
            if event.get('passesWithFields',0) < event.get('passesCaptured',0):
                raise AssertionError('Captured more field passes than observed')
        for item in sampled_passes:
            fields = item.get('fields',[])
            if not item.get('block') or not item.get('visitor'):
                raise AssertionError('Missing visitor/block pointer in visit order')
            if item.get('fieldCount',0) < len(fields) or len(fields) > 20:
                raise AssertionError('Field visitor sample overflow')
            if [i.get('ordinal') for i in fields] != list(range(len(fields))):
                raise AssertionError('Field visitor ordering ordinals are inconsistent')
            if not all(i.get('node') and str(i.get('kind','')).startswith('H')
                       for i in fields):
                raise AssertionError('Missing typed node from visit order')
        if shadow_enabled:
            inits = [v for v in payloads if v.get('type') == 'artwatch-shadow-init']
            if not any(v.get('ready') is True and v.get('buildIdVerified') is True
                       for v in inits):
                raise AssertionError(f'Native passive shadow shim rejected: {inits}')
            graphs = [v for v in payloads
                      if v.get('type') == 'artwatch-shadow-graph']
            nodes = [v for v in payloads
                     if v.get('type') == 'artwatch-shadow-node']
            stats = [v for v in payloads
                     if v.get('type') == 'artwatch-shadow-stats'
                     and v.get('ready') is True]
            kinds = {v.get('kind') for v in nodes}
            record('host',f'Native shadow graphs={len(graphs)} '
                   f'nodes={len(nodes)} kinds={sorted(kinds)} '
                   f'latest-stats={stats[-1] if stats else None}')
            if not graphs or not {'HInstanceFieldGet',
                                   'HInstanceFieldSet'}.issubset(kinds):
                raise AssertionError('Native shim did not validate graph/get/set')
            if not stats or not all(stats[-1].get(k,0)>0
                                    for k in ('graphs','gets','sets')):
                raise AssertionError('Native shim missing expected counters')
            if stats[-1].get('rejected') != 0:
                raise AssertionError('Native shim rejected a pointer/vtable')
            scopes = [v for v in payloads
                      if v.get('type') == 'artwatch-shadow-scope']
            active_scopes = [v for v in scopes
                             if v.get('getVisits',0) + v.get('setVisits',0) > 0]
            total_unique = sum(v.get('uniqueGets',0) + v.get('uniqueSets',0)
                               for v in scopes)
            record('host',f'Native optimization scopes={len(scopes)} '
                   f'with-field-visits={len(active_scopes)} '
                   f'sum-unique-field-nodes={total_unique}')
            if not scopes or not active_scopes or total_unique <= 0:
                raise AssertionError('Native per-compilation observer saw no field nodes')
            if any(v.get('overflow') != 0 for v in scopes):
                raise AssertionError('Native fixed-capacity field inventory overflowed')
            if any(v.get('uniqueGets',0) > v.get('getVisits',0) or
                   v.get('uniqueSets',0) > v.get('setVisits',0) for v in scopes):
                raise AssertionError('Native field inventory has inconsistent counts')
            block_hooks = [v for v in payloads
                           if v.get('type') == 'artwatch-hook-attached'
                           and v.get('layer') in ('graph_add_block',
                                                  'graph_checker_block')]
            constructed = [v for v in payloads
                           if v.get('type') == 'artwatch-block-discovery']
            checked = [v for v in payloads
                       if v.get('type') == 'artwatch-block-checker']
            unique_blocks = sum(v.get('uniqueBlocks',0) for v in constructed)
            checked_blocks = sum(v.get('uniqueBlocks',0) for v in checked)
            record('host', f'Graph block hooks={sorted({v.get("layer") for v in block_hooks})} '
                   f'created unique={unique_blocks} checked unique={checked_blocks} '
                   f'native block callbacks={stats[-1].get("blocks",0)}')
            if any(v.get('uniqueBlocks',0) < 0 or v.get('unmatched',0) < 0
                   for v in constructed):
                raise AssertionError('Invalid graph block discovery counts')
            if unique_blocks and stats[-1].get('blocks',0) < unique_blocks:
                raise AssertionError('Native block confirmations smaller than unique discoveries')
            if 'graph_add_block' not in {v.get('layer') for v in block_hooks}:
                raise AssertionError('Previously verified HGraph::AddBlock export disappeared')
            if not constructed or unique_blocks <= 0:
                raise AssertionError('No block identities observed at graph construction')
            instruction_evidence = [v for v in payloads
                                    if v.get('type') ==
                                       'artwatch-block-instruction-evidence']
            visitor_evidence = [v for v in payloads
                                if v.get('type') == 'artwatch-block-visitor']
            insert_calls = sum(v.get('addInstructionCalls',0)
                               for v in instruction_evidence)
            inserted_fields = sum(v.get('fieldNodeInserts',0)
                                  for v in instruction_evidence)
            visited_blocks = sum(v.get('uniqueBlocks',0)
                                 for v in visitor_evidence)
            record('host',f'Block/instruction bridge calls={insert_calls} '
                   f'typed-field-inserts={inserted_fields} '
                   f'visitor-scopes={len(visitor_evidence)} '
                   f'visitor-blocks={visited_blocks}')
            if any(v.get('mappedFieldNodes',0) > v.get('fieldNodeInserts',0)
                   for v in instruction_evidence):
                raise AssertionError('Impossible block-to-field mapping counts')
            if any(v.get('newlySeenBlocks',0) > v.get('uniqueBlocks',0)
                   for v in visitor_evidence):
                raise AssertionError('Impossible visitor block membership counts')
            ownership = [v for v in payloads
                         if v.get('type') == 'artwatch-field-block-ownership']
            matched_visits = sum(v.get('correlatedVisits',0) for v in ownership)
            get_visits = sum(v.get('getVisits',0) for v in ownership)
            set_visits = sum(v.get('setVisits',0) for v in ownership)
            pairs = sum(v.get('uniqueFieldBlockPairs',0) for v in ownership)
            mismatches = sum(v.get('visitorPointerMismatches',0) for v in ownership)
            record('host',f'Field->block visitor correlation scopes={len(ownership)} '
                   f'visits={matched_visits} get={get_visits} set={set_visits} '
                   f'node/block pairs={pairs} visitor mismatches={mismatches}')
            if not ownership or matched_visits <= 0 or pairs <= 0:
                raise AssertionError('No field instruction correlated with a '
                                     'real HGraphVisitor basic-block callback')
            if get_visits <= 0 or set_visits <= 0:
                raise AssertionError('Visitor ownership missing field get or set')
            if mismatches:
                raise AssertionError('Field Accept visitor did not match active '
                                     'HGraphVisitor::VisitBasicBlock')
            for item in ownership:
                if item.get('uniqueFieldBlockPairs',0) > item.get('correlatedVisits',0):
                    raise AssertionError('More unique ownership pairs than field visits')
                if item.get('uniqueFieldNodes',0) > item.get('uniqueFieldBlockPairs',0):
                    raise AssertionError('More unique nodes than node-block pairs')
                if any(not sample.get('block') or not sample.get('node')
                       for sample in item.get('examples',[])):
                    raise AssertionError('Field ownership example missing pointer')
            # Do not mistake observation during an ART traversal for a
            # direct C++ layout walk, insertion event, or runtime read.
    record('host','PASS: Frida attach + ART discovery + fixture warmup')

if __name__ == '__main__':
    try: main()
    except Exception as e:
        record('host','FAIL: '+repr(e))
        (LOG_DIR/'frida-messages.json').write_text(json.dumps(messages,indent=2))
        sys.exit(1)
