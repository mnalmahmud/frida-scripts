# ART Fieldwatch Phase 1 — JIT and HGraph research

**Read-only diagnostic:** field interception, graph mutation, DEX rewriting,
deoptimization and native compiled-code patching are NOT implemented.

## Verified compiler interface

GitHub Actions run [44590572013](https://github.com/mnalmahmud/frida-scripts/actions/runs/44590572013)
observed 11 successful JIT compilations on each Android API 33 and 34 x86_64
emulator. API 33 used the exported JitCompiler::CompileMethod; API 34 used
the existing JitCompilerInterface vtable's slot 2. API 34 also exposed
the internal runtime dispatch symbol. ARM64 is unverified.

## New read-only graph boundary experiment (API 33 x86_64)

The actual API 33 `libart-compiler.so` dynamic ELF symbol table includes:
- `art::HGraphBuilder::BuildGraph()`
- `art::OptimizingCompiler::RunOptimizations(HGraph*, CodeGenerator*, const DexCompilationUnit&, PassObserver*)`

The probe now hooks these exact exports, tags callbacks with the currently
compiled ArtMethod pointer and compilation kind on the same native thread,
and compares the candidate `HGraphBuilder::graph_` pointer against the
`HGraph*` argument at the start of `RunOptimizations()`. The CI smoke test
requires hooks, callbacks, and at least one matching graph pointer on API 33.

The `graph_` offset is based on the AOSP `HGraphBuilder` C++ class layout
(`ValueObject` base, `graph_` first member), and MUST be validated on device.
The pointer is never traversed or retained after compilation. This
experiment does not preserve field events yet.

API 34 lacks the corresponding dynamic compiler exports in run 44590572013.
It continues the verified JIT-only smoke, pending a version-specific
pre-optimization interception adapter.

## CI and constraints

Workflow: `.github/workflows/art-fieldwatch-phase1.yml`
Results: `/tmp/artwatch-logs/art-elf-inventory.txt`, Frida messages,
and Android logcat uploaded as artifacts.

Pinned Frida server/client: 17.27.1. Target ultimately API 21–37 and
ARM/ARM64/x86/x86_64; no compatibility claim beyond tested profiles.
No global or selective deoptimization, Stalker or watchpoints.

Source: https://android.googlesource.com/platform/art/
Frida: https://github.com/frida/frida-java-bridge

## First field-builder experiment (API 33 x86_64)

ART instruction builder has non-inline `BuildInstanceFieldAccess` and
`BuildStaticFieldAccess` methods in AOSP. The probe now resolves the exact
candidate mangled exports; only addresses actually found in the device's
compiler library are hooked. It records DEX PC, read/write direction,
the raw field-index code unit (not a resolved field identity), the
active ArtMethod pointer, compilation kind, and builder graph pointer.

A minimal Java fixture performs `value = x; return value;` and runs hot
enough to induce JIT compilation. CI requires an actual instance read and
write compiler callback tied to a live graph. This is read-only:
there is no actual run-time Java field event and no IR mutation.

No field-builder hooks or event counts have been validated until this
commit's emulator jobs complete.

## API 33 read-only node identity experiment

Source: [AOSP instruction_builder.cc](https://android.googlesource.com/platform/art/+/master/compiler/optimizing/instruction_builder.cc)
shows `BuildInstanceFieldAccess` creating either a resolved
`HInstanceFieldGet/Set` or an `HUnresolvedInstanceFieldGet/Set`, then
calling `AppendInstruction`. The latter forwards the actual
`HInstruction*` to `HBasicBlock::AddInstruction`.

A new *optional* API 33 x86_64 probe looks for exact exported
`HInstructionBuilder::AppendInstruction(HInstruction*)`, falling back
to `HBasicBlock::AddInstruction(HInstruction*)`. During an active field
build, it records the passed IR node pointer and its primary vtable
address. If vtable export symbols exist, it compares their Itanium ABI
address points to label the concrete class. No node fields are traversed,
no graph is modified, and no raw pointer is retained past compilation.

The CI test fails if the append hook attaches but does not execute
within field-building context. Missing export symbols are reported as
an explicit *research gap* rather than falsely asserting unsupported ART
or crashing the process. This is not yet a runtime access event.

## Follow-up: out-of-line append versus virtual visitor

Run 44708162512 verified both the `AppendInstruction` export and field
node vtable exports, but zero callbacks reached `AppendInstruction`
while `BuildInstanceFieldAccess` was active. This is consistent with an
inlined call site, not proof that the instruction never enters the graph.

This patch observes `HBasicBlock::AddInstruction` independently and hooks
the exported `HInstanceFieldGet/Set::Accept(HGraphVisitor*)`, plus
static/unresolved variants when available. The latter exposes actual IR
object pointers during ordinary ART visitor passes; per-thread correlation
ties them to JIT compilation without traversing arbitrary graph memory.

It asserts that at least one field IR node is observed via either
insertion or virtual visitor callbacks. Vtable matching distinguishes
the actual node kind, but a visitor event alone does not establish that
a particular DEX instruction survived a specific optimization pass.

## Targeted field IR lifecycle (new experiment)

The 2026-11-20 run 44709847484 passed on API 33 and API 34.
API 33 observed 180 field IR `Accept` callbacks, all matching
their exported class vtables. The two insertion symbols remained silent
during active field-builder hooks, confirming that merely finding their
exports was insufficient.

A new probe identifies `FieldIRTarget.test(int)` through the verified
DEX pattern `iput@0` and `iget@2` (field_idx 0) and independently
records each unique field IR object/class/visitor phase for that method.
It avoids losing the small fixture to the earlier 180-callback sample cap.

AOSP load/store elimination can replace redundant field loads and remove
unnecessary stores. This commit adds **read-only**, opt-in interception
candidates for `HInstruction::ReplaceWith`,
`HBasicBlock::RemoveInstruction`, and `LoadStoreElimination::Run`
if those exact exports exist on the API 33 binary. Offline ELF symbol
inventory records the actual signatures for follow-up corrections.

The test strictly requires the target method and both get/set IR node
types. It does *not* require an elimination event before one is observed,
does not assume pass identity from an arbitrary visitor, and does not
modify compiler memory or deoptimize any Java method.

AOSP sources:
- https://android.googlesource.com/platform/art/+/master/compiler/optimizing/load_store_elimination.cc
- https://android.googlesource.com/platform/art/+/master/compiler/optimizing/nodes.cc

## Test non-debuggable release JIT/LSE — November 2026

Run 44711997095 passed on both API 33 and 34. In the API 33
debug APK, the exact `HInstanceFieldSet` and `HInstanceFieldGet` objects
were observed during the target method's baseline JIT build. Three
mutation/LSE symbol hooks were installed but reported zero target mutations.
Do not interpret this as a negative ART result: AOSP
`LoadStoreElimination::Run` explicitly returns early if
`graph_->IsDebuggable()`, and our APK was previously *only* built
as `assembleDebug`.

The API 33 CI matrix now includes a separately signed,
**non-debuggable** `assembleRelease` APK. Rooted frida-server attaches
normally. The app logs its actual ApplicationInfo debuggable flag,
and the Python harness asserts this flag matches the tested variant.
The non-debuggable fixture performs additional hot calls to target
optimized compilation without touching ART's deoptimization APIs.

Read-only `LoadStoreElimination::Run(bool)` hooks now report every
JIT invocation (bounded output), with the compilation kind and whether
the invocation belongs to the target method, plus the Boolean result
of the pass. Per-method compilation summaries include whether
`RunOptimizations()` ran and how often LSE was entered.

The release job explicitly requires an optimized JIT compilation and
at least one LSE invocation. If either is missing, it fails with
a diagnostic instead of silently reporting an invalid optimization test.

Source: https://android.googlesource.com/platform/art/+/master/compiler/optimizing/load_store_elimination.cc

## CI harness correction after run 44713659551

The API 33 release `assembleRelease` failed in
`lintVitalRelease` because Google Play's
`ExpiredTargetSdkVersion` check rejects the fixture's intentional
targetSdk 28. Suppress only this Play-store publishing diagnostic;
keep remaining lint checks enabled and preserve targetSdk for comparisons.

The API 33 debug test reached ART and observed LSE calls, but the test
method was not identified because adding the debuggable-flag logging
changed the target field's raw DEX index from 0 to 1.
The signature matcher now requires `iput@0` and `iget@2` on
the *same* field index within the same compiled method, regardless
of the actual index. This is a fixture fingerprint, not a general
method-identity mechanism.

## Release DEX / field mutation research follow-up

Run 44716336483 passed API 33 debug and API 34 debug. The new
API 33 non-debuggable release job **booted and ran ART**, including
`LoadStoreElimination::Run(bool)` with several `true` returns, but the
strict target-method DEX fingerprint was absent. Its field-builder logs
contained an `iput` for the target's field index but no corresponding
`iget` in that method. D8 has a redundant-field-load elimination pass
that can remove such a read *before ART sees the DEX*, so **do not
attribute this disappearance to ART LSE without direct DEX evidence**.

The new `ci/dex-inventory.sh` saves the actual debug/release
`FieldIRTarget` smali using Android SDK `apkanalyzer` (or reports
tool unavailability) along with DEX SHA-256 in CI artifacts.

The release CI now requires an optimized JIT compilation and at least
one LSE pass returning `true`, but does *not* require the debug-only
`iput@0/iget@2` DEX fingerprint. The debug CI continues its strict
get/set IR assertions.

The API 33 observer now also recognizes
`HBasicBlock::ReplaceAndRemoveInstructionWith` and
`RemoveInstructionOrPhi`, and records vtable-verified field-node
replacements/removals across **all** compilation methods, not only the
one that may have been transformed by D8. Per-compilation call deltas
distinguish an exported hook from an actually executed call.

The experiment is still read-only. A `true` LSE return does not, by
itself, prove any specific field read was removed, nor does it imply
a runtime field event.

Sources:
- https://r8.googlesource.com/r8/+/main/src/main/java/com/android/tools/r8/ir/optimize/RedundantFieldLoadAndStoreElimination.java
- https://developer.android.com/tools/apkanalyzer
- https://android.googlesource.com/platform/art/+/master/compiler/optimizing/load_store_elimination.cc
