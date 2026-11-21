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

## Read-only backend field lowering experiment

Run 44718929267 passed all required jobs and proved through
`apkanalyzer` that `FieldIRTarget.test(int)` contains `iput` + `iget`
in debug DEX, but *only `iput` + `return p1`* in release DEX.
This is a D8/build-time transformation, not evidence of ART LSE.

`FieldIRTarget.testViaIdentity(int)` now passes the receiver through
a trivial helper before re-reading its field. The release DEX inventory
**strictly requires** the new method to contain both an `iput` and
an `iget`, otherwise CI fails before the emulator starts. This
separates build-time preservation from ART's runtime JIT optimizer.

On API 33 x86_64, the read-only Frida probe also hooks the exported
`LocationsBuilderX86_64::VisitInstanceFieldGet/Set` and
`InstructionCodeGeneratorX86_64::VisitInstanceFieldGet/Set`
entry points. Their `HInstruction*` arguments are verified against
the exact exported field-node vtable. Observer events are associated
with the current compiled method and IR node address; per-compilation
summaries list nodes reaching location assignment and code emission.

**A code emission visitor callback is a compile-time observation, not
a runtime field event**, and neither stage proves an optimized-away
source-level field read executed. All research hooks remain read-only.

Relevant historical AOSP:
https://android.googlesource.com/platform/art/+/0c0043d8cc/compiler/optimizing/code_generator_x86_64.cc

## Exact-node field elimination proof (API 33 release)

Run [44722172785](https://github.com/mnalmahmud/frida-scripts/actions/runs/44722172785)
succeeded with both `iput` and `iget` in the **release**
`testViaIdentity(int)` DEX. ART on API 33 entered real LSE and recorded
seven vtable-validated field-node mutations: in optimized compilation
`kind=2` of a method containing the fixture's field accesses, an
`HInstanceFieldGet*` was replaced by another HInstruction and then
removed. The same pointer had been observed by a compiler visitor
before LSE. Removed nodes were absent from backend location assignment
and emission in that successful compilation. This is compiler-time
elimination, **not a runtime field callback**.

The new `artwatch-field-lifecycle` event combines observations from
the same JIT compilation using `kind + node address` as the temporary
identity. The event records `visitedBeforeMutation`, the ordered
mutation operations, the replacement pointer, and whether the node
reached backend location assignment/code emission. No instruction
memory is accessed after deletion or after compilation.

**Strict API 33 release CI assertion:** a successfully optimized
compilation must include an `HInstanceFieldGet` visited before
replacement/removal during LSE that is absent from backend emission.
As a control, an independently observed baseline compilation must
still emit an `HInstanceFieldGet`. The debug tests retain their
original assertions.

**Method identity caveat:** the DEX-pattern matcher can identify
inlined `iput`/`iget` operations within a caller, not just the
standalone fixture method. Thus this proves elimination of actual
field IR during optimized compilation, but does not claim that the
standalone Java method was individually optimized or that its
source-level access occurred as a physical field load.

This research supports a decision to treat **logical DEX-level field
events** separately from **physical compiled memory accesses**.
A future compiler-side event sink would require side-effect ordering,
exception/GC-safety analysis, field-target resolution and live-value
mapping. No such sink or IR mutation is implemented yet.

## Opt-in API33 P1 native shadow companion

`native/passive-shadow.c` is a read-only NDK shared library for the
**exact** API 33 x86_64 emulator ART ELF build IDs. It checks live
`libart.so` and `libart-compiler.so` GNU build IDs and SDK before
enabling observation. It reads one opaque word from a matched live
`HGraph*`, and checks `HInstanceFieldGet/Set` vptrs against exported
primary C++ vtable address points while the compiler visitor executes.
No ART memory writes or C++ class layout guesses are present.

Only API33 CI opts in via `ARTWATCH_SHADOW_SHIM=1`. An NDK build alone
is not considered evidence: CI requires the native module to load,
verify both mapped build IDs, observe a graph, recognize both instance
field node kinds, and reject zero pointers. API34 remains unchanged.

P1 does **not** traverse HGraph blocks or construct an IR node. The
test covers native-bridge callability and object validation, which
are prerequisites for source-matched native traversal in the next
phase. No field runtime monitoring has been implemented.

## Native-library deployment fix (follow-up)

CI run 44729819209 compiled the native shim on API33 debug and
release, and ART's exact GNU build IDs were present, but both jobs
failed because the app process could not map executable segments from
`/data/local/tmp/libartwatch_shadow.so` (Permission denied). API34 and
static checks passed. **This was a deployment/SELinux limitation, not a
failure of graph or node-pointer validation.**

The shim is now staged at `test/app/src/main/jniLibs/x86_64/` as an
ephemeral NDK build output before `assembleDebug/assembleRelease`.
The APK is built with legacy JNI extraction, so Android installs the
library in the application's native library directory. The Java
fixture loads it with `System.loadLibrary("artwatch_shadow")` in
`MainActivity.onCreate()` before warmup, and the Frida agent resolves
the *already loaded* ELF lazily when the first compiler callback
occurs. No `dlopen` attempt from `/data/local/tmp`, global SELinux
policy change or writable executable file mapping is used.
API34 retains the previous monitoring behavior.

## More reliable release JIT/LSE fixture coverage

Run 44734968302 confirmed the API33 native shim works, with correct
ART build IDs, six graph validations, and native get/set vtable counts,
but the release compiler did not eliminate the targeted get during
that particular warmup (no field-node mutation event). The debug and
API34 jobs passed. This does not invalidate prior exact-node
elimination evidence; it reveals JIT-scheduling/coverage variability.

Release warmup now exercises three **different** naturally hot methods
across five bounded stages, with short sleeps so the optimizing JIT
worker has time to drain its queue: `warmup`, `exerciseOverwrites`
and `exerciseAlternating`. The latter two have read-after-write
operations behind an `identity()` helper, and the release DEX audit
asserts `iput` **and** `iget` survived D8 in each method.
The Frida observation window is extended from 20 to 30 seconds only
for release; it must see all five logcat stage markers.

This is still a natural JIT test. No selective/global deoptimization,
Stalker or compiler mutation is required. Crucially, the strict
same-node LSE replacement/removal assertion is **unchanged**; failing
to provoke elimination will remain visible as a CI failure.

## P1.1 bounded optimization-window field-node inventory

Native `artwatch_shadow_scope_begin/end` now maintains a **thread-local**
fixed-size (512-node) inventory of vptr-verified `HInstanceFieldGet/Set`
objects visited by ART **inside** a matched `RunOptimizations(HGraph*)`
call. The native caller reports get/set visitor counts and distinct
node identities per compilation; no pointers are retained after scope
end and no ART object is modified. The inventory never calls Java,
allocates ART memory or invokes a graph transformation. Overflow is
reported and treated as a CI failure, rather than silently losing nodes.

This is a compiler-visitor observation window, **not** direct traversal
of `HGraph::GetBlocks()`. AOSP uses an `ArenaVector<HBasicBlock*>`
for its block list, but constructing a compatible native reader from
the NDK alone requires layout verification against the exact Android
13 compiler build. We deliberately do not interpret private
`HGraph` offsets or follow guessed pointers at this stage.

Reference for structural IR types (not an ABI guarantee):
https://android.googlesource.com/platform/art/+/refs/heads/android13-d4-s1-release/compiler/optimizing/nodes.h

## P1.2 optional source-backed basic-block discovery

The published ART `nodes.cc` defines `HGraph::AddBlock(HBasicBlock*)`,
and `GraphChecker::VisitBasicBlock(HBasicBlock*)` is a separate
graph-verification boundary. They are candidates for **observing live
basic-block identities without assuming private object offsets**.

The API33 x86_64 probe checks the exact exported symbols, and attaches
read-only callbacks only if present. `AddBlock` pointers must match
the graph candidate captured during the active HGraphBuilder call.
The passive native shim validates the supplied graph/block addresses
without dereferencing HBasicBlock or retaining a pointer after the
callback. `GraphChecker` block observations are logged separately.
Counts are correlated to the active JIT method and its optimization
boundary. Missing exports or inlined call sites are reported as research
gaps, **not** as evidence of an empty graph.

This experiment does **not** claim native traversal of
`HGraph::GetBlocks()`: that accessor is inline, its member layout
is not certified against the emulator ABI, and scanning guessed C++
memory would be unsafe. IR mutation remains disabled.

Source:
https://android.googlesource.com/platform/art/+/refs/heads/android13-d4-s1-release/compiler/optimizing/nodes.cc

## P1.3 optional block-to-instruction and traversal correlation

Run [44763868026](https://github.com/mnalmahmud/frida-scripts/actions/runs/44763868026)
passed all required CI jobs. The API33 compiler exports and executes
`HGraph::AddBlock(HBasicBlock*)`, yielding real block pointers associated
with the exact building `HGraph*`. The native observer confirmed 68
block callbacks on the debug fixture and 343 on release; the sampled
per-method block counts are 29 and 63, respectively.
`GraphChecker::VisitBasicBlock` is exported but no matching
optimization-phase callbacks were captured.

To advance instruction ownership without undocumented pointer offsets,
the P1.3 probe independently observes *all* executed exported
`HBasicBlock::AddInstruction(HInstruction*)` calls, even outside the
original field-builder stack frame. A match to one of the construction
block identities correlates a concrete `HInstruction*` and its
vtable-identified type with its containing `HBasicBlock*`.
The existing `HInstanceFieldGet/Set::Accept` callbacks may then match
that exact `kind@node` identity. This code remains **read-only**.

The experiment separately checks the exported
`HGraphVisitor::VisitBasicBlock` boundary and logs whether the
compiler calls it during optimization; it compares those block
pointers with construction-time identities. AOSP's
`HGraphVisitor::VisitInsertionOrder/VisitReversePostOrder` functions
are inventoried but **never invoked** by the probe. Any method inlined
into its caller may yield no out-of-line callback, and this is
recorded as a research limitation rather than fabricated traversal.

This is not direct `HGraph::GetBlocks()` memory traversal, a mutable
native shim, or runtime field-event emission. The stronger verified
`HGraph::AddBlock` observation is now mandatory in API33 CI.
See AOSP `nodes.cc` for graph visitor/block traversal structure:
https://android.googlesource.com/platform/art/+/c32e770f21540e4e9eda6dc7f770e745d33f1b9f/compiler/optimizing/nodes.cc

## P1.4 source-backed block-to-field instruction ownership

Run [44787102253](https://github.com/mnalmahmud/frida-scripts/actions/runs/44787102253)
passed API33 debug/release, API34 debug and static checks.
`HGraphVisitor::VisitBasicBlock(HBasicBlock*)` is exported and actually
executes: the release compiler recorded 300 basic-block observations
across optimization scopes. The out-of-line `HBasicBlock::AddInstruction`
export continued to produce zero matching insertion callbacks.

The next experiment correlates the *dynamic extent* of
`HGraphVisitor::VisitBasicBlock` (native thread, visitor object and
block pointer) with `HInstanceFieldGet/Set::Accept(HGraphVisitor*)`.
The AOSP `nodes.cc` implementation of `VisitBasicBlock` iterates
phis/instructions and calls `instruction->Accept(this)`.
The Frida probe therefore stores an active visitor/block pair in a
thread-local JS map only until `VisitBasicBlock` returns and accepts
an instruction association only if `Accept` supplies the *same visitor*.
Nested visitors restore previous context in `onLeave`; no stale
`HInstruction*` is dereferenced after a pass.

Per-compilation `artwatch-field-block-ownership` reports unique
field node/block pairs, get/set visit counts, visitor mismatches
and a small set of vtable-confirmed pointer samples. API33 CI
now requires actual correlated get **and** set visits, nonempty
ownership pairs and zero visitor mismatches. This is an observation
of fields traversed in a basic block, not an invocation of
`GetBlocks()` and not a statement that every graph node survives
optimization. Nothing mutates ART memory or invokes ART graph APIs.

AOSP implementation reference:
https://android.googlesource.com/platform/art/+/257ab7fe6885c83f1ab17fe9d4cc4a996ebd3c7e/compiler/optimizing/nodes.cc

## P1.5 exact eliminated field instruction → observed basic block

[Run 44801128480](https://github.com/mnalmahmud/frida-scripts/actions/runs/44801128480)
passed Android API33 debug/release, API34 debug and static checks. Its
release logs correlated **401** `Accept` callbacks to the active
`VisitBasicBlock` frame (127 gets, 274 sets) across **108**
distinct node/block pairs, with zero mismatched visitor pointers.

The release traces also contain four optimized
`HInstanceFieldGet*` nodes replaced and removed during LSE. Each of
these exact instruction pointers appeared in a source-backed
`VisitBasicBlock` callback with a block previously observed via
`HGraph::AddBlock`.

This patch joins the historical block identities to the
`artwatch-field-lifecycle` event using **exact pointer+IR-kind
identity within one compilation**. It asserts that every
LSE-eliminated field-get node has a real, previously observed
basic-block owner and that the corresponding block was seen in
construction callbacks.

Important caveat: an instruction can move between blocks, so
`observedBlocks` contains *historical visitation evidence*,
not an assertion that its final `HInstruction::GetBlock()` equals
any listed address. Removed node memory is never dereferenced.
All instrumentation remains read-only.

## P1.6 read-only field sequence and LSE replacement producer evidence

Run [44802096790](https://github.com/mnalmahmud/frida-scripts/actions/runs/44802096790)
passed all required CI jobs, confirming historical block ownership for
every tested optimized LSE-eliminated field read.

AOSP `HGraphVisitor::VisitBasicBlock` iterates instructions and calls
`Accept(this)`. This experiment records a **bounded per-invocation
sequence of field-node visits** (visitor address, block address, exact
instruction pointer, field IR kind, and relative field-only ordinal).
The map is restored on `VisitBasicBlock` return, even for nested
calls. It does not claim a complete block instruction listing: phis
and non-field instructions are intentionally omitted, and optimizations
may move an instruction between visits.

The experiment also examines LSE `HInstruction::ReplaceWith` calls.
At method entry, both old field node and live replacement SSA
`HInstruction*` are known. For replacements only, the agent matches
the replacement's primary vptr against **explicitly exported,
name-and-address-validated** ART instruction vtables, without calling
virtual functions or interpreting object fields. The IR lifecycle
record exposes the replacement pointer and `replacementKind`
when recognized; otherwise it reports a null kind instead of guessing.

CI requires nonempty, internally consistent field-visit sequences;
SSA producer classification is diagnostic initially because the
compiler may use an instruction kind without a suitable exported
primary vtable. This remains compiler-time, read-only research:
neither Java field values nor actual field-access runtime events are
emitted. These observations define the next ABI verification needed
for a correctly typed, side-effecting event sink.

AOSP reference (structural, not a binary ABI contract):
https://android.googlesource.com/platform/art/+/refs/heads/android13-release/compiler/optimizing/nodes.h


## P2 runtime event transport — executable, but not compiler-injected yet

The previous phase proved compiler-time field identity, block ownership,
LSE replacement/removal, and native pointer validation. It did **not**
deliver an event from executed Java code.

This phase adds a real, bounded, zero-allocation-on-hot-path JNI event
recorder in native/runtime-events.c. It is deliberately packaged as a
separate libartwatch_events.so, with no dependency on private ART layouts.
The C recorder takes (site, read/write, int value), reserves a fixed slot
atomically, publishes the record with release ordering, and counts drops
instead of allocating when its fixed capacity is exceeded. A separate
bounded JSON snapshot is exported for Frida RPC *after* the worker finishes.

The fixture FieldIRTarget.watchedOn(receiver, x) now contains **explicit**
bytecode calls to FieldEventSink.recordInt after a successful field write
and read. It warms the method naturally, resets the event recorder, runs
128 instrumented invocations, and checks a null receiver throws before
any event is recorded. Frida's runtimeevents() RPC returns the actual
native records; CI asserts 256 events, exact per-site integer values,
write/read order, no drops, and the absence of a null-access event.

**Scope and critical distinction:** These are genuine runtime events
from executing JIT-eligible Java code, but the event calls were placed
explicitly in the fixture by Java source. Arbitrary Java field
instructions are **not** yet instrumented; ART IR call insertion is
still required. This isolates the sink ABI, JNI integration, Frida
delivery and correctness from the dangerous next step of compiler IR
mutation. The old strict LSE and native-shadow assertions are retained
unchanged. The prototype covers only successful nonvolatile integer
accesses; no reference or volatile field support is claimed.

Android's supported JNI loading/symbol contract:
https://developer.android.com/ndk/guides/jni-tips
