# ART Fieldwatch Phase 1 — JIT and HGraph research

**Research prototype:** early P1 observations are read-only; later P3 experiments
include opt-in compiler mutation restricted to the repository's own synthetic APK.
General field monitoring, template-independent injection, and broad Android/ABI
coverage are not established. The historical sections below describe their
respective milestones.

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

## Verified baseline — 2026-11-24

[CI run 45287652043](https://github.com/mnalmahmud/frida-scripts/actions/runs/45287652043)
for commit `4a5d9abb` passed static checks, API33 x86_64 debug and
non-debuggable release, and API34 x86_64 debug. ARM64 was skipped.
Both API33 jobs reported 256 archived P3 fixture events with exact values,
ordering and DEX metadata, and independently passed the 256-event P2 oracle.
The two P3 cloned nodes reached location assignment and code emission.
Both jobs also passed 14 explicit primitive JNI transport records.
These are separate kinds of evidence; the primitive transport check is not
proof of compiler injection for all primitive types. API34 establishes only
the JIT smoke test, not P3 coverage. The raw-field canary remains a negative
control and general template-independent monitoring is not verified.

The host now additionally validates complete, unique and ordered fixture
completion markers and ties null-access assertions to their own workload.
Static self-tests exercise missing, duplicated, malformed and reordered
markers. This changes validation only, not field instrumentation.

## Independent no-template release workload

The synthetic APK now includes `NoTemplateTarget` and `NoTemplateStaticState`,
with separate instance/static read and write methods and no event sink calls.
CI checks all four leaf methods against the actual packaged DEX: exactly one
matching field opcode and a return, with only register moves/nops additionally
allowed. The read/write IDs must agree for each of two independent fields.
The release workload checks 128 iterations, signed integer results, checksum
-16768, and separate null-read/null-write exceptions. This is a workload and
DEX-shape oracle only; it does not record runtime events and is not evidence
of a template-independent instrumentation backend.

## Stock ART synthetic leaf-method oracle

The source-built ART experiment is not part of the active project path. The
release CI instead runs a separate official Frida Java bridge check against
the four fixed leaf methods in the repository's own APK. The packaged DEX
oracle establishes that each leaf contains exactly one corresponding field
operation and no invokes. The independent runtime test records successful
method arguments/returns, not arbitrary field instructions, and checks 512
records and two null exceptions. No ART source build is required.

This is a reference measurement only. It is not a template-independent
field-opcode interception backend, does not observe eliminated operations
or inlined callers, and does not establish arbitrary field coverage.

## Stock-ART nterp instruction interceptor (research, API33 x86_64)

`nterp-field-probe.js` attaches **to actual 128-byte nterp opcode handler
entries** for instance/static integer reads and writes plus allowed successor
opcodes. Unlike the Java leaf-call oracle, the callback is reached only when
ART dispatches a DEX field instruction through nterp. The handler's own
`r12` DEX instruction pointer and `r13` virtual-register frame are read.
A successful field operation is recognized when nterp dispatches its immediate
successor; the read value is taken from the destination virtual register,
and the write value comes from the input register, not from a second field
read. Failed/null operations do not reach the immediate successor.

The host extracts actual ELF symbol offsets for
`artNterpAsmInstructionStart/End` from the pulled `libart.so`, checking
an exact 32768-byte opcode table and the pinned GNU Build ID. The agent
independently verifies the **live mapped** ELF Build ID before attaching.
The separate non-debuggable `fieldwatch_nterp` process exercises four DEX
methods with no authored event-sink calls. CI checks 512 exact-value
nterp events with runtime instruction addresses and static DEX identities.
**This is not a claim about JIT, AOT, switch-interpreter, other APIs or ISAs.**
Field PCs are mapped from the verified fixture catalog rather than measured
from the method code-item base. Source-backed assumptions remain gated to
this precise ART build; unrelated binaries must fail closed.

The isolated test activity now starts idle and only executes field code
when the host has attached and armed the opcode probe. The test hooks only the
four actual integer field opcode slots and the two immediate return handlers,
avoiding per-instruction overhead in unrelated move handlers during startup.

A CI startup tombstone showed that instrumenting the nterp handlers before
Android application initialization was unsafe. Hooks are now installed only
on the host's explicit arm request after the separate process reaches an idle
state. This is a safety gate, not yet proof that nterp instruction hooks execute
correctly. If a hook triggers an ART crash or zero events, CI must fail.

## Hardware breakpoint nterp experiment (2026-11-24)

Inline Frida interception of Android 13's shared nterp opcode handler entries
crashed stock ART in two separate CI emulator runs. That unsafe path has now
been removed. This experiment uses Frida's documented per-thread **hardware
execution breakpoints** and native exception handler instead, avoiding edits
to ART executable memory. Four slots observe iget/iput/sget/sput on the single
synthetic worker thread, temporarily redirecting the slot to the next DEX
opcode handler to sample successful reads and writes. The ELF build-ID gate,
DEX identity checks, and strict 512-event host oracle are retained.
Hardware breakpoint availability and runtime correctness still require CI
verification; this is not JIT/AOT or general app-wide coverage.

The first hardware-breakpoint emulator run reached 511 executed field events
before an exception-path overlap: a failed null field access skipped its
successor, leaving its temporary breakpoint pending. The callback now restores
that slot when the next field handler executes and discards the unsuccessful
access. The isolated test pre-initializes the second declaring class before
arming the recorder so the 512-event measurement does not mix its initial
class-linking path with the steady-state nterp path. These are experimental
correctness fixes; no JIT/AOT or exception-coverage claims are implied.

## Data-driven nterp field-site selection

The API33 x86_64 hardware-breakpoint agent now consumes a configurable list
of exact `methodClass` / `methodName` / `fieldName` selectors from the actual
packaged DEX catalog, or all supported integer sites if no selectors are
provided. It no longer embeds the four fixture method names. The separate
CI oracle supplies those four selectors explicitly and verifies class/field
names, DEX SHA-256, method/field indices, source metadata, and values.

The current runtime adapter **requires one packaged DEX** and refuses repeated
same-method/same-field/same-opcode sites, since an ArtMethod DEX method index
alone cannot safely disambiguate multiple DEX files/class loaders or recover
multiple source DEX PCs. `dexPcSource=single-candidate DEX site` makes this
provenance explicit. Runtime code-item binding, multi-DEX and class-loader
identity are still needed before claiming app-wide monitoring.

## Runtime watcher configuration and cleanup

The Frida nterp agent now accepts a required `__artwatchNterpThreadFilter`
(string): an exact native thread name or `*` for an explicitly requested
all-thread watch. The CI test pins `NterpFieldProbe` to avoid unrelated work.
The agent limits concurrent watched threads to 64 and exposes `rpc.stop()`
to detach the thread observer and remove remaining hardware breakpoints.
The CI host calls stop before detaching. Watching all threads on a stock ART
process is still experimental; no claim of general thread/exception coverage
is made from the single-worker test. The DEX selector is covered by dedicated
Node tests, including ambiguous-site and missing-selector rejection.

## Non-leaf field operation execution

The nterp hardware-breakpoint state machine now tracks **any immediate DEX
successor**, not only `return` and `return-void`. If the next opcode is also a
watched field operation, it reuses that hardware breakpoint and samples the
completed operation before beginning the next one. It handles consecutive
same-opcode instructions without duplicate breakpoint addresses.

The synthetic non-debuggable APK includes `NoTemplateTarget.complexStep`,
which uses both `value` and `other` fields in one method, with intervening
method calls and ordinary computations. The runtime oracle now verifies the
original 512 leaf accesses and **512 additional non-leaf field accesses** in
DEX order and with exact integer values. If the packaged DEX does not retain
all four non-leaf operations, CI must reject it before claiming coverage.

## Runtime DEX PC binding and repeated field operations (2026-11-24)

The stock nterp hardware-breakpoint backend now requires the catalog to
contain exact instruction bytes for every field-bearing DEX method. At the
executed field handler, it takes the **live** nterp DEX instruction address,
finds a candidate method instruction base using the packaged site offset,
then checks the complete method instruction bytes against readable process
memory before accepting that site. It caches the base by observed ArtMethod
address and reports `runtimeMethodAddress` alongside the resolved DEX PC.

This replaces the former single-candidate inference. Multiple accesses to
the same opcode/field ID in one method are now represented by distinct DEX PC
keys. Unmatched or ambiguous code bytes yield no event, with an explicit
`unverifiedSites` diagnostic counter. If ART quickens or alters instructions
relative to the packaged DEX, the current implementation rejects that method
instead of pretending the packaged PC is proven.

The non-debuggable isolated workload adds `repeatedStep`, with two writes
and two reads of the same instance field, and retains `complexStep`.
The strengthened CI oracle requires 1,536 executed field operations in the
original order, including 512 repeated-site operations, exact read/write values,
DEX PCs, and two failed null accesses with no successful events.

This verifies instruction identity **within one exact packaged DEX** only.
It does not authenticate the class loader for the observed ArtMethod,
instrument quickened field opcodes, or extend coverage beyond the explicitly
verified API33 x86_64 nterp build. The live full-method byte comparison is a
correctness gate, not a generic decompilation/resolution mechanism.

## Exact float field payloads on the int-family nterp handlers (2026-11-24)

On the pinned API33 x86_64 ART build, ordinary `iget/iput/sget/sput`
opcodes access both DEX `I` (signed 32-bit integer) and `F` (IEEE754
32-bit float) field descriptors. The Frida nterp backend now distinguishes
the descriptor from verified packaged DEX metadata, sampling float vregs
as `readU32()` **raw IEEE754 bits**. It labels the value representation
`raw-u32-ieee754`; it does not convert floats through JavaScript Number,
which would lose exact NaN payload provenance. Integer events retain their
signed 32-bit representation.

The non-debuggable test workload adds separate instance/static float
read and write methods, tests negative zero, a NaN with payload bits,
subnormal 1 and negative infinity, and checks the observed 32-bit
payload on each side of all four field operations. The oracle now requires
2,048 selected field events per run, 2,050 attempted field matches
including two unsuccessful null instance accesses, and zero ambiguous
runtime DEX sites.

This is deliberately **not** an implementation of `iget-wide`/`sget-wide`
(`J`/`D`), object references, narrower primitive opcodes, quickened
field operations, native JNI field writes, switch interpreter or compiled
field instructions. Those need separate opcode and data layout handling.

## Wide64 nterp field-opcode family (2026-11-25)

The stock ART API33 x86_64 breakpoint adapter now supports a selectable
`__artwatchNterpOpcodeGroup`: `scalar32` (0x52/0x59/0x60/0x67) or
`wide64` (0x53/0x5a/0x61/0x68). These are **separate measurement
passes**, not simultaneous complete field coverage. Only four hardware
execution breakpoints are allocated on the selected worker thread.

Wide DEX field descriptors `J` and `D` are read as the consecutive pair
of 32-bit virtual-register slots in the pinned x86_64 nterp shadow frame.
The agent emits a lossless 16-digit hexadecimal string, `0x...`,
including leading zeroes; `J` uses `raw-u64-le` provenance (raw bits
assembled from two little-endian 32-bit words) and `D` uses
`raw-u64-ieee754`. JavaScript `Number` and floating-point conversion
are never used to transport these values.

The non-debuggable release APK exercises instance/static field writes
and reads for `long` and `double`, including changing high and low
halves, negative zero, subnormal doubles, infinity, and a noncanonical
NaN payload. A dedicated second run starts a **fresh isolated process**
after the scalar32 pass. It checks 1,024 actual wide field accesses,
DEX PC and ArtMethod identity, correct opcode/field descriptors, and exact
64-bit read/write payloads. Unknown ART builds, nonmatching packaged
DEX method bytes, and other field opcodes still fail closed or are
outside this adapter's scope.

The two-run coverage is scoped to this synthetic workload. It is not
an app-wide simultaneous field watch and does not cover JIT/AOT/native,
reference fields, quickened opcodes, or other Android ART builds/ISAs.

## Conservative multi-DEX runtime method binding (experimental)

The packed DEX field catalog can now include multiple ordered `classes*.dex`
files, each with its own SHA-256 identity and method index scope. The
interceptor indexes candidate methods by DEX method index, then requires
the **entire exact runtime instruction stream** to match one, and only
one, packaged DEX candidate for the observed field opcode/operand/PC.
Repeated accesses remain distinguished by exact live DEX PC. The
per-ArtMethod cache retains both the chosen code-item base and its DEX
candidate; it cannot silently switch DEX mappings afterward.

Identical method bytes from more than one DEX are an ambiguous match;
the agent refuses to emit a field event and increments
`unverifiedSites`. Likewise, quickening or instruction rewriting can
cause valid methods to be rejected. The probe does not yet read the
actual ART DexFile ownership pointer, class-loader identity, or
cross-APK split/install-time DEX contents. Bytecode-equivalent methods
from a DEX outside the packaged catalog may still collide; **there is
no assertion of general arbitrary-app attribution** until runtime
DexFile identity is authenticated independently.

The existing synthetic release fixture is still single-DEX. Multi-DEX
selection and method-index collisions are currently static regression
tests only; runtime execution across distinct DexFiles remains pending.

## Narrow primitive nterp field opcode families (2026-11-25)

The pinned API33 x86_64 interpreter backend additionally supports four
independent four-breakpoint passes: `boolean8` (`iget/iput/sget/sput-boolean`,
0x55/0x5c/0x63/0x6a), `byte8` (0x56/0x5d/0x64/0x6b), `char16`
(0x57/0x5e/0x65/0x6c), and `short16` (0x58/0x5f/0x66/0x6d).
The catalog requires the matching field DEX descriptor (`Z`, `B`,
`C`, or `S`) and valueKind; mismatches are not reported.

The observer reads from the nterp interpreter's 32-bit virtual register
slots at the hardware trap (before a write / after a read), normalizing
the result to the actual stored narrow width: unsigned 8-bit for Boolean
(`unsigned-boolean-byte`), signed 8-bit for byte (`signed-int8`),
unsigned 16-bit for char (`unsigned-int16`), signed 16-bit for short
(`signed-int16`). This is a raw byte representation for Boolean, not
a claim that arbitrary noncanonical Boolean byte patterns have been
tested. No live object reference is converted to a JS/Java wrapper.

The non-debuggable release APK contains separate instance/static
setter/getter methods and 128 iterations of changing boundary-crossing
values per type. The CI harness runs each opcode family in a separate
process, validates the exact packaged DEX instructions and runtime DEX
PC/ArtMethod binding, and requires **512 exact events per family**
(2,048 additional accesses across the four narrow passes). Static
oracle tests reject malformed values, missing events, incorrect field
opcodes, and mismatched metadata. This is **not** simultaneous all-field
coverage: only one opcode group fits the four hardware execution
breakpoint slots at a time.

Across scalar32, wide64 and the four narrow families, the current
fixture expects 5,120 exact field-access events over six isolated
measurements. The backend remains limited to one pinned ART build,
nterp execution, selected methods and their matched DEX bytes. It
does not cover compiled field accesses, object references, or all
threads of arbitrary applications.

## Experimental thread-local nterp Stalker backend (2026-11-25)

The first all-primitive software-handler experiment, commit
\`2e9ab136\`, used \`Interceptor.attach\` to hook shared ART handler
entrypoints. **This approach failed the non-debuggable emulator test**:
the Android main thread crashed with SIGSEGV during field resolution,
even though the callbacks filtered for the separate worker thread.
Register-preservation/stack assumptions cannot be made safe simply by
ignoring callbacks from other threads. It is intentionally not
considered a working backend.

The replacement \`nterp-software-probe.js\` prototype uses Frida
\`Stalker.follow(tid, { transform })\` on the **named worker thread
only**. Its transformer checks each original instruction address
against the selected nterp opcode handler entries and inserts
\`iterator.putCallout\` at selected field handlers and their successor
handlers. No process-wide ART handler entries are overwritten, no ART
binary or DEX is modified on disk, and no CPU debug-register
breakpoints are consumed. The callout captures vregs before a field
write, or after a successful read at the successor handler. Failed
null accesses never complete through the recorded successor. The
same exact DEX method-byte and live DEX-PC provenance checks apply.

The new experiment uses
\`ARTWATCH_NTERP_BACKEND=software ARTWATCH_NTERP_GROUP=allPrimitives\`
for compatibility with the runner's existing environment. A single
strict API33 non-debuggable release execution must yield 5,120
ordered field operations (all primitive kinds) and reject the two
failed null accesses. Until that runtime oracle passes, this is an
experimental *not-yet-verified* instrumenter, not a claim of complete
Java field monitoring.

Stalker rewrites instructions in a thread-local code cache and
therefore has substantial cost and compatibility risks with ART
interpreter control flow, indirect jumps, and register conventions.
A targeted worker-thread experiment cannot establish simultaneous
app-wide coverage, object reference safety, JIT/AOT coverage, or
support for other ART builds.


## Concurrent worker-thread coverage test (2026-11-25)

A separate experimental Stalker release test runs two Java threads
named \`NterpFieldProbe\` concurrently, with independent receiver
objects and disjoint 32-bit integer value ranges. A coordinator
holds both workers on a \`CountDownLatch\` until the host confirms
\`threadsFollowed==2\` from the Stalker agent, then releases both via
a separate Activity intent. No method hooks or injected Java event
recorders are used.

The Stalker agent now tags each event with its actual OS \`threadId\`.
The test requires 512 successful \`iput\`/\`iget\` accesses overall,
then checks the 256 read/write records of **each** thread separately,
with exact values, method identity, DEX PC, and consistent ArtMethod
bindings. Globally interleaved event sequence numbers must remain
contiguous, but the verifier makes no assumption about relative
scheduling or which thread executes an access first. Two actual
worker TIDs must have been followed. No global ART handler entry
is patched.

This is a concurrency test scoped to two named threads executing
a known nterp workload. It does not demonstrate automatic coverage
of an arbitrary application's UI, GC, JIT or AOT compiled threads.

## GC-visible object field snapshots (experimental, 2026-11-25)

The new `allFields` Stalker mode extends the 24 primitive opcode handlers
with `iget-object` (0x54), `iput-object` (0x5b),
`sget-object` (0x62), and `sput-object` (0x69). It accepts only
object/array DEX field descriptors, requires the exact packaged
`registers_size` for each object-bearing method, and verifies the
running DEX instruction stream and live DEX PC before attributing an
event.

ART nterp keeps a separate, GC-scanned array of 32-bit reference
registers immediately below its ordinary virtual registers. The
probe reads the corresponding **GC-visible root slot** at the
field-opcode boundary (before a successful write, after a successful
read); it never dereferences the object or converts a raw compressed
reference to a JNI handle. The record carries
`raw-nterp-gc-root-u32-ephemeral`, `referenceIsNull`, and
`referenceSnapshotGcStable:false`. The 8-digit hex payload is
exact *at observation time* but is **not a stable object identity**:
a moving GC can change the underlying reference bits after capture.

An independent non-debuggable release mode selects both the 24
primitive and four object field opcode families in **one** named
worker-thread Stalker execution. Its oracle requires 5,632
real field events per 128 iterations: 5,120 primitive events and
512 object reference events, with alternating null and nonnull
instance/static object slots, exact method/field/DEX-PC attribution,
and two unsuccessful null-receiver attempts excluded from completed
events. The Java workload keeps the two nonnull objects strongly
reachable while exercising real object-field getters and setters.
A separate static oracle rejects invalid reference metadata, raw
bit patterns, descriptors, and counts.

**This is not complete GC-safe Java object observation.** It does
not pin objects, track identity through compaction, inspect fields of
the referenced object, or resolve Java class/member values for a
recorded reference. Those require ART-native rooted handles or JNI
references created within a valid mutator state. Similarly, this
nterp Stalker backend does not observe field instructions executed
in compiled JIT/AOT code, alternative ART interpreters, or all
Android versions and CPU architectures.

## Run the nterp field watcher on a permitted Android application

`watch.py` is a generic (non-fixture-specific) Frida host frontend.
It indexes the **exact APK DEX bytes**, creates a restricted field-site
catalog, attaches to the process, arms the same thread-local Stalker
opcode backend, and streams DEX-attributed JSONL events. The output
preserves global sequence numbers even when batches are drained.

Requires an authorized Frida connection, the application's matching
APK, a prevalidated `nterp-profile.json`, and the **exact pinned
API33 x86_64 libart build**. It rejects a different build ID/API/ISA
instead of guessing offsets. To inspect a specific field:

```sh
python3 art-fieldwatch-phase1/watch.py \
  --apk /path/to/base.apk \
  --profile /path/to/nterp-profile.json \
  --process com.example.app \
  --thread MyWorker \
  --field 'Lcom/example/Worker;#perform#counter' \
  --duration 30 --output events.jsonl
```

To observe all field instructions found in the supplied APK that
**actually execute in nterp on followed threads**, choose
`--all-fields` and an explicit `--thread '*'`. The wildcard is
high-overhead and has not been established to be safe or complete
for an arbitrary app's main/GC/foreign threads. A field's inclusion
in the packaged DEX catalog is not proof that it executes; compiled
and dynamically loaded code remain outside the coverage scope.
Use `--primitives-only` to exclude object reference snapshots.

The agent's `rpc.exports.drain(limit)` returns a bounded batch and
preserves a monotonically increasing per-process sequence number,
so a continuous host can consume more than 8192 operations without
dropping records due only to the original finite event-array capacity.
The host treats any dropped event, ambiguous DEX method, or agent
diagnostic as an error. It never claims that unintercepted compiled
instructions were observed.

Offline integration validation:
`python3 art-fieldwatch-phase1/watch.py --self-test`.

## Second stock ART profile: Android 34 x86_64 (2026-11-25)

Android 34's stock `libart.so` image from the CI emulator has a
distinct GNU Build ID, `b6dc79e02101ea00827a35a55ab6597a`. It
has a full ELF symbol table. The offline `nterp_profile.py`
now accepts **only** this explicitly allowlisted API34 build in
addition to the previously verified API33 build, and still requires
unique nterp start/end symbols, a 256 × 128-byte handler table,
and x86_64 ET_DYN ELF structure.

A new non-debuggable API34 release CI job produces the profile from
the **actual pulled libart.so**, checks its live Build ID again inside
Frida, and runs strict single-pass 5,120-primitive and
5,632-primitive-plus-object oracles. This is a portability gate,
not a general claim that all API34 OEM ART builds work: any Build ID
or table layout discrepancy is a hard failure. The API34 compiler
native shim is intentionally not reused from API33.

The general `watch.py` host now recognizes both allowlisted profiles,
but no other API/architecture without equivalent runtime validation.

## Base and split APK DEX catalogs

The host CLI accepts repeatable `--apk` arguments. Provide the
installed base APK first, followed by each split APK containing DEX
in their expected loader order:

```sh
python3 art-fieldwatch-phase1/watch.py \
  --apk base.apk --apk split_feature.apk \
  --profile nterp-profile.json \
  --process com.example.app --thread MyWorker \
  --all-fields --duration 30 --output events.jsonl
```

The frontend merges the inventories into a single ordered catalog,
remaps per-APK `dexId` indexes, and carries `dexLocation` such as
`split_feature.apk!classes.dex` into observed field events. This
preserves identity without assuming that a method index is globally
unique across different DexFiles. It does not currently attest
runtime class-loader ownership or code loaded after catalog creation:
byte-equivalent candidate collisions fail closed where detectable.

## Exact DEX method prototypes and overloaded-method selectors

The field catalog now includes the complete DEX method prototype,
`(parameterDescriptor...)returnDescriptor`, obtained directly
from `proto_id_item` and the type list in the installed DEX bytes.
Field access records preserve `methodPrototype` next to the
declaring class, method name, field ID, and DEX PC.

A field selector may optionally include this method prototype to
distinguish overloaded methods with the same name and field access:

```sh
python3 art-fieldwatch-phase1/watch.py \
  --apk base.apk --profile nterp-profile.json \
  --process com.example.app --thread Worker \
  --field 'Lcom/example/Worker;#update(I)V#counter'
```

The old unqualified `Class#method#field` selector remains valid,
and matches all overloads. Runtime attribution still requires an
unambiguous full DEX byte-stream match for each ArtMethod.

## Automated ART profile verification and observation report

Instead of providing a saved JSON profile, pass `--auto-profile` to
have the host query Android's API/ABI over adb, pull the device's
installed libart.so from an APEX or system library path, and validate
its exact build ID, ELF architecture, and nterp table symbol bounds.
Only allowlisted ART binaries are accepted. This never guesses a
nterp handler address or modifies a system image.

The optional `--coverage-output observed.json` produces a per-site
count for every field instruction from the selected packaged DEX
catalog, with dexLocation, class, full method prototype, field,
opcode and DEX PC. Its explicit scope is **sites observed in nterp**.
A zero count cannot distinguish unexecuted code from an execution
handled by compiled JIT/AOT, JNI, or another interpreter, and is not
a claim of missed instrumentation or complete program coverage.

## Live overloaded-method attribution regression

The release APK has separate `overloadedWrite` and `overloadedRead`
Java methods taking either an `int` or a `long` argument. The
field names, declaring class, and method names deliberately overlap,
but the packaged DEX method prototypes and method IDs differ. A
strict on-device Stalker test selects all four exact prototypes and
checks 512 ordered real field operations with two distinct value
ranges, matching live ArtMethod and DEX-PC identities. Both the
API33 and API34 x86_64 non-debuggable release jobs run this oracle.

The runtime event record includes `methodPrototype`, while an
unqualified `Class#method#field` selector remains a deliberate
wildcard across overloads.

## End-to-end host CLI release oracle

`ci/run-generic-watch-smoke.py` starts the separate non-debuggable
fieldwatch Activity process and invokes **the public `watch.py` CLI**,
using `--auto-profile`, four exact overloaded-method selectors,
and a 15-second live Frida attachment. Only after the CLI confirms
that the Stalker observer is armed does the host start the Java
workload.

The independent oracle reads the emitted JSONL stream and requires
512 contiguous, exactly attributed read/write field records with
signed values and full DEX prototypes. It also reads the
`--coverage-output` report, requiring all four selected sites
to have been observed exactly 128 times each. Both non-debuggable
API33 and API34 release jobs include this test; an offline
`py_compile` gate checks the runner before building an APK.

This verifies the *actual user-facing host tool* rather than
only embedded synthetic Frida scripts. It does not expand monitoring
to JIT/AOT/native or unallowlisted ART versions.

## Sustained host-streaming integrity regression

A separate non-debuggable runtime workload now performs 10,000
`iput` writes and 10,000 `iget` reads of the same instance field
through two ordinary Java DEX leaf methods, with deterministic
individually verified integer values. The public `watch.py` host
arms Frida Stalker on the executing worker thread and polls the
agent's `drain()` RPC every 20 ms, collecting JSONL records.

The oracle requires 20,000 **actual emitted field events**, strictly
monotonic and contiguous event sequence numbers, exact int32 read
and write values, opcode and method identities, provenance-checked
DEX PCs and two selected DEX sites observed 10,000 times each. It
is intentionally larger than the earlier 8,192-record fixed queue
to validate genuine host-to-agent draining rather than simply
increasing a static event buffer. Any queue overrun, unverified DEX
site, or Stalker callback diagnostic must fail the test.

Test implementation:
`ci/run-generic-stream-smoke.py`. This tests transport and
high-frequency field attribution under the existing **nterp-only**
coverage; it does not imply compiled-code or arbitrary-thread coverage.

## Watch a field across every caller method (field-centric selector)

The public CLI now supports `--watch-field
'Lpackage/DeclaringClass;#fieldName'` to select a **declared Java
field**, not one particular method that reads or writes it.
The APK DEX indexer enumerates every matching `iget/iput/sget/sput`
site across all packaged DEX methods, retains its actual caller
class, full method prototype and DEX PC, and sends the reduced
exact instruction-byte catalog to the nterp Stalker.

```sh
python3 art-fieldwatch-phase1/watch.py \
  --apk base.apk --auto-profile \
  --process com.example.app --thread MyWorker \
  --watch-field 'Lcom/example/Account;#balance' \
  --output field-events.jsonl \
  --coverage-output observed-sites.json
```

`--field` remains useful when only one executing method should
trigger observations. `--watch-field` matches all callers in the
supplied **packaged APK DEX catalog**; it does not intercept
nterp-independent JIT/AOT, JNI, dynamically loaded DEX, nor
unfollowed threads. A DEX site indexed in the catalog but absent
from the observation report's nonzero sites may simply never run.
The Android 33/34 generic-CLI release tests exercise this
field-centric selector against four different overloaded caller
methods and still demand their 512 exact runtime events.

## Select several worker threads without following the whole process

The host CLI accepts `--thread-regex '^Worker-[0-9]+$'` as an
alternative to `--thread Worker` or the broad `--thread '*'`.
The agent uses one precompiled JavaScript RegExp to filter
`Process.attachThreadObserver` additions and renames, then
`Stalker.follow(tid)` on only matched live threads. This is useful
for independently named Java worker pools and avoids forcing a
potentially dangerous all-thread follow.

The two-worker Android runtime oracle now names the workers
`NterpProbe-0` and `NterpProbe-1`, selects them both
with `regex:^NterpFieldProbe-[01]$`, and requires 256 exact field
operations from each thread. This does not establish safety for
arbitrary non-Java/GC/Frida threads or compiled instructions.

## Streaming and worker-name fixes (2026-11-27)

CI run 45692194383 identified two independent regressions:
the Android Linux task `comm` name is limited to 15 bytes, so
`NterpFieldProbe-0/-1` was truncated and never matched the
`regex:` filter; and the 20,000-field-operation workload overflowed
the 8,192-record buffer by 3,670 events before a host RPC poll.

The worker-thread experiment now uses `NterpProbe-0/-1`
(12/12 bytes) and matches precisely those names. The *public CLI*
enables batched asynchronous Frida `send()` transport, batching
128 completed field events per message. Non-CLI synthetic snapshot
tests still use the original RPC/snapshot mode, so their verifiers
are unaffected.

The Python host queues delivered batches without doing I/O in
Frida's callback, merges RPC-tail records into a single sequence,
flushes only contiguous sequence IDs, enforces a bounded queue and
a fail-closed duplicate/gap check, then verifies the final agent
`totalRecorded` count. The strict 20,000-operation Android 33/34
release oracle remains the acceptance criterion. Batching reduces
pressure on the in-process ring; this is not a guarantee of
unbounded-rate/lossless monitoring without backpressure.

## Read-only or write-only DEX site selection

The generic host supports `--operation read` or `--operation write`,
or the default `--operation both`, with `--watch-field`,
`--field` and `--all-fields`. This filters opcode sites in the
verified packaged DEX catalog **before** initializing the Stalker
rather than discarding events after interception. Per-method
instruction streams and the original DEX IDs remain unchanged, and
the coverage report counts only the selected read or write sites.

Example: `--watch-field 'Lcom/example/Account;#balance' --operation write`
watches successful stores to that declared field from every selected
DEX caller on followed threads; compiled, JNI and dynamic-code
stores remain outside the nterp-only scope.

## Asynchronous event-delivery regression test

`ci/stream_transport_test.py` runs the real generic `watch.watch()`
host pipeline using a minimal mocked Frida device/agent. It delivers
the first two 128-style batches in reverse order, then returns a
trailing event through the ordinary `drain()` RPC. The oracle
requires contiguous ordered JSONL output and exact per-DEX-site
coverage counts, and separately verifies that a duplicate event
sequence causes a hard error. It does not fake an ART runtime result:
the separate Android 33/34 20,000-event release workloads are
required to verify actual Frida/Stalker performance and safety.

## API33 stock ART JIT field code-emission backend (experimental)

`jit-field-emission-probe.js` hooks the real optimizing compiler's
x86_64 `InstructionCodeGenerator::VisitInstanceFieldGet/Set`, associated
with an active `JitCompiler::CompileMethod` on the compiler thread.
It verifies the **runtime and compiler mapped ELF Build IDs** against
the known stock Android 33 release pair before interpreting any
private compiler layout or attaching hooks. The compiler may be
loaded lazily; an ART module observer installs after its mapping
appears. For each HInstanceFieldGet/Set, it checks the exact exported
instruction vtable and source-matched `dex_pc_` layout, then
correlates that DEX PC with the packaged APK's verified field site
catalog. It records compiler success and candidate identities.

The release APK test `ci/run-jit-field-emission-smoke.py` first
warms unrelated actual ART field methods to load the compiler.
It then observes two deliberately sink-free DEX leaf methods,
`NoTemplateTarget.writeInstance` and `readInstance`, called
40,000 times through Java reflection so the calling method cannot
inline the leaf call. The oracle requires both field get/set
codegen visits and exact DEX site correlation, preserving a JSON
report of matched field nodes.

**This is not yet an executed-field-value backend**. Inlining,
load-store elimination, instruction reordering, and the absence
of a verified native-code PC map still prevent equating a compiler
field node with an exact executed field event. The conservative
records expressly set `valueAvailable:false`,
`dexFileRuntimeVerified:false`, and
`nativeInstructionOffsetKnown:false`. Arbitrary DEX/ArtMethod
identity collisions and all AOT/ARM64/other versions are unsupported
until validated. This is an entrypoint for generalized compiled-code
runtime instrumentation research, not an assertion of full JIT/AOT
field interception.

## Android 14 ARM64 nterp runtime port (experimental)

The nterp software agent now has an ARM64-specific register decoder,
separate from the proven API33/34 x86_64 ABI:

- `x22` = DEX PC, `x29` = 32-bit DEX virtual-register array,
  `x23` = current instruction, `x24` = handler table base,
  `x25` = ART GC-visible reference-slot array.
- `sp[0]` = active `ArtMethod*`; the same exact packaged DEX
  code-byte validation checks method index, opcode, field index and PC.
- Primitive and wide values are copied from the DEX registers;
  references are read **only as ephemeral compressed GC root bits**
  and are never dereferenced as `jobject`/JNI handles.

These assignments come from AOSP
`runtime/interpreter/mterp/arm64ng/main.S`; they must be
revalidated on each installed stock binary. The ARM64 path requires
**both** `--experimental-arm64` and a matching ELF-derived
`--auto-profile` (or a previously resolved profile), including
its GNU Build ID, architecture, exact table-symbol offsets,
handler size and opcode count. An incorrectly signed/absent profile
does not enable a fallback or a guessed hook location.

A dedicated Android 34 **non-debuggable release** macOS Apple Silicon
CI job builds the APK, inspects the installed ARM64 `libart.so`,
and runs the 512-event overloaded and 20,000-event stress oracles
against genuine ARM64 opcode handlers. Until that job passes, ARM64
is *experimental*, not validated. Unlike x86_64, the ARM64 entry
is dynamically pinned to the **actual pulled** ELF Build ID
rather than a multi-device allowlist; it is deliberately not
auto-enabled for unrelated apps/builds.

## GC-stable object identity through JNI weak roots (experimental API33 x64)

`--reference-identity` is an explicit opt-in to a new private ART/JNI
bridge, separate from the default raw reference snapshotter. The
bridge `jni-reference-ledger.js` starts **only after exact mapped
ART Build-ID verification** on Android 33 x86_64 and resolves the
private `JNIEnvExt::NewLocalRef(mirror::Object*)` entrypoint. It
uses that ART-internal native method to turn a validated nterp
reference-slot object pointer into a genuine JNI local handle,
then immediately creates a **JNI weak global reference**, releases
the local and assigns a monotonic `art-ref-N` ID. Subsequent
field events use JNI `IsSameObject` against these weak roots;
cleared weak roots are cleaned up, and all remaining references
are released when monitoring stops.

This is fundamentally different from (invalidly) passing a
compressed 32-bit heap pointer directly to `JNIEnv->NewGlobalRef`.
`NewGlobalRef` accepts a *JNI indirect reference*, not a raw ART
`mirror::Object*`. The nterp value remains a transient 32-bit
snapshot (`referenceSnapshotGcStable:false`), while the optional
`referenceIdentityId` aims to provide a stable **identity** across
moving collections (`referenceIdentityKind:jni-weak-global`).
Weak references do not intentionally keep observed objects alive.

The isolated `ci/run-gc-reference-smoke.py` release oracle
executes 512 genuine object-field operations on two ordinary Java
objects, with eight requested GC rounds, and checks that the two
identity IDs remain distinct and stable across all reads/writes.
Actual movement by the collector is **not** asserted, merely
requested. The private `JNIEnvExt` entrypoint, compressed reference
representation, and caller thread's JNI-transition state are
ABI-sensitive. The feature remains **unverified and disabled by
default** until the exact-device test succeeds; a missing export,
invalid build, JNI error or excessive tracked objects fails closed.

## Compiled ArtMethod quick-entrypoint inventory (ABI-pinned)

The JIT compiler observer also inventories the **live quick entrypoint**
of each method that reaches the selected JIT compilation boundary.
For the source-matched Android 13 x86_64 `ArtMethod` layout,
`dex_method_index_` is at byte 8 and
`entry_point_from_quick_compiled_code_` is at byte 24. The probe
reads the entrypoint **without modifying it** and checks the mapped
executable range. A verified executable address is classified by
its ownership: ART runtime bridge, candidate anonymous JIT code,
or mapped OAT/ODEX native module. It does not mistake a runtime
bridge stub for proof that a field access was compiled.

Compiler-time field nodes supply potential DEX field sites, while
the runtime quick entrypoint identifies *where the method may
execute*. It does not yet supply the individual field instruction
PC or its live read/write register, particularly in AOT code or
after inlining/load-store elimination. A field-event hook must
correlate the compiler's instruction offsets and final native
code buffer before declaring exact JIT/AOT values.

## macOS ARM64 runner label fix

GitHub's public-hosted Apple Silicon standard runner uses `macos-15`,
**not** `macos-15-arm64`. Earlier ARM64 jobs remained queued on
the nonexistent custom label. The ARM64 CI job now uses `macos-15`,
so its Android 34 emulator test can execute and determine whether
the new ARM64 nterp ABI actually produces exact field events.
