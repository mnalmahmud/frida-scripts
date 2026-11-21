# P3 research: first ART-inserted integer field event (API 33 x86_64)

**Status (2026-11-21): implementation gate, not a working IR injector.**
Active branch: `ci/art-fieldwatch-phase1`; baseline head `2fe8fca967e8`.
Do not report arbitrary-field coverage from the explicit Java call-site P2 test.
The first mutation remains **off by default**, exact-ELF-gated, and APK-fixture-only.

## What is already established

- CI [44843045544](https://github.com/mnalmahmud/frida-scripts/actions/runs/44843045544)
  passed API 33 debug, API 33 release and API 34 debug. The API 33 native
  recorder delivered 256 real integer runtime events (128 read/write pairs),
  with the expected values and ordering and zero dropped events.
  **Those invocations come from explicit Java source calls** to
  `FieldEventSink.recordInt` in `FieldIRTarget.watchedOn`, not compiler insertion.
- The API 33 release run also observed a successfully optimized compilation
  where ART's LSE replaced an `HInstanceFieldGet` with an `HPhi` and then
  removed the get. The removed node reached neither backend locations nor
  emission. This is the live-value/optimization regression case for P3.
- `native/passive-shadow.c` has a fail-closed x86_64 API 33 gate for the
  *observed emulator binary*, runtime GNU Build ID
  `c8b6a2df9893030c07b3b96dc24a7d30` and compiler GNU Build ID
  `0b33b00205f7151b4fce7490c3715d99`.
  It only validates graph/node pointers and never mutates ART objects.

## AOSP constraints that change the implementation

1. **Use ART's IR insertion machinery, not a raw linked-list edit.**
   AOSP `HBasicBlock::InsertInstructionAfter` validates the cursor/block,
   assigns the new instruction's graph ID, sets its block and updates input
   user lists. Even a correctly placed pointer without this accounting is
   not a valid SSA node. Its actual callable ABI/export on our emulator is
   *not yet established*.
2. **A call node is more than an address to a native C function.**
   `HInvokeStaticOrDirect` construction includes the number/types of
   arguments, return type, DEX PC and method index, an `ArtMethod*` and
   dispatch metadata, invocation kind, target `MethodReference`, and
   class-initialization requirements. Some dispatch modes add implicit
   inputs such as the current method or class-init check. The compiler's
   Java invocation lowering cannot be fed `artwatch_events_snapshot` or
   `recordInt`'s native function pointer as if it were an `ArtMethod*`.
3. **An invoke may trigger GC or throw.** Validate the attached
   `HEnvironment`, inlined parent chain, safepoints, register liveness,
   stack maps, method resolution and class initialization. Loading an
   unresolved helper inside the compiler worker is not a valid shortcut.
   Pre-initialize the fixture's `FieldEventSink` before warmup.
4. **The helper method reference must be legal for the caller.**
   For the *fixture-only* canary, the app's DEX already references
   `FieldEventSink.recordInt(int,int,int)` from `watchedOn`; its
   resolved method, DEX method ID, and prototype can be checked against
   the existing ART-created invoke as an oracle. For arbitrary third-party
   DEX files the helper method ID need not exist at all. A direct-address
   dispatch mode does **not** by itself prove that the rest of
   `HInvokeStaticOrDirect` accepts a nonexistent DEX method index.
   Generalizing beyond the canary is a separate design gate.
5. **Logical rather than physical semantics.** Insert the side-effecting
   callback after successful `HInstanceFieldSet` / `HInstanceFieldGet`,
   not at backend emission. A get's event argument must use the *get's SSA
   result*, and a set's argument the actual value stored. If LSE replaces
   the get with `HPhi`, the event use must be updated to the proven
   substitute through normal ART SSA maintenance. An optimized-away field
   load can still have a logical DEX read event. The callback must not run
   on a null receiver that throws before completing the field access.

Source anchors (structural evidence, **not** confirmation of the exact
on-device ABI):
- [AOSP Android 13 optimizing source tree](https://android.googlesource.com/platform/art/+/refs/heads/android13-d4-s1-release/compiler/optimizing/)
- [AOSP nodes.cc insertion and user-list maintenance](https://android.googlesource.com/platform/art/+/refs/heads/android13-d4-s1-release/compiler/optimizing/nodes.cc)
- [AOSP nodes.h invoke metadata](https://android.googlesource.com/platform/art/+/refs/heads/android13-d4-s1-release/compiler/optimizing/nodes.h)
- [AOSP instruction builder](https://android.googlesource.com/platform/art/+/refs/heads/android13-d4-s1-release/compiler/optimizing/instruction_builder.cc)
- [AOSP graph checker](https://android.googlesource.com/platform/art/+/refs/heads/android13-d4-s1-release/compiler/optimizing/graph_checker.cc)

## Smallest acceptable P3 mutation

**Scope:** one *resolved*, nonvolatile `int` instance field belonging to
the controlled API 33 release fixture. Do not start with every Java class.
No object references, volatiles, static fields, unresolved accesses, other
architectures, or unverified ART builds. Keep the read-only P1 observers
unchanged and available as a rollback baseline.

- **Identify a legal insertion point.** The current verified
  `RunOptimizations(HGraph*, ...)` entry is a graph pointer boundary, but
  alone does not prove final post-inlining pass order. Determine the actual
  API 33 inlining/LSE order; prefer a point after relevant inlining and
  before first field elimination. Baseline `CompilationKind=1` may not
  visit this path and needs a separate verified insertion point.
- **Build a source-matched native C++ helper.** Compile against the
  matching ART C++ structures, not only NDK/JNI headers or guessed offsets.
  Load only after both mapped ART ELF build IDs match. Validate the graph,
  allocator, field node, owner block and target invoke ABI before *any*
  change. On mismatch, return an explicit failure reason; do not partially
  rewrite the graph. Do not call Frida JavaScript or JNI from the JIT
  compiler worker.
- **Use the preexisting canary helper method.** The APK fixture already
  contains a correctly resolved static native invoke. Verify its method
  reference, dispatch, signature, class-init state and environment from
  an ART-generated invoke before constructing a new one. This is a
  narrowly controlled way to close the call-lowering question; it is
  not a general arbitrary-Dex solution.
- **Construct and insert through ART APIs.** Allocate in the graph arena;
  set the event's site/kind constants and typed int SSA argument, attach a
  correct environment, then use `InsertInstructionAfter`. Validate
  argument use lists and dominance *immediately*. Do not retain live
  `HInstruction*` or graph pointers after compilation.
- **Validate compiler output.** Run graph-checker-style invariants and
  require successful code generation, not just a non-crashing app run.
  Log an unambiguous `artwatch-injection` record with
  `{attempted, inserted, rejectedReason, compilationKind, site}`.
  Never confuse a compile-time IR observation with execution of the call.

## Minimum acceptance and negative controls

1. **Off by default:** existing passing P1/P2 CI remains unchanged; the
   canary mutation is enabled only through an explicit workflow/agent flag.
   Unknown ELF IDs, unsupported tier, missing helper metadata, or missing
   graph invariants must return `inserted=false` and leave code untouched.
2. **Positive control:** remove *explicit* `recordInt` calls from a
   distinct canary method while retaining the current explicit-call oracle.
   Verify that this raw canary emits zero events with injection disabled,
   then exactly one write and one read per successful invocation when P3
   injection is enabled. Keep the original `watchedOn` test intact.
3. **Exception control:** a null-receiver write must throw before
   recording any event. Check that the method's return value is unchanged.
4. **Tier and optimization controls:** require evidence in both a
   baseline-emitted get and an optimized compilation that can replace
   get with `HPhi`. A side-effecting invoke may itself inhibit LSE; if
   so record that fact instead of claiming optimized-get replacement.
5. **Sink behavior:** confirm exact value bits, order, count and drops
   through the existing native snapshot. For later generalization,
   test multiple threads, capacity exhaustion and reentrancy separately.
6. **Coverage claim:** future JIT compilations of selected DEX methods
   only. Already compiled AOT/JIT, interpreted, inlined before attachment,
   and D8-eliminated source operations remain outside this milestone.

## Specific implementation blocker to resolve next

Find a **real source/binary-compatible way to construct and lower a
`HInvokeStaticOrDirect` targeting the fixture sink**. The existing
Frida JavaScript observer and NDK passive shim do not contain the ART
C++ header/layout, environment construction, allocator plumbing, or
method-resolution contract required for this. Hook attachment and a
matching HGraph pointer are necessary but *not sufficient*.
Until those prerequisites are demonstrated, keep mutation disabled.


## 2026-11-21: same-graph clone proof implementation (source unit only)

The device's API33 libart-compiler.so exported
`HBasicBlock::InsertInstructionAfter(HInstruction*,HInstruction*)` and
`HBasicBlock::InsertInstructionBefore(HInstruction*,HInstruction*)`, along
with `HInvokeStaticOrDirect::Accept`. CI run 44896426059 confirmed actual
invoke visitor callbacks on real compilations and an existing 256-event P2
oracle. The newer invoke backend assertions remain a separate CI gate.

Experimental C++ file:
[`native/p3-clone-injector-art.cc`](../../art-fieldwatch-phase1/native/p3-clone-injector-art.cc).

This file contains **actual HGraph mutation code**, but is deliberately
**not built or loaded by the current NDK CI**. It uses source-level ART
interfaces, so it must be compiled in the matching ART source environment,
with the exact ELF Build IDs validated before integration. Its entrypoint
requires already validated same-graph `HInstanceFieldGet`, a real
`HInvokeStaticOrDirect` template, and its resolved sink `ArtMethod*`.

The new `p3TemplateCarrierOn()` adds
`recordInt(0,0,observed)` in the same Java method as a real `iput` and
`iget`. The native sink excludes this reserved sentinel. The first
injected clone will use site 9002, kind 1, and the original field-get
SSA output; only the cloned call can emit a read event.

**Important gates:** adjacency, type, source invoke signature, resolved
method identity, class-init dispatch, presence of a valid source environment,
and graph ownership must be checked before mutation. The helper refuses
nonadjacent nodes, volatiles, and cross-block calls. It clones the invoke,
replaces its first two SSA operands with constants, inserts immediately before
the existing call using ART APIs, then copies the original call environment.
It does not yet identify template and field pointers automatically, install a
compiler hook, or cover eliminated accesses.

AOSP-compatible research reference for this clone design:
[Android 13 era AOSPA topaz nodes.h](https://github.com/AOSPA/android_art/blob/topaz/compiler/optimizing/nodes.h),
[nodes.cc](https://github.com/AOSPA/android_art/blob/topaz/compiler/optimizing/nodes.cc).
These mirror sources establish the algorithmic contract but **do not prove**
a binary ABI match with the emulator. Exact matching ART headers and a
build-tested injector are still required before enabling it.

Before claiming P3 success require: fixture DEX retains the template; the
actual optimized graph retains its adjacent field get and sink invoke; the
mutator is built and loaded under the exact build-ID gate; the compiler
completes with valid SSA and environments; an injected invocation yields
128 events with the exact expected field-read values; zero-event controls
remain unchanged; and the P2 256-event oracle still passes.

## P3 get/invoke adjacency check (2026-11-21)

A build-ID-gated **read-only** native function now checks the Android 13
`HInstruction` link layout for actual, vtable-validated
`HInstanceFieldGet` and `HInvokeStaticOrDirect` objects seen during the
same `HGraphVisitor::VisitBasicBlock` visit. It compares reciprocal
`previous_`/`next_` pointers and exact `HBasicBlock*` identity. Results
are reported as `adjacencyProbes`, `adjacencyMatches`,
`adjacencyRejected`, and bounded pointer samples per compilation.
No ART memory is modified. A passing API33 JIT must not have negative
identity checks; actual adjacency has to be observed before deploying the
`CloneUniqueIntReadInGraph` logic. A zero adjacency count is meaningful
and must not be relabeled as successful injection.
