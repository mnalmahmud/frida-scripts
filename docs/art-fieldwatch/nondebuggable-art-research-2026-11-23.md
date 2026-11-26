# Non-debuggable ART field monitoring: AOSP-backed architecture decision

Research date: 2026-11-23. Scope: Android ART API 21–37, ARM/ARM64/x86/x86_64,
with a first executable implementation target of API 33 x86_64 **release**
(`android:debuggable=false`). This document is a design and evidence summary,
not a claim of working arbitrary-field tracing.

## Decision

Build an **interpreter-backed non-debuggable baseline** before pursuing
JIT/AOT performance. Use Frida native injection + ART deoptimization, with
source-matched interpreter field instrumentation that records the exact
read result / committed write. Follow this with compiler-side event insertion
for JIT and a separate AOT/machine-code fallback.

Do **not** put JVMTI agent attachment on the critical path. Ordinary
non-debuggable APKs are explicitly blocked by the public ART/JVMTI attach
checks (even with adb/root there are separate runtime checks). Frida native
in-process injection is a different mechanism.

## Verified from upstream sources

1. ART's `Instrumentation` contains native `FieldReadEvent` and
   `FieldWriteEvent` hooks, described as interpreter-only. Registration via
   `Instrumentation::AddListener` requires exclusive mutator lock. The event
   bitmasks in Android 13 include `kFieldRead=0x10`, `kFieldWritten=0x20`.
   See:
   https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/instrumentation.h

2. In `DoFieldGetCommon`, the ART read notification happens **before**
   `ArtField::Get{Boolean,Byte,Char,Short,Int,Long,Object}` populates the
   `JValue result`. Therefore reading the field a second time from an
   instrumentation listener is **not** exact under concurrent writes.
   In `DoFieldPutCommon`, `FieldWriteEvent` runs **before** `ArtField::Set*`,
   so that event is a proposed write, not guaranteed to commit. Some
   reference-store checks can fail afterward. To provide successful-access
   semantics, hook after the result load / successful store or the enclosing
   interpreter operation, respecting exception paths.
   https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/common_dex_operations.h

3. `Java.deoptimizeEverything()` is implemented by frida-java-bridge:
   `requestDeoptimization()` uses internal ART/JDWP deoptimization for
   Android 7–10 (API 24–29) and `Instrumentation::DeoptimizeEverything`
   from Android 11 (API 30+) in the currently inspected implementation.
   **The Frida bridge throws for API <24.** For API 21–23 use a separately
   versioned native ART deoptimization path; do not claim the JS function
   supports them.
   https://github.com/frida-packages/frida-java-bridge/blob/main/lib/android.js
   https://frida.re/docs/javascript-api/

4. AOSP nterp's `CanRuntimeUseNterp()` checks
   `Instrumentation::NeedsSlowInterpreterForListeners()`, and has other
   interpreter-only restrictions. Nevertheless, field-event correctness
   must test the actual selected interpreter mode per ART build. Quickened
   and unresolved field opcodes require explicit coverage.
   https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/interpreter/mterp/nterp.cc
   https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/interpreter/interpreter_common.h

5. ART's JIT `HInstanceFieldGet/Set` and `HStaticFieldGet/Set` nodes
   contain an `ArtField`/DexFile/field index/dex pc and the SSA field
   value or setter input. The Android 13 graph builder creates environments
   in `InitializeInstruction()` for instructions whose
   `NeedsEnvironment()` is true. Field get/set nodes **do not normally
   carry an HEnvironment**. Therefore
   `native/p3-direct-injector-art.cc`'s unconditional
   `access->HasEnvironment()` gate rejects ordinary field nodes; that
   file is source-only and not a deployable generic injector.
   https://android.googlesource.com/platform/art/+/refs/heads/main/compiler/optimizing/instruction_builder.cc

6. ART ships as a Mainline APEX on Android 12+. SDK version alone is
   insufficient to select C++ private ABI offsets/symbols; fingerprint
   **the actual libart.so/libart-compiler.so build IDs**, ISA, APEX variant,
   and source matching. Fail closed on unknown builds.
   https://source.android.com/docs/core/ota/modular-system/art
   https://android-developers.googleblog.com/2023/08/latest-artwork-on-hundreds-of-millions-of-devices.html

7. Android 17 (API 37) introduces stricter `static final` modification
   behavior for apps targeting SDK 37+, as well as ART generational-GC
   changes; the watcher must be read-only and GC-safe. Native file loading
   restrictions for apps targeting 37 also apply.
   https://android-developers.googleblog.com/2026/06/Android-17.html

## Backend A: interpreter (correctness-first, non-debuggable)

- Inject a native companion into the **release** process (rooted Frida
  server, or explicitly embedded/repackaged Gadget). Do not call
  `Debug.attachJvmtiAgent` or set `android:debuggable=true`.
- Trigger ART deoptimization via Frida's existing bridge where available;
  record whether interpreter stubs actually became active. New compiled
  entrypoints and already-running frames require their own verification.
- For immediate reachability, create a source-matched native
  `InstrumentationListener` and register with proper ART stop-the-world /
  exclusive-mutator-lock semantics. Do **not** call `AddListener` from an
  arbitrary JS callback without the required lock.
- This listener produces **metadata and pre-events only**. For exact
  successful primitive reads/writes use a separate after-operation
  capture point in the switch interpreter, preserving the original
  `JValue` / `ShadowFrame` destination and exception outcome.
  A listener that re-reads the field is unacceptable.
- Keep records in per-thread bounded lock-free native buffers. No Frida
  `send()`, Java reflection, string formatting or reentrant JNI from
  inside hot ART callbacks.
- For reference values, retain GC-safe handles and allocate stable
  tokens only in a safe thread state. Never interpret a moving
  `mirror::Object*` as a permanent identity.

### Interpreter correctness gates

1. A true release APK (`APP_DEBUGGABLE=false`) on API33 x86_64, with
   ordinary `iget/iput/sget/sput` and **zero authored sink invokes**.
2. Two fields, two declaring classes and two distinct caller methods,
   with exact field identities and DEX PCs.
3. Exact read result under a concurrent writer (a separate JNI
   re-read must be demonstrably allowed to disagree; *our event must not*).
4. No successful read/write event for null-receiver operations,
   failed resolution, or rejected reference stores.
5. Verify primitive widths and raw floating-point bits (including
   negative zero and NaN payload test vectors where ART preserves them).
6. Verify object events survive GC and never report stale raw pointers.
7. Verify no silent misses across switch / nterp / quickened opcode
   paths, new threads, and JIT/AOT deoptimization transitions.
8. Bound dropped event counters, reentrancy, and performance.

## Backend B: JIT compiler (performance-first after A)

- Insert after SSA field access using actual get-result/set-argument,
  before optimizing away semantic accesses if bytecode semantics is the
  desired definition. A different mode may intentionally watch only
  physical memory loads/stores left after optimization.
- Do not depend on adjacent Java recorder templates. Replace the source
  unit's `access->HasEnvironment()` gate with legitimate deoptimization
  state construction at the instruction-builder boundary (where locals
  exist), or with a separately verified source-matched pass that derives
  an equivalent environment correctly. Never copy a later instruction's
  unrelated environment.
- Do not assume a JNI method from another DexFile is addressable by a
  fabricated `MethodReference`. Validate cross-DEX resolution, invoke
  dispatch, and JNI class initialization before compiler mutation.
- Preserve source method provenance through inlining. `graph->GetMethodIdx()`
  is the compiled root, *not necessarily* the owner of an inlined access.
- Prove backend code generation for exact cloned/new node identities,
  then prove executed runtime values in a no-sink method.

## Backend C: AOT/native field access

JIT-only hooks **cannot** promise app-wide coverage: release methods may
execute existing AOT code, framework code, or native/JNI code. Use interpreter
deoptimization as the fallback or architecture/build-specific machine
instruction instrumentation. Reflection, Unsafe, VarHandle, and native
field manipulation need separate explicit semantics, not a blanket claim.

## Coverage by platform

| API | First-line approach | Critical condition |
| --- | --- | --- |
| 21–23 | ART interpreter + native deopt | Frida JS deopt API unavailable; older C++ layout |
| 24–25 | Interpreter + Frida deopt / JIT | Frida's older JDWP-mediated deopt path |
| 26–29 | Interpreter + Frida deopt / JIT | JVMTI exists but attach is still restricted |
| 30–32 | Interpreter + direct ART deopt / JIT | nterp/mterp and APEX changes per build |
| 33–37 | Interpreter correctness baseline then JIT | ART Mainline build IDs; GC/ABI/ISA differences |

ARM, ARM64, x86 and x86_64 require separate evidence even at the same API.
The matrix is architectural planning, not a list of verified targets.

## Prioritized implementation plan

P0. Stop adding debuggable JVMTI features to the non-debuggable milestone.
P1. Prove deoptimization and real `Instrumentation::FieldRead/Write`
    delivery in an API33 release APK, across two fields and without sinks.
P2. Prove **after-load** exact read values and post-commit write success.
P3. Generalize class/method/field/DEX PC and GC-safe primitive/reference
    event transport, then API34–37 on matching ART builds.
P4. Implement direct compiler insertion with real HEnvironment / dispatch,
    enabled only on supported builds, retaining interpreter fallback.
P5. Backport interpreter ABI to API21–32 and add ARM/ARM64/x86 coverage.

**Do not mark arbitrary-field monitoring complete** before P2 passes.
Do not mark full API21–37 or app-wide coverage complete until all runtime
modes, versions, ISAs and object-reference cases have concrete evidence.
