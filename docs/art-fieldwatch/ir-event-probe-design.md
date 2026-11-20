# Design: compiler-IR logical Java field events

**Status:** proposal for research prototype; **not implemented**. No IR mutation
or runtime callback is shipped in phase 1. Retain the verified read-only probe.
**Initial target:** Android API 33 x86_64, ART compiler ELF Build ID
`0b33b00205f7151b4fce7490c3715d99`; runtime `libart.so` Build ID
`c8b6a2df9893030c07b3b96dc24a7d30`. Fail closed for other binaries.

## Evidence and problem definition

CI [44725544918](https://github.com/mnalmahmud/frida-scripts/actions/runs/44725544918)
passed API 33 debug/release and API 34 debug. The release test checked
**two** optimized `HInstanceFieldGet*` nodes visited by ART, replaced
and removed inside LSE, and absent from the same compilation's backend
location assignment/code emission; at least one baseline JIT compilation
did emit a field-get. The preceding run
[44722172785](https://github.com/mnalmahmud/frida-scripts/actions/runs/44722172785)
also verified that `FieldIRTarget.testViaIdentity(int)` contains both
`iput` and `iget` in **release** DEX. Unlike `test(int)`, its read
was not already eliminated by D8.

**Two monitoring semantics, deliberately distinct:**

* **Logical DEX event**: one event on each *successful execution* of
  an instrumented DEX `iget/iput/sget/sput` instruction (not each
  compiler visitor invocation or emitted machine load).
* **Physical event**: one event for each actual machine memory access
  in compiled code. Optimization can legitimately remove this access,
  so it cannot substitute for logical monitoring.

This document designs *logical* events. It cannot reconstruct
source-level operations eliminated by D8 before DEX exists.

## Candidate mechanism: a real side-effecting ART IR operation

Work with a **source-matched native C++ compiler shim**, not JS-written
C++ object memory. The current Frida JS remains a read-only observer and
gates the shim on build ID, architecture and verified graph invariants.
Prefer an existing `HInvokeStaticOrDirect` to a dedicated, known
event sink, so the stock ART backend, stack maps and call lowering are
reused. An arbitrary C native function pointer is **not** a valid
`HInvokeStaticOrDirect` destination. It needs a real resolved
`ArtMethod*`, an acceptable dispatch method, DexCache / loader
resolution, correct invoke arguments and any required class-init
state. The source-matched shim must validate all of these; if not
possible, stop instead of constructing an invalid call.

Prototype on the test APK only: predefine a minimal nonthrowing-in-
practice primitive event sink, e.g. `FieldEventSink.recordInt(siteId,
value)`, initialize it before warmup, make its observable side effect
undeniable and prohibit inlining if the ART variant supports a
documented, verified mechanism. Its goal is an event count/value
oracle, **not** production safety or a stable general application API.

Proposed IR transformation, after valid SSA construction and **before
LSE**. Start with resolved, nonvolatile `HInstanceFieldGet/Set` of
type int:

```text
DEX: iput v, obj, field       DEX: iget dest, obj, field
              |                              |
IR:   HNullCheck(obj)            HNullCheck(obj)
       HInstanceFieldSet(obj,v)   HInstanceFieldGet(obj) -> value
       HInvoke sink(site,v)       HInvoke sink(site,value)
              |                              |
       ordinary next IR               ordinary next IR
```

**Place sink after the field operation** so it runs only after a
successful access, including any required null and resolution checks.
Connect its value operand to the actual SSA producer: `Get` result
for reads, `Set` value input for writes. If LSE replaces the
`Get` value with a substitute, the sink's SSA use should be
retargeted to that substitute; the event still uses the logically
observed value. The sink must itself be a visible, non-removable
side effect, not a pure helper that DCE/GVN drops.

Do not assume this will leave LSE behavior unchanged: conservative
invoke side effects can inhibit load/store elimination and code motion.
**Compiled execution must be preserved; identical optimization output
is not a goal for this first prototype.** The stronger claim that an
optimized-away load still produces a synthetic logical event must be
demonstrated experimentally, not asserted from IR construction alone.

## Insertion, order and provenance contracts

1. **Version gate:** exact ART build IDs, 64-bit ABI, verified vtable
   and graph layout, successful source-matched shim initialization.
   Missing/unknown layout => survey-only, no mutation.
2. **Insertion window:** after instruction building/SSA validity and
   before the first optimization that can eliminate the field node.
   API 33 `RunOptimizations(HGraph*,...)` is a verified boundary;
   test actual pass order and whether inlining introduces additional
   field nodes *after* injection. Instrument cloned/inlined copies
   exactly once if an inliner later imports them.
3. **Control flow:** sink must be on the same successful execution
   path as the original field instruction. It must not execute on a
   path that throws `NullPointerException`, field-resolution/access
   errors, or class initialization failures. Compare CFG, dominance,
   exceptional edges, and live SSA inputs before and after injection.
4. **Compiler representation:** verify method dispatch, argument
   widths/types, environments, graph uses, graph allocator lifetime,
   safepoint/stack-map requirements and side-effect flags. Run ART's
   graph checker and post-codegen verification, not just a non-crashing
   Android warmup.
5. **Field identity:** `(DexFile identity, declaring loader, field
   index, access opcode, dex PC, inlined frame)`; the raw field index
   alone is not globally stable. Preserve the resolved `ArtField`
   metadata only using a supported lifetime-safe mechanism.
6. **Java semantics:** read event after a successful get and write
   event after a successful set; do **not** accidentally duplicate
   null checks or materialize a load purely to observe its value.
   For initially optimized-out reads, use the compiler's *substitute*
   SSA value if it is proven semantically equivalent.
7. **Volatile, static, unresolved, reference and wide/FP fields are
   out of scope for the first mutation prototype.** Volatiles need
   exact acquire/release ordering; statics need clinit ordering;
   unresolved accesses can throw resolution/access exceptions.
   A raw `mirror::Object*` must never be retained across GC. Expand
   types only after a verified root/handle strategy.

## Runtime sink and event transport

Prototype first with `int` values only. Define an immutable event
schema (version, compilation site ID, thread sequence, dex source
identity + PC, kind, value bit pattern, dropped-count). Do not emit
raw object pointers as durable object identities. The eventual
production sink should be **bounded, allocation-free and
non-blocking on hot paths**, with explicit overflow reporting and
reentrancy suppression, but such a sink still needs ABI/GC/safepoint
proof. A Java-method sink is suitable only for a controlled first
count/value experiment; it may allocate, throw, trigger class
initialization, or perturb optimization if implemented incorrectly.

When providing callbacks to `frida-java-bridge`, keep the Frida
consumer outside the compiler's internal locks and JIT worker.
The compiler injects a runtime site; it does not call user JavaScript
while constructing or optimizing the graph.

## Coverage limitations (explicit)

* Instruments **future matching JIT compilations only** after shim
  installation. Existing AOT/JIT code is **not** retroactively covered.
  Forcing deoptimization, Stalker and watchpoints are not part of this
  design; completeness of preexisting compiled code is consequently
  not promised.
* API 34's field IR boundary is not established, so **no API 34
  mutation**. API 21-37 and ARM/ARM64/x86 adapters require separate
  evidence, codegen checks and exact ABI validation.
* Inlining, quickened DEX, constructor special cases, exception paths
  and compiler-generated field nodes need their own provenance and
  duplication checks. A field instruction is not always a one-to-one
  representation of a Java source expression.

## Prototype acceptance gates

| Stage | Required CI evidence | Rollback condition |
|---|---|---|
| P0: immutable baseline | Existing `44725544918` debug/release lifecycle suite stays green | Baseline regression |
| P1: shadow shim | Native shim loads and enumerates *only* expected int field nodes; ART graph remains byte-for-byte unmodified | Unknown ABI, wrong ownership, graph-check failure |
| P2: one inserted event | The API 33 **release** `testViaIdentity` DEX still has iput+iget; one chosen compilation compiles; event counts/values match executed field instructions | Crash, changed return value, missing event or false event on null |
| P3: optimized code | Baseline & optimizing tiers pass; event operation appears at backend/code emission even if corresponding field node is replaced/removed | Event dropped, duplicated, reordered or exception behavior altered |
| P4: inlining and exceptions | Nested/inlined helper path and null receiver tests have correct site provenance and exactly-once behavior | Duplicate or false events |
| P5: types/versions | Long/FP, static, volatile, reference/GC, API34 and other ABIs added individually after safety tests | Unsupported/unstable ABI |

**Immediate next action:** implement P1 **only**, a passive
version-checked native companion that inspects the same live graph
without modifying it. Then prototype P2 with a single int field
and compare its events with the Java fixture oracle. Keep all
injection behind an explicit opt-in environment flag, disabled by
default.

## AOSP reference points

- [ART instruction builder](https://android.googlesource.com/platform/art/+/master/compiler/optimizing/instruction_builder.cc): resolved and unresolved get/set, null-check ordering.
- [ART IR nodes](https://android.googlesource.com/platform/art/+/refs/heads/main/compiler/optimizing/nodes.h): HInstanceFieldGet/Set, HInvoke and side-effect/environment semantics.
- [ART load/store elimination](https://android.googlesource.com/platform/art/+/master/compiler/optimizing/load_store_elimination.cc): ReplaceWith, RemoveInstruction, debuggable graph restriction.
- [ART x86_64 code generator](https://android.googlesource.com/platform/art/+/refs/heads/main/compiler/optimizing/code_generator_x86_64.cc): backend lowering of invokes and field nodes.

These are **structural** references; all on-device object layouts
and method signatures must be matched to the exact CI binary before
native compiler mutation.
