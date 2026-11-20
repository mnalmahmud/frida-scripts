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
