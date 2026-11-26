// ART-source build unit: direct typed field-event insertion, no Java-authored
// invoke template required in the method being instrumented.
//
// IMPORTANT: compile as part of a source-matched ART optimizing compiler, NOT
// as an NDK library. This code has not been linked into stock emulator ART.
// The injector must run on the compiler worker after SSA construction and
// before optimizations capable of removing/merging field operations.
//
// The host must resolve a preloaded, class-initialized, native static method
// with signature recordFieldInt(IIIIII)V, and supply BOTH the exact ArtMethod*
// and the method's DexFile/MethodId pair. Cross-DEX target-method references
// must be validated with the selected compiler backend before deployment.
//
// Unlike the earlier CloneUniqueIntReadInGraph, the field-accessing Java
// method needs NO FieldEventSink reference and NO adjacent sink call.
// Field identity and runtime value come directly from the HGraph itself.
//
// Follow-on: build matched native module, export entrypoint, and exercise
// live JIT/compilation on API33 x86_64 before enabling other versions.
// TODO: wide, reference, volatile, unresolved field accesses, inlined callee
// attribution, interpreter and AOT code; do not silently claim coverage.
#include <cstdint>
#include "art_method.h"
#include "nodes.h"

namespace art {
namespace artwatch_direct {

enum class RejectReason : uint32_t {
  kNone, kInvalidGraph, kBadSink, kNoEnvironment, kUnresolvedField,
  kOtherDex, kUnsupportedType, kVolatile, kNoValue, kUnsupportedBlock,
};

struct Result {
  uint32_t examined = 0;
  uint32_t inserted = 0;
  uint32_t missing_environment = 0;
  uint32_t mismatched_dex = 0;
  uint32_t unsupported_type = 0;
  uint32_t volatile_fields = 0;
  uint32_t no_value = 0;
};

struct Sink {
  const DexFile* dex_file;
  uint32_t method_index;
  ArtMethod* method;           // Pre-resolved and class-initialized JNI method.
  uint32_t dex_id;             // Stable APK DEX ID from the per-APK catalog.
};

struct FieldAccess {
  HInstruction* value;
  const FieldInfo* info;
  uint32_t operation;          // READ=1, WRITE=2
};

static FieldAccess Describe(HInstruction* inst) {
  if (inst->IsInstanceFieldGet()) {
    auto* get = inst->AsInstanceFieldGet();
    return {get, &get->GetFieldInfo(), 1u};
  }
  if (inst->IsInstanceFieldSet()) {
    auto* set = inst->AsInstanceFieldSet();
    return {set->GetValue(), &set->GetFieldInfo(), 2u};
  }
  if (inst->IsStaticFieldGet()) {
    auto* get = inst->AsStaticFieldGet();
    return {get, &get->GetFieldInfo(), 1u};
  }
  if (inst->IsStaticFieldSet()) {
    auto* set = inst->AsStaticFieldSet();
    return {set->GetValue(), &set->GetFieldInfo(), 2u};
  }
  return {nullptr, nullptr, 0u};
}

static RejectReason InsertIntEventAfter(HGraph* graph,
                                        HInstruction* access,
                                        const FieldAccess& field,
                                        const Sink& sink) {
  if (field.info == nullptr || field.value == nullptr) {
    return RejectReason::kNoValue;
  }
  if (&field.info->GetDexFile() != &graph->GetDexFile()) {
    // A field in an inlined callee needs that callee's MethodReference,
    // not the compiled caller's method index.
    return RejectReason::kOtherDex;
  }
  if (field.info->GetFieldType() != DataType::Type::kInt32 ||
      field.value->GetType() != DataType::Type::kInt32) {
    return RejectReason::kUnsupportedType;
  }
  if (field.info->IsVolatile()) {
    // Volatile/atomic ordering needs an explicit contract of its own.
    return RejectReason::kVolatile;
  }
  if (!access->HasEnvironment()) {
    // Never copy an unrelated HEnvironment from a later instruction:
    // its deoptimization state may describe a DIFFERENT DEX PC.
    return RejectReason::kNoEnvironment;
  }
  if (graph->GetArtMethod() == nullptr ||
      access->GetEnvironment()->GetMethod() != graph->GetArtMethod() ||
      access->GetEnvironment()->GetParent() != nullptr) {
    // Same DexFile alone does not distinguish an inlined callee from
    // its compiled caller. An inlined method needs its own method ID.
    return RejectReason::kOtherDex;
  }
  HBasicBlock* block = access->GetBlock();
  if (block == nullptr || block->GetGraph() != graph ||
      access->IsControlFlow() || block->GetLastInstruction() == access) {
    // No mutation across block boundaries or control-flow terminators.
    return RejectReason::kUnsupportedBlock;
  }

  const uint32_t dex_pc = access->GetDexPc();
  const uint32_t field_id = field.info->GetFieldIndex();
  const uint32_t method_id = graph->GetMethodIdx();
  ArenaAllocator* allocator = graph->GetAllocator();
  const MethodReference sink_ref(sink.dex_file, sink.method_index);

  // ART's JIT direct-address dispatch is the source-supported choice
  // for a resolved ArtMethod*. No HCurrentMethod or clinit input is needed.
  // The sink class must ALREADY be initialized; otherwise reject at caller.
  HInvokeStaticOrDirect::DispatchInfo dispatch = {
      MethodLoadKind::kJitDirectAddress,
      CodePtrLocation::kCallArtMethod,
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(sink.method))
  };
  HInvokeStaticOrDirect* call = new (allocator) HInvokeStaticOrDirect(
      allocator,
      6u,
      DataType::Type::kVoid,
      dex_pc,
      sink_ref,
      sink.method,
      dispatch,
      kStatic,
      sink_ref,
      HInvokeStaticOrDirect::ClinitCheckRequirement::kNone);

  // The six arguments make provenance explicit in the executed native call.
  // Values are SSA inputs, not post-hoc field reads or call-count inference.
  call->SetArgumentAt(0u, graph->GetIntConstant(static_cast<int32_t>(sink.dex_id),dex_pc));
  call->SetArgumentAt(1u, graph->GetIntConstant(static_cast<int32_t>(method_id),dex_pc));
  call->SetArgumentAt(2u, graph->GetIntConstant(static_cast<int32_t>(field_id),dex_pc));
  call->SetArgumentAt(3u, graph->GetIntConstant(static_cast<int32_t>(dex_pc),dex_pc));
  call->SetArgumentAt(4u, graph->GetIntConstant(static_cast<int32_t>(field.operation),dex_pc));
  call->SetArgumentAt(5u, field.value);
  // Insertion AFTER the field access matters: null checks and class
  // initialization errors must happen before a successful-access event.
  block->InsertInstructionAfter(call, access);
  call->CopyEnvironmentFrom(access->GetEnvironment());
  return RejectReason::kNone;
}

// Called at an ART compiler boundary with an already-built SSA graph,
// under normal compilation thread confinement. No Frida callback may
// mutate the graph concurrently with this pass.
Result InsertAllIntFieldEvents(HGraph* graph, const Sink& sink) {
  Result result;
  if (graph == nullptr || !graph->IsInSsaForm() ||
      sink.dex_file == nullptr || sink.method == nullptr ||
      !sink.method->IsStatic() || !sink.method->IsNative()) {
    return result;
  }
  if (sink.dex_file != &graph->GetDexFile()) {
    // ART MethodReference indices are scoped to their DexFile. Refuse
    // cross-DEX dispatch until verified against the target compiler.
    ++result.mismatched_dex;
    return result;
  }
  // Avoid recursively instrumenting the sink itself.
  if (sink.dex_file == &graph->GetDexFile() &&
      sink.method_index == graph->GetMethodIdx()) {
    return result;
  }
  for (HBasicBlock* block : graph->GetActiveBlocks()) {
    for (HInstruction* access = block->GetFirstInstruction();
         access != nullptr;) {
      HInstruction* next = access->GetNext();
      FieldAccess field = Describe(access);
      if (field.info != nullptr) {
        ++result.examined;
        switch (InsertIntEventAfter(graph, access, field, sink)) {
          case RejectReason::kNone: ++result.inserted; break;
          case RejectReason::kNoEnvironment: ++result.missing_environment; break;
          case RejectReason::kOtherDex: ++result.mismatched_dex; break;
          case RejectReason::kUnsupportedType: ++result.unsupported_type; break;
          case RejectReason::kVolatile: ++result.volatile_fields; break;
          default: ++result.no_value; break;
        }
      }
      // Do not re-enter a freshly inserted invocation.
      access = next;
    }
  }
  return result;
}

}  // namespace artwatch_direct
}  // namespace art
