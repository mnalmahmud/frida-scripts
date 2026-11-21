// P3 experimental ART-source build unit (NOT an NDK / on-device ABI shim).
//
// Build inside a source-matched Android ART compiler tree, after validating
// the exact device libart-compiler.so/libart.so build IDs. The existing CI
// intentionally does NOT compile, dlopen, or invoke this unit.
// This is the first real IR mutation implementation, not yet a deployed hook.
//
// Caller responsibilities:
//  - Locate an exact same-graph FieldEventSink.recordInt(0,0,observed)
//    template, a matching int field GET, and the resolved ArtMethod*.
//  - Invoke only on the compilation worker with HGraph and nodes alive.
//  - Select API33 x86_64 verified library identities before calling.
//  - Hold the ART compiler's normal graph-mutation context; no concurrent walk.
//  - Do not invoke from Frida JS or a JNI runtime thread.
//
// Safety: this is a narrowly gated *read event* proof. Refuse all other
// fields, unresolved calls, clinit checks, mixed blocks, or invalid source
// instruction placement. Writes and generalized method resolution are next.
#include "nodes.h"

namespace art {
namespace artwatch_p3 {

enum class CloneResult : int {
  kInserted = 1,
  kMissing = -1,
  kGraphMismatch = -2,
  kTypeMismatch = -3,
  kNotAdjacent = -4,
  kTemplateMismatch = -5,
  kEnvironmentMismatch = -6,
  kUnsupportedDispatch = -7
};

// The injected clone records a real successful read with the existing JNI
// recorder. The template itself passes (0,0,observed), so the recorder ignores
// its own execution; only an inserted clone with (9002,1,observed) produces
// events. Value is the actual HInstanceFieldGet SSA output.
CloneResult CloneIntReadFromResolvedTemplate(
    HGraph* graph,
    HInstanceFieldGet* field_get,
    HInvokeStaticOrDirect* template_invoke,
    ArtMethod* expected_sink_method,
    int32_t read_site) {
  if (graph == nullptr || field_get == nullptr ||
      template_invoke == nullptr || expected_sink_method == nullptr) {
    return CloneResult::kMissing;
  }
  HBasicBlock* block = field_get->GetBlock();
  if (block == nullptr || template_invoke->GetBlock() != block ||
      block->GetGraph() != graph || !graph->IsInSsaForm()) {
    return CloneResult::kGraphMismatch;
  }
  if (field_get->GetType() != DataType::Type::kInt32 ||
      field_get->GetFieldType() != DataType::Type::kInt32 ||
      field_get->IsVolatile()) {
    return CloneResult::kTypeMismatch;
  }
  // This deliberately accepts only adjacent field-get -> invoke templates.
  // The already-correct call environment describes precisely this point.
  // Never move a throwing call over unrelated operations.
  if (field_get->GetNext() != template_invoke) {
    return CloneResult::kNotAdjacent;
  }
  if (!template_invoke->IsStatic() ||
      template_invoke->GetResolvedMethod() != expected_sink_method ||
      template_invoke->GetNumberOfArguments() != 3u ||
      template_invoke->InputCount() != 3u ||
      template_invoke->InputAt(2) != field_get ||
      template_invoke->GetType() != DataType::Type::kVoid ||
      !template_invoke->IsClonable()) {
    return CloneResult::kTemplateMismatch;
  }
  HInstruction* site = template_invoke->InputAt(0);
  HInstruction* kind = template_invoke->InputAt(1);
  if (site == nullptr || kind == nullptr ||
      !site->IsIntConstant() || !kind->IsIntConstant() ||
      site->AsIntConstant()->GetValue() != 0 ||
      kind->AsIntConstant()->GetValue() != 0 ||
      read_site <= 0) {
    return CloneResult::kTemplateMismatch;
  }
  if (!template_invoke->HasEnvironment() ||
      template_invoke->GetEnvironment() == nullptr) {
    return CloneResult::kEnvironmentMismatch;
  }
  // Reject dispatch modes requiring additional current-method/clinit input,
  // even though the cloned source method reference would otherwise be valid.
  if (template_invoke->GetClinitCheckRequirement() !=
          HInvokeStaticOrDirect::ClinitCheckRequirement::kNone ||
      template_invoke->HasCurrentMethodInput()) {
    return CloneResult::kUnsupportedDispatch;
  }
  // All checks above run before the first mutation. Clone inherits the
  // real DEX method reference and dispatch, but not its block, ID,
  // environment or use-list links (those are rebuilt by ART).
  HInstruction* raw = template_invoke->Clone(graph->GetAllocator());
  HInvokeStaticOrDirect* invoke = raw->AsInvokeStaticOrDirect();
  invoke->SetArgumentAt(0, graph->GetIntConstant(read_site, field_get->GetDexPc()));
  invoke->SetArgumentAt(1, graph->GetIntConstant(1, field_get->GetDexPc()));
  // Argument 2 already refers to field_get from the source template.
  block->InsertInstructionBefore(invoke, template_invoke);
  // Copy uses and inlined parent environment through ART, not a memcpy.
  invoke->CopyEnvironmentFrom(template_invoke->GetEnvironment());
  return CloneResult::kInserted;
}

}  // namespace artwatch_p3
}  // namespace art
