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

// Select the template by *exact* DEX identities within the compiler's
// current graph, never by a global ArtMethod pointer or a stale node address.
// The caller obtains these IDs from the currently compiled APK and resolves
// expected_sink_method using ART's normal class/method resolution.
CloneResult CloneUniqueIntReadInGraph(
    HGraph* graph,
    const DexFile* expected_dex,
    uint32_t expected_compiled_method_idx,
    uint32_t expected_field_idx,
    uint32_t expected_get_dex_pc,
    uint32_t expected_sink_method_idx,
    ArtMethod* expected_sink_method,
    int32_t read_site) {
  if (graph == nullptr || expected_dex == nullptr ||
      expected_sink_method == nullptr) {
    return CloneResult::kMissing;
  }
  // A DEX method index is not globally unique across class loaders.
  if (&graph->GetDexFile() != expected_dex ||
      graph->GetMethodIdx() != expected_compiled_method_idx ||
      !graph->IsInSsaForm()) {
    return CloneResult::kGraphMismatch;
  }
  HInstanceFieldGet* selected_get = nullptr;
  HInvokeStaticOrDirect* selected_invoke = nullptr;
  for (HBasicBlock* block : graph->GetActiveBlocks()) {
    for (HInstruction* inst = block->GetFirstInstruction();
         inst != nullptr; inst = inst->GetNext()) {
      if (!inst->IsInvokeStaticOrDirect()) continue;
      HInvokeStaticOrDirect* invoke = inst->AsInvokeStaticOrDirect();
      const MethodReference reference = invoke->GetMethodReference();
      if (reference.dex_file != expected_dex ||
          reference.index != expected_sink_method_idx ||
          invoke->GetResolvedMethod() != expected_sink_method) continue;
      HInstruction* previous = inst->GetPrevious();
      if (previous == nullptr || !previous->IsInstanceFieldGet()) continue;
      HInstanceFieldGet* get = previous->AsInstanceFieldGet();
      if (get->GetFieldInfo().GetFieldIndex() != expected_field_idx ||
          get->GetDexPc() != expected_get_dex_pc ||
          &get->GetFieldInfo().GetDexFile() != expected_dex) continue;
      if (selected_invoke != nullptr) return CloneResult::kTemplateMismatch;
      selected_get = get;
      selected_invoke = invoke;
    }
  }
  if (selected_invoke == nullptr) return CloneResult::kMissing;
  return CloneIntReadFromResolvedTemplate(
      graph, selected_get, selected_invoke, expected_sink_method, read_site);
}


/*
 * Source-matched four-way integer access injector (instance/static, get/set).
 *
 * Unlike the earlier two-PC fixture specialization, this accepts field
 * identities from the live IR itself, not from a hard-coded field index.
 * For safety this deployment stage still REQUIRES a resolved inert
 * recordInt(0, 0, value) template immediately after each field instruction,
 * in its own basic block. Uninstrumented DEX has no such template and is
 * intentionally skipped. We do not fabricate HEnvironment objects or
 * relocate a resolved call across throwing/volatile/class-init operations.
 *
 * The clone itself calls recordInt(field_index + 1, operation, exact_ssa_value).
 * field_index + 1 avoids the zero sentinel namespace. The host joins
 * (DexFile identity, field_index, compiled method index, field dex_pc)
 * with the APK-wide catalog. This three-argument sink cannot directly
 * carry the full metadata tuple; use the generic seven-argument ABI for
 * production field events after a verified invoke constructor is available.
 *
 * This is ART-source code, not a build-tested NDK binary or an enabled Frida
 * hook. It must be compiled against the source corresponding to the actual
 * ART runtime build IDs.
 */
struct IntFieldInsertionStats {
  uint32_t candidates = 0;
  uint32_t inserted = 0;
  uint32_t no_template = 0;
  uint32_t unsupported = 0;
  uint32_t identity_rejected = 0;
};

CloneResult CloneIntAccessFromResolvedTemplate(
    HGraph* graph,
    HInstruction* access,
    HInvokeStaticOrDirect* template_invoke,
    ArtMethod* expected_sink_method,
    const DexFile* expected_dex,
    uint32_t expected_field_index,
    uint32_t expected_access_pc) {
  if (graph == nullptr || access == nullptr ||
      template_invoke == nullptr || expected_sink_method == nullptr ||
      expected_dex == nullptr) {
    return CloneResult::kMissing;
  }

  HBasicBlock* block = access->GetBlock();
  if (block == nullptr || block->GetGraph() != graph ||
      template_invoke->GetBlock() != block || !graph->IsInSsaForm()) {
    return CloneResult::kGraphMismatch;
  }

  // All four HFieldAccess classes expose verified FieldInfo. The field
  // access's own source PC is used, never the following invoke's PC.
  uint32_t field_index = 0;
  const DexFile* field_dex = nullptr;
  HInstruction* value = nullptr;
  uint32_t operation = 0;  // READ=1, WRITE=2
  bool is_volatile = false;
  DataType::Type field_type = DataType::Type::kVoid;
  if (access->IsInstanceFieldGet()) {
    auto* field = access->AsInstanceFieldGet();
    field_index = field->GetFieldInfo().GetFieldIndex();
    field_dex = &field->GetFieldInfo().GetDexFile();
    field_type = field->GetFieldType();
    is_volatile = field->IsVolatile();
    value = field;
    operation = 1;
  } else if (access->IsInstanceFieldSet()) {
    auto* field = access->AsInstanceFieldSet();
    field_index = field->GetFieldInfo().GetFieldIndex();
    field_dex = &field->GetFieldInfo().GetDexFile();
    field_type = field->GetFieldType();
    is_volatile = field->IsVolatile();
    value = field->GetValue();
    operation = 2;
  } else if (access->IsStaticFieldGet()) {
    auto* field = access->AsStaticFieldGet();
    field_index = field->GetFieldInfo().GetFieldIndex();
    field_dex = &field->GetFieldInfo().GetDexFile();
    field_type = field->GetFieldType();
    is_volatile = field->IsVolatile();
    value = field;
    operation = 1;
  } else if (access->IsStaticFieldSet()) {
    auto* field = access->AsStaticFieldSet();
    field_index = field->GetFieldInfo().GetFieldIndex();
    field_dex = &field->GetFieldInfo().GetDexFile();
    field_type = field->GetFieldType();
    is_volatile = field->IsVolatile();
    value = field->GetValue();
    operation = 2;
  } else {
    return CloneResult::kTypeMismatch;
  }

  // Preserve exact field identity and avoid accidental capture of inlined
  // accesses from another DexFile or an unrelated field with the same index.
  if (field_dex != expected_dex ||
      field_index != expected_field_index ||
      access->GetDexPc() != expected_access_pc) {
    return CloneResult::kGraphMismatch;
  }
  if (field_type != DataType::Type::kInt32 || is_volatile ||
      value == nullptr || value->GetType() != DataType::Type::kInt32 ||
      field_index >= static_cast<uint32_t>(INT32_MAX)) {
    return CloneResult::kTypeMismatch;
  }
  if (access->GetNext() != template_invoke) {
    return CloneResult::kNotAdjacent;
  }

  const MethodReference method = template_invoke->GetMethodReference();
  if (!template_invoke->IsStatic() ||
      method.dex_file != expected_dex ||
      template_invoke->GetResolvedMethod() != expected_sink_method ||
      template_invoke->GetNumberOfArguments() != 3u ||
      template_invoke->InputCount() != 3u ||
      template_invoke->GetType() != DataType::Type::kVoid ||
      !template_invoke->IsClonable() ||
      !template_invoke->HasEnvironment() ||
      template_invoke->GetEnvironment() == nullptr ||
      template_invoke->GetEnvironment()->GetParent() != nullptr) {
    return CloneResult::kTemplateMismatch;
  }
  HInstruction* site = template_invoke->InputAt(0);
  HInstruction* kind = template_invoke->InputAt(1);
  if (site == nullptr || kind == nullptr ||
      !site->IsIntConstant() || !kind->IsIntConstant() ||
      site->AsIntConstant()->GetValue() != 0 ||
      kind->AsIntConstant()->GetValue() != 0 ||
      template_invoke->GetClinitCheckRequirement() !=
          HInvokeStaticOrDirect::ClinitCheckRequirement::kNone ||
      template_invoke->HasCurrentMethodInput()) {
    return CloneResult::kUnsupportedDispatch;
  }

  // All guards precede mutation. Use ART's own clone, SSA updates, block
  // insertion and environment-copy logic, never raw C++ layout copying.
  HInstruction* cloned = template_invoke->Clone(graph->GetAllocator());
  if (cloned == nullptr || !cloned->IsInvokeStaticOrDirect()) {
    return CloneResult::kTemplateMismatch;
  }
  HInvokeStaticOrDirect* invoke = cloned->AsInvokeStaticOrDirect();
  invoke->SetArgumentAt(
      0, graph->GetIntConstant(static_cast<int32_t>(field_index + 1u),
                               access->GetDexPc()));
  invoke->SetArgumentAt(
      1, graph->GetIntConstant(static_cast<int32_t>(operation),
                               access->GetDexPc()));
  invoke->SetArgumentAt(2, value);
  block->InsertInstructionBefore(invoke, template_invoke);
  invoke->CopyEnvironmentFrom(template_invoke->GetEnvironment());
  return CloneResult::kInserted;
}

// Caller passes the resolved native sink and exact compiled DexFile.
// No site allowlist: every qualifying int field get/set in this compiled
// method is considered, regardless of declaring class/field name.
// Only a verified same-block adjacent template can make it executable.
IntFieldInsertionStats CloneAllAdjacentIntFieldTemplates(
    HGraph* graph,
    const DexFile* expected_dex,
    uint32_t expected_compiled_method_index,
    uint32_t expected_sink_method_index,
    ArtMethod* expected_sink_method) {
  IntFieldInsertionStats stats;
  if (graph == nullptr || expected_dex == nullptr ||
      expected_sink_method == nullptr || !graph->IsInSsaForm() ||
      &graph->GetDexFile() != expected_dex ||
      graph->GetMethodIdx() != expected_compiled_method_index) {
    ++stats.identity_rejected;
    return stats;
  }

  for (HBasicBlock* block : graph->GetActiveBlocks()) {
    for (HInstruction* inst = block->GetFirstInstruction();
         inst != nullptr; inst = inst->GetNext()) {
      if (!inst->IsInstanceFieldGet() && !inst->IsInstanceFieldSet() &&
          !inst->IsStaticFieldGet() && !inst->IsStaticFieldSet()) {
        continue;
      }
      ++stats.candidates;
      HInstruction* next = inst->GetNext();
      if (next == nullptr || !next->IsInvokeStaticOrDirect()) {
        ++stats.no_template;
        continue;
      }
      HInvokeStaticOrDirect* invoke = next->AsInvokeStaticOrDirect();
      const MethodReference method = invoke->GetMethodReference();
      if (method.dex_file != expected_dex ||
          method.index != expected_sink_method_index ||
          invoke->GetResolvedMethod() != expected_sink_method) {
        ++stats.no_template;
        continue;
      }
      const FieldInfo* info = nullptr;
      if (inst->IsInstanceFieldGet()) {
        info = &inst->AsInstanceFieldGet()->GetFieldInfo();
      } else if (inst->IsInstanceFieldSet()) {
        info = &inst->AsInstanceFieldSet()->GetFieldInfo();
      } else if (inst->IsStaticFieldGet()) {
        info = &inst->AsStaticFieldGet()->GetFieldInfo();
      } else {
        info = &inst->AsStaticFieldSet()->GetFieldInfo();
      }
      const CloneResult result = CloneIntAccessFromResolvedTemplate(
          graph, inst, invoke, expected_sink_method, expected_dex,
          info->GetFieldIndex(), inst->GetDexPc());
      if (result == CloneResult::kInserted) {
        ++stats.inserted;
      } else {
        ++stats.unsupported;
      }
    }
  }
  return stats;
}

}  // namespace artwatch_p3
}  // namespace art
