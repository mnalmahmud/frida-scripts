#!/usr/bin/env python3
"""Install the fixture-only backend in a separate, source-built ART lab tree.

Never patches a device binary. Exact input blob and anchor checks fail closed.
"""
import argparse
import hashlib
from pathlib import Path

EXPECTED_BLOB = "0b91120c58b05567289a94bdd5fc4fb5765efa9e"
RELATIVE = Path("runtime/interpreter/interpreter_common.h")
REPLACEMENTS = [
  [
    "void ThrowNullPointerExceptionFromInterpreter()\n",
    "// ARTWATCH_LAB_V1: synthetic test fixture only. Do not ship in production.\ninline void RecordArtwatchLabInt(ArtMethod* method,\n                                uint32_t dex_pc,\n                                uint32_t field_index,\n                                bool is_static,\n                                bool is_write,\n                                int32_t value)\n    REQUIRES_SHARED(Locks::mutator_lock_) {\n  // No public configuration or arbitrary field selection. Only these four\n  // fixed leaf methods in the repository's own laboratory application.\n  const auto name = method->GetNameView();\n  const char* label = nullptr;\n  if (!is_static &&\n      method->GetDeclaringClass()->DescriptorEquals(\n          \"Lcom/example/artfieldwatch/NoTemplateTarget;\")) {\n    if (is_write && name == \"writeInstance\") label = \"writeInstance\";\n    if (!is_write && name == \"readInstance\") label = \"readInstance\";\n  } else if (is_static &&\n             method->GetDeclaringClass()->DescriptorEquals(\n                 \"Lcom/example/artfieldwatch/NoTemplateStaticState;\")) {\n    if (is_write && name == \"writeStatic\") label = \"writeStatic\";\n    if (!is_write && name == \"readStatic\") label = \"readStatic\";\n  }\n  if (label == nullptr) return;\n  static std::atomic<uint32_t> sequence{0};\n  const uint32_t n = sequence.fetch_add(1, std::memory_order_relaxed) + 1;\n  if (n > 1024u) {\n    if (n == 1025u) LOG(ERROR) << \"ARTWATCH_LAB_OVERFLOW\";\n    return;\n  }\n  LOG(INFO) << \"ARTWATCH_LAB_V1 seq=\" << n\n            << \" method=\" << label\n            << \" methodId=\" << method->GetDexMethodIndex()\n            << \" fieldId=\" << field_index\n            << \" dexPc=\" << dex_pc\n            << \" kind=\" << (is_write ? 2 : 1)\n            << \" value=\" << value;\n}\n\nvoid ThrowNullPointerExceptionFromInterpreter()\n"
  ],
  [
    "  return true;\n}\n\nstatic inline bool CheckWriteConstraint",
    "  if (!transaction_active && field_type == Primitive::kPrimInt &&\n      !self->IsExceptionPending() && !shadow_frame.GetForcePopFrame()) {\n    RecordArtwatchLabInt(method, shadow_frame.GetDexPC(), field_idx,\n                         is_static, false, result.GetI());\n  }\n  return true;\n}\n\nstatic inline bool CheckWriteConstraint"
  ],
  [
    "  return DoFieldPutCommon<field_type, do_assignability_check, transaction_active>(self,\n                                                                                  shadow_frame,\n                                                                                  obj,\n                                                                                  f,\n                                                                                  value);",
    "  const bool success =\n      DoFieldPutCommon<field_type, do_assignability_check, transaction_active>(\n          self, shadow_frame, obj, f, value);\n  if (success && !transaction_active && field_type == Primitive::kPrimInt &&\n      !self->IsExceptionPending() && !shadow_frame.GetForcePopFrame()) {\n    RecordArtwatchLabInt(method, shadow_frame.GetDexPC(), field_idx,\n                         is_static, true, value.GetI());\n  }\n  return success;"
  ]
]


def blob_id(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def patch(text):
    for before, after in REPLACEMENTS:
        if text.count(before) != 1:
            raise ValueError("Missing or ambiguous ART source anchor")
        text = text.replace(before, after, 1)
    return text


def self_test():
    sample = "\n".join(before for before, _ in REPLACEMENTS)
    modified = patch(sample)
    assert modified.count("RecordArtwatchLabInt(") == 3
    assert "const bool success =" in modified
    for invalid in (sample + REPLACEMENTS[0][0], sample.replace(REPLACEMENTS[1][0], "")):
        try:
            patch(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Unexpected source accepted")
    print("ART lab source patch self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("art_tree", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.art_tree is None:
        parser.error("Supply a separate ART lab source tree")
    target = args.art_tree / RELATIVE
    data = target.read_bytes()
    if blob_id(data) != EXPECTED_BLOB:
        raise SystemExit("ART source revision mismatch; no changes made")
    modified = patch(data.decode("utf-8"))
    target.write_text(modified, encoding="utf-8")
    print("Installed fixture-only lab instrumentation in", target)


if __name__ == "__main__":
    main()
