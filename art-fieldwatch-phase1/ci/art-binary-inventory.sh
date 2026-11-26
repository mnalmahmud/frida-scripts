#!/usr/bin/env bash
# Offline ELF visibility evidence (no symbol scan inside the Frida process).
set -euo pipefail
# macOS Homebrew installs GNU binutils with a g-prefix.
if ! command -v readelf >/dev/null 2>&1 && command -v greadelf >/dev/null 2>&1; then
  readelf() { greadelf "$@"; }
fi
out="${ARTWATCH_LOG_DIR:-/tmp/artwatch-logs}"
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
api="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
abi="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
{
  echo "device api=$api abi=$abi"
  for library in libart.so libart-compiler.so; do
    source="/apex/com.android.art/lib64/$library"
    if ! adb pull "$source" "$tmp/$library" >/dev/null 2>&1; then
      echo "pull-failed $source"
      continue
    fi
    if [[ "$library" == libart.so && "$abi" == x86_64 && ( "$api" == 33 || "$api" == 34 ) ]]; then
      python3 art-fieldwatch-phase1/ci/nterp_profile.py "$tmp/$library" \
        --api "$api" --out "$out/nterp-profile.json" ||
        echo "NTERP_PROFILE_UNAVAILABLE: stock ART table could not be certified"
    fi
    if [[ "$library" == libart.so && "$abi" == arm64-v8a && "$api" == 34 ]]; then
      # Only a device-matched, experimental ABI profile; no built-in
      # ARM64 allowlist or claim of confirmed field-event fidelity.
      python3 art-fieldwatch-phase1/ci/nterp_profile.py "$tmp/$library" \
        --api 34 --architecture arm64 --experimental-arm64 \
        --out "$out/nterp-arm64-experimental-profile.json" ||
        echo "ARM64_NTERP_PROFILE_UNAVAILABLE: ELF table not independently verified"
    fi
    echo "=== $library ==="
    sha256sum "$tmp/$library"
    echo "-- build-id --"
    readelf -n "$tmp/$library" 2>&1 | grep -i -m 1 'Build ID:' || true
    echo "-- available symbol sections --"
    readelf -SW "$tmp/$library" 2>&1 | grep -E ' (\.symtab|\.dynsym|\.debug_info|\.gnu_debugdata) ' || true
    if [[ "$library" == libart.so ]]; then
      echo "-- JNI managed reference bridge ABI candidates --"
      readelf -Ws "$tmp/$library" 2>&1 |
        grep -E '(JNI_GetCreatedJavaVMs|JNIEnvExt.*NewLocalRef|JNIEnvExt.*AddLocalReference)' |
        head -n 50 || true
    fi
    echo "-- targeted symbols (dynamic and full, if available) --"
    readelf -Ws "$tmp/$library" 2>&1 |
      grep -E 'HGraphBuilder|OptimizingCompiler|TryCompile|RunOptimizations|PassObserver|JitCompiler.*CompileMethod|jit_load|CompileMethodInternal|BuildInstanceFieldAccess|BuildStaticFieldAccess|HInstanceField(Get|Set)|HStaticField(Get|Set)' |
      head -n 80 || true
    echo "-- graph insertion and field node vtable candidates --"
    readelf -Ws "$tmp/$library" 2>&1 |
      grep -E '(HBasicBlock.*AddInstruction|HInstructionBuilder.*AppendInstruction|_ZTVN3art[0-9]+H(Unresolved)?(Instance|Static)Field(Get|Set)E)' |
      head -n 100 || true
    echo "-- P3 invoke construction/insertion ABI candidates --"
    readelf -Ws "$tmp/$library" 2>&1 |
      grep -E '(HInvokeStaticOrDirect|HBasicBlock.*InsertInstruction(After|Before)|HInstruction.*SetEnvironment|HEnvironment.*(Copy|Create)|HInvoke.*(SetArgument|SetRawInputAt)|HGraph.*GetArena)' |
      head -n 120 || true
    echo "-- optimization, IR replacement/removal candidates --"
    readelf -Ws "$tmp/$library" 2>&1 |
      grep -E '(LoadStoreElimination|LSEVisitor|HInstruction.*ReplaceWith|HBasicBlock.*RemoveInstruction|ReplaceAndRemoveInstruction)' |
      head -n 100 || true
    echo "-- HGraphVisitor traversal and instruction ownership symbols --"
    readelf -Ws "$tmp/$library" 2>&1 |
      grep -E '(HGraphVisitor.*(VisitBasicBlock|VisitInsertionOrder|VisitReversePostOrder)|HBasicBlock.*AddInstruction|HInstruction.*GetBlock)' |
      head -n 120 || true
    echo "-- HGraph/AddBlock and graph checker exports --"
    readelf -Ws "$tmp/$library" 2>&1 |
      grep -E '(HGraph.*AddBlock|GraphChecker.*VisitBasicBlock|HGraph.*BuildDominatorTree|HBasicBlock.*GetFirstInstruction|HInstruction.*GetBlock|HGraphVisitor.*VisitBasicBlock)' |
      head -n 100 || true
    echo "-- summary --"
    if readelf -SW "$tmp/$library" | grep -q ' \.symtab '; then
      echo 'full-symbol-table=present'
    else
      echo 'full-symbol-table=absent'
    fi
  done
} > "$out/art-elf-inventory.txt" 2>&1
cat "$out/art-elf-inventory.txt"
