#!/usr/bin/env bash
# Offline ELF visibility evidence (no symbol scan inside the Frida process).
set -euo pipefail
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
    echo "=== $library ==="
    sha256sum "$tmp/$library"
    echo "-- build-id --"
    readelf -n "$tmp/$library" 2>&1 | grep -i -m 1 'Build ID:' || true
    echo "-- available symbol sections --"
    readelf -SW "$tmp/$library" 2>&1 | grep -E ' (\.symtab|\.dynsym|\.debug_info|\.gnu_debugdata) ' || true
    echo "-- targeted symbols (dynamic and full, if available) --"
    readelf -Ws "$tmp/$library" 2>&1 |
      grep -E 'HGraphBuilder|OptimizingCompiler|TryCompile|RunOptimizations|PassObserver|JitCompiler.*CompileMethod|jit_load|CompileMethodInternal|BuildInstanceFieldAccess|BuildStaticFieldAccess|HInstanceField(Get|Set)|HStaticField(Get|Set)' |
      head -n 80 || true
    echo "-- summary --"
    if readelf -SW "$tmp/$library" | grep -q ' \.symtab '; then
      echo 'full-symbol-table=present'
    else
      echo 'full-symbol-table=absent'
    fi
  done
} > "$out/art-elf-inventory.txt" 2>&1
cat "$out/art-elf-inventory.txt"
