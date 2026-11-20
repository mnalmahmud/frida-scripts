#!/usr/bin/env bash
# Pin the NDK and build only a passive Android 13 x86_64 ELF shared library.
set -euo pipefail
version="27.2.12479018"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
: "${sdk:?Set ANDROID_HOME or ANDROID_SDK_ROOT}"
clang="$sdk/ndk/$version/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android33-clang"
if [[ ! -x "$clang" ]]; then
  # sdkmanager closes stdin when done; under pipefail, 'yes' then reports
  # SIGPIPE even after a successful install. Check the installed compiler.
  (yes | sdkmanager --install "ndk;$version" >/dev/null) || test -x "$clang"
fi
test -x "$clang"
out="art-fieldwatch-phase1/native/out"
mkdir -p "$out"
"$clang" -std=c11 -O2 -fPIC -fvisibility=hidden -fstack-protector-strong \
  -Wall -Wextra -Werror -shared -Wl,-z,relro -Wl,-z,now \
  art-fieldwatch-phase1/native/passive-shadow.c -ldl \
  -o "$out/libartwatch_shadow.so"
file "$out/libartwatch_shadow.so"
readelf -Ws "$out/libartwatch_shadow.so" | grep -E 'artwatch_shadow_(init|graph|node|report|scope_begin|scope_end)' | tee "$out/exports.txt"

# Package the shim as an app-owned native library. This is an ephemeral CI
# build output, not a tracked ELF in the research branch.
jni_dir="art-fieldwatch-phase1/test/app/src/main/jniLibs/x86_64"
mkdir -p "$jni_dir"
cp "$out/libartwatch_shadow.so" "$jni_dir/libartwatch_shadow.so"
echo "Native shadow library staged for APK packaging: $jni_dir"
