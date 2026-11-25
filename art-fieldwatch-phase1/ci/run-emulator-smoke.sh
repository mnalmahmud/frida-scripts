#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${ARTWATCH_LOG_DIR:-/tmp/artwatch-logs}"
# adbd restarts when switching to root. A just-booted API33 emulator can
# briefly close the transport, returning "unable to connect for root: closed".
# Retry only the setup operation; never mask errors from the test workload.
root_ready=0
for attempt in 1 2 3 4 5 6 7 8; do
  if adb root && adb wait-for-device; then
    uid="$(adb shell id -u 2>/dev/null | tr -d '\r' || true)"
    if [[ "$uid" == 0 ]]; then
      root_ready=1
      break
    fi
  fi
  echo "::warning::adbd root not ready (attempt $attempt/8)"
  sleep 3
done
if [[ "$root_ready" -ne 1 ]]; then
  echo "::error::Android emulator did not stabilize in root mode"
  adb devices -l || true
  exit 1
fi
variant="${ARTWATCH_BUILD_VARIANT:-debug}"
case "$variant" in
  debug|release) ;;
  *) echo "Invalid APK variant: $variant" >&2; exit 1 ;;
esac
apk="art-fieldwatch-phase1/test/app/build/outputs/apk/$variant/app-$variant.apk"
test -f "$apk" || { echo "APK not found: $apk" >&2; exit 1; }
adb install -r "$apk"
FRIDA_VERSION="${FRIDA_VERSION:-17.27.1}"
ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in
 x86_64) FRIDA_ARCH=x86_64 ;;
 arm64-v8a) FRIDA_ARCH=arm64 ;;
 x86) FRIDA_ARCH=x86 ;;
 armeabi-v7a) FRIDA_ARCH=arm ;;
 *) echo "Unsupported emulator ABI: $ABI" >&2; exit 1 ;;
esac
curl --fail --location --retry 3 "https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida-server-$FRIDA_VERSION-android-$FRIDA_ARCH.xz" --output /tmp/frida-server.xz
xz -df /tmp/frida-server.xz
adb push /tmp/frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell '(/data/local/tmp/frida-server >/data/local/tmp/artwatch-frida-server.log 2>&1 < /dev/null &)'
# Check that frida-server actually survives startup.
ready=0
for i in $(seq 1 12); do
  if adb shell pidof frida-server >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
if [ "$ready" -ne 1 ]; then
  echo "Frida server is not running"
  adb shell cat /data/local/tmp/artwatch-frida-server.log || true
  exit 1
fi
if [[ "${ARTWATCH_SHADOW_SHIM:-0}" == 1 ]]; then
  # The app uses System.loadLibrary() from its packaged nativeLibraryDir;
  # never attempt executable mappings from /data/local/tmp in an app context.
  # grep -q can close its pipe early, yielding unzip SIGPIPE under
  # pipefail and falsely reporting a missing library. Read the full listing.
  if ! unzip -Z -1 "$apk" | grep -Fx 'lib/x86_64/libartwatch_shadow.so' >/dev/null; then
    echo "Native shim missing from APK" >&2
    unzip -Z -1 "$apk" | grep 'libartwatch_' || true
    exit 1
  fi
fi
# Pull ART ELF files for offline symbol inspection; never scan their full
# symbol tables inside the injected application.
bash art-fieldwatch-phase1/ci/art-binary-inventory.sh || true
if ! python3 art-fieldwatch-phase1/ci/smoke_test.py; then
  adb shell cat /data/local/tmp/artwatch-frida-server.log || true
  adb logcat -d -t 1500 > "$ARTWATCH_LOG_DIR/logcat-failure.txt" || true
  exit 1
fi

# Independent public-Java-bridge oracle; no compiler mutation in this test.
if [[ "$variant" == release && "${ARTWATCH_SHADOW_SHIM:-0}" == 1 ]]; then
  python3 art-fieldwatch-phase1/lab/run_stock_fixture_oracle.py
fi

# Experimental *instruction-level* nterp backend on unmodified ART.
# A separate process avoids previous JIT warmup / method-hook interference.
if [[ "$variant" == release && "${ARTWATCH_SHADOW_SHIM:-0}" == 1 ]]; then
  # Every opcode group consumes all four hardware breakpoint slots. Run each
  # group in a fresh, non-debuggable release process; never present this as
  # simultaneous app-wide coverage.
  first_group=1
  for group in scalar32 wide64 boolean8 byte8 char16 short16; do
    if [[ "$first_group" == 0 ]]; then
      adb shell am force-stop com.example.artfieldwatch
    fi
    first_group=0
    echo "Stock ART nterp field opcode group: $group"
    ARTWATCH_NTERP_GROUP="$group" python3 art-fieldwatch-phase1/ci/run-nterp-smoke.py
  done
  # Experimental software opcode-entry hooks, without the four-slot limit.
  # This intentionally runs in another fresh release process. An exact
  # 5120-event oracle must pass before calling it supported.
  adb shell am force-stop com.example.artfieldwatch
  ARTWATCH_NTERP_GROUP=allPrimitives ARTWATCH_NTERP_BACKEND=software \
    python3 art-fieldwatch-phase1/ci/run-nterp-smoke.py
  # Two independent named workers run the same verified field leaf DEX.
  # The host holds their Java start gate until Stalker follows both TIDs.
  adb shell am force-stop com.example.artfieldwatch
  ARTWATCH_NTERP_GROUP=allPrimitives ARTWATCH_NTERP_BACKEND=software \
    ARTWATCH_NTERP_WORKLOAD=parallel \
    python3 art-fieldwatch-phase1/ci/run-nterp-smoke.py
fi
