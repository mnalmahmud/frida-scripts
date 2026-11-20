#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${ARTWATCH_LOG_DIR:-/tmp/artwatch-logs}"
adb root
adb wait-for-device
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
# Pull ART ELF files for offline symbol inspection; never scan their full
# symbol tables inside the injected application.
bash art-fieldwatch-phase1/ci/art-binary-inventory.sh || true
if ! python3 art-fieldwatch-phase1/ci/smoke_test.py; then
  adb shell cat /data/local/tmp/artwatch-frida-server.log || true
  adb logcat -d -t 1500 > "$ARTWATCH_LOG_DIR/logcat-failure.txt" || true
  exit 1
fi
