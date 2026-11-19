#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${ARTWATCH_LOG_DIR:-/tmp/artwatch-logs}"
adb root
adb wait-for-device
adb install -r art-fieldwatch-phase1/test/app/build/outputs/apk/debug/app-debug.apk
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
sleep 3
python3 art-fieldwatch-phase1/ci/smoke_test.py
