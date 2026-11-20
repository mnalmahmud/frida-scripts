#!/usr/bin/env bash
# Inspect the DEX actually shipped to the emulator, not Java source or classfiles.
# Read-only; saved per variant and uploaded with other ART CI evidence.
set -euo pipefail
variant="${ARTWATCH_BUILD_VARIANT:-debug}"
case "$variant" in debug|release) ;; *) echo "Invalid variant: $variant" >&2; exit 1 ;; esac
apk="art-fieldwatch-phase1/test/app/build/outputs/apk/$variant/app-$variant.apk"
test -f "$apk"
out="${ARTWATCH_LOG_DIR:-/tmp/artwatch-logs}"
mkdir -p "$out"
echo "variant=$variant apk=$apk"
unzip -p "$apk" classes.dex | sha256sum | tee "$out/dex-sha256-$variant.txt"
analyzer="${ANDROID_HOME:-}/cmdline-tools/latest/bin/apkanalyzer"
if [[ ! -x "$analyzer" ]]; then
  analyzer="$(command -v apkanalyzer || true)"
fi
if [[ -z "$analyzer" || ! -x "$analyzer" ]]; then
  echo "apkanalyzer not found; leaving a diagnostic instead of guessing DEX shape"
  printf 'apkanalyzer unavailable\n' > "$out/fieldir-$variant.txt"
  exit 0
fi
if "$analyzer" dex code --class com.example.artfieldwatch.FieldIRTarget "$apk" > "$out/fieldir-$variant.smali" 2> "$out/fieldir-$variant.stderr"; then
  echo "-- FieldIRTarget actual DEX instructions, $variant --"
  grep -E '^\.method|^[[:space:]]*\.method|iput|iget|invoke|return' "$out/fieldir-$variant.smali" | head -n 90 || true
  echo "-- DEX dump saved in $out/fieldir-$variant.smali --"
else
  echo "apkanalyzer failed; preserving stderr as diagnostic"
  cat "$out/fieldir-$variant.stderr"
  printf 'apkanalyzer failed\n' > "$out/fieldir-$variant.txt"
fi
