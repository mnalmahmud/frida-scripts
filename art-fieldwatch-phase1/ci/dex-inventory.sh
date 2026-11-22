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
# Preserve the exact method_ids[] index of the real native sink in the
# packaged DEX (it can change across debug/release, or between builds).
python3 art-fieldwatch-phase1/ci/dex_method_index.py "$apk" |
  tee "$out/p3-sink-method-$variant.json"
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
  # The release test must preserve both instructions in the *new* method.
  # The old test() intentionally demonstrates release DEX simplification.
  if [[ "$variant" == release ]]; then
    awk '/^\.method public testViaIdentity\(I\)I/ { inside=1; next }
         inside && /^\.end method/ { exit }
         inside { print }' "$out/fieldir-$variant.smali" > "$out/fieldir-release-identity.smali"
    if ! grep -q 'iput' "$out/fieldir-release-identity.smali" ||
       ! grep -q 'iget' "$out/fieldir-release-identity.smali"; then
      echo "::error::Release DEX removed iget/iput from testViaIdentity; ART LSE cannot be tested with it."
      cat "$out/fieldir-release-identity.smali"
      exit 1
    fi
    echo "Verified release testViaIdentity DEX retains both iput and iget."
    awk '/^\.method.* p3CanaryOn\(/ { inside=1; next }
         inside && /^\.end method/ { exit }
         inside { print }' "$out/fieldir-$variant.smali" > "$out/fieldir-release-p3CanaryOn.smali"
    if ! grep -q 'iput' "$out/fieldir-release-p3CanaryOn.smali" ||
       ! grep -q 'iget' "$out/fieldir-release-p3CanaryOn.smali"; then
      echo "::error::P3 canary missing iput or iget in release DEX"
      cat "$out/fieldir-release-p3CanaryOn.smali"
      exit 1
    fi
    if grep -q 'FieldEventSink' "$out/fieldir-release-p3CanaryOn.smali"; then
      echo "::error::P3 canary must not call the native event sink"
      exit 1
    fi
    echo "Verified P3 canary has real field instructions without an explicit event sink."
    # The template carrier must retain a genuine resolved native invoke
    # alongside both field operations in the same DEX method.
    awk '/^\.method.* p3TemplateCarrierOn\(/ { inside=1; next }
         inside && /^\.end method/ { exit }
         inside { print }' "$out/fieldir-$variant.smali" > "$out/fieldir-release-p3TemplateCarrierOn.smali"
    if ! grep -q 'iput' "$out/fieldir-release-p3TemplateCarrierOn.smali" ||
       ! grep -q 'iget' "$out/fieldir-release-p3TemplateCarrierOn.smali" ||
       ! grep -q 'FieldEventSink;->recordInt(III)V' "$out/fieldir-release-p3TemplateCarrierOn.smali"; then
      echo "::error::P3 template must retain iput, iget and a real recordInt invoke"
      cat "$out/fieldir-release-p3TemplateCarrierOn.smali"
      exit 1
    fi
    echo "Verified P3 template DEX contains field operations and recordInt invoke."
    # Separate loop fixtures should also preserve actual field reads in DEX.
    # Otherwise JIT cannot be credited with eliminating them.
    for method in exerciseOverwrites exerciseAlternating; do
      awk -v method="$method" '
        $0 ~ "^\\.method.* " method "\\(I\\)I" { inside=1; next }
        inside && /^\.end method/ { exit }
        inside { print }
      ' "$out/fieldir-$variant.smali" > "$out/fieldir-release-$method.smali"
      if ! grep -q 'iput' "$out/fieldir-release-$method.smali" ||
         ! grep -q 'iget' "$out/fieldir-release-$method.smali"; then
        echo "::error::Release DEX missing field iput/iget in $method"
        cat "$out/fieldir-release-$method.smali"
        exit 1
      fi
      echo "Verified release DEX $method retains both iput and iget."
    done
  fi
else
  echo "apkanalyzer failed; preserving stderr as diagnostic"
  cat "$out/fieldir-$variant.stderr"
  printf 'apkanalyzer failed\n' > "$out/fieldir-$variant.txt"
fi
