# ART Fieldwatch Phase 1 CI

This is a **read-only diagnostic** for JIT symbol and compilation-path discovery.
It is NOT yet a Java field-read/write interceptor.

The workflow uses Android API 33 and 34 x86_64 emulators for spawn,
Frida attachment, ART module discovery and APK warmup. Both x86_64 tests
operate in passive inventory mode; they do not prove the ARM64 hook works.

The optional workflow_dispatch arm64 job targets Android 14 API 34
and **strictly** checks for a JIT hook and compilation. Failing here can
mean missing symbols, unexpected ART ABI, no compilations, or unavailable
emulator images. Preserve CI logs as research evidence, not as proof of field
monitoring coverage.

The architecture goal is API 21-37. There is no compatibility guarantee
without running the field-watch suite on each profile.

Frida runtime and server version: 17.27.1 (pinned).

Run from GitHub Actions > ART Fieldwatch phase 1 > Run workflow,
optionally arm64=true. Check the log artifacts for diagnostics.
