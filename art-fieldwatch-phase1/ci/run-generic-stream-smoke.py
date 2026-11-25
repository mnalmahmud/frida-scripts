#!/usr/bin/env python3
"""Validate sustained public-CLI Stalker streaming (>8192 real field ops).

This is not a synthetic queue benchmark: the Java release APK performs
10,000 verified writes and 10,000 verified reads on a single instance
field, while the generic watcher drains its native callback stream.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PACKAGE = "com.example.artfieldwatch"
PROCESS = PACKAGE + ":fieldwatch_nterp"
ACTIVITY = PACKAGE + "/.NoTemplateNterpActivity"
OWNER = "Lcom/example/artfieldwatch/NoTemplateTarget;"
SITES = ("writeInstance", "readInstance")
COUNT = 10000
EXPECTED_CHECKSUM = 31024


def adb(*args, timeout=30):
    return subprocess.check_output(["adb", *args], text=True,
                                   timeout=timeout).strip()


def logcat(pid):
    return adb("logcat", "-d", f"--pid={pid}", "-s",
               "ARTWATCH_NTERP_LAB:I", "*:S")


def wait_for(condition, timeout, label):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for " + label)


def main():
    if os.environ.get("ARTWATCH_BUILD_VARIANT") != "release":
        raise AssertionError("Non-debuggable release APK required")
    root = Path(os.environ.get("ARTWATCH_LOG_DIR", "/tmp/artwatch-logs"))
    root.mkdir(parents=True, exist_ok=True)
    apk = (BASE / "test" / "app" / "build" / "outputs" / "apk" /
           "release" / "app-release.apk")
    if not apk.is_file():
        raise FileNotFoundError(apk)
    adb("shell", "am", "force-stop", PACKAGE)
    adb("logcat", "-c")
    adb("shell", "am", "start", "-W", "-n", ACTIVITY)
    def live_pid():
        try:
            return adb("shell", "pidof", PROCESS).split()[0]
        except (subprocess.CalledProcessError, IndexError):
            return None
    pid = wait_for(live_pid, 15, "separate nterp lab process")
    output = root / "generic-fieldwatch-streaming.jsonl"
    report = root / "generic-fieldwatch-streaming-coverage.json"
    trace = root / "generic-fieldwatch-streaming-host.log"
    cmd = [sys.executable, str(BASE / "watch.py"),
           "--apk", str(apk), "--auto-profile",
           "--process", pid, "--thread", "NterpFieldProbe",
           "--poll-ms", "50", "--duration", "22",
           "--output", str(output), "--coverage-output", str(report)]
    for name in SITES:
        cmd += ["--field", f"{OWNER}#{name}#value"]
    with trace.open("w+", encoding="utf-8") as log:
        child = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=log)
        try:
            def watcher_armed():
                if child.poll() is not None:
                    raise AssertionError(
                        "Watcher exited before arming: " +
                        trace.read_text(errors="replace")[-3000:])
                log.flush()
                return "Watching " in trace.read_text(errors="replace")
            wait_for(watcher_armed, 20, "generic Stalker watch ready")
            started = subprocess.run(
                ["adb", "shell", "am", "start", "-W", "-n", ACTIVITY,
                 "--ez", "streaming", "true"],
                capture_output=True, text=True, timeout=15)
            if started.returncode != 0:
                raise AssertionError("Failed to launch streaming Java workload")
            def done():
                log = logcat(pid)
                if "NTERP_LAB_FAILED" in log:
                    raise AssertionError("Java streaming field oracle failed: " + log)
                return (f"NTERP_LAB_STREAMING_DONE checks={COUNT} "
                        f"checksum={EXPECTED_CHECKSUM}") in log
            wait_for(done, 18, "10,000 Java writes and reads")
            if child.wait(timeout=35) != 0:
                raise AssertionError("watch.py streaming process failed: " +
                                     trace.read_text(errors="replace")[-5000:])
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
    rows = [json.loads(line) for line in output.read_text().splitlines()
            if line.strip()]
    if len(rows) != 2 * COUNT:
        raise AssertionError(
            f"Expected {2 * COUNT} real field events, got {len(rows)}")
    for i in range(COUNT):
        expected = 123456 + i * 7
        for kind, name, op in ((2, "writeInstance", 0x59),
                               (1, "readInstance", 0x52)):
            j = i * 2 + (kind == 1)
            event = rows[j]
            requirements = {
                "seq": j + 1, "method": name, "methodClass": OWNER,
                "fieldName": "value", "fieldType": "I",
                "kind": kind, "opcode": op, "value": expected,
                "valueRepresentation": "signed-int32",
                "dexPcSource":
                    "live instruction base verified against packaged DEX bytes",
            }
            for key, want in requirements.items():
                if event.get(key) != want:
                    raise AssertionError(
                        f"Stream event {j} {key}: {event.get(key)!r} != {want!r}")
    coverage = json.loads(report.read_text())
    if (coverage["observedEvents"] != 2 * COUNT or
            coverage["totalSelectedSites"] != 2 or
            coverage["observedSites"] != 2 or
            coverage["unobservedSites"] != 0 or
            sorted(x["observedCount"] for x in coverage["sites"]) !=
            [COUNT, COUNT]):
        raise AssertionError("Streaming per-site coverage report mismatch")
    print(f"PASS: {2 * COUNT} exact non-debuggable nterp field events "
          "streamed by generic CLI, with zero loss and complete site counts")


if __name__ == "__main__":
    main()
