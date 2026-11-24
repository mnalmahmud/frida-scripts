#!/usr/bin/env python3
"""Isolated stock ART nterp field-opcode runtime test, no Java method hooks.

Strict, optional API33 x86_64 research backend. Missing interpreter coverage
is an explicit failure, not an inferred success based on method wrappers.
"""
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
PKG = "com.example.artfieldwatch"
LAB_PROCESS = PKG + ":fieldwatch_nterp"
ACTIVITY = PKG + "/.NoTemplateNterpActivity"
ORDER = ("writeInstance", "writeStatic", "readInstance", "readStatic")
OPCODE = {"writeInstance": 0x59, "readInstance": 0x52,
          "writeStatic": 0x67, "readStatic": 0x60}


def verify(catalog, result):
    if result.get("ready") is not True or result.get("errors") or result.get("dropped"):
        raise AssertionError(f"nterp backend unavailable or rejected: {result}")
    methods = {m["methodName"]: m for m in catalog["fixtureMethods"]}
    if set(methods) != set(ORDER):
        raise AssertionError("Missing synthetic DEX method identity")
    events = result["events"]
    if len(events) != 512:
        raise AssertionError(f"Expected 512 executed nterp field opcodes, got {len(events)}")
    for n, event in enumerate(events):
        iteration, k = divmod(n, 4)
        name = ORDER[k]
        m = methods[name]
        f = m["fields"][0]
        value = (7 + 3*iteration) if "Instance" in name else -11 - 5*iteration
        dex = catalog.get("dexFiles", [{}])[0]
        expected = {"seq": n + 1, "method": name,
                    "methodClass": m["methodClass"],
                    "declaringClass": f["declaringClass"],
                    "fieldName": f["fieldName"], "fieldType": "I",
                    "dexId": m["dexId"], "dexSha256": dex["sha256"],
                    "methodIndex": m["methodIndex"], "fieldIndex": f["fieldIndex"],
                    "dexPc": f["dexPc"], "opcode": OPCODE[name],
                    "kind": 2 if name.startswith("write") else 1,
                    "value": value}
        for key, want in expected.items():
            if event.get(key) != want:
                raise AssertionError(f"nterp instruction event {n} {key}: {event} != {want}")
        if event.get("dexPcSource") != "single-candidate DEX site":
            raise AssertionError("Unverified DEX PC provenance")
        if not event.get("instructionAddress"):
            raise AssertionError("Runtime instruction pointer missing")
    print("PASS: 512 stock ART nterp field operations, exact values and DEX identity")


def self_test():
    names = ORDER
    methods = []
    for i, name in enumerate(names):
        op = OPCODE[name]
        owner = "Lcom/example/artfieldwatch/NoTemplate" + (
            "Target;" if "Instance" in name else "StaticState;")
        methods.append({"methodName": name, "methodClass": owner,
                        "methodIndex": 10+i, "dexId": 0, "fields": [
            {"fieldIndex": i//2, "dexPc": 0,
             "fieldName": "value" if "Instance" in name else "shared",
             "declaringClass": owner}]})
    cat = {"fixtureMethods": methods, "dexFiles": [{
        "dexId": 0, "sha256": "0"*64}]}
    rows = []
    for i in range(128):
        for j, name in enumerate(names):
            m = methods[j]
            rows.append({"seq": i*4+j+1, "method": name,
                         "methodClass": m["methodClass"],
                         "declaringClass": m["fields"][0]["declaringClass"],
                         "fieldName": m["fields"][0]["fieldName"],
                         "fieldType": "I", "dexId": 0, "dexSha256": "0"*64,
                         "dexPcSource": "single-candidate DEX site",
                         "methodIndex": m["methodIndex"],
                         "fieldIndex": m["fields"][0]["fieldIndex"],
                         "dexPc": 0, "opcode": OPCODE[name],
                         "kind": 2 if name.startswith("write") else 1,
                         "value": 7+3*i if "Instance" in name else -11-5*i,
                         "instructionAddress": "0x1234"})
    verify(cat, {"ready": True, "events": rows, "errors": [], "dropped": 0})
    for bad in (rows[:-1], rows + [rows[-1]],
                [{**rows[0], "value": 0}, *rows[1:]]):
        try: verify(cat, {"ready": True, "events": bad, "errors": [], "dropped": 0})
        except AssertionError: pass
        else: raise AssertionError("Invalid nterp trace accepted")
    print("nterp event verifier self-test passed")


def main():
    if os.environ.get("ARTWATCH_BUILD_VARIANT") != "release":
        raise RuntimeError("Only the non-debuggable release APK is supported")
    out = Path(os.environ.get("ARTWATCH_LOG_DIR", "/tmp/artwatch-logs"))
    profile = json.loads((out / "nterp-profile.json").read_text())
    catalog = json.loads((out / "field-sites-release.json").read_text())
    # Explicit selection is test-only. The probe itself consumes arbitrary
    # exact field-site selectors from a packaged single-DEX catalog.
    selected = [{"methodClass": m["methodClass"],
                 "methodName": m["methodName"],
                 "fieldName": m["fields"][0]["fieldName"]}
                for m in catalog["fixtureMethods"]]
    source = ("globalThis.__artwatchNterpSelectors=" + json.dumps(selected) + ";\n" +
              "globalThis.__artwatchNterpProfile=" + json.dumps(profile) + ";\n" +
              "globalThis.__artwatchNterpCatalog=" + json.dumps(catalog) + ";\n" +
              (BASE / "nterp-field-probe.js").read_text())
    import frida
    device = frida.get_usb_device(timeout=30)
    joined, results, errors, events = [], {}, [], []
    trace = []
    have_agent = threading.Event()

    def on_message(message, unused):
        trace.append(str(message)[:2000])
        if message.get("type") == "error":
            errors.append(message.get("stack") or str(message))
        else:
            payload = message.get("payload")
            if isinstance(payload, dict):
                events.append(payload)

    def on_spawn(spawn):
        trace.append(f"spawn-added {spawn.identifier} pid={spawn.pid}")
        if spawn.identifier != LAB_PROCESS:
            try: device.resume(spawn.pid)
            except Exception as e: errors.append(str(e))
            return
        def initialize():
            try:
                session = device.attach(spawn.pid)
                script = session.create_script(source)
                script.on("message", on_message)
                script.load()
                trace.append("script loaded")
                results["pid"] = spawn.pid
                results["session"] = session
                results["script"] = script
                device.resume(spawn.pid)
                trace.append("lab process resumed")
            except Exception as e:
                errors.append(str(e))
                try: device.resume(spawn.pid)
                except Exception: pass
            finally:
                have_agent.set()
        worker = threading.Thread(target=initialize, daemon=True)
        joined.append(worker)
        worker.start()

    subprocess.run(["adb", "logcat", "-c"], check=True)
    device.on("spawn-added", on_spawn)
    device.enable_spawn_gating()
    child = subprocess.Popen(["adb", "shell", "am", "start", "-W", "-n", ACTIVITY],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        if not have_agent.wait(25):
            raise AssertionError("Frida never received the lab process spawn")
        if errors or "script" not in results:
            raise AssertionError(f"Failed to attach nterp probe: {errors}")
        started_output, _ = child.communicate(timeout=25)
        trace.append("initial am start: " + started_output[:500])
        if child.returncode != 0:
            raise AssertionError("Could not launch separate nterp activity")
        def lab_log():
            return subprocess.check_output(
                ["adb", "logcat", "-d", "--pid=" + str(results["pid"]),
                 "-s", "ARTWATCH_NTERP_LAB:I", "*:S"], text=True)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            log = lab_log()
            if "NTERP_LAB_FAILED" in log:
                raise AssertionError("Synthetic nterp process failed during startup")
            if "NTERP_LAB_IDLE" in log:
                break
            time.sleep(0.3)
        else:
            raise AssertionError("Separate nterp activity never became idle")
        init = results["script"].exports_sync.snapshot()
        trace.append("probe initialization: " + json.dumps(
            {k:v for k,v in init.items() if k != "events"}))
        if not init["ready"] or init["errors"]:
            raise AssertionError("nterp probe initialization failed")
        if results["script"].exports_sync.arm() is not True:
            raise AssertionError("Could not arm nterp opcode recorder")
        run_result = subprocess.run(
            ["adb", "shell", "am", "start", "-W", "-n", ACTIVITY,
             "--ez", "run", "true"],
            capture_output=True, text=True, timeout=12)
        trace.append("workload am start: " + run_result.stdout[:500] +
                     run_result.stderr[:500])
        if run_result.returncode != 0:
            raise AssertionError("Could not trigger nterp workload")
        done = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            log = lab_log()
            if "NTERP_LAB_FAILED" in log:
                raise AssertionError("Synthetic field workload failed")
            if "NTERP_LAB_DONE checksum=-16768 nullChecks=2" in log:
                done = True
                break
            time.sleep(0.3)
        if not done:
            raise AssertionError("Synthetic field workload did not finish")
        snapshot = results["script"].exports_sync.snapshot()
        (out / "nterp-runtime-events.json").write_text(json.dumps(snapshot, indent=2))
        (out / "nterp-probe-messages.json").write_text(json.dumps(events, indent=2))
        verify(catalog, snapshot)
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        device.disable_spawn_gating()
        device.off("spawn-added", on_spawn)
        if "session" in results:
            results["session"].detach()
        for worker in joined:
            worker.join(timeout=5)
        (out / "nterp-host-trace.txt").write_text("\\n".join(trace + errors) + "\\n")
        try:
            log_all = subprocess.check_output(
                ["adb", "logcat", "-d", "-t", "2500"], text=True)
            (out / "nterp-logcat-tail.txt").write_text(log_all)
        except Exception as e:
            trace.append(str(e))
    if errors:
        raise AssertionError(f"Frida errors: {errors}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        main()
