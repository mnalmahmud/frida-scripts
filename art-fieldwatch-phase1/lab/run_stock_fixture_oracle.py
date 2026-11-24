#!/usr/bin/env python3
"""Stock ART leaf-method oracle for the repository's own release APK.

Never claims arbitrary field interception or compiler/interpreter coverage.
"""
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "com.example.artfieldwatch"
ACTIVITY = PACKAGE + "/.NoTemplateLabActivity"
ORDER = ("writeInstance", "writeStatic", "readInstance", "readStatic")
sys.path.insert(0, str(ROOT / 'ci'))
from dex_field_sites import verify_fixture_methods


def verify(lines):
    events = []
    for line in lines:
        if "ARTWATCH_STOCK_EVENT " in line:
            events.append(json.loads(line.split("ARTWATCH_STOCK_EVENT ", 1)[1]))
    if len(events) != 512:
        raise AssertionError(f"Expected 512 successful leaf calls, got {len(events)}")
    for index, actual in enumerate(events):
        i, j = divmod(index, 4)
        name = ORDER[j]
        expected = {"seq": index + 1, "method": name,
                    "value": 7 + 3*i if "Instance" in name else -11 - 5*i}
        if actual != expected:
            raise AssertionError(f"Leaf call {index}: {actual} != {expected}")
    return events


def resolve_reference(catalog, events):
    """Attach static DEX identities, not runtime-observed PCs."""
    methods = catalog["fixtureMethods"]
    verify_fixture_methods(methods)
    dex_files = {d["dexId"]: d for d in catalog["dexFiles"]}
    if len(dex_files) != len(catalog["dexFiles"]):
        raise AssertionError("Duplicate DEX IDs")
    by_name = {}
    for m in methods:
        f = m["fields"][0]
        dex = dex_files[m["dexId"]]
        identity = (m["methodIndex"], f["fieldIndex"], f["dexPc"])
        matching = [x for x in dex["fieldAccesses"]
                    if (x["methodIndex"], x["fieldIndex"], x["dexPc"]) == identity]
        if matching != [f]:
            raise AssertionError("Fixture method disagrees with DEX catalog")
        if m["methodName"] in by_name:
            raise AssertionError("Ambiguous fixture method")
        by_name[m["methodName"]] = {
            "dexId": m["dexId"], "dexSha256": dex["sha256"],
            "methodIndex": m["methodIndex"], "methodClass": m["methodClass"],
            "fieldIndex": f["fieldIndex"], "declaringClass": f["declaringClass"],
            "fieldName": f["fieldName"], "fieldType": f["fieldType"],
            "operation": f["operation"], "access": f["access"],
            "dexPc": f["dexPc"], "sourceFile": f.get("sourceFile"),
            "sourceLine": f.get("sourceLine"),
            "provenance": "static DEX mapping of observed leaf call"
        }
    return [{**e, **by_name[e["method"]]} for e in events]


def self_test():
    lines = []
    for i in range(128):
        for j, name in enumerate(ORDER):
            lines.append("ARTWATCH_STOCK_EVENT " + json.dumps({
                "seq": 4*i+j+1, "method": name,
                "value": 7+3*i if "Instance" in name else -11-5*i}))
    assert len(verify(lines)) == 512
    for bad in (lines[:-1], lines + [lines[0]],
                [lines[1], lines[0], *lines[2:]]):
        try:
            verify(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError("Invalid leaf-call trace was accepted")
    from dex_field_sites import FIXTURE_LEAVES
    methods = []
    fields = []
    for index, (key, spec) in enumerate(FIXTURE_LEAVES.items()):
        opcode, name, access, operation, ret = spec
        field = {"methodIndex": index, "fieldIndex": index//2, "dexPc": 0,
                 "declaringClass": key[0], "fieldName": name, "fieldType": "I",
                 "operation": operation, "access": access}
        fields.append(field)
        methods.append({"methodClass": key[0], "methodName": key[1],
                        "methodIndex": index, "dexId": 0,
                        "opcodes": [opcode, ret], "fields": [field]})
    catalog = {"fixtureMethods": methods, "dexFiles": [
        {"dexId": 0, "sha256": "0"*64, "fieldAccesses": fields}]}
    resolved = resolve_reference(catalog, verify(lines))
    assert len(resolved) == 512
    assert resolved[0]["operation"] == "write"
    assert resolved[2]["operation"] == "read"
    assert resolved[0]["fieldIndex"] == resolved[2]["fieldIndex"]
    try:
        resolve_reference({**catalog, "dexFiles": [
            {**catalog["dexFiles"][0], "fieldAccesses": fields[:-1]}]}, verify(lines))
    except AssertionError:
        pass
    else:
        raise AssertionError("Inconsistent DEX catalog accepted")
    print("Stock fixture oracle self-test passed")


def main():
    if os.environ.get("ARTWATCH_BUILD_VARIANT") != "release":
        raise RuntimeError("This experiment requires the synthetic release APK")
    out = Path(os.environ.get("ARTWATCH_LOG_DIR", "/tmp/artwatch-logs"))
    out.mkdir(parents=True, exist_ok=True)
    # Main smoke has completed; reuse that isolated emulator app process.
    pids = subprocess.check_output(["adb", "shell", "pidof", PACKAGE],
                                   text=True).split()
    if len(pids) != 1 or not pids[0].isdigit():
        raise AssertionError("Expected exactly one synthetic fixture process")
    lines = []
    ready = threading.Event()
    with subprocess.Popen(
        ["frida", "-U", "-p", pids[0], "-q", "-t", "25",
         "--exit-on-error", "--no-auto-reload", "-l",
         str(ROOT / "lab" / "stock_fixture_oracle.js")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    ) as proc:
        def drain():
            for line in proc.stdout:
                lines.append(line.rstrip())
                if line.strip() == "ARTWATCH_STOCK_READY":
                    ready.set()

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            if not ready.wait(12):
                raise AssertionError("Java bridge fixture oracle not ready")
            subprocess.run(["adb", "shell", "am", "start", "-W", "-n", ACTIVITY],
                           check=True, timeout=10)
            rc = proc.wait(timeout=35)
            if rc != 0:
                raise AssertionError(f"Frida CLI exited with status {rc}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            reader.join(timeout=5)
            (out / "stock-fixture-oracle.log").write_text("\n".join(lines) + "\n")
    events = verify(lines)
    log = subprocess.check_output(
        ["adb", "logcat", "-d", "--pid=" + pids[0], "-s", "ARTWATCH_LAB:I", "*:S"],
        text=True)
    (out / "stock-fixture-app.log").write_text(log)
    if ("NO_TEMPLATE_LAB_FAILED" in log or
            log.count("NO_TEMPLATE_LAB_DONE checksum=-16768 nullChecks=2") != 1):
        raise AssertionError("Synthetic workload did not finish successfully")
    (out / "stock-fixture-leaf-events.json").write_text(
        json.dumps({"scope": "fixed synthetic leaf method oracle",
                    "events": events}, indent=2))
    catalog = json.loads((out / "field-sites-release.json").read_text())
    resolved = resolve_reference(catalog, events)
    (out / "stock-fixture-resolved-reference.json").write_text(
        json.dumps({"scope": "leaf-call reference, not opcode observation",
                    "events": resolved}, indent=2))
    print("PASS: 512 successful synthetic leaf calls on stock ART (not field opcode coverage)")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        main()
