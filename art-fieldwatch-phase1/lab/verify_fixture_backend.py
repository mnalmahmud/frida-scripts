#!/usr/bin/env python3
"""Check executed lab events against the packaged synthetic APK field catalog."""
import argparse
import json
import re
from pathlib import Path

EVENT = re.compile(
    r"ARTWATCH_LAB_V1 seq=(\d+) method=(\w+) methodId=(\d+) "
    r"fieldId=(\d+) dexPc=(\d+) kind=([12]) value=(-?\d+)$")
ORDER = ("writeInstance", "writeStatic", "readInstance", "readStatic")
CLASSES = {
    "writeInstance": "NoTemplateTarget",
    "readInstance": "NoTemplateTarget",
    "writeStatic": "NoTemplateStaticState",
    "readStatic": "NoTemplateStaticState",
}


def verify(catalog, log):
    sites = {}
    dex_ids = set()
    for method in catalog["fixtureMethods"]:
        name = method["methodName"]
        if name not in CLASSES or name in sites:
            raise AssertionError("Unexpected fixture method")
        owner = "Lcom/example/artfieldwatch/" + CLASSES[name] + ";"
        if method["methodClass"] != owner or len(method["fields"]) != 1:
            raise AssertionError("Unexpected fixture identity")
        field = method["fields"][0]
        kind = 2 if name.startswith("write") else 1
        if (field["declaringClass"] != owner or field["fieldType"] != "I" or
                field["operation"] != ("write" if kind == 2 else "read") or
                field["fieldName"] != ("value" if "Instance" in name else "shared")):
            raise AssertionError("Unexpected fixture field")
        dex_ids.add(method["dexId"])
        sites[name] = (method["methodIndex"], field["fieldIndex"],
                       field["dexPc"], kind)
    if set(sites) != set(ORDER) or len(dex_ids) != 1:
        raise AssertionError("Incomplete or multi-DEX fixture identity")
    if "NO_TEMPLATE_LAB_FAILED" in log or "ARTWATCH_LAB_OVERFLOW" in log:
        raise AssertionError("Lab runtime reported failure")
    events = []
    for line in log.splitlines():
        if "ARTWATCH_LAB_V1 seq=" not in line:
            continue
        match = EVENT.search(line.strip())
        if match is None:
            raise AssertionError("Malformed lab event")
        seq, method, mid, fid, pc, kind, value = match.groups()
        events.append((int(seq), method, int(mid), int(fid), int(pc),
                       int(kind), int(value)))
    if len(events) != 512:
        raise AssertionError(f"Expected 512 executed field events, got {len(events)}")
    for index, event in enumerate(events):
        i, j = divmod(index, 4)
        name = ORDER[j]
        value = (7 + 3*i) if "Instance" in name else (-11 - 5*i)
        expected = (index + 1, name, *sites[name], value)
        if event != expected:
            raise AssertionError(f"Event {index}: {event} != {expected}")
    markers = [line for line in log.splitlines() if "NO_TEMPLATE_LAB_DONE" in line]
    if (len(markers) != 1 or
            not markers[0].endswith("NO_TEMPLATE_LAB_DONE checksum=-16768 nullChecks=2")):
        raise AssertionError("Missing or malformed workload completion")
    print("PASS: 512 executed synthetic interpreter field events, exact values and DEX sites")


def self_test():
    methods = []
    lines = []
    for j, name in enumerate(ORDER):
        owner = "Lcom/example/artfieldwatch/" + CLASSES[name] + ";"
        kind = 2 if name.startswith("write") else 1
        methods.append({"methodClass": owner, "methodName": name,
                        "methodIndex": j+10, "dexId": 0,
                        "fields": [{"fieldIndex": j%2, "dexPc": 0,
                                    "declaringClass": owner, "fieldType": "I",
                                    "fieldName": "value" if "Instance" in name else "shared",
                                    "operation": "write" if kind == 2 else "read"}]})
    for i in range(128):
        for j, name in enumerate(ORDER):
            value = 7+3*i if "Instance" in name else -11-5*i
            lines.append(f"ARTWATCH_LAB_V1 seq={4*i+j+1} method={name} "
                         f"methodId={j+10} fieldId={j%2} dexPc=0 "
                         f"kind={2 if j<2 else 1} value={value}")
    lines.append("NO_TEMPLATE_LAB_DONE checksum=-16768 nullChecks=2")
    catalog = {"fixtureMethods": methods}
    verify(catalog, "\n".join(lines))
    for invalid in (lines[:-2] + lines[-1:], lines + [lines[0]],
                    [lines[0].replace("value=7", "value=8"), *lines[1:]],
                    lines + ["ARTWATCH_LAB_OVERFLOW"]):
        try:
            verify(catalog, "\n".join(invalid))
        except AssertionError:
            pass
        else:
            raise AssertionError("Bad lab evidence accepted")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", nargs="?", type=Path)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.catalog and args.log:
        verify(json.loads(args.catalog.read_text()), args.log.read_text())
    else:
        parser.error("Provide the packaged DEX catalog and isolated lab log")
