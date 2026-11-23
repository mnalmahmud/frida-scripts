#!/usr/bin/env python3
"""Strictly join executed ART field events with the *packaged* DEX site catalog.

The tuple (dexId, methodId, fieldId, dexPc, read/write) is authoritative.
Never infer a field name from event order, field index alone, or a method name.
Field values are the original event bit patterns, not a second field read.
"""
import argparse
import json
import re
from pathlib import Path

VALUE_TYPES = {"Z": 1, "B": 2, "C": 3, "S": 4, "I": 5,
               "J": 6, "F": 7, "D": 8}
KIND = {1: "read", 2: "write"}
BITS = re.compile(r"0x[0-9a-fA-F]{16}\Z")


def _type_id(descriptor):
    if not isinstance(descriptor, str) or not descriptor:
        raise ValueError(f"invalid DEX field descriptor {descriptor!r}")
    return VALUE_TYPES.get(descriptor, 9 if descriptor[0] in ("L", "[") else 0)


def _signed(value, bits):
    mask = (1 << bits) - 1
    value &= mask
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def resolve(inventory, snapshot):
    if inventory.get("schemaVersion") != 1:
        raise ValueError("unsupported DEX catalog version")
    if snapshot.get("version") != 2:
        raise ValueError("unsupported native event ABI version")
    dexes = {}
    sites = {}
    for dex in inventory.get("dexFiles", []):
        dex_id = dex.get("dexId")
        if not isinstance(dex_id, int) or dex_id < 0 or dex_id in dexes:
            raise ValueError("invalid or repeated DEX ID")
        if not isinstance(dex.get("sha256"), str) or len(dex["sha256"]) != 64:
            raise ValueError("missing DEX SHA-256")
        dexes[dex_id] = dex
        if dex.get("count") != len(dex.get("fieldAccesses", [])):
            raise ValueError("DEX field-site count mismatch")
        for site in dex["fieldAccesses"]:
            direction = site.get("operation")
            kind = {"read": 1, "write": 2}.get(direction)
            key = (dex_id, site.get("methodIndex"), site.get("fieldIndex"),
                   site.get("dexPc"), kind)
            if kind is None or key in sites or not all(isinstance(n, int) for n in key):
                raise ValueError(f"ambiguous DEX site identity {key}")
            sites[key] = (dex, site)
    if inventory.get("totalFieldSites") != len(sites):
        raise ValueError("APK-wide field-site count mismatch")
    events = snapshot.get("events", [])
    if snapshot.get("total") != len(events) or snapshot.get("dropped") != 0:
        raise ValueError("incomplete, dropped or truncated event snapshot")
    resolved = []
    for index, event in enumerate(events):
        if event.get("seq") != index + 1:
            raise ValueError("non-contiguous event sequence")
        key = tuple(event.get(k) for k in
                    ("dexId", "methodId", "fieldId", "dexPc", "kind"))
        if key not in sites:
            raise ValueError(f"event {index + 1} has no matching DEX field instruction: {key}")
        dex, site = sites[key]
        type_id = _type_id(site["fieldType"])
        if type_id == 0 or event.get("type") != type_id:
            raise ValueError(f"event {index + 1} type does not match DEX field descriptor")
        bits = event.get("valueBits")
        if not isinstance(bits, str) or not BITS.fullmatch(bits):
            raise ValueError(f"event {index + 1} has invalid 64-bit value encoding")
        value_bits = int(bits, 16)
        # The direct 6-int JNI ABI sign-extends to 64 bits, preserving negative ints.
        # Floating point values retain raw IEEE bits, with no precision-losing JSON floats.
        value = None
        if type_id in (1, 2, 3, 4, 5):
            width = {1: 1, 2: 8, 3: 16, 4: 16, 5: 32}[type_id]
            if type_id == 1:
                if value_bits not in (0, 1):
                    raise ValueError("invalid boolean bit value")
                value = bool(value_bits)
            elif type_id == 3:
                if value_bits > 0xFFFF:
                    raise ValueError("invalid unsigned Java char")
                value = value_bits
            else:
                value = _signed(value_bits, width)
                if value_bits != (value & ((1 << 64) - 1)):
                    raise ValueError("invalid signed narrow-primitive extension")
        elif type_id == 6:
            value = _signed(value_bits, 64)
        # Never claim an object identity or dereference an opaque reference token.
        resolved.append({
            "seq": index + 1,
            "dexId": key[0], "dexName": dex["name"], "dexSha256": dex["sha256"],
            "methodId": key[1], "methodClass": site["methodClass"],
            "methodName": site["methodName"], "prototypeIndex": site["prototypeIndex"],
            "fieldId": key[2], "declaringClass": site["declaringClass"],
            "fieldName": site["fieldName"], "fieldType": site["fieldType"],
            "access": site["access"], "operation": KIND[key[4]],
            "dexPc": key[3], "sourceFile": site["sourceFile"],
            "sourceLine": site["sourceLine"], "valueType": type_id,
            "valueBits": f"0x{value_bits:016x}", "value": value,
        })
    return {"schemaVersion": 1, "apk": inventory.get("apk"),
            "eventCount": len(resolved), "events": resolved}


def self_test():
    sha = "a" * 64
    def site(method, field, pc, operation, typ="I", access="instance"):
        return {"methodIndex": method, "fieldIndex": field, "dexPc": pc,
                "operation": operation, "access": access, "fieldType": typ,
                "methodClass": "Lexample/Caller;", "methodName": "hot",
                "prototypeIndex": 2, "declaringClass": "Lexample/Data;",
                "fieldName": "watched", "sourceFile": "Caller.java",
                "sourceLine": 17}
    inv = {"schemaVersion": 1, "apk": "test.apk", "totalFieldSites": 3,
           "dexFiles": [{"dexId": 0, "name": "classes.dex", "sha256": sha,
                         "count": 3, "fieldAccesses": [
                             site(1, 2, 3, "write"),
                             site(1, 2, 4, "read"),
                             site(1, 9, 8, "write", "J", "static")]}]}
    def ev(seq, field, pc, kind, typ, bits):
        return {"seq": seq, "dexId": 0, "methodId": 1, "fieldId": field,
                "dexPc": pc, "kind": kind, "type": typ, "valueBits": bits}
    snapshot = {"version": 2, "total": 3, "dropped": 0, "events": [
        ev(1, 2, 3, 2, 5, "0xfffffffffffffff5"),
        ev(2, 2, 4, 1, 5, "0xfffffffffffffff5"),
        ev(3, 9, 8, 2, 6, "0x8000000000000000")]}
    result = resolve(inv, snapshot)
    assert result["eventCount"] == 3
    assert [e["value"] for e in result["events"]] == [
        -11, -11, -(1 << 63)]
    assert result["events"][2]["access"] == "static"
    for key, bad in (("kind", 1), ("fieldId", 999), ("dexPc", 99),
                     ("type", 7), ("valueBits", "garbage")):
        old = snapshot["events"][0][key]
        snapshot["events"][0][key] = bad
        try:
            resolve(inv, snapshot)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid {key} event accepted")
        snapshot["events"][0][key] = old
    print("strict DEX field-event resolver self-test passed")


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--inventory", type=Path)
    cli.add_argument("--events", type=Path)
    cli.add_argument("--output", type=Path)
    cli.add_argument("--self-test", action="store_true")
    args = cli.parse_args()
    if args.self_test:
        self_test()
    else:
        if not all((args.inventory, args.events, args.output)):
            cli.error("--inventory, --events and --output are required")
        catalog = json.loads(args.inventory.read_text())
        snapshot = json.loads(args.events.read_text())
        result = resolve(catalog, snapshot)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(f"Resolved {result['eventCount']} field events with strict DEX identities")
