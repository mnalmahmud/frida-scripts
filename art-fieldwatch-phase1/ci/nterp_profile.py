#!/usr/bin/env python3
"""Resolve the actual nterp dispatch table from a pulled stock libart ELF.

No in-process pattern search or guessed addresses. Only ABI-checked
x86_64 ART build IDs present on our non-debuggable Android emulator matrix
are accepted. New versions require an explicit audited allowlist entry.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

EXPECTED_BUILD_ID = "c8b6a2df9893030c07b3b96dc24a7d30"
KNOWN_BUILD_IDS = {
    33: EXPECTED_BUILD_ID,
    34: "b6dc79e02101ea00827a35a55ab6597a",
}
HANDLER_SIZE = 128
OPCODES = 256
SYMBOLS = ("artNterpAsmInstructionStart", "artNterpAsmInstructionEnd")


def resolve(symbol_table, notes, header, api=33, architecture="x86_64",
            experimental_arm64=False):
    if architecture == "x86_64":
        expected_build = KNOWN_BUILD_IDS.get(api)
        expected_machine = r"Machine:\s*Advanced Micro Devices X86-64"
        if not expected_build:
            raise ValueError("Unsupported Android API for pinned nterp backend")
    elif architecture == "arm64" and experimental_arm64 and api == 34:
        # The ARM64 opt-in is an ABI experiment, NOT an allowlisted runtime.
        # Obtain the exact Build ID from the actual, pulled libart ELF.
        expected_machine = r"Machine:\s*AArch64"
        expected_build = None
    else:
        raise ValueError("Unsupported architecture or missing ARM64 opt-in")
    build = re.search(r"Build ID:\s*([a-fA-F0-9]+)", notes)
    if not build or (expected_build is not None and
                     build.group(1).lower() != expected_build):
        raise ValueError(f"Unsupported libart.so GNU Build ID on API {api}")
    if not re.search(expected_machine, header):
        raise ValueError("ART ELF architecture does not match the selected backend")
    if architecture == "arm64":
        actual = build.group(1).lower()
        if len(actual) not in (32,40):
            raise ValueError("Invalid ARM64 ELF GNU Build ID")
        expected_build = actual
    if not re.search(r"Type:\s*DYN\b", header):
        raise ValueError("Expected a position-independent ELF shared library")
    found = {}
    for line in symbol_table.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        name = fields[-1]
        if name not in SYMBOLS:
            continue
        if fields[3] not in ("FUNC", "NOTYPE") or fields[6] == "UND":
            raise ValueError("nterp table is not a defined symbol")
        found.setdefault(name, set()).add(int(fields[1], 16))
    if set(found) != set(SYMBOLS) or any(len(values) != 1 for values in found.values()):
        raise ValueError("nterp table symbols missing or ambiguous")
    start, end = (next(iter(found[name])) for name in SYMBOLS)
    if start == 0 or end - start != OPCODES * HANDLER_SIZE:
        raise ValueError("Unexpected nterp opcode table span")
    result = {"schemaVersion": 1, "architecture": architecture,
              "api": api, "buildId": expected_build,
              "startOffset": start, "endOffset": end,
              "handlerSize": HANDLER_SIZE, "opcodeCount": OPCODES}
    if architecture == "arm64":
        result["experimentalArm64"] = True
    return result


def self_test():
    start = 0x100000
    table = (f" 100: {start:016x} 0 FUNC GLOBAL HIDDEN 14 {SYMBOLS[0]}\n"
             f" 101: {start + HANDLER_SIZE*OPCODES:016x} 0 NOTYPE GLOBAL HIDDEN 14 {SYMBOLS[1]}")
    note = "Build ID: " + EXPECTED_BUILD_ID
    header = "Type: DYN (Shared object file)\nMachine: Advanced Micro Devices X86-64"
    assert resolve(table, note, header)["handlerSize"] == 128
    assert resolve(table, "Build ID: "+KNOWN_BUILD_IDS[34], header,
                   api=34)["api"]==34
    for rejected_api in (21, 32, 35, 37):
        try:resolve(table,note,header,api=rejected_api)
        except ValueError:pass
        else:raise AssertionError("Unverified Android nterp version accepted")
    try:resolve(table,note,header,api=34)
    except ValueError:pass
    else:raise AssertionError("Wrong API34 ART binary identity accepted")
    for invalid in (table[:-2], table.replace("100000", "100001"),
                    table.replace(SYMBOLS[1], SYMBOLS[0])):
        try:
            resolve(invalid, note, header)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid nterp table accepted")
    armheader = "Type: DYN (Shared object file)\nMachine: AArch64"
    arm = resolve(table,"Build ID: "+"a"*40,armheader,api=34,
                  architecture="arm64",experimental_arm64=True)
    assert arm["experimentalArm64"] and arm["architecture"]=="arm64"
    assert arm["buildId"]=="a"*40
    for overrides in ({"architecture":"arm64"},
                      {"architecture":"arm64","experimental_arm64":True},
                      {"architecture":"x86_64","experimental_arm64":True}):
        try: resolve(table,"Build ID: "+"a"*40,header,api=34,**overrides)
        except (TypeError,ValueError):pass
        else:raise AssertionError("ARM64 ELF header/opt-in check bypassed")
    try:
        resolve(table, "Build ID: " + "0"*32, header)
    except ValueError:
        pass
    else:
        raise AssertionError("Wrong ART build accepted")
    print("nterp ELF profile self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("libart", nargs="?", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--api", type=int, choices=sorted(KNOWN_BUILD_IDS),
                        default=33)
    parser.add_argument("--architecture", choices=("x86_64","arm64"),
                        default="x86_64")
    parser.add_argument("--experimental-arm64", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.libart is None or args.out is None:
        parser.error("Provide pulled libart.so and --out path")
    def elf(*options):
        return subprocess.check_output(["readelf", *options, str(args.libart)],
                                       text=True)
    result = resolve(elf("--wide", "-Ws"), elf("-n"), elf("-h"),
                     api=args.api, architecture=args.architecture,
                     experimental_arm64=args.experimental_arm64)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print("Verified nterp opcode table:", json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
