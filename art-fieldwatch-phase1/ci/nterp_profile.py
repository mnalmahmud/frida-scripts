#!/usr/bin/env python3
"""Resolve the actual nterp dispatch table from a pulled stock libart ELF.

No in-process pattern search or guessed addresses. Experimental API33 x86_64
backend only: all other binary builds must be validated independently.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

EXPECTED_BUILD_ID = "c8b6a2df9893030c07b3b96dc24a7d30"
HANDLER_SIZE = 128
OPCODES = 256
SYMBOLS = ("artNterpAsmInstructionStart", "artNterpAsmInstructionEnd")


def resolve(symbol_table, notes, header):
    build = re.search(r"Build ID:\s*([a-fA-F0-9]+)", notes)
    if not build or build.group(1).lower() != EXPECTED_BUILD_ID:
        raise ValueError("Unsupported libart.so GNU Build ID")
    if not re.search(r"Machine:\s*Advanced Micro Devices X86-64", header):
        raise ValueError("Not x86_64 ART")
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
    return {"schemaVersion": 1, "architecture": "x86_64",
            "api": 33, "buildId": EXPECTED_BUILD_ID,
            "startOffset": start, "endOffset": end,
            "handlerSize": HANDLER_SIZE, "opcodeCount": OPCODES}


def self_test():
    start = 0x100000
    table = (f" 100: {start:016x} 0 FUNC GLOBAL HIDDEN 14 {SYMBOLS[0]}\n"
             f" 101: {start + HANDLER_SIZE*OPCODES:016x} 0 NOTYPE GLOBAL HIDDEN 14 {SYMBOLS[1]}")
    note = "Build ID: " + EXPECTED_BUILD_ID
    header = "Type: DYN (Shared object file)\nMachine: Advanced Micro Devices X86-64"
    assert resolve(table, note, header)["handlerSize"] == 128
    for invalid in (table[:-2], table.replace("100000", "100001"),
                    table.replace(SYMBOLS[1], SYMBOLS[0])):
        try:
            resolve(invalid, note, header)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid nterp table accepted")
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
    result = resolve(elf("--wide", "-Ws"), elf("-n"), elf("-h"))
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print("Verified nterp opcode table:", json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
