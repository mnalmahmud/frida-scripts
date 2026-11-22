#!/usr/bin/env python3
"""Find the fixture sink's DEX method ID without Android framework dependencies.

A method index is scoped to its DexFile. This is *not* proof that an arbitrary
ART invoke points at the sink; it must be joined with the compiled DexFile and
the exact DEX PC before constructing or cloning a compiler invoke.
"""
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path

SINK_CLASS = "Lcom/example/artfieldwatch/FieldEventSink;"
SINK_NAME = "recordInt"
SINK_PROTO = "(III)V"


def u16(data, pos):
    if pos < 0 or pos + 2 > len(data):
        raise ValueError("DEX u16 out of bounds")
    return struct.unpack_from("<H", data, pos)[0]


def u32(data, pos):
    if pos < 0 or pos + 4 > len(data):
        raise ValueError("DEX u32 out of bounds")
    return struct.unpack_from("<I", data, pos)[0]


def uleb128(data, pos):
    value = 0
    for n in range(5):
        if pos + n >= len(data):
            raise ValueError("truncated DEX ULEB128")
        byte = data[pos + n]
        value |= (byte & 0x7f) << (7 * n)
        if not (byte & 0x80):
            return value, pos + n + 1
    raise ValueError("oversized DEX ULEB128")


def sink_method_index(data):
    if len(data) < 0x70 or data[:4] != b"dex\\n":
        raise ValueError("not a DEX file")
    strings_count, strings_off = u32(data, 0x38), u32(data, 0x3c)
    types_count, types_off = u32(data, 0x40), u32(data, 0x44)
    protos_count, protos_off = u32(data, 0x48), u32(data, 0x4c)
    methods_count, methods_off = u32(data, 0x58), u32(data, 0x5c)
    for count, off, stride in [(strings_count, strings_off, 4),
                               (types_count, types_off, 4),
                               (protos_count, protos_off, 12),
                               (methods_count, methods_off, 8)]:
        if count > len(data) // stride or off > len(data) - count * stride:
            raise ValueError("invalid DEX table bounds")
    cache = {}

    def string(idx):
        if idx >= strings_count:
            raise ValueError("invalid DEX string ID")
        if idx not in cache:
            off = u32(data, strings_off + 4 * idx)
            _, start = uleb128(data, off)
            end = data.find(b"\\0", start)
            if end < 0:
                raise ValueError("unterminated DEX string")
            # Java descriptors and method names are ASCII even though
            # general DEX strings use modified UTF-8.
            cache[idx] = data[start:end].decode("ascii")
        return cache[idx]

    def descriptor(idx):
        if idx >= types_count:
            raise ValueError("invalid DEX type ID")
        return string(u32(data, types_off + 4 * idx))

    def signature(idx):
        if idx >= protos_count:
            raise ValueError("invalid DEX proto ID")
        item = protos_off + 12 * idx
        result = descriptor(u32(data, item + 4))
        params_off = u32(data, item + 8)
        args = ""
        if params_off:
            n = u32(data, params_off)
            if n > len(data) // 2 or params_off + 4 + 2*n > len(data):
                raise ValueError("invalid DEX parameter list")
            args = "".join(descriptor(u16(data, params_off + 4 + 2*i))
                           for i in range(n))
        return "(" + args + ")" + result

    found = []
    for idx in range(methods_count):
        pos = methods_off + 8 * idx
        class_idx = u16(data, pos)
        proto_idx = u16(data, pos + 2)
        name_idx = u32(data, pos + 4)
        if descriptor(class_idx) == SINK_CLASS and string(name_idx) == SINK_NAME:
            if signature(proto_idx) != SINK_PROTO:
                raise ValueError("sink name found but prototype mismatches")
            found.append(idx)
    if len(found) != 1:
        raise ValueError(f"expected one sink DEX method ID, found {len(found)}")
    return found[0]


def apk_sink_method(apk):
    with zipfile.ZipFile(apk) as archive:
        dex_names = sorted(x for x in archive.namelist()
                           if x == "classes.dex" or
                           (x.startswith("classes") and x.endswith(".dex") and
                            x[7:-4].isdigit()))
        matches = []
        for name in dex_names:
            data = archive.read(name)
            try:
                idx = sink_method_index(data)
            except ValueError as e:
                if "expected one sink DEX method ID, found 0" in str(e):
                    continue
                raise
            matches.append({"dex": name, "methodIndex": idx,
                            "sha256": hashlib.sha256(data).hexdigest()})
        if len(matches) != 1:
            raise ValueError(f"expected one fixture sink in APK, found {len(matches)}")
        return matches[0]


def self_test():
    strings = [SINK_CLASS, SINK_NAME, "I", "V"]
    data = bytearray(1024)
    data[:8] = b"dex\\n035\\0"
    strings_off, types_off, protos_off, methods_off = 0x100, 0x120, 0x140, 0x160
    for base, count_off, offset_off, count in [
            (strings_off, 0x38, 0x3c, len(strings)),
            (types_off, 0x40, 0x44, 3),
            (protos_off, 0x48, 0x4c, 1),
            (methods_off, 0x58, 0x5c, 1)]:
        struct.pack_into("<II", data, count_off, count, base)
    cursor = 0x200
    for i, value in enumerate(strings):
        struct.pack_into("<I", data, strings_off + 4*i, cursor)
        blob = bytes([len(value)]) + value.encode("ascii") + b"\\0"
        data[cursor:cursor + len(blob)] = blob
        cursor += len(blob)
    # class, int, void types; shorty does not matter for lookup.
    for i, index in enumerate([0, 2, 3]):
        struct.pack_into("<I", data, types_off + 4*i, index)
    struct.pack_into("<III", data, protos_off, 3, 2, 0x180)
    struct.pack_into("<IHHH", data, 0x180, 3, 1, 1, 1)
    struct.pack_into("<HHI", data, methods_off, 0, 0, 1)
    assert sink_method_index(bytes(data)) == 0
    data[methods_off + 4] = 2
    try:
        sink_method_index(bytes(data))
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched method name was accepted")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("DEX method-ID parser self-test passed")
    elif len(sys.argv) == 2:
        print(json.dumps(apk_sink_method(Path(sys.argv[1])), sort_keys=True))
    else:
        raise SystemExit("usage: dex_method_index.py <APK> | --self-test")
