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
    if len(data) < 0x70 or data[:4] != b"dex\n":
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
            end = data.find(b"\0", start)
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


def canary_pcs(data, sink_idx):
    """Return exact code-unit PCs for one iget and sink invoke in carrier."""
    types_count, types_off = u32(data, 0x40), u32(data, 0x44)
    strings_count, strings_off = u32(data, 0x38), u32(data, 0x3c)
    methods_off = u32(data, 0x5c)
    classes_count, classes_off = u32(data, 0x60), u32(data, 0x64)

    def string(idx):
        if idx >= strings_count:
            raise ValueError("bad string ID")
        off = u32(data, strings_off + 4 * idx)
        _, pos = uleb128(data, off)
        end = data.find(b"\0", pos)
        if end < 0:
            raise ValueError("bad string terminator")
        return data[pos:end].decode("ascii")

    def descriptor(idx):
        if idx >= types_count:
            raise ValueError("bad type ID")
        return string(u32(data, types_off + 4 * idx))

    target = "Lcom/example/artfieldwatch/FieldIRTarget;"
    found = []
    for j in range(classes_count):
        pos = classes_off + 32 * j
        if descriptor(u32(data, pos)) != target:
            continue
        off = u32(data, pos + 24)
        if off == 0:
            raise ValueError("missing field target class data")
        counts = []
        for _ in range(4):
            n, off = uleb128(data, off)
            counts.append(n)
        if any(n > len(data) for n in counts):
            raise ValueError("invalid class member count")
        for _ in range(counts[0] + counts[1]):
            _, off = uleb128(data, off)
            _, off = uleb128(data, off)
        for group, n in enumerate(counts[2:]):
            method_index = 0
            for _ in range(n):
                diff, off = uleb128(data, off)
                method_index += diff
                _, off = uleb128(data, off)
                code_off, off = uleb128(data, off)
                name_idx = u32(data, methods_off + method_index * 8 + 4)
                if string(name_idx) != "p3TemplateCarrierOn":
                    continue
                if code_off == 0:
                    raise ValueError("P3 carrier has no DEX code")
                insn_count = u32(data, code_off + 12)
                insns_start = code_off + 16
                if insn_count > len(data) // 2 or insns_start + 2*insn_count > len(data):
                    raise ValueError("invalid P3 carrier code bounds")
                candidates_set = []
                candidates_get = []
                candidates_invoke = []
                for pc in range(insn_count):
                    op = u16(data, insns_start + pc*2) & 0xff
                    if op == 0x59:
                        candidates_set.append(pc)
                    if op == 0x52:
                        candidates_get.append(pc)
                    if op in (0x71, 0x77) and pc+1 < insn_count:
                        method_id = u16(data, insns_start+(pc+1)*2)
                        if method_id == sink_idx:
                            candidates_invoke.append(pc)
                if (len(candidates_set)!=1 or len(candidates_get)!=1 or
                    len(candidates_invoke)!=2 or
                    not (candidates_set[0] < candidates_invoke[0] <
                         candidates_get[0] < candidates_invoke[1])):
                    raise ValueError(f"bad P3 templates: sets={candidates_set} gets={candidates_get} invokes={candidates_invoke}")
                put_field = u16(data, insns_start + 2*(candidates_set[0] + 1))
                get_field = u16(data, insns_start + 2*(candidates_get[0] + 1))
                if put_field != get_field:
                    raise ValueError("P3 template accesses different DEX fields")
                found.append({"carrierMethodIndex":method_index,
                              "fieldIndex":put_field,
                              "setDexPc":candidates_set[0],
                              "writeInvokeDexPc":candidates_invoke[0],
                              "getDexPc":candidates_get[0],
                              "readInvokeDexPc":candidates_invoke[1]})
    if len(found) != 1:
        raise ValueError(f"expected one P3 carrier method, found {len(found)}")
    return found[0]


def apk_sink_method(apk):
    with zipfile.ZipFile(apk) as archive:
        dex_names = sorted(x for x in archive.namelist()
                           if x == "classes.dex" or
                           (x.startswith("classes") and x.endswith(".dex") and
                            x[7:-4].isdigit()))
        matches = []
        for dex_id, name in enumerate(dex_names):
            data = archive.read(name)
            try:
                idx = sink_method_index(data)
            except ValueError as e:
                if "expected one sink DEX method ID, found 0" in str(e):
                    continue
                raise
            try:
                pcs = canary_pcs(data, idx)
            except ValueError as e:
                if "expected one P3 carrier method, found 0" in str(e):
                    continue
                raise
            matches.append({"dex": name, "dexId":dex_id,
                            "methodIndex": idx,
                            **pcs,
                            "sha256": hashlib.sha256(data).hexdigest()})
        if len(matches) != 1:
            raise ValueError(f"expected one fixture sink in APK, found {len(matches)}")
        return matches[0]


def self_test():
    strings = [SINK_CLASS, SINK_NAME, "I", "V"]
    data = bytearray(1024)
    data[:8] = b"dex\n035\0"
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
        blob = bytes([len(value)]) + value.encode("ascii") + b"\0"
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
