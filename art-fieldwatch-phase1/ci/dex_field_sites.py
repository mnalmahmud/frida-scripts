#!/usr/bin/env python3
"""Enumerate *every* concrete iget/iput/sget/sput in packaged APK DEX.

Field IDs, method IDs and DEX PCs are scoped to a particular DexFile.
This is the identity catalog for an eventual generic ART compiler injector,
not an assertion that every DEX operation runs or survives optimization.
"""
import argparse
import bisect
import hashlib
import json
import struct
import zipfile
from pathlib import Path
from dex_method_index import u16, u32, uleb128

KINDS = ("int", "wide", "object", "boolean", "byte", "char", "short")
WIDTHS = {**{op: 1 for op in range(0x00, 0x100)}}
for op in (0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,
           0x20,0x22,0x23,0x29,0xfe,0xff):
    WIDTHS[op] = 2
for op in (0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,
           0x2b,0x2c,0xfc,0xfd):
    WIDTHS[op] = 3
WIDTHS[0x18] = 5
WIDTHS[0xfa] = WIDTHS[0xfb] = 4
for first,last,width in ((0x2d,0x3d,2),(0x44,0x6d,2),
                         (0x6e,0x72,3),(0x74,0x78,3),
                         (0x90,0xaf,2),(0xd0,0xe2,2)):
    for op in range(first,last+1): WIDTHS[op] = width
# Only legal DEX instructions are decoded. Reserved/odex opcodes fail closed.
RESERVED = set(range(0x3e,0x44)) | {0x73,0x79,0x7a} | set(range(0xe3,0xfa))
FIELD_OPS = {
    op: {"access": "instance" if op < 0x60 else "static",
         "operation": "read" if (0x52 <= op <= 0x58 or 0x60 <= op <= 0x66) else "write",
         "valueKind": KINDS[(op - (0x52 if op <= 0x58 else
                             0x59 if op <= 0x5f else
                             0x60 if op <= 0x66 else 0x67))]}
    for op in range(0x52,0x6e)
}

def sleb128(data,pos):
    value=0
    for i in range(5):
        if pos>=len(data): raise ValueError("truncated SLEB128")
        b=data[pos]; pos+=1; value |= (b&0x7f) << (7*i)
        if not b&0x80:
            if b&0x40: value -= 1 << (7*(i+1))
            return value,pos
    raise ValueError("oversized SLEB128")

def insn_width(data, base, pc, count):
    first=u16(data,base+2*pc)
    op=first&255
    if op==0 and first:
        marker=first>>8
        if marker==1: width=4+2*u16(data,base+2*(pc+1))
        elif marker==2: width=2+4*u16(data,base+2*(pc+1))
        elif marker==3:
            size=u32(data,base+2*(pc+2))
            unit=u16(data,base+2*(pc+1))
            if unit not in (1,2,4,8): raise ValueError("bad array payload width")
            width=4+(size*unit+1)//2
        else: raise ValueError(f"unknown DEX payload 0x{first:04x}")
    else:
        if op in RESERVED: raise ValueError(f"reserved opcode 0x{op:02x}")
        width=WIDTHS[op]
    if pc+width>count: raise ValueError("truncated DEX instruction")
    return width

def debug_lines(data, off):
    if not off: return []
    line,off=uleb128(data,off)
    params,off=uleb128(data,off)
    for _ in range(params): _,off=uleb128(data,off)
    addr=0
    positions=[(0,line)]
    for _ in range(len(data)):
        if off>=len(data): raise ValueError("unterminated DEX debug info")
        op=data[off];off+=1
        if op==0: return positions
        if op==1:
            delta,off=uleb128(data,off);addr+=delta
        elif op==2:
            delta,off=sleb128(data,off);line+=delta
        elif op in (3,4):
            count=4 if op==4 else 3
            for __ in range(count): _,off=uleb128(data,off)
        elif op == 9:
            _,off=uleb128(data,off)
        elif op in (7,8): pass
        else:
            shifted=op-10
            addr+=shifted//15
            line+=shifted%15-4
            positions.append((addr,line))
    raise ValueError("too many DEX debug operations")

class Dex:
    def __init__(self,data,name):
        if len(data)<112 or data[:4]!=b"dex\n": raise ValueError("not a standard DEX")
        self.data=data
        self.name=name
        self.shasum=hashlib.sha256(data).hexdigest()
        self.strings_count,self.strings_off=u32(data,0x38),u32(data,0x3c)
        self.types_count,self.types_off=u32(data,0x40),u32(data,0x44)
        self.protos_count,self.protos_off=u32(data,0x48),u32(data,0x4c)
        self.fields_count,self.fields_off=u32(data,0x50),u32(data,0x54)
        self.methods_count,self.methods_off=u32(data,0x58),u32(data,0x5c)
        self.classes_count,self.classes_off=u32(data,0x60),u32(data,0x64)
        for n,off,stride in ((self.strings_count,self.strings_off,4),
                             (self.types_count,self.types_off,4),
                             (self.protos_count,self.protos_off,12),
                             (self.fields_count,self.fields_off,8),
                             (self.methods_count,self.methods_off,8),
                             (self.classes_count,self.classes_off,32)):
            if n>len(data)//stride or off>len(data)-n*stride:
                raise ValueError("DEX table bounds")
        self.string_cache={}
    def string(self,i):
        if i>=self.strings_count: raise ValueError("string ID out of bounds")
        if i not in self.string_cache:
            offset=u32(self.data,self.strings_off+4*i)
            _,pos=uleb128(self.data,offset)
            end=self.data.find(b"\0",pos)
            if end<0: raise ValueError("unterminated DEX string")
            self.string_cache[i]=self.data[pos:end].decode("utf-8","replace")
        return self.string_cache[i]
    def typ(self,i):
        if i>=self.types_count: raise ValueError("type ID out of bounds")
        return self.string(u32(self.data,self.types_off+4*i))
    def field(self,i):
        if i>=self.fields_count: raise ValueError("field ID out of bounds")
        pos=self.fields_off+8*i
        return {"fieldIndex":i,"declaringClass":self.typ(u16(self.data,pos)),
                "fieldType":self.typ(u16(self.data,pos+2)),
                "fieldName":self.string(u32(self.data,pos+4))}
    def method(self,i):
        if i>=self.methods_count: raise ValueError("method ID out of bounds")
        pos=self.methods_off+8*i
        return {"methodIndex":i,"methodClass":self.typ(u16(self.data,pos)),
                "methodName":self.string(u32(self.data,pos+4)),
                "prototypeIndex":u16(self.data,pos+2)}
    def sites(self):
        out=[]
        for cls in range(self.classes_count):
            pos=self.classes_off+cls*32
            class_type=self.typ(u32(self.data,pos))
            source_idx=u32(self.data,pos+16)
            source=None if source_idx==0xffffffff else self.string(source_idx)
            offset=u32(self.data,pos+24)
            if not offset: continue
            counts=[]
            for _ in range(4):
                n,offset=uleb128(self.data,offset)
                if n>len(self.data): raise ValueError("class item count exceeds DEX")
                counts.append(n)
            for _ in range(counts[0]+counts[1]):
                _,offset=uleb128(self.data,offset)
                _,offset=uleb128(self.data,offset)
            for count in counts[2:]:
                method_idx=0
                for _ in range(count):
                    diff,offset=uleb128(self.data,offset)
                    method_idx+=diff
                    _,offset=uleb128(self.data,offset)
                    code,offset=uleb128(self.data,offset)
                    if not code: continue
                    if method_idx>=self.methods_count: raise ValueError("method index OOB")
                    debug=u32(self.data,code+8)
                    insns=u32(self.data,code+12)
                    base=code+16
                    if insns>(len(self.data)-base)//2:
                        raise ValueError("code item instruction extent OOB")
                    positions=debug_lines(self.data,debug)
                    pc=0
                    method=self.method(method_idx)
                    if method["methodClass"]!=class_type: raise ValueError("class method mismatch")
                    while pc<insns:
                        op=u16(self.data,base+2*pc)&255
                        width=insn_width(self.data,base,pc,insns)
                        if op in FIELD_OPS:
                            field_idx=u16(self.data,base+2*(pc+1))
                            line=None
                            if positions:
                                k=bisect.bisect_right(positions,(pc,1<<31))-1
                                if k>=0: line=positions[k][1]
                            out.append({**method,**self.field(field_idx),
                                        **FIELD_OPS[op],"dexPc":pc,
                                        "sourceFile":source,"sourceLine":line,
                                        "opcode":f"0x{op:02x}"})
                        pc+=width
        return out

def inventory(apk):
    with zipfile.ZipFile(apk) as z:
        names=sorted(n for n in z.namelist() if n=="classes.dex" or
                     (n.startswith("classes") and n.endswith(".dex") and n[7:-4].isdigit()))
        if not names: raise ValueError("APK has no DEX")
        dex_files=[]
        for name in names:
            dex=Dex(z.read(name),name)
            sites=dex.sites()
            dex_files.append({"name":name,"sha256":dex.shasum,
                              "fieldAccesses":sites,"count":len(sites)})
        return {"schemaVersion":1,"apk":Path(apk).name,
                "totalFieldSites":sum(d["count"] for d in dex_files),
                "dexFiles":dex_files}

def self_test():
    assert FIELD_OPS[0x52]=={"access":"instance","operation":"read","valueKind":"int"}
    assert FIELD_OPS[0x5a]["valueKind"]=="wide"
    assert FIELD_OPS[0x60]["access"]=="static"
    assert FIELD_OPS[0x6d]=={"access":"static","operation":"write","valueKind":"short"}
    assert insn_width(b"\x52\x00\x03\x00",0,0,2)==2
    assert insn_width(b"\x00\x01\x02\x00"+b"\0"*12,0,0,8)==8
    assert insn_width(b"\x00\x03\x02\x00\x03\x00\x00\x00"+b"\0"*6,0,0,7)==7
    try: insn_width(b"\x52\x00",0,0,1)
    except ValueError: pass
    else: raise AssertionError("truncated field instruction accepted")
    print("dex_field_sites self-test OK")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("apk",nargs="?")
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.self_test:
        self_test()
    else:
        if not args.apk: parser.error("APK argument required")
        result=inventory(args.apk)
        payload=json.dumps(result,indent=2,sort_keys=True)
        if args.output: args.output.write_text(payload+"\n")
        else: print(payload)
        print(f"Indexed {result['totalFieldSites']} field sites across {len(result['dexFiles'])} DEX files",file=__import__("sys").stderr)
