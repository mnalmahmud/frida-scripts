#!/usr/bin/env python3
"""Offline end-to-end test of watch.py asynchronous batch/RPC-tail transport.

Mocks only Frida device I/O; executes the real watch() host pipeline,
including catalog selection, event ordering, JSONL and coverage output.
"""
import json
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import watch


OWNER="Lcom/example/Target;"
FIELD="count"
PROVENANCE=watch.PROVENANCE


def catalog():
    fields=[]
    methods=[]
    for i,op in enumerate((0x59,0x52)):
        name=("write","read")[i]
        fields.append({
            "methodClass":OWNER,"methodName":name,
            "methodPrototype":"(I)V" if i==0 else "()I",
            "declaringClass":OWNER,"fieldName":FIELD,
            "fieldType":"I","valueKind":"int",
            "methodIndex":10+i,"fieldIndex":2,
            "dexPc":0,"opcode":f"0x{op:02x}",
            "operation":"write" if i==0 else "read",
        })
        methods.append({
            "methodClass":OWNER,"methodName":name,
            "methodIndex":10+i,"registersSize":2,
            "insnsSize":2,"insnsHex":f"{op:02x}000200",
        })
    return {
        "schemaVersion":1,"dexFiles":[{
            "dexId":0,"name":"classes.dex","sha256":"a"*64,
            "fieldAccesses":fields,"fieldMethods":methods,"count":2
        }],"totalFieldSites":2,"fixtureMethods":[]
    }


def event(seq):
    i=(seq-1)%2
    return {
        "seq":seq,"methodIndex":10+i,
        "dexId":0,"dexPc":0,"fieldIndex":2,
        "opcode":(0x59,0x52)[i],
        "fieldType":"I","fieldName":FIELD,
        "dexPcSource":PROVENANCE,
        "value":(seq+1)//2,
    }


class Script:
    def __init__(self,mode):
        self.mode=mode
        self.message_callback=None
        self.exports_sync=self
        self.armed=False
        self.ended=False
        self.tail_once=False

    def on(self,topic,callback):
        assert topic=="message"
        self.message_callback=callback

    def load(self):
        return None

    def snapshot(self):
        return {
            "ready":True,"errors":[],"totalRecorded":5,
            "dropped":0,"unverifiedSites":0,"fieldHits":5,
            "completedHits":5,"threadsFollowed":1,
            "abandonedFieldAttempts":0,
        }

    def arm(self):
        self.armed=True
        # Force arrival out of order to test sequence reassembly.
        self.send([event(3),event(4)])
        self.send([event(1),event(2)])
        if self.mode=="duplicate":
            self.send([event(1)])
        return True

    def send(self,events):
        self.message_callback({
            "type":"send","payload":{
                "type":"artwatch-nterp-record-batch","events":events
            }
        },None)

    def drain(self,limit):
        assert limit==4096
        if self.tail_once:
            events=[]
        else:
            events=[event(5)]
            self.tail_once=True
        return {
            "events":events,"queued":0,"errors":[],
            "dropped":0,"unverifiedSites":0,
        }

    def stop(self):
        self.ended=True
        return {"removed":1,"failures":0,"recorded":5}


class Session:
    def __init__(self,mode):
        self.mode=mode

    def create_script(self,source):
        assert "__artwatchNterpStreamBatchSize" in source
        return Script(self.mode)

    def detach(self):
        pass


class Device:
    def __init__(self,mode):
        self.mode=mode

    def attach(self,target):
        assert target=="demo"
        return Session(self.mode)


def run(mode,folder):
    out=folder/("events-"+mode+".jsonl")
    coverage=folder/("coverage-"+mode+".json")
    args=types.SimpleNamespace(
        apk=[folder/"base.apk"],profile=None,auto_profile=True,
        process="demo",thread="Worker",thread_regex=None,
        all_fields=True,field=None,watch_field=None,
        primitives_only=True,operation="both",
        spawn=False,duration=0.001,poll_ms=50,
        max_events=0,output=out,coverage_output=coverage,
    )
    fake_frida=types.SimpleNamespace(
        get_usb_device=lambda timeout:Device(mode)
    )
    with patch.dict(sys.modules,{"frida":fake_frida}), \
         patch.object(watch,"discover_device_profile",lambda **kwargs:profile()), \
         patch.object(watch,"inventory_packages",lambda apks:catalog()), \
         patch.object(watch,"assemble_agent",lambda *a,**kwargs:"__artwatchNterpStreamBatchSize"):
        if mode=="duplicate":
            try:
                watch.watch(args)
            except RuntimeError as error:
                assert "Duplicate" in str(error),str(error)
            else:
                raise AssertionError("Duplicate streamed event was accepted")
        else:
            assert watch.watch(args)==0
            rows=[json.loads(line) for line in out.read_text().splitlines()]
            assert [row["seq"] for row in rows]==[1,2,3,4,5]
            assert [row["value"] for row in rows]==[1,1,2,2,3]
            cov=json.loads(coverage.read_text())
            assert cov["observedEvents"]==5
            assert cov["observedSites"]==2
            assert [s["observedCount"] for s in cov["sites"]]==[3,2]


def profile():
    return {
        "schemaVersion":1,"api":33,"architecture":"x86_64",
        "buildId":watch.EXPECTED_BUILD_ID,
        "handlerSize":128,"opcodeCount":256,
        "startOffset":4096,"endOffset":4096+32768,
    }


def main():
    with tempfile.TemporaryDirectory(prefix="artwatch-transport-") as tmp:
        folder=Path(tmp)
        run("reorder",folder)
        run("duplicate",folder)
    print("PASS: generic watch.py async batches and RPC tail, "
          "contiguous JSONL and duplicate-event rejection")


if __name__=="__main__":
    main()
