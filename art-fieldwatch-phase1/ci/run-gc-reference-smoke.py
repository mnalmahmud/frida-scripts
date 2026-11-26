#!/usr/bin/env python3
"""Opt-in JNI weak-root identity oracle across GC requests (API33 release).

The raw 32-bit ART reference bits remain ephemeral. This validates that
a separately issued weak JNI global reference identity persists across
field writes and reads, without a Java sink/field trampoline.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PACKAGE="com.example.artfieldwatch"
PROCESS=PACKAGE+":fieldwatch_nterp"
ACTIVITY=PACKAGE+"/.NoTemplateNterpActivity"
OWNER="Lcom/example/artfieldwatch/NoTemplateTarget;"
STATIC="Lcom/example/artfieldwatch/NoTemplateStaticState;"
FIELDS=[
    (OWNER,"writeInstanceObject","reference",2,0x5b),
    (STATIC,"writeStaticObject","sharedObject",2,0x69),
    (OWNER,"readInstanceObject","reference",1,0x54),
    (STATIC,"readStaticObject","sharedObject",1,0x62)
]


def adb(*args,timeout=30):
    return subprocess.check_output(["adb",*args],text=True,timeout=timeout).strip()


def lab_log(pid):
    return adb("logcat","-d",f"--pid={pid}","-s",
               "ARTWATCH_NTERP_LAB:I","*:S")


def wait(predicate,seconds,why):
    limit=time.monotonic()+seconds
    while time.monotonic()<limit:
        result=predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("GC reference fieldwatch timeout: "+why)


def main():
    if os.environ.get("ARTWATCH_BUILD_VARIANT")!="release":
        raise AssertionError("GC-root bridge requires non-debuggable APK")
    if adb("shell","getprop","ro.build.version.sdk")!="33" or (
            adb("shell","getprop","ro.product.cpu.abi")!="x86_64"):
        raise AssertionError("Only exact stock Android 33 x64 supported")
    folder=Path(os.environ.get("ARTWATCH_LOG_DIR","/tmp/artwatch-logs"))
    folder.mkdir(parents=True,exist_ok=True)
    apk=ROOT/"test/app/build/outputs/apk/release/app-release.apk"
    adb("shell","am","force-stop",PACKAGE)
    adb("logcat","-c")
    adb("shell","am","start","-W","-n",ACTIVITY)
    def pid():
        try:return adb("shell","pidof",PROCESS).split()[0]
        except (subprocess.CalledProcessError,IndexError):return None
    target=wait(pid,15,"target process")
    output=folder/"gc-stable-reference-events.jsonl"
    coverage=folder/"gc-stable-reference-coverage.json"
    trace=folder/"gc-stable-reference-host.log"
    cmd=[sys.executable,str(ROOT/"watch.py"),
         "--apk",str(apk),"--auto-profile",
         "--process",target,"--thread","NterpFieldProbe",
         "--reference-identity","--duration","28","--poll-ms","50",
         "--output",str(output),"--coverage-output",str(coverage)]
    for owner,method,field,_,_ in FIELDS:
        cmd+=["--field",f"{owner}#{method}#{field}"]
    with trace.open("w+",encoding="utf-8") as log:
        child=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=log)
        try:
            def ready():
                if child.poll() is not None:
                    raise AssertionError(
                        "JNI reference bridge initialization failed: "+
                        trace.read_text(errors="replace")[-5000:])
                log.flush()
                return "Watching " in trace.read_text(errors="replace")
            wait(ready,20,"JNI weak-root bridge armed")
            launch=subprocess.run(
                ["adb","shell","am","start","-W","-n",ACTIVITY,
                 "--ez","gcRefs","true"],
                capture_output=True,text=True,timeout=15)
            if launch.returncode:
                raise AssertionError("Cannot run GC reference workload")
            def complete():
                lines=lab_log(target)
                if "NTERP_LAB_FAILED" in lines:
                    raise AssertionError("Java GC reference oracle failed: "+lines)
                return "NTERP_LAB_GC_REFS_DONE checks=128" in lines
            wait(complete,26,"128 GC-pressured field checks")
            if child.wait(timeout=40)!=0:
                raise AssertionError("JNI weak-root fieldwatch rejected run: "+
                                     trace.read_text(errors="replace")[-5000:])
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
    rows=[json.loads(line) for line in output.read_text().splitlines() if line]
    if len(rows)!=512:
        raise AssertionError(f"Expected 512 object field events, got {len(rows)}")
    objects=set()
    first_ids=None
    for iteration in range(128):
        quartet=rows[iteration*4:iteration*4+4]
        if len(quartet)!=4:
            raise AssertionError("Incomplete object field quartet")
        ids=[]
        for j,(owner,method,field,kind,opcode) in enumerate(FIELDS):
            entry=quartet[j]
            required={
                "seq":iteration*4+j+1,"methodClass":owner,
                "method":method,"fieldName":field,"kind":kind,
                "opcode":opcode,"fieldType":"Ljava/lang/Object;",
                "referenceIsNull":False,
                "referenceSnapshotGcStable":False,
                "referenceIdentityGcStable":True,
                "referenceIdentityKind":"jni-weak-global",
            }
            for key,value in required.items():
                if entry.get(key)!=value:
                    raise AssertionError(
                        f"GC identity event {iteration}/{j}: "
                        f"{key}={entry.get(key)!r} != {value!r}")
            identity=entry.get("referenceIdentityId")
            if not isinstance(identity,str) or not identity.startswith("art-ref-"):
                raise AssertionError("Missing managed JNI weak-root identity")
            ids.append(identity)
            objects.add(identity)
        if ids[0]!=ids[2] or ids[1]!=ids[3] or ids[0]==ids[1]:
            raise AssertionError("Object identity inconsistent within quartet")
        if first_ids is None:
            first_ids=(ids[0],ids[1])
        expected=(first_ids if iteration%2==0 else first_ids[::-1])
        if tuple(ids[:2])!=expected:
            raise AssertionError(
                f"Managed object ID changed across GC round {iteration}")
    if len(objects)!=2:
        raise AssertionError("Expected exactly two distinct managed object IDs")
    report=json.loads(coverage.read_text())
    if (report["observedEvents"]!=512 or report["observedSites"]!=4 or
            report["totalSelectedSites"]!=4):
        raise AssertionError("GC reference opcode-site coverage mismatch")
    print("PASS: 512 object field operations with two persistent JNI weak "
          "identity IDs across 8 Java GC requests (moving GC not asserted)")


if __name__=="__main__":
    main()
