#!/usr/bin/env python3
"""End-to-end generic watch.py CLI oracle on a real non-debuggable APK."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
PKG="com.example.artfieldwatch"
LAB=PKG+":fieldwatch_nterp"
ACTIVITY=PKG+"/.NoTemplateNterpActivity"
OWNER="Lcom/example/artfieldwatch/NoTemplateTarget;"
SITES=(
    ("overloadedWrite",f"({OWNER}I)V",0x59,2),
    ("overloadedRead", f"({OWNER}I)I",0x52,1),
    ("overloadedWrite",f"({OWNER}J)V",0x59,2),
    ("overloadedRead", f"({OWNER}J)I",0x52,1)
)

def adb(*args,timeout=30):
    return subprocess.check_output(["adb",*args],text=True,timeout=timeout).strip()

def lab_log(pid):
    return adb("logcat","-d",f"--pid={pid}","-s",
               "ARTWATCH_NTERP_LAB:I","*:S")

def main():
    if os.environ.get("ARTWATCH_BUILD_VARIANT")!="release":
        raise AssertionError("Generic field watcher only tests non-debuggable release APK")
    root=Path(os.environ.get("ARTWATCH_LOG_DIR","/tmp/artwatch-logs"))
    root.mkdir(parents=True,exist_ok=True)
    apk=BASE/"test"/"app"/"build"/"outputs"/"apk"/"release"/"app-release.apk"
    if not apk.is_file():
        raise FileNotFoundError(apk)
    adb("shell","am","force-stop",PKG)
    adb("logcat","-c")
    adb("shell","am","start","-W","-n",ACTIVITY)
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        try:
            pids=adb("shell","pidof",LAB)
        except subprocess.CalledProcessError:
            pids=""
        if pids:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("No isolated nterp process for generic watcher")
    pid=pids.split()[0]
    out=root/"generic-fieldwatch-overload.jsonl"
    coverage=root/"generic-fieldwatch-overload-coverage.json"
    stderr=root/"generic-fieldwatch-overload-host.log"
    cmd=[sys.executable,str(BASE/"watch.py"),
         "--apk",str(apk),"--auto-profile",
         "--process",pid,"--thread","NterpFieldProbe",
         "--duration","15","--poll-ms","50",
         "--output",str(out),"--coverage-output",str(coverage)]
    # Select the FIELD itself, across every DEX caller method. There
    # are more eligible packaged sites than the four workload overloads,
    # so the observation report must distinguish executed nterp sites
    # from sites that were merely indexed.
    cmd.extend(["--watch-field", f"{OWNER}#value"])
    with stderr.open("w+",encoding="utf-8") as log:
        child=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=log)
        try:
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if child.poll() is not None:
                    log.flush()
                    raise AssertionError("Generic watcher exited before arming: "+
                                         stderr.read_text()[-3000:])
                log.flush()
                if "Watching " in stderr.read_text():
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Generic watcher did not arm before workload")
            started=subprocess.run(["adb","shell","am","start","-W","-n",ACTIVITY,
                                    "--ez","overload","true"],
                                   capture_output=True,text=True,timeout=15)
            if started.returncode!=0:
                raise AssertionError("Cannot launch overloaded Java workload")
            deadline=time.monotonic()+12
            while time.monotonic()<deadline:
                logs=lab_log(pid)
                if "NTERP_LAB_FAILED" in logs:
                    raise AssertionError("Overloaded Java workload failed")
                if "NTERP_LAB_OVERLOAD_DONE checks=256 checksum=-12800" in logs:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Overloaded Java workload did not complete")
            return_code=child.wait(timeout=35)
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
        if return_code!=0:
            raise AssertionError("Generic watcher exited with "+
                                 str(return_code)+": "+stderr.read_text()[-4000:])
    rows=[json.loads(line) for line in out.read_text().splitlines() if line]
    if len(rows)!=512:
        raise AssertionError(f"Expected 512 JSONL field events, got {len(rows)}")
    for i in range(128):
        for j,(name,proto,opcode,kind) in enumerate(SITES):
            row=rows[4*i+j]
            expected_value=100+i if j<2 else -200-i
            required={
                "seq":4*i+j+1,"method":name,"methodPrototype":proto,
                "methodClass":OWNER,"fieldName":"value",
                "fieldType":"I","value":expected_value,"opcode":opcode,
                "kind":kind,"valueRepresentation":"signed-int32",
                "dexPcSource":"live instruction base verified against packaged DEX bytes",
            }
            for key,value in required.items():
                if row.get(key)!=value:
                    raise AssertionError(
                        f"Generic watcher event i={i} j={j}: "
                        f"{key} {row.get(key)!r} != {value!r}")
    summary=json.loads(coverage.read_text())
    selected=summary["totalSelectedSites"]
    nonzero=sorted(site["observedCount"] for site in summary["sites"]
                   if site["observedCount"])
    if (summary["observedEvents"]!=512 or
            selected<4 or summary["observedSites"]!=4 or
            summary["unobservedSites"]!=selected-4 or
            nonzero != [128]*4 or
            any(site["declaringClass"]!=OWNER for site in
                summary["sites"])):
        raise AssertionError("Declaring-field watcher coverage report incorrect")
    print("PASS: generic watch.py --auto-profile streamed 512 exact "
          "overloaded nterp field events with four fully observed DEX sites")

if __name__=="__main__":
    main()
