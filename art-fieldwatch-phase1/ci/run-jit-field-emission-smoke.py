#!/usr/bin/env python3
"""Stock non-debuggable ART JIT compiler field-codegen correlation oracle.

Only observes compiler HInstanceFieldGet/Set codegen visits. It DOES NOT
install runtime field hooks, extract native field values, or claim AOT coverage.
The two Java leaf methods have no sink/template, and the input catalog
comes from the packaged final APK's real DEX field instructions.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from watch import inventory_packages, select_catalog, parse_selector

PACKAGE="com.example.artfieldwatch"
PROCESS=PACKAGE+":fieldwatch_nterp"
ACTIVITY=PACKAGE+"/.NoTemplateNterpActivity"
OWNER="Lcom/example/artfieldwatch/NoTemplateTarget;"
JAVA_TAG="ARTWATCH_NTERP_LAB"


def adb(*arguments,timeout=30):
    return subprocess.check_output(
        ["adb",*arguments],text=True,timeout=timeout).strip()


def wait(predicate,seconds,description):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        result=predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("JIT field codegen: timeout waiting for "+description)


def log(pid):
    return adb("logcat","-d",f"--pid={pid}","-s",JAVA_TAG+":I","*:S")


def command(extra):
    result=subprocess.run(["adb","shell","am","start","-W","-n",ACTIVITY,
                           "--ez",extra,"true"],
                          capture_output=True,text=True,timeout=15)
    if result.returncode!=0:
        raise AssertionError("Cannot launch JIT workload: "+result.stderr)


def main():
    if os.environ.get("ARTWATCH_BUILD_VARIANT")!="release":
        raise AssertionError("JIT codegen oracle requires non-debuggable APK")
    if adb("shell","getprop","ro.build.version.sdk")!="33":
        raise AssertionError("JIT codegen observer is gated to API33 exact ELF")
    folder=Path(os.environ.get("ARTWATCH_LOG_DIR","/tmp/artwatch-logs"))
    folder.mkdir(parents=True,exist_ok=True)
    apk=ROOT/"test/app/build/outputs/apk/release/app-release.apk"
    if not apk.exists():
        raise FileNotFoundError(apk)
    # ART compiled the 40k-iteration caller, not its trivial reflective
    # leaf methods. Verify the volatile field in that genuinely JIT-compiled
    # caller so optimizing ART retains both read and write operations.
    selectors=[parse_selector(OWNER+"#exerciseJitFieldCanary#jitVolatile")]
    catalog=select_catalog(inventory_packages([apk]),selectors)
    fields=[f for d in catalog["dexFiles"] for f in d["fieldAccesses"]]
    if (len(fields)!=2 or sorted(f["opcode"] for f in fields)!=["0x52","0x59"] or
            {f["operation"] for f in fields}!={"read","write"}):
        raise AssertionError("Missing two exact hot JIT caller DEX field accesses")
    adb("shell","am","force-stop",PACKAGE)
    adb("logcat","-c")
    adb("shell","am","start","-W","-n",ACTIVITY)
    def pid():
        try:return adb("shell","pidof",PROCESS).split()[0]
        except (subprocess.CalledProcessError,IndexError):return None
    target=wait(pid,15,"isolated release process")
    # Ensure libart-compiler.so is loaded before the target methods heat up.
    command("jitWarm")
    wait(lambda:"NTERP_LAB_JIT_WARM_DONE checks=50000" in log(target),
         30,"unrelated JIT warmup")
    import frida
    device=frida.get_usb_device(timeout=30)
    session=device.attach(int(target))
    script=None
    messages=[]
    try:
        source=("globalThis.__artwatchJitFieldCatalog="+
                json.dumps(catalog,separators=(",",":"))+";\n"+
                (ROOT/"jit-field-emission-probe.js").read_text())
        script=session.create_script(source)
        script.on("message",lambda msg,_:messages.append(msg))
        script.load()
        ready=wait(
            lambda:script.exports_sync.snapshot().get("ready") or
                   script.exports_sync.snapshot().get("errors"),
            15,"stock ART compiler ABI inventory")
        state=script.exports_sync.snapshot()
        if not state["ready"] or state["errors"]:
            raise AssertionError("JIT codegen hook profile unavailable: "+
                                 repr(state["errors"]))
        command("jit")
        wait(lambda:"NTERP_LAB_JIT_DONE checks=40000" in log(target),
             40,"unmodified reflected hot Java method calls")
        # ART JIT compilation is asynchronous; the live source observer
        # must record codegen visits for both selected DEX leaf methods.
        def has_compiled_sites():
            snapshot=script.exports_sync.snapshot()
            records=snapshot["records"]
            observed={r.get("kind") for r in records
                      if r.get("phase")=="field-codegen" and
                      r.get("candidateCount")==1}
            return snapshot if observed=={"read","write"} else None
        try:
            state=wait(has_compiled_sites,20,
                       "both exact JIT compiler field emissions")
        except AssertionError as original:
            state=script.exports_sync.snapshot()
            detail={
                "summary":{k:state.get(k) for k in
                           ("ready","compiled","emitted","matched",
                            "rawFieldVisits","selectedCompilations","errors")},
                "records":state.get("records",[]),
                "fridaMessages":messages[-64:],
                "javaLog":log(target)[-6000:]
            }
            (folder/"jit-field-codegen-diagnostics.json").write_text(
                json.dumps(detail,indent=2,sort_keys=True)+"\n")
            raise AssertionError(str(original)+"; observed "+
                                 json.dumps(detail["summary"])) from original
        fields=[r for r in state["records"] if r["phase"]=="field-codegen"]
        if not fields or state["errors"] or any(
                r["candidateCount"]!=1 or
                r["dexFileRuntimeVerified"] or
                r["valueAvailable"] or
                not r["nodeVtableVerified"] for r in fields):
            raise AssertionError("JIT codegen correlation/integrity failure")
        report={
            "scope":"API33 verified compiler codegen observations only",
            "noRuntimeFieldValues":True,
            "noAotCoverage":True,
            "summary":{k:state[k] for k in ("compiled","emitted","matched")},
            "records":fields
        }
        (folder/"jit-field-codegen-observations.json").write_text(
            json.dumps(report,indent=2,sort_keys=True)+"\n")
        print("PASS: API33 stock non-debuggable ART JIT codegen emitted "
              "native instance read AND write for DEX-indexed leaf methods; "
              "compiler-only, no exact runtime values")
    finally:
        if script is not None:
            try:script.unload()
            except Exception:pass
        session.detach()


if __name__=="__main__":
    main()
