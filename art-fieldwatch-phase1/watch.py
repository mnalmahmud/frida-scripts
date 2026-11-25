#!/usr/bin/env python3
"""Stream verified stock-ART nterp field operations from an authorized process.

This is a reusable front end to nterp-software-probe.js, not a generalized
JIT/AOT/Android-version field interceptor. It is pinned to explicitly
allowlisted Android 13/14 x86_64 ART profiles and requires Frida device access. Only executing nterp
opcodes with independently matched packaged DEX method bytes are attributed.

Example:
  python3 art-fieldwatch-phase1/watch.py \
      --apk app-release.apk --profile nterp-profile.json \
      --process com.example.app --thread 'Worker' \
      --field 'Lcom/example/Worker;#run#counter' --duration 20
"""
import argparse
import copy
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "ci"))
from dex_field_sites import inventory  # noqa: E402
from nterp_profile import EXPECTED_BUILD_ID, KNOWN_BUILD_IDS  # noqa: E402

PROVENANCE = "live instruction base verified against packaged DEX bytes"


def parse_selector(text):
    parts = text.split("#")
    if len(parts) != 3 or not all(parts) or (
            not parts[0].startswith("L") or
            not parts[0].endswith(";") or
            "/" not in parts[0] or len(text) > 1024):
        raise ValueError(
            "Field selector must be 'Lpackage/Owner;#methodName#fieldName'")
    return {"methodClass":parts[0], "methodName":parts[1],
            "fieldName":parts[2]}


def verify_profile(profile):
    if (not isinstance(profile, dict) or profile.get("schemaVersion") != 1 or
            profile.get("api") not in KNOWN_BUILD_IDS or
            profile.get("architecture") != "x86_64" or
            profile.get("buildId") != KNOWN_BUILD_IDS[profile["api"]] or
            profile.get("handlerSize") != 128 or
            profile.get("opcodeCount") != 256 or
            not isinstance(profile.get("startOffset"), int) or
            not isinstance(profile.get("endOffset"), int) or
            profile["startOffset"] <= 0 or
            profile["endOffset"] - profile["startOffset"] != 32768):
        raise ValueError("Unsupported ART profile; no address guesses permitted")
    return profile


def inventory_packages(apks, loader=inventory):
    """Merge base/split APK DEX catalogs while preserving each DexFile ID.

    Input order is explicit: base.apk first, then split APKs in the same
    order that their DEX contents were supplied to the VM. This is NOT a
    proof of Android runtime class-loader ownership; ambiguity still fails
    closed in the Stalker method-byte matcher.
    """
    if not apks:
        raise ValueError("Provide at least one APK")
    absolute=[str(Path(path).resolve()) for path in apks]
    if len(set(absolute))!=len(absolute):
        raise ValueError("Duplicate APK path in fieldwatch DEX catalog")
    all_dex=[]
    all_fixture=[]
    for path in apks:
        part=loader(path)
        if part.get("schemaVersion")!=1 or not part.get("dexFiles"):
            raise ValueError("Invalid field-site inventory for "+str(path))
        old_to_new={}
        for item in part["dexFiles"]:
            dex=copy.deepcopy(item)
            old=dex["dexId"]
            if old in old_to_new:
                raise ValueError("Duplicate per-APK DexFile ID")
            new=len(all_dex)
            old_to_new[old]=new
            dex["dexId"]=new
            dex["apkName"]=Path(path).name
            dex["dexLocation"]=Path(path).name+"!"+dex["name"]
            all_dex.append(dex)
        for item in part.get("fixtureMethods",[]):
            method=copy.deepcopy(item)
            method["dexId"]=old_to_new[method["dexId"]]
            all_fixture.append(method)
    return {"schemaVersion":1,"apk":";".join(Path(p).name for p in apks),
            "totalFieldSites":sum(len(d["fieldAccesses"]) for d in all_dex),
            "dexFiles":all_dex,"fixtureMethods":all_fixture}


def select_catalog(catalog, selectors):
    """Shrink the host-to-agent catalog without changing per-DexFile IDs."""
    result = copy.deepcopy(catalog)
    if selectors is None:
        return result
    wanted = {(s["methodClass"], s["methodName"], s["fieldName"])
              for s in selectors}
    matched = set()
    for dex in result["dexFiles"]:
        accesses = []
        used = set()
        for site in dex["fieldAccesses"]:
            key = (site["methodClass"], site["methodName"],
                   site["fieldName"])
            if key not in wanted:
                continue
            matched.add(key)
            accesses.append(site)
            used.add(site["methodIndex"])
        dex["fieldAccesses"] = accesses
        dex["fieldMethods"] = [
            method for method in dex["fieldMethods"]
            if method["methodIndex"] in used]
        dex["count"] = len(accesses)
    if matched != wanted:
        raise ValueError("Requested DEX field selectors not found: " +
                         repr(sorted(wanted-matched)))
    result["totalFieldSites"] = sum(dex["count"] for dex in result["dexFiles"])
    return result


def assemble_agent(catalog, profile, selectors, thread, group):
    if group not in ("allPrimitives", "allFields"):
        raise ValueError("Software Stalker supports only allPrimitives/allFields")
    if not thread or len(thread) > 128:
        raise ValueError("Thread name or * must be 1..128 characters")
    source = (ROOT / "nterp-software-probe.js").read_text(encoding="utf-8")
    bindings = {
        "__artwatchNterpOpcodeGroup": group,
        "__artwatchNterpThreadFilter": thread,
        "__artwatchNterpSelectors": selectors,
        "__artwatchNterpProfile": verify_profile(profile),
        "__artwatchNterpCatalog": catalog,
    }
    # Serialize rather than interpolate selector text into JavaScript.
    preamble = "".join("globalThis."+name+"="+
                       json.dumps(value, separators=(",",":"),ensure_ascii=True)+
                       ";\n" for name,value in bindings.items())
    return preamble + source


def self_test():
    example = parse_selector("Lcom/example/Foo;#run#count")
    assert example == {"methodClass":"Lcom/example/Foo;",
                       "methodName":"run","fieldName":"count"}
    for bad in ("A#b#c","Lfoo;#x#field","Lcom/X;#x",
                "Lcom/X;#x#","Lcom/X;#x#y#z"):
        try:parse_selector(bad)
        except ValueError:pass
        else:raise AssertionError("Invalid field selector accepted: "+bad)
    profile = {
        "schemaVersion":1,"api":33,"architecture":"x86_64",
        "buildId":EXPECTED_BUILD_ID,"handlerSize":128,"opcodeCount":256,
        "startOffset":4096,"endOffset":4096+32768,
    }
    verify_profile(profile)
    verify_profile({**profile,"api":34,"buildId":KNOWN_BUILD_IDS[34]})
    for invalid in ({**profile,"api":35},
                    {**profile,"api":34},
                    {**profile,"buildId":"0"*40},
                    {**profile,"handlerSize":64}):
        try:verify_profile(invalid)
        except ValueError:pass
        else:raise AssertionError("Unsupported ART profile accepted")
    dex = {
        "dexId":0,"count":2,
        "fieldAccesses":[
            {**example,"methodIndex":1,"fieldIndex":2},
            {"methodClass":"Lcom/example/Other;","methodName":"run",
             "fieldName":"value","methodIndex":2,"fieldIndex":3}],
        "fieldMethods":[{"methodIndex":1,"registersSize":3},
                        {"methodIndex":2,"registersSize":2}],
    }
    cat = {"schemaVersion":1,"dexFiles":[dex],
           "totalFieldSites":2,"fixtureMethods":[]}
    filtered=select_catalog(cat,[example])
    assert len(filtered["dexFiles"][0]["fieldAccesses"])==1
    assert len(filtered["dexFiles"][0]["fieldMethods"])==1
    assert cat["totalFieldSites"]==2  # no mutation of caller input
    assert select_catalog(cat,None)["totalFieldSites"]==2
    merged=inventory_packages(["base.apk","split_feature.apk"],
        loader=lambda path: {**cat,"dexFiles":[{**dex,"name":"classes.dex"}]})
    assert len(merged["dexFiles"])==2
    assert [d["dexId"] for d in merged["dexFiles"]]==[0,1]
    assert [d["dexLocation"] for d in merged["dexFiles"]]==[
        "base.apk!classes.dex","split_feature.apk!classes.dex"]
    assert merged["totalFieldSites"]==4
    try: inventory_packages(["base.apk","base.apk"],
        loader=lambda path:cat)
    except ValueError:pass
    else:raise AssertionError("Duplicate split APK input accepted")
    try:select_catalog(cat,[parse_selector("Lcom/example/No;#run#x")])
    except ValueError:pass
    else:raise AssertionError("Missing DEX selector accepted")
    agent=assemble_agent(filtered,profile,[example],"Worker'\\\n", "allFields")
    assert "Stalker.follow" in agent and "rpc.exports" in agent
    assert '"Worker\\u0027' not in agent  # json.dumps uses escaped quotes
    assert 'globalThis.__artwatchNterpOpcodeGroup="allFields";' in agent
    assert 'globalThis.__artwatchNterpCatalog=' in agent
    print("Generic ART nterp field watcher CLI self-test passed")


def watch(args):
    if not args.apk or not args.profile or not args.process or not args.thread:
        raise ValueError("--apk, --profile, --process, and --thread required")
    if not args.all_fields and not args.field:
        raise ValueError("Use explicit --field selectors or --all-fields")
    if args.duration < 0 or not 50 <= args.poll_ms <= 5000:
        raise ValueError("Invalid duration/poll interval")
    selectors = ([parse_selector(item) for item in args.field]
                 if args.field else None)
    group = "allPrimitives" if args.primitives_only else "allFields"
    profile = verify_profile(json.loads(args.profile.read_text()))
    catalog = select_catalog(inventory_packages(args.apk), selectors)
    if not catalog["totalFieldSites"]:
        raise ValueError("No field instructions were found in the APK")
    source=assemble_agent(catalog,profile,selectors,args.thread,group)

    # Frida is imported only when actually running on a connected device;
    # static/unit tests do not require the mobile SDK or live device.
    import frida
    device=frida.get_usb_device(timeout=30)
    session=None
    script=None
    spawned=None
    resumed=False
    errors=[]
    produced=0
    target=args.process if not args.process.isdigit() else int(args.process)
    stream=open(args.output,"w",encoding="utf-8") if args.output else sys.stdout

    def on_message(message, unused):
        if message.get("type") == "error":
            errors.append(message.get("stack") or str(message))
        else:
            item=message.get("payload")
            if isinstance(item,dict) and item.get("type") in (
                    "artwatch-nterp-stalker-error",
                    "artwatch-nterp-software-error"):
                errors.append(item.get("error") or repr(item))

    def drain():
        nonlocal produced
        while True:
            item=script.exports_sync.drain(4096)
            for event in item["events"]:
                if event.get("dexPcSource") != PROVENANCE:
                    raise RuntimeError("Runtime DEX identity was not verified")
                stream.write(json.dumps(event,sort_keys=True)+"\n")
                produced+=1
            stream.flush()
            if item["errors"] or item["dropped"] or item["unverifiedSites"]:
                raise RuntimeError("Field instrumentation did not remain lossless: "+
                                   repr({k:item[k] for k in (
                                       "errors","dropped","unverifiedSites")}))
            if item["queued"]==0:
                break

    try:
        if args.spawn:
            if not isinstance(target,str):
                raise ValueError("--spawn requires an application package name")
            spawned=device.spawn([target])
            target=spawned
        session=device.attach(target)
        script=session.create_script(source)
        script.on("message",on_message)
        script.load()
        initial=script.exports_sync.snapshot()
        if not initial.get("ready") or initial.get("errors"):
            raise RuntimeError("Unsupported ART or unverified DEX catalog: "+
                               repr(initial.get("errors",[])))
        if script.exports_sync.arm() is not True:
            raise RuntimeError("Could not begin Stalker field tracing")
        if spawned is not None:
            device.resume(spawned)
            resumed=True
        print(f"Watching {args.process}: {catalog['totalFieldSites']} packaged "
              f"sites, group={group}, thread={args.thread}; "
              "nterp-only; no JIT/AOT coverage", file=sys.stderr,flush=True)
        started=time.monotonic()
        while not args.duration or time.monotonic()-started<args.duration:
            time.sleep(args.poll_ms/1000)
            drain()
            if errors:
                raise RuntimeError("Frida errors: "+"; ".join(errors))
            if args.max_events and produced>=args.max_events:
                break
        drain()
        state=script.exports_sync.snapshot()
        print("ART fieldwatch summary: "+json.dumps({
            key:state.get(key) for key in (
                "threadsFollowed","fieldHits","completedHits",
                "unverifiedSites","dropped","totalRecorded","abandonedFieldAttempts")
        },sort_keys=True),file=sys.stderr,flush=True)
        return 0
    except KeyboardInterrupt:
        if script is not None:
            drain()
        return 0
    finally:
        if script is not None:
            try:script.exports_sync.stop()
            except Exception as e:print("Unable to stop field tracing: "+str(e),
                                     file=sys.stderr)
        if spawned is not None and not resumed:
            try:device.resume(spawned)
            except Exception:pass
        if session is not None:
            try:session.detach()
            except Exception:pass
        if stream is not sys.stdout:
            stream.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--apk",type=Path,action="append",
                        help="Exact base APK; repeat for split APKs in order")
    parser.add_argument("--profile",type=Path,help="Pinned nterp ELF profile JSON")
    parser.add_argument("--process",help="Existing process name/PID or spawn package")
    parser.add_argument("--thread",help="Exact thread name, or * for all threads")
    selection=parser.add_mutually_exclusive_group()
    selection.add_argument("--field",action="append",help="Class#method#field")
    selection.add_argument("--all-fields",action="store_true",
                           help="Explicitly select all packaged DEX field sites")
    parser.add_argument("--primitives-only",action="store_true",
                        help="Exclude reference-field opcodes")
    parser.add_argument("--spawn",action="store_true",
                        help="Spawn package paused, attach+arm, then resume")
    parser.add_argument("--duration",type=float,default=20.0,
                        help="Seconds to observe; 0 runs until Ctrl+C")
    parser.add_argument("--poll-ms",type=int,default=200)
    parser.add_argument("--max-events",type=int,default=0,
                        help="Stop after at least N events (0 means no cap)")
    parser.add_argument("--output",type=Path,help="Write JSONL instead of stdout")
    args=parser.parse_args()
    if args.self_test:
        self_test()
    else:
        try:
            sys.exit(watch(args))
        except (ValueError,RuntimeError,OSError) as error:
            parser.exit(2,"ART fieldwatch: "+str(error)+"\n")


if __name__=="__main__":
    main()
