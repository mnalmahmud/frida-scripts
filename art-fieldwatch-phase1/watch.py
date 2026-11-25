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
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "ci"))
from dex_field_sites import inventory  # noqa: E402
from nterp_profile import EXPECTED_BUILD_ID, KNOWN_BUILD_IDS, resolve  # noqa: E402

PROVENANCE = "live instruction base verified against packaged DEX bytes"


def parse_selector(text):
    parts = text.split("#")
    if len(parts) != 3 or not all(parts) or (
            not parts[0].startswith("L") or
            not parts[0].endswith(";") or
            "/" not in parts[0] or len(text) > 1024):
        raise ValueError(
            "Field selector must be 'Lpackage/Owner;#methodName#fieldName'")
    method = parts[1]
    proto = None
    if "(" in method:
        pos = method.index("(")
        proto = method[pos:]
        method = method[:pos]
        if not method or not re.fullmatch(r"\([^)]*\).+", proto):
            raise ValueError("Invalid method prototype in field selector")
    elif ")" in method:
        raise ValueError("Unexpected closing method prototype")
    result = {"methodClass":parts[0], "methodName":method,
              "fieldName":parts[2]}
    if proto is not None:
        result["methodPrototype"] = proto
    return result


def parse_declared_field(text):
    """Select a DEX field by its DECLARING class, not the executing method."""
    parts = text.split("#")
    if (len(parts) != 2 or not all(parts) or len(text) > 1024 or
            not parts[0].startswith("L") or
            not parts[0].endswith(";") or
            "/" not in parts[0] or any(c.isspace() for c in text)):
        raise ValueError(
            "Field watch must be 'Lpackage/DeclaringClass;#fieldName'")
    return {"declaringClass": parts[0], "fieldName": parts[1]}


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


def discover_device_profile(adb="adb", readelf="readelf"):
    """Verify the installed ART ELF using the device's actual binary.

    No guessed offsets: the ELF build ID, machine, symbol table, and exact
    nterp handler-table span must all pass the same standalone resolver.
    """
    def prop(name):
        result=subprocess.run([adb,"shell","getprop",name],
                              check=True,capture_output=True,text=True,
                              timeout=20)
        return result.stdout.strip()
    sdk=prop("ro.build.version.sdk")
    abi=prop("ro.product.cpu.abi")
    if not sdk.isdigit() or int(sdk) not in KNOWN_BUILD_IDS or abi!="x86_64":
        raise ValueError(f"No approved nterp profile for SDK={sdk} ABI={abi}")
    with tempfile.TemporaryDirectory(prefix="artwatch-profile-") as directory:
        libart=Path(directory)/"libart.so"
        pulled=False
        for remote in ("/apex/com.android.art/lib64/libart.so",
                       "/system/lib64/libart.so"):
            try:
                subprocess.run([adb,"pull",remote,str(libart)],
                               check=True,capture_output=True,text=True,
                               timeout=60)
                if libart.is_file() and libart.stat().st_size>4096:
                    pulled=True
                    break
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
                continue
        if not pulled:
            raise ValueError("Failed to retrieve the installed ART ELF")
        def elf(*options):
            return subprocess.check_output([readelf,*options,str(libart)],
                                           text=True,timeout=30)
        return verify_profile(resolve(elf("--wide","-Ws"),
                                      elf("-n"),elf("-h"),api=int(sdk)))


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
    wanted = {(s["methodClass"], s["methodName"], s["fieldName"],
               s.get("methodPrototype")) for s in selectors}
    matched = set()
    for dex in result["dexFiles"]:
        accesses = []
        used = set()
        for site in dex["fieldAccesses"]:
            prefix = (site["methodClass"], site["methodName"],
                      site["fieldName"])
            wildcard = (*prefix, None)
            specific = (*prefix, site.get("methodPrototype"))
            if wildcard not in wanted and specific not in wanted:
                continue
            if wildcard in wanted:
                matched.add(wildcard)
            if specific in wanted:
                matched.add(specific)
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


def select_catalog_by_declared_fields(catalog, field_selectors):
    """Select every DEX caller site accessing each named declaring field.

    A declared field may have many iget/iput/sget/sput instructions in
    unrelated caller methods. Preserve original per-DEX method indices and
    exact method bytes, only pruning unselected sites and methods.
    """
    if not field_selectors:
        raise ValueError("At least one declaring-field selector is required")
    wanted = {(s["declaringClass"], s["fieldName"])
              for s in field_selectors}
    seen = set()
    result = copy.deepcopy(catalog)
    for dex in result["dexFiles"]:
        accesses = []
        method_ids = set()
        for site in dex["fieldAccesses"]:
            identity = (site["declaringClass"], site["fieldName"])
            if identity not in wanted:
                continue
            accesses.append(site)
            method_ids.add(site["methodIndex"])
            seen.add(identity)
        dex["fieldAccesses"] = accesses
        dex["fieldMethods"] = [method for method in dex["fieldMethods"]
                               if method["methodIndex"] in method_ids]
        dex["count"] = len(accesses)
    if seen != wanted:
        raise ValueError("Requested declaring fields missing from DEX: " +
                         repr(sorted(wanted-seen)))
    result["totalFieldSites"] = sum(d["count"] for d in result["dexFiles"])
    return result


class CoverageTracker:
    """Report observed nterp sites without claiming executed-code coverage."""
    def __init__(self,catalog,include_object=True):
        self.entries={}
        for dex in catalog["dexFiles"]:
            for site in dex["fieldAccesses"]:
                if not include_object and site["valueKind"]=="object":
                    continue
                key=(dex["dexId"],site["methodIndex"],
                     site["dexPc"],site["fieldIndex"])
                if key in self.entries:
                    raise ValueError("Duplicate catalog field site: "+repr(key))
                self.entries[key]={
                    "dexId":dex["dexId"],"dexName":dex.get("name"),
                    "dexLocation":dex.get("dexLocation",dex.get("name")),
                    "methodClass":site["methodClass"],
                    "declaringClass":site["declaringClass"],
                    "methodName":site["methodName"],
                    "methodPrototype":site.get("methodPrototype"),
                    "fieldName":site["fieldName"],"fieldType":site["fieldType"],
                    "fieldIndex":site["fieldIndex"],"methodIndex":site["methodIndex"],
                    "dexPc":site["dexPc"],"opcode":site["opcode"],
                    "observedCount":0
                }
        self.total_events=0

    def observe(self,event):
        key=(event["dexId"],event["methodIndex"],
             event["dexPc"],event["fieldIndex"])
        site=self.entries.get(key)
        if site is None:
            raise RuntimeError("Event refers to a site outside verified APK catalog")
        if int(site["opcode"],16)!=event["opcode"] or (
                site["fieldType"]!=event["fieldType"]):
            raise RuntimeError("Field opcode or descriptor differs from catalog")
        site["observedCount"]+=1
        self.total_events+=1

    def report(self):
        seen=sum(site["observedCount"]>0 for site in self.entries.values())
        return {
            "schemaVersion":1,
            "scope":"observed-nterp-site-only; not executed-code coverage",
            "limitations":("Non-observation can mean never executed, compiled "
                "JIT/AOT/native path, unfollowed thread, dynamic DEX, or a "
                "different ART interpreter; no execution completeness claim"),
            "totalSelectedSites":len(self.entries),
            "observedSites":seen,
            "unobservedSites":len(self.entries)-seen,
            "observedEvents":self.total_events,
            "sites":sorted(self.entries.values(),
                key=lambda x:(x["dexId"],x["methodIndex"],x["dexPc"]))
        }


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
    overloaded = parse_selector("Lcom/example/Foo;#run(I)J#count")
    assert overloaded == {**example,"methodPrototype":"(I)J"}
    assert parse_selector("Lcom/example/Foo;#<init>(Ljava/lang/String;)V#count")[
        "methodPrototype"] == "(Ljava/lang/String;)V"
    for bad in ("A#b#c","Lfoo;#x#field","Lcom/X;#x",
                "Lcom/X;#x#","Lcom/X;#x#y#z",
                "Lcom/X;#run(Invalid#field", "Lcom/X;#run)#x"):
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
            {**example,"methodIndex":1,"fieldIndex":2,
             "declaringClass":"Lcom/example/Shared;",
             "dexPc":0,"fieldType":"I","valueKind":"int","opcode":"0x59"},
            {"methodClass":"Lcom/example/Other;","methodName":"run",
             "fieldName":"value","methodIndex":2,"fieldIndex":3,
             "declaringClass":"Lcom/example/Shared;",
             "dexPc":0,"fieldType":"I","valueKind":"int","opcode":"0x59"}],
        "fieldMethods":[{"methodIndex":1,"registersSize":3},
                        {"methodIndex":2,"registersSize":2}],
    }
    cat = {"schemaVersion":1,"dexFiles":[dex],
           "totalFieldSites":2,"fixtureMethods":[]}
    filtered=select_catalog(cat,[example])
    tracker=CoverageTracker(filtered)
    assert tracker.report()["totalSelectedSites"]==1
    first=filtered["dexFiles"][0]["fieldAccesses"][0]
    tracker.observe({"dexId":0,"methodIndex":first["methodIndex"],
                     "dexPc":0,"fieldIndex":first["fieldIndex"],
                     "opcode":0x59,"fieldType":"I"})
    assert tracker.report()["observedEvents"]==1
    assert tracker.report()["observedSites"]==1
    try: tracker.observe({"dexId":0,"methodIndex":999,
                          "dexPc":0,"fieldIndex":1,"opcode":0x59,"fieldType":"I"})
    except RuntimeError:pass
    else:raise AssertionError("Unknown runtime DEX site accepted")
    assert len(filtered["dexFiles"][0]["fieldAccesses"])==1
    assert len(filtered["dexFiles"][0]["fieldMethods"])==1
    declared = parse_declared_field("Lcom/example/Shared;#count")
    assert declared == {"declaringClass":"Lcom/example/Shared;",
                        "fieldName":"count"}
    for bad in ("Lx;#field","Lcom/X;#","Lcom/X;#field#more",
                "Lcom/X;#field name","Lcom/X;"):
        try: parse_declared_field(bad)
        except ValueError: pass
        else: raise AssertionError("Malformed declaring-field selector accepted")
    multi = copy.deepcopy(cat)
    for site in multi["dexFiles"][0]["fieldAccesses"]:
        site["declaringClass"] = "Lcom/example/Shared;"
        site["fieldName"] = "count"
    filtered_multi = select_catalog_by_declared_fields(multi,[declared])
    assert filtered_multi["totalFieldSites"]==2
    assert len(filtered_multi["dexFiles"][0]["fieldMethods"])==2
    assert filtered_multi["dexFiles"][0]["fieldAccesses"][0][
        "methodClass"] != filtered_multi["dexFiles"][0]["fieldAccesses"][1][
        "methodClass"]
    assert multi["totalFieldSites"]==2
    try: select_catalog_by_declared_fields(multi,[
        parse_declared_field("Lcom/example/NotPresent;#count")])
    except ValueError: pass
    else: raise AssertionError("Unmatched declaring-field selector accepted")
    assert cat["totalFieldSites"]==2  # no mutation of caller input
    assert select_catalog(cat,None)["totalFieldSites"]==2
    overload_cat = copy.deepcopy(cat)
    overload_cat["dexFiles"][0]["fieldAccesses"][0]["methodPrototype"]="(I)J"
    overload_cat["dexFiles"][0]["fieldAccesses"].append({
        **example, "methodPrototype":"(Ljava/lang/String;)J",
        "methodIndex":3, "fieldIndex":2})
    overload_cat["dexFiles"][0]["fieldMethods"].append({
        "methodIndex":3, "registersSize":3})
    only=select_catalog(overload_cat,[overloaded])
    assert len(only["dexFiles"][0]["fieldAccesses"])==1
    assert only["dexFiles"][0]["fieldAccesses"][0]["methodIndex"]==1
    broad=select_catalog(overload_cat,[example])
    assert len(broad["dexFiles"][0]["fieldAccesses"])==2
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
    if not args.apk or not (args.profile or args.auto_profile) or (
            not args.process or not (args.thread or args.thread_regex)):
        raise ValueError("Provide --apk, --process, --thread/--thread-regex and an ART profile")
    if not args.all_fields and not args.field and not args.watch_field:
        raise ValueError(
            "Choose --field, --watch-field or --all-fields")
    if args.duration < 0 or not 50 <= args.poll_ms <= 5000:
        raise ValueError("Invalid duration/poll interval")
    selectors = ([parse_selector(item) for item in args.field]
                 if args.field else None)
    declaring_fields = ([parse_declared_field(item) for item in args.watch_field]
                        if args.watch_field else None)
    group = "allPrimitives" if args.primitives_only else "allFields"
    profile = (discover_device_profile() if args.auto_profile else
               verify_profile(json.loads(args.profile.read_text())))
    full_catalog = inventory_packages(args.apk)
    if declaring_fields is not None:
        # The runtime agent gets a narrowly scoped DEX catalog and null
        # method selectors: selected callers may differ in method name.
        catalog = select_catalog_by_declared_fields(
            full_catalog, declaring_fields)
    else:
        catalog = select_catalog(full_catalog, selectors)
    if not catalog["totalFieldSites"]:
        raise ValueError("No field instructions were found in the APK")
    thread_selection=('regex:'+args.thread_regex
                      if args.thread_regex is not None else args.thread)
    if args.thread_regex is not None:
        try: re.compile(args.thread_regex)
        except re.error as e:
            raise ValueError("Invalid thread selection regex") from e
    source=assemble_agent(catalog,profile,selectors,thread_selection,group)

    # Frida is imported only when actually running on a connected device;
    # static/unit tests do not require the mobile SDK or live device.
    import frida
    device=frida.get_usb_device(timeout=30)
    session=None
    script=None
    spawned=None
    resumed=False
    stopped=False
    errors=[]
    produced=0
    target=args.process if not args.process.isdigit() else int(args.process)
    stream=open(args.output,"w",encoding="utf-8") if args.output else sys.stdout
    coverage=CoverageTracker(catalog,include_object=not args.primitives_only)

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
                coverage.observe(event)
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
              f"sites, group={group}, thread={thread_selection}; "
              "nterp-only; no JIT/AOT coverage", file=sys.stderr,flush=True)
        started=time.monotonic()
        while not args.duration or time.monotonic()-started<args.duration:
            time.sleep(args.poll_ms/1000)
            drain()
            if errors:
                raise RuntimeError("Frida errors: "+"; ".join(errors))
            if args.max_events and produced>=args.max_events:
                break
        # Stop the observer BEFORE the final drain so no completed field
        # event can arrive after the host believes its JSONL stream ended.
        cleanup=script.exports_sync.stop()
        stopped=True
        if cleanup.get("failures"):
            raise RuntimeError("Could not stop all followed threads cleanly")
        drain()
        state=script.exports_sync.snapshot()
        if state.get("totalRecorded")!=produced:
            raise RuntimeError("Agent/host event count mismatch after final drain")
        print("ART fieldwatch summary: "+json.dumps({
            key:state.get(key) for key in (
                "threadsFollowed","fieldHits","completedHits",
                "unverifiedSites","dropped","totalRecorded","abandonedFieldAttempts")
        },sort_keys=True),file=sys.stderr,flush=True)
        return 0
    except KeyboardInterrupt:
        if script is not None:
            cleanup=script.exports_sync.stop()
            stopped=True
            if cleanup.get("failures"):
                raise RuntimeError("Could not stop all followed threads cleanly")
            drain()
        return 0
    finally:
        if script is not None and not stopped:
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
        if args.coverage_output:
            args.coverage_output.write_text(
                json.dumps(coverage.report(),indent=2,sort_keys=True)+"\n",
                encoding="utf-8")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--apk",type=Path,action="append",
                        help="Exact base APK; repeat for split APKs in order")
    profile_args=parser.add_mutually_exclusive_group()
    profile_args.add_argument("--profile",type=Path,
                              help="Prevalidated ART nterp ELF profile JSON")
    profile_args.add_argument("--auto-profile",action="store_true",
                              help="Pull installed libart ELF and verify its exact ABI")
    parser.add_argument("--process",help="Existing process name/PID or spawn package")
    thread_selection=parser.add_mutually_exclusive_group()
    thread_selection.add_argument("--thread",
                                  help="Exact thread name, or * for all threads")
    thread_selection.add_argument("--thread-regex",
                                  help="Match worker thread names by JS RegExp")
    selection=parser.add_mutually_exclusive_group()
    selection.add_argument("--field",action="append",
                           help="CallerClass#method[(paramTypes)returnType]#field")
    selection.add_argument("--watch-field",action="append",
                           help="DeclaringClass#fieldName across all DEX callers")
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
    parser.add_argument("--coverage-output",type=Path,
                        help="Write observed DEX field-site report (not execution coverage)")
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
