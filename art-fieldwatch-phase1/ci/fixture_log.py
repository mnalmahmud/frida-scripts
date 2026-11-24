"""Validate completion markers from the repository's own Android test APK."""
import re

TAG = re.compile(r"\b[VDIWEF]\s+ARTWATCH_CI\s*:\s*(.*)$")


def validate(log, variant, native_fixture, injection):
    messages = [m.group(1).strip() for line in log.splitlines()
                if (m := TAG.search(line))]
    if any(m.startswith(("WARMUP_FAILED", "SHADOW_LIB_LOAD_FAILED"))
           for m in messages):
        raise AssertionError("APK reported a failure")
    expected = [("APP_DEBUGGABLE=", "APP_DEBUGGABLE=" +
                 ("true" if variant == "debug" else "false"))]
    if native_fixture:
        expected.extend([
            ("SHADOW_LIB_LOADED=", "SHADOW_LIB_LOADED=true"),
            ("EVENT_LIB_LOADED=", "EVENT_LIB_LOADED=true"),
        ])
    if variant == "release":
        stages = [m for m in messages if m.startswith("LSE_STAGE_DONE=")]
        if stages != [f"LSE_STAGE_DONE={i}" for i in range(5)]:
            raise AssertionError(f"Unexpected release stages: {stages}")
        expected.extend((f"LSE_STAGE_DONE={i}", f"LSE_STAGE_DONE={i}")
                        for i in range(5))
    if native_fixture:
        expected.extend([
            ("P3_TEMPLATE_DONE", "P3_TEMPLATE_DONE count=" +
             ("256" if injection else "0") +
             " checksum=25280 nullCheck=true injected=" +
             ("true" if injection else "false")),
            ("P3_CANARY_DONE", "P3_CANARY_DONE count=0 checksum=25280 nullCheck=true"),
            ("RUNTIME_EVENTS_DONE", "RUNTIME_EVENTS_DONE count=256 checksum=25280 nullCheck=true"),
            ("DIRECT_ABI_DONE", "DIRECT_ABI_DONE count=4 checksum=103"),
            ("PRIMITIVE_ABI_DONE", "PRIMITIVE_ABI_DONE count=14 checksum=61"),
        ])
    expected.append(("WARMUP_DONE", r"WARMUP_DONE checksum=-?\d+"))
    last = -1
    for prefix, pattern in expected:
        found = [(i, m) for i, m in enumerate(messages) if m.startswith(prefix)]
        if len(found) != 1:
            raise AssertionError(f"Expected exactly one {prefix} marker, got {found}")
        i, message = found[0]
        if i <= last or re.fullmatch(pattern, message) is None:
            raise AssertionError(f"Malformed or out-of-order fixture marker: {message}")
        last = i


def self_test():
    messages = [
        "APP_DEBUGGABLE=false", "SHADOW_LIB_LOADED=true", "EVENT_LIB_LOADED=true",
        *[f"LSE_STAGE_DONE={i}" for i in range(5)],
        "P3_TEMPLATE_DONE count=256 checksum=25280 nullCheck=true injected=true",
        "P3_CANARY_DONE count=0 checksum=25280 nullCheck=true",
        "RUNTIME_EVENTS_DONE count=256 checksum=25280 nullCheck=true",
        "DIRECT_ABI_DONE count=4 checksum=103",
        "PRIMITIVE_ABI_DONE count=14 checksum=61", "WARMUP_DONE checksum=123",
    ]

    def log(rows):
        return "\n".join("11-23 23:21:40.000  100  101 I ARTWATCH_CI: " + m
                         for m in rows)

    validate(log(messages), "release", True, True)
    validate(log(["APP_DEBUGGABLE=true", "WARMUP_DONE checksum=1"]),
             "debug", False, False)
    for invalid in (
        messages[:-1],
        messages + [messages[-1]],
        messages[:9] + messages[10:11] + messages[9:10] + messages[11:],
        [m.replace("RUNTIME_EVENTS_DONE count=256", "RUNTIME_EVENTS_DONE count=2560")
         for m in messages],
        [m.replace("nullCheck=true", "nullCheck=false")
         if m.startswith("RUNTIME_EVENTS_DONE") else m for m in messages],
        messages + ["WARMUP_FAILED"],
    ):
        try:
            validate(log(invalid), "release", True, True)
        except AssertionError:
            pass
        else:
            raise AssertionError("Invalid fixture log was accepted")
    print("Fixture completion marker self-test passed")


if __name__ == "__main__":
    self_test()
