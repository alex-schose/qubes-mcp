#!/usr/bin/env python3
"""Seat suite: the M1 tools against a real dom0, from the hub.

Run it IN the hub qube, from the public tree:

    PYTHONPATH=. python3 tests/seat_suite.py [--keep]

Every call goes through the shipped client (qubes_mcp.tools, the same code the
MCP server and the CLI use) and real qrexec, so it proves the whole chain:
client, policy, dom0 library, platform.

Fixtures are named `ai-st<run id>-*`. The suite refuses to start if any such
qube exists, and removes only what it created. Another session may share the
box and its fixture names; this never touches theirs.

Reports PASS / FAIL / NOT-RUN per check and exits 0 GREEN, 2 FAILED,
3 INCOMPLETE. INCOMPLETE is not green.

Copies between the hub's own qubes (p00) need no dialog, and the suite copies
between two of them. Other copies out of AI space need the operator's dialog,
so the suite asserts only the dialog-free paths: a copy into a guarded qube is
refused without one. The dialog path itself is covered by tests/test_policy.py.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import random
import statistics
import string
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from qubes_mcp import tools  # noqa: E402

RUN = "".join(random.choice(string.ascii_lowercase) for _ in range(4))
PREFIX = f"ai-hub-st{RUN}"
TEMPLATE = os.environ.get("QMCP_SEAT_TEMPLATE", "ai-debian-13")
GUARDED_QUBE = os.environ.get("QMCP_SEAT_GUARDED", "ai-net-router")
OUTSIDE_QUBE = os.environ.get("QMCP_SEAT_OUTSIDE", "sys-net")

results: list = []
created: list = []


def call(tool, **args):
    t = tools.TOOLS[tool]
    return t.handler(tools.validate_arguments(t, args))


def check(name, ok, detail=""):
    results.append(("PASS" if ok else "FAIL", name, detail))
    print(f"{'PASS' if ok else 'FAIL':7s} {name}" + (f"  -- {detail}" if detail and not ok else ""), flush=True)
    return ok


def not_run(name, why):
    results.append(("NOT-RUN", name, why))
    print(f"NOT-RUN {name}  -- {why}", flush=True)


def spawn(suffix, **kw):
    name = f"{PREFIX}-{suffix}"
    r = call("qubes_spawn", name=name, template=kw.pop("template", TEMPLATE), **kw)
    if r.get("ok"):
        created.append(name)
    return name, r


#: The gateways the operator enrolled, read from the hub's pool stats.
ENROLLED: set = set()


def main() -> int:
    keep = "--keep" in sys.argv
    t0 = time.monotonic()

    # ---------------------------------------------------------------- listing
    r = call("qubes_list")
    if not check("list answers", r.get("ok") is True, json.dumps(r)[:200]):
        return report(t0)
    by = {q["name"]: q for q in r["qubes"]}
    if any(n.startswith(PREFIX) for n in by):
        check("fixture names are free", False, f"something already uses {PREFIX}-*; aborting")
        return report(t0)
    check("template is listed managed", by.get(TEMPLATE, {}).get("guarded") is False, str(by.get(TEMPLATE)))
    check("gateway is listed guarded", by.get(GUARDED_QUBE, {}).get("guarded") is True, str(by.get(GUARDED_QUBE)))
    check("hub and operator qubes are not listed",
          "mcp-control" not in by and OUTSIDE_QUBE not in by and "dom0" not in by)

    # ---------------------------------------------------------------- the registry
    stats = call("qubes_get_pool_stats")
    gws = stats.get("gateways") if stats.get("ok") else None
    if not check("the hub reads the gateway registry", isinstance(gws, list) and bool(gws),
                 json.dumps(stats)[:300]):
        return report(t0)
    ENROLLED.update(g["name"] for g in gws)
    r = call("qubes_spawn", name="ai-st-outside", template=TEMPLATE)
    check("a name outside the hub's own space is refused", "ai-hub-" in str(r.get("error")),
          json.dumps(r))
    r = call("qubes_spawn", name=f"{PREFIX}-x", template=TEMPLATE, netvm=OUTSIDE_QUBE)
    check("a network that is not enrolled is refused", "enrolled gateway" in str(r.get("error")),
          json.dumps(r))

    # ---------------------------------------------------------------- reads / oracle
    a = call("qubes_props_get", name=OUTSIDE_QUBE, properties=["memory"])
    b = call("qubes_props_get", name="no-such-qube-zz", properties=["memory"])
    check("out of scope reads like nonexistent", a == b and a.get("ok") is False, f"{a} vs {b}")
    r = call("qubes_props_get", name=GUARDED_QUBE, properties=["netvm", "tags"])
    check("a guarded qube is readable, outside names redacted",
          r.get("ok") and r["values"].get("netvm") == "<out-of-scope>"
          and r["values"].get("tags") == ["ai-managed", "qmcp-guarded"], json.dumps(r))

    # ---------------------------------------------------------------- creates
    r = call("qubes_spawn", name="not-in-prefix-zz", template=TEMPLATE)
    check("a name outside the prefix is refused", "reserved" in str(r.get("error")), json.dumps(r))
    w, r = spawn("w1")
    if not check("spawn an AppVM from the managed template", r.get("ok") is True, json.dumps(r)):
        return report(t0, keep)
    r = call("qubes_props_get", name=w, properties=["tags", "netvm", "default_dispvm", "template"])
    v = r.get("values", {})
    check("born managed, provenance hidden", v.get("tags") == ["ai-managed"], json.dumps(r))
    check("born on an enrolled network", v.get("netvm") not in (None, "<out-of-scope>")
          and v.get("netvm") in ENROLLED, json.dumps(r) + f" enrolled={sorted(ENROLLED)}")
    check("default_dispvm pinned to none", v.get("default_dispvm") is None, json.dumps(r))
    r = call("qubes_spawn", name=w, template=TEMPLATE)
    check("collision inside the prefix", "already exists" in str(r.get("error")), json.dumps(r))

    # ---------------------------------------------------------------- writes
    check("set memory", call("qubes_props_set", name=w, property="memory", value=600) == {"ok": True})
    r = call("qubes_props_set", name=w, property="template", value=TEMPLATE)
    check("template is operator-only", r.get("error") == "property not settable", json.dumps(r))
    r = call("qubes_props_set", name=w, property="netvm", value=GUARDED_QUBE)
    check("netvm can only be cleared", "operator-only" in str(r.get("error")), json.dumps(r))
    r = call("qubes_feature_set", name=w, feature="service.cups", value=True)
    check("allowed feature", r == {"ok": True, "feature": "service.cups", "value": "1"}, json.dumps(r))
    for key in ("preload-dispvm-max", "internal", "guivm"):
        r = call("qubes_feature_set", name=w, feature=key, value="1")
        check(f"feature {key} refused", r.get("error") == "feature not settable", json.dumps(r))

    # ---------------------------------------------------------------- guarded
    r = call("qubes_start", name=GUARDED_QUBE)
    check("lifecycle on a guarded qube refused", r.get("error") == "guarded: reference only", json.dumps(r))
    r = call("qubes_run", name=GUARDED_QUBE, cmd=["true"])
    check("exec into a guarded qube refused by policy", r == {"ok": False, "error": "not found or refused"},
          json.dumps(r))
    r = call("qubes_firewall_set", name=GUARDED_QUBE, rules="action=accept\n")
    check("firewall write on a guarded qube refused", r.get("ok") is False, json.dumps(r))

    # ---------------------------------------------------------------- run, events
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        ev = pool.submit(call, "qubes_events", duration=60, qube=w, events=["domain-start"])
        time.sleep(2)
        r = call("qubes_start", name=w)
        check("start", r == {"ok": True}, json.dumps(r))
        events = ev.result()
    check("events saw the start", any(e.get("event") == "domain-start" for e in events.get("events", [])),
          json.dumps(events)[:300])
    r = call("qubes_run", name=w, cmd=["id", "-u"], timeout=60)
    check("exec as root in the managed qube", r.get("ok") and r.get("stdout", "").strip() == "0", json.dumps(r))
    r = call("qubes_firewall_get", name=w)
    check("firewall read", r.get("ok") is True, json.dumps(r))
    r = call("qubes_firewall_set", name=w, rules="action=accept\n", reload=True)
    check("firewall write", r.get("ok") is True, json.dumps(r))
    # A file that exists, so the refusal is the policy's and not a missing
    # path's (until 0.9.18 this used /etc/hostname, which Qubes qubes lack).
    src = "/home/user/qmcp-seat-copy.txt"
    call("qubes_run", name=w, cmd=f"echo seat-{RUN} > {src}", shell=True, timeout=30)
    r = call("qubes_copy", source=w, target=GUARDED_QUBE, path=src, timeout=60)
    check("copy into a guarded qube refused, no dialog",
          r.get("ok") is False and "does not exist" not in str(r.get("error")), json.dumps(r))

    # ---------------------------------------------------------------- clone, and templates the hub builds
    c = f"{PREFIX}-c1"
    call("qubes_shutdown", name=w)
    for _ in range(30):
        if call("qubes_state", name=w).get("power_state") == "Halted":
            break
        time.sleep(2)
    r = call("qubes_clone", source=w, name=c)
    if check("clone a managed qube", r.get("ok") is True, json.dumps(r)):
        created.append(c)
        r = call("qubes_props_get", name=c, properties=["tags"])
        check("the clone is managed", r.get("values", {}).get("tags") == ["ai-managed"], json.dumps(r))
    r = call("qubes_clone", source=GUARDED_QUBE, name=f"{PREFIX}-gc")
    check("clone of a guarded qube refused", r.get("error") == "guarded: reference only", json.dumps(r))
    # The hub's own AppVMs share p00: a copy between them needs no dialog.
    if c in created:
        call("qubes_start", name=w)
        r = call("qubes_copy", source=w, target=c, path=src, timeout=120)
        check("copy between two of the hub's p00 qubes, no dialog", r.get("ok") is True, json.dumps(r))
        call("qubes_shutdown", name=c)

    # ---------------------------------------------------------------- disposables
    d, r = spawn("dvm", klass="DispVMTemplate")
    if check("the hub builds a disposable template", r.get("ok") is True, json.dumps(r)):
        timings = []
        for i in range(2):
            t = time.monotonic()
            r = call("qubes_run_disposable", template=d, cmd=["id", "-u"], timeout=120)
            timings.append(time.monotonic() - t)
            check(f"run_disposable #{i + 1}", r.get("ok") and r.get("stdout", "").strip() == "0", json.dumps(r))
        print(f"INFO    run_disposable wall time: {', '.join(f'{x:.1f}s' for x in timings)}", flush=True)
    gd = os.environ.get("QMCP_SEAT_GUARDED_DVM")
    if gd:
        r = call("qubes_spawn_disposable", template=gd)
        if check("disposable from a guarded template (reference use)", r.get("ok") is True, json.dumps(r)):
            created.append(r["name"])
            r2 = call("qubes_props_get", name=r["name"], properties=["tags"])
            check("that disposable is managed", r2.get("values", {}).get("tags") == ["ai-managed"], json.dumps(r2))
    else:
        not_run("disposable from a guarded template", "set QMCP_SEAT_GUARDED_DVM to a guarded DVMT")

    # ---------------------------------------------------------------- name oracle timing
    t_out, t_col = [], []
    for _ in range(5):
        t = time.monotonic(); call("qubes_spawn", name="zz-outside", template=TEMPLATE); t_out.append(time.monotonic() - t)
        t = time.monotonic(); call("qubes_spawn", name=w, template=TEMPLATE); t_col.append(time.monotonic() - t)
    print(f"INFO    refusal latency, median: outside prefix {statistics.median(t_out)*1000:.0f} ms, "
          f"collision inside {statistics.median(t_col)*1000:.0f} ms", flush=True)

    r = call("qubes_get_pool_stats")
    check("pool stats: the hub's own names and the reserved prefix",
          r.get("ok") is True and r["ai_managed_bytes_cap"] > 0 and bool(r.get("reserved_prefix"))
          and r.get("name_prefix") == f"{r['reserved_prefix']}hub-", json.dumps(r)[:300])
    return report(t0, keep)


def cleanup():
    for name in reversed(created):
        call("qubes_shutdown", name=name, force=True)
    time.sleep(5)
    for name in reversed(created):
        r = call("qubes_remove", name=name)
        if not r.get("ok") and "disp" not in name:
            print(f"WARN    could not remove {name}: {r}", flush=True)


def report(t0, keep=False) -> int:
    if not keep:
        cleanup()
    else:
        print(f"INFO    --keep: left {created}", flush=True)
    fails = [r for r in results if r[0] == "FAIL"]
    missing = [r for r in results if r[0] == "NOT-RUN"]
    verdict = "FAILED" if fails else ("INCOMPLETE" if missing or not results else "GREEN")
    print(f"\nseat suite: {verdict}  ({len(results)} checks, {len(fails)} failed, "
          f"{len(missing)} not run, {time.monotonic() - t0:.0f}s)")
    return {"GREEN": 0, "FAILED": 2, "INCOMPLETE": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
