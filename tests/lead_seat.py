#!/usr/bin/env python3
"""Lead seat: projects from inside a project's lead, against a real dom0.

Run it IN A LEAD, from the public tree (tests/project_suite.py ships it there
from the hub and starts it):

    PYTHONPATH=. python3 tests/lead_seat.py --other QUBE [--other QUBE ...]
        [--guarded QUBE] [--hub NAME] [--keep]

`--other` names qubes this lead must not see or reach: one of the hub's
qubes, another project's lead or worker, a qube outside AI space. Each must
read exactly like a name that does not exist, and the rulebook must refuse
running a command in it. `--guarded` is a guarded qube in AI space.

Every call goes through the shipped client and real qrexec, so the chain is
the lead's own: the client, the lead's slot lines in the policy, the dom0
library reading the lead's project record, the platform. Then the suite runs
probes as root inside its own workers, the way a compromised worker would.

The project should have a quota of 11 GiB, two named worker networks, an
approved disposable template, and nothing in it yet; the suite
reads its prefix, templates, networks and dump sink from qubes_get_pool_stats.
Fixtures are named `<project prefix>st<run id>-*`; the suite refuses to start
if any such qube exists and removes only what it created.

Reports PASS / FAIL / NOT-RUN / INFO and exits 0 GREEN, 2 FAILED,
3 INCOMPLETE. INCOMPLETE is not green.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shlex
import statistics
import string
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from qubes_mcp import tools  # noqa: E402

CLIENT = "/usr/lib/qubes/qrexec-client-vm"
GiB = 1024 ** 3
RUN = "".join(random.choice(string.ascii_lowercase) for _ in range(3))
results: list = []
created: list = []


def call(tool, **args):
    t = tools.TOOLS[tool]
    return t.handler(tools.validate_arguments(t, args))


def check(name, ok, detail=""):
    results.append(("PASS" if ok else "FAIL", name))
    print(f"{'PASS' if ok else 'FAIL':7s} {name}" + (f"  -- {detail}" if detail and not ok else ""), flush=True)
    return ok


def not_run(name, why):
    results.append(("NOT-RUN", name))
    print(f"NOT-RUN {name}  -- {why}", flush=True)


def info(text):
    print(f"INFO    {text}", flush=True)


def raw(target, service, payload=b"", timeout=30):
    """(rc, stdout) of one qrexec call from this lead, bypassing the client."""
    try:
        p = subprocess.run([CLIENT, target, service], input=payload, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return None, b""


def refused_raw(name, target, service, payload=b""):
    rc, out = raw(target, service, payload)
    if rc is None:
        return check(name, False, "HUNG: a dialog may be waiting")
    return check(name, rc != 0 and not out.strip(), f"rc={rc} out={out[:120]!r}")


def wait_power(name, want, tries=30):
    for _ in range(tries):
        if call("qubes_state", name=name).get("power_state") == want:
            return True
        time.sleep(2)
    return False


def worker_probes(worker, lead, peer, hub, others):
    """Root inside a worker, against the lead, dom0, the hub and other qubes."""
    probes = [
        ("CONTROL: an allowed call from the worker succeeds", "@default", "qubes.GetDate", True),
        ("worker copies a file to its lead", lead, "qubes.Filecopy", False),
        ("worker opens a URL in its lead", lead, "qubes.OpenURL", False),
        ("worker drives exec in its lead", lead, "qmcp.RunInAIManaged", False),
        ("worker calls a qmcp service", "dom0", "qmcp.ListAIManagedQubes", False),
        ("worker calls the Admin API", "dom0", "admin.vm.List", False),
        ("worker raw @dispvm shell", "@dispvm", "qubes.VMShell", False),
        ("worker reaches the hub", hub, "qubes.OpenURL", False),
        ("worker drives exec in a peer", peer, "qmcp.RunInAIManaged", False),
    ] + [(f"worker drives exec in {o}", o, "qmcp.RunInAIManaged", False) for o in others]
    lines = ["set +e"]
    for i, (_, target, svc, _) in enumerate(probes):
        lines.append(f"timeout 25 {CLIENT} {shlex.quote(target)} {shlex.quote(svc)} </dev/null "
                     f">/tmp/p{i}.out 2>/dev/null; echo \"P{i} rc=$? bytes=$(wc -c </tmp/p{i}.out)\"")
    r = call("qubes_run", name=worker, cmd="\n".join(lines), shell=True, timeout=400)
    if not check("run the probes inside a worker", r.get("ok") is True, json.dumps(r)[:200]):
        return
    got = {}
    for line in r.get("stdout", "").splitlines():
        if line.startswith("P"):
            tag, rc, size = line.split()
            got[int(tag[1:])] = (int(rc.split("=")[1]), int(size.split("=")[1]))
    for i, (label, _, _, allowed) in enumerate(probes):
        rc, size = got.get(i, (None, None))
        if allowed:
            check(label, rc == 0 and (size or 0) > 0, f"rc={rc} bytes={size}")
        elif rc == 124:
            check(label, False, "HUNG: a dialog may be waiting")
        else:
            check(label, rc not in (None, 0) and size == 0, f"rc={rc} bytes={size}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--other", action="append", default=[])
    ap.add_argument("--guarded", default=os.environ.get("QMCP_SEAT_GUARDED", "ai-net-router"))
    ap.add_argument("--hub", default="mcp-control")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    t0 = time.monotonic()
    lead = os.uname().nodename

    # ------------------------------------------------------------ the project
    stats = call("qubes_get_pool_stats")
    if not check("pool stats answer with the project", stats.get("ok") is True and "project" in stats,
                 json.dumps(stats)[:300]):
        return report(t0, args.keep)
    prefix, templates = stats["name_prefix"], stats["templates"]
    networks, dump = stats["networks"], stats["dump"]
    info(f"project {stats['project']}: prefix {prefix}, templates {templates}, networks {networks}, "
         f"dump {dump}, quota {stats['ai_managed_bytes_cap'] / GiB:.1f} GiB")
    base = f"{prefix}st{RUN}"
    appvm_template = next((t for t in templates if not call("qubes_props_get", name=t,
                           properties=["template_for_dispvms"]).get("values", {}).get("template_for_dispvms")),
                          None)
    dvmt = next((t for t in templates if t != appvm_template and call("qubes_props_get", name=t,
                 properties=["template_for_dispvms"]).get("values", {}).get("template_for_dispvms")), None)

    r = call("qubes_list")
    if not check("list answers", r.get("ok") is True, json.dumps(r)[:200]):
        return report(t0, args.keep)
    by = {q["name"]: q for q in r["qubes"]}
    if any(n.startswith(base) for n in by):
        check("fixture names are free", False, f"{base}-* exists; aborting")
        return report(t0, args.keep)
    named_nets = [n for n in networks if n]
    slots = {q["slot"] for q in by.values() if q["slot"]}
    stray = sorted(n for n, q in by.items()
                   if q["slot"] is None and n not in templates and n not in named_nets)
    check("the list holds only the project, its templates and its networks",
          not stray and len(slots) <= 1, f"stray {stray}, slots {sorted(slots)}")
    check("no other principal's qube is listed", not (set(args.other) | {args.hub, lead}) & set(by),
          str(sorted(set(args.other) & set(by))))

    # ------------------------------------------------------------ nothing outside reads
    missing = call("qubes_props_get", name=f"{prefix}zz-no-such", properties=["memory"])
    for other in args.other:
        r = call("qubes_props_get", name=other, properties=["memory"])
        check(f"{other} reads like a name that does not exist", r == missing and r.get("ok") is False,
              f"{r} vs {missing}")
    # The rulebook has no event line for leads, so the call never reaches dom0.
    r = call("qubes_events", duration=1)
    check("no event stream for a lead (refused by the rulebook)",
          r == {"ok": False, "error": "not found or refused"}, json.dumps(r))

    # ------------------------------------------------------------ creates
    r = call("qubes_spawn", name="ai-zz-outside", template=appvm_template)
    check("a name outside the project's prefix is refused", "must start with" in str(r.get("error")),
          json.dumps(r))
    # Refused on the list alone, before any lookup, so any name off it will do.
    r = call("qubes_spawn", name=f"{base}-x", template="zz-not-approved")
    check("a template off the approved list is refused", "approved list" in str(r.get("error")),
          json.dumps(r))
    r = call("qubes_spawn", name=f"{base}-x", template=appvm_template, klass="DispVMTemplate")
    check("a lead cannot build a disposable template", "klass must be one of" in str(r.get("error")),
          json.dumps(r))
    r = call("qubes_spawn", name=f"{base}-x", template=appvm_template, netvm="zz-not-listed")
    check("a network off the project's list is refused", "worker networks" in str(r.get("error")),
          json.dumps(r))

    w1, w2 = f"{base}-w1", f"{base}-w2"
    r = call("qubes_spawn", name=w1, template=appvm_template)
    if not check("spawn a worker", r.get("ok") is True, json.dumps(r)):
        return report(t0, args.keep)
    created.append(w1)
    r = call("qubes_props_get", name=w1, properties=["tags", "netvm", "default_dispvm"])
    v = r.get("values", {})
    check("the worker is born on the project's default network", v.get("netvm") == networks[0], json.dumps(r))
    check("the worker's badges stay hidden", v.get("tags") == ["ai-managed"], json.dumps(r))
    check("default_dispvm pinned to none", v.get("default_dispvm") is None, json.dumps(r))
    # A just-created qube must be reachable by the lead's slot line at once (#10911).
    t = time.monotonic()
    first = call("qubes_run", name=w1, cmd=["id", "-u"], timeout=120)
    info(f"first exec after create: {'ok' if first.get('ok') else first} "
         f"in {time.monotonic() - t:.1f}s (starts the worker)")
    if not first.get("ok"):
        time.sleep(3)
        first = call("qubes_run", name=w1, cmd=["id", "-u"], timeout=120)
        info(f"retry: {'ok' if first.get('ok') else first}")
    check("exec as root in the lead's own worker", first.get("ok") and first.get("stdout", "").strip() == "0",
          json.dumps(first)[:200])
    r = call("qubes_spawn", name=w2, template=appvm_template, netvm=None)
    if check("spawn an offline worker", r.get("ok") is True, json.dumps(r)):
        created.append(w2)
    if len(named_nets) > 1:
        r = call("qubes_spawn", name=f"{base}-w3", template=appvm_template, netvm=named_nets[1])
        if check("spawn on the second listed network", r.get("ok") is True, json.dumps(r)):
            created.append(f"{base}-w3")
    else:
        not_run("spawn on the second listed network", "the project lists one named network")

    # ------------------------------------------------------------ operating the workers
    check("set memory on a worker",
          call("qubes_props_set", name=w1, property="memory", value=600) == {"ok": True})
    r = call("qubes_firewall_get", name=w1)
    check("firewall read on a worker", r.get("ok") is True, json.dumps(r)[:200])
    r = call("qubes_firewall_set", name=w1, rules="action=accept\n", reload=True)
    check("firewall write on a worker", r.get("ok") is True, json.dumps(r)[:200])
    call("qubes_start", name=w2)
    wait_power(w2, "Running")
    # A file that exists: a missing path fails before any copy is attempted.
    src = "/tmp/qmcp-lead-seat.txt"
    call("qubes_run", name=w1, cmd=f"echo lead-seat-{RUN} > {src}", shell=True, timeout=30)
    r = call("qubes_copy", source=w1, target=w2, path=src, timeout=60)
    check("copy between the project's workers, no dialog", r.get("ok") is True, json.dumps(r)[:200])
    r = call("qubes_run", name=w2, cmd=["cat", f"/home/user/QubesIncoming/{w1}/qmcp-lead-seat.txt"], timeout=30)
    check("the copy arrived", r.get("stdout", "").strip() == f"lead-seat-{RUN}", json.dumps(r)[:200])
    if dump:
        r = call("qubes_copy", source=w1, target=dump, path=src, timeout=60)
        check("copy into the project's dump sink, no dialog", r.get("ok") is True, json.dumps(r)[:200])
    else:
        not_run("copy into the dump sink", "the project has no dump sink")
    for other in args.other:
        r = call("qubes_run", name=other, cmd=["true"], timeout=30)
        check(f"exec in {other} refused by the rulebook", r == {"ok": False, "error": "not found or refused"},
              json.dumps(r)[:200])
        r = call("qubes_start", name=other)
        check(f"lifecycle on {other} refused", r.get("ok") is False, json.dumps(r)[:200])
    r = call("qubes_run", name=args.guarded, cmd=["true"], timeout=30)
    check("exec in a guarded qube refused", r.get("ok") is False, json.dumps(r)[:200])

    # ------------------------------------------------------------ worker probes
    worker_probes(w1, lead, w2, args.hub, args.other)

    # ------------------------------------------------------------ raw from the lead
    rc, out = raw("@adminvm", "qmcp.GetPoolStats")
    check("CONTROL: the lead's own call succeeds raw", rc == 0 and b'"ok": true' in out, f"rc={rc}")
    refused_raw("raw admin.vm.List from the lead", "@adminvm", "admin.vm.List")
    refused_raw("raw policy.Get from the lead", "@adminvm", "policy.Get")
    refused_raw("raw event stream from the lead", "@adminvm", "qmcp.AIManagedEvents", b'{"duration": 1}')
    refused_raw("raw proposal from the lead", "@adminvm", "qmcp.SubmitProposal",
                b'{"type":"project-delete","title":"x","project":"p01"}')
    refused_raw("raw proposal states from the lead", "@adminvm", "qmcp.ProposalStatus", b"{}")
    refused_raw("raw tag.Set on its own worker", w1, "admin.vm.tag.Set+qmcp-lead")
    refused_raw("raw exec into the hub", args.hub, "qmcp.RunInAIManaged", b'{"cmd":["true"]}')
    refused_raw("raw exec into a guarded qube", args.guarded, "qmcp.RunInAIManaged", b'{"cmd":["true"]}')
    rc, out = raw("@adminvm", "qmcp.SetPropertyAIManaged", b'{"name":"' + b"x" * 70000 + b'"}')
    check("an oversized request is refused before parsing", b"request too large" in out, f"{out[:120]!r}")

    # ------------------------------------------------------------ clone, disposables, quota
    call("qubes_shutdown", name=w1)
    wait_power(w1, "Halted")
    # The clone first: a disposable's removal lags its shutdown, and its disk
    # counts against the quota until it is gone.
    c1 = f"{base}-c1"
    r = call("qubes_clone", source=w1, name=c1)
    if check("clone a worker", r.get("ok") is True, json.dumps(r)):
        created.append(c1)
    if dvmt:
        r = call("qubes_run_disposable", template=dvmt, cmd=["id", "-u"], timeout=120)
        check("run in a disposable from an approved disposable template",
              r.get("ok") and r.get("stdout", "").strip() == "0", json.dumps(r)[:200])
    else:
        not_run("disposable from an approved template", "no disposable template on the list")
    # Sized past the quota but under the per-qube cap (10 GiB by default), so
    # only the quota can refuse it; with more headroom than that, no probe can.
    stats = call("qubes_get_pool_stats")
    over = stats.get("ai_managed_bytes_headroom", 0) + GiB
    if over > 8 * GiB:
        not_run("a create past the project's quota is refused",
                f"{over / GiB:.0f} GiB would also pass the per-qube cap; give the project less headroom")
    else:
        r = call("qubes_spawn", name=f"{base}-big", template=appvm_template, private_size=over)
        check("a create past the project's quota is refused", r.get("error") == "project quota exceeded",
              json.dumps(r))

    # ------------------------------------------------------------ the name oracle, timed
    samples = {"missing": [], **{o: [] for o in args.other}}
    order = [k for k in samples for _ in range(25)]
    random.shuffle(order)
    for k in order:
        name = f"{prefix}zz-no-such" if k == "missing" else k
        t = time.monotonic()
        call("qubes_props_get", name=name, properties=["memory"])
        samples[k].append(time.monotonic() - t)
    medians = {k: statistics.median(v) * 1000 for k, v in samples.items()}
    info("not-found latency, median ms: " + ", ".join(f"{k} {v:.1f}" for k, v in medians.items()))
    # Control: the calls really reached dom0 (a qrexec round trip is tens of ms),
    # so a small spread is a measurement and not a client that answered alone.
    if check("the timed calls reached dom0", medians["missing"] > 20, f"{medians['missing']:.1f} ms"):
        spread = max(abs(v - medians["missing"]) for k, v in medians.items() if k != "missing")
        # The 0.9.x tell this guards against was about 50 ms (68 vs 118 ms).
        check("a foreign name costs what a missing one costs (within 10 ms)", spread < 10,
              f"spread {spread:.1f} ms")
    return report(t0, args.keep)


def cleanup():
    for name in reversed(created):
        call("qubes_shutdown", name=name, force=True)
    time.sleep(5)
    for name in reversed(created):
        r = call("qubes_remove", name=name)
        if not r.get("ok"):
            print(f"WARN    could not remove {name}: {r}", flush=True)


def report(t0, keep=False) -> int:
    if keep:
        info(f"--keep: left {created}")
    else:
        cleanup()
    fails = [r for r in results if r[0] == "FAIL"]
    missing = [r for r in results if r[0] == "NOT-RUN"]
    verdict = "FAILED" if fails else ("INCOMPLETE" if missing or not results else "GREEN")
    print(f"\nlead seat: {verdict}  ({len(results)} checks, {len(fails)} failed, "
          f"{len(missing)} not run, {time.monotonic() - t0:.0f}s)", flush=True)
    return {"GREEN": 0, "FAILED": 2, "INCOMPLETE": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
