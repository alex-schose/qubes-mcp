#!/usr/bin/env python3
"""Red-team suite: try to get past M1 from the hub and from inside AI space.

Run it IN the hub qube, from the public tree:

    PYTHONPATH=. python3 tests/redteam_suite.py --inside <managed qube> [--peer QUBE]
        [--lead LEAD] [--model-qube QUBE]

Two vantage points:

- the hub, calling qrexec directly and skipping every check the client makes,
  as a compromised hub process would;
- a managed qube, as root (reached with qubes_run), as a prompt-injected or
  compromised workload would.

Every probe is expected to be REFUSED and to be refused WITHOUT a dialog: an
`ask` here would wait for a human, so each probe runs under a timeout and a
probe that hangs is reported as a failure, not a pass. Exits 0 GREEN, 2 FAILED,
3 INCOMPLETE.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from qubes_mcp import tools  # noqa: E402

CLIENT = "/usr/lib/qubes/qrexec-client-vm"
GUARDED_QUBE = os.environ.get("QMCP_SEAT_GUARDED", "ai-net-router")
TEMPLATE = os.environ.get("QMCP_SEAT_TEMPLATE", "ai-debian-13")
OUTSIDE_QUBE = os.environ.get("QMCP_SEAT_OUTSIDE", "sys-net")
results: list = []


def check(name, ok, detail=""):
    results.append(("PASS" if ok else "FAIL", name))
    print(f"{'PASS' if ok else 'FAIL':5s} {name}" + (f"  -- {detail}" if detail and not ok else ""), flush=True)


def raw(target, service, payload=b"", timeout=30):
    """(returncode, stdout) of one qrexec call from the hub; rc None = hung."""
    try:
        p = subprocess.run([CLIENT, target, service], input=payload, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return None, b""


def not_run(name, why):
    results.append(("NOT-RUN", name))
    print(f"NOT-RUN {name}  -- {why}", flush=True)


def refused_raw(name, target, service, payload=b""):
    rc, out = raw(target, service, payload)
    if rc is None:
        check(name, False, "HUNG: a dialog may be waiting")
    else:
        # A policy refusal: qrexec-client-vm exits non-zero with no stdout.
        check(name, rc != 0 and not out.strip(), f"rc={rc} out={out[:120]!r}")


def call(tool, **args):
    t = tools.TOOLS[tool]
    return t.handler(tools.validate_arguments(t, args))


def from_hub(inside, lead=None, model=None):
    print("== from the hub, bypassing the client")
    # Positive control first: a refusal proves nothing if no call can succeed.
    rc, out = raw("@adminvm", "qmcp.GetPoolStats")
    check("CONTROL: an allowed call from the hub succeeds", rc == 0 and b'"ok": true' in out,
          f"rc={rc} out={out[:120]!r}")
    refused_raw("admin.vm.List to dom0", "@adminvm", "admin.vm.List")
    refused_raw("admin.vm.tag.Set on an AI qube", inside, "admin.vm.tag.Set+ai-full")
    refused_raw("admin.vm.property.Set on an AI qube", inside, "admin.vm.property.Set+template")
    refused_raw("policy.Get", "@adminvm", "policy.Get")
    refused_raw("exec into a guarded qube", GUARDED_QUBE, "qmcp.RunInAIManaged", b'{"cmd":["true"]}')
    refused_raw("firewall write on a guarded qube", GUARDED_QUBE, "admin.vm.firewall.Set", b"action=accept\n")
    refused_raw("exec outside AI space", OUTSIDE_QUBE, "qmcp.RunInAIManaged", b'{"cmd":["true"]}')
    refused_raw("raw @dispvm shell from the hub", "@dispvm", "qubes.VMShell", b"true\n")
    rc, out = raw("@adminvm", "qmcp.SetPropertyAIManaged", b'{"name":"' + b"x" * 70000 + b'"}')
    check("an oversized request is refused before parsing", b"request too large" in out, f"{out[:120]!r}")
    rc, out = raw("@adminvm", "qmcp.SetPropertyAIManaged", b'{"name":["ai-x"],"property":7}')
    check("type-confused input is refused, not crashed", b'"ok": false' in out, f"{out[:120]!r}")
    # Proposals: the hub may submit, but only proposals of a valid shape are
    # stored. These are refused, so the suite leaves nothing for the operator.
    rc, out = raw("@adminvm", "qmcp.SubmitProposal", b'{"type":"project-create","title":"x"}')
    check("a proposal missing its fields is refused", b"invalid proposal" in out, f"{out[:120]!r}")
    rc, out = raw("@adminvm", "qmcp.SubmitProposal",
                  b'{"type":"project-delete","title":"a\\u202eb","project":"p01"}')
    check("a proposal title with a bidi override is refused", b"title" in out and b'"ok": false' in out,
          f"{out[:120]!r}")
    rc, out = raw("@adminvm", "qmcp.SubmitProposal", b'{"type":"qube-remove","title":"x","name":"ai-x"}')
    check("a proposal of an unknown type is refused", b"invalid proposal" in out, f"{out[:120]!r}")
    rc, out = raw("@adminvm", "qmcp.SubmitProposal", b'{"title":"' + b"x" * 70000 + b'"}')
    check("an oversized proposal is refused before parsing", b"request too large" in out, f"{out[:120]!r}")
    rc, out = raw("@adminvm", "qmcp.ProposalStatus", b"{}")
    check("the hub reads its proposals' states", rc == 0 and b'"proposals"' in out, f"{out[:120]!r}")
    # A name says who owns a qube: the hub's are ai-hub-..., judged on the name alone.
    rc, out = raw("@adminvm", "qmcp.SpawnAIManagedQube", b'{"name":"ai-rt-x","template":"x"}')
    check("a hub name outside ai-hub- is refused", b"ai-hub-" in out and b'"ok": false' in out,
          f"{out[:160]!r}")
    # Only an enrolled gateway may be a network; nothing is created either way.
    req = json.dumps({"name": "ai-hub-rt-net", "template": TEMPLATE, "netvm": OUTSIDE_QUBE}).encode()
    rc, out = raw("@adminvm", "qmcp.SpawnAIManagedQube", req)
    check("a network that is not enrolled is refused", b"enrolled gateway" in out, f"{out[:160]!r}")
    # A lead's firewall is the operator's: the hub reads it, and never writes it.
    if lead:
        rc, out = raw(lead, "admin.vm.firewall.Get")
        check("CONTROL: the hub reads a lead's firewall", rc == 0 and b"action=" in out,
              f"rc={rc} out={out[:120]!r}")
        refused_raw("firewall write on a lead", lead, "admin.vm.firewall.Set", b"action=accept\n")
        refused_raw("firewall reload on a lead", lead, "admin.vm.firewall.Reload")
    else:
        not_run("firewall write on a lead", "name a lead with --lead LEAD")
    # A model qube is its leads' alone, on port 11434.
    if model:
        # The policy's refusal, exit status 126: a call into a closed port fails too.
        rc, out = raw(model, "qubes.ConnectTCP+11434")
        check("TCP from the hub to a model qube", rc == 126 and not out.strip(), f"rc={rc} out={out[:80]!r}")
        refused_raw("exec into a model qube", model, "qmcp.RunInAIManaged", b'{"cmd":["true"]}')
    else:
        not_run("TCP from the hub to a model qube", "name one with --model-qube QUBE")
    # More concurrent calls than the per-caller cap; at least one is refused.
    with concurrent.futures.ThreadPoolExecutor(10) as pool:
        outs = list(pool.map(lambda _: raw("@adminvm", "qmcp.AIManagedEvents",
                                           b'{"duration": 12}', timeout=60)[1], range(10)))
    check("the per-caller concurrency cap holds", any(b"too many concurrent calls" in o for o in outs),
          str([o[:60] for o in outs]))


#: Index 0 is the positive control: allowed by Qubes' default policy, so the
#: probe machinery (client path, timeout, shell) is shown to work before any
#: refusal below it counts.
PROBES = [
    ("CONTROL: an allowed call from inside succeeds", "@default", "qubes.GetDate"),
    ("a qmcp wrapper from AI space", "dom0", "qmcp.ListAIManagedQubes"),
    ("a proposal from AI space", "dom0", "qmcp.SubmitProposal"),
    ("proposal states from AI space", "dom0", "qmcp.ProposalStatus"),
    ("admin.vm.List from AI space", "dom0", "admin.vm.List"),
    ("policy.List from AI space", "dom0", "policy.List"),
    ("admin.vm.tag.Set on another AI qube", "{peer}", "admin.vm.tag.Set+qmcp-x"),
    ("raw @dispvm shell", "@dispvm", "qubes.VMShell"),
    ("@dispvm of the default template", "@dispvm:default-dvm", "qubes.VMExec+true"),
    ("open a URL in the hub", "mcp-control", "qubes.OpenURL"),
    ("copy a file to the hub", "mcp-control", "qubes.Filecopy"),
    ("drive qmcp exec in another AI qube", "{peer}", "qmcp.RunInAIManaged"),
    ("a dom0 desktop notification through @default", "@default", "qubes.Notifications"),
    ("a TCP connection into another AI qube", "{peer}", "qubes.ConnectTCP+22"),
    ("a TCP connection into a model qube", "{model}", "qubes.ConnectTCP+11434"),
]


def from_inside(inside, peer, model=None):
    print(f"== from inside {inside} (root), against {peer}")
    probes = [p for p in PROBES if "{model}" not in p[1] or model]
    if not model:
        not_run("a TCP connection into a model qube", "name one with --model-qube QUBE")
    lines = ["set +e"]
    for i, (_, target, svc) in enumerate(probes):
        tgt = target.replace("{peer}", peer).replace("{model}", model or "")
        lines.append(f"timeout 25 {CLIENT} {shlex.quote(tgt)} {shlex.quote(svc)} </dev/null >/tmp/p{i}.out 2>/dev/null; "
                     f"echo \"P{i} rc=$? bytes=$(wc -c </tmp/p{i}.out)\"")
    r = call("qubes_run", name=inside, cmd="\n".join(lines), shell=True, timeout=400)
    if not r.get("ok"):
        check("run the probes inside a managed qube", False, json.dumps(r))
        return
    got = {}
    for line in r.get("stdout", "").splitlines():
        if line.startswith("P"):
            tag, rc, size = line.split()
            got[int(tag[1:])] = (int(rc.split("=")[1]), int(size.split("=")[1]))
    for i, (label, _, svc) in enumerate(probes):
        rc, size = got.get(i, (None, None))
        if i == 0:
            check(label, rc == 0 and (size or 0) > 0, f"rc={rc} bytes={size}")
            continue
        if rc == 124:
            check(label, False, "HUNG: a dialog may be waiting")
        elif svc.startswith("qubes.ConnectTCP"):
            # The policy's refusal, exit status 126, never a closed port's failure.
            check(label, rc == 126 and size == 0, f"rc={rc} bytes={size}")
        else:
            check(label, rc not in (None, 0) and size == 0, f"rc={rc} bytes={size}")


def main() -> int:
    if "--inside" not in sys.argv:
        print("usage: redteam_suite.py --inside <managed qube> [--peer <managed qube>] [--lead LEAD] "
              "[--model-qube QUBE]")
        return 2
    inside = sys.argv[sys.argv.index("--inside") + 1]
    peer = sys.argv[sys.argv.index("--peer") + 1] if "--peer" in sys.argv else inside
    lead = sys.argv[sys.argv.index("--lead") + 1] if "--lead" in sys.argv else None
    model = sys.argv[sys.argv.index("--model-qube") + 1] if "--model-qube" in sys.argv else None
    from_hub(inside, lead, model)
    r = call("qubes_start", name=inside)
    from_inside(inside, peer, model)
    fails = [x for x in results if x[0] == "FAIL"]
    unrun = [x for x in results if x[0] == "NOT-RUN"]
    # A probe that could not run leaves the suite INCOMPLETE, which is not green.
    verdict = "FAILED" if fails else ("INCOMPLETE" if unrun or not results else "GREEN")
    print(f"\nred-team suite: {verdict}  ({len(results)} probes, {len(fails)} got through or hung)")
    return {"GREEN": 0, "FAILED": 2, "INCOMPLETE": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
