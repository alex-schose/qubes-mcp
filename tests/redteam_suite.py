#!/usr/bin/env python3
"""Red-team suite: try to get past M1 from the hub and from inside AI space.

Run it IN the hub qube, from the public tree:

    PYTHONPATH=. python3 tests/redteam_suite.py --inside <managed qube>

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


def from_hub(inside):
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
]


def from_inside(inside, peer):
    print(f"== from inside {inside} (root), against {peer}")
    lines = ["set +e"]
    for i, (_, target, svc) in enumerate(PROBES):
        tgt = target.replace("{peer}", peer)
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
    for i, (label, _, _) in enumerate(PROBES):
        rc, size = got.get(i, (None, None))
        if i == 0:
            check(label, rc == 0 and (size or 0) > 0, f"rc={rc} bytes={size}")
            continue
        if rc == 124:
            check(label, False, "HUNG: a dialog may be waiting")
        else:
            check(label, rc not in (None, 0) and size == 0, f"rc={rc} bytes={size}")


def main() -> int:
    if "--inside" not in sys.argv:
        print("usage: redteam_suite.py --inside <managed qube> [--peer <managed qube>]")
        return 2
    inside = sys.argv[sys.argv.index("--inside") + 1]
    peer = sys.argv[sys.argv.index("--peer") + 1] if "--peer" in sys.argv else inside
    from_hub(inside)
    r = call("qubes_start", name=inside)
    from_inside(inside, peer)
    fails = [x for x in results if x[0] == "FAIL"]
    verdict = "FAILED" if fails else ("GREEN" if results else "INCOMPLETE")
    print(f"\nred-team suite: {verdict}  ({len(results)} probes, {len(fails)} got through or hung)")
    return {"GREEN": 0, "FAILED": 2, "INCOMPLETE": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
