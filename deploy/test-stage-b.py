#!/usr/bin/env python3
"""Stage B test plan — run from mcp-control after dom0 + template deploy.

Verifies qmcp.RunInAIManaged and qmcp.CopyToAIManaged + the qubes.Filecopy
policy between ai-managed qubes. Cleans up its test qubes at the end.

Before running, set PROBE_UNTAGGED to a qube name on your system that
exists but isn't tagged ai-managed (for the negative-refusal test).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Make `qubes_mcp` importable when the repo isn't `pip install -e .`'d.
# Walks: deploy/test-stage-b.py → deploy/ → repo_root/ (containing qubes_mcp/).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp, call_service  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"
PROBE_UNTAGGED = "sys-firewall"  # any operator qube that isn't ai-managed


# ====================================================================
def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r: dict) -> None:
    out = dict(r)
    for k in ("stdout", "stderr"):
        if isinstance(out.get(k), str) and len(out[k]) > 200:
            out[k] = out[k][:200] + "... (truncated)"
    print(f"  {label:36s} → {json.dumps(out)}")


def cleanup(*qube_names: str) -> None:
    for n in qube_names:
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "kill"})
        time.sleep(1)
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "remove"})


def wait_for_state(qube: str, state: str, max_seconds: int = 30) -> str:
    for _ in range(max_seconds):
        r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": qube, "property": "power_state"})
        if r.get("value") == state:
            return state
        time.sleep(1)
    return r.get("value", "unknown")


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftovers")
cleanup("ai-scratch-1", "ai-scratch-2")

# ------------------------------------------------------- 1. spawn + start
header("1. Spawn + start ai-scratch-1 and ai-scratch-2")
for name in ("ai-scratch-1", "ai-scratch-2"):
    r = call_qmcp("qmcp.SpawnAIManagedQube",
                 {"name": name, "template": PROBE_AI_MANAGED_TEMPLATE, "label": "gray"})
    show(f"spawn {name}", r)
    if not r.get("ok"):
        print("  FAIL: spawn failed, aborting test plan.")
        sys.exit(1)

for name in ("ai-scratch-1", "ai-scratch-2"):
    r = call_qmcp("qmcp.LifecycleAIManaged", {"name": name, "action": "start"})
    show(f"start {name}", r)
    s = wait_for_state(name, "Running", 20)
    print(f"    {name} power_state: {s}")

# ----------------------------------------------------------- 2. run whoami
header("2. qubes_run — verify root execution")
r = call_service("ai-scratch-1", "qmcp.RunInAIManaged",
                 {"cmd": ["whoami"], "timeout": 10}, timeout=40)
show("whoami in ai-scratch-1", r)
who = r.get("stdout", "").strip()
if who == "root":
    print("  PASS: qmcp.RunInAIManaged executes as root.")
else:
    print(f"  FAIL: expected 'root', got {who!r}")

# ------------------------------------------------------ 3. run system info
header("3. qubes_run — system info inside the sandbox")
r = call_service("ai-scratch-1", "qmcp.RunInAIManaged",
                 {"cmd": ["uname", "-srm"], "timeout": 5}, timeout=35)
show("uname -srm", r)

# --------------------------------------- 4. write file via shell command
header("4. qubes_run with shell — write a file in ai-scratch-1")
r = call_service("ai-scratch-1", "qmcp.RunInAIManaged",
                 {"cmd": "echo 'hello from stage B' > /tmp/test.txt && cat /tmp/test.txt",
                  "shell": True, "timeout": 5}, timeout=35)
show("write /tmp/test.txt", r)
wrote_ok = r.get("ok") and r.get("rc") == 0 and "hello from stage B" in r.get("stdout", "")
print(f"  {'PASS' if wrote_ok else 'FAIL'}: file created and content readable")

# -------------------------------------------------- 5. inter-qube copy
header("5. qubes_copy — ai-scratch-1:/tmp/test.txt → ai-scratch-2")
r = call_service("ai-scratch-1", "qmcp.CopyToAIManaged",
                 {"target": "ai-scratch-2", "path": "/tmp/test.txt"}, timeout=60)
show("copy to ai-scratch-2", r)
copy_ok = bool(r.get("ok"))

r = call_service("ai-scratch-2", "qmcp.RunInAIManaged",
                 {"cmd": ["cat", "/home/user/QubesIncoming/ai-scratch-1/test.txt"],
                  "timeout": 5}, timeout=35)
show("read on ai-scratch-2", r)
read_ok = r.get("ok") and "hello from stage B" in r.get("stdout", "")
print(f"  {'PASS' if copy_ok and read_ok else 'FAIL'}: file content matches across qubes")

# ----------------------------- 6. negative — try to run on untagged qube
header(f"6. Negative — qubes_run against {PROBE_UNTAGGED} (operator qube, untagged)")
r = call_service(PROBE_UNTAGGED, "qmcp.RunInAIManaged",
                 {"cmd": ["whoami"], "timeout": 5}, timeout=15)
show(f"run on {PROBE_UNTAGGED}", r)
refused = (not r.get("ok"))
print(f"  {'PASS' if refused else 'FAIL'}: policy refused (or qube absent — indistinguishable)")

# ---------------------------------------------------------- summary
header("Stage B test plan — summary")
print("  Expected PASS markers: 4")
print("    - root execution")
print("    - file creation via shell")
print("    - inter-qube copy + read")
print("    - negative refusal on untagged target")

# ---------------------------------------------------------- cleanup
header("Cleanup")
cleanup("ai-scratch-1", "ai-scratch-2")
r = call_qmcp("qmcp.ListAIManagedQubes")
remaining = [q["name"] for q in r.get("qubes", [])]
print(f"  Remaining ai-managed qubes: {remaining}")
