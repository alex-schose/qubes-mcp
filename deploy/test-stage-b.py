#!/usr/bin/env python3
"""Stage B test plan (flip-aware — re-baselined for Stage G0c) — run from mcp-control.

Post-flip (tier-default=ro) the exec + copy surfaces require ai-exec, and Stage
G0c requires BOTH copy endpoints be ai-exec+. So the happy paths need
OPERATOR-TIERED fixtures passed by name via env — the slot spawns them and tiers
them in dom0 (AI cannot self-tier), and STARTS them (an ai-exec qube cannot be
started over the wrapper, which needs ai-full — so the slot starts it in dom0):

    QMCP_B_EXEC   — an ai-exec+ qube, RUNNING (exec + write + copy SOURCE)
    QMCP_B_EXEC2  — a second ai-exec+ qube, RUNNING (copy TARGET)
    QMCP_B_UNTAGGED — an operator qube that is NOT ai-managed (default sys-firewall)

Without the fixtures the exec/copy happy paths SKIP (not fail); the negative
refusal runs regardless. Exits non-zero on any FAIL. The Stage-G0c DENY teeth (an
ai-exec -> ai-ro copy is refused) lives in the slot, which can start an ai-ro
target in dom0 — the AI seat cannot start an untiered qube, so it cannot set that
case up cleanly here.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_service  # noqa: E402

EXEC = os.environ.get("QMCP_B_EXEC")
EXEC2 = os.environ.get("QMCP_B_EXEC2")
PROBE_UNTAGGED = os.environ.get("QMCP_B_UNTAGGED", "sys-firewall")

_p = _f = _s = 0


def ok(m):
    global _p
    _p += 1
    print(f"  PASS  {m}")


def bad(m):
    global _f
    _f += 1
    print(f"  FAIL  {m}")


def skip(m):
    global _s
    _s += 1
    print(f"  SKIP  {m}")


def header(s):
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label, r):
    out = dict(r)
    for k in ("stdout", "stderr"):
        if isinstance(out.get(k), str) and len(out[k]) > 160:
            out[k] = out[k][:160] + "… (truncated)"
    print(f"  {label:40s} → {json.dumps(out)}")


# ---------------------------------------------------------------- 1. happy path
header("1. exec / write / copy happy path (needs ai-exec+ fixtures)")
if not (EXEC and EXEC2):
    skip("QMCP_B_EXEC / QMCP_B_EXEC2 not set — exec/copy happy paths skipped")
else:
    r = call_service(EXEC, "qmcp.RunInAIManaged", {"cmd": ["whoami"], "timeout": 10}, timeout=40)
    show("whoami", r)
    (ok if r.get("stdout", "").strip() == "root" else bad)(f"RunInAIManaged in {EXEC} runs as root")

    r = call_service(EXEC, "qmcp.RunInAIManaged",
                     {"cmd": "echo 'hello G0c' > /tmp/test.txt && cat /tmp/test.txt",
                      "shell": True, "timeout": 5}, timeout=35)
    show("write /tmp/test.txt", r)
    (ok if (r.get("ok") and "hello G0c" in r.get("stdout", "")) else bad)(f"wrote /tmp/test.txt in {EXEC}")

    r = call_service(EXEC, "qmcp.CopyToAIManaged", {"target": EXEC2, "path": "/tmp/test.txt"}, timeout=60)
    show("copy exec→exec", r)
    (ok if r.get("ok") else bad)(f"G0c ALLOW: copy {EXEC} → {EXEC2} (both ai-exec+) succeeds")

    r = call_service(EXEC2, "qmcp.RunInAIManaged",
                     {"cmd": ["cat", f"/home/user/QubesIncoming/{EXEC}/test.txt"], "timeout": 5}, timeout=35)
    show("read on target", r)
    (ok if (r.get("ok") and "hello G0c" in r.get("stdout", "")) else bad)(f"content readable on {EXEC2}")

# ---------------------------------------------------------------- 2. negative
header(f"2. Negative — RunInAIManaged on {PROBE_UNTAGGED} (untagged) is refused")
r = call_service(PROBE_UNTAGGED, "qmcp.RunInAIManaged", {"cmd": ["whoami"], "timeout": 5}, timeout=15)
show(f"run on {PROBE_UNTAGGED}", r)
(ok if not r.get("ok") else bad)(f"policy refused exec on {PROBE_UNTAGGED} (or absent — indistinguishable)")

# ---------------------------------------------------------------- summary
header("Stage B — summary")
print(f"  PASS={_p}  FAIL={_f}  SKIP={_s}")
print("  OVERALL: FAIL" if _f else "  OVERALL: PASS (skips are not failures)")
sys.exit(1 if _f else 0)
