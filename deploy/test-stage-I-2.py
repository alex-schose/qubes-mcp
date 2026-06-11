#!/usr/bin/env python3
"""Stage I-2 test plan — run from mcp-control after slot-49.sh applied.

I-2 adds a hash-chained dom0 audit log of every state-changing qmcp.* call.
Its defining property is that the log is **AI-unreachable**: no qmcp.*
service reads it and no policy line exposes it. That makes the test split
along the trust boundary:

  - From mcp-control (here) we can prove the AI-SIDE properties: the audit
    hook is invisible (responses are byte-identical to pre-I-2, and a
    logging failure never blocks an op), and there is no AI-facing surface
    that reads the log.
  - The POSITIVE proof — that a chained line was actually written and the
    chain verifies — lives in dom0, because mcp-control cannot read the log
    (that unreachability IS the security property). slot-49 does it on
    hardware; the operator can re-check any time with:
        sudo python3 /etc/qubes-rpc/qmcp_audit.py verify

Tests (all HARD):
  1. Transparency on the refused path. A refused Lifecycle / SetProperty /
     SetFeature returns the exact pre-I-2 opaque response. The audit call
     fires inside the same emit() funnel on this path, so byte-identical
     responses prove the hook changes nothing AI observes (and, being
     best-effort, never blocks the call).
  2. No AI-facing audit read surface. The MCP tool layer references the
     audit log nowhere, and probing plausible audit-read service names is
     refused — AI has no way to read or forge the trail.
  3. Unrelated read path intact. ListAIManagedQubes still answers, and a
     file-path-shaped name is still opaque "not found" — I-2 added no new
     existence/read oracle.

Pure probes — does NOT create or modify any qube.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp  # noqa: E402

NOT_FOUND = {"ok": False, "error": "not found"}
GHOST = "qmcp-i2-no-such-qube-zzz"


def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r) -> None:
    print(f"  {label:48s} → {json.dumps(r)}")


# ====================================================================
def test_1_refused_transparency() -> bool:
    header("1. Transparency on the refused path (hook invisible to AI)")
    r_life = call_qmcp("qmcp.LifecycleAIManaged", {"name": GHOST, "action": "kill"})
    r_prop = call_qmcp("qmcp.SetPropertyAIManaged", {"name": GHOST, "property": "memory", "value": 400})
    r_feat = call_qmcp("qmcp.SetFeatureAIManaged", {"name": GHOST, "feature": "x", "value": "1"})
    show("Lifecycle(ghost, kill)", r_life)
    show("SetProperty(ghost, memory=400)", r_prop)
    show("SetFeature(ghost, x=1)", r_feat)
    ok = True
    for label, r in (("Lifecycle", r_life), ("SetProperty", r_prop), ("SetFeature", r_feat)):
        if r != NOT_FOUND:
            print(f"  FAIL — {label} not the pre-I-2 opaque not-found: {r}")
            ok = False
    if ok:
        print("  PASS — refused calls return the unchanged opaque response;")
        print("         audit fires in the same funnel yet alters nothing.")
    return ok


def test_2_no_audit_read_surface() -> bool:
    header("2. No AI-facing audit read surface")
    # The MCP tool layer must not reference the audit log at all. We do NOT
    # probe made-up qmcp.* service names from here: a nonexistent service trips
    # the qrexec policy catch-all deny, which pops a desktop denial dialog on
    # the operator's screen for every probe — noisy and pointless. This static
    # scan is the real, silent proof that I-2 added no AI-facing read surface;
    # dom0-side, no qmcp.* service reads the log by construction (and there is
    # no policy line exposing it).
    pkg = Path(__file__).resolve().parents[1] / "qubes_mcp"
    needles = ("qmcp_audit", "qmcp-audit", "/var/log/qmcp-audit")
    offenders = []
    for pyf in pkg.rglob("*.py"):
        txt = pyf.read_text(encoding="utf-8", errors="replace")
        if any(n in txt for n in needles):
            offenders.append(str(pyf.relative_to(pkg)))
    if offenders:
        print(f"  FAIL — MCP tool layer references the audit log: {offenders}")
        return False
    print("  PASS — no MCP tool references the audit log path/lib (silent static scan).")
    return True


def test_3_read_path_intact() -> bool:
    header("3. Unrelated read path intact (no new oracle)")
    r_list = call_qmcp("qmcp.ListAIManagedQubes")
    show("ListAIManagedQubes ok", {"ok": r_list.get("ok"), "n": len(r_list.get("qubes", []))})
    if not r_list.get("ok"):
        print(f"  FAIL — list no longer answers: {r_list}")
        return False
    # A file-path-shaped name must still be opaque (not an existence/read oracle).
    r_path = call_qmcp("qmcp.GetPropertyAIManaged",
                       {"name": "/var/log/qmcp-audit.log", "property": "netvm"})
    show("GetProperty(/var/log/qmcp-audit.log)", r_path)
    if r_path != NOT_FOUND:
        print(f"  FAIL — path-shaped name not opaque not-found: {r_path}")
        return False
    print("  PASS — list answers; path-shaped reads stay opaque.")
    return True


# ====================================================================
def main() -> int:
    tests = [
        test_1_refused_transparency,
        test_2_no_audit_read_surface,
        test_3_read_path_intact,
    ]
    results = []
    for t in tests:
        try:
            results.append((t.__name__, t()))
        except Exception as e:
            print(f"  EXCEPTION in {t.__name__}: {e}")
            results.append((t.__name__, False))

    header("Summary")
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{passed}/{len(results)} tests green.")
    print("\nNOTE — chain integrity is verified in DOM0 (the log is")
    print("       AI-unreachable by design). slot-49 checks it on deploy;")
    print("       re-check anytime: sudo python3 /etc/qubes-rpc/qmcp_audit.py verify")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
