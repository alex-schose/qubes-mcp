#!/usr/bin/env python3
"""Stage I-3 test plan — run from mcp-control after slot-52.sh applied.

I-3 introduces the tier taxonomy + the dom0 tier-resolution helper
(qmcp_tier.py), in COMPAT mode (untiered ai-managed = full). It is
BEHAVIOUR-NEUTRAL on every AI surface: no wrapper sources the helper yet
(that is I-5) and no policy line changed. So, like I-2, the proof splits
along the trust boundary:

  - The helper's resolution LOGIC (the whole risk surface) is proven
    exhaustively OFFLINE — operator-local offline-validate-I-3.py, 40 checks
    (ladder, cumulative invariant, highest-wins, the two-phase flip,
    fail-closed). mcp-control cannot call the helper: it is a dom0 lib, not a
    service, exposed by no policy line.
  - From mcp-control (here) we prove the AI-SIDE invariants: reads are
    byte-identical to pre-I-3 (behaviour-neutral), the tier tags are NOT
    readable (the authority topology is not an AI oracle even though the tags
    now exist), and AI has no tier-read surface at all.

Tests (all HARD):
  1. Tier tags are not AI-readable. For every ai-managed qube, the `tags`
     read returns only the qmcp observable vocabulary — never a tier tag
     (ai-exec / ai-net / ai-full / ai-dump). Even an operator-tiered qube
     looks identical to AI: capability is discovered through opaque refusals,
     never a tag read (design §1.1 — visibility ≠ capability).
  2. Reads behaviour-neutral. ListAIManagedQubes answers; a VM-valued read
     still round-trips (in-scope name or the <out-of-scope> sentinel);
     existence-hiding holds (dom0 + ghost → opaque not found, byte-identical).
     I-3 added no read regression and no new oracle.
  3. No AI-facing tier surface. The MCP tool layer (qubes_mcp/tools/) does not
     reach the tier helper, the tier-default flag, or the capability resolver:
     enforcement is dom0-only (the server.py _RING_MIN_TIER annotation is
     declarative ring vocabulary, not a tool and not a boundary — design §4.1).

Pure read probes — does NOT create or modify any qube.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp  # noqa: E402

SENTINEL = "<out-of-scope>"
TIER_TAGS = {"ai-exec", "ai-net", "ai-full", "ai-dump"}
VM_VALUED = ["netvm", "template", "default_dispvm", "guivm", "audiovm", "management_dispvm"]
NOT_FOUND = {"ok": False, "error": "not found"}


def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r) -> None:
    print(f"  {label:48s} → {json.dumps(r)}")


_LIST_CACHE: dict = {}


def ai_managed() -> list:
    if "r" not in _LIST_CACHE:
        _LIST_CACHE["r"] = call_qmcp("qmcp.ListAIManagedQubes")
    return [q["name"] for q in _LIST_CACHE["r"].get("qubes", [])]


def getprop(name: str, prop: str) -> dict:
    return call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})


# ====================================================================
def test_1_tiers_not_readable() -> bool:
    header("1. Tier tags are NOT AI-readable (no authority-topology oracle)")
    names = ai_managed()
    if not names:
        print("  PASS — vacuously (no ai-managed qubes to probe).")
        return True
    ok = True
    seen_any = False
    for q in names:
        r = getprop(q, "tags")
        if not r.get("ok") or not isinstance(r.get("value"), list):
            print(f"  FAIL — tags read on {q} not a deliberate list: {r}")
            ok = False
            continue
        seen_any = True
        leaked = set(r["value"]) & TIER_TAGS
        if leaked:
            print(f"  FAIL — {q} tags read leaked tier vocabulary: {sorted(leaked)}")
            ok = False
    if ok and seen_any:
        print(f"  PASS — {len(names)} qube(s): every tags read is tier-free")
        print("         (tiers exist in dom0; AI cannot read the fleet's tier map).")
    return ok


def test_2_reads_behaviour_neutral() -> bool:
    header("2. Reads behaviour-neutral (no regression, no new oracle)")
    names = ai_managed()
    ok = True
    # list still answers
    if not _LIST_CACHE["r"].get("ok"):
        print(f"  FAIL — list no longer answers: {_LIST_CACHE['r']}")
        ok = False
    else:
        print(f"  list answers: {len(names)} ai-managed qube(s).")
    # VM-valued reads still round-trip (in-scope name present in list, or sentinel)
    nameset = set(names)
    for q in names:
        for p in VM_VALUED:
            r = getprop(q, p)
            if not r.get("ok"):
                continue
            for v in (r["value"] if isinstance(r["value"], list) else [r["value"]]):
                if isinstance(v, str) and v not in ("", SENTINEL) and v not in nameset:
                    # only flag qube-shaped strings; scalars/colours pass
                    rr = getprop(v, "klass")
                    if rr.get("ok"):
                        print(f"  FAIL — {q}.{p}='{v}' emitted but not in the ai-managed list")
                        ok = False
    # existence-hiding baseline byte-identical
    r_dom0 = getprop("dom0", "netvm")
    r_ghost = getprop("qmcp-i3-no-such-qube-zzz", "netvm")
    show("dom0.netvm", r_dom0)
    show("ghost.netvm", r_ghost)
    if not (r_dom0 == r_ghost == NOT_FOUND):
        print("  FAIL — existence-hiding baseline changed (dom0/ghost not opaque-identical)")
        ok = False
    if ok:
        print("  PASS — reads answer as before; existence-hiding intact.")
    return ok


def test_3_no_aifacing_tier_surface() -> bool:
    header("3. No AI-facing tier surface (enforcement is dom0-only)")
    # Silent static scan (no fake-service probes — those trip the qrexec
    # catch-all deny and pop denial dialogs on the operator's screen). The
    # AI-facing surface is the MCP tool layer; scan it for any reach into the
    # tier helper / flag / resolver. server.py's _RING_MIN_TIER is declarative
    # ring vocabulary (not a tool, not a boundary — design §4.1) and is out of
    # scope by construction.
    tools = Path(__file__).resolve().parents[1] / "qubes_mcp" / "tools"
    needles = ("qmcp_tier", "tier-default", "tier_default", "effective_capabilities")
    offenders = []
    for pyf in tools.rglob("*.py"):
        txt = pyf.read_text(encoding="utf-8", errors="replace")
        hits = [n for n in needles if n in txt]
        if hits:
            offenders.append(f"{pyf.name}:{hits}")
    if offenders:
        print(f"  FAIL — a tool reaches the tier layer: {offenders}")
        return False
    print("  PASS — no MCP tool reaches the tier helper/flag/resolver")
    print("         (AI cannot read or set a tier; dom0 wrappers enforce in I-5).")
    return True


# ====================================================================
def main() -> int:
    tests = [
        test_1_tiers_not_readable,
        test_2_reads_behaviour_neutral,
        test_3_no_aifacing_tier_surface,
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
    print("\nNOTE — the tier helper's resolution logic is proven OFFLINE")
    print("       (offline-validate-I-3.py, 40 checks); it is a dom0 lib and")
    print("       AI-unreachable by design, so mcp-control cannot call it.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
