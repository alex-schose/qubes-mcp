#!/usr/bin/env python3
"""Stage I-4 test plan — run from mcp-control after slot-60.sh applied.

I-4 graduates the directly-`@tag:`-scoped policy surfaces to the tier ladder:
firewall WRITE (Set/Reload) moves to `@tag:ai-net` + `@tag:ai-full`, firewall
READ + device-list stay at the ai-managed ro-floor, and `ai-dump` gets a
dedicated copy-IN-only `qubes.Filecopy` line. It ships under Option A — a
`@tag:ai-managed` COMPAT BACKSTOP keeps firewall WRITE working for every
umbrella qube during migration, so the WRITE surface is behaviour-neutral in
compat; real per-tier enforcement goes live at the I-5 flip (backstop removed).

Because the policy layer matches tags LITERALLY, I-4's whole risk surface is
the policy file. So the proof splits three ways (the I-2/I-3 pattern):

  - OFFLINE (operator-local offline-validate-I-4.py, 100 checks) parses the real
    policy and simulates qrexec first-match-wins for the full (surface x tier)
    matrix, COMPAT *and* POST-FLIP. The bulk of coverage lives there.
  - The SLOT (dom0, slot-60.sh) is the positive per-tier proof on real qrexec:
    operator-tagged ro/exec/net/full/dump fixtures, exercised under the compat
    policy AND a throwaway no-backstop probe policy (proving the flip), then
    restored byte-exact. Only dom0 can create the tier fixtures (AI cannot tag).
  - THIS script (mcp-control) proves the AI-SIDE invariants that hold in compat
    WITHOUT tag authority: firewall still works on the qubes AI can spawn
    (behaviour-neutral), every refusal is the same opaque sentinel (no
    tier/existence oracle), and the ai-dump sink is invisible to AI.

In compat, firewall WRITE is uniformly allowed on every umbrella tier (the
backstop), so the per-tier DIFFERENTIATION is not observable from the AI side
here — that is the slot's job. This script asserts what AI *can* observe.

Spawns + removes its own umbrella test qube; never tags, never touches an
operator qube or ai-net-router.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp, call_admin  # noqa: E402

# ====================================================================
# Probe constants — adjust to your setup. The OPTIONAL fixture names let the
# slot hand this script operator-tagged qubes for extra per-tier assertions;
# leave them None to skip those (the slot covers them directly).
# ====================================================================
PROBE_TEMPLATE = "ai-debian-13"
PROBE_UNTAGGED = "sys-firewall"          # a real but NOT-ai-managed operator qube
GHOST = "qmcp-i4-no-such-qube-zzz"
TEST_QUBE = "ai-i4-fw"
OPAQUE = {"ok": False, "error": "not found or refused"}

# Optional operator-tagged fixtures. The slot (slot-61) creates these in dom0
# and passes their names via env so this AI-side test also exercises the
# per-tier surfaces; left None when run standalone (those probes then SKIP).
PROBE_AI_DUMP = os.environ.get("QMCP_I4_DUMP") or None   # a pure ai-dump sink (NOT ai-managed)
PROBE_AI_NET = os.environ.get("QMCP_I4_NET") or None     # ai-managed + ai-net

TEST_RULES = (
    "action=accept proto=tcp dstports=443-443\n"
    "action=drop\n"
)


def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r) -> None:
    out = dict(r) if isinstance(r, dict) else r
    if isinstance(out, dict):
        for k in ("stdout", "stderr", "rules"):
            if isinstance(out.get(k), str) and len(out[k]) > 160:
                out[k] = out[k][:160] + "... (truncated)"
    print(f"  {label:46s} → {json.dumps(out)}")


def cleanup(*names: str) -> None:
    for n in names:
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "kill"})
        time.sleep(1)
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "remove"})


# ====================================================================
def test_1_compat_invariance() -> bool:
    header("1. Compat invariance — firewall still works on an umbrella qube")
    print("   (Option A backstop: untiered ai-managed qubes keep firewall WRITE;")
    print("    this is the 'A–F3 stays green' proof at the firewall surface.)")
    cleanup(TEST_QUBE)
    r = call_qmcp("qmcp.SpawnAIManagedQube",
                  {"name": TEST_QUBE, "template": PROBE_TEMPLATE, "label": "gray"})
    show("spawn umbrella test qube", r)
    if not r.get("ok"):
        print("  FAIL — could not spawn the test qube")
        return False
    ok = True
    set_r = call_admin("admin.vm.firewall.Set", TEST_QUBE, payload=TEST_RULES.encode())
    show("firewall.Set (umbrella, backstop)", set_r)
    ok &= bool(set_r.get("ok"))
    get_r = call_admin("admin.vm.firewall.Get", TEST_QUBE)
    show("firewall.Get (ro-floor)", get_r)
    ok &= bool(get_r.get("ok"))
    rel_r = call_admin("admin.vm.firewall.Reload", TEST_QUBE)
    show("firewall.Reload (umbrella, backstop)", rel_r)
    ok &= bool(rel_r.get("ok"))
    if set_r.get("ok") and get_r.get("ok"):
        sent = [l.strip() for l in TEST_RULES.splitlines() if l.strip()]
        got = [l.strip() for l in get_r.get("stdout", "").splitlines() if l.strip()]
        ok &= all(l in got for l in sent)
    print(f"  {'PASS' if ok else 'FAIL'}: firewall Get/Set/Reload + round-trip on an umbrella qube")
    return ok


def test_2_oracle_hygiene() -> bool:
    header("2. Oracle hygiene — every denied firewall call is the same sentinel")
    print("   firewall.Set AND firewall.Get on {untagged, ghost, dom0} must all")
    print("   collapse to one opaque refusal — no existence/tier oracle.")
    ok = True
    probes = [("untagged", PROBE_UNTAGGED), ("ghost", GHOST), ("dom0", "dom0")]
    responses = []
    for label, tgt in probes:
        s = call_admin("admin.vm.firewall.Set", tgt, payload=b"action=drop\n")
        g = call_admin("admin.vm.firewall.Get", tgt)
        show(f"firewall.Set  on {label}", s)
        show(f"firewall.Get  on {label}", g)
        responses.append((f"Set/{label}", s))
        responses.append((f"Get/{label}", g))
    for name, r in responses:
        if r != OPAQUE:
            print(f"  FAIL — {name} not the opaque sentinel: {r}")
            ok = False
    if ok:
        print(f"  PASS — all {len(responses)} denied calls are byte-identical: {json.dumps(OPAQUE)}")
    return ok


def test_3_dump_invisible() -> bool:
    header("3. ai-dump sink is invisible to AI (orthogonal, not ai-managed)")
    r = call_qmcp("qmcp.ListAIManagedQubes")
    names = [q["name"] for q in r.get("qubes", [])]
    ok = True
    # No qube AI can see should be a pure dump sink; the sink lacks the umbrella.
    if PROBE_AI_DUMP and PROBE_AI_DUMP in names:
        print(f"  FAIL — ai-dump sink {PROBE_AI_DUMP} is visible in ListAIManagedQubes")
        ok = False
    # tier/dump tags are never readable off any ai-managed qube (I-3 invariant,
    # re-checked here: I-4 introduces ai-dump but it must not become readable).
    TIER_TAGS = {"ai-exec", "ai-net", "ai-full", "ai-dump"}
    for q in names:
        tr = call_qmcp("qmcp.GetPropertyAIManaged", {"name": q, "property": "tags"})
        if tr.get("ok") and isinstance(tr.get("value"), list):
            leaked = set(tr["value"]) & TIER_TAGS
            if leaked:
                print(f"  FAIL — {q} tags read leaked tier/dump vocabulary: {sorted(leaked)}")
                ok = False
    # If a dump fixture is provided, reads on it must be opaque (it is unreadable).
    if PROBE_AI_DUMP:
        g = call_admin("admin.vm.firewall.Get", PROBE_AI_DUMP)
        show(f"firewall.Get on dump {PROBE_AI_DUMP}", g)
        if g != OPAQUE:
            print(f"  FAIL — dump sink readable via firewall.Get: {g}")
            ok = False
    if ok:
        msg = "no dump sink visible; no tier/dump tag readable"
        print(f"  PASS — {msg}.")
    return ok


def test_4_optional_net_fixture() -> bool:
    header("4. (optional) operator ai-net fixture can write firewall")
    if not PROBE_AI_NET:
        print("  SKIP — no PROBE_AI_NET fixture provided (slot covers per-tier).")
        return True
    s = call_admin("admin.vm.firewall.Set", PROBE_AI_NET, payload=TEST_RULES.encode())
    show(f"firewall.Set on ai-net {PROBE_AI_NET}", s)
    ok = bool(s.get("ok"))
    print(f"  {'PASS' if ok else 'FAIL'}: ai-net qube may write firewall")
    return ok


def main() -> int:
    tests = [
        test_1_compat_invariance,
        test_2_oracle_hygiene,
        test_3_dump_invisible,
        test_4_optional_net_fixture,
    ]
    results = []
    for t in tests:
        try:
            results.append((t.__name__, t()))
        except Exception as e:
            print(f"  EXCEPTION in {t.__name__}: {e}")
            results.append((t.__name__, False))
    header("Cleanup")
    cleanup(TEST_QUBE)
    r = call_qmcp("qmcp.ListAIManagedQubes")
    print(f"  Remaining ai-managed qubes: {[q['name'] for q in r.get('qubes', [])]}")

    header("Summary")
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{passed}/{len(results)} tests green.")
    print("\nNOTE — per-tier ENFORCEMENT (ro/exec denied firewall WRITE after the")
    print("       flip; net/full allowed) is proven OFFLINE (offline-validate-I-4.py,")
    print("       100 checks) and on dom0 hardware (slot-60). In compat the backstop")
    print("       allows every umbrella tier, so AI cannot observe the split here.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
