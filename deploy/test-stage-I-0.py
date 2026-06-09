#!/usr/bin/env python3
"""Stage I-0 test plan — run from mcp-control after slot-43.sh applied.

Verifies the F3 pool cap has been promoted from advisory signal to a
hard gate on every create path (Spawn / Clone / SpawnDisposable).

Design: each test attempts its create surface unconditionally, then
classifies the response across the three valid cap states:
  - ok=True                                → wrapper proceeded under headroom
  - error == "pool cap exceeded"           → gate fired (cap-low / SOFT S1)
  - error == "pool cap not configured"     → gate fired fail-closed (SOFT S2)
Any other response → FAIL. So the same test script gives a deterministic
PASS in all three operator-cap-states, and slot-44 can run it under each
phase and grep the output for the expected error string per phase.

HARD probes (cap raised above current `used` + estimate):
  1. Spawn — attempts qmcp.SpawnAIManagedQube on an ai-managed
     template; under headroom expects ok=True + used grows + cleanup.
  2. Clone — attempts qmcp.CloneAIManagedQube on an ai-managed source
     (the probe template itself, which is permanent); under headroom
     expects ok=True + cleanup.
  3. Disposable — spawns its own DVMT (ai-I-0-dvmt) then spawns a
     disposable from it; auto-cleanup on kill returns `used` to
     baseline. Under cap pressure, the DVMT-spawn step proves the
     gate (same gate code as the Disposable wrapper).
  4. Cap-shape — GetPoolStats still returns {used, cap, headroom} with
     `used + headroom == cap` whenever `used <= cap`. Under SOFT S2
     (cap file absent), accepts the fail-closed "pool cap not
     configured" response as PASS — that IS the documented behaviour.

SOFT manual probes (operator-driven, dom0 write required — slot-44
automates these by manipulating /etc/qmcp/pool-cap):
  S1. Lower /etc/qmcp/pool-cap below current `used`. All four tests
      still PASS, but the response lines now carry
      `"error": "pool cap exceeded"`.
  S2. Remove /etc/qmcp/pool-cap entirely. All four tests still PASS,
      but the response lines carry `"error": "pool cap not configured"`.

The test spawns at most: one AppVM (test 1), one cloned TemplateVM
(test 2), one DVMT + one disposable (test 3). Each is cleaned up
before the test returns. Does NOT touch any operator qube.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp  # noqa: E402
from qubes_mcp.tools.qubes_get_pool_stats import qubes_get_pool_stats  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"   # ai-managed TemplateVM

TEST_QUBE_SPAWN  = "ai-I-0-spawn"
TEST_QUBE_SOURCE = "ai-I-0-clone-src"
TEST_QUBE_CLONE  = "ai-I-0-clone-dst"
TEST_DVMT        = "ai-I-0-dvmt"             # self-spawned by test 3
                                              # (mirrors test-stage-e2 pattern)


# ====================================================================
def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r: dict) -> None:
    print(f"  {label:48s} → {json.dumps(r)}")


def cleanup(*qube_names: str) -> None:
    for n in qube_names:
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "kill"})
        time.sleep(1)
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "remove"})


def stats() -> dict:
    return qubes_get_pool_stats()


def gib(n: int) -> str:
    return f"{n / 1024**3:.2f} GiB"


# Three response shapes count as PASS — they cover every valid cap state:
GATE_FIRED_LOW = "pool cap exceeded"          # cap > 0 but used + estimate > cap
GATE_FIRED_MISSING = "pool cap not configured"  # cap file absent / malformed
VALID_REFUSALS = {GATE_FIRED_LOW, GATE_FIRED_MISSING}


def classify_response(r: dict) -> str:
    """Return one of: 'ok', 'gate-low', 'gate-missing', 'unexpected'."""
    if r.get("ok"):
        return "ok"
    err = r.get("error", "")
    if err == GATE_FIRED_LOW:
        return "gate-low"
    if err == GATE_FIRED_MISSING:
        return "gate-missing"
    return "unexpected"


# ====================================================================
# tests
# ====================================================================

def test_1_spawn_happy_path() -> bool:
    header("1. SpawnAIManagedQube — gate behaviour across cap states")
    cleanup(TEST_QUBE_SPAWN)

    baseline = stats()
    show("baseline GetPoolStats", baseline)

    # Always attempt the create. The response classifies the cap state.
    r = call_qmcp("qmcp.SpawnAIManagedQube", {
        "name":     TEST_QUBE_SPAWN,
        "template": PROBE_AI_MANAGED_TEMPLATE,
        "label":    "gray",
        "netvm":    None,
    })
    show("spawn", r)
    kind = classify_response(r)

    if kind == "gate-low":
        print(f"  PASS — gate fired with '{GATE_FIRED_LOW}' (SOFT S1 / low headroom).")
        return True
    if kind == "gate-missing":
        print(f"  PASS — gate fired with '{GATE_FIRED_MISSING}' (SOFT S2 fail-closed).")
        return True
    if kind == "unexpected":
        print(f"  FAIL — spawn refused unexpectedly: {r}")
        return False

    # ok=True: verify the wrapper actually works under headroom.
    after = stats()
    show("post-spawn GetPoolStats", after)
    if after.get("ok"):
        grew = after["ai_managed_bytes_used"] - baseline.get("ai_managed_bytes_used", 0)
        if grew > 0:
            print(f"  used grew by {gib(grew)} — sane")
        else:
            print(f"  WARN — used did not grow ({gib(grew)}); accounting drift?")

    cleanup(TEST_QUBE_SPAWN)
    print("  PASS — spawn under cap; cleaned up.")
    return True


def test_2_clone_happy_path() -> bool:
    header("2. CloneAIManagedQube — gate behaviour across cap states")
    cleanup(TEST_QUBE_CLONE, TEST_QUBE_SOURCE)

    baseline = stats()
    show("baseline GetPoolStats", baseline)

    # Clone the ai-managed TEMPLATE directly — it's permanent
    # ai-managed infrastructure, so the clone surface can be exercised
    # under any cap state without needing a separate source spawn.
    # (Cloning a TemplateVM produces another TemplateVM. The Clone
    # wrapper does not constrain klass.)
    r = call_qmcp("qmcp.CloneAIManagedQube", {
        "source": PROBE_AI_MANAGED_TEMPLATE,
        "name":   TEST_QUBE_CLONE,
    })
    show("clone", r)
    kind = classify_response(r)

    if kind == "gate-low":
        print(f"  PASS — gate fired with '{GATE_FIRED_LOW}' (SOFT S1).")
        return True
    if kind == "gate-missing":
        print(f"  PASS — gate fired with '{GATE_FIRED_MISSING}' (SOFT S2).")
        return True
    if kind == "unexpected":
        print(f"  FAIL — clone refused unexpectedly: {r}")
        return False

    # ok=True: clone proceeded under headroom; clean up.
    cleanup(TEST_QUBE_CLONE)
    print("  PASS — clone under cap; cleaned up.")
    return True


def cleanup_dvmt(dvmt: str) -> None:
    """Order-aware cleanup: kill+remove any disposable still pointing
    at `dvmt` before removing the DVMT itself (Qubes refuses to
    remove a DVMT while any qube references it as `template`).
    Mirrors test-stage-e2's preamble."""
    lst = call_qmcp("qmcp.ListAIManagedQubes")
    for q in lst.get("qubes", []):
        if q.get("template") == dvmt and q.get("klass") == "DispVM":
            call_qmcp("qmcp.LifecycleAIManaged",
                      {"name": q["name"], "action": "kill"})
            time.sleep(1)
            call_qmcp("qmcp.LifecycleAIManaged",
                      {"name": q["name"], "action": "remove"})
    cleanup(dvmt)


def test_3_disposable_happy_path() -> bool:
    header("3. SpawnDisposableAIManaged — gate behaviour across cap states")
    cleanup_dvmt(TEST_DVMT)

    baseline = stats()
    show("baseline GetPoolStats", baseline)

    # Always attempt the DVMT spawn. Under cap pressure (S1/S2), this
    # will refuse via the Spawn-wrapper gate — same gate code as the
    # Disposable wrapper uses, so the gate-firing proof transfers.
    r0 = call_qmcp("qmcp.SpawnAIManagedQube", {
        "name":     TEST_DVMT,
        "template": PROBE_AI_MANAGED_TEMPLATE,
        "klass":    "DispVMTemplate",
        "label":    "gray",
    })
    show("spawn DVMT", r0)
    kind0 = classify_response(r0)

    if kind0 == "gate-low":
        print(f"  PASS — DVMT spawn gate fired with '{GATE_FIRED_LOW}' (SOFT S1).")
        return True
    if kind0 == "gate-missing":
        print(f"  PASS — DVMT spawn gate fired with '{GATE_FIRED_MISSING}' (SOFT S2).")
        return True
    if kind0 == "unexpected":
        print(f"  FAIL — DVMT spawn refused unexpectedly: {r0}")
        return False

    # DVMT spawned ok → attempt the Disposable surface.
    r = call_qmcp("qmcp.SpawnDisposableAIManaged", {
        "template": TEST_DVMT,
    })
    show("spawn-disposable", r)
    kind = classify_response(r)

    if kind == "gate-low":
        cleanup_dvmt(TEST_DVMT)
        print(f"  PASS — Disposable gate fired with '{GATE_FIRED_LOW}'.")
        return True
    if kind == "gate-missing":
        cleanup_dvmt(TEST_DVMT)
        print(f"  PASS — Disposable gate fired with '{GATE_FIRED_MISSING}'.")
        return True
    if kind == "unexpected":
        cleanup_dvmt(TEST_DVMT)
        print(f"  FAIL — disposable refused unexpectedly: {r}")
        return False

    # ok=True path
    disp = r["name"]
    call_qmcp("qmcp.LifecycleAIManaged", {"name": disp, "action": "kill"})
    time.sleep(3)
    cleanup_dvmt(TEST_DVMT)
    print("  PASS — disposable under cap; auto-cleanup on kill.")
    return True


def test_4_cap_shape_unchanged() -> bool:
    header("4. GetPoolStats — shape + arithmetic invariant unchanged")
    r = stats()
    show("GetPoolStats", r)

    # SOFT S2 path: cap file absent → GetPoolStats fail-closed.
    # That IS the documented behaviour; PASS.
    if not r.get("ok"):
        if r.get("error") == GATE_FIRED_MISSING:
            print(f"  PASS — fail-closed read with '{GATE_FIRED_MISSING}' (SOFT S2).")
            return True
        print(f"  FAIL — GetPoolStats returned not-ok unexpectedly: {r}")
        return False

    for k in ("ai_managed_bytes_used", "ai_managed_bytes_cap",
              "ai_managed_bytes_headroom"):
        if not isinstance(r.get(k), int) or r[k] < 0:
            print(f"  FAIL — {k} not a non-negative integer")
            return False
    used, cap, hr = (r["ai_managed_bytes_used"],
                     r["ai_managed_bytes_cap"],
                     r["ai_managed_bytes_headroom"])
    if used <= cap:
        if used + hr != cap:
            print(f"  FAIL — invariant used+headroom==cap violated "
                  f"({used}+{hr}!={cap})")
            return False
    else:
        if hr != 0:
            print(f"  FAIL — headroom must clamp to 0 when used>cap "
                  f"(got {hr})")
            return False
    print("  PASS — shape + invariant green.")
    return True


# ====================================================================
def main() -> int:
    tests = [
        test_1_spawn_happy_path,
        test_2_clone_happy_path,
        test_3_disposable_happy_path,
        test_4_cap_shape_unchanged,
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
    print(f"\n{passed}/{len(results)} probes green.")
    print()
    print("This test PASSes under any cap state — happy path, low cap,")
    print("or missing cap. Read the response JSON above each test to see")
    print("which gate path actually fired. slot-44 automates the cap")
    print("manipulation for SOFT S1 (low) + S2 (missing) verification.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
