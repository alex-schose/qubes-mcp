#!/usr/bin/env python3
"""Stage F3 test plan — run from mcp-control after slot-14.sh applied.

Verifies qmcp.GetPoolStats — the AI-scoped disk-budget read.

  1. Response shape: returns {used, cap, headroom} with all three as
     non-negative integers, and the arithmetic invariant
     `used + headroom == cap` holds when used <= cap.
  2. Untagged volumes excluded (sanity bound): `used` is bounded by
     N * 100 GiB where N is the count of currently ai-managed qubes.
     A typical operator setup carries hundreds of GiB across
     templates + sys-* qubes + user AppVMs; if the wrapper were
     summing untagged volumes the bound would fail immediately. Loose
     by design — a stricter "exact expected sum" is unverifiable from
     mcp-control without an AI-side volume-read surface (which the
     trust model intentionally denies).
  3. Spawn-delta + remove-baseline: baseline `used`, spawn an
     ai-managed AppVM, `used` strictly increases. Remove the qube,
     `used` returns to baseline. Proves the sum tracks ai-managed-set
     membership both ways and nothing is stuck.
  4. Payload ignored: posting a non-empty JSON object via the helper
     still succeeds with the same shape — the wrapper has an empty
     kwargs whitelist (no smuggling surface).

SOFT (manual, informational): edit /etc/qmcp/pool-cap in dom0 to a
different integer, re-run the test, confirm `cap` reflects the new
value WITHOUT a policy-daemon restart. Tests below cannot drive this
because mcp-control has no dom0 write access.

Spawns one disposable-free AppVM (no network) as the test target and
removes it at the end. Does NOT touch any operator qube.
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
TEST_QUBE = "ai-pool-f3"

# Loose sanity ceiling for test 2. 100 GiB per ai-managed qube is
# already generous (typical AppVMs sum to a few GiB of root snapshots
# plus a couple of GiB of private volume); a wrapper that erroneously
# summed operator qubes would blow past this on any real Qubes host.
PER_QUBE_CEILING_BYTES = 100 * 1024**3


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


def visible_in_list() -> set[str]:
    r = call_qmcp("qmcp.ListAIManagedQubes")
    return {q["name"] for q in r.get("qubes", [])}


def gib(n: int) -> str:
    return f"{n / 1024**3:.2f} GiB"


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftover test qube")
cleanup(TEST_QUBE)

# ---------------------------- 1. response shape + arithmetic invariant
header("1. response shape + arithmetic invariant (used + headroom == cap)")
r0 = qubes_get_pool_stats()
show("baseline GetPoolStats", r0)
shape_ok = (
    r0.get("ok") is True
    and isinstance(r0.get("ai_managed_bytes_used"), int)
    and isinstance(r0.get("ai_managed_bytes_cap"), int)
    and isinstance(r0.get("ai_managed_bytes_headroom"), int)
    and r0["ai_managed_bytes_used"] >= 0
    and r0["ai_managed_bytes_cap"] >= 0
    and r0["ai_managed_bytes_headroom"] >= 0
)
arithmetic_ok = False
if shape_ok:
    used = r0["ai_managed_bytes_used"]
    cap = r0["ai_managed_bytes_cap"]
    headroom = r0["ai_managed_bytes_headroom"]
    if used <= cap:
        arithmetic_ok = (used + headroom == cap)
    else:
        # Over-cap is legal (the cap is advisory; AI may already exceed
        # it when the cap is lowered) — headroom must be 0 in that case.
        arithmetic_ok = (headroom == 0)
    print(f"  used={gib(used)}  cap={gib(cap)}  headroom={gib(headroom)}")
print(f"  {'PASS' if shape_ok and arithmetic_ok else 'FAIL'}: "
      f"triple present + invariant holds")

# ---------------------------- 2. untagged volumes excluded (sanity bound)
header("2. untagged operator volumes excluded (loose ceiling check)")
n_ai_managed = len(visible_in_list())
ceiling = max(1, n_ai_managed) * PER_QUBE_CEILING_BYTES
under_ceiling = False
if shape_ok:
    used = r0["ai_managed_bytes_used"]
    under_ceiling = used < ceiling
    print(f"  ai-managed qubes visible: {n_ai_managed}")
    print(f"  loose ceiling (N * 100 GiB): {gib(ceiling)}")
    print(f"  used: {gib(used)}")
print(f"  {'PASS' if under_ceiling else 'FAIL'}: "
      f"used < N * 100 GiB (would fail dramatically if operator volumes summed)")

# ---------------------------- 3. spawn-delta positive + remove-baseline
header(f"3. spawn ai-managed AppVM ({TEST_QUBE}) → used grows; remove → used returns")
spawn_ok = delta_positive = baseline_restored = False
if shape_ok:
    r = call_qmcp("qmcp.SpawnAIManagedQube",
                  {"name": TEST_QUBE, "template": PROBE_AI_MANAGED_TEMPLATE,
                   "label": "gray", "netvm": None})
    show(f"spawn {TEST_QUBE}", r)
    spawn_ok = bool(r.get("ok")) and TEST_QUBE in visible_in_list()

    if spawn_ok:
        # Volume sizes are reported by qubesd as soon as the qube exists;
        # no need to start it. Small settle delay for clean readback.
        time.sleep(1)
        r1 = qubes_get_pool_stats()
        show("after spawn", r1)
        if r1.get("ok"):
            delta = r1["ai_managed_bytes_used"] - r0["ai_managed_bytes_used"]
            print(f"  delta: {gib(delta)}")
            delta_positive = delta > 0

        cleanup(TEST_QUBE)
        time.sleep(1)
        r2 = qubes_get_pool_stats()
        show("after remove", r2)
        if r2.get("ok"):
            baseline_restored = (r2["ai_managed_bytes_used"] ==
                                 r0["ai_managed_bytes_used"])
print(f"  {'PASS' if spawn_ok and delta_positive and baseline_restored else 'FAIL'}: "
      f"spawn → delta>0; remove → used == baseline")

# ---------------------------- 4. empty kwargs whitelist (payload ignored)
header("4. payload ignored — wrapper accepts arbitrary JSON, ignores it")
r = call_qmcp("qmcp.GetPoolStats",
              {"bogus_key": "value", "nested": {"x": 1}, "list": [1, 2, 3]})
show("call with non-empty payload", r)
payload_ignored_ok = (
    r.get("ok") is True
    and isinstance(r.get("ai_managed_bytes_used"), int)
    and isinstance(r.get("ai_managed_bytes_cap"), int)
    and isinstance(r.get("ai_managed_bytes_headroom"), int)
)
print(f"  {'PASS' if payload_ignored_ok else 'FAIL'}: "
      f"wrapper returned the triple regardless of payload")

# ---------------------------------------------------------- SOFT block
header("SOFT — manual cap-edit check (cannot drive from mcp-control)")
print("  In dom0, edit /etc/qmcp/pool-cap to a different integer:")
print("    sudo sh -c 'echo 107374182400 > /etc/qmcp/pool-cap'   # 100 GiB")
print("  Then re-run this test — `cap` should reflect the new value on the")
print("  next GetPoolStats call, with NO policy-daemon restart.")

# ---------------------------------------------------------- summary
header("Stage F3 test plan — summary")
results = {
    "response shape + arithmetic invariant":      shape_ok and arithmetic_ok,
    "untagged volumes excluded (sanity bound)":   under_ceiling,
    "spawn-delta positive + remove-baseline":     spawn_ok and delta_positive and baseline_restored,
    "payload ignored (empty kwargs whitelist)":   payload_ignored_ok,
}
for label, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}: {label}")
print(f"\n  Total: {sum(results.values())}/{len(results)} green")

# ---------------------------------------------------------- cleanup
header("Cleanup")
cleanup(TEST_QUBE)
r = call_qmcp("qmcp.ListAIManagedQubes")
remaining = [q["name"] for q in r.get("qubes", [])]
print(f"  Remaining ai-managed qubes: {remaining}")

sys.exit(0 if all(results.values()) else 1)
