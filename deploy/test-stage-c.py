#!/usr/bin/env python3
"""Stage C test plan — run from mcp-control after slot-2.sh applied.

Verifies:
  1. ai-net-router is the only ai-managed network-providing qube AI sees.
  2. The previously-provisioned ai-sys-* qubes are no longer ai-managed
     (operator-side now; invisible to AI).
  3. qmcp.SpawnAIManagedQube defaults netvm to ai-net-router when omitted.
  4. Explicit netvm=null keeps the qube netvm-less (no defaulting).
  5. SetPropertyAIManaged refuses to mutate ai-net-router.netvm
     (egress-qube invariant — operator-only).
  6. SetPropertyAIManaged can point an AI qube's netvm at ai-net-router.
  7. admin.vm.firewall.Set + Get round-trip on an ai-managed qube.
  8. Negative: admin.vm.firewall.Set against an untagged operator qube refused.

Cleans up its test qubes at the end. Does NOT touch ai-net-router or
any operator qube.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp, call_admin  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"
PROBE_UNTAGGED = "sys-firewall"
EGRESS_QUBE = "ai-net-router"
FORMER_AI_SYS = ["ai-sys-net", "ai-sys-firewall", "ai-sys-tor", "ai-sys-vpn"]

# Qubes canonicalises dstports=N → dstports=N-N on Set. We send the
# canonical form so round-trip equality is byte-exact.
TEST_RULES = (
    "action=accept proto=tcp dstports=443-443\n"
    "action=accept proto=tcp dstports=80-80\n"
    "action=drop\n"
)


# ====================================================================
def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r: dict) -> None:
    out = dict(r)
    for k in ("stdout", "stderr", "rules"):
        if isinstance(out.get(k), str) and len(out[k]) > 200:
            out[k] = out[k][:200] + "... (truncated)"
    print(f"  {label:48s} → {json.dumps(out)}")


def cleanup(*qube_names: str) -> None:
    for n in qube_names:
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "kill"})
        time.sleep(1)
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "remove"})


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftovers")
cleanup("ai-fw-default", "ai-fw-nonet", "ai-fw-rules", "ai-fw-redirect")

# ---------------------------- 1. ai-net-router is ai-managed and network-providing
header(f"1. {EGRESS_QUBE} is ai-managed and provides_network")
r = call_qmcp("qmcp.ListAIManagedQubes")
visible = {q["name"]: q for q in r.get("qubes", [])}
egress_visible = EGRESS_QUBE in visible
print(f"  {'PASS' if egress_visible else 'FAIL'}: {EGRESS_QUBE} visible in ListAIManagedQubes")

if egress_visible:
    r = call_qmcp("qmcp.GetPropertyAIManaged",
                  {"name": EGRESS_QUBE, "property": "provides_network"})
    show(f"read {EGRESS_QUBE}.provides_network", r)
    provides_net = r.get("ok") and r.get("value") is True
    print(f"  {'PASS' if provides_net else 'FAIL'}: provides_network is true")
else:
    provides_net = False

# ---------------------------- 2. former ai-sys-* are no longer ai-managed
header("2. Former ai-sys-* qubes are no longer ai-managed (invisible to AI)")
former_invisible = True
for q in FORMER_AI_SYS:
    seen = q in visible
    status = "PASS" if not seen else "FAIL"
    print(f"  {status}: {q:18s} {'invisible' if not seen else 'STILL VISIBLE (untag missed)'}")
    if seen:
        former_invisible = False

# ---------------------------- 3. default netvm applied when omitted
header(f"3. SpawnAIManagedQube: netvm omitted → defaults to {EGRESS_QUBE}")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-fw-default", "template": PROBE_AI_MANAGED_TEMPLATE, "label": "gray"})
show("spawn ai-fw-default (no netvm key)", r)
spawn_default_ok = bool(r.get("ok"))

if spawn_default_ok:
    r = call_qmcp("qmcp.GetPropertyAIManaged",
                  {"name": "ai-fw-default", "property": "netvm"})
    show("read netvm on ai-fw-default", r)
    netvm_applied = r.get("ok") and r.get("value") == EGRESS_QUBE
    print(f"  {'PASS' if netvm_applied else 'FAIL'}: default netvm == {EGRESS_QUBE}")
else:
    print("  FAIL: spawn failed; skipping netvm check")
    netvm_applied = False

# ---------------------------- 4. explicit null skips defaulting
header("4. SpawnAIManagedQube: netvm=null → no default applied")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-fw-nonet", "template": PROBE_AI_MANAGED_TEMPLATE,
               "label": "gray", "netvm": None})
show("spawn ai-fw-nonet (netvm=null)", r)
spawn_nonet_ok = bool(r.get("ok"))

if spawn_nonet_ok:
    r = call_qmcp("qmcp.GetPropertyAIManaged",
                  {"name": "ai-fw-nonet", "property": "netvm"})
    show("read netvm on ai-fw-nonet", r)
    nonet_kept = r.get("ok") and r.get("value") is None
    print(f"  {'PASS' if nonet_kept else 'FAIL'}: explicit null preserved")
else:
    print("  FAIL: spawn failed; skipping null-netvm check")
    nonet_kept = False

# ---------------------------- 5. egress invariant — netvm of router refused
header(f"5. SetPropertyAIManaged: netvm of {EGRESS_QUBE} refused (egress invariant)")
r = call_qmcp("qmcp.SetPropertyAIManaged",
              {"name": EGRESS_QUBE, "property": "netvm", "value": None})
show(f"try set {EGRESS_QUBE}.netvm = null", r)
egress_locked = (not r.get("ok")) and "network-providing" in str(r.get("error", ""))
print(f"  {'PASS' if egress_locked else 'FAIL'}: refused with the egress invariant message")

# ---------------------------- 6. AI qube netvm → ai-net-router works
header(f"6. SetPropertyAIManaged: AI qube netvm → {EGRESS_QUBE} works")
redirect_ok = False
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-fw-redirect", "template": PROBE_AI_MANAGED_TEMPLATE,
               "label": "gray", "netvm": None})
if r.get("ok"):
    r = call_qmcp("qmcp.SetPropertyAIManaged",
                  {"name": "ai-fw-redirect", "property": "netvm", "value": EGRESS_QUBE})
    show(f"set ai-fw-redirect.netvm = {EGRESS_QUBE}", r)
    redirect_ok = bool(r.get("ok"))
    if redirect_ok:
        r = call_qmcp("qmcp.GetPropertyAIManaged",
                      {"name": "ai-fw-redirect", "property": "netvm"})
        redirect_ok = r.get("ok") and r.get("value") == EGRESS_QUBE
print(f"  {'PASS' if redirect_ok else 'FAIL'}: ai-fw-redirect netvm now {EGRESS_QUBE}")

# ---------------------------- 7. firewall Set + Get round-trip
header("7. admin.vm.firewall.Set + Get on an ai-managed qube")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-fw-rules", "template": PROBE_AI_MANAGED_TEMPLATE, "label": "gray"})
show("spawn ai-fw-rules", r)
spawn_rules_ok = bool(r.get("ok"))

set_ok = read_ok = roundtrip_ok = False
if spawn_rules_ok:
    set_r = call_admin("admin.vm.firewall.Set", "ai-fw-rules", payload=TEST_RULES.encode())
    show("set firewall rules", set_r)
    set_ok = bool(set_r.get("ok"))

    get_r = call_admin("admin.vm.firewall.Get", "ai-fw-rules")
    show("get firewall rules", get_r)
    read_ok = bool(get_r.get("ok"))

    if set_ok and read_ok:
        got = get_r.get("stdout", "")
        sent_lines = [ln.strip() for ln in TEST_RULES.splitlines() if ln.strip()]
        got_lines = [ln.strip() for ln in got.splitlines() if ln.strip()]
        roundtrip_ok = all(ln in got_lines for ln in sent_lines)
        print(f"  {'PASS' if roundtrip_ok else 'FAIL'}: rules round-trip "
              f"(sent {len(sent_lines)} lines, got {len(got_lines)})")

# ---------------------------- 8. negative — untagged qube refused
header(f"8. Negative — firewall.Set on {PROBE_UNTAGGED} (untagged)")
r = call_admin("admin.vm.firewall.Set", PROBE_UNTAGGED, payload=b"action=drop\n")
show(f"set rules on {PROBE_UNTAGGED}", r)
refused = (not r.get("ok"))
print(f"  {'PASS' if refused else 'FAIL'}: policy refused (or qube absent — indistinguishable)")

# ---------------------------------------------------------- summary
header("Stage C test plan — summary")
results = {
    f"{EGRESS_QUBE} visible + provides_network":  egress_visible and provides_net,
    "former ai-sys-* invisible":                  former_invisible,
    "default netvm applied":                      netvm_applied,
    "explicit netvm=null preserved":              nonet_kept,
    "egress-qube netvm locked":                   egress_locked,
    "AI qube can be retargeted at egress":        redirect_ok,
    "firewall set+get round-trip":                set_ok and read_ok and roundtrip_ok,
    "untagged target refused":                    refused,
}
for label, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}: {label}")
print(f"\n  Total: {sum(results.values())}/{len(results)} green")

# ---------------------------------------------------------- cleanup
header("Cleanup")
cleanup("ai-fw-default", "ai-fw-nonet", "ai-fw-rules", "ai-fw-redirect")
r = call_qmcp("qmcp.ListAIManagedQubes")
remaining = [q["name"] for q in r.get("qubes", [])]
print(f"  Remaining ai-managed qubes: {remaining}")

sys.exit(0 if all(results.values()) else 1)
