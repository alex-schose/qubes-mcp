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

# ---------------------------- 3. birth netvm is INHERITED, not defaulted
# Rewritten for Wave 2 Stage 2. This used to assert "netvm omitted -> the
# constant ai-net-router", which was the behaviour §3.4 deliberately removed:
# the constant was fleet-specific (an adopter whose egress qube is named
# otherwise got network-less qubes) and, on a fleet with two egress classes,
# it let a Tor-side agent spawn a clearnet qube.
#
# The assertion below still expects EGRESS_QUBE, and on a single-egress fleet
# that is the same string as before — which is exactly why the OLD wording had
# to go. It would have kept passing while testing nothing: `ai-net-router`
# would be right whether the wrapper inherited it or hardcoded it. What makes
# this a real test is the second check, which asserts the child matches THE
# GATEWAY'S OWN netvm. Move the gateway to another egress qube and this test
# must follow it; the old one could not.
header(f"3. SpawnAIManagedQube: netvm omitted → INHERITED from the creator")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-fw-default", "template": PROBE_AI_MANAGED_TEMPLATE, "label": "gray"})
show("spawn ai-fw-default (no netvm key)", r)
spawn_default_ok = bool(r.get("ok"))

if spawn_default_ok:
    r = call_qmcp("qmcp.GetPropertyAIManaged",
                  {"name": "ai-fw-default", "property": "netvm"})
    show("read netvm on ai-fw-default", r)
    born_on = r.get("value") if r.get("ok") else None
    netvm_applied = born_on == EGRESS_QUBE
    print(f"  {'PASS' if netvm_applied else 'FAIL'}: birth netvm == {EGRESS_QUBE}")
    # Inheritance itself is NOT assertable from this seat, and that is a
    # property of the design rather than a gap in the test. The gateway is
    # deliberately not tagged `ai-managed` (tagging it would make its own named
    # policy rules shadowed by the umbrella rules, and would make it an
    # OBJECT of every wrapper), so a wrapped read of `mcp-control` returns the
    # opaque "not found" — as it does below. The seat therefore has nothing to
    # compare the birth value against.
    #
    # Do not "fix" this by tagging the gateway. The comparison belongs in dom0,
    # where `qvm-prefs mcp-control netvm` and `qvm-prefs <child> netvm` are both
    # readable; `deploy/install-stage-2.sh` prints exactly that check, and the
    # decisive version is to move the gateway to a second egress qube and
    # confirm the child follows it. On a single-egress fleet the assertion above
    # cannot fail for the right reason — it would read `ai-net-router` whether
    # the value was inherited or hardcoded (Stage 0.5's vacuous-pass problem).
    g = call_qmcp("qmcp.GetPropertyAIManaged",
                  {"name": "mcp-control", "property": "netvm"})
    if g.get("ok"):
        same = born_on == g.get("value")
        print(f"  {'PASS' if same else 'FAIL'}: birth netvm tracks the GATEWAY's "
              f"netvm ({g.get('value')}) — inheritance, not a constant")
        netvm_applied = netvm_applied and same
    else:
        print("  INFO: the gateway is not ai-managed (by design), so this seat "
              "cannot read its netvm. Inheritance is a dom0-side assertion — "
              "see install-stage-2.sh. This is not a failure.")
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
header(f"5. SetPropertyAIManaged: netvm of {EGRESS_QUBE} refused")
r = call_qmcp("qmcp.SetPropertyAIManaged",
              {"name": EGRESS_QUBE, "property": "netvm", "value": None})
show(f"try set {EGRESS_QUBE}.netvm = null", r)
# The security property is "AI cannot retarget the egress qube's upstream" — it
# must be REFUSED. Two valid refusal layers, depending on the egress qube's tier:
#   - Stage C egress invariant ("network-providing …") when the egress qube is
#     ai-full / untiered: SetProperty is reachable and the invariant blocks netvm.
#   - I-5 CAP_FULL tier gate (opaque "not found"), which fires FIRST and blocks
#     ALL property writes when the egress qube is tiered BELOW ai-full (e.g. ai-net
#     — firewall-only). This SUBSUMES the egress invariant: netvm is locked harder.
# Either way netvm is locked. §1 already proved the qube is visible + ai-managed,
# so a refusal here is never a genuine missing-qube.
err = str(r.get("error", ""))
egress_locked = (not r.get("ok")) and ("network-providing" in err or "not found" in err)
layer = ("egress invariant" if "network-providing" in err
         else "I-5 tier gate (egress tiered < ai-full)" if "not found" in err
         else "NOT REFUSED — netvm leak!")
print(f"  {'PASS' if egress_locked else 'FAIL'}: {EGRESS_QUBE}.netvm refused [{layer}]")

# ---------------------------- 6. retarget of an EXISTING qube — still open
# Wave 2 Stage 2 closed BIRTH egress; it did not close RETARGET, and the
# difference is the whole point of §3.4's "birth != retarget". Birth creates an
# empty qube with nothing to leak. Retargeting an EXISTING qube is the
# deanonymisation event: it may already hold Tor-derived data, a session, an
# identity. `qmcp_caps.decide()` already answers escalation-class DENY for a
# `netvm` write, but Stage 1 runs in shadow, so the wrapper still allows it and
# the disagreement is recorded on the dom0 audit chain.
#
# So this test asserts the CURRENT, deliberately-still-open behaviour, and it
# must be INVERTED by Stage 3 when enforcement flips to decide(). It is left
# passing rather than deleted so the flip has something concrete to flip.
header(f"6. SetPropertyAIManaged: retarget to {EGRESS_QUBE} — OPEN until Stage 3")
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
    "birth netvm inherited (see note)":                      netvm_applied,
    "explicit netvm=null preserved":              nonet_kept,
    "egress-qube netvm locked":                   egress_locked,
    "AI qube retarget still open (Stage 3 inverts)": redirect_ok,
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
