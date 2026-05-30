#!/usr/bin/env python3
"""Stage F1 test plan — run from mcp-control after slot-12.sh applied.

Verifies the feature.Set wrapper (qmcp.SetFeatureAIManaged):

  1. Round-trip: set a benign feature on an ai-managed qube and read it
     back from the wrapper's echoed value; confirm boolean coercion
     (True -> "1", False -> "" or removed — Qubes may store an empty
     feature value or treat empty-as-removal, both are valid falsy).
  2. Deny: setting `internal` on an ai-managed qube is refused
     (operator-only) — AI cannot hide a qube from the operator's menus.
  3. Cross-ref accept: a cross-VM feature key (audiovm) pointing at an
     ai-managed qube succeeds.
  4. Cross-ref refuse (opaque): the same key pointing at an untagged
     qube AND at a nonexistent qube both fail with the SAME opaque
     message — the surface is not an existence oracle.
  5. Untagged target: setting any feature on an untagged operator qube
     returns the literal opaque "not found".

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
from qubes_mcp.tools.qubes_feature_set import qubes_feature_set  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"   # ai-managed TemplateVM
PROBE_AI_MANAGED_REF = "ai-debian-13"        # any ai-managed qube, used as a cross-ref value
PROBE_UNTAGGED = "sys-firewall"              # exists, NOT ai-managed
PROBE_NONEXISTENT = "no-such-qube-zzz"       # does not exist

TEST_QUBE = "ai-feat-f1"


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


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftover test qube")
cleanup(TEST_QUBE)

# ---------------------------- setup: spawn a no-network AppVM target
header(f"setup — spawn ai-managed AppVM ({TEST_QUBE}, no netvm)")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": TEST_QUBE, "template": PROBE_AI_MANAGED_TEMPLATE,
               "label": "gray", "netvm": None})
show(f"spawn {TEST_QUBE}", r)
target_ok = bool(r.get("ok")) and TEST_QUBE in visible_in_list()
if not target_ok:
    print("  WARN: target spawn failed; dependent checks will be skipped")

# ---------------------------- 1. round-trip set + readback + bool coercion
header("1. feature.Set round-trip + boolean coercion")
roundtrip_ok = bool_true_ok = bool_false_ok = False
if target_ok:
    r = qubes_feature_set(TEST_QUBE, "qmcp-test-marker", "hello")
    show("set qmcp-test-marker=hello", r)
    roundtrip_ok = (r.get("ok") and r.get("feature") == "qmcp-test-marker"
                    and r.get("value") == "hello")

    r = qubes_feature_set(TEST_QUBE, "qmcp-test-flag", True)
    show("set qmcp-test-flag=True", r)
    bool_true_ok = r.get("ok") and r.get("value") == "1"

    # False coerces to "" in the wrapper; what Qubes stores is the
    # interesting bit. The Admin API may keep an empty-string feature
    # (readback "") or treat empty-as-removal (readback None). Both are
    # legitimate falsy states, so we accept either and print what we got.
    r = qubes_feature_set(TEST_QUBE, "qmcp-test-flag", False)
    show("set qmcp-test-flag=False", r)
    bool_false_ok = r.get("ok") and r.get("value") in ("", None)
print(f"  {'PASS' if roundtrip_ok and bool_true_ok and bool_false_ok else 'FAIL'}: "
      f"set echoes value back + bool coercion (True→\"1\", False→\"\"/None)")

# ---------------------------- 2. deny internal
header("2. setting `internal` is operator-only (refused)")
internal_refused = False
if target_ok:
    r = qubes_feature_set(TEST_QUBE, "internal", "1")
    show("set internal=1", r)
    internal_refused = (not r.get("ok")) and "operator-only" in r.get("error", "")
print(f"  {'PASS' if internal_refused else 'FAIL'}: internal refused (operator-only)")

# ---------------------------- 3. cross-ref accepts an ai-managed value
header(f"3. cross-VM feature (audiovm) → ai-managed qube ({PROBE_AI_MANAGED_REF}) accepted")
crossref_accept_ok = False
if target_ok:
    r = qubes_feature_set(TEST_QUBE, "audiovm", PROBE_AI_MANAGED_REF)
    show(f"set audiovm={PROBE_AI_MANAGED_REF}", r)
    crossref_accept_ok = r.get("ok") and r.get("value") == PROBE_AI_MANAGED_REF
print(f"  {'PASS' if crossref_accept_ok else 'FAIL'}: cross-ref to ai-managed accepted")

# ---------------------------- 4. cross-ref refuses non-ai-managed, OPAQUELY
header("4. cross-VM feature → untagged AND nonexistent both refused identically")
r_untagged = qubes_feature_set(TEST_QUBE, "audiovm", PROBE_UNTAGGED) if target_ok else {}
r_missing = qubes_feature_set(TEST_QUBE, "guivm", PROBE_NONEXISTENT) if target_ok else {}
show(f"set audiovm={PROBE_UNTAGGED} (untagged)", r_untagged)
show(f"set guivm={PROBE_NONEXISTENT} (missing)", r_missing)
# Both must fail with the cross-ref message and reveal nothing about
# whether the referenced qube exists (no "not found" / "is not ai-managed"
# distinction, no leaked qube name).
opaque_phrase = "must reference an ai-managed qube"
untagged_opaque = (not r_untagged.get("ok")
                   and opaque_phrase in r_untagged.get("error", "")
                   and PROBE_UNTAGGED not in r_untagged.get("error", ""))
missing_opaque = (not r_missing.get("ok")
                  and opaque_phrase in r_missing.get("error", "")
                  and PROBE_NONEXISTENT not in r_missing.get("error", ""))
crossref_opaque_ok = target_ok and untagged_opaque and missing_opaque
print(f"  {'PASS' if crossref_opaque_ok else 'FAIL'}: "
      f"untagged and missing both opaque, neither leaks existence")

# ---------------------------- 5. untagged target → opaque "not found"
header(f"5. feature.Set on untagged qube ({PROBE_UNTAGGED}) → opaque 'not found'")
r = qubes_feature_set(PROBE_UNTAGGED, "qmcp-test-marker", "x")
show(f"set on {PROBE_UNTAGGED}", r)
untagged_target_ok = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if untagged_target_ok else 'FAIL'}: refused with literal 'not found'")

# ---------------------------------------------------------- summary
header("Stage F1 test plan — summary")
results = {
    "round-trip set + echo + bool coercion":      roundtrip_ok and bool_true_ok and bool_false_ok,
    "internal refused (operator-only)":           internal_refused,
    "cross-ref to ai-managed accepted":           crossref_accept_ok,
    "cross-ref untagged+missing opaque":          crossref_opaque_ok,
    "untagged target opaque 'not found'":         untagged_target_ok,
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
