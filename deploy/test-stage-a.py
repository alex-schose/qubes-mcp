#!/usr/bin/env python3
"""Stage A test plan — run from mcp-control after dom0 deploy.

Exercises the four qmcp.* RPCs and the tag-scoped lifecycle methods.

MODE-AGNOSTIC. This suite runs from the AI seat and by design CANNOT read
/etc/qmcp/tier-default, so it does not assume whether the fleet flip has
happened. The CAP_FULL assertions test COHERENCE: every CAP_FULL surface on an
untiered qube must agree — all opaque-denied (post-flip least privilege) or all
successful (compat, where untiered == ai-full is the documented default). A
MIXED result is the real defect and is what fails the run. An earlier version
asserted post-flip unconditionally and therefore failed on a correct, freshly
installed compat box.

A qube spawned via qmcp.SpawnAIManagedQube is born
UNTIERED (the create path strips every inherited tier tag), so post-flip it
resolves to ai-ro: READS succeed, but every CAP_FULL op (start/shutdown/kill/
pause/unpause/remove, SetProperty, SetFeature, Clone, Attach, Detach) is DENIED
with the opaque {"ok": false, "error": "not found"} — byte-identical to a
missing/untagged qube (no tier oracle). AI can create a qube but cannot
lifecycle/remove it until an operator tiers it ai-full.

So the lifecycle happy-path (start/shutdown/remove SUCCEEDS) is proven ONLY
against an operator-tagged ai-full fixture, whose name is passed in via the
QMCP_A_FULL env var; absent → those steps SKIP (the slot covers the
destructive happy-path on a throwaway probe it tiered in dom0). The DENIAL path
(CAP_FULL op on the untiered self-spawned qube → opaque NOT_FOUND) needs no
fixture and always runs — it is the anti-self-escalation assertion.

Before running, set the constants below to match your Qubes setup.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Make `qubes_mcp` importable when the repo isn't `pip install -e .`'d.
# Walks: deploy/test-stage-a.py → deploy/ → repo_root/ (which contains the
# qubes_mcp/ package directory). If you've run `pip install -e .` inside
# your venv, this insert is harmless and the package resolves via the venv.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

# An ai-managed TemplateVM (the one you enrolled). It must be tagged ai-full
# so the create-gate (which gates on the TEMPLATE's cap) lets the spawn through;
# the RESULT qube is still born untiered (tags stripped on create).
PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"

# Two qubes that exist on your system but are NOT tagged ai-managed.
# Defaults are common Qubes-installed names; adjust if yours differ.
PROBE_UNTAGGED_1 = "sys-firewall"
PROBE_UNTAGGED_2 = "personal"

# A truly nonexistent name.
PROBE_NONEXISTENT = "doesnotexist-xyz-test-probe"

# A TemplateVM that exists but is NOT tagged ai-managed (for cross-ref test).
# Default "debian-13" is the standard Qubes Debian template name. If your
# system uses a different name (any Fedora/Debian/Whonix variant), edit
# this to match a template you actually have.
UNTAGGED_TEMPLATE = "debian-13"

# OPTIONAL operator-tagged ai-full fixture. When set, the lifecycle happy-path
# (start → shutdown, non-destructive) runs against it; absent → SKIP. Only dom0
# can tag it ai-full (AI cannot self-tier), so the slot hands it in via env.
# NEVER removed/killed by this script — it is a shared fixture the operator owns.
PROBE_A_FULL = os.environ.get("QMCP_A_FULL") or None

# The wrapper's opaque refusal, emitted on stdout as {"ok":false,"error":
# "not found"}. A CAP_FULL tier denial and a missing/untagged target collapse to
# this SAME object — that opacity is the no-tier-oracle property. (This is a
# DIFFERENT surface from the MCP normaliser's empty-stdout sentinel "not found or
# refused"; the wrapper-emitted opacity we assert on the untiered qube is
# "not found".)
NOT_FOUND = {"ok": False, "error": "not found"}


# ====================================================================
def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r: dict) -> None:
    print(f"  {label:32s} → {json.dumps(r)}")


# ---------------------------------------------------------------- preamble
header("preamble — sanity")
print(f"  qrexec-client-vm exists: {os.path.exists('/usr/lib/qubes/qrexec-client-vm')}")

pre = call_qmcp("qmcp.GetPropertyAIManaged", {"name": "ai-scratch-1", "property": "klass"})
if pre.get("ok"):
    # A lingering untiered ai-scratch-1 CANNOT be removed by AI post-flip (kill/
    # remove are CAP_FULL → denied). Best-effort only; if it survives, note it —
    # the slot/dom0 cleans it. Never fail the run on a leftover.
    print("  ai-scratch-1 lingers from a prior run — attempting best-effort cleanup...")
    call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "kill"})
    time.sleep(2)
    call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "remove"})
    time.sleep(1)
    still = call_qmcp("qmcp.GetPropertyAIManaged", {"name": "ai-scratch-1", "property": "klass"})
    if still.get("ok"):
        print("  NOTE: ai-scratch-1 still present (untiered → AI cannot remove it post-flip);")
        print("        the slot/dom0 will clean it. Continuing.")

# ----------------------------------------------------- 1. existence leak
header("1. Existence-leak — qmcp.GetPropertyAIManaged on 4 probes")
probes = [
    (PROBE_AI_MANAGED_TEMPLATE, "klass"),  # ai-managed
    (PROBE_UNTAGGED_1,          "klass"),  # likely-existing operator qube
    (PROBE_UNTAGGED_2,          "klass"),  # likely-existing operator qube
    (PROBE_NONEXISTENT,         "klass"),  # nonexistent
]
responses = {}
for name, prop in probes:
    r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})
    responses[name] = json.dumps(r)
    show(name, r)

bad = [n for n in (PROBE_UNTAGGED_1, PROBE_UNTAGGED_2, PROBE_NONEXISTENT)
       if responses[n] != responses[PROBE_NONEXISTENT]]
existence_leak_ok = not bad
if bad:
    print(f"\n  FAIL: LEAK DETECTED: {bad} returned a response distinguishable from nonexistent.")
else:
    print("\n  PASS: untagged qubes return byte-identical 'not found' to nonexistent.")

# -------------------------------------------------------- 2. qubes_list
header("2. qubes_list — only ai-managed")
r = call_qmcp("qmcp.ListAIManagedQubes")
print(json.dumps(r, indent=2))
names = [q["name"] for q in r.get("qubes", [])]
print(f"\n  Visible names: {names}")

# -------------------------------------------------------- 3. qubes_spawn
# The create-gate gates on the TEMPLATE's capability (ai-full), so a spawn from
# an ai-full template SUCCEEDS; the create path then STRIPS every tier tag, so
# the RESULT qube (ai-scratch-1) is born UNTIERED → ai-ro. This is the seat the
# AI actually holds post-flip: it can mint a qube but not act on it.
header(f"3. Spawn ai-scratch-1 from {PROBE_AI_MANAGED_TEMPLATE} (born untiered)")
r = call_qmcp("qmcp.SpawnAIManagedQube", {
    "name": "ai-scratch-1",
    "template": PROBE_AI_MANAGED_TEMPLATE,
    "label": "gray",
})
show("spawn ai-scratch-1", r)
spawn_ok = bool(r.get("ok"))
if spawn_ok:
    print("  PASS: spawn succeeded (template ai-full → create allowed; result untiered).")
else:
    print("  NOTE: spawn did NOT succeed — check that the template is tagged ai-full")
    print(f"        (the create-gate gates on the template's cap). Response: {json.dumps(r)}")

r2 = call_qmcp("qmcp.ListAIManagedQubes")
names2 = [q["name"] for q in r2.get("qubes", [])]
print(f"  After spawn, list: {names2}")

# ---------------------------- 3b. Reads on the untiered self-spawned qube SUCCEED
# The umbrella (= ai-ro) read floor holds on the qube AI just created, even
# though it can't lifecycle it. Assert a couple of reads come back ok.
read_ok = None  # None => not exercised (spawn didn't succeed); True/False once run
if spawn_ok:
    header("3b. Reads on untiered ai-scratch-1 SUCCEED (ai-ro read floor)")
    read_ok = True
    for prop in ("klass", "power_state", "template"):
        rp = call_qmcp("qmcp.GetPropertyAIManaged", {"name": "ai-scratch-1", "property": prop})
        show(f"get {prop}", rp)
        read_ok &= bool(rp.get("ok"))
    print(f"  {'PASS' if read_ok else 'FAIL'}: reads on the self-spawned untiered qube succeed")

# ------------------- 3c. CAP_FULL ops on untiered ai-scratch-1 → opaque NOT_FOUND
# THE ANTI-SELF-ESCALATION ASSERTION. Post-flip an untiered qube (which AI just
# created and CANNOT self-tier) must DENY every CAP_FULL op with the opaque
# {"ok":false,"error":"not found"} — byte-identical to a missing/untagged target.
# If any of these ever SUCCEEDED it would be a real self-escalation, so this
# assertion stays strict and it DRIVES THE EXIT CODE (see the rollup): a False
# here makes the process exit 1, so the slot's exit-code-based run_mcp_test flips
# to `bad`. It needs no operator fixture — only that the self-spawn in step 3
# succeeded (spawn_ok); if the template wasn't ai-full the spawn is blocked and
# this guard is SKIPPED (None) and the rollup flags it loudly.
cap_full_denied = None
if spawn_ok:
    header("3c. CAP_FULL ops on untiered ai-scratch-1 → opaque NOT_FOUND (no self-escalation)")
    # ORDER MATTERS: non-destructive probes FIRST, `remove` LAST. These all run
    # against the same qube, so a `remove` partway down destroys the subject and
    # every later probe then answers "not found" for a trivial reason — a false
    # denial indistinguishable from a tier denial. Post-flip that was invisible
    # (everything is denied anyway); in compat the remove SUCCEEDS and the tail of
    # the list silently tested nothing. test-stage-I-5.py already orders it this
    # way, which is why it passed in both modes.
    cap_full_probes = [
        ("SetProperty memory", {"name": "ai-scratch-1", "property": "memory", "value": "400"},
         "qmcp.SetPropertyAIManaged"),
        ("SetFeature probe", {"name": "ai-scratch-1", "feature": "ai-a-probe", "value": "1"},
         "qmcp.SetFeatureAIManaged"),
        ("Lifecycle start",  {"name": "ai-scratch-1", "action": "start"},   "qmcp.LifecycleAIManaged"),
        ("Lifecycle kill",   {"name": "ai-scratch-1", "action": "kill"},    "qmcp.LifecycleAIManaged"),
        ("Lifecycle remove", {"name": "ai-scratch-1", "action": "remove"},  "qmcp.LifecycleAIManaged"),
    ]
    # COHERENCE, not a fixed expectation. This suite runs from the AI seat and by
    # design CANNOT read /etc/qmcp/tier-default, so it cannot know which mode the
    # box is in — and asserting post-flip unconditionally made this suite FAIL on
    # a correct, freshly-installed (compat) system, where untiered == ai-full is
    # the documented behaviour. What must hold in BOTH modes is that the surfaces
    # agree with each other:
    #     all denied   -> post-flip least privilege
    #     all succeed  -> compat (untiered == ai-full), the shipped default
    #     MIXED        -> the real bug: enforcement is incoherent across surfaces,
    #                     i.e. a split-brain window of the kind the I-4 coupled
    #                     flip exists to prevent.
    denied, succeeded, other = [], [], []
    for label, payload, svc in cap_full_probes:
        rr = call_qmcp(svc, payload)
        show(label, rr)
        if rr == NOT_FOUND:
            denied.append(label)
        elif isinstance(rr, dict) and rr.get("ok") is True:
            succeeded.append(label)
        else:
            other.append((label, rr))

    if other:
        cap_full_denied = False
        print("  FAIL — a CAP_FULL probe returned neither the opaque refusal nor success:")
        for label, rr in other:
            print(f"         {label}: {rr}")
    elif denied and succeeded:
        cap_full_denied = False
        print("  FAIL — INCOHERENT: some CAP_FULL ops on the untiered qube were denied "
              "and others succeeded.")
        print(f"         denied:    {denied}")
        print(f"         succeeded: {succeeded}")
        print("         One tier mode must apply to every surface at once; a split "
              "means a gate is missing on the surfaces that succeeded.")
    elif denied:
        cap_full_denied = True
        print(f"  PASS: POST-FLIP — every CAP_FULL op on the untiered qube collapses "
              f"to {json.dumps(NOT_FOUND)} (no self-escalation).")
    else:
        cap_full_denied = True
        print("  PASS: COMPAT (/etc/qmcp/tier-default absent or not 'ro') — every "
              "CAP_FULL op on the untiered qube succeeded, which is the documented "
              "compat behaviour (untiered == ai-full).")
        print("        This is NOT self-escalation: the qube is untiered, and in "
              "compat untiered carries full authority by design.")
        print("        Re-run after the flip to exercise least privilege.")

# ----------------------------------- 4. SetProperty cross-ref OPAQUE COLLAPSE
# The wrapper's cross-ref refusal must collapse "missing" and "untagged"
# into one byte-identical message that does NOT echo the value name —
# otherwise this surface is an existence oracle on every untagged qube
# in dom0. Probe both branches and assert the responses are identical
# AND neither response contains the probed name.
#
# NOTE post-flip: this cross-ref check fires BEFORE the CAP_FULL tier gate on
# an ai-full target, but ai-scratch-1 is untiered — so on ai-scratch-1 the tier
# gate would deny first with plain "not found". To keep proving the cross-ref
# OPACITY (a distinct property from the tier gate), run these probes against the
# QMCP_A_FULL fixture when available (there the wrapper reaches the cross-ref
# branch); absent → SKIP. The tier-gate NOT_FOUND on ai-scratch-1 is already
# proven in 3c above.
def cross_ref_probe(target: str, value: str) -> dict:
    return call_qmcp("qmcp.SetPropertyAIManaged", {
        "name": target,
        "property": "template",
        "value": value,
    })


header("4. SetProperty cross-ref OPAQUE — untagged vs. missing must be identical")
if not PROBE_A_FULL:
    print("  SKIP (no QMCP_A_FULL fixture) — cross-ref opacity needs a CAP_FULL")
    print("        target so the wrapper reaches the cross-ref branch (past the tier")
    print("        gate). The slot proves it on its dom0-tiered probe.")
    opaque_pass = None
else:
    probe_value = UNTAGGED_TEMPLATE
    r_untagged = cross_ref_probe(PROBE_A_FULL, probe_value)
    show(f"set template={probe_value} (untagged)", r_untagged)

    # With the opaque collapse there is no longer a "not found" vs "is not
    # ai-managed" branch to distinguish — both branches return the same string.
    r_missing = cross_ref_probe(PROBE_A_FULL, PROBE_NONEXISTENT)
    show(f"set template={PROBE_NONEXISTENT} (missing)", r_missing)

    opaque_phrase = "must reference an ai-managed qube"
    both_opaque = (
        (not r_untagged.get("ok")) and (not r_missing.get("ok"))
        and opaque_phrase in r_untagged.get("error", "")
        and opaque_phrase in r_missing.get("error", "")
    )
    no_leak = (
        probe_value not in r_untagged.get("error", "")
        and PROBE_NONEXISTENT not in r_missing.get("error", "")
    )
    identical = r_untagged.get("error") == r_missing.get("error")
    opaque_pass = both_opaque and no_leak and identical
    if opaque_pass:
        print(f"  PASS: both refused with the opaque message, byte-identical, neither leaks the value.")
    else:
        print(f"  FAIL: opaque collapse expected but got\n"
              f"        untagged: {r_untagged}\n"
              f"        missing:  {r_missing}")

# ----------------------------------- 4b. Spawn template cross-ref OPAQUE
# Spawn was leaking the same way before the F2-bundle backport. Verify
# it now collapses too. The template cross-ref check runs at the front of the
# Spawn wrapper (before any create), so it is observable regardless of tiering —
# an untagged vs. missing TEMPLATE both collapse to one opaque message. Use a
# unique candidate name so we don't collide with the test qube above.
header("4b. Spawn template cross-ref OPAQUE — untagged vs. missing must be identical")
def spawn_template_probe(value: str) -> dict:
    return call_qmcp("qmcp.SpawnAIManagedQube", {
        "name": "ai-scratch-spawnprobe",
        "template": value,
        "label": "gray",
    })


s_untagged = spawn_template_probe(UNTAGGED_TEMPLATE)
s_missing = spawn_template_probe(PROBE_NONEXISTENT)
show(f"spawn template={UNTAGGED_TEMPLATE} (untagged)", s_untagged)
show(f"spawn template={PROBE_NONEXISTENT} (missing)", s_missing)

spawn_opaque_phrase = "template must reference an ai-managed qube"
spawn_opaque_pass = (
    (not s_untagged.get("ok")) and (not s_missing.get("ok"))
    and s_untagged.get("error") == s_missing.get("error")
    and spawn_opaque_phrase in s_untagged.get("error", "")
    and UNTAGGED_TEMPLATE not in s_untagged.get("error", "")
    and PROBE_NONEXISTENT not in s_missing.get("error", "")
)
if spawn_opaque_pass:
    print("  PASS: Spawn template cross-ref is byte-identical opaque.")
else:
    print(f"  FAIL: Spawn template cross-ref opaque expected but got\n"
          f"        untagged: {s_untagged}\n"
          f"        missing:  {s_missing}")

# ----------------------------------- 5. policy refusal on untagged qube
header(f"5. Policy refusal — {PROBE_UNTAGGED_2}.label = red (not ai-managed)")
r = call_qmcp("qmcp.SetPropertyAIManaged", {
    "name": PROBE_UNTAGGED_2,
    "property": "label",
    "value": "red",
})
show(f"set {PROBE_UNTAGGED_2}.label", r)
policy_refusal_ok = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if policy_refusal_ok else 'FAIL'}: returned 'not found' (indistinguishable from nonexistent)")

# ------------------- 6. Lifecycle happy-path on an ai-full fixture (non-destructive)
# The lifecycle happy-path (CAP_FULL start → shutdown SUCCEEDS) is provable only
# on an operator-tagged ai-full qube; absent → SKIP. NON-DESTRUCTIVE: start then
# shutdown, restoring the fixture's power state — NEVER remove/kill the operator's
# fixture. The destructive happy-path (remove SUCCEEDS) is proven in the slot, on
# a throwaway probe the slot itself tiered in dom0.
header("6. Lifecycle happy-path (CAP_FULL) on an ai-full fixture — non-destructive")
lifecycle_happy = None
if not PROBE_A_FULL:
    print("  SKIP (no QMCP_A_FULL fixture) — CAP_FULL lifecycle happy-path is proven")
    print("        in the slot on a dom0-tiered throwaway probe.")
else:
    # Record the starting power state so we can restore it.
    pre_state = call_qmcp("qmcp.GetPropertyAIManaged",
                          {"name": PROBE_A_FULL, "property": "power_state"}).get("value")
    print(f"  {PROBE_A_FULL} initial power_state = {pre_state!r}")
    lifecycle_happy = True

    st = call_qmcp("qmcp.LifecycleAIManaged", {"name": PROBE_A_FULL, "action": "start"})
    show(f"lifecycle start {PROBE_A_FULL}", st)
    # start on an already-running qube may be a benign no-op refusal; only treat a
    # transition-to-running as the positive proof.
    for i in range(15):
        s = call_qmcp("qmcp.GetPropertyAIManaged", {"name": PROBE_A_FULL, "property": "power_state"})
        print(f"  poll #{i+1}: power_state = {s.get('value')!r}")
        if s.get("value") in ("Running", "Transient"):
            break
        time.sleep(2)
    running = call_qmcp("qmcp.GetPropertyAIManaged",
                        {"name": PROBE_A_FULL, "property": "power_state"}).get("value")
    if running not in ("Running", "Transient"):
        print(f"  FAIL: could not bring the ai-full fixture to Running (got {running!r})")
        lifecycle_happy = False

    # Restore: only shut down if it was Halted before we started it (leave a qube
    # the operator had running alone).
    if pre_state == "Halted":
        sd = call_qmcp("qmcp.LifecycleAIManaged", {"name": PROBE_A_FULL, "action": "shutdown"})
        show(f"lifecycle shutdown {PROBE_A_FULL} (restore)", sd)
        lifecycle_happy &= bool(sd.get("ok"))
        for i in range(15):
            s = call_qmcp("qmcp.GetPropertyAIManaged", {"name": PROBE_A_FULL, "property": "power_state"})
            if s.get("value") == "Halted":
                break
            time.sleep(2)
    else:
        print(f"  (leaving {PROBE_A_FULL} running — it was not Halted before the test)")
    print(f"  {'PASS' if lifecycle_happy else 'FAIL'}: CAP_FULL lifecycle succeeds on the ai-full fixture")

# ----------------------------------------------------- 7. cleanup / leftover note
# AI CANNOT remove its own untiered self-spawned ai-scratch-1 post-flip (remove is
# CAP_FULL → denied, already asserted in 3c). Attempt best-effort cleanup, tolerate
# the denial, and CLEARLY note any leftover — the slot/dom0 removes it. Never
# assert-fail because a self-spawned untiered qube could not be removed.
header("7. Cleanup — best-effort (untiered self-spawned qube is un-removable by AI)")
for probe in ("ai-scratch-1",):
    call_qmcp("qmcp.LifecycleAIManaged", {"name": probe, "action": "kill"})
    time.sleep(1)
    call_qmcp("qmcp.LifecycleAIManaged", {"name": probe, "action": "remove"})

r3 = call_qmcp("qmcp.ListAIManagedQubes")
names3 = [q["name"] for q in r3.get("qubes", [])]
print(f"  After best-effort cleanup, list: {names3}")
if "ai-scratch-1" in names3:
    print("  LEFTOVER: ai-scratch-1 remains (expected post-flip — untiered → AI cannot")
    print("            remove it). The slot/dom0 cleans it. This is NOT a failure.")
else:
    print("  ai-scratch-1 is gone (either never spawned, or the slot pre-tiered it).")

# ------------------------------------------------------ rollup
# Aggregate into an exit code, mirroring test-stage-I-5.py / test-stage-I-6.py
# (both end with `sys.exit(main())` returning 1 on any failed assertion). Without
# this, every assertion here only print()s 'FAIL' and the process still exits 0 —
# so the slot's run_mcp_test (which judges purely on `[ rc -eq 0 ]`) would count a
# real self-escalation (a CAP_FULL op SUCCEEDING on the untiered ai-scratch-1) as
# GREEN. The anti-self-escalation guard (cap_full_denied, section 3c) MUST be able
# to turn the run red; it is the strictest security assertion in Stage A.
#
# Convention (matches the fixture-env protocol): each check is a tri-state —
#   True  => ran and PASSED
#   False => ran and FAILED  (contributes 1 to the exit code)
#   None  => SKIPPED (no fixture, or a precondition like spawn_ok was not met)
# A None NEVER fails the run; only an explicit False does. The always-run,
# no-fixture-needed security assertions (existence-leak, cap_full_denied,
# spawn_opaque_pass, policy_refusal) are the ones that keep the run honest.
header("Stage A test plan — summary (flip-aware)")

# always-run (no fixture needed):
checks = [
    ("existence-leak opacity (untagged == nonexistent) [1]",            existence_leak_ok),
    ("reads on the untiered self-spawned qube succeed [3b]",            read_ok),
    ("CAP_FULL ops on the untiered qube -> opaque NOT_FOUND [3c] "
     "(anti-self-escalation)",                                          cap_full_denied),
    ("Spawn template cross-ref opaque [4b]",                            spawn_opaque_pass),
    ("policy refusal on an untagged qube -> 'not found' [5]",           policy_refusal_ok),
    # fixture-gated (None => SKIP without QMCP_A_FULL, never a failure):
    ("SetProperty cross-ref opacity on a CAP_FULL target [4]",          opaque_pass),
    ("CAP_FULL lifecycle happy-path, non-destructive [6]",              lifecycle_happy),
]

any_fail = False
for label, result in checks:
    if result is None:
        tag = "SKIP"
    elif result:
        tag = "PASS"
    else:
        tag = "FAIL"
        any_fail = True
    print(f"  {tag}  {label}")

if spawn_ok is False:
    # Not a security failure — the template just wasn't ai-full, so the create-gate
    # blocked the spawn and 3b/3c could not exercise the self-spawned qube. Flag it
    # loudly (the anti-self-escalation guard did NOT get to run) but don't fail the
    # run on a missing/mis-tagged template fixture.
    print("  NOTE  spawn did not succeed (template not ai-full?) — 3b/3c were SKIPPED;")
    print("        the anti-self-escalation guard could not run this pass.")

print("\n  Leftover ai-scratch-1 is expected and is cleaned by the slot/dom0 — not a failure.")

if any_fail:
    print("\n  OVERALL: FAIL — at least one Stage-A assertion failed (see 'FAIL' above).")
else:
    print("\n  OVERALL: PASS — all exercised Stage-A assertions held (skips are not failures).")

sys.exit(1 if any_fail else 0)
