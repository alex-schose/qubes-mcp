#!/usr/bin/env python3
"""Stage A test plan — run from mcp-control after dom0 deploy.

Exercises the four qmcp.* RPCs and the tag-scoped lifecycle methods.
Cleans up the test qube (ai-scratch-1) at the end.

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

# An ai-managed TemplateVM (the one you enrolled).
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
    print("  ai-scratch-1 lingers from a prior run — cleaning up...")
    call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "kill"})
    time.sleep(2)
    call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "remove"})
    time.sleep(1)

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
if bad:
    print(f"\n  LEAK DETECTED: {bad} returned a response distinguishable from nonexistent.")
else:
    print("\n  PASS: untagged qubes return byte-identical 'not found' to nonexistent.")

# -------------------------------------------------------- 2. qubes_list
header("2. qubes_list — only ai-managed")
r = call_qmcp("qmcp.ListAIManagedQubes")
print(json.dumps(r, indent=2))
names = [q["name"] for q in r.get("qubes", [])]
print(f"\n  Visible names: {names}")

# -------------------------------------------------------- 3. qubes_spawn
header(f"3. Spawn ai-scratch-1 from {PROBE_AI_MANAGED_TEMPLATE}")
r = call_qmcp("qmcp.SpawnAIManagedQube", {
    "name": "ai-scratch-1",
    "template": PROBE_AI_MANAGED_TEMPLATE,
    "label": "gray",
})
show("spawn ai-scratch-1", r)
spawn_ok = r.get("ok")

r2 = call_qmcp("qmcp.ListAIManagedQubes")
names2 = [q["name"] for q in r2.get("qubes", [])]
print(f"  After spawn, list: {names2}")

# ----------------------------------- 4. SetProperty cross-ref OPAQUE COLLAPSE
# The wrapper's cross-ref refusal must collapse "missing" and "untagged"
# into one byte-identical message that does NOT echo the value name —
# otherwise this surface is an existence oracle on every untagged qube
# in dom0. Probe both branches and assert the responses are identical
# AND neither response contains the probed name.
def cross_ref_probe(value: str) -> dict:
    return call_qmcp("qmcp.SetPropertyAIManaged", {
        "name": "ai-scratch-1",
        "property": "template",
        "value": value,
    })


probe_value = UNTAGGED_TEMPLATE
header("4. SetProperty cross-ref OPAQUE — untagged vs. missing must be identical")
r_untagged = cross_ref_probe(probe_value)
show(f"set template={probe_value} (untagged)", r_untagged)

# If the configured probe doesn't exist, fall back to a qube every default
# install has (sys-firewall). With the opaque collapse there is no longer
# a "not found" vs "is not ai-managed" branch to distinguish — both
# branches return the same string — so we can't auto-detect the fallback
# from the response. The default value is left as a hint for operators
# with an unusual template name.
r_missing = cross_ref_probe(PROBE_NONEXISTENT)
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
# it now collapses too. Use a unique candidate name so we don't collide
# with the test qube above.
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
nf = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if nf else 'FAIL'}: returned 'not found' (indistinguishable from nonexistent)")

# ----------------------------------------------------- 6. qubes_start
header("6. Start ai-scratch-1")
r = call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "start"})
show("lifecycle start ai-scratch-1", r)

for i in range(15):
    s = call_qmcp("qmcp.GetPropertyAIManaged", {"name": "ai-scratch-1", "property": "power_state"})
    print(f"  poll #{i+1}: power_state = {s.get('value')!r}")
    if s.get("value") in ("Running", "Transient"):
        break
    time.sleep(2)

# --------------------------------------------------- 7. qubes_shutdown
header("7. Shutdown ai-scratch-1 (clean)")
r = call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "shutdown"})
show("lifecycle shutdown ai-scratch-1", r)

for i in range(15):
    s = call_qmcp("qmcp.GetPropertyAIManaged", {"name": "ai-scratch-1", "property": "power_state"})
    print(f"  poll #{i+1}: power_state = {s.get('value')!r}")
    if s.get("value") == "Halted":
        break
    time.sleep(2)

final = call_qmcp("qmcp.GetPropertyAIManaged", {"name": "ai-scratch-1", "property": "power_state"})
if final.get("value") != "Halted":
    print("  shutdown didn't complete cleanly; force-killing...")
    call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "kill"})
    time.sleep(2)

# ----------------------------------------------------- 8. qubes_remove
header("8. Remove ai-scratch-1")
r = call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-scratch-1", "action": "remove"})
show("lifecycle remove ai-scratch-1", r)

r3 = call_qmcp("qmcp.ListAIManagedQubes")
names3 = [q["name"] for q in r3.get("qubes", [])]
print(f"  After remove, list: {names3}")
print(f"  {'PASS' if 'ai-scratch-1' not in names3 else 'FAIL'}: ai-scratch-1 removed")

# ------------------------------------------------------ rollup
header("Stage A test plan — summary")
print("  Expected: 5 PASS markers (existence-leak, SetProperty cross-ref opaque,")
print("            Spawn template cross-ref opaque, policy refusal, remove confirmation).")
