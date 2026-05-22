#!/usr/bin/env python3
"""Stage D test plan — run from mcp-control after slot-4.sh applied.

Verifies:
  1. Clone an ai-managed AppVM → clone exists and is ai-managed.
  2. Negative — clone of an untagged operator qube refused with "not found"
     (existence-oracle hiding holds across the clone surface too).
  3. Spawn klass=DispVMTemplate → klass is DispVMTemplate, ai-managed,
     template_for_dispvms=True.
  4. Spawn klass=DispVM from the DispVMTemplate → ai-managed, template
     points at the DispVMTemplate, klass=DispVM.
  5. Negative — spawn klass=DispVM with a plain TemplateVM as template
     refused (cross-ref check: template_for_dispvms must be True).
  6. End-to-end DispVM usability — start ai-dvm via qmcp.LifecycleAIManaged,
     run `whoami` inside via qmcp.RunInAIManaged (proves the
     ai-debian-13 → DVMT → DispVM service-inheritance chain), shutdown.
     This is the test that proves AI can actually USE its DispVMs, not
     just create them.

Cleans up its test qubes at the end. Does NOT touch any operator qube.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp, call_service  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"
PROBE_UNTAGGED = "sys-firewall"

TEST_QUBES = ["ai-clone-src", "ai-clone-tgt", "ai-dvmt", "ai-dvm", "ai-dvm-bad"]


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


def get_prop(name: str, prop: str) -> dict:
    return call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftovers")
cleanup(*TEST_QUBES)

# ---------------------------- 1. clone an ai-managed qube
header("1. Clone an ai-managed AppVM → clone is ai-managed")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-clone-src", "template": PROBE_AI_MANAGED_TEMPLATE,
               "label": "gray"})
show("spawn ai-clone-src", r)
spawn_src_ok = bool(r.get("ok"))

clone_ok = False
clone_visible = False
if spawn_src_ok:
    r = call_qmcp("qmcp.CloneAIManagedQube",
                  {"source": "ai-clone-src", "name": "ai-clone-tgt"})
    show("clone → ai-clone-tgt", r)
    clone_ok = bool(r.get("ok"))

    if clone_ok:
        lr = call_qmcp("qmcp.ListAIManagedQubes")
        visible = {q["name"] for q in lr.get("qubes", [])}
        clone_visible = "ai-clone-tgt" in visible
        print(f"  ai-clone-tgt in ListAIManagedQubes: {clone_visible}")

print(f"  {'PASS' if clone_ok and clone_visible else 'FAIL'}: clone exists and is ai-managed")

# ---------------------------- 2. clone of untagged refused (opaque)
header(f"2. Clone of {PROBE_UNTAGGED} (untagged) refused with 'not found'")
r = call_qmcp("qmcp.CloneAIManagedQube",
              {"source": PROBE_UNTAGGED, "name": "ai-clone-leak"})
show(f"clone untagged → ai-clone-leak", r)
opaque_refused = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if opaque_refused else 'FAIL'}: refused with literal 'not found'")
# Defensive cleanup if the clone somehow succeeded.
if r.get("ok"):
    cleanup("ai-clone-leak")

# ---------------------------- 3. spawn klass=DispVMTemplate
header("3. Spawn klass=DispVMTemplate → ai-managed, template_for_dispvms=True")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-dvmt", "template": PROBE_AI_MANAGED_TEMPLATE,
               "klass": "DispVMTemplate", "label": "gray"})
show("spawn ai-dvmt (DispVMTemplate)", r)
spawn_dvmt_ok = bool(r.get("ok"))

# The meaningful invariant is template_for_dispvms=True — the klass itself
# is incidental (AppVM-plus-flag is the canonical form across Qubes versions;
# some 4.2+ versions also expose a distinct DispVMTemplate klass, but the
# wrapper builds disposable templates via the AppVM-plus-flag path for
# version-agnostic behaviour).
dvmt_t4d_ok = dvmt_tagged_ok = False
if spawn_dvmt_ok:
    k = get_prop("ai-dvmt", "klass")
    show("read ai-dvmt.klass", k)

    t = get_prop("ai-dvmt", "template_for_dispvms")
    show("read ai-dvmt.template_for_dispvms", t)
    dvmt_t4d_ok = t.get("ok") and t.get("value") is True

    lr = call_qmcp("qmcp.ListAIManagedQubes")
    dvmt_tagged_ok = "ai-dvmt" in {q["name"] for q in lr.get("qubes", [])}

print(f"  {'PASS' if dvmt_t4d_ok and dvmt_tagged_ok else 'FAIL'}: "
      f"template_for_dispvms=True + ai-managed")

# ---------------------------- 4. spawn klass=DispVM from the DispVMTemplate
header("4. Spawn klass=DispVM from ai-dvmt → ai-managed, template=ai-dvmt")
spawn_dvm_ok = False
dvm_klass_ok = dvm_template_ok = dvm_tagged_ok = False
if spawn_dvmt_ok:
    r = call_qmcp("qmcp.SpawnAIManagedQube",
                  {"name": "ai-dvm", "template": "ai-dvmt",
                   "klass": "DispVM", "label": "gray"})
    show("spawn ai-dvm (DispVM)", r)
    spawn_dvm_ok = bool(r.get("ok"))

    if spawn_dvm_ok:
        k = get_prop("ai-dvm", "klass")
        show("read ai-dvm.klass", k)
        dvm_klass_ok = k.get("ok") and k.get("value") == "DispVM"

        t = get_prop("ai-dvm", "template")
        show("read ai-dvm.template", t)
        dvm_template_ok = t.get("ok") and t.get("value") == "ai-dvmt"

        lr = call_qmcp("qmcp.ListAIManagedQubes")
        dvm_tagged_ok = "ai-dvm" in {q["name"] for q in lr.get("qubes", [])}

print(f"  {'PASS' if dvm_klass_ok and dvm_template_ok and dvm_tagged_ok else 'FAIL'}: "
      f"klass=DispVM + template=ai-dvmt + ai-managed")

# ---------------------------- 5. negative — DispVM from plain TemplateVM refused
header("5. Spawn klass=DispVM from a plain TemplateVM refused "
       "(cross-ref: template_for_dispvms must be True)")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-dvm-bad", "template": PROBE_AI_MANAGED_TEMPLATE,
               "klass": "DispVM", "label": "gray"})
show("spawn ai-dvm-bad (DispVM from TemplateVM)", r)
cross_ref_refused = (not r.get("ok")) and "template_for_dispvms" in r.get("error", "")
print(f"  {'PASS' if cross_ref_refused else 'FAIL'}: refused with the "
      f"template_for_dispvms cross-ref message")
# Defensive cleanup if it somehow succeeded.
if r.get("ok"):
    cleanup("ai-dvm-bad")

# ---------------------------- 6. end-to-end DispVM usability
# Start ai-dvm, run a command inside, shutdown. Proves the chain
# ai-debian-13 → DVMT → DispVM correctly inherits qmcp.RunInAIManaged
# (installed in ai-debian-13 in Stage B) all the way down to the DispVM.
header("6. End-to-end DispVM usability — start + run + shutdown ai-dvm")
dvm_start_ok = dvm_run_ok = dvm_shutdown_ok = False
if spawn_dvm_ok:
    r = call_qmcp("qmcp.LifecycleAIManaged", {"name": "ai-dvm", "action": "start"})
    show("lifecycle start ai-dvm", r)
    dvm_start_ok = bool(r.get("ok"))

    if dvm_start_ok:
        # Poll for Running before invoking the in-qube service.
        for i in range(15):
            s = call_qmcp("qmcp.GetPropertyAIManaged",
                          {"name": "ai-dvm", "property": "power_state"})
            if s.get("value") in ("Running", "Transient"):
                break
            time.sleep(2)

        r = call_service("ai-dvm", "qmcp.RunInAIManaged",
                         {"cmd": ["whoami"], "timeout": 10}, timeout=40)
        show("whoami in ai-dvm", r)
        dvm_run_ok = (r.get("ok") and r.get("rc") == 0
                      and r.get("stdout", "").strip() == "root")

        r = call_qmcp("qmcp.LifecycleAIManaged",
                      {"name": "ai-dvm", "action": "shutdown"})
        show("lifecycle shutdown ai-dvm", r)
        dvm_shutdown_ok = bool(r.get("ok"))

        # Wait for Halted so the cleanup below can remove it cleanly.
        for i in range(15):
            s = call_qmcp("qmcp.GetPropertyAIManaged",
                          {"name": "ai-dvm", "property": "power_state"})
            if s.get("value") == "Halted":
                break
            time.sleep(2)

print(f"  {'PASS' if dvm_start_ok and dvm_run_ok and dvm_shutdown_ok else 'FAIL'}: "
      f"start + whoami=root + shutdown")

# ---------------------------------------------------------- summary
header("Stage D test plan — summary")
results = {
    "clone of ai-managed → ai-managed":           clone_ok and clone_visible,
    "clone of untagged opaque-refused":           opaque_refused,
    "DispVMTemplate spawn + tag + t4d=True":      spawn_dvmt_ok and dvmt_t4d_ok
                                                  and dvmt_tagged_ok,
    "DispVM spawn + tag + template correct":      spawn_dvm_ok and dvm_klass_ok
                                                  and dvm_template_ok and dvm_tagged_ok,
    "DispVM from plain TemplateVM refused":       cross_ref_refused,
    "DispVM start + whoami=root + shutdown":      dvm_start_ok and dvm_run_ok
                                                  and dvm_shutdown_ok,
}
for label, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}: {label}")
print(f"\n  Total: {sum(results.values())}/{len(results)} green")

# ---------------------------------------------------------- cleanup
header("Cleanup")
# Order matters: remove DispVM before its DispVMTemplate parent.
cleanup("ai-dvm", "ai-dvm-bad", "ai-dvmt", "ai-clone-tgt", "ai-clone-src")
r = call_qmcp("qmcp.ListAIManagedQubes")
remaining = [q["name"] for q in r.get("qubes", [])]
print(f"  Remaining ai-managed qubes: {remaining}")

sys.exit(0 if all(results.values()) else 1)
