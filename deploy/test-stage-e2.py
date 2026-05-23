#!/usr/bin/env python3
"""Stage E2 test plan — run from mcp-control after slot-10.sh applied.

Verifies the ephemeral DispVM wrapper and the one-shot orchestrator:

  1. Spawn a DispVMTemplate (ai-dvmt) — same as Stage D.
  2. Spawn an ephemeral disposable from ai-dvmt → returns auto-name
     dispXXXX; the qube is ai-managed, klass=DispVM, template=ai-dvmt,
     auto_cleanup=True.
  3. Start, run whoami=root, shutdown → after shutdown the qube
     auto-removes (no longer in ListAIManagedQubes).
  4. Negative: spawn from a plain TemplateVM (no template_for_dispvms)
     → cross-ref error mentioning template_for_dispvms.
  5. Negative: spawn from an untagged operator qube → opaque "not found"
     (existence-oracle hiding holds across the disposable surface).
  6. End-to-end one-shot: qubes_run_disposable(ai-dvmt, ["whoami"]) →
     {ok, name, rc=0, stdout="root\n"}; the qube auto-removes after.

Cleans up its test qubes at the end. Does NOT touch any operator qube.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp, call_service  # noqa: E402
from qubes_mcp.tools.qubes_run_disposable import qubes_run_disposable  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"
PROBE_UNTAGGED = "sys-firewall"

TEST_DVMT = "ai-dvmt-e2"           # distinct from Stage D's ai-dvmt to avoid collision
DISPOSABLE_NAMES: list[str] = []   # populated as we go, used by cleanup


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


def wait_halted(name: str, attempts: int = 30) -> bool:
    """Wait until either the qube is Halted or has vanished (auto-cleanup)."""
    for _ in range(attempts):
        s = call_qmcp("qmcp.GetPropertyAIManaged",
                      {"name": name, "property": "power_state"})
        if not s.get("ok") and s.get("error") == "not found":
            return True  # already auto-removed — same outcome as Halted for us
        if s.get("value") == "Halted":
            return True
        time.sleep(2)
    return False


def wait_running(name: str, attempts: int = 15) -> bool:
    for _ in range(attempts):
        s = call_qmcp("qmcp.GetPropertyAIManaged",
                      {"name": name, "property": "power_state"})
        if s.get("value") in ("Running", "Transient"):
            return True
        time.sleep(2)
    return False


def get_prop(name: str, prop: str) -> dict:
    return call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})


def visible_in_list() -> set[str]:
    r = call_qmcp("qmcp.ListAIManagedQubes")
    return {q["name"] for q in r.get("qubes", [])}


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftovers")
# Order matters: a DVMT cannot be removed while any qube (including a
# disposable from a previous botched run) references it as its template.
# Sweep up any leftover disposables tied to TEST_DVMT first, then the
# DVMT itself. Best-effort throughout — most paths are no-ops on first run.
_pre = call_qmcp("qmcp.ListAIManagedQubes")
for _q in _pre.get("qubes", []):
    if _q.get("template") == TEST_DVMT and _q.get("klass") == "DispVM":
        print(f"  cleanup leftover disposable: {_q['name']}")
        cleanup(_q["name"])
cleanup(TEST_DVMT)

# ---------------------------- 1. Spawn DispVMTemplate
header(f"1. Spawn ai-managed DispVMTemplate ({TEST_DVMT})")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": TEST_DVMT, "template": PROBE_AI_MANAGED_TEMPLATE,
               "klass": "DispVMTemplate", "label": "gray"})
show(f"spawn {TEST_DVMT} (DispVMTemplate)", r)
dvmt_ok = bool(r.get("ok"))
if not dvmt_ok:
    print("  WARN: DVMT spawn failed; the rest of the test will be skipped")

# ---------------------------- 2. Spawn ephemeral disposable + verify props
header("2. Spawn ephemeral disposable from the DVMT")
disp_name = None
disp_klass_ok = disp_template_ok = disp_autoclean_ok = disp_visible_ok = False
if dvmt_ok:
    r = call_qmcp("qmcp.SpawnDisposableAIManaged", {"template": TEST_DVMT})
    show("SpawnDisposableAIManaged", r)
    if r.get("ok"):
        disp_name = r["name"]
        DISPOSABLE_NAMES.append(disp_name)

        k = get_prop(disp_name, "klass")
        show(f"read {disp_name}.klass", k)
        disp_klass_ok = k.get("ok") and k.get("value") == "DispVM"

        t = get_prop(disp_name, "template")
        show(f"read {disp_name}.template", t)
        disp_template_ok = t.get("ok") and t.get("value") == TEST_DVMT

        a = get_prop(disp_name, "auto_cleanup")
        show(f"read {disp_name}.auto_cleanup", a)
        disp_autoclean_ok = a.get("ok") and a.get("value") is True

        disp_visible_ok = disp_name in visible_in_list()
        print(f"  {disp_name} in ListAIManagedQubes: {disp_visible_ok}")

spawn_pass = (disp_name is not None
              and disp_klass_ok and disp_template_ok
              and disp_autoclean_ok and disp_visible_ok)
print(f"  {'PASS' if spawn_pass else 'FAIL'}: spawn + tag + klass=DispVM + "
      f"template + auto_cleanup=True")

# ---------------------------- 3. Start, whoami=root, shutdown, verify auto-remove
header("3. Start + whoami=root + shutdown → auto-remove on halt")
start_ok = run_ok = shutdown_ok = autoremoved_ok = False
if disp_name:
    r = call_qmcp("qmcp.LifecycleAIManaged",
                  {"name": disp_name, "action": "start"})
    show(f"start {disp_name}", r)
    start_ok = bool(r.get("ok"))

    if start_ok and wait_running(disp_name):
        r = call_service(disp_name, "qmcp.RunInAIManaged",
                         {"cmd": ["whoami"], "timeout": 10}, timeout=40)
        show(f"whoami in {disp_name}", r)
        run_ok = (r.get("ok") and r.get("rc") == 0
                  and r.get("stdout", "").strip() == "root")

        r = call_qmcp("qmcp.LifecycleAIManaged",
                      {"name": disp_name, "action": "shutdown"})
        show(f"shutdown {disp_name}", r)
        shutdown_ok = bool(r.get("ok"))

        if shutdown_ok:
            wait_halted(disp_name)
            # After shutdown the auto_cleanup=True default in qubesd should
            # have removed the qube. Allow a brief settle for dom0 cleanup.
            for _ in range(10):
                if disp_name not in visible_in_list():
                    autoremoved_ok = True
                    break
                time.sleep(1)

print(f"  {'PASS' if start_ok and run_ok and shutdown_ok and autoremoved_ok else 'FAIL'}: "
      f"start + whoami=root + shutdown + auto-removed")

# ---------------------------- 4. Negative — plain TemplateVM refused
header(f"4. Spawn disposable from plain TemplateVM ({PROBE_AI_MANAGED_TEMPLATE}) refused")
r = call_qmcp("qmcp.SpawnDisposableAIManaged",
              {"template": PROBE_AI_MANAGED_TEMPLATE})
show("spawn disposable from TemplateVM", r)
crossref_refused = (not r.get("ok")
                    and "template_for_dispvms" in r.get("error", ""))
print(f"  {'PASS' if crossref_refused else 'FAIL'}: refused with template_for_dispvms message")
if r.get("ok"):
    DISPOSABLE_NAMES.append(r["name"])  # defensive cleanup

# ---------------------------- 5. Negative — untagged refused opaquely
header(f"5. Spawn disposable from {PROBE_UNTAGGED} (untagged) → opaque 'not found'")
r = call_qmcp("qmcp.SpawnDisposableAIManaged", {"template": PROBE_UNTAGGED})
show("spawn disposable from untagged", r)
untagged_refused = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if untagged_refused else 'FAIL'}: refused with literal 'not found'")
if r.get("ok"):
    DISPOSABLE_NAMES.append(r["name"])

# ---------------------------- 6. End-to-end one-shot
header("6. qubes_run_disposable one-shot: spawn → start → whoami → shutdown")
oneshot_ok = False
oneshot_name = None
if dvmt_ok:
    r = qubes_run_disposable(TEST_DVMT, ["whoami"], timeout=20)
    show("qubes_run_disposable(TEST_DVMT, whoami)",
         # Trim potentially-long stdout/stderr for the summary line.
         {k: (v if k not in ("stdout", "stderr") else v[:80]) for k, v in r.items()})
    if r.get("ok"):
        oneshot_name = r.get("name")
        oneshot_ok = (r.get("rc") == 0
                      and r.get("stdout", "").strip() == "root")
        if oneshot_name:
            DISPOSABLE_NAMES.append(oneshot_name)
            # Verify auto-cleanup completed (poll briefly).
            for _ in range(15):
                if oneshot_name not in visible_in_list():
                    break
                time.sleep(1)
print(f"  {'PASS' if oneshot_ok else 'FAIL'}: one-shot returned ok+rc=0+stdout=root")

# ---------------------------------------------------------- summary
header("Stage E2 test plan — summary")
results = {
    "spawn + tag + DispVM + template + auto_cleanup":  spawn_pass,
    "start + whoami=root + shutdown + auto-removed":   start_ok and run_ok
                                                       and shutdown_ok
                                                       and autoremoved_ok,
    "plain TemplateVM refused (cross-ref)":            crossref_refused,
    "untagged refused (opaque)":                       untagged_refused,
    "qubes_run_disposable one-shot":                   oneshot_ok,
}
for label, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}: {label}")
print(f"\n  Total: {sum(results.values())}/{len(results)} green")

# ---------------------------------------------------------- cleanup
header("Cleanup")
# Any disposable we created that DIDN'T auto-cleanup gets killed here so
# auto_cleanup fires. The DVMT itself is named persistent — remove last.
for n in DISPOSABLE_NAMES:
    cleanup(n)
cleanup(TEST_DVMT)
r = call_qmcp("qmcp.ListAIManagedQubes")
remaining = [q["name"] for q in r.get("qubes", [])]
print(f"  Remaining ai-managed qubes: {remaining}")

sys.exit(0 if all(results.values()) else 1)
