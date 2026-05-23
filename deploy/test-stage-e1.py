#!/usr/bin/env python3
"""Stage E1 test plan — run from mcp-control after slot-9.sh applied.

Verifies the wrapper mechanics and the policy surface for virtual device
attach/detach between ai-managed qubes:

  HARD (counted toward pass/fail):
    1. List devices on an ai-managed backend → succeeds (returns lines,
       maybe empty) via the new tag-scoped allow.
    2. List devices on an untagged qube → opaque "not found or refused"
       (existence-oracle hiding holds on the read surface too).
    3. Attach with frontend=<untagged> → "not found" (wrapper-side check).
    4. Attach with backend=<untagged>  → "not found" (wrapper-side check).
    5. Detach with frontend=<untagged> → "not found".
    6. Detach with backend=<untagged>  → "not found".

  SOFT (printed, not counted — depends on qubes-core-agent loop-device
  exposure behaviour, which varies across templates / Qubes versions):
    7. Inside the backend, create a 16M loop device via RunInAIManaged.
    8. List block devices on backend → loop appears.
    9. Attach the loop device to the frontend → ok.
   10. Verify a new /dev/xvd* device appears inside the frontend.
   11. Detach → /dev/xvd* shrinks back.

Cleans up its test qubes at the end. Does NOT touch any operator qube.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp, call_service, call_admin  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"
PROBE_UNTAGGED = "sys-firewall"

TEST_QUBES = ["ai-blk-backend", "ai-blk-frontend"]


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


def wait_running(name: str, attempts: int = 15) -> bool:
    for _ in range(attempts):
        s = call_qmcp("qmcp.GetPropertyAIManaged",
                      {"name": name, "property": "power_state"})
        if s.get("value") in ("Running", "Transient"):
            return True
        time.sleep(2)
    return False


def device_list(qube: str, device_class: str, mode: str = "available") -> dict:
    method = (f"admin.vm.device.{device_class}."
              + ("Available" if mode == "available" else "List"))
    r = call_admin(method, qube)
    if not r.get("ok"):
        return r
    return {"ok": True,
            "lines": [ln for ln in r.get("stdout", "").splitlines() if ln.strip()]}


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftovers")
cleanup(*TEST_QUBES)

header("Spawn backend + frontend (ai-managed AppVMs)")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-blk-backend", "template": PROBE_AI_MANAGED_TEMPLATE,
               "label": "gray"})
show("spawn ai-blk-backend", r)
backend_spawn_ok = bool(r.get("ok"))

r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": "ai-blk-frontend", "template": PROBE_AI_MANAGED_TEMPLATE,
               "label": "gray"})
show("spawn ai-blk-frontend", r)
frontend_spawn_ok = bool(r.get("ok"))

both_spawned = backend_spawn_ok and frontend_spawn_ok
if not both_spawned:
    print("  WARN: spawn failed; hard tests will be skipped")

# ---------------------------- 1. list devices on ai-managed backend → ok
header("1. List devices on ai-managed backend → tag-scoped allow works")
list_ok = False
if both_spawned:
    r = device_list("ai-blk-backend", "block", mode="available")
    show("admin.vm.device.block.Available ai-blk-backend", r)
    list_ok = bool(r.get("ok"))
print(f"  {'PASS' if list_ok else 'FAIL'}: list on ai-managed backend returns ok")

# ---------------------------- 2. list devices on untagged qube → opaque refuse
header(f"2. List devices on {PROBE_UNTAGGED} (untagged) → opaque refuse")
r = device_list(PROBE_UNTAGGED, "block", mode="available")
show(f"admin.vm.device.block.Available {PROBE_UNTAGGED}", r)
list_untagged_refused = (not r.get("ok")) and r.get("error") == "not found or refused"
print(f"  {'PASS' if list_untagged_refused else 'FAIL'}: refused with "
      f"'not found or refused'")

# ---------------------------- 3. attach with frontend=untagged → "not found"
header(f"3. Attach with frontend={PROBE_UNTAGGED} → opaque 'not found'")
attach_bad_frontend_refused = False
if backend_spawn_ok:
    r = call_qmcp("qmcp.AttachDeviceAIManaged",
                  {"device_class": "block", "backend": "ai-blk-backend",
                   "device_id": "loop0", "frontend": PROBE_UNTAGGED})
    show("attach (bad frontend)", r)
    attach_bad_frontend_refused = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if attach_bad_frontend_refused else 'FAIL'}: refused with 'not found'")

# ---------------------------- 4. attach with backend=untagged → "not found"
header(f"4. Attach with backend={PROBE_UNTAGGED} → opaque 'not found'")
attach_bad_backend_refused = False
if frontend_spawn_ok:
    r = call_qmcp("qmcp.AttachDeviceAIManaged",
                  {"device_class": "block", "backend": PROBE_UNTAGGED,
                   "device_id": "sda1", "frontend": "ai-blk-frontend"})
    show("attach (bad backend)", r)
    attach_bad_backend_refused = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if attach_bad_backend_refused else 'FAIL'}: refused with 'not found'")

# ---------------------------- 5. detach with frontend=untagged → "not found"
header(f"5. Detach with frontend={PROBE_UNTAGGED} → opaque 'not found'")
detach_bad_frontend_refused = False
if backend_spawn_ok:
    r = call_qmcp("qmcp.DetachDeviceAIManaged",
                  {"device_class": "block", "backend": "ai-blk-backend",
                   "device_id": "loop0", "frontend": PROBE_UNTAGGED})
    show("detach (bad frontend)", r)
    detach_bad_frontend_refused = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if detach_bad_frontend_refused else 'FAIL'}: refused with 'not found'")

# ---------------------------- 6. detach with backend=untagged → "not found"
header(f"6. Detach with backend={PROBE_UNTAGGED} → opaque 'not found'")
detach_bad_backend_refused = False
if frontend_spawn_ok:
    r = call_qmcp("qmcp.DetachDeviceAIManaged",
                  {"device_class": "block", "backend": PROBE_UNTAGGED,
                   "device_id": "sda1", "frontend": "ai-blk-frontend"})
    show("detach (bad backend)", r)
    detach_bad_backend_refused = (not r.get("ok")) and r.get("error") == "not found"
print(f"  {'PASS' if detach_bad_backend_refused else 'FAIL'}: refused with 'not found'")

# =====================================================================
# SOFT tests — real attach round-trip with a loop device.
# Whether the loop device auto-exposes depends on qubes-core-agent's
# block-device enumerator behaviour, which varies by template and Qubes
# version. We print PASS/SKIP, but only the HARD tests above contribute
# to the pass count.
# =====================================================================

header("SOFT 7-11. Real loop-device attach round-trip (informational)")

soft_loop_setup = soft_loop_listed = soft_attach_ok = False
soft_frontend_sees = soft_detach_ok = False
loop_port = None

if both_spawned:
    # Start backend, set up loop device.
    r = call_qmcp("qmcp.LifecycleAIManaged",
                  {"name": "ai-blk-backend", "action": "start"})
    show("start ai-blk-backend", r)
    if r.get("ok") and wait_running("ai-blk-backend"):
        # 7. losetup. -P flag is no-op on a partitionless raw image but harmless.
        r = call_service("ai-blk-backend", "qmcp.RunInAIManaged",
                         {"cmd": "truncate -s 16M /tmp/disk.img "
                                 "&& losetup -f --show /tmp/disk.img",
                          "shell": True, "timeout": 15}, timeout=40)
        show("setup loop in backend", r)
        soft_loop_setup = bool(r.get("ok") and r.get("rc") == 0)
        if soft_loop_setup:
            loop_dev = r.get("stdout", "").strip()
            # loop_dev looks like '/dev/loop0' — derive the port_id by stripping
            # the '/dev/' prefix. The Admin API enumerates by basename.
            loop_port = loop_dev.replace("/dev/", "")

    # 8. List should now show the loop device (after a brief settle).
    if loop_port:
        for _ in range(8):
            r = device_list("ai-blk-backend", "block", mode="available")
            lines = r.get("lines", [])
            if any(loop_port in ln for ln in lines):
                soft_loop_listed = True
                break
            time.sleep(2)
        show("list block devices on backend (post-losetup)",
             {"ok": r.get("ok"), "loop_listed": soft_loop_listed, "lines": lines})

    # 9. Start frontend, attach.
    if soft_loop_listed:
        r = call_qmcp("qmcp.LifecycleAIManaged",
                      {"name": "ai-blk-frontend", "action": "start"})
        show("start ai-blk-frontend", r)
        if r.get("ok") and wait_running("ai-blk-frontend"):
            r = call_qmcp("qmcp.AttachDeviceAIManaged",
                          {"device_class": "block",
                           "backend": "ai-blk-backend",
                           "device_id": loop_port,
                           "frontend": "ai-blk-frontend",
                           "options": {"read-only": "yes"}})
            show(f"attach {loop_port} → ai-blk-frontend", r)
            soft_attach_ok = bool(r.get("ok"))

    # 10. Confirm a new block device showed up inside the frontend.
    if soft_attach_ok:
        time.sleep(2)
        r = call_service("ai-blk-frontend", "qmcp.RunInAIManaged",
                         {"cmd": "ls /dev/xvd* 2>/dev/null | wc -l",
                          "shell": True, "timeout": 10}, timeout=30)
        show("count /dev/xvd* in frontend", r)
        try:
            count = int(r.get("stdout", "0").strip())
        except ValueError:
            count = 0
        # Frontend always has /dev/xvda (root) + /dev/xvdb (private); we
        # expect >= 3 after a successful block attach.
        soft_frontend_sees = count >= 3

    # 11. Detach.
    if soft_attach_ok:
        r = call_qmcp("qmcp.DetachDeviceAIManaged",
                      {"device_class": "block",
                       "backend": "ai-blk-backend",
                       "device_id": loop_port,
                       "frontend": "ai-blk-frontend"})
        show(f"detach {loop_port}", r)
        soft_detach_ok = bool(r.get("ok"))

for label, ok in (
    ("backend loop setup",      soft_loop_setup),
    ("loop device listed",      soft_loop_listed),
    ("attach to frontend",      soft_attach_ok),
    ("frontend sees new xvd*",  soft_frontend_sees),
    ("detach",                  soft_detach_ok),
):
    tag = "PASS" if ok else "SKIP"
    print(f"  {tag} (soft): {label}")

# ---------------------------------------------------------- summary
header("Stage E1 test plan — summary (hard tests only)")
results = {
    "list on ai-managed backend ok":              list_ok,
    "list on untagged refused (opaque)":          list_untagged_refused,
    "attach with bad frontend refused":           attach_bad_frontend_refused,
    "attach with bad backend refused":            attach_bad_backend_refused,
    "detach with bad frontend refused":           detach_bad_frontend_refused,
    "detach with bad backend refused":            detach_bad_backend_refused,
}
for label, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}: {label}")
print(f"\n  Total: {sum(results.values())}/{len(results)} green")

# ---------------------------------------------------------- cleanup
header("Cleanup")
cleanup(*TEST_QUBES)
r = call_qmcp("qmcp.ListAIManagedQubes")
remaining = [q["name"] for q in r.get("qubes", [])]
print(f"  Remaining ai-managed qubes: {remaining}")

sys.exit(0 if all(results.values()) else 1)
