#!/usr/bin/env python3
"""Stage F2 test plan — run from mcp-control after slot-13.sh applied.

Verifies the events surface (qmcp.AIManagedEvents) and the existence-
oracle backports it ships with (see test-stage-a.py for the cross-ref
opaque-collapse assertions).

  1. Basic surfacing: a domain-start fired on an ai-managed qube WITHIN
     the window IS surfaced in the returned batch.
  2. Tag-filter boundary: every event in the returned batch has a
     subject that is (or was at window-open) ai-managed — no leak of
     operator-qube activity through this surface.
  3. Qube filter (positive): qube="<ai-managed>" restricts the batch to
     events whose subject is that qube AND still surfaces events.
  4. Qube filter (opaque): qube="<untagged>" and qube="<nonexistent>"
     both return byte-identical {"ok": false, "error": "not found"} —
     this surface is not an existence oracle on untagged qube names.
  5. Events filter: events=[...] restricts the batch to event names that
     equal an entry OR match it as a "<entry>:" prefix.

Plus one SOFT (manual) check: tag-delete-mid-window. The wrapper has a
special case for domain-tag-delete:ai-managed (the revocation signal
itself, where live tag-check would drop the event); verifying this
end-to-end requires the operator to run `qvm-tags <vm> del ai-managed`
in dom0 during the window. Instructions printed at the end.

The qube ai-feat-f2 is spawned at setup (no network) and removed in
cleanup. Three windows of ~10s each + one immediate-return opaque check
≈ 35s wall time.
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp  # noqa: E402
from qubes_mcp.tools.qubes_events import qubes_events  # noqa: E402


# ====================================================================
# Probe constants — set these to match your Qubes setup.
# ====================================================================

PROBE_AI_MANAGED_TEMPLATE = "ai-debian-13"   # ai-managed TemplateVM
PROBE_UNTAGGED = "sys-firewall"              # exists, NOT ai-managed
PROBE_NONEXISTENT = "no-such-qube-zzz"       # does not exist

TEST_QUBE = "ai-feat-f2"


# ====================================================================
def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r) -> None:
    s = json.dumps(r)
    if len(s) > 240:
        s = s[:236] + "...(truncated)"
    print(f"  {label:48s} → {s}")


def cleanup(*qube_names: str) -> None:
    for n in qube_names:
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "kill"})
        time.sleep(1)
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "remove"})


def wait_halted(name: str, timeout_s: float = 30.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        s = call_qmcp("qmcp.GetPropertyAIManaged",
                      {"name": name, "property": "power_state"})
        if s.get("value") == "Halted":
            return True
        time.sleep(1)
    return False


def trigger_start_after(name: str, delay_s: float) -> None:
    """Sleep, then issue a lifecycle start. Runs in a worker thread so
    the main thread can be inside qubes_events()'s window when this
    fires."""
    time.sleep(delay_s)
    call_qmcp("qmcp.LifecycleAIManaged", {"name": name, "action": "start"})


def open_window(**kwargs) -> dict:
    """Convenience wrapper — qubes_events() with the kwargs passed
    through. Returns the parsed JSON dict."""
    return qubes_events(**kwargs)


# ---------------------------------------------------------------- preamble
header("preamble — cleanup any leftover test qube")
cleanup(TEST_QUBE)

# ---------------------------- setup: spawn a no-network ai-managed AppVM
header(f"setup — spawn ai-managed AppVM ({TEST_QUBE}, no netvm)")
r = call_qmcp("qmcp.SpawnAIManagedQube",
              {"name": TEST_QUBE, "template": PROBE_AI_MANAGED_TEMPLATE,
               "label": "gray", "netvm": None})
show(f"spawn {TEST_QUBE}", r)
target_ok = bool(r.get("ok"))
if not target_ok:
    print("  WARN: target spawn failed; dependent checks will be skipped")

# ---------------------------- snapshot ai-managed set (for leak detection)
r_list = call_qmcp("qmcp.ListAIManagedQubes")
ai_managed_names: set[str] = {q["name"] for q in r_list.get("qubes", [])}
print(f"  ai-managed at test start: {sorted(ai_managed_names)}")

# ---------------------------- 1+2. basic surfacing + no untagged leaks
header("1+2. domain-start IS surfaced; no event with non-ai-managed subject leaks")
basic_pass = no_leak_pass = False
if target_ok:
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_events = ex.submit(open_window, duration=10)
        ex.submit(trigger_start_after, TEST_QUBE, 1.5)
        batch = fut_events.result()
    show("events batch (truncated)", batch)
    events_list = batch.get("events", [])
    subjects_seen = {e["subject"] for e in events_list}
    print(f"  subjects in batch: {sorted(subjects_seen)}")
    basic_pass = TEST_QUBE in subjects_seen and any(
        e["event"] in ("domain-pre-start", "domain-start")
        and e["subject"] == TEST_QUBE for e in events_list
    )
    # Every event must have a subject that is either in the ai-managed
    # snapshot at test start OR could have been added during the window
    # (we account for the second by re-listing here — covers a tag-add
    # that happened during the window).
    r_list2 = call_qmcp("qmcp.ListAIManagedQubes")
    ai_now: set[str] = {q["name"] for q in r_list2.get("qubes", [])}
    allowed = ai_managed_names | ai_now
    leaks = [e for e in events_list if e["subject"] not in allowed]
    no_leak_pass = not leaks
    if leaks:
        print(f"  LEAKS: {leaks}")
print(f"  {'PASS' if basic_pass else 'FAIL'}: ai-managed start IS surfaced")
print(f"  {'PASS' if no_leak_pass else 'FAIL'}: no event with non-ai-managed subject")

# wait halt so the next sub-test can start fresh
if target_ok:
    call_qmcp("qmcp.LifecycleAIManaged", {"name": TEST_QUBE, "action": "shutdown"})
    if not wait_halted(TEST_QUBE):
        call_qmcp("qmcp.LifecycleAIManaged", {"name": TEST_QUBE, "action": "kill"})
        wait_halted(TEST_QUBE, timeout_s=10)

# ---------------------------- 3. qube filter restricts to that qube
header(f"3. qube filter — qube={TEST_QUBE} surfaces only that subject")
qube_filter_pass = False
if target_ok:
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_events = ex.submit(open_window, duration=10, qube=TEST_QUBE)
        ex.submit(trigger_start_after, TEST_QUBE, 1.5)
        batch_q = fut_events.result()
    show("filtered batch (truncated)", batch_q)
    events_q = batch_q.get("events", [])
    if events_q:
        subjects_q = {e["subject"] for e in events_q}
        qube_filter_pass = subjects_q == {TEST_QUBE}
    if not events_q:
        print("  WARN: window collected zero events; flaky timing — re-running may help")
print(f"  {'PASS' if qube_filter_pass else 'FAIL'}: qube filter restricts subjects to "
      f"the requested qube and surfaces events")

# wait halt before opaque test (background ops don't matter; just hygiene)
if target_ok:
    call_qmcp("qmcp.LifecycleAIManaged", {"name": TEST_QUBE, "action": "shutdown"})
    if not wait_halted(TEST_QUBE):
        call_qmcp("qmcp.LifecycleAIManaged", {"name": TEST_QUBE, "action": "kill"})
        wait_halted(TEST_QUBE, timeout_s=10)

# ---------------------------- 4. qube filter opaque (missing == untagged)
header("4. qube filter opaque — untagged vs. missing byte-identical")
r_untagged = open_window(duration=1, qube=PROBE_UNTAGGED)
r_missing = open_window(duration=1, qube=PROBE_NONEXISTENT)
show(f"qube={PROBE_UNTAGGED} (untagged)", r_untagged)
show(f"qube={PROBE_NONEXISTENT} (missing)", r_missing)
opaque_pass = (
    (not r_untagged.get("ok")) and (not r_missing.get("ok"))
    and r_untagged.get("error") == "not found"
    and r_missing.get("error") == "not found"
    and json.dumps(r_untagged, sort_keys=True) == json.dumps(r_missing, sort_keys=True)
)
print(f"  {'PASS' if opaque_pass else 'FAIL'}: byte-identical opaque 'not found'")

# ---------------------------- 5. events filter restricts to matching names
header("5. events filter — events=['domain-pre-start','domain-start'] excludes other events")
events_filter_pass = False
if target_ok:
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_events = ex.submit(
            open_window,
            duration=10,
            events=["domain-pre-start", "domain-start"],
        )
        ex.submit(trigger_start_after, TEST_QUBE, 1.5)
        batch_e = fut_events.result()
    show("filtered-by-event batch", batch_e)
    events_e = batch_e.get("events", [])
    if events_e:
        # Every entry must match one of the filter prefixes (exact OR
        # "<filter>:" prefix). For the chosen filter, no entry should
        # be e.g. "domain-pre-shutdown" or "property-set:*".
        def matches(name: str) -> bool:
            return any(
                name == f or name.startswith(f + ":")
                for f in ("domain-pre-start", "domain-start")
            )

        events_filter_pass = all(matches(e["event"]) for e in events_e)
    if not events_e:
        print("  WARN: window collected zero events; flaky timing — re-running may help")
print(f"  {'PASS' if events_filter_pass else 'FAIL'}: events filter restricts to matching names")

# ---------------------------------------------------------- summary
header("Stage F2 test plan — summary")
results = {
    "ai-managed domain-start IS surfaced":           basic_pass,
    "no event with non-ai-managed subject leaks":    no_leak_pass,
    "qube filter restricts to requested qube":       qube_filter_pass,
    "qube filter opaque (missing == untagged)":      opaque_pass,
    "events filter restricts to matching names":     events_filter_pass,
}
for label, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}: {label}")
print(f"\n  Total: {sum(results.values())}/{len(results)} green")

# ---------------------------------------------------------- soft block
header("SOFT (manual) — tag-delete-mid-window surfaces revocation event")
print("""\
  The wrapper has a special case: when the operator removes the ai-managed
  tag from a qube, the resulting domain-tag-delete event normally would be
  dropped (live tag-check on the now-untagged subject fails), losing the
  revocation signal AI most needs to see. The special case includes the
  event if the subject was in the snapshot at window-open.

  To verify end-to-end, run this in dom0 during the window:

    qvm-tags ai-feat-f2 add ai-managed-probe     # any benign tag to set up
    qvm-tags ai-feat-f2 del ai-managed-probe     # warm-up (no F2 surfacing)
    # then with the test qube re-tagged ai-managed and window open:
    qvm-tags ai-feat-f2 del ai-managed
    qvm-tags ai-feat-f2 add ai-managed           # re-add so cleanup succeeds

  Expect a {"event": "domain-tag-delete", "subject": "ai-feat-f2",
  "tag": "ai-managed", ...} entry in the batch.
""")

# ---------------------------------------------------------- cleanup
header("Cleanup")
cleanup(TEST_QUBE)
r = call_qmcp("qmcp.ListAIManagedQubes")
remaining = [q["name"] for q in r.get("qubes", [])]
print(f"  Remaining ai-managed qubes: {remaining}")

sys.exit(0 if all(results.values()) else 1)
