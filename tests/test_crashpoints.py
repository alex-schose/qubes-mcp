"""Crash points: every state-changing operation, interrupted at every qubesd call.

Each scenario is one operation (an operator command, or a dom0 service called
by the hub or a lead) on the project fleet of test_projects.ProjectBase. A
clean run counts the fake qubesd calls the operation makes, reads and writes
alike, and records the state before (B) and after (E). Then, for every call i:

- fail:  the i-th call raises the fake's own exception, so the code's error
         handling and rollback run. A tag write has two calls, one before the
         tag is set and one after (`tag.add.landed:`), so this covers a write
         that fails before it lands and one that lands and still raises;
- death: the i-th call and every later one raise Death, a BaseException that
         no `except Exception` catches, as after a SIGKILL or a power cut;
         nothing after that point reaches qubesd, and files written after it
         are rolled back to what they held at that moment.

What the run left (S) is judged against B and E:

  NEW-AUTHORITY     a qube wears a granting badge neither B nor E gave it
  RESTRICTION-LOST  a restricting badge both B and E keep is gone
  QUBE-LOST         a qube both B and E have is gone
  UNNAMED-MIXED     a qube's badges match neither B nor E, and `qmcp check`
                    has no new finding at all
  MIXED-GENERIC     as above, and check has a new finding that names some
                    other qube but not this one
  RECORDS-TORN      projects.json or gateways.json is neither B's nor E's
  REPORTED-OK       (fail) the operation reported success but S is not E
  SWALLOWED-DEATH   (death) the operation returned normally after Death
  HUNG / ERROR      the run hung, or the operation crashed the harness

A qube left mixed that a new check finding names is acceptable: the operator
is told. Each scenario runs as two tests, one per mode. A verdict that stands
for a known issue deliberately left for a later release is excluded from those
tests and asserted in a test of its own marked expectedFailure, so the issue
stays visible and the rest of the scenario keeps its teeth.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

import racefixture as rf  # noqa: E402
import scratch  # noqa: E402
from racefixture import LEAD, cmd, svc  # noqa: E402
from qmcp import audit  # noqa: E402

# ======================================================================= scenarios

#: name -> (setup, operation)
SCENARIOS: dict = {
    # The services, from the hub's seat and a lead's.
    "svc-spawn-appvm": (rf.nothing, svc("qmcp.SpawnAIManagedQube",
                                        {"name": "ai-hub-new", "template": "ai-debian-13", "netvm": None})),
    "svc-spawn-standalone": (rf.nothing, svc("qmcp.SpawnAIManagedQube",
                                             {"name": "ai-hub-sa", "template": "ai-debian-13",
                                              "klass": "StandaloneVM", "netvm": None})),
    "svc-spawn-dvmt": (rf.nothing, svc("qmcp.SpawnAIManagedQube",
                                       {"name": "ai-hub-dvmt", "template": "ai-debian-13",
                                        "klass": "DispVMTemplate", "netvm": None})),
    "svc-clone-hub": (rf.nothing, svc("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-hub-c1"})),
    "svc-clone-member-by-hub": (rf.nothing, svc("qmcp.CloneAIManagedQube",
                                                {"source": "ai-osint-w1", "name": "ai-osint-w1c"})),
    "svc-disposable": (rf.nothing, svc("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})),
    "lead-spawn": (rf.nothing, svc("qmcp.SpawnAIManagedQube",
                                   {"name": "ai-osint-w3", "template": "ai-debian-13"}, caller=LEAD)),
    "lead-clone": (rf.nothing, svc("qmcp.CloneAIManagedQube",
                                   {"source": "ai-osint-w1", "name": "ai-osint-w1d"}, caller=LEAD)),
    "svc-remove": (rf.nothing, svc("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "remove"})),
    "svc-netvm-null": (rf.nothing, svc("qmcp.SetPropertyAIManaged",
                                       {"name": "ai-work", "property": "netvm", "value": None})),
    "svc-submit": (rf.nothing, svc("qmcp.SubmitProposal",
                                   {"type": "qube-revoke", "title": "t", "qube": "ai-work2"})),
    # The operator's role actions and windows.
    "manage": (rf.outsider, cmd("manage", "op-x")),
    "guard": (rf.nothing, cmd("guard", "ai-work2")),
    "revoke": (rf.nothing, cmd("revoke", "ai-work")),
    "open": (rf.nothing, cmd("open", "ai-tpl-g", "--for", "1h", "--firewall")),
    "seal": (rf.opened, cmd("seal", "ai-tpl-g")),
    "seal-expired": (rf.expired, cmd("seal", "--expired")),
    "seal-all": (rf.opened, cmd("seal", "--all")),
    # Projects.
    "project-create": (rf.nothing, cmd("project", "create", "tools", "--lead-template", "ai-debian-13",
                                       "--network", "none", "--quota", "10G")),
    "project-create-clone": (rf.nothing, cmd("project", "create", "toolc", "--lead-clone", "ai-work2",
                                             "--network", "none", "--quota", "10G")),
    "project-lead-remove": (rf.nothing, cmd("project", "lead", "osint", "--remove")),
    "project-lead-new": (rf.nothing, cmd("project", "lead", "other", "--lead-template", "ai-debian-13")),
    # Refused by the command (another project's member): nothing may change.
    "project-lead-promote-keep": (rf.nothing, cmd("project", "lead", "osint", "--lead-promote",
                                                  "ai-osint-w2", "--keep-old")),
    # Refused by the command (a lead with a network needs its model).
    "project-lead-promote-p00": (rf.nothing, cmd("project", "lead", "osint", "--lead-promote", "ai-hubq",
                                                 "--keep-old")),
    "project-lead-promote-model": (rf.nothing, cmd("project", "lead", "osint", "--lead-promote", "ai-hubq",
                                                   "--keep-old", "--model", "api.example.com:443")),
    "project-delete": (rf.nothing, cmd("project", "delete", "osint", "--yes")),
    "project-move": (rf.nothing, cmd("project", "move", "ai-hubq", "osint", "--yes")),
    "project-dump": (rf.nothing, cmd("project", "dump", "other")),
    "project-edit": (rf.nothing, cmd("project", "edit", "osint", "--quota", "30G")),
    # Gateways, settings, the restore check and the gate.
    "gateway-enroll": (rf.new_gateway, cmd("gateway", "enroll", "gw-new")),
    "gateway-remove": (rf.enrolled_new_gateway, cmd("gateway", "remove", "gw-new")),
    "gateway-set-anon": (rf.enrolled_new_gateway, cmd("gateway", "set", "gw-new", "--anonymising", "yes")),
    "settings-pool-cap": (rf.nothing, cmd("settings", "set", "--pool-cap", "2000G")),
    "restored-accept": (rf.held_restored, cmd("restored", "accept", "ai-back")),
    "restored-accept-all": (rf.held_restored, cmd("restored", "accept", "--all")),
    "restored-reject": (rf.held_restored, cmd("restored", "reject", "ai-back")),
    "gate-hold": (rf.unheld_restored, cmd("gate")),
    # Accepted proposals.
    "accept-revoke": (rf.proposal({"type": "qube-revoke", "title": "t", "qube": "ai-work2"}), rf.accept_op),
    "accept-manage": (rf.proposal({"type": "qube-manage", "title": "t", "qube": "op-x"}, before=rf.outsider),
                      rf.accept_op),
    "accept-open": (rf.proposal({"type": "qube-open", "title": "t", "qube": "ai-tpl-g", "for": "1h",
                                 "firewall": False}), rf.accept_op),
    "accept-project-create": (rf.proposal({"type": "project-create", "title": "t", "label": "scrape",
                                           "lead": {"from": "template", "qube": "ai-debian-13"},
                                           "networks": ["ai-net-router"], "quota": 5 * 1024 ** 3}),
                              rf.accept_op),
}


def _without_lead(record, slot):
    if not isinstance(record, dict) or slot not in record.get("slots", {}):
        return None
    doc = json.loads(json.dumps(record))
    doc["slots"][slot]["lead"] = None
    return doc


def lead_change_stopped(slot, removed=None):
    """A lead change that stops part-way may leave its project with no lead:
    the record names none, and with a new lead made under the old one's name
    (Qubes cannot rename a qube, so the old lead is removed first) the old
    lead may be gone too. No qube is then a principal for the project: the
    safe direction. Acceptable when the command did not report success, a new
    `qmcp check` finding names the project as one without a lead, and the
    record is the one before or after with only the project's lead taken
    away."""
    def allow(verdict, res, clean):
        if res["outcome"].get("ok") or "t" not in res:
            return False
        if not any(i[1] == "projects without a lead" and f"({slot})" in i[2]
                   for i in new_findings(clean, res)):
            return False
        if verdict[0] == "QUBE-LOST":
            return removed is not None and verdict[1] == removed
        if verdict[0] == "RECORDS-TORN" and verdict[1] == "records":
            S = res["S"]["records"]
            return S in (_without_lead(clean["B"]["records"], slot),
                         _without_lead(clean["S"]["records"], slot))
        return False
    allow.__doc__ = lead_change_stopped.__doc__
    return allow


def still_held(qube):
    """A reject stopped part-way may leave the qube wearing only the hold: its
    routed badges come off first and the hold last, so the hold outlives them.
    That is the restrictive direction (still held, nothing routed to it), and
    acceptable when the command did not report success and `qmcp check`'s
    existing "restored qubes" warning names the qube as held for review. The
    finding is not new (the qube was held before the reject too), which is why
    the general rule, which wants a new finding, does not cover it."""
    def allow(verdict, res, clean):
        if verdict[0] not in ("UNNAMED-MIXED", "MIXED-GENERIC") or verdict[1] != qube:
            return False
        if res["outcome"].get("ok") or "t" not in res:
            return False
        left = res["S"]["vms"].get(qube, {}).get("tags", [])
        if [t for t in left if t.startswith("qmcp-") or t in rf.GRANT_FIXED] != ["qmcp-quarantine"]:
            return False
        return any(i[1] == "restored qubes" and "held for your review" in i[2] and qube in i[2]
                   for i in _check(res)[1])
    return allow


#: Verdicts a scenario accepts, each with its reason in the function's docstring.
ALLOWED = {"project-lead-new": lead_change_stopped("p02", removed=rf.OTHER_LEAD),
           "project-lead-promote-model": lead_change_stopped("p01"),
           "restored-reject": still_held("ai-back")}

#: Known issues deliberately left for a later release: (scenario, mode, verdict
#: kind) -> what its expectedFailure test waits for.
KNOWN: dict = {
}


# ======================================================================= runs

def run(name, mode=None, target=0, scenarios=SCENARIOS) -> dict:
    setup, op = scenarios[name]
    t = rf.new_fixture()
    try:
        with rf.time_limit():
            setup(t)
            before = rf.state(t)
            t.probe.arm(mode, target)
            try:
                outcome = rf.guarded(op, t)
                outcome["returned"] = True
            except rf.Death:
                outcome = {"returned": False, "died": True}
            died, count, keys = t.probe.dead, t.probe.count, list(t.probe.keys)
            t.probe.disarm()
            t.probe.dead = False
            if died and t.probe.snap is not None:
                rf.restore_files(t.tmp, t.probe.snap)
            res = {"B": before, "S": rf.state(t), "outcome": outcome, "died": died,
                   "count": count, "keys": keys, "t": t}
            return res
    except rf.Hung as e:
        t.probe.disarm()
        t.probe.dead = False
        rf.close_fixture(t)
        return {"error": f"HUNG: {e}"}
    except BaseException:
        t.probe.disarm()
        t.probe.dead = False
        rf.close_fixture(t)
        raise


def finish(res):
    """Close a run's fixture once the judge is done with it. A call that
    "died" never closed its locks, so they stay held while the run is judged;
    the fixture's cleanup closes them, as the kernel would a killed
    process's, or a sweep of every death point would hold thousands (past
    dom0's default limit of open files)."""
    t = res.pop("t", None)
    if t is not None:
        rf.close_fixture(t)


def _check(res):
    if "CS" not in res:
        res["CS"] = rf.check_items(res["t"])
    return res["CS"]


def new_findings(clean, res) -> list:
    """The `qmcp check` findings on what the run left that neither check(B)
    nor check(E) has."""
    old = {tuple(i) for i in clean["CB"][1]} | {tuple(i) for i in clean["CS"][1]}
    return [i for i in _check(res)[1] if tuple(i) not in old and i[0] != "pass"]


def judge(clean, res, mode) -> list:
    if "error" in res:
        return [["HUNG" if res["error"].startswith("HUNG") else "ERROR", res["error"]]]
    B, E, S = clean["B"], clean["S"], res["S"]
    out = []
    mixed = []
    for q in sorted(set(B["vms"]) | set(E["vms"]) | set(S["vms"])):
        vb, ve, vs = B["vms"].get(q), E["vms"].get(q), S["vms"].get(q)
        if vs is None:
            if vb is not None and ve is not None:
                out.append(["QUBE-LOST", q])
            continue
        ts = set(vs["tags"])
        gb = rf.granting(vb["tags"]) if vb else set()
        ge = rf.granting(ve["tags"]) if ve else set()
        extra = rf.granting(ts) - (gb | ge)
        if extra:
            out.append(["NEW-AUTHORITY", q, sorted(extra), sorted(ts)])
        if vb and ve:
            lost = (rf.restricting(vb["tags"]) & rf.restricting(ve["tags"])) - rf.restricting(ts)
            if lost:
                out.append(["RESTRICTION-LOST", q, sorted(lost), sorted(ts)])
        options = [rf.badge_pair(v) for v in (vb, ve) if v is not None] or [(frozenset(), frozenset())]
        if rf.badge_pair(vs) not in options:
            mixed.append((q, sorted(ts)))
    res["check"] = None
    if mixed or any(v[0] in ("QUBE-LOST", "RECORDS-TORN") for v in out):
        cs = _check(res)
        res["check"] = cs[0]
        new_items = new_findings(clean, res)
        for q, ts in mixed:
            if any(q in i[2] for i in new_items):
                continue                    # mixed, and check names it: the operator is told
            out.append(["MIXED-GENERIC" if new_items else "UNNAMED-MIXED", q, ts, cs[0]])
    for f in ("records", "gateways"):
        if S[f] != B[f] and S[f] != E[f]:
            out.append(["RECORDS-TORN", f, str(S[f])[:200]])
    if out and res["check"] is None:
        res["check"] = _check(res)[0]
    differs = set(S["vms"]) != set(E["vms"]) or any(
        rf.badge_pair(S["vms"][q]) != rf.badge_pair(E["vms"][q]) for q in set(S["vms"]) & set(E["vms"]))
    if mode == "fail" and res["outcome"].get("ok") and differs:
        out.append(["REPORTED-OK", res["outcome"].get("text", "")[-300:]])
    if mode == "death" and res["died"] and res["outcome"].get("returned"):
        out.append(["SWALLOWED-DEATH", res["outcome"].get("text", "")[-300:]])
    return out


_CLEAN: dict = {}


def clean_run(name, scenarios=SCENARIOS) -> dict:
    key = (id(scenarios), name)
    if key not in _CLEAN:
        res = run(name, scenarios=scenarios)
        if "error" in res:
            raise AssertionError(f"{name}: the clean run failed: {res['error']}")
        t = res["t"]
        res["CS"] = rf.check_items(t)
        finish(res)
        # check(B): the same setup, judged before the operation.
        setup, _ = scenarios[name]
        t = rf.new_fixture()
        try:
            setup(t)
            res["CB"] = rf.check_items(t)
        finally:
            rf.close_fixture(t)
        _CLEAN[key] = res
    return _CLEAN[key]


def sweep(name, mode, scenarios=SCENARIOS) -> list:
    """Every crash point of one scenario in one mode: [(i, key, verdicts)]."""
    clean = clean_run(name, scenarios)
    n = clean["count"]
    found = []
    for i in range(1, n + 1):
        res = run(name, mode, i, scenarios)
        try:
            verdicts = judge(clean, res, mode)
            allow = ALLOWED.get(name)
            if allow is not None:
                verdicts = [v for v in verdicts if not allow(v, res, clean)]
        finally:
            finish(res)
        if verdicts:
            found.append((i, clean["keys"][i - 1], verdicts))
    return found


def describe(found, limit=12) -> str:
    lines = []
    for i, key, verdicts in found[:limit]:
        lines.append(f"  call {i} [{key}]: " + "; ".join(json.dumps(v)[:240] for v in verdicts))
    if len(found) > limit:
        lines.append(f"  ... and {len(found) - limit} more crash points")
    return "\n".join(lines)


_SWEEPS: dict = {}


def cached_sweep(name, mode):
    if (name, mode) not in _SWEEPS:
        _SWEEPS[(name, mode)] = sweep(name, mode)
    return _SWEEPS[(name, mode)]


# ======================================================================= the tests

class CrashPoints(unittest.TestCase):
    """One test per scenario and mode; generated below."""

    maxDiff = None


def _make(name, mode):
    def test(self):
        found = cached_sweep(name, mode)
        bad = []
        for i, key, verdicts in found:
            rest = [v for v in verdicts if (name, mode, v[0]) not in KNOWN]
            if rest:
                bad.append((i, key, rest))
        if bad:
            self.fail(f"{name} ({mode}): {len(bad)} of {clean_run(name)['count']} crash points "
                      f"leave a state the invariants refuse\n{describe(bad)}")
    test.__doc__ = f"{name}, {mode} at every qubesd call: no authority gained or restriction lost, " \
                   f"no qube lost, mixed states named by check, success never reported for a failed change."
    return test


def _make_known(name, mode, kind, reason):
    @unittest.expectedFailure
    def test(self):
        found = cached_sweep(name, mode)
        hits = [(i, key, [v for v in verdicts if v[0] == kind]) for i, key, verdicts in found]
        hits = [h for h in hits if h[2]]
        self.assertFalse(hits, f"{name} ({mode}) {kind}:\n{describe(hits)}")
    test.__doc__ = f"Known, left for a later release: {name} ({mode}) {kind}. Waits for {reason}."
    return test


for _name in SCENARIOS:
    for _mode in ("fail", "death"):
        setattr(CrashPoints, f"test_{_name.replace('-', '_')}_{_mode}", _make(_name, _mode))


# ======================================================================= positive controls

def _control_bad_rollback(t):
    vm = t.app.domains["ai-work2"]
    try:
        vm.tags.add("qmcp-guarded")
        vm.features["control"] = "1"
    except Exception:
        vm.tags.discard("qmcp-guarded")
        vm.tags.add("qmcp-lead-p01")        # a "rollback" that grants
        raise
    return {"ok": True, "text": "done"}


def _control_reports_ok(t):
    vm = t.app.domains["ai-work2"]
    try:
        vm.tags.add("qmcp-guarded")
        vm.features["control"] = "1"
    except Exception:
        pass                                 # says done after a failure
    return {"ok": True, "text": "done"}


def _control_swallows_death(t):
    vm = t.app.domains["ai-work2"]
    try:
        vm.tags.add("qmcp-guarded")
    except BaseException:                    # noqa: B036  (catches Death on purpose)
        pass
    return {"ok": True, "text": "done"}


CONTROLS = {
    "bad-rollback": (rf.nothing, _control_bad_rollback),
    "reports-ok": (rf.nothing, _control_reports_ok),
    "swallows-death": (rf.nothing, _control_swallows_death),
}


class Controls(unittest.TestCase):
    """Each control is written to break one invariant; the judge must see it,
    or a green crash-point test proves nothing."""

    def kinds(self, name, mode):
        return {v[0] for _, _, verdicts in sweep(name, mode, CONTROLS) for v in verdicts}

    def test_a_rollback_that_grants_is_new_authority(self):
        self.assertIn("NEW-AUTHORITY", self.kinds("bad-rollback", "fail"))

    def test_success_after_a_failure_is_reported_ok(self):
        self.assertIn("REPORTED-OK", self.kinds("reports-ok", "fail"))

    def test_catching_death_is_swallowed_death(self):
        self.assertIn("SWALLOWED-DEATH", self.kinds("swallows-death", "death"))

    def test_the_fail_mode_covers_a_write_that_lands_and_raises(self):
        keys = clean_run("guard")["keys"]
        self.assertTrue(any(k.startswith("tag.add.landed:") for k in keys), keys)


# ======================================================================= what a run leaves behind

class Hygiene(unittest.TestCase):
    """A simulated death keeps the dead operation's locks held while its run
    is judged, as a dead process's would be until the kernel closed them, and
    closing the run leaves nothing: no descriptor, no temp dir, no snapshot."""

    def test_a_death_holds_its_locks_until_the_run_is_closed(self):
        name = "svc-spawn-appvm"
        n = clean_run(name)["count"]
        open_before = len(os.listdir("/proc/self/fd"))
        held_somewhere = False
        for i in range(1, n + 1):
            res = run(name, "death", i)
            t, snap = res["t"], res["t"].probe.snap
            self.assertTrue(res["died"], i)
            held = scratch.fds_under(t.tmp)
            held_somewhere = held_somewhere or bool(held)
            finish(res)
            self.assertEqual(scratch.fds_under(t.tmp), [], i)
            self.assertFalse(t.tmp.exists(), i)
            self.assertFalse(snap is not None and snap.exists(), i)
            self.assertLessEqual(len(os.listdir("/proc/self/fd")), open_before, i)
        # Teeth: some death point does leave a lock held during the judge.
        self.assertTrue(held_somewhere, f"no death point of {name} left a lock held")


# ======================================================================= a torn audit line

class TornAudit(rf.Fixture):
    """A crash or power cut in the middle of an audit append leaves half a
    line with no newline. The next change's record must still be a line of its
    own, so it is not lost with the torn bytes."""

    def change(self, value):
        r = rf.run_svc(self, "qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory",
                                                           "value": value})
        self.assertTrue(r["ok"], r)

    def test_the_record_after_a_torn_line_is_kept(self):
        log = pathlib.Path(audit.LOG_PATH)
        self.change(500)
        full = log.read_text()
        last = full.splitlines()[-1]
        log.write_text(full + last[: len(last) // 2])
        self.change(600)
        tail = log.read_text().splitlines()[-1]
        rec = json.loads(tail)
        self.assertEqual((rec["service"], rec["args"]["property"]), ("qmcp.SetPropertyAIManaged", "memory"))

    def test_the_tear_is_reported(self):
        log = pathlib.Path(audit.LOG_PATH)
        self.change(500)
        full = log.read_text()
        last = full.splitlines()[-1]
        log.write_text(full + last[: len(last) // 2])
        ok, _, _ = audit.verify()
        self.assertFalse(ok)


def _register_known():
    for (name, mode, kind), reason in KNOWN.items():
        setattr(CrashPoints, f"test_known_{name.replace('-', '_')}_{mode}_{kind.lower().replace('-', '_')}",
                _make_known(name, mode, kind, reason))


_register_known()

if __name__ == "__main__":
    unittest.main()
