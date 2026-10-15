"""Interleavings: two operations on one fleet at once must end as some serial order.

For a pair (A, B) of operations on the project fleet of
test_projects.ProjectBase, the serial runs give the acceptable end states: A
then B, B then A, and A or B alone (an "alone" state counts only when the other
operation refused in the interleaved run, as a busy lock or a failed re-check
makes it do). Then, for every fake qubesd call k of A, a run pauses A just
before that call and starts B in a thread of its own, as a second process
would run it. A goes on once B has finished, or once B is waiting (every wait
in the library is a sleep between tries of a lock, and the only lock B can
wait for is one A holds); B then gets that lock when A lets it go, and must
finish within a few seconds. B's locks are new descriptors, which flock
treats as another holder even in one process, and every lock wait is real
(a few seconds), so an operator command waits for a call in flight exactly as
it does on dom0, where no call holds a qube's lock for anywhere near its wait.

The end state is judged per qube on its granting badges, its restricting
badges, whether it runs, and whether it exists:

  NON-SERIAL          the end state is none of the acceptable ones
  OUTCOME-NOT-SERIAL  the end state is a serial one, but what A and B were told
                      (success or refusal) is not what that order tells them:
                      one was told it succeeded and the other undid it
  NEW-AUTHORITY       a qube wears a granting badge no acceptable state gives it
  DEADLOCK            B never finished
  A-WAITED            A slept on a lock while B still ran: the two take locks
                      in different orders

Each pair is one test, which fails on any of these at any k, listing the
failing calls and, per qube, what the run left against what each acceptable
order leaves.

Two pairs also run with B in A's thread and every wait zero, so B can never
wait for A: an operator command that only takes authority away then goes on
without the qube's lock, which on dom0 needs a call to hold that lock for
longer than the command's whole wait. Those runs are judged only on what the
command told the operator: it must say it went on without the lock.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

import racefixture as rf  # noqa: E402
from racefixture import LEAD, cmd, svc  # noqa: E402


def raw_tag(qube, tag):
    """What one of dom0's own passes does to a qube in one write: the restore
    check's hold, or the anonymity gate's block."""
    def op(t):
        t.app.domains[qube].tags.add(tag)
        return {"ok": True, "text": f"{tag} on {qube}"}
    return op


def unlabelled(qube):
    """`qube` carries no label of this dom0's, as after a restore from a
    backup: the restore check's next pass holds it."""
    def setup(t):
        dict.__delitem__(t.app.domains[qube].features, "qmcp-id")
    return setup


LEAD_SPAWN = svc("qmcp.SpawnAIManagedQube", {"name": "ai-osint-w3", "template": "ai-debian-13"}, caller=LEAD)
HUB_SPAWN_A = svc("qmcp.SpawnAIManagedQube", {"name": "ai-hub-a", "template": "ai-debian-13", "netvm": None})
REVOKE_PROPOSAL = rf.proposal({"type": "qube-revoke", "title": "t", "qube": "ai-work2"})

#: name -> (setup, A, B)
PAIRS = {
    # A create against the operator changing its source, its caller or its project.
    "clone-x-revoke-source": (rf.nothing, svc("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-hub-c1"}),
                              cmd("revoke", "ai-work2")),
    "clone-x-guard-source": (rf.nothing, svc("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-hub-c1"}),
                             cmd("guard", "ai-work2")),
    "lead-spawn-x-lead-remove": (rf.nothing, LEAD_SPAWN, cmd("project", "lead", "osint", "--remove")),
    "lead-spawn-x-lead-new": (rf.nothing, LEAD_SPAWN,
                              cmd("project", "lead", "osint", "--lead-template", "ai-debian-13")),
    "lead-spawn-x-delete": (rf.nothing, LEAD_SPAWN, cmd("project", "delete", "osint", "--yes")),
    "lead-spawn-x-hold-lead": (rf.nothing, LEAD_SPAWN, raw_tag(LEAD, "qmcp-quarantine")),
    "lead-spawn-x-block-lead": (rf.nothing, LEAD_SPAWN, raw_tag(LEAD, "qmcp-blocked")),
    "lead-clone-x-move-out": (rf.nothing, svc("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1", "name": "ai-osint-w1d"},
                                              caller=LEAD),
                              cmd("project", "move", "ai-osint-w1", "p00", "--yes")),
    # A service operating a qube against the operator or dom0 changing that qube.
    "remove-x-guard": (rf.nothing, svc("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "remove"}),
                       cmd("guard", "ai-work2")),
    # The restore check's pass (the first thing `qmcp gate` runs) holding the
    # qube the hub is removing.
    "remove-x-hold": (unlabelled("ai-work2"),
                      svc("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "remove"}),
                      cmd("gate")),
    "feature-x-guard": (rf.nothing, svc("qmcp.SetFeatureAIManaged", {"name": "ai-work2", "feature": "service.x",
                                                                     "value": "1"}),
                        cmd("guard", "ai-work2")),
    "start-x-revoke": (rf.nothing, svc("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"}),
                       cmd("revoke", "ai-work2")),
    "netvm-null-x-move-in": (rf.nothing, svc("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "netvm",
                                                                           "value": None}),
                             cmd("project", "move", "ai-work", "osint", "--yes")),
    # Two creates, and a create against the cap.
    "spawn-x-spawn-same-name": (rf.nothing,
                                svc("qmcp.SpawnAIManagedQube", {"name": "ai-hub-dup", "template": "ai-debian-13",
                                                               "netvm": None}),
                                svc("qmcp.SpawnAIManagedQube", {"name": "ai-hub-dup", "template": "ai-debian-13",
                                                               "netvm": None})),
    "spawn-x-spawn-at-cap": (rf.cap_room(1), HUB_SPAWN_A,
                             svc("qmcp.SpawnAIManagedQube", {"name": "ai-hub-b", "template": "ai-debian-13",
                                                            "netvm": None})),
    "spawn-x-lower-cap": (rf.nothing, HUB_SPAWN_A, cmd("settings", "set", "--pool-cap", "1G")),
    # Windows.
    "open-x-seal": (rf.nothing, cmd("open", "ai-tpl-g", "--for", "1h", "--firewall"), cmd("seal", "ai-tpl-g")),
    "seal-x-open": (rf.opened, cmd("seal", "ai-tpl-g"), cmd("open", "ai-tpl-g", "--for", "1h")),
    "expire-x-open": (rf.expired, cmd("seal", "--expired"), cmd("open", "ai-tpl-g", "--for", "1h")),
    "open-x-manage": (rf.nothing, cmd("open", "ai-tpl-g", "--for", "1h", "--firewall"), cmd("manage", "ai-tpl-g")),
    # Proposals.
    "accept-x-accept": (REVOKE_PROPOSAL, rf.accept_op, rf.accept_op),
    "accept-x-reject": (REVOKE_PROPOSAL, rf.accept_op, rf.reject_op),
    # The restore check and the gate.
    "restored-accept-x-gate": (rf.held_restored, cmd("restored", "accept", "ai-back"), cmd("gate")),
    "manage-x-gate": (rf.outsider, cmd("manage", "op-x"), cmd("gate")),
    "lead-new-x-lead-spawn": (rf.nothing, cmd("project", "lead", "osint", "--lead-template", "ai-debian-13"),
                              LEAD_SPAWN),
}


# ======================================================================= runs

def run(pairs, name, plan, k=0) -> dict:
    """plan: "A", "B", "AB", "BA", "none" (serial); "T": B in its own thread
    from call k of A; "I": B run to the end in A's thread at call k, with
    every wait zero."""
    setup, a_op, b_op = pairs[name]
    t = rf.new_fixture()
    try:
        with rf.time_limit():
            setup(t)
            out = {}
            ops = {"A": a_op, "B": b_op}
            if plan == "T":
                rf.real_waits()
                t.probe.arm("thread", k, second=b_op)
                out["a"] = rf.guarded(a_op, t)
                t.probe.disarm()
                if not t.probe.finish_second():
                    return {"error": "DEADLOCK: B was still running 10 s after A finished",
                            "deadlock": True}
                out["b"] = t.probe.second_outcome or {"ok": None, "note": "B never ran"}
                out["blocked"], out["a_waited"] = t.probe.second_blocked, t.probe.first_waited
                out["count"], out["keys"] = t.probe.count, list(t.probe.keys)
            elif plan == "I":
                t.probe.arm("pause", k, second=b_op)
                out["a"] = rf.guarded(a_op, t)
                t.probe.disarm()
                out["b"] = t.probe.second_outcome or {"ok": None, "note": "B never ran"}
                out["count"], out["keys"] = t.probe.count, list(t.probe.keys)
            else:
                for step in ("" if plan == "none" else plan):
                    if step == "A":
                        t.probe.arm()
                    out[step.lower()] = rf.guarded(ops[step], t)
                    if step == "A":
                        out["count"], out["keys"] = t.probe.count, list(t.probe.keys)
                    t.probe.disarm()
            out["S"] = rf.state(t)
            return out
    except rf.Hung as e:
        return {"error": f"HUNG: {e}"}
    finally:
        t.probe.disarm()
        t.doCleanups()


def _view(S) -> dict:
    """Per qube: granting badges, restricting badges, and whether it runs (a
    revoke or seal that leaves the qube running has not done its job)."""
    return {q: rf.badge_pair(v) + (v.get("power") in rf.RUNNING,) for q, v in S["vms"].items()}


def _show(entry) -> str:
    if entry is None:
        return "absent"
    g, r, running = entry
    return f"grant={sorted(g)} restrict={sorted(r)}{' running' if running else ''}"


def _text(outcome) -> str:
    return (outcome.get("text") or outcome.get("raised") or outcome.get("note") or "").strip()[-200:]


def judge(serial, res) -> list:
    if "error" in res:
        return [["DEADLOCK" if res.get("deadlock") else "ERROR", res["error"]]]
    if res.get("a_waited"):
        return [["A-WAITED", f"A slept on a lock while B still ran; A told {_text(res['a'])!r}, "
                 f"B told {_text(res['b'])!r}"]]
    a_ok, b_ok = bool(res["a"].get("ok")), bool(res["b"].get("ok"))
    acceptable = {"A then B": serial["AB"]["S"], "B then A": serial["BA"]["S"]}
    if not b_ok:
        acceptable["A alone"] = serial["A"]["S"]
    if not a_ok:
        acceptable["B alone"] = serial["B"]["S"]
    if not a_ok and not b_ok:
        acceptable["neither"] = serial["none"]["S"]
    told = {"A then B": (bool(serial["AB"]["a"].get("ok")), bool(serial["AB"]["b"].get("ok"))),
            "B then A": (bool(serial["BA"]["a"].get("ok")), bool(serial["BA"]["b"].get("ok"))),
            "A alone": (True, False), "B alone": (False, True), "neither": (False, False)}
    if "A alone" in acceptable:
        told["A alone"] = (bool(serial["A"]["a"].get("ok")), False)
    if "B alone" in acceptable:
        told["B alone"] = (False, bool(serial["B"]["b"].get("ok")))
    view = _view(res["S"])
    matches = [label for label, st in acceptable.items() if _view(st) == view]
    for label in matches:
        if told[label] == (a_ok, b_ok):
            return []
    if matches:
        return [["OUTCOME-NOT-SERIAL", f"the end state is {' / '.join(matches)}'s, but A was told "
                 f"ok={a_ok} ({_text(res['a'])!r}) and B ok={b_ok} ({_text(res['b'])!r}); that "
                 f"order tells them " + ", ".join(f"{m}: A ok={told[m][0]}, B ok={told[m][1]}"
                                                  for m in matches)]]
    out = []
    union: dict = {}
    for st in acceptable.values():
        for q, (g, _, _) in _view(st).items():
            union.setdefault(q, set()).update(g)
    for q, (g, _, _) in sorted(view.items()):
        extra = set(g) - union.get(q, set())
        if extra:
            out.append(["NEW-AUTHORITY", f"{q} wears {sorted(extra)}, which no serial order gives it"])
    diffs = []
    for q in sorted(set(view) | {q for st in acceptable.values() for q in st["vms"]}):
        options = {label: _view(st).get(q) for label, st in acceptable.items()}
        if view.get(q) not in options.values():
            diffs.append(f"{q}: left {_show(view.get(q))}; " +
                         "; ".join(f"{label}: {_show(v)}" for label, v in options.items()))
    out.append(["NON-SERIAL", f"A ok={a_ok} ({_text(res['a'])!r}), B ok={b_ok} ({_text(res['b'])!r}); "
                + " | ".join(diffs)])
    return out


def serial_runs(pairs, name) -> dict:
    serial = {p: run(pairs, name, p) for p in ("A", "B", "AB", "BA", "none")}
    errors = {p: s["error"] for p, s in serial.items() if "error" in s}
    if errors:
        raise AssertionError(f"{name}: a serial run failed: {errors}")
    return serial


def interleavings(pairs, name, plan="T") -> tuple:
    """(number of A's calls, [(k, key, verdicts)] for every k that is not serial)."""
    serial = serial_runs(pairs, name)
    n = serial["A"]["count"]
    bad = []
    for k in range(1, n + 1):
        verdicts = judge(serial, run(pairs, name, plan, k))
        if verdicts:
            bad.append((k, serial["A"]["keys"][k - 1], verdicts))
    return n, bad


def describe(n, bad) -> str:
    """The failing calls, runs of identical verdicts folded into one line."""
    lines, i = [], 0
    while i < len(bad):
        j = i
        while j + 1 < len(bad) and bad[j + 1][2] == bad[i][2] and bad[j + 1][0] == bad[j][0] + 1:
            j += 1
        span = f"k={bad[i][0]}" if i == j else f"k={bad[i][0]}-{bad[j][0]}"
        lines.append(f"  {span} of {n} [{bad[i][1]}{'' if i == j else ' .. ' + bad[j][1]}]:")
        lines += [f"    {v[0]}: {v[1]}" for v in bad[i][2]]
        i = j + 1
    return "\n".join(lines)


class Interleave(unittest.TestCase):
    """One test per pair; generated below."""


def _make(name):
    def test(self):
        n, bad = interleavings(PAIRS, name)
        self.assertGreater(n, 0, f"{name}: A made no qubesd call, so nothing was interleaved")
        if bad:
            self.fail(f"{name}: {len(bad)} of {n} pause points end in no serial order\n{describe(n, bad)}")
    test.__doc__ = f"{name}: B run at each qubesd call of A ends as A then B, B then A, or one alone."
    return test


for _name in PAIRS:
    setattr(Interleave, f"test_{_name.replace('-', '_')}", _make(_name))


#: The pairs also run with B unable to wait for A (see the module docstring).
UNLOCKED_PAIRS = ("remove-x-guard", "start-x-revoke")
WENT_ON = "went on without it"


class Unlocked(unittest.TestCase):
    """A command that takes authority away and could not have the qube's lock
    goes on, and says so: the operator is told to look again."""


def _make_unlocked(name):
    def test(self):
        serial = serial_runs(PAIRS, name)
        n = serial["A"]["count"]
        said, silent = [], []
        for k in range(1, n + 1):
            res = run(PAIRS, name, "I", k)
            self.assertNotIn("error", res, f"{name} k={k}: {res.get('error')}")
            told = _text(res["b"]) if len(_text(res["b"])) < 190 else (res["b"].get("text") or "")
            if WENT_ON in told:
                said.append(k)
            elif judge(serial, res):
                silent.append(f"k={k} [{serial['A']['keys'][k - 1]}]: B told {_text(res['b'])!r}")
        self.assertTrue(said, f"{name}: B never went on without the lock, so this tests nothing")
        self.assertFalse(silent, f"{name}: B ended in no serial order without saying it went on "
                                 f"without the lock:\n  " + "\n  ".join(silent))
    test.__doc__ = (f"{name}, B unable to wait for A: wherever the end is not serial, B said it "
                    f"went on without the lock.")
    return test


for _name in UNLOCKED_PAIRS:
    setattr(Unlocked, f"test_{_name.replace('-', '_')}", _make_unlocked(_name))


# ======================================================================= the judge's teeth

def _check_then_grant(t):
    """Reads the qube's tags, then (one more qubesd call later) grants it a
    window on the strength of that read: no lock, no re-check."""
    vm = t.app.domains["ai-work2"]
    if "ai-managed" not in set(vm.tags):
        return {"ok": False, "text": "not in AI space"}
    vm.features["control"] = "1"
    vm.tags.add("qmcp-open")
    return {"ok": True, "text": "opened"}


def _strip_everything(t):
    vm = t.app.domains["ai-work2"]
    for tag in sorted(rf.granting(vm.tags.raw())):
        vm.tags.discard(tag)
    return {"ok": True, "text": "stripped"}


def _refuse(t):
    return {"ok": False, "text": "busy"}


CONTROLS = {
    "check-then-grant-x-strip": (rf.nothing, _check_then_grant, _strip_everything),
    "check-then-grant-x-refusal": (rf.nothing, _check_then_grant, _refuse),
}


class Controls(unittest.TestCase):
    def test_a_grant_on_a_stale_check_is_caught(self):
        n, bad = interleavings(CONTROLS, "check-then-grant-x-strip")
        kinds = {v[0] for _, _, verdicts in bad for v in verdicts}
        self.assertIn("NEW-AUTHORITY", kinds)
        self.assertIn("NON-SERIAL", kinds)
        # Before the first read, B's strip lands first: B then A, serial.
        self.assertNotIn(1, [k for k, _, _ in bad])

    def test_a_refused_b_is_a_alone(self):
        n, bad = interleavings(CONTROLS, "check-then-grant-x-refusal")
        self.assertEqual(bad, [], describe(n, bad))


if __name__ == "__main__":
    unittest.main()
