"""Offline suite for where audit lines go, and for the log's rotation and
retention (0.9.33).

- **Modes**: the install's (`install.sh --audit-log`) and a project's
  (`qmcp project audit`), the more private winning; a line belongs to a
  project when its caller leads it, a qube it names wears its badges (before
  the call acts, read only from the request keys its service acts on, or
  after), or it names the project; an unknown place is RAM.
- **A line kept nowhere costs what any line costs**: it is counted, capped
  and spends its caller's budget (only install mode none counts nothing), and
  the room is judged on every chain the install may write, whatever the
  line's own place.
- **Rotation and retention**: the hourly run rotates the log by day or size
  and removes rotated logs by age only; it rotates a RAM chain past its size
  and removes the oldest rotated RAM files past the RAM bound, never a live
  chain; it writes a line only for what it did, and an unreadable setting
  removes nothing. A rotation killed part-way never stops the next, and
  `qmcp check` fails while the timer does not run.
- **Wiring**: the timer and service, the tmpfiles line, the installer and the
  uninstaller, and every audit call naming where its line belongs, pinned.
"""
from __future__ import annotations

import ast
import datetime
import json
import os
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, cli, core, fleet, projects, services  # noqa: E402
from test_dom0 import HUB, Base  # noqa: E402
from test_projects import LEAD  # noqa: E402
from test_proposals import PBase  # noqa: E402

DEPLOY = HERE.parent / "deploy"


def lines_of(path) -> list:
    p = pathlib.Path(path)
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


class ModeBase(PBase):
    def set_install(self, word):
        pathlib.Path(audit.MODE_PATH).write_text(word + "\n")

    def set_project(self, slot, mode):
        records = projects.load()
        records[slot].audit = mode
        projects.save(records)

    def disk(self):
        return lines_of(audit.LOG_PATH)

    def ram(self, slot=None):
        return lines_of(audit.ram_path(slot))

    def services_of(self, lines):
        return [l["service"] for l in lines]


# ======================================================================= the services' lines

class ServiceLines(ModeBase):
    def test_a_lead_call_follows_its_projects_ram_mode(self):
        self.set_project("p01", "ram")
        r = self.lcall("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "memory",
                                                     "value": 900})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.services_of(self.ram("p01")), ["qmcp.SetPropertyAIManaged"])
        self.assertEqual(self.disk(), [])
        ok, n, err = audit.verify(audit.ram_path("p01"))
        self.assertEqual((ok, n), (True, 1), err)

    def test_the_hubs_call_into_an_off_projects_qube_writes_nothing_but_counts_as_one(self):
        # Counted and capped like any line, so the time a call takes past a
        # cap does not tell which names belong to a project logging nowhere.
        self.set_project("p01", "off")
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "start"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.disk(), [])
        self.assertEqual(audit.ram_chains(), [])
        counter = pathlib.Path(audit.ram_dir()).parent / "calls" / f"{HUB}{audit.REFUSED_SUFFIX}"
        self.assertEqual(json.loads(counter.read_text()).get("lines"), 1)
        self.assertIsNone(audit.dropped())          # nothing meant to be written was lost

    def test_past_the_hourly_cap_an_off_projects_call_does_what_a_disk_one_does(self):
        from unittest import mock
        self.set_project("p01", "off")
        paid = []
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 1), \
                mock.patch.object(audit, "_pay_like", lambda mode: paid.append(mode)):
            for name in ("ai-osint-w1", "ai-work2", "ai-osint-w1", "ai-work2"):
                r = self.call("qmcp.SetPropertyAIManaged", {"name": name, "property": "no-such",
                                                            "value": 1})
                self.assertFalse(r["ok"])
        # The cap is the caller's, whatever the project: the first (off) call
        # takes it and pays the padded write; past it no call writes anything,
        # off or disk, but the one line saying calls are counted.
        self.assertEqual(paid, ["disk"])
        self.assertEqual([l["service"] for l in self.disk()], [audit.CAPPED_SERVICE])

    def test_a_key_the_service_ignores_never_moves_its_line(self):
        # The caller chooses every key it sends: one the service does not act
        # on, naming a qube of a project kept nowhere or in RAM, must not take
        # the caller's own change off the disk.
        from qmcp import services
        self.set_project("p01", "off")
        self.set_project("p02", "ram")
        for extra in ({"template": "ai-osint-w1"}, {"source": "ai-other-w1"},
                      {"qube": "ai-osint-w1", "qubes": ["ai-other-w1"], "project": "osint"}):
            with self.subTest(extra):
                n = len(self.disk())
                r = self.call("qmcp.SetPropertyAIManaged",
                              dict({"name": "ai-work2", "property": "memory",
                                    "value": 900 + n}, **extra))
                self.assertTrue(r["ok"], r)
                self.assertEqual(len(self.disk()), n + 1)
        self.assertEqual(audit.ram_chains(), [])
        # Every service that changes something says which keys it acts on.
        changing = {name for name, (_, changes) in services.SERVICES.items() if changes}
        self.assertEqual(changing - set(audit.REQUEST_KEYS), {"qmcp.SubmitProposal"})

    def test_the_capped_line_goes_where_the_callers_own_lines_go(self):
        # The call that crosses the cap names an off project's qube: the line
        # saying calls are now counted must not follow it nowhere.
        from unittest import mock
        self.set_project("p01", "off")
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1",
                                                        "property": "no-such", "value": 1})
        self.assertFalse(r["ok"])
        self.assertEqual(self.services_of(self.disk()), [audit.CAPPED_SERVICE])

    def test_a_proposals_line_goes_where_the_hubs_own_lines_go(self):
        self.set_project("p01", "off")
        r = self.call("qmcp.SubmitProposal", {"type": "project-delete", "title": "t",
                                              "project": "osint"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.services_of(self.disk()), ["qmcp.SubmitProposal"])

    def test_the_records_are_read_for_every_name(self):
        # Read only for a slot-badged name, the time would tell a hidden
        # project's qube from a name that does not exist.
        from unittest import mock
        loads = []
        real = projects.load
        with mock.patch.object(projects, "load", lambda *a, **k: loads.append(1) or real(*a, **k)):
            for name in ("ai-osint-w1", "no-such-qube", "ai-work2"):
                loads.clear()
                audit.place(self.app, {"name": name})
                self.assertEqual(len(loads), 1, name)

    def test_the_hubs_call_on_a_qube_of_no_project_stays_on_disk(self):
        self.set_project("p01", "off")
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory",
                                                    "value": 900})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.services_of(self.disk()), ["qmcp.SetPropertyAIManaged"])

    def test_a_qube_the_call_removes_still_counts_by_the_badges_read_before(self):
        self.set_project("p01", "ram")
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "remove"})
        self.assertTrue(r["ok"], r)
        self.assertIsNone(self.app.domains._any("ai-osint-w1"))
        self.assertEqual(self.services_of(self.ram("p01")), ["qmcp.LifecycleAIManaged"])
        self.assertEqual(self.disk(), [])

    def test_a_badge_read_that_fails_sends_the_line_to_ram_and_refuses_nothing(self):
        # The first tag.List of the qube is the audit's, before the call acts.
        self.app.fail_reads("tag.List:ai-work2", "fail")
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory",
                                                    "value": 900})
        self.assertTrue(r["ok"], r)
        self.assertGreater(self.app.failed["tag.List:ai-work2"], 0)
        self.assertEqual(self.disk(), [])
        self.assertEqual(self.services_of(self.ram()), ["qmcp.SetPropertyAIManaged"])

    def test_badges_a_qube_wears_when_the_line_is_written_count(self):
        # The operator moves the qube into p01 while the hub's call runs: its
        # line follows p01's mode, read again after the call acts.
        self.set_project("p01", "ram")
        handler, changing = services.SERVICES["qmcp.SetPropertyAIManaged"]

        def moved(app, call, req):
            out = handler(app, call, req)
            app.domains["ai-work2"].tags.add("qmcp-proj-p01")
            return out
        services.SERVICES["qmcp.SetPropertyAIManaged"] = (moved, changing)
        self.addCleanup(services.SERVICES.__setitem__, "qmcp.SetPropertyAIManaged",
                        (handler, changing))
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory",
                                                    "value": 900})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.disk(), [])
        self.assertEqual(self.services_of(self.ram("p01")), ["qmcp.SetPropertyAIManaged"])

    def test_a_slot_badge_with_no_record_is_ram(self):
        self.app.vm("ai-left", tags={"ai-managed", "qmcp-proj-p07"})
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-left", "property": "memory",
                                                    "value": 900})
        self.assertEqual(self.disk(), [], r)
        self.assertEqual(len(self.ram()), 1)                # the install's chain: no p07 to own it
        self.assertEqual(self.ram("p07"), [])

    def test_install_mode_none_writes_nothing_and_never_refuses_for_the_log(self):
        self.set_install("none")
        saved = audit.room
        audit.room = lambda path=None: False            # no room anywhere
        self.addCleanup(setattr, audit, "room", saved)
        counter = pathlib.Path(audit.ram_dir()).parent / "calls" / f"{HUB}{audit.REFUSED_SUFFIX}"
        day = audit._utc_now_iso()[:10]
        counter.write_text(json.dumps({"day": day, "lines": audit.AUDIT_LINES_PER_DAY}))
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory",
                                                    "value": 900})
        self.assertTrue(r["ok"], r)                       # no floor, no budget: nothing is written
        self.assertEqual(self.disk(), [])
        self.assertEqual(audit.ram_chains(), [])

    def test_install_mode_ram_and_an_unreadable_mode_file_go_to_the_install_ram_chain(self):
        for word in ("ram", "garbage"):
            self.set_install(word)
            r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory",
                                                        "value": 900 if word == "ram" else 901})
            self.assertTrue(r["ok"], r)
        self.assertEqual(self.disk(), [])
        self.assertEqual(len(self.ram()), 2)

    def test_the_install_mode_is_the_floor_for_a_disk_project(self):
        self.set_install("ram")
        r = self.lcall("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "memory",
                                                     "value": 900})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.disk(), [])
        self.assertEqual(len(self.ram()), 1)              # the install's chain, not p01's
        self.assertEqual(self.ram("p01"), [])

    def test_the_floor_is_judged_on_every_chain_whatever_the_line(self):
        # A refusal for room must not say where a line was going: a full
        # tmpfs, or a full disk, refuses a call into a project kept nowhere,
        # in RAM, or on disk alike.
        self.set_project("p01", "ram")
        self.set_project("p02", "off")
        saved = audit.room
        self.addCleanup(setattr, audit, "room", saved)
        for full in (audit.ram_path(), audit.LOG_PATH):
            audit.room = lambda path=None, full=full: (path or audit.LOG_PATH) != full
            for name in ("ai-osint-w1", "ai-other-w1", "ai-work2"):
                with self.subTest(full=full, name=name):
                    r = self.call("qmcp.SetPropertyAIManaged",
                                  {"name": name, "property": "memory", "value": 900})
                    self.assertEqual(r, {"ok": False, "error": services.NO_AUDIT_ROOM})
        audit.room = lambda path=None: True
        self.assertTrue(self.call("qmcp.SetPropertyAIManaged",
                                  {"name": "ai-work2", "property": "memory", "value": 900})["ok"])

    def test_the_budget_covers_ram_lines(self):
        self.set_project("p01", "ram")
        counter = pathlib.Path(audit.ram_dir()).parent / "calls" / f"{LEAD}{audit.REFUSED_SUFFIX}"
        counter.write_text(json.dumps({"day": audit._utc_now_iso()[:10],
                                       "lines": audit.AUDIT_LINES_PER_DAY}))
        r = self.lcall("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "memory",
                                                     "value": 900})
        self.assertEqual(r, {"ok": False, "error": services.NO_AUDIT_BUDGET})
        # Its one capped line goes where its call's would: p01's chain, not the disk.
        self.assertEqual(self.services_of(self.ram("p01")), [audit.CAPPED_SERVICE])
        self.assertEqual(self.disk(), [])


# ======================================================================= refused out of reach

class RefusedOutOfReach(ModeBase):
    """A refused call's line is placed by what its service reached: a qube the
    caller may not see or act on, or one the call never judged, sends the line
    nowhere but where the caller's own lines go, and is recorded as
    `audit.OUT_OF_REACH`."""

    def setUp(self):
        super().setUp()
        # A hidden anonymous project that logs nowhere, with one qube that
        # wears its badges and one that lost its hidden badge.
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p05"] = {"label": "hid", "lead": None, "templates": ["ai-hid-tpl"],
                               "networks": [None], "quota": 2 ** 30, "dump": None,
                               "anonymous": True, "hidden": True, "audit": "off"}
        pathlib.Path(projects.PROJECTS_PATH).write_text(json.dumps(doc))
        self.app.vm("ai-hid-w1", tags={"ai-managed", "qmcp-proj-p05", "qmcp-anon",
                                       "qmcp-hubblind"})
        self.app.vm("ai-hid-w2", tags={"ai-managed", "qmcp-proj-p05", "qmcp-anon"})

    def one_disk_line(self, n):
        lines = self.disk()
        self.assertEqual(len(lines), n + 1, lines)
        return lines[-1]

    def test_the_hubs_refused_call_on_a_hidden_projects_qube_stays_on_its_own_log(self):
        cases = [
            ("qmcp.SetPropertyAIManaged", {"name": "ai-hid-w1", "property": "memory",
                                           "value": 900}, "name"),
            ("qmcp.SetFeatureAIManaged", {"name": "ai-hid-w1", "feature": "service.x",
                                          "value": 1}, "name"),
            ("qmcp.LifecycleAIManaged", {"name": "ai-hid-w1", "action": "start"}, "name"),
            ("qmcp.CloneAIManagedQube", {"source": "ai-hid-w1", "name": "ai-hub-c1"},
             "source"),
            ("qmcp.SpawnDisposableAIManaged", {"template": "ai-hid-w1"}, "template"),
            ("qmcp.SpawnAIManagedQube", {"name": "ai-hub-s1", "template": "ai-hid-w1"},
             "template"),
        ]
        for svc, req, key in cases:
            with self.subTest(svc):
                n = len(self.disk())
                r = self.call(svc, req)
                self.assertFalse(r["ok"], r)
                line = self.one_disk_line(n)
                self.assertEqual(line["service"], svc)
                self.assertEqual(line["args"][key], audit.OUT_OF_REACH)
        self.assertEqual(audit.ram_chains(), [])
        self.assertNotIn(b"ai-hid-w1", pathlib.Path(audit.LOG_PATH).read_bytes())

    def test_a_missing_name_and_an_out_of_reach_one_leave_the_same_line(self):
        for name in ("no-such-qube", "ai-hid-w1", "personal"):
            self.call("qmcp.SetPropertyAIManaged", {"name": name, "property": "memory",
                                                    "value": 900})
        lines = self.disk()
        self.assertEqual(len(lines), 3, lines)
        shown = {json.dumps({k: l[k] for k in ("service", "caller", "args", "ok", "error")})
                 for l in lines}
        self.assertEqual(len(shown), 1, shown)
        self.assertEqual(lines[0]["args"]["name"], audit.OUT_OF_REACH)

    def test_a_leads_refused_call_on_another_projects_qube_goes_where_its_own_lines_go(self):
        self.set_project("p01", "ram")
        self.set_project("p02", "off")
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-other-w1", "action": "start"},
                      caller=LEAD)
        self.assertFalse(r["ok"], r)
        lines = self.ram("p01")
        self.assertEqual(self.services_of(lines), ["qmcp.LifecycleAIManaged"])
        self.assertEqual(lines[0]["args"]["name"], audit.OUT_OF_REACH)
        self.assertEqual(self.disk(), [])

    def test_a_guarded_qube_refused_is_out_of_reach(self):
        self.set_project("p01", "ram")
        self.app.domains["ai-osint-w1"].tags.add("qmcp-guarded")
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "start"})
        self.assertFalse(r["ok"], r)
        self.assertEqual(self.ram("p01"), [])
        self.assertEqual(self.one_disk_line(0)["args"]["name"], audit.OUT_OF_REACH)

    def test_a_guarded_qube_in_no_slot_refused_is_named_but_places_nothing(self):
        # A guarded template wears no slot badge: the line names it, and goes
        # where the hub's own lines go. A project's guarded qube stays masked
        # (above).
        self.set_install("ram")
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-tpl-g", "action": "start"})
        self.assertEqual(r, core.GUARDED_REFUSAL)
        self.assertEqual(self.ram()[-1]["args"]["name"], "ai-tpl-g")

    def test_a_not_found_after_the_qube_resolved_is_out_of_reach(self):
        # The hub reaches a qube that lost its hidden badge, and is then told
        # it does not exist: its project is hidden.
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-hid-w2", "name": "ai-hub-c2"})
        self.assertEqual(r, {"ok": False, "error": "not found"})
        self.assertEqual(self.one_disk_line(0)["args"]["source"], audit.OUT_OF_REACH)

    def test_a_refusal_before_the_qube_is_judged_follows_no_qube_it_names(self):
        self.set_project("p02", "off")
        # A name outside the lead's space, refused on its shape alone, that is
        # another project's qube; an action that is not one; a request
        # refused before its name reached the summary.
        for svc, req in (("qmcp.SpawnAIManagedQube", {"name": "ai-other-w1",
                                                      "template": "ai-debian-13"}),
                         ("qmcp.LifecycleAIManaged", {"name": "ai-other-w1",
                                                      "action": "bogus"}),
                         ("qmcp.SetPropertyAIManaged", {"name": "ai-other-w1"})):
            with self.subTest(svc):
                n = len(self.disk())
                self.assertFalse(self.call(svc, req, caller=LEAD)["ok"])
                line = self.one_disk_line(n)
                self.assertNotEqual(line["args"].get("name"), "ai-other-w1")
        self.assertNotIn(b"ai-other-w1", pathlib.Path(audit.LOG_PATH).read_bytes())

    def test_a_proposed_name_in_the_callers_space_is_kept(self):
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-osint-new", "template": "ai-tpl-g"},
                      caller=LEAD)
        self.assertFalse(r["ok"], r)
        args = self.one_disk_line(0)["args"]
        self.assertEqual((args["name"], args["template"]), ("ai-osint-new", audit.OUT_OF_REACH))

    def test_a_qube_the_check_under_its_lock_refuses_is_out_of_reach(self):
        # Reached when the call first judged it, guarded while the call waited
        # for its lock: refused by the second check, and no longer in reach.
        self.set_project("p01", "ram")
        real = services._recheck

        def guarded_meanwhile(app, call, *a, **k):
            app.domains["ai-osint-w1"].tags.add("qmcp-guarded")
            return real(app, call, *a, **k)
        services._recheck = guarded_meanwhile
        self.addCleanup(setattr, services, "_recheck", real)
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "memory",
                                                    "value": 900})
        self.assertFalse(r["ok"], r)
        self.assertEqual(self.ram("p01"), [])
        self.assertEqual(self.one_disk_line(0)["args"]["name"], audit.OUT_OF_REACH)

    # ------------------------------------------------------------ what stays as it was

    def test_a_template_the_call_reached_stays_named_on_its_refused_line(self):
        # Judged in reach, then refused for its class.
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-x9", "template": "ai-debian-13",
                                                  "klass": "DispVM"})
        self.assertFalse(r["ok"], r)
        args = self.one_disk_line(0)["args"]
        self.assertEqual((args["name"], args["template"]), ("ai-hub-x9", "ai-debian-13"))

    def test_a_refusal_of_a_qube_in_reach_keeps_its_place_and_its_name(self):
        self.set_project("p01", "ram")
        for svc, req in (("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1",
                                                        "property": "no-such", "value": 1}),
                         ("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1",
                                                      "action": "bogus"})):
            with self.subTest(svc):
                self.assertFalse(self.call(svc, req)["ok"])
        lines = self.ram("p01")
        self.assertEqual(self.services_of(lines),
                         ["qmcp.SetPropertyAIManaged", "qmcp.LifecycleAIManaged"])
        self.assertEqual({l["args"]["name"] for l in lines}, {"ai-osint-w1"})
        self.assertEqual(self.disk(), [])

    def test_a_successful_call_keeps_its_place(self):
        self.set_project("p01", "ram")
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "memory",
                                                    "value": 900})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.ram("p01")[0]["args"]["name"], "ai-osint-w1")
        self.assertEqual(self.disk(), [])

    def test_the_operators_own_lines_still_follow_what_they_name(self):
        # Not a principal's service call: placed by the qubes it names.
        self.assertEqual(audit.destination(audit.place(self.app, {"name": "ai-hid-w1"}))[0],
                         "none")

    def test_refused_place_on_its_own(self):
        logged, placing, where = audit.refused_place(
            {"name": "ai-x", "source": "ai-y", "qubes": ["ai-y", "ai-z"], "action": "start"},
            audit.Where({"p05": "none"}), ["ai-x"], {"ai-y"}, set(), "p01")
        self.assertEqual(logged, {"name": audit.OUT_OF_REACH, "source": "ai-y",
                                  "qubes": ["ai-y", audit.OUT_OF_REACH], "action": "start"})
        self.assertEqual(placing, {"source": "ai-y", "qubes": ["ai-y"], "action": "start"})
        self.assertEqual(where, ("p01",))
        # Every name the request's keys hold was reached: the place read before stays.
        before = audit.Where({"p02": "ram"})
        self.assertIs(audit.refused_place({"name": "ai-x"}, before, ["ai-x"], {"ai-x"},
                                          set(), None)[2], before)


# ======================================================================= placement itself

class Placement(ModeBase):
    def test_modes_order_and_where(self):
        self.assertEqual(audit.most_private(["disk", "ram"]), "ram")
        self.assertEqual(audit.most_private(["disk", "none", "ram"]), "none")
        self.set_project("p01", "ram")
        self.set_project("p02", "ram")
        both = audit.place(self.app, {"qubes": ["ai-osint-w1", "ai-other-w1"]})
        self.assertEqual(both.modes, {"p01": "ram", "p02": "ram"})
        # Two projects in RAM: the install's chain, never one project's.
        self.assertEqual(audit.destination(both), ("ram", audit.ram_path()))
        one = audit.place(self.app, {"qube": "ai-osint-w1"})
        self.assertEqual(audit.destination(one), ("ram", audit.ram_path("p01")))
        self.assertEqual(audit.destination(audit.Where(unknown=True)), ("ram", audit.ram_path()))
        self.assertEqual(audit.destination(audit.Where()), ("disk", audit.LOG_PATH))

    def test_a_line_kept_off_the_disk_pays_for_a_disk_write_with_zeros(self):
        # Else the time a refused call takes tells a principal that a name it
        # cannot see belongs to a project logging to RAM or nowhere.
        import os
        from unittest import mock
        log_dir = os.path.dirname(audit.LOG_PATH)
        synced, real = [], os.fsync

        def fsync(fd):
            synced.append(os.path.dirname(os.readlink(f"/proc/self/fd/{fd}")))
            return real(fd)
        self.set_project("p01", "ram")
        self.set_project("p02", "off")
        for summary in ({"qube": "ai-work2"}, {"qube": "ai-osint-w1"}, {"qube": "ai-other-w1"}):
            with self.subTest(summary), mock.patch.object(audit.os, "fsync", fsync):
                synced.clear()
                self.assertTrue(audit.audit("qmcp.SetPropertyAIManaged", "mcp-control",
                                            dict(summary), True, app=self.app))
                self.assertEqual(synced.count(log_dir), 1, synced)
        pad = pathlib.Path(audit.LOG_PATH + audit.PAD_SUFFIX).read_bytes()
        self.assertEqual(pad, b"\0" * audit.PAD_BYTES)
        self.assertNotIn(b"ai-osint-w1", pathlib.Path(audit.LOG_PATH).read_bytes())

    def test_a_project_named_by_label_or_slot_belongs_to_it(self):
        self.set_project("p02", "off")
        for summary in ({"project": "other"}, {"project": "p02"}, {"target": "other"},
                        {"subject": "other"}):
            self.assertEqual(audit.destination(audit.place(None, summary))[0], "none", summary)
        self.assertEqual(audit.place(None, {"project": "p00"}).modes, {})

    def test_every_named_qube_is_read_whatever_came_before(self):
        # The number of reads never says what a name is: after a read that
        # fails, and after an unknown place, the rest are read all the same.
        self.app.fail_reads("tag.List:ai-osint-w1", "fail")
        self.app.calls.clear()
        where = audit.place(self.app, {"qubes": ["ai-osint-w1", "ai-other-w1", "no-such-qube"]})
        self.assertTrue(where.unknown)
        # Each read is balanced by one of the other kind: a missing qube after a
        # read that found its qube, dom0 after one that did not.
        self.assertEqual([c[0] for c in self.app.calls],
                         ["ai-osint-w1", core.BALANCE_PRESENT, "ai-other-w1",
                          core.BALANCE_MISSING, "no-such-qube", core.BALANCE_PRESENT])
        self.app.calls.clear()
        audit.place(self.app, {"name": "ai-work2"}, audit.Where(unknown=True))
        self.assertEqual([c[0] for c in self.app.calls], ["ai-work2", core.BALANCE_MISSING])

    def test_records_that_do_not_read_are_an_unknown_place(self):
        pathlib.Path(projects.PROJECTS_PATH).write_text("{not json")
        self.assertTrue(audit.place(self.app, {"qube": "ai-osint-w1"}).unknown)
        self.assertTrue(audit.place(None, {"project": "osint"}).unknown)
        self.assertFalse(audit.place(self.app, {"qube": "ai-work2"}).unknown)

    def test_a_missing_qube_is_in_no_project_and_the_mode_read_before_is_kept(self):
        missing = audit.place(self.app, {"name": "no-such-qube"})
        self.assertEqual((missing.modes, missing.unknown), ({}, False))
        self.set_project("p01", "off")
        before = audit.place(self.app, {"qube": "ai-osint-w1"})
        self.set_project("p01", "disk")     # switched back while the call ran
        after = audit.place(self.app, {"qube": "ai-osint-w1"}, before)
        self.assertEqual(after.modes, {"p01": "none"})      # the more private of the two

    def test_the_record_keeps_only_ram_or_off(self):
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        for value, ok in (("ram", True), ("off", True), ("disk", False), ("", False), (None, False)):
            doc["slots"]["p01"]["audit"] = value
            if ok:
                self.assertEqual(projects.parse(json.dumps(doc))["p01"].audit, value)
            else:
                with self.assertRaises(projects.ProjectsUnreadable, msg=value):
                    projects.parse(json.dumps(doc))
        del doc["slots"]["p01"]["audit"]
        p = projects.parse(json.dumps(doc))["p01"]
        self.assertEqual(p.audit, "disk")
        self.assertNotIn("audit", p.to_json())


# ======================================================================= the operator's lines

class OperatorLines(ModeBase):
    def test_a_switch_leaves_one_slot_only_line_and_says_the_old_lines_stay(self):
        rc, out, err = self.cli("project", "audit", "osint", "ram")
        self.assertEqual(rc, 0, err)
        self.assertEqual(projects.load()["p01"].audit, "ram")
        last = self.disk()[-1]
        self.assertEqual((last["service"], last["args"]), ("qmcp project audit",
                                                           {"slot": "p01", "mode": "ram"}))
        self.assertNotIn("osint", json.dumps(last))
        self.assertIn("stay in dom0's audit log on disk", out)
        self.assertIn("is not erasing it", out)
        self.assertEqual(self.ram("p01"), [])

    def test_the_operators_commands_on_the_project_follow_it(self):
        self.set_project("p01", "ram")
        n = len(self.disk())
        rc, _, err = self.cli("project", "edit", "osint", "--quota", "30G")
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.disk()), n)
        self.assertEqual(self.services_of(self.ram("p01"))[-1], "qmcp project edit")
        # A command on one of its qubes too, by the qube's badges.
        rc, _, err = self.cli("revoke", "ai-osint-w2")
        self.assertEqual(len(self.disk()), n, err)
        self.assertEqual(self.services_of(self.ram("p01"))[-1], "qmcp revoke")

    def test_a_delete_follows_the_mode_its_project_had(self):
        self.set_project("p02", "off")
        n = len(self.disk())
        rc, _, err = self.cli("project", "delete", "other", "--yes")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("p02", projects.load())
        self.assertEqual(len(self.disk()), n)
        self.assertEqual(audit.ram_chains(), [])

    def test_back_to_disk_says_no_warning_and_the_same_mode_changes_nothing(self):
        self.set_project("p01", "off")
        rc, out, _ = self.cli("project", "audit", "p01", "disk")
        self.assertEqual(rc, 0)
        self.assertNotIn("not erasing", out)
        n = len(self.disk())
        rc, out, _ = self.cli("project", "audit", "p01", "disk")
        self.assertEqual(rc, 0)
        self.assertIn("nothing changed", out)
        self.assertEqual(len(self.disk()), n)
        rc, _, _ = self.cli("project", "audit", "p01", "nowhere")
        self.assertEqual(rc, 2)
        rc, _, err = self.cli("project", "audit", "p01", "ram", root=False)
        self.assertNotEqual(rc, 0)
        self.assertEqual(projects.load()["p01"].audit, "disk")


# ======================================================================= rotation and retention

class Retention(ModeBase):
    def now(self):
        return datetime.datetime.now(datetime.timezone.utc)

    def write_log(self, first_ts, n=2):
        """A chain of `n` lines whose first is dated `first_ts`."""
        pathlib.Path(audit.LOG_PATH).write_text("")
        for i in range(n):
            audit._audit("qmcp.x", "operator", {"i": i}, True, path=audit.LOG_PATH)
        lines = pathlib.Path(audit.LOG_PATH).read_text().splitlines()
        rec = json.loads(lines[0])
        rec["ts"] = first_ts
        rec["hash"] = audit._body_hash(rec)
        # Re-link the chain after the edit, so verify() holds.
        out, prev = [], audit.GENESIS
        for j, line in enumerate(lines):
            r = rec if j == 0 else json.loads(line)
            r["prev"] = prev
            r["hash"] = audit._body_hash(r)
            prev = r["hash"]
            out.append(json.dumps(r, sort_keys=True, separators=(",", ":")))
        pathlib.Path(audit.LOG_PATH).write_text("\n".join(out) + "\n")

    def rotated_file(self, days_ago, size=10):
        when = self.now() - datetime.timedelta(days=days_ago)
        path = pathlib.Path(audit.LOG_PATH + "." + when.strftime("%Y%m%dT%H%M%SZ"))
        path.write_bytes(b"x" * size)
        return path

    def test_a_log_from_an_earlier_day_is_rotated_and_the_chain_continues(self):
        yesterday = (self.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.write_log(yesterday)
        lines, ok = audit.auto_rotate()
        self.assertTrue(ok, lines)
        self.assertTrue(lines[0].startswith("rotated"), lines)
        self.assertEqual(len(audit.rotated()), 1)
        first = self.disk()[0]
        self.assertEqual((first["service"], first["caller"]), (audit.ROTATE_SERVICE, "rotate"))
        self.assertTrue(audit.verify()[0])
        # The next hour, the same day: only the anchor, nothing due.
        lines, ok = audit.auto_rotate()
        self.assertEqual((lines, ok), ([], True))
        self.assertEqual(len(audit.rotated()), 1)

    def test_a_log_holding_only_an_earlier_days_anchor_is_not_rotated(self):
        # A quiet day: the log is only the anchor of yesterday's rotation.
        yesterday = (self.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.write_log(yesterday, n=1)
        lines = pathlib.Path(audit.LOG_PATH).read_text().splitlines()
        rec = json.loads(lines[0])
        rec["service"] = audit.ROTATE_SERVICE
        rec["hash"] = audit._body_hash(rec)
        pathlib.Path(audit.LOG_PATH).write_text(json.dumps(rec) + "\n")
        self.assertEqual(audit.auto_rotate(), ([], True))
        self.assertEqual(audit.rotated(), [])

    def test_a_log_of_today_is_not_rotated_until_it_is_past_the_size(self):
        self.write_log(audit._utc_now_iso())
        self.assertEqual(audit.auto_rotate(), ([], True))
        saved = audit.ROTATE_AT_BYTES
        audit.ROTATE_AT_BYTES = 10
        self.addCleanup(setattr, audit, "ROTATE_AT_BYTES", saved)
        lines, ok = audit.auto_rotate()
        self.assertTrue(lines and lines[0].startswith("rotated"), lines)

    def test_rotated_logs_are_removed_by_age_never_by_size(self):
        old = self.rotated_file(91)
        young_and_huge = self.rotated_file(10, size=5 * 1024 * 1024)
        decoy = pathlib.Path(audit.LOG_PATH + ".bak")
        decoy.write_text("not ours")
        lines, ok = audit.auto_rotate()
        self.assertTrue(ok, lines)
        self.assertFalse(old.exists())
        self.assertTrue(young_and_huge.exists())
        self.assertTrue(decoy.exists())
        last = self.disk()[-1]
        self.assertEqual((last["service"], last["args"]["removed"], last["args"]["keep_days"]),
                         (audit.REMOVE_SERVICE, [old.name], 90))

    def test_the_setting_decides_and_one_that_does_not_read_removes_nothing(self):
        old = self.rotated_file(40)
        pathlib.Path(audit.KEEP_DAYS_PATH).write_text("60\n")
        self.assertEqual(audit.auto_rotate(), ([], True))
        self.assertTrue(old.exists())
        pathlib.Path(audit.KEEP_DAYS_PATH).write_text("off\n")
        self.assertEqual(audit.auto_rotate(), ([], True))
        self.assertTrue(old.exists())
        for bad in ("0\n", "abc\n", "36501\n", "-5\n", ""):
            pathlib.Path(audit.KEEP_DAYS_PATH).write_text(bad)
            lines, ok = audit.auto_rotate()
            self.assertFalse(ok, bad)
            self.assertTrue(old.exists(), bad)
        self.assertEqual(self.disk(), [])               # no run above did anything
        pathlib.Path(audit.KEEP_DAYS_PATH).write_text("30\n")
        audit.auto_rotate()
        self.assertFalse(old.exists())

    def test_a_quiet_run_writes_nothing(self):
        self.write_log(audit._utc_now_iso())
        before = pathlib.Path(audit.LOG_PATH).read_bytes()
        self.rotated_file(5)
        self.assertEqual(audit.auto_rotate(), ([], True))
        self.assertEqual(pathlib.Path(audit.LOG_PATH).read_bytes(), before)

    def test_no_rotation_in_mode_ram_or_none_but_removal_goes_on(self):
        yesterday = (self.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for word in ("ram", "none"):
            self.write_log(yesterday)
            old = self.rotated_file(100)
            self.set_install(word)
            lines, ok = audit.auto_rotate()
            self.assertTrue(ok, lines)
            self.assertEqual(audit.rotated(), [], word)          # the old one removed, none made
            self.assertFalse(old.exists())
            self.assertFalse(any(l["service"] == audit.ROTATE_SERVICE for l in self.disk()), word)

    def test_a_rotation_by_hand_rotates_the_installs_own_log(self):
        # In mode ram that is its RAM chain, and the disk log is left alone;
        # in mode none, or a mode that does not read, there is nothing to rotate.
        import os
        self.write_log(audit._utc_now_iso())
        disk = pathlib.Path(audit.LOG_PATH).read_bytes()
        for word in ("none", "x"):
            self.set_install(word)
            rc, _, err = self.cli("audit", "rotate")
            self.assertEqual(rc, 1, word)
            self.assertIn("nothing was rotated", err)
        self.set_install("ram")
        rc, out, err = self.cli("audit", "rotate")
        self.assertEqual(rc, 0, err)
        self.assertIn(os.path.dirname(audit.ram_path()), out)
        self.assertEqual(pathlib.Path(audit.LOG_PATH).read_bytes(), disk)
        self.assertEqual(audit.verify(audit.ram_path())[0], True)
        self.assertEqual(audit.rotated(), [])
        self.set_install("disk")
        self.assertEqual(self.cli("audit", "rotate")[0], 0)
        self.assertEqual(len(audit.rotated()), 1)

    def test_the_command_is_roots(self):
        rc, _, _ = self.cli("audit", "rotate", "--auto", root=False)
        self.assertNotEqual(rc, 0)
        rc, out, err = self.cli("audit", "rotate", "--auto")
        self.assertEqual((rc, out), (0, ""), err)


# ======================================================================= settings, status, check

class RamRetention(ModeBase):
    def test_ram_chains_rotate_by_size_and_the_oldest_rotated_go_first(self):
        import os
        from unittest import mock
        audit._ram_dir_ready()
        d = audit.ram_dir()
        live = audit.ram_path("p01")
        pathlib.Path(live).write_text("x" * 300 + "\n")
        for stamp in ("20261001T000000Z", "20261002T000000Z", "20261003T000000Z"):
            pathlib.Path(f"{live}.{stamp}").write_text("y" * 400)
        with mock.patch.object(audit, "RAM_ROTATE_AT_BYTES", 200), \
                mock.patch.object(audit, "RAM_KEEP_BYTES", 1000):
            lines, ok = audit.auto_rotate()
        self.assertTrue(ok, lines)
        left = sorted(os.listdir(d))
        # The live chain was rotated (its new self holds only the anchor), and
        # rotated files went oldest first: every one removed is older than
        # every one left, and the one just rotated stays.
        self.assertIn("p01.log", left)
        gone = [l.split()[1].rstrip(":") for l in lines if l.startswith("removed ")]
        kept = [n for n in left if n.startswith("p01.log.")]
        self.assertIn("p01.log.20261001T000000Z", gone)
        self.assertTrue(all(g < k for g in gone for k in kept), (gone, kept))
        self.assertTrue(any(k > "p01.log.20261003T000000Z" for k in kept), kept)
        self.assertLessEqual(sum(os.path.getsize(os.path.join(d, n)) for n in left), 1000)
        self.assertEqual(audit.verify(live)[0], True)

    def test_a_live_ram_chain_is_never_removed(self):
        import os
        from unittest import mock
        audit._ram_dir_ready()
        live = audit.ram_path()
        pathlib.Path(live).write_text("z" * 5000 + "\n")
        with mock.patch.object(audit, "RAM_ROTATE_AT_BYTES", 10 ** 9), \
                mock.patch.object(audit, "RAM_KEEP_BYTES", 10):
            audit.auto_rotate()
        self.assertTrue(os.path.exists(live))


class PlantedLinks(ModeBase):
    """The RAM chains' directory is the services' group's to write; root
    writes there too, and must never follow a link planted in it."""

    def test_a_link_planted_as_a_chain_or_pad_is_never_followed(self):
        import os
        audit._ram_dir_ready()
        target = self.tmp / "elsewhere"
        target.write_text("keep\n")
        os.symlink(target, audit.ram_path("p01"))
        os.symlink(target, audit.ram_path() + audit.PAD_SUFFIX)
        self.set_project("p01", "ram")
        audit.audit("qmcp.SetPropertyAIManaged", "mcp-control", {"qube": "ai-osint-w1"}, True,
                    app=self.app)
        audit._pay_like("ram")
        self.assertEqual(target.read_text(), "keep\n")

    def test_the_sweep_skips_what_it_cannot_remove_and_goes_on(self):
        import os
        from unittest import mock
        audit._ram_dir_ready()
        live = audit.ram_path("p01")
        pathlib.Path(live).write_text("x\n")
        os.mkdir(f"{live}.20261001T000000Z")                 # planted, cannot be unlinked
        pathlib.Path(f"{live}.20261002T000000Z").write_text("y" * 500)
        with mock.patch.object(audit, "RAM_KEEP_BYTES", 10):
            lines, ok = audit.auto_rotate()
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(f"{live}.20261002T000000Z"), lines)


class StaleRotation(ModeBase):
    def test_a_rotation_killed_part_way_never_stops_the_next(self):
        pathlib.Path(audit.LOG_PATH + audit.ROTATING_SUFFIX).write_text("half\n")
        found = [(f.status, f.detail) for f in fleet.check(self.app)
                 if f.check == "audit retention"]
        self.assertTrue(any("stopped part-way" in d for _, d in found), found)
        aside = audit.rotate()
        self.assertTrue(os.path.exists(aside))
        self.assertFalse(os.path.exists(audit.LOG_PATH + audit.ROTATING_SUFFIX))
        self.assertEqual(audit.verify()[0], True)

    def test_check_fails_while_the_audit_timer_does_not_run(self):
        from qmcp import anon

        def timer():
            return [f.status for f in fleet.check(self.app) if f.check == "audit timer"]
        self.assertEqual(timer(), [])                      # running: no item
        saved = anon.TIMER_CHECK
        self.addCleanup(setattr, anon, "TIMER_CHECK", saved)
        # Only the audit timer stopped; the gate's still runs.
        anon.TIMER_CHECK = lambda unit=None: unit != audit.AUDIT_TIMER
        self.assertEqual(timer(), ["fail"])
        self.assertNotIn("fail", [f.status for f in fleet.check(self.app)
                                  if f.check == "gate timer"])


class SettingsStatusCheck(ModeBase):
    def finding(self, name):
        found = [f for f in fleet.check(self.app) if f.check == name]
        return found[0] if found else None

    def test_keep_days_is_set_checked_and_shown(self):
        rc, out, err = self.cli("settings", "set", "--audit-keep-days", "30")
        self.assertEqual(rc, 0, err)
        self.assertEqual(pathlib.Path(audit.KEEP_DAYS_PATH).read_text(), "30\n")
        self.assertEqual(self.disk()[-1]["args"]["audit_keep_days"], "30")
        for bad in ("0", "abc", "36501", "1.5"):
            rc, _, err = self.cli("settings", "set", "--audit-keep-days", bad)
            self.assertEqual(rc, 1, bad)
            self.assertIn("nothing was changed", err)
        self.assertEqual(pathlib.Path(audit.KEEP_DAYS_PATH).read_text(), "30\n")
        rc, _, _ = self.cli("settings", "set", "--audit-keep-days", "off")
        self.assertEqual(audit.keep_days(), "off")
        rc, out, _ = self.cli("settings", "--json")
        doc = json.loads(out)
        self.assertEqual((doc["audit_mode"], doc["audit_keep_days"]), ("disk", "off"))

    def test_status_answers_every_part_and_none_for_what_does_not_read(self):
        from qmcp import guimodel as gm
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory",
                                                "value": 900})
        rc, out, _ = self.cli("audit", "status", "--json", root=False)
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(set(doc), {k for k, _ in gm.AUDIT_STATUS_FIELDS})
        self.assertEqual(doc["principals"], 3)                  # the hub and two leads
        self.assertEqual(doc["needed_bytes"], 3 * audit.AUDIT_LINES_PER_DAY * audit.LINE_BYTES * 90)
        self.assertEqual([b["caller"] for b in doc["budgets"]], [HUB])
        self.assertEqual(doc["budgets"][0]["lines_today"], 1)
        self.assertIsInstance(doc["free_bytes"], int)
        counter = pathlib.Path(audit.ram_dir()).parent / "calls" / f"{HUB}{audit.REFUSED_SUFFIX}"
        counter.write_text("[not an object")
        doc = json.loads(self.cli("audit", "status", "--json", root=False)[1])
        self.assertIsNone(doc["budgets"][0]["lines_today"])
        pathlib.Path(audit.MODE_PATH).write_text("bogus\n")
        pathlib.Path(audit.KEEP_DAYS_PATH).write_text("bogus\n")
        doc = json.loads(self.cli("audit", "status", "--json", root=False)[1])
        self.assertEqual((doc["mode"], doc["keep_days"]), (None, None))

    def test_check_names_the_modes_and_the_journal(self):
        self.assertEqual(self.finding("audit mode").status, "pass")
        self.assertIsNone(self.finding("dom0 journal"))
        self.set_project("p01", "ram")
        f = self.finding("dom0 journal")
        self.assertEqual(f.status, "warn")
        self.assertIn("Storage=volatile", f.detail)
        self.assertIn("osint (p01): ram", self.finding("project audit modes").detail)
        self.set_project("p01", "disk")
        self.set_install("none")
        self.assertEqual(self.finding("audit mode").status, "warn")
        self.assertEqual(self.finding("dom0 journal").status, "warn")
        self.set_install("what")
        self.assertEqual(self.finding("audit mode").status, "fail")

    def test_check_judges_retention(self):
        saved = audit.free_bytes
        self.addCleanup(setattr, audit, "free_bytes", saved)
        audit.free_bytes = lambda path=None: 10 * 1024 ** 4
        self.assertEqual(self.finding("audit retention").status, "pass")
        audit.free_bytes = lambda path=None: 1024
        f = self.finding("audit retention")
        self.assertEqual(f.status, "warn")
        self.assertIn("3 principal(s)", f.detail)
        pathlib.Path(audit.KEEP_DAYS_PATH).write_text("off\n")
        self.assertEqual(self.finding("audit retention").status, "warn")
        pathlib.Path(audit.KEEP_DAYS_PATH).write_text("nope\n")
        self.assertEqual(self.finding("audit retention").status, "fail")

    def test_check_fails_on_an_operator_file_the_services_cannot_read(self):
        """The 0.9.33 README's `echo off | sudo tee` made the keep-days file
        0600 under dom0's umask: root's check read it, the user's did not.
        The item judges the mode, so a check run as root fails on it too."""
        from qmcp import opfiles
        self.assertEqual(self.finding("operator files").status, "pass")
        keep = pathlib.Path(audit.KEEP_DAYS_PATH)
        keep.write_text("off\n")
        os.chmod(keep, 0o600)
        f = self.finding("operator files")
        self.assertEqual(f.status, "fail")
        self.assertIn(f"{keep} is 0600", f.detail)
        self.assertIn(f"sudo chmod 0644 {keep}", f.detail)
        os.chmod(keep, 0o646)
        f = self.finding("operator files")
        self.assertEqual(f.status, "fail")
        self.assertIn("every user can write", f.detail)
        os.chmod(keep, 0o644)
        self.assertEqual(self.finding("operator files").status, "pass")
        # Every operator file is judged, not only keep-days: the list is the
        # one export and import use.
        for path in opfiles._paths().values():
            p = pathlib.Path(path)
            existed = p.exists()
            if not existed:
                p.write_text("x\n")
            saved = p.stat().st_mode & 0o7777
            os.chmod(p, 0o600)
            self.assertEqual(self.finding("operator files").status, "fail", path)
            os.chmod(p, saved)
            if not existed:
                p.unlink()
        keep.unlink()
        os.symlink(self.tmp / "hub", keep)
        f = self.finding("operator files")
        self.assertEqual(f.status, "fail")
        self.assertIn("not a plain file", f.detail)
        keep.unlink()

    def test_check_verifies_the_ram_chains(self):
        self.set_project("p01", "ram")
        self.lcall("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "memory",
                                                 "value": 900})
        self.assertEqual(self.finding("audit chain in RAM").status, "pass")
        path = pathlib.Path(audit.ram_path("p01"))
        path.write_text(path.read_text().replace("900", "901").replace('"memory"', '"vcpus"'))
        self.assertEqual(self.finding("audit chain in RAM").status, "fail")


# ======================================================================= the wiring

class Wiring(unittest.TestCase):
    def keys(self, name):
        out = {}
        for line in (DEPLOY / name).read_text().splitlines():
            if line and not line.startswith(("#", "[")) and "=" in line:
                k, v = line.split("=", 1)
                out.setdefault(k.strip(), []).append(v.strip())
        return out

    def test_the_timer_runs_the_rotation_as_root_every_hour(self):
        """A rotation "the timer runs" needs the line that runs it: pinned."""
        svc = self.keys("qmcp-audit.service")
        self.assertEqual(svc["ExecStart"], ["/usr/local/bin/qmcp audit rotate --auto"])
        self.assertNotIn("User", svc)               # root: /var/log is root's to create in
        self.assertEqual(svc["Type"], ["oneshot"])
        timer = self.keys("qmcp-audit.timer")
        self.assertEqual(timer["OnCalendar"], ["hourly"])
        self.assertEqual(timer["Persistent"], ["true"])
        install = (DEPLOY / "install.sh").read_text()
        for line in ("systemctl enable qmcp-audit.timer", "systemctl start qmcp-audit.timer",
                     '/etc/systemd/system/qmcp-audit.service', '/etc/systemd/system/qmcp-audit.timer'):
            self.assertIn(line, install)
        # And the command it runs exists with that option.
        ns = cli.build_parser().parse_args(["audit", "rotate", "--auto"])
        self.assertTrue(ns.auto)

    def test_tmpfiles_declares_the_ram_chains_directory(self):
        rows = {tuple(line.split()[:5]) for line in
                (DEPLOY / "qmcp-tmpfiles.conf").read_text().splitlines()
                if line.strip() and not line.startswith("#")}
        self.assertIn(("d", "/run/qmcp/audit", "2770", "root", "qubes"), rows)
        self.assertEqual(audit.RAM_SUBDIR, "audit")

    def test_the_installer_sets_the_operator_files_and_checks_as_the_user(self):
        """It sets every operator file to 0644 from the library's own list,
        and its closing check runs as the gate's user, not as root."""
        install = (DEPLOY / "install.sh").read_text()
        self.assertIn("opfiles._paths().values()", install)
        self.assertIn('chmod 0644 "$f"', install)
        self.assertIn('runuser -u "$GATE_USER" -- /usr/local/bin/qmcp check', install)
        verify = install.split("# ===================================================================== verify", 1)[1]
        self.assertNotIn("\n/usr/local/bin/qmcp check", verify)
        # The mode is set after every write to /etc/qmcp, and before the gate's
        # first run, which as its user would block every anonymous qube on
        # records it cannot read.
        self.assertLess(install.index('QMCP_WRITE_MODE=1 stamp_mode'), install.index('chmod 0644 "$f"'))
        self.assertLess(install.index('chmod 0644 "$f"'), install.index("systemctl start qmcp-gate.service"))
        self.assertLess(install.index('chmod 0644 "$f"'), install.index("\nsystemctl start qmcp-gate.timer\n"))

    def test_the_balancing_reads_missing_name_cannot_be_created(self):
        from qmcp import birth
        self.assertIsNotNone(birth.name_refusal(core.BALANCE_MISSING, "qmcp-"))
        self.assertIsNone(birth.name_refusal("qmcp-no-such-qube2", "qmcp-"))

    def test_the_installer_takes_the_audit_log_option(self):
        install = (DEPLOY / "install.sh").read_text()
        self.assertIn("--audit-log) AUDIT_LOG_MODE=", install)
        self.assertIn('""|disk|ram|none) ;;', install)
        self.assertIn("audit.MODE_PATH", install)

    def test_every_audit_call_says_where_its_line_belongs(self):
        """A call that names neither its projects (`slots=`), an app to read
        the badges with (`app=`), nor a file (`path=`) would default a
        project's line to the install's chain: refused here."""
        offenders, seen = [], 0
        for path in sorted((HERE.parent / "dom0" / "qmcp").glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "audit" and isinstance(node.func.value, ast.Name)
                        and node.func.value.id in ("audit", "audit_mod")):
                    continue
                seen += 1
                if not {k.arg for k in node.keywords} & {"slots", "app", "path"}:
                    offenders.append(f"{path.name}:{node.lineno}")
        for name in ("install.sh",):
            for i, line in enumerate((DEPLOY / name).read_text().splitlines(), 1):
                if re.search(r"\baudit\.audit\(", line):
                    seen += 1
                    block = "\n".join((DEPLOY / name).read_text().splitlines()[i - 1:i + 3])
                    if not re.search(r"\b(slots|app|path)=", block):
                        offenders.append(f"{name}:{i}")
        self.assertGreater(seen, 10)                        # not a vacuous pass
        self.assertEqual(offenders, [])

    def test_the_uninstaller_removes_the_units(self):
        text = (DEPLOY / "uninstall.sh").read_text()
        units = set(text.split('\nUNITS="', 1)[1].split('"', 1)[0].split())
        self.assertLessEqual({"qmcp-audit.timer", "qmcp-audit.service"}, units)


if __name__ == "__main__":
    unittest.main()
