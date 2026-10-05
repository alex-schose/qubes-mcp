"""Offline suite: a failed read is never an answer.

qubesadmin raises when a read fails (an empty qubesd reply, a qube that
vanished), and its property errors are AttributeErrors. A read written with a
default (`getattr(vm, "x", default)`, a helper that returns `set()` for tags it
could not read) turns that failure into the default: no umbrella, no guard,
no badge, no network role. Here one read at a time is made to fail, every read
of a key or only its first, second, ... read, and what a service or command
then does must never be more than it does with nothing failing: it refuses,
or it does what was asked, and it never reports done what it left undone.

`fakequbes` fails tag reads as qubesadmin's do (`tag.List` and `tag.Get`, each
optionally `:<qube>`) and property reads with its AttributeError. The last
class walks the dom0 library's source for the pattern itself.
"""
from __future__ import annotations

import ast
import pathlib
import sys
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import birth, budget, core, fleet, gateways, projects, proposals, scope  # noqa: E402
from fakequbes import GiB  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_projects import LEAD, ProjectBase  # noqa: E402

#: More reads than any one call makes of one qube under one key.
POSITIONS = 8


class StrictBase(ProjectBase):
    def arm(self, key, n: int) -> str:
        """Fail every read under `key` (n == 0) or only its nth; the label
        says which, for the assertion messages."""
        if n == 0:
            self.app.fail.add(key)
            return f"{key}: every read"
        self.app.fail_reads(key, " ".join(["ok"] * (n - 1) + ["fail"]))
        return f"{key}: read {n} only"

    def disarm(self) -> None:
        self.app.fail.clear()
        self.app.fail_plan.clear()

    def each_failure(self, key):
        """Every read under `key` failing, then only its first, second, ...
        The first pass must read the key at least once: a sweep of a key the
        call never reads passes whatever the code does."""
        for n in range(POSITIONS + 1):
            before = self.app.reads[key]
            label = self.arm(key, n)
            try:
                yield label
            finally:
                read = self.app.reads[key] - before
                self.disarm()
            if n == 0:
                self.assertGreater(read, 0, f"{key} is never read here: the sweep proves nothing")

    def fresh(self) -> None:
        """A new fleet for the next run: this test's cleanups first, so the
        module paths setUp patches are put back before it patches them again."""
        self.doCleanups()
        self.setUp()

    def raw(self, name) -> set | None:
        """A qube's tags as they are, read without qubesd: None once it is gone."""
        vm = self.app.domains._any(name)
        return None if vm is None else vm.__dict__["tags"].raw()

    def set_raw(self, name, tags) -> None:
        self.app.domains._any(name).__dict__["tags"]._tags = set(tags)

    def exists(self, name) -> bool:
        return self.app.domains._any(name) is not None


# ======================================================================= the services

class Services(StrictBase):
    def test_a_gateway_whose_role_cannot_be_read_is_guarded(self):
        # ai-gw-unbadged provides network and wears no qmcp-guarded badge.
        req_feature = {"name": "ai-gw-unbadged", "feature": "service.qubes-firewall", "value": ""}
        req_remove = {"name": "ai-gw-unbadged", "action": "remove"}
        self.assertFalse(self.call("qmcp.SetFeatureAIManaged", req_feature)["ok"])
        for why in self.each_failure("get.provides_network:ai-gw-unbadged"):
            self.assertFalse(self.call("qmcp.SetFeatureAIManaged", req_feature)["ok"], why)
            self.assertFalse(self.call("qmcp.LifecycleAIManaged", req_remove)["ok"], why)
            self.assertTrue(self.exists("ai-gw-unbadged"), why)

    def test_a_guarded_qube_stays_guarded_whichever_tag_read_fails(self):
        for key in ("tag.List:ai-dvm-g", "tag.Get:ai-dvm-g"):
            for i, why in enumerate(self.each_failure(key)):
                name = f"ai-hub-c{i}"
                r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-dvm-g", "name": name})
                self.assertFalse(r["ok"], why)
                self.assertFalse(self.exists(name), why)
                r = self.call("qmcp.SetPropertyAIManaged",
                              {"name": "ai-dvm-g", "property": "memory", "value": 800})
                self.assertFalse(r["ok"], why)
                r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-dvm-g", "action": "remove"})
                self.assertFalse(r["ok"], why)
        self.assertTrue(self.exists("ai-dvm-g"))

    def test_a_recheck_that_fails_refuses_even_a_managed_qube(self):
        # tag.Get is the by-name check; tag.List the re-check on the object,
        # there because its tags may have changed in between. Either read
        # failing alone refuses the qube, as a qube outside AI space is refused.
        for key in ("tag.List:ai-work2", "tag.Get:ai-work2"):
            self.app.fail_reads(key, "fail")
            r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"})
            self.disarm()
            self.assertEqual(r, core.NOT_FOUND, key)
            self.assertEqual(self.app.domains["ai-work2"]._power, "Halted", key)

    def test_the_hub_never_removes_a_lead_on_a_failed_read(self):
        self.app.domains._vms[LEAD].__dict__["_power"] = "Halted"
        req = {"name": LEAD, "action": "remove"}
        self.assertFalse(self.call("qmcp.LifecycleAIManaged", req)["ok"])
        for key in (f"tag.List:{LEAD}", f"tag.Get:{LEAD}"):
            for why in self.each_failure(key):
                self.assertFalse(self.call("qmcp.LifecycleAIManaged", req)["ok"], why)
                self.assertTrue(self.exists(LEAD), why)

    def test_a_clone_never_joins_p00_on_a_failed_read(self):
        # The hub's clone of a project's qube, or of a disposable template,
        # joins no slot: in p00 it could drop files into the hub's qubes.
        cases = [("ai-osint-w1", ["tag.List:ai-osint-w1", "tag.Get:ai-osint-w1"]),
                 ("ai-dvm", ["get.template_for_dispvms:ai-dvm", "tag.List:ai-dvm"])]
        i = 0
        for source, keys in cases:
            for key in keys:
                for why in self.each_failure(key):
                    i += 1
                    name = f"ai-hub-k{i}"
                    r = self.call("qmcp.CloneAIManagedQube", {"source": source, "name": name})
                    if r["ok"]:
                        self.assertNotIn("qmcp-proj-p00", self.raw(name), why)
                    else:
                        self.assertFalse(self.exists(name), why)

    def test_a_spawn_from_an_anonymous_template_never_loses_anon_vm(self):
        self.app.vm("ai-anon-t", klass="TemplateVM", tags={"ai-managed", "anon-vm"})
        for i, why in enumerate(self.each_failure("tag.List:ai-anon-t")):
            name = f"ai-hub-a{i}"
            r = self.call("qmcp.SpawnAIManagedQube", {"name": name, "template": "ai-anon-t",
                                                      "label": "red", "netvm": None})
            if r["ok"]:
                self.assertIn("anon-vm", self.raw(name), why)
            else:
                self.assertFalse(self.exists(name), why)

    def test_the_hubs_own_lookup_that_fails_refuses_its_birth_network(self):
        # A failed lookup of the hub is no "no network of its own", which would
        # fall through to birth-egress.
        self.egress("ai-net-router")
        self.app.fail.add(f"lookup:{HUB}")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-b1", "template": "ai-debian-13",
                                                  "label": "red"})
        self.assertEqual(r, {"ok": False, "error": "read failed"})
        self.assertFalse(self.exists("ai-hub-b1"))
        # No network asked for: nothing to resolve, so nothing that failed to read.
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-b0", "template": "ai-debian-13",
                                                  "label": "red", "netvm": None})
        self.assertTrue(r["ok"], r)
        self.app.fail.clear()
        self.assertTrue(self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-b1",
                                                              "template": "ai-debian-13",
                                                              "label": "red"})["ok"])

    def test_the_cap_never_skips_a_qube_it_cannot_read(self):
        req = {"name": "ai-hub-new", "template": "ai-debian-13", "label": "red", "netvm": None}
        self.app.fail.add("tag.List:ai-work")
        with self.assertRaises(Exception):
            budget.persistent_sum(self.app)
        self.assertFalse(self.call("qmcp.SpawnAIManagedQube", req)["ok"])
        self.assertFalse(self.exists("ai-hub-new"))
        self.app.fail.clear()
        self.app.fail.add("tag.List:ai-osint-w1")
        r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-new", "template": "ai-debian-13",
                                                   "label": "red", "netvm": None})
        self.assertFalse(r["ok"])
        self.assertFalse(self.exists("ai-osint-new"))

    def test_the_hubs_reads_never_show_a_failed_read_as_state(self):
        self.app.fail.add("tag.List:ai-work")
        names = [q["name"] for q in self.call("qmcp.ListAIManagedQubes")["qubes"]]
        self.assertNotIn("ai-work", names)          # never listed as some other state
        self.assertIn("ai-work2", names)
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "tags"})
        self.assertFalse(r["ok"])                   # never [] for tags it could not read
        self.app.fail.clear()
        self.app.fail_reads("tag.List:ai-work", "ok fail")    # in AI space, then the read fails
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "tags"})
        self.assertEqual(r, {"ok": False, "error": "read failed"})
        self.app.fail.clear()
        self.app.fail.add("get.memory:ai-work")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "memory"})
        self.assertEqual(r, {"ok": False, "error": "read failed"})   # said as a read, not a name
        self.app.fail.clear()
        self.app.fail.add("tag.List:ai-osint-w1")
        # The disk AI space uses is not known, so the hub is told so, never less.
        self.assertEqual(self.call("qmcp.GetPoolStats"),
                         {"ok": False, "error": budget.ERR_STATS_UNAVAILABLE})
        self.app.fail.clear()
        self.assertEqual(self.call("qmcp.GetPropertyAIManaged",
                                   {"name": "ai-work", "property": "tags"})["value"], ["ai-managed"])

    def test_a_reference_whose_class_cannot_be_read_is_out_of_scope(self):
        class Unreadable:
            name = "sys-net"

            @property
            def klass(self):
                raise AttributeError("QubesPropertyAccessError")

            @property
            def tags(self):
                raise AttributeError("QubesPropertyAccessError")

        self.assertEqual(scope.scoped_name(self.app, Unreadable(), None), scope.OUT_OF_SCOPE)
        # A label is no qube and keeps its name.
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "label"})
        self.assertEqual(r["value"], "gray")


# ======================================================================= the operator's commands

class Commands(StrictBase):
    def test_revoke_never_reports_done_with_badges_left(self):
        vm = self.app.domains["ai-work"]
        before, dispvm = self.raw("ai-work"), vm._props["default_dispvm"]
        self.assertIsNotNone(dispvm)                  # it has one to pin
        for key in ("tag.List:ai-work", "get.default_dispvm:ai-work"):
            for why in self.each_failure(key):
                # Each position starts from the qube as it was: a revoke that
                # did its work at one must not hide another's.
                self.set_raw("ai-work", before)
                vm._props["default_dispvm"] = dispvm
                try:
                    fleet.revoke(self.app, "ai-work", shutdown=False)
                except fleet.RoleError:
                    continue
                self.assertFalse({t for t in self.raw("ai-work") if birth.controlled(t)}, why)
                self.assertIsNone(vm._props["default_dispvm"], why)

    def test_revoke_reads_its_strip_back(self):
        # A badge that is still there after the strip (re-added meanwhile, or
        # a remove that did nothing) is said, never reported revoked.
        tags = self.app.domains["ai-work"].__dict__["tags"]
        real = tags.discard
        tags.discard = lambda t: None if t == "ai-managed" else real(t)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, "ai-work", shutdown=False)
        self.assertIn("still wears ai-managed", str(cm.exception))

    def test_a_removed_lead_never_keeps_its_routed_badges(self):
        ops = {"remove": lambda: fleet.remove_lead(self.app, "osint"),
               "replace": lambda: fleet.set_lead(self.app, "osint", "template", "ai-debian-13",
                                                 lead_netvm="none", keep_old=False,
                                                 lead_name="ai-osint-lead2"),
               "delete": lambda: fleet.delete_project(self.app, "osint")}
        for op, run in ops.items():
            for key in (f"tag.List:{LEAD}", f"tag.Get:{LEAD}", f"lookup:{LEAD}"):
                for n in range(POSITIONS + 1):
                    self.fresh()                    # each run on a fleet of its own
                    self.app.domains._vms[LEAD].__dict__["_power"] = "Halted"
                    why = self.arm(key, n)
                    try:
                        run()
                    except fleet.RoleError:
                        pass
                    self.disarm()
                    rec = projects.load().get("p01")
                    if rec is None or rec.lead != LEAD:
                        tags = self.raw(LEAD)
                        self.assertTrue(tags is None or "qmcp-lead-p01" not in tags,
                                        f"{op}, {why}: record cleared, lead still wears {tags}")

    def test_enrolling_never_accepts_what_it_cannot_read(self):
        fw = self.app.domains["sys-firewall"]
        self.app.vm("sys-whonix-x", provides_network=True, netvm=fw, tags={"anon-gateway"},
                    features={"qubes-firewall": "1"})
        self.app.vm("gw-x", template=self.app.domains["ai-debian-13"], provides_network=True,
                    netvm=fw, features={"qubes-firewall": "1"})
        self.app.vm("gw-box", provides_network=True, netvm=fw, tags={"ai-dump"},
                    features={"qubes-firewall": "1"})
        cases = [("sys-whonix-x", ["tag.List:sys-whonix-x"]),
                 ("gw-x", ["get.template:gw-x", "tag.List:ai-debian-13"]),
                 ("gw-box", ["tag.List:gw-box"])]
        for name, keys in cases:
            with self.assertRaises(fleet.RoleError):
                fleet.enroll_gateway(self.app, name)
            for key in keys:
                for why in self.each_failure(key):
                    with self.assertRaises(fleet.RoleError, msg=why):
                        fleet.enroll_gateway(self.app, name)
                    self.assertNotIn(name, gateways.load(), why)
                    self.assertTrue(fleet.gateway_refusal(
                        {vm.name: vm for vm in self.app.domains}, name, HUB), why)

    def test_manage_never_takes_in_a_gateway_or_a_drop_box(self):
        self.app.vm("sys-gw-out", provides_network=True, netvm=self.app.domains["sys-firewall"])
        cases = [("sys-gw-out", ["get.provides_network:sys-gw-out", "tag.List:sys-gw-out"]),
                 ("ai-sink", ["tag.List:ai-sink"])]
        for name, keys in cases:
            with self.assertRaises(fleet.RoleError):
                fleet.manage(self.app, name)
            for key in keys:
                for why in self.each_failure(key):
                    with self.assertRaises(fleet.RoleError, msg=why):
                        fleet.manage(self.app, name)
                    self.assertNotIn("ai-managed", self.raw(name), why)

    def test_guard_never_takes_a_member_of_a_slot(self):
        for key in ("tag.List:ai-osint-w1",):
            for why in self.each_failure(key):
                with self.assertRaises(fleet.RoleError, msg=why):
                    fleet.guard(self.app, "ai-osint-w1")
                self.assertNotIn("qmcp-guarded", self.raw("ai-osint-w1"), why)

    def test_a_slot_is_never_reused_past_a_badge_it_cannot_read(self):
        self.app.vm("ai-stray", tags={"qmcp-proj-p03"})
        for key in ("tag.List:ai-stray",):
            for why in self.each_failure(key):
                with self.assertRaises(fleet.RoleError, msg=why):
                    fleet.create_project(self.app, "newp", "template", "ai-debian-13",
                                         networks=[None], quota=GiB)
                self.assertIsNone(projects.find(projects.load(), "newp"), why)

    def test_in_use_counts_what_it_cannot_read(self):
        # ai-osint-w1 sits on ai-net-router, so p01 cannot drop it from its list.
        for key in ("tag.List:ai-osint-w1",):
            for why in self.each_failure(key):
                with self.assertRaises(fleet.RoleError, msg=why):
                    fleet.edit_project(self.app, "osint", networks=[None])
        gw2 = self.app.vm("gw2", provides_network=True, netvm=self.app.domains["sys-firewall"],
                          features={"qubes-firewall": "1"})
        self.enroll("gw2")
        self.app.domains["ai-work2"]._props["netvm"] = gw2
        for key in ("tag.List:ai-work2",):
            for why in self.each_failure(key):
                with self.assertRaises(fleet.RoleError, msg=why):
                    fleet.remove_gateway(self.app, "gw2")
                self.assertIn("gw2", gateways.load(), why)

    def test_a_move_never_crosses_slots_unconfirmed(self):
        for key in ("tag.List:ai-osint-w2",):
            for why in self.each_failure(key):
                with self.assertRaises(fleet.RoleError, msg=why):
                    fleet.move(self.app, "ai-osint-w2", "other")
                self.assertEqual(self.raw("ai-osint-w2"), {"ai-managed", "qmcp-proj-p01"}, why)

    def test_a_promoted_lead_never_keeps_its_old_slot(self):
        for key in ("tag.List:ai-hubq", "tag.Get:ai-hubq"):
            for n in range(POSITIONS + 1):
                self.fresh()                        # each run on a fleet of its own
                why = self.arm(key, n)
                try:
                    fleet.create_project(self.app, "newp", "promote", "ai-hubq", networks=[None],
                                         quota=GiB, model="api.example.com:443")
                    done = True
                except fleet.RoleError:
                    done = False
                self.disarm()
                tags = self.raw("ai-hubq")
                if done:
                    self.assertTrue(core.lead_badges_agree(tags, "p03"), f"{why}: {tags}")
                else:
                    self.assertFalse({"qmcp-lead"} & tags or projects.lead_slots(tags),
                                     f"{why}: {tags}")


    def test_the_command_says_what_it_could_not_read(self):
        import contextlib, io
        from qmcp import cli
        saved = cli._app
        cli._app = lambda: self.app
        self.addCleanup(setattr, cli, "_app", saved)
        self.app.fail.add("tag.List:ai-work")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["revoke", "ai-work", "--no-shutdown"])
        self.assertEqual(rc, 1)
        self.assertIn("cannot read the tags of ai-work", err.getvalue())
        self.assertIn("ai-managed", self.raw("ai-work"))
        # The listings say what they could not read, never a default.
        self.app.fail.clear()
        self.app.fail.add("tag.List:sys-firewall")          # ai-net-router's upstream
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["gateway", "list"])
        self.assertIn("whether its upstream ignores its firewall rules cannot be read", out.getvalue())
        self.assertEqual(out.getvalue().count("ignores its firewall rules"), 1)   # never the claim
        self.app.fail.clear()
        self.app.fail.add("tag.List:ai-work")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["project", "list"])
        self.assertIn("members=?", out.getvalue())
        # A lookup that fails is said too, never a traceback.
        self.app.fail.clear()
        self.app.fail.add("lookup:ai-work2")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["guard", "ai-work2"])
        self.assertEqual(rc, 1)
        self.assertIn("qmcp guard: Injected", err.getvalue())


    def test_a_new_lead_is_never_left_unrecorded(self):
        # The template read after the new lead is made may fail: the lead is
        # recorded, or gone, never left wearing the slot's badge unrecorded.
        # ai-tpl-g is no approved template of osint yet, so it is read then.
        self.assertNotIn("ai-tpl-g", projects.load()["p01"].templates)
        for key in ("tag.List:ai-tpl-g", "tag.Get:ai-tpl-g"):
            for n in range(POSITIONS + 1):
                self.fresh()
                why = self.arm(key, n)
                try:
                    fleet.set_lead(self.app, "osint", "template", "ai-tpl-g",
                                   lead_netvm="none", keep_old=True, lead_name="ai-osint-new")
                except fleet.RoleError:
                    pass
                self.disarm()
                tags = self.raw("ai-osint-new")
                if tags is not None and "qmcp-lead-p01" in tags:
                    self.assertEqual(projects.load()["p01"].lead, "ai-osint-new", why)


    def test_the_gateway_list_counts_a_qube_it_cannot_read(self):
        # Outside AI space, a qube on the router is no user; whose tags cannot
        # be read, it may be one: counted, as remove_gateway counts it.
        self.app.vm("outsider", netvm=self.app.domains["ai-net-router"])
        users = lambda: {r["name"]: r for r in fleet.gateway_rows(self.app)}["ai-net-router"]["used_by"]  # noqa: E731
        self.assertNotIn("outsider", users())
        self.app.fail.add("tag.List:outsider")
        self.assertIn("outsider", users())

    def test_a_failed_read_never_stops_the_kill_of_a_stripped_lead(self):
        # Its badges come off first; a read-back that fails must not stop the
        # kill: a lead left running without them keeps its network and loses
        # the rulebook's guard on its firewall (A1b).
        ops = {"remove": lambda: fleet.remove_lead(self.app, "osint"),
               "replace": lambda: fleet.set_lead(self.app, "osint", "template", "ai-debian-13",
                                                 lead_netvm="none", keep_old=False,
                                                 lead_name="ai-osint-lead2"),
               "delete": lambda: fleet.delete_project(self.app, "osint")}
        for op, run in ops.items():
            for n in range(POSITIONS + 1):
                self.fresh()
                self.assertEqual(self.app.domains[LEAD]._power, "Running")
                why = self.arm(f"tag.List:{LEAD}", n)
                try:
                    run()
                except fleet.RoleError:
                    pass
                self.disarm()
                vm = self.app.domains._any(LEAD)
                if vm is not None and "qmcp-lead-p01" not in vm.__dict__["tags"].raw():
                    self.assertEqual(vm._power, "Halted", f"{op}, {why}: stripped and running")

    def test_a_new_lead_that_fails_leaves_a_report_that_says_the_record_is_empty(self):
        # The old lead is out and the record cleared before the new one is made:
        # a failure making it must leave a report that says so.
        self.app.fail.add("add_new_vm")
        with self.assertRaises(Exception) as cm:
            fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="none",
                           keep_old=True, lead_name="ai-osint-lead2")
        self.assertIsNone(projects.load()["p01"].lead)
        self.assertIn("p01: the record names no lead now", getattr(cm.exception, "report", []))

    def test_a_qube_gone_when_killed_is_not_waited_for(self):
        # A disposable qubesd removes when it is killed reads "NA" from then on:
        # the removal does not wait out its timeout for a halt it cannot read.
        self.app.vm("disp4242", klass="DispVM", template=self.app.domains["ai-dvm"],
                    power="Running", auto_cleanup=True, tags={"ai-managed"})
        start = time.monotonic()
        self.assertEqual(fleet._remove_qube(self.app, "disp4242"), "")
        self.assertLess(time.monotonic() - start, 5)

    def test_removing_a_lead_whose_qube_is_gone_succeeds(self):
        # The cleanup after a lead was removed by hand: noted, never a failure.
        self.app.domains._drop(LEAD)
        report = fleet.remove_lead(self.app, "osint")
        self.assertFalse(report.failed, report)
        self.assertIn(f"p01: no qube is named {LEAD} now", report)
        self.assertIsNone(projects.load()["p01"].lead)

    def test_a_failed_kill_of_a_kept_lead_is_a_failure(self):
        # The lead no longer acts as one, but it still runs on its network. Kept
        # as a worker, it is not removed, so the failed kill is the only failure.
        self.app.fail.add("kill")
        report = fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="none",
                                keep_old=True, lead_name="ai-osint-lead2")
        self.assertTrue(report.failed, report)
        self.assertTrue(any("may still be running" in line for line in report), report)

    def test_a_kill_that_fails_before_a_removal_is_left_to_the_removal(self):
        # The removal tries the kill again, and its result says whether the qube is gone.
        self.app.fail.add("kill")
        self.addCleanup(setattr, fleet, "HALT_WAIT_S", fleet.HALT_WAIT_S)
        fleet.HALT_WAIT_S = 0.05
        report = fleet.remove_lead(self.app, "osint")
        self.assertIn("p01: kill of ai-osint-lead failed (Injected); its removal, once the "
                      "record is saved, tries again", report)
        self.assertFalse(any("may still be running" in line for line in report), report)
        self.assertTrue(any("NOT removed" in line and "kill it by hand (qvm-kill ai-osint-lead)"
                            in line for line in report), report)                  # it still runs

    def test_a_command_that_stops_says_what_it_did(self):
        # A read that fails after a change: the message says the change, never
        # that nothing changed, and never only "try again".
        self.app.vm("plain-x")
        # Each command, and the words that say the step it stopped after.
        cases = [("manage", "plain-x", lambda: fleet.manage(self.app, "plain-x"),
                  ("in AI space now",)),
                 ("guard", "ai-work2", lambda: fleet.guard(self.app, "ai-work2"), ("now, but",)),
                 ("revoke", "ai-work", lambda: fleet.revoke(self.app, "ai-work", shutdown=False),
                  ("taken off, but",)),
                 ("move", "ai-osint-w2", lambda: fleet.move(self.app, "ai-osint-w2", "none"),
                  ("taken out of",)),
                 ("move in", "ai-hubq", lambda: fleet.move(self.app, "ai-hubq", "osint",
                                                           confirm=True),
                  ("taken out of", "put in")),
                 ("keep old", LEAD, lambda: fleet.set_lead(self.app, "osint", "template",
                                                           "ai-debian-13", lead_netvm="none",
                                                           keep_old=True,
                                                           lead_name="ai-osint-lead2"),
                  ("taken off, but", "kept as a worker, but"))]
        for op, name, run, says in cases:
            for n in range(POSITIONS + 1):
                self.fresh()
                self.app.vm("plain-x")
                before = self.raw(name)
                why = self.arm(f"tag.List:{name}", n)
                try:
                    result = run()
                    text, raised = " ".join(result) if isinstance(result, list) else result, False
                except fleet.RoleError as e:
                    text = " ".join(getattr(e, "report", [])) + " " + str(e)
                    raised = True
                self.disarm()
                failed = raised or bool(getattr(result, "failed", None)) if not raised else True
                if failed and self.raw(name) != before:
                    self.assertTrue(any(s in text for s in says), f"{op}, {why}: {text}")
                    self.assertNotIn("before changing anything", text, f"{op}, {why}")
                if op == "keep old" and projects.load()["p01"].lead is None:
                    self.assertIn("the record names no lead", text, f"{op}, {why}: {text}")

    def test_a_delete_removes_a_member_it_read_late(self):
        # Its first read failed; the next pass reads it as a member: removed,
        # never stripped and kept.
        self.app.fail_reads("tag.List:ai-osint-w1", "fail")
        report = fleet.delete_project(self.app, "osint")
        self.assertFalse(self.exists("ai-osint-w1"), report)
        self.assertIn("p01: removed ai-osint-w1", report)

    def test_manage_pins_a_default_disposable_template_it_follows(self):
        vm = self.app.vm("plain-y")                    # follows Qubes' global default
        self.assertTrue(vm.property_is_default("default_dispvm"))
        fleet.manage(self.app, "plain-y")
        self.assertFalse(vm.property_is_default("default_dispvm"))
        self.assertIsNone(vm._props["default_dispvm"])

    def test_a_default_sink_name_qubesd_refuses_is_refused_first(self):
        # A label may start with a digit; a qube name may not.
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.create_project(self.app, "42", "template", "ai-debian-13", networks=[None],
                                 quota=GiB, dump=True)
        self.assertIn("no qube name", str(cm.exception))
        self.assertFalse(self.exists("ai-42-lead"))
        for req in ({"type": "project-create", "title": "t", "label": "42", "dump": True,
                     "lead": {"from": "template", "qube": "ai-debian-13"}, "networks": [None],
                     "quota": GiB},
                    {"type": "project-dump", "title": "t", "project": "42"}):
            with self.assertRaises(proposals.Invalid, msg=req) as cm:
                proposals.normalise(req, "ai-")
            self.assertIn("42-dump, which is no qube name", str(cm.exception))


# ======================================================================= qmcp check

class Check(StrictBase):
    """From a fleet `qmcp check` calls GREEN, proven first: a failed read never
    leaves the check GREEN, and an item that still passes has an error beside
    it that names what it could not read."""

    def setUp(self):
        super().setUp()
        pol, share, rpc = self.tmp / "pol", self.tmp / "lib" / "share", self.tmp / "rpc"
        for d in (pol, share, rpc):
            d.mkdir(parents=True, exist_ok=True)
        text = (HERE.parent / "policy" / fleet.POLICY_NAME).read_text()
        for d in (pol, share):
            (d / fleet.POLICY_NAME).write_text(text)
        from qmcp.services import SERVICES
        for s in SERVICES:
            (rpc / s).write_text("")
        self.env = dict(policy_dir=str(pol), lib_dir=str(self.tmp / "lib"), rpc_dir=str(rpc),
                        legacy_paths=(), system_info={"domains": {}})
        self.app.domains["ai-gw-unbadged"].tags.add("qmcp-guarded")

    def check(self):
        return fleet.check(self.app, **self.env)

    def status(self, findings, item):
        return next((f.status for f in findings if f.check == item), None)

    def assert_green(self):
        findings = self.check()
        self.assertEqual(fleet.overall(findings), "GREEN",
                         [f for f in findings if f.status in ("fail", "error")])

    def test_an_item_passes_a_failed_read_only_beside_an_error(self):
        mutations = [
            ("hub", lambda a: a.domains[HUB].tags.add("ai-managed"), ["tag.List:" + HUB]),
            ("gateways guarded", lambda a: a.domains["ai-gw-unbadged"].tags.discard("qmcp-guarded"),
             ["get.provides_network:ai-gw-unbadged", "tag.List:ai-gw-unbadged"]),
            ("drop boxes", lambda a: a.domains["ai-sink"].tags.add("ai-managed"),
             ["tag.List:ai-sink"]),
            ("tier tags", lambda a: a.domains["ai-work"].tags.add("ai-full"),
             ["tag.List:ai-work"]),
            ("no template in a project", lambda a: a.domains["ai-dvm"].tags.add("qmcp-proj-p01"),
             ["get.template_for_dispvms:ai-dvm", "tag.List:ai-dvm"]),
            ("leads", lambda a: a.domains["ai-work"].tags.update({"qmcp-lead", "qmcp-lead-p01"}),
             ["tag.List:ai-work"]),
            ("AI networks", lambda a: a.domains["ai-work2"]._props.update(
                netvm=a.domains["sys-firewall"]),
             ["tag.List:ai-work2", "get.provides_network:ai-work2"]),
        ]
        for item, mutate, keys in mutations:
            self.fresh()
            self.assert_green()
            mutate(self.app)
            self.assertEqual(self.status(self.check(), item), "fail", item)
            for key in keys:
                for why in self.each_failure(key):
                    findings = self.check()
                    self.assertNotEqual(fleet.overall(findings), "GREEN", why)
                    # The item fails, or an error names what could not be read.
                    if self.status(findings, item) == "pass":
                        qube = key.split(":", 1)[1]
                        self.assertTrue(any(f.status == "error" and qube in f.detail
                                            for f in findings), f"{item}, {why}: {findings}")

    def test_any_failed_read_keeps_the_check_off_green(self):
        # Each a read of a qube the check is otherwise happy with.
        keys = ["tag.List:ai-work", "tag.List:ai-net-router", "get.provides_network:ai-work2",
                "get.default_dispvm:ai-work", "get.netvm:ai-osint-w1", "get.netvm:osint-dump",
                "get.template_for_dispvms:ai-dvm", "get.template:ai-net-router",
                "get.netvm:ai-work"]
        for key in keys:
            self.fresh()
            self.assert_green()
            for why in self.each_failure(key):
                fired = self.app.failed[key]
                findings = self.check()
                if self.app.failed[key] > fired:        # a position past the reads injects nothing
                    self.assertNotEqual(fleet.overall(findings), "GREEN", why)

    def test_a_qube_that_is_gone_is_no_failed_read(self):
        # Removed since the domain list was read, as disposables often are:
        # qubesd answers not-found, and it holds nothing.
        from unittest import mock
        ghost = self.app.vm("disp9999", template=self.app.domains["ai-dvm"], klass="DispVM",
                            tags={"ai-managed", "qmcp-proj-p01"})
        self.app.domains._drop("disp9999")
        listed = lambda domains: iter(list(domains._vms.values()) + [ghost])  # noqa: E731
        with mock.patch.object(type(self.app.domains), "__iter__", listed):
            self.assert_green()
            self.assertGreater(budget.persistent_sum(self.app), 0)
            r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-new", "template": "ai-debian-13",
                                                      "label": "red", "netvm": None})
            self.assertTrue(r["ok"], r)
            rows = self.call("qmcp.GetPoolStats")["projects"]
            self.assertNotIn(None, [r["used"] for r in rows])     # gone holds nothing: still known
            fleet.create_project(self.app, "newp", "template", "ai-debian-13", networks=[None],
                                 quota=GiB)
            self.assertNotIn("disp9999", [r["name"] for r in fleet.listing(self.app)])

    def test_a_remote_qube_is_no_gateway_and_no_failed_read(self):
        self.app.vm("ai-remote", klass="RemoteVM")
        rows = {r["name"]: r for r in fleet.listing(self.app, everything=True)}
        self.assertIs(rows["ai-remote"]["gateway"], False)
        self.assertIs(rows["ai-remote"]["dvmt"], False)
        self.assertIsNone(rows["ai-remote"]["netvm"])           # no network, never unreadable
        self.assert_green()
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.enroll_gateway(self.app, "ai-remote")
        self.assertIn("does not provide network", str(cm.exception))

    def test_a_target_whose_tags_fail_is_no_target_outside_ai_space(self):
        # ai-work2 points at ai-dvm, in AI space: with ai-dvm's tags unread, the
        # "qube tags" error names it, and the default_dispvm item does not
        # call it outside.
        self.app.domains["ai-work2"]._props["default_dispvm"] = self.app.domains["ai-dvm"]
        self.app.fail.add("tag.List:ai-dvm")
        findings = {f.check: f for f in self.check() if f.check == "default_dispvm"}
        self.assertNotIn("ai-work2", findings["default_dispvm"].detail)

    def test_a_gateway_that_is_gone_is_refused(self):
        # Removed: its property reads fail first, as qubesadmin's do.
        gw = self.app.vm("gw-gone", provides_network=True, netvm=self.app.domains["sys-firewall"],
                         features={"qubes-firewall": "1"})
        self.app.domains._drop("gw-gone")
        self.assertIn("cannot read whether gw-gone provides network",
                      fleet.gateway_refusal({"gw-gone": gw}, "gw-gone", HUB))

        # Removed between its role read and its tag read: no such qube.
        class Racing:
            name, klass, provides_network = "gw-race", "AppVM", True

            @property
            def tags(self):
                raise KeyError("QubesVMNotFoundError")
        self.assertEqual(fleet.gateway_refusal({"gw-race": Racing()}, "gw-race", HUB),
                         "no such qube")

    def test_the_operators_list_shows_an_unreadable_qube(self):
        self.app.fail.add("tag.List:ai-work")
        rows = {r["name"]: r for r in fleet.listing(self.app)}
        self.assertIn("ai-work", rows)               # never dropped from the operator's view
        # What the tags say is not known: never shown as no slot or no badges.
        self.assertEqual({k: rows["ai-work"][k] for k in ("state", "slot", "lead", "owner", "badges")},
                         {"state": fleet.UNREADABLE, "slot": fleet.UNREADABLE,
                          "lead": fleet.UNREADABLE, "owner": fleet.UNREADABLE, "badges": None})


# ======================================================================= the second tick

class SecondTick(StrictBase):
    def test_an_unreadable_gateway_never_makes_a_network_look_used(self):
        # A gateway's own upstream is no network AI space uses: a qube put on
        # it directly would skip the gateway. One that cannot be read is no
        # proof of use either.
        up = self.app.vm("sys-up", provides_network=True)
        self.app.domains["ai-gw-unbadged"]._props["netvm"] = up
        p = proposals.normalise({"type": "project-edit", "title": "t", "project": "osint",
                                 "add_networks": ["sys-up"]}, "ai-")
        fresh = "gives AI space a network it does not use today: sys-up"
        self.assertIn(fresh, proposals.second_tick(self.app, p, projects.load()))
        for key in ("get.provides_network:ai-gw-unbadged", "tag.List:ai-gw-unbadged"):
            for why in self.each_failure(key):
                self.assertIn(fresh, proposals.second_tick(self.app, p, projects.load()), why)


# ======================================================================= the pattern itself

#: Properties qubesadmin reads from qubesd, each a read that can fail.
QUBE_PROPERTIES = frozenset({
    "netvm", "provides_network", "template", "template_for_dispvms", "default_dispvm",
    "klass", "label", "tags", "features", "volumes", "memory", "maxmem", "vcpus",
    "management_dispvm", "guivm", "audiovm", "default_template", "default_netvm",
    "virt_mode", "kernel", "autostart"})

#: (module, function) whose `try` reads a qube property and does not re-raise,
#: with the reason its answer on failure is the restrictive one, or is reported.
ALLOWED_TRY = {
    ("birth.py", "resolve_egress"): "a failed read answers 'unresolved', which refuses the create",
    ("budget.py", "_vol_size"): "only KeyError: the qube has no such volume, or is gone",
    ("cli.py", "cmd_gateway"): "the command's own error handler: it prints the error, exits 1",
    ("cli.py", "cmd_project"): "the command's own error handler: it prints the error, exits 1",
    ("fleet.py", "apply_migration"): "writes; each failure is reported FAILED",
    ("fleet.py", "_undo_lead"): "a write and its read-back; the failure is returned and reported",
    ("proposals.py", "_netvm_name"): "UNREADABLE is no network in use: a reason, never one fewer",
    ("proposals.py", "_wears_lead_badge"): "None counts as a removal: a reason, never one fewer",
    ("services.py", "svc_list"): "the label is shown, as UNREADABLE when it fails",
    ("services.py", "svc_set_feature"): "the read-back is shown, as UNREADABLE when it fails",
    ("services.py", "svc_spawn"): "a resize that fails is reported as a warning",
    ("services.py", "include"): "an event whose subject cannot be read is dropped; one whose "
                                "subject is gone is kept only if it was in AI space when the "
                                "window opened",
    ("services.py", "handler"): "the event's class is shown, as UNREADABLE when it fails",
}


def _own_nodes(fn):
    """The nodes of a function, not of the functions nested in it: each is
    judged as its own."""
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))
        elif isinstance(node, ast.Lambda):
            stack.append(node.body)


def lenient_reads(tree) -> list:
    """(function, line, what) for each qube property read that turns a failure
    into a default: `getattr` with a default, `hasattr`, `_safe` around one,
    and a `try` that reads one and has a handler that does not re-raise."""
    found = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in _own_nodes(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name, args = node.func.id, node.args
                if name in ("getattr", "hasattr") and len(args) >= 2 \
                        and isinstance(args[1], ast.Constant) and args[1].value in QUBE_PROPERTIES \
                        and (name == "hasattr" or len(args) == 3):
                    found.append((fn.name, node.lineno, f"{name}(..., {args[1].value!r})"))
                if name == "_safe" and args:
                    for inner in ast.walk(args[0]):
                        if isinstance(inner, ast.Attribute) and inner.attr in QUBE_PROPERTIES:
                            found.append((fn.name, node.lineno, f"_safe(... .{inner.attr})"))
            if isinstance(node, ast.Try):
                reads = {i.attr for s in node.body for i in ast.walk(s)
                         if isinstance(i, ast.Attribute) and i.attr in QUBE_PROPERTIES}
                quiet = [h for h in node.handlers
                         if not any(isinstance(x, ast.Raise) for x in ast.walk(h))]
                if reads and quiet:
                    found.append((fn.name, node.lineno, f"try reading {sorted(reads)}"))
    return found


class NoLenientReads(unittest.TestCase):
    """A qube property read with a default answers a failed read with that
    default. In the dom0 library, `getattr` with a default, `hasattr` and
    `_safe` around a qube property are refused here, and so is a `try` that
    reads one and swallows the failure, unless ALLOWED_TRY names its function
    with the reason its answer is the restrictive one, or is reported."""

    def scanned(self):
        for path in sorted((HERE.parent / "dom0" / "qmcp").glob("*.py")):
            yield path.name, lenient_reads(ast.parse(path.read_text(), filename=str(path)))

    def test_no_qube_property_is_read_with_a_default(self):
        found, modules = [], set()
        for module, reads in self.scanned():
            modules.add(module)
            for fn, line, what in reads:
                if not (what.startswith("try") and (module, fn) in ALLOWED_TRY):
                    found.append(f"{module}:{line} {fn}: {what}")
        self.assertLessEqual({"core.py", "fleet.py", "services.py", "scope.py"}, modules)
        self.assertEqual(found, [], "read the property directly and handle the failure at the "
                                    "decision, or list a try in ALLOWED_TRY with its reason")

    def test_every_allowance_is_still_used(self):
        used = {(m, fn) for m, reads in self.scanned() for fn, _, what in reads
                if what.startswith("try")}
        self.assertEqual(set(ALLOWED_TRY) - used, set(), "an allowance nothing needs: remove it")

    def test_the_guard_finds_the_pattern(self):
        # Teeth: the walker the test runs finds each form it refuses.
        planted = {
            "def f(vm):\n    return getattr(vm, 'netvm', None)\n": "getattr",
            "def f(vm):\n    return hasattr(vm, 'klass')\n": "hasattr",
            "def f(vm):\n    return _safe(lambda: vm.template)\n": "_safe",
            "def f(vm):\n    try:\n        return vm.tags\n    except Exception:\n        return set()\n": "try",
            "def f(vm):\n    def g():\n        try:\n            return vm.label\n        except Exception:\n            return None\n    return g\n": "try",
        }
        for source, form in planted.items():
            found = lenient_reads(ast.parse(source))
            self.assertEqual(len(found), 1, source)
            self.assertTrue(found[0][2].startswith(form), (source, found))
        self.assertEqual(lenient_reads(ast.parse("def f(vm):\n    try:\n        return vm.tags\n"
                                                 "    except Exception:\n        raise Unreadable()\n")),
                         [])                               # a try that re-raises is strict


if __name__ == "__main__":
    unittest.main()
