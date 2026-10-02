"""Offline suite for projects (M2a): leads, slots and the operator's project commands.

It runs the dom0 library against tests/fakequbes.py, as test_dom0.py does. A
lead is a second principal, so every property the hub has is checked again
from a lead's seat, scoped to its project, and every way a lead could reach
past its project is tried. Where the library closes a gap the platform leaves
open, the test shows the fake reproduces the platform first.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import sys
import threading
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, budget, core, fleet, projects, services  # noqa: E402
from fakequbes import GiB  # noqa: E402
from test_dom0 import HUB, Base  # noqa: E402

LEAD = "ai-osint-lead"
OTHER_LEAD = "ai-other-lead"

RECORDS = {
    "version": 1,
    "slots": {
        "p01": {"label": "osint", "lead": LEAD, "templates": ["ai-debian-13", "ai-dvm"],
                "networks": ["ai-net-router", None], "quota": 20 * GiB, "dump": "osint-dump"},
        "p02": {"label": "other", "lead": OTHER_LEAD, "templates": ["ai-tpl-g"],
                "networks": [None], "quota": 10 * GiB, "dump": None},
    },
}


class ProjectBase(Base):
    """The standard fleet plus two projects and a qube of the hub's in p00."""

    def setUp(self):
        super().setUp()
        a = self.app
        tpl, router = a.domains["ai-debian-13"], a.domains["ai-net-router"]
        a.vm(LEAD, template=tpl, netvm=router, power="Running",
             tags={"ai-managed", "qmcp-lead", "qmcp-lead-p01"})
        a.vm("ai-osint-w1", template=tpl, netvm=router, tags={"ai-managed", "qmcp-proj-p01"})
        a.vm("ai-osint-w2", template=tpl, netvm=None, power="Running",
             tags={"ai-managed", "qmcp-proj-p01"})
        a.vm(OTHER_LEAD, template=tpl, netvm=None, tags={"ai-managed", "qmcp-lead", "qmcp-lead-p02"})
        a.vm("ai-other-w1", template=tpl, netvm=None, tags={"ai-managed", "qmcp-proj-p02"})
        a.vm("ai-hubq", template=tpl, netvm=router, tags={"ai-managed", "qmcp-proj-p00"})
        a.vm("osint-dump", template=a.domains["debian-13"], tags={"ai-dump", "qmcp-dump-p01"})
        self.write_records(RECORDS)

    def write_records(self, doc):
        pathlib.Path(projects.PROJECTS_PATH).write_text(json.dumps(doc))

    def records(self):
        return projects.load()

    def lcall(self, service, req=None, lead=LEAD):
        return self.call(service, req, caller=lead)


# ======================================================================= who is a lead

class Principal(ProjectBase):
    def test_a_lead_with_record_and_badges_is_a_principal(self):
        self.assertTrue(self.lcall("qmcp.ListAIManagedQubes")["ok"])

    def test_record_and_badges_must_agree(self):
        lead = self.app.domains[LEAD]
        cases = [
            ("no slot badge", lambda: lead.tags.discard("qmcp-lead-p01")),
            ("no qmcp-lead", lambda: lead.tags.discard("qmcp-lead")),
            ("another slot's badge", lambda: (lead.tags.discard("qmcp-lead-p01"),
                                              lead.tags.add("qmcp-lead-p02"))),
            ("a member badge too", lambda: lead.tags.add("qmcp-proj-p01")),
            ("two lead badges", lambda: lead.tags.add("qmcp-lead-p03")),
            ("guarded", lambda: lead.tags.add("qmcp-guarded")),
            ("outside AI space", lambda: lead.tags.discard("ai-managed")),
        ]
        for why, mutate in cases:
            saved = set(lead.tags)
            mutate()
            self.assertEqual(self.lcall("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED, why)
            lead.tags.clear()
            lead.tags.update(saved)

    def test_badges_without_a_record_are_no_principal(self):
        self.app.vm("ai-rogue", tags={"ai-managed", "qmcp-lead", "qmcp-lead-p05"})
        self.assertEqual(self.lcall("qmcp.ListAIManagedQubes", lead="ai-rogue"), core.NOT_AUTHORIZED)

    def test_workers_and_hub_qubes_are_no_principal(self):
        for caller in ("ai-osint-w1", "ai-hubq", "osint-dump", "ai-work"):
            self.assertEqual(self.lcall("qmcp.ListAIManagedQubes", lead=caller), core.NOT_AUTHORIZED, caller)

    def test_unreadable_records_refuse_leads_and_hub_creates(self):
        pathlib.Path(projects.PROJECTS_PATH).write_text("{not json")
        self.assertEqual(self.lcall("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)
        self.assertTrue(self.call("qmcp.ListAIManagedQubes")["ok"])        # the hub still reads
        self.egress("ai-net-router")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-new", "template": "ai-debian-13"})
        self.assertEqual(r["error"], "project records unreadable")
        self.assertNotIn("ai-new", self.app.domains)

    def test_record_validation(self):
        bad = [
            {"version": 2, "slots": {}},
            {"version": 1, "slots": {"p16": {}}},
            {"version": 1, "slots": {"p01": dict(RECORDS["slots"]["p01"], label="Osint")}},
            {"version": 1, "slots": {"p01": dict(RECORDS["slots"]["p01"], label="toolonglabel")}},
            {"version": 1, "slots": {"p01": dict(RECORDS["slots"]["p01"], quota=True)}},
            {"version": 1, "slots": {"p01": dict(RECORDS["slots"]["p01"], templates=[])}},
            {"version": 1, "slots": {"p01": dict(RECORDS["slots"]["p01"], networks=[None, None])}},
            {"version": 1, "slots": {"p01": RECORDS["slots"]["p01"],
                                     "p02": dict(RECORDS["slots"]["p02"], label="osint")}},
            {"version": 1, "slots": {"p01": RECORDS["slots"]["p01"],
                                     "p02": dict(RECORDS["slots"]["p02"], lead=LEAD)}},
            {"version": 1, "slots": {"p00": {"lead": "x"}}},
        ]
        for doc in bad:
            with self.assertRaises(projects.ProjectsUnreadable, msg=json.dumps(doc)[:80]):
                projects.parse(json.dumps(doc))
        self.assertEqual(sorted(projects.parse(json.dumps(RECORDS))), ["p00", "p01", "p02"])

    def test_lead_concurrency_and_the_shared_pool(self):
        held = [core.acquire_call_slot(LEAD, limit=core.LEAD_CALLS) for _ in range(core.LEAD_CALLS)]
        try:
            self.assertEqual(self.lcall("qmcp.ListAIManagedQubes")["error"], "too many concurrent calls")
            self.assertTrue(self.lcall("qmcp.ListAIManagedQubes", lead=OTHER_LEAD)["ok"])
        finally:
            for fd in held:
                os.close(fd)
        pool = [core.acquire_call_slot(core.LEADS_POOL_KEY, limit=core.LEADS_POOL)
                for _ in range(core.LEADS_POOL)]
        try:
            self.assertEqual(self.lcall("qmcp.ListAIManagedQubes")["error"], "too many concurrent calls")
            # The leads' pool never locks the hub out.
            self.assertTrue(self.call("qmcp.ListAIManagedQubes")["ok"])
        finally:
            for fd in pool:
                os.close(fd)
        self.assertTrue(self.lcall("qmcp.ListAIManagedQubes")["ok"])

    def test_a_leads_call_is_audited_under_its_name(self):
        self.lcall("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "memory", "value": 600})
        line = self.audit_lines()[-1]
        self.assertEqual((line["caller"], line["ok"]), (LEAD, True))
        self.assertTrue(audit.verify()[0])


# ======================================================================= what a lead sees

class LeadReads(ProjectBase):
    def test_list_is_the_project(self):
        r = self.lcall("qmcp.ListAIManagedQubes")
        names = {q["name"]: q for q in r["qubes"]}
        self.assertEqual(set(names), {"ai-osint-w1", "ai-osint-w2", "ai-debian-13", "ai-dvm",
                                      "ai-net-router"})
        self.assertEqual(names["ai-osint-w1"]["slot"], "p01")
        self.assertIsNone(names["ai-debian-13"]["slot"])
        self.assertNotIn("ai-other", json.dumps(r))
        self.assertNotIn("ai-hubq", json.dumps(r))

    def test_hub_list_shows_slots_and_leads(self):
        names = {q["name"]: q for q in self.call("qmcp.ListAIManagedQubes")["qubes"]}
        self.assertEqual((names[LEAD]["slot"], names[LEAD]["lead"]), ("p01", True))
        self.assertEqual((names["ai-hubq"]["slot"], names["ai-hubq"]["lead"]), ("p00", False))
        self.assertIsNone(names["ai-work"]["slot"])
        self.assertNotIn("osint-dump", names)

    def test_outside_the_project_reads_like_nothing(self):
        for name in ("ai-other-w1", OTHER_LEAD, "ai-hubq", "ai-work", "personal", "no-such",
                     LEAD, "ai-tpl-g", "osint-dump"):
            r = self.lcall("qmcp.GetPropertyAIManaged", {"name": name, "property": "memory"})
            self.assertEqual(r, core.NOT_FOUND, name)

    def test_missing_and_foreign_names_cost_the_same(self):
        # One qubesd call each, the same call, and no domain-list shortcut.
        traces = {}
        for name in ("no-such-qube", "ai-other-w1", "ai-hubq", "personal"):
            self.app.calls.clear()
            self.app.domains.lookups = 0
            r = self.lcall("qmcp.SetPropertyAIManaged", {"name": name, "property": "memory", "value": 5})
            self.assertEqual(r, core.NOT_FOUND, name)
            # The first call is the lead's own badges, the same for every request.
            traces[name] = ([c[1:] for c in self.app.calls[1:]], self.app.domains.lookups)
        self.assertEqual(len(set(map(repr, traces.values()))), 1, traces)
        self.assertEqual(traces["no-such-qube"][0], [("admin.vm.tag.Get", "qmcp-proj-p01")])

    def test_references_are_scoped_to_the_project(self):
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": "ai-osint-w1", "property": "netvm"})
        self.assertEqual(r["value"], "ai-net-router")          # on the project's networks
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": "ai-osint-w1", "property": "template"})
        self.assertEqual(r["value"], "ai-debian-13")           # on the approved list
        self.app.domains["ai-osint-w1"]._props["netvm"] = self.app.domains["ai-gw-unbadged"]
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": "ai-osint-w1", "property": "netvm"})
        self.assertEqual(r["value"], "<out-of-scope>")
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": "ai-osint-w1", "property": "dns"})
        self.assertEqual(r["value"], "<out-of-scope>")         # an address of an unseen netvm
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": "ai-net-router", "property": "netvm"})
        self.assertEqual(r["value"], "<out-of-scope>")

    def test_pool_stats_are_the_projects(self):
        r = self.lcall("qmcp.GetPoolStats")
        self.assertEqual(r["ai_managed_bytes_used"], 2 * 2 * GiB)
        self.assertEqual(r["ai_managed_bytes_cap"], 20 * GiB)
        self.assertEqual(r["ai_managed_bytes_headroom"], 16 * GiB)
        self.assertEqual((r["project"], r["name_prefix"], r["dump"]), ("osint", "ai-osint-", "osint-dump"))
        self.assertEqual(r["networks"], ["ai-net-router", None])
        hub = self.call("qmcp.GetPoolStats")
        self.assertEqual(hub["name_prefix"], "ai-")
        self.assertGreater(hub["ai_managed_bytes_used"], r["ai_managed_bytes_used"])

    def test_no_event_stream_for_leads(self):
        r = self.lcall("qmcp.AIManagedEvents", {"duration": 1})
        self.assertEqual(r["error"], "events are not available to leads")


# ======================================================================= what a lead does

class LeadWrites(ProjectBase):
    def test_a_lead_operates_its_members_only(self):
        ok = {"name": "ai-osint-w1", "property": "memory", "value": 600}
        self.assertEqual(self.lcall("qmcp.SetPropertyAIManaged", ok), {"ok": True})
        for name in ("ai-other-w1", "ai-hubq", OTHER_LEAD, LEAD, "ai-debian-13", "ai-dvm"):
            r = self.lcall("qmcp.SetPropertyAIManaged", dict(ok, name=name))
            self.assertEqual(r, core.NOT_FOUND, name)
        self.assertEqual(self.lcall("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "start"}),
                         {"ok": True})
        self.assertEqual(self.lcall("qmcp.LifecycleAIManaged", {"name": "ai-other-w1", "action": "start"}),
                         core.NOT_FOUND)
        r = self.lcall("qmcp.SetFeatureAIManaged", {"name": "ai-osint-w1", "feature": "service.x", "value": 1})
        self.assertTrue(r["ok"])
        r = self.lcall("qmcp.SetFeatureAIManaged", {"name": "ai-osint-w1", "feature": "internal", "value": 1})
        self.assertEqual(r["error"], "feature not settable")
        r = self.lcall("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1", "property": "netvm",
                                                     "value": "ai-net-router"})
        self.assertIn("operator-only", r["error"])

    def test_a_lead_removes_its_workers(self):
        self.assertEqual(self.lcall("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "remove"}),
                         {"ok": True})
        self.assertNotIn("ai-osint-w1", self.app.domains)

    def test_a_guarded_member_is_still_guarded(self):
        self.app.domains["ai-osint-w1"].tags.add("qmcp-guarded")
        r = self.lcall("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "start"})
        self.assertEqual(r, core.GUARDED_REFUSAL)


class LeadCreates(ProjectBase):
    def spawn(self, **req):
        req.setdefault("name", "ai-osint-w3")
        req.setdefault("template", "ai-debian-13")
        return self.lcall("qmcp.SpawnAIManagedQube", req)

    def test_names_inside_the_project_only_and_before_any_lookup(self):
        for name in ("ai-x", "ai-other-x", "zzz", "ai-osint-", "ai-osintx-1"):
            self.app.domains.lookups = 0
            self.app.calls.clear()
            r = self.spawn(name=name)
            self.assertFalse(r["ok"], name)
            self.assertEqual(self.app.domains.lookups, 0, name)
            self.assertEqual([c[1] for c in self.app.calls], ["admin.vm.tag.List"], name)

    def test_spawn_joins_the_project_on_its_default_network(self):
        r = self.spawn()
        self.assertEqual(r, {"ok": True, "name": "ai-osint-w3"})
        self.assertEqual(self.tags("ai-osint-w3"),
                         {"ai-managed", "qmcp-proj-p01", f"qmcp-owner_{LEAD}"})
        vm = self.app.domains["ai-osint-w3"]
        self.assertEqual(vm.netvm.name, "ai-net-router")          # never the lead's own network
        self.assertIsNone(vm.default_dispvm)
        self.assertFalse(vm.property_is_default("netvm"))

    def test_the_lead_network_never_leaks_to_workers(self):
        # p02's lead sits on no network; its only worker network is "none".
        self.app.domains[OTHER_LEAD]._props["netvm"] = self.app.domains["ai-net-router"]
        r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-other-w2", "template": "ai-tpl-g"},
                       lead=OTHER_LEAD)
        self.assertTrue(r["ok"], r)
        self.assertIsNone(self.app.domains["ai-other-w2"].netvm)

    def test_worker_networks(self):
        self.assertTrue(self.spawn(name="ai-osint-off", netvm=None)["ok"])
        self.assertIsNone(self.app.domains["ai-osint-off"].netvm)
        self.assertTrue(self.spawn(name="ai-osint-r", netvm="ai-net-router")["ok"])
        r = self.spawn(name="ai-osint-g", netvm="ai-gw-unbadged")
        self.assertEqual(r["error"], "netvm must be one of this project's worker networks")
        self.assertNotIn("ai-osint-g", self.app.domains)

    def test_templates_from_the_approved_list_only(self):
        for tpl in ("ai-tpl-g", "debian-13", "no-such"):
            self.app.domains.lookups = 0
            r = self.spawn(template=tpl)
            self.assertEqual(r["error"], "template is not on this project's approved list", tpl)
            self.assertEqual(self.app.domains.lookups, 0, tpl)

    def test_no_disposable_templates_from_a_lead(self):
        r = self.spawn(klass="DispVMTemplate")
        self.assertIn("klass must be one of", r["error"])

    def test_quota(self):
        self.assertEqual(self.spawn(private_size=17 * GiB)["error"], "project quota exceeded")
        self.assertNotIn("ai-osint-w3", self.app.domains)
        self.assertTrue(self.spawn(private_size=16 * GiB)["ok"])
        self.assertEqual(self.spawn(name="ai-osint-w4")["error"], "project quota exceeded")

    def test_fleet_cap_still_applies(self):
        (self.tmp / "pool-cap").write_text(str(10 * GiB))
        self.assertEqual(self.spawn()["error"], "pool cap exceeded")

    def test_clone_a_member(self):
        src = self.app.domains["ai-osint-w1"]
        src.tags.add("qmcp-proj-p02")            # a stray badge the platform would copy
        src.tags.add("qmcp-dump-p05")
        r = self.lcall("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1", "name": "ai-osint-c1"})
        self.assertEqual(r, {"ok": True, "name": "ai-osint-c1"})
        self.assertEqual(self.tags("ai-osint-c1"), {"ai-managed", "qmcp-proj-p01", f"qmcp-owner_{LEAD}"})
        self.assertEqual(self.app.domains["ai-osint-c1"].netvm.name, "ai-net-router")

    def test_clone_refusals(self):
        for source in ("ai-other-w1", "ai-hubq", "ai-debian-13", OTHER_LEAD, LEAD, "personal"):
            r = self.lcall("qmcp.CloneAIManagedQube", {"source": source, "name": "ai-osint-c2"})
            self.assertEqual(r, core.NOT_FOUND, source)
        self.app.domains["ai-osint-w1"]._props["netvm"] = self.app.domains["ai-gw-unbadged"]
        r = self.lcall("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1", "name": "ai-osint-c3"})
        self.assertEqual(r["error"], "the source's network is not one of this project's worker networks")

    def test_disposables(self):
        r = self.lcall("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.tags(r["name"]), {"ai-managed", "qmcp-proj-p01", f"qmcp-owner_{LEAD}"})
        r = self.lcall("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-g"})
        self.assertEqual(r["error"], "template is not on this project's approved list")
        r = self.spawn(name="ai-osint-d1", klass="DispVM", template="ai-dvm")
        self.assertTrue(r["ok"], r)
        self.assertIn("qmcp-proj-p01", self.tags("ai-osint-d1"))

    def test_a_disposable_template_on_another_network_is_refused(self):
        self.app.domains["ai-dvm"]._props["netvm"] = self.app.domains["ai-gw-unbadged"]
        r = self.lcall("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertEqual(r["error"], "the source's network is not one of this project's worker networks")
        self.assertEqual(self.app.domains._hidden, {})


# ======================================================================= the hub, with projects

class HubWithProjects(ProjectBase):
    def test_the_hub_cannot_name_into_a_project(self):
        self.egress("ai-net-router")
        for name in ("ai-osint-x", "ai-other-y"):
            self.app.domains.lookups = 0
            r = self.call("qmcp.SpawnAIManagedQube", {"name": name, "template": "ai-debian-13"})
            self.assertEqual(r["error"], "name is inside a project's name space")
            self.assertEqual(self.app.domains.lookups, 0)
            r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": name})
            self.assertEqual(r["error"], "name is inside a project's name space")
        self.assertTrue(self.call("qmcp.SpawnAIManagedQube", {"name": "ai-osintx", "template": "ai-debian-13"})["ok"])

    def test_what_the_hubs_creates_join(self):
        self.egress("ai-net-router")
        self.call("qmcp.SpawnAIManagedQube", {"name": "ai-app", "template": "ai-debian-13"})
        self.assertIn("qmcp-proj-p00", self.tags("ai-app"))
        self.call("qmcp.SpawnAIManagedQube", {"name": "ai-mydvm", "template": "ai-debian-13",
                                             "klass": "DispVMTemplate"})
        self.assertFalse(projects.member_slots(self.tags("ai-mydvm")))
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertFalse(projects.member_slots(self.tags(r["name"])))      # 121: no p00 for disposables
        self.call("qmcp.CloneAIManagedQube", {"source": "ai-debian-13", "name": "ai-tpl2"})
        self.assertFalse(projects.member_slots(self.tags("ai-tpl2")))

    def test_the_hub_clones_a_lead_into_no_slot_without_its_role(self):
        # Project content never joins p00's dialog-free copies by a clone.
        r = self.call("qmcp.CloneAIManagedQube", {"source": LEAD, "name": "ai-lead-copy"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.tags("ai-lead-copy"), {"ai-managed", f"qmcp-owner_{HUB}"})

    def test_the_hub_operates_projects_but_does_not_remove_a_lead(self):
        r = self.call("qmcp.LifecycleAIManaged", {"name": LEAD, "action": "remove"})
        self.assertEqual(r["error"], "removing a lead takes the operator's approval")
        self.assertIn(LEAD, self.app.domains)
        self.assertEqual(self.call("qmcp.LifecycleAIManaged", {"name": LEAD, "action": "kill"}), {"ok": True})
        self.assertEqual(self.call("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "remove"}),
                         {"ok": True})
        r = self.call("qmcp.SetPropertyAIManaged", {"name": LEAD, "property": "netvm", "value": None})
        self.assertEqual(r, {"ok": True})                       # disconnecting stays allowed


# ======================================================================= the operator's commands

class Operator(ProjectBase):
    def test_create_from_a_template(self):
        report = fleet.create_project(self.app, "res", "template", "ai-debian-13",
                                      templates=["ai-dvm"], networks=["ai-net-router", "none"],
                                      quota="40G", lead_netvm="ai-net-router", dump=True)
        self.assertTrue(report[-1].endswith("workers are named ai-res-*"), report)
        p = projects.find(self.records(), "res")
        self.assertEqual((p.slot, p.lead, p.templates, p.networks, p.quota, p.dump),
                         ("p03", "ai-res-lead", ("ai-debian-13", "ai-dvm"), ("ai-net-router", None),
                          40 * GiB, "res-dump"))
        self.assertEqual(self.tags("ai-res-lead"),
                         {"ai-managed", "qmcp-lead", "qmcp-lead-p03", "qmcp-owner_dom0"})
        lead = self.app.domains["ai-res-lead"]
        self.assertEqual(lead.netvm.name, "ai-net-router")
        self.assertIsNone(lead.default_dispvm)
        self.assertEqual(self.tags("res-dump"), {"ai-dump", "qmcp-dump-p03"})
        self.assertIsNone(self.app.domains["res-dump"].netvm)
        # The new lead is a principal at once.
        self.assertTrue(self.lcall("qmcp.ListAIManagedQubes", lead="ai-res-lead")["ok"])

    def test_a_lead_on_a_template_outside_ai_space(self):
        # The hub cannot edit the lead's root; the list holds only AI space.
        fleet.create_project(self.app, "safe", "template", "debian-13", templates=["ai-debian-13"],
                             networks=["none"], quota="5G", lead_netvm="none")
        self.assertEqual(self.app.domains["ai-safe-lead"].template.name, "debian-13")
        self.assertEqual(projects.find(self.records(), "safe").templates, ("ai-debian-13",))

    def test_create_by_promoting_or_cloning(self):
        fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"], quota=10 * GiB)
        self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-lead", "qmcp-lead-p03"})
        self.assertEqual(self.app.domains["ai-hubq"].netvm.name, "ai-net-router")   # kept
        self.assertEqual(projects.find(self.records(), "prom").templates, ("ai-debian-13",))
        fleet.create_project(self.app, "clo", "clone", "ai-work", networks=["none"], quota=10 * GiB,
                             lead_netvm="none")
        self.assertEqual(self.tags("ai-clo-lead"),
                         {"ai-managed", "qmcp-lead", "qmcp-lead-p04", "qmcp-owner_dom0", "operator-note"})
        self.assertIsNone(self.app.domains["ai-clo-lead"].netvm)

    def test_create_refusals(self):
        def create(label="new", source="template", origin="ai-debian-13", **kw):
            kw.setdefault("networks", ["none"])
            kw.setdefault("quota", "1G")
            return fleet.create_project(self.app, label, source, origin, **kw)
        for kwargs, why in [
            (dict(label="osint"), "taken"),
            (dict(label="Big"), "lowercase"),
            (dict(label="ai", dump=True), "inside"),
            (dict(origin="ai-work"), "not a TemplateVM"),
            (dict(origin="debian-13"), "at least one approved template in AI space"),
            (dict(networks=["ai-work"]), "not a gateway"),
            (dict(templates=["ai-work"]), "not a template"),
            (dict(source="promote", origin=LEAD), "already leads"),
            (dict(source="promote", origin="ai-osint-w1"), "another project's member"),
            (dict(source="promote", origin="ai-tpl-g"), "AppVM"),
            (dict(quota=True), "quota"),
        ]:
            with self.assertRaises(fleet.RoleError, msg=why) as cm:
                create(**kwargs)
            self.assertIn(why, str(cm.exception))
        self.app.vm("ai-new-squat", tags=set())
        with self.assertRaises(fleet.RoleError) as cm:
            create()
        self.assertIn("already sit in", str(cm.exception))
        self.assertEqual(sorted(self.records()), ["p00", "p01", "p02"])

    def test_a_slot_with_leftover_badges_is_not_reused(self):
        self.app.domains["personal"].tags.add("qmcp-proj-p03")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.create_project(self.app, "new", "template", "ai-debian-13", networks=["none"], quota="1G")
        self.assertIn("p03 still has badges", str(cm.exception))

    def test_a_failed_create_leaves_nothing(self):
        self.app.fail.add("tag.add:qmcp-dump-p03")
        with self.assertRaises(Exception):
            fleet.create_project(self.app, "res", "template", "ai-debian-13", networks=["none"],
                                 quota="1G", dump=True)
        self.assertNotIn("ai-res-lead", self.app.domains)
        self.assertNotIn("res-dump", self.app.domains)
        self.assertIsNone(projects.find(self.records(), "res"))

    def test_delete(self):
        self.app.domains["personal"].tags.add("qmcp-proj-p01")      # a stray badge outside AI space
        report = fleet.delete_project(self.app, "osint")
        for gone in (LEAD, "ai-osint-w1", "ai-osint-w2"):
            self.assertNotIn(gone, self.app.domains, report)
        self.assertIn("personal", self.app.domains)                 # stripped, never removed
        self.assertNotIn("qmcp-proj-p01", self.tags("personal"))
        self.assertEqual(self.tags("osint-dump"), {"ai-dump"})      # kept, badge stripped
        self.assertIsNone(projects.find(self.records(), "osint"))
        self.assertEqual(report[-1], "p01: free")
        self.assertEqual(self.lcall("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)

    def test_remove_the_lead(self):
        fleet.remove_lead(self.app, "osint")
        self.assertNotIn(LEAD, self.app.domains)
        self.assertIsNone(projects.find(self.records(), "p01").lead)
        self.assertIn("ai-osint-w1", self.app.domains)               # workers untouched
        self.assertIn("qmcp-proj-p01", self.tags("ai-osint-w1"))

    def test_change_the_lead_keeping_the_old_one_as_a_worker(self):
        fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="none",
                       keep_old=True, lead_name="ai-osint-lead2")
        self.assertEqual(self.tags(LEAD), {"ai-managed", "qmcp-proj-p01"})
        self.assertEqual(projects.find(self.records(), "osint").lead, "ai-osint-lead2")
        self.assertEqual(self.lcall("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)
        self.assertTrue(self.lcall("qmcp.ListAIManagedQubes", lead="ai-osint-lead2")["ok"])
        r = self.lcall("qmcp.SetPropertyAIManaged", {"name": LEAD, "property": "memory", "value": 500},
                       lead="ai-osint-lead2")
        self.assertEqual(r, {"ok": True})

    def test_move(self):
        fleet.move(self.app, "ai-work", "p00")
        self.assertIn("qmcp-proj-p00", self.tags("ai-work"))
        fleet.move(self.app, "ai-work", "osint", confirm=True)
        self.assertEqual(projects.member_slots(self.tags("ai-work")), {"p01"})
        fleet.move(self.app, "ai-work", "none")
        self.assertEqual(projects.member_slots(self.tags("ai-work")), set())
        for name in ("ai-debian-13", LEAD, "ai-net-router", "personal"):
            with self.assertRaises(fleet.RoleError, msg=name):
                fleet.move(self.app, name, "p00")

    def test_p00_dump_sink(self):
        fleet.add_dump(self.app, "p00")
        self.assertEqual(self.records()["p00"].dump, "hub-dump")
        self.assertEqual(self.tags("hub-dump"), {"ai-dump", "qmcp-dump-p00"})
        with self.assertRaises(fleet.RoleError):
            fleet.add_dump(self.app, "p00")

    def test_role_actions_refuse_leads_and_members(self):
        for action, name in ((fleet.guard, LEAD), (fleet.revoke, LEAD), (fleet.guard, "ai-osint-w1")):
            with self.assertRaises(fleet.RoleError, msg=name):
                action(self.app, name)


class CheckProjects(ProjectBase):
    def findings(self):
        records = self.records()
        vms = list(self.app.domains)
        return {f.check: f for f in fleet.project_findings(vms, {v.name: v for v in vms}, records, "ai-")}

    def test_a_sound_fleet_has_no_failure(self):
        f = self.findings()
        self.assertEqual([x for x in f.values() if x.status == "fail"], [])
        self.assertEqual(f["managed qubes in no slot"].status, "warn")
        self.assertIn("ai-work", f["managed qubes in no slot"].detail)

    def test_badges_a_lead_could_route_to(self):
        self.app.domains["personal"].tags.add("qmcp-proj-p01")
        self.assertEqual(self.findings()["slot badges in AI space"].status, "fail")

    def test_stale_slot_badges(self):
        self.app.domains["ai-work"].tags.add("qmcp-proj-p07")
        self.assertEqual(self.findings()["slot badges have records"].status, "fail")

    def test_disagreeing_lead(self):
        self.app.domains[LEAD].tags.discard("qmcp-lead-p01")
        self.assertEqual(self.findings()["leads"].status, "fail")

    def test_two_slots_and_templates(self):
        self.app.domains["ai-osint-w1"].tags.add("qmcp-proj-p02")
        self.app.domains["ai-debian-13"].tags.add("qmcp-proj-p01")
        f = self.findings()
        self.assertEqual(f["one slot per qube"].status, "fail")
        self.assertEqual(f["no template in a project"].status, "fail")

    def test_sinks(self):
        self.app.domains["osint-dump"].tags.add("ai-managed")
        self.assertEqual(self.findings()["dump sinks"].status, "fail")

    def test_a_dump_sink_is_no_stray_badge(self):
        # Found on hardware: the generic stray-badge check flagged every sink.
        self.app.domains["personal"].tags.add("qmcp-something")
        f = {x.check: x for x in fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["stray badges"].status, "warn")
        self.assertIn("personal", f["stray badges"].detail)
        self.assertNotIn("osint-dump", f["stray badges"].detail)
        self.assertEqual(f["dump sinks"].status, "pass")

    def test_a_leaderless_project_warns(self):
        fleet.remove_lead(self.app, "osint")
        f = self.findings()
        self.assertEqual(f["projects without a lead"].status, "warn")
        self.assertEqual([x for x in f.values() if x.status == "fail"], [])




# ======================================================================= audit findings (M2a)

class RevokingStdin(io.BytesIO):
    """A request that arrives slowly: `hook` runs when the service reads it."""

    def __init__(self, data, hook):
        super().__init__(data)
        self.hook = hook

    def read(self, n=-1):
        if self.hook:
            hook, self.hook = self.hook, None
            hook()
        return super().read(n)


class AuditFixes(ProjectBase):
    """Regression tests from the pre-release audit of M2a (2026-10-01). Each fails
    on the code as it stood before its fix."""

    def assertUntouched(self, lead=LEAD, slot="p01"):
        self.assertIn(lead, self.app.domains)
        self.assertIn(f"qmcp-lead-{slot}", self.tags(lead))
        self.assertEqual(projects.find(self.records(), slot).lead, lead)

    # F-001 / F-002: validate before taking anything away
    def test_a_promote_with_a_bad_network_changes_nothing(self):
        before = self.tags("ai-hubq")
        with self.assertRaises(fleet.RoleError):
            fleet.set_lead(self.app, "osint", "promote", "ai-hubq", lead_netvm="no-such-gw")
        self.assertEqual(self.tags("ai-hubq"), before)
        self.assertUntouched()

    def test_a_bad_new_lead_leaves_the_old_one_in_place(self):
        for source, origin in (("template", "no-such-tpl"), ("template", "ai-work"),
                               ("clone", "ai-osint-w1"), ("promote", OTHER_LEAD)):
            with self.assertRaises(fleet.RoleError, msg=origin):
                fleet.set_lead(self.app, "osint", source, origin, lead_netvm="none")
            self.assertUntouched()

    def test_keep_old_under_the_default_name_is_refused_before_any_change(self):
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="none", keep_old=True)
        self.assertIn("--lead-name", str(cm.exception))
        self.assertUntouched()

    def test_a_failed_command_reports_what_it_did(self):
        self.app.fail.add("add_new_vm")
        with self.assertRaises(Exception) as cm:
            fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="none")
        self.assertTrue(any("no longer the lead" in line for line in getattr(cm.exception, "report", [])))

    def test_check_fails_on_lead_badges_without_a_record(self):
        self.app.domains["ai-work"].tags.update({"qmcp-lead", "qmcp-lead-p01"})
        fails = [f.check for f in fleet.project_findings(
            list(self.app.domains), {v.name: v for v in self.app.domains}, self.records(), "ai-")
            if f.status == "fail"]
        self.assertIn("leads", fails)

    # F-003: authority is current when the work is done
    def test_a_lead_revoked_while_its_request_arrives_is_refused(self):
        req = json.dumps({"name": "ai-osint-w1", "action": "remove"}).encode()
        out = io.StringIO()
        services.main("qmcp.LifecycleAIManaged",
                      stdin=RevokingStdin(req, lambda: fleet.remove_lead(self.app, "osint")),
                      environ={"QREXEC_REMOTE_DOMAIN": LEAD}, app_factory=lambda: self.app, out=out)
        self.assertEqual(json.loads(out.getvalue()), core.NOT_AUTHORIZED)
        self.assertIn("ai-osint-w1", self.app.domains)

    def test_a_create_that_waited_for_the_lock_rechecks_authority(self):
        budget.LOCK_TIMEOUT_S = 5.0
        held = budget.acquire_create_lock()
        result = {}

        def spawn():
            result["r"] = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-late",
                                                                "template": "ai-debian-13"})
        worker = threading.Thread(target=spawn)
        worker.start()
        time.sleep(0.5)                                   # the spawn now waits on the lock
        doc = json.loads(json.dumps(RECORDS))
        doc["slots"]["p01"]["lead"] = None
        self.write_records(doc)
        self.app.domains[LEAD].tags.discard("qmcp-lead-p01")
        os.close(held)
        worker.join(10)
        self.assertEqual(result["r"], core.NOT_AUTHORIZED)
        self.assertNotIn("ai-osint-late", self.app.domains)

    def test_project_commands_wait_for_creates(self):
        held = budget.acquire_create_lock()
        try:
            with self.assertRaises(fleet.RoleError):
                fleet.remove_lead(self.app, "osint")
        finally:
            os.close(held)
        self.assertUntouched()

    # F-004: a qube entering a slot meets the rules a new one meets
    def test_keep_old_needs_its_network_on_the_list(self):
        self.app.domains[OTHER_LEAD]._props["netvm"] = self.app.domains["ai-net-router"]
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead(self.app, "other", "template", "ai-debian-13", lead_netvm="none",
                           keep_old=True, lead_name="ai-other-lead2")
        self.assertIn("network", str(cm.exception))
        self.assertUntouched(OTHER_LEAD, "p02")

    def test_moves_between_slots_need_confirmation(self):
        with self.assertRaises(fleet.RoleError):
            fleet.move(self.app, "ai-osint-w1", "p00")
        self.assertEqual(projects.member_slots(self.tags("ai-osint-w1")), {"p01"})
        fleet.move(self.app, "ai-osint-w1", "p00", confirm=True)
        self.assertEqual(projects.member_slots(self.tags("ai-osint-w1")), {"p00"})
        fleet.move(self.app, "ai-work", "p00")             # from no slot: no confirmation needed
        with self.assertRaises(fleet.RoleError) as cm:     # off the target's network list
            fleet.move(self.app, "ai-work", "other", confirm=True)
        self.assertIn("network", str(cm.exception))

    def test_the_hub_clones_project_content_into_no_slot(self):
        for source, want in (("ai-osint-w1", set()), (LEAD, set()), ("ai-hubq", {"p00"}),
                             ("ai-work2", {"p00"})):
            name = f"ai-c-{source[-4:]}"
            r = self.call("qmcp.CloneAIManagedQube", {"source": source, "name": name})
            self.assertTrue(r["ok"], (source, r))
            self.assertEqual(projects.member_slots(self.tags(name)), want, source)

    # F-006, F-007, F-008
    def test_a_failed_promote_restores_the_exact_badges(self):
        before = self.tags("ai-work")
        self.app.fail.add("tag.add:qmcp-dump-p03")
        with self.assertRaises(Exception):
            fleet.create_project(self.app, "prom", "promote", "ai-work", networks=["none"],
                                 quota="1G", dump=True)
        self.assertEqual(self.tags("ai-work"), before)

    def test_labels_shaped_like_slots_are_refused(self):
        for label in ("p01", "p15", "p99", "none", "hub"):
            with self.assertRaises(fleet.RoleError, msg=label):
                fleet.create_project(self.app, label, "template", "ai-debian-13", networks=["none"],
                                     quota="1G")
            doc = {"version": 1, "slots": {"p03": dict(RECORDS["slots"]["p01"], label=label, lead=None)}}
            with self.assertRaises(projects.ProjectsUnreadable, msg=label):
                projects.parse(json.dumps(doc))

    def test_lead_removal_leaves_an_unbadged_namesake_alone(self):
        doc = json.loads(json.dumps(RECORDS))
        doc["slots"]["p01"]["lead"] = "ai-work2"            # removed by hand; the name reused
        self.write_records(doc)
        report = fleet.remove_lead(self.app, "osint")
        self.assertIn("ai-work2", self.app.domains)
        self.assertTrue(any("left alone" in line for line in report), report)

    # F-009
    def test_the_quota_is_checked_before_the_fleet_cap(self):
        (self.tmp / "pool-cap").write_text(str(1 * GiB))
        r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-big", "template": "ai-debian-13",
                                                   "private_size": 17 * GiB})
        self.assertEqual(r["error"], "project quota exceeded")

    def test_check_warns_when_quotas_outgrow_the_pool(self):
        (self.tmp / "pool-cap").write_text(str(25 * GiB))
        f = {x.check: x for x in fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["project quotas"].status, "warn")



class EditAndCli(ProjectBase):
    """`qmcp project edit`, the command line, and the warnings the other classes leave out."""

    def test_edit_replaces_lists_and_quota_and_moves_no_worker(self):
        fleet.edit_project(self.app, "osint", templates=["ai-debian-13"], networks=["none"], quota="30G")
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.templates, p.networks, p.quota), (("ai-debian-13",), (None,), 30 * GiB))
        self.assertEqual(self.app.domains["ai-osint-w1"].netvm.name, "ai-net-router")   # not moved
        for kwargs in ({"templates": ["ai-work"]}, {"networks": ["ai-work"]}, {"quota": "0"}):
            with self.assertRaises(fleet.RoleError, msg=kwargs):
                fleet.edit_project(self.app, "osint", **kwargs)
        self.assertEqual(projects.find(self.records(), "osint").quota, 30 * GiB)

    def cli(self, *argv):
        from qmcp import cli
        saved = cli._app
        cli._app = lambda: self.app
        out, err = io.StringIO(), io.StringIO()
        try:
            from contextlib import redirect_stderr, redirect_stdout
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    rc = cli.main(list(argv))
                except SystemExit as e:
                    rc = e.code
        finally:
            cli._app = saved
        return rc, out.getvalue(), err.getvalue()

    def test_cli_list_and_show(self):
        rc, out, _ = self.cli("project", "list", "--json")
        self.assertEqual(rc, 0)
        rows = {r["slot"]: r for r in json.loads(out)}
        self.assertEqual((rows["p01"]["label"], rows["p01"]["members"]), ("osint", 2))
        rc, out, _ = self.cli("project", "show", "osint")
        self.assertEqual((rc, json.loads(out)["lead"]), (0, LEAD))
        rc, _, err = self.cli("project", "show", "nope")
        self.assertEqual(rc, 1)

    @unittest.skipIf(os.geteuid() == 0, "the root check only refuses non-root")
    def test_cli_changes_need_root(self):
        rc, _, _ = self.cli("project", "delete", "osint", "--yes")
        self.assertIn("run as root", str(rc))
        self.assertIsNotNone(projects.find(self.records(), "osint"))

    def findings(self):
        vms = list(self.app.domains)
        return {f.check: f for f in fleet.project_findings(vms, {v.name: v for v in vms},
                                                            self.records(), "ai-")}

    def test_warnings_on_lists_sinks_and_names(self):
        doc = json.loads(json.dumps(RECORDS))
        doc["slots"]["p01"]["templates"] = ["ai-debian-13", "ai-work"]       # not a template
        doc["slots"]["p01"]["networks"] = ["ai-net-router", "ai-work"]       # not a gateway
        self.write_records(doc)
        self.app.domains["osint-dump"]._props["netvm"] = self.app.domains["sys-firewall"]
        self.app.vm("ai-osint-moved", tags={"ai-managed"})                 # left the project
        f = self.findings()
        self.assertEqual(f["approved templates"].status, "warn")
        self.assertIn("ai-work", f["approved templates"].detail)
        self.assertEqual(f["worker networks"].status, "warn")
        self.assertEqual(f["dump sink network"].status, "warn")
        self.assertEqual(f["project name spaces"].status, "warn")
        self.assertIn("ai-osint-moved", f["project name spaces"].detail)
        self.assertNotIn(LEAD, f["project name spaces"].detail)
        self.assertNotIn("ai-osint-w1", f["project name spaces"].detail)

    def test_a_move_out_says_the_name_stays_detectable(self):
        report = fleet.move(self.app, "ai-osint-w1", "none")
        self.assertTrue(any("can still detect it by name" in line for line in report), report)



class BadgeOrder(ProjectBase):
    """Found by the M2b audit (2026-10-02). The rulebook's slot lines route on
    `qmcp-lead-pNN` alone (root exec, copy and firewall into the slot's
    members), so no failure part-way may leave that badge on a qube that has
    lost `qmcp-lead`: that is a principal the services refuse and the policy
    still serves."""

    def assert_no_bare_slot_badge(self):
        tags = self.tags(LEAD)
        self.assertFalse("qmcp-lead-p01" in tags and "qmcp-lead" not in tags, tags)

    def test_removing_a_lead_that_fails_between_the_badges(self):
        self.app.fail.add("tag.discard:qmcp-lead-p01")
        with self.assertRaises(Exception):
            fleet.remove_lead(self.app, "osint")
        self.assert_no_bare_slot_badge()

    def test_removing_a_lead_that_fails_on_the_last_badge(self):
        self.app.fail.add("tag.discard:qmcp-lead")
        with self.assertRaises(Exception):
            fleet.remove_lead(self.app, "osint")
        self.assert_no_bare_slot_badge()
        self.assertNotIn("qmcp-lead-p01", self.tags(LEAD))      # the routed badge went first

    def test_adding_puts_the_routed_badge_last(self):
        vm = self.app.domains["ai-work2"]
        self.app.fail.add("tag.add:qmcp-lead-p03")
        with self.assertRaises(Exception):
            fleet._set_tags(vm, add={"ai-managed", "qmcp-lead", "qmcp-lead-p03"})
        self.assertIn("qmcp-lead", self.tags("ai-work2"))
        self.assertNotIn("qmcp-lead-p03", self.tags("ai-work2"))


class RevokeAndTagOrder(ProjectBase):
    """From the M2b release gate (2026-10-02): `qmcp revoke` stripped badges in
    name order, so `ai-managed` went before `qmcp-proj-pNN`. A failure between
    the two left a qube outside AI space that its slot's lead still reaches
    through the rulebook. And `_set_tags` added before it removed."""

    def test_revoke_takes_the_slot_badge_first(self):
        self.app.fail.add("tag.discard:qmcp-proj-p01")
        with self.assertRaises(Exception):
            fleet.revoke(self.app, "ai-osint-w1", shutdown=False)
        tags = self.tags("ai-osint-w1")
        self.assertFalse("qmcp-proj-p01" in tags and "ai-managed" not in tags, tags)
        self.app.fail.clear()
        fleet.revoke(self.app, "ai-osint-w1", shutdown=False)
        self.assertFalse({t for t in self.tags("ai-osint-w1") if t.startswith(("qmcp-", "ai-"))})

    def test_a_change_of_slot_never_holds_both(self):
        vm = self.app.domains["ai-osint-w1"]
        self.app.fail.add("tag.discard:qmcp-proj-p01")
        with self.assertRaises(Exception):
            fleet._set_tags(vm, add={"qmcp-proj-p02"}, remove={"qmcp-proj-p01"})
        self.assertNotIn("qmcp-proj-p02", self.tags("ai-osint-w1"))   # removal comes first


class PromoteKeepsItsName(ProjectBase):
    """Found while testing the window, 2026-10-02: promoting one of the hub's
    qubes with --keep-old was refused whenever the old lead had the default
    name, with advice (--lead-name) a promotion cannot take: a promoted lead
    keeps its own name, so the default name never clashes."""

    def test_promote_with_keep_old(self):
        report = fleet.set_lead(self.app, "osint", "promote", "ai-work2", keep_old=True)
        self.assertIn("p01: lead ai-work2 (promoted)", report)
        self.assertEqual(projects.find(self.records(), "osint").lead, "ai-work2")
        self.assertIn("qmcp-proj-p01", self.tags(LEAD))

    def test_a_fresh_lead_still_needs_another_name(self):
        with self.assertRaises(fleet.ProjectError):
            fleet.set_lead(self.app, "osint", "template", "ai-debian-13", keep_old=True)


class HardwareFindings(ProjectBase):
    """Found on the development box (Qubes 4.3.1), 2026-10-01."""

    def test_the_create_lock_stays_group_writable_whoever_creates_it(self):
        # Created first by root (`qmcp project` under sudo) it came out 0600 on
        # the box, and every create by the (non-root) services then refused.
        pathlib.Path(budget.LOCK_PATH).unlink(missing_ok=True)
        old = os.umask(0o022)
        try:
            os.close(budget.acquire_create_lock())
        finally:
            os.umask(old)
        self.assertEqual(os.stat(budget.LOCK_PATH).st_mode & 0o777, 0o660)

    def test_check_fails_on_a_create_lock_the_services_cannot_write(self):
        lock = pathlib.Path(budget.LOCK_PATH)
        lock.touch()
        os.chmod(lock, 0o640)
        f = {x.check: x for x in fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["runtime dir"].status, "fail")
        self.assertIn("create.lock", f["runtime dir"].detail)

    def test_tmpfiles_declares_the_create_lock(self):
        conf = (HERE.parent / "deploy" / "qmcp-tmpfiles.conf").read_text().splitlines()
        rules = {tuple(line.split()[:5]) for line in conf if line and not line.startswith("#")}
        for kind in ("f", "z"):
            self.assertIn((kind, "/run/qmcp/create.lock", "0660", "root", "qubes"), rules)
        self.assertIn('LOCK_PATH = "/run/qmcp/create.lock"', (HERE.parent / "dom0" / "qmcp" / "budget.py").read_text())


if __name__ == "__main__":
    unittest.main()
