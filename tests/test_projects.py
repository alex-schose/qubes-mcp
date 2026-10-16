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
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, budget, core, fleet, inqube, projects, services  # noqa: E402
from fakequbes import GiB  # noqa: E402
from test_dom0 import HUB, Base  # noqa: E402
from qmcp import gateways  # noqa: E402

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

    def test_unreadable_records_refuse_leads_but_not_the_hubs_creates(self):
        # A lead is no principal without its record. The hub's creates no longer
        # read the records: its names are ai-hub-..., and `hub` is never a
        # project's label, so no project's space can hold one of them.
        pathlib.Path(projects.PROJECTS_PATH).write_text("{not json")
        self.assertEqual(self.lcall("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)
        self.assertTrue(self.call("qmcp.ListAIManagedQubes")["ok"])        # the hub still reads
        self.egress("ai-net-router")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-new", "template": "ai-debian-13"})
        self.assertEqual(r, {"ok": True, "name": "ai-hub-new"})

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
        self.assertEqual(hub["name_prefix"], "ai-hub-")          # the names its creates must carry
        self.assertEqual(hub["reserved_prefix"], "ai-")          # what a project's names build on
        self.assertNotIn("reserved_prefix", r)                    # a lead proposes nothing
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
        # The hub names only inside ai-hub-, so no project's space is reachable,
        # judged on the name alone.
        self.egress("ai-net-router")
        for name in ("ai-osint-x", "ai-other-y", "ai-osintx"):
            self.app.domains.lookups = 0
            r = self.call("qmcp.SpawnAIManagedQube", {"name": name, "template": "ai-debian-13"})
            self.assertIn("must start with 'ai-hub-'", r["error"])
            self.assertEqual(self.app.domains.lookups, 0)
            r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": name})
            self.assertIn("must start with 'ai-hub-'", r["error"])
        self.assertTrue(self.call("qmcp.SpawnAIManagedQube",
                                  {"name": "ai-hub-osintx", "template": "ai-debian-13"})["ok"])

    def test_what_the_hubs_creates_join(self):
        self.egress("ai-net-router")
        self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-app", "template": "ai-debian-13"})
        self.assertIn("qmcp-proj-p00", self.tags("ai-hub-app"))
        self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-mydvm", "template": "ai-debian-13",
                                             "klass": "DispVMTemplate"})
        self.assertFalse(projects.member_slots(self.tags("ai-hub-mydvm")))
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertFalse(projects.member_slots(self.tags(r["name"])))      # no p00 for disposables
        self.call("qmcp.CloneAIManagedQube", {"source": "ai-debian-13", "name": "ai-hub-tpl2"})
        self.assertFalse(projects.member_slots(self.tags("ai-hub-tpl2")))

    def test_the_hub_clones_a_lead_into_no_slot_without_its_role(self):
        # Project content never joins p00's dialog-free copies by a clone.
        r = self.call("qmcp.CloneAIManagedQube", {"source": LEAD, "name": "ai-hub-lead-copy"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.tags("ai-hub-lead-copy"), {"ai-managed", f"qmcp-owner_{HUB}"})

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
                                      quota="40G", lead_netvm="ai-net-router", dump=True,
                                      model="API.anthropic.com:443")
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
        # Model endpoint only: written into the lead, and what qubesd read
        # back is the record's accepted firewall.
        rules = ["action=accept dsthost=api.anthropic.com proto=tcp dstports=443-443",
                 "action=accept specialtarget=dns", "action=drop"]
        self.assertEqual(lead.__dict__["_firewall"], rules)
        self.assertEqual((p.model, list(p.lead_firewall)), ("api.anthropic.com:443", rules))
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
        # A promoted lead keeps its network, so it needs its model endpoint.
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"],
                                 quota=10 * GiB)
        self.assertIn("model endpoint", str(cm.exception))
        self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-proj-p00"})
        fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"], quota=10 * GiB,
                             model="api.example.org:8443")
        self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-lead", "qmcp-lead-p03"})
        self.assertEqual(self.app.domains["ai-hubq"].netvm.name, "ai-net-router")   # kept
        self.assertEqual(self.app.domains["ai-hubq"].__dict__["_firewall"][0],
                         "action=accept dsthost=api.example.org proto=tcp dstports=8443-8443")
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
            (dict(networks=["ai-work"]), "not an enrolled gateway"),
            (dict(networks=["ai-gw-unbadged"]), "not an enrolled gateway"),
            (dict(lead_netvm="ai-net-router"), "needs its model endpoint"),
            (dict(lead_netvm="ai-gw-unbadged", model="h.example:1"), "not an enrolled gateway"),
            (dict(model="h.example:1"), "no network reaches no model endpoint"),
            (dict(lead_netvm="ai-net-router", model="no-port"), "host:port"),
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
        self.app.domains["ai-work"].shutdown()     # a qube changes project only when shut down
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


class NetworkBeforeBadges(ProjectBase):
    """A fresh lead (from a template, a clone, a standalone copy) and a dump
    sink have their network and default disposable template set before the
    first badge lands, so no start between boots them on Qubes' defaults."""

    def test_a_new_lead_or_sink_has_its_network_before_its_first_badge(self):
        import fakequbes
        seen = {}
        real = fakequbes.FakeTags.add

        def add(tags, tag):
            vm = tags._vm
            if vm.name not in seen and tag in (core.UMBRELLA, "qmcp-lead", "ai-dump"):
                seen[vm.name] = (tag, vm._props.get("netvm"), vm.property_is_default("netvm"),
                                 vm.property_is_default("default_dispvm"))
            return real(tags, tag)
        fakequbes.FakeTags.add = add
        self.addCleanup(setattr, fakequbes.FakeTags, "add", real)
        router = self.app.domains["ai-net-router"]
        fleet.create_project(self.app, "fr", "template", "ai-debian-13", networks=["none"],
                             quota="10G", lead_netvm="ai-net-router", dump=True,
                             model="api.example.org:443")
        fleet.create_project(self.app, "st", "template", "ai-debian-13", networks=["none"],
                             quota="10G", lead_netvm="none", lead_class="standalone")
        fleet.create_project(self.app, "cl", "clone", "ai-hubq", networks=["none"],
                             quota="10G", lead_netvm="none")
        want = {"ai-fr-lead": router, "fr-dump": None, "ai-st-lead": None, "ai-cl-lead": None}
        for name, net in want.items():
            tag, got, net_default, dvm_default = seen[name]
            self.assertIs(got, net, (name, tag))
            self.assertFalse(net_default, f"{name} wore {tag} on the default netvm")
            self.assertFalse(dvm_default, f"{name} wore {tag} on the default disposable template")


class RunningQubesStay(ProjectBase):
    """A qube changes slot only when shut down: whatever runs in it would go on
    with the reach of the place it joins. It is never killed for this, since a
    kill loses what is being written; the command says to shut it down."""

    def power(self, name):
        return self.app.domains[name].get_power_state()

    def starting_on(self, badge):
        """`_set_tags`, which starts the qube once `badge` goes on: a start that
        lands while the command runs (the hub's command into it wakes it, and
        takes no lock)."""
        real = fleet._set_tags

        def set_tags(vm, add=(), remove=()):
            real(vm, add=add, remove=remove)
            if badge in set(add):
                vm.__dict__["_power"] = "Running"
        return mock.patch.object(fleet, "_set_tags", set_tags)

    def test_a_running_qube_is_neither_moved_across_slots_nor_killed(self):
        vm = self.app.domains["ai-osint-w2"]
        for state in ("Running", "Paused"):
            vm.__dict__["_power"] = state
            for target in ("p00", "none", "other"):
                with self.assertRaisesRegex(fleet.ProjectError, "only when shut down") as cm:
                    fleet.move(self.app, "ai-osint-w2", target, confirm=True)
                self.assertIn("qvm-shutdown ai-osint-w2", str(cm.exception))
                if state == "Paused":
                    self.assertIn("qvm-unpause ai-osint-w2, then", str(cm.exception))
                if target == "other":
                    self.assertIn("into other (p02)", str(cm.exception))
                self.assertEqual(projects.member_slots(self.tags("ai-osint-w2")), {"p01"})
                self.assertEqual(self.power("ai-osint-w2"), state)

    def test_a_power_state_that_does_not_read_refuses(self):
        self.app.domains["ai-osint-w2"].shutdown()
        self.app.fail_reads("power:ai-osint-w2", "fail")
        with self.assertRaisesRegex(fleet.ProjectError, "power state cannot be read"):
            fleet.move(self.app, "ai-osint-w2", "p00", confirm=True)
        self.assertEqual(projects.member_slots(self.tags("ai-osint-w2")), {"p01"})

    def test_a_shut_down_qube_moves(self):
        self.app.domains["ai-osint-w2"].shutdown()
        report = fleet.move(self.app, "ai-osint-w2", "p00", confirm=True)
        self.assertEqual(report.failed, [])
        self.assertEqual(projects.member_slots(self.tags("ai-osint-w2")), {"p00"})

    def test_between_p00_and_no_slot_a_running_qube_moves(self):
        # Both are the hub's own, so nothing crosses.
        self.app.domains["ai-hubq"].__dict__["_power"] = "Running"
        fleet.move(self.app, "ai-hubq", "none")
        self.assertEqual(projects.member_slots(self.tags("ai-hubq")), set())
        fleet.move(self.app, "ai-hubq", "p00")
        self.assertEqual(projects.member_slots(self.tags("ai-hubq")), {"p00"})
        self.assertEqual(self.power("ai-hubq"), "Running")

    def test_a_start_admitted_before_the_block_refuses_the_move(self):
        # A start admitted just before the move's qmcp-blocked (Qubes' pre-start
        # reads Halted) shows while the qube must stay Halted: nothing moves,
        # nothing is killed, and the block comes off again.
        self.app.domains["ai-osint-w2"].shutdown()
        with self.starting_on("qmcp-blocked"):
            with self.assertRaisesRegex(fleet.ProjectError, "only when shut down"):
                fleet.move(self.app, "ai-osint-w2", "p00", confirm=True)
        self.assertEqual(projects.member_slots(self.tags("ai-osint-w2")), {"p01"})
        self.assertNotIn("qmcp-blocked", self.tags("ai-osint-w2"))
        self.assertEqual(self.power("ai-osint-w2"), "Running")

    def test_the_block_is_on_from_before_the_badges_change_to_after(self):
        self.app.domains["ai-osint-w2"].shutdown()
        seen = []
        real = fleet._set_tags

        def set_tags(vm, add=(), remove=()):
            if vm.name == "ai-osint-w2" and {"qmcp-proj-p00", "qmcp-proj-p01"} & (set(add) | set(remove)):
                seen.append("qmcp-blocked" in vm.tags.raw())
            real(vm, add=add, remove=remove)
        with mock.patch.object(fleet, "_set_tags", set_tags):
            report = fleet.move(self.app, "ai-osint-w2", "p00", confirm=True)
        self.assertEqual(report.failed, [])
        self.assertTrue(seen and all(seen), seen)
        self.assertNotIn("qmcp-blocked", self.tags("ai-osint-w2"))
        # Between p00 and no slot nothing crosses, and no block is put on.
        seen.clear()
        self.app.domains["ai-hubq"].__dict__["_power"] = "Running"
        fleet.move(self.app, "ai-hubq", "none")
        self.assertNotIn("qmcp-blocked", self.tags("ai-hubq"))

    def test_a_start_during_the_move_undoes_it_and_kills_nothing(self):
        # Started after the badges changed, though no call could be admitted
        # (dom0 can start it): the move is undone to the badges it had.
        self.app.domains["ai-osint-w2"].shutdown()
        with self.starting_on("qmcp-proj-p00"):
            report = fleet.move(self.app, "ai-osint-w2", "p00", confirm=True)
        self.assertEqual(len(report.failed), 1)
        self.assertIn("the move was undone", report.failed[0])
        self.assertIn("qvm-shutdown ai-osint-w2", report.failed[0])
        self.assertEqual(projects.member_slots(self.tags("ai-osint-w2")), {"p01"})
        self.assertNotIn("qmcp-blocked", self.tags("ai-osint-w2"))
        self.assertEqual(self.power("ai-osint-w2"), "Running")

    def test_a_running_qube_is_not_promoted_and_the_old_lead_stays(self):
        self.app.domains["ai-hubq"].__dict__["_power"] = "Running"
        for promote in (lambda: fleet.set_lead(self.app, "osint", "promote", "ai-hubq"),
                        lambda: fleet.create_project(self.app, "prom", "promote", "ai-hubq",
                                                     networks=["none"], quota=10 * GiB,
                                                     model="api.example.org:8443")):
            with self.assertRaisesRegex(fleet.ProjectError, "only when shut down"):
                promote()
            self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-proj-p00"})
            self.assertEqual(self.records()["p01"].lead, LEAD)
            self.assertEqual(self.tags(LEAD), {"ai-managed", "qmcp-lead", "qmcp-lead-p01"})
            self.assertEqual(self.power("ai-hubq"), "Running")
        self.assertNotIn("prom", {p.label for p in self.records().values()})

    def test_a_start_during_a_lead_change_leaves_the_project_with_no_lead_and_says_so(self):
        # The plan refused nothing (the qube was down); the start landed after
        # the old lead went, so the project is left with no lead, never with a
        # lead running what the hub started.
        with self.starting_on("qmcp-lead-p01"):
            with self.assertRaises(fleet.ProjectError) as cm:
                fleet.set_lead(self.app, "osint", "promote", "ai-hubq", lead_netvm="none")
        self.assertIn("stays done", str(cm.exception))
        self.assertIn("give the project its lead again", str(cm.exception))
        self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-proj-p00"})
        self.assertIsNone(self.records()["p01"].lead)
        self.assertNotIn(LEAD, self.app.domains)        # the old lead was removed, as asked

    def test_a_start_during_a_promotion_gives_the_qube_back(self):
        with self.starting_on("qmcp-lead-p03"):
            with self.assertRaisesRegex(fleet.ProjectError, "started while it was made the lead"):
                fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"],
                                     quota=10 * GiB, model="api.example.org:8443")
        self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-proj-p00"})
        self.assertEqual(self.power("ai-hubq"), "Running")
        self.assertNotIn("prom", {p.label for p in self.records().values()})


class StrayLeadBadges(ProjectBase):
    """A qube wearing lead badges that no project's record names is no lead:
    revoke takes the badges off, and the advice never points at the lead the
    record does name."""

    def stray(self):
        self.app.domains["ai-hubq"].tags.add("qmcp-lead")
        self.app.domains["ai-hubq"].tags.add("qmcp-lead-p01")
        return "ai-hubq"

    def test_revoke_takes_a_stray_lead_badge_off_and_the_real_lead_stays(self):
        name = self.stray()
        self.assertIn("qmcp revoke ai-hubq", " ".join(
            f.detail for f in fleet.project_findings(list(self.app.domains),
                                                     {v.name: v for v in self.app.domains},
                                                     self.records(), "ai-")
            if f.check == "leads"))
        fleet.revoke(self.app, name)
        self.assertFalse({"qmcp-lead", "qmcp-lead-p01"} & self.tags(name))
        self.assertEqual(self.records()["p01"].lead, LEAD)
        self.assertEqual(self.tags(LEAD), {"ai-managed", "qmcp-lead", "qmcp-lead-p01"})

    def test_guard_and_open_refuse_a_stray_and_point_at_revoke(self):
        name = self.stray()
        for action in (fleet.guard, lambda app, n: fleet.open_window(app, n, 600)):
            with self.assertRaises(fleet.RoleError) as cm:
                action(self.app, name)
            self.assertIn(f"qmcp revoke {name}", str(cm.exception))
            self.assertNotIn("--remove", str(cm.exception))

    def test_the_recorded_lead_is_refused_by_its_projects_name(self):
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, LEAD)
        self.assertIn("qmcp project lead osint --remove", str(cm.exception))

    def test_unread_records_let_revoke_go_on_and_refuse_guard(self):
        name = self.stray()
        pathlib.Path(projects.PROJECTS_PATH).write_text("{bad")
        with self.assertRaisesRegex(fleet.RoleError, "records do not read"):
            fleet.guard(self.app, name)
        fleet.revoke(self.app, name)
        self.assertFalse({"qmcp-lead", "qmcp-lead-p01"} & self.tags(name))


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

    # Validate before taking anything away
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

    # Authority is current when the work is done
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

    # A kept lead joins on a listed network, or on none
    def test_a_kept_lead_off_the_list_loses_its_network(self):
        self.app.domains[OTHER_LEAD]._props["netvm"] = self.app.domains["ai-net-router"]
        report = fleet.set_lead(self.app, "other", "template", "ai-debian-13", lead_netvm="none",
                                keep_old=True, lead_name="ai-other-lead2")
        self.assertIsNone(self.app.domains[OTHER_LEAD].netvm)
        self.assertEqual(projects.member_slots(self.tags(OTHER_LEAD)), {"p02"})
        self.assertEqual(projects.find(self.records(), "other").networks, (None,))
        self.assertTrue(any("lost its network" in line for line in report), report)

    def test_a_kept_lead_keeps_a_network_the_tick_adds(self):
        self.app.domains[OTHER_LEAD]._props["netvm"] = self.app.domains["ai-net-router"]
        fleet.set_lead(self.app, "other", "template", "ai-debian-13", lead_netvm="none",
                       keep_old=True, lead_name="ai-other-lead2", add_old_network=True)
        self.assertEqual(self.app.domains[OTHER_LEAD].netvm.name, "ai-net-router")
        self.assertEqual(projects.find(self.records(), "other").networks, (None, "ai-net-router"))
        # Without keep_old the tick means nothing, and is refused.
        with self.assertRaises(fleet.RoleError):
            fleet.set_lead(self.app, "other", "template", "ai-debian-13", lead_netvm="none",
                           lead_name="ai-other-lead3", add_old_network=True)

    def test_a_kept_lead_on_an_unenrolled_network_cannot_be_added(self):
        self.app.domains[OTHER_LEAD]._props["netvm"] = self.app.domains["ai-gw-unbadged"]
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead(self.app, "other", "template", "ai-debian-13", lead_netvm="none",
                           keep_old=True, lead_name="ai-other-lead2", add_old_network=True)
        self.assertIn("not an enrolled gateway", str(cm.exception))
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

    def test_a_clone_lands_where_its_source_is(self):
        # A project member's clone joins that project, in its name space; a
        # lead's clone joins no slot; a p00 qube's joins p00, and one in no
        # slot (ai-work2) joins none.
        for source, name, want in (("ai-osint-w1", "ai-osint-hc1", {"p01"}),
                                   (LEAD, "ai-hub-c-lead", set()),
                                   ("ai-hubq", "ai-hub-c-hubq", {"p00"}),
                                   ("ai-work2", "ai-hub-c-ork2", set())):
            r = self.call("qmcp.CloneAIManagedQube", {"source": source, "name": name})
            self.assertTrue(r["ok"], (source, r))
            self.assertEqual(projects.member_slots(self.tags(name)), want, source)
        self.assertNotIn(projects.LEAD, self.tags("ai-hub-c-lead"))

    def test_the_hubs_clone_of_a_member_is_named_in_its_project(self):
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1", "name": "ai-hub-c1"})
        self.assertEqual(r["error"], "name must start with 'ai-osint-': that namespace is "
                                     "reserved for AI-created qubes")
        self.assertNotIn("ai-hub-c1", self.app.domains)

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
        self.assertTrue(any("not demoted or killed" in line for line in report), report)

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
        # A network a member still sits on stays on the list.
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.edit_project(self.app, "osint", networks=["none"])
        self.assertIn("ai-osint-w1 on ai-net-router", str(cm.exception))
        self.assertEqual(projects.find(self.records(), "osint").networks, ("ai-net-router", None))
        self.app.domains["ai-osint-w1"].netvm = None
        fleet.edit_project(self.app, "osint", templates=["ai-debian-13"], networks=["none"], quota="30G")
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.templates, p.networks, p.quota), (("ai-debian-13",), (None,), 30 * GiB))
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
                                                            self.records(), "ai-", gateways.load())}

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

    def test_check_fails_on_a_create_turnstile_the_services_cannot_write(self):
        turn = pathlib.Path(core.queue_path(str(budget.LOCK_PATH)))
        turn.touch()
        os.chmod(turn, 0o640)
        f = {x.check: x for x in fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["runtime dir"].status, "fail")
        self.assertIn("create.queue", f["runtime dir"].detail)

    def test_tmpfiles_declares_the_create_lock(self):
        conf = (HERE.parent / "deploy" / "qmcp-tmpfiles.conf").read_text().splitlines()
        rules = {tuple(line.split()[:5]) for line in conf if line and not line.startswith("#")}
        for kind in ("f", "z"):
            self.assertIn((kind, "/run/qmcp/create.lock", "0660", "root", "qubes"), rules)
            # and its turnstile, which every create passes through first
            self.assertIn((kind, "/run/qmcp/create.queue", "0660", "root", "qubes"), rules)
        self.assertIn('LOCK_PATH = "/run/qmcp/create.lock"', (HERE.parent / "dom0" / "qmcp" / "budget.py").read_text())



# ======================================================================= standalones (0.9.27)

class Standalones(ProjectBase):
    """A StandaloneVM as a project's worker or lead: spawned or cloned by its
    lead, made the lead from a template, promoted or cloned from one of the
    hub's, and moved in by the operator."""

    def setUp(self):
        super().setUp()
        a = self.app
        a.domains["ai-debian-13"].volumes["root"].size = 10 * GiB
        a.vm("ai-hub-sa", klass="StandaloneVM", netvm=None, root=8 * GiB,
             tags={"ai-managed", "qmcp-proj-p00"})
        a.vm("ai-hub-sb", klass="StandaloneVM", netvm=None, root=8 * GiB, tags={"ai-managed"})

    def spawn(self, name, klass="StandaloneVM", template="ai-debian-13", **req):
        return self.lcall("qmcp.SpawnAIManagedQube",
                          dict(req, name=name, template=template, klass=klass, netvm=None))

    def test_a_lead_spawns_a_standalone_worker(self):
        r = self.spawn("ai-osint-sa")
        self.assertEqual(r, {"ok": True, "name": "ai-osint-sa"})
        vm = self.app.domains["ai-osint-sa"]
        self.assertEqual(vm.klass, "StandaloneVM")
        self.assertEqual(self.tags("ai-osint-sa"), {"ai-managed", "qmcp-proj-p01",
                                                    f"qmcp-owner_{LEAD}"})
        self.assertEqual(vm.volumes["root"].size, 10 * GiB)

    def test_its_root_counts_against_the_quota(self):
        # 20 GiB quota; the two workers hold 4. A standalone holds 12 (its own
        # 10 GiB root and a 2 GiB private), so a second one is over.
        self.assertTrue(self.spawn("ai-osint-sa")["ok"])
        self.assertEqual(self.spawn("ai-osint-sb")["error"], budget.ERR_QUOTA_EXCEEDED)
        self.assertNotIn("ai-osint-sb", self.app.domains)
        self.assertTrue(self.spawn("ai-osint-ab", klass="AppVM")["ok"])

    def test_only_from_an_approved_template(self):
        r = self.spawn("ai-osint-sa", template="ai-tpl-g")
        self.assertEqual(r["error"], "template is not on this project's approved list")

    def test_a_lead_clones_its_standalone_worker(self):
        self.assertTrue(self.spawn("ai-osint-sa")["ok"])
        r = self.lcall("qmcp.CloneAIManagedQube", {"source": "ai-osint-sa", "name": "ai-osint-sc"})
        self.assertEqual(r["error"], budget.ERR_QUOTA_EXCEEDED)         # 4 + 12 + 12 > 20
        rec = json.loads(json.dumps(RECORDS))
        rec["slots"]["p01"]["quota"] = 40 * GiB
        self.write_records(rec)
        r = self.lcall("qmcp.CloneAIManagedQube", {"source": "ai-osint-sa", "name": "ai-osint-sc"})
        self.assertEqual(r, {"ok": True, "name": "ai-osint-sc"})
        self.assertEqual(self.app.domains["ai-osint-sc"].klass, "StandaloneVM")
        self.assertIn("qmcp-proj-p01", self.tags("ai-osint-sc"))

    def test_the_hubs_clone_of_a_member_counts_against_its_project(self):
        self.assertTrue(self.spawn("ai-osint-sa")["ok"])
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-osint-sa", "name": "ai-osint-hc"})
        self.assertEqual(r["error"], budget.ERR_QUOTA_EXCEEDED)
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1", "name": "ai-osint-hc"})
        self.assertEqual(r, {"ok": True, "name": "ai-osint-hc"})
        self.assertEqual(projects.member_slots(self.tags("ai-osint-hc")), {"p01"})

    def test_a_standalone_lead_from_a_template(self):
        fleet.create_project(self.app, "tools", "template", "ai-debian-13", networks=["none"],
                             quota="40G", lead_class="standalone")
        p = projects.find(self.records(), "tools")
        vm = self.app.domains[p.lead]
        self.assertEqual(vm.klass, "StandaloneVM")
        self.assertEqual(vm.volumes["root"].size, 10 * GiB)
        self.assertEqual(self.tags(p.lead), {"ai-managed", "qmcp-lead", f"qmcp-lead-{p.slot}",
                                             "qmcp-owner_dom0"})
        self.assertEqual(p.templates, ("ai-debian-13",))
        self.assertTrue(self.lcall("qmcp.ListAIManagedQubes", lead=p.lead)["ok"])

    def test_a_standalone_lead_comes_from_a_template_only(self):
        for source, origin in (("clone", "ai-hub-sa"), ("promote", "ai-hub-sa")):
            with self.assertRaisesRegex(fleet.ProjectError, "keeps the class", msg=source):
                fleet.create_project(self.app, "tools", source, origin, networks=["none"],
                                     quota="1G", lead_class="standalone")
        with self.assertRaisesRegex(fleet.ProjectError, "one of: appvm, standalone"):
            fleet.create_project(self.app, "tools", "template", "ai-debian-13",
                                 networks=["none"], quota="1G", lead_class="hvm")
        self.assertIsNone(projects.find(self.records(), "tools"))

    def test_a_hub_standalone_is_promoted_or_cloned_into_a_lead(self):
        # A standalone has no template to join the approved list: name one.
        with self.assertRaisesRegex(fleet.ProjectError, "at least one approved template"):
            fleet.create_project(self.app, "prom", "promote", "ai-hub-sa", networks=["none"],
                                 quota="1G")
        fleet.create_project(self.app, "prom", "promote", "ai-hub-sa", networks=["none"],
                             quota="1G", templates=["ai-debian-13"])
        self.assertEqual(projects.find(self.records(), "prom").lead, "ai-hub-sa")
        self.assertEqual(self.app.domains["ai-hub-sa"].klass, "StandaloneVM")
        self.assertNotIn("qmcp-proj-p00", self.tags("ai-hub-sa"))
        fleet.create_project(self.app, "clon", "clone", "ai-hub-sb", networks=["none"],
                             quota="1G", templates=["ai-debian-13"])
        lead = projects.find(self.records(), "clon").lead
        self.assertEqual(lead, "ai-clon-lead")
        self.assertEqual(self.app.domains[lead].klass, "StandaloneVM")
        self.assertEqual(self.app.domains[lead].volumes["root"].size, 8 * GiB)

    def test_a_new_standalone_lead(self):
        fleet.set_lead(self.app, "osint", "template", "ai-debian-13", keep_old=True,
                       lead_name="ai-osint-boss", lead_class="standalone")
        self.assertEqual(projects.find(self.records(), "osint").lead, "ai-osint-boss")
        self.assertEqual(self.app.domains["ai-osint-boss"].klass, "StandaloneVM")
        self.assertIn("qmcp-proj-p01", self.tags(LEAD))          # the old one, kept as a worker

    def test_the_operator_moves_a_standalone_in(self):
        fleet.move(self.app, "ai-hub-sb", "osint", confirm=True)
        self.assertEqual(projects.member_slots(self.tags("ai-hub-sb")), {"p01"})
        fleet.move(self.app, "ai-hub-sb", "none", confirm=True)
        self.assertEqual(projects.member_slots(self.tags("ai-hub-sb")), set())

    def test_the_check_warns_on_a_standalone_in_no_slot(self):
        vms = list(self.app.domains)
        f = {x.check: x for x in fleet.project_findings(vms, {v.name: v for v in vms},
                                                         self.records(), "ai-")}
        self.assertIn("ai-hub-sb", f["managed qubes in no slot"].detail)
        self.assertNotIn("ai-hub-sa", f["managed qubes in no slot"].detail)

    def test_a_clone_keeps_its_source_s_template(self):
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1", "name": "ai-osint-ct"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.app.domains["ai-osint-ct"].template.name, "ai-debian-13")

    def test_a_source_that_moved_while_the_clone_waited_is_refused(self):
        # The slot a clone lands in is read before the create lock and again
        # under it: a project command in between must not land it elsewhere.
        real = budget.acquire_create_lock

        def moving(*a, **kw):
            fd = real(*a, **kw)
            src = self.app.domains["ai-osint-w1"]
            src.tags.discard("qmcp-proj-p01")
            src.tags.add("qmcp-proj-p00")
            return fd
        budget.acquire_create_lock = moving
        try:
            r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1",
                                                       "name": "ai-osint-cm"})
        finally:
            budget.acquire_create_lock = real
        self.assertEqual(r["error"], "the source moved while this call waited; try again")
        self.assertNotIn("ai-osint-cm", self.app.domains)

    def test_a_standalone_lead_from_a_running_template_reads_behind(self):
        tpl = self.app.domains["ai-debian-13"]
        dict.__setitem__(tpl.features, "qmcp-services", "sha256:v1")
        tpl.start()
        fleet.create_project(self.app, "tools", "template", "ai-debian-13", networks=["none"],
                             quota="40G", lead_class="standalone")
        lead = projects.find(self.records(), "tools").lead
        self.assertEqual(dict.__getitem__(self.app.domains[lead].features, "qmcp-services"),
                         inqube.UNKNOWN)

    def test_the_command_takes_lead_class(self):
        import contextlib
        from qmcp import cli
        saved = cli._app, os.geteuid
        cli._app, os.geteuid = (lambda: self.app), (lambda: 0)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                rc = cli.main(["project", "create", "tools", "--lead-template", "ai-debian-13",
                               "--lead-class", "standalone", "--network", "none",
                               "--quota", "40G"])
                self.assertEqual(rc, 0, out.getvalue())
                self.assertEqual(self.app.domains["ai-tools-lead"].klass, "StandaloneVM")
                rc = cli.main(["project", "lead", "tools", "--lead-template", "ai-debian-13",
                               "--lead-class", "standalone", "--lead-name", "ai-tools-boss"])
                self.assertEqual(rc, 0, out.getvalue())
                rc = cli.main(["project", "create", "toolc", "--lead-clone", "ai-hub-sb",
                               "--lead-class", "standalone", "--network", "none",
                               "--quota", "1G"])
        finally:
            cli._app, os.geteuid = saved
        self.assertEqual(rc, 1, out.getvalue())
        self.assertIn("keeps the class", out.getvalue())
        self.assertEqual(self.app.domains["ai-tools-boss"].klass, "StandaloneVM")


class CopyRechecks(ProjectBase):
    """What a copy checks under the create lock (0.9.27's audit): its source
    and the template it builds on are read again there, as a spawn's are."""

    def waiting(self, change):
        """Run `change` once the call holds the create lock."""
        real = budget.acquire_create_lock

        def taken(*a, **kw):
            fd = real(*a, **kw)
            change()
            return fd
        budget.acquire_create_lock = taken
        self.addCleanup(setattr, budget, "acquire_create_lock", real)

    def clone(self, source, name, lead=None):
        req = {"source": source, "name": name}
        return self.lcall("qmcp.CloneAIManagedQube", req, lead=lead) if lead \
            else self.call("qmcp.CloneAIManagedQube", req)

    def test_a_lead_from_a_whonix_template_keeps_anon_vm(self):
        self.app.domains["ai-debian-13"].tags.add("anon-vm")
        for cls, label in (("standalone", "tools"), ("appvm", "toolb")):
            fleet.create_project(self.app, label, "template", "ai-debian-13",
                                 networks=["none"], quota="40G", lead_class=cls)
            lead = projects.find(self.records(), label).lead
            self.assertIn("anon-vm", self.tags(lead), cls)

    def test_a_clone_on_a_stopped_or_held_template_is_refused(self):
        tpl = self.app.domains["ai-debian-13"]
        tpl.tags.add("qmcp-blocked")
        self.assertEqual(self.clone("ai-hubq", "ai-hub-c1"), core.BLOCKED_REFUSAL)
        tpl.tags.discard("qmcp-blocked")
        dict.__setitem__(tpl.features, "qmcp-id", "another-uuid")      # not held yet
        self.assertEqual(self.clone("ai-hubq", "ai-hub-c1"), core.QUARANTINE_REFUSAL)
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-s1", "template": "ai-debian-13",
                                                  "klass": "StandaloneVM", "netvm": None})
        self.assertEqual(r, core.QUARANTINE_REFUSAL)
        self.assertNotIn("ai-hub-c1", self.app.domains)

    def test_a_lead_clones_only_on_an_approved_template(self):
        rec = json.loads(json.dumps(RECORDS))
        rec["slots"]["p01"]["templates"] = ["ai-dvm"]
        self.write_records(rec)
        r = self.clone("ai-osint-w1", "ai-osint-c1", lead=LEAD)
        self.assertEqual(r["error"], "the source's template is not on this project's approved list")

    def test_a_restored_source_not_yet_held_is_not_copied(self):
        dict.__setitem__(self.app.domains["ai-osint-w1"].features, "qmcp-id", "another-uuid")
        self.assertEqual(self.clone("ai-osint-w1", "ai-osint-c1"), core.QUARANTINE_REFUSAL)
        self.assertEqual(self.clone("ai-osint-w1", "ai-osint-c2", lead=LEAD),
                         core.QUARANTINE_REFUSAL)
        a = self.app
        a.vm("ai-hub-sx", klass="StandaloneVM", netvm=None, tags={"ai-managed"},
             features={"qmcp-id": "another-uuid"})
        with self.assertRaisesRegex(fleet.ProjectError, "waits for your review"):
            fleet.create_project(a, "tools", "clone", "ai-hub-sx", networks=["none"],
                                 quota="1G", templates=["ai-debian-13"])
        dict.__setitem__(a.domains["ai-debian-13"].features, "qmcp-id", "another-uuid")
        with self.assertRaisesRegex(fleet.ProjectError, "waits for your review"):
            fleet.create_project(a, "toolb", "template", "ai-debian-13", networks=["none"],
                                 quota="1G", lead_class="standalone")

    def test_a_lead_s_source_that_left_its_project_meanwhile(self):
        def move():
            w = self.app.domains["ai-osint-w1"]
            w.tags.discard("qmcp-proj-p01")
            w.tags.add("qmcp-proj-p02")
        self.waiting(move)
        self.assertEqual(self.clone("ai-osint-w1", "ai-osint-c1", lead=LEAD), core.NOT_FOUND)
        self.assertNotIn("ai-osint-c1", self.app.domains)

    def test_a_source_stopped_or_held_meanwhile(self):
        for badge, want in (("qmcp-blocked", core.BLOCKED_REFUSAL),
                            ("qmcp-quarantine", core.QUARANTINE_REFUSAL)):
            w = self.app.domains["ai-osint-w1"]
            self.waiting(lambda: w.tags.add(badge))
            self.assertEqual(self.clone("ai-osint-w1", "ai-osint-c1"), want, badge)
            w.tags.discard(badge)
            self.assertNotIn("ai-osint-c1", self.app.domains)

    def test_the_project_record_read_under_the_lock_decides(self):
        def shrink():
            rec = json.loads(json.dumps(RECORDS))
            rec["slots"]["p01"]["quota"] = GiB
            self.write_records(rec)
        self.waiting(shrink)
        r = self.clone("ai-osint-w1", "ai-osint-c1")
        self.assertEqual(r["error"], budget.ERR_QUOTA_EXCEEDED)

    def test_a_hidden_project_s_member_answers_as_missing(self):
        rec = json.loads(json.dumps(RECORDS))
        rec["slots"]["p03"] = {"label": "x7k2m9qa", "lead": None, "templates": ["ai-debian-13"],
                               "networks": [None], "quota": 10 * GiB, "dump": None,
                               "anonymous": True, "hidden": True}
        self.write_records(rec)
        # It lost its hidden badge (the check fails on that), not its slot's.
        self.app.vm("ai-x7k2m9qa-w1", template=self.app.domains["ai-debian-13"], netvm=None,
                    tags={"ai-managed", "qmcp-proj-p03", "qmcp-anon"})
        for name in ("ai-hub-zz", "ai-x7k2m9qa-c"):
            r = self.clone("ai-x7k2m9qa-w1", name)
            self.assertEqual(r, core.NOT_FOUND, name)
            self.assertNotIn("x7k2m9qa", json.dumps(r))

    def test_the_hub_s_clone_stays_on_the_project_s_networks(self):
        self.app.domains["ai-osint-w2"]._props["netvm"] = self.app.domains["ai-gw-unbadged"]
        self.enroll("ai-gw-unbadged")
        r = self.clone("ai-osint-w2", "ai-osint-c1")
        self.assertEqual(r["error"], "the source's network is not one of this project's "
                                     "worker networks")

    def test_a_disposable_template_s_clone_does_not_preload(self):
        dvm = self.app.domains["ai-dvm"]
        dict.__setitem__(dvm.features, "preload-dispvm-max", "2")
        self.assertTrue(self.clone("ai-dvm", "ai-hub-dvm2")["ok"])
        self.assertNotIn("preload-dispvm-max", dict.keys(self.app.domains["ai-hub-dvm2"].features))

    def test_a_property_the_copy_s_class_lacks_is_skipped(self):
        self.app.domains["ai-hubq"]._props["only_on_source"] = 1
        self.assertTrue(self.clone("ai-hubq", "ai-hub-c1")["ok"])



class LeadChangesWaitForCalls(ProjectBase):
    """A lead's removal or change waits for the lead's calls that are past
    their check (its acting lock), and runs under the lead's own lock, as a
    revoke does; a promotion holds the promoted qube's lock throughout."""

    def setUp(self):
        super().setUp()
        core.OPERATOR_WAIT_S = 5.0

    def in_thread(self, fn):
        out = {}
        t = threading.Thread(target=lambda: out.setdefault("r", fn()), daemon=True)
        t.start()
        self.addCleanup(t.join, 10)
        return t, out

    def test_a_project_command_gets_the_create_lock_from_a_busy_creator(self):
        # The project commands queue in the create lock's turnstile.
        budget.LOCK_TIMEOUT_S = 3.0
        stop = threading.Event()

        def creator():
            while not stop.is_set():
                try:
                    fd = budget.acquire_create_lock(timeout=5)
                except core.Refusal:
                    continue
                time.sleep(0.03)
                os.close(fd)
        t = threading.Thread(target=creator, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(stop.set)
        time.sleep(0.1)
        fleet.edit_project(self.app, "osint", quota=7 * GiB)
        stop.set()
        self.assertEqual(projects.find(self.records(), "osint").quota, 7 * GiB)

    def test_a_lead_call_past_its_check_lands_before_the_lead_is_removed(self):
        call = core.hold_acting(LEAD)                     # a call of the lead's, past its check
        t, _ = self.in_thread(lambda: fleet.remove_lead(self.app, "osint"))
        time.sleep(0.3)
        self.assertIn("qmcp-lead-p01", self.tags(LEAD))    # the removal waits for the call
        os.close(call)
        t.join(10)
        self.assertIsNone(projects.find(self.records(), "osint").lead)
        self.assertNotIn(LEAD, self.app.domains)

    def test_a_project_delete_waits_for_the_leads_call_too(self):
        call = core.hold_acting(LEAD)
        t, _ = self.in_thread(lambda: fleet.delete_project(self.app, "osint"))
        time.sleep(0.3)
        self.assertIn("ai-osint-w1", self.app.domains)       # nothing removed yet
        self.assertIn("qmcp-lead-p01", self.tags(LEAD))
        os.close(call)
        t.join(10)
        self.assertNotIn("ai-osint-w1", self.app.domains)
        self.assertIsNone(projects.find(self.records(), "osint"))

    def test_a_lead_cannot_starve_the_drain_by_overlapping_its_calls(self):
        # Two of the lead's calls, staggered, keep the acting lock shared at
        # every moment; the drain waits in its turnstile, so each new call
        # waits behind it and it is had within about one call's length.
        stop = threading.Event()

        def calls(offset):
            time.sleep(offset)
            while not stop.is_set():
                try:
                    fd = core.hold_acting(LEAD, 5)
                except core.Refusal:
                    continue
                time.sleep(0.2)
                os.close(fd)
        workers = [threading.Thread(target=calls, args=(i * 0.1,), daemon=True)
                   for i in range(2)]
        for w in workers:
            w.start()
            self.addCleanup(w.join, 5)
        self.addCleanup(stop.set)
        time.sleep(0.3)
        t0 = time.monotonic()
        fd = core.drain_caller(LEAD, 3.0)
        waited = time.monotonic() - t0
        stop.set()
        self.assertIsNotNone(fd, "the lead's overlapping calls starved the drain")
        os.close(fd)
        self.assertLess(waited, 1.0)

    def test_a_lead_call_reaching_its_check_meanwhile_is_refused(self):
        drain = core.drain_caller(LEAD, 1)                # the removal holds it
        req = {"name": "ai-osint-w1", "property": "memory", "value": 600}
        t, out = self.in_thread(lambda: self.lcall("qmcp.SetPropertyAIManaged", req))
        time.sleep(0.3)
        doc = json.loads(json.dumps(RECORDS))
        doc["slots"]["p01"]["lead"] = None
        self.write_records(doc)
        self.app.domains[LEAD].tags.discard("qmcp-lead-p01")
        os.close(drain)
        t.join(10)
        self.assertEqual(out["r"], core.NOT_AUTHORIZED)
        self.assertNotEqual(self.app.domains["ai-osint-w1"].memory, 600)

    def test_a_removal_that_waited_past_the_wait_says_so(self):
        core.OPERATOR_WAIT_S = 0.3
        call = core.hold_acting(LEAD)
        self.addCleanup(os.close, call)
        report = fleet.remove_lead(self.app, "osint")
        self.assertTrue(any("was still running after" in line for line in report), report)
        self.assertIsNone(projects.find(self.records(), "osint").lead)

    def test_a_create_that_promotes_refuses_while_a_call_holds_that_qube(self):
        core.OPERATOR_WAIT_S = 0.3
        held = core.acquire_qube_lock("ai-work2", 1)
        self.addCleanup(os.close, held)
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.create_project(self.app, "newp", "promote", "ai-work2",
                                 templates=["ai-debian-13"])
        self.assertIn("is being changed", str(cm.exception))
        self.assertIsNone(projects.find(self.records(), "newp"))
        self.assertNotIn("qmcp-lead", self.tags("ai-work2"))

    def test_a_drain_that_cannot_open_its_lock_says_so(self):
        real = core.drain_caller
        core.drain_caller = lambda *a, **k: (_ for _ in ()).throw(PermissionError("x"))
        self.addCleanup(setattr, core, "drain_caller", real)
        report = fleet.remove_lead(self.app, "osint")
        self.assertTrue(any("acting lock could not be opened" in l for l in report), report)
        self.assertFalse(any("was still running" in l for l in report), report)

    def test_a_promotion_refuses_while_a_call_holds_the_promoted_qube(self):
        core.OPERATOR_WAIT_S = 0.3
        held = core.acquire_qube_lock("ai-work2", 1)
        self.addCleanup(os.close, held)
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.set_lead(self.app, "osint", "promote", "ai-work2", keep_old=True)
        self.assertIn("is being changed", str(cm.exception))
        self.assertEqual(projects.find(self.records(), "osint").lead, LEAD)
        self.assertIn("qmcp-lead-p01", self.tags(LEAD))
        self.assertNotIn("qmcp-lead", self.tags("ai-work2"))

    def test_a_start_of_the_old_lead_that_landed_after_its_kill_is_killed_again(self):
        real, asked = core.acquire_qube_lock, []

        def acquire(name, timeout=None, **kw):
            if name == LEAD:
                asked.append(name)
                if len(asked) == 1:
                    return None                         # a call of the hub's holds it
                if len(asked) == 2:
                    self.app.domains[LEAD].start()      # ... and its start lands
            return real(name, timeout, **kw)
        core.acquire_qube_lock = acquire
        self.addCleanup(setattr, core, "acquire_qube_lock", real)
        report = fleet.set_lead(self.app, "osint", "promote", "ai-work2", keep_old=True)
        self.assertEqual(len(asked), 2)
        self.assertEqual(self.app.domains[LEAD].get_power_state(), "Halted")
        self.assertTrue(any("killed again" in line for line in report), report)
        self.assertIn("qmcp-proj-p01", self.tags(LEAD))

if __name__ == "__main__":
    unittest.main()
