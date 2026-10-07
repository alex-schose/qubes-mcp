"""Offline suite for M3b: self-hosted model qubes and the leads' model endpoints,
against tests/fakequbes.py.

Each expectation below is the design's, written down before the code was read
for what it does:

- A project's model is a remote endpoint or a self-hosted model qube, never
  both. A lead whose model is a qube has no network.
- A model qube wears `qmcp-model-pNN`, one per slot it serves, is guarded,
  has no network, sits in no slot, and runs on no template the hub manages.
  The lead reaches it on port 11434; the rulebook routes on the badge, so a
  badge anywhere else is a failure of `qmcp check`, and every command that
  makes or unmakes one changes authority in the order that fails toward less.
- A model qube may serve several projects; that is a path between them, and
  the command says so.
- An endpoint given as an address gets no DNS rule; a lead set before keeps
  the rules the operator accepted, and `qmcp check` warns.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import core, firewall, fleet, projects, proposals, scope  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_projects import LEAD, OTHER_LEAD, ProjectBase  # noqa: E402

MODEL = "ai-hub-model"
BADGE1, BADGE2 = projects.model_badge("p01"), projects.model_badge("p02")


def findings(app, **kw):
    return {f"{f.status}:{f.check}": f for f in fleet.check(app, legacy_paths=(),
                                                            system_info={"domains": {}}, **kw)}


class ModelBase(ProjectBase):
    """The project fleet, plus a qube the hub set up to serve a model: in p00,
    on the hub's router, on a template outside AI space."""

    def setUp(self):
        super().setUp()
        a = self.app
        a.vm(MODEL, template=a.domains["debian-13"], netvm=a.domains["ai-net-router"],
             power="Running", tags={"ai-managed", "qmcp-proj-p00", "qmcp-owner_mcp-control"})

    def raw(self, name):
        return self.app.domains[name].tags.raw()

    def netvm(self, name):
        ref = self.app.domains[name]._props["netvm"]
        return None if ref is None else ref.name

    def record(self, key="osint"):
        return projects.find(projects.load(), key)

    def state(self):
        """Everything a model-qube command may change, for before/after."""
        return ({n: frozenset(self.raw(n)) for n in (MODEL, LEAD, OTHER_LEAD, "ai-osint-w1")},
                {n: self.netvm(n) for n in (MODEL, LEAD)},
                pathlib.Path(projects.PROJECTS_PATH).read_text())

    def model_findings(self):
        return {k: f.detail for k, f in findings(self.app).items() if k.endswith(":model qubes")}


# ======================================================================= 191, 196: the endpoint's rules

class EndpointRules(ModelBase):
    def test_an_address_gets_no_dns_rule_and_a_name_does(self):
        self.assertEqual(firewall.endpoint_rules("192.0.2.5:11434"),
                         ["action=accept proto=tcp dsthost=192.0.2.5 dstports=11434", "action=drop"])
        self.assertEqual(firewall.endpoint_rules("api.anthropic.com:443"),
                         ["action=accept proto=tcp dsthost=api.anthropic.com dstports=443",
                          "action=accept specialtarget=dns", "action=drop"])
        # A name made of digits that is no address is looked up, so it keeps DNS.
        self.assertIn("action=accept specialtarget=dns", firewall.endpoint_rules("1.2.3:443"))

    def test_a_lead_given_an_address_has_no_dns_live_and_on_record(self):
        report = fleet.set_lead_firewall(self.app, "osint", model="192.0.2.5:443")
        live = self.app.domains[LEAD].__dict__["_firewall"]
        self.assertEqual(live, ["action=accept dst4=192.0.2.5/32 proto=tcp dstports=443-443",
                                "action=drop"])
        self.assertEqual(list(self.record().lead_firewall), live)
        self.assertIn("192.0.2.5:443", report[-1])
        self.assertNotIn("lead DNS", " ".join(findings(self.app)))

    def test_a_create_says_what_the_lead_may_reach(self):
        report = fleet.create_project(self.app, "addr", "template", "ai-debian-13", (),
                                      ["ai-net-router"], "1G", "ai-net-router", False, None,
                                      "192.0.2.5:443")
        self.assertIn("firewall: 192.0.2.5:443 only", report[0])
        report = fleet.create_project(self.app, "name", "template", "ai-debian-13", (),
                                      ["ai-net-router"], "1G", "ai-net-router", False, None,
                                      "api.anthropic.com:443")
        self.assertIn("firewall: api.anthropic.com:443 and DNS only", report[0])

    def old_dns_rules(self, model="192.0.2.5:443"):
        """The rules 0.9.21 wrote and accepted for an address endpoint."""
        old = ["action=accept dst4=192.0.2.5/32 proto=tcp dstports=443-443",
               "action=accept specialtarget=dns", "action=drop"]
        self.app.domains[LEAD].__dict__["_firewall"] = list(old)
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p01"].update(model=model, lead_firewall=old)
        self.write_records(doc)

    def test_a_lead_set_before_keeps_its_dns_rule_and_is_warned_until_its_model_is_set_again(self):
        self.old_dns_rules()
        f = findings(self.app)
        self.assertEqual(f["pass:lead firewalls"].status, "pass")      # what you accepted holds
        warn = f["warn:lead DNS"].detail
        self.assertIn(LEAD, warn)
        self.assertIn("qmcp project firewall osint --model 192.0.2.5:443", warn)
        self.assertEqual(len(self.app.domains[LEAD].__dict__["_firewall"]), 3)   # nothing changed
        fleet.set_lead_firewall(self.app, "osint", model="192.0.2.5:443")
        self.assertNotIn("warn:lead DNS", findings(self.app))

    def test_rules_the_operator_chose_are_not_second_guessed(self):
        self.old_dns_rules()
        fleet.set_lead_firewall(self.app, "osint", rules=["action=accept proto=tcp dsthost=192.0.2.5 "
                                                          "dstports=443", "action=accept specialtarget=dns",
                                                          "action=accept proto=tcp dsthost=192.0.2.6 "
                                                          "dstports=443", "action=drop"])
        self.assertNotIn("warn:lead DNS", findings(self.app))

    def test_a_name_endpoint_with_dns_is_no_warning(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        self.assertNotIn("warn:lead DNS", findings(self.app))


# ======================================================================= 194: one command, in order

class MakeModelQube(ModelBase):
    def test_the_whole_workflow_in_one_command(self):
        report = fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertEqual(self.raw(MODEL), {"ai-managed", "qmcp-guarded", BADGE1, "qmcp-owner_mcp-control"})
        self.assertIsNone(self.netvm(MODEL))
        self.assertIsNone(self.netvm(LEAD))                 # a lead whose model is a qube: none
        p = self.record()
        self.assertEqual((p.model, p.model_qube, p.lead_firewall), (None, MODEL, None))
        text = "\n".join(report)
        for said in ("lost its network (ai-net-router): a lead whose model is a qube has none",
                     f"{MODEL} is out of p00", f"{MODEL} lost its network", f"{MODEL} is guarded",
                     "port 11434"):
            self.assertIn(said, text)
        self.assertEqual(self.model_findings(), {"pass:model qubes": self.model_findings()["pass:model qubes"]})

    def test_the_badge_goes_on_last(self):
        # Every step before it takes authority away; the badge is the one that
        # gives the lead a way in, and the record names the qube before it.
        order = []
        real_save = projects.save

        def save(records, path=None):
            order.append(("record", BADGE1 in self.raw(MODEL), self.netvm(MODEL),
                          "qmcp-guarded" in self.raw(MODEL)))
            return real_save(records, path)
        projects.save = save
        try:
            fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        finally:
            projects.save = real_save
        self.assertEqual(order, [("record", False, None, True)])

    def test_a_failure_part_way_leaves_less_authority_never_more(self):
        for key in ("set.netvm", "tag.discard:qmcp-proj-p00", "tag.add:qmcp-guarded",
                    f"tag.add:{BADGE1}"):
            with self.subTest(key):
                self.doCleanups()
                self.setUp()
                self.app.fail.add(key)
                with self.assertRaises(Exception):
                    fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
                self.app.fail.discard(key)
                self.assertGreater(self.app.failed[key], 0, "the failure fired")
                # Never a badge without every step before it.
                tags = self.raw(MODEL)
                if BADGE1 in tags:
                    self.fail("the badge went on despite a failed step")
                # Whatever happened, no qube wears the model badge, so the lead
                # reaches nothing, and qmcp check says what is left.
                self.assertFalse(any(BADGE1 in v.tags.raw() for v in self.app.domains))

    def test_the_badge_failing_leaves_a_recorded_qube_check_warns_about(self):
        self.app.fail.add(f"tag.add:{BADGE1}")
        with self.assertRaises(Exception):
            fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.app.fail.clear()
        self.assertEqual(self.record().model_qube, MODEL)
        warn = self.model_findings()["warn:model qubes"]
        self.assertIn(f"does not wear {BADGE1}", warn)
        self.assertIn(f"--model-qube {MODEL}", warn)
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)     # run again: done
        self.assertIn(BADGE1, self.raw(MODEL))

    def test_refused_before_anything_changes(self):
        a = self.app
        a.vm("ai-m-tpl-managed", template=a.domains["ai-debian-13"], netvm=None, tags={"ai-managed"})
        a.vm("ai-m-standalone", klass="StandaloneVM", netvm=None, tags={"ai-managed"})
        cases = {
            "ai-debian-13": "TemplateVM",                 # a template
            "ai-dvm": "disposable template",
            "ai-net-router": "provides network",          # a gateway
            HUB: "is the hub",
            "osint-dump": "drop box",
            LEAD: "is a lead",
            OTHER_LEAD: "is a lead",
            "ai-osint-w1": "member of p01",                # a project's member
            "ai-other-w1": "member of p02",
            "ai-m-tpl-managed": "one the hub manages",     # 172
            "dom0": "no such qube",
            "no-such-qube": "no such qube",
        }
        for name, why in cases.items():
            with self.subTest(name):
                before = self.state()
                with self.assertRaises(fleet.RoleError) as cm:
                    fleet.set_lead_firewall(a, "osint", model_qube=name)
                self.assertIn(why, str(cm.exception))
                self.assertEqual(self.state(), before)
        # A StandaloneVM has no template, and is a model qube like an AppVM.
        fleet.set_lead_firewall(a, "osint", model_qube="ai-m-standalone")
        self.assertIn(BADGE1, self.raw("ai-m-standalone"))

    def test_a_qube_whose_tags_cannot_be_read_is_refused_unchanged(self):
        before = self.state()
        self.app.fail.add(f"tag.List:{MODEL}")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.app.fail.clear()
        self.assertIn("refused until that reads", str(cm.exception))
        self.assertEqual(self.state(), before)

    def test_any_qube_whose_tags_cannot_be_read_stops_it(self):
        # It may wear the slot's model badge: the command could not take it off.
        before = self.state()
        self.app.fail.add("tag.List:ai-work2")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.app.fail.clear()
        self.assertIn("ai-work2", str(cm.exception))
        self.assertEqual(self.state(), before)

    def test_a_qube_outside_ai_space_is_refused_until_guarded(self):
        # The command never brings a qube into AI space, so neither can a
        # proposal: adopting a qube is the operator's own step.
        self.app.vm("ollama", template=self.app.domains["debian-13"], netvm=None)
        before = self.raw("ollama")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "osint", model_qube="ollama")
        self.assertIn("outside AI space: guard it first (qmcp guard ollama)", str(cm.exception))
        self.assertEqual(self.raw("ollama"), before)
        fleet.guard(self.app, "ollama")
        fleet.set_lead_firewall(self.app, "osint", model_qube="ollama")
        self.assertEqual(self.raw("ollama"), {"ai-managed", "qmcp-guarded", BADGE1})

    def test_a_hub_file_that_cannot_be_read_refuses(self):
        pathlib.Path(core.HUB_PATH).unlink()
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "osint", model_qube=HUB)
        self.assertIn("not known whether it is the hub", str(cm.exception))
        self.assertNotIn(BADGE1, self.raw(HUB))

    def test_a_running_qube_the_hub_managed_is_killed_once_guarded(self):
        # Guarding stops new calls from the hub; a call it started while the
        # qube was managed ends with the qube.
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Running")
        report = fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Halted")
        self.assertTrue(any("killed, so no process the hub started in it while it was managed "
                            "runs on" in line for line in report), report)
        # One that already serves a project, guarded, is left running: the hub
        # could not reach it since, and its leads may be using it.
        self.app.domains[MODEL].start()
        report = fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Running")
        self.assertFalse(any("killed" in line for line in report), report)

    def test_a_running_qube_guarded_first_is_killed_when_it_becomes_one(self):
        # Guarding a qube that serves nothing kills nothing; what the hub
        # started in it while it was managed ends when it becomes a model qube.
        self.app.domains[MODEL].tags.discard("qmcp-proj-p00")
        self.app.domains[MODEL].netvm = None
        self.assertEqual(fleet.guard(self.app, MODEL), f"{MODEL}: guarded")
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Running")
        report = fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Halted")
        self.assertTrue(any("killed, so no process started in it before it became a model qube"
                            in line for line in report), report)

    def test_a_power_state_that_cannot_be_read_is_never_taken_for_halted(self):
        # qubesadmin answers "NA" for a qube it cannot read: the kill is tried.
        vm = self.app.domains[MODEL]
        vm.__dict__["get_power_state"] = lambda: "NA"
        report = fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertEqual(vm._power, "Halted")
        self.assertTrue(any("killed" in line for line in report), report)
        # A kill that fails while the state still cannot be read is a failure.
        fleet.set_lead_firewall(self.app, "osint", model_qube="none")
        fleet.manage(self.app, MODEL)
        vm.__dict__["_power"] = "Running"
        self.app.fail.add("kill")
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertIn("could NOT be killed", str(cm.exception))
        self.assertIn(f"qvm-kill {MODEL}", str(cm.exception))

    def test_a_kill_that_fails_stops_before_the_record_and_the_badge(self):
        # No lead may reach a qube that may still run what the hub started.
        self.app.fail.add("kill")
        with self.assertRaises(fleet.ProjectError):
            fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertNotIn(BADGE1, self.raw(MODEL))
        self.assertIsNone(self.record().model_qube)
        self.assertIn("qmcp-guarded", self.raw(MODEL))          # less authority, never more
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Running")
        # Killed by hand, the command run again completes.
        self.app.fail.clear()
        self.app.domains[MODEL].kill()
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertIn(BADGE1, self.raw(MODEL))

    def test_the_model_qubes_own_network_failing_leaves_no_badge(self):
        # The second network write is the model qube's (the first, the lead's).
        self.app.fail_reads("set.netvm", "ok fail")
        with self.assertRaises(Exception):
            fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertEqual(self.app.failed["set.netvm"], 1)
        self.assertIsNone(self.netvm(LEAD))
        self.assertEqual(self.netvm(MODEL), "ai-net-router")
        self.assertNotIn(BADGE1, self.raw(MODEL))
        self.assertNotIn("qmcp-guarded", self.raw(MODEL))

    def test_replacing_the_model_qube_moves_the_badge_off_first(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.app.vm("ai-hub-model2", template=self.app.domains["debian-13"], netvm=None,
                    tags={"ai-managed"})
        self.app.fail.add(f"tag.add:{BADGE1}")
        with self.assertRaises(Exception):
            fleet.set_lead_firewall(self.app, "osint", model_qube="ai-hub-model2")
        self.app.fail.clear()
        self.assertNotIn(BADGE1, self.raw(MODEL))           # off the old one already
        self.assertNotIn(BADGE1, self.raw("ai-hub-model2"))
        fleet.set_lead_firewall(self.app, "osint", model_qube="ai-hub-model2")
        self.assertIn(BADGE1, self.raw("ai-hub-model2"))
        self.assertEqual(self.record().model_qube, "ai-hub-model2")

    def test_a_stray_holder_of_the_badge_loses_it(self):
        self.app.vm("ai-stray", netvm=None, tags={"ai-managed", "qmcp-guarded", BADGE1})
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertNotIn(BADGE1, self.raw("ai-stray"))

    def test_none_takes_it_away(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        report = fleet.set_lead_firewall(self.app, "osint", model_qube="none")
        self.assertNotIn(BADGE1, self.raw(MODEL))
        self.assertIn("qmcp-guarded", self.raw(MODEL))      # still guarded, still offline
        self.assertIsNone(self.record().model_qube)
        self.assertIn("no longer its model qube", report[0])

    def test_running_it_again_changes_nothing(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        before = self.state()
        report = fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertEqual(self.state(), before)
        self.assertEqual(len(report), 1)

    def test_a_remote_model_is_refused_while_the_model_is_a_qube(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        self.assertIn("a remote model takes a new lead on a network", str(cm.exception))

    def test_exactly_one_change(self):
        for kw in ({"model": "a.b:1", "model_qube": MODEL},
                   {"rules": ["action=drop"], "model_qube": MODEL},
                   {"accept_current": True, "model_qube": MODEL}):
            with self.assertRaises(fleet.RoleError, msg=kw):
                fleet.set_lead_firewall(self.app, "osint", **kw)


class Shared(ModelBase):
    def test_a_second_project_may_share_it_and_is_told_what_that_means(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        report = fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        self.assertEqual({BADGE1, BADGE2} & self.raw(MODEL), {BADGE1, BADGE2})
        warning = [l for l in report if "WARNING" in l]
        self.assertEqual(len(warning), 1)
        self.assertIn("also serves p01", warning[0])
        self.assertIn(fleet.SHARED_MODEL_WARNING, warning[0])
        self.assertIn("API filter", fleet.SHARED_MODEL_WARNING)
        self.assertIn("qmcp ships none", fleet.SHARED_MODEL_WARNING)
        self.assertIn("pass:model qubes", self.model_findings())

    def test_deleting_one_project_keeps_the_qube_for_the_other(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        plan = fleet.delete_plan(self.app, projects.load(), "other")[1]
        self.assertIn(f"its model qube {MODEL} is kept and loses p02's badge", plan)
        report = fleet.delete_project(self.app, "other")
        self.assertIn(f"p02: stripped {BADGE2} from {MODEL} (the model qube, kept)", report)
        self.assertEqual(self.raw(MODEL) & {BADGE1, BADGE2}, {BADGE1})
        self.assertIn(MODEL, {v.name for v in self.app.domains})


# ======================================================================= 193: creates and lead changes

class CreatesAndLeads(ModelBase):
    def create(self, label="sealed", source="template", origin="ai-debian-13", lead_netvm=None,
               model=None, model_qube=MODEL, networks=(None,)):
        return fleet.create_project(self.app, label, source, origin, (), list(networks), "1G",
                                    lead_netvm, False, None, model, model_qube)

    def test_a_project_with_a_model_qube_has_a_lead_with_no_network(self):
        report = self.create()
        p = self.record("sealed")
        self.assertEqual((p.model, p.model_qube), (None, MODEL))
        self.assertIsNone(self.netvm(p.lead))
        self.assertIn(projects.model_badge(p.slot), self.raw(MODEL))
        self.assertIn(f"model qube {MODEL}", report[-1])

    def test_a_lead_network_with_a_model_qube_is_refused_first(self):
        before = self.state()
        for kw, why in (({"lead_netvm": "ai-net-router"}, "a lead whose model is a qube has no network"),
                        ({"model": "api.anthropic.com:443"}, "not both")):
            with self.assertRaises(fleet.RoleError, msg=kw) as cm:
                self.create(**kw)
            self.assertIn(why, str(cm.exception))
            self.assertEqual(self.state(), before)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead(self.app, "other", "template", "ai-debian-13", None, False, None,
                           "api.anthropic.com:443", model_qube=MODEL)
        self.assertIn("not both", str(cm.exception))
        self.assertEqual(self.state(), before)
        self.create(lead_netvm="none")                      # none is no network: fine

    def test_a_promoted_lead_loses_its_network_and_is_never_its_own_model_qube(self):
        self.app.vm("ai-hub-agent", template=self.app.domains["ai-debian-13"],
                    netvm=self.app.domains["ai-net-router"], tags={"ai-managed", "qmcp-proj-p00"})
        tags = self.raw("ai-hub-agent")
        with self.assertRaises(fleet.RoleError) as cm:
            self.create(source="promote", origin="ai-hub-agent", model_qube="ai-hub-agent")
        self.assertIn("cannot be both the lead and its model qube", str(cm.exception))
        self.assertIsNone(self.record("sealed"))            # refused before anything changed
        self.assertEqual(self.raw("ai-hub-agent"), tags)
        self.create(source="promote", origin="ai-hub-agent")
        self.assertIsNone(self.netvm("ai-hub-agent"))
        self.assertEqual(self.record("sealed").lead, "ai-hub-agent")

    def test_a_refused_model_qube_creates_nothing(self):
        names = {v.name for v in self.app.domains}
        with self.assertRaises(fleet.RoleError):
            self.create(model_qube="ai-osint-w1")
        self.assertEqual({v.name for v in self.app.domains}, names)
        self.assertIsNone(self.record("sealed"))

    def test_a_new_lead_without_a_network_keeps_the_projects_model_qube(self):
        fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        fleet.set_lead(self.app, "other", "template", "ai-debian-13", None, False, None)
        p = self.record("other")
        self.assertEqual(p.model_qube, MODEL)
        self.assertIn(BADGE2, self.raw(MODEL))
        self.assertIsNone(self.netvm(p.lead))

    def test_a_new_lead_on_a_network_with_a_remote_model_drops_the_model_qube_first(self):
        fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        seen = []
        real = fleet._demote_lead

        def demote(app, p, report, removing=False):
            seen.append(BADGE2 in self.raw(MODEL))
            return real(app, p, report, removing)
        fleet._demote_lead = demote
        try:
            fleet.set_lead(self.app, "other", "template", "ai-debian-13", "ai-net-router", False,
                           "ai-other-lead2", "api.anthropic.com:443")
        finally:
            fleet._demote_lead = real
        self.assertEqual(seen, [False])                     # off before the old lead is touched
        p = self.record("other")
        self.assertEqual((p.model, p.model_qube), ("api.anthropic.com:443", None))
        self.assertEqual(self.netvm(p.lead), "ai-net-router")

    def test_a_new_lead_on_a_network_with_only_a_model_qube_is_refused(self):
        fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        before = self.state()
        with self.assertRaises(fleet.RoleError):
            fleet.set_lead(self.app, "other", "template", "ai-debian-13", "ai-net-router", False,
                           "ai-other-lead2")
        self.assertEqual(self.state(), before)

    def test_none_asks_nothing_of_the_new_leads_network(self):
        # "none" is no model qube: a new lead on a network with a remote model is fine.
        fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        fleet.set_lead(self.app, "other", "template", "ai-debian-13", "ai-net-router", False,
                       "ai-other-lead2", "api.anthropic.com:443", model_qube="none")
        p = self.record("other")
        self.assertEqual((p.model, p.model_qube), ("api.anthropic.com:443", None))
        self.assertNotIn(BADGE2, self.raw(MODEL))
        req = {"type": "project-lead", "title": "t", "project": "other", "keep_old": False,
               "lead": {"from": "template", "qube": "deb"}, "lead_netvm": "ai-net-router",
               "model_qube": "none"}
        self.assertEqual(proposals.normalise(req, "ai-")["model_qube"], "none")

    def test_a_lead_change_can_name_a_new_model_qube_or_none(self):
        fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        self.app.vm("ai-hub-model2", template=self.app.domains["debian-13"], netvm=None,
                    tags={"ai-managed"})
        fleet.set_lead(self.app, "other", "template", "ai-debian-13", None, False, None,
                       model_qube="ai-hub-model2")
        self.assertNotIn(BADGE2, self.raw(MODEL))
        self.assertIn(BADGE2, self.raw("ai-hub-model2"))
        fleet.set_lead(self.app, "other", "template", "ai-debian-13", None, False, None,
                       model_qube="none")
        self.assertNotIn(BADGE2, self.raw("ai-hub-model2"))
        self.assertIsNone(self.record("other").model_qube)


# ======================================================================= a model qube is no member and no lead

class NoOtherRole(ModelBase):
    def setUp(self):
        super().setUp()
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)

    def test_it_joins_no_slot(self):
        fleet.manage(self.app, MODEL)                       # even un-guarded for maintenance
        for target in ("p00", "osint", "other"):
            with self.assertRaises(fleet.RoleError, msg=target):
                fleet.move(self.app, MODEL, target)
        self.assertEqual(self.raw(MODEL) & {"qmcp-proj-p00", "qmcp-proj-p01", "qmcp-proj-p02"}, set())

    def test_guard_after_maintenance_kills_it_if_it_runs(self):
        # The maintenance window closes: no process the hub started runs on.
        fleet.manage(self.app, MODEL)
        self.app.domains[MODEL].start()
        out = fleet.guard(self.app, MODEL)
        self.assertIn("killed", out)
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Halted")
        # Halted, there is nothing to kill and nothing to say.
        fleet.manage(self.app, MODEL)
        self.assertEqual(fleet.guard(self.app, MODEL), f"{MODEL}: guarded")

    def test_guard_kills_no_model_qube_already_guarded(self):
        # Its leads may be using it, and the hub could not reach it.
        self.app.domains[MODEL].start()
        self.assertEqual(fleet.guard(self.app, MODEL), f"{MODEL}: guarded")
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Running")

    def test_guard_tries_the_kill_when_the_state_cannot_be_read(self):
        fleet.manage(self.app, MODEL)
        vm = self.app.domains[MODEL]
        vm.__dict__["_power"] = "Running"
        vm.__dict__["get_power_state"] = lambda: "NA"
        self.assertIn("killed", fleet.guard(self.app, MODEL))
        self.assertEqual(vm._power, "Halted")
        fleet.manage(self.app, MODEL)
        vm.__dict__["_power"] = "Running"
        self.app.fail.add("kill")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.guard(self.app, MODEL)
        self.assertIn("could NOT be killed", str(cm.exception))

    def test_guard_kills_no_template_whatever_it_wears(self):
        # A template is no model qube: killing it could break an update.
        tpl = self.app.domains["ai-tpl-g"]
        tpl.tags.discard("qmcp-guarded")
        tpl.tags.add("ai-managed")
        tpl.tags.add(BADGE1)
        tpl.__dict__["_power"] = "Running"
        self.assertEqual(fleet.guard(self.app, "ai-tpl-g"), "ai-tpl-g: guarded")
        self.assertEqual(tpl.get_power_state(), "Running")

    def test_guard_kills_no_disposable_template_whatever_it_wears(self):
        dvt = self.app.vm("ai-hub-dvt", template=self.app.domains["debian-13"], netvm=None,
                          template_for_dispvms=True, power="Running", tags={"ai-managed", BADGE1})
        self.assertEqual(fleet.guard(self.app, "ai-hub-dvt"), "ai-hub-dvt: guarded")
        self.assertEqual(dvt.get_power_state(), "Running")

    def test_guard_kills_no_gateway_whatever_it_wears(self):
        # A gateway is no model qube: killing it would take its clients' network.
        gw = self.app.domains["ai-net-router"]
        gw.tags.discard("qmcp-guarded")
        gw.tags.add("ai-managed")
        gw.tags.add(BADGE1)
        gw.__dict__["_power"] = "Running"
        self.assertEqual(fleet.guard(self.app, "ai-net-router"), "ai-net-router: guarded")
        self.assertEqual(gw.get_power_state(), "Running")

    def test_a_kill_that_fails_after_guard_is_an_error(self):
        fleet.manage(self.app, MODEL)
        self.app.domains[MODEL].start()
        self.app.fail.add("kill")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.guard(self.app, MODEL)
        self.assertIn("could NOT be killed", str(cm.exception))
        self.assertIn(f"qvm-kill {MODEL}", str(cm.exception))
        self.assertIn("qmcp-guarded", self.raw(MODEL))          # guarded all the same
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Running")

    def test_guard_kills_no_qube_that_serves_no_project(self):
        self.app.vm("ai-plain", template=self.app.domains["debian-13"], netvm=None,
                    power="Running", tags={"ai-managed"})
        self.assertEqual(fleet.guard(self.app, "ai-plain"), "ai-plain: guarded")
        self.assertEqual(self.app.domains["ai-plain"].get_power_state(), "Running")

    def test_it_is_no_lead_source(self):
        fleet.manage(self.app, MODEL)
        for source in ("promote", "clone"):
            with self.assertRaises(fleet.RoleError, msg=source) as cm:
                fleet.create_project(self.app, "x", source, MODEL, ("ai-debian-13",), [None], "1G")
            self.assertIn("is a model qube of p01", str(cm.exception))

    def test_a_lead_wearing_a_model_badge_is_no_principal(self):
        self.app.domains[OTHER_LEAD].tags.add(BADGE1)
        r = self.call("qmcp.ListAIManagedQubes", caller=OTHER_LEAD)
        self.assertEqual(r, core.NOT_AUTHORIZED)

    def test_the_hub_clones_no_model_badge(self):
        fleet.manage(self.app, MODEL)
        r = self.call("qmcp.CloneAIManagedQube", {"source": MODEL, "name": "ai-hub-copy"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.raw("ai-hub-copy") & {BADGE1, "qmcp-guarded"}, set())

    def test_manage_says_it_still_serves_and_check_warns(self):
        out = fleet.manage(self.app, MODEL)
        self.assertIn("still the model qube of p01", out)
        self.assertIn(f"qmcp guard {MODEL}", self.model_findings()["warn:model qubes"])
        # Never the advice to move it into p00, which a model qube is refused.
        unslotted = findings(self.app).get("warn:managed qubes in no slot")
        self.assertNotIn(MODEL, unslotted.detail if unslotted else "")
        fleet.guard(self.app, MODEL)
        self.assertNotIn("warn:model qubes", self.model_findings())


class KillComesFirst(ModelBase):
    """A single failure never leaves a model qube guarded and still running
    what the hub started in it while it was managed, unless the error says to
    kill it by hand: a second run would find it guarded and spare it. So the
    kill comes right after the guard lands, and is tried when the guard's own
    call fails, since qubesd may have set the tag before it failed."""

    GUARD_KEYS = (f"tag.List:{MODEL}", "tag.add:ai-managed", "tag.add:qmcp-guarded",
                  "tag.add.landed:qmcp-guarded", f"get.provides_network:{MODEL}",
                  f"get.template_for_dispvms:{MODEL}", f"get.netvm:{MODEL}")
    COMMAND_KEYS = (f"tag.List:{MODEL}", "tag.add:qmcp-guarded", "tag.add.landed:qmcp-guarded",
                    "tag.add:qmcp-model-p02", f"get.netvm:{MODEL}")

    def sweep(self, keys, prepare, act):
        landed = 0
        for key in keys:
            fired = 0
            for n in range(1, 7):
                with self.subTest(key=key, n=n):
                    self.doCleanups()
                    self.setUp()
                    prepare()
                    self.app.fail_reads(key, " ".join(["ok"] * (n - 1) + ["fail"]))
                    told = ""
                    try:
                        act()
                    except Exception as e:
                        told = str(e) or type(e).__name__
                    fired += self.app.failed[key]
                    self.app.fail_plan.clear()
                    vm = self.app.domains[MODEL]
                    guarded = "qmcp-guarded" in vm.tags.raw()
                    if guarded and vm.get_power_state() == "Running":
                        self.assertIn(f"qvm-kill {MODEL}", told)
                    landed += bool(told) and guarded
            self.assertGreater(fired, 0, f"{key} never fired: its sweep proves nothing")
        self.assertGreater(landed, 0, "no failure came after the guard landed: the sweep proves nothing")

    def managed_and_running(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        fleet.manage(self.app, MODEL)
        self.app.domains[MODEL].start()

    def test_guard(self):
        self.sweep(self.GUARD_KEYS, self.managed_and_running, lambda: fleet.guard(self.app, MODEL))

    def test_the_command_for_a_further_project(self):
        # Its maintenance window, and it is given to a second project: the
        # command guards it, and a second run would spare a guarded model qube.
        self.sweep(self.COMMAND_KEYS, self.managed_and_running,
                   lambda: fleet.set_lead_firewall(self.app, "other", model_qube=MODEL))

    def test_guard_when_its_call_fails_and_the_kill_too(self):
        self.managed_and_running()
        self.app.fail.update({"tag.add:qmcp-guarded", "kill"})
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.guard(self.app, MODEL)
        said = str(cm.exception)
        for words in ("may be guarded now", "could NOT be killed", f"qvm-kill {MODEL}",
                      f"run qmcp guard {MODEL} again"):
            self.assertIn(words, said)
        self.assertNotIn("is guarded now", said)

    def test_guard_says_the_kill_when_a_later_step_fails(self):
        self.managed_and_running()
        self.app.fail.add("tag.add:ai-managed")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.guard(self.app, MODEL)
        self.assertIn(f"'{MODEL}' is guarded now; it was killed, but it could not be added to AI "
                      f"space (Injected)", str(cm.exception))
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Halted")

    def test_guard_when_its_call_fails_says_it_may_be_guarded(self):
        self.managed_and_running()
        self.app.fail.add("tag.add:qmcp-guarded")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.guard(self.app, MODEL)
        self.assertIn("may be guarded now, but the call failed (Injected); it was killed",
                      str(cm.exception))
        self.assertEqual(self.app.domains[MODEL].get_power_state(), "Halted")

    def test_a_kind_that_cannot_be_read_never_stops_the_guard(self):
        # Guarding takes the hub's authority away: it lands, and only the kill
        # waits, with the operator told.
        self.managed_and_running()
        self.app.fail.add(f"get.template_for_dispvms:{MODEL}")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.guard(self.app, MODEL)
        self.assertIn("could not be read, so it was not killed", str(cm.exception))
        self.assertIn(f"qvm-kill {MODEL}", str(cm.exception))
        self.assertIn("qmcp-guarded", self.raw(MODEL))

    def test_a_guard_that_lands_says_the_kind_is_unknown(self):
        # A guard that lands must say the kind is unknown, whether its own call
        # failed after landing or later steps would have failed: a second guard
        # finds it guarded and says nothing of a kill.
        landed = 0
        for second, plan in (("tag.add.landed:qmcp-guarded", "fail"), ("tag.add:ai-managed", "fail"),
                             (f"tag.List:{MODEL}", "ok fail"), (f"tag.List:{MODEL}", "ok ok fail")):
            with self.subTest(second=second, plan=plan):
                self.doCleanups()
                self.setUp()
                self.managed_and_running()
                self.app.fail.add(f"get.template_for_dispvms:{MODEL}")
                self.app.fail_reads(second, plan)
                with self.assertRaises(fleet.RoleError) as cm:
                    fleet.guard(self.app, MODEL)
                if "qmcp-guarded" in self.raw(MODEL):
                    landed += 1
                    self.assertIn(f"qvm-kill {MODEL}", str(cm.exception))
                    self.assertIn("no gateway or disposable template", str(cm.exception))
        self.assertGreater(landed, 0)

    def test_the_command_when_its_guard_step_fails_and_the_kill_too(self):
        self.managed_and_running()
        self.app.fail.update({"tag.add:qmcp-guarded", "kill"})
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        self.assertIn(f"{MODEL} may not be guarded (that step failed too: Injected)",
                      str(cm.exception))
        self.assertNotIn(BADGE2, self.raw(MODEL))

    def test_manage_promises_no_kill_guard_will_not_make(self):
        tpl = self.app.domains["ai-tpl-g"]
        tpl.tags.add(BADGE1)
        tpl.tags.discard("qmcp-guarded")
        self.assertEqual(fleet.manage(self.app, "ai-tpl-g"), "ai-tpl-g: managed")
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.app.fail.add(f"get.template_for_dispvms:{MODEL}")
        out = fleet.manage(self.app, MODEL)
        self.assertIn("still the model qube of p01", out)
        self.assertNotIn("kills it", out)


# ======================================================================= 195: qmcp check

class Check(ModelBase):
    def setUp(self):
        super().setUp()
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        self.assertEqual(list(self.model_findings()), ["pass:model qubes"])

    def fails_on(self, mutate, *words):
        mutate(self.app)
        detail = self.model_findings().get("fail:model qubes", "")
        for word in words:
            self.assertIn(word, detail)
        self.assertNotEqual(fleet.overall(list(findings(self.app).values())), "GREEN")

    def test_each_badge_out_of_place_fails(self):
        a = self.app
        cases = {
            "a network": (lambda a: setattr(a.domains[MODEL], "netvm", "ai-net-router"),
                          f"{MODEL} has a network (ai-net-router)"),
            "outside AI space": (lambda a: a.domains[MODEL].tags.discard("ai-managed"),
                                 f"{MODEL} is outside AI space but wears a model badge"),
            "in p00": (lambda a: a.domains[MODEL].tags.add("qmcp-proj-p00"),
                       f"{MODEL} is in p00: it copies into the hub's p00 qubes without a dialog "
                       f"(qmcp project firewall osint --model-qube {MODEL} takes it out)"),
            "a member": (lambda a: a.domains["ai-osint-w1"].tags.add(BADGE1),
                         "ai-osint-w1: is a member of p01"),
            "a template": (lambda a: a.domains["ai-tpl-g"].tags.add(BADGE1), "ai-tpl-g: is a TemplateVM"),
            "a gateway": (lambda a: a.domains["ai-net-router"].tags.add(BADGE1),
                          "ai-net-router: provides network"),
            "a drop box": (lambda a: a.domains["osint-dump"].tags.add(BADGE1), "osint-dump"),
            "no record": (lambda a: a.vm("ai-rogue-model", netvm=None,
                                         tags={"ai-managed", "qmcp-guarded", "qmcp-model-p05"}),
                          "ai-rogue-model wears qmcp-model-p05, which no project's record names"),
            "another record's": (lambda a: a.vm("ai-other-model", netvm=None,
                                                tags={"ai-managed", "qmcp-guarded", BADGE2}),
                                 "ai-other-model wears qmcp-model-p02, but other's record names "
                                 "no model qube"),
            "a managed template": (lambda a: setattr(a.domains[MODEL], "template", "ai-debian-13"),
                                   "its template ai-debian-13 is one the hub manages"),
        }
        for label, (mutate, words) in cases.items():
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                self.fails_on(mutate, words)

    def test_the_hub_wearing_one_fails(self):
        self.app.domains[HUB].tags.add(BADGE1)
        detail = self.model_findings()["fail:model qubes"]
        self.assertIn(HUB, detail)

    def test_a_lead_wearing_one_fails_as_a_lead(self):
        self.app.domains[OTHER_LEAD].tags.add(BADGE1)
        f = findings(self.app)
        self.assertIn(OTHER_LEAD, f["fail:leads"].detail)
        self.assertIn(f"{OTHER_LEAD}: is a lead", f["fail:model qubes"].detail)

    def test_a_model_qube_lead_given_a_network_fails_and_is_not_advised_to_accept_it(self):
        # A lead whose model is a qube has no network. One given a network
        # outside qmcp unseals its project.
        self.app.domains[LEAD].netvm = "ai-net-router"
        f = findings(self.app)
        self.assertIn(LEAD, f["fail:model-qube leads"].detail)
        self.assertIn(f"though its model is the qube {MODEL}", f["fail:model-qube leads"].detail)
        self.assertNotIn("warn:lead firewalls not accepted", f)
        for kw in ({"accept_current": True}, {"rules": ["action=drop"]}):
            with self.assertRaises(fleet.RoleError, msg=kw) as cm:
                fleet.set_lead_firewall(self.app, "osint", **kw)
            self.assertIn("has no firewall to set or accept", str(cm.exception))
        self.app.domains[LEAD].netvm = None
        self.assertNotIn("fail:model-qube leads", findings(self.app))

    def test_a_model_qube_leads_network_that_cannot_be_read_is_an_error(self):
        self.app.fail.add(f"get.netvm:{LEAD}")
        f = findings(self.app)
        self.app.fail.clear()
        self.assertIn("error:lead firewalls", f)
        self.assertNotIn("pass:lead firewalls", f)

    def test_a_recorded_model_qube_gone_is_a_warning(self):
        self.app.domains._drop(MODEL)
        self.assertIn(f"its model qube {MODEL} does not exist", self.model_findings()["warn:model qubes"])

    def test_a_network_that_cannot_be_read_is_incomplete_never_green(self):
        self.app.fail.add(f"get.netvm:{MODEL}")
        f = self.model_findings()
        self.app.fail.clear()
        self.assertIn("error:model qubes", f)
        self.assertNotIn("pass:model qubes", f)

    def test_the_policy_claims_are_ours(self):
        from test_dom0 import PolicyFacts
        facts = PolicyFacts("test_precedence_is_clean_on_upstream_defaults")
        facts.tmp, facts.app = self.tmp, self.app
        clean = fleet.precedence(facts._policy(), {"domains": {}}, HUB)
        self.assertEqual(clean, [])
        # The ports, not `*`: a claim that lost its argument would match `*` too.
        policy = facts._policy({"20-operator.policy": "qubes.ConnectTCP +11434 @anyvm @anyvm allow\n"
                                                      "qubes.ConnectTCP +22 @anyvm @anyvm allow\n"})
        self.assertIn("a TCP connection from AI space through @default",
                      " ".join(fleet.precedence(facts._policy({"20-operator.policy":
                               "qubes.ConnectTCP +11434 @anyvm @default allow target=sys-net\n"}),
                               {"domains": {}}, HUB)))
        problems = " ".join(fleet.precedence(policy, {"domains": {}}, HUB))
        for label in ("a lead's connection to its model qube",
                      "a worker's connection to its slot's model qube",
                      "the hub's connection to a model qube",
                      "a TCP connection from AI space into another qube"):
            self.assertIn(label, problems)


# ======================================================================= what the lead and the hub are told

class Told(ModelBase):
    def test_the_lead_learns_its_model_qube_and_port_and_nothing_else_of_it(self):
        r = self.lcall("qmcp.GetPoolStats")
        self.assertEqual((r["model"], r["model_qube"], r["model_port"]), (None, None, None))
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        r = self.lcall("qmcp.GetPoolStats")
        self.assertEqual((r["model"], r["model_qube"], r["model_port"]), (None, MODEL, 11434))
        names = {q["name"] for q in self.lcall("qmcp.ListAIManagedQubes")["qubes"]}
        self.assertNotIn(MODEL, names)                      # no member of its project
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": MODEL, "property": "netvm"})
        self.assertFalse(r["ok"])

    def test_a_model_qube_out_of_ai_space_is_redacted_for_the_lead(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        fleet.revoke(self.app, MODEL, shutdown=False)
        r = self.lcall("qmcp.GetPoolStats")
        self.assertEqual(r["model_qube"], scope.OUT_OF_SCOPE)

    def test_a_remote_model_is_told_too(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        r = self.lcall("qmcp.GetPoolStats")
        self.assertEqual((r["model"], r["model_qube"]), ("api.anthropic.com:443", None))

    def test_the_hub_reads_each_projects_model(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        rows = {x["slot"]: x for x in self.call("qmcp.GetPoolStats")["projects"]}
        self.assertEqual((rows["p01"]["model"], rows["p01"]["model_qube"]), (None, MODEL))
        # Out of AI space, its name is redacted as every read redacts one.
        fleet.revoke(self.app, MODEL, shutdown=False)
        rows = {x["slot"]: x for x in self.call("qmcp.GetPoolStats")["projects"]}
        self.assertEqual(rows["p01"]["model_qube"], scope.OUT_OF_SCOPE)

    def test_listing_and_records_carry_it(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        fleet.set_lead_firewall(self.app, "other", model_qube=MODEL)
        row = {r["name"]: r for r in fleet.listing(self.app)}[MODEL]
        self.assertEqual(row["model"], "p01,p02")
        prow = {r["slot"]: r for r in fleet.project_rows(self.app, projects.load())}
        self.assertEqual(prow["p01"]["model_qube"], MODEL)
        view = fleet.lead_firewall_view(self.app, projects.load(), "osint")
        self.assertEqual((view["model"], view["model_qube"]), (None, MODEL))


# ======================================================================= the operator's command

class Command(ModelBase):
    def cli(self, *argv):
        from contextlib import redirect_stderr, redirect_stdout
        from qmcp import cli
        saved = cli._app, os.geteuid
        cli._app, os.geteuid = (lambda: self.app), (lambda: 0)
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    rc = cli.main(list(argv))
                except SystemExit as e:
                    rc = e.code
        finally:
            cli._app, os.geteuid = saved
        return rc, out.getvalue(), err.getvalue()

    def test_firewall_model_qube_runs_and_is_audited(self):
        rc, out, err = self.cli("project", "firewall", "osint", "--model-qube", MODEL)
        self.assertEqual(rc, 0, err)
        self.assertIn(f"model qube {MODEL}", out)
        self.assertIn(BADGE1, self.raw(MODEL))
        line = [l for l in self.audit_lines() if l["caller"] == "operator"][-1]
        self.assertEqual((line["service"], line["args"]["model_qube"]),
                         ("qmcp project firewall", MODEL))
        rc, out, _ = self.cli("project", "firewall", "osint")
        self.assertIn(f"lead {LEAD}, model qube {MODEL}", out)
        self.assertIn("should have no network, and qmcp check fails if it has one", out)
        self.assertIn("with none, no firewall rule applies to it", out)
        self.assertNotIn("DIFFERENT", out)
        rc, out, _ = self.cli("project", "list")
        self.assertIn(f"model={MODEL}", out)
        rc, out, err = self.cli("project", "firewall", "osint", "--model-qube", "none")
        self.assertEqual(rc, 0, err)
        self.assertNotIn(BADGE1, self.raw(MODEL))

    def test_create_and_lead_take_it(self):
        rc, out, err = self.cli("project", "create", "sealed", "--lead-template", "ai-debian-13",
                                "--model-qube", MODEL, "--network", "none", "--quota", "1G")
        self.assertEqual(rc, 0, err)
        p = self.record("sealed")
        self.assertEqual(p.model_qube, MODEL)
        self.assertIsNone(self.netvm(p.lead))
        rc, out, err = self.cli("project", "lead", "other", "--lead-template", "ai-debian-13",
                                "--model-qube", MODEL)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.record("other").model_qube, MODEL)
        line = [l for l in self.audit_lines() if l["caller"] == "operator"][-1]
        self.assertEqual(line["args"]["model_qube"], MODEL)

    def test_a_network_with_it_is_refused_in_plain_words(self):
        rc, out, err = self.cli("project", "create", "sealed", "--lead-template", "ai-debian-13",
                                "--lead-netvm", "ai-net-router", "--model-qube", MODEL,
                                "--network", "none", "--quota", "1G")
        self.assertEqual(rc, 1)
        self.assertIn("a lead whose model is a qube has no network", err)
        self.assertIsNone(self.record("sealed"))


# ======================================================================= the record

class Record(ModelBase):
    def test_an_endpoint_and_a_model_qube_never_both(self):
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p01"].update(model="api.anthropic.com:443", model_qube=MODEL)
        with self.assertRaises(projects.ProjectsUnreadable):
            projects.parse(json.dumps(doc))
        doc["slots"]["p01"].pop("model")
        doc["slots"]["p01"]["model_qube"] = "not a name!"
        with self.assertRaises(projects.ProjectsUnreadable):
            projects.parse(json.dumps(doc))

    def test_a_record_without_it_keeps_its_format(self):
        text = pathlib.Path(projects.PROJECTS_PATH).read_text()
        self.assertNotIn("model_qube", projects.dump_json(projects.parse(text)))

    def test_the_model_badge_is_a_slot_badge(self):
        self.assertEqual(projects.slot_badge_parts("qmcp-model-p03"), ("model", "p03"))
        self.assertIsNone(projects.slot_badge_parts("qmcp-model-p16"))
        self.assertTrue(projects.is_slot_tag("qmcp-model-p01"))
        self.assertEqual(projects.model_slots({"qmcp-model-p01", "qmcp-proj-p01"}), {"p01"})


# ======================================================================= proposals

class Proposals(ModelBase):
    def submit(self, req):
        out = io.StringIO()
        from qmcp import services
        services.main("qmcp.SubmitProposal", stdin=io.BytesIO(json.dumps(req).encode()),
                      environ={"QREXEC_REMOTE_DOMAIN": HUB}, app_factory=lambda: self.app, out=out)
        return json.loads(out.getvalue())

    def test_shapes(self):
        ok = [
            {"type": "project-create", "title": "t", "label": "sealed", "networks": [None],
             "quota": 1, "lead": {"from": "template", "qube": "deb"}, "model_qube": MODEL},
            {"type": "project-lead", "title": "t", "project": "osint", "keep_old": False,
             "lead": {"from": "template", "qube": "deb"}, "model_qube": "none"},
            {"type": "project-firewall", "title": "t", "project": "osint", "model_qube": MODEL},
            {"type": "project-firewall", "title": "t", "project": "osint", "model_qube": "none"},
        ]
        for req in ok:
            self.assertEqual(proposals.normalise(req, "ai-")["model_qube"], req["model_qube"])
        bad = [
            dict(ok[0], model="a.b:1"),                     # both
            dict(ok[0], lead_netvm="ai-net-router"),        # a lead with a network
            dict(ok[0], model_qube="none"),                 # a create names one, or none at all
            dict(ok[2], model="a.b:1"),
            dict(ok[2], rules=["action=drop"]),
            dict(ok[2], model_qube="bad name!"),
        ]
        for req in bad:
            with self.assertRaises(proposals.Invalid, msg=req):
                proposals.normalise(req, "ai-")

    def test_one_stored_before_reads_back_as_itself(self):
        old = {"type": "project-firewall", "title": "t", "project": "osint",
               "model": "api.anthropic.com:443"}
        self.assertEqual(proposals.normalise(old), old)

    def test_the_second_tick_names_the_qube_and_the_sharing(self):
        r = self.submit({"type": "project-firewall", "title": "self-hosted", "project": "osint",
                         "model_qube": MODEL})
        doc = proposals.show(self.app, r["id"])
        self.assertEqual(len(doc["second_tick"]), 1)
        self.assertIn(f"makes {MODEL} the model qube of osint", doc["second_tick"][0])
        self.assertEqual(doc["after"], {"model": None, "model_qube": MODEL, "rules": None})
        self.assertEqual(doc["command"], f"qmcp project firewall osint --model-qube {MODEL}")
        with self.assertRaises(proposals.Refused):          # never one click
            proposals.accept(self.app, r["id"], doc["sha256"])
        ok, report = proposals.accept(self.app, r["id"], doc["sha256"], tick=doc["tick"])
        self.assertTrue(ok, report)
        self.assertIn(BADGE1, self.raw(MODEL))
        # A second project's: the reasons say what sharing means.
        r = self.submit({"type": "project-firewall", "title": "share", "project": "other",
                         "model_qube": MODEL})
        reasons = proposals.show(self.app, r["id"])["second_tick"]
        self.assertTrue(any("already serves p01" in x and fleet.SHARED_MODEL_WARNING in x
                            for x in reasons), reasons)

    def test_taking_it_away_and_replacing_it_by_a_remote_model_are_named(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        r = self.submit({"type": "project-firewall", "title": "none", "project": "osint",
                         "model_qube": "none"})
        reasons = proposals.show(self.app, r["id"])["second_tick"]
        self.assertTrue(any(f"takes the model qube {MODEL} away" in x for x in reasons), reasons)
        r = self.submit({"type": "project-lead", "title": "remote", "project": "osint",
                         "lead": {"from": "template", "qube": "ai-debian-13"},
                         "lead_netvm": "ai-net-router", "lead_name": "ai-osint-lead2",
                         "keep_old": False, "model": "api.anthropic.com:443"})
        reasons = proposals.show(self.app, r["id"])["second_tick"]
        self.assertTrue(any(f"model qube {MODEL} stops serving osint" in x for x in reasons), reasons)
        # none with a remote model: the new lead reaches that, and says so.
        r = self.submit({"type": "project-lead", "title": "remote", "project": "osint",
                         "lead": {"from": "template", "qube": "ai-debian-13"},
                         "lead_netvm": "ai-net-router", "lead_name": "ai-osint-lead2",
                         "keep_old": False, "model": "api.anthropic.com:443",
                         "model_qube": "none"})
        reasons = proposals.show(self.app, r["id"])["second_tick"]
        self.assertTrue(any(f"takes the model qube {MODEL} away" in x for x in reasons), reasons)
        self.assertFalse(any("reaches no model" in x for x in reasons), reasons)
        self.assertTrue(any("api.anthropic.com:443" in x for x in reasons), reasons)

    def test_none_shows_what_stays(self):
        # With no model qube, nothing is taken away: the model and its rules stay.
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        r = self.submit({"type": "project-firewall", "title": "t", "project": "osint",
                         "model_qube": "none"})
        doc = proposals.show(self.app, r["id"])
        self.assertEqual(doc["after"]["model"], "api.anthropic.com:443")
        self.assertEqual(doc["after"]["rules"], doc["before"]["accepted"])
        self.assertIsNotNone(doc["after"]["rules"])
        self.assertFalse(any("reaches no model" in x for x in doc["second_tick"]))
        # With one: it goes, and the lead stays with no network and no rules.
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        r = self.submit({"type": "project-firewall", "title": "t", "project": "osint",
                         "model_qube": "none"})
        doc = proposals.show(self.app, r["id"])
        self.assertEqual(doc["after"], {"model": None, "model_qube": None, "rules": None})
        self.assertTrue(any("the lead reaches no model" in x for x in doc["second_tick"]))

    def test_a_remote_model_or_rules_for_a_model_qube_project_say_they_cannot_apply(self):
        fleet.set_lead_firewall(self.app, "osint", model_qube=MODEL)
        for extra in ({"model": "api.anthropic.com:443"}, {"rules": ["action=drop"]}):
            r = self.submit(dict({"type": "project-firewall", "title": "t", "project": "osint"},
                                 **extra))
            doc = proposals.show(self.app, r["id"])
            self.assertIsNone(doc["after"], extra)
            self.assertIn("accepting it will fail", doc["plan"])
            ok, report = proposals.accept(self.app, r["id"], doc["sha256"], tick=doc["tick"])
            self.assertFalse(ok, extra)
            self.assertIn(BADGE1, self.raw(MODEL))

    def test_a_new_endpoint_is_named_with_its_dns(self):
        r = self.submit({"type": "project-firewall", "title": "t", "project": "osint",
                         "model": "10.137.0.50:11434"})
        reasons = " ".join(proposals.show(self.app, r["id"])["second_tick"])
        self.assertIn("model 10.137.0.50:11434 only", reasons)
        r = self.submit({"type": "project-firewall", "title": "t", "project": "osint",
                         "model": "api.anthropic.com:443"})
        reasons = " ".join(proposals.show(self.app, r["id"])["second_tick"])
        self.assertIn("model api.anthropic.com:443 and DNS only", reasons)

    def test_a_promoted_lead_with_a_model_qube_is_said_to_lose_its_network(self):
        self.app.vm("ai-hub-agent", template=self.app.domains["ai-debian-13"],
                    netvm=self.app.domains["ai-net-router"], tags={"ai-managed", "qmcp-proj-p00"})
        r = self.submit({"type": "project-create", "title": "t", "label": "sealed",
                         "lead": {"from": "promote", "qube": "ai-hub-agent"}, "networks": [None],
                         "quota": 1, "model_qube": MODEL})
        reasons = " ".join(proposals.show(self.app, r["id"])["second_tick"])
        self.assertIn("loses its network", reasons)
        self.assertNotIn("keeps its files, template and network", reasons)

    def test_a_proposal_cannot_bring_a_qube_into_ai_space(self):
        self.app.vm("vault", template=self.app.domains["debian-13"], netvm=None)
        r = self.submit({"type": "project-firewall", "title": "t", "project": "osint",
                         "model_qube": "vault"})
        doc = proposals.show(self.app, r["id"])
        ok, report = proposals.accept(self.app, r["id"], doc["sha256"], tick=doc["tick"])
        self.assertFalse(ok)
        self.assertEqual(self.app.domains["vault"].tags.raw(), set())
        self.assertNotIn("vault", {q["name"] for q in self.call("qmcp.ListAIManagedQubes")["qubes"]})

    def test_badges_that_cannot_be_read_are_a_reason_never_one_fewer(self):
        r = self.submit({"type": "project-firewall", "title": "t", "project": "osint",
                         "model_qube": MODEL})
        self.app.fail.add(f"tag.List:{MODEL}")
        reasons = proposals.show(self.app, r["id"])["second_tick"]
        self.app.fail.clear()
        self.assertTrue(any("may already serve other projects" in x for x in reasons), reasons)


if __name__ == "__main__":
    unittest.main()
