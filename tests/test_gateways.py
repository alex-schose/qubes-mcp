"""Offline suite for M3a: the gateway registry, the networks AI space may use,
and leads' firewalls, against tests/fakequbes.py.

Each expectation below is the design's (the registry is the only source of
usable networks; a lead's firewall is the operator's), written down before the
code was read for what it does: a test that records what code does can bless a
hole.
"""
from __future__ import annotations

import io
import os
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import core, firewall, fleet, gateways, projects, proposals, scope  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_projects import LEAD, ProjectBase  # noqa: E402

ENDPOINT = ["action=accept dsthost=api.anthropic.com proto=tcp dstports=443-443",
            "action=accept specialtarget=dns", "action=drop"]


def findings(app, **kw):
    return {f.check: f for f in fleet.check(app, legacy_paths=(), system_info={"domains": {}}, **kw)}


# ======================================================================= the registry file

class RegistryFile(ProjectBase):
    def test_absent_means_none_enrolled_and_unreadable_means_none_usable(self):
        path = pathlib.Path(gateways.GATEWAYS_PATH)
        path.unlink()
        self.assertEqual(gateways.load(), {})
        for text in ("{not json", '{"version": 2, "gateways": {}}',
                     '{"version": 1, "gateways": {"ai-net-router": {"anonymising": 1, "label": ""}}}',
                     '{"version": 1, "gateways": {"bad name!": {"anonymising": false, "label": ""}}}',
                     '{"version": 1, "gateways": {"x": {"anonymising": false, "label": "\\n"}}}',
                     '{"version": 1, "gateways": {"x": {"anonymising": false}}}',
                     '{"version": 1, "gateways": {}, "extra": 1}', '{"version": 1, "gateways": []}',
                     '[]', json.dumps({"version": 1, "gateways": {
                         f"gw{i}": {"anonymising": False, "label": ""}
                         for i in range(gateways.MAX_GATEWAYS + 1)}})):
            path.write_text(text)
            with self.assertRaises(gateways.GatewaysUnreadable, msg=text):
                gateways.load()
            # Fail closed: nothing is enrolled, so nothing can be given a network.
            self.assertEqual(gateways.enrolled_names(), frozenset(), text)

    def test_a_source_whose_network_cannot_be_read_gives_no_birth_network(self):
        # Refused, never born offline as if the source had none.
        self.app.fail.add("get.netvm:ai-work")
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-work", "name": "ai-hub-c1"})
        self.assertEqual(r["error"], "birth egress could not be resolved")
        self.assertNotIn("ai-hub-c1", {v.name for v in self.app.domains})

    def test_a_network_refused_from_the_registry_does_not_wait_for_the_create_lock(self):
        # Refused from the request and the registry alone, at once: never
        # behind the creates in flight.
        from qmcp import budget
        pathlib.Path(gateways.GATEWAYS_PATH).write_text("{not json")
        real = budget.acquire_create_lock

        def no_lock(*a, **kw):
            raise AssertionError("waited for the create lock")
        budget.acquire_create_lock = no_lock
        try:
            r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-n4", "template": "ai-debian-13",
                                                       "netvm": "ai-net-router"})
        finally:
            budget.acquire_create_lock = real
        self.assertEqual(r["error"], "netvm must be an enrolled gateway")

    def test_a_network_unenrolled_while_a_create_waits_for_the_lock_is_refused(self):
        from qmcp import budget
        real = budget.acquire_create_lock

        def slow_lock(*a, **kw):
            gateways.save({})                                         # the operator, meanwhile
            return real(*a, **kw)
        budget.acquire_create_lock = slow_lock
        try:
            r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-n3", "template": "ai-debian-13",
                                                       "netvm": "ai-net-router"})
        finally:
            budget.acquire_create_lock = real
        self.assertEqual(r["error"], "netvm must be an enrolled gateway")
        self.assertNotIn("ai-osint-n3", {v.name for v in self.app.domains})

    def test_the_hubs_own_network_unread_is_refused_not_replaced(self):
        # The birth chain falls back to the configured network only when the
        # hub's own is none or not enrolled, never when it could not be read.
        self.egress("ai-net-router")
        self.app.fail.add(f"get.netvm:{HUB}")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-o1", "template": "ai-debian-13"})
        self.assertEqual(r["error"], "birth egress could not be resolved")
        self.assertNotIn("ai-hub-o1", {v.name for v in self.app.domains})

    def test_a_birth_egress_that_is_not_enrolled_is_warned(self):
        self.egress("sys-firewall")
        self.assertEqual(findings(self.app)["birth egress"].status, "warn")
        self.egress("ai-net-router")
        self.assertEqual(findings(self.app)["birth egress"].status, "pass")

    def test_an_unreadable_registry_refuses_every_create_that_needs_a_network(self):
        pathlib.Path(gateways.GATEWAYS_PATH).write_text("{not json")
        self.egress("ai-net-router")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-new", "template": "ai-debian-13"})
        self.assertEqual(r["error"], "birth egress could not be resolved")
        r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-new", "template": "ai-debian-13"})
        self.assertEqual(r["error"], "birth egress could not be resolved")
        r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-n2", "template": "ai-debian-13",
                                                   "netvm": "ai-net-router"})
        self.assertEqual(r["error"], "netvm must be an enrolled gateway")
        r = self.lcall("qmcp.CloneAIManagedQube", {"source": "ai-osint-w1", "name": "ai-osint-c1"})
        self.assertEqual(r["error"], "birth egress could not be resolved")
        self.assertFalse({"ai-osint-n2", "ai-osint-c1"} & {v.name for v in self.app.domains})
        # No network is still a network the hub may choose.
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-off", "template": "ai-debian-13",
                                                  "netvm": None})
        self.assertTrue(r["ok"], r)
        self.assertNotIn("ai-hub-new", self.app.domains)

    def test_round_trip(self):
        reg = {"sys-ai-tor": gateways.Gateway("sys-ai-tor", True, "Tor")}
        gateways.save(reg)
        back = gateways.load()
        self.assertEqual((back["sys-ai-tor"].anonymising, back["sys-ai-tor"].label), (True, "Tor"))
        # Root writes it; the services, a non-root dom0 user, must read it.
        self.assertEqual(os.stat(gateways.GATEWAYS_PATH).st_mode & 0o777, 0o644)
        # At the limit it saves; past it, and with a bad entry, nothing is written.
        full = {f"gw{i}": gateways.Gateway(f"gw{i}") for i in range(gateways.MAX_GATEWAYS)}
        gateways.save(full)
        before = pathlib.Path(gateways.GATEWAYS_PATH).read_text()
        for bad in (dict(full, extra=gateways.Gateway("extra")),
                    {"x": gateways.Gateway("x", False, "a\nb")}):
            with self.assertRaises(gateways.GatewaysUnreadable):
                gateways.save(bad)
            self.assertEqual(pathlib.Path(gateways.GATEWAYS_PATH).read_text(), before)


# ======================================================================= who may be enrolled

class Enroll(ProjectBase):
    def setUp(self):
        super().setUp()
        a = self.app
        fw = a.domains["sys-firewall"]
        # The operator's own routers, outside AI space, on templates the hub cannot edit.
        a.domains["debian-13"].features["qubes-firewall"] = "1"
        a.vm("sys-ai-net", provides_network=True, netvm=fw, template=a.domains["debian-13"])
        a.vm("sys-whonix", provides_network=True, netvm=fw, tags={"anon-gateway"},
             features={"qubes-firewall": "1"})
        a.vm("sys-ai-tor", provides_network=True, netvm=a.domains["sys-whonix"],
             template=a.domains["debian-13"])
        # On a template the hub manages: it could switch the firewall off.
        a.domains["ai-debian-13"].features["qubes-firewall"] = "1"
        a.vm("sys-hub-tpl-gw", provides_network=True, netvm=fw, template=a.domains["ai-debian-13"])
        # On a guarded template: fine.
        a.domains["ai-tpl-g"].features["qubes-firewall"] = "1"
        a.vm("sys-guarded-tpl-gw", provides_network=True, netvm=fw, template=a.domains["ai-tpl-g"])
        # No marker anywhere in its chain; and one switched off.
        a.vm("sys-no-marker", provides_network=True, netvm=fw)
        a.vm("tpl-off", klass="TemplateVM", features={"qubes-firewall": "0"})
        a.vm("sys-marker-off", provides_network=True, netvm=fw, template=a.domains["tpl-off"])
        # A disposable router whose disposable template sits on a template the hub manages.
        dvmt = a.vm("dvm-on-hub-tpl", template=a.domains["ai-debian-13"], template_for_dispvms=True)
        a.vm("disp-gw", klass="DispVM", provides_network=True, template=dvmt)

    def test_who_may_be_enrolled(self):
        for name in ("sys-ai-net", "sys-ai-tor", "sys-guarded-tpl-gw", "ai-net-router"):
            self.assertIsNone(fleet.gateway_refusal({v.name: v for v in self.app.domains}, name), name)
        for name, why in [("no-such-qube", "no such qube"), ("personal", "does not provide network"),
                          (HUB, "does not provide network"), ("dom0", "no such qube"),
                          ("ai-gw-unbadged", "without qmcp-guarded"),
                          ("sys-no-marker", "qubes-firewall"), ("sys-marker-off", "qubes-firewall"),
                          ("sys-whonix", "Whonix gateway"),
                          ("sys-hub-tpl-gw", "one the hub manages"),
                          ("disp-gw", "one the hub manages")]:
            with self.assertRaises(fleet.RoleError, msg=name) as cm:
                fleet.enroll_gateway(self.app, name)
            self.assertIn(why, str(cm.exception), name)
        self.assertEqual(set(gateways.load()), {"ai-net-router"})

    def test_the_hub_a_drop_box_or_a_project_member_is_never_a_gateway(self):
        a = self.app
        a.domains[HUB]._props["provides_network"] = True
        a.domains[HUB].features["qubes-firewall"] = "1"
        a.domains["ai-sink"]._props["provides_network"] = True
        a.domains["ai-sink"].features["qubes-firewall"] = "1"
        w = a.domains["ai-osint-w1"]
        w._props["provides_network"] = True
        w.features["qubes-firewall"] = "1"
        for name, why in ((HUB, "is the hub"), ("ai-sink", "drop box"), ("ai-osint-w1", "member")):
            with self.assertRaises(fleet.RoleError, msg=name) as cm:
                fleet.enroll_gateway(self.app, name)
            self.assertIn(why, str(cm.exception), name)

    @unittest.skipIf(os.geteuid() == 0, "root reads a file whatever its mode")
    def test_an_unreadable_hub_file_refuses_a_gateway_rather_than_enrolling_it(self):
        """`read_hub` answers None both for a file that is absent and for one it
        could not read, and `name == None` is false for every qube — so until
        0.9.25 a hub qube that provides network could be enrolled while the hub
        file was unreadable. The model-qube refusal beside it always refused.

        The teeth: the subject here IS the hub qube, with network, so the only
        thing that can refuse it is the hub read. Remove that check and this
        passes.
        """
        a = self.app
        a.domains[HUB]._props["provides_network"] = True
        a.domains[HUB].features["qubes-firewall"] = "1"
        hub_file = pathlib.Path(core.HUB_PATH)
        self.assertEqual(core.read_hub(), HUB)              # readable: refused as the hub
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.enroll_gateway(a, HUB)
        self.assertIn("is the hub", str(cm.exception))
        os.chmod(hub_file, 0o000)
        try:
            self.assertIsNone(core.read_hub())              # the fail-closed read
            with self.assertRaises(fleet.RoleError) as cm:
                fleet.enroll_gateway(a, HUB)
            self.assertIn("cannot be read", str(cm.exception))
            self.assertNotIn(HUB, gateways.load())
            # The same answer the model-qube refusal gives, so the two agree.
            self.assertIn("cannot be read",
                          fleet.model_qube_refusal({v.name: v for v in a.domains}, HUB) or "")
        finally:
            os.chmod(hub_file, 0o644)

    def test_enroll_set_remove(self):
        self.assertIn("enrolled", fleet.enroll_gateway(self.app, "sys-ai-tor", True, "Tor, CH"))
        with self.assertRaises(fleet.RoleError):
            fleet.enroll_gateway(self.app, "sys-ai-tor")            # once
        with self.assertRaises(fleet.RoleError):
            fleet.enroll_gateway(self.app, "sys-ai-net", label="x" * 41)
        fleet.set_gateway(self.app, "sys-ai-tor", anonymising=False, label="Tor")
        g = gateways.load()["sys-ai-tor"]
        self.assertEqual((g.anonymising, g.label), (False, "Tor"))
        with self.assertRaises(fleet.RoleError):
            fleet.set_gateway(self.app, "sys-ai-net", anonymising=True)    # not enrolled
        self.assertIn("no longer enrolled", fleet.remove_gateway(self.app, "sys-ai-tor"))
        self.assertNotIn("sys-ai-tor", gateways.load())

    def test_a_gateway_in_use_cannot_be_removed(self):
        # ai-net-router is on osint's list and under three qubes.
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.remove_gateway(self.app, "ai-net-router")
        self.assertIn("osint", str(cm.exception))
        self.assertIn("ai-osint-w1", str(cm.exception))
        self.assertIn("ai-net-router", gateways.load())

    def test_removing_waits_for_every_user_one_at_a_time(self):
        fleet.enroll_gateway(self.app, "sys-ai-net")
        fleet.edit_project(self.app, "osint", networks=["ai-net-router", "sys-ai-net", "none"])
        with self.assertRaises(fleet.RoleError) as cm:                # listed, nothing on it
            fleet.remove_gateway(self.app, "sys-ai-net")
        self.assertIn("osint", str(cm.exception))
        fleet.edit_project(self.app, "osint", networks=["ai-net-router", "none"])
        self.app.domains["ai-osint-w2"].netvm = self.app.domains["sys-ai-net"]
        with self.assertRaises(fleet.RoleError) as cm:                # on it, listed by none
            fleet.remove_gateway(self.app, "sys-ai-net")
        self.assertIn("ai-osint-w2", str(cm.exception))
        self.app.domains["ai-osint-w2"].netvm = None
        self.app.fail.add("get.netvm:ai-osint-w2")                    # cannot tell: refused
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.remove_gateway(self.app, "sys-ai-net")
        self.assertIn("ai-osint-w2 (network unreadable)", str(cm.exception))
        self.app.fail.clear()
        self.assertIn("no longer enrolled", fleet.remove_gateway(self.app, "sys-ai-net"))

    @unittest.skipIf(os.geteuid() == 0, "the root check only refuses non-root")
    def test_the_gateway_commands_need_root(self):
        from contextlib import redirect_stderr, redirect_stdout
        from qmcp import cli
        saved = cli._app
        cli._app = lambda: self.app
        try:
            for argv in (["enroll", "sys-ai-net"], ["set", "ai-net-router", "--label", "x"],
                         ["remove", "ai-net-router"]):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as cm:
                        cli.main(["gateway", *argv])
                self.assertIn("run as root", str(cm.exception.code), argv)
        finally:
            cli._app = saved
        self.assertEqual(set(gateways.load()), {"ai-net-router"})

    def test_rows_show_what_is_wrong_and_the_whonix_mark(self):
        fleet.enroll_gateway(self.app, "sys-ai-tor", True, "Tor")
        fleet.enroll_gateway(self.app, "sys-ai-net")
        rows = {r["name"]: r for r in fleet.gateway_rows(self.app)}
        self.assertTrue(rows["sys-ai-tor"]["upstream_ignores_firewall"])      # 185
        self.assertEqual(rows["sys-ai-tor"]["upstream"], "sys-whonix")
        self.assertFalse(rows["sys-ai-net"]["upstream_ignores_firewall"])
        self.assertIsNone(rows["sys-ai-net"]["problem"])
        self.assertEqual(rows["ai-net-router"]["projects"], ["osint"])
        self.assertIn("ai-osint-w1", rows["ai-net-router"]["used_by"])
        # An enrolled gateway that stops qualifying says so.
        self.app.domains["debian-13"].features.pop("qubes-firewall")      # its template's marker
        rows = {r["name"]: r for r in fleet.gateway_rows(self.app)}
        self.assertIn("qubes-firewall", rows["sys-ai-net"]["problem"])


# ======================================================================= qmcp check

class Check(ProjectBase):
    def test_an_ai_qube_on_a_network_that_is_not_enrolled_fails(self):
        self.assertEqual(findings(self.app)["AI networks"].status, "pass")
        self.app.domains["ai-work2"].netvm = self.app.domains["sys-firewall"]
        f = findings(self.app)["AI networks"]
        self.assertEqual(f.status, "fail")
        self.assertIn("ai-work2 on sys-firewall", f.detail)
        self.assertIn("qmcp gateway enroll", f.detail)

    def test_an_empty_registry_fails_every_networked_ai_qube(self):
        # An upgrade starts with an empty registry.
        pathlib.Path(gateways.GATEWAYS_PATH).unlink()
        f = findings(self.app)
        self.assertIn("no gateway enrolled", f["gateway registry"].detail)
        self.assertEqual(f["AI networks"].status, "fail")
        for name in (LEAD, "ai-osint-w1", "ai-work", "ai-hubq"):
            self.assertIn(name, f["AI networks"].detail)
        self.assertNotIn("ai-net-router on", f["AI networks"].detail)    # a gateway's own upstream

    def test_an_unreadable_registry_fails(self):
        pathlib.Path(gateways.GATEWAYS_PATH).write_text("[]")
        f = findings(self.app)
        self.assertEqual(f["gateway registry"].status, "fail")
        self.assertEqual(fleet.overall(list(f.values())), "FAILED")

    def test_an_enrolled_gateway_that_stops_qualifying_fails(self):
        self.app.domains["ai-net-router"].tags.discard("qmcp-guarded")
        f = findings(self.app)["gateway registry"]
        self.assertEqual(f.status, "fail")
        self.assertIn("ai-net-router", f.detail)

    def test_a_listed_network_that_is_not_enrolled_is_warned(self):
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p02"]["networks"] = [None, "sys-firewall"]
        self.write_records(doc)
        f = findings(self.app)["worker networks"]
        self.assertEqual(f.status, "warn")
        self.assertIn("other: sys-firewall is not an enrolled gateway", f.detail)


class UnusableGateways(ProjectBase):
    def test_an_enrolled_gateway_that_stopped_qualifying_takes_no_new_project_or_lead(self):
        # qmcp check fails on it; the operator's commands refuse it too.
        self.app.domains["ai-net-router"].tags.discard("qmcp-guarded")
        for call in (lambda: fleet.create_project(self.app, "res", "template", "ai-debian-13",
                                                  networks=["ai-net-router"], quota="1G"),
                     lambda: fleet.create_project(self.app, "res", "template", "ai-debian-13",
                                                  networks=["none"], quota="1G",
                                                  lead_netvm="ai-net-router", model="a.example:1")):
            with self.assertRaises(fleet.RoleError) as cm:
                call()
            self.assertIn("enrolled but not usable", str(cm.exception))
        # Taking it off a list stays possible (no member on it).
        self.app.domains["ai-osint-w1"].netvm = None
        fleet.edit_project(self.app, "osint", networks=["none"])


class RoleActions(ProjectBase):
    def test_a_qube_joins_ai_space_only_on_an_enrolled_network(self):
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.manage(self.app, "personal")                    # on sys-firewall
        self.assertIn("not an enrolled gateway", str(cm.exception))
        with self.assertRaises(fleet.RoleError):
            fleet.guard(self.app, "personal")
        self.assertNotIn("ai-managed", self.tags("personal"))
        self.app.domains["personal"].netvm = None
        self.assertIn("managed", fleet.manage(self.app, "personal"))
        # A gateway's own upstream is not its network as a client: guarding one
        # needs no enrolled upstream.
        self.app.vm("gw-outside", provides_network=True, netvm=self.app.domains["sys-firewall"])
        self.assertIn("guarded", fleet.guard(self.app, "gw-outside"))

    def test_a_new_lead_that_fails_leaves_no_rules_accepted_for_the_old_one(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        self.app.fail.add("tag.add:qmcp-lead-p01")
        with self.assertRaises(Exception):
            fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="ai-net-router",
                           keep_old=False, lead_name="ai-osint-l2")
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.lead, p.lead_firewall, p.model), (None, None, "api.anthropic.com:443"))

    def test_the_model_outlives_a_removed_lead_and_its_accepted_rules_do_not(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        fleet.remove_lead(self.app, "osint")
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.lead, p.model, p.lead_firewall), (None, "api.anthropic.com:443", None))
        fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="ai-net-router",
                       keep_old=False)
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.model, list(p.lead_firewall)), ("api.anthropic.com:443", ENDPOINT))


# ======================================================================= what reads say

class Reads(ProjectBase):
    def setUp(self):
        super().setUp()
        self.app.domains["debian-13"].features["qubes-firewall"] = "1"
        self.app.vm("sys-ai-net", provides_network=True, netvm=self.app.domains["sys-firewall"],
                    template=self.app.domains["debian-13"])
        self.app.domains["ai-work2"].netvm = self.app.domains["sys-ai-net"]

    def test_an_enrolled_gateway_outside_ai_space_is_named_to_the_hub(self):
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work2", "property": "netvm"})
        self.assertEqual(r["value"], scope.OUT_OF_SCOPE)          # not enrolled: redacted
        self.enroll("sys-ai-net")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work2", "property": "netvm"})
        self.assertEqual(r["value"], "sys-ai-net")

    def test_a_network_that_cannot_be_read_is_listed_as_unreadable_never_as_none(self):
        self.enroll("sys-ai-net")
        self.app.fail.add("get.netvm:ai-work2")
        row = next(r for r in fleet.listing(self.app) if r["name"] == "ai-work2")
        self.assertEqual(row["netvm"], fleet.UNREADABLE)
        self.app.fail.add("get.netvm:sys-ai-net")
        gw = next(r for r in fleet.gateway_rows(self.app) if r["name"] == "sys-ai-net")
        # Whose upstream it is cannot be read, so neither can whether it ignores rules.
        self.assertEqual((gw["upstream"], gw["upstream_ignores_firewall"]),
                         (fleet.UNREADABLE, fleet.UNREADABLE))
        self.app.fail.clear()
        row = next(r for r in fleet.listing(self.app) if r["name"] == "ai-work2")
        self.assertEqual(row["netvm"], "sys-ai-net")

    def test_a_lead_sees_only_its_own_networks_named(self):
        self.enroll("sys-ai-net")
        self.app.domains["ai-osint-w2"].netvm = self.app.domains["sys-ai-net"]
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": "ai-osint-w2", "property": "netvm"})
        self.assertEqual(r["value"], scope.OUT_OF_SCOPE)          # enrolled, but not osint's
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p01"]["networks"].append("sys-ai-net")
        self.write_records(doc)
        r = self.lcall("qmcp.GetPropertyAIManaged", {"name": "ai-osint-w2", "property": "netvm"})
        self.assertEqual(r["value"], "sys-ai-net")

    def test_the_hub_reads_the_registry_and_a_lead_does_not(self):
        self.enroll("sys-ai-net", anonymising=False, label="clearnet")
        r = self.call("qmcp.GetPoolStats")
        self.assertEqual(r["gateways"], [{"name": "ai-net-router", "anonymising": False, "label": ""},
                                         {"name": "sys-ai-net", "anonymising": False,
                                          "label": "clearnet"}])
        self.assertNotIn("gateways", self.lcall("qmcp.GetPoolStats"))
        pathlib.Path(gateways.GATEWAYS_PATH).write_text("{")
        self.assertIsNone(self.call("qmcp.GetPoolStats")["gateways"])   # never an empty list

    def test_a_lead_cannot_use_a_listed_network_that_is_not_enrolled(self):
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p01"]["networks"].append("sys-ai-net")
        self.write_records(doc)
        r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-n", "template": "ai-debian-13",
                                                   "netvm": "sys-ai-net"})
        self.assertEqual(r["error"], "netvm must be an enrolled gateway")
        self.enroll("sys-ai-net")
        r = self.lcall("qmcp.SpawnAIManagedQube", {"name": "ai-osint-n", "template": "ai-debian-13",
                                                   "netvm": "sys-ai-net"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.app.domains["ai-osint-n"].netvm.name, "sys-ai-net")


# ======================================================================= a lead's firewall

class LeadFirewall(ProjectBase):
    def accept_current(self):
        fleet.set_lead_firewall(self.app, "osint", accept_current=True)

    def rules(self, name=LEAD):
        return list(self.app.domains[name].__dict__["_firewall"])

    def test_a_lead_with_a_network_and_no_accepted_rules_is_warned(self):
        # An upgraded lead.
        f = findings(self.app)
        self.assertIn("osint", f["lead firewalls not accepted"].detail)
        self.assertEqual(f["lead firewalls not accepted"].status, "warn")
        self.assertNotIn("other", f["lead firewalls not accepted"].detail)   # no network: no firewall
        self.accept_current()
        self.assertNotIn("lead firewalls not accepted", findings(self.app))
        self.assertEqual(findings(self.app)["lead firewalls"].status, "pass")

    def test_drift_from_the_accepted_rules_fails(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        self.assertEqual(self.rules(), ENDPOINT)
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.model, list(p.lead_firewall)), ("api.anthropic.com:443", ENDPOINT))
        self.assertEqual(findings(self.app)["lead firewalls"].status, "pass")
        self.app.domains[LEAD].__dict__["_firewall"] = ["action=accept"]     # by hand in dom0
        f = findings(self.app)["lead firewalls"]
        self.assertEqual(f.status, "fail")
        self.assertIn(LEAD, f.detail)

    def test_an_unreadable_firewall_is_incomplete_never_green(self):
        self.accept_current()
        self.app.fail.add("admin.vm.firewall.Get")
        f = findings(self.app)
        self.assertEqual(f["lead firewalls"].status, "error")
        self.assertNotEqual(fleet.overall(list(f.values())), "GREEN")

    def test_set_rules_and_refuse_bad_ones_before_writing(self):
        fleet.set_lead_firewall(self.app, "osint", rules=["action=accept proto=tcp dsthost=1.2.3.4 "
                                                          "dstports=443", "action=drop"])
        self.assertEqual(self.rules(), ["action=accept dst4=1.2.3.4/32 proto=tcp dstports=443-443",
                                        "action=drop"])
        before = self.rules()
        for bad in (["action=accept comment=hello"], ["action=allow"], ["proto=tcp"],
                    ["action=accept action=drop"], [], ["x" * 300], ["action=accept  dsthost=a"]):
            with self.assertRaises(fleet.RoleError, msg=bad):
                fleet.set_lead_firewall(self.app, "osint", rules=bad)
            self.assertEqual(self.rules(), before, bad)

    def test_exactly_one_change(self):
        for kw in ({}, {"model": "a.b:1", "rules": ["action=drop"]},
                   {"model": "a.b:1", "accept_current": True}):
            with self.assertRaises(fleet.RoleError, msg=kw):
                fleet.set_lead_firewall(self.app, "osint", **kw)
        with self.assertRaises(fleet.RoleError):
            fleet.set_lead_firewall(self.app, "osint", model="no-port")

    def test_live_rules_outside_qmcps_form_are_refused_in_plain_words(self):
        # An upgraded lead's rules may hold what a 0.9.20 hub could write.
        # No rules at all (qubesd states none back) is refused for its count.
        for live in (["action=accept comment=from the hub"], ["action=accept expire=+3600"],
                     ["action=drop"] * (firewall.MAX_RULES + 1), []):
            self.app.domains[LEAD].__dict__["_firewall"] = list(live)
            with self.assertRaises(fleet.RoleError) as cm:
                self.accept_current()
            self.assertIn("not in the form qmcp records", str(cm.exception))
            self.assertIn(firewall.rules_refusal(live), str(cm.exception))   # the real reason
            self.assertIn("--rule or --model", str(cm.exception))
            self.assertIsNone(projects.find(self.records(), "osint").lead_firewall)

    def test_a_lead_with_no_network_takes_no_model(self):
        # As create and lead refuse --model for a lead with no network.
        lead = projects.find(self.records(), "other").lead
        before = list(self.app.domains[lead].__dict__["_firewall"])
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "other", model="api.anthropic.com:443")
        self.assertIn("has no network", str(cm.exception))
        self.assertEqual(self.rules(lead), before)
        self.assertIsNone(projects.find(self.records(), "other").model)
        self.app.fail.add(f"get.netvm:{lead}")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "other", model="api.anthropic.com:443")
        self.assertIn("cannot be read", str(cm.exception))
        self.app.fail.discard(f"get.netvm:{lead}")
        fleet.set_lead_firewall(self.app, "other", rules=["action=drop"])    # rules it may take
        self.assertEqual(self.rules(lead), ["action=drop"])

    def test_a_project_without_its_lead_has_no_firewall_to_set(self):
        fleet.remove_lead(self.app, "osint")
        with self.assertRaises(fleet.RoleError):
            fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")

    def test_a_fresh_lead_gets_its_firewall_before_its_badges(self):
        # If the lead badge cannot be added, the fresh lead is removed: it never
        # existed with its badges and a wider firewall.
        self.app.fail.add("tag.add:qmcp-lead-p03")
        with self.assertRaises(Exception):
            fleet.create_project(self.app, "res", "template", "ai-debian-13", networks=["none"],
                                 quota="1G", lead_netvm="ai-net-router", model="api.anthropic.com:443")
        self.assertNotIn("ai-res-lead", self.app.domains)
        self.assertIsNone(projects.find(self.records(), "res"))

    def test_a_failed_promotion_gives_the_qube_its_old_firewall_back(self):
        hubq = self.app.domains["ai-hubq"]
        hubq.__dict__["_firewall"] = ["action=accept dsthost=example.org proto=tcp dstports=80-80",
                                      "action=drop"]
        before = list(hubq.__dict__["_firewall"])
        self.app.fail.add("tag.add:qmcp-lead-p03")
        with self.assertRaises(Exception):
            fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"],
                                 quota="1G", model="api.anthropic.com:443")
        self.assertEqual(hubq.__dict__["_firewall"], before)
        self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-proj-p00"})

    def test_a_new_lead_takes_the_projects_model(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="ai-net-router",
                       keep_old=False, lead_name="ai-osint-lead2")
        self.assertEqual(self.rules("ai-osint-lead2"), ENDPOINT)
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.lead, p.model), ("ai-osint-lead2", "api.anthropic.com:443"))
        # A new lead with no network takes no model and gets no firewall.
        fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="none",
                       keep_old=False, lead_name="ai-osint-lead3")
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.model, p.lead_firewall), (None, None))


# ======================================================================= proposals

class FirewallProposals(ProjectBase):
    def submit(self, req):
        out = io.StringIO()
        from qmcp import services
        services.main("qmcp.SubmitProposal", stdin=io.BytesIO(json.dumps(req).encode()),
                      environ={"QREXEC_REMOTE_DOMAIN": HUB}, app_factory=lambda: self.app, out=out)
        return json.loads(out.getvalue())

    def test_the_hub_proposes_and_the_operator_compares_and_ticks(self):
        fleet.set_lead_firewall(self.app, "osint", accept_current=True)
        r = self.submit({"type": "project-firewall", "title": "the API", "project": "osint",
                         "model": "API.Anthropic.com:443"})
        self.assertTrue(r["ok"], r)
        doc = proposals.show(self.app, r["id"])
        self.assertEqual(doc["before"]["accepted"], ["action=accept"])
        self.assertEqual(doc["before"]["live"], ["action=accept"])
        self.assertEqual(doc["after"], {"model": "api.anthropic.com:443", "model_qube": None,
                                        "rules": firewall.endpoint_rules("api.anthropic.com:443")})
        self.assertEqual(len(doc["second_tick"]), 1)
        self.assertIn("compare the old and new rules", doc["second_tick"][0])
        with self.assertRaises(proposals.Refused):                 # never one click
            proposals.accept(self.app, r["id"], doc["sha256"])
        ok, report = proposals.accept(self.app, r["id"], doc["sha256"], tick=doc["tick"])
        self.assertTrue(ok, report)
        self.assertEqual(list(projects.find(self.records(), "osint").lead_firewall), ENDPOINT)
        self.assertEqual(self.app.domains[LEAD].__dict__["_firewall"], ENDPOINT)

    def test_a_proposal_stored_by_0_9_20_still_reads_back(self):
        # Fields added in 0.9.21 join the normal form only when given.
        old = {"type": "project-lead", "title": "t", "project": "osint", "remove": False,
               "lead": {"from": "template", "qube": "ai-debian-13"}, "lead_netvm": None,
               "lead_name": "ai-osint-lead2", "keep_old": True}
        self.assertEqual(proposals.normalise(old), old)
        self.assertEqual(proposals.normalise(dict(old, add_old_network=False)), old)

    def test_rules_from_the_hub_are_checked_before_they_are_stored(self):
        for rules in (["action=accept comment=x"], [], ["action=drop"] * 33, "action=drop"):
            r = self.submit({"type": "project-firewall", "title": "t", "project": "osint",
                             "rules": rules})
            self.assertFalse(r["ok"], rules)


# ======================================================================= the pre-commit audit

class AuditFixes(ProjectBase):
    """Regression tests for the M3a audit (2026-10-04). Each fails on the code as
    it stood before its fix."""

    def spy_firewall_set(self, name):
        """Record the qube's tags at each admin.vm.firewall.Set dom0 sends it."""
        seen, real = [], self.app.qubesd_call

        def call(dest, method, arg=None, payload=None):
            if dest == name and method == "admin.vm.firewall.Set":
                seen.append(set(self.app.domains._any(dest).tags))
            return real(dest, method, arg, payload)
        self.app.qubesd_call = call
        return seen

    # The rules are written while qmcp-lead already stops the hub (A8)
    # and before the slot's lead badge exists.
    def test_a_fresh_leads_rules_are_written_under_qmcp_lead_and_before_its_slot_badge(self):
        seen = self.spy_firewall_set("ai-res-lead")
        fleet.create_project(self.app, "res", "template", "ai-debian-13", networks=["none"],
                             quota="1G", lead_netvm="ai-net-router", model="api.anthropic.com:443")
        self.assertEqual(len(seen), 1)
        self.assertIn("qmcp-lead", seen[0])
        self.assertNotIn("qmcp-lead-p03", seen[0])

    def test_a_promoted_leads_rules_are_written_under_qmcp_lead_and_before_its_slot_badge(self):
        seen = self.spy_firewall_set("ai-hubq")
        fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"], quota="1G",
                             model="api.anthropic.com:443")
        self.assertIn("qmcp-lead", seen[0])
        self.assertNotIn("qmcp-lead-p03", seen[0])

    def test_a_promoted_lead_given_no_network_is_off_it_before_its_slot_badge(self):
        # The rulebook routes on the slot's lead badge: the qube must never hold
        # it while still on the network it is leaving.
        hubq = self.app.domains["ai-hubq"]
        net = hubq.netvm.name
        seen, real_add = [], hubq.tags.add

        def add(tag):
            if tag == "qmcp-lead-p03":
                seen.append(hubq.netvm)
            return real_add(tag)
        hubq.tags.add = add
        fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"],
                             quota="1G", lead_netvm="none")
        self.assertEqual(seen, [None])
        # And a failure at that badge gives it back the network it had.
        fleet.delete_project(self.app, "prom")
        self.app.vm("ai-hubq2", template=self.app.domains["ai-debian-13"],
                    netvm=self.app.domains[net], tags=("ai-managed", "qmcp-proj-p00"))
        self.app.fail.add("tag.add:qmcp-lead-p03")
        with self.assertRaises(Exception):
            fleet.create_project(self.app, "prom2", "promote", "ai-hubq2", networks=["none"],
                                 quota="1G", lead_netvm="none")
        self.assertEqual(self.app.domains["ai-hubq2"].netvm.name, net)
        self.assertEqual(self.tags("ai-hubq2"), {"ai-managed", "qmcp-proj-p00"})

    def test_rules_someone_else_wrote_in_between_are_never_accepted(self):
        # A write that lands between dom0's Set and its read-back (the hub's,
        # before A8 could apply) makes the read-back differ: the lead is undone.
        real = self.app.qubesd_call

        def call(dest, method, arg=None, payload=None):
            out = real(dest, method, arg, payload)
            if dest == "ai-res-lead" and method == "admin.vm.firewall.Set":
                # As many rules as dom0 wrote, so only the content can tell them apart.
                self.app.domains._any(dest).__dict__["_firewall"] = [
                    "action=accept dsthost=exfil.example proto=tcp dstports=443-443",
                    "action=accept specialtarget=dns", "action=accept"]
            return out
        self.app.qubesd_call = call
        with self.assertRaises(Exception):
            fleet.create_project(self.app, "res", "template", "ai-debian-13", networks=["none"],
                                 quota="1G", lead_netvm="ai-net-router", model="api.anthropic.com:443")
        self.assertNotIn("ai-res-lead", self.app.domains)
        self.assertIsNone(projects.find(self.records(), "res"))

    # A model endpoint the hub proposes is never one click
    def test_a_new_model_endpoint_needs_the_second_tick(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        records = self.records()
        lead = proposals.normalise({"type": "project-lead", "title": "t", "project": "osint",
                                    "keep_old": True, "lead": {"from": "template", "qube": "ai-debian-13"},
                                    "lead_netvm": "ai-net-router", "lead_name": "ai-osint-lead2",
                                    "model": "exfil.example:443"})
        reasons = proposals.second_tick(self.app, lead, records)
        self.assertTrue(any("exfil.example:443" in r and "api.anthropic.com:443" in r for r in reasons),
                        reasons)
        same = dict(lead, model="api.anthropic.com:443")
        self.assertFalse(any("model endpoint" in r for r in proposals.second_tick(self.app, same, records)))
        create = proposals.normalise({"type": "project-create", "title": "t", "label": "res",
                                      "lead": {"from": "template", "qube": "ai-debian-13"},
                                      "lead_netvm": "ai-net-router", "networks": ["none"], "quota": 1,
                                      "model": "exfil.example:443"})
        self.assertTrue(any("no project uses today" in r for r in proposals.second_tick(self.app, create, records)))
        used = dict(create, model="api.anthropic.com:443")
        self.assertFalse(any("model endpoint" in r for r in proposals.second_tick(self.app, used, records)))

    # A network that cannot be read is never "no network"
    def test_an_unreadable_network_is_never_read_as_none(self):
        self.app.domains["ai-work2"].netvm = self.app.domains["sys-firewall"]
        self.app.fail.add("get.netvm:ai-work2")
        f = findings(self.app)
        self.assertEqual(f["AI networks"].status, "error")
        self.assertNotEqual(fleet.overall(list(f.values())), "GREEN")
        self.app.fail.discard("get.netvm:ai-work2")
        fleet.set_lead_firewall(self.app, "osint", accept_current=True)
        self.app.fail.add(f"get.netvm:{LEAD}")
        self.assertEqual(findings(self.app)["lead firewalls"].status, "error")
        self.app.fail.discard(f"get.netvm:{LEAD}")
        self.app.fail.add("get.netvm:personal")
        with self.assertRaises(fleet.RoleError):
            fleet.manage(self.app, "personal")
        self.app.fail.discard("get.netvm:personal")
        self.app.fail.add("get.netvm:ai-osint-w2")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.edit_project(self.app, "osint", networks=["ai-net-router"])     # drops none
        self.assertIn("unreadable", str(cm.exception))

    # A record that would not validate is refused before the old lead is touched
    def test_adding_a_ninth_network_is_refused_before_the_old_lead_is_demoted(self):
        for i in range(6):
            self.app.vm(f"gw{i}", provides_network=True, features={"qubes-firewall": "1"})
            self.enroll(f"gw{i}")
        fleet.edit_project(self.app, "osint", networks=["ai-net-router", "none"] + [f"gw{i}" for i in range(6)])
        self.app.vm("gw-old", provides_network=True, features={"qubes-firewall": "1"})
        self.enroll("gw-old")
        self.app.domains[LEAD].netvm = self.app.domains["gw-old"]
        before = self.tags(LEAD)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead(self.app, "osint", "template", "ai-debian-13", lead_netvm="none",
                           keep_old=True, lead_name="ai-osint-lead2", add_old_network=True)
        self.assertIn("8 networks", str(cm.exception))
        self.assertEqual(self.tags(LEAD), before)
        self.assertEqual(projects.find(self.records(), "osint").lead, LEAD)

    # The gateway commands wait for a create in flight
    def test_gateway_commands_hold_the_create_lock(self):
        from qmcp import budget
        held = budget.acquire_create_lock()
        try:
            for call in (lambda: fleet.enroll_gateway(self.app, "ai-gw-unbadged"),
                         lambda: fleet.set_gateway(self.app, "ai-net-router", label="x"),
                         lambda: fleet.remove_gateway(self.app, "ai-net-router")):
                with self.assertRaises(fleet.RoleError) as cm:
                    call()
                self.assertIn("create is in progress", str(cm.exception))
        finally:
            import os
            os.close(held)

    # No network moves, a promoted lead's included
    def test_a_promoted_lead_keeps_its_network_or_loses_it(self):
        self.app.vm("gw-b", provides_network=True, features={"qubes-firewall": "1"})
        self.enroll("gw-b")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"], quota="1G",
                                 lead_netvm="gw-b", model="api.anthropic.com:443")
        self.assertIn("keeps its own network", str(cm.exception))
        self.assertEqual(self.app.domains["ai-hubq"].netvm.name, "ai-net-router")
        with self.assertRaises(proposals.Invalid):
            proposals.normalise({"type": "project-create", "title": "t", "label": "prom",
                                 "lead": {"from": "promote", "qube": "ai-hubq"}, "lead_netvm": "gw-b",
                                 "networks": ["none"], "quota": 1})
        fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"], quota="1G",
                             lead_netvm="none")
        self.assertIsNone(self.app.domains["ai-hubq"].netvm)

    def test_a_failed_promotion_restores_rules_qmcp_would_not_write(self):
        hubq = self.app.domains["ai-hubq"]
        hubq.__dict__["_firewall"] = ["action=accept dsthost=example.org comment=the operator's", "action=drop"]
        before = list(hubq.__dict__["_firewall"])
        self.app.fail.add("tag.add:qmcp-lead-p03")
        with self.assertRaises(Exception):
            fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"],
                                 quota="1G", model="api.anthropic.com:443")
        self.assertEqual(hubq.__dict__["_firewall"], before)

    def test_a_write_that_does_not_read_back_puts_the_old_rules_back(self):
        fleet.set_lead_firewall(self.app, "osint", model="api.anthropic.com:443")
        before = list(self.app.domains[LEAD].__dict__["_firewall"])
        real = self.app.qubesd_call

        def call(dest, method, arg=None, payload=None):
            out = real(dest, method, arg, payload)
            if dest == LEAD and method == "admin.vm.firewall.Set" and b"example.net" in (payload or b""):
                self.app.domains[LEAD].__dict__["_firewall"].append("action=accept")   # someone else
            return out
        self.app.qubesd_call = call
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.set_lead_firewall(self.app, "osint", rules=["action=accept proto=tcp dsthost=example.net "
                                                              "dstports=443", "action=drop"])
        self.assertIn("put back as they were", str(cm.exception))
        self.assertEqual(self.app.domains[LEAD].__dict__["_firewall"], before)
        self.assertEqual(list(projects.find(self.records(), "osint").lead_firewall), before)

    def test_an_undo_that_does_not_finish_is_reported(self):
        self.app.fail.update({"tag.add:qmcp-lead-p03", "tag.discard:qmcp-lead"})
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.create_project(self.app, "prom", "promote", "ai-hubq", networks=["none"],
                                 quota="1G", model="api.anthropic.com:443")
        self.assertIn("undoing it did not finish", str(cm.exception))

    def test_a_lead_firewall_proposal_carries_a_model_or_rules_never_both(self):
        for extra in ({}, {"model": "a.example:1", "rules": ["action=drop"]}):
            with self.assertRaises(proposals.Invalid, msg=extra):
                proposals.normalise({"type": "project-firewall", "title": "t", "project": "osint",
                                     **extra})

    def test_a_proposal_stored_by_0_9_20_reads_back_pending(self):
        # The bytes a 0.9.20 store held for a lead change are what this one
        # writes for it; its file loads, in normal form, and stays pending.
        pid, _, _ = proposals.submit(proposals.normalise({
            "type": "project-lead", "title": "t", "project": "osint", "keep_old": True,
            "lead": {"from": "template", "qube": "ai-debian-13"}, "lead_name": "ai-osint-lead2"}), HUB)
        e = [x for x in proposals.entries() if x.id == pid][0]
        self.assertIsNone(e.problem)
        self.assertNotIn("model", e.proposal)
        self.assertEqual(proposals.show(self.app, pid)["state"], "pending")


# ======================================================================= the firewall module

class FirewallModule(unittest.TestCase):
    def test_models(self):
        self.assertEqual(firewall.model_text("API.Anthropic.com:443"), "api.anthropic.com:443")
        self.assertEqual(firewall.model_text("192.0.2.5:11434"), "192.0.2.5:11434")
        for bad in ("api.anthropic.com", "a:b:c", ":443", "a.b:0", "a.b:65536", "a b:1",
                    "-a.b:1", "a..b:1", 443, None, "[::1]:443"):
            with self.assertRaises(firewall.FirewallError, msg=bad):
                firewall.model_text(bad)

    def test_rules(self):
        self.assertIsNone(firewall.rules_refusal(firewall.endpoint_rules("h.example:1")))
        for bad in (["action=accept expire=+60"], ["comment=x action=accept"], ["action=accept\tx=1"]):
            self.assertIsNotNone(firewall.rules_refusal(bad), bad)

    def test_qubesds_own_spelling_is_the_same_rule(self):
        # As qubesd states each back: the first three forms measured on Qubes
        # 4.3.1, the rest read from its DstHost and DstPorts.
        for written, read in (
                ("action=accept proto=tcp dsthost=example.com dstports=443",
                 "action=accept dsthost=example.com proto=tcp dstports=443-443"),
                ("action=drop dsthost=1.2.3.4", "action=drop dst4=1.2.3.4/32"),
                ("action=accept proto=icmp dst4=198.51.100.0/24 icmptype=8",
                 "action=accept dst4=198.51.100.0/24 proto=icmp icmptype=8"),
                ("action=drop dst4=192.0.2.7", "action=drop dst4=192.0.2.7/32"),
                ("action=drop dsthost=2001:DB8::0:1", "action=drop dst6=2001:db8::1/128"),
                ("action=drop dst6=2001:db8::1", "action=drop dst6=2001:db8::1/128"),
                ("action=accept proto=tcp dsthost=a.example dstports=0443",
                 "action=accept dsthost=a.example proto=tcp dstports=443-443")):
            self.assertTrue(firewall.same_rules([written], [read]), written)
        # Another rule, another port, one rule more: never the same.
        for read in (["action=accept dsthost=example.com proto=tcp dstports=444-444"],
                     ["action=accept dsthost=example.org proto=tcp dstports=443-443"],
                     ["action=accept dsthost=example.com proto=tcp dstports=443-443", "action=accept"]):
            self.assertFalse(firewall.same_rules(["action=accept proto=tcp dsthost=example.com "
                                                  "dstports=443"], read), read)


class _Qubesd:
    """A qubesd that stores what is Set, or, with `other`, someone else's rules."""
    def __init__(self, rules=("action=accept",), other=None):
        self.rules, self.other, self.sets = list(rules), other, 0

    def qubesd_call(self, dest, method, arg=None, payload=None):
        if method == "admin.vm.firewall.Set":
            self.sets += 1
            self.rules = list(self.other) if self.other else payload.decode().splitlines()
        return "".join(f"{r}\n" for r in self.rules).encode()


class FirewallWrites(unittest.TestCase):
    def test_a_write_sends_only_qmcps_own_format(self):
        q = _Qubesd()
        with self.assertRaises(firewall.FirewallError):
            firewall.write_rules(q, "x", ["action=accept comment=x"])
        self.assertEqual(q.sets, 0)

    def test_a_restore_that_does_not_read_back_raises(self):
        firewall.restore_rules(_Qubesd(), "x", ["action=drop"])
        with self.assertRaises(firewall.FirewallError):
            firewall.restore_rules(_Qubesd(other=["action=accept"]), "x", ["action=drop"])


class RegistryReadErrors(unittest.TestCase):
    def test_every_read_or_parse_error_is_unreadable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "gateways.json"
            for data in (b"\xff\xfe not utf-8", b"[" * 100000):
                path.write_bytes(data)
                with self.assertRaises(gateways.GatewaysUnreadable, msg=data[:8]):
                    gateways.load(str(path))
                self.assertEqual(gateways.enrolled_names(str(path)), frozenset())
            path.unlink()
            path.mkdir()                                      # there, and not readable as a file
            with self.assertRaises(gateways.GatewaysUnreadable):
                gateways.load(str(path))
            self.assertEqual(gateways.enrolled_names(str(path)), frozenset())


if __name__ == "__main__":
    unittest.main()
