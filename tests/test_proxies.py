"""Offline suite for project proxies (1.2.0).

A project proxy is a member of one slot that provides network to that slot's
members only. AI has root in it, so its clients' own firewall rules are only
advisory (measured on Qubes 4.3.2); what bounds them is the proxy's
own network, an enrolled gateway the slot may use, another proxy of the slot,
or none. These tests pin each half: what a principal may make and put behind
one, what the operator's move does, and what `qmcp check` proves.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import anon, core, fleet, projects  # noqa: E402
from fakequbes import Injected  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_anon import policy_view  # noqa: E402
from test_projects import LEAD, OTHER_LEAD, ProjectBase  # noqa: E402

PX = "ai-osint-px"
NO_NET = "netvm must be one of this project's worker networks"


def findings(app):
    return {f.check: f for f in fleet.check(app, legacy_paths=(), system_info={"domains": {}})}


class ProxyBase(ProjectBase):
    """The project fleet plus p01's proxy on the project's router."""

    def setUp(self):
        super().setUp()
        a = self.app
        a.vm(PX, template=a.domains["ai-debian-13"], netvm=a.domains["ai-net-router"],
             provides_network=True, tags={"ai-managed", "qmcp-proj-p01", core.PROXY})

    def spawn(self, lead=LEAD, **req):
        req.setdefault("name", "ai-osint-w3")
        req.setdefault("template", "ai-debian-13")
        return self.lcall("qmcp.SpawnAIManagedQube", req, lead=lead)


# ======================================================================= the core split

class GatewayOrProxy(ProxyBase):
    def test_a_proxy_is_no_gateway_and_is_managed(self):
        px, router = self.app.domains[PX], self.app.domains["ai-net-router"]
        self.assertTrue(core.is_netvm(px))
        self.assertFalse(core.is_gateway(px))
        self.assertFalse(core.is_guarded(px))
        self.assertEqual(core.state(px), "managed")
        self.assertTrue(core.is_gateway(router))

    def test_the_badge_alone_is_what_tells_them_apart(self):
        # Without the badge the same qube is a gateway, and so guarded.
        self.app.domains[PX].tags.discard(core.PROXY)
        self.assertTrue(core.is_gateway(self.app.domains[PX]))
        self.assertTrue(core.is_guarded(self.app.domains[PX]))

    def test_a_tag_read_that_fails_is_never_a_proxy(self):
        self.app.fail.add(f"tag.List:{PX}")
        self.assertTrue(core.is_guarded(self.app.domains[PX]))

    def test_the_lead_operates_its_proxy(self):
        r = self.lcall("qmcp.SetPropertyAIManaged", {"name": PX, "property": "memory",
                                                     "value": 800})
        self.assertTrue(r["ok"], r)


# ======================================================================= a principal's create

class LeadMakesProxies(ProxyBase):
    def test_a_spawn_with_provides_network_is_a_badged_proxy_of_the_project(self):
        r = self.spawn(name="ai-osint-px2", provides_network=True)
        self.assertEqual(r, {"ok": True, "name": "ai-osint-px2"})
        vm = self.app.domains["ai-osint-px2"]
        self.assertTrue(vm.provides_network)
        self.assertEqual(self.tags("ai-osint-px2"),
                         {"ai-managed", "qmcp-proj-p01", core.PROXY, f"qmcp-owner_{LEAD}"})
        self.assertEqual(vm.netvm.name, "ai-net-router")

    def test_the_badge_is_on_before_provides_network(self):
        self.spawn(name="ai-osint-px2", provides_network=True)
        seen = [tags for name, tags in self.app.tag_log if name == "ai-osint-px2"]
        self.assertIn(core.PROXY, seen[-1])
        # Every moment it wore the umbrella it did not yet provide network
        # without the badge: the badge went on in the stamp, the flag after.
        self.assertTrue(any(core.PROXY in t and "ai-managed" in t for t in seen))

    def test_a_standalone_may_be_one(self):
        r = self.spawn(name="ai-osint-sa", klass="StandaloneVM", provides_network=True)
        self.assertTrue(r["ok"], r)
        self.assertTrue(self.app.domains["ai-osint-sa"].provides_network)

    def test_a_disposable_never_is(self):
        r = self.spawn(name="ai-osint-d", klass="DispVM", template="ai-dvm",
                       provides_network=True)
        self.assertFalse(r["ok"])
        self.assertIn("can provide network", r["error"])

    def test_the_flag_is_a_boolean(self):
        for bad in ("yes", 1, None, [True]):
            r = self.spawn(name="ai-osint-px9", provides_network=bad)
            self.assertFalse(r["ok"], bad)
            self.assertEqual(r["error"], "provides_network must be true or false", bad)
        self.assertNotIn("ai-osint-px9", self.app.domains)

    def test_a_failed_flag_write_rolls_the_qube_back(self):
        self.app.fail.add("set.provides_network")
        r = self.spawn(name="ai-osint-px2", provides_network=True)
        self.assertFalse(r["ok"])
        self.assertNotIn("ai-osint-px2", self.app.domains)

    def test_a_later_flip_stays_the_operators(self):
        r = self.lcall("qmcp.SetPropertyAIManaged", {"name": "ai-osint-w1",
                                                     "property": "provides_network",
                                                     "value": True})
        self.assertFalse(r["ok"])
        self.assertFalse(self.app.domains["ai-osint-w1"].provides_network)

    def test_a_proxy_is_never_cloned(self):
        r = self.lcall("qmcp.CloneAIManagedQube", {"source": PX, "name": "ai-osint-px3"})
        self.assertEqual(r, {"ok": False, "error": "a qube that provides network is not "
                                                   "cloned; spawn a new proxy"})
        self.assertNotIn("ai-osint-px3", self.app.domains)

    def test_audit_names_the_flag_only_when_given(self):
        self.spawn(name="ai-osint-w3")
        self.spawn(name="ai-osint-px2", provides_network=True)
        lines = [l for l in self.audit_lines() if l.get("service") == "qmcp.SpawnAIManagedQube"]
        self.assertNotIn("provides_network", lines[-2]["args"])
        self.assertIs(lines[-1]["args"]["provides_network"], True)


class LeadPutsQubesBehindProxies(ProxyBase):
    def test_a_worker_born_on_the_projects_proxy(self):
        r = self.spawn(netvm=PX)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.app.domains["ai-osint-w3"].netvm.name, PX)

    def test_a_chain_of_the_projects_proxies(self):
        self.assertTrue(self.spawn(name="ai-osint-px2", provides_network=True, netvm=PX)["ok"])
        r = self.spawn(netvm="ai-osint-px2")
        self.assertTrue(r["ok"], r)

    def test_an_internal_lan_on_a_proxy_with_no_network(self):
        self.assertTrue(self.spawn(name="ai-osint-lan", provides_network=True, netvm=None)["ok"])
        self.assertTrue(self.spawn(netvm="ai-osint-lan")["ok"])

    def test_every_other_name_answers_alike(self):
        a = self.app
        # Another project's proxy, a member that is no proxy, a gateway outside
        # the list, a qube outside AI space and a name nobody has: one reply.
        a.vm("ai-other-px", template=a.domains["ai-debian-13"], netvm=None,
             provides_network=True, tags={"ai-managed", "qmcp-proj-p02", core.PROXY})
        for name in ("ai-other-px", "ai-osint-w1", "ai-gw-unbadged", "sys-firewall",
                     "no-such-qube", LEAD):
            r = self.spawn(netvm=name)
            self.assertEqual(r, {"ok": False, "error": NO_NET}, name)
        self.assertNotIn("ai-osint-w3", a.domains)

    def test_a_proxy_whose_chain_leaves_the_list_is_refused(self):
        a = self.app
        a.vm("ai-osint-pxoff", template=a.domains["ai-debian-13"], netvm=a.domains["sys-firewall"],
             provides_network=True, tags={"ai-managed", "qmcp-proj-p01", core.PROXY})
        self.assertEqual(self.spawn(netvm="ai-osint-pxoff"), {"ok": False, "error": NO_NET})

    def test_a_chain_through_another_projects_proxy_is_refused(self):
        a = self.app
        a.vm("ai-other-px", template=a.domains["ai-debian-13"], netvm=a.domains["ai-net-router"],
             provides_network=True, tags={"ai-managed", "qmcp-proj-p02", core.PROXY})
        a.domains[PX]._props["netvm"] = a.domains["ai-other-px"]
        self.assertEqual(self.spawn(netvm=PX), {"ok": False, "error": NO_NET})

    def test_a_badge_without_the_flag_serves_nothing(self):
        self.app.domains[PX]._props["provides_network"] = False
        self.assertEqual(self.spawn(netvm=PX), {"ok": False, "error": NO_NET})

    def test_a_clone_of_a_client_stays_behind_the_proxy(self):
        self.assertTrue(self.spawn(netvm=PX)["ok"])
        r = self.lcall("qmcp.CloneAIManagedQube", {"source": "ai-osint-w3", "name": "ai-osint-w4"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.app.domains["ai-osint-w4"].netvm.name, PX)

    def test_a_proxy_that_stops_being_one_while_the_call_waits(self):
        # Judged again under the create lock.
        from qmcp import budget
        real = budget.acquire_create_lock

        def strip():
            self.app.domains[PX].tags.discard(core.PROXY)
            return real()
        budget.acquire_create_lock = strip
        self.addCleanup(setattr, budget, "acquire_create_lock", real)
        self.assertEqual(self.spawn(netvm=PX), {"ok": False, "error": NO_NET})
        self.assertNotIn("ai-osint-w3", self.app.domains)


class HubProxies(ProxyBase):
    def setUp(self):
        super().setUp()
        self.egress("ai-net-router")

    def test_the_hubs_proxy_joins_p00(self):
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-px", "template": "ai-debian-13",
                                                  "provides_network": True})
        self.assertTrue(r["ok"], r)
        self.assertIn("qmcp-proj-p00", self.tags("ai-hub-px"))
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-w", "template": "ai-debian-13",
                                                  "netvm": "ai-hub-px"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.app.domains["ai-hub-w"].netvm.name, "ai-hub-px")

    def test_a_p00_proxy_on_another_gateway_opens_no_new_way_out(self):
        a = self.app
        a.vm("ai-other-gw", provides_network=True, netvm=a.domains["sys-firewall"],
             tags={"ai-managed", "qmcp-guarded"}, features={"qubes-firewall": "1"})
        self.enroll("ai-other-gw")
        a.vm("ai-hub-px", template=a.domains["ai-debian-13"], netvm=a.domains["ai-other-gw"],
             provides_network=True, tags={"ai-managed", "qmcp-proj-p00", core.PROXY})
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-w", "template": "ai-debian-13",
                                                  "netvm": "ai-hub-px"})
        self.assertEqual(r, {"ok": False, "error": "netvm must be an enrolled gateway"})

    def test_the_hub_cannot_use_a_projects_proxy_for_p00(self):
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-w", "template": "ai-debian-13",
                                                  "netvm": PX})
        self.assertEqual(r, {"ok": False, "error": "netvm must be an enrolled gateway"})

    def test_the_hubs_disposables_are_in_no_slot_so_on_no_proxy(self):
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-d", "template": "ai-dvm",
                                                  "klass": "DispVM", "netvm": PX})
        self.assertFalse(r["ok"])


# ======================================================================= the operator's move

class OperatorMove(ProxyBase):
    def test_move_proxy_badges_then_provides_network(self):
        report = fleet.move(self.app, "ai-osint-w2", "osint", proxy=True)
        self.assertFalse(report.failed, report)
        vm = self.app.domains["ai-osint-w2"]
        self.assertTrue(vm.provides_network)
        self.assertIn(core.PROXY, self.tags("ai-osint-w2"))
        self.assertTrue(any("a proxy of p01" in line for line in report), report)

    def test_a_proxy_never_goes_to_no_slot(self):
        with self.assertRaises(fleet.ProjectError):
            fleet.move(self.app, "ai-osint-w2", "none", proxy=True)
        with self.assertRaises(fleet.ProjectError):
            fleet.move(self.app, PX, "none")

    def test_a_qube_already_providing_network_is_a_gateway_not_a_candidate(self):
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.move(self.app, "ai-gw-unbadged", "osint", proxy=True)
        self.assertIn("--proxy sets it", str(cm.exception))

    def test_a_lead_is_never_a_proxy(self):
        with self.assertRaises(fleet.ProjectError):
            fleet.move(self.app, LEAD, "osint", proxy=True)

    def test_a_proxy_in_use_does_not_move(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.move(a, PX, "p00", confirm=True)
        self.assertIn("serves ai-osint-w1", str(cm.exception))

    def test_a_client_does_not_follow_into_another_slot(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.move(a, "ai-osint-w1", "p00", confirm=True)
        self.assertIn("a proxy of another slot", str(cm.exception))

    def test_a_proxy_is_never_enrolled(self):
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.enroll_gateway(self.app, PX)
        self.assertIn("project proxy", str(cm.exception))

    def test_delete_removes_a_projects_chain_whole(self):
        a = self.app
        a.vm("ai-osint-px2", template=a.domains["ai-debian-13"], netvm=a.domains[PX],
             provides_network=True, tags={"ai-managed", "qmcp-proj-p01", core.PROXY})
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains["ai-osint-px2"]
        a.domains["ai-osint-w2"].kill()
        report = fleet.delete_project(a, "osint")
        self.assertFalse(report.failed, report)
        for n in (PX, "ai-osint-px2", "ai-osint-w1", "ai-osint-w2"):
            self.assertNotIn(n, a.domains, n)
        removed = [l.split("removed ", 1)[1] for l in report if ": removed " in l]
        self.assertLess(removed.index("ai-osint-w1"), removed.index("ai-osint-px2"))
        self.assertLess(removed.index("ai-osint-px2"), removed.index(PX))

    def test_delete_removes_clients_before_their_proxy(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        order = fleet._clients_first(a, sorted(["ai-osint-w1", PX, "ai-osint-w2"]))
        self.assertLess(order.index("ai-osint-w1"), order.index(PX))


class AuditFixes(ProxyBase):
    def test_revoking_a_client_clears_its_proxy_network_first(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        out = fleet.revoke(a, "ai-osint-w1")
        self.assertIsNone(a.domains["ai-osint-w1"].netvm)
        self.assertIn(f"its network {PX}, a project proxy, was cleared", out)
        self.assertNotIn("ai-managed", self.tags("ai-osint-w1"))

    def test_a_client_whose_network_does_not_read_is_revoked_and_says_so(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        a.fail_reads("get.netvm:ai-osint-w1", "fail")
        with self.assertRaises(fleet.RoleError) as cm:      # the report's problems raise
            fleet.revoke(a, "ai-osint-w1")
        self.assertIn("could not be read", str(cm.exception))
        self.assertNotIn("ai-managed", self.tags("ai-osint-w1"))

    def test_a_proxys_revoke_takes_the_create_lock(self):
        from qmcp import budget
        taken = []
        real = budget.acquire_create_lock
        budget.acquire_create_lock = lambda **kw: taken.append(1) or real(**kw)
        self.addCleanup(setattr, budget, "acquire_create_lock", real)
        fleet.revoke(self.app, PX)
        self.assertTrue(taken)
        taken.clear()
        fleet.revoke(self.app, "ai-osint-w2")
        self.assertFalse(taken)

    def test_a_qube_that_became_a_proxy_unlocked_is_not_revoked(self):
        with self.assertRaises(fleet.RoleError) as cm:
            fleet._revoke(self.app, PX, project_locked=False)
        self.assertIn("became a project proxy", str(cm.exception))
        self.assertIn("ai-managed", self.tags(PX))

    def test_a_proxy_that_serves_anyone_is_not_revoked(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(a, PX)
        self.assertIn("serves ai-osint-w1", str(cm.exception))
        self.assertIn("ai-managed", self.tags(PX))

    def test_a_revoked_proxy_keeps_no_proxy_badge(self):
        fleet.revoke(self.app, PX)
        self.assertNotIn(core.PROXY, self.tags(PX))
        self.assertTrue(core.is_gateway(self.app.domains[PX]))

    def test_a_stray_badge_exempts_nothing(self):
        a = self.app
        stray = a.vm("ai-stray", template=a.domains["ai-debian-13"], netvm=None,
                     provides_network=True, tags={core.PROXY})
        self.assertTrue(core.is_gateway(stray))
        with self.assertRaises(fleet.RoleError):
            fleet.manage(a, "ai-stray")
        a.domains[PX].tags.add("qmcp-proj-p02")          # two slots
        self.assertTrue(core.is_gateway(a.domains[PX]))

    def test_a_held_or_stopped_proxy_serves_no_new_qube(self):
        for badge in (core.QUARANTINE, projects.BLOCKED, projects.STOPPED):
            self.app.domains[PX].tags.add(badge)
            r = self.spawn(netvm=PX)
            self.assertEqual(r, {"ok": False, "error": NO_NET}, badge)
            self.app.domains[PX].tags.discard(badge)

    def test_a_client_start_does_not_wake_a_held_proxy(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        a.domains[PX].tags.add(core.QUARANTINE)
        r = self.lcall("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "start"})
        self.assertEqual(r, core.QUARANTINE_REFUSAL)
        a.domains[PX].tags.discard(core.QUARANTINE)
        a.domains[PX].tags.add(projects.STOPPED)
        r = self.lcall("qmcp.LifecycleAIManaged", {"name": "ai-osint-w1", "action": "start"})
        self.assertEqual(r, core.BLOCKED_REFUSAL)
        self.assertFalse(a.domains["ai-osint-w1"].is_running())

    def test_a_disposable_template_on_a_proxy_is_refused_on_both_paths(self):
        a = self.app
        a.domains["ai-dvm"]._props["netvm"] = a.domains[PX]
        r = self.spawn(name="ai-osint-d1", klass="DispVM", template="ai-dvm")
        self.assertFalse(r["ok"])
        r = self.lcall("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertFalse(r["ok"])


# ======================================================================= qmcp check

class CheckProves(ProxyBase):
    def item(self):
        return findings(self.app)["project proxies"]

    def test_a_sound_proxy_passes_and_its_clients_are_not_loose(self):
        self.app.domains["ai-osint-w1"]._props["netvm"] = self.app.domains[PX]
        f = findings(self.app)
        self.assertEqual(f["project proxies"].status, "pass", f["project proxies"].detail)
        self.assertEqual(f["AI networks"].status, "pass", f["AI networks"].detail)
        # The standard fleet's own unbadged gateway is the only loose one.
        self.assertEqual(f["gateways guarded"].detail,
                         "gateway(s) without qmcp-guarded: ai-gw-unbadged (qmcp guard <qube>)")

    def test_serving_another_project_fails(self):
        self.app.domains["ai-other-w1"]._props["netvm"] = self.app.domains[PX]
        self.assertEqual(self.item().status, "fail")
        self.assertIn("serves ai-other-w1", self.item().detail)

    def test_serving_a_qube_outside_ai_space_fails(self):
        self.app.domains["personal"]._props["netvm"] = self.app.domains[PX]
        self.assertIn("serves personal", self.item().detail)

    def test_a_lead_behind_a_proxy_fails(self):
        self.app.domains[LEAD]._props["netvm"] = self.app.domains[PX]
        self.assertEqual(self.item().status, "fail")
        self.assertIn("lead", self.item().detail)

    def test_a_lead_wearing_a_member_badge_behind_a_proxy_fails_as_a_lead(self):
        self.app.domains[LEAD].tags.add("qmcp-proj-p01")
        self.app.domains[LEAD]._props["netvm"] = self.app.domains[PX]
        self.assertIn(f"serves the lead {LEAD}", self.item().detail)

    def test_a_proxy_that_is_a_lead_fails(self):
        self.app.domains[OTHER_LEAD].tags.add(core.PROXY)
        self.assertEqual(self.item().status, "fail")

    def test_a_proxy_in_no_slot_or_two_fails(self):
        self.app.domains[PX].tags.discard("qmcp-proj-p01")
        self.assertIn("no slot", self.item().detail)
        self.app.domains[PX].tags.add("qmcp-proj-p01")
        self.app.domains[PX].tags.add("qmcp-proj-p02")
        self.assertIn("not of one", self.item().detail)

    def test_a_proxy_on_a_network_its_project_does_not_list_fails(self):
        self.app.domains[PX]._props["netvm"] = self.app.domains["sys-firewall"]
        self.assertIn("neither a network p01 may use", self.item().detail)

    def test_a_model_qube_proxy_fails(self):
        self.app.domains[PX].tags.add("qmcp-model-p01")
        self.assertIn("is a model qube", self.item().detail)

    def test_a_disposable_template_or_a_template_proxy_fails(self):
        self.app.domains[PX]._props["template_for_dispvms"] = True
        self.assertIn("is a disposable template", self.item().detail)
        self.app.domains["ai-debian-13"].tags.add(core.PROXY)
        self.assertIn("ai-debian-13 is a TemplateVM", self.item().detail)

    def test_a_proxy_outside_ai_space_fails(self):
        self.app.domains[PX].tags.discard("ai-managed")
        self.assertIn("is outside AI space", self.item().detail)

    def test_an_enrolled_proxy_fails(self):
        self.enroll(PX)
        self.assertIn("enrolled gateway", self.item().detail)

    def test_a_network_provider_without_the_badge_is_still_a_loose_gateway(self):
        self.app.domains[PX].tags.discard(core.PROXY)
        self.assertIn(PX, findings(self.app)["gateways guarded"].detail)

    def test_a_failed_network_read_is_an_error(self):
        self.app.fail.add(f"get.netvm:{PX}")
        self.assertNotEqual(self.item().status, "pass")

    def test_list_rows_say_which_is_a_proxy(self):
        rows = {r["name"]: r for r in fleet.listing(self.app, everything=True)}
        self.assertIs(rows[PX]["proxy"], True)
        self.assertIs(rows[PX]["gateway"], False)
        self.assertIs(rows["ai-net-router"]["proxy"], False)


# ======================================================================= qubesd, as measured

class FakeIsQubesd(ProxyBase):
    """What the fake refuses is what qubesd 4.3.2 refused on the box."""

    def test_a_netvm_must_provide_network(self):
        with self.assertRaises(Injected):
            self.app.domains["ai-osint-w1"].netvm = self.app.domains["ai-osint-w2"]

    def test_no_loop(self):
        a = self.app
        a.domains["ai-osint-w1"]._props["provides_network"] = True
        a.domains["ai-osint-w1"].netvm = a.domains[PX]
        with self.assertRaises(Injected):
            a.domains[PX].netvm = a.domains["ai-osint-w1"]

    def test_removing_one_in_use(self):
        a = self.app
        a.domains["ai-osint-w1"].netvm = a.domains[PX]
        with self.assertRaises(Injected):
            del a.domains[PX]

    def test_un_proxying_one_in_use(self):
        a = self.app
        a.domains["ai-osint-w1"].netvm = a.domains[PX]
        with self.assertRaises(Injected):
            a.domains[PX].provides_network = False


# ======================================================================= the anonymity gate

class AnonymousProjects(ProxyBase):
    def test_a_member_on_its_projects_proxy_is_on_the_lists_terms(self):
        a = self.app
        p = projects.find(self.records(), "osint")
        a.domains["ai-osint-w1"]._props["netvm"] = a.domains[PX]
        tags_by = {v.name: set(v.tags) for v in a.domains}
        by_name = {v.name: v for v in a.domains}
        view = policy_view(a)
        v = anon.evaluate(a, p, {}, view, by_name, tags_by)
        text = repr(v.problems)
        self.assertNotIn("the member ai-osint-w1 is on", text)
        # The control: a member on another project's qube still fails.
        a.domains["ai-osint-w2"]._props["netvm"] = a.domains["ai-gw-unbadged"]
        v = anon.evaluate(a, p, {}, view, by_name, tags_by)
        self.assertIn("the member ai-osint-w2 is on ai-gw-unbadged", repr(v.problems))


if __name__ == "__main__":
    unittest.main()
