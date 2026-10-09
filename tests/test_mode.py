"""Anonymous mode (0.9.24): every project anonymous, the gate judging the hub
and the rest of AI space; the operator's updates tick on an anonymising
gateway; and moves into, out of and between anonymous projects.

Against the fake qubesadmin, with dom0's update question asked of qrexec's
real parser (`test_anon.policy_view`)."""
from __future__ import annotations

import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import anon, audit, core, fleet, gateways, projects, services  # noqa: E402
import fakequbes  # noqa: E402
from fakequbes import GiB  # noqa: E402
from test_anon import AnonBase, anon_create, policy_view  # noqa: E402
from test_dom0 import HUB, Base  # noqa: E402

BLOCKED, STOPPED, ANON, HUBBLIND = (projects.BLOCKED, projects.STOPPED, projects.ANON,
                                    projects.HUBBLIND)


class ModeBase(Base):
    """A box set up for anonymous mode, as `install.sh --anonymous` leaves it:
    a Tor router behind `sys-whonix`, enrolled anonymising and ticked for
    updates; the hub on it, its template outside AI space; templates' updates
    going to `sys-whonix`; `qmcp-anon` on the hub and on everything in AI
    space; and the mode file written."""

    def setUp(self):
        super().setUp()
        a = self.app = fakequbes.FakeApp()
        a.vm("dom0", klass="AdminVM")
        net = a.vm("sys-net", provides_network=True)
        fw = a.vm("sys-firewall", provides_network=True, netvm=net)
        a.default_netvm = fw
        whonix = a.vm("sys-whonix", provides_network=True, netvm=fw, tags={"anon-gateway"})
        tor = a.vm("ai-net-tor", provides_network=True, netvm=whonix, power="Running",
                   tags={"ai-managed", "qmcp-guarded"}, features={"qubes-firewall": "1"})
        deb = a.default_template = a.vm("debian-13", klass="TemplateVM")
        a.default_dispvm = a.vm("default-dvm", template=deb, template_for_dispvms=True, netvm=fw)
        a.vm("ai-tpl-g", klass="TemplateVM", tags={"ai-managed", "qmcp-guarded", ANON})
        a.vm("ai-hub-tpl", klass="TemplateVM", tags={"ai-managed", ANON})
        a.vm(HUB, template=deb, netvm=tor, power="Running", tags={ANON})
        pathlib.Path(gateways.GATEWAYS_PATH).unlink()
        fleet.enroll_gateway(a, "ai-net-tor", anonymising=True, updates=True)
        self.updates_to, self.extra = "sys-whonix", ""
        self.notices = []
        for mod, attr, value in [
            (anon, "RETRY_WAIT_S", 0.0),
            (anon, "load_policy", lambda: policy_view(self.app, self.updates_to, self.extra)),
            (anon, "notify", lambda text: self.notices.append(text) or True),
            (anon, "TIMER_CHECK", lambda: True),
        ]:
            self._saved.append((mod, attr, getattr(mod, attr)))
            setattr(mod, attr, value)
        self.mode("anonymous")

    def mode(self, word):
        path = pathlib.Path(core.MODE_PATH)
        if word is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(word + "\n")

    def spawn(self, name, template="ai-tpl-g", klass="AppVM", **kw):
        r = self.call("qmcp.SpawnAIManagedQube", dict(name=name, template=template, klass=klass,
                                                      **kw))
        self.assertTrue(r["ok"], r)
        return self.app.domains[name]

    def hub_verdict(self, act=False):
        verdicts = anon.run(self.app, act=act)
        hub = [v for v in verdicts if v.is_hub]
        self.assertEqual(len(hub), 1, verdicts)
        return hub[0]

    def anonymous_project(self, hub_sees=False):
        before = set(projects.load())
        fleet.create_project(self.app, None, "template", "ai-tpl-g", networks=["ai-net-tor"],
                             quota="5G", lead_netvm="ai-net-tor", model="api.example.org:443",
                             hub_sees=hub_sees)
        slot = (set(projects.load()) - before).pop()
        return projects.load()[slot]


class ModeFile(ModeBase):
    def test_absent_is_normal_and_anything_but_anonymous_is_unreadable(self):
        self.assertTrue(core.anonymous_mode())
        self.mode(None)
        self.assertFalse(core.anonymous_mode())
        for word in ("normal", "Anonymous", "anonymous please", ""):
            self.mode(word)
            with self.assertRaises(core.ModeUnreadable):
                core.anonymous_mode()
        self.mode(None)
        pathlib.Path(core.MODE_PATH).mkdir()
        with self.assertRaises(core.ModeUnreadable):
            core.anonymous_mode()

    def test_settings_say_the_mode(self):
        self.assertEqual(fleet.settings(self.app)["mode"], "anonymous")
        self.mode(None)
        self.assertEqual(fleet.settings(self.app)["mode"], "normal")
        self.mode("x")
        self.assertEqual(fleet.settings(self.app)["mode"], core.UNREADABLE)


class Gateways(ModeBase):
    def setUp(self):
        super().setUp()
        a = self.app
        a.vm("sys-ai-net", provides_network=True, netvm=a.domains["sys-firewall"],
             features={"qubes-firewall": "1"})
        a.vm("sys-vpn", provides_network=True, netvm=a.domains["sys-firewall"],
             features={"qubes-firewall": "1"})

    def test_the_mode_enrolls_no_clearnet_gateway(self):
        with self.assertRaisesRegex(fleet.RoleError, "anonymous mode"):
            fleet.enroll_gateway(self.app, "sys-ai-net")
        with self.assertRaisesRegex(fleet.RoleError, "anonymous mode"):
            fleet.set_gateway(self.app, "ai-net-tor", anonymising=False)
        self.assertTrue(gateways.load()["ai-net-tor"].anonymising)
        self.mode("x")                          # cannot tell: refused, never normal
        with self.assertRaisesRegex(fleet.RoleError, "cannot be told"):
            fleet.enroll_gateway(self.app, "sys-ai-net")
        self.mode(None)
        self.assertIn("enrolled", fleet.enroll_gateway(self.app, "sys-ai-net"))

    def test_the_tick_needs_an_anonymising_gateway_with_a_recorded_network(self):
        self.mode(None)
        with self.assertRaisesRegex(fleet.RoleError, "--updates is for an anonymising"):
            fleet.enroll_gateway(self.app, "sys-ai-net", updates=True)
        fleet.enroll_gateway(self.app, "sys-ai-net")
        with self.assertRaisesRegex(fleet.RoleError, "not anonymising"):
            fleet.set_gateway(self.app, "sys-ai-net", updates=True)
        self.assertFalse(gateways.load()["sys-ai-net"].updates)
        # Unmarking takes the tick with it.
        fleet.enroll_gateway(self.app, "sys-vpn", anonymising=True, updates=True)
        fleet.set_gateway(self.app, "sys-vpn", anonymising=False)
        self.assertFalse(gateways.load()["sys-vpn"].updates)

    def test_the_registry_reads_the_tick_and_old_files(self):
        doc = json.loads(pathlib.Path(gateways.GATEWAYS_PATH).read_text())
        self.assertIs(doc["gateways"]["ai-net-tor"]["updates"], True)
        del doc["gateways"]["ai-net-tor"]["updates"]                # as 0.9.23 wrote it
        pathlib.Path(gateways.GATEWAYS_PATH).write_text(json.dumps(doc))
        self.assertFalse(gateways.load()["ai-net-tor"].updates)
        for bad in ({"anonymising": False, "label": "", "updates": True},
                    {"anonymising": True, "label": "", "updates": True},
                    {"anonymising": True, "label": "", "upstream": "x", "updates": 1},
                    {"anonymising": True, "label": "", "upstream": "x", "updates": "yes"}):
            text = json.dumps({"version": 1, "gateways": {"g": bad}})
            with self.assertRaises(gateways.GatewaysUnreadable, msg=bad):
                gateways.parse(text)

    def test_marking_again_keeps_the_tick_only_on_the_same_network(self):
        fleet.set_gateway(self.app, "ai-net-tor", anonymising=True)
        self.assertTrue(gateways.load()["ai-net-tor"].updates)          # same network
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-vpn"]
        text = fleet.set_gateway(self.app, "ai-net-tor", anonymising=True)
        g = gateways.load()["ai-net-tor"]
        self.assertEqual((g.upstream, g.updates), ("sys-vpn", False))
        self.assertIn("do not count", text)
        fleet.set_gateway(self.app, "ai-net-tor", updates=True)
        self.assertTrue(gateways.load()["ai-net-tor"].updates)

    def test_an_unticked_upstream_carries_no_update(self):
        # The case the tick closes: a VPN qube enrolled with no router in front
        # has sys-firewall above it, which only the operator can tell from
        # sys-whonix above a router.
        fleet.enroll_gateway(self.app, "sys-vpn", anonymising=True)
        self.assertEqual(gateways.load()["sys-vpn"].upstream, "sys-firewall")
        self.updates_to = "sys-firewall"
        v = self.hub_verdict()
        self.assertEqual(v.status, anon.RED)
        detail = " ".join(d for c, d in v.problems if c == "templates")
        self.assertIn("sys-firewall, the recorded upstream of sys-vpn, which is not ticked", detail)
        # Teeth: the operator's word decides, nothing else.
        fleet.set_gateway(self.app, "sys-vpn", updates=True)
        self.assertEqual(self.hub_verdict().status, anon.GREEN)

    def test_the_tick_does_not_come_off_where_the_gate_would_stop(self):
        p = self.anonymous_project()
        with self.assertRaisesRegex(fleet.RoleError, f"would stop {p.label}, the hub"):
            fleet.set_gateway(self.app, "ai-net-tor", updates=False)
        self.assertTrue(gateways.load()["ai-net-tor"].updates)
        # With the updates sent elsewhere nothing would stop.
        self.app.vm("sys-tor2", provides_network=True,
                    netvm=self.app.domains["sys-whonix"], features={"qubes-firewall": "1"})
        fleet.enroll_gateway(self.app, "sys-tor2", anonymising=True, updates=True)
        self.assertIn("do not count", fleet.set_gateway(self.app, "ai-net-tor", updates=False))


class HubCheck(ModeBase):
    def test_a_sound_hub_is_judged_only_in_the_mode(self):
        self.spawn("ai-hub-w")
        v = self.hub_verdict()
        self.assertEqual((v.status, v.problems), (anon.GREEN, []))
        self.assertEqual(v.names, [HUB, "ai-hub-tpl", "ai-hub-w", "ai-tpl-g"])
        self.assertEqual(v.p00, ["ai-hub-w"])
        self.assertEqual(v.to_json()["hub"], True)
        self.mode(None)
        self.assertEqual(anon.run(self.app), [])
        self.mode("anonymous")
        # The timer beats with only the hub to judge.
        pathlib.Path(anon.HEARTBEAT_PATH).unlink()
        anon.run(self.app, beat=True)
        self.assertIsNotNone(anon.heartbeat_age())

    def test_an_anonymous_projects_qubes_and_the_gateways_are_not_the_hubs(self):
        p = self.anonymous_project()
        # A router kept in AI space but not enrolled (as after `gateway remove`)
        # is no subject either, and gets no qmcp-anon from the installer.
        self.app.vm("ai-net-old", provides_network=True, netvm=self.app.domains["sys-firewall"],
                    tags={"ai-managed", "qmcp-guarded"})
        names = self.hub_verdict().names
        self.assertNotIn(p.lead, names)
        self.assertNotIn("ai-net-tor", names)
        self.assertNotIn("ai-net-old", names)
        self.assertIn(HUB, names)
        by_name, tags_by = anon._snapshot(self.app, strict=True)
        self.assertEqual(anon.hub_subjects(HUB, projects.load(), gateways.load(), by_name,
                                           tags_by), names)

    def test_the_hub_on_clearnet_stops_the_hub_and_p00(self):
        w = self.spawn("ai-hub-w")
        w.__dict__["_power"] = "Running"
        p = self.anonymous_project()
        hub = self.app.domains[HUB]
        hub.autostart = True
        hub.netvm = self.app.domains["sys-firewall"]
        v = self.hub_verdict(act=True)
        self.assertEqual(v.status, anon.RED)
        self.assertEqual(v.offenders, [HUB])
        self.assertIn("the hub mcp-control is on sys-firewall", " ".join(d for _, d in v.problems))
        for name in (HUB, "ai-hub-w"):
            self.assertLessEqual({BLOCKED, STOPPED}, self.tags(name))
            self.assertEqual(self.app.domains[name]._power, "Halted")
        self.assertFalse(hub.autostart)
        # Not the templates, and not the anonymous projects: they are judged apart.
        self.assertNotIn(BLOCKED, self.tags("ai-hub-tpl"))
        self.assertNotIn(BLOCKED, self.tags(p.lead))
        self.assertIn("the hub and its qubes in p00", self.notices[-1])
        line = json.loads(pathlib.Path(audit.LOG_PATH).read_text().splitlines()[-1])
        self.assertEqual((line["args"]["project"], line["args"]["hub"]), ("p00", True))

    def test_a_p00_qube_in_violation_stops_the_hub_and_p00(self):
        self.spawn("ai-hub-w")
        self.spawn("ai-hub-x")
        self.app.domains["ai-hub-w"].netvm = self.app.domains["sys-firewall"]
        v = self.hub_verdict(act=True)
        self.assertEqual(v.offenders, ["ai-hub-w"])
        self.assertEqual(anon.hub_stop_set(v, HUB), [HUB, "ai-hub-w", "ai-hub-x"])
        for name in (HUB, "ai-hub-w", "ai-hub-x"):
            self.assertIn(BLOCKED, self.tags(name))

    def test_a_template_updating_over_clearnet_stops_that_template_alone(self):
        self.extra = "qubes.UpdatesProxy * ai-hub-tpl @default allow target=sys-net\n"
        v = self.hub_verdict(act=True)
        self.assertEqual((v.status, v.offenders), (anon.RED, ["ai-hub-tpl"]))
        self.assertIn("ai-hub-tpl's updates to sys-net", " ".join(d for _, d in v.problems))
        self.assertIn(BLOCKED, self.tags("ai-hub-tpl"))
        self.assertNotIn(BLOCKED, self.tags(HUB))
        self.assertEqual(self.app.domains[HUB]._power, "Running")
        self.assertIn("ai-hub-tpl (anonymous mode)", self.notices[-1])
        # The block is the cut: nothing reaches a blocked qube, the hub included.
        self.assertEqual(self.call("qmcp.CloneAIManagedQube",
                                   {"source": "ai-hub-tpl", "name": "ai-hub-tpl2"}),
                         core.BLOCKED_REFUSAL)

    def test_a_stopped_qube_is_judged_as_it_would_be_once_cleared(self):
        # With the rulebook in place a blocked qube is refused every call, its
        # updates included (measured on the box: the stopped template read
        # sound). The gate asks where they go once the stop is cleared.
        self.extra = "qubes.UpdatesProxy * ai-hub-tpl @default allow target=sys-net\n"
        anon.load_policy = lambda: policy_view(self.app, self.updates_to, self.extra, ours=True)
        v = self.hub_verdict(act=True)
        self.assertEqual(v.offenders, ["ai-hub-tpl"])
        self.assertLessEqual({BLOCKED, STOPPED}, self.tags("ai-hub-tpl"))
        v = self.hub_verdict()
        self.assertEqual((v.status, v.offenders), (anon.RED, ["ai-hub-tpl"]))
        with self.assertRaisesRegex(fleet.ProjectError, "still finds the hub unsound"):
            fleet.unblock(self.app, "p00")
        # Teeth: the rulebook really does refuse the stopped template its updates.
        policy, info = anon.load_policy()
        from qrexec.exc import AccessDenied
        from qrexec.policy.parser import Request
        req = Request(anon.UPDATES, "+", "ai-hub-tpl", "@default", system_info=info)
        with self.assertRaises(AccessDenied):
            policy.find_matching_rule(req).action.evaluate(req)
        self.extra = ""
        self.assertEqual(fleet.unblock(self.app, "p00"),
                         ["p00: ai-hub-tpl unblocked (autostart stays off)"])

    def test_the_hubs_own_template_updating_over_clearnet_stops_the_hub(self):
        # Qubes' default: every template's updates to sys-net.
        self.updates_to = None
        v = self.hub_verdict()
        self.assertIn(HUB, v.offenders)
        self.assertIn("debian-13's updates to sys-net", " ".join(d for _, d in v.problems))

    def test_a_disposable_template_on_a_network_not_anonymising_stops_it_alone(self):
        d = self.spawn("ai-hub-dvm", klass="DispVMTemplate")
        d.netvm = self.app.domains["sys-firewall"]
        v = self.hub_verdict()
        self.assertEqual(v.offenders, ["ai-hub-dvm"])
        self.assertEqual(anon.hub_stop_set(v, HUB), ["ai-hub-dvm"])

    def test_the_hub_without_qmcp_anon_is_unsound(self):
        self.app.domains[HUB].tags.discard(ANON)
        v = self.hub_verdict()
        self.assertEqual((v.status, v.conditions(), v.offenders), (anon.RED, ["badges"], [HUB]))

    def test_a_mode_that_cannot_be_read_blocks_the_hub_and_p00_without_a_kill(self):
        self.spawn("ai-hub-w")
        self.mode("x")
        v = self.hub_verdict(act=True)
        self.assertEqual(v.status, anon.UNREADABLE)
        self.assertIn("cannot be told", v.problems[0][1])
        for name in (HUB, "ai-hub-w"):
            self.assertIn(BLOCKED, self.tags(name))
            self.assertNotIn(STOPPED, self.tags(name))
        self.assertEqual(self.app.domains[HUB]._power, "Running")

    def test_a_read_that_fails_twice_blocks_the_hub_without_a_kill(self):
        self.app.fail_reads("tag.List:ai-hub-tpl", "fail fail fail fail")
        v = self.hub_verdict(act=True)
        self.assertEqual(v.status, anon.UNREADABLE)
        self.assertIn(BLOCKED, self.tags(HUB))
        self.assertEqual(self.app.domains[HUB]._power, "Running")

    def test_unblock_p00_waits_for_a_sound_hub_and_leaves_autostart_off(self):
        self.spawn("ai-hub-w")
        hub = self.app.domains[HUB]
        hub.autostart = True
        hub.netvm = self.app.domains["sys-firewall"]
        self.hub_verdict(act=True)
        with self.assertRaisesRegex(fleet.ProjectError, "still finds the hub unsound"):
            fleet.unblock(self.app, "p00")
        self.assertIn(BLOCKED, self.tags(HUB))
        hub.netvm = self.app.domains["ai-net-tor"]
        report = fleet.unblock(self.app, "hub")
        self.assertIn(f"p00: {HUB} unblocked (autostart stays off)", report)
        for name in (HUB, "ai-hub-w"):
            self.assertFalse({BLOCKED, STOPPED} & self.tags(name))
        self.assertFalse(hub.autostart)
        self.assertEqual(fleet.unblock(self.app, "p00"), ["p00: nothing was blocked"])
        self.mode("x")
        with self.assertRaisesRegex(fleet.ProjectError, "cannot be told"):
            fleet.unblock(self.app, "p00")

    def test_unblock_p00_in_normal_mode_clears_what_the_mode_left(self):
        self.app.domains[HUB].tags.add(BLOCKED)
        self.mode(None)
        self.assertEqual(fleet.unblock(self.app, "p00"),
                         [f"p00: {HUB} unblocked (autostart stays off)"])
        self.assertNotIn(BLOCKED, self.tags(HUB))

    def test_check_says_the_mode(self):
        def items(name):
            return [(f.status, f.detail) for f in fleet.check(self.app) if f.check == name]
        self.assertEqual([s for s, _ in items("anonymous mode")], ["pass"])
        self.assertEqual([s for s, _ in items("hub")], ["pass"])            # it wears qmcp-anon
        self.assertTrue(any("the hub (p00) is sound" in d for _, d in items("anonymity gate")))
        self.assertFalse(items("anonymous badges"))
        self.assertEqual(items("stray badges"), [("pass", "none")])    # the hub's qmcp-anon
        # A clearnet gateway, written by hand: the mode fails on it.
        registry = gateways.load()
        registry["sys-firewall"] = gateways.Gateway("sys-firewall")
        gateways.save(registry)
        self.assertIn(("fail", "gateways that are not anonymising: sys-firewall "
                               "(qmcp gateway remove)"), items("anonymous mode"))
        self.mode("x")
        self.assertEqual([s for s, _ in items("anonymous mode")], ["fail"])
        # In normal mode qmcp-anon on the hub is an AI-space badge.
        self.mode(None)
        self.assertEqual([s for s, _ in items("hub")], ["fail"])


class AuditFindings(ModeBase):
    """What the adversarial review of 0.9.24 found, before release."""

    def test_nothing_is_made_from_a_stopped_template(self):
        self.spawn("ai-hub-dvm", klass="DispVMTemplate")
        for name in ("ai-hub-dvm", "ai-hub-tpl"):
            self.app.domains[name].tags.add(BLOCKED)
        self.assertEqual(self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-hub-dvm"}),
                         core.BLOCKED_REFUSAL)
        self.assertEqual(self.call("qmcp.SpawnAIManagedQube",
                                   {"name": "ai-hub-v", "template": "ai-hub-tpl"}),
                         core.BLOCKED_REFUSAL)
        self.assertNotIn("ai-hub-v", self.app.domains)
        # Teeth: once the stop is cleared, the same calls make qubes.
        for name in ("ai-hub-dvm", "ai-hub-tpl"):
            self.app.domains[name].tags.discard(BLOCKED)
        self.assertTrue(self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-hub-dvm"})["ok"])

    def test_nothing_is_born_on_a_router_off_its_recorded_network(self):
        self.spawn("ai-hub-dvm", klass="DispVMTemplate")              # on ai-net-tor
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        refusal = "anonymous mode: netvm is not on the network recorded for it"
        self.assertEqual(self.call("qmcp.SpawnDisposableAIManaged",
                                   {"template": "ai-hub-dvm"})["error"], refusal)
        self.assertEqual(self.call("qmcp.SpawnAIManagedQube",
                                   {"name": "ai-hub-v", "template": "ai-tpl-g"})["error"], refusal)
        self.mode(None)                                     # normal mode: as before
        self.assertTrue(self.call("qmcp.SpawnAIManagedQube",
                                  {"name": "ai-hub-v", "template": "ai-tpl-g"})["ok"])

    def test_an_unguarded_qube_that_provides_network_is_judged(self):
        w = self.spawn("ai-hub-w")
        w.provides_network = True
        w.netvm = self.app.domains["sys-firewall"]
        v = self.hub_verdict()
        self.assertEqual(v.offenders, ["ai-hub-w"])
        self.assertEqual(anon.hub_stop_set(v, HUB)[:1], [HUB])         # a p00 qube: all of p00
        w.tags.add(core.GUARDED)                            # guarded: a router nothing operates
        self.assertNotIn("ai-hub-w", self.hub_verdict().names)

    def test_removing_a_ticked_gateway_is_refused_where_the_gate_would_stop(self):
        a = self.app
        a.vm("ai-net-tor2", provides_network=True, netvm=a.domains["sys-whonix"],
             tags={"ai-managed", "qmcp-guarded"}, features={"qubes-firewall": "1"})
        fleet.enroll_gateway(a, "ai-net-tor2", anonymising=True, updates=True)
        fleet.set_gateway(a, "ai-net-tor", updates=False)             # tor2 still ticks sys-whonix
        with self.assertRaisesRegex(fleet.RoleError, "without 'ai-net-tor2' the anonymity gate "
                                                     "would stop the hub"):
            fleet.remove_gateway(a, "ai-net-tor2")
        self.assertIn("ai-net-tor2", gateways.load())
        fleet.set_gateway(a, "ai-net-tor", updates=True)
        self.assertIn("no longer enrolled", fleet.remove_gateway(a, "ai-net-tor2"))

    def test_a_move_that_widens_the_hubs_stop_is_refused(self):
        a = self.app
        a.vm("debian-x", klass="TemplateVM")                # outside AI space
        a.vm("ai-q", template=a.domains["debian-x"], netvm=None, tags={"ai-managed", ANON})
        self.extra = "qubes.UpdatesProxy * debian-x @default allow target=sys-net\n"
        v = self.hub_verdict()
        self.assertEqual(anon.hub_stop_set(v, HUB), ["ai-q"])          # it alone, now
        # Into p00 the same problem would stop the hub: refused, though no word of
        # the problem changes.
        with self.assertRaisesRegex(fleet.ProjectError, "would stop the hub with 'ai-q'"):
            fleet.move(a, "ai-q", "p00")
        self.assertNotIn(projects.member_badge("p00"), self.tags("ai-q"))
        self.extra = ""
        fleet.move(a, "ai-q", "p00")
        self.assertIn(projects.member_badge("p00"), self.tags("ai-q"))

    def test_guard_writes_nothing_when_the_mode_cannot_be_read(self):
        self.app.vm("plain-y", template=self.app.domains["debian-13"], netvm=None)
        self.mode("x")
        with self.assertRaisesRegex(fleet.RoleError, "cannot be told"):
            fleet.guard(self.app, "plain-y")
        self.assertEqual(self.tags("plain-y") & {core.GUARDED, core.UMBRELLA, ANON}, set())

    def test_a_model_qube_wears_qmcp_anon_and_stays_sound_once_its_project_goes(self):
        a = self.app
        p = self.anonymous_project()
        a.vm("ai-hub-mq", template=a.domains["ai-tpl-g"], netvm=None, tags={"ai-managed"})
        fleet.set_lead_firewall(a, p.slot, model_qube="ai-hub-mq")
        self.assertIn(ANON, self.tags("ai-hub-mq"))
        self.assertFalse([f for f in fleet.check(a) if f.check == "anonymous badges"])
        fleet.delete_project(a, p.slot)
        v = self.hub_verdict()
        self.assertIn("ai-hub-mq", v.names)                  # under the hub's check now
        self.assertEqual((v.status, v.problems), (anon.GREEN, []))

    def test_the_services_refuse_a_stopped_hub(self):
        self.app.domains[HUB].tags.add(BLOCKED)
        self.assertEqual(self.call("qmcp.ListAIManagedQubes", {}), core.NOT_AUTHORIZED)
        self.app.domains[HUB].tags.discard(BLOCKED)
        self.assertTrue(self.call("qmcp.ListAIManagedQubes", {})["ok"])


class Creates(ModeBase):
    def test_the_hubs_creates_wear_qmcp_anon(self):
        self.spawn("ai-hub-w")
        self.spawn("ai-hub-dvm", klass="DispVMTemplate")
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-hub-tpl", "name": "ai-hub-tpl2"})
        self.assertTrue(r["ok"], r)
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-hub-dvm"})
        self.assertTrue(r["ok"], r)
        for name in ("ai-hub-w", "ai-hub-dvm", "ai-hub-tpl2", r["name"]):
            self.assertIn(ANON, self.tags(name), name)
        self.assertEqual(self.hub_verdict().status, anon.GREEN)
        # In normal mode they wear none.
        self.mode(None)
        self.spawn("ai-hub-v")
        self.assertNotIn(ANON, self.tags("ai-hub-v"))

    def test_a_mode_that_cannot_be_read_makes_nothing(self):
        self.mode("x")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-w", "template": "ai-tpl-g"})
        self.assertEqual(r, {"ok": False, "error": "anonymous mode cannot be read"})
        self.assertNotIn("ai-hub-w", self.app.domains)

    def test_a_create_onto_a_clearnet_gateway_is_refused(self):
        a = self.app
        a.vm("sys-ai-net", provides_network=True, netvm=a.domains["sys-firewall"],
             features={"qubes-firewall": "1"})
        registry = gateways.load()                      # written by hand, past the command
        registry["sys-ai-net"] = gateways.Gateway("sys-ai-net")
        gateways.save(registry)
        a.vm("ai-hub-dvmc", template=a.domains["ai-tpl-g"], template_for_dispvms=True,
             netvm=a.domains["sys-ai-net"], tags={"ai-managed", ANON})
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-hub-dvmc"})
        self.assertEqual(r["error"], "anonymous mode: netvm must be an anonymising gateway")

    def test_every_project_is_anonymous(self):
        with self.assertRaisesRegex(fleet.ProjectError, "leave the label out"):
            fleet.create_project(self.app, "plain", "template", "ai-tpl-g",
                                 networks=["ai-net-tor"], quota="5G", lead_netvm="ai-net-tor",
                                 model="api.example.org:443")
        p = self.anonymous_project()
        self.assertTrue(p.anonymous and p.hidden)
        self.assertLessEqual({ANON, HUBBLIND}, self.tags(p.lead))
        visible = self.anonymous_project(hub_sees=True)
        self.assertFalse(visible.hidden)

    def test_a_proposal_for_an_ordinary_project_is_refused(self):
        req = dict(anon_create(anonymous=False), label="plain")
        r = self.call("qmcp.SubmitProposal", req)
        self.assertEqual(r["error"], "invalid proposal: anonymous mode: every new project is "
                                     "anonymous (anonymous: true)")
        self.assertTrue(self.call("qmcp.SubmitProposal", anon_create())["ok"])

    def test_manage_and_guard_put_qmcp_anon_on_before_the_umbrella(self):
        a = self.app
        a.vm("plain-x", template=a.domains["debian-13"], netvm=None)
        a.vm("plain-y", template=a.domains["debian-13"], netvm=None)
        order = []
        for name in ("plain-x", "plain-y"):
            vm = a.domains[name]
            add = vm.tags.add
            vm.tags.add = lambda t, n=name, add=add: (order.append((n, t)), add(t))[1]
        fleet.manage(a, "plain-x")
        fleet.guard(a, "plain-y")
        for name in ("plain-x", "plain-y"):
            mine = [t for n, t in order if n == name]
            self.assertLess(mine.index(ANON), mine.index(core.UMBRELLA), mine)
        self.assertEqual(self.hub_verdict().status, anon.GREEN)


class Moves(AnonBase):
    """Moves in normal mode: into, out of and between anonymous projects, with
    the warning and the tick (amends 0.9.23's refusal)."""

    def setUp(self):
        super().setUp()
        self.p = self.make()                              # hidden
        self.v = self.make(hub_sees=True)                 # visible

    def test_out_of_a_hidden_project_says_it_hands_the_hub_its_contents(self):
        w = f"ai-{self.p.label}-w2"
        with self.assertRaisesRegex(fleet.ProjectError, "hands the hub its contents.*--yes"):
            fleet.move(self.app, w, "p00")
        self.assertIn(HUBBLIND, self.tags(w))                # nothing moved
        order = []
        vm = self.app.domains[w]
        add, discard = vm.tags.add, vm.tags.discard
        vm.tags.add = lambda t: (order.append(("+", t)), add(t))[1]
        vm.tags.discard = lambda t: (order.append(("-", t)), discard(t))[1]
        report = fleet.move(self.app, w, "p00", confirm=True)
        self.assertIn(f"{w}: {fleet.MOVE_PAST_WARNING}", report)
        self.assertIn(f"{w}: {fleet.MOVE_HIDDEN_WARNING}", report)
        self.assertEqual(self.tags(w) & {ANON, HUBBLIND, projects.member_badge(self.p.slot)},
                         set())
        self.assertIn(projects.member_badge("p00"), self.tags(w))
        # The hidden badge comes off last: no moment is the qube both in p00 and
        # open to the hub while still its old project's member.
        self.assertEqual(order[-1], ("-", HUBBLIND))
        self.assertLess(order.index(("-", projects.member_badge(self.p.slot))),
                        order.index(("+", projects.member_badge("p00"))))

    def test_between_two_anonymous_projects_warns_and_changes_the_badges(self):
        w = f"ai-{self.p.label}-w2"
        with self.assertRaisesRegex(fleet.ProjectError, "a qube has a past"):
            fleet.move(self.app, w, self.v.label)
        fleet.move(self.app, w, self.v.label, confirm=True)
        tags = self.tags(w)
        self.assertIn(projects.member_badge(self.v.slot), tags)
        self.assertIn(ANON, tags)
        self.assertNotIn(HUBBLIND, tags)
        self.assertEqual(self.gate(act=False)[self.v.slot].status, anon.GREEN)

    def test_into_one_is_judged_by_the_gate_first(self):
        # ai-work2 (no network) comes from ai-debian-13, a template the hub manages.
        with self.assertRaisesRegex(fleet.ProjectError, "would stop .*ai-debian-13 is managed"):
            fleet.move(self.app, "ai-work2", self.v.label, confirm=True)
        self.assertNotIn(ANON, self.tags("ai-work2"))
        self.assertEqual(self.gate(act=False)[self.v.slot].status, anon.GREEN)
        # One from a guarded template goes in, wearing the project's badges.
        self.app.vm("ai-hubq2", template=self.app.domains["ai-tpl-g"], netvm=None,
                    tags={"ai-managed", projects.member_badge("p00")})
        with self.assertRaisesRegex(fleet.ProjectError, "--yes"):
            fleet.move(self.app, "ai-hubq2", self.p.label)
        fleet.move(self.app, "ai-hubq2", self.p.label, confirm=True)
        self.assertLessEqual({ANON, HUBBLIND, projects.member_badge(self.p.slot)},
                             self.tags("ai-hubq2"))
        self.assertEqual(self.gate(act=False)[self.p.slot].status, anon.GREEN)

    def test_a_stopped_qube_does_not_move(self):
        w = f"ai-{self.p.label}-w2"
        self.app.domains[w].tags.add(BLOCKED)
        with self.assertRaisesRegex(fleet.ProjectError, "unblock"):
            fleet.move(self.app, w, "none", confirm=True)

    def test_inside_clear_space_nothing_changes(self):
        self.assertEqual(fleet.move_warnings(self.records(), {"p01"}, "p02"), [])
        self.assertEqual(fleet.move_warnings(self.records(), set(), self.p.slot),
                         [fleet.MOVE_PAST_WARNING])


if __name__ == "__main__":
    unittest.main()
