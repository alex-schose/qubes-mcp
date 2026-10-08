"""Offline suite for anonymous projects (M3c): the gate, hidden projects, the block.

It runs the dom0 library against tests/fakequbes.py, as the other suites do,
and asks dom0's update question with qrexec's real parser over upstream's 4.3
policy plus a `50-config-updates.policy` the test writes, as Qubes' Global
Config does. Each condition is broken on its own, against a project the gate
first finds sound, so a test that expects red cannot pass on a project that
was never green.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest
import uuid

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import anon, audit, birth, core, fleet, gateways, projects, proposals  # noqa: E402
from fakequbes import GiB  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_proposals import PBase  # noqa: E402

from qrexec.policy.parser import FilePolicy  # noqa: E402

UPSTREAM = HERE / "data" / "upstream-policy-4.3"
WHONIX_LINES = ("qubes.UpdatesProxy * @tag:whonix-updatevm @default allow target=sys-whonix\n"
                "qubes.UpdatesProxy * @tag:whonix-updatevm @anyvm deny\n")


def policy_view(app, updates_to="sys-whonix", extra=""):
    """(policy, system information) as dom0's policy daemon would see them:
    upstream 4.3's files, and Global Config's update file sending every
    TemplateVM's updates to `updates_to` (none: Qubes' default, sys-net)."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-anon-policy-"))
    try:
        shutil.copytree(UPSTREAM, tmp, dirs_exist_ok=True)
        (tmp / "README.md").unlink(missing_ok=True)
        lines = WHONIX_LINES + extra
        if updates_to:
            lines += f"qubes.UpdatesProxy * @type:TemplateVM @default allow target={updates_to}\n"
        (tmp / "50-config-updates.policy").write_text(lines)
        policy = FilePolicy(policy_path=tmp)
    finally:
        shutil.rmtree(tmp)
    domains = {}
    for vm in app.domains.values():
        props = vm.__dict__["_props"]
        dd = props.get("default_dispvm")
        domains[vm.name] = {"tags": sorted(vm.tags.raw()), "type": vm.klass,
                            "template_for_dispvms": bool(props.get("template_for_dispvms")),
                            "default_dispvm": None if dd is None else dd.name, "icon": "",
                            "internal": False, "power_state": vm.__dict__["_power"],
                            "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, vm.name))}
    return policy, {"domains": domains}


class AnonBase(PBase):
    """The project fleet, plus a Tor router behind `sys-whonix` and a VPN router
    behind `sys-vpn`, both enrolled anonymising (their upstream recorded), and
    dom0's updates going to `sys-whonix`."""

    def setUp(self):
        super().setUp()
        a = self.app
        fw = a.domains["sys-firewall"]
        # As on a real box: sys-net under sys-firewall, Qubes' default update qube.
        fw.netvm = a.vm("sys-net", provides_network=True)
        whonix = a.vm("sys-whonix", provides_network=True, netvm=fw, tags={"anon-gateway"})
        vpn = a.vm("sys-vpn", provides_network=True, netvm=fw)
        a.vm("ai-net-tor", provides_network=True, netvm=whonix, power="Running",
             tags={"ai-managed", "qmcp-guarded"}, features={"qubes-firewall": "1"})
        a.vm("ai-net-vpn", provides_network=True, netvm=vpn, power="Running",
             tags={"ai-managed", "qmcp-guarded"}, features={"qubes-firewall": "1"})
        fleet.enroll_gateway(a, "ai-net-tor", anonymising=True)
        fleet.enroll_gateway(a, "ai-net-vpn", anonymising=True, label="vpn")
        self.updates_to, self.extra = "sys-whonix", ""
        self.notices, self.timer = [], True
        for mod, attr, value in [
            (anon, "RETRY_WAIT_S", 0.0),
            (anon, "load_policy", lambda: policy_view(self.app, self.updates_to, self.extra)),
            (anon, "notify", lambda text: self.notices.append(text) or True),
            (anon, "TIMER_CHECK", lambda: self.timer),
        ]:
            self._saved.append((mod, attr, getattr(mod, attr)))
            setattr(mod, attr, value)

    # -- an anonymous project the gate finds sound, with a running lead and two workers
    def make(self, hub_sees=False, **kw):
        args = dict(templates=(), networks=["ai-net-tor"], quota="10G", lead_netvm="ai-net-tor",
                    model="api.example.org:443", anonymous=True, hub_sees=hub_sees)
        args.update(kw)
        fleet.create_project(self.app, None, "template", "ai-tpl-g", **args)
        p = next(p for p in self.records().values() if p.anonymous and p.slot not in self.seen)
        self.seen.add(p.slot)
        lead = self.app.domains[p.lead]
        lead.__dict__["_power"] = "Running"
        for w in ("w1", "w2"):
            r = self.lcall("qmcp.SpawnAIManagedQube",
                           {"name": f"ai-{p.label}-{w}", "template": "ai-tpl-g"}, lead=p.lead)
            self.assertTrue(r["ok"], r)
        self.app.domains[f"ai-{p.label}-w1"].__dict__["_power"] = "Running"
        return projects.find(self.records(), p.slot)

    @property
    def seen(self):
        if "_seen" not in self.__dict__:
            self.__dict__["_seen"] = set()
        return self.__dict__["_seen"]

    def gate(self, act=True, **kw):
        return {v.slot: v for v in anon.run(self.app, act=act, **kw)}

    def green(self, p):
        v = self.gate(act=False)[p.slot]
        self.assertEqual((v.status, v.problems), (anon.GREEN, []), "the fixture is not sound")
        return v

    def red(self, p, condition, act=False):
        v = self.gate(act=act)[p.slot]
        self.assertEqual(v.status, anon.RED, v.problems)
        self.assertIn(condition, v.conditions(), v.problems)
        return v

    def qubes_of(self, p):
        return sorted([p.lead, f"ai-{p.label}-w1", f"ai-{p.label}-w2"])


# ======================================================================= the records

class Records(AnonBase):
    def test_an_anonymous_record_round_trips_and_old_records_still_read(self):
        p = self.make()
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        entry = doc["slots"][p.slot]
        self.assertEqual((entry["anonymous"], entry["hidden"]), (True, True))
        self.assertNotIn("note", entry)
        # An ordinary record is written exactly as before: no new key appears.
        self.assertNotIn("anonymous", doc["slots"]["p01"])
        self.assertNotIn("hidden", doc["slots"]["p01"])
        bad = [dict(entry, anonymous=False), dict(entry, hidden=False),
               dict(entry, anonymous=None, hidden=True), {**entry, "note": "x\n"},
               {k: v for k, v in entry.items() if k not in ("anonymous", "hidden")} | {"note": "n"}]
        for e in bad:
            with self.assertRaises(projects.ProjectsUnreadable, msg=e):
                projects.parse(json.dumps({"version": 1, "slots": {p.slot: e}}))

    def test_the_random_label_is_a_label_and_its_sink_a_name(self):
        for _ in range(200):
            label = projects.random_label(set(), "ai-")
            self.assertIsNone(projects.label_refusal(label))
            self.assertTrue(core.valid_qube_name(f"{label}-dump"))
            self.assertEqual(len(label), projects.RANDOM_LABEL_LEN)
        self.assertFalse(projects.random_label(set(), "ab").startswith("ab"))

    def test_the_registry_records_an_anonymising_upstream_and_reads_old_files(self):
        reg = gateways.load()
        self.assertEqual((reg["ai-net-tor"].upstream, reg["ai-net-vpn"].upstream),
                         ("sys-whonix", "sys-vpn"))
        self.assertIsNone(reg["ai-net-router"].upstream)
        old = {"version": 1, "gateways": {"g": {"anonymising": True, "label": ""}}}
        self.assertIsNone(gateways.parse(json.dumps(old))["g"].upstream)
        for bad in ({"anonymising": False, "label": "", "upstream": "x"},
                    {"anonymising": True, "label": "", "upstream": "bad name"},
                    {"anonymising": True, "label": "", "upstream": "x", "more": 1}):
            with self.assertRaises(gateways.GatewaysUnreadable):
                gateways.parse(json.dumps({"version": 1, "gateways": {"g": bad}}))

    def test_marking_records_the_upstream_now_and_unmarking_in_use_is_refused(self):
        a = self.app
        a.vm("ai-net-loose", provides_network=True, netvm=None, tags={"ai-managed", "qmcp-guarded"},
             features={"qubes-firewall": "1"})
        with self.assertRaisesRegex(fleet.RoleError, "no network of its own"):
            fleet.enroll_gateway(a, "ai-net-loose", anonymising=True)
        self.assertNotIn("ai-net-loose", gateways.load())
        a.domains["ai-net-vpn"].netvm = a.domains["sys-whonix"]
        self.assertIn("on sys-whonix", fleet.set_gateway(a, "ai-net-vpn", anonymising=True))
        self.assertEqual(gateways.load()["ai-net-vpn"].upstream, "sys-whonix")
        p = self.make()
        with self.assertRaisesRegex(fleet.RoleError, p.label):
            fleet.set_gateway(a, "ai-net-tor", anonymising=False)
        self.assertTrue(gateways.load()["ai-net-tor"].anonymising)
        fleet.set_gateway(a, "ai-net-vpn", anonymising=False)
        self.assertIsNone(gateways.load()["ai-net-vpn"].upstream)


# ======================================================================= creating one

class Create(AnonBase):
    def test_a_hidden_project_and_its_badges(self):
        p = self.make()
        self.assertTrue((p.anonymous, p.hidden) == (True, True))
        self.assertRegex(p.label, r"\A[a-z][a-z0-9]{7}\Z")
        self.assertEqual(p.lead, f"ai-{p.label}-lead")
        for name in self.qubes_of(p):
            self.assertLessEqual({"qmcp-anon", "qmcp-hubblind", "ai-managed"}, self.tags(name), name)
        self.assertIn("qmcp-lead", self.tags(p.lead))
        self.green(p)

    def test_a_visible_one_wears_no_hidden_badge(self):
        p = self.make(hub_sees=True)
        self.assertEqual((p.anonymous, p.hidden), (True, False))
        for name in self.qubes_of(p):
            self.assertIn("qmcp-anon", self.tags(name))
            self.assertNotIn("qmcp-hubblind", self.tags(name))
        self.green(p)

    def test_the_hidden_badge_goes_on_before_the_umbrella(self):
        added = []
        io = birth.TagIO(lambda: set(added), added.append, lambda t: None)
        birth.stamp(io, set(), "dom0", "qmcp-proj-p05", {"qmcp-anon", "qmcp-hubblind"})
        self.assertLess(added.index("qmcp-hubblind"), added.index("ai-managed"))
        self.assertLess(added.index("qmcp-anon"), added.index("ai-managed"))
        # Teeth: in sorted order, the umbrella would come first.
        self.assertLess(sorted(added).index("ai-managed"), sorted(added).index("qmcp-hubblind"))

    def test_what_create_refuses(self):
        a = self.app
        base = dict(networks=["ai-net-tor"], quota="10G", lead_netvm="ai-net-tor",
                    model="api.example.org:443", anonymous=True)
        cases = [
            ("a label", ("lbl", "template", "ai-tpl-g"), {}, "picked by dom0"),
            ("a lead name", (None, "template", "ai-tpl-g"), {"lead_name": "ai-x-lead"}, "named by dom0"),
            ("a cloned lead", (None, "clone", "ai-work"), {}, "made fresh"),
            ("a promoted lead", (None, "promote", "ai-hubq"), {}, "made fresh"),
            ("a managed template", (None, "template", "ai-debian-13"), {}, "managed"),
            ("a clearnet network", (None, "template", "ai-tpl-g"),
             {"networks": ["ai-net-router"]}, "not an anonymising"),
            ("a clearnet lead", (None, "template", "ai-tpl-g"),
             {"lead_netvm": "ai-net-router"}, "not an anonymising"),
            ("a managed approved template", (None, "template", "ai-tpl-g"),
             {"templates": ["ai-debian-13"]}, "managed"),
            ("a bad note", (None, "template", "ai-tpl-g"), {"note": "two\nlines"}, "printable"),
        ]
        before = len(self.records())
        for why, (label, src, origin), extra, msg in cases:
            with self.assertRaisesRegex(fleet.RoleError, msg, msg=why):
                fleet.create_project(a, label, src, origin, **(base | extra))
        with self.assertRaisesRegex(fleet.RoleError, "go with --anonymous"):
            fleet.create_project(a, "plain", "template", "ai-tpl-g", networks=["none"],
                                 quota="1G", note="n")
        self.assertEqual(len(self.records()), before)
        self.assertFalse([n for n in a.domains._vms if n.endswith("-lead") and n.startswith("ai-")
                          and n not in ("ai-osint-lead", "ai-other-lead")])

    def test_a_router_moved_off_its_recorded_network_is_refused(self):
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        with self.assertRaisesRegex(fleet.RoleError, "not on sys-whonix as recorded"):
            self.make()

    def test_an_old_registry_entry_carries_no_anonymous_project(self):
        self.enroll("ai-net-tor", anonymising=True)            # as 0.9.22 wrote it: no upstream
        with self.assertRaisesRegex(fleet.RoleError, "no recorded network"):
            self.make()

    def test_a_hidden_project_with_a_sink_and_a_note(self):
        p = self.make(dump=True, note="leak research, client B")
        self.assertEqual(self.tags(p.dump), {"ai-dump", f"qmcp-dump-{p.slot}", "qmcp-hubblind"})
        self.assertEqual(projects.find(self.records(), p.slot).note, "leak research, client B")
        # The note is the operator's: never in the lead's view, never the hub's.
        view = self.lcall("qmcp.GetPoolStats", lead=p.lead)
        self.assertNotIn("client B", json.dumps(view))
        self.assertEqual((view["anonymous"], view["hub_sees"]), (True, False))
        self.assertNotIn("client B", json.dumps(self.call("qmcp.GetPoolStats")))

    def test_create_warns_of_hub_prepared_templates_and_shared_routers(self):
        report = fleet.create_project(self.app, None, "template", "ai-tpl-g", networks=["ai-net-tor"],
                                      quota="1G", lead_netvm="ai-net-tor",
                                      model="api.example.org:443", anonymous=True)
        text = "\n".join(report)
        self.assertIn(fleet.HIDDEN_WARNING, text)
        self.assertNotIn("shares", text)
        report = fleet.create_project(self.app, None, "template", "ai-tpl-g", networks=["ai-net-tor"],
                                      quota="1G", lead_netvm="ai-net-tor",
                                      model="api.example.org:443", anonymous=True)
        self.assertIn("shares ai-net-tor", "\n".join(report))


# ======================================================================= hub-blind

class HubBlind(AnonBase):
    def test_the_hub_sees_nothing_of_a_hidden_project(self):
        p = self.make(dump=True)
        names = {q["name"] for q in self.call("qmcp.ListAIManagedQubes")["qubes"]}
        self.assertFalse(set(self.qubes_of(p)) & names)
        rows = self.call("qmcp.GetPoolStats")["projects"]
        self.assertNotIn(p.slot, {r["slot"] for r in rows})
        self.assertNotIn(p.label, json.dumps(rows))
        for name in self.qubes_of(p):
            for svc, req in (("qmcp.GetPropertyAIManaged", {"name": name, "property": "memory"}),
                             ("qmcp.SetPropertyAIManaged", {"name": name, "property": "memory",
                                                            "value": 900}),
                             ("qmcp.LifecycleAIManaged", {"name": name, "action": "kill"}),
                             ("qmcp.CloneAIManagedQube", {"source": name, "name": "ai-hub-cp"}),
                             ("qmcp.AIManagedEvents", {"duration": 1, "qube": name})):
                self.assertEqual(self.call(svc, req), core.NOT_FOUND, f"{svc} {name}")
        self.assertEqual(self.app.domains[p.lead]._power, "Running")

    def test_the_hub_sees_and_operates_a_visible_one(self):
        p = self.make(hub_sees=True)
        names = {q["name"] for q in self.call("qmcp.ListAIManagedQubes")["qubes"]}
        self.assertLessEqual(set(self.qubes_of(p)), names)
        row = {r["slot"]: r for r in self.call("qmcp.GetPoolStats")["projects"]}[p.slot]
        self.assertEqual((row["label"], row["anonymous"]), (p.label, True))
        r = self.call("qmcp.SetPropertyAIManaged",
                      {"name": f"ai-{p.label}-w2", "property": "memory", "value": 900})
        self.assertTrue(r["ok"], r)

    def test_events_leave_a_hidden_project_out(self):
        p = self.make()
        w1 = self.app.domains[f"ai-{p.label}-w1"]

        class Dispatcher:
            def __init__(s, app):
                s.handlers = []

            def add_handler(s, name, fn):
                s.handlers.append(fn)

            async def listen_for_events(s, reconnect=False):
                for fn in s.handlers:
                    fn(w1, "domain-start")
                    fn(self.app.domains["ai-work"], "domain-start")
        out = __import__("io").StringIO()
        from qmcp import services
        call = core.Call("qmcp.AIManagedEvents")
        call.principal = core.Principal(HUB, "hub")
        r = services.svc_events(self.app, call, {"duration": 1}, dispatcher_factory=Dispatcher)
        subjects = [e["subject"] for e in r["events"]]
        self.assertEqual(subjects, ["ai-work"], out.getvalue())

    def test_a_hidden_projects_lead_runs_its_project(self):
        p = self.make()
        r = self.lcall("qmcp.SetPropertyAIManaged",
                       {"name": f"ai-{p.label}-w2", "property": "memory", "value": 900}, lead=p.lead)
        self.assertTrue(r["ok"], r)
        r = self.lcall("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-g"}, lead=p.lead)
        self.assertFalse(r["ok"])           # not on its approved list: refused as ever

    def test_a_blocked_lead_is_no_principal(self):
        p = self.make()
        self.app.domains[p.lead].tags.add("qmcp-blocked")
        self.assertEqual(self.lcall("qmcp.ListAIManagedQubes", lead=p.lead), core.NOT_AUTHORIZED)


# ======================================================================= the gate's conditions

class Conditions(AnonBase):
    def setUp(self):
        super().setUp()
        self.p = self.make()
        self.green(self.p)

    def test_no_anonymous_project_means_no_policy_read(self):
        self.write_records({"version": 1, "slots": {}})
        anon.load_policy = lambda: self.fail("the policy was read for no project")
        self.assertEqual(anon.run(self.app), [])

    def test_1_a_router_moved_to_clearnet(self):
        # Teeth: the router stays enrolled and marked anonymising, which is all
        # condition 1 asked before 202, so only the recorded upstream catches it.
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        reg = gateways.load()["ai-net-tor"]
        self.assertTrue(reg.anonymising)
        v = self.red(self.p, "networks")
        self.assertEqual(len(v.problems), len(set(v.problems)), v.problems)   # said once

    def test_1_a_listed_network_that_is_not_anonymising(self):
        rec = self.records()
        rec[self.p.slot].networks = ("ai-net-tor", "ai-net-router")
        projects.save(rec)
        self.red(self.p, "networks")

    def test_1_a_member_off_the_list_and_a_lead_on_clearnet(self):
        self.app.domains[f"ai-{self.p.label}-w2"].netvm = self.app.domains["ai-net-router"]
        self.red(self.p, "networks")
        self.app.domains[f"ai-{self.p.label}-w2"].netvm = None
        self.green(self.p)
        self.app.domains[self.p.lead].netvm = self.app.domains["ai-net-router"]
        self.red(self.p, "networks")

    def test_2_a_model_qube_that_could_leak(self):
        a = self.app
        a.vm("ai-hub-mq", template=a.domains["ai-tpl-g"], netvm=None,
             tags={"ai-managed", "qmcp-proj-p00"})
        fleet.set_lead_firewall(a, self.p.slot, model_qube="ai-hub-mq")
        self.assertIn("qmcp-hubblind", self.tags("ai-hub-mq"))
        self.green(self.p)
        mq = a.domains["ai-hub-mq"]
        breaks = [
            ("a network", lambda: setattr(mq, "netvm", a.domains["ai-net-tor"]),
             lambda: setattr(mq, "netvm", None)),
            ("un-guarded", lambda: mq.tags.discard("qmcp-guarded"),
             lambda: mq.tags.add("qmcp-guarded")),
            ("shared", lambda: mq.tags.add("qmcp-model-p02"),
             lambda: mq.tags.discard("qmcp-model-p02")),
            ("the update proxy", lambda: mq.tags.add("whonix-updatevm"),
             lambda: mq.tags.discard("whonix-updatevm")),
        ]
        for why, breaking, mending in breaks:
            breaking()
            v = self.gate(act=False)[self.p.slot]
            self.assertIn("model", v.conditions(), why)
            mending()
            self.green(self.p)

    def test_3_templates_and_where_their_updates_go(self):
        tpl = self.app.domains["ai-tpl-g"]
        tpl.tags.discard("qmcp-guarded")
        self.red(self.p, "templates")
        tpl.tags.add("qmcp-guarded")
        tpl.netvm = self.app.domains["sys-firewall"]
        self.red(self.p, "templates")
        tpl.netvm = None
        self.green(self.p)
        for to in (None, "sys-firewall", "sys-net"):
            # Qubes' default (sys-net), and sys-firewall, which the Tor router's
            # traffic passes on the way: neither is the qube directly above an
            # anonymising router.
            self.updates_to = to
            self.red(self.p, "templates")
        self.updates_to = "sys-vpn"          # the VPN router's recorded upstream counts too
        self.green(self.p)
        self.updates_to = None
        self.extra = "qubes.UpdatesProxy * @type:TemplateVM @default ask default_target=sys-whonix\n"
        self.red(self.p, "templates")        # a dialog is no answer
        # Updates denied outright reach nothing, so they leak nothing.
        self.extra = "qubes.UpdatesProxy * @type:TemplateVM @default deny\n"
        self.green(self.p)

    def test_3_a_disposable_template_off_the_list(self):
        a = self.app
        a.vm("ai-dvm-anon", template=a.domains["ai-tpl-g"], template_for_dispvms=True,
             netvm=a.domains["ai-net-tor"], tags={"ai-managed", "qmcp-guarded"})
        fleet.edit_project(a, self.p.slot, templates=list(self.p.templates) + ["ai-dvm-anon"])
        # Approved for a hidden project, it is hidden from the hub itself: its
        # disposables are born with its tags.
        self.assertIn("qmcp-hubblind", self.tags("ai-dvm-anon"))
        self.green(self.p)
        a.domains["ai-dvm-anon"].tags.discard("qmcp-hubblind")
        self.red(self.p, "templates")
        a.domains["ai-dvm-anon"].tags.add("qmcp-hubblind")
        a.domains["ai-dvm-anon"].netvm = a.domains["ai-net-router"]
        self.red(self.p, "templates")

    def test_4_a_member_that_lost_its_hidden_badge(self):
        self.app.domains[f"ai-{self.p.label}-w2"].tags.discard("qmcp-hubblind")
        self.red(self.p, "badges")


# ======================================================================= acting on it

class Acting(AnonBase):
    def setUp(self):
        super().setUp()
        self.p = self.make()
        self.other = self.make(hub_sees=True)

    def test_a_violation_blocks_kills_and_turns_autostart_off_in_that_order(self):
        order = []
        for name in self.qubes_of(self.p):
            vm = self.app.domains[name]
            vm.autostart = True
            add, kill = vm.tags.add, vm.kill
            vm.tags.add = lambda t, n=name, add=add: (order.append(("tag", n, t)), add(t))[1]
            vm.__dict__["kill"] = lambda n=name, kill=kill: (order.append(("kill", n)), kill())[1]
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        verdicts = self.gate()
        v = verdicts[self.p.slot]
        self.assertEqual(v.status, anon.RED)
        for name in self.qubes_of(self.p):
            self.assertIn("qmcp-blocked", self.tags(name))
            self.assertEqual(self.app.domains[name]._power, "Halted")
            self.assertFalse(self.app.domains[name].autostart)
        lead_events = [e for e in order if e[1] == self.p.lead]
        self.assertEqual(lead_events, [("tag", self.p.lead, "qmcp-blocked"), ("kill", self.p.lead),
                                       ("tag", self.p.lead, "qmcp-stopped")])
        # Passes, not qube by qube: every qube is blocked, the lead first, before
        # any is killed, so no worker dies while its lead can still restart it.
        blocks = [i for i, e in enumerate(order) if e[0] == "tag" and e[2] == "qmcp-blocked"]
        kills = [i for i, e in enumerate(order) if e[0] == "kill"]
        self.assertEqual(len(blocks), 3)
        self.assertLess(max(blocks), min(kills))
        self.assertEqual(order[blocks[0]][1], self.p.lead)
        # The visible project shares the router, so it is stopped too; nothing else is.
        self.assertEqual(verdicts[self.other.slot].status, anon.RED)
        self.assertNotIn("qmcp-blocked", self.tags("ai-osint-w1"))
        line = json.loads(pathlib.Path(audit.LOG_PATH).read_text().splitlines()[-1])
        self.assertIn(anon.SERVICE, json.dumps(line))
        self.assertEqual(len(self.notices), 2)
        self.assertIn("its networks", self.notices[0])
        # The rulebook now refuses the lead's calls; the services refuse it too.
        self.assertEqual(self.lcall("qmcp.ListAIManagedQubes", lead=self.p.lead), core.NOT_AUTHORIZED)

    def test_a_blocked_qube_started_by_hand_is_not_killed_again(self):
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.gate()
        self.notices.clear()
        self.app.domains[self.p.lead].start()            # the operator looks at it
        v = self.gate()[self.p.slot]
        self.assertTrue(v.blocked)
        self.assertEqual(v.acted, [])
        self.assertEqual(self.app.domains[self.p.lead]._power, "Running")
        self.assertEqual(self.notices, [])

    def test_a_partly_blocked_project_blocks_the_rest_and_spares_the_rest(self):
        # One badge write failed last time: the next run blocks that qube, and
        # does not kill again the one the operator started by hand to look at.
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.gate()
        w2 = f"ai-{self.p.label}-w2"
        self.app.domains[w2].tags.discard("qmcp-blocked")
        self.app.domains[w2].tags.discard("qmcp-stopped")
        self.app.domains[w2].start()
        self.app.domains[self.p.lead].start()
        v = self.gate()[self.p.slot]
        self.assertTrue(v.blocked)                   # as it is once this run has acted
        self.assertIn("qmcp-blocked", self.tags(w2))
        self.assertEqual(self.app.domains[w2]._power, "Halted")
        self.assertEqual(self.app.domains[self.p.lead]._power, "Running")
        self.assertEqual(v.acted, [f"{w2}: blocked", f"{w2}: killed"])

    def test_a_block_after_a_failed_read_still_kills_on_a_violation(self):
        # A stop for a read that failed twice is no kill; a later violation is.
        anon.load_policy = lambda: (_ for _ in ()).throw(anon.PolicyUnreadable("down"))
        self.assertEqual(self.gate()[self.p.slot].status, anon.UNREADABLE)
        self.assertEqual(self.app.domains[self.p.lead]._power, "Running")
        anon.load_policy = lambda: policy_view(self.app, self.updates_to, self.extra)
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        v = self.gate()[self.p.slot]
        self.assertEqual(v.status, anon.RED)
        self.assertTrue(v.blocked)
        for name in self.qubes_of(self.p):
            self.assertEqual(self.app.domains[name]._power, "Halted", name)
            self.assertIn("qmcp-stopped", self.tags(name))
        self.assertIn(f"{self.p.lead}: killed", v.acted)

    def test_the_services_never_wake_or_copy_a_blocked_qube(self):
        p = self.other                       # visible: the hub may operate it, until it is stopped
        w1 = f"ai-{p.label}-w1"
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.gate()
        for svc, req in (("qmcp.LifecycleAIManaged", {"name": p.lead, "action": "start"}),
                         ("qmcp.LifecycleAIManaged", {"name": w1, "action": "start"}),
                         ("qmcp.CloneAIManagedQube", {"source": w1, "name": "ai-hub-cp"}),
                         ("qmcp.SetPropertyAIManaged", {"name": w1, "property": "memory",
                                                        "value": 900})):
            self.assertEqual(self.call(svc, req), core.BLOCKED_REFUSAL, f"{svc} {req}")
        self.assertEqual(self.app.domains[p.lead]._power, "Halted")
        self.assertNotIn("ai-hub-cp", self.app.domains._vms)
        # Reading one is no change: still answered.
        self.assertTrue(self.call("qmcp.GetPropertyAIManaged",
                                  {"name": w1, "property": "memory"})["ok"])

    def test_a_start_checks_the_block_again_right_before_waking(self):
        p = self.other
        w2 = self.app.domains[f"ai-{p.label}-w2"]
        real = core.operand

        def operand_then_gate(app, name, who):
            vm = real(app, name, who)
            w2.tags.add("qmcp-blocked")              # the gate lands in between
            return vm
        core.operand = operand_then_gate
        try:
            r = self.call("qmcp.LifecycleAIManaged", {"name": w2.name, "action": "start"})
        finally:
            core.operand = real
        self.assertEqual(r, core.BLOCKED_REFUSAL)
        self.assertEqual(w2._power, "Halted")

    def test_a_member_taken_out_of_ai_space_is_still_judged(self):
        w1 = self.app.domains[f"ai-{self.p.label}-w1"]
        w1.tags.discard("ai-managed")            # the rulebook still routes on its slot badge
        w1.netvm = self.app.domains["sys-firewall"]
        v = self.gate()[self.p.slot]
        self.assertEqual(v.status, anon.RED)
        self.assertIn("badges", v.conditions())
        self.assertEqual(w1._power, "Halted")
        self.assertIn("qmcp-blocked", self.tags(w1.name))

    def test_a_members_own_update_proxy_is_a_way_around_its_router(self):
        self.app.domains[f"ai-{self.p.label}-w2"].tags.add("whonix-updatevm")
        v = self.gate(act=False)[self.p.slot]
        self.assertIn("networks", v.conditions(), v.problems)
        self.assertTrue(any("update proxy" in d for _, d in v.problems))

    def test_a_project_with_nothing_to_stop_says_so_once(self):
        fleet.remove_lead(self.app, self.p.slot)
        for w in ("w1", "w2"):
            self.app.domains[f"ai-{self.p.label}-{w}"].tags.add("qmcp-blocked")
            self.app.domains[f"ai-{self.p.label}-{w}"].tags.add("qmcp-stopped")
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.notices.clear()
        lines = len(self.audit_lines())
        for _ in range(3):
            v = self.gate()[self.p.slot]
            self.assertEqual(v.status, anon.RED)
        self.assertTrue(all(self.p.label not in n for n in self.notices), self.notices)
        self.assertEqual(len([l for l in self.audit_lines()[lines:]
                              if l["args"].get("project") == self.p.slot]), 0)

    def test_unblock_holds_the_gate(self):
        import fcntl
        import os
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.gate()
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-whonix"]
        fd = os.open(anon.LOCK_PATH, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        saved = anon.LOCK_WAIT_S
        anon.LOCK_WAIT_S = 0.1
        try:
            with self.assertRaisesRegex(fleet.RoleError, "gate is running"):
                fleet.unblock(self.app, self.p.label)
        finally:
            anon.LOCK_WAIT_S = saved
            os.close(fd)
        self.assertIn("qmcp-blocked", self.tags(self.p.lead))
        fleet.unblock(self.app, self.p.label)
        self.assertNotIn("qmcp-blocked", self.tags(self.p.lead))
        self.assertNotIn("qmcp-stopped", self.tags(self.p.lead))

    def test_a_power_state_that_cannot_be_read_is_no_halt(self):
        # qubesadmin answers "NA" for a state it cannot read: the kill is tried,
        # and a qube not known to be down is never marked stopped.
        lead = self.app.domains[self.p.lead]
        lead.__dict__["get_power_state"] = lambda: "NA"
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        v = self.gate()[self.p.slot]
        self.assertIn(f"{self.p.lead}: killed", v.acted)
        self.assertEqual(lead._power, "Halted")
        self.assertIn("qmcp-stopped", self.tags(self.p.lead))

    def test_a_kill_that_fails_on_an_unread_state_is_tried_again(self):
        lead = self.app.domains[self.p.lead]
        lead.__dict__["get_power_state"] = lambda: "NA"
        real_kill = lead.kill
        lead.__dict__["kill"] = lambda: (_ for _ in ()).throw(RuntimeError("busy"))
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        v = self.gate()[self.p.slot]
        self.assertTrue(any("NOT killed" in a for a in v.acted), v.acted)
        self.assertNotIn("qmcp-stopped", self.tags(self.p.lead))
        self.assertIn("qmcp-blocked", self.tags(self.p.lead))
        lead.__dict__["kill"] = real_kill
        v = self.gate()[self.p.slot]
        self.assertIn(f"{self.p.lead}: killed", v.acted)
        self.assertEqual(lead._power, "Halted")
        self.assertIn("qmcp-stopped", self.tags(self.p.lead))

    def test_a_qube_already_halted_is_marked_stopped_and_says_so(self):
        # The badge is a change the run made: it is in the audit line, and no
        # kill is sent to a qube that reads halted.
        w2 = f"ai-{self.p.label}-w2"
        self.assertEqual(self.app.domains[w2]._power, "Halted")
        kills = []
        real = self.app.domains[w2].kill
        self.app.domains[w2].__dict__["kill"] = lambda: (kills.append(w2), real())[1]
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        v = self.gate()[self.p.slot]
        self.assertIn(f"{w2}: halted, marked stopped", v.acted)
        self.assertNotIn(f"{w2}: killed", v.acted)
        self.assertEqual(kills, [])
        self.assertIn("qmcp-stopped", self.tags(w2))

    def test_a_qube_that_halts_after_a_failed_kill_is_recorded_when_marked(self):
        lead = self.app.domains[self.p.lead]
        lead.__dict__["kill"] = lambda: (_ for _ in ()).throw(RuntimeError("busy"))
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        v = self.gate()[self.p.slot]
        self.assertTrue(any("NOT killed" in a for a in v.acted), v.acted)
        self.assertNotIn("qmcp-stopped", self.tags(self.p.lead))
        lead.__dict__["_power"] = "Halted"              # it went down by itself
        self.notices.clear()
        lines = len(self.audit_lines())
        v = self.gate()[self.p.slot]
        self.assertEqual(v.acted, [f"{self.p.lead}: halted, marked stopped"])
        self.assertIn("qmcp-stopped", self.tags(self.p.lead))
        self.assertEqual(len([l for l in self.audit_lines()[lines:]
                              if l["args"].get("project") == self.p.slot]), 1)
        self.assertEqual(len(self.notices), 1)
        # Nothing new after that: no line, no notice.
        v = self.gate()[self.p.slot]
        self.assertEqual(v.acted, [])

    def test_project_list_says_when_the_stop_cannot_be_read(self):
        # A failed read is never "not stopped".
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.gate()
        rc, out, _ = self.cli("project", "list")
        self.assertEqual(rc, 0)
        self.assertIn("BLOCKED", next(l for l in out.splitlines() if l.startswith(self.p.slot)))
        self.app.fail.add(f"tag.List:ai-{self.p.label}-w1")
        rc, out, _ = self.cli("project", "list")
        line = next(l for l in out.splitlines() if l.startswith(self.p.slot))
        self.assertIn("members=?", line)
        self.assertIn("blocked=?", line)
        self.assertNotIn("BLOCKED", line)

    def test_a_stopped_lead_still_agrees_with_its_record(self):
        # qmcp check's leads item judges record against badges; the stop is the
        # gate's item to report.
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.gate()
        vms = list(self.app.domains)
        tags_by = {vm.name: vm.tags.raw() for vm in vms}
        f = {(x.check, x.status) for x in fleet.project_findings(
            vms, {vm.name: vm for vm in vms}, self.records(), "ai-", gateways.load(), tags_by)}
        self.assertIn(("leads", "pass"), f)

    def test_a_read_that_fails_once_is_tried_again(self):
        calls = []
        real = anon.load_policy

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise anon.PolicyUnreadable("flaky")
            return real()
        anon.load_policy = flaky
        v = self.gate()[self.p.slot]
        self.assertEqual(v.status, anon.GREEN)
        self.assertNotIn("qmcp-blocked", self.tags(self.p.lead))

    def test_a_read_that_fails_twice_blocks_without_killing(self):
        anon.load_policy = lambda: (_ for _ in ()).throw(anon.PolicyUnreadable("down"))
        v = self.gate()[self.p.slot]
        self.assertEqual(v.status, anon.UNREADABLE)
        for name in self.qubes_of(self.p):
            self.assertIn("qmcp-blocked", self.tags(name))
        self.assertEqual(self.app.domains[self.p.lead]._power, "Running")
        self.assertIn("a read that failed twice", self.notices[0])

    def test_a_registry_that_cannot_be_read_blocks_without_killing(self):
        pathlib.Path(gateways.GATEWAYS_PATH).write_text("{not json")
        v = self.gate()[self.p.slot]
        self.assertEqual(v.status, anon.UNREADABLE, v.problems)
        self.assertIn("gateway registry", v.problems[0][1])
        self.assertIn("qmcp-blocked", self.tags(self.p.lead))
        self.assertEqual(self.app.domains[self.p.lead]._power, "Running")

    def test_a_member_whose_tags_cannot_be_read_is_never_skipped(self):
        # Without its tags the gate cannot tell it is a member: it judges nothing
        # sound over it, and blocks without killing once the read fails again.
        self.app.fail.add(f"tag.List:ai-{self.p.label}-w2")
        v = self.gate()[self.p.slot]
        self.assertEqual(v.status, anon.UNREADABLE, v.problems)
        self.assertEqual(self.app.domains[self.p.lead]._power, "Running")

    def test_every_read_the_gate_makes_failing_is_never_green_twice(self):
        # (A qube's class cannot fail: qubesadmin keeps it from the domain list.)
        keys = [f"get.netvm:{self.p.lead}", "get.netvm:ai-net-tor", "get.netvm:ai-tpl-g",
                f"get.template:{self.p.lead}", f"get.template:ai-{self.p.label}-w1",
                "tag.List:ai-tpl-g", f"tag.List:{self.p.lead}"]
        for key in keys:
            self.app.fail.add(key)
            v = self.gate(act=False)[self.p.slot]
            self.app.fail.discard(key)
            self.assertEqual(v.status, anon.UNREADABLE, key)
            self.assertGreater(self.app.failed[key], 0, f"{key} never failed: proves nothing")

    def test_unblock_waits_for_a_sound_project_and_leaves_autostart_off(self):
        for name in self.qubes_of(self.p):
            self.app.domains[name].autostart = True
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        self.gate()
        with self.assertRaisesRegex(fleet.RoleError, "unsound"):
            fleet.unblock(self.app, self.p.label)
        self.assertIn("qmcp-blocked", self.tags(self.p.lead))
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-whonix"]
        report = fleet.unblock(self.app, self.p.label)
        self.assertTrue(any("unblocked" in line for line in report), report)
        for name in self.qubes_of(self.p):
            self.assertNotIn("qmcp-blocked", self.tags(name))
            self.assertFalse(self.app.domains[name].autostart)
        self.assertTrue(self.lcall("qmcp.ListAIManagedQubes", lead=self.p.lead)["ok"])

    def test_one_run_at_a_time(self):
        import fcntl
        import os
        fd = os.open(anon.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            saved = anon.LOCK_WAIT_S
            anon.LOCK_WAIT_S = 0.1
            self.assertIsNone(anon.run(self.app))           # nothing was judged
            rc, out, err = self.cli("gate")
            self.assertEqual(rc, 3, err)
        finally:
            anon.LOCK_WAIT_S = saved
            os.close(fd)


# ======================================================================= the commands around it

class Commands(AnonBase):
    def test_edit_lead_move_and_model_keep_the_rules(self):
        a = self.app
        p = self.make()
        with self.assertRaisesRegex(fleet.RoleError, "not an anonymising"):
            fleet.edit_project(a, p.slot, networks=["ai-net-tor", "ai-net-router"])
        with self.assertRaisesRegex(fleet.RoleError, "managed"):
            fleet.edit_project(a, p.slot, templates=["ai-tpl-g", "ai-debian-13"])
        fleet.edit_project(a, p.slot, networks=["ai-net-tor", "ai-net-vpn", "none"])
        with self.assertRaisesRegex(fleet.RoleError, "made fresh"):
            fleet.set_lead(a, p.slot, "promote", "ai-hubq")
        with self.assertRaisesRegex(fleet.RoleError, "anonymous"):
            fleet.move(a, "ai-hubq", p.slot)
        with self.assertRaisesRegex(fleet.RoleError, "anonymous"):
            fleet.move(a, f"ai-{p.label}-w2", "p00", confirm=True)
        report = fleet.set_lead(a, p.slot, "template", "ai-tpl-g", lead_netvm="ai-net-vpn",
                                keep_old=True, model="api.example.org:443")
        new = projects.find(self.records(), p.slot).lead
        self.assertEqual(new, f"ai-{p.label}-lead2", report)
        self.assertLessEqual({"qmcp-anon", "qmcp-hubblind", "qmcp-lead"}, self.tags(new))
        self.green(projects.find(self.records(), p.slot))

    def test_an_anonymous_projects_model_qube_serves_it_alone(self):
        a = self.app
        a.vm("ai-hub-mq", template=a.domains["ai-tpl-g"], netvm=None, tags={"ai-managed"})
        fleet.set_lead_firewall(a, "p02", model_qube="ai-hub-mq")       # an ordinary project's
        p = self.make()
        with self.assertRaisesRegex(fleet.RoleError, "serves it alone"):
            fleet.set_lead_firewall(a, p.slot, model_qube="ai-hub-mq")
        a.vm("ai-hub-mq2", template=a.domains["ai-tpl-g"], netvm=None, tags={"ai-managed"})
        fleet.set_lead_firewall(a, p.slot, model_qube="ai-hub-mq2")
        with self.assertRaisesRegex(fleet.RoleError, "serves the anonymous"):
            fleet.set_lead_firewall(a, "p02", model_qube="ai-hub-mq2")

    def test_delete_keeps_what_holds_its_output_hidden(self):
        a = self.app
        a.vm("ai-hub-mq", template=a.domains["ai-tpl-g"], netvm=None, tags={"ai-managed"})
        p = self.make(dump=True, model=None, lead_netvm="none", model_qube="ai-hub-mq")
        report = fleet.delete_project(a, p.slot)
        self.assertIn("qmcp-hubblind", self.tags(p.dump))
        self.assertIn("qmcp-hubblind", self.tags("ai-hub-mq"))
        self.assertTrue(any("still hidden from the hub" in line for line in report), report)
        self.assertNotIn(p.lead, a.domains._vms)

    def test_a_hidden_projects_disposables_are_born_hidden(self):
        a = self.app
        a.vm("ai-dvm-anon", template=a.domains["ai-tpl-g"], template_for_dispvms=True,
             netvm=a.domains["ai-net-tor"], tags={"ai-managed", "qmcp-guarded"})
        p = self.make(templates=["ai-dvm-anon"])
        self.assertIn("qmcp-hubblind", self.tags("ai-dvm-anon"))
        seen = []
        real = a.qubesd_call

        def watch(dest, method, arg=None, payload=None):
            out = real(dest, method, arg, payload)
            if method == "admin.vm.CreateDisposable":
                name = out.decode()
                seen.append((name, set(a.domains._any(name).tags.raw()),
                             core.in_ai_space_by_name(a, name, hub=True)))
            return out
        a.qubesd_call = watch
        r = self.lcall("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-anon"}, lead=p.lead)
        a.qubesd_call = real
        self.assertTrue(r["ok"], r)
        name, tags, hub_sees = seen[0]
        self.assertIn("qmcp-hubblind", tags)          # from its first moment
        self.assertFalse(hub_sees)
        self.assertLessEqual({"qmcp-anon", "qmcp-hubblind", f"qmcp-proj-{p.slot}"}, self.tags(name))

    def test_check_fails_on_a_gate_that_cannot_run_or_has_stopped(self):
        import os
        p = self.make()
        os.chmod(anon.LOCK_PATH, 0)
        try:
            vms = list(self.app.domains)
            tags_by = {vm.name: vm.tags.raw() for vm in vms}
            f = fleet.anonymity_findings(self.app, vms, self.records(), tags_by)
        finally:
            os.chmod(anon.LOCK_PATH, 0o660)
        if os.geteuid() != 0:                       # root ignores the mode
            self.assertIn(("anonymity gate", "error"), {(x.check, x.status) for x in f})
        os.utime(anon.HEARTBEAT_PATH, (0, 0))       # the timer stopped long ago
        f = {(x.check, x.status) for x in fleet.anonymity_findings(
            self.app, vms, self.records(), tags_by)}
        self.assertIn(("gate heartbeat", "fail"), f)
        # Only the timer's runs beat: a check's own run must not hide a dead timer.
        self.assertIn(("gate heartbeat", "fail"), {(x.check, x.status) for x in
                                                   fleet.anonymity_findings(
                                                       self.app, vms, self.records(), tags_by)})
        os.environ[anon.HEARTBEAT_ENV] = "1"
        try:
            rc, out, err = self.cli("gate")
        finally:
            del os.environ[anon.HEARTBEAT_ENV]
        self.assertEqual(rc, 0, err)
        self.assertLess(anon.heartbeat_age(), 5)
        self.assertTrue(p.anonymous)

    def test_the_timer_beats_with_no_anonymous_project_too(self):
        # Else the first anonymous project reads as a dead timer until its next run.
        import os
        self.write_records({"version": 1, "slots": {}})
        os.utime(anon.HEARTBEAT_PATH, (0, 0))
        self.assertEqual(anon.run(self.app, beat=True), [])
        self.assertLess(anon.heartbeat_age(), 5)
        os.utime(anon.HEARTBEAT_PATH, (0, 0))
        self.assertEqual(anon.run(self.app), [])          # a check's run never beats
        self.assertGreater(anon.heartbeat_age(), 1000)

    def test_the_gate_makes_its_own_files_group_writable(self):
        import os
        import stat
        for path in (anon.LOCK_PATH, anon.HEARTBEAT_PATH):
            os.unlink(path)
        self.make()
        old = os.umask(0o077)                        # a hostile umask: the gate sets its own
        try:
            anon.run(self.app, beat=True)
        finally:
            os.umask(old)
        for path in (anon.LOCK_PATH, anon.HEARTBEAT_PATH):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o060, 0o060, path)

    def test_check_reports_the_gate_and_its_timer(self):
        p = self.make()
        vms = list(self.app.domains)
        tags_by = {vm.name: vm.tags.raw() for vm in vms}
        f = {(x.check, x.status) for x in fleet.anonymity_findings(self.app, vms, self.records(),
                                                                  tags_by)}
        self.assertIn(("anonymity gate", "pass"), f)
        self.assertIn(("gate timer", "pass"), f)
        self.timer = False
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        tags_by = {vm.name: vm.tags.raw() for vm in vms}
        f = {(x.check, x.status) for x in fleet.anonymity_findings(self.app, vms, self.records(),
                                                                  tags_by)}
        self.assertIn(("anonymity gate", "fail"), f)
        self.assertIn(("gate timer", "fail"), f)
        self.assertIn("qmcp-blocked", self.tags(p.lead))       # check acts as the gate does

    def test_the_gate_command_and_the_run_after_a_change(self):
        p = self.make()
        rc, out, err = self.cli("gate", "--json")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)[0]["status"], "green")
        self.app.domains["ai-net-tor"].netvm = self.app.domains["sys-firewall"]
        # Any change of the operator's runs the gate after it.
        rc, out, err = self.cli("project", "edit", "p01", "--quota", "21G")
        self.assertEqual(rc, 0, err)
        self.assertIn(f"stopped {p.label}", err)
        self.assertIn("qmcp-blocked", self.tags(p.lead))
        rc, out, err = self.cli("gate")
        self.assertEqual(rc, 1)
        self.assertIn("(blocked)", out)

    def test_the_create_command_line(self):
        rc, out, err = self.cli("project", "create", "--anonymous", "--lead-template", "ai-tpl-g",
                                "--lead-netvm", "ai-net-tor", "--model", "api.example.org:443",
                                "--network", "ai-net-tor", "--quota", "5G", "--note", "private")
        self.assertEqual(rc, 0, err)
        line = self.operator_lines()[-1]
        self.assertEqual((line["args"]["anonymous"], line["args"]["note"]), (True, "set"))
        self.assertNotIn("private", json.dumps(line))
        rc, out, err = self.cli("project", "create", "--lead-template", "ai-tpl-g",
                                "--network", "none", "--quota", "5G")
        self.assertEqual(rc, 1)
        self.assertIn("give the project a LABEL", err)


# ======================================================================= proposals

def anon_create(**kw):
    req = {"type": "project-create", "title": "an anonymous one", "anonymous": True,
           "lead": {"from": "template", "qube": "ai-tpl-g"}, "lead_netvm": "ai-net-tor",
           "model": "api.example.org:443", "networks": ["ai-net-tor"], "quota": 5 * GiB}
    req.update(kw)
    return req


class Proposals(AnonBase):
    def test_the_shape(self):
        p = proposals.normalise(anon_create(), "ai-")
        self.assertEqual((p["anonymous"], p["label"]), (True, None))
        self.assertNotIn("hub_sees", p)
        self.assertEqual(proposals.normalise(p, "ai-"), p)      # a fixed point
        bad = [({"label": "x"}, "picked by dom0"), ({"lead_name": "ai-x-lead"}, "named by dom0"),
               ({"lead": {"from": "clone", "qube": "ai-work"}}, "made fresh")]
        for change, msg in bad:
            with self.assertRaisesRegex(proposals.Invalid, msg):
                proposals.normalise(anon_create(**change), "ai-")
        with self.assertRaisesRegex(proposals.Invalid, "goes with anonymous"):
            proposals.normalise(dict(anon_create(anonymous=False), label="x", hub_sees=True), "ai-")
        self.assertIn("--anonymous", proposals.command(p))
        self.assertNotIn("None", proposals.command(p))

    def test_accepting_one_tells_the_hub_nothing_of_what_was_created(self):
        r = self.submit(anon_create(dump=True))
        self.assertTrue(r["ok"], r)
        doc = proposals.show(self.app, r["id"])
        self.assertTrue(any("anonymous project" in x for x in doc["second_tick"]))
        self.assertTrue(any(fleet.HIDDEN_WARNING in x for x in doc["second_tick"]))
        with self.assertRaisesRegex(proposals.Refused, "second tick"):
            self.accept(r["id"])
        ok, report = self.accept(r["id"], yes=True)
        self.assertTrue(ok, report)
        p = next(p for p in self.records().values() if p.anonymous)
        self.assertTrue(p.hidden)
        status = json.dumps(self.status({"id": r["id"]}))
        self.assertIn('"accepted"', status)
        self.assertNotIn(p.label, status)
        self.assertNotIn(p.lead, status)

    def test_a_proposal_naming_a_hidden_project_fails_as_a_missing_one(self):
        p = self.make()
        for req in ({"type": "project-delete", "title": "t", "project": p.label},
                    {"type": "project-edit", "title": "t", "project": p.label, "quota": GiB}):
            r = self.submit(req)
            doc = proposals.show(self.app, r["id"])
            ok, report = self.accept(r["id"], yes=bool(doc["tick"]))
            self.assertFalse(ok)
            self.assertIn(f"no project '{p.label}'", "\n".join(report))
        self.assertIn(p.lead, self.app.domains._vms)

    def test_a_visible_one_takes_proposals(self):
        p = self.make(hub_sees=True)
        r = self.submit({"type": "project-edit", "title": "t", "project": p.label,
                         "add_networks": ["ai-net-router"]})
        ok, report = self.accept(r["id"], yes=bool(proposals.show(self.app, r["id"])["tick"]))
        self.assertFalse(ok)                 # the command refuses a clearnet network
        self.assertIn("not an anonymising", "\n".join(report))
        r = self.submit({"type": "project-edit", "title": "t", "project": p.label, "quota": 2 * GiB})
        ok, report = self.accept(r["id"], yes=bool(proposals.show(self.app, r["id"])["tick"]))
        self.assertTrue(ok, report)


if __name__ == "__main__":
    unittest.main()
