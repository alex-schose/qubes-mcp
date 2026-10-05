"""Offline suite for the operator's window: qmcp.guimodel, qmcp.gui, and the
reads the window added to the `qmcp` command.

The window drives the command and nothing else, so these tests drive it the
same way: `CliRunner` hands every argv the window builds to `qmcp.cli.main`,
in-process, against the fake qubesadmin, as `sudo -n qmcp ...` (a change) or
`qmcp ...` (a read) would run in dom0. A form that builds the wrong command,
or a command the real parser rejects, fails here.

Four guarantees, each with a test that fails when it breaks:
- **It cannot go stale.** Every command and option of the parser, every field
  of every read, is offered or shown by the window, or exempted in
  `guimodel` by name with a reason (`Parity`).
- **Every displayed string is escaped.** `esc()` is checked against hostile
  text; the GTK layer accepts only its output, and no markup API appears in
  it (`Escaping`, `Structure`, `Widgets`).
- **Roles come from records and badges, never a label colour** (`Model`).
- **It never imports qubesadmin and never runs as root** (`Structure`,
  `Widgets`).
- **A proposal runs only as it was read**: accepted with the fingerprint of the
  `proposal show` on display, with the second tick when the command asks for
  one, and never from a show that failed (`ProposalModel`, `Widgets`).
- **A lead's firewall is shown as it was read**: rules that could not be read
  are never an empty list, a form that changes them shows them now and after,
  and runs only while the view it was opened on still reads the same
  (`FirewallModel`, `Widgets`). The forms offer only enrolled gateways
  (`GatewayModel`, `LeadModel`).

The GTK tests build widgets without showing them, and are skipped where GTK
cannot start (no PyGObject, or no display).
"""
from __future__ import annotations

import argparse
import ast
import fcntl
import io
import json
import os
import pathlib
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, cli, firewall, fleet, gateways, projects, proposals  # noqa: E402
from qmcp import guimodel as gm  # noqa: E402
from fakequbes import GiB, _qubesd_rule  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_projects import LEAD, OTHER_LEAD, ProjectBase  # noqa: E402

GUI_SRC = HERE.parent / "dom0" / "qmcp" / "gui.py"
MODEL_SRC = HERE.parent / "dom0" / "qmcp" / "guimodel.py"
#: Rules a lead-firewall proposal sets, as the hub sends them.
RULES = ["action=accept proto=tcp dsthost=example.com dstports=443",
         "action=accept specialtarget=dns", "action=drop"]
#: One proposal of every type the hub can submit, and every option, each
#: valid on the projects fixture. The delete and the two lead-firewall ones
#: need the second tick there.
PROPOSALS = {
    "create": {"type": "project-create", "title": "new project <b>newp</b>", "label": "newp",
               "lead": {"from": "template", "qube": "ai-debian-13"},
               "networks": ["ai-net-router"], "quota": 5 * GiB},
    "edit": {"type": "project-edit", "title": "more room for other", "project": "other",
             "add_networks": ["ai-net-router"], "default_network": "ai-net-router",
             "quota": 15 * GiB},
    "dump": {"type": "project-dump", "title": "a sink for other", "project": "other"},
    "lead": {"type": "project-lead", "title": "a new lead for other", "project": "other",
             "lead": {"from": "clone", "qube": "ai-work2"}, "lead_name": "ai-other-boss",
             "keep_old": True},
    "delete": {"type": "project-delete", "title": "remove osint", "project": "osint"},
    "rules": {"type": "project-firewall", "title": "example.com for osint's lead",
              "project": "osint", "rules": RULES},
    "model": {"type": "project-firewall", "title": "a model for osint's lead", "project": "osint",
              "model": "api.anthropic.com:443"},
    "netlead": {"type": "project-lead", "title": "a networked lead for osint", "project": "osint",
                "lead": {"from": "template", "qube": "ai-debian-13"}, "lead_netvm": "ai-net-router",
                "lead_name": "ai-osint-boss", "keep_old": True, "add_old_network": True,
                "model": "api.anthropic.com:443"},
}
HOSTILE = "ai-x\u202egnp.exe\nFAKE ok:true <b>bold</b> &amp; \x00\x7f\u200b\x1b[31m"


def _gtk():
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
        return Gtk if Gtk.init_check(None)[0] else None
    except Exception:
        return None


Gtk = _gtk()


class CliRunner:
    """What `Gio.Subprocess` does for the window, in-process: a change runs as
    root (`sudo -n` stripped, euid 0), a read as the user. `hold` keeps the
    reply back, so a test can look at the window while a command runs."""

    def __init__(self, app, hold=False):
        self.app, self.hold = app, hold
        self.calls: list = []
        self.timeouts: list = []
        self.held: list = []
        self.fail: set = set()          # argv tuples to answer as a failed read

    def run(self, argv, done, timeout=None):
        self.calls.append(list(argv))
        self.timeouts.append(timeout)
        if tuple(argv) in self.fail:
            done(gm.Result(argv, 1, "", "QubesDaemonCommunicationError"))
            return
        if self.hold:
            self.held.append((argv, done))
            return
        done(self.execute(argv))

    def release(self):
        argv, done = self.held.pop(0)
        done(self.execute(argv))

    def execute(self, argv):
        argv = list(argv)
        root = argv[:2] == list(gm.SUDO)
        rest = argv[2:] if root else argv
        assert rest[0] == gm.QMCP, argv
        saved = cli._app, os.geteuid, fleet.check
        real_check = fleet.check
        cli._app = lambda: self.app
        fleet.check = lambda app, **kw: real_check(app, legacy_paths=(),
                                                   system_info={"domains": {}}, **kw)
        if root:
            os.geteuid = lambda: 0
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    rc = cli.main(rest[1:])
                except SystemExit as e:
                    if isinstance(e.code, str):
                        err.write(e.code + "\n")
                        rc = 1
                    else:
                        rc = 0 if e.code is None else e.code
        finally:
            cli._app, os.geteuid, fleet.check = saved
        return gm.Result(argv, rc, out.getvalue(), err.getvalue())


class GuiBase(ProjectBase):
    def setUp(self):
        super().setUp()
        self.runner = CliRunner(self.app)

    def read(self, *args):
        result = self.runner.execute(gm.read_cmd(*args))
        return result

    def read_json(self, *args):
        return json.loads(self.read(*args).out)

    def tree(self):
        return gm.build_tree(self.read_json("list", "--all", "--json"),
                             self.read_json("project", "list", "--json"),
                             self.read_json("settings", "--json"))

    def node(self, key):
        return next(n for n in gm.walk(self.tree()) if n.key == key)

    def submit_proposal(self, name, **changes):
        """A proposal from the hub, through the real service."""
        reply = self.call("qmcp.SubmitProposal", dict(PROPOSALS[name], **changes))
        self.assertTrue(reply["ok"], reply)
        return reply

    def show(self, pid):
        return gm.parse_proposal(self.runner.execute(gm.show_proposal(pid)), pid)

    def routers(self):
        """The operator's own routers, outside AI space and not enrolled:
        sys-ai-net behind sys-firewall, and sys-ai-tor behind a Whonix
        gateway, which wears Whonix's own tag. Both on a template that
        advertises Qubes' firewall marker."""
        a = self.app
        a.domains["debian-13"].features["qubes-firewall"] = "1"
        fw = a.domains["sys-firewall"]
        a.vm("sys-ai-net", provides_network=True, netvm=fw, template=a.domains["debian-13"])
        a.vm("sys-whonix", provides_network=True, netvm=fw, tags={"anon-gateway"},
             features={"qubes-firewall": "1"})
        a.vm("sys-ai-tor", provides_network=True, netvm=a.domains["sys-whonix"],
             template=a.domains["debian-13"])

    def gateways(self):
        return self.read_json("gateway", "list", "--json")

    def view(self, key="osint"):
        """The lead firewall of a project, as the window reads it."""
        return gm.parse_firewall(self.runner.execute(gm.show_lead_firewall(key)), key)

    def lead_rules(self, name=LEAD):
        return list(self.app.domains[name].__dict__["_firewall"])


# ======================================================================= escaping

class Escaping(unittest.TestCase):
    def test_hostile_text_comes_out_ascii_and_visible(self):
        out = gm.esc(HOSTILE)
        self.assertIsInstance(out, gm.Shown)
        self.assertTrue(out.isascii())
        self.assertTrue(all(0x20 <= ord(c) < 0x7f for c in out), out)
        for escape in ("\\u202e", "\\n", "\\u0000", "\\u007f", "\\u200b", "\\u001b"):
            self.assertIn(escape, out)
        self.assertNotIn("\n", out)
        # Markup is only text here: plain-text widgets show it literally.
        self.assertIn("<b>bold</b>", out)

    def test_what_the_command_prints_is_what_the_window_shows(self):
        rec = {"args": {"name": HOSTILE}, "ok": False}
        self.assertIn(gm.esc(HOSTILE), json.dumps(rec, sort_keys=True))

    def test_values_of_every_type(self):
        self.assertEqual(gm.esc(None), "-")
        self.assertEqual((gm.esc(True), gm.esc(False), gm.esc(7)), ("yes", "no", "7"))
        self.assertEqual(gm.esc({"b": 1, "a": "\u202e"}), '{"a": "\\u202e", "b": 1}')
        self.assertEqual(gm.esc(["none", None]), '["none", null]')
        self.assertTrue(gm.esc(object()).isascii())
        for value in (None, True, 3, "x", [1], {"a": 1}, object()):
            self.assertIsInstance(gm.esc(value), gm.Shown, value)

    def test_lines_keep_their_breaks_and_lose_everything_else(self):
        out = gm.esc_lines("p01: removed\nai-\u202ex: gone\r\n")
        self.assertIsInstance(out, gm.Shown)
        self.assertEqual(out.split("\n"), ["p01: removed", "ai-\\u202ex: gone"])

    def test_composed_text_is_plain_again(self):
        # A Shown joined or formatted is a str: the widgets refuse it, so text
        # is composed raw and escaped once.
        self.assertNotIsInstance(gm.esc("a") + gm.esc("b"), gm.Shown)
        self.assertNotIsInstance(f"{gm.esc('a')}", gm.Shown)

    def test_sizes(self):
        self.assertEqual(gm.size(20 * 1024 ** 3), "20.0 GiB")
        self.assertEqual(gm.size(None), "-")
        self.assertEqual(gm.quota_text(20 * 1024 ** 3), "20G")
        self.assertEqual(gm.quota_text(1500), "1500")
        self.assertEqual(gm.quota_text(True), "")


# ======================================================================= parity: it cannot go stale

def _options(sp, skip=None) -> set:
    out = set()
    for a in sp._actions:
        if isinstance(a, argparse._HelpAction) or a is skip:
            continue
        if a.option_strings:
            out.add(max(a.option_strings, key=len))
        elif a.nargs in ("?", "*"):
            out.add(a.dest)
    return out


def _leaves(parser):
    """(command path, option-key prefix, subparser, the choices positional)."""
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    for cmd, sp in sub.choices.items():
        nested = [a for a in sp._actions if isinstance(a, argparse._SubParsersAction)]
        if nested:
            for what, leaf in nested[0].choices.items():
                yield (cmd, what), (cmd, what), leaf, None
            continue
        chooser = next((a for a in sp._actions if a.choices and not a.option_strings), None)
        if chooser is not None:
            for what in chooser.choices:
                yield (cmd, what), (cmd,), sp, chooser
        else:
            yield (cmd,), (cmd,), sp, None


def cli_keys(parser) -> set:
    keys = set()
    for path, prefix, sp, chooser in _leaves(parser):
        keys.add(path)
        keys |= {prefix + (opt,) for opt in _options(sp, chooser)}
    return keys


def covered_by(parser, argv) -> set:
    rest = argv[2:] if argv[:2] == list(gm.SUDO) else argv
    assert rest[0] == gm.QMCP, argv
    ns = parser.parse_args(rest[1:])
    for path, prefix, sp, chooser in _leaves(parser):
        if path[0] != ns.cmd:
            continue
        if len(path) == 2 and getattr(ns, "what", None) != path[1]:
            continue
        keys = {path}
        for a in sp._actions:
            if isinstance(a, argparse._HelpAction) or a is chooser:
                continue
            if not (a.option_strings or a.nargs in ("?", "*")):
                continue
            if getattr(ns, a.dest) != a.default:
                keys.add(prefix + ((max(a.option_strings, key=len),) if a.option_strings else (a.dest,)))
        return keys
    raise AssertionError(f"no command for {argv}")


#: One or more calls of every builder the window uses.
SAMPLES = {
    gm.create_project: [
        dict(label="newp", lead_source="template", lead_origin="ai-debian-13",
             lead_name="ai-newp-boss", lead_netvm="ai-net-router", templates=["ai-dvm"],
             networks=["ai-net-router", "none"], quota="5G", dump=True),
        dict(label="newq", lead_source="clone", lead_origin="ai-work2", networks=["none"],
             quota="1G"),
        dict(label="newr", lead_source="promote", lead_origin="ai-work2", networks=["none"],
             quota="1G"),
        dict(label="news", lead_source="template", lead_origin="ai-debian-13",
             lead_netvm="ai-net-router", networks=["none"], quota="1G",
             model="api.anthropic.com:443"),
    ],
    gm.edit_project: [dict(key="osint", templates=["ai-debian-13"], networks=["none"], quota="30G")],
    gm.remove_lead: [dict(key="osint")],
    gm.change_lead: [dict(key="osint", lead_source="clone", lead_origin="ai-work2",
                          lead_name="ai-osint-lead2", lead_netvm="none", keep_old=True),
                     dict(key="osint", lead_source="template", lead_origin="ai-debian-13"),
                     dict(key="osint", lead_source="promote", lead_origin="ai-work2"),
                     dict(key="osint", lead_source="template", lead_origin="ai-debian-13",
                          lead_name="ai-osint-boss", lead_netvm="ai-net-router", keep_old=True,
                          model="api.anthropic.com:443", add_old_network=True)],
    gm.add_dump: [dict(key="other", sink_name="other-sink")],
    gm.move: [dict(qube="ai-work2", target="osint", confirm=True)],
    gm.delete_plan: [dict(key="osint")],
    gm.delete_project: [dict(key="osint")],
    gm.role: [dict(action="manage", qube="x1"), dict(action="guard", qube="x1"),
              dict(action="revoke", qube="x1", keep_running=True)],
    gm.audit_rotate: [dict()],
    gm.show_proposal: [dict(pid=1)],
    gm.accept_proposal: [dict(pid=1, sha256="0" * 64), dict(pid=2, sha256="ab" * 32, tick="cd" * 32)],
    gm.reject_proposal: [dict(pid=1)],
    gm.enroll_gateway: [dict(qube="sys-ai-tor", anonymising=True, label="Tor, CH")],
    gm.change_gateway: [dict(qube="ai-net-router", anonymising=False, label="clearnet")],
    gm.remove_gateway: [dict(qube="ai-net-router")],
    gm.show_lead_firewall: [dict(key="osint")],
    gm.set_lead_model: [dict(key="osint", model="api.anthropic.com:443")],
    gm.set_lead_rules: [dict(key="osint", rules=RULES)],
    gm.accept_lead_rules: [dict(key="osint")],
}


class Parity(GuiBase):
    """Decision: the window cannot go stale. Each test here fails when the
    command grows something the window neither offers nor exempts."""

    def setUp(self):
        super().setUp()
        self.parser = cli.build_parser()

    def window_argvs(self):
        out = list(gm.READS.values()) + [gm.AUDIT_VERIFY]
        for builder, calls in SAMPLES.items():
            out += [builder(**kw) for kw in calls]
        return out

    def test_every_builder_is_sampled(self):
        self.assertEqual(set(SAMPLES), set(gm.BUILDERS))

    def test_every_command_and_option_is_offered_or_exempted(self):
        covered = set()
        for argv in self.window_argvs():
            covered |= covered_by(self.parser, argv)
        exempt = set(gm.CLI_ONLY) | set(gm.SHOWN_BY)
        missing = {k for k in cli_keys(self.parser) - covered
                   if not any(k[:len(e)] == e for e in exempt)}
        self.assertEqual(missing, set(),
                         "the qmcp command has commands or options the window does not offer: "
                         "add them to a form, or exempt them in guimodel with a reason")

    def test_no_exemption_is_stale_or_contradicted(self):
        keys = cli_keys(self.parser)
        covered = set()
        for argv in self.window_argvs():
            covered |= covered_by(self.parser, argv)
        for entry, reason in {**gm.CLI_ONLY, **gm.SHOWN_BY}.items():
            under = {k for k in keys if k[:len(entry)] == entry}
            self.assertTrue(under, f"{entry} exempts nothing the command has")
            self.assertTrue(under - covered, f"{entry} is exempted but the window offers it")
            self.assertGreater(len(reason), 20, entry)

    def test_every_window_command_parses_with_the_real_parser(self):
        for argv in self.window_argvs():
            covered_by(self.parser, argv)       # raises SystemExit on a bad command

    def test_every_field_of_every_read_is_shown(self):
        rows = self.read_json("list", "--all", "--json")
        fields = set().union(*(r.keys() for r in rows))
        self.assertEqual(fields, {k for k, _ in gm.QUBE_FIELDS})
        self.assertLessEqual({k for k, _ in gm.COLUMNS} - {"name", "role"}, fields)
        prows = self.read_json("project", "list", "--json")
        self.assertEqual(set().union(*(r.keys() for r in prows)), {k for k, _ in gm.PROJECT_FIELDS})
        for p in projects.load().values():
            self.assertLessEqual(set(p.to_json()), {k for k, _ in gm.PROJECT_FIELDS})
        self.assertEqual(set(self.read_json("settings", "--json")), {k for k, _ in gm.SETTINGS_FIELDS})
        doc = self.read_json("check", "--json")
        self.assertEqual(set(doc), set(gm.CHECK_DOC_FIELDS))
        self.assertEqual(set().union(*(f.keys() for f in doc["findings"])),
                         {k for k, _ in gm.CHECK_FIELDS})
        # The gateway registry, and a lead's firewall: named, and on screen.
        self.routers()
        self.assertEqual(self.runner.execute(gm.enroll_gateway("sys-ai-tor", True, "Tor")).rc, 0)
        gws = self.gateways()
        self.assertEqual(set().union(*(r.keys() for r in gws)), {k for k, _ in gm.GATEWAY_FIELDS})
        self.assertLessEqual({k for k, _ in gm.GATEWAY_COLUMNS} - {"used", "notes"},
                             {k for k, _ in gm.GATEWAY_FIELDS})
        for row in gws:
            self.assertEqual([h for h, _ in gm.gateway_details(row)],
                             [h for _, h in gm.GATEWAY_FIELDS])
        for failing in (True, False):                       # so read_error carries something
            (self.app.fail.add if failing else self.app.fail.discard)("admin.vm.firewall.Get")
            view = self.view()
            self.assertEqual(set(view), set(gm.FIREWALL_OF) | {k for k, _ in gm.FIREWALL_FIELDS})
            shown = dict(gm.firewall_details(view))
            for key, heading in gm.FIREWALL_FIELDS:
                if key != "read_error" or view[key] is not None:
                    self.assertIn(heading, shown, key)
            self.assertEqual(shown["Lead firewall of"], f"osint (p01), lead {LEAD}")
            self.assertEqual(failing, view["read_error"] is not None)

    def test_every_field_of_an_audit_line_is_shown_or_left_to_verify(self):
        self.app.fail.add("start")
        self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"})   # error_class
        self.call("qmcp.LifecycleAIManaged", {"name": "nope", "action": "start"})       # refusal
        recs = gm.parse_audit(self.read("audit", "tail", "50"))
        fields = set().union(*(r.keys() for r in recs))
        shown = {k for k, _ in gm.AUDIT_FIELDS}
        self.assertEqual(fields - shown, set(gm.AUDIT_NOT_SHOWN))
        self.assertLessEqual(shown, fields)

    def test_every_field_of_every_proposal_read_is_shown(self):
        # One proposal of every type, through the real service and the real
        # command; two decided, so a decision with a report is read as well.
        ids = {name: self.submit_proposal(name)["id"] for name in PROPOSALS}
        self.runner.execute(gm.accept_proposal(ids["dump"], self.show(ids["dump"])["sha256"]))
        self.runner.execute(gm.reject_proposal(ids["lead"]))
        rows = self.read_json("proposal", "list", "--json")
        self.assertEqual(len(rows), len(PROPOSALS))
        listed = {k for k, _ in gm.PROPOSAL_FIELDS}
        self.assertEqual(set().union(*(r.keys() for r in rows)), listed)
        self.assertLessEqual({k for k, _ in gm.PROPOSAL_COLUMNS}, listed)
        docs = [self.read_json("proposal", "show", str(r["id"]), "--json") for r in rows]
        for doc in docs:
            self.assertEqual(set(doc), listed | {k for k, _ in gm.PROPOSAL_SHOW_FIELDS}
                             | set(gm.PROPOSAL_BY_PART))
        options = set().union(*(doc["proposal"].keys() for doc in docs))
        self.assertEqual(options - {"type", "title"}, {k for k, _ in gm.PROPOSAL_OPTIONS})
        # An edit's before and after are its record's parts; a lead
        # firewall's, its model and its rules now and after.
        with_before = {doc["type"]: doc for doc in docs if doc["before"] is not None}
        self.assertEqual(set(with_before), {"project-edit", "project-firewall"})
        for doc in docs:
            if doc["before"] is None:
                continue
            table = gm.FIREWALL_CHANGE if doc["type"] == "project-firewall" else gm.EDIT_FIELDS
            self.assertEqual(set(doc["before"]) | set(doc["after"]), {k for k, _ in table},
                             doc["type"])
        decisions = [doc["decision"] for doc in docs if doc["decision"] is not None]
        self.assertEqual(len(decisions), 2)
        fields = set().union(*(d.keys() for d in decisions))
        self.assertEqual(fields - {k for k, _ in gm.DECISION_FIELDS}, set(gm.DECISION_NOT_SHOWN))
        self.assertLessEqual({k for k, _ in gm.DECISION_FIELDS}, fields)
        # Named is not enough: each field that carries something is on screen.
        self.assertEqual({"proposal", "before", "after", "decision"}, set(gm.PROPOSAL_BY_PART))
        self.assertTrue(any(doc["tick"] for doc in docs))
        for doc in docs:
            shown = {h for h, _ in gm.proposal_details(doc)}
            change = gm.FIREWALL_CHANGE if doc["type"] == "project-firewall" else gm.EDIT_FIELDS
            parts = {"proposal": gm.PROPOSAL_OPTIONS, "before": change, "after": change,
                     "decision": gm.DECISION_FIELDS}
            for key, heading in gm.PROPOSAL_SHOW_FIELDS:
                if doc[key] or (key == "second_tick" and doc["state"] == "pending"):
                    self.assertIn(heading, shown, (doc["id"], key))
            for key, table in parts.items():
                if doc[key]:
                    self.assertTrue({h for _, h in table} & shown, (doc["id"], key))
            if doc["type"] == "project-firewall" and doc["before"] is not None:
                self.assertLessEqual({h for _, h in gm.FIREWALL_CHANGE}, shown)


# ======================================================================= the model

class Model(GuiBase):
    def test_the_tree(self):
        tree = self.tree()
        self.assertEqual([n.key for n in tree][:2], ["hub", "group:projects"])
        hub = tree[0]
        self.assertEqual(hub.cells[0], HUB)
        p00 = hub.children[0]
        self.assertEqual([c.key for c in p00.children], ["qube:ai-hubq"])
        noslot = {c.key for c in hub.children[1].children}
        self.assertEqual(noslot, {"qube:ai-work", "qube:ai-work2", "qube:ai-on-operator-tpl"})
        osint = self.node("project:p01")
        self.assertEqual([c.key for c in osint.children],
                         [f"qube:{LEAD}", "qube:ai-osint-w1", "qube:ai-osint-w2", "qube:osint-dump"])
        self.assertEqual([c.data["role"] for c in osint.children],
                         ["lead", "worker", "worker", "dump sink"])
        groups = {n.key: {c.key for c in n.children} for n in tree[2:]}
        self.assertEqual(groups["group:templates"], {"qube:ai-debian-13", "qube:ai-tpl-g",
                                                     "qube:ai-dvm", "qube:ai-dvm-g"})
        self.assertEqual(groups["group:gateways"], {"qube:ai-net-router"})
        # A gateway without qmcp-guarded: the services refuse it, but the rulebook's
        # guarded denies key on the badge, so the hub may run commands in it. The
        # first version of this test asserted no Needs attention here, and blessed it.
        self.assertEqual(groups["group:attention"], {"qube:ai-gw-unbadged"})
        keys = [n.key for n in gm.walk(tree)]
        self.assertEqual(len(keys), len(set(keys)), "a key names two rows")
        names = {n.data.get("name") for n in gm.walk(tree) if n.kind == "qube"}
        self.assertNotIn("personal", names)                 # outside AI space: not in the tree
        self.assertNotIn(HUB, names)

    def test_roles_come_from_badges_and_records_never_the_label(self):
        before = [(n.key, n.cells) for n in gm.walk(self.tree())]
        self.app.domains["ai-osint-w1"].label = "purple"    # the hub may set label
        self.assertEqual([(n.key, n.cells) for n in gm.walk(self.tree())], before)
        self.assertNotIn("label", {k for k, _ in gm.QUBE_FIELDS})

    SCENARIOS = {
        # name: (mutation, the qube, why)
        "a lead without qmcp-lead keeps its slot's exec": (
            lambda a: a.domains[LEAD].tags.discard("qmcp-lead"), LEAD, "lead"),
        "a lead that is also a member": (
            lambda a: a.domains[OTHER_LEAD].tags.add("qmcp-proj-p02"), OTHER_LEAD, "lead"),
        "lead badges with no record": (
            lambda a: a.vm("ai-rogue", tags={"ai-managed", "qmcp-lead", "qmcp-lead-p05"}),
            "ai-rogue", "lead"),
        "in two slots": (
            lambda a: a.domains["ai-work2"].tags.update({"qmcp-proj-p01", "qmcp-proj-p02"}),
            "ai-work2", "two_slots"),
        "a template in a project": (
            lambda a: a.domains["ai-dvm"].tags.add("qmcp-proj-p01"), "ai-dvm", "template_member"),
        "a sink badge in AI space": (
            lambda a: a.domains["ai-work"].tags.add("qmcp-dump-p01"), "ai-work", "drop_box"),
        "the hub in AI space": (
            lambda a: a.domains[HUB].tags.add("ai-managed"), HUB, "hub"),
        "lead badges outside AI space": (
            lambda a: a.domains["personal"].tags.update({"qmcp-lead", "qmcp-lead-p04"}),
            "personal", "outside"),
        "a member badge outside AI space": (
            lambda a: a.domains["personal"].tags.add("qmcp-proj-p02"), "personal", "outside"),
    }

    def test_what_check_fails_on_is_under_needs_attention(self):
        def failing():
            doc = self.read_json("check", "--json")
            return {(f["check"], f["detail"]) for f in doc["findings"] if f["status"] == "fail"}
        for label, (mutate, name, why) in self.SCENARIOS.items():
            with self.subTest(label):
                self.doCleanups()
                self.setUp()
                before = failing()
                mutate(self.app)
                new = " ".join(detail for _, detail in failing() - before)
                self.assertIn(name, new, "check must fail on it first")
                tree = self.tree()
                placed = [n for n in gm.walk(tree) if n.kind == "qube" and n.data.get("name") == name]
                self.assertEqual([n.data.get("attention") for n in placed], [why])
                self.assertEqual(gm.actions(placed[0], {}), {"new_project", "add_to_ai_space"})
                keys = [n.key for n in gm.walk(tree)]
                self.assertEqual(len(keys), len(set(keys)))

    def test_a_qube_that_cannot_be_read_is_under_needs_attention(self):
        # A failed read is never state: the qube is shown, placed by none of
        # the values that failed, and offers nothing until it reads.
        for key, name in (("tag.List:ai-work", "ai-work"),
                          ("get.provides_network:ai-work2", "ai-work2"),
                          ("get.template_for_dispvms:ai-dvm", "ai-dvm")):
            with self.subTest(key):
                self.app.fail.add(key)
                try:
                    tree = self.tree()
                    rows = self.read_json("list", "--all", "--json")
                finally:
                    self.app.fail.discard(key)
                placed = [n for n in gm.walk(tree) if n.kind == "qube" and n.data.get("name") == name]
                self.assertEqual([n.data.get("attention") for n in placed], ["unreadable"])
                self.assertEqual(gm.actions(placed[0], {}), {"new_project", "add_to_ai_space"})
                self.assertNotIn(name, gm.approved_template_choices(rows))
                self.assertNotIn(name, gm.hubs_appvms(rows, HUB))
                self.assertNotIn(name, gm.enroll_choices(rows, []))
        # A template, and a qube outside AI space, that cannot be read are offered
        # by no form either.
        for key, name, offers in (("tag.List:ai-debian-13", "ai-debian-13", gm.lead_templates),
                                  ("get.provides_network:personal", "personal",
                                   lambda rows: gm.outside_choices(rows, HUB))):
            with self.subTest(key):
                self.assertIn(name, offers(self.read_json("list", "--all", "--json")))
                self.app.fail.add(key)
                try:
                    rows = self.read_json("list", "--all", "--json")
                finally:
                    self.app.fail.discard(key)
                self.assertNotIn(name, offers(rows))

    def test_a_network_that_cannot_be_read_is_said_so_by_the_forms(self):
        # In the commands' own words (fleet._lead_network, fleet._set_lead),
        # never as a network called "<unreadable>" or as none.
        self.app.fail.add("get.netvm:ai-hubq")
        self.app.fail.add(f"get.netvm:{LEAD}")
        try:
            rows = self.read_json("list", "--all", "--json")
        finally:
            self.app.fail.clear()
        gws = self.read_json("gateway", "list", "--json")
        with self.assertRaises(gm.FormError) as cm:
            gm.lead_network("promote", "ai-hubq", None, rows, gws)
        self.assertIn("the network of 'ai-hubq' cannot be read", str(cm.exception))
        osint = {r["slot"]: r for r in self.read_json("project", "list", "--json")}["p01"]
        with self.assertRaises(gm.FormError) as cm:
            gm.old_lead_network(osint, rows, gws, True, False)
        self.assertIn(f"the network of the old lead {LEAD} cannot be read", str(cm.exception))
        self.assertEqual(gm.old_lead_network(osint, rows, gws, False, False), "")   # not kept

    def test_an_unguarded_gateway_can_be_guarded_from_its_row(self):
        node = self.node("qube:ai-gw-unbadged")
        self.assertEqual(node.data["attention"], "gateway")
        self.assertIn("guard", gm.actions(node, {}))

    def test_an_unfinished_delete_shows_its_slot(self):
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        del doc["slots"]["p02"]
        self.write_records(doc)
        node = self.node("slot:p02")
        self.assertEqual({c.key for c in node.children}, {"qube:ai-other-w1"})
        self.assertIn("finish_delete", gm.actions(node, {}))
        self.assertEqual(gm.project_key(node), "p02")

    def test_actions_follow_the_selection(self):
        records = {r["slot"]: r for r in self.read_json("project", "list", "--json")}
        a = lambda key: gm.actions(self.node(key), records)  # noqa: E731
        self.assertEqual(gm.actions(None, records), {"new_project", "add_to_ai_space"})
        self.assertLessEqual({"edit_project", "change_lead", "remove_lead", "delete_project"},
                             a("project:p01"))
        self.assertNotIn("add_dump", a("project:p01"))      # it has one
        self.assertIn("add_dump", a("project:p02"))
        self.assertIn("add_dump", a("slot:p00"))
        self.assertLessEqual({"move", "revoke"}, a("qube:ai-osint-w1"))
        self.assertNotIn("revoke", a(f"qube:{LEAD}"))
        self.assertNotIn("move", a(f"qube:{LEAD}"))
        self.assertLessEqual({"move", "guard", "revoke"}, a("qube:ai-work2"))
        self.assertIn("manage", a("qube:ai-tpl-g"))
        self.assertNotIn("manage", a("qube:ai-net-router"))   # a gateway stays guarded
        self.assertEqual(a("qube:ai-gw-unbadged") - {"new_project", "add_to_ai_space"}, {"guard"})
        self.assertNotIn("revoke", a("qube:osint-dump"))      # outside AI space

    def test_details_show_every_field(self):
        node = self.node("project:p01")
        self.assertEqual([h for h, _ in gm.details(node)], [h for _, h in gm.PROJECT_FIELDS])
        text = dict(gm.details(node))
        self.assertEqual(text["Disk quota"], "20.0 GiB")
        self.assertEqual(text["Worker networks (first is the default)"], '["ai-net-router", "none"]')
        q = dict(gm.details(self.node("qube:ai-osint-w1")))
        self.assertEqual((q["Role"], q["Slot badges"], q["Network"]), ("worker", "p01", "ai-net-router"))
        for _, value in gm.details(node) + gm.details(self.node("qube:ai-work")):
            self.assertIsInstance(value, gm.Shown)

    def test_choices_for_the_forms(self):
        rows = self.read_json("list", "--all", "--json")
        self.assertIn("debian-13", gm.lead_templates(rows))           # outside AI space too
        self.assertEqual(gm.hubs_appvms(rows, HUB), ["ai-hubq", "ai-on-operator-tpl", "ai-work", "ai-work2"])
        self.assertEqual(gm.approved_template_choices(rows),
                         ["ai-debian-13", "ai-dvm", "ai-dvm-g", "ai-tpl-g"])
        # The networks a project or a lead may use are the enrolled gateways,
        # and none: a qube that provides network but is not enrolled is not offered.
        self.assertEqual(gm.network_choices(self.gateways()), ["none", "ai-net-router"])
        self.assertTrue({"sys-firewall", "ai-gw-unbadged"} <= {r["name"] for r in rows
                                                               if r["gateway"]})
        outside = gm.outside_choices(rows, HUB, ["osint-dump"])
        self.assertIn("personal", outside)
        self.assertNotIn(HUB, outside)
        self.assertNotIn("osint-dump", outside)
        self.assertNotIn("dom0", outside)
        records = {r["slot"]: r for r in self.read_json("project", "list", "--json")}
        self.assertEqual([t for t, _ in gm.move_targets(records)], ["p00", "osint", "other", "none"])

    def test_builders_refuse_what_the_command_would(self):
        cases = [
            (gm.create_project, dict(label="Bad", lead_source="template", lead_origin="t",
                                     networks=["none"], quota="1G")),
            (gm.create_project, dict(label="p03", lead_source="template", lead_origin="t",
                                     networks=["none"], quota="1G")),
            (gm.create_project, dict(label="ok", lead_source="template", lead_origin="t",
                                     networks=[], quota="1G")),
            (gm.create_project, dict(label="ok", lead_source="template", lead_origin="t",
                                     networks=["none"], quota="-1")),
            (gm.create_project, dict(label="ok", lead_source="template", lead_origin="t",
                                     networks=["none"], quota="0")),
            (gm.create_project, dict(label="ok", lead_source="template", lead_origin="--evil",
                                     networks=["none"], quota="1G")),
            (gm.create_project, dict(label="ok", lead_source="promote", lead_origin="ai-work2",
                                     lead_name="ai-ok-x", networks=["none"], quota="1G")),
            (gm.create_project, dict(label="ok", lead_source="nowhere", lead_origin="t",
                                     networks=["none"], quota="1G")),
            (gm.edit_project, dict(key="osint")),
            (gm.edit_project, dict(key="osint", templates=[])),
            (gm.edit_project, dict(key="--yes", quota="1G")),
            (gm.move, dict(qube="ai-work2", target="-x")),
            (gm.role, dict(action="manage", qube="x", keep_running=True)),
            (gm.role, dict(action="delete", qube="x")),
            (gm.add_dump, dict(key="osint", sink_name="-x")),
        ]
        for builder, kw in cases:
            with self.assertRaises(gm.FormError, msg=(builder.__name__, kw)):
                builder(**kw)

    def test_builders_make_exactly_the_typed_command(self):
        self.assertEqual(gm.create_project("newp", "template", "ai-debian-13", None, None,
                                           ["ai-dvm"], ["ai-net-router", "none"], "5G", True),
                         ["/usr/bin/sudo", "-n", gm.QMCP, "project", "create", "newp",
                          "--lead-template", "ai-debian-13", "--template", "ai-dvm",
                          "--network", "ai-net-router", "--network", "none", "--quota", "5G", "--dump"])
        self.assertEqual(gm.edit_project("osint", quota="40G"),
                         ["/usr/bin/sudo", "-n", gm.QMCP, "project", "edit", "osint", "--quota", "40G"])
        # The plan changes nothing, so it is a read: no sudo.
        self.assertEqual(gm.delete_plan("p02"), [gm.QMCP, "project", "delete", "p02"])
        self.assertEqual(gm.READS["check"], [gm.QMCP, "check", "--json"])
        self.assertEqual(gm.shown(gm.move("ai-work2", "none")),
                         "/usr/bin/sudo -n /usr/local/bin/qmcp project move ai-work2 none")

    def test_reads_that_fail_say_so(self):
        with self.assertRaises(gm.ReadError):
            gm.parse_json(gm.Result(["qmcp"], 1, "", "Traceback\nQubesDaemonAccessError"))
        rows = gm.parse_audit(gm.Result(["qmcp"], 0, 'not json\n{"ok": true}\n[1]\n'))
        self.assertEqual(rows, [{"unparseable": "not json"}, {"ok": True}, {"unparseable": "[1]"}])
        self.assertEqual(gm.light(None), "UNKNOWN")
        self.assertEqual(gm.light({"result": "<b>GREEN</b>"}), "UNKNOWN")

    def test_audit_lines_through_the_real_chain_are_escaped(self):
        self.call("qmcp.LifecycleAIManaged", {"name": HOSTILE[:100], "action": "start"})
        rec = gm.parse_audit(self.read("audit", "tail", "1"))[-1]
        self.assertEqual(rec["args"]["name"], HOSTILE[:100])     # the log keeps the raw text
        cells = gm.audit_cells(rec)
        for cell in cells:
            self.assertIsInstance(cell, gm.Shown)
            self.assertTrue(cell.isascii() and "\n" not in cell, cell)
        self.assertIn("\\u202e", cells[5])
        detail = gm.audit_detail(rec)
        self.assertIn("\\u202e", detail)
        self.assertEqual(len(detail.split("\n")), len([k for k in rec if k]))

    def test_check_rows_put_failures_first(self):
        rows = gm.check_rows({"result": "FAILED", "findings": [
            {"status": "pass", "check": "a", "detail": ""},
            {"status": "warn", "check": "b", "detail": "x\ny"},
            {"status": "fail", "check": "c", "detail": ""}]})
        self.assertEqual([r[0] for r in rows], ["FAIL", "WARN", "PASS"])
        self.assertEqual(rows[1][2], "x\\ny")


# ======================================================================= proposals: the model

class ProposalModel(GuiBase):
    """The Proposals tab's decisions, against the real service and command."""

    def listing(self):
        return gm.proposal_rows(self.read_json("proposal", "list", "--json"))

    def test_rows_newest_first_and_the_tab_counts_what_waits(self):
        self.assertEqual(gm.proposals_tab(self.listing()), "Proposals (0)")
        a = self.submit_proposal("create")
        b = self.submit_proposal("delete")
        rows = self.listing()
        self.assertEqual([r["id"] for r in rows], [b["id"], a["id"]])
        self.assertEqual(gm.proposals_tab(rows), "Proposals (2)")
        self.assertEqual(gm.proposal_cells(rows[1]),
                         [str(a["id"]), "pending", "project-create", "newp",
                          "new project <b>newp</b>", rows[1]["submitted"]])
        self.assertEqual(self.runner.execute(gm.reject_proposal(b["id"])).rc, 0)
        self.assertEqual(gm.proposals_tab(self.listing()), "Proposals (1)")
        self.assertEqual(gm.proposals_tab(None), "Proposals (?)")      # never read: no count
        self.assertEqual(gm.proposal_rows([{"id": True}, {"id": "1"}, ["x"], {"id": 4}]),
                         [{"id": 4}])

    def test_details_show_every_field_of_every_proposal(self):
        ids = {name: self.submit_proposal(name)["id"] for name in PROPOSALS}
        self.runner.execute(gm.accept_proposal(ids["dump"], self.show(ids["dump"])["sha256"]))
        self.runner.execute(gm.reject_proposal(ids["lead"]))
        for name, pid in ids.items():
            doc = self.show(pid)
            details = gm.proposal_details(doc)
            headings = [h for h, _ in details]
            self.assertEqual(len(headings), len(set(headings)), headings)
            for _, value in details:
                self.assertIsInstance(value, gm.Shown)
            want = {h for k, h in gm.PROPOSAL_FIELDS
                    if not (k in ("problem", "needs_closing") and not doc[k])}
            want |= {h for k, h in gm.PROPOSAL_OPTIONS if k in doc["proposal"]}
            if doc["command"] is not None:
                want.add("Equivalent command")
            if doc["state"] == "pending":
                want.add("Second tick")
            if doc["tick"] is not None:
                want.add("Second tick digest")
            if doc["before"] is not None:
                want |= {h for _, h in (gm.FIREWALL_CHANGE if doc["type"] == "project-firewall"
                                        else gm.EDIT_FIELDS)}
            if doc["plan"] is not None:
                want.add("Plan")
            if doc["decision"] is not None:
                want |= {h for _, h in gm.DECISION_FIELDS}
            self.assertEqual(set(headings), want, name)
        create = dict(gm.proposal_details(self.show(ids["create"])))
        self.assertEqual(create["State"], "pending: waiting for you")
        self.assertEqual(create["Title (written by AI)"], "new project <b>newp</b>")
        self.assertEqual(create["Lead"], "a fresh qube from the template ai-debian-13")
        self.assertEqual(create["Workers' disk quota"], "5G")              # exact
        self.assertEqual(create["Equivalent command"], "qmcp project create newp --lead-template "
                                                       "ai-debian-13 --network ai-net-router --quota 5G")
        self.assertEqual(create["Second tick"], "not needed: one click is enough")
        edit = dict(gm.proposal_details(self.show(ids["edit"])))
        self.assertNotIn("Equivalent command", edit)           # an edit applies to the record then
        self.assertEqual(edit["Worker networks, now -> after"], "none -> ai-net-router, none")
        self.assertEqual(edit["Quota, now -> after"], "10G -> 15G")
        self.assertEqual(edit["Templates, now -> after"], "ai-tpl-g -> ai-tpl-g")
        dump = dict(gm.proposal_details(self.show(ids["dump"])))
        self.assertEqual(dump["Decision"], "accepted")
        self.assertIn("other-dump", dump["Report"])
        self.assertNotIn("Second tick", dump)                   # only computed while pending
        lead = dict(gm.proposal_details(self.show(ids["lead"])))
        self.assertEqual((lead["Decision"], lead["Report"]), ("rejected", "-"))
        self.assertEqual(lead["Lead"], "a clone of ai-work2")
        delete = dict(gm.proposal_details(self.show(ids["delete"])))
        self.assertIn("this removes p01 'osint'", delete["Plan"])
        self.assertEqual(delete["Second tick"], "needed: the reasons are in red below")

    def test_a_title_is_text_written_by_ai(self):
        # The schema lets in printable ASCII only, which still holds markup,
        # quotes and backslashes: the window shows them as the command's JSON does.
        title = '<b>Approve</b> &amp; "now" <span foreground="red">' + chr(92) + "n</span>"
        reply = self.submit_proposal("create", title=title)
        doc = self.show(reply["id"])
        self.assertEqual(doc["title"], title)
        shown = dict(gm.proposal_details(doc))["Title (written by AI)"]
        self.assertEqual(shown, json.dumps(title)[1:-1])
        self.assertIn("<b>Approve</b>", shown)
        self.assertIn(shown, self.read("proposal", "list", "--json").out)
        self.assertIn(shown, gm.proposal_cells(self.listing()[0]))
        # A line break or a bidi override never gets that far...
        for bad in ("a" + chr(10) + "b", "a" + chr(0x202E) + "b", ""):
            self.assertFalse(self.call("qmcp.SubmitProposal",
                                       dict(PROPOSALS["create"], title=bad))["ok"], ascii(bad))
        # ...and were one stored, it would still reach the screen as visible escapes.
        doc = dict(doc, title=HOSTILE, subject=HOSTILE, caller=HOSTILE)
        for heading, value in gm.proposal_details(doc) + list(zip(gm.PROPOSAL_COLUMNS,
                                                                  gm.proposal_cells(doc))):
            self.assertTrue(value.isascii() and chr(10) not in value, (heading, value))
        self.assertIn(chr(92) + "u202e", dict(gm.proposal_details(doc))["Title (written by AI)"])

    def test_the_second_tick_gates_accept(self):
        create = self.submit_proposal("create")
        delete = self.submit_proposal("delete")
        doc = self.show(delete["id"])
        self.assertTrue(doc["second_tick"])
        self.assertEqual(gm.proposal_actions(doc), {"reject_proposal"})
        self.assertEqual(gm.proposal_actions(doc, ticked=True), {"accept_proposal", "reject_proposal"})
        text = gm.second_tick_text(doc)
        self.assertTrue(text.startswith("Accepting it needs the second tick:"))
        self.assertIn("- deletes the project osint", text)
        self.assertEqual(gm.tick_key(doc), (delete["id"], delete["sha256"], doc["tick"]))
        self.assertEqual(dict(gm.proposal_details(doc))["Second tick digest"], doc["tick"])
        # Without --yes the command refuses, and the proposal stays pending.
        refused = self.runner.execute(gm.accept_proposal(delete["id"], doc["sha256"]))
        self.assertEqual(refused.rc, 1)
        self.assertIn("needs the second tick", refused.err)
        self.assertEqual(self.show(delete["id"])["state"], "pending")
        doc = self.show(create["id"])
        self.assertEqual(doc["second_tick"], [])
        self.assertEqual(gm.proposal_actions(doc), {"accept_proposal", "reject_proposal"})
        self.assertIsNone(gm.tick_key(doc))
        self.assertEqual(gm.second_tick_text(doc), "")
        # A tick for other reasons is refused, and the proposal stays pending.
        moved = self.runner.execute(gm.accept_proposal(delete["id"], delete["sha256"], "ab" * 32))
        self.assertEqual(moved.rc, 1)
        self.assertIn("not the ones it was given for", moved.err)
        self.assertEqual(self.show(delete["id"])["state"], "pending")
        argv = gm.accept_proposal(delete["id"], delete["sha256"], self.show(delete["id"])["tick"])
        self.assertEqual(argv[-2:], ["--yes", self.show(delete["id"])["tick"]])
        self.assertEqual(self.runner.execute(argv).rc, 0)
        self.assertIsNone(projects.find(projects.load(), "osint"))

    def test_closed_proposals_offer_nothing(self):
        accepted = self.submit_proposal("dump")
        rejected = self.submit_proposal("create")
        failed = self.submit_proposal("create", label="bad",
                                      lead={"from": "template", "qube": "ai-no-such"})
        running = self.submit_proposal("create", label="run")
        expired, _, _ = proposals.submit(proposals.normalise(PROPOSALS["edit"], "ai-"), HUB,
                                         now=time.time() - proposals.EXPIRY_S - 60)
        self.assertEqual(self.runner.execute(gm.accept_proposal(accepted["id"], accepted["sha256"])).rc, 0)
        self.assertEqual(self.runner.execute(gm.reject_proposal(rejected["id"])).rc, 0)
        result = self.runner.execute(gm.accept_proposal(failed["id"], failed["sha256"]))
        self.assertEqual(result.rc, 1)                          # the command refused: it closes as failed
        self.assertIn("is not a TemplateVM", result.out)
        store = pathlib.Path(proposals.PROPOSALS_DIR)
        # An accept still running holds its claim locked.
        claim = store / f"{running['id']:06d}.accepting"
        claim.write_text("{}")
        fd = os.open(claim, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        for pid, state in ((accepted["id"], "accepted"), (rejected["id"], "rejected"),
                           (failed["id"], "failed"), (expired, "expired"),
                           (running["id"], "accepting")):
            doc = self.show(pid)
            self.assertEqual((doc["state"], doc["needs_closing"]), (state, False))
            self.assertEqual(gm.proposal_actions(doc, ticked=True), set(), state)
            self.assertIsNone(gm.tick_key(doc), state)
            self.assertEqual(gm.second_tick_text(doc), "", state)
            self.assertNotIn("needs closing", gm.proposal_cells(doc)[1])

    def test_what_needs_closing_gets_close_and_closes_as_the_command_does(self):
        # The three cases the command says need closing: a stored file that does
        # not read, a decision file that does not read, and an accept that never
        # finished. Each offers Close alone, and closes in the state the pane
        # said it would, by the command's own word.
        decided = self.submit_proposal("create")
        stale = self.submit_proposal("create", label="stale")
        self.assertEqual(self.runner.execute(gm.reject_proposal(decided["id"])).rc, 0)
        store = pathlib.Path(proposals.PROPOSALS_DIR)
        (store / "000099.json").write_text("{not json")
        (store / f"{decided['id']:06d}.decision").write_text("garbage")
        (store / f"{stale['id']:06d}.accepting").write_bytes(b"")    # nobody holds it

        def store_check():
            return [(f["status"], f["detail"]) for f in self.read_json("check", "--json")["findings"]
                    if f["check"] == "proposal store"]
        [(status, detail)] = store_check()                          # check warns first
        self.assertEqual(status, "warn")
        self.assertEqual(set(detail.split(" with ")[0].split(" ", 1)[1].split(", ")),
                         {"99", str(decided["id"]), str(stale["id"])})
        for pid, state, closed in ((99, "unreadable", "rejected"), (decided["id"], "failed", "failed"),
                                   (stale["id"], "failed", "failed")):
            doc = self.show(pid)
            self.assertEqual((doc["state"], doc["needs_closing"]), (state, True))
            self.assertEqual(gm.proposal_actions(doc, ticked=True), {"close_proposal"})
            self.assertEqual(gm.closes_as(doc), closed)
            self.assertIn(f"records the proposal as {closed}", gm.close_intro(doc))
            self.assertIn(f"Why: {doc['problem']}.", gm.close_intro(doc))
            self.assertIn(f"Close records it as {closed}",
                          dict(gm.proposal_details(doc))["Needs closing"])
            self.assertEqual(gm.proposal_cells(doc)[1], f"{state}, needs closing")
            result = self.runner.execute(gm.reject_proposal(pid))   # what Close runs
            self.assertEqual(result.out, f"proposal {pid}: {closed}\n")
            doc = self.show(pid)
            self.assertEqual((doc["state"], doc["needs_closing"]), (closed, False))
            self.assertEqual(gm.proposal_actions(doc, ticked=True), set())
            self.assertNotIn("Needs closing", dict(gm.proposal_details(doc)))
        self.assertEqual([s for s, _ in store_check()], ["pass"])
        # Not while an accept is running, whatever else is wrong: the command
        # refuses that, so the window does not offer it.
        self.assertEqual(gm.proposal_actions({"state": "accepting", "needs_closing": True}), set())

    def test_a_failed_show_keeps_the_last_view_of_that_proposal_only(self):
        a = self.submit_proposal("create")
        b = self.submit_proposal("delete")
        pane = gm.ProposalPane()
        self.assertEqual(pane.note(None), "The proposals have not been read.")
        self.assertEqual(pane.note(False), "No proposals from the hub.")
        seq = pane.select(a["id"])
        self.assertEqual(pane.actions(), set())                 # reading: nothing allowed yet
        self.assertTrue(pane.answer(seq, self.runner.execute(gm.show_proposal(a["id"])), "10:00:00"))
        self.assertEqual(pane.actions(), {"accept_proposal", "reject_proposal"})
        good = pane.doc
        # A show that exits non-zero failed, whatever it printed.
        with self.assertRaises(gm.ReadError):
            gm.parse_proposal(gm.Result(gm.show_proposal(a["id"]), 1, json.dumps(good)), a["id"])
        failed = gm.Result(gm.show_proposal(a["id"]), 1, "", "qmcp proposal show: no answer")
        # Read again, as a refresh does, and the show fails: the last view stays,
        # says so, and nothing may change until a show reads.
        self.assertTrue(pane.answer(pane.select(a["id"]), failed, "10:01:00"))
        self.assertIs(pane.doc, good)
        self.assertEqual(pane.actions(ticked=True), set())
        self.assertIn(f"Could not read proposal {a['id']}", pane.note())
        self.assertIn("Showing it as read at 10:00:00", pane.note())
        # Another proposal's failed show never shows the first one.
        self.assertTrue(pane.answer(pane.select(b["id"]), failed, "10:02:00"))
        self.assertIsNone(pane.doc)
        self.assertEqual(pane.actions(ticked=True), set())
        self.assertNotIn("Showing it", pane.note())
        # An answer about another proposal is not taken for this one.
        pane.answer(pane.select(b["id"]), self.runner.execute(gm.show_proposal(a["id"])), "10:03:00")
        self.assertIsNone(pane.doc)
        self.assertIn("unexpected answer", pane.error)
        # A show that answers after a newer one was asked for changes nothing.
        old, new = pane.select(a["id"]), pane.select(a["id"])
        self.assertFalse(pane.answer(old, self.runner.execute(gm.show_proposal(a["id"])), "10:04:00"))
        self.assertIsNone(pane.doc)
        self.assertTrue(pane.reading)
        self.assertTrue(pane.answer(new, self.runner.execute(gm.show_proposal(a["id"])), "10:05:00"))
        self.assertEqual(pane.doc["id"], a["id"])
        self.assertEqual(pane.note(), f"Proposal {a['id']}, read at 10:05:00.")
        pane.select(None)
        self.assertEqual((pane.doc, pane.actions()), (None, set()))

    def test_a_refresh_makes_the_pane_stale_until_it_reads_again(self):
        a = self.submit_proposal("create")
        pane = gm.ProposalPane()
        pane.stale()                                            # nothing selected: nothing to do
        self.assertFalse(pane.reading)
        show = lambda: self.runner.execute(gm.show_proposal(a["id"]))  # noqa: E731
        pane.answer(pane.select(a["id"]), show(), "10:00:00")
        self.assertEqual(pane.actions(), {"accept_proposal", "reject_proposal"})
        doc = pane.doc
        running = pane.select(a["id"])                          # a show already running...
        pane.stale()                                            # ...when a refresh starts
        self.assertEqual((pane.actions(), pane.doc), (set(), doc))
        self.assertEqual(pane.note(), f"Reading proposal {a['id']}...")
        self.assertFalse(pane.answer(running, show(), "10:01:00"))   # may predate the change
        self.assertEqual(pane.actions(), set())
        self.assertTrue(pane.answer(pane.select(a["id"]), show(), "10:02:00"))
        self.assertEqual(pane.actions(), {"accept_proposal", "reject_proposal"})

    def test_an_open_form_is_checked_against_the_show_on_display(self):
        a = self.submit_proposal("create")
        d = self.submit_proposal("delete")
        pane = gm.ProposalPane()
        show = lambda pid: self.runner.execute(gm.show_proposal(pid))  # noqa: E731
        pane.answer(pane.select(a["id"]), show(a["id"]), "10:00:00")
        opened = pane.doc
        changed = "the proposal changed since this form opened; read it again"
        self.assertIsNone(gm.proposal_changed(opened, "accept_proposal", pane, False))
        pane.stale()
        self.assertEqual(gm.proposal_changed(opened, "accept_proposal", pane, False), changed)
        pane.answer(pane.select(a["id"]), show(a["id"]), "10:01:00")
        self.assertIsNone(gm.proposal_changed(opened, "accept_proposal", pane, False))
        for key, value in (("id", 99), ("sha256", "ab" * 32), ("tick", "cd" * 32)):
            pane.doc = dict(opened, **{key: value})
            self.assertEqual(gm.proposal_changed(opened, "reject_proposal", pane, False), changed, key)
        pane.answer(pane.select(a["id"]), gm.Result(gm.show_proposal(a["id"]), 1, "", "x"), "t")
        self.assertEqual(gm.proposal_changed(opened, "reject_proposal", pane, False), changed)
        # Accept needs the tick as it is at OK, not only as it was at opening.
        pane.answer(pane.select(d["id"]), show(d["id"]), "10:02:00")
        opened = pane.doc
        self.assertEqual(gm.proposal_changed(opened, "accept_proposal", pane, False), changed)
        self.assertIsNone(gm.proposal_changed(opened, "accept_proposal", pane, True))

    def test_quotas_are_shown_exactly(self):
        # Rounded to 0.1 GiB, a quota one byte past 5 GiB read as 5.0 GiB.
        odd = 5 * GiB + 1
        create = dict(gm.proposal_details(self.show(self.submit_proposal("create", quota=odd)["id"])))
        self.assertEqual(create["Workers' disk quota"], str(odd))
        self.assertIn(f"--quota {odd}", create["Equivalent command"])
        edit = dict(gm.proposal_details(self.show(self.submit_proposal("edit", quota=odd)["id"])))
        self.assertEqual(edit["Quota, now -> after"], f"10G -> {odd}")

    def test_proposal_commands_are_exactly_what_runs(self):
        sha = "ab" * 32
        self.assertEqual(gm.show_proposal(3), [gm.QMCP, "proposal", "show", "3", "--json"])  # a read
        self.assertEqual(gm.accept_proposal(3, sha),
                         ["/usr/bin/sudo", "-n", gm.QMCP, "proposal", "accept", "3", "--sha256", sha])
        self.assertEqual(gm.accept_proposal(3, sha, tick="cd" * 32)[-2:], ["--yes", "cd" * 32])
        for bad in ("", "CD" * 32, "cd" * 31, "--json", True):
            with self.assertRaises(gm.FormError, msg=repr(bad)):
                gm.accept_proposal(3, sha, tick=bad)
        self.assertEqual(gm.reject_proposal(3), ["/usr/bin/sudo", "-n", gm.QMCP, "proposal", "reject", "3"])
        for pid in (0, -1, True, "3", None, 3.0):
            with self.assertRaises(gm.FormError, msg=repr(pid)):
                gm.reject_proposal(pid)
        # The window refuses a fingerprint exactly when the command does, on a
        # proposal that exists and stays pending through every refusal.
        reply = self.submit_proposal("create")
        pid = str(reply["id"])
        for bad in (None, "", "AB" * 32, "ab" * 31, "ab" * 33, "--yes", "g" * 64):
            with self.assertRaises(gm.FormError, msg=repr(bad)):
                gm.accept_proposal(reply["id"], bad)
            if bad is not None:
                argv = [*gm.SUDO, gm.QMCP, "proposal", "accept", pid, "--sha256", bad]
                self.assertNotEqual(self.runner.execute(argv).rc, 0, bad)
        self.assertEqual(self.show(reply["id"])["state"], "pending")
        self.assertEqual(self.runner.execute(gm.accept_proposal(reply["id"], reply["sha256"])).rc, 0)

    def test_the_forms_say_what_accepting_and_rejecting_do(self):
        reply = self.submit_proposal("create")
        doc = self.show(reply["id"])
        intro = gm.accept_intro(doc)
        self.assertIn(f"Accepts proposal {reply['id']} from {HUB}: project-create newp", intro)
        self.assertIn("The equivalent command: qmcp project create newp", intro)
        edit = self.show(self.submit_proposal("edit")["id"])
        self.assertIn("now -> after", gm.accept_intro(edit))
        self.assertIn("without running anything", gm.reject_intro(doc))


# ======================================================================= gateways: the model

#: The rules qubesd reads back for RULES, in its own spelling (`fakequbes`
#: models it as measured on Qubes 4.3.1): its own option order, a port range.
SPELLED = [_qubesd_rule(r) for r in RULES]
MARK = "its own firewall rules have no effect upstream"


class GatewayModel(GuiBase):
    """The Gateways tab and the networks the forms offer, against the real
    command. Each refusal the window makes before OK is checked against the
    command's own."""

    def setUp(self):
        super().setUp()
        self.routers()

    def run_ok(self, argv):
        result = self.runner.execute(argv)
        self.assertEqual(result.rc, 0, (argv, result.out, result.err))
        return result

    def test_each_registry_command_is_exactly_what_runs(self):
        sudo = [*gm.SUDO, gm.QMCP, "gateway"]
        enroll = gm.enroll_gateway("sys-ai-tor", True, "Tor, CH")
        self.assertEqual(enroll, sudo + ["enroll", "sys-ai-tor", "--anonymising", "--label",
                                         "Tor, CH"])
        self.assertEqual(gm.enroll_gateway("sys-ai-net", label=""), sudo + ["enroll", "sys-ai-net"])
        self.run_ok(enroll)
        g = gateways.load()["sys-ai-tor"]
        self.assertEqual((g.anonymising, g.label), (True, "Tor, CH"))
        change = gm.change_gateway("sys-ai-tor", anonymising=False, label="")
        self.assertEqual(change, sudo + ["set", "sys-ai-tor", "--anonymising", "no", "--label", ""])
        self.run_ok(change)
        g = gateways.load()["sys-ai-tor"]
        self.assertEqual((g.anonymising, g.label), (False, ""))
        # A label that would read as an option goes as --label=TEXT, which parses.
        dash = gm.change_gateway("sys-ai-tor", label="-eu")
        self.assertEqual(dash, sudo + ["set", "sys-ai-tor", "--label=-eu"])
        self.run_ok(dash)
        self.assertEqual(gateways.load()["sys-ai-tor"].label, "-eu")
        remove = gm.remove_gateway("sys-ai-tor")
        self.assertEqual(remove, sudo + ["remove", "sys-ai-tor"])
        self.run_ok(remove)
        self.assertNotIn("sys-ai-tor", gateways.load())
        for builder, kw in ((gm.enroll_gateway, dict(qube="-x")),
                            (gm.enroll_gateway, dict(qube=None)),
                            (gm.enroll_gateway, dict(qube="sys-ai-tor", label="x" * 41)),
                            (gm.enroll_gateway, dict(qube="sys-ai-tor", label="a" + chr(10) + "b")),
                            (gm.change_gateway, dict(qube="sys-ai-tor")),
                            (gm.change_gateway, dict(qube="sys-ai-tor", label=chr(0x202E))),
                            (gm.remove_gateway, dict(qube="--json"))):
            with self.assertRaises(gm.FormError, msg=(builder.__name__, kw)):
                builder(**kw)
        # The window refuses a label exactly as the command does.
        with self.assertRaises(gm.FormError) as cm:
            gm.enroll_gateway("sys-ai-tor", label="x" * 41)
        result = self.runner.execute(sudo + ["enroll", "sys-ai-tor", "--label", "x" * 41])
        self.assertEqual(result.rc, 1)
        self.assertIn(str(cm.exception), result.err)

    def test_the_whonix_mark(self):
        self.run_ok(gm.enroll_gateway("sys-ai-tor", True, "Tor"))
        self.run_ok(gm.enroll_gateway("sys-ai-net"))
        gws = self.gateways()
        rows = {r["name"]: r for r in gws}
        tor, net = rows["sys-ai-tor"], rows["sys-ai-net"]
        self.assertTrue(tor["upstream_ignores_firewall"])
        self.assertEqual(gm.UPSTREAM_IGNORES, MARK)
        cells = dict(zip([k for k, _ in gm.GATEWAY_COLUMNS], gm.gateway_cells(tor)))
        self.assertEqual((cells["upstream"], cells["notes"]), ("sys-whonix", MARK))
        self.assertTrue(dict(gm.gateway_details(tor))["Its upstream ignores its firewall rules"]
                        .startswith(f"yes: {MARK}. Its upstream, sys-whonix, is a Whonix gateway"))
        self.assertEqual(gm.network_text("sys-ai-tor", gws), f"sys-ai-tor ({MARK})")
        # A router behind sys-firewall carries no mark.
        self.assertEqual(gm.gateway_notes(net), [])
        self.assertEqual(dict(gm.gateway_details(net))["Its upstream ignores its firewall rules"], "no")
        self.assertEqual(gm.network_text("sys-ai-net", gws), "sys-ai-net")
        # The mark follows the upstream.
        self.app.domains["sys-ai-tor"].netvm = self.app.domains["sys-firewall"]
        self.assertEqual(gm.gateway_notes(next(r for r in self.gateways() if r["name"] == "sys-ai-tor")),
                         [])
        # Whether it does cannot be read, through the upstream's tags or the
        # gateway's own network: said so, never "no".
        unread = "whether its upstream ignores its firewall rules cannot be read now; refresh"
        for key in ("tag.List:sys-firewall", "get.netvm:sys-ai-net"):
            with self.subTest(key):
                self.app.fail.add(key)
                try:
                    row = next(r for r in self.gateways() if r["name"] == "sys-ai-net")
                finally:
                    self.app.fail.discard(key)
                self.assertIn(unread, gm.gateway_notes(row))
                self.assertEqual(dict(gm.gateway_details(row))[
                    "Its upstream ignores its firewall rules"], "cannot be read now; refresh")

    def test_a_gateway_that_no_longer_qualifies_is_offered_and_marked(self):
        # Enrolled as it was; then its template lost Qubes' firewall marker,
        # and qmcp check fails on it.
        self.run_ok(gm.enroll_gateway("sys-ai-net"))
        self.app.domains["debian-13"].features.pop("qubes-firewall")
        gws = self.gateways()
        row = next(r for r in gws if r["name"] == "sys-ai-net")
        self.assertIn("qubes-firewall", row["problem"])
        self.assertIn("sys-ai-net", gm.network_choices(gws))
        self.assertTrue(gm.network_text("sys-ai-net", gws).startswith("sys-ai-net (NOT USABLE: "))
        self.assertTrue(gm.gateway_cells(row)[-1].startswith("NOT USABLE: "))
        self.assertIn("qmcp check fails on it", dict(gm.gateway_details(row))["Problem"])
        status = [f["status"] for f in self.read_json("check", "--json")["findings"]
                  if f["check"] == "gateway registry"]
        self.assertEqual(status, ["fail"])

    def test_a_gateway_that_no_longer_qualifies_is_refused_where_the_command_refuses_it(self):
        # sys-ai-net enrolled and on other's list while it qualified; then its
        # template lost Qubes' firewall marker.
        self.run_ok(gm.enroll_gateway("sys-ai-net"))
        self.run_ok(gm.edit_project("other", networks=["none", "sys-ai-net"]))
        self.app.domains["debian-13"].features.pop("qubes-firewall")
        gws, rows = self.gateways(), self.read_json("list", "--all", "--json")
        problem = next(r for r in gws if r["name"] == "sys-ai-net")["problem"]
        why = f"'sys-ai-net' is enrolled but not usable: {problem}"
        other = {r["slot"]: r for r in self.read_json("project", "list", "--json")}["p02"]

        def refused(form_check, argv):
            """The form refuses, in the command's words, and so does the command."""
            with self.assertRaises(gm.FormError) as cm:
                form_check()
            self.assertEqual(str(cm.exception), why)
            result = self.runner.execute(argv)
            self.assertEqual(result.rc, 1, argv)
            self.assertIn(why, result.err)
        # A new project's worker network, and a new lead's network.
        refused(lambda: gm.check_networks(["none", "sys-ai-net"], gws),
                gm.create_project("newp", "template", "ai-debian-13", networks=["none", "sys-ai-net"],
                                  quota="1G"))
        refused(lambda: gm.lead_network("template", "ai-debian-13", "sys-ai-net", rows, gws),
                gm.create_project("newp", "template", "ai-debian-13", lead_netvm="sys-ai-net",
                                  networks=["none"], quota="1G", model="api.anthropic.com:443"))
        refused(lambda: gm.lead_network("template", "ai-debian-13", "sys-ai-net", rows, gws),
                gm.change_lead("other", "template", "ai-debian-13", "ai-other-l2", "sys-ai-net", True,
                               "api.anthropic.com:443"))
        # A promoted lead keeps its own network: refused too when that one is broken.
        self.app.domains["ai-hubq"].netvm = self.app.domains["sys-ai-net"]
        rows = self.read_json("list", "--all", "--json")
        refused(lambda: gm.lead_network("promote", "ai-hubq", None, rows, gws),
                gm.create_project("prom", "promote", "ai-hubq", networks=["none"], quota="1G",
                                  model="api.anthropic.com:443"))
        # Adding the old lead's network checks the whole new list, so a broken
        # gateway already on it refuses the tick...
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["ai-net-router"]
        rows = self.read_json("list", "--all", "--json")
        refused(lambda: gm.old_lead_network(other, rows, gws, True, True),
                gm.change_lead("other", "template", "ai-debian-13", "ai-other-l2", "none", True, None,
                               True))
        # ...and so does a broken network the old lead itself is on.
        osint = {r["slot"]: r for r in self.read_json("project", "list", "--json")}["p01"]
        self.app.domains[LEAD].netvm = self.app.domains["sys-ai-net"]
        rows = self.read_json("list", "--all", "--json")
        refused(lambda: gm.old_lead_network(osint, rows, gws, True, True),
                gm.change_lead("osint", "template", "ai-debian-13", "ai-osint-l2", "none", True, None,
                               True))
        # An edit whose new list keeps it is refused; one that takes it off is
        # not, and neither is an edit that leaves the list alone.
        refused(lambda: gm.check_networks(["sys-ai-net", "none"], gws),
                gm.edit_project("other", networks=["sys-ai-net", "none"]))
        self.run_ok(gm.edit_project("other", quota="11G"))
        self.assertEqual(gm.check_networks(["none"], gws), ["none"])
        self.run_ok(gm.edit_project("other", networks=["none"]))
        self.assertEqual(projects.find(projects.load(), "other").networks, (None,))
        # Nothing the refusals stopped changed anything.
        self.assertEqual((projects.find(projects.load(), "other").lead,
                          projects.find(projects.load(), "osint").lead), (OTHER_LEAD, LEAD))
        self.assertIsNone(projects.find(projects.load(), "newp"))

    def test_enroll_offers_every_gateway_not_enrolled_and_refuses_as_the_command_does(self):
        a = self.app
        for name in ("ai-sink", "ai-osint-w1"):        # a drop box and a member that route
            a.domains[name]._props["provides_network"] = True
            a.domains[name].features["qubes-firewall"] = "1"
        rows = self.read_json("list", "--all", "--json")
        by_name = {r["name"]: r for r in rows}
        choices = gm.enroll_choices(rows, self.gateways(), HUB)
        self.assertNotIn("ai-net-router", choices)       # enrolled already
        self.assertNotIn(HUB, choices)
        self.assertLessEqual({"sys-ai-net", "sys-ai-tor", "sys-whonix", "sys-firewall",
                              "ai-gw-unbadged", "ai-sink", "ai-osint-w1"}, set(choices))
        seen = set()
        for name in choices:
            why = gm.enroll_refusal(by_name[name], HUB)
            result = self.runner.execute(gm.enroll_gateway(name))
            if why is not None:
                self.assertEqual(result.rc, 1, name)
                self.assertIn(why, result.err, name)      # in the command's words
                seen.add("form")
            elif result.rc:
                # What only the command can see, the window's `list` row holding
                # none of it: Whonix's own tag, the marker, the templates.
                self.assertTrue(any(why in result.err for why in (
                    "is a Whonix gateway", "qubes-firewall", "one the hub manages")),
                    (name, result.err))
                seen.add("command")
            else:
                seen.add("enrolled")
        self.assertEqual(seen, {"form", "command", "enrolled"})
        self.assertEqual(gm.enroll_refusal(by_name["ai-gw-unbadged"], HUB),
                         "'ai-gw-unbadged' cannot be enrolled: is in AI space without "
                         "qmcp-guarded (qmcp guard ai-gw-unbadged)")
        self.assertIn("a drop box", gm.enroll_refusal(by_name["ai-sink"], HUB))
        self.assertIn("member", gm.enroll_refusal(by_name["ai-osint-w1"], HUB))
        self.assertEqual(gm.enroll_refusal(dict(by_name["sys-ai-net"], name=HUB), HUB),
                         f"'{HUB}' cannot be enrolled: is the hub")
        self.assertEqual(gm.enroll_refusal(None), "choose a qube that provides network")
        self.assertEqual(gm.enroll_text(by_name["sys-ai-net"], HUB), "sys-ai-net (outside AI space)")
        self.assertEqual(gm.enroll_text(by_name["ai-gw-unbadged"], HUB),
                         "ai-gw-unbadged (in AI space; cannot be enrolled: is in AI space without "
                         "qmcp-guarded (qmcp guard ai-gw-unbadged))")

    def test_remove_is_refused_while_in_use_in_the_commands_words(self):
        row = next(r for r in self.gateways() if r["name"] == "ai-net-router")
        why = gm.gateway_in_use(row)
        self.assertTrue(why.startswith("'ai-net-router' is in use: projects ['osint'], qubes ["), why)
        result = self.runner.execute(gm.remove_gateway("ai-net-router"))
        self.assertEqual(result.rc, 1)
        self.assertIn(why, result.err)
        self.run_ok(gm.enroll_gateway("sys-ai-net"))
        free = next(r for r in self.gateways() if r["name"] == "sys-ai-net")
        self.assertIsNone(gm.gateway_in_use(free))
        self.assertIn("The qube itself does not change", gm.remove_gateway_intro(free))
        self.run_ok(gm.remove_gateway("sys-ai-net"))

    def test_settings_count_them_and_a_registry_that_does_not_read_is_no_registry(self):
        settings = dict(gm.settings_rows(self.read_json("settings", "--json")))
        self.assertEqual(settings["Gateways enrolled"], "1")
        self.assertEqual(gm.gateways_note(self.gateways()), gm.GATEWAYS_NOTE)
        pathlib.Path(gateways.GATEWAYS_PATH).write_text("{")
        settings = dict(gm.settings_rows(self.read_json("settings", "--json")))
        self.assertEqual(settings["Gateways enrolled"], "not known: the registry cannot be read")
        result = self.read("gateway", "list", "--json")
        self.assertEqual(result.rc, 1)
        with self.assertRaises(gm.ReadError):             # a failed read, never an empty list
            gm.parse_json(result)
        self.assertEqual(gm.gateways_note(None), "The gateway registry has not been read.")
        self.assertIn("None is enrolled", gm.gateways_note([]))
        self.assertEqual(gm.gateway_actions(None), {"enroll_gateway"})
        self.assertEqual(gm.gateway_actions({"name": "x"}),
                         {"enroll_gateway", "change_gateway", "remove_gateway"})


# ======================================================================= leads: network and model

class LeadModel(GuiBase):
    """A new lead's network, its model endpoint and the old lead's network,
    as the project forms judge them before OK: each refusal is the
    command's, checked against the command."""

    def rows(self):
        return self.read_json("list", "--all", "--json")

    def test_the_network_a_new_lead_will_have(self):
        gws = self.gateways()
        net = lambda *a: gm.lead_network(*a, self.rows(), gws)  # noqa: E731
        self.assertIsNone(net("template", "ai-debian-13", None))      # a fresh lead: none, unless chosen
        self.assertIsNone(net("clone", "ai-work", None))               # its source's is not inherited
        self.assertEqual(net("template", "ai-debian-13", "ai-net-router"), "ai-net-router")
        self.assertIsNone(net("template", "ai-debian-13", "none"))
        self.assertEqual(net("promote", "ai-hubq", None), "ai-net-router")   # a promoted lead keeps its own
        self.assertIsNone(net("promote", "ai-hubq", "none"))
        self.assertIsNone(net("promote", "ai-work2", None))
        with self.assertRaises(gm.FormError) as cm:
            net("template", "ai-debian-13", "sys-firewall")
        self.assertEqual(str(cm.exception),
                         "'sys-firewall' is not an enrolled gateway (qmcp gateway enroll sys-firewall)")
        # A promoted lead on a network that is not enrolled: the form refuses
        # as the command does.
        self.app.domains["ai-work2"].netvm = self.app.domains["sys-firewall"]
        with self.assertRaises(gm.FormError) as cm:
            net("promote", "ai-work2", None)
        result = self.runner.execute(gm.create_project("prom", "promote", "ai-work2", networks=["none"],
                                                       quota="1G", model="api.anthropic.com:443"))
        self.assertEqual(result.rc, 1)
        self.assertIn(str(cm.exception), result.err)
        # No network moves: a promoted lead takes its own, named or not, or
        # none; never another, even an enrolled one.
        self.enroll("sys-firewall")
        gws = self.gateways()
        self.assertEqual(gm.lead_network("promote", "ai-hubq", "ai-net-router", self.rows(), gws),
                         "ai-net-router")
        with self.assertRaises(gm.FormError) as cm:
            gm.lead_network("promote", "ai-hubq", "sys-firewall", self.rows(), gws)
        result = self.runner.execute(gm.create_project("prom", "promote", "ai-hubq", networks=["none"],
                                                       quota="1G", lead_netvm="sys-firewall",
                                                       model="api.anthropic.com:443"))
        self.assertEqual(result.rc, 1)
        self.assertIn(str(cm.exception), result.err)
        self.assertEqual(self.tags("ai-hubq"), {"ai-managed", "qmcp-proj-p00"})   # untouched

    def test_a_lead_with_a_network_needs_a_model_and_one_without_takes_none(self):
        gws = self.gateways()
        for i, (netvm, model, why) in enumerate((
                ("ai-net-router", "", "needs its model endpoint"),
                ("none", "api.anthropic.com:443", "reaches no model endpoint"),
                ("ai-net-router", "no-port", "host:port"),
                ("ai-net-router", " api.anthropic.com:443 ", None),
                ("none", "", None))):
            with self.subTest(netvm=netvm, model=model):
                network = gm.lead_network("template", "ai-debian-13", netvm, self.rows(), gws)
                raw = [*gm.SUDO, gm.QMCP, "project", "create", f"m{i}", "--lead-template",
                       "ai-debian-13", "--lead-netvm", netvm, "--network", "none", "--quota", "1G"]
                raw += ["--model", model.strip()] if model else []
                result = self.runner.execute(raw)
                if why is None:
                    self.assertEqual(gm.lead_model(network, model), model.strip() or None)
                    self.assertEqual(result.rc, 0, result.err)
                    continue
                with self.assertRaises(gm.FormError) as cm:
                    gm.lead_model(network, model)
                self.assertIn(why, str(cm.exception))
                self.assertEqual(result.rc, 1)
                self.assertIn(why, result.err)                       # the command's refusal
        self.assertEqual(gm.lead_info(None), "The lead will have no network: leave the model "
                                             "empty. It needs no firewall.")
        self.assertTrue(gm.lead_info("ai-net-router").endswith("Give its model endpoint."))

    def test_a_new_lead_of_a_project_takes_its_model(self):
        # other has no model on record: a new lead with a network needs one typed.
        with self.assertRaises(gm.FormError):
            gm.lead_model("ai-net-router", "", None)
        self.assertIn("The project has no model on record: give one.",
                      gm.lead_info("ai-net-router", None, change=True))
        result = self.runner.execute(gm.change_lead("other", "template", "ai-debian-13", "ai-other-l2",
                                                    "ai-net-router", True))
        self.assertEqual(result.rc, 1)
        self.assertIn("needs its model endpoint", result.err)
        self.assertIsNone(projects.find(projects.load(), "other").model)
        # Once it has one, the field may stay empty, and the new lead takes it.
        # A model is set only on a lead with a network: give other's one by
        # hand first, as an upgrade from 0.9.20 leaves a lead (checklist step 28).
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["ai-net-router"]
        self.assertEqual(self.runner.execute(gm.set_lead_model("other", "api.anthropic.com:443")).rc, 0)
        self.assertEqual(projects.find(projects.load(), "other").model, "api.anthropic.com:443")
        self.assertIsNone(gm.lead_model("ai-net-router", "", "api.anthropic.com:443"))
        self.assertIn("Left empty, the model is the project's, api.anthropic.com:443.",
                      gm.lead_info("ai-net-router", "api.anthropic.com:443", change=True))
        # The old lead, kept, is now on ai-net-router, which other does not
        # list: the form says it goes to no network, and the command does that.
        other = {r["slot"]: r for r in self.read_json("project", "list", "--json")}["p02"]
        self.assertIn("without the tick it goes to no network",
                      gm.old_lead_network(other, self.rows(), self.gateways(), True, False))
        argv = gm.change_lead("other", "template", "ai-debian-13", "ai-other-l2", "ai-net-router", True)
        self.assertNotIn("--model", argv)                         # the field was left empty
        result = self.runner.execute(argv)
        self.assertEqual(result.rc, 0, result.err)
        endpoint = [_qubesd_rule(r) for r in firewall.endpoint_rules("api.anthropic.com:443")]
        self.assertEqual(self.lead_rules("ai-other-l2"), endpoint)    # the project's model
        p = projects.find(projects.load(), "other")
        self.assertEqual((p.lead, p.model, list(p.lead_firewall)),
                         ("ai-other-l2", "api.anthropic.com:443", endpoint))
        self.assertIn(f"{OTHER_LEAD} lost its network", result.out)
        self.assertIsNone(self.app.domains[OTHER_LEAD].netvm)
        self.assertIn("qmcp-proj-p02", self.tags(OTHER_LEAD))         # kept, as a worker

    def test_what_happens_to_a_kept_leads_network(self):
        records = {r["slot"]: r for r in self.read_json("project", "list", "--json")}
        osint, other = records["p01"], records["p02"]
        gws = self.gateways()
        self.assertEqual(gm.old_lead_network(osint, self.rows(), gws, True, False),
                         f"{LEAD} is on ai-net-router, which osint lists: it keeps it as a worker.")
        self.assertEqual(gm.old_lead_network(osint, self.rows(), gws, False, False), "")
        with self.assertRaises(gm.FormError):
            gm.old_lead_network(osint, self.rows(), gws, False, True)   # the tick without keep
        self.assertEqual(gm.old_lead_network(other, self.rows(), gws, True, False),
                         f"{OTHER_LEAD} has no network, and keeps none as a worker.")
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["ai-net-router"]   # other lists none only
        self.assertEqual(gm.old_lead_network(other, self.rows(), gws, True, False),
                         f"{OTHER_LEAD} is on ai-net-router, which other does not list: without the "
                         f"tick it goes to no network as a worker.")
        self.assertEqual(gm.old_lead_network(other, self.rows(), gws, True, True),
                         f"{OTHER_LEAD} is on ai-net-router, which other does not list: the tick adds "
                         f"ai-net-router to the worker networks, and {OTHER_LEAD} keeps it.")
        # On a network that is not enrolled the tick is refused, by the form
        # and the command alike, and nothing changes.
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["sys-firewall"]
        with self.assertRaises(gm.FormError) as cm:
            gm.old_lead_network(other, self.rows(), gws, True, True)
        argv = gm.change_lead("other", "template", "ai-debian-13", "ai-other-l2", "none", True, None, True)
        self.assertEqual(argv[-2:], ["--keep-old", "--add-old-network"])
        result = self.runner.execute(argv)
        self.assertEqual(result.rc, 1)
        self.assertIn(str(cm.exception), result.err)
        self.assertEqual(projects.find(projects.load(), "other").lead, OTHER_LEAD)
        # A list that is full takes no more, by the form and the command alike.
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["ai-net-router"]
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p02"]["networks"] = [None] + [f"gw{i}" for i in range(projects.MAX_NETWORKS - 1)]
        self.write_records(doc)
        other = {r["slot"]: r for r in self.read_json("project", "list", "--json")}["p02"]
        with self.assertRaises(gm.FormError) as cm:
            gm.old_lead_network(other, self.rows(), gws, True, True)
        result = self.runner.execute(argv)
        self.assertEqual(result.rc, 1)
        self.assertIn(str(cm.exception), result.err)
        # The tick without keep: the builder refuses it, and so does the command.
        with self.assertRaises(gm.FormError):
            gm.change_lead("other", "template", "ai-debian-13", add_old_network=True)
        raw = [*gm.SUDO, gm.QMCP, "project", "lead", "other", "--lead-template", "ai-debian-13",
               "--lead-name", "ai-other-l3", "--add-old-network"]
        self.assertEqual(self.runner.execute(raw).rc, 1)

    def test_the_commands_with_a_model(self):
        sudo = [*gm.SUDO, gm.QMCP, "project"]
        self.assertEqual(gm.create_project("newp", "template", "ai-debian-13", None, "ai-net-router", [],
                                           ["none"], "5G", False, "api.anthropic.com:443"),
                         sudo + ["create", "newp", "--lead-template", "ai-debian-13", "--lead-netvm",
                                 "ai-net-router", "--model", "api.anthropic.com:443", "--network",
                                 "none", "--quota", "5G"])
        self.assertEqual(gm.change_lead("osint", "template", "ai-debian-13", "ai-osint-boss",
                                        "ai-net-router", True, "api.anthropic.com:443", True),
                         sudo + ["lead", "osint", "--lead-template", "ai-debian-13", "--lead-name",
                                 "ai-osint-boss", "--lead-netvm", "ai-net-router", "--keep-old",
                                 "--add-old-network", "--model", "api.anthropic.com:443"])
        self.assertNotIn("--model", gm.change_lead("osint", "template", "ai-debian-13", model=" "))
        for kw in (dict(model="no-port"), dict(model="a.b:0")):
            with self.assertRaises(gm.FormError, msg=kw):
                gm.create_project("newp", "template", "ai-debian-13", networks=["none"], quota="1G", **kw)
        self.assertEqual(gm.check_networks(["none", "ai-net-router"], self.gateways()),
                         ["none", "ai-net-router"])
        with self.assertRaises(gm.FormError):
            gm.check_networks(["sys-firewall"], self.gateways())


# ======================================================================= lead firewalls: the model

class FirewallModel(GuiBase):
    """A lead's firewall: the view, its pane, the forms' commands, and the
    proposal that changes it, against the real command. osint's lead has a
    network and no rules on record, as after an upgrade."""

    def test_each_firewall_command_is_exactly_what_runs(self):
        sudo = [*gm.SUDO, gm.QMCP, "project", "firewall"]
        self.assertEqual(gm.show_lead_firewall("osint"),
                         [gm.QMCP, "project", "firewall", "osint", "--json"])         # a read
        self.assertEqual(gm.set_lead_model("osint", " API.anthropic.com:443 "),
                         sudo + ["osint", "--model", "API.anthropic.com:443"])
        self.assertEqual(gm.set_lead_rules("osint", RULES),
                         sudo + ["osint", "--rule", RULES[0], "--rule", RULES[1], "--rule", RULES[2]])
        self.assertEqual(gm.accept_lead_rules("p01"), sudo + ["p01", "--accept-current"])
        for builder, kw in ((gm.set_lead_model, dict(key="osint", model="")),
                            (gm.set_lead_model, dict(key="osint", model="no-port")),
                            (gm.set_lead_model, dict(key="osint", model="a.b:0")),
                            (gm.set_lead_rules, dict(key="osint", rules=[])),
                            (gm.set_lead_rules, dict(key="osint", rules=["action=drop"] * 33)),
                            (gm.set_lead_rules, dict(key="osint", rules=["action=accept  proto=tcp"])),
                            (gm.accept_lead_rules, dict(key="--json")),
                            (gm.show_lead_firewall, dict(key="Bad"))):
            with self.assertRaises(gm.FormError, msg=(builder.__name__, kw)):
                builder(**kw)
        # The window refuses a rule exactly when the command does, in its words.
        for rules in (["action=accept comment=hi"], ["action=allow"], ["proto=tcp"]):
            with self.assertRaises(gm.FormError) as cm:
                gm.set_lead_rules("osint", rules)
            result = self.runner.execute(sudo + ["osint"] + [x for r in rules for x in ("--rule", r)])
            self.assertEqual(result.rc, 1, rules)
            self.assertIn(str(cm.exception), result.err)
        self.assertEqual(self.lead_rules(), ["action=accept"])

    def test_the_view_of_a_lead_with_no_rules_accepted(self):
        doc = self.view()
        self.assertEqual((doc["lead"], doc["model"], doc["accepted"], doc["live"], doc["same"]),
                         (LEAD, None, None, ["action=accept"], False))
        rows = dict(gm.firewall_details(doc))
        self.assertEqual(rows["Rules you accepted"], "none on record")
        self.assertEqual(rows["Rules it has now (live)"], "action=accept")
        self.assertEqual(rows["Live rules are the ones you accepted"],
                         "not known: the rules you accepted or the live ones are missing")
        self.assertNotIn("Live rules not read", rows)
        self.assertEqual(gm.firewall_actions(doc), {"set_model", "set_rules", "accept_rules"})
        self.assertEqual(self.runner.execute(gm.accept_lead_rules("osint")).rc, 0)
        doc = self.view()
        self.assertEqual((doc["accepted"], doc["same"]), (["action=accept"], True))
        self.assertEqual(dict(gm.firewall_details(doc))["Live rules are the ones you accepted"], "yes")
        self.assertEqual(gm.firewall_actions(doc), {"set_model", "set_rules"})   # nothing to accept
        # A change made by hand in dom0: they differ, and check fails on it.
        self.app.domains[LEAD].__dict__["_firewall"] = ["action=drop"]
        doc = self.view()
        self.assertEqual(dict(gm.firewall_details(doc))["Live rules are the ones you accepted"],
                         "no: they differ, and qmcp check fails on it while the lead has a network")
        self.assertIn("accept_rules", gm.firewall_actions(doc))
        cols = gm.rules_compare(doc)
        self.assertEqual(cols, [("Accepted now", "action=accept"), ("Live now", "action=drop")])

    def test_rules_that_were_not_read_are_never_an_empty_list(self):
        self.app.fail.add("admin.vm.firewall.Get")
        doc = self.view()
        self.assertEqual((doc["live"], doc["read_error"], doc["same"]), (None, "Injected", False))
        rows = dict(gm.firewall_details(doc))
        self.assertEqual(rows["Rules it has now (live)"], "could not be read (Injected)")
        self.assertEqual(rows["Live rules not read"], "Injected")
        self.assertEqual(gm.firewall_actions(doc), {"set_model", "set_rules"})   # nothing read to accept
        self.assertEqual(dict(gm.rules_compare(doc))["Live now"], "could not be read (Injected)")
        self.assertEqual(gm.live_text(dict(doc, live=[], read_error=None)), "(no rules)")  # read: empty
        # A project without a lead has none to show, and nothing to change.
        self.assertEqual(self.runner.execute(gm.remove_lead("other")).rc, 0)
        doc = self.view("other")
        self.assertEqual(dict(gm.firewall_details(doc))["Rules it has now (live)"],
                         "none: the project has no lead")
        self.assertEqual(gm.firewall_actions(doc), set())
        # A read that failed, or answered about something else, is no view.
        for result in (gm.Result(gm.show_lead_firewall("osint"), 1, "", "qmcp project firewall: x"),
                       gm.Result(gm.show_lead_firewall("osint"), 0, json.dumps(dict(self.view(),
                                                                                  live="action=accept"))),
                       gm.Result(gm.show_lead_firewall("osint"), 0, json.dumps(self.view("other")))):
            with self.assertRaises(gm.ReadError):
                gm.parse_firewall(result, "osint")

    def test_each_rule_is_one_line_and_is_sent_as_it_is(self):
        quoted = 'action=accept dsthost=a"b'
        shown = gm.esc_items([quoted, "action=drop"])
        self.assertIsInstance(shown, gm.Shown)
        self.assertEqual(shown, "action=accept dsthost=a" + chr(92) + '"b' + chr(10) + "action=drop")
        self.assertEqual(gm.typed_rules(shown, [quoted, "action=drop"]), [quoted, "action=drop"])
        self.assertEqual(gm.typed_rules("  action=drop  \n\n\taction=accept\n"),
                         ["action=drop", "action=accept"])
        hostile = gm.esc_items([HOSTILE, "action=drop"])
        self.assertEqual(len(hostile.split(chr(10))), 2)
        self.assertTrue(hostile.isascii())
        self.assertIn(chr(92) + "u202e", hostile)

    def test_the_pane_keeps_the_last_view_of_its_project_only(self):
        read = lambda key="osint": self.runner.execute(gm.show_lead_firewall(key))  # noqa: E731
        pane = gm.FirewallPane()
        self.assertEqual((pane.note(), pane.actions("osint")), ("", set()))
        seq = pane.select("osint")
        self.assertEqual(pane.actions("osint"), set())                 # reading: nothing yet
        self.assertEqual(pane.note(), "reading: qmcp project firewall osint --json")
        self.assertTrue(pane.answer(seq, read(), "10:00:00"))
        self.assertEqual(pane.actions("osint"), {"set_model", "set_rules", "accept_rules"})
        self.assertEqual(pane.actions("other"), set())                 # not the selection's
        self.assertEqual(pane.note(), "read at 10:00:00: qmcp project firewall osint --json")
        good = pane.doc
        failed = gm.Result(gm.show_lead_firewall("osint"), 1, "", "QubesDaemonCommunicationError")
        self.assertTrue(pane.answer(pane.select("osint"), failed, "10:01:00"))
        self.assertIs(pane.doc, good)
        self.assertEqual(pane.actions("osint"), set())
        self.assertIn("could not be read", pane.note())
        self.assertIn("Showing it as read at 10:00:00", pane.note())
        section = gm.firewall_section(pane, "osint")
        self.assertEqual(section[0], ("Lead firewall", pane.note()))
        self.assertEqual(section[1:], gm.firewall_details(good))
        self.assertEqual(gm.firewall_section(pane, "other"), [])
        # Another project's failed read never shows this one's view.
        self.assertTrue(pane.answer(pane.select("other"), failed, "10:02:00"))
        self.assertIsNone(pane.doc)
        # A late answer changes nothing; a refresh makes the view stale.
        old, new = pane.select("osint"), pane.select("osint")
        self.assertFalse(pane.answer(old, read(), "x"))
        self.assertTrue(pane.answer(new, read(), "10:03:00"))
        self.assertTrue(pane.actions("osint"))
        pane.stale()
        self.assertEqual(pane.actions("osint"), set())

    def test_an_open_form_is_checked_against_the_view_on_display(self):
        read = lambda: self.runner.execute(gm.show_lead_firewall("osint"))  # noqa: E731
        pane = gm.FirewallPane()
        pane.answer(pane.select("osint"), read(), "10:00:00")
        opened = pane.doc
        self.assertIsNone(gm.firewall_changed(opened, "set_rules", pane))
        pane.stale()
        self.assertIsNotNone(gm.firewall_changed(opened, "set_rules", pane))      # being read again
        pane.answer(pane.select("osint"), read(), "10:01:00")
        self.assertIsNone(gm.firewall_changed(opened, "set_rules", pane))         # it reads the same
        self.app.domains[LEAD].__dict__["_firewall"] = ["action=drop"]
        pane.answer(pane.select("osint"), read(), "10:02:00")
        self.assertIn("changed since this form opened", gm.firewall_changed(opened, "set_rules", pane))
        self.assertEqual(self.runner.execute(gm.accept_lead_rules("osint")).rc, 0)
        pane.answer(pane.select("osint"), read(), "10:03:00")
        opened = pane.doc
        self.assertIsNotNone(gm.firewall_changed(opened, "accept_rules", pane))   # not allowed now
        self.assertIsNone(gm.firewall_changed(opened, "set_model", pane))

    def test_a_lead_with_no_network_takes_no_model(self):
        # other's lead has no network. The command refuses it a model, in
        # these words, and changes nothing; its rules can still be set or accepted.
        why = (f"{OTHER_LEAD} has no network, so it reaches no model endpoint; set its rules, or "
               f"give the project a new lead on a network")
        fleet_rows = lambda: self.read_json("list", "--all", "--json")  # noqa: E731
        doc = self.view("other")
        self.assertIs(gm.lead_on_network(doc, fleet_rows()), False)
        self.assertEqual(gm.model_refusal(doc, fleet_rows()), why)
        self.assertEqual(gm.firewall_actions(doc, fleet_rows()), {"set_rules", "accept_rules"})
        result = self.runner.execute(gm.set_lead_model("other", "api.anthropic.com:443"))
        self.assertEqual(result.rc, 1)
        self.assertIn(why, result.err)
        p = projects.find(projects.load(), "other")
        self.assertEqual((p.model, p.lead_firewall, self.lead_rules(OTHER_LEAD)),
                         (None, None, ["action=accept"]))
        self.assertEqual(self.runner.execute(gm.accept_lead_rules("other")).rc, 0)
        self.assertEqual(self.runner.execute(gm.set_lead_rules("other", ["action=drop"])).rc, 0)
        self.assertEqual(self.lead_rules(OTHER_LEAD), ["action=drop"])
        # The view's pane says why Set lead model is off, and keeps it off.
        pane = gm.FirewallPane()
        pane.answer(pane.select("other"), self.runner.execute(gm.show_lead_firewall("other")), "10:00:00")
        self.assertEqual(pane.actions("other", fleet_rows()), {"set_rules"})
        section = dict(gm.firewall_section(pane, "other", fleet_rows()))
        self.assertEqual(section["Set lead model"], f"off: {why}")
        opened = pane.doc
        self.assertEqual(gm.firewall_changed(opened, "set_model", pane, fleet_rows()), why)
        self.assertIsNone(gm.firewall_changed(opened, "set_rules", pane, fleet_rows()))
        # On a network, it takes one.
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["ai-net-router"]
        self.assertIs(gm.lead_on_network(opened, fleet_rows()), True)
        self.assertIn("set_model", pane.actions("other", fleet_rows()))
        self.assertNotIn("Set lead model", dict(gm.firewall_section(pane, "other", fleet_rows())))
        self.assertIsNone(gm.firewall_changed(opened, "set_model", pane, fleet_rows()))
        self.assertEqual(self.runner.execute(gm.set_lead_model("other", "api.anthropic.com:443")).rc, 0)
        # A lead whose row is not on show: the command decides.
        self.assertIsNone(gm.lead_on_network(opened, []))
        self.assertIn("set_model", gm.firewall_actions(opened, []))
        # A network the listing could not read is never taken for none, nor for
        # one: the window says the command's reason before OK, and the command,
        # which reads it again, refuses in the same words.
        self.app.fail.add(f"get.netvm:{OTHER_LEAD}")
        rows = fleet_rows()
        self.assertEqual(next(r for r in rows if r["name"] == OTHER_LEAD)["netvm"], "<unreadable>")
        self.assertIsNone(gm.lead_on_network(opened, rows))
        self.assertEqual(gm.model_refusal(opened, rows), f"the network of {OTHER_LEAD} cannot be read")
        self.assertNotIn("set_model", gm.firewall_actions(opened, rows))
        result = self.runner.execute(gm.set_lead_model("other", "api.anthropic.com:443"))
        self.assertEqual(result.rc, 1)
        self.assertIn("cannot be read", result.err)
        self.app.fail.discard(f"get.netvm:{OTHER_LEAD}")

    def test_the_forms_say_what_they_do(self):
        doc = self.view()
        after = gm.model_rules("API.anthropic.com:443")
        self.assertEqual(after, firewall.endpoint_rules("api.anthropic.com:443"))
        cols = gm.rules_compare(doc, after)
        self.assertEqual([h for h, _ in cols], ["Accepted now", "Live now", "After OK"])
        self.assertEqual(cols[2][1], chr(10).join(after))
        self.assertEqual(gm.model_rules(""), "type the endpoint, host:port")
        self.assertIn("host:port", gm.model_rules("no-port"))
        self.assertEqual(dict(gm.rules_compare(doc, "no rules typed"))["After OK"], "no rules typed")
        self.assertIn(f"Sets the model endpoint of {LEAD}, the lead of osint", gm.model_intro(doc))
        self.assertIn("compare the rules below", gm.rules_intro(doc))
        self.assertIn("nothing on the qube changes", gm.accept_rules_intro(doc, "10:00:00"))
        self.assertIn("as read at 10:00:00", gm.accept_rules_intro(doc, "10:00:00"))

    def test_the_check_tab_lists_the_lead_firewall_findings(self):
        def rows():
            return {(r[0], r[1]) for r in gm.check_rows(self.read_json("check", "--json"))}
        self.assertIn(("WARN", "lead firewalls not accepted"), rows())
        self.assertEqual(self.runner.execute(gm.accept_lead_rules("osint")).rc, 0)
        self.assertNotIn(("WARN", "lead firewalls not accepted"), rows())
        self.assertIn(("PASS", "lead firewalls"), rows())
        self.app.domains[LEAD].__dict__["_firewall"] = ["action=drop"]      # by hand, in dom0
        self.assertIn(("FAIL", "lead firewalls"), rows())

    def test_a_lead_firewall_proposal_shows_the_rules_now_and_after(self):
        reply = self.submit_proposal("rules")
        doc = self.show(reply["id"])
        rows = dict(gm.proposal_details(doc))
        self.assertEqual(rows["Lead's model, now -> after"], "- -> -")
        self.assertEqual(rows["Lead firewall now, as you accepted it"], "none on record")
        self.assertEqual(rows["Lead firewall now, live"], "action=accept")
        self.assertEqual(rows["Lead firewall after accepting"], chr(10).join(RULES))
        self.assertEqual(rows["Lead firewall rules"], chr(10).join(RULES))      # the option itself
        self.assertTrue(rows["Equivalent command"].startswith("qmcp project firewall osint --rule "))
        self.assertEqual(rows["Second tick"], "needed: the reasons are in red below")
        self.assertIn("- changes the lead firewall of osint to 3 rules: compare the old and new rules",
                      gm.second_tick_text(doc))
        self.assertEqual(gm.proposal_actions(doc), {"reject_proposal"})
        self.assertIn("compare its firewall now and after accepting", gm.accept_intro(doc))
        self.assertEqual(self.runner.execute(gm.accept_proposal(reply["id"], doc["sha256"])).rc, 1)
        self.assertEqual(self.runner.execute(gm.accept_proposal(reply["id"], doc["sha256"],
                                                                doc["tick"])).rc, 0)
        self.assertEqual(self.lead_rules(), SPELLED)
        self.assertEqual(self.view()["accepted"], SPELLED)
        # A model: the model now and after, and the rules the endpoint writes.
        rows = dict(gm.proposal_details(self.show(self.submit_proposal("model")["id"])))
        self.assertEqual(rows["Lead's model, now -> after"], "- -> api.anthropic.com:443")
        self.assertEqual(rows["Lead firewall now, as you accepted it"], chr(10).join(SPELLED))
        self.assertEqual(rows["Lead firewall after accepting"],
                         chr(10).join(firewall.endpoint_rules("api.anthropic.com:443")))
        # Rules not read say so; each rule is one line, escaped, whatever it holds.
        rows = dict(gm.firewall_change({"model": None, "accepted": None, "live": None,
                                        "read_error": None}, None))
        self.assertEqual(rows["Lead firewall now, live"],
                         "not read: the project has no lead, or no qube of that name")
        live = dict(gm.firewall_change({"live": [HOSTILE, "action=drop"]}, {}))["Lead firewall now, live"]
        self.assertEqual(len(live.split(chr(10))), 2)
        self.assertTrue(live.isascii())
        # Live rules that could not be read say so, with the error: never an
        # empty list, never "no lead". Through the real show.
        self.app.fail.add("admin.vm.firewall.Get")
        doc = self.show(self.submit_proposal("rules")["id"])
        self.assertEqual((doc["before"]["live"], doc["before"]["read_error"]), (None, "Injected"))
        rows = dict(gm.proposal_details(doc))
        self.assertEqual(rows["Lead firewall now, live"], "could not be read (Injected)")
        self.assertEqual(rows["Lead firewall now, as you accepted it"], chr(10).join(SPELLED))
        self.app.fail.discard("admin.vm.firewall.Get")
        # A project with no lead now: no live rules, and no error either.
        self.assertEqual(self.runner.execute(gm.remove_lead("osint")).rc, 0)
        doc = self.show(self.submit_proposal("rules")["id"])
        self.assertEqual((doc["before"]["live"], doc["before"]["read_error"]), (None, None))
        self.assertEqual(dict(gm.proposal_details(doc))["Lead firewall now, live"],
                         "not read: the project has no lead, or no qube of that name")

    def test_a_lead_proposal_shows_its_model_and_the_old_leads_network(self):
        doc = self.show(self.submit_proposal("netlead")["id"])
        rows = dict(gm.proposal_details(doc))
        self.assertEqual(rows["Lead's model endpoint"], "api.anthropic.com:443")
        self.assertEqual(rows["Add the old lead's network to the worker networks"], "yes")
        self.assertTrue(rows["Equivalent command"].endswith(
            "--keep-old --add-old-network --model api.anthropic.com:443"), rows["Equivalent command"])


# ======================================================================= the command's new reads

class CliReads(GuiBase):
    def test_check_json_keeps_the_exit_status(self):
        result = self.read("check", "--json")
        doc = json.loads(result.out)
        self.assertEqual(result.rc, cli.EXIT[doc["result"]])
        self.assertTrue(doc["findings"])

    def test_list_all_adds_qubes_outside_ai_space_but_not_dom0(self):
        rows = {r["name"]: r for r in self.read_json("list", "--all", "--json")}
        self.assertIsNone(rows["personal"]["state"])
        self.assertNotIn("dom0", rows)
        self.assertTrue(rows["ai-net-router"]["gateway"])
        self.assertTrue(rows["ai-dvm"]["dvmt"])
        self.assertFalse(rows["ai-work"]["dvmt"])
        plain = {r["name"] for r in self.read_json("list", "--json")}
        self.assertNotIn("personal", plain)
        self.assertEqual(plain, {n for n, r in rows.items() if r["state"] is not None})

    def test_settings_reads_the_operator_files_as_the_services_do(self):
        s = self.read_json("settings", "--json")
        self.assertEqual((s["hub"], s["name_prefix"], s["pool_cap"]), (HUB, "ai-", 1000 * 1024 ** 3))
        self.assertIsNone(s["birth_egress"])
        self.egress("ai-net-router")
        self.assertEqual(self.read_json("settings", "--json")["birth_egress"], "ai-net-router")
        self.assertGreater(s["ai_space_bytes"], 0)
        self.assertIn("hub: mcp-control", self.read("settings").out)


class UninstallRotatedLogs(unittest.TestCase):
    """`uninstall.sh --purge` removes the files `qmcp audit rotate` makes, and its
    clean-state check names them. Found on the dev box 2026-10-02: purge left them
    and said nothing. The helper is run out of the script itself, against names
    made by the real `audit.rotate`, under the script's own `set -euo pipefail`."""

    def helper(self, prefix):
        text = (HERE.parent / "deploy" / "uninstall.sh").read_text()
        glob = next(l for l in text.splitlines() if l.startswith("ROTATED_GLOB="))
        func = next(l for l in text.splitlines() if l.startswith("rotated() {"))
        return glob.replace("/var/log/", prefix + "/") + "\n" + func + "\n"

    def run_helper(self, prefix, body):
        script = "set -euo pipefail\n" + self.helper(prefix) + body
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)

    def test_it_lists_exactly_what_rotate_makes(self):
        import tempfile
        d = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-rot-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        log = d / "qmcp-audit.log"
        log.write_text("")
        made = audit.rotate(str(log))                          # the real name
        for decoy in ("qmcp-audit.log.bak", "qmcp-audit.log.20261002", "other.log.20261002T105307Z",
                      "qmcp-audit.log.20261002T105307Zx"):
            (d / decoy).write_text("")
        r = self.run_helper(str(d), 'rotated; n=$(rotated | wc -l); echo "n=$n"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), [made, "n=1"])

    def test_none_is_not_an_error_under_set_e(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="qmcp-rot-")
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        r = self.run_helper(d, 'n=$(rotated | wc -l); echo "n=$n reached"')
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "n=0 reached"), r.stderr)

    def test_purge_removes_them_and_the_check_names_them(self):
        text = (HERE.parent / "deploy" / "uninstall.sh").read_text()
        purge = text.split('if [ "$MODE" = purge ]; then', 1)[1].split("fi", 1)[0]
        self.assertIn('for f in $(rotated); do rm -f "$f"; done', purge)
        self.assertIn('for f in $(rotated); do report "$f"; done', text)
        self.assertIn("$(rotated); do [ -f \"$f\" ] && cp -a \"$f\" \"$BACKUP/\"", text)


class CliPlanAndSizes(GuiBase):
    def test_the_delete_plan_is_a_read(self):
        result = self.read("project", "delete", "osint")          # as the user, no sudo
        self.assertEqual(result.rc, 1)
        self.assertIn("this removes p01 'osint'", result.out)
        self.assertIn("Re-run with --yes", result.out)
        self.assertIsNotNone(projects.find(projects.load(), "osint"))
        result = self.read("project", "delete", "p09")
        self.assertIn("finishes a delete", result.out)
        result = self.read("project", "delete", "osint", "--yes")  # the delete itself needs root
        self.assertIn("run as root", result.err)
        self.assertIsNotNone(projects.find(projects.load(), "osint"))

    def test_a_quota_past_one_eib_is_refused_by_the_form_and_the_command(self):
        self.assertEqual(projects.MAX_QUOTA, 1048576 * 1024 ** 4)       # 1 EiB = 1048576T
        gm.edit_project("osint", quota="1048576T")                       # the cap itself is a quota
        for builder, kw in ((gm.edit_project, dict(key="osint", quota="1048577T")),
                            (gm.create_project, dict(label="ok", lead_source="template",
                                                     lead_origin="t", networks=["none"],
                                                     quota="1048577T"))):
            with self.assertRaises(gm.FormError, msg=builder.__name__):
                builder(**kw)
        result = self.runner.execute(gm.write_cmd("project", "edit", "osint", "--quota", "1048577T"))
        self.assertEqual(result.rc, 1)
        self.assertIn("at most 1 EiB", result.err)

    def test_sizes_are_ascii(self):
        for text in ("5\u212a", "\uff15G", "5\u0130"):         # KELVIN SIGN, FULLWIDTH 5, dotted I
            with self.assertRaises(fleet.ProjectError, msg=ascii(text)):
                fleet.parse_size(text)
        self.assertEqual(fleet.parse_size("5k"), 5 * 1024)


# ======================================================================= structure

TEXT_SETTERS = {"set_text", "set_label", "set_title", "set_name", "append", "prepend", "insert",
                "set", "set_value", "append_text", "prepend_text", "insert_text",
                "new_with_label", "new_with_label_from_widget", "set_placeholder_text",
                "set_tooltip_text", "add_button", "push", "set_secondary_text",
                "set_tab_label_text", "set_menu_label_text", "insert_at_cursor", "set_subtitle",
                "set_comments", "set_icon_tooltip_text", "set_text_column"}
#: Properties whose value is text on screen; `w.props.<name> = value` sets them.
TEXT_PROPS = {"label", "title", "text", "tooltip_text", "placeholder_text", "secondary_text",
              "subtitle", "name", "markup", "tooltip_markup", "use_markup", "use_underline"}
TEXT_CTORS = {"Label", "Button", "CheckButton", "RadioButton", "ToggleButton", "Frame",
              "Expander", "MenuItem", "LinkButton", "Dialog", "TreeViewColumn", "Window",
              "__init__", "Entry"}
TEXT_KWARGS = {"label", "title", "text", "tooltip_text", "placeholder_text", "secondary_text"}
BANNED = {"set_markup", "set_markup_with_mnemonic", "set_use_markup", "use_markup", "markup",
          "set_tooltip_markup", "tooltip_markup", "set_tooltip_column", "tooltip_column",
          "insert_markup", "format_secondary_markup", "secondary_use_markup", "parse_markup",
          "markup_escape_text", "new_with_mnemonic", "set_use_underline", "use_underline",
          "set_text_with_mnemonic", "MessageDialog"}
FUNNELS = {"_need", "_label", "_set", "_set_lines", "_title", "_named", "_button", "_add_button",
           "_placeholder", "_check", "_radio", "_fill", "_column", "_tree_append", "_list_append"}


def _literal(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None)))


class Structure(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse(GUI_SRC.read_text())
        self.parents = {}
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent

    def enclosing(self, node):
        while node in self.parents:
            node = self.parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name
        return None

    def test_no_markup_api_anywhere_in_the_window(self):
        hits = []
        for node in ast.walk(self.tree):
            name = (node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name)
                    else node.arg if isinstance(node, ast.keyword) else None)
            if name in BANNED:
                hits.append((name, getattr(node, "lineno", "?")))
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and "markup" in node.value and not node.value.startswith(("qmcp.gui", "\n")):
                hits.append((node.value[:30], node.lineno))
        self.assertEqual(hits, [])

    def test_widget_text_is_set_only_through_the_helpers(self):
        offenders = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    # w.props.label = raw
                    if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Attribute)
                            and t.value.attr == "props" and t.attr in TEXT_PROPS):
                        offenders.append(("props." + t.attr, node.lineno))
                    # store[it][column] = raw: a model cell set behind the helpers
                    if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Subscript):
                        offenders.append(("store cell", node.lineno))
                continue
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else None   # methods and Gtk.X(...)
            if isinstance(f, ast.Name) and f.id in TEXT_CTORS:          # a from-imported Label(...)
                name = f.id
            if (name == "new" and isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute)
                    and f.value.attr in TEXT_CTORS):                    # Gtk.Label.new(raw)
                name = "new_with_label"
            texty = [a for a in node.args] if name in TEXT_SETTERS else []
            if name in TEXT_SETTERS or name in TEXT_CTORS:
                texty += [k.value for k in node.keywords if k.arg in TEXT_KWARGS]
            if name == "set_property":
                prop = node.args[0] if node.args else None
                if not _literal(prop) or str(prop.value).replace("_", "-") in {
                        "text", "label", "title", "markup", "use-markup", "tooltip-text",
                        "tooltip-markup", "placeholder-text", "secondary-text"}:
                    offenders.append(("set_property", node.lineno))
                continue
            if not texty or self.enclosing(node) in FUNNELS:
                continue
            if not all(_literal(a) for a in texty):
                offenders.append((name, node.lineno))
        self.assertEqual(offenders, [], "set widget text with a helper, from esc()")

    def test_the_structure_check_sees_every_way_text_reaches_a_widget(self):
        # Each of these got past the first version of the check (M2b audit).
        for line in ('Gtk.Label.new(raw)', 'w.props.label = raw', 'store[it][1] = raw',
                     'Label(label=raw)', 'nb.set_tab_label_text(page, raw)',
                     'buf.insert_at_cursor(raw)', 'bar.set_subtitle(raw)', 'w.props.use_markup = True'):
            src = "def f():\n    " + line + "\n"
            saved = self.tree
            self.tree = ast.parse(src)
            self.parents = {c: p for p in ast.walk(self.tree) for c in ast.iter_child_nodes(p)}
            try:
                with self.assertRaises(AssertionError, msg=line):
                    self.test_widget_text_is_set_only_through_the_helpers()
            finally:
                self.tree = saved
                self.parents = {c: p for p in ast.walk(saved) for c in ast.iter_child_nodes(p)}

    def test_every_helper_refuses_unescaped_text(self):
        funcs = {n.name: n for n in self.tree.body if isinstance(n, ast.FunctionDef)}
        self.assertLessEqual(FUNNELS, set(funcs))
        for name in FUNNELS - {"_need"}:
            calls = {c.func.id for c in ast.walk(funcs[name])
                     if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
            self.assertIn("_need", calls, name)

    def test_only_the_escapers_make_shown_text(self):
        model = ast.parse(MODEL_SRC.read_text())
        makers = set()
        for fn in (n for n in ast.walk(model) if isinstance(n, ast.FunctionDef)):
            if any(isinstance(c, ast.Call) and getattr(c.func, "id", None) == "Shown"
                   for c in ast.walk(fn)):
                makers.add(fn.name)
        self.assertEqual(makers, {"esc", "esc_lines", "esc_items", "audit_detail"})

    def test_the_window_never_makes_shown_text_itself(self):
        calls = [n for n in ast.walk(self.tree) if isinstance(n, ast.Call)
                 and getattr(n.func, "attr", getattr(n.func, "id", None)) == "Shown"]
        self.assertEqual(calls, [])

    def test_the_window_never_imports_qubesadmin(self):
        code = ("import sys\nfor m in ('qubesadmin', 'qubesadmin.app', 'qubesadmin.exc'):\n"
                "    sys.modules[m] = None\nimport qmcp.guimodel, qmcp.cli\n")
        if Gtk is not None:
            code += "import qmcp.gui\n"
        env = dict(os.environ, PYTHONPATH=str(HERE.parent / "dom0"), PYTHONDONTWRITEBYTECODE="1")
        r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        model = ast.parse(MODEL_SRC.read_text())
        imported = {a.name.split(".")[0] for n in ast.walk(model)
                    if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
        imported |= {n.module.split(".")[0] for n in ast.walk(model)
                     if isinstance(n, ast.ImportFrom) and n.module}
        self.assertFalse(imported & {"gi", "qubesadmin"})

    def test_no_bidi_or_invisible_characters_in_the_tree(self):
        # Hostile text is tested with escapes in the source, never the
        # characters themselves: a raw U+202E in a source file reorders how the
        # code reads (CVE-2021-42574). One slipped into this file once.
        invisible = {*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200B, 0x200C, 0x200D,
                     0x200E, 0x200F, 0x061C, 0xFEFF}
        hits = []
        for path in HERE.parent.rglob("*"):
            if ".git" in path.parts or not path.is_file() or path.suffix in (".pyc",):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            hits += [f"{path.relative_to(HERE.parent)}:{i}" for i, line in enumerate(text.splitlines(), 1)
                     if any(ord(c) in invisible for c in line)]
        self.assertEqual(hits, [])

    def test_the_menu_entry_and_launcher(self):
        # Qubes' app menu (qubes-desktop-linux-menu 1.2.11, read on Qubes 4.3.1) reads
        # only ~/.local/share/applications and /usr/share/applications, and lists
        # under Settings > Qubes Tools an entry in X-XFCE-SettingsDialog whose file
        # name contains "qubes". The first build installed under /usr/local, and the
        # operator could not find it.
        desktop = (HERE.parent / "deploy" / "qubes-mcp.desktop").read_text()
        self.assertIn("Exec=/usr/local/bin/qmcp-gui\n", desktop)
        self.assertIn("Terminal=false", desktop)
        categories = next(l for l in desktop.splitlines() if l.startswith("Categories=")).split("=", 1)[1]
        self.assertIn("X-XFCE-SettingsDialog", categories.split(";"))
        self.assertIn("qubes", "qubes-mcp.desktop")
        install_lines = [l for l in (HERE.parent / "deploy" / "install.sh").read_text().splitlines()
                         if "qubes-mcp.desktop" in l and l.startswith("install ")]
        self.assertEqual(install_lines, ['install -m 0644 "$SRC/deploy/qubes-mcp.desktop" '
                                         '/usr/share/applications/qubes-mcp.desktop'])
        launcher = (HERE.parent / "dom0" / "bin" / "qmcp-gui").read_text()
        self.assertIn('sys.path.insert(0, "/usr/local/lib/qmcp")', launcher)
        self.assertTrue(os.access(HERE.parent / "dom0" / "bin" / "qmcp-gui", os.X_OK))
        install = (HERE.parent / "deploy" / "install.sh").read_text()
        uninstall = (HERE.parent / "deploy" / "uninstall.sh").read_text()
        for path in ("/usr/local/bin/qmcp-gui", "/usr/share/applications/qubes-mcp.desktop"):
            self.assertIn(path, install)
            self.assertIn(path, uninstall.split("OTHER_PATHS=", 1)[1].split('"', 2)[1])


# ======================================================================= the GTK window

@unittest.skipIf(Gtk is None, "GTK 3 cannot start here (no PyGObject or no display)")
class Widgets(GuiBase):
    def setUp(self):
        super().setUp()
        from qmcp import gui
        self.gui = gui
        self.reports = []
        self.win = gui.Window(runner=self.runner, show_forms=False,
                              report=lambda title, result: self.reports.append((title, result)))
        self.addCleanup(self.win.destroy)
        self.win.refresh()

    def rows(self, store):
        out = []

        def visit(model, path, it):
            out.append(list(model[it]))
            return False
        store.foreach(visit)
        return out

    def select(self, key):
        def visit(model, path, it):
            if model[it][0] == key:
                self.win.tree.get_selection().select_iter(it)
                return True
            return False
        self.win.store.foreach(visit)
        self.assertEqual(self.win.selected, key)

    def sensitive(self):
        return {k for k, b in self.win.buttons.items() if b.get_sensitive()}

    def deciding(self):
        """The Proposals tab's buttons that are on."""
        return {k for k, b in self.win.proposal_buttons.items() if b.get_sensitive()}

    def select_proposal(self, pid):
        def visit(model, path, it):
            if model[it][0] == str(pid):
                self.win.proposal_view.get_selection().select_iter(it)
                return True
            return False
        self.win.proposal_store.foreach(visit)
        self.assertEqual(self.win.pane.pid, pid)

    def gateway_select(self, name):
        def visit(model, path, it):
            if model[it][0] == name:
                self.win.gateway_view.get_selection().select_iter(it)
                return True
            return False
        self.win.gateway_store.foreach(visit)
        self.assertEqual(self.win.gateway_selected, name)

    def one_line(self, form, ok=True):
        """One line under one heading: the command while OK is on, why OK is
        off otherwise, never both and never neither. show_all() runs over the
        fields first, as it does when the window shows the form (on the
        content area: the dialog itself is never put on the screen here)."""
        form.get_content_area().show_all()
        want = (self.gui.RUNS, True, False) if ok else (self.gui.OK_OFF, False, True)
        self.assertEqual((form.runs.get_text(), form.preview.get_visible(),
                          form.error.get_visible()), want, form.get_title())
        self.assertEqual(form.ok.get_sensitive(), ok, form.get_title())
        self.assertTrue(form.error.get_style_context().has_class("qmcp-note"))

    def registry(self):
        """The Gateways tab's buttons that are on."""
        return {k for k, b in self.win.gateway_buttons.items() if b.get_sensitive()}

    def grid(self, grid):
        """A details grid, heading -> text."""
        return {grid.get_child_at(0, i).get_text(): grid.get_child_at(1, i).get_text()
                for i in range(len(grid.get_children()) // 2)}

    def propose(self, name, **changes):
        """A proposal from the hub; then Refresh, and select it."""
        reply = self.submit_proposal(name, **changes)
        self.win.refresh()
        self.select_proposal(reply["id"])
        return reply

    def pane(self):
        """The Proposals tab's details pane, heading -> text."""
        grid = self.win.proposal_details
        return {grid.get_child_at(0, i).get_text(): grid.get_child_at(1, i).get_text()
                for i in range(len(grid.get_children()) // 2)}

    def test_every_builder_parameter_has_a_field_in_its_form(self):
        # The parity test proves each builder can make every option; this
        # proves the form that calls it lets the operator set each one.
        import inspect
        self.select("project:p01")
        record = self.win.node().data
        view = self.win.fw_pane.doc
        self.assertEqual(view["project"], "osint")
        row = next(r for r in self.win.fleet if r["name"] == "ai-work2")
        self.propose("delete")
        doc = self.win.pane.doc
        forms = {
            # The number and the fingerprint come from the show on display; the
            # second tick is the box beside its reasons, on the Proposals tab.
            gm.accept_proposal: (self.gui.ProposalForm(self.win, doc, "accept_proposal", True), {
                "pid": "doc", "sha256": "doc", "tick": "ticked"}),
            gm.reject_proposal: (self.gui.ProposalForm(self.win, doc, "reject_proposal"),
                                 {"pid": "doc"}),
            gm.create_project: (self.gui.ProjectForm(self.win, self.win.fleet, self.win.gateways,
                                                     HUB), {
                "label": "label_entry", "lead_source": "source", "lead_origin": "origin",
                "lead_name": "lead_name", "lead_netvm": "lead_netvm", "templates": "templates",
                "networks": "nets", "quota": "quota", "dump": "dump", "model": "model"}),
            gm.edit_project: (self.gui.EditForm(self.win, self.win.fleet, self.win.gateways,
                                                record), {
                "key": "record", "templates": "templates", "networks": "nets", "quota": "quota"}),
            gm.change_lead: (self.gui.LeadForm(self.win, self.win.fleet, self.win.gateways, HUB,
                                               record), {
                "key": "record", "lead_source": "source", "lead_origin": "origin",
                "lead_name": "lead_name", "lead_netvm": "lead_netvm", "keep_old": "old_lead",
                "model": "model", "add_old_network": "add_old"}),
            # The registry's forms; the qube and its current values come from the row.
            gm.enroll_gateway: (self.gui.EnrollForm(self.win, self.win.fleet, self.win.gateways,
                                                    HUB), {
                "qube": "qube", "anonymising": "anonymising", "label": "label_entry"}),
            gm.change_gateway: (self.gui.GatewayForm(self.win, self.win.gateways[0]), {
                "qube": "row_data", "anonymising": "anonymising", "label": "label_entry"}),
            # A lead firewall's: the project comes from the view the form opened on.
            gm.set_lead_model: (self.gui.ModelForm(self.win, view), {"key": "doc",
                                                                     "model": "model"}),
            gm.set_lead_rules: (self.gui.RulesForm(self.win, view), {"key": "doc",
                                                                     "rules": "rules_view"}),
            gm.accept_lead_rules: (self.gui.AcceptRulesForm(self.win, view), {"key": "doc"}),
            gm.add_dump: (self.gui.DumpForm(self.win, "osint", "osint-dump"), {
                "key": "key", "sink_name": "sink_name"}),
            gm.move: (self.gui.MoveForm(self.win, row, self.win.records), {
                "qube": "row_data", "target": "target", "confirm": "confirm"}),
            gm.role: (self.gui.RevokeForm(self.win, "ai-work2"), {
                "action": "build", "qube": "qube_name", "keep_running": "keep"}),
        }
        for builder, (form, fields) in forms.items():
            params = set(inspect.signature(builder).parameters)
            self.assertEqual(params, set(fields), builder.__name__)
            for attr in fields.values():
                self.assertTrue(hasattr(form, attr), (builder.__name__, attr))
            form.destroy()
        for ident in ("remove_lead", "delete_project", "add_to_ai_space", "manage", "guard",
                      "set_model", "set_rules", "accept_rules"):
            self.assertIn(ident, dict(self.gui.Window.ACTIONS))
        self.assertEqual(set(self.win.gateway_buttons),
                         {"enroll_gateway", "change_gateway", "remove_gateway"})
        self.assertTrue(self.win.proposal_tick.get_visible())
        # Close runs reject_proposal too, from its own form (test_a_proposal_that_needs_closing...).
        self.assertEqual(set(self.win.proposal_buttons),
                         {"accept_proposal", "reject_proposal", "close_proposal"})
        for builder in set(gm.BUILDERS) - set(forms):
            # show_proposal runs when a proposal is selected, and
            # show_lead_firewall when a project or its lead is, as delete_plan
            # runs before the delete form. The others are confirmations.
            self.assertIn(builder.__name__, {"remove_lead", "delete_plan", "delete_project",
                                             "audit_rotate", "show_proposal", "remove_gateway",
                                             "show_lead_firewall"},
                          "a builder without a form")

    def test_refresh_fills_every_page_from_the_command(self):
        keys = [r[0] for r in self.rows(self.win.store)]
        self.assertEqual(keys, [n.key for n in gm.walk(self.tree())])
        self.assertTrue(set(self.win.light.get_text().split()) & {"GREEN", "FAILED", "INCOMPLETE"})
        self.assertTrue(self.rows(self.win.check_store))
        settings = [c.get_text() for c in self.win.settings_grid.get_children()]
        self.assertIn(HUB, settings)
        self.assertEqual({tuple(c[:1]) for c in self.runner.calls}, {(gm.QMCP,)})   # reads: no sudo

    def test_every_cell_on_screen_is_escaped(self):
        self.call("qmcp.LifecycleAIManaged", {"name": HOSTILE[:120], "action": "start"})
        self.win.refresh()
        for store in (self.win.store, self.win.check_store, self.win.audit_store):
            for row in self.rows(store):
                for cell in row[1:]:
                    self.assertTrue(cell.isascii() and "\n" not in cell, cell)
        newest = self.rows(self.win.audit_store)[0]
        self.assertIn("\\u202e", newest[6])
        self.win.audit_view.get_selection().select_path(Gtk.TreePath.new_first())
        buf = self.win.audit_detail.get_buffer()
        text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        self.assertIn("\\u202e", text)
        self.assertTrue(text.isascii())

    def test_the_helpers_refuse_plain_text(self):
        with self.assertRaises(TypeError):
            self.gui._set(Gtk.Label(), "plain")
        with self.assertRaises(TypeError):
            self.gui._label("plain")
        with self.assertRaises(TypeError):
            self.gui._fill(Gtk.ComboBoxText(), [("a", "plain")])

    def test_buttons_follow_the_selection(self):
        self.assertEqual(self.sensitive(), {"new_project", "add_to_ai_space"})
        self.select("project:p01")
        self.assertLessEqual({"edit_project", "change_lead", "remove_lead", "delete_project"},
                             self.sensitive())
        self.select("qube:ai-osint-w1")
        self.assertLessEqual({"move", "revoke"}, self.sensitive())
        labels = [c.get_text() for c in self.win.details.get_children() if isinstance(c, Gtk.Label)]
        self.assertIn("worker", labels)

    def submit(self, form, ok=True):
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        self.assertEqual(form.preview.get_text(), gm.shown(form.argv()))
        before = len(self.reports)
        form.response(Gtk.ResponseType.OK)
        self.assertEqual(len(self.reports), before + 1)
        title, result = self.reports[-1]
        self.assertEqual(result.ok, ok, (result.out, result.err))
        return result

    def test_new_project_from_the_form_to_the_fleet(self):
        form = self.win.act("new_project")
        self.assertFalse(form.ok.get_sensitive())               # empty form: nothing to run
        form.label_entry.set_text("newp")
        form.source["template"].set_active(True)
        form.origin.set_active_id("ai-debian-13")
        form.templates["ai-dvm"].set_active(True)
        form.nets["none"].set_active(True)
        form.nets["ai-net-router"].set_active(True)
        form.default_net.set_active_id("ai-net-router")
        form.quota.set_text("5G")
        form.dump.set_active(True)
        self.assertNotIn("ai-gw-unbadged", form.nets)          # needs attention, not offered
        self.assertEqual(form.argv(), gm.create_project(
            "newp", "template", "ai-debian-13", None, None, ["ai-dvm"],
            ["ai-net-router", "none"], "5G", True))
        result = self.submit(form)
        self.assertEqual(result.argv[:2], list(gm.SUDO))
        self.assertEqual(gm.SUDO[0], "/usr/bin/sudo")      # pinned, not found on PATH
        p = projects.find(projects.load(), "newp")
        self.assertEqual((p.lead, p.networks, p.dump), ("ai-newp-lead", ("ai-net-router", None), "newp-dump"))
        self.assertIn(f"project:{p.slot}", [r[0] for r in self.rows(self.win.store)])   # refreshed

    def test_a_promoted_lead_has_no_name_field(self):
        form = self.win.act("new_project")
        form.source["promote"].set_active(True)
        self.assertFalse(form.lead_name.get_sensitive())
        self.assertEqual(form.origin.get_active_id(), gm.hubs_appvms(self.win.fleet, HUB)[0])

    def test_edit_sends_only_what_changed(self):
        self.select("project:p01")
        form = self.win.act("edit_project")
        self.assertFalse(form.ok.get_sensitive())               # nothing changed yet
        self.assertEqual(form.error.get_text(), "nothing changed")
        form.quota.set_text("30G")
        self.assertEqual(form.argv(), gm.edit_project("osint", quota="30G"))
        form.default_net.set_active_id("none")                  # reorder: a real change
        self.assertEqual(form.argv(), gm.edit_project("osint", networks=["none", "ai-net-router"],
                                                      quota="30G"))
        self.submit(form)
        p = projects.find(projects.load(), "osint")
        self.assertEqual((p.networks, p.quota), ((None, "ai-net-router"), 30 * 1024 ** 3))

    def test_change_and_remove_the_lead(self):
        self.select("project:p02")
        form = self.win.act("change_lead")
        form.source["clone"].set_active(True)
        form.origin.set_active_id("ai-work2")
        form.old_lead.set_active_id("keep")
        form.lead_name.set_text("boss")                       # typed after the shown ai-other-
        self.assertEqual(form.lead_space.get_text(), "ai-other-")
        self.submit(form)
        p = projects.find(projects.load(), "other")
        self.assertEqual(p.lead, "ai-other-boss")
        self.assertIn("qmcp-proj-p02", self.tags(OTHER_LEAD))    # kept as a worker
        self.select("project:p02")
        form = self.win.act("remove_lead")
        self.submit(form)
        self.assertIsNone(projects.find(projects.load(), "other").lead)
        self.assertNotIn("ai-other-boss", self.app.domains)

    def test_dump_move_and_roles(self):
        self.select("project:p02")
        self.submit(self.win.act("add_dump"))
        self.assertEqual(projects.find(projects.load(), "other").dump, "other-dump")
        self.select("qube:ai-work2")
        form = self.win.act("move")
        form.target.set_active_id("p00")
        self.submit(form)
        self.assertIn("qmcp-proj-p00", self.tags("ai-work2"))
        self.select("qube:ai-work2")
        form = self.win.act("move")
        form.target.set_active_id("other")
        self.assertFalse(form.ok.get_sensitive())               # crossing slots needs the tick
        form.confirm.set_active(True)
        self.assertEqual(form.argv()[-1], "--yes")
        self.submit(form)
        self.assertIn("qmcp-proj-p02", self.tags("ai-work2"))
        self.select("qube:ai-tpl-g")
        self.submit(self.win.act("manage"))
        self.assertNotIn("qmcp-guarded", self.tags("ai-tpl-g"))
        self.select("qube:ai-tpl-g")
        self.submit(self.win.act("guard"))
        self.assertIn("qmcp-guarded", self.tags("ai-tpl-g"))
        self.select("qube:ai-work")
        form = self.win.act("revoke")
        form.keep.set_active(True)
        self.assertEqual(form.argv()[-1], "--no-shutdown")
        self.submit(form)
        self.assertNotIn("ai-managed", self.tags("ai-work"))
        form = self.win.act("add_to_ai_space")
        form.qube.set_active_id("ai-work")
        form.guarded.set_active(True)
        self.submit(form)
        self.assertLessEqual({"ai-managed", "qmcp-guarded"}, self.tags("ai-work"))

    def test_delete_shows_the_commands_own_plan_first(self):
        self.select("project:p02")
        self.win.act("delete_project")
        plan_call = self.runner.calls[-1]
        self.assertEqual(plan_call, gm.delete_plan("other"))
        form = self.win.last_form
        intro = [c.get_text() for c in form.get_content_area().get_children()
                 if isinstance(c, Gtk.Label)][0]
        self.assertIn(OTHER_LEAD, intro)
        self.assertNotIn("--yes", intro)
        self.assertIsNotNone(projects.find(projects.load(), "other"))   # the plan changed nothing
        self.submit(form)
        self.assertIsNone(projects.find(projects.load(), "other"))
        self.assertNotIn("project:p02", [r[0] for r in self.rows(self.win.store)])

    def test_one_command_at_a_time(self):
        self.runner.hold = True
        self.assertTrue(self.win.write("t", gm.audit_rotate()))
        self.assertTrue(self.win.busy)
        self.assertEqual(self.sensitive(), set())
        self.assertFalse(self.win.write("t", gm.audit_rotate()))
        self.runner.hold = False
        self.runner.release()
        self.assertFalse(self.win.busy)
        self.assertEqual(self.reports[-1][0], "t")

    def test_a_refused_change_is_reported_with_the_commands_reason(self):
        self.select("qube:ai-work")                              # on ai-net-router
        form = self.win.act("move")
        form.target.set_active_id("other")                      # other's only network is none
        result = self.submit(form, ok=False)
        self.assertIn("not one of other's worker networks", result.err)
        self.assertNotIn("qmcp-proj-p02", self.tags("ai-work"))

    def test_a_failed_read_keeps_the_last_good_view_and_turns_changes_off(self):
        self.select("project:p01")
        self.runner.fail.add(tuple(gm.READS["projects"]))
        self.win.refresh()
        keys = [r[0] for r in self.rows(self.win.store)]
        self.assertIn("project:p01", keys)                      # the last good view
        self.assertNotIn("slot:p01", keys)                      # never "no record" from a failure
        self.assertEqual(self.sensitive(), set())
        self.assertFalse(self.win.rotate_button.get_sensitive())
        self.assertIn("Changes are off", self.win.status.get_text())
        self.assertFalse(self.win.write("t", gm.audit_rotate()))
        self.runner.fail.clear()
        self.win.refresh()
        self.select("project:p01")
        self.assertIn("delete_project", self.sensitive())

    def test_records_never_read_judge_nothing(self):
        runner = CliRunner(self.app)
        runner.fail.add(tuple(gm.READS["projects"]))
        win = self.gui.Window(runner=runner, show_forms=False, report=lambda *a: None)
        self.addCleanup(win.destroy)
        win.refresh()
        nodes = {k: n for k, n in win.nodes.items()}
        self.assertIn("slot:p01", nodes)
        self.assertEqual(nodes["slot:p01"].cells[1], "records not read")
        self.assertNotIn("finish_delete", gm.actions(nodes["slot:p01"], {}))
        self.assertEqual(nodes[f"qube:{LEAD}"].data["role"], "lead (records not read)")
        # Judgements that need the records are not made; one from badges alone is.
        attention = {c.data["name"]: c.data["attention"] for c in nodes["group:attention"].children}
        self.assertEqual(attention, {"ai-gw-unbadged": "gateway"})
        self.assertFalse(any(b.get_sensitive() for b in win.buttons.values()))

    def test_a_failed_check_is_no_light(self):
        self.runner.fail.add(tuple(gm.READS["check"]))
        self.win.refresh()
        self.assertEqual(self.win.light.get_text(), "qmcp check: UNKNOWN")
        self.assertEqual(self.sensitive(), set())

    def test_reads_have_a_timeout_and_changes_do_not(self):
        self.runner.calls.clear()
        self.runner.timeouts.clear()
        self.select("qube:ai-tpl-g")
        self.submit(self.win.act("manage"))
        by_call = list(zip(self.runner.calls, self.runner.timeouts))
        writes = [t for c, t in by_call if c[:2] == list(gm.SUDO)]
        reads = [t for c, t in by_call if c[:2] != list(gm.SUDO)]
        self.assertEqual(writes, [None])
        self.assertTrue(reads and all(t == self.gui.READ_TIMEOUT_S for t in reads))

    def test_the_add_form_starts_with_nothing_chosen_and_the_lesser_authority(self):
        form = self.win.act("add_to_ai_space")
        self.assertIsNone(form.qube.get_active_id())
        self.assertTrue(form.guarded.get_active())
        self.assertFalse(form.ok.get_sensitive())

    def test_dialog_buttons_have_no_mnemonics(self):
        dialog = Gtk.Dialog()
        self.addCleanup(dialog.destroy)
        button = self.gui._add_button(dialog, gm.esc("ai_x"), Gtk.ResponseType.OK)
        self.assertFalse(button.get_use_underline())
        self.assertEqual(button.get_label(), "ai_x")

    def test_an_unexpected_error_never_leaves_an_old_command_on_show(self):
        form = self.win.act("new_project")
        form.label_entry.set_text("newp")
        form.nets["none"].set_active(True)
        form.quota.set_text("5G")
        self.assertTrue(form.ok.get_sensitive())
        form.quota.set_text("5\u212a")                     # KELVIN SIGN: case-folds to k
        self.assertFalse(form.ok.get_sensitive())
        self.assertEqual(form.preview.get_text(), "")
        saved = gm.create_project
        gm.create_project = lambda *a, **kw: {}["boom"]
        try:
            form.quota.set_text("5G")
            self.assertFalse(form.ok.get_sensitive())
            self.assertIn("KeyError", form.error.get_text())
        finally:
            gm.create_project = saved

    def test_every_option_is_reachable_from_a_form(self):
        # The parity test proves each builder can make every option; this one
        # proves the forms make them, by filling each form every way.
        parser = cli.build_parser()
        argvs = list(gm.READS.values()) + [gm.AUDIT_VERIFY]
        rows = self.win.fleet

        gws = self.win.gateways

        def project(source, origin, name):
            f = self.gui.ProjectForm(self.win, rows, gws, HUB)
            f.label_entry.set_text("newp")
            f.source[source].set_active(True)
            f.origin.set_active_id(origin)
            if name:
                f.lead_name.set_text(name)
            if source == "promote":             # it keeps its own network (none), or takes none
                f.lead_netvm.set_active_id("none")
            else:
                f.lead_netvm.set_active_id("ai-net-router")
                f.model.set_text("api.anthropic.com:443")
            f.templates["ai-dvm"].set_active(True)
            f.nets["none"].set_active(True)
            f.quota.set_text("5G")
            f.dump.set_active(True)
            return f
        forms = [project("template", "ai-debian-13", "ai-newp-boss"),
                 project("clone", "ai-work2", "ai-newp-boss"), project("promote", "ai-work2", None)]
        self.select("project:p01")
        record = self.win.node().data
        f = self.gui.EditForm(self.win, rows, gws, record)
        f.templates["ai-dvm"].set_active(False)
        f.default_net.set_active_id("none")
        f.quota.set_text("30G")
        forms.append(f)
        for source, origin in (("template", "ai-debian-13"), ("clone", "ai-work2"), ("promote", "ai-work2")):
            f = self.gui.LeadForm(self.win, rows, gws, HUB, record)
            f.source[source].set_active(True)
            f.origin.set_active_id(origin)
            if source != "promote":
                f.lead_name.set_text("ai-osint-boss")
            f.old_lead.set_active_id("keep")
            if source == "template":
                f.lead_netvm.set_active_id("ai-net-router")
                f.model.set_text("api.anthropic.com:443")
                f.add_old.set_active(True)
            else:
                f.lead_netvm.set_active_id("none")
            forms.append(f)
        # The registry: enroll a router, change one, remove one no project uses.
        self.routers()
        self.assertEqual(self.runner.execute(gm.enroll_gateway("sys-ai-net")).rc, 0)
        self.win.refresh()
        rows, gws = self.win.fleet, self.win.gateways
        f = self.gui.EnrollForm(self.win, rows, gws, HUB)
        f.qube.set_active_id("sys-ai-tor")
        f.anonymising.set_active(True)
        f.label_entry.set_text("Tor")
        forms.append(f)
        f = self.gui.GatewayForm(self.win, next(r for r in gws if r["name"] == "ai-net-router"))
        f.anonymising.set_active_id("yes")
        f.label_entry.set_text("clearnet")
        forms.append(f)
        f = self.gui.DumpForm(self.win, "other", "other-dump")
        f.sink_name.set_text("other-sink")
        forms.append(f)
        f = self.gui.MoveForm(self.win, self.node("qube:ai-osint-w1").data, self.win.records)
        f.target.set_active_id("other")
        f.confirm.set_active(True)
        forms.append(f)
        f = self.gui.RevokeForm(self.win, "ai-work")
        f.keep.set_active(True)
        forms.append(f)
        for kind in ("managed", "guarded"):
            f = self.gui.AddForm(self.win, rows, HUB, [])
            f.qube.set_active_id("personal")
            getattr(f, kind).set_active(True)
            forms.append(f)
        for argv in forms:
            self.one_line(argv)
            argvs.append(argv.argv())
            argv.destroy()
        for ident in ("manage", "guard", "remove_lead", "rotate"):
            self.select({"manage": "qube:ai-tpl-g", "guard": "qube:ai-work2",
                         "remove_lead": "project:p01", "rotate": "project:p01"}[ident])
            form = self.win.act(ident)
            self.one_line(form)
            argvs.append(form.argv())
            form.destroy()
        self.gateway_select("sys-ai-net")
        form = self.win.act("remove_gateway")
        argvs.append(form.argv())
        form.destroy()
        # A lead's firewall: the read when its project is selected, then each form.
        self.select("qube:ai-work2")
        self.runner.calls.clear()
        self.select("project:p01")
        argvs.append(self.runner.calls[-1])
        self.assertEqual(self.runner.calls[-1], gm.show_lead_firewall("osint"))
        for ident in ("set_model", "set_rules", "accept_rules"):
            form = self.win.act(ident)
            if ident == "set_model":
                form.model.set_text("api.anthropic.com:443")
            argvs.append(form.argv())
            form.destroy()
        self.select("project:p02")
        self.win.act("delete_project")
        argvs.append(self.runner.calls[-1])                     # the plan, a read
        argvs.append(self.win.last_form.argv())                 # the delete itself
        self.runner.calls.clear()
        self.propose("delete")                                  # it needs the second tick
        argvs.append(self.runner.calls[-1])                     # the show, a read
        self.win.proposal_tick.set_active(True)
        for ident in ("accept_proposal", "reject_proposal"):
            form = self.win.act(ident)
            argvs.append(form.argv())
            form.destroy()
        covered = set()
        for argv in argvs:
            covered |= covered_by(parser, argv)
        exempt = set(gm.CLI_ONLY) | set(gm.SHOWN_BY)
        missing = {k for k in cli_keys(parser) - covered if not any(k[:len(e)] == e for e in exempt)}
        self.assertEqual(missing, set(), "a form cannot make these")

    def test_keeping_the_old_lead_asks_for_a_new_name_first(self):
        # Checklist step 9, 2026-10-02: the form ran, and the command refused the
        # default name the kept lead still had. The form now says so before OK.
        self.select("project:p01")
        form = self.win.act("change_lead")
        form.source["template"].set_active(True)
        form.origin.set_active_id("ai-debian-13")
        form.old_lead.set_active_id("keep")
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn(f"keeps the name {LEAD}", form.error.get_text())
        form.lead_name.set_text("boss")
        self.assertTrue(form.ok.get_sensitive())
        form.source["promote"].set_active(True)               # a promoted lead keeps its own name
        form.origin.set_active_id("ai-work2")
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        self.submit(form)
        self.assertEqual(projects.find(projects.load(), "osint").lead, "ai-work2")
        self.assertIn("qmcp-proj-p01", self.tags(LEAD))         # kept as a worker

    def test_a_lead_name_is_typed_after_the_project_space(self):
        # From the operator's click-through: "newlead" was refused as a name
        # outside ai-t1-. The form shows the space and composes the name; a full
        # name pasted in is kept.
        form = self.win.act("new_project")
        self.assertEqual(form.lead_space.get_text(), "ai-<label>-")
        form.label_entry.set_text("newp")
        form.nets["none"].set_active(True)
        form.quota.set_text("5G")
        self.assertEqual(form.lead_space.get_text(), "ai-newp-")
        self.assertNotIn("--lead-name", form.argv())          # empty: the command's default
        for typed in ("boss", "ai-newp-boss", "  boss "):
            form.lead_name.set_text(typed)
            argv = form.argv()
            self.assertEqual(argv[argv.index("--lead-name") + 1], "ai-newp-boss", typed)
        for typed in ("new lead", "boss_1", "x" * 30):
            form.lead_name.set_text(typed)
            self.assertFalse(form.ok.get_sensitive(), typed)
            self.assertIn("lead name", form.error.get_text())
        form.lead_name.set_text("boss")
        self.submit(form)
        self.assertEqual(projects.find(projects.load(), "newp").lead, "ai-newp-boss")

    def test_the_old_lead_is_a_choice_with_no_default(self):
        # From the operator's click-through: a missed tick would remove the old
        # lead. Now nothing is preselected, and removal is spelled out in red.
        self.select("project:p01")
        form = self.win.act("change_lead")
        form.source["template"].set_active(True)
        form.origin.set_active_id("ai-debian-13")
        form.lead_name.set_text("boss")
        self.assertIsNone(form.old_lead.get_active_id())
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn(f"choose what happens to the old lead, {LEAD}", form.error.get_text())
        self.assertEqual(form.warning.get_text(), "")
        form.old_lead.set_active_id("remove")
        self.assertTrue(form.ok.get_sensitive())
        self.assertIn(f"{LEAD} will be removed, with everything in it", form.warning.get_text())
        self.assertTrue(form.warning.get_style_context().has_class("qmcp-FAILED"))
        self.assertNotIn("--keep-old", form.argv())
        form.old_lead.set_active_id("keep")
        self.assertEqual(form.warning.get_text(), "")
        self.assertIn("--keep-old", form.argv())

    def test_a_project_without_a_lead_asks_nothing_about_one(self):
        self.runner.execute(gm.remove_lead("osint"))
        self.win.refresh()
        self.select("project:p01")
        form = self.win.act("change_lead")
        self.assertIsNone(form.old_lead)
        form.lead_name.set_text("boss")
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        self.assertNotIn("--keep-old", form.argv())

    def test_removals_say_so_in_red_before_ok(self):
        self.select("project:p01")
        form = self.win.act("remove_lead")
        self.assertIn(f"{LEAD} will be removed, with everything in it", form.warning.get_text())
        form.destroy()
        self.select("project:p02")
        self.win.act("delete_project")
        self.assertIn("every member qube are removed", self.win.last_form.warning.get_text())

    def test_the_move_form_shows_whether_the_network_fits(self):
        # Checklist step 8, 2026-10-02: a qube on another network was refused only
        # after OK. The form now shows the qube's network beside the project's list.
        self.select("qube:ai-work")                              # on ai-net-router
        form = self.win.act("move")
        form.target.set_active_id("other")                      # other takes only none
        info = form.netinfo.get_text()
        self.assertIn("ai-work is on ai-net-router; other takes qubes on: none.", info)
        self.assertIn("will refuse it", info)
        form.target.set_active_id("osint")
        self.assertNotIn("refuse", form.netinfo.get_text())
        form.target.set_active_id("p00")
        self.assertIn("take any network", form.netinfo.get_text())

    def test_revoke_says_it_leaves_ai_space(self):
        self.select("qube:ai-work")
        form = self.win.act("revoke")
        intro = [c.get_text() for c in form.get_content_area().get_children()
                 if isinstance(c, Gtk.Label)][0]
        self.assertIn("out of AI space", intro)
        self.assertIn("not removed", intro)

    def test_the_audit_pane_says_whose_calls_it_shows(self):
        buf = self.win.audit_detail.get_buffer()
        text = lambda: buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)  # noqa: E731
        self.assertIn("Nothing on this log yet", text())
        self.assertIn("every command of yours that changes something", text())
        self.assertIn("(caller operator)", self.win.verify_label.get_text())
        self.assertNotIn("not on", self.win.verify_label.get_text() + text())
        # The operator's own commands are on the audit chain, as caller operator.
        self.select("qube:ai-tpl-g")
        self.submit(self.win.act("manage"))
        newest = self.rows(self.win.audit_store)[0]
        self.assertEqual((newest[3], newest[4]), ("operator", "qmcp manage"))
        self.submit(self.win.act("rotate"))
        self.assertIn("This log starts at a rotation", text())
        self.assertIn("--path /var/log/", text())
        self.assertEqual(self.rows(self.win.audit_store)[0][3], "operator")

    def test_a_failed_refresh_keeps_the_whole_previous_view(self):
        # From the M2b release gate: after one good read, a failed project read
        # judged the fresh fleet against old records. Now a refresh is whole.
        before = [r[0] for r in self.rows(self.win.store)]
        self.runner.execute(gm.create_project("late", "template", "ai-debian-13",
                                              networks=["none"], quota="1G"))
        self.runner.fail.add(tuple(gm.READS["projects"]))
        self.win.refresh()
        self.assertEqual([r[0] for r in self.rows(self.win.store)], before)
        self.assertNotIn("qube:ai-late-lead", self.win.nodes)
        self.assertIn("Showing the qubes and records read at", self.win.status.get_text())
        self.runner.fail.clear()
        self.win.refresh()
        self.assertIn("qube:ai-late-lead", self.win.nodes)
        self.assertEqual(self.win.nodes["qube:ai-late-lead"].data["role"], "lead")

    def test_an_unreadable_audit_log_is_a_failed_read_not_an_empty_one(self):
        log = pathlib.Path(audit.LOG_PATH)
        log.write_text('{"seq": 1}\n')
        os.chmod(log, 0)
        self.addCleanup(os.chmod, log, 0o600)
        if os.access(log, os.R_OK):
            self.skipTest("running as root: permissions do not bind")
        result = self.read("audit", "tail", "5")
        self.assertEqual(result.rc, 1)
        self.assertIn("cannot read the log", result.err)
        self.win.refresh()
        self.assertFalse(self.win.complete)
        self.assertEqual(self.sensitive(), set())

    def test_the_delete_plan_is_a_read_with_a_time_limit(self):
        self.select("project:p02")
        self.runner.timeouts.clear()
        self.runner.calls.clear()
        self.win.act("delete_project")
        plan = [t for c, t in zip(self.runner.calls, self.runner.timeouts) if c == gm.delete_plan("other")]
        self.assertEqual(plan, [self.gui.READ_TIMEOUT_S])

    def test_verify(self):
        self.win.verify()
        self.assertTrue(self.win.verify_label.get_text().startswith("chain OK"))
        pathlib.Path(audit.LOG_PATH).write_text('{"seq": 1, "hash": "x"}\n')
        self.win.verify()
        self.assertIn("BROKEN", self.win.verify_label.get_text())

    # ------------------------------------------------------------------ proposals

    def test_a_proposal_from_the_hub_to_the_fleet(self):
        self.assertEqual(self.win.proposals_tab.get_text(), "Proposals (0)")
        self.assertEqual(self.win.proposal_note.get_text(), "No proposals from the hub.")
        reply = self.submit_proposal("create")
        self.win.refresh()
        self.assertEqual(self.win.proposals_tab.get_text(), "Proposals (1)")
        row = self.rows(self.win.proposal_store)[0]
        self.assertEqual(row[:6], [str(reply["id"]), str(reply["id"]), "pending", "project-create",
                                   "newp", "new project <b>newp</b>"])
        self.assertEqual(self.deciding(), set())                 # nothing selected
        self.runner.calls.clear()
        self.select_proposal(reply["id"])
        self.assertEqual(self.runner.calls, [gm.show_proposal(reply["id"])])   # a read, as you
        pane = self.pane()
        self.assertEqual(pane["Title (written by AI)"], "new project <b>newp</b>")
        self.assertEqual(pane["Fingerprint (sha256)"], reply["sha256"])
        self.assertEqual(pane["Equivalent command"], "qmcp project create newp --lead-template "
                                                     "ai-debian-13 --network ai-net-router --quota 5G")
        self.assertFalse(self.win.proposal_tick.get_visible())   # one click is enough
        self.assertEqual(self.win.proposal_warning.get_text(), "")
        self.assertEqual(self.deciding(), {"accept_proposal", "reject_proposal"})
        form = self.win.act("accept_proposal")
        argv = form.argv()
        self.assertEqual(argv, gm.accept_proposal(reply["id"], pane["Fingerprint (sha256)"]))
        self.assertEqual(form.preview.get_text(), gm.shown(argv))
        # Replies held, as a real runner delivers them: from the moment the
        # accept runs until the proposal is read again, nothing may be decided
        # from the show taken before it.
        self.runner.hold = True
        form.response(Gtk.ResponseType.OK)
        self.assertEqual([c for c, _ in self.runner.held], [argv])           # what was shown runs
        self.assertEqual(self.deciding(), set())
        self.runner.release()                                     # it ran; a refresh starts
        answered = 0
        while self.runner.held:
            self.assertEqual(self.deciding(), set(), f"after {answered} replies")
            self.runner.release()
            answered += 1
        self.runner.hold = False
        self.assertEqual(answered, len(gm.READS) + 1)             # the reads, then the re-show
        title, result = self.reports[-1]
        self.assertEqual((title, result.argv, result.rc), (f"Accept proposal {reply['id']}", argv, 0))
        self.assertEqual(argv[:2], list(gm.SUDO))
        self.assertIn(f"proposal {reply['id']}: accepted", result.out)
        p = projects.find(projects.load(), "newp")
        self.assertEqual((p.lead, p.networks, p.quota), ("ai-newp-lead", ("ai-net-router",), 5 * GiB))
        self.assertIn(f"project:{p.slot}", [r[0] for r in self.rows(self.win.store)])   # refreshed
        self.assertEqual(self.win.proposals_tab.get_text(), "Proposals (0)")
        pane = self.pane()                                        # read again after the change
        self.assertEqual(pane["Decision"], "accepted")
        self.assertIn("p03: lead ai-newp-lead (created)", pane["Report"])
        self.assertEqual(self.deciding(), set())                 # closed: nothing to do
        calls = {(r.get("caller"), r.get("service")) for r in self.win.audit_rows}
        self.assertLessEqual({(HUB, "qmcp.SubmitProposal"), ("operator", "qmcp proposal accept")},
                             calls)

    def test_accept_is_off_until_the_tick_when_reasons_exist(self):
        reply = self.propose("delete", project="other")
        self.assertTrue(self.win.proposal_tick.get_visible())
        self.assertFalse(self.win.proposal_tick.get_active())
        warning = self.win.proposal_warning.get_text()
        self.assertIn("- deletes the project other", warning)
        self.assertTrue(self.win.proposal_warning.get_style_context().has_class("qmcp-FAILED"))
        self.assertIn("this removes p02 'other'", self.pane()["Plan"])
        self.assertEqual(self.deciding(), {"reject_proposal"})
        self.assertIsNone(self.win.act("accept_proposal"))       # no form without the tick
        self.win.proposal_tick.set_active(True)
        self.assertEqual(self.deciding(), {"accept_proposal", "reject_proposal"})
        # The tick sent is the digest the show on display gave, exactly.
        tick = self.pane()["Second tick digest"]
        self.assertEqual(tick, self.win.pane.doc["tick"])
        self.assertEqual(tick, self.show(reply["id"])["tick"])
        form = self.win.act("accept_proposal")
        argv = form.argv()
        self.assertEqual(argv, gm.accept_proposal(reply["id"], reply["sha256"], tick))
        self.assertEqual(argv[-2:], ["--yes", tick])
        self.assertEqual(form.warning.get_text(), warning)       # the reasons again, in red
        self.assertTrue(form.warning.get_style_context().has_class("qmcp-FAILED"))
        self.runner.calls.clear()
        result = self.submit(form)
        self.assertEqual((self.runner.calls[0], result.argv), (argv, argv))   # as shown, it ran
        self.assertIsNone(projects.find(projects.load(), "other"))
        self.assertNotIn(OTHER_LEAD, self.app.domains)
        self.assertFalse(self.win.proposal_tick.get_visible())   # closed: no tick, no buttons
        self.assertEqual(self.deciding(), set())

    def test_the_tick_answers_one_proposal_only(self):
        first = self.propose("delete", project="other")
        self.win.proposal_tick.set_active(True)
        self.win.refresh()                                       # the same reasons, read again
        self.assertEqual(self.win.pane.pid, first["id"])
        self.assertTrue(self.win.proposal_tick.get_active())
        second = self.propose("delete")
        self.assertNotEqual(second["id"], first["id"])
        self.assertFalse(self.win.proposal_tick.get_active())
        self.assertEqual(self.deciding(), {"reject_proposal"})
        self.select_proposal(first["id"])
        self.assertFalse(self.win.proposal_tick.get_active())   # never carried back either

    def test_a_proposal_changed_after_it_was_read_is_refused(self):
        # What the operator read is what runs: the form carries the fingerprint
        # of the show on display, and the command refuses a stored file that no
        # longer hashes to it. Nothing runs, the proposal stays pending, and the
        # refresh after the report reads it again.
        reply = self.propose("create")
        form = self.win.act("accept_proposal")
        path = pathlib.Path(proposals.PROPOSALS_DIR) / f"{reply['id']:06d}.json"
        record = json.loads(path.read_text())
        record["proposal"]["networks"] = ["none"]               # still a proposal dom0 could store
        path.write_bytes(proposals.canonical(record))
        result = self.submit(form, ok=False)
        self.assertIn("its fingerprint differs", result.err)
        self.assertIn(reply["sha256"], result.argv)
        self.assertIsNone(projects.find(projects.load(), "newp"))
        self.assertEqual(self.win.pane.doc["state"], "pending")
        self.assertNotEqual(self.pane()["Fingerprint (sha256)"], reply["sha256"])
        self.assertIn("--network none", self.pane()["Equivalent command"])

    def release_all(self, check=None):
        """Answer every held command in order, `check()` before each; returns
        how many there were."""
        n = 0
        while self.runner.held:
            if check is not None:
                check(n)
            self.runner.release()
            n += 1
        return n

    def change_others_lead_on_the_qubes_tab(self):
        """A new lead for other, the old one kept as a worker: the change form."""
        self.select("project:p02")
        form = self.win.act("change_lead")
        form.source["clone"].set_active(True)
        form.origin.set_active_id("ai-work2")
        form.lead_name.set_text("l2")
        form.old_lead.set_active_id("keep")
        return form

    def test_after_a_change_no_proposal_button_is_on_until_the_re_show(self):
        # The second review's reproduction, replies held as a real runner holds
        # them. A lead proposal for other, ticked for the reason "removes the
        # old lead ai-other-lead"; then other's lead is changed to ai-other-l2
        # on the Qubes tab. Accept from the old show and tick would have sent
        # --yes and removed ai-other-l2.
        reply = self.propose("lead", keep_old=False)
        self.assertIn("removes the old lead ai-other-lead", self.win.proposal_warning.get_text())
        self.win.proposal_tick.set_active(True)
        self.assertEqual(self.deciding(), {"accept_proposal", "reject_proposal"})
        old = self.win.pane.doc
        form = self.change_others_lead_on_the_qubes_tab()
        self.runner.hold = True
        form.response(Gtk.ResponseType.OK)                       # the change runs, held
        self.assertEqual(self.deciding(), set())

        def off(n):
            self.assertEqual(self.deciding(), set(), f"after {n} replies")
            self.assertIsNone(self.win.act("accept_proposal"), f"after {n} replies")
        # The change, the reads of the refresh it starts, then the lead
        # firewall of the project selected on the Qubes tab, and the re-show.
        self.assertEqual(self.release_all(off), 1 + len(gm.READS) + 1 + 1)
        self.runner.hold = False
        self.assertEqual(projects.find(projects.load(), "other").lead, "ai-other-l2")
        self.assertIn("removes the old lead ai-other-l2", self.win.proposal_warning.get_text())
        self.assertNotEqual(self.win.pane.doc["tick"], old["tick"])
        self.assertFalse(self.win.proposal_tick.get_active())   # the old tick does not carry over
        self.assertEqual(self.deciding(), {"reject_proposal"})
        self.assertIn("ai-other-l2", self.app.domains)
        self.assertEqual(self.show(reply["id"])["state"], "pending")

    def test_an_open_form_runs_nothing_once_its_proposal_reads_differently(self):
        reply = self.propose("lead", keep_old=False)
        self.win.proposal_tick.set_active(True)
        form = self.win.act("accept_proposal")                   # opened on the old reasons
        self.assertEqual(form.argv()[-2], "--yes")
        # A refresh starts with the form open. While it reads, OK refuses...
        self.runner.hold = True
        self.win.refresh()
        writes = lambda: [c for c in self.runner.calls if c[:2] == list(gm.SUDO)]  # noqa: E731
        before = writes()
        form.response(Gtk.ResponseType.OK)
        self.assertIn("the proposal changed since this form opened", form.error.get_text())
        self.assertFalse(form.ok.get_sensitive())
        # ...and once the lead has changed under it, from a dom0 terminal, the
        # re-show reads other reasons: OK still runs nothing.
        self.assertEqual(self.runner.execute(gm.change_lead("other", "clone", "ai-work2",
                                                            "ai-other-l2", None, True)).rc, 0)
        self.release_all()
        self.runner.hold = False
        self.assertIn("removes the old lead ai-other-l2", self.win.proposal_warning.get_text())
        form.response(Gtk.ResponseType.OK)
        # Ticked again, for the new reasons: the form still carries the old
        # digest, so it still runs nothing.
        self.win.proposal_tick.set_active(True)
        self.assertEqual(self.deciding(), {"accept_proposal", "reject_proposal"})
        form.response(Gtk.ResponseType.OK)
        self.assertEqual(writes(), before)                       # nothing ran
        self.assertIn("the proposal changed since this form opened", form.error.get_text())
        self.assertIn("ai-other-l2", self.app.domains)
        self.assertEqual(self.show(reply["id"])["state"], "pending")

    def test_an_open_form_runs_nothing_once_its_show_fails(self):
        reply = self.propose("create")
        form = self.win.act("accept_proposal")
        self.runner.hold = True
        self.runner.fail.add(tuple(gm.show_proposal(reply["id"])))
        self.win.refresh()
        self.release_all()                                       # the reads; the re-show fails
        self.runner.hold = False
        self.assertIn(f"Could not read proposal {reply['id']}", self.win.proposal_note.get_text())
        self.assertEqual(self.deciding(), set())
        self.runner.calls.clear()
        form.response(Gtk.ResponseType.OK)
        self.assertEqual(self.runner.calls, [])                  # nothing ran
        self.assertIn("the proposal changed since this form opened", form.error.get_text())
        self.assertIsNone(projects.find(projects.load(), "newp"))
        self.assertEqual(self.show(reply["id"])["state"], "pending")

    def test_an_open_form_still_runs_when_its_proposal_reads_the_same(self):
        # The control for the two tests above: a refresh that reads the same
        # proposal, fingerprint and second tick leaves the form able to run.
        reply = self.propose("delete", project="other")
        self.win.proposal_tick.set_active(True)
        form = self.win.act("accept_proposal")
        self.runner.hold = True
        self.win.refresh()
        self.release_all()
        self.runner.hold = False
        self.assertTrue(self.win.proposal_tick.get_active())
        tick = self.win.pane.doc["tick"]
        self.assertTrue(tick)
        result = self.submit(form)
        self.assertEqual(result.argv, gm.accept_proposal(reply["id"], reply["sha256"], tick))
        self.assertIsNone(projects.find(projects.load(), "other"))

    def test_reject_runs_nothing(self):
        reply = self.propose("create")
        form = self.win.act("reject_proposal")
        self.assertEqual(form.argv(), gm.reject_proposal(reply["id"]))
        intro = [c.get_text() for c in form.get_content_area().get_children()
                 if isinstance(c, Gtk.Label)][0]
        self.assertIn("without running anything", intro)
        self.assertEqual(form.warning.get_text(), "")
        result = self.submit(form)
        self.assertEqual(result.out, f"proposal {reply['id']}: rejected\n")
        self.assertIsNone(projects.find(projects.load(), "newp"))
        self.assertEqual((self.pane()["Decision"], self.pane()["Report"]), ("rejected", "-"))
        self.assertEqual(self.deciding(), set())

    def test_one_proposal_command_at_a_time(self):
        first = self.submit_proposal("create")
        second = self.submit_proposal("dump")
        self.win.refresh()
        self.select_proposal(first["id"])
        form = self.win.act("accept_proposal")
        other = self.win.act("reject_proposal")                  # opened before the accept runs
        self.addCleanup(other.destroy)
        self.runner.hold = True
        form.response(Gtk.ResponseType.OK)
        self.assertTrue(self.win.busy)
        self.assertEqual((self.deciding(), self.sensitive()), (set(), set()))
        self.assertFalse(self.win.write("t", gm.reject_proposal(second["id"])))
        self.assertIsNone(self.win.act("reject_proposal"))       # no form opens while one runs
        other.response(Gtk.ResponseType.OK)                      # and one already open refuses
        self.assertIn("another command is running", other.error.get_text())
        self.runner.hold = False
        self.runner.release()
        self.assertFalse(self.win.busy)
        self.assertEqual([title for title, _ in self.reports], [f"Accept proposal {first['id']}"])
        self.assertEqual(self.show(second["id"])["state"], "pending")

    def test_a_failed_list_read_turns_proposal_changes_off(self):
        reply = self.propose("create")
        self.assertEqual(self.deciding(), {"accept_proposal", "reject_proposal"})
        self.runner.fail.add(tuple(gm.READS["proposals"]))
        self.win.refresh()
        self.assertEqual(self.deciding(), set())
        self.assertEqual([r[0] for r in self.rows(self.win.proposal_store)], [str(reply["id"])])
        self.assertEqual(self.win.proposals_tab.get_text(), "Proposals (1)")   # the last good list
        self.assertIn("Changes are off", self.win.status.get_text())
        self.assertEqual(self.sensitive(), set())
        self.runner.fail.clear()
        self.win.refresh()
        self.assertEqual(self.deciding(), {"accept_proposal", "reject_proposal"})

    def test_a_failed_show_keeps_the_pane_and_turns_its_buttons_off(self):
        reply = self.propose("create")
        before = self.pane()
        self.runner.fail.add(tuple(gm.show_proposal(reply["id"])))
        self.win.refresh()
        self.assertEqual(self.pane(), before)                    # the last good view of it
        note = self.win.proposal_note.get_text()
        self.assertIn(f"Could not read proposal {reply['id']}", note)
        self.assertIn("Showing it as read at", note)
        self.assertEqual(self.deciding(), set())
        self.assertIn("new_project", self.sensitive())           # the rest of the window is current
        self.runner.fail.clear()
        self.win.refresh()
        self.assertEqual(self.deciding(), {"accept_proposal", "reject_proposal"})

    def test_proposals_never_read_count_nothing(self):
        runner = CliRunner(self.app)
        runner.fail.add(tuple(gm.READS["proposals"]))
        win = self.gui.Window(runner=runner, show_forms=False, report=lambda *a: None)
        self.addCleanup(win.destroy)
        win.refresh()
        self.assertEqual(win.proposals_tab.get_text(), "Proposals (?)")
        self.assertEqual(win.proposal_note.get_text(), "The proposals have not been read.")
        self.assertFalse(any(b.get_sensitive() for b in win.buttons.values()))

    def test_every_cell_of_a_proposal_is_escaped(self):
        title = '<b>bold</b> &amp; "q" <span foreground="red">x</span>'
        reply = self.propose("create", title=title)
        row = self.rows(self.win.proposal_store)[0]
        self.assertEqual(row[5], json.dumps(title)[1:-1])
        self.assertIn("<b>bold</b>", row[5])                     # as text: no markup on screen
        self.assertEqual(self.pane()["Title (written by AI)"], row[5])
        for text in row[1:] + list(self.pane().values()) + [self.win.proposal_note.get_text()]:
            self.assertTrue(text.isascii() and chr(10) not in text, text)
        self.assertEqual(self.win.pane.doc["title"], title)
        self.assertEqual(reply["id"], self.win.pane.pid)

    def test_a_decided_proposal_offers_nothing(self):
        reply = self.submit_proposal("create")
        self.assertEqual(self.runner.execute(gm.reject_proposal(reply["id"])).rc, 0)
        self.win.refresh()
        self.select_proposal(reply["id"])
        self.assertEqual(self.pane()["State"], "rejected")
        self.assertNotIn("Needs closing", self.pane())
        self.assertEqual(self.deciding(), set())
        for ident in self.win.proposal_buttons:
            self.assertIsNone(self.win.act(ident), ident)
        self.assertFalse(self.win.proposal_tick.get_visible())

    def test_a_proposal_that_needs_closing_gets_close(self):
        # A decision file that does not read: the command says the proposal
        # needs closing, `qmcp check` warns, and the window offers Close, which
        # runs reject. Afterwards the tab shows it closed, and the warning is gone.
        reply = self.submit_proposal("create")
        self.assertEqual(self.runner.execute(gm.reject_proposal(reply["id"])).rc, 0)
        store = pathlib.Path(proposals.PROPOSALS_DIR)
        (store / f"{reply['id']:06d}.decision").write_text("garbage")
        self.win.refresh()
        checks = lambda: {r[2]: r[1] for r in self.rows(self.win.check_store)}  # noqa: E731
        self.assertEqual(checks()["proposal store"], "WARN")
        self.assertEqual(self.rows(self.win.proposal_store)[0][2], "failed, needs closing")
        self.select_proposal(reply["id"])
        pane = self.pane()
        self.assertIn("decision file unreadable", pane["Problem"])
        self.assertIn("Close records it as failed", pane["Needs closing"])
        self.assertEqual(self.deciding(), {"close_proposal"})
        self.assertFalse(self.win.proposal_tick.get_visible())
        self.assertIsNone(self.win.act("reject_proposal"))       # Close, named for what it does
        form = self.win.act("close_proposal")
        self.assertEqual(form.get_title(), f"Close proposal {reply['id']}")
        self.assertEqual(form.argv(), gm.reject_proposal(reply["id"]))
        intro = [c.get_text() for c in form.get_content_area().get_children()
                 if isinstance(c, Gtk.Label)][0]
        self.assertIn("Why: decision file unreadable", intro)
        self.assertIn("records the proposal as failed", intro)
        result = self.submit(form)
        self.assertEqual(result.out, f"proposal {reply['id']}: failed\n")
        self.assertEqual(self.rows(self.win.proposal_store)[0][2], "failed")
        pane = self.pane()
        self.assertNotIn("Needs closing", pane)
        self.assertEqual(pane["Decision"], "failed")
        self.assertIn("did not read; closed by the operator", pane["Report"])
        self.assertEqual(self.deciding(), set())
        self.assertEqual(checks()["proposal store"], "PASS")
        self.assertEqual((store / f"{reply['id']:06d}.decision.unreadable").read_text(), "garbage")

    # ------------------------------------------------------------------ gateways and lead firewalls

    def text(self, view):
        buf = view.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)

    def test_the_gateways_tab(self):
        self.routers()
        self.win.refresh()
        rows = self.rows(self.win.gateway_store)
        self.assertEqual([r[0] for r in rows], ["ai-net-router"])
        self.assertEqual(rows[0][1:], gm.gateway_cells(self.gateways()[0]))
        self.assertEqual(self.registry(), {"enroll_gateway"})              # nothing selected
        self.gateway_select("ai-net-router")
        self.assertEqual(self.registry(), {"enroll_gateway", "change_gateway", "remove_gateway"})
        pane = self.grid(self.win.gateway_details)
        self.assertEqual(list(pane), [h for _, h in gm.GATEWAY_FIELDS])
        self.assertEqual(pane["Problem"], "none: AI space may use it")
        self.assertEqual(self.grid(self.win.settings_grid)["Gateways enrolled"], "1")
        # Enroll: the form offers every qube that provides network and is not
        # enrolled, and refuses what the command would, where it can see why.
        form = self.win.act("enroll_gateway")
        self.assertIsNone(form.qube.get_active_id())
        self.assertFalse(form.ok.get_sensitive())
        self.assertNotIn("ai-net-router", [row[1] for row in form.qube.get_model()])
        form.qube.set_active_id("ai-gw-unbadged")
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn("is in AI space without qmcp-guarded", form.error.get_text())
        form.qube.set_active_id("sys-ai-tor")
        form.anonymising.set_active(True)
        form.label_entry.set_text("Tor, CH")
        self.assertEqual(form.argv(), gm.enroll_gateway("sys-ai-tor", True, "Tor, CH"))
        self.submit(form)
        self.assertEqual(gateways.load()["sys-ai-tor"].label, "Tor, CH")
        self.assertEqual([r[0] for r in self.rows(self.win.gateway_store)], ["ai-net-router", "sys-ai-tor"])
        self.assertEqual(self.grid(self.win.settings_grid)["Gateways enrolled"], "2")
        # A router behind a Whonix gateway is marked on its row and beside its fields.
        tor = next(r for r in self.rows(self.win.gateway_store) if r[0] == "sys-ai-tor")
        self.assertEqual(tor[-1], MARK)
        self.gateway_select("sys-ai-tor")
        self.assertEqual(self.win.gateway_warning.get_text(), MARK)
        self.assertTrue(self.win.gateway_warning.get_style_context().has_class("qmcp-note"))
        self.assertTrue(self.grid(self.win.gateway_details)["Its upstream ignores its firewall rules"]
                        .startswith("yes: " + MARK))
        # Change: only what changed is sent.
        form = self.win.act("change_gateway")
        self.assertFalse(form.ok.get_sensitive())
        self.assertEqual(form.error.get_text(), "nothing changed")
        form.anonymising.set_active_id("no")
        self.assertEqual(form.argv(), gm.change_gateway("sys-ai-tor", anonymising=False))
        form.label_entry.set_text("Tor")
        self.submit(form)
        g = gateways.load()["sys-ai-tor"]
        self.assertEqual((g.anonymising, g.label), (False, "Tor"))
        # Remove: the form refuses one still in use, in the command's words; it
        # removes authority, never a qube, so no red line.
        self.gateway_select("ai-net-router")
        form = self.win.act("remove_gateway")
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn("'ai-net-router' is in use: projects ['osint']", form.error.get_text())
        self.assertEqual(form.warning.get_text(), "")
        form.destroy()
        self.gateway_select("sys-ai-tor")
        result = self.submit(self.win.act("remove_gateway"))
        self.assertEqual(result.argv, gm.remove_gateway("sys-ai-tor"))
        self.assertNotIn("sys-ai-tor", gateways.load())
        self.assertEqual([r[0] for r in self.rows(self.win.gateway_store)], ["ai-net-router"])
        self.assertIsNone(self.win.gateway_selected)
        self.assertEqual(self.registry(), {"enroll_gateway"})
        for row in self.rows(self.win.gateway_store):
            for cell in row[1:]:
                self.assertTrue(cell.isascii() and "\n" not in cell, cell)

    def test_a_failed_registry_read_turns_changes_off(self):
        self.assertIsNone(self.win.act("change_gateway"))       # nothing selected: no form
        self.assertIsNone(self.win.act("remove_gateway"))
        self.gateway_select("ai-net-router")
        pathlib.Path(gateways.GATEWAYS_PATH).write_text("{")
        self.win.refresh()
        self.assertFalse(self.win.complete)
        self.assertIn("gateway list --json failed", self.win.status.get_text())
        self.assertEqual((self.sensitive(), self.registry()), (set(), set()))
        self.assertEqual([r[0] for r in self.rows(self.win.gateway_store)], ["ai-net-router"])  # last good
        for ident in ("enroll_gateway", "change_gateway", "remove_gateway"):
            self.assertIsNone(self.win.act(ident), ident)       # no form opens while changes are off

    def test_the_edit_form_refuses_a_network_that_is_not_enrolled(self):
        # Listed before the registry existed (an upgrade), or removed from it since.
        self.routers()
        doc = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        doc["slots"]["p02"]["networks"] = [None, "sys-ai-net"]
        self.write_records(doc)
        self.win.refresh()
        self.select("project:p02")
        form = self.win.act("edit_project")
        self.assertEqual(form.nets["sys-ai-net"].get_label(), "sys-ai-net (not enrolled)")
        form.quota.set_text("11G")
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())   # networks unchanged
        form.default_net.set_active_id("sys-ai-net")
        self.assertFalse(form.ok.get_sensitive())
        why = "'sys-ai-net' is not an enrolled gateway (qmcp gateway enroll sys-ai-net)"
        self.assertEqual(form.error.get_text(), why)
        result = self.runner.execute(gm.edit_project("other", networks=["sys-ai-net", "none"]))
        self.assertEqual(result.rc, 1)
        self.assertIn(why, result.err)                          # the command's refusal
        form.nets["sys-ai-net"].set_active(False)               # off the list: no worker is on it
        self.assertEqual(form.argv(), gm.edit_project("other", networks=["none"], quota="11G"))
        self.submit(form)
        self.assertEqual(projects.find(projects.load(), "other").networks, (None,))

    def test_a_refusal_takes_the_commands_line_never_one_below_it(self):
        # The 0.9.21 click-through: ticking a gateway that no longer qualifies
        # emptied the line under "Runs:" and put the reason one line lower, in
        # the command's own style, where it reads as the command.
        self.routers()
        self.assertEqual(self.runner.execute(gm.enroll_gateway("sys-ai-net")).rc, 0)
        self.app.domains["debian-13"].features.pop("qubes-firewall")
        self.win.refresh()
        form = self.win.act("new_project")
        self.one_line(form, ok=False)                           # empty: no label yet
        form.label_entry.set_text("newp")
        form.quota.set_text("1G")
        form.nets["none"].set_active(True)
        self.one_line(form)
        command = form.preview.get_text()
        self.assertTrue(command.startswith("/usr/bin/sudo -n "), command)
        form.nets["sys-ai-net"].set_active(True)
        self.one_line(form, ok=False)
        self.assertTrue(form.error.get_text().startswith("'sys-ai-net' is enrolled but not usable: "))
        self.assertEqual(form.preview.get_text(), "")           # no command left behind
        form.nets["sys-ai-net"].set_active(False)
        self.one_line(form)
        self.assertEqual((form.preview.get_text(), form.error.get_text()), (command, ""))
        form.destroy()

    def test_the_forms_refuse_a_gateway_that_no_longer_qualifies(self):
        # Enrolled and on other's list while it qualified; then its template
        # lost Qubes' firewall marker.
        self.routers()
        self.assertEqual(self.runner.execute(gm.enroll_gateway("sys-ai-net")).rc, 0)
        self.assertEqual(self.runner.execute(gm.edit_project("other", networks=["none",
                                                                                "sys-ai-net"])).rc, 0)
        self.app.domains["debian-13"].features.pop("qubes-firewall")
        self.win.refresh()
        problem = next(r for r in self.win.gateways if r["name"] == "sys-ai-net")["problem"]
        why = f"'sys-ai-net' is enrolled but not usable: {problem}"
        # A new project: as a worker network, or as the lead's.
        form = self.win.act("new_project")
        form.label_entry.set_text("newp")
        form.quota.set_text("1G")
        form.nets["none"].set_active(True)
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        self.assertTrue(form.nets["sys-ai-net"].get_label().startswith("sys-ai-net (NOT USABLE: "))
        form.nets["sys-ai-net"].set_active(True)
        self.assertFalse(form.ok.get_sensitive())
        self.assertEqual(form.error.get_text(), why)
        form.nets["sys-ai-net"].set_active(False)
        form.lead_netvm.set_active_id("sys-ai-net")
        form.model.set_text("api.anthropic.com:443")
        self.assertFalse(form.ok.get_sensitive())
        self.assertEqual(form.error.get_text(), why)
        form.destroy()
        # Editing other: the quota alone changes, the list keeping it does not,
        # and taking it off the list does.
        self.select("project:p02")
        form = self.win.act("edit_project")
        form.quota.set_text("11G")
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        form.default_net.set_active_id("sys-ai-net")
        self.assertFalse(form.ok.get_sensitive())
        self.assertEqual(form.error.get_text(), why)
        form.nets["sys-ai-net"].set_active(False)
        self.assertEqual(form.argv(), gm.edit_project("other", networks=["none"], quota="11G"))
        self.submit(form)
        self.assertEqual(projects.find(projects.load(), "other").networks, (None,))
        # A new lead on it, from the change-lead form.
        self.select("project:p02")
        form = self.win.act("change_lead")
        form.lead_name.set_text("l2")
        form.old_lead.set_active_id("keep")
        form.lead_netvm.set_active_id("sys-ai-net")
        form.model.set_text("api.anthropic.com:443")
        self.assertFalse(form.ok.get_sensitive())
        self.assertEqual(form.error.get_text(), why)
        form.destroy()

    def test_the_project_forms_offer_the_enrolled_gateways_marked(self):
        self.routers()
        self.enroll("sys-firewall")          # by hand: no qubes-firewall marker, so not usable
        self.win.refresh()
        form = self.win.act("new_project")
        self.assertEqual(list(form.nets), ["none", "ai-net-router", "sys-firewall"])
        labels = {n: cb.get_label() for n, cb in form.nets.items()}
        self.assertEqual(labels["ai-net-router"], "ai-net-router")
        self.assertTrue(labels["sys-firewall"].startswith("sys-firewall (NOT USABLE: "))
        self.assertEqual([row[1] for row in form.lead_netvm.get_model()],
                         ["", "none", "ai-net-router", "sys-firewall"])
        form.destroy()
        self.select("project:p01")
        form = self.win.act("edit_project")
        self.assertEqual(set(form.nets), {"none", "ai-net-router", "sys-firewall"})
        form.destroy()

    def test_a_lead_with_a_network_needs_its_model(self):
        form = self.win.act("new_project")
        form.label_entry.set_text("newp")
        form.nets["none"].set_active(True)
        form.quota.set_text("5G")
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())    # no network, no model
        self.assertIn("will have no network", form.lead_info.get_text())
        form.model.set_text("api.anthropic.com:443")
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn("reaches no model endpoint", form.error.get_text())
        form.lead_netvm.set_active_id("ai-net-router")
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        self.assertIn("will be on ai-net-router", form.lead_info.get_text())
        form.model.set_text("")
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn("needs its model endpoint", form.error.get_text())
        form.model.set_text("api.anthropic.com:443")
        self.assertEqual(form.argv(), gm.create_project(
            "newp", "template", "ai-debian-13", None, "ai-net-router", [], ["none"], "5G", False,
            "api.anthropic.com:443"))
        self.submit(form)
        p = projects.find(projects.load(), "newp")
        endpoint = [_qubesd_rule(r) for r in firewall.endpoint_rules("api.anthropic.com:443")]
        self.assertEqual((p.model, list(p.lead_firewall)), ("api.anthropic.com:443", endpoint))
        # Its details show the model and the rules you accepted; the view
        # beside them reads the live ones: the same.
        self.select(f"project:{p.slot}")
        details = self.grid(self.win.details)
        self.assertEqual(details["Lead's model endpoint"], "api.anthropic.com:443")
        self.assertEqual(details["Lead firewall you accepted"], chr(10).join(endpoint))
        self.assertTrue(details["Lead firewall"].startswith("read at "), details["Lead firewall"])
        self.assertEqual(details["Rules it has now (live)"], chr(10).join(endpoint))
        self.assertEqual(details["Live rules are the ones you accepted"], "yes")
        self.assertLessEqual({"set_model", "set_rules"}, self.sensitive())
        self.assertNotIn("accept_rules", self.sensitive())
        # A promoted lead keeps its network, so it needs a model too.
        form = self.win.act("new_project")
        form.label_entry.set_text("prom")
        form.source["promote"].set_active(True)
        form.origin.set_active_id("ai-hubq")
        form.nets["none"].set_active(True)
        form.quota.set_text("1G")
        self.assertIn("needs its model endpoint", form.error.get_text())
        self.assertIn("will be on ai-net-router", form.lead_info.get_text())
        form.destroy()

    def test_the_lead_form_says_what_happens_to_the_old_leads_network(self):
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["ai-net-router"]   # other lists none only
        self.win.refresh()
        self.select("project:p02")
        form = self.win.act("change_lead")
        form.source["clone"].set_active(True)
        form.origin.set_active_id("ai-work2")
        form.lead_name.set_text("l2")
        self.assertFalse(form.add_old.get_sensitive())                 # nothing chosen yet
        form.old_lead.set_active_id("keep")
        self.assertTrue(form.add_old.get_sensitive())
        self.assertIn("without the tick it goes to no network", form.old_info.get_text())
        self.assertNotIn("--add-old-network", form.argv())
        form.add_old.set_active(True)
        self.assertIn("the tick adds ai-net-router to the worker networks", form.old_info.get_text())
        self.assertIn("--add-old-network", form.argv())
        form.old_lead.set_active_id("remove")                          # the tick goes with keep only
        self.assertFalse(form.add_old.get_active())
        self.assertFalse(form.add_old.get_sensitive())
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        self.assertNotIn("--add-old-network", form.argv())
        form.old_lead.set_active_id("keep")
        form.add_old.set_active(True)
        # A network for the new lead, and other has no model on record.
        form.lead_netvm.set_active_id("ai-net-router")
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn("needs its model endpoint", form.error.get_text())
        self.assertIn("The project has no model on record", form.lead_info.get_text())
        form.model.set_text("api.anthropic.com:443")
        self.assertEqual(form.argv(), gm.change_lead("other", "clone", "ai-work2", "ai-other-l2",
                                                     "ai-net-router", True, "api.anthropic.com:443",
                                                     True))
        self.submit(form)
        p = projects.find(projects.load(), "other")
        self.assertEqual((p.lead, p.networks, p.model),
                         ("ai-other-l2", (None, "ai-net-router"), "api.anthropic.com:443"))
        self.assertEqual(self.app.domains[OTHER_LEAD].netvm.name, "ai-net-router")   # it kept it

    def test_the_lead_firewall_view_and_its_forms(self):
        fw = {"set_model", "set_rules", "accept_rules"}
        self.select("project:p01")
        details = self.grid(self.win.details)
        grid = self.win.details
        headings = [grid.get_child_at(0, i).get_text() for i in range(len(grid.get_children()) // 2)]
        self.assertEqual(len(headings), len(set(headings)), headings)      # no line said twice
        self.assertEqual(details["Lead firewall of"], f"osint (p01), lead {LEAD}")
        self.assertEqual(details["Rules you accepted"], "none on record")
        self.assertEqual(details["Rules it has now (live)"], "action=accept")
        self.assertLessEqual(fw, self.sensitive())
        # The lead's own row shows the same view, with the same buttons; a worker's, none.
        self.select(f"qube:{LEAD}")
        self.assertEqual(self.grid(self.win.details)["Rules it has now (live)"], "action=accept")
        self.assertLessEqual(fw, self.sensitive())
        self.select("qube:ai-osint-w1")
        self.assertNotIn("Lead firewall", self.grid(self.win.details))
        self.assertFalse(fw & self.sensitive())
        # Accept current rules: the rules now side by side; the qube does not change.
        self.select("project:p01")
        form = self.win.act("accept_rules")
        self.assertEqual(form.argv(), gm.accept_lead_rules("osint"))
        self.assertEqual([self.text(v) for v in form.compare], ["none on record", "action=accept"])
        self.submit(form)
        self.assertEqual(self.view()["accepted"], ["action=accept"])
        self.assertEqual(self.lead_rules(), ["action=accept"])
        self.assertEqual(self.grid(self.win.details)["Live rules are the ones you accepted"], "yes")
        self.assertNotIn("accept_rules", self.sensitive())
        # Set rules: it starts from the rules you accepted; what you type is the After column.
        form = self.win.act("set_rules")
        self.assertEqual(self.text(form.rules_view), "action=accept")
        form.rules_view.get_buffer().set_text(chr(10).join(["action=allow"]))
        self.assertFalse(form.ok.get_sensitive())
        self.assertIn("accept or drop", form.error.get_text())
        form.rules_view.get_buffer().set_text(chr(10).join(RULES + ["", ""]))
        self.assertEqual(form.argv(), gm.set_lead_rules("osint", RULES))
        self.assertEqual([self.text(v) for v in form.compare],
                         ["action=accept", "action=accept", chr(10).join(RULES)])
        self.submit(form)
        self.assertEqual(self.lead_rules(), SPELLED)
        self.assertEqual(self.view()["accepted"], SPELLED)
        # Set model: the After column is what the endpoint writes.
        form = self.win.act("set_model")
        self.assertFalse(form.ok.get_sensitive())
        self.assertEqual(self.text(form.compare[2]), "type the endpoint, host:port")
        form.model.set_text("api.anthropic.com:443")
        self.assertEqual(self.text(form.compare[2]),
                         chr(10).join(firewall.endpoint_rules("api.anthropic.com:443")))
        self.submit(form)
        self.assertEqual(projects.find(projects.load(), "osint").model, "api.anthropic.com:443")
        self.assertEqual(self.grid(self.win.details)["Lead's model endpoint"], "api.anthropic.com:443")
        lines = [r for r in self.win.audit_rows if r.get("service") == "qmcp project firewall"]
        self.assertEqual([r["caller"] for r in lines], ["operator"] * 3)

    def test_set_lead_model_is_off_for_a_lead_with_no_network(self):
        why = (f"{OTHER_LEAD} has no network, so it reaches no model endpoint; set its rules, or "
               f"give the project a new lead on a network")
        for key in ("project:p02", f"qube:{OTHER_LEAD}"):        # the project, and its lead's row
            self.select(key)
            self.assertIn("set_rules", self.sensitive())
            self.assertNotIn("set_model", self.sensitive())
            self.assertEqual(self.grid(self.win.details)["Set lead model"], f"off: {why}")
            self.assertIsNone(self.win.act("set_model"))           # no form opens
        # On a network, it is on, and the line saying why is gone.
        self.app.domains[OTHER_LEAD].netvm = self.app.domains["ai-net-router"]
        self.win.refresh()
        self.select("project:p02")
        self.assertIn("set_model", self.sensitive())
        self.assertNotIn("Set lead model", self.grid(self.win.details))
        form = self.win.act("set_model")
        form.model.set_text("api.anthropic.com:443")
        self.assertTrue(form.ok.get_sensitive(), form.error.get_text())
        # The lead loses its network while the form is open (the hub may clear
        # a qube's network): after a refresh, OK refuses in the command's words,
        # and runs nothing. The command refuses the same.
        self.app.domains[OTHER_LEAD].netvm = None
        self.win.refresh()
        writes = lambda: [c for c in self.runner.calls if c[:2] == list(gm.SUDO)]  # noqa: E731
        before = writes()
        form.response(Gtk.ResponseType.OK)
        self.assertEqual(writes(), before)
        self.assertEqual(form.error.get_text(), why)
        result = self.runner.execute(form.argv())
        self.assertEqual(result.rc, 1)
        self.assertIn(why, result.err)
        self.assertIsNone(projects.find(projects.load(), "other").model)
        self.assertNotIn("set_model", self.sensitive())

    def test_a_failed_firewall_read_keeps_the_view_and_turns_its_buttons_off(self):
        fw = {"set_model", "set_rules", "accept_rules"}
        self.select("project:p01")
        before = self.grid(self.win.details)
        self.runner.fail.add(tuple(gm.show_lead_firewall("osint")))
        self.win.refresh()
        details = self.grid(self.win.details)
        self.assertIn("could not be read", details["Lead firewall"])
        self.assertIn("Showing it as read at", details["Lead firewall"])
        self.assertEqual(details["Rules it has now (live)"], before["Rules it has now (live)"])
        self.assertFalse(fw & self.sensitive())
        self.assertIn("edit_project", self.sensitive())         # the rest of the window is current
        self.assertIsNone(self.win.act("set_rules"))
        self.runner.fail.clear()
        self.win.refresh()
        self.assertLessEqual(fw, self.sensitive())

    def test_while_the_view_is_read_again_its_buttons_are_off(self):
        self.select("project:p01")
        self.runner.hold = True
        self.win.refresh()
        self.assertFalse({"set_model", "set_rules", "accept_rules"} & self.sensitive())
        self.release_all()
        self.runner.hold = False
        self.assertLessEqual({"set_model", "set_rules", "accept_rules"}, self.sensitive())

    def test_an_open_firewall_form_runs_nothing_once_the_view_reads_differently(self):
        self.select("project:p01")
        form = self.win.act("set_rules")
        # The firewall changes from a dom0 terminal, and a refresh reads it.
        self.assertEqual(self.runner.execute(gm.set_lead_model("osint", "api.anthropic.com:443")).rc, 0)
        self.win.refresh()
        writes = lambda: [c for c in self.runner.calls if c[:2] == list(gm.SUDO)]  # noqa: E731
        before = writes()
        form.response(Gtk.ResponseType.OK)
        self.assertEqual(writes(), before)
        self.assertIn("changed since this form opened", form.error.get_text())
        form.destroy()
        # The control: a refresh that reads the same leaves an open form able to run.
        form = self.win.act("set_rules")
        self.win.refresh()
        result = self.submit(form)
        self.assertEqual(result.argv[-1], "action=drop")

    def test_a_lead_firewall_proposal_shows_the_rules_now_and_after(self):
        self.propose("rules")
        pane = self.pane()
        self.assertEqual(pane["Lead firewall now, live"], "action=accept")
        self.assertEqual(pane["Lead firewall after accepting"], chr(10).join(RULES))
        self.assertIn("changes the lead firewall of osint to 3 rules",
                      self.win.proposal_warning.get_text())
        self.assertTrue(self.win.proposal_tick.get_visible())
        self.assertEqual(self.deciding(), {"reject_proposal"})
        self.win.proposal_tick.set_active(True)
        form = self.win.act("accept_proposal")
        self.assertEqual(form.argv()[-2], "--yes")
        self.submit(form)
        self.assertEqual(self.lead_rules(), SPELLED)
        self.select("project:p01")
        self.assertEqual(self.grid(self.win.details)["Rules you accepted"], chr(10).join(SPELLED))

    def test_the_check_tab_shows_the_lead_firewall_findings(self):
        checks = lambda: {r[2]: r[1] for r in self.rows(self.win.check_store)}  # noqa: E731
        self.assertEqual(checks()["lead firewalls not accepted"], "WARN")
        self.select("project:p01")
        self.submit(self.win.act("accept_rules"))
        self.assertNotIn("lead firewalls not accepted", checks())
        self.assertEqual(checks()["lead firewalls"], "PASS")
        self.app.domains[LEAD].__dict__["_firewall"] = ["action=drop"]     # by hand, in dom0
        self.win.refresh()
        self.assertEqual(checks()["lead firewalls"], "FAIL")
        self.assertIn("accept_rules", self.sensitive())

    def test_it_never_runs_as_root(self):
        # If the refusal ever goes, main() must fail here, fast and invisibly,
        # rather than open a window and block in the main loop.
        opened = []
        saved = self.gui.os.geteuid, self.gui.Window, self.gui.Gtk.main
        self.gui.os.geteuid = lambda: 0
        self.gui.Window = lambda *a, **kw: opened.append(1) or (_ for _ in ()).throw(
            AssertionError("main() opened a window as root"))
        self.gui.Gtk.main = lambda: opened.append("main")
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                rc = self.gui.main([])
        finally:
            self.gui.os.geteuid, self.gui.Window, self.gui.Gtk.main = saved
        self.assertEqual((rc, opened), (2, []))
        self.assertIn("not root", err.getvalue())


@unittest.skipIf(Gtk is None, "GTK 3 cannot start here (no PyGObject or no display)")
class RealRunner(unittest.TestCase):
    """`gui.Runner`, the one place the window starts a process, on real ones."""

    def run_one(self, argv, timeout=None, wait=20):
        from gi.repository import GLib
        from qmcp import gui
        got = []
        gui.Runner().run(argv, got.append, timeout=timeout)
        ctx = GLib.MainContext.default()
        deadline = __import__("time").monotonic() + wait
        while not got and __import__("time").monotonic() < deadline:
            ctx.iteration(True)
        self.assertTrue(got, "the runner never answered")
        return got[0]

    def test_output_status_and_no_stdin(self):
        r = self.run_one(["/bin/sh", "-c", "echo out; echo err >&2; read x; echo \"[$x]\"; exit 3"])
        self.assertEqual((r.rc, r.out, r.err), (3, "out\n[]\n", "err\n"))

    def test_a_missing_program(self):
        r = self.run_one(["/nonexistent/qmcp"])
        self.assertEqual(r.rc, 127)
        self.assertIn("cannot start", r.err)

    def test_a_read_that_hangs_is_killed(self):
        r = self.run_one(["/bin/sleep", "30"], timeout=1)
        self.assertNotEqual(r.rc, 0)
        self.assertIn("timed out after 1 s", r.err)

    def test_undecodable_output_is_replaced_not_raised(self):
        r = self.run_one(["/bin/sh", "-c", "printf '\\377\\376ok'"])
        self.assertEqual(r.rc, 0)
        self.assertTrue(r.out.endswith("ok"))


if __name__ == "__main__":
    unittest.main()
