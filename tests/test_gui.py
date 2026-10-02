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

The GTK tests build widgets without showing them, and are skipped where GTK
cannot start (no PyGObject, or no display).
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
import pathlib
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, cli, fleet, projects  # noqa: E402
from qmcp import guimodel as gm  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_projects import LEAD, OTHER_LEAD, ProjectBase  # noqa: E402

GUI_SRC = HERE.parent / "dom0" / "qmcp" / "gui.py"
MODEL_SRC = HERE.parent / "dom0" / "qmcp" / "guimodel.py"
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
    ],
    gm.edit_project: [dict(key="osint", templates=["ai-debian-13"], networks=["none"], quota="30G")],
    gm.remove_lead: [dict(key="osint")],
    gm.change_lead: [dict(key="osint", lead_source="clone", lead_origin="ai-work2",
                          lead_name="ai-osint-lead2", lead_netvm="none", keep_old=True),
                     dict(key="osint", lead_source="template", lead_origin="ai-debian-13"),
                     dict(key="osint", lead_source="promote", lead_origin="ai-work2")],
    gm.add_dump: [dict(key="other", sink_name="other-sink")],
    gm.move: [dict(qube="ai-work2", target="osint", confirm=True)],
    gm.delete_plan: [dict(key="osint")],
    gm.delete_project: [dict(key="osint")],
    gm.role: [dict(action="manage", qube="x1"), dict(action="guard", qube="x1"),
              dict(action="revoke", qube="x1", keep_running=True)],
    gm.audit_rotate: [dict()],
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

    def test_every_field_of_an_audit_line_is_shown_or_left_to_verify(self):
        self.app.fail.add("start")
        self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"})   # error_class
        self.call("qmcp.LifecycleAIManaged", {"name": "nope", "action": "start"})       # refusal
        recs = gm.parse_audit(self.read("audit", "tail", "50"))
        fields = set().union(*(r.keys() for r in recs))
        shown = {k for k, _ in gm.AUDIT_FIELDS}
        self.assertEqual(fields - shown, set(gm.AUDIT_NOT_SHOWN))
        self.assertLessEqual(shown, fields)


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
        self.assertEqual(gm.worker_network_choices(rows), ["none", "ai-net-router"])
        self.assertIn("sys-firewall", gm.lead_network_choices(rows))
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
        self.assertEqual(makers, {"esc", "esc_lines", "audit_detail"})

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

    def test_every_builder_parameter_has_a_field_in_its_form(self):
        # The parity test proves each builder can make every option; this
        # proves the form that calls it lets the operator set each one.
        import inspect
        self.select("project:p01")
        record = self.win.node().data
        row = next(r for r in self.win.fleet if r["name"] == "ai-work2")
        forms = {
            gm.create_project: (self.gui.ProjectForm(self.win, self.win.fleet, HUB), {
                "label": "label_entry", "lead_source": "source", "lead_origin": "origin",
                "lead_name": "lead_name", "lead_netvm": "lead_netvm", "templates": "templates",
                "networks": "nets", "quota": "quota", "dump": "dump"}),
            gm.edit_project: (self.gui.EditForm(self.win, self.win.fleet, record), {
                "key": "record", "templates": "templates", "networks": "nets", "quota": "quota"}),
            gm.change_lead: (self.gui.LeadForm(self.win, self.win.fleet, HUB, record), {
                "key": "record", "lead_source": "source", "lead_origin": "origin",
                "lead_name": "lead_name", "lead_netvm": "lead_netvm", "keep_old": "old_lead"}),
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
        for ident in ("remove_lead", "delete_project", "add_to_ai_space", "manage", "guard"):
            self.assertIn(ident, dict(self.gui.Window.ACTIONS))
        for builder in set(gm.BUILDERS) - set(forms):
            self.assertIn(builder.__name__, {"remove_lead", "delete_plan", "delete_project",
                                             "audit_rotate"}, "a builder without a form")

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

        def project(source, origin, name):
            f = self.gui.ProjectForm(self.win, rows, HUB)
            f.label_entry.set_text("newp")
            f.source[source].set_active(True)
            f.origin.set_active_id(origin)
            if name:
                f.lead_name.set_text(name)
            f.lead_netvm.set_active_id("ai-net-router")
            f.templates["ai-dvm"].set_active(True)
            f.nets["none"].set_active(True)
            f.quota.set_text("5G")
            f.dump.set_active(True)
            return f
        forms = [project("template", "ai-debian-13", "ai-newp-boss"),
                 project("clone", "ai-work2", "ai-newp-boss"), project("promote", "ai-work2", None)]
        self.select("project:p01")
        record = self.win.node().data
        f = self.gui.EditForm(self.win, rows, record)
        f.templates["ai-dvm"].set_active(False)
        f.default_net.set_active_id("none")
        f.quota.set_text("30G")
        forms.append(f)
        for source, origin in (("template", "ai-debian-13"), ("clone", "ai-work2"), ("promote", "ai-work2")):
            f = self.gui.LeadForm(self.win, rows, HUB, record)
            f.source[source].set_active(True)
            f.origin.set_active_id(origin)
            if source != "promote":
                f.lead_name.set_text("ai-osint-boss")
            f.lead_netvm.set_active_id("none")
            f.old_lead.set_active_id("keep")
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
            argvs.append(argv.argv())
            argv.destroy()
        for ident in ("manage", "guard", "remove_lead", "rotate"):
            self.select({"manage": "qube:ai-tpl-g", "guard": "qube:ai-work2",
                         "remove_lead": "project:p01", "rotate": "project:p01"}[ident])
            form = self.win.act(ident)
            argvs.append(form.argv())
            form.destroy()
        self.select("project:p02")
        self.win.act("delete_project")
        argvs.append(self.runner.calls[-1])                     # the plan, a read
        argvs.append(self.win.last_form.argv())                 # the delete itself
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
        self.assertIn("No calls from the hub or a lead", text())
        self.assertIn("Your other commands are not", self.win.verify_label.get_text())
        self.submit(self.win.act("rotate"))
        self.assertIn("This log starts at a rotation", text())
        self.assertIn("--path /var/log/", text())

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
