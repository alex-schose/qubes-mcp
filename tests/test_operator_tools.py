"""0.9.26's operator tools against tests/fakequbes.py: the in-qube services kept
in dom0 and written into templates and standalones (`qmcp template`), the
restore check that holds a qube back from a backup or a copy for review
(`qmcp restored`), the operator files (`qmcp settings set`, `qmcp export`,
`qmcp import`), and the audit lines each leaves.

Every negative test proves its own positive first: a held qube is shown to be
reachable without the hold, a refused write is shown to happen without the
refusal, so a green suite cannot be one that tests nothing.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import (audit, budget, cli, core, fleet, gateways, inqube, opfiles,  # noqa: E402
                  projects, restored, services)
from fakequbes import GiB  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_projects import LEAD, OTHER_LEAD, ProjectBase  # noqa: E402

SOURCES = HERE.parent / "template-rpc"
#: The roots the fixtures run commands in: the managed qubes' templates and the
#: templates the projects approve (a guarded one included: workers spawn from it).
ROOTS = ("ai-debian-13", "ai-tpl-g", "debian-13")


class ToolsBase(ProjectBase):
    def setUp(self):
        super().setUp()
        self.rpc_copy = self.tmp / "lib" / "template-rpc"
        shutil.copytree(SOURCES, self.rpc_copy)
        saved = inqube.SERVICES_DIR
        inqube.SERVICES_DIR = str(self.rpc_copy)
        self.addCleanup(setattr, inqube, "SERVICES_DIR", saved)
        self.files = inqube.read_services()
        self.version = inqube.version(self.files)

    def cli(self, *argv, root=True):
        saved = cli._app
        cli._app = lambda: self.app
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err), \
                    mock.patch("os.geteuid", return_value=0 if root else 1000):
                try:
                    rc = cli.main(list(argv))
                except SystemExit as e:
                    rc = e.code
        finally:
            cli._app = saved
        return rc, out.getvalue(), err.getvalue()

    def tags(self, name):
        return set(self.app.domains[name].tags)

    def label(self, name):
        return dict.get(self.app.domains[name].features, core.ID_FEATURE)

    def uuid(self, name):
        return self.app.domains[name]._props["uuid"]


# ======================================================================= in-qube services

class InQube(ToolsBase):
    def test_the_version_names_both_files_and_moves_with_a_byte(self):
        self.assertEqual(set(self.files), set(inqube.SERVICE_NAMES))
        self.assertEqual(self.version, inqube.version(dict(self.files)))
        changed = dict(self.files)
        changed["qmcp.RunInAIManaged"] += b"\n"
        self.assertNotEqual(self.version, inqube.version(changed))

    def test_the_script_writes_exactly_the_two_files(self):
        vm = self.app.vm("tpl-x", klass="TemplateVM", power="Running")
        proc = vm.run_service("qubes.VMShell", user="root", autostart=False)
        proc.communicate(inqube.script(self.files), timeout=5)
        self.assertEqual((proc.returncode, vm.rpc_files()), (0, self.files))

    def test_prepare_starts_a_halted_template_writes_labels_and_stops_it(self):
        tpl = self.app.domains["ai-debian-13"]
        self.assertEqual(tpl.get_power_state(), "Halted")
        r = inqube.prepare(self.app, "ai-debian-13")
        self.assertEqual(r, {"qube": "ai-debian-13", "version": self.version, "started": True})
        self.assertEqual(tpl.rpc_files(), self.files)
        self.assertEqual(dict.get(tpl.features, inqube.LABEL), self.version)
        self.assertEqual(tpl.get_power_state(), "Halted")
        self.assertIn(("ai-debian-13", "run_service", "qubes.VMShell", "root"), self.app.calls)

    def test_prepare_leaves_a_running_qube_running_and_takes_a_standalone(self):
        sa = self.app.vm("ai-standalone", klass="StandaloneVM", power="Running",
                         tags={"ai-managed"})
        r = inqube.prepare(self.app, "ai-standalone")
        self.assertFalse(r["started"])
        self.assertEqual((sa.get_power_state(), sa.rpc_files()), ("Running", self.files))

    def test_prepare_refuses_a_qube_without_a_root_of_its_own(self):
        for name in ("ai-osint-w1", "dom0", "no-such-qube"):
            with self.assertRaises(inqube.InQubeError, msg=name):
                inqube.prepare(self.app, name)
        self.assertNotIn("run_service", [c[1] for c in self.app.calls])

    def test_prepare_refuses_a_stopped_or_held_qube_before_starting_it(self):
        for badge in ("qmcp-blocked", core.QUARANTINE):
            tpl = self.app.vm(f"tpl-{badge}", klass="TemplateVM", tags={"ai-managed", badge})
            with self.assertRaises(inqube.InQubeError, msg=badge):
                inqube.prepare(self.app, tpl.name)
            self.assertEqual(tpl.get_power_state(), "Halted")
            self.assertEqual(tpl.rpc_files(), {})

    def test_a_failed_or_hung_write_leaves_the_label_and_stops_the_qube(self):
        for mode, words in (("exit1", "exited 1"), ("timeout", "did not finish")):
            tpl = self.app.vm(f"tpl-{mode}", klass="TemplateVM")
            self.app.vmshell[tpl.name] = mode
            with self.assertRaises(inqube.InQubeError) as cm:
                inqube.prepare(self.app, tpl.name, timeout=0.01)
            self.assertIn(words, str(cm.exception))
            self.assertIsNone(dict.get(tpl.features, inqube.LABEL))
            self.assertEqual(tpl.get_power_state(), "Halted")

    def test_a_missing_copy_in_dom0_is_reported_and_starts_nothing(self):
        (self.rpc_copy / "qmcp.CopyToAIManaged").unlink()
        with self.assertRaises(inqube.InQubeError) as cm:
            inqube.prepare(self.app, "ai-debian-13")
        self.assertIn("reinstall", str(cm.exception))
        self.assertEqual(self.app.domains["ai-debian-13"].get_power_state(), "Halted")

    def fleet_for_refresh(self):
        a = self.app
        mk = lambda name, klass, power, label, tags=(): a.vm(  # noqa: E731
            name, klass=klass, power=power, tags=set(tags),
            features={} if label is None else {inqube.LABEL: label})
        return {
            "behind-running": mk("t-behind-run", "TemplateVM", "Running", "sha256:old"),
            "behind-halted": mk("t-behind-halt", "TemplateVM", "Halted", "sha256:old"),
            "current": mk("t-current", "TemplateVM", "Running", self.version),
            "never": mk("t-never", "TemplateVM", "Running", None),
            "standalone": mk("s-behind", "StandaloneVM", "Running", "sha256:old", {"ai-managed"}),
            "blocked": mk("s-blocked", "StandaloneVM", "Running", "sha256:old",
                          {"ai-managed", "qmcp-blocked"}),
            "held": mk("s-held", "StandaloneVM", "Running", "sha256:old",
                       {"ai-managed", core.QUARANTINE}),
        }

    def test_refresh_writes_only_running_prepared_qubes_that_are_behind(self):
        q = self.fleet_for_refresh()
        done = dict(inqube.refresh(self.app))
        self.assertEqual(done, {"t-behind-run": "updated", "s-behind": "updated"})
        for key in ("behind-running", "standalone"):
            self.assertEqual(dict.get(q[key].features, inqube.LABEL), self.version)
            self.assertEqual(q[key].rpc_files(), self.files)
        for key in ("behind-halted", "never", "blocked", "held", "current"):
            self.assertEqual(q[key].rpc_files(), {}, key)

    def test_refresh_never_starts_a_qube(self):
        q = self.fleet_for_refresh()
        inqube.refresh(self.app)
        self.assertEqual(q["behind-halted"].get_power_state(), "Halted")
        self.assertNotIn("t-behind-halt", [c[0] for c in self.app.calls if c[1] == "run_service"])

    def test_refresh_reports_a_failed_write_and_keeps_the_old_label(self):
        q = self.fleet_for_refresh()
        self.app.vmshell["t-behind-run"] = "exit1"
        done = dict(inqube.refresh(self.app))
        self.assertTrue(done["t-behind-run"].startswith("not updated"))
        self.assertEqual(dict.get(q["behind-running"].features, inqube.LABEL), "sha256:old")
        self.assertEqual(done["s-behind"], "updated")

    def test_refresh_reports_a_label_it_cannot_read_and_writes_nothing_there(self):
        q = self.fleet_for_refresh()
        self.app.fail.add("feature.get:t-behind-run")
        done = dict(inqube.refresh(self.app))
        self.assertTrue(done["t-behind-run"].startswith("not judged"))
        self.assertEqual(q["behind-running"].rpc_files(), {})

    def findings(self, records=None):
        out = []
        tags_by = {vm.name: set(vm.tags) for vm in self.app.domains}
        inqube.findings(list(self.app.domains), self.records() if records is None else records,
                        tags_by, lambda *a: out.append(a), str(self.rpc_copy))
        return out

    def test_the_check_warns_on_a_missing_or_old_label_and_passes_once_current(self):
        out = self.findings()
        self.assertEqual([f[0] for f in out], ["warn"])
        self.assertIn("ai-debian-13", out[0][2])
        self.assertIn("not the qube's disk", out[0][2])
        for root in ROOTS:
            inqube.prepare(self.app, root)
        self.assertEqual([f[0] for f in self.findings()], ["pass"])
        self.app.domains["ai-debian-13"].features[inqube.LABEL] = "sha256:old"
        self.assertIn("older version", self.findings()[0][2])

    def test_the_check_covers_a_managed_standalone_and_follows_a_template_chain(self):
        for root in ROOTS:
            inqube.prepare(self.app, root)
        self.app.vm("ai-sa", klass="StandaloneVM", tags={"ai-managed"})
        out = self.findings()
        self.assertIn("ai-sa", out[0][2])
        # A guarded standalone is never operated: the check leaves it alone.
        self.app.domains["ai-sa"].tags.add("qmcp-guarded")
        self.assertEqual([f[0] for f in self.findings()], ["pass"])

    def test_an_unreadable_label_is_an_error_never_a_pass(self):
        self.app.fail.add("feature.get:ai-debian-13")
        self.assertIn("error", [f[0] for f in self.findings()])

    def test_neither_label_is_a_feature_the_hub_or_a_lead_can_write(self):
        for key in (inqube.LABEL, core.ID_FEATURE):
            self.assertFalse(services._feature_allowed(key), key)
            r = self.call("qmcp.SetFeatureAIManaged",
                          {"name": "ai-osint-w1", "feature": key, "value": "forged"})
            self.assertFalse(r["ok"], key)
        # Teeth: an allowed key goes through the same call.
        self.assertTrue(self.call("qmcp.SetFeatureAIManaged",
                                  {"name": "ai-osint-w1", "feature": "service.x", "value": 1})["ok"])

    def test_the_cli_prepares_as_root_and_the_refresh_leaves_one_line_per_qube(self):
        rc, _, err = self.cli("template", "prepare", "ai-debian-13", root=False)
        self.assertNotEqual(rc, 0)
        self.assertIn("run as root", str(rc) + err)
        rc, out, _ = self.cli("template", "prepare", "ai-debian-13")
        self.assertEqual(rc, 0, out)
        self.assertIn("prepared", out)
        self.fleet_for_refresh()
        before = len(self.audit_lines())
        rc, out, _ = self.cli("template", "refresh", root=False)
        self.assertEqual(rc, 0, out)
        lines = self.audit_lines()[before:]
        self.assertEqual(sorted(l["args"]["qube"] for l in lines), ["s-behind", "t-behind-run"])
        self.assertTrue(all((l["service"], l["caller"], l["ok"]) == ("qmcp template refresh",
                                                                    "refresh", True)
                            for l in lines))
        # A qube whose write keeps failing leaves no line, run after run: the
        # chain records changes, not invocations.
        self.app.vmshell["t-behind-halt"] = "exit1"
        self.app.domains["t-behind-halt"].start()
        before = len(self.audit_lines())
        for _ in range(3):
            rc, out, _ = self.cli("template", "refresh", root=False)
            self.assertEqual(rc, 3, out)
        self.assertEqual(len(self.audit_lines()), before)


# ======================================================================= the restore check

class Labels(ToolsBase):
    def assert_own_label(self, name):
        self.assertEqual(self.label(name), self.uuid(name), name)

    def test_every_create_labels_its_qube_with_its_own_uuid(self):
        self.egress("ai-net-router")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-new", "template": "ai-debian-13"})
        self.assertTrue(r["ok"], r)
        self.assert_own_label("ai-hub-new")
        # A clone arrives wearing its source's label: it gets its own.
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-hubq", "name": "ai-hub-copy"})
        self.assertTrue(r["ok"], r)
        self.assertNotEqual(self.uuid("ai-hub-copy"), self.uuid("ai-hubq"))
        self.assert_own_label("ai-hub-copy")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertTrue(r["ok"], r)
        self.app.domains.clear_cache()
        self.assert_own_label(r["name"])

    def test_the_operator_commands_label_what_they_bring_in(self):
        a = self.app
        a.vm("plain", netvm=None, labelled=False)
        self.assertIsNone(self.label("plain"))
        fleet.manage(a, "plain")
        self.assert_own_label("plain")
        a.vm("plain2", netvm=None, labelled=False)
        fleet.guard(a, "plain2")
        self.assert_own_label("plain2")

    def test_a_badge_never_goes_on_a_qube_carrying_another_qubes_label(self):
        a = self.app
        vm = a.vm("ai-copied", netvm=None, tags={"ai-managed"}, features={core.ID_FEATURE: "x"})
        with self.assertRaises(restored.NotReviewed):
            fleet._set_tags(vm, add={"qmcp-proj-p00"})
        self.assertNotIn("qmcp-proj-p00", self.tags("ai-copied"))
        # Teeth: the same call on a labelled qube goes through.
        fleet._set_tags(a.domains["ai-hubq"], add={"qmcp-hubblind"})
        self.assertIn("qmcp-hubblind", self.tags("ai-hubq"))


class Hold(ToolsBase):
    def restore_worker(self, name="ai-osint-w9", slot="p01"):
        """A worker back from a backup: its badges, a label naming its old UUID."""
        return self.app.vm(name, template=self.app.domains["ai-debian-13"], netvm=None,
                           tags={"ai-managed", projects.member_badge(slot)},
                           features={core.ID_FEATURE: "6a0b0b5e-0000-4000-8000-000000000000"})

    def test_teeth_without_the_hold_a_restored_worker_is_its_leads(self):
        self.restore_worker()
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-osint-w9", "action": "start"},
                      caller=LEAD)
        self.assertTrue(r["ok"], r)

    def test_the_gate_holds_a_restored_worker_and_keeps_its_badges(self):
        self.restore_worker()
        rc, out, err = self.cli("gate", "--json", root=False)
        self.assertIn(core.QUARANTINE, self.tags("ai-osint-w9"))
        self.assertIn("qmcp-proj-p01", self.tags("ai-osint-w9"))
        self.assertIn("ai-osint-w9: held for review", err)
        json.loads(out)                     # --json is the gate's verdicts alone
        line = self.audit_lines()[-1]
        self.assertEqual((line["service"], line["caller"], line["args"]["qube"]),
                         ("qmcp gate", "gate", "ai-osint-w9"))
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-osint-w9", "action": "start"},
                      caller=LEAD)
        self.assertEqual(r, core.QUARANTINE_REFUSAL)

    def test_a_hand_copy_is_held_and_an_unlabelled_badged_qube_too(self):
        self.app.clone_vm(self.app.domains["ai-hubq"], "ai-hubq-copy")
        self.app.vm("ai-tagged-by-hand", netvm=None, tags={"ai-managed"}, labelled=False)
        held = restored.hold(self.app)
        self.assertEqual(sorted(held.held), ["ai-hubq-copy", "ai-tagged-by-hand"])
        self.assertNotIn(core.QUARANTINE, self.tags("ai-hubq"))

    def test_a_qube_out_of_scope_is_never_held(self):
        self.app.vm("operator-thing", labelled=False)
        self.assertEqual(restored.hold(self.app).held, [])
        self.assertNotIn(core.QUARANTINE, self.tags("operator-thing"))

    def test_a_label_it_cannot_read_is_left_for_the_next_run_and_reported(self):
        self.restore_worker()
        self.app.fail.add("feature.get:ai-osint-w9")
        held = restored.hold(self.app)
        self.assertEqual(held.held, [])
        self.assertTrue(held.unread)
        self.assertNotIn(core.QUARANTINE, self.tags("ai-osint-w9"))

    def test_the_pass_waits_for_a_create_in_flight_and_then_judges_nothing(self):
        self.restore_worker()
        fd = budget.acquire_create_lock()
        try:
            held = restored.hold(self.app, lock_wait=0.1)
        finally:
            os.close(fd)
        self.assertFalse(held.judged)
        self.assertNotIn(core.QUARANTINE, self.tags("ai-osint-w9"))
        rc, _, err = self.cli("gate", root=False)
        self.assertIn(core.QUARANTINE, self.tags("ai-osint-w9"))

    def test_the_services_refuse_a_held_qube_as_operand_and_as_reference(self):
        self.restore_worker()
        tpl = self.app.vm("ai-tpl-back", klass="TemplateVM", tags={"ai-managed"},
                          features={core.ID_FEATURE: "other"})
        restored.hold(self.app)
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-osint-w9", "name": "ai-hub-c"})
        self.assertEqual(r, core.QUARANTINE_REFUSAL)
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-s", "template": tpl.name})
        self.assertEqual(r, core.QUARANTINE_REFUSAL)

    def test_a_held_lead_is_no_principal_and_a_held_hub_is_refused(self):
        self.app.domains[LEAD].tags.add(core.QUARANTINE)
        self.assertEqual(self.call("qmcp.ListAIManagedQubes", {}, caller=LEAD), core.NOT_AUTHORIZED)
        self.app.domains[LEAD].tags.discard(core.QUARANTINE)
        self.assertTrue(self.call("qmcp.ListAIManagedQubes", {}, caller=LEAD)["ok"])
        self.app.domains[HUB].tags.add(core.QUARANTINE)
        self.assertEqual(self.call("qmcp.ListAIManagedQubes", {}), core.NOT_AUTHORIZED)

    def test_a_disposable_qubes_made_from_a_labelled_template_is_not_held(self):
        # Qubes copies a disposable template's features to its disposables (a
        # preloaded one, one launched by hand), so their label is the
        # template's UUID. Those clean themselves up, and Qubes leaves them out
        # of backups: such a qube is known, not restored.
        name = self.app.qubesd_call("ai-dvm", "admin.vm.CreateDisposable").decode()
        self.app.domains.clear_cache()
        disp = self.app.domains[name]
        self.assertEqual(dict.get(disp.features, core.ID_FEATURE), self.uuid("ai-dvm"))
        self.assertEqual(restored.hold(self.app).held, [])
        self.assertEqual(restored.review(self.app, None), [])
        # Teeth: a named disposable (no auto_cleanup), which a backup holds,
        # is held with the same label; so is one whose label is any other UUID.
        disp.__dict__["auto_cleanup"] = False
        self.assertEqual(restored.hold(self.app).held, [name])
        disp.tags.discard(core.QUARANTINE)
        disp.__dict__["auto_cleanup"] = True
        disp.features[core.ID_FEATURE] = "6a0b0b5e-0000-4000-8000-000000000000"
        self.assertEqual(restored.hold(self.app).held, [name])
        # And one whose template is no labelled one is held.
        disp.tags.discard(core.QUARANTINE)
        disp.features[core.ID_FEATURE] = self.uuid("ai-dvm")
        self.app.domains["ai-dvm"].features[core.ID_FEATURE] = "other"
        self.assertIn(name, restored.hold(self.app).held)

    def test_a_create_never_lifts_a_hold(self):
        from qmcp import birth
        vm = self.app.vm("ai-held-child", netvm=None, tags={"ai-managed", core.QUARANTINE})
        with self.assertRaises(RuntimeError):
            birth.stamp(birth.TagIO.for_vm(vm), set(), "mcp-control", "qmcp-proj-p00")
        self.assertIn(core.QUARANTINE, self.tags("ai-held-child"))

    def test_a_held_template_is_refused_as_a_leads_or_an_approved_one(self):
        tpl = self.app.vm("ai-tpl-back", klass="TemplateVM", tags={"ai-managed"},
                          features={core.ID_FEATURE: "other"})
        restored.hold(self.app)
        with self.assertRaises(fleet.ProjectError):
            fleet._lead_template(self.app, tpl.name)
        with self.assertRaises(fleet.ProjectError):
            fleet._check_templates(self.app, [tpl.name])
        # Teeth: the same calls take a template that is not held.
        fleet._lead_template(self.app, "ai-debian-13")
        self.assertEqual(fleet._check_templates(self.app, ["ai-debian-13"]), ["ai-debian-13"])

    def test_a_lead_change_or_gateway_set_refuses_a_held_one_before_changing_anything(self):
        self.app.domains[LEAD].tags.add(core.QUARANTINE)
        before = pathlib.Path(projects.PROJECTS_PATH).read_text()
        for call in (lambda: fleet.remove_lead(self.app, "osint"),
                     lambda: fleet.set_lead(self.app, "osint", "template", "ai-debian-13",
                                            keep_old=True)):
            with self.assertRaises((fleet.ProjectError, fleet.RoleError)):
                call()
        self.assertEqual(pathlib.Path(projects.PROJECTS_PATH).read_text(), before)
        self.app.domains["ai-net-router"].tags.add(core.QUARANTINE)
        with self.assertRaises(fleet.RoleError):
            fleet.set_gateway(self.app, "ai-net-router", label="x")

    def test_a_lead_firewall_or_model_change_refuses_a_held_lead(self):
        # Teeth: the same change goes through while the lead is not held.
        fleet.set_lead_firewall(self.app, "osint", model="192.0.2.5:443")
        lead = self.app.domains[LEAD]
        lead.tags.add(core.QUARANTINE)
        model = self.app.vm("ai-hub-model", template=self.app.domains["debian-13"], netvm=None,
                            tags={"ai-managed", "qmcp-proj-p00"})
        before = (pathlib.Path(projects.PROJECTS_PATH).read_text(), lead.netvm,
                  frozenset(model.tags))
        for kw in ({"model": "192.0.2.6:443"}, {"accept_current": True},
                   {"rules": ["action=accept proto=tcp dsthost=192.0.2.6 dstports=443-443"]},
                   {"model_qube": "ai-hub-model"}):
            with self.assertRaises(fleet.ProjectError, msg=kw) as cm:
                fleet.set_lead_firewall(self.app, "osint", **kw)
            self.assertIn(fleet.HELD_WHY, str(cm.exception))
        self.assertEqual((pathlib.Path(projects.PROJECTS_PATH).read_text(), lead.netvm,
                          frozenset(model.tags)), before)
        # Taking a model qube away only takes authority, and leaves the lead alone.
        fleet.set_lead_firewall(self.app, "osint", model_qube="none")

    def test_migrate_never_labels_a_qube(self):
        # On a fleet no 0.9.26 has run there is nothing to review yet: the plan
        # goes ahead and leaves the labelling to the installer's seed.
        for vm in self.app.domains:
            dict.pop(vm.features, core.ID_FEATURE, None)
        self.app.vm("ai-tiered", netvm=None, tags={"ai-managed", "ai-exec"}, labelled=False)
        steps, problems = fleet.plan_migration(self.app, {}, exec_default="guarded",
                                               compat_default="managed", tier_default=None)
        self.assertEqual(problems, [])
        self.assertIn("ai-tiered", {s.qube for s in steps})
        results = fleet.apply_migration(self.app, steps)
        self.assertTrue(all(r.startswith("done") for r in results), results)
        self.assertIn("qmcp-guarded", self.tags("ai-tiered"))
        self.assertEqual([vm.name for vm in self.app.domains
                          if dict.get(vm.features, core.ID_FEATURE) is not None], [])

    def test_the_installers_shape_check_leaves_restored_qubes_to_the_restore_check(self):
        # The README's restore order installs over restored qubes that carry
        # another qube's label and are not held yet; a reinstall may meet held
        # ones. Neither is a reason to refuse the install.
        self.app.vm("ai-copied", netvm=None, tags={"ai-managed"},
                    features={core.ID_FEATURE: "other"})
        self.app.vm("ai-held", netvm=None, tags={"ai-managed", core.QUARANTINE},
                    features={core.ID_FEATURE: "other"})
        steps, problems = fleet.plan_migration(self.app, {}, tier_default=None, review=False)
        mine = {"ai-copied", "ai-held"}
        self.assertEqual(([s for s in steps if s.qube in mine],
                          [p for p in problems if p.split()[0] in mine]), ([], []))
        self.assertIn("fleet.plan_migration(app, {}, review=False)",
                      (HERE.parent / "deploy" / "install.sh").read_text())
        # Teeth: the migration itself refuses both.
        _, problems = fleet.plan_migration(self.app, {}, tier_default=None)
        self.assertEqual({p.split()[0] for p in problems} & mine, mine)

    def test_migrate_refuses_an_unknown_qube_once_any_qube_carries_a_label(self):
        self.app.vm("ai-nolabel", netvm=None, tags={"ai-managed", "ai-exec"}, labelled=False)
        self.app.vm("ai-copied", netvm=None, tags={"ai-managed", "ai-exec"},
                    features={core.ID_FEATURE: "other"})
        steps, problems = fleet.plan_migration(self.app, {}, exec_default="managed",
                                               compat_default="managed", tier_default=None)
        self.assertFalse({"ai-nolabel", "ai-copied"} & {s.qube for s in steps})
        for name in ("ai-nolabel", "ai-copied"):
            self.assertTrue(any(p.startswith(f"{name} ") and "waits for review" in p
                                for p in problems), (name, problems))
        self.assertIsNone(self.label("ai-nolabel"))

    def test_a_lead_from_a_clone_or_promotion_refuses_a_held_template(self):
        # The new lead's template joins the approved list, as create's does.
        tpl = self.app.vm("ai-tpl-back", klass="TemplateVM", tags={"ai-managed"},
                          features={core.ID_FEATURE: "other"})
        self.app.vm("ai-hubr", template=tpl, netvm=None, tags={"ai-managed", "qmcp-proj-p00"})
        restored.hold(self.app)
        before = pathlib.Path(projects.PROJECTS_PATH).read_text()
        for source, name in (("clone", "ai-osint-lead2"), ("promote", None)):
            with self.assertRaises(fleet.ProjectError, msg=source) as cm:
                fleet.set_lead(self.app, "osint", source, "ai-hubr", lead_netvm="none",
                               keep_old=True, lead_name=name)
            self.assertIn(fleet.HELD_WHY, str(cm.exception))
        self.assertEqual(pathlib.Path(projects.PROJECTS_PATH).read_text(), before)
        # Teeth: once the template is accepted the same promotion approves it.
        restored.accept(self.app, "ai-tpl-back")
        fleet.set_lead(self.app, "osint", "promote", "ai-hubr", lead_netvm="none", keep_old=True)
        self.assertIn("ai-tpl-back", projects.find(projects.load(), "osint").templates)

    def test_no_badge_goes_on_a_badged_qube_with_no_label_before_the_gate_holds_it(self):
        vm = self.app.vm("ai-nolabel", netvm=None, tags={"ai-managed", "qmcp-proj-p00"},
                         labelled=False)
        with self.assertRaises(restored.NotReviewed):
            fleet._set_tags(vm, add={"qmcp-proj-p01"}, remove={"qmcp-proj-p00"})
        self.assertIsNone(self.label("ai-nolabel"))
        self.assertEqual(self.tags("ai-nolabel") & {"qmcp-proj-p00", "qmcp-proj-p01"},
                         {"qmcp-proj-p00"})
        # Teeth: a qube with no badge is labelled afresh and badged.
        plain = self.app.vm("ai-plain", netvm=None, tags=set(), labelled=False)
        fleet._set_tags(plain, add={"ai-managed"})
        self.assertEqual(self.label("ai-plain"), self.uuid("ai-plain"))

    def test_migrate_plans_nothing_for_a_held_qube(self):
        # Teeth: a tiered qube that is not held gets a step.
        self.app.vm("ai-tiered", netvm=None, tags={"ai-managed", "ai-exec"})
        self.app.vm("ai-tiered-back", netvm=None, tags={"ai-managed", "ai-exec"},
                    features={core.ID_FEATURE: "other"})
        restored.hold(self.app)
        steps, problems = fleet.plan_migration(self.app, {}, exec_default="managed",
                                               tier_default=None)
        self.assertEqual([s.qube for s in steps if s.qube.startswith("ai-tiered")],
                         ["ai-tiered"])
        self.assertTrue(any(p.startswith("ai-tiered-back ") and fleet.HELD_WHY in p
                            for p in problems), problems)

    def test_the_operator_commands_refuse_a_held_qube(self):
        self.restore_worker()
        g = self.app.vm("ai-g-back", netvm=None, tags={"ai-managed", "qmcp-guarded"},
                        features={core.ID_FEATURE: "other"})
        restored.hold(self.app)
        for call in (lambda: fleet.manage(self.app, "ai-g-back"),
                     lambda: fleet.guard(self.app, "ai-osint-w9"),
                     lambda: fleet.open_window(self.app, "ai-g-back", 60)):
            with self.assertRaises(fleet.RoleError):
                call()
        with self.assertRaises(fleet.ProjectError):
            fleet.move_qube(self.app, "ai-osint-w9", "p00", confirm=True) \
                if hasattr(fleet, "move_qube") else fleet._move(fleet.Report(), self.app,
                                                               "ai-osint-w9", "p00", True)
        self.assertEqual(g.get_power_state(), "Halted")


class Review(ToolsBase):
    def back(self, name, tags):
        return self.app.vm(name, netvm=None, tags=set(tags) | {"ai-managed"},
                           features={core.ID_FEATURE: "old"})

    def test_review_says_what_each_came_back_as_and_whether_it_agrees(self):
        self.app.domains[LEAD].features[core.ID_FEATURE] = "old"     # the recorded lead, restored
        self.back("ai-old-lead", {"qmcp-lead", "qmcp-lead-p01"})
        self.back("ai-gone-w", {"qmcp-proj-p09"})
        self.back("ai-hubq2", {"qmcp-proj-p00"})
        rows = {r["name"]: r for r in restored.review(self.app, self.records())}
        self.assertEqual((rows[LEAD]["role"], rows[LEAD]["agrees"]), ("lead of p01", True))
        self.assertFalse(rows["ai-old-lead"]["agrees"])
        self.assertIn(f"names {LEAD} as lead", rows["ai-old-lead"]["why"][0])
        self.assertEqual(rows["ai-gone-w"]["why"], ["no project holds p09"])
        self.assertTrue(rows["ai-hubq2"]["agrees"])
        self.assertEqual(rows["ai-hubq2"]["label"], "another qube's")
        self.assertNotIn("ai-osint-w1", rows)

    def test_accept_labels_first_then_lifts_the_hold_and_keeps_the_badges(self):
        self.back("ai-x", {"qmcp-proj-p00"})
        restored.hold(self.app)
        self.app.fail.add("feature.set")
        with self.assertRaises(Exception):
            restored.accept(self.app, "ai-x")
        self.assertIn(core.QUARANTINE, self.tags("ai-x"))
        self.app.fail.discard("feature.set")
        restored.accept(self.app, "ai-x")
        self.assertEqual(self.label("ai-x"), self.uuid("ai-x"))
        self.assertEqual(self.tags("ai-x") - {"created-by-dom0"}, {"ai-managed", "qmcp-proj-p00"})
        self.assertEqual(restored.hold(self.app).held, [])

    def test_reject_takes_the_routed_badges_off_before_the_hold(self):
        self.back("ai-y", {"qmcp-proj-p01"})
        restored.hold(self.app)
        self.app.fail.add("tag.discard:" + core.QUARANTINE)
        with self.assertRaises(Exception):
            restored.reject(self.app, "ai-y")
        self.assertEqual(self.tags("ai-y") & {"ai-managed", "qmcp-proj-p01", core.QUARANTINE},
                         {core.QUARANTINE})
        self.app.fail.discard("tag.discard:" + core.QUARANTINE)
        restored.reject(self.app, "ai-y")
        self.assertFalse(restored.in_scope(self.tags("ai-y")))

    def test_the_hold_comes_off_last_whatever_sorts_after_it(self):
        # `qmcp-stopped` sorts after `qmcp-quarantine` in the removal order's
        # last group: a removal that took the hold off with the rest would take
        # it off first, and a failure on the next badge would leave the qube
        # unheld with a badge still on.
        self.back("ai-w", {"qmcp-proj-p01", "qmcp-stopped"})
        restored.hold(self.app)
        self.app.fail.add("tag.discard:qmcp-stopped")
        with self.assertRaises(Exception):
            restored.reject(self.app, "ai-w")
        self.assertIn(core.QUARANTINE, self.tags("ai-w"))

    def test_revoke_refuses_a_held_qube(self):
        self.back("ai-rv", set())
        restored.hold(self.app)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, "ai-rv")
        self.assertIn("reject it instead", str(cm.exception))
        self.assertIn(core.QUARANTINE, self.tags("ai-rv"))

    def test_a_label_that_cannot_be_read_is_never_none_waiting(self):
        def check():
            out = []
            restored.findings(self.app, lambda *f: out.append(f))
            return out
        # Teeth: a fleet with every label its own passes.
        self.assertEqual(check(), [("pass", "restored qubes", "none waiting for review")])
        self.app.fail.add("feature.get:ai-osint-w1")
        self.assertEqual([f[0] for f in check()], ["error"])

    def test_accept_and_reject_refuse_a_qube_not_waiting(self):
        for name in ("ai-osint-w1", "personal"):
            for act in (restored.accept, restored.reject):
                with self.assertRaises(restored.ReviewError, msg=(name, act.__name__)):
                    act(self.app, name)

    def test_accept_all_and_the_audit_lines(self):
        for n in ("ai-a", "ai-b"):
            self.back(n, {"qmcp-proj-p00"})
        restored.hold(self.app)
        rc, out, _ = self.cli("restored", "list", "--json", root=False)
        self.assertEqual(sorted(r["name"] for r in json.loads(out) if r["held"]), ["ai-a", "ai-b"])
        rc, out, _ = self.cli("restored", "accept", "--all")
        self.assertEqual(rc, 0, out)
        self.assertEqual(restored.review(self.app, {}), [])
        line = self.audit_lines()[-1]
        self.assertEqual((line["service"], line["args"]["all"]), ("qmcp restored accept", True))

    def test_unreadable_records_make_agreement_not_known_never_no(self):
        self.back("ai-n", {"qmcp-proj-p01"})
        [row] = restored.review(self.app, None)
        self.assertEqual((row["agrees"], row["why"]), (None, None))
        pathlib.Path(projects.PROJECTS_PATH).write_text("{not json")
        rc, out, err = self.cli("restored", "list", "--json", root=False)
        self.assertEqual(rc, 0)
        self.assertIn("cannot be read", err)
        self.assertEqual([(r["agrees"], r["why"]) for r in json.loads(out)], [(None, None)])

    def test_a_held_qube_whose_label_is_its_own_is_still_listed_and_checked(self):
        # An accept that labelled it and stopped before lifting the hold.
        self.app.domains["ai-hubq"].tags.add(core.QUARANTINE)
        [row] = restored.review(self.app, self.records())
        self.assertEqual((row["name"], row["held"], row["label"]), ("ai-hubq", True, "its own"))
        out = []
        restored.findings(self.app, lambda *a: out.append(a))
        self.assertEqual([o[0] for o in out], ["warn"])
        restored.accept(self.app, "ai-hubq")
        self.assertNotIn(core.QUARANTINE, self.tags("ai-hubq"))

    def test_reject_removes_the_label_and_manage_then_labels_it_afresh(self):
        self.back("ai-r", {"qmcp-proj-p00"})
        restored.hold(self.app)
        restored.reject(self.app, "ai-r")
        self.assertIsNone(self.label("ai-r"))
        fleet.manage(self.app, "ai-r")
        self.assertEqual(self.label("ai-r"), self.uuid("ai-r"))
        self.assertEqual(restored.hold(self.app).held, [])

    def test_manage_and_guard_refuse_a_badged_copy_not_yet_held(self):
        g = self.back("ai-g", {"qmcp-guarded"})
        for act in (fleet.manage, fleet.guard):
            with self.assertRaises(fleet.RoleError, msg=act.__name__) as cm:
                act(self.app, "ai-g")
            self.assertIn("missing or another qube's", str(cm.exception))
        # A badged qube with no label at all is refused the same way.
        self.app.vm("ai-nolabel", netvm=None, tags={"ai-managed", "qmcp-guarded"}, labelled=False)
        with self.assertRaises(fleet.RoleError):
            fleet.manage(self.app, "ai-nolabel")
        self.assertEqual(self.label("ai-g"), "old")         # never laundered
        # Teeth: a plain qube with another qube's label is the operator's to bring in.
        self.app.vm("plain-old", netvm=None, features={core.ID_FEATURE: "old"})
        fleet.manage(self.app, "plain-old")
        self.assertEqual(self.label("plain-old"), self.uuid("plain-old"))
        del g

    def test_accept_takes_exactly_the_names_given(self):
        for n in ("ai-a", "ai-b", "ai-c"):
            self.back(n, {"qmcp-proj-p00"})
        restored.hold(self.app)
        rc, out, _ = self.cli("restored", "accept", "ai-a", "ai-b")
        self.assertEqual(rc, 0, out)
        self.assertEqual([r["name"] for r in restored.review(self.app, None)], ["ai-c"])
        line = self.audit_lines()[-1]
        self.assertEqual((line["args"]["qubes"], line["args"]["all"]), (["ai-a", "ai-b"], False))
        rc, _, err = self.cli("restored", "accept", "ai-c", "--all")
        self.assertNotEqual(rc, 0)
        self.assertIn(core.QUARANTINE, self.tags("ai-c"))

    def test_the_check_items(self):
        out = []
        restored.findings(self.app, lambda *a: out.append(a))
        self.assertEqual([o[0] for o in out], ["pass"])
        self.back("ai-z", {"qmcp-proj-p00"})
        out = []
        restored.findings(self.app, lambda *a: out.append(a))
        self.assertEqual([o[0] for o in out], ["fail"])
        restored.hold(self.app)
        out = []
        restored.findings(self.app, lambda *a: out.append(a))
        self.assertEqual([o[0] for o in out], ["warn"])


# ======================================================================= operator files

class OpFiles(ToolsBase):
    def test_settings_set_writes_each_part_and_refuses_what_the_command_would(self):
        opfiles.settings_set(self.app, pool_cap="900G", private_cap="5G")
        self.assertEqual(budget.read_cap(), 900 * GiB)
        self.assertEqual(budget.read_private_cap(), 5 * GiB)
        opfiles.settings_set(self.app, birth_egress="ai-net-router")
        self.assertEqual(pathlib.Path(fleet.birth.BIRTH_EGRESS_PATH).read_text(), "ai-net-router\n")
        opfiles.settings_set(self.app, birth_egress="none")
        self.assertFalse(os.path.exists(fleet.birth.BIRTH_EGRESS_PATH))
        for kw in ({}, {"pool_cap": "1K"}, {"pool_cap": "x"}, {"birth_egress": "personal"},
                   {"birth_egress": "../etc"}):
            with self.assertRaises(opfiles.OpFilesError, msg=kw):
                opfiles.settings_set(self.app, **kw)
        self.assertEqual(budget.read_cap(), 900 * GiB)

    def export_path(self):
        return str(self.tmp / "export.json")

    def test_export_writes_one_private_file_and_never_over_another(self):
        path = opfiles.export("0.9.26", self.export_path())
        doc = json.loads(pathlib.Path(path).read_text())
        self.assertEqual(doc["format"], opfiles.FORMAT)
        self.assertEqual(doc["files"]["hub"], HUB + "\n")
        self.assertIn("osint", doc["files"]["projects.json"])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with self.assertRaises(opfiles.OpFilesError):
            opfiles.export("0.9.26", path)

    def test_export_by_default_goes_to_the_sudo_users_home(self):
        home = self.tmp / "home"
        home.mkdir()
        fake = mock.Mock(pw_dir=str(home), pw_uid=os.getuid(), pw_gid=os.getgid())
        with mock.patch.object(opfiles.pwd, "getpwnam", return_value=fake):
            path = opfiles.export("0.9.26", None, "someone")
        self.assertEqual(pathlib.Path(path).parent, home)
        self.assertTrue(pathlib.Path(path).name.startswith("qmcp-export-"))

    def fresh(self):
        """This install as a fresh one: no project record, no gateway."""
        os.unlink(projects.PROJECTS_PATH)
        os.unlink(gateways.GATEWAYS_PATH)

    def test_an_export_comes_back_whole_on_a_fresh_install(self):
        before = {n: pathlib.Path(p).read_text() for n, p in opfiles._paths().items()
                  if os.path.exists(p) and n not in ("hub", "mode")}
        path = opfiles.export("0.9.26", self.export_path())
        self.fresh()
        pathlib.Path(budget.CAP_PATH).write_text("1\n")
        opfiles.import_(path)
        for n, text in before.items():
            p = opfiles._paths()[n]
            if n.endswith(".json"):
                self.assertEqual(json.loads(pathlib.Path(p).read_text()), json.loads(text), n)
            else:
                self.assertEqual(pathlib.Path(p).read_text().strip(), text.strip(), n)

    def test_import_refuses_a_populated_install_another_hub_mode_or_file(self):
        path = opfiles.export("0.9.26", self.export_path())
        with self.assertRaises(opfiles.OpFilesError) as cm:
            opfiles.import_(path)
        self.assertIn("fresh install", str(cm.exception))
        self.fresh()
        doc = json.loads(pathlib.Path(path).read_text())
        bad = []
        for change in (lambda d: d["files"].update(hub="other-hub\n"),
                       lambda d: d.update(format="something-else"),
                       lambda d: d["files"].update({"projects.json": "{"}),
                       lambda d: d["files"].update({"pool-cap": "0\n"}),
                       lambda d: d["files"].update({"birth-egress": "not-enrolled\n"})):
            d = json.loads(json.dumps(doc))
            change(d)
            p = self.tmp / f"bad{len(bad)}.json"
            p.write_text(json.dumps(d))
            bad.append(p)
        for p in bad:
            with self.assertRaises(opfiles.OpFilesError, msg=p.name):
                opfiles.import_(str(p))
        self.assertFalse(os.path.exists(projects.PROJECTS_PATH))

    def test_an_anonymous_export_goes_onto_a_normal_install_and_not_the_other_way(self):
        path = opfiles.export("0.9.26", self.export_path())
        doc = json.loads(pathlib.Path(path).read_text())
        doc["files"]["mode"] = "anonymous\n"
        anon = self.tmp / "anon.json"
        anon.write_text(json.dumps(doc))
        self.fresh()
        out = opfiles.import_(str(anon))
        self.assertIn("install.sh --anonymous", out[-1])
        # An ordinary export onto an install in anonymous mode is refused.
        os.unlink(projects.PROJECTS_PATH)
        os.unlink(gateways.GATEWAYS_PATH)
        pathlib.Path(core.MODE_PATH).write_text("anonymous\n")
        with self.assertRaises(opfiles.OpFilesError) as cm:
            opfiles.import_(path)
        self.assertIn("anonymous mode", str(cm.exception))

    def test_birth_egress_refuses_a_held_gateway(self):
        self.app.domains["ai-net-router"].tags.add(core.QUARANTINE)
        with self.assertRaises(opfiles.OpFilesError) as cm:
            opfiles.settings_set(self.app, birth_egress="ai-net-router")
        self.assertIn("held", str(cm.exception))

    def test_the_cli_lines(self):
        rc, out, _ = self.cli("settings", "set", "--pool-cap", "800G")
        self.assertEqual(rc, 0, out)
        line = self.audit_lines()[-1]
        self.assertEqual((line["service"], line["args"]["pool_cap"]), ("qmcp settings set", "set"))
        rc, out, _ = self.cli("export", str(self.tmp / "e.json"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.audit_lines()[-1]["service"], "qmcp export")
        before = len(self.audit_lines())
        self.cli("settings", "--json", root=False)
        self.cli("restored", "list", root=False)
        self.assertEqual(len(self.audit_lines()), before)

    def test_the_root_commands_refuse_a_non_root_user(self):
        for argv in (("settings", "set", "--pool-cap", "1G"), ("export",), ("import", "x"),
                     ("restored", "accept", "--all"), ("restored", "reject", "x"),
                     ("template", "prepare", "x")):
            rc, _, err = self.cli(*argv, root=False)
            self.assertIn("run as root", str(rc) + err, argv)


class Seed(ToolsBase):
    """The installer's seed program itself, cut out of install.sh and run
    against the fake: what it labels on each path, and that a seed which
    stopped part-way runs again."""

    TEXT = (HERE.parent / "deploy" / "install.sh").read_text()
    _start = TEXT.index("<<'PYEOF'\n", TEXT.index('SEEDED="$(')) + len("<<'PYEOF'\n")
    PROGRAM = TEXT[_start:TEXT.index("\nPYEOF\n", _start) + 1]

    def seed(self, mode, pending=False):
        import types
        qa = types.ModuleType("qubesadmin")
        qa.app = types.ModuleType("qubesadmin.app")
        qa.app.QubesLocal = lambda: self.app
        out = io.StringIO()
        self.marker = self.tmp / "SEED-PENDING"
        env = {"QMCP_SEED": mode, "QMCP_SEED_PENDING": "1" if pending else "0",
               "QMCP_SEED_MARKER": str(self.marker)}
        with mock.patch.dict(sys.modules, {"qubesadmin": qa, "qubesadmin.app": qa.app}), \
                mock.patch.dict(os.environ, env), redirect_stdout(out):
            try:
                exec(compile(self.PROGRAM, "install.sh seed", "exec"), {"__name__": "__main__"})
                rc = 0
            except SystemExit as e:
                rc = e.code or 0
        return rc, out.getvalue()

    def unlabelled(self, *names):
        for n in names:
            self.app.vm(n, netvm=None, tags={"ai-managed", "qmcp-proj-p00"}, labelled=False)

    def test_the_second_path_seeds_nothing_on_a_box_that_carries_a_label(self):
        self.unlabelled("ai-kept")
        rc, out = self.seed("2")
        self.assertEqual(rc, 0)
        self.assertIn("no seed", out)
        self.assertIsNone(self.label("ai-kept"))
        # The second path's marker goes on only once its guard has passed.
        self.assertFalse(self.marker.exists())
        # Teeth: the first path labels it.
        self.assertEqual(self.seed("1"), (0, "labelled 1 qube(s)\n"))
        self.assertEqual(self.label("ai-kept"), self.uuid("ai-kept"))

    def test_a_seed_that_stopped_part_way_runs_again_on_the_second_path(self):
        self.unlabelled("ai-a", "ai-b")
        for vm in self.app.domains:
            if vm.name not in ("ai-a", "ai-b"):
                dict.pop(vm.features, core.ID_FEATURE, None)
        real = restored.label

        def label(vm):
            if vm.name == "ai-b":
                raise RuntimeError("qubesd went away")
            return real(vm)
        with mock.patch.object(restored, "label", label):
            rc, out = self.seed("2")
        self.assertEqual(rc, 1, out)
        self.assertIn("NOT labelled: ai-b", out)
        self.assertIsNone(self.label("ai-b"))
        # Without the marker the next run reads the labels it wrote as a box
        # that ran 0.9.26, and stops.
        self.assertIn("no seed", self.seed("2")[1])
        self.assertIsNone(self.label("ai-b"))
        # With it, the next run finishes the seed.
        rc, out = self.seed("2", pending=True)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.label("ai-b"), self.uuid("ai-b"))
        self.assertTrue(self.marker.exists())

    def test_the_seed_leaves_a_held_qube_alone_and_a_hold_stops_the_second_path(self):
        self.unlabelled("ai-free")
        self.app.vm("ai-held-nl", netvm=None, tags={"ai-managed", core.QUARANTINE},
                    labelled=False)
        for vm in self.app.domains:
            if vm.name not in ("ai-free", "ai-held-nl"):
                dict.pop(vm.features, core.ID_FEATURE, None)
        rc, out = self.seed("2")
        self.assertIn("no seed", out)
        self.assertIsNone(self.label("ai-free"))
        rc, out = self.seed("1")
        self.assertEqual(rc, 0, out)
        self.assertIn("ai-held-nl held for review, left as they are", out)
        self.assertIsNone(self.label("ai-held-nl"))
        self.assertEqual(self.label("ai-free"), self.uuid("ai-free"))

    def test_a_read_the_seed_cannot_make_is_reported_apart_from_a_write(self):
        self.app.vm("ai-other-label", netvm=None, tags={"ai-managed"},
                    features={core.ID_FEATURE: "other"})
        self.app.fail.add("feature.get:ai-other-label")
        rc, out = self.seed("1")
        self.assertEqual(rc, 1, out)
        self.assertIn("could not be read: ai-other-label", out)
        self.assertNotIn("NOT labelled", out)

    def test_the_preflight_refuses_a_held_updates_via_gateway_before_any_change(self):
        # Ticking it later goes through `qmcp gateway set`, which refuses a held
        # gateway: found then, the install would stop halfway, every time.
        opener = self.TEXT.index("<<'PYEOF'", self.TEXT.index('QMCP_UPDATES_VIA="$UPDATES_VIA"'))
        start = self.TEXT.index("\n", opener) + 1
        program = self.TEXT[start:self.TEXT.index("\nPYEOF\n", start) + 1]
        self.assertIn('os.environ["QMCP_UPDATES_VIA"]', program)
        registry = gateways.load()
        registry["ai-net-router"] = gateways.Gateway("ai-net-router", True, "", "sys-firewall")
        gateways.save(registry)

        def run():
            import types
            qa = types.ModuleType("qubesadmin")
            qa.app = types.ModuleType("qubesadmin.app")
            qa.app.QubesLocal = lambda: self.app
            env = {"QMCP_HUB": HUB, "QMCP_ANONYMOUS": "0", "QMCP_UPDATES_VIA": "ai-net-router"}
            err = io.StringIO()
            with mock.patch.dict(sys.modules, {"qubesadmin": qa, "qubesadmin.app": qa.app}), \
                    mock.patch.dict(os.environ, env), redirect_stderr(err), \
                    redirect_stdout(io.StringIO()), mock.patch.object(core, "read_hub"):
                try:
                    exec(compile(program, "install.sh preflight", "exec"),
                         {"__name__": "__main__"})
                    rc = 0
                except SystemExit as e:
                    rc = e.code or 0
            return rc, err.getvalue()
        # Teeth: the same gateway, not held, passes the whole preflight.
        self.assertEqual(run(), (0, ""))
        self.app.domains["ai-net-router"].tags.add(core.QUARANTINE)
        rc, err = run()
        self.assertEqual(rc, 1, err)
        self.assertIn("--updates-via ai-net-router: held for your review", err)

    def test_the_marker_is_written_before_the_first_change_and_removed_after_the_version(self):
        marker = self.TEXT.index(': > "$LIB/SEED-PENDING"')
        self.assertIn('if [ "$SEED_LABELS" -eq 1 ]; then\n    install -d -m 0755 "$LIB"\n'
                      '    : > "$LIB/SEED-PENDING"', self.TEXT)
        self.assertIn('QMCP_SEED_MARKER="$LIB/SEED-PENDING"', self.TEXT)
        self.assertLess(self.TEXT.index('say "dry run: nothing was changed"'), marker)
        self.assertLess(marker, self.TEXT.index("# ===================================================================== install"))
        seed = self.TEXT.index("SEEDED=", marker)
        version = self.TEXT.index('> "$LIB/VERSION"')
        removed = self.TEXT.index('rm -f "$LIB/SEED-PENDING"')
        self.assertLess(self.TEXT.index('[ -e "$LIB/SEED-PENDING" ]'), marker)
        self.assertLess(marker, seed)
        self.assertLess(seed, version)
        self.assertLess(version, removed)


class Install(unittest.TestCase):
    """The installer labels existing AI space once, on an upgrade from before
    0.9.26, while the gate's timer is stopped, and never on a fresh install."""

    TEXT = (HERE.parent / "deploy" / "install.sh").read_text()

    def seed_for(self, prev, kept_files=False, legacy=0, pending=False):
        start = self.TEXT.index("SEED_LABELS=0")
        block = self.TEXT[start:self.TEXT.index("# (end of the seed decision)", start)]
        etc = self.tmp_etc(kept_files)
        lib = self.tmp_etc(False)
        if pending:
            (lib / "SEED-PENDING").write_text("")
        script = (f'ETC_QMCP="{etc}"\nLIB="{lib}"\nPREV_VERSION="{prev}"\nLEGACY_LEFT={legacy}\n'
                  f'{block}\necho "$SEED_LABELS"\n')
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              check=True).stdout.strip()

    def tmp_etc(self, kept_files):
        import tempfile
        d = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-etc-"))
        self.addCleanup(shutil.rmtree, d)
        if kept_files:
            (d / "hub").write_text("mcp-control\n")
        return d

    def test_the_seed_runs_only_on_an_upgrade_from_before_0_9_26(self):
        for prev, want in (("0.9.25", "1"), ("0.9.9", "1"), ("0.9.17", "1"), ("0.9.26", "0"),
                           ("0.9.30", "0"), ("1.0.0", "0"), ("", "0"), ("unknown", "0")):
            self.assertEqual(self.seed_for(prev), want, prev)

    def test_v0_9_16_which_wrote_no_version_file_is_known_by_its_files(self):
        self.assertEqual(self.seed_for("", legacy=3), "1")
        self.assertEqual(self.seed_for("", legacy=0), "0")
        self.assertEqual(self.seed_for("0.9.26", legacy=3), "0")
        self.assertIn("fleet.LEGACY_PATHS", self.TEXT[:self.TEXT.index("SEED_LABELS=0")])

    def test_a_seed_an_earlier_install_did_not_finish_runs_again(self):
        # The v0.9.16 files are gone once removed, and the labels a seed wrote
        # read as a box that ran 0.9.26: the marker carries the seed over.
        self.assertEqual(self.seed_for("", pending=True), "2")
        self.assertEqual(self.seed_for("", kept_files=True, pending=True), "2")
        self.assertEqual(self.seed_for("0.9.25", pending=True), "1")
        self.assertEqual(self.seed_for("0.9.26", pending=True), "0")

    def test_a_reinstall_over_kept_operator_files_may_seed(self):
        # A plain uninstall removes the version file and keeps /etc/qmcp: the
        # installer then asks the seed to run if no qube carries a label yet.
        self.assertEqual(self.seed_for("", kept_files=True), "2")
        self.assertEqual(self.seed_for("0.9.26", kept_files=True), "0")

    def test_the_seed_runs_while_the_gates_timer_is_stopped(self):
        stop = self.TEXT.index("systemctl stop qmcp-gate.timer")
        seed = self.TEXT.index('SEEDED="$(')
        start = self.TEXT.rindex("systemctl start qmcp-gate.timer")
        self.assertLess(stop, seed)
        self.assertLess(seed, start)

    def test_every_library_name_the_installers_call_exists(self):
        # The Python inside the installers runs only on a box; a name removed
        # from the library fails there and nowhere else.
        import importlib
        import re
        for script in ("install.sh", "uninstall.sh"):
            text = (HERE.parent / "deploy" / script).read_text()
            heredocs = re.findall(r"<<'PYEOF'[^\n]*\n(.*?)\nPYEOF\n", text, re.S)
            self.assertEqual(len(heredocs), text.count("<<'PYEOF'"), script)
            code = heredocs + re.findall(r"python3 -c '([^']*)'", text)
            if script == "install.sh":
                self.assertGreater(len(heredocs), 4)
            for body in code:
                for mod in set(re.findall(r"from qmcp import ([\w, ]+)", body)):
                    for m in (x.strip() for x in mod.split(",")):
                        module = importlib.import_module(f"qmcp.{m}")
                        for name in set(re.findall(rf"\b{m}\.([A-Za-z_]\w*)", body)):
                            self.assertTrue(hasattr(module, name), f"{script}: {m}.{name}")
                for m, names in re.findall(r"from qmcp\.(\w+) import ([\w, ]+)", body):
                    module = importlib.import_module(f"qmcp.{m}")
                    for name in (x.strip() for x in names.split(",")):
                        self.assertTrue(hasattr(module, name), f"{script}: qmcp.{m}.{name}")

    def test_dom0_keeps_the_in_qube_services_and_the_uninstaller_removes_them(self):
        self.assertIn('"$LIB/template-rpc/"', self.TEXT)
        un = (HERE.parent / "deploy" / "uninstall.sh").read_text()
        self.assertIn('rm -rf "$LIB"', un)
        for unit in ("qmcp-refresh.timer", "qmcp-refresh.service"):
            self.assertIn(unit, un)
            self.assertIn(unit, self.TEXT)


if __name__ == "__main__":
    unittest.main()
