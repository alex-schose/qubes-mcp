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
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import (anon, audit, birth, budget, cli, core, fleet, gateways, inqube, opfiles,  # noqa: E402
                  projects, proposals, restored, services)
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


# ======================================================================= seals

class SealExit(ToolsBase):
    """A seal whose kill was not read back exits 3, named or swept (a named
    seal for its own kill, a sweep for any), unless the kill failed on the
    seal's second wait, which exits 1: the window's badges are off, but what
    the hub started may still run."""

    def setUp(self):
        super().setUp()
        self.app.domains["ai-tpl-g"].__dict__["_power"] = "Running"
        fleet.open_window(self.app, "ai-tpl-g", 3600)
        self.app.fail.add("kill")

    def test_a_named_seal_whose_kill_fails_exits_3(self):
        rc, out, _ = self.cli("seal", "ai-tpl-g")
        self.assertEqual(rc, 3, out)
        self.assertIn("could NOT be killed", out)

    def test_a_sweep_with_a_pending_kill_exits_3_until_it_is_made(self):
        self.assertEqual(self.cli("seal", "--all")[0], 3)
        self.assertEqual(self.cli("seal", "--expired")[0], 3)
        self.app.fail.discard("kill")
        self.assertEqual(self.cli("seal", "--expired")[0], 0)

    def test_check_fails_on_a_window_directory_the_services_cannot_write(self):
        self.app.fail.discard("kill")
        os.chmod(fleet.WINDOW_DIR, 0o2750)
        self.addCleanup(os.chmod, fleet.WINDOW_DIR, 0o2770)
        f = {x.check: x for x in fleet.check(self.app, legacy_paths=(),
                                              system_info={"domains": {}})}
        self.assertEqual(f["runtime dir"].status, "fail")
        self.assertIn(str(fleet.WINDOW_DIR), f["runtime dir"].detail)


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
        self.assertEqual(r, {"qube": "ai-debian-13", "version": self.version, "started": True,
                             "stopped": True})
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

    def test_the_stop_after_a_prepare_is_reported_as_it_went(self):
        tpl = self.app.domains["ai-debian-13"]
        # A stop that raises while the qube keeps running: not "shut down
        # again", and the command exits 1 naming what to do.
        self.app.fail.add("shutdown")
        rc, out, err = self.cli("template", "prepare", "ai-debian-13")
        self.app.fail.discard("shutdown")
        self.assertEqual(rc, 1)
        self.assertNotIn("shut down again", out)
        self.assertIn("did not complete", out)
        self.assertEqual(tpl.get_power_state(), "Running")
        tpl.kill()
        # A stop that raises for a qube already halted (killed meanwhile) has
        # still left it stopped.
        def raced(vm, force=False, wait=False):
            vm._went_down()
            raise RuntimeError("QubesVMNotStartedError")
        with mock.patch.object(type(tpl), "shutdown", raced):
            r = inqube.prepare(self.app, "ai-debian-13")
        self.assertEqual((r["started"], r["stopped"]), (True, True))
        rc, out, err = self.cli("template", "prepare", "ai-debian-13")
        self.assertEqual(rc, 0, err)
        self.assertIn("shut down again", out)

    def test_a_lookup_that_fails_is_not_a_missing_qube(self):
        for argv in (("template", "prepare", "ai-debian-13"),
                     ("template", "install", "ai-tpl-g", "curl")):
            with self.subTest(argv=argv):
                self.app.fail_reads(f"lookup:{argv[2]}", "fail")
                rc, out, err = self.cli(*argv)
                self.assertEqual(self.app.failed[f"lookup:{argv[2]}"], 1)
                self.assertEqual(rc, 1)
                self.assertIn("cannot be looked up", err)
                self.assertNotIn("no qube", err)
                self.app.failed.clear()
        self.assertEqual(self.app.domains["ai-tpl-g"].installed_packages(), [])

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

    def test_a_copy_made_while_its_source_ran_is_brought_up_to_date(self):
        # A copy of a running qube is labelled UNKNOWN, never a version: the
        # check reads it as behind, and the refresh writes into it once it runs.
        sa = self.app.vm("ai-copy", klass="StandaloneVM", power="Running", tags={"ai-managed"},
                         features={inqube.LABEL: inqube.UNKNOWN})
        self.assertEqual(inqube.label_state(sa, self.version), "behind")
        self.assertEqual(dict(inqube.refresh(self.app)).get("ai-copy"), "updated")
        self.assertEqual((dict.get(sa.features, inqube.LABEL), sa.rpc_files()),
                         (self.version, self.files))

    def test_after_copy_keeps_a_halted_source_s_label_only(self):
        def copy_of(src_power, label="sha256:x", src_label="sha256:x", before=True):
            src = self.app.vm(f"ai-s-{len(self.app.domains._vms)}", klass="TemplateVM",
                              power=src_power, features={inqube.LABEL: src_label})
            vm = self.app.vm(f"ai-c-{len(self.app.domains._vms)}", klass="StandaloneVM",
                             features={inqube.LABEL: label})
            inqube.after_copy(vm, src, before)
            return dict.get(vm.features, inqube.LABEL)
        self.assertEqual(copy_of("Halted"), "sha256:x")
        # Running before the copy, or started during it, or relabelled during it:
        # the root may not hold what the label says.
        self.assertEqual(copy_of("Halted", before=False), inqube.UNKNOWN)
        self.assertEqual(copy_of("Running"), inqube.UNKNOWN)
        self.assertEqual(copy_of("Halted", src_label="sha256:y"), inqube.UNKNOWN)
        bare = self.app.vm("ai-c-bare", klass="StandaloneVM")
        inqube.after_copy(bare, self.app.domains["ai-debian-13"], False)
        self.assertNotIn(inqube.LABEL, dict.keys(bare.features))
        # A power state that cannot be read is not halted: qubesadmin's "NA",
        # or a read that raises.
        gone = self.app.vm("ai-c-gone", klass="StandaloneVM")
        self.app.domains._drop("ai-c-gone")
        self.assertFalse(inqube.halted(gone))

        class Raises:
            def get_power_state(self):
                raise RuntimeError("qubesd did not answer")
        self.assertFalse(inqube.halted(Raises()))

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

    def test_a_refresh_cut_short_has_a_line_for_every_qube_it_wrote(self):
        qs = [self.app.vm(f"s-behind-{i}", klass="StandaloneVM", power="Running",
                          tags={"ai-managed"}, features={inqube.LABEL: "sha256:old"})
              for i in range(4)]
        real, calls = inqube._push, []

        def push(vm, files, timeout):
            calls.append(vm.name)
            if len(calls) == 3:
                raise KeyboardInterrupt                         # the unit is killed here
            return real(vm, files, timeout)
        before = len(self.audit_lines())
        with mock.patch.object(inqube, "_push", push):
            with self.assertRaises(KeyboardInterrupt):
                self.cli("template", "refresh", root=False)
        written = sorted(q.name for q in qs if dict.get(q.features, inqube.LABEL) != "sha256:old")
        lines = sorted(l["args"]["qube"] for l in self.audit_lines()[before:]
                       if l["caller"] == "refresh")
        self.assertEqual(len(written), 2)
        self.assertEqual(lines, written)

    def test_a_refresh_whose_label_fails_says_it_wrote_and_logs_it(self):
        self.fleet_for_refresh()
        self.app.fail.add("feature.set")
        before = len(self.audit_lines())
        seen = []
        inqube.refresh(self.app, done=lambda n, o, w: seen.append((n, o, w)))
        self.app.fail.clear()
        self.assertTrue(any(w and o.startswith("written, but its label was not")
                            for _, o, w in seen), seen)
        self.cli("template", "refresh", root=False)             # written again, and logged
        self.assertTrue(len(self.audit_lines()) > before)

    def test_a_refresh_starts_no_write_past_its_budget(self):
        self.fleet_for_refresh()
        done = dict(inqube.refresh(self.app, budget_s=0))
        self.assertTrue(done and all("ran out" in o for o in done.values()), done)

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
        self.assertIn("another version of them than the installed one in ai-debian-13",
                      self.findings()[0][2])
        # Never "older": after a rollback the label names a newer version.
        self.assertNotIn("older", self.findings()[0][2])

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

class PrepareStop(ToolsBase):
    def test_a_failed_prepare_says_when_the_template_it_started_did_not_stop(self):
        tpl = self.app.vm("tpl-hostile", klass="TemplateVM")
        self.app.vmshell[tpl.name] = "exit1"          # the write fails
        self.app.fail.add("shutdown")                 # and so does the shutdown
        rc, out, err = self.cli("template", "prepare", "tpl-hostile")
        self.assertEqual(rc, 1)
        self.assertIn("the write exited 1", err)
        self.assertIn("its shutdown did not complete", err)
        self.assertEqual(tpl.get_power_state(), "Running")
        self.app.fail.clear()
        tpl.shutdown()
        rc, out, err = self.cli("template", "prepare", "tpl-hostile")
        self.assertNotIn("shutdown did not complete", err)     # stopped: only the failure
        self.assertEqual(tpl.get_power_state(), "Halted")


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

    def waits(self, lock, settle):
        for attr, value in (("HOLD_LOCK_WAIT_S", lock), ("HOLD_SETTLE_WAIT_S", settle)):
            self.addCleanup(setattr, restored, attr, getattr(restored, attr))
            setattr(restored, attr, value)

    def hold_lock_then(self, name, after, then):
        """A call holding `name`'s lock that does `then` after `after` seconds
        and then finishes."""
        fd = core.acquire_qube_lock(name, 1)

        def run():
            time.sleep(after)
            then()
            os.close(fd)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        return t

    def test_the_holds_waits_are_bounded_in_all_whatever_is_in_flight(self):
        # A call keeps the lock of every qube to be held: the pass waits for
        # qube locks only until its budget is spent, holds the rest without,
        # and settles them together, so its time does not grow with the
        # number of qubes AI space keeps busy.
        self.waits(0.4, 0.4)
        self.addCleanup(setattr, restored, "HOLD_PASS_S", restored.HOLD_PASS_S)
        restored.HOLD_PASS_S = 0.6
        pick = [vm for vm in self.app.domains if core.UMBRELLA in vm.tags.raw()
                and vm.klass == "AppVM" and core.QUARANTINE not in vm.tags.raw()][:6]
        self.assertGreaterEqual(len(pick), 4)
        fds = []
        for vm in pick:
            vm.features[core.ID_FEATURE] = "00000000-0000-0000-0000-000000000000"
            fds.append(core.acquire_qube_lock(vm.name, 1.0))
        self.addCleanup(lambda: [os.close(fd) for fd in fds if fd is not None])
        started = time.monotonic()
        held = restored.hold(self.app)
        took = time.monotonic() - started
        self.assertLess(took, 0.6 + 0.4 + 0.5)            # the budget, one settle, slack
        self.assertEqual(sorted(held.unsettled), sorted(vm.name for vm in pick))
        for vm in pick:
            self.assertIn(core.QUARANTINE, vm.tags.raw())

    def test_the_gate_judges_the_anonymous_projects_before_the_restore_check(self):
        order = []
        real_run, real_hold = anon.run, restored.hold
        self.addCleanup(setattr, anon, "run", real_run)
        self.addCleanup(setattr, restored, "hold", real_hold)
        anon.run = lambda *a, **k: (order.append("anon"), real_run(*a, **k))[1]
        restored.hold = lambda *a, **k: (order.append("hold"), real_hold(*a, **k))[1]
        self.cli("gate", "--json", root=False)
        self.assertEqual(order, ["anon", "hold"])

    def test_a_hold_without_the_lock_on_a_qube_rejected_meanwhile_comes_off(self):
        # The reject holds the qube's lock throughout, so the pass holds
        # without it and cannot settle under it either: it still judges the
        # qube, and a qube out of AI space is never left held.
        self.restore_worker()
        real, calls = core.acquire_qube_lock, []

        def busy(name, timeout=None, queue=False):
            if name == "ai-osint-w9":
                calls.append(name)
                if len(calls) == 1:
                    restored._reject(self.app, "ai-osint-w9")
                return None
            return real(name, timeout, queue)
        with mock.patch.object(core, "acquire_qube_lock", busy):
            held = restored.hold(self.app)
        self.assertNotIn("ai-osint-w9", held.held)
        self.assertEqual(self.tags("ai-osint-w9") & {core.QUARANTINE, core.UMBRELLA}, set())

    def test_a_remove_in_flight_when_the_hold_went_on_is_reported_not_held(self):
        self.waits(0.1, 3.0)
        self.restore_worker()
        self.hold_lock_then("ai-osint-w9", 0.5, lambda: self.app.domains.__delitem__("ai-osint-w9"))
        held = restored.hold(self.app)
        self.assertEqual(held.gone, ["ai-osint-w9"])
        self.assertEqual(held.held, [])

    def test_a_remove_that_landed_before_the_hold_is_gone_not_failed(self):
        self.restore_worker()
        app = self.app

        def removed_first(tag):
            # A remove already running lands just before the hold's own write.
            app.domains.__delitem__("ai-osint-w9")
            raise RuntimeError("gone")
        self.app.domains["ai-osint-w9"].tags.add = removed_first
        held = restored.hold(self.app)
        self.assertEqual((held.gone, held.failed, held.held), (["ai-osint-w9"], [], []))

    def test_a_hold_made_without_the_lock_is_read_back_once_it_is_had(self):
        self.waits(0.1, 3.0)
        vm = self.restore_worker()
        call = self.hold_lock_then("ai-osint-w9", 0.5, lambda: vm.tags.discard(core.QUARANTINE))
        held = restored.hold(self.app)
        call.join(5)                                    # what the call did has landed
        self.assertEqual(held.held, ["ai-osint-w9"])
        self.assertIn(core.QUARANTINE, self.tags("ai-osint-w9"))

    def test_an_accept_between_the_passs_read_and_its_hold_wins(self):
        # The operator was told "accepted": the pass must not hold it after.
        vm = self.restore_worker()
        real_known, said = restored.known, []

        def known(q):
            answer = real_known(q)
            if q.name == "ai-osint-w9" and not said:
                said.append(restored.accept(self.app, "ai-osint-w9"))
            return answer
        self.addCleanup(setattr, restored, "known", real_known)
        restored.known = known
        held = restored.hold(self.app)
        self.assertIn("accepted", said[0])
        self.assertEqual(held.held, [])
        self.assertNotIn(core.QUARANTINE, self.tags("ai-osint-w9"))
        self.assertTrue(restored.labelled(vm))

    def test_an_accept_in_flight_when_the_hold_went_on_without_the_lock_wins(self):
        self.waits(0.1, 3.0)
        vm = self.restore_worker()
        call = self.hold_lock_then("ai-osint-w9", 0.5, lambda: restored.label(vm))
        held = restored.hold(self.app)
        call.join(5)
        self.assertEqual(held.held, [])
        self.assertNotIn(core.QUARANTINE, self.tags("ai-osint-w9"))

    def test_a_hold_whose_call_outlasts_both_waits_says_so(self):
        self.waits(0.1, 0.1)
        self.restore_worker()
        fd = core.acquire_qube_lock("ai-osint-w9", 1)
        self.addCleanup(os.close, fd)
        held = restored.hold(self.app)
        self.assertEqual((held.held, held.unsettled), (["ai-osint-w9"], ["ai-osint-w9"]))
        self.assertIn(core.QUARANTINE, self.tags("ai-osint-w9"))

    def test_a_reject_that_went_on_without_the_lock_says_so(self):
        self.restore_worker()
        restored.hold(self.app)
        fd = core.acquire_qube_lock("ai-osint-w9", 1)
        self.addCleanup(os.close, fd)
        self.assertIn("went on without it", restored.reject(self.app, "ai-osint-w9"))

    def test_a_hand_copy_is_held_and_an_unlabelled_badged_qube_too(self):
        self.app.clone_vm(self.app.domains["ai-hubq"], "ai-hubq-copy")
        self.app.vm("ai-tagged-by-hand", netvm=None, tags={"ai-managed"}, labelled=False)
        held = restored.hold(self.app)
        self.assertEqual(sorted(held.held), ["ai-hubq-copy", "ai-tagged-by-hand"])
        self.assertNotIn(core.QUARANTINE, self.tags("ai-hubq"))

    # A hand copy of a qube qmcp made carries its owner badge, which would let
    # the hub remove the operator's copy (often a backup). The pass decides once
    # per qube waiting for review, after the hold: a proven restore keeps the
    # badge and is recorded by its own UUID (qmcp-owner-kept), anything else
    # loses it. Accept keeps a badge only where that record names the qube.

    GONE_UUID = "6a0b0b5e-0000-4000-8000-000000000000"

    def hub_made(self, name="ai-hub-src"):
        return self.app.vm(name, template=self.app.domains["ai-debian-13"], netvm=None,
                           tags={"ai-managed", "qmcp-proj-p00", birth.owner_tag(HUB)})

    def restore_of_gone(self, name="ai-hub-back"):
        vm = self.hub_made(name)
        vm.features[core.ID_FEATURE] = self.GONE_UUID
        return vm

    def hub_remove(self, name):
        return self.call("qmcp.LifecycleAIManaged", {"name": name, "action": "remove"})

    def owned(self, name):
        return birth.owner_tag(HUB) in self.tags(name)

    def kept(self, name):
        return dict.get(self.app.domains[name].features, restored.KEPT)

    def test_a_hand_copy_loses_its_owner_badge_at_the_hold_and_the_hub_cannot_remove_it(self):
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.assertTrue(self.owned("ai-hub-src-copy"))           # the platform copied it
        held = restored.hold(self.app)
        self.assertEqual((held.held, held.unowned), (["ai-hub-src-copy"], ["ai-hub-src-copy"]))
        self.assertFalse(self.owned("ai-hub-src-copy"))
        self.assertTrue(self.owned("ai-hub-src"))                 # the source keeps its own
        lines = [l for l in self.audit_lines() if l["args"].get("qube") == "ai-hub-src-copy"]
        self.assertEqual([("owner badge" in l["args"], l["ok"]) for l in lines],
                         [(False, True), (True, True)])            # held first, then decided
        self.assertNotIn("held", lines[1]["args"])
        # Removing the source afterwards changes nothing: the decision was made.
        del self.app.domains["ai-hub-src"]
        self.assertIn("its badges stay", restored.accept(self.app, "ai-hub-src-copy"))
        self.assertFalse(self.owned("ai-hub-src-copy"))
        r = self.hub_remove("ai-hub-src-copy")
        self.assertIn("qmcp did not create", r["error"])
        self.assertIn("ai-hub-src-copy", self.app.domains)

    def test_the_hub_cannot_remove_a_hand_copy_before_the_pass_holds_it(self):
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.assertNotIn(core.QUARANTINE, self.tags("ai-hub-src-copy"))
        self.assertEqual(self.hub_remove("ai-hub-src-copy"), core.QUARANTINE_REFUSAL)
        self.assertIn("ai-hub-src-copy", self.app.domains)
        # Nor its source while the copy waits (removed first, it would make
        # the copy read as a restore); the positive: a qube with no copy.
        self.assertIn("waits for the operator's review", self.hub_remove("ai-hub-src")["error"])
        self.hub_made("ai-hub-other")
        self.assertTrue(self.hub_remove("ai-hub-other")["ok"])

    def test_a_restore_whose_original_is_gone_keeps_its_owner_badge(self):
        self.restore_of_gone()
        held = restored.hold(self.app)
        self.assertEqual((held.held, held.unowned, held.owner_kept),
                         (["ai-hub-back"], [], ["ai-hub-back"]))
        self.assertTrue(self.owned("ai-hub-back"))
        self.assertEqual(self.kept("ai-hub-back"), self.uuid("ai-hub-back"))
        self.assertIn("its badges stay", restored.accept(self.app, "ai-hub-back"))
        self.assertTrue(self.hub_remove("ai-hub-back")["ok"])
        self.assertNotIn("ai-hub-back", self.app.domains)

    def test_a_copy_of_a_held_restore_loses_it_and_the_restore_keeps_its_own(self):
        self.restore_of_gone("ai-hub-back")
        restored.hold(self.app)
        # The copy carries the hold, the label and the record, under a new UUID.
        self.app.clone_vm(self.app.domains["ai-hub-back"], "ai-hub-back-copy")
        self.assertIn(core.QUARANTINE, self.tags("ai-hub-back-copy"))
        self.assertEqual(self.kept("ai-hub-back-copy"), self.uuid("ai-hub-back"))
        held = restored.hold(self.app)
        self.assertEqual((held.unowned, held.owner_kept), (["ai-hub-back-copy"], []))
        self.assertFalse(self.owned("ai-hub-back-copy"))
        self.assertTrue(self.owned("ai-hub-back"))
        for n in ("ai-hub-back", "ai-hub-back-copy"):
            restored.accept(self.app, n)
        self.assertIn("qmcp did not create", self.hub_remove("ai-hub-back-copy")["error"])
        self.assertTrue(self.hub_remove("ai-hub-back")["ok"])

    def test_a_copy_of_a_decided_restore_accepted_before_the_next_pass_loses_it(self):
        # The original is accepted (its label becomes its own UUID) before the
        # pass that decides the copy: the copy's label is then worn by no qube
        # and names none, so only dom0's record of the replaced label, and the
        # copied record naming a qube that exists, tell it is a copy.
        self.restore_of_gone("ai-hub-back")
        restored.hold(self.app)
        self.app.clone_vm(self.app.domains["ai-hub-back"], "ai-hub-back-copy")
        restored.accept(self.app, "ai-hub-back")
        held = restored.hold(self.app)
        self.assertEqual((held.unowned, held.owner_kept), (["ai-hub-back-copy"], []))
        restored.accept(self.app, "ai-hub-back-copy")
        self.assertIn("qmcp did not create", self.hub_remove("ai-hub-back-copy")["error"])

    def test_the_hub_removing_the_accepted_original_first_leaves_the_copy_without_it(self):
        # The evidence is dom0's (`REPLACED_PATH`), not the original's: the hub
        # may remove a kept restore once accepted, and that must not turn the
        # operator's copy of it into a restore whose original is gone.
        self.restore_of_gone("ai-hub-back")
        restored.hold(self.app)
        self.app.clone_vm(self.app.domains["ai-hub-back"], "ai-hub-back-copy")
        restored.accept(self.app, "ai-hub-back")
        # The hub cannot remove the original while the copy waits: the guard.
        self.assertIn("waits for the operator's review", self.hub_remove("ai-hub-back")["error"])
        # And were it gone (removed by hand), dom0's record still tells.
        del self.app.domains["ai-hub-back"]
        held = restored.hold(self.app)
        self.assertEqual((held.unowned, held.owner_kept), (["ai-hub-back-copy"], []))
        restored.accept(self.app, "ai-hub-back-copy")
        self.assertIn("qmcp did not create", self.hub_remove("ai-hub-back-copy")["error"])
        self.assertEqual(os.stat(restored.REPLACED_PATH).st_mode & 0o777, 0o644)

    def test_a_record_of_replaced_labels_that_does_not_read_proves_no_restore(self):
        self.restore_of_gone("ai-hub-back")
        os.makedirs(os.path.dirname(restored.REPLACED_PATH), exist_ok=True)
        os.mkdir(restored.REPLACED_PATH)                        # not a file: does not read
        held = restored.hold(self.app)
        self.assertEqual(held.owner_kept, [])
        self.assertFalse(self.owned("ai-hub-back"))

    def test_qmcps_own_clone_of_a_kept_restore_does_not_inherit_its_record(self):
        self.restore_of_gone("ai-hub-back")
        restored.hold(self.app)
        restored.accept(self.app, "ai-hub-back")
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-hub-back", "name": "ai-hub-c"})
        self.assertTrue(r["ok"], r)
        self.assertIsNone(self.kept("ai-hub-c"))

    def test_the_hub_cannot_remove_the_source_of_a_copy_that_waits_for_review(self):
        # Removed first, the source would make the copy read as a restore whose
        # original is gone, keeping the owner badge the hub could then use.
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        r = self.hub_remove("ai-hub-src")
        self.assertIn("a copy of this qube waits for the operator's review", r["error"])
        held = restored.hold(self.app)
        self.assertEqual(held.unowned, ["ai-hub-src-copy"])
        self.assertIn("waits for the operator's review", self.hub_remove("ai-hub-src")["error"])
        restored.accept(self.app, "ai-hub-src-copy")            # reviewed: its own label now
        self.assertTrue(self.hub_remove("ai-hub-src")["ok"])
        self.assertIn("qmcp did not create", self.hub_remove("ai-hub-src-copy")["error"])

    def test_a_copy_still_being_cloned_when_the_hub_removed_its_source_loses_it(self):
        # qubesadmin's clone_vm copies the tags before the label: the remove's
        # check of the copies cannot see a copy in that gap, so dom0's record
        # of the UUIDs AI space removed is what tells.
        src = self.hub_made("ai-hub-src")
        s_uuid = restored._uuid(src)
        c = self.app.vm("ai-hub-src-copy", labelled=False,
                        template=self.app.domains["ai-debian-13"], netvm=None,
                        tags=set(src.tags))
        real = restored.copies_waiting

        def scan_then_clone_finishes(app, vm):
            got = real(app, vm)
            c.features[core.ID_FEATURE] = s_uuid              # clone_vm's feature loop lands
            return got
        with mock.patch.object(restored, "copies_waiting", scan_then_clone_finishes):
            self.assertTrue(self.hub_remove("ai-hub-src")["ok"])
        self.assertIn(s_uuid, restored.removed_uuids())
        held = restored.hold(self.app)
        self.assertEqual((held.unowned, held.owner_kept), (["ai-hub-src-copy"], []))
        restored.accept(self.app, "ai-hub-src-copy")
        self.assertIn("qmcp did not create", self.hub_remove("ai-hub-src-copy")["error"])

    def test_the_removal_record_is_pruned_after_a_week_but_never_while_a_label_names_it(self):
        src = self.hub_made("ai-hub-old")
        s_uuid = restored._uuid(src)
        self.app.clone_vm(src, "ai-hub-old-copy")               # a copy that names it
        self.hub_made("ai-hub-x")
        self.assertTrue(self.hub_remove("ai-hub-x")["ok"])
        old = time.time() - restored.REMOVED_KEEP_S - 60
        for n in os.listdir(restored.REMOVED_DIR):
            os.utime(os.path.join(restored.REMOVED_DIR, n), (old, old))
        pathlib.Path(restored.REMOVED_DIR, s_uuid).touch()       # as if its remove had landed
        os.utime(os.path.join(restored.REMOVED_DIR, s_uuid), (old, old))
        self.assertEqual(restored.prune_removed(self.app), 1)    # ai-hub-x's, not the named one
        self.assertEqual(os.listdir(restored.REMOVED_DIR), [s_uuid])
        # A label that does not read: nothing is pruned at all.
        del self.app.domains["ai-hub-old-copy"]
        self.app.fail_reads("feature.get", "fail")
        self.assertEqual(restored.prune_removed(self.app), 0)

    def test_a_fresh_entry_survives_a_prune_though_no_label_names_it_yet(self):
        # The age is what keeps a copy still between its tags and its label
        # (qubesadmin's clone_vm): its source's entry must outlive the prune.
        src = self.hub_made("ai-hub-src")
        s_uuid = restored._uuid(src)
        self.app.vm("ai-hub-src-copy", labelled=False,
                    template=self.app.domains["ai-debian-13"], netvm=None, tags=set(src.tags))
        restored.record_removed(src)
        del self.app.domains["ai-hub-src"]
        self.assertEqual(restored.prune_removed(self.app), 0)
        self.assertIn(s_uuid, restored.removed_uuids())

    def test_the_hourly_run_prunes_the_record_and_says_so(self):
        q = self.hub_made("ai-hub-gone")
        restored.record_removed(q)
        path = os.path.join(restored.REMOVED_DIR, restored._uuid(q))
        del self.app.domains["ai-hub-gone"]
        old = time.time() - restored.REMOVED_KEEP_S - 60
        os.utime(path, (old, old))
        rc, out, err = self.cli("audit", "rotate", "--auto")
        self.assertEqual(rc, 0, err)
        self.assertIn("removal record: 1 entry older than 7 days dropped", out)
        self.assertFalse(os.path.exists(path))

    def test_a_prune_that_fails_never_changes_the_hourly_runs_status(self):
        def broken(app, now=None):
            raise RuntimeError("qubesd is down")
        with mock.patch.object(restored, "prune_removed", broken):
            rc, out, err = self.cli("audit", "rotate", "--auto")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("removal record", out)

    def test_an_entry_is_aged_from_its_latest_remove(self):
        q = self.hub_made("ai-hub-again")
        restored.record_removed(q)
        path = os.path.join(restored.REMOVED_DIR, restored._uuid(q))
        old = time.time() - restored.REMOVED_KEEP_S - 60
        os.utime(path, (old, old))
        restored.record_removed(q)                               # a later write
        self.assertLess(time.time() - os.stat(path).st_mtime, 60)

    def test_a_remove_is_refused_while_its_record_cannot_be_written(self):
        self.hub_made("ai-hub-other")
        os.chmod(restored.REMOVED_DIR, 0o500)
        self.addCleanup(os.chmod, restored.REMOVED_DIR, 0o2770)
        if os.geteuid() == 0:
            self.skipTest("root writes a read-only directory")
        r = self.hub_remove("ai-hub-other")
        self.assertIn("cannot be written; nothing was removed", r["error"])
        self.assertIn("ai-hub-other", self.app.domains)

    def test_a_removal_record_that_does_not_read_proves_no_restore(self):
        self.restore_of_gone("ai-hub-back")
        os.rmdir(restored.REMOVED_DIR)
        held = restored.hold(self.app)
        self.assertEqual(held.owner_kept, [])
        self.assertFalse(self.owned("ai-hub-back"))

    def test_the_record_of_replaced_labels_is_read_after_every_label(self):
        # An accept writes the record before it relabels: read after the
        # labels, a relabel the pass saw is always in the record it reads.
        self.restore_of_gone("ai-hub-back")
        order = []
        real_label, real_record = restored.label_of, restored.replaced_labels
        with mock.patch.object(restored, "label_of",
                               lambda vm: (order.append("label"), real_label(vm))[1]), \
                mock.patch.object(restored, "replaced_labels",
                                  lambda *a: (order.append("record"), real_record(*a))[1]):
            restored.Origins(self.app)
        self.assertEqual(order[-1], "record")
        self.assertEqual(order.count("record"), 1)

    def test_a_label_that_names_no_qube_proves_nothing_and_never_blocks_a_reject(self):
        for bad in ("", "not a uuid", "ZZZ"):
            self.restore_of_gone("ai-hub-back")
            self.app.domains["ai-hub-back"].features[core.ID_FEATURE] = bad
            held = restored.hold(self.app)
            self.assertEqual(held.owner_kept, [], bad)
            restored.reject(self.app, "ai-hub-back")
            self.assertNotIn(core.QUARANTINE, self.tags("ai-hub-back"))
            del self.app.domains["ai-hub-back"]

    def test_an_accept_takes_off_a_hold_the_pass_put_on_while_it_ran(self):
        self.restore_of_gone("ai-hub-back")
        vm = self.app.domains["ai-hub-back"]
        real = restored.label

        def label_then_held(v):
            real(v)
            v.tags.add(core.QUARANTINE)                         # the pass, without the lock
        with mock.patch.object(restored, "label", label_then_held):
            restored.accept(self.app, "ai-hub-back")
        self.assertNotIn(core.QUARANTINE, vm.tags.raw())

    def test_a_copy_made_before_any_pass_whose_original_is_accepted_or_rejected_loses_it(self):
        for decide in (restored.accept, restored.reject):
            self.restore_of_gone("ai-hub-back")
            self.app.clone_vm(self.app.domains["ai-hub-back"], "ai-hub-back-copy")
            decide(self.app, "ai-hub-back")
            held = restored.hold(self.app)
            self.assertEqual((held.owner_kept, held.unowned), ([], ["ai-hub-back-copy"]),
                             decide.__name__)
            self.assertFalse(self.owned("ai-hub-back-copy"))
            del self.app.domains["ai-hub-back-copy"]
            del self.app.domains["ai-hub-back"]

    def test_two_qubes_with_one_label_before_any_pass_both_lose_it(self):
        # A restore copied before the pass ran, or one backup restored twice:
        # neither is proven, since another qube carries the same label.
        self.restore_of_gone("ai-hub-back")
        self.app.clone_vm(self.app.domains["ai-hub-back"], "ai-hub-back-copy")
        held = restored.hold(self.app)
        self.assertEqual(sorted(held.unowned), ["ai-hub-back", "ai-hub-back-copy"])
        self.assertFalse(self.owned("ai-hub-back") or self.owned("ai-hub-back-copy"))

    def test_a_copy_held_before_this_release_is_decided_by_the_next_pass(self):
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.app.domains["ai-hub-src-copy"].tags.add(core.QUARANTINE)  # as 0.9.36 held it
        held = restored.hold(self.app)
        self.assertEqual((held.held, held.unowned), ([], ["ai-hub-src-copy"]))
        self.assertFalse(self.owned("ai-hub-src-copy"))
        del self.app.domains["ai-hub-src"]
        restored.accept(self.app, "ai-hub-src-copy")
        self.assertFalse(self.owned("ai-hub-src-copy"))

    def test_no_label_or_a_uuid_read_that_fails_is_not_proven_a_restore(self):
        vm = self.hub_made("ai-hub-nolabel")
        dict.pop(vm.features, core.ID_FEATURE, None)
        self.restore_of_gone("ai-hub-back")
        self.app.fail.add("get.uuid:ai-hubq")                    # another qube's UUID
        held = restored.hold(self.app)
        self.assertEqual(sorted(held.unowned), ["ai-hub-back", "ai-hub-nolabel"])
        self.assertFalse(self.owned("ai-hub-back") or self.owned("ai-hub-nolabel"))

    def test_a_qube_qubesd_says_is_gone_does_not_spoil_the_reading(self):
        self.restore_of_gone("ai-hub-back")
        self.app.fail.add("get.uuid:ai-hubq")
        with mock.patch.object(restored, "_is_gone", lambda app, name: name == "ai-hubq"):
            held = restored.hold(self.app)
        self.assertEqual(held.owner_kept, ["ai-hub-back"])
        self.assertTrue(self.owned("ai-hub-back"))

    def test_a_decision_that_fails_still_holds_and_the_next_pass_decides(self):
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        owner = birth.owner_tag(HUB)
        self.app.fail.add(f"tag.discard:{owner}")
        rc, _, err = self.cli("gate", root=False)
        self.assertEqual(rc, 3)
        self.assertIn("ai-hub-src-copy: held for review", err)
        self.assertIn("ai-hub-src-copy: its owner badge was NOT decided", err)
        self.assertIn(core.QUARANTINE, self.tags("ai-hub-src-copy"))
        self.assertTrue(self.owned("ai-hub-src-copy"))
        line = [l for l in self.audit_lines() if l["args"].get("owner badge")][-1]
        self.assertEqual((line["args"]["qube"], line["ok"]), ("ai-hub-src-copy", False))
        self.app.fail.discard(f"tag.discard:{owner}")
        held = restored.hold(self.app)
        self.assertEqual(held.unowned, ["ai-hub-src-copy"])
        self.assertFalse(self.owned("ai-hub-src-copy"))

    def test_a_decision_that_keeps_failing_the_same_way_is_logged_once(self):
        # A pass records what it changed: one line for a failure, again only
        # when it fails another way or succeeds; every pass still reports it.
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        owner = birth.owner_tag(HUB)
        self.app.fail.add(f"tag.discard:{owner}")

        def owner_lines():
            return [l for l in self.audit_lines()
                    if l["args"].get("owner badge") and l["args"]["qube"] == "ai-hub-src-copy"]
        for _ in range(3):
            held = restored.hold(self.app)
            self.assertEqual([n for n, _ in held.owner_failed], ["ai-hub-src-copy"])
        self.assertEqual([(l["ok"], l["error"]) for l in owner_lines()], [(False, "Injected")])
        copy = self.app.domains["ai-hub-src-copy"]
        real = copy.tags.discard
        copy.tags.discard = lambda tag: None          # fails another way: not read back
        restored.hold(self.app)
        restored.hold(self.app)
        self.assertEqual(len(owner_lines()), 2)
        self.assertEqual(owner_lines()[-1]["ok"], False)
        copy.tags.discard = real
        self.app.fail.discard(f"tag.discard:{owner}")
        self.assertEqual(restored.hold(self.app).unowned, ["ai-hub-src-copy"])
        self.assertEqual([l["ok"] for l in owner_lines()], [False, False, True])
        self.assertEqual([f for f in os.listdir(core.RUN_DIR)
                          if f.startswith(restored.FAILED_PREFIX)], [])

    def test_a_hold_that_keeps_failing_the_same_way_is_logged_once(self):
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.app.fail.add(f"tag.add:{core.QUARANTINE}")

        def hold_lines():
            return [l for l in self.audit_lines()
                    if l["args"].get("held") and l["args"]["qube"] == "ai-hub-src-copy"]
        for _ in range(3):
            self.assertEqual([n for n, _ in restored.hold(self.app).failed], ["ai-hub-src-copy"])
        self.assertEqual([l["ok"] for l in hold_lines()], [False])
        self.app.fail.discard(f"tag.add:{core.QUARANTINE}")
        self.assertEqual(restored.hold(self.app).held, ["ai-hub-src-copy"])
        self.assertEqual([l["ok"] for l in hold_lines()], [False, True])

    def test_a_new_qube_under_the_name_of_one_that_failed_is_logged_again(self):
        # The record is the qube's, by UUID: a later qube of the same name that
        # fails the same way is another qube's failure, and gets its line.
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.app.fail.add(f"tag.add:{core.QUARANTINE}")

        def hold_lines():
            return [l for l in self.audit_lines()
                    if l["args"].get("held") and l["args"]["qube"] == "ai-hub-src-copy"]
        restored.hold(self.app)
        restored.hold(self.app)
        self.assertEqual(len(hold_lines()), 1)
        old = self.app.domains["ai-hub-src-copy"]
        old.__dict__["_power"] = "Halted"
        del self.app.domains["ai-hub-src-copy"]
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.assertNotEqual(self.app.domains["ai-hub-src-copy"].uuid, old.__dict__["_props"]["uuid"])
        restored.hold(self.app)
        self.assertEqual(len(hold_lines()), 2)

    def test_a_qube_whose_uuid_does_not_read_logs_every_failure(self):
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.app.fail.add(f"tag.add:{core.QUARANTINE}")
        with mock.patch.object(restored, "_failure_key", lambda vm, name: None):
            restored.hold(self.app)
            restored.hold(self.app)
        self.assertEqual(len([l for l in self.audit_lines() if l["args"].get("held")]), 2)

    def test_a_link_or_fifo_planted_at_a_failure_record_is_never_followed(self):
        # /run/qmcp is the services' group's to write: root's pass must not
        # write through a link planted at the record or its temporary name, nor
        # block on a FIFO there. Either way the failure is logged.
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.app.fail.add(f"tag.add:{core.QUARANTINE}")
        vm = self.app.domains["ai-hub-src-copy"]
        path = restored._failure_path("hold", "ai-hub-src-copy", restored._uuid(vm))
        victim = pathlib.Path(self.tmp) / "victim"
        victim.write_text("precious")
        os.symlink(victim, path)
        os.symlink(victim, f"{path}.{os.getpid()}.tmp")
        restored.hold(self.app)
        self.assertEqual(victim.read_text(), "precious")
        self.assertFalse(os.path.islink(path))                # replaced, not followed
        os.unlink(path)
        os.mkfifo(path)
        restored.hold(self.app)                               # no hang on the FIFO
        lines = [l for l in self.audit_lines() if l["args"].get("held")]
        self.assertEqual(len(lines), 2)

    def test_a_failure_record_that_cannot_be_written_still_logs_every_failure(self):
        src = self.hub_made()
        self.app.clone_vm(src, "ai-hub-src-copy")
        self.app.fail.add(f"tag.discard:{birth.owner_tag(HUB)}")
        with mock.patch.object(restored.os, "replace", side_effect=PermissionError(13, "x")):
            restored.hold(self.app)
            restored.hold(self.app)
        self.assertEqual(len([l for l in self.audit_lines() if l["args"].get("owner badge")]), 2)

    def test_a_discard_that_does_not_land_is_a_failed_decision(self):
        src = self.hub_made()
        copy = self.app.clone_vm(src, "ai-hub-src-copy") or self.app.domains["ai-hub-src-copy"]
        copy.tags.discard = lambda tag: None
        held = restored.hold(self.app)
        self.assertEqual([n for n, _ in held.owner_failed], ["ai-hub-src-copy"])
        self.assertEqual(held.unowned, [])

    def test_accept_takes_off_a_badge_the_pass_did_not_record(self):
        # A qube held with no decision yet (accepted within a pass, or every
        # decision failed): fail-safe, even where the label would read as a restore.
        vm = self.restore_of_gone("ai-hub-back")
        vm.tags.add(core.QUARANTINE)
        self.assertIn("owner badge came off", restored.accept(self.app, "ai-hub-back"))
        self.assertFalse(self.owned("ai-hub-back"))

    def test_accept_refuses_a_disposable_born_of_its_template(self):
        name = self.app.qubesd_call("ai-dvm", "admin.vm.CreateDisposable").decode()
        self.app.domains.clear_cache()
        with self.assertRaises(restored.ReviewError):
            restored.accept(self.app, name)

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

    def test_a_lead_from_a_clone_or_promotion_refuses_a_template_waiting_for_review(self):
        # Not held yet (the gate's next pass would hold it): built on now, the
        # lead would escape that review.
        tpl = self.app.vm("ai-tpl-back", klass="TemplateVM", tags={"ai-managed"},
                          features={core.ID_FEATURE: "other"})
        self.app.vm("ai-hubr", template=tpl, netvm=None, tags={"ai-managed", "qmcp-proj-p00"})
        before = pathlib.Path(projects.PROJECTS_PATH).read_text()
        for source, name in (("clone", "ai-osint-lead2"), ("promote", None)):
            with self.assertRaises(fleet.ProjectError, msg=source) as cm:
                fleet.set_lead(self.app, "osint", source, "ai-hubr", lead_netvm="none",
                               keep_old=True, lead_name=name)
            self.assertIn(fleet.WAITS_WHY, str(cm.exception))
        self.assertEqual(pathlib.Path(projects.PROJECTS_PATH).read_text(), before)
        self.assertNotIn("ai-osint-lead2", self.app.domains)

    def test_a_clone_reads_its_template_again_under_the_locks(self):
        # Held after the plan read it (here: while the old lead was demoted):
        # the clone is refused before it is made.
        tpl = self.app.vm("ai-tpl-c", klass="TemplateVM", tags={"ai-managed"})
        self.app.vm("ai-hubr", template=tpl, netvm=None, tags={"ai-managed", "qmcp-proj-p00"})
        real = fleet._demote_lead

        def demote(*a, **kw):
            out = real(*a, **kw)
            tpl.tags.add(core.QUARANTINE)
            return out
        with mock.patch.object(fleet, "_demote_lead", demote):
            with self.assertRaises(fleet.ProjectError) as cm:
                fleet.set_lead(self.app, "osint", "clone", "ai-hubr", lead_netvm="none",
                               keep_old=True, lead_name="ai-osint-lead2")
        self.assertIn(fleet.HELD_WHY, str(cm.exception))
        self.assertNotIn("ai-osint-lead2", self.app.domains)

    def test_a_promotion_reads_its_template_again_under_the_locks(self):
        tpl = self.app.vm("ai-tpl-c", klass="TemplateVM", tags={"ai-managed"})
        self.app.vm("ai-hubr", template=tpl, netvm=None, tags={"ai-managed", "qmcp-proj-p00"})
        real = fleet._demote_lead

        def demote(*a, **kw):
            out = real(*a, **kw)
            tpl.tags.add(core.QUARANTINE)
            return out
        with mock.patch.object(fleet, "_demote_lead", demote):
            with self.assertRaises(fleet.ProjectError) as cm:
                fleet.set_lead(self.app, "osint", "promote", "ai-hubr", lead_netvm="none",
                               keep_old=True)
        self.assertIn(fleet.HELD_WHY, str(cm.exception))
        self.assertEqual(self.app.domains["ai-hubr"].tags.raw() & {"qmcp-lead"}, set())

    def test_a_dump_sink_refuses_a_default_template_waiting_for_review(self):
        tpl = self.app.vm("ai-tpl-d", klass="TemplateVM", tags={"ai-managed"},
                          features={core.ID_FEATURE: "other"})
        self.app.default_template = tpl
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.add_dump(self.app, "p00")
        self.assertIn(fleet.WAITS_WHY, str(cm.exception))
        self.assertNotIn("hub-dump", self.app.domains)
        restored.hold(self.app)
        with self.assertRaises(fleet.ProjectError) as cm:
            fleet.add_dump(self.app, "p00")
        self.assertIn(fleet.HELD_WHY, str(cm.exception))
        # Teeth: an accepted template takes the sink.
        restored.accept(self.app, "ai-tpl-d")
        fleet.add_dump(self.app, "p00")
        self.assertIn("hub-dump", self.app.domains)

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

    def test_reject_refuses_the_hub_and_its_stop_stays(self):
        # The hub is the hub by its file: a reject would strip the gate's stop
        # and leave it a caller. Accept keeps the stop.
        hub = self.app.domains[HUB]
        for t in ("qmcp-anon", "qmcp-blocked", "qmcp-stopped", core.QUARANTINE):
            hub.tags.add(t)
        hub.features[core.ID_FEATURE] = "old"
        before = set(hub.tags.raw())
        with self.assertRaisesRegex(restored.ReviewError, "is the hub"):
            restored.reject(self.app, HUB)
        self.assertEqual(set(hub.tags.raw()), before)
        self.assertEqual(self.call("qmcp.ListAIManagedQubes", {}), core.NOT_AUTHORIZED)
        rc, _, err = self.cli("restored", "reject", HUB)
        self.assertEqual(rc, 1, err)
        self.assertIn("qmcp restored accept", err)

    def test_reject_refuses_while_the_hub_file_does_not_read(self):
        self.back("ai-a", {"qmcp-proj-p00"})
        restored.hold(self.app)
        os.unlink(core.HUB_PATH)
        with self.assertRaisesRegex(restored.ReviewError, "may be the hub"):
            restored.reject(self.app, "ai-a")
        self.assertIn(core.QUARANTINE, self.app.domains["ai-a"].tags.raw())

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
        before = len(self.audit_lines())
        rc, out, _ = self.cli("restored", "accept", "--all")
        self.assertEqual(rc, 0, out)
        self.assertEqual(restored.review(self.app, {}), [])
        # One line per qube it accepted, naming it: `--all` alone names none.
        lines = self.audit_lines()[before:]
        self.assertEqual([(x["service"], x["args"], x["ok"]) for x in lines],
                         [("qmcp restored accept", {"qubes": [n], "all": True}, True)
                          for n in ("ai-a", "ai-b")])
        rc, out, _ = self.cli("restored", "accept", "--all")
        self.assertEqual((rc, out.strip()), (0, "nothing is held"))
        self.assertEqual(self.audit_lines()[-1]["args"], {"qubes": [], "all": True})

    def test_export_names_every_qube_waiting_for_review_and_still_writes(self):
        """After a restore every AI qube is held alike and `accept --all`
        takes them all, so a qube held before the backup (a hand qvm-clone)
        would skip its review: the export says so, and is written all the same,
        byte for byte the file it writes with nothing waiting."""
        stamp = mock.patch.object(opfiles, "_now", return_value="20261018T120000Z")
        clean = self.tmp / "e0.json"
        with stamp:
            rc, out, err = self.cli("export", str(clean))
        self.assertEqual((rc, err), (0, ""), err)       # nothing waits: no warning
        self.back("ai-a", {"qmcp-proj-p00"})
        restored.hold(self.app)
        self.back("ai-b", {"qmcp-proj-p00"})            # not held yet: the next pass holds it
        path = self.tmp / "e1.json"
        with stamp:
            rc, out, err = self.cli("export", str(path))
        self.assertEqual(rc, 0, err)
        self.assertIn(f"wrote {path}", out)
        self.assertEqual(path.read_bytes(), clean.read_bytes())
        self.assertIn("qmcp export: held for review, or about to be: ai-a, ai-b. Accept or "
                      "reject each before you back up", err)
        self.assertIn("restored accept --all takes these with the rest", err)
        # The warning names the qubes it found, and only those.
        restored.accept(self.app, "ai-a")
        rc, _, err = self.cli("export", str(self.tmp / "e2.json"))
        self.assertEqual(rc, 0)
        self.assertIn("about to be: ai-b.", err)
        self.assertNotIn("ai-a", err)

    def test_export_says_when_whether_a_qube_is_held_cannot_be_read(self):
        """A qube whose tags do not read may be held: never left out, and a
        review that cannot run at all is never "nothing waits". The file is
        the one written with nothing waiting, byte for byte."""
        stamp = mock.patch.object(opfiles, "_now", return_value="20261018T120000Z")
        with stamp:
            self.assertEqual(self.cli("export", str(self.tmp / "e0.json"))[0], 0)
        clean = (self.tmp / "e0.json").read_bytes()
        for n in ("ai-a", "ai-b"):
            self.back(n, {"qmcp-proj-p00"})
        restored.hold(self.app)
        self.app.fail.add("tag.List:ai-b")
        with stamp:
            rc, _, err = self.cli("export", str(self.tmp / "e1.json"))
        self.app.fail.clear()
        self.assertEqual(rc, 0, err)
        self.assertTrue((self.tmp / "e1.json").exists())
        self.assertIn("about to be: ai-a.", err)
        self.assertIn("whether ai-b is held for review is not known, since it cannot be read "
                      "now", err)
        with stamp, mock.patch.object(restored, "review", side_effect=RuntimeError("boom")):
            rc, _, err = self.cli("export", str(self.tmp / "e2.json"))
        self.assertEqual(rc, 0, err)
        self.assertTrue((self.tmp / "e2.json").exists())
        self.assertIn("whether any qube is held for review could not be read (RuntimeError)", err)
        self.assertNotIn("boom", err)
        # And when the Admin API client cannot even be made: still written, still said.
        with stamp, mock.patch.object(restored, "before_export",
                                      side_effect=ImportError("qubesadmin")):
            rc, _, err = self.cli("export", str(self.tmp / "e3.json"))
        self.assertEqual(rc, 0, err)
        for f in ("e1.json", "e2.json", "e3.json"):
            self.assertEqual((self.tmp / f).read_bytes(), clean, f)
        self.assertIn("whether any qube is held for review could not be read (ImportError)", err)

    def test_accept_all_never_says_nothing_is_held_over_a_qube_it_cannot_read(self):
        for n in ("ai-a", "ai-b"):
            self.back(n, {"qmcp-proj-p00"})
        restored.hold(self.app)
        self.app.fail.add("tag.List:ai-b")
        rc, out, err = self.cli("restored", "accept", "--all")
        self.app.fail.clear()
        self.assertEqual(rc, 1, err)
        self.assertIn("ai-a: accepted", out)
        self.assertIn("ai-b cannot be read now", err)
        self.assertIn(core.QUARANTINE, self.app.domains["ai-b"].tags.raw())
        # And with nothing else held: refused, never "nothing is held".
        self.app.fail.add("tag.List:ai-b")
        rc, out, err = self.cli("restored", "accept", "--all")
        self.app.fail.clear()
        self.assertEqual(rc, 1)
        self.assertNotIn("nothing is held", out)

    def test_operator_lines_hold_every_option_and_say_how_many_names_were_cut(self):
        def line(*argv):
            return cli.operator_line(cli.build_parser().parse_args(list(argv)))
        self.assertTrue(line("gateway", "enroll", "gw", "--anonymising", "--updates")[1]["updates"])
        self.assertFalse(line("gateway", "enroll", "gw")[1]["updates"])
        self.assertEqual(line("gateway", "set", "gw", "--updates", "no")[1]["updates"], "no")
        self.assertIsNone(line("gateway", "set", "gw", "--label", "x")[1]["updates"])
        names = [f"ai-q{i}" for i in range(40)]
        qubes = line("restored", "accept", *names)[1]["qubes"]
        self.assertEqual(qubes, names[:32] + ["and 8 more"])
        self.assertEqual(line("restored", "accept", *names[:32])[1]["qubes"], names[:32])

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

    def test_keep_days_and_the_audit_mode_go_through_an_export(self):
        pathlib.Path(audit.KEEP_DAYS_PATH).write_text("30\n")
        pathlib.Path(audit.MODE_PATH).write_text("ram\n")
        path = opfiles.export("0.9.33", self.export_path())
        doc = json.loads(pathlib.Path(path).read_text())
        self.assertEqual((doc["files"]["audit-keep-days"], doc["files"]["audit-mode"]),
                         ("30\n", "ram\n"))
        self.fresh()
        os.unlink(audit.KEEP_DAYS_PATH)
        os.unlink(audit.MODE_PATH)                          # this install logs to disk
        out = opfiles.import_(path)
        self.assertEqual(pathlib.Path(audit.KEEP_DAYS_PATH).read_text(), "30\n")
        self.assertFalse(os.path.exists(audit.MODE_PATH))  # the mode is the install's
        self.assertTrue(any("install.sh --audit-log ram" in line for line in out), out)

    def test_an_export_from_before_still_imports(self):
        path = opfiles.export("0.9.32", self.export_path())
        doc = json.loads(pathlib.Path(path).read_text())
        for name in ("audit-keep-days", "audit-mode"):
            del doc["files"][name]
        pathlib.Path(path).write_text(json.dumps(doc))
        self.fresh()
        opfiles.import_(path)
        self.assertFalse(os.path.exists(audit.KEEP_DAYS_PATH))
        # Half the new files is no export qmcp writes: refused.
        doc["files"]["audit-mode"] = None
        pathlib.Path(path).write_text(json.dumps(doc))
        with self.assertRaises(opfiles.OpFilesError):
            opfiles.plan_import(path)

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

    def test_a_crafted_export_is_refused_in_words_never_a_traceback(self):
        path = opfiles.export("0.9.26", self.export_path())
        self.fresh()
        doc = json.loads(pathlib.Path(path).read_text())
        for cap in ("\u00b2\n", "\u0663\u0660\n", "\uff13\uff10\n", "1" * 21 + "\n"):
            with self.subTest(cap=cap):
                d = json.loads(json.dumps(doc))
                d["files"]["pool-cap"] = cap
                p = self.tmp / "crafted.json"
                p.write_text(json.dumps(d))
                with self.assertRaisesRegex(opfiles.OpFilesError, "pool-cap is not a positive"):
                    opfiles.import_(str(p))
        deep = self.tmp / "deep.json"
        deep.write_text("[" * 100000 + "]" * 100000)
        rc, out, err = self.cli("import", str(deep))
        self.assertEqual(rc, 1)
        self.assertIn("is not JSON; nothing was changed", err)
        self.assertNotIn("Traceback", err)
        self.assertFalse(os.path.exists(projects.PROJECTS_PATH))
        self.assertFalse(os.path.exists(gateways.GATEWAYS_PATH))

    def test_an_import_that_fails_part_way_says_what_it_wrote_and_a_rerun_finishes_it(self):
        path = opfiles.export("0.9.26", self.export_path())
        want = {n: pathlib.Path(opfiles._paths()[n]).read_text()
                for n in ("gateways.json", "projects.json")}
        self.fresh()
        with mock.patch.object(projects, "save", side_effect=OSError(28, "No space left")):
            rc, out, err = self.cli("import", path)
        self.assertEqual(rc, 1)
        self.assertIn("gateways.json: ", out)                    # what was written, first
        self.assertIn("projects.json could not be written (OSError)", err)
        self.assertIn("run the import again", err)
        self.assertNotIn("nothing was changed", err)
        self.assertTrue(os.path.exists(gateways.GATEWAYS_PATH))
        self.assertFalse(os.path.exists(projects.PROJECTS_PATH))
        rc, out, err = self.cli("import", path)
        self.assertEqual(rc, 0, err)
        for n, text in want.items():
            self.assertEqual(json.loads(pathlib.Path(opfiles._paths()[n]).read_text()),
                             json.loads(text), n)
        # Finished, it is refused again: an import is for a fresh install.
        with self.assertRaisesRegex(opfiles.OpFilesError, "fresh install"):
            opfiles.import_(path)
        # And a registry that is not the export's still refuses, records or not.
        os.unlink(projects.PROJECTS_PATH)
        registry = gateways.parse(want["gateways.json"])
        self.assertTrue(registry)
        gateways.save({"ai-net-other": next(iter(registry.values()))}, gateways.GATEWAYS_PATH)
        with self.assertRaisesRegex(opfiles.OpFilesError, "fresh install"):
            opfiles.import_(path)

    def test_settings_set_says_what_it_wrote_before_a_failure_and_names_a_busy_lock(self):
        real = opfiles._write
        calls = []

        def second_fails(path, text, mode=0o644):
            calls.append(path)
            if len(calls) == 2:
                raise OSError(28, "No space left")
            return real(path, text, mode)
        with mock.patch.object(opfiles, "_write", second_fails):
            rc, out, err = self.cli("settings", "set", "--pool-cap", "900G", "--private-cap", "5G")
        self.assertEqual(rc, 1)
        self.assertEqual(out.splitlines(), [f"pool-cap: {900 * GiB}"])
        self.assertIn("private-cap could not be written (OSError)", err)
        self.assertNotIn("nothing was changed", err)
        self.assertEqual(budget.read_cap(), 900 * GiB)
        with projects.Locked():
            # Another command holds the records' lock; this one gives up soon.
            with mock.patch.object(projects.Locked.__init__, "__defaults__", (None, 0.1)):
                rc, out, err = self.cli("settings", "set", "--pool-cap", "800G")
        self.assertEqual(rc, 1)
        self.assertIn("another qmcp project command holds the lock; nothing was changed", err)
        self.assertNotIn("RuntimeError", err)
        self.assertEqual(budget.read_cap(), 900 * GiB)

    def test_birth_egress_whose_lookup_fails_is_not_a_missing_qube(self):
        self.app.fail_reads("lookup:ai-net-router", "fail")
        with self.assertRaises(opfiles.OpFilesError) as cm:
            opfiles.settings_set(self.app, birth_egress="ai-net-router")
        self.assertEqual(self.app.failed["lookup:ai-net-router"], 1)
        self.assertIn("cannot be looked up", str(cm.exception))
        self.assertFalse(os.path.exists(fleet.birth.BIRTH_EGRESS_PATH))
        self.app.fail.add("tag.List:ai-net-router")
        with self.assertRaisesRegex(opfiles.OpFilesError, "cannot be looked up"):
            opfiles.settings_set(self.app, birth_egress="ai-net-router")
        self.app.fail.discard("tag.List:ai-net-router")
        opfiles.settings_set(self.app, birth_egress="ai-net-router")          # the control

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


class MigrateRoot(ToolsBase):
    def test_migrate_apply_refuses_a_non_root_user_before_reading_anything(self):
        # Without root it would apply the badges, then fail to retire the flag
        # that says how to read them, and a second run would guard the
        # managed qubes. The dry run reads only, and needs no root.
        planned = []
        with mock.patch.object(fleet, "plan_migration",
                               side_effect=lambda *a, **kw: planned.append(a) or ([], [])), \
                mock.patch.object(fleet, "apply_migration") as apply:
            rc, out, err = self.cli("migrate", "--apply", root=False)
            self.assertIn("qmcp migrate --apply: run as root", str(rc))
            self.assertEqual((planned, apply.call_count), ([], 0))
            rc, out, err = self.cli("migrate", root=False)
            self.assertEqual(rc, 0, err)
            self.assertEqual(len(planned), 1)
            rc, out, err = self.cli("migrate", "--apply")
            self.assertEqual(rc, 0, err)
            self.assertEqual(len(planned), 2)


class UsageText(unittest.TestCase):
    def test_the_modules_usage_names_every_command_and_template_action(self):
        import argparse
        usage = cli.__doc__.split("\n\n")[1]
        words = set(usage.replace("|", " ").replace("/", " ").split())
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        self.assertEqual(sorted(set(sub.choices) - words), [])
        tpl = next(a for a in sub.choices["template"]._actions
                   if isinstance(a, argparse._SubParsersAction))
        self.assertEqual(sorted(set(tpl.choices) - words), [])


class StampMode(ToolsBase):
    """The installer's anonymous-mode stamp, cut out of install.sh: it runs
    under the gate's lock, writes the mode file between its two passes, and
    leaves an audit line for what it changed."""

    TEXT = (HERE.parent / "deploy" / "install.sh").read_text()
    _start = TEXT.index("<<'PYEOF'\n", TEXT.index("stamp_mode() {")) + len("<<'PYEOF'\n")
    PROGRAM = TEXT[_start:TEXT.index("\nPYEOF\n", _start) + 1]

    def stamp(self, write_mode: bool):
        import types
        qa = types.ModuleType("qubesadmin")
        qa.app = types.ModuleType("qubesadmin.app")
        qa.app.QubesLocal = lambda: self.app
        self.mode_path = self.tmp / "mode"
        env = {"QMCP_HUB": HUB, "QMCP_MODE_PATH": str(self.mode_path),
               "QMCP_WRITE_MODE": "1" if write_mode else "0"}
        with mock.patch.dict(sys.modules, {"qubesadmin": qa, "qubesadmin.app": qa.app}), \
                mock.patch.dict(os.environ, env), redirect_stdout(io.StringIO()):
            try:
                exec(compile(self.PROGRAM, "install.sh stamp", "exec"), {"__name__": "__main__"})
                return 0
            except SystemExit as e:
                return e.code or 0

    def test_it_turns_the_mode_on_under_the_gate_lock_and_says_so(self):
        from qmcp import anon, projects
        self.assertEqual(self.stamp(write_mode=True), 0)
        self.assertEqual(self.mode_path.read_text(), "anonymous\n")
        self.assertIn(projects.ANON, self.tags(HUB))
        line = self.audit_lines()[-1]
        self.assertEqual((line["service"], line["caller"], line["args"]["turned_on"]),
                         ("qmcp install", "operator", True))
        n = len(self.audit_lines())
        self.assertEqual(self.stamp(write_mode=False), 0)       # nothing new: no line
        self.assertEqual(len(self.audit_lines()), n)

    def test_the_updates_tick_leaves_its_line(self):
        import re
        import types
        program = re.search(r"python3 -c '([^']*set_gateway[^']*)' \"\$g\"", self.TEXT).group(1)
        qa = types.ModuleType("qubesadmin")
        qa.app = types.ModuleType("qubesadmin.app")
        qa.app.QubesLocal = lambda: self.app
        from qmcp import fleet
        fleet.set_gateway(self.app, "ai-net-router", anonymising=True)
        with mock.patch.dict(sys.modules, {"qubesadmin": qa, "qubesadmin.app": qa.app}), \
                mock.patch.object(sys, "argv", ["-c", "ai-net-router"]), \
                redirect_stdout(io.StringIO()):
            exec(compile(program, "install.sh tick", "exec"), {"__name__": "__main__"})
        line = self.audit_lines()[-1]
        self.assertEqual((line["service"], line["args"]), ("qmcp gateway set",
                                                           {"qube": "ai-net-router", "updates": True}))

    def test_a_held_gate_lock_stops_it_before_anything(self):
        import fcntl
        from qmcp import anon, projects
        fd = os.open(anon.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with mock.patch.object(anon._GateLock, "__init__",
                               lambda s, path=None, wait=None: (
                                   setattr(s, "path", anon.LOCK_PATH),
                                   setattr(s, "wait", 0.2), setattr(s, "fd", None))[0]):
            self.assertIn("held its lock", str(self.stamp(write_mode=True)))
        self.assertFalse(self.mode_path.exists())
        self.assertNotIn(projects.ANON, self.tags(HUB))


class StaleBadgePreflight(ToolsBase):
    """The installer's stale-badge preflight, cut out of install.sh and run
    against the fake: 0 none, 1 found, 2 a qube whose tags do not read, and 3
    (never 1) when the fleet itself cannot be read."""

    TEXT = (HERE.parent / "deploy" / "install.sh").read_text()
    _start = TEXT.index("<<'PYEOF'\n", TEXT.index('STALE_OUT="$(')) + len("<<'PYEOF'\n")
    PROGRAM = TEXT[_start:TEXT.index("\nPYEOF\n", _start) + 1]

    def run_program(self, app_factory=None):
        import types
        qa = types.ModuleType("qubesadmin")
        qa.app = types.ModuleType("qubesadmin.app")
        qa.app.QubesLocal = app_factory or (lambda: self.app)
        out = io.StringIO()
        with mock.patch.dict(sys.modules, {"qubesadmin": qa, "qubesadmin.app": qa.app}), \
                redirect_stdout(out):
            try:
                exec(compile(self.PROGRAM, "install.sh stale", "exec"), {"__name__": "__main__"})
                rc = 0
            except SystemExit as e:
                rc = e.code or 0
        return rc, out.getvalue()

    def test_its_exit_statuses(self):
        self.assertEqual(self.run_program()[0], 0)
        pathlib.Path(projects.PROJECTS_PATH).unlink()           # as a purge leaves it
        rc, out = self.run_program()
        self.assertEqual(rc, 1)
        self.assertIn("qmcp-lead-p01", out)

        def broken():
            raise RuntimeError("qubesd is down")
        rc, out = self.run_program(broken)
        self.assertEqual(rc, 3)
        self.assertIn("could not be read", out)


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

    def test_the_refresh_unit_runs_the_refresh_as_the_gates_user_on_its_timer(self):
        # A refresh "every minute, as the gate's user" is true only while the
        # unit and the timer say so, and the installer enables the timer.
        def keys(name):
            out = {}
            for line in (HERE.parent / "deploy" / name).read_text().splitlines():
                if "=" in line and not line.startswith(("#", "[")):
                    k, v = line.split("=", 1)
                    out.setdefault(k.strip(), []).append(v.strip())
            return out
        unit = keys("qmcp-refresh.service")
        self.assertEqual(unit["ExecStart"], ["/usr/local/bin/qmcp template refresh"])
        self.assertEqual(unit["User"], ["@GATE_USER@"])                # never root
        self.assertEqual(unit["Type"], ["oneshot"])
        # The refresh exits 3 for a qube it could not judge or write into; the
        # unit counts that a success, so the timer keeps running it.
        self.assertEqual(unit["SuccessExitStatus"], ["3"])
        self.assertEqual(unit["NoNewPrivileges"], ["yes"])
        self.assertGreater(int(unit["TimeoutStartSec"][0]), 0)
        timer = keys("qmcp-refresh.timer")
        self.assertEqual((timer["OnBootSec"], timer["OnUnitActiveSec"]), (["60s"], ["60s"]))
        self.assertIn("systemctl enable qmcp-refresh.timer", self.TEXT)
        self.assertIn('sed "s/@GATE_USER@/$GATE_USER/" "$SRC/deploy/qmcp-refresh.service"',
                      self.TEXT)



# ======================================================================= packages (0.9.28)

class Packages(ToolsBase):
    """`qmcp template install`: exact package names into a TemplateVM in AI
    space, by the template's own package manager. dom0 decides on exit
    statuses alone and keeps only the tail of what the template writes."""

    TPL = "ai-tpl-g"

    def tpl(self):
        return self.app.domains[self.TPL]

    def test_the_script_checks_every_name_then_installs_with_the_updaters_options(self):
        apt = inqube.install_script("apt-get", ["curl", "g++"]).decode()
        self.assertIn("export DEBIAN_FRONTEND=noninteractive", apt)
        self.assertIn("apt-get -q update || exit 21", apt)
        self.assertIn('apt-cache pkgnames "$n" | grep -qxF -- "$n"', apt)
        # --no-remove: with -y, apt would remove a package that conflicts
        # (measured: chrony removes systemd-timesyncd).
        self.assertIn("\napt-get install -y -q --no-remove -o Dpkg::Options::=--force-confdef -o "
                      "Dpkg::Options::=--force-confold --no-install-recommends -- curl g++ "
                      "|| exit $?\n", apt)
        self.assertIn("dpkg-query -W -f='installed: ${Package} ${Version}\\n' -- curl g++ "
                      "|| true", apt)
        dnf = inqube.install_script("dnf", ["curl"]).decode()
        # dnf5 refuses `--` (measured on Fedora 43); a versioned name resolves
        # to another name and is refused by the check.
        self.assertNotIn(" -- ", dnf)
        self.assertIn("repoquery --qf '%{name}\\n' \"$n\"", dnf)
        self.assertIn("dnf -q makecache || exit 21", dnf)
        self.assertIn("\ndnf -y -q --setopt=install_weak_deps=False --setopt=obsoletes=0 "
                      "install curl || exit $?\n", dnf)
        pac = inqube.install_script("pacman", ["curl"]).decode()
        # Never `-Sy` with names: a partial upgrade. `-Sy`, the check, `-Su`.
        # No 10 s download timeout on either: an anonymising proxy is slower.
        self.assertIn("pacman --noconfirm --disable-download-timeout -Sy || exit 21", pac)
        self.assertIn('pacman -Si "$n" >/dev/null 2>&1 ||', pac)
        self.assertIn("\npacman --noconfirm --disable-download-timeout --needed -Su curl "
                      "|| exit $?\n", pac)
        self.assertNotRegex(pac, r"-Sy[^u\n]*curl")
        for text in (apt, dnf, pac):
            # The check comes first, then the install, whose failure is the
            # script's exit status; the versions are printed after a success
            # only, and their failure changes nothing.
            lines = text.rstrip("\n").split("\n")
            check = next(i for i, line in enumerate(lines) if "not a package name here" in line)
            install = next(i for i, line in enumerate(lines) if line.endswith("|| exit $?"))
            self.assertLess(check, install)
            self.assertTrue(lines[install + 1].endswith("|| true"), lines[install + 1])
            self.assertIn("installed: ", lines[install + 1])
            self.assertEqual(lines[-1], "exit 0")
        with self.assertRaises(inqube.InQubeError):
            inqube.install_script("zypper", ["curl"])

    def test_the_last_lines_name_what_was_installed(self):
        r = inqube.install(self.app, self.TPL, ["curl", "jq"])
        self.assertEqual(r["lines"][-2:], ["installed: curl 1.0", "installed: jq 1.0"])

    def test_the_shape_of_a_name(self):
        good = ["curl", "g++", "gir1.2-gtk-3.0", "python3.13", "NetworkManager", "lib_x", "a"]
        bad = ["", "-y", ".hidden", "sl-", "bas*", "x?", "@core", "x/y", "x:amd64", "x=1",
               "pkgconfig(x)", "a b", "caf\u00e9", "x" * 101, None, 7, b"curl"]
        for name in good:
            self.assertIsNone(inqube.package_refusal(name), name)
        for name in bad:
            self.assertIsNotNone(inqube.package_refusal(name), name)
        self.assertIsNotNone(inqube.packages_refusal(["curl"] * 2))
        self.assertIsNotNone(inqube.packages_refusal([]))
        self.assertIsNotNone(inqube.packages_refusal("curl"))
        self.assertIsNotNone(inqube.packages_refusal(["p%d" % i for i in range(33)]))
        self.assertIsNone(inqube.packages_refusal(["p%d" % i for i in range(32)]))

    def test_an_install_starts_a_halted_template_and_stops_it_again(self):
        self.assertEqual(self.tpl().get_power_state(), "Halted")
        r = inqube.install(self.app, self.TPL, ["curl", "jq"])
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["manager"], r["started"]), ("apt-get", True))
        self.assertEqual(self.tpl().installed_packages(), ["curl", "jq"])
        self.assertEqual(self.tpl().get_power_state(), "Halted")
        # The probe, then the install: two scripts, the probe first.
        probe, script = self.app.vmshell_scripts[-2:]
        self.assertEqual(probe, inqube.PROBE)
        self.assertEqual(script, inqube.install_script("apt-get", ["curl", "jq"]))

    def test_the_stop_after_an_install_is_reported_as_it_went(self):
        tpl = self.tpl()

        def raced(vm, force=False, wait=False):
            vm._went_down()
            raise RuntimeError("QubesVMNotStartedError")
        with mock.patch.object(type(tpl), "shutdown", raced):
            report = proposals.install_report(self.app, self.TPL, ["curl"])
        self.assertEqual(report.failed, [])
        self.assertIn("shut down again", " ".join(report))
        self.app.fail.add("shutdown")
        try:
            r = inqube.install(self.app, self.TPL, ["jq"])
        finally:
            self.app.fail.discard("shutdown")
        self.assertEqual((r["started"], r["stopped"]), (True, False))
        self.assertEqual(tpl.get_power_state(), "Running")

    def test_an_open_template_is_refused_before_anything_runs(self):
        # The window's expiry kills it, which would stop the install part-way.
        for badges in ({core.OPEN}, {core.OPEN_FW}, {core.OPEN, core.OPEN_FW}):
            with self.subTest(badges=badges):
                for badge in badges:
                    self.tpl().tags.add(badge)
                with self.assertRaisesRegex(inqube.InQubeError, "open to the hub: seal it first"):
                    inqube.install(self.app, self.TPL, ["curl"])
                for badge in badges:
                    self.tpl().tags.discard(badge)
        self.assertEqual(self.app.vmshell_scripts, [])
        self.assertEqual(self.tpl().get_power_state(), "Halted")
        self.assertTrue(inqube.install(self.app, self.TPL, ["curl"])["ok"])   # the control

    def test_a_running_template_keeps_running_and_each_manager_is_used(self):
        for manager in ("dnf", "pacman"):
            tpl = self.app.vm(f"ai-{manager}", klass="TemplateVM", power="Running",
                              tags={"ai-managed", "qmcp-guarded"})
            self.app.pkgmgr[tpl.name] = manager
            r = inqube.install(self.app, tpl.name, ["curl"])
            self.assertTrue(r["ok"] and not r["started"], r)
            self.assertEqual(r["manager"], manager)
            self.assertEqual(self.app.vmshell_scripts[-1], inqube.install_script(manager, ["curl"]))
            self.assertEqual(tpl.get_power_state(), "Running")

    def test_refusals_come_before_anything_runs(self):
        self.app.vm("ai-blocked", klass="TemplateVM", tags={"ai-managed", "qmcp-blocked"})
        self.app.vm("ai-held", klass="TemplateVM", tags={"ai-managed", core.QUARANTINE})
        self.app.vm("ai-hid-tpl", klass="TemplateVM", tags={"ai-managed", projects.HUBBLIND})
        self.app.vm("ai-sa", klass="StandaloneVM", tags={"ai-managed"})
        self.app.vm("ai-paused", klass="TemplateVM", power="Paused", tags={"ai-managed"})
        for name, words in (("debian-13", "not in AI space"), ("ai-work", "is a AppVM"),
                            ("ai-sa", "is a StandaloneVM"), ("ai-blocked", "anonymity gate"),
                            ("ai-held", "held for your review"), ("ai-hid-tpl", "hidden project"),
                            ("no-such", "no qube"), ("dom0", "no qube"),
                            ("ai-paused", "is Paused")):
            with self.subTest(name):
                with self.assertRaises(inqube.InQubeError) as cm:
                    inqube.install(self.app, name, ["curl"])
                self.assertIn(words, str(cm.exception))
        with self.assertRaises(inqube.InQubeError):
            inqube.install(self.app, self.TPL, ["sl-"])
        self.assertEqual(self.app.vmshell_scripts, [])
        self.assertNotIn("run_service", [c[1] for c in self.app.calls])
        self.assertEqual(self.app.domains["ai-blocked"].get_power_state(), "Halted")

    def test_a_name_the_repositories_do_not_hold_refuses_the_whole_install(self):
        r = inqube.install(self.app, self.TPL, ["curl", "nosuch"])
        self.assertFalse(r["ok"])
        self.assertIn("refused inside the template", r["status"])
        self.assertEqual(r["lines"], ["not a package name here: nosuch"])
        self.assertEqual(self.tpl().installed_packages(), [])

    def test_each_failure_is_said_in_words_and_stops_a_template_it_started(self):
        for mode, words in (("exit1", "apt-get exited 1"),
                            ("norefresh", "could not refresh the package lists")):
            tpl = self.app.vm(f"ai-{mode}", klass="TemplateVM", tags={"ai-managed"})
            self.app.vmshell[tpl.name] = mode
            r = inqube.install(self.app, tpl.name, ["curl"])
            self.assertFalse(r["ok"])
            self.assertIn(words, r["status"])
            self.assertEqual(tpl.get_power_state(), "Halted")
        self.app.pkgmgr[self.TPL] = None
        with self.assertRaises(inqube.InQubeError) as cm:
            inqube.install(self.app, self.TPL, ["curl"])
        self.assertIn("none of apt-get, dnf and pacman", str(cm.exception))
        self.assertEqual(self.tpl().get_power_state(), "Halted")

    def test_a_hung_probe_raises_and_stops_the_template(self):
        tpl = self.app.vm("ai-hang", klass="TemplateVM", tags={"ai-managed"})
        self.app.vmshell[tpl.name] = "timeout"
        with self.assertRaises(inqube.InQubeError) as cm:
            inqube.install(self.app, tpl.name, ["curl"], timeout=0.01)
        self.assertIn("the probe for its package manager", str(cm.exception))
        self.assertEqual(tpl.get_power_state(), "Halted")

    def test_a_probe_that_fails_says_what_became_of_a_template_it_started(self):
        tpl = self.app.vm("ai-hang-p", klass="TemplateVM", tags={"ai-managed"})
        self.app.vmshell[tpl.name] = "timeout"
        with self.assertRaises(inqube.InQubeError) as cm:
            inqube.install(self.app, tpl.name, ["curl"])
        self.assertIn("was started for this and shut down again", str(cm.exception))
        self.app.fail.add("shutdown")
        try:
            with self.assertRaises(inqube.InQubeError) as cm:
                inqube.install(self.app, tpl.name, ["curl"])
        finally:
            self.app.fail.discard("shutdown")
        self.assertIn("its shutdown did not complete: qvm-kill ai-hang-p", str(cm.exception))

    def test_a_hung_install_is_a_failed_result_that_says_what_it_did(self):
        # dom0 killing its end stops nothing inside the qube: a template this
        # started is shut down, which stops the install where it was; one that
        # was running keeps running it. Either way the tail so far is kept.
        halted = self.app.vm("ai-hang", klass="TemplateVM", tags={"ai-managed"})
        running = self.app.vm("ai-hang-r", klass="TemplateVM", power="Running",
                              tags={"ai-managed"})
        for tpl, words, power in ((halted, "stopped the install part-way", "Halted"),
                                  (running, "dom0 stopped reading its output", "Running")):
            self.app.vmshell[tpl.name] = "hanginstall"
            r = inqube.install(self.app, tpl.name, ["curl"], timeout=0.01)
            self.assertFalse(r["ok"])
            self.assertIn("dom0 stopped waiting", r["status"])
            self.assertIn(words, r["status"])
            self.assertEqual(r["lines"], ["Reading package lists..."])
            self.assertEqual(tpl.get_power_state(), power)
        rc, out, err = self.cli("template", "install", "ai-hang-r", "curl")
        self.assertEqual(rc, 1)
        self.assertIn("check the template", out)

    def test_a_shutdown_that_does_not_complete_is_said_and_fails_the_report(self):
        self.app.fail.add("shutdown")
        try:
            rc, out, err = self.cli("template", "install", self.TPL, "curl")
        finally:
            self.app.fail.discard("shutdown")
        self.assertEqual(rc, 1)
        self.assertIn("installed with apt-get", out)
        self.assertIn("its shutdown did not complete", out)
        self.assertNotIn("shut down again", out)
        self.app.vmshell["ai-hang"] = "hanginstall"
        self.app.vm("ai-hang", klass="TemplateVM", tags={"ai-managed"})
        self.app.fail.add("shutdown")
        try:
            r = inqube.install(self.app, "ai-hang", ["curl"], timeout=0.01)
        finally:
            self.app.fail.discard("shutdown")
        self.assertIn("its shutdown did not complete, so the install may still be running",
                      r["status"])
        self.assertIs(r["stopped"], False)

    def test_every_packages_version_fits_in_the_tail(self):
        names = [f"p{i}" for i in range(inqube.MAX_PACKAGES)]
        self.app.repo.update(names)
        r = inqube.install(self.app, self.TPL, names)
        self.assertEqual(r["lines"][-len(names):], [f"installed: {n} 1.0" for n in names])

    def test_the_lock_is_never_followed_through_a_link_or_taken_from_another(self):
        target = self.tmp / "elsewhere"
        target.write_text("")
        link = os.path.join(core.state_dir(), f"inqube-{self.TPL}.lock")
        os.makedirs(core.state_dir(), exist_ok=True)
        os.symlink(target, link)
        with self.assertRaises(inqube.InQubeError):
            inqube.install(self.app, self.TPL, ["curl"])
        self.assertEqual(target.read_text(), "")
        self.assertEqual(self.app.vmshell_scripts, [])
        os.unlink(link)
        self.assertTrue(inqube.install(self.app, self.TPL, ["curl"])["ok"])

    def test_one_writer_at_a_time_in_a_qube(self):
        # An install or a prepare that started a qube shuts it down at the end,
        # which would stop another's write part-way: the second refuses, after
        # trying the lock again for half a second (the gate's sweep holds it briefly).
        with inqube._OneWriter(self.TPL):
            with self.assertRaises(inqube.InQubeError) as cm:
                inqube.install(self.app, self.TPL, ["curl"])
            self.assertIn("another prepare or install", str(cm.exception))
            with self.assertRaises(inqube.InQubeError):
                inqube.prepare(self.app, self.TPL)
        self.assertEqual(self.app.vmshell_scripts, [])
        self.assertEqual(self.tpl().get_power_state(), "Halted")
        self.assertTrue(inqube.install(self.app, self.TPL, ["curl"])["ok"])

    def test_endless_output_costs_dom0_a_bounded_tail(self):
        self.app.vmshell[self.TPL] = "flood"
        r = inqube.install(self.app, self.TPL, ["curl"])
        self.assertTrue(r["ok"])
        self.assertLessEqual(len(r["lines"]), inqube.TAIL_LINES)
        self.assertTrue(all(len(line) <= 300 for line in r["lines"]))
        # A megabyte written; a thousand bytes kept.
        rc, tail = inqube._run_bounded(self._running(), b"flood", 5, keep=1000)
        self.assertEqual(len(tail), 1000)

    def test_a_qube_that_keeps_its_output_open_never_hangs_the_command(self):
        # The process ends but the pipe stays open (a child of it holds it):
        # the reader stays blocked, and closing that pipe from the command
        # would wait on the read for good. The command returns instead.
        import threading
        import time as _time
        r, w = os.pipe()

        class Held:
            stdout = os.fdopen(r, "rb")
            returncode = 0

            class stdin:
                @staticmethod
                def write(data):
                    return len(data)

                @staticmethod
                def close():
                    os.write(w, b"partial output\n")

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        vm = self._running()
        vm.__dict__["run_service"] = lambda *a, **kw: Held()
        done = {}
        worker = threading.Thread(target=lambda: done.update(
            out=inqube._run_bounded(vm, b"x", 5)), daemon=True)
        t0 = _time.monotonic()
        worker.start()
        worker.join(20)
        try:
            self.assertFalse(worker.is_alive(), "the command hung on a pipe left open")
            self.assertLess(_time.monotonic() - t0, 15)
            self.assertEqual(done["out"], (0, b"partial output\n"))
        finally:
            os.close(w)                 # frees the reader the command left behind

    def _running(self):
        vm = self.app.vm("ai-flood", klass="TemplateVM", power="Running", tags={"ai-managed"})
        self.app.vmshell[vm.name] = "flood"
        return vm

    def test_the_templates_words_are_escaped_never_laid_out(self):
        r = inqube.install(self.app, self.TPL, ["curl"])
        shown = "\n".join(r["lines"])
        self.assertNotIn("\x1b", shown)
        self.assertNotIn(chr(0x202E), shown)
        self.assertIn("\\u001b[31mred\\u202eevil", shown)

    def test_the_command_reports_and_exits_on_the_status(self):
        rc, out, err = self.cli("template", "install", self.TPL, "curl", "jq")
        self.assertEqual(rc, 0, err)
        self.assertIn("ai-tpl-g: installed with apt-get", out)
        self.assertIn("started for this and shut down again", out)
        self.assertIn("escaped:", out)
        rc, out, err = self.cli("template", "install", self.TPL, "nosuch")
        self.assertEqual(rc, 1)
        self.assertIn("refused inside the template", out)
        self.assertNotIn("get the packages", out)
        rc, out, err = self.cli("template", "install", self.TPL, "sl-")
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("removing the package", err)
        rc, out, err = self.cli("template", "install", self.TPL, "curl", root=False)
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.tpl().installed_packages(), ["curl", "jq"])

    def test_each_run_leaves_one_operator_line_with_its_packages(self):
        self.cli("template", "install", self.TPL, "curl")
        self.cli("template", "install", self.TPL, "nosuch")
        lines = [l for l in self.audit_lines() if l["service"] == "qmcp template install"]
        self.assertEqual([(l["ok"], l["args"]) for l in lines],
                         [(True, {"qube": self.TPL, "packages": ["curl"]}),
                          (False, {"qube": self.TPL, "packages": ["nosuch"]})])



class InstallSealStep(unittest.TestCase):
    """The installer's seal step, cut out of install.sh and run against stub
    modules: it goes on past a seal whose kill is pending only when no qube
    reads as wearing an open badge, and stops on anything else."""

    TEXT = (HERE.parent / "deploy" / "install.sh").read_text()

    def step(self, rc, left="", left_fails=False):
        import tempfile
        start = self.TEXT.index("# Exit 3 is also a kill a seal could not make yet")
        end = self.TEXT.index("\n", self.TEXT.index('[ "$SEAL_RC" -eq 0 ] && [ -n "$SEAL_OUT" ]', start))
        lib = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-seal-step-"))
        self.addCleanup(shutil.rmtree, lib)
        (lib / "qmcp").mkdir()
        (lib / "qubesadmin").mkdir()
        (lib / "qmcp" / "__init__.py").write_text("")
        (lib / "qmcp" / "cli.py").write_text(
            f"def main(argv):\n    print('sealed ai-x')\n    return {rc}\n")
        (lib / "qmcp" / "fleet.py").write_text(
            "def open_badge_holders(app):\n"
            + ("    raise RuntimeError('read')\n" if left_fails else f"    return {left.split()!r}\n"))
        (lib / "qubesadmin" / "__init__.py").write_text("")
        (lib / "qubesadmin" / "app.py").write_text("class QubesLocal:\n    pass\n")
        script = ('set -euo pipefail\n'
                  'die() { echo "install.sh: $*" >&2; exit 1; }\nsay() { echo "==> $*"; }\n'
                  f'LIB="{lib}"\n' + self.TEXT[start:end] + '\necho GOES-ON\n')
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def test_a_clean_seal_goes_on(self):
        r = self.step(0)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("GOES-ON", r.stdout)

    def test_a_pending_kill_with_no_badge_left_goes_on_and_says_so(self):
        r = self.step(3)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("could not kill its qube yet", r.stdout)
        self.assertIn("GOES-ON", r.stdout)

    def test_a_badge_still_on_stops_the_install(self):
        r = self.step(3, left="ai-x")
        self.assertEqual(r.returncode, 1)
        self.assertIn("still open: ai-x", r.stderr)
        self.assertNotIn("GOES-ON", r.stdout)

    def test_a_read_that_fails_stops_the_install(self):
        r = self.step(3, left_fails=True)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("GOES-ON", r.stdout)

    def test_any_other_failure_stops_the_install(self):
        r = self.step(1)
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be sealed", r.stderr)
        self.assertNotIn("GOES-ON", r.stdout)

if __name__ == "__main__":
    unittest.main()
