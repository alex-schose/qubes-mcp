"""Offline suite for the dom0 library (dom0/qmcp) against tests/fakequbes.py.

Every security property M1 claims for the services and the operator commands,
with teeth: where a v0.9.16 defect is being closed,
the test first shows the fake can reproduce the dangerous behaviour, then
that the library does not let it through.
"""
from __future__ import annotations

import fcntl
import grp
import io
import json
import os
import pathlib
import shutil
import sys
import threading
import time
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import anon, audit, birth, budget, core, firewall, fleet, gateways, inqube, projects, proposals, restored, services  # noqa: E402
import fakequbes  # noqa: E402
import scratch  # noqa: E402
from fakequbes import GiB, SECRET, standard_fleet  # noqa: E402

HUB = "mcp-control"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = scratch.tempdir(self, "qmcp-dom0-")
        self._saved = []
        for mod, attr, value in [
            (core, "HUB_PATH", self.tmp / "hub"),
            (audit, "DROPPED_PATH", str(self.tmp / "run" / "audit-dropped")),
            (core, "MODE_PATH", self.tmp / "mode"),
            (core, "RUN_DIR", self.tmp / "run"),
            (budget, "CAP_PATH", self.tmp / "pool-cap"),
            (budget, "PRIVATE_CAP_PATH", self.tmp / "private-cap"),
            (budget, "LOCK_PATH", self.tmp / "run" / "create.lock"),
            (budget, "LOCK_TIMEOUT_S", 0.5),
            (core, "QUBE_WAIT_S", 0.3),
            (core, "OPERATOR_WAIT_S", 0.3),
            (fleet, "OPEN_LOCK_WAIT_S", 0.3),
            (fleet, "MOVE_SETTLE_S", 0.0),
            (anon, "KILL_LOCK_WAIT_S", 0.3),
            (birth, "NAME_PREFIX_PATH", self.tmp / "name-prefix"),
            (birth, "BIRTH_EGRESS_PATH", self.tmp / "birth-egress"),
            (audit, "LOG_PATH", self.tmp / "audit.log"),
            (audit, "MODE_PATH", self.tmp / "audit-mode"),
            (audit, "KEEP_DAYS_PATH", self.tmp / "audit-keep-days"),
            (audit, "CLOCK_PATH", str(self.tmp / "lib" / "audit-clock")),
            (audit, "CLOCK_MOVED_PATH", str(self.tmp / "lib" / "audit-clock-moved")),
            (restored, "REPLACED_PATH", str(self.tmp / "lib" / "replaced-labels")),
            (restored, "REMOVED_DIR", str(self.tmp / "lib" / "removed")),
            (fleet, "TIER_DEFAULT_PATH", self.tmp / "tier-default"),
            (fleet, "ENFORCE_MODE_PATH", self.tmp / "enforce-mode"),
            (fleet, "GUARDED_LIST_PATH", self.tmp / "guarded"),
            (services, "DISPOSE_WAIT_S", 0.01),
            (projects, "PROJECTS_PATH", self.tmp / "projects.json"),
            (gateways, "GATEWAYS_PATH", self.tmp / "gateways.json"),
            (projects, "LOCK_PATH", self.tmp / "run" / "projects.lock"),
            (proposals, "PROPOSALS_DIR", self.tmp / "proposals"),
            (proposals, "LOCK_PATH", self.tmp / "run" / "proposals.lock"),
            (proposals, "BUS_DIR", self.tmp / "no-session"),
            (fleet, "WINDOW_DIR", self.tmp / "run" / "open"),
            (fleet, "SEAL_DROPIN", self.tmp / "10-qmcp-seal.conf"),
            (anon, "LOCK_PATH", self.tmp / "run" / "gate.lock"),
            (anon, "HEARTBEAT_PATH", self.tmp / "run" / "gate.last"),
            # The files the fixtures make are this user's group, as tmpfiles makes
            # them the services' group on a real dom0.
            (fleet, "SERVICES_GROUP", grp.getgrgid(os.getegid()).gr_name),
        ]:
            self._saved.append((mod, attr, getattr(mod, attr)))
            setattr(mod, attr, value if isinstance(value, float) else str(value))
        # The gate's timer runs, as on an installed dom0: `qmcp check` judges it
        # in every mode, and this host has no systemd unit to ask.
        self._saved.append((anon, "TIMER_CHECK", anon.TIMER_CHECK))
        anon.TIMER_CHECK = lambda: True
        self.addCleanup(self._restore)
        # The boot seal's drop-in, as the installer writes it.
        (self.tmp / "10-qmcp-seal.conf").write_text(
            (pathlib.Path(__file__).parent.parent / "deploy" / "qubes-vm-qmcp-seal.conf").read_text())
        (self.tmp / "run" / "calls").mkdir(parents=True)
        (self.tmp / "run" / "open").mkdir()
        (self.tmp / "run" / "qubes").mkdir()
        for d in ("run", "run/calls", "run/open", "run/qubes"):  # as tmpfiles makes them
            os.chmod(self.tmp / d, 0o2770)
        (self.tmp / "lib" / "removed").mkdir(parents=True)        # as tmpfiles makes it
        os.chmod(self.tmp / "lib" / "removed", 0o2770)
        (self.tmp / "proposals").mkdir(mode=0o2770)
        os.chmod(self.tmp / "proposals", 0o2770)
        # As the installer and tmpfiles leave it: present, group-writable.
        (self.tmp / "audit.log").touch(mode=0o660)
        os.chmod(self.tmp / "audit.log", 0o660)
        for f in ("gate.lock", "gate.last"):        # tmpfiles declares both
            (self.tmp / "run" / f).touch(mode=0o660)
            os.chmod(self.tmp / "run" / f, 0o660)
        (self.tmp / "hub").write_text(HUB + "\n")
        (self.tmp / "pool-cap").write_text(str(1000 * GiB) + "\n")
        (self.tmp / "private-cap").write_text(str(20 * GiB) + "\n")
        # As the installer leaves every operator file, whatever the umask
        # (dom0's is 0077): `qmcp check` fails on one not every user can read.
        for f in ("hub", "pool-cap", "private-cap"):
            os.chmod(self.tmp / f, 0o644)
        self.app = standard_fleet()
        # As after the operator enrolled the fleet's AI router: the registry
        # starts empty on install, and the fixtures assume a working fleet.
        self.enroll("ai-net-router")

    def _restore(self):
        for mod, attr, value in reversed(self._saved):
            setattr(mod, attr, value)

    def call(self, service, req=None, caller=HUB, raw=None, app=None):
        out = io.StringIO()
        data = raw if raw is not None else json.dumps(req or {}).encode()
        rc = services.main(service, stdin=io.BytesIO(data),
                           environ={"QREXEC_REMOTE_DOMAIN": caller} if caller else {},
                           app_factory=lambda: app or self.app, out=out)
        reply = json.loads(out.getvalue())
        self.assertEqual(rc, 0 if reply.get("ok") else 1)
        return reply

    def audit_lines(self):
        p = pathlib.Path(audit.LOG_PATH)
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def logged(self):
        """The audit lines of calls, without the one each cap leaves."""
        return [l for l in self.audit_lines() if l["service"] != audit.CAPPED_SERVICE]

    def capped(self):
        return [(l["caller"], l["args"]["cap"]) for l in self.audit_lines()
                if l["service"] == audit.CAPPED_SERVICE]

    def enroll(self, name, anonymising=False, label=""):
        registry = gateways.load()
        registry[name] = gateways.Gateway(name, anonymising, label)
        gateways.save(registry)

    def egress(self, name):
        pathlib.Path(birth.BIRTH_EGRESS_PATH).write_text(name + "\n")

    def tags(self, name):
        self.app.domains.clear_cache()
        return set(self.app.domains[name].tags)


class TempDirs(unittest.TestCase):
    """Every suite built on Base leaves nothing in the temp dir, whatever the
    outcome of its test."""

    def _outcome_of(self, body):
        seen = {}

        class Inner(Base):
            def runTest(inner):
                seen["tmp"] = inner.tmp
                body(inner)

        result = unittest.TestResult()
        Inner().run(result)
        return seen["tmp"], result

    def test_a_failed_test_leaves_no_temp_dir(self):
        def body(t):
            t.fail("on purpose")
        tmp, result = self._outcome_of(body)
        self.assertEqual((len(result.failures), result.errors), (1, []))
        self.assertFalse(tmp.exists())

    def test_an_errored_test_leaves_no_temp_dir(self):
        def body(t):
            raise RuntimeError("on purpose")
        tmp, result = self._outcome_of(body)
        self.assertEqual((result.failures, len(result.errors)), ([], 1))
        self.assertFalse(tmp.exists())

    def test_a_tree_left_unwritable_is_still_removed(self):
        def body(t):
            os.chmod(t.tmp / "run" / "qubes", 0o000)
            os.chmod(t.tmp / "run", 0o500)
        tmp, result = self._outcome_of(body)
        self.assertTrue(result.wasSuccessful(), result.errors)
        self.assertFalse(tmp.exists())

    def test_a_link_out_of_the_tree_is_not_followed(self):
        outside = scratch.tempdir(self, "qmcp-outside-")
        (outside / "keep").write_text("x")
        os.chmod(outside, 0o500)
        self.addCleanup(os.chmod, outside, 0o700)

        def body(t):
            os.symlink(outside, t.tmp / "out")
            os.chmod(t.tmp, 0o500)               # forces the second pass
        tmp, result = self._outcome_of(body)
        self.assertTrue(result.wasSuccessful(), result.errors)
        self.assertFalse(tmp.exists())
        self.assertEqual(((outside / "keep").read_text(), oct(os.stat(outside).st_mode & 0o777)),
                         ("x", "0o500"))


# ======================================================================= funnel

class Funnel(Base):
    def test_caller_must_be_the_hub(self):
        for caller in (None, "", "ai-work", "dom0 ", "personal"):
            r = self.call("qmcp.ListAIManagedQubes", caller=caller)
            self.assertEqual(r, core.NOT_AUTHORIZED, caller)

    def test_no_hub_file_means_no_hub(self):
        (self.tmp / "hub").unlink()
        self.assertEqual(self.call("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)
        (self.tmp / "hub").write_text("not a name!\n")
        self.assertEqual(self.call("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)

    def test_request_cap_before_parse(self):
        big = json.dumps({"name": "ai-work", "pad": "x" * core.MAX_REQUEST_BYTES}).encode()
        r = self.call("qmcp.SetPropertyAIManaged", raw=big)
        self.assertEqual(r["error"], "request too large")
        # Refused before the caller is checked, so it changes nothing and is not
        # audited: AI space must not be able to fill the log.
        self.assertEqual(self.audit_lines(), [])

    def test_invalid_json_is_not_echoed(self):
        r = self.call("qmcp.GetPropertyAIManaged", raw=b'{"name": "SECRET-ish')
        self.assertEqual(r, {"ok": False, "error": "invalid JSON input"})
        r = self.call("qmcp.GetPropertyAIManaged", raw=b'["a list"]')
        self.assertEqual(r["error"], "request must be a JSON object")

    def test_unknown_service(self):
        self.assertEqual(self.call("qmcp.Nope")["error"], "unknown service")

    def test_concurrency_cap(self):
        held = [core.acquire_call_slot(HUB) for _ in range(core.MAX_CONCURRENT_CALLS)]
        try:
            self.assertEqual(self.call("qmcp.ListAIManagedQubes")["error"],
                             "too many concurrent calls")
        finally:
            for fd in held:
                os.close(fd)
        self.assertTrue(self.call("qmcp.ListAIManagedQubes")["ok"])

    def test_runtime_dir_missing_fails_closed(self):
        shutil.rmtree(self.tmp / "run")
        self.assertEqual(self.call("qmcp.ListAIManagedQubes")["error"],
                         "qmcp runtime directory unavailable")

    def test_audit_carries_caller_never_value(self):
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 777})
        line = self.audit_lines()[-1]
        self.assertEqual((line["caller"], line["service"], line["v"]), (HUB, "qmcp.SetPropertyAIManaged", 2))
        self.assertEqual(line["args"], {"name": "ai-work", "property": "memory"})
        # Not in any field but the chain's own: the line's hash holds "777" by
        # chance about once in seventy runs.
        self.assertNotIn("777", json.dumps({k: v for k, v in line.items()
                                            if k not in ("hash", "prev", "ts")}))
        ok, n, err = audit.verify()
        self.assertTrue(ok, err)

    def test_a_log_line_that_is_not_utf8_breaks_the_chain_at_its_line(self):
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 777})
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 778})
        self.assertEqual(audit.verify(), (True, 2, None))           # the positive
        p = pathlib.Path(audit.LOG_PATH)
        lines = p.read_bytes().splitlines()
        p.write_bytes(lines[0] + b"\n" + lines[1][:-2] + b"\xff}\n")
        self.assertEqual(audit.verify(), (False, 2, "line 2 is not UTF-8"))
        p.write_bytes(lines[0] + b"\n[1]\n")
        self.assertEqual(audit.verify(), (False, 2, "unparseable line 2"))

    def test_two_rotations_in_one_second_keep_both_logs(self):
        # The rotated name is the time to the second, exactly as retention
        # matches it: a second rotation within that second waits for the next
        # one rather than failing at the link or taking another name.
        import re
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 777})
        first = audit.rotate()
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 778})
        frozen = os.path.basename(first).rsplit(".", 1)[1]
        import datetime
        real = datetime.datetime
        calls = []

        class Clock(real):
            @classmethod
            def now(cls, tz=None):
                calls.append(1)
                t = real.strptime(frozen, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
                if len(calls) == 1:   # still the first rotation's second
                    return t.replace(microsecond=990000)
                return t + datetime.timedelta(seconds=1)
        with mock.patch.object(datetime, "datetime", Clock), \
                mock.patch("time.sleep") as nap:
            second = audit.rotate()
        nap.assert_called_once()
        self.assertNotEqual(first, second)
        for aside in (first, second):
            self.assertRegex(os.path.basename(aside), r"\.\d{8}T\d{6}Z$")
        names = [n for n, _ in audit.rotated()]
        self.assertIn(os.path.basename(first), names)
        self.assertIn(os.path.basename(second), names)
        self.assertEqual(audit.verify(first), (True, 1, None))
        self.assertEqual(audit.verify(second), (True, 2, None))

    def test_a_rotation_never_leaves_the_log_missing(self):
        # A writer finding no file at the log's name would start a fresh,
        # unanchored chain from GENESIS.
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 777})
        seen, real_link, real_rename = [], os.link, os.rename

        def watch(fn):
            def call(*a, **kw):
                seen.append(os.path.exists(audit.LOG_PATH))
                out = fn(*a, **kw)
                seen.append(os.path.exists(audit.LOG_PATH))
                return out
            return call
        with mock.patch.object(audit.os, "link", watch(real_link)), \
                mock.patch.object(audit.os, "rename", watch(real_rename)):
            aside = audit.rotate()
        self.assertTrue(seen and all(seen), seen)
        self.assertEqual(audit.verify(aside), (True, 1, None))
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 778})
        self.assertEqual(audit.verify(), (True, 2, None))
        self.assertFalse(os.path.exists(audit.LOG_PATH + ".rotating"))

    def test_a_counter_rewrite_cut_short_keeps_its_counts(self):
        path = os.path.join(self.tmp, "c.refused")
        pathlib.Path(path).write_text('{"day": "2026-10-18", "lines": 12345, "unlogged": 7}\n')
        # The new, shorter record written over the start, the truncate never run.
        pathlib.Path(path).write_text('{"day": "2026-10-18", "lines": 9}\n' + "345, \"x\": 7}\n")
        self.assertEqual(audit._update(path, lambda rec: rec["lines"]), 9)

    def test_reads_are_not_audited(self):
        self.call("qmcp.ListAIManagedQubes")
        self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "memory"})
        self.assertEqual(self.audit_lines(), [])

    def test_an_audit_write_that_fails_is_counted_and_check_fails(self):
        # A write that fails with room on the disk (here: the log is a
        # directory) does not undo the call, which already ran; it is counted
        # where a full /var cannot reach, and qmcp check fails until removed.
        (self.tmp / "logdir").mkdir()
        audit.LOG_PATH = str(self.tmp / "logdir")
        for value in (500, 600):
            r = self.call("qmcp.SetPropertyAIManaged",
                          {"name": "ai-work", "property": "memory", "value": value})
            self.assertEqual(r, {"ok": True})
        count, first = audit.dropped()
        self.assertEqual(count, 2)
        self.assertTrue(first)
        found = {f.check: f for f in fleet.check(self.app, legacy_paths=(),
                                                 system_info={"domains": {}})}
        self.assertEqual(found["audit lines lost"].status, "fail")
        self.assertIn("2 line(s) could not be written", found["audit lines lost"].detail)
        os.unlink(audit.DROPPED_PATH)
        self.assertIsNone(audit.dropped())

    def test_below_the_floor_a_change_is_refused_before_it_acts(self):
        # Nothing changes without its line (decided for a full disk): with too little
        # room for the log the services refuse what would change something,
        # and change nothing; reads go on. The refusal itself is not audited.
        vm = self.app.domains["ai-work"]
        before = vm.memory
        with mock.patch.object(audit, "FLOOR_BYTES", 1 << 62):
            r = self.call("qmcp.SetPropertyAIManaged",
                          {"name": "ai-work", "property": "memory", "value": before + 100})
            self.assertEqual(r, {"ok": False, "error": services.NO_AUDIT_ROOM})
            self.assertEqual(vm.memory, before)
            self.assertTrue(self.call("qmcp.ListAIManagedQubes")["ok"])
            self.assertEqual(self.audit_lines(), [])
            found = {f.check: f for f in fleet.check(self.app, legacy_paths=(),
                                                     system_info={"domains": {}})}
            self.assertEqual(found["audit room"].status, "fail")
        r = self.call("qmcp.SetPropertyAIManaged",
                      {"name": "ai-work", "property": "memory", "value": before + 100})
        self.assertEqual(r, {"ok": True})
        self.assertEqual(len(self.audit_lines()), 1)

    def test_below_the_floor_a_kill_still_goes_on_and_nothing_else(self):
        vm = self.app.domains["ai-work"]
        with mock.patch.object(audit, "FLOOR_BYTES", 1 << 62):
            r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-work", "action": "kill"})
            self.assertEqual(r, {"ok": True})
            self.assertEqual(vm.get_power_state(), "Halted")
            for action in ("start", "shutdown"):
                r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-work", "action": action})
                self.assertEqual(r, {"ok": False, "error": services.NO_AUDIT_ROOM}, action)
            self.assertEqual(vm.get_power_state(), "Halted")

    def test_below_the_floor_only_a_kill_that_was_done_is_logged(self):
        # A refused kill changes nothing: logged, it would let a principal fill
        # the disk past the floor, one refused call at a time.
        with mock.patch.object(audit, "FLOOR_BYTES", 1 << 62):
            for _ in range(3):
                r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-no-such", "action": "kill"})
                self.assertFalse(r["ok"])
            self.assertEqual(self.audit_lines(), [])
            r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-work", "action": "kill"})
            self.assertEqual(r, {"ok": True})
            self.assertEqual(len(self.audit_lines()), 1)

    def counter(self, caller=HUB):
        return os.path.join(core.RUN_DIR, "calls", caller + audit.REFUSED_SUFFIX)

    def test_refusals_past_the_hourly_cap_are_counted_not_logged(self):
        # A compromised principal must not fill the log's disk to the floor
        # with refusals that change nothing: past the cap they are counted, on
        # tmpfs, and qmcp check names the caller.
        bad = {"name": "ai-work", "property": "no-such", "value": 1}
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 3):
            for _ in range(5):
                self.assertFalse(self.call("qmcp.SetPropertyAIManaged", bad)["ok"])
            self.assertEqual(len(self.logged()), 3)
            # The first call past the cap leaves one line, the second none:
            # the counter is on tmpfs, the chain keeps that calls were withheld.
            self.assertEqual(self.capped(), [(HUB, "hour")])
            found = {f.check: f for f in fleet.check(self.app, legacy_paths=(),
                                                     system_info={"domains": {}})}
            self.assertEqual(found["calls not logged"].status, "warn")
            self.assertIn(f"{HUB}: 2 call(s) past 3 in an hour", found["calls not logged"].detail)
            # A change is logged whatever the count.
            r = self.call("qmcp.SetPropertyAIManaged",
                          {"name": "ai-work", "property": "memory", "value": 700})
            self.assertEqual(r, {"ok": True})
            self.assertEqual(len(self.logged()), 4)
            self.assertIsNone(audit.dropped())

    def test_a_write_that_landed_before_it_raised_is_always_logged(self):
        key = sorted(services.FEATURE_KEYS)[0]
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            for fail, service, req in (
                    ("set.memory.landed", "qmcp.SetPropertyAIManaged",
                     {"name": "ai-work", "property": "memory", "value": 701}),
                    ("feature.set.landed", "qmcp.SetFeatureAIManaged",
                     {"name": "ai-work", "feature": key, "value": "7"})):
                with self.subTest(fail):
                    self.app.fail.add(fail)
                    n = len(self.audit_lines())
                    self.assertFalse(self.call(service, req)["ok"])
                    self.app.fail.discard(fail)
                    self.assertEqual(len(self.audit_lines()), n + 1)

    def test_a_failed_call_that_created_nothing_is_capped_whatever_raised(self):
        # The cap keys on what landed, not on whether an exception was behind
        # the refusal: a malformed field that raises, or a qubesd call dom0
        # refused, is as cheap to repeat as a plain refusal.
        key = sorted(services.FEATURE_KEYS)[0]
        self.app.fail.add("feature.set")
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            r = self.call("qmcp.SetFeatureAIManaged", {"name": "ai-work", "feature": key, "value": "1"})
            self.assertEqual(r, {"ok": False, "error": "feature.Set failed"})
            r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-x", "template": "ai-debian-13",
                                                      "klass": []})
            self.assertFalse(r["ok"])
        self.assertEqual(self.logged(), [])
        self.assertEqual(audit.unlogged_refusals(os.path.dirname(self.counter()))[0][:2], (HUB, 2))

    def test_a_set_to_the_value_already_there_is_capped_and_still_answers_ok(self):
        # A successful call that changes nothing is as cheap to repeat as a
        # refusal: capped. A real change, and a pin of a default, still log.
        vm = self.app.domains["ai-work"]
        vm.label = "gray"
        vm.__dict__["_defaults"].discard("label")
        key = sorted(services.FEATURE_KEYS)[0]
        vm.features[key] = "1"
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            for _ in range(3):
                self.assertEqual(self.call("qmcp.SetPropertyAIManaged",
                                           {"name": "ai-work", "property": "label", "value": "gray"}),
                                 {"ok": True})
                self.assertTrue(self.call("qmcp.SetFeatureAIManaged",
                                          {"name": "ai-work", "feature": key, "value": "1"})["ok"])
            self.assertEqual(self.logged(), [])
            r = self.call("qmcp.SetPropertyAIManaged",
                          {"name": "ai-work", "property": "label", "value": "blue"})
            self.assertEqual(r, {"ok": True})
            vm.__dict__["_defaults"].add("memory")
            r = self.call("qmcp.SetPropertyAIManaged",
                          {"name": "ai-work", "property": "memory", "value": vm.memory})
            self.assertEqual(r, {"ok": True})
        self.assertEqual([l["args"].get("property") for l in self.logged()], ["label", "memory"])
        self.assertEqual(audit.unlogged_refusals(os.path.dirname(self.counter()))[0][:2], (HUB, 6))

    def test_an_accepted_shut_down_and_kill_are_logged_past_the_cap(self):
        # Nothing changes without its line: what dom0 carried out is logged.
        vm = self.app.domains["ai-work"]
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            vm.start()
            self.assertEqual(self.call("qmcp.LifecycleAIManaged",
                                       {"name": "ai-work", "action": "shutdown"}), {"ok": True})
            vm.start()
            self.assertEqual(self.call("qmcp.LifecycleAIManaged",
                                       {"name": "ai-work", "action": "kill"}), {"ok": True})
        self.assertEqual([l["args"]["action"] for l in self.audit_lines()], ["shutdown", "kill"])

    def test_the_cap_is_per_caller_and_per_hour(self):
        a, b = self.counter("ai-lead-a"), self.counter("ai-lead-b")
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 2):
            got = [audit.take_refusal(a, "2026-10-16T10:00:00Z") for _ in range(3)]
            self.assertEqual(got, [True, True, False])
            self.assertTrue(audit.take_refusal(b, "2026-10-16T10:00:01Z"))
            # The next hour logs again; what was withheld stays counted.
            self.assertTrue(audit.take_refusal(a, "2026-10-16T11:00:00Z"))
        self.assertEqual(audit.unlogged_refusals(os.path.dirname(a)),
                         [("ai-lead-a", 1, "2026-10-16T10:00:00Z")])

    def test_a_counter_that_cannot_be_kept_logs_the_line(self):
        # The cap only withholds a line it has counted.
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            self.assertTrue(audit.take_refusal(str(self.tmp / "no" / "dir" / "x.refused")))
        # One that does not read: the cap logs the line; the budget, a gate,
        # refuses; qmcp check names it.
        p = self.counter()
        pathlib.Path(p).write_text("not json")
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            self.assertTrue(audit.take_refusal(p))
        self.assertIsNone(audit.budget_left(p))
        self.assertEqual(audit.unlogged_refusals(os.path.dirname(p))[0][:2], (HUB, None))

    def test_a_counter_the_services_cannot_keep_fails_check(self):
        # It refuses that principal's every change (the budget fails closed),
        # so the check fails on it, by its content, group and mode, whoever runs it.
        p = pathlib.Path(self.counter())
        for content, mode in (("{", 0o660), ("{}", 0o600)):
            p.write_text(content)
            os.chmod(p, mode)
            if content == "{":
                self.assertIsNone(audit.budget_left(str(p)))
                r = self.call("qmcp.SetPropertyAIManaged",
                              {"name": "ai-work", "property": "memory", "value": 777})
                self.assertEqual(r, {"ok": False, "error": services.NO_AUDIT_COUNTER})
            found = {f.check: f for f in fleet.check(self.app, legacy_paths=(),
                                                     system_info={"domains": {}})}
            self.assertEqual(found["audit counter"].status, "fail", (content, oct(mode)))
            self.assertIn("every change of that principal but a kill is refused",
                          found["audit counter"].detail)
        os.chmod(p, 0o660)
        found = {f.check: f for f in fleet.check(self.app, legacy_paths=(),
                                                 system_info={"domains": {}})}
        self.assertNotIn("audit counter", found)

    def test_a_caller_past_its_daily_budget_is_refused_and_the_others_go_on(self):
        # One principal spends only its own share: past it, a change is
        # refused before it acts and not logged; a kill goes on; another
        # caller is untouched; check names the caller.
        vm = self.app.domains["ai-work"]
        with mock.patch.object(audit, "AUDIT_LINES_PER_DAY", 2):
            for value in (500, 600):
                self.assertEqual(self.call("qmcp.SetPropertyAIManaged",
                                           {"name": "ai-work", "property": "memory", "value": value}),
                                 {"ok": True})
            r = self.call("qmcp.SetPropertyAIManaged",
                          {"name": "ai-work", "property": "memory", "value": 700})
            self.assertEqual(r, {"ok": False, "error": services.NO_AUDIT_BUDGET})
            self.assertEqual(vm.memory, 600)
            self.assertEqual(len(self.logged()), 2)
            self.assertEqual(self.capped(), [(HUB, "day")])
            self.call("qmcp.SetPropertyAIManaged",
                      {"name": "ai-work", "property": "memory", "value": 800})
            self.assertEqual(self.capped(), [(HUB, "day")])            # once a day
            # Past the budget a kill still acts, its line under the hourly cap.
            with mock.patch.object(audit, "REFUSALS_PER_HOUR", 1):
                for n in range(3):
                    vm.start()
                    self.assertEqual(self.call("qmcp.LifecycleAIManaged",
                                               {"name": "ai-work", "action": "kill"}), {"ok": True})
                    self.assertEqual(vm.get_power_state(), "Halted")
            self.assertEqual(len(self.logged()), 3)            # one kill logged, two counted
            found = {f.check: f for f in fleet.check(self.app, legacy_paths=(),
                                                     system_info={"domains": {}})}
            self.assertEqual(found["audit budget spent"].status, "warn")
            self.assertIn(f"{HUB}: 2 line(s) today", found["audit budget spent"].detail)
            self.assertIn(f"{HUB}: 2 call(s) past {audit.REFUSALS_PER_HOUR} in an hour", found["calls not logged"].detail)
            self.assertIn("2 change(s) refused", found["audit budget spent"].detail)
            # The cap's lines do not spend the budget, and another caller has its own.
            other = self.counter("ai-osint-lead")
            self.assertTrue(audit.budget_left(other))

    def test_lines_of_calls_that_changed_nothing_do_not_spend_the_budget(self):
        with mock.patch.object(audit, "AUDIT_LINES_PER_DAY", 1):
            for _ in range(3):
                self.assertFalse(self.call("qmcp.SetPropertyAIManaged",
                                           {"name": "ai-work", "property": "no-such", "value": 1})["ok"])
            self.assertEqual(self.call("qmcp.SetPropertyAIManaged",
                                       {"name": "ai-work", "property": "memory", "value": 555}),
                             {"ok": True})
        self.assertEqual(len(self.audit_lines()), 4)

    def test_check_reads_a_counter_under_its_lock(self):
        # A writer truncates before it writes: an unlocked read could catch the
        # gap and report a counter that does not read.
        import threading
        p = self.counter()
        audit.spend(p)
        stop, torn = threading.Event(), []

        def writer():
            while not stop.is_set():
                audit.spend(p)
        t = threading.Thread(target=writer)
        t.start()
        try:
            for _ in range(2000):
                rec = dict(audit.counters(os.path.dirname(p))).get(HUB)
                if not rec or "lines" not in rec:       # unreadable, or caught empty
                    torn.append(rec)
        finally:
            stop.set()
            t.join()
        self.assertEqual(torn, [])

    def test_the_budget_is_per_utc_day(self):
        p = self.counter()
        with mock.patch.object(audit, "AUDIT_LINES_PER_DAY", 1):
            audit.spend(p, "2026-10-16T23:59:00Z")
            self.assertFalse(audit.budget_left(p, "2026-10-16T23:59:30Z"))
            self.assertTrue(audit.budget_left(p, "2026-10-17T00:00:01Z"))

    def test_a_log_directory_that_does_not_stat_has_no_room(self):
        self.assertTrue(audit.room())
        self.assertFalse(audit.room(str(self.tmp / "no" / "such" / "dir" / "log")))

    def test_a_refusal_before_the_principal_check_is_not_audited(self):
        r = self.call("qmcp.SetPropertyAIManaged",
                      {"name": "ai-work", "property": "memory", "value": 500}, caller="personal")
        self.assertEqual(r, core.NOT_AUTHORIZED)
        self.assertEqual(self.audit_lines(), [])
        self.assertIsNone(audit.dropped())

    def test_internal_error_is_opaque(self):
        self.app.fail.add("property_list")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "memory"})
        self.assertEqual(r, {"ok": False, "error": "read failed"})


# ======================================================================= reads

class Reads(Base):
    def test_list_is_ai_space_only(self):
        r = self.call("qmcp.ListAIManagedQubes")
        names = {q["name"]: q for q in r["qubes"]}
        self.assertEqual(set(names), {"ai-debian-13", "ai-tpl-g", "ai-net-router", "ai-gw-unbadged",
                                      "ai-work", "ai-work2", "ai-on-operator-tpl", "ai-dvm", "ai-dvm-g"})
        self.assertFalse(names["ai-work"]["guarded"])
        self.assertFalse(names["ai-debian-13"]["guarded"])    # a managed template
        self.assertTrue(names["ai-tpl-g"]["guarded"])
        self.assertTrue(names["ai-gw-unbadged"]["guarded"])   # a gateway is guarded, badge or not
        self.assertEqual(names["ai-work"]["template"], "ai-debian-13")
        self.assertEqual(names["ai-on-operator-tpl"]["template"], "<out-of-scope>")
        self.assertNotIn("debian-13", json.dumps(r).replace("ai-debian-13", ""))

    def test_get_property_scope(self):
        self.assertEqual(self.call("qmcp.GetPropertyAIManaged", {"name": "personal", "property": "memory"}),
                         core.NOT_FOUND)
        self.assertEqual(self.call("qmcp.GetPropertyAIManaged", {"name": "no-such", "property": "memory"}),
                         core.NOT_FOUND)
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-tpl-g", "property": "memory"})
        self.assertTrue(r["ok"])                              # guarded qubes are readable
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-net-router", "property": "netvm"})
        self.assertEqual(r["value"], "<out-of-scope>")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "default_dispvm"})
        self.assertEqual(r["value"], "<out-of-scope>")

    def test_tags_read_shows_only_badges(self):
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "tags"})
        self.assertEqual(r["value"], ["ai-managed"])
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-tpl-g", "property": "tags"})
        self.assertEqual(r["value"], ["ai-managed", "qmcp-guarded"])

    def test_only_qubesd_properties_are_read(self):
        for prop in ("app", "qubesd_call", "__class__", "_props", "tags_x", "Memory"):
            r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": prop})
            self.assertFalse(r["ok"], prop)
            self.assertIn("does not exist", r["error"])

    def test_power_state(self):
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "power_state"})
        self.assertEqual(r["value"], "Running")

    def test_pool_stats(self):
        r = self.call("qmcp.GetPoolStats")
        self.assertTrue(r["ok"])
        used = r["ai_managed_bytes_used"]
        # privates of every AI-space qube + roots of the two AI templates
        self.assertEqual(used, 9 * 2 * GiB + 2 * 10 * GiB)
        self.assertEqual(r["ai_managed_bytes_headroom"], 1000 * GiB - used)
        (self.tmp / "pool-cap").unlink()
        self.assertEqual(self.call("qmcp.GetPoolStats")["error"], budget.ERR_CAP_MISSING)


# ======================================================================= writes

class Writes(Base):
    def setp(self, name, prop, value):
        return self.call("qmcp.SetPropertyAIManaged", {"name": name, "property": prop, "value": value})

    def test_operator_only_properties(self):
        # default_dispvm is no longer settable; nor are template/name/provides_network.
        for prop in ("template", "name", "default_dispvm", "provides_network", "autostart",
                     "kernel", "template_for_dispvms", "guivm"):
            self.assertEqual(self.setp("ai-work", prop, "ai-work2")["error"], "property not settable", prop)

    def test_netvm_only_to_null(self):
        self.assertIn("operator-only", self.setp("ai-work", "netvm", "ai-net-router")["error"])
        self.assertEqual(self.setp("ai-work", "netvm", None), {"ok": True})
        self.assertIsNone(self.app.domains["ai-work"].netvm)

    def test_int_means_int(self):
        for bad in (True, 1.5, "512", -1, 0):
            self.assertIn("positive integer", self.setp("ai-work", "memory", bad)["error"], bad)
        self.assertEqual(self.setp("ai-work", "memory", 512), {"ok": True})
        self.assertEqual(self.app.domains["ai-work"].memory, 512)

    def test_label(self):
        self.assertIn("label must be", self.setp("ai-work", "label", "pink")["error"])
        self.assertEqual(self.setp("ai-work", "label", "red"), {"ok": True})

    def test_guarded_and_out_of_scope(self):
        self.assertEqual(self.setp("ai-tpl-g", "memory", 512), core.GUARDED_REFUSAL)
        self.assertEqual(self.setp("ai-gw-unbadged", "memory", 512), core.GUARDED_REFUSAL)
        self.assertEqual(self.setp("personal", "memory", 512), core.NOT_FOUND)
        self.assertEqual(self.setp("no-such-qube", "memory", 512), core.NOT_FOUND)
        # The hub operates the templates it manages.
        self.assertEqual(self.setp("ai-debian-13", "memory", 512), {"ok": True})

    def test_caller_is_never_its_own_object(self):
        # Only on a misconfigured fleet (the hub tagged into AI space).
        self.app.domains["mcp-control"].tags.add("ai-managed")
        self.assertEqual(self.setp("mcp-control", "memory", 512), core.NOT_FOUND)

    def feat(self, key, value="1", name="ai-work"):
        return self.call("qmcp.SetFeatureAIManaged", {"name": name, "feature": key, "value": value})

    def test_feature_allowlist(self):
        # preload-dispvm-max is the case that motivated the allowlist.
        for key in ("preload-dispvm-max", "internal", "guivm", "audiovm", "gui-allow-fullscreen",
                    "qrexec", "service.", "vm-config.", "service.a b", "qmcp-anything",
                    "a-key-qubes-adds-next-year"):
            self.assertEqual(self.feat(key)["error"], "feature not settable", key)
        self.assertEqual(self.feat("service.cups", True), {"ok": True, "feature": "service.cups", "value": "1"})
        self.assertEqual(self.feat("service.cups", False)["value"], "")
        self.assertEqual(self.feat("vm-config.x", 5)["value"], "5")
        self.assertTrue(self.feat("menu-items", "firefox.desktop")["ok"])
        self.assertIn("removal is operator-only", self.feat("service.cups", None)["error"])
        self.assertIn("removal is operator-only", self.feat("service.cups", "x" * 5000)["error"])
        self.assertEqual(self.feat("service.cups", True, name="ai-tpl-g"), core.GUARDED_REFUSAL)

    def life(self, name, action):
        return self.call("qmcp.LifecycleAIManaged", {"name": name, "action": action})

    def test_lifecycle(self):
        self.assertIn("action must be", self.life("ai-work", "destroy")["error"])
        self.assertEqual(self.life("ai-work2", "start"), {"ok": True})
        self.assertEqual(self.life("ai-work2", "pause"), {"ok": True})
        self.assertEqual(self.life("ai-work2", "unpause"), {"ok": True})
        self.assertEqual(self.life("ai-work2", "kill"), {"ok": True})
        self.assertEqual(self.life("ai-tpl-g", "start"), core.GUARDED_REFUSAL)
        self.assertEqual(self.life("personal", "kill"), core.NOT_FOUND)

    def created(self, name="ai-work2"):
        # What every qmcp create stamps: the hub may remove only such a qube.
        self.app.domains[name].tags.add("qmcp-owner_mcp-control")

    def test_remove_is_a_real_remove(self):
        self.assertEqual(self.life("ai-work", "remove")["error"], "action failed")   # running
        self.created()
        self.assertEqual(self.life("ai-work2", "remove"), {"ok": True})
        self.assertNotIn("ai-work2", self.app.domains)

    def qube_lock_files(self, name):
        path = core.qube_lock_path(name)
        return [p for p in (path, core.queue_path(path)) if os.path.exists(p)]

    def seed_qube_locks(self, name):
        os.close(core.acquire_qube_lock(name, 1))
        self.assertEqual(len(self.qube_lock_files(name)), 2)

    def test_the_gates_pass_sweeps_the_lock_files_of_names_that_are_gone(self):
        """A disposable that qubesd removes itself after a kill never passes
        through qmcp's own remove: the gate's pass sweeps its files, leaves a
        file a call holds, and never touches a qube's that exists."""
        import fcntl
        from qmcp import cli
        d = pathlib.Path(core.RUN_DIR) / core.QUBE_LOCK_SUBDIR
        for f in ("disp9.lock", "disp9.queue", "ai-work.lock", "ai-work.queue",
                  "disp10.lock", "disp11.queue", "not a name.lock"):
            (d / f).touch()
        held = os.open(d / "disp10.lock", os.O_RDWR)
        self.addCleanup(os.close, held)
        fcntl.flock(held, fcntl.LOCK_EX)
        self.assertEqual(core.sweep_qube_locks(self.app), 2)       # disp9, disp11
        self.assertEqual(sorted(os.listdir(d)),
                         ["ai-work.lock", "ai-work.queue", "disp10.lock", "not a name.lock"])
        fcntl.flock(held, fcntl.LOCK_UN)
        self.assertEqual(core.sweep_qube_locks(self.app), 1)       # disp10, now free
        self.assertNotIn("disp10.lock", os.listdir(d))
        # A list that cannot be read sweeps nothing.
        (d / "disp12.lock").touch()
        self.app.fail_reads("admin.vm.List", "fail")
        self.assertEqual(core.sweep_qube_locks(self.app), 0)
        self.assertIn("disp12.lock", os.listdir(d))
        # The gate's timer runs `qmcp gate`, which sweeps first.
        self.assertIn("core.sweep_qube_locks(_app())", pathlib.Path(cli.__file__).read_text())
        self.assertIn("ExecStart=/usr/local/bin/qmcp gate",
                      (pathlib.Path(__file__).parent.parent / "deploy" / "qmcp-gate.service").read_text())

    def test_the_sweep_takes_a_gone_qubes_inqube_lock_and_never_a_live_or_held_one(self):
        """A template removed by hand left `inqube-<name>.lock` until boot (the
        box, 2026-10-18). The pass removes it once qubesd no longer lists the
        name, and leaves a live qube's, one a prepare holds, and a FIFO."""
        import fcntl
        run = pathlib.Path(core.RUN_DIR)
        for f in ("inqube-gone-tpl.lock", "inqube-ai-work.lock", "inqube-gone-held.lock",
                  "inqube-not a name.lock", "inqube-gone-tpl.other"):
            (run / f).touch()
        os.mkfifo(run / "inqube-gone-fifo.lock")
        held = os.open(run / "inqube-gone-held.lock", os.O_RDWR)
        self.addCleanup(os.close, held)
        fcntl.flock(held, fcntl.LOCK_EX)
        self.assertEqual(core.sweep_qube_locks(self.app), 1)
        left = sorted(f for f in os.listdir(run) if f.startswith("inqube-"))
        self.assertEqual(left, ["inqube-ai-work.lock", "inqube-gone-fifo.lock",
                                "inqube-gone-held.lock", "inqube-gone-tpl.other",
                                "inqube-not a name.lock"])
        fcntl.flock(held, fcntl.LOCK_UN)
        self.assertEqual(core.sweep_qube_locks(self.app), 1)
        self.assertNotIn("inqube-gone-held.lock", os.listdir(run))
        # A prepare in progress on a name qubesd does not list keeps its lock.
        with inqube._OneWriter("gone-tpl2") as w:
            self.assertEqual(core.sweep_qube_locks(self.app), 0)
            self.assertTrue(os.path.exists(w.path))
        self.assertEqual(core.sweep_qube_locks(self.app), 1)
        self.assertFalse(os.path.exists(w.path))
        # A list that cannot be read, or one without dom0 (not qubesd's list),
        # removes nothing.
        (run / "inqube-gone-tpl3.lock").touch()
        self.app.fail_reads("admin.vm.List", "fail")
        self.assertEqual(core.sweep_qube_locks(self.app), 0)
        with mock.patch.object(self.app, "qubesd_call", return_value=b"ai-work class=AppVM"):
            self.assertEqual(core.sweep_qube_locks(self.app), 0)
        self.assertIn("inqube-gone-tpl3.lock", os.listdir(run))

    def test_the_inqube_lock_is_the_gates_to_open_and_a_writer_retakes_a_removed_file(self):
        """The gate's user opens the lock root made to remove it, so it is
        0640 under any umask; and a writer left holding the lock on a file the
        pass removed after its open (the pass takes the lock, unlinks, lets go,
        and the writer's flock then lands on the removed file) opens the path
        again, never keeping a lock on a lost file. The mock unlinks once the
        lock is had, which leaves the writer in that same state."""
        old = os.umask(0o077)
        try:
            with inqube._OneWriter("ai-tpl-x") as w:
                self.assertEqual(os.stat(w.path).st_mode & 0o777, 0o640)
        finally:
            os.umask(old)
        real, calls = inqube._OneWriter._open, []

        def open_then_swept(self_w):
            fd = real(self_w)
            if not calls:
                os.unlink(self_w.path)          # the pass, after the open
            calls.append(fd)
            return fd
        with mock.patch.object(inqube._OneWriter, "_open", open_then_swept):
            with inqube._OneWriter("ai-tpl-y") as w:
                self.assertEqual(len(calls), 2)
                self.assertEqual(os.fstat(w.fd).st_ino, os.stat(w.path).st_ino)
                # So a second writer finds it held.
                with self.assertRaises(inqube.InQubeError):
                    inqube._OneWriter("ai-tpl-y").__enter__()

    def test_a_writer_tries_a_lock_held_for_a_moment_again_before_calling_it_busy(self):
        """The sweep holds a writer lock for a moment to remove a gone qube's
        file: a prepare that meets that moment tries again, and only a lock
        held through every try is another writer's."""
        import fcntl
        import threading
        path = pathlib.Path(core.RUN_DIR) / "inqube-ai-tpl-z.lock"
        path.touch(mode=0o640)
        fd = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        t = threading.Timer(0.15, fcntl.flock, (fd, fcntl.LOCK_UN))
        t.start()
        self.addCleanup(t.cancel)
        with inqube._OneWriter("ai-tpl-z") as w:          # had on a later try
            self.assertEqual(os.fstat(w.fd).st_ino, os.stat(path).st_ino)
        fcntl.flock(fd, fcntl.LOCK_EX)
        sleeps = []
        with mock.patch.object(inqube.time, "sleep", sleeps.append):
            with self.assertRaises(inqube.InQubeError) as cm:
                inqube._OneWriter("ai-tpl-z").__enter__()
        self.assertIn("another prepare or install", str(cm.exception))
        self.assertEqual(sleeps, [inqube.LOCK_RETRY_S] * (inqube.LOCK_TRIES - 1))

    def test_a_call_slot_is_made_for_the_gate_to_open_whatever_the_umask(self):
        """A `--gate-user` other than the services' user removes a gone
        caller's slots: a slot file is 0660 under the service's umask, and
        never made through a link."""
        old = os.umask(0o077)
        try:
            fd = core.acquire_call_slot("ai-umask-lead", limit=1)
        finally:
            os.umask(old)
        self.addCleanup(os.close, fd)
        path = pathlib.Path(core.RUN_DIR) / "calls" / "ai-umask-lead.0"
        self.assertEqual(path.stat().st_mode & 0o777, 0o660)
        target = self.tmp / "elsewhere"
        target.write_text("")
        os.symlink(target, pathlib.Path(core.RUN_DIR) / "calls" / "ai-link-lead.0")
        with self.assertRaises(core.Refusal) as cm:
            core.acquire_call_slot("ai-link-lead", limit=1)
        self.assertEqual(cm.exception.payload["error"], "qmcp runtime directory unavailable")

    def test_the_sweep_takes_a_gone_callers_call_locks_and_never_a_counter(self):
        """A lead removed by hand, then its project deleted, left
        `calls/<lead>.0` until boot (the box, 2026-10-18). The pass removes a
        gone caller's call slots and acting lock with its turnstile; it never
        removes a counter (`.refused`, the caller's day of the audit budget), a
        live qube's file, the hub's, the leads' pool or a file a call holds,
        and nothing at all while the hub file or qubesd's list does not read."""
        import fcntl
        calls = pathlib.Path(core.RUN_DIR) / "calls"
        self.app.vm("ai-x.0", netvm=None, tags={"ai-managed"})
        counter = '{"day": "2026-10-18", "lines": 19999}\n'
        gone = ["ai-gone-lead.0", "ai-gone-lead.3", "ai-gone-lead.acting",
                "ai-gone-lead.acting.queue", "ai-x.0"]
        kept = ["ai-gone-lead.refused", "ai-work.0", "ai-work.refused", "ai-x.0.0",
                "@leads.0", "ai-held.0", "ai-gone-lead.99", "ghost-hub.0", "ghost-hub.acting"]
        for f in gone + kept:
            (calls / f).write_text(counter if f.endswith(".refused") else "")
        held = os.open(calls / "ai-held.0", os.O_RDWR)
        self.addCleanup(os.close, held)
        fcntl.flock(held, fcntl.LOCK_EX)
        # The hub, as /etc/qmcp/hub names it, even while qubesd does not list it.
        pathlib.Path(core.HUB_PATH).write_text("ghost-hub\n")
        # Unreadable first: no hub file, then no list, then a list without dom0.
        os.unlink(core.HUB_PATH)
        self.assertEqual(core.sweep_qube_locks(self.app), 0)
        pathlib.Path(core.HUB_PATH).write_text("ghost-hub\n")
        self.app.fail_reads("admin.vm.List", "fail")
        self.assertEqual(core.sweep_qube_locks(self.app), 0)
        with mock.patch.object(self.app, "qubesd_call", return_value=b"ai-work class=AppVM"):
            self.assertEqual(core.sweep_qube_locks(self.app), 0)
        self.assertEqual(sorted(os.listdir(calls)), sorted(gone + kept))
        # Readable: ai-gone-lead and ai-x go (two callers), the rest stay.
        self.assertEqual(core.sweep_qube_locks(self.app), 2)
        self.assertEqual(sorted(os.listdir(calls)), sorted(kept))
        self.assertEqual((calls / "ai-gone-lead.refused").read_text(), counter)
        # The held slot goes once it is free; the counter still stays.
        fcntl.flock(held, fcntl.LOCK_UN)
        self.assertEqual(core.sweep_qube_locks(self.app), 1)
        self.assertNotIn("ai-held.0", os.listdir(calls))
        self.assertIn("ai-gone-lead.refused", os.listdir(calls))

    def test_the_sweep_leaves_an_acting_lock_held_shared_or_exclusive(self):
        """A call still holds its caller's acting lock shared, and a drain
        holds it exclusively: either way the pass leaves it, and removes it
        once it is let go."""
        acting = core.acting_lock_path("ai-gone-actor")
        for take in (lambda: core.hold_acting("ai-gone-actor", 1),
                     lambda: core.drain_caller("ai-gone-actor", 1)):
            fd = take()
            self.assertIsNotNone(fd)
            try:
                self.assertEqual(core.sweep_qube_locks(self.app), 0)
                self.assertTrue(os.path.exists(acting))
            finally:
                os.close(fd)
            self.assertEqual(core.sweep_qube_locks(self.app), 1)
            self.assertFalse(os.path.exists(acting))
            self.assertFalse(os.path.exists(core.queue_path(acting)))

    def test_a_removed_qubes_lock_files_go_with_it(self):
        # The lock itself goes under the one the call holds; another qube's stay.
        self.seed_qube_locks("ai-work2")
        self.seed_qube_locks("ai-work")
        self.created()
        self.assertEqual(self.life("ai-work2", "remove"), {"ok": True})
        self.assertEqual(self.qube_lock_files("ai-work2"), [])
        self.assertEqual(len(self.qube_lock_files("ai-work")), 2)

    def test_a_failed_remove_keeps_the_qubes_lock_files(self):
        self.seed_qube_locks("ai-work")
        self.assertEqual(self.life("ai-work", "remove")["error"], "action failed")   # running
        self.assertEqual(len(self.qube_lock_files("ai-work")), 2)

    def test_a_turnstile_in_use_is_left_and_the_remove_still_succeeds(self):
        self.seed_qube_locks("ai-work2")
        queue = core.queue_path(core.qube_lock_path("ai-work2"))
        fd = os.open(queue, os.O_RDWR)
        self.addCleanup(os.close, fd)
        r = {}
        # Held by "another process" only once the call is past it.
        real = core.retire_qube_locks

        def retire(name, held=()):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r["left"] = real(name, held)
            return r["left"]
        self.created()
        with mock.patch.object(core, "retire_qube_locks", retire):
            self.assertEqual(self.life("ai-work2", "remove"), {"ok": True})
        self.assertEqual(self.qube_lock_files("ai-work2"), [queue])
        self.assertEqual([p for p, _ in r["left"]], [queue])

    def test_a_rolled_back_create_and_a_disposable_remove_their_lock_files(self):
        for remove in (services._remove, services._dispose):
            with self.subTest(remove.__name__):
                self.app.vm("ai-hub-gone", template=self.app.domains["ai-debian-13"],
                            netvm=None, tags={"ai-managed"})
                self.seed_qube_locks("ai-hub-gone")
                self.assertTrue(remove(self.app, "ai-hub-gone"))
                self.assertEqual(self.qube_lock_files("ai-hub-gone"), [])


# ======================================================================= creates

class Creates(Base):
    def spawn(self, **req):
        req.setdefault("name", "ai-hub-new")
        req.setdefault("template", "ai-debian-13")
        return self.call("qmcp.SpawnAIManagedQube", req)

    def test_name_outside_namespace_is_refused_before_any_lookup(self):
        # No host lookup at all, so the refusal cannot depend on what exists.
        for svc, req in (("qmcp.SpawnAIManagedQube", {"name": "personal", "template": "ai-debian-13"}),
                         ("qmcp.CloneAIManagedQube", {"name": "vault", "source": "ai-work"})):
            self.app.domains.lookups = 0
            r = self.call(svc, req)
            self.assertIn("reserved for AI-created qubes", r["error"])
            self.assertEqual(self.app.domains.lookups, 0, svc)

    def test_spawn_birth(self):
        self.egress("ai-net-router")
        r = self.spawn()
        self.assertEqual(r, {"ok": True, "name": "ai-hub-new"})
        vm = self.app.domains["ai-hub-new"]
        # The hub's AppVMs join p00, its own slot.
        self.assertEqual(self.tags("ai-hub-new"), {"ai-managed", "qmcp-owner_mcp-control", "qmcp-proj-p00"})
        self.assertEqual(vm.netvm.name, "ai-net-router")
        self.assertIsNone(vm.default_dispvm)     # the add_new_vm default was default-dvm
        # Pinned, not following a default: a qube left on the global default
        # would move when the operator changes it.
        self.assertFalse(vm.property_is_default("netvm"))
        self.assertFalse(vm.property_is_default("default_dispvm"))
        self.assertTrue(self.audit_lines()[-1]["ok"])

    def test_birth_egress_chain(self):
        # Row 4: nothing resolves -> refused, nothing created.
        r = self.spawn()
        self.assertEqual(r["error"], "birth egress could not be resolved")
        self.assertNotIn("ai-hub-new", self.app.domains)
        # Row 2: the hub's own netvm, when it is in AI space.
        self.app.domains["mcp-control"]._props["netvm"] = self.app.domains["ai-net-router"]
        self.assertTrue(self.spawn()["ok"])
        self.assertEqual(self.app.domains["ai-hub-new"].netvm.name, "ai-net-router")

    def test_explicit_netvm(self):
        self.egress("ai-net-router")
        self.assertEqual(self.spawn(name="ai-hub-n1", netvm=None)["ok"], True)
        self.assertIsNone(self.app.domains["ai-hub-n1"].netvm)
        self.assertTrue(self.spawn(name="ai-hub-n2", netvm="ai-net-router")["ok"])
        # A gateway that is not enrolled is refused, inside AI space or not,
        # judged from the registry alone, before any lookup.
        lookups = self.app.domains.lookups
        self.assertEqual(self.spawn(name="ai-hub-n3", netvm="ai-gw-unbadged")["error"],
                         "netvm must be an enrolled gateway")
        r = self.spawn(name="ai-hub-n4", netvm="sys-firewall")
        self.assertEqual(r["error"], "netvm must be an enrolled gateway")
        # An enrolled one must still be the answer the birth chain gives (here
        # the configured birth egress: the hub's own network is not enrolled).
        self.enroll("ai-gw-unbadged")
        self.assertEqual(self.spawn(name="ai-hub-n5", netvm="ai-gw-unbadged")["error"],
                         "netvm must match the inherited birth egress")
        self.assertNotIn("ai-hub-n3", self.app.domains)
        # Once the hub's own network is enrolled, it is the chain's answer.
        self.enroll("sys-firewall")
        self.assertTrue(self.spawn(name="ai-hub-n6", netvm="sys-firewall")["ok"])
        self.assertEqual(self.spawn(name="ai-hub-n7", netvm="ai-net-router")["error"],
                         "netvm must match the inherited birth egress")
        self.assertGreater(self.app.domains.lookups, lookups)    # the spawns themselves look up

    def test_template_references(self):
        self.egress("ai-net-router")
        r = self.spawn(template="debian-13")
        self.assertEqual(r["error"], "template must reference an ai-managed qube")
        self.assertTrue(self.spawn(name="ai-hub-from-guarded", template="ai-tpl-g")["ok"])
        self.assertNotIn("qmcp-guarded", self.tags("ai-hub-from-guarded"))
        self.assertIn("must be a TemplateVM", self.spawn(name="ai-hub-x", template="ai-work")["error"])

    def test_dispvm_template_and_dispvm(self):
        self.egress("ai-net-router")
        r = self.spawn(name="ai-hub-mydvm", klass="DispVMTemplate")
        self.assertTrue(r["ok"], r)
        vm = self.app.domains["ai-hub-mydvm"]
        self.assertEqual((vm.klass, vm.template_for_dispvms), ("AppVM", True))
        self.assertEqual(self.tags("ai-hub-mydvm"), {"ai-managed", "qmcp-owner_mcp-control"})
        # A named disposable off a guarded DVMT: the DVMT answers for its network (offline).
        r = self.spawn(name="ai-hub-d1", klass="DispVM", template="ai-dvm-g")
        self.assertTrue(r["ok"], r)
        self.assertIsNone(self.app.domains["ai-hub-d1"].netvm)
        self.assertIn("disposable template", self.spawn(name="ai-hub-d2", klass="DispVM",
                                                         template="ai-debian-13")["error"])

    def test_restrictions_are_inherited(self):
        # Whonix's marker is carried to a child; v0.9.16's egress lock is no
        # longer read by anything (no network moves), so a create strips it.
        self.egress("ai-net-router")
        tpl = self.app.domains["ai-debian-13"]
        tpl.tags.add("anon-vm")
        tpl.tags.add("qmcp-egress-locked_ai-net-router")
        self.assertTrue(self.spawn()["ok"])
        self.assertEqual(self.tags("ai-hub-new"), {"ai-managed", "qmcp-owner_mcp-control", "anon-vm",
                                                   "qmcp-proj-p00"})

    def test_a_restriction_added_while_the_call_waits_reaches_the_child(self):
        # The template's tags are read under the create lock, right before
        # the create: an `anon-vm` put on while the call waited is carried.
        self.egress("ai-net-router")
        tpl = self.app.domains["ai-debian-13"]
        real = budget.acquire_create_lock

        def slow_lock(*a, **kw):
            tpl.tags.add("anon-vm")
            return real(*a, **kw)
        with mock.patch.object(budget, "acquire_create_lock", slow_lock):
            self.assertTrue(self.spawn()["ok"])
        self.assertIn("anon-vm", self.tags("ai-hub-new"))

    def test_private_size(self):
        self.egress("ai-net-router")
        for bad in (True, 1.5, "1", 0, -5):
            self.assertIn("private_size", self.spawn(private_size=bad)["error"], bad)
        self.assertEqual(self.spawn(private_size=21 * GiB)["error"], budget.ERR_PRIVATE_TOO_LARGE)
        self.assertTrue(self.spawn(private_size=8 * GiB)["ok"])
        self.assertEqual(self.app.domains["ai-hub-new"].volumes["private"].size, 8 * GiB)
        self.app.fail.add("resize")
        r = self.spawn(name="ai-hub-big", private_size=8 * GiB)
        self.assertEqual(r, {"ok": True, "name": "ai-hub-big", "warning": "private_resize_failed"})

    def test_pool_cap(self):
        self.egress("ai-net-router")
        (self.tmp / "pool-cap").write_text(str(10 * GiB))
        self.assertEqual(self.spawn()["error"], budget.ERR_CAP_EXCEEDED)
        self.assertNotIn("ai-hub-new", self.app.domains)

    def test_collision_inside_namespace(self):
        self.egress("ai-net-router")
        self.app.vm("ai-hub-taken", tags={"ai-managed"})
        self.assertEqual(self.spawn(name="ai-hub-taken")["error"], "qube 'ai-hub-taken' already exists")

    def test_the_hub_names_only_inside_its_own_space(self):
        # A name says who owns a qube: the hub's are ai-hub-..., judged on
        # the name alone, before anything is looked up.
        self.egress("ai-net-router")
        lookups = self.app.domains.lookups
        for name in ("ai-work", "ai-new", "ai-hubx-new", "ai-hub-"):
            r = self.spawn(name=name)
            self.assertFalse(r["ok"], name)
            self.assertIn("ai-hub-", r["error"], name)
        self.assertEqual(self.app.domains.lookups, lookups)

    def test_a_failed_create_that_made_a_qube_is_logged_past_the_cap(self):
        # It made something in dom0, rolled back or not: never withheld.
        self.egress("ai-net-router")
        with mock.patch.object(audit, "REFUSALS_PER_HOUR", 0):
            self.app.fail.add("tag.add")
            self.assertEqual(self.spawn()["error"], "birth stamp failed (rolled back)")
            self.app.fail.add("remove")
            self.assertIn("rollback failed", self.spawn(name="ai-hub-stuck")["error"])
            self.app.fail.clear()
            self.app.fail.add("tag.add")
            r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
            self.assertEqual(r["error"], "birth stamp failed (rolled back)")
        lines = self.audit_lines()
        self.assertEqual([(l["service"], l["ok"]) for l in lines],
                         [("qmcp.SpawnAIManagedQube", False)] * 2
                         + [("qmcp.SpawnDisposableAIManaged", False)])

    def test_rollback_is_reported_truthfully(self):
        # "rolled back" only when the qube is really gone.
        self.egress("ai-net-router")
        self.app.fail.add("tag.add")
        r = self.spawn()
        self.assertEqual(r["error"], "birth stamp failed (rolled back)")
        self.assertNotIn("ai-hub-new", self.app.domains)
        self.app.fail.add("remove")
        r = self.spawn(name="ai-hub-stuck")
        self.assertEqual(r["error"], "birth stamp failed and rollback failed: "
                                     "qube 'ai-hub-stuck' needs manual cleanup in dom0")
        self.assertIn("ai-hub-stuck", self.app.domains)
        self.app.fail.clear()
        self.app.fail.add("set.netvm")
        self.assertEqual(self.spawn(name="ai-hub-n")["error"], "netvm assignment failed (rolled back)")

    def test_no_exception_text_reaches_the_caller(self):
        # Inject a failure carrying SECRET into every step there is.
        self.egress("ai-net-router")
        steps = ["add_new_vm", "clone_vm", "tag.add", "set.netvm", "set.default_dispvm",
                 "set.template_for_dispvms", "resize", "remove", "feature.set", "set.memory",
                 "start", "kill", "admin.vm.CreateDisposable", "admin.vm.tag.Set",
                 "admin.vm.property.Set", "property_list"]
        replies = []
        for step in steps:
            self.app.fail = {step}
            replies += [
                self.spawn(name="ai-hub-s1", private_size=4 * GiB, klass="DispVMTemplate"),
                self.call("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-hub-c1"}),
                self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"}),
                self.call("qmcp.SetFeatureAIManaged", {"name": "ai-work2", "feature": "service.x", "value": 1}),
                self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory", "value": 9}),
                self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"}),
                self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work2", "property": "memory"}),
            ]
            self.app = standard_fleet()
        self.assertTrue(replies)
        for r in replies:
            self.assertNotIn(SECRET, json.dumps(r))
            self.assertNotIn("Injected", json.dumps(r))

    # -------------------------------------------------------------- clone

    def test_fake_clone_copies_tags(self):
        # Teeth: the platform behaviour the strip exists for must be reproduced.
        src = self.app.domains["ai-work"]
        copy = self.app.clone_vm(src, "ai-raw")
        self.assertIn("qmcp-owner_mcp-control", copy.tags)
        self.assertIn("operator-note", copy.tags)

    def clone(self, source="ai-work", name="ai-hub-clone"):
        return self.call("qmcp.CloneAIManagedQube", {"source": source, "name": name})

    def test_clone_strips_and_restamps(self):
        src = self.app.domains["ai-work"]
        for t in ("ai-full", "qmcp-owner_someone-else", "qmcp-guarded-not-really",
                  "qmcp-egress-locked_ai-net-router"):
            src.tags.add(t)
        src.tags.discard("qmcp-owner_mcp-control")
        r = self.clone()
        self.assertEqual(r, {"ok": True, "name": "ai-hub-clone"})
        # ai-work is in no slot, so its clone joins none (a clone lands where
        # its source is); the operator's own tag is copied.
        self.assertEqual(self.tags("ai-hub-clone"), {"ai-managed", "qmcp-owner_mcp-control",
                                                     "operator-note"})
        vm = self.app.domains["ai-hub-clone"]
        self.assertEqual(vm.netvm.name, "ai-net-router")   # the source answers for itself
        self.assertIsNone(vm.default_dispvm)

    def test_clone_needs_a_managed_source(self):
        self.assertEqual(self.clone(source="ai-tpl-g"), core.GUARDED_REFUSAL)
        self.assertEqual(self.clone(source="ai-dvm-g"), core.GUARDED_REFUSAL)
        self.assertEqual(self.clone(source="personal"), core.NOT_FOUND)
        self.assertEqual(self.clone(source="ai-gw-unbadged"), core.GUARDED_REFUSAL)

    def test_clone_a_managed_template(self):
        # The hub builds templates; a cloned template stays off the network.
        r = self.clone(source="ai-debian-13", name="ai-hub-tpl-dev")
        self.assertTrue(r["ok"], r)
        vm = self.app.domains["ai-hub-tpl-dev"]
        self.assertEqual(vm.klass, "TemplateVM")
        self.assertIsNone(vm.netvm)
        self.assertEqual(core.state(vm), "managed")

    def test_clone_from_a_source_on_an_outside_network(self):
        self.app.domains["ai-work2"]._props["netvm"] = self.app.domains["sys-firewall"]
        self.assertEqual(self.clone(source="ai-work2")["error"], "birth egress could not be resolved")

    # -------------------------------------------------------------- disposables

    def test_fake_disposable_inherits_template_tags(self):
        name = self.app.qubesd_call("ai-dvm-g", "admin.vm.CreateDisposable").decode()
        self.assertIn("qmcp-guarded", self.app.domains._hidden[name].tags)

    def test_spawn_disposable(self):
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-g"})
        self.assertTrue(r["ok"], r)
        name = r["name"]
        self.assertEqual(self.tags(name), {"ai-managed", "qmcp-owner_mcp-control"})
        vm = self.app.domains[name]
        self.assertIsNone(vm.netvm)
        self.assertIsNone(vm.default_dispvm)
        self.assertEqual(core.state(vm), "managed")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.app.domains.clear_cache()
        self.assertEqual(self.app.domains[r["name"]].netvm.name, "ai-net-router")

    def test_spawn_disposable_refusals(self):
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "default-dvm"})
        self.assertEqual(r["error"], "template must reference an ai-managed qube")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-work"})
        self.assertIn("must be a disposable template", r["error"])

    def test_disposable_rollback(self):
        self.app.fail.add("tag.add")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertEqual(r["error"], "birth stamp failed (rolled back)")
        self.assertEqual(self.app.domains._hidden, {})
        self.app.fail.add("admin.vm.Remove")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertIn("rollback failed", r["error"])


# ======================================================================= events

class FakeDispatcher:
    def __init__(self, app, script):
        self.app, self.script, self.handlers = app, script, []

    def add_handler(self, event, handler):
        self.handlers.append(handler)

    async def listen_for_events(self, reconnect=False):
        for subject, event, kwargs in self.script:
            if callable(subject):
                subject()
                continue
            subj = self.app.domains._vms.get(subject, subject)
            for h in self.handlers:
                h(subj, event, **kwargs)


class Standalones(Base):
    """A StandaloneVM made from a template (0.9.27), and every copy dom0 makes:
    built in dom0's own order, so nothing of ours is on it before its stamp."""

    def setUp(self):
        super().setUp()
        self.egress("ai-net-router")
        tpl = self.app.domains["ai-tpl-g"]
        tpl.volumes["root"].size = 20 * GiB
        tpl.__dict__["_rpc"] = {"qmcp.RunInAIManaged": b"v1"}
        tpl.__dict__["_devices"] = ["pci:00_1f.3"]
        tpl._props["memory"] = 800
        for key, value in (("qrexec", "1"), ("qmcp-services", "sha256:v1"),
                           ("preload-dispvm", "x")):
            dict.__setitem__(tpl.features, key, value)
        tpl.tags.add("updates-group")              # the operator's own tag on the template
        self.tpl = tpl

    def spawn(self, **req):
        req.setdefault("name", "ai-hub-sa")
        req.setdefault("template", "ai-tpl-g")
        req.setdefault("klass", "StandaloneVM")
        return self.call("qmcp.SpawnAIManagedQube", req)

    def test_the_hub_spawns_a_standalone(self):
        r = self.spawn(label="blue")
        self.assertEqual(r, {"ok": True, "name": "ai-hub-sa"})
        vm = self.app.domains["ai-hub-sa"]
        self.assertEqual(vm.klass, "StandaloneVM")
        # The hub's standalones join p00, as its AppVMs do; nothing of the
        # template's but what Qubes keeps itself: not guarded, and without the
        # operator's tag.
        self.assertEqual(self.tags("ai-hub-sa"), {"ai-managed", "qmcp-owner_mcp-control",
                                                  "qmcp-proj-p00"})
        self.assertEqual(vm.label.name, "blue")
        self.assertEqual(vm.volumes["root"].size, 20 * GiB)
        self.assertEqual(vm.volumes["private"].size, 2 * GiB)
        self.assertEqual(vm.rpc_files(), {"qmcp.RunInAIManaged": b"v1"})
        self.assertEqual(vm.__dict__["_devices"], [])
        self.assertEqual(vm.memory, 800)            # what an AppVM follows from its template
        features = dict(dict.items(vm.features))
        self.assertEqual(features["qrexec"], "1")
        self.assertEqual(features["qmcp-services"], "sha256:v1")    # the template was halted
        self.assertEqual(features["qmcp-id"], vm.uuid)
        self.assertNotIn("preload-dispvm", features)
        self.assertEqual(vm.netvm.name, "ai-net-router")
        self.assertIsNone(vm.default_dispvm)
        self.assertEqual(core.state(vm), "managed")

    def test_it_takes_only_what_an_appvm_follows_from_its_template(self):
        # memory is one an AppVM follows; autostart is the template's own.
        self.tpl._props["autostart"] = True
        self.assertTrue(self.spawn()["ok"])
        vm = self.app.domains["ai-hub-sa"]
        self.assertEqual(vm.memory, 800)
        self.assertFalse(vm.autostart)

    def test_the_platform_copies_the_template_s_tags_first(self):
        # Teeth: qubesadmin's own standalone (`qvm-create --standalone`) puts
        # the template's ai-managed and its guard on the new qube before anything
        # else, and the operator's tags with them.
        self.app.clone_vm(self.tpl, "ai-raw", new_cls="StandaloneVM",
                          ignore_volumes=("private",))
        first = next(tags for name, tags in self.app.tag_log if name == "ai-raw")
        self.assertEqual(first, {"ai-managed"})
        self.assertIn("updates-group", self.app.domains["ai-raw"].tags)
        self.assertEqual(self.app.domains["ai-raw"].__dict__["_devices"], ["pci:00_1f.3"])

    def test_nothing_of_ours_is_on_it_before_its_stamp(self):
        # Every tag it ever wore is one it ends with: the template's guard and
        # the operator's tag never touch it, and nothing comes off later.
        pathlib.Path(core.MODE_PATH).write_text("anonymous\n")
        self.app.tag_log.clear()
        self.assertTrue(self.spawn(netvm=None)["ok"], self.app.tag_log)
        final = self.tags("ai-hub-sa")
        self.assertIn("qmcp-anon", final)
        mine = [tags for name, tags in self.app.tag_log if name == "ai-hub-sa"]
        self.assertTrue(mine)
        self.assertTrue(all(t <= final for t in mine), mine)
        # In anonymous mode `qmcp-anon` is on before it is in AI space.
        self.assertTrue(all("qmcp-anon" in t for t in mine if "ai-managed" in t), mine)

    def test_a_running_template_s_copy_is_marked_behind(self):
        # The copy gets the root the template had when it started; the refresh
        # may have written newer services into it since, and labelled it.
        self.tpl.start()
        self.tpl.__dict__["_rpc"]["qmcp.RunInAIManaged"] = b"v2"
        dict.__setitem__(self.tpl.features, "qmcp-services", "sha256:v2")
        self.assertTrue(self.spawn()["ok"])
        vm = self.app.domains["ai-hub-sa"]
        self.assertEqual(vm.rpc_files(), {"qmcp.RunInAIManaged": b"v1"})
        self.assertEqual(dict.__getitem__(vm.features, "qmcp-services"), inqube.UNKNOWN)

    def test_a_template_that_ran_before_the_copy_and_stopped_during_it(self):
        # Read before the copy as well as after: halted only at the second
        # read, the root copied may be the older one.
        copied = []
        real_halted, real_fill = inqube.halted, birth.fill_copy
        inqube.halted = lambda vm: bool(copied)        # running until the copy, then halted

        def fill(*a, **kw):
            real_fill(*a, **kw)
            copied.append(True)
        birth.fill_copy = fill
        try:
            self.assertTrue(self.spawn()["ok"])
        finally:
            inqube.halted, birth.fill_copy = real_halted, real_fill
        self.assertEqual(dict.__getitem__(self.app.domains["ai-hub-sa"].features,
                                          "qmcp-services"), inqube.UNKNOWN)

    def test_the_root_counts_against_the_cap(self):
        used = budget.persistent_sum(self.app)
        pathlib.Path(budget.CAP_PATH).write_text(str(used + 21 * GiB) + "\n")
        self.assertEqual(self.spawn()["error"], "pool cap exceeded")
        self.assertNotIn("ai-hub-sa", self.app.domains)
        self.assertTrue(self.spawn(klass="AppVM", template="ai-tpl-g")["ok"])

    def test_a_standalone_comes_from_a_template_only(self):
        r = self.spawn(template="ai-dvm")
        self.assertEqual(r["error"], "template 'ai-dvm' must be a TemplateVM for klass=StandaloneVM")

    def test_a_failed_copy_is_rolled_back(self):
        for step, key in (("copy", "volume.clone"), ("copy", "feature.set"),
                          ("services label", "feature.get"), ("birth stamp", "tag.add")):
            self.app.fail = {key}
            if key == "feature.get":
                self.tpl.start()                    # only a running template's copy reads it
                self.app.fail = set()
                self.app.fail_reads("feature.get", "ok ok fail")
            r = self.spawn(name=f"ai-hub-{key.replace('.', '-')}")
            self.assertIn("(rolled back)", r["error"], key)
            self.assertNotIn(f"ai-hub-{key.replace('.', '-')}", self.app.domains, key)
            self.assertNotIn(SECRET, json.dumps(r))
            self.app.fail = set()
            self.app.fail_plan.clear()
            self.tpl.shutdown()

    def clone(self, source, name):
        return self.call("qmcp.CloneAIManagedQube", {"source": source, "name": name})

    def test_a_clone_of_a_standalone_copies_its_root_and_private(self):
        self.assertTrue(self.spawn()["ok"])
        sa = self.app.domains["ai-hub-sa"]
        sa.volumes["private"].size = 5 * GiB
        firewall.restore_rules(self.app, "ai-hub-sa", ["action=accept dsthost=example.org",
                                                       "action=drop"])
        r = self.clone("ai-hub-sa", "ai-hub-sa2")
        self.assertEqual(r, {"ok": True, "name": "ai-hub-sa2"})
        vm = self.app.domains["ai-hub-sa2"]
        self.assertEqual(vm.klass, "StandaloneVM")
        self.assertEqual(vm.volumes["root"].size, 20 * GiB)
        self.assertEqual(vm.volumes["private"].size, 5 * GiB)
        self.assertEqual(vm.rpc_files(), {"qmcp.RunInAIManaged": b"v1"})
        self.assertEqual(firewall.read_rules(self.app, "ai-hub-sa2"),
                         firewall.read_rules(self.app, "ai-hub-sa"))
        self.assertEqual(dict.__getitem__(vm.features, "qmcp-id"), vm.uuid)
        self.assertEqual(self.tags("ai-hub-sa2"), self.tags("ai-hub-sa"))    # p00, as its source

    def test_a_running_standalone_s_clone_is_marked_behind(self):
        self.assertTrue(self.spawn()["ok"])
        self.app.domains["ai-hub-sa"].start()
        self.assertTrue(self.clone("ai-hub-sa", "ai-hub-sa2")["ok"])
        self.assertEqual(dict.__getitem__(self.app.domains["ai-hub-sa2"].features,
                                          "qmcp-services"), inqube.UNKNOWN)

    def test_a_copy_keeps_its_source_s_pools_notes_and_virt_mode(self):
        self.tpl.volumes["root"].pool = "big-pool"
        self.tpl._props["virt_mode"] = "hvm"
        self.assertTrue(self.spawn()["ok"])
        sa = self.app.domains["ai-hub-sa"]
        self.assertEqual(sa.volumes["root"].pool, "big-pool")
        self.assertEqual(sa.volumes["private"].pool, "vm-pool")        # new, the default
        self.assertEqual(sa.virt_mode, "hvm")
        work = self.app.domains["ai-work"]
        work.volumes["private"].pool = "big-pool"
        work.set_notes("the operator's note")
        self.assertTrue(self.clone("ai-work", "ai-hub-w")["ok"])
        w = self.app.domains["ai-hub-w"]
        self.assertEqual((w.volumes["private"].pool, w.get_notes()),
                         ("big-pool", "the operator's note"))

    def test_a_disposable_s_clone_copies_no_volume(self):
        # A disposable keeps nothing across a restart, so its clone takes no
        # volume, as qubesadmin's clone_vm did.
        name = self.app.qubesd_call("ai-dvm", "admin.vm.CreateDisposable").decode()
        self.app.domains.clear_cache()
        self.assertEqual(birth.copied_volumes(self.app.domains[name], False), ())
        self.assertEqual(birth.copied_volumes(self.app.domains["ai-work"], False), ("private",))
        self.assertEqual(birth.copied_volumes(self.tpl, False), ("root", "private"))

    def test_a_clone_takes_no_device(self):
        self.app.domains["ai-work"].__dict__["_devices"] = ["usb:2-1"]
        self.assertTrue(self.clone("ai-work", "ai-hub-w")["ok"])
        self.assertEqual(self.app.domains["ai-hub-w"].__dict__["_devices"], [])


class Events(Base):
    def run_events(self, script, **req):
        saved = services._dispatcher
        services._dispatcher = lambda app: FakeDispatcher(app, script)
        try:
            req.setdefault("duration", 1)
            return self.call("qmcp.AIManagedEvents", req)
        finally:
            services._dispatcher = saved

    def test_input_bounds(self):
        self.assertIn("duration", self.run_events([], duration=True)["error"])
        r = self.run_events([], events=["e"] * (services.EVENTS_MAX_FILTERS + 1))
        self.assertIn("at most", r["error"])
        r = self.run_events([], events=["x" * (services.EVENTS_MAX_FILTER_LEN + 1)])
        self.assertIn("at most", r["error"])
        self.assertEqual(self.run_events([], qube="personal"), core.NOT_FOUND)

    def test_a_hub_stopped_or_held_during_the_window_gets_nothing(self):
        script = [("ai-work", "domain-start", {})]
        self.assertEqual(len(self.run_events(script)["events"]), 1)       # the positive
        for badge in (projects.BLOCKED, core.QUARANTINE):
            with self.subTest(badge):
                hold = lambda b=badge: self.app.domains[HUB].tags.add(b)  # noqa: E731
                r = self.run_events(script + [(hold, None, None)])
                self.assertEqual(r, core.NOT_AUTHORIZED)
                self.app.domains[HUB].tags.discard(badge)

    def test_scope_and_tag_redaction(self):
        def delete_ai_work2():
            self.app.domains._drop("ai-work2")
        script = [
            ("ai-work", "domain-start", {}),
            ("personal", "domain-start", {}),
            ("ai-work", "domain-tag-add:operator-secret", {}),
            ("ai-work", "domain-tag-add:qmcp-guarded", {}),
            ("ai-work", "domain-tag-add:ai-full", {}),
            (delete_ai_work2, None, None),
            ("ai-work2", "domain-shutdown", {}),
            ("ai-work2", "domain-tag-delete:ai-managed", {}),
        ]
        r = self.run_events(script)
        got = [(e["event"], e["subject"], e.get("tag")) for e in r["events"]]
        self.assertEqual(got, [("domain-start", "ai-work", None),
                               ("domain-tag-add", "ai-work", "qmcp-guarded"),
                               ("domain-shutdown", "ai-work2", None),
                               ("domain-tag-delete", "ai-work2", "ai-managed")])
        self.assertNotIn("operator-secret", json.dumps(r))
        self.assertNotIn("ai-full", json.dumps(r))

    def test_filters(self):
        script = [("ai-work", "property-set:netvm", {}), ("ai-work", "domain-start", {}),
                  ("ai-work2", "domain-start", {})]
        r = self.run_events(script, events=["property-set"])
        self.assertEqual([e["event"] for e in r["events"]], ["property-set:netvm"])
        r = self.run_events(script, qube="ai-work2")
        self.assertEqual([e["subject"] for e in r["events"]], ["ai-work2"])


# ======================================================================= fleet

class Fleet(Base):
    def test_check_reports_a_fresh_v0916_fleet(self):
        self.app.domains["ai-work"].tags.add("ai-full")
        self.app.domains["ai-sink"].tags.add("ai-managed")
        findings = {f.check: f for f in fleet.check(self.app, policy_dir=str(self.tmp / "pol"),
                                                    lib_dir=str(self.tmp / "lib"),
                                                    rpc_dir=str(self.tmp / "rpc"), legacy_paths=(),
                                                    system_info={"domains": {}})}
        self.assertEqual(findings["hub"].status, "pass")
        self.assertEqual(findings["tier tags"].status, "fail")
        self.assertEqual(findings["gateways guarded"].status, "fail")
        self.assertIn("ai-gw-unbadged", findings["gateways guarded"].detail)
        self.assertEqual(findings["drop boxes"].status, "fail")
        self.assertEqual(findings["name namespace"].status, "warn")
        self.assertIn("ai-operator-squat", findings["name namespace"].detail)
        self.assertEqual(findings["default_dispvm"].status, "warn")
        self.assertEqual(findings["services"].status, "fail")
        self.assertEqual(fleet.overall(list(findings.values())), "FAILED")

    def test_overall_has_three_answers(self):
        F = fleet.Finding
        self.assertEqual(fleet.overall([]), "INCOMPLETE")
        self.assertEqual(fleet.overall([F("pass", "a"), F("warn", "b")]), "GREEN")
        self.assertEqual(fleet.overall([F("pass", "a"), F("error", "b")]), "INCOMPLETE")
        self.assertEqual(fleet.overall([F("fail", "a"), F("error", "b")]), "FAILED")

    def test_hub_in_ai_space_fails_the_check(self):
        self.app.domains["mcp-control"].tags.add("ai-managed")
        f = {x.check: x for x in fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["hub"].status, "fail")

    def tiered_fleet(self):
        a = self.app
        a.domains["ai-work"].tags.add("ai-full")
        a.domains["ai-work2"].tags.add("ai-exec")
        a.domains["ai-dvm"].tags.add("ai-net")
        a.domains["ai-net-router"].tags.discard("qmcp-guarded")
        a.domains["ai-net-router"].tags.add("ai-full")
        return a

    def test_migration_plan_on_a_flipped_fleet(self):
        app = self.tiered_fleet()
        steps, problems = fleet.plan_migration(app, {}, tier_default="ro")
        self.assertEqual(sorted(p.split(":")[0] for p in problems), ["ai-dvm", "ai-work2"])
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed"}, exec_default="guarded",
                                               tier_default="ro")
        self.assertEqual(problems, [])
        plan = {s.qube: s for s in steps}
        self.assertEqual(plan["ai-work"].remove, {"ai-full"})
        self.assertTrue(plan["ai-work"].pin_dispvm)
        self.assertEqual(plan["ai-work2"].remove, {"ai-exec"})
        self.assertEqual(plan["ai-dvm"].add, {"qmcp-guarded"})
        self.assertEqual(plan["ai-net-router"].add, {"qmcp-guarded"})   # a gateway, whatever it was
        self.assertEqual(plan["ai-on-operator-tpl"].add, {"qmcp-guarded"})  # the read floor
        results = fleet.apply_migration(app, steps)
        self.assertTrue(all(r.startswith("done") for r in results), results)
        self.assertFalse(any(core.tags_of(vm) & birth.LEGACY_TIER_TAGS for vm in app.domains))
        self.assertIsNone(app.domains["ai-work"].default_dispvm)

    def test_migration_is_idempotent(self):
        # Without retiring tier-default, a second run would read every managed
        # (umbrella-only) qube as the old read floor and guard it.
        app = self.tiered_fleet()
        (self.tmp / "tier-default").write_text("ro\n")
        steps, problems = fleet.plan_migration(app, {}, exec_default="managed")
        self.assertEqual(problems, [])
        fleet.apply_migration(app, steps)
        self.assertEqual(fleet.finish_migration(), [str(self.tmp / "tier-default")])
        managed_before = {vm.name for vm in app.domains if core.state(vm) == "managed"}
        steps, problems = fleet.plan_migration(app, {})
        self.assertEqual((problems, [s for s in steps if s.add or s.remove]), ([], []))
        self.assertIn("ai-work", managed_before)
        self.assertEqual(managed_before, {vm.name for vm in app.domains if core.state(vm) == "managed"})

    def test_migration_on_a_never_flipped_fleet_asks(self):
        app = self.tiered_fleet()
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed", "ai-dvm": "managed"},
                                               tier_default=None)
        self.assertIn("ai-on-operator-tpl", " ".join(problems))
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed", "ai-dvm": "managed"},
                                               compat_default="managed", tier_default=None)
        self.assertEqual(problems, [])

    def test_migration_keeps_the_v0916_guarded_list(self):
        # v0.9.16 always refused the qubes named in /etc/qmcp/guarded. Dropping
        # the list on upgrade would make an ai-full qube on it managed.
        app = self.tiered_fleet()
        (self.tmp / "guarded").write_text("# wallets\nai-work\nno-such-qube  # gone\n")
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed", "ai-dvm": "managed"},
                                               tier_default="ro")
        self.assertEqual(problems, [])
        plan = {s.qube: s for s in steps}
        self.assertEqual((plan["ai-work"].add, plan["ai-work"].remove), ({"qmcp-guarded"}, {"ai-full"}))
        steps, _ = fleet.plan_migration(app, {"ai-work": "managed", "ai-work2": "managed",
                                              "ai-dvm": "managed"}, tier_default="ro")
        self.assertEqual({s.qube: s for s in steps}["ai-work"].add, set())   # an explicit choice wins
        self.assertIn("/etc/qmcp/guarded", fleet.LEGACY_PATHS)   # check and install treat it as a leftover
        fleet.apply_migration(app, [s for s in steps if s.qube != "ai-work"])
        self.assertIn(str(self.tmp / "guarded"), fleet.finish_migration())
        self.assertFalse((self.tmp / "guarded").exists())

    @unittest.skipIf(os.geteuid() == 0, "root reads a file whatever its mode")
    def test_an_unreadable_guarded_list_blocks_the_migration(self):
        (self.tmp / "guarded").write_text("ai-work\n")
        os.chmod(self.tmp / "guarded", 0o000)
        try:
            _, problems = fleet.plan_migration(self.tiered_fleet(), {}, tier_default="ro")
        finally:
            os.chmod(self.tmp / "guarded", 0o644)
        self.assertTrue(any(fleet.GUARDED_LIST_PATH in p for p in problems), problems)

    def test_migration_refuses_a_hub_or_a_hybrid_in_ai_space(self):
        self.app.domains["mcp-control"].tags.add("ai-managed")
        self.app.domains["ai-sink"].tags.add("ai-managed")
        _, problems = fleet.plan_migration(self.app, {}, tier_default="ro")
        self.assertEqual(sorted(p.split(":")[0] for p in problems), ["ai-sink", "mcp-control"])

    def test_role_actions(self):
        with self.assertRaises(fleet.RoleError):
            fleet.manage(self.app, "ai-net-router")      # gateways are always guarded
        with self.assertRaises(fleet.RoleError):
            fleet.manage(self.app, "mcp-control")        # the hub is never in AI space
        with self.assertRaises(fleet.RoleError):
            fleet.guard(self.app, "ai-sink")             # a drop box is never in AI space
        self.app.domains["personal"].netvm = self.app.domains["ai-net-router"]   # enrolled
        fleet.guard(self.app, "personal")
        self.assertEqual(core.state(self.app.domains["personal"]), "guarded")
        fleet.manage(self.app, "personal")
        self.assertEqual(core.state(self.app.domains["personal"]), "managed")
        self.assertIsNone(self.app.domains["personal"].default_dispvm)
        msg = fleet.revoke(self.app, "ai-work")
        vm = self.app.domains["ai-work"]
        self.assertEqual(core.tags_of(vm), {"operator-note"})
        self.assertIsNone(vm.default_dispvm)
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertIn("killed", msg)


# ======================================================================= audit findings

class AuditFindings(Base):
    """Regression tests from the pre-release review of M1 (2026-10-01). Each would fail on the
    code as it stood before the fix."""

    def spawn(self, **req):
        req.setdefault("name", "ai-hub-new")
        req.setdefault("template", "ai-debian-13")
        return self.call("qmcp.SpawnAIManagedQube", req)

    def trace(self, service, req):
        self.app.calls.clear()
        self.app.domains.lookups = 0
        r = self.call(service, req)
        return r, [c[1] for c in self.app.calls], self.app.domains.lookups

    def test_missing_and_outside_names_cost_the_same(self):
        # one qubesd call either way, and no domain-list shortcut.
        cases = [
            ("qmcp.GetPropertyAIManaged", lambda n: {"name": n, "property": "memory"}),
            ("qmcp.SetPropertyAIManaged", lambda n: {"name": n, "property": "memory", "value": 5}),
            ("qmcp.SetFeatureAIManaged", lambda n: {"name": n, "feature": "service.x", "value": 1}),
            ("qmcp.LifecycleAIManaged", lambda n: {"name": n, "action": "start"}),
            ("qmcp.CloneAIManagedQube", lambda n: {"source": n, "name": "ai-hub-oracle"}),
            ("qmcp.SpawnDisposableAIManaged", lambda n: {"template": n}),
            ("qmcp.SpawnAIManagedQube", lambda n: {"name": "ai-hub-oracle", "template": n}),
            ("qmcp.AIManagedEvents", lambda n: {"duration": 1, "qube": n}),
        ]
        # A qube of a hidden anonymous project is the hub's to see no more than
        # one outside AI space, and gets the same reply and the same qubesd
        # calls (not the same time: qubesd answers a missing qube sooner).
        self.app.vm("ai-hid-w1", tags={"ai-managed", "qmcp-proj-p05", "qmcp-anon",
                                       "qmcp-hubblind"})
        for svc, make in cases:
            missing = self.trace(svc, make("no-such-qube"))
            outside = self.trace(svc, make("personal"))
            hidden = self.trace(svc, make("ai-hid-w1"))
            self.assertEqual(missing, outside, svc)
            self.assertEqual(missing, hidden, svc)
            # The first read is the caller's own tags: the services refuse a hub
            # the anonymity gate stopped or the restore check holds. It is the
            # same for every name. A state-changing call also reads the badges
            # of each qube its request names, before it acts and after, for the
            # project its audit line belongs to: the same for every name too.
            # Before: the keys the service acts on; after: the names its line
            # records that the call judged in reach, which none of these is, so
            # after a refusal none of them is read. Both the same for every
            # name, as asserted above. Every read by name is balanced by a
            # second one (`core.tag_read_by_name`).
            reads = missing[1]
            self.assertEqual(set(reads), {"admin.vm.tag.List"}, svc)
            if services.SERVICES[svc][1]:
                self.assertGreaterEqual(len(reads), 3 + 2 * len(audit.REQUEST_KEYS[svc]), svc)
            else:
                self.assertEqual(len(reads), 3, svc)
            self.assertEqual(missing[2], 0, svc)

    def test_a_read_by_name_is_balanced_by_one_of_the_other_kind(self):
        """qubesd answers a missing qube sooner than it reads an existing
        one's tags, so a read by name is followed by one more of the same
        method on the other kind: a missing qube after a read that found its
        qube, dom0 after one that did not. Its answer and its failure are
        never used."""
        self.app.calls.clear()
        out = core.tag_read_by_name(self.app, "ai-work", "admin.vm.tag.Get", "ai-managed")
        self.assertEqual(out, b"1")
        self.assertEqual(self.app.calls, [("ai-work", "admin.vm.tag.Get", "ai-managed"),
                                          (core.BALANCE_MISSING, "admin.vm.tag.Get", "ai-managed")])
        self.app.calls.clear()
        with self.assertRaises(KeyError):
            core.tag_read_by_name(self.app, "no-such-qube", "admin.vm.tag.List")
        self.assertEqual([c[0] for c in self.app.calls], ["no-such-qube", core.BALANCE_PRESENT])
        # A read that fails (not a missing qube) raises its own error, after
        # its balance; a balance that fails changes nothing.
        self.app.fail_reads("admin.vm.tag.List", "fail fail")
        self.app.calls.clear()
        with self.assertRaises(Exception) as e:
            core.tag_read_by_name(self.app, "ai-work", "admin.vm.tag.List")
        self.assertNotIsInstance(e.exception, KeyError)
        self.assertEqual([c[0] for c in self.app.calls], ["ai-work", core.BALANCE_PRESENT])
        self.assertIn("ai-managed", core.tag_read_by_name(self.app, "ai-work",
                                                          "admin.vm.tag.List").decode())
        self.assertNotIn(core.BALANCE_MISSING, self.app.domains)

    def test_explicit_netvm_is_checked_by_name(self):
        self.egress("ai-net-router")
        a = self.trace("qmcp.SpawnAIManagedQube", {"name": "ai-hub-x1", "template": "ai-debian-13",
                                                   "netvm": "no-such-qube"})
        b = self.trace("qmcp.SpawnAIManagedQube", {"name": "ai-hub-x1", "template": "ai-debian-13",
                                                   "netvm": "sys-firewall"})
        self.assertEqual(a[0], b[0])
        self.assertEqual(a[1].count("admin.vm.tag.Get"), b[1].count("admin.vm.tag.Get"))

    def test_a_name_taken_during_the_lock_wait_is_refused(self):
        # the name is re-checked under the create lock.
        self.egress("ai-net-router")
        real = budget.acquire_create_lock

        def slow_lock(*a, **kw):
            self.app.vm("ai-hub-new", tags={"operator-made"})    # someone else, meanwhile
            return real(*a, **kw)
        budget.acquire_create_lock = slow_lock
        try:
            r = self.spawn()
        finally:
            budget.acquire_create_lock = real
        self.assertEqual(r["error"], "qube 'ai-hub-new' already exists")
        self.assertIn("operator-made", self.tags("ai-hub-new"))

    def test_a_failed_create_never_removes_someone_elses_qube(self):
        # a create call that raised is never "rolled back" by name.
        self.egress("ai-net-router")

        def racing_add(klass, name, label, template=None):
            self.app.vm(name, tags={"operator-made"})
            raise fakequbes.Injected(f"exists {SECRET}")
        self.app.add_new_vm = racing_add
        r = self.spawn()
        self.assertEqual(r["error"], "create failed; a qube named 'ai-hub-new' exists and was left alone")
        self.assertIn("operator-made", self.tags("ai-hub-new"))

    def test_a_template_netvm_never_decides(self):
        # a TemplateVM base does not answer for a child's network.
        self.egress("ai-net-router")
        self.app.domains["ai-debian-13"]._props["netvm"] = self.app.domains["ai-gw-unbadged"]
        self.assertTrue(self.spawn()["ok"])
        self.assertEqual(self.app.domains["ai-hub-new"].netvm.name, "ai-net-router")

    def test_nothing_is_spawned_from_a_gateway(self):
        # the child would provide network with its guard stripped.
        router = self.app.domains["ai-net-router"]
        self.app.vm("ai-gw-dvm", template_for_dispvms=True, provides_network=True,
                    netvm=router, tags={"ai-managed", "qmcp-guarded"})
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-gw-dvm"})
        self.assertEqual(r["error"], "a disposable template that provides network cannot be spawned from")
        r = self.spawn(name="ai-hub-gwd", klass="DispVM", template="ai-gw-dvm")
        self.assertEqual(r["error"], "a template that provides network cannot be spawned from")
        self.assertEqual(self.app.domains._hidden, {})
        self.assertNotIn("ai-hub-gwd", self.app.domains)

    def test_a_child_that_provides_network_is_rolled_back(self):
        # Second line of defence: if the pre-check is ever bypassed.
        router = self.app.domains["ai-net-router"]
        self.app.vm("ai-gw-dvm", template_for_dispvms=True, provides_network=True,
                    netvm=router, tags={"ai-managed", "qmcp-guarded"})
        saved = services._not_a_gateway
        services._not_a_gateway = lambda vm, what: None
        try:
            r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-gw-dvm"})
        finally:
            services._not_a_gateway = saved
        self.assertEqual(r["error"], "network check failed (rolled back)")
        self.assertEqual(self.app.domains._hidden, {})

    def test_a_label_is_not_a_qube(self):
        # an operator qube named like a colour.
        self.app.vm("black")
        self.app.domains["ai-work"]._props["label"] = fakequbes.FakeLabel("black")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "label"})
        self.assertEqual(r["value"], "black")

    def test_an_unreadable_volume_refuses_creates_and_stats(self):
        # never budget against a guess.
        self.egress("ai-net-router")

        class Broken:
            def __getitem__(self, key):
                raise fakequbes.Injected("volume read failed")
        self.app.domains["ai-work2"].__dict__["volumes"] = Broken()
        self.assertEqual(self.spawn()["error"], budget.ERR_STATS_UNAVAILABLE)
        self.assertEqual(self.audit_lines()[-1].get("error_class"), "Injected")
        self.assertEqual(self.call("qmcp.GetPoolStats")["error"], budget.ERR_STATS_UNAVAILABLE)

    def test_an_unreadable_clone_source_is_refused_and_logged(self):
        class Broken:
            def __getitem__(self, key):
                raise fakequbes.Injected(f"volume read failed: {SECRET}")
        self.app.domains["ai-work2"].__dict__["volumes"] = Broken()
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-hub-copy"})
        self.assertEqual(r["error"], budget.ERR_STATS_UNAVAILABLE)
        self.assertEqual(self.audit_lines()[-1].get("error_class"), "Injected")

    def test_a_name_that_cannot_be_checked_is_refused_and_logged(self):
        self.egress("ai-net-router")

        def broken():
            raise fakequbes.Injected(f"lookup failed: {SECRET}")
        self.app.domains.clear_cache = broken
        r = self.spawn()
        self.assertEqual(r, {"ok": False, "error": "could not check the name"})
        self.assertEqual(self.audit_lines()[-1].get("error_class"), "Injected")

    def test_pins_hold_even_when_the_value_equals_the_default(self):
        # the global default already IS the birth network; still pin it.
        self.egress("ai-net-router")
        self.app.default_netvm = self.app.domains["ai-net-router"]
        self.assertTrue(self.spawn()["ok"])
        self.assertFalse(self.app.domains["ai-hub-new"].property_is_default("netvm"))

    def test_netvm_addresses_follow_the_netvm(self):
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-net-router", "property": "visible_gateway"})
        self.assertEqual(r["value"], "<out-of-scope>")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "visible_gateway"})
        self.assertEqual(r["value"], "10.137.0.5")
        # Whose addresses they are must be read: a network that cannot be read
        # is refused, never taken for none and the addresses shown.
        self.app.fail.add("get.netvm:ai-net-router")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-net-router", "property": "visible_gateway"})
        self.assertFalse(r["ok"], r)
        self.assertNotIn("10.137", json.dumps(r))

    def test_a_network_that_does_not_read_back_rolls_the_create_back(self):
        self.egress("ai-net-router")
        real = self.app.add_new_vm

        def add(*a, **kw):
            vm = real(*a, **kw)
            self.app.fail.add(f"get.netvm:{vm.name}")        # its read-back fails
            return vm
        self.app.add_new_vm = add
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-nr", "template": "ai-debian-13",
                                                  "netvm": None})
        self.assertFalse(r["ok"], r)
        self.app.fail.clear()
        self.assertNotIn("ai-hub-nr", {v.name for v in self.app.domains})

    def test_audit_rotation_keeps_the_chain(self):
        for i in range(3):
            audit.audit("svc", HUB, {"i": i}, True)
        aside = audit.rotate()
        audit.audit("svc", HUB, {"i": 3}, True)
        self.assertEqual(audit.verify(), (True, 2, None))
        self.assertEqual(audit.verify(aside), (True, 3, None))
        anchor = json.loads(pathlib.Path(audit.LOG_PATH).read_text().splitlines()[0])
        old_head = json.loads(pathlib.Path(aside).read_text().splitlines()[-1])
        self.assertEqual(anchor["prev"], old_head["hash"])

    def test_audit_appends_read_only_the_tail(self):
        # a log far longer than the tail window still chains.
        n = 3000
        for i in range(n):
            audit.audit("svc", HUB, {"i": i, "pad": "x" * 100}, True)
        self.assertGreater(pathlib.Path(audit.LOG_PATH).stat().st_size, audit.TAIL_BYTES * 4)
        self.assertEqual(audit.verify(), (True, n, None))


class PolicyFacts(Base):
    """qmcp check's policy facts: the hub the policy names, and precedence."""

    def test_check_catches_a_policy_naming_another_hub(self):
        # the installer once rendered `mcp-control` over a custom hub.
        pol, share = self.tmp / "pol", self.tmp / "lib" / "share"
        pol.mkdir(); share.mkdir(parents=True)
        text = "*  *  other-hub  @anyvm  deny\n"
        for d in (pol, share):
            (d / fleet.POLICY_NAME).write_text(text)
        f = {x.check: x for x in fleet.check(self.app, policy_dir=str(pol), lib_dir=str(self.tmp / "lib"),
                                             legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["policy hub"].status, "fail")
        self.assertIn("other-hub", f["policy hub"].detail)

    def _policy(self, extra=None):
        import logging
        from qrexec.policy.parser import FilePolicy
        logging.disable(logging.WARNING)
        d = self.tmp / "policy.d"
        shutil.copytree(HERE / "data" / "upstream-policy-4.3", d, dirs_exist_ok=True)
        shutil.copy(HERE.parent / "policy" / fleet.POLICY_NAME, d / fleet.POLICY_NAME)
        for name, text in (extra or {}).items():
            (d / name).write_text(text)
        try:
            return FilePolicy(policy_path=d)
        finally:
            logging.disable(logging.NOTSET)

    def test_precedence_is_clean_on_upstream_defaults(self):
        self.assertEqual(fleet.precedence(self._policy(), {"domains": {}}, HUB), [])

    def test_precedence_catches_an_earlier_file(self):
        # parsing passes, precedence does not.
        policy = self._policy({"20-operator.policy":
                               "qubes.VMExec * @anyvm @anyvm allow\n"
                               "admin.vm.tag.Set * @anyvm @anyvm allow target=dom0\n"})
        problems = fleet.precedence(policy, {"domains": {}}, HUB)
        self.assertTrue(any("20-operator.policy" in p and "qubes.VMExec" not in p for p in problems))
        self.assertTrue(any("Admin API on a qube" in p for p in problems), problems)

    def _check_with(self, extra_name, extra_text, mode=None):
        pol, share = self.tmp / "pol", self.tmp / "lib" / "share"
        pol.mkdir(); share.mkdir(parents=True)
        text = (HERE.parent / "policy" / fleet.POLICY_NAME).read_text()
        for d in (pol, share):
            (d / fleet.POLICY_NAME).write_text(text)
        (pol / extra_name).write_text(extra_text)
        if mode is not None:
            os.chmod(pol / extra_name, mode)
        try:
            return {x.check: x for x in fleet.check(self.app, policy_dir=str(pol),
                                                    lib_dir=str(self.tmp / "lib"), legacy_paths=(),
                                                    system_info={"domains": {}})}
        finally:
            os.chmod(pol / extra_name, 0o644)

    @unittest.skipIf(os.geteuid() == 0, "root reads a file whatever its mode")
    def test_an_unreadable_policy_file_is_incomplete_not_failed(self):
        # Measured on the dev box: a root-only 0600 file made check, run as the
        # dom0 user, report FAILED "parser refuses ... AccessDenied" for a policy
        # set that was fine. Mode 000 makes the file unreadable to its owner too.
        f = self._check_with("20-operator.policy", "qubes.OpenURL * @anyvm @anyvm deny\n", 0o000)
        self.assertEqual(f["policy parses"].status, "error")
        self.assertIn("run qmcp check as root", f["policy parses"].detail)

    def test_a_malformed_policy_file_still_fails(self):
        f = self._check_with("20-operator.policy", "qubes.OpenURL * @anyvm\n")
        self.assertEqual(f["policy parses"].status, "fail")


class EventFeatureKeys(Base):
    def test_only_the_feature_keys_the_hub_may_set_reach_it(self):
        script = [("ai-work", "domain-feature-set:qmcp-owner-kept", {"feature": "qmcp-owner-kept"}),
                  ("ai-work", "domain-feature-set:qmcp-id", {}),
                  ("ai-work", "domain-feature-delete:qmcp-id", {}),
                  ("ai-work", "domain-feature-set:qmcp-services", {}),
                  ("ai-work", "domain-feature-set:service.cups", {"feature": "service.cups"}),
                  ("ai-work", "domain-feature-set:menu-items", {})]
        saved = services._dispatcher
        services._dispatcher = lambda app: FakeDispatcher(app, script)
        try:
            r = self.call("qmcp.AIManagedEvents", {"duration": 1})
        finally:
            services._dispatcher = saved
        self.assertEqual([e["event"] for e in r["events"]],
                         ["domain-feature-set:service.cups", "domain-feature-set:menu-items"])


class RequestDeadline(Base):
    def test_a_request_stream_left_open_frees_the_callers_slots(self):
        saved = core.REQUEST_TIMEOUT_S
        self.addCleanup(setattr, core, "REQUEST_TIMEOUT_S", saved)
        core.REQUEST_TIMEOUT_S = 0.3
        r, w = os.pipe()
        self.addCleanup(os.close, w)
        os.write(w, b'{"name": ')                              # and never more, never closed
        stdin = os.fdopen(r, "rb")
        self.addCleanup(stdin.close)
        out = io.StringIO()
        started = time.monotonic()
        services.main("qmcp.GetPoolStats", stdin=stdin, environ={"QREXEC_REMOTE_DOMAIN": HUB},
                      app_factory=lambda: self.app, out=out)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(json.loads(out.getvalue())["error"], "request timed out")
        self.assertTrue(self.call("qmcp.GetPoolStats")["ok"])  # its slot is free again


class StaleDomainList(Base):
    """A create's budget is judged on the domain list as it is under the
    create lock, not as the process first read it (qubesadmin keeps it)."""

    def test_parallel_disposables_never_pass_the_pool_cap(self):
        from fakequbes import ProcApp
        self.egress("ai-net-router")
        used = budget.persistent_sum(self.app)
        (self.tmp / "pool-cap").write_text(str(used + 2 * GiB) + "\n")   # room for one
        real = budget.acquire_create_lock
        other = {}

        def another_lands_while_this_waits(*a, **kw):
            if not other:
                budget.acquire_create_lock = real
                other["r"] = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"},
                                       app=ProcApp(self.app))
                budget.acquire_create_lock = another_lands_while_this_waits
            return real(*a, **kw)
        budget.acquire_create_lock = another_lands_while_this_waits
        try:
            mine = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"},
                             app=ProcApp(self.app))
        finally:
            budget.acquire_create_lock = real
        self.assertTrue(other["r"]["ok"], other)
        self.assertFalse(mine["ok"], mine)
        self.assertIn("pool cap", mine["error"])
        self.app.domains.clear_cache()
        self.assertLessEqual(budget.persistent_sum(self.app), used + 2 * GiB)


class Windows(Base):
    """The operator's open window on a guarded qube.

    The badge is the whole gate — A6b routes on it, and the services it opens
    run inside the target qube or are qubesd's own — so these tests are about
    two things: that a badge is never on when it should not be, and that
    whatever takes it off is an ACTION and not a report.
    """

    TPL = "ai-tpl-g"            # a guarded template: the window's own use case

    def findings(self):
        return {f.check: f for f in fleet.check(self.app, legacy_paths=(),
                                                system_info={"domains": {}})}

    def tags(self, name=None):
        return self.app.domains[name or self.TPL].tags.raw()

    def test_a_seal_says_the_hubs_firewall_rules_stay(self):
        for firewall in (False, True):
            with self.subTest(firewall=firewall):
                fleet.open_window(self.app, "ai-tpl-g", 3600, firewall=firewall)
                text = fleet.seal(self.app, "ai-tpl-g")
                self.assertEqual("firewall rules the hub wrote stay" in text, firewall, text)

    def test_manage_of_an_open_qube_ends_the_window_while_it_is_guarded(self):
        vm = self.app.domains["ai-tpl-g"]
        vm.start()
        fleet.open_window(self.app, "ai-tpl-g", 3600)
        seen = []
        real = fakequbes.FakeTags.discard

        def discard(tags, tag):
            if tag in (core.OPEN, core.OPEN_FW):
                seen.append(core.GUARDED in tags.raw())
            return real(tags, tag)
        self.addCleanup(setattr, fakequbes.FakeTags, "discard", real)
        fakequbes.FakeTags.discard = discard
        fleet.manage(self.app, "ai-tpl-g")
        self.assertEqual(seen, [True])          # guarded still, when the window's badge came off
        self.assertFalse(vm.tags.raw() & {core.OPEN, core.OPEN_FW, core.GUARDED})

    def test_manage_whose_window_does_not_come_off_says_seal_and_keeps_the_guard(self):
        vm = self.app.domains["ai-tpl-g"]
        vm.start()
        fleet.open_window(self.app, "ai-tpl-g", 3600)
        self.app.fail.add(f"tag.discard:{core.OPEN}")
        with self.assertRaisesRegex(fleet.RoleError, "run qmcp seal ai-tpl-g"):
            fleet.manage(self.app, "ai-tpl-g")
        self.app.fail.clear()
        self.assertIn(core.GUARDED, vm.tags.raw())
        self.assertEqual(vm._power, "Running")

    def test_open_gives_both_halves_only_when_asked(self):
        fleet.open_window(self.app, self.TPL, 3600)
        self.assertEqual(self.tags() & {core.OPEN, core.OPEN_FW}, {core.OPEN})
        rec = fleet.read_window(self.TPL)
        self.assertFalse(rec["firewall"])
        self.assertGreater(fleet.window_left(self.TPL), 3500)
        # Re-opening with --firewall adds the second badge; without it, it goes.
        fleet.open_window(self.app, self.TPL, 600, firewall=True)
        self.assertEqual(self.tags() & {core.OPEN, core.OPEN_FW}, {core.OPEN, core.OPEN_FW})
        self.assertTrue(fleet.read_window(self.TPL)["firewall"])
        fleet.open_window(self.app, self.TPL, 600)
        self.assertEqual(self.tags() & {core.OPEN, core.OPEN_FW}, {core.OPEN})

    def test_open_refuses_every_qube_243_names(self):
        a = self.app
        for name, word in (("ai-net-router", "provides network"),    # a gateway, by its property
                           ("ai-work", "managed already"),           # no window needed
                           ("personal", "not in AI space"),
                           ("mcp-control", "the hub"),
                           ("ai-sink", "drop box")):
            with self.assertRaises(fleet.RoleError) as cm:
                fleet.open_window(a, name, 60)
            self.assertIn(word, str(cm.exception))
        for badge in (projects.BLOCKED, projects.HUBBLIND):
            a.domains[self.TPL].tags.add(badge)
            with self.assertRaises(fleet.RoleError) as cm:
                fleet.open_window(a, self.TPL, 60)
            self.assertIn(badge, str(cm.exception))
            a.domains[self.TPL].tags.discard(badge)
        a.domains[self.TPL].tags.add("qmcp-proj-p01")
        with self.assertRaises(fleet.RoleError):
            fleet.open_window(a, self.TPL, 60)
        # Refused means nothing was written: no badge, and no record either.
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        with self.assertRaises(fleet.WindowUnreadable):
            fleet.read_window(self.TPL)

    def test_the_duration_is_bounded_and_has_no_indefinite_form(self):
        self.assertEqual([fleet.duration_seconds(x) for x in ("90s", "30m", "2h", "45")],
                         [90, 1800, 7200, 45])
        for junk in ("", "2 h", "1.5h", "-5", "2d", "h", None, 3600, " 2h", "2h\n", "2h\r"):
            with self.assertRaises(fleet.RoleError):
                fleet.duration_seconds(junk)
        for bad in (0, -1, fleet.WINDOW_MAX_S + 1, True, 1.5):
            with self.assertRaises(fleet.RoleError):
                fleet.open_window(self.app, self.TPL, bad)
        fleet.open_window(self.app, self.TPL, fleet.WINDOW_MAX_S)       # the cap itself is fine

    def test_a_failed_badge_write_leaves_neither_badge_nor_record(self):
        self.app.fail.add(f"tag.add:{core.OPEN}")
        with self.assertRaises(fleet.RoleError):
            fleet.open_window(self.app, self.TPL, 600, firewall=True)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        with self.assertRaises(fleet.WindowUnreadable):
            fleet.read_window(self.TPL)

    def test_a_badge_that_landed_before_the_failure_still_comes_off(self):
        # qubesd sets the tag and then fails: the rollback must not believe
        # the exception meant nothing was written.
        self.app.fail.add(f"tag.add.landed:{core.OPEN}")
        with self.assertRaises(fleet.RoleError):
            fleet.open_window(self.app, self.TPL, 600)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})

    def test_the_record_rejects_a_bool_and_anything_malformed(self):
        fleet.open_window(self.app, self.TPL, 600)
        path = pathlib.Path(fleet.WINDOW_DIR) / self.TPL
        for bad in ('{"opened": 1, "expires": true, "firewall": false}',
                    '{"opened": 1, "expires": 99, "firewall": "yes"}',
                    '{"expires": 99, "firewall": false}', "[]", "not json", ""):
            path.write_text(bad)
            with self.assertRaises(fleet.WindowUnreadable):
                fleet.read_window(self.TPL)

    def test_seal_takes_both_badges_off_and_kills_what_runs(self):
        self.app.domains[self.TPL].__dict__["_power"] = "Running"
        fleet.open_window(self.app, self.TPL, 600, firewall=True)
        msg = fleet.seal(self.app, self.TPL)
        self.assertIn("killed", msg)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        self.assertEqual(self.app.domains[self.TPL].get_power_state(), "Halted")
        self.assertFalse((pathlib.Path(fleet.WINDOW_DIR) / self.TPL).exists())
        # Twice is safe, and says so rather than killing a qube that is not open.
        self.app.domains[self.TPL].__dict__["_power"] = "Running"
        self.assertIn("not open", fleet.seal(self.app, self.TPL))
        self.assertEqual(self.app.domains[self.TPL].get_power_state(), "Running")

    def test_the_pass_seals_every_window_that_cannot_be_trusted(self):
        a, path = self.app, pathlib.Path(fleet.WINDOW_DIR)
        fleet.open_window(a, self.TPL, 600)
        (path / self.TPL).write_text('{"opened": 1, "expires": 2, "firewall": false}')
        self.assertTrue(fleet.expire_windows(a))
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        # A badge with no record at all: the state every boot would leave.
        fleet.open_window(a, self.TPL, 600)
        (path / self.TPL).unlink()
        self.assertTrue(fleet.expire_windows(a))
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        # A record that does not parse.
        fleet.open_window(a, self.TPL, 600)
        (path / self.TPL).write_text("{")
        self.assertTrue(fleet.expire_windows(a))
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        # A healthy window is left alone.
        fleet.open_window(a, self.TPL, 600)
        self.assertEqual(fleet.expire_windows(a), [])
        self.assertIn(core.OPEN, self.tags())

    def test_the_pass_strips_a_badge_the_rulebook_could_not_refuse(self):
        # A gateway is guarded by its provides_network property, and no tag
        # carries that, so A6b would be live for one wearing the badge. The
        # command refuses to put it there; this takes it off if it arrives.
        a = self.app
        # A HEALTHY, unexpired record, so the only thing that can seal this is
        # the refusal itself. Without it the qube is sealed for having no
        # record at all and the test passes whatever `_open_refusal` says — a
        # mutation run caught exactly that.
        fleet.write_window("ai-net-router", 600, False)
        a.domains["ai-net-router"].tags.add(core.OPEN)
        self.assertGreater(fleet.window_left("ai-net-router"), 500)
        lines = fleet.expire_windows(a)
        self.assertTrue(any("ai-net-router" in l and "provides network" in l for l in lines),
                        lines)
        self.assertNotIn(core.OPEN, a.domains["ai-net-router"].tags.raw())

    def test_an_unreadable_hub_file_never_stops_a_seal(self):
        # The role actions refuse every name while the hub file does not read
        # (any name may be the hub); taking a window off only lowers authority,
        # so the boot seal, the expiry pass and `qmcp seal` still do it, and
        # skip only the kill, which needs to know the qube is not the hub.
        from unittest import mock
        self.app.domains[self.TPL].start()
        for sweep in ("every", "expired", "named"):
            with self.subTest(sweep):
                fleet.open_window(self.app, self.TPL, 1 if sweep == "expired" else 3600)
                with mock.patch.object(core, "read_hub", return_value=None):
                    if sweep == "named":
                        line = fleet.seal(self.app, self.TPL)
                    else:
                        if sweep == "expired":
                            import time as _t
                            _t.sleep(1.1)
                        lines = fleet.expire_windows(self.app, every=sweep == "every")
                        line = " ".join(lines)
                    with self.assertRaises(fleet.RoleError):
                        fleet.open_window(self.app, self.TPL, 60)
                self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW}, line)
                self.assertIn("not killed", line)
                self.assertEqual(self.app.domains[self.TPL].get_power_state(), "Running")
                with self.assertRaises(Exception):
                    fleet.read_window(self.TPL)
                # The kill waits for the hub file, as a pending kill; this
                # test's next round opens the qube again, so it goes here.
                self.assertTrue(fleet.kill_pending(self.TPL))
                fleet.clear_window(self.TPL)

    def test_a_seal_takes_the_badges_off_a_drop_box_and_the_hub(self):
        # `qmcp open` refuses both, but a hand-written tag reaches them, and the
        # rulebook's window lines match the badge alone. Every seal takes it off;
        # the hub is never killed.
        a = self.app
        a.domains["mcp-control"].start()
        for sweep in ("named", "expired", "every"):
            with self.subTest(sweep):
                for name in ("ai-sink", "mcp-control"):
                    a.domains[name].tags.add(core.OPEN)
                    a.domains[name].tags.add(core.OPEN_FW)
                if sweep == "named":
                    lines = [fleet.seal(a, "ai-sink"), fleet.seal(a, "mcp-control")]
                else:
                    lines = fleet.expire_windows(a, every=sweep == "every")
                for name in ("ai-sink", "mcp-control"):
                    self.assertFalse(self.tags(name) & {core.OPEN, core.OPEN_FW}, lines)
                self.assertFalse(any("NOT sealed" in line for line in lines), lines)
                self.assertTrue(any("mcp-control" in line and "it is the hub" in line
                                    for line in lines), lines)
                self.assertEqual(a.domains["mcp-control"].get_power_state(), "Running")

    def test_a_window_whose_refusal_read_fails_is_sealed_not_skipped(self):
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail.add(f"get.provides_network:{self.TPL}")
        lines = fleet.expire_windows(self.app)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW}, lines)
        self.assertTrue(any("cannot be told" in line for line in lines), lines)

    def test_a_window_record_is_never_read_or_written_through_a_link(self):
        # /run/qmcp/open is the services' group's to write: root opens no link
        # planted at a record or its temporary name, nor blocks on a FIFO.
        d = pathlib.Path(fleet.WINDOW_DIR)
        d.mkdir(parents=True, exist_ok=True)
        victim = self.tmp / "victim"
        victim.write_text("precious")
        os.symlink(victim, d / "ai-work")
        os.symlink(victim, d / f"ai-work.{os.getpid()}.tmp")
        with self.assertRaises(fleet.WindowUnreadable):
            fleet.read_window("ai-work")                     # a link reads as unreadable
        self.assertFalse(fleet.kill_pending("ai-work"))
        fleet.write_window("ai-work", 600, False)
        self.assertEqual(victim.read_text(), "precious")
        self.assertFalse((d / "ai-work").is_symlink())
        self.assertEqual(fleet.read_window("ai-work")["firewall"], False)
        fleet.mark_kill_pending("ai-work")
        self.assertTrue(fleet.kill_pending("ai-work"))
        os.unlink(d / "ai-work")
        os.mkfifo(d / "ai-work")
        with self.assertRaises(fleet.WindowUnreadable):
            fleet.read_window("ai-work")                     # and a FIFO never blocks it
        self.assertEqual(victim.read_text(), "precious")
        self.assertEqual(sorted(p.name for p in d.iterdir() if p.name.endswith(".tmp")), [])

    def test_a_revoke_whose_kill_fails_keeps_the_seals_pending_kill(self):
        vm = self.app.domains[self.TPL]
        vm.start()
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail.add("kill")
        fleet.seal(self.app, self.TPL)
        with self.assertRaises(fleet.RoleError):
            fleet.revoke(self.app, self.TPL)                    # its own kill fails too
        self.app.fail.clear()
        self.assertEqual(fleet.pending_kills(), [self.TPL])
        fleet.expire_windows(self.app)
        self.assertEqual(vm.get_power_state(), "Halted")

    def test_a_revoke_of_an_open_qube_whose_kill_fails_leaves_a_pending_kill(self):
        # W: an open window; E: a seal that marked its kill and could not take
        # the badge off. Either way a kill of the revoke's that fails leaves
        # a kill the timer tries again.
        for case in ("W", "E"):
            vm = self.app.domains[self.TPL]
            if core.UMBRELLA not in vm.tags.raw():
                fleet.guard(self.app, self.TPL)
            if vm.get_power_state() != "Running":
                vm.start()
            fleet.open_window(self.app, self.TPL, 3600)
            if case == "E":
                self.app.fail.add("tag.discard:qmcp-open")
                try:
                    fleet.seal(self.app, self.TPL)
                except Exception:
                    pass
                self.app.fail.clear()
                self.assertEqual(fleet.pending_kills(), [self.TPL], case)
            self.app.fail.add("kill")
            with self.assertRaises(fleet.RoleError):
                fleet.revoke(self.app, self.TPL)
            self.app.fail.clear()
            self.assertEqual(fleet.pending_kills(), [self.TPL], case)
            fleet.expire_windows(self.app)
            self.assertEqual(vm.get_power_state(), "Halted", case)
            self.assertEqual(fleet.pending_kills(), [], case)

    def test_the_check_fails_on_a_boot_seal_disabled_or_unordered(self):
        def item():
            return [(f.status, f.detail) for f in fleet.check(self.app) if f.check == "boot seal"]
        self.assertEqual([st for st, _ in item()], ["pass"])
        saved = anon.TIMER_CHECK
        self.addCleanup(setattr, anon, "TIMER_CHECK", saved)
        anon.TIMER_CHECK = lambda unit=None: unit != fleet.SEAL_UNIT
        self.assertEqual([st for st, _ in item()], ["fail"])
        anon.TIMER_CHECK = saved
        os.unlink(fleet.SEAL_DROPIN)
        found = item()
        self.assertEqual([st for st, _ in found], ["fail"])
        self.assertIn("does not order Qubes' autostart", found[0][1])

    def test_manage_and_revoke_drop_a_pending_kill_so_the_sweep_kills_nothing(self):
        for act in ("manage", "revoke"):
            vm = self.app.domains[self.TPL]
            if core.UMBRELLA not in vm.tags.raw():                # back after the revoke
                fleet.guard(self.app, self.TPL)
            vm.start()
            fleet.open_window(self.app, self.TPL, 3600)
            self.app.fail.add("kill")
            fleet.seal(self.app, self.TPL)
            self.app.fail.clear()
            self.assertEqual(fleet.pending_kills(), [self.TPL])
            msg = (fleet.manage(self.app, self.TPL) if act == "manage"
                   else fleet.revoke(self.app, self.TPL, shutdown=False))
            self.assertIn("the kill its seal could not make is dropped", msg)
            self.assertEqual(fleet.pending_kills(), [])
            fleet.expire_windows(self.app)
            self.assertEqual(vm.get_power_state(), "Running", act)
            if act == "manage":
                fleet.guard(self.app, self.TPL)

    def test_a_wall_clock_stepped_back_never_lengthens_a_window(self):
        # The end is kept on the clock since boot too, which nothing sets: a
        # wall clock held back (within the slack) still ends a 2 h window when
        # the boot clock says 2 h have passed, and one stepped back further
        # (the window opened "in the future", or ends past the 24 h cap) ends
        # it at once.
        boot = [1000.0]
        with mock.patch.object(fleet, "_boot_clock", lambda: boot[0]):
            fleet.open_window(self.app, self.TPL, 7200)
            self.assertLessEqual(fleet.window_left(self.TPL, now=time.time() - 3600), 0)
            back = time.time() - 30
            self.assertGreater(fleet.window_left(self.TPL, now=back), 0)
            boot[0] += 7300
            lines = fleet.expire_windows(self.app, now=back)
            self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW}, lines)
            fleet.open_window(self.app, self.TPL, 7200)
            self.assertLessEqual(fleet.window_left(self.TPL, now=time.time() - 86400), 0)
            lines = fleet.expire_windows(self.app, now=time.time() - 86400)
            self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW}, lines)

    def test_an_expired_window_whose_tags_do_not_read_is_sealed(self):
        fleet.open_window(self.app, self.TPL, 60)
        self.app.fail_reads(f"tag.List:{self.TPL}", "fail")      # the pass's own read only
        lines = fleet.expire_windows(self.app, now=time.time() + 120)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW}, lines)
        self.assertTrue(any("ran out, and its tags do not read" in line for line in lines), lines)
        self.assertFalse(os.path.exists(fleet._window_path(self.TPL)))

    def test_an_unread_window_with_time_left_or_no_record_stays_and_is_named(self):
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail_reads(f"tag.List:{self.TPL}", "fail")
        lines = fleet.expire_windows(self.app)
        self.assertIn(core.OPEN, self.tags(), lines)          # time left: nothing to seal
        self.assertTrue(any("could not be judged" in line for line in lines), lines)
        fleet.clear_window(self.TPL)                         # no record: nothing says it is open
        self.app.fail_reads(f"tag.List:{self.TPL}", "fail")
        lines = fleet.expire_windows(self.app, now=time.time() + 7200)
        self.assertIn(core.OPEN, self.tags(), lines)
        self.assertTrue(any("could not be judged" in line for line in lines), lines)

    def test_a_named_seal_needs_no_tag_read(self):
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail_reads(f"tag.List:{self.TPL}", "fail")
        fleet.seal(self.app, self.TPL)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})

    def test_a_seal_whose_kill_fails_is_named_and_tried_again(self):
        vm = self.app.domains[self.TPL]
        vm.__dict__["_power"] = "Running"
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail.add("kill")
        msg = fleet.seal(self.app, self.TPL)
        self.assertIn("could NOT be killed", msg)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        self.assertTrue(fleet.kill_pending(self.TPL))
        self.assertEqual(fleet.pending_kills(), [self.TPL])
        self.assertEqual(self.findings()["open windows"].status, "fail")
        self.assertIn("NOT killed", " ".join(fleet.expire_windows(self.app)))
        self.app.fail.discard("kill")
        lines = fleet.expire_windows(self.app)
        self.assertTrue(any("killed on a later pass" in line for line in lines), lines)
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertEqual(fleet.pending_kills(), [])
        self.assertEqual(self.findings()["open windows"].status, "pass")

    def test_a_seal_cut_short_after_its_badges_is_killed_by_the_next_pass(self):
        vm = self.app.domains[self.TPL]
        vm.__dict__["_power"] = "Running"
        fleet.open_window(self.app, self.TPL, 3600)
        real = fleet._kill_if_running
        fleet._kill_if_running = lambda vm: (_ for _ in ()).throw(SystemExit("killed"))
        try:
            with self.assertRaises(SystemExit):
                fleet.seal(self.app, self.TPL)          # the process dies before its kill
        finally:
            fleet._kill_if_running = real
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        self.assertEqual(vm.get_power_state(), "Running")
        fleet.expire_windows(self.app)
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertEqual(fleet.pending_kills(), [])

    def test_a_record_that_cannot_be_removed_never_ends_the_pass(self):
        for name in (self.TPL, "ai-dvm-g"):
            fleet.open_window(self.app, name, 3600)
        real = fleet.clear_window

        def stuck(name, dir_=None):
            if name == self.TPL:
                raise PermissionError(name)
            return real(name, dir_)
        fleet.clear_window = stuck
        try:
            lines = fleet.expire_windows(self.app, every=True)
        finally:
            fleet.clear_window = real
        for name in (self.TPL, "ai-dvm-g"):
            self.assertFalse(self.tags(name) & {core.OPEN, core.OPEN_FW}, lines)

    def test_an_unexpected_error_in_one_seal_never_ends_the_pass(self):
        for name in (self.TPL, "ai-dvm-g"):
            fleet.open_window(self.app, name, 3600)
        real = fleet._seal_target

        def broken(app, name):
            if name == self.TPL:
                raise RuntimeError("qubesd")
            return real(app, name)
        fleet._seal_target = broken
        try:
            lines = fleet.expire_windows(self.app, every=True)
        finally:
            fleet._seal_target = real
        self.assertIn(f"{self.TPL}: NOT sealed: RuntimeError", lines)
        self.assertFalse(self.tags("ai-dvm-g") & {core.OPEN, core.OPEN_FW}, lines)

    def pending_after_failed_kill(self):
        vm = self.app.domains[self.TPL]
        vm.start()
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail.add("kill")
        fleet.seal(self.app, self.TPL)
        self.app.fail.discard("kill")
        self.assertTrue(fleet.kill_pending(self.TPL))
        return vm

    def test_a_pending_kill_spares_a_qube_started_again_since(self):
        # The operator's own restart ended what the hub left running; a kill
        # now would only end the operator's session.
        vm = self.pending_after_failed_kill()
        vm.kill()
        vm.start()
        lines = fleet.expire_windows(self.app)
        self.assertTrue(any("started again since its seal" in l for l in lines), lines)
        self.assertEqual(vm.get_power_state(), "Running")
        self.assertEqual(fleet.pending_kills(), [])

    def test_a_pending_kill_spares_another_qube_of_that_name(self):
        self.pending_after_failed_kill()
        self.app.domains[self.TPL]._props["uuid"] = "00000000-0000-4000-8000-000000000000"
        lines = fleet.expire_windows(self.app)
        self.assertTrue(any("another qube of that name" in l for l in lines), lines)
        self.assertEqual(self.app.domains[self.TPL].get_power_state(), "Running")

    def test_a_dropped_pending_kill_leaves_one_line(self):
        vm = self.pending_after_failed_kill()
        vm.kill()
        vm.start()
        n = len(self.audit_lines())
        fleet.expire_windows(self.app)
        new = self.audit_lines()[n:]
        self.assertEqual([(l["service"], l["args"]["swept"]) for l in new],
                         [("qmcp seal", "pending kill dropped: stopped and started again since "
                                        "its seal")])
        fleet.expire_windows(self.app)                     # nothing left: no second line
        self.assertEqual(len(self.audit_lines()), n + 1)

    def test_a_retry_that_fails_again_leaves_no_line(self):
        self.pending_after_failed_kill()
        self.app.fail.add("kill")
        n = len(self.audit_lines())
        fleet.expire_windows(self.app)
        fleet.expire_windows(self.app)
        self.app.fail.discard("kill")
        self.assertEqual(len(self.audit_lines()), n)
        self.assertEqual(fleet.pending_kills(), [self.TPL])

    def test_the_hub_is_never_left_with_a_pending_kill(self):
        a = self.app
        a.domains["mcp-control"].start()
        a.domains["mcp-control"].tags.add(core.OPEN)
        fleet.seal(a, "mcp-control")
        self.assertEqual(fleet.pending_kills(), [])
        self.assertEqual(self.findings()["open windows"].status, "pass")

    def test_the_hub_sealed_while_its_file_did_not_read_is_never_left_pending(self):
        from unittest import mock
        a = self.app
        a.domains["mcp-control"].start()
        a.domains["mcp-control"].tags.add(core.OPEN)
        with mock.patch.object(core, "read_hub", return_value=None):
            fleet.seal(a, "mcp-control")
        self.assertEqual(fleet.pending_kills(), ["mcp-control"])   # it may not be the hub
        lines = fleet.expire_windows(a)
        self.assertIn("mcp-control: its pending kill was dropped: it is the hub", lines)
        self.assertEqual(fleet.pending_kills(), [])
        self.assertEqual(a.domains["mcp-control"].get_power_state(), "Running")

    def test_a_settle_never_kills_a_qube_the_seal_may_not(self):
        # Its class cannot be read, so whether it is dom0 is not known: no
        # kill, on the first try or after a wait it lost.
        vm = self.app.domains[self.TPL]
        vm.start()
        fleet.open_window(self.app, self.TPL, 3600)
        real_klass = core.klass_of
        core.klass_of = lambda v: (_ for _ in ()).throw(core.Unreadable("class")) \
            if getattr(v, "name", None) == self.TPL else real_klass(v)
        self.addCleanup(setattr, core, "klass_of", real_klass)
        real, asked = core.acquire_qube_lock, []

        def acquire(name, timeout=None, **kw):
            if name == self.TPL:
                asked.append(name)
                if len(asked) == 1:
                    return None
            return real(name, timeout, **kw)
        core.acquire_qube_lock = acquire
        self.addCleanup(setattr, core, "acquire_qube_lock", real)
        msg = fleet.seal(self.app, self.TPL)
        self.assertIn("not killed", msg)
        self.assertEqual(vm.get_power_state(), "Running")

    def test_a_pending_kill_on_a_qube_that_only_stopped_says_so(self):
        vm = self.pending_after_failed_kill()
        vm.kill()
        lines = fleet.expire_windows(self.app)
        self.assertIn(f"{self.TPL}: down, after its seal's kill failed", lines)
        self.assertEqual(fleet.pending_kills(), [])

    def test_open_is_refused_while_a_kill_is_pending(self):
        vm = self.pending_after_failed_kill()
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.open_window(self.app, self.TPL, 600)
        self.assertIn("could not kill it yet", str(cm.exception))
        self.assertTrue(fleet.kill_pending(self.TPL))
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        self.assertEqual(vm.get_power_state(), "Running")

    def test_a_settle_that_kills_clears_the_pending_kill(self):
        vm = self.app.domains[self.TPL]
        vm.__dict__["_power"] = "Running"
        fleet.open_window(self.app, self.TPL, 3600)
        real, asked = core.acquire_qube_lock, []

        def acquire(name, timeout=None, **kw):
            if name == self.TPL:
                asked.append(name)
                if len(asked) == 1:
                    return None                     # a call holds it past the wait
                if len(asked) == 2:
                    vm.start()                      # ... and its start lands
            return real(name, timeout, **kw)
        core.acquire_qube_lock = acquire
        self.addCleanup(setattr, core, "acquire_qube_lock", real)
        msg = fleet.seal(self.app, self.TPL)
        self.assertIn("killed again", msg)
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertEqual(fleet.pending_kills(), [])
        # And when the seal's own kill failed, leaving a pending kill, a settle
        # that kills clears it.
        asked.clear()
        core.acquire_qube_lock = real
        fleet.open_window(self.app, self.TPL, 3600)
        vm.start()
        self.app.fail.add("kill")

        def acquire2(name, timeout=None, **kw):
            if name == self.TPL:
                asked.append(name)
                if len(asked) == 1:
                    return None
                if len(asked) == 2:
                    self.app.fail.discard("kill")   # the kill works by the settle
            return real(name, timeout, **kw)
        core.acquire_qube_lock = acquire2
        msg = fleet.seal(self.app, self.TPL)
        self.assertIn("could NOT be killed", msg)
        self.assertIn("its kill was made once the call that held its lock had finished", msg)
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertEqual(fleet.pending_kills(), [])

    def settle_after_failed_kill(self, at_settle):
        """A seal whose own kill fails and whose first lock wait is lost;
        `at_settle` runs when the lock is had again."""
        vm = self.app.domains[self.TPL]
        vm.start()
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail.add("kill")
        real, asked = core.acquire_qube_lock, []

        def acquire(name, timeout=None, **kw):
            if name == self.TPL:
                asked.append(name)
                if len(asked) == 1:
                    return None
                if len(asked) == 2:
                    at_settle(vm)
            return real(name, timeout, **kw)
        core.acquire_qube_lock = acquire
        self.addCleanup(setattr, core, "acquire_qube_lock", real)
        return vm

    def test_a_settle_whose_kill_fails_again_keeps_the_pending_kill_and_says_why(self):
        self.settle_after_failed_kill(lambda vm: None)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.seal(self.app, self.TPL)
        self.assertIn("even once the call that held its lock had finished", str(cm.exception))
        self.assertNotIn("started it again", str(cm.exception))
        self.assertEqual(fleet.pending_kills(), [self.TPL])

    def test_a_settle_that_finds_the_qube_down_says_so_and_clears_it(self):
        def down(vm):
            self.app.fail.discard("kill")
            vm.kill()
        self.settle_after_failed_kill(down)
        msg = fleet.seal(self.app, self.TPL)
        self.assertIn("it was down once the call that held its lock had finished", msg)
        self.assertEqual(fleet.pending_kills(), [])

    def test_one_failing_pending_kill_never_ends_the_pass(self):
        self.pending_after_failed_kill()
        fleet.mark_kill_pending("ai-dvm-g", vm=self.app.domains["ai-dvm-g"])
        self.app.domains["ai-dvm-g"].start()
        real = fleet._retry_kill

        def broken(app, name, dir_):
            if name == "ai-dvm-g":
                raise RuntimeError("qubesd")
            return real(app, name, dir_)
        fleet._retry_kill = broken
        try:
            lines = fleet.retry_kills(self.app)
        finally:
            fleet._retry_kill = real
        self.assertIn("ai-dvm-g: NOT killed (RuntimeError); tried again on the next pass", lines)
        self.assertEqual(self.app.domains[self.TPL].get_power_state(), "Halted")

    def test_open_badge_holders_names_what_wears_a_badge(self):
        fleet.open_window(self.app, self.TPL, 600)
        self.assertEqual(fleet.open_badge_holders(self.app), [self.TPL])
        fleet.seal(self.app, self.TPL)
        self.assertEqual(fleet.open_badge_holders(self.app), [])

    def test_a_failed_reopen_seals_the_old_window_and_kills(self):
        vm = self.app.domains[self.TPL]
        vm.__dict__["_power"] = "Running"
        fleet.open_window(self.app, self.TPL, 3600)
        self.app.fail.add(f"tag.add:{core.OPEN_FW}")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.open_window(self.app, self.TPL, 7200, firewall=True)
        self.assertIn("sealed instead", str(cm.exception))
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertEqual(fleet.pending_kills(), [])

    def test_the_boot_seal_takes_a_healthy_window_too(self):
        fleet.open_window(self.app, self.TPL, fleet.WINDOW_MAX_S, firewall=True)
        lines = fleet.expire_windows(self.app, every=True)
        self.assertTrue(any("never survives a reboot" in l for l in lines), lines)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})

    def test_a_qube_whose_tags_will_not_read_is_reported_never_skipped(self):
        self.app.fail_reads("tag.List", "fail")
        lines = fleet.expire_windows(self.app)
        self.assertTrue(any("could not be judged" in l for l in lines), lines)

    def test_check_warns_while_a_window_is_open_and_fails_when_it_is_not_sound(self):
        self.assertEqual(self.findings()["open windows"].status, "pass")
        fleet.open_window(self.app, self.TPL, 600)
        self.assertEqual(self.findings()["open windows"].status, "warn")
        (pathlib.Path(fleet.WINDOW_DIR) / self.TPL).unlink()
        f = self.findings()["open windows"]
        self.assertEqual(f.status, "fail")
        self.assertIn("no window record", f.detail)
        fleet.write_window(self.TPL, -1, False)
        self.assertEqual(self.findings()["open windows"].status, "fail")

    def test_a_window_under_a_minute_reads_in_seconds_not_zero_minutes(self):
        msg = fleet.open_window(self.app, self.TPL, 30)
        self.assertIn("(30 s)", msg)
        self.assertNotIn("0 min", msg)
        detail = self.findings()["open windows"].detail
        self.assertRegex(detail, rf"{self.TPL} \(\d+ s left\)")
        fleet.seal(self.app, self.TPL)
        self.assertIn("(10 min)", fleet.open_window(self.app, self.TPL, 600))

    def test_check_fails_on_the_firewall_half_alone(self):
        self.app.domains[self.TPL].tags.add(core.OPEN_FW)
        f = self.findings()["open windows"]
        self.assertEqual(f.status, "fail")
        self.assertIn("without", f.detail)

    def test_an_open_badge_comes_off_before_the_umbrella(self):
        # A6b does not ask for the umbrella, so a failure between the two must
        # never leave a window open on a qube that has left AI space.
        order = sorted([core.UMBRELLA, core.OPEN, core.OPEN_FW, "qmcp-lead-p01", "other"],
                       key=fleet._removal_order)
        self.assertLess(order.index(core.OPEN), order.index(core.UMBRELLA))
        self.assertLess(order.index(core.OPEN_FW), order.index(core.UMBRELLA))
        self.assertLess(order.index(core.OPEN), order.index(core.OPEN_FW))
        self.assertEqual(order[-1], "other")

    def test_the_badges_are_controlled_and_unreadable_to_a_principal(self):
        from qmcp import scope
        for badge in (core.OPEN, core.OPEN_FW):
            self.assertTrue(birth.controlled(badge))        # stripped on every create path
            self.assertNotIn(badge, scope.TAG_VOCABULARY)   # no principal reads it

    def test_open_refuses_when_the_record_directory_is_missing(self):
        shutil.rmtree(fleet.WINDOW_DIR)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.open_window(self.app, self.TPL, 600)
        self.assertIn("missing", str(cm.exception))
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW})

    def test_a_quiet_sweep_leaves_no_audit_line_and_a_real_one_leaves_one(self):
        """The gate's timer runs a sweep every 15 seconds. On the dev box every
        one of them wrote an operator audit line, which is 5,760 a day: it
        buries what the operator did and rotates the log for nothing. A sweep
        is recorded by what it sealed, not by having run."""
        from qmcp import cli
        for argv in (["seal", "--expired"], ["seal", "--all"]):
            self.assertIsNone(cli.operator_line(cli.build_parser().parse_args(argv)), argv)
        named = cli.operator_line(cli.build_parser().parse_args(["seal", self.TPL]))
        self.assertEqual(named, ("qmcp seal", {"qube": self.TPL}))
        before = len(self.audit_lines())
        self.assertEqual(fleet.expire_windows(self.app), [])        # nothing to do
        self.assertEqual(len(self.audit_lines()), before)
        fleet.open_window(self.app, self.TPL, 600)
        (pathlib.Path(fleet.WINDOW_DIR) / self.TPL).unlink()        # a badge with no record
        self.assertTrue(fleet.expire_windows(self.app))
        lines = self.audit_lines()
        self.assertEqual(len(lines), before + 1)
        self.assertEqual(lines[-1]["caller"], "operator")
        self.assertEqual(lines[-1]["service"], "qmcp seal")
        self.assertEqual(lines[-1]["args"]["qube"], self.TPL)
        self.assertIn("no window record", lines[-1]["args"]["swept"])

    def test_a_window_widens_no_dom0_wrapper(self):
        """The window is four lines of the rulebook and nothing else. Every
        dom0 service still refuses an open qube, because `core.operand` was
        never taught the badge: that is what makes "it can never change which
        network the qube is on" true, and it is asserted here rather than left
        to the fact that nobody wrote the code."""
        self.assertEqual(core.tags_of(self.app.domains[self.TPL]) & {core.OPEN}, set())
        fleet.open_window(self.app, self.TPL, 600, firewall=True)
        self.assertEqual(self.tags() & {core.OPEN, core.OPEN_FW}, {core.OPEN, core.OPEN_FW})
        for service, req in (
                ("qmcp.SetPropertyAIManaged",
                 {"name": self.TPL, "property": "netvm", "value": "ai-net-router"}),
                ("qmcp.SetFeatureAIManaged", {"name": self.TPL, "feature": "x", "value": "1"}),
                ("qmcp.LifecycleAIManaged", {"name": self.TPL, "action": "start"}),
                ("qmcp.CloneAIManagedQube", {"source": self.TPL, "name": "ai-hub-x1"}),
                ("qmcp.SpawnDisposableAIManaged", {"name": "ai-hub-x2", "dvmt": self.TPL})):
            reply = self.call(service, req)
            self.assertFalse(reply.get("ok"), (service, reply))
        # The refused write did not land: the qube's network is what it was.
        self.assertIsNone(self.app.domains[self.TPL].netvm)
        # A spawn FROM it answers exactly as it does for a managed template,
        # so the window changed nothing there either. (This base configures no
        # birth egress, so both refuse for that reason; the point is that the
        # two answers are the same.)
        guarded = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-x3", "template": self.TPL})
        managed = self.call("qmcp.SpawnAIManagedQube",
                            {"name": "ai-hub-x4", "template": "ai-debian-13"})
        self.assertEqual(guarded, managed)

    def test_revoke_takes_an_open_badge_off_too(self):
        fleet.open_window(self.app, self.TPL, 600, firewall=True)
        fleet.revoke(self.app, self.TPL)
        self.assertFalse(self.tags() & {core.OPEN, core.OPEN_FW, core.UMBRELLA, core.GUARDED})


if __name__ == "__main__":
    unittest.main()


# ======================================================================= removing what qmcp did not create

class RemovingAQubeQmcpDidNotCreate(Base):
    """The services remove only a qube wearing an owner badge (one qmcp
    created); any other leaves AI space removed only by `qmcp revoke --remove`,
    the operator's command or an accepted qube-revoke with remove."""

    REFUSED = {"ok": False,
               "error": "removing a qube qmcp did not create takes the operator's approval"}

    def life(self, name, action):
        return self.call("qmcp.LifecycleAIManaged", {"name": name, "action": action})

    def tags(self, name):
        return set(self.app.domains[name].tags.raw())

    def test_the_hub_does_not_remove_a_qube_qmcp_did_not_create(self):
        self.assertNotIn("qmcp-owner_mcp-control", self.tags("ai-work2"))
        self.assertEqual(self.life("ai-work2", "remove"), self.REFUSED)
        self.assertIn("ai-work2", self.app.domains)

    def test_any_owner_badge_lets_the_hub_remove_it(self):
        # A lead's worker, or a qube the hub created: provenance, whoever it was.
        self.app.domains["ai-work2"].tags.add("qmcp-owner_ai-osint-lead")
        self.assertEqual(self.life("ai-work2", "remove"), {"ok": True})
        self.assertNotIn("ai-work2", self.app.domains)

    def test_the_other_actions_still_work_on_it(self):
        self.assertEqual(self.life("ai-work2", "start"), {"ok": True})
        self.assertEqual(self.life("ai-work2", "kill"), {"ok": True})

    def test_the_decision_read_failing_refuses_the_remove(self):
        # The lead and owner checks rest on one strict read; when it fails,
        # nothing is removed (core.tags_of raises, never answers "no badges").
        self.app.domains["ai-work2"].tags.add("qmcp-owner_mcp-control")
        real = core.tags_of

        def failing(vm):
            if sys._getframe(1).f_code.co_name == "svc_lifecycle":
                raise core.Unreadable("injected")
            return real(vm)
        with mock.patch.object(core, "tags_of", failing):
            r = self.life("ai-work2", "remove")
        self.assertFalse(r.get("ok"), r)
        self.assertIn("ai-work2", self.app.domains)
        # The same read, answering, removes it: the failure above was the cause.
        self.assertEqual(self.life("ai-work2", "remove"), {"ok": True})

    # ------------------------------------------------ the operator's command
    def test_revoke_remove_removes_it(self):
        msg = fleet.revoke(self.app, "ai-work2", remove=True)
        self.assertTrue(msg.endswith(", removed"), msg)
        self.assertNotIn("ai-work2", self.app.domains)

    def test_revoke_remove_removes_its_lock_files(self):
        for name in ("ai-work2", "ai-work"):
            os.close(core.acquire_qube_lock(name, 1))
        files = lambda n: [p for p in (core.qube_lock_path(n),
                                       core.queue_path(core.qube_lock_path(n)))
                           if os.path.exists(p)]
        self.assertTrue(files("ai-work2"))
        fleet.revoke(self.app, "ai-work2", remove=True)
        self.assertEqual(files("ai-work2"), [])
        self.assertEqual(len(files("ai-work")), 2)       # another qube's stay

    def test_a_revoke_that_does_not_remove_keeps_the_lock_files(self):
        os.close(core.acquire_qube_lock("ai-work2", 1))
        fleet.revoke(self.app, "ai-work2")
        self.assertTrue(os.path.exists(core.qube_lock_path("ai-work2")))

    def test_revoke_remove_kills_a_running_qube_first(self):
        self.assertEqual(self.app.domains["ai-work"].get_power_state(), "Running")
        self.app.vm("ai-leaf", template=self.app.domains["ai-debian-13"], netvm=None,
                    tags={"ai-managed"}, power="Running")
        msg = fleet.revoke(self.app, "ai-leaf", remove=True)
        self.assertIn("killed", msg)
        self.assertNotIn("ai-leaf", self.app.domains)

    def refused(self, name, words, **kw):
        before = self.tags(name)
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, name, remove=True, **kw)
        self.assertIn(words, str(cm.exception))
        self.assertIn("nothing was changed", str(cm.exception))
        self.assertIn(name, self.app.domains)
        self.assertEqual(self.tags(name), before)
        return str(cm.exception)

    def test_revoke_remove_refuses_a_guarded_qube(self):
        self.refused("ai-tpl-g", "guarded")

    def test_revoke_remove_refuses_a_gateway(self):
        self.refused("ai-net-router", "guarded")

    def test_revoke_remove_refuses_a_qube_others_are_built_on(self):
        msg = self.refused("ai-debian-13", "in use by")
        self.assertIn("ai-work", msg)

    def test_revoke_remove_refuses_a_qube_another_starts_disposables_from(self):
        dvm = self.app.vm("ai-ddvm", template=self.app.domains["ai-debian-13"], netvm=None,
                          template_for_dispvms=True, tags={"ai-managed"})
        self.app.domains["ai-work2"]._props["default_dispvm"] = dvm
        self.refused("ai-ddvm", "in use by")

    def test_revoke_remove_refuses_a_qube_another_uses_as_a_service_qube(self):
        # qubesd refuses to remove a qube any qube's management disposable,
        # GUI or audio qube is: refused before the revoke, not after it.
        for prop in core.SERVICE_QUBE_PROPS:
            with self.subTest(prop=prop):
                self.app.domains["ai-work"]._props[prop] = self.app.domains["ai-work2"]
                msg = self.refused("ai-work2", "in use by")
                self.assertIn("ai-work", msg)
                self.app.domains["ai-work"]._props[prop] = None

    def test_revoke_remove_refuses_when_a_service_qube_cannot_be_read(self):
        for prop in core.SERVICE_QUBE_PROPS:
            with self.subTest(prop=prop):
                self.app.fail_reads(f"get.{prop}:ai-work", "fail")
                self.refused("ai-work2", "could not be read")

    def test_revoke_remove_refuses_a_qube_outside_ai_space(self):
        # The operator's own command too: one mistyped name is no remove.
        self.refused("personal", "not in AI space")

    def test_revoke_remove_refuses_a_qube_a_global_setting_names(self):
        for prop in ("default_dispvm", "updatevm", "management_dispvm"):
            with self.subTest(prop=prop):
                setattr(self.app, prop, self.app.domains["ai-work2"])
                msg = self.refused("ai-work2", "in use by")
                self.assertIn(f"the global {prop}", msg)
                setattr(self.app, prop, None)

    def test_revoke_remove_refuses_dom0s_default_disposable_template(self):
        dvm = self.app.vm("ai-ddvm0", template=self.app.domains["ai-debian-13"], netvm=None,
                          template_for_dispvms=True, tags={"ai-managed"})
        self.app.domains["dom0"]._props["default_dispvm"] = dvm
        msg = self.refused("ai-ddvm0", "in use by")
        self.assertIn("dom0", msg)

    def test_revoke_remove_never_leaves_it_running(self):
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, "ai-work2", shutdown=False, remove=True)
        self.assertIn("cannot be left running", str(cm.exception))
        self.assertIn("ai-managed", self.tags("ai-work2"))

    def test_revoke_remove_refuses_when_what_uses_it_cannot_be_read(self):
        self.app.fail_reads("get.template:ai-work", "fail")
        self.refused("ai-work2", "could not be read")
        self.assertGreater(sum(self.app.failed.values()), 0)

    def test_a_remove_that_fails_after_the_revoke_says_so(self):
        self.app.fail.add("remove")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, "ai-work2", remove=True)
        self.assertIn("NOT removed", str(cm.exception))
        self.assertIn("qvm-remove ai-work2", str(cm.exception))
        self.assertIn("ai-work2", self.app.domains)
        self.assertNotIn("ai-managed", self.tags("ai-work2"))     # out of AI space all the same


# ======================================================================= taking authority away

class TakingAuthorityAway(Base):
    """A revoke kills and reads the qube back; a qube's lock serialises the
    services that operate it with the commands that change its role."""

    def test_revoke_kills_a_guest_that_ignores_the_shutdown_request(self):
        vm = self.app.domains["ai-work"]
        vm.__dict__["ignores_shutdown"] = True
        vm.shutdown()
        self.assertEqual(vm.get_power_state(), "Running")       # the fake's guest ignores it
        msg = fleet.revoke(self.app, "ai-work")
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertIn("killed", msg)
        self.assertNotIn(core.UMBRELLA, self.tags("ai-work"))

    def test_revoke_kills_a_paused_qube(self):
        vm = self.app.domains["ai-work"]
        vm.pause()
        with self.assertRaises(Exception):
            vm.shutdown()                                       # a request a paused qube refuses
        fleet.revoke(self.app, "ai-work")
        self.assertEqual(vm.get_power_state(), "Halted")

    def test_a_revoke_whose_kill_fails_fails(self):
        self.app.fail.add("kill")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, "ai-work")
        self.assertIn("could NOT be killed", str(cm.exception))
        self.assertNotIn(core.UMBRELLA, self.tags("ai-work"))  # out of AI space all the same
        self.assertEqual(self.app.domains["ai-work"].get_power_state(), "Running")

    def test_a_qube_that_reads_running_after_the_kill_is_not_down(self):
        vm = self.app.domains["ai-work"]
        vm.__dict__["kill"] = lambda: None                      # returned, but nothing stopped
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, "ai-work")
        self.assertIn("still Running after the kill", str(cm.exception))

    def test_a_state_that_cannot_be_read_after_the_kill_is_not_down(self):
        # The kill returned, the qube still runs, and its state then reads NA:
        # never "killed".
        vm = self.app.domains["ai-work"]
        vm.__dict__["kill"] = lambda: None
        self.app.fail_reads("power:ai-work", "ok fail fail fail")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.revoke(self.app, "ai-work")
        self.assertIn("NA after the kill", str(cm.exception))
        self.assertEqual(vm._power, "Running")

    def test_an_open_whose_warning_cannot_be_read_still_reports_the_open(self):
        real = fleet.hidden_projects_on
        fleet.hidden_projects_on = lambda *a: (_ for _ in ()).throw(RuntimeError("list failed"))
        self.addCleanup(setattr, fleet, "hidden_projects_on", real)
        msg = fleet.open_window(self.app, "ai-tpl-g", 600)
        self.assertIn("open until", msg)
        self.assertIn(core.OPEN, self.tags("ai-tpl-g"))

    def test_revoke_no_shutdown_leaves_it_running(self):
        fleet.revoke(self.app, "ai-work", shutdown=False)
        self.assertEqual(self.app.domains["ai-work"].get_power_state(), "Running")

    def hold_lock(self, name):
        fd = core.acquire_qube_lock(name, 1)
        self.assertIsNotNone(fd)
        self.addCleanup(os.close, fd)
        return fd

    def test_a_service_refuses_while_the_qubes_lock_is_held(self):
        self.hold_lock("ai-work2")
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"})
        self.assertEqual(r, core.BUSY_REFUSAL)
        self.assertEqual(self.app.domains["ai-work2"].get_power_state(), "Halted")
        for svc, req in (("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "vcpus",
                                                        "value": 1}),
                         ("qmcp.SetFeatureAIManaged", {"name": "ai-work2", "feature": "service.x",
                                                       "value": "1"}),
                         ("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-hub-c"})):
            self.assertEqual(self.call(svc, req), core.BUSY_REFUSAL, svc)

    def test_a_name_out_of_reach_never_waits_on_a_lock(self):
        # The lock is taken only once the qube resolves: a hidden or missing
        # name answers at once, so contention tells the hub nothing.
        self.app.domains["personal"]                            # outside AI space
        self.hold_lock("personal")
        core.QUBE_WAIT_S = 5.0
        t0 = time.monotonic()
        r = self.call("qmcp.LifecycleAIManaged", {"name": "personal", "action": "start"})
        self.assertEqual(r, core.NOT_FOUND)
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_a_service_checks_again_under_the_lock(self):
        # A guard that lands while the call waits for the lock is honoured.
        real = core.acquire_qube_lock

        def guard_meanwhile(name, timeout=None, **kw):
            self.app.domains[name].tags.add(core.GUARDED)
            return real(name, timeout, **kw)
        core.acquire_qube_lock = guard_meanwhile
        self.addCleanup(setattr, core, "acquire_qube_lock", real)
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "remove"})
        self.assertEqual(r, core.GUARDED_REFUSAL)
        self.assertIn("ai-work2", self.app.domains)

    def test_a_service_checks_its_caller_again_under_the_lock(self):
        real = core.acquire_qube_lock

        def hub_file_gone(name, timeout=None, **kw):
            (self.tmp / "hub").write_text("someone-else\n")
            return real(name, timeout, **kw)
        core.acquire_qube_lock = hub_file_gone
        self.addCleanup(setattr, core, "acquire_qube_lock", real)
        r = self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"})
        self.assertEqual(r, core.NOT_AUTHORIZED)
        self.assertEqual(self.app.domains["ai-work2"].get_power_state(), "Halted")

    def test_a_command_that_takes_authority_away_goes_on_after_the_wait(self):
        self.hold_lock("ai-work")
        msg = fleet.revoke(self.app, "ai-work")
        self.assertIn("went on without it", msg)
        self.assertEqual(self.app.domains["ai-work"].get_power_state(), "Halted")
        self.assertNotIn(core.UMBRELLA, self.tags("ai-work"))

    def in_flight(self, landing):
        """The qube's lock is held by a call when the command first asks for
        it; the call's effect (`landing`) lands, and the call ends, before the
        command asks again."""
        real, asked = core.acquire_qube_lock, []

        def acquire(name, timeout=None, **kw):
            asked.append(name)
            if len(asked) == 1:
                return None                         # held past the wait
            if len(asked) == 2:
                landing()
            return real(name, timeout, **kw)
        core.acquire_qube_lock = acquire
        self.addCleanup(setattr, core, "acquire_qube_lock", real)
        return asked

    def test_a_revoke_that_went_on_unlocked_kills_a_start_that_landed_after(self):
        vm = self.app.domains["ai-work2"]
        asked = self.in_flight(vm.start)
        msg = fleet.revoke(self.app, "ai-work2")
        self.assertEqual(len(asked), 2)
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertIn("killed again", msg)
        self.assertNotIn("went on without it", msg)

    def test_a_guard_that_went_on_unlocked_says_a_remove_in_flight_won(self):
        self.in_flight(lambda: self.app.domains._drop("ai-work2"))
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.guard(self.app, "ai-work2")
        self.assertIn("removed it since", str(cm.exception))

    def test_a_seal_that_went_on_unlocked_kills_a_start_that_landed_after(self):
        fleet.open_window(self.app, "ai-tpl-g", 600)
        vm = self.app.domains["ai-tpl-g"]
        self.in_flight(vm.start)
        msg = fleet.seal(self.app, "ai-tpl-g")
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertIn("killed again", msg)
        self.assertFalse({core.OPEN, core.OPEN_FW} & self.tags("ai-tpl-g"))

    def test_a_command_that_grants_authority_refuses_after_the_wait(self):
        fleet.guard(self.app, "ai-work2")
        self.hold_lock("ai-work2")
        with self.assertRaises(fleet.RoleError) as cm:
            fleet.manage(self.app, "ai-work2")
        self.assertIn("is being changed", str(cm.exception))
        self.assertIn(core.GUARDED, self.tags("ai-work2"))
        self.hold_lock("ai-tpl-g")
        with self.assertRaises(fleet.RoleError):
            fleet.open_window(self.app, "ai-tpl-g", 600)
        self.assertNotIn(core.OPEN, self.tags("ai-tpl-g"))

    def test_the_lock_files_are_the_services_groups(self):
        old = os.umask(0o077)
        try:
            os.close(core.acquire_qube_lock("ai-work2", 1))
        finally:
            os.umask(old)
        st = os.stat(core.qube_lock_path("ai-work2"))
        self.assertEqual(st.st_mode & 0o777, 0o660)
        self.assertEqual(os.stat(os.path.dirname(core.qube_lock_path("ai-work2"))).st_mode
                         & 0o7777, 0o2770)



class Turnstile(Base):
    """A lock is taken through its turnstile: an operator's command waits in
    it, so a caller that keeps calls in flight cannot keep taking the lock
    first each time it comes free (flock is not fair)."""

    def busy_caller(self, take, stop):
        """A caller that takes the lock, holds it briefly and takes it again at
        once, until `stop` is set."""
        def run():
            while not stop.is_set():
                fd = take()
                if fd is None:
                    continue
                time.sleep(0.03)
                os.close(fd)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(stop.set)
        time.sleep(0.1)
        return t

    def test_an_operator_gets_a_qube_lock_a_busy_caller_keeps_taking(self):
        stop = threading.Event()
        self.busy_caller(lambda: core.acquire_qube_lock("ai-work2", 5), stop)
        t0 = time.monotonic()
        fd = core.acquire_qube_lock("ai-work2", 3, queue=True)
        waited = time.monotonic() - t0
        stop.set()
        self.assertIsNotNone(fd, "the operator never got the lock")
        os.close(fd)
        self.assertLess(waited, 1.0)

    def test_an_operator_command_waits_in_the_turnstile(self):
        # `core.qube_lock`, which every operator command takes, holds the
        # turnstile while it waits.
        held = core.acquire_qube_lock("ai-work2", 1)
        lock = core.qube_lock("ai-work2", must=False, timeout=1)
        waiter = threading.Thread(target=lock.__enter__, daemon=True)
        waiter.start()
        self.addCleanup(waiter.join, 5)
        time.sleep(0.2)
        q = os.open(core.queue_path(core.qube_lock_path("ai-work2")), os.O_RDWR)
        self.addCleanup(os.close, q)
        with self.assertRaises(BlockingIOError):
            fcntl.flock(q, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.close(held)
        waiter.join(5)
        self.assertIsNotNone(lock.fd)
        lock.__exit__(None, None, None)

    def test_an_operator_gets_the_create_lock_a_busy_caller_keeps_taking(self):
        def take():
            try:
                return budget.acquire_create_lock(timeout=5)
            except core.Refusal:
                return None
        stop = threading.Event()
        self.busy_caller(take, stop)
        fd = budget.acquire_create_lock(timeout=3, queue=True)
        stop.set()
        os.close(fd)

    def test_a_service_never_holds_the_turnstile_while_it_waits(self):
        # Services pass straight through: one waiting for the lock never makes
        # another, or an operator's command, wait behind it in the turnstile.
        held = core.acquire_qube_lock("ai-work2", 1)
        self.addCleanup(os.close, held)
        waiter = threading.Thread(target=lambda: core.acquire_qube_lock("ai-work2", 1),
                                  daemon=True)
        waiter.start()
        self.addCleanup(waiter.join, 5)
        time.sleep(0.2)
        q = os.open(core.queue_path(core.qube_lock_path("ai-work2")), os.O_RDWR)
        self.addCleanup(os.close, q)
        fcntl.flock(q, fcntl.LOCK_EX | fcntl.LOCK_NB)        # free: raises if it were held

    def test_a_call_arriving_behind_a_waiting_operator_waits_behind_it(self):
        held = core.acquire_qube_lock("ai-work2", 1)
        order = []

        def operator():
            fd = core.acquire_qube_lock("ai-work2", 5, queue=True)
            order.append("operator")
            time.sleep(0.1)
            os.close(fd)

        def service():
            fd = core.acquire_qube_lock("ai-work2", 5)
            order.append("service")
            os.close(fd)
        a = threading.Thread(target=operator, daemon=True)
        a.start()
        time.sleep(0.2)
        b = threading.Thread(target=service, daemon=True)
        b.start()
        time.sleep(0.2)
        os.close(held)
        a.join(5)
        b.join(5)
        self.assertEqual(order, ["operator", "service"])

    def test_the_turnstile_files_are_the_services_groups(self):
        old = os.umask(0o077)
        try:
            os.close(core.acquire_qube_lock("ai-work2", 1, queue=True))
            os.close(budget.acquire_create_lock(timeout=1, queue=True))
        finally:
            os.umask(old)
        for path in (core.queue_path(core.qube_lock_path("ai-work2")),
                     core.queue_path(str(budget.LOCK_PATH))):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o660, path)

    def test_no_qube_name_makes_a_lock_file_another_qubes_turnstile(self):
        # Every lock file ends in .lock and every turnstile in .queue.
        for name in ("x", "x.queue", "x.lock", "a.b"):
            lock = core.qube_lock_path(name)
            self.assertTrue(lock.endswith(".lock"))
            self.assertTrue(core.queue_path(lock).endswith(".queue"))
            self.assertNotEqual(core.queue_path(lock), core.qube_lock_path("x"))

class StampOrder(unittest.TestCase):
    def test_routed_badges_come_off_before_the_guard(self):
        # A disposable of a guarded disposable template with a window open on
        # it arrives wearing both: the window's badge must never be the last
        # one standing beside a removed guard.
        tags = {"ai-managed", "qmcp-guarded", "qmcp-open", "qmcp-open-fw", "qmcp-proj-p02"}
        removed = []
        io = birth.TagIO(lambda: set(tags), tags.add,
                         lambda t: (removed.append(t), tags.discard(t)))
        birth.stamp(io, set(tags), HUB, "qmcp-proj-p02")
        self.assertEqual(removed[-1], "qmcp-guarded")
        self.assertEqual(set(removed), {"qmcp-guarded", "qmcp-open", "qmcp-open-fw"})
        # Teeth: in sorted order the guard would come off first.
        self.assertEqual(sorted(removed)[0], "qmcp-guarded")


class CreatesUnderTheLock(Base):
    """A create judges its template again once it holds the create lock, sets
    its network before it joins AI space, and counts what qubesd will give it."""

    def during_the_wait(self, fn):
        real = budget.acquire_create_lock

        def wait(*a, **kw):
            fd = real(*a, **kw)
            fn()
            return fd
        budget.acquire_create_lock = wait
        self.addCleanup(setattr, budget, "acquire_create_lock", real)

    def test_a_source_taken_off_its_network_while_a_create_waited_is_refused(self):
        self.egress("ai-net-router")
        real = budget.acquire_create_lock
        for service, req, src in (
                ("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-g"}, "ai-dvm-g"),
                ("qmcp.SpawnAIManagedQube", {"name": "ai-hub-nd", "template": "ai-dvm-g",
                                             "klass": "DispVM"}, "ai-dvm-g"),
                ("qmcp.CloneAIManagedQube", {"source": "ai-work", "name": "ai-hub-cl"},
                 "ai-work")):
            with self.subTest(service):
                vm = self.app.domains[src]
                vm.netvm = self.app.domains["ai-net-router"]
                before = set(self.app.domains._vms)
                self.during_the_wait(lambda: setattr(vm, "netvm", None))
                r = self.call(service, req)
                self.assertFalse(r["ok"], r)
                self.assertIn("network changed while this call waited", r["error"])
                self.assertEqual(set(self.app.domains._vms), before)
                budget.acquire_create_lock = real

    def test_a_template_stopped_while_a_spawn_waited_is_not_built_on(self):
        self.during_the_wait(lambda: self.app.domains["ai-debian-13"].tags.add("qmcp-blocked"))
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-n", "template": "ai-debian-13",
                                                  "netvm": None})
        self.assertEqual(r, core.BLOCKED_REFUSAL)
        self.assertNotIn("ai-hub-n", self.app.domains)

    def test_a_template_revoked_while_a_spawn_waited_is_not_built_on(self):
        self.during_the_wait(lambda: self.app.domains["ai-debian-13"].tags.discard("ai-managed"))
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-n", "template": "ai-debian-13",
                                                  "netvm": None})
        self.assertFalse(r["ok"])
        self.assertNotIn("ai-hub-n", self.app.domains)

    def test_a_disposable_template_hidden_while_a_call_waited_is_not_built_on(self):
        self.during_the_wait(lambda: self.app.domains["ai-dvm-g"].tags.add("qmcp-hubblind"))
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-g"})
        self.assertFalse(r["ok"])
        self.assertFalse([v for v in self.app.domains._hidden.values()
                          if "ai-managed" in v.tags.raw()])

    def test_a_child_that_arrives_hidden_is_rolled_back(self):
        # Hidden after the last check: the platform copies the badge into the
        # child, and the stamp refuses to take it off.
        real = services._check_budget

        def then_hide(*a, **kw):
            real(*a, **kw)
            self.app.domains["ai-dvm-g"].tags.add("qmcp-hubblind")
        services._check_budget = then_hide
        self.addCleanup(setattr, services, "_check_budget", real)
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-g"})
        self.assertFalse(r["ok"])
        self.assertIn("rolled back", r["error"])

    def test_a_new_qube_has_its_network_before_it_joins_ai_space(self):
        seen = {}
        real = fakequbes.FakeTags.add

        def add(tags, tag):
            if tag == core.UMBRELLA:
                vm = tags._vm
                seen[vm.name] = (vm._props.get("netvm"), vm.property_is_default("netvm"),
                                 vm.property_is_default("default_dispvm"))
            return real(tags, tag)
        fakequbes.FakeTags.add = add
        self.addCleanup(setattr, fakequbes.FakeTags, "add", real)
        self.egress("ai-net-router")
        self.assertTrue(self.call("qmcp.SpawnAIManagedQube", {
            "name": "ai-hub-n", "template": "ai-debian-13"})["ok"])
        self.assertTrue(self.call("qmcp.CloneAIManagedQube", {
            "source": "ai-work", "name": "ai-hub-c"})["ok"])
        router = self.app.domains["ai-net-router"]
        for name in ("ai-hub-n", "ai-hub-c"):
            net, net_default, dvm_default = seen[name]
            self.assertIs(net, router, name)
            self.assertFalse(net_default, f"{name} joined AI space following the default netvm")
            self.assertFalse(dvm_default, f"{name} joined AI space following the default "
                                          f"disposable template")

    def test_a_named_disposable_is_counted_at_its_templates_private_size(self):
        dvmt = self.app.domains["ai-dvm-g"]
        dvmt.volumes["private"].size = 30 * GiB
        used = budget.persistent_sum(self.app)
        (self.tmp / "pool-cap").write_text(str(used + 3 * GiB) + "\n")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-d", "template": "ai-dvm-g",
                                                  "klass": "DispVM"})
        self.assertEqual(r["error"], budget.ERR_CAP_EXCEEDED)
        self.assertNotIn("ai-hub-d", self.app.domains)
        (self.tmp / "pool-cap").write_text(str(used + 31 * GiB) + "\n")
        r = self.call("qmcp.SpawnAIManagedQube", {"name": "ai-hub-d", "template": "ai-dvm-g",
                                                  "klass": "DispVM"})
        self.assertTrue(r["ok"], r)
        self.assertLessEqual(budget.persistent_sum(self.app), used + 31 * GiB)
