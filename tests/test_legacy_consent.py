"""What v0.9.16 left outside the paths 0.9.17 removes: its consent daemon, a
systemd --user unit in the operator's home that kept running and listening in
/run/qmcp, and the rotated audit logs no retention of this release removes."""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, fleet  # noqa: E402
from test_audit_modes import ModeBase  # noqa: E402

INSTALL = (HERE.parent / "deploy" / "install.sh").read_text()


def tmpdir(test) -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-legacy-"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


class Users(unittest.TestCase):
    def test_every_qubes_member_and_uid_1000_once_never_root(self):
        import grp
        import pwd
        homes = {"user2": "/srv/user2", "user": "/home/user", "root": "/root"}
        gr = mock.Mock(gr_mem=["root", "user", "user2"])
        with mock.patch.object(grp, "getgrnam", return_value=gr), \
                mock.patch.object(pwd, "getpwuid", return_value=mock.Mock(pw_name="user")), \
                mock.patch.object(pwd, "getpwnam",
                                  side_effect=lambda n: mock.Mock(pw_dir=homes[n])):
            self.assertEqual(fleet.legacy_users(),
                             [("user", "/home/user"), ("user2", "/srv/user2")])

    def test_a_home_that_is_not_absolute_is_skipped(self):
        import grp
        import pwd
        homes = {"a": "", "b": "relative/home", "c": "/", "d": "//", "e": "/srv/e",
                 "f": "/srv/f\tx", "g": "/srv/g\nh"}
        with mock.patch.object(grp, "getgrnam", return_value=mock.Mock(gr_mem=list(homes))), \
                mock.patch.object(pwd, "getpwuid", side_effect=KeyError), \
                mock.patch.object(pwd, "getpwnam",
                                  side_effect=lambda n: mock.Mock(pw_dir=homes[n])):
            self.assertEqual(fleet.legacy_users(), [("e", "/srv/e")])

    def test_no_qubes_group_and_no_uid_1000_is_nobody(self):
        import grp
        import pwd
        with mock.patch.object(grp, "getgrnam", side_effect=KeyError), \
                mock.patch.object(pwd, "getpwuid", side_effect=KeyError):
            self.assertEqual(fleet.legacy_users(), [])

    def test_the_unit_its_wants_link_and_the_socket(self):
        unit = "/home/user/.config/systemd/user/qmcp-consent.service"
        self.assertEqual(fleet.legacy_user_paths([("user", "/home/user")]), [
            unit, "/home/user/.config/systemd/user/graphical-session.target.wants/"
                  "qmcp-consent.service", "/run/qmcp/consent.sock"])

    def test_the_names_are_v0_9_16s(self):
        # Pinned to what the v0.9.16 unit and installer wrote.
        self.assertEqual(fleet.LEGACY_USER_UNIT, "qmcp-consent.service")
        self.assertEqual(fleet.LEGACY_DAEMON, "qmcp-consentd")
        self.assertEqual(fleet.LEGACY_SOCKET, "/run/qmcp/consent.sock")


class Daemons(unittest.TestCase):
    def proc(self, cmdlines):
        root = tmpdir(self)
        for pid, argv in cmdlines.items():
            (root / str(pid)).mkdir()
            if argv is not None:
                (root / str(pid) / "cmdline").write_bytes(b"\0".join(argv) + b"\0")
        (root / "self").mkdir()
        return str(root)

    def test_the_daemon_as_its_unit_ran_it_and_nothing_else(self):
        root = self.proc({
            12: [b"python3", b"/usr/local/lib/qmcp/qmcp-consentd"],        # env python3
            7: [b"/usr/bin/python3.13", b"/usr/local/lib/qmcp/qmcp-consentd"],
            30: [b"/usr/local/lib/qmcp/qmcp-consentd"],
            40: [b"less", b"/usr/local/lib/qmcp/qmcp-consentd"],          # a pager on it
            41: [b"vim", b"qmcp-consentd"],
            42: [b"python3", b"-m", b"qmcp-consentd"],
            50: None,                                                    # gone mid-read
        })
        self.assertEqual(fleet.legacy_daemons(root), [7, 12, 30])

    def test_a_proc_that_does_not_list_is_not_none_found(self):
        with self.assertRaises(OSError):
            fleet.legacy_daemons("/nonexistent-proc")


class Check(ModeBase):
    def item(self, **kw):
        found = [f for f in fleet.check(self.app, system_info={"domains": {}}, **kw)
                 if f.check == "v0.9.16 leftovers"]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_a_unit_in_a_home_fails_the_check(self):
        d = tmpdir(self)
        unit = d / "qmcp-consent.service"
        self.assertEqual(self.item(legacy_paths=[str(unit)], legacy_procs=list).status, "pass")
        unit.write_text("[Unit]\n")
        f = self.item(legacy_paths=[str(unit)], legacy_procs=list)
        self.assertEqual(f.status, "fail")
        self.assertIn(str(unit), f.detail)

    def test_a_dangling_wants_link_counts(self):
        link = tmpdir(self) / "qmcp-consent.service"
        link.symlink_to("/nonexistent/qmcp-consent.service")
        self.assertEqual(self.item(legacy_paths=[str(link)], legacy_procs=list).status, "fail")

    def test_a_daemon_still_running_fails_with_its_pid(self):
        f = self.item(legacy_paths=[], legacy_procs=lambda: [4711])
        self.assertEqual(f.status, "fail")
        self.assertIn("pid 4711", f.detail)
        self.assertIn("sudo kill 4711", f.detail)

    def test_a_process_list_that_does_not_read_is_an_error(self):
        def gone():
            raise PermissionError
        f = self.item(legacy_paths=[], legacy_procs=gone)
        self.assertEqual(f.status, "error")
        self.assertIn("the process list", f.detail)

    @unittest.skipIf(os.geteuid() == 0, "root reads every home")
    def test_a_home_that_does_not_read_is_not_none(self):
        home = tmpdir(self) / "other"
        (home / ".config").mkdir(parents=True)
        home.chmod(0)
        self.addCleanup(home.chmod, 0o700)
        # Another user's private home is a note, never a warning on every run
        # nor INCOMPLETE: the process scan still finds a daemon that runs.
        f = self.item(legacy_paths=[str(home / ".config" / "x")], legacy_procs=list)
        self.assertEqual(f.status, "pass")
        self.assertIn("not looked at as this user", f.detail)
        self.assertIn("sudo qmcp check looks", f.detail)
        f = self.item(legacy_paths=[str(home / ".config" / "x")], legacy_procs=lambda: [9])
        self.assertEqual(f.status, "fail")

    def test_by_default_it_looks_in_the_homes_and_for_the_socket(self):
        seen = []
        with mock.patch.object(fleet, "legacy_user_paths", lambda: seen.append(1) or ["/x"]), \
                mock.patch.object(fleet, "legacy_daemons", lambda: []):
            fleet.check(self.app, system_info={"domains": {}})
        self.assertEqual(seen, [1])


class Unpruned(ModeBase):
    def test_only_names_no_retention_removes(self):
        d = os.path.dirname(audit.LOG_PATH)
        base = audit.LOG_PATH
        for suffix in (".20260901T000000Z", audit.ROTATING_SUFFIX, audit.PAD_SUFFIX, ".1",
                       ".2.gz", ".old"):
            pathlib.Path(base + suffix).write_text("x\n")
        pathlib.Path(os.path.join(d, "unrelated.log.1")).write_text("x\n")
        name = os.path.basename(base)
        self.assertEqual(audit.unpruned(), [name + ".1", name + ".2.gz", name + ".old"])

    def test_the_check_warns_and_retention_leaves_them(self):
        pathlib.Path(audit.LOG_PATH + ".1").write_text("x\n")
        found = [f for f in fleet.check(self.app, system_info={"domains": {}})
                 if f.check == "audit retention" and "not named" in f.detail]
        self.assertEqual(len(found), 1, found)
        self.assertIn(os.path.basename(audit.LOG_PATH) + ".1", found[0].detail)
        self.assertIn("remove it by hand", found[0].detail)
        self.assertNotIn(os.path.basename(audit.LOG_PATH) + ".1",
                         [n for n, _ in audit.rotated()])

    def test_none_is_no_item(self):
        self.assertEqual([f for f in fleet.check(self.app, system_info={"domains": {}})
                          if f.check == "audit retention" and "not named" in f.detail], [])

    def test_a_log_directory_that_does_not_list_is_an_error(self):
        with mock.patch.object(audit, "unpruned", side_effect=PermissionError):
            found = [f for f in fleet.check(self.app, system_info={"domains": {}})
                     if f.check == "audit retention" and f.status == "error"]
        self.assertEqual(len(found), 1, found)
        self.assertIn("does not list", found[0].detail)

    def test_a_long_list_is_cut(self):
        for i in range(8):
            pathlib.Path(f"{audit.LOG_PATH}.{i}").write_text("x\n")
        found = [f.detail for f in fleet.check(self.app, system_info={"domains": {}})
                 if f.check == "audit retention" and "not named" in f.detail]
        self.assertIn("and 3 more", found[0])


class Install(unittest.TestCase):
    """The installer stops the daemon before it removes the files, and removes
    what `qmcp check` looks for."""

    def test_the_stop_comes_before_the_removal(self):
        stop = INSTALL.index("as_user disable --now qmcp-consent.service")
        program = INSTALL.index("rm -f /usr/local/lib/qmcp/qmcp-consentd")
        kill = INSTALL.index("fleet.legacy_daemons()")
        self.assertLess(stop, program)
        self.assertLess(program, kill)
        removal = INSTALL.index('removed v0.9.16 file $path')
        self.assertLess(stop, kill)
        self.assertLess(kill, removal)

    def test_it_removes_the_files_check_looks_for(self):
        # check looks at LEGACY_PATHS + legacy_user_paths(), which is the home
        # paths of legacy_users() and the socket; the installer removes the
        # first and the socket as root, the home paths as each home's owner.
        start = INSTALL.index('LEGACY="$(')
        line = INSTALL[start:INSTALL.index('while IFS= read -r path', start)]
        self.assertIn("fleet.LEGACY_PATHS + (fleet.LEGACY_SOCKET,)", line)
        homes = INSTALL[INSTALL.index("# Its unit and wants link sit in a home"):start]
        self.assertIn('sudo -u "$user" rm -f -- "$path"', homes)
        self.assertIn('paths="$(home_paths "$home")" || die', homes)
        self.assertIn("fleet.legacy_home_paths(sys.argv[1])", INSTALL)
        self.assertEqual(fleet.legacy_user_paths([("u", "/srv/u")]),
                         fleet.legacy_home_paths("/srv/u") + [fleet.LEGACY_SOCKET])

    def test_the_seed_decision_never_counts_a_users_file(self):
        # A file in a home, or in the qubes-writable /run/qmcp, must not make a
        # fresh install look like an upgrade from v0.9.16 (that seeds labels).
        head = INSTALL[:INSTALL.index("SEED_LABELS=0")]
        legacy_left = head[head.index("LEGACY_LEFT="):]
        self.assertIn("fleet.LEGACY_PATHS))", legacy_left)
        self.assertNotIn("legacy_user_paths", legacy_left)
        self.assertNotIn("LEGACY_SOCKET", legacy_left)
        self.assertFalse(any(p.startswith("/run/") or p.startswith("/home/")
                             for p in fleet.LEGACY_PATHS))

    def test_the_kill_step_ends_a_daemon_running_from_a_deleted_file(self):
        self.run_kill_step(ignore_term=False)

    def test_a_daemon_that_ignores_sigterm_is_killed(self):
        self.run_kill_step(ignore_term=True)

    def run_kill_step(self, ignore_term):
        d = tmpdir(self)
        daemon = d / "qmcp-consentd"
        ready = d / "ready"
        trap = "import signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n" if ignore_term else ""
        daemon.write_text(f"#!/usr/bin/env python3\nimport time\n{trap}open({str(ready)!r}, 'w')\n"
                          f"time.sleep(60)\n")
        daemon.chmod(0o755)
        proc = subprocess.Popen([str(daemon)])
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        for _ in range(100):        # running the file, not just named by its cmdline
            if ready.exists():
                break
            subprocess.run(["sleep", "0.1"], check=True)
        self.assertIn(proc.pid, fleet.legacy_daemons())
        daemon.unlink()
        start = INSTALL.index("legacy_daemons() {")
        block = INSTALL[start:INSTALL.index("# Its unit and wants link sit in a home", start)]
        script = (f'set -euo pipefail\nSRC="{HERE.parent}"\nsay() {{ echo "==> $*"; }}\n'
                  f'die() {{ echo "die: $*"; exit 1; }}\n{block}')
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("ended the v0.9.16 consent daemon", out.stdout)
        self.assertEqual(proc.wait(timeout=10), -9 if ignore_term else -15)
        self.assertNotIn(proc.pid, fleet.legacy_daemons())


if __name__ == "__main__":
    unittest.main()
