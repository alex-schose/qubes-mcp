"""Root in the directories the services' group may write (1.0.3).

/run/qmcp's subdirectories, the proposal store and the RAM chains are 2770:
code running as the services' user can put a link, a dangling link or a FIFO
at any name in them. Every file root opens there opens no link, never blocks
on a FIFO and is refused unless it is a plain file; what it writes goes to
the file, never through a name. Each test plants all three at the one name a
function opens, and runs the real function under a watchdog, so a FIFO that
would block fails the test instead of hanging it."""
from __future__ import annotations

import os
import pathlib
import sys
import threading
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import anon, audit, core, opfiles, projects, proposals  # noqa: E402
from test_dom0 import Base  # noqa: E402


def within(seconds, fn, *a, **kw):
    """fn's result, or AssertionError when it is still running after `seconds`."""
    box = {}

    def run():
        try:
            box["value"] = fn(*a, **kw)
        except BaseException as e:      # noqa: BLE001 — reported to the caller
            box["error"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise AssertionError(f"{getattr(fn, '__name__', fn)} blocked")
    if "error" in box:
        raise box["error"]
    return box.get("value")


class Planted(Base):
    def setUp(self):
        super().setUp()
        self.victim = self.tmp / "victim"
        self.victim.write_text("precious")
        os.chmod(self.victim, 0o640)

    def plants(self, path):
        """Yield, for each planted kind, after putting it at `path`."""
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        for kind in ("link", "dangling", "fifo"):
            if path.is_symlink() or path.exists():
                path.unlink()
            if kind == "link":
                os.symlink(self.victim, path)
            elif kind == "dangling":
                os.symlink(self.tmp / "made-through-a-link", path)
            else:
                os.mkfifo(path)
            yield kind
        if path.is_symlink() or path.exists():
            path.unlink()

    def untouched(self, kind):
        self.assertEqual(self.victim.read_text(), "precious", kind)
        self.assertEqual(self.victim.stat().st_mode & 0o7777, 0o640, kind)
        self.assertFalse((self.tmp / "made-through-a-link").exists(), kind)

    # ------------------------------------------------------------ the audit
    def test_the_dropped_counter(self):
        for kind in self.plants(audit.DROPPED_PATH):
            within(5, audit._note_dropped)          # best-effort: never raises
            self.untouched(kind)
            self.assertIn(within(5, audit.dropped), ((None, None), None), kind)

    def test_a_callers_counter(self):
        calls = os.path.join(core.RUN_DIR, "calls")
        for kind in self.plants(os.path.join(calls, "ai-x" + audit.REFUSED_SUFFIX)):
            within(5, audit.counters, calls)
            self.untouched(kind)

    def test_a_ram_chain_and_its_pad(self):
        audit._ram_dir_ready()
        for kind in self.plants(audit.ram_path() + audit.PAD_SUFFIX):
            with mock.patch.object(audit, "install_mode", return_value=("ram", None)):
                within(5, audit._pay_like, "ram")
            self.untouched(kind)
        chain = audit.ram_path("p09")
        for kind in self.plants(chain):
            ok, _, _ = within(5, audit.verify, chain)
            self.untouched(kind)
            self.assertFalse(ok, kind)                   # a link or FIFO is no chain
            with self.assertRaises(OSError):
                within(5, audit.tail, 5, chain)

    def test_an_append_to_a_ram_chain(self):
        # Root appends every operator line that goes to RAM: a link or FIFO at
        # the chain is no chain, and the line is counted as not written. (1.0.2
        # was safe here already, read-write never blocks and the seek failed;
        # this keeps it so.)
        audit._ram_dir_ready()
        chain = audit.ram_path("p08")
        for kind in self.plants(chain):
            within(5, audit.audit, "qmcp settings set", "operator", {}, True, path=chain)
            self.untouched(kind)

    def test_a_rotation_chmods_the_file_it_holds_never_a_name(self):
        # The aside is the inode the rotation holds: a link put at its name
        # between the link and the chmod must not have the victim's mode changed.
        path = audit.ram_path()
        audit._ram_dir_ready()
        audit.audit("qmcp settings set", "operator", {}, True, path=path)
        real_link = os.link

        def link_then_swap(src, dst, *a, **kw):
            real_link(src, dst, *a, **kw)
            os.unlink(dst)
            os.symlink(self.victim, dst)
        with mock.patch.object(audit.os, "link", link_then_swap):
            try:
                audit.rotate(path)
            except OSError:
                pass
        self.untouched("swapped aside")

    # ------------------------------------------------------------ the locks
    def test_the_gates_lock_and_heartbeat(self):
        for kind in self.plants(anon.LOCK_PATH):
            try:
                with within(5, anon._GateLock, anon.LOCK_PATH, 0.1) as got:
                    pass
            except OSError:
                pass                                 # refused: no run, no stop missed
            self.untouched(kind)
        for kind in self.plants(anon.HEARTBEAT_PATH):
            within(5, anon._beat)
            self.untouched(kind)

    def test_the_records_and_proposals_locks(self):
        for path, enter in ((projects.LOCK_PATH, lambda: projects.Locked(timeout=0.1)),
                            (proposals.LOCK_PATH, lambda: proposals._Locked(0.1))):
            for kind in self.plants(path):
                lock = enter()
                try:
                    within(5, lock.__enter__)
                    lock.__exit__(None, None, None)
                except Exception:                    # refused
                    pass
                self.untouched(kind)

    # ------------------------------------------------------------ the store
    def test_a_proposal_file_and_its_claim(self):
        store = pathlib.Path(proposals.PROPOSALS_DIR)
        store.mkdir(parents=True, exist_ok=True)
        for kind in self.plants(store / "000001.json"):
            self.assertRaises(OSError, within, 5, proposals._read_bytes,
                              str(store / "000001.json"))
            self.untouched(kind)
        for kind in self.plants(store / "000001.accepting"):
            entry = proposals.Entry(1)
            within(5, proposals._probe_claim, entry, str(store / "000001.accepting"),
                   str(store / "000001.decision"))
            self.untouched(kind)

    def test_verify_streams_and_refuses_a_line_no_record_is(self):
        audit.audit("qmcp settings set", "operator", {}, True)
        with open(audit.LOG_PATH, "ab") as f:
            f.write(b"x" * (audit.VERIFY_MAX_LINE + 10))
        ok, n, why = within(5, audit.verify)
        self.assertEqual((ok, n), (False, 2))
        self.assertIn("too long to be a record", why)

    # ------------------------------------------------------------ the export
    def test_the_export_chowns_the_file_it_wrote_never_a_name(self):
        calls = []
        with mock.patch.object(opfiles.os, "geteuid", return_value=0), \
                mock.patch.object(opfiles.os, "chown", lambda *a, **kw: calls.append("chown")), \
                mock.patch.object(opfiles.os, "fchown",
                                  lambda *a, **kw: calls.append("fchown")):
            out = opfiles.export("1.0.3", path=str(self.tmp / "export.json"),
                                 user=os.environ.get("USER") or "root")
        self.assertTrue(os.path.exists(out))
        self.assertNotIn("chown", calls)


if __name__ == "__main__":
    unittest.main()
