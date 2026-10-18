"""The two in-qube services in template-rpc/, run as they run in a qube: a
JSON request on stdin, one JSON reply on stdout. qvm-copy-to-vm is replaced by
a fake that records its argv.

Every negative test proves its own positive first: a command the timeout must
stop is shown to finish without it, a refused target is shown to reach the
copy when it is a name, so a green suite cannot be one that tests nothing.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

SOURCES = pathlib.Path(__file__).resolve().parent.parent / "template-rpc"
RUN = SOURCES / "qmcp.RunInAIManaged"
COPY = SOURCES / "qmcp.CopyToAIManaged"


def _load(path: pathlib.Path):
    # No .py extension, so the default spec finder cannot load it.
    loader = importlib.machinery.SourceFileLoader(path.name.replace(".", "_"), str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RunTests(unittest.TestCase):

    def setUp(self) -> None:
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.dir)]))
        self.marker = self.dir / "marker"

    def run_service(self, request: dict) -> dict:
        proc = subprocess.run([sys.executable, str(RUN)], input=json.dumps(request).encode(),
                              capture_output=True, timeout=60,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        return json.loads(proc.stdout)

    def late_touch(self, timeout) -> dict:
        # A background child of the shell, in the shell's process group: a
        # kill of the shell's pid alone leaves it to finish.
        return self.run_service({"cmd": f"(sleep 2; touch {self.marker}) & wait",
                                 "shell": True, "timeout": timeout})

    def test_a_command_runs(self):
        reply = self.run_service({"cmd": ["sh", "-c", "cat; echo err >&2; exit 3"],
                                  "stdin": "in"})
        self.assertEqual(reply, {"ok": True, "rc": 3, "stdout": "in", "stderr": "err\n"})

    def test_the_timeout_stops_the_command_and_its_children(self):
        self.assertTrue(self.late_touch(10)["ok"])
        self.assertTrue(self.marker.exists())                      # the positive
        self.marker.unlink()
        reply = self.late_touch(1)
        self.assertEqual(reply, {"ok": False, "error": "timeout after 1s; the command and its "
                                                       "process group were killed"})
        time.sleep(3)
        self.assertFalse(self.marker.exists())

    def test_a_child_that_left_the_group_never_holds_the_reply(self):
        # setsid takes it out of the process group the kill reaches; holding
        # the inherited pipe, it must not keep the service from answering.
        start = time.monotonic()
        reply = self.run_service({"cmd": "setsid sleep 30 & sleep 30", "shell": True,
                                  "timeout": 1})
        self.assertFalse(reply["ok"])
        self.assertLess(time.monotonic() - start, 15)

    def test_a_timeout_out_of_range_starts_nothing(self):
        touch = ["touch", str(self.marker)]
        self.assertTrue(self.run_service({"cmd": touch, "timeout": 1})["ok"])
        self.assertTrue(self.marker.exists())                      # the positive
        self.marker.unlink()
        for bad in (0, -1, 86401, True, 1.5, None, "5"):
            with self.subTest(timeout=bad):
                reply = self.run_service({"cmd": touch, "timeout": bad})
                self.assertEqual(reply, {"ok": False, "error": "'timeout' must be a whole "
                                                               "number of seconds, 1 to 86400"})
                self.assertFalse(self.marker.exists())


class CopyTests(unittest.TestCase):

    def setUp(self) -> None:
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.dir)]))
        self.log = self.dir / "argv"
        self.fake = self.dir / "qvm-copy-to-vm"
        self.sleep = 0
        self.module = _load(COPY)
        self.source = self.dir / "out.txt"
        self.source.write_text("x")

    def write_fake(self) -> None:
        self.fake.write_text("#!/bin/sh\n"
                             f"printf '%s\\n' \"$@\" > {self.log}\n"
                             f"sleep {self.sleep}\n")
        self.fake.chmod(0o755)

    def copy(self, request: dict) -> dict:
        self.write_fake()
        out = io.StringIO()
        with mock.patch.object(self.module, "QVM_COPY", str(self.fake)), \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps(request))), \
                redirect_stdout(out):
            self.module.main()
        return json.loads(out.getvalue())

    def argv(self) -> list[str] | None:
        return self.log.read_text().splitlines() if self.log.exists() else None

    def test_a_copy_names_its_target_after_the_end_of_options(self):
        reply = self.copy({"target": "ai-b", "path": str(self.source)})
        self.assertEqual(reply, {"ok": True, "target": "ai-b", "path": str(self.source)})
        self.assertEqual(self.argv(), ["--", "ai-b", str(self.source)])

    def test_a_target_that_is_not_a_name_never_reaches_the_copy(self):
        self.assertTrue(self.copy({"target": "ai-b", "path": str(self.source)})["ok"])
        self.log.unlink()                                          # the positive
        for bad in ("-h", "--help", "dom0", "DOM0", "@default", "a b", "a" * 32, ""):
            with self.subTest(target=bad):
                reply = self.copy({"target": bad, "path": str(self.source)})
                self.assertFalse(reply["ok"])
                self.assertIsNone(self.argv())

    def test_a_relative_path_is_refused(self):
        os.chdir(self.dir)
        self.addCleanup(os.chdir, "/")
        reply = self.copy({"target": "ai-b", "path": "out.txt"})
        self.assertEqual(reply, {"ok": False, "error": "'path' must be absolute"})
        self.assertIsNone(self.argv())

    def test_the_callers_timeout_stops_the_copy(self):
        self.sleep = 3
        start = time.monotonic()
        reply = self.copy({"target": "ai-b", "path": str(self.source), "timeout": 1})
        self.assertEqual(reply, {"ok": False, "error": "copy timed out after 1s; it was stopped"})
        self.assertLess(time.monotonic() - start, 2.5)

    def test_a_timeout_out_of_range_is_refused(self):
        for bad in (0, -1, 86401, True, 1.5, None):
            with self.subTest(timeout=bad):
                reply = self.copy({"target": "ai-b", "path": str(self.source), "timeout": bad})
                self.assertFalse(reply["ok"])
                self.assertIn("1 to 86400", reply["error"])
                self.assertIsNone(self.argv())


if __name__ == "__main__":
    unittest.main()
