"""The installer runs python3 as root from the operator's cwd: `-c`, `-` and
`-m` put that cwd first on sys.path, ahead of PYTHONPATH, so a `qmcp/` there
would replace the release's code. PYTHONSAFEPATH, exported before the first
python3 and checked in the preflight, keeps it out."""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
INSTALL = (HERE.parent / "deploy" / "install.sh").read_text()
EXPORT = "export PYTHONSAFEPATH=1 PYTHONNOUSERSITE=1"
GUARD = ("python3 -c 'import sys; sys.exit(0 if sys.flags.safe_path and "
         "sys.flags.no_user_site else 1)'")


def _run(cmd: list, cwd: str, safe: bool) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONSAFEPATH"}
    env["PYTHONPATH"] = str(HERE.parent / "dom0")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if safe:
        env["PYTHONSAFEPATH"] = "1"
        env["PYTHONNOUSERSITE"] = "1"
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=60)


class SafePath(unittest.TestCase):
    def setUp(self):
        self.cwd = tempfile.mkdtemp(prefix="qmcp-safepath-")
        self.addCleanup(shutil.rmtree, self.cwd, True)
        # A planted package of the release's name in the operator's cwd.
        os.mkdir(os.path.join(self.cwd, "qmcp"))
        pathlib.Path(self.cwd, "qmcp", "__init__.py").write_text("PLANTED = True\n")

    def _which(self, form: str, safe: bool) -> str:
        probe = "import qmcp; print(getattr(qmcp, 'PLANTED', False))"
        if form == "-c":
            cmd = [sys.executable, "-c", probe]
            r = _run(cmd, self.cwd, safe)
        else:
            r = subprocess.run([sys.executable, "-"], input=probe, cwd=self.cwd,
                               env={**{k: v for k, v in os.environ.items()
                                       if k != "PYTHONSAFEPATH"},
                                    "PYTHONPATH": str(HERE.parent / "dom0"),
                                    "PYTHONDONTWRITEBYTECODE": "1",
                                    **({"PYTHONSAFEPATH": "1"} if safe else {})},
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_the_cwd_shadows_the_release_without_it(self):
        # The positive control: the hole is real on this python.
        for form in ("-c", "-"):
            with self.subTest(form=form):
                self.assertEqual(self._which(form, safe=False), "True")

    def test_the_release_is_imported_with_it(self):
        for form in ("-c", "-"):
            with self.subTest(form=form):
                self.assertEqual(self._which(form, safe=True), "False")

    def test_the_export_comes_before_every_python3(self):
        lines = INSTALL.splitlines()
        at = [i for i, line in enumerate(lines) if line.strip() == EXPORT]
        self.assertEqual(len(at), 1)
        set_e = next(i for i, line in enumerate(lines) if line.startswith("set -euo pipefail"))
        self.assertLess(set_e, at[0])
        for i, line in enumerate(lines[:at[0]]):
            code = line.split("#", 1)[0]
            self.assertNotRegex(code, r"\bpython3\b", f"line {i + 1} runs python3 before the export")

    def test_no_python3_drops_the_environment(self):
        for i, line in enumerate(INSTALL.splitlines(), 1):
            code = line.split("#", 1)[0]
            if not re.search(r"\bpython3\b", code):
                continue
            if code.lstrip().startswith("echo "):
                # Advice printed for the operator, who runs it under sudo,
                # which drops the variable: it carries -P instead.
                self.assertIn("python3 -P ", code, f"line {i}")
                continue
            self.assertNotRegex(code, r"env -i|sudo |runuser ", f"line {i}")

    def test_the_callers_python_environment_is_cleared_before_any_python3(self):
        lines = INSTALL.splitlines()
        export = lines.index(EXPORT)
        unset = next(i for i, l in enumerate(lines) if l.startswith("unset PYTHONPATH "))
        self.assertEqual(unset, export + 1)
        for var in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE"):
            self.assertIn(var, lines[unset].split())

    def test_the_m_form_is_covered_too(self):
        # `python3 -m compileall` would import a planted compileall.py.
        pathlib.Path(self.cwd, "compileall.py").write_text("raise SystemExit('PLANTED')\n")
        r = _run([sys.executable, "-m", "compileall", "-q", "-l", self.cwd], self.cwd, safe=True)
        self.assertNotIn("PLANTED", r.stderr + r.stdout)
        r = _run([sys.executable, "-m", "compileall", "-q", "-l", self.cwd], self.cwd, safe=False)
        self.assertIn("PLANTED", r.stderr + r.stdout)          # the control

    def test_the_preflight_refuses_a_python_that_ignores_it(self):
        self.assertIn(GUARD, INSTALL)
        guard = GUARD.replace("python3", sys.executable, 1)
        self.assertEqual(_run(["sh", "-c", guard], self.cwd, safe=True).returncode, 0)
        self.assertEqual(_run(["sh", "-c", guard], self.cwd, safe=False).returncode, 1)
        # The guard sits in the preflight, before anything is changed.
        self.assertLess(INSTALL.index(GUARD), INSTALL.index("# ===================================================================== install"))


if __name__ == "__main__":
    unittest.main()
