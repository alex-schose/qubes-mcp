#!/usr/bin/env python3
"""Project suite: run tests/lead_seat.py inside a project's lead, from the hub.

Run it IN THE HUB, from the public tree:

    PYTHONPATH=. python3 tests/project_suite.py --lead LEAD -- [lead_seat.py arguments]

The hub's exec reaches every managed qube, leads included, so the hub carries
the client and the lead seat into the lead, starts the seat there detached (a
dropped connection cannot lose its result), waits for it, prints its report
and exits with its status: 0 GREEN, 2 FAILED, 3 INCOMPLETE. Everything the
seat proves, it proves as the lead; the hub only delivers it.
"""
from __future__ import annotations

import base64
import io
import os
import shlex
import sys
import tarfile
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from qubes_mcp import tools  # noqa: E402

SEAT_DIR = "/root/qmcp-lead-seat"
WAIT_S = 2400


def call(tool, **args):
    t = tools.TOOLS[tool]
    return t.handler(tools.validate_arguments(t, args))


def run(lead, cmd, stdin="", timeout=60):
    return call("qubes_run", name=lead, cmd=cmd, shell=True, stdin=stdin, timeout=timeout)


def bundle() -> str:
    buf = io.BytesIO()
    skip = lambda ti: None if "__pycache__" in ti.name else ti  # noqa: E731
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(os.path.join(ROOT, "qubes_mcp"), arcname="qubes_mcp", filter=skip)
        tar.add(os.path.join(ROOT, "tests", "lead_seat.py"), arcname="tests/lead_seat.py")
    return base64.b64encode(buf.getvalue()).decode()


def main() -> int:
    argv = sys.argv[1:]
    if "--lead" not in argv:
        print(__doc__)
        return 2
    lead = argv[argv.index("--lead") + 1]
    seat_args = argv[argv.index("--") + 1:] if "--" in argv else []
    call("qubes_start", name=lead)
    r = run(lead, f"rm -rf {SEAT_DIR} && mkdir -p {SEAT_DIR} && base64 -d | tar -xz -C {SEAT_DIR} "
                  f"&& echo shipped", stdin=bundle(), timeout=120)
    if not (r.get("ok") and "shipped" in r.get("stdout", "")):
        print(f"FAIL    could not ship the lead seat into {lead}: {r}")
        return 2
    args = " ".join(shlex.quote(a) for a in seat_args)
    r = run(lead, f"cd {SEAT_DIR} && rm -f /tmp/lead_seat.rc /tmp/lead_seat.out && "
                  f"(PYTHONPATH=. setsid nohup python3 tests/lead_seat.py {args} > /tmp/lead_seat.out 2>&1; "
                  f"echo $? > /tmp/lead_seat.rc) > /dev/null 2>&1 & echo started")
    if not (r.get("ok") and "started" in r.get("stdout", "")):
        print(f"FAIL    could not start the lead seat in {lead}: {r}")
        return 2
    deadline = time.monotonic() + WAIT_S
    rc = None
    while time.monotonic() < deadline:
        time.sleep(10)
        r = run(lead, "cat /tmp/lead_seat.rc 2>/dev/null || true", timeout=30)
        text = r.get("stdout", "").strip() if r.get("ok") else ""
        if text.isdigit():
            rc = int(text)
            break
    out = run(lead, "cat /tmp/lead_seat.out 2>/dev/null", timeout=60)
    print(out.get("stdout", out.get("error", "")), end="")
    if rc is None:
        print(f"\nproject suite: INCOMPLETE  (the lead seat did not finish within {WAIT_S}s)")
        return 3
    return rc


if __name__ == "__main__":
    sys.exit(main())
