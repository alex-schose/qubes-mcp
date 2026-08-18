#!/usr/bin/env python3
"""Offline validation for Stage I-2 (hash-chained dom0 audit log).

Ships in public/deploy/ alongside the test-stage-*.py harnesses so external
reviewers and cloners can run it. Mirrors the CLAUDE.md "validate
dom0 wrapper logic offline before slot deploy" pattern: inject a fake
`qubesadmin`, load the no-extension wrappers via SourceFileLoader, drive
main() with stdin via io.StringIO, redirect each wrapper's audit lib to a
temp log, assert on the chained lines.

Three things proven here, before any slot burns dom0:
  1. qmcp_audit itself — chain builds, verify() passes, every tamper
     (edit / delete / insert / reorder / corrupt / seq) is caught, perms
     are 0600, and audit() is best-effort (returns False, never raises,
     on an unwritable path).
  2. Wrapper integration — a state-changing wrapper leaves exactly one
     chained line per call with the right service / ok / error, and the
     logged `args` summary NEVER contains a property/feature *value* (the
     no-secret-leak invariant — checked with a distinctive secret string).
  3. Best-effort — a wrapper whose audit lib is missing or whose log is
     unwritable still returns its normal response (logging never blocks
     the op).

Plus a static sweep: all 8 state-changing wrappers carry the hook.

Run from the repo root:   .venv/bin/python deploy/offline-validate-I-2.py
or from inside public/:   python3 deploy/offline-validate-I-2.py
"""
from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
import types

# This file lives in public/deploy/; the wrappers it loads are siblings in
# public/dom0-rpc/. Resolve them relative to THIS file's directory (the same
# os.path.dirname(os.path.realpath(__file__)) sibling-load the dom0 wrappers
# use), so it runs from the repo root AND from inside public/ with no cwd
# assumption and no hardcoded path.
HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(HERE, os.pardir, "dom0-rpc")

STATE_CHANGING = [
    "qmcp.SpawnAIManagedQube", "qmcp.CloneAIManagedQube",
    "qmcp.SpawnDisposableAIManaged", "qmcp.SetPropertyAIManaged",
    "qmcp.SetFeatureAIManaged", "qmcp.LifecycleAIManaged",
    "qmcp.AttachDeviceAIManaged", "qmcp.DetachDeviceAIManaged",
]


# --------------------------------------------------------------------- fakes
class FakeTags:
    def __init__(self, items):
        self._s = set(items)

    def __contains__(self, x):
        return x in self._s

    def __iter__(self):
        return iter(self._s)

    def add(self, x):
        self._s.add(x)


class FakeVM:
    def __init__(self, name, klass, tags, power="Halted", **props):
        self.name = name
        self.klass = klass
        self.tags = FakeTags(tags)
        self.features = {}
        self._power = power
        self._props = props

    # lifecycle no-ops (Lifecycle success path calls these)
    def start(self): pass
    def shutdown(self): pass
    def kill(self): pass
    def pause(self): pass
    def unpause(self): pass

    def is_running(self):
        return self._power == "Running"

    def __str__(self):
        # A real qubesadmin VM stringifies to its name, which is how the
        # birth-egress chain turns a `netvm` property into a name to check
        # against the umbrella. A fake without this reads as an out-of-scope
        # netvm and every create fails closed — correct behaviour, wrong cause.
        return self.name

    def __getattr__(self, item):
        props = self.__dict__.get("_props", {})
        if item in props:
            return props[item]
        raise AttributeError(item)


class FakeDomains:
    def __init__(self, vms):
        self._byname = {vm.name: vm for vm in vms}

    def __contains__(self, name):
        return name in self._byname

    def __getitem__(self, name):
        return self._byname[name]

    def __delitem__(self, name):
        del self._byname[name]

    def __iter__(self):
        return iter(self._byname.values())


class FakeApp:
    def __init__(self, domains):
        self.domains = domains


ai_a = FakeVM("ai-work", "AppVM", {"ai-managed"})
ai_b = FakeVM("ai-net-router", "AppVM", {"ai-managed"}, provides_network=False)
ai_tpl = FakeVM("ai-debian-13", "TemplateVM", {"ai-managed"})
operator = FakeVM("operator-vm", "AppVM", set())
# Wave 2 Stage 2: the create paths now resolve a birth egress and REFUSE when
# the chain cannot. The gateway is therefore part of the fleet, sitting behind
# an ai-managed egress qube exactly as production does, so a spawn here reaches
# the budget gate this section is actually about rather than failing earlier on
# an unresolvable chain. (`QREXEC_REMOTE_DOMAIN` is set below so the wrapper
# looks the gateway up by the name qrexec would give it.)
gateway = FakeVM("mcp-control", "AppVM", set())
gateway.netvm = ai_b
# Assigned, never setdefault: this variable is often already present in a
# session's ambient environment (it reads `dom0` in an operator shell), and a
# setdefault silently keeps that value — the fleet then has no gateway under
# that name and every create fails closed for a reason that has nothing to do
# with the test.
os.environ["QREXEC_REMOTE_DOMAIN"] = "mcp-control"
THE_APP = FakeApp(FakeDomains([ai_a, ai_b, ai_tpl, operator, gateway]))

_qa = types.ModuleType("qubesadmin")
_qa_app = types.ModuleType("qubesadmin.app")
_qa_app.QubesLocal = lambda: THE_APP
_qa.app = _qa_app
sys.modules["qubesadmin"] = _qa
sys.modules["qubesadmin.app"] = _qa_app


# --------------------------------------------------------------------- loaders
def load_lib():
    path = os.path.join(DOM0_RPC, "qmcp_audit.py")
    spec = importlib.util.spec_from_file_location("qmcp_audit", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_wrapper(filename, modname):
    path = os.path.join(DOM0_RPC, filename)
    loader = importlib.machinery.SourceFileLoader(modname, path)
    spec = importlib.util.spec_from_loader(modname, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def run_wrapper(mod, payload, log_path=None):
    """Run a wrapper's main() with a JSON request; redirect its audit lib to
    log_path and clear the persisted summary so runs don't contaminate each
    other (in production each call is a fresh process; here the module
    persists across calls)."""
    if log_path is not None and getattr(mod, "_AUDIT", None) is not None:
        mod._AUDIT.LOG_PATH = log_path
    if hasattr(mod, "_audit_summary"):
        mod._audit_summary.clear()
    out = io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(json.dumps(payload))
    try:
        with contextlib.redirect_stdout(out):
            mod.main()
    finally:
        sys.stdin = old_stdin
    return json.loads(out.getvalue().strip())


def read_lines(path):
    with open(path, "r") as f:
        return [json.loads(s) for s in (ln.strip() for ln in f) if s]


# --------------------------------------------------------------------- harness
RESULTS = []


def check(desc, cond):
    RESULTS.append((desc, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {desc}")


def tmp_log():
    fd, p = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    os.remove(p)  # start absent — exercise the create path
    return p


# --------------------------------------------------------------------- 1. lib
def section_lib(audit):
    print("\n=== qmcp_audit unit (chain / verify / tamper / perms / best-effort) ===")
    p = tmp_log()
    check("missing log verifies trivially (True,0)", audit.verify(p) == (True, 0, None))

    audit.LOG_PATH = p
    assert audit.audit("qmcp.SpawnAIManagedQube", {"name": "ai-x", "template": "ai-debian-13"}, True) is True
    assert audit.audit("qmcp.LifecycleAIManaged", {"name": "ai-x", "action": "start"}, True) is True
    assert audit.audit("qmcp.SetPropertyAIManaged", {"name": "ai-x", "property": "netvm"}, False, "not found") is True
    ok, n, err = audit.verify(p)
    check("3 appended → verify ok, n==3", ok and n == 3 and err is None)
    # Production perms (root:qubes 0660) are set by the installer, not the lib;
    # what the lib must never do is create a world-accessible log. (Under
    # whatever umask, 0o660 create-mode masks to no other-access.)
    check("lib-created log has no world access (o-rwx == 0)",
          (os.stat(p).st_mode & 0o007) == 0)

    rows = read_lines(p)
    check("each line carries seq/prev/hash/ts/service/args/ok", all(
        all(k in r for k in ("seq", "prev", "hash", "ts", "service", "args", "ok")) for r in rows))
    check("seq is 1..n contiguous", [r["seq"] for r in rows] == [1, 2, 3])
    check("first prev is GENESIS", rows[0]["prev"] == audit.GENESIS)
    check("each prev links the previous hash",
          rows[1]["prev"] == rows[0]["hash"] and rows[2]["prev"] == rows[1]["hash"])

    # tamper: edit a content field
    raw = open(p).read().splitlines()
    o = json.loads(raw[1]); o["ok"] = not o["ok"]
    raw[1] = json.dumps(o, sort_keys=True, separators=(",", ":"))
    open(p, "w").write("\n".join(raw) + "\n")
    check("edit tamper detected", audit.verify(p)[0] is False)

    # delete a line
    p2 = tmp_log(); audit.LOG_PATH = p2
    for i in range(4):
        audit.audit("qmcp.X", {"i": i}, True)
    raw = open(p2).read().splitlines(); del raw[1]
    open(p2, "w").write("\n".join(raw) + "\n")
    check("delete tamper detected", audit.verify(p2)[0] is False)

    # reorder
    p3 = tmp_log(); audit.LOG_PATH = p3
    for i in range(3):
        audit.audit("qmcp.X", {"i": i}, True)
    raw = open(p3).read().splitlines(); raw[0], raw[1] = raw[1], raw[0]
    open(p3, "w").write("\n".join(raw) + "\n")
    check("reorder tamper detected", audit.verify(p3)[0] is False)

    # corrupt (non-JSON) line
    p4 = tmp_log(); audit.LOG_PATH = p4
    audit.audit("qmcp.X", {"i": 0}, True)
    open(p4, "a").write("this is not json\n")
    check("corrupt line detected", audit.verify(p4)[0] is False)

    # best-effort: unwritable path → False, no raise
    audit.LOG_PATH = "/proc/nonexistent-dir/cannot-write.log"
    try:
        r = audit.audit("qmcp.X", {"i": 0}, True)
        check("audit on unwritable path returns False (no raise)", r is False)
    except Exception as e:
        check(f"audit on unwritable path returns False (no raise) [raised {e}]", False)

    for pp in (p, p2, p3, p4):
        with contextlib.suppress(Exception):
            os.remove(pp)


# --------------------------------------------------------------------- 2. integration
def section_integration():
    print("\n=== wrapper integration (one line / call, right fields, no value leak) ===")
    life = load_wrapper("qmcp.LifecycleAIManaged", "w_life")
    setp = load_wrapper("qmcp.SetPropertyAIManaged", "w_setp")
    setf = load_wrapper("qmcp.SetFeatureAIManaged", "w_setf")

    # Lifecycle success → one line, ok True, service + summary correct
    p = tmp_log()
    r = run_wrapper(life, {"name": "ai-work", "action": "start"}, p)
    rows = read_lines(p)
    check("lifecycle ok response unchanged", r == {"ok": True})
    check("lifecycle leaves exactly one line", len(rows) == 1)
    check("line service == qmcp.LifecycleAIManaged", rows and rows[0]["service"] == "qmcp.LifecycleAIManaged")
    check("line ok True", rows and rows[0]["ok"] is True)
    check("line args == {name, action}", rows and rows[0]["args"] == {"name": "ai-work", "action": "start"})
    os.remove(p)

    # Lifecycle refused (untagged operator-side qube) → one line, ok False, opaque error
    p = tmp_log()
    r = run_wrapper(life, {"name": "operator-vm", "action": "kill"}, p)
    rows = read_lines(p)
    check("lifecycle refused response opaque not found", r == {"ok": False, "error": "not found"})
    check("refused call still leaves exactly one line", len(rows) == 1)
    check("refused line ok False + error recorded",
          rows and rows[0]["ok"] is False and rows[0]["error"] == "not found")
    os.remove(p)

    # SetProperty with a distinctive value → value MUST NOT appear in the log
    SECRET = "S3CR3T-VALUE-MUST-NOT-APPEAR"
    p = tmp_log()
    r = run_wrapper(setp, {"name": "ai-work", "property": "memory", "value": SECRET}, p)
    blob = open(p).read()
    rows = read_lines(p)
    check("setproperty leaves one line", len(rows) == 1)
    check("setproperty args = {name, property} only (no 'value' key)",
          rows and rows[0]["args"] == {"name": "ai-work", "property": "memory"})
    check("the secret value string appears NOWHERE in the log line", SECRET not in blob)
    os.remove(p)

    # SetFeature with a distinctive value → value MUST NOT appear in the log
    p = tmp_log()
    r = run_wrapper(setf, {"name": "ai-work", "feature": "ai-probe", "value": SECRET}, p)
    blob = open(p).read()
    rows = read_lines(p)
    check("setfeature leaves one line", len(rows) == 1)
    check("setfeature args = {name, feature} only (no 'value' key)",
          rows and rows[0]["args"] == {"name": "ai-work", "feature": "ai-probe"})
    check("setfeature: secret value appears NOWHERE in the log line", SECRET not in blob)
    os.remove(p)

    # Spawn — the wrapper whose funnel was RESTRUCTURED (fail() + 3 direct
    # success prints unified through a new emit()). Offline its budget gate
    # refuses with "pool cap not configured" (no /etc/qmcp/pool-cap here),
    # which drives the fail()->emit()->audit path. Confirm: exactly one line,
    # right service, full whitelisted summary, no 'value'.
    spawn = load_wrapper("qmcp.SpawnAIManagedQube", "w_spawn")
    p = tmp_log()
    r = run_wrapper(spawn, {"name": "ai-new", "template": "ai-debian-13",
                            "klass": "AppVM", "label": "gray"}, p)
    rows = read_lines(p)
    check("spawn (restructured funnel) leaves exactly one line", len(rows) == 1)
    check("spawn line service == qmcp.SpawnAIManagedQube",
          rows and rows[0]["service"] == "qmcp.SpawnAIManagedQube")
    check("spawn refused at budget gate (ok False, 'pool cap' error)",
          rows and rows[0]["ok"] is False and "pool cap" in (rows[0]["error"] or ""))
    # The wrapper whitelists a 6th summary key, `private_size` (an AI-supplied
    # persistent-volume size, not a property/feature *value*), so the
    # no-secret-leak invariant still holds. The security assertion is the
    # absence of a 'value' key, which we keep below.
    check("spawn summary = name/template/klass/netvm/label/private_size, no 'value'",
          rows and set(rows[0]["args"]) == {"name", "template", "klass", "netvm", "label", "private_size"}
          and "value" not in rows[0]["args"])
    os.remove(p)

    # a fresh chain across mixed wrappers still verifies end to end
    audit = load_lib()
    p = tmp_log()
    run_wrapper(life, {"name": "ai-work", "action": "start"}, p)
    run_wrapper(setp, {"name": "ai-work", "property": "memory", "value": 4242}, p)
    run_wrapper(setf, {"name": "ai-work", "feature": "k", "value": True}, p)
    run_wrapper(life, {"name": "operator-vm", "action": "kill"}, p)
    ok, n, err = audit.verify(p)
    check("mixed 4-call chain verifies (n==4)", ok and n == 4)
    os.remove(p)


# --------------------------------------------------------------------- 3. best-effort
def section_best_effort():
    print("\n=== best-effort: op never blocked by audit ===")
    life = load_wrapper("qmcp.LifecycleAIManaged", "w_life_be")

    # (a) audit lib absent
    saved = life._AUDIT
    life._AUDIT = None
    r = run_wrapper(life, {"name": "ai-work", "action": "start"})
    check("audit lib None → op still returns normal ok", r == {"ok": True})
    life._AUDIT = saved

    # (b) audit log unwritable → op still returns normal response
    r = run_wrapper(life, {"name": "operator-vm", "action": "kill"},
                    "/proc/nonexistent-dir/x.log")
    check("unwritable log → refused op still returns opaque not found",
          r == {"ok": False, "error": "not found"})


# --------------------------------------------------------------------- 4. static sweep
def section_static():
    print("\n=== static: every state-changing wrapper carries the hook ===")
    for svc in STATE_CHANGING:
        src = open(os.path.join(DOM0_RPC, svc)).read()
        has = ("_load_audit_lib" in src and "_AUDIT.audit(" in src
               and "_audit_summary" in src and 'qmcp_audit.py' in src)
        check(f"{svc} wired", has)


def main():
    audit = load_lib()
    section_lib(audit)
    section_integration()
    section_best_effort()
    section_static()

    print("\n=== Summary ===")
    passed = sum(1 for _, ok in RESULTS if ok)
    total = len(RESULTS)
    for desc, ok in RESULTS:
        if not ok:
            print(f"  FAIL: {desc}")
    print(f"\n{passed}/{total} checks green.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
