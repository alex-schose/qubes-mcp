"""Shared fixture for the crash-point and interleaving suites.

Both suites drive one state-changing operation at a time (an operator command
through `cli.main`, or a dom0 service through `services.main`) on the project
fleet of test_projects.ProjectBase, and watch every call that operation makes
to the fake qubesd. A *probe* installed on the fake app sees each call before
the fake answers it, which is where the suites act:

- test_crashpoints fails the call (the fake's own exception, so the code's
  error handling and rollback run), or kills the process at it: the call and
  every later one raise `Death`, a BaseException no `except Exception`
  catches, and files written after that moment are rolled back, as after a
  SIGKILL or a power cut;
- test_interleave pauses the operation at the call and runs a second one,
  in the same thread (it runs to the end first) or in a thread of its own
  (it runs until it finishes or waits for a lock the first one holds, and
  the first one then goes on).

The probe is set on the app instance, never on the fake class, so nothing it
does outlives the fixture. Every lock wait is set to zero, so a lock is tried
once: a lock another operation holds is "held past the wait" at once, and the
run never sleeps.

Each run judges the end state by the badges qubes wear. A *granting* badge
gives the hub or a lead reach into a qube; a *restricting* badge takes reach
away or marks the qube for the operator's attention.
"""
from __future__ import annotations

import collections
import contextlib
import io
import json
import os
import pathlib
import shutil
import signal
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

import scratch  # noqa: E402
import test_projects  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from qmcp import anon, budget, cli as qcli, core, fleet, gateways, projects, proposals, restored, services  # noqa: E402

LEAD, OTHER_LEAD = test_projects.LEAD, test_projects.OTHER_LEAD

GRANT_FIXED = {"ai-managed", "qmcp-lead", "qmcp-open", "qmcp-open-fw", "ai-dump"}
GRANT_PREFIX = ("qmcp-lead-", "qmcp-proj-", "qmcp-model-", "qmcp-dump-")
RESTRICT = {"qmcp-guarded", "qmcp-blocked", "qmcp-stopped", "qmcp-quarantine", "qmcp-hubblind",
            "qmcp-anon"}
RUNNING = ("Running", "Paused", "Transient")

#: How long one run may take before it is judged hung. No lock is waited for
#: here, so a run that takes this long is stuck.
RUN_LIMIT_S = 20


def granting(tags) -> set:
    return {t for t in tags if t in GRANT_FIXED or t.startswith(GRANT_PREFIX)}


def restricting(tags) -> set:
    return {t for t in tags if t in RESTRICT}


def badge_pair(v) -> tuple:
    tags = set(v.get("tags", ()))
    return (frozenset(granting(tags)), frozenset(restricting(tags)))


class Death(BaseException):
    """The process is gone: nothing after this reaches qubesd."""


class Hung(BaseException):
    """A run took longer than RUN_LIMIT_S."""


# ======================================================================= the probe

class Probe:
    """Sees every fake qubesd call of the operation under test.

    mode None:   count the calls only (a clean run);
    "fail":      the `target`-th call raises the fake's own exception;
    "death":     the `target`-th call and every later one raise Death, and the
                 files are snapshotted at that moment;
    "pause":     before the `target`-th call, run `second(fixture)` to the end,
                 in this thread;
    "thread":    before the `target`-th call, start `second(fixture)` in a
                 thread of its own and let this operation go on once that
                 thread has finished or is waiting (it sleeps: every wait in
                 the library is a sleep between tries of a lock).
    Calls made while `active` is False (setup, the judge's reads), and every
    call from another thread, are passed straight to the fake and not
    counted."""

    #: How long the operation under test waits for the second one to finish
    #: or start waiting before it goes on regardless.
    SETTLE_S = 0.3

    def __init__(self, fixture):
        self.fixture = fixture
        self.app = fixture.app
        self.orig = self.app._maybe_fail          # the fake's bound method
        self.active = False
        self.mode = None
        self.target = 0
        self.count = 0
        self.keys: list = []
        self.dead = False
        self.snap = None
        self.second = None
        self.second_outcome = None
        self.owner = None                          # the thread whose calls are counted
        self.thread = None                         # the second operation's, in "thread" mode
        self.second_waiting = threading.Event()
        self.second_blocked = False                # it was waiting when this one went on
        self.first_waited = False                  # this one slept while the second still ran
        self.app._maybe_fail = self                # an instance attribute shadows the class's

    def arm(self, mode=None, target=0, second=None):
        self.mode, self.target, self.second = mode, target, second
        self.count, self.keys, self.dead, self.snap, self.second_outcome = 0, [], False, None, None
        self.owner, self.thread = threading.get_ident(), None
        self.second_waiting.clear()
        self.second_blocked = self.first_waited = False
        self.active = True

    def disarm(self):
        self.active = False

    def __call__(self, key):
        if self.dead:
            raise Death(key)
        if not self.active or threading.get_ident() != self.owner:
            return self.orig(key)
        self.count += 1
        self.keys.append(key)
        if self.count == self.target:
            if self.mode == "death":
                self.snap = snapshot_files(self.fixture.tmp)
                # restore_files removes it; this removes it when a run ends first.
                self.fixture.addCleanup(scratch.remove, self.snap)
                self.dead = True
                raise Death(key)
            if self.mode == "fail":
                self.app.fail_plan[key] = collections.deque([True])
            if self.mode == "pause" and self.second is not None and self.second_outcome is None:
                self.second_outcome = self._run_second()
            if self.mode == "thread" and self.second is not None and self.thread is None:
                self._start_second()
        return self.orig(key)

    def _start_second(self):
        """The second operation in a thread of its own, as a second process:
        its calls are not counted, it sees no project lock of this thread's
        as its own (`fleet._HELD` is per thread here), and its locks are new
        descriptors, which flock treats as another holder."""
        def body():
            try:
                self.second_outcome = guarded(self.second, self.fixture)
            except BaseException as e:      # noqa: B036  (Hung, or worse: never lost)
                self.second_outcome = {"ok": False, "raised": f"{type(e).__name__}: {e}"}
        self.thread = threading.Thread(target=body, name="second-operation", daemon=True)
        self.thread.start()
        deadline = time.monotonic() + self.SETTLE_S
        while self.thread.is_alive() and not self.second_waiting.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                break
            self.second_waiting.wait(min(left, 0.01))
        self.second_blocked = self.thread.is_alive()

    def finish_second(self, timeout=10.0) -> bool:
        """Join the second operation's thread; False when it never finished."""
        if self.thread is None:
            return True
        self.thread.join(timeout)
        return not self.thread.is_alive()

    def on_sleep(self):
        """Called by the fixture's `time.sleep` before every sleep."""
        if self.thread is None or not self.thread.is_alive():
            return
        ident = threading.get_ident()
        if ident == self.thread.ident:
            self.second_waiting.set()
        elif ident == self.owner:
            self.first_waited = True

    def _run_second(self):
        """The second operation, as another process would run it: its calls
        are not counted, and the project locks this process may hold are not
        re-entered (a second flock on a new descriptor of the same file waits
        for the first, as a second process's would)."""
        saved_held = fleet._HELD[0]
        fleet._HELD[0] = 0
        self.active = False
        try:
            return guarded(self.second, self.fixture)
        finally:
            self.active = True
            fleet._HELD[0] = saved_held


def snapshot_files(tmp) -> pathlib.Path:
    dst = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-crash-snap-"))
    shutil.rmtree(dst)
    shutil.copytree(tmp, dst, symlinks=True)
    return dst


def restore_files(tmp, snap) -> None:
    tmp = pathlib.Path(tmp)
    for p in tmp.iterdir():
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        else:
            p.unlink()
    for p in snap.iterdir():
        if p.is_dir() and not p.is_symlink():
            shutil.copytree(p, tmp / p.name, symlinks=True)
        else:
            shutil.copy2(p, tmp / p.name, follow_symlinks=False)
    shutil.rmtree(snap)


def guarded(op, fixture) -> dict:
    """`op(fixture)` as an outcome dict; Death and Hung pass through."""
    try:
        return op(fixture)
    except (Death, Hung):
        raise
    except BaseException as e:      # noqa: B036  (an operation must never crash the judge)
        return {"ok": False, "raised": f"{type(e).__name__}: {str(e)[:300]}"}


@contextlib.contextmanager
def time_limit(seconds=RUN_LIMIT_S):
    def _alarm(signum, frame):
        raise Hung(f"run took more than {seconds}s")
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


# ======================================================================= the fixture

#: Every wait an operation may spend on a lock or a state change, set to zero:
#: each lock loop tries once and gives up, and no loop sleeps.
SHORT_WAITS = [
    (core, "QUBE_WAIT_S", 0.0), (core, "OPERATOR_WAIT_S", 0.0),
    (fleet, "SWEEP_WAIT_S", 0.0), (fleet, "HALT_WAIT_S", 0.0),
    (restored, "HOLD_LOCK_WAIT_S", 0.0), (restored, "HOLD_SETTLE_WAIT_S", 0.0),
    (restored, "LOCK_WAIT_S", 0.0), (anon, "KILL_LOCK_WAIT_S", 0.0),
    (budget, "LOCK_TIMEOUT_S", 0.0),
    (anon, "LOCK_WAIT_S", 0.0), (anon, "RETRY_WAIT_S", 0.0),
    (proposals, "SUBMIT_WAIT_S", 0.0), (proposals, "DECIDE_WAIT_S", 0.0),
    (services, "DISPOSE_WAIT_S", 0.0),
]


#: The waits for a run where the second operation runs in a thread of its own:
#: real, a few seconds, so an operator command that waits for a lock does
#: wait, and gets it once the operation holding it finishes.
REAL_WAITS = [
    (core, "QUBE_WAIT_S", 3.0), (core, "OPERATOR_WAIT_S", 3.0),
    (fleet, "SWEEP_WAIT_S", 3.0), (restored, "HOLD_LOCK_WAIT_S", 3.0), (restored, "LOCK_WAIT_S", 3.0),
    (restored, "HOLD_SETTLE_WAIT_S", 3.0), (anon, "KILL_LOCK_WAIT_S", 3.0),
    (budget, "LOCK_TIMEOUT_S", 3.0), (anon, "LOCK_WAIT_S", 3.0),
    (proposals, "SUBMIT_WAIT_S", 3.0), (proposals, "DECIDE_WAIT_S", 3.0),
]


def real_waits():
    """Switch a fixture to REAL_WAITS; its cleanup restores the originals."""
    for mod, attr, value in REAL_WAITS:
        setattr(mod, attr, value)
    projects.Locked.__init__.__defaults__ = (None, 3.0)


class Fixture(test_projects.ProjectBase):
    """One run's fleet, temp dir and patched paths; used as an object, not
    collected as a test (its runTest does nothing)."""

    def runTest(self):
        pass

    def setUp(self):
        super().setUp()
        # A simulated death leaves the locks of the "dead" operation held: its
        # call slots, its acting lock, its qubes' and the create lock. That is
        # the state the judge must see, so they stay open for the whole run. A
        # killed process's descriptors are closed by the kernel; the harness
        # closes them here, when the fixture ends (before its temp dir goes),
        # or a sweep of every death point holds thousands of them.
        self.addCleanup(self._close_left_open)
        for mod, attr, value in SHORT_WAITS:
            self.addCleanup(setattr, mod, attr, getattr(mod, attr))
            setattr(mod, attr, value)
        # The records lock's wait is a default argument, not a module constant.
        defaults = projects.Locked.__init__.__defaults__
        self.addCleanup(setattr, projects.Locked.__init__, "__defaults__", defaults)
        projects.Locked.__init__.__defaults__ = (None, 0.0)
        self.probe = Probe(self)
        self._per_thread_process_state()

    def _close_left_open(self):
        probe = getattr(self, "probe", None)
        if probe is not None and probe.thread is not None and probe.thread.is_alive():
            # A second operation still running (a deadlock the run reported)
            # owns its descriptors, as a live process would: closing them
            # under it could hand their numbers to the next fixture's files.
            return
        scratch.close_fds_under(self.tmp)

    def _per_thread_process_state(self):
        """What an operation reads from the process, kept per thread, so a
        second operation in a thread of its own is a second process to it:
        the project-lock re-entrancy count, the effective uid and the CLI's
        output. `time.sleep` tells the probe who is waiting, and never sleeps
        long: every lock loop checks its deadline, so a short sleep only
        polls more often."""
        held = _PerThreadCount()
        self.addCleanup(setattr, fleet, "_HELD", fleet._HELD)
        fleet._HELD = held
        real_geteuid = os.geteuid
        self.addCleanup(setattr, os, "geteuid", real_geteuid)
        os.geteuid = lambda: 0 if getattr(_LOCAL, "root", False) else real_geteuid()
        saved_app = qcli._app
        self.addCleanup(setattr, qcli, "_app", saved_app)
        qcli._app = lambda: self.app
        for name in ("stdout", "stderr"):
            stream = getattr(sys, name)
            self.addCleanup(setattr, sys, name, stream)
            setattr(sys, name, _PerThreadStream(stream, name))
        real_sleep = time.sleep
        self.addCleanup(setattr, time, "sleep", real_sleep)
        probe = self.probe

        def sleep(seconds):
            probe.on_sleep()
            real_sleep(min(seconds, 0.002))
        time.sleep = sleep


_LOCAL = threading.local()


class _PerThreadCount:
    """`fleet._HELD`, a one-element list, with an element per thread."""

    def __getitem__(self, i):
        return getattr(_LOCAL, "held", 0)

    def __setitem__(self, i, value):
        _LOCAL.held = value


class _PerThreadStream:
    """sys.stdout or sys.stderr: the calling thread's buffer while it runs a
    command (`run_cli`), the real stream otherwise."""

    def __init__(self, real, name):
        self._real, self._name = real, name

    def _target(self):
        return getattr(_LOCAL, self._name, None) or self._real

    def write(self, s):
        return self._target().write(s)

    def flush(self):
        return self._target().flush()

    def __getattr__(self, attr):
        return getattr(self._target(), attr)


def new_fixture() -> Fixture:
    t = Fixture()
    try:
        t.setUp()
    except BaseException:
        t.doCleanups()          # what setUp made so far; its own error is the one to see
        raise
    return t


def close_fixture(t) -> None:
    """Run a fixture's cleanups: the patched paths and waits restored, the
    descriptors a simulated death left open closed, the temp dir and any
    snapshot removed. A fixture is used as an object, never run as a test, so
    a cleanup that fails would otherwise be dropped without a word."""
    if not t.doCleanups():
        raise AssertionError(f"a cleanup of the fixture in {getattr(t, 'tmp', '?')} failed; "
                             f"it may be left behind")


def run_cli(t, *argv) -> dict:
    """The operator's command, as root, its output captured for this thread
    only (the fixture points the CLI at its fake app)."""
    out, err = io.StringIO(), io.StringIO()
    saved = getattr(_LOCAL, "root", False), getattr(_LOCAL, "stdout", None), getattr(_LOCAL, "stderr", None)
    _LOCAL.root, _LOCAL.stdout, _LOCAL.stderr = True, out, err
    try:
        try:
            rc = qcli.main(list(argv))
        except SystemExit as e:
            rc = e.code
    finally:
        _LOCAL.root, _LOCAL.stdout, _LOCAL.stderr = saved
    return {"ok": rc == 0, "rc": rc, "text": (out.getvalue() + err.getvalue())[-1500:]}


def run_svc(t, service, req, caller=HUB) -> dict:
    out = io.StringIO()
    rc = services.main(service, stdin=io.BytesIO(json.dumps(req).encode()),
                       environ={"QREXEC_REMOTE_DOMAIN": caller}, app_factory=lambda: t.app, out=out)
    try:
        reply = json.loads(out.getvalue())
    except ValueError:
        reply = None
    return {"ok": bool(reply and reply.get("ok")), "rc": rc, "text": out.getvalue()[-1500:]}


def cmd(*argv):
    return lambda t: run_cli(t, *argv)


def svc(service, req, caller=HUB):
    return lambda t: run_svc(t, service, req, caller)


# ======================================================================= what a run left

def _name(x):
    return getattr(x, "name", x) if x is not None else None


def _readjson(path):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:
        return "<absent>"
    except Exception as e:      # torn or unreadable
        return f"<unreadable: {type(e).__name__}>"


def _windows() -> dict:
    d = pathlib.Path(fleet.WINDOW_DIR)
    out = {}
    if d.is_dir():
        for p in sorted(d.iterdir()):
            if p.suffix == ".lock":
                continue
            try:
                out[p.name] = p.read_text()[:200]
            except OSError as e:
                out[p.name] = f"<{type(e).__name__}>"
    return out


def state(t) -> dict:
    """Every qube's tags, label, power and links, and the record files, read
    from the fake's own storage: no qubesd call, so nothing injected fails it."""
    vms = {}
    domains = t.app.domains
    for name, vm in list(domains._vms.items()) + list(domains._hidden.items()):
        d = vm.__dict__
        props = d.get("_props", {})
        feats = dict(dict.items(vm.features))
        vms[name] = {"klass": d.get("klass"), "tags": sorted(vm.tags.raw()),
                     "labelled": feats.get("qmcp-id") == props.get("uuid"),
                     "power": d.get("_power"), "netvm": _name(props.get("netvm")),
                     "template": _name(props.get("template"))}
    return {"vms": vms, "records": _readjson(projects.PROJECTS_PATH),
            "gateways": _readjson(gateways.GATEWAYS_PATH), "windows": _windows()}


def check_items(t) -> list:
    """`qmcp check` on the fleet as it is: [overall, [[status, check, detail]...]]."""
    was = t.probe.active
    t.probe.active = False
    try:
        findings = fleet.check(t.app)
        # A detail may name the run's temp dir; without this every run's
        # finding would read as new.
        tmp = str(t.tmp)
        return [fleet.overall(findings),
                [[f.status, f.check, str(f.detail).replace(tmp, "<tmp>")] for f in findings]]
    except BaseException as e:      # noqa: B036
        return [f"CRASH {type(e).__name__}", []]
    finally:
        t.probe.active = was


# ======================================================================= setups

def nothing(t):
    pass


def outsider(t):
    """A qube of the operator's, outside AI space."""
    t.app.vm("op-x", netvm=None)


def opened(t, seconds=3600):
    """`ai-tpl-g` open to the hub, firewall rules too."""
    fleet.open_window(t.app, "ai-tpl-g", seconds, firewall=True)


def expired(t):
    """`ai-tpl-g` open, its window already past its end."""
    opened(t)
    path = pathlib.Path(fleet.WINDOW_DIR) / "ai-tpl-g"
    rec = json.loads(path.read_text())
    rec["opened"], rec["expires"] = rec["opened"] - 7200, int(time.time()) - 60
    path.write_text(json.dumps(rec, sort_keys=True) + "\n")


def unheld_restored(t):
    """A qube restored from a backup: it wears a project's badges and no
    label of this dom0's, and the restore check has not seen it yet."""
    t.app.vm("ai-back", labelled=False, template=t.app.domains["ai-debian-13"], netvm=None,
             tags={"ai-managed", "qmcp-proj-p01"})


def held_restored(t):
    """The same restored qube, held for the operator's review."""
    unheld_restored(t)
    restored.hold(t.app)


def new_gateway(t):
    t.app.vm("gw-new", provides_network=True, netvm=t.app.domains["sys-firewall"],
             features={"qubes-firewall": "1"})


def enrolled_new_gateway(t):
    new_gateway(t)
    r = run_cli(t, "gateway", "enroll", "gw-new")
    assert r["ok"], r


def proposal(req, before=nothing):
    """A setup that submits `req` as the hub's proposal and keeps what the
    operator's accept needs on the fixture (`pid`, `sha`, `tick`)."""
    def setup(t):
        before(t)
        r = run_svc(t, "qmcp.SubmitProposal", req)
        assert r["ok"], r
        t.pid = json.loads(r["text"])["id"]
        doc = proposals.show(t.app, t.pid)
        t.sha, t.tick = doc["sha256"], doc.get("tick")
    return setup


def accept_op(t):
    argv = ["proposal", "accept", str(t.pid), "--sha256", t.sha]
    if t.tick:
        argv += ["--yes", t.tick]
    return run_cli(t, *argv)


def reject_op(t):
    return run_cli(t, "proposal", "reject", str(t.pid))


def cap_room(n_qubes):
    """A pool cap with room for `n_qubes` default-size creates beyond what AI
    space holds now."""
    def setup(t):
        used = budget.persistent_sum(t.app)
        per = budget.estimate_new_private(None)
        pathlib.Path(budget.CAP_PATH).write_text(str(int(used + per * n_qubes + per // 2)) + "\n")
    return setup
