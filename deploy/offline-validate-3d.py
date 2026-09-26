#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 3d — the principal is never an OBJECT.

I-5 strips every tier tag from a freshly created qube so AI cannot mint
authority for itself. The identical invariant on the MUTATE path was never
built: no wrapper compared its target against the calling principal. 3d builds
it, as an UNCONDITIONAL pre-gate — ahead of the existence check, the umbrella
check, the tier gate, the consent gate and `/etc/qmcp/enforce-mode`.

WHAT THIS SUITE PROVES, AND WHERE THE REST OF THE PROOF LIVES
-------------------------------------------------------------
  - **Here (mcp-control, mocked qubesadmin)** — the whole decision surface: the
    guarded/dominated partition, the fail-closed direction, the config
    direction, the ordering of the policy half, and the teeth. The risk lives
    here and so does the coverage.
  - **`install-stage-3d.sh` (dom0)** — that the STAGED module behaves, by
    executing it against the partition rather than grepping it (the 3b lesson).
  - **The rig, from the AI seat** — that an umbrella-tagged gateway is refused
    in practice. **The teeth in §0 must NEVER run there**: a real rename of the
    principal severs the rig's own policy and costs a reinstall. Hardware proves
    the REFUSAL; this file proves the vulnerability the refusal removes.

Every check is host-free apart from reading the repo's own policy file.
"""
from __future__ import annotations

import ast
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
DOM0_RPC = os.path.join(ROOT, "dom0-rpc")
POLICY = os.path.join(ROOT, "policy", "30-mcp-control.policy")

PASSED = 0
FAILED = 0


def check(label, cond, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}" + (f"  -- {detail}" if detail else ""))


def load_lib(name):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(DOM0_RPC, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prin = load_lib("qmcp_principal")
caps = load_lib("qmcp_caps")

#: The principal under test. Deliberately NOT the project's real gateway name:
#: the guard derives the principal from QREXEC_REMOTE_DOMAIN, so a suite that
#: hardcodes the deployed name would pass on a fleet where the guard was keyed
#: on a constant instead of on the caller.
GW = "gateway-under-test"
ENV = {"QREXEC_REMOTE_DOMAIN": GW}
NOFILE = os.path.join(tempfile.gettempdir(), "qmcp-3d-absent-principals")
if os.path.exists(NOFILE):
    os.unlink(NOFILE)


# ==========================================================================
# ---- mocked qubesadmin, matching offline-validate-3c.py's harness --------
# ==========================================================================
class FakeVolume:
    def __init__(self, size):
        self.size = size


class FakeVM:
    def __init__(self, name, klass="AppVM", tags=(), netvm=None,
                 provides_network=False, running=True):
        self.name = name
        self.klass = klass
        self.tags = set(tags)
        self.netvm = netvm
        self.template_for_dispvms = False
        self.provides_network = provides_network
        self.template = None
        self.label = "red"
        self.features = {}
        self.volumes = {"private": FakeVolume(2 * 1024 ** 3),
                        "root": FakeVolume(10 * 1024 ** 3),
                        "volatile": FakeVolume(1 * 1024 ** 3)}
        self._running = running

    def __str__(self):
        return self.name

    def is_running(self):
        return self._running

    def kill(self):
        self._running = False

    def start(self):
        self._running = True

    def shutdown(self):
        self._running = False

    def pause(self):
        pass

    def unpause(self):
        pass


class FakeApp:
    def __init__(self, vms):
        self.domains = {v.name: v for v in vms}
        self.touched = False

    def qubesd_call(self, vm_name, method, arg=None, payload=None):
        if method == "admin.vm.tag.Set":
            self.domains[vm_name].tags.add(arg)
            return b""
        if method == "admin.vm.tag.Remove":
            self.domains[vm_name].tags.discard(arg)
            return b""
        if method == "admin.vm.tag.List":
            return (" ".join(sorted(self.domains[vm_name].tags))).encode()
        return b""


def install_fake_qubesadmin(vms):
    qa = types.ModuleType("qubesadmin")
    qa_app = types.ModuleType("qubesadmin.app")
    app = FakeApp(vms)
    qa_app.QubesLocal = lambda *a, **kw: app
    qa.app = qa_app
    qa.Qubes = lambda *a, **kw: app
    exc = types.ModuleType("qubesadmin.exc")

    class QubesException(Exception):
        pass

    exc.QubesException = QubesException
    qa.exc = exc
    sys.modules["qubesadmin"] = qa
    sys.modules["qubesadmin.app"] = qa_app
    sys.modules["qubesadmin.exc"] = exc
    return app


def load_wrapper(name):
    loader = SourceFileLoader("w3d_" + name.replace(".", "_"),
                              os.path.join(DOM0_RPC, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


_POLICY_F = tempfile.NamedTemporaryFile("w", suffix=".consent-policy",
                                        delete=False)
_POLICY_F.write("# empty — nothing gated (I-6)\n")
_POLICY_F.close()
EMPTY_POLICY = _POLICY_F.name


def with_empty_consent_policy(mod):
    c = mod._CONSENT
    mod._CONSENT.gate = lambda svc, act, summary: (
        (False, "unavailable")
        if c.consent_required(svc, act, policy_path=EMPTY_POLICY)
        else (True, "open"))


class Recorder:
    def __init__(self):
        self.calls = 0

    def audit(self, service, summary, ok, error=None, **kw):
        self.calls += 1
        return True


class _StubBudget:
    def check_private_size(self, *a, **kw):
        return None

    def check_cap_for_create(self, *a, **kw):
        return None

    def acquire_create_lock(self, *a, **kw):
        return -1

    def dvmt_private_bytes(self, *a, **kw):
        return 2 * 1024 ** 3


FULL = {"ai-managed", "ai-full"}


def fleet():
    """The gateway carries the umbrella AND ai-full — the misconfiguration
    measured live on 2026-08-13, and the state a fresh install resolves to
    anyway because `/etc/qmcp/tier-default` absent means compat."""
    return [
        FakeVM(GW, tags=FULL),
        FakeVM("full-work", tags=FULL),
        FakeVM("ai-net-router", tags={"ai-managed", "ai-net"},
               provides_network=True),
        FakeVM("outsider"),
    ]


def run(name, request, vms, *, patch=None, env=None, no_qubesadmin=False):
    """Run one wrapper's main(). Returns (response, app)."""
    app = None
    if no_qubesadmin:
        for m in ("qubesadmin", "qubesadmin.app", "qubesadmin.exc"):
            sys.modules.pop(m, None)
        sys.modules["qubesadmin"] = None          # import raises
    else:
        app = install_fake_qubesadmin(vms)
    mod = load_wrapper(name)
    mod._AUDIT = Recorder()
    mod._load_budget_lib = lambda: _StubBudget()
    if not no_qubesadmin:
        with_empty_consent_policy(mod)
    # Bind the guard to the test principal and to an ABSENT operator file, so
    # every assertion below is about the derived half unless it says otherwise.
    real = mod._PRINCIPAL
    if real is not None:
        mod._PRINCIPAL = types.SimpleNamespace(
            refuses_as_principal=lambda svc, role, nm, act=None: (
                real.refuses_as_principal(svc, role, nm, act,
                                          path=NOFILE,
                                          environ=env or ENV)))
    if patch:
        patch(mod)

    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(request))
    sys.stdout = io.StringIO()
    try:
        mod.main()
        raw = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
        if no_qubesadmin:
            sys.modules.pop("qubesadmin", None)
    return json.loads(raw or "{}"), app


LIFE = "qmcp.LifecycleAIManaged"
SETP = "qmcp.SetPropertyAIManaged"
SETF = "qmcp.SetFeatureAIManaged"
ATT = "qmcp.AttachDeviceAIManaged"
DET = "qmcp.DetachDeviceAIManaged"
GUARDED_WRAPPERS = [SETP, SETF, LIFE, ATT, DET]
READ_WRAPPERS = ["qmcp.GetPropertyAIManaged",
                 "qmcp.ListAttachedDevicesAIManaged",
                 "qmcp.ListAIManagedQubes", "qmcp.AIManagedEvents",
                 "qmcp.GetPoolStats"]


# ==========================================================================
print("\n=== 0. Teeth: the hole is reproduced before it is shown closed ===")
# ==========================================================================
# The pre-3d code path is EXACTLY this wrapper with `_principal_refuses`
# returning False — that is what the file looked like before the stage. Run it
# and rename the gateway. If this does not succeed, every assertion in §1
# proves nothing.
def _disarm(mod):
    mod._principal_refuses = lambda *a, **kw: False


r, app = run(SETP, {"name": GW, "property": "name", "value": "seized"},
             fleet(), patch=_disarm)
check("teeth: PRE-3d, renaming the gateway from the AI seat SUCCEEDS",
      r.get("ok") is True,
      f"the vulnerability did not reproduce; response={r}")

# Which of SETTABLE_PROPS were actually open on the principal before 3d is
# DERIVED, not guessed. The first draft of this suite asserted that the egress
# retarget was one of them and the suite failed: F-2's netvm guard already
# refuses that for every qube, principal or not. Asserting a hole that another
# stage had closed would have credited 3d with F-2's work — so the open set is
# measured here and only then required to close.
settable = sorted(load_wrapper(SETP).SETTABLE_PROPS)
VALUES = {"name": "seized", "label": "blue", "memory": 400, "maxmem": 4000,
          "vcpus": 2, "template": "full-work", "netvm": "ai-net-router",
          "default_dispvm": "full-work"}
open_pre = []
for prop in settable:
    r, _ = run(SETP, {"name": GW, "property": prop,
                      "value": VALUES.get(prop, 1)}, fleet(), patch=_disarm)
    if r.get("ok") is True:
        open_pre.append(prop)
check("teeth: PRE-3d, at least one gateway property is mutable from the seat",
      bool(open_pre), "nothing reproduced; the stage would prove nothing")
check("teeth: `name` is among them — the unrecoverable one",
      "name" in open_pre, f"open pre-3d: {open_pre}")
print(f"      (open on the principal pre-3d: {open_pre})")

# ...and every one of them is closed with the guard armed. This is the pair
# that matters: the same list, measured open, then required shut.
for prop in open_pre:
    r, _ = run(SETP, {"name": GW, "property": prop,
                      "value": VALUES.get(prop, 1)}, fleet())
    check(f"teeth: ...and POST-3d, `{prop}` on the principal is shut",
          r == prin.NOT_FOUND, f"response={r}")

# And a control: the guard is not an always-refuse. A non-principal target
# must still work with the guard fully armed, or §1 would pass vacuously.
r, app = run(SETP, {"name": "full-work", "property": "label",
                    "value": "blue"}, fleet())
check("control: a NON-principal target is still settable with 3d armed",
      r.get("ok") is True, f"response={r}")


# ==========================================================================
print("\n=== 1. The guarded positions refuse, opaquely ===")
# ==========================================================================
r, _ = run(SETP, {"name": GW, "property": "name", "value": "seized"}, fleet())
check("SetProperty(name) on the principal is REFUSED", r.get("ok") is False)
check("...and the refusal is the opaque NOT_FOUND",
      r == prin.NOT_FOUND, f"response={r}")

for prop in ("netvm", "template", "memory", "label", "default_dispvm"):
    r, _ = run(SETP, {"name": GW, "property": prop, "value": None}, fleet())
    check(f"SetProperty({prop}) on the principal is refused",
          r == prin.NOT_FOUND, f"response={r}")

r, _ = run(SETF, {"name": GW, "feature": "service.qubes-firewall",
                  "value": "1"}, fleet())
check("SetFeature on the principal is refused", r == prin.NOT_FOUND, f"{r}")

for act in ("pause", "remove"):
    r, _ = run(LIFE, {"name": GW, "action": act}, fleet())
    check(f"Lifecycle({act}) on the principal is refused",
          r == prin.NOT_FOUND, f"response={r}")

for role in ("backend", "frontend"):
    req = {"device_class": "block", "device_id": "sda",
           "backend": GW if role == "backend" else "full-work",
           "frontend": GW if role == "frontend" else "full-work"}
    r, _ = run(ATT, dict(req), fleet())
    check(f"AttachDevice with the principal as {role} is refused",
          r == prin.NOT_FOUND, f"response={r}")
    r, _ = run(DET, dict(req), fleet())
    check(f"DetachDevice with the principal as {role} is refused",
          r == prin.NOT_FOUND, f"response={r}")


# ==========================================================================
print("\n=== 2. Anti-theatre: the DOMINATED half must stay UNGUARDED ===")
# ==========================================================================
# This is the section a later session will want to weaken ("why not guard
# everything?"). AI runs AS the principal and already holds code execution
# there, so gating what the seat can do from inside deletes nothing and reads
# as a control — invariant 2's no-illusion defect.
for act in ("kill", "shutdown", "start"):
    check(f"Lifecycle({act}) on the principal is NOT guarded (exec dominates)",
          prin.guards(LIFE, "target", act) is False)
    check(f"...and qmcp_caps agrees {act} is dominated by CAP_EXEC",
          (LIFE, act) in caps.DOMINATION)

check("Lifecycle(pause) IS guarded — exec does not reach unpause",
      prin.guards(LIFE, "target", "pause") is True)
check("...and qmcp_caps agrees pause is NOT in DOMINATION",
      (LIFE, "pause") not in caps.DOMINATION)

check("Clone with the principal as source is NOT guarded (dominated for data)",
      prin.guards("qmcp.CloneAIManagedQube", "source") is False)
check("Spawn with the principal as template is NOT guarded",
      prin.guards("qmcp.SpawnAIManagedQube", "template") is False)
check("SpawnDisposable with the principal as dvmt is NOT guarded",
      prin.guards("qmcp.SpawnDisposableAIManaged", "dvmt") is False)
for w in READ_WRAPPERS:
    check(f"{w.split('.')[-1]} is NOT guarded (a read is invariant-2 theatre)",
          prin.guards(w, "target") is False)

# The partition, pinned whole. A future stage moving a row fails HERE rather
# than silently inverting the invariant.
EXPECTED = {
    SETP: {"target"}, SETF: {"target"}, LIFE: {"target"},
    ATT: {"backend", "frontend"}, DET: {"backend", "frontend"},
}
check("the guarded (service, roles) partition is exactly as designed",
      {k: set(v) for k, v in prin.PRINCIPAL_GUARDED_ROLES.items()} == EXPECTED,
      f"got {prin.PRINCIPAL_GUARDED_ROLES}")
check("LIFECYCLE_DOMINATED is exactly {kill, shutdown, start}",
      set(prin.LIFECYCLE_DOMINATED) == {"kill", "shutdown", "start"},
      f"got {set(prin.LIFECYCLE_DOMINATED)}")
check("every LIFECYCLE_DOMINATED action is dominated in qmcp_caps too",
      all((LIFE, a) in caps.DOMINATION for a in prin.LIFECYCLE_DOMINATED))


# ==========================================================================
print("\n=== 3. Fail-closed — and the direction is INVERTED from I-2 ===")
# ==========================================================================
# I-2 is best-effort instrumentation and must degrade silently. This is a GATE.
# A dom0 on a pre-3d deploy has no qmcp_principal.py; a partially-updated one
# has the module but not the function. Both must REFUSE.
def _no_module(mod):
    mod._PRINCIPAL = None


r, _ = run(SETP, {"name": "full-work", "property": "label", "value": "blue"},
           fleet(), patch=_no_module)
check("a MISSING qmcp_principal refuses (not falls through)",
      r == prin.NOT_FOUND, f"response={r}")


def _stale_module(mod):
    mod._PRINCIPAL = types.SimpleNamespace()      # pre-3d: no such attribute


r, _ = run(SETP, {"name": "full-work", "property": "label", "value": "blue"},
           fleet(), patch=_stale_module)
check("a STALE qmcp_principal (AttributeError) refuses",
      r == prin.NOT_FOUND, f"response={r}")


def _raising_module(mod):
    def boom(*a, **kw):
        raise RuntimeError("helper exploded")
    mod._PRINCIPAL = types.SimpleNamespace(refuses_as_principal=boom)


r, _ = run(SETP, {"name": "full-work", "property": "label", "value": "blue"},
           fleet(), patch=_raising_module)
check("a RAISING qmcp_principal refuses", r == prin.NOT_FOUND, f"{r}")

# An unparsed lifecycle action cannot be shown dominated, so it is guarded.
check("Lifecycle with action=None is guarded (fail-closed by omission)",
      prin.guards(LIFE, "target", None) is True)


# ==========================================================================
print("\n=== 4. Decided on SHAPE — no host lookup, so no oracle ===")
# ==========================================================================
# The FUNCTION is pure and host-free — that part was never in doubt and is
# asserted below. What changed on 2026-09-02 is the CALL SITE: proving the
# function needs no host is not the same as proving the CALL costs the same as
# its neighbours, and only the second is what an observer measures. The
# end-to-end equality is a hardware property and lives in
# the end-to-end latency probe run from the AI seat, which is what caught the gap.
check("the guard needs no app at all (pure, host-free)",
      prin.refuses_as_principal(SETP, "target", GW,
                                path=NOFILE, environ=ENV) is True)
check("a name that is not the principal is not refused on shape",
      prin.refuses_as_principal(SETP, "target", "full-work",
                                path=NOFILE, environ=ENV) is False)


# ==========================================================================
print("\n=== 5. Config direction: the file only ever ADDS (F-1, not F-N) ===")
# ==========================================================================
check("absent file still protects the caller",
      prin.protected_principals(NOFILE, ENV) == frozenset({GW}))
check("absent file is NOT 'protect nothing'",
      prin.protected_principals(NOFILE, ENV) != frozenset())

with tempfile.NamedTemporaryFile("w", delete=False) as f:
    f.write("# a comment\n\nsecond-gateway\n   third-gateway   \n")
    extra = f.name
check("the file ADDS to the derived principal",
      prin.protected_principals(extra, ENV) ==
      frozenset({GW, "second-gateway", "third-gateway"}),
      f"got {prin.protected_principals(extra, ENV)}")
check("comments and blank lines are ignored (the F-N lesson)",
      "# a comment" not in prin.protected_principals(extra, ENV))

with tempfile.NamedTemporaryFile("wb", delete=False) as f:
    f.write(b"\xff\xfe\x00binary garbage\n")
    junk = f.name
check("a malformed file cannot REMOVE the derived principal",
      GW in prin.protected_principals(junk, ENV))

# An UNBOUNDED read is a fail-HANG: neither open nor closed, and for a qrexec
# service it blocks the caller too. Found on hardware 2026-09-02 by symlinking
# the operator file to /dev/zero, which never returned.
_huge = os.path.join(tempfile.gettempdir(), "qmcp-3d-huge-principals")
with open(_huge, "w") as _f:
    _f.write("padding-name\n" * 20000)          # ~260 KB, over the cap
check("an OVERSIZED principals file is rejected, not truncated",
      prin.protected_principals(_huge, ENV) == frozenset({GW}),
      "a truncated read would silently drop names past the cap")
check("...and the cap is a real bound, not a comment",
      prin.MAX_PRINCIPALS_BYTES > 0 and os.path.getsize(_huge) > prin.MAX_PRINCIPALS_BYTES)
if os.path.exists("/dev/zero"):
    check("an UNBOUNDED source (/dev/zero) returns instead of hanging",
          prin.protected_principals("/dev/zero", ENV) == frozenset({GW}),
          "unbounded read — every guarded call would hang")
os.unlink(_huge)

# An UNREADABLE file is a fail-QUIET, not a fail-open: the caller stays
# protected and only the named siblings are silently lost. The module says so
# and the installer reports it; assert the behaviour so the claim is not prose.
import stat as _stat
with tempfile.NamedTemporaryFile("w", delete=False) as _f:
    _f.write("sibling-gateway\n")
    _unreadable = _f.name
os.chmod(_unreadable, 0o000)
_can_read = os.access(_unreadable, os.R_OK)   # False unless running as root
if _can_read:
    print("SKIP  unreadable-file check (running as root: mode 000 is readable)")
else:
    check("an UNREADABLE principals file still protects the caller",
          prin.protected_principals(_unreadable, ENV) == frozenset({GW}))
    check("...and silently drops only the siblings it named (fail-quiet)",
          "sibling-gateway" not in prin.protected_principals(_unreadable, ENV))
os.chmod(_unreadable, 0o644)

check("an empty QREXEC_REMOTE_DOMAIN yields no derived principal",
      prin.protected_principals(NOFILE, {}) == frozenset())

# --- the undeterminable caller must FAIL CLOSED -------------------------
# This was a fail-OPEN until the 2026-09-02 re-audit, and these three lines
# used to assert the hole: an absent/empty/blank variable made the guard
# protect nothing, and the suite called that expected. A test defending a
# hole is worse than no test, because it makes the hole look considered.
for _lbl, _env in (("absent", {}), ("empty", {"QREXEC_REMOTE_DOMAIN": ""}),
                   ("blank", {"QREXEC_REMOTE_DOMAIN": "   "})):
    check(f"an {_lbl} QREXEC_REMOTE_DOMAIN REFUSES a guarded position",
          prin.refuses_as_principal(SETP, "target", "anything",
                                    path=NOFILE, environ=_env) is True,
          "fail-open: the guard cannot tell whether this is the principal")
    check(f"...and an {_lbl} caller still leaves DOMINATED positions open",
          prin.refuses_as_principal(LIFE, "target", "anything", "shutdown",
                                    path=NOFILE, environ=_env) is False,
          "the anti-theatre partition must survive the fail-closed path")

# teeth: reconstruct the pre-fix predicate and show it let the call through,
# so the three checks above are shown necessary rather than merely passing.
def _prefix_refuses(name, environ):
    """The shipped predicate before the re-audit: no caller check at all."""
    return str(name) in prin.protected_principals(NOFILE, environ)


check("teeth: the PRE-FIX predicate waved an unknown caller through",
      _prefix_refuses(GW, {}) is False,
      "if this refuses, the fix above proves nothing")
check("teeth: ...and the shipped one does not",
      prin.refuses_as_principal(SETP, "target", GW,
                                path=NOFILE, environ={}) is True)

check("the operator file still protects what it names, caller known",
      prin.refuses_as_principal(SETP, "target", "second-gateway",
                                path=extra,
                                environ={"QREXEC_REMOTE_DOMAIN": GW}) is True)


# ==========================================================================
print("\n=== 6. The policy half, asserted against the LIVE file ===")
# ==========================================================================
# 3b's §5b precedent: pin a load-bearing partition against the real file so a
# paragraph cannot rot into a false claim.
lines = open(POLICY, encoding="utf-8").read().splitlines()
rules = [(i, l) for i, l in enumerate(lines)
         if l.strip() and not l.lstrip().startswith("#")]

# Only the firewall WRITE methods. `qmcp.RunInAIManaged` / `CopyToAIManaged`
# were in this list until the hardware pass: dom0's policy daemon ALLOWS the
# self-call and the qrexec transport then refuses it ("loopback qrexec
# connection not supported"), so a deny there guards a capability that does not
# exist. The firewall path is not a loopback — `target=@adminvm` sends it to
# dom0 — and `firewall.Get` on the gateway itself returns the same bytes as on
# any ai-managed qube, so those two are real. §6b pins the distinction.
TAG_SCOPED_GUARDED = ["admin.vm.firewall.Set", "admin.vm.firewall.Reload"]
LOOPBACK_ONLY = ["qmcp.RunInAIManaged", "qmcp.CopyToAIManaged"]
for svc in TAG_SCOPED_GUARDED:
    mine = [(i, l) for i, l in rules if l.split()[0] == svc]
    deny = [i for i, l in mine
            if l.split()[-1] == "deny" and l.split()[2] == l.split()[3]]
    tags = [i for i, l in mine if "@tag:" in l]
    check(f"policy: {svc} has a self-target deny", bool(deny))
    check(f"policy: {svc}'s deny precedes its @tag: lines (first-match-wins)",
          bool(deny) and bool(tags) and max(deny) < min(tags),
          f"deny={deny} tags={tags}")

# 6b — and the loopback-only services must NOT have gained a deny. This is the
# check that stops a future session "completing the set" by re-adding them.
for svc in LOOPBACK_ONLY:
    mine = [l for _, l in rules if l.split()[0] == svc]
    check(f"policy: {svc} has NO self-deny (qrexec cannot loopback; it would "
          f"be theatre)",
          not [l for l in mine
               if len(l.split()) >= 5 and l.split()[4] == "deny"
               and l.split()[2] == l.split()[3]])

get_rules = [l for _, l in rules if l.split()[0] == "admin.vm.firewall.Get"]
check("policy: firewall.Get has NO deny line (a read is theatre)",
      not any(l.split()[-1] == "deny" for l in get_rules))

check("policy: no rule line carries a trailing inline comment (I-4)",
      not [l for _, l in rules if "#" in l])
VALID = {"allow", "deny", "ask"}
check("policy: every rule line still lints (>=4 fields + a valid action)",
      not [l for _, l in rules
           if len(l.split()) < 4 or not any(f in VALID for f in l.split())])

# The installer's un-flip guard, run as the installer runs it. The shipped
# policy carries the four `@tag:ai-managed` COMPAT backstops that the I-4/I-5
# flip deletes; an installer that writes this file over a FLIPPED fleet
# restores them while `tier-default` stays `ro`, which is the F9 split-brain.
# That is not hypothetical — measured on the development box 2026-09-02, a
# policy-only release had done exactly that on 2026-08-19 and the fleet sat
# split-brained for two weeks. Pinning the count here means a future stage that
# deletes a backstop fails a check instead of silently changing what the guard
# is guarding.
import re as _re
_BACKSTOP = _re.compile(
    r'^(qmcp\.(RunIn|CopyTo)AIManaged|admin\.vm\.firewall\.(Set|Reload))'
    r'\s+\*\s+\S+\s+@tag:ai-managed\s+allow')
_found = [l for _, l in rules if _BACKSTOP.match(l)]
check("the shipped policy carries exactly the 4 known COMPAT backstops",
      len(_found) == 4, f"found {len(_found)}: {_found}")
_inst = open(os.path.join(HERE, "install-stage-3d.sh"), encoding="utf-8").read()
check("install-stage-3d.sh refuses to un-flip a flipped fleet",
      "QMCP_ALLOW_UNFLIP" in _inst and "tier-default" in _inst,
      "a policy-carrying installer with no flip guard is the 0.9.12 defect")
check("...and offers a policy-free install as the always-safe option",
      "QMCP_SKIP_POLICY" in _inst)

# The two halves must cover the same lattice between them: every service the
# kernel models is either wrapper-guarded here, policy-guarded there, or
# deliberately unguarded with a reason recorded in qmcp_principal's docstring.
modelled = set(caps.SERVICE_TABLE)
covered = set(prin.PRINCIPAL_GUARDED_ROLES) | set(TAG_SCOPED_GUARDED)
# COMPLETENESS. Until the 2026-09-02 re-audit the three create wrappers were
# excluded by a paragraph in a docstring, and a sixth mutating wrapper added
# later would have arrived silently unguarded with nothing failing. Every
# CAP_FULL-gated service the kernel models must now appear in exactly one of
# PRINCIPAL_GUARDED_ROLES or PRINCIPAL_EXCLUDED — so a new one fails HERE until
# someone decides which side it is on. Same idiom as G0a's SETTABLE_PROPS
# default-deny and 3b §5b's pinned partition.
_mutating = {svc for svc, roles in caps.SERVICE_TABLE.items()
             if roles and any(v == caps.CAP_FULL for v in roles.values())}
_classified = set(prin.PRINCIPAL_GUARDED_ROLES) | set(prin.PRINCIPAL_EXCLUDED)
check("every CAP_FULL-gated service is classified guarded-or-excluded",
      _mutating <= _classified,
      f"unclassified (would be silently unguarded): {sorted(_mutating - _classified)}")
check("...and nothing is classified BOTH guarded and excluded",
      not (set(prin.PRINCIPAL_GUARDED_ROLES) & set(prin.PRINCIPAL_EXCLUDED)),
      f"both: {sorted(set(prin.PRINCIPAL_GUARDED_ROLES) & set(prin.PRINCIPAL_EXCLUDED))}")
check("...and nothing is excluded that the kernel does not model as mutating",
      set(prin.PRINCIPAL_EXCLUDED) <= _mutating,
      f"phantom exclusions: {sorted(set(prin.PRINCIPAL_EXCLUDED) - _mutating)}")
for _svc, _why in prin.PRINCIPAL_EXCLUDED.items():
    check(f"exclusion {_svc.split('.')[-1]} carries a reason",
          bool(_why) and _why in {"dominated-for-data", "class-impossible"},
          f"reason={_why!r}")

# teeth: a hypothetical new mutating wrapper must FAIL the completeness check.
_fake = dict(caps.SERVICE_TABLE)
_fake["qmcp.RenameAIManagedQube"] = {"target": caps.CAP_FULL}
_fake_mut = {s for s, r in _fake.items()
             if r and any(v == caps.CAP_FULL for v in r.values())}
check("teeth: an unclassified new mutating wrapper would FAIL this check",
      not (_fake_mut <= _classified),
      "the completeness check would not notice a new wrapper")

check("every guarded service is one the kernel actually models",
      covered <= modelled, f"unmodelled: {sorted(covered - modelled)}")


# ==========================================================================
print("\n=== 7. Wiring: present where it must be, absent where it must not ===")
# ==========================================================================
for w in GUARDED_WRAPPERS:
    src = open(os.path.join(DOM0_RPC, w), encoding="utf-8").read()
    tree = ast.parse(src)
    fns = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    check(f"{w.split('.')[-1]} defines _principal_refuses",
          "_principal_refuses" in fns)
    body = src[src.index("def main("):]
    check(f"{w.split('.')[-1]} calls it from main()",
          "_principal_refuses(" in body,
          "helper present but never consulted — the silent half of a flip")
    # Ordering, and it INVERTED on 2026-09-02. The call used to be required to
    # precede the qubesadmin import ("decide on shape before any host lookup").
    # That was right about disclosure and wrong about latency: skipping the
    # qubesd round trip made the principal 44% faster than every other refusal
    # class on hardware, byte-identical messages notwithstanding — an oracle
    # over /etc/qmcp/principals. The guard now runs AFTER the existence and
    # umbrella checks (same answers, same cost) and still before the tier gate,
    # the consent gate and the enforce-mode flag.
    _umb = body.index('"ai-managed" not in')
    _g = body.index("_principal_refuses(")
    _tier = min(x for x in (body.find("_require_full"), body.find("_gate("),
                            body.find("_full_ok")) if x > 0)
    check(f"{w.split('.')[-1]} calls it AFTER the umbrella check",
          _umb < _g, "an early call site is the timing oracle again")
    check(f"{w.split('.')[-1]} calls it BEFORE the tier/consent/enforce gates",
          _g < _tier)

for w in READ_WRAPPERS:
    src = open(os.path.join(DOM0_RPC, w), encoding="utf-8").read()
    check(f"{w.split('.')[-1]} did NOT gain the guard",
          "_principal_refuses" not in src,
          "a read surface acquired a gate — invariant-2 theatre")

# One copy of the helper, not five drifting ones.
# Extracted by AST, not by slicing to a blank-line run. The first draft used
# `\n\n\n` as the boundary and reported "2 distinct copies" because four
# wrappers carry a `_MODE_PATH` block after the helper and Lifecycle does not —
# the bodies were identical and the EXTRACTION differed. Structure, not
# vocabulary (Stage 3a), applies to the checker as much as to the checked.
import hashlib
blocks = set()
for w in GUARDED_WRAPPERS:
    wsrc = open(os.path.join(DOM0_RPC, w), encoding="utf-8").read()
    node = next(n for n in ast.walk(ast.parse(wsrc))
                if isinstance(n, ast.FunctionDef)
                and n.name == "_principal_refuses")
    blk = ast.get_source_segment(wsrc, node)
    blocks.add(hashlib.sha256(blk.encode()).hexdigest())
check(f"_principal_refuses is byte-identical across all "
      f"{len(GUARDED_WRAPPERS)} wrappers",
      len(blocks) == 1, f"{len(blocks)} distinct copies")


# ==========================================================================
print("\n=== 8. Mode-invariance: the guard is ahead of the flag ===")
# ==========================================================================
enforce = load_lib("qmcp_enforce")
for mode in (enforce.SHADOW, enforce.STRICT, enforce.ENFORCE):
    def _mode(mod, m=mode):
        mod._ENFORCE.read_mode = lambda *a, **kw: m
        mod._MODE = None
    r, _ = run(SETP, {"name": GW, "property": "name", "value": "seized"},
               fleet(), patch=_mode)
    check(f"the principal is refused identically under {mode}",
          r == prin.NOT_FOUND, f"response={r}")


# ==========================================================================
print("\n=== 9. The uninstaller actually reverts the policy half ===")
# ==========================================================================
# An uninstaller nobody exercises is a comment. This runs the REAL awk program
# out of uninstall-stage-3d.sh against the REAL policy and requires the result
# to equal the pre-3d file byte for byte. Two bugs were caught this way before
# the stage shipped: a `grep -E \4` backreference that is a hard error on
# non-GNU greps (so the count came back empty, `-gt 0` was false, and the
# revert silently did nothing while reporting success), and a strip that left
# three stray blank lines behind.
import subprocess

UNINST = os.path.join(HERE, "uninstall-stage-3d.sh")
usrc = open(UNINST, encoding="utf-8").read()
pred = usrc[usrc.index("AWK_IS_3D_DENY='") + len("AWK_IS_3D_DENY='"):]
pred = pred[:pred.index("'\n")]
prog = usrc[usrc.index('awk "$AWK_IS_3D_DENY"\'\n'):]
prog = prog[prog.index("\n") + 1:prog.index("\n        ' \"$POLICY_DST\"")]

have_awk = True
try:
    n = subprocess.run(["awk", pred + ' { if (is3d()) c++ } END { print c+0 }',
                        POLICY], capture_output=True, text=True, check=True)
except (OSError, subprocess.CalledProcessError):
    have_awk = False

if not have_awk:
    print("SKIP  awk unavailable — the uninstaller round-trip could not run")
else:
    check("uninstaller: its predicate finds exactly the 2 deny lines",
          n.stdout.strip() == "2", f"counted {n.stdout.strip()}")
    stripped = subprocess.run(["awk", pred + prog, POLICY],
                              capture_output=True, text=True, check=True).stdout
    live = open(POLICY, encoding="utf-8").read()
    check("uninstaller: the strip removes the deny lines",
          not [l for l in stripped.splitlines()
               if l.split()[:1] and len(l.split()) >= 5
               and l.split()[4] == "deny" and l.split()[2] == l.split()[3]])
    check("uninstaller: it leaves no stray blank line behind",
          "\n\n\n" not in stripped or "\n\n\n" in live,
          "the strip introduced a blank run the original did not have")
    check("uninstaller: everything else is untouched",
          [l for l in live.splitlines() if l.strip()
           and not l.lstrip().startswith("#")
           and not (len(l.split()) >= 5 and l.split()[4] == "deny"
                    and l.split()[2] == l.split()[3])] ==
          [l for l in stripped.splitlines() if l.strip()
           and not l.lstrip().startswith("#")],
          "the strip removed a rule it should not have")
    # Idempotent: stripping an already-stripped file changes nothing further.
    again = subprocess.run(["awk", pred + prog], input=stripped,
                           capture_output=True, text=True, check=True).stdout
    # ORDERING: the refusal must precede every mutation. Found on hardware
# 2026-09-11 — the uninstaller stripped the policy deny lines, THEN hit its
# refusal, printed "That is an outage, not a revert" and exited 1, leaving the
# fleet half-reverted while reporting that it had refused. A script that mutates
# before it validates cannot honestly report refusing. Keyed on the actual
# mutating commands, not on a comment (the Stage 3a structure-over-vocabulary
# rule applies to this check as much as to the code).
_u = open(os.path.join(HERE, "uninstall-stage-3d.sh"), encoding="utf-8").read()
_refusal = _u.find("REFUSING")
_mutations = [_u.find(k) for k in ('install -m 0664', 'rm -f "$LIB"', 'sudo rm')
              if _u.find(k) > 0]
check("uninstaller: it refuses BEFORE any mutation, not after",
      _refusal > 0 and _mutations and _refusal < min(_mutations),
      f"refusal at {_refusal}, first mutation at "
      f"{min(_mutations) if _mutations else None} — a partial revert on the "
      f"error path, reported as a refusal")
check("uninstaller: the guard-detection loop exists exactly once",
      _u.count('STILL_3D=""') == 1,
      "two detections drift; the one that runs may not be the one that refuses")
check("uninstaller: QMCP_POLICY_ONLY bypasses the refusal (it is a narrowing)",
      "QMCP_POLICY_ONLY" in _u[:_refusal + 400],
      "policy-only revert must remain available while the wrappers are in")

check("uninstaller: the strip is idempotent", again == stripped)


# --------------------------------------------------------------------------
print(f"\n{'=' * 70}")
print(f"Stage 3d offline validation: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
