#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 3c — the enforcement flip.

Stage 1 landed `qmcp_caps.decide()` in shadow: the kernel computed a verdict and
the wrapper threw it away. Stage 3b landed the three-mode flag. **3c is where
the two are joined**: every mutation wrapper's capability gate now runs through
`qmcp_enforce.effective_verdict`, and `qmcp.LifecycleAIManaged:remove` becomes a
Stage 3a tombstone the moment any mode binds the kernel.

WHAT THIS SUITE PROVES, AND WHERE THE REST OF THE PROOF LIVES
-------------------------------------------------------------
The trust boundary splits the evidence three ways, as it has since I-2, and the
split is stated here so no one later tries to move a check to the wrong side:

  - **Here (mcp-control, mocked qubesadmin)** — the whole decision surface. The
    mode ladder, the carve-out, the partial-deploy branches, the tombstone
    transition and the divergence record. This is where the risk lives and where
    the coverage belongs.
  - **`install-stage-3c.sh` (dom0)** — that the staged artifacts BEHAVE, checked
    by running them rather than grepping them (the 3b lesson), and that the
    deployed layout is the one the wrappers load from (the 3a lesson).
  - **The rig, from the AI seat** — that arming a mode changes what an agent can
    actually do, and that a tombstoned qube is gone from AI's world. The tier and
    tombstone tags are outside `qmcp_scope.QMCP_TAG_VOCABULARY`, so the seat
    CANNOT read them; whether the strip really happened is a `qvm-tags` read in
    dom0, exactly as I-5's slot-62 proved the create-path strip.

**The teeth in §0 and §9 are the point.** A suite that asserts only the new
behaviour passes just as happily against code that never had the bug, so every
fix in this stage is first shown to be necessary — the pre-fix predicate is
reconstructed and the hole is reproduced — and only then shown to be closed.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import types
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(os.path.dirname(HERE), "dom0-rpc")

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


def _load_lib(modname):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(DOM0_RPC, modname + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


caps = _load_lib("qmcp_caps")
enforce = _load_lib("qmcp_enforce")
tomb = _load_lib("qmcp_tombstone")
tier = _load_lib("qmcp_tier")
birth = _load_lib("qmcp_birth")


# --------------------------------------------------------------------------
# Mocked qubesadmin — the same shape Stage 2's wiring suite uses, because the
# propagations it models (clone copies tags, CreateDisposable inherits them)
# are properties of Qubes and not of a stage.
# --------------------------------------------------------------------------

class FakeVolume:
    def __init__(self, size):
        self.size = size

    def resize(self, n):
        self.size = int(n)


class FakeVM:
    def __init__(self, name, klass="AppVM", tags=(), netvm=None,
                 template_for_dispvms=False, provides_network=False,
                 running=False):
        self.name = name
        self.klass = klass
        self.tags = set(tags)
        self.netvm = netvm
        self.template_for_dispvms = template_for_dispvms
        self.provides_network = provides_network
        self.template = None
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


class FakeDomains(dict):
    def __delitem__(self, k):
        dict.__delitem__(self, k)


class FakeApp:
    def __init__(self, vms):
        self.domains = FakeDomains({v.name: v for v in vms})

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
    loader = SourceFileLoader("w_" + name.replace(".", "_"),
                              os.path.join(DOM0_RPC, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


#: I-6's empty consent policy. `qmcp_consent.consent_required` fail-closes when
#: this file is ABSENT — gating Lifecycle remove/kill and both device ops — so
#: without it every remove in this suite would refuse for an I-6 reason and none
#: of the tombstone assertions would mean anything. That is not a workaround:
#: the installer ships the empty policy BEFORE the wrappers precisely because
#: the two are only byte-neutral together (see `qmcp_consent`'s INSTALL
#: INVARIANT). I-6's own semantics are covered by `offline-validate-I-6.py`;
#: here the file exists so that consent is out of the way.
_POLICY = tempfile.NamedTemporaryFile("w", suffix=".consent-policy",
                                      delete=False)
_POLICY.write("# empty — nothing gated (I-6)\n")
_POLICY.close()
EMPTY_POLICY = _POLICY.name


def with_empty_consent_policy(mod):
    """Point the wrapper's consent helper at the empty policy, keeping the
    real parser and the real (service, action) lookup."""
    c = mod._CONSENT
    mod._CONSENT.gate = lambda svc, act, summary: (
        (False, "unavailable")
        if c.consent_required(svc, act, policy_path=EMPTY_POLICY)
        else (True, "open"))


class Recorder:
    """Captures the audit call so the divergence record can be asserted."""

    def __init__(self):
        self.kw = {}
        self.calls = 0

    def audit(self, service, summary, ok, error=None, **kw):
        self.kw = kw
        self.calls += 1
        return True


#: Explicit tier tags on every fixture. `qmcp_tier` reads `/etc/qmcp/tier-default`
#: for an UNTIERED umbrella qube, and that file's presence differs between this
#: host and the rig — so a fixture relying on the compat default would give a
#: different answer in the two places and neither would be wrong. Every qube
#: below states its tier, and §1 asserts that this is so.
FULL = {"ai-managed", "ai-full"}
EXEC = {"ai-managed", "ai-exec"}
NET = {"ai-managed", "ai-net"}


def fleet():
    return [
        FakeVM("sys-firewall"),
        FakeVM("ai-net-router", tags={"ai-managed", "ai-net"},
               provides_network=True),
        FakeVM("mcp-control"),
        FakeVM("ai-debian-13", klass="TemplateVM", tags=FULL),
        FakeVM("full-work", tags=FULL),
        FakeVM("exec-work", tags=EXEC),
        FakeVM("net-work", tags=NET),
        FakeVM("guarded-work", tags=FULL | {"qmcp-guarded"}),
        FakeVM("outsider"),
    ]


class _StubBudget:
    def check_private_size(self, *a, **kw):
        return None

    def check_cap_for_create(self, *a, **kw):
        return None

    def acquire_create_lock(self, *a, **kw):
        return -1

    def dvmt_private_bytes(self, *a, **kw):
        return 2 * 1024 ** 3


def run(name, request, vms, *, mode=None, patch=None, guarded=None):
    """Run one wrapper's main() at `mode`. Returns (response, app, recorder).

    `mode` is injected by replacing `qmcp_enforce.read_mode` rather than by
    writing the operator file, and that division is deliberate: 3b's suite owns
    the FILE semantics (91 checks over absent / malformed / unreadable / the
    0644 trap) and this suite owns what the wrapper DOES with the resolved word.
    Testing the file here a second time would duplicate 3b's coverage while
    leaving `_gate`'s own matrix no better covered. §7 is the exception — the
    partial-deploy branch reads the path itself, so it gets the real file.
    """
    app = install_fake_qubesadmin(vms)
    mod = load_wrapper(name)
    rec = Recorder()
    mod._AUDIT = rec
    mod._load_budget_lib = lambda: _StubBudget()
    with_empty_consent_policy(mod)
    if mode is not None:
        mod._ENFORCE.read_mode = lambda *a, **kw: mode
        mod._MODE = None
    if guarded is not None:
        mod._CAPS.GUARDED_LIST_PATH = guarded
        _orig = mod._CAPS.decide
        mod._CAPS.decide = (
            lambda *a, **kw: _orig(*a, **dict(kw, guarded_list_path=guarded)))
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
    return json.loads(raw or "{}"), app, rec


LIFE = "qmcp.LifecycleAIManaged"
SETP = "qmcp.SetPropertyAIManaged"
SETF = "qmcp.SetFeatureAIManaged"

SHADOW, STRICT, ENFORCE = enforce.SHADOW, enforce.STRICT, enforce.ENFORCE
MODES = (SHADOW, STRICT, ENFORCE)


# ==========================================================================
print("\n=== 0. Teeth: every fix is shown NECESSARY before it is shown made ===")
# ==========================================================================

# T1 — the netvm:null carve-out. Reconstruct Stage 1's predicate (flat
# escalation, no value) and show it refuses the disconnect that both wrappers
# permit. Measured on the rig 2026-08-19: the shadow log carries `netvm` writes
# with ok:true AFTER F-2 landed, which is this carve-out being exercised — so
# arming a mode against the Stage 1 model would have deleted a live capability.
def _stage1_escalation(prop, params):
    """Stage 1's check, verbatim: the property alone decides."""
    return prop in caps.ESCALATION_PROPS


check("teeth: the PRE-FIX kernel refuses `netvm = null` (the hole this closes)",
      _stage1_escalation("netvm", {"value": None}) is True,
      "if this passes, the carve-out below proves nothing")
check("teeth: ...and the shipped kernel does not",
      caps._is_disconnect("netvm", {"value": None}) is True)

# T2 — the tombstone. If the mock let `entomb` "succeed" without moving tags,
# every tombstone assertion below would be vacuous.
_probe = FakeVM("probe", tags=FULL | {"qmcp-owner_mcp-control"})
_io = birth.TagIO.for_vm(_probe)
tomb.entomb(_io, tier.QMCP_TIER_TAGS, when=1_700_000_000,
            umbrella=tier.UMBRELLA, is_halted=lambda: True)
check("teeth: the mock's TagIO really mutates tags (entomb is not a no-op)",
      tier.UMBRELLA not in _probe.tags
      and any(t.startswith(tomb.TOMBSTONE_PREFIX) for t in _probe.tags),
      str(sorted(_probe.tags)))
_running = FakeVM("live", tags=FULL, running=True)
try:
    tomb.entomb(birth.TagIO.for_vm(_running), tier.QMCP_TIER_TAGS,
                when=1, umbrella=tier.UMBRELLA,
                is_halted=lambda: not _running.is_running())
    _halt_enforced = False
except Exception:
    _halt_enforced = True
check("teeth: entomb refuses an unhalted qube (a live invisible qube is worse)",
      _halt_enforced and tier.UMBRELLA in _running.tags)


# ==========================================================================
print("\n=== 1. Fixtures state their own tier (no reliance on tier-default) ===")
# ==========================================================================

# Every gated fixture states its tier EXPLICITLY. `qmcp_tier` consults
# `/etc/qmcp/tier-default` only for an untiered umbrella qube, and that file is
# absent here and `ro` on the rig — so a fixture leaning on the compat default
# would resolve differently in the two places and neither answer would be wrong.
# Asserting the fixtures rather than the default is what makes every verdict
# below portable.
for name, want in (("full-work", "full"), ("exec-work", "exec"),
                   ("net-work", "net")):
    vm = {v.name: v for v in fleet()}[name]
    caps_for = tier.effective_capabilities(vm)
    check(f"{name}: tier resolves from its own tags ({tier.tier_label(vm)})",
          want in caps_for, f"caps={sorted(caps_for)}")
check("no gated fixture relies on the tier-default compat fallback",
      all(v.tags & (set(tier.QMCP_TIER_TAGS) - {tier.UMBRELLA})
          for v in fleet()
          if tier.UMBRELLA in v.tags and v.name != "ai-net-router"),
      "an untiered fixture would answer differently here and on the rig")


# ==========================================================================
print("\n=== 2. INVARIANCE — with no operator file, 3c changes nothing ===")
# ==========================================================================

# The shipped default. `read_mode` is NOT stubbed here: the real function reads
# the real (absent) path, so this is the state a fresh install lands in.
_fresh = load_wrapper(LIFE)
check("a wrapper with no operator file resolves to SHADOW",
      _fresh._enforce_mode() == SHADOW, _fresh._enforce_mode())
check("...and _enforcing() is False, so every armed side effect stays dormant",
      _fresh._enforcing() is False)

INVARIANT_CASES = [
    (LIFE, {"name": "full-work", "action": "start"}),
    (LIFE, {"name": "exec-work", "action": "start"}),
    (LIFE, {"name": "net-work", "action": "shutdown"}),
    (LIFE, {"name": "outsider", "action": "start"}),
    (LIFE, {"name": "nope", "action": "start"}),
    (SETP, {"name": "full-work", "property": "memory", "value": "400"}),
    (SETP, {"name": "exec-work", "property": "memory", "value": "400"}),
    (SETF, {"name": "full-work", "feature": "appmenus-dispvm", "value": "1"}),
]
for svc, req in INVARIANT_CASES:
    r, _, rec = run(svc, req, fleet())          # real read_mode => shadow
    check(f"shadow: {svc.split('.')[-1]}({req.get('action') or req.get('property') or req.get('feature')} on {req['name']}) unchanged",
          "shadow" not in rec.kw or rec.kw["shadow"] is None
          or "mode" not in (rec.kw.get("shadow") or {}),
          str(rec.kw.get("shadow")))

# The dominated remove: refused under shadow, and a REAL delete, not a tombstone.
r, app, rec = run(LIFE, {"name": "full-work", "action": "remove"}, fleet(),
                  mode=SHADOW)
check("shadow: a CAP_FULL remove still DELETES (no tombstone at install)",
      r.get("ok") is True and "full-work" not in app.domains, str(r))
r, app, rec = run(LIFE, {"name": "exec-work", "action": "remove"}, fleet(),
                  mode=SHADOW)
check("shadow: a CAP_EXEC remove is still refused by the wrapper's own gate",
      r.get("ok") is not True and "exec-work" in app.domains, str(r))
check("shadow: ...and the divergence IS logged, in Stage 1's exact shape",
      set(rec.kw.get("shadow") or {}) == {"kernel", "rule", "wrapper"}
      and rec.kw["shadow"]["rule"] == "dominated:exec",
      str(rec.kw.get("shadow")))


# ==========================================================================
print("\n=== 3. STRICT — every narrowing, and provably no widening ===")
# ==========================================================================

# The property that makes `strict` the safe fail-closed target: its allow set is
# a SUBSET of shadow's. Asserted over the matrix rather than argued in prose.
MATRIX = [
    (LIFE, {"name": "full-work", "action": "start"}),
    (LIFE, {"name": "full-work", "action": "remove"}),
    (LIFE, {"name": "exec-work", "action": "start"}),
    (LIFE, {"name": "exec-work", "action": "remove"}),
    (LIFE, {"name": "exec-work", "action": "kill"}),
    (LIFE, {"name": "exec-work", "action": "unpause"}),
    (LIFE, {"name": "net-work", "action": "start"}),
    (SETP, {"name": "full-work", "property": "memory", "value": "400"}),
    (SETP, {"name": "full-work", "property": "netvm", "value": "ai-net-router"}),
    (SETP, {"name": "full-work", "property": "netvm", "value": None}),
    (SETP, {"name": "exec-work", "property": "memory", "value": "400"}),
    (SETF, {"name": "full-work", "feature": "appmenus-dispvm", "value": "1"}),
    # The narrowing that is visible END TO END: `name` is settable today and is
    # escalation-class to the kernel (renaming the gateway severs every policy
    # line naming it literally). Without a case like this, §3's
    # "enforce genuinely narrows" check would pass vacuously — the netvm cases
    # are refused by the F-2 wrapper guard in every mode, so they show no delta.
    (SETP, {"name": "full-work", "property": "name", "value": "renamed"}),
]


def allow_set(mode):
    out = set()
    for i, (svc, req) in enumerate(MATRIX):
        r, _, _ = run(svc, req, fleet(), mode=mode)
        if r.get("ok") is True:
            out.add(i)
    return out


A_SHADOW = allow_set(SHADOW)
A_STRICT = allow_set(STRICT)
A_ENFORCE = allow_set(ENFORCE)

check("strict allows nothing shadow refuses (no widening, by construction)",
      A_STRICT <= A_SHADOW,
      f"widened: {sorted(A_STRICT - A_SHADOW)}")
check("strict allows nothing enforce refuses (it is the INTERSECTION)",
      A_STRICT <= A_ENFORCE, f"extra: {sorted(A_STRICT - A_ENFORCE)}")
check("strict is the intersection exactly, not merely a subset",
      A_STRICT == (A_SHADOW & A_ENFORCE),
      f"shadow={sorted(A_SHADOW)} strict={sorted(A_STRICT)} enforce={sorted(A_ENFORCE)}")
check("enforce genuinely WIDENS somewhere (else the three-mode design is moot)",
      bool(A_ENFORCE - A_SHADOW),
      "the dominated lifecycle ops are the widening 3a's tombstone exists for")
check("...and genuinely NARROWS somewhere too (the bidirectionality)",
      bool(A_SHADOW - A_ENFORCE))

# The narrowing that matters most: the escalation class stops being writable.
r, app, _ = run(SETP, {"name": "full-work", "property": "netvm",
                       "value": "ai-net-router"}, fleet(), mode=STRICT)
check("strict: a netvm RETARGET is refused",
      r.get("ok") is not True, str(r))
r, _, _ = run(SETP, {"name": "full-work", "property": "name",
                     "value": "renamed"}, fleet(), mode=STRICT)
check("strict: a rename is refused (the gateway-severing escalation)",
      r.get("ok") is not True, str(r))

# The widening that must NOT arrive with strict.
r, app, _ = run(LIFE, {"name": "exec-work", "action": "remove"}, fleet(),
                mode=STRICT)
check("strict: the dominated remove is still REFUSED at CAP_EXEC",
      r.get("ok") is not True and "exec-work" in app.domains, str(r))


# ==========================================================================
print("\n=== 4. ENFORCE — the widening arrives WITH the tombstone ===")
# ==========================================================================

r, app, rec = run(LIFE, {"name": "exec-work", "action": "remove"}, fleet(),
                  mode=ENFORCE)
check("enforce: the dominated remove at CAP_EXEC is ALLOWED (anti-theatre)",
      r.get("ok") is True, str(r))
check("enforce: ...and the qube is NOT deleted — it is entombed",
      "exec-work" in app.domains, "an irreversible remove is the failure mode")
_t = app.domains["exec-work"].tags
check("enforce: the tombstone marker is present and datable",
      any(x.startswith(tomb.TOMBSTONE_PREFIX) and x[len(tomb.TOMBSTONE_PREFIX):].isdigit()
          for x in _t), str(sorted(_t)))
check("enforce: the umbrella is gone, so AI can no longer see it",
      tier.UMBRELLA not in _t, str(sorted(_t)))
check("enforce: every tier tag is gone with it",
      not (_t & set(tier.QMCP_TIER_TAGS)), str(sorted(_t)))
check("enforce: the tombstone still counts against the pool cap",
      _load_lib("qmcp_budget").counts_toward_cap(_t) is True,
      "an uncharged tombstone re-opens the create/remove churn bypass")
check("enforce: the divergence record names the mode and who won",
      set(rec.kw.get("shadow") or {}) == {"kernel", "rule", "wrapper", "mode",
                                          "effective"}
      and rec.kw["shadow"]["mode"] == ENFORCE
      and rec.kw["shadow"]["effective"] == enforce.ALLOW,
      str(rec.kw.get("shadow")))

# A CAP_FULL remove is recoverable too — under BOTH enforcing modes. A rollout
# step where the stricter mode destroys irreversibly and the looser one does not
# would be backwards.
for mode in (STRICT, ENFORCE):
    r, app, _ = run(LIFE, {"name": "full-work", "action": "remove"}, fleet(),
                    mode=mode)
    check(f"{mode}: a CAP_FULL remove is a tombstone too, not a delete",
          r.get("ok") is True and "full-work" in app.domains
          and tier.UMBRELLA not in app.domains["full-work"].tags, str(r))

# Running qubes: entomb refuses, and the wrapper must report its ordinary
# opaque failure rather than deleting anything.
_vms = fleet()
{v.name: v for v in _vms}["full-work"]._running = True
r, app, _ = run(LIFE, {"name": "full-work", "action": "remove"}, _vms,
                mode=ENFORCE)
check("enforce: removing a RUNNING qube fails, and fails opaquely",
      r.get("ok") is not True and r.get("error") == "action failed"
      and "full-work" in app.domains and tier.UMBRELLA in app.domains["full-work"].tags,
      str(r))

# The tombstone helpers missing must NOT fall back to an irreversible delete.
r, app, _ = run(LIFE, {"name": "full-work", "action": "remove"}, fleet(),
                mode=ENFORCE,
                patch=lambda m: setattr(m, "_TOMB", None))
check("enforce: helpers missing => refuse, never fall back to a real delete",
      r.get("ok") is not True and "full-work" in app.domains, str(r))
check("...and the refusal is the wrapper's ordinary opaque string",
      r.get("error") == "action failed", str(r))


# ==========================================================================
print("\n=== 5. The `netvm = null` carve-out survives every mode ===")
# ==========================================================================

for mode in MODES:
    r, app, _ = run(SETP, {"name": "full-work", "property": "netvm",
                           "value": None}, fleet(), mode=mode)
    check(f"{mode}: `netvm = null` (de-escalation) is permitted",
          r.get("ok") is True, str(r))
    r, app, _ = run(SETP, {"name": "full-work", "property": "netvm",
                           "value": "ai-net-router"}, fleet(), mode=mode)
    check(f"{mode}: a netvm RETARGET is refused",
          r.get("ok") is not True, str(r))

# The carve-out is authority-bearing, not a bypass: it is exempt from the
# escalation class, never from the ladder.
r, _, _ = run(SETP, {"name": "exec-work", "property": "netvm", "value": None},
              fleet(), mode=STRICT)
check("the carve-out does not let a CAP_EXEC actor disconnect a qube",
      r.get("ok") is not True, str(r))

# Omitting `value` entirely is the wrapper's own "disconnect" spelling, and the
# kernel must agree with it rather than with a stricter reading of its own.
r, _, _ = run(SETP, {"name": "full-work", "property": "netvm"}, fleet(),
              mode=ENFORCE)
check("an OMITTED value reads as null in the kernel exactly as in the wrapper",
      r.get("ok") is True, str(r))


# ==========================================================================
print("\n=== 6. GATE is not an allow (Stage 7's channel is not armed) ===")
# ==========================================================================

with tempfile.NamedTemporaryFile("w", suffix=".guarded", delete=False) as fh:
    fh.write("guarded-work\n")
    GUARDED = fh.name

check("kernel: a guarded target returns GATE, not ALLOW",
      caps.decide("mcp-control", LIFE, "start",
                  {"target": FakeVM("guarded-work", tags=FULL | {"qmcp-guarded"})},
                  {}, guarded_list_path=GUARDED).verdict == caps.GATE)
check("enforce: a GATE verdict is treated as a refusal, never a pass",
      enforce.effective_verdict(ENFORCE, True, caps.GATE) != enforce.ALLOW)
r, _, _ = run(LIFE, {"name": "guarded-work", "action": "start"}, fleet(),
              mode=ENFORCE, guarded=GUARDED)
check("enforce: the wrapper refuses a guarded target end to end",
      r.get("ok") is not True, str(r))
check("shadow: the same target is UNAFFECTED (Stage 7 is not armed yet)",
      run(LIFE, {"name": "guarded-work", "action": "start"}, fleet(),
          mode=SHADOW, guarded=GUARDED)[0].get("ok") is True)
os.unlink(GUARDED)


# ==========================================================================
print("\n=== 7. Partial deploy — 3c wrappers without qmcp_enforce.py ===")
# ==========================================================================
# The F9 split-brain family, and the same shape as the additive-kwarg blackout
# that silently killed the I-2 audit line. Neither constant default is safe, so
# the branch reads the operator's own file. This is the ONE place the suite uses
# the real path, because it is the real path that is under test.

with tempfile.TemporaryDirectory() as td:
    missing = os.path.join(td, "enforce-mode")     # does not exist
    present = os.path.join(td, "enforce-mode-present")
    with open(present, "w", encoding="utf-8") as fh:
        fh.write("enforce\n")

    def _strip(path):
        def _p(m):
            m._ENFORCE = None
            m._MODE = None
            m._MODE_PATH = path
        return _p

    r, app, rec = run(LIFE, {"name": "full-work", "action": "start"}, fleet(),
                      patch=_strip(missing))
    check("module missing + flag ABSENT => shadow: the wrapper behaves as Stage 1",
          r.get("ok") is True, str(r))
    check("...and logs nothing, so an absence never invents a divergence",
          rec.kw.get("shadow") is None, str(rec.kw.get("shadow")))

    r, app, _ = run(LIFE, {"name": "full-work", "action": "start"}, fleet(),
                    patch=_strip(present))
    check("module missing + flag PRESENT => refuse (the operator DID ask)",
          r.get("ok") is not True, str(r))

    r, app, _ = run(LIFE, {"name": "exec-work", "action": "remove"}, fleet(),
                    patch=_strip(present))
    check("...and the refusal cannot arm a widening: no tombstone, no delete",
          r.get("ok") is not True and "exec-work" in app.domains
          and tier.UMBRELLA in app.domains["exec-work"].tags, str(r))

# The kernel missing while a mode is armed: fail closed, never fall through.
r, app, _ = run(LIFE, {"name": "full-work", "action": "start"}, fleet(),
                mode=ENFORCE, patch=lambda m: setattr(m, "_CAPS", None))
check("kernel missing + enforcing => refuse (an unreadable opinion is no allow)",
      r.get("ok") is not True, str(r))
r, app, rec = run(LIFE, {"name": "full-work", "action": "start"}, fleet(),
                  mode=SHADOW, patch=lambda m: setattr(m, "_CAPS", None))
check("kernel missing + shadow => unchanged AND unlogged (Stage 1's promise)",
      r.get("ok") is True and rec.kw.get("shadow") is None, str(rec.kw))


# ==========================================================================
print("\n=== 8. The divergence record: two modes, two questions ===")
# ==========================================================================

# Under shadow the record answers "would the kernel have decided otherwise?" —
# the log the flip is gated on. Under an enforcing mode it answers "did
# enforcement CHANGE the outcome?", which is a different and smaller set.
r, _, rec_shadow = run(SETP, {"name": "full-work", "property": "netvm",
                              "value": "ai-net-router"}, fleet(), mode=SHADOW)
check("shadow: a retarget diverges even though the wrapper refuses it later",
      (rec_shadow.kw.get("shadow") or {}).get("rule") == "escalation-class",
      str(rec_shadow.kw.get("shadow")))
check("shadow: the record carries NO mode/effective keys (Stage 1's shape)",
      set(rec_shadow.kw["shadow"]) == {"kernel", "rule", "wrapper"})

# The record is GATE-LOCAL, and saying so is the point of this block. Under
# strict the same retarget still records, because at the capability gate the
# wrapper WOULD have continued and enforcement stopped it. That the call would
# also have been refused thirty lines later by the F-2 netvm guard is true and
# unknowable here — `wrapper` has always meant "this wrapper's verdict AT THIS
# GATE", since Stage 1. Reading it as an end-to-end verdict over-counts, which
# is exactly how the rig's shadow log reads today: 22 escalation-class lines, of
# which only the `ok: true` ones are outcomes that would actually change.
r, _, rec_strict = run(SETP, {"name": "full-work", "property": "netvm",
                              "value": "ai-net-router"}, fleet(), mode=STRICT)
check("strict: a retarget records — enforcement DID change the gate's outcome",
      (rec_strict.kw.get("shadow") or {}).get("effective") == enforce.DENY
      and rec_strict.kw["shadow"]["wrapper"] == enforce.ALLOW,
      str(rec_strict.kw.get("shadow")))

# Agreement is silent in every mode — otherwise the log is noise and the flip
# gate cannot be read.
for mode in MODES:
    _, _, rec_ok = run(SETP, {"name": "full-work", "property": "memory",
                              "value": "400"}, fleet(), mode=mode)
    check(f"{mode}: an op both sides ALLOW writes no divergence key",
          rec_ok.kw.get("shadow") is None, str(rec_ok.kw.get("shadow")))
    _, _, rec_no = run(LIFE, {"name": "outsider", "action": "start"}, fleet(),
                       mode=mode)
    check(f"{mode}: an op both sides REFUSE writes no divergence key",
          rec_no.kw.get("shadow") is None, str(rec_no.kw.get("shadow")))

# No free text, no request values, in either shape. The I-2 caller-sanitises
# contract does not relax because the record grew two keys.
r, _, rec = run(SETP, {"name": "full-work", "property": "name",
                       "value": "SECRETNAME"}, fleet(), mode=STRICT)
check("no request value ever reaches the divergence record",
      "SECRETNAME" not in json.dumps(rec.kw.get("shadow") or {}),
      str(rec.kw.get("shadow")))
check("...and no kernel `reason` prose either — fixed vocabulary only",
      set(rec.kw.get("shadow") or {}) <= {"kernel", "rule", "wrapper", "mode",
                                          "effective"},
      str(rec.kw.get("shadow")))


# ==========================================================================
print("\n=== 9. Teeth: reverting any half of this stage re-opens a hole ===")
# ==========================================================================

# T3 — a `_gate` that ignored the mode (i.e. always enforced) would arm the
# widening at install. Reconstruct that and show the invariance check catches it.
r, app, _ = run(LIFE, {"name": "exec-work", "action": "remove"}, fleet(),
                mode=SHADOW,
                patch=lambda m: setattr(
                    m, "_gate", lambda a, ro, p, w: True))
check("teeth: a mode-blind gate WOULD allow the dominated remove under shadow",
      r.get("ok") is True,
      "so §2's invariance check is load-bearing, not decorative")

# T4 — a tombstone armed at INSTALL rather than with enforcement would break
# byte-neutrality. Reconstruct the "always tombstone" predicate.
r, app, _ = run(LIFE, {"name": "full-work", "action": "remove"}, fleet(),
                mode=SHADOW,
                patch=lambda m: setattr(m, "_enforcing", lambda: True))
check("teeth: an install-armed tombstone WOULD change shadow's behaviour",
      "full-work" in app.domains,
      "so the _enforcing() coupling is what keeps the install byte-neutral")

# T5 — the three verdict literals must agree across the two modules, or
# `effective_verdict` silently compares strings that never match.
check("teeth: qmcp_enforce and qmcp_caps agree on all three verdict literals",
      (enforce.ALLOW, enforce.DENY, enforce.GATE)
      == (caps.ALLOW, caps.DENY, caps.GATE))

# T6 — `_gate` must be byte-identical in all 8 wrappers. Eight hand-maintained
# copies of a security decision is how one of them silently lags.
import hashlib   # noqa: E402  (used only here)

WRAPPERS = [LIFE, SETP, SETF, "qmcp.CloneAIManagedQube",
            "qmcp.SpawnAIManagedQube", "qmcp.SpawnDisposableAIManaged",
            "qmcp.AttachDeviceAIManaged", "qmcp.DetachDeviceAIManaged"]
_hashes = set()
for w in WRAPPERS:
    src = open(os.path.join(DOM0_RPC, w), encoding="utf-8").read()
    blk = src[src.index("def _gate("):
              src.index("    return allowed") + len("    return allowed")]
    _hashes.add(hashlib.sha256(blk.encode()).hexdigest())
check(f"teeth: _gate is byte-identical across all {len(WRAPPERS)} wrappers",
      len(_hashes) == 1, f"{len(_hashes)} distinct copies")

# T7 — and every one of them actually calls it. A wrapper carrying the helper
# but no call site is the silent half of a partial flip.
for w in WRAPPERS:
    src = open(os.path.join(DOM0_RPC, w), encoding="utf-8").read()
    body = src[src.index("def main("):]
    check(f"teeth: {w.split('.')[-1]} calls _gate from main()",
          "_gate(" in body, "helper present but never consulted")


# --------------------------------------------------------------------------
print(f"\n{'=' * 70}")
print(f"Stage 3c offline validation: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
