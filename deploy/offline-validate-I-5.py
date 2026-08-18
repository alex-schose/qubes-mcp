#!/usr/bin/env python3
"""offline-validate-I-5.py — exhaustive offline validation of Stage I-5
(tiers on the @adminvm wrapper surfaces + the policy exec-tier diff).

Ships in public/deploy/ alongside the test-stage-*.py harnesses. Mirrors
offline-validate-I-{2,3,4}.py: a mocked-qubesadmin harness that loads the
REAL extension-less wrappers via SourceFileLoader, drives main() with JSON on
stdin, and asserts on the response. This is where the bulk of I-5 coverage
lives (the slot only confirms the real qrexec daemon + dom0 agree on hardware).

What it proves:
  1. Each of the 8 @adminvm wrappers GATES on CAP_FULL of the right qube
     (target / source / template / DVMT / both device endpoints).
  2. The gate is BEHAVIOUR-NEUTRAL in compat: an untiered ai-managed qube
     resolves to ai-full (flag absent), so every prior-stage happy path still
     passes — the A–F3 regression cannot break from I-5.
  3. The gate is FAIL-CLOSED: a missing tier resolver (_TIER is None) denies.
  4. The refusal is OPAQUE: a tier refusal is byte-identical to the untagged
     refusal that surface already returns — no tier-probing oracle.
  5. Attach/Detach require CAP_FULL on BOTH endpoints.
  6. Tier refusals still route through emit() (so they are AUDITED, not
     silently dropped).
  7. HELPER-LEVEL flip bridge: an untiered qube LOSES CAP_FULL once
     /etc/qmcp/tier-default reads "ro" — so post-flip the wrappers (which deny
     when has_capability is False, proven above) deny untiered qubes. This ties
     the wrapper gate to the operator flip without writing to /etc.

Run from the repo root:   .venv/bin/python deploy/offline-validate-I-5.py
or from inside public/:   python3 deploy/offline-validate-I-5.py
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
# use), so it runs from the repo root AND from inside public/.
HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(HERE, os.pardir, "dom0-rpc")

NOT_FOUND = {"ok": False, "error": "not found"}
SPAWN_OPAQUE = "template must reference an ai-managed qube"

_passed = 0
_failed = 0


def check(label, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")


# --------------------------------------------------------------------------
# Mock qubesadmin
# --------------------------------------------------------------------------
class FakeTags:
    def __init__(self, items):
        self._s = set(items)

    def __contains__(self, x):
        return x in self._s

    def __iter__(self):
        return iter(self._s)

    def add(self, x):
        self._s.add(x)

    def discard(self, x):
        self._s.discard(x)


class FakeVolume:
    def __init__(self, size):
        self.size = size

    def resize(self, n):
        self.size = int(n)


class FakeVM:
    def __init__(self, name, klass="AppVM", tags=(), provides_network=False,
                 template_for_dispvms=False):
        self.name = name
        self.klass = klass
        self.tags = FakeTags(tags)
        self.provides_network = provides_network
        self.template_for_dispvms = template_for_dispvms
        self.netvm = None
        self.volumes = {"private": FakeVolume(2 * 1024**3),
                        "root": FakeVolume(10 * 1024**3),
                        "volatile": FakeVolume(1 * 1024**3)}
        self.features = {}
        self._running = False

    # lifecycle no-ops
    def start(self): self._running = True
    def shutdown(self): self._running = False
    def kill(self): self._running = False
    def pause(self): pass
    def unpause(self): pass
    def is_running(self): return self._running


class FakeDomains:
    def __init__(self, vms):
        self._d = {vm.name: vm for vm in vms}

    def __contains__(self, name): return name in self._d
    def __getitem__(self, name): return self._d[name]
    def __setitem__(self, name, vm): self._d[name] = vm
    def __delitem__(self, name): del self._d[name]
    def __iter__(self): return iter(self._d)
    def values(self): return self._d.values()


class FakeApp:
    def __init__(self, vms):
        self.domains = FakeDomains(vms)
        self._disp_counter = 9000

    def add_new_vm(self, klass, name, label, template=None):
        vm = FakeVM(name, klass=klass)
        self.domains[name] = vm
        return vm

    def clone_vm(self, src_vm, name):
        # FAITHFUL to qubesadmin QubesBase.clone_vm: copies EVERY source tag
        # except created-by-*. Modelling this is the whole point — the original
        # mock returned a tagless clone and so could not see the I-5 CRITICAL
        # (clone inherits the source's ai-full). (Review finding, medium.)
        vm = FakeVM(name, klass=src_vm.klass)
        for t in src_vm.tags:
            if not t.startswith("created-by-"):
                vm.tags.add(t)
        self.domains[name] = vm
        return vm

    def qubesd_call(self, vm_name, method, *args):
        if method == "admin.vm.CreateDisposable":
            self._disp_counter += 1
            dname = f"disp{self._disp_counter}"
            d = FakeVM(dname, klass="DispVM")
            # Model slot-16: the disposable INHERITS the DVMT's tags (so an
            # ai-full DVMT yields an ai-full disposable absent the strip).
            for t in self.domains[vm_name].tags:
                d.tags.add(t)
            self.domains[dname] = d
            return dname.encode()
        if method == "admin.vm.tag.Set":
            self.domains[vm_name].tags.add(args[0])
            return b""
        if method == "admin.vm.tag.Remove":
            self.domains[vm_name].tags.discard(args[0])
            return b""
        if method == "admin.vm.tag.List":
            return (" ".join(self.domains[vm_name].tags)).encode()
        if method == "admin.vm.Kill":
            return b""
        return b""


def install_fake_qubesadmin(app):
    qa = types.ModuleType("qubesadmin")
    qa_app = types.ModuleType("qubesadmin.app")
    qa_app.QubesLocal = lambda: app
    qa.app = qa_app
    sys.modules["qubesadmin"] = qa
    sys.modules["qubesadmin.app"] = qa_app


class BudgetStub:
    """Bypass the I-0 budget gate so create-wrapper tests isolate the I-5 tier
    gate (the real budget reads /etc/qmcp/pool-cap, absent in mcp-control)."""
    def check_cap_for_create(self, *a, **k): return None
    def check_private_size(self, *a, **k): return None
    # The create wrappers also call these (cap-gate serialization lock + the
    # disposable footprint estimate); the tier-gate tests don't exercise them,
    # so the stub just keeps them inert (no lock taken; default-floor estimate).
    def acquire_create_lock(self, *a, **k): return -1
    def release_create_lock(self, *a, **k): pass
    def dvmt_private_bytes(self, *a, **k): return 0


class AuditRecorder:
    """Stand-in for the qmcp_audit module: record (ok, error) of every emit()."""
    def __init__(self): self.calls = []
    # `**kw` on purpose: emit() grew `consent` (I-6) and `shadow` (Wave 2
    # Stage 1), and a stub with a fixed signature turns every additive kwarg
    # into a silent audit blackout here — emit()'s best-effort guard swallows
    # the TypeError, `calls` stays empty, and the failure looks like a wrapper
    # bug. Permissive is right for a stub; the REAL audit() signature and its
    # byte-neutral omission are asserted in offline-validate-1-wiring.py §5.
    def audit(self, service, summary, ok, error, consent=None, **kw):
        self.calls.append((ok, error))


def load_wrapper(filename):
    """Load an extension-less wrapper fresh (SourceFileLoader)."""
    path = os.path.join(DOM0_RPC, filename)
    loader = importlib.machinery.SourceFileLoader("wrapper_under_test", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def run(mod, payload):
    out = io.StringIO()
    old = sys.stdin
    sys.stdin = io.StringIO(json.dumps(payload))
    try:
        with contextlib.redirect_stdout(out):
            mod.main()
    finally:
        sys.stdin = old
    return json.loads(out.getvalue().strip())


def prep(mod, *, tier_none=False, stub_budget=False, audit=None):
    """Apply the standard offline overrides to a freshly-loaded wrapper."""
    if tier_none:
        mod._TIER = None
    if stub_budget and hasattr(mod, "_load_budget_lib"):
        mod._load_budget_lib = lambda: BudgetStub()
    mod._AUDIT = audit  # None disables the best-effort audit hook (clean output)
    # Stage I-6 added a consent gate to the 8 @adminvm wrappers; offline (no
    # /etc/qmcp/consent-policy) qmcp_consent.gate() fail-closes to
    # ('unavailable' -> deny), which would spuriously turn every past-the-tier
    # case into NOT_FOUND. This file validates the I-5 TIER logic, not the consent
    # axis (offline-validate-I-6.py covers that), so neutralise the gate to the
    # I-6 empty-gate default (open), mirroring the _AUDIT=None override above.
    if hasattr(mod, "_consent_gate"):
        mod._consent_gate = lambda action: True
    return mod


# Fleet of fixtures, re-created per test so state never leaks.
def fleet():
    return [
        FakeVM("ai-full-vm", tags=("ai-managed", "ai-full")),
        FakeVM("ai-exec-vm", tags=("ai-managed", "ai-exec")),
        FakeVM("ai-ro-vm", tags=("ai-managed",)),            # untiered umbrella
        FakeVM("ai-net-vm", tags=("ai-managed", "ai-net")),
        FakeVM("ai-full-tpl", klass="TemplateVM", tags=("ai-managed", "ai-full")),
        FakeVM("ai-exec-tpl", klass="TemplateVM", tags=("ai-managed", "ai-exec")),
        FakeVM("ai-ro-tpl", klass="TemplateVM", tags=("ai-managed",)),
        FakeVM("ai-full-dvmt", tags=("ai-managed", "ai-full"), template_for_dispvms=True),
        FakeVM("ai-exec-dvmt", tags=("ai-managed", "ai-exec"), template_for_dispvms=True),
        FakeVM("untagged", tags=()),
    ]


def app_with_fleet():
    app = FakeApp(fleet())
    install_fake_qubesadmin(app)
    return app


# ==========================================================================
print("=== Stage I-5 offline validation ===\n")

# --------------------------------------------------------------------------
print("### Section 1 — Lifecycle / SetProperty / SetFeature: CAP_FULL on target")
for fname, payload_for in [
    ("qmcp.LifecycleAIManaged", lambda n: {"name": n, "action": "start"}),
    ("qmcp.SetPropertyAIManaged", lambda n: {"name": n, "property": "memory", "value": 400}),
    ("qmcp.SetFeatureAIManaged", lambda n: {"name": n, "feature": "appmenus-dispvm", "value": True}),
]:
    short = fname.split(".")[1]

    # ai-full target → tier passes → op proceeds (ok=True on the fake VM)
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r = run(m, payload_for("ai-full-vm"))
    check(f"{short}: ai-full target → tier PASS (ok)", r.get("ok") is True)

    # untiered target (compat = full) → tier passes → behaviour-neutral
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r = run(m, payload_for("ai-ro-vm"))
    check(f"{short}: untiered target compat=full → PASS (behaviour-neutral)", r.get("ok") is True)

    # ai-exec target (lacks full) → opaque NOT_FOUND
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r = run(m, payload_for("ai-exec-vm"))
    check(f"{short}: ai-exec target → tier DENY (opaque NOT_FOUND)", r == NOT_FOUND)

    # fail-closed: missing resolver → NOT_FOUND even for ai-full
    app_with_fleet()
    m = prep(load_wrapper(fname), tier_none=True)
    r = run(m, payload_for("ai-full-vm"))
    check(f"{short}: _TIER=None → FAIL-CLOSED (NOT_FOUND)", r == NOT_FOUND)

    # opacity: ai-exec refusal byte-identical to untagged refusal
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r_under = run(m, payload_for("ai-exec-vm"))
    app_with_fleet()
    m2 = prep(load_wrapper(fname))
    r_untag = run(m2, payload_for("untagged"))
    check(f"{short}: under-tier refusal == untagged refusal (no oracle)",
          r_under == r_untag == NOT_FOUND)

# --------------------------------------------------------------------------
print("\n### Section 2 — Clone: CAP_FULL on the SOURCE")
fname = "qmcp.CloneAIManagedQube"
for src, expect_pass, lbl in [
    ("ai-full-vm", True, "ai-full source → PASS"),
    ("ai-ro-vm", True, "untiered source compat=full → PASS"),
    ("ai-exec-vm", False, "ai-exec source → DENY"),
]:
    app_with_fleet()
    m = prep(load_wrapper(fname), stub_budget=True)
    r = run(m, {"source": src, "name": "clone-x"})
    if expect_pass:
        check(f"Clone: {lbl}", r.get("ok") is True)
    else:
        check(f"Clone: {lbl} (opaque NOT_FOUND)", r == NOT_FOUND)
# fail-closed
app_with_fleet()
m = prep(load_wrapper(fname), stub_budget=True, tier_none=True)
r = run(m, {"source": "ai-full-vm", "name": "clone-y"})
check("Clone: _TIER=None → FAIL-CLOSED", r == NOT_FOUND)
# opacity
app_with_fleet(); r1 = run(prep(load_wrapper(fname), stub_budget=True), {"source": "ai-exec-vm", "name": "c1"})
app_with_fleet(); r2 = run(prep(load_wrapper(fname), stub_budget=True), {"source": "untagged", "name": "c2"})
check("Clone: under-tier == untagged refusal (no oracle)", r1 == r2 == NOT_FOUND)

# --------------------------------------------------------------------------
print("\n### Section 3 — Spawn: CAP_FULL on the TEMPLATE (opaque cross-ref message)")
fname = "qmcp.SpawnAIManagedQube"
for tpl, expect_pass, lbl in [
    ("ai-full-tpl", True, "ai-full template → PASS"),
    ("ai-ro-tpl", True, "untiered template compat=full → PASS"),
    ("ai-exec-tpl", False, "ai-exec template → DENY"),
]:
    app_with_fleet()
    m = prep(load_wrapper(fname), stub_budget=True)
    r = run(m, {"name": "spawn-x", "template": tpl, "netvm": None})
    if expect_pass:
        check(f"Spawn: {lbl}", r.get("ok") is True)
    else:
        check(f"Spawn: {lbl} (opaque cross-ref msg)", r.get("error") == SPAWN_OPAQUE)
# fail-closed
app_with_fleet()
m = prep(load_wrapper(fname), stub_budget=True, tier_none=True)
r = run(m, {"name": "spawn-y", "template": "ai-full-tpl", "netvm": None})
check("Spawn: _TIER=None → FAIL-CLOSED (cross-ref msg)", r.get("error") == SPAWN_OPAQUE)
# opacity: ai-exec template refusal byte-identical to untagged template refusal
app_with_fleet(); r1 = run(prep(load_wrapper(fname), stub_budget=True),
                           {"name": "s1", "template": "ai-exec-tpl", "netvm": None})
app_with_fleet(); r2 = run(prep(load_wrapper(fname), stub_budget=True),
                           {"name": "s2", "template": "untagged", "netvm": None})
check("Spawn: under-tier template == untagged template refusal (no oracle)",
      r1 == r2 and r1.get("error") == SPAWN_OPAQUE)

# --------------------------------------------------------------------------
print("\n### Section 4 — SpawnDisposable: CAP_FULL on the DVMT")
fname = "qmcp.SpawnDisposableAIManaged"
for dvmt, expect_pass, lbl in [
    ("ai-full-dvmt", True, "ai-full DVMT → PASS"),
    ("ai-exec-dvmt", False, "ai-exec DVMT → DENY"),
]:
    app_with_fleet()
    m = prep(load_wrapper(fname), stub_budget=True)
    r = run(m, {"template": dvmt})
    if expect_pass:
        check(f"SpawnDisposable: {lbl}", r.get("ok") is True)
    else:
        check(f"SpawnDisposable: {lbl} (opaque NOT_FOUND)", r == NOT_FOUND)
app_with_fleet()
m = prep(load_wrapper(fname), stub_budget=True, tier_none=True)
r = run(m, {"template": "ai-full-dvmt"})
check("SpawnDisposable: _TIER=None → FAIL-CLOSED", r == NOT_FOUND)

# --------------------------------------------------------------------------
print("\n### Section 5 — Attach / Detach: CAP_FULL on BOTH endpoints")
for fname in ("qmcp.AttachDeviceAIManaged", "qmcp.DetachDeviceAIManaged"):
    short = fname.split(".")[1]
    base = {"device_class": "block", "device_id": "dev1"}

    # both full → tier passes (reaches the qvm-device-absent check, NOT NOT_FOUND)
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r = run(m, {**base, "backend": "ai-full-vm", "frontend": "ai-full-tpl"})
    check(f"{short}: both ai-full → tier PASS (past gate)", r != NOT_FOUND)

    # backend full, frontend exec → DENY
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r = run(m, {**base, "backend": "ai-full-vm", "frontend": "ai-exec-vm"})
    check(f"{short}: frontend under-tier → DENY", r == NOT_FOUND)

    # backend exec, frontend full → DENY
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r = run(m, {**base, "backend": "ai-exec-vm", "frontend": "ai-full-vm"})
    check(f"{short}: backend under-tier → DENY", r == NOT_FOUND)

    # both untiered (compat=full) → PASS (behaviour-neutral)
    app_with_fleet()
    m = prep(load_wrapper(fname))
    r = run(m, {**base, "backend": "ai-ro-vm", "frontend": "ai-ro-tpl"})
    check(f"{short}: both untiered compat=full → PASS (behaviour-neutral)", r != NOT_FOUND)

    # fail-closed
    app_with_fleet()
    m = prep(load_wrapper(fname), tier_none=True)
    r = run(m, {**base, "backend": "ai-full-vm", "frontend": "ai-full-tpl"})
    check(f"{short}: _TIER=None → FAIL-CLOSED", r == NOT_FOUND)

# --------------------------------------------------------------------------
print("\n### Section 6 — tier refusals route through emit() (so they are AUDITED)")
app_with_fleet()
rec = AuditRecorder()
m = prep(load_wrapper("qmcp.LifecycleAIManaged"), audit=rec)
r = run(m, {"name": "ai-exec-vm", "action": "start"})
check("Lifecycle tier-refusal funneled through emit() → audit saw it",
      r == NOT_FOUND and rec.calls and rec.calls[-1] == (False, "not found"))

# --------------------------------------------------------------------------
print("\n### Section 7 — helper-level flip bridge (untiered loses CAP_FULL post-flip)")
# load qmcp_tier directly (it HAS a .py extension)
spec = importlib.util.spec_from_file_location("qmcp_tier_direct",
                                              os.path.join(DOM0_RPC, "qmcp_tier.py"))
qt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qt)

with tempfile.TemporaryDirectory() as td:
    absent = os.path.join(td, "does-not-exist")
    ro_flag = os.path.join(td, "tier-default-ro")
    full_flag = os.path.join(td, "tier-default-full")
    with open(ro_flag, "w") as f: f.write("ro\n")
    with open(full_flag, "w") as f: f.write("full\n")

    def caps(tags, path):
        return qt.effective_capabilities(tags=set(tags), tier_default_path=path)

    check("compat (flag absent): untiered umbrella → CAP_FULL present",
          qt.CAP_FULL in caps({"ai-managed"}, absent))
    check("flag 'full': untiered umbrella → CAP_FULL present",
          qt.CAP_FULL in caps({"ai-managed"}, full_flag))
    check("flag 'ro' (POST-FLIP): untiered umbrella → CAP_FULL ABSENT",
          qt.CAP_FULL not in caps({"ai-managed"}, ro_flag))
    check("flag 'ro': untiered umbrella keeps CAP_READ (ro floor)",
          qt.CAP_READ in caps({"ai-managed"}, ro_flag))
    check("ai-exec qube: no CAP_FULL regardless of flag",
          qt.CAP_FULL not in caps({"ai-managed", "ai-exec"}, absent)
          and qt.CAP_FULL not in caps({"ai-managed", "ai-exec"}, ro_flag))
    check("ai-full qube: CAP_FULL present regardless of flag",
          qt.CAP_FULL in caps({"ai-managed", "ai-full"}, absent)
          and qt.CAP_FULL in caps({"ai-managed", "ai-full"}, ro_flag))
    # ai-dump disjointness sanity (used by the installer's machine-enforce)
    check("ai-dump is in QMCP_TIER_TAGS (installer keys disjointness off it)",
          qt.TAG_DUMP in qt.QMCP_TIER_TAGS and qt.UMBRELLA in qt.QMCP_TIER_TAGS)

# --------------------------------------------------------------------------
print("\n### Section 8 — create paths must NOT inherit an elevation tag (review CRITICAL/HIGH)")
ELEV = {"ai-exec", "ai-net", "ai-full", "ai-dump"}

# TEETH: prove the mock now MODELS the vulnerability — a raw clone_vm /
# CreateDisposable inherits ai-full. If these fail, the Section-8 strip asserts
# below are vacuous (the medium "false-green" finding). They must PASS.
app_t = FakeApp(fleet())
raw_clone = app_t.clone_vm(app_t.domains["ai-full-vm"], "raw-clone")
check("(teeth) raw clone_vm INHERITS ai-full — mock models the real bug",
      "ai-full" in set(raw_clone.tags))
app_t2 = FakeApp(fleet())
raw_disp = app_t2.qubesd_call("ai-full-dvmt", "admin.vm.CreateDisposable").decode()
check("(teeth) raw CreateDisposable INHERITS ai-full — mock models the real bug",
      "ai-full" in set(app_t2.domains[raw_disp].tags))

# Clone of an ai-full source. **Wave 2 Stage 2 changed the expected answer
# here, and the change is deliberate.** I-5 stripped every create to UNTIERED,
# which held the no-self-escalation keystone but left a created qube with no
# capability at all post-flip (F6) — an operator had to tier it before its
# creator could even start it. D2 replaces the blanket strip with a CLAMP: the
# child is born at the source's literal tier, bounded by the operator's
# `/etc/qmcp/birth-ceiling`. What is preserved is the property that actually
# mattered: nothing is ever born ABOVE its source, and the source's tier is
# operator-assigned because AI cannot write tags. What is given up is the
# blanket strip, on purpose. `birth-ceiling` is absent in this harness, so
# these assert the no-clamp default; the clamp matrix itself lives in
# `offline-validate-2.py`.
app = app_with_fleet()
m = prep(load_wrapper("qmcp.CloneAIManagedQube"), stub_budget=True)
r = run(m, {"source": "ai-full-vm", "name": "clone-esc"})
ctags = set(app.domains["clone-esc"].tags) if "clone-esc" in app.domains else set()
check("Clone(ai-full source) \u2192 ok", r.get("ok") is True)
check("Clone(ai-full source) \u2192 clone keeps ai-managed", "ai-managed" in ctags)
check("Clone(ai-full source) \u2192 born ai-full (D2 clamp, no ceiling set)",
      "ai-full" in ctags)
check("Clone(ai-full source) \u2192 never ABOVE the source: no other elevation tag",
      (ctags & ELEV) == {"ai-full"})
check("Clone \u2192 stamped with the calling principal's ownership",
      any(t.startswith("qmcp-owner") for t in ctags))

# The brief's worked escalation example \u2014 "an ai-exec actor cloning an ai-full
# source gets an ai-exec child" \u2014 is NOT reachable in the shipped model, and
# saying so is more useful than asserting a scenario that cannot occur. There
# is one principal (the gateway) and capability is a property of the TARGET
# qube, so "the actor's tier on the source" IS the source's tier; the two only
# diverge when I-9's principal axis lands. Below ai-full the clone is refused
# outright by the I-5 CAP_FULL gate, so no child exists to be escalated \u2014 a
# stronger property than the clamp, and the one that actually holds. The clamp
# that does real work today is the operator ceiling, exercised across the whole
# ladder in `offline-validate-2.py` \u00a71.
app = app_with_fleet()
m = prep(load_wrapper("qmcp.CloneAIManagedQube"), stub_budget=True)
r = run(m, {"source": "ai-exec-vm", "name": "clone-exec"})
check("Clone(ai-exec source) \u2192 REFUSED by the CAP_FULL gate, no child at all",
      r.get("ok") is not True and "clone-exec" not in app.domains)

# SpawnDisposable from an ai-full DVMT \u2014 same clamp, ephemeral target.
app = app_with_fleet()
m = prep(load_wrapper("qmcp.SpawnDisposableAIManaged"), stub_budget=True)
r = run(m, {"template": "ai-full-dvmt"})
dn = r.get("name")
dtags = set(app.domains[dn].tags) if dn and dn in app.domains else set()
check("SpawnDisposable(ai-full DVMT) \u2192 ok", r.get("ok") is True)
check("SpawnDisposable(ai-full DVMT) \u2192 disposable keeps ai-managed",
      "ai-managed" in dtags)
check("SpawnDisposable(ai-full DVMT) \u2192 born ai-full (D2 clamp)",
      (dtags & ELEV) == {"ai-full"})

# Spawn: `add_new_vm` creates a FRESH qube that inherits nothing, so the tier
# it is born with comes from the clamp rather than from propagation \u2014 the same
# answer by a different route, which is why it is worth asserting separately.
app = app_with_fleet()
m = prep(load_wrapper("qmcp.SpawnAIManagedQube"), stub_budget=True)
r = run(m, {"name": "spawn-esc", "template": "ai-full-tpl", "netvm": None})
stags = set(app.domains["spawn-esc"].tags) if "spawn-esc" in app.domains else set()
check("Spawn(ai-full template) \u2192 ok", r.get("ok") is True)
check("Spawn(ai-full template) \u2192 born ai-full, nothing above it",
      "ai-managed" in stags and (stags & ELEV) == {"ai-full"})
check("Spawn \u2192 stamped with the calling principal's ownership",
      any(t.startswith("qmcp-owner") for t in stags))

# ==========================================================================
print(f"\n=== I-5 offline: {_passed} passed, {_failed} failed ===")
sys.exit(1 if _failed else 0)
