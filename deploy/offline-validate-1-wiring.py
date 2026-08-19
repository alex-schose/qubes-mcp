#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 1 — the WIRING into the 8 wrappers.

`offline-validate-1.py` proves the kernel's lattice. This proves the thing a
shadow stage actually promises: **the kernel cannot change what AI sees.**

The invariance check here is deliberately not "the response matches a string I
typed in this file" — that only proves I typed it correctly. Instead every case
runs TWICE, once with the kernel loaded and once with `_CAPS = None` (the
kernel-absent path, which is also what a broken or missing
`/etc/qubes-rpc/qmcp_caps.py` produces in dom0), and asserts the two responses
are **byte-identical**. That is the real property: a kernel fault is invisible.

Mocked `qubesadmin` per the project pattern — a fake module installed in
`sys.modules` before the wrapper's in-function import runs, and the wrappers
loaded with `SourceFileLoader` because `qmcp.*` files carry no `.py` extension.

What this suite does NOT claim: that the real dom0 wrappers behave this way on
hardware. That is the slot's job (install, then one benign call per surface and
a before/after audit-line count). Offline proves the logic; only the qrexec path
proves the writer — the I-2 lesson.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
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


# --------------------------------------------------------------------------
# Mocked qubesadmin
# --------------------------------------------------------------------------

class FakeVM:
    def __init__(self, name, tags=(), netvm=None, klass="AppVM"):
        self.name = name
        self.tags = set(tags)
        self.netvm = netvm
        self.klass = klass
        self.template = None
        self.provides_network = False
        self.features = {}        # so SetFeature exercises its SUCCESS path
        self.template_for_dispvms = False

    # lifecycle surface — recorded, not simulated
    def start(self): self.started = True
    def kill(self): self.killed = True
    def shutdown(self, **kw): self.shut = True
    def pause(self): self.paused = True
    def unpause(self): self.unpaused = True
    def get_power_state(self): return "Halted"


class FakeDomains(dict):
    def __delitem__(self, k):          # `del app.domains[name]` == remove
        dict.__delitem__(self, k)


class FakeApp:
    def __init__(self, vms):
        self.domains = FakeDomains({v.name: v for v in vms})

    def qubesd_call(self, *a, **kw):
        return b"0\x00"


def install_fake_qubesadmin(vms):
    import types
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
    """Load a `qmcp.*` wrapper — SourceFileLoader, since there is no .py."""
    loader = SourceFileLoader("w_" + name.replace(".", "_"),
                              os.path.join(DOM0_RPC, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def run(name, request, vms, *, kernel=True, force_deny=False):
    """Run one wrapper's main() and return (stdout, audit_kwargs).

    `kernel=False` simulates a missing/broken qmcp_caps in dom0.
    `force_deny` stubs the I-5 tier gate to False so the DENY branch is
    reachable offline — the resolver itself is covered by I-3's suite and by
    offline-validate-1, so stubbing it here tests the wiring, not the tiers.
    """
    install_fake_qubesadmin(vms)
    mod = load_wrapper(name)

    captured = {}

    class Recorder:
        def audit(self, service, summary, ok, error=None, **kw):
            captured.update(kw)
            captured["service"] = service
            return True
    mod._AUDIT = Recorder()

    if not kernel:
        mod._CAPS = None
    if force_deny:
        mod._require_full = lambda vm: False

    old_stdin, old_stdout = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(request))
    sys.stdout = io.StringIO()
    try:
        mod.main()
        out = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = old_stdin, old_stdout
    return out, captured


# --------------------------------------------------------------------------
# Fixtures — compat mode (no /etc/qmcp/tier-default on mcp-control), so an
# untiered umbrella qube resolves to ai-full exactly as it does in production
# today. That is the shipped default and therefore the right row to test.
# --------------------------------------------------------------------------

def fleet():
    return [
        FakeVM("ai-work", {"ai-managed"}, netvm="ai-net-router"),
        FakeVM("ai-net-router", {"ai-managed"}, netvm=None),
        FakeVM("ai-debian-13", {"ai-managed"}, klass="TemplateVM"),
        FakeVM("outsider", set()),
    ]


ALL_WRAPPERS = [
    "qmcp.LifecycleAIManaged", "qmcp.SetPropertyAIManaged",
    "qmcp.SetFeatureAIManaged", "qmcp.CloneAIManagedQube",
    "qmcp.SpawnAIManagedQube", "qmcp.SpawnDisposableAIManaged",
    "qmcp.AttachDeviceAIManaged", "qmcp.DetachDeviceAIManaged",
]

print("\n-- 1. every wrapper loads with the kernel attached --")
for w in ALL_WRAPPERS:
    install_fake_qubesadmin(fleet())
    m = load_wrapper(w)
    check(f"{w}: kernel + decision hook present",
          m._CAPS is not None and hasattr(m, "_gate")
          and m._shadow is None,
          "a wrapper whose _CAPS failed to load would silently log nothing")
    check(f"{w}: enforcement flag reachable, and SHADOW with no operator file",
          m._ENFORCE is not None and m._enforce_mode() == "shadow",
          "Stage 3c's shipped default — a wrapper resolving anything else here "
          "would arm enforcement that the operator never configured")

# --------------------------------------------------------------------------
print("\n-- 2. INVARIANCE: the kernel cannot change what AI sees --")

CASES = [
    ("qmcp.LifecycleAIManaged", {"name": "ai-work", "action": "start"}, False),
    ("qmcp.LifecycleAIManaged", {"name": "ai-work", "action": "remove"}, True),
    ("qmcp.SetPropertyAIManaged",
     {"name": "ai-work", "property": "netvm", "value": "ai-net-router"}, False),
    ("qmcp.SetPropertyAIManaged",
     {"name": "ai-work", "property": "memory", "value": 400}, False),
    ("qmcp.SetFeatureAIManaged",
     {"name": "ai-work", "feature": "appmenus", "value": "1"}, False),
    ("qmcp.LifecycleAIManaged", {"name": "outsider", "action": "start"}, False),
    ("qmcp.LifecycleAIManaged", {"name": "nope", "action": "start"}, False),
]

for wrapper, req, deny in CASES:
    with_k, _ = run(wrapper, req, fleet(), kernel=True, force_deny=deny)
    without_k, _ = run(wrapper, req, fleet(), kernel=False, force_deny=deny)
    what = req.get("action") or req.get("property") or req.get("feature")
    label = (f"{wrapper.split('.')[1]}({what} on {req['name']}"
             f"{', tier-denied' if deny else ''})")
    check(f"invariance: {label}", with_k == without_k,
          f"kernel-present {with_k!r} != kernel-absent {without_k!r}")

# --------------------------------------------------------------------------
print("\n-- 3. the divergence log: populated only on real disagreement --")

# Agreement: ai-full target, ordinary property. Kernel ALLOWs, wrapper allows.
_, aud = run("qmcp.SetPropertyAIManaged",
             {"name": "ai-work", "property": "memory", "value": 400}, fleet())
check("agreement writes NO shadow key (byte-identical audit line)",
      aud.get("shadow") is None, str(aud))

# Divergence 1: netvm is escalation-class to the kernel, settable to the wrapper.
_, aud = run("qmcp.SetPropertyAIManaged",
             {"name": "ai-work", "property": "netvm",
              "value": "ai-net-router"}, fleet())
check("divergence recorded: netvm retarget (kernel deny / wrapper allow)",
      isinstance(aud.get("shadow"), dict)
      and aud["shadow"]["kernel"] == "deny"
      and aud["shadow"]["rule"] == "escalation-class"
      and aud["shadow"]["wrapper"] == "allow", str(aud.get("shadow")))

# Divergence 2: name — the judgement call the operator confirmed. Same shape.
_, aud = run("qmcp.SetPropertyAIManaged",
             {"name": "ai-work", "property": "name", "value": "renamed"},
             fleet())
check("divergence recorded: rename (the confirmed escalation widening)",
      isinstance(aud.get("shadow"), dict)
      and aud["shadow"]["rule"] == "escalation-class", str(aud.get("shadow")))

# Divergence 3: the other direction — wrapper denies, kernel allows by
# domination. This is the half a shadow hook on the allow-path-only would miss.
_, aud = run("qmcp.LifecycleAIManaged", {"name": "ai-work", "action": "remove"},
             fleet(), force_deny=True)
check("divergence recorded in the DENY direction (dominated remove)",
      isinstance(aud.get("shadow"), dict)
      and aud["shadow"]["kernel"] == "allow"
      and aud["shadow"]["wrapper"] == "deny"
      and aud["shadow"]["rule"].startswith("dominated:"), str(aud.get("shadow")))

# No free text ever reaches the log.
_, aud = run("qmcp.SetPropertyAIManaged",
             {"name": "ai-work", "property": "netvm", "value": "SECRET"},
             fleet())
check("the shadow record carries no free text and no request values",
      set(aud["shadow"]) == {"kernel", "rule", "wrapper"}
      and "SECRET" not in json.dumps(aud["shadow"]), str(aud.get("shadow")))

# Kernel absent => no shadow key at all, even where it would have diverged.
_, aud = run("qmcp.SetPropertyAIManaged",
             {"name": "ai-work", "property": "netvm",
              "value": "ai-net-router"}, fleet(), kernel=False)
check("kernel absent: no shadow key (absence is benign, not a denial)",
      aud.get("shadow") is None, str(aud))

# --------------------------------------------------------------------------
print("\n-- 4. a kernel that misbehaves still cannot alter the wrapper --")

install_fake_qubesadmin(fleet())
m = load_wrapper("qmcp.LifecycleAIManaged")


class ExplodingKernel:
    def shadow_record(self, *a, **kw):
        raise RuntimeError("kernel on fire")


m._CAPS = ExplodingKernel()


class Rec:
    def audit(self, service, summary, ok, error=None, **kw):
        self.kw = kw
        return True


rec = Rec()
m._AUDIT = rec
sys.stdin = io.StringIO(json.dumps({"name": "ai-work", "action": "start"}))
_o, sys.stdout = sys.stdout, io.StringIO()
try:
    m.main()
    boom_out = sys.stdout.getvalue()
finally:
    sys.stdout = _o
clean_out, _ = run("qmcp.LifecycleAIManaged",
                   {"name": "ai-work", "action": "start"}, fleet())
check("a raising kernel does not propagate and does not change the response",
      boom_out == clean_out and rec.kw.get("shadow") is None,
      f"{boom_out!r} vs {clean_out!r}")

# --------------------------------------------------------------------------
print("\n-- 4b. a STALE dom0 qmcp_audit.py must not blank the audit trail --")

# The failure this guards against was found by breaking offline-validate-I-5:
# emit() originally passed `shadow=` unconditionally, so a dom0 still holding a
# pre-Stage-1 qmcp_audit.py (a partial deploy — F9's split-brain family) raised
# TypeError INSIDE emit()'s best-effort guard, which swallowed it and dropped
# the ENTIRE audit line. The audit trail would have gone dark silently, which is
# precisely the failure mode the I-2 lesson warns about.

class OldAudit:
    """Pre-Stage-1 signature: knows `consent`, has never heard of `shadow`."""

    def __init__(self):
        self.calls = []

    def audit(self, service, summary, ok, error=None, consent=None):
        self.calls.append((ok, error))
        return True


install_fake_qubesadmin(fleet())
m = load_wrapper("qmcp.LifecycleAIManaged")
old = OldAudit()
m._AUDIT = old
sys.stdin = io.StringIO(json.dumps({"name": "ai-work", "action": "start"}))
_o, sys.stdout = sys.stdout, io.StringIO()
try:
    m.main()
finally:
    sys.stdout = _o
check("an agreeing call still audits against a pre-Stage-1 audit helper",
      old.calls == [(True, None)], str(old.calls))

# And on a genuine divergence against the old helper the line is lost rather
# than the operation — acceptable, and worth knowing rather than discovering.
install_fake_qubesadmin(fleet())
m = load_wrapper("qmcp.SetPropertyAIManaged")
old = OldAudit()
m._AUDIT = old
sys.stdin = io.StringIO(json.dumps({"name": "ai-work", "property": "netvm",
                                    "value": "ai-net-router"}))
_o, sys.stdout = sys.stdout, io.StringIO()
try:
    m.main()
    stale_out = sys.stdout.getvalue()
finally:
    sys.stdout = _o
fresh_out, _ = run("qmcp.SetPropertyAIManaged",
                   {"name": "ai-work", "property": "netvm",
                    "value": "ai-net-router"}, fleet())
check("a stale helper costs only the divergence line, never the response",
      stale_out == fresh_out and old.calls == [],
      f"{stale_out!r} vs {fresh_out!r}; calls={old.calls}")

# --------------------------------------------------------------------------
print("\n-- 5. qmcp_audit: the shadow key is byte-neutral when absent --")

spec = importlib.util.spec_from_file_location(
    "qmcp_audit", os.path.join(DOM0_RPC, "qmcp_audit.py"))
audit_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_mod)

tmpdir = tempfile.mkdtemp(prefix="qmcp-audit-wiring-")


def chain_lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


baseline = os.path.join(tmpdir, "baseline.log")
audit_mod.LOG_PATH = baseline
audit_mod.audit("qmcp.LifecycleAIManaged", {"name": "a", "action": "start"},
                True)
withnone = os.path.join(tmpdir, "withnone.log")
audit_mod.LOG_PATH = withnone
audit_mod.audit("qmcp.LifecycleAIManaged", {"name": "a", "action": "start"},
                True, shadow=None)

b, w = chain_lines(baseline), chain_lines(withnone)
check("audit(): shadow=None writes a record identical to omitting it",
      len(b) == 1 and len(w) == 1
      and {k: v for k, v in b[0].items() if k != "ts"}
      == {k: v for k, v in w[0].items() if k != "ts"}
      and "shadow" not in w[0],
      "a null-written key would change the chain hash of every agreeing call")

withdiv = os.path.join(tmpdir, "withdiv.log")
audit_mod.LOG_PATH = withdiv
audit_mod.audit("qmcp.LifecycleAIManaged", {"name": "a", "action": "remove"},
                True, shadow={"kernel": "allow", "rule": "dominated:exec",
                              "wrapper": "deny"})
dv = chain_lines(withdiv)
check("audit(): a divergence IS recorded, and the chain still verifies",
      dv and dv[0].get("shadow", {}).get("rule") == "dominated:exec"
      and audit_mod.verify(withdiv)[0] is True)

# --------------------------------------------------------------------------
print(f"\n{PASSED}/{PASSED + FAILED} checks passed")
sys.exit(1 if FAILED else 0)
