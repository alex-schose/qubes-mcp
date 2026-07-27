#!/usr/bin/env python3
"""offline-validate-G0a.py — offline validation of Stage G0a (finding [1]:
the property allowlist on qmcp.SetPropertyAIManaged).

Ships in public/deploy/ alongside the other offline-validate-*.py harnesses.
Same shape as offline-validate-I-{2,3,4,5}.py: a mocked-qubesadmin harness that
loads the REAL extension-less wrapper via SourceFileLoader, drives main() with
JSON on stdin, and asserts on the response. This is where the bulk of G0a
coverage lives; the slot (slot-71) only confirms on hardware that a real
`SetProperty provides_network=True` driven from mcp-control leaves the dom0
prefs untouched.

The authority gates (tier CAP_FULL + I-6 consent) are OUT OF SCOPE here — they
are validated by offline-validate-I-5 / -I-6 — so we monkeypatch them to "pass"
and isolate the ONE thing G0a adds: the SETTABLE_PROPS allowlist and its opaque
refusal. What it proves:

  1. ALLOWLIST-PASS: every allowlisted property (name/label/memory/maxmem/vcpus
     + the cross-reffed template/netvm/default_dispvm) proceeds past the
     allowlist to the cross-ref / setattr path and succeeds.
  2. DEFAULT-DENY: every non-allowlisted property (provides_network, autostart,
     virt_mode, kernel, management_dispvm, default_user, and a nonexistent
     name) is refused with the opaque PROP_NOT_SETTABLE.
  3. TEETH (the I-5 lesson — the mock models the side effect the fix prevents):
     a refused set NEVER reaches setattr(vm, prop, value). The RecordingVM logs
     every setattr; assert provides_network=True is refused AND absent from the
     log. Remove the allowlist and this reddens (setattr would fire) — so the
     test proves the fix rather than re-hiding it.
  4. NO ORACLE: provides_network's refusal is byte-identical to a nonexistent
     property's — no "operator-only" tell distinguishes what the operator
     reserves from what simply is not a property.
  5. NO REGRESSION on the surfaces G0a sits between: the Stage-C egress
     invariant (netvm on a provides_network qube refused, informatively) and
     the Stage-F2-sibling cross-ref opacity (template → non-ai-managed refused
     opaquely) still fire exactly as before.

Run from the repo root:   .venv/bin/python deploy/offline-validate-G0a.py
or from inside public/:   python3 deploy/offline-validate-G0a.py
"""
from __future__ import annotations

import contextlib
import importlib.machinery
import io
import json
import os
import sys
import types

# This file lives in public/deploy/; the wrapper it loads is a sibling in
# public/dom0-rpc/. Resolve it relative to THIS file (same as the wrapper's own
# os.path.dirname(os.path.realpath(__file__)) sibling-load) so it runs from the
# repo root AND from inside public/.
HERE = os.path.dirname(os.path.realpath(__file__))
WRAPPER = os.path.join(HERE, os.pardir, "dom0-rpc", "qmcp.SetPropertyAIManaged")

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
# Mock qubesadmin — a VM that RECORDS every setattr (for the teeth check).
# --------------------------------------------------------------------------
class RecordingVM:
    def __init__(self, name, tags=("ai-managed",), provides_network=False):
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "tags", set(tags))
        object.__setattr__(self, "provides_network", provides_network)
        object.__setattr__(self, "setattr_log", [])

    def __setattr__(self, k, v):
        # Record the mutation the wrapper attempts, THEN apply it. The whole
        # point of G0a is that a refused property never reaches here.
        self.setattr_log.append((k, v))
        object.__setattr__(self, k, v)


class FakeDomains:
    def __init__(self, vms):
        self._d = {vm.name: vm for vm in vms}

    def __contains__(self, name): return name in self._d
    def __getitem__(self, name): return self._d[name]


class FakeApp:
    def __init__(self, vms):
        self.domains = FakeDomains(vms)


def _install_fake_qubesadmin(app):
    qa = types.ModuleType("qubesadmin")
    qa_app = types.ModuleType("qubesadmin.app")
    qa_app.QubesLocal = lambda: app
    qa.app = qa_app
    sys.modules["qubesadmin"] = qa
    sys.modules["qubesadmin.app"] = qa_app


def _load_wrapper():
    loader = importlib.machinery.SourceFileLoader("w_setp_g0a", WRAPPER)
    mod = loader.load_module()
    # Isolate the allowlist: bypass the tier + consent authority gates (proven
    # elsewhere) and silence the best-effort audit hook (its dom0 log path does
    # not exist here). These are the ONLY monkeypatches — the allowlist logic
    # under test runs untouched.
    mod._require_full = lambda vm: True
    mod._consent_gate = lambda action: True
    mod._AUDIT = None
    return mod


W = _load_wrapper()


def run(prop, value, *, target=None, extra=None):
    """Drive the real main() with {name, property, value} on stdin against a
    fresh domain set. Returns (response_dict, target_vm)."""
    tgt = target or RecordingVM("ai-x")
    vms = [tgt] + list(extra or [])
    _install_fake_qubesadmin(FakeApp(vms))
    req = json.dumps({"name": tgt.name, "property": prop, "value": value})
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sys.stdin = io.StringIO(req)
        try:
            W.main()
        finally:
            sys.stdin = sys.__stdin__
    line = out.getvalue().strip().splitlines()[-1]
    return json.loads(line), tgt


def _refused(resp):
    return resp.get("ok") is False


def _not_settable(resp):
    return resp == {"ok": False, "error": "property not settable"}


def _reached_setattr(vm, prop):
    return any(k == prop for (k, _) in vm.setattr_log)


print("=" * 70)
print("  Stage G0a — SetPropertyAIManaged property allowlist (finding [1])")
print("=" * 70)

# -- 1. ALLOWLIST-PASS: allowlisted scalar props proceed to setattr + succeed --
print("\n1. Allowlisted properties proceed and succeed")
for prop, val in [("memory", 400), ("maxmem", 4000), ("vcpus", 2),
                  ("label", "red"), ("name", "ai-x")]:
    resp, vm = run(prop, val)
    check(f"set {prop}={val!r} → ok:true and setattr reached",
          resp.get("ok") is True and _reached_setattr(vm, prop))

# cross-ref allowlisted props with an ai-managed referent → succeed
for prop in ("template", "default_dispvm"):
    ref = RecordingVM("ai-ref", tags=("ai-managed",))
    resp, vm = run(prop, "ai-ref", extra=[ref])
    check(f"set {prop}=<ai-managed> → ok:true (cross-ref passes)",
          resp.get("ok") is True and _reached_setattr(vm, prop))

# netvm to an ai-managed non-router referent, target is not a router → succeeds
ref = RecordingVM("ai-router-ish", tags=("ai-managed",))
resp, vm = run("netvm", "ai-router-ish",
               target=RecordingVM("ai-x", provides_network=False), extra=[ref])
check("set netvm=<ai-managed> on a non-router target → ok:true",
      resp.get("ok") is True and _reached_setattr(vm, "netvm"))

# -- 2 & 3. DEFAULT-DENY + TEETH: non-allowlisted props refused, never setattr --
print("\n2/3. Non-allowlisted properties refused opaquely, setattr NEVER reached")
DENIED = ["provides_network", "autostart", "virt_mode", "kernel",
          "management_dispvm", "default_user", "netvm_str_typo", "nonexistent"]
for prop in DENIED:
    resp, vm = run(prop, True)
    check(f"set {prop} → PROP_NOT_SETTABLE and setattr NOT reached (teeth)",
          _not_settable(resp) and not _reached_setattr(vm, prop))

# The single most important teeth case, stated explicitly:
resp, vm = run("provides_network", True)
check("FINDING [1]: provides_network=True refused, egress-router mint blocked",
      _not_settable(resp) and ("provides_network", True) not in vm.setattr_log)

# -- 4. NO ORACLE: operator-only vs nonexistent are indistinguishable --
print("\n4. No oracle — operator-only and nonexistent collapse to one message")
r_provnet, _ = run("provides_network", True)
r_bogus, _ = run("nonexistent", "x")
check("provides_network refusal == nonexistent-property refusal (no tell)",
      r_provnet == r_bogus and _not_settable(r_provnet))

# -- 5. NO REGRESSION on the neighbours G0a sits between --
print("\n5. Neighbouring guarantees intact (egress invariant + cross-ref opacity)")

# Egress invariant (Stage C): netvm on a provides_network qube is refused,
# informatively (this fires AFTER the allowlist — netvm is allowlisted).
ref = RecordingVM("ai-any", tags=("ai-managed",))
resp, vm = run("netvm", "ai-any",
               target=RecordingVM("ai-router", provides_network=True), extra=[ref])
check("egress invariant still fires: netvm on a router refused (operator-only)",
      resp == {"ok": False,
               "error": "netvm of a network-providing qube is operator-only"}
      and not _reached_setattr(vm, "netvm"))

# Cross-ref opacity (Stage F2 sibling): template → a non-ai-managed qube is
# refused opaquely (allowlisted prop, but the referent fails the cross-ref).
op = RecordingVM("op-tpl", tags=())  # not ai-managed
resp, vm = run("template", "op-tpl", extra=[op])
check("cross-ref opacity still fires: template → non-ai-managed refused opaquely",
      resp == {"ok": False,
               "error": "cross-ref property 'template' must reference an "
                        "ai-managed qube"}
      and not _reached_setattr(vm, "template"))

# Pre-authority opacity unchanged: an untagged target is NOT_FOUND (the
# allowlist never runs — tag check precedes it).
resp, vm = run("memory", 400, target=RecordingVM("op-x", tags=()))
check("untagged target → NOT_FOUND (tag check precedes the allowlist)",
      resp == {"ok": False, "error": "not found"})

# --------------------------------------------------------------------------
print("\n" + "=" * 70)
print(f"  RESULT: {_passed} passed / {_failed} failed")
print("=" * 70)
sys.exit(1 if _failed else 0)
