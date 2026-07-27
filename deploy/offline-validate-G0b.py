#!/usr/bin/env python3
"""offline-validate-G0b.py — offline validation of Stage G0b: the gateway input
boundary (finding [2]) + exception masking (Component D, findings [12]/[9]).

Ships in public/deploy/. Three risk surfaces, three parts:

  PART A — target validator (qubes_mcp/tools/_qrexec._valid_target).
     Table-driven, per the brief: every rejected shape (@adminvm, @dispvm,
     @tag:…, dom0, whitespace, metacharacters, empty, >31 chars, digit/dash
     start) is refused; every valid name passes. Then: call_admin / call_service
     on a rejected target return the opaque refusal WITHOUT spawning a
     subprocess (monkeypatched to explode if called), and the refusal is
     byte-identical to a policy deny (no validation oracle).

  PART B — policy scoping (the real public/policy/30-mcp-control.policy).
     A first-match-wins simulator (the I-4/I-5 pattern) asserts the finding-[2]
     tuple (admin.vm.device.usb.{List,Available}, source=mcp-control,
     target=@adminvm) now resolves to `ask`, NOT `allow` — while the intended
     ai-managed enumeration (target=@tag:ai-managed) stays `allow`. Includes the
     finding-[8] fallthrough sentinel: the resolver reports the matching line
     number, and we assert the security-critical @adminvm device tuples are
     handled by an EXPLICIT in-file rule, not by catch-all fallthrough.

  PART C — exception masking (Component D). call_service / call_admin collapse a
     subprocess TimeoutExpired / OSError to the opaque refusal instead of raising.

Run from the repo root:   .venv/bin/python deploy/offline-validate-G0b.py
or from inside public/:   python3 deploy/offline-validate-G0b.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# import the real _qrexec module from the package
sys.path.insert(0, str(HERE.parent))
from qubes_mcp.tools import _qrexec  # noqa: E402
from qubes_mcp.tools._qrexec import _valid_target, call_admin, call_service  # noqa: E402

POLICY = HERE.parent / "policy" / "30-mcp-control.policy"

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


OPAQUE = {"ok": False, "error": "not found or refused"}

# ==========================================================================
# PART A — the target validator
# ==========================================================================
print("=" * 70)
print("  PART A — _qrexec._valid_target (finding [2] untrusted-side guard)")
print("=" * 70)

REJECT = ["@adminvm", "@dispvm", "@default", "@tag:ai-managed", "dom0", "DOM0",
          "Dom0", "", "has space", "bad;char", "bad|char", "a/b", "x`id`",
          "$(x)", "-startsdash", "1startsdigit", ".startsdot", "a" * 32,
          None, 123]
ACCEPT = ["ai-debian-13", "ai_poc", "ai.x-1", "mcp-control", "a",
          "ai-net-router", "A", "a" * 31]

for name in REJECT:
    check(f"REJECT {name!r}", _valid_target(name) is False)
for name in ACCEPT:
    check(f"accept {name!r}", _valid_target(name) is True)

# The chokepoint short-circuits: a rejected target must NOT spawn a subprocess;
# a valid target MUST reach it. A spy records each subprocess.run and then raises
# TimeoutExpired (which Component D collapses to the opaque refusal), so we never
# touch the real qrexec transport.
_real_run = subprocess.run
_calls = []


def _spy(*a, **k):
    _calls.append(a)
    raise subprocess.TimeoutExpired(cmd="x", timeout=1)


_qrexec.subprocess.run = _spy
try:
    _calls.clear()
    r1 = call_admin("admin.vm.device.usb.List", "@adminvm")
    check("call_admin('@adminvm') → opaque, no subprocess spawned",
          r1 == OPAQUE and len(_calls) == 0)
    _calls.clear()
    r2 = call_service("dom0", "qmcp.RunInAIManaged", {"cmd": "x"})
    check("call_service('dom0') → opaque, no subprocess spawned",
          r2 == OPAQUE and len(_calls) == 0)
    _calls.clear()
    call_admin("admin.vm.firewall.Get", "ok-name")  # valid → reaches the spy
    check("valid name reaches subprocess (guard passes it through)",
          len(_calls) == 1)
finally:
    _qrexec.subprocess.run = _real_run

# ==========================================================================
# PART B — policy first-match-wins simulator (finding [2] dom0 boundary + [8])
# ==========================================================================
print("\n" + "=" * 70)
print("  PART B — policy scoping (real 30-mcp-control.policy, first-match-wins)")
print("=" * 70)


class Qube:
    def __init__(self, name, tags=(), adminvm=False):
        self.name, self.tags, self.adminvm = name, set(tags), adminvm


def parse_policy(path):
    rules = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        toks = s.split()
        if len(toks) < 5:
            raise SystemExit(f"FATAL line {i}: <5 fields: {s!r}")
        if toks[4] not in ("allow", "deny", "ask"):
            raise SystemExit(f"FATAL line {i}: 5th field not an action: {toks[4]!r}")
        rules.append((toks[0], toks[1], toks[2], toks[3], toks[4], i))
    return rules


def _match(token, q):
    if token == "*":
        return True
    if token == "@anyvm":
        return not q.adminvm
    if token in ("@adminvm", "dom0"):
        return q.adminvm
    if token.startswith("@tag:"):
        return token[5:] in q.tags
    return token == q.name


def resolve_ex(rules, service, source, target):
    """First-match-wins → (action, lineno). Fallthrough → ('deny', None) — the
    finding-[8] sentinel that distinguishes an EXPLICIT deny from catch-all."""
    for svc, arg, src, tgt, act, lineno in rules:
        if svc not in (service, "*"):
            continue
        if arg != "*":
            continue
        if _match(src, source) and _match(tgt, target):
            return act, lineno
    return "deny", None


rules = parse_policy(POLICY)
MCP = Qube("mcp-control")
ADMINVM = Qube("dom0", adminvm=True)
AIVM = Qube("ai-x", {"ai-managed"})

# finding [2]: the @adminvm USB enumeration lines must now be `ask`, not `allow`.
for method in ("admin.vm.device.usb.List", "admin.vm.device.usb.Available"):
    act, ln = resolve_ex(rules, method, MCP, ADMINVM)
    check(f"[2] ({method}, mcp-control→@adminvm) resolves 'ask' (was 'allow')",
          act == "ask")
    # finding [8]: it is an EXPLICIT in-file rule, not catch-all fallthrough.
    check(f"[8] ({method}, @adminvm) handled by an explicit rule (line {ln}), not fallthrough",
          ln is not None)

# the intended surface is untouched: ai-managed enumeration still allows.
# G0d/G0e route ALL device enumeration through qmcp.ListAttachedDevicesAIManaged
# and DENY the direct admin.vm.device.* methods to AI (.Available joined the deny
# set in G0e). Assert the direct methods are denied and the wrapper is the path.
for method in ("admin.vm.device.usb.Available", "admin.vm.device.block.Available",
               "admin.vm.device.usb.Attached"):
    act, _ = resolve_ex(rules, method, MCP, AIVM)
    check(f"({method}, mcp-control→@tag:ai-managed) now 'deny' (wrapper-mediated)",
          act == "deny")
a, _ = resolve_ex(rules, "qmcp.ListAttachedDevicesAIManaged", MCP, ADMINVM)
check("qmcp.ListAttachedDevicesAIManaged @adminvm allowed (the device-read path)",
      a == "allow")

# a bare AI-shaped @adminvm call on a NON-whitelisted admin method still denies.
act, _ = resolve_ex(rules, "admin.vm.Start", MCP, ADMINVM)
check("catch-all still denies (admin.vm.Start, mcp-control→@adminvm)", act == "deny")

# ==========================================================================
# PART C — exception masking (Component D, findings [12]/[9])
# ==========================================================================
print("\n" + "=" * 70)
print("  PART C — exception masking on call_service / call_admin")
print("=" * 70)


def _raise_timeout(*a, **k):
    raise subprocess.TimeoutExpired(cmd="x", timeout=1)


def _raise_oserror(*a, **k):
    raise OSError("qrexec-client-vm not found")


for exc_name, fn in (("TimeoutExpired", _raise_timeout), ("OSError", _raise_oserror)):
    _qrexec.subprocess.run = fn
    try:
        rs = call_service("ai-x", "qmcp.RunInAIManaged", {"cmd": "x"})
        ra = call_admin("admin.vm.firewall.Get", "ai-x")
        check(f"call_service collapses {exc_name} → opaque refusal", rs == OPAQUE)
        check(f"call_admin collapses {exc_name} → opaque refusal", ra == OPAQUE)
    finally:
        _qrexec.subprocess.run = _real_run

# --------------------------------------------------------------------------
print("\n" + "=" * 70)
print(f"  RESULT: {_passed} passed / {_failed} failed")
print("=" * 70)
sys.exit(1 if _failed else 0)
