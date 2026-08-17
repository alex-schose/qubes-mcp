#!/usr/bin/env python3
"""offline-validate-0-2.py — offline validation of the Stage 0.2 class fix
(finding F-G) in the two MCP read tools that compose qmcp.GetPropertyAIManaged.

F-G: `qubes_state` requested `template` unconditionally and both tools aborted
the whole call on the FIRST per-property failure, so a StandaloneVM or a
TemplateVM — which have no `template` property — returned nothing usable even
though `power_state`, `netvm` and `provides_network` all read fine. The dom0
wrapper was never the problem: `qmcp.GetPropertyAIManaged` already answers per
property (it returns `property '<p>' does not exist` only AFTER the ai-managed
check passes, lines 83/86 vs 106-108), so the granularity existed and the tool
layer threw it away.

The whole risk surface is tool-layer control flow, which needs no qubesd and no
hardware — so this is the offline analogue of the mocked-`qubesadmin` suites:
`fastmcp` and `call_qmcp` are stubbed in `sys.modules`, and the REAL tool
functions run against a scripted dom0.

PART A — per-property results (the fix).
PART B — opacity is unchanged: a total failure still collapses, verbatim, to
   the same opaque refusal it produced before, so no new existence oracle.
PART C — TEETH: assert the pre-fix control flow actually loses the good reads.
   A green suite that would also pass against the bug proves nothing (the I-5
   lesson: the mock must reproduce the defect before it can prove the fix).

Run:  .venv/bin/python deploy/offline-validate-0-2.py
      (or plain python3 from the repo root — no install needed)
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

_passed = _failed = 0


def check(label, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")


# --------------------------------------------------------------------------
# Stub fastmcp so the REAL qubes_mcp.server (Ring, ring_tool) imports without
# the dependency; the decorator is exercised as shipped.
_fastmcp = types.ModuleType("fastmcp")


class _FakeFastMCP:
    def __init__(self, *a, **kw):
        pass

    def tool(self, *a, **kw):
        def deco(fn):
            return fn
        return deco


_fastmcp.FastMCP = _FakeFastMCP
sys.modules.setdefault("fastmcp", _fastmcp)

# Stub the qrexec layer. `responses` maps a property name to the dom0 reply.
_calls: list[tuple[str, str]] = []
_responses: dict[str, dict] = {}

NOT_FOUND = {"ok": False, "error": "not found"}
OPAQUE = {"ok": False, "error": "not found or refused"}


def _no_such_prop(p):
    return {"ok": False, "error": f"property '{p}' does not exist"}


def _fake_call_qmcp(service, payload=None, timeout=30.0):
    prop = (payload or {}).get("property", "")
    _calls.append((service, prop))
    return _responses.get(prop, NOT_FOUND)


import qubes_mcp.tools._qrexec as _qrexec  # noqa: E402

_qrexec.call_qmcp = _fake_call_qmcp

from qubes_mcp.tools.qubes_props_get import qubes_props_get  # noqa: E402
from qubes_mcp.tools.qubes_state import _STATE_PROPS, qubes_state  # noqa: E402

# The tool modules did `from ... import call_qmcp`, binding the real function
# into their own namespace — rebind there too.
import qubes_mcp.tools.qubes_props_get as _m_props  # noqa: E402
import qubes_mcp.tools.qubes_state as _m_state  # noqa: E402

_m_props.call_qmcp = _fake_call_qmcp
_m_state.call_qmcp = _fake_call_qmcp


def scenario(mapping):
    """Install a dom0 script and reset the call log."""
    _responses.clear()
    _responses.update(mapping)
    _calls.clear()


OK = lambda v: {"ok": True, "value": v}  # noqa: E731

# A StandaloneVM inside the ai-managed umbrella — the shape F-G names. Its
# `template` property does not exist, and it is the read that used to be fatal.
STANDALONE = {
    "power_state": OK("Halted"),
    "netvm": OK("ai-net-router"),
    "provides_network": OK(False),
    "template": _no_such_prop("template"),
}
APPVM = {
    "power_state": OK("Running"),
    "netvm": OK("ai-net-router"),
    "provides_network": OK(False),
    "template": OK("ai-debian-13"),
}

# ==========================================================================
print("=" * 70)
print("  PART A — per-property results (F-G)")
print("=" * 70)

scenario(STANDALONE)
r = qubes_state("ai-standalone-1")
check("StandaloneVM: qubes_state ok=True (was False — whole call lost)", r.get("ok") is True)
check("StandaloneVM: power_state survives", r.get("power_state") == "Halted")
check("StandaloneVM: netvm survives", r.get("netvm") == "ai-net-router")
check("StandaloneVM: provides_network survives (read AFTER the failing one)",
      r.get("provides_network") is False)
check("StandaloneVM: template reported under errors, not fatal",
      "template" in r.get("errors", {}))
check("StandaloneVM: errors names only the inapplicable property",
      list(r.get("errors", {})) == ["template"])
check("StandaloneVM: every property was attempted (no early abort)",
      [p for _, p in _calls] == list(_STATE_PROPS))

scenario(APPVM)
r = qubes_state("ai-scratch-1")
check("AppVM: no errors key when everything reads", "errors" not in r)
check("AppVM: template value present", r.get("template") == "ai-debian-13")
check("AppVM: name echoed (shape unchanged)", r.get("name") == "ai-scratch-1")

scenario(STANDALONE)
r = qubes_props_get("ai-standalone-1", ["power_state", "template", "netvm"])
check("props_get: ok=True with a mixed result", r.get("ok") is True)
check("props_get: values holds the two that read",
      r.get("values") == {"power_state": "Halted", "netvm": "ai-net-router"})
check("props_get: errors holds the inapplicable one", "template" in r.get("errors", {}))
check("props_get: order-independent — a failure first still yields later reads",
      qubes_props_get("ai-standalone-1", ["template", "netvm"]).get("values")
      == {"netvm": "ai-net-router"})

scenario({})
r = qubes_props_get("ai-scratch-1", [])
check("props_get: empty request is a vacuous success, not a refusal",
      r.get("ok") is True and r.get("values") == {})

# ==========================================================================
print("\n" + "=" * 70)
print("  PART B — opacity unchanged (no new existence oracle)")
print("=" * 70)

# Out of scope / nonexistent: the wrapper answers NOT_FOUND for EVERY property,
# so nothing reads and the tool must return that verbatim — byte-identical to
# the pre-fix behaviour.
scenario({})
r = qubes_state("personal")
check("out-of-scope: qubes_state returns the opaque refusal verbatim", r == NOT_FOUND)
r = qubes_props_get("personal", ["power_state", "netvm"])
check("out-of-scope: props_get returns the opaque refusal verbatim", r == NOT_FOUND)

scenario({p: OPAQUE for p in _STATE_PROPS})
r = qubes_state("ai-scratch-1")
check("transport failure on all: collapses to 'not found or refused'", r == OPAQUE)

# The distinct per-property error can only appear once a read has succeeded,
# which already proves the target is inside the umbrella.
scenario(STANDALONE)
r = qubes_state("ai-standalone-1")
check("a distinct error is only ever returned ALONGSIDE a successful read",
      ("errors" not in r) or bool([k for k in r if k in _STATE_PROPS]))

# A single-property request for an inapplicable property still surfaces the
# wrapper's own message — the ordering guarantee lives in dom0 (post-umbrella),
# not here, so the tool must not invent opacity the wrapper did not apply.
scenario(STANDALONE)
r = qubes_props_get("ai-standalone-1", ["template"])
check("single inapplicable property: passes the wrapper's answer through",
      r == _no_such_prop("template"))

# ==========================================================================
print("\n" + "=" * 70)
print("  PART C — TEETH: the pre-fix control flow must FAIL these")
print("=" * 70)


def prefix_state(name):
    """The shipped-before-0.2 body of qubes_state, verbatim."""
    out = {"ok": True, "name": name}
    for prop in _STATE_PROPS:
        r = _fake_call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})
        if not r.get("ok"):
            return r
        out[prop] = r["value"]
    return out


scenario(STANDALONE)
old = prefix_state("ai-standalone-1")
check("teeth: pre-fix qubes_state DID lose the whole call on a StandaloneVM",
      old.get("ok") is False and old == _no_such_prop("template"))
check("teeth: pre-fix aborted before reading provides_network",
      [p for _, p in _calls] == ["power_state", "netvm", "template"])

scenario(STANDALONE)
new = qubes_state("ai-standalone-1")
check("teeth: the fix changes that exact case", new.get("ok") is True and old != new)

scenario({})
_old_oos = prefix_state("personal")
scenario({})
_new_oos = qubes_state("personal")
check("teeth: out-of-scope is the one case where old and new agree",
      _old_oos == NOT_FOUND and _new_oos == NOT_FOUND)

# --------------------------------------------------------------------------
print("\n" + "=" * 70)
print(f"  RESULT: {_passed} passed / {_failed} failed")
print("=" * 70)
sys.exit(1 if _failed else 0)
