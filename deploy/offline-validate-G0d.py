#!/usr/bin/env python3
"""offline-validate-G0d.py — offline validation of the device-list backend/
attachment name redactor (finding [4], hardened in G0e for findings [2]/[3]/[5]).

PART A — the FAIL-CLOSED redactor (_redact): a qube name in a device-list line
   appears in structured positions — `<backend>:<port>` and `<key>=<value>`
   (attachment=, backend_domain=). Those are ALLOWLISTED (kept only if the token
   is an ai-managed name, else redacted), so dom0 (absent from app.domains) and
   stale/removed backend names default to redacted (finding [2]). Bare tokens
   redact only against the known-out-of-scope set (+dom0); descriptions survive.
PART B — the wrapper end-to-end (real qmcp.ListAttachedDevicesAIManaged, mocked
   qubesadmin + synthetic qubesd_call payloads) for BOTH modes: attached (backend
   redaction) and available (the `attachment=` consuming-frontend leak, finding [3]).
PART C — policy: EVERY direct admin.vm.device.<class>.{Available,Attached,Assigned}
   is denied to AI (all wrapper-mediated now); the wrapper is allowed; the
   operator's usb.{List,Available} @adminvm `ask` survives; and the other device
   methods to @adminvm are project-owned denies, not platform-default fallthrough
   (finding [5]).

Run:  .venv/bin/python deploy/offline-validate-G0d.py
"""
from __future__ import annotations

import contextlib
import importlib.machinery
import io
import json
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
WRAPPER = HERE.parent / "dom0-rpc" / "qmcp.ListAttachedDevicesAIManaged"
POLICY = HERE.parent / "policy" / "30-mcp-control.policy"

_passed = _failed = 0


def check(label, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")


W = importlib.machinery.SourceFileLoader("w_listdev", str(WRAPPER)).load_module()
SENT = "<out-of-scope>"

# ==========================================================================
print("=" * 70)
print("  PART A — _redact (FAIL-CLOSED allowlist on name-positions)")
print("=" * 70)

AI = {"ai-frontend", "ai-backend"}
BARE = {"personal", "sys-usb", "dom0"}


def red(line):
    return W._redact([line], AI, BARE)[0]


check("dom0 backend redacted (allowlist name-position; dom0 not in app.domains)",
      "dom0" not in red("dom0:sda RootDisk ai-frontend").split(":")[0] and SENT in red("dom0:sda x"))
check("stale/removed backend redacted (not a current VM)",
      "old-removed-vm" not in red("old-removed-vm:2-1 x") and SENT in red("old-removed-vm:2-1 x"))
check("in-scope backend kept usable for detach",
      "ai-backend" in red("ai-backend:1-2 Disk ai-frontend"))
check("attachment= out-of-scope consuming-frontend redacted (finding [3])",
      "personal" not in red("2-1 x attachment='personal'") and SENT in red("2-1 x attachment='personal'"))
check("attachment= in-scope frontend kept",
      "ai-frontend" in red("2-1 x attachment='ai-frontend'"))
check("plain description word left intact",
      "Kingston_DataTraveler" in red("2-1 Kingston_DataTraveler ai-frontend"))
check("bare known-out-of-scope name (USED-BY column) redacted",
      "personal" not in red("sys-usb:2-1 x personal"))

# ==========================================================================
print("\n" + "=" * 70)
print("  PART B — wrapper end-to-end, BOTH modes (mocked qubesadmin)")
print("=" * 70)


class FakeTags:
    def __init__(self, items): self._s = set(items)
    def __contains__(self, x): return x in self._s


class FakeVM:
    def __init__(self, name, tags): self.name, self.tags = name, FakeTags(tags)


class FakeApp:
    def __init__(self, vms, payload_by_method):
        self._d = {v.name: v for v in vms}
        self._pm = payload_by_method

    class _Dom:
        def __init__(self, d): self._d = d
        def __contains__(self, n): return n in self._d
        def __getitem__(self, n): return self._d[n]
        def __iter__(self): return iter(self._d.values())

    @property
    def domains(self): return FakeApp._Dom(self._d)

    def qubesd_call(self, name, method):
        # raise for a method not in the map, so the wrapper's fallback loop is exercised
        if method not in self._pm:
            raise RuntimeError("no such method")
        return self._pm[method]


def _run(name, device_class, mode, vms, payload_by_method):
    qa = types.ModuleType("qubesadmin")
    qa_app = types.ModuleType("qubesadmin.app")
    app = FakeApp(vms, payload_by_method)
    qa_app.QubesLocal = lambda: app
    qa.app = qa_app
    sys.modules["qubesadmin"] = qa
    sys.modules["qubesadmin.app"] = qa_app
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sys.stdin = io.StringIO(json.dumps({"name": name, "device_class": device_class, "mode": mode}))
        try:
            W.main()
        finally:
            sys.stdin = sys.__stdin__
    return json.loads(out.getvalue().strip().splitlines()[-1])


VMS = [FakeVM("ai-frontend", {"ai-managed"}), FakeVM("ai-backend", {"ai-managed"}),
       FakeVM("personal", set())]  # personal = operator qube, out of scope

# attached mode: out-of-scope backend (dom0) redacted
r = _run("ai-frontend", "block", "attached", VMS,
         {"admin.vm.device.block.Attached": b"dom0:sda RootDisk ai-frontend\n"})
check("attached: ok + dom0 backend redacted",
      r.get("ok") is True and all("dom0" != ln.split(":")[0] for ln in r.get("lines", []))
      and any(SENT in ln for ln in r.get("lines", [])))

# attached mode falls back to legacy .List when .Attached is absent
r = _run("ai-frontend", "usb", "attached", VMS,
         {"admin.vm.device.usb.List": b"personal:2-1 Kingston ai-frontend\n"})
check("attached: .List fallback works + out-of-scope backend redacted",
      r.get("ok") is True and all("personal" not in ln for ln in r.get("lines", [])))

# available mode: the attachment= consuming-frontend leak is redacted (finding [3])
r = _run("ai-backend", "usb", "available", VMS,
         {"admin.vm.device.usb.Available": b"2-1 Kingston attachment='personal'\n"})
check("available: ok + attachment= out-of-scope frontend redacted",
      r.get("ok") is True and all("personal" not in ln for ln in r.get("lines", []))
      and any(SENT in ln for ln in r.get("lines", [])))

# untagged / missing frontend → opaque NOT_FOUND
check("untagged frontend → NOT_FOUND",
      _run("personal", "usb", "attached", VMS, {"admin.vm.device.usb.Attached": b"x\n"})
      == {"ok": False, "error": "not found"})
check("bad mode → refused",
      _run("ai-frontend", "usb", "bogus", VMS, {}).get("ok") is False)

# ==========================================================================
print("\n" + "=" * 70)
print("  PART C — policy (real 30-mcp-control.policy)")
print("=" * 70)


def parse_policy(path):
    rules = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        t = s.split()
        if len(t) < 5 or t[4] not in ("allow", "deny", "ask"):
            raise SystemExit(f"FATAL line {i}: {s!r}")
        rules.append((t[0], t[1], t[2], t[3], t[4], i))
    return rules


class Q:
    def __init__(self, name, tags=(), adminvm=False):
        self.name, self.tags, self.adminvm = name, set(tags), adminvm


def _m(tok, q):
    if tok == "*":
        return True
    if tok == "@anyvm":
        return not q.adminvm
    if tok in ("@adminvm", "dom0"):
        return q.adminvm
    if tok.startswith("@tag:"):
        return tok[5:] in q.tags
    return tok == q.name


def resolve(rules, svc, src, tgt):
    for s, a, so, ta, act, ln in rules:
        if s not in (svc, "*") or a != "*":
            continue
        if _m(so, src) and _m(ta, tgt):
            return act, ln
    return "default", None


rules = parse_policy(POLICY)
MCP = Q("mcp-control")
AIVM = Q("ai-x", {"ai-managed"})
ADMINVM = Q("dom0", adminvm=True)

# every direct device-enum method to an AI target is DENY now
for cls in ("block", "usb", "mic"):
    for m in ("Available", "Attached", "Assigned"):
        a, ln = resolve(rules, f"admin.vm.device.{cls}.{m}", MCP, AIVM)
        check(f"[4] direct .{cls}.{m} on ai-managed → DENY (line {ln})", a == "deny" and ln)

# the wrapper is the allowed path
a, _ = resolve(rules, "qmcp.ListAttachedDevicesAIManaged", MCP, ADMINVM)
check("wrapper qmcp.ListAttachedDevicesAIManaged @adminvm → allow", a == "allow")

# finding [5]: project-owned @adminvm denies (explicit, not fallthrough) for the
# methods with no operator use
for svc in ("admin.vm.device.block.Attached", "admin.vm.device.usb.Attached",
            "admin.vm.device.mic.Assigned", "admin.vm.device.block.Available",
            "admin.vm.device.mic.Available"):
    a, ln = resolve(rules, svc, MCP, ADMINVM)
    check(f"[5] {svc} @adminvm → explicit DENY (line {ln}, not platform fallthrough)",
          a == "deny" and ln)

# the operator's usb.{Available,List} @adminvm workflow still resolves `ask`
for svc in ("admin.vm.device.usb.Available", "admin.vm.device.usb.List"):
    a, _ = resolve(rules, svc, MCP, ADMINVM)
    check(f"operator {svc} @adminvm still 'ask' (G0b preserved)", a == "ask")

# --------------------------------------------------------------------------
print("\n" + "=" * 70)
print(f"  RESULT: {_passed} passed / {_failed} failed")
print("=" * 70)
sys.exit(1 if _failed else 0)
