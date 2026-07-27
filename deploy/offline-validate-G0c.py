#!/usr/bin/env python3
"""offline-validate-G0c.py — offline validation of Stage G0c (finding [6]:
inter-ai-managed qubes.Filecopy graduates to require ai-exec+ on BOTH endpoints).

A policy-only stage, so — per the I-4/I-5 lesson — the bulk of proof is an
offline first-match-wins simulator over the REAL public/policy/30-mcp-control.policy.
The slot (slot-73) only confirms the live qrexec daemon agrees on hardware.

What it proves (the qubes.Filecopy resolution matrix):
  1. PEER MESH: every (src,dst) with both in {ai-exec,ai-net,ai-full} → allow
     (the 3x3 cross-product; cumulative ladder expressed as literal tags).
  2. [6] CORE: an ai-exec+ source → an ai-ro target is DENIED (the fleet-wide
     "push into every ai-ro ~/QubesIncoming" blast radius is closed).
  3. an ai-ro source → anything (except the ai-dump sink) is DENIED (no
     integrity-inversion push up the ladder; ai-ro can't seed peers).
  4. ai-dump VALVE unchanged: any ai-managed source → an ai-dump target is
     allowed (the write-only sink line still wins, being ordered before the deny).
  5. [8] NO FALLTHROUGH: the ai-exec→ai-ro denial is an EXPLICIT in-file rule,
     not a fall-through to the system-default qubes.Filecopy `ask`.
  6. NO REGRESSION: the operator's own `qubes.Filecopy mcp-control @anyvm ask`
     still resolves `ask` (the new @tag:ai-managed deny never matches it).

Run from the repo root:   .venv/bin/python deploy/offline-validate-G0c.py
or from inside public/:   python3 deploy/offline-validate-G0c.py
"""
from __future__ import annotations

import sys
from pathlib import Path

POLICY = Path(__file__).resolve().parent.parent / "policy" / "30-mcp-control.policy"

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
    """First-match-wins → (action, lineno). Fallthrough → ('default', None) —
    the finding-[8] sentinel: 'default' means NO in-file rule matched, so the
    real outcome is whatever the SYSTEM-DEFAULT policy says (not self-contained)."""
    for svc, arg, src, tgt, act, lineno in rules:
        if svc not in (service, "*"):
            continue
        if arg != "*":
            continue
        if _match(src, source) and _match(tgt, target):
            return act, lineno
    return "default", None


rules = parse_policy(POLICY)

# tier fixtures (single-elevation tags: a qube carries the umbrella + at most one)
RO   = Qube("q-ro",   {"ai-managed"})
EXEC = Qube("q-exec", {"ai-managed", "ai-exec"})
NET  = Qube("q-net",  {"ai-managed", "ai-net"})
FULL = Qube("q-full", {"ai-managed", "ai-full"})
DUMP = Qube("q-dump", {"ai-dump"})            # pure sink (NOT ai-managed)
OP   = Qube("sys-firewall", {"operator"})     # out-of-scope operator qube
MCP  = Qube("mcp-control")

FC = "qubes.Filecopy"


def act(src, dst):
    return resolve_ex(rules, FC, src, dst)[0]


print("=" * 70)
print("  Stage G0c — qubes.Filecopy tier matrix (finding [6])")
print("=" * 70)

# 1. PEER MESH — every ai-exec+ × ai-exec+ pair is allowed.
print("\n1. Peer mesh: ai-exec+ ↔ ai-exec+ allowed (3x3 cross-product)")
ELEV = [("exec", EXEC), ("net", NET), ("full", FULL)]
for sn, s in ELEV:
    for dn, d in ELEV:
        check(f"{sn} → {dn} : allow", act(s, d) == "allow")

# 2. [6] CORE — ai-exec+ source → ai-ro target is DENIED.
print("\n2. [6] core: an ai-exec+ source CANNOT push into an ai-ro target")
for sn, s in ELEV:
    check(f"{sn} → ro : DENY (no fleet-wide push into ai-ro ~/QubesIncoming)",
          act(s, RO) == "deny")

# 3. ai-ro source cannot seed peers (except the dump sink, below).
print("\n3. ai-ro source cannot push up the ladder")
check("ro → ro   : DENY", act(RO, RO) == "deny")
check("ro → exec : DENY (no integrity inversion)", act(RO, EXEC) == "deny")
check("ro → operator-qube : DENY", act(RO, OP) == "deny")
check("exec → operator-qube : DENY", act(EXEC, OP) == "deny")

# 4. ai-dump valve unchanged — any ai-managed source may push to the sink.
print("\n4. ai-dump write-only sink unchanged (ordered before the deny)")
check("ro   → dump : allow (valve open to umbrella sources)", act(RO, DUMP) == "allow")
check("exec → dump : allow", act(EXEC, DUMP) == "allow")
check("full → dump : allow", act(FULL, DUMP) == "allow")

# 5. [8] no fallthrough — the ai-exec→ai-ro denial is an EXPLICIT in-file rule.
print("\n5. [8] the ai-exec→ai-ro denial is explicit, not a system-default fallthrough")
a, ln = resolve_ex(rules, FC, EXEC, RO)
check(f"exec → ro handled by an explicit rule (line {ln}), action={a}",
      a == "deny" and ln is not None)
a, ln = resolve_ex(rules, FC, RO, RO)
check(f"ro → ro handled by an explicit rule (line {ln}), not 'default'",
      a == "deny" and ln is not None)

# 6. NO REGRESSION — operator's own copy line + the ai-dump ordering.
print("\n6. No regression: operator copy line + ai-dump ordering")
a, _ = resolve_ex(rules, FC, MCP, OP)
check("operator: mcp-control → @anyvm still 'ask' (deny never matches mcp-control)",
      a == "ask")
# structural: the ai-dump allow line precedes the @tag:ai-managed @anyvm deny.
dump_ln = next((ln for (svc, ar, s, t, ac, ln) in rules
                if svc == FC and t == "@tag:ai-dump" and ac == "allow"), None)
deny_ln = next((ln for (svc, ar, s, t, ac, ln) in rules
                if svc == FC and s == "@tag:ai-managed" and t == "@anyvm" and ac == "deny"), None)
check("ai-dump allow line precedes the @tag:ai-managed @anyvm deny",
      dump_ln is not None and deny_ln is not None and dump_ln < deny_ln)

# --------------------------------------------------------------------------
print("\n" + "=" * 70)
print(f"  RESULT: {_passed} passed / {_failed} failed")
print("=" * 70)
sys.exit(1 if _failed else 0)
