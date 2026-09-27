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
  5. [8] NO FALLTHROUGH: the ai-exec→ai-ro decision is an EXPLICIT in-file rule,
     not a fall-through to the system-default qubes.Filecopy `ask`. Finding [8]
     is about OWNERSHIP of the rule, not about which action it names.
  6. NO REGRESSION: the operator's own `qubes.Filecopy mcp-control @anyvm ask`
     still resolves `ask` (the @tag:ai-managed deny never matches it).
  7. TEETH: the final ask and the ai-dump-source deny are each shown NECESSARY
     by removing them from the parsed rule set and re-resolving.
  8. REAL ENGINE: the same questions put to qrexec's own parser
     (python3-qrexec), including the two request shapes the simulator above
     cannot express — `@default` (what `qvm-copy` sends) and a NAME THAT DOES
     NOT EXIST. Missing module -> the suite exits 3 (INCOMPLETE), never 0.

UPDATED 2026-08-19 (operator decision). Points 2 and 3 asserted `deny` where the
file now says `ask`. G0c's actual property is that one operator ai-exec grant
must not become a SILENT fleet-wide data plane; `deny` was the strongest answer
available while the umbrella peer line was simply absent — G0c being the one
tag-scoped surface graduated with no compat backstop, which is why an operator
could not hand-copy out of a qube they own. The assertions were inverted WITH
the code and now pin the property that matters: never `allow`.

UPDATED 2026-09-27 (operator decision). Leaving the umbrella is now the
ordinary operator dialog: the last Filecopy rule for an ai-managed source is
`@tag:ai-managed -> @anyvm ask`, replacing both the tag-scoped ask and the
dialog-free `@anyvm deny`. Two reasons, both measured with the real engine:
`qvm-copy` sends `@default`, which `@anyvm` matches, so the old deny refused
every `qvm-copy` from an AI qube before any ask fired (the operator reported it
twice); and the old deny's justification -- that an `@anyvm` ask would let an
agent learn which qube names exist -- is false, because qrexec replaces a
nonexistent target with `@default`. The simulator in this file never modelled
either shape, which is why v0.9.12's suite passed with the gap in place; §8
exists so that cannot happen again.

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

# 2. [6] CORE — INVERTED 2026-08-19, with the code, not around it.
# G0c's property was "one operator ai-exec grant must not become a SILENT
# fleet-wide data plane". It asserted that as `deny`, which was the strongest
# available answer while the umbrella peer line was simply missing — G0c is the
# one tag-scoped surface graduated with no compat backstop, so an untiered qube
# lost hand-copy entirely and the operator could not move a file out of a qube
# they own. The operator's decision (2026-08-19) is an ASK: still not a silent
# push, because every one of these now costs an operator click, and AI cannot
# click zenity. What must NEVER hold is `allow` — that is the property, and it
# is what these now assert.
print("\n2. [6] core: an ai-exec+ source cannot SILENTLY push into an ai-ro target")
for sn, s in ELEV:
    check(f"{sn} → ro : never ALLOW (operator dialog, not a silent push)",
          act(s, RO) != "allow")
    check(f"{sn} → ro : specifically ASK (the 2026-08-19 decision)",
          act(s, RO) == "ask")

# 3. ai-ro source cannot seed peers SILENTLY (except the dump sink, below).
print("\n3. ai-ro source cannot push up the ladder without an operator")
check("ro → ro   : never ALLOW", act(RO, RO) != "allow")
check("ro → ro   : ASK", act(RO, RO) == "ask")
check("ro → exec : never ALLOW (no silent integrity inversion)",
      act(RO, EXEC) != "allow")
check("ro → exec : ASK", act(RO, EXEC) == "ask")
# Leaving the umbrella — INVERTED 2026-09-27 with the policy (operator
# decision): the ordinary operator dialog, where it was a dialog-free deny.
# The property that must hold is the same one as inside: never ALLOW.
check("ro → operator-qube : never ALLOW (no silent copy out)", act(RO, OP) != "allow")
check("ro → operator-qube : ASK (the 2026-09-27 decision)", act(RO, OP) == "ask")
check("exec → operator-qube : never ALLOW", act(EXEC, OP) != "allow")
check("exec → operator-qube : ASK", act(EXEC, OP) == "ask")

# 3b. The price of introducing an ask: a MISCONFIGURED hybrid must not become a
# way back in. Without this rule the hybrid matches the new
# @tag:ai-managed → @tag:ai-managed ask as a SOURCE and the valve is dialogued
# open. It also closes a real fallthrough that predates the change: a PURE sink
# copying back into the fleet previously matched no rule here at all and landed
# on the Qubes system-default ask (finding [8]'s hazard, in the one direction
# G0c did not cover).
print("\n3b. the ai-dump valve survives the introduction of an ask")
HYBRID = Qube("q-hybrid", {"ai-managed", "ai-dump"})
check("hybrid (ai-managed+ai-dump) → exec : DENY, not a dialog",
      act(HYBRID, EXEC) == "deny")
check("hybrid → ro : DENY", act(HYBRID, RO) == "deny")
check("pure sink → exec : DENY (was a SYSTEM-DEFAULT fallthrough before)",
      act(DUMP, EXEC) == "deny")
check("pure sink → ro : DENY", act(DUMP, RO) == "deny")
# ...and the operator can still DRAIN a buffer by hand: sink → out-of-umbrella
# is deliberately NOT denied, so it falls to the system default and prompts.
check("sink → operator-qube : NOT denied here (the operator drains the buffer)",
      act(DUMP, OP) != "deny")

# 4. ai-dump valve unchanged — any ai-managed source may push to the sink.
print("\n4. ai-dump write-only sink unchanged (ordered before the deny)")
check("ro   → dump : allow (valve open to umbrella sources)", act(RO, DUMP) == "allow")
check("exec → dump : allow", act(EXEC, DUMP) == "allow")
check("full → dump : allow", act(FULL, DUMP) == "allow")

# 5. [8] no fallthrough — the ai-exec→ai-ro denial is an EXPLICIT in-file rule.
print("\n5. [8] every AI-sourced copy is decided in THIS file, not by a system-default fallthrough")
# Finding [8] is about OWNERSHIP of the rule, not about which action it names:
# the hazard was landing on a system-default dialog governed by a policy file
# this project does not own. An explicit `ask` in OUR file closes that exactly
# as completely as an explicit `deny` did. So these assert the rule is ours and
# names a decided action — never 'default'.
DECIDED = {"deny", "ask"}
a, ln = resolve_ex(rules, FC, EXEC, RO)
check(f"exec → ro handled by an explicit rule in THIS file (line {ln}), action={a}",
      a in DECIDED and ln is not None)
a, ln = resolve_ex(rules, FC, RO, RO)
check(f"ro → ro handled by an explicit rule (line {ln}), not 'default'",
      a in DECIDED and ln is not None)
a, ln = resolve_ex(rules, FC, EXEC, OP)
check(f"exec → out-of-umbrella decided by an explicit ASK in THIS file (line {ln})",
      a == "ask" and ln is not None)

# 7. TEETH — remove each 2026-08-19 rule from the parsed set and re-resolve.
# A suite that only asserts the new behaviour passes just as happily against a
# file that never had the problem, so each rule is shown NECESSARY before it is
# shown present.
print("\n7. Teeth: the final ask and the dump-source deny are each necessary, not decorative")

def _without(pred):
    return [r for r in rules if not pred(r)]

def _act(rs, src, dst):
    return resolve_ex(rs, FC, src, dst)[0]

# Drop the final ask: every copy the mesh and the sink do not cover falls out
# of this file to the Qubes SYSTEM-DEFAULT policy — finding [8]'s hazard.
no_ask = _without(lambda r: r[0] == FC and r[2] == "@tag:ai-managed"
                  and r[3] == "@anyvm" and r[4] == "ask")
check("teeth: WITHOUT the final ask, ro → ro falls through to the system default",
      resolve_ex(no_ask, FC, RO, RO)[1] is None)
check("teeth: WITHOUT it, exec → out-of-umbrella falls through too",
      resolve_ex(no_ask, FC, EXEC, OP)[1] is None)

# Drop the dump-source deny: the misconfigured hybrid becomes dialoguable back
# into the fleet, which is the valve defeated — and a PURE sink falls through to
# the system default, which is finding [8]'s hazard in the return direction.
no_deny = _without(lambda r: r[0] == FC and r[2] == "@tag:ai-dump"
                   and r[3] == "@tag:ai-managed" and r[4] == "deny")
check("teeth: WITHOUT the dump-source deny, a hybrid can be dialogued back in",
      _act(no_deny, HYBRID, EXEC) == "ask")
check("teeth: WITHOUT it, a PURE sink falls through to the system default",
      resolve_ex(no_deny, FC, DUMP, EXEC)[1] is None)
check("teeth: ...and WITH it, neither does",
      _act(rules, HYBRID, EXEC) == "deny" and _act(rules, DUMP, EXEC) == "deny")

# Ordering is the whole mechanism: the ask must sit AFTER the tiered mesh, or a
# pair that works dialog-free today starts prompting.
ask_ln = next(ln for (svc, ar, s_, t_, ac, ln) in rules
              if svc == FC and s_ == "@tag:ai-managed" and t_ == "@anyvm"
              and ac == "ask")
mesh_max = max(ln for (svc, ar, s_, t_, ac, ln) in rules
               if svc == FC and ac == "allow" and t_ != "@tag:ai-dump")
dump_ln2 = next(ln for (svc, ar, s_, t_, ac, ln) in rules
                if svc == FC and t_ == "@tag:ai-dump" and ac == "allow")
check("teeth: the ask is ordered AFTER the whole tiered mesh",
      ask_ln > mesh_max)
check("teeth: the ask is ordered AFTER the ai-dump valve",
      ask_ln > dump_ln2)
check("teeth: the dump-source deny precedes the ask (else the hybrid slips)",
      next(ln for (svc, ar, s_, t_, ac, ln) in rules
           if svc == FC and s_ == "@tag:ai-dump" and ac == "deny") < ask_ln)
check("structure: no dialog-free `@tag:ai-managed -> @anyvm deny` remains",
      not any(svc == FC and s_ == "@tag:ai-managed" and t_ == "@anyvm" and ac == "deny"
              for (svc, ar, s_, t_, ac, ln) in rules))

# 6. NO REGRESSION — operator's own copy line + the ai-dump ordering.
print("\n6. No regression: operator copy line + ai-dump ordering")
a, _ = resolve_ex(rules, FC, MCP, OP)
check("operator: mcp-control → @anyvm still 'ask' (deny never matches mcp-control)",
      a == "ask")
# structural: the ai-dump allow line precedes the @tag:ai-managed @anyvm ask.
dump_ln = next((ln for (svc, ar, s, t, ac, ln) in rules
                if svc == FC and t == "@tag:ai-dump" and ac == "allow"), None)
last_ln = next((ln for (svc, ar, s, t, ac, ln) in rules
                if svc == FC and s == "@tag:ai-managed" and t == "@anyvm" and ac == "ask"), None)
check("ai-dump allow line precedes the @tag:ai-managed @anyvm ask",
      dump_ln is not None and last_ln is not None and dump_ln < last_ln)

# 8. The REAL qrexec engine. The simulator above re-implements first-match-wins
# over NAMED qubes only, which is exactly why the `qvm-copy` gap passed it: a
# `qvm-copy` request carries no target (`@default`), and a target that does not
# exist is rewritten to `@default` by the engine itself. Neither shape exists in
# `_match`. Putting the questions to qrexec's own parser is the lesson this
# project already wrote down ("call the project's own verifier; reimplementing
# it tests your reimplementation"), applied to the policy engine.
print("\n8. Real qrexec engine: @default, made-up names, the stock default file")
ENGINE_RAN = False
try:
    import logging as _logging
    import uuid as _uuid
    from qrexec.policy.parser import StringPolicy as _SP, Request as _Req
    from qrexec.exc import AccessDenied as _Denied, RequestError as _ReqErr
except ImportError:
    print("  NOT-RUN  python3-qrexec is not importable on this host — the suite")
    print("           cannot vouch for @default or made-up-name behaviour.")
else:
    ENGINE_RAN = True
    _logging.disable(_logging.WARNING)   # the engine logs every @default rewrite

    def _dom(tags, klass="AppVM", dvmt=False):
        return {"tags": list(tags), "type": klass, "default_dispvm": None,
                "template_for_dispvms": dvmt, "power_state": "Running",
                "uuid": str(_uuid.uuid4())}

    _SI = {"domains": {
        "dom0": _dom([], "AdminVM"),
        "mcp-control": _dom([]),
        "q-ro": _dom(["ai-managed"]),
        "q-exec": _dom(["ai-managed", "ai-exec"]),
        "q-full": _dom(["ai-managed", "ai-full"]),
        "q-dump": _dom(["ai-dump"]),
        "q-hybrid": _dom(["ai-managed", "ai-dump"]),
        "sys-firewall": _dom([]),
        "op-dvm": _dom([], dvmt=True),
    }}
    # The one line of the stock Qubes 90-default.policy that governs this
    # service. Modelling it is what lets a fall-through be told apart from a
    # decision made in OUR file (finding [8]).
    _STOCK = "qubes.Filecopy * @anyvm @anyvm ask\n"

    def _engine(policy_text):
        return _SP(policy={"__main__": "!include 30\n!include 90\n",
                           "30": policy_text, "90": _STOCK})

    def _ev(pol, src, tgt):
        """-> (ACTION, file-of-deciding-rule, targets offered in the dialog)"""
        try:
            r = pol.evaluate(_Req(FC, "+", src, tgt, system_info=_SI))
        except (_Denied, _ReqErr) as e:
            where = "30" if "30[" in str(e) else ("90" if "90[" in str(e) else "-")
            return "DENY", where, frozenset()
        kind = type(r).__name__.replace("Resolution", "").upper()
        offered = frozenset(getattr(r, "targets_for_ask", None) or ())
        return kind, str(r.rule.filepath).split("[")[0], offered

    text = POLICY.read_text(encoding="utf-8")
    real = _engine(text)

    # 8a. `qvm-copy` — no target. The request the old deny swallowed.
    for src in ("q-ro", "q-exec", "q-full"):
        k, f, offered = _ev(real, src, "@default")
        check(f"{src} → @default (qvm-copy): ASK decided in THIS file", k == "ASK" and f == "30")
        check(f"{src} → @default: the dialog offers a qube OUTSIDE the umbrella",
              "sys-firewall" in offered)
        check(f"{src} → @default: the dialog offers the ai-dump sink and a peer",
              "q-dump" in offered and "q-full" in offered | {src} and "dom0" not in offered)

    # 8b. Named targets, unchanged where they were already right.
    check("q-exec → q-full : ALLOW (mesh, no dialog)", _ev(real, "q-exec", "q-full")[0] == "ALLOW")
    check("q-exec → q-ro   : ASK (never a silent push down)", _ev(real, "q-exec", "q-ro")[0] == "ASK")
    check("q-ro   → q-exec : ASK", _ev(real, "q-ro", "q-exec")[0] == "ASK")
    check("q-exec → q-dump : ALLOW (the valve)", _ev(real, "q-exec", "q-dump")[0] == "ALLOW")
    check("q-dump   → q-exec : DENY (sink stays write-only)", _ev(real, "q-dump", "q-exec")[0] == "DENY")
    check("q-hybrid → q-exec : DENY (misconfigured hybrid stays shut)",
          _ev(real, "q-hybrid", "q-exec")[0] == "DENY")
    k, f, _ = _ev(real, "q-dump", "sys-firewall")
    check("q-dump → out-of-umbrella : ASK by the stock default (operator drains it)",
          k == "ASK" and f == "90")
    check("q-exec → dom0 : DENY", _ev(real, "q-exec", "dom0")[0] == "DENY")
    check("mcp-control → @default : ASK (operator's own line, unchanged)",
          _ev(real, "mcp-control", "@default")[0] == "ASK")

    # 8c. Leaving the umbrella, and the absence of a name oracle. A real qube
    # outside the umbrella and a name that exists nowhere must look the same
    # from the source: both a dialog. If one were an instant refusal and the
    # other a dialog, an agent could map the host by guessing names.
    real_out = _ev(real, "q-exec", "sys-firewall")
    made_up = _ev(real, "q-exec", "no-such-qube")
    check("q-exec → out-of-umbrella qube : ASK decided in THIS file",
          real_out[0] == "ASK" and real_out[1] == "30")
    check("q-exec → a name that does not exist : ASK as well (no existence oracle)",
          made_up[0] == "ASK" and made_up[1] == "30")

    # Known residual, reported rather than asserted: `@dispvm:<name>` is
    # refused before any rule is read when <name> is not a disposable
    # template, so DVMT names are probeable. The policy comment states this.
    dv_real = _ev(real, "q-exec", "@dispvm:op-dvm")[0]
    dv_fake = _ev(real, "q-exec", "@dispvm:sys-firewall")[0]
    print(f"  INFO  residual: @dispvm:<a DVMT> -> {dv_real}, @dispvm:<not a DVMT> -> {dv_fake}"
          " (DVMT names are probeable; documented in the policy)")

    # 8d. Teeth: the v0.9.14 shape, rebuilt from the current file by turning
    # the final ask back into the old dialog-free deny. The same checks must
    # FAIL against it, or this section proves nothing.
    old_text = text.replace(
        "qubes.Filecopy              *  @tag:ai-managed  @anyvm          ask",
        "qubes.Filecopy              *  @tag:ai-managed  @anyvm          deny")
    check("teeth: the rebuild really changed the file", old_text != text)
    old = _engine(old_text)
    check("teeth: under the old deny, q-exec → @default is a dialog-free DENY (the bug)",
          _ev(old, "q-exec", "@default")[0] == "DENY")
    check("teeth: under the old deny, a made-up name is refused instantly",
          _ev(old, "q-exec", "no-such-qube")[0] == "DENY")

# --------------------------------------------------------------------------
print("\n" + "=" * 70)
print(f"  RESULT: {_passed} passed / {_failed} failed"
      + ("" if ENGINE_RAN else "  — INCOMPLETE: real-engine section NOT-RUN"))
print("=" * 70)
# 1 = a check failed. 3 = INCOMPLETE: nothing failed but the real-engine
# section could not run, which is NOT green (the anti-grep lesson).
sys.exit(1 if _failed else (0 if ENGINE_RAN else 3))
