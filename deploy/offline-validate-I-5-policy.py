#!/usr/bin/env python3
"""offline-validate-I-5-policy.py — ships in public/deploy/ alongside test-stage-*.py.

The I-5 companion to offline-validate-I-4.py. I-5 has TWO risk surfaces:
  - the dom0 WRAPPER code (CAP_FULL gate) → offline-validate-I-5.py (mocked qubesadmin)
  - the POLICY diff (exec/copy graduate to @tag:ai-exec + compat backstop) → THIS file

This parses the REAL public/policy/30-mcp-control.policy, re-implements qrexec
first-match-wins (same R4.3 model as I-4: @anyvm excludes @adminvm, @tag:
membership, first match wins, default-deny), and asserts the EXEC surface
(qmcp.RunInAIManaged / qmcp.CopyToAIManaged) x tier for BOTH:

  - COMPAT (as shipped — all FOUR backstops present), and
  - POST-FLIP (all four @tag:ai-managed backstops removed: firewall.Set,
    firewall.Reload from I-4, RunInAIManaged, CopyToAIManaged from I-5 — what
    the I-5 flip slot will do, paired with tier-default -> "ro").

It also re-confirms the I-4 firewall matrix under the 4-backstop flip (the flip
is now coupled across all four lines) and that the ai-dump valve is unchanged.
"""
from __future__ import annotations

import sys
from pathlib import Path

# This file lives in public/deploy/; the policy it parses is a sibling at
# public/policy/. Resolve it relative to THIS file's directory (the standard
# os.path.dirname(os.path.realpath(__file__)) sibling-load pattern, via pathlib
# here), so it runs from the repo root AND from inside public/.
POLICY = Path(__file__).resolve().parent.parent / "policy" / "30-mcp-control.policy"

EXEC_SERVICES = ("qmcp.RunInAIManaged", "qmcp.CopyToAIManaged")
FW_WRITE = ("admin.vm.firewall.Set", "admin.vm.firewall.Reload")
BACKSTOP_SERVICES = set(EXEC_SERVICES) | set(FW_WRITE)


class Qube:
    def __init__(self, name, tags=(), adminvm=False):
        self.name = name
        self.tags = set(tags)
        self.adminvm = adminvm


class Rule:
    __slots__ = ("service", "argument", "source", "target", "action", "lineno")

    def __init__(self, service, argument, source, target, action, lineno):
        self.service, self.argument, self.source = service, argument, source
        self.target, self.action, self.lineno = target, action, lineno


def parse_policy(path):
    rules = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        toks = s.split()
        if len(toks) < 5:
            raise SystemExit(f"FATAL line {i}: <5 fields (inline comment?): {s!r}")
        if toks[4] not in ("allow", "deny", "ask"):
            raise SystemExit(f"FATAL line {i}: 5th field not an action: {toks[4]!r}")
        rules.append(Rule(*toks[:5], i))
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


def resolve(rules, service, source, target):
    for r in rules:
        if r.service not in (service, "*"):
            continue
        if r.argument != "*":
            continue
        if not _match(r.source, source) or not _match(r.target, target):
            continue
        return r.action
    return "deny"


def flip(rules):
    """The REAL I-5 flip: drop ALL FOUR @tag:ai-managed compat backstops
    (firewall.Set + firewall.Reload + RunInAIManaged + CopyToAIManaged)."""
    return [r for r in rules
            if not (r.service in BACKSTOP_SERVICES
                    and r.target == "@tag:ai-managed"
                    and r.action == "allow")]


MCP = Qube("mcp-control")
TARGETS = {
    "untiered/ro": Qube("q-ro", {"ai-managed"}),
    "exec":        Qube("q-exec", {"ai-managed", "ai-exec"}),
    "net":         Qube("q-net", {"ai-managed", "ai-net"}),
    "full":        Qube("q-full", {"ai-managed", "ai-full"}),
    "dump":        Qube("q-dump", {"ai-dump"}),
    "untagged":    Qube("sys-firewall", {"operator-only"}),
    "dom0":        Qube("dom0", adminvm=True),
    "ghost":       Qube("no-such-qube"),
}

# exec/copy — COMPAT: backstop keeps every umbrella tier executable.
EXEC_COMPAT = {
    "untiered/ro": "allow", "exec": "allow", "net": "allow", "full": "allow",
    "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
}
# exec/copy — POST-FLIP: ro LOSES exec; exec/net/full keep it (cumulative).
EXEC_POSTFLIP = {
    "untiered/ro": "deny", "exec": "allow", "net": "allow", "full": "allow",
    "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
}
# firewall WRITE under the 4-backstop flip — ro+exec lose write, net+full keep.
FW_POSTFLIP = {
    "untiered/ro": "deny", "exec": "deny", "net": "allow", "full": "allow",
    "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
}
FW_COMPAT = {k: ("allow" if k in ("untiered/ro", "exec", "net", "full") else "deny")
             for k in TARGETS}


def run_matrix(rules, services, expected, phase):
    print(f"\n{'=' * 68}\n  {phase}\n{'=' * 68}")
    p = f = 0
    for svc in services:
        for tier, want in expected.items():
            got = resolve(rules, svc, MCP, TARGETS[tier])
            ok = got == want
            p += ok
            f += not ok
            note = "" if ok else f"   <<< expected {want}"
            print(f"  {'PASS' if ok else 'FAIL'}  {svc:24s} -> {tier:12s} : {got}{note}")
    return p, f


def main():
    if not POLICY.exists():
        raise SystemExit(f"FATAL: policy not found at {POLICY}")
    rules = parse_policy(POLICY)
    flipped = flip(rules)
    removed = len(rules) - len(flipped)
    print(f"Parsed {len(rules)} rules. Flip removes {removed} backstop line(s) "
          f"(expect 4: fw.Set + fw.Reload + Run + Copy).")

    tp = tf = 0
    a, b = run_matrix(rules, EXEC_SERVICES, EXEC_COMPAT,
                      "PHASE 1 — exec/copy COMPAT (behaviour-neutral, backstop live)")
    tp += a; tf += b
    a, b = run_matrix(flipped, EXEC_SERVICES, EXEC_POSTFLIP,
                      "PHASE 2 — exec/copy POST-FLIP (ro denied; ai-exec+ allowed)")
    tp += a; tf += b
    a, b = run_matrix(rules, FW_WRITE, FW_COMPAT,
                      "PHASE 3 — firewall WRITE COMPAT (unchanged from I-4)")
    tp += a; tf += b
    a, b = run_matrix(flipped, FW_WRITE, FW_POSTFLIP,
                      "PHASE 4 — firewall WRITE POST-FLIP (coupled in the same flip)")
    tp += a; tf += b

    # firewall.Get + device-list stay ro-floor (the flip must not touch reads)
    a, b = run_matrix(rules, ("admin.vm.firewall.Get",),
                      FW_COMPAT, "PHASE 5 — reads stay ro-floor (compat)")
    tp += a; tf += b
    a, b = run_matrix(flipped, ("admin.vm.firewall.Get",),
                      FW_COMPAT, "PHASE 6 — reads UNCHANGED by the flip")
    tp += a; tf += b

    print(f"\n{'=' * 68}\n  structural guards\n{'=' * 68}")
    WORKER = Qube("q-worker", {"ai-managed"})
    DUMP = TARGETS["dump"]
    guards = [
        ("flip removes EXACTLY 4 backstop lines", removed == 4),
        ("compat: ro qube CAN exec (RunInAIManaged allow)",
         resolve(rules, "qmcp.RunInAIManaged", MCP, TARGETS["untiered/ro"]) == "allow"),
        ("post-flip: ro qube CANNOT exec",
         resolve(flipped, "qmcp.RunInAIManaged", MCP, TARGETS["untiered/ro"]) == "deny"),
        ("post-flip: ai-exec qube CAN exec but CANNOT write firewall",
         resolve(flipped, "qmcp.RunInAIManaged", MCP, TARGETS["exec"]) == "allow"
         and resolve(flipped, "admin.vm.firewall.Set", MCP, TARGETS["exec"]) == "deny"),
        ("ai-dump valve copy-IN allowed in BOTH phases (flip doesn't touch it)",
         resolve(rules, "qubes.Filecopy", WORKER, DUMP) == "allow"
         and resolve(flipped, "qubes.Filecopy", WORKER, DUMP) == "allow"),
        ("catch-all still denies an unmatched mcp-control call (both phases)",
         resolve(rules, "qmcp.RunInAIManaged", MCP, TARGETS["untagged"]) == "deny"
         and resolve(flipped, "qmcp.CopyToAIManaged", MCP, TARGETS["untagged"]) == "deny"),
    ]
    for label, cond in guards:
        ok = bool(cond)
        tp += ok
        tf += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")

    print(f"\n{'=' * 68}\n  TOTAL: {tp}/{tp + tf} green ({tf} failing)\n{'=' * 68}")
    return 0 if tf == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
