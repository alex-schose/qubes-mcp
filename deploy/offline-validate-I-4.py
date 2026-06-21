#!/usr/bin/env python3
"""offline-validate-I-4.py — ships in public/deploy/ alongside test-stage-*.py.

Stage I-4 applies the tier ladder to the directly-`@tag:`-scoped policy
surfaces (firewall, device-list) and adds the `ai-dump` write-only sink.
Because the policy layer matches `@tag:` selectors LITERALLY (it cannot call
qmcp_tier), the whole risk surface of I-4 is the policy FILE itself — which
rule matches which (service, source, target-tier). So, exactly like I-2/I-3,
the bulk of coverage is OFFLINE here: this script parses the real
`public/policy/30-mcp-control.policy`, re-implements qrexec first-match-wins
resolution, and asserts the full (surface x tier) matrix for BOTH:

  - COMPAT (the file as shipped — firewall WRITE backstop present), and
  - POST-FLIP (the two `admin.vm.firewall.{Set,Reload} ... @tag:ai-managed
    allow` backstop lines removed — what the I-5 flip will do).

No hardware. The slot proves the same matrix on real qrexec; this proves the
LOGIC exhaustively first, so a slot is only ever burned on already-correct
policy. The opaqueness of a refusal (every deny looks identical to AI) is a
property of the MCP `_qrexec.py` normaliser + the single catch-all funnel, and
is asserted on hardware; here we assert the allow/deny DECISION per tier.

qrexec matching modelled (per the R4.3 findings in NEXT.md, slot-16/18):
  *            — wildcard, matches anything
  @anyvm       — any VM, but EXCLUDES @adminvm/dom0
  @adminvm     — the dom0 target only (alias: dom0)
  @tag:NAME    — the qube carries tag NAME
  <literal>    — exact qube-name match
First rule whose (service, argument, source, target) all match wins; if none
matches, the request is DENIED (qrexec default-deny / "no matching rule").
"""
from __future__ import annotations

import sys
from pathlib import Path

# This file lives in public/deploy/; the policy it parses is a sibling at
# public/policy/. Resolve it relative to THIS file's directory (the standard
# os.path.dirname(os.path.realpath(__file__)) sibling-load pattern, via pathlib
# here), so it runs from the repo root AND from inside public/ with no cwd
# assumption and no hardcoded path.
POLICY = Path(__file__).resolve().parent.parent / "policy" / "30-mcp-control.policy"


# ---------------------------------------------------------------- model
class Qube:
    """A target/source endpoint: a name plus its tag set. `adminvm` marks dom0."""

    def __init__(self, name: str, tags=(), adminvm: bool = False):
        self.name = name
        self.tags = set(tags)
        self.adminvm = adminvm


class Rule:
    __slots__ = ("service", "argument", "source", "target", "action", "lineno", "raw")

    def __init__(self, service, argument, source, target, action, lineno, raw):
        self.service = service
        self.argument = argument
        self.source = source
        self.target = target
        self.action = action
        self.lineno = lineno
        self.raw = raw


def parse_policy(path: Path) -> list[Rule]:
    rules = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        toks = s.split()
        if len(toks) < 5:
            raise SystemExit(f"FATAL: rule line {i} has <5 fields (inline comment?): {s!r}")
        service, argument, source, target, action = toks[:5]
        if action not in ("allow", "deny", "ask"):
            raise SystemExit(f"FATAL: rule line {i} 5th field not an action: {action!r} :: {s!r}")
        rules.append(Rule(service, argument, source, target, action, i, s))
    return rules


def _endpoint_match(token: str, q: Qube) -> bool:
    if token == "*":
        return True
    if token == "@anyvm":
        return not q.adminvm           # @anyvm explicitly excludes @adminvm/dom0
    if token in ("@adminvm", "dom0"):
        return q.adminvm
    if token.startswith("@tag:"):
        return token[5:] in q.tags
    return token == q.name             # literal name


def resolve(rules: list[Rule], service: str, source: Qube, target: Qube) -> str:
    """qrexec first-match-wins; default DENY when nothing matches."""
    for r in rules:
        if r.service not in (service, "*"):
            continue
        # argument is always "*" in this policy; calls carry none we scope on
        if r.argument != "*":
            continue
        if not _endpoint_match(r.source, source):
            continue
        if not _endpoint_match(r.target, target):
            continue
        return r.action
    return "deny"                       # no matching rule == refused


def flip(rules: list[Rule]) -> list[Rule]:
    """The I-5 flip: drop the firewall-WRITE compat backstop lines."""
    out = []
    for r in rules:
        is_backstop = (
            r.service in ("admin.vm.firewall.Set", "admin.vm.firewall.Reload")
            and r.target == "@tag:ai-managed"
            and r.action == "allow"
        )
        if not is_backstop:
            out.append(r)
    return out


# ---------------------------------------------------------------- fixtures
MCP = Qube("mcp-control")                                   # the AI source
# tier fixtures (requested targets), keyed by tier label:
TARGETS = {
    "untiered/ro": Qube("q-ro",   {"ai-managed"}),
    "exec":        Qube("q-exec", {"ai-managed", "ai-exec"}),
    "net":         Qube("q-net",  {"ai-managed", "ai-net"}),
    "full":        Qube("q-full", {"ai-managed", "ai-full"}),
    "dump":        Qube("q-dump", {"ai-dump"}),             # NOT ai-managed
    "untagged":    Qube("sys-firewall", {"operator-only"}),
    "dom0":        Qube("dom0", adminvm=True),
    "ghost":       Qube("no-such-qube"),                    # no tags
}
# ai-managed worker as a *source* (for Filecopy valve + inter-copy):
WORKER = Qube("q-worker", {"ai-managed"})
DUMP_SRC = Qube("q-dump", {"ai-dump"})
# A HYBRID (ai-managed + ai-dump) — an OPERATOR MISCONFIG. The write-only
# guarantee does NOT hold for it; we assert that read-out below so the known
# limitation is documented + tested, not hidden. (AI cannot create this — no
# tag mutation; the installer warns + I-5 machine-refuses it.)
HYBRID = Qube("q-hybrid", {"ai-managed", "ai-dump"})


# ---------------------------------------------------------------- expectations
# A=allow, D=deny (ask treated distinctly where it appears). Each row: service
# -> {tier: expected-action}. "_src" overrides the source qube for that row.
def fw(get_w):
    """firewall.Get is ro-floor (any ai-managed tier); Set/Reload per `get_w`."""
    return get_w


COMPAT = {
    # reads / enumerate — ro-floor: every ai-managed tier allowed; non-umbrella denied
    "admin.vm.firewall.Get": {
        "untiered/ro": "allow", "exec": "allow", "net": "allow", "full": "allow",
        "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
    },
    "admin.vm.device.block.List": {
        "untiered/ro": "allow", "exec": "allow", "net": "allow", "full": "allow",
        "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
    },
    # exec surface — I-4 leaves it at the umbrella floor (tiering is I-5). Guard
    # that I-4 did NOT accidentally move it.
    "qmcp.RunInAIManaged": {
        "untiered/ro": "allow", "exec": "allow", "net": "allow", "full": "allow",
        "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
    },
    # firewall WRITE — compat: backstop keeps every umbrella tier writable
    "admin.vm.firewall.Set": {
        "untiered/ro": "allow", "exec": "allow", "net": "allow", "full": "allow",
        "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
    },
    "admin.vm.firewall.Reload": {
        "untiered/ro": "allow", "exec": "allow", "net": "allow", "full": "allow",
        "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
    },
}

POSTFLIP = {
    # reads unchanged by the flip
    "admin.vm.firewall.Get": COMPAT["admin.vm.firewall.Get"],
    "admin.vm.device.block.List": COMPAT["admin.vm.device.block.List"],
    "qmcp.RunInAIManaged": COMPAT["qmcp.RunInAIManaged"],
    # firewall WRITE — flip: ro + exec LOSE write; net + full keep it
    "admin.vm.firewall.Set": {
        "untiered/ro": "deny", "exec": "deny", "net": "allow", "full": "allow",
        "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
    },
    "admin.vm.firewall.Reload": {
        "untiered/ro": "deny", "exec": "deny", "net": "allow", "full": "allow",
        "dump": "deny", "untagged": "deny", "dom0": "deny", "ghost": "deny",
    },
}


# ---------------------------------------------------------------- runner
def run_matrix(rules, expected, phase):
    print(f"\n{'=' * 70}\n  {phase}\n{'=' * 70}")
    npass = nfail = 0
    for service, row in expected.items():
        for tier, want in row.items():
            got = resolve(rules, service, MCP, TARGETS[tier])
            ok = got == want
            npass += ok
            nfail += not ok
            mark = "PASS" if ok else "FAIL"
            note = "" if ok else f"   <<< expected {want}"
            print(f"  {mark}  {service:28s} -> {tier:12s} : {got}{note}")
    return npass, nfail


def run_filecopy(rules, phase):
    print(f"\n{'=' * 70}\n  {phase} — qubes.Filecopy valve + sink invariants\n{'=' * 70}")
    cases = [
        # (label, source, target, expected)
        ("ai-managed  -> ai-dump   (the valve, copy-IN)", WORKER, TARGETS["dump"], "allow"),
        ("ai-managed  -> ai-managed (inter-copy, unchanged)", WORKER, WORKER, "allow"),
        ("ai-managed  -> untagged  (no exfil to random qube)", WORKER, TARGETS["untagged"], "deny"),
        ("ai-managed  -> dom0      (no exfil to dom0)", WORKER, TARGETS["dom0"], "deny"),
        ("ai-dump     -> ai-managed (sink is WRITE-ONLY)", DUMP_SRC, WORKER, "deny"),
        ("ai-dump     -> ai-dump    (cannot read its own sink)", DUMP_SRC, TARGETS["dump"], "deny"),
    ]
    npass = nfail = 0
    for label, src, tgt, want in cases:
        got = resolve(rules, "qubes.Filecopy", src, tgt)
        ok = got == want
        npass += ok
        nfail += not ok
        mark = "PASS" if ok else "FAIL"
        note = "" if ok else f"   <<< expected {want}"
        print(f"  {mark}  {label:50s} : {got}{note}")
    return npass, nfail


def main() -> int:
    if not POLICY.exists():
        raise SystemExit(f"FATAL: policy not found at {POLICY}")
    rules = parse_policy(POLICY)
    flipped = flip(rules)
    removed = len(rules) - len(flipped)
    print(f"Parsed {len(rules)} rules from {POLICY.name}.")
    print(f"Flip simulation removes {removed} firewall-WRITE backstop line(s) "
          f"(expect 2: Set + Reload).")

    tp = tf = 0
    a, b = run_matrix(rules, COMPAT, "PHASE 1 — COMPAT (policy as shipped)")
    tp += a; tf += b
    a, b = run_filecopy(rules, "PHASE 1 — COMPAT")
    tp += a; tf += b
    a, b = run_matrix(flipped, POSTFLIP, "PHASE 2 — POST-FLIP (backstop removed)")
    tp += a; tf += b
    a, b = run_filecopy(flipped, "PHASE 2 — POST-FLIP")
    tp += a; tf += b

    # HYBRID CAVEAT — document the known limitation explicitly (red-team finding).
    # A qube tagged BOTH ai-managed and ai-dump is NOT write-only: the inter-copy
    # line matches it as a source, so its contents read back out. These checks
    # assert that (mis)behaviour so it is acknowledged + tested, not silently
    # green. The fix is operator-side (disjointness): installer warns, I-5 refuses.
    print(f"\n{'=' * 70}\n  HYBRID CAVEAT (ai-managed + ai-dump — operator misconfig)\n{'=' * 70}")
    hp = hf = 0
    for label, src, tgt, want, note in [
        ("hybrid -> ai-managed copies OUT (valve DEFEATED — the known gap)",
         HYBRID, WORKER, "allow", "documents the read-out"),
        ("hybrid is itself an ai-managed read target (firewall.Get allowed)",
         None, None, "allow", "hybrid carries the umbrella → readable"),
    ]:
        if src is None:
            got = resolve(rules, "admin.vm.firewall.Get", MCP, HYBRID)
        else:
            got = resolve(rules, "qubes.Filecopy", src, tgt)
        ok = got == want
        hp += ok; hf += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got}  ({note})")
    print("  → NOTE: these PASS by asserting the LEAK exists; the guarantee holds")
    print("         only for a PURE sink. AI cannot create a hybrid (no tag mutation).")
    tp += hp; tf += hf

    # structural guard: the flip must remove exactly the two backstop lines
    print(f"\n{'=' * 70}\n  structural guards\n{'=' * 70}")
    gpass = gfail = 0
    for label, cond in [
        ("flip removes exactly 2 backstop lines", removed == 2),
        ("compat: ro qube CAN write firewall (backstop live)",
         resolve(rules, "admin.vm.firewall.Set", MCP, TARGETS["untiered/ro"]) == "allow"),
        ("post-flip: ro qube CANNOT write firewall",
         resolve(flipped, "admin.vm.firewall.Set", MCP, TARGETS["untiered/ro"]) == "deny"),
        ("net qube writes firewall in BOTH phases",
         resolve(rules, "admin.vm.firewall.Set", MCP, TARGETS["net"]) == "allow"
         and resolve(flipped, "admin.vm.firewall.Set", MCP, TARGETS["net"]) == "allow"),
        ("firewall.Get unchanged by the flip (ro-floor in both)",
         resolve(rules, "admin.vm.firewall.Get", MCP, TARGETS["untiered/ro"]) == "allow"
         and resolve(flipped, "admin.vm.firewall.Get", MCP, TARGETS["untiered/ro"]) == "allow"),
        ("ai-dump invisible to firewall.Get in both phases",
         resolve(rules, "admin.vm.firewall.Get", MCP, TARGETS["dump"]) == "deny"
         and resolve(flipped, "admin.vm.firewall.Get", MCP, TARGETS["dump"]) == "deny"),
    ]:
        ok = bool(cond)
        gpass += ok
        gfail += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    tp += gpass; tf += gfail

    print(f"\n{'=' * 70}\n  TOTAL: {tp}/{tp + tf} green ({tf} failing)\n{'=' * 70}")
    return 0 if tf == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
