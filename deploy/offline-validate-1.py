#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 1 — the `qmcp_caps` decision kernel.

Runs on mcp-control with no dom0 and no qubesadmin. The kernel is pure logic
over tag sets and two operator files, so **this is where essentially all of
Stage 1's risk surface lives** — the hardware side can only show that the
wrappers still behave identically (invariance), which is a much weaker claim
than "the lattice says the right thing for every tuple".

**What this suite asserts, and what it deliberately does not.**

The property tests assert **`decide()`'s OUTPUT**, never the shipped wrappers'
behaviour. Those two disagree on purpose in Stage 1: today's create path really
does produce a cross-egress child, and today's Lifecycle gate really does
refuse a dominated `remove`. A test written against the wrapper would go red on
day one under "behaviour unchanged", and the tempting repair is to weaken the
property until it passes — which would quietly delete the whole point of shadow
mode. The correct shape is: `decide()` returns its verdict, the wrapper still
does what it always did, and the I-2 chain records the divergence. The
divergences are themselves asserted below (see DIVERGENCE), so they cannot be
"fixed" by accident.

Split of proof, per the project's trust-boundary rule:
  - HERE (offline)  — the lattice: every tuple, every invariant, fail-closed.
  - hardware        — invariance only: wrapper responses byte-identical, and a
                      populated divergence log.
  - dom0 slot       — that the module installs and imports next to its siblings.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(os.path.dirname(HERE), "dom0-rpc")


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(DOM0_RPC, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


caps = _load("qmcp_caps", "qmcp_caps.py")
tier = _load("qmcp_tier", "qmcp_tier.py")

#: Read for the §8 structural check that Stage 3c's cut branch stayed cut.
CAPS_SRC = os.path.join(DOM0_RPC, "qmcp_caps.py")

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
# Fixtures
# --------------------------------------------------------------------------

class FakeVM:
    """Minimal stand-in for a qubesadmin VM.

    Carries only what the kernel reads: `name`, `tags`, `netvm`. Faithful in
    the one way that matters here — `.tags` may RAISE, because a tag read
    against a vanished qube does, and every fail-closed path in the kernel
    exists for that case.
    """

    def __init__(self, name, tags=(), netvm=None, raises=False):
        self.name = name
        self._tags = set(tags)
        self.netvm = netvm
        self._raises = raises

    @property
    def tags(self):
        if self._raises:
            raise RuntimeError("tag read failed")
        return self._tags


UMB = tier.UMBRELLA
TIERS = {
    "untiered": (UMB,),
    "ai-exec": (UMB, tier.TAG_EXEC),
    "ai-net": (UMB, tier.TAG_NET),
    "ai-full": (UMB, tier.TAG_FULL),
}

_tmp = tempfile.mkdtemp(prefix="qmcp-caps-validate-")
FLAG_RO = os.path.join(_tmp, "tier-default-ro")
FLAG_FULL = os.path.join(_tmp, "tier-default-full")
with open(FLAG_RO, "w", encoding="utf-8") as fh:
    fh.write("ro\n")
with open(FLAG_FULL, "w", encoding="utf-8") as fh:
    fh.write("full\n")

NO_GUARDED = os.path.join(_tmp, "guarded-absent")   # never created
GUARDED = os.path.join(_tmp, "guarded")
with open(GUARDED, "w", encoding="utf-8") as fh:
    fh.write("# operator-authored\nwallet\n")


def vm(tier_name, name="t"):
    return FakeVM(name, TIERS[tier_name])


def d(service, action="", targets=None, params=None,
      flag=FLAG_RO, guarded=NO_GUARDED):
    """decide() under post-flip least privilege by default.

    Post-flip is the interesting row: in compat an untiered umbrella qube is
    `ai-full`, so nearly every tuple collapses to ALLOW and the lattice is
    untestable. Compat is exercised separately below.
    """
    return caps.decide("mcp-control", service, action, targets or {},
                       params or {}, tier_default_path=flag,
                       guarded_list_path=guarded)


# --------------------------------------------------------------------------
# 1. Structure — the table cannot silently rot
# --------------------------------------------------------------------------
print("\n-- 1. structure --")

KNOWN_CAPS = {caps.CAP_READ, caps.CAP_EXEC, caps.CAP_NET,
              caps.CAP_FULL, caps.CAP_DUMP_IN}
check("every SERVICE_TABLE requirement is a known capability token",
      all(req in KNOWN_CAPS
          for roles in caps.SERVICE_TABLE.values() for req in roles.values()))
check("every DOMINATION key names a service in the table",
      all(svc in caps.SERVICE_TABLE for svc, _ in caps.DOMINATION))
check("every NO_TARGET service is in the table",
      all(s in caps.SERVICE_TABLE for s in caps.NO_TARGET_SERVICES))
check("no NO_TARGET service declares roles",
      all(not caps.SERVICE_TABLE[s] for s in caps.NO_TARGET_SERVICES))
check("kernel capability tokens match the tier helper's",
      {caps.CAP_READ, caps.CAP_EXEC, caps.CAP_NET, caps.CAP_FULL,
       caps.CAP_DUMP_IN} ==
      {tier.CAP_READ, tier.CAP_EXEC, tier.CAP_NET, tier.CAP_FULL,
       tier.CAP_DUMP_IN},
      "a token renamed in one module and not the other would silently deny")
check("attach/detach are NOT dominated (the cross-boundary asymmetry)",
      not any(svc.endswith("DeviceAIManaged") for svc, _ in caps.DOMINATION))
check("unpause is not dominated (exec cannot reach a paused qube)",
      ("qmcp.LifecycleAIManaged", "unpause") not in caps.DOMINATION)

# --------------------------------------------------------------------------
# 2. Step 1 — the existence boundary outranks everything
# --------------------------------------------------------------------------
print("\n-- 2. existence boundary --")

OUTSIDE = FakeVM("outsider", tags=())
check("read on an out-of-umbrella target denies",
      d("qmcp.GetPropertyAIManaged", "get", {"target": OUTSIDE}).rule
      == "outside-umbrella")
check("exec on an out-of-umbrella target denies",
      d("qmcp.RunInAIManaged", "run", {"target": OUTSIDE}).rule
      == "outside-umbrella")
check("attach denies if EITHER endpoint is outside",
      d("qmcp.AttachDeviceAIManaged", "attach",
        {"backend": vm("ai-full", "b"), "frontend": OUTSIDE}).rule
      == "outside-umbrella")
check("a broken tag read denies (fail-closed, not fail-open)",
      d("qmcp.LifecycleAIManaged", "start",
        {"target": FakeVM("x", raises=True)}).verdict == caps.DENY)
check("a service with no target needs none",
      d("qmcp.GetPoolStats", "get").verdict == caps.ALLOW)
check("a targeted service with no target denies",
      d("qmcp.LifecycleAIManaged", "start", {}).rule == "no-target")
check("an unknown service denies (default-deny on new surfaces)",
      d("qmcp.SomethingNew", "x", {"target": vm("ai-full")}).rule
      == "unknown-service")

# --------------------------------------------------------------------------
# 3. Step 2 — no ALLOW anywhere in the escalation class, at any tier
# --------------------------------------------------------------------------
print("\n-- 3. escalation class (invariant 3) --")

esc_allowed = []
for tname in TIERS:
    for flag in (FLAG_RO, FLAG_FULL):
        for prop in sorted(caps.ESCALATION_PROPS):
            r = d("qmcp.SetPropertyAIManaged", "set", {"target": vm(tname)},
                  {"property": prop}, flag=flag)
            if r.verdict == caps.ALLOW:
                esc_allowed.append((tname, flag, prop))
        for klass in sorted(caps.ESCALATION_KLASSES):
            r = d("qmcp.SpawnAIManagedQube", "spawn",
                  {"template": vm(tname)}, {"klass": klass}, flag=flag)
            if r.verdict == caps.ALLOW:
                esc_allowed.append((tname, flag, klass))
        for svc in sorted(caps.ESCALATION_SERVICES):
            r = d(svc, "set", {"target": vm(tname)}, flag=flag)
            if r.verdict == caps.ALLOW:
                esc_allowed.append((tname, flag, svc))
check("no ALLOW in the escalation class over every (tier x mode x op)",
      not esc_allowed, f"leaked: {esc_allowed[:4]}")
check("escalation beats ai-full in COMPAT too (the permissive mode)",
      d("qmcp.SetPropertyAIManaged", "set", {"target": vm("ai-full")},
        {"property": "netvm"}, flag=FLAG_FULL).rule == "escalation-class")
check("a non-escalation property is unaffected",
      d("qmcp.SetPropertyAIManaged", "set", {"target": vm("ai-full")},
        {"property": "memory"}).verdict == caps.ALLOW)
check("escalation outranks domination (order matters, not just membership)",
      d("qmcp.LifecycleAIManaged", "remove", {"target": vm("ai-exec")},
        {"klass": "TemplateVM"}).rule == "escalation-class")

# --------------------------------------------------------------------------
# 4. Step 3 — the guarded hard class, checked BEFORE domination
# --------------------------------------------------------------------------
print("\n-- 4. guarded hard class --")

WALLET_EXEC = FakeVM("wallet", TIERS["ai-exec"])
check("a guarded target GATEs even when the op is dominated",
      d("qmcp.LifecycleAIManaged", "remove", {"target": WALLET_EXEC},
        guarded=GUARDED).rule == "guarded")
check("an unguarded target of the same tier is unaffected",
      d("qmcp.LifecycleAIManaged", "remove", {"target": vm("ai-exec")},
        guarded=GUARDED).verdict == caps.ALLOW)
check("an absent guarded list guards nothing",
      d("qmcp.LifecycleAIManaged", "remove", {"target": WALLET_EXEC},
        guarded=NO_GUARDED).verdict == caps.ALLOW)
check("guarded still loses to the escalation class",
      d("qmcp.SetPropertyAIManaged", "set", {"target": WALLET_EXEC},
        {"property": "netvm"}, guarded=GUARDED).rule == "escalation-class")
check("guarded still loses to the existence boundary",
      d("qmcp.LifecycleAIManaged", "remove", {"target": FakeVM("wallet")},
        guarded=GUARDED).rule == "outside-umbrella")

_unreadable = os.path.join(_tmp, "guarded-dir")
os.makedirs(_unreadable, exist_ok=True)   # a directory: present but unreadable
check("a present-but-unreadable guarded list GATEs (fail-closed)",
      d("qmcp.LifecycleAIManaged", "remove", {"target": vm("ai-full")},
        guarded=_unreadable).rule == "guarded-unreadable")

# --------------------------------------------------------------------------
# 5. Step 4 — domination, and "no GATE where dominated"
# --------------------------------------------------------------------------
print("\n-- 5. domination (invariant 1) --")

# The brief's property is "no GATE where dominated". Checking only the
# dominated tuples is near-vacuous — GATE has exactly one source today, so a
# loop over four entries can hardly fail. The load-bearing version is the
# converse and it is cheap: with no guarded list, NOTHING anywhere may gate.
# That catches the real regression — a future stage introducing a second GATE
# path (a dialog on some op) without routing it through the hard class, where
# it would sit below domination and be silently argued away.
stray_gate = []
for svc, roles in caps.SERVICE_TABLE.items():
    for action in ("op", "remove", "kill", "shutdown", "start", "unpause",
                   "attach", "detach", "set", "get", "run", "copy", "spawn"):
        for tname in TIERS:
            for flag in (FLAG_RO, FLAG_FULL):
                r = d(svc, action, {role: vm(tname, role) for role in roles},
                      flag=flag)
                if r.verdict == caps.GATE:
                    stray_gate.append((svc, action, tname, r.rule))
check("with no guarded list, NO (service x action x tier x mode) tuple gates",
      not stray_gate, f"{len(stray_gate)} stray: {stray_gate[:3]}")
check("...and that sweep is non-trivial (it really exercised the lattice)",
      len(caps.SERVICE_TABLE) * len(TIERS) * 2 >= 100,
      "guards against the sweep silently shrinking to nothing")
check("remove is ALLOWed at ai-exec by domination, not by the ladder",
      d("qmcp.LifecycleAIManaged", "remove", {"target": vm("ai-exec")}).rule
      == f"dominated:{caps.CAP_EXEC}")
check("remove is DENIED at the untiered floor post-flip (nothing to dominate)",
      d("qmcp.LifecycleAIManaged", "remove", {"target": vm("untiered")}).verdict
      == caps.DENY)
check("attach at ai-exec is denied — nothing dominates a hardware boundary",
      d("qmcp.AttachDeviceAIManaged", "attach",
        {"backend": vm("ai-exec", "b"), "frontend": vm("ai-exec", "f")}).verdict
      == caps.DENY)

# --------------------------------------------------------------------------
# 6. Step 5 — the ladder, exhaustively
# --------------------------------------------------------------------------
print("\n-- 6. ladder coverage --")

uncovered = []
bad_verdict = []
for svc, roles in caps.SERVICE_TABLE.items():
    for tname in TIERS:
        targets = {role: vm(tname, role) for role in roles}
        r = d(svc, "op", targets)
        if r.verdict not in (caps.ALLOW, caps.DENY, caps.GATE):
            bad_verdict.append((svc, tname, r.verdict))
        if not r.rule:
            uncovered.append((svc, tname))
check("every (service x tier) tuple yields a verdict with a named rule",
      not uncovered and not bad_verdict, f"{uncovered[:3]} {bad_verdict[:3]}")

check("ai-exec grants exec but not full",
      d("qmcp.RunInAIManaged", "run", {"target": vm("ai-exec")}).verdict
      == caps.ALLOW
      and d("qmcp.SetFeatureAIManaged", "set",
            {"target": vm("ai-exec")}).rule == f"insufficient:{caps.CAP_FULL}")
check("ai-net grants firewall write; ai-exec does not",
      d("admin.vm.firewall.Set", "set", {"target": vm("ai-net")}).verdict
      == caps.ALLOW
      and d("admin.vm.firewall.Set", "set",
            {"target": vm("ai-exec")}).verdict == caps.DENY)
check("the read floor holds at the untiered umbrella post-flip",
      d("qmcp.GetPropertyAIManaged", "get", {"target": vm("untiered")}).verdict
      == caps.ALLOW)
check("Filecopy requires exec on BOTH ends (G0)",
      d("qubes.Filecopy", "copy",
        {"source": vm("ai-exec", "s"), "target": vm("untiered", "t")}).verdict
      == caps.DENY)
check("COMPAT: an untiered umbrella qube reaches full (today's boundary)",
      d("qmcp.SetFeatureAIManaged", "set", {"target": vm("untiered")},
        flag=FLAG_FULL).verdict == caps.ALLOW)

# --------------------------------------------------------------------------
# 7. Birth egress — the §3.4 precedence chain
# --------------------------------------------------------------------------
print("\n-- 7. birth egress --")

IN_SCOPE = {"ai-net-router", "ai-net-alt"}
managed = lambda n: n in IN_SCOPE          # noqa: E731 - injectable predicate

CFG = os.path.join(_tmp, "birth-egress")
with open(CFG, "w", encoding="utf-8") as fh:
    fh.write("ai-net-router\n")
NO_CFG = os.path.join(_tmp, "birth-egress-absent")

GATEWAY_IN = FakeVM("mcp-control", netvm="ai-net-router")   # production shape
GATEWAY_OUT = FakeVM("mcp-control", netvm="sys-firewall")   # out-of-umbrella
TOR_SOURCE = FakeVM("tor-side", TIERS["ai-full"], netvm="ai-net-alt")
TEMPLATE = FakeVM("ai-debian-13", TIERS["ai-full"], netvm=None)

name, rule = caps.resolve_birth_egress(GATEWAY_IN, TOR_SOURCE,
                                       birth_egress_path=CFG,
                                       is_ai_managed=managed)
check("row 1 — the source's egress wins over the principal's",
      (name, rule) == ("ai-net-alt", "birth-egress:source"),
      "this is the clone-of-a-Tor-qube case; reversing rows 1 and 2 leaks it")

name, rule = caps.resolve_birth_egress(GATEWAY_IN, TEMPLATE,
                                       birth_egress_path=CFG,
                                       is_ai_managed=managed)
check("row 2 — a template create inherits the principal's egress",
      (name, rule) == ("ai-net-router", "birth-egress:principal"))

name, rule = caps.resolve_birth_egress(GATEWAY_OUT, TEMPLATE,
                                       birth_egress_path=CFG,
                                       is_ai_managed=managed)
check("row 3 — an out-of-umbrella gateway falls back to the operator file",
      (name, rule) == ("ai-net-router", "birth-egress:configured"),
      "this is the rig's shape before it was re-plugged, and an adopter's")

name, rule = caps.resolve_birth_egress(GATEWAY_OUT, TEMPLATE,
                                       birth_egress_path=NO_CFG,
                                       is_ai_managed=managed)
check("row 4 — nothing resolves: REFUSE, never a network-less qube",
      (name, rule) == (None, "birth-egress:unresolved"),
      "today's code leaves netvm unset here and the qube boots with no network")

name, _ = caps.resolve_birth_egress(
    GATEWAY_IN, FakeVM("src", netvm="sys-firewall"),
    birth_egress_path=CFG, is_ai_managed=managed)
check("a source whose egress is out-of-umbrella is skipped, not proposed",
      name == "ai-net-router",
      "proposing it would be refused by CROSS_REF_PROPS — the wrong mechanism")

# --------------------------------------------------------------------------
# 8. TEETH — the suite must fail if the fix is reverted
# --------------------------------------------------------------------------
print("\n-- 8. teeth --")

# The live 0.5 finding — a create landing on an egress its creator did not
# choose — is enforced in the CREATE WRAPPERS, not here. Stage 1 shipped a
# `resolved_netvm` comparison in `_decide_inner` that no caller ever populated,
# and Stage 3c cut it on invariant 2 (no-illusion) rather than wiring it: a
# second opinion computed from the answer the wrapper is about to act on is not
# a second enforcement. The property itself is asserted where it is enforced,
# against the real wrappers, in `offline-validate-2-wiring.py` §1 ("explicit
# netvm DIFFERING from the inherited one is refused" and its five neighbours).
#
# These two checks pin the CUT so a later stage cannot quietly restore a branch
# that reads as a gate and is not one.
# Keyed on STRUCTURE, not vocabulary: a grep for the word matches the comment
# above the cut explaining why it is cut, which is the "read a refusal as a
# result" family this project has already been bitten by twice. Parse instead
# and look for the string as a LITERAL in the code — the only form that can
# reach `params`.
_caps_ast = ast.parse(open(CAPS_SRC, encoding="utf-8").read())
check("teeth: the kernel does NOT decide birth egress (the branch stayed cut)",
      not any(isinstance(n, ast.Constant) and n.value == "resolved_netvm"
              for n in ast.walk(_caps_ast)),
      "re-adding it needs a caller that populates it AND a test at that caller")
check("teeth: a create proposing any netvm is decided on the ladder, not egress",
      d("qmcp.SpawnAIManagedQube", "spawn", {"template": vm("ai-full")},
        {"netvm": "ai-net-alt"}).rule == "ladder",
      "the kernel has no opinion on which egress a create lands on")

# A domination table that grew a merely-plausible entry would delete a real
# gate. Assert the two we argued are NOT airtight stay out.
check("teeth: adding unpause/attach to DOMINATION would break this check",
      all(k not in caps.DOMINATION
          for k in (("qmcp.LifecycleAIManaged", "unpause"),
                    ("qmcp.AttachDeviceAIManaged", "attach"))))

# A kernel that raises must deny. Force it by handing decide() a targets map
# that is not a mapping at all.
check("teeth: an internal error resolves to DENY, never to a leak",
      caps.decide("mcp-control", "qmcp.LifecycleAIManaged", "remove",
                  "not-a-mapping").verdict == caps.DENY)

# --------------------------------------------------------------------------
# 9. DIVERGENCE — the deltas Stage 1 exists to surface
# --------------------------------------------------------------------------
print("\n-- 9. expected divergence from shipped behaviour --")

check("divergence: shipped Lifecycle needs CAP_FULL; the kernel allows at exec",
      d("qmcp.LifecycleAIManaged", "remove", {"target": vm("ai-exec")}).verdict
      == caps.ALLOW,
      "Stage 3 deletes the dominated gate — WITH D3 tombstoning in the same change")
# CONVERGED 2026-08-19. This read "shipped SetProperty allows netvm retarget;
# the kernel denies" until F-2 closed the retarget in the wrapper (761bae1), so
# the two now AGREE on a pinned retarget. The assertion is kept — with an honest
# label — because it is the load-bearing half of Stage 3c's carve-out pair
# below: `netvm` denies by default, and only a caller that says the value is
# null earns the exemption.
check("kernel: a netvm write with no stated value is escalation-class",
      d("qmcp.SetPropertyAIManaged", "set", {"target": vm("ai-full")},
        {"property": "netvm"}).verdict == caps.DENY,
      "omitting `value` must get the conservative reading, not the carve-out")
check("kernel: a netvm write to a NAMED qube is escalation-class",
      d("qmcp.SetPropertyAIManaged", "set", {"target": vm("ai-full")},
        {"property": "netvm", "value": "ai-net-alt"}).verdict == caps.DENY)
check("kernel: `netvm = null` is de-escalation and falls through to the ladder",
      d("qmcp.SetPropertyAIManaged", "set", {"target": vm("ai-full")},
        {"property": "netvm", "value": None}).rule == "ladder",
      "both wrappers permit the disconnect; arming a mode against the Stage 1 "
      "model would have deleted it silently")
check("kernel: the carve-out is netvm-only — a null `template` is still denied",
      d("qmcp.SetPropertyAIManaged", "set", {"target": vm("ai-full")},
        {"property": "template", "value": None}).verdict == caps.DENY)
check("kernel: `netvm = null` below CAP_FULL is still refused, on the ladder",
      d("qmcp.SetPropertyAIManaged", "set", {"target": vm("ai-exec")},
        {"property": "netvm", "value": None}).rule == "insufficient:full",
      "de-escalation is exempt from the escalation class, not from authority")

# --------------------------------------------------------------------------
print(f"\n{PASSED}/{PASSED + FAILED} checks passed")
sys.exit(1 if FAILED else 0)
