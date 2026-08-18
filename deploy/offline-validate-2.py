#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 2 — birth tier, ownership, birth egress.

Runs on mcp-control with no dom0 and no qubesadmin. Everything Stage 2 decides
is pure logic over tag sets, one operator file per axis, and a netvm chain, so
**this is where essentially all of Stage 2's risk surface lives**. Its sibling
`offline-validate-2-wiring.py` proves the three create wrappers actually call
this logic and roll back when it refuses; the dom0 slot proves only that the
result lands on real hardware.

**Which side proves what** (the I-2 trust-boundary split, and Stage 2 needs it
more than most):

  - HERE (offline)      — the clamp matrix, the two tag classes, the egress
                          chain including its refusal rows, fail-closed on
                          every malformed operator file.
  - wiring (offline)    — the wrappers stamp, verify, and roll back; the mocks
                          are FAITHFUL to qubesadmin's propagation and carry
                          teeth asserting they reproduce the pre-fix bug.
  - dom0 slot           — that a clone of an `ai-full` source really is born
                          `ai-full` and a clone of a Tor-side qube really is
                          born on Tor. **This cannot be asserted from the AI
                          seat**: tier tags are deliberately outside
                          `qmcp_scope.QMCP_TAG_VOCABULARY`, so `test-stage-*`
                          cannot see a child's tier at all. `qvm-tags` in dom0
                          is the only eye that can — the I-5 slot-62 pattern.

**The compat-neutrality property is the one to read twice.** Birth tier is
resolved from the source's LITERAL tag, never its effective capability. In
compat an untiered umbrella qube resolves to `ai-full`, so a stamp built on
effective capability would mint permanently-`ai-full` children throughout the
migration — qubes that keep full authority through the flip when everything
else drops to the read floor. §1 asserts the literal reading directly, with a
`tier-default` file set to `full` present to prove it is ignored.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(os.path.dirname(HERE), "dom0-rpc")

PASSED = 0
FAILED = 0


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(DOM0_RPC, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tier = _load("qmcp_tier", "qmcp_tier.py")
birth = _load("qmcp_birth", "qmcp_birth.py")
caps = _load("qmcp_caps", "qmcp_caps.py")

UMB = tier.UMBRELLA
VOCAB = tier.QMCP_TIER_TAGS


def check(label, cond, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}" + (f"  -- {detail}" if detail else ""))


def raises(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        return True
    return False


TMP = tempfile.mkdtemp(prefix="qmcp-v2-")


def ceiling_file(value):
    """Write an operator birth-ceiling file and return its path."""
    path = os.path.join(TMP, f"ceil-{value!r}".replace("/", "_"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(value)
    return path


ABSENT = os.path.join(TMP, "no-such-ceiling")


class FakeVM:
    """Minimal stand-in — only `.name`, `.tags`, `.netvm` are ever read."""

    def __init__(self, name, tags=(), netvm=None, klass="AppVM"):
        self.name = name
        self.tags = set(tags)
        self.netvm = netvm
        self.klass = klass

    def __str__(self):
        return self.name


# --------------------------------------------------------------------------
# 1. Birth tier — the D2 clamp, and compat neutrality
# --------------------------------------------------------------------------
print("\n=== 1. Birth tier (qmcp_tier.resolve_birth_tier) ===")

# The headline property: an untiered source yields an untiered child, so this
# whole stage is behaviour-neutral in compat. The tier-default flag is present
# and says "full" — resolve_birth_tier must not consult it.
compat_flag = os.path.join(TMP, "tier-default-full")
with open(compat_flag, "w", encoding="utf-8") as fh:
    fh.write("full")
check("untiered source -> untiered child (compat-neutral)",
      tier.resolve_birth_tier(tags={UMB}, birth_ceiling_path=ABSENT) is None)
check("untiered source resolves ai-full EFFECTIVELY in compat (the trap)",
      tier.CAP_FULL in tier.effective_capabilities(
          tags={UMB}, tier_default_path=compat_flag),
      "if this ever stops being true the trap above is gone, not the test")

for src, want in ((tier.TAG_EXEC, tier.TAG_EXEC),
                  (tier.TAG_NET, tier.TAG_NET),
                  (tier.TAG_FULL, tier.TAG_FULL)):
    check(f"no ceiling: {src} source -> {want} child",
          tier.resolve_birth_tier(tags={UMB, src},
                                  birth_ceiling_path=ABSENT) == want)

# The clamp is min(source, ceiling) in both directions.
CLAMP = [
    ({UMB, tier.TAG_FULL}, "ai-exec", tier.TAG_EXEC),
    ({UMB, tier.TAG_FULL}, "ai-net", tier.TAG_NET),
    ({UMB, tier.TAG_FULL}, "ai-full", tier.TAG_FULL),
    ({UMB, tier.TAG_FULL}, "ai-ro", None),
    ({UMB, tier.TAG_EXEC}, "ai-full", tier.TAG_EXEC),   # ceiling never RAISES
    ({UMB, tier.TAG_EXEC}, "ai-ro", None),
    ({UMB}, "ai-full", None),                            # untiered stays untiered
]
for tags, ceil, want in CLAMP:
    got = tier.resolve_birth_tier(tags=tags, birth_ceiling_path=ceiling_file(ceil))
    check(f"clamp: source={sorted(tags)} ceiling={ceil} -> {want}",
          got == want, f"got {got}")

# A ceiling can only lower. Asserted as a property over the whole ladder rather
# than case by case, so a future rung cannot slip past the matrix above.
def _rank(t):
    return -1 if t is None else tier.ELEVATION_LADDER.index(t)


raised = [
    (s, c) for s in (None, tier.TAG_EXEC, tier.TAG_NET, tier.TAG_FULL)
    for c in ("ai-ro", "ai-exec", "ai-net", "ai-full")
    if _rank(tier.resolve_birth_tier(
        tags={UMB} | ({s} if s else set()),
        birth_ceiling_path=ceiling_file(c))) > _rank(s)
]
check("no (source, ceiling) pair births ABOVE its source", not raised, str(raised))

# Fail-closed on every unusable operator value.
for bad in ("", "ai-super", "FULL\n\nx", "ro", "0"):
    got = tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                                  birth_ceiling_path=ceiling_file(bad))
    check(f"malformed ceiling {bad!r} fails closed to untiered", got is None,
          f"got {got}")
check("unreadable-but-present ceiling fails closed",
      tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                              birth_ceiling_path=TMP) is None,
      "a directory stands in for an unreadable file")
check("absent ceiling = no clamp (the shipped default)",
      tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                              birth_ceiling_path=ABSENT) == tier.TAG_FULL)

# --- the two operator-file traps, both measured on hardware 2026-08-18 -----
# These are regression tests, not hypotheticals. Both fired on the rig and both
# failed CLOSED and SILENTLY, which is the worst combination to debug: the
# operator sets a ceiling and every created qube comes out with no capability,
# with nothing anywhere saying why.

# Trap 1 — the file is annotated the way every neighbouring operator file is
# (`pool-cap` as shipped literally contains `53687091200  # 50 GiB`).
for annotated, want in (("ai-exec  # leaf workloads only", tier.TAG_EXEC),
                        ("ai-net\t# tab-separated comment", tier.TAG_NET),
                        ("ai-full # trailing", tier.TAG_FULL)):
    got = tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                                  birth_ceiling_path=ceiling_file(annotated))
    check(f"ceiling honours `value # comment`: {annotated!r} -> {want}",
          got == want, f"got {got}")
check("tier-default honours `value # comment` too",
      tier.effective_capabilities(
          tags={UMB}, tier_default_path=ceiling_file("ro  # least privilege"))
      == frozenset({tier.CAP_READ}),
      "an annotated flag used to fall through to the fail-closed branch, which "
      "happened to be the same answer for 'ro' and the OPPOSITE for 'full'")
check("an annotated `full` flag really does mean full",
      tier.CAP_FULL in tier.effective_capabilities(
          tags={UMB}, tier_default_path=ceiling_file("full  # compat")),
      "this is the case where the missing comment-strip inverted the meaning")

# Trap 2 — `sudo bash -c 'echo x > f'` creates the file 0600 root:root, and the
# qrexec wrapper is not root. Simulated here by a file the test cannot read.
_unreadable = os.path.join(TMP, "ceiling-unreadable")
with open(_unreadable, "w", encoding="utf-8") as fh:
    fh.write("ai-exec")
os.chmod(_unreadable, 0o000)
if os.access(_unreadable, os.R_OK):          # running as root: cannot simulate
    check("unreadable ceiling fails closed (skipped: running as root)", True)
else:
    check("unreadable ceiling fails CLOSED to untiered, never to no-clamp",
          tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                                  birth_ceiling_path=_unreadable) is None)
    check("...and is distinguishable from ABSENT, which means no clamp",
          tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                                  birth_ceiling_path=ABSENT) == tier.TAG_FULL)
os.chmod(_unreadable, 0o644)

# Outside the model nothing is born tiered.
check("non-umbrella source -> untiered",
      tier.resolve_birth_tier(tags={tier.TAG_FULL},
                              birth_ceiling_path=ABSENT) is None)
check("ai-dump-only source -> untiered",
      tier.resolve_birth_tier(tags={tier.TAG_DUMP},
                              birth_ceiling_path=ABSENT) is None)
check("unreadable tag set fails closed",
      tier.resolve_birth_tier(FakeVM("x"), birth_ceiling_path=ABSENT) is None
      or tier.resolve_birth_tier(object(), birth_ceiling_path=ABSENT) is None)

# --------------------------------------------------------------------------
# 2. The reserved namespace — two classes (§3.2)
# --------------------------------------------------------------------------
print("\n=== 2. Reserved namespace (qmcp_birth) ===")

check("owner tag shape", birth.owner_tag("mcp-control")
      == f"{birth.OWNER_PREFIX}mcp-control")
check("owner tag sanitises punctuation",
      birth.owner_tag("bad name/../x") == f"{birth.OWNER_PREFIX}badnamex")
check("owner tag never empty", birth.owner_tag("") == f"{birth.OWNER_PREFIX}unknown")

for t in (birth.TAG_GUARDED, "anon-vm", birth.egress_lock_tag("ai-net-alt")):
    check(f"restriction: {t}", birth.is_restriction(t))
for t in (UMB, tier.TAG_FULL, tier.TAG_EXEC, tier.TAG_DUMP,
          birth.owner_tag("mcp-control"), "created-by-dom0", "work"):
    check(f"NOT a restriction: {t}", not birth.is_restriction(t))

src_tags = {UMB, tier.TAG_FULL, birth.TAG_GUARDED, "anon-vm",
            birth.egress_lock_tag("ai-net-alt"), birth.owner_tag("someone-else"),
            "operator-label", "created-by-dom0"}
inh = birth.inherited_restrictions(src_tags)
check("inherited restrictions are exactly the restriction class",
      inh == {birth.TAG_GUARDED, "anon-vm", birth.egress_lock_tag("ai-net-alt")},
      str(sorted(inh)))

check("controlled vocabulary covers tier tags and qmcp-*",
      all(birth.controlled(t, VOCAB) for t in
          (UMB, tier.TAG_FULL, tier.TAG_DUMP, birth.owner_tag("x"),
           birth.TAG_GUARDED, birth.egress_lock_tag("y"))))
check("controlled vocabulary excludes operator + platform tags",
      not any(birth.controlled(t, VOCAB)
              for t in ("operator-label", "created-by-dom0",
                        "disp-created-by-mcp-control", "anon-vm")),
      "anon-vm is INHERITED but not OWNED — we never delete a platform tag")

want = birth.expected_tags(src_tags, "mcp-control", tier.TAG_FULL, UMB, VOCAB)
check("expected tags = umbrella + owner + birth tier + restrictions",
      want == {UMB, birth.owner_tag("mcp-control"), tier.TAG_FULL,
               birth.TAG_GUARDED, "anon-vm",
               birth.egress_lock_tag("ai-net-alt")}, str(sorted(want)))
check("expected tags omit the tier when the child is untiered",
      birth.expected_tags({UMB}, "mcp-control", None, UMB, VOCAB)
      == {UMB, birth.owner_tag("mcp-control")})

# --------------------------------------------------------------------------
# 3. The stamp — clamp privilege, carry restrictions, verify both sides
# --------------------------------------------------------------------------
print("\n=== 3. The birth stamp ===")


class DictIO(birth.TagIO):
    """A TagIO over a plain set, so the stamp is testable with no qubesadmin.

    `drop_adds` / `drop_removes` simulate a platform that accepts a tag write
    and does not apply it — the failure the read-back exists to catch.
    """

    def __init__(self, initial, drop_adds=False, drop_removes=False):
        self.tags = set(initial)
        self.drop_adds = drop_adds
        self.drop_removes = drop_removes
        super().__init__(self._read, self._add, self._remove)

    def _read(self):
        return set(self.tags)

    def _add(self, t):
        if not self.drop_adds:
            self.tags.add(t)

    def _remove(self, t):
        if not self.drop_removes:
            self.tags.discard(t)


def run_stamp(initial, source_tags, principal="mcp-control", birth_tier=None,
              **kw):
    io = DictIO(initial, **kw)
    birth.stamp(io, source_tags, principal, birth_tier, UMB, VOCAB)
    return io.tags


# The clone case: the child starts life carrying the source's tags verbatim.
src = {UMB, tier.TAG_FULL, birth.TAG_GUARDED, "operator-label",
       birth.owner_tag("someone-else")}
out = run_stamp(set(src), src, birth_tier=tier.TAG_FULL)
check("clone at full: umbrella + owner + ai-full + guard survive",
      {UMB, birth.owner_tag("mcp-control"), tier.TAG_FULL,
       birth.TAG_GUARDED} <= out, str(sorted(out)))
check("clone at full: the SOURCE's owner tag is stripped (no dual ownership)",
      birth.owner_tag("someone-else") not in out)
check("clone at full: an operator label is left alone",
      "operator-label" in out)

out = run_stamp(set(src), src, birth_tier=None)
check("clamped to untiered: ai-full removed from the child",
      tier.TAG_FULL not in out and UMB in out, str(sorted(out)))
check("clamped to untiered: the guard STILL survives (F-E)",
      birth.TAG_GUARDED in out,
      "a restriction the privilege clamp can remove is a laundering hole")

out = run_stamp({UMB, tier.TAG_FULL, tier.TAG_DUMP, tier.TAG_EXEC},
                {UMB, tier.TAG_FULL}, birth_tier=tier.TAG_EXEC)
check("every off-clamp tier tag is stripped, including ai-dump",
      out == {UMB, tier.TAG_EXEC, birth.owner_tag("mcp-control")},
      str(sorted(out)))

# The disposable case: the platform inherited the DVMT's egress lock.
locked = birth.egress_lock_tag("ai-net-alt")
out = run_stamp({UMB, tier.TAG_FULL, locked}, {UMB, tier.TAG_FULL, locked},
                birth_tier=None)
check("an inherited egress lock is never removable by the clamp", locked in out)

# Read-back teeth, both sides.
check("stamp raises when an add silently does not take",
      raises(run_stamp, {UMB}, {UMB}, birth_tier=tier.TAG_EXEC, drop_adds=True))
check("stamp raises when a remove silently does not take",
      raises(run_stamp, {UMB, tier.TAG_FULL}, {UMB, tier.TAG_FULL},
             birth_tier=None, drop_removes=True))

io = DictIO({UMB, birth.owner_tag("mcp-control")})
check("verify accepts an exact controlled match",
      not raises(birth.verify, io, {UMB, birth.owner_tag("mcp-control")}, VOCAB))
io.tags.add("created-by-dom0")
io.tags.add("operator-label")
check("verify tolerates uncontrolled tags the platform/operator added",
      not raises(birth.verify, io, {UMB, birth.owner_tag("mcp-control")}, VOCAB))
io.tags.add(tier.TAG_FULL)
check("verify REJECTS an unexpected controlled tag appearing late",
      raises(birth.verify, io, {UMB, birth.owner_tag("mcp-control")}, VOCAB),
      "this is the side that catches a platform that starts propagating")

# --------------------------------------------------------------------------
# 4. Birth egress — the chain, and F-J's authoritative source
# --------------------------------------------------------------------------
print("\n=== 4. Birth egress (qmcp_caps.resolve_birth_egress) ===")

FLEET = {"ai-net-router", "ai-net-alt", "ai-dvmt", "work"}


def in_scope(n):
    return n in FLEET


GATEWAY = FakeVM("mcp-control", netvm="ai-net-router")
GATEWAY_OUT = FakeVM("mcp-control", netvm="sys-firewall")
TEMPLATE = FakeVM("ai-debian-13", netvm=None, klass="TemplateVM")
TOR_SRC = FakeVM("tor-work", netvm="ai-net-alt")
OFFLINE_SRC = FakeVM("vault", netvm=None)
STRANDED_SRC = FakeVM("odd", netvm="sys-firewall")

BIRTH_EGRESS = os.path.join(TMP, "birth-egress")
with open(BIRTH_EGRESS, "w", encoding="utf-8") as fh:
    fh.write("ai-net-router\n")
NO_FILE = os.path.join(TMP, "no-birth-egress")

CASES = [
    # (label, actor, source, authoritative, want_name, want_rule, egress_path)
    ("source outranks principal (Tor clone stays on Tor)",
     GATEWAY, TOR_SRC, True, "ai-net-alt", "birth-egress:source", NO_FILE),
    ("template create falls to the principal's egress",
     GATEWAY, TEMPLATE, None, "ai-net-router", "birth-egress:principal", NO_FILE),
    ("gateway outside the umbrella falls to the operator file",
     GATEWAY_OUT, TEMPLATE, None, "ai-net-router",
     "birth-egress:configured", BIRTH_EGRESS),
    ("nothing resolves -> refuse",
     GATEWAY_OUT, TEMPLATE, None, None, "birth-egress:unresolved", NO_FILE),
    # F-J: an authoritative source answers for itself, both ways.
    ("F-J: offline workload source -> offline child, NOT the gateway's egress",
     GATEWAY, OFFLINE_SRC, True, None, "birth-egress:source-offline", NO_FILE),
    ("F-J: source stranded off-umbrella -> refuse, never re-home",
     GATEWAY, STRANDED_SRC, True, None, "birth-egress:unresolved", BIRTH_EGRESS),
    # Stage 1 behaviour is preserved exactly when the flag is omitted.
    ("omitted flag: offline source still falls through (Stage 1 shape)",
     GATEWAY, OFFLINE_SRC, None, "ai-net-router", "birth-egress:principal",
     NO_FILE),
]
for label, actor, source, auth, want_name, want_rule, path in CASES:
    kw = {} if auth is None else {"source_authoritative": auth}
    got_name, got_rule = caps.resolve_birth_egress(
        actor, source, is_ai_managed=in_scope, birth_egress_path=path, **kw)
    check(label, (got_name, got_rule) == (want_name, want_rule),
          f"got {(got_name, got_rule)}")

check("a refusal and a resolved-offline answer are DISTINGUISHABLE",
      caps.resolve_birth_egress(GATEWAY_OUT, TEMPLATE, is_ai_managed=in_scope,
                                birth_egress_path=NO_FILE)[1]
      != caps.resolve_birth_egress(GATEWAY, OFFLINE_SRC, is_ai_managed=in_scope,
                                   birth_egress_path=NO_FILE,
                                   source_authoritative=True)[1],
      "callers branch on the RULE; both carry name=None")

check("no candidate outside the umbrella is ever returned",
      all(caps.resolve_birth_egress(a, s, is_ai_managed=in_scope,
                                    birth_egress_path=NO_FILE)[0] in
          (None,) + tuple(FLEET)
          for a in (GATEWAY, GATEWAY_OUT, None)
          for s in (TEMPLATE, TOR_SRC, OFFLINE_SRC, STRANDED_SRC, None)))

check("a missing is_ai_managed predicate refuses everything",
      caps.resolve_birth_egress(GATEWAY, TOR_SRC,
                                birth_egress_path=BIRTH_EGRESS)
      == (None, "birth-egress:unresolved"),
      "fail-closed: no predicate, no inheritance")

# --------------------------------------------------------------------------
print(f"\n{'='*68}\nStage 2 offline validation: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
