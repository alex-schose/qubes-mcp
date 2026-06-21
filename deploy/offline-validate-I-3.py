#!/usr/bin/env python3
"""Offline validation for Stage I-3 (tier taxonomy + resolution helper).

Ships in public/deploy/ alongside the test-stage-*.py harnesses. I-3 is
behaviour-neutral on every AI
surface — its whole risk surface is the dom0 helper's resolution logic, so
this is where the real coverage lives (the hardware test only proves the
AI-side invariance). Mirrors the CLAUDE.md "validate dom0 wrapper logic
offline before slot deploy" pattern: load the helper via spec_from_file_
location (same sibling-load the wrappers use in dom0), drive every tag
combination, assert the capability set.

Proven here, before any slot:
  1. Ladder resolution — every (umbrella + elevation) combination maps to the
     documented cumulative capability set; ai-dump → copy-in only; out-of-model
     tags → no capability.
  2. The cumulative INVARIANT — ai-full ⊃ ai-net ⊃ ai-exec ⊃ ai-ro, and the
     locked net⊃exec model decision holds.
  3. Highest-wins — a qube with several elevation tags never grants beyond its
     top tag.
  4. The two-phase flip — the untiered-umbrella default tracks /etc/qmcp/
     tier-default: absent/"full" → full (compat), "ro" → ro, malformed → ro
     (fail-closed). The flip changes ONLY untiered qubes; an explicitly-tiered
     qube is unaffected.
  5. Behaviour-neutrality — in compat (flag absent) every ai-managed qube
     resolves to FULL, i.e. exactly today's binary boundary, so I-5 wrappers
     gate identically to pre-I-3.
  6. Fail-closed — a vm whose .tags read raises yields the empty set.
  7. Cross-module invariant — qmcp_scope's AI-observable tag vocabulary does
     NOT contain the tier tags, so a `tags` read cannot leak the authority
     topology (the helper's namespace and AI's observable set are disjoint
     except for the umbrella).

Run from the repo root:   .venv/bin/python deploy/offline-validate-I-3.py
or from inside public/:   python3 deploy/offline-validate-I-3.py
"""
from __future__ import annotations

import importlib.util
import os
import tempfile

# This file lives in public/deploy/; the helpers it loads are siblings in
# public/dom0-rpc/. Resolve them relative to THIS file's directory (the same
# os.path.dirname(os.path.realpath(__file__)) sibling-load the dom0 wrappers
# use), so it runs from the repo root AND from inside public/.
HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(HERE, os.pardir, "dom0-rpc")


def _load(modname: str):
    path = os.path.join(DOM0_RPC, f"{modname}.py")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T = _load("qmcp_tier")
SCOPE = _load("qmcp_scope")


# --------------------------------------------------------------------- fakes
class FakeTags:
    def __init__(self, items):
        self._s = set(items)

    def __iter__(self):
        return iter(self._s)

    def __contains__(self, x):
        return x in self._s


class FakeVM:
    def __init__(self, tags):
        self.tags = FakeTags(tags)


class ExplodingVM:
    """A vm whose .tags read raises — exercises the fail-closed path."""

    @property
    def tags(self):
        raise RuntimeError("qubesd unreachable")


# --------------------------------------------------------------------- harness
_PASS = 0
_FAIL = 0


def check(label, got, want):
    global _PASS, _FAIL
    if got == want:
        _PASS += 1
        print(f"  PASS  {label}")
    else:
        _FAIL += 1
        print(f"  FAIL  {label}\n          got  {got}\n          want {want}")


def check_true(label, cond):
    check(label, bool(cond), True)


def caps(tags, **kw):
    """effective_capabilities as a plain set, for readable comparisons."""
    return set(T.effective_capabilities(tags=tags, **kw))


# expected capability sets (compat / explicit tiers)
RO = {T.CAP_READ}
EXEC = RO | {T.CAP_EXEC}
NET = EXEC | {T.CAP_NET}
FULL = NET | {T.CAP_FULL}


def section(s):
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


# A flag file that does not exist → compat. We point at a guaranteed-absent
# path so the helper's FileNotFoundError → compat branch runs.
ABSENT = os.path.join(tempfile.gettempdir(), "qmcp-i3-no-such-tier-default-zzz")


def write_flag(value):
    fd, p = tempfile.mkstemp(prefix="qmcp-i3-tier-default-")
    with os.fdopen(fd, "w") as fh:
        fh.write(value)
    return p


# ===================================================================== tests
def test_ladder_compat():
    section("1. Ladder resolution (compat: flag absent → untiered = full)")
    check("umbrella only          → full (compat)", caps(["ai-managed"], tier_default_path=ABSENT), FULL)
    check("umbrella + ai-exec     → {read,exec}", caps(["ai-managed", "ai-exec"], tier_default_path=ABSENT), EXEC)
    check("umbrella + ai-net      → {read,exec,net}", caps(["ai-managed", "ai-net"], tier_default_path=ABSENT), NET)
    check("umbrella + ai-full     → {read,exec,net,full}", caps(["ai-managed", "ai-full"], tier_default_path=ABSENT), FULL)
    check("ai-dump only           → {dump-in}", caps(["ai-dump"], tier_default_path=ABSENT), {T.CAP_DUMP_IN})
    check("no qmcp tags           → {} (outside model)", caps(["some-operator-tag"], tier_default_path=ABSENT), set())
    check("empty tag set          → {}", caps([], tier_default_path=ABSENT), set())


def test_cumulative_invariant():
    section("2. Cumulative invariant: full ⊃ net ⊃ exec ⊃ ro (net⊃exec locked)")
    check_true("ai-ro  ⊂ ai-exec", RO < EXEC)
    check_true("ai-exec ⊂ ai-net  (net⊃exec — the locked model decision)", EXEC < NET)
    check_true("ai-net ⊂ ai-full", NET < FULL)
    check_true("CAP_EXEC present at ai-net", T.CAP_EXEC in caps(["ai-managed", "ai-net"], tier_default_path=ABSENT))
    check_true("CAP_READ present at every rung",
               all(T.CAP_READ in caps(["ai-managed", t], tier_default_path=ABSENT)
                   for t in ("ai-exec", "ai-net", "ai-full")))


def test_highest_wins():
    section("3. Highest-wins on a multi-elevation tag set")
    check("exec+full → full", caps(["ai-managed", "ai-exec", "ai-full"], tier_default_path=ABSENT), FULL)
    check("exec+net  → net", caps(["ai-managed", "ai-exec", "ai-net"], tier_default_path=ABSENT), NET)
    check("net+full  → full", caps(["ai-managed", "ai-net", "ai-full"], tier_default_path=ABSENT), FULL)
    check("tier_label(exec+net) == ai-net", T.tier_label(tags=["ai-managed", "ai-exec", "ai-net"]), "ai-net")


def test_flip():
    section("4. Two-phase flip: untiered default tracks /etc/qmcp/tier-default")
    f_full = write_flag("full")
    f_ro = write_flag("ro")
    f_ro_case = write_flag("RO\n")
    f_bad = write_flag("least-privilege-please")
    f_empty = write_flag("   \n")
    try:
        check("absent     → untiered = full (compat)", caps(["ai-managed"], tier_default_path=ABSENT), FULL)
        check('"full"     → untiered = full', caps(["ai-managed"], tier_default_path=f_full), FULL)
        check('"ro"       → untiered = ro', caps(["ai-managed"], tier_default_path=f_ro), RO)
        check('"RO\\n"     → untiered = ro (case/trim)', caps(["ai-managed"], tier_default_path=f_ro_case), RO)
        check('malformed  → untiered = ro (fail-closed)', caps(["ai-managed"], tier_default_path=f_bad), RO)
        check('whitespace → untiered = ro (fail-closed)', caps(["ai-managed"], tier_default_path=f_empty), RO)
        # the flip changes ONLY untiered qubes — explicit tiers are unaffected
        check("flip=ro: explicit ai-full unaffected", caps(["ai-managed", "ai-full"], tier_default_path=f_ro), FULL)
        check("flip=ro: explicit ai-exec unaffected", caps(["ai-managed", "ai-exec"], tier_default_path=f_ro), EXEC)
    finally:
        for p in (f_full, f_ro, f_ro_case, f_bad, f_empty):
            os.remove(p)


def test_behaviour_neutral():
    section("5. Behaviour-neutrality: compat ⇒ every ai-managed qube = FULL")
    # In compat (the I-3..I-5 default) an untiered ai-managed qube grants FULL,
    # i.e. exactly today's binary boundary. Every existing wrapper that acts on
    # *any* ai-managed qube today would be permitted identically under I-5.
    for extra in ([], ["created-by-dom0"], ["ai-managed"]):
        check_true(f"compat ai-managed (+{extra}) has CAP_FULL",
                   T.CAP_FULL in caps(["ai-managed"] + extra, tier_default_path=ABSENT))
    # via a FakeVM object (the real wrapper call shape), not just explicit tags
    check_true("FakeVM(ai-managed) compat has CAP_FULL",
               T.has_capability(FakeVM(["ai-managed"]), T.CAP_FULL, tier_default_path=ABSENT))


def test_fail_closed():
    section("6. Fail-closed on an unreadable tag set")
    check("ExplodingVM.tags raises → {}", set(T.effective_capabilities(ExplodingVM(), tier_default_path=ABSENT)), set())
    check("has_capability on exploding vm → False",
          T.has_capability(ExplodingVM(), T.CAP_READ, tier_default_path=ABSENT), False)
    check("tier_label on exploding vm → none", T.tier_label(ExplodingVM()), "none")


def test_immutability_and_dump():
    section("7. Return type + ai-dump orthogonality")
    check_true("returns a frozenset", isinstance(T.effective_capabilities(tags=["ai-managed"], tier_default_path=ABSENT), frozenset))
    # ai-dump composes orthogonally if (unusually) combined with the umbrella
    check("ai-managed+ai-full+ai-dump → full ∪ {dump-in}",
          caps(["ai-managed", "ai-full", "ai-dump"], tier_default_path=ABSENT), FULL | {T.CAP_DUMP_IN})
    check("tier_label(ai-dump only) == ai-dump", T.tier_label(tags=["ai-dump"]), "ai-dump")


def test_scope_disjoint():
    section("8. Cross-module: tier tags are NOT AI-observable (no topology oracle)")
    leaks = T.QMCP_TIER_TAGS & SCOPE.QMCP_TAG_VOCABULARY
    # the umbrella is legitimately observable; the ELEVATION/dump tags must not be
    check("observable vocab ∩ tier tags == {ai-managed} only", leaks, {"ai-managed"})
    for t in ("ai-exec", "ai-net", "ai-full", "ai-dump"):
        check_true(f"{t} filtered out of scoped_tags", t not in SCOPE.scoped_tags(["ai-managed", t]))
    check("scoped_tags drops tiers, keeps umbrella", SCOPE.scoped_tags(["ai-managed", "ai-full", "ai-exec"]), ["ai-managed"])


def main():
    for t in (test_ladder_compat, test_cumulative_invariant, test_highest_wins,
              test_flip, test_behaviour_neutral, test_fail_closed,
              test_immutability_and_dump, test_scope_disjoint):
        t()
    section("Summary")
    total = _PASS + _FAIL
    print(f"  {_PASS}/{total} checks green.")
    if _FAIL:
        print(f"  {_FAIL} FAILED.")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
