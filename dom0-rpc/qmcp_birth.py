"""qmcp_birth — the reserved `qmcp-*` namespace and the atomic birth stamp.

Wave 2 Stage 2. Every create path (`qmcp.SpawnAIManagedQube`,
`qmcp.CloneAIManagedQube`, `qmcp.SpawnDisposableAIManaged`) ends in the same
three-part question — *what tags must this new qube carry, what must it NOT
carry, and how do we prove it before AI sees it* — and each of the three
answered a slice of it in its own copy of `strip_inherited_tier_tags`. This
module is the single answer, sibling-loaded like `qmcp_tier` / `qmcp_budget` /
`qmcp_scope` / `qmcp_audit` / `qmcp_caps`.

**Two tag classes, and the asymmetry between them is the whole design (§3.2).**

- **Privilege tags** — the tier ladder and `qmcp-owner_` — are **clamped** to
  the actor's authority on the source (D2, `qmcp_tier.resolve_birth_tier`).
  Inheriting them unchanged is how an AI mints authority it was not granted.
- **Restriction tags** — `qmcp-egress-locked_*`, `qmcp-guarded`, and the
  platform's `anon-vm` — are **inherited unconditionally** and are never
  removable by the clamp path. Per F-E, a restriction a strip can remove is a
  laundering hole: clone the guarded qube, lose the guard, operate freely.

So the strip is not "remove everything and re-add what we chose" — it is
"remove every PRIVILEGE tag in our controlled vocabulary, carry every
RESTRICTION forward, then assert the exact expected state". A tag we do not
own (an operator's own label, the platform's `created-by-*`) is left alone.

**Verify, then roll back — never assume.** `qubesadmin.clone_vm` copies the
source's tags and `admin.vm.CreateDisposable` inherits the DVMT's; the I-5
lesson (and the adversarial review that caught it) is that a create wrapper
must strip, **read back**, and roll the create back on any mismatch, because
the platform's propagation is not ours to assume. `verify()` here is that read-
back, and it is deliberately stricter than "the tags I added are present": it
also fails when a tag from our controlled vocabulary is present that we did
NOT intend, which is what catches a future platform change that starts
propagating something new.

**Not an AI surface.** This module runs in dom0. The tags it stamps are
outside `qmcp_scope.QMCP_TAG_VOCABULARY`, so a `tags` read still returns only
`["ai-managed"]` — ownership and birth tier are enforcement facts, not an
AI-readable oracle, exactly as the tier tags are.

**Tag punctuation — MEASURED, not assumed (2026-08-18, Qubes R4.3).** The brief
writes these as `qmcp-owner:<principal>` and `qmcp-egress-locked:<netvm>`, and
**qubesd refuses that**: `qubes.vm.Tags.validate_tag` raises
`ValueError("disallowed characters")` for `:` and `.`, accepting only
alphanumerics, `-` and `_`. Probed directly against `admin.vm.tag.Set` in dom0.

`SEP` is therefore `"_"`, and it is the single place the choice is written. `_`
rather than `-` because both the key (`egress-locked`) and the value
(`ai-net-alt`) already contain dashes, so a dash separator would render the tag
as one undifferentiated run — and legibility in `qvm-tags` output is the entire
purpose of the egress class tag. Parsing never depends on it either way: every
reader strips a fixed prefix.

`install-stage-2.sh` still pre-flights a real `admin.vm.tag.Set` with the
configured separator and ABORTS on refusal. That check earns its keep even now
the answer is known — the validator is a platform detail that can differ across
Qubes versions, and the failure mode it prevents is silent: every create path
would fail closed forever afterwards, on a fleet where the install reported
success.

**How that refusal presents, because it cost a debugging cycle.** qubesd
answers a tag-validation failure as an *unhandled exception*: the caller sees
`QubesDaemonAccessError: Got empty response from qubesd`, with the actual
`ValueError` visible only in dom0's journal. Nothing in the error names the
tag, the character, or the validator. If a `qmcp-*` tag write ever fails with
an empty-response error, check `journalctl -u qubesd` before suspecting this
code.
"""
from __future__ import annotations

#: The separator between a reserved tag's key and its value. See the docstring:
#: qubesd's validate_tag accepts only alphanumerics, "-" and "_", so ":" (the
#: brief's notation) is not available. Changing this changes every reserved tag
#: this module writes and reads, and nothing else.
SEP = "_"

#: Everything this module owns. A tag starting with it is ours to assert on;
#: anything else on the qube is left untouched.
NAMESPACE = "qmcp-"

OWNER_PREFIX = f"{NAMESPACE}owner{SEP}"
EGRESS_LOCK_PREFIX = f"{NAMESPACE}egress-locked{SEP}"
TAG_GUARDED = f"{NAMESPACE}guarded"

#: Restriction tags matched exactly. `anon-vm` is the platform's own Whonix
#: marker and is deliberately in here: a Whonix-derived qube that lost it on
#: clone would be a deanonymisation event dressed as a tag bug.
RESTRICTION_TAGS = frozenset({TAG_GUARDED, "anon-vm"})

#: Restriction tags matched by prefix (they carry a value).
RESTRICTION_PREFIXES = (EGRESS_LOCK_PREFIX,)


class TagIO:
    """Read/add/remove for one qube's tags, injected by the caller.

    The three create wrappers reach tags two different ways and both are
    correct: Spawn and Clone hold a real VM object and use `vm.tags`, while
    SpawnDisposable must use direct `qubesd_call`s because qubesadmin's
    `VMCollection` cache lags `admin.vm.CreateDisposable` by several seconds
    and `app.domains[name]` raises `KeyError` (reviewer ask #7). Rather than
    pick one and break the other, this module takes the three operations as
    callables — which also makes every path here testable offline with no
    qubesadmin at all.
    """

    __slots__ = ("read", "add", "remove")

    def __init__(self, read, add, remove) -> None:
        self.read = read
        self.add = add
        self.remove = remove

    @classmethod
    def for_vm(cls, vm):
        """Adapter for a qubesadmin VM object (Spawn / Clone)."""
        return cls(lambda: set(vm.tags),
                   lambda t: vm.tags.add(t),
                   lambda t: vm.tags.discard(t))

    @classmethod
    def for_qubesd(cls, app, name):
        """Adapter using direct admin calls (SpawnDisposable, cache-lag-safe)."""
        def _read():
            raw = app.qubesd_call(name, "admin.vm.tag.List")
            return set(raw.decode(errors="replace").split())
        return cls(_read,
                   lambda t: app.qubesd_call(name, "admin.vm.tag.Set", t),
                   lambda t: app.qubesd_call(name, "admin.vm.tag.Remove", t))


def owner_tag(principal: str) -> str:
    """The ownership tag for a calling principal (D1).

    The principal is the qrexec source domain — `mcp-control` today, and the
    reason I-9's delegation fields need no schema change tomorrow. Provenance
    is carried HERE and never on `created-by-*`: qubesd stamps that with the
    *calling* domain, which is dom0 for every qmcp create, so it cannot tell an
    AI-spawned qube from an operator-created one (F-A). `disp-created-by-*` is
    worse — qubesd's guard misses it entirely, so it is forgeable by anything
    holding `tag.Set`. Never scope anything on either.
    """
    safe = "".join(c for c in str(principal) if c.isalnum() or c in "-_")
    return f"{OWNER_PREFIX}{safe or 'unknown'}"


def egress_lock_tag(netvm) -> str:
    """The legibility tag naming the egress a qube is locked to.

    Stage 2 only INHERITS these (a locked source produces a locked child); the
    operator freeze tool that mints them is brief §7 / Stage 5. Enforcement
    never reads this tag — §3.4 enforces on the literal `netvm` identity, and a
    class tag that could be argued into the enforcement path is how a legibility
    label quietly becomes a security control.
    """
    return f"{EGRESS_LOCK_PREFIX}{netvm}"


def is_restriction(tag: str) -> bool:
    """True iff `tag` is inherited unconditionally by a created qube."""
    return tag in RESTRICTION_TAGS or tag.startswith(RESTRICTION_PREFIXES)


def inherited_restrictions(source_tags) -> set:
    """The restriction tags a child of this source must carry (§3.2)."""
    return {t for t in set(source_tags) if is_restriction(t)}


def controlled(tag: str, tier_tags) -> bool:
    """True iff this stage asserts the presence/absence of `tag`.

    Our vocabulary is the tier tags plus everything under `qmcp-`. Operator
    labels and platform tags (`created-by-*`, and `anon-vm` when the platform
    rather than the source put it there) fall outside it and are not touched —
    a create wrapper that started deleting the operator's own tags would be a
    far worse bug than the one it was fixing.
    """
    return tag in set(tier_tags) or tag.startswith(NAMESPACE)


def expected_tags(source_tags, principal, birth_tier, umbrella, tier_tags) -> set:
    """The exact set of CONTROLLED tags a freshly created qube must carry.

    `birth_tier` is `qmcp_tier.resolve_birth_tier`'s answer — a tag or None for
    untiered. Tags outside the controlled vocabulary are not part of this set
    and are not asserted on.
    """
    want = {umbrella, owner_tag(principal)}
    if birth_tier:
        want.add(birth_tier)
    want |= inherited_restrictions(source_tags)
    return want


def stamp(io: TagIO, source_tags, principal, birth_tier, umbrella, tier_tags) -> set:
    """Apply the birth stamp and prove it. Raises on any mismatch.

    The caller MUST roll the created qube back when this raises — a qube whose
    tag state we could not prove has an unknown authority, and leaving it in
    place is precisely the laundering hole the two-class split exists to close.

    Order matters: add first, then remove. A create that dies between the two
    leaves a qube that is over-restricted (it still carries an inherited
    privilege tag but also the umbrella and owner), which the caller's rollback
    then removes. The reverse order would briefly leave a qube with no umbrella
    at all — invisible to the very rollback that has to find it.
    """
    want = expected_tags(source_tags, principal, birth_tier, umbrella, tier_tags)
    have = set(io.read())

    for tag in sorted(want - have):
        io.add(tag)
    for tag in sorted(t for t in have - want if controlled(t, tier_tags)):
        io.remove(tag)

    verify(io, want, tier_tags)
    return want


def verify(io: TagIO, want, tier_tags) -> None:
    """Read back and assert the controlled vocabulary matches `want` exactly.

    Two-sided on purpose. Missing-expected catches a tag write that silently
    did not take; **unexpected-present** catches the case that actually shipped
    a bug once — a platform propagating something we did not model. An
    assertion that only checks what it added agrees with itself, not with
    Qubes.
    """
    final = set(io.read())
    missing = set(want) - final
    if missing:
        raise RuntimeError(f"birth stamp incomplete: missing {sorted(missing)}")
    extra = {t for t in final - set(want) if controlled(t, tier_tags)}
    if extra:
        raise RuntimeError(f"birth stamp carries unexpected tags: {sorted(extra)}")
