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


# --- the reserved NAME namespace (F-1) ------------------------------------
#
# This module already owns the reserved *tag* namespace, and a reserved *qube
# name* namespace is the same idea enforced one layer out, so it lives here
# rather than in a fourth file — and here it is loaded by exactly the three
# wrappers that create qubes, which are exactly the three that must enforce it.
#
# WHY A NAMESPACE AND NOT A BETTER ERROR MESSAGE. The create paths used to
# check a requested name against `app.domains` — the whole host — and answer
# `qube '<name>' already exists`, which let AI confirm any qube name it could
# guess: `vault`, `personal`, `sys-usb`, the operator's own qubes. Measured on
# hardware 2026-08-18: 11 out-of-scope qubes identified from the AI seat.
#
# Collapsing the message is not sufficient, and it is worth being precise about
# why, because the cheap fix looks convincing. A create has three outcomes: the
# name is free (a qube appears), the name is taken by an ai-managed qube, or the
# name is taken by something outside the umbrella. AI can already enumerate the
# second group. So even with one uniform refusal, "refused and not in my list"
# still means "something I cannot see is there" — and the *timing* separates
# them anyway, since a free name goes on to do real work while a taken one
# returns immediately.
#
# The oracle is therefore inherent to an unnamespaced create, and the only way
# to remove it is to make the third outcome impossible: AI proposes names ONLY
# inside a namespace reserved for it, and a name outside that namespace is
# refused on SHAPE ALONE — no host lookup, constant time, an error that depends
# on nothing but the rule. Then a collision can only ever concern a name inside
# AI's own namespace.
#
# RESIDUAL, stated rather than glossed: a qube inside the reserved namespace
# that is NOT ai-managed remains detectable, because AI can list the ai-managed
# ones and subtract. That is a deliberate, bounded trade — one namespace the
# project documents as reserved, instead of the whole host — and the installer
# warns when such a qube exists. Do not "fix" it by making collisions silent:
# a create that fails without saying the name is taken is worse to operate and
# closes nothing, since the timing tell survives.

#: Operator-owned override, read per call like every other operator file.
NAME_PREFIX_PATH = "/etc/qmcp/name-prefix"

#: The shipped default. Matches the project's own public vocabulary — every
#: default qube name in this repo is already `ai-*`.
DEFAULT_NAME_PREFIX = "ai-"

#: A prefix must itself be a legal start-of-name, or it could never be
#: satisfied and every create would fail closed forever.
_PREFIX_RE = r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,15}$"


def read_name_prefix(path: str = NAME_PREFIX_PATH) -> str:
    """The reserved prefix AI-created names must carry.

    Absent      -> `DEFAULT_NAME_PREFIX` (the shipped behaviour).
    A legal prefix -> that prefix.
    Malformed, unreadable, or empty -> `DEFAULT_NAME_PREFIX`.

    **Fail-closed here means falling back to the RESTRICTIVE default, not to
    "no prefix".** Every other operator file in this tree drops to least
    authority on a malformed value; for this one, "no prefix" would be MOST
    authority — it reopens the whole-host oracle — so the safe landing is the
    default rather than the empty string. An operator cannot switch the guard
    off by corrupting the file, only by editing the code.
    """
    import re
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except Exception:
        return DEFAULT_NAME_PREFIX
    word = raw.split("#", 1)[0].strip()
    if not word or not re.match(_PREFIX_RE, word):
        return DEFAULT_NAME_PREFIX
    return word


def name_refusal(name: str, prefix: str) -> str | None:
    """`None` if `name` may be created by AI, else the refusal message.

    Depends on `name` and `prefix` ONLY — never on what exists on the host —
    so it cannot become an oracle and runs in constant time with respect to
    the fleet. Callers must run this BEFORE any `app.domains` lookup; running
    it after would leak exactly what it exists to prevent.
    """
    if not isinstance(name, str) or not name.startswith(prefix):
        return (f"name must start with '{prefix}' — that namespace is reserved "
                f"for AI-created qubes")
    if len(name) <= len(prefix):
        return f"name must have something after the reserved '{prefix}' prefix"
    return None


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
