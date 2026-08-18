"""qmcp_tombstone — an AI-initiated remove becomes a recoverable tombstone.

Wave 2 Stage 3a. Ships INERT: nothing calls `entomb()` yet. The wrapper flip
that routes `qmcp.LifecycleAIManaged:remove` through here is Stage 3c, and it
must not land before this module and the reaper exist — see below.

**Why this has to exist BEFORE the enforcement flip, not with it.**
`qmcp_caps.DOMINATION` lists Lifecycle `remove` as dominated by `CAP_EXEC`, on
the anti-theatre invariant: an actor holding exec already reaches `rm -rf`, so
refusing `remove` leaves the same data gone and an empty qube behind. That
reasoning is sound *for the data* and false *for the qube*. Honouring the
domination table without a tombstone would convert a `CAP_FULL` gate into a
`CAP_EXEC` capability to irreversibly destroy a qube — a strict widening of
destructive authority, shipped inside the stage whose purpose is least
privilege. The tombstone is the compensating control that makes the widening
honest: AI's remove becomes *invisible and unresurrectable to AI* immediately,
and *irreversible* only after the operator's inspection window has passed.

**The transition, and why the order is what it is.**

    halted?  ->  add qmcp-tombstone_<epoch>  ->  drop the umbrella + privilege
                                                 tags  ->  read back and verify

1. **Halted first.** Dropping the umbrella from a *running* qube would leave a
   live qube nothing in the model can see — `decide()` denies at step 1, the
   list surface filters it out, and the operator has no reason to look. So
   `entomb()` refuses on an unhalted qube rather than trusting the caller to
   have shut it down; the contract is enforced, not documented.
2. **Tag before strip.** If the process dies between the two, tag-first leaves
   a qube that is both `ai-managed` and tombstoned: visible, still charged to
   the pool cap, and reported by the reaper as stuck. Strip-first leaves one
   that is invisible, uncharged and undated — an orphan that silently consumes
   pool for the rest of the fleet's life. Between a loud wrong state and a
   silent one, take the loud one. (`qmcp_birth.stamp` adds before it removes
   too, for a related reason: never leave a created qube outside the umbrella
   that must find it.)
3. **Read back, two-sided.** Same posture as `qmcp_birth.verify` — assert the
   controlled vocabulary EXACTLY, so a surviving umbrella or a tier tag that
   did not strip is an error, not a silent half-tombstone.

**Restriction tags survive (§3.2).** `qmcp-guarded`, `qmcp-egress-locked_*` and
`anon-vm` are carried through. A tombstone cannot be resurrected by AI — the
umbrella is gone and `admin.vm.tag.Set` is policy-denied to the gateway — so
this is not load-bearing today. It is kept because the alternative is a strip
that removes a restriction, and per F-E that is the shape of every laundering
hole this project has found. A restriction our own code can drop is one an
attacker only has to reach.

**Tombstones are still charged to the pool cap, and that is a security
property, not bookkeeping.** `qmcp_budget.counts_toward_cap` charges anything
carrying the umbrella OR this module's prefix. If it charged only the umbrella,
dropping the umbrella would make a tombstone free, and an `ai-exec` actor could
create-and-remove in a loop to park an unbounded number of full-size qubes
outside the accounting for the whole retention window — churn straight through
the one bound on accumulation. `qmcp.GetPoolStats` calls the same sum, so AI's
`(used, cap, headroom)` still predicts the gate byte-for-byte: a remove does
not immediately return headroom, and waiting out the window is the honest cost.

**Reaping is timer-only — never under pressure (operator decision,
2026-08-16).** The brief's own Stage 3 text says tombstones "reap oldest-first
under pressure"; that was overridden and this module implements the override.
Early-reaping under pool pressure is an evidence-destruction path: the I-2
chain records the *operations*, not the qube contents, so an AI that wanted a
tombstone gone before the operator read it would only have to flood small
creates until the cap evicted it. Under pressure the cap REFUSES the create.
Nothing here is reachable from a create path, by construction.

**Not an AI surface.** No `qmcp.*` service exposes this module, no policy line
reaches it, and the tombstone tag is outside `qmcp_scope.QMCP_TAG_VOCABULARY`.
A tombstoned qube reads as `"not found"` — the same opaque answer as a qube
that never existed — because it is outside the umbrella, not because anything
special-cases it.

Sibling-loaded by path like every other dom0 helper, so the same file runs in
dom0 (`/etc/qubes-rpc/qmcp_tombstone.py`) and under offline validation on
mcp-control (`public/dom0-rpc/qmcp_tombstone.py`).
"""
from __future__ import annotations

# --- the reserved tag ------------------------------------------------------

#: `qmcp_birth.NAMESPACE` + "tombstone" + `qmcp_birth.SEP`, written out rather
#: than composed so this module has no load-time dependency on another helper.
#: The separator is `_` because qubesd's `validate_tag` accepts only
#: alphanumerics, `-` and `_` — measured on R4.3, see `qmcp_birth`'s docstring.
#:
#: `qmcp_budget.py` carries this same literal for its cap predicate, and that
#: duplication is deliberate: the cap is a GATE, and a sibling import that
#: failed to load would silently stop charging tombstones — reinstating the
#: create/remove churn bypass with no symptom at all. A literal cannot fail to
#: load. `deploy/offline-validate-3a.py` asserts the two agree, so it cannot
#: drift instead.
TOMBSTONE_PREFIX = "qmcp-tombstone_"

#: Operator-owned retention window in seconds. Absent = 24h (the shipped
#: default, and the figure D3 names). AI can neither read nor write it: no
#: `qmcp.*` service exposes it and no policy line reaches it.
RETENTION_PATH = "/etc/qmcp/tombstone-retention"

#: 24 hours — the operator's window to inspect what AI removed.
DEFAULT_RETENTION_SECONDS = 86400


def tombstone_tag(when: int) -> str:
    """The tombstone tag recording the moment of death, as a UTC epoch."""
    return f"{TOMBSTONE_PREFIX}{int(when)}"


def is_tombstone(tag: str) -> bool:
    """True iff `tag` is this module's marker."""
    return str(tag).startswith(TOMBSTONE_PREFIX)


def is_tombstoned(tags) -> bool:
    """True iff the qube carries any tombstone marker, datable or not."""
    try:
        return any(is_tombstone(t) for t in tags)
    except Exception:
        return False


def tombstone_epoch(tags):
    """The death timestamp, or None if the qube is not datably tombstoned.

    A qube should carry exactly one marker. If it somehow carries several, the
    LATEST wins — the longest retention, i.e. the answer that destroys least.
    A marker with a non-numeric suffix is undatable and contributes nothing; if
    that leaves no datable marker at all, this returns None and `due_for_reap`
    refuses to reap. An undatable tombstone is a bug to be looked at by a
    person, not a qube to be deleted by a timer.
    """
    best = None
    try:
        candidates = list(tags)
    except Exception:
        return None
    for tag in candidates:
        if not is_tombstone(tag):
            continue
        suffix = str(tag)[len(TOMBSTONE_PREFIX):]
        if not suffix.isdigit():
            continue
        value = int(suffix)
        if best is None or value > best:
            best = value
    return best


# --- the transition --------------------------------------------------------

def expected_tags(before, umbrella, tier_tags, when):
    """The exact set of CONTROLLED tags a tombstoned qube must carry.

    The umbrella and every tier tag are gone; `qmcp-owner_*` is gone (it is a
    privilege tag and the qube has no owner to answer for it any more); every
    restriction is carried forward; the marker is added. Tags outside the
    controlled vocabulary — operator labels, `created-by-*` — are not in this
    set and are not asserted on.
    """
    want = {tombstone_tag(when)}
    want |= _restrictions(before)
    return want


def _restrictions(tags) -> set:
    """The restriction tags carried through a tombstone (§3.2).

    Deliberately a local copy of `qmcp_birth`'s vocabulary rather than an
    import, for the same reason `TOMBSTONE_PREFIX` is duplicated in the budget
    helper: a helper that fails to load must never quietly widen what this
    module strips. The two definitions are asserted equal offline.
    """
    out = set()
    for tag in set(tags):
        text = str(tag)
        if text in ("qmcp-guarded", "anon-vm"):
            out.add(text)
        elif text.startswith("qmcp-egress-locked_"):
            out.add(text)
    return out


def controlled(tag: str, tier_tags) -> bool:
    """True iff this module asserts the presence/absence of `tag`.

    Same vocabulary as `qmcp_birth.controlled`: the tier tags plus everything
    under `qmcp-`. The umbrella is inside `QMCP_TIER_TAGS`, so a umbrella that
    failed to strip is caught by `verify` as an unexpected controlled tag.
    """
    return tag in set(tier_tags) or str(tag).startswith("qmcp-")


def entomb(io, tier_tags, *, when, umbrella, is_halted) -> set:
    """Apply the tombstone transition and prove it. Raises on any mismatch.

    `io` is a `qmcp_birth.TagIO` (or anything with the same read/add/remove
    callables) so this is testable with no qubesadmin at all. `is_halted` is a
    zero-arg predicate; a truthy answer is required before anything is written.

    The caller MUST treat a raise as "the remove did not happen" and return its
    usual opaque error. Retrying is safe: every step is idempotent, and a
    partially-applied transition converges on the second pass.
    """
    try:
        halted = bool(is_halted())
    except Exception:
        halted = False
    if not halted:
        raise RuntimeError("refusing to tombstone a qube that is not halted")

    before = set(io.read())
    want = expected_tags(before, umbrella, tier_tags, when)

    # Add before remove — see the module docstring. Never leave a qube outside
    # the umbrella without the marker that makes it findable and chargeable.
    for tag in sorted(want - before):
        io.add(tag)
    for tag in sorted(t for t in before - want if controlled(t, tier_tags)):
        io.remove(tag)

    verify(io, want, tier_tags, umbrella)
    return want


def verify(io, want, tier_tags, umbrella) -> None:
    """Read back and assert the controlled vocabulary matches `want` exactly.

    Two-sided, like `qmcp_birth.verify`. The umbrella gets its own named check
    ahead of the generic one purely so the error says which invariant broke:
    "still inside the umbrella" is a live qube AI can still reach, and it reads
    very differently in a log from "a stray tier tag survived".
    """
    final = set(io.read())
    if umbrella in final:
        raise RuntimeError("tombstone incomplete: still inside the umbrella")
    missing = set(want) - final
    if missing:
        raise RuntimeError(f"tombstone incomplete: missing {sorted(missing)}")
    extra = {t for t in final - set(want) if controlled(t, tier_tags)}
    if extra:
        raise RuntimeError(f"tombstone carries unexpected tags: {sorted(extra)}")


# --- the reaper's policy ---------------------------------------------------

def read_retention(path: str = RETENTION_PATH):
    """The retention window in seconds, or None meaning NEVER REAP.

    Absent  -> `DEFAULT_RETENTION_SECONDS` (the shipped default).
    Integer -> that many seconds; `0` is legal and means "reap on the next
               timer tick", which is an operator's choice to make.
    Anything else, or unreadable -> None.

    Fail-closed here points AWAY from deletion, which is the opposite of every
    other fail-closed in this codebase and is correct for the same reason they
    are: the closed direction is the one that cannot destroy something the
    operator wanted. A malformed config must not license a timer to delete
    evidence.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read().strip()
    except FileNotFoundError:
        return DEFAULT_RETENTION_SECONDS
    except Exception:
        return None
    if not raw or not raw.isdigit():
        return None
    return int(raw)


def due_for_reap(tags, now, retention, *, umbrella="ai-managed",
                 running=False) -> bool:
    """True iff this qube may be destroyed by the reaper right now.

    Every condition below is a veto, and each one exists because the reaper's
    licence to destroy comes from the qube already being dead:

      - `retention is None`        the config is malformed; reap nothing
      - not datably tombstoned     an undatable marker is a bug for a person
      - `umbrella` still present   the strip did not complete, so AI can still
                                   see it — it is not dead, it is stuck
      - `running`                  something started it; on a tombstone that is
                                   the operator inspecting, and the timer does
                                   not delete what someone is looking at
      - inside the window          including a marker dated in the future,
                                   which a clock change can produce and which
                                   this arithmetic vetoes for free
    """
    if retention is None:
        return False
    if running:
        return False
    try:
        if umbrella in set(tags):
            return False
    except Exception:
        return False
    epoch = tombstone_epoch(tags)
    if epoch is None:
        return False
    return (int(now) - epoch) >= int(retention)
