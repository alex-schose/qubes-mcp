"""qmcp_tier — shared dom0 helper for graduated-authority resource tiers.

Stage I-3, the keystone of the resource axis (design §3). Until now the
trust boundary is binary: a qube tagged `ai-managed` gets every right the
wrappers + policy grant; an untagged qube is invisible. I-3 replaces the
single boundary with a **tier ladder** so authority graduates *within*
`ai-managed`, closing Marek's M0 (a hallucinating / prompt-injected agent
must not hold full lifecycle authority on every qube it can see).

The taxonomy — umbrella + at most one *elevation* tag, an ordered ladder:

    ai-managed   umbrella: existence boundary AND read floor (= ai-ro)
    ai-exec      + run commands        (RunInAIManaged / CopyTo / install-pkg)
    ai-net       + firewall write      (firewall.Set / Reload)
    ai-full      + lifecycle / property-set / clone / spawn / feature /
                   attach / detach
    ai-dump      copy-IN only — a write-only sink (the Biba valve); ORTHOGONAL
                 to the ladder and NOT ai-managed (so it is invisible to reads)

The ladder is cumulative: `ai-net` ⊃ `ai-exec` ⊃ read floor. This is the
deliberate model decision (operator, 2026-06-12): capabilities here nest —
anyone who may rewrite a qube's firewall may already run commands in it, so
withholding exec from a net-capable qube buys nothing. A genuine non-ladder
capability (the rare "net without exec") is expressed as an orthogonal tag,
exactly as `ai-dump` already is; the carve-out hatch exists without paying a
tag-explosion tax on every qube. See STAGE-I-DESIGN.md §3 / §1.1.

**Set-returning interface (operator decision, 2026-06-12).** The public
entry point `effective_capabilities()` returns a frozenset of capability
TOKENS, never a tier rank. Callers ask `CAP_FULL in caps`, not "what rung is
this?". So if a future need ever forces the ladder to a non-ladder/orthogonal
model, only this helper's internals change — the wrappers and the test
contract do not. The ladder is just *how the set is computed today*.

**Compat vs least-privilege (the two-phase migration, design §3.3).** An
umbrella qube with NO elevation tag resolves to a default read from the
operator-owned flag `/etc/qmcp/tier-default` (re-read per call, like F3's
`/etc/qmcp/pool-cap` — operator edits take effect with no daemon restart):

    absent      -> compat: untiered umbrella = ai-full   (I-3..I-5 default)
    "full"      -> compat: untiered umbrella = ai-full
    "ro"        -> least-privilege: untiered umbrella = ai-ro
    malformed   -> least-privilege (fail-closed: the file exists only because
                   the operator created it, so we are in the managed regime;
                   an unreadable value drops to LEAST authority, never more)

Compat is the migration default so every A–F3 surface behaves exactly as
today while I-3..I-5 ship the tiers inert-then-enforced; the operator tiers
the fleet, then writes `ro` to flip the default to least privilege. Two
reversible toggles, not a rewrite. No intermediate state is less safe than
today — enforcement (I-4/I-5) lands *before* the flip.

**This helper never reads AI-facing.** It runs in dom0 with full authority,
sourced by the wrappers (I-5) the same way `qmcp_budget` / `qmcp_scope` are.
AI cannot read a qube's tier: the tier tags are deliberately kept OUT of
`qmcp_scope.QMCP_TAG_VOCABULARY`, so a `tags` read still returns only
`["ai-managed"]` (the authority topology is not an AI-readable oracle —
keystone invariant 2 already forbids AI mutating tags; we also deny reading
them). I-3 is therefore behaviour-neutral on every AI surface.

Loaded by the wrappers via `importlib.util.spec_from_file_location` against
`os.path.dirname(os.path.realpath(__file__))`, so the same module runs in
dom0 (`/etc/qubes-rpc/qmcp_tier.py`) and in offline-validation on mcp-control
(`public/dom0-rpc/qmcp_tier.py`) with no sys.path dependency — the sibling-
import pattern Stage I-0 introduced (deviation from the Qubes self-contained-
rpc-script convention recorded as reviewer ask #12 in `public/README.md`).

F-2 note (design §18.4): tier resolution keys on TAGS only and is klass-
agnostic. A DispVMTemplate is an `AppVM` carrying `template_for_dispvms=True`,
not a distinct klass — disposables and their templates tier like any other
qube, so no klass branch belongs here.
"""
from __future__ import annotations

import os

#: Operator-owned flag selecting the untiered-umbrella default. Re-read per
#: call (no daemon restart), mirroring F3's `/etc/qmcp/pool-cap`. Absent during
#: I-3..I-5 (compat); the operator creates it with "ro" to flip to least
#: privilege once the fleet is tiered.
TIER_DEFAULT_PATH = "/etc/qmcp/tier-default"

# --- the tag taxonomy (design §3.1) --------------------------------------
UMBRELLA = "ai-managed"   #: existence boundary AND read floor
TAG_EXEC = "ai-exec"
TAG_NET = "ai-net"
TAG_FULL = "ai-full"
TAG_DUMP = "ai-dump"      #: orthogonal write-only sink; NOT on the ladder

#: The elevation ladder, low → high. `ai-dump` is intentionally absent — it is
#: orthogonal, not a rung. A qube carries the umbrella plus AT MOST ONE of
#: these; if more than one is present, the HIGHEST wins (least surprise — a
#: redundant/contradictory tag set never grants *more* than the top tag names).
ELEVATION_LADDER = (TAG_EXEC, TAG_NET, TAG_FULL)

#: The qmcp tier vocabulary — every tag this helper assigns meaning to. This is
#: the namespace the tier model OWNS; it is deliberately NOT the set of tags AI
#: may OBSERVE (that stays `{ai-managed}` in qmcp_scope). Separating the two is
#: the point: tiers are enforced off these tags in dom0, never read back by AI.
QMCP_TIER_TAGS = frozenset({UMBRELLA, TAG_EXEC, TAG_NET, TAG_FULL, TAG_DUMP})

# --- the capability tokens (the set-returning interface) ------------------
CAP_READ = "read"        #: GetProperty / List / events / device-list / firewall.Get
CAP_EXEC = "exec"        #: RunInAIManaged / CopyToAIManaged / install-pkg
CAP_NET = "net"          #: firewall.Set / firewall.Reload
CAP_FULL = "full"        #: lifecycle / property-set / clone / spawn / feature / attach / detach
CAP_DUMP_IN = "dump-in"  #: qubes.Filecopy IN only (the write-only sink)

# Cumulative cap sets per tier label. Built by accumulation so the ladder
# ordering lives in exactly one place and each rung provably contains the one
# below it.
_RO = frozenset({CAP_READ})
_EXEC = _RO | {CAP_EXEC}
_NET = _EXEC | {CAP_NET}
_FULL = _NET | {CAP_FULL}

#: Tier label → capability set. `"ai-ro"` is the synthetic floor (umbrella
#: alone). The elevation tags map to their cumulative sets.
TIER_CAPS = {
    "ai-ro": _RO,
    TAG_EXEC: _EXEC,
    TAG_NET: _NET,
    TAG_FULL: _FULL,
}


def _read_operator_word(path: str):
    """One lowercase token from an operator config file, or a failure sentinel.

    Returns the token, `None` if the file is ABSENT, or `False` if it exists but
    could not be read or parsed. Callers must treat those two failures
    differently: absent means "the operator has not opted in", unreadable means
    "the operator opted in and we cannot see how", which fails closed.

    **Honours `value  # comment`,** the format every other operator file in this
    project already uses (`qmcp_budget._read_int_file`, and the `pool-cap`
    shipped by install-stage-I-0 literally contains one). Without the strip, an
    operator who annotates their file the way the neighbouring files are
    annotated gets a silently malformed value — and because malformed fails
    closed, the setting appears to do nothing at all.

    **The permission trap this exists to make survivable.** These wrappers run
    under qrexec as a NON-ROOT dom0 user, so an operator file created with
    `sudo bash -c 'echo x > /etc/qmcp/f'` lands `root:root 0600` (root's umask
    is 077 in that context) and is UNREADABLE here. It then fails closed and the
    operator sees their setting silently ignored. Every such file must be 0644.
    `install-stage-2.sh` checks this at deploy for the whole `/etc/qmcp` read
    set. Same family as the I-2 lesson about the non-root wrapper user, on the
    read side rather than the write side.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return None
    except Exception:
        return False
    return raw.split("#", 1)[0].strip().lower()


def _untiered_default_label(tier_default_path: str) -> str:
    """Resolve the untiered-umbrella default tier label from the operator flag.

    `ai-full` in compat (the I-3..I-5 default; flag absent or "full"),
    `ai-ro` once the operator flips it ("ro") and on any malformed value
    (fail-closed — the file exists only by the operator's hand, so an
    unreadable value drops to least authority).
    """
    val = _read_operator_word(tier_default_path)
    if val is None:
        return TAG_FULL        # compat: the flag is not yet created
    if val is False:
        return "ai-ro"         # fail-closed: file exists but unreadable
    if val == "full":
        return TAG_FULL
    if val == "ro":
        return "ai-ro"
    return "ai-ro"             # fail-closed on any other (malformed) value


def _highest_elevation(tagset) -> str | None:
    """The top elevation tag present in `tagset`, or None if untiered.

    Walks the ladder high → low and returns the first match, so a qube tagged
    with several elevation tags resolves to the HIGHEST — never an accidental
    grant beyond what its top tag names.
    """
    for tag in reversed(ELEVATION_LADDER):
        if tag in tagset:
            return tag
    return None


def _tags_of(vm, tags):
    """Normalise the caller's input to a plain set of tag strings.

    Accepts either an explicit `tags` iterable (offline tests) or a qubesadmin
    VM whose `.tags` is read. Raises on failure; callers treat any exception as
    fail-closed (no capability).
    """
    if tags is not None:
        return set(tags)
    return set(vm.tags)


def tier_label(vm=None, *, tags=None) -> str:
    """Human tier label for a qube — DIAGNOSTIC ONLY (audit / logs / tests).

    Returns the highest elevation tag, or `"ai-ro"` for an untiered umbrella
    qube, or `"ai-dump"` for a pure sink, or `"none"` for a qube this model
    does not recognise. Enforcement must use `effective_capabilities()` (the
    capability set), never this label — the label collapses the orthogonal
    `ai-dump` and the ladder into one string and is not a security surface.
    """
    try:
        tagset = _tags_of(vm, tags)
    except Exception:
        return "none"
    if UMBRELLA in tagset:
        return _highest_elevation(tagset) or "ai-ro"
    if TAG_DUMP in tagset:
        return TAG_DUMP
    return "none"


def effective_capabilities(vm=None, *, tags=None,
                           tier_default_path: str = TIER_DEFAULT_PATH) -> frozenset:
    """The capability tokens granted on a qube — the one enforcement entry point.

    Resolution:
      - `ai-managed` present → the read floor, plus the cumulative caps of the
        highest elevation tag; an untiered umbrella qube takes the operator's
        compat/least-privilege default (see `_untiered_default_label`).
      - `ai-dump` present → adds `CAP_DUMP_IN` (orthogonal to the ladder; a
        qube may in principle carry both, though the intended use is a
        standalone non-ai-managed sink).
      - neither → the empty set (a qube outside the model grants nothing).

    Fail-closed: any error reading the tag set yields the empty frozenset —
    a tag-read failure denies, it never leaks authority. Returns a frozenset
    so callers cannot mutate the shared TIER_CAPS sets.
    """
    try:
        tagset = _tags_of(vm, tags)
    except Exception:
        return frozenset()

    caps: set = set()
    if UMBRELLA in tagset:
        rung = _highest_elevation(tagset)
        label = rung if rung is not None else _untiered_default_label(tier_default_path)
        caps |= TIER_CAPS[label]
    if TAG_DUMP in tagset:
        caps.add(CAP_DUMP_IN)
    return frozenset(caps)


def has_capability(vm=None, cap: str = "", *, tags=None,
                   tier_default_path: str = TIER_DEFAULT_PATH) -> bool:
    """True iff the qube grants `cap`. Thin wrapper the I-5 wrappers call as
    `has_capability(vm, qmcp_tier.CAP_FULL)` before a state-changing op."""
    return cap in effective_capabilities(vm, tags=tags, tier_default_path=tier_default_path)
