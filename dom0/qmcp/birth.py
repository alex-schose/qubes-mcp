"""qmcp.birth — names, badges and network for every qube qmcp creates.

**The reserved name namespace.** The hub proposes names only inside a
prefix reserved for AI (`/etc/qmcp/name-prefix`, default `ai-`), and a name
outside it is refused on its shape alone, before any lookup. A collapsed
"already exists" message would not be enough: a create has three outcomes —
free, taken inside AI space, taken outside it — and the hub can list the
second, so a uniform refusal still reveals the third by subtraction, and
timing separates them anyway. The only fix is to make the third impossible.
Residual, stated: a qube outside AI space whose name sits inside the prefix
stays detectable; `qmcp check` reports such qubes.

**Strip on create.** `clone_vm` copies the source's tags and
`admin.vm.CreateDisposable` copies the disposable template's, so a created
qube must not be assumed clean. `stamp()` adds what the child must carry —
the umbrella, a provenance badge and, for a workload, the creator's slot
badge — carries the platform's Whonix marker forward, removes every other tag
in our controlled vocabulary (`qmcp-guarded` included: a child spawned from a
guarded template is managed; every role and slot badge, so a clone of a lead or
of another project's member is neither; and v0.9.16's `qmcp-egress-locked_*`,
which nothing reads since no network moves), and then reads the tags back and
asserts the exact result, both ways. The caller rolls the qube back if it
raises. Tags outside our vocabulary (the operator's own, `created-by-*`) are
left alone.

**Birth network** (the hub's creates; a lead's follow its project's list).
A hub request for no network is always granted (`services._birth_netvm`).
Otherwise first match wins; every answer but "no network" is an enrolled
gateway (`qmcp.gateways`), and a network that cannot be read refuses the
create:
  1. the creation source's netvm, when the source answers for itself — a
     clone source or a disposable template, including "no network"; a
     source on a network that is not enrolled refuses the create;
  2. the hub's own netvm, if it is enrolled;
  3. `/etc/qmcp/birth-egress`, operator-owned, if it is enrolled;
  4. refuse the create.
A TemplateVM used as the base of a spawn does not answer for itself: its
netvm is an update path, not a workload's network.

qubesd's tag validator accepts only letters, digits, `-` and `_` (measured
2026-08-18), which is why the separator is `_`.
"""
from __future__ import annotations

import re

from qmcp import gateways
from qmcp.core import GUARDED, UMBRELLA

SEP = "_"
NAMESPACE = "qmcp-"
OWNER_PREFIX = f"{NAMESPACE}owner{SEP}"
#: v0.9.16's egress lock. Nothing reads it since no network moves, so it is no
#: longer carried to a child: like every tag in our vocabulary, a create strips it.
EGRESS_LOCK_PREFIX = f"{NAMESPACE}egress-locked{SEP}"

#: The v0.9.16 tier tags. No longer meaningful, but a child must never carry
#: one, so they stay in the controlled vocabulary.
LEGACY_TIER_TAGS = frozenset({"ai-exec", "ai-net", "ai-full"})

#: Restrictions a child inherits unconditionally. `anon-vm` is the platform's
#: Whonix marker: losing it on a clone would be a deanonymisation event.
RESTRICTION_TAGS = frozenset({"anon-vm"})

NAME_PREFIX_PATH = "/etc/qmcp/name-prefix"
DEFAULT_NAME_PREFIX = "ai-"
_PREFIX_RE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9-]{0,15}\Z")
#: A name qmcp may create: letters, digits and dashes, starting with a letter
#: or digit. Narrower than Qubes allows on purpose (no dots or underscores).
NAME_RE = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9-]{0,30}\Z")

BIRTH_EGRESS_PATH = "/etc/qmcp/birth-egress"


# ----------------------------------------------------------------- names

def read_name_prefix(path: str | None = None) -> str:
    """The reserved prefix. Malformed or absent falls back to the DEFAULT —
    the restrictive answer here, since "no prefix" would reopen the oracle."""
    try:
        with open(NAME_PREFIX_PATH if path is None else path, encoding="utf-8") as fh:
            word = fh.read(256).split("#", 1)[0].strip()
    except OSError:
        return DEFAULT_NAME_PREFIX
    return word if _PREFIX_RE.match(word) else DEFAULT_NAME_PREFIX


def name_refusal(name, prefix: str) -> str | None:
    """None if `name` may be created, else why not. Depends on `name` and
    `prefix` only, never on the host, so it is constant time and no oracle.
    Callers run it before any lookup."""
    if not isinstance(name, str) or not NAME_RE.match(name):
        return "name must be letters, digits and dashes, 1-31 chars, starting with a letter or digit"
    if not name.startswith(prefix):
        return f"name must start with '{prefix}': that namespace is reserved for AI-created qubes"
    if len(name) <= len(prefix):
        return f"name must have something after the reserved '{prefix}' prefix"
    return None


# ----------------------------------------------------------------- badges

class TagIO:
    """read/add/remove for one qube's tags, supplied by the caller.

    Spawn and Clone hold a VM object. SpawnDisposable must talk to qubesd
    directly, because qubesadmin's domain cache lags CreateDisposable by
    seconds and `app.domains[name]` raises meanwhile.
    """

    __slots__ = ("read", "add", "remove")

    def __init__(self, read, add, remove) -> None:
        self.read, self.add, self.remove = read, add, remove

    @classmethod
    def for_vm(cls, vm):
        return cls(lambda: set(vm.tags), vm.tags.add, vm.tags.discard)

    @classmethod
    def for_qubesd(cls, app, name):
        def _read():
            raw = app.qubesd_call(name, "admin.vm.tag.List")
            return set(raw.decode(errors="replace").split())
        return cls(_read,
                   lambda t: app.qubesd_call(name, "admin.vm.tag.Set", t),
                   lambda t: app.qubesd_call(name, "admin.vm.tag.Remove", t))


def owner_tag(principal: str) -> str:
    """Provenance only, never a gate. Never `created-by-*`, which
    qubesd stamps with the CALLING domain — dom0 for every qmcp create."""
    safe = "".join(c for c in str(principal) if c.isalnum() or c in "-_")
    return f"{OWNER_PREFIX}{safe or 'unknown'}"


def controlled(tag: str) -> bool:
    return tag in LEGACY_TIER_TAGS or tag.startswith(NAMESPACE) or tag in (UMBRELLA, GUARDED)


def is_restriction(tag: str) -> bool:
    return tag in RESTRICTION_TAGS


def expected_tags(source_tags, principal: str, slot_badge: str | None = None) -> set:
    want = {UMBRELLA, owner_tag(principal)}
    if slot_badge is not None:
        want.add(slot_badge)
    want |= {t for t in set(source_tags) if is_restriction(t)}
    return want


def stamp(io: TagIO, source_tags, principal: str, slot_badge: str | None = None) -> set:
    """Make the child's controlled tags exactly `expected_tags`, or raise.

    Add before remove: a failure in between leaves an over-badged qube that
    the caller's rollback can still find, never an umbrella-less one it
    cannot.
    """
    want = expected_tags(source_tags, principal, slot_badge)
    have = set(io.read())
    for tag in sorted(want - have):
        io.add(tag)
    for tag in sorted(t for t in have - want if controlled(t) and not is_restriction(t)):
        io.remove(tag)
    final = set(io.read())
    missing = want - final
    if missing:
        raise RuntimeError(f"birth stamp incomplete: missing {sorted(missing)}")
    extra = {t for t in final - want if controlled(t)}
    if extra:
        raise RuntimeError(f"birth stamp carries unexpected tags: {sorted(extra)}")
    return want


# ----------------------------------------------------------------- network

def _name(value):
    if value is None:
        return None
    return str(getattr(value, "name", value))


def resolve_egress(app, caller_vm, source_vm, source_authoritative: bool,
                   path: str | None = None, registry_path: str | None = None):
    """(netvm name or None, rule). Branch on the RULE: `unresolved` means
    refuse; `source-offline` is a resolved answer of "no network". Every
    network answer is an enrolled gateway, judged from the registry file alone."""
    enrolled = gateways.enrolled_names(registry_path)

    if source_authoritative:
        # A clone source or a disposable template answers for itself, "none"
        # included; a network that is not enrolled is refused rather than
        # re-homed. A TemplateVM base never gets here: its netvm is an update
        # path, so a template's netvm must not decide a child's network
        # (v0.9.16's code let it, against its own documentation).
        try:
            src = _name(source_vm.netvm)
        except Exception:
            return None, "unresolved"
        if src is None:
            return None, "source-offline"
        return (src, "source") if src in enrolled else (None, "unresolved")

    try:
        own = _name(caller_vm.netvm) if caller_vm is not None else None
    except Exception:
        # A failed read is not "no network of its own": refuse rather than
        # fall through to the configured one.
        return None, "unresolved"
    if own and own in enrolled:
        return own, "principal"

    configured = read_birth_egress(path)
    if configured and configured in enrolled:
        return configured, "configured"
    return None, "unresolved"


def read_birth_egress(path: str | None = None) -> str:
    try:
        with open(BIRTH_EGRESS_PATH if path is None else path, encoding="utf-8") as fh:
            return fh.read(256).split("#", 1)[0].strip()
    except OSError:
        return ""
