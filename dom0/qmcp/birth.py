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

**Strip on create.** `admin.vm.CreateDisposable`, and qubesd's create of a
named DispVM, give the new qube its disposable template's tags, so a created
qube must not be assumed clean. `stamp()` adds what the child must carry —
the umbrella, a provenance badge and, for a workload, its slot badge (a
spawn's is its creator's, a clone's its source's) — carries the platform's
Whonix marker forward, removes every other tag in our controlled vocabulary
(`qmcp-guarded` included: a child spawned from a guarded template is managed;
every role and slot badge, so a clone of a lead is no lead; and v0.9.16's
`qmcp-egress-locked_*`, which nothing reads since no network moves), and then
reads the tags back and asserts the exact result, both ways. The caller rolls
the qube back if it raises. Tags outside our vocabulary (the operator's own,
`created-by-*`) are left alone.

**A copy is built in dom0's own order** (`create_copy`, then `fill_copy`):
a clone, a standalone made from a template, and a lead cloned from one of the
hub's qubes. qubesadmin's `clone_vm`, which `qvm-clone` and `qvm-create
--standalone -t T` run, creates the qube, copies its source's properties, then
its tags one by one in the sorted order qubesd lists them (source-read), so
`ai-managed` lands before `qmcp-anon` and `qmcp-hubblind`, then features and
volumes, which took seconds for a standalone (5.6 s measured on Qubes 4.3.1,
2026-10-10). A hidden project's member's clone was thus in AI space without
`qmcp-hubblind` for a moment, and a standalone made from a template the
project's badges are not on would have been, through `clone_vm`, for those
seconds. So dom0 creates the qube with none of the source's tags, copies
properties, features, notes, the operator's tags and the volumes into it, and
only then labels and stamps it: the stamp is the first moment the qube is in
AI space, and its restricting badges go on first. (A named DispVM's clone is
the exception: qubesd gives it its disposable template's tags in the create
call itself.) A standalone made from a template takes the template's features,
as `qvm-create --standalone` does, the template's own values of the
properties an AppVM follows from its template (`TEMPLATE_PROPS`), and a copy
of its root, in the template root's pool; its private volume is new. It takes
none of the template's tags, firewall rules or device assignments: its stamp
then carries `anon-vm` from the template (an AppVM on a Whonix template also
gets what Whonix's addon puts on it; a standalone does not). A clone takes what
`clone_vm` copies, keeping each volume's pool, but device assignments, menu
entries and a disposable template's `preload-dispvm*`.

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
    except (OSError, UnicodeDecodeError):
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


#: The restore check's hold (`core.QUARANTINE`), named here because birth
#: cannot import core.
HELD = "qmcp-quarantine"


def controlled(tag: str) -> bool:
    return tag in LEGACY_TIER_TAGS or tag.startswith(NAMESPACE) or tag in (UMBRELLA, GUARDED)


def is_restriction(tag: str) -> bool:
    return tag in RESTRICTION_TAGS


#: Tags Qubes itself keeps on every qube, from its creator or from its own
#: properties: a fresh qube already has its own, so these are never copied.
QUBES_TAG_PREFIXES = ("created-by-", "audiovm-", "guivm-", "relayvm-")

#: The properties an AppVM follows from its template while it has none of its
#: own (Qubes' `_default_with_template`, and `virt_mode` and `kernelopts`,
#: whose defaults read the template too), but `bootmode`, which an AppVM takes
#: from the template's `appvm_default_bootmode`. A standalone made from a template
#: takes the template's own values of these, so it boots as an AppVM of it would.
TEMPLATE_PROPS = ("kernel", "kernelopts", "virt_mode", "memory", "maxmem", "vcpus",
                  "default_user", "qrexec_timeout", "shutdown_timeout", "management_dispvm")
#: What a clone never copies from its source: its identity, and what the create
#: itself sets (`clone_vm` leaves out the same).
NOT_COPIED = frozenset({"name", "qid", "uuid", "label", "template", "installed_by_rpm"})
#: The volumes a copy can take: those its source keeps across a restart.
VOLUMES = ("root", "private")


def operators(tag: str) -> bool:
    """A tag that is the operator's own: not ours, no restriction, and none
    that Qubes keeps itself."""
    return not controlled(tag) and not is_restriction(tag) \
        and not tag.startswith(QUBES_TAG_PREFIXES)


def copied_volumes(source, standalone: bool) -> tuple:
    """The volumes a copy takes from `source`: a standalone made from a template
    its root alone (its private volume is new); a clone every volume its source
    keeps across a restart (`save_on_stop`), as `clone_vm` copies them: a
    template's or a standalone's root and private, an AppVM's private, nothing
    of a disposable's. Raises when a volume cannot be read."""
    if standalone:
        return ("root",)
    return tuple(v for v in VOLUMES if v in source.volumes and source.volumes[v].save_on_stop)


def create_copy(app, source, name: str, klass: str, label: str, standalone: bool = False):
    """Create the qube a copy fills, with none of its source's tags but a named
    DispVM's (below): `klass`, on the
    source's template for an AppVM or a DispVM, each copied volume in the pool
    its source's is in (as `clone_vm` keeps it). qubesd gives a named DispVM its
    disposable template's tags at create, in the one call. The caller fills it
    (`fill_copy`), then labels and stamps it, and rolls it back on any failure
    after this returns."""
    from qmcp import core
    template = core.template_of(source) if klass in ("AppVM", "DispVM") else None
    pools = {v: str(source.volumes[v].pool) for v in copied_volumes(source, standalone)}
    return app.add_new_vm(klass, name, label, template=template, pools=pools or None)


def fill_copy(app, vm, source, standalone: bool) -> None:
    """Copy `source` into the qube `create_copy` made, before it is in AI space.
    A standalone made from a template (`standalone`) takes the template's own
    values of `TEMPLATE_PROPS`, its features and its root. A clone takes every
    property the source does not leave at its default, its features, the
    operator's tags and restrictions, its firewall rules, its notes, and every
    volume the source keeps (`copied_volumes`). The `qmcp-id` label is never
    copied: the caller writes the qube's own. Raises on any failure, so the
    caller rolls the qube back."""
    from qmcp import core, firewall
    have = set(source.property_list())
    names = TEMPLATE_PROPS if standalone else sorted(have - NOT_COPIED)
    for prop in names:
        if prop not in have or source.property_is_default(prop):
            continue
        value = getattr(source, prop)
        try:
            setattr(vm, prop, value)
        except AttributeError:
            # A property the new qube's class lacks, or a write qubesd answered
            # with no reply (QubesPropertyAccessError is an AttributeError):
            # `clone_vm` skips both the same way. The read above is strict.
            continue
    for key, value in source.features.items():
        # `preload-dispvm*` is a disposable template's queue of its own
        # disposables, and its maximum would start preloading from the copy
        # while it is half-built and outside AI space; the operator sets it.
        if key == core.ID_FEATURE or key.startswith("preload-dispvm"):
            continue
        vm.features[key] = value
    if not standalone:
        for tag in sorted(t for t in core.tags_of(source) if operators(t) or is_restriction(t)):
            vm.tags.add(tag)
        firewall.restore_rules(app, vm.name, firewall.read_rules(app, source.name))
        notes = source.get_notes()
        if notes:
            vm.set_notes(notes)
    for name in copied_volumes(source, standalone):
        vm.volumes[name].clone(source.volumes[name])


def expected_tags(source_tags, principal: str, slot_badge: str | None = None,
                  extra=()) -> set:
    want = {UMBRELLA, owner_tag(principal)} | set(extra)
    if slot_badge is not None:
        want.add(slot_badge)
    want |= {t for t in set(source_tags) if is_restriction(t)}
    return want


#: Badges that take authority away, which a child gets before anything else:
#: `qmcp-hubblind` before `ai-managed`, so no moment of a hidden project's new
#: qube is open to the hub's AI-space lines.
FIRST = ("qmcp-blocked", "qmcp-hubblind", "qmcp-anon")
#: Badges that keep a caller out of a qube, which a stamp never removes.
KEEPS_OUT = frozenset({"qmcp-blocked", "qmcp-stopped", "qmcp-hubblind"})


def _add_order(tag: str) -> tuple:
    return (FIRST.index(tag), tag) if tag in FIRST else (len(FIRST), tag)


def _remove_order(tag: str) -> tuple:
    """Badges that route a caller in (a lead's, a slot's, a window's) come off
    first and `qmcp-guarded` last, so a failure between two removals leaves
    the child guarded with less, never unguarded with a routed badge."""
    return (tag == GUARDED, tag)


def stamp(io: TagIO, source_tags, principal: str, slot_badge: str | None = None,
          extra=()) -> set:
    """Make the child's controlled tags exactly `expected_tags`, or raise.
    `extra`: an anonymous project's badges, for a qube its lead creates.

    Add before remove: a failure in between leaves an over-badged qube that
    the caller's rollback can still find, never an umbrella-less one it
    cannot. The badges that take authority away go on first (`FIRST`).
    """
    want = expected_tags(source_tags, principal, slot_badge, extra)
    have = set(io.read())
    # A child already held for the operator's review (a disposable the gate
    # held before it was claimed) is never released by a create: only the
    # operator lifts a hold. Refused, so the caller rolls the child back.
    if HELD in have:
        raise RuntimeError("the new qube is held for the operator's review")
    # Nor is a badge that keeps someone out (a hidden project's, or the gate's
    # stop) ever taken off a child that arrived wearing it unasked: the
    # platform copied it from a template that was hidden or stopped after the
    # caller's checks, and stripping it would hand the caller a visible,
    # unstopped child built on that template. Refused: the caller rolls back.
    arrived = (have & KEEPS_OUT) - want
    if arrived:
        raise RuntimeError(f"the new qube arrived wearing {sorted(arrived)}")
    for tag in sorted(want - have, key=_add_order):
        io.add(tag)
    for tag in sorted((t for t in have - want if controlled(t) and not is_restriction(t)),
                      key=_remove_order):
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
    except (OSError, UnicodeDecodeError):
        return ""
