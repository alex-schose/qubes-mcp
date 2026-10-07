"""qmcp.core — the shared, fail-closed check every qmcp.* service runs.

Identity is qrexec's: the caller is `QREXEC_REMOTE_DOMAIN`, set by dom0's
qrexec daemon, and nothing sits between a principal and this code. Two kinds
of principal call the services:

- the HUB, named in `/etc/qmcp/hub`. It operates every managed qube.
- a LEAD, named in a project record (`qmcp.projects`) and wearing that slot's
  lead badges. Both must agree, or the caller is no principal. A lead
  operates its own project's members and references its approved templates.

A qube is in AI space when it carries the umbrella tag `ai-managed`. Inside AI
space it is MANAGED (operable by its principal, templates included for the
hub) or GUARDED (`qmcp-guarded`, or a gateway: listed, read and referenced,
never operated). Everything a principal may not see answers exactly like a
qube that does not exist, at the same cost.

Every check here fails closed. A read of a qube that fails is never an
answer: `tags_of`, `is_gateway` and the readers beside them raise
`Unreadable`, and each decision turns that into its restrictive answer
(refused, guarded, in use). `tags_of` raises `Gone`, a kind of `Unreadable`,
when qubesd says the qube no longer exists. A property read cannot tell that
apart from a failed read: qubesadmin turns the answer into its property-access
error. `lookup` and the by-name checks answer None or False instead, which
`_resolve` and `_resolve_member` refuse. qubesadmin's property errors are
AttributeErrors, so a property is never read with a default (`getattr(vm, "x",
default)` would return the default for a failed read);
`tests/test_strict_reads.py` refuses the pattern. A missing hub
file means no caller is the hub, an unreadable project record means no caller
is a lead, and a missing runtime directory refuses the call.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import sys

from qmcp import projects

UMBRELLA = "ai-managed"
GUARDED = "qmcp-guarded"

#: A value that could not be read, where one is shown: never a qube name or a
#: state, so nothing that reads it can take it for none.
UNREADABLE = "<unreadable>"

HUB_PATH = "/etc/qmcp/hub"
RUN_DIR = "/run/qmcp"

#: Requests larger than this are refused before they are parsed.
MAX_REQUEST_BYTES = 64 * 1024
#: Concurrent qmcp.* calls the hub may hold open in dom0.
MAX_CONCURRENT_CALLS = 8
#: Concurrent calls one lead may hold, and all leads together. The leads' pool
#: is separate from the hub's slots, so no lead can lock the hub out. Measured
#: on Qubes 4.3.1: a call costs dom0 about 14 MiB, so the worst case of
#: 8 + 16 calls stays near 330 MiB.
LEAD_CALLS = 4
LEADS_POOL = 16
LEADS_POOL_KEY = "@leads"

#: A Qubes qube name. Used on everything that becomes a lookup, so a name that
#: could not exist is refused without asking qubesd about it.
_QUBE_NAME_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9_.-]{0,30}\Z")

NOT_FOUND = {"ok": False, "error": "not found"}
GUARDED_REFUSAL = {"ok": False, "error": "guarded: reference only"}
NOT_AUTHORIZED = {"ok": False, "error": "caller is not a qmcp principal"}


class Unreadable(Exception):
    """A read of a qube that failed. Never an answer: each caller turns it into
    its restrictive one."""


class Gone(Unreadable):
    """qubesd says the qube no longer exists (qubesadmin's
    QubesVMNotFoundError, a KeyError): one removed after the domain list was
    read, which disposables often are. A loop over the fleet may skip it: it
    holds no disk and wears no badge. A decision about that qube refuses."""


class Refusal(Exception):
    """A response to send instead of doing the operation."""

    def __init__(self, payload: dict, error_class: str | None = None) -> None:
        super().__init__(payload.get("error"))
        self.payload = payload
        self.error_class = error_class


def refuse(error: str) -> Refusal:
    return Refusal({"ok": False, "error": error})


def valid_qube_name(name) -> bool:
    return isinstance(name, str) and _QUBE_NAME_RE.match(name) is not None


# --------------------------------------------------------------- the caller

def caller(environ=None) -> str:
    """The calling qube, as qrexec's daemon reports it."""
    env = os.environ if environ is None else environ
    name = env.get("QREXEC_REMOTE_DOMAIN", "")
    if not valid_qube_name(name):
        raise Refusal(NOT_AUTHORIZED)
    return name


def read_hub(path: str | None = None) -> str | None:
    """The hub's name from the operator file, or None.

    Written once by the installer: which qube is the hub is fixed at install. Absent, empty or malformed means there is no hub, so every
    call is refused rather than any caller being trusted.
    """
    try:
        with open(HUB_PATH if path is None else path, encoding="utf-8") as fh:
            word = fh.read(256).split("#", 1)[0].strip()
    except OSError:
        return None
    return word if valid_qube_name(word) else None


class Principal:
    """Who is calling: the hub, or a lead with its project record."""

    __slots__ = ("name", "kind", "project")

    def __init__(self, name: str, kind: str, project=None) -> None:
        self.name, self.kind, self.project = name, kind, project

    @property
    def slot(self):
        return None if self.project is None else self.project.slot

    def is_hub(self) -> bool:
        return self.kind == "hub"

    def __repr__(self):
        return f"<Principal {self.kind} {self.name}>"


def lead_badges_agree(tags, slot: str) -> bool:
    """A lead wears the umbrella, `qmcp-lead` and exactly its own slot's lead
    badge, no member badge and no model badge, and is not guarded."""
    tags = set(tags)
    return (UMBRELLA in tags and projects.LEAD in tags and GUARDED not in tags
            and projects.lead_slots(tags) == {slot} and not projects.member_slots(tags)
            and not projects.model_slots(tags))


def principal(app, caller_name: str, hub: str | None = None) -> Principal:
    """The caller as a principal, or NOT_AUTHORIZED.

    The hub is recognised from its file, at no qubesd cost. A lead must be
    named as the lead of a project in the record file AND wear that slot's
    lead badges, read with one qubesd call. A record without the badges, or
    badges without a record, is no principal: the record says what a slot
    may do, and the badges are what the rulebook routes on.
    """
    if hub is None:
        hub = read_hub()
    if hub is not None and caller_name == hub:
        return Principal(caller_name, "hub")
    try:
        records = projects.load()
    except projects.ProjectsUnreadable:
        raise Refusal(NOT_AUTHORIZED) from None
    project = projects.by_lead(records, caller_name)
    if project is None or project.slot == projects.HUB_SLOT:
        raise Refusal(NOT_AUTHORIZED)
    try:
        raw = app.qubesd_call(caller_name, "admin.vm.tag.List")
        tags = set(raw.decode(errors="replace").split())
    except Exception:
        raise Refusal(NOT_AUTHORIZED) from None
    if not lead_badges_agree(tags, project.slot):
        raise Refusal(NOT_AUTHORIZED)
    return Principal(caller_name, "lead", project)


# ------------------------------------------------------------------ the caps

def read_request(stream, limit: int | None = None) -> dict:
    """Read and parse one JSON request object, at most `limit` bytes.

    The cap is checked on the raw bytes before json.loads runs, so an
    oversized payload costs dom0 one bounded read and nothing more. The
    refusal text never echoes the payload or the parser's message.
    """
    limit = MAX_REQUEST_BYTES if limit is None else limit
    raw = getattr(stream, "buffer", stream).read(limit + 1)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if len(raw) > limit:
        raise refuse("request too large")
    if not raw.strip():
        return {}
    try:
        obj = json.loads(raw)
    except ValueError:
        raise refuse("invalid JSON input") from None
    if not isinstance(obj, dict):
        raise refuse("request must be a JSON object")
    return obj


def acquire_call_slot(caller_name: str, run_dir: str | None = None,
                      limit: int | None = None) -> int:
    """Take one of the caller's `limit` concurrency slots, or refuse.

    Each qrexec call is its own dom0 process, so the slot is an flock on one
    of `limit` files; the kernel releases it when this process exits. Fails
    closed: without the runtime directory there is no limit to enforce, and
    that is reported rather than skipped. The leads' shared pool uses the
    same mechanism under `LEADS_POOL_KEY`, which no qube name can equal.
    """
    base = os.path.join(RUN_DIR if run_dir is None else run_dir, "calls")
    for i in range(MAX_CONCURRENT_CALLS if limit is None else limit):
        path = os.path.join(base, f"{caller_name}.{i}")
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o660)
        except OSError:
            raise refuse("qmcp runtime directory unavailable") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError:
            os.close(fd)
    raise refuse("too many concurrent calls")


# ------------------------------------------------------------------ the states

def tags_of(vm) -> set:
    """A qube's tags, one qubesd read. Raises `Unreadable`: tags that could
    not be read are not "no tags", which would read as outside AI space,
    unguarded and wearing no badge."""
    try:
        return set(vm.tags)
    except KeyError:
        raise Gone(f"{name_of(vm)} no longer exists") from None
    except Exception:
        raise Unreadable(f"cannot read the tags of {name_of(vm)}") from None


def name_of(vm) -> str:
    """A qube's name, for messages. qubesadmin keeps it on the object (its
    `name` property returns the name it was made with), so it is no qubesd
    read."""
    try:
        return str(vm.name)
    except Exception:
        return "?"


def in_scope(vm) -> bool:
    return UMBRELLA in tags_of(vm)


def klass_of(vm) -> str:
    try:
        return vm.klass
    except Exception:
        raise Unreadable(f"cannot read the class of {name_of(vm)}") from None


#: Classes without a network (Qubes' NetVMMixin): no `netvm`, no
#: `provides_network`, no `default_dispvm` either for a RemoteVM.
NO_NETWORK_CLASSES = frozenset({"AdminVM", "RemoteVM"})


def is_gateway(vm) -> bool:
    """A qube that provides network. Raises `Unreadable` when that cannot be
    read: the caller decides which answer is the restrictive one. dom0 and a
    RemoteVM have no such property and are no gateway."""
    if klass_of(vm) in NO_NETWORK_CLASSES:
        return False
    try:
        return bool(vm.provides_network)
    except Exception:
        raise Unreadable(f"cannot read whether {name_of(vm)} provides network") from None


def is_dvmt(vm) -> bool:
    """A disposable template. Only an AppVM or a StandaloneVM can be one; for
    those the flag is read, and a failed read raises `Unreadable`."""
    if klass_of(vm) not in ("AppVM", "StandaloneVM"):
        return False
    try:
        return bool(vm.template_for_dispvms)
    except Exception:
        raise Unreadable(f"cannot read whether {name_of(vm)} is a disposable template") from None


def is_template(vm) -> bool:
    """A TemplateVM or a disposable template. Raises `Unreadable`."""
    return klass_of(vm) == "TemplateVM" or is_dvmt(vm)


def template_of(vm):
    """The qube's template (a disposable's is its disposable template), or None
    for a class that has none. Raises `Unreadable`."""
    if klass_of(vm) not in ("AppVM", "DispVM"):
        return None
    try:
        return vm.template
    except Exception:
        raise Unreadable(f"cannot read the template of {name_of(vm)}") from None


def default_dispvm_of(vm):
    """The qube's default disposable template, or None. Every local class has
    the property, so a failed read is never an absence: it raises
    `Unreadable`. A RemoteVM has none."""
    if klass_of(vm) == "RemoteVM":
        return None
    try:
        return vm.default_dispvm
    except Exception:
        raise Unreadable(f"cannot read the default disposable template of {name_of(vm)}") from None


def is_guarded(vm, tags=None) -> bool:
    """Guarded = badged by the operator, or a gateway (always guarded). A read
    that fails counts as guarded, so it never makes a qube operable."""
    try:
        return GUARDED in (tags_of(vm) if tags is None else tags) or is_gateway(vm)
    except Unreadable:
        return True


def state(vm) -> str | None:
    """'managed', 'guarded', or None for anything outside AI space, from one
    tag read. Raises `Unreadable` when the tags cannot be read; a qube whose
    network role cannot be read is guarded."""
    tags = tags_of(vm)
    if UMBRELLA not in tags:
        return None
    return "guarded" if is_guarded(vm, tags) else "managed"


def lookup(app, name):
    """The qube called `name`, or None. Never raises."""
    if not valid_qube_name(name):
        return None
    try:
        if name not in app.domains:
            return None
        return app.domains[name]
    except Exception:
        return None


def in_ai_space_by_name(app, name) -> bool:
    """Is the qube called `name` in AI space? One qubesd round trip either way.

    A qube outside AI space must cost exactly what a missing one costs, or the
    response time says which names exist. Answering a missing
    name from the domain list and an existing one with a tag read was measured
    on 2026-10-01 at ~0.7 ms apart. `admin.vm.tag.Get` answers "1"/"0" for a
    qube and fails for a missing one, after the same single call.
    """
    if not valid_qube_name(name):
        return False
    try:
        return app.qubesd_call(name, "admin.vm.tag.Get", UMBRELLA).strip() == b"1"
    except Exception:
        return False


def _resolve(app, name, refusal: "Refusal"):
    """The VM object for `name`, which must be in AI space, else `refusal`.

    The by-name check decides; the object is fetched only for a qube already
    known to be in AI space, and re-checked, since its tags may have changed
    in between.
    """
    if not in_ai_space_by_name(app, name):
        raise refusal
    vm = lookup(app, name)
    try:
        if vm is None or not in_scope(vm):
            raise refusal
    except Unreadable:
        raise refusal from None
    return vm


def is_member(vm, slot: str) -> bool:
    """In AI space, wearing `slot`'s member badge, and not a lead. Raises
    `Unreadable`."""
    tags = tags_of(vm)
    return (UMBRELLA in tags and projects.member_badge(slot) in tags
            and projects.LEAD not in tags)


def member_by_name(app, name, slot: str) -> bool:
    """Is the qube called `name` a member of `slot`? One qubesd round trip
    either way, for the same reason as `in_ai_space_by_name`: a lead must not
    tell a qube of another project, or of the hub, from a missing name."""
    if not valid_qube_name(name):
        return False
    try:
        return app.qubesd_call(name, "admin.vm.tag.Get",
                               projects.member_badge(slot)).strip() == b"1"
    except Exception:
        return False


def _resolve_member(app, name, slot: str, refusal: "Refusal"):
    if not member_by_name(app, name, slot):
        raise refusal
    vm = lookup(app, name)
    try:
        if vm is None or not is_member(vm, slot):
            raise refusal
    except Unreadable:
        raise refusal from None
    return vm


def visible(vm, who: "Principal | None", tags=None) -> bool:
    """May `who` see this qube in a list, a read or a reference? `tags`, when
    the caller read them already.

    The hub sees AI space. A lead sees its members, its approved templates and
    its worker networks, all inside AI space. A qube whose tags cannot be read
    is not seen."""
    if tags is None:
        try:
            tags = tags_of(vm)
        except Unreadable:
            return False
    if UMBRELLA not in tags:
        return False
    if who is None or who.is_hub():
        return True
    p = who.project
    name = name_of(vm)
    return (projects.member_badge(p.slot) in tags and projects.LEAD not in tags) \
        or name in p.templates or name in p.named_networks()


def operand(app, name, who: Principal):
    """A qube the caller is about to operate: it must be managed, and for a
    lead, a member of its project.

    Missing and out of scope collapse to one answer, in content and in cost,
    so this is no existence oracle. The caller is never its own object: the
    hub is never in AI space and a lead is never a member, so that refusal
    fires only on a misconfigured fleet, which `qmcp check` reports. A guarded
    qube gets its own refusal: it is already visible in the list, so saying
    why costs nothing.
    """
    if who.is_hub():
        vm = _resolve(app, name, Refusal(NOT_FOUND))
    else:
        vm = _resolve_member(app, name, who.slot, Refusal(NOT_FOUND))
    if name == who.name:
        raise Refusal(NOT_FOUND)
    if is_guarded(vm):
        raise Refusal(GUARDED_REFUSAL)
    return vm


def readable(app, name, who: Principal):
    """A qube the caller reads: for the hub, managed or guarded; for a lead, a
    member, or one of its approved templates or worker networks (names it
    already knows, so looking them up reveals nothing)."""
    if who.is_hub():
        return _resolve(app, name, Refusal(NOT_FOUND))
    p = who.project
    if name in p.templates or name in p.named_networks():
        return _resolve(app, name, Refusal(NOT_FOUND))
    return _resolve_member(app, name, p.slot, Refusal(NOT_FOUND))


def reference(app, name, what: str, who: Principal):
    """A qube used only as a reference (a template, a disposable template).

    Managed or guarded both qualify. A lead may reference only the templates
    on its project's approved list, decided on the list alone, before any
    lookup. The refusal never echoes the name, so a create is no oracle over
    names outside AI space.
    """
    if not who.is_hub() and name not in who.project.templates:
        raise refuse(f"{what} is not on this project's approved list")
    return _resolve(app, name, refuse(f"{what} must reference an ai-managed qube"))


# ------------------------------------------------------------------ the funnel

class Call:
    """One invocation: what the audit line will say about it."""

    __slots__ = ("service", "caller", "principal", "summary", "error_class", "fds")

    def __init__(self, service: str) -> None:
        self.service = service
        self.caller = None
        self.principal = None
        #: Lock descriptors (call slot, create lock) closed after the reply.
        #: A service process would release them on exit anyway; closing them
        #: explicitly keeps the library correct for a long-lived caller.
        self.fds: list = []
        #: Built field by field from parsed request values (names, keys,
        #: actions) and never from the raw request, so a property or feature
        #: VALUE cannot reach the log by omission.
        self.summary: dict = {}
        self.error_class = None


def emit(call: Call, payload: dict, audit: bool, out=None) -> int:
    """The single response funnel: one audit line, one JSON reply.

    Auditing is best-effort — it can never change what the caller sees or
    whether the operation ran. Only state-changing services audit.
    """
    if audit:
        try:
            from qmcp import audit as audit_mod
            audit_mod.audit(call.service, call.caller, call.summary,
                            bool(payload.get("ok")), payload.get("error"),
                            error_class=call.error_class)
        except Exception:
            pass
    stream = sys.stdout if out is None else out
    stream.write(json.dumps(payload) + "\n")
    stream.flush()
    return 0 if payload.get("ok") else 1
