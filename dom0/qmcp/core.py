"""qmcp.core — the shared, fail-closed check every qmcp.* service runs.

Identity is qrexec's: the caller is `QREXEC_REMOTE_DOMAIN`, set by dom0's
qrexec daemon, and nothing sits between a principal and this code. In this
release the only principal is the hub, named in `/etc/qmcp/hub`; projects and
their leads arrive in M2.

A qube is in AI space when it carries the umbrella tag `ai-managed`. Inside AI
space it is MANAGED (the hub may operate it, templates included) or GUARDED
(`qmcp-guarded`, or a gateway: listed, read and referenced, never operated).
Everything outside AI space answers exactly like a qube that does not exist.

Every check here fails closed. An unreadable tag set is out of scope, an
unreadable `provides_network` is guarded, a missing hub file means no caller
is the hub, and a missing runtime directory refuses the call.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import sys

UMBRELLA = "ai-managed"
GUARDED = "qmcp-guarded"

HUB_PATH = "/etc/qmcp/hub"
RUN_DIR = "/run/qmcp"

#: Requests larger than this are refused before they are parsed.
MAX_REQUEST_BYTES = 64 * 1024
#: Concurrent qmcp.* calls one caller may hold open in dom0.
MAX_CONCURRENT_CALLS = 8

#: A Qubes qube name. Used on everything that becomes a lookup, so a name that
#: could not exist is refused without asking qubesd about it.
_QUBE_NAME_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9_.-]{0,30}\Z")

NOT_FOUND = {"ok": False, "error": "not found"}
GUARDED_REFUSAL = {"ok": False, "error": "guarded: reference only"}
NOT_AUTHORIZED = {"ok": False, "error": "caller is not a qmcp principal"}


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


def role(caller_name: str, hub_path: str | None = None) -> str:
    """The caller's role. In this release only the hub has one."""
    hub = read_hub(hub_path)
    if hub is not None and caller_name == hub:
        return "hub"
    raise Refusal(NOT_AUTHORIZED)


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
    that is reported rather than skipped.
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
    try:
        return set(vm.tags)
    except Exception:
        return set()


def in_scope(vm) -> bool:
    return UMBRELLA in tags_of(vm)


def is_gateway(vm) -> bool:
    """A qube that provides network. Unreadable counts as yes."""
    try:
        return bool(getattr(vm, "provides_network", False))
    except Exception:
        return True


def is_guarded(vm) -> bool:
    """Guarded = badged by the operator, or a gateway (always guarded)."""
    return GUARDED in tags_of(vm) or is_gateway(vm)


def state(vm) -> str | None:
    """'managed', 'guarded', or None for anything outside AI space."""
    if not in_scope(vm):
        return None
    return "guarded" if is_guarded(vm) else "managed"


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
    if vm is None or not in_scope(vm):
        raise refusal
    return vm


def operand(app, name, caller_name: str):
    """A qube the caller is about to operate: it must be managed.

    Missing and out of scope collapse to one answer, in content and in cost,
    so this is no existence oracle. The caller is never its own object: the hub is never in AI space, so in this release that refusal
    fires only on a misconfigured fleet, and `qmcp check` reports that fleet.
    A guarded qube gets its own refusal: it is already visible in the list, so
    saying why costs nothing.
    """
    vm = _resolve(app, name, Refusal(NOT_FOUND))
    if name == caller_name:
        raise Refusal(NOT_FOUND)
    if is_guarded(vm):
        raise Refusal(GUARDED_REFUSAL)
    return vm


def readable(app, name):
    """A qube the caller reads: managed or guarded."""
    return _resolve(app, name, Refusal(NOT_FOUND))


def reference(app, name, what: str):
    """A qube used only as a reference (a template, a disposable template).

    Managed or guarded both qualify. The refusal never echoes the name, so a
    create is no oracle over names outside AI space.
    """
    return _resolve(app, name, refuse(f"{what} must reference an ai-managed qube"))


# ------------------------------------------------------------------ the funnel

class Call:
    """One invocation: what the audit line will say about it."""

    __slots__ = ("service", "caller", "summary", "error_class", "fds")

    def __init__(self, service: str) -> None:
        self.service = service
        self.caller = None
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
