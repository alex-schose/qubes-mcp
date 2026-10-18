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
import time

from qmcp import projects

UMBRELLA = "ai-managed"
GUARDED = "qmcp-guarded"
#: The operator's open window on a guarded qube. The rulebook's A6b
#: routes on these two badges and on nothing else, because no dom0 code sees
#: the calls they open: the exec service runs INSIDE the target qube, the copy
#: is Qubes' own, and the firewall methods are qubesd's. So a badge is the
#: whole gate, dom0 takes it off when the window ends and at every boot, and
#: nothing here can consult an expiry at call time.
#: `OPEN` opens the hub's exec and its copy-in dialog, `OPEN_FW` the two
#: firewall writes; each works alone, and exec is the greater authority, so
#: `OPEN` comes off first and goes on last (`fleet._removal_order`).
#: Deliberately outside `scope.TAG_VOCABULARY`: a principal reads neither,
#: as it reads no other badge that carries authority.
OPEN = "qmcp-open"
OPEN_FW = "qmcp-open-fw"

#: A qube that came back from a backup or was copied by hand, held for the
#: operator's review (`qmcp.restored`). dom0 labels every qube it brings into AI
#: space or badges with the feature `ID_FEATURE` set to the qube's own UUID; a
#: restore and a `qvm-clone` keep the feature and give the qube a new UUID, so
#: the label stops matching. The gate's pass then puts `QUARANTINE` on it, and
#: the rulebook's A0 refuses every call into it and out of it. Like the open
#: badges it is outside `scope.TAG_VOCABULARY`.
QUARANTINE = "qmcp-quarantine"
ID_FEATURE = "qmcp-id"

#: A value that could not be read, where one is shown: never a qube name or a
#: state, so nothing that reads it can take it for none.
UNREADABLE = "<unreadable>"

HUB_PATH = "/etc/qmcp/hub"
RUN_DIR = "/run/qmcp"
#: Anonymous mode: the one word `anonymous`, written by `install.sh --anonymous`
#: and removed only by `uninstall.sh --purge`. Absent means normal mode.
MODE_PATH = "/etc/qmcp/mode"
ANONYMOUS = "anonymous"

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
BLOCKED_REFUSAL = {"ok": False, "error": "stopped by the anonymity gate"}
QUARANTINE_REFUSAL = {"ok": False, "error": "held for the operator's review"}
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
    except (OSError, UnicodeDecodeError):
        return None
    return word if valid_qube_name(word) else None


class ModeUnreadable(Exception):
    """`/etc/qmcp/mode` exists but cannot be read or does not say `anonymous`."""


def anonymous_mode(path: str | None = None) -> bool:
    """Whether this installation runs in anonymous mode: every project
    anonymous, and the hub with its own qubes under the anonymity gate.

    An absent file is normal mode, which is how an install starts. A file that
    exists but cannot be read, or says anything but `anonymous`, raises
    ModeUnreadable: each caller turns that into its restrictive answer (a
    create or an enrollment refused, the gate blocking the hub without a
    kill), never into normal mode.
    """
    try:
        with open(MODE_PATH if path is None else path, encoding="utf-8") as fh:
            word = fh.read(256).split("#", 1)[0].strip()
    except FileNotFoundError:
        return False
    except (OSError, UnicodeDecodeError):
        raise ModeUnreadable(f"{MODE_PATH if path is None else path} cannot be read") from None
    if word != ANONYMOUS:
        raise ModeUnreadable(f"{MODE_PATH if path is None else path} does not hold the one "
                             f"word '{ANONYMOUS}'")
    return True


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
    badge, no member badge and no model badge, and is not guarded. A lead the
    anonymity gate stopped (`qmcp-blocked`) is no principal: the operator may
    start it by hand to look at it, and it acts on nothing. Nor is one held for
    the operator's review (`qmcp-quarantine`): a lead restored from a backup is
    a lead again only once the operator accepts it."""
    tags = set(tags)
    return (UMBRELLA in tags and projects.LEAD in tags and GUARDED not in tags
            and projects.BLOCKED not in tags and QUARANTINE not in tags
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
        # The rulebook refuses a blocked hub every call (anonymous mode stops
        # the hub), and a held one (a hub in anonymous mode wears qmcp-anon, so
        # a hub restored from a backup is held for review); the services refuse
        # both too, as they refuse a blocked or held lead. One read of its tags.
        try:
            raw = app.qubesd_call(caller_name, "admin.vm.tag.List")
            stopped = bool({projects.BLOCKED, QUARANTINE}
                           & set(raw.decode(errors="replace").split()))
        except Exception:
            stopped = True
        if stopped:
            raise Refusal(NOT_AUTHORIZED)
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
        # A slot file removed while this call held it open (`retire_caller`)
        # is a slot no other call can see: opened again, the one at the path.
        for _ in range(3):
            try:
                fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o660)
            except OSError:
                raise refuse("qmcp runtime directory unavailable") from None
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                break
            if _is_current(fd, path):
                return fd
            os.close(fd)
    raise refuse("too many concurrent calls")


#: The per-qube lock: a service that operates a qube holds it from its check
#: to its effect, and so do the commands `fleet._with_qube_lock` serves and the
#: restore check's, so a call already past its check lands before such a
#: command acts, unless the command went on without the lock.
QUBE_LOCK_SUBDIR = "qubes"
#: How long a service waits for a qube's lock before it refuses.
QUBE_WAIT_S = 30.0
#: How long an operator command waits. One that takes authority away goes on
#: without the lock after this (and guard, revoke and seal wait again after).
OPERATOR_WAIT_S = 60.0
BUSY_REFUSAL = {"ok": False, "error": "busy: the qube is being changed; try again"}


class QubeBusy(Exception):
    """A qube's lock was held past the wait."""


def qube_lock_path(name: str, run_dir: str | None = None) -> str:
    return os.path.join(RUN_DIR if run_dir is None else run_dir, QUBE_LOCK_SUBDIR,
                        f"{name}.lock")


def queue_path(lock_path: str) -> str:
    """The turnstile beside a lock file: a qube's or the create lock's
    `x.lock` -> `x.queue`; any other lock (a caller's acting lock) gets
    `.queue` appended. A turnstile always ends in `.queue` and a lock never
    does, so no name can make one file the other's."""
    return lock_path[:-len(".lock")] + ".queue" if lock_path.endswith(".lock") \
        else lock_path + ".queue"


def _open_lock_file(path: str) -> int:
    """Open (creating it group-writable) a lock file the services and the
    operator's commands share. Raises OSError."""
    old = os.umask(0o007)
    try:
        return os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o660)
    finally:
        os.umask(old)


def _wait_flock(fd: int, deadline: float, step: float, mode: int = fcntl.LOCK_EX) -> bool:
    while True:
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(step)


def _is_current(fd: int, path: str) -> bool:
    """Whether the open file `fd` is still the one at `path`. A lock file may
    be removed (`retire_caller`, under its lock): a taker that locked the
    removed file holds a lock no later taker can see, so it opens the path
    again. Removal and this check are both made under the lock, so a taker
    that found its file current keeps it until it lets go."""
    try:
        a, b = os.fstat(fd), os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _take_current(path: str, deadline: float, step: float, mode: int) -> int | None:
    """The lock on the file at `path` as it is once had: its descriptor, or
    None past `deadline`. Raises OSError when it cannot be opened."""
    while True:
        fd = _open_lock_file(path)
        if not _wait_flock(fd, deadline, step, mode):
            os.close(fd)
            return None
        if _is_current(fd, path):
            return fd
        os.close(fd)
        if time.monotonic() >= deadline:
            return None


def take_queued_lock(path: str, timeout: float, step: float, queue: bool,
                     mode: int = fcntl.LOCK_EX) -> int | None:
    """A lock taken through its turnstile (`queue_path`): its descriptor, or
    None when it was not had within `timeout`. Raises OSError when a file
    cannot be opened.

    flock is not fair, so a caller that keeps calls in flight could hold a
    lock off the operator for as long as it liked. The turnstile ends that:
    every taker passes through it first, and a `queue` taker (an operator's
    command, the restore check) keeps it while it waits for the lock, so a
    call that arrives after it waits behind it; a call already past the
    turnstile goes first, and there are at most as many of those as the
    callers that reach the qube have slots. A service passes straight through: it never holds the
    turnstile while it waits, so services never queue behind each other.
    `mode`: the lock itself is taken shared (`fcntl.LOCK_SH`) by the calls
    that hold a caller's acting lock, and exclusively by everyone else. A
    file removed while it was waited on is opened again (`_take_current`)."""
    deadline = time.monotonic() + timeout
    qfd = _take_current(queue_path(path), deadline, step, fcntl.LOCK_EX)
    if qfd is None:
        return None
    try:
        if not queue:
            os.close(qfd)
            qfd = None
        return _take_current(path, deadline, step, mode)
    finally:
        if qfd is not None:
            os.close(qfd)


def acquire_qube_lock(name: str, timeout: float | None = None,
                      queue: bool = False) -> int | None:
    """The lock of the qube `name`: its descriptor, or None when it was held
    past `timeout`. Released when the descriptor is closed, or the process
    exits. `queue`: an operator's command, which waits in the qube's
    turnstile, so calls arriving after it wait behind it (`take_queued_lock`).

    Taken only on a qube the caller may already see: a service resolves the
    qube first and checks again under the lock, so a name outside its reach
    never waits on a lock an operator command holds, and contention is no
    oracle over names. The services (a non-root dom0 user in `qubes`) and the
    operator's commands (root) share the files, so each is made group-writable
    in the setgid directory tmpfiles declares; the directory is made here too
    when it is missing. Raises `Refusal` when the lock cannot be opened at
    all: a lock that cannot be opened never lets a service, or a command that
    grants authority, go on."""
    if not valid_qube_name(name):
        raise Refusal(NOT_FOUND)
    path = qube_lock_path(name)
    old = os.umask(0o007)
    try:
        os.mkdir(os.path.dirname(path), 0o2770)
    except FileExistsError:
        pass
    except OSError:
        raise refuse("qmcp runtime directory unavailable") from None
    finally:
        os.umask(old)
    try:
        return take_queued_lock(path, QUBE_WAIT_S if timeout is None else timeout, 0.05, queue)
    except OSError:
        raise refuse("qmcp runtime directory unavailable") from None


def acting_lock_path(caller: str, run_dir: str | None = None) -> str:
    """The caller's acting lock, beside its call slots (`<caller>.<i>`), so
    no name makes one file the other; its turnstile is `<caller>.acting.queue`."""
    return os.path.join(RUN_DIR if run_dir is None else run_dir, "calls", f"{caller}.acting")


def hold_acting(caller: str, timeout: float | None = None) -> int:
    """The caller's acting lock, shared: every call that changes a qube
    holds it from the moment its caller is checked again under a qube's lock or the create lock to its
    reply, so a call is either checked after a command that takes the
    caller's authority away (and refused), or finished before that command
    goes on (`drain_caller`). Through the lock's turnstile, so a caller cannot
    keep its acting lock held by overlapping its own calls: once a drain waits,
    each new call waits behind it. Raises `Refusal`: busy when it was not had
    within `timeout`, the runtime directory when it cannot be opened."""
    try:
        fd = take_queued_lock(acting_lock_path(caller),
                              QUBE_WAIT_S if timeout is None else timeout, 0.05, False,
                              fcntl.LOCK_SH)
    except OSError:
        raise refuse("qmcp runtime directory unavailable") from None
    if fd is None:
        raise Refusal(BUSY_REFUSAL)
    return fd


def drain_caller(caller: str, timeout: float | None = None) -> int | None:
    """The caller's acting lock, exclusive, for a command that takes the
    caller's authority away: it waits for every call of the caller already
    past its check, and while it holds the lock, a call reaching its check
    waits and is then checked against what the command left. The descriptor,
    or None when a call still held it after `timeout`. It waits in the lock's
    turnstile, so only the calls already past it hold it off. Raises OSError
    when the lock cannot be opened."""
    return take_queued_lock(acting_lock_path(caller),
                            OPERATOR_WAIT_S if timeout is None else timeout, 0.05, True)


def _remove_if_free(path: str) -> str | None:
    """Remove the lock file at `path` under its own lock, exclusive, taken
    without waiting: None when it is gone, or the reason it was left. Never
    made where it is missing."""
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"not opened ({type(e).__name__})"
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return "a call still held it"
        if not _is_current(fd, path):
            return None                 # removed meanwhile
        os.unlink(path)
        return None
    except OSError as e:
        return f"not removed ({type(e).__name__})"
    finally:
        os.close(fd)


def retire_caller(caller: str, acting_fd: int, run_dir: str | None = None) -> list:
    """Remove the lock files of a caller that is no principal any more: its
    acting lock and the acting lock's turnstile, and its call slots. Called by
    a command that ended its authority while it still holds `acting_fd`, the
    caller's acting lock taken exclusively (`drain_caller`). [(path, why)] for
    each file left, and nothing it leaves grants anything: every file is only
    a lock, and a caller's authority is its record and badges (`principal`).

    It never waits. The command holds the acting lock (and the create lock),
    and a call holding a slot or passing the turnstile may be waiting for
    either, so a wait here would take locks in the other order; a file in use
    is left, and a reboot clears it.

    Safe against the taker that has the file open meanwhile: each file is
    removed only while this process holds its lock exclusively, and every
    taker checks, once it has a lock, that its file is still the one at the
    path (`_is_current`), and opens the path again when it is not. So no two
    takers ever hold one lock on two files. A call of the caller's that then
    gets the acting lock is checked again against its record and badges
    (`services._recheck`), which the command has already taken away.

    Its counter (`<caller>.refused`) is kept: what it counted is the evidence
    `qmcp check` warns on, and removing it would also give the name a new
    day's share of the audit log."""
    if not valid_qube_name(caller):
        return []
    base = os.path.join(RUN_DIR if run_dir is None else run_dir, "calls")
    left = []
    acting = acting_lock_path(caller, run_dir)
    try:
        if _is_current(acting_fd, acting):
            os.unlink(acting)
    except OSError as e:
        left.append((acting, f"not removed ({type(e).__name__})"))
    for path in [queue_path(acting)] + [os.path.join(base, f"{caller}.{i}")
                                       for i in range(max(MAX_CONCURRENT_CALLS, LEAD_CALLS))]:
        why = _remove_if_free(path)
        if why:
            left.append((path, why))
    return left


def retire_qube_locks(name: str, held=()) -> list:
    """Remove the lock file of a qube qmcp has just removed, and its
    turnstile: [(path, why)] for each file left. `held`: descriptors this
    process may hold the qube's lock on (a service's `call.fds`); the lock
    file goes under that lock when one of them is it, else under its own,
    taken without waiting. It never waits, so it never delays a remove, and
    a file in use is left (a reboot clears it): every taker checks its file
    is still the one at the path (`_take_current`), and a service checks the
    qube again under the lock and finds it gone, so a file left or removed
    grants nothing. A qube removed outside qmcp keeps its files. Never
    raises: a remove that landed is never reported as failed for this."""
    if not valid_qube_name(name):
        return []
    path, left = qube_lock_path(name), []
    try:
        mine = next((fd for fd in held if _is_current(fd, path)), None)
        if mine is not None:
            try:
                os.unlink(path)
            except OSError as e:
                left.append((path, f"not removed ({type(e).__name__})"))
        elif (why := _remove_if_free(path)):
            left.append((path, why))
        if (why := _remove_if_free(queue_path(path))):
            left.append((queue_path(path), why))
    except Exception as e:
        left.append((path, type(e).__name__))
        print(f"qmcp: the lock files of the removed qube {name} were left "
              f"({type(e).__name__})", file=sys.stderr)
    return left


def sweep_qube_locks(app) -> int:
    """Remove the lock files of names that are no longer qubes: a disposable
    qubesd removed itself after a kill, a qube removed outside qmcp. Run by
    every pass of the gate's timer; the number of names swept. A file a call
    holds is left for the next pass, and one whose name is a qube is never
    touched; the list is read from qubesd itself (`admin.vm.List`), not from
    the client's cache, which lags a new disposable. Safe against a qube
    created under the name meanwhile for the same reason as
    `retire_qube_locks`: every taker checks its file is still the one at the
    path. Never raises, and writes no audit line: it changes nothing a
    principal or the operator did."""
    try:
        raw = app.qubesd_call("dom0", "admin.vm.List").decode(errors="replace")
        live = {line.split(" ", 1)[0] for line in raw.splitlines() if line.strip()}
        files = os.listdir(os.path.join(RUN_DIR, QUBE_LOCK_SUBDIR))
    except Exception:
        return 0
    names = set()
    for f in files:
        for suffix in (".lock", ".queue"):
            if f.endswith(suffix) and valid_qube_name(f[:-len(suffix)]):
                names.add(f[:-len(suffix)])
    swept = 0
    for name in sorted(names - live):
        if not retire_qube_locks(name):
            swept += 1
    return swept


class qube_lock:
    """`with core.qube_lock(name) as held:` for an operator command, which
    waits in the qube's turnstile (`take_queued_lock`). `must`:
    a command that grants authority refuses (`QubeBusy`) when the lock is held
    past the wait; one that only takes authority away goes on without it
    (`held` False) and says so."""

    def __init__(self, name: str, must: bool = True, timeout: float | None = None) -> None:
        self.name, self.must = name, must
        self.timeout = OPERATOR_WAIT_S if timeout is None else timeout
        self.fd = None

    def __enter__(self) -> bool:
        self.fd = acquire_qube_lock(self.name, self.timeout, queue=True)
        if self.fd is None and self.must:
            raise QubeBusy(f"'{self.name}' is being changed by a call or another command "
                           f"(its lock was held for {self.timeout:.0f}s); try again")
        return self.fd is not None

    def __exit__(self, *exc) -> bool:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        return False


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


def netvm_of(vm):
    """The qube's network's name, or None for none (dom0 and a RemoteVM have no
    network). Raises `Unreadable`: a failed read is never "no network"."""
    if klass_of(vm) in NO_NETWORK_CLASSES:
        return None
    try:
        ref = vm.netvm
    except Exception:
        raise Unreadable(f"cannot read the network of {name_of(vm)}") from None
    return None if ref is None else str(getattr(ref, "name", ref))


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


#: A valid qube name no qube carries: the balancing read of `tag_read_by_name`
#: after a read of a qube that exists. Should a qube ever be given this name,
#: the balance degrades to the gap it closes, never to a new one.
BALANCE_MISSING = "qmcp-no-such-qube"
#: The qube the balancing read goes to after a read that failed: it always exists.
BALANCE_PRESENT = "dom0"


def tag_read_by_name(app, name, method: str, *args) -> bytes:
    """A tag read of the qube called `name` (`admin.vm.tag.List` or `.Get`),
    which costs the same whether or not that qube exists. Raises what the read
    raised.

    qubesd answers a missing qube sooner than it reads an existing one's tags:
    measured on the development box (Qubes 4.3.1, 2026-10-18), about 0.22 ms a
    read, for `tag.List` and `tag.Get` alike. So every read by name is followed
    by one more of the same method: on a qube that does not exist when the read
    found its qube, on dom0 when it did not. Each name then costs one read of
    an existing qube and one of a missing one (measured: -0.003 ms apart, 600
    pairs). The second read's answer is never used."""
    ok = False
    try:
        out = app.qubesd_call(name, method, *args)
        ok = True
        return out
    finally:
        try:
            app.qubesd_call(BALANCE_MISSING if ok else BALANCE_PRESENT, method, *args)
        except Exception:
            pass


def in_ai_space_by_name(app, name, hub: bool = False) -> bool:
    """Is the qube called `name` in AI space (and, for the hub, not hidden
    from it)? One qubesd round trip either way.

    A qube outside AI space must cost exactly what a missing one costs, or the
    response time says which names exist. Answering a missing
    name from the domain list and an existing one with a tag read was measured
    on 2026-10-01 at ~0.7 ms apart. `admin.vm.tag.Get` answers "1"/"0" for a
    qube and fails for a missing one, after the same single call. For the hub
    the one call is `admin.vm.tag.List`, so a qube of a hidden anonymous project
    (`qmcp-hubblind`) takes the same calls as a missing one. qubesd answers a
    missing qube sooner, which made such a service call about 1 ms slower
    than one naming a missing qube (measured on the development box,
    2026-10-18), so each read is balanced (`tag_read_by_name`).
    """
    if not valid_qube_name(name):
        return False
    try:
        if hub:
            tags = set(tag_read_by_name(app, name, "admin.vm.tag.List")
                       .decode(errors="replace").split())
            return UMBRELLA in tags and projects.HUBBLIND not in tags
        return tag_read_by_name(app, name, "admin.vm.tag.Get", UMBRELLA).strip() == b"1"
    except Exception:
        return False


def _resolve(app, name, refusal: "Refusal", hub: bool = False):
    """The VM object for `name`, which must be in AI space, else `refusal`;
    for the hub, not of a hidden anonymous project either.

    The by-name check decides; the object is fetched only for a qube already
    known to be in AI space, and re-checked, since its tags may have changed
    in between.
    """
    if not in_ai_space_by_name(app, name, hub):
        raise refusal
    vm = lookup(app, name)
    try:
        if vm is None:
            raise refusal
        tags = tags_of(vm)
        if UMBRELLA not in tags or (hub and projects.HUBBLIND in tags):
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
        return tag_read_by_name(app, name, "admin.vm.tag.Get",
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
        # A hidden anonymous project is not the hub's to see, nor any reference to it.
        return projects.HUBBLIND not in tags
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
    why costs nothing. So does a qube the anonymity gate stopped
    (`qmcp-blocked`): no service starts, changes or clones one, as the rulebook
    lets nothing reach one; only the operator starts one, by hand.
    """
    if who.is_hub():
        vm = _resolve(app, name, Refusal(NOT_FOUND), hub=True)
    else:
        vm = _resolve_member(app, name, who.slot, Refusal(NOT_FOUND))
    if name == who.name:
        raise Refusal(NOT_FOUND)
    try:
        tags = tags_of(vm)
    except Unreadable:
        raise Refusal(GUARDED_REFUSAL) from None
    if projects.BLOCKED in tags:
        raise Refusal(BLOCKED_REFUSAL)
    if QUARANTINE in tags:
        raise Refusal(QUARANTINE_REFUSAL)
    if is_guarded(vm, tags):
        raise Refusal(GUARDED_REFUSAL)
    return vm


def readable(app, name, who: Principal):
    """A qube the caller reads: for the hub, managed or guarded; for a lead, a
    member, or one of its approved templates or worker networks (names it
    already knows, so looking them up reveals nothing)."""
    if who.is_hub():
        return _resolve(app, name, Refusal(NOT_FOUND), hub=True)
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
    vm = _resolve(app, name, refuse(f"{what} must reference an ai-managed qube"),
                  hub=who.is_hub())
    # A qube the anonymity gate stopped is nothing to build on: a create from
    # it would make a fresh, unblocked child on the path the gate stopped.
    try:
        tags = tags_of(vm)
    except Unreadable:
        raise refuse(f"{what} must reference an ai-managed qube") from None
    if tags & {projects.BLOCKED, projects.STOPPED}:
        raise Refusal(BLOCKED_REFUSAL)
    if QUARANTINE in tags:
        raise Refusal(QUARANTINE_REFUSAL)
    return vm


# ------------------------------------------------------------------ the funnel

class Call:
    """One invocation: what the audit line will say about it."""

    __slots__ = ("service", "caller", "principal", "summary", "error_class", "fds", "acting",
                 "landed", "noop", "where", "reached", "proposed")

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
        #: Whether `fds` holds the caller's acting lock (`hold_acting`).
        self.acting = False
        #: This call created a qube (kept, or rolled back since), or may have:
        #: a create failed and a qube of that name exists or cannot be read.
        #: Such a failed call is always logged, past the refusal cap
        #: (`audit.REFUSALS_PER_HOUR`).
        self.landed = False
        #: The call succeeded without changing anything (a value the qube
        #: already had): capped like a failed call, though it answers ok.
        self.noop = False
        #: The projects its line belongs to (`audit.place`), worked out before
        #: the call acts and again after; () until then: no project.
        self.where = ()
        #: The qubes the service judged within its caller's reach, by the same
        #: check that lets it act on them (`operand`, `reference`), or that
        #: this call created. A refused call's line is placed, and names a
        #: qube, only by these (`audit.OUT_OF_REACH` for any other).
        self.reached: set = set()
        #: A create's proposed name, judged inside its caller's own name
        #: space: kept on a refused call's line as given, though it places
        #: nothing until the call creates it.
        self.proposed: set = set()


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
                            error_class=call.error_class, slots=call.where)
        except Exception:
            pass
    stream = sys.stdout if out is None else out
    stream.write(json.dumps(payload) + "\n")
    stream.flush()
    return 0 if payload.get("ok") else 1
