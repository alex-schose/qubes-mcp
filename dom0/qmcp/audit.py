"""qmcp.audit — the hash-chained, AI-unreachable record of state changes.

Every state-changing qmcp.* call appends one JSON line to the audit chain
(/var/log/qmcp-audit.log, unless the modes below send it elsewhere), and so does every command of the operator's that
changes something (caller "operator": the command and the names it acts on),
accepting and rejecting the hub's proposals included. Each line carries `prev`, the sha256 of the line
before it, and `hash`, the sha256 of its own canonical form, so an edit, a
deletion, a reorder or an insertion breaks the chain and `verify()` finds it.

Two properties the callers rely on:

1. Tamper-EVIDENT, not tamper-proof. Root in dom0 can rewrite the chain from
   any point onward. What it cannot do is quietly remove one line.
2. AI-unreachable by construction. No qmcp.* service reads or writes an
   arbitrary dom0 path and no policy line exposes this file.

Contracts:
- BEST-EFFORT. `audit()` never raises and never blocks the operation.
- THE CALLER SANITISES the summary: qube names, property and feature KEYS,
  actions. Never a property or feature value.

Schema 2 (0.9.17) adds `caller` (the qrexec source, or "operator" for the
operator's own commands) and `error_class` (the exception class behind a
fixed-vocabulary error, so the operator can see what the caller was not told). Lines of schema 1 chain on unchanged. A write reads
only the end of the file, and `qmcp audit rotate` moves the log aside and
starts a new one anchored on the old head.

The wrappers run as a non-root dom0 user in the `qubes` group, and the
operator's commands as root or as a member of `qubes`. The installer and tmpfiles create the log
root:qubes 0660, and `qmcp check` fails when the services could not write it;
this module never chmods it, because a non-owner fchmod is EPERM and would make
every append fail.

Where a line goes (0.9.33). The install has a mode (`install.sh --audit-log`,
`/etc/qmcp/audit-mode`): `disk`, the log above; `ram`, a chain under
/run/qmcp/audit, gone at shutdown; `none`, no line at all. A project has one
too (its record's `audit`, `qmcp project audit`): disk, ram or off. A line
belongs to a project when its caller is the project's lead, a qube it names
wears one of the project's slot badges (read before the call acts and after,
so a removed qube and a created one both count), or it names the project. Its
effective mode is the most private of the install's and of every project it
belongs to (none, then ram, then disk). A line whose project cannot be worked
out (a badge read that failed, records that do not read, a slot badge with no
record) goes to RAM (nowhere only in install mode none), never to disk.
A principal's REFUSED call is placed only by the qubes its service judged
within the caller's reach (or created): a name it did not (out of reach,
missing, or refused before it was judged) places nothing, and the line
records it as `OUT_OF_REACH` (`refused_place`). Every caller says where its line belongs (`slots=`, `app=`, or a `Where` it worked out
before, which `audit()` takes as final), and a test refuses one that does not.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import time

LOG_PATH = "/var/log/qmcp-audit.log"
GENESIS = hashlib.sha256(b"").hexdigest()
SCHEMA = 2


def _utc_now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _body_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


#: How much of the end of the log is read to find the last record. A record is
#: well under 2 KiB, so a write costs the same however long the log has grown.
TAIL_BYTES = 64 * 1024

#: Past this size the hourly rotation (`qmcp-audit.timer`, `auto_rotate`)
#: rotates the log whatever the day, and `qmcp check` warns. The services run
#: as an unprivileged user who cannot create files in /var/log, so rotation is
#: root's: the timer's, or `qmcp audit rotate`.
ROTATE_AT_BYTES = 32 * 1024 * 1024
#: The RAM chains (tmpfs, dom0's memory) are bounded by size, unlike the log on
#: disk: the hourly run rotates one past `RAM_ROTATE_AT_BYTES`, and removes the
#: oldest rotated RAM files while all RAM chains together hold more than
#: `RAM_KEEP_BYTES`. A live chain is never removed. A flood can so push earlier
#: RAM lines off; a reboot clears them all anyway.
RAM_ROTATE_AT_BYTES = 8 * 1024 * 1024
RAM_KEEP_BYTES = 64 * 1024 * 1024

ROTATE_SERVICE = "qmcp.audit-rotate"
#: The new log's name while a rotation writes it, before it is renamed in.
ROTATING_SUFFIX = ".rotating"
#: The hourly rotation and removal by age; `qmcp check` fails while it does
#: not run.
AUDIT_TIMER = "qmcp-audit.timer"


def _tail_state(f) -> tuple[int, str]:
    """(last seq, last hash) from the end of a binary file, or (0, GENESIS)
    for an empty log or a last line that does not parse. A damaged tail still
    gets the new line appended, anchored on GENESIS, so verify() reports the
    break instead of hiding it."""
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size == 0:
        return 0, GENESIS
    start = max(0, size - TAIL_BYTES)
    f.seek(start)
    lines = [line for line in f.read().split(b"\n") if line.strip()]
    if not lines:
        return 0, GENESIS
    try:
        obj = json.loads(lines[-1])
        return int(obj["seq"]), str(obj["hash"])
    except Exception:
        return 0, GENESIS


def _keep_for_the_services(fd: int) -> None:
    """A log root has just created is root's group, and the services (the
    `qubes` group) could no longer append to it, without a symptom. Give a new,
    empty, root-owned log to `qubes`; never touch one that has lines."""
    try:
        st = os.fstat(fd)
        if st.st_size == 0 and st.st_uid == 0:
            import grp
            gid = grp.getgrnam("qubes").gr_gid
            if st.st_gid != gid:
                os.fchown(fd, -1, gid)
    except (KeyError, OSError):
        pass


def _locked_log(path: str):
    """The log opened for append and exclusively locked, as a binary file.

    After taking the lock, check the file is still the one at `path`: a
    rotation may have renamed it while this call waited, and a line appended
    to the renamed file would fork the chain.
    """
    for _ in range(5):
        # Root (the operator's commands) and the services both append here: a
        # file whoever creates it must stay group-writable (tmpfiles declares it).
        old = os.umask(0o007)
        try:
            # The RAM chains' directory is the services' group's to write: root
            # opens no link and no FIFO planted there, only a plain file.
            fd = _open_run(path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
        finally:
            os.umask(old)
        if os.geteuid() == 0:
            _keep_for_the_services(fd)
        f = os.fdopen(fd, "r+b")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            if os.fstat(f.fileno()).st_ino == os.stat(path).st_ino:
                return f
        except FileNotFoundError:
            pass
        f.close()
    raise OSError("audit log keeps moving")


def _write(f, record: dict) -> None:
    f.seek(0, os.SEEK_END)
    line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if f.tell():
        # A write cut short (a kill, a full disk) leaves a last line with no
        # newline: the next record starts a line of its own, so it is never
        # glued onto the torn bytes and lost with them.
        f.seek(-1, os.SEEK_END)
        if f.read(1) != b"\n":
            line = b"\n" + line
        f.seek(0, os.SEEK_END)
    f.write(line)
    f.flush()
    os.fsync(f.fileno())


def _append(record: dict, path: str) -> bool:
    try:
        f = _locked_log(path)
    except OSError:
        return False
    try:
        seq, prev = _tail_state(f)
        record["seq"] = seq + 1
        record["prev"] = prev
        record["hash"] = _body_hash(record)
        _write(f, record)
        return True
    except Exception:
        return False
    finally:
        f.close()


def _free_aside(path: str, tries: int = 3) -> str:
    """The rotated log's name, `<log>.<UTC time to the second>`, exactly as
    retention matches it. A name already taken (a rotation earlier in the same
    second) waits for the next second rather than adding a suffix no reader
    would match; the caller holds the log's lock, so no other rotation of this
    log can take it meanwhile."""
    import datetime
    import time
    for _ in range(tries):
        now = datetime.datetime.now(datetime.timezone.utc)
        aside = path + "." + now.strftime("%Y%m%dT%H%M%SZ")
        if not os.path.lexists(aside):
            return aside
        time.sleep(1.0 - now.microsecond / 1e6 + 0.01)
    raise FileExistsError(aside)


def rotate(path: str | None = None, caller: str = "operator") -> str:
    """Keep the log aside and start a new one whose first record anchors on
    the old head, so the chain continues across files. Operator only (root).
    Returns the name the old log now has.

    The new log is written in full under a temporary name, the old one is
    linked to its new name, and the new one renamed over the log in one step:
    there is no moment with no file at the log's name, in which a writer
    would create a fresh log from GENESIS, unanchored. A writer waiting for
    the old log's lock finds it is no longer the file at the name, and appends
    to the new one (`_locked_log`)."""
    path = LOG_PATH if path is None else path
    f = _locked_log(path)
    tmp = None
    try:
        seq, head = _tail_state(f)
        st = os.fstat(f.fileno())
        aside = _free_aside(path)
        tmp = path + ROTATING_SUFFIX
        # One left by a rotation killed part-way (it was never renamed in) is
        # taken over: this rotation holds the log's lock, so no other is running.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        nfd = os.open(tmp, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o660)
        try:
            os.fchown(nfd, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.fchmod(nfd, st.st_mode & 0o7777)
        with os.fdopen(nfd, "r+b") as nf:
            record = {"v": SCHEMA, "ts": _utc_now_iso(), "service": ROTATE_SERVICE,
                      "caller": str(caller), "args": {"continues": os.path.basename(aside),
                                               "after_seq": seq},
                      "ok": True, "error": None, "seq": 1, "prev": head}
            record["hash"] = _body_hash(record)
            _write(nf, record)
        os.link(path, aside)
        try:
            os.rename(tmp, path)
        except OSError as e:
            # The log stays the log: the name it was to move to goes again.
            try:
                os.unlink(aside)
            except OSError:
                raise OSError(e.errno, f"{e.strerror}, and {aside} is still a second name of "
                                       f"the live log: remove it (rm {aside})") from e
            raise
        tmp = None
        # Nothing appends to a rotated log again (a writer that waited for
        # the old lock finds the new file at the name): read-only, so cutting
        # its last lines takes root, as removing it does.
        try:
            # By the fd: the aside is the inode this rotation holds, and a
            # chmod by name would follow a link put at that name meanwhile.
            os.fchmod(f.fileno(), st.st_mode & 0o7444)
        except OSError:
            pass
        return aside
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        f.close()


#: Lines that could not be written are counted here, on tmpfs, which a full
#: /var does not fill: `qmcp check` fails while it exists. Created by the
#: first failure (root or the services' user: /run/qmcp is setgid qubes) and
#: removed by the operator, never by qmcp; a reboot or `uninstall.sh` clears
#: it with the rest of /run/qmcp, so a gap is told until then.
DROPPED_PATH = "/run/qmcp/state/audit-dropped"
#: Below this much free space under the log's directory the services refuse
#: every state-changing call before it acts, but a kill (which only takes
#: away, and is logged only when dom0 accepted it): no other change is made
#: without its line.
FLOOR_BYTES = 64 * 1024 * 1024


#: A principal's calls that changed nothing (refused, failed, or a feature, or
#: a property set explicitly, set to the value already there) are logged up
#: to this many in each hour of the clock since boot (`_periods`), for each
#: caller; past it they are counted in `<run>/calls/<caller>.refused`, on
#: tmpfs, and `qmcp check` warns while that counts one (a reboot clears it). A
#: failed create that made a qube, or may have, is always logged.
#: Without the cap a compromised principal could fill the log's disk down to
#: the floor, one failed call at a time, and stop every lead's changes.
REFUSALS_PER_HOUR = 60
REFUSED_SUFFIX = ".refused"


#: Each principal may put this many lines a day (of the clock since boot,
#: `_periods`) on the log for calls that changed something; past it, its state-changing calls are refused
#: before they act (a kill goes on), counted in the same file, not logged. One
#: compromised principal then spends only its own budget, and the 64 MiB
#: floor stays the backstop for all of them. Lines of calls that changed
#: nothing are under the hourly cap above and do not spend it.
AUDIT_LINES_PER_DAY = 20000


def _counter(text: str):
    """A counter's record: its first JSON value. A rewrite cut short between
    its write and its truncate leaves the end of the older, longer text behind
    the new record, which is ignored; an empty file is a fresh counter."""
    text = text.lstrip()
    return json.JSONDecoder().raw_decode(text)[0] if text else {}


def _update(path: str, change):
    """Read-modify-write the caller's counter under its lock. `change(rec)`
    edits the dict and returns the answer. Raises when the counter cannot be
    opened, read or written: each caller decides which way that fails."""
    old = os.umask(0o007)
    try:
        # Never through a link: the counter is a file of its own, as every
        # lock file under /run/qmcp is.
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o660)
    finally:
        os.umask(old)
    with os.fdopen(fd, "r+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        text = fh.read(4096)
        rec = _counter(text)
        if not isinstance(rec, dict):
            raise ValueError("counter is not an object")
        answer = change(rec)
        # Written over the old text, then cut to length: a failure part-way
        # leaves the old counts or the new, never an empty file that reads as
        # a fresh day (the evidence gone, the budget restarted).
        fh.seek(0)
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush()
        fh.truncate()
        return answer


def _boot_clock() -> float:
    """Seconds since dom0 booted, which nothing can set."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _periods(now: str | None = None) -> tuple:
    """(day, hour): the periods the daily budget and the hourly cap count in.
    Counted on the clock since boot, which no one sets and which only moves
    forward, never on the wall clock: a wall clock stepped back would give a
    principal a fresh share, and one stepped forward and corrected would keep
    it refused. The counters live on /run, cleared at every boot, so a period
    is good for a counter's whole life. `now`, an ISO time, is a test's: its
    UTC day and hour."""
    if now is not None:
        return now[:10], now[:13]
    b = _boot_clock()
    return f"boot-day-{int(b // 86400)}", f"boot-hour-{int(b // 3600)}"


def take_refusal(path: str, now: str | None = None) -> bool:
    """Count one call that changed nothing, of the caller whose counter is
    `path`. True when its line may be written (under the cap this hour);
    False when it is counted instead. A counter that cannot be kept logs the
    line: the cap only ever withholds a line it has counted."""
    _, hour = _periods(now)
    stamp = now or _utc_now_iso()

    def change(rec):
        if rec.get("hour") != hour:
            rec["hour"], rec["logged"] = hour, 0
        if int(rec.get("logged", 0)) < REFUSALS_PER_HOUR:
            rec["logged"] = int(rec.get("logged", 0)) + 1
            return True
        rec["unlogged"] = int(rec.get("unlogged", 0)) + 1
        rec["first"] = rec.get("first") or stamp
        return False
    try:
        return _update(path, change)
    except Exception:
        return True


def budget_left(path: str, now: str | None = None) -> bool | None:
    """May this caller still change something today? False once it has spent
    `AUDIT_LINES_PER_DAY`, and then the refusal is counted here. None when the
    counter cannot be kept: a gate, so the caller refuses then too (with its
    own reason), and `qmcp check` fails on a counter that does not read or is
    not the services group's to write."""
    day, _ = _periods(now)
    stamp = now or _utc_now_iso()

    def change(rec):
        if rec.get("day") == day and int(rec.get("lines", 0)) >= AUDIT_LINES_PER_DAY:
            rec["over"] = int(rec.get("over", 0)) + 1
            rec["over_first"] = rec.get("over_first") or stamp
            return False
        return True
    try:
        return _update(path, change)
    except Exception:
        return None


#: The line a caller's first withheld call of an hour (the cap) or of a day
#: (the budget) leaves on the chain: the counter that counts the rest is on
#: tmpfs, which a reboot or an `rm` clears, so the chain keeps that they were.
CAPPED_SERVICE = "qmcp.calls-capped"


def first_capped(path: str, kind: str, now: str | None = None) -> str | None:
    """The hour (`kind` "hour") or day ("day") just capped for this caller,
    the first time it is asked in that period, else None: at most one line
    per caller per period. None too when the counter cannot be kept."""
    day, hour = _periods(now)
    period = hour if kind == "hour" else day

    def change(rec):
        key = f"noted_{kind}"
        if rec.get(key) == period:
            return None
        rec[key] = period
        return period
    try:
        return _update(path, change)
    except Exception:
        return None


def budget_spent(path: str, now: str | None = None) -> bool:
    """Has this caller spent today's share? Read only, under the counter's
    lock; a counter that does not read counts as spent. For a kill, which acts
    whatever the answer: it decides only whether its line is capped."""
    day, _ = _periods(now)
    try:
        with open(path, encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            text = fh.read(4096)
    except FileNotFoundError:
        return False
    except (OSError, UnicodeDecodeError):
        return True
    try:
        rec = _counter(text)
        return rec.get("day") == day and int(rec.get("lines", 0)) >= AUDIT_LINES_PER_DAY
    except Exception:
        return True


def spend(path: str, now: str | None = None) -> None:
    """One line of a call that changed something, against the day's budget.
    Best-effort: a counter that cannot be kept is caught by `budget_left`."""
    day, _ = _periods(now)

    def change(rec):
        if rec.get("day") != day:
            rec["day"], rec["lines"] = day, 0
        rec["lines"] = int(rec.get("lines", 0)) + 1
    try:
        _update(path, change)
    except Exception:
        pass


def counters(calls_dir: str, now: str | None = None) -> list:
    """[(caller, record or None)] for every caller's counter; None for one
    that does not read."""
    out = []
    try:
        names = sorted(os.listdir(calls_dir))
    except OSError:
        return out
    for fn in names:
        if not fn.endswith(REFUSED_SUFFIX):
            continue
        try:
            with os.fdopen(_open_run(os.path.join(calls_dir, fn)),
                           encoding="utf-8") as fh:
                # Under the writers' lock, shared: `_update` truncates before
                # it writes, and an unlocked read could catch the gap.
                fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                text = fh.read(4096)
            rec = _counter(text)
            if not isinstance(rec, dict):
                raise ValueError
        except Exception:
            rec = None
        out.append((fn[:-len(REFUSED_SUFFIX)], rec))
    return out


def unlogged_refusals(calls_dir: str) -> list:
    """[(caller, count or None, first)] for every counter that withheld a
    line; count None for one that does not read."""
    out = []
    for caller, rec in counters(calls_dir):
        if rec is None:
            out.append((caller, None, None))
        elif int(rec.get("unlogged", 0) or 0):
            out.append((caller, int(rec["unlogged"]), rec.get("first")))
    return out


def spent_budgets(calls_dir: str, now: str | None = None) -> list:
    """[(caller, lines today, refused past the budget, first such refusal)]
    for every caller that reached its daily budget today or was refused for it
    since its counter was made."""
    day, _ = _periods(now)
    out = []
    for caller, rec in counters(calls_dir):
        if rec is None:
            continue
        today = int(rec.get("lines", 0) or 0) if rec.get("day") == day else 0
        over = int(rec.get("over", 0) or 0)
        if today >= AUDIT_LINES_PER_DAY or over:
            out.append((caller, today, over, rec.get("over_first")))
    return out


def room(path: str | None = None) -> bool:
    """True when the directory of the chain `path` (default: the log) has
    `FLOOR_BYTES` free: the log's disk, or for a RAM chain the tmpfs, which is
    dom0's memory. False when it has not, or when that cannot be read: a gate,
    so it fails toward refusing. A RAM chain's directory not made yet is
    judged by its parent's filesystem, the same tmpfs."""
    path = LOG_PATH if path is None else path
    d = os.path.dirname(path) or "."
    if not os.path.isdir(d):
        d = os.path.dirname(d) or "."
    try:
        st = os.statvfs(d)
    except OSError:
        return False
    return st.f_bavail * st.f_frsize >= FLOOR_BYTES


def install_room() -> bool:
    """Room on every chain this install may write to: the log's disk in mode
    disk, and the RAM chains' tmpfs in modes disk and ram (a project in RAM,
    and a line whose project cannot be worked out, go there). Asked for every
    line whatever its own place, so a refusal for room never says where a
    line was going; mode none writes nothing and needs none."""
    mode = install_mode()[0]
    if mode == "none":
        return True
    ok = room(ram_path())
    return ok and room(LOG_PATH) if mode == "disk" else ok


def dropped(path: str | None = None):
    """(lines not written, first time) from the marker, or None without one;
    (None, None) for a marker that does not read."""
    try:
        rec = _counter(_read_run(DROPPED_PATH if path is None else path))
        return int(rec["count"]), str(rec["first"])
    except FileNotFoundError:
        return None
    except Exception:
        return None, None


def _note_dropped() -> None:
    """Count a line that was not written. Best-effort: it never raises."""
    try:
        old = os.umask(0o007)
        try:
            fd = _open_run(DROPPED_PATH, os.O_RDWR | os.O_CREAT)
        finally:
            os.umask(old)
        with os.fdopen(fd, "r+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                rec = _counter(fh.read(4096))
                count, first = int(rec.get("count", 0)), str(rec.get("first") or _utc_now_iso())
            except Exception:
                count, first = 0, _utc_now_iso()
            # Written over, then cut to length, as the callers' counters are:
            # a failure part-way never leaves an empty marker that reads as none.
            fh.seek(0)
            fh.write(json.dumps({"count": count + 1, "first": first}) + "\n")
            fh.flush()
            fh.truncate()
    except Exception:
        pass


# ------------------------------------------------------------------ where a line goes

#: The install's mode: one word, `disk`, `ram` or `none` (`install.sh
#: --audit-log`). Absent: `disk`, as every install before the option.
MODE_PATH = "/etc/qmcp/audit-mode"
#: Most private first: a line's mode is the first of these any of its parts asks for.
MODES = ("none", "ram", "disk")
#: A project's word for each mode (its record's `audit`; absent is disk).
PROJECT_MODES = {"disk": "disk", "ram": "ram", "off": "none"}
#: The RAM chains, under the runtime directory (tmpfs): one per project in
#: RAM, and one for the install in RAM and for a line no single project's.
RAM_SUBDIR = "audit"
RAM_LOG = "qmcp-audit.log"
#: Summary keys that hold a qube's name, a list of them, or a project's label
#: or slot: what a line is about, for the project it belongs to.
NAME_KEYS = ("name", "source", "template", "qube", "lead_clone", "lead_promote",
             "model_qube", "subject")
LIST_KEYS = ("qubes",)
PROJECT_KEYS = ("project", "target", "subject")
#: The request keys each state-changing service acts on, and so the qubes its
#: line is about, read before the call acts. Only these: a key the service
#: ignores is the caller's to choose, and would let it send its own line to a
#: project kept in RAM or nowhere by naming one of that project's qubes.
REQUEST_KEYS = {
    "qmcp.SetPropertyAIManaged": ("name",),
    "qmcp.SetFeatureAIManaged": ("name",),
    "qmcp.LifecycleAIManaged": ("name",),
    "qmcp.SpawnAIManagedQube": ("template",),
    "qmcp.CloneAIManagedQube": ("source",),
    "qmcp.SpawnDisposableAIManaged": ("template",),
}


def install_mode(path: str | None = None) -> tuple:
    """(mode, problem). Absent: disk. A file that does not read or does not
    hold one of the three words: ram, with the problem (`qmcp check` fails on
    it). The operator may have asked for less than disk, so disk could leak
    what was meant to stay off it, and none would lose the record: RAM is the
    answer a line of an unknown project gets too."""
    path = MODE_PATH if path is None else path
    try:
        with open(path, encoding="ascii") as fh:
            word = fh.read(64).strip()
    except FileNotFoundError:
        return "disk", None
    except (OSError, UnicodeDecodeError) as e:
        return "ram", f"{path} does not read ({type(e).__name__})"
    if word not in MODES:
        return "ram", f"{path} holds neither disk, ram nor none"
    return word, None


def most_private(modes) -> str:
    modes = list(modes)
    return min(modes, key=MODES.index) if modes else "disk"


def ram_dir() -> str:
    from qmcp import core
    return os.path.join(str(core.RUN_DIR), RAM_SUBDIR)


def ram_path(slot: str | None = None) -> str:
    """The RAM chain of project `slot`, or the install's (`slot` None)."""
    return os.path.join(ram_dir(), RAM_LOG if slot is None else f"{slot}.log")


class Where:
    """The projects a line belongs to, each with its mode as read when the
    line's qubes were read (`modes`: slot -> disk, ram or none), or
    `unknown`: some part of it could not be worked out."""

    __slots__ = ("modes", "unknown")

    def __init__(self, modes=None, unknown=False):
        self.modes, self.unknown = dict(modes or {}), bool(unknown)

    def __or__(self, other: "Where") -> "Where":
        modes = dict(self.modes)
        for slot, mode in other.modes.items():
            modes[slot] = most_private([mode, modes.get(slot, mode)])
        return Where(modes, self.unknown or other.unknown)

    def __repr__(self):
        return f"<Where {'unknown' if self.unknown else sorted(self.modes.items())}>"


def _names(summary: dict) -> list:
    from qmcp import core
    out = []
    for key in NAME_KEYS:
        if isinstance(summary.get(key), str):
            out.append(summary[key])
    for key in LIST_KEYS:
        if isinstance(summary.get(key), list):
            out += [v for v in summary[key] if isinstance(v, str)]
    return [n for i, n in enumerate(out) if core.valid_qube_name(n) and n not in out[:i]]


def place(app, summary=None, slots=()) -> Where:
    """Where a line about `summary` belongs: the projects in `slots` (a
    caller's own, or a `Where` worked out before), those whose slot badge a
    named qube wears (one `admin.vm.tag.List` each, read through `app`; none
    without one), and those it names by label or slot. A qube qubesd says is
    missing belongs to none. Never raises: a read that fails is an unknown
    place. Every named qube is read whatever came before, a missing one, an
    unreadable one or an unknown place, so the number of reads is the same for
    every name and never says what a name is; each read is balanced
    (`core.tag_read_by_name`), since qubesd answers a missing qube sooner
    than it reads an existing one's tags."""
    from qmcp import projects
    if isinstance(slots, Where):
        base, slots = slots, ()
    else:
        base = Where()
    summary = summary if isinstance(summary, dict) else {}
    found = {s for s in slots if s in projects.PROJECT_SLOTS}
    unknown = base.unknown
    if app is not None:
        for name in _names(summary):
            try:
                from qmcp import core
                raw = core.tag_read_by_name(app, name, "admin.vm.tag.List")
                tags = raw.decode("ascii", "replace").split()
            except KeyError:
                continue                # QubesVMNotFoundError: no such qube, in no slot
            except Exception:
                unknown = True
                continue
            found |= {part[1] for part in map(projects.slot_badge_parts, tags)
                      if part and part[1] in projects.PROJECT_SLOTS}
    keys = [summary[k] for k in PROJECT_KEYS if isinstance(summary.get(k), str)]
    if unknown:
        return Where(base.modes, unknown=True)
    # The records are read for every line, whatever its names wear: read only
    # for a slot-badged name, the time it takes would tell such a name (a
    # hidden project's qube) from one that does not exist.
    try:
        records = projects.load()
        for key in keys:
            if key in projects.PROJECT_SLOTS:
                found.add(key)
                continue
            p = projects.by_label(records, key)
            if p is not None and p.slot in projects.PROJECT_SLOTS:
                found.add(p.slot)
        # A slot whose record is gone (a delete part-way, badges left) has no
        # mode to follow: an unknown place, RAM.
        return base | Where({s: PROJECT_MODES[records[s].audit] for s in found if s in records},
                            unknown=any(s not in records for s in found))
    except Exception:
        # Records that do not read leave unknown only a line that needs them:
        # one of a project, or naming one. Another stays where it was going.
        needed = found or any(k in projects.PROJECT_SLOTS or projects.LABEL_RE.match(k)
                              for k in keys)
        return Where(unknown=True) if needed else base


def request_place(app, service: str, req, slot=None) -> Where:
    """Where a service call's line belongs as the request stands, before it
    acts: its caller's project, and the qubes the request names in the keys
    the service acts on (`REQUEST_KEYS`), never any other."""
    keys = REQUEST_KEYS.get(service, ())
    names = {k: req.get(k) for k in keys} if isinstance(req, dict) else {}
    return place(app, names, () if slot is None else (slot,))


def request_names(service: str, req) -> list:
    """The qube names `request_place` reads: those in the keys the service
    acts on, that could be a qube's name."""
    keys = REQUEST_KEYS.get(service, ())
    return _names({k: req.get(k) for k in keys}) if isinstance(req, dict) else []


#: What a refused call's line records in place of a name its service did not
#: judge within the caller's reach: one the caller may not see or act on, one
#: that does not exist, or one the call was refused before it judged. The
#: three are recorded alike, so the line never says which a name was.
OUT_OF_REACH = "<out-of-reach>"


def refused_place(summary, where, before, reached, proposed, slot=None) -> tuple:
    """A refused call's line, placed by what its service reached rather than
    by what the request names: (the summary to record, the summary to place
    it by, the place worked out before the call acted, or its caller's alone).

    A named qube the service did not judge within its caller's reach
    (`reached`: by the check that lets it act, or a qube this call created)
    places nothing and is recorded as `OUT_OF_REACH`; a create's proposed
    name inside the caller's own name space (`proposed`) is kept as given but
    places nothing either. When a name the request's own keys hold (`before`,
    which `request_place` read before the call acted) was not reached, that
    place is dropped for the caller's own: its project for a lead (`slot`),
    the install's mode for the hub. So a principal cannot send its own
    refused line after a qube it may not reach, and the line never records
    that qube's name. Neither depends on whether the name exists: a missing
    name and an out-of-reach one take the same path."""
    summary = summary if isinstance(summary, dict) else {}
    out = set(_names(summary)) - set(reached)
    logged, placing = {}, {}
    for key, value in summary.items():
        if key in NAME_KEYS and value in out:
            logged[key] = value if value in proposed else OUT_OF_REACH
        elif key in LIST_KEYS and isinstance(value, list):
            logged[key] = [OUT_OF_REACH if v in out and v not in proposed else v for v in value]
            placing[key] = [v for v in value if v not in out]
        else:
            logged[key] = placing[key] = value
    if any(name not in reached for name in before):
        where = () if slot is None else (slot,)
    return logged, placing, where


def destination(where: Where | None = None) -> tuple:
    """(mode, path) for a line: path None for `none`. RAM goes to the
    project's own chain when the line belongs to one project only and that
    project asked for RAM, else to the install's RAM chain."""
    where = Where() if where is None else where
    install = install_mode()[0]
    modes = [install] + (["ram"] if where.unknown else list(where.modes.values()))
    mode = most_private(modes)
    if mode == "none":
        return "none", None
    if mode == "disk":
        return "disk", LOG_PATH
    if not where.unknown and list(where.modes.values()) == ["ram"]:
        return "ram", ram_path(next(iter(where.modes)))
    return "ram", ram_path()


def audit(service, caller, summary, ok, error=None, error_class=None,
          path: str | None = None, slots=(), app=None) -> bool:
    """Record one state-changing call. Returns True if a line was written, or
    if the line's mode is none (nothing is meant to be written); a line that
    should have been and was not is counted (`DROPPED_PATH`). `slots`: the
    projects the line belongs to that its summary does not show (a lead's
    own), or a `Where` already worked out; `app`: read the badges of the
    qubes the summary names. `path` writes to that file, whatever the modes."""
    try:
        if path is None:
            # A place already worked out (a `Where`) is the caller's last word:
            # the funnel reads the summary itself, and places a proposal's line
            # by its caller alone. Otherwise it is worked out here.
            where = slots if isinstance(slots, Where) else place(app, summary, slots)
            mode, path = destination(where)
            # A line kept more privately than the install's own costs what an
            # install line costs: otherwise the time a refused call takes
            # tells a principal that a name it cannot see belongs to a project
            # logging to RAM or nowhere.
            install = install_mode()[0]
            if MODES.index(mode) < MODES.index(install):
                _pay_like(install)
            if mode == "none":
                return True
            if mode == "ram":
                _ram_dir_ready()
    except Exception:
        _note_dropped()
        return False
    written = _audit(service, caller, summary, ok, error, error_class, path)
    if not written:
        _note_dropped()
    return written


#: What a line kept off the install's chain writes instead, to cost the same:
#: zeros only, the same size each time, over the same bytes, so it never grows
#: and holds nothing of any line.
PAD_SUFFIX = ".pad"
PAD_BYTES = 512


def _pay_like(mode: str) -> None:
    """The work an append to the install's chain does (its lock, its tail
    read, a durable write on its filesystem), with nothing of the line in it.
    Best-effort: a failure here never changes what the call does."""
    path = LOG_PATH if mode == "disk" else ram_path()
    pad = (LOG_PATH if mode == "disk" else ram_path()) + PAD_SUFFIX
    if mode == "ram":
        _ram_dir_ready()
    try:
        f = _locked_log(path)
    except OSError:
        return
    try:
        _tail_state(f)
        old = os.umask(0o007)
        try:
            fd = _open_run(pad, os.O_WRONLY | os.O_CREAT)
        finally:
            os.umask(old)
        try:
            os.pwrite(fd, b"\0" * PAD_BYTES, 0)
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass
    finally:
        f.close()


def _ram_dir_ready() -> None:
    """The RAM chains' directory, which tmpfiles declares; made here when a
    boot or a test has not, setgid from /run/qmcp, so the group is `qubes`."""
    d = ram_dir()
    if not os.path.isdir(d):
        old = os.umask(0o007)
        try:
            os.makedirs(d, 0o2770, exist_ok=True)
        finally:
            os.umask(old)


def _audit(service, caller, summary, ok, error=None, error_class=None,
           path: str | None = None) -> bool:
    try:
        record = {
            "v": SCHEMA,
            "ts": _utc_now_iso(),
            "service": str(service),
            "caller": None if caller is None else str(caller),
            "args": summary if isinstance(summary, dict) else {},
            "ok": bool(ok),
            "error": None if error is None else str(error),
        }
        if error_class is not None:
            record["error_class"] = str(error_class)
        return _append(record, LOG_PATH if path is None else path)
    except Exception:
        return False


def ram_chains() -> list:
    """[(name, bytes or None)] of the RAM chains there are now, and of their
    rotated files (`<chain>.log.<UTC time>`), which hold memory too."""
    d = ram_dir()
    try:
        names = sorted(n for n in os.listdir(d)
                       if n.endswith(".log") or re.fullmatch(r".+\.log\.\d{8}T\d{6}Z", n))
    except FileNotFoundError:
        return []
    out = []
    for n in names:
        try:
            out.append((n, os.path.getsize(os.path.join(d, n))))
        except OSError:
            out.append((n, None))
    return out


def install_chain() -> str | None:
    """The chain the install's own lines go to now: the log, the install's
    RAM chain, or None in mode none."""
    mode = install_mode()[0]
    return None if mode == "none" else LOG_PATH if mode == "disk" else ram_path()


# ------------------------------------------------------------------ rotation and retention

#: How long a rotated log is kept, in days, or `off` (never removed). Absent:
#: `KEEP_DAYS_DEFAULT`. `qmcp settings set --audit-keep-days`.
KEEP_DAYS_PATH = "/etc/qmcp/audit-keep-days"
KEEP_DAYS_DEFAULT = 90
KEEP_DAYS_MAX = 36500
#: What `qmcp check` reckons a line takes on disk, for the room a full budget
#: needs: 352 bytes measured on the development box (2026-10-17), rounded up.
LINE_BYTES = 400
#: The service and caller of the line a removal leaves.
REMOVE_SERVICE = "qmcp audit remove"
ROTATE_CALLER = "rotate"
_STAMP = "%Y%m%dT%H%M%SZ"
_ROTATED_RE = re.compile(r"\A\d{8}T\d{6}Z\Z")


#: The clocks of the last retention run, to tell a clock that moved from time
#: that passed: `{"boot_id", "wall", "boot"}`. Root's (the timer runs as root),
#: under /var/lib so it outlives a boot.
CLOCK_PATH = "/var/lib/qmcp/audit-clock"
#: Present while removal is paused because the clock moved: what was seen.
#: Only the operator removes it, once dom0's clock is right; `qmcp check` warns.
CLOCK_MOVED_PATH = "/var/lib/qmcp/audit-clock-moved"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
#: How far the wall clock may drift from the clock since boot between two runs.
CLOCK_SLACK_S = 300


def _boot_id():
    try:
        with open(BOOT_ID_PATH, encoding="ascii") as fh:
            return fh.read(64).strip() or None
    except (OSError, UnicodeDecodeError):
        return None


def clock_moved(now, keep) -> str | None:
    """Why the wall clock cannot be trusted to remove old logs, or None. A
    removal judged by a clock stepped forward would erase the record for good,
    so each run compares the wall clock with the clock since boot, which no
    one sets, against the last run: within one boot they must agree within
    `CLOCK_SLACK_S`; across a boot, the wall clock must not have gone back,
    nor forward by more than the keep-days (which would make every file
    removable at once). A run that finds it moved pauses removal until the
    operator removes `CLOCK_MOVED_PATH`. `now`: the run's wall clock (a
    datetime)."""
    wall, boot, bid = now.timestamp(), time.clock_gettime(time.CLOCK_BOOTTIME), _boot_id()
    why = None
    try:
        with open(CLOCK_PATH, encoding="ascii") as fh:
            prev = json.loads(fh.read(512))
        pw, pb, pid = float(prev["wall"]), float(prev["boot"]), prev.get("boot_id")
    except (OSError, ValueError, KeyError, TypeError):
        prev = None
    if prev is not None:
        if pid is not None and pid == bid:
            drift = (wall - pw) - (boot - pb)
            if abs(drift) > CLOCK_SLACK_S:
                why = (f"the wall clock moved {drift:+.0f} s against the clock since boot "
                       f"since the last run")
        elif wall < pw - CLOCK_SLACK_S:
            why = f"the wall clock is {pw - wall:.0f} s behind the last run's, across a boot"
        elif isinstance(keep, int) and wall - pw > keep * 86400:
            why = (f"the wall clock is {(wall - pw) / 86400:.0f} days past the last run's, "
                   f"across a boot: more than the {keep} days kept")
    try:
        os.makedirs(os.path.dirname(CLOCK_PATH), exist_ok=True)
        _write_small(CLOCK_PATH, json.dumps({"boot_id": bid, "wall": wall, "boot": boot}))
        if why is not None:
            _write_small(CLOCK_MOVED_PATH, f"{now.strftime(_STAMP)} {why}")
    except OSError:
        pass
    if why is not None:
        return why
    try:
        with open(CLOCK_MOVED_PATH, encoding="utf-8", errors="replace") as fh:
            return fh.read(512).strip() or "the clock moved"
    except FileNotFoundError:
        return None
    except OSError:
        return f"{CLOCK_MOVED_PATH} does not read"


def _write_small(path: str, text: str) -> None:
    tmp = f"{path}.tmp"
    old = os.umask(0o022)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        os.umask(old)
    os.replace(tmp, path)


def keep_days(path: str | None = None):
    """The days a rotated log is kept: an int, "off", or None when the file
    does not read or does not hold one of them. None removes nothing: removing
    evidence is the direction that cannot be undone, so a setting that cannot
    be read keeps everything, and `qmcp check` fails on it."""
    path = KEEP_DAYS_PATH if path is None else path
    try:
        with open(path, encoding="ascii") as fh:
            word = fh.read(64).strip()
    except FileNotFoundError:
        return KEEP_DAYS_DEFAULT
    except (OSError, UnicodeDecodeError):
        return None
    return parse_keep_days(word)


def parse_keep_days(word):
    """An int 1..KEEP_DAYS_MAX or "off" from the operator's text, else None."""
    if word == "off":
        return "off"
    if isinstance(word, str) and re.fullmatch(r"[0-9]{1,5}", word) \
            and 1 <= int(word) <= KEEP_DAYS_MAX:
        return int(word)
    return None


def rotated(path: str | None = None) -> list:
    """[(file name, its time as a datetime)] of the logs rotated from `path`,
    oldest first: exactly `rotate()`'s names, never a wider pattern."""
    import datetime
    path = LOG_PATH if path is None else path
    d, base = os.path.dirname(path) or ".", os.path.basename(path) + "."
    out = []
    try:
        names = os.listdir(d)
    except FileNotFoundError:
        return out
    for n in names:
        stamp = n[len(base):]
        if n.startswith(base) and _ROTATED_RE.match(stamp):
            try:
                when = datetime.datetime.strptime(stamp, _STAMP).replace(
                    tzinfo=datetime.timezone.utc)
            except ValueError:
                continue
            out.append((n, when))
    return sorted(out, key=lambda x: x[1])


def unpruned(path: str | None = None) -> list:
    """The files beside `path` named like a rotated log of it that `rotated()`
    does not list (a hand copy, or another tool's rotation, such as `.1`), and
    that this module does not write either: no retention ever removes them.
    Sorted."""
    path = LOG_PATH if path is None else path
    d, base = os.path.dirname(path) or ".", os.path.basename(path) + "."
    ours = {n for n, _ in rotated(path)} | {
        os.path.basename(path) + s for s in (ROTATING_SUFFIX, PAD_SUFFIX)}
    try:
        names = os.listdir(d)
    except FileNotFoundError:
        return []
    return sorted(n for n in names if n.startswith(base) and n not in ours)


def _open_run(path: str, flags: int = os.O_RDONLY) -> int:
    """`core.open_run_file`: no link, no FIFO, a plain file (imported late:
    core imports this module)."""
    from qmcp import core
    return core.open_run_file(path, flags)


def _read_run(path: str) -> str:
    from qmcp import core
    return core.read_run_file(path)


def _first_record(path: str):
    """The log's first record, or None for an empty one. Raises OSError for
    one that does not read, ValueError for a first line that does not parse."""
    with os.fdopen(_open_run(path), "rb") as fh:
        for line in fh:
            if line.strip():
                try:
                    return json.loads(line.decode("utf-8"))
                except RecursionError:
                    raise ValueError("the first line nests too deep") from None
    return None


def _rotation_due(path: str, now) -> bool:
    """Past `ROTATE_AT_BYTES`, or a first record of an earlier UTC day with
    something after it besides a rotation's anchor. A first line that does not
    parse is due too: the break stays in the file it is in."""
    size = os.path.getsize(path)
    if size > ROTATE_AT_BYTES:
        return True
    try:
        first = _first_record(path)
    except ValueError:
        return size > 0
    if first is None:
        return False
    with os.fdopen(_open_run(path), "rb") as fh:
        lines = sum(1 for line in fh if line.strip())
    if first.get("service") == ROTATE_SERVICE and lines == 1:
        return False            # only the anchor of the last rotation
    return str(first.get("ts", ""))[:10] < now.strftime("%Y-%m-%d")


def auto_rotate(now=None) -> tuple:
    """What the hourly timer does: rotate the log when it is due, then remove
    the rotated logs older than the keep-days setting, judged by the time in
    their names, never by their size: a flood must not be able to push the
    record of anyone's earlier actions off the disk. Root only.

    Under install mode ram or none nothing is appended to the log, and a
    rotation's anchor would be a line on disk: no rotation then; the removal
    runs in every mode. The RAM chains are bounded by size instead
    (`_ram_retention`). Returns (lines, ok): a line per thing done, and False
    when something could not be. A run that did nothing writes nothing; one
    that removed files writes one line naming them, to the install's chain."""
    import datetime
    now = now or datetime.datetime.now(datetime.timezone.utc)
    out, ok = [], True
    mode, problem = install_mode()
    if problem:
        out.append(f"not rotated: {problem}")
        ok = False
    elif mode == "disk" and os.path.exists(LOG_PATH):
        try:
            if _rotation_due(LOG_PATH, now):
                out.append(f"rotated: the old log is now {rotate(LOG_PATH, ROTATE_CALLER)}")
        except OSError as e:
            out.append(f"not rotated: {LOG_PATH} ({e.strerror or type(e).__name__})")
            ok = False
    lines, ram_ok = _ram_retention()
    out += lines
    ok = ok and ram_ok
    keep = keep_days()
    if keep is None:
        out.append(f"nothing removed: {KEEP_DAYS_PATH} does not read")
        return out, False
    if keep == "off":
        return out, ok
    moved = clock_moved(now, keep)
    if moved is not None:
        out.append(f"nothing removed: {moved}; once dom0's clock is right, remove "
                   f"{CLOCK_MOVED_PATH}")
        return out, False
    removed, failed = [], []
    cutoff = now - datetime.timedelta(days=keep)
    d = os.path.dirname(LOG_PATH) or "."
    for name, when in rotated(LOG_PATH):
        if when >= cutoff:
            continue
        try:
            os.unlink(os.path.join(d, name))
            removed.append(name)
        except FileNotFoundError:
            continue
        except OSError as e:
            failed.append(f"{name} ({e.strerror or type(e).__name__})")
    if removed or failed:
        audit(REMOVE_SERVICE, ROTATE_CALLER,
              {"removed": removed[:32] + ([f"and {len(removed) - 32} more"]
                                          if len(removed) > 32 else []),
               "keep_days": keep}, not failed,
              None if not failed else "not removed: " + ", ".join(failed)[:512], slots=())
    out += [f"removed {name}: older than {keep} days" for name in removed]
    out += [f"NOT removed {f}" for f in failed]
    return out, ok and not failed


def _ram_retention() -> tuple:
    """Rotate each RAM chain past `RAM_ROTATE_AT_BYTES`, then remove the
    oldest rotated RAM files, by the time in their names, while every RAM file
    together holds more than `RAM_KEEP_BYTES`. One line names what was
    removed. Returns (lines, ok)."""
    d = ram_dir()
    try:
        chains = sorted(n for n in os.listdir(d) if n.endswith(".log"))
    except FileNotFoundError:
        return [], True
    out, ok = [], True
    for n in chains:
        path = os.path.join(d, n)
        try:
            st = os.lstat(path)
            if stat.S_ISREG(st.st_mode) and st.st_size > RAM_ROTATE_AT_BYTES:
                out.append(f"rotated: the old RAM chain is now {rotate(path, ROTATE_CALLER)}")
        except OSError as e:
            out.append(f"not rotated: {path} ({e.strerror or type(e).__name__})")
            ok = False
    old = sorted(((when, name) for n in chains for name, when in rotated(os.path.join(d, n))))

    def total():
        # Regular files only, never followed: a link planted in the directory
        # must neither count nor be read through.
        size = 0
        for n in os.listdir(d):
            try:
                st = os.lstat(os.path.join(d, n))
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                size += st.st_size
        return size
    removed, failed = [], []
    for _, name in old:
        if total() <= RAM_KEEP_BYTES:
            break
        try:
            os.unlink(os.path.join(d, name))
            removed.append(name)
        except FileNotFoundError:
            continue
        except OSError as e:
            # Said, and the next one tried: one that cannot go (a directory
            # planted under its name) must not stop the sweep for good.
            failed.append(f"{name} ({e.strerror or type(e).__name__})")
    if removed or failed:
        audit(REMOVE_SERVICE, ROTATE_CALLER,
              {"removed": removed[:32] + ([f"and {len(removed) - 32} more"]
                                          if len(removed) > 32 else []),
               "ram_keep_bytes": RAM_KEEP_BYTES}, not failed,
              None if not failed else "not removed: " + ", ".join(failed)[:512], slots=())
    out += [f"removed {name}: the RAM chains held more than {RAM_KEEP_BYTES // 1024 ** 2} MiB"
            for name in removed]
    out += [f"NOT removed {f}" for f in failed]
    return out, ok and not failed


def free_bytes(path: str | None = None):
    """The bytes free under `path`'s directory, or None when that cannot be read."""
    path = LOG_PATH if path is None else path
    try:
        st = os.statvfs(os.path.dirname(path) or ".")
    except OSError:
        return None
    return st.f_bavail * st.f_frsize


def room_needed(principals: int, keep) -> int | None:
    """The disk a full budget of every principal for `keep` days takes, or
    None when nothing is ever removed."""
    if not isinstance(keep, int) or isinstance(keep, bool):
        return None
    return principals * AUDIT_LINES_PER_DAY * LINE_BYTES * keep


def status(calls_dir: str, principals, now: str | None = None) -> dict:
    """What `qmcp audit status --json` answers. A value that does not read
    is None, never 0."""
    day, _ = _periods(now)
    mode, problem = install_mode()
    keep = keep_days()

    def size(p):
        try:
            return os.path.getsize(p)
        except FileNotFoundError:
            return 0
        except OSError:
            return None
    d = os.path.dirname(LOG_PATH) or "."
    budgets = []
    for caller, rec in counters(calls_dir):
        lines = None if rec is None else rec.get("lines", 0)
        if rec is not None and rec.get("day") != day:
            today = 0
        elif isinstance(lines, int) and not isinstance(lines, bool) and lines >= 0:
            today = lines
        else:
            today = None                    # a counter that does not read: never 0
        budgets.append({"caller": caller, "lines_today": today, "budget": AUDIT_LINES_PER_DAY})
    return {
        "mode": mode if problem is None else None,
        "keep_days": keep,
        "log": LOG_PATH,
        "log_bytes": size(LOG_PATH),
        "rotated": [{"name": n, "bytes": size(os.path.join(d, n))} for n, _ in rotated(LOG_PATH)],
        "ram": [{"name": n, "bytes": b} for n, b in ram_chains()],
        "free_bytes": free_bytes(LOG_PATH),
        "floor_bytes": FLOOR_BYTES,
        "principals": principals,
        "needed_bytes": None if principals is None else room_needed(principals, keep),
        "budgets": budgets,
    }


#: Longer than any record qmcp writes (a refused call's fields are cut to 128
#: characters each): a longer line is no record, and is not read whole.
VERIFY_MAX_LINE = 1024 * 1024


def verify(path: str | None = None) -> tuple[bool, int, str | None]:
    """Walk the chain from GENESIS. Returns (ok, entries, first problem).
    Streams the file a line at a time, so a log grown large, or a line with
    no end, is never held whole in memory."""
    path = LOG_PATH if path is None else path
    try:
        f = os.fdopen(_open_run(path), "rb")
    except FileNotFoundError:
        return True, 0, None
    except OSError as e:
        return False, 0, f"cannot read log: {e.strerror or type(e).__name__}"
    expected_prev, expected_seq = GENESIS, 1
    i = 0
    try:
        with f:
            # Bytes, decoded line by line: one byte that is not UTF-8 is a
            # broken chain at its line, not an exception in the caller.
            while True:
                raw = f.readline(VERIFY_MAX_LINE + 1)
                if not raw:
                    break
                line = raw.strip()
                if not line:
                    continue
                if len(raw) > VERIFY_MAX_LINE:
                    return False, i + 1, f"line {i + 1} is too long to be a record"
                try:
                    obj = json.loads(line.decode("utf-8"))
                except UnicodeDecodeError:
                    return False, i + 1, f"line {i + 1} is not UTF-8"
                except (ValueError, RecursionError):
                    return False, i + 1, f"unparseable line {i + 1}"
                if not isinstance(obj, dict):
                    return False, i + 1, f"unparseable line {i + 1}"
                if i == 0 and obj.get("service") == ROTATE_SERVICE:
                    # A rotated log starts on the previous file's head hash.
                    expected_prev = obj.get("prev")
                if _body_hash(obj) != obj.get("hash"):
                    return False, obj.get("seq", i + 1), f"hash mismatch at seq {obj.get('seq')}"
                if obj.get("prev") != expected_prev:
                    return False, obj.get("seq", i + 1), f"prev mismatch at seq {obj.get('seq')}"
                if obj.get("seq") != expected_seq:
                    return False, i + 1, f"seq mismatch at index {i + 1}"
                expected_prev, expected_seq = obj["hash"], expected_seq + 1
                i += 1
    except OSError as e:
        return False, i, f"cannot read log: {e.strerror or type(e).__name__}"
    return True, i, None


def verify_links(path: str | None = None) -> tuple[bool, str | None]:
    """Each file of the chain against the next, for the rotated logs still on
    disk: the next file's anchor must carry the head hash and last seq of the
    file it names. `verify` walks one file and trusts its anchor, so records
    cut from the end of a rotated log would otherwise go unseen. A file
    removed by age (the oldest present names one that is gone) is no break.
    Returns (ok, first problem)."""
    path = LOG_PATH if path is None else path
    d = os.path.dirname(path) or "."
    files = [os.path.join(d, n) for n, _ in rotated(path)] + [path]
    for earlier, later in zip(files, files[1:]):
        try:
            first = _first_record(later)
        except (OSError, ValueError):
            return False, f"{os.path.basename(later)}: its first line does not read"
        if not isinstance(first, dict) or first.get("service") != ROTATE_SERVICE:
            continue
        args = first.get("args") or {}
        if args.get("continues") != os.path.basename(earlier):
            continue
        try:
            with os.fdopen(_open_run(earlier), "rb") as fh:
                seq, head = _tail_state(fh)
        except OSError as e:
            return False, f"{os.path.basename(earlier)} cannot be read ({e.strerror})"
        if first.get("prev") != head or args.get("after_seq") != seq:
            return False, (f"{os.path.basename(later)} continues {os.path.basename(earlier)} "
                           f"after seq {args.get('after_seq')}, which ends at seq {seq} with "
                           f"another head: lines are missing from its end")
    return True, None


def _lines_from_the_end(f, block: int = 65536):
    """The non-empty lines of a binary file, last first, read backwards in
    blocks: what iterating it in text mode gives (UTF-8 with replacement,
    universal newlines, stripped), without reading what comes before the
    lines wanted. A cut at a newline byte never splits a UTF-8 character."""
    f.seek(0, os.SEEK_END)
    pos = f.tell()
    carry = b""
    while pos > 0:
        step = min(block, pos)
        pos -= step
        f.seek(pos)
        segs = (f.read(step) + carry).split(b"\n")
        carry = segs.pop(0)          # may continue in the block before
        for seg in reversed(segs):
            yield from _text_lines(seg)
    yield from _text_lines(carry)


def _text_lines(seg: bytes):
    for part in reversed(seg.decode("utf-8", errors="replace").split("\r")):
        part = part.strip()
        if part:
            yield part


def tail(n: int = 20, path: str | None = None, caller: str | None = None) -> list[dict]:
    """The last `n` records, or with `caller` the last `n` of that caller's
    (a line that does not parse belongs to no caller then). A log that does
    not exist yet has none; one that cannot be read raises, so it is never
    shown as an empty one. Read from the end, as far back as the lines it
    returns: the window reads it on every refresh. It verifies nothing
    (`verify` walks the whole chain)."""
    path = LOG_PATH if path is None else path
    out = []
    try:
        with os.fdopen(_open_run(path), "rb") as f:
            if n <= 0:
                return []
            for line in _lines_from_the_end(f):
                try:
                    rec = json.loads(line)
                except (ValueError, RecursionError):
                    rec = {"unparseable": line[:200]}
                if caller is not None and (not isinstance(rec, dict)
                                           or rec.get("caller") != caller):
                    continue
                out.append(rec)
                if len(out) == n:
                    break
    except FileNotFoundError:
        return []
    out.reverse()
    return out
