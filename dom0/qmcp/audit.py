"""qmcp.audit — the hash-chained, AI-unreachable record of state changes.

Every state-changing qmcp.* call appends one JSON line to
/var/log/qmcp-audit.log, and so does every command of the operator's that
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
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os

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

#: Past this size `qmcp check` asks the operator to rotate. The services run as
#: an unprivileged user who cannot create files in /var/log, so rotation is the
#: operator's (`qmcp audit rotate`), not automatic.
ROTATE_AT_BYTES = 32 * 1024 * 1024

ROTATE_SERVICE = "qmcp.audit-rotate"


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
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o660)
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
    f.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
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


def rotate(path: str | None = None) -> str:
    """Rename the log aside and start a new one whose first record anchors on
    the old head, so the chain continues across files. Operator only (root).
    Returns the name the old log now has."""
    path = LOG_PATH if path is None else path
    f = _locked_log(path)
    try:
        seq, head = _tail_state(f)
        st = os.fstat(f.fileno())
        import datetime
        aside = path + "." + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        os.rename(path, aside)
        nfd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o660)
        try:
            os.fchown(nfd, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.fchmod(nfd, st.st_mode & 0o7777)
        with os.fdopen(nfd, "r+b") as nf:
            record = {"v": SCHEMA, "ts": _utc_now_iso(), "service": ROTATE_SERVICE,
                      "caller": "operator", "args": {"continues": os.path.basename(aside),
                                               "after_seq": seq},
                      "ok": True, "error": None, "seq": 1, "prev": head}
            record["hash"] = _body_hash(record)
            _write(nf, record)
        return aside
    finally:
        f.close()


#: Lines that could not be written are counted here, on tmpfs, which a full
#: /var does not fill: `qmcp check` fails while it exists. Created by the
#: first failure (root or the services' user: /run/qmcp is setgid qubes) and
#: removed by the operator, never by qmcp; a reboot or `uninstall.sh` clears
#: it with the rest of /run/qmcp, so a gap is told until then.
DROPPED_PATH = "/run/qmcp/audit-dropped"
#: Below this much free space under the log's directory the services refuse
#: every state-changing call before it acts, but a kill (which only takes
#: away, and is logged only when dom0 accepted it): no other change is made
#: without its line.
FLOOR_BYTES = 64 * 1024 * 1024


#: A principal's calls that changed nothing (refused, failed, or a feature, or
#: a property set explicitly, set to the value already there) are logged up to this many in each clock hour (UTC)
#: each; past it they are counted in `<run>/calls/<caller>.refused`, on
#: tmpfs, and `qmcp check` warns while that counts one (a reboot clears it). A
#: failed create that made a qube, or may have, is always logged.
#: Without the cap a compromised principal could fill the log's disk down to
#: the floor, one failed call at a time, and stop every lead's changes.
REFUSALS_PER_HOUR = 60
REFUSED_SUFFIX = ".refused"


#: Each principal may put this many lines a day (UTC) on the log for calls
#: that changed something; past it, its state-changing calls are refused
#: before they act (a kill goes on), counted in the same file, not logged. One
#: compromised principal then spends only its own budget, and the 64 MiB
#: floor stays the backstop for all of them. Lines of calls that changed
#: nothing are under the hourly cap above and do not spend it.
AUDIT_LINES_PER_DAY = 20000


def _update(path: str, change):
    """Read-modify-write the caller's counter under its lock. `change(rec)`
    edits the dict and returns the answer. Raises when the counter cannot be
    opened, read or written: each caller decides which way that fails."""
    old = os.umask(0o007)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o660)
    finally:
        os.umask(old)
    with os.fdopen(fd, "r+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        text = fh.read(4096)
        rec = json.loads(text) if text.strip() else {}
        if not isinstance(rec, dict):
            raise ValueError("counter is not an object")
        answer = change(rec)
        fh.seek(0)
        fh.truncate()
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return answer


def take_refusal(path: str, now: str | None = None) -> bool:
    """Count one call that changed nothing, of the caller whose counter is
    `path`. True when its line may be written (under the cap this hour);
    False when it is counted instead. A counter that cannot be kept logs the
    line: the cap only ever withholds a line it has counted."""
    now = now or _utc_now_iso()

    def change(rec):
        if rec.get("hour") != now[:13]:
            rec["hour"], rec["logged"] = now[:13], 0
        if int(rec.get("logged", 0)) < REFUSALS_PER_HOUR:
            rec["logged"] = int(rec.get("logged", 0)) + 1
            return True
        rec["unlogged"] = int(rec.get("unlogged", 0)) + 1
        rec["first"] = rec.get("first") or now
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
    now = now or _utc_now_iso()

    def change(rec):
        if rec.get("day") == now[:10] and int(rec.get("lines", 0)) >= AUDIT_LINES_PER_DAY:
            rec["over"] = int(rec.get("over", 0)) + 1
            rec["over_first"] = rec.get("over_first") or now
            return False
        return True
    try:
        return _update(path, change)
    except Exception:
        return None


def budget_spent(path: str, now: str | None = None) -> bool:
    """Has this caller spent today's share? Read only, under the counter's
    lock; a counter that does not read counts as spent. For a kill, which acts
    whatever the answer: it decides only whether its line is capped."""
    now = now or _utc_now_iso()
    try:
        with open(path, encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            text = fh.read(4096)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    try:
        rec = json.loads(text) if text.strip() else {}
        return rec.get("day") == now[:10] and int(rec.get("lines", 0)) >= AUDIT_LINES_PER_DAY
    except Exception:
        return True


def spend(path: str, now: str | None = None) -> None:
    """One line of a call that changed something, against the day's budget.
    Best-effort: a counter that cannot be kept is caught by `budget_left`."""
    now = now or _utc_now_iso()

    def change(rec):
        if rec.get("day") != now[:10]:
            rec["day"], rec["lines"] = now[:10], 0
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
            with open(os.path.join(calls_dir, fn), encoding="utf-8") as fh:
                # Under the writers' lock, shared: `_update` truncates before
                # it writes, and an unlocked read could catch the gap.
                fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                text = fh.read(4096)
            rec = json.loads(text) if text.strip() else {}
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
    now = now or _utc_now_iso()
    out = []
    for caller, rec in counters(calls_dir):
        if rec is None:
            continue
        today = int(rec.get("lines", 0) or 0) if rec.get("day") == now[:10] else 0
        over = int(rec.get("over", 0) or 0)
        if today >= AUDIT_LINES_PER_DAY or over:
            out.append((caller, today, over, rec.get("over_first")))
    return out


def room(path: str | None = None) -> bool:
    """True when the log's directory has `FLOOR_BYTES` free. False when it has
    not, or when that cannot be read: a gate, so it fails toward refusing."""
    path = LOG_PATH if path is None else path
    try:
        st = os.statvfs(os.path.dirname(path) or ".")
    except OSError:
        return False
    return st.f_bavail * st.f_frsize >= FLOOR_BYTES


def dropped(path: str | None = None):
    """(lines not written, first time) from the marker, or None without one;
    (None, None) for a marker that does not read."""
    try:
        with open(DROPPED_PATH if path is None else path, encoding="utf-8") as fh:
            rec = json.loads(fh.read(4096))
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
            fd = os.open(DROPPED_PATH, os.O_RDWR | os.O_CREAT, 0o660)
        finally:
            os.umask(old)
        with os.fdopen(fd, "r+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                rec = json.loads(fh.read(4096) or "{}")
                count, first = int(rec.get("count", 0)), str(rec.get("first") or _utc_now_iso())
            except Exception:
                count, first = 0, _utc_now_iso()
            fh.seek(0)
            fh.truncate()
            fh.write(json.dumps({"count": count + 1, "first": first}) + "\n")
    except Exception:
        pass


def audit(service, caller, summary, ok, error=None, error_class=None,
          path: str | None = None) -> bool:
    """Record one state-changing call. Returns True if a line was written; a
    line that was not is counted (`DROPPED_PATH`)."""
    written = _audit(service, caller, summary, ok, error, error_class, path)
    if not written:
        _note_dropped()
    return written


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


def verify(path: str | None = None) -> tuple[bool, int, str | None]:
    """Walk the chain from GENESIS. Returns (ok, entries, first problem)."""
    path = LOG_PATH if path is None else path
    try:
        with open(path, encoding="utf-8") as f:
            lines = [s for s in (ln.strip() for ln in f) if s]
    except FileNotFoundError:
        return True, 0, None
    except OSError as e:
        return False, 0, f"cannot read log: {e.strerror}"
    expected_prev, expected_seq = GENESIS, 1
    for i, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except ValueError:
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
    return True, len(lines), None


def tail(n: int = 20, path: str | None = None) -> list[dict]:
    """The last `n` records. A log that does not exist yet has none; one that
    cannot be read raises, so it is never shown as an empty one."""
    path = LOG_PATH if path is None else path
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [s for s in (ln.strip() for ln in f) if s]
    except FileNotFoundError:
        return []
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({"unparseable": line[:200]})
    return out
