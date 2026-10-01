"""qmcp.audit — the hash-chained, AI-unreachable record of state changes.

Every state-changing qmcp.* call appends one JSON line to
/var/log/qmcp-audit.log. Each line carries `prev`, the sha256 of the line
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

Schema 2 (0.9.17) adds `caller` (the qrexec source) and `error_class` (the
exception class behind a fixed-vocabulary error, so the operator can see what
the caller was not told). Lines of schema 1 chain on unchanged. A write reads
only the end of the file, and `qmcp audit rotate` moves the log aside and
starts a new one anchored on the old head.

The wrappers run as a non-root dom0 user in the `qubes` group. The installer
creates the log root:qubes 0660; this module never chmods it, because a
non-owner fchmod is EPERM and would make every append fail.
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


def _locked_log(path: str):
    """The log opened for append and exclusively locked, as a binary file.

    After taking the lock, check the file is still the one at `path`: a
    rotation may have renamed it while this call waited, and a line appended
    to the renamed file would fork the chain.
    """
    for _ in range(5):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o660)
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
                      "caller": None, "args": {"continues": os.path.basename(aside),
                                               "after_seq": seq},
                      "ok": True, "error": None, "seq": 1, "prev": head}
            record["hash"] = _body_hash(record)
            _write(nf, record)
        return aside
    finally:
        f.close()


def audit(service, caller, summary, ok, error=None, error_class=None,
          path: str | None = None) -> bool:
    """Record one state-changing call. Returns True if a line was written."""
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
    path = LOG_PATH if path is None else path
    try:
        with open(path, encoding="utf-8") as f:
            lines = [s for s in (ln.strip() for ln in f) if s]
    except OSError:
        return []
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({"unparseable": line[:200]})
    return out
