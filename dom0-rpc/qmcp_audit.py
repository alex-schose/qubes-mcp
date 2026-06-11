"""qmcp_audit — shared dom0 helper for the tamper-evident AI action log.

Stage I-2. Before this stage there was no dom0 record of what the AI
*did*: `/var/log/qmcp-changes.log` records the operator's slot deploys,
not the agent's calls. This helper adds a hash-chained, AI-unreachable
trail of every state-changing `qmcp.*` invocation — foundational before
graduated authority (I-3+) and **mandatory before the I-10 vault's
`qmcp.SignTransaction`** (design: STAGE-I-BUILD-PLAN.md §4 I-2,
STAGE-I-DESIGN.md §18.6).

What it provides
----------------
`audit(service, args_summary, ok, error)` appends one JSON line to
`/var/log/qmcp-audit.log`. Each line carries `prev` — the sha256 of the
preceding line — and `hash` — the sha256 of its own canonical content.
Any deletion, edit, reordering, or insertion therefore breaks the chain
and is caught by `verify()`. The log is created `root:qubes` `0660` at
install time (the wrappers run under qrexec as a non-root dom0 user in the
`qubes` group, so group-write is what lets them append) and is written
under an exclusive `flock`, so concurrent dom0 wrappers serialise cleanly.

Two load-bearing properties
---------------------------
1. **Tamper-EVIDENT, not tamper-proof.** A root attacker in dom0 can
   rewrite the whole chain from any point forward (it is a local hash
   chain, not a notarised one). What it guarantees is that *partial*
   edits — deleting the one line that records a destructive call, say —
   cannot be hidden: the break is detectable. Notarisation / external
   anchoring is out of scope for the minimum version (I-10 may add it
   alongside the vault).
2. **AI-unreachable by construction.** No `qmcp.*` service reads or
   writes an arbitrary dom0 path, and no qrexec policy line exposes this
   file. There is therefore no surface through which an ai-managed qube
   can read past entries or append forged ones. The agent's only
   relationship to this log is that the dom0 wrappers it calls write to
   it on its behalf. (This is why the I-1 read-scope work matters: the
   audit log records real out-of-scope names the agent supplied, which
   is fine precisely because the agent can never read the log back.)

Contracts the callers rely on
-----------------------------
- **BEST-EFFORT.** `audit()` never raises and never blocks the wrapped
  operation. It returns True on a written line, False on any failure.
  A wrapper that cannot log still completes its operation — the call
  sites guard it in `emit()` as well, so an audit bug can never change
  what AI sees or whether the op runs. (I-10 introduces a *fail-closed*
  variant for `SignTransaction`: refuse to sign if the call can't be
  logged. That is a deliberate, surface-specific upgrade — the default
  here stays best-effort so logging never becomes a denial-of-service
  lever on ordinary operations.)
- **THE CALLER SANITISES `args_summary`.** Pass qube names, property
  keys, feature keys, actions, device ports — structural identifiers
  only. NEVER pass secret-bearing values (property/feature *values*,
  and — at I-10 — key material). This helper records whatever dict it is
  handed, verbatim. Keeping secrets out of the log is the wrapper's job,
  and the wrappers do it by *building the summary from a whitelist of
  named fields* rather than forwarding the raw request — so a value
  field cannot leak in by omission.

Deferred to I-10 (noted, not implemented here)
----------------------------------------------
Log rotation (size cap / logrotate that preserves chain continuity
across a roll) and the fail-closed `SignTransaction` variant. The
minimum version reads the whole file to find the tail on each append —
O(n) in the line count, fine at the low call volume of a single agent,
and the rotation work is where that is addressed.

Loaded by the wrappers via `importlib.util.spec_from_file_location`
against `os.path.dirname(os.path.realpath(__file__))`, the same
sibling-import shim Stage I-0 introduced for `qmcp_budget.py` and I-1
for `qmcp_scope.py` (deviation from the Qubes self-contained-rpc-script
convention is recorded as reviewer ask #12 in `public/README.md`).
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys

#: Where the trail lives. dom0-only — see the
#: "AI-unreachable by construction" note above. Exposed as a module
#: attribute so offline validation can redirect it to a temp file; the
#: production wrappers never reassign it, and qrexec services in dom0 run
#: with a fixed environment AI cannot influence, so there is no override
#: surface in production. Owned `root:qubes` mode `0660` (set at install
#: time): the qrexec wrappers run as a non-root dom0 user that is in the
#: `qubes` group (it has to be, to reach qubesd), so group-write lets them
#: append; root owns it; AI is in neither — and has no dom0 file access at
#: all — so it can still neither read nor forge entries.
LOG_PATH = "/var/log/qmcp-audit.log"

#: `prev` of the very first entry: sha256 of the empty string. A fixed,
#: well-known anchor so `verify()` has a defined chain origin.
GENESIS = hashlib.sha256(b"").hexdigest()

#: Log-line schema version. Lets a future reader / rotation distinguish
#: format generations (the I-10 fail-closed variant, rotation headers)
#: without guessing.
SCHEMA = 1


def _utc_now_iso() -> str:
    """UTC timestamp, ISO-8601, second precision. Isolated for testability."""
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj: dict) -> bytes:
    """Deterministic byte serialisation for hashing: sorted keys (all
    levels), compact separators. The hash must be reproducible by
    `verify()`, so the serialisation must be canonical."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _body_hash(record: dict) -> str:
    """sha256 over the record's canonical form excluding its own `hash`
    field. `prev` is part of the body, so each hash transitively commits
    to the entire prefix of the chain."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _tail_state(f) -> tuple[int, str]:
    """Return (last_seq, last_hash) from the file's current tail, or
    (0, GENESIS) when the log is empty or its tail line is unparseable.

    A corrupt tail is treated as a chain origin rather than a hard error:
    best-effort logging must still append (we never drop an action record
    because an earlier line was damaged), and anchoring the new entry on
    GENESIS makes the discontinuity loud — `verify()` flags both the
    `prev` mismatch and the `seq` reset rather than silently papering
    over the damage."""
    last = None
    f.seek(0)
    for line in f:
        s = line.strip()
        if s:
            last = s
    if last is None:
        return 0, GENESIS
    try:
        obj = json.loads(last)
        return int(obj["seq"]), str(obj["hash"])
    except Exception:
        return 0, GENESIS


def _append(record: dict) -> bool:
    """Append one fully-formed record under an exclusive lock. Computes
    seq/prev/hash from the tail while holding the lock so concurrent
    wrappers cannot interleave and fork the chain."""
    # The wrapper runs under qrexec as a NON-root dom0 user (uid 1000, in the
    # `qubes` group) — NOT root. So we must NOT fchmod here: the file is owned
    # root:qubes 0660 (set at install time, see the module docstring), the
    # writer is not its owner, and an fchmod by a non-owner raises EPERM —
    # which would make every append fail. We open the existing, group-writable
    # file and append; ownership/perms are an install-time concern, not ours.
    fd = os.open(LOG_PATH, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o660)
    try:
        with os.fdopen(fd, "r+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                prev_seq, prev_hash = _tail_state(f)
                record["seq"] = prev_seq + 1
                record["prev"] = prev_hash
                record["hash"] = _body_hash(record)
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return True
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        return False


def audit(service, args_summary, ok, error=None) -> bool:
    """Record one state-changing `qmcp.*` call. Best-effort; see module
    docstring for the two caller contracts (best-effort + caller-sanitises).

    Returns True if a chained line was written, False on any failure.
    Never raises."""
    try:
        record = {
            "v": SCHEMA,
            "ts": _utc_now_iso(),
            "service": str(service),
            "args": args_summary if isinstance(args_summary, dict) else {},
            "ok": bool(ok),
            "error": None if error is None else str(error),
        }
        return _append(record)
    except Exception:
        return False


def verify(path: str = None) -> tuple[bool, int, str]:
    """Walk the chain from the origin and confirm it is intact.

    Returns (ok, n_entries, error). A missing or empty log verifies
    trivially as (True, 0, None) — there is nothing to tamper with.
    On the first anomaly returns (False, seq_or_index, reason):
      - "unparseable line N"      — not valid JSON
      - "hash mismatch at seq S"  — a field was edited
      - "prev mismatch at seq S"  — a line was deleted / reordered / inserted
      - "seq mismatch at index I" — sequence numbers are not 1..N contiguous
    """
    if path is None:
        path = LOG_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [s for s in (ln.strip() for ln in f) if s]
    except FileNotFoundError:
        return True, 0, None
    except Exception as e:
        return False, 0, f"cannot read log: {e}"

    expected_prev = GENESIS
    expected_seq = 1
    for i, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except Exception:
            return False, i + 1, f"unparseable line {i + 1}"
        if _body_hash(obj) != obj.get("hash"):
            return False, obj.get("seq", i + 1), f"hash mismatch at seq {obj.get('seq')}"
        if obj.get("prev") != expected_prev:
            return False, obj.get("seq", i + 1), f"prev mismatch at seq {obj.get('seq')}"
        if obj.get("seq") != expected_seq:
            return False, i + 1, f"seq mismatch at index {i + 1}"
        expected_prev = obj["hash"]
        expected_seq += 1
    return True, len(lines), None


def _cli(argv) -> int:
    """`python3 qmcp_audit.py verify [path]` — operator / slot chain check."""
    if len(argv) >= 2 and argv[1] == "verify":
        path = argv[2] if len(argv) >= 3 else LOG_PATH
        ok, n, err = verify(path)
        print(json.dumps({"ok": ok, "entries": n, "error": err}))
        return 0 if ok else 1
    print(json.dumps({"ok": False, "error": "usage: qmcp_audit.py verify [path]"}))
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
