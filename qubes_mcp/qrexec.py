"""qrexec transport for the qubes-mcp tools.

Every call leaves the hub (or a project's lead) through qrexec-client-vm, in one of three shapes:

- call_qmcp:    a qmcp.* service in dom0 (target @adminvm); JSON in, JSON out.
- call_service: a qmcp.* service inside a named qube; JSON in, JSON out.
- call_admin:   an admin.* method aimed at a named qube; Admin API framing.

Every failure the transport itself can produce collapses to exactly
{"ok": false, "error": "not found or refused"}: a policy refusal, a qube that
does not exist, a crashed service, empty stdout, output that is not a JSON
object, a timeout, a client binary that cannot be started. This is a security
property. A distinct answer per cause would let the agent tell "refused" from
"does not exist", which is an existence oracle for qubes it must not see, and
raw exception text can carry dom0 internals. dom0's own refusals arrive as JSON
objects and pass through unchanged.

Two answers are not that refusal, and neither is an oracle, because each can
only follow a call the policy allowed and its far end answered or worked on:
a reply longer than MAX_REPLY gives {"ok": false, "error": "reply too large"},
and call_qmcp's caller may name its own reply for a call that got no answer in
time (a create that dom0 may still finish).
"""
from __future__ import annotations

import json
import logging
import os
import re
import selectors
import subprocess
import threading
import time

log = logging.getLogger(__name__)

DEFAULT_CLIENT = "/usr/lib/qubes/qrexec-client-vm"
# The test suite points this at a fake client. Whoever can set the server's
# environment already controls the process, so the override widens nothing.
CLIENT_ENV = "QUBES_MCP_QREXEC_CLIENT"

REFUSED = "not found or refused"
TOO_LARGE = "reply too large"

# The longest reply read, in bytes. qubes_run hands back whatever a command in a
# qube prints, so the qube decides the size; a reply is held, decoded, parsed and
# serialised for the agent, each a copy, and an unbounded one lets any qube the
# hub or a lead operates exhaust that server's memory.
MAX_REPLY = 16 * 1024 * 1024


def refused() -> dict:
    """The one opaque refusal. A fresh dict each time, so no caller can mutate a shared one."""
    return {"ok": False, "error": REFUSED}


def too_large() -> dict:
    return {"ok": False, "error": TOO_LARGE}


def client_path() -> str:
    return os.environ.get(CLIENT_ENV) or DEFAULT_CLIENT


# The shape a tool-supplied qube name must have before it may become a qrexec
# TARGET (qubes_run, qubes_copy, the firewall tools, and the disposable that
# qubes_run_disposable is handed back by dom0). A Qubes VM name is a letter
# followed by up to 30 more of [A-Za-z0-9_.-] (Qubes' own 31-character limit).
# Anything else (a qrexec @-token such as @adminvm, @dispvm or @tag:..., the
# plain-name special target `dom0`, whitespace, argv metacharacters, empty, or
# overlong) is refused BEFORE any qrexec call, so an agent-supplied name cannot
# ride a policy line meant for another target, and cannot inject an option into
# qrexec-client-vm's argv. This is defence in depth in the untrusted process: a
# compromised hub or lead bypasses it, which is why the dom0 policy is scoped on its
# own. `dom0` passes the charset, so it is denied explicitly, in any letter case.
# \A ... \Z, not ^...$: Python's `$` also matches just before a trailing
# newline, so `^...$` would accept "dom0\n" and forward the newline to
# qrexec-client-vm, past both the charset and the reserved-name check.
_VALID_TARGET_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9_.-]{0,30}\Z")
_RESERVED_TARGETS = {"dom0"}


def _valid_target(name) -> bool:
    return (isinstance(name, str)
            and _VALID_TARGET_RE.match(name) is not None
            and name.lower() not in _RESERVED_TARGETS)


def _reject_constant(token: str):
    # json.loads accepts NaN/Infinity by default; they are not JSON.
    raise ValueError(f"non-JSON constant {token}")


def _encode(payload: dict | None) -> bytes:
    # ensure_ascii (the default) keeps the request pure ASCII whatever it carries.
    return b"" if payload is None else json.dumps(payload).encode("ascii")


# qubes_run and qubes_copy derive their wait from an agent-chosen integer, and
# subprocess raises OverflowError for an absurd one (10**30). Clamp instead.
_MAX_WAIT = 86400.0
_CHUNK = 65536

# What _run returns, besides a CompletedProcess, when no whole reply was read.
_FAILED = None              # the client could not run, or its pipe broke
_TIMED_OUT = "timed out"    # no complete reply within the timeout
_OVERSIZE = "too large"     # the reply passed MAX_REPLY


def _feed(pipe, data: bytes, target: str, service: str) -> None:
    """Write the request and close the client's stdin, in a thread of its own:
    a client that answers before it has read the whole request would otherwise
    block on a full stdout pipe while this process blocks writing its stdin."""
    try:
        with pipe:
            pipe.write(data)
    except OSError as exc:
        # The client exited, or was killed, before it read everything: its
        # answer (or its absence) decides the call.
        log.info("qrexec %s -> %s: request not fully written: %s", service, target,
                 type(exc).__name__)


def _read(proc, deadline: float):
    """stdout until EOF: a bytearray, _OVERSIZE once past MAX_REPLY, or
    _TIMED_OUT at the deadline. Read in chunks, so at most MAX_REPLY plus one
    chunk is ever held, and handed back without a copy."""
    fd = proc.stdout.fileno()
    buf = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return _TIMED_OUT
            if not selector.select(left):
                continue
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                return buf
            buf += chunk
            if len(buf) > MAX_REPLY:
                return _OVERSIZE


def _run(target: str, service: str, stdin: bytes, timeout: float):
    """Run qrexec-client-vm once. Returns the CompletedProcess, or _FAILED,
    _TIMED_OUT or _OVERSIZE (the callers turn each into a fixed reply).

    stderr goes to /dev/null: nothing reads it, and a pipe nobody reads would
    stall a client that writes much there, while one read into memory is a
    second unbounded buffer. The client is killed on any outcome but a
    complete reply from a client that then exits by the deadline."""
    timeout = min(timeout, _MAX_WAIT)
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen([client_path(), target, service], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        # Operator-side detail only: stderr, never the agent.
        log.warning("qrexec %s -> %s failed: %s: %s", service, target, type(exc).__name__, exc)
        return _FAILED
    writer = threading.Thread(target=_feed, args=(proc.stdin, stdin, target, service),
                              name="qubes-mcp-qrexec-stdin", daemon=True)
    writer.start()
    outcome = _FAILED
    lagged = False
    try:
        outcome = _read(proc, deadline)
        if isinstance(outcome, bytearray):
            # stdout is closed, so the reply is whole; give the client what is
            # left to exit. One that does not is killed, and the reply stands
            # with no exit status known.
            proc.wait(timeout=max(deadline - time.monotonic(), 0.001))
    except subprocess.TimeoutExpired:
        lagged = True
        log.info("qrexec %s -> %s: whole reply read, client still running at the deadline",
                 service, target)
    except OSError as exc:
        log.warning("qrexec %s -> %s failed: %s: %s", service, target, type(exc).__name__, exc)
        outcome = _FAILED
    finally:
        if lagged or not isinstance(outcome, bytearray):
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log.warning("qrexec %s -> %s: client did not exit after a kill", service, target)
        proc.stdout.close()
        writer.join(timeout=5)
    if outcome is _TIMED_OUT:
        log.warning("qrexec %s -> %s: no answer within %.0fs", service, target, timeout)
        return _TIMED_OUT
    if outcome is _OVERSIZE:
        log.warning("qrexec %s -> %s: reply too large (over %d bytes); client killed", service,
                    target, MAX_REPLY)
        return _OVERSIZE
    if outcome is _FAILED:
        return _FAILED
    # A client killed after its reply has no exit status of its own: None,
    # which call_admin, the one caller that reads it, refuses.
    return subprocess.CompletedProcess(proc.args, None if lagged else proc.returncode,
                                       outcome, None)


def _no_reply(proc, on_timeout: dict | None = None) -> dict | None:
    """The fixed reply for a call that produced no reply to parse, else None."""
    if proc is _OVERSIZE:
        return too_large()
    if proc is _TIMED_OUT and on_timeout is not None:
        return dict(on_timeout)
    if proc is _FAILED or proc is _TIMED_OUT:
        return refused()
    return None


def _decode(stdout: bytes | bytearray, service: str) -> dict:
    """Parse a qmcp.* reply: exactly one JSON object, else the opaque refusal.

    The exit status is deliberately not consulted. The dom0 services print a
    JSON refusal and exit 1, and that refusal ("pool cap exceeded", say) is
    meant to reach the agent. A policy denial or a crash leaves stdout empty or
    unparseable, and collapses here.
    """
    try:
        # Not stripped: json.loads skips surrounding whitespace itself, and a
        # strip would copy a reply that may be MAX_REPLY long.
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("qrexec %s: reply is not UTF-8", service)
        return refused()
    if not text or text.isspace():
        # The normal shape of a policy denial, so not worth a warning.
        log.info("qrexec %s: empty reply", service)
        return refused()
    try:
        obj = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        log.warning("qrexec %s: reply is not JSON (%d bytes)", service, len(stdout))
        return refused()
    if not isinstance(obj, dict):
        log.warning("qrexec %s: reply is JSON but not an object", service)
        return refused()
    return obj


def call_qmcp(service: str, payload: dict | None = None, timeout: float = 60.0, *,
              on_timeout: dict | None = None) -> dict:
    """Invoke a qmcp.* service in dom0 and return its JSON reply.

    Convention: every qmcp.* service writes one JSON object to stdout,
    {"ok": true, ...} or {"ok": false, "error": "..."}. Qube names travel in the
    payload, where dom0 checks them, so there is no target to validate here.

    `on_timeout`: the reply to give, in place of the opaque refusal, when no
    answer came within `timeout`. dom0 goes on with a call whose client gave up,
    so a create may yet make its qube; the caller says so with fixed text.
    """
    proc = _run("@adminvm", service, _encode(payload), timeout)
    failed = _no_reply(proc, on_timeout)
    if failed is not None:
        return failed
    return _decode(proc.stdout, service)


def call_service(qube: str, service: str, payload: dict | None = None,
                 timeout: float = 120.0) -> dict:
    """Invoke a qmcp.* service inside a NAMED qube (qmcp.RunInAIManaged,
    qmcp.CopyToAIManaged). Policy decides whether the caller may reach it."""
    if not _valid_target(qube):
        # Byte-identical to a policy denial, so a rejected name is no
        # validation oracle; no subprocess is started.
        return refused()
    proc = _run(qube, service, _encode(payload), timeout)
    failed = _no_reply(proc)
    if failed is not None:
        return failed
    return _decode(proc.stdout, service)


def call_admin(method: str, vm_name: str, payload: bytes = b"", timeout: float = 60.0) -> dict:
    """Invoke an admin.* qrexec method aimed at a named qube (the firewall
    methods). Returns {"ok": true, "stdout": "<payload>"} or the opaque refusal.

    Admin API framing: a reply starts with a status byte and a NUL, b"0\\x00" on
    success or b"2\\x00<exception>..." on an in-band failure, followed by the
    payload. The header is stripped on success; an in-band failure collapses to
    the opaque refusal like every other failure. A reply without the header is
    passed through as it is.
    """
    if not _valid_target(vm_name):
        return refused()
    proc = _run(vm_name, method, payload, timeout)
    failed = _no_reply(proc)
    if failed is not None:
        return failed
    if proc.returncode != 0:
        return refused()
    raw = proc.stdout
    if len(raw) >= 2 and raw[1:2] == b"\x00":
        if raw[0:1] != b"0":
            return refused()
        raw = raw[2:]
    return {"ok": True, "stdout": raw.decode("utf-8", errors="replace")}
