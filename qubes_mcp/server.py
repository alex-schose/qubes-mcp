"""qubes-mcp: an MCP server over stdio, standard library only.

Speaks newline-delimited JSON-RPC 2.0 on stdin and stdout, one UTF-8 message
per line, and serves the tools in qubes_mcp.tools. It runs in the hub qube or in a
project's lead; an agent reaches it over stdio, often through SSH.

- stdout carries JSON-RPC and nothing else. main() points file descriptor 1 at
  stderr before serving, so a stray print, a library warning or a child
  process can only ever reach stderr, and replies leave through a private
  duplicate of the original stdout. A foreign line on stdout would corrupt the
  client's stream; this makes one impossible rather than unlikely.
- tools/call runs on a pool of 8 worker threads, so a long qubes_events window
  never blocks other calls. Everything else is answered on the reader thread.
- A tool result with "ok": false is a normal result (isError false): the agent
  has to read the refusal. Only an exception inside a handler gives isError
  true, with the fixed text "internal error"; the traceback goes to stderr.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import BinaryIO, Callable, Optional, Union

from qubes_mcp import __version__, tools

log = logging.getLogger(__name__)

SERVER_NAME = "qubes-mcp"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST_VERSION = SUPPORTED_VERSIONS[0]
# Protocol versions whose tool results may carry structuredContent.
STRUCTURED_VERSIONS = frozenset({"2025-06-18"})
WORKERS = 8
# How long in-flight calls may run on after stdin closes. Long enough for a
# create, or a disposable's teardown, to finish rather than be abandoned half
# way; bounded so a dead session cannot keep the process alive indefinitely.
# A qubes_run_disposable still running then has its disposable killed by
# main() before the process leaves (tools.end_abandoned).
EOF_GRACE_SECONDS = 600.0
# On SIGTERM or SIGINT, how long the disposables of calls in flight get to be
# killed and confirmed before the process leaves. Each kill is sent at once;
# the rest is the read-back. A second signal leaves at once.
SIGNAL_TEARDOWN_SECONDS = 30.0

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

Message = Union[dict, list]
Sink = Callable[[Optional[Message]], None]

# Returned by _route when a worker thread will answer later.
_DEFERRED = object()

_ENCODER = json.JSONEncoder(separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _result(msg_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _valid_id(value) -> bool:
    # MCP: a request id is a string or an integer, never null. bool is an int
    # subclass in Python, so it is excluded by hand.
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def _id_key(value):
    # 1 and "1" are different request ids.
    return (type(value).__name__, value)


def _brief(text: str, limit: int = 64) -> str:
    # Method and tool names come from the client; cap what is echoed back.
    shown = repr(text)
    return shown if len(shown) <= limit + 2 else shown[:limit - 1] + "...'"


class _Batch:
    """Collects the answers to one JSON array of messages and sends them as a
    single array once the last one is in. Notifications leave no entry, and if
    nothing is left nothing is sent, as JSON-RPC requires."""

    def __init__(self, size: int, write: Callable[[Message], None]):
        self._answers: list = [None] * size
        self._missing = size
        self._lock = threading.Lock()
        self._write = write

    def slot(self, index: int) -> Sink:
        def fill(answer: Optional[Message]) -> None:
            with self._lock:
                self._answers[index] = answer
                self._missing -= 1
                complete = self._missing == 0
            if complete:
                answers = [a for a in self._answers if a is not None]
                if answers:
                    self._write(answers)
        return fill


class Server:
    """One MCP session: feed it lines with handle_line(), or let serve() read
    a stream until EOF. Replies are written to `out`, a binary stream."""

    def __init__(self, out: BinaryIO, registry: Optional[dict] = None, workers: int = WORKERS):
        self._out = out
        self._registry = tools.TOOLS if registry is None else registry
        self._write_lock = threading.Lock()
        self._out_closed = False
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="qubes-mcp-call")
        self._pending = 0
        self._pending_cv = threading.Condition()
        self._version: Optional[str] = None
        # Calls submitted but not yet started, by request id: whoever takes a
        # call out of here (the worker that starts it, or a cancel) owns it.
        self._queued: dict = {}
        self._queued_lock = threading.Lock()

    # ---- input -----------------------------------------------------------

    def serve(self, inp: BinaryIO, grace: float = EOF_GRACE_SECONDS) -> bool:
        """Answer every line until EOF, then let in-flight calls finish for up
        to `grace` seconds. Returns True when all of them finished."""
        while True:
            try:
                line = inp.readline()
            except OSError as exc:
                log.error("reading stdin failed, treating it as closed: %s", exc)
                break
            if not line:
                break
            self.handle_line(line)
        return self.drain(grace)

    def handle_line(self, line: bytes) -> None:
        if not line.strip():
            return
        try:
            message = tools.parse_json(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            # ValueError also covers an integer too long to convert, and
            # RecursionError a pathologically nested document.
            self._write(_error(None, PARSE_ERROR, "parse error"))
            return
        if isinstance(message, list):
            if not message:
                self._write(_error(None, INVALID_REQUEST, "invalid request: empty batch"))
                return
            batch = _Batch(len(message), self._write)
            for index, element in enumerate(message):
                self._dispatch(element, batch.slot(index))
        else:
            self._dispatch(message, self._write)

    def _dispatch(self, message, sink: Sink) -> None:
        """Answer one message through `sink`, exactly once: a reply, or None
        when nothing is to be sent."""
        try:
            answer = self._route(message, sink)
        except Exception:
            # A bug here must still produce an answer, or the client waits forever.
            log.exception("handling a message failed")
            if isinstance(message, dict) and "id" not in message:
                answer = None
            else:
                msg_id = message.get("id") if isinstance(message, dict) else None
                answer = _error(msg_id if _valid_id(msg_id) else None,
                                INTERNAL_ERROR, "internal error")
        if answer is not _DEFERRED:
            sink(answer)

    def _route(self, message, sink: Sink):
        if not isinstance(message, dict):
            return _error(None, INVALID_REQUEST, "invalid request: not an object")
        if "method" not in message and ("result" in message or "error" in message):
            return None          # a response; this server never sends requests
        has_id = "id" in message
        msg_id = message.get("id")
        if has_id and not _valid_id(msg_id):
            return _error(None, INVALID_REQUEST,
                          "invalid request: id must be a string or an integer")
        reply_id = msg_id if has_id else None
        if message.get("jsonrpc") != "2.0":
            return _error(reply_id, INVALID_REQUEST, 'invalid request: jsonrpc must be "2.0"')
        method = message.get("method")
        if not isinstance(method, str):
            return _error(reply_id, INVALID_REQUEST, "invalid request: method must be a string")
        params = message.get("params")
        if params is not None and not isinstance(params, (dict, list)):
            return _error(reply_id, INVALID_REQUEST,
                          "invalid request: params must be an object or an array")

        if not has_id:
            # A notification is never answered. notifications/cancelled drops
            # a call that has not started yet (a running one is not
            # interrupted: the work is already in a qube or in dom0);
            # notifications/initialized needs nothing, unknown ones are
            # ignored, and a request method sent without an id is NOT executed:
            # a tool call whose result nobody can see would be all side effect
            # and no report.
            if method == "notifications/cancelled" and isinstance(params, dict):
                request_id = params.get("requestId")
                if _valid_id(request_id):
                    self._cancel_queued(_id_key(request_id))
            return None

        if method == "initialize":
            return _result(msg_id, self._initialize(params))
        if method == "ping":
            return _result(msg_id, {})
        if method == "tools/list":
            return _result(msg_id, {"tools": self._list_tools()})
        if method == "tools/call":
            return self._tools_call(msg_id, params, sink)
        return _error(msg_id, METHOD_NOT_FOUND, f"method not found: {_brief(method)}")

    # ---- methods ---------------------------------------------------------

    def _initialize(self, params) -> dict:
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        version = requested if requested in SUPPORTED_VERSIONS else LATEST_VERSION
        self._version = version
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
        }

    def _list_tools(self) -> list:
        return [{"name": t.name, "description": t.description, "inputSchema": t.input_schema}
                for t in self._registry.values()]

    def _tools_call(self, msg_id, params, sink: Sink):
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _error(msg_id, INVALID_PARAMS, "params must be an object")
        name = params.get("name")
        if not isinstance(name, str):
            return _error(msg_id, INVALID_PARAMS, "params.name must be a string naming a tool")
        tool = self._registry.get(name)
        if tool is None:
            return _error(msg_id, INVALID_PARAMS, f"unknown tool: {_brief(name)}")
        try:
            args = tools.validate_arguments(tool, params.get("arguments"))
        except tools.ArgumentError as exc:
            return _error(msg_id, INVALID_PARAMS, f"invalid arguments for {name}: {exc}")
        # A client that never sent initialize gets the newest behaviour.
        version = self._version or LATEST_VERSION
        with self._pending_cv:
            self._pending += 1
        token = object()
        key = _id_key(msg_id)
        with self._queued_lock:
            self._queued.setdefault(key, {})[token] = (msg_id, sink)
        try:
            self._pool.submit(self._run_call, tool, args, msg_id, version, sink, key, token)
        except RuntimeError:     # the pool has been shut down
            self._take(key, token)
            self._call_finished()
            return _error(msg_id, INTERNAL_ERROR, "server is shutting down")
        return _DEFERRED

    def _take(self, key, token) -> bool:
        """Take one queued call out of the queue; False when a cancel had it."""
        with self._queued_lock:
            calls = self._queued.get(key)
            if not calls or token not in calls:
                return False
            del calls[token]
            if not calls:
                del self._queued[key]
            return True

    def _cancel_queued(self, key) -> None:
        """Drop every not-yet-started call under `key`, unanswered, as MCP has
        a cancelled request."""
        with self._queued_lock:
            dropped = list(self._queued.pop(key, {}).values())
        for _, sink in dropped:
            try:
                sink(None)
            finally:
                self._call_finished()

    def _run_call(self, tool: tools.Tool, args: dict, msg_id, version: str, sink: Sink,
                  key=None, token=None) -> None:
        if token is not None and not self._take(key, token):
            return               # cancelled before it started; the cancel answered it
        try:
            sink(_result(msg_id, self._call(tool, args, version)))
        except Exception:
            log.exception("answering a %s call failed", tool.name)
        finally:
            self._call_finished()

    @staticmethod
    def _call(tool: tools.Tool, args: dict, version: str) -> dict:
        try:
            result = tool.handler(args)
            if not isinstance(result, dict):
                raise TypeError(f"{tool.name} returned {type(result).__name__}, not a dict")
            text = json.dumps(result, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except Exception:
            # The agent gets two fixed words; the exception text, which may
            # carry internals, stays on stderr with the traceback.
            log.exception("tool %s raised", tool.name)
            return {"content": [{"type": "text", "text": "internal error"}], "isError": True}
        answer: dict = {"content": [{"type": "text", "text": text}], "isError": False}
        if version in STRUCTURED_VERSIONS:
            answer["structuredContent"] = result
        return answer

    # ---- in-flight accounting --------------------------------------------

    def _call_finished(self) -> None:
        with self._pending_cv:
            self._pending -= 1
            if self._pending == 0:
                self._pending_cv.notify_all()

    def drain(self, timeout: float) -> bool:
        """Wait up to `timeout` seconds for in-flight calls, queued ones
        included, to be answered, then stop the worker pool. Returns True if
        none was left running. A queued call is not dropped at EOF: a client
        that writes its requests and closes its end at once (a pipe) still
        reads the answers; one it no longer wants it cancels."""
        deadline = time.monotonic() + timeout
        with self._pending_cv:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._pending_cv.wait(remaining)
            left = self._pending
        if left:
            log.warning("%d call(s) still running %.0fs after stdin closed; exiting without them",
                        left, timeout)
            self._pool.shutdown(wait=False, cancel_futures=True)
            return False
        self._pool.shutdown(wait=True)
        return True

    # ---- output ----------------------------------------------------------

    def _write(self, message: Optional[Message]) -> None:
        if message is None:
            return
        try:
            # Pure ASCII on the wire. json.dumps escapes every control
            # character, so a newline inside a string can never split a
            # message; ensure_ascii also escapes U+2028, U+2029 and U+0085,
            # which some line readers (str.splitlines among them) treat as
            # line breaks. Encoded as a list of pieces, written one by one: a
            # reply can be large (a command's output, up to qrexec.MAX_REPLY,
            # twice over with structuredContent), and one string of the whole
            # line plus its bytes would hold it twice more. The list is built
            # before anything is written, so a reply that cannot be encoded
            # never leaves half a line.
            pieces = list(_ENCODER.iterencode(message))
        except (TypeError, ValueError, RecursionError):
            log.exception("a reply could not be encoded")
            if not (isinstance(message, dict) and "id" in message):
                return
            pieces = [json.dumps(_error(message["id"], INTERNAL_ERROR, "internal error"))]
        pieces.append("\n")
        with self._write_lock:
            if self._out_closed:
                return
            try:
                for piece in pieces:
                    self._out.write(piece.encode("ascii"))
                self._out.flush()
            except (OSError, ValueError) as exc:
                self._out_closed = True
                log.error("stdout is gone (%s); further replies are dropped", exc)


def _claim_stdout() -> BinaryIO:
    """Keep the real stdout for protocol replies and point fd 1 at stderr."""
    sys.stdout.flush()
    fd = sys.stdout.fileno()
    protocol_out = os.fdopen(os.dup(fd), "wb")
    os.dup2(sys.stderr.fileno(), fd)
    sys.stdout = sys.stderr
    return protocol_out


_leaving = False


def _on_signal(signum, frame) -> None:
    """SIGTERM or SIGINT: kill the disposables of calls in flight, bounded,
    then leave with the shell's status for the signal. A client closing a
    session often sends SIGTERM shortly after closing stdin, well inside the
    end-of-input grace, so this is the path that usually runs."""
    global _leaving
    if _leaving:
        os._exit(128 + signum)
    _leaving = True
    log.warning("signal %d: ending the disposables of calls in flight, then leaving", signum)
    try:
        tools.end_abandoned(SIGNAL_TEARDOWN_SECONDS)
    except Exception:
        log.exception("ending the disposables of abandoned calls failed")
    sys.stderr.flush()
    os._exit(128 + signum)


def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                        format="qubes-mcp: %(levelname)s: %(message)s")
    out = _claim_stdout()
    server = Server(out)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, _on_signal)
    try:
        # The grace is read here, not bound as serve()'s default, so a test
        # can shorten it.
        drained = server.serve(sys.stdin.buffer, grace=EOF_GRACE_SECONDS)
    except KeyboardInterrupt:
        sys.stderr.flush()
        os._exit(130)
    if not drained:
        # A qubes_run_disposable still in flight would leave its disposable
        # running: end those first, bounded like the call's own teardown. A
        # failure here must not keep the process from leaving.
        try:
            tools.end_abandoned(tools.TEARDOWN_SECONDS)
        except Exception:
            log.exception("ending the disposables of abandoned calls failed")
    sys.stderr.flush()
    if not drained:
        # Worker threads are still blocked in qrexec calls, and the
        # interpreter would wait for them at exit; leave without them.
        os._exit(0)
    return 0
