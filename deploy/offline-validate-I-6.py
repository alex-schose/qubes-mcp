#!/usr/bin/env python3
"""offline-validate-I-6.py — exhaustive offline validation of Stage I-6
(the operator-consent MECHANISM, shipped INERT).

Ships in public/deploy/ alongside the test-stage-*.py harnesses. This is the
BULK of I-6 coverage — the analogue of offline-validate-I-{2,3,4,5}.py. It runs
PURE PYTHON in mcp-control with NO dom0 dependency: it imports the REAL
`qmcp_consent.py` helper (a sibling in public/dom0-rpc/) and exercises every
branch of the policy parser, the wire protocol against an IN-PROCESS MOCK
AF_UNIX daemon faithful to the frozen protocol, and the gate() composition.

Trust-boundary note. Three-way split, same as the earlier stages:
  - OFFLINE (this file, mcp-control, pure python)  → the bulk: helper logic +
    a faithful mock daemon. NO real daemon, NO /etc/qmcp/consent-policy read.
  - test-stage-I-6.py (mcp-control, hardware)      → AI-SIDE invariance +
    absence-of-surface: the empty gate is byte-neutral, no qmcp.* service
    exposes the policy or the socket, opaque-refusal parity.
  - the SLOT (dom0)                                → the daemon starts, the
    socket is 0660 root:qubes, and the empty gate pops NO dialog on hardware.

What this file proves:
  1. consent_required: empty policy  => NOTHING gated (the I-6 case).
  2. consent_required: missing file  => MALFORMED => fail-closed DEFAULT_GATED.
  3. consent_required: any bad line   => MALFORMED => fail-closed DEFAULT_GATED.
  4. consent_required: exact match + '*' wildcard match on a well-formed policy.
  5. request_consent against a FAITHFUL in-process mock daemon:
        approved / denied / timeout pass through;
        nonce mismatch => "denied" (never a soft-fail toward approval);
        malformed reply => "denied";
        socket absent / connect-refused => "unavailable".
  6. gate() composition: ungated => (True,"open") WITHOUT opening the socket
     (the TEETH check — the empty-gate invariance); gated => maps the verdict.
  7. _t_gate() reads /etc/qmcp/consent-timeout, default 300 on any error, and
     request_consent's recv timeout is _t_gate()+10.

Run from the repo root:   .venv/bin/python deploy/offline-validate-I-6.py
or from inside public/:   python3 deploy/offline-validate-I-6.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import tempfile
import threading
import time

# This file lives in public/deploy/; the helper it loads is a sibling in
# public/dom0-rpc/. Resolve it relative to THIS file's directory (the same
# os.path.dirname(os.path.realpath(__file__)) sibling-load the dom0 wrappers
# use), so it runs from the repo root AND from inside public/.
HERE = os.path.dirname(os.path.realpath(__file__))
CONSENT_PATH = os.path.join(HERE, os.pardir, "dom0-rpc", "qmcp_consent.py")

_passed = 0
_failed = 0


def check(label, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")


def load_consent():
    """Load qmcp_consent.py fresh (it HAS a .py extension, so a normal
    spec_from_file_location works — this is the same module the dom0 wrappers
    sibling-load as /etc/qubes-rpc/qmcp_consent.py)."""
    spec = importlib.util.spec_from_file_location("qmcp_consent", CONSENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


qc = load_consent()


def write_tmp(text):
    """Write `text` to a fresh temp file and return its path (caller unlinks)."""
    fd, path = tempfile.mkstemp(prefix="qmcp-i6-policy-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class wire_paths:
    """Context manager that redirects the helper's DEFAULT policy/socket paths.

    gate() calls consent_required(service, action) and request_consent(service,
    action, summary) POSITIONALLY — the policy_path / socket_path defaults are
    keyword-only and were BOUND at def-time from the module constants, so simply
    reassigning qc.POLICY_PATH / qc.SOCKET_PATH after import does NOT reach them.
    Patch the functions' __kwdefaults__ (and the module constants, for any code
    that reads them directly) for the duration, then restore. This is faithful:
    we exercise the real gate() → consent_required()/request_consent() call
    chain unchanged, only redirecting where they look for the policy + socket."""

    def __init__(self, *, policy_path=None, socket_path=None):
        self.policy_path = policy_path
        self.socket_path = socket_path

    def __enter__(self):
        self._saved_const = (qc.POLICY_PATH, qc.SOCKET_PATH)
        self._saved_cr = dict(qc.consent_required.__kwdefaults__ or {})
        self._saved_rc = dict(qc.request_consent.__kwdefaults__ or {})
        if self.policy_path is not None:
            qc.POLICY_PATH = self.policy_path
            qc.consent_required.__kwdefaults__["policy_path"] = self.policy_path
        if self.socket_path is not None:
            qc.SOCKET_PATH = self.socket_path
            qc.request_consent.__kwdefaults__["socket_path"] = self.socket_path
        return self

    def __exit__(self, *exc):
        qc.POLICY_PATH, qc.SOCKET_PATH = self._saved_const
        qc.consent_required.__kwdefaults__.clear()
        qc.consent_required.__kwdefaults__.update(self._saved_cr)
        qc.request_consent.__kwdefaults__.clear()
        qc.request_consent.__kwdefaults__.update(self._saved_rc)
        return False


# ==========================================================================
# A FAITHFUL in-process mock consent daemon.
#
# It speaks the frozen wire protocol EXACTLY (newline-delimited JSON over an
# AF_UNIX SOCK_STREAM socket): read one request line, echo the request's nonce
# (unless told to corrupt it), reply {"v":1,"nonce":..,"verdict":..}. It can be
# told to: return a fixed verdict, corrupt the echoed nonce, send malformed
# (non-JSON) bytes, delay before replying, or record whether it was connected
# to at all (the teeth of the empty-gate invariance — the daemon must NEVER be
# reached when nothing is gated).
# ==========================================================================
class MockDaemon:
    def __init__(self, *, verdict="approved", corrupt_nonce=False,
                 malformed=False, delay=0.0):
        self.verdict = verdict
        self.corrupt_nonce = corrupt_nonce
        self.malformed = malformed
        self.delay = delay
        self.connections = 0          # how many times a client connected
        self.last_request = None      # the last request dict we parsed
        self._dir = tempfile.mkdtemp(prefix="qmcp-i6-sock-")
        self.path = os.path.join(self._dir, "consent.sock")
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.path)
        self._srv.listen(8)
        self._srv.settimeout(5.0)
        self._stop = False
        self._t = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._t.start()
        return self

    def _recv_line(self, conn):
        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                return None
            chunks.append(data)
            if b"\n" in data:
                break
        return b"".join(chunks).split(b"\n", 1)[0].decode("utf-8", "replace")

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            try:
                line = self._recv_line(conn)
                if line is None:
                    conn.close()
                    continue
                try:
                    req = json.loads(line)
                    self.last_request = req
                except Exception:
                    req = {}
                if self.delay:
                    time.sleep(self.delay)
                if self.malformed:
                    conn.sendall(b"this-is-not-json\n")
                else:
                    nonce = req.get("nonce", "")
                    if self.corrupt_nonce:
                        nonce = "0" * 32
                    resp = {"v": 1, "nonce": nonce, "verdict": self.verdict}
                    conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def stop(self):
        self._stop = True
        try:
            self._srv.close()
        except Exception:
            pass
        try:
            os.unlink(self.path)
        except OSError:
            pass
        try:
            os.rmdir(self._dir)
        except OSError:
            pass


# ==========================================================================
print("=== Stage I-6 offline validation ===\n")

# --------------------------------------------------------------------------
print("### Section 1 — consent_required: policy parsing (the inert I-6 case)")

# The I-6 shipped default: an all-comments / blank file → EMPTY gate → nothing
# gated. This is the invariance that keeps the stage byte-neutral.
empty = write_tmp("# only comments\n\n   \n#qmcp.LifecycleAIManaged:remove\n")
try:
    none_gated = all(
        not qc.consent_required(s, a, policy_path=empty)
        for (s, a) in [
            ("qmcp.LifecycleAIManaged", "remove"),
            ("qmcp.LifecycleAIManaged", "kill"),
            ("qmcp.AttachDeviceAIManaged", "attach"),
            ("qmcp.DetachDeviceAIManaged", "detach"),
            ("qmcp.SetPropertyAIManaged", "set-property"),
            ("qmcp.SpawnAIManagedQube", "spawn"),
        ]
    )
    check("empty (all-comments) policy → NOTHING gated (I-6 invariance)", none_gated)
finally:
    os.unlink(empty)

# Missing file → MALFORMED regime → fail-closed to DEFAULT_GATED.
missing = os.path.join(tempfile.gettempdir(), "qmcp-i6-does-not-exist-zzz")
check("missing policy → fail-closed: DEFAULT_GATED gated",
      qc.consent_required("qmcp.LifecycleAIManaged", "remove", policy_path=missing)
      and qc.consent_required("qmcp.AttachDeviceAIManaged", "attach", policy_path=missing))
check("missing policy → fail-closed: a NON-default pair stays UNGATED",
      not qc.consent_required("qmcp.SetPropertyAIManaged", "set-property", policy_path=missing))
check("DEFAULT_GATED is exactly the 4 wrapper-reachable destructive/high-blast pairs",
      qc.DEFAULT_GATED == frozenset({
          ("qmcp.LifecycleAIManaged", "remove"),
          ("qmcp.LifecycleAIManaged", "kill"),
          ("qmcp.AttachDeviceAIManaged", "attach"),
          ("qmcp.DetachDeviceAIManaged", "detach"),
      }))

# Any unparseable non-comment line → MALFORMED → fail-closed default gate,
# even though other lines look valid (a corrupt policy denies MORE, never less).
malformed = write_tmp(
    "qmcp.LifecycleAIManaged:remove\n"      # valid line
    "this-line-has-no-colon\n"              # malformed → whole file malformed
    "qmcp.SetPropertyAIManaged:set-property\n"
)
try:
    check("any bad line → MALFORMED → fail-closed DEFAULT_GATED (kill gated)",
          qc.consent_required("qmcp.LifecycleAIManaged", "kill", policy_path=malformed))
    check("malformed policy does NOT honour its own (would-be valid) lines",
          not qc.consent_required("qmcp.SetPropertyAIManaged", "set-property",
                                  policy_path=malformed))
finally:
    os.unlink(malformed)

# Empty service or empty action on a colon line is also malformed.
for bad_text, lbl in [(":remove", "empty service"),
                      ("qmcp.LifecycleAIManaged:", "empty action"),
                      ("a:b:c", "too many colons")]:
    p = write_tmp(bad_text + "\n")
    try:
        check(f"malformed line ({lbl}) → fail-closed DEFAULT_GATED",
              qc.consent_required("qmcp.LifecycleAIManaged", "remove", policy_path=p))
    finally:
        os.unlink(p)

# --------------------------------------------------------------------------
print("\n### Section 2 — consent_required: well-formed non-empty policy (I-7 preview)")

# Exact match + wildcard '*' match on a clean, non-empty policy. This is the
# I-7 case; here we prove the PARSER honours it (I-6 ships empty, so no wrapper
# reaches this path yet, but the logic must be correct for I-7).
clean = write_tmp(
    "# operator policy\n"
    "qmcp.LifecycleAIManaged:remove\n"
    "qmcp.SetPropertyAIManaged:*\n"
)
try:
    check("exact match: LifecycleAIManaged:remove is gated", qc.consent_required(
        "qmcp.LifecycleAIManaged", "remove", policy_path=clean))
    check("exact non-match: LifecycleAIManaged:start is NOT gated", not qc.consent_required(
        "qmcp.LifecycleAIManaged", "start", policy_path=clean))
    check("wildcard: SetPropertyAIManaged:* gates set-property", qc.consent_required(
        "qmcp.SetPropertyAIManaged", "set-property", policy_path=clean))
    check("wildcard: SetPropertyAIManaged:* gates any OTHER action too", qc.consent_required(
        "qmcp.SetPropertyAIManaged", "anything", policy_path=clean))
    check("a service with no rule at all is NOT gated (clean policy)", not qc.consent_required(
        "qmcp.CloneAIManagedQube", "clone", policy_path=clean))
finally:
    os.unlink(clean)

# --------------------------------------------------------------------------
print("\n### Section 3 — request_consent: faithful mock daemon (the wire protocol)")

# approved / denied / timeout pass straight through.
for verdict in ("approved", "denied", "timeout"):
    d = MockDaemon(verdict=verdict).start()
    try:
        got = qc.request_consent("qmcp.LifecycleAIManaged", "remove",
                                 {"target": "ai-x"}, socket_path=d.path)
        check(f"request_consent: daemon says {verdict!r} → {verdict!r}", got == verdict)
        # The request the daemon received must carry v=1, a 32-hex nonce, and
        # the whitelisted summary — proving the helper emits the frozen shape.
        req = d.last_request or {}
        check(f"  → request wire-shape correct (v=1, 32-hex nonce, principal) [{verdict}]",
              req.get("v") == 1
              and isinstance(req.get("nonce"), str) and len(req["nonce"]) == 32
              and req.get("principal") == "mcp-control"
              and req.get("summary") == {"target": "ai-x"})
    finally:
        d.stop()

# Nonce mismatch → "denied" (never a soft-fail toward approval), even though the
# daemon "approved". This is the anti-replay / anti-confusion guarantee.
d = MockDaemon(verdict="approved", corrupt_nonce=True).start()
try:
    got = qc.request_consent("qmcp.LifecycleAIManaged", "remove",
                             {"target": "ai-x"}, socket_path=d.path)
    check("request_consent: nonce mismatch → 'denied' (not 'approved')", got == "denied")
finally:
    d.stop()

# Malformed (non-JSON) reply → "denied".
d = MockDaemon(malformed=True).start()
try:
    got = qc.request_consent("qmcp.LifecycleAIManaged", "remove",
                             {"target": "ai-x"}, socket_path=d.path)
    check("request_consent: malformed reply → 'denied'", got == "denied")
finally:
    d.stop()

# Socket absent (no daemon) → "unavailable" (ENOENT on connect).
absent_sock = os.path.join(tempfile.gettempdir(), "qmcp-i6-no-socket-zzz.sock")
try:
    os.unlink(absent_sock)
except OSError:
    pass
got = qc.request_consent("qmcp.LifecycleAIManaged", "remove",
                         {"target": "ai-x"}, socket_path=absent_sock)
check("request_consent: socket absent → 'unavailable'", got == "unavailable")

# A verdict outside the allowed set from an otherwise-valid reply → "denied".
d = MockDaemon(verdict="maybe").start()
try:
    got = qc.request_consent("qmcp.LifecycleAIManaged", "remove",
                             {"target": "ai-x"}, socket_path=d.path)
    check("request_consent: unknown verdict token → 'denied'", got == "denied")
finally:
    d.stop()

# --------------------------------------------------------------------------
print("\n### Section 4 — gate(): composition + the EMPTY-GATE TEETH check")

# TEETH: under an empty policy, gate() must return (True,"open") WITHOUT ever
# opening the socket. We point the helper's socket at a LIVE mock daemon and its
# policy at an EMPTY file; a correct gate() short-circuits in consent_required()
# and never connects, so the daemon's connection counter must stay ZERO. If
# gate() opened the socket on the ungated path, this counter would be 1 and
# behaviour would NOT be byte-neutral vs the pre-I-6 tree.
d = MockDaemon(verdict="approved").start()
empty = write_tmp("# empty gate (I-6)\n")
with wire_paths(policy_path=empty, socket_path=d.path):
    ok, verdict = qc.gate("qmcp.LifecycleAIManaged", "remove", {"target": "ai-x"})
check("gate(): empty policy → (True, 'open')", ok is True and verdict == "open")
check("gate(): TEETH — empty-gate path NEVER opened the socket "
      f"(daemon connections={d.connections})", d.connections == 0)
os.unlink(empty)
d.stop()

# gate() on a GATED pair asks the daemon and maps the verdict. approved→True,
# every other verdict→False, and each opens the socket exactly once.
for verdict, want_ok in [("approved", True), ("denied", False),
                         ("timeout", False)]:
    d = MockDaemon(verdict=verdict).start()
    clean = write_tmp("qmcp.LifecycleAIManaged:remove\n")
    with wire_paths(policy_path=clean, socket_path=d.path):
        ok, got = qc.gate("qmcp.LifecycleAIManaged", "remove", {"target": "ai-x"})
    check(f"gate(): gated + daemon {verdict!r} → (ok={want_ok}, {verdict!r})",
          ok is want_ok and got == verdict)
    check(f"  → gated path opened the socket exactly once [{verdict}]",
          d.connections == 1)
    os.unlink(clean)
    d.stop()

# gate() with the daemon DOWN (gated pair, no socket) → (False, "unavailable"):
# fail-closed, the wrapper then emits the opaque "not found or refused".
clean = write_tmp("qmcp.LifecycleAIManaged:remove\n")
down_sock = os.path.join(tempfile.gettempdir(), "qmcp-i6-down-zzz.sock")
try:
    os.unlink(down_sock)
except OSError:
    pass
with wire_paths(policy_path=clean, socket_path=down_sock):
    ok, got = qc.gate("qmcp.LifecycleAIManaged", "remove", {"target": "ai-x"})
check("gate(): gated + daemon DOWN → (False, 'unavailable') [FAIL-CLOSED]",
      ok is False and got == "unavailable")
os.unlink(clean)

# --------------------------------------------------------------------------
print("\n### Section 5 — _t_gate(): timeout read + recv-timeout ordering")

# _t_gate reads /etc/qmcp/consent-timeout; default 300 on any error. We can't
# point the module constant at a temp file without patching, so exercise the
# default (the real path is absent in mcp-control) and a patched path.
check("_t_gate() default is 300 (real timeout file absent in mcp-control)",
      qc._t_gate() == qc.DEFAULT_TIMEOUT == 300)

saved_timeout = qc.TIMEOUT_PATH
tf = write_tmp("120\n")
try:
    qc.TIMEOUT_PATH = tf
    check("_t_gate() reads an integer timeout file → 120", qc._t_gate() == 120)
finally:
    qc.TIMEOUT_PATH = saved_timeout
    os.unlink(tf)

tf = write_tmp("not-an-int\n")
try:
    qc.TIMEOUT_PATH = tf
    check("_t_gate() non-integer content → default 300", qc._t_gate() == 300)
finally:
    qc.TIMEOUT_PATH = saved_timeout
    os.unlink(tf)

# CLAMP band: T_gate is clamped to [MIN_TIMEOUT, MAX_TIMEOUT] so the frozen
# ordering T_gate < recv(=T_gate+10) < T_mcp(360) holds for ANY operator file
# content. A zero/negative typo saturates UP to MIN_TIMEOUT (never disables the
# dialog auto-expiry / collapses the recv backstop); a huge value saturates DOWN
# to MAX_TIMEOUT (never pushes recv past the 360 MCP ceiling). This is the fix
# that makes the hardcoded GATED_TIMEOUT=360 in tools/_qrexec.py safe against
# operator edits (mcp-control can't read the dom0 file, so the clamp is the
# coupling). The daemon's own _t_gate() clamps to the identical band.
check("MIN_TIMEOUT/MAX_TIMEOUT band is [5, 340] (keeps recv<=350 < 360)",
      qc.MIN_TIMEOUT == 5 and qc.MAX_TIMEOUT == 340
      and qc.MAX_TIMEOUT + qc._RECV_SLACK < 360)
for val, want in [("0", 5), ("-30", 5), ("3", 5), ("5", 5), ("340", 340),
                  ("341", 340), ("400", 340), ("600", 340), ("120", 120)]:
    tf = write_tmp(val + "\n")
    try:
        qc.TIMEOUT_PATH = tf
        check(f"_t_gate() clamps {val!r} → {want}", qc._t_gate() == want)
    finally:
        qc.TIMEOUT_PATH = saved_timeout
        os.unlink(tf)

# recv timeout = T_gate + _RECV_SLACK (so the daemon's zenity --timeout, == T_gate,
# always fires first and the recv is only a backstop). Prove the arithmetic by
# reading the module constants, and prove the ORDERING holds against a delayed
# mock: a daemon that replies AFTER T_gate but BEFORE T_gate+slack still gets its
# reply through (recv did not trip early).
check("_RECV_SLACK is 10 (recv = T_gate + 10, the frozen ordering)",
      qc._RECV_SLACK == 10)

# Delayed-reply ordering probe with a SHORT T_gate so the test is fast: point
# TIMEOUT_PATH at "1" → clamped UP to MIN_TIMEOUT(5), so recv = 5 + 10 = 15s; the
# daemon delays 2s then replies "approved". recv must NOT trip early (that would
# be "unavailable"); it must wait out the daemon and return "approved". (The clamp
# floor is exactly why a "1" typo can't collapse the recv backstop to ~11s.)
d = MockDaemon(verdict="approved", delay=2.0).start()
tf = write_tmp("1\n")
saved_timeout = qc.TIMEOUT_PATH
try:
    qc.TIMEOUT_PATH = tf
    got = qc.request_consent("qmcp.LifecycleAIManaged", "remove",
                             {"target": "ai-x"}, socket_path=d.path)
    check("recv timeout is T_gate+10 (delayed reply past T_gate still lands)",
          got == "approved")
finally:
    qc.TIMEOUT_PATH = saved_timeout
    os.unlink(tf)
    d.stop()

# --------------------------------------------------------------------------
print("\n### Section 6 — consent-oracle parity: the refusal branch matches the "
      "wrapper's OWN tag/tier sentinel (no oracle)")

# The frozen contract requires a denied/timed-out/unavailable consent to return
# the SAME opaque sentinel a tag/tier denial returns IN THAT WRAPPER — else, once
# I-7 arms a policy line, AI could tell 'operator refused consent' apart from
# 'target untagged/under-tier'. The MCP layer passes non-empty wrapper JSON
# through verbatim, so the two strings would be distinguishable. This is a STATIC
# teeth check on the shipped wrapper source (the wrappers need a mocked
# qubesadmin to run, so we assert the coded branch, not a live call): the consent
# branch must return the wrapper's NOT_FOUND (7 wrappers) or its cross-ref
# fail(...) message (Spawn) — and must NEVER return "not found or refused" as a
# CODE return (that MCP-layer string may appear only in comments).
DOM0_RPC = os.path.join(HERE, os.pardir, "dom0-rpc")

# 7 wrappers whose tag/tier denial is `emit(NOT_FOUND)` — the consent branch
# must be `emit(NOT_FOUND)` too.
NOT_FOUND_WRAPPERS = [
    "qmcp.LifecycleAIManaged", "qmcp.SetPropertyAIManaged",
    "qmcp.CloneAIManagedQube", "qmcp.SetFeatureAIManaged",
    "qmcp.AttachDeviceAIManaged", "qmcp.DetachDeviceAIManaged",
    "qmcp.SpawnDisposableAIManaged",
]


def _consent_return_line(wrapper_src):
    """Return the CODE line immediately following the `_consent_gate(...)` guard
    — i.e. the wrapper's consent-refusal return — stripped, or None."""
    lines = wrapper_src.splitlines()
    for i, ln in enumerate(lines):
        if "_consent_gate(" in ln and ln.lstrip().startswith("if not "):
            # the next non-blank line is the refusal return
            for nxt in lines[i + 1:]:
                if nxt.strip():
                    return nxt.strip()
    return None


for w in NOT_FOUND_WRAPPERS:
    with open(os.path.join(DOM0_RPC, w), encoding="utf-8") as fh:
        src = fh.read()
    ret = _consent_return_line(src)
    check(f"{w}: consent branch returns emit(NOT_FOUND) (parity w/ tag/tier)",
          ret == "return emit(NOT_FOUND)")
    check(f"{w}: consent branch does NOT return the MCP 'not found or refused' string",
          ret is not None and "not found or refused" not in ret)

# Spawn's tag/tier denial is the cross-ref message, so its consent branch must
# match THAT (not NOT_FOUND — Spawn has no NOT_FOUND path; an untagged/under-tier
# template surfaces as the cross-ref fail()).
with open(os.path.join(DOM0_RPC, "qmcp.SpawnAIManagedQube"), encoding="utf-8") as fh:
    spawn_src = fh.read()
spawn_ret = _consent_return_line(spawn_src)
check("qmcp.SpawnAIManagedQube: consent branch returns the cross-ref fail() "
      "(parity w/ template tag/tier denial)",
      spawn_ret == 'return fail("template must reference an ai-managed qube")')
check("qmcp.SpawnAIManagedQube: consent branch does NOT return 'not found or refused'",
      spawn_ret is not None and "not found or refused" not in spawn_ret)

# ==========================================================================
print(f"\n=== I-6 offline: {_passed} passed, {_failed} failed ===")
raise SystemExit(1 if _failed else 0)
