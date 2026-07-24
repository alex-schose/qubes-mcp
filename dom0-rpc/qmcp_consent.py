"""qmcp_consent — shared dom0 helper for the operator-consent action gate.

Stage I-6, the first sub-stage of the action axis (Wave 2). It ships the
consent MECHANISM but leaves it INERT: the installed `/etc/qmcp/consent-policy`
gates the EMPTY set, so `consent_required()` returns False for every call and no
wrapper ever consults the daemon. Behaviour is therefore byte-neutral vs the
current tree — proven by INVARIANCE, the Stage I-3 pattern (an empty-gate policy
means the socket is never even opened). Enforcement — a non-empty operator policy
that actually pops the consent dialog — is Stage I-7.

What this helper provides
-------------------------
Three call-site entry points the eight `@adminvm` wrappers use, plus the
policy-parse and timeout-read primitives underneath them:

  consent_required(service, action) -> bool
      Does the operator's policy gate this (service, action)? Parses
      `/etc/qmcp/consent-policy`. FAIL-CLOSED on a missing or malformed file:
      falls back to DEFAULT_GATED (the destructive-by-default set). An empty
      (all-comments/blank) policy is the I-6 case: parses cleanly to an empty
      gate set, so nothing is gated.

  request_consent(service, action, summary) -> "approved"|"denied"|"timeout"|"unavailable"
      Ask the consent daemon over the AF_UNIX socket. Newline-delimited JSON
      wire protocol; a fresh 32-hex nonce per request that the reply must echo.
      Any socket error (ENOENT / ECONNREFUSED / EACCES / recv-timeout) =>
      "unavailable"; a nonce mismatch or malformed reply => "denied".

  gate(service, action, summary) -> (ok: bool, verdict: str)
      The composition the wrapper calls. If the policy does not gate this pair,
      returns (True, "open") WITHOUT touching the socket (the teeth of the
      empty-gate invariance). Otherwise asks the daemon and maps the verdict.

Fail-closed, like the I-5 tier check (a missing/broken resolver DENIES) — the
OPPOSITE of the best-effort I-2 audit hook. A denied / timed-out / unavailable
consent surfaces at the wrapper as the SAME opaque refusal a tag or tier denial
surfaces — the wrapper's own sentinel (for 7 of the 8 wrappers that is
`{"ok":false,"error":"not found"}`; SpawnAIManagedQube reuses its cross-ref
message instead) — so the gate is not an oracle. (Historically this doc and the
wrapper comments claimed the shared string was "not found or refused"; that was
wrong — "not found or refused" is only what the MCP layer collapses an EMPTY
stdout / policy-deny to, never what a wrapper's own tag/tier denial prints. The
consent branch matches the wrapper's tag/tier sentinel, not that MCP string.)

Timeout ordering (kills the split-brain — a late click must never execute after
the agent already saw a refusal):

    T_gate (dialog auto-expiry, /etc/qmcp/consent-timeout, default 300s)
      < helper socket recv timeout (= T_gate + 10)
      < T_mcp (MCP-side client timeout for gated tools, 360s constant).

On expiry the DAEMON returns verdict "timeout" (its `zenity --timeout` fires
first); the helper's recv timeout is only a backstop; the MCP client (360)
outlasts both.

Loaded by the wrappers via `importlib.util.spec_from_file_location` against
`os.path.dirname(os.path.realpath(__file__))`, the same sibling-import shim
Stage I-0 introduced for qmcp_budget / qmcp_scope / qmcp_audit / qmcp_tier —
so the same module runs in dom0 (`/etc/qubes-rpc/qmcp_consent.py`) and in
offline-validation on mcp-control (`public/dom0-rpc/qmcp_consent.py`) with no
sys.path dependency (reviewer ask #12 in `public/README.md`).
"""
from __future__ import annotations

import json
import os
import secrets
import socket

#: Operator-owned policy selecting which (service, action) pairs require
#: consent. One `service:action` per line ('#' comments, blank lines ignored;
#: action '*' = any action of that service). Shipped EMPTY at I-6 (the mechanism
#: is inert). Re-read per call so operator edits take effect with no daemon
#: restart, mirroring F3's `/etc/qmcp/pool-cap`.
POLICY_PATH = "/etc/qmcp/consent-policy"

#: The AF_UNIX SOCK_STREAM socket the daemon binds inside the 2770 root:qubes
#: `/run/qmcp` dir and chmods 0660 — reachable by the wrapper user (uid 1000,
#: group `qubes`) and by the operator GUI session (also uid 1000, group
#: `qubes`), unreachable by AI (no dom0 file access, no service exposes it).
SOCKET_PATH = "/run/qmcp/consent.sock"

#: Operator-owned dialog auto-expiry (seconds). Read per call; default 300 on
#: any error. This is T_gate — the innermost of the three timeouts.
TIMEOUT_PATH = "/etc/qmcp/consent-timeout"

#: The (service, action) pairs that are BOTH the fail-closed default (used when
#: the policy file is missing/malformed) AND the intended I-7 default gate set.
#: WRAPPER-REACHABLE ONLY: firewall.{Set,Reload} and exec/copy are policy-scoped
#: surfaces, not `@adminvm` wrappers, so they cannot be gated here — only the
#: eight wrapper surfaces can. The default names the destructive/high-blast ops.
DEFAULT_GATED = frozenset({
    ("qmcp.LifecycleAIManaged", "remove"),
    ("qmcp.LifecycleAIManaged", "kill"),
    ("qmcp.AttachDeviceAIManaged", "attach"),
    ("qmcp.DetachDeviceAIManaged", "detach"),
})

#: Fallback dialog auto-expiry when the timeout file is absent/unreadable.
DEFAULT_TIMEOUT = 300

#: T_gate clamp band, MIRRORING the daemon's. The frozen ordering
#: T_gate < helper_recv(=T_gate+_RECV_SLACK) < T_mcp(360) must hold for ANY
#: content of the operator-editable timeout file, so T_gate is clamped into
#: [MIN_TIMEOUT, MAX_TIMEOUT]. MAX_TIMEOUT=340 keeps helper_recv = 340+10 = 350
#: < 360 even at the ceiling; MIN_TIMEOUT=5 stops a zero/negative typo from
#: collapsing the recv backstop to ~10s while the daemon's dialog (clamped the
#: same way) stays open. The daemon's own _t_gate() clamps to the identical band.
MIN_TIMEOUT = 5
MAX_TIMEOUT = 340

#: Slack added to the helper's socket recv timeout over T_gate, so the daemon's
#: own `zenity --timeout` always fires first and the recv is only a backstop.
_RECV_SLACK = 10


def _t_gate() -> int:
    """Read the dialog auto-expiry (T_gate) from `/etc/qmcp/consent-timeout`.

    Returns the integer seconds, or DEFAULT_TIMEOUT (300) on any error —
    missing file, non-integer content, unreadable — and CLAMPS an in-range-parse
    to [MIN_TIMEOUT, MAX_TIMEOUT] so the recv timeout (= T_gate + _RECV_SLACK)
    can never invert the frozen T_gate < recv < T_mcp(360) ordering regardless of
    what the operator wrote in the file. The daemon reads and clamps the same
    file independently to the identical band, so operator edits to the timeout
    apply without a daemon restart on the next request.
    """
    try:
        with open(TIMEOUT_PATH, encoding="utf-8") as fh:
            v = int(fh.read().strip())
    except Exception:
        return DEFAULT_TIMEOUT
    return max(MIN_TIMEOUT, min(v, MAX_TIMEOUT))


def _parse_policy(text: str):
    """Parse consent-policy text into a set of (service, action) gate pairs.

    Each real line is `service:action`; '#' comments and blank lines are
    ignored. Returns (gateset, malformed): `malformed` is True if ANY
    non-comment line does not split into exactly a non-empty service and a
    non-empty action. An all-comments/blank file parses to an empty gateset
    with malformed=False (the I-6 case).
    """
    gate: set = set()
    malformed = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) != 2:
            malformed = True
            continue
        service, action = parts[0].strip(), parts[1].strip()
        if not service or not action:
            malformed = True
            continue
        gate.add((service, action))
    return gate, malformed


def consent_required(service, action, *, policy_path=POLICY_PATH) -> bool:
    """True iff the operator policy gates this (service, action).

    Parse `policy_path`:
      - file MISSING            => MALFORMED => fail-closed: gate DEFAULT_GATED.
      - ANY unparseable line    => MALFORMED => fail-closed: gate DEFAULT_GATED.
      - parses to an EMPTY set  => the I-6 case: return False for everything.
      - otherwise               => (service, action) in the parsed set, honouring
                                    an action of '*' as any action of that service.

    Fail-closed like the I-5 tier check: an absent or corrupt policy denies more
    (gates the destructive default), never less. AI cannot influence this file
    (no dom0 write surface), so the fail-closed branch is an operator-integrity
    guard, not an AI-reachable lever.

    INSTALL INVARIANT (not optional): I-6 byte-neutrality REQUIRES the empty
    policy file to be PRESENT while the patched wrappers are live. If the file is
    absent, this branch fires => the 4 DEFAULT_GATED ops (Lifecycle remove/kill,
    Attach, Detach) route to the daemon and — with the daemon down or a gate that
    denies — fail-closed, a behaviour CHANGE from pre-I-6 (which proceeded). The
    installer ships the empty policy in step 5 BEFORE the wrappers in step 6, and
    the uninstaller must restore the hook-free wrappers BEFORE deleting the
    policy, so the wrappers and this file are never live-but-policyless. The
    empty policy is a required install artifact, not a convenience default.
    """
    try:
        with open(policy_path, encoding="utf-8") as fh:
            text = fh.read()
    except Exception:
        # Missing / unreadable => malformed regime => fail-closed default gate.
        return (service, action) in DEFAULT_GATED

    gate, malformed = _parse_policy(text)
    if malformed:
        return (service, action) in DEFAULT_GATED
    if (service, action) in gate:
        return True
    if (service, "*") in gate:
        return True
    return False


def request_consent(service, action, summary, *, socket_path=SOCKET_PATH,
                    principal="mcp-control") -> str:
    """Ask the consent daemon and return its verdict.

    Returns "approved" | "denied" | "timeout" | "unavailable".

    Wire protocol (newline-delimited JSON over AF_UNIX SOCK_STREAM):
      request  {"v":1,"nonce":<32-hex>,"service":..,"action":..,
                "principal":..,"summary":..}
      response {"v":1,"nonce":<same>,"verdict":..}

    A fresh 32-hex nonce is sent and the reply MUST echo it; a mismatch or any
    malformed reply is treated as "denied" (never a soft-fail toward approval).
    Any socket error (ENOENT / ECONNREFUSED / EACCES / recv-timeout) =>
    "unavailable". The recv timeout is T_gate + 10, so the daemon's own
    `zenity --timeout` (== T_gate) always fires first and returns "timeout";
    the recv timeout is only a backstop for a wedged daemon.
    """
    nonce = secrets.token_hex(16)  # 32 hex chars
    req = {
        "v": 1,
        "nonce": nonce,
        "service": service,
        "action": action,
        "principal": principal,
        "summary": summary if isinstance(summary, dict) else {},
    }
    recv_timeout = _t_gate() + _RECV_SLACK

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(recv_timeout)
        try:
            sock.connect(socket_path)
        except OSError:
            # ENOENT / ECONNREFUSED / EACCES — daemon down or unreachable.
            return "unavailable"
        try:
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            buf = _recv_line(sock)
        except socket.timeout:
            # recv backstop tripped (daemon wedged past T_gate+10).
            return "unavailable"
        except OSError:
            return "unavailable"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if buf is None:
        return "unavailable"
    try:
        resp = json.loads(buf)
    except Exception:
        return "denied"
    if not isinstance(resp, dict) or resp.get("nonce") != nonce:
        # Nonce mismatch or unstructured reply — treat as a denial, never
        # a soft-fail toward approval.
        return "denied"
    verdict = resp.get("verdict")
    if verdict in ("approved", "denied", "timeout"):
        return verdict
    return "denied"


def _recv_line(sock) -> str | None:
    """Read one newline-delimited frame from `sock`. Returns the line WITHOUT
    the trailing newline, or None if the peer closed before a newline arrived.

    A `socket.timeout` propagates to the caller (mapped to "unavailable"); the
    reply is a single short line, so we read to the first '\\n' and stop."""
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            return None
        chunks.append(data)
        if b"\n" in data:
            break
    return b"".join(chunks).split(b"\n", 1)[0].decode("utf-8", "replace")


def gate(service, action, summary) -> tuple[bool, str]:
    """Consent-gate composition the wrapper hook calls.

    If the policy does not gate this (service, action), returns (True, "open")
    WITHOUT opening the socket — the empty-gate invariance (I-6): no policy
    line, no daemon contact, byte-identical behaviour to the pre-stage tree.

    Otherwise asks the daemon and returns (verdict == "approved", verdict). A
    "denied" / "timeout" / "unavailable" verdict yields ok=False; the wrapper
    then emits the SAME opaque sentinel a tag/tier denial emits — its own
    "not found" object (or, for SpawnAIManagedQube, the cross-ref message), NOT
    the MCP-layer "not found or refused" string — so the gate leaks no distinct
    signal (no consent oracle).
    """
    if not consent_required(service, action):
        return True, "open"
    verdict = request_consent(service, action, summary)
    return verdict == "approved", verdict
