"""Shared qrexec helpers for MCP tools."""
from __future__ import annotations

import json
import subprocess

QREXEC_CLIENT = "/usr/lib/qubes/qrexec-client-vm"

# Client-side timeout for the qmcp.* services that Stage I-6 gates behind an
# operator-consent dialog (Lifecycle/SetProperty/SetFeature/Clone/Spawn/
# SpawnDisposable/AttachDevice/DetachDevice). A gated call may block while the
# operator decides, so its ceiling must sit ABOVE the whole consent chain:
#
#   T_gate (<=340s)  <  helper socket recv (<=350s)  <  T_mcp (360s)
#
# - T_gate is the dom0 consent dialog's auto-expiry (zenity --timeout, read from
#   the operator-editable /etc/qmcp/consent-timeout, default 300). On expiry the
#   daemon returns "timeout".
# - The consent helper's socket recv is T_gate+10, a backstop that only fires if
#   the dialog's own timeout somehow doesn't.
# - GATED_TIMEOUT=360 is this MCP-side client timeout: it must OUTLAST both so a
#   verdict (approve/deny/timeout) always arrives before we give up, otherwise a
#   late operator click could execute after the agent already saw a failure.
#
# WHY A HARDCODED 360 IS SAFE AGAINST OPERATOR EDITS: this file runs in
# mcp-control and CANNOT read the dom0 timeout file, so it cannot recompute the
# ceiling from the operator's value. The ordering is instead protected at the
# SOURCE: both the daemon and the helper CLAMP T_gate to <=340 (qmcp-consentd /
# qmcp_consent.py MAX_TIMEOUT), so helper_recv <= 350 < 360 holds for ANY content
# of /etc/qmcp/consent-timeout. Raising the operator timeout past 340 no longer
# inverts the ordering — it saturates at the clamp. (Before the clamp, a value
# >=350 silently inverted this; the clamp is the coupling.)
#
# HONEST CAVEAT: this bounds only the subprocess call we make here. The MCP
# CLIENT's own request timeout and the SSH stdio transport may impose a ceiling
# BELOW 360s that this codebase does not control. Whether the full 360s survives
# end-to-end must be verified empirically on the real transport — it cannot be
# confirmed from mcp-control. Read-only tools keep the default 30s.
GATED_TIMEOUT = 360.0


def _decode_response(proc: subprocess.CompletedProcess) -> dict:
    raw = proc.stdout.decode().strip()
    if not raw:
        # Opaque on every empty-stdout failure (policy denial, no such VM,
        # service crash, transport error) so AI cannot use the helper as a
        # probe for the existence of untagged qubes.
        return {"ok": False, "error": "not found or refused"}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"ok": False, "error": "not found or refused"}


def call_qmcp(service: str, payload: dict | None = None, timeout: float = 30.0) -> dict:
    """Invoke a qmcp.* qrexec service in dom0. Returns parsed JSON response.

    Convention: every qmcp.* script writes a single JSON object to stdout with
    `{"ok": true, ...}` or `{"ok": false, "error": "..."}`.

    A client-side TimeoutExpired (the GATED_TIMEOUT ceiling firing on a gated
    service, or any transport-imposed cutoff below it) collapses to the SAME
    opaque `{"ok": false, "error": "not found or refused"}` a policy deny /
    empty-stdout failure produces — NOT a raised exception. This preserves
    opaque-refusal parity on the timeout path (a raw exception would be a signal
    distinct from a tag/tier/consent denial) and guarantees a clean refusal even
    if the ordering degrades. It stays fail-safe: the dom0 daemon's own
    zenity --timeout (T_gate, clamped <=340) fires well before this ceiling, so a
    verdict normally arrives first; if it doesn't, the agent sees a refusal, not
    a crash or a silent success.
    """
    try:
        proc = subprocess.run(
            [QREXEC_CLIENT, "@adminvm", service],
            input=json.dumps(payload).encode() if payload is not None else b"",
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "not found or refused"}
    return _decode_response(proc)


def call_service(qube: str, service: str, payload: dict | None = None, timeout: float = 120.0) -> dict:
    """Invoke a qrexec service in a NAMED qube (not @adminvm).

    Used for Stage B+ services that run inside ai-managed qubes
    (qmcp.RunInAIManaged, qmcp.CopyToAIManaged). The named qube must be
    ai-managed and running; policy gates the source/target pair.
    """
    proc = subprocess.run(
        [QREXEC_CLIENT, qube, service],
        input=json.dumps(payload).encode() if payload is not None else b"",
        capture_output=True,
        timeout=timeout,
    )
    return _decode_response(proc)


def call_admin(method: str, vm_name: str, payload: bytes = b"", timeout: float = 60.0) -> dict:
    """Invoke an `admin.*` qrexec method targeted at a named VM.

    Used for lifecycle methods (admin.vm.Start, Shutdown, Remove, ...) and
    Stage C firewall methods (admin.vm.firewall.Get/Set/Reload). All are
    tag-scoped at the policy layer. If the target isn't ai-managed, the
    call returns a generic refusal — surfaced here as "not found or refused"
    to keep the response shape opaque.

    Admin-API response framing: every admin.* call returns a small header
    on stdout — `b"0\\x00"` on success or `b"2\\x00<msg>"` on in-band
    failure — followed by the payload. We strip the header so callers see
    clean stdout. In-band failures collapse to "not found or refused" too.
    """
    proc = subprocess.run(
        [QREXEC_CLIENT, vm_name, method],
        input=payload,
        capture_output=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        return {"ok": False, "error": "not found or refused"}

    raw = proc.stdout
    # Admin API framing: <status-byte>\x00<payload>. status byte is the
    # ASCII char "0" for ok, "2" (and a few other codes) for error.
    if len(raw) >= 2 and raw[1:2] == b"\x00":
        if raw[0:1] == b"0":
            payload_out = raw[2:]
        else:
            return {"ok": False, "error": "not found or refused"}
    else:
        # Unframed response (some services skip the header). Pass through.
        payload_out = raw

    return {"ok": True, "stdout": payload_out.decode(errors="replace")}
