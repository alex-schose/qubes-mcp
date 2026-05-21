"""Shared qrexec helpers for MCP tools."""
from __future__ import annotations

import json
import subprocess

QREXEC_CLIENT = "/usr/lib/qubes/qrexec-client-vm"


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
    """
    proc = subprocess.run(
        [QREXEC_CLIENT, "@adminvm", service],
        input=json.dumps(payload).encode() if payload is not None else b"",
        capture_output=True,
        timeout=timeout,
    )
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

    Used for lifecycle methods (admin.vm.Start, Shutdown, Remove, ...) that
    are tag-scoped at the policy layer. If the target isn't ai-managed, the
    call returns a generic refusal — surfaced here as "not found or refused"
    to keep the response shape opaque.
    """
    proc = subprocess.run(
        [QREXEC_CLIENT, vm_name, method],
        input=payload,
        capture_output=True,
        timeout=timeout,
    )
    if proc.returncode == 0:
        return {"ok": True, "stdout": proc.stdout.decode()}
    return {"ok": False, "error": "not found or refused"}
