from __future__ import annotations

from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.DEVICE)
def qubes_device_attach(
    device_class: str,
    backend: str,
    device_id: str,
    frontend: str,
    options: dict | None = None,
) -> dict:
    """Attach a device exposed by one ai-managed qube to another.

    Args:
      device_class:  "block" | "usb" | "mic".
      backend:       ai-managed qube exposing the device.
      device_id:     port_id as enumerated by qubes_device_list(mode="available").
      frontend:      ai-managed qube to attach the device to.
      options:       class-specific key/value options (e.g. {"read-only": "yes"}
                     for block). Optional.

    Returns:
      {"ok": true}
      {"ok": false, "error": "not found"}        -- backend or frontend missing/untagged
      {"ok": false, "error": "<reason>"}

    Both backend and frontend must be ai-managed; the dom0 wrapper
    collapses missing/untagged on either side to the same opaque
    "not found" so AI cannot use the device surface as an existence
    oracle for untagged qubes.
    """
    payload: dict = {
        "device_class": device_class,
        "backend": backend,
        "device_id": device_id,
        "frontend": frontend,
    }
    if options is not None:
        payload["options"] = options
    return call_qmcp("qmcp.AttachDeviceAIManaged", payload)
