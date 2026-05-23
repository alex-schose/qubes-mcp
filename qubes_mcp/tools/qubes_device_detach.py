from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.DEVICE)
def qubes_device_detach(
    device_class: str,
    backend: str,
    device_id: str,
    frontend: str,
) -> dict:
    """Detach a device previously attached between two ai-managed qubes.

    Mirror of qubes_device_attach. Same trust invariant (both endpoints
    must be ai-managed) and same opaque "not found" on missing/untagged
    either side.

    Returns:
      {"ok": true}
      {"ok": false, "error": "not found"}        -- backend or frontend missing/untagged
      {"ok": false, "error": "<reason>"}
    """
    return call_qmcp("qmcp.DetachDeviceAIManaged", {
        "device_class": device_class,
        "backend": backend,
        "device_id": device_id,
        "frontend": frontend,
    })
