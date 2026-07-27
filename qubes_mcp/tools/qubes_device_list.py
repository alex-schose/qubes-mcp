from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp

_ALLOWED_CLASSES = ("block", "usb", "mic")


@ring_tool(Ring.DEVICE)
def qubes_device_list(qube: str, device_class: str, mode: str = "available") -> dict:
    """Enumerate devices on an ai-managed qube.

    Args:
      qube:          target ai-managed qube (backend if mode="available",
                     frontend if mode="attached").
      device_class:  "block" | "usb" | "mic".
      mode:          "available" (default) — devices the qube EXPOSES as a
                     backend, ready to be attached elsewhere; "attached" —
                     devices currently ATTACHED to the qube as a frontend.

    Returns:
      {"ok": true,  "lines": ["<raw enumeration line>", ...]}
      {"ok": false, "error": "not found or refused"}

    Policy: admin.vm.device.<class>.{Available,List} is allow-listed only
    for `@tag:ai-managed` targets. A call against an untagged qube
    collapses to the opaque "not found or refused" response so AI cannot
    use this surface as an existence oracle.

    Raw-line output: the Admin API returns one device per line; the
    exact field layout has drifted across Qubes 4.1 / 4.2 / 4.3, so we
    pass the lines through unmodified. The first whitespace-separated
    token on each line is the port_id to use with qubes_device_attach.
    """
    if device_class not in _ALLOWED_CLASSES:
        return {"ok": False, "error": f"device_class must be one of: {list(_ALLOWED_CLASSES)}"}
    if mode not in ("available", "attached"):
        return {"ok": False, "error": "mode must be 'available' or 'attached'"}

    # Stage G0d/G0e (findings [4] and [3]): BOTH modes route through the dom0
    # redactor wrapper. "attached" can leak an out-of-scope BACKEND name;
    # "available" can leak an out-of-scope CONSUMING-FRONTEND name (the
    # `attachment=` field). The wrapper redacts either to <out-of-scope>; the
    # direct admin device-enum methods are denied to AI, so it can't be bypassed.
    return call_qmcp("qmcp.ListAttachedDevicesAIManaged",
                     {"name": qube, "device_class": device_class, "mode": mode})
