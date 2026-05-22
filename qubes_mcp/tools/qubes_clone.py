from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.CLONE)
def qubes_clone(source: str, name: str) -> dict:
    """Clone an ai-managed qube into a new ai-managed qube.

    The source qube must be ai-managed (else "not found" — the same opaque
    response the property-read surface emits). The new qube is auto-tagged
    `ai-managed` by the dom0 wrapper. The clone inherits the source's
    prefs (template, netvm, memory, …); since the source is ai-managed,
    its netvm is by construction None or itself ai-managed.

    Returns:
      {"ok": true, "name": "<new-vm-name>"}
      {"ok": false, "error": "not found"}        -- source missing or not ai-managed
      {"ok": false, "error": "<reason>"}
    """
    return call_qmcp("qmcp.CloneAIManagedQube", {"source": source, "name": name})
