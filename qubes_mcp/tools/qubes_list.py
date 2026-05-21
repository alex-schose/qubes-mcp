from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.READ_ONLY)
def qubes_list() -> dict:
    """List the AI-managed qubes visible to this MCP.

    Untagged qubes are not enumerated. Returns:
      {"ok": true,  "qubes": [{name, klass, label, template, power_state}, ...]}
      {"ok": false, "error": "..."}
    """
    return call_qmcp("qmcp.ListAIManagedQubes")
