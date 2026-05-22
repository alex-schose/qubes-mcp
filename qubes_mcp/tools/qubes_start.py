from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.LIFECYCLE)
def qubes_start(name: str) -> dict:
    """Start an ai-managed qube via qmcp.LifecycleAIManaged."""
    return call_qmcp("qmcp.LifecycleAIManaged",
                     {"name": name, "action": "start"})
