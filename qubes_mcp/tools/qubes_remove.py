from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_admin


@ring_tool(Ring.LIFECYCLE)
def qubes_remove(name: str) -> dict:
    """Remove an ai-managed qube. Qube must be shut down first."""
    return call_admin("admin.vm.Remove", name)
