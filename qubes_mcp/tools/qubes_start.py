from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_admin


@ring_tool(Ring.LIFECYCLE)
def qubes_start(name: str) -> dict:
    """Start an ai-managed qube via admin.vm.Start (tag-scoped at policy)."""
    return call_admin("admin.vm.Start", name)
