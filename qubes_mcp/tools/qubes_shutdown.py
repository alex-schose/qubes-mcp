from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_admin


@ring_tool(Ring.LIFECYCLE)
def qubes_shutdown(name: str, force: bool = False) -> dict:
    """Shutdown an ai-managed qube. If `force=True`, kill instead of clean shutdown."""
    method = "admin.vm.Kill" if force else "admin.vm.Shutdown"
    return call_admin(method, name)
