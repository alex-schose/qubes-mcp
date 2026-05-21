from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


_STATE_PROPS = ("power_state", "netvm", "template", "provides_network")


@ring_tool(Ring.READ_ONLY)
def qubes_state(name: str) -> dict:
    """Return power state and a handful of core properties for an ai-managed qube.

    Composes qmcp.GetPropertyAIManaged for each property. Returns "not found"
    on the first non-ai-managed read (indistinguishable from nonexistent).
    """
    out: dict = {"ok": True, "name": name}
    for prop in _STATE_PROPS:
        r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})
        if not r.get("ok"):
            return r
        out[prop] = r["value"]
    return out
