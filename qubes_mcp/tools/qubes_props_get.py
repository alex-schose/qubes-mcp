from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.READ_ONLY)
def qubes_props_get(name: str, properties: list[str]) -> dict:
    """Read multiple properties of an ai-managed qube.

    Returns {"ok": true, "values": {prop: value, ...}} on full success.
    Returns the qmcp response unchanged on first failure (typically
    "not found" if `name` isn't ai-managed).
    """
    values: dict = {}
    for prop in properties:
        r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})
        if not r.get("ok"):
            return r
        values[prop] = r["value"]
    return {"ok": True, "values": values}
