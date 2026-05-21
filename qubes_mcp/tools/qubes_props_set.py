from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.LIFECYCLE)
def qubes_props_set(name: str, property: str, value) -> dict:
    """Set a property on an ai-managed qube via qmcp.SetPropertyAIManaged.

    The dom0 wrapper enforces:
      - target qube is ai-managed (else "not found")
      - cross-reference properties (template, netvm, default_dispvm) point
        at ai-managed qubes (else refused)
    """
    return call_qmcp(
        "qmcp.SetPropertyAIManaged",
        {"name": name, "property": property, "value": value},
    )
