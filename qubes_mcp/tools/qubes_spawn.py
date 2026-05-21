from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.LIFECYCLE)
def qubes_spawn(
    name: str,
    template: str,
    label: str = "gray",
    netvm: str | None = None,
) -> dict:
    """Create a new AI-managed AppVM.

    The new qube is auto-tagged `ai-managed` by the dom0 wrapper. `template`
    must itself be an ai-managed TemplateVM; if `netvm` is given, it must be
    ai-managed too. The wrapper refuses on validation failure.

    Stage A: AppVM only. Other classes (TemplateVM, StandaloneVM) land in Stage D.
    """
    payload: dict = {"name": name, "template": template, "label": label}
    if netvm is not None:
        payload["netvm"] = netvm
    return call_qmcp("qmcp.SpawnAIManagedQube", payload)
