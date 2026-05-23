from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.LIFECYCLE)
def qubes_spawn_disposable(template: str) -> dict:
    """Create an ephemeral DispVM from an ai-managed DispVMTemplate.

    The created qube is auto-tagged ai-managed and has
    `auto_cleanup=True`, so dom0 removes it once it halts. AI then
    starts it (qubes_start), uses it (qubes_run / qubes_copy), and
    shuts it down (qubes_shutdown) — at which point it vanishes.

    For the common spawn → start → run → shutdown cycle, use
    `qubes_run_disposable` (one-shot composition).

    Args:
      template: ai-managed DispVMTemplate (a qube with
                template_for_dispvms=True; created via
                qubes_spawn(klass="DispVMTemplate", ...) in Stage D).

    Returns:
      {"ok": true,  "name": "<auto-assigned, e.g. disp1234>"}
      {"ok": false, "error": "not found"}         -- template missing or not ai-managed
      {"ok": false, "error": "<reason>"}          -- e.g. template lacks
                                                     template_for_dispvms
    """
    return call_qmcp("qmcp.SpawnDisposableAIManaged", {"template": template})
