from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.READ_ONLY)
def qubes_get_pool_stats() -> dict:
    """Return AI's provisioned disk footprint and operator-set cap.

    Reports the total *provisioned* size of every volume on every
    ai-managed qube, plus the operator-set ceiling and the headroom
    remaining. Use this to self-throttle spawn loops before the cap is
    hit: stop creating new ai-managed qubes when `ai_managed_bytes_headroom`
    drops below your next allocation. The cap is set by the operator
    in dom0 (`/etc/qmcp/pool-cap`); AI cannot change it.

    Untagged operator qubes are not enumerated or summed. Pool topology
    (free space, total size, pool names) is intentionally not exposed —
    it would leak operator-side state.

    Notes:
      - `ai_managed_bytes_used` is provisioned size, not on-disk write
        bytes. On thin-LVM, whether the underlying pool can fulfill
        the cap is the operator's concern, not AI's.
      - Returns `{"ok": false, "error": "pool cap not configured"}` if
        the operator removed the cap file. Treat as "throttle to zero
        new spawns" and ask the operator to restore the cap.

    Returns:
      {"ok": true, "ai_managed_bytes_used": <int>,
                   "ai_managed_bytes_cap":  <int>,
                   "ai_managed_bytes_headroom": <int>}
      {"ok": false, "error": "..."}
    """
    return call_qmcp("qmcp.GetPoolStats")
