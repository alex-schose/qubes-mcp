from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_admin


@ring_tool(Ring.NETWORK)
def qubes_firewall_get(name: str) -> dict:
    """Read the firewall ruleset for an ai-managed qube.

    Returns:
      {"ok": true,  "rules": "<rule lines>"}
      {"ok": false, "error": "not found or refused"}

    Rule format (one per line; see Qubes Admin API for full grammar):
      action=accept dsthost=8.8.8.8 proto=tcp dstports=443
      action=drop

    Policy: admin.vm.firewall.Get is allow-listed only for `@tag:ai-managed`
    targets. A call against an untagged qube collapses to the opaque
    "not found or refused" response so AI cannot use this surface as an
    existence oracle.
    """
    r = call_admin("admin.vm.firewall.Get", name)
    if not r.get("ok"):
        return r
    return {"ok": True, "rules": r.get("stdout", "")}
