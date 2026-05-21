from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_admin


@ring_tool(Ring.NETWORK)
def qubes_firewall_set(name: str, rules: str, reload: bool = True) -> dict:
    """Replace the firewall ruleset for an ai-managed qube.

    Args:
      name:    target ai-managed qube
      rules:   newline-separated rule lines (Qubes Admin API grammar)
      reload:  if True (default), also call admin.vm.firewall.Reload so
               the rules take effect immediately in the netvm. Set False
               when the target has no netvm running yet — Set still
               persists; the rules apply on next netvm boot.

    Returns:
      {"ok": true,  "reloaded": bool}
      {"ok": false, "error": "not found or refused"}
      {"ok": false, "error": "set ok but reload failed: ..."}

    Policy refuses (collapsed to "not found or refused") if the target is
    not tagged ai-managed.
    """
    set_r = call_admin("admin.vm.firewall.Set", name, payload=rules.encode())
    if not set_r.get("ok"):
        return set_r

    if not reload:
        return {"ok": True, "reloaded": False}

    rel_r = call_admin("admin.vm.firewall.Reload", name)
    if not rel_r.get("ok"):
        return {"ok": False, "error": f"set ok but reload failed: {rel_r.get('error')}"}
    return {"ok": True, "reloaded": True}
