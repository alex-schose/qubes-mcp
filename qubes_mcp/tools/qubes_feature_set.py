from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.FEATURE)
def qubes_feature_set(name: str, feature: str, value) -> dict:
    """Set a feature on an ai-managed qube via qmcp.SetFeatureAIManaged.

    The dom0 wrapper enforces:
      - target qube is ai-managed (else opaque "not found")
      - `internal` is operator-only (refused) — AI must not hide a qube
        from the operator's menus
      - cross-VM feature keys (audiovm, guivm) must point at ai-managed
        qubes (else an opaque refusal that does not reveal whether the
        named qube exists)

    Value handling: booleans follow Qubes convention (True -> "1",
    False -> ""); ints/strings pass through. `None` is rejected — this
    sets a feature, it does not remove one (removal is operator-only).

    On success the response echoes the value read back from dom0:
    {"ok": true, "feature": "<key>", "value": "<readback>"}.
    """
    return call_qmcp(
        "qmcp.SetFeatureAIManaged",
        {"name": name, "feature": feature, "value": value},
    )
