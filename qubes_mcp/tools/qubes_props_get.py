from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.READ_ONLY)
def qubes_props_get(name: str, properties: list[str]) -> dict:
    """Read multiple properties of an ai-managed qube.

    Returns {"ok": true, "values": {prop: value, ...}} and, when some
    properties could not be read, {"errors": {prop: reason, ...}} alongside.

    Per-property, not abort-on-first-failure (finding F-G). A property that
    does not exist on the target's CLASS — `template` on a TemplateVM or a
    StandaloneVM, say — used to discard the whole call, losing the properties
    that read fine. The dom0 wrapper already answers per property
    (`qmcp.GetPropertyAIManaged` returns `property '<p>' does not exist`), so
    the fix is to stop throwing that granularity away here. This is why the
    tool needs no class-awareness of its own: no extra round trip to learn the
    klass, and it keeps working for class-specific properties added later.

    Opacity is unchanged. If NOTHING read successfully the first error is
    returned verbatim — byte-identical to the previous behaviour — so an
    out-of-scope or nonexistent qube still collapses to the same opaque
    "not found" / "not found or refused" it always did. The richer shape only
    appears once a property has already been read, which itself proves the
    target is inside the umbrella; the distinct per-property error therefore
    fires strictly AFTER the scope check and is no existence oracle (the same
    ordering rule the cross-ref and egress refusals follow).
    """
    values: dict = {}
    errors: dict = {}
    first_error: dict | None = None

    for prop in properties:
        r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})
        if r.get("ok"):
            values[prop] = r["value"]
        else:
            errors[prop] = r.get("error", "not found or refused")
            if first_error is None:
                first_error = r

    if not values and first_error is not None:
        return first_error

    out: dict = {"ok": True, "values": values}
    if errors:
        out["errors"] = errors
    return out
