from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


# A superset across klasses on purpose: `template` exists on an AppVM and a
# DispVM but not on a TemplateVM or a StandaloneVM. Rather than branch on the
# klass (an extra round trip, and a list that rots as Qubes adds properties),
# ask for all of them and report per property — see the docstring below.
_STATE_PROPS = ("power_state", "netvm", "template", "provides_network")


@ring_tool(Ring.READ_ONLY)
def qubes_state(name: str) -> dict:
    """Return power state and a handful of core properties for an ai-managed qube.

    Composes qmcp.GetPropertyAIManaged per property. Properties that do not
    exist on the target's class are reported under "errors" instead of
    discarding the whole call (finding F-G: this returned nothing usable for
    a StandaloneVM, or for either template).

    Opacity is unchanged: if NO property reads, the first error is returned
    verbatim, so an out-of-scope or nonexistent qube collapses to the same
    opaque "not found" as before. See qubes_props_get for the full argument on
    why the per-property error is not an existence oracle.
    """
    out: dict = {"ok": True, "name": name}
    errors: dict = {}
    first_error: dict | None = None
    read_any = False

    for prop in _STATE_PROPS:
        r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": prop})
        if r.get("ok"):
            out[prop] = r["value"]
            read_any = True
        else:
            errors[prop] = r.get("error", "not found or refused")
            if first_error is None:
                first_error = r

    if not read_any and first_error is not None:
        return first_error

    if errors:
        out["errors"] = errors
    return out
