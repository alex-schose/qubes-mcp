from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp


@ring_tool(Ring.EVENTS)
def qubes_events(duration: int, qube: str | None = None,
                 events: list[str] | None = None) -> dict:
    """Collect admin events for ai-managed qubes over a bounded window.

    Blocks for `duration` seconds (clamped server-side to [1, 120]) while
    qmcp.AIManagedEvents subscribes to admin.Events in dom0 and filters
    every event by the ai-managed tag on its subject. Returns the
    collected batch as a list of {event, subject, subject_klass, ts}
    dicts (plus a whitelisted `tag` field for domain-tag-add /
    domain-tag-delete events).

    Composition pattern (load-bearing). The wrapper only sees events
    fired AFTER subscription. To catch the immediate consequence of an
    action, open the window FIRST (a concurrent tool call), THEN
    perform the action. Sequential
        qubes_start(...)  ;  qubes_events(...)
    will miss the boot events; the parallel
        await asyncio.gather(qubes_events(duration=30), qubes_start(...))
    will catch them. The bounded-window model trades inter-call coverage
    for a stateless dom0 footprint (no persistent collector daemon).

    Filters:
      - `qube`: optional. Restrict to events whose subject is this exact
        qube name. Must be ai-managed (else opaque "not found").
      - `events`: optional. Restrict to events whose name matches any
        entry, where match means equality OR colon-suffix prefix
        ("property-set" matches "property-set:netvm").

    Edge cases the wrapper handles:
      - Delete events (subject already removed when the event fires):
        falls back to the ai-managed-at-window-open snapshot.
      - Revocation event itself (domain-tag-delete:ai-managed):
        surfaced if the subject was in the snapshot.
      - Dispatcher dies mid-window: returns partial events + a `warning`
        field; AI can decide whether to retry.
    """
    # Allow the dom0 call up to `duration + 10s` before declaring transport
    # failure — the wrapper itself caps duration at 120s, so the worst-case
    # MCP-side wait is bounded at 130s. The +10s is buffer for asyncio
    # tear-down + qrexec round-trip.
    timeout = float(duration) + 10.0
    return call_qmcp(
        "qmcp.AIManagedEvents",
        {"duration": duration, "qube": qube, "events": events},
        timeout=timeout,
    )
