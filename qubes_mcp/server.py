from __future__ import annotations

import functools
from enum import Enum

from fastmcp import FastMCP


class Ring(str, Enum):
    READ_ONLY = "read_only"      # Stage A reads
    LIFECYCLE = "lifecycle"      # Stage A writes (spawn, props_set, start/shutdown/remove)
    EXEC      = "exec"           # Stage B (RunInAIManaged, CopyToAIManaged, install_pkg)
    # NETWORK   = "network"      # Stage C (firewall mgmt)
    # CLONE     = "clone"        # Stage D
    # DEVICE    = "device"       # Stage E
    # FEATURE   = "feature"      # Stage F
    # EVENTS    = "events"       # Stage F


ACTIVE_RINGS: set[Ring] = {Ring.READ_ONLY, Ring.LIFECYCLE, Ring.EXEC}


# Per-ring budgets — None means unlimited (the default for every active ring
# today). Stages C+ will populate these from operator-provided limits to
# throttle AI activity: e.g. cap spawn rate, cap exec calls per minute, cap
# network bytes via Ring.NETWORK. The budget shape lives in `_RING_BUDGETS`
# rather than per-call arguments so a future operator-facing config layer can
# adjust limits without touching tool code.
_RING_BUDGETS: dict[Ring, int | None] = {
    Ring.READ_ONLY: None,
    Ring.LIFECYCLE: None,
    Ring.EXEC:      None,
}


mcp = FastMCP("qubes")


def spend_gate(ring: Ring) -> None:
    """Verify the ring is active and (when budgets are set) deduct from it.

    Today this is a defensive re-check that the ring is in ACTIVE_RINGS —
    redundant with the @ring_tool decorator's registration-time filter, but
    catches the case where someone hand-calls a wrapped function bypassing
    registration. Stages C+ extend this with per-ring quota deduction: see
    `_RING_BUDGETS`.
    """
    if ring not in ACTIVE_RINGS:
        raise PermissionError(f"ring {ring.value} not enabled in current stage")

    budget = _RING_BUDGETS.get(ring)
    if budget is not None:
        if budget <= 0:
            raise PermissionError(f"ring {ring.value} budget exhausted")
        _RING_BUDGETS[ring] = budget - 1


def ring_tool(ring: Ring):
    def decorator(fn):
        if ring not in ACTIVE_RINGS:
            return fn  # not registered
        @mcp.tool()
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            spend_gate(ring)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def main() -> None:
    # Importing each tool module registers it via @ring_tool.
    from qubes_mcp.tools import (  # noqa: F401
        qubes_list,
        qubes_spawn,
        qubes_state,
        qubes_props_get,
        qubes_props_set,
        qubes_start,
        qubes_shutdown,
        qubes_remove,
        qubes_run,
        qubes_copy,
        qubes_install_pkg,
    )
    mcp.run()
