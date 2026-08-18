from __future__ import annotations

import functools
from enum import Enum

from fastmcp import FastMCP


class Ring(str, Enum):
    READ_ONLY = "read_only"      # Stage A reads
    LIFECYCLE = "lifecycle"      # Stage A writes (spawn, props_set, start/shutdown/remove)
    EXEC      = "exec"           # Stage B (RunInAIManaged, CopyToAIManaged, install_pkg)
    NETWORK   = "network"        # Stage C (firewall mgmt on ai-managed qubes)
    CLONE     = "clone"          # Stage D (CloneAIManagedQube)
    DEVICE    = "device"         # Stage E1 (AttachDevice/DetachDevice/device_list)
    FEATURE   = "feature"        # Stage F1 (SetFeatureAIManaged)
    EVENTS    = "events"         # Stage F2 (AIManagedEvents — blocking-for-duration)


ACTIVE_RINGS: set[Ring] = {
    Ring.READ_ONLY, Ring.LIFECYCLE, Ring.EXEC,
    Ring.NETWORK, Ring.CLONE, Ring.DEVICE, Ring.FEATURE, Ring.EVENTS,
}


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
    Ring.NETWORK:   None,
    Ring.CLONE:     None,
    Ring.DEVICE:    None,
    Ring.FEATURE:   None,
    Ring.EVENTS:    None,
}


# Wave 2 Stage 2 removed `_RING_MIN_TIER` from here, and the removal is the
# point rather than a tidy-up. It mapped each ring to the tier its write
# surface needs — accurate, and enforced nowhere. This layer runs inside
# mcp-control, the untrusted side, so an injected agent controlling this
# process simply does not consult it; the real check is the dom0 helper
# `dom0-rpc/qmcp_tier.py`, read by the wrappers across the trust boundary.
# Invariant 2 of the capability model (brief §3.1, "no-illusion") forbids
# anything above the dom0 boundary that RESEMBLES a control: a reader who finds
# a tier table in the server believes there is a tier check in the server, and
# reasons about the system's authority from a table that has never denied
# anything. A comment saying "declarative only" does not survive being skimmed.
# The per-ring tier vocabulary, if an operator-facing config ever wants it,
# belongs on the dom0 side where it can be true.


# Stage G0b (Component D, findings [12]/[9]): mask_error_details keeps raw
# exception text (qubesd messages, transport errors, tracebacks) out of the
# response the agent sees — the detail is already on the AI-unreachable dom0
# audit chain. Pairs with the exception collapse in _qrexec.call_service /
# call_admin so no path leaks server-internal strings past the opaque refusal.
mcp = FastMCP("qubes", mask_error_details=True)


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
        qubes_firewall_get,
        qubes_firewall_set,
        qubes_clone,
        qubes_device_list,
        qubes_device_attach,
        qubes_device_detach,
        qubes_spawn_disposable,
        qubes_run_disposable,
        qubes_feature_set,
        qubes_events,
        qubes_get_pool_stats,
    )
    mcp.run()
