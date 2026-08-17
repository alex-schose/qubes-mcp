#!/bin/bash
# uninstall-stage-1.sh — run in dom0.
#
# Reverts Wave 2 Stage 1 (the capability decision kernel, shadow mode).
#
# REMOVING ONE FILE DISARMS THE WHOLE STAGE, and that is a designed property
# rather than a lucky one. Every wrapper reaches the kernel through
# `_load_caps_lib()`, which returns None on any failure, and `_shadow_note()`
# returns immediately when it is None. So with /etc/qubes-rpc/qmcp_caps.py gone:
#
#   - no wrapper consults the kernel,
#   - `_shadow` stays None on every call,
#   - emit() therefore omits the field entirely, which means the audit line is
#     byte-identical to pre-Stage-1 AND the call works against an OLD
#     qmcp_audit.py that never heard of `shadow`.
#
# The wrappers are left in place on purpose. They are byte-identical in
# behaviour with the kernel absent — the offline suite proves exactly this by
# running every case twice, once with the kernel loaded and once with
# `_CAPS = None`, and asserting identical responses. Ripping eight wrappers out
# to undo a stage that changes no behaviour would be the riskier operation.
#
# Two revert depths:
#   (A) this script — remove the kernel. The stage is inert; behaviour and audit
#       format return to exactly pre-Stage-1. Sufficient in every normal case.
#   (B) slot-runner rollback (/tmp/run.sh revert) — byte-level restore of
#       qmcp_audit.py and the 8 wrappers from the MANIFEST the deploying slot
#       recorded (qmcp_caps.py as ADDED-DOM0, the rest as REPLACED). Use this
#       only if you need the files themselves back, not just the behaviour.
#
# The audit log is PRESERVED, always. Any divergence lines already written are
# evidence about how the fleet behaved, they are not stage state, and this
# script must never touch them — the same reasoning that made tombstone reaping
# timer-only (an eviction path is an evidence-destruction path).
#
# No policy change; no daemon restart.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/uninstall-stage-1.sh' > /tmp/uninstall-1.sh
#   bash /tmp/uninstall-1.sh

set -euo pipefail

KERNEL="/etc/qubes-rpc/qmcp_caps.py"
LOG="/var/log/qmcp-audit.log"

echo "==> Wave 2 Stage 1 uninstall starting"
echo

if [ -f "$KERNEL" ]; then
    sudo rm -f "$KERNEL"
    echo "==> Removed $KERNEL."
    echo "    Every wrapper's _load_caps_lib() now returns None, so _shadow_note()"
    echo "    is a no-op, _shadow stays None, and emit() omits the field. Behaviour"
    echo "    and audit-line format are exactly pre-Stage-1."
else
    echo "==> $KERNEL absent; nothing to remove."
fi
echo

echo "==> Confirming the wrappers still load with the kernel gone..."
FAILED=0
for b in qmcp.LifecycleAIManaged qmcp.SetPropertyAIManaged qmcp.SetFeatureAIManaged \
         qmcp.CloneAIManagedQube qmcp.SpawnAIManagedQube qmcp.SpawnDisposableAIManaged \
         qmcp.AttachDeviceAIManaged qmcp.DetachDeviceAIManaged; do
    if [ -f "/etc/qubes-rpc/$b" ]; then
        if ! python3 -c "compile(open('/etc/qubes-rpc/$b').read(), '$b', 'exec')"; then
            echo "    WARNING: $b does not compile" >&2
            FAILED=1
        fi
    fi
done
if [ "$FAILED" -eq 0 ]; then
    echo "    all present wrappers compile."
else
    echo "    ONE OR MORE WRAPPERS ARE BROKEN — use the slot-runner revert (depth B)." >&2
fi
echo

if [ -e "$LOG" ]; then
    N=$(sudo grep -c '"shadow"' "$LOG" 2>/dev/null || true)
    echo "==> Audit log preserved at $LOG (${N:-0} divergence lines recorded)."
    echo "    Deliberately NOT truncated: those lines are evidence, not stage state."
else
    echo "==> No audit log at $LOG."
fi
echo
echo "==> Wave 2 Stage 1 uninstall complete."
