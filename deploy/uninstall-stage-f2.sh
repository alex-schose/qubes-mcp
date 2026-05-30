#!/bin/bash
# uninstall-stage-f2.sh — run in dom0.
#
# Removes the Stage F2 capability surface:
#   - Removes /etc/qubes-rpc/qmcp.AIManagedEvents.
#   - In the policy file: strips the Stage F2 allow block (one allow
#     line for qmcp.AIManagedEvents plus the comment header).
#   - Restarts the qrexec policy daemon.
#
# Does NOT revert the opaque-cross-ref backport on SetPropertyAIManaged
# / SpawnAIManagedQube — those are existence-oracle hygiene that should
# stay even if F2 itself is rolled back. Revert the backport with
# slot-revert.sh (which restores from the backup tree captured by
# slot-13.sh).
#
# The direct admin.Events deny in the explicit-deny block stays, so
# after uninstall the event stream is fully denied again (Stage F1
# state).
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-f2.sh' > /tmp/uninstall-f2.sh
#   bash /tmp/uninstall-f2.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage F2 uninstall starting"
echo

# ---------------------------------------------------------------- 1. remove Stage F2 RPC script
if [ -f "/etc/qubes-rpc/qmcp.AIManagedEvents" ]; then
    sudo rm -f "/etc/qubes-rpc/qmcp.AIManagedEvents"
    echo "==> Removed /etc/qubes-rpc/qmcp.AIManagedEvents."
else
    echo "==> /etc/qubes-rpc/qmcp.AIManagedEvents absent; nothing to remove."
fi
echo

# ---------------------------------------------------------------- 2. revert policy
if [ -f "$POLICY" ]; then
    echo "==> Reverting Stage F2 policy edits..."

    # Strip the Stage F2 allow block (header comment + 1 allow line).
    if grep -q "^# --- Stage F2:" "$POLICY"; then
        sudo sed -i '/^# --- Stage F2:/,/^qmcp\.AIManagedEvents /d' "$POLICY"
        echo "    Stripped Stage F2 allow block."
    fi
else
    echo "==> Policy file not found at $POLICY; skipping policy revert."
fi
echo

# ---------------------------------------------------------------- 3. reload daemon
echo "==> Reloading qrexec policy daemon..."
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked."
fi

echo
echo "==> Stage F2 uninstall complete."
echo "    The events surface is removed; the opaque-cross-ref backport on"
echo "    SetPropertyAIManaged / SpawnAIManagedQube remains. Use"
echo "    slot-revert.sh to undo the full slot-13 bundle if desired."
