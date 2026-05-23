#!/bin/bash
# uninstall-stage-e2.sh — run in dom0.
#
# Removes Stage E2 capability surface:
#   - Removes /etc/qubes-rpc/qmcp.SpawnDisposableAIManaged.
#   - In the policy file: strips the Stage E2 allow block (one allow
#     line for qmcp.SpawnDisposableAIManaged plus the comment header).
#   - Restarts the qrexec policy daemon.
#
# Does NOT remove any ephemeral disposables that may still be running.
# Those auto-cleanup on shutdown anyway; the operator can `qvm-kill`
# any straggler in dom0 if needed.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-e2.sh' > /tmp/uninstall-e2.sh
#   bash /tmp/uninstall-e2.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage E2 uninstall starting"
echo

# ---------------------------------------------------------------- 1. remove Stage E2 RPC script
if [ -f "/etc/qubes-rpc/qmcp.SpawnDisposableAIManaged" ]; then
    sudo rm -f "/etc/qubes-rpc/qmcp.SpawnDisposableAIManaged"
    echo "==> Removed /etc/qubes-rpc/qmcp.SpawnDisposableAIManaged."
else
    echo "==> /etc/qubes-rpc/qmcp.SpawnDisposableAIManaged absent; nothing to remove."
fi
echo

# ---------------------------------------------------------------- 2. revert policy
if [ -f "$POLICY" ]; then
    echo "==> Reverting Stage E2 policy edits..."

    # Strip the Stage E2 allow block (header comment + 1 allow line).
    if grep -q "^# --- Stage E2:" "$POLICY"; then
        sudo sed -i '/^# --- Stage E2:/,/^qmcp\.SpawnDisposableAIManaged /d' "$POLICY"
        echo "    Stripped Stage E2 allow block."
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
echo "==> Stage E2 uninstall complete."
echo "    System is back to Stage E1 policy surface."
