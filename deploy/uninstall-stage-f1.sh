#!/bin/bash
# uninstall-stage-f1.sh — run in dom0.
#
# Removes Stage F1 capability surface:
#   - Removes /etc/qubes-rpc/qmcp.SetFeatureAIManaged.
#   - In the policy file: strips the Stage F1 allow block (one allow
#     line for qmcp.SetFeatureAIManaged plus the comment header).
#   - Restarts the qrexec policy daemon.
#
# The direct admin.vm.feature.Set deny in the explicit-deny block stays,
# so after uninstall feature.Set is fully denied again (Stage E2 state).
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-f1.sh' > /tmp/uninstall-f1.sh
#   bash /tmp/uninstall-f1.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage F1 uninstall starting"
echo

# ---------------------------------------------------------------- 1. remove Stage F1 RPC script
if [ -f "/etc/qubes-rpc/qmcp.SetFeatureAIManaged" ]; then
    sudo rm -f "/etc/qubes-rpc/qmcp.SetFeatureAIManaged"
    echo "==> Removed /etc/qubes-rpc/qmcp.SetFeatureAIManaged."
else
    echo "==> /etc/qubes-rpc/qmcp.SetFeatureAIManaged absent; nothing to remove."
fi
echo

# ---------------------------------------------------------------- 2. revert policy
if [ -f "$POLICY" ]; then
    echo "==> Reverting Stage F1 policy edits..."

    # Strip the Stage F1 allow block (header comment + 1 allow line).
    if grep -q "^# --- Stage F1:" "$POLICY"; then
        sudo sed -i '/^# --- Stage F1:/,/^qmcp\.SetFeatureAIManaged /d' "$POLICY"
        echo "    Stripped Stage F1 allow block."
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
echo "==> Stage F1 uninstall complete."
echo "    System is back to Stage E2 policy surface."
