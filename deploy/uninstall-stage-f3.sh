#!/bin/bash
# uninstall-stage-f3.sh — run in dom0.
#
# Removes Stage F3 capability surface:
#   - Removes /etc/qubes-rpc/qmcp.GetPoolStats.
#   - In the policy file: strips the Stage F3 allow block (one allow
#     line for qmcp.GetPoolStats plus the comment header).
#   - LEAVES /etc/qmcp/pool-cap in place — it's operator state, not
#     shipped code. Operator can `sudo rm /etc/qmcp/pool-cap` if a
#     full revert is wanted.
#   - Restarts the qrexec policy daemon.
#
# The direct admin.pool.* and admin.vm.volume.{List,Info} denies stay
# in the explicit-deny block, so after uninstall the disk-pressure
# surface is fully denied again (Stage F2 state).
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-f3.sh' > /tmp/uninstall-f3.sh
#   bash /tmp/uninstall-f3.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage F3 uninstall starting"
echo

# ---------------------------------------------------------------- 1. remove Stage F3 RPC script
if [ -f "/etc/qubes-rpc/qmcp.GetPoolStats" ]; then
    sudo rm -f "/etc/qubes-rpc/qmcp.GetPoolStats"
    echo "==> Removed /etc/qubes-rpc/qmcp.GetPoolStats."
else
    echo "==> /etc/qubes-rpc/qmcp.GetPoolStats absent; nothing to remove."
fi
echo

# ---------------------------------------------------------------- 2. revert policy
if [ -f "$POLICY" ]; then
    echo "==> Reverting Stage F3 policy edits..."

    # Strip the Stage F3 allow block (header comment + 1 allow line).
    if grep -q "^# --- Stage F3:" "$POLICY"; then
        sudo sed -i '/^# --- Stage F3:/,/^qmcp\.GetPoolStats /d' "$POLICY"
        echo "    Stripped Stage F3 allow block."
    fi
else
    echo "==> Policy file not found at $POLICY; skipping policy revert."
fi
echo

# ---------------------------------------------------------------- 3. note about cap file
if [ -f "/etc/qmcp/pool-cap" ]; then
    echo "==> /etc/qmcp/pool-cap preserved (operator state)."
    echo "    Remove with: sudo rm /etc/qmcp/pool-cap"
    echo
fi

# ---------------------------------------------------------------- 4. reload daemon
echo "==> Reloading qrexec policy daemon..."
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked."
fi

echo
echo "==> Stage F3 uninstall complete."
echo "    System is back to Stage F2 policy surface."
