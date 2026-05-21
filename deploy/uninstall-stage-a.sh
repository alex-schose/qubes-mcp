#!/bin/bash
# uninstall-stage-a.sh — run in dom0.
#
# Removes the qrexec policy and qmcp.* services, untags ai-debian-13.
# Does NOT delete the ai-debian-13 template (preserves AI's work).
# Run if you want to roll back Stage A entirely.

set -euo pipefail

echo "==> Removing qrexec policy..."
sudo rm -f /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Removing qmcp.* qrexec services..."
sudo rm -f /etc/qubes-rpc/qmcp.ListAIManagedQubes \
           /etc/qubes-rpc/qmcp.SpawnAIManagedQube \
           /etc/qubes-rpc/qmcp.GetPropertyAIManaged \
           /etc/qubes-rpc/qmcp.SetPropertyAIManaged

if qvm-check ai-debian-13 >/dev/null 2>&1; then
    echo "==> Untagging ai-debian-13 (template preserved)..."
    qvm-tags ai-debian-13 del ai-managed 2>/dev/null || true
fi

echo
echo "==> Stage A uninstall complete."
echo "    ai-debian-13 template still exists. To remove it manually:"
echo "      qvm-remove ai-debian-13"
