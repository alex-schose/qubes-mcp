#!/bin/bash
# uninstall-stage-I-3.sh — run in dom0.
#
# Reverts Stage I-3 (tier taxonomy + dom0 tier-resolution helper).
#
# I-3 installs the helper INERT: no wrapper sources qmcp_tier.py yet (that is
# Stage I-5), and the stage changed no policy line. So removing the lib is
# wholly safe — it cannot brick any surface, because no surface depends on it.
# Behaviour is identical before and after (it was behaviour-neutral going in).
#
# If the operator created the tier-default flag /etc/qmcp/tier-default while
# experimenting with the flip, it is PRESERVED here (operator state, like F3's
# pool-cap) — remove it by hand if intended. With the helper gone it has no
# effect regardless.
#
# Two revert depths:
#   (A) slot-runner rollback (/tmp/run.sh revert) — clean revert via the
#       MANIFEST the deploying slot recorded (qmcp_tier.py as ADDED-DOM0).
#   (B) this script — the minimum: remove the lib.
#
# No policy change; no daemon restart.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/uninstall-stage-I-3.sh' > /tmp/uninstall-I-3.sh
#   bash /tmp/uninstall-I-3.sh

set -euo pipefail

LIB="/etc/qubes-rpc/qmcp_tier.py"
FLAG="/etc/qmcp/tier-default"

echo "==> Stage I-3 uninstall starting"
echo

if [ -f "$LIB" ]; then
    sudo rm -f "$LIB"
    echo "==> Removed $LIB."
    echo "    No wrapper sourced it (I-3 ships the helper inert), so behaviour"
    echo "    is unchanged — exactly pre-I-3."
else
    echo "==> $LIB absent; nothing to remove."
fi

echo
if [ -e "$FLAG" ]; then
    echo "==> Tier-default flag preserved at $FLAG (operator state: '$(sudo cat "$FLAG" 2>/dev/null || echo '?')')."
    echo "    It has no effect with the helper removed; delete it by hand if intended."
else
    echo "==> No tier-default flag at $FLAG (compat default was in effect)."
fi
echo
echo "==> Stage I-3 uninstall complete."
