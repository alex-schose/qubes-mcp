#!/bin/bash
# uninstall-stage-I-0.sh — run in dom0.
#
# Reverts Stage I-0 (hard cap-gate on create paths).
#
# Stage I-0 patched three existing wrappers (Spawn / Clone /
# SpawnDisposable) to call qmcp_budget.check_cap_for_create() before
# the Admin API. The wrappers fail closed if the budget lib is absent
# — they refuse every create with "budget helper load failed: ...".
# So removing the lib alone would brick spawns until the wrappers
# themselves are restored to their pre-I-0 versions.
#
# Two clean revert paths:
#
#   (A) RECOMMENDED — slot-runner rollback. The operator-local
#       slot script that deployed I-0 (slot-43.sh) recorded the
#       pre-I-0 wrappers in /var/lib/qmcp-rollback/<TS>/MANIFEST as
#       REPLACED= entries. Run in dom0:
#           /tmp/run.sh revert
#       This restores the three wrappers to their pre-I-0 state and
#       removes the (newly-added) qmcp_budget.py.
#
#   (B) Re-install the prior stage from mcp-control. Check out the
#       pre-I-0 commit of the three wrappers in public/dom0-rpc/, then
#       run install-stage-f3.sh (the F-band terminus) to restore the
#       advisory-cap behaviour.
#
# This script does the minimum on top: removes the lib only if the
# operator confirms the wrappers have already been restored
# (otherwise it warns and stops). No policy changes; no daemon
# restart.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-I-0.sh' > /tmp/uninstall-I-0.sh
#   bash /tmp/uninstall-I-0.sh
#   # or:    bash /tmp/uninstall-I-0.sh --force   (skips the wrapper check)

set -euo pipefail

FORCE="${1:-}"

LIB="/etc/qubes-rpc/qmcp_budget.py"
WRAPPERS=(
    /etc/qubes-rpc/qmcp.SpawnAIManagedQube
    /etc/qubes-rpc/qmcp.CloneAIManagedQube
    /etc/qubes-rpc/qmcp.SpawnDisposableAIManaged
)

echo "==> Stage I-0 uninstall starting"
echo

# ---------------------------------------------------------------- 1. sanity-check wrappers
if [ "$FORCE" != "--force" ]; then
    echo "==> Checking that wrappers no longer reference the budget lib..."
    referencing=0
    for w in "${WRAPPERS[@]}"; do
        if [ -f "$w" ] && grep -q "qmcp_budget" "$w"; then
            echo "    STILL PATCHED: $w  (contains 'qmcp_budget')"
            referencing=1
        fi
    done
    if [ "$referencing" -eq 1 ]; then
        echo
        echo "==> ERROR: at least one wrapper still imports the budget lib."
        echo "    Removing the lib now would brick creates."
        echo "    Restore pre-I-0 wrappers first (see header for options),"
        echo "    or re-run with --force if you know what you're doing."
        exit 1
    fi
    echo "    OK — no wrapper references qmcp_budget."
    echo
fi

# ---------------------------------------------------------------- 2. remove lib
if [ -f "$LIB" ]; then
    sudo rm -f "$LIB"
    echo "==> Removed $LIB."
else
    echo "==> $LIB absent; nothing to remove."
fi
echo

# ---------------------------------------------------------------- 3. note cap file
if [ -f "/etc/qmcp/pool-cap" ]; then
    echo "==> /etc/qmcp/pool-cap preserved (operator state)."
    echo "    F3 still reads it; AI's GetPoolStats keeps reporting"
    echo "    (used, cap, headroom) as before."
fi

echo
echo "==> Stage I-0 uninstall complete."
echo "    System is back to Stage F3 surface (cap is advisory only)."
