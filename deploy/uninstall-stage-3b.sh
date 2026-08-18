#!/bin/bash
# uninstall-stage-3b.sh — run in dom0.
#
# Removes Wave 2 Stage 3b: /etc/qubes-rpc/qmcp_enforce.py.
#
# REFUSES while any wrapper sources the module or while the operator flag is
# armed. Removing the switch out from under a flipped fleet is not a rollback —
# it is a fleet whose wrappers raise ImportError on every mutation, which fails
# closed but takes qmcp with it.
#
# Note the ordinary way back is NOT this script. Reverting the flip is one write
# and needs no uninstall, no policy reload and no slot-revert:
#
#     printf 'shadow\n' | sudo tee /etc/qmcp/enforce-mode >/dev/null
#
# This script exists to remove the stage's file, which is a different thing.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/uninstall-stage-3b.sh' > /tmp/uninstall-3b.sh
#   bash /tmp/uninstall-3b.sh

set -euo pipefail

LIB="/etc/qubes-rpc/qmcp_enforce.py"
FLAG="/etc/qmcp/enforce-mode"

echo "==> Wave 2 Stage 3b uninstall"
echo

# ------------------------------------------------------------ 1. in-use gate
echo "==> Checking no installed wrapper sources qmcp_enforce..."
IN_USE=$(grep -l 'qmcp_enforce' /etc/qubes-rpc/qmcp.* 2>/dev/null || true)
if [ -n "$IN_USE" ]; then
    echo "REFUSING: these installed wrappers source qmcp_enforce:" >&2
    echo "$IN_USE" | sed 's|^|    |' >&2
    echo "" >&2
    echo "    Stage 3c is deployed. Removing the module would make every" >&2
    echo "    mutation path fail on import. To return to pre-flip behaviour" >&2
    echo "    without removing anything:" >&2
    echo "        printf 'shadow\\n' | sudo tee $FLAG >/dev/null" >&2
    echo "    To remove the stage, uninstall Stage 3c first." >&2
    exit 1
fi
echo "    none. Stage 3b is still inert."

# ------------------------------------------------------------ 2. armed gate
echo "==> Checking the operator flag is not armed..."
if [ -e "$FLAG" ]; then
    MODE=$(sed 's/#.*//' "$FLAG" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    if [ "$MODE" != "shadow" ] && [ -n "$MODE" ]; then
        echo "REFUSING: $FLAG says '$MODE', not 'shadow'." >&2
        echo "    Set it back to shadow (or remove the file) before removing" >&2
        echo "    the module that reads it." >&2
        exit 1
    fi
    echo "    $FLAG = '$MODE' (not armed)."
else
    echo "    $FLAG absent (shadow, the default)."
fi
echo

# ------------------------------------------------------------ 3. remove
if [ -e "$LIB" ]; then
    echo "==> Removing $LIB..."
    sudo rm -f "$LIB"
    echo "    removed."
else
    echo "==> $LIB already absent."
fi

# The operator's own file is deliberately LEFT ALONE. It is theirs, it is not
# something this stage created, and deleting an operator's configuration during
# an uninstall is how a setting silently reverts on the next install.
if [ -e "$FLAG" ]; then
    echo "==> $FLAG left in place (operator-owned; this stage never created it)."
fi
echo

echo "==> Stage 3b uninstall complete."
echo "    Nothing else moved: no policy line, no systemd unit, no operator file."
