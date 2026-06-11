#!/bin/bash
# uninstall-stage-I-1.sh — run in dom0.
#
# Reverts Stage I-1 (read-surface scope redaction, F-3).
#
# Stage I-1 patched two existing read wrappers (GetProperty / List) to
# route VM-valued results through qmcp_scope. The wrappers fail closed
# if the scope lib is absent — GetProperty refuses with "scope lib load
# failed: ..." and List errors out. So removing the lib alone would
# brick reads until the wrappers themselves are restored to their
# pre-I-1 versions.
#
# Two clean revert paths:
#
#   (A) RECOMMENDED — slot-runner rollback. The operator-local slot
#       script that deployed I-1 (slot-47.sh) recorded the pre-I-1
#       wrappers in /var/lib/qmcp-rollback/<TS>/MANIFEST as REPLACED=
#       entries. Run in dom0:
#           /tmp/run.sh revert
#       This restores the two wrappers to their pre-I-1 state and
#       removes the (newly-added) qmcp_scope.py.
#
#   (B) Re-install the prior stage from mcp-control. Check out the
#       pre-I-1 commit of the two wrappers in public/dom0-rpc/, then
#       run install-stage-a.sh to restore the unredacted reads.
#
# This script does the minimum on top: removes the lib only if the
# wrappers have already been restored (otherwise it warns and stops).
# No policy changes; no daemon restart.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-I-1.sh' > /tmp/uninstall-I-1.sh
#   bash /tmp/uninstall-I-1.sh
#   # or:    bash /tmp/uninstall-I-1.sh --force   (skips the wrapper check)

set -euo pipefail

FORCE="${1:-}"

LIB="/etc/qubes-rpc/qmcp_scope.py"
WRAPPERS=(
    /etc/qubes-rpc/qmcp.GetPropertyAIManaged
    /etc/qubes-rpc/qmcp.ListAIManagedQubes
)

echo "==> Stage I-1 uninstall starting"
echo

# ---------------------------------------------------------------- 1. sanity-check wrappers
if [ "$FORCE" != "--force" ]; then
    echo "==> Checking that wrappers no longer reference the scope lib..."
    referencing=0
    for w in "${WRAPPERS[@]}"; do
        if [ -f "$w" ] && grep -q "qmcp_scope" "$w"; then
            echo "    STILL PATCHED: $w  (contains 'qmcp_scope')"
            referencing=1
        fi
    done
    if [ "$referencing" -eq 1 ]; then
        echo
        echo "==> ERROR: at least one wrapper still imports the scope lib."
        echo "    Removing the lib now would brick reads (fail-closed)."
        echo "    Restore pre-I-1 wrappers first (see header for options),"
        echo "    or re-run with --force if you know what you're doing."
        exit 1
    fi
    echo "    OK — no wrapper references qmcp_scope."
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
echo "==> Stage I-1 uninstall complete."
echo "    System is back to the pre-I-1 read surface (VM-valued reads"
echo "    serialise to raw names again — the F-3 leak is reopened)."
