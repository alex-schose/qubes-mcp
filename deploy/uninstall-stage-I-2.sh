#!/bin/bash
# uninstall-stage-I-2.sh — run in dom0.
#
# Reverts Stage I-2 (hash-chained dom0 audit log).
#
# Unlike I-1 (whose read wrappers fail CLOSED without their lib), the I-2
# audit hook is BEST-EFFORT: each patched wrapper detects a missing/unloadable
# qmcp_audit and simply skips logging — the operation still runs and the
# response is unchanged. So removing the lib alone is SAFE; it does not brick
# any surface, it only stops new audit lines from being written.
#
# Two revert depths:
#
#   (A) RECOMMENDED — slot-runner rollback for a clean, complete revert. The
#       operator-local slot that deployed I-2 (slot-49.sh) recorded the 8
#       pre-I-2 wrappers in /var/lib/qmcp-rollback/<TS>/MANIFEST as REPLACED=
#       and the lib as ADDED-DOM0. Run in dom0:
#           /tmp/run.sh revert
#       This restores the 8 wrappers to their pre-I-2 form AND removes
#       /etc/qubes-rpc/qmcp_audit.py.
#
#   (B) This script — the minimum: remove the lib. The 8 wrappers keep their
#       (now inert) audit-hook code; with the lib gone they no-op the logging
#       and behave exactly as their pre-I-2 selves. Use (A) if you want the
#       wrapper source restored too.
#
# The existing audit log (/var/log/qmcp-audit.log) is PRESERVED — it is a
# record, not transient state; removing it is the operator's explicit call.
#
# No policy change; no daemon restart.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-I-2.sh' > /tmp/uninstall-I-2.sh
#   bash /tmp/uninstall-I-2.sh

set -euo pipefail

LIB="/etc/qubes-rpc/qmcp_audit.py"
LOG="/var/log/qmcp-audit.log"

echo "==> Stage I-2 uninstall starting"
echo

if [ -f "$LIB" ]; then
    sudo rm -f "$LIB"
    echo "==> Removed $LIB."
    echo "    The 8 state-changing wrappers retain their best-effort audit"
    echo "    hook but now no-op it (lib absent) — behaviour is pre-I-2."
    echo "    For a full wrapper-source revert, use '/tmp/run.sh revert'."
else
    echo "==> $LIB absent; nothing to remove."
fi

echo
if [ -e "$LOG" ]; then
    echo "==> Audit log preserved at $LOG"
    echo "    ($(sudo wc -l < "$LOG" 2>/dev/null || echo '?') lines). Remove it by hand if you intend to."
else
    echo "==> No audit log present at $LOG."
fi
echo
echo "==> Stage I-2 uninstall complete."
