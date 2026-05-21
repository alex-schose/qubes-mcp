#!/bin/bash
# uninstall-stage-b.sh — run in dom0.
#
# Reverts Stage B:
#   1. Removes qmcp.RunInAIManaged and qmcp.CopyToAIManaged from ai-managed templates.
#   2. (Leaves dom0 policy in place — use uninstall-stage-a.sh to revert that too.)
#
# Stage A is independent and remains functional after running this.

set -euo pipefail

TEMPLATES=("${@:-ai-debian-13}")

for TPL in "${TEMPLATES[@]}"; do
    if ! qvm-check "$TPL" >/dev/null 2>&1; then
        echo "==> Template $TPL not found; skipping."
        continue
    fi

    echo "==> Removing qmcp.* services from $TPL..."

    TPL_WAS_RUNNING=true
    if ! qvm-check --running "$TPL" >/dev/null 2>&1; then
        TPL_WAS_RUNNING=false
        qvm-start "$TPL"
    fi

    qvm-run --pass-io --user root "$TPL" \
        'rm -f /etc/qubes-rpc/qmcp.RunInAIManaged /etc/qubes-rpc/qmcp.CopyToAIManaged'

    if [ "$TPL_WAS_RUNNING" = false ]; then
        qvm-shutdown --wait "$TPL"
    else
        echo "    NOTE: $TPL was already running. Restart it later to commit removal."
    fi
done

echo
echo "==> Stage B uninstall complete (template-side services removed)."
echo "    To also revert the dom0 policy, run uninstall-stage-a.sh."
