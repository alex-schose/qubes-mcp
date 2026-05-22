#!/bin/bash
# uninstall-stage-c.sh — run in dom0.
#
# Removes Stage C: kills + removes the egress qube (default ai-net-router),
# strips the Stage C `admin.vm.firewall.*` allow lines from the live policy
# file, restarts the daemon.
#
# The qmcp.SpawnAIManagedQube + qmcp.SetPropertyAIManaged scripts stay at
# their Stage C versions on disk: their additions (default-netvm to
# ai-net-router; egress invariant on provides_network qubes) are inert
# when no ai-managed provides_network qube exists. Backwards-compatible
# with Stage A/B operation.
#
# To fully restore Stage B's exact policy + scripts, re-run install-stage-b.sh
# (which overwrites the policy file with the repo's current copy — note: as
# the repo evolves, that copy also evolves; for a pristine Stage B-era
# version, git checkout the prior tag/commit before re-running the script).
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-c.sh' > /tmp/uninstall-c.sh
#   bash /tmp/uninstall-c.sh
#
# Env-var knobs (all optional):
#   EGRESS_QUBE  = ai-net-router    # which qube to remove

set -euo pipefail

EGRESS_QUBE="${EGRESS_QUBE:-ai-net-router}"
POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage C uninstall starting (egress qube = $EGRESS_QUBE)"
echo

# ---------------------------------------------------------------- 1. remove the egress qube
if qvm-check "$EGRESS_QUBE" >/dev/null 2>&1; then
    if qvm-check --running "$EGRESS_QUBE" >/dev/null 2>&1; then
        echo "==> Killing running qube $EGRESS_QUBE..."
        qvm-kill "$EGRESS_QUBE" || true
        sleep 1
    fi

    if qvm-tags "$EGRESS_QUBE" 2>/dev/null | grep -q '^ai-managed$'; then
        qvm-tags "$EGRESS_QUBE" del ai-managed || true
        echo "==> Untagged $EGRESS_QUBE."
    fi

    echo "==> Removing $EGRESS_QUBE..."
    qvm-remove -f "$EGRESS_QUBE"
else
    echo "==> $EGRESS_QUBE does not exist; nothing to remove."
fi
echo

# ---------------------------------------------------------------- 2. strip Stage C allows
if [ -f "$POLICY" ]; then
    if grep -q "^# --- Stage C:" "$POLICY"; then
        echo "==> Stripping Stage C allow block from $POLICY..."
        sudo sed -i '/^# --- Stage C:/,/^admin\.vm\.firewall\.Reload/d' "$POLICY"
        echo "    (qmcp.* scripts stay at Stage C version; their additions are"
        echo "     inert without an ai-managed provides_network qube.)"
    else
        echo "==> Policy file has no Stage C block; nothing to strip."
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
echo "==> Stage C uninstall complete."
echo "    System is back to Stage B + dormant Stage C scripts."
