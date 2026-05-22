#!/bin/bash
# install-stage-d.sh — run in dom0.
#
# Stage D install:
#   1. Pull updated policy + updated qmcp.SpawnAIManagedQube + new
#      qmcp.CloneAIManagedQube + new qmcp.LifecycleAIManaged from mcp-control.
#   2. Install them into /etc/qubes/policy.d/ and /etc/qubes-rpc/.
#   3. Restart the qrexec policy daemon.
#
# No qube provisioning — Stage D only adds capability surface (DispVMTemplate /
# DispVM creation via SpawnAIManagedQube, clone via CloneAIManagedQube,
# dom0-mediated lifecycle via LifecycleAIManaged).
#
# Idempotent — re-runnable. Installs overwrite without backup.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-d.sh' > /tmp/install-d.sh
#   bash /tmp/install-d.sh mcp-control ~user/qubes_mcp

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp}"

STAGE_DIR="/tmp/qubes-mcp-stage-d"

echo "==> Stage D deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage D files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - policy/30-mcp-control.policy dom0-rpc/qmcp.SpawnAIManagedQube dom0-rpc/qmcp.CloneAIManagedQube dom0-rpc/qmcp.LifecycleAIManaged" \
    > "$STAGE_DIR/stage-d.tar"

(cd "$STAGE_DIR" && tar -xf stage-d.tar)

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum policy/30-mcp-control.policy \
                                dom0-rpc/qmcp.SpawnAIManagedQube \
                                dom0-rpc/qmcp.CloneAIManagedQube \
                                dom0-rpc/qmcp.LifecycleAIManaged )
echo

# ---------------------------------------------------------------- 2. install dom0 files
echo "==> Installing dom0 policy..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Installing dom0 qmcp.* scripts..."
for svc in qmcp.SpawnAIManagedQube qmcp.CloneAIManagedQube qmcp.LifecycleAIManaged; do
    sudo install -m 0755 -o root -g root \
        "$STAGE_DIR/dom0-rpc/$svc" \
        "/etc/qubes-rpc/$svc"
    echo "    /etc/qubes-rpc/$svc"
done
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

# ---------------------------------------------------------------- 4. cleanup
rm -rf "$STAGE_DIR"

echo
echo "==> Stage D deploy complete."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-d.py"
