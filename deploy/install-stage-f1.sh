#!/bin/bash
# install-stage-f1.sh — run in dom0.
#
# Stage F1 install:
#   1. Pull updated policy + the new qmcp.SetFeatureAIManaged script
#      from mcp-control.
#   2. Install them into /etc/qubes/policy.d/ and /etc/qubes-rpc/.
#   3. Restart the qrexec policy daemon.
#
# No qube provisioning. Stage F1 only adds capability surface:
# feature.Set on ai-managed qubes (with the `internal`-key deny and
# the audiovm/guivm cross-ref check; the wrapper is the only path,
# direct admin.vm.feature.Set stays denied).
#
# Idempotent — re-runnable. Installs overwrite without backup.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-f1.sh' > /tmp/install-f1.sh
#   bash /tmp/install-f1.sh mcp-control ~user/qubes_mcp

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp}"

STAGE_DIR="/tmp/qubes-mcp-stage-f1"

echo "==> Stage F1 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage F1 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - policy/30-mcp-control.policy dom0-rpc/qmcp.SetFeatureAIManaged" \
    > "$STAGE_DIR/stage-f1.tar"

(cd "$STAGE_DIR" && tar -xf stage-f1.tar)

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum policy/30-mcp-control.policy \
                                dom0-rpc/qmcp.SetFeatureAIManaged )
echo

# ---------------------------------------------------------------- 2. install dom0 files
echo "==> Installing dom0 policy..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Installing dom0 qmcp.* script..."
sudo install -m 0755 -o root -g root \
    "$STAGE_DIR/dom0-rpc/qmcp.SetFeatureAIManaged" \
    "/etc/qubes-rpc/qmcp.SetFeatureAIManaged"
echo "    /etc/qubes-rpc/qmcp.SetFeatureAIManaged"
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
echo "==> Stage F1 deploy complete."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-f1.py"
