#!/bin/bash
# install-stage-f2.sh — run in dom0.
#
# Stage F2 install:
#   1. Pull updated policy + the new qmcp.AIManagedEvents script + the
#      two patched cross-ref wrappers (SetPropertyAIManaged,
#      SpawnAIManagedQube) from mcp-control.
#   2. Install them into /etc/qubes/policy.d/ and /etc/qubes-rpc/.
#   3. Restart the qrexec policy daemon.
#
# No qube provisioning. Stage F2 adds the bounded-window event
# streaming surface (qmcp.AIManagedEvents) AND backports the opaque
# cross-ref collapse to SetPropertyAIManaged and SpawnAIManagedQube
# (closes the existence-oracle gap that F1 already addressed in
# SetFeatureAIManaged). The bundle is shipped together because both
# pieces are existence-oracle hygiene aligned with the F1 design.
#
# Idempotent — re-runnable. Installs overwrite without backup (the
# slot-13.sh runner captures backups in /var/lib/qmcp-rollback/).
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-f2.sh' > /tmp/install-f2.sh
#   bash /tmp/install-f2.sh mcp-control ~user/qubes_mcp

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp}"

STAGE_DIR="/tmp/qubes-mcp-stage-f2"

echo "==> Stage F2 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage F2 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - \
        policy/30-mcp-control.policy \
        dom0-rpc/qmcp.AIManagedEvents \
        dom0-rpc/qmcp.SetPropertyAIManaged \
        dom0-rpc/qmcp.SpawnAIManagedQube" \
    > "$STAGE_DIR/stage-f2.tar"

(cd "$STAGE_DIR" && tar -xf stage-f2.tar)

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum \
        policy/30-mcp-control.policy \
        dom0-rpc/qmcp.AIManagedEvents \
        dom0-rpc/qmcp.SetPropertyAIManaged \
        dom0-rpc/qmcp.SpawnAIManagedQube )
echo

# ---------------------------------------------------------------- 2. install dom0 files
echo "==> Installing dom0 policy..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Installing dom0 qmcp.* scripts..."
for s in qmcp.AIManagedEvents qmcp.SetPropertyAIManaged qmcp.SpawnAIManagedQube; do
    sudo install -m 0755 -o root -g root \
        "$STAGE_DIR/dom0-rpc/$s" \
        "/etc/qubes-rpc/$s"
    echo "    /etc/qubes-rpc/$s"
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
echo "==> Stage F2 deploy complete."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-a.py    # 5 PASS expected (opaque-collapse backport)"
echo "  .venv/bin/python deploy/test-stage-f1.py   # 5 PASS expected (unchanged)"
echo "  .venv/bin/python deploy/test-stage-f2.py   # 5 PASS expected (new events surface)"
