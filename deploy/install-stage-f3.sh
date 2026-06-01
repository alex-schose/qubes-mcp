#!/bin/bash
# install-stage-f3.sh — run in dom0.
#
# Stage F3 install:
#   1. Pull updated policy + the new qmcp.GetPoolStats script from
#      mcp-control.
#   2. Install them into /etc/qubes/policy.d/ and /etc/qubes-rpc/.
#   3. Seed /etc/qmcp/pool-cap with a 50 GiB default if the file does
#      not already exist. Operator edits survive reinstall (we never
#      overwrite an existing cap file — the cap is operator state, not
#      shipped code).
#   4. Restart the qrexec policy daemon.
#
# No qube provisioning. Stage F3 only adds capability surface: an
# AI-scoped disk-budget read (sum of provisioned bytes on every
# ai-managed qube) + an operator-set cap returned alongside it. The
# wrapper is the only path; direct admin.pool.* / admin.vm.volume.*
# stay denied.
#
# Idempotent — re-runnable. Installs overwrite the wrapper/policy
# without backup; the cap file is preserved on every re-run.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-f3.sh' > /tmp/install-f3.sh
#   bash /tmp/install-f3.sh mcp-control ~user/qubes_mcp

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp}"

STAGE_DIR="/tmp/qubes-mcp-stage-f3"
CAP_DIR="/etc/qmcp"
CAP_FILE="$CAP_DIR/pool-cap"
DEFAULT_CAP_BYTES="53687091200"  # 50 GiB

echo "==> Stage F3 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage F3 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - policy/30-mcp-control.policy dom0-rpc/qmcp.GetPoolStats" \
    > "$STAGE_DIR/stage-f3.tar"

(cd "$STAGE_DIR" && tar -xf stage-f3.tar)

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum policy/30-mcp-control.policy \
                                dom0-rpc/qmcp.GetPoolStats )
echo

# ---------------------------------------------------------------- 2. install dom0 files
echo "==> Installing dom0 policy..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Installing dom0 qmcp.* script..."
sudo install -m 0755 -o root -g root \
    "$STAGE_DIR/dom0-rpc/qmcp.GetPoolStats" \
    "/etc/qubes-rpc/qmcp.GetPoolStats"
echo "    /etc/qubes-rpc/qmcp.GetPoolStats"
echo

# ---------------------------------------------------------------- 3. seed cap (only if absent)
echo "==> Configuring operator-set pool cap..."
if [ ! -e "$CAP_FILE" ]; then
    sudo install -d -m 0755 -o root -g root "$CAP_DIR"
    # Seed with 50 GiB default. The operator edits this any time;
    # the wrapper re-reads per call, no daemon restart needed.
    sudo bash -c "echo '$DEFAULT_CAP_BYTES  # 50 GiB — edit to taste (bytes; integer)' > '$CAP_FILE'"
    sudo chmod 0644 "$CAP_FILE"
    sudo chown root:root "$CAP_FILE"
    echo "    Seeded $CAP_FILE with $DEFAULT_CAP_BYTES bytes (50 GiB)."
else
    echo "    $CAP_FILE already exists — preserved (operator state):"
    echo "    $(cat "$CAP_FILE")"
fi
echo

# ---------------------------------------------------------------- 4. reload daemon
echo "==> Reloading qrexec policy daemon..."
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked."
fi

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo
echo "==> Stage F3 deploy complete."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-f3.py"
