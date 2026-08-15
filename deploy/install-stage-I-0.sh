#!/bin/bash
# install-stage-I-0.sh — run in dom0.
#
# Stage I-0 install: promote the F3 pool cap from advisory signal to
# a hard gate on every create path. Closes finding F-1 (design §18.3).
#
# Surface delta:
#   - NEW dom0 lib       /etc/qubes-rpc/qmcp_budget.py
#                        Shared helper: read_cap / sum / estimate /
#                        check_cap_for_create. Imported by the three
#                        create wrappers below.
#   - PATCHED wrappers   /etc/qubes-rpc/qmcp.SpawnAIManagedQube
#                        /etc/qubes-rpc/qmcp.CloneAIManagedQube
#                        /etc/qubes-rpc/qmcp.SpawnDisposableAIManaged
#                        Each one calls budget.check_cap_for_create()
#                        after cross-ref validation and refuses
#                        BEFORE invoking the Admin API on cap
#                        violation.
#
# Trust-model invariants preserved:
#   - GetPoolStats stays read-only (same measurement).
#   - Cross-ref refusal still fires before the cap gate, so the gate
#     adds no new existence oracle.
#   - Refusal messages are opaque ("pool cap exceeded" /
#     "pool cap not configured"); no numbers echoed.
#   - Fail-closed: if /etc/qmcp/pool-cap is missing or malformed,
#     every create refuses. (F3 install seeds the cap, so the
#     missing-cap state is a deliberate operator action.)
#
# No policy change. No daemon restart. /etc/qmcp/pool-cap is NOT
# touched (F3 install seeds it; I-0 only consumes it).
#
# Idempotent — re-runnable. Installs overwrite the lib and the three
# wrappers; the cap file is never touched.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-0.sh' > /tmp/install-I-0.sh
#   bash /tmp/install-I-0.sh mcp-control ~user/qubes_mcp

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-I-0"

echo "==> Stage I-0 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage I-0 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - \
        dom0-rpc/qmcp_budget.py \
        dom0-rpc/qmcp.SpawnAIManagedQube \
        dom0-rpc/qmcp.CloneAIManagedQube \
        dom0-rpc/qmcp.SpawnDisposableAIManaged" \
    > "$STAGE_DIR/stage-I-0.tar"

(cd "$STAGE_DIR" && tar -xf stage-I-0.tar)

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum \
    dom0-rpc/qmcp_budget.py \
    dom0-rpc/qmcp.SpawnAIManagedQube \
    dom0-rpc/qmcp.CloneAIManagedQube \
    dom0-rpc/qmcp.SpawnDisposableAIManaged )
echo

# ---------------------------------------------------------------- 2. install lib (0644)
echo "==> Installing shared budget lib..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/dom0-rpc/qmcp_budget.py" \
    "/etc/qubes-rpc/qmcp_budget.py"
echo "    /etc/qubes-rpc/qmcp_budget.py"
echo

# ---------------------------------------------------------------- 3. install patched wrappers (0755)
echo "==> Installing patched create wrappers..."
for w in qmcp.SpawnAIManagedQube qmcp.CloneAIManagedQube qmcp.SpawnDisposableAIManaged; do
    sudo install -m 0755 -o root -g root \
        "$STAGE_DIR/dom0-rpc/$w" \
        "/etc/qubes-rpc/$w"
    echo "    /etc/qubes-rpc/$w"
done
echo

# ---------------------------------------------------------------- 3b. provision the create-lock
# The cap-check->create critical section is serialized by an flock on
# /etc/qmcp/budget.lock (qmcp_budget.acquire_create_lock). The non-root qrexec
# wrapper user (uid 1000, group qubes) must be able to open+flock it, so it is
# owned root:qubes 0660 — the same perm pattern as the I-2 audit log. Without
# this file the wrapper's O_CREAT in a root-owned /etc/qmcp fails and cross-process
# serialization silently degrades (now audit-loud in qmcp_budget). Idempotent:
# reasserts perms if the file already exists; never truncates a live lock inode.
echo "==> Provisioning the create-lock (/etc/qmcp/budget.lock, 0660 root:qubes)..."
sudo install -d -m 0755 -o root -g root /etc/qmcp
if [ -e "/etc/qmcp/budget.lock" ]; then
    sudo chown root:qubes /etc/qmcp/budget.lock
    sudo chmod 0660 /etc/qmcp/budget.lock
    echo "    /etc/qmcp/budget.lock (existed; owner/mode reasserted)"
else
    sudo install -m 0660 -o root -g qubes /dev/null /etc/qmcp/budget.lock
    echo "    /etc/qmcp/budget.lock (created)"
fi
echo

# ---------------------------------------------------------------- 4. sanity-check cap file
if [ -e "/etc/qmcp/pool-cap" ]; then
    echo "==> Pool cap file present (operator state):"
    echo "    /etc/qmcp/pool-cap -> $(cat /etc/qmcp/pool-cap)"
else
    echo "==> WARNING: /etc/qmcp/pool-cap is absent."
    echo "    All create paths will refuse with 'pool cap not configured'."
    echo "    Install Stage F3 first (it seeds the cap), or:"
    echo "    sudo install -d -m 0755 /etc/qmcp && \\"
    echo "    sudo bash -c 'echo 53687091200 > /etc/qmcp/pool-cap'  # 50 GiB"
fi
echo

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo "==> Stage I-0 deploy complete."
echo
echo "No policy change; no daemon restart needed."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-I-0.py"
