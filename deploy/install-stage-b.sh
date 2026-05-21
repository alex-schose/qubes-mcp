#!/bin/bash
# install-stage-b.sh — run in dom0.
#
# Stage B install:
#   1. Pull updated policy + two template-side qmcp.* scripts from mcp-control.
#   2. Install the template-side scripts INSIDE the ai-debian-13 template
#      (and any additional ai-managed templates passed as arguments).
#   3. Update dom0 policy file (overwrites the Stage A version).
#
# Re-runnable / idempotent. After running:
#   - New AppVMs based on patched templates inherit the qmcp.RunInAIManaged
#     and qmcp.CopyToAIManaged services.
#   - Existing running AppVMs need to be restarted to pick them up.

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp}"
shift 2 2>/dev/null || shift || true
TEMPLATES=("${@:-ai-debian-13}")
STAGE_DIR="/tmp/qubes-mcp-stage-b"

echo "==> Stage B deploy starting"
echo "    source qube: $SOURCE_QUBE"
echo "    source path: $SOURCE_PATH"
echo "    templates:   ${TEMPLATES[*]}"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage B tarball from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - policy/30-mcp-control.policy -C template-rpc qmcp.RunInAIManaged qmcp.CopyToAIManaged" \
    > "$STAGE_DIR/stage-b.tar"

(cd "$STAGE_DIR" && tar -xf stage-b.tar)

echo "==> Files pulled:"
ls -la "$STAGE_DIR/policy/30-mcp-control.policy" \
       "$STAGE_DIR/qmcp.RunInAIManaged" \
       "$STAGE_DIR/qmcp.CopyToAIManaged"
echo

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum policy/30-mcp-control.policy \
                                qmcp.RunInAIManaged \
                                qmcp.CopyToAIManaged )
echo

# ----------------------------------------- 2. push services into templates
for TPL in "${TEMPLATES[@]}"; do
    if ! qvm-check "$TPL" >/dev/null 2>&1; then
        echo "==> Template $TPL not found; skipping."
        continue
    fi
    if ! qvm-tags "$TPL" 2>/dev/null | grep -q '^ai-managed$'; then
        echo "==> Template $TPL is not tagged ai-managed; skipping."
        continue
    fi

    echo "==> Installing qmcp.* services into $TPL..."

    TPL_WAS_RUNNING=true
    if ! qvm-check --running "$TPL" >/dev/null 2>&1; then
        TPL_WAS_RUNNING=false
        echo "    starting $TPL..."
        qvm-start "$TPL"
    fi

    for svc in qmcp.RunInAIManaged qmcp.CopyToAIManaged; do
        echo "    pushing $svc..."
        cat "$STAGE_DIR/$svc" | qvm-run --pass-io --user root "$TPL" \
            "tee /etc/qubes-rpc/$svc > /dev/null && chmod 0755 /etc/qubes-rpc/$svc"
    done

    if [ "$TPL_WAS_RUNNING" = false ]; then
        echo "    shutting down $TPL to commit changes..."
        qvm-shutdown --wait "$TPL"
    else
        echo "    NOTE: $TPL was already running. Restart it later to commit changes."
    fi
    echo
done

# ----------------------------------------- 3. update dom0 policy
echo "==> Updating dom0 qrexec policy..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Final policy file:"
ls -la /etc/qubes/policy.d/30-mcp-control.policy
echo

# ----------------------------------------- 4. cleanup
echo "==> Cleaning staging directory..."
rm -rf "$STAGE_DIR"

echo
echo "==> Stage B deploy complete."
echo "    Existing running ai-managed AppVMs need a restart to pick up new"
echo "    services. New AppVMs spawned via qmcp.SpawnAIManagedQube inherit"
echo "    them automatically."
