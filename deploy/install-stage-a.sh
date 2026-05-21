#!/bin/bash
# install-stage-a.sh — run in dom0.
#
# Pulls the policy file and the four qmcp.* qrexec scripts from
# mcp-control, installs them in dom0, clones debian-13 → ai-debian-13
# and tags it ai-managed. Idempotent: safe to re-run.
#
# Review this script BEFORE executing it. Dom0 is your trust root.

set -euo pipefail

QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp}"
STAGE_DIR="/tmp/qubes-mcp-stage-a"

echo "==> Stage A deploy starting"
echo "    source qube: $QUBE"
echo "    source path: $SOURCE_PATH"
echo

# -----------------------------------------------------------------------
# 1. Pull files from the source qube via qvm-run --pass-io.
# -----------------------------------------------------------------------
echo "==> Pulling tarball from $QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - policy/30-mcp-control.policy -C dom0-rpc qmcp.ListAIManagedQubes qmcp.SpawnAIManagedQube qmcp.GetPropertyAIManaged qmcp.SetPropertyAIManaged" \
    > "$STAGE_DIR/stage-a.tar"

(cd "$STAGE_DIR" && tar -xf stage-a.tar)

echo "==> Files extracted to $STAGE_DIR:"
ls -la "$STAGE_DIR/policy/30-mcp-control.policy" \
       "$STAGE_DIR/qmcp.ListAIManagedQubes" \
       "$STAGE_DIR/qmcp.SpawnAIManagedQube" \
       "$STAGE_DIR/qmcp.GetPropertyAIManaged" \
       "$STAGE_DIR/qmcp.SetPropertyAIManaged"
echo

# -----------------------------------------------------------------------
# 2. Checksums — record these for audit.
# -----------------------------------------------------------------------
echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum policy/30-mcp-control.policy \
                                qmcp.ListAIManagedQubes \
                                qmcp.SpawnAIManagedQube \
                                qmcp.GetPropertyAIManaged \
                                qmcp.SetPropertyAIManaged )
echo

# -----------------------------------------------------------------------
# 3. Provision the ai-managed template.
# -----------------------------------------------------------------------
if qvm-check ai-debian-13 >/dev/null 2>&1; then
    echo "==> ai-debian-13 already exists, skipping clone."
elif qvm-check debian-13 >/dev/null 2>&1; then
    echo "==> Cloning debian-13 → ai-debian-13..."
    qvm-clone debian-13 ai-debian-13
else
    echo "==> ai-debian-13 not found and no 'debian-13' template to clone from."
    echo "    Create the ai-managed base template manually first, e.g.:"
    echo "      qvm-clone <your-source-template-name> ai-debian-13"
    echo "    Then re-run this script."
    exit 1
fi

echo "==> Tagging ai-debian-13 as ai-managed..."
qvm-tags ai-debian-13 add ai-managed
echo

# -----------------------------------------------------------------------
# 4. Install qmcp.* qrexec services.
# -----------------------------------------------------------------------
echo "==> Installing qmcp.* qrexec services into /etc/qubes-rpc/..."
sudo install -m 0755 -o root -g root \
    "$STAGE_DIR/qmcp.ListAIManagedQubes"   /etc/qubes-rpc/qmcp.ListAIManagedQubes
sudo install -m 0755 -o root -g root \
    "$STAGE_DIR/qmcp.SpawnAIManagedQube"   /etc/qubes-rpc/qmcp.SpawnAIManagedQube
sudo install -m 0755 -o root -g root \
    "$STAGE_DIR/qmcp.GetPropertyAIManaged" /etc/qubes-rpc/qmcp.GetPropertyAIManaged
sudo install -m 0755 -o root -g root \
    "$STAGE_DIR/qmcp.SetPropertyAIManaged" /etc/qubes-rpc/qmcp.SetPropertyAIManaged

# -----------------------------------------------------------------------
# 5. Install the qrexec policy.
# -----------------------------------------------------------------------
echo "==> Installing qrexec policy into /etc/qubes/policy.d/..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

# -----------------------------------------------------------------------
# 6. Verify and clean up.
# -----------------------------------------------------------------------
echo
echo "==> Final check — installed files:"
ls -la /etc/qubes-rpc/qmcp.ListAIManagedQubes \
       /etc/qubes-rpc/qmcp.SpawnAIManagedQube \
       /etc/qubes-rpc/qmcp.GetPropertyAIManaged \
       /etc/qubes-rpc/qmcp.SetPropertyAIManaged \
       /etc/qubes/policy.d/30-mcp-control.policy

echo
echo "==> Cleaning staging directory..."
rm -rf "$STAGE_DIR"

echo
echo "==> Stage A deploy complete."
echo "    Template: ai-debian-13 (tagged ai-managed)"
echo "    Policy:   /etc/qubes/policy.d/30-mcp-control.policy"
echo "    Services: qmcp.{List,Spawn,GetProperty,SetProperty}AIManaged*"
echo
echo "    No daemon restart needed — qrexec re-reads policy on each call."
echo "    Tell the MCP session to run the Stage A test plan from mcp-control."
