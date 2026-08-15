#!/bin/bash
# install-stage-a.sh — run in dom0.
#
# Pulls the policy file and the four qmcp.* qrexec scripts from
# mcp-control, installs them in dom0, clones debian-13 → ai-debian-13
# and tags it ai-managed. Idempotent: safe to re-run.
#
# Review this script BEFORE executing it. Dom0 is your trust root.

set -euo pipefail
# ---------------------------------------------------------------- flip coherence guard
# This installer writes /etc/qubes/policy.d/30-mcp-control.policy from the
# shipped, PRE-FLIP artifact, which still carries the four @tag:ai-managed
# compat backstops. Doing that on a FLIPPED fleet restores those backstops while
# /etc/qmcp/tier-default stays "ro", so the two halves of the coupled flip
# disagree -- and it fails PERMISSIVE: exec, file-copy and firewall-write reopen
# to every umbrella qube while the @adminvm wrapper surfaces keep denying. The
# operator has every reason to think least privilege is still on; nothing
# announces the regression. This is the split-brain the I-4 design note warns
# about, reached by routine stage maintenance rather than a partial flip.
if [ "$(tr -d '[:space:]' < /etc/qmcp/tier-default 2>/dev/null)" = "ro" ]; then
    if [ "${QMCP_ALLOW_UNFLIP:-0}" = "1" ]; then
        echo "    WARNING: fleet is FLIPPED; this install restores the compat" >&2
        echo "             backstops. Proceeding on QMCP_ALLOW_UNFLIP=1 --" >&2
        echo "             RE-RUN deploy/install-stage-flip.sh when it finishes." >&2
    else
        echo "FATAL: this fleet is FLIPPED (/etc/qmcp/tier-default=ro), but this" >&2
        echo "       installer writes the shipped policy, which still carries the" >&2
        echo "       four compat backstops. Installing it would un-flip the policy" >&2
        echo "       half while the flag stays 'ro' -- reopening exec, file-copy" >&2
        echo "       and firewall-write to every @tag:ai-managed qube, silently." >&2
        echo "       Re-run with QMCP_ALLOW_UNFLIP=1 and then immediately re-run" >&2
        echo "       deploy/install-stage-flip.sh to restore coherence." >&2
        exit 1
    fi
fi


QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"
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
echo "    The qrexec policy daemon CACHES policy — it does NOT re-read per call."
echo "    Later stages restart it; if you stop after Stage A, apply it yourself:"
echo "      sudo systemctl restart qubes-qrexec-policy-daemon"
echo "    Tell the MCP session to run the Stage A test plan from mcp-control."
