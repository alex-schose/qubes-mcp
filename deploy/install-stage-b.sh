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


SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"
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
