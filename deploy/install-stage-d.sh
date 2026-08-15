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
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-d.sh' > /tmp/install-d.sh
#   bash /tmp/install-d.sh mcp-control ~user/qubes_mcp

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
# Reload the policy daemon — reset-failed FIRST, then POST-ASSERT it came back.
# Load-bearing: many installers restart this daemon, and the 6th restart inside
# systemd's 10s StartLimitIntervalSec trips StartLimitBurst, leaving the unit
# `failed`. qrexec then falls back to spawning qrexec-policy-exec per call, so
# nothing announces the degradation: VM->dom0 call latency rises roughly 7x,
# every call forks a dom0 python interpreter (~190 concurrent at 200 offered
# calls), and inter-qube clipboard paste stops working entirely.
# Restarts 1-5 return 0 and leave the unit ACTIVE; only the failing one returns
# rc=1 — these installers missed it because they never checked $?, not because
# systemd was silent. Asserting is-active is still the better check: it also
# catches the daemon dying for any reason other than the start limit.
sudo systemctl reset-failed qubes-qrexec-policy-daemon qubes-policy-daemon 2>/dev/null || true
_qmcp_unit=""
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    _qmcp_unit=qubes-qrexec-policy-daemon
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    _qmcp_unit=qubes-policy-daemon
fi
if [ -z "$_qmcp_unit" ]; then
    echo "    ERROR: neither policy daemon name could be restarted." >&2
    exit 1
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(systemctl is-active "$_qmcp_unit")" = "active" ] && break
    sleep 1
done
if [ "$(systemctl is-active "$_qmcp_unit")" != "active" ]; then
    echo "    ERROR: $_qmcp_unit did not return to active after restart." >&2
    echo "           qrexec policy evaluation is DEGRADED. Recover with:" >&2
    echo "             sudo systemctl reset-failed $_qmcp_unit" >&2
    echo "             sudo systemctl start $_qmcp_unit" >&2
    exit 1
fi
echo "    Restarted $_qmcp_unit (verified active)."

# ---------------------------------------------------------------- 4. cleanup
rm -rf "$STAGE_DIR"

echo
echo "==> Stage D deploy complete."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-d.py"
