#!/bin/bash
# install-stage-c.sh — run in dom0.
#
# Stage C install:
#   1. Pull updated policy + qmcp.SpawnAIManagedQube + qmcp.SetPropertyAIManaged
#      from mcp-control.
#   2. Install them into /etc/qubes/policy.d/ and /etc/qubes-rpc/.
#   3. Create the single egress qube (default: ai-net-router) as an AppVM,
#      set provides_network=True, autostart=True, memory, netvm=<upstream>,
#      then tag it ai-managed.
#   4. Restart the qrexec policy daemon.
#
# Idempotent — re-runnable. Existing ai-net-router (or whatever EGRESS_QUBE
# is set to) is detected and its prefs are reapplied.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-c.sh' > /tmp/install-c.sh
#   EGRESS_UPSTREAM=sys-firewall bash /tmp/install-c.sh mcp-control ~user/qubes_mcp
#
# Env-var knobs (all optional):
#   EGRESS_QUBE      = ai-net-router          # name of the egress qube
#   EGRESS_TEMPLATE  = fedora-43-xfce         # AppVM template
#   EGRESS_LABEL     = red                    # Qubes label colour
#   EGRESS_MEMORY    = 500                    # RAM in MiB
#   EGRESS_UPSTREAM  = sys-firewall           # netvm; "" means offline
#
# Note: the default-netvm constant in dom0-rpc/qmcp.SpawnAIManagedQube is
# hard-coded to "ai-net-router". If you set EGRESS_QUBE to something else,
# also sed-replace DEFAULT_NETVM in that script before installing, or
# AI-spawned qubes will inherit no netvm by default.

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

EGRESS_QUBE="${EGRESS_QUBE:-ai-net-router}"
EGRESS_TEMPLATE="${EGRESS_TEMPLATE:-fedora-43-xfce}"
EGRESS_LABEL="${EGRESS_LABEL:-red}"
EGRESS_MEMORY="${EGRESS_MEMORY:-500}"
EGRESS_UPSTREAM="${EGRESS_UPSTREAM:-sys-firewall}"

STAGE_DIR="/tmp/qubes-mcp-stage-c"

echo "==> Stage C deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo "    egress qube:    $EGRESS_QUBE"
echo "    egress template:$EGRESS_TEMPLATE"
echo "    egress label:   $EGRESS_LABEL"
echo "    egress memory:  $EGRESS_MEMORY MiB"
echo "    egress upstream:${EGRESS_UPSTREAM:-(offline)}"
echo

# Sanity-check the upstream qube exists (empty = offline, allowed).
if [ -n "$EGRESS_UPSTREAM" ] && ! qvm-check "$EGRESS_UPSTREAM" >/dev/null 2>&1; then
    echo "FATAL: EGRESS_UPSTREAM '$EGRESS_UPSTREAM' is not an existing qube."
    echo "  Set it to an existing qube name (sys-firewall / sys-whonix / your-vpn),"
    echo "  or to '' for offline." >&2
    exit 1
fi

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage C files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - policy/30-mcp-control.policy dom0-rpc/qmcp.SpawnAIManagedQube dom0-rpc/qmcp.SetPropertyAIManaged" \
    > "$STAGE_DIR/stage-c.tar"

(cd "$STAGE_DIR" && tar -xf stage-c.tar)

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum policy/30-mcp-control.policy \
                                dom0-rpc/qmcp.SpawnAIManagedQube \
                                dom0-rpc/qmcp.SetPropertyAIManaged )
echo

# ---------------------------------------------------------------- 2. install dom0 files
echo "==> Installing dom0 policy..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Installing dom0 qmcp.* scripts..."
for svc in qmcp.SpawnAIManagedQube qmcp.SetPropertyAIManaged; do
    sudo install -m 0755 -o root -g root \
        "$STAGE_DIR/dom0-rpc/$svc" \
        "/etc/qubes-rpc/$svc"
    echo "    /etc/qubes-rpc/$svc"
done
echo

# ---------------------------------------------------------------- 3. egress qube
if qvm-check "$EGRESS_QUBE" >/dev/null 2>&1; then
    echo "==> $EGRESS_QUBE already exists, skipping create (will reapply prefs)."
else
    if ! qvm-check "$EGRESS_TEMPLATE" >/dev/null 2>&1; then
        echo "FATAL: template '$EGRESS_TEMPLATE' not found." >&2
        echo "  Either install it (qvm-template install $EGRESS_TEMPLATE)" >&2
        echo "  or set EGRESS_TEMPLATE to an existing TemplateVM." >&2
        exit 1
    fi
    echo "==> Creating $EGRESS_QUBE (AppVM, template=$EGRESS_TEMPLATE)..."
    qvm-create --class AppVM --template "$EGRESS_TEMPLATE" \
               --label "$EGRESS_LABEL" "$EGRESS_QUBE"
fi

echo "==> Configuring $EGRESS_QUBE prefs..."
qvm-prefs "$EGRESS_QUBE" provides_network True
qvm-prefs "$EGRESS_QUBE" autostart True
qvm-prefs "$EGRESS_QUBE" memory "$EGRESS_MEMORY"
qvm-prefs "$EGRESS_QUBE" netvm "$EGRESS_UPSTREAM"

if qvm-tags "$EGRESS_QUBE" 2>/dev/null | grep -q '^ai-managed$'; then
    echo "==> $EGRESS_QUBE already tagged ai-managed."
else
    qvm-tags "$EGRESS_QUBE" add ai-managed
    echo "==> Tagged $EGRESS_QUBE ai-managed."
fi
echo

# ---------------------------------------------------------------- 4. reload daemon
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

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo
echo "==> Stage C deploy complete."
echo
echo "Switch the upstream any time, in dom0:"
echo "  qvm-prefs $EGRESS_QUBE netvm sys-firewall   # clearnet"
echo "  qvm-prefs $EGRESS_QUBE netvm sys-whonix     # Tor"
echo "  qvm-prefs $EGRESS_QUBE netvm <your-vpn>     # VPN"
echo "  qvm-prefs $EGRESS_QUBE netvm \"\"             # offline"
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-c.py"
