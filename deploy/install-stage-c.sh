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
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-c.sh' > /tmp/install-c.sh
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

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp}"

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
