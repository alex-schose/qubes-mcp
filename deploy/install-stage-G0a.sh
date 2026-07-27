#!/bin/bash
# install-stage-G0a.sh — run in dom0.
#
# Stage G0a (review finding [1]): install the property-allowlist hardening of
# qmcp.SetPropertyAIManaged. This is a WRAPPER-ONLY change — it touches exactly
# one dom0 file (/etc/qubes-rpc/qmcp.SetPropertyAIManaged) and NOTHING else:
#   - no policy file change  → NO qrexec policy-daemon restart (a wrapper is
#     exec'd fresh per qrexec call, so the new logic is live the instant the
#     file is replaced; restarting the policy daemon is unnecessary and avoids
#     any qrexec disruption).
#   - no new RPC service, no new qube, no daemon.
#
# What the new wrapper does: replaces the deny-nothing setattr() fall-through
# with an explicit SETTABLE_PROPS allowlist. provides_network becomes
# operator-only (hard-deny, opaque), closing the self-minted-egress break.
#
# Rollback: this records a REPLACED manifest + backup, so `/tmp/run.sh revert`
# (slot-revert.sh) restores the pre-G0a wrapper from the backup tree. There is
# deliberately NO uninstall-stage-G0a.sh that reopens the hole with one command.
#
# Idempotent — re-running replaces the wrapper again (backing up whatever is
# there). Run from dom0 (normally via slot-71):
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-G0a.sh' > /tmp/install-G0a.sh
#   sudo -E SUDO_USER="$USER" bash /tmp/install-G0a.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

WRAPPER_REL="dom0-rpc/qmcp.SetPropertyAIManaged"
WRAPPER_DST="/etc/qubes-rpc/qmcp.SetPropertyAIManaged"
STAGE_DIR="/tmp/qubes-mcp-stage-g0a.$$"

CHANGELOG="/var/log/qmcp-changes.log"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
ROLLBACK_DIR="/var/lib/qmcp-rollback/$TS"
MANIFEST="$ROLLBACK_DIR/MANIFEST"

log()      { local l="[$(date -Is)] G0A $*"; sudo bash -c "echo '$l' >> '$CHANGELOG'"; echo "$l"; }
manifest() { sudo bash -c "printf '%s\n' '$*' >> '$MANIFEST'"; }
backup()   { [ -e "$1" ] && { sudo install -D -m 0644 "$1" "$ROLLBACK_DIR$1"; log "BACKUP $1"; }; return 0; }

echo "==> Stage G0a deploy starting"
echo "    source qube:  $SOURCE_QUBE"
echo "    source path:  $SOURCE_PATH"
echo "    rollback dir: $ROLLBACK_DIR"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling the G0a wrapper from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"
qvm-run --pass-io "$SOURCE_QUBE" "cd '$SOURCE_PATH' && tar -cf - '$WRAPPER_REL'" \
    > "$STAGE_DIR/g0a.tar"
( cd "$STAGE_DIR" && tar -xf g0a.tar )
STAGED="$STAGE_DIR/$WRAPPER_REL"
[ -s "$STAGED" ] || { echo "FATAL: pulled an empty wrapper" >&2; exit 1; }

echo "==> SHA-256 of pulled wrapper (record for your audit):"
( cd "$STAGE_DIR" && sha256sum "$WRAPPER_REL" )
echo

# ---------------------------------------------------------------- 2. validate
# A broken SetProperty wrapper would break every property write. Syntax-check
# the staged file BEFORE it replaces the live one (the extension-less analogue
# of the policy-file pre-validate lesson). compile() only — no import, so it
# needs no qubesadmin and runs no wrapper code.
echo "==> Validating the staged wrapper compiles..."
if python3 -c "import sys; src=open(sys.argv[1]).read(); compile(src, sys.argv[1], 'exec')" "$STAGED"; then
    echo "    OK — staged wrapper is syntactically valid."
else
    echo "FATAL: staged wrapper does not compile — ABORTING, live file untouched." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
# Belt-and-suspenders: confirm the allowlist actually shipped (guards against
# pulling a stale pre-G0a wrapper).
if ! grep -q "SETTABLE_PROPS" "$STAGED"; then
    echo "FATAL: staged wrapper has no SETTABLE_PROPS — that is the pre-G0a file. ABORTING." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo

# ---------------------------------------------------------------- 3. backup + install (REPLACED)
sudo mkdir -p "$ROLLBACK_DIR"; sudo touch "$CHANGELOG" "$MANIFEST"
log "=== STAGE G0A INSTALL START rollback=$ROLLBACK_DIR ==="

if [ -e "$WRAPPER_DST" ]; then
    backup "$WRAPPER_DST"
    manifest "REPLACED=$WRAPPER_DST"
    log "REPLACE $WRAPPER_DST (pre-G0a wrapper backed up)"
else
    # A wrapper this old should always pre-exist; handle the broken-tree case.
    manifest "ADDED-DOM0=$WRAPPER_DST"
    log "ADD $WRAPPER_DST (was absent — recorded ADDED-DOM0)"
fi
sudo install -m 0755 -o root -g root "$STAGED" "$WRAPPER_DST"
echo "==> Installed $WRAPPER_DST (0755 root:root)"

# NO policy-daemon restart — this stage changes no policy file. (Left as a
# comment so a future reader does not "helpfully" add one.)

# ---------------------------------------------------------------- 4. cleanup
rm -rf "$STAGE_DIR"
echo
echo "==> Stage G0a deploy complete.  Rollback: $MANIFEST  (or '/tmp/run.sh revert')"
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/offline-validate-G0a.py"
echo "  .venv/bin/python deploy/test-stage-a.py"
