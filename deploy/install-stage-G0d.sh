#!/bin/bash
# install-stage-G0d.sh — run in dom0.
#
# Stage G0d (finding [4]): the attached-device-list backend-name redactor.
#   - NEW dom0 wrapper /etc/qubes-rpc/qmcp.ListAttachedDevicesAIManaged (redacts
#     out-of-scope backend qube names from admin.vm.device.<class>.List output).
#   - POLICY: allow the wrapper; DENY the direct admin.vm.device.<class>.List
#     (so AI must go through the redactor); .Available stays direct.
# Plus an in-repo tool change (qubes_device_list routes mode="attached" through
# the wrapper) that the mcp-control MCP server loads on restart — NOT installed
# here (see the NEXT note). The slot's tests spawn fresh python, so they exercise
# the new tool regardless.
#
# VALIDATES the staged policy before replacing the live one (I-4 lesson), records
# a manifest (ADDED-DOM0 for the new wrapper, REPLACED for the policy) so
# `/tmp/run.sh revert` restores cleanly, then reloads the policy daemon.
#
# Idempotent. Run from dom0 (normally via slot-74):
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-G0d.sh' > /tmp/install-G0d.sh
#   sudo -E bash /tmp/install-G0d.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

WRAPPER_REL="dom0-rpc/qmcp.ListAttachedDevicesAIManaged"
WRAPPER_DST="/etc/qubes-rpc/qmcp.ListAttachedDevicesAIManaged"
POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
STAGE_DIR="/tmp/qubes-mcp-stage-g0d.$$"

CHANGELOG="/var/log/qmcp-changes.log"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
ROLLBACK_DIR="/var/lib/qmcp-rollback/$TS"
MANIFEST="$ROLLBACK_DIR/MANIFEST"

log()      { local l="[$(date -Is)] G0D $*"; sudo bash -c "echo '$l' >> '$CHANGELOG'"; echo "$l"; }
manifest() { sudo bash -c "printf '%s\n' '$*' >> '$MANIFEST'"; }
backup()   { [ -e "$1" ] && { sudo install -D -m 0644 "$1" "$ROLLBACK_DIR$1"; log "BACKUP $1"; }; return 0; }
verb_for() { [ -e "$1" ] && echo "REPLACED" || echo "ADDED-DOM0"; }

echo "==> Stage G0d deploy starting (new device-list redactor wrapper + policy)"
echo "    source: $SOURCE_QUBE:$SOURCE_PATH   rollback: $ROLLBACK_DIR"
echo

# ---------------------------------------------------------------- 1. pull
rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"
qvm-run --pass-io "$SOURCE_QUBE" "cd '$SOURCE_PATH' && tar -cf - '$WRAPPER_REL' '$POLICY_REL'" > "$STAGE_DIR/g0d.tar"
( cd "$STAGE_DIR" && tar -xf g0d.tar )
STAGED_W="$STAGE_DIR/$WRAPPER_REL"; STAGED_P="$STAGE_DIR/$POLICY_REL"
[ -s "$STAGED_W" ] && [ -s "$STAGED_P" ] || { echo "FATAL: pulled empty wrapper/policy" >&2; exit 1; }
echo "==> SHA-256:"; ( cd "$STAGE_DIR" && sha256sum "$WRAPPER_REL" "$POLICY_REL" ); echo

# ---------------------------------------------------------------- 2. validate
echo "==> Validating staged wrapper compiles + policy is well-formed ..."
python3 -c "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')" "$STAGED_W" \
    || { echo "FATAL: wrapper does not compile — ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
python3 - "$STAGED_P" <<'PY' || { echo "FATAL: policy failed validation — ABORTING, live policy untouched." >&2; rm -rf "$STAGE_DIR"; exit 1; }
import sys
bad = 0
for i, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    t = s.split()
    if len(t) < 5 or t[4] not in ("allow", "deny", "ask"):
        print(f"  LINT FAIL line {i}: {s!r}"); bad += 1
sys.exit(1 if bad else 0)
PY
# Belt-and-suspenders: confirm the G0d changes shipped.
grep -q "ListAttachedDevicesAIManaged" "$STAGED_W" || { echo "FATAL: wrong wrapper staged." >&2; rm -rf "$STAGE_DIR"; exit 1; }
grep -qE '^\s*qmcp\.ListAttachedDevicesAIManaged\s+\*\s+mcp-control\s+@adminvm\s+allow' "$STAGED_P" \
    || { echo "FATAL: policy missing the wrapper allow. ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
if grep -qE '^\s*admin\.vm\.device\.usb\.(List|Attached|Assigned)\s+\*\s+mcp-control\s+@tag:ai-managed\s+allow' "$STAGED_P"; then
    echo "FATAL: policy still has a direct device-enum @tag:ai-managed allow. ABORTING." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
grep -qE '^\s*admin\.vm\.device\.usb\.Attached\s+\*\s+mcp-control\s+@anyvm\s+deny' "$STAGED_P" \
    || { echo "FATAL: policy missing the G0d .Attached deny. ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
echo "    OK."; echo

# ---------------------------------------------------------------- 3. backup + install
sudo mkdir -p "$ROLLBACK_DIR"; sudo touch "$CHANGELOG" "$MANIFEST"
log "=== STAGE G0D INSTALL START rollback=$ROLLBACK_DIR ==="

VW="$(verb_for "$WRAPPER_DST")"; backup "$WRAPPER_DST"
sudo install -m 0755 -o root -g root "$STAGED_W" "$WRAPPER_DST"
manifest "$VW=$WRAPPER_DST"; log "$VW $WRAPPER_DST"
echo "==> Installed $WRAPPER_DST (0755 root:root, $VW)"

backup "$POLICY_DST"; manifest "REPLACED=$POLICY_DST"
sudo install -m 0644 -o root -g root "$STAGED_P" "$POLICY_DST"
log "REPLACE $POLICY_DST"
echo "==> Installed $POLICY_DST (0644 root:root, REPLACED)"

# ---------------------------------------------------------------- 4. reload
echo "==> Reloading qrexec policy daemon..."
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked." >&2
fi

rm -rf "$STAGE_DIR"
echo
echo "==> Stage G0d deploy complete.  Rollback: $MANIFEST  (or '/tmp/run.sh revert')"
echo "==> NEXT: restart the mcp-control MCP server to load the qubes_device_list"
echo "         change (mode='attached' now routes through the redactor wrapper)."
