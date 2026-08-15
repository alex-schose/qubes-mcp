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

rm -rf "$STAGE_DIR"
echo
echo "==> Stage G0d deploy complete.  Rollback: $MANIFEST  (or '/tmp/run.sh revert')"
echo "==> NEXT: restart the mcp-control MCP server to load the qubes_device_list"
echo "         change (mode='attached' now routes through the redactor wrapper)."
