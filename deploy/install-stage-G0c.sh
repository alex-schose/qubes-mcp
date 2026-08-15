#!/bin/bash
# install-stage-G0c.sh — run in dom0.
#
# Stage G0c (finding [6]): inter-ai-managed qubes.Filecopy graduates to require
# ai-exec+ on BOTH endpoints. Policy-only (one file: 30-mcp-control.policy):
# the single @tag:ai-managed -> @tag:ai-managed allow becomes the 3x3 ai-exec+
# peer-copy mesh, plus an explicit @tag:ai-managed -> @anyvm DENY (ordered after
# the ai-dump sink) so an ai-exec -> ai-ro copy is a dialog-free deny rather than
# a system-default `ask`. No wrapper/RPC/qube change; no mcp-control-side change.
#
# VALIDATES the staged policy before replacing the live one (a malformed policy
# breaks ALL of qrexec on reload — the I-4 lesson), records a REPLACED manifest +
# backup so `/tmp/run.sh revert` restores the prior policy, then reloads.
#
# Idempotent. Run from dom0 (normally via slot-73):
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-G0c.sh' > /tmp/install-G0c.sh
#   sudo -E bash /tmp/install-G0c.sh mcp-control ~user/qubes_mcp/public

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

POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
STAGE_DIR="/tmp/qubes-mcp-stage-g0c.$$"

CHANGELOG="/var/log/qmcp-changes.log"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
ROLLBACK_DIR="/var/lib/qmcp-rollback/$TS"
MANIFEST="$ROLLBACK_DIR/MANIFEST"

log()      { local l="[$(date -Is)] G0C $*"; sudo bash -c "echo '$l' >> '$CHANGELOG'"; echo "$l"; }
manifest() { sudo bash -c "printf '%s\n' '$*' >> '$MANIFEST'"; }
backup()   { [ -e "$1" ] && { sudo install -D -m 0644 "$1" "$ROLLBACK_DIR$1"; log "BACKUP $1"; }; return 0; }

echo "==> Stage G0c deploy starting (policy only)"
echo "    source: $SOURCE_QUBE:$SOURCE_PATH   rollback: $ROLLBACK_DIR"
echo

# ---------------------------------------------------------------- 1. pull
rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"
qvm-run --pass-io "$SOURCE_QUBE" "cd '$SOURCE_PATH' && tar -cf - '$POLICY_REL'" > "$STAGE_DIR/g0c.tar"
( cd "$STAGE_DIR" && tar -xf g0c.tar )
STAGED="$STAGE_DIR/$POLICY_REL"
[ -s "$STAGED" ] || { echo "FATAL: pulled an empty policy" >&2; exit 1; }
echo "==> SHA-256 of pulled policy:"; ( cd "$STAGE_DIR" && sha256sum "$POLICY_REL" ); echo

# ---------------------------------------------------------------- 2. validate BEFORE replacing
echo "==> Validating the staged policy before it touches /etc/qubes/policy.d/ ..."
if python3 - "$STAGED" <<'PY'
import sys
bad = 0
for i, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    toks = s.split()
    if len(toks) < 5:
        print(f"  LINT FAIL line {i}: <5 fields (inline comment?): {s!r}"); bad += 1; continue
    if toks[4] not in ("allow", "deny", "ask"):
        print(f"  LINT FAIL line {i}: 5th field not an action: {toks[4]!r}"); bad += 1
sys.exit(1 if bad else 0)
PY
then
    echo "    OK — staged policy is structurally valid."
else
    echo "FATAL: staged policy failed validation — ABORTING, live policy untouched." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
# Belt-and-suspenders: confirm the G0c change actually shipped.
if grep -qE '^\s*qubes\.Filecopy\s+\*\s+@tag:ai-managed\s+@tag:ai-managed\s+allow' "$STAGED"; then
    echo "FATAL: staged policy still has the pre-G0c any-to-any Filecopy line. ABORTING." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
if ! grep -qE '^\s*qubes\.Filecopy\s+\*\s+@tag:ai-managed\s+@anyvm\s+deny' "$STAGED"; then
    echo "FATAL: staged policy missing the G0c explicit @tag:ai-managed @anyvm deny. ABORTING." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo

# ---------------------------------------------------------------- 3. backup + install (REPLACED)
sudo mkdir -p "$ROLLBACK_DIR"; sudo touch "$CHANGELOG" "$MANIFEST"
log "=== STAGE G0C INSTALL START rollback=$ROLLBACK_DIR ==="
backup "$POLICY_DST"; manifest "REPLACED=$POLICY_DST"
sudo install -m 0644 -o root -g root "$STAGED" "$POLICY_DST"
log "REPLACE $POLICY_DST"
echo "==> Installed $POLICY_DST (0644 root:root)"

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

rm -rf "$STAGE_DIR"
echo
echo "==> Stage G0c policy deploy complete.  Rollback: $MANIFEST  (or '/tmp/run.sh revert')"
