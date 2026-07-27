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
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked — reload may not have applied." >&2
fi

rm -rf "$STAGE_DIR"
echo
echo "==> Stage G0c policy deploy complete.  Rollback: $MANIFEST  (or '/tmp/run.sh revert')"
