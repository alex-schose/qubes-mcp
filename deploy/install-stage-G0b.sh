#!/bin/bash
# install-stage-G0b.sh — run in dom0.
#
# Stage G0b (finding [2] + Component D): the gateway input boundary.
#   - DOM0 side (this installer): the policy file drops the two operator-UX
#     admin.vm.device.usb.{List,Available} @adminvm lines from `allow` to `ask`,
#     so an AI-shaped call can no longer SILENTLY enumerate dom0 USB.
#   - MCP-CONTROL side (NOT installed here — it is in-repo Python the running
#     FastMCP server loads): the _qrexec target validator (rejects @adminvm/dom0/
#     @-tokens before any qrexec call) + mask_error_details + exception collapse.
#     >>> After this deploy, RESTART the mcp-control MCP server so it reloads
#     >>> qubes_mcp/tools/_qrexec.py and qubes_mcp/server.py. The slot's tests
#     >>> spawn a fresh python so they exercise the new code regardless.
#
# This installer touches ONE dom0 file (the policy). It VALIDATES the staged
# policy BEFORE replacing the live one (a malformed policy can break ALL of
# qrexec on reload — the I-4 lesson), records a REPLACED manifest + backup so
# `/tmp/run.sh revert` restores the prior policy, then reloads the policy daemon.
#
# Idempotent. Run from dom0 (normally via slot-72):
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-G0b.sh' > /tmp/install-G0b.sh
#   sudo -E bash /tmp/install-G0b.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
STAGE_DIR="/tmp/qubes-mcp-stage-g0b.$$"

CHANGELOG="/var/log/qmcp-changes.log"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
ROLLBACK_DIR="/var/lib/qmcp-rollback/$TS"
MANIFEST="$ROLLBACK_DIR/MANIFEST"

log()      { local l="[$(date -Is)] G0B $*"; sudo bash -c "echo '$l' >> '$CHANGELOG'"; echo "$l"; }
manifest() { sudo bash -c "printf '%s\n' '$*' >> '$MANIFEST'"; }
backup()   { [ -e "$1" ] && { sudo install -D -m 0644 "$1" "$ROLLBACK_DIR$1"; log "BACKUP $1"; }; return 0; }

echo "==> Stage G0b deploy starting (policy only; MCP server restart follows)"
echo "    source: $SOURCE_QUBE:$SOURCE_PATH   rollback: $ROLLBACK_DIR"
echo

# ---------------------------------------------------------------- 1. pull
rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"
qvm-run --pass-io "$SOURCE_QUBE" "cd '$SOURCE_PATH' && tar -cf - '$POLICY_REL'" > "$STAGE_DIR/g0b.tar"
( cd "$STAGE_DIR" && tar -xf g0b.tar )
STAGED="$STAGE_DIR/$POLICY_REL"
[ -s "$STAGED" ] || { echo "FATAL: pulled an empty policy" >&2; exit 1; }
echo "==> SHA-256 of pulled policy:"; ( cd "$STAGE_DIR" && sha256sum "$POLICY_REL" ); echo

# ---------------------------------------------------------------- 2. validate BEFORE replacing
echo "==> Validating the staged policy before it touches /etc/qubes/policy.d/ ..."
# Prefer the real qrexec parser; fall back to a structural lint (≥5 fields +
# valid action per non-comment line — the I-4 lesson). Abort on any failure.
if python3 - "$STAGED" <<'PY'
import sys
p = sys.argv[1]
# real parser if available
try:
    from qrexec.policy.parser import FilePolicy  # noqa
    # FilePolicy wants a policy dir; a structural lint is enough + portable, so
    # we only use the import as a "parser exists" signal and still lint below.
except Exception:
    pass
bad = 0
for i, line in enumerate(open(p, encoding="utf-8"), 1):
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
# Belt-and-suspenders: confirm the finding-[2] fix actually shipped.
if grep -qE '^\s*admin\.vm\.device\.usb\.(List|Available)\s+\*\s+mcp-control\s+@adminvm\s+allow' "$STAGED"; then
    echo "FATAL: staged policy still has device.usb @adminvm ALLOW — that is the pre-G0b file. ABORTING." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo

# ---------------------------------------------------------------- 3. backup + install (REPLACED)
sudo mkdir -p "$ROLLBACK_DIR"; sudo touch "$CHANGELOG" "$MANIFEST"
log "=== STAGE G0B INSTALL START rollback=$ROLLBACK_DIR ==="
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
echo "==> Stage G0b policy deploy complete.  Rollback: $MANIFEST  (or '/tmp/run.sh revert')"
echo "==> NEXT: restart the mcp-control MCP server to load the _qrexec validator +"
echo "         server.py mask_error_details (the in-repo mcp-control-side half of G0b)."
