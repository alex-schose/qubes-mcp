#!/bin/bash
# install-stage-G0e.sh — run in dom0.
#
# Stage G0e — pre-push audit remediation. Dom0-side changes (this installer):
#   - qmcp.GetPropertyAIManaged, qmcp.SetPropertyAIManaged: collapse raw {e}
#     exception text to a constant opaque message (finding [9]); detail -> stderr.
#   - qmcp.ListAttachedDevicesAIManaged: FAIL-CLOSED redactor (allowlist name
#     positions + dom0; findings [2]) and a `mode` param so the tool routes BOTH
#     attached and available device enumeration through it (finding [3]).
#   - policy: deny EVERY direct admin.vm.device.<class>.{Available,Attached,
#     Assigned} to AI (all wrapper-mediated) + project-owned @adminvm denies
#     (finding [5]).
# Mcp-control-side changes (NOT installed here — in-repo Python the server loads
# on restart): _qrexec._valid_target \A\Z anchor (finding [1]); qubes_device_list
# routes both modes through the wrapper. The slot's tests spawn fresh python.
#
# VALIDATES before replacing; records a REPLACED manifest + backup; reloads.
# Run from dom0 (normally via slot-75):
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-G0e.sh' > /tmp/install-G0e.sh
#   sudo -E bash /tmp/install-G0e.sh mcp-control ~user/qubes_mcp/public

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

WRAPPERS=(qmcp.GetPropertyAIManaged qmcp.SetPropertyAIManaged qmcp.ListAttachedDevicesAIManaged \
          qmcp.SetFeatureAIManaged qmcp.LifecycleAIManaged qmcp.ListAIManagedQubes)
POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
STAGE_DIR="/tmp/qubes-mcp-stage-g0e.$$"

CHANGELOG="/var/log/qmcp-changes.log"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
ROLLBACK_DIR="/var/lib/qmcp-rollback/$TS"
MANIFEST="$ROLLBACK_DIR/MANIFEST"

log()      { local l="[$(date -Is)] G0E $*"; sudo bash -c "echo '$l' >> '$CHANGELOG'"; echo "$l"; }
manifest() { sudo bash -c "printf '%s\n' '$*' >> '$MANIFEST'"; }
backup()   { [ -e "$1" ] && { sudo install -D -m 0644 "$1" "$ROLLBACK_DIR$1"; log "BACKUP $1"; }; return 0; }

echo "==> Stage G0e deploy (3 wrappers + policy).  rollback: $ROLLBACK_DIR"; echo

# 1. pull
rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"
TAR_ARGS=("$POLICY_REL"); for w in "${WRAPPERS[@]}"; do TAR_ARGS+=("dom0-rpc/$w"); done
qvm-run --pass-io "$SOURCE_QUBE" "cd '$SOURCE_PATH' && tar -cf - ${TAR_ARGS[*]}" > "$STAGE_DIR/g0e.tar"
( cd "$STAGE_DIR" && tar -xf g0e.tar )
echo "==> SHA-256:"; ( cd "$STAGE_DIR" && sha256sum "${TAR_ARGS[@]}" ); echo

# 2. validate
echo "==> Validating staged files..."
for w in "${WRAPPERS[@]}"; do
    python3 -c "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')" "$STAGE_DIR/dom0-rpc/$w" \
        || { echo "FATAL: $w does not compile — ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
done
python3 - "$STAGE_DIR/$POLICY_REL" <<'PY' || { echo "FATAL: policy failed lint — ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
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
# belt-and-suspenders: the G0e changes shipped
grep -q '"error": "read failed"' "$STAGE_DIR/dom0-rpc/qmcp.GetPropertyAIManaged" \
    || { echo "FATAL: GetProperty missing the [9] opaque collapse. ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
# No AI-facing raw exception ({e} or str(e)) inside an `"error":` value in ANY of
# the six wrappers (finding [9]) — NOT the intentional `print(f"...{e}",
# file=sys.stderr)` operator-debug lines (dom0-only, not a leak).
for w in "${WRAPPERS[@]}"; do
    grep -qE '"error":[^}]*(\{e\}|str\(e\))' "$STAGE_DIR/dom0-rpc/$w" \
        && { echo "FATAL: $w returns a raw exception in an AI-facing error. ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
done
grep -qE '^\s*admin\.vm\.device\.block\.Available\s+\*\s+mcp-control\s+@anyvm\s+deny' "$STAGE_DIR/$POLICY_REL" \
    || { echo "FATAL: policy missing the G0e .Available deny. ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1; }
if grep -qE '^\s*admin\.vm\.device\.[a-z]+\.Available\s+\*\s+mcp-control\s+@tag:ai-managed\s+allow' "$STAGE_DIR/$POLICY_REL"; then
    echo "FATAL: policy still has a pre-G0e .Available @tag:ai-managed allow. ABORTING." >&2; rm -rf "$STAGE_DIR"; exit 1
fi
echo "    OK."; echo

# 3. backup + install (all pre-exist => REPLACED)
sudo mkdir -p "$ROLLBACK_DIR"; sudo touch "$CHANGELOG" "$MANIFEST"
log "=== STAGE G0E INSTALL START rollback=$ROLLBACK_DIR ==="
for w in "${WRAPPERS[@]}"; do
    dst="/etc/qubes-rpc/$w"; backup "$dst"; manifest "REPLACED=$dst"
    sudo install -m 0755 -o root -g root "$STAGE_DIR/dom0-rpc/$w" "$dst"; log "REPLACE $dst"
done
backup "$POLICY_DST"; manifest "REPLACED=$POLICY_DST"
sudo install -m 0644 -o root -g root "$STAGE_DIR/$POLICY_REL" "$POLICY_DST"; log "REPLACE $POLICY_DST"
echo "==> Installed 3 wrappers + policy."

# 4. reload
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
echo; echo "==> Stage G0e complete.  Rollback: $MANIFEST  (or '/tmp/run.sh revert')"
echo "==> NEXT: restart the mcp-control MCP server to load the _qrexec validator +"
echo "         qubes_device_list routing (the in-repo mcp-control-side half)."
