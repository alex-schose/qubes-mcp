#!/bin/bash
# uninstall-stage-flip.sh — run in dom0. UN-FLIP back to compat.
#
# Reverses install-stage-flip.sh: restores the four @tag:ai-managed compat
# backstops and the prior tier-default state, returning the fleet to compat
# (every untiered ai-managed qube = ai-full) as ONE coherent change.
#
# It restores from the backup install-stage-flip.sh wrote to
# /var/lib/qmcp-rollback/flip-latest/ (policy + the flag's prior state). If that
# backup is absent (the flip was applied some other way), use the slot-runner
# '/tmp/run.sh revert', or re-deploy I-4/I-5 from source — this script will not
# guess the pre-flip bytes.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/uninstall-stage-flip.sh' > /tmp/uninstall-flip.sh
#   bash /tmp/uninstall-flip.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"
FLAG="/etc/qmcp/tier-default"
BK_LATEST="/var/lib/qmcp-rollback/flip-latest"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BK_DIR="/var/lib/qmcp-rollback"

reload_daemon() {
    sudo systemctl reset-failed qubes-qrexec-policy-daemon qubes-policy-daemon 2>/dev/null || true
    sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null \
        || sudo systemctl restart qubes-policy-daemon 2>/dev/null \
        || echo "    WARNING: neither policy daemon name worked — reload by hand." >&2
}

echo "==> Stage I-5 UN-FLIP (restore compat backstops + reset tier-default)"
if [ ! -d "$BK_LATEST" ] || [ ! -f "$BK_LATEST/30-mcp-control.policy" ]; then
    echo "FATAL: no flip backup at $BK_LATEST." >&2
    echo "       Use '/tmp/run.sh revert' (slot MANIFEST) or re-deploy I-4/I-5 from source." >&2
    exit 1
fi

# Snapshot the current (flipped) state outside policy.d before overwriting it.
sudo cp -a "$POLICY" "$BK_DIR/$(basename "$POLICY").pre-unflip.$TS" 2>/dev/null || true

# Validate the backup BEFORE installing it (never install an unvalidated policy).
if ! python3 - "$BK_LATEST/30-mcp-control.policy" <<'PY'
import sys
bad = []
for i, line in enumerate(open(sys.argv[1], encoding='utf-8'), 1):
    s = line.strip()
    if not s or s.startswith('#'):
        continue
    t = s.split()
    if len(t) < 5 or t[4] not in ('allow', 'deny', 'ask'):
        bad.append((i, s))
for i, s in bad:
    print(f"FATAL: backup policy malformed at line {i}: {s!r}", file=sys.stderr)
sys.exit(1 if bad else 0)
PY
then
    echo "FATAL: the backup policy is malformed — refusing to install it." >&2; exit 1
fi

# Restore policy (re-adds the four backstops) + the flag's prior state together.
sudo install -m 0644 -o root -g root "$BK_LATEST/30-mcp-control.policy" "$POLICY"
if [ -e "$BK_LATEST/tier-default" ]; then
    sudo install -d -m 0755 -o root -g root "$(dirname "$FLAG")"
    sudo install -m 0644 -o root -g root "$BK_LATEST/tier-default" "$FLAG"
    echo "==> Restored prior tier-default."
else
    sudo rm -f "$FLAG"      # flag did not pre-exist the flip → compat is "absent"
    echo "==> Removed tier-default (compat default = absent)."
fi
reload_daemon

# Post-assert compat is back: the four backstops present, flag is not "ro".
remain="$(grep -cE '^(admin\.vm\.firewall\.(Set|Reload)|qmcp\.(RunInAIManaged|CopyToAIManaged))[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@tag:ai-managed[[:space:]]+allow' "$POLICY" || true)"
flagval="$( [ -e "$FLAG" ] && sudo awk 'NR==1{print $1}' "$FLAG" 2>/dev/null || echo absent )"
if [ "$remain" -eq 4 ] && [ "$flagval" != "ro" ]; then
    echo "    OK: four compat backstops restored; tier-default=$flagval (compat)."
    echo "==> Un-flip complete — fleet is back to compat (untiered ai-managed = ai-full)."
else
    echo "WARNING: post-assert unexpected (backstops_present=$remain flag=$flagval)." >&2
    echo "         Inspect $POLICY; '/tmp/run.sh revert' is the byte-exact fallback." >&2
    exit 1
fi
