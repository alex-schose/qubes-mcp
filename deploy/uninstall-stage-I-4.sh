#!/bin/bash
# uninstall-stage-I-4.sh — run in dom0.
#
# Reverts Stage I-4 (tiers on the policy-scoped surfaces + the ai-dump valve).
#
# I-4 is a SINGLE-FILE change to /etc/qubes/policy.d/30-mcp-control.policy. The
# CLEANEST revert is the slot-runner rollback, which restores the exact pre-I-4
# file from the backup the deploying slot captured (the policy is recorded as
# REPLACED):
#
#     /tmp/run.sh revert
#
# Prefer that. This script is the fallback when the slot backup is unavailable:
# it strips the lines I-4 ADDED and restores firewall WRITE to the single
# pre-I-4 @tag:ai-managed form. Because policy edits are surgical, the slot
# backup is safer — use it if you have it.
#
# Either way: removing I-4 returns firewall WRITE to "any ai-managed qube" and
# removes the ai-dump valve. No qube is touched; no tag is changed.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-I-4.sh' > /tmp/uninstall-I-4.sh
#   bash /tmp/uninstall-I-4.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage I-4 uninstall (fallback — prefer '/tmp/run.sh revert')"
echo

if [ ! -f "$POLICY" ]; then
    echo "==> Policy file not found at $POLICY; nothing to do."
    exit 0
fi

# Back up the current file before surgery so a botched sed is recoverable.
# OUTSIDE /etc/qubes/policy.d/ — a `30-mcp-control.policy.*` sibling left in the
# policy dir risks the qrexec loader picking it up and is poor hygiene.
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BK_DIR="/var/lib/qmcp-rollback"
sudo mkdir -p "$BK_DIR"
BK="$BK_DIR/$(basename "$POLICY").pre-uninstall-I-4.$TS"
sudo cp -a "$POLICY" "$BK"
echo "==> Backed up current policy to $BK"
echo

# 1. Strip the ai-dump valve block (comment header + its one allow line).
if grep -q "^# --- Stage I-4: ai-dump" "$POLICY"; then
    sudo sed -i '/^# --- Stage I-4: ai-dump/,/^qubes\.Filecopy .*@tag:ai-dump.*allow/d' "$POLICY"
    echo "==> Stripped the ai-dump valve block."
fi

# 2. Restore firewall WRITE to the single pre-I-4 ai-managed line.
#    Remove the @tag:ai-net and @tag:ai-full WRITE lines AND the backstop
#    comments; the @tag:ai-managed backstop line is the pre-I-4 line, so it
#    stays and becomes the sole rule again.
for m in Set Reload; do
    sudo sed -i "\#^admin\.vm\.firewall\.$m  *\*  *mcp-control  *@tag:ai-net  *allow#d" "$POLICY"
    sudo sed -i "\#^admin\.vm\.firewall\.$m  *\*  *mcp-control  *@tag:ai-full  *allow#d" "$POLICY"
    # delimiter must NOT be '#': the comment line itself starts with '#'. Use '|'.
    sudo sed -i "\|^# COMPAT backstop (firewall\.$m)|d" "$POLICY"
done
echo "==> Restored firewall.Set/Reload to the single @tag:ai-managed rule."
echo

echo "==> Validating the reverted policy before reloading..."
if ! python3 - "$POLICY" <<'PY'
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
    print(f"FATAL: malformed rule line {i}: {s!r}", file=sys.stderr)
sys.exit(1 if bad else 0)
PY
then
    echo "FATAL: revert produced a malformed policy. Restoring the pre-uninstall backup." >&2
    sudo cp -a "$BK" "$POLICY"
    echo "       Restored. Use '/tmp/run.sh revert' for a clean revert instead." >&2
    exit 1
fi
echo "    reverted policy parses clean."
echo

# Coherence with the FLIP: if the fleet was flipped (/etc/qmcp/tier-default=ro),
# reverting the POLICY to compat while the wrapper surfaces stay least-privilege
# is the split-brain the design forbids (one surface loose, another strict).
# Reset the flag to compat so the wrapper surfaces revert WITH the policy.
FLAG="/etc/qmcp/tier-default"
if [ -f "$FLAG" ] && [ "$(sudo awk 'NR==1{print $1}' "$FLAG" 2>/dev/null)" = "ro" ]; then
    sudo cp -a "$FLAG" "$BK_DIR/tier-default.pre-uninstall-I-4.$TS"
    sudo rm -f "$FLAG"
    echo "==> Fleet was flipped (tier-default=ro); reset to compat (removed $FLAG)."
    echo "    Wrapper surfaces now revert WITH the policy — no split-brain."
    echo
fi

echo "==> Reloading qrexec policy daemon..."
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked — reload by hand." >&2
fi
echo
echo "==> Stage I-4 uninstall complete (firewall WRITE back to ai-managed; valve removed)."
