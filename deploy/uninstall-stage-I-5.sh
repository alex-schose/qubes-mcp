#!/bin/bash
# uninstall-stage-I-5.sh — run in dom0.
#
# Reverts Stage I-5 (CAP_FULL wrapper gates + the exec policy tiers).
#
# I-5 modifies 9 dom0 files: 8 qmcp.* wrappers (each gained a fail-closed
# CAP_FULL gate via qmcp_tier) and the single policy file (the exec surfaces
# graduated to the tier ladder + a @tag:ai-managed compat backstop each). All 9
# PRE-EXIST in dom0 from prior stages — I-5 added NO new dom0 file, so the
# CLEANEST revert is the slot-runner rollback, which restores every one of them
# byte-exact from the backup the deploying slot captured (each recorded as
# REPLACED):
#
#     /tmp/run.sh revert
#
# Prefer that. qmcp_tier.py is NOT touched by I-5 (slot-52 owns it), so a revert
# leaves the helper installed and inert — exactly the I-3..I-4 state, which is
# behaviour-neutral. Do NOT remove qmcp_tier.py here.
#
# This script is the FALLBACK when the slot backup is unavailable. It cannot
# reconstruct the pre-I-5 wrapper bytes (they live only in the slot backup tree
# or the public source), so it does the one thing it safely can without that
# backup: strip the I-5 EXEC tier lines + backstops from the live policy,
# restoring exec to the single pre-I-5 @tag:ai-managed form, and it WARNS that
# the wrapper gates remain until you reinstall the pre-I-5 wrappers from source.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-I-5.sh' > /tmp/uninstall-I-5.sh
#   bash /tmp/uninstall-I-5.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage I-5 uninstall (fallback — STRONGLY prefer '/tmp/run.sh revert')"
echo
echo "    The slot revert restores the 8 wrappers AND the policy byte-exact."
echo "    This fallback only reverts the POLICY (exec tiers); the wrapper"
echo "    CAP_FULL gates stay until you reinstall the pre-I-5 wrappers from"
echo "    source. In COMPAT they are behaviour-neutral anyway, so a policy-only"
echo "    revert is safe — but use the slot revert for a true byte-exact undo."
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
BK="$BK_DIR/$(basename "$POLICY").pre-uninstall-I-5.$TS"
sudo cp -a "$POLICY" "$BK"
echo "==> Backed up current policy to $BK"
echo

# Restore the EXEC surfaces (RunInAIManaged / CopyToAIManaged) to the single
# pre-I-5 @tag:ai-managed allow. Remove the @tag:ai-exec/ai-net/ai-full tier
# lines AND the backstop comment lines; the @tag:ai-managed line was the pre-I-5
# rule, so it stays and becomes the sole rule again (it carries `user=root`).
for svc in RunInAIManaged CopyToAIManaged; do
    sudo sed -i "\#^qmcp\.$svc  *\*  *mcp-control  *@tag:ai-exec  *allow#d" "$POLICY"
    sudo sed -i "\#^qmcp\.$svc  *\*  *mcp-control  *@tag:ai-net  *allow#d" "$POLICY"
    sudo sed -i "\#^qmcp\.$svc  *\*  *mcp-control  *@tag:ai-full  *allow#d" "$POLICY"
    # delimiter must NOT be '#': the comment line itself starts with '#'. Use '|'.
    sudo sed -i "\|^# COMPAT backstop ($svc)|d" "$POLICY"
done
echo "==> Restored qmcp.RunInAIManaged/CopyToAIManaged to the single @tag:ai-managed rule."
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

# Coherence with the FLIP: I-5 leaves the wrapper CAP_FULL gates installed, so if
# the fleet was flipped (/etc/qmcp/tier-default=ro) those gates keep enforcing
# least-privilege on untiered qubes while this policy revert loosens the exec
# surface — the split-brain the design forbids. Reset the flag to compat so the
# still-installed wrapper gates resolve untiered=full again, coherent with the
# reverted policy.
FLAG="/etc/qmcp/tier-default"
if [ -f "$FLAG" ] && [ "$(sudo awk 'NR==1{print $1}' "$FLAG" 2>/dev/null)" = "ro" ]; then
    sudo cp -a "$FLAG" "$BK_DIR/tier-default.pre-uninstall-I-5.$TS"
    sudo rm -f "$FLAG"
    echo "==> Fleet was flipped (tier-default=ro); reset to compat (removed $FLAG)."
    echo "    The still-installed wrapper gates now resolve untiered=full — no split-brain."
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
echo "==> Stage I-5 policy revert complete (exec back to @tag:ai-managed)."
echo "    REMINDER: the 8 wrapper CAP_FULL gates are STILL installed (compat =>"
echo "    behaviour-neutral). To fully undo, '/tmp/run.sh revert' OR reinstall"
echo "    the pre-I-5 wrappers from source. qmcp_tier.py is intentionally kept."
