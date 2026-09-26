#!/bin/bash
# uninstall-stage-3d.sh — run in dom0.
#
# Reverts Wave 2 Stage 3d, and is honest that this one is NOT a single write.
#
# WHY IT DIFFERS FROM 3c's REVERT. 3c is disarmed by unlinking
# /etc/qmcp/enforce-mode, because 3c's whole effect is gated on that flag. 3d
# has no flag ON PURPOSE: a guard behind /etc/qmcp/enforce-mode would be inert
# under `shadow`, which is this fleet's posture and precisely the state the gap
# is live in. The cost of that decision is paid here — reverting 3d means
# putting the pre-3d wrapper code back, not flipping something.
#
# THE ORDER MATTERS, AND GETTING IT WRONG IS A FLEET-WIDE OUTAGE.
# The guard fails CLOSED by design: a wrapper that cannot load
# qmcp_principal.py REFUSES. So removing the lib while the 3d wrappers are
# still installed does not "turn the guard off" — it turns every guarded call
# into a refusal, for every target, not just the principal. This script refuses
# to do that.
#
# THE SUPPORTED REVERT, in order:
#     git -C <repo> checkout <pre-3d-ref> -- dom0-rpc/
#     bash deploy/install-stage-3c.sh mcp-control <repo>     # pre-3d wrappers
#     bash /tmp/uninstall-3d.sh     # strips the deny lines IN PLACE, drops the lib
#
# Do NOT use install-stage-I-4.sh for the policy half. It writes the WHOLE
# shipped policy, which carries the four @tag:ai-managed COMPAT backstops: on a
# flipped fleet it refuses, and with QMCP_ALLOW_UNFLIP=1 it restores them —
# un-flipping the fleet, the F9 split-brain this stage's own GATE 0 exists to
# prevent. An earlier version of this header listed it as a revert step; the
# uninstaller's in-place strip is the correct policy revert and keeps whatever
# flip state the fleet is in. (install-stage-3c.sh has its own gate: it refuses
# while /etc/qmcp/enforce-mode exists, overridable with QMCP_ALLOW_ARMED_INSTALL=1.)
#
# Idempotent — re-runnable.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/uninstall-stage-3d.sh' > /tmp/uninstall-3d.sh
#   bash /tmp/uninstall-3d.sh
#
# Environment:
#   QMCP_POLICY_ONLY=1   revert ONLY the policy half (delete the self-target
#                        deny lines) and leave the code alone. The
#                        code half then still guards the @adminvm surfaces,
#                        which is a narrowing, not a split-brain — safe.

set -euo pipefail

#: The one predicate for "this is a Stage 3d self-target deny line", shared by
#: the count and the strip below so they cannot disagree about what to remove.
AWK_IS_3D_DENY='
function is3d(   n, t) {
  n = split($0, t, /[[:space:]]+/)
  return (n >= 5 && t[5] == "deny" && t[3] == t[4] &&
          (t[1] == "admin.vm.firewall.Set" || t[1] == "admin.vm.firewall.Reload"))
}
'

LIB="/etc/qubes-rpc/qmcp_principal.py"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
WRAPPERS="qmcp.SetPropertyAIManaged qmcp.SetFeatureAIManaged
qmcp.LifecycleAIManaged qmcp.AttachDeviceAIManaged qmcp.DetachDeviceAIManaged"

echo "==> Wave 2 Stage 3d revert"
echo

# --------------------------------------------------- preconditions, FIRST
# Detected BEFORE anything is written, and the ordering is the whole point.
#
# This block used to live below the policy half, next to the refusal it feeds.
# Exercised on hardware for the first time 2026-09-11, that shape was a partial
# revert on an error path: the run stripped the two policy deny lines, THEN hit
# the refusal, printed "That is an outage, not a revert" and exited 1 — leaving
# the fleet code-guarded and policy-unguarded while telling the operator it had
# refused. Measured: `denies=2` before, `denies=0` after a run that reported
# failure. A script that mutates before it validates cannot honestly report
# refusing.
STILL_3D=""
for w in $WRAPPERS; do
    p="/etc/qubes-rpc/$w"
    [ -f "$p" ] || continue
    if grep -q '_principal_refuses' "$p"; then
        STILL_3D="$STILL_3D $w"
    fi
done

if [ -n "$STILL_3D" ] && [ "${QMCP_POLICY_ONLY:-0}" != "1" ]; then
    echo "REFUSING: nothing has been changed." >&2
    echo >&2
    echo "These wrappers still carry the Stage 3d guard:" >&2
    for w in $STILL_3D; do echo "    $w" >&2; done
    echo >&2
    echo "The guard fails CLOSED. Removing $LIB underneath them" >&2
    echo "would not disable it — it would make EVERY guarded call refuse, for" >&2
    echo "every target, not just the principal. That is an outage, not a revert." >&2
    echo >&2
    echo "Put the pre-3d wrappers back first (see this script's header), then" >&2
    echo "re-run. Or, to revert only the policy half now:" >&2
    echo "    QMCP_POLICY_ONLY=1 bash \$0" >&2
    exit 1
fi

# ------------------------------------------------------------- policy half
if [ -f "$POLICY_DST" ]; then
    # Counted with the SAME predicate the strip below uses, in awk, so the two
    # cannot drift. Deliberately not `grep -E` with a \4 backreference: that is
    # a GNU extension, and it is a hard error on other greps (measured on
    # ugrep, 2026-09-01) — the count would then be empty, `-gt 0` false, and
    # the policy half would silently not revert while the script reported
    # success. Reading a tool error as "zero matches" is the same defect as
    # reading an anti-grep that could not run as an anti-grep that found
    # nothing.
    BEFORE="$(awk "$AWK_IS_3D_DENY"' { if (is3d()) c++ } END { print c+0 }' "$POLICY_DST" 2>/dev/null || echo 0)"
    if [ "${BEFORE:-0}" -gt 0 ]; then
        echo "==> Removing $BEFORE Stage 3d self-target deny line(s) from policy..."
        TMP="$(mktemp)"
        # Drop the deny lines and the 3d comment block that introduces them.
        awk "$AWK_IS_3D_DENY"'
          # A comment block ends where the comments end — not at the next
          # blank line. Keying it on a blank assumed one always followed; when
          # the two loopback-only denies were cut it no longer did, and the
          # skip ran on into live @tag: rules. Structure, not adjacency.
          /^# --- Wave 2 Stage 3d: the calling principal/ { skip=1 }
          skip && /^#/                                    { next }
          skip                                            { skip=0; eat=1 }
          /^# Stage 3d principal guard/                   { eat=1; next }
          is3d()                                          { eat=1; next }
          # The comment+rule+blank that this stage inserted goes out whole; a
          # blank left behind reads as a diff for the next reader to puzzle over
          # (measured: the first draft left three).
          eat && /^$/                                     { eat=0; next }
          { eat=0; print }
        ' "$POLICY_DST" > "$TMP"
        # Validate BEFORE replacing — a malformed policy breaks ALL of qrexec.
        if ! python3 - "$TMP" <<'PY'
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
            echo "FATAL: the rewritten policy does not lint — NOT installing it." >&2
            rm -f "$TMP"; exit 1
        fi
        sudo install -m 0664 -o root -g qubes "$TMP" "$POLICY_DST"
        rm -f "$TMP"
        sudo systemctl reset-failed qubes-qrexec-policy-daemon qubes-policy-daemon 2>/dev/null || true
        sudo systemctl reload qubes-qrexec-policy-daemon 2>/dev/null \
            || sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null \
            || sudo systemctl restart qubes-policy-daemon 2>/dev/null || true
        if systemctl is-failed --quiet qubes-qrexec-policy-daemon 2>/dev/null; then
            echo "FATAL: the policy daemon failed after reload. Inspect before" >&2
            echo "       proceeding — qrexec is now evaluating policy per call." >&2
            exit 1
        fi
        echo "    policy half reverted; daemon healthy."
    else
        echo "==> No Stage 3d deny lines in policy — nothing to revert there."
    fi
fi
echo

if [ "${QMCP_POLICY_ONLY:-0}" = "1" ]; then
    echo "==> QMCP_POLICY_ONLY=1 — leaving the code half installed."
    echo "    The @adminvm wrapper surfaces are still guarded. That is a"
    echo "    narrowing relative to pre-3d, not a split-brain, so it is safe to"
    echo "    sit in indefinitely."
    exit 0
fi

# ------------------------------------------------------------- code half
# Preconditions were checked at the top; reaching here means either the pre-3d
# wrappers are back, or no 3d wrapper is installed at all.

if [ -f "$LIB" ]; then
    sudo rm -f "$LIB"
    echo "==> Removed $LIB."
else
    echo "==> $LIB already absent."
fi
echo

cat <<'EOF'
==> Stage 3d reverted.

    The principal is an OBJECT again on every surface it was before: the
    @adminvm wrapper surfaces (SetProperty, SetFeature, Lifecycle, device
    attach/detach) and the @tag:-scoped ones (exec, copy, firewall write).

    That is the pre-3d state, and it is worth restating what it means, because
    the state reads as harmless right up until the gateway is tagged: with
    /etc/qmcp/tier-default absent (compat, the shipped default), an
    umbrella-tagged gateway is fully mutable from the AI seat, and `name` is
    settable. Renaming the gateway severs every policy line that names it.

    If you reverted to debug something, the narrower option is to keep the code
    half and drop only the policy half:
        QMCP_POLICY_ONLY=1 bash /tmp/uninstall-3d.sh
EOF
