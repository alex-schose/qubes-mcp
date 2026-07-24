#!/bin/bash
# uninstall-stage-I-6.sh — run in dom0.
#
# Reverts Stage I-6 (the operator-consent MECHANISM, shipped inert).
#
# I-6 adds SIX brand-new dom0 files (the daemon, the helper, the tmpfiles conf,
# the two /etc/qmcp config files, and the operator --user unit) and PATCHES the 8
# state-changing qmcp.* wrappers. The CLEANEST revert is the slot-runner rollback,
# which removes the ADDED-DOM0 files and restores the REPLACED wrappers byte-exact
# from the backup the deploying slot captured:
#
#     /tmp/run.sh revert
#
# Prefer that. This script is the FALLBACK when the slot backup is unavailable.
# It cannot reconstruct the pre-I-6 wrapper bytes (they live only in the slot
# backup tree or the public source), so for the wrappers it WARNS that they must
# be reinstalled from the pre-I-6 source; everything else (daemon, tmpfiles,
# unit, socket) it removes cleanly.
#
# CRITICAL — why this fallback KEEPS the helper + the empty policy:
# The 8 wrappers call `_consent_gate(action)` on EVERY state-changing op, and
# `_consent_gate` short-circuits `if _CONSENT is None: return False` BEFORE it
# ever reads the policy. So removing the helper (qmcp_consent.py) while the hooked
# wrappers are still live does NOT fail-closed to "just the 4 DEFAULT_GATED ops"
# — the None-check fires first and every state-changing op (start/shutdown/kill/
# pause/unpause/remove, set-property, set-feature, clone, spawn, spawn-disposable,
# attach, detach) returns "not found or refused". That BRICKS all 8 surfaces and
# is NOT byte-neutral. The ONLY byte-neutral inert state with the hooked wrappers
# present is helper PRESENT + empty policy PRESENT: then gate() returns
# (True,"open") without touching the daemon and behaviour matches pre-I-6 exactly.
# Therefore this fallback leaves BOTH the helper and the empty policy in place and
# removes only the daemon/tmpfiles/unit/socket. The wrappers stay validly inert
# until you reinstall the pre-I-6 (hook-free) wrappers — at which point the helper
# and policy can be deleted by hand (see the end of this script).
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-I-6.sh' > /tmp/uninstall-I-6.sh
#   bash /tmp/uninstall-I-6.sh

set -uo pipefail

RPC_DST="/etc/qubes-rpc"
DAEMON_DST="/usr/local/lib/qmcp/qmcp-consentd"
HELPER_DST="$RPC_DST/qmcp_consent.py"
TMPFILES_DST="/etc/tmpfiles.d/qmcp.conf"
SOCKET="/run/qmcp/consent.sock"
POLICY_DST="/etc/qmcp/consent-policy"
TIMEOUT_DST="/etc/qmcp/consent-timeout"

OPERATOR="${SUDO_USER:-}"
[ -z "$OPERATOR" ] && OPERATOR="$(id -un 1000 2>/dev/null || echo user)"
UID_OP="$(id -u "$OPERATOR" 2>/dev/null || echo 1000)"
OP_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)"
[ -z "$OP_HOME" ] && OP_HOME="/home/$OPERATOR"
UNIT_DST="$OP_HOME/.config/systemd/user/qmcp-consent.service"

echo "==> Stage I-6 uninstall (fallback — STRONGLY prefer '/tmp/run.sh revert')"
echo
echo "    The slot revert restores the 8 wrappers byte-exact AND removes the new"
echo "    files. This fallback removes the daemon/tmpfiles/unit/socket and KEEPS"
echo "    the helper + EMPTY consent policy (that pair is the byte-neutral inert"
echo "    state — the wrappers' hook reads the empty policy and short-circuits to"
echo "    'open'). Removing the helper here would deny ALL state-changing ops, so"
echo "    it is left until you reinstall the pre-I-6 wrappers from source."
echo

# ---------------------------------------------------------------- 1. stop + disable the --user unit
echo "==> Stopping + disabling the operator --user unit ($OPERATOR)..."
if [ -e "$UNIT_DST" ]; then
    sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$UID_OP" \
        systemctl --user disable --now qmcp-consent.service 2>/dev/null \
        && echo "    disabled + stopped qmcp-consent.service" \
        || echo "    (could not reach $OPERATOR's session bus; will remove the unit file anyway)"
    sudo rm -f "$UNIT_DST"
    sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$UID_OP" \
        systemctl --user daemon-reload 2>/dev/null || true
    echo "    removed $UNIT_DST"
else
    echo "    no unit at $UNIT_DST — nothing to stop."
fi
echo

# ---------------------------------------------------------------- 2. remove the daemon + its dir (if empty) + a stale socket
echo "==> Removing the daemon + socket..."
sudo rm -f "$DAEMON_DST"
sudo rmdir /usr/local/lib/qmcp 2>/dev/null || true
sudo rm -f "$SOCKET"
# The /run/qmcp dir is tmpfs-backed and recreated by tmpfiles; remove it now so a
# stale dir doesn't linger with the old perms.
sudo rmdir /run/qmcp 2>/dev/null || true
echo "    removed $DAEMON_DST and $SOCKET"
echo

# ---------------------------------------------------------------- 3. remove the tmpfiles conf
echo "==> Removing the tmpfiles conf..."
sudo rm -f "$TMPFILES_DST"
echo "    removed $TMPFILES_DST"
echo

# ---------------------------------------------------------------- 4. config files + helper — KEEP them (this IS the byte-neutral inert state)
# With the hooked wrappers still live, the ONLY byte-neutral state is
# helper-present + empty-policy-present (gate() short-circuits to "open" without
# touching the daemon). Removing EITHER breaks byte-neutrality:
#   - remove the policy => consent_required hits the missing-file branch =>
#     MALFORMED => the 4 DEFAULT_GATED ops route to the (now-gone) daemon => DENY.
#   - remove the helper => _CONSENT is None short-circuits BEFORE the policy is
#     read => ALL 8 state-changing surfaces return "not found or refused".
# So we keep BOTH. Delete them by hand ONLY after reinstalling the pre-I-6
# (hook-free) wrappers, in that order (wrappers first, then policy+helper).
echo "==> Leaving the helper + config files in place (this IS the byte-neutral inert state):"
[ -e "$HELPER_DST" ]  && echo "    kept $HELPER_DST (present => gate() reads the empty policy, short-circuits to 'open')"
[ -e "$POLICY_DST" ]  && echo "    kept $POLICY_DST (empty gate — keeps hooked wrappers inert)"
[ -e "$TIMEOUT_DST" ] && echo "    kept $TIMEOUT_DST"
echo "    (Remove helper + policy by hand ONLY AFTER reinstalling the pre-I-6 wrappers.)"
echo

# ---------------------------------------------------------------- 5. wrappers — cannot rebuild here; warn (do NOT remove the helper)
echo "==> The 8 wrappers STILL carry the I-6 consent hook (this fallback cannot"
echo "    reconstruct their pre-I-6 bytes)."
echo "    Because the helper + empty policy are LEFT in place, the hook stays"
echo "    byte-neutral: _consent_gate reaches the helper, the helper reads the"
echo "    EMPTY policy, consent_required() returns False, and gate() returns"
echo "    (True,'open') WITHOUT opening the (now-removed) daemon socket — exactly"
echo "    pre-I-6 behaviour. Do NOT delete the helper while the hooked wrappers"
echo "    are live: that would make _CONSENT None and deny ALL 8 state-changing"
echo "    surfaces, not just the 4 default-gated ops."
echo
echo "    To FULLY undo (drop the hook entirely), restore the pre-I-6 wrappers:"
echo "      /tmp/run.sh revert                 # byte-exact, if slot-deployed"
echo "    or reinstall the pre-I-6 wrapper sources over $RPC_DST/qmcp.* ; THEN it"
echo "    is safe to 'sudo rm -f $HELPER_DST $POLICY_DST $TIMEOUT_DST'."
echo
echo "==> Stage I-6 uninstall (fallback) complete."
echo "    No qrexec policy change was made by I-6, so no policy-daemon reload is needed."
