#!/bin/bash
# deploy/uninstall.sh — remove qubes-mcp from dom0, then prove it is gone.
#
#   sudo bash uninstall.sh            remove the code, the policy and the runtime
#                                     state; keep /etc/qmcp, the hub's proposals
#                                     (/var/lib/qmcp) and the audit log
#   sudo bash uninstall.sh --purge    also remove /etc/qmcp, /var/lib/qmcp, the
#                                     audit log and the files `qmcp audit rotate`
#                                     made from it
#   sudo bash uninstall.sh --check    change nothing; only report what remains
#
# It also removes anything v0.9.16 left behind, so it works on a box that never
# ran install.sh. Qubes keep their tags (ai-managed, qmcp-*): they are your
# fleet's data, and `qvm-tags` removes them if you want them gone.
#
# The policy goes first. From that moment no AI caller can reach a qmcp.*
# service, so nothing runs half-removed. The run ends with a clean-state check
# and exits 0 only if nothing qubes-mcp installed is left beyond what it
# reports as kept: /etc/qmcp, /var/lib/qmcp, the audit log and its rotated files
# (unless --purge), the backups under /var/lib/qmcp-rollback/, which are never
# removed — they hold copies of the policy, /etc/qmcp, /var/lib/qmcp and the
# audit logs — and
# /var/log/qmcp-changes.log, the change history some older installers appended
# to.

set -euo pipefail

MODE=remove
case "${1:-}" in
    "") ;;
    --purge) MODE=purge ;;
    --check) MODE=check ;;
    *) echo "uninstall.sh: unknown option $1" >&2; exit 2 ;;
esac

LIB=/usr/local/lib/qmcp
RPC=/etc/qubes-rpc
POLICY=/etc/qubes/policy.d/30-mcp-control.policy
LEGACY_RPC="qmcp.AttachDeviceAIManaged qmcp.DetachDeviceAIManaged qmcp.ListAttachedDevicesAIManaged
qmcp.ListAIManagedQubes qmcp.GetPropertyAIManaged qmcp.SetPropertyAIManaged qmcp.SetFeatureAIManaged
qmcp.LifecycleAIManaged qmcp.SpawnAIManagedQube qmcp.CloneAIManagedQube qmcp.SpawnDisposableAIManaged
qmcp.AIManagedEvents qmcp.GetPoolStats qmcp.SubmitProposal qmcp.ProposalStatus"
LEGACY_UNITS="qmcp-consent.service qmcp-tombstone-reaper.timer qmcp-tombstone-reaper.service"
UNITS="qmcp-gate.timer qmcp-gate.service qmcp-refresh.timer qmcp-refresh.service qmcp-seal.service"
OTHER_PATHS="/usr/local/bin/qmcp /usr/local/bin/qmcp-gui /usr/share/applications/qubes-mcp.desktop
/etc/systemd/system/qmcp-gate.service /etc/systemd/system/qmcp-gate.timer
/etc/systemd/system/qmcp-refresh.service /etc/systemd/system/qmcp-refresh.timer
/etc/systemd/system/qmcp-seal.service
/etc/systemd/system/qubes-vm@.service.d/10-qmcp-seal.conf
/etc/tmpfiles.d/qmcp.conf /run/qmcp /run/qmcp-consent
/etc/systemd/system/qmcp-consent.service /etc/systemd/system/qmcp-tombstone-reaper.service
/etc/systemd/system/qmcp-tombstone-reaper.timer
/etc/qmcp/tier-default /etc/qmcp/enforce-mode /etc/qmcp/birth-ceiling /etc/qmcp/principals
/etc/qmcp/consent-policy /etc/qmcp/consent-timeout /etc/qmcp/budget.lock
/etc/qmcp/tombstone-retention /etc/qmcp/guarded"

# The files `qmcp audit rotate` makes: exactly audit.rotate()'s name, never a wider glob.
ROTATED_GLOB='/var/log/qmcp-audit.log.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z'
rotated() { for f in $ROTATED_GLOB; do [ -e "$f" ] && echo "$f"; done; return 0; }   # 0 even when none: set -e

die() { echo "uninstall.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash $0)"
[ -e /etc/qubes-release ] || die "this is not dom0"

# ===================================================================== remove
if [ "$MODE" != check ]; then
    TS="$(date -u +%Y%m%dT%H%M%SZ)"
    BACKUP=/var/lib/qmcp-rollback/$TS-uninstall
    mkdir -p "$BACKUP"
    chmod 0700 /var/lib/qmcp-rollback "$BACKUP"
    [ -f "$POLICY" ] && cp -a "$POLICY" "$BACKUP/"
    [ -d /etc/qmcp ] && cp -a /etc/qmcp "$BACKUP/etc-qmcp"
    [ -d /var/lib/qmcp ] && cp -a /var/lib/qmcp "$BACKUP/var-lib-qmcp"
    for f in /var/log/qmcp-audit.log $(rotated); do [ -f "$f" ] && cp -a "$f" "$BACKUP/"; done
    say "backed up to $BACKUP (root-only)"

    if [ -e "$POLICY" ]; then
        rm -f "$POLICY"
        systemctl restart qubes-qrexec-policy-daemon || die "policy removed, but the daemon did not restart"
        say "removed $POLICY and restarted the policy daemon"
    fi
    for unit in $UNITS $LEGACY_UNITS; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    for f in $LEGACY_RPC "$RPC"/qmcp_*.py; do
        path="$f"; [ "${f#/}" = "$f" ] && path="$RPC/$f"
        if [ -e "$path" ]; then rm -f "$path"; say "removed $path"; fi
    done
    for path in $OTHER_PATHS; do
        if [ -e "$path" ] || [ -L "$path" ]; then rm -rf "$path"; say "removed $path"; fi
    done
    # The drop-in directory is Qubes' unit's, not ours: take it away only if
    # removing our file left it empty, and never recursively.
    if [ -d /etc/systemd/system/qubes-vm@.service.d ]; then
        rmdir /etc/systemd/system/qubes-vm@.service.d 2>/dev/null \
            && say "removed the empty /etc/systemd/system/qubes-vm@.service.d" \
            || say "left /etc/systemd/system/qubes-vm@.service.d: it holds another drop-in"
    fi
    if [ -d "$LIB" ]; then rm -rf "$LIB"; say "removed $LIB"; fi
    systemctl daemon-reload
    if [ "$MODE" = purge ]; then
        rm -rf /etc/qmcp /var/lib/qmcp /var/log/qmcp-audit.log
        for f in $(rotated); do rm -f "$f"; done
        say "purged /etc/qmcp, /var/lib/qmcp (the hub's proposals), /var/log/qmcp-audit.log and its rotated files"
    fi
fi

# ===================================================================== clean-state check
echo
say "clean-state check"
LEFT=0
report() { echo "    LEFT  $1"; LEFT=$((LEFT + 1)); }
[ -e "$POLICY" ] && report "$POLICY"
# Only names qubes-mcp installs: another tool's qmcp.* service is not ours.
for f in $LEGACY_RPC; do [ -e "$RPC/$f" ] && report "$RPC/$f"; done
for f in "$RPC"/qmcp_*.py; do [ -e "$f" ] && report "$f"; done
for path in $OTHER_PATHS "$LIB"; do
    { [ -e "$path" ] || [ -L "$path" ]; } && report "$path"
done
for unit in $UNITS $LEGACY_UNITS; do
    systemctl is-enabled --quiet "$unit" 2>/dev/null && report "enabled unit $unit"
    systemctl is-active --quiet "$unit" 2>/dev/null && report "active unit $unit"
done
if [ "$MODE" = purge ]; then
    [ -e /etc/qmcp ] && report /etc/qmcp
    [ -e /var/lib/qmcp ] && report /var/lib/qmcp
    [ -e /var/log/qmcp-audit.log ] && report /var/log/qmcp-audit.log
    for f in $(rotated); do report "$f"; done
else
    [ -e /etc/qmcp ] && echo "    kept  /etc/qmcp (operator config; --purge removes it)"
    [ -e /var/lib/qmcp ] && echo "    kept  /var/lib/qmcp (the hub's proposals and their decisions; --purge removes it)"
    [ -e /var/log/qmcp-audit.log ] && echo "    kept  /var/log/qmcp-audit.log (--purge removes it)"
    n=$(rotated | wc -l)
    [ "$n" -gt 0 ] && echo "    kept  $n rotated audit log(s), /var/log/qmcp-audit.log.<time> (--purge removes them)"
fi
if [ -d /var/lib/qmcp-rollback ]; then
    echo "    kept  /var/lib/qmcp-rollback ($(find /var/lib/qmcp-rollback -mindepth 1 -maxdepth 1 | wc -l) backups; delete by hand)"
fi
[ -e /var/log/qmcp-changes.log ] && echo "    kept  /var/log/qmcp-changes.log (change history from older installers; delete by hand)"
if [ "$LEFT" -eq 0 ]; then
    say "clean: nothing qubes-mcp installed is left"
    exit 0
fi
say "NOT clean: $LEFT item(s) left"
exit 1
