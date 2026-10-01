#!/bin/bash
# deploy/uninstall.sh — remove qubes-mcp from dom0, then prove it is gone.
#
#   sudo bash uninstall.sh            remove the code, the policy and the runtime
#                                     state; keep /etc/qmcp and the audit log
#   sudo bash uninstall.sh --purge    also remove /etc/qmcp and the audit log
#   sudo bash uninstall.sh --check    change nothing; only report what remains
#
# It also removes anything v0.9.16 left behind, so it works on a box that never
# ran install.sh. Qubes keep their tags (ai-managed, qmcp-*): they are your
# fleet's data, and `qvm-tags` removes them if you want them gone.
#
# The policy goes first. From that moment no AI caller can reach a qmcp.*
# service, so nothing runs half-removed. The run ends with a clean-state check
# and exits 0 only if nothing qubes-mcp installed is left beyond what it
# reports as kept: /etc/qmcp and the audit log (unless --purge), the backups
# under /var/lib/qmcp-rollback/, which are never removed — they hold copies of
# the policy, /etc/qmcp and the audit log — and /var/log/qmcp-changes.log, the
# change history some older installers appended to.

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
qmcp.AIManagedEvents qmcp.GetPoolStats"
LEGACY_UNITS="qmcp-consent.service qmcp-tombstone-reaper.timer qmcp-tombstone-reaper.service"
OTHER_PATHS="/usr/local/bin/qmcp /etc/tmpfiles.d/qmcp.conf /run/qmcp /run/qmcp-consent
/etc/systemd/system/qmcp-consent.service /etc/systemd/system/qmcp-tombstone-reaper.service
/etc/systemd/system/qmcp-tombstone-reaper.timer
/etc/qmcp/tier-default /etc/qmcp/enforce-mode /etc/qmcp/birth-ceiling /etc/qmcp/principals
/etc/qmcp/consent-policy /etc/qmcp/consent-timeout /etc/qmcp/budget.lock
/etc/qmcp/tombstone-retention /etc/qmcp/guarded"

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
    [ -f /var/log/qmcp-audit.log ] && cp -a /var/log/qmcp-audit.log "$BACKUP/"
    say "backed up to $BACKUP (root-only)"

    if [ -e "$POLICY" ]; then
        rm -f "$POLICY"
        systemctl restart qubes-qrexec-policy-daemon || die "policy removed, but the daemon did not restart"
        say "removed $POLICY and restarted the policy daemon"
    fi
    for unit in $LEGACY_UNITS; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    for f in $LEGACY_RPC "$RPC"/qmcp_*.py; do
        path="$f"; [ "${f#/}" = "$f" ] && path="$RPC/$f"
        if [ -e "$path" ]; then rm -f "$path"; say "removed $path"; fi
    done
    for path in $OTHER_PATHS; do
        if [ -e "$path" ] || [ -L "$path" ]; then rm -rf "$path"; say "removed $path"; fi
    done
    if [ -d "$LIB" ]; then rm -rf "$LIB"; say "removed $LIB"; fi
    systemctl daemon-reload
    if [ "$MODE" = purge ]; then
        rm -rf /etc/qmcp /var/log/qmcp-audit.log
        say "purged /etc/qmcp and /var/log/qmcp-audit.log"
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
for unit in $LEGACY_UNITS; do
    systemctl is-enabled --quiet "$unit" 2>/dev/null && report "enabled unit $unit"
done
if [ "$MODE" = purge ]; then
    [ -e /etc/qmcp ] && report /etc/qmcp
    [ -e /var/log/qmcp-audit.log ] && report /var/log/qmcp-audit.log
else
    [ -e /etc/qmcp ] && echo "    kept  /etc/qmcp (operator config; --purge removes it)"
    [ -e /var/log/qmcp-audit.log ] && echo "    kept  /var/log/qmcp-audit.log (--purge removes it)"
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
