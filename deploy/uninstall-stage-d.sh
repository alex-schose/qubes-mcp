#!/bin/bash
# uninstall-stage-d.sh — run in dom0.
#
# Removes Stage D capability surface:
#   - Removes /etc/qubes-rpc/qmcp.CloneAIManagedQube.
#   - Removes /etc/qubes-rpc/qmcp.LifecycleAIManaged.
#   - In the policy file: strips the Stage D allow lines for those two
#     services AND restores the six Stage A `admin.vm.*` tag-scoped
#     lifecycle allow lines that Stage D removed (because Stage D
#     replaced them with the dom0-mediated lifecycle wrapper).
#   - Restarts the qrexec policy daemon.
#
# Leaves qmcp.SpawnAIManagedQube at its Stage D version on disk: its klass
# extensions (DispVMTemplate / DispVM) are additive and unreachable without
# an AI agent that knows to request those klasses. If you want pristine
# Stage C-era spawn behaviour, re-run install-stage-c.sh after a `git
# checkout` of a Stage C-era commit (so the policy pull picks up the
# pre-Stage-D file).
#
# CAVEAT — restored lifecycle policy lines work for klass=AppVM and
# klass=TemplateVM targets but NOT klass=DispVM (qrexec's @tag: selector
# doesn't match DispVM targets on at least Qubes R4.3 — see reviewer
# ask #6 in README). If you have DispVMs from Stage D testing, remove
# them via dom0 (`qvm-remove`) before running this uninstall, otherwise
# they become unmanageable through MCP.
#
# Does NOT remove any qubes created via clone or DispVM spawn during testing.
# That's the operator's call — `qvm-remove` whichever ai-* test qubes remain.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-d.sh' > /tmp/uninstall-d.sh
#   bash /tmp/uninstall-d.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage D uninstall starting"
echo

# ---------------------------------------------------------------- 1. remove Stage D RPC scripts
for svc in qmcp.CloneAIManagedQube qmcp.LifecycleAIManaged; do
    if [ -f "/etc/qubes-rpc/$svc" ]; then
        sudo rm -f "/etc/qubes-rpc/$svc"
        echo "==> Removed /etc/qubes-rpc/$svc."
    else
        echo "==> /etc/qubes-rpc/$svc absent; nothing to remove."
    fi
done
echo

# ---------------------------------------------------------------- 2. revert policy
if [ -f "$POLICY" ]; then
    echo "==> Reverting Stage D policy edits..."

    # 2a. Strip the Stage D allow block (Clone).
    if grep -q "^# --- Stage D:" "$POLICY"; then
        sudo sed -i '/^# --- Stage D:/,/^qmcp\.CloneAIManagedQube/d' "$POLICY"
        echo "    Stripped Stage D Clone allow block."
    fi

    # 2b. Strip the qmcp.LifecycleAIManaged allow line and the Stage D
    # comment lines added to the "Stage A: custom dom0 RPC services" header.
    sudo sed -i '/^qmcp\.LifecycleAIManaged /d' "$POLICY"
    sudo sed -i '/^# Lifecycle (start\/shutdown\/kill\/pause\/unpause\/remove) routes/,/^# across all klasses\.$/d' "$POLICY"

    # 2c. Restore the Stage A header comment to its pre-Stage-D form.
    sudo sed -i 's|^# --- Stage A: custom dom0 RPC services (lifecycle, discovery, properties)\.$|# --- Stage A: custom dom0 RPC services.|' "$POLICY"

    # 2d. Add back the six admin.vm.* tag-scoped lifecycle allow lines
    # (Stage A's original lifecycle block). Insert before the
    # "# --- Stage A: custom dom0 RPC services." comment line.
    if ! grep -q '^admin\.vm\.Start ' "$POLICY"; then
        sudo python3 -c "
import re
p = '$POLICY'
src = open(p).read()
block = '''# --- Stage A: lifecycle on ai-managed qubes.
# target=@adminvm clause redirects execution to dom0 without starting the
# target qube (load-bearing — omitting it triggers spurious VM starts).

admin.vm.Start              *  mcp-control  @tag:ai-managed  allow  target=@adminvm
admin.vm.Shutdown           *  mcp-control  @tag:ai-managed  allow  target=@adminvm
admin.vm.Kill               *  mcp-control  @tag:ai-managed  allow  target=@adminvm
admin.vm.Pause              *  mcp-control  @tag:ai-managed  allow  target=@adminvm
admin.vm.Unpause            *  mcp-control  @tag:ai-managed  allow  target=@adminvm
admin.vm.Remove             *  mcp-control  @tag:ai-managed  allow  target=@adminvm

'''
needle = '# --- Stage A: custom dom0 RPC services.'
if needle not in src:
    raise SystemExit('FATAL: anchor line missing from policy; cannot restore lifecycle block')
out = src.replace(needle, block + needle, 1)
open(p, 'w').write(out)
"
        echo "    Restored Stage A admin.vm.* lifecycle allow block."
    else
        echo "    Stage A lifecycle block already present; skipping insert."
    fi
else
    echo "==> Policy file not found at $POLICY; skipping policy revert."
fi
echo

# ---------------------------------------------------------------- 3. reload daemon
echo "==> Reloading qrexec policy daemon..."
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked."
fi

echo
echo "==> Stage D uninstall complete."
echo "    System is back to Stage A/B/C policy surface (klass=DispVM"
echo "    lifecycle no longer reachable via MCP — by design after revert)."
