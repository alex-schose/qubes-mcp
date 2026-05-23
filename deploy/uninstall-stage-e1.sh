#!/bin/bash
# uninstall-stage-e1.sh — run in dom0.
#
# Removes Stage E1 capability surface:
#   - Removes /etc/qubes-rpc/qmcp.AttachDeviceAIManaged.
#   - Removes /etc/qubes-rpc/qmcp.DetachDeviceAIManaged.
#   - In the policy file: strips the Stage E1 allow block (Attach/Detach
#     wrapper allows + tag-scoped {block,usb,mic}.{List,Available} reads)
#     and restores the explicit device.{block,usb,mic}.{List,Available}
#     denies that Stage E1 dropped (since those were superseded by the
#     tag-scoped allows the install introduced).
#   - Restarts the qrexec policy daemon.
#
# Does NOT detach any devices that may currently be attached between
# ai-managed qubes. Those persist in qubesdb until the frontend reboots
# or someone runs `qvm-device <class> detach` in dom0.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/uninstall-stage-e1.sh' > /tmp/uninstall-e1.sh
#   bash /tmp/uninstall-e1.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage E1 uninstall starting"
echo

# ---------------------------------------------------------------- 1. remove Stage E1 RPC scripts
for svc in qmcp.AttachDeviceAIManaged qmcp.DetachDeviceAIManaged; do
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
    echo "==> Reverting Stage E1 policy edits..."

    # 2a. Strip the Stage E1 allow block (header comment + 8 allow lines).
    if grep -q "^# --- Stage E1:" "$POLICY"; then
        sudo sed -i '/^# --- Stage E1:/,/^admin\.vm\.device\.mic\.Available /d' "$POLICY"
        echo "    Stripped Stage E1 allow block."
    fi

    # 2b. Restore the explicit device.{block,usb,mic}.{List,Available}
    # denies that the install removed. Insert just before the pci.Attach
    # deny line so the device-API block reads coherently again.
    if ! grep -q '^admin\.vm\.device\.block\.List ' "$POLICY"; then
        sudo python3 -c "
p = '$POLICY'
src = open(p).read()
restore = '''admin.vm.device.block.List       *  mcp-control  @anyvm  deny
admin.vm.device.block.Available  *  mcp-control  @anyvm  deny
admin.vm.device.usb.List         *  mcp-control  @anyvm  deny
admin.vm.device.usb.Available    *  mcp-control  @anyvm  deny
admin.vm.device.mic.List         *  mcp-control  @anyvm  deny
admin.vm.device.mic.Available    *  mcp-control  @anyvm  deny
'''
needle = 'admin.vm.device.pci.Attach'
if needle not in src:
    raise SystemExit('FATAL: anchor line missing from policy; cannot restore List/Available denies')
out = src.replace(needle, restore + needle, 1)
open(p, 'w').write(out)
"
        echo "    Restored device.{block,usb,mic}.{List,Available} denies."
    else
        echo "    device List/Available denies already present; skipping insert."
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
echo "==> Stage E1 uninstall complete."
echo "    System is back to Stage D policy surface."
