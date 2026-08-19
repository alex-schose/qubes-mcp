#!/bin/bash
# uninstall-stage-3c.sh — run in dom0.
#
# Reverts the BEHAVIOUR of Wave 2 Stage 3c, which is the whole of what an
# operator normally wants, and is honest about what it does not do.
#
# WHAT THIS REVERTS — everything Stage 3c can actually change.
# 3c's wrappers act on the kernel only when `/etc/qmcp/enforce-mode` says so.
# Removing that file resolves every wrapper to SHADOW, and shadow is defined as
# "return the wrapper's own verdict, unchanged" — the Stage 1 behaviour, byte
# for byte, including that `remove` is a real remove and not a tombstone. So a
# single unlink is a complete behavioural revert, with no policy reload, no
# qrexec daemon restart and no slot-revert. That property is the reason the flag
# exists at all; using it is not a workaround.
#
# WHAT THIS DOES NOT DO — and will not pretend to.
# It does not put the Stage 1/2 wrapper CODE back. Those files are not archived
# anywhere in dom0, and an uninstaller that silently left newer code in place
# while reporting success would be the "read a refusal as a result" failure this
# project has already been bitten by. To revert the code, re-run the installers
# from a pre-3c checkout of the repo:
#
#     git -C <repo> checkout <pre-3c-ref> -- dom0-rpc/
#     bash deploy/install-stage-1.sh   mcp-control <repo>
#     bash deploy/install-stage-2.sh   mcp-control <repo>
#
# It also leaves qmcp_enforce.py, qmcp_tombstone.py and the reaper alone: those
# belong to Stages 3b and 3a, which have their own uninstallers.
#
# Idempotent — re-runnable.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/uninstall-stage-3c.sh' > /tmp/uninstall-3c.sh
#   bash /tmp/uninstall-3c.sh

set -euo pipefail

echo "==> Wave 2 Stage 3c revert (disarm; the code stays)"
echo

if [ -e /etc/qmcp/enforce-mode ]; then
    echo "==> Current enforcement mode:"
    sudo sed 's|^|    |' /etc/qmcp/enforce-mode || true
    sudo rm -f /etc/qmcp/enforce-mode
    echo "==> Removed /etc/qmcp/enforce-mode."
else
    echo "==> /etc/qmcp/enforce-mode already absent — nothing was armed."
fi
echo

# Confirm against the REAL installed wrappers rather than asserting it. If a
# wrapper still resolves to something other than shadow after the file is gone,
# the revert did NOT work and saying so is the only useful thing to do.
echo "==> Verifying every installed wrapper now resolves to shadow..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader

NAMES = ["qmcp.LifecycleAIManaged", "qmcp.SetPropertyAIManaged",
         "qmcp.SetFeatureAIManaged", "qmcp.CloneAIManagedQube",
         "qmcp.SpawnAIManagedQube", "qmcp.SpawnDisposableAIManaged",
         "qmcp.AttachDeviceAIManaged", "qmcp.DetachDeviceAIManaged"]
fail = []
seen = 0
for name in NAMES:
    p = os.path.join("/etc/qubes-rpc", name)
    if not os.path.exists(p):
        continue
    loader = SourceFileLoader("u_" + name.replace(".", "_"), p)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    if not hasattr(mod, "_enforce_mode"):
        # A pre-3c wrapper. Nothing to disarm; it never read the flag.
        continue
    seen += 1
    if mod._enforce_mode() != "shadow":
        fail.append("%s: still resolves to %r" % (name, mod._enforce_mode()))
    if mod._enforcing():
        fail.append("%s: _enforcing() is still true" % name)

print("    %d Stage 3c wrapper(s) checked." % seen)
for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: a wrapper is still enforcing after the flag was removed." >&2
    echo "       Do not treat this as reverted. Check for a second copy of the" >&2
    echo "       flag path, or a wrapper with a hardcoded mode." >&2
    exit 1
fi
echo "    all shadow."
echo

cat <<'EOF'
==> Stage 3c disarmed.

    Every wrapper now returns its own verdict unchanged: the Stage I-5 CAP_FULL
    gates are authoritative again, `remove` deletes rather than entombs, and the
    kernel is back to logging divergence only.

    Existing tombstones are NOT touched — they are Stage 3a's, they still count
    against the pool cap, and the reaper still governs them on its timer. To
    inspect or stop that:  sudo /usr/local/lib/qmcp/qmcp-tombstone-reaper --list

    To re-arm:   echo strict | sudo tee /etc/qmcp/enforce-mode
    To revert the wrapper CODE as well, see the header of this script.
EOF
