#!/bin/bash
# uninstall-stage-3a.sh — run in dom0.
#
# Reverts Wave 2 Stage 3a (the tombstone mechanism and its reaper).
#
# REMOVES: /etc/qubes-rpc/qmcp_tombstone.py
#          /usr/local/lib/qmcp/qmcp-tombstone-reaper
#          /etc/systemd/system/qmcp-tombstone-reaper.{service,timer}
#
# DELIBERATELY DOES NOT REVERT /etc/qubes-rpc/qmcp_budget.py, and this is the
# one decision in the script worth reading twice. The budget change charges
# tombstones against the pool cap. With the library gone nothing can create a
# new tombstone, so the charge is inert — but any tombstone that ALREADY exists
# is still occupying real disk, and reverting the charge would silently stop
# accounting for it. Un-charging existing tombstones is precisely the churn
# bypass this stage was built to close, and an uninstall script is the last
# place it should reappear. If you genuinely need the old file back, take it
# from the slot-runner MANIFEST (`/tmp/run.sh revert`), where the operation is
# explicit and reviewed rather than a side effect of "undo the stage".
#
# REFUSES BY DEFAULT WHEN TOMBSTONES EXIST. Removing the reaper is removing the
# only thing that ever cleans them up: they would sit outside the umbrella (so
# no qmcp surface can see them), charged to the cap (so they shrink AI's
# headroom), with nothing left to reap them — an invisible, permanent leak
# created by a script whose name says "uninstall". Override with
# QMCP_ALLOW_ORPHAN_TOMBSTONES=1 once you have dealt with them by hand; the
# same explicit-env idiom install-stage-I-4/I-5 use for their flip guard.
#
# The audit log is PRESERVED, always — reap and tombstone lines are evidence
# about what AI removed, not stage state.
#
# No policy change; no qrexec daemon restart.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/uninstall-stage-3a.sh' > /tmp/uninstall-3a.sh
#   bash /tmp/uninstall-3a.sh

set -euo pipefail

REAPER_DIR="/usr/local/lib/qmcp"
UNIT_DIR="/etc/systemd/system"
ALLOW_ORPHANS="${QMCP_ALLOW_ORPHAN_TOMBSTONES:-0}"

echo "==> Wave 2 Stage 3a uninstall starting (tombstone + reaper)"
echo

# ---------------------------------------------------------------- 1. guard
echo "==> Checking for tombstones that would be orphaned..."
FOUND=0
if [ -x "$REAPER_DIR/qmcp-tombstone-reaper" ]; then
    # --list is read-only and exits 0 even with nothing to report. Count the
    # data lines (the trailing summary line starts with '#').
    FOUND=$(sudo "$REAPER_DIR/qmcp-tombstone-reaper" --list 2>/dev/null \
        | grep -vc '^#' || true)
    FOUND=${FOUND:-0}
fi
if [ "$FOUND" -gt 0 ]; then
    echo "    found $FOUND tombstone(s):" >&2
    sudo "$REAPER_DIR/qmcp-tombstone-reaper" --list 2>/dev/null | sed 's|^|      |' >&2
    if [ "$ALLOW_ORPHANS" != "1" ]; then
        echo >&2
        echo "REFUSING: uninstalling now leaves those qubes with no reaper." >&2
        echo "  They are outside the umbrella, so no qmcp surface can see them;" >&2
        echo "  they stay charged to the pool cap; and nothing will ever remove" >&2
        echo "  them. Deal with them first:" >&2
        echo "    sudo $REAPER_DIR/qmcp-tombstone-reaper --list" >&2
        echo "    sudo qvm-remove <name>        # after inspecting it" >&2
        echo "  Then re-run, or override deliberately:" >&2
        echo "    QMCP_ALLOW_ORPHAN_TOMBSTONES=1 bash \$0" >&2
        exit 1
    fi
    echo "    QMCP_ALLOW_ORPHAN_TOMBSTONES=1 — proceeding, orphans left behind." >&2
else
    echo "    none. Safe to proceed."
fi
echo

# ---------------------------------------------------------------- 2. timer
echo "==> Stopping and disabling the reaper timer..."
sudo systemctl disable --now qmcp-tombstone-reaper.timer 2>/dev/null || true
sudo systemctl stop qmcp-tombstone-reaper.service 2>/dev/null || true
echo "    stopped."

# ---------------------------------------------------------------- 3. files
echo "==> Removing units, reaper and library..."
for f in "$UNIT_DIR/qmcp-tombstone-reaper.timer" \
         "$UNIT_DIR/qmcp-tombstone-reaper.service" \
         "$REAPER_DIR/qmcp-tombstone-reaper" \
         "/etc/qubes-rpc/qmcp_tombstone.py"; do
    if [ -e "$f" ]; then
        sudo rm -f "$f"
        echo "    removed $f"
    else
        echo "    (absent) $f"
    fi
done
# Only if we put it there and nothing else lives in it.
if [ -d "$REAPER_DIR" ] && [ -z "$(ls -A "$REAPER_DIR")" ]; then
    sudo rmdir "$REAPER_DIR"
    echo "    removed empty $REAPER_DIR"
fi
sudo systemctl daemon-reload
echo

# ---------------------------------------------------------------- 4. verify
echo "==> Verifying the revert..."
if sudo systemctl is-enabled --quiet qmcp-tombstone-reaper.timer 2>/dev/null; then
    echo "FATAL: the timer is still enabled after removal." >&2
    exit 1
fi
if [ -e "/etc/qubes-rpc/qmcp_tombstone.py" ]; then
    echo "FATAL: qmcp_tombstone.py is still present." >&2
    exit 1
fi
if ! grep -q 'def counts_toward_cap' /etc/qubes-rpc/qmcp_budget.py; then
    echo "WARNING: qmcp_budget.py no longer charges tombstones." >&2
    echo "         This script does not touch that file, so something else" >&2
    echo "         reverted it. Any surviving tombstone is now uncharged." >&2
fi
echo "    timer gone, library gone, pool-cap charge intact."
echo

echo "==> Wave 2 Stage 3a uninstall complete."
echo
echo "Left in place ON PURPOSE:"
echo "  /etc/qubes-rpc/qmcp_budget.py   still charges tombstones (inert with"
echo "                                  the library gone; see the header)."
echo "  /var/log/qmcp-audit.log         evidence, never stage state."
echo "  /etc/qmcp/tombstone-retention   operator config, if you created one."
