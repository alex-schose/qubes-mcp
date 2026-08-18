#!/bin/bash
# install-stage-3a.sh — run in dom0.
#
# Wave 2 Stage 3a install: the tombstone mechanism and its reaper, INERT.
#
# Surface delta:
#   - NEW dom0 lib   /etc/qubes-rpc/qmcp_tombstone.py
#                    the tag transition (entomb/verify), the retention file, and
#                    the reaper's veto matrix. Sibling-loaded exactly like
#                    qmcp_budget / qmcp_scope / qmcp_audit / qmcp_tier / qmcp_caps.
#   - NEW dom0 exec  /usr/local/lib/qmcp/qmcp-tombstone-reaper
#                    a root systemd oneshot. NOT a qrexec service: no policy line
#                    names it and it takes no input from outside dom0.
#   - NEW units      /etc/systemd/system/qmcp-tombstone-reaper.{service,timer}
#   - MODIFIED       /etc/qubes-rpc/qmcp_budget.py
#                    the pool-cap sum gains counts_toward_cap(), charging
#                    tombstones as well as ai-managed qubes.
#
# INERT. Nothing creates a tombstone yet — qmcp.LifecycleAIManaged still removes
# outright, and the flip that routes remove through here is Stage 3c. On this
# fleet the reaper finds nothing on every tick and the budget change is
# byte-identical to the code it replaces (offline-validate-3a.py §7 proves that
# by invariance over four fleet shapes). The window exists BEFORE the capability
# that needs it, which is the whole reason 3a is a separate stage.
#
# Why the budget change ships HERE and not with the flip: it is the security
# half of the tombstone. A tombstone drops the umbrella so AI cannot see it, and
# the pre-3a sum charged `"ai-managed" in tags` — so dropping the umbrella made
# a tombstone free, and an ai-exec actor could create-and-remove in a loop to
# park unbounded disk outside the accounting. Shipping the mechanism without the
# charge would arm that bypass the moment 3c landed. See §6 of the offline suite,
# which reproduces the bypass under the pre-fix predicate before asserting the
# shipped one closes it.
#
# No policy change. No qrexec daemon restart (finding F1 — nothing here touches
# policy, so nothing here restarts the policy daemon). No new AI-callable RPC
# service: a lib is not a service, a systemd unit is not a service, and no policy
# line exposes either.
#
# Idempotent — re-runnable. Install overwrites; the timer enable is a no-op when
# already enabled.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-3a.sh' > /tmp/install-3a.sh
#   bash /tmp/install-3a.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-3a"
REAPER_DIR="/usr/local/lib/qmcp"
UNIT_DIR="/etc/systemd/system"

LIBS="dom0-rpc/qmcp_tombstone.py dom0-rpc/qmcp_budget.py"
EXECS="dom0-rpc/qmcp-tombstone-reaper"
UNITS="deploy/qmcp-tombstone-reaper.service deploy/qmcp-tombstone-reaper.timer"
ALL="$LIBS $EXECS $UNITS"

echo "==> Wave 2 Stage 3a deploy starting (tombstone + reaper, INERT)"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage 3a files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Collapse the file list to one line before it becomes a REMOTE command — see
# the long note in install-stage-1.sh (finding F-L). An embedded newline in the
# remote string is read as a command separator by the target's shell, tar
# archives only the first line, and the rest EXECUTE. Do not inline this.
REMOTE_LIST="$(echo $ALL)"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $REMOTE_LIST" \
    > "$STAGE_DIR/stage-3a.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf stage-3a.tar)

for f in $ALL; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    pulled 5 files."
echo

# ---------------------------------------------------------------- 2. gates
# Everything is checked BEFORE anything is installed. A half-installed set here
# is not cosmetic: the library without the budget change IS the churn bypass.
echo "==> Compile-checking every staged python file..."
for f in $LIBS $EXECS; do
    if ! python3 -c "compile(open('$STAGE_DIR/$f').read(), '$f', 'exec')"; then
        echo "FATAL: $f failed to compile — aborting before install." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    all 3 compile."

# THE split-brain guard for this stage. Installing qmcp_tombstone.py against a
# qmcp_budget.py that predates counts_toward_cap() would mean tombstones exist
# and are charged NOTHING — the bypass, live, with no symptom whatsoever. Same
# family as the Stage 1 additive-kwarg blackout: the failure is silent, so the
# check has to be explicit.
echo "==> Confirming the staged budget helper charges tombstones..."
if ! grep -q 'def counts_toward_cap' "$STAGE_DIR/dom0-rpc/qmcp_budget.py"; then
    echo "FATAL: staged qmcp_budget.py predates counts_toward_cap()." >&2
    echo "       Installing the tombstone lib against it would make every" >&2
    echo "       tombstone free of the pool cap. Aborting." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
STAGED_TOMB_PREFIX=$(sed -n 's/^TOMBSTONE_PREFIX = "\(.*\)"$/\1/p' \
    "$STAGE_DIR/dom0-rpc/qmcp_tombstone.py")
STAGED_BUDGET_PREFIX=$(sed -n 's/^TOMBSTONE_PREFIX = "\(.*\)"$/\1/p' \
    "$STAGE_DIR/dom0-rpc/qmcp_budget.py")
if [ -z "$STAGED_TOMB_PREFIX" ] || \
   [ "$STAGED_TOMB_PREFIX" != "$STAGED_BUDGET_PREFIX" ]; then
    echo "FATAL: the two TOMBSTONE_PREFIX definitions disagree:" >&2
    echo "       qmcp_tombstone.py = '${STAGED_TOMB_PREFIX}'" >&2
    echo "       qmcp_budget.py    = '${STAGED_BUDGET_PREFIX}'" >&2
    echo "       A tombstone written under one and read under the other is" >&2
    echo "       uncharged and unreapable. Aborting." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    both agree on '${STAGED_TOMB_PREFIX}'."

echo "==> Confirming the reaper's flag surface is exactly the two read-only ones..."
# Reaping is timer-only by operator decision (2026-08-16): an under-pressure or
# on-demand reap is a path an AI can drive to destroy evidence before the
# operator has read it. The guard is an ALLOWLIST over the argument parser's
# actual flags — the G0a SETTABLE_PROPS posture — not a grep for suspicious
# words. The first draft of this check did grep for words, and it matched the
# reaper's own docstring explaining why there is no early-reap path: a lexical
# guard over prose fails on correct code and passes on a flag named innocuously.
# A parser allowlist can do neither.
STAGED_FLAGS=$(grep -o -- 'ap\.add_argument("--[a-z-]*"' "$STAGE_DIR/$EXECS" \
    | sed 's/.*"--\([a-z-]*\)"/\1/' | sort | tr '\n' ' ')
if [ "$STAGED_FLAGS" != "dry-run list " ]; then
    echo "FATAL: the staged reaper's flags are '${STAGED_FLAGS}'," >&2
    echo "       expected exactly 'dry-run list '. Any other flag is a new way" >&2
    echo "       to reap outside the timer and must be reviewed, not installed." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    flags: ${STAGED_FLAGS}(read-only; timer-only, as designed)."
echo

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && find . -type f ! -name '*.tar' -print0 \
    | sort -z | xargs -0 sha256sum | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 3. install
echo "==> Installing shared libs (0644)..."
for f in $LIBS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")"
done

echo "==> Installing the reaper (0755, root-only dir)..."
sudo install -d -m 0755 -o root -g root "$REAPER_DIR"
sudo install -m 0755 -o root -g root "$STAGE_DIR/$EXECS" \
    "$REAPER_DIR/qmcp-tombstone-reaper"
echo "    $REAPER_DIR/qmcp-tombstone-reaper"

echo "==> Installing the systemd units (0644)..."
for f in $UNITS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "$UNIT_DIR/$(basename "$f")"
    echo "    $UNIT_DIR/$(basename "$f")"
done
echo

# ---------------------------------------------------------------- 4. enable
echo "==> Enabling the reaper timer..."
sudo systemctl daemon-reload
sudo systemctl enable --now qmcp-tombstone-reaper.timer
# Verify rather than assume. F1's lesson was a fleet of installers that
# restarted a unit and never checked the result; the failure mode here is a
# timer that silently never fires, which looks exactly like "no tombstones were
# due" for as long as anyone cares to look.
if ! sudo systemctl is-active --quiet qmcp-tombstone-reaper.timer; then
    echo "FATAL: qmcp-tombstone-reaper.timer did not become active." >&2
    sudo systemctl status --no-pager qmcp-tombstone-reaper.timer >&2 || true
    exit 1
fi
echo "    timer active. Next tick:"
sudo systemctl list-timers --no-pager qmcp-tombstone-reaper.timer \
    | sed -n '2p' | sed 's|^|    |'
echo

# ---------------------------------------------------------------- 5. smoke
# The tombstone library's full proof is the offline suite (77 checks). What can
# only be proven HERE is that the installed copies load in dom0 beside their
# siblings, that the charge is live in the INSTALLED budget helper, and that the
# reaper's real path — qubesadmin, sibling load, retention read — runs clean.
echo "==> Smoke: the installed budget helper charges a tombstone..."
sudo python3 - <<'PY'
import importlib.util

def load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m

b = load("qmcp_budget", "/etc/qubes-rpc/qmcp_budget.py")
t = load("qmcp_tombstone", "/etc/qubes-rpc/qmcp_tombstone.py")

assert b.TOMBSTONE_PREFIX == t.TOMBSTONE_PREFIX, "installed prefixes disagree"
assert b.counts_toward_cap({"ai-managed"}), "live qube not charged"
assert b.counts_toward_cap({t.tombstone_tag(1)}), "TOMBSTONE NOT CHARGED"
assert not b.counts_toward_cap({"created-by-dom0"}), "outsider charged"
assert not b.counts_toward_cap({"qmcp-owner_mcp-control"}), "owner tag charged"
# The retention file's fail-closed direction points AWAY from deletion.
assert t.read_retention("/nonexistent") == t.DEFAULT_RETENTION_SECONDS
assert t.read_retention("/etc") is None, "unreadable retention did not veto"
# The reaper's vetoes, against the installed copy.
dead = {t.tombstone_tag(0)}
assert t.due_for_reap(dead, 10 ** 9, 0), "a long-dead tombstone is not due"
assert not t.due_for_reap(dead | {"ai-managed"}, 10 ** 9, 0), "umbrella veto gone"
assert not t.due_for_reap(dead, 10 ** 9, None), "malformed-config veto gone"
assert not t.due_for_reap(dead, 10 ** 9, 0, running=True), "running veto gone"
print("    charge live; retention fail-closed; all four reaper vetoes hold")
PY
echo

echo "==> Smoke: the reaper runs its real path read-only..."
# --list exercises qubesadmin, the sibling load and the retention read without
# deleting anything. On a Stage 3a fleet it must report zero tombstones: if it
# reports any, something already created one and 3c has landed early.
sudo "$REAPER_DIR/qmcp-tombstone-reaper" --list | sed 's|^|    |'
echo

# ---------------------------------------------------------------- 6. cleanup
rm -rf "$STAGE_DIR"

echo "==> Wave 2 Stage 3a deploy complete (tombstone + reaper installed, INERT)."
echo
echo "No policy change; no qrexec daemon restart; no wrapper behaviour change."
echo "Nothing creates a tombstone until Stage 3c flips qmcp.LifecycleAIManaged."
echo
echo "Transparency check from mcp-control (responses must be unchanged):"
echo "  .venv/bin/python deploy/test-stage-I-0.py    # pool cap: unchanged"
echo "  .venv/bin/python deploy/test-stage-a.py      # regression: unchanged"
echo
echo "Operator controls (both dom0-only; AI can reach neither):"
echo "  /etc/qmcp/tombstone-retention   seconds; ABSENT = 86400 (24h)."
echo "                                  Malformed = reap NOTHING, by design."
echo "  sudo $REAPER_DIR/qmcp-tombstone-reaper --list      # what exists"
echo "  sudo $REAPER_DIR/qmcp-tombstone-reaper --dry-run   # what would go"
echo "  sudo journalctl -u qmcp-tombstone-reaper           # what went"
