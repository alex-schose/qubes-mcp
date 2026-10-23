#!/bin/bash
# deploy/install.sh — install or update qubes-mcp in dom0. Idempotent.
#
# This runs as root in dom0, so the tree it runs from must come from somewhere
# AI cannot write. A tree copied out of the hub is only as trustworthy as the
# hub: the first update after a hub compromise would hand over dom0. Fetch a
# tagged release in a fresh disposable instead:
#
#   qvm-run --dispvm=default-dvm --pass-io \
#     'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.26.tar.gz' \
#     > /tmp/qmcp.tgz
#   rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
#   tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
#   sudo bash /tmp/qubes-mcp/deploy/install.sh
#
# Clear the staging directory first: the installer copies every dom0/qmcp/*.py
# it finds, so a module left over from an older release would be installed.
#
# Options:
#   --hub NAME           the hub qube (default mcp-control). Fixed at the first
#                        install; to change it, run uninstall.sh --purge first.
#   --birth-egress QUBE  written to /etc/qmcp/birth-egress if that file is absent
#   --pool-cap BYTES     written to /etc/qmcp/pool-cap if absent (default 50 GiB)
#   --private-cap BYTES  written to /etc/qmcp/private-cap if absent (default 10 GiB)
#   --gate-user NAME     the dom0 user the anonymity gate's timer runs as (default: the
#                        user who ran this with sudo, else the qubes group's one member)
#   --anonymous          turn on anonymous mode: every project anonymous, and the gate
#                        judges the hub and the rest of AI space. Refused unless no
#                        ordinary project exists, no clearnet gateway is enrolled and the
#                        gate finds the hub sound. No qmcp command turns it off;
#                        uninstall.sh --purge does. An update keeps it without the option.
#   --updates-via GATEWAY  tick an enrolled anonymising gateway for templates' updates
#                        (qmcp gateway set GATEWAY --updates yes), before the gate's timer
#                        runs the new code (repeatable): an entry written before 0.9.24 is
#                        unticked
#   --audit-log disk|ram|none   where qmcp's audit lines go, for the whole install
#                        (/etc/qmcp/audit-mode): disk (the default), /var/log/qmcp-audit.log;
#                        ram, a chain under /run/qmcp/audit, gone at shutdown; none, no line
#                        at all. A project may keep its own lines more private still (qmcp
#                        project audit). An update keeps the mode without the option; a change
#                        leaves one line on the less private of the two. Lines already on disk
#                        stay there: deleting a file on dom0's disk is not erasing it. dom0's
#                        journal keeps every qrexec call whatever the mode (qmcp check says
#                        how to keep it in RAM)
#   --dry-run            run every check, change nothing
#
# What it installs:
#   /usr/local/lib/qmcp/qmcp/        the dom0 library
#   /etc/qubes-rpc/qmcp.*            one shim, under each service name
#   /usr/local/bin/qmcp              the operator command
#   /usr/local/bin/qmcp-gui          the operator's window, which runs that command;
#   /usr/share/applications/qubes-mcp.desktop   and its menu entry: the Qubes menu reads
#                                    only /usr/share/applications and ~/.local, and lists
#                                    under Settings > Qubes Tools an X-XFCE-SettingsDialog
#                                    entry whose file name contains "qubes"
#   /etc/qubes/policy.d/30-mcp-control.policy   the rulebook, hub name rendered in
#   /etc/tmpfiles.d/qmcp.conf        the runtime directory the caps use, and the
#                                    files root and the services share: the
#                                    proposal store /var/lib/qmcp/proposals
#                                    (root:qubes 2770), its lock, the audit log
#   /etc/qmcp/{hub,pool-cap,private-cap,birth-egress}   only when absent
#   /etc/qmcp/projects.json          the project records, empty, only when absent;
#                                    `qmcp project` writes it (as root)
#   /etc/systemd/system/qmcp-seal.service   the boot seal: it takes the open
#                                    badges off every guarded qube before any user session
#                                    exists, because a tag survives a reboot and the window
#                                    records under /run do not. Enabled, and run once here
#                                    so an install never leaves a window open
#   /etc/systemd/system/qubes-vm@.service.d/10-qmcp-seal.conf   a drop-in on Qubes' own
#                                    per-qube autostart unit, ordering it after the seal, so
#                                    an autostart qube cannot start ahead of it. The one file
#                                    qmcp installs that belongs to a Qubes unit; it changes
#                                    that unit's ordering and nothing else
#   /etc/systemd/system/qmcp-gate.{service,timer}   the anonymity gate every 15 s, as the
#                                    dom0 user the services run as (never root: it notifies
#                                    the operator's desktop), enabled and started. The timer
#                                    is stopped while this script changes things, after a run
#                                    already going has finished, and started again at the end,
#                                    also when it fails part-way, so the anonymous projects stay
#                                    judged; a qmcp command run meanwhile still runs the gate
#   /usr/local/lib/qmcp/template-rpc/   dom0's copy of the two in-qube services, from which
#                                    `qmcp template prepare` writes them into a template or a
#                                    standalone at any time
#   /etc/systemd/system/qmcp-refresh.{service,timer}   every minute, as the gate's user, the
#                                    in-qube services brought up to date in every RUNNING
#                                    prepared template or standalone; it never starts one
#   /etc/systemd/system/qmcp-audit.{service,timer}   hourly, as root: the audit log rotated
#                                    once a UTC day or past 32 MiB, and rotated logs removed
#                                    once older than /etc/qmcp/audit-keep-days (90 by default;
#                                    qmcp settings set --audit-keep-days), by age, never size
#   /etc/qmcp/audit-mode             with --audit-log: disk, ram or none
#   the qmcp-id label                on an upgrade from before 0.9.26 (v0.9.16, which wrote no
#                                    version file, known by the files it installed), or a
#                                    reinstall over the operator files a plain uninstall of
#                                    one kept when no qube carries a label or a hold yet,
#                                    once: every qube already wearing ai-managed, ai-dump or
#                                    a qmcp- badge with no label and no hold is labelled with its own UUID, the label the restore check
#                                    reads; a seed that stopped part-way runs again on the
#                                    next install (after an uninstall in between, the gate
#                                    holds what it missed). A fresh install seeds none: a badged
#                                    qube with no label of its own there came back from a backup
#                                    or a copy, or was badged before 0.9.26 and kept through a
#                                    purge, and the gate holds it for review. (With --anonymous
#                                    it labels the hub as it gets qmcp-anon.)
#   stale slot badges                with --strip-stale-badges: the slot badges no project
#                                    record backs (after uninstall.sh --purge), routed ones
#                                    first, before the policy; without it the install refuses
#                                    while any qube wears one
#   /etc/qmcp/mode                   with --anonymous: the word anonymous, written after the
#                                    policy, once qmcp-anon is on the hub and on every qube
#                                    under the hub's check; then they are stamped once more
#   the operator files' mode         every operator file under /etc/qmcp that is there and
#                                    is a plain file is set to 0644, whoever wrote it: the services and the dom0
#                                    user read them, and one written with tee under sudo
#                                    comes out 0600 under dom0's umask
# It takes every open window off (seal --all, which kills an open qube that runs), and
# anonymous mode puts qmcp-anon on the hub and on every
# qube in AI space that is not an anonymous project's lead, member or model qube,
# guarded routers aside: managed qubes from an older release stay in no project slot
# until `qmcp project move` puts them in one.
# It removes everything v0.9.16 installed that this release no longer has, and
# backs up what it replaces under /var/lib/qmcp-rollback/<timestamp>/.
#
# Every preflight check runs before anything changes: the source tree, the hub,
# the values for /etc/qmcp, the fleet's shape, and the policy, which is checked
# with qrexec's own parser against this box's real policy directory, with ours
# swapped in, before the live file is replaced. The last step is `qmcp check`, run
# as the gate's user (the dom0 user, as the README runs it), not as root, which reads
# files that user cannot; this script exits with its status (0 GREEN, 1 FAILED,
# 3 INCOMPLETE — not green).

set -euo pipefail
# Staged code is imported as root from a world-writable /tmp: never leave
# root-owned bytecode behind it.
export PYTHONDONTWRITEBYTECODE=1

HUB=""
BIRTH_EGRESS=""
POOL_CAP=$((50 * 1024 * 1024 * 1024))
PRIVATE_CAP=$((10 * 1024 * 1024 * 1024))
DRY_RUN=0
GATE_USER=""
ANONYMOUS=0
UPDATES_VIA=""
AUDIT_LOG_MODE=""
STRIP_STALE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --hub) HUB="$2"; shift 2 ;;
        --anonymous) ANONYMOUS=1; shift ;;
        --updates-via) UPDATES_VIA="$UPDATES_VIA $2"; shift 2 ;;
        --audit-log) AUDIT_LOG_MODE="$2"; shift 2 ;;
        --gate-user) GATE_USER="$2"; shift 2 ;;
        --birth-egress) BIRTH_EGRESS="$2"; shift 2 ;;
        --pool-cap) POOL_CAP="$2"; shift 2 ;;
        --private-cap) PRIVATE_CAP="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --strip-stale-badges) STRIP_STALE=1; shift ;;
        *) echo "install.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

SRC="$(cd "$(dirname "$0")/.." && pwd)"
LIB=/usr/local/lib/qmcp
RPC=/etc/qubes-rpc
POLICY_DST=/etc/qubes/policy.d/30-mcp-control.policy
ETC_QMCP=/etc/qmcp
AUDIT_LOG=/var/log/qmcp-audit.log
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP=/var/lib/qmcp-rollback/$TS
SCRATCH="$(mktemp -d /tmp/qmcp-install.XXXXXX)"
TIMER_STOPPED=0
cleanup() {
    rm -rf "$SCRATCH"
    # A run that stopped the gate's timer starts it again, whatever happened.
    if [ "$TIMER_STOPPED" -eq 1 ]; then
        systemctl start qmcp-gate.timer >/dev/null 2>&1 \
            || echo "install.sh: could NOT start qmcp-gate.timer again: sudo systemctl enable --now qmcp-gate.timer" >&2
    fi
}
trap cleanup EXIT

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }

# ===================================================================== preflight
# Nothing below this banner changes the system until "install".

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash $0)"
[ -e /etc/qubes-release ] && command -v qvm-ls >/dev/null || die "this is not dom0"
for f in dom0/qmcp/core.py dom0/qmcp/services.py dom0/qmcp/fleet.py dom0/qmcp/projects.py \
         dom0/qmcp/proposals.py dom0/qmcp/gateways.py dom0/qmcp/firewall.py dom0/rpc/qmcp-service \
         dom0/bin/qmcp policy/30-mcp-control.policy deploy/qmcp-tmpfiles.conf pyproject.toml \
         dom0/qmcp/gui.py dom0/qmcp/guimodel.py dom0/bin/qmcp-gui deploy/qubes-mcp.desktop \
         dom0/qmcp/anon.py deploy/qmcp-gate.service deploy/qmcp-gate.timer \
         dom0/qmcp/restored.py dom0/qmcp/inqube.py dom0/qmcp/opfiles.py \
         template-rpc/qmcp.RunInAIManaged template-rpc/qmcp.CopyToAIManaged \
         deploy/qmcp-refresh.service deploy/qmcp-refresh.timer \
         deploy/qmcp-audit.service deploy/qmcp-audit.timer; do
    [ -s "$SRC/$f" ] || die "the source tree at $SRC is incomplete: $f missing or empty"
done
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/pyproject.toml")"
[ -n "$VERSION" ] || die "no version in $SRC/pyproject.toml"
# The version installed now, read before anything changes. The qmcp-id labels
# are seeded once, on an upgrade from a release before 0.9.26, or a reinstall
# over an earlier install's kept operator files (see the header). v0.9.16 wrote
# no version file and no /etc/qmcp/hub; the files it installed tell it apart
# from a fresh box.
PREV_VERSION="$(head -c 32 /usr/local/lib/qmcp/VERSION 2>/dev/null | tr -d '[:space:]' || true)"
LEGACY_LEFT="$(PYTHONPATH="$SRC/dom0" python3 -c 'import os
from qmcp import fleet
print(sum(os.path.lexists(p) for p in fleet.LEGACY_PATHS))')" || die "the v0.9.16 file list could not be read"
SEED_LABELS=0 SEED_WHY=""
if [ -n "$PREV_VERSION" ] && [ "$PREV_VERSION" != unknown ] \
        && [ "$(printf '%s\n%s\n' "$PREV_VERSION" 0.9.26 | sort -V | head -n1)" != 0.9.26 ]; then
    SEED_LABELS=1 SEED_WHY="upgrade from $PREV_VERSION"
elif [ -z "$PREV_VERSION" ] && [ -e "$ETC_QMCP/hub" ]; then
    # Every uninstall removes the version file, and only --purge removes
    # /etc/qmcp: an earlier install's operator files with no version file are a
    # reinstall over a plain uninstall. The seed then runs only if no qube on
    # the box carries a label or a hold yet: then no 0.9.26 or later labelled or
    # held a qube here.
    SEED_LABELS=2 SEED_WHY="reinstall over the operator files an uninstall kept"
elif [ -z "$PREV_VERSION" ] && [ "$LEGACY_LEFT" -gt 0 ]; then
    SEED_LABELS=1 SEED_WHY="upgrade from v0.9.16"
fi
# An install that seeds leaves this marker until its version file is written:
# the first path from before its first change (the v0.9.16 files it keys on
# are removed below), the second once its guard has passed. The next run with
# no version file then seeds again, whatever it finds: the labels a seed did
# write would otherwise read as a box that ran 0.9.26. Every uninstall removes
# it with the rest of the library.
SEED_PENDING=0
[ -e "$LIB/SEED-PENDING" ] && SEED_PENDING=1
if [ "$SEED_PENDING" -eq 1 ] && [ -z "$PREV_VERSION" ] && [ "$SEED_LABELS" -ne 1 ]; then
    SEED_LABELS=2 SEED_WHY="the seed an earlier install did not finish"
fi
# (end of the seed decision)
# An empty or truncated pull passes "parses clean", so check for a known rule.
grep -qE '^\*[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@anyvm[[:space:]]+deny' \
    "$SRC/policy/30-mcp-control.policy" || die "the staged policy is not the qubes-mcp rulebook"
PYTHONPATH="$SRC/dom0" python3 -c 'import qmcp.services, qmcp.fleet, qmcp.cli, qmcp.guimodel, qmcp.proposals, qmcp.anon, qmcp.restored, qmcp.inqube, qmcp.opfiles' \
    || die "the staged library does not import"

# The hub: fixed at the first install. Read with the same function the services
# use, so the installer can never disagree with them about who the hub is.
if [ -e "$ETC_QMCP/hub" ]; then
    CURRENT_HUB="$(PYTHONPATH="$SRC/dom0" python3 -c 'from qmcp import core; print(core.read_hub() or "")')"
    [ -n "$CURRENT_HUB" ] || die "$ETC_QMCP/hub names no valid qube; fix it or run uninstall.sh --purge"
    if [ -n "$HUB" ] && [ "$HUB" != "$CURRENT_HUB" ]; then
        die "the hub is '$CURRENT_HUB' (fixed at install); run uninstall.sh --purge before changing it"
    fi
    HUB="$CURRENT_HUB"
fi
HUB="${HUB:-mcp-control}"
[[ "$HUB" =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,30}$ ]] || die "'$HUB' is not a qube name"
qvm-check -q "$HUB" 2>/dev/null || die "the hub qube '$HUB' does not exist"

# The anonymity gate's user: the one who ran this with sudo, else the qubes
# group's one member. Never root: the gate notifies the operator's desktop,
# whose bus refuses root. It must be in `qubes`, as the services' user is.
if [ -z "$GATE_USER" ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != root ]; then
    GATE_USER="$SUDO_USER"
fi
if [ -z "$GATE_USER" ]; then
    MEMBERS="$(getent group qubes | cut -d: -f4 | tr ',' '\n' | grep -v -e '^$' -e '^root$' || true)"
    [ "$(printf '%s\n' "$MEMBERS" | grep -c .)" -eq 1 ] \
        || die "say which dom0 user the anonymity gate runs as: --gate-user NAME (a member of qubes)"
    GATE_USER="$MEMBERS"
fi
[[ "$GATE_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "'$GATE_USER' is not a user name"
[ "$(id -u "$GATE_USER" 2>/dev/null || echo 0)" -ne 0 ] || die "the gate's user '$GATE_USER' does not exist, or is root"
id -nG "$GATE_USER" | tr ' ' '\n' | grep -qx qubes || die "the gate's user '$GATE_USER' is not in the qubes group"

# The values written to /etc/qmcp. Checked here, so a typo stops the install
# instead of surfacing as a failed `qmcp check` once the new policy is live.
[[ "$POOL_CAP" =~ ^[0-9]+$ ]] || die "--pool-cap wants a number of bytes, got '$POOL_CAP'"
[[ "$PRIVATE_CAP" =~ ^[0-9]+$ ]] || die "--private-cap wants a number of bytes, got '$PRIVATE_CAP'"
case "$AUDIT_LOG_MODE" in
    ""|disk|ram|none) ;;
    *) die "--audit-log is disk, ram or none, got '$AUDIT_LOG_MODE'" ;;
esac
if [ -n "$BIRTH_EGRESS" ]; then
    [[ "$BIRTH_EGRESS" =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,30}$ ]] || die "'$BIRTH_EGRESS' is not a qube name"
    qvm-check -q "$BIRTH_EGRESS" 2>/dev/null || die "the birth-egress qube '$BIRTH_EGRESS' does not exist"
    PYTHONPATH="$SRC/dom0" python3 -c 'import sys; from qmcp import gateways; sys.exit(0 if gateways.is_enrolled(sys.argv[1]) else 1)' "$BIRTH_EGRESS" \
        || echo "install.sh: warning: '$BIRTH_EGRESS' is not an enrolled gateway; the hub's template spawns do not use it until it is (qmcp gateway enroll $BIRTH_EGRESS)" >&2
fi

# Project records that exist must load: while they cannot, the services refuse
# every lead's call.
if [ -e "$ETC_QMCP/projects.json" ]; then
    PYTHONPATH="$SRC/dom0" python3 -c 'from qmcp import projects; projects.load()' 2>/dev/null \
        || die "$ETC_QMCP/projects.json does not load; fix it (qmcp check names the problem) before installing"
fi

# So must the gateway registry: while it cannot, no AI qube may be given a network.
if [ -e "$ETC_QMCP/gateways.json" ]; then
    PYTHONPATH="$SRC/dom0" python3 -c 'from qmcp import gateways; gateways.load()' 2>/dev/null \
        || die "$ETC_QMCP/gateways.json does not load; fix it (qmcp check names the problem) before installing"
fi

# The fleet must already be in the two-state shape: no tier tags, gateways
# guarded, the hub and drop boxes outside AI space. `qmcp migrate` does it.
FLEET_STATUS=0
PYTHONPATH="$SRC/dom0" QMCP_HUB="$HUB" python3 - <<'PYEOF' || FLEET_STATUS=$?
import os, sys
from qmcp import core, fleet
import qubesadmin.app
core.read_hub = lambda path=None: os.environ["QMCP_HUB"]
app = qubesadmin.app.QubesLocal()
# The shape only: a restored or held qube is the restore check's, not the migration's.
steps, problems = fleet.plan_migration(app, {}, review=False)
blocking = [s for s in steps if s.add or s.remove]
for p in problems:
    print(f"    BLOCKED {p}")
for s in blocking:
    print(f"    needs   {s!r}")
sys.exit(1 if problems or blocking else 0)
PYEOF
if [ "$FLEET_STATUS" -ne 0 ]; then
    echo "install.sh: the fleet is not in the two-state shape yet. Run the staged migration first:" >&2
    echo "    sudo PYTHONPATH=$SRC/dom0 python3 -m qmcp.cli migrate          # dry run" >&2
    echo "    sudo PYTHONPATH=$SRC/dom0 python3 -m qmcp.cli migrate --apply" >&2
    exit 1
fi

# The rulebook routes on badges, not records: a slot badge no record backs
# (left by uninstall.sh --purge, which removes the records and keeps the qubes'
# tags) would give a former lead root exec into its former workers again the
# moment the policy goes in. Listed here; taken off before the policy only with
# --strip-stale-badges, routed badges first.
STALE_STATUS=0
STALE_OUT="$(PYTHONPATH="$SRC/dom0" python3 - <<'PYEOF'
import sys
try:
    from qmcp import fleet, projects
    import qubesadmin.app
    stale, unread = fleet.stale_slot_badges(qubesadmin.app.QubesLocal(), projects.load())
except Exception as e:
    # Exit 1 means "stale badges found": a crash must never read as that.
    print(f"    the fleet could not be read ({type(e).__name__})")
    sys.exit(3)
for name, badges in stale:
    print(f"    {name}: {' '.join(badges)}")
for name in sorted(unread):
    print(f"    {name}: its tags do not read")
sys.exit(2 if unread else 1 if stale else 0)
PYEOF
)" || STALE_STATUS=$?
case "$STALE_STATUS" in
    0|1|2) ;;
    *) die "whether any qube wears stale slot badges could not be told: $STALE_OUT" ;;
esac
if [ "$STALE_STATUS" -eq 2 ] || { [ "$STALE_STATUS" -ne 0 ] && [ "$STRIP_STALE" -ne 1 ]; }; then
    echo "install.sh: qubes wear slot badges that no project record backs (left by" >&2
    echo "uninstall.sh --purge, or a project delete that stopped half-way); the rulebook" >&2
    echo "would route on them again once it is installed:" >&2
    printf '%s\n' "$STALE_OUT" >&2
    [ "$STALE_STATUS" -eq 2 ] && die "the tags of a qube do not read; try again"
    die "run again with --strip-stale-badges to take them off before the policy goes in"
fi

# Render the hub's name into the policy, then check the result with qrexec's
# parser against this box's policy directory with ours swapped in.
RENDERED="$SCRATCH/30-mcp-control.policy"
# Only whole whitespace-delimited fields: a comment naming the file keeps its name.
sed -E "s/(^|[[:space:]])mcp-control([[:space:]]|\$)/\1$HUB\2/g" \
    "$SRC/policy/30-mcp-control.policy" > "$RENDERED"
[ -s "$RENDERED" ] || die "rendering the policy produced nothing"
POLICY_STATUS=0
PYTHONPATH="$SRC/dom0" QMCP_HUB="$HUB" python3 - "$RENDERED" <<'PYEOF' || POLICY_STATUS=$?
import logging, os, pathlib, shutil, sys, tempfile
logging.disable(logging.WARNING)
try:
    from qrexec.policy.parser import FilePolicy
    import qrexec.utils
except ImportError:
    print("    qrexec's policy parser is not importable", file=sys.stderr)
    sys.exit(2)
from qmcp import fleet
hub = os.environ["QMCP_HUB"]
if fleet.policy_hub(sys.argv[1]) != hub:
    print(f"    the rendered policy does not name '{hub}' as the hub", file=sys.stderr)
    sys.exit(1)
etc, run = pathlib.Path("/etc/qubes/policy.d"), pathlib.Path("/run/qubes/policy.d")
scratch = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-policy-"))
try:
    shutil.copytree(etc, scratch / "policy.d", symlinks=True)
    shutil.copyfile(sys.argv[1], scratch / "policy.d" / "30-mcp-control.policy")
    dirs = [d for d in (run, scratch / "policy.d") if d.is_dir()]
    policy = FilePolicy(policy_path=dirs)
    ours = [r for r in policy.rules if pathlib.Path(r.filepath).name == "30-mcp-control.policy"]
    print(f"    parsed: {len(policy.rules)} rules, {len(ours)} of them ours")
    if not ours:
        sys.exit(1)
    # Parsing proves nothing about precedence: a file sorting before ours can
    # override any of our rules. Every claim must be decided by our file, for
    # every AI-space qube on this box.
    problems = fleet.precedence(policy, qrexec.utils.get_system_info(), hub)
    for p in problems:
        print(f"    PRECEDENCE {p}", file=sys.stderr)
    sys.exit(1 if problems else 0)
except Exception as e:
    print(f"    qrexec's parser refuses the policy set: {type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
finally:
    shutil.rmtree(scratch)
PYEOF
[ "$POLICY_STATUS" -eq 0 ] || die "the rendered policy does not load on this box, or a file sorting earlier overrides it; nothing was changed"

for g in $UPDATES_VIA; do
    [[ "$g" =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,30}$ ]] || die "--updates-via: '$g' is not a qube name"
done

# The anonymity gate, as the staged code will judge: every anonymous project, and
# the hub in anonymous mode (on now, or with --anonymous), with the --updates-via
# ticks applied. An entry written before 0.9.24 is not ticked for updates, so a
# project whose templates update through it would be stopped by the first run of
# the new code: name it here, before anything changes. Turning anonymous mode on
# needs no ordinary project, no clearnet gateway, and the hub sound.
MODE_STATUS=0
PYTHONPATH="$SRC/dom0" QMCP_HUB="$HUB" QMCP_ANONYMOUS="$ANONYMOUS" QMCP_UPDATES_VIA="$UPDATES_VIA" \
    python3 - <<'PYEOF' || MODE_STATUS=$?
import os, sys
from qmcp import anon, core, gateways, projects
import qubesadmin.app
hub = os.environ["QMCP_HUB"]
core.read_hub = lambda path=None: hub
turn_on = os.environ["QMCP_ANONYMOUS"] == "1"
try:
    mode_on = core.anonymous_mode()
except core.ModeUnreadable as e:
    print(f"    {e}: write the one word anonymous, or run uninstall.sh --purge", file=sys.stderr)
    sys.exit(1)
records = projects.load()
registry = gateways.load()
for name in os.environ["QMCP_UPDATES_VIA"].split():
    g = registry.get(name)
    if g is None or not g.anonymising or g.upstream is None:
        print(f"    --updates-via {name}: not an enrolled anonymising gateway with a recorded "
              f"network", file=sys.stderr)
        sys.exit(1)
    # Ticking it later goes through `qmcp gateway set`, which refuses a held one.
    domains = qubesadmin.app.QubesLocal().domains
    if name not in domains:
        print(f"    --updates-via {name}: no such qube", file=sys.stderr)
        sys.exit(1)
    try:
        held = core.QUARANTINE in core.tags_of(domains[name])
    except Exception as e:
        print(f"    --updates-via {name}: its tags cannot be read ({type(e).__name__})",
              file=sys.stderr)
        sys.exit(1)
    if held:
        print(f"    --updates-via {name}: held for your review (qmcp restored list); accept "
              f"or reject it first", file=sys.stderr)
        sys.exit(1)
    g.updates = True
turning = turn_on and not mode_on
if turning:
    ordinary = sorted(p.label for p in records.values() if p.label and not p.anonymous)
    clearnet = sorted(n for n, g in registry.items() if not g.anonymising)
    if ordinary or clearnet:
        if ordinary:
            print(f"    anonymous mode: projects that are not anonymous: {', '.join(ordinary)} "
                  f"(delete them first)", file=sys.stderr)
        if clearnet:
            print(f"    anonymous mode: gateways that are not anonymising: {', '.join(clearnet)} "
                  f"(qmcp gateway remove)", file=sys.stderr)
        sys.exit(1)
app = qubesadmin.app.QubesLocal()
subjects = [p for p in sorted(records.values(), key=lambda p: p.slot)
            if p.anonymous and p.slot != projects.HUB_SLOT]
overlay, past = {}, []
if mode_on or turn_on:
    subjects.append(anon.HUB)
if turning:
    # qmcp-anon goes on these before the mode is written: judged as wearing it.
    by_name, tags_by = anon._snapshot(app, strict=True)
    for n in anon.hub_subjects(hub, records, registry, by_name, tags_by):
        overlay[n] = tags_by[n] | {projects.ANON}
    past = [n for n in overlay if n != hub]
ticked = {n: gateways.Gateway(g.name, g.anonymising, g.label, g.upstream, True)
          for n, g in registry.items()}
failed = False
for p in subjects:
    v = anon.judge(app, p, records=records, overlay=overlay, registry=registry)
    if v.status == anon.GREEN:
        continue
    why = "; ".join(d for _, d in v.problems)
    if p is anon.HUB and turning:
        print(f"    anonymous mode: the gate would stop the hub: {why}", file=sys.stderr)
        failed = True
    elif anon.judge(app, p, records=records, overlay=overlay, registry=ticked).status == anon.GREEN:
        print(f"    {p.label} ({p.slot}) would be stopped by this release: {why}", file=sys.stderr)
        failed = True
    else:
        print(f"    note: {p.label} ({p.slot}) is not sound already, whatever this release does: "
              f"{why}")
if failed:
    print("    Tick a gateway whose upstream is the anonymiser itself (sys-whonix, a VPN qube) "
          "with --updates-via GATEWAY, or fix what is named, then run this again.",
          file=sys.stderr)
    sys.exit(1)
if turning:
    print("    anonymous mode: every project will be anonymous, and the gate judges the hub "
          "and the rest of AI space every 15 seconds.")
    print("    qmcp cannot check whose account the hub's model uses, nor what the hub qube did "
          "before now: use a hub qube and a model account that never ran on clearnet.")
    for n in sorted(past):
        print(f"    {n} is already in AI space and gets qmcp-anon: a qube has a past (what it "
              f"holds and what it was used for come with it)")
sys.exit(0)
PYEOF
[ "$MODE_STATUS" -eq 0 ] || die "the anonymity preflight refused (above); nothing was changed"

say "preflight passed: qubes-mcp $VERSION, hub '$HUB', gate user '$GATE_USER'"
if [ "$SEED_LABELS" -eq 1 ] || { [ "$SEED_PENDING" -eq 1 ] && [ "$SEED_LABELS" -eq 2 ]; }; then
    say "it will label AI space for the restore check: $SEED_WHY"
elif [ "$SEED_LABELS" -eq 2 ]; then
    say "it will label AI space for the restore check if no qube carries a label or a hold yet: $SEED_WHY"
fi
if [ "$DRY_RUN" -eq 1 ]; then
    say "dry run: nothing was changed"
    exit 0
fi
# The first path's marker goes on before the first change (the v0.9.16 files
# it keys on are removed below); the second path's once its guard has passed.
if [ "$SEED_LABELS" -eq 1 ]; then
    install -d -m 0755 "$LIB"
    : > "$LIB/SEED-PENDING"
fi

# ===================================================================== install

# --- back up what this install will replace or remove
mkdir -p "$BACKUP"
chmod 0700 /var/lib/qmcp-rollback "$BACKUP"
[ -f "$POLICY_DST" ] && cp -a "$POLICY_DST" "$BACKUP/"
for f in "$RPC"/qmcp.* "$RPC"/qmcp_*.py; do [ -e "$f" ] && cp -a "$f" "$BACKUP/"; done
[ -d "$ETC_QMCP" ] && cp -a "$ETC_QMCP" "$BACKUP/etc-qmcp"
[ -d "$LIB" ] && cp -a "$LIB" "$BACKUP/usr-local-lib-qmcp"
[ -f /etc/tmpfiles.d/qmcp.conf ] && cp -a /etc/tmpfiles.d/qmcp.conf "$BACKUP/"
for f in /etc/systemd/system/qmcp-gate.service /etc/systemd/system/qmcp-gate.timer \
         /etc/systemd/system/qmcp-refresh.service /etc/systemd/system/qmcp-refresh.timer \
         /etc/systemd/system/qmcp-audit.service /etc/systemd/system/qmcp-audit.timer; do
    [ -f "$f" ] && cp -a "$f" "$BACKUP/"
done
say "backed up to $BACKUP (root-only)"

# --- the gate's timer stops while this changes things; cleanup() starts it again
if systemctl is-active --quiet qmcp-gate.timer 2>/dev/null; then
    TIMER_STOPPED=1
    systemctl stop qmcp-gate.timer
    # A run already going finishes first (the unit stops one after 60 s).
    for _ in $(seq 1 65); do
        [ "$(systemctl is-active qmcp-gate.service 2>/dev/null)" = activating ] || break
        sleep 1
    done
    say "stopped qmcp-gate.timer until the install is done"
fi

# --- v0.9.16 leftovers
for unit in qmcp-consent.service qmcp-tombstone-reaper.timer qmcp-tombstone-reaper.service; do
    if [ -e "/etc/systemd/system/$unit" ]; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        say "stopped and disabled $unit"
    fi
done
# v0.9.16's consent daemon was a --user unit of the operator's, and it listened
# in /run/qmcp, which is ours now. Stop it through each user's own manager, end
# any copy still running, then remove its unit and wants link (as the home's
# owner) and its socket (with the files below).
LEGACY_USERS="$(PYTHONPATH="$SRC/dom0" python3 -c 'from qmcp import fleet
for user, home in fleet.legacy_users():
    print(user + "\t" + home)')" || die "the dom0 users could not be read"
# The unit and its wants link in one home (an absolute one: legacy_users() says so).
home_paths() { PYTHONPATH="$SRC/dom0" python3 -c 'import sys
from qmcp import fleet
print("\n".join(fleet.legacy_home_paths(sys.argv[1])))' "$1"; }
while IFS=$'\t' read -r user home; do
    [ -n "$user" ] || continue
    uid="$(id -u -- "$user")"
    [ -S "/run/user/$uid/bus" ] || continue
    paths="$(home_paths "$home")" || die "the v0.9.16 paths in $home could not be read"
    found=0
    while IFS= read -r path; do
        if [ -e "$path" ] || [ -L "$path" ]; then found=1; fi
    done <<< "$paths"
    [ "$found" = 1 ] || continue
    as_user() { timeout -k 5 30 sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user "$@"; }
    rc=0; as_user disable --now qmcp-consent.service >/dev/null 2>&1 || rc=$?
    state="$(as_user is-active qmcp-consent.service 2>/dev/null || true)"
    if [ "$rc" = 0 ] && { [ "$state" = inactive ] || [ "$state" = failed ]; }; then
        say "stopped and disabled $user's qmcp-consent.service"
    else
        say "WARN: $user's qmcp-consent.service did not stop (status $rc, ${state:-no state}); the next step ends it"
    fi
done <<< "$LEGACY_USERS"
# Its program goes first, so a unit that restarts what is killed below has
# nothing left to run (v0.9.16's restarts after 2 s).
rm -f /usr/local/lib/qmcp/qmcp-consentd
legacy_daemons() { timeout -k 5 15 env PYTHONPATH="$SRC/dom0" python3 -c 'from qmcp import fleet
print(" ".join(map(str, fleet.legacy_daemons())))'; }
PIDS="$(legacy_daemons)" || die "the running processes could not be read"
if [ -n "$PIDS" ]; then
    # shellcheck disable=SC2086  # a list of pids
    kill $PIDS 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        sleep 1
        PIDS="$(legacy_daemons)" || die "the running processes could not be read"
        [ -n "$PIDS" ] || break
    done
    # shellcheck disable=SC2086
    [ -z "$PIDS" ] || kill -9 $PIDS 2>/dev/null || true
    sleep 1
    PIDS="$(legacy_daemons)" || die "the running processes could not be read"
    if [ -z "$PIDS" ]; then
        say "ended the v0.9.16 consent daemon"
    else
        say "WARN: the v0.9.16 consent daemon still runs (pid $PIDS); qmcp check fails until it ends"
    fi
fi
# Its unit and wants link sit in a home, so they go as that home's owner: root
# never follows a path its user controls.
while IFS=$'\t' read -r user home; do
    [ -n "$user" ] || continue
    paths="$(home_paths "$home")" || die "the v0.9.16 paths in $home could not be read"
    while IFS= read -r path; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            if sudo -u "$user" rm -f -- "$path"; then
                say "removed v0.9.16 file $path"
            else
                say "WARN: could not remove $path as $user"
            fi
        fi
    done <<< "$paths"
done <<< "$LEGACY_USERS"
LEGACY="$(PYTHONPATH="$SRC/dom0" python3 -c 'from qmcp import fleet
print("\n".join(fleet.LEGACY_PATHS + (fleet.LEGACY_SOCKET,)))')"
while IFS= read -r path; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        rm -f "$path"
        say "removed v0.9.16 file $path"
    fi
done <<< "$LEGACY"
rm -rf /run/qmcp-consent 2>/dev/null || true
systemctl daemon-reload

# --- the library and the operator command
rm -rf "$LIB/qmcp"
install -d -m 0755 "$LIB" "$LIB/qmcp" "$LIB/share"
install -m 0644 "$SRC"/dom0/qmcp/*.py "$LIB/qmcp/"
# Precompiled once, as root: the services run as an unprivileged dom0 user who
# cannot write here, and would otherwise recompile the library on every call.
PYTHONDONTWRITEBYTECODE= python3 -m compileall -q "$LIB/qmcp"
install -m 0644 "$RENDERED" "$LIB/share/30-mcp-control.policy"
install -m 0755 "$SRC/dom0/bin/qmcp" /usr/local/bin/qmcp
say "installed the library to $LIB and the command to /usr/local/bin/qmcp"
rm -rf "$LIB/template-rpc"
install -d -m 0755 "$LIB/template-rpc"
install -m 0644 "$SRC/template-rpc/qmcp.RunInAIManaged" "$SRC/template-rpc/qmcp.CopyToAIManaged" \
    "$LIB/template-rpc/"
say "kept the in-qube services in $LIB/template-rpc (qmcp template prepare QUBE writes them in)"

# --- the qmcp-id labels: once, on an upgrade or a reinstall (above), while the
# gate's timer is stopped, so no pass can hold a qube before it is labelled
if [ "$SEED_LABELS" -ne 0 ]; then
    SEEDED="$(PYTHONPATH="$LIB" QMCP_SEED="$SEED_LABELS" QMCP_SEED_PENDING="$SEED_PENDING" \
              QMCP_SEED_MARKER="$LIB/SEED-PENDING" python3 - <<'PYEOF'
import os
import sys
import qubesadmin.app
from qmcp import core, restored
app = qubesadmin.app.QubesLocal()
if os.environ.get("QMCP_SEED") == "2" and os.environ.get("QMCP_SEED_PENDING") != "1":
    for vm in app.domains:
        try:
            if core.klass_of(vm) != "AdminVM" and (restored.label_of(vm) is not None
                                                   or core.QUARANTINE in core.tags_of(vm)):
                print("no seed: a qube already carries a label or a hold, so this box ran "
                      "0.9.26 or later")
                sys.exit(0)
        except core.Gone:
            continue
open(os.environ["QMCP_SEED_MARKER"], "w").close()
done, left, held, failed, unread = 0, [], [], [], []
for vm in app.domains:
    try:
        tags = core.tags_of(vm)
        if core.klass_of(vm) == "AdminVM" or not restored.in_scope(tags):
            continue
        if core.QUARANTINE in tags:
            held.append(vm.name)
            continue
        if restored.label_of(vm) is None:
            try:
                restored.label(vm)
                done += 1
            except Exception as e:
                failed.append(f"{vm.name} ({type(e).__name__})")
        elif not restored.known(vm):
            left.append(vm.name)
    except core.Gone:
        continue
    except Exception as e:
        unread.append(f"{vm.name} ({type(e).__name__})")
print(f"labelled {done} qube(s)" + (f"; {', '.join(left)} carry another qube's label and will be held for review" if left else "")
      + (f"; {', '.join(held)} held for review, left as they are" if held else "")
      + (f"; NOT labelled: {', '.join(failed)}" if failed else "")
      + (f"; could not be read: {', '.join(unread)}" if unread else ""))
sys.exit(1 if failed or unread else 0)
PYEOF
)" || die "the qmcp-id labels could not all be read or written (${SEEDED:-the seed stopped before it reported}). The gate's timer may hold those qubes for review meanwhile. Run the install again (it seeds again until it finishes), then accept any qube it held: qmcp restored list"
    say "$SEED_WHY: $SEEDED"
fi
# The version last, then the marker: a seed that did not finish is tried again
# by the next run, on either path.
printf '%s\n' "$VERSION" > "$LIB/VERSION"
chmod 0644 "$LIB/VERSION"
rm -f "$LIB/SEED-PENDING"
install -m 0755 "$SRC/dom0/bin/qmcp-gui" /usr/local/bin/qmcp-gui
install -m 0644 "$SRC/deploy/qubes-mcp.desktop" /usr/share/applications/qubes-mcp.desktop
say "installed the window, /usr/local/bin/qmcp-gui, and its menu entry"

# --- one shim under each service name
SERVICES="$(PYTHONPATH="$LIB" python3 -c 'from qmcp.services import SERVICES; print("\n".join(SERVICES))')"
while IFS= read -r svc; do
    install -m 0755 "$SRC/dom0/rpc/qmcp-service" "$RPC/$svc"
done <<< "$SERVICES"
say "installed $(echo "$SERVICES" | wc -l) services in $RPC"

# --- runtime directory, proposal store, operator files, audit log
install -m 0644 "$SRC/deploy/qmcp-tmpfiles.conf" /etc/tmpfiles.d/qmcp.conf
systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf
say "runtime directory /run/qmcp and proposal store /var/lib/qmcp/proposals in place"
install -d -m 0755 "$ETC_QMCP"
write_if_absent() {   # file value
    if [ -e "$1" ]; then
        say "kept $1 ($(head -c 80 "$1" | tr '\n' ' '))"
    else
        printf '%s\n' "$2" > "$1"
        chmod 0644 "$1"
        say "wrote $1 = $2"
    fi
}
write_if_absent "$ETC_QMCP/hub" "$HUB"
write_if_absent "$ETC_QMCP/pool-cap" "$POOL_CAP"
write_if_absent "$ETC_QMCP/private-cap" "$PRIVATE_CAP"
[ -n "$BIRTH_EGRESS" ] && write_if_absent "$ETC_QMCP/birth-egress" "$BIRTH_EGRESS"
write_if_absent "$ETC_QMCP/projects.json" '{"version": 1, "slots": {}}'
chown root:root "$ETC_QMCP/projects.json"
touch "$AUDIT_LOG"
chown root:qubes "$AUDIT_LOG"
chmod 0660 "$AUDIT_LOG"
# --- the install's audit mode: written only when given and different. The
# change leaves one line on the less private of the old and the new mode
# (disk if either is), so the chain says why it stops or starts.
if [ -n "$AUDIT_LOG_MODE" ]; then
    AUDIT_SAID="$(PYTHONPATH="$LIB" QMCP_NEW="$AUDIT_LOG_MODE" python3 - <<'PYEOF'
import os
from qmcp import audit
new = os.environ["QMCP_NEW"]
old, problem = audit.install_mode()
if problem is None and old == new:
    print(f"kept {audit.MODE_PATH} ({new})")
    raise SystemExit(0)
tmp = audit.MODE_PATH + ".new"
with open(tmp, "w", encoding="ascii") as fh:
    fh.write(new + "\n")
os.chmod(tmp, 0o644)
os.replace(tmp, audit.MODE_PATH)
kept = max((old, new), key=audit.MODES.index)
if kept != "none":
    dest = audit.LOG_PATH if kept == "disk" else audit.ram_path()
    if kept == "ram":
        audit._ram_dir_ready()
    audit.audit("qmcp install", "operator", {"audit_log": new, "was": old}, True,
                path=dest, slots=())
print(f"wrote {audit.MODE_PATH} = {new} (was {old})"
      + ("; the lines already in /var/log stay there: deleting a file on dom0's disk is not "
         "erasing it" if old == "disk" else ""))
PYEOF
)" || die "could not write $ETC_QMCP/audit-mode"
    say "$AUDIT_SAID"
fi

# --- an upgrade from before 0.9.33 has no keep-days setting, and the hourly timer
# would remove, at the default, rotated logs that release kept for ever: where
# any of them is older than the default, the setting is written "off", and said,
# before the timer first runs. Removing evidence is the step that cannot be undone.
KEEP_SAID="$(PYTHONPATH="$LIB" python3 - <<'PYEOF'
import datetime, os
from qmcp import audit
if os.path.exists(audit.KEEP_DAYS_PATH):
    raise SystemExit(0)
cutoff = datetime.datetime.now(datetime.timezone.utc) \
    - datetime.timedelta(days=audit.KEEP_DAYS_DEFAULT)
old = [n for n, when in audit.rotated() if when < cutoff]
if not old:
    raise SystemExit(0)
tmp = audit.KEEP_DAYS_PATH + ".new"
with open(tmp, "w", encoding="ascii") as fh:
    fh.write("off\n")
os.chmod(tmp, 0o644)
os.replace(tmp, audit.KEEP_DAYS_PATH)
print(f"wrote {audit.KEEP_DAYS_PATH} = off: {len(old)} rotated audit log(s) are older than "
      f"the default {audit.KEEP_DAYS_DEFAULT} days, and no setting said to remove them; "
      f"set one with qmcp settings set --audit-keep-days N once you have kept what you need")
PYEOF
)" || die "could not judge or write $ETC_QMCP/audit-keep-days"
[ -n "$KEEP_SAID" ] && say "$KEEP_SAID"

# --- the anonymity gate's timer, as the services' user
sed "s/@GATE_USER@/$GATE_USER/" "$SRC/deploy/qmcp-gate.service" > "$SCRATCH/qmcp-gate.service"
grep -qx "User=$GATE_USER" "$SCRATCH/qmcp-gate.service" || die "the gate's unit did not render"
install -m 0644 "$SCRATCH/qmcp-gate.service" /etc/systemd/system/qmcp-gate.service
install -m 0644 "$SRC/deploy/qmcp-gate.timer" /etc/systemd/system/qmcp-gate.timer
sed "s/@GATE_USER@/$GATE_USER/" "$SRC/deploy/qmcp-refresh.service" > "$SCRATCH/qmcp-refresh.service"
grep -qx "User=$GATE_USER" "$SCRATCH/qmcp-refresh.service" || die "the refresh unit did not render"
install -m 0644 "$SCRATCH/qmcp-refresh.service" /etc/systemd/system/qmcp-refresh.service
install -m 0644 "$SRC/deploy/qmcp-refresh.timer" /etc/systemd/system/qmcp-refresh.timer
install -m 0644 "$SRC/deploy/qmcp-audit.service" /etc/systemd/system/qmcp-audit.service
install -m 0644 "$SRC/deploy/qmcp-audit.timer" /etc/systemd/system/qmcp-audit.timer
systemctl daemon-reload
systemctl enable qmcp-gate.timer >/dev/null
systemctl enable qmcp-refresh.timer >/dev/null
systemctl enable qmcp-audit.timer >/dev/null
TIMER_STOPPED=1
say "the anonymity gate will run every 15 seconds as $GATE_USER (qmcp-gate.timer)"

# --- the boot seal, and one run now: an install never leaves a window open.
# It runs BEFORE the new policy goes in, so a window that was open under the
# old code is closed before the lines that would honour it exist.
install -d -m 0755 /etc/systemd/system/qubes-vm@.service.d
install -m 0644 "$SRC/deploy/qmcp-seal.service" /etc/systemd/system/qmcp-seal.service
install -m 0644 "$SRC/deploy/qubes-vm-qmcp-seal.conf" \
    /etc/systemd/system/qubes-vm@.service.d/10-qmcp-seal.conf
systemctl daemon-reload
systemctl enable qmcp-seal.service >/dev/null
# Exit 3 is also a kill a seal could not make yet, with every badge off: the
# policy may go in then, once no qube is read wearing an open badge. Any other
# failure, or a badge still on, stops the install.
SEAL_RC=0
SEAL_OUT="$(PYTHONPATH="$LIB" python3 -c 'import sys; from qmcp import cli; sys.exit(cli.main(["seal", "--all"]))' 2>&1)" || SEAL_RC=$?
if [ "$SEAL_RC" -ne 0 ]; then
    [ "$SEAL_RC" -eq 3 ] || die "an open window could not be sealed ($SEAL_OUT); the new policy is NOT installed: run qmcp seal --all by hand, then install again"
    LEFT="$(PYTHONPATH="$LIB" python3 -c 'import qubesadmin.app; from qmcp import fleet; print(" ".join(fleet.open_badge_holders(qubesadmin.app.QubesLocal())))' 2>&1)" \
        || die "whether any qube still wears an open badge could not be read ($LEFT); the new policy is NOT installed: run qmcp seal --all by hand, then install again"
    [ -z "$LEFT" ] || die "an open window could not be sealed ($SEAL_OUT; still open: $LEFT); the new policy is NOT installed: run qmcp seal --all by hand, then install again"
    say "WARN: a seal could not kill its qube yet; the gate's timer tries again and qmcp check names it ($SEAL_OUT)"
fi
[ "$SEAL_RC" -eq 0 ] && [ -n "$SEAL_OUT" ] && say "sealed what was open: $SEAL_OUT"
say "every boot seals the open guarded qubes before any user session (qmcp-seal.service)"

# --- the updates ticks, before the gate's timer runs the new code
for g in $UPDATES_VIA; do
    PYTHONPATH="$LIB" python3 -c 'import sys, qubesadmin.app; from qmcp import audit, fleet; print(fleet.set_gateway(qubesadmin.app.QubesLocal(), sys.argv[1], updates=True)); audit.audit("qmcp gateway set", "operator", {"qube": sys.argv[1][:128], "updates": True}, True, slots=())' "$g" \
        || die "could not tick $g for updates; the new policy is NOT installed (nor, with --anonymous, the mode), but the gate's timer starts again on the new code and may stop a project, or in anonymous mode the hub, whose templates update through $g: run the install again at once"
done

# --- slot badges no record backs, taken off with --strip-stale-badges (the
# preflight listed them and refused without it)
if [ "$STRIP_STALE" -eq 1 ]; then
    PYTHONPATH="$LIB" python3 -c 'import qubesadmin.app; from qmcp import audit, fleet, projects
for line in fleet.strip_stale_slot_badges(qubesadmin.app.QubesLocal(), projects.load()):
    print("==> " + line)
    audit.audit("qmcp install", "operator", {"stale badges": line.split(":")[0][:128]}, True, slots=())' \
        || die "the stale slot badges could not all be taken off; the new policy is NOT installed: run the install again"
fi

# --- the policy last: the services run the new library under the old rulebook from the
# library step on, and under the new one from here
install -m 0644 -o root -g root "$RENDERED" "$POLICY_DST"
say "installed $POLICY_DST"
systemctl reset-failed qubes-qrexec-policy-daemon >/dev/null 2>&1 || true
systemctl restart qubes-qrexec-policy-daemon
for _ in $(seq 1 10); do
    [ "$(systemctl is-active qubes-qrexec-policy-daemon)" = "active" ] && break
    sleep 1
done
[ "$(systemctl is-active qubes-qrexec-policy-daemon)" = "active" ] \
    || die "the qrexec policy daemon is not active after the restart; the policy IS installed"
say "qrexec policy daemon restarted"

# --- anonymous mode, last: qmcp-anon on the hub and the rest of AI space first, so
# the gate never judges a qube of the mode without it. The stamps, and with
# QMCP_WRITE_MODE=1 the mode file between them, run under the gate's lock: a
# gate run (qmcp gate, qmcp check, the run after any command) cannot judge in
# the gap and stop the hub for a qube not yet stamped.
stamp_mode() {   # qmcp-anon on the hub and on every qube under its check
    PYTHONPATH="$LIB" QMCP_HUB="$HUB" QMCP_MODE_PATH="$ETC_QMCP/mode" python3 - <<'PYEOF'
import os, sys
import qubesadmin.app
from qmcp import anon, audit, core, gateways, projects, restored
hub = os.environ["QMCP_HUB"]
app = qubesadmin.app.QubesLocal()


def stamp(again: bool = False) -> int:
    """Puts qmcp-anon on the mode's qubes and reads it back. The first pass names
    each qube; the second (`again`) names only the ones it stamped itself."""
    records, registry = projects.load(), gateways.load()
    by_name, tags_by = anon._snapshot(app, strict=True)
    # The hub's subjects, and the anonymous projects' model qubes, which join
    # them when their project goes (its leads and members wear it already).
    models = sorted({p.model_qube for p in records.values() if p.anonymous and p.model_qube
                     and p.model_qube in by_name})
    added = 0
    for name in anon.hub_subjects(hub, records, registry, by_name, tags_by) + models:
        vm = app.domains[name]
        tags = core.tags_of(vm)
        if projects.ANON not in tags:
            # A qube outside the restore check's scope (no ai-managed, ai-dump or
            # qmcp badge) and with no label yet (the hub) is labelled before it
            # gets this one; one carrying another qube's label keeps it. One
            # already badged is never labelled here: if it has no label of its
            # own it came back from a backup, and the gate holds it.
            if not restored.in_scope(tags):
                restored.label_if_missing(vm)
            vm.tags.add(projects.ANON)
            added += 1
            stamped = True
        else:
            stamped = False
        if projects.ANON not in core.tags_of(vm):
            sys.exit(f"    {name} does not read back wearing {projects.ANON}")
        if stamped or not again:
            print(f"==> {name} wears {projects.ANON}")
    return added


with anon._GateLock(wait=120) as got:
    if not got:
        sys.exit("    the anonymity gate held its lock past 120 s; nothing was stamped")
    added = stamp()
    wrote = os.environ.get("QMCP_WRITE_MODE") == "1"
    if wrote:
        path = os.environ["QMCP_MODE_PATH"]
        with open(path + ".new", "w", encoding="ascii") as fh:
            fh.write("anonymous\n")
        os.chmod(path + ".new", 0o644)
        os.replace(path + ".new", path)
        # A qube the hub made between the first pass and the mode file was born
        # without it (the services stamp only in the mode): a second pass.
        added += stamp(again=True)
    if wrote or added:
        audit.audit("qmcp install", "operator",
                    {"mode": "anonymous", "turned_on": wrote, "stamped": added}, True, slots=())
PYEOF
}
if [ "$ANONYMOUS" -eq 1 ] && [ ! -e "$ETC_QMCP/mode" ]; then
    QMCP_WRITE_MODE=1 stamp_mode || die "could not put qmcp-anon on every qube of the mode, or write $ETC_QMCP/mode (the qubes named above wear it; the mode is on only if that file exists): run the install again"
    say "anonymous mode is on ($ETC_QMCP/mode); no qmcp command turns it off, uninstall.sh --purge does"
elif [ -e "$ETC_QMCP/mode" ]; then
    say "kept $ETC_QMCP/mode ($(head -c 40 "$ETC_QMCP/mode" | tr '\n' ' '))"
    # The mode's invariant, put back on an update: qmcp-anon on every qube under the hub's check.
    stamp_mode > /dev/null || die "could not put qmcp-anon on every qube of the mode; run the install again"
fi

# --- the operator files: every one the services and the dom0 user read is
# 0644, whoever wrote it. A file written with `tee` under sudo inherits dom0's
# umask (0077) and comes out 0600, which root reads and the services and the
# operator's own `qmcp check` do not. The list is the library's own. Before the
# gate's first run: as its user it would block every anonymous qube on records
# it cannot read.
OPFILES="$(PYTHONPATH="$LIB" python3 -c 'from qmcp import opfiles; print("\n".join(sorted(opfiles._paths().values())))')" \
    || die "could not list the operator files"
while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] && [ ! -L "$f" ] || continue
    was="$(stat -c %a "$f")"
    if [ "$was" != 644 ]; then
        chmod 0644 "$f"
        say "set $f to 0644 (it was $was)"
    fi
done <<< "$OPFILES"

# --- the gate's timer, and one run now, so its heartbeat is this release's
systemctl start qmcp-gate.timer
systemctl start qmcp-gate.service || true
TIMER_STOPPED=0
systemctl start qmcp-refresh.timer
systemctl start qmcp-audit.timer
say "the anonymity gate runs every 15 seconds as $GATE_USER (qmcp-gate.timer)"
say "the audit log is rotated daily and rotated logs removed by age, hourly (qmcp-audit.timer)"

# ===================================================================== verify
# As the dom0 user, as the README runs it: a check as root reads files the
# services and the operator cannot.
echo
CHECK_STATUS=0
say "qmcp check, as $GATE_USER:"
runuser -u "$GATE_USER" -- /usr/local/bin/qmcp check || CHECK_STATUS=$?
echo
if [ "$CHECK_STATUS" -eq 0 ]; then
    say "qubes-mcp $VERSION installed. Hub: $HUB."
else
    say "qubes-mcp $VERSION installed, but qmcp check, as $GATE_USER, is not GREEN (status $CHECK_STATUS)."
fi
# The registry starts empty, on a fresh install and on an upgrade from 0.9.20:
# no AI qube can be given a network until the operator enrolls one.
if ! PYTHONPATH="$LIB" python3 -c 'import sys; from qmcp import gateways; sys.exit(0 if gateways.load() else 1)' 2>/dev/null; then
    say "no gateway is enrolled: AI qubes can be given no network, and qmcp check fails on any"
    say "(gateways aside) that already has one. Enroll each router AI space may use:"
    say "sudo qmcp gateway enroll QUBE"
fi
exit "$CHECK_STATUS"
