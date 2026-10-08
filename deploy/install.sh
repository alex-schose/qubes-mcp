#!/bin/bash
# deploy/install.sh — install or update qubes-mcp in dom0. Idempotent.
#
# This runs as root in dom0, so the tree it runs from must come from somewhere
# AI cannot write. A tree copied out of the hub is only as trustworthy as the
# hub: the first update after a hub compromise would hand over dom0. Fetch a
# tagged release in a fresh disposable instead:
#
#   qvm-run --dispvm=default-dvm --pass-io \
#     'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.23.tar.gz' \
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
#   /etc/systemd/system/qmcp-gate.{service,timer}   the anonymity gate every 15 s, as the
#                                    dom0 user the services run as (never root: it notifies
#                                    the operator's desktop), enabled and started
# It changes no qube's tags: managed qubes from an older release stay in no
# project slot until `qmcp project move` puts them in one.
# It removes everything v0.9.16 installed that this release no longer has, and
# backs up what it replaces under /var/lib/qmcp-rollback/<timestamp>/.
#
# Every preflight check runs before anything changes: the source tree, the hub,
# the values for /etc/qmcp, the fleet's shape, and the policy, which is checked
# with qrexec's own parser against this box's real policy directory, with ours
# swapped in, before the live file is replaced. The last step is `qmcp check`;
# this script exits with its status (0 GREEN, 1 FAILED, 3 INCOMPLETE — not green).

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
while [ $# -gt 0 ]; do
    case "$1" in
        --hub) HUB="$2"; shift 2 ;;
        --gate-user) GATE_USER="$2"; shift 2 ;;
        --birth-egress) BIRTH_EGRESS="$2"; shift 2 ;;
        --pool-cap) POOL_CAP="$2"; shift 2 ;;
        --private-cap) PRIVATE_CAP="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
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
trap 'rm -rf "$SCRATCH"' EXIT

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
         dom0/qmcp/anon.py deploy/qmcp-gate.service deploy/qmcp-gate.timer; do
    [ -s "$SRC/$f" ] || die "the source tree at $SRC is incomplete: $f missing or empty"
done
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/pyproject.toml")"
[ -n "$VERSION" ] || die "no version in $SRC/pyproject.toml"
# An empty or truncated pull passes "parses clean", so check for a known rule.
grep -qE '^\*[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@anyvm[[:space:]]+deny' \
    "$SRC/policy/30-mcp-control.policy" || die "the staged policy is not the qubes-mcp rulebook"
PYTHONPATH="$SRC/dom0" python3 -c 'import qmcp.services, qmcp.fleet, qmcp.cli, qmcp.guimodel, qmcp.proposals, qmcp.anon' \
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
steps, problems = fleet.plan_migration(app, {})
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

say "preflight passed: qubes-mcp $VERSION, hub '$HUB', gate user '$GATE_USER'"
if [ "$DRY_RUN" -eq 1 ]; then
    say "dry run: nothing was changed"
    exit 0
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
for f in /etc/systemd/system/qmcp-gate.service /etc/systemd/system/qmcp-gate.timer; do
    [ -f "$f" ] && cp -a "$f" "$BACKUP/"
done
say "backed up to $BACKUP (root-only)"

# --- v0.9.16 leftovers
for unit in qmcp-consent.service qmcp-tombstone-reaper.timer qmcp-tombstone-reaper.service; do
    if [ -e "/etc/systemd/system/$unit" ]; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        say "stopped and disabled $unit"
    fi
done
LEGACY="$(PYTHONPATH="$SRC/dom0" python3 -c 'from qmcp import fleet; print("\n".join(fleet.LEGACY_PATHS))')"
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
printf '%s\n' "$VERSION" > "$LIB/VERSION"
chmod 0644 "$LIB/VERSION"
install -m 0755 "$SRC/dom0/bin/qmcp" /usr/local/bin/qmcp
say "installed the library to $LIB and the command to /usr/local/bin/qmcp"
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

# --- the anonymity gate's timer, as the services' user
sed "s/@GATE_USER@/$GATE_USER/" "$SRC/deploy/qmcp-gate.service" > "$SCRATCH/qmcp-gate.service"
grep -qx "User=$GATE_USER" "$SCRATCH/qmcp-gate.service" || die "the gate's unit did not render"
install -m 0644 "$SCRATCH/qmcp-gate.service" /etc/systemd/system/qmcp-gate.service
install -m 0644 "$SRC/deploy/qmcp-gate.timer" /etc/systemd/system/qmcp-gate.timer
systemctl daemon-reload
systemctl enable --now qmcp-gate.timer >/dev/null
say "the anonymity gate runs every 15 seconds as $GATE_USER (qmcp-gate.timer)"

# --- the policy, last: until it is in place no AI caller reaches the new code
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

# ===================================================================== verify
echo
CHECK_STATUS=0
/usr/local/bin/qmcp check || CHECK_STATUS=$?
echo
if [ "$CHECK_STATUS" -eq 0 ]; then
    say "qubes-mcp $VERSION installed. Hub: $HUB."
else
    say "qubes-mcp $VERSION installed, but qmcp check is not GREEN (status $CHECK_STATUS)."
fi
# The registry starts empty, on a fresh install and on an upgrade from 0.9.20:
# no AI qube can be given a network until the operator enrolls one.
if ! PYTHONPATH="$LIB" python3 -c 'import sys; from qmcp import gateways; sys.exit(0 if gateways.load() else 1)' 2>/dev/null; then
    say "no gateway is enrolled: AI qubes can be given no network, and qmcp check fails on any"
    say "(gateways aside) that already has one. Enroll each router AI space may use:"
    say "sudo qmcp gateway enroll QUBE"
fi
exit "$CHECK_STATUS"
