#!/bin/bash
# install-stage-I-6.sh — run in dom0.
#
# Stage I-6 install: the operator-consent MECHANISM, shipped INERT (design:
# STAGE-I-DESIGN.md; the action axis / Wave 2). It installs a consent daemon +
# helper + wrapper hook + policy file, but the shipped /etc/qmcp/consent-policy
# gates the EMPTY set — so consent_required() returns False for every call, no
# wrapper ever consults the daemon, and behaviour is byte-neutral vs the current
# tree (INVARIANCE, the Stage I-3 pattern). Enforcement is I-7.
#
# Surface delta:
#   - NEW dom0 lib   /etc/qubes-rpc/qmcp_consent.py        (sibling helper)
#   - NEW dom0 bin   /usr/local/lib/qmcp/qmcp-consentd     (the daemon, 0755)
#   - NEW user unit  ~/.config/systemd/user/qmcp-consent.service (operator)
#   - NEW tmpfiles   /etc/tmpfiles.d/qmcp.conf   (d /run/qmcp 2770 root qubes -)
#   - NEW config     /etc/qmcp/consent-policy   (EMPTY gate; installed ONLY IF ABSENT)
#   - NEW config     /etc/qmcp/consent-timeout  (300; installed ONLY IF ABSENT)
#   - PATCHED        the 8 state-changing qmcp.* wrappers (each gained the I-6
#                    consent hook AFTER the I-5 CAP_FULL check, before the mutation)
#
# Manifest verbs (the CLAUDE.md ADDED-DOM0 vs REPLACED lesson): the daemon, the
# helper, the tmpfiles conf, and the two /etc/qmcp config files are BRAND-NEW dom0
# files => ADDED-DOM0 (revert REMOVES them). The 8 wrappers PRE-EXIST from prior
# stages => REPLACED (revert restores from backup). The consent policy/timeout are
# installed only if absent — so a re-run never clobbers an operator edit, and on a
# re-run they are neither added nor replaced.
#
# This installer VALIDATES the daemon (compiles + pyflakes-clean if pyflakes is
# present) BEFORE enabling the unit — a broken daemon that fails to start would,
# under the fail-closed gate, DENY every gated call once I-7 lands. At I-6 the
# empty gate means it is never asked, but we refuse to ship an unstartable daemon.
#
# zenity availability in dom0 is a SLOT-VERIFY assumption (dom0 is minimal). At
# I-6 the empty gate never invokes zenity, so its absence cannot regress
# behaviour; the installer WARNS if zenity is missing but does not abort.
#
# Idempotent — re-runnable. Wrappers/daemon/helper/tmpfiles are overwritten; the
# two /etc/qmcp config files are left untouched if present.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-6.sh' > /tmp/install-I-6.sh
#   bash /tmp/install-I-6.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail
# ---------------------------------------------------------------- flip coherence guard
# This installer writes /etc/qubes/policy.d/30-mcp-control.policy from the
# shipped, PRE-FLIP artifact, which still carries the four @tag:ai-managed
# compat backstops. Doing that on a FLIPPED fleet restores those backstops while
# /etc/qmcp/tier-default stays "ro", so the two halves of the coupled flip
# disagree -- and it fails PERMISSIVE: exec, file-copy and firewall-write reopen
# to every umbrella qube while the @adminvm wrapper surfaces keep denying. The
# operator has every reason to think least privilege is still on; nothing
# announces the regression. This is the split-brain the I-4 design note warns
# about, reached by routine stage maintenance rather than a partial flip.
if [ "$(tr -d '[:space:]' < /etc/qmcp/tier-default 2>/dev/null)" = "ro" ]; then
    if [ "${QMCP_ALLOW_UNFLIP:-0}" = "1" ]; then
        echo "    WARNING: fleet is FLIPPED; this install restores the compat" >&2
        echo "             backstops. Proceeding on QMCP_ALLOW_UNFLIP=1 --" >&2
        echo "             RE-RUN deploy/install-stage-flip.sh when it finishes." >&2
    else
        echo "FATAL: this fleet is FLIPPED (/etc/qmcp/tier-default=ro), but this" >&2
        echo "       installer writes the shipped policy, which still carries the" >&2
        echo "       four compat backstops. Installing it would un-flip the policy" >&2
        echo "       half while the flag stays 'ro' -- reopening exec, file-copy" >&2
        echo "       and firewall-write to every @tag:ai-managed qube, silently." >&2
        echo "       Re-run with QMCP_ALLOW_UNFLIP=1 and then immediately re-run" >&2
        echo "       deploy/install-stage-flip.sh to restore coherence." >&2
        exit 1
    fi
fi


SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-I-6"
RPC_DST="/etc/qubes-rpc"
DAEMON_DIR="/usr/local/lib/qmcp"
DAEMON_DST="$DAEMON_DIR/qmcp-consentd"
HELPER_DST="$RPC_DST/qmcp_consent.py"
TMPFILES_DST="/etc/tmpfiles.d/qmcp.conf"
QMCP_ETC="/etc/qmcp"
POLICY_DST="$QMCP_ETC/consent-policy"
TIMEOUT_DST="$QMCP_ETC/consent-timeout"
CHANGELOG="/var/log/qmcp-changes.log"

# Source-tree relative paths (inside SOURCE_PATH).
HELPER_SRC="dom0-rpc/qmcp_consent.py"
DAEMON_SRC="dom0-rpc/qmcp-consentd"
UNIT_SRC="deploy/qmcp-consent.service"
TMPFILES_SRC="deploy/qmcp-tmpfiles.conf"
POLICY_SRC="deploy/consent-policy.default"
TIMEOUT_SRC="deploy/consent-timeout.default"

# The 8 wrappers I-6 patches with the consent hook (all pre-exist => REPLACED).
WRAPPERS=(
    qmcp.LifecycleAIManaged
    qmcp.SetPropertyAIManaged
    qmcp.CloneAIManagedQube
    qmcp.SpawnAIManagedQube
    qmcp.SetFeatureAIManaged
    qmcp.AttachDeviceAIManaged
    qmcp.DetachDeviceAIManaged
    qmcp.SpawnDisposableAIManaged
)

# The operator whose --user unit we enable. dom0 qrexec wrappers and the GUI
# session both run as uid 1000; SUDO_USER is set when the slot invoked us via
# sudo, else fall back to the login owner of /run/user/1000 or 'user'.
OPERATOR="${SUDO_USER:-}"
[ -z "$OPERATOR" ] && OPERATOR="$(id -un 1000 2>/dev/null || echo user)"

echo "==> Stage I-6 deploy starting (consent mechanism, INERT)"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo "    operator user:  $OPERATOR (for the systemd --user unit)"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage I-6 artifacts from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

PULL_LIST="$HELPER_SRC $DAEMON_SRC $UNIT_SRC $TMPFILES_SRC $POLICY_SRC $TIMEOUT_SRC"
for w in "${WRAPPERS[@]}"; do
    PULL_LIST="$PULL_LIST dom0-rpc/$w"
done

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $PULL_LIST" \
    > "$STAGE_DIR/stage-I-6.tar"
(cd "$STAGE_DIR" && tar -xf stage-I-6.tar)

for f in $PULL_LIST; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
done

echo "==> SHA-256 of pulled artifacts (record for your audit):"
( cd "$STAGE_DIR" && sha256sum $PULL_LIST )
echo

# ---------------------------------------------------------------- 2. compile-gate the daemon + helper + wrappers
# A broken daemon would, once I-7 gates a surface, deny every gated call
# (fail-closed). A broken wrapper would brick that surface immediately. Refuse
# the whole deploy if anything does not compile — before touching dom0. The
# wrappers + daemon have no .py extension, so use SourceFileLoader; the helper
# has one, so py_compile is fine.
echo "==> Compile-checking the staged daemon + helper + wrappers..."
for f in "$DAEMON_SRC" "${WRAPPERS[@]/#/dom0-rpc/}"; do
    if ! python3 - "$STAGE_DIR/$f" <<'PY'
import sys, importlib.machinery
path = sys.argv[1]
src = importlib.machinery.SourceFileLoader("staged", path).get_source("staged")
compile(src, path, "exec")
PY
    then
        echo "FATAL: staged file failed to compile: $f — NOT installing." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
done
if ! python3 -m py_compile "$STAGE_DIR/$HELPER_SRC"; then
    echo "FATAL: $HELPER_SRC failed to compile — NOT installing." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "    daemon + helper + all ${#WRAPPERS[@]} wrappers compile clean."

# pyflakes-clean if the linter is available (dom0 may or may not have it). This
# catches an undefined name the compile step would miss. Absent => skip (compile
# already gated). NEVER abort the whole deploy just because pyflakes is missing.
echo "==> pyflakes lint of the daemon + helper (if pyflakes present)..."
if python3 -c 'import pyflakes' 2>/dev/null; then
    if ! python3 -m pyflakes "$STAGE_DIR/$DAEMON_SRC" "$STAGE_DIR/$HELPER_SRC"; then
        echo "FATAL: pyflakes flagged the daemon/helper — NOT installing." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
    echo "    pyflakes: daemon + helper clean."
else
    echo "    pyflakes not installed in dom0 — skipped (compile gate stands)."
fi
echo

# ---------------------------------------------------------------- 2.5 zenity presence (SLOT-VERIFY assumption; warn only)
echo "==> Checking zenity presence (the daemon's dialog tool)..."
if command -v zenity >/dev/null 2>&1; then
    echo "    zenity present: $(command -v zenity)"
else
    echo "    WARNING: zenity NOT found in dom0. At I-6 the empty gate never" >&2
    echo "             invokes it, so behaviour is unaffected — but I-7" >&2
    echo "             enforcement REQUIRES it. Install before enabling any gate." >&2
fi
echo

# ---------------------------------------------------------------- 3. changelog + rollback scaffold
# Mirror the slot-runner convention so a manual install is still revert-friendly:
# a timestamped backup tree + a MANIFEST recording each change with the right
# verb (ADDED-DOM0 for brand-new files, REPLACED for pre-existing ones).
TS="$(date -u +%Y%m%dT%H%M%SZ)"
ROLLBACK_DIR="/var/lib/qmcp-rollback/$TS"
MANIFEST="$ROLLBACK_DIR/MANIFEST"
sudo mkdir -p "$ROLLBACK_DIR"
sudo touch "$CHANGELOG" "$MANIFEST"
log()      { sudo bash -c "printf '%s\n' \"[\$(date -Is)] $*\" >> '$CHANGELOG'"; }
manifest() { sudo bash -c "printf '%s\n' '$*' >> '$MANIFEST'"; }
backup()   { [ -e "$1" ] && { sudo install -D -m 0644 "$1" "$ROLLBACK_DIR$1"; log "BACKUP $1"; }; return 0; }
log "=== STAGE I-6 INSTALL START rollback=$ROLLBACK_DIR ==="
manifest "ROLLBACK_TS=$TS"

# ---------------------------------------------------------------- 4. install the NEW dom0 files (ADDED-DOM0)
# On a FIRST install these are new (ADDED-DOM0 => revert removes them). On a
# re-run they pre-exist; record the actual verb per file so revert behaves
# correctly either way.
verb_for() { [ -e "$1" ] && echo "REPLACED" || echo "ADDED-DOM0"; }

echo "==> Installing the consent helper (sibling lib, 0644)..."
V="$(verb_for "$HELPER_DST")"; backup "$HELPER_DST"
sudo install -m 0644 -o root -g root "$STAGE_DIR/$HELPER_SRC" "$HELPER_DST"
manifest "$V=$HELPER_DST"; log "INSTALLED $HELPER_DST ($V)"
echo "    $HELPER_DST ($V)"

echo "==> Installing the consent daemon (0755, executable)..."
sudo mkdir -p "$DAEMON_DIR"
V="$(verb_for "$DAEMON_DST")"; backup "$DAEMON_DST"
sudo install -m 0755 -o root -g root "$STAGE_DIR/$DAEMON_SRC" "$DAEMON_DST"
manifest "$V=$DAEMON_DST"; log "INSTALLED $DAEMON_DST ($V)"
echo "    $DAEMON_DST ($V)"

echo "==> Installing the tmpfiles conf + creating /run/qmcp (2770 root:qubes)..."
V="$(verb_for "$TMPFILES_DST")"; backup "$TMPFILES_DST"
sudo install -m 0644 -o root -g root "$STAGE_DIR/$TMPFILES_SRC" "$TMPFILES_DST"
manifest "$V=$TMPFILES_DST"; log "INSTALLED $TMPFILES_DST ($V)"
sudo systemd-tmpfiles --create "$TMPFILES_DST"
echo "    $TMPFILES_DST ($V); /run/qmcp: $(sudo stat -c '%a %U:%G' /run/qmcp 2>/dev/null || echo '<missing>')"
echo

# ---------------------------------------------------------------- 5. install config defaults ONLY IF ABSENT (never clobber operator edits)
echo "==> Installing /etc/qmcp config defaults (only if absent)..."
sudo mkdir -p "$QMCP_ETC"
if [ -e "$POLICY_DST" ]; then
    echo "    $POLICY_DST already exists — LEFT UNTOUCHED (operator-owned)."
else
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$POLICY_SRC" "$POLICY_DST"
    manifest "ADDED-DOM0=$POLICY_DST"; log "INSTALLED $POLICY_DST (ADDED-DOM0, empty gate)"
    echo "    $POLICY_DST (ADDED-DOM0 — EMPTY gate: mechanism inert)."
fi
if [ -e "$TIMEOUT_DST" ]; then
    echo "    $TIMEOUT_DST already exists — LEFT UNTOUCHED (operator-owned)."
else
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$TIMEOUT_SRC" "$TIMEOUT_DST"
    manifest "ADDED-DOM0=$TIMEOUT_DST"; log "INSTALLED $TIMEOUT_DST (ADDED-DOM0, 300)"
    echo "    $TIMEOUT_DST (ADDED-DOM0 — T_gate=300)."
fi
echo

# ---------------------------------------------------------------- 5.5 INVARIANCE GUARD — policy must be present + empty-gate BEFORE hooking wrappers
# I-6 byte-neutrality REQUIRES /etc/qmcp/consent-policy to be present AND parse to
# an EMPTY gate set while the hooked wrappers are live: only then does gate()
# short-circuit to "open" without touching the daemon. If the policy were absent,
# the hooked wrappers would hit consent_required()'s missing-file branch =>
# MALFORMED => the 4 DEFAULT_GATED ops (Lifecycle remove/kill, Attach, Detach)
# route to the daemon and fail-closed to DENY — a behaviour CHANGE from pre-I-6.
# On a clean install step 5 just created it, so this is a belt: it defends the
# re-run case where an operator DELETED the policy (or edited it to a non-empty
# gate) and re-ran the installer — we must NOT silently ship hooked wrappers over
# a policy that would gate anything. (A non-empty operator policy is the I-7 arm;
# I-6's installer refuses to be the thing that arms it by surprise.)
echo "==> Invariance guard: consent-policy present + EMPTY gate before hooking wrappers..."
if [ ! -e "$POLICY_DST" ]; then
    echo "FATAL: $POLICY_DST is absent, but the I-6 wrappers about to ship gate on it." >&2
    echo "       Shipping them now would route the 4 DEFAULT_GATED ops to the daemon" >&2
    echo "       and fail-closed to DENY (NOT byte-neutral). Re-run after restoring an" >&2
    echo "       empty $POLICY_DST (see deploy/consent-policy.default). Rollback: /var/lib/qmcp-rollback/$TS" >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
# Count non-comment, non-blank lines. Zero => empty gate (the inert I-6 state).
POLICY_RULES="$(grep -vcE '^[[:space:]]*(#|$)' "$POLICY_DST" 2>/dev/null || echo 0)"
if [ "$POLICY_RULES" != "0" ]; then
    echo "    WARNING: $POLICY_DST has $POLICY_RULES gate rule(s) — this is the I-7 ARMED" >&2
    echo "             state, NOT the inert I-6 empty gate. The wrappers below WILL gate" >&2
    echo "             those (service,action) pairs once shipped. If that is intentional" >&2
    echo "             (I-7), proceed; if not, restore the empty policy and re-run." >&2
    echo "             (Not aborting: an operator may deliberately arm before re-shipping.)" >&2
else
    echo "    $POLICY_DST present + EMPTY gate (0 rules) — wrappers ship byte-neutral."
fi
echo

# ---------------------------------------------------------------- 6. re-ship the 8 patched wrappers (REPLACED)
echo "==> Installing the 8 consent-hooked wrappers (REPLACED)..."
for w in "${WRAPPERS[@]}"; do
    dst="$RPC_DST/$w"
    V="$(verb_for "$dst")"     # normally REPLACED; ADDED-DOM0 only on a broken tree
    backup "$dst"
    sudo install -m 0755 -o root -g root "$STAGE_DIR/dom0-rpc/$w" "$dst"
    manifest "$V=$dst"; log "INSTALLED $dst ($V)"
    echo "    $dst ($V)"
done
echo

# ---------------------------------------------------------------- 7. validate the daemon imports cleanly BEFORE enabling
echo "==> Validating the installed daemon imports + the socket serve() path..."
if ! sudo python3 - <<PY
import importlib.machinery, sys
path = "$DAEMON_DST"
mod = importlib.machinery.SourceFileLoader("qmcp_consentd_check", path).load_module()
# The daemon must expose serve()/decide()/handle() and the frozen socket path.
for name in ("serve", "decide", "handle", "_recv_line"):
    assert hasattr(mod, name), f"daemon missing {name}"
assert mod.SOCKET_PATH == "/run/qmcp/consent.sock", mod.SOCKET_PATH
assert mod.TIMEOUT_PATH == "/etc/qmcp/consent-timeout", mod.TIMEOUT_PATH
# The I-8 grant stub must ALWAYS report no active grant at I-6.
assert mod._active_grant("qmcp.LifecycleAIManaged", "remove", "x") is False
print("    daemon imports clean; serve()/decide()/handle() present; grant stub inert.")
PY
then
    echo "FATAL: the installed daemon did not import cleanly — NOT enabling the unit." >&2
    echo "       The consent hook stays inert (empty gate), so this is safe to leave," >&2
    echo "       but fix the daemon before I-7. Rollback: /var/lib/qmcp-rollback/$TS" >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo

# ---------------------------------------------------------------- 8. install + enable the operator --user unit
echo "==> Installing the systemd --user unit for $OPERATOR + enabling it..."
OP_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)"
[ -z "$OP_HOME" ] && OP_HOME="/home/$OPERATOR"
UNIT_DIR="$OP_HOME/.config/systemd/user"
UNIT_DST="$UNIT_DIR/qmcp-consent.service"
V="$(verb_for "$UNIT_DST")"
[ "$V" = "REPLACED" ] && backup "$UNIT_DST"
sudo -u "$OPERATOR" mkdir -p "$UNIT_DIR"
sudo install -m 0644 -o "$OPERATOR" -g "$(id -gn "$OPERATOR")" \
    "$STAGE_DIR/$UNIT_SRC" "$UNIT_DST"
manifest "$V=$UNIT_DST"; log "INSTALLED $UNIT_DST ($V)"
echo "    $UNIT_DST ($V)"

# Enable + start as the operator user. --user commands need the user's bus; a
# graphical operator session already has it. If the session bus is unreachable
# (headless install), enable statically and WARN — the daemon starts on next login.
UID_OP="$(id -u "$OPERATOR")"
if sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$UID_OP" \
        systemctl --user daemon-reload 2>/dev/null \
   && sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$UID_OP" \
        systemctl --user enable --now qmcp-consent.service 2>/dev/null; then
    echo "    enabled + started qmcp-consent.service (--user, $OPERATOR)."
    sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$UID_OP" \
        systemctl --user --no-pager status qmcp-consent.service 2>/dev/null \
        | sed -n '1,4p' | sed 's/^/      /' || true
else
    echo "    WARNING: could not reach $OPERATOR's session bus (headless?)." >&2
    echo "             Enable it from the operator's GRAPHICAL session with:" >&2
    echo "               systemctl --user enable --now qmcp-consent.service" >&2
    # Best-effort: mark it enabled for the next login so it comes up automatically.
    sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$UID_OP" \
        systemctl --user enable qmcp-consent.service 2>/dev/null \
        && echo "             (statically enabled — will start on next login)." || true
fi
echo

# ---------------------------------------------------------------- 9. cleanup
rm -rf "$STAGE_DIR"
log "=== STAGE I-6 INSTALL COMPLETE ==="

echo "==> Stage I-6 deploy complete (consent mechanism installed, INERT)."
echo
echo "What changed live: NOTHING observable — /etc/qmcp/consent-policy gates the"
echo "EMPTY set, so no wrapper opens the daemon socket and every call is"
echo "byte-identical to pre-I-6. Enforcement is Stage I-7 (uncomment rules in"
echo "$POLICY_DST)."
echo
echo "Verify:"
echo "  from mcp-control:  .venv/bin/python deploy/test-stage-I-6.py       # AI-side invariance"
echo "  offline (bulk):    .venv/bin/python deploy/offline-validate-I-6.py # helper + mock daemon"
echo "  in dom0:           systemctl --user status qmcp-consent.service"
echo "                     stat -c '%a %U:%G' /run/qmcp/consent.sock       # expect 660 <operator>:qubes"
echo "                     # (the daemon is a --user unit, so the socket owner is the"
echo "                     #  operator, NOT root; reachability rests on group qubes + 0660.)"
echo "Rollback: /var/lib/qmcp-rollback/$TS/MANIFEST  (or '/tmp/run.sh revert' if slot-deployed)"
