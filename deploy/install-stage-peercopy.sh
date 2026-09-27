#!/bin/bash
# install-stage-peercopy.sh — run in dom0. POLICY-ONLY.
#
# Installs public/policy/30-mcp-control.policy, whose qubes.Filecopy section is
# the subject of this installer, and keeps the fleet in whichever tier phase it
# is already in (see GATE 0).
#
# THE FILECOPY CONTRACT. Checked with qrexec's OWN parser, against this box's
# own policy directory with the staged file substituted in, BEFORE anything is
# written — and again against the installed set afterwards:
#   - between two AI qubes tagged ai-exec / ai-net / ai-full: allowed, no dialog;
#   - AI qube -> an ai-dump sink (not ai-managed): allowed, no dialog;
#   - ai-dump source -> any AI qube: denied (the sink stays write-only);
#   - every OTHER copy from an AI qube — into a read-only or untiered AI qube,
#     out of the umbrella, or `qvm-copy` with no target at all (@default) —
#     the ordinary dialog, decided by THIS file rather than the system default;
#   - a name that does not exist gets the same dialog as a real qube (qrexec
#     rewrites it to @default), so the dialog is no existence oracle;
#   - ai-dump -> out of the umbrella: the stock dialog, which is how the
#     operator drains a buffer by hand.
#
# HISTORY — two defects of this installer's first version (v0.9.12), both fixed
# here rather than left behind a new filename:
#   1. It checked the matrix with a RE-IMPLEMENTED resolver that knew only NAMED
#      targets. `qvm-copy` sends no target — the request is `@default` — and
#      `@anyvm` matches `@default`, so every `qvm-copy` from an AI qube hit the
#      dialog-free `@tag:ai-managed -> @anyvm deny` the old file ended with. The
#      resolver could not see it, and the operator reported the same failure a
#      second time (2026-09-27). The contract is now evaluated by the engine
#      that will enforce it.
#   2. It wrote the shipped file over a FLIPPED fleet, restoring the four compat
#      backstops while /etc/qmcp/tier-default stayed "ro": the F9 split-brain
#      the development box sat in for two weeks. GATE 0 now keeps the phase.
#
# Idempotent. A malformed policy can break ALL of qrexec, so nothing touches
# /etc/qubes/policy.d/ until the staged file has parsed AND resolved correctly.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-peercopy.sh' > /tmp/install-peercopy.sh
#   bash /tmp/install-peercopy.sh mcp-control /home/user/qubes_mcp/public
#
# Environment:
#   QMCP_ALLOW_UNFLIP=1   install the shipped backstops even on a flipped fleet
#                         (an explicit, deliberate widening — never a default).

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-peercopy"
POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
FLAG="/etc/qmcp/tier-default"
BACKUP_DIR="/var/lib/qmcp-rollback"

echo "==> Filecopy policy deploy starting (policy-only)"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling the policy from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $POLICY_REL" \
    > "$STAGE_DIR/stage.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf stage.tar)
STAGED="$STAGE_DIR/$POLICY_REL"
# An empty or wrong file must not get as far as the gates: "parses clean" is
# true of an empty policy too (the 2026-08-19 empty-pull lesson).
if [ ! -s "$STAGED" ] || ! grep -qE '^qubes\.Filecopy[[:space:]]+\*[[:space:]]+@tag:ai-managed[[:space:]]+@anyvm[[:space:]]+ask' "$STAGED"; then
    echo "FATAL: the pulled policy is empty or is not the v0.9.15 Filecopy shape." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "==> SHA-256 of the pulled policy (record for your audit):"
( cd "$STAGE_DIR" && sha256sum "$POLICY_REL" | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 2. GATE 0 — keep the fleet's phase
# The shipped file is the COMPAT phase: it carries the four @tag:ai-managed
# backstops (firewall.Set, firewall.Reload, RunInAIManaged, CopyToAIManaged)
# that install-stage-flip.sh deletes. On a flipped fleet this installer installs
# the shipped file MINUS exactly those four, so a policy-only change never moves
# the fleet between phases. Anything other than exactly four found is a file
# this installer does not understand, and it stops.
EFFECTIVE="$STAGE_DIR/30-mcp-control.policy.effective"
PHASE="$(sudo awk '{sub(/#.*/, ""); for (i = 1; i <= NF; i++) {print $i; exit}}' "$FLAG" 2>/dev/null || true)"
if [ "$PHASE" = "ro" ] && [ "${QMCP_ALLOW_UNFLIP:-0}" != "1" ]; then
    echo "==> GATE 0: the fleet is FLIPPED (tier-default=ro). Stripping the four"
    echo "    compat backstops from the staged copy so this install keeps it flipped..."
    if ! python3 - "$STAGED" "$EFFECTIVE" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
RULE = re.compile(r'^(qmcp\.(RunIn|CopyTo)AIManaged|admin\.vm\.firewall\.(Set|Reload))'
                  r'\s+\*\s+\S+\s+@tag:ai-managed\s+allow(\s|$)')
NOTE = re.compile(r'^# COMPAT backstop \((firewall\.Set|firewall\.Reload|RunInAIManaged|CopyToAIManaged)\)')
out, rules, notes = [], 0, 0
for line in open(src, encoding="utf-8"):
    if RULE.match(line):
        rules += 1
        continue
    if NOTE.match(line):
        notes += 1
        continue
    out.append(line)
if rules != 4:
    print(f"FATAL: expected exactly 4 backstop rule lines, found {rules}", file=sys.stderr)
    sys.exit(1)
open(dst, "w", encoding="utf-8").writelines(out)
print(f"    removed {rules} backstop rule lines + {notes} backstop comment lines")
PY
    then
        echo "FATAL: GATE 0 could not produce the flipped variant — NOT installing." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
    EXPECT_BACKSTOPS=0
else
    if [ "$PHASE" = "ro" ]; then
        echo "    WARNING: flipped fleet + QMCP_ALLOW_UNFLIP=1 — installing the shipped"
        echo "    backstops. The fleet will be split-brained until install-stage-flip.sh"
        echo "    runs again."
    else
        echo "==> GATE 0: the fleet is in COMPAT (tier-default is not 'ro'); installing"
        echo "    the shipped file as-is."
    fi
    cp "$STAGED" "$EFFECTIVE"
    EXPECT_BACKSTOPS=4
fi
echo

# ---------------------------------------------------------------- 3. the contract checker (used twice)
cat > "$STAGE_DIR/filecopy_contract.py" <<'PY'
"""Evaluate the Filecopy contract with qrexec's own parser.

    filecopy_contract.py staged <effective-file> <gateway>
        this box's policy directories, with 30-mcp-control.policy replaced by
        <effective-file> in a scratch copy — what the daemon WILL see.
    filecopy_contract.py live <gateway>
        the installed directories — what the daemon DOES see.

Synthetic qubes (qmcp-gate-*) so the verdict does not depend on the fleet.
"""
import logging, pathlib, shutil, sys, tempfile, uuid

try:
    from qrexec.policy.parser import FilePolicy, Request
    from qrexec.exc import AccessDenied, RequestError
except ImportError:
    print("FATAL: qrexec's policy parser is not importable; refusing to install a "
          "policy this installer cannot evaluate.", file=sys.stderr)
    sys.exit(2)
logging.disable(logging.WARNING)      # the engine logs every @default rewrite

ETC = pathlib.Path("/etc/qubes/policy.d")
RUN = pathlib.Path("/run/qubes/policy.d")
OURS = "30-mcp-control.policy"
mode = sys.argv[1]
gateway = sys.argv[-1]

scratch = None
if mode == "staged":
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-policy-"))
    shutil.copytree(ETC, scratch / "policy.d", symlinks=True)
    shutil.copyfile(sys.argv[2], scratch / "policy.d" / OURS)
    dirs = [d for d in (RUN, scratch / "policy.d") if d.is_dir()]
else:
    dirs = [d for d in (RUN, ETC) if d.is_dir()]
policy = FilePolicy(policy_path=dirs)


def dom(tags, klass="AppVM", dvmt=False):
    return {"tags": list(tags), "type": klass, "default_dispvm": None,
            "template_for_dispvms": dvmt, "power_state": "Running",
            "uuid": str(uuid.uuid4())}


SI = {"domains": {
    "dom0": dom([], "AdminVM"),
    gateway: dom([]),
    "qmcp-gate-ro": dom(["ai-managed"]),
    "qmcp-gate-ro2": dom(["ai-managed"]),
    "qmcp-gate-exec": dom(["ai-managed", "ai-exec"]),
    "qmcp-gate-full": dom(["ai-managed", "ai-full"]),
    "qmcp-gate-dump": dom(["ai-dump"]),
    "qmcp-gate-hybrid": dom(["ai-managed", "ai-dump"]),
    "qmcp-gate-out": dom([]),
}}


def ev(src, tgt):
    """-> (ACTION, decided-in-our-file, targets offered by the dialog)"""
    try:
        r = policy.evaluate(Request("qubes.Filecopy", "+", src, tgt, system_info=SI))
    except (AccessDenied, RequestError) as e:
        return "DENY", OURS in str(e), frozenset()
    kind = type(r).__name__.replace("Resolution", "").upper()
    return (kind, str(r.rule.filepath).endswith(OURS),
            frozenset(getattr(r, "targets_for_ask", None) or ()))


fails = 0


def check(label, ok):
    global fails
    print(f"    {'PASS' if ok else 'FAIL'}  {label}")
    fails += not ok


check("exec -> full : ALLOW (no dialog)", ev("qmcp-gate-exec", "qmcp-gate-full")[0] == "ALLOW")
check("full -> exec : ALLOW", ev("qmcp-gate-full", "qmcp-gate-exec")[0] == "ALLOW")
check("ro   -> dump : ALLOW (the valve)", ev("qmcp-gate-ro", "qmcp-gate-dump")[0] == "ALLOW")
check("exec -> dump : ALLOW", ev("qmcp-gate-exec", "qmcp-gate-dump")[0] == "ALLOW")
check("dump   -> exec : DENY (sink stays write-only)", ev("qmcp-gate-dump", "qmcp-gate-exec")[0] == "DENY")
check("hybrid -> exec : DENY", ev("qmcp-gate-hybrid", "qmcp-gate-exec")[0] == "DENY")
for label, s, t in (("exec -> ro ", "qmcp-gate-exec", "qmcp-gate-ro"),
                    ("ro   -> exec", "qmcp-gate-ro", "qmcp-gate-exec"),
                    ("ro   -> ro2 ", "qmcp-gate-ro", "qmcp-gate-ro2"),
                    ("exec -> out ", "qmcp-gate-exec", "qmcp-gate-out")):
    k, ours, _ = ev(s, t)
    check(f"{label} : ASK decided in {OURS}", k == "ASK" and ours)
for s in ("qmcp-gate-ro", "qmcp-gate-exec", "qmcp-gate-full"):
    k, ours, offered = ev(s, "@default")
    check(f"{s} -> @default (qvm-copy) : ASK decided in {OURS}", k == "ASK" and ours)
    check(f"{s} -> @default : dialog offers a qube outside the umbrella and the sink",
          "qmcp-gate-out" in offered and "qmcp-gate-dump" in offered)
k1 = ev("qmcp-gate-exec", "qmcp-gate-out")[0]
k2, ours2, _ = ev("qmcp-gate-exec", "qmcp-gate-no-such-qube")
check("exec -> a name that does not exist : the same ASK as a real qube (no oracle)",
      k2 == "ASK" and ours2 and k1 == k2)
k, ours, _ = ev("qmcp-gate-dump", "qmcp-gate-out")
check("dump -> out : ASK from the stock default (operator drains the buffer)",
      k == "ASK" and not ours)
check(f"{gateway} -> @default : ASK (the operator's own line)", ev(gateway, "@default")[0] == "ASK")

if scratch is not None:
    shutil.rmtree(scratch, ignore_errors=True)
print(f"    {'contract holds' if not fails else f'{fails} contract check(s) FAILED'}")
sys.exit(1 if fails else 0)
PY

# ---------------------------------------------------------------- 4. validate + resolve BEFORE replacing
echo "==> Validating the staged policy with qrexec's parser..."
if ! python3 - "$EFFECTIVE" <<'PY'
import sys
try:
    from qrexec.policy.parser import StringPolicy
except ImportError:
    print("FATAL: qrexec's policy parser is not importable.", file=sys.stderr)
    sys.exit(1)
try:
    StringPolicy(policy={"__main__": open(sys.argv[1], encoding="utf-8").read()})
except Exception as e:
    print(f"FATAL: the parser rejected the staged policy: {e}", file=sys.stderr)
    sys.exit(1)
print("    parses clean.")
PY
then
    echo "FATAL: staged policy failed validation — NOT installing." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi

# Counted with awk on whole fields, not a grep backreference: `\2` in grep -E
# is a GNU extension, and a grep that errors prints nothing — the 3d
# uninstaller's silent no-op (the round-trip lesson).
count_backstops() {
    awk '$1 !~ /^#/ && $1 ~ /^(qmcp\.(RunIn|CopyTo)AIManaged|admin\.vm\.firewall\.(Set|Reload))$/ \
         && $2 == "*" && $4 == "@tag:ai-managed" && $5 == "allow" {n++} END {print n + 0}' "$1"
}
count_selfdenies() {
    awk '$1 ~ /^admin\.vm\.firewall\.(Set|Reload)$/ && $2 == "*" && $3 == $4 \
         && $5 == "deny" {n++} END {print n + 0}' "$1"
}
EB="$(count_backstops "$EFFECTIVE")"
ES="$(count_selfdenies "$EFFECTIVE")"
echo "    staged: $EB backstop line(s) (expected $EXPECT_BACKSTOPS), $ES firewall self-deny line(s) (expected 2)"
if [ "$EB" != "$EXPECT_BACKSTOPS" ] || [ "$ES" != "2" ]; then
    echo "FATAL: the staged file's backstop / self-deny counts are wrong — NOT installing." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi

echo "==> Resolving the Filecopy contract: this box's policy directory + the staged file..."
# As root: the scratch copy must be able to read every file in the policy
# directory, exactly as the daemon does.
if ! sudo python3 "$STAGE_DIR/filecopy_contract.py" staged "$EFFECTIVE" "$SOURCE_QUBE"; then
    echo "FATAL: the staged policy does not resolve as the contract requires." >&2
    echo "       The live policy has NOT been touched." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo

echo "==> Rule-line changes live -> staged (comments ignored):"
if [ -f "$POLICY_DST" ]; then
    diff <(grep -vE '^[[:space:]]*(#|$)' "$POLICY_DST") \
         <(grep -vE '^[[:space:]]*(#|$)' "$EFFECTIVE") | sed 's/^/    /' || true
else
    echo "    (no live policy)"
fi
echo

# ---------------------------------------------------------------- 5. back up, then install
TS="$(date -u +%Y%m%dT%H%M%SZ)"
sudo mkdir -p "$BACKUP_DIR/$TS"
if [ -f "$POLICY_DST" ]; then
    sudo cp -a "$POLICY_DST" "$BACKUP_DIR/$TS/30-mcp-control.policy"
    echo "==> Backed up the live policy to $BACKUP_DIR/$TS/ (root-only; inspect with sudo)"
    echo "    revert: sudo install -m 0644 -o root -g root \\"
    echo "            $BACKUP_DIR/$TS/30-mcp-control.policy $POLICY_DST"
else
    echo "==> No live policy present to back up (first install)."
fi
echo

echo "==> Installing dom0 policy (REPLACE)..."
sudo install -m 0644 -o root -g root "$EFFECTIVE" "$POLICY_DST"
echo "    $POLICY_DST"
echo

# ---------------------------------------------------------------- 6. reload the daemon
echo "==> Reloading the qrexec policy daemon..."
sudo systemctl reset-failed qubes-qrexec-policy-daemon qubes-policy-daemon 2>/dev/null || true
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    _unit=qubes-qrexec-policy-daemon
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    _unit=qubes-policy-daemon
else
    echo "FATAL: could not restart a policy daemon. The policy file IS installed;" >&2
    echo "       restart it by hand before relying on the new rules." >&2
    exit 1
fi
for _ in $(seq 1 10); do
    [ "$(systemctl is-active "$_unit")" = "active" ] && break
    sleep 1
done
if [ "$(systemctl is-active "$_unit")" != "active" ]; then
    echo "FATAL: $_unit is not active after the restart." >&2
    echo "       sudo systemctl reset-failed $_unit && sudo systemctl start $_unit" >&2
    exit 1
fi
echo "    $_unit active."
echo

# ---------------------------------------------------------------- 7. post-assert on what the daemon sees
echo "==> Re-resolving the contract off the INSTALLED policy directory..."
LB="$(count_backstops "$POLICY_DST")"
PHASE_AFTER="$(sudo awk '{sub(/#.*/, ""); for (i = 1; i <= NF; i++) {print $i; exit}}' "$FLAG" 2>/dev/null || true)"
echo "    installed: $LB backstop line(s); tier-default before='${PHASE:-<absent>}' after='${PHASE_AFTER:-<absent>}'"
if [ "$LB" != "$EXPECT_BACKSTOPS" ] || [ "$PHASE" != "$PHASE_AFTER" ]; then
    echo "FATAL: the installed phase is not the phase this install was meant to keep." >&2
    echo "       Restore the backup printed above before continuing." >&2
    exit 1
fi
if ! sudo python3 "$STAGE_DIR/filecopy_contract.py" live "$SOURCE_QUBE"; then
    echo "FATAL: the INSTALLED policy does not resolve as the contract requires." >&2
    echo "       Restore the backup printed above before continuing." >&2
    exit 1
fi
echo

rm -rf "$STAGE_DIR"

cat <<'EOF'
==> Installed.

    From an AI qube, `qvm-copy` now shows the normal Qubes dialog, and copies
    out to any of your qubes go through that dialog as well. Copies between
    qubes tagged ai-exec / ai-net / ai-full still need no dialog; copies into
    read-only or untiered AI qubes still ask. The ai-dump drop box is
    unchanged.

    Revert: restore the backup printed above and restart the policy daemon.
EOF
