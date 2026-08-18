#!/bin/bash
# install-stage-3b.sh — run in dom0.
#
# Wave 2 Stage 3b install: the enforcement-mode flag, INERT.
#
# Surface delta:
#   - NEW dom0 lib   /etc/qubes-rpc/qmcp_enforce.py
#                    the operator's flip switch: read_mode() over
#                    /etc/qmcp/enforce-mode, and effective_verdict() composing
#                    a wrapper's own decision with qmcp_caps' verdict.
#                    Sibling-installed exactly like qmcp_caps / qmcp_tier /
#                    qmcp_tombstone.
#
# That is the entire delta. No operator file is created (absent = shadow = the
# shipped default, so creating one would be the flip). No policy change, so no
# qrexec daemon restart (F1). No systemd unit. No new AI-callable RPC service —
# a lib is not a service, and no policy line names it.
#
# INERT. Nothing sources this module until Stage 3c wires it into the wrappers;
# `git diff --stat -- 'dom0-rpc/qmcp.*' 'policy/' 'template-rpc/'` is empty for
# this stage, which is how behaviour-neutrality is proven here (the I-3 pattern)
# rather than by a state-changing hardware regression.
#
# WHY THERE IS NO POLICY BACKSTOP, though every prior flip in this project had
# one. `tier-default` needed paired COMPAT lines in 30-mcp-control.policy
# because the surfaces it governed were @tag:-scoped, and the qrexec policy
# engine matches tags literally and cannot read an operator file (the I-4
# lesson).
#
# The surfaces Stage 3c flips are the 13 dom0 WRAPPER services, scoped
# `* mcp-control @adminvm allow` with no tag matching: the decision is made
# inside our own wrapper, which CAN read the file, so a backstop line would back
# up nothing while reading as a control — invariant 2 (no-illusion), the same
# defect as the _RING_MIN_TIER table Stage 2 deleted.
#
# The lattice's OTHER 6 surfaces (the two template exec/copy services, the three
# firewall methods, qubes.Filecopy) are @tag:-scoped and decided by the qrexec
# engine before any code of ours runs. This flag cannot govern them — and does
# not need to: they were graduated to the ladder already by Stages I-4, I-5 and
# G0c, each with its own COMPAT backstop, and those flips are done. Every
# tag-scoped surface in the lattice already had its backstop, at the stage that
# graduated it. Revert is one write, below.
#
# Idempotent — re-runnable. Install overwrites; nothing is enabled or started.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-3b.sh' > /tmp/install-3b.sh
#   bash /tmp/install-3b.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-3b"
LIBS="dom0-rpc/qmcp_enforce.py"
ALL="$LIBS"

echo "==> Wave 2 Stage 3b deploy starting (enforcement-mode flag, INERT)"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage 3b files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Collapse the file list to one line before it becomes a REMOTE command (F-L):
# an embedded newline in the remote string is a command separator on the
# target's shell, tar archives only the first line, and the rest EXECUTE.
REMOTE_LIST="$(echo $ALL)"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $REMOTE_LIST" \
    > "$STAGE_DIR/stage-3b.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf stage-3b.tar)

for f in $ALL; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    pulled 1 file."
echo

# ---------------------------------------------------------------- 2. gates
# Everything is checked BEFORE anything is installed.
echo "==> Compile-checking the staged python file..."
for f in $LIBS; do
    if ! python3 -c "compile(open('$STAGE_DIR/$f').read(), '$f', 'exec')"; then
        echo "FATAL: $f failed to compile — aborting before install." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    compiles."

# THE guard for this stage, and it asserts BEHAVIOUR, not vocabulary. The
# Stage 3a lesson was that a guard grepping for forbidden words matches the
# docstring explaining why the thing is forbidden, and misses a flag named
# innocuously. So instead of grepping qmcp_enforce.py for "enforce", run the
# staged module and check what it actually does on the inputs that matter.
#
# The property being guarded: this flip is BIDIRECTIONAL. It narrows the
# escalation class and simultaneously widens lifecycle (invariant 1 grants
# remove/kill/shutdown/start at CAP_EXEC, because exec already reaches every
# effect they have). So "enforce" is not uniformly safer than "shadow", and a
# corrupt operator flag must NOT land there — it would hand every ai-exec actor
# irreversible qube destruction on the strength of a typo. It must land in
# strict, the one mode that takes every narrowing and no widening.
echo "==> Confirming the staged module fails closed to STRICT, not ENFORCE..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/$LIBS" <<'PY'
import importlib.util, os, sys, tempfile
spec = importlib.util.spec_from_file_location("qmcp_enforce", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

d = tempfile.mkdtemp(prefix="qmcp-3b-guard-")


def flagfile(name, content=None, mode=0o644):
    p = os.path.join(d, name)
    if content is None:
        return p
    with open(p, "w") as fh:
        fh.write(content)
    os.chmod(p, mode)
    return p


fail = []
if m.read_mode(flagfile("absent")) != m.SHADOW:
    fail.append("an absent flag must resolve to shadow — the stage is not inert")
for bad in ("enforece\n", "full\n", "", "1\n", "# not yet\n"):
    if m.read_mode(flagfile("bad%d" % len(fail + [bad]), bad)) != m.STRICT:
        fail.append("a malformed flag (%r) does not fail closed to strict" % bad)
if os.geteuid() != 0 and m.read_mode(flagfile("nr", "enforce\n", 0o000)) != m.STRICT:
    fail.append("an unreadable flag does not fail closed to strict")
# strict must refuse BOTH directions of divergence.
if m.effective_verdict(m.STRICT, False, m.ALLOW) != m.DENY:
    fail.append("strict admits the kernel's WIDENING — it is not fail-closed")
if m.effective_verdict(m.STRICT, True, m.DENY) != m.DENY:
    fail.append("strict admits what the kernel denies — it is not fail-closed")
# shadow must be behaviourally invisible, or the stage is not inert.
if any(m.effective_verdict(m.SHADOW, w, k) != (m.ALLOW if w else m.DENY)
       for w in (True, False) for k in (m.ALLOW, m.DENY, m.GATE, "junk")):
    fail.append("shadow does not return the wrapper's verdict unchanged")

for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: the staged qmcp_enforce.py does not fail closed as designed." >&2
    echo "       Installing it would let a typo in /etc/qmcp/enforce-mode arm" >&2
    echo "       the lifecycle widening. Aborting." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    absent->shadow, malformed->strict, strict refuses both directions."

# The vocabulary drift guard, checked against the INSTALLED kernel rather than
# the staged one: qmcp_enforce ranks the three verdict literals qmcp_caps
# returns, and holds its own copies so it can load without a sibling import. A
# rename in one that missed the other makes every comparison silently false —
# every kernel verdict reads as unrecognised and collapses to DENY. That fails
# safe and bricks the fleet, which is a bad enough outcome to check for. Same
# family as Stage 3a's two TOMBSTONE_PREFIX copies.
if [ -f /etc/qubes-rpc/qmcp_caps.py ]; then
    echo "==> Confirming the verdict vocabulary matches the installed kernel..."
    if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/$LIBS" <<'PY'
import importlib.util, sys


def load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


enf = load("qmcp_enforce", sys.argv[1])
caps = load("qmcp_caps", "/etc/qubes-rpc/qmcp_caps.py")
bad = [n for n in ("ALLOW", "DENY", "GATE")
       if getattr(enf, n) != getattr(caps, n)]
for n in bad:
    print("    %s: staged %r != installed kernel %r"
          % (n, getattr(enf, n), getattr(caps, n)), file=sys.stderr)
missing = {caps.ALLOW, caps.DENY, caps.GATE} - set(enf._SEVERITY)
if missing:
    print("    unranked kernel verdicts: %r" % (missing,), file=sys.stderr)
sys.exit(1 if (bad or missing) else 0)
PY
    then
        echo "FATAL: verdict vocabulary drift between qmcp_enforce and qmcp_caps." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
    echo "    allow/deny/gate agree with /etc/qubes-rpc/qmcp_caps.py."
else
    echo "==> WARNING: /etc/qubes-rpc/qmcp_caps.py is not installed."
    echo "             Stage 3b's flag is meaningless without the Stage 1 kernel."
    echo "             Install Stage 1 before Stage 3c flips anything."
fi
echo

echo "==> SHA-256 of pulled files (record for your audit):"
# Excludes __pycache__ as well as the tar: the gates above execute the staged
# module, so a stray .pyc would otherwise be listed here as if it had been
# pulled from the source qube. An audit line that reports a file nobody sent is
# worse than one that reports nothing.
( cd "$STAGE_DIR" && find . -type f ! -name '*.tar' ! -path '*/__pycache__/*' -print0 \
    | sort -z | xargs -0 sha256sum | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 3. install
echo "==> Installing the shared lib (0644)..."
for f in $LIBS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0644)"
done
echo

# ---------------------------------------------------------------- 4. operator file
# NOT created. Absent is the shipped default and means shadow; creating it here
# with any content would be performing the flip inside the installer.
echo "==> /etc/qmcp/enforce-mode: not created (absent = shadow, the default)."
echo "        To take every narrowing without the lifecycle widening:"
echo "            printf 'strict\\n' | sudo tee /etc/qmcp/enforce-mode >/dev/null"
echo "            sudo chmod 0644 /etc/qmcp/enforce-mode"
echo "        To hand the kernel full authority (Stage 3c, after the smoke suite):"
echo "            printf 'enforce\\n' | sudo tee /etc/qmcp/enforce-mode >/dev/null"
echo "        To revert, at any time, with no policy reload and no slot-revert:"
echo "            printf 'shadow\\n' | sudo tee /etc/qmcp/enforce-mode >/dev/null"
echo

# The I-2 permission trap on the read side: these wrappers run under qrexec as a
# NON-ROOT dom0 user, and `sudo bash -c 'echo enforce > …'` lands root:root 0600.
# Unlike every other operator file here, an unreadable enforce-mode does not fail
# closed silently — it lands in strict, which is louder than shadow — but the
# operator still gets a mode they did not choose.
echo "==> Checking operator files are readable by the non-root wrapper user..."
_qmcp_perm_warn=0
for f in enforce-mode tier-default birth-ceiling birth-egress guarded; do
    [ -e "/etc/qmcp/$f" ] || continue
    mode=$(stat -c '%a' "/etc/qmcp/$f")
    case "$mode" in
        *4|*5|*6|*7) echo "    ok         /etc/qmcp/$f ($mode)" ;;
        *) echo "    UNREADABLE /etc/qmcp/$f ($mode) — the wrapper cannot read this."
           echo "               Fix: sudo chmod 0644 /etc/qmcp/$f"
           _qmcp_perm_warn=1 ;;
    esac
done
if [ "$_qmcp_perm_warn" = "1" ]; then
    echo "    WARNING: at least one operator file is unreadable by the wrapper."
fi
echo

# ---------------------------------------------------------------- 5. smoke
echo "==> Smoke: the installed lib loads in dom0 and reports the live mode..."
sudo python3 - <<'PY'
import importlib.util

s = importlib.util.spec_from_file_location(
    "qmcp_enforce", "/etc/qubes-rpc/qmcp_enforce.py")
enf = importlib.util.module_from_spec(s)
s.loader.exec_module(enf)

mode = enf.read_mode()
print("    loads from /etc/qubes-rpc, modes = %s" % (enf.MODES,))
print("    %s -> mode is %r" % (enf.MODE_PATH, mode))
if mode == enf.SHADOW:
    print("    SHADOW: the kernel's verdict cannot change any wrapper's behaviour.")
    print("    Stage 3b is INERT, as designed.")
else:
    print("    NOTE: this fleet is NOT in shadow. Stage 3c's flip is already")
    print("          armed (or partly armed) by the operator file above.")
PY
echo

echo "==> Stage 3b deploy complete."
echo "    Installed: /etc/qubes-rpc/qmcp_enforce.py"
echo "    Created:   nothing — the flag is absent, so the fleet is unchanged."
echo "    Next:      run deploy/smoke-production.py from mcp-control."
echo "               Exit 0 (GREEN) is Stage 3c's gate; exit 3 (INCOMPLETE) is not."
