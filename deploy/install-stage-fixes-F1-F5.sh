#!/bin/bash
# install-stage-fixes-F1-F5.sh — run in dom0.
#
# Security fixes for the five findings of the 2026-08-18 adversarial pass, all
# of which were reproduced from the AI seat against a live fleet.
#
# Surface delta:
#   - MODIFIED /etc/qubes-rpc/qmcp_birth.py
#              gains the reserved NAME namespace: read_name_prefix() over the
#              new operator file /etc/qmcp/name-prefix (absent = "ai-"), and
#              name_refusal(), which depends on the requested name and the
#              prefix ONLY — never on what exists on the host.
#   - MODIFIED /etc/qubes-rpc/qmcp.SpawnAIManagedQube      (F-1, F-4, F-5)
#   - MODIFIED /etc/qubes-rpc/qmcp.CloneAIManagedQube      (F-1, F-4)
#   - MODIFIED /etc/qubes-rpc/qmcp.SpawnDisposableAIManaged (F-4)
#   - MODIFIED /etc/qubes-rpc/qmcp.SetPropertyAIManaged    (F-2, F-3)
#
# No policy change, so no qrexec daemon restart (F1). No new RPC service. No
# new operator file is created — /etc/qmcp/name-prefix absent means "ai-".
#
# BEHAVIOUR CHANGES — this is not an inert stage, and both are intended:
#   1. A create whose requested name is outside the reserved prefix is REFUSED.
#      Existing qubes are unaffected; only new creates are. Adopters whose
#      agents create qubes under other names must set /etc/qmcp/name-prefix or
#      rename their conventions.
#   2. An egress RETARGET (a non-null netvm write) is REFUSED. `netvm = null`
#      stays allowed, mirroring the birth path's de-escalation carve-out.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-fixes-F1-F5.sh' > /tmp/fixes.sh
#   bash /tmp/fixes.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"
STAGE_DIR="/tmp/qubes-mcp-stage-fixes"

LIBS="dom0-rpc/qmcp_birth.py"
WRAPPERS="dom0-rpc/qmcp.SpawnAIManagedQube dom0-rpc/qmcp.CloneAIManagedQube dom0-rpc/qmcp.SpawnDisposableAIManaged dom0-rpc/qmcp.SetPropertyAIManaged"
ALL="$LIBS $WRAPPERS"

echo "==> F-1..F-5 security fixes deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"
REMOTE_LIST="$(echo $ALL)"          # one line — F-L
qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $REMOTE_LIST" \
    > "$STAGE_DIR/fixes.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf fixes.tar)
for f in $ALL; do
    [ -s "$STAGE_DIR/$f" ] || { echo "FATAL: pulled an empty file: $f" >&2; rm -rf "$STAGE_DIR"; exit 1; }
done
echo "    pulled 5 files."
echo

# ---------------------------------------------------------------- 2. gates
echo "==> Compile-checking..."
for f in $ALL; do
    python3 -c "compile(open('$STAGE_DIR/$f').read(), '$f', 'exec')" \
      || { echo "FATAL: $f failed to compile." >&2; rm -rf "$STAGE_DIR"; exit 1; }
done
echo "    all 5 compile."

# Behavioural guard, not a grep: run the staged namespace helper against the
# inputs that matter. The Stage 3a lesson says assert structure over
# vocabulary; where the artifact IS a function, run it (the Stage 3b lesson).
echo "==> Confirming the staged name guard refuses out-of-namespace names..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/$LIBS" <<'PY'
import importlib.util, os, sys, tempfile
spec = importlib.util.spec_from_file_location("qmcp_birth", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
d = tempfile.mkdtemp()
def f(n, c=None):
    p = os.path.join(d, n)
    if c is None: return p
    open(p, "w").write(c); return p
bad = []
if m.read_name_prefix(f("absent")) != "ai-":
    bad.append("absent prefix file does not give the default")
for junk in ("", "   ", "-x", "a b", "x" * 40):
    if m.read_name_prefix(f("j%d" % len(bad + [junk]), junk)) != "ai-":
        bad.append("malformed prefix %r does not fall back to the default" % junk)
for n in ("vault", "personal", "sys-usb", "dom0", "ai", "ai-"):
    if m.name_refusal(n, "ai-") is None:
        bad.append("out-of-namespace name %r was accepted" % n)
for n in ("ai-worker", "ai-smoke-parent"):
    if m.name_refusal(n, "ai-") is not None:
        bad.append("in-namespace name %r was refused" % n)
# The refusal must not echo the requested name — that was the leak.
for n in ("vault", "personal"):
    if n in (m.name_refusal(n, "ai-") or ""):
        bad.append("the refusal for %r echoes the name back" % n)
for line in bad: print("    " + line, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
then
    echo "FATAL: the staged name guard does not behave as designed." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "    out-of-namespace refused, in-namespace allowed, no name echoed back."

echo "==> Confirming the staged property wrapper refuses a netvm retarget..."
if ! grep -q 'netvm change is operator-only' "$STAGE_DIR/dom0-rpc/qmcp.SetPropertyAIManaged"; then
    echo "FATAL: the staged qmcp.SetPropertyAIManaged does not carry the F-2 refusal." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "    present."

# F-4: no AI-visible field may carry an exception. Structural, over CODE lines
# only — the comments explaining the fix legitimately name what leaked.
echo "==> Confirming no wrapper returns raw exception text to AI..."
# `|| true` on the pipeline is load-bearing under `set -o pipefail`: a grep
# that legitimately matches nothing exits 1, pipefail propagates it, and -e
# aborts the install on the CLEAN case. The first run of this installer died
# exactly there, which is the good version of that mistake — a gate that fails
# closed on success is at least loud.
LEAKS=0
for f in $WRAPPERS; do
    n=$( { grep -vE '^[[:space:]]*#' "$STAGE_DIR/$f" \
           | grep -E '("error"|"warning"|fail\()' \
           | grep -F '{e}' \
           | grep -vF 'invalid JSON input' \
           | wc -l; } 2>/dev/null || true )
    n=${n:-0}
    if [ "$n" -gt 0 ]; then
        echo "    $f: $n raw-exception site(s)"
        LEAKS=$((LEAKS + n))
    fi
done
if [ "$LEAKS" -gt 0 ]; then
    echo "FATAL: $LEAKS AI-visible field(s) still carry exception text." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "    none (the JSON-parse echo is excluded: it carries AI's own payload)."
echo

echo "==> SHA-256 of pulled files:"
( cd "$STAGE_DIR" && find . -type f ! -name '*.tar' ! -path '*/__pycache__/*' -print0 \
    | sort -z | xargs -0 sha256sum | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 3. install
echo "==> Installing the lib (0644) and the wrappers (0755)..."
for f in $LIBS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0644)"
done
for f in $WRAPPERS; do
    sudo install -m 0755 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0755)"
done
echo

# ---------------------------------------------------------------- 4. residual
# The namespace bounds the oracle to itself; a NON-ai-managed qube inside it is
# still detectable. That residual is documented, not hidden, so the operator is
# told when it actually exists on their fleet.
echo "==> Checking the reserved namespace for qubes AI must not learn about..."
# Every command here is guarded. The operator file usually does NOT exist
# (absent = the default), so an unguarded `sed` on it fails, pipefail
# propagates, and `set -e` aborts the install AFTER the files are already
# in place — which is the worst moment for a purely informational check to
# take the script down. It did exactly that on the first run.
PREFIX=""
if [ -r /etc/qmcp/name-prefix ]; then
    PREFIX=$( { sed 's/#.*//' /etc/qmcp/name-prefix | tr -d '[:space:]'; } 2>/dev/null || true )
fi
[ -n "$PREFIX" ] || PREFIX="ai-"
echo "    reserved prefix: '$PREFIX'"
SHADOWED=""
ALL_VMS=$(qvm-ls --raw-list 2>/dev/null || true)
for v in $ALL_VMS; do
    case "$v" in
        "$PREFIX"*)
            if ! qvm-tags "$v" 2>/dev/null | grep -qx 'ai-managed'; then
                SHADOWED="$SHADOWED $v"
            fi
            ;;
    esac
done
if [ -n "$SHADOWED" ]; then
    echo "    NOTE: these qubes sit inside the reserved namespace but are NOT"
    echo "          ai-managed, so AI can still infer their existence by name:"
    for v in $SHADOWED; do echo "            $v"; done
    echo "          Rename them out of the '$PREFIX' namespace, or accept it."
else
    echo "    none — the namespace holds only ai-managed qubes, so the residual"
    echo "    disclosure is empty on this fleet."
fi
echo

# ---------------------------------------------------------------- 5. smoke
echo "==> Smoke: the installed helper answers correctly in dom0..."
sudo python3 - <<'PY'
import importlib.util
s = importlib.util.spec_from_file_location("qmcp_birth", "/etc/qubes-rpc/qmcp_birth.py")
b = importlib.util.module_from_spec(s); s.loader.exec_module(b)
p = b.read_name_prefix()
print("    live prefix: %r" % p)
print("    'vault'      -> %s" % b.name_refusal("vault", p))
print("    'ai-worker'  -> %s" % b.name_refusal("ai-worker", p))
assert b.name_refusal("vault", p) is not None
assert b.name_refusal("ai-worker", p) is None
print("    guard live.")
PY
echo
echo "==> F-1..F-5 fixes deploy complete."
echo "    Behaviour CHANGED: out-of-namespace creates and egress retargets are"
echo "    now refused. Re-run deploy/test-stage-c.py and deploy/smoke-production.py."
