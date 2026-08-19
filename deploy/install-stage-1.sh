#!/bin/bash
# install-stage-1.sh — run in dom0.
#
# Wave 2 Stage 1 install: the capability decision kernel, in SHADOW mode.
#
# Surface delta:
#   - NEW dom0 lib   /etc/qubes-rpc/qmcp_caps.py
#                    decide(actor, service, action, targets) -> a verdict derived
#                    from the domination lattice, plus capabilities(), explain()
#                    and resolve_birth_egress(). Sibling-loaded exactly like
#                    qmcp_budget / qmcp_scope / qmcp_audit / qmcp_tier.
#   - MODIFIED       /etc/qubes-rpc/qmcp_audit.py
#                    audit() gains an optional `shadow` field, OMITTED when None
#                    (the same byte-neutral contract `consent` already follows).
#   - MODIFIED       the 8 state-changing wrappers
#                    each asks the kernel the same question it just answered and
#                    records ONLY a disagreement, through its existing emit().
#
# BEHAVIOUR-NEUTRAL. The kernel enforces NOTHING. Every wrapper's authority
# decision is still its Stage I-5 CAP_FULL gate; the kernel's verdict is
# compared against it and, when they differ, one line lands on the AI-unreachable
# I-2 audit chain. Where they agree — the overwhelming majority — no field is
# written and the audit line and its chain hash are byte-identical to pre-Stage-1.
#
# The point of the stage is that divergence log. Stage 3 flips enforcement over
# to decide() and is GATED on that log holding nothing unexplained.
#
# Fail-open BY DESIGN, and this is the one inversion in the codebase worth
# stating twice: a missing or broken qmcp_caps.py must change nothing at all.
# The tier and consent gates fail CLOSED because they are gates; this is not a
# gate. If a later stage makes it one, the posture has to move with it.
#
# No policy change. No daemon restart — deliberately (finding F1: 14 installers
# restarted qubes-qrexec-policy-daemon with no verification and tripped systemd's
# start limit; nothing here touches policy, so nothing here restarts anything).
# No new RPC service callable by AI: a lib is not a service, and no policy line
# exposes it.
#
# Idempotent — re-runnable. Install overwrites.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-1.sh' > /tmp/install-1.sh
#   bash /tmp/install-1.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-1"
LIBS="dom0-rpc/qmcp_caps.py dom0-rpc/qmcp_audit.py"
WRAPPERS="dom0-rpc/qmcp.LifecycleAIManaged
dom0-rpc/qmcp.SetPropertyAIManaged
dom0-rpc/qmcp.SetFeatureAIManaged
dom0-rpc/qmcp.CloneAIManagedQube
dom0-rpc/qmcp.SpawnAIManagedQube
dom0-rpc/qmcp.SpawnDisposableAIManaged
dom0-rpc/qmcp.AttachDeviceAIManaged
dom0-rpc/qmcp.DetachDeviceAIManaged"

echo "==> Wave 2 Stage 1 deploy starting (decision kernel, SHADOW mode)"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage 1 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Collapse the file list to a single line before it becomes a REMOTE command.
# `$WRAPPERS` is written multi-line for readability, and an unquoted expansion
# inside the double-quoted command string keeps those newlines — which the
# target's shell reads as command separators. `tar` then archives only the
# files up to the first newline and the remaining lines are EXECUTED: each is a
# qmcp wrapper, so each reads stdin, hits EOF, prints its `invalid JSON input`
# refusal INTO the tar stream, and exits 1. The pull returns rc=1 and `set -e`
# aborts with no message at all. Fail-closed, but silent — and one `set -e`
# removal away from installing a partial set (F9's split-brain family).
# `$(echo ...)` collapses every whitespace run to a single space. Do not "tidy"
# this back into an inline expansion.
REMOTE_LIST="$(echo $LIBS $WRAPPERS)"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $REMOTE_LIST" \
    > "$STAGE_DIR/stage-1.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf stage-1.tar)

for f in $LIBS $WRAPPERS; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    pulled 10 files."
echo

# ---------------------------------------------------------------- 2. gates
# Everything is checked BEFORE anything is installed. A half-installed set is
# the split-brain failure F9 taught us to design against: here it would mean
# wrappers passing a kwarg an older qmcp_audit.py does not accept.
echo "==> Compile-checking every staged file..."
for f in $LIBS $WRAPPERS; do
    if ! python3 -c "compile(open('$STAGE_DIR/$f').read(), '$f', 'exec')"; then
        echo "FATAL: $f failed to compile — aborting before install." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    all 10 compile."

# Stage 3c renamed this hook from `_shadow_note` (which computed the kernel's
# verdict and discarded it) to `_gate` (which acts on it). The marker moved with
# it, so this guard keeps checking the tree it is actually installing.
echo "==> Confirming every wrapper actually carries the decision hook..."
for f in $WRAPPERS; do
    if ! grep -q '_gate(' "$STAGE_DIR/$f"; then
        echo "FATAL: $f has no _gate call — wrong or stale source tree." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    8/8 wired."

echo "==> Confirming qmcp_audit.py accepts the shadow field..."
if ! grep -q 'shadow=None' "$STAGE_DIR/dom0-rpc/qmcp_audit.py"; then
    echo "FATAL: staged qmcp_audit.py predates the shadow field — aborting." >&2
    echo "       Installing wired wrappers against it would lose divergence lines." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    ok."
echo

echo "==> SHA-256 of pulled files (record for your audit):"
# -type f, not ./*: a stray directory (a __pycache__ left by any
# python that touched the staging dir) makes sha256sum exit non-zero,
# and `set -e` then aborts the install with nothing but a one-line
# sha256sum error to explain it.
( cd "$STAGE_DIR/dom0-rpc" && find . -maxdepth 1 -type f -print0 \
    | sort -z | xargs -0 sha256sum | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 3. install
# Libs 0644, wrappers 0755 — matching the modes every prior stage installed.
echo "==> Installing shared libs..."
for f in $LIBS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0644)"
done

echo "==> Installing the 8 shadow-wired wrappers..."
for f in $WRAPPERS; do
    sudo install -m 0755 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0755)"
done
echo

# ---------------------------------------------------------------- 4. smoke
# The kernel is dom0-side and AI-unreachable; its full proof is the offline
# suite (deploy/offline-validate-1.py, 46 checks). Here we confirm only that it
# LOADS in dom0 beside its siblings and that the three invariants it exists to
# hold still hold in the installed copy — so a broken lib is caught at deploy
# rather than by its silence.
echo "==> Smoke: kernel loads in dom0 and holds its three invariants..."
sudo python3 - <<'PY'
import importlib.util, tempfile, os
s = importlib.util.spec_from_file_location("qmcp_caps", "/etc/qubes-rpc/qmcp_caps.py")
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
assert m._TIER is not None, "kernel could not load its qmcp_tier sibling"
for fn in ("decide", "capabilities", "explain", "resolve_birth_egress",
           "shadow_record"):
    assert hasattr(m, fn), "kernel missing %s" % fn


class VM:
    def __init__(self, name, tags):
        self.name = name
        self.tags = set(tags)


flag = tempfile.mktemp()
open(flag, "w").write("ro")
absent = os.path.join(tempfile.gettempdir(), "qmcp-s1-guarded-absent-zzz")


def d(svc, act, tgts, params=None):
    return m.decide("mcp-control", svc, act, tgts, params or {},
                    tier_default_path=flag, guarded_list_path=absent)


full = VM("x", ["ai-managed", "ai-full"])
execv = VM("x", ["ai-managed", "ai-exec"])
out = VM("x", [])

# invariant: the existence boundary outranks everything
assert d("qmcp.LifecycleAIManaged", "start", {"target": out}).rule \
    == "outside-umbrella", "umbrella check not first"
# invariant 3: escalation is never dominated, at any tier
assert d("qmcp.SetPropertyAIManaged", "set", {"target": full},
         {"property": "netvm"}).rule == "escalation-class", "escalation leaked"
# invariant 1: anti-theatre — a dominated op is allowed, not gated
assert d("qmcp.LifecycleAIManaged", "remove", {"target": execv}).verdict \
    == m.ALLOW, "domination not applied"
# nothing dominates a hardware-boundary crossing
assert d("qmcp.AttachDeviceAIManaged", "attach",
         {"backend": execv, "frontend": execv}).verdict == m.DENY, \
    "attach wrongly dominated"
# fail-closed on an unknown surface
assert d("qmcp.NotAService", "x", {"target": full}).rule == "unknown-service"
# shadow_record is silent on agreement — the byte-neutrality the stage rests on
assert m.shadow_record("mcp-control", "qmcp.LifecycleAIManaged", "start",
                       {"target": full}, {}, wrapper_allowed=True,
                       tier_default_path=flag,
                       guarded_list_path=absent) is None, \
    "agreement would write a field"
os.remove(flag)
print("    kernel OK: boundary first, escalation held, domination applied,")
print("               attach undominated, unknown-service denied, agreement silent")
PY
echo

echo "==> Smoke: every installed wrapper still compiles in dom0..."
for f in $WRAPPERS; do
    b=$(basename "$f")
    python3 -c "compile(open('/etc/qubes-rpc/$b').read(), '$b', 'exec')"
done
echo "    8/8 compile in place."
echo

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo "==> Wave 2 Stage 1 deploy complete (kernel installed in SHADOW mode)."
echo
echo "No policy change; no daemon restart; no wrapper behaviour change."
echo
echo "Transparency check from mcp-control (responses must be unchanged):"
echo "  .venv/bin/python deploy/test-stage-a.py      # regression: unchanged"
echo "  .venv/bin/python deploy/test-stage-I-5.py    # regression: unchanged"
echo
echo "The divergence log is dom0-side and AI-unreachable BY DESIGN — read it here:"
echo "  sudo grep -c '\"shadow\"' /var/log/qmcp-audit.log"
echo "  sudo grep '\"shadow\"' /var/log/qmcp-audit.log | tail"
echo
echo "Expect divergences on exactly two shapes until Stages 2 and 3 land:"
echo "  - lifecycle on an ai-exec target  -> kernel allow / wrapper deny (dominated)"
echo "  - SetProperty netvm|template|name -> kernel deny / wrapper allow (escalation)"
echo "Anything ELSE in that log is a finding, and Stage 3 must not flip until it"
echo "is explained."
