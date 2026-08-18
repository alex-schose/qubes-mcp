#!/bin/bash
# install-stage-2.sh — run in dom0.
#
# Wave 2 Stage 2 install: ownership + birth tier + birth egress.
#
# Surface delta:
#   - NEW dom0 lib   /etc/qubes-rpc/qmcp_birth.py
#                    the reserved `qmcp-*` namespace (§3.2) and the atomic birth
#                    stamp: clamp privilege, inherit restrictions, read back,
#                    raise so the caller rolls the create back.
#   - MODIFIED       /etc/qubes-rpc/qmcp_tier.py
#                    + resolve_birth_tier() and /etc/qmcp/birth-ceiling.
#   - MODIFIED       /etc/qubes-rpc/qmcp_caps.py
#                    resolve_birth_egress() gains `source_authoritative` (F-J).
#   - MODIFIED       the 3 create wrappers (Spawn / Clone / SpawnDisposable)
#   - NEW operator file /etc/qmcp/birth-egress   (0644 root:root)
#
# THIS STAGE CHANGES BEHAVIOUR — it is the F6 unblock and the 1.0.0 gate, so it
# cannot be the usual inert-then-prove stage. What it changes, precisely:
#   1. A created qube is born at its SOURCE's literal tier, clamped by
#      /etc/qmcp/birth-ceiling, instead of always untiered. In COMPAT this is
#      invisible (an untiered source still yields an untiered child); post-flip
#      it is the difference between a created qube being usable by its creator
#      and being inert until an operator tiers it.
#   2. A created qube's netvm is INHERITED (§3.4) instead of defaulting to the
#      hardcoded `ai-net-router`. On a single-egress fleet the answer is the
#      same qube; on a fleet with two egress classes it is the difference
#      between a Tor-side agent spawning a Tor qube and spawning a clearnet one.
#   3. A create whose egress or tag state cannot be PROVEN is rolled back, where
#      a netvm failure used to return ok=true with a warning.
#
# No policy change. No daemon restart (finding F1 — nothing here touches policy).
# No new RPC service callable by AI: a lib is not a service.
#
# Idempotent — re-runnable. Install overwrites; the operator file is created
# once and never overwritten.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-2.sh' > /tmp/install-2.sh
#   bash /tmp/install-2.sh mcp-control ~user/qubes_mcp/public
#
# Environment:
#   EGRESS_QUBE   name written to /etc/qmcp/birth-egress (default ai-net-router).
#                 Must match the egress qube install-stage-c.sh created.

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"
EGRESS_QUBE="${EGRESS_QUBE:-ai-net-router}"
GATEWAY="${GATEWAY:-$SOURCE_QUBE}"

STAGE_DIR="/tmp/qubes-mcp-stage-2"
LIBS="dom0-rpc/qmcp_birth.py dom0-rpc/qmcp_tier.py dom0-rpc/qmcp_caps.py"
WRAPPERS="dom0-rpc/qmcp.SpawnAIManagedQube
dom0-rpc/qmcp.CloneAIManagedQube
dom0-rpc/qmcp.SpawnDisposableAIManaged"

echo "==> Wave 2 Stage 2 deploy starting (ownership + birth tier + birth egress)"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo "    egress qube:    $EGRESS_QUBE"
echo "    gateway:        $GATEWAY"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage 2 files from $SOURCE_QUBE:$SOURCE_PATH..."
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
    > "$STAGE_DIR/stage-2.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf stage-2.tar)

for f in $LIBS $WRAPPERS; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
done
echo "    pulled 6 files."
echo

# ---------------------------------------------------------------- 2. gates
# Everything is checked BEFORE anything is installed. A half-installed set is
# F9's split-brain failure: here it would mean create wrappers calling a
# qmcp_tier.py with no resolve_birth_tier, which fails closed on every create.
echo "==> Compile-checking every staged file..."
for f in $LIBS $WRAPPERS; do
    if ! python3 -c "compile(open('$STAGE_DIR/$f').read(), '$f', 'exec')"; then
        echo "FATAL: $f failed to compile — aborting before install." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
done
echo "    all 6 compile."

echo "==> Confirming the staged helpers carry Stage 2's entry points..."
if ! grep -q 'def resolve_birth_tier' "$STAGE_DIR/dom0-rpc/qmcp_tier.py"; then
    echo "FATAL: staged qmcp_tier.py predates the birth clamp — aborting." >&2
    echo "       Installing the wrappers against it would refuse every create." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
if ! grep -q 'source_authoritative' "$STAGE_DIR/dom0-rpc/qmcp_caps.py"; then
    echo "FATAL: staged qmcp_caps.py predates F-J — aborting." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
for f in $WRAPPERS; do
    if ! grep -q '_birth_stamp' "$STAGE_DIR/$f"; then
        echo "FATAL: $f has no birth stamp — wrong or stale source tree." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
done
echo "    3/3 wrappers wired; both helpers current."

# The reserved tags (`qmcp-owner_<principal>`, `qmcp-egress-locked_<netvm>`)
# join key and value with the separator `SEP` in qmcp_birth.py. Which
# punctuation qubesd tolerates is a PLATFORM fact — measured as alphanumerics,
# "-" and "_" on R4.3, where `qubes.vm.Tags.validate_tag` raises
# ValueError("disallowed characters") for ":" and "." — and it could differ on
# another release. Probe the REAL separator, taken from the staged helper rather
# than written here, so this check can never drift away from the thing it
# checks. The failure it prevents is silent and total: every create path would
# fail closed forever afterwards, on a fleet whose install reported success.
#
# Note the diagnosis cost if this ever fires for real: qubesd answers a
# tag-validation failure as an UNHANDLED EXCEPTION, so the caller sees only
# "Got empty response from qubesd" and the actual ValueError lands in dom0's
# journal. Nothing in the error names the tag or the character.
echo "==> Pre-flight: does this Qubes accept the reserved tag shape?"
SEP="$(PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/dom0-rpc/qmcp_birth.py" <<'PYSEP'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("qmcp_birth", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.SEP)
PYSEP
)"
PROBE_TAG="qmcp-install-probe${SEP}$$"
PROBE_VM="$GATEWAY"
if ! qvm-check "$PROBE_VM" >/dev/null 2>&1; then
    echo "FATAL: gateway qube '$PROBE_VM' not found — pass GATEWAY=<name>." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
if qvm-tags "$PROBE_VM" add "$PROBE_TAG" >/dev/null 2>&1; then
    qvm-tags "$PROBE_VM" del "$PROBE_TAG" >/dev/null 2>&1 || true
    echo "    accepted: separator '$SEP' (probed with $PROBE_TAG)."
else
    echo "FATAL: this Qubes REFUSES a tag containing '$SEP'." >&2
    echo "       Probe tag was: $PROBE_TAG" >&2
    echo "       Check 'journalctl -u qubesd' in dom0 for the real reason —" >&2
    echo "       a validation failure surfaces to the caller as an empty" >&2
    echo "       response with no detail." >&2
    echo "       Then pick a separator this platform accepts, set SEP in" >&2
    echo "       dom0-rpc/qmcp_birth.py, re-run deploy/offline-validate-2*.py," >&2
    echo "       and re-run this script. Nothing else in the stage moves." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi

# The gateway's own placement is load-bearing for rows 1-2 of the chain. This
# is a WARNING, not a gate: row 3 (/etc/qmcp/birth-egress, written below)
# covers a gateway outside the umbrella, which is exactly why row 3 exists.
echo "==> Checking the gateway's egress placement..."
GW_NETVM="$(qvm-prefs "$GATEWAY" netvm 2>/dev/null || true)"
if [ -z "$GW_NETVM" ]; then
    echo "    NOTE: $GATEWAY has no netvm; birth egress will come from"
    echo "          /etc/qmcp/birth-egress (row 3)."
elif qvm-tags "$GW_NETVM" 2>/dev/null | grep -q '^ai-managed$'; then
    echo "    $GATEWAY -> $GW_NETVM (ai-managed): rows 1-2 resolve normally."
else
    echo "    WARNING: $GATEWAY sits behind '$GW_NETVM', which is NOT ai-managed."
    echo "             Template-based creates will fall through to row 3"
    echo "             (/etc/qmcp/birth-egress). That works, but the inheritance"
    echo "             chain is then a configured constant rather than the"
    echo "             gateway's real egress. See README 'Gateway placement'."
fi
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
echo "==> Installing shared libs..."
for f in $LIBS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0644)"
done

echo "==> Installing the 3 create wrappers..."
for f in $WRAPPERS; do
    sudo install -m 0755 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0755)"
done
echo

# ---------------------------------------------------------------- 4. operator files
# birth-egress is 0644 root:root: the wrappers only READ it, and unlike the
# audit log nothing writes it at runtime, so the group-write dance I-2 needed
# is not wanted here. AI cannot read it — no qmcp.* service reads an arbitrary
# dom0 path and no policy line exposes it.
echo "==> Provisioning /etc/qmcp/birth-egress (row 3 of the inheritance chain)..."
sudo install -d -m 0755 -o root -g root /etc/qmcp
if [ -e /etc/qmcp/birth-egress ]; then
    echo "    exists, left alone -> $(cat /etc/qmcp/birth-egress)"
else
    printf '%s\n' "$EGRESS_QUBE" | sudo tee /etc/qmcp/birth-egress >/dev/null
    sudo chmod 0644 /etc/qmcp/birth-egress
    sudo chown root:root /etc/qmcp/birth-egress
    echo "    created -> $EGRESS_QUBE"
fi
if ! qvm-check "$EGRESS_QUBE" >/dev/null 2>&1; then
    echo "    WARNING: '$EGRESS_QUBE' does not exist. Row 3 will not resolve and"
    echo "             a create that reaches it will REFUSE (by design — better"
    echo "             than the old silent no-network qube)."
elif ! qvm-tags "$EGRESS_QUBE" 2>/dev/null | grep -q '^ai-managed$'; then
    echo "    WARNING: '$EGRESS_QUBE' is not ai-managed. Row 3 will not resolve."
fi

# birth-ceiling is deliberately NOT created: absent means "no clamp", which is
# the shipped default and keeps this stage compat-neutral. Creating it with a
# value is an operator decision, not an install step.
echo "==> /etc/qmcp/birth-ceiling: not created (absent = no clamp, the default)."
echo "    To clamp every AI-created qube to at most exec authority:"
echo "        printf 'ai-exec\\n' | sudo tee /etc/qmcp/birth-ceiling >/dev/null"
echo "        sudo chmod 0644 /etc/qmcp/birth-ceiling"
echo "    The chmod is NOT optional and NOT cosmetic. These wrappers run under"
echo "    qrexec as a non-root dom0 user; 'sudo bash -c \"echo x > file\"' creates"
echo "    the file 0600 root:root (root's umask is 077 there), the wrapper cannot"
echo "    read it, and the ceiling then FAILS CLOSED to untiered — every created"
echo "    qube silently gets no capability at all, with nothing to explain why."
echo "    Measured on this rig, 2026-08-18. The check below catches it."
echo "    Scope note: a ceiling below ai-full also stops a created qube being"
echo "    used as INFRASTRUCTURE — Clone/Spawn/SpawnDisposable/SetProperty all"
echo "    gate on CAP_FULL and are NOT dominated by exec, so an ai-exec child"
echo "    cannot be a DVMT or a clone source even after Stage 3. Right for leaf"
echo "    workload qubes; wrong if the child is meant to be a base."
echo

# Every operator file these wrappers READ must be readable by the non-root
# qrexec user. This is the I-2 lesson (dom0 wrappers run as uid 1000 in group
# qubes) applied to the read side, and it has already bitten once: an
# unreadable file fails closed SILENTLY, so the operator sees a setting that
# appears to do nothing.
echo "==> Checking the operator files are readable by the non-root wrapper user..."
_qmcp_perm_warn=0
for f in tier-default birth-ceiling birth-egress pool-cap private-cap guarded; do
    [ -e "/etc/qmcp/$f" ] || continue
    mode=$(stat -c '%a' "/etc/qmcp/$f")
    case "$mode" in
        *4|*5|*6|*7) echo "    ok        /etc/qmcp/$f ($mode)" ;;
        *) echo "    UNREADABLE /etc/qmcp/$f ($mode) — the wrapper cannot read this."
           echo "               Fix: sudo chmod 0644 /etc/qmcp/$f"
           _qmcp_perm_warn=1 ;;
    esac
done
if [ "$_qmcp_perm_warn" = "1" ]; then
    echo "    WARNING: at least one operator file is unreadable by the wrapper."
    echo "             It will fail closed silently. Fix before relying on it."
fi
echo

# ---------------------------------------------------------------- 5. smoke
echo "==> Smoke: helpers load in dom0 and hold Stage 2's invariants..."
sudo python3 - <<'PY'
import importlib.util, os, tempfile


def load(name):
    s = importlib.util.spec_from_file_location(name, "/etc/qubes-rpc/%s.py" % name)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


tier = load("qmcp_tier")
birth = load("qmcp_birth")
caps = load("qmcp_caps")

UMB, VOCAB = tier.UMBRELLA, tier.QMCP_TIER_TAGS
absent = os.path.join(tempfile.gettempdir(), "qmcp-s2-no-ceiling-zzz")

# compat neutrality: an untiered source still yields an untiered child
assert tier.resolve_birth_tier(tags={UMB}, birth_ceiling_path=absent) is None, \
    "an untiered source would be born tiered — NOT compat-neutral"
# the clamp lowers and never raises
ceil = tempfile.mktemp()
open(ceil, "w").write("ai-exec")
assert tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                               birth_ceiling_path=ceil) == tier.TAG_EXEC
assert tier.resolve_birth_tier(tags={UMB, tier.TAG_EXEC},
                               birth_ceiling_path=ceil) == tier.TAG_EXEC
open(ceil, "w").write("nonsense")
assert tier.resolve_birth_tier(tags={UMB, tier.TAG_FULL},
                               birth_ceiling_path=ceil) is None, \
    "a malformed ceiling must fail CLOSED"
os.remove(ceil)

# a restriction survives the privilege clamp (F-E)
want = birth.expected_tags({UMB, tier.TAG_FULL, birth.TAG_GUARDED},
                           "mcp-control", None, UMB, VOCAB)
assert birth.TAG_GUARDED in want and tier.TAG_FULL not in want, \
    "restriction inheritance or the privilege clamp is broken"

# the real operator file resolves through the chain
name, rule = caps.resolve_birth_egress(
    None, None, is_ai_managed=lambda n: True)
assert rule in ("birth-egress:configured", "birth-egress:unresolved"), rule
print("    helpers OK: compat-neutral, clamp lowers only, malformed fails")
print("                closed, restrictions survive, chain reads the file")
PY
echo

echo "==> Smoke: every installed wrapper still compiles in dom0..."
for f in $WRAPPERS; do
    b=$(basename "$f")
    python3 -c "compile(open('/etc/qubes-rpc/$b').read(), '$b', 'exec')"
done
echo "    3/3 compile in place."
echo

# ---------------------------------------------------------------- 6. cleanup
rm -rf "$STAGE_DIR"

echo "==> Wave 2 Stage 2 deploy complete."
echo
echo "PROVE IT IN DOM0 — the AI seat CANNOT see any of this. Tier tags and"
echo "qmcp-owner_ are outside qmcp_scope.QMCP_TAG_VOCABULARY by design, so"
echo "deploy/test-stage-*.py cannot read a child's tier or owner. Only dom0 can:"
echo
echo "  # from mcp-control, clone an ai-full source, then HERE:"
echo "  qvm-tags <the-clone>          # expect ai-managed + the source's tier"
echo "                                #        + qmcp-owner_<gateway>"
echo "  qvm-prefs <the-clone> netvm   # expect the SOURCE's netvm, not a default"
echo
echo "SCOPE — this stage governs BIRTH egress only. Moving an EXISTING qube"
echo "across egress classes is still allowed at ai-full, and it is the more"
echo "dangerous half: a new qube is empty, an existing one may hold Tor-derived"
echo "data. decide() already says escalation-class DENY for a netvm write, but"
echo "it runs in shadow. Retarget closes when Stage 3 flips enforcement."
echo
echo "Cross-egress is the one to check on a two-egress fleet: a clone of a"
echo "Tor-side qube must come up on Tor even when the gateway is on clearnet."
echo "With one egress class that test passes vacuously (Stage 0.5)."
echo
echo "Rollback: re-install the previous wrappers + helpers, and remove"
echo "/etc/qmcp/birth-egress. Leaving the file is harmless — nothing reads it"
echo "without the Stage 2 wrappers."
