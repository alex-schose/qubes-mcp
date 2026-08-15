#!/bin/bash
# install-stage-I-5.sh — run in dom0.
#
# Stage I-5 install: tier the @adminvm WRAPPER surfaces + graduate the EXEC
# policy surfaces to the tier ladder (design: STAGE-I-DESIGN.md §3.2;
# STAGE-I-BUILD-PLAN.md §I-5).
#
# Surface delta:
#   - 8 dom0 wrappers gain a fail-closed CAP_FULL gate via the sibling
#     qmcp_tier helper (lifecycle / property-set / clone / spawn / feature /
#     attach / detach):
#         qmcp.LifecycleAIManaged    qmcp.SetPropertyAIManaged
#         qmcp.CloneAIManagedQube    qmcp.SpawnAIManagedQube
#         qmcp.SetFeatureAIManaged   qmcp.AttachDeviceAIManaged
#         qmcp.DetachDeviceAIManaged qmcp.SpawnDisposableAIManaged
#   - /etc/qubes/policy.d/30-mcp-control.policy graduates the EXEC surfaces
#     (qmcp.RunInAIManaged + qmcp.CopyToAIManaged) to @tag:ai-exec/ai-net/
#     ai-full + a @tag:ai-managed COMPAT BACKSTOP each — mirroring I-4's
#     firewall pattern. There are now FOUR compat backstops (firewall.Set,
#     firewall.Reload, RunInAIManaged, CopyToAIManaged).
#
# qmcp_tier.py is NOT redeployed here — slot-52 (Stage I-3) deployed it
# PERSISTENTLY at /etc/qubes-rpc/qmcp_tier.py. This installer VERIFIES it is
# present and ABORTS if absent (the wrapper gate fails closed without it).
#
# BEHAVIOUR-NEUTRAL in compat: the wrapper gate's fail-closed default is
# overridden by qmcp_tier's compat resolution (untiered ai-managed = ai-full),
# and the four policy backstops keep exec open — so every A–F3 surface behaves
# exactly as before. The FLIP (delete the four backstops + write "ro" to
# /etc/qmcp/tier-default) is a SEPARATE operator step (slot-63-flip.sh), run
# AFTER the fleet is tiered. This installer does NOT flip.
#
# MACHINE-ENFORCED ai-dump disjointness: I-4 only WARNED on an ai-managed +
# ai-dump hybrid; I-5 REFUSES the install (exit non-zero) if any qube carries
# BOTH tags — the write-only sink guarantee is void for a hybrid and the fleet
# must be clean before least-privilege enforcement lands.
#
# Idempotent — re-runnable (install overwrites the wrappers + policy). The
# slot-62.sh runner captures the pre-install backups in /var/lib/qmcp-rollback/
# and records each of the 9 files as REPLACED (they all pre-exist in dom0 from
# prior stages — I-5 adds NO new dom0 file), so `/tmp/run.sh revert` restores
# the pre-I-5 wrappers + policy.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-5.sh' > /tmp/install-I-5.sh
#   bash /tmp/install-I-5.sh mcp-control ~user/qubes_mcp/public

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

STAGE_DIR="/tmp/qubes-mcp-stage-I-5"
POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
RPC_DST="/etc/qubes-rpc"
TIER_LIB="$RPC_DST/qmcp_tier.py"

# The 8 wrappers tiered in I-5 (each gained a CAP_FULL gate via qmcp_tier).
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

echo "==> Stage I-5 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 0. qmcp_tier dependency (slot-52)
# The wrapper gate is fail-closed: without qmcp_tier.py present every gated
# surface DENIES. So a missing helper is not a soft warning — it is an abort.
echo "==> Verifying the qmcp_tier dependency (deployed persistently by slot-52)..."
if [ ! -s "$TIER_LIB" ]; then
    echo "FATAL: $TIER_LIB is absent or empty." >&2
    echo "       I-5's wrapper gate fails closed without it — every CAP_FULL" >&2
    echo "       surface would deny. Run the Stage I-3 deploy (slot-52) first." >&2
    exit 1
fi
echo "    $TIER_LIB present:"
sha256sum "$TIER_LIB" | sed 's/^/      /'
echo

# ---------------------------------------------------------------- 0.5 ai-dump disjointness — REFUSE on any hybrid
# I-4 WARNED; I-5 REFUSES. A qube carrying BOTH ai-managed and ai-dump voids the
# write-only sink guarantee (the inter-ai-managed copy line reads its contents
# back out). AI cannot create such a hybrid (no tag mutation) — this is an
# operator-misconfig guard that MUST be clean before least-privilege lands.
echo "==> Enforcing the ai-dump invariant (NO ai-managed + ai-dump hybrid)..."
if ! sudo python3 - <<'PY'
import sys
import qubesadmin
app = qubesadmin.Qubes()
hybrids = [vm.name for vm in app.domains
           if {'ai-managed', 'ai-dump'} <= set(getattr(vm, 'tags', []))]
if hybrids:
    print("FATAL: these qubes carry BOTH ai-managed and ai-dump — the ai-dump",
          file=sys.stderr)
    print("       write-only guarantee does NOT hold for them. I-5 REFUSES the",
          file=sys.stderr)
    print("       install until the fleet is clean. Remove one tag from each:",
          file=sys.stderr)
    for n in hybrids:
        print(f"          qvm-tags {n} del ai-dump   # (or del ai-managed)",
              file=sys.stderr)
    sys.exit(1)
print("    OK — no ai-managed + ai-dump hybrid qube.")
PY
then
    echo "FATAL: ai-dump disjointness check failed — NOT installing." >&2
    exit 1
fi
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage I-5 wrappers + policy from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

PULL_LIST="$POLICY_REL"
for w in "${WRAPPERS[@]}"; do
    PULL_LIST="$PULL_LIST dom0-rpc/$w"
done

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $PULL_LIST" \
    > "$STAGE_DIR/stage-I-5.tar"
(cd "$STAGE_DIR" && tar -xf stage-I-5.tar)

if [ ! -s "$STAGE_DIR/$POLICY_REL" ]; then
    echo "FATAL: pulled an empty policy file." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
for w in "${WRAPPERS[@]}"; do
    if [ ! -s "$STAGE_DIR/dom0-rpc/$w" ]; then
        echo "FATAL: pulled an empty wrapper: $w" >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
done

echo "==> SHA-256 of pulled artifacts (record for your audit):"
( cd "$STAGE_DIR" && sha256sum "$POLICY_REL" )
for w in "${WRAPPERS[@]}"; do
    ( cd "$STAGE_DIR" && sha256sum "dom0-rpc/$w" )
done
echo

# ---------------------------------------------------------------- 2. compile-gate the wrappers (refuse a broken deploy)
# The wrappers have no .py extension, so use SourceFileLoader. A syntax error in
# a CAP_FULL-gated wrapper would brick that surface — catch it before touching
# dom0 (the qmcp_tier compile-gate is slot-52's job; we only verify presence).
echo "==> Compile-checking staged wrappers (before install)..."
for w in "${WRAPPERS[@]}"; do
    if ! python3 - "$STAGE_DIR/dom0-rpc/$w" <<'PY'
import sys
import importlib.machinery
import importlib.util
path = sys.argv[1]
loader = importlib.machinery.SourceFileLoader("staged_wrapper", path)
src = loader.get_source("staged_wrapper")
compile(src, path, "exec")
PY
    then
        echo "FATAL: staged wrapper failed to compile: $w — NOT installing." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
done
echo "    all ${#WRAPPERS[@]} wrappers compile clean."
echo

# ---------------------------------------------------------------- 3. VALIDATE the policy before replacing the live file
# A malformed policy can break ALL qrexec, so validate the staged file BEFORE
# it touches /etc/qubes/policy.d/. Prefer the authoritative qrexec parser; fall
# back to a structural lint (every non-comment line has >=5 fields + a valid
# action — this is what bit us if an inline comment ever sneaks onto a rule).
echo "==> Validating staged policy syntax (before install)..."
STAGED="$STAGE_DIR/$POLICY_REL"
if python3 - "$STAGED" <<'PY'
import sys
path = sys.argv[1]
try:
    # Authoritative: the qrexec policy parser, if present in dom0.
    from qrexec.policy.parser import StringPolicy  # type: ignore
    _s = open(path, encoding='utf-8').read()
    try:
        # Qubes 4.3+ qrexec requires a '__main__' entry point in the dict.
        StringPolicy(policy={'__main__': _s})
    except Exception as _e1:
        try:
            # Older qrexec accepted a plain named key.
            StringPolicy(policy={'30-mcp-control': _s})
        except Exception:
            raise _e1  # report the REAL parse error, not the key-shape error
    print("    qrexec parser: policy parses clean.")
    sys.exit(0)
except ImportError:
    pass
except Exception as e:  # parser present but rejected the file
    print(f"FATAL: qrexec parser rejected the policy: {e}", file=sys.stderr)
    sys.exit(1)
# Fallback structural lint.
bad = []
for i, line in enumerate(open(path, encoding='utf-8'), 1):
    s = line.strip()
    if not s or s.startswith('#'):
        continue
    toks = s.split()
    if len(toks) < 5 or toks[4] not in ('allow', 'deny', 'ask'):
        bad.append((i, s))
if bad:
    for i, s in bad:
        print(f"FATAL: malformed rule line {i}: {s!r}", file=sys.stderr)
    sys.exit(1)
print("    structural lint: all rule lines well-formed (>=5 fields, valid action).")
PY
then
    echo "    policy validation OK."
else
    echo "FATAL: staged policy failed validation — NOT installing." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo

# ---------------------------------------------------------------- 4. install (REPLACE) the wrappers
# dom0 qrexec wrappers run as a NON-root qubes-group user — but install scripts
# here run with sudo via the slot, exactly like install-stage-I-4. The wrappers
# are executable (0755 root:root) like every other /etc/qubes-rpc/qmcp.* script;
# qmcp_tier.py (read-only, 0644) is untouched.
echo "==> Installing dom0 wrappers (REPLACE)..."
for w in "${WRAPPERS[@]}"; do
    sudo install -m 0755 -o root -g root "$STAGE_DIR/dom0-rpc/$w" "$RPC_DST/$w"
    echo "    $RPC_DST/$w"
done
echo

# ---------------------------------------------------------------- 5. install (REPLACE) the policy
echo "==> Installing dom0 policy (REPLACE)..."
sudo install -m 0644 -o root -g root "$STAGED" "$POLICY_DST"
echo "    $POLICY_DST"
echo

# ---------------------------------------------------------------- 6. reload daemon
echo "==> Reloading qrexec policy daemon..."
# Reload the policy daemon — reset-failed FIRST, then POST-ASSERT it came back.
# Load-bearing: many installers restart this daemon, and the 6th restart inside
# systemd's 10s StartLimitIntervalSec trips StartLimitBurst, leaving the unit
# `failed`. qrexec then falls back to spawning qrexec-policy-exec per call, so
# nothing announces the degradation: VM->dom0 call latency rises roughly 7x,
# every call forks a dom0 python interpreter (~190 concurrent at 200 offered
# calls), and inter-qube clipboard paste stops working entirely.
# Restarts 1-5 return 0 and leave the unit ACTIVE; only the failing one returns
# rc=1 — these installers missed it because they never checked $?, not because
# systemd was silent. Asserting is-active is still the better check: it also
# catches the daemon dying for any reason other than the start limit.
sudo systemctl reset-failed qubes-qrexec-policy-daemon qubes-policy-daemon 2>/dev/null || true
_qmcp_unit=""
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    _qmcp_unit=qubes-qrexec-policy-daemon
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    _qmcp_unit=qubes-policy-daemon
fi
if [ -z "$_qmcp_unit" ]; then
    echo "    ERROR: neither policy daemon name could be restarted." >&2
    exit 1
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(systemctl is-active "$_qmcp_unit")" = "active" ] && break
    sleep 1
done
if [ "$(systemctl is-active "$_qmcp_unit")" != "active" ]; then
    echo "    ERROR: $_qmcp_unit did not return to active after restart." >&2
    echo "           qrexec policy evaluation is DEGRADED. Recover with:" >&2
    echo "             sudo systemctl reset-failed $_qmcp_unit" >&2
    echo "             sudo systemctl start $_qmcp_unit" >&2
    exit 1
fi
echo "    Restarted $_qmcp_unit (verified active)."
echo

# ---------------------------------------------------------------- 7. cleanup
rm -rf "$STAGE_DIR"

echo "==> Stage I-5 deploy complete (wrapper gates + EXEC tiers; behaviour-neutral in compat)."
echo
echo "What changed live: NOTHING observable in compat — the wrapper gate resolves"
echo "every untiered umbrella qube to ai-full and the four policy backstops keep"
echo "exec open. Per-tier enforcement activates at the FLIP (slot-63-flip.sh):"
echo "delete the four @tag:ai-managed backstops + write 'ro' to /etc/qmcp/tier-default."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-I-5.py   # AI-side: compat invariance + opaque tier refusals"
echo "  .venv/bin/python deploy/test-stage-a.py     # regression: unchanged"
echo "  .venv/bin/python deploy/test-stage-d.py     # lifecycle/clone regression: unchanged"
echo "Per-tier proof is the slot (slot-62) + the offline wrapper-gate suite."
