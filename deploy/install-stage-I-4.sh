#!/bin/bash
# install-stage-I-4.sh — run in dom0.
#
# Stage I-4 install: apply the tier ladder to the directly-`@tag:`-scoped
# policy surfaces (design: STAGE-I-DESIGN.md §3.2; STAGE-I-BUILD-PLAN.md §I-4).
#
# Surface delta (SINGLE FILE — /etc/qubes/policy.d/30-mcp-control.policy):
#   - firewall.Get + device-list stay at the ai-managed ro-floor (no change).
#   - firewall.Set/Reload graduate to @tag:ai-net + @tag:ai-full, PLUS a
#     @tag:ai-managed COMPAT BACKSTOP (Option A) that keeps untiered umbrella
#     qubes writable during migration — so the A–F3 regression stays green and
#     the live ai-net-router keeps firewall control on deploy. The backstop is
#     deleted at the I-5 flip (paired with /etc/qmcp/tier-default → "ro").
#   - NEW: qubes.Filecopy * @tag:ai-managed @tag:ai-dump allow — the ai-dump
#     write-only sink (copy-IN only; the Biba valve).
#
# No new RPC script. No new qube. No wrapper change. server.py is untouched
# (the _RING_MIN_TIER annotation landed in I-3). The ONLY change is the policy
# file + a policy-daemon reload.
#
# BEHAVIOUR-NEUTRAL on firewall in compat: while the backstop is present it
# subsumes the net/full lines, so every umbrella qube writes its firewall
# exactly as before. The one new live capability is the ai-dump valve.
#
# Idempotent — re-runnable (install overwrites the policy file). The slot-60.sh
# runner captures the pre-install backup in /var/lib/qmcp-rollback/ and records
# the policy as REPLACED, so `/tmp/run.sh revert` restores the pre-I-4 file.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-4.sh' > /tmp/install-I-4.sh
#   bash /tmp/install-I-4.sh mcp-control ~user/qubes_mcp/public

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

STAGE_DIR="/tmp/qubes-mcp-stage-I-4"
POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"

echo "==> Stage I-4 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage I-4 policy from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $POLICY_REL" \
    > "$STAGE_DIR/stage-I-4.tar"
(cd "$STAGE_DIR" && tar -xf stage-I-4.tar)

if [ ! -s "$STAGE_DIR/$POLICY_REL" ]; then
    echo "FATAL: pulled an empty policy file." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi

echo "==> SHA-256 of pulled policy (record for your audit):"
( cd "$STAGE_DIR" && sha256sum "$POLICY_REL" )
echo

# ---------------------------------------------------------------- 2. VALIDATE before replacing the live file
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

# ---------------------------------------------------------------- 3. install (REPLACE)
echo "==> Installing dom0 policy (REPLACE)..."
sudo install -m 0644 -o root -g root "$STAGED" "$POLICY_DST"
echo "    $POLICY_DST"
echo

# ---------------------------------------------------------------- 4. reload daemon
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

# ---------------------------------------------------------------- 4.5 ai-dump disjointness check
# The ai-dump write-only property holds only for a PURE sink (ai-dump and NOT
# ai-managed). A hybrid (both tags) is fully readable — the inter-copy line
# would copy its contents back out. AI cannot create such a hybrid (no tag
# mutation), but the operator could by hand, so warn (non-fatal) on any.
echo "==> Checking the ai-dump invariant (no ai-managed + ai-dump hybrid)..."
sudo python3 - <<'PY' || true
import qubesadmin
app = qubesadmin.Qubes()
hybrids = [vm.name for vm in app.domains
           if {'ai-managed', 'ai-dump'} <= set(getattr(vm, 'tags', []))]
if hybrids:
    print("    WARNING: these qubes carry BOTH ai-managed and ai-dump — the")
    print("    ai-dump write-only guarantee does NOT hold for them (they are")
    print("    fully readable via the inter-copy line):")
    for n in hybrids:
        print(f"       - {n}")
    print("    Fix: an ai-dump sink must NOT also be ai-managed; remove one tag.")
else:
    print("    OK — no ai-managed + ai-dump hybrid qube.")
PY
echo

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo "==> Stage I-4 deploy complete (policy-only; behaviour-neutral on firewall in compat)."
echo
echo "What changed live: the ai-dump copy-IN valve. Firewall WRITE is unchanged"
echo "in compat (the @tag:ai-managed backstop). Per-tier enforcement activates at"
echo "the I-5 flip when the two backstop lines are deleted."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-I-4.py   # 4 PASS — compat invariance + oracle hygiene"
echo "  .venv/bin/python deploy/test-stage-c.py     # firewall regression: unchanged"
echo "  .venv/bin/python deploy/test-stage-a.py     # regression: unchanged"
echo "Per-tier proof is the slot (slot-60) + offline-validate-I-4.py (100 checks)."
