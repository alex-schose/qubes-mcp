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
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-I-4.sh' > /tmp/install-I-4.sh
#   bash /tmp/install-I-4.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

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
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked — reload by hand." >&2
fi
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
