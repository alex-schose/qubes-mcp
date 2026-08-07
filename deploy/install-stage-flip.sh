#!/bin/bash
# install-stage-flip.sh — run in dom0. THE LEAST-PRIVILEGE FLIP (end of Stage I-5).
#
# ============================================================================
#  RUN ONLY AFTER THE REAL FLEET IS TIERED. Operationally irreversible-ish.
# ============================================================================
# This is the separate, COUPLED change that drops the trust boundary from
# "compat" (every umbrella qube = ai-full) to LEAST PRIVILEGE (each qube gets
# only its operator-assigned tier). Once it lands, an UNTIERED ai-managed qube
# loses exec + lifecycle/property/clone/spawn/feature/attach/detach (it drops to
# the ai-ro read floor). Run this ONLY after you have assigned ai-exec / ai-net /
# ai-full to the qubes that need them (e.g. ai-net-router keeps firewall control
# via ai-net or ai-full; an exec workhorse needs at least ai-exec) — otherwise
# every working qube becomes read-only and AI workflows break.
#
# WHY ONE COUPLED CHANGE (design: CLAUDE.md "A policy-layer surface cannot honour
# a helper's compat default"): the policy-scoped surfaces (firewall + exec) and
# the wrapper surfaces (lifecycle/property/...) flip via DIFFERENT mechanisms —
# deleting policy backstops vs. the helper's tier-default flag. Doing only one
# leaves the surfaces incoherent (least-privilege backwards). So this installer
# does BOTH as one transactional unit and ROLLS BACK if either half fails:
#   (a) delete the FOUR @tag:ai-managed compat-backstop rule lines from the live
#       policy (firewall.Set, firewall.Reload from I-4 + RunInAIManaged,
#       CopyToAIManaged from I-5) via a python rewrite (NOT an inline-comment
#       edit), with a hard guard that EXACTLY four were removed, VALIDATED before
#       it replaces the live file.
#   (b) write "ro" to /etc/qmcp/tier-default (644 root:root; the helper re-reads
#       it per call).
# Then it POST-ASSERTS both halves landed (0 backstops remain, the tiered lines
# survived, tier-default == ro) and rolls back to coherent compat if not.
#
# Reversible via deploy/uninstall-stage-flip.sh (restores this run's backup) or
# the slot-runner '/tmp/run.sh revert' if you deployed through it.
#
# Run from dom0 (no source qube needed — it edits the live dom0 policy):
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-flip.sh' > /tmp/install-flip.sh
#   bash /tmp/install-flip.sh

set -euo pipefail

POLICY="/etc/qubes/policy.d/30-mcp-control.policy"
FLAG="/etc/qmcp/tier-default"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BK_DIR="/var/lib/qmcp-rollback/flip-$TS"     # OUTSIDE policy.d/ (loader hygiene)
BK_LATEST="/var/lib/qmcp-rollback/flip-latest"

reload_daemon() {
    sudo systemctl reset-failed qubes-qrexec-policy-daemon qubes-policy-daemon 2>/dev/null || true
    sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null \
        || sudo systemctl restart qubes-policy-daemon 2>/dev/null \
        || echo "    WARNING: neither policy daemon name worked — reload by hand." >&2
}

# Restore this run's pre-flip state (policy + flag) and reload. Called on any
# failure after the live files may have been touched, so the fleet never lingers
# in a split-brain.
rollback() {
    echo "==> ROLLING BACK to pre-flip (coherent compat)..." >&2
    sudo cp -a "$BK_DIR/30-mcp-control.policy" "$POLICY"
    if [ -e "$BK_DIR/tier-default" ]; then
        sudo cp -a "$BK_DIR/tier-default" "$FLAG"
    else
        sudo rm -f "$FLAG"      # flag did not pre-exist → compat is "absent"
    fi
    reload_daemon
    echo "    rolled back: backstops restored, tier-default reset." >&2
}

echo "==> Stage I-5 LEAST-PRIVILEGE FLIP"
[ -f "$POLICY" ] || { echo "FATAL: $POLICY not found — deploy I-4/I-5 first." >&2; exit 1; }

# ----------------------------------------------------------------- 0. backup (outside policy.d)
sudo mkdir -p "$BK_DIR"
sudo cp -a "$POLICY" "$BK_DIR/30-mcp-control.policy"
if [ -e "$FLAG" ]; then sudo cp -a "$FLAG" "$BK_DIR/tier-default"; fi
sudo rm -rf "$BK_LATEST"; sudo cp -a "$BK_DIR" "$BK_LATEST"   # pointer for uninstall-stage-flip.sh
echo "    backed up policy + flag to $BK_DIR (and $BK_LATEST)"

# ----------------------------------------------------------------- 1. rewrite: delete EXACTLY the four backstops
STAGED="/tmp/qmcp-flip-policy.$$"
if ! sudo python3 - "$POLICY" "$STAGED" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src, encoding="utf-8").read().splitlines(keepends=True)
# The four flipped surfaces' @tag:ai-managed backstop rule shapes (anchored,
# whitespace-tolerant). NOT the ro-floor @tag:ai-managed lines (firewall.Get,
# device.*.List, inter-ai-managed Filecopy) — those are method-specific misses.
RULE = [
    re.compile(r'^admin\.vm\.firewall\.Set\s+\*\s+mcp-control\s+@tag:ai-managed\s+allow\b'),
    re.compile(r'^admin\.vm\.firewall\.Reload\s+\*\s+mcp-control\s+@tag:ai-managed\s+allow\b'),
    re.compile(r'^qmcp\.RunInAIManaged\s+\*\s+mcp-control\s+@tag:ai-managed\s+allow\b'),
    re.compile(r'^qmcp\.CopyToAIManaged\s+\*\s+mcp-control\s+@tag:ai-managed\s+allow\b'),
]
COMMENT = re.compile(r'^# COMPAT backstop \((firewall\.Set|firewall\.Reload|RunInAIManaged|CopyToAIManaged)\)')
out, removed_rules, removed_comments = [], 0, 0
for ln in lines:
    if COMMENT.match(ln):
        removed_comments += 1
        continue
    if any(rx.match(ln) for rx in RULE):
        removed_rules += 1
        continue
    out.append(ln)
open(dst, "w", encoding="utf-8").write("".join(out))
if removed_rules != 4:
    print(f"FATAL: expected to remove 4 backstop rule lines, removed {removed_rules}", file=sys.stderr)
    sys.exit(1)
print(f"    removed {removed_rules} backstop rule lines + {removed_comments} backstop comment lines")
PY
then
    echo "FATAL: backstop rewrite did not remove exactly 4 rules — aborting (live policy untouched)." >&2
    sudo rm -f "$STAGED"; exit 1
fi

# ----------------------------------------------------------------- 2. VALIDATE before replacing the live file
if python3 - "$STAGED" <<'PY'
import sys
path = sys.argv[1]
try:
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
    print("    qrexec parser: flipped policy parses clean.")
    sys.exit(0)
except ImportError:
    pass
except Exception as e:
    print(f"FATAL: qrexec parser rejected the flipped policy: {e}", file=sys.stderr)
    sys.exit(1)
bad = []
for i, line in enumerate(open(path, encoding='utf-8'), 1):
    s = line.strip()
    if not s or s.startswith('#'):
        continue
    t = s.split()
    if len(t) < 5 or t[4] not in ('allow', 'deny', 'ask'):
        bad.append((i, s))
if bad:
    for i, s in bad:
        print(f"FATAL: malformed rule line {i}: {s!r}", file=sys.stderr)
    sys.exit(1)
print("    structural lint: flipped policy well-formed.")
PY
then echo "    flipped policy validates."
else echo "FATAL: flipped policy failed validation — aborting (live policy untouched)." >&2; sudo rm -f "$STAGED"; exit 1
fi

# ----------------------------------------------------------------- 3. COUPLED apply (rollback on any failure)
echo "==> Applying the coupled flip (policy + tier-default)..."
if ! sudo install -m 0644 -o root -g root "$STAGED" "$POLICY"; then
    echo "FATAL: policy install failed." >&2; rollback; sudo rm -f "$STAGED"; exit 1
fi
sudo rm -f "$STAGED"

sudo mkdir -p "$(dirname "$FLAG")"
if ! printf 'ro\n' | sudo tee "$FLAG" >/dev/null; then
    echo "FATAL: tier-default write failed — rolling back the policy half." >&2; rollback; exit 1
fi
sudo chmod 0644 "$FLAG"; sudo chown root:root "$FLAG"
reload_daemon
echo "    policy flipped + tier-default=ro written + daemon reloaded."

# ----------------------------------------------------------------- 4. POST-ASSERT both halves (rollback if wrong)
echo "==> Post-asserting the end state..."
remain="$(grep -cE '^(admin\.vm\.firewall\.(Set|Reload)|qmcp\.(RunInAIManaged|CopyToAIManaged))[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@tag:ai-managed[[:space:]]+allow' "$POLICY" || true)"
tiered_ok=true
for rx in \
    '^admin\.vm\.firewall\.Set[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@tag:ai-net[[:space:]]+allow' \
    '^admin\.vm\.firewall\.Reload[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@tag:ai-net[[:space:]]+allow' \
    '^qmcp\.RunInAIManaged[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@tag:ai-exec[[:space:]]+allow' \
    '^qmcp\.CopyToAIManaged[[:space:]]+\*[[:space:]]+mcp-control[[:space:]]+@tag:ai-exec[[:space:]]+allow' ; do
    grep -qE "$rx" "$POLICY" || tiered_ok=false
done
flagval="$(sudo awk 'NR==1{print $1}' "$FLAG" 2>/dev/null || true)"

if [ "$remain" -ne 0 ] || [ "$tiered_ok" != true ] || [ "$flagval" != "ro" ]; then
    echo "FATAL: post-assert failed (backstops_remaining=$remain tiered_survived=$tiered_ok flag=$flagval)." >&2
    rollback
    exit 1
fi
echo "    OK: 0 backstops remain, the tiered (ai-net/ai-exec/ai-full) lines survived, tier-default=ro."

echo
echo "==> THE FLIP IS LIVE — least privilege is enforced fleet-wide."
echo "    Untiered ai-managed qubes are read-only; grant ai-exec/ai-net/ai-full per qube as needed."
echo "    Verify from mcp-control:  .venv/bin/python deploy/test-stage-I-5.py"
echo "    Revert:  bash deploy/uninstall-stage-flip.sh   (or '/tmp/run.sh revert' if slot-deployed)"
