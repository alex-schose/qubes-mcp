#!/bin/bash
# install-stage-peercopy.sh — run in dom0.
#
# Intra-umbrella qubes.Filecopy by operator dialog (2026-08-19). POLICY-ONLY.
#
# Surface delta — two rule lines in /etc/qubes/policy.d/30-mcp-control.policy,
# both placed between the ai-dump valve and the @tag:ai-managed @anyvm deny:
#
#   qubes.Filecopy  *  @tag:ai-dump     @tag:ai-managed  deny
#   qubes.Filecopy  *  @tag:ai-managed  @tag:ai-managed  ask
#
# WHAT THIS FIXES. G0c replaced the single `@tag:ai-managed -> @tag:ai-managed`
# peer-copy line with the 3x3 tiered mesh and left NO COMPAT BACKSTOP — the only
# tag-scoped surface graduated without one (install-stage-flip.sh deletes exactly
# four, and Filecopy is not among them). The qrexec engine matches tags LITERALLY
# and cannot read /etc/qmcp/tier-default, so an UNTIERED umbrella qube has matched
# none of those lines since G0c, in compat as much as post-flip, and fell to the
# dialog-free deny. An operator working by hand inside a qube they own could not
# move a file out of it and got no prompt explaining why.
#
# The fix restores intra-umbrella peer copy as an ASK, which is tighter than the
# pre-G0c ALLOW and tighter than the backstop G0c should have left. It changes
# exactly the five pairs the mesh missed (elevated->untiered, untiered->elevated,
# untiered->untiered). Everything the mesh already covers keeps its dialog-free
# allow, so nothing that works today starts prompting.
#
# WHY THE TARGET IS @tag:ai-managed AND NOT @anyvm. qrexec cannot tell the
# operator apart from the agent, so an ask is a control only because AI cannot
# click zenity — a human-attention control, not a mechanical one. What a rule CAN
# bound is what the agent learns by asking. With @anyvm the agent names any qube
# on the host and observes whether a dialog appeared: an existence oracle over
# every out-of-scope qube, the class F-1 closed on the create paths. With
# @tag:ai-managed the target set is exactly what qmcp.ListAIManagedQubes already
# returns, so naming one discloses nothing.
#
# WHY THE ACCOMPANYING DENY. Introducing an ask at all creates a way back through
# the Biba valve: a MISCONFIGURED hybrid (ai-managed AND ai-dump — the operator
# invariant the I-4 installer warns about) would match the new ask as a SOURCE and
# could be dialogued into the fleet. Denying an ai-dump SOURCE into the umbrella
# closes that, and closes more besides — a PURE sink copying back in previously
# matched no rule here and landed on the Qubes system-default ask, finding [8]'s
# fallthrough hazard in the one direction G0c did not cover. It deliberately does
# NOT touch ai-dump -> out-of-umbrella, which is how an operator DRAINS a buffer.
#
# LEAVING THE UMBRELLA IS UNCHANGED and still a dialog-free deny. For the
# vault-handoff case use the ai-dump sink that already exists as the buffer:
#
#     ai-owned qube  --allow-->  buffer tagged {ai-dump}  --system ask-->  vault
#
# AI can push into the buffer and cannot read it back (no umbrella => no read, no
# exec, no enumeration), and the operator drains it by hand. No new tag, no new
# mechanism.
#
# A malformed policy breaks ALL of qrexec, so the staged file is VALIDATED before
# it touches /etc/qubes/policy.d/ and the live file is backed up first.
#
# Idempotent — re-runnable. Re-running replaces the policy with the same content.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-peercopy.sh' > /tmp/install-peercopy.sh
#   bash /tmp/install-peercopy.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-peercopy"
POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
BACKUP_DIR="/var/lib/qmcp-rollback"

echo "==> Intra-umbrella Filecopy deploy starting (policy-only)"
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
if [ ! -s "$STAGED" ]; then
    echo "FATAL: pulled an empty policy file." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "==> SHA-256 of the pulled policy (record for your audit):"
( cd "$STAGE_DIR" && sha256sum "$POLICY_REL" | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 2. validate BEFORE replacing
echo "==> Validating staged policy syntax (before it touches the live file)..."
if python3 - "$STAGED" <<'PY'
import sys
path = sys.argv[1]
try:
    from qrexec.policy.parser import StringPolicy  # type: ignore
    _s = open(path, encoding='utf-8').read()
    try:
        StringPolicy(policy={'__main__': _s})
    except Exception as _e1:
        try:
            StringPolicy(policy={'30-mcp-control': _s})
        except Exception:
            raise _e1
    print("    qrexec parser: policy parses clean.")
    sys.exit(0)
except ImportError:
    pass
except Exception as e:
    print(f"FATAL: qrexec parser rejected the policy: {e}", file=sys.stderr)
    sys.exit(1)
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
print("    structural lint: all rule lines well-formed.")
PY
then
    echo "    policy validation OK."
else
    echo "FATAL: staged policy failed validation — NOT installing." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi

# The behavioural gate: resolve the matrix off the STAGED file and refuse if the
# two rules are absent, mis-ordered, or have drifted in scope. Structure over
# vocabulary (the 3a lesson) and behaviour over structure where a decision exists
# (the 3b lesson) — here the artifact is a rule table, so resolve it.
echo "==> Resolving the Filecopy matrix off the staged policy..."
if ! python3 - "$STAGED" <<'PY'
import sys

rules = []
for n, raw in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    s = raw.strip()
    if not s or s.startswith("#"):
        continue
    f = s.split()
    if len(f) >= 5 and f[0] == "qubes.Filecopy":
        rules.append((n, f[2], f[3], f[4]))


def m(sel, tags):
    if sel == "@anyvm":
        return True
    if sel.startswith("@tag:"):
        return sel[5:] in tags
    return False


def act(stags, ttags):
    for n, s_, t_, a in rules:
        if m(s_, stags) and m(t_, ttags):
            return a, n
    return "SYSTEM-DEFAULT", None


U = {"ai-managed"}
FULL, EXEC, RO = U | {"ai-full"}, U | {"ai-exec"}, U
DUMP, HYBRID, OUT = {"ai-dump"}, U | {"ai-dump"}, set()

fail = []
# What must NOT change.
for label, s_, t_ in (("full->full", FULL, FULL), ("exec->exec", EXEC, EXEC),
                      ("full->exec", FULL, EXEC)):
    if act(s_, t_)[0] != "allow":
        fail.append(f"the tiered mesh no longer allows {label} — this change must "
                    f"not make working copies start prompting")
for label, s_ in (("full", FULL), ("exec", EXEC), ("ro", RO)):
    if act(s_, DUMP)[0] != "allow":
        fail.append(f"the ai-dump valve is closed for a {label} source")
for label, s_ in (("full", FULL), ("exec", EXEC), ("ro", RO)):
    if act(s_, OUT)[0] != "deny":
        fail.append(f"{label} -> OUT-of-umbrella is no longer a dialog-free deny — "
                    f"leaving the umbrella is not what this change touches")
# What must change.
for label, s_, t_ in (("exec->ro", EXEC, RO), ("full->ro", FULL, RO),
                      ("ro->ro", RO, RO), ("ro->exec", RO, EXEC)):
    a, _ = act(s_, t_)
    if a != "ask":
        fail.append(f"{label} resolves {a!r}, expected 'ask' — the operator "
                    f"dialog this change exists for is not there")
# The valve must survive the ask.
for label, s_ in (("hybrid", HYBRID), ("pure sink", DUMP)):
    for tl, t_ in (("exec", EXEC), ("ro", RO)):
        a, _ = act(s_, t_)
        if a != "deny":
            fail.append(f"{label} -> {tl} resolves {a!r}, expected 'deny' — an "
                        f"ai-dump source must never be dialogued back into the fleet")
# ...but a buffer must still be drainable by hand.
if act(DUMP, OUT)[0] == "deny":
    fail.append("sink -> OUT-of-umbrella is denied; the operator cannot drain the "
                "buffer to a vault, which is the whole handoff pattern")

for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: the staged policy does not resolve as this change requires." >&2
    echo "       The live policy has NOT been touched." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "    mesh + valve + umbrella boundary unchanged; the five missed pairs now ask."
echo

# ---------------------------------------------------------------- 3. back up, then install
TS="$(date -u +%Y%m%dT%H%M%SZ)"
sudo mkdir -p "$BACKUP_DIR/$TS"
if [ -f "$POLICY_DST" ]; then
    sudo cp -a "$POLICY_DST" "$BACKUP_DIR/$TS/30-mcp-control.policy"
    echo "==> Backed up the live policy to $BACKUP_DIR/$TS/"
    echo "    revert: sudo install -m 0644 -o root -g root \\"
    echo "            $BACKUP_DIR/$TS/30-mcp-control.policy $POLICY_DST"
else
    echo "==> No live policy present to back up (first install)."
fi
echo

echo "==> Installing dom0 policy (REPLACE)..."
sudo install -m 0644 -o root -g root "$STAGED" "$POLICY_DST"
echo "    $POLICY_DST"
echo

# ---------------------------------------------------------------- 4. reload the daemon
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

# ---------------------------------------------------------------- 5. post-assert on the LIVE file
echo "==> Re-resolving the matrix off the INSTALLED policy..."
if ! sudo python3 - "$POLICY_DST" <<'PY'
import sys
rules = []
for n, raw in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    s = raw.strip()
    if s and not s.startswith("#"):
        f = s.split()
        if len(f) >= 5 and f[0] == "qubes.Filecopy":
            rules.append((n, f[2], f[3], f[4]))


def m(sel, tags):
    return True if sel == "@anyvm" else (sel[5:] in tags if sel.startswith("@tag:") else False)


def act(s_, t_):
    for n, a, b, ac in rules:
        if m(a, s_) and m(b, t_):
            return ac
    return "SYSTEM-DEFAULT"


U = {"ai-managed"}
ok = (act(U, U) == "ask"
      and act(U | {"ai-full"}, U | {"ai-full"}) == "allow"
      and act(U | {"ai-full"}, set()) == "deny"
      and act({"ai-dump"}, U | {"ai-exec"}) == "deny"
      and act(U | {"ai-full"}, {"ai-dump"}) == "allow")
print("    live policy: ro->ro=%s  mesh=%s  out=%s  sink-back=%s  valve=%s"
      % (act(U, U), act(U | {"ai-full"}, U | {"ai-full"}),
         act(U | {"ai-full"}, set()), act({"ai-dump"}, U | {"ai-exec"}),
         act(U | {"ai-full"}, {"ai-dump"})))
sys.exit(0 if ok else 1)
PY
then
    echo "FATAL: the INSTALLED policy does not resolve as expected." >&2
    echo "       Restore the backup printed above before continuing." >&2
    exit 1
fi
echo

rm -rf "$STAGE_DIR"

cat <<'EOF'
==> Installed.

    You can now hand-copy between your ai-managed qubes: a normal Qubes copy
    dialog appears, you approve it, the file moves. Pairs already covered by the
    tiered mesh keep copying with no dialog at all.

    Leaving the umbrella is UNCHANGED and still refused. For that, use an
    ai-dump buffer, which already exists and needs no new rule:

        1. make a buffer qube and tag it   qvm-tags <buffer> add ai-dump
           (NEVER also ai-managed — that hybrid is what the new deny guards)
        2. copy into it from any ai-managed qube            (allowed, no dialog)
        3. drain it to the vault by hand from the buffer    (system dialog)

    The buffer is write-only from AI's side by construction: it carries no
    umbrella, so there is no read surface, no exec service and no enumeration
    into it. AI can put things in; only you take them out.

    Revert: restore the backup printed above and restart the policy daemon.
EOF
