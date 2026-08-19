#!/bin/bash
# install-stage-3c.sh — run in dom0.
#
# Wave 2 Stage 3c install: the enforcement flip, SHIPPED INERT.
#
# Surface delta:
#   - 8 REWRITTEN wrappers  /etc/qubes-rpc/qmcp.{Lifecycle,SetProperty,SetFeature,
#                           Clone,Spawn,SpawnDisposable,Attach,Detach}*
#                           Stage 1's `_shadow_note` — which computed the kernel's
#                           verdict and threw it away — becomes `_gate`, which acts
#                           on it through qmcp_enforce.effective_verdict().
#                           qmcp.LifecycleAIManaged additionally routes `remove`
#                           through the Stage 3a tombstone WHEN ENFORCING.
#   - 1 REWRITTEN lib       /etc/qubes-rpc/qmcp_caps.py
#                           the `netvm = null` carve-out (see below), and the
#                           removal of an unreachable branch.
#
# No operator file is created. No policy change, so no qrexec daemon restart
# (F1). No systemd unit. No new AI-callable RPC service.
#
# INERT ON INSTALL, and that is a property this installer CHECKS rather than
# claims: `/etc/qmcp/enforce-mode` absent means shadow, shadow means every
# wrapper returns its own verdict unchanged, and under shadow the tombstone
# path is not reachable at all. So a fresh install is byte-neutral and the
# revert is one write. If the flag already exists when this runs, the install
# would arm enforcement in the same breath as landing the code that reads it —
# gate 5 refuses that unless the operator says otherwise.
#
# WHY THE CARVE-OUT IS PART OF THIS STAGE AND NOT A SEPARATE FIX.
# `qmcp_caps.ESCALATION_PROPS` modelled every `netvm` write as escalation-class.
# That was right while the kernel only logged, and wrong the moment it decides:
# both halves of §3.4 deliberately permit `netvm = null` (de-escalation cannot
# leak), and the rig's own shadow log carries such writes with ok:true AFTER the
# F-2 retarget guard landed. Arming EITHER strict or enforce against the old
# model would therefore have deleted a live capability silently — not a security
# regression, but a change nobody enumerated. Shipping the fix in the stage that
# arms the kernel is the only ordering where it cannot be missed.
#
# Idempotent — re-runnable. Install overwrites; nothing is enabled or started.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-3c.sh' > /tmp/install-3c.sh
#   bash /tmp/install-3c.sh mcp-control ~user/qubes_mcp/public
#
# Environment:
#   QMCP_ALLOW_ARMED_INSTALL=1   proceed even though /etc/qmcp/enforce-mode
#                                already exists (gate 5). You are then installing
#                                the code and arming it in one step, with no
#                                invariance measurement in between.

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-3c"

WRAPPERS="dom0-rpc/qmcp.LifecycleAIManaged
dom0-rpc/qmcp.SetPropertyAIManaged
dom0-rpc/qmcp.SetFeatureAIManaged
dom0-rpc/qmcp.CloneAIManagedQube
dom0-rpc/qmcp.SpawnAIManagedQube
dom0-rpc/qmcp.SpawnDisposableAIManaged
dom0-rpc/qmcp.AttachDeviceAIManaged
dom0-rpc/qmcp.DetachDeviceAIManaged"
LIBS="dom0-rpc/qmcp_caps.py"
ALL="$WRAPPERS $LIBS"

#: Every helper a 3c wrapper loads at runtime. A wrapper installed while one of
#: these is missing is the F9 split-brain family — and for `qmcp_enforce.py`
#: specifically it is the exact partial deploy the wrapper's `_enforce_mode`
#: branch exists to survive. Surviving it is not a reason to create it.
PREREQ_LIBS="qmcp_caps.py qmcp_enforce.py qmcp_tombstone.py qmcp_birth.py
qmcp_tier.py qmcp_audit.py qmcp_consent.py qmcp_budget.py qmcp_scope.py"

echo "==> Wave 2 Stage 3c deploy starting (enforcement flip, INERT on install)"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage 3c files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Collapse the file list to one line before it becomes a REMOTE command (F-L):
# an embedded newline in the remote string is a command separator on the
# target's shell, tar archives only the first line, and the rest EXECUTE.
REMOTE_LIST="$(echo $ALL)"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $REMOTE_LIST" \
    > "$STAGE_DIR/stage-3c.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf stage-3c.tar)

PULLED=0
for f in $ALL; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
    PULLED=$((PULLED + 1))
done
echo "    pulled $PULLED files."
echo

# ---------------------------------------------------------------- 2. gates
# Everything is checked BEFORE anything is installed.

echo "==> Compile-checking every staged file..."
for f in $ALL; do
    if ! python3 -c "compile(open('$STAGE_DIR/$f').read(), '$f', 'exec')"; then
        echo "FATAL: $f failed to compile — aborting before install." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    $PULLED files compile."

# GATE 1 — prerequisites. Refuse a partial deploy rather than rely on the
# wrapper surviving one.
echo "==> Confirming every runtime helper is already installed..."
MISSING=""
for lib in $PREREQ_LIBS; do
    [ -f "/etc/qubes-rpc/$lib" ] || MISSING="$MISSING $lib"
done
if [ -n "$MISSING" ]; then
    echo "FATAL: missing dom0 helpers:$MISSING" >&2
    echo "       Stage 3c's wrappers load these at runtime. Install the stages" >&2
    echo "       that own them (1, 2, 3a, 3b, I-2, I-6) first." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    all $(echo $PREREQ_LIBS | wc -w) helpers present."

# GATE 2 — the kernel BEHAVES. Run the staged qmcp_caps against the decisions
# this stage changes, rather than grepping it for words (the 3a lesson: a
# vocabulary guard matches the comment explaining the rule). A behavioural guard
# cannot be fooled by a rename and fails on exactly the property being protected.
echo "==> Running the staged decision kernel against the carve-out matrix..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/$LIBS" <<'PY'
import ast
import importlib.util
import os
import shutil
import sys
import tempfile

path = sys.argv[1]

# `qmcp_caps` sibling-loads `qmcp_tier` from ITS OWN directory, and the staging
# tree holds only what this stage pulls — so loading it in place gives it no
# tier helper, `_in_umbrella` fails closed, and EVERY decision below returns
# "outside-umbrella". That reads as seven independent failures and is one
# missing file. (It happened on the first real run of this gate; the gate was
# right to abort and wrong about why.)
#
# Load it beside the INSTALLED tier helper instead — which is also the more
# honest test, because that is the pairing that will run in production. The
# scratch directory is outside STAGE_DIR so the SHA-256 audit listing still
# names only files that were actually pulled.
_scratch = tempfile.mkdtemp(prefix="qmcp-3c-gate2-")
shutil.copy(path, os.path.join(_scratch, "qmcp_caps.py"))
shutil.copy("/etc/qubes-rpc/qmcp_tier.py", os.path.join(_scratch, "qmcp_tier.py"))

spec = importlib.util.spec_from_file_location(
    "qmcp_caps", os.path.join(_scratch, "qmcp_caps.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

if getattr(m, "_TIER", None) is None:
    print("    the staged kernel could not load qmcp_tier — every verdict below "
          "would be a fail-closed DENY and mean nothing", file=sys.stderr)
    sys.exit(1)


class VM:
    def __init__(self, tags):
        self.name = "probe"
        self.tags = set(tags)


FULL = VM({"ai-managed", "ai-full"})
SETP = "qmcp.SetPropertyAIManaged"


def verdict(params, vm=FULL):
    return m.decide("mcp-control", SETP, "set", {"target": vm}, params)


fail = []

# The carve-out is a DIRECTION, not a value, and it is opt-in by the caller.
if verdict({"property": "netvm", "value": None}).verdict != m.ALLOW:
    fail.append("`netvm = null` is refused — the de-escalation carve-out is gone")
if verdict({"property": "netvm", "value": "somewhere"}).rule != "escalation-class":
    fail.append("a netvm RETARGET is not escalation-class — the guard is gone")
if verdict({"property": "netvm"}).rule != "escalation-class":
    fail.append("a netvm write with no stated value is not refused — a caller "
                "that omits `value` must get the conservative reading")
for prop in ("template", "name", "provides_network"):
    if verdict({"property": prop, "value": None}).rule != "escalation-class":
        fail.append("the carve-out leaked to `%s` — it is netvm-only" % prop)

# De-escalation is exempt from the escalation class, never from the ladder.
if verdict({"property": "netvm", "value": None},
           VM({"ai-managed", "ai-exec"})).verdict == m.ALLOW:
    fail.append("`netvm = null` is allowed below CAP_FULL — authority bypassed")

# The three decisions the enforcement flip turns on. If any of these moved, the
# wrappers about to be installed would enforce something other than the lattice
# this stage was reviewed against.
if m.decide("mcp-control", "qmcp.LifecycleAIManaged", "remove",
            {"target": VM({"ai-managed", "ai-exec"})}, {}).rule != "dominated:exec":
    fail.append("the dominated remove is not ALLOWed at CAP_EXEC — the widening "
                "3a's tombstone exists for is not where it was")
if m.decide("mcp-control", "qmcp.LifecycleAIManaged", "unpause",
            {"target": VM({"ai-managed", "ai-exec"})}, {}).verdict == m.ALLOW:
    fail.append("`unpause` became dominated — exec cannot reach a paused qube")
if m.decide("mcp-control", "qmcp.AttachDeviceAIManaged", "attach",
            {"backend": VM({"ai-managed", "ai-exec"}),
             "frontend": VM({"ai-managed", "ai-exec"})}, {}).verdict == m.ALLOW:
    fail.append("device attach became dominated — it crosses to hardware, which "
                "exec-inside genuinely cannot")

# The cut branch stays cut. Structural (an AST string literal), not a grep: the
# comment explaining the cut names the key, and a grep would match it.
tree = ast.parse(open(path, encoding="utf-8").read())   # the STAGED file
if any(isinstance(n, ast.Constant) and n.value == "resolved_netvm"
       for n in ast.walk(tree)):
    fail.append("`resolved_netvm` is back in the kernel — §3.4's birth half is "
                "enforced in the create wrappers; a branch here reads as a gate "
                "and is not one (invariant 2)")

for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: the staged qmcp_caps.py does not decide as Stage 3c requires." >&2
    echo "       Installing wrappers that OBEY it would enforce a different" >&2
    echo "       lattice than the one this stage was reviewed against. Aborting." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    carve-out, escalation class and domination table all as designed."

# GATE 3 — the wrappers BEHAVE. Each is a module that imports qubesadmin only
# inside main(), so it loads standalone and its gate can be exercised directly.
echo "==> Running each staged wrapper's own gate through the mode ladder..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/dom0-rpc" $(echo $WRAPPERS | tr ' ' '\n' | xargs -n1 basename) <<'PY'
import hashlib
import importlib.util
import os
import sys
import tempfile
from importlib.machinery import SourceFileLoader

d, names = sys.argv[1], sys.argv[2:]
fail = []
blocks = set()

for name in names:
    loader = SourceFileLoader("w_" + name.replace(".", "_"), os.path.join(d, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    try:
        loader.exec_module(mod)
    except Exception as exc:
        fail.append("%s: does not load standalone (%s)" % (name, type(exc).__name__))
        continue

    for attr in ("_gate", "_enforcing", "_enforce_mode", "_ENFORCE", "_CAPS",
                 "_MODE", "_MODE_PATH"):
        if not hasattr(mod, attr):
            fail.append("%s: no %s — this is not a Stage 3c wrapper" % (name, attr))
    if any(name in f for f in fail):
        continue

    # The PARTIAL-DEPLOY branch: 3c wrappers live while qmcp_enforce.py is not.
    # `_ENFORCE` is forced to None rather than inferred from what happens to be
    # in the staging directory — a guard whose meaning depends on which sibling
    # files a tar pulled is a guard that quietly stops testing what it names.
    saved_enforce, saved_caps = mod._ENFORCE, mod._CAPS
    mod._ENFORCE = None
    with tempfile.TemporaryDirectory() as td:
        absent = os.path.join(td, "absent")
        present = os.path.join(td, "present")
        with open(present, "w") as fh:
            fh.write("enforce\n")

        mod._MODE, mod._MODE_PATH, mod._shadow = None, absent, None
        if mod._enforce_mode() != "shadow":
            fail.append("%s: no helper + no operator flag must be SHADOW; got %r"
                        % (name, mod._enforce_mode()))
        if mod._enforcing():
            fail.append("%s: _enforcing() true with no operator flag — the "
                        "install is NOT inert" % name)
        if mod._gate("start", {}, {}, True) is not True:
            fail.append("%s: shadow does not pass the wrapper's own verdict "
                        "through unchanged" % name)

        mod._MODE, mod._MODE_PATH = None, present
        if mod._enforce_mode() != "strict":
            fail.append("%s: no helper + an operator flag must fail closed to "
                        "STRICT; got %r" % (name, mod._enforce_mode()))
        if mod._gate("start", {}, {}, True) is not False:
            fail.append("%s: gate admits a call it cannot decide" % name)

        # The KERNEL missing, the flag module present. `_MODE` is set directly
        # here rather than through `_MODE_PATH`: once qmcp_enforce loads, IT owns
        # the path and `read_mode` would consult the real /etc/qmcp file, so
        # steering the mode by path only works on the branch where the module is
        # gone. Writing the resolved mode is the honest way to pin it.
        mod._ENFORCE, mod._CAPS = saved_enforce, None
        if saved_enforce is not None:
            mod._MODE, mod._shadow = "shadow", None
            if mod._gate("start", {}, {}, True) is not True:
                fail.append("%s: shadow + no kernel changed the verdict" % name)
            if mod._shadow is not None:
                fail.append("%s: shadow logged a divergence from an ABSENT "
                            "kernel — an absence must not invent one" % name)
            for armed in ("strict", "enforce"):
                mod._MODE, mod._shadow = armed, None
                if mod._gate("start", {}, {}, True) is not False:
                    fail.append("%s: %s + no kernel did not fail closed"
                                % (name, armed))

    mod._ENFORCE, mod._CAPS = saved_enforce, saved_caps
    mod._MODE, mod._MODE_PATH, mod._shadow = None, "/etc/qmcp/enforce-mode", None

    src = open(os.path.join(d, name), encoding="utf-8").read()
    try:
        blk = src[src.index("def _gate("):
                  src.index("    return allowed") + len("    return allowed")]
    except ValueError:
        fail.append("%s: _gate is not in the expected shape" % name)
        continue
    blocks.add(hashlib.sha256(blk.encode()).hexdigest())
    if "_gate(" not in src[src.index("def main("):]:
        fail.append("%s: carries _gate but main() never calls it" % name)

if len(blocks) > 1:
    fail.append("_gate differs between wrappers (%d distinct copies) — eight "
                "hand-maintained copies of a security decision is how one lags"
                % len(blocks))

for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: a staged wrapper's gate does not behave as Stage 3c requires." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    8/8: inert with no flag, fail-closed with one, identical gate."

# GATE 4 — the tombstone is reachable from where the wrapper will actually load
# it. Stage 3a's live bug was precisely this: the module was correct and the
# sibling path was not, and only the deploy could tell.
echo "==> Confirming the tombstone helpers load from the INSTALLED layout..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import importlib.util
import sys

fail = []
mods = {}
for name in ("qmcp_tombstone", "qmcp_birth", "qmcp_tier"):
    try:
        s = importlib.util.spec_from_file_location(
            name, "/etc/qubes-rpc/%s.py" % name)
        m = importlib.util.module_from_spec(s)
        s.loader.exec_module(m)
        mods[name] = m
    except Exception as exc:
        fail.append("%s: not loadable from /etc/qubes-rpc (%s)"
                    % (name, type(exc).__name__))

if not fail:
    # A real transition against an in-memory tag set. If this cannot run here it
    # cannot run in the wrapper, and `remove` would refuse for every AI caller
    # the moment a mode is armed.
    tomb, birth, tier = mods["qmcp_tombstone"], mods["qmcp_birth"], mods["qmcp_tier"]
    tags = set(tier.QMCP_TIER_TAGS) | {"qmcp-owner_mcp-control", "some-operator-tag"}
    io = birth.TagIO(lambda: set(tags), tags.add, tags.discard)
    try:
        tomb.entomb(io, tier.QMCP_TIER_TAGS, when=1_700_000_000,
                    umbrella=tier.UMBRELLA, is_halted=lambda: True)
    except Exception as exc:
        fail.append("entomb() raised on a clean transition: %r" % (exc,))
    else:
        if tier.UMBRELLA in tags:
            fail.append("entomb() left the umbrella — a live qube nothing can see")
        if not any(t.startswith(tomb.TOMBSTONE_PREFIX) for t in tags):
            fail.append("entomb() left no marker — the qube is unreapable")
        if "some-operator-tag" not in tags:
            fail.append("entomb() stripped an uncontrolled operator tag")
    # And it must REFUSE an unhalted qube.
    live = set(tier.QMCP_TIER_TAGS)
    try:
        tomb.entomb(birth.TagIO(lambda: set(live), live.add, live.discard),
                    tier.QMCP_TIER_TAGS, when=1, umbrella=tier.UMBRELLA,
                    is_halted=lambda: False)
        fail.append("entomb() accepted an UNHALTED qube")
    except Exception:
        pass

for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: the Stage 3a tombstone is not usable from the installed layout." >&2
    echo "       Arming a mode would then make every AI remove refuse — or, if" >&2
    echo "       the fallback were ever loosened, destroy a qube irreversibly." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    entomb() transitions and refuses an unhalted qube, from /etc/qubes-rpc."

# GATE 5 — do not land the code and arm it in the same step.
echo "==> Checking that this install stays INERT..."
if [ -e /etc/qmcp/enforce-mode ]; then
    if [ "${QMCP_ALLOW_ARMED_INSTALL:-0}" != "1" ]; then
        echo "FATAL: /etc/qmcp/enforce-mode already exists:" >&2
        sudo sed 's|^|         |' /etc/qmcp/enforce-mode >&2 || true
        echo "       Nothing read that file before this stage, so installing now" >&2
        echo "       lands the code and arms it in one step — with no invariance" >&2
        echo "       measurement in between, which is the whole reason this stage" >&2
        echo "       ships inert." >&2
        echo "       Either remove the file (revert to shadow) and re-run, or" >&2
        echo "       re-run with QMCP_ALLOW_ARMED_INSTALL=1 if that is intended." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
    echo "    WARNING: flag present and QMCP_ALLOW_ARMED_INSTALL=1 — arming on install."
else
    echo "    /etc/qmcp/enforce-mode absent => shadow => byte-neutral. Good."
fi
echo

echo "==> SHA-256 of pulled files (record for your audit):"
# Excludes __pycache__ as well as the tar: the gates above execute the staged
# modules, so a stray .pyc would otherwise be listed as if it had been pulled
# from the source qube. An audit line naming a file nobody sent is worse than
# one naming nothing.
( cd "$STAGE_DIR" && find . -type f ! -name '*.tar' ! -path '*/__pycache__/*' -print0 \
    | sort -z | xargs -0 sha256sum | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 3. install
echo "==> Installing the shared lib (0644)..."
for f in $LIBS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0644)"
done

echo "==> Installing the 8 wrappers (0755)..."
for f in $WRAPPERS; do
    sudo install -m 0755 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0755)"
done
echo

# ---------------------------------------------------------------- 4. verify
# Post-install, against the REAL deployed files — the only check that can catch
# a layout fault, because it is the only one running where the wrapper runs.
echo "==> Verifying the installed wrappers resolve their helpers..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader

NAMES = ["qmcp.LifecycleAIManaged", "qmcp.SetPropertyAIManaged",
         "qmcp.SetFeatureAIManaged", "qmcp.CloneAIManagedQube",
         "qmcp.SpawnAIManagedQube", "qmcp.SpawnDisposableAIManaged",
         "qmcp.AttachDeviceAIManaged", "qmcp.DetachDeviceAIManaged"]
fail = []
for name in NAMES:
    p = os.path.join("/etc/qubes-rpc", name)
    loader = SourceFileLoader("i_" + name.replace(".", "_"), p)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    if mod._CAPS is None:
        fail.append("%s: qmcp_caps did not load from the installed layout" % name)
    if mod._ENFORCE is None:
        fail.append("%s: qmcp_enforce did not load from the installed layout — "
                    "the wrapper would fall back to the partial-deploy branch"
                    % name)
    if mod._enforce_mode() != "shadow":
        fail.append("%s: resolves to %r, not shadow — the install is not inert"
                    % (name, mod._enforce_mode()))
    if name == "qmcp.LifecycleAIManaged":
        if mod._TOMB is None or mod._BIRTH is None or mod._TIER_LIB is None:
            fail.append("Lifecycle: tombstone helpers unresolved — a remove "
                        "would refuse the moment a mode is armed (the Stage 3a "
                        "sibling-path fault, caught where it shows up)")
for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: installed wrappers do not resolve their helpers. The files are" >&2
    echo "       in place; behaviour is shadow, so nothing is armed — but do NOT" >&2
    echo "       write /etc/qmcp/enforce-mode until this is fixed." >&2
    exit 1
fi
echo "    8/8 resolve qmcp_caps + qmcp_enforce; Lifecycle resolves the tombstone."
echo "    all 8 report mode=shadow."
echo

# ---------------------------------------------------------------- 5. report
rm -rf "$STAGE_DIR"

cat <<'EOF'
==> Wave 2 Stage 3c installed. NOTHING IS ARMED.

    /etc/qmcp/enforce-mode is absent, which means SHADOW: every wrapper acts on
    its own verdict exactly as it did before this stage, the kernel only logs a
    disagreement, and `remove` is still a real remove.

    The ladder, each step one write and reversible by another:

      shadow   (absent, or `echo shadow`)   today's behaviour; kernel logs only
      strict   `echo strict  | sudo tee /etc/qmcp/enforce-mode`
                 allow only what the wrapper AND the kernel allow. Takes every
                 NARROWING — the escalation class stops being writable — and no
                 widening. An AI remove becomes a tombstone here.
      enforce  `echo enforce | sudo tee /etc/qmcp/enforce-mode`
                 the kernel's verdict is the verdict. Adds the WIDENING:
                 remove/kill/shutdown/start at CAP_EXEC, per anti-theatre.

    Write the file 0644 root:root. These wrappers run as a NON-ROOT dom0 user,
    so a 0600 file is unreadable to them — that resolves to `strict`, not to
    silence, but it is not what you asked for. `sudo tee` gets this right;
    `sudo bash -c 'echo … > …'` does not.

    Revert at any point:  sudo rm -f /etc/qmcp/enforce-mode
    No policy reload, no daemon restart, no slot-revert.

    BEFORE ARMING, read the divergence log — that is what it is for:
      sudo grep '"shadow"' /var/log/qmcp-audit.log | tail -40
    A line with "ok": true is an outcome the flip WOULD change. A line with
    "ok": false diverged at the capability gate but was refused later anyway by
    a check the kernel does not model, so the end state is already what the flip
    would produce. Count the first kind; the second is noise by construction.

    NOT governed by this flag, and 3c does not pretend otherwise: the six
    @tag:-scoped surfaces (the two template exec/copy services, the three
    firewall methods, qubes.Filecopy) are decided by the qrexec engine before
    any of our code runs. They were graduated by I-4/I-5/G0c, each with its own
    compat backstop, and those flips are done. §3.4's birth egress is likewise
    enforced in the create wrappers, not in the kernel.
EOF
