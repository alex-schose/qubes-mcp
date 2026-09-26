#!/bin/bash
# install-stage-3d.sh — run in dom0.
#
# Wave 2 Stage 3d install: the calling principal is never a legitimate OBJECT.
#
# Surface delta:
#   - 1 NEW lib             /etc/qubes-rpc/qmcp_principal.py
#   - 5 REWRITTEN wrappers  /etc/qubes-rpc/qmcp.{SetProperty,SetFeature,
#                           Lifecycle,AttachDevice,DetachDevice}AIManaged
#                           each gains an UNCONDITIONAL pre-gate ahead of the
#                           existence check, the umbrella check, the tier gate,
#                           the consent gate and /etc/qmcp/enforce-mode.
#   - 1 REPLACED policy     /etc/qubes/policy.d/30-mcp-control.policy
#                           four self-target `deny` lines for the @tag:-scoped
#                           services a helper cannot reach. Policy changes, so
#                           the daemon IS reloaded (unlike 3c).
#
# No operator file is created. The optional /etc/qmcp/principals only ever ADDS
# to the derived principal, so its absence is the correct default, not a gap.
#
# THIS STAGE SHIPS ARMED, AND THAT IS DELIBERATE.
# Every stage since I-6 shipped inert behind a flag. This one does not, because
# the guard is not a capability decision: it removes an operation with no
# legitimate use (the gateway is the principal; its being an object at all is
# the 2026-08-13 shadowing bug), so there is nothing to be compat with and no
# backstop to write. Placing it behind /etc/qmcp/enforce-mode would make it
# inert under `shadow` — which is production's posture and exactly the state
# the gap is live in. Gate 3 proves the guard is mode-independent.
#
# WHAT IT CLOSES. On a fresh install /etc/qmcp/tier-default is absent, which
# resolves to COMPAT (untiered umbrella = ai-full). An umbrella-tagged gateway
# is then fully mutable from the AI seat, and `name` is in SETTABLE_PROPS:
# renaming the principal severs every policy line that names it literally,
# unrecoverable without dom0. Measured offline: 7 of the 8 settable properties
# were open on the principal before this stage (netvm was already shut, by F-2).
#
# Idempotent — re-runnable. Install overwrites.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-3d.sh' > /tmp/install-3d.sh
#   bash /tmp/install-3d.sh mcp-control ~user/qubes_mcp/public
#
# Environment:
#   QMCP_SKIP_POLICY=1   install the code half only, leaving policy untouched.
#                        Leaves the @tag:-scoped services UNGUARDED — an F9
#                        split-brain window. For staged debugging only.

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-3d"

WRAPPERS="dom0-rpc/qmcp.SetPropertyAIManaged
dom0-rpc/qmcp.SetFeatureAIManaged
dom0-rpc/qmcp.LifecycleAIManaged
dom0-rpc/qmcp.AttachDeviceAIManaged
dom0-rpc/qmcp.DetachDeviceAIManaged"
LIBS="dom0-rpc/qmcp_principal.py"
POLICY_REL="policy/30-mcp-control.policy"
POLICY_DST="/etc/qubes/policy.d/30-mcp-control.policy"
ALL="$WRAPPERS $LIBS $POLICY_REL"

# Helpers the rewritten wrappers load at import time. A wrapper landing without
# one of these fails closed on every call, so check before installing, not after.
PREREQ_LIBS="qmcp_caps.py qmcp_enforce.py qmcp_tier.py qmcp_consent.py
qmcp_audit.py qmcp_tombstone.py qmcp_birth.py qmcp_scope.py qmcp_budget.py"

echo "==> Wave 2 Stage 3d deploy starting (principal guard, ARMED on install)"
echo "    source: $SOURCE_QUBE:$SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage 3d files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

REMOTE_LIST="$(echo $ALL)"
qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $REMOTE_LIST" \
    > "$STAGE_DIR/stage-3d.tar" < /dev/null
(cd "$STAGE_DIR" && tar -xf stage-3d.tar)

PULLED=0
for f in $ALL; do
    # -s, not -e: an EMPTY pulled file passes `bash -n` and compiles to nothing.
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: $f did not arrive (missing or empty)." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
    PULLED=$((PULLED + 1))
done
echo "    $PULLED files pulled."
echo

# ---------------------------------------------------------------- 2. gates
echo "==> Compile-checking every staged Python file..."
for f in $WRAPPERS $LIBS; do
    if ! python3 -c "compile(open('$STAGE_DIR/$f').read(), '$f', 'exec')"; then
        echo "FATAL: $f does not compile." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    all staged Python compiles."

echo "==> Confirming every runtime helper is already installed..."
MISSING=""
for l in $PREREQ_LIBS; do
    [ -f "/etc/qubes-rpc/$l" ] || MISSING="$MISSING $l"
done
if [ -n "$MISSING" ]; then
    echo "FATAL: missing helpers in /etc/qubes-rpc:$MISSING" >&2
    echo "       Install the earlier stages first." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    all $(echo $PREREQ_LIBS | wc -w) helpers present."
echo

# GATE 1 — behavioural, not structural. The artifact IS a function, so RUN it
# (the 3b lesson). A grep for a name matches a docstring; a rename defeats it;
# this cannot be fooled by either, and it fails on exactly the property the
# stage protects.
echo "==> Running the staged principal guard against the partition..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/$LIBS" <<'PY'
import importlib.util, sys
path = sys.argv[1]
spec = importlib.util.spec_from_file_location("qmcp_principal", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fail = []
GW, ENV, NOFILE = "gw-probe", {"QREXEC_REMOTE_DOMAIN": "gw-probe"}, "/nonexistent"

def refuses(svc, role, name, act=None):
    return m.refuses_as_principal(svc, role, name, act, path=NOFILE, environ=ENV)

LIFE = "qmcp.LifecycleAIManaged"
# The guarded half.
for svc, role in (("qmcp.SetPropertyAIManaged", "target"),
                  ("qmcp.SetFeatureAIManaged", "target"),
                  ("qmcp.AttachDeviceAIManaged", "backend"),
                  ("qmcp.AttachDeviceAIManaged", "frontend"),
                  ("qmcp.DetachDeviceAIManaged", "backend"),
                  ("qmcp.DetachDeviceAIManaged", "frontend")):
    if not refuses(svc, role, GW):
        fail.append("%s/%s does not refuse the principal" % (svc, role))
for act in ("pause", "remove"):
    if not refuses(LIFE, "target", GW, act):
        fail.append("Lifecycle/%s does not refuse the principal" % act)
if not refuses(LIFE, "target", GW, None):
    fail.append("Lifecycle with an unparsed action is not fail-closed")

# The DOMINATED half must stay open, or the stage is shipping theatre.
for act in ("kill", "shutdown", "start"):
    if refuses(LIFE, "target", GW, act):
        fail.append("Lifecycle/%s is guarded — exec already dominates it" % act)
for svc, role in (("qmcp.CloneAIManagedQube", "source"),
                  ("qmcp.SpawnAIManagedQube", "template"),
                  ("qmcp.SpawnDisposableAIManaged", "dvmt"),
                  ("qmcp.GetPropertyAIManaged", "target"),
                  ("qmcp.ListAttachedDevicesAIManaged", "target")):
    if refuses(svc, role, GW):
        fail.append("%s/%s is guarded — invariant-2 theatre" % (svc, role))

# COMPLETENESS: every service the kernel gates on CAP_FULL must be classified
# guarded-or-excluded, so a mutation wrapper added without a decision fails the
# install rather than arriving silently unguarded.
try:
    import importlib.util as _il
    _cs = _il.spec_from_file_location("qmcp_caps", "/etc/qubes-rpc/qmcp_caps.py")
    _c = _il.module_from_spec(_cs); _cs.loader.exec_module(_c)
    _mut = {s for s, r in _c.SERVICE_TABLE.items()
            if r and any(v == _c.CAP_FULL for v in r.values())}
    _cls = set(m.PRINCIPAL_GUARDED_ROLES) | set(getattr(m, "PRINCIPAL_EXCLUDED", {}))
    if not _mut <= _cls:
        fail.append("unclassified mutating service(s): %s" % sorted(_mut - _cls))
    if set(m.PRINCIPAL_GUARDED_ROLES) & set(getattr(m, "PRINCIPAL_EXCLUDED", {})):
        fail.append("a service is both guarded and excluded")
except Exception as _e:
    fail.append("completeness check could not run: %r" % (_e,))

# A non-principal must pass, or the guard is an always-refuse.
if refuses("qmcp.SetPropertyAIManaged", "target", "some-worker"):
    fail.append("a NON-principal target is refused — always-refuse, not a gate")

# Config direction: the file only ever ADDS.
if m.protected_principals(NOFILE, ENV) != frozenset({GW}):
    fail.append("an absent principals file does not protect the caller")
if m.protected_principals(NOFILE, {}) != frozenset():
    fail.append("a blank QREXEC_REMOTE_DOMAIN invents a principal")

# An UNDETERMINABLE caller must fail CLOSED on the guarded positions and must
# still leave the dominated ones open. This was a fail-open until 2026-09-02.
for _lbl, _env in (("absent", {}), ("empty", {"QREXEC_REMOTE_DOMAIN": ""}),
                   ("blank", {"QREXEC_REMOTE_DOMAIN": "   "})):
    if not m.refuses_as_principal("qmcp.SetPropertyAIManaged", "target",
                                  "anything", None, NOFILE, _env):
        fail.append("an %s QREXEC_REMOTE_DOMAIN does not refuse (fail-OPEN)"
                    % _lbl)
    if m.refuses_as_principal("qmcp.LifecycleAIManaged", "target", "anything",
                              "shutdown", NOFILE, _env):
        fail.append("an %s caller closes a DOMINATED position too" % _lbl)

for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: the staged qmcp_principal does not implement the partition." >&2
    echo "       Installing it would either leave the gap open or ship theatre." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    guarded positions refuse; dominated positions do not; config only adds."

# GATE 2 — the inverted fail-closed direction, checked on the staged wrappers
# themselves. This is the rider a session pattern-matching on I-2 gets backwards:
# I-2's audit hook is best-effort and degrades silently; this is a GATE and must
# refuse. A wrapper that falls through on a missing helper re-opens the gap while
# looking installed.
echo "==> Checking each staged wrapper refuses when the helper is unavailable..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/dom0-rpc" <<'PY'
import importlib.util, os, sys, types
from importlib.machinery import SourceFileLoader
staged = sys.argv[1]
fail = []
WRAPPERS = ["qmcp.SetPropertyAIManaged", "qmcp.SetFeatureAIManaged",
            "qmcp.LifecycleAIManaged", "qmcp.AttachDeviceAIManaged",
            "qmcp.DetachDeviceAIManaged"]

# Scratch = installed helpers, overlaid with everything this stage stages.
# Outside STAGE_DIR so the SHA-256 audit listing still names only files that
# were really pulled from the source qube (the 3b __pycache__ rider).
import shutil, tempfile
scratch = tempfile.mkdtemp(prefix="qmcp-3d-gate-")
for d in ("/etc/qubes-rpc", staged):
    if not os.path.isdir(d):
        continue
    for fn in os.listdir(d):
        src_p = os.path.join(d, fn)
        if os.path.isfile(src_p):
            shutil.copyfile(src_p, os.path.join(scratch, fn))
if not os.path.exists(os.path.join(scratch, "qmcp_principal.py")):
    fail.append("qmcp_principal.py is neither staged nor installed")
for w in WRAPPERS:
    # Loaded beside a SCRATCH layout that is the installed tree overlaid with
    # this stage's staged files — which is the pairing that will run after
    # section 3, and the only one that is right both on a first install and on
    # an upgrade.
    #
    # Two earlier shapes were wrong and both are the 3c gate-2 lesson wearing a
    # different hat. Loading in the staging dir fails closed for want of
    # siblings the stage does not pull, so one missing file reads as five
    # faults. Loading against /etc/qubes-rpc is right on an upgrade and
    # impossible on a FIRST install, because qmcp_principal.py is not installed
    # until later in this very script — measured 2026-09-02, where it aborted
    # the install with "could not load qmcp_principal" on a clean fleet. A
    # guard whose verdict depends on which files happen to be on disk is a
    # guard that has stopped testing what it names.
    src = open(os.path.join(staged, w), encoding="utf-8").read()
    ns = {"__name__": "gate_" + w.replace(".", "_"),
          "__file__": os.path.join(scratch, w)}
    try:
        exec(compile(src, w, "exec"), ns)
    except Exception as exc:
        fail.append("%s does not import from the installed layout: %r" % (w, exc))
        continue
    fn = ns.get("_principal_refuses")
    if fn is None:
        fail.append("%s has no _principal_refuses" % w)
        continue
    saved = ns.get("_PRINCIPAL")
    for label, stub in (("missing", None),
                        ("stale", types.SimpleNamespace()),
                        ("raising", types.SimpleNamespace(
                            refuses_as_principal=lambda *a, **k: 1 / 0))):
        ns["_PRINCIPAL"] = stub
        try:
            verdict = fn("target", "anything")
        except Exception as exc:
            fail.append("%s: _principal_refuses RAISED on a %s helper: %r"
                        % (w, label, exc))
            continue
        if verdict is not True:
            fail.append("%s: a %s helper does NOT refuse (fail-OPEN)" % (w, label))
    ns["_PRINCIPAL"] = saved
    if saved is None:
        fail.append("%s could not load the STAGED qmcp_principal" % w)

shutil.rmtree(scratch, ignore_errors=True)
for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: a staged wrapper does not fail closed on an unavailable helper." >&2
    echo "       That is the silent failure mode this stage exists to avoid." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    all 5 wrappers refuse on a missing, stale or raising helper."

# GATE 3 — mode-independence. The guard must not be reachable through
# qmcp_enforce, or it is inert under `shadow`, which is production's posture.
echo "==> Checking the guard is ahead of /etc/qmcp/enforce-mode..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$STAGE_DIR/dom0-rpc" <<'PY'
import ast, os, sys
staged = sys.argv[1]
fail = []
for w in ("qmcp.SetPropertyAIManaged", "qmcp.SetFeatureAIManaged",
          "qmcp.LifecycleAIManaged", "qmcp.AttachDeviceAIManaged",
          "qmcp.DetachDeviceAIManaged"):
    src = open(os.path.join(staged, w), encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
               and n.name == "_principal_refuses"), None)
    if fn is None:
        fail.append("%s: no _principal_refuses" % w)
        continue
    body = ast.dump(fn)
    for forbidden in ("_ENFORCE", "_MODE", "read_mode", "effective_verdict",
                      "_CAPS"):
        if forbidden in body:
            fail.append("%s: the guard consults %s — it would be inert in shadow"
                        % (w, forbidden))
    main = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    seg = ast.get_source_segment(src, main) or ""
    if "_principal_refuses(" not in seg:
        fail.append("%s: main() never calls the guard" % w)
    else:
        # Ordering, INVERTED on 2026-09-02. This used to require the guard to
        # precede the qubesadmin import. That skipped the qubesd round trip and
        # made a principal-target call 44% faster than every other refusal class
        # on hardware — byte-identical messages, a latency oracle over
        # /etc/qmcp/principals. The guard must now come AFTER the umbrella check
        # (same answer, same cost) and still BEFORE the tier/consent/enforce
        # gates, which is the ordering that carries the security property.
        _umb = seg.find('"ai-managed" not in')
        _g = seg.find("_principal_refuses(")
        _tier = min([x for x in (seg.find("_require_full"), seg.find("_gate("),
                                 seg.find("_full_ok")) if x > 0] or [-1])
        if not (0 <= _umb < _g):
            fail.append("%s: the guard runs BEFORE the umbrella check — that is "
                        "the timing oracle" % w)
        if not (0 < _tier and _g < _tier):
            fail.append("%s: the guard runs AFTER the tier gate" % w)
for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: the guard is not mode-independent or not shape-only." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    the guard consults no mode, and runs before any host lookup."
echo

# ---------------------------------------------------------------- 2b. policy
if [ "${QMCP_SKIP_POLICY:-0}" = "1" ]; then
    echo "==> QMCP_SKIP_POLICY=1 — leaving policy untouched."
    # Report what the LIVE policy actually says rather than assuming this is a
    # first install. Skipping the policy on a fleet that already has the deny
    # lines leaves them in place, so a flat "UNGUARDED" warning here would be
    # false — and a gate that misreports the state it is describing is the
    # defect this stage is about.
    LIVE_DENIES="$(grep -v '^[[:space:]]*#' "$POLICY_DST" 2>/dev/null \
        | awk '{n=split($0,t,/[ \t]+/); if (n>=5 && t[5]=="deny" && t[3]==t[4] &&
                (t[1]=="admin.vm.firewall.Set" || t[1]=="admin.vm.firewall.Reload")) c++}
               END {print c+0}')"
    if [ "${LIVE_DENIES:-0}" -ge 2 ]; then
        echo "    The live policy already carries $LIVE_DENIES self-target deny line(s);"
        echo "    the @tag:-scoped half stays guarded. Nothing to do."
    else
        echo "    WARNING: the live policy carries ${LIVE_DENIES:-0} of the 2 self-target"
        echo "    deny lines, so the @tag:-scoped firewall-write surface is UNGUARDED"
        echo "    while the wrapper half is guarded — an F9 split-brain window."
    fi
else
    # GATE 0 — do not silently UN-FLIP a flipped fleet.
    # The staged policy is the shipped/compat one: it carries the four
    # `@tag:ai-managed` COMPAT backstops that the I-4/I-5 flip deletes. Writing
    # it over a flipped fleet's policy restores them, widening the @tag:-scoped
    # surfaces, while `/etc/qmcp/tier-default` stays `ro` — the F9 split-brain
    # this project's own rule forbids, arriving through a policy-carrying
    # installer that never mentioned the flip.
    #
    # This is not hypothetical. Measured on the development box 2026-09-02: its
    # installed policy is byte-identical to the shipped file with an mtime of
    # 2026-08-19, the day a policy-only release deployed. That release had no
    # such guard, so it re-installed the backstops over a fleet whose
    # tier-default still read `ro`, and the fleet sat split-brained for two
    # weeks while the notes recorded it as flipped. install-stage-I-4.sh and
    # -I-5.sh already refuse this; a policy-carrying installer that does not is
    # the hole they were guarding.
    FLIPPED="$(tr -d '[:space:]' < /etc/qmcp/tier-default 2>/dev/null || true)"
    STAGED_BACKSTOPS="$(grep -v '^[[:space:]]*#' "$STAGE_DIR/$POLICY_REL" \
        | grep -cE '^(qmcp\.(RunIn|CopyTo)AIManaged|admin\.vm\.firewall\.(Set|Reload))[[:space:]]+\*[[:space:]]+[^[:space:]]+[[:space:]]+@tag:ai-managed[[:space:]]+allow' || true)"
    if [ "$FLIPPED" = "ro" ] && [ "${STAGED_BACKSTOPS:-0}" -gt 0 ]; then
        if [ "${QMCP_ALLOW_UNFLIP:-0}" != "1" ]; then
            echo "FATAL: this fleet is FLIPPED (/etc/qmcp/tier-default=ro), but the" >&2
            echo "       staged policy still carries $STAGED_BACKSTOPS COMPAT backstop line(s)." >&2
            echo "       Installing it would restore them and leave the helper flipped" >&2
            echo "       — an F9 split-brain, and least privilege backwards on the" >&2
            echo "       @tag:-scoped surfaces (exec, copy, firewall write)." >&2
            echo "       Either re-run install-stage-flip.sh afterwards to delete them" >&2
            echo "       again, or re-run this with QMCP_ALLOW_UNFLIP=1 if the widening" >&2
            echo "       is intended. Or QMCP_SKIP_POLICY=1 to install the code half" >&2
            echo "       only, which is a narrowing and always safe." >&2
            rm -rf "$STAGE_DIR"
            exit 1
        fi
        echo "    WARNING: flipped fleet + QMCP_ALLOW_UNFLIP=1 — restoring $STAGED_BACKSTOPS backstop(s)."
    elif [ "$FLIPPED" = "ro" ]; then
        echo "    fleet is flipped and the staged policy carries no backstops. Good."
    fi

    # A malformed policy can break ALL of qrexec on reload, so validate the
    # staged file BEFORE it touches /etc/qubes/policy.d/ (I-4).
    echo "==> Validating staged policy (before install)..."
    if ! python3 - "$STAGE_DIR/$POLICY_REL" <<'PY'
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
        echo "FATAL: staged policy failed validation — NOT installing." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi

    # GATE 4 — first-match-wins is the whole mechanism, so the ordering is a
    # correctness property, not formatting. A deny that lands below its own
    # @tag: lines never matches and the stage ships a comment.
    echo "==> Checking each self-target deny precedes its @tag: lines..."
    if ! python3 - "$STAGE_DIR/$POLICY_REL" <<'PY'
import sys
lines = open(sys.argv[1], encoding='utf-8').read().splitlines()
rules = [(i, l) for i, l in enumerate(lines)
         if l.strip() and not l.lstrip().startswith('#')]
fail = []
# Only the firewall WRITE methods: measured 2026-09-02, a self-call to the exec
# and copy services is refused by the qrexec TRANSPORT ("loopback qrexec
# connection not supported") after policy has already allowed it, so a deny
# there would be a rule that can never match.
for svc in ("admin.vm.firewall.Set", "admin.vm.firewall.Reload"):
    mine = [(i, l) for i, l in rules if l.split()[0] == svc]
    deny = [i for i, l in mine
            if l.split()[4] == 'deny' and l.split()[2] == l.split()[3]]
    tags = [i for i, l in mine if '@tag:' in l]
    if not deny:
        fail.append("%s: no self-target deny line" % svc)
    elif tags and max(deny) > min(tags):
        fail.append("%s: deny at %s is BELOW @tag: at %s — it never matches"
                    % (svc, deny, tags))
get = [l for _, l in rules if l.split()[0] == 'admin.vm.firewall.Get']
if any(l.split()[4] == 'deny' for l in get):
    fail.append("firewall.Get gained a deny — a read is invariant-2 theatre")
for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
    then
        echo "FATAL: the policy half is mis-ordered — NOT installing." >&2
        rm -rf "$STAGE_DIR"; exit 1
    fi
    echo "    every self-target deny precedes its own @tag: lines."
fi
echo

echo "==> SHA-256 of pulled files (record for your audit):"
# Excludes __pycache__ as well as the tar: the gates above execute the staged
# modules, so a stray .pyc would otherwise be listed as if it had been pulled.
( cd "$STAGE_DIR" && find . -type f ! -name '*.tar' ! -path '*/__pycache__/*' -print0 \
    | sort -z | xargs -0 sha256sum | sed 's|^|    |' )
echo

# ---------------------------------------------------------------- 3. install
echo "==> Installing the new lib (0644)..."
for f in $LIBS; do
    sudo install -m 0644 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0644)"
done

echo "==> Installing the 5 wrappers (0755)..."
for f in $WRAPPERS; do
    sudo install -m 0755 -o root -g root "$STAGE_DIR/$f" "/etc/qubes-rpc/$(basename "$f")"
    echo "    /etc/qubes-rpc/$(basename "$f")  (0755)"
done

if [ "${QMCP_SKIP_POLICY:-0}" != "1" ]; then
    echo "==> Installing dom0 policy (REPLACE)..."
    sudo install -m 0664 -o root -g qubes "$STAGE_DIR/$POLICY_REL" "$POLICY_DST"
    echo "    $POLICY_DST"

    echo "==> Reloading qrexec policy daemon..."
    sudo systemctl reset-failed qubes-qrexec-policy-daemon qubes-policy-daemon 2>/dev/null || true
    sudo systemctl reload qubes-qrexec-policy-daemon 2>/dev/null \
        || sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null \
        || sudo systemctl restart qubes-policy-daemon 2>/dev/null || true
    if systemctl is-failed --quiet qubes-qrexec-policy-daemon 2>/dev/null; then
        echo "FATAL: the policy daemon is in a failed state after reload." >&2
        echo "       qrexec then falls back to per-call policy evaluation, which" >&2
        echo "       works but hides the fault. Inspect before proceeding." >&2
        exit 1
    fi
    echo "    policy daemon healthy."
fi
echo

# ---------------------------------------------------------------- 4. verify
# Post-install, against the REAL deployed files — the only check that can catch
# a layout fault, because it is the only one running where the wrapper runs.
echo "==> Verifying the INSTALLED wrappers resolve the guard..."
if ! PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import os, sys
fail = []
for w in ("qmcp.SetPropertyAIManaged", "qmcp.SetFeatureAIManaged",
          "qmcp.LifecycleAIManaged", "qmcp.AttachDeviceAIManaged",
          "qmcp.DetachDeviceAIManaged"):
    p = os.path.join("/etc/qubes-rpc", w)
    ns = {"__name__": "post_" + w.replace(".", "_"), "__file__": p}
    try:
        exec(compile(open(p, encoding="utf-8").read(), w, "exec"), ns)
    except Exception as exc:
        fail.append("%s: will not import in dom0: %r" % (w, exc))
        continue
    if ns.get("_PRINCIPAL") is None:
        fail.append("%s: _PRINCIPAL is None — every call will now REFUSE" % w)
for line in fail:
    print("    " + line, file=sys.stderr)
sys.exit(1 if fail else 0)
PY
then
    echo "FATAL: an installed wrapper cannot load /etc/qubes-rpc/qmcp_principal.py." >&2
    echo "       Because the guard fails CLOSED, every guarded call now refuses." >&2
    echo "       Re-run this installer; if it persists, run uninstall-stage-3d.sh." >&2
    exit 1
fi
echo "    all 5 installed wrappers load the guard from /etc/qubes-rpc."
echo

# ---------------------------------------------------------------- 5. residual
# A bounded residual reported is better than one that reads as absent (F-1).
# The wrapper runs as a NON-root dom0 user (uid 1000, group qubes — I-2/slot-51),
# so an operator file it cannot READ contributes nothing and says nothing. That
# is a fail-quiet: the caller stays protected, sibling gateways silently do not.
echo "==> Checking the optional /etc/qmcp/principals file..."
if [ -e /etc/qmcp/principals ]; then
    echo "    present: $(sudo stat -c '%U:%G %a' /etc/qmcp/principals)"
    if sudo -u "#1000" test -r /etc/qmcp/principals 2>/dev/null; then
        echo "    readable by the wrapper user; it names $(grep -cvE '^[[:space:]]*(#|$)' /etc/qmcp/principals 2>/dev/null || echo '?') extra principal(s)."
    else
        echo "    WARNING: NOT readable by the wrapper user (uid 1000)."
        echo "    It will contribute nothing and report nothing. The calling"
        echo "    principal stays protected either way; any sibling gateway"
        echo "    named in this file does NOT. Fix:  sudo chmod 0644 /etc/qmcp/principals"
    fi
else
    echo "    absent — the calling principal is protected on its own. That is"
    echo "    the correct default; the file only ever ADDS."
fi
echo

echo "==> Checking the gateway's own tags..."
if qvm-tags "$SOURCE_QUBE" list 2>/dev/null | grep -qx 'ai-managed'; then
    echo "    WARNING: $SOURCE_QUBE carries the 'ai-managed' umbrella."
    echo "    This stage now refuses the mutations that made that dangerous, but"
    echo "    the tag still costs you things it was never meant to buy: it makes"
    echo "    the gateway an OBJECT on every @tag:-scoped surface, and"
    echo "    'qubes.Filecopy * @tag:ai-managed @anyvm deny' sits ABOVE the"
    echo "    operator's own Filecopy line, so copying OUT of it is dead."
    echo "    The gateway is the named SOURCE in every qmcp rule; source matching"
    echo "    is by name, so the umbrella adds nothing to its authority."
    echo "    Recommended:  qvm-tags $SOURCE_QUBE del ai-managed"
else
    echo "    $SOURCE_QUBE does not carry the umbrella. Good."
fi
echo

rm -rf "$STAGE_DIR"

cat <<EOF
==> Stage 3d installed.

    The guard is ARMED. It is deliberately NOT behind /etc/qmcp/enforce-mode:
    it is an object-identity check, not a capability decision, and the kernel is
    inert under 'shadow' — which is this fleet's posture.

    What changed, from the AI seat:
      - SetProperty / SetFeature / Lifecycle(pause,remove) / device attach and
        detach naming the CALLING PRINCIPAL now return the opaque "not found".
      - Lifecycle kill / shutdown / start on the principal are UNCHANGED. The
        seat can already do those from inside itself, so gating them would
        delete nothing and read as a control.
      - Nothing else moved. Every non-principal target behaves as before.

    Optional, for a fleet with more than one gateway:
      /etc/qmcp/principals  — one qube name per line, '#' comments ignored.
      It only ever ADDS to the caller-derived principal, so an absent file is
      the correct default and a malformed one cannot unprotect the caller.

    Revert:  bash uninstall-stage-3d.sh
EOF
