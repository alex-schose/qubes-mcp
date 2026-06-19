#!/bin/bash
# install-stage-I-3.sh — run in dom0.
#
# Stage I-3 install: tier taxonomy + dom0 tier-resolution helper
# (design: STAGE-I-DESIGN.md §3; the keystone of the resource axis).
#
# Surface delta:
#   - NEW dom0 lib   /etc/qubes-rpc/qmcp_tier.py
#                    effective_capabilities(vm) -> frozenset of capability
#                    tokens for a qube, resolving the umbrella + elevation-tag
#                    ladder (ai-ro < ai-exec < ai-net < ai-full; ai-dump is an
#                    orthogonal write-only sink). Sibling-loaded by the wrappers
#                    exactly like qmcp_budget / qmcp_scope / qmcp_audit.
#
# BEHAVIOUR-NEUTRAL. This stage installs the helper INERT — no wrapper sources
# it yet (that is Stage I-5), and no policy line changes. The helper ships in
# COMPAT mode: with the operator flag /etc/qmcp/tier-default absent, an untiered
# `ai-managed` qube resolves to FULL — i.e. exactly today's binary boundary, so
# every A–F3 surface behaves identically. The least-privilege flip (writing
# "ro" to that flag) is a deliberate later step (I-5), after the operator tiers
# the fleet.
#
# No policy change. No daemon restart. No new RPC service callable by AI (a lib
# is not a service; nothing in policy exposes it). AI cannot read its own tier:
# the tier tags are kept out of qmcp_scope's AI-observable vocabulary.
#
# Idempotent — re-runnable. Install overwrites the lib.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-I-3.sh' > /tmp/install-I-3.sh
#   bash /tmp/install-I-3.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-I-3"
LIB="dom0-rpc/qmcp_tier.py"

echo "==> Stage I-3 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage I-3 helper from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $LIB" \
    > "$STAGE_DIR/stage-I-3.tar"
(cd "$STAGE_DIR" && tar -xf stage-I-3.tar)

if [ ! -s "$STAGE_DIR/$LIB" ]; then
    echo "FATAL: pulled an empty file: $LIB" >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi

# ---------------------------------------------------------------- 2. compile gate
echo "==> Compile-checking staged helper..."
if ! python3 -m py_compile "$STAGE_DIR/$LIB"; then
    echo "FATAL: $LIB failed to compile — aborting before install." >&2
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "    $LIB compiles."
echo

echo "==> SHA-256 of pulled file (record for your audit):"
( cd "$STAGE_DIR" && sha256sum "$LIB" )
echo

# ---------------------------------------------------------------- 3. install lib (0644)
echo "==> Installing shared tier helper..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/$LIB" "/etc/qubes-rpc/qmcp_tier.py"
echo "    /etc/qubes-rpc/qmcp_tier.py"
echo

# ---------------------------------------------------------------- 4. smoke check
# The helper is dom0-side and AI-unreachable; the proof it works lives in the
# offline suite. Here we only confirm it loads in dom0 and resolves the ladder +
# the compat default the way the install claims (so a broken lib is caught at
# deploy, not at I-5 when the wrappers first source it).
echo "==> Smoke: tier helper loads in dom0 + resolves the ladder (compat)..."
sudo python3 - <<'PY'
import importlib.util, tempfile, os
s = importlib.util.spec_from_file_location("qmcp_tier", "/etc/qubes-rpc/qmcp_tier.py")
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
for fn in ("effective_capabilities", "has_capability", "tier_label"):
    assert hasattr(m, fn), f"lib missing {fn}"
absent = os.path.join(tempfile.gettempdir(), "qmcp-i3-smoke-absent-zzz")
caps = lambda tags, p=absent: set(m.effective_capabilities(tags=tags, tier_default_path=p))
# compat: untiered umbrella == FULL == today's boundary
assert caps(["ai-managed"]) == {m.CAP_READ, m.CAP_EXEC, m.CAP_NET, m.CAP_FULL}, "compat default not FULL"
assert caps(["ai-managed", "ai-exec"]) == {m.CAP_READ, m.CAP_EXEC}, "ai-exec wrong"
assert caps(["ai-managed", "ai-net"]) == {m.CAP_READ, m.CAP_EXEC, m.CAP_NET}, "ai-net wrong"
assert caps(["ai-dump"]) == {m.CAP_DUMP_IN}, "ai-dump wrong"
assert caps(["nonqmcp"]) == set(), "out-of-model not empty"
# the flip changes only the untiered default
f = tempfile.mktemp(); open(f, "w").write("ro")
assert caps(["ai-managed"], f) == {m.CAP_READ}, "flip ro: untiered not ro"
assert caps(["ai-managed", "ai-full"], f) == {m.CAP_READ, m.CAP_EXEC, m.CAP_NET, m.CAP_FULL}, "flip ro: explicit tier changed"
os.remove(f)
print("    tier helper OK: ladder + compat-FULL + ro-flip resolve correctly")
PY
echo

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo "==> Stage I-3 deploy complete (helper installed INERT — behaviour-neutral)."
echo
echo "No policy change; no daemon restart; no wrapper sources it yet (that is I-5)."
echo
echo "Transparency check from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-I-3.py"
echo "  .venv/bin/python deploy/test-stage-a.py     # regression: unchanged"
