#!/bin/bash
# install-stage-I-1.sh — run in dom0.
#
# Stage I-1 install: close the read-surface name leak (F-3, design §18.6).
#
# Surface delta:
#   - NEW dom0 lib       /etc/qubes-rpc/qmcp_scope.py
#                        Shared helper: is_ai_managed / scoped_name /
#                        scoped_value / scoped_tags. Imported by the two
#                        read wrappers below.
#   - PATCHED wrappers   /etc/qubes-rpc/qmcp.GetPropertyAIManaged
#                        /etc/qubes-rpc/qmcp.ListAIManagedQubes
#                        Route every VM-valued result through scoped_value:
#                        a referenced qube's name survives only if that qube
#                        is ai-managed, else it collapses to the opaque
#                        "<out-of-scope>" sentinel. GetProperty also gives
#                        `tags` a deliberate, vocabulary-filtered path.
#
# Trust-model invariants preserved:
#   - Existence-hiding unchanged: an untagged or nonexistent target still
#     returns the opaque "not found" (the value channel is what F-3 fixes).
#   - Write/cross-ref opacity unchanged (Stage F2).
#   - Fail-closed: if the helper can't load, the read refuses rather than
#     falling back to the pre-I-1 (leaking) serialisation.
#
# No policy change. No daemon restart. No new RPC service.
#
# Idempotent — re-runnable. Installs overwrite the lib and the two wrappers.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-I-1.sh' > /tmp/install-I-1.sh
#   bash /tmp/install-I-1.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-I-1"

echo "==> Stage I-1 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage I-1 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - \
        dom0-rpc/qmcp_scope.py \
        dom0-rpc/qmcp.GetPropertyAIManaged \
        dom0-rpc/qmcp.ListAIManagedQubes" \
    > "$STAGE_DIR/stage-I-1.tar"

(cd "$STAGE_DIR" && tar -xf stage-I-1.tar)

for f in dom0-rpc/qmcp_scope.py \
         dom0-rpc/qmcp.GetPropertyAIManaged \
         dom0-rpc/qmcp.ListAIManagedQubes; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum \
    dom0-rpc/qmcp_scope.py \
    dom0-rpc/qmcp.GetPropertyAIManaged \
    dom0-rpc/qmcp.ListAIManagedQubes )
echo

# ---------------------------------------------------------------- 2. install lib (0644)
echo "==> Installing shared scope-redaction lib..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/dom0-rpc/qmcp_scope.py" \
    "/etc/qubes-rpc/qmcp_scope.py"
echo "    /etc/qubes-rpc/qmcp_scope.py"
echo

# ---------------------------------------------------------------- 3. install patched wrappers (0755)
echo "==> Installing patched read wrappers..."
for w in qmcp.GetPropertyAIManaged qmcp.ListAIManagedQubes; do
    sudo install -m 0755 -o root -g root \
        "$STAGE_DIR/dom0-rpc/$w" \
        "/etc/qubes-rpc/$w"
    echo "    /etc/qubes-rpc/$w"
done
echo

# ---------------------------------------------------------------- 4. smoke check
echo "==> Smoke check: scope lib loads + existence-hiding holds..."
sudo python3 -c "import importlib.util; \
s=importlib.util.spec_from_file_location('qmcp_scope','/etc/qubes-rpc/qmcp_scope.py'); \
m=importlib.util.module_from_spec(s); s.loader.exec_module(m); \
print('    scope lib OK:', hasattr(m,'scoped_name') and hasattr(m,'scoped_tags'))"
echo '    dom0 read (expect {"ok": false, "error": "not found"}):'
# The wrapper's emit() returns `0 if payload["ok"] else 1`, so a REFUSAL exits 1
# — and a refusal is exactly the security property this smoke check exists to
# demonstrate. Piping it directly under `set -euo pipefail` therefore aborts the
# installer on success-as-designed. Capture the output instead, and assert the
# refusal explicitly so the check still means something.
# (Bit the fresh-box rebuild on 2026-08-05: this installer predates the
# exit-on-refusal behaviour that later stages gave the wrappers.)
_i1_out="$(echo '{"name":"dom0","property":"netvm"}' | sudo /etc/qubes-rpc/qmcp.GetPropertyAIManaged || true)"
printf '%s\n' "$_i1_out" | sed 's/^/      /'
if printf '%s' "$_i1_out" | grep -q '"ok": *false'; then
    echo '    existence-hiding holds (dom0 read refused).'
else
    echo "FATAL: dom0 read was NOT refused — existence-hiding is broken." >&2
    exit 1
fi
echo

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo "==> Stage I-1 deploy complete."
echo
echo "No policy change; no daemon restart needed."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-I-1.py"
