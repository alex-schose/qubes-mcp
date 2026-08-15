#!/bin/bash
# install-stage-I-2.sh — run in dom0.
#
# Stage I-2 install: tamper-evident, AI-unreachable dom0 audit log
# (design: STAGE-I-DESIGN.md §18.6).
#
# Surface delta:
#   - NEW dom0 lib       /etc/qubes-rpc/qmcp_audit.py
#                        audit(service, args_summary, ok, error) appends a
#                        hash-chained JSON line to /var/log/qmcp-audit.log
#                        (root:qubes, 0660, O_APPEND + flock). verify() walks
#                        the chain; `python3 qmcp_audit.py verify` is the CLI.
#   - PATCHED wrappers   the 8 state-changing qmcp.* services:
#                        Spawn / Clone / SpawnDisposable / SetProperty /
#                        SetFeature / Lifecycle / Attach / Detach.
#                        Each routes its single response funnel (emit())
#                        through audit() so every call leaves exactly one
#                        chained line. Read wrappers are NOT logged (noise).
#
# Trust-model invariants:
#   - AI-unreachable: no qmcp.* service reads/writes an arbitrary dom0 path
#     and no policy line exposes the log, so an ai-managed qube can neither
#     read past entries nor append forged ones.
#   - Best-effort: a logging failure NEVER blocks or alters an operation
#     (the I-10 vault upgrades to a fail-closed variant for SignTransaction).
#   - No secrets in the log: each wrapper builds its summary from a whitelist
#     of structural fields (qube names / property + feature KEYS / actions);
#     property and feature *values* are never logged.
#
# No policy change. No daemon restart. No new RPC service callable by AI.
#
# Idempotent — re-runnable. Installs overwrite the lib and the 8 wrappers.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-2.sh' > /tmp/install-I-2.sh
#   bash /tmp/install-I-2.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-I-2"
LOG="/var/log/qmcp-audit.log"

LIB="dom0-rpc/qmcp_audit.py"
WRAPPERS=(
    dom0-rpc/qmcp.SpawnAIManagedQube
    dom0-rpc/qmcp.CloneAIManagedQube
    dom0-rpc/qmcp.SpawnDisposableAIManaged
    dom0-rpc/qmcp.SetPropertyAIManaged
    dom0-rpc/qmcp.SetFeatureAIManaged
    dom0-rpc/qmcp.LifecycleAIManaged
    dom0-rpc/qmcp.AttachDeviceAIManaged
    dom0-rpc/qmcp.DetachDeviceAIManaged
)

echo "==> Stage I-2 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage I-2 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - $LIB ${WRAPPERS[*]}" \
    > "$STAGE_DIR/stage-I-2.tar"
(cd "$STAGE_DIR" && tar -xf stage-I-2.tar)

for f in "$LIB" "${WRAPPERS[@]}"; do
    if [ ! -s "$STAGE_DIR/$f" ]; then
        echo "FATAL: pulled an empty file: $f" >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done

# ---------------------------------------------------------------- 2. pre-install compile gate
# Touching 8 wrappers at once — refuse the whole deploy if any staged file
# does not even compile, rather than install a broken security wrapper.
echo "==> Compile-checking staged lib + wrappers..."
for f in "$LIB" "${WRAPPERS[@]}"; do
    if ! python3 -m py_compile "$STAGE_DIR/$f"; then
        echo "FATAL: $f failed to compile — aborting before install." >&2
        rm -rf "$STAGE_DIR"
        exit 1
    fi
done
echo "    all $(( ${#WRAPPERS[@]} + 1 )) files compile."
echo

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum "$LIB" "${WRAPPERS[@]}" )
echo

# ---------------------------------------------------------------- 3. install lib (0644)
echo "==> Installing shared audit lib..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/$LIB" "/etc/qubes-rpc/qmcp_audit.py"
echo "    /etc/qubes-rpc/qmcp_audit.py"
echo

# ---------------------------------------------------------------- 4. install patched wrappers (0755)
echo "==> Installing patched state-changing wrappers..."
for w in "${WRAPPERS[@]}"; do
    base="$(basename "$w")"
    sudo install -m 0755 -o root -g root \
        "$STAGE_DIR/$w" "/etc/qubes-rpc/$base"
    echo "    /etc/qubes-rpc/$base"
done
echo

# ------------------------------------------------- 4.5 audit log ownership
# The wrappers run under qrexec as a NON-root dom0 user that is in the `qubes`
# group (it must be, to reach qubesd). A root:0600 log would be unwritable by
# them and audit() would silently no-op. Create/normalise the log root:qubes
# 0660 so group-write lets the wrappers append; root owns it; AI can't reach it
# (no qrexec service exposes it, and AI has no dom0 file access). chown
# preserves any existing chain.
echo "==> Ensuring $LOG is writable by the wrapper user (root:qubes 0660)..."
if [ -e "$LOG" ]; then
    sudo chown root:qubes "$LOG" && sudo chmod 0660 "$LOG"
    echo "    normalised $LOG -> root:qubes 0660 (existing chain preserved)"
else
    sudo install -o root -g qubes -m 0660 /dev/null "$LOG"
    echo "    created $LOG -> root:qubes 0660"
fi
echo

# ---------------------------------------------------------------- 5. smoke check
echo "==> Smoke: audit lib loads + temp-chain self-test (isolated from the real log)..."
sudo python3 - <<'PY'
import importlib.util, os, tempfile
s = importlib.util.spec_from_file_location("qmcp_audit", "/etc/qubes-rpc/qmcp_audit.py")
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
assert hasattr(m, "audit") and hasattr(m, "verify"), "lib missing audit/verify"
p = tempfile.mktemp(suffix=".log"); m.LOG_PATH = p
for i in range(3): assert m.audit("qmcp.smoke", {"i": i}, True) is True
ok, n, err = m.verify(p); assert ok and n == 3, (ok, n, err)
ls = open(p).read().splitlines(); ls[1] = ls[1].replace('"ok":true', '"ok":false')
open(p, "w").write("\n".join(ls) + "\n")
assert m.verify(p)[0] is False, "tamper not detected"
os.remove(p)
print("    audit lib OK: chain verifies, tamper detected")
PY

echo "==> Smoke: REAL qrexec path — call a wrapper from $SOURCE_QUBE, confirm the log GROWS..."
# A wrapper invoked over qrexec runs as the NON-root wrapper user — the path AI
# actually uses. A root/sudo-direct call would write fine even if that path were
# broken, so we exercise the qrexec path explicitly. Lifecycle on a nonexistent
# name is refused immediately (no qube touched), but emit() still records the
# attempt — so the log must grow by one line.
# This smoke needs the MCP server's venv in the source qube. Nothing earlier in
# the band builds it, so on a clean-room install it is legitimately absent —
# and dying here with `.venv/bin/python: No such file or directory` (rc=127)
# would abort AFTER the audit log is installed, leaving the one check that
# proves the non-root write path silently unrun. Skip loudly instead, and say
# exactly how to complete the verification.
if ! qvm-run --pass-io "$SOURCE_QUBE" "test -x '$SOURCE_PATH/.venv/bin/python'" </dev/null 2>/dev/null; then
    echo "      SKIPPED — no venv at $SOURCE_QUBE:$SOURCE_PATH/.venv" >&2
    echo "      The audit log is installed but the NON-ROOT qrexec write path is" >&2
    echo "      UNVERIFIED. Build the venv and re-run this installer:" >&2
    echo "        (in $SOURCE_QUBE)  cd $SOURCE_PATH && python3 -m venv .venv \\" >&2
    echo "                           && .venv/bin/pip install -e ." >&2
    echo
    echo "==> Stage I-2 deploy complete (smoke SKIPPED — see above)."
    exit 0
fi
before="$(sudo cat "$LOG" 2>/dev/null | wc -l)"
qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && .venv/bin/python -c 'from qubes_mcp.tools._qrexec import call_qmcp; print(call_qmcp(\"qmcp.LifecycleAIManaged\", {\"name\": \"qmcp-i2-install-smoke\", \"action\": \"start\"}))'" \
    </dev/null | sed 's/^/      /'
after="$(sudo cat "$LOG" 2>/dev/null | wc -l)"
echo "      audit lines: before=$before after=$after   (must grow by 1)"
# ASSERT, don't just print: a non-root wrapper user that cannot write the log
# (root:0600 instead of root:qubes 0660, or a wrapper fchmod) makes audit()
# silently no-op — the exact I-2 v1 failure the sudo/offline smokes hid. Fail
# the install loudly if the real qrexec write path did not record the attempt.
if [ "$after" -ne "$((before + 1))" ]; then
    echo "FATAL: audit log did NOT grow by exactly 1 over the real qrexec path." >&2
    echo "       The non-root wrapper user cannot append to $LOG." >&2
    echo "       Check: $LOG is root:qubes 0660 and no wrapper fchmod's it." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo "      OK: log grew by exactly 1 — non-root qrexec write path verified."
sudo python3 /etc/qubes-rpc/qmcp_audit.py verify "$LOG" | sed 's/^/      verify: /'
if [ -e "$LOG" ]; then
    echo "      perms: $(sudo stat -c '%a %U:%G' "$LOG")   (expect 660 root:qubes)"
fi
echo

# ---------------------------------------------------------------- 6. cleanup
rm -rf "$STAGE_DIR"

echo "==> Stage I-2 deploy complete."
echo
echo "No policy change; no daemon restart needed."
echo
echo "Inspect the trail in dom0:"
echo "  sudo tail -n 5 $LOG"
echo "  sudo python3 /etc/qubes-rpc/qmcp_audit.py verify"
echo
echo "Transparency check from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-I-2.py"
