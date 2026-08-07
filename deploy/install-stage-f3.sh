#!/bin/bash
# install-stage-f3.sh — run in dom0.
#
# Stage F3 install:
#   1. Pull updated policy + the new qmcp.GetPoolStats script from
#      mcp-control.
#   2. Install them into /etc/qubes/policy.d/ and /etc/qubes-rpc/.
#   3. Seed /etc/qmcp/pool-cap with a 50 GiB default if the file does
#      not already exist. Operator edits survive reinstall (we never
#      overwrite an existing cap file — the cap is operator state, not
#      shipped code).
#   4. Restart the qrexec policy daemon.
#
# No qube provisioning. Stage F3 only adds capability surface: an
# AI-scoped disk-budget read (sum of provisioned bytes on every
# ai-managed qube) + an operator-set cap returned alongside it. The
# wrapper is the only path; direct admin.pool.* / admin.vm.volume.*
# stay denied.
#
# Idempotent — re-runnable. Installs overwrite the wrapper/policy
# without backup; the cap file is preserved on every re-run.
#
# Run from dom0:
#   qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-f3.sh' > /tmp/install-f3.sh
#   bash /tmp/install-f3.sh mcp-control ~user/qubes_mcp/public

set -euo pipefail

SOURCE_QUBE="${1:-mcp-control}"
# The repo lives in public/ (post-2026-05-21 layout); policy/ and dom0-rpc/ are
# under it. The default must point at public/, or the default-arg pull is empty.
SOURCE_PATH="${2:-/home/user/qubes_mcp/public}"

STAGE_DIR="/tmp/qubes-mcp-stage-f3"
CAP_DIR="/etc/qmcp"
CAP_FILE="$CAP_DIR/pool-cap"
DEFAULT_CAP_BYTES="53687091200"  # 50 GiB
PRIVATE_CAP_FILE="$CAP_DIR/private-cap"
DEFAULT_PRIVATE_CAP_BYTES="21474836480"  # 20 GiB per-qube private ceiling

echo "==> Stage F3 deploy starting"
echo "    source qube:    $SOURCE_QUBE"
echo "    source path:    $SOURCE_PATH"
echo

# ---------------------------------------------------------------- 1. pull
echo "==> Pulling Stage F3 files from $SOURCE_QUBE:$SOURCE_PATH..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

qvm-run --pass-io "$SOURCE_QUBE" \
    "cd '$SOURCE_PATH' && tar -cf - policy/30-mcp-control.policy dom0-rpc/qmcp.GetPoolStats" \
    > "$STAGE_DIR/stage-f3.tar"

(cd "$STAGE_DIR" && tar -xf stage-f3.tar)

# Guard against an empty/failed pull — installing an empty policy and then
# reloading the daemon would break ALL qrexec.
for f in policy/30-mcp-control.policy dom0-rpc/qmcp.GetPoolStats; do
    [ -s "$STAGE_DIR/$f" ] || { echo "FATAL: pulled an empty file: $f" >&2; rm -rf "$STAGE_DIR"; exit 1; }
done

echo "==> SHA-256 of pulled files (record for your audit):"
( cd "$STAGE_DIR" && sha256sum policy/30-mcp-control.policy \
                                dom0-rpc/qmcp.GetPoolStats )
echo

# ---------------------------------------------------------------- 2. validate + install dom0 files
# A malformed policy can break ALL qrexec, so validate the staged file BEFORE it
# touches /etc/qubes/policy.d/. Prefer the authoritative qrexec parser; fall back
# to a structural lint (every non-comment line >=5 fields + a valid action). Same
# gate the I-4/I-5 installers use — f3 reloads the daemon too, so it needs it.
echo "==> Validating staged policy syntax (before install)..."
if python3 - "$STAGE_DIR/policy/30-mcp-control.policy" <<'PY'
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
    print("    qrexec parser: policy parses clean.")
    sys.exit(0)
except ImportError:
    pass
except Exception as e:  # parser present but rejected the file
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
print("    structural lint: all rule lines well-formed (>=5 fields, valid action).")
PY
then
    echo "    policy validation OK."
else
    echo "FATAL: staged policy failed validation — NOT installing." >&2
    rm -rf "$STAGE_DIR"; exit 1
fi
echo

echo "==> Installing dom0 policy..."
sudo install -m 0644 -o root -g root \
    "$STAGE_DIR/policy/30-mcp-control.policy" \
    /etc/qubes/policy.d/30-mcp-control.policy

echo "==> Installing dom0 qmcp.* script..."
sudo install -m 0755 -o root -g root \
    "$STAGE_DIR/dom0-rpc/qmcp.GetPoolStats" \
    "/etc/qubes-rpc/qmcp.GetPoolStats"
echo "    /etc/qubes-rpc/qmcp.GetPoolStats"
echo

# ---------------------------------------------------------------- 3. seed cap (only if absent)
echo "==> Configuring operator-set pool cap..."
if [ ! -e "$CAP_FILE" ]; then
    sudo install -d -m 0755 -o root -g root "$CAP_DIR"
    # Seed with 50 GiB default. The operator edits this any time;
    # the wrapper re-reads per call, no daemon restart needed.
    sudo bash -c "echo '$DEFAULT_CAP_BYTES  # 50 GiB — edit to taste (bytes; integer)' > '$CAP_FILE'"
    sudo chmod 0644 "$CAP_FILE"
    sudo chown root:root "$CAP_FILE"
    echo "    Seeded $CAP_FILE with $DEFAULT_CAP_BYTES bytes (50 GiB)."
else
    echo "    $CAP_FILE already exists — preserved (operator state):"
    echo "    $(cat "$CAP_FILE")"
fi

# Per-qube private ceiling P (the persistent-footprint accounting, 2026-06-12).
# A spawn may request a larger `private` than the default, up to this; the dom0
# wrapper refuses a request above it. Operator state — seed only if absent.
if [ ! -e "$PRIVATE_CAP_FILE" ]; then
    sudo install -d -m 0755 -o root -g root "$CAP_DIR"
    sudo bash -c "echo '$DEFAULT_PRIVATE_CAP_BYTES  # 20 GiB per-qube private ceiling — edit to taste' > '$PRIVATE_CAP_FILE'"
    sudo chmod 0644 "$PRIVATE_CAP_FILE"
    sudo chown root:root "$PRIVATE_CAP_FILE"
    echo "    Seeded $PRIVATE_CAP_FILE with $DEFAULT_PRIVATE_CAP_BYTES bytes (20 GiB)."
else
    echo "    $PRIVATE_CAP_FILE already exists — preserved (operator state):"
    echo "    $(cat "$PRIVATE_CAP_FILE")"
fi
echo

# ---------------------------------------------------------------- 4. reload daemon
echo "==> Reloading qrexec policy daemon..."
if sudo systemctl restart qubes-qrexec-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-qrexec-policy-daemon."
elif sudo systemctl restart qubes-policy-daemon 2>/dev/null; then
    echo "    Restarted qubes-policy-daemon."
else
    echo "    WARNING: neither policy daemon name worked."
fi

# ---------------------------------------------------------------- 5. cleanup
rm -rf "$STAGE_DIR"

echo
echo "==> Stage F3 deploy complete."
echo
echo "Verify from mcp-control:"
echo "  .venv/bin/python deploy/test-stage-f3.py"
