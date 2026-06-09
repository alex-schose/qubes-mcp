"""qmcp_budget — shared dom0 helper for the AI-scoped disk-budget gate.

Stage I-0. The F3 pool cap (`/etc/qmcp/pool-cap`) was advisory: AI could
read `(used, cap, headroom)` via `qmcp.GetPoolStats` and was expected to
self-throttle. A hallucinating or prompt-injected agent could ignore the
signal and spawn past the budget (design §18.3, F-1). I-0 promotes the
cap to a hard gate by calling `check_cap_for_create()` from every create
wrapper *before* it invokes the Admin API.

Trust posture mirrors F3 exactly:
  - Cap source is the same operator-owned config file
    (`/etc/qmcp/pool-cap`, re-read per call, no daemon restart).
  - `used` is summed the same way (sum of `vol.size` across every
    volume of every ai-managed qube — provisioned bytes, not on-disk).
  - Missing/malformed cap → opaque "pool cap not configured" (fail
    closed; F3's install seeds the cap, so the unconfigured state is
    a deliberate operator action).
  - Over-cap → opaque "pool cap exceeded"; no numbers echoed. AI can
    call `qmcp.GetPoolStats` for the diagnostic triple if it wants —
    we leak nothing new on top of what that surface already provides.

The new-qube estimate is the conservative one: the *full* provisioned
size of the template/source (root + private + volatile + anything
else `vm.volumes` enumerates), not just `private.size`. Root provisioned
bytes already count against F3's `used`, so estimating only private
would under-count and let AI slip past the cap. Some volumes are
COW-shared with the template on disk; we still count them because
F3's `used` does, and the estimate must speak the same language as
the budget it is gated against.

Loaded by the wrappers via `importlib.util.spec_from_file_location`
using a path derived from `__file__`, so the same code runs in dom0
(`/etc/qubes-rpc/qmcp_budget.py`) and in offline-validation tests on
mcp-control (`public/dom0-rpc/qmcp_budget.py`) without any sys.path
or PYTHONPATH dependency.

Why sibling-import instead of an installed package: Qubes' own
`/etc/qubes-rpc/` scripts (qubes.GetDate, admin.vm.Console) and the
qubesadmin client tools (qvm-run, etc.) are self-contained — shared
infrastructure is consumed via the globally installed `qubesadmin`
package, and no qubes-rpc script sibling-imports another. We deviate
from that convention because our deployment is a tarball + slot
runner, not an RPM, so installing a shared Python module under
`/usr/lib/python3/dist-packages/` per slot adds packaging overhead
(spec files, dist-packages path drift across Qubes releases)
disproportionate to a ~150-line helper. The trade-off is recorded
as reviewer ask #12 in `public/README.md` so a Qubes reviewer can
flag a better long-term answer (most likely: graduate to a tiny
`qubes-mcp-helpers` RPM once the helper count crosses ~300 shared
lines or ~3 distinct helpers, projected at Stage I-3 or so).
"""
from __future__ import annotations

CAP_PATH = "/etc/qmcp/pool-cap"

ERR_CAP_MISSING = "pool cap not configured"
ERR_CAP_EXCEEDED = "pool cap exceeded"
ERR_STATS_UNAVAILABLE = "pool stats unavailable"


def read_cap() -> int | None:
    """Read the operator-set cap as integer bytes.

    Returns None on any failure (missing file, parse error, negative
    value). Callers must convert None into the opaque
    ERR_CAP_MISSING message — never leak path or parse details to AI.

    Format mirrors F3's: a single integer on the first line, optional
    `# comment` trailer for operator legibility:
        53687091200  # 50 GiB
    """
    try:
        with open(CAP_PATH, "r") as f:
            raw = f.read().strip()
        head = raw.split("#", 1)[0].strip()
        n = int(head)
        if n < 0:
            return None
        return n
    except Exception:
        return None


def sum_ai_managed_volume_bytes(app) -> int:
    """Sum vol.size across every volume of every ai-managed qube.

    Byte-identical semantics to qmcp.GetPoolStats's
    sum_ai_managed_volume_bytes — the gate and the read surface must
    measure the same thing so AI's view of (used, cap, headroom)
    predicts the gate's behaviour exactly.
    """
    total = 0
    for vm in app.domains:
        try:
            tags = vm.tags
        except Exception:
            continue
        if "ai-managed" not in tags:
            continue
        try:
            volumes = vm.volumes
        except Exception:
            continue
        for vol in volumes.values():
            try:
                size = int(vol.size or 0)
            except Exception:
                size = 0
            total += size
    return total


def estimate_new_qube_bytes(src_vm) -> int:
    """Estimate provisioned bytes a new qube will consume.

    `src_vm` is the template (AppVM/DispVMTemplate/DispVM spawn,
    SpawnDisposable) or the source (clone) — in both cases the new
    qube's volumes inherit from this VM, so its full vol.size sum is
    the conservative estimate.

    Any access error returns 0 for that volume rather than aborting;
    a wrapper that can't enumerate the source's volumes will under-
    count the estimate (looser gate) but never refuse a legitimate
    create on a bookkeeping error. The cap itself is the floor on
    misbehaviour, not this estimate.
    """
    total = 0
    try:
        volumes = src_vm.volumes
    except Exception:
        return 0
    for vol in volumes.values():
        try:
            size = int(vol.size or 0)
        except Exception:
            size = 0
        total += size
    return total


def check_cap_for_create(app, src_vm) -> str | None:
    """The gate. Return None to allow the create, error string to refuse.

    Refuses iff:
      - cap is missing/malformed (fail-closed; ERR_CAP_MISSING)
      - current ai-managed provisioned sum can't be computed
        (ERR_STATS_UNAVAILABLE; conservative — refuse rather than
        allow a create we can't budget against)
      - projected = used + estimate > cap (ERR_CAP_EXCEEDED)

    Note `projected > cap`, strict — equality is allowed (the cap is
    the ceiling AI may reach but not exceed).
    """
    cap = read_cap()
    if cap is None:
        return ERR_CAP_MISSING

    try:
        used = sum_ai_managed_volume_bytes(app)
    except Exception:
        return ERR_STATS_UNAVAILABLE

    estimated_new = estimate_new_qube_bytes(src_vm)
    if used + estimated_new > cap:
        return ERR_CAP_EXCEEDED

    return None
