"""qmcp_budget — shared dom0 helper for the AI-scoped disk-budget gate.

Stage I-0 introduced the gate; the 2026-06-12 accounting correction (this
version) changes WHAT it counts. The original gate summed `vol.size`
(provisioned / max) across EVERY volume of every ai-managed qube — root,
private, volatile alike. Measured against real on-disk usage that over-counted
~8x (slot-53 on hardware): an AppVM's `root` is a COW snapshot of its template
(real persistent delta ~0) and `volatile` is ephemeral (destroyed on shutdown),
yet both were charged at full provisioned size. Two scratch qubes could exhaust
a 120 GiB cap while really using <1 GiB.

The corrected basis counts only the PERSISTENT footprint:

  - `private` (always) — /home + /rw, the only volume that accumulates real
    persistent bytes for a template-based qube.
  - `root` ONLY for klasses whose root persists — TemplateVM and StandaloneVM.
    An AppVM / DispVM / DispVMTemplate root is COW from its template and is NOT
    counted (real persistent delta ~0; slot-53 measured a live AppVM root at
    0.00 GiB).
  - `volatile` is never counted (ephemeral; reclaimed on shutdown; slot-53
    measured 0.02 GiB on a running qube vs 10 GiB provisioned).

Because a volume cannot exceed its own `size`, summing provisioned
`private.size` (+ persistent `root.size`) and capping the sum is a HARD ceiling
on the PERSISTENT footprint only: persistent ≤ Σ size ≤ cap. A running qube's
volatile + COW-root consume real pool space transiently (reclaimed on shutdown)
and are intentionally NOT metered, so the cap bounds persistent exhaustion, not
transient runtime pool pressure. The gate stays provisioned-based (stable and
predictable for AI) but drops the volumes that don't persist, so the ceiling
tracks reality instead of 8x-inflating it.

Two operator-owned config files (both re-read per call, no daemon restart — the
F3 `/etc/qmcp/pool-cap` pattern):
  - `/etc/qmcp/pool-cap`     — the global cap (Σ persistent ≤ this).
  - `/etc/qmcp/private-cap`  — the per-qube `private.size` ceiling P. A spawn may
    request a larger private than the 2 GiB default, up to P; a request above P
    is refused. This bounds any single qube's blast radius and lets AI spawn big
    qubes *under the limit*.

Trust posture mirrors F3 / I-0 exactly:
  - Caps are operator-owned files AI cannot touch.
  - Over-cap / over-P / missing-cap collapse to opaque messages; no numbers
    echoed (AI can call `qmcp.GetPoolStats` for its `(used, cap, headroom)`).
  - The new-qube estimate is conservative: a spawn counts the requested private
    (clamped up to the 2 GiB default floor); a clone counts the source's full
    persistent footprint (it copies those volumes).

Loaded by the wrappers via `importlib.util.spec_from_file_location` using a path
derived from `__file__`, so the same code runs in dom0
(`/etc/qubes-rpc/qmcp_budget.py`) and in offline-validation on mcp-control
(`public/dom0-rpc/qmcp_budget.py`) without any sys.path dependency.
`qmcp.GetPoolStats` imports `sum_ai_managed_persistent_bytes` from here so the
read surface and the gate can never drift (the F3 self-contained copy is gone —
the klass-aware sum is too easy to duplicate wrong). Sibling-import rationale
(deviation from Qubes' self-contained-rpc-script convention) is reviewer ask
#12 in `public/README.md`.
"""
from __future__ import annotations

import fcntl
import os
import sys

CAP_PATH = "/etc/qmcp/pool-cap"
PRIVATE_CAP_PATH = "/etc/qmcp/private-cap"
#: Exclusive create lock — serializes the cap-check->create critical section
#: across concurrent qmcp.* create PROCESSES (each qrexec call is its own
#: process). The create wrappers hold it from the gate through the Admin API
#: create; pre-created root:qubes 0660 at install so the non-root wrapper user
#: can flock it. See acquire_create_lock.
LOCK_PATH = "/etc/qmcp/budget.lock"

#: Default private size assumed for a spawn that doesn't request one — the Qubes
#: default a new AppVM/DispVM receives (2 GiB). Also the floor the estimate
#: clamps up to, since Qubes cannot shrink a volume below its created size, so a
#: sub-default request still yields a default-sized private.
DEFAULT_PRIVATE_BYTES = 2 * 1024 ** 3

#: Klasses whose `root` volume persists real bytes (installed software /
#: standalone disk) and therefore counts toward the budget. Every klass AI can
#: create (AppVM, DispVM, DispVMTemplate) has a COW root and is absent here.
PERSISTENT_ROOT_KLASSES = frozenset({"TemplateVM", "StandaloneVM"})

#: The tombstone marker (Wave 2 Stage 3a). OWNED by `qmcp_tombstone.py`; this
#: is a deliberate literal copy, not a sibling import. `counts_toward_cap` is a
#: GATE, and a helper that failed to load would silently stop charging
#: tombstones — which is precisely the create/remove churn bypass the charge
#: exists to close, reintroduced with no symptom whatsoever. A literal cannot
#: fail to load. `deploy/offline-validate-3a.py` asserts the two agree, so the
#: duplication cannot drift instead.
TOMBSTONE_PREFIX = "qmcp-tombstone_"

ERR_CAP_MISSING = "pool cap not configured"
ERR_CAP_EXCEEDED = "pool cap exceeded"
ERR_STATS_UNAVAILABLE = "pool stats unavailable"
ERR_PRIVATE_CAP_MISSING = "private cap not configured"
ERR_PRIVATE_TOO_LARGE = "private size exceeds per-qube limit"


def _read_int_file(path: str) -> int | None:
    """Read a single non-negative integer (bytes) from an operator config file.

    Format mirrors F3's: an integer on the first line, optional `# comment`:
        96636764160  # 90 GiB
    Returns None on any failure (missing file, parse error, negative) — callers
    convert None into the opaque "not configured" message, never leaking detail.
    """
    try:
        with open(path, "r") as f:
            raw = f.read().strip()
        head = raw.split("#", 1)[0].strip()
        n = int(head)
        if n < 0:
            return None
        return n
    except Exception:
        return None


def read_cap() -> int | None:
    """The global pool cap (Σ persistent ≤ this)."""
    return _read_int_file(CAP_PATH)


def read_private_cap() -> int | None:
    """The per-qube private.size ceiling P."""
    return _read_int_file(PRIVATE_CAP_PATH)


def _vol_size(volumes, name: str) -> int:
    try:
        vol = volumes[name]
    except Exception:
        return 0
    try:
        return int(vol.size or 0)
    except Exception:
        return 0


def persistent_bytes(vm) -> int:
    """The persistent provisioned footprint of one qube.

    `private.size` always, plus `root.size` only when the klass's root persists
    (TemplateVM / StandaloneVM). `volatile` is never counted. Fail-safe: any
    access error contributes 0 for that piece rather than aborting the sum.
    """
    try:
        volumes = vm.volumes
    except Exception:
        return 0
    total = _vol_size(volumes, "private")
    try:
        klass = vm.klass
    except Exception:
        klass = None
    if klass in PERSISTENT_ROOT_KLASSES:
        total += _vol_size(volumes, "root")
    return total


def counts_toward_cap(tags) -> bool:
    """True iff this qube's persistent bytes are charged to the AI pool cap.

    Two ways to be charged, and the second is a security property rather than
    bookkeeping:

    - **inside the umbrella** — the original rule, unchanged.
    - **carrying a tombstone marker** — an AI-initiated remove drops the
      umbrella so AI can neither see nor touch the qube, but its private (and,
      for a persistent-root klass, its root) stays allocated until the reaper
      runs. If the cap ignored tombstones, dropping the umbrella would make
      one free, and an `ai-exec` actor could create-and-remove in a loop to
      park an unbounded number of full-size qubes outside the accounting for
      the whole retention window — churn straight through the one bound on
      accumulation. See `qmcp_tombstone.py`.

    Fail-closed to NOT charging on an unreadable tag set, matching the loop
    this replaced: a qube whose tags cannot be read is not demonstrably ours,
    and inventing a charge against it would refuse AI's creates for a reason
    nothing can explain.
    """
    try:
        tagset = set(tags)
    except Exception:
        return False
    if "ai-managed" in tagset:
        return True
    return any(str(t).startswith(TOMBSTONE_PREFIX) for t in tagset)


def sum_ai_managed_persistent_bytes(app) -> int:
    """Σ `persistent_bytes` over every qube charged to the AI pool.

    That is every ai-managed qube plus every tombstone awaiting the reaper —
    see `counts_toward_cap` for why the second is not optional. The name is
    kept because `qmcp.GetPoolStats` imports it by name and the whole point of
    the shared function is that the read surface and the gate cannot drift:
    AI's `(used, cap, headroom)` still predicts the gate byte-for-byte, so a
    remove does not immediately hand back headroom and waiting out the
    retention window is the honest, visible cost of churning qubes.
    """
    total = 0
    for vm in app.domains:
        try:
            tags = vm.tags
        except Exception:
            continue
        if not counts_toward_cap(tags):
            continue
        total += persistent_bytes(vm)
    return total


def estimate_spawn_bytes(requested_private: int | None) -> int:
    """Persistent footprint a spawn / disposable will add: just the new qube's
    private. The new qube's root is COW from its template (real persistent
    delta ~0), so it is not counted — matching `sum_ai_managed_persistent_bytes`.

    Clamped up to the default floor: a fresh qube's private is at least the
    Qubes default, and Qubes cannot shrink it below that, so charging less than
    the default would under-count what the qube actually gets.
    """
    if requested_private is None:
        return DEFAULT_PRIVATE_BYTES
    return max(int(requested_private), DEFAULT_PRIVATE_BYTES)


def dvmt_private_bytes(dvmt_vm) -> int:
    """The `private.size` a disposable inherits from its DispVMTemplate.

    A disposable provisions its `private` FROM the DVMT, so a cap estimate that
    assumed the 2 GiB default under-counts a disposable spawned off an inflated
    DVMT. SpawnDisposable passes this as `requested_private` so estimate_spawn_bytes
    clamps it up to the floor and the projection matches what the disposable
    actually provisions. Fail-safe: the default floor on any access error.
    """
    try:
        return _vol_size(dvmt_vm.volumes, "private")
    except Exception:
        return DEFAULT_PRIVATE_BYTES


def estimate_clone_bytes(src_vm) -> int:
    """Persistent footprint a clone will add: the source's full persistent
    footprint. A clone copies the source's volumes, so cloning a template
    persists its root too (`persistent_bytes` already encodes the klass rule)."""
    return persistent_bytes(src_vm)


def check_private_size(requested_private: int | None) -> str | None:
    """Refuse a spawn whose requested `private.size` exceeds the per-qube cap P.

    None when no size was requested (the default is always within P) or the
    request is within P. Fail-closed (`ERR_PRIVATE_CAP_MISSING`) if P is
    unconfigured — the install seeds it, so an absent P is a deliberate
    operator action, like the pool cap.
    """
    if requested_private is None:
        return None
    p = read_private_cap()
    if p is None:
        return ERR_PRIVATE_CAP_MISSING
    if int(requested_private) > p:
        return ERR_PRIVATE_TOO_LARGE
    return None


def acquire_create_lock() -> int:
    """Take the exclusive create lock, serializing the cap-check->create critical
    section across concurrent qmcp.* create processes. Each qrexec invocation is
    a separate dom0 process, so without this two spawns can both read the same
    pre-create `used`, both pass the gate, and both create — overshooting the cap
    by up to (N-1)x estimate. The wrappers acquire this BEFORE check_cap_for_create
    and hold it through the Admin API create; the lock releases when the
    short-lived wrapper PROCESS EXITS (a raw fd is not closed on GC), so callers
    need not release it explicitly.

    BEST-EFFORT: the cap is a soft, reclaimable ceiling (overshoot is a bounded
    transient DoS, not a breakout), so a create still PROCEEDS if the lock can't
    be taken — a broken lock file must never block all creates; it only loses
    cross-process serialization. Returns the locked fd, or -1 on failure.
    """
    try:
        fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660)
    except Exception as e:
        # AUDIT-LOUD (Stage I-7, finding [5]): the lock file is provisioned
        # root:qubes 0660 at install (install-stage-I-0.sh), so a failure here is
        # exceptional — surface it to stderr/journal instead of silently degrading
        # serialization to nothing. Still BEST-EFFORT by design (see the docstring:
        # a cap overshoot is a bounded, reclaimable transient DoS, not a breakout,
        # and a broken lock file must never block every create).
        print(f"qmcp_budget: create-lock open failed ({e}); proceeding UNLOCKED "
              f"— serialization degraded, concurrent creates may overshoot the cap",
              file=sys.stderr, flush=True)
        return -1
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except Exception as e:
        print(f"qmcp_budget: create-lock flock failed ({e}); proceeding UNLOCKED "
              f"— serialization degraded", file=sys.stderr, flush=True)
        try:
            os.close(fd)
        except Exception:
            pass
        return -1
    return fd


def release_create_lock(fd: int) -> None:
    """Release a lock taken by acquire_create_lock. The wrappers rely on process
    exit and don't call this; it exists for offline tests and any long-lived
    caller that must not hold the lock until exit."""
    if fd is None or fd < 0:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        os.close(fd)
    except Exception:
        pass


def check_cap_for_create(app, src_vm, requested_private: int | None = None,
                         is_clone: bool = False) -> str | None:
    """The global gate. Return None to allow the create, error string to refuse.

    Refuses iff:
      - cap missing/malformed (fail-closed; ERR_CAP_MISSING)
      - the current persistent sum can't be computed (ERR_STATS_UNAVAILABLE;
        conservative — refuse rather than budget against an unknown)
      - projected = used + estimate > cap (ERR_CAP_EXCEEDED; strict — equality
        is allowed, the cap is the ceiling AI may reach but not exceed)

    The estimate is the source's persistent footprint for a clone, else the
    spawn's requested-or-default private. The per-qube `private` clamp is a
    separate check (`check_private_size`), which Spawn runs first.
    """
    cap = read_cap()
    if cap is None:
        return ERR_CAP_MISSING

    try:
        used = sum_ai_managed_persistent_bytes(app)
    except Exception:
        return ERR_STATS_UNAVAILABLE

    if is_clone:
        estimate = estimate_clone_bytes(src_vm)
    else:
        estimate = estimate_spawn_bytes(requested_private)

    if used + estimate > cap:
        return ERR_CAP_EXCEEDED

    return None
