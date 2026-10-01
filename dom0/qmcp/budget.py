"""qmcp.budget — the disk budget AI space lives inside.

The budget is the PERSISTENT footprint of every qube in AI space: each
qube's `private` volume, plus `root` for the classes whose root persists
(TemplateVM, StandaloneVM). A template-based root is copy-on-write and
`volatile` is reclaimed at shutdown, so neither is counted; counting them
over-stated real use about eightfold (measured 2026-06-12).

Two operator files, re-read on every call:
  /etc/qmcp/pool-cap     ceiling on the sum
  /etc/qmcp/private-cap  ceiling on any one qube's requested `private`

`qmcp.GetPoolStats` and every create gate share `persistent_sum`, so the
`(used, cap, headroom)` the hub reads predicts the gate exactly. Refusals
never echo numbers.

Creates are serialised by an exclusive lock held from the cap check through
the create, so two concurrent creates cannot both pass the same `used`.
The wait is bounded; a create that cannot get the lock in time is
refused, and a lock that cannot be opened at all refuses too.
"""
from __future__ import annotations

import fcntl
import os
import time

from qmcp.core import UMBRELLA, Refusal, refuse

CAP_PATH = "/etc/qmcp/pool-cap"
PRIVATE_CAP_PATH = "/etc/qmcp/private-cap"
LOCK_PATH = "/run/qmcp/create.lock"
LOCK_TIMEOUT_S = 120.0

DEFAULT_PRIVATE_BYTES = 2 * 1024 ** 3
PERSISTENT_ROOT_KLASSES = frozenset({"TemplateVM", "StandaloneVM"})

ERR_CAP_MISSING = "pool cap not configured"
ERR_CAP_EXCEEDED = "pool cap exceeded"
ERR_STATS_UNAVAILABLE = "pool stats unavailable"
ERR_PRIVATE_CAP_MISSING = "private cap not configured"
ERR_PRIVATE_TOO_LARGE = "private size exceeds per-qube limit"


def _read_int_file(path: str) -> int | None:
    """A non-negative integer on the first line, `# comment` allowed."""
    try:
        with open(path, encoding="utf-8") as f:
            head = f.read(256).split("#", 1)[0].strip()
        n = int(head)
    except (OSError, ValueError):
        return None
    return n if n >= 0 else None


def read_cap(path: str | None = None) -> int | None:
    return _read_int_file(CAP_PATH if path is None else path)


def read_private_cap(path: str | None = None) -> int | None:
    return _read_int_file(PRIVATE_CAP_PATH if path is None else path)


def _vol_size(vm, name: str) -> int:
    """A volume's provisioned size. A qube without that volume has 0; a volume
    that cannot be read raises, so a budget is never computed from a guess."""
    try:
        volume = vm.volumes[name]
    except KeyError:
        return 0
    return int(volume.size or 0)


def persistent_bytes(vm) -> int:
    total = _vol_size(vm, "private")
    if vm.klass in PERSISTENT_ROOT_KLASSES:
        total += _vol_size(vm, "root")
    return total


def persistent_sum(app) -> int:
    """Σ persistent_bytes over AI space. Raises if anything in AI space cannot
    be read: an under-count would let a create through the cap. A qube whose
    tags cannot be read is not in AI space and is skipped."""
    total = 0
    for vm in app.domains:
        try:
            tags = set(vm.tags)
        except Exception:
            continue
        if UMBRELLA in tags:
            total += persistent_bytes(vm)
    return total


def check_private_size(requested: int | None, path: str | None = None) -> None:
    if requested is None:
        return
    cap = read_private_cap(path)
    if cap is None:
        raise refuse(ERR_PRIVATE_CAP_MISSING)
    if requested > cap:
        raise refuse(ERR_PRIVATE_TOO_LARGE)


def estimate_new_private(requested: int | None) -> int:
    """A new qube's private is at least the Qubes default, which cannot shrink."""
    if requested is None:
        return DEFAULT_PRIVATE_BYTES
    return max(int(requested), DEFAULT_PRIVATE_BYTES)


def check_cap(app, estimate: int, path: str | None = None) -> None:
    cap = read_cap(path)
    if cap is None:
        raise refuse(ERR_CAP_MISSING)
    try:
        used = persistent_sum(app)
    except Exception as e:
        raise Refusal({"ok": False, "error": ERR_STATS_UNAVAILABLE},
                      error_class=type(e).__name__) from None
    if used + estimate > cap:
        raise refuse(ERR_CAP_EXCEEDED)


def acquire_create_lock(path: str | None = None, timeout: float | None = None) -> int:
    """The create lock, or a refusal. Released when the process exits."""
    try:
        fd = os.open(LOCK_PATH if path is None else path, os.O_RDWR | os.O_CREAT, 0o660)
    except OSError:
        raise refuse("qmcp runtime directory unavailable") from None
    deadline = time.monotonic() + (LOCK_TIMEOUT_S if timeout is None else timeout)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError:
            if time.monotonic() >= deadline:
                os.close(fd)
                raise refuse("busy: another create is in progress") from None
            time.sleep(0.2)
