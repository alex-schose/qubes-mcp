"""Temp dirs for the offline suites, gone when the test that made them ends.

Every suite makes its temp dirs here, so each is removed by the test's own
cleanup whether the test passed, failed or errored, and a run leaves nothing
in the temp dir. A removal that cannot be done raises: a leftover is a fault
of the test that left it, and it must say so rather than accumulate.

`close_fds_under` is for the in-process harness that simulates a death
(tests/racefixture.py): a killed process's descriptors are closed by the
kernel, the harness's are not.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import stat
import tempfile


def tempdir(test, prefix: str = "qmcp-test-") -> pathlib.Path:
    """A new temp dir, removed by `test`'s cleanup."""
    path = pathlib.Path(tempfile.mkdtemp(prefix=prefix))
    test.addCleanup(remove, path)
    return path


def remove(path) -> None:
    """Remove a temp tree. A tree already gone is fine (a test or a restore
    may have removed it); a tree a test left unwritable or unreadable is
    made the owner's again first. Symlinks are removed, never followed."""
    path = os.fspath(path)
    if not os.path.lexists(path):
        return
    try:
        shutil.rmtree(path)
    except PermissionError:
        _own(path)
        shutil.rmtree(path)


def _own(path: str) -> None:
    """u+rwx on every directory of the tree, top down, so rmtree can list and
    empty each one; a symlink is never followed out of the tree (rmtree has
    already refused a link given as the tree itself)."""
    os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) | stat.S_IRWXU)
    with os.scandir(path) as it:
        subdirs = [e.path for e in it if e.is_dir(follow_symlinks=False)]
    for d in subdirs:
        _own(d)


def fds_under(root) -> list:
    """The descriptors of this process open on a file under `root`, including
    one whose file was deleted since. The path is compared both as given and
    resolved, so a temp dir reached through a symlink is still matched."""
    roots = {os.path.abspath(os.fspath(root)), os.path.realpath(os.fspath(root))}
    prefixes = tuple(r + os.sep for r in roots)
    found = []
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except FileNotFoundError:
            continue                    # the listing's own descriptor, closed already
        if target.endswith(" (deleted)"):
            target = target[: -len(" (deleted)")]
        if target in roots or target.startswith(prefixes):
            found.append(int(fd))
    return found


def close_fds_under(root) -> int:
    """Close every descriptor `fds_under(root)` finds; returns how many."""
    found = fds_under(root)
    for fd in found:
        os.close(fd)
    return len(found)
