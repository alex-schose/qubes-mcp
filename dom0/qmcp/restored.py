"""qmcp.restored — a qube that came back from a backup, or was copied by hand,
waits for the operator's review.

Measured on Qubes 4.3.1 (2026-10-10): `qvm-backup-restore` and `qvm-clone`
both give a qube a NEW UUID and keep its tags and its features: measured for
`qvm-clone`, a restore beside the original, and a restore with the original
gone. A qube that came back with no label is held all the same. So dom0 labels
every qube it brings into AI space or badges with the feature `qmcp-id`, set to
that qube's own UUID. A qube whose label is missing, or names another UUID, did
not get its badges from this install's dom0: it was restored, copied by hand,
or badged outside qmcp. Without that, a worker restored after months would join
whatever project holds its slot now, since the rulebook routes on badges alone
and a project's record keeps no list of its members.

- `label(vm)` writes the label whatever is there. A create calls it on the qube
  it has just made, which may carry its source's label (a clone copies features).
- `label_if_missing(vm)` writes it only where there is none (the installer's
  anonymous-mode stamp, on the hub). `require_label(vm)` (every badge
  `fleet._set_tags` adds) labels a qube with no label and no `ai-managed`,
  `ai-dump` or qmcp badge, and refuses a qube whose label is another's, and a
  badged one with none, held or not. It never writes over another UUID's
  label: that would release a restored qube without the operator. (`manage`
  and `guard` label a qube outside the check's scope afresh; the gate's own badges
  and the hold are written without a label.)
- `hold(app)`, run by the gate's pass, puts `qmcp-quarantine` on every qube in
  scope whose label does not match. The rulebook's A0 refuses every call into
  it and out of it, and the services refuse to operate it or create from it. It
  keeps the badges it came back with, so the review can show them, but for an
  owner badge: once a qube waiting for review is held, the same pass decides
  its `qmcp-owner_*` badges once (`decide_owner`): a proven restore keeps them
  and is recorded by its own UUID in `qmcp-owner-kept`, which no copy of it
  shares; any other qube loses them, so the hub cannot remove a copy decided
  while its source exists. The lifecycle service refuses to remove a qube waiting for
  review even before the pass holds it.
- `review(app, records)` lists every such qube, with the role its badges name
  and whether that agrees with the records today.
- `accept(app, name)` takes off an owner badge the pass did not record as
  kept, then labels the qube, and only then lifts the hold, so a failure
  leaves it held. `reject(app, name)` takes every qmcp badge off, the
  routed ones first and the hold last.

A qube is in scope when it wears `ai-managed`, `ai-dump` or any `qmcp-` badge.
Neither the hub nor a lead can write a feature outside its allowlist
(`menu-items`, `default-menu-items`, `service.*`, `vm-config.*`), and no rule
gives the hub or AI space an `admin.vm.feature` method, so neither can forge a
label. A label or a UUID that
cannot be read is never "matches": the pass leaves that qube for its next run,
and `qmcp check` reports the read.
"""
from __future__ import annotations

import hashlib
import os
import re
import time

from qmcp import audit, budget, core, projects
from qmcp.birth import OWNER_PREFIX

ID = core.ID_FEATURE
#: dom0's record that the restore check proved a qube a restore, so it keeps
#: its owner badge: that qube's own UUID, which no copy of it shares.
KEPT = core.OWNER_KEPT_FEATURE
#: dom0's record of every label an accept or a reject replaced or removed,
#: one per line: a copy made before then still wears it, and must never read
#: as a restore whose original is gone (`proven_restore`). Kept in dom0, not
#: on the qube, so removing the accepted original (the hub may remove a kept
#: restore) takes none of it away. Root writes it; the gate's user reads it.
REPLACED_PATH = "/var/lib/qmcp/replaced-labels"
#: dom0's record of every qube the hub or a lead removed: one empty file per
#: UUID, written by the lifecycle service before it removes. A copy whose
#: label names one of them is a copy of a qube AI space removed, never a
#: restore, however its remove and the copy's clone interleaved (qubesadmin's
#: `clone_vm` copies the tags before the label, so a check of the copies at
#: the remove cannot see one still being cloned). 2770 root:qubes in tmpfiles:
#: the services write it, the gate's user reads it.
REMOVED_DIR = "/var/lib/qmcp/removed"
HOLD = core.QUARANTINE
SERVICE = "qmcp gate"
CALLER = "gate"
#: How long the pass waits for a create in flight, in the create lock's
#: turnstile: creates that arrive after it wait behind it, so only the ones
#: already past it (at most the callers' slots) go first. The anonymity gate
#: runs before this pass (`cli.cmd_gate`), so the wait costs this run's stop
#: nothing; it is short because the next run, and its heartbeat, wait for this
#: one to end. A pass that cannot have the lock judges nothing this time and
#: says so (`qmcp gate` exits 3): creates kept in flight can delay a hold past
#: one pass, the residual the design states.
LOCK_WAIT_S = 10
#: How long the hold waits for one qube's lock before holding it without.
HOLD_LOCK_WAIT_S = 2.0
#: The most the pass spends waiting for qube locks, in all: past it, a qube is
#: held without waiting (a hold only takes authority away) and settled below.
HOLD_PASS_S = 10.0
#: How long the holds made without a lock then wait, together, for those locks
#: again, so the calls that held them have finished, and each hold is read back.
HOLD_SETTLE_WAIT_S = 5.0
NOTICE = ("qubes-mcp is holding {name} for your review: it came back from a backup, or was "
          "copied by hand. Open the qubes-mcp window.")


def in_scope(tags) -> bool:
    return (core.UMBRELLA in tags or projects.DROP_BOX in tags
            or any(t.startswith("qmcp-") for t in tags))


def _uuid(vm) -> str:
    try:
        return str(vm.uuid).strip().lower()
    except Exception as e:
        raise core.Unreadable(f"cannot read the UUID of {core.name_of(vm)}") from e


def label_of(vm):
    """The `qmcp-id` label, or None when there is none. Raises core.Unreadable."""
    try:
        value = vm.features.get(ID, None)
    except Exception as e:
        raise core.Unreadable(f"cannot read the {ID} feature of {core.name_of(vm)}") from e
    return None if value is None else str(value).strip().lower()


def labelled(vm) -> bool:
    """True when the qube's label is its own UUID. Raises core.Unreadable."""
    label = label_of(vm)
    return label is not None and label == _uuid(vm)


def born_of_its_template(vm, label) -> bool:
    """A disposable Qubes made itself (a preloaded one, or one launched by
    hand) from a labelled disposable template: Qubes copies the template's
    features, so its label is its template's UUID. Only one that cleans itself
    up (`auto_cleanup`) counts: Qubes leaves those out of backups, while a
    named disposable is backed up like any qube and must be held when it comes
    back. Raises core.Unreadable."""
    if label is None or core.klass_of(vm) != "DispVM":
        return False
    try:
        cleans_up = vm.auto_cleanup
    except Exception as e:
        raise core.Unreadable(f"cannot read auto_cleanup of {core.name_of(vm)}") from e
    if cleans_up is not True:
        return False
    tpl = core.template_of(vm)
    return tpl is not None and label == _uuid(tpl) and labelled(tpl)


def known(vm) -> bool:
    """Labelled with its own UUID, or a disposable born of a labelled
    disposable template. Raises core.Unreadable."""
    label = label_of(vm)
    if label is not None and label == _uuid(vm):
        return True
    return born_of_its_template(vm, label)


#: A UUID's shape, as qubesd writes one: only such a label names a qube, and
#: only such a label is recorded or proves a restore.
_UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def is_uuid(text) -> bool:
    return isinstance(text, str) and bool(_UUID_RE.match(text))


def copies_waiting(app, vm) -> bool:
    """Is a copy of `vm` waiting for review: a qube in scope, not known (held,
    or not yet), whose `qmcp-id` label or `qmcp-owner-kept` record names
    `vm`'s UUID? The hub may remove a qube it made; removing the source of a
    copy before the restore check decides the copy would make the copy read
    as a restore whose original is gone, so the source's remove waits for the
    operator's review of the copy. Raises core.Unreadable on any read that
    fails: then the remove is refused."""
    own = _uuid(vm)
    for other in list(app.domains):
        try:
            if other is vm or core.name_of(other) == core.name_of(vm):
                continue
            tags = core.tags_of(other)
        except core.Gone:
            continue
        if not in_scope(tags):
            continue
        if HOLD not in tags and known(other):
            continue
        if own in (label_of(other), kept_of(other)):
            return True
    return False


def label(vm) -> None:
    """Label a qube dom0 has just made. Raises on any failure: a create that
    cannot label its qube is rolled back, as one that cannot stamp it is."""
    vm.features[ID] = _uuid(vm)
    if label_of(vm) != _uuid(vm):
        raise RuntimeError(f"the {ID} label did not read back")


def label_direct(app, name: str) -> None:
    """`label` for a disposable, through direct admin calls: qubesadmin's
    domain cache lags `admin.vm.CreateDisposable` by seconds."""
    text = app.qubesd_call(name, "admin.vm.property.Get", "uuid").decode(errors="replace")
    parts = text.split(" ", 2)
    uid = (parts[2] if len(parts) == 3 else "").strip().lower()
    if not uid:
        raise RuntimeError("the new qube's UUID did not read")
    app.qubesd_call(name, "admin.vm.feature.Set", ID, uid.encode())
    back = app.qubesd_call(name, "admin.vm.feature.Get", ID).decode(errors="replace")
    if back.strip().lower() != uid:
        raise RuntimeError(f"the {ID} label did not read back")


def label_if_missing(vm) -> None:
    """Label a qube that has no label, and leave one naming another UUID alone:
    that qube is held until the operator accepts it. The installer calls it on
    the hub before it gets `qmcp-anon`. Raises when the label cannot be read or
    written."""
    if label_of(vm) is None:
        label(vm)


class NotReviewed(RuntimeError):
    """A badge was about to go on a qube whose label names another qube's UUID, or on a
    badged one with no label."""


def require_label(vm) -> None:
    """Before dom0 gives a qube a badge: label it if it has no label and no
    badge, and refuse it if its label names another UUID, or if it already
    wears a badge with no label: either came back from a backup or a copy and
    waits for the operator's review, held or not yet. Raises."""
    if label_of(vm) is None:
        if in_scope(core.tags_of(vm)):
            raise NotReviewed(f"{core.name_of(vm)} wears qmcp badges with no label and waits "
                              f"for review (qmcp restored)")
        label(vm)
    if not labelled(vm):
        raise NotReviewed(f"{core.name_of(vm)} waits for review (qmcp restored)")


class Held:
    """What one pass did: qubes newly held, holds that failed, reads it could
    not make; `gone`, qubes removed by a call that was already running when
    they were held; `unsettled`, qubes held while a call kept their lock past
    both waits; `unowned`, qubes waiting for review whose owner badge it took
    off (a copy, or not proven a restore), `owner_kept`, those it proved a
    restore, and `owner_failed`, those whose decision failed (the next pass
    tries again, and accept strips the badge without a record). `judged` is
    False when the pass could not run at all."""

    __slots__ = ("held", "failed", "unread", "judged", "gone", "unsettled", "unowned",
                 "owner_kept", "owner_failed")

    def __init__(self):
        self.held, self.failed, self.unread, self.judged = [], [], [], True
        self.gone, self.unsettled, self.unowned, self.owner_failed = [], [], [], []
        self.owner_kept = []


def _owner_badges(vm) -> list:
    return sorted(t for t in core.tags_of(vm) if t.startswith(OWNER_PREFIX))


def kept_of(vm):
    """The `qmcp-owner-kept` record: the UUID of the qube the restore check
    proved a restore, or None. Raises core.Unreadable."""
    try:
        value = vm.features.get(KEPT, None)
    except Exception as e:
        raise core.Unreadable(f"cannot read the {KEPT} feature of {core.name_of(vm)}") from e
    return None if value is None else str(value).strip().lower()


def replaced_labels(path: str | None = None) -> set:
    """Every label an accept or a reject replaced (`REPLACED_PATH`); empty when
    none was. Raises core.Unreadable: a record that does not read proves no
    restore."""
    path = REPLACED_PATH if path is None else path
    try:
        with open(path, encoding="ascii") as fh:
            return {w for w in fh.read().split() if w}
    except FileNotFoundError:
        return set()
    except (OSError, UnicodeDecodeError) as e:
        raise core.Unreadable(f"{path} cannot be read ({type(e).__name__})") from None


def record_removed(vm) -> None:
    """Before the hub or a lead removes `vm`: record its UUID. Raises
    OSError or core.Unreadable: the remove is then refused."""
    own = _uuid(vm)
    if not is_uuid(own):
        raise core.Unreadable(f"the UUID of {core.name_of(vm)} is not one")
    old = os.umask(0o007)
    try:
        fd = os.open(os.path.join(REMOVED_DIR, own),
                     os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o660)
    finally:
        os.umask(old)
    try:
        os.utime(fd)                    # aged from this remove, not an earlier write
        os.fsync(fd)
    finally:
        os.close(fd)
    # And the entry itself, so a crash right after cannot keep the remove
    # and lose its record.
    dfd = os.open(REMOVED_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


#: How long the removal record keeps a UUID at least. It exists for a copy
#: being cloned while its source was removed; an entry goes only once it is
#: this old AND no qube's label names it, so a copy still undecided keeps it
#: however long the gate's timer was stopped.
REMOVED_KEEP_S = 7 * 86400


def prune_removed(app, now=None) -> int:
    """Drop the entries older than `REMOVED_KEEP_S` whose UUID no qube's
    `qmcp-id` label names: how many. Nothing at all unless every qube's label
    reads. Run hourly by root (`qmcp audit rotate --auto`); best-effort."""
    now = time.time() if now is None else now
    named = set()
    try:
        # A qube removed during the scan reads as unlabelled (qubesadmin's
        # feature read answers the default for a qube that is gone), which
        # is the right answer here; any read that fails keeps everything.
        for vm in list(app.domains):
            lab = label_of(vm)
            if lab is not None:
                named.add(lab)
    except Exception:
        return 0
    dropped = 0
    try:
        names = os.listdir(REMOVED_DIR)
    except OSError:
        return 0
    for n in names:
        if n in named:
            continue
        path = os.path.join(REMOVED_DIR, n)
        try:
            if now - os.lstat(path).st_mtime > REMOVED_KEEP_S:
                os.unlink(path)
                dropped += 1
        except OSError:
            continue
    return dropped


def removed_uuids() -> set:
    """The UUIDs AI space removed (`REMOVED_DIR`). Raises core.Unreadable,
    a missing record included: then no restore is proven."""
    try:
        return {n for n in os.listdir(REMOVED_DIR) if is_uuid(n)}
    except OSError as e:
        raise core.Unreadable(f"{REMOVED_DIR} cannot be read ({type(e).__name__})") from None


def keep_former_label(vm) -> None:
    """Before an accept rewrites the label, or a reject removes it: record the
    label it wore in dom0 (`REPLACED_PATH`), so a copy made earlier, which
    still wears it, never reads as a restore whose original is gone. Raises
    on any failure: the label stays as it was then."""
    lab = label_of(vm)
    if not is_uuid(lab) or lab == _uuid(vm):
        return                          # names no qube, so proves no restore
    path = REPLACED_PATH
    if lab in replaced_labels(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    try:
        os.fchmod(fd, 0o644)            # whatever the umask: the gate's user reads it
        os.write(fd, (lab + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if lab not in replaced_labels(path):
        raise RuntimeError(f"the replaced label did not read back from {path}")


class Origins:
    """Every qube's UUID and `qmcp-id` label, and the labels accepts and
    rejects replaced (`REPLACED_PATH`), read once per pass. `complete` is
    False when any read failed but that of a qube qubesd says is gone."""

    __slots__ = ("uuids", "labels", "former", "removed", "complete")

    def __init__(self, app):
        self.uuids, self.labels, self.former, self.removed = set(), {}, set(), set()
        self.complete = True
        try:
            domains = list(app.domains)
        except Exception:
            self.complete = False
            return
        for vm in domains:
            try:
                name = core.name_of(vm)
                self.uuids.add(_uuid(vm))
                lab = label_of(vm)
            except Exception:
                try:
                    gone = _is_gone(app, core.name_of(vm))
                except Exception:
                    gone = False
                if not gone:
                    self.complete = False
                continue
            if lab is not None:
                self.labels[lab] = self.labels.get(lab, 0) + 1
        # The record last: an accept writes it (and syncs it) before it
        # relabels, so a relabel the enumeration above saw is recorded by now,
        # and one it did not see left the old label on the qube it read.
        try:
            self.former = replaced_labels()
            self.removed = removed_uuids()
        except core.Unreadable:
            self.complete = False


def proven_restore(vm, origins) -> bool:
    """True only when every read succeeded and the qube's label names a UUID
    that no qube has now, and no other qube carries that label: a restore
    whose original is gone. A copy names a qube that exists, or shares its
    label with the qube it was copied from (a copy of a held restore, a second
    restore of one backup); a qube with no label, or its own, is not proven.
    Nor is one whose label an accept or a reject replaced (`REPLACED_PATH`):
    a copy of that qube made before then."""
    if origins is None or not origins.complete:
        return False
    try:
        lab, own = label_of(vm), _uuid(vm)
    except core.Unreadable:
        return False
    return (is_uuid(lab) and lab != own and lab not in origins.uuids
            and origins.labels.get(lab, 0) == 1 and lab not in origins.former
            and lab not in origins.removed)


def decide_owner(vm, origins):
    """For a qube waiting for review that wears an owner badge: decide once,
    and record it. A proven restore keeps the badge, and `qmcp-owner-kept`
    is set to its own UUID, so a copy of it (a new UUID) never inherits the
    decision; anything else loses every `qmcp-owner_*` badge: AI removes only
    what qmcp created, and a copy the operator made is not that. Returns
    "kept", "removed", or None when there was nothing to decide (no badge, or
    the record already names this qube). Raises when a badge did not come
    off or the record did not read back, and core.Unreadable or core.Gone
    from its own reads."""
    owners = _owner_badges(vm)
    if not owners:
        return None
    own = _uuid(vm)
    kept = kept_of(vm)
    if kept == own:
        return None
    # A record naming another qube that exists is that qube's decision, copied
    # with it: a copy of a decided restore, never a restore itself.
    copied = kept is not None and origins is not None and kept in origins.uuids
    if not copied and proven_restore(vm, origins):
        vm.features[KEPT] = own
        if kept_of(vm) != own:
            raise RuntimeError(f"the {KEPT} record did not read back")
        return "kept"
    for t in owners:
        vm.tags.discard(t)
    if _owner_badges(vm):
        raise RuntimeError("the owner badge did not come off")
    return "removed"


def hold(app, lock_wait: float | None = None) -> Held:
    """Put `qmcp-quarantine` on every qube in scope whose label does not match.
    Holds the create lock, so a qube being created is never seen between its
    create and its label. Best-effort per qube: a qube it cannot read or hold
    is reported and tried again next run."""
    out = Held()
    origins = None                  # read once, on the first qube that needs it
    try:
        fd = budget.acquire_create_lock(timeout=LOCK_WAIT_S if lock_wait is None else lock_wait,
                                        queue=True)
    except Exception:
        out.judged = False
        return out
    # Bounded in all, whatever AI space keeps in flight: the qube locks are
    # waited for until the pass's budget is spent, then not at all, and the
    # holds made without one settle together after the loop.
    deadline = time.monotonic() + HOLD_PASS_S
    unsettled = []
    try:
        for vm in list(app.domains):
            try:
                if core.klass_of(vm) == "AdminVM":
                    continue
                tags = core.tags_of(vm)
            except core.Gone:
                continue
            except core.Unreadable as e:
                out.unread.append(str(e))
                continue
            if not in_scope(tags):
                continue
            try:
                if known(vm):
                    continue
            except core.Unreadable as e:
                out.unread.append(str(e))
                continue
            name = core.name_of(vm)
            if HOLD in tags:
                # Already held (a copy of a held qube copies the hold, and
                # 0.9.36 held without deciding): its owner badge is decided here.
                _failure_cleared("hold", vm, name)
                origins = _decide(app, vm, name, out, origins)
                continue
            # The qube's own lock, briefly: a service already past its check
            # (a remove, a start) lands before the hold, and none after it. A
            # hold only takes authority away, so it goes on without the lock
            # when it cannot be had, and settles once the call has finished.
            try:
                qfd = core.acquire_qube_lock(
                    name, max(0.0, min(HOLD_LOCK_WAIT_S, deadline - time.monotonic())),
                    queue=True)
            except core.Refusal:
                qfd = None
            if qfd is not None:
                # Judged again under the lock: an accept that held it while
                # this pass waited has labelled the qube, and the operator was
                # told it was accepted.
                try:
                    # Still in scope, too: a reject or a revoke that finished
                    # while this pass waited took it out of AI space.
                    now = core.tags_of(vm)
                    again = HOLD in now or not in_scope(now) or known(vm)
                except core.Gone:
                    again = True
                except core.Unreadable as e:
                    out.unread.append(str(e))
                    again = True
                if again:
                    os.close(qfd)
                    continue
            try:
                vm.tags.add(HOLD)
                if HOLD not in core.tags_of(vm):
                    raise RuntimeError("the hold did not read back")
            except Exception as e:
                if _is_gone(app, name):
                    # A remove already running landed first: nothing is left to hold.
                    out.gone.append(name)
                    _audit(name, False, "removed by a call that was already running", app=app)
                else:
                    out.failed.append((name, type(e).__name__))
                    if _new_failure("hold", vm, name, type(e).__name__):
                        _audit(name, False, f"not held: {type(e).__name__}", app=app)
                continue
            finally:
                if qfd is not None:
                    os.close(qfd)
            if qfd is None:
                unsettled.append((vm, name))
                continue
            out.held.append(name)
            _failure_cleared("hold", vm, name)
            _audit(name, True, app=app)
            # Held first, then its owner badge decided: the hold is the larger
            # restriction, and a held qube's badge grants nothing until accept.
            origins = _decide(app, vm, name, out, origins)
        settle_by = time.monotonic() + HOLD_SETTLE_WAIT_S
        for vm, name in unsettled:
            if _settle(app, vm, name, out,
                       max(0.0, min(HOLD_SETTLE_WAIT_S, settle_by - time.monotonic()))):
                continue
            out.held.append(name)
            _failure_cleared("hold", vm, name)
            _audit(name, True, app=app)
            origins = _decide(app, vm, name, out, origins)
    finally:
        try:
            os.close(fd)
        except Exception:
            pass
    return out


def _decide(app, vm, name: str, out: Held, origins):
    """The pass's owner-badge decision for one qube waiting for review (see
    `decide_owner`). Returns the pass's Origins, read on first need."""
    try:
        if not _owner_badges(vm) or kept_of(vm) == _uuid(vm):
            _failure_cleared("owner", vm, name)
            return origins
        if origins is None:
            origins = Origins(app)
        what = decide_owner(vm, origins)
    except core.Gone:
        return origins
    except Exception as e:
        if _is_gone(app, name):
            return origins
        out.owner_failed.append((name, type(e).__name__))
        if _new_failure("owner", vm, name, type(e).__name__):
            _audit_owner(name, False, "not decided", f"{type(e).__name__}", app=app)
        return origins
    _failure_cleared("owner", vm, name)
    if what == "removed":
        out.unowned.append(name)
        _audit_owner(name, True, "removed: a copy, or not proven a restore", app=app)
    elif what == "kept":
        out.owner_kept.append(name)
        _audit_owner(name, True, "kept: a restore whose original is gone", app=app)
    return origins


#: The failure a pass last logged for one qube and one step (`hold`, `owner`),
#: keyed to the qube's UUID (a later qube of the same name is another qube), under
#: `core.RUN_DIR`: a step that keeps failing the same way leaves one
#: audit line, not one every 15 s, since a pass records what it changed. Every
#: pass still reports the failure (standard error, exit 3); a success, or a
#: failure of another kind, logs again; a boot clears them.
FAILED_PREFIX = "gate-failed."


def _failure_path(step: str, name: str, uuid: str) -> str:
    key = hashlib.sha256(f"{step}\0{name}\0{uuid}".encode()).hexdigest()[:32]
    return os.path.join(core.state_dir(), FAILED_PREFIX + key)


def _failure_key(vm, name: str):
    try:
        return _uuid(vm)
    except core.Unreadable:
        return None


def _new_failure(step: str, vm, name: str, reason: str) -> bool:
    """True when `reason` is not the failure last logged for this qube and
    step, and records it. A UUID, or a record, that cannot be read or written
    counts as new: a line too many is the safe side, a line missing is not."""
    uuid = _failure_key(vm, name)
    if uuid is None:
        return True
    path = _failure_path(step, name, uuid)
    core.state_dir_ready()
    try:
        if core.read_run_file(path, 256) == reason:
            return False
    except (OSError, ValueError):
        pass
    try:
        core.write_run_file(path, reason)
    except OSError:
        pass
    return True


def _failure_cleared(step: str, vm, name: str) -> None:
    uuid = _failure_key(vm, name)
    if uuid is None:
        return
    try:
        os.unlink(_failure_path(step, name, uuid))
    except OSError:
        pass


def _audit_owner(name: str, ok: bool, what: str, error: str | None = None, app=None) -> None:
    try:
        audit.audit(SERVICE, CALLER, {"qube": name[:128], "owner badge": what}, ok, error,
                    app=app)
    except Exception:
        pass


def _is_gone(app, name: str) -> bool:
    """True only when qubesd says the qube no longer exists."""
    try:
        clear = getattr(app.domains, "clear_cache", None)
        if clear is not None:
            clear()
        return name not in app.domains
    except Exception:
        return False


def _settle(app, vm, name: str, out: Held, wait: float | None = None) -> bool:
    """After a hold made without the qube's lock: wait for the lock again, so
    the call that held it has finished, then read the hold back. True when the
    qube is gone (that call removed it), or its hold could not be read back or
    put back, which `out` records; False otherwise: held, or not settled
    because the lock was not had again (`out.unsettled`)."""
    try:
        late = core.acquire_qube_lock(name, HOLD_SETTLE_WAIT_S if wait is None else wait,
                                      queue=True)
    except core.Refusal:
        late = None
    try:
        if late is None:
            # Still judged, without the lock: a reject or a revoke that took
            # the qube out of AI space meanwhile must not leave it held.
            try:
                if not in_scope(core.tags_of(vm) - {HOLD}):
                    vm.tags.discard(HOLD)
                    _audit(name, False, "taken out of AI space by a call that was already "
                                        "running", app=app)
                    return True
            except Exception:
                pass
            out.unsettled.append(name)
            return False
        if _is_gone(app, name):
            out.gone.append(name)
            _audit(name, False, "removed by a call that was already running", app=app)
            return True
        try:
            # An accept that was already running labelled the qube and told
            # the operator so, or a reject or a revoke took it out of AI
            # space: the hold this pass put on comes off again.
            if not in_scope(core.tags_of(vm) - {HOLD}):
                vm.tags.discard(HOLD)
                if HOLD in core.tags_of(vm):
                    raise RuntimeError("the hold did not come off")
                _audit(name, False, "taken out of AI space by a call that was already running",
                       app=app)
                return True
            if known(vm):
                vm.tags.discard(HOLD)
                if HOLD in core.tags_of(vm):
                    raise RuntimeError("the hold did not come off")
                _audit(name, False, "accepted by a call that was already running", app=app)
                return True
            if HOLD not in core.tags_of(vm):
                vm.tags.add(HOLD)
                if HOLD not in core.tags_of(vm):
                    raise RuntimeError("the hold did not read back")
        except Exception as e:
            out.failed.append((name, type(e).__name__))
            if _new_failure("hold", vm, name, type(e).__name__):
                _audit(name, False, f"not held: {type(e).__name__}", app=app)
            return True
        return False
    finally:
        if late is not None:
            os.close(late)


def _audit(name: str, ok: bool, error: str | None = None, app=None) -> None:
    try:
        audit.audit(SERVICE, CALLER, {"qube": name[:128], "held": "label does not match"},
                    ok, error, app=app)
    except Exception:
        pass


def notify(held: Held) -> None:
    """One desktop notice per qube newly held, with fixed text and the qube's
    name, which qubesd restricts to letters, digits and `_.-`."""
    from qmcp import anon
    for name in held.held:
        try:
            anon.notify(NOTICE.format(name=name))
        except Exception:
            pass


# ------------------------------------------------------------------ review

def _role(name: str, tags, records: dict) -> tuple:
    """(what its badges make it, [why that disagrees with the records]). An
    empty list means the badges agree with the records as they are now."""
    tags = set(tags)
    roles, why = [], []
    for slot in sorted(projects.lead_slots(tags)):
        roles.append(f"lead of {slot}")
        p = records.get(slot)
        if p is None or p.lead != name:
            why.append(f"{slot}'s record names "
                       f"{'no such project' if p is None else (p.lead or 'no lead')} as lead")
    for slot in sorted(projects.member_slots(tags)):
        roles.append(f"member of {slot}")
        if slot != projects.HUB_SLOT and slot not in records:
            why.append(f"no project holds {slot}")
    for tag in sorted(tags):
        parts = projects.slot_badge_parts(tag)
        if parts is None:
            continue
        kind, slot = parts
        p = records.get(slot)
        if kind == "dump":
            roles.append(f"dump sink of {slot}")
            if p is None or p.dump != name:
                why.append(f"{slot}'s record names {getattr(p, 'dump', None) or 'no sink'}")
        elif kind == "model":
            roles.append(f"model qube of {slot}")
            if p is None or p.model_qube != name:
                why.append(f"{slot}'s record names "
                           f"{getattr(p, 'model_qube', None) or 'no model qube'}")
    if core.OPEN in tags or core.OPEN_FW in tags:
        roles.append("open window")
        why.append("an open window's badge, which no window record backs")
    if not roles:
        roles.append("guarded" if core.GUARDED in tags else
                     "managed" if core.UMBRELLA in tags else
                     "drop box" if projects.DROP_BOX in tags else "badged")
    return ", ".join(roles), why


def review(app, records) -> list:
    """Every qube waiting for review, as rows: one in scope whose label does not
    match, held or not yet, and one held whatever its label says (an accept that
    labelled it and stopped before lifting the hold). Fields: name, held, label
    (`none`, `another qube's` or `its own`), badges, role, agrees, why. With
    `records` None (they could not be read) `agrees` and `why` are None: not
    known, never "disagrees". A qube that cannot be read is a row with
    `unreadable` set."""
    rows = []
    for vm in list(app.domains):
        try:
            if core.klass_of(vm) == "AdminVM":
                continue
            tags = core.tags_of(vm)
        except core.Gone:
            continue
        except core.Unreadable as e:
            rows.append({"name": getattr(vm, "name", "?"), "unreadable": str(e)})
            continue
        if not in_scope(tags):
            continue
        name = core.name_of(vm)
        try:
            lab = label_of(vm)
            own = lab is not None and lab == _uuid(vm)
            if not own and HOLD not in tags and born_of_its_template(vm, lab):
                continue
        except core.Unreadable as e:
            rows.append({"name": name, "unreadable": str(e)})
            continue
        if own and HOLD not in tags:
            continue
        role, why = _role(name, tags, records or {})
        rows.append({"name": name, "held": HOLD in tags,
                     "label": "its own" if own else "none" if lab is None else "another qube's",
                     "badges": sorted(t for t in tags if t != HOLD and
                                      (t in (core.UMBRELLA, projects.DROP_BOX)
                                       or t.startswith("qmcp-"))),
                     "role": role, "agrees": None if records is None else not why,
                     "why": None if records is None else why})
    return sorted(rows, key=lambda r: r["name"])


def before_export(app) -> list:
    """What `qmcp export` warns about: [] when no qube waits for review. A
    restore gives every qube a new identity, so after one every AI qube is
    held alike, and `restored accept --all` takes a qube held now (a hand
    `qvm-clone`, say) with the rest: its review would be skipped. So the
    export names each qube waiting for review now, held or about to be, and
    each whose state cannot be read; a list that cannot be read at all is
    said so too, never "nothing waits". The export is written either way: it
    is a backup step, not a gate."""
    try:
        rows = review(app, None)
    except Exception as e:
        return [f"whether any qube is held for review could not be read "
                f"({type(e).__name__}): run qmcp restored list before you back up"]
    waiting = [r["name"] for r in rows if "unreadable" not in r]
    unread = [r["name"] for r in rows if "unreadable" in r]
    out = []
    if waiting:
        out.append(f"held for review, or about to be: {', '.join(waiting)}. Accept or reject "
                   f"each before you back up (sudo qmcp restored accept QUBE, or reject QUBE): "
                   f"after a restore every AI qube is held alike, and restored accept --all "
                   f"takes these with the rest")
    if unread:
        one = len(unread) == 1
        out.append(f"whether {', '.join(unread)} {'is' if one else 'are'} held for review is "
                   f"not known, since {'it' if one else 'they'} cannot be read now: qmcp "
                   f"restored list, then accept or reject {'it' if one else 'each'} before "
                   f"you back up")
    return out


class ReviewError(Exception):
    pass


def _subject(app, name: str):
    vm = core.lookup(app, name)
    if vm is None or core.klass_of(vm) == "AdminVM":
        raise ReviewError(f"no qube '{name}'")
    tags = core.tags_of(vm)
    if not in_scope(tags):
        raise ReviewError(f"'{name}' carries no qmcp badge")
    if HOLD not in tags and (labelled(vm) or born_of_its_template(vm, label_of(vm))):
        raise ReviewError(f"'{name}' is not waiting for review")
    return vm, tags


def _locked(name: str, must: bool, fn):
    """`fn()` under the qube's lock (`core.qube_lock`): an accept, which
    gives authority back, refuses when it is held past the wait; a reject,
    which takes it away, goes on without it."""
    if not core.valid_qube_name(name):
        raise ReviewError(f"no qube '{name}'")
    from qmcp import fleet
    try:
        lock = core.qube_lock(name, must=must)
        held = lock.__enter__()
    except core.QubeBusy as e:
        raise ReviewError(str(e)) from None
    except core.Refusal as r:
        if must:
            raise ReviewError(f"'{name}''s lock cannot be taken ({r.payload.get('error')}), so "
                              f"nothing was changed") from None
        return fn() + fleet.UNLOCKED
    try:
        return fn() + ("" if held else fleet.UNLOCKED)
    finally:
        lock.__exit__(None, None, None)


def accept(app, name: str) -> str:
    """Take off an owner badge the pass did not record as kept, label the
    qube, then lift its hold, under its lock. Its other badges stay as they
    came back: `qmcp check` judges them against the records from here on."""
    return _locked(name, True, lambda: _accept(app, name))


def _accept(app, name: str) -> str:
    vm, tags = _subject(app, name)
    # An owner badge stays only where the pass recorded this qube a proven
    # restore; any other (not decided yet, or its decision failed) comes off
    # here, before the label makes the qube known.
    unowned = False
    owners = _owner_badges(vm)
    if owners and kept_of(vm) != _uuid(vm):
        for t in owners:
            vm.tags.discard(t)
        if _owner_badges(vm):
            raise RuntimeError("the owner badge did not come off")
        unowned = True
    keep_former_label(vm)
    label(vm)
    # Whether this read saw the hold or the gate's pass put it on meanwhile.
    if HOLD in tags or HOLD in core.tags_of(vm):
        vm.tags.discard(HOLD)
        if HOLD in core.tags_of(vm):
            raise RuntimeError("the hold did not come off")
    if unowned:
        return (f"{name}: accepted; its owner badge came off (the restore check had not "
                f"recorded it a restore: only you remove it), its other badges stay as they "
                f"came back")
    return f"{name}: accepted; its badges stay as they came back"


def reject(app, name: str) -> str:
    """Take every qmcp badge off, the umbrella and the drop-box badge included:
    the routed ones first, the hold last, so no moment leaves it routed and
    unheld. The qube and its data stay. Under its lock, as `accept`."""
    return _locked(name, False, lambda: _reject(app, name))


def _reject(app, name: str) -> str:
    from qmcp import fleet
    # The hub is the hub by its file, not by a badge: a reject would take the
    # gate's stop off it and leave it a caller. Refused, as every role command
    # refuses it, and while the file does not read, since it may be the hub.
    hub = core.read_hub()
    if hub is None:
        raise ReviewError(f"{core.HUB_PATH} cannot be read, so '{name}' may be the hub, which a "
                          f"reject would free from the gate's stop; nothing was changed")
    if name == hub:
        raise ReviewError(f"'{name}' is the hub, which is the hub by its file and not by a badge: "
                          f"a reject would take the gate's stop off it and leave it a caller. "
                          f"Accept it (qmcp restored accept {name}: the hold lifts, any stop "
                          f"stays); the hub changes only through uninstall.sh --purge and a "
                          f"fresh install")
    vm, tags = _subject(app, name)
    keep_former_label(vm)
    strip = {t for t in tags if t != HOLD and
             (t in (core.UMBRELLA, core.GUARDED, projects.DROP_BOX) or t.startswith("qmcp-"))}
    fleet._set_tags(vm, remove=strip)
    # The hold last, and whether this read saw it or the gate's pass put it on
    # while the strip ran: a qube out of AI space is never left held.
    if HOLD in tags or HOLD in core.tags_of(vm):
        fleet._set_tags(vm, remove={HOLD})
    # The label it came back with goes too: it is an ordinary qube now, and the
    # operator bringing it back into AI space later labels it afresh.
    try:
        del vm.features[ID]
    except KeyError:
        pass
    return (f"{name}: taken out of AI space ({len(strip)} badge(s) off, its label removed); "
            f"the qube and its data stay")


def findings(app, add, unread: list | None = None) -> None:
    """`qmcp check`'s items: amber for each qube waiting for review, red for
    one in scope whose label does not match and that the pass has not held."""
    rows = review(app, None)
    held = [r["name"] for r in rows if r.get("held")]
    loose = [r["name"] for r in rows if not r.get("held") and "unreadable" not in r]
    bad = [r["unreadable"] for r in rows if "unreadable" in r]
    if loose:
        add("fail", "restored qubes",
            f"badged qube(s) dom0 did not label, not yet held: {', '.join(loose)} "
            f"(the gate's next run holds them; qmcp restored list)")
    if held:
        add("warn", "restored qubes",
            f"held for your review: {', '.join(held)} (qmcp restored list, then accept or reject)")
    if not loose and not held and not bad:
        add("pass", "restored qubes", "none waiting for review")
    for msg in bad:
        add("error", "restored qubes", msg)
