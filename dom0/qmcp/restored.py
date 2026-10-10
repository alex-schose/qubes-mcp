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
  keeps the badges it came back with, so the review can show them.
- `review(app, records)` lists every such qube, with the role its badges name
  and whether that agrees with the records today.
- `accept(app, name)` labels the qube first and only then lifts the hold, so a
  failure leaves it held. `reject(app, name)` takes every qmcp badge off, the
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

import os

from qmcp import audit, budget, core, projects

ID = core.ID_FEATURE
HOLD = core.QUARANTINE
SERVICE = "qmcp gate"
CALLER = "gate"
#: How long the pass waits for a create in flight. Short: the anonymity gate
#: runs right after it, and a pass that cannot have the lock judges nothing
#: this time and says so.
LOCK_WAIT_S = 5
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
    not make. `judged` is False when the pass could not run at all."""

    __slots__ = ("held", "failed", "unread", "judged")

    def __init__(self):
        self.held, self.failed, self.unread, self.judged = [], [], [], True


def hold(app, lock_wait: float | None = None) -> Held:
    """Put `qmcp-quarantine` on every qube in scope whose label does not match.
    Holds the create lock, so a qube being created is never seen between its
    create and its label. Best-effort per qube: a qube it cannot read or hold
    is reported and tried again next run."""
    out = Held()
    try:
        fd = budget.acquire_create_lock(timeout=LOCK_WAIT_S if lock_wait is None else lock_wait)
    except Exception:
        out.judged = False
        return out
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
            if not in_scope(tags) or HOLD in tags:
                continue
            try:
                if known(vm):
                    continue
            except core.Unreadable as e:
                out.unread.append(str(e))
                continue
            name = core.name_of(vm)
            try:
                vm.tags.add(HOLD)
                if HOLD not in core.tags_of(vm):
                    raise RuntimeError("the hold did not read back")
            except Exception as e:
                out.failed.append((name, type(e).__name__))
                _audit(name, False, f"not held: {type(e).__name__}")
                continue
            out.held.append(name)
            _audit(name, True)
    finally:
        try:
            os.close(fd)
        except Exception:
            pass
    return out


def _audit(name: str, ok: bool, error: str | None = None) -> None:
    try:
        audit.audit(SERVICE, CALLER, {"qube": name[:128], "held": "label does not match"},
                    ok, error)
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


class ReviewError(Exception):
    pass


def _subject(app, name: str):
    vm = core.lookup(app, name)
    if vm is None or core.klass_of(vm) == "AdminVM":
        raise ReviewError(f"no qube '{name}'")
    tags = core.tags_of(vm)
    if not in_scope(tags):
        raise ReviewError(f"'{name}' carries no qmcp badge")
    if labelled(vm) and HOLD not in tags:
        raise ReviewError(f"'{name}' is not waiting for review")
    return vm, tags


def accept(app, name: str) -> str:
    """Label the qube, then lift its hold. Its badges stay as they came back:
    `qmcp check` judges them against the records from here on."""
    vm, tags = _subject(app, name)
    label(vm)
    if HOLD in tags:
        vm.tags.discard(HOLD)
        if HOLD in core.tags_of(vm):
            raise RuntimeError("the hold did not come off")
    return f"{name}: accepted; its badges stay as they came back"


def reject(app, name: str) -> str:
    """Take every qmcp badge off, the umbrella and the drop-box badge included:
    the routed ones first, the hold last, so no moment leaves it routed and
    unheld. The qube and its data stay."""
    from qmcp import fleet
    vm, tags = _subject(app, name)
    strip = {t for t in tags if t != HOLD and
             (t in (core.UMBRELLA, core.GUARDED, projects.DROP_BOX) or t.startswith("qmcp-"))}
    fleet._set_tags(vm, remove=strip)
    if HOLD in tags:
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
