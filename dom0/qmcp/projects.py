"""qmcp.projects — project records and slot badges.

Sixteen slots, p00 to p15. p00 holds the hub's own working qubes. p01 to p15
are projects: one lead, its workers, and optionally a dump sink. A slot lives
in two places, and the two must agree:

- the BADGES dom0 writes on qubes, which the static rulebook matches:
    qmcp-proj-pNN               a member (a project's worker, or a hub qube in p00)
    qmcp-lead + qmcp-lead-pNN   the project's lead, which wears no member badge
    qmcp-dump-pNN               the slot's dump sink (with ai-dump; never in AI space)
    qmcp-model-pNN              the slot's self-hosted model qube (guarded; never a
                                member or a lead), which the lead reaches over
                                qubes.ConnectTCP on port 11434
- the RECORD in /etc/qmcp/projects.json, which holds what a tag cannot: the
  label (and with it the project's name space), the lead's name, the approved
  templates, the worker networks, the disk quota, the dump sink's name, and,
  once set, the lead's model: a remote endpoint (`model`) or a self-hosted model
  qube (`model_qube`), never both; and the firewall the operator accepted for
  the lead (`lead_firewall`); and, for an anonymous project (0.9.23), `anonymous`,
  `hidden` when the hub may not see it, and the operator's private `note`. Those
  keys are written only when set, so a record without them stays in the format
  of 0.9.18 to 0.9.20.

Four more badges carry an anonymous project (0.9.23): `qmcp-anon` on its lead
and every member (the anonymity gate watches it, `qmcp.anon`),
`qmcp-hubblind` on every qube of a hidden one (the rulebook keeps the hub out,
and the services leave it out of the hub's reads), `qmcp-blocked`, which the
gate puts on the lead and members of a project it stopped (the rulebook
refuses every call into it), and `qmcp-stopped` on each of those it knows to
be down. An anonymous project's label is random, picked by dom0, so a name an agent
leaks links to nothing; the operator tells projects apart by the note, which
only the window and the `qmcp` command show.

The record file is root-owned. The operator's `qmcp project` commands write
it, under a lock and by atomic rename (the installer writes it empty); the
services only read it. Every
reader fails closed: a file that exists but cannot be read or validated means
that no lead is recognised, so every lead's call is refused (the hub's creates
do not read it). An absent file means no project has been created yet.

A project's name space is the hub's name prefix, its label and a dash
(`ai-osint-`). A label is 1 to 8 lowercase letters or digits. With no dash
inside a label, no project's space can contain another's, and the hub is
refused names inside any of them. A lead therefore collides only with its own
workers, or with a qube the operator named inside its space or moved out of
it, which `qmcp check` lists.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile

from qmcp import firewall

SLOTS = tuple(f"p{n:02d}" for n in range(16))
HUB_SLOT = "p00"
PROJECT_SLOTS = SLOTS[1:]

PROJECTS_PATH = "/etc/qmcp/projects.json"
LOCK_PATH = "/run/qmcp/projects.lock"
VERSION = 1

LEAD = "qmcp-lead"
MEMBER_PREFIX = "qmcp-proj-"
LEAD_PREFIX = "qmcp-lead-"
DUMP_PREFIX = "qmcp-dump-"
MODEL_PREFIX = "qmcp-model-"
DROP_BOX = "ai-dump"
#: An anonymous project's lead and members (the gate watches them).
ANON = "qmcp-anon"
#: Every qube of a hidden anonymous project: the hub may not reach or see it.
HUBBLIND = "qmcp-hubblind"
#: A qube the anonymity gate stopped: the rulebook refuses every call into it.
BLOCKED = "qmcp-blocked"
#: A blocked qube the gate stopped for a violation and knows to be down: one
#: running again was started by the operator, by hand, and the gate leaves it.
STOPPED = "qmcp-stopped"
#: The port a lead reaches its slot's model qube on (the rulebook's A6 lines).
MODEL_PORT = 11434

_SLOT_BADGE_RE = re.compile(r"\Aqmcp-(proj|lead|dump|model)-(p[0-9]{2})\Z")
LABEL_RE = re.compile(r"\A[a-z0-9]{1,8}\Z")
#: Labels a command could not tell from a slot or a keyword.
_RESERVED_LABEL_RE = re.compile(r"\Ap[0-9]{2}\Z")
#: The hub creates qubes only as `<prefix>hub-…`, so `hub` is never a project's label.
HUB_LABEL = "hub"
RESERVED_LABELS = frozenset({"none", HUB_LABEL})
_QUBE_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9_.-]{0,30}\Z")

#: A random label is this long: 36^7 names after its first letter.
RANDOM_LABEL_LEN = 8
MAX_NOTE = 80
_NOTE_RE = re.compile(r"\A[\x20-\x7e]{1,%d}\Z" % MAX_NOTE)
MAX_TEMPLATES = 16
MAX_NETWORKS = 8
#: A quota past any disk (1 EiB): bigger numbers would only overflow arithmetic.
MAX_QUOTA = 2 ** 60


class ProjectsUnreadable(Exception):
    """The record file exists but cannot be read or does not validate."""


def member_badge(slot: str) -> str:
    return f"{MEMBER_PREFIX}{slot}"


def lead_badge(slot: str) -> str:
    return f"{LEAD_PREFIX}{slot}"


def dump_badge(slot: str) -> str:
    return f"{DUMP_PREFIX}{slot}"


def model_badge(slot: str) -> str:
    return f"{MODEL_PREFIX}{slot}"


def slot_badge_parts(tag: str):
    """(kind, slot) for a slot badge (kind: proj, lead, dump or model), else None."""
    m = _SLOT_BADGE_RE.match(tag)
    if not m or m.group(2) not in SLOTS:
        return None
    return m.group(1), m.group(2)


def is_slot_tag(tag: str) -> bool:
    return tag == LEAD or slot_badge_parts(tag) is not None


def member_slots(tags) -> set:
    return {p[1] for p in map(slot_badge_parts, tags) if p and p[0] == "proj"}


def lead_slots(tags) -> set:
    return {p[1] for p in map(slot_badge_parts, tags) if p and p[0] == "lead"}


def model_slots(tags) -> set:
    """The slots whose lead reaches this qube as its model qube."""
    return {p[1] for p in map(slot_badge_parts, tags) if p and p[0] == "model"}


def label_refusal(label) -> str | None:
    """None if `label` may name a project, else why not."""
    if not isinstance(label, str) or not LABEL_RE.match(label):
        return "a label is 1-8 lowercase letters or digits"
    if _RESERVED_LABEL_RE.match(label) or label in RESERVED_LABELS:
        return f"'{label}' could be read as a slot or a keyword; choose another label"
    return None


def valid_qube_name(name) -> bool:
    return isinstance(name, str) and _QUBE_RE.match(name) is not None


def note_refusal(note) -> str | None:
    """None if `note` may be an anonymous project's private note, else why not.
    Printable ASCII, so no line break or bidi control ever reaches the window."""
    if not isinstance(note, str) or not _NOTE_RE.match(note):
        return f"a note is 1-{MAX_NOTE} printable ASCII characters"
    return None


def random_label(taken, prefix: str = "ai-") -> str:
    """A label no project has, for an anonymous project: a letter, then
    lowercase letters and digits, so its dump sink `<label>-dump` is a qube
    name, and never one that starts with the reserved name prefix."""
    import secrets
    first, rest = "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz0123456789"
    while True:
        label = secrets.choice(first) + "".join(secrets.choice(rest)
                                                for _ in range(RANDOM_LABEL_LEN - 1))
        if label not in taken and label_refusal(label) is None \
                and not f"{label}-dump".startswith(prefix):
            return label


class Project:
    """One slot's record. p00 carries only `dump`."""

    __slots__ = ("slot", "label", "lead", "templates", "networks", "quota", "dump",
                 "model", "lead_firewall", "model_qube", "anonymous", "hidden", "note")

    def __init__(self, slot, label=None, lead=None, templates=(), networks=(), quota=None,
                 dump=None, model=None, lead_firewall=None, model_qube=None,
                 anonymous=False, hidden=False, note=None):
        self.slot, self.label, self.lead = slot, label, lead
        self.templates = tuple(templates)
        self.networks = tuple(networks)
        self.quota, self.dump = quota, dump
        self.model = model
        self.lead_firewall = None if lead_firewall is None else tuple(lead_firewall)
        self.model_qube = model_qube
        self.anonymous = bool(anonymous)
        self.hidden = bool(anonymous and hidden)
        self.note = note

    def badges(self) -> set:
        """The badges every lead and member of this project wears besides its
        slot badges: `qmcp-anon` for an anonymous one, and `qmcp-hubblind` for
        a hidden one."""
        return ({ANON} if self.anonymous else set()) | ({HUBBLIND} if self.hidden else set())

    def space(self, prefix: str) -> str:
        """The project's name space, e.g. `ai-osint-`."""
        return f"{prefix}{self.label}-"

    def named_networks(self) -> tuple:
        return tuple(n for n in self.networks if n is not None)

    def to_json(self) -> dict:
        if self.slot == HUB_SLOT:
            return {"dump": self.dump}
        out = {"label": self.label, "lead": self.lead, "templates": list(self.templates),
               "networks": list(self.networks), "quota": self.quota, "dump": self.dump}
        if self.model is not None:
            out["model"] = self.model
        if self.lead_firewall is not None:
            out["lead_firewall"] = list(self.lead_firewall)
        if self.model_qube is not None:
            out["model_qube"] = self.model_qube
        if self.anonymous:
            out["anonymous"] = True
        if self.hidden:
            out["hidden"] = True
        if self.note is not None:
            out["note"] = self.note
        return out

    def __repr__(self):
        return f"<Project {self.slot} {self.label or 'hub'}>"


def _bad(why: str) -> ProjectsUnreadable:
    return ProjectsUnreadable(why)


def _validate_slot(slot: str, entry) -> Project:
    if not isinstance(entry, dict):
        raise _bad(f"{slot}: not an object")
    if slot == HUB_SLOT:
        extra = set(entry) - {"dump"}
        if extra:
            raise _bad(f"{slot}: unexpected keys {sorted(extra)}")
        dump = entry.get("dump")
        if dump is not None and not valid_qube_name(dump):
            raise _bad(f"{slot}: bad dump")
        return Project(slot, dump=dump)
    want = {"label", "lead", "templates", "networks", "quota", "dump"}
    optional = {"model", "lead_firewall", "model_qube", "anonymous", "hidden", "note"}
    if not want <= set(entry) <= want | optional:
        raise _bad(f"{slot}: keys must be {sorted(want)}, and optionally {sorted(optional)}")
    label = entry["label"]
    if label_refusal(label):
        raise _bad(f"{slot}: bad label")
    lead = entry["lead"]
    if lead is not None and not valid_qube_name(lead):
        raise _bad(f"{slot}: bad lead")
    templates = entry["templates"]
    if (not isinstance(templates, list) or not 1 <= len(templates) <= MAX_TEMPLATES
            or not all(valid_qube_name(t) for t in templates)
            or len(set(templates)) != len(templates)):
        raise _bad(f"{slot}: templates must be 1-{MAX_TEMPLATES} distinct qube names")
    networks = entry["networks"]
    if (not isinstance(networks, list) or not 1 <= len(networks) <= MAX_NETWORKS
            or not all(n is None or valid_qube_name(n) for n in networks)
            or len(set(networks)) != len(networks)):
        raise _bad(f"{slot}: networks must be 1-{MAX_NETWORKS} distinct qube names or null")
    quota = entry["quota"]
    if isinstance(quota, bool) or not isinstance(quota, int) or not 0 < quota <= MAX_QUOTA:
        raise _bad(f"{slot}: quota must be a positive integer number of bytes, at most 1 EiB")
    dump = entry["dump"]
    if dump is not None and not valid_qube_name(dump):
        raise _bad(f"{slot}: bad dump")
    model = entry.get("model")
    if model is not None:
        try:
            if firewall.model_text(model) != model:
                raise firewall.FirewallError("not canonical")
        except firewall.FirewallError:
            raise _bad(f"{slot}: model must be host:port") from None
    lead_firewall = entry.get("lead_firewall")
    if lead_firewall is not None and firewall.rules_refusal(lead_firewall):
        raise _bad(f"{slot}: lead_firewall must be 1-{firewall.MAX_RULES} firewall rules")
    model_qube = entry.get("model_qube")
    if model_qube is not None and not valid_qube_name(model_qube):
        raise _bad(f"{slot}: bad model_qube")
    if model is not None and model_qube is not None:
        raise _bad(f"{slot}: a lead's model is an endpoint or a model qube, not both")
    # Written only when true, so a present key is never false.
    anonymous, hidden, note = entry.get("anonymous"), entry.get("hidden"), entry.get("note")
    if anonymous is not None and anonymous is not True:
        raise _bad(f"{slot}: anonymous is true, or absent")
    if hidden is not None and (hidden is not True or anonymous is not True):
        raise _bad(f"{slot}: hidden is true, and only on an anonymous project")
    if note is not None and (anonymous is not True or note_refusal(note)):
        raise _bad(f"{slot}: note is 1-{MAX_NOTE} printable characters, on an anonymous project")
    return Project(slot, label, lead, templates, networks, quota, dump, model, lead_firewall,
                   model_qube, anonymous is True, hidden is True, note)


def parse(text: str) -> dict:
    """slot -> Project, from the file's text. Raises ProjectsUnreadable."""
    try:
        doc = json.loads(text)
    except ValueError:
        raise _bad("not JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != VERSION or set(doc) != {"version", "slots"}:
        raise _bad(f"top level must be {{'version': {VERSION}, 'slots': {{...}}}}")
    slots = doc["slots"]
    if not isinstance(slots, dict) or not set(slots) <= set(SLOTS):
        raise _bad("slots must map p00..p15 to records")
    out = {slot: _validate_slot(slot, entry) for slot, entry in slots.items()}
    out.setdefault(HUB_SLOT, Project(HUB_SLOT))
    labels = [p.label for p in out.values() if p.label]
    if len(set(labels)) != len(labels):
        raise _bad("labels must be unique")
    leads = [p.lead for p in out.values() if p.lead]
    if len(set(leads)) != len(leads):
        raise _bad("a qube leads at most one project")
    return out


def load(path: str | None = None) -> dict:
    """slot -> Project. Absent file: only p00. Present but bad: raises."""
    path = PROJECTS_PATH if path is None else path
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(1024 * 1024 + 1)
    except FileNotFoundError:
        return {HUB_SLOT: Project(HUB_SLOT)}
    except OSError as e:
        raise _bad(f"cannot read ({type(e).__name__})") from None
    if len(text) > 1024 * 1024:
        raise _bad("file too large")
    return parse(text)


def by_lead(projects: dict, name: str):
    """The project `name` leads, or None."""
    for p in projects.values():
        if p.lead is not None and p.lead == name:
            return p
    return None


def by_label(projects: dict, label: str):
    for p in projects.values():
        if p.label is not None and p.label == label:
            return p
    return None


def find(projects: dict, key: str):
    """A project by slot (p03) or label (osint), or None."""
    if key in projects:
        return projects[key]
    return by_label(projects, key)


def free_slots(projects: dict) -> list:
    return [s for s in PROJECT_SLOTS if s not in projects]


# ----------------------------------------------------------------- writing (operator only)

def dump_json(projects: dict) -> str:
    slots = {s: projects[s].to_json() for s in SLOTS if s in projects
             and not (s == HUB_SLOT and projects[s].dump is None)}
    return json.dumps({"version": VERSION, "slots": slots}, indent=2, sort_keys=True) + "\n"


class Locked:
    """The operator's exclusive lock over the record file, for read-modify-write."""

    def __init__(self, path: str | None = None, timeout: float = 30.0):
        self.path = LOCK_PATH if path is None else path
        self.timeout, self.fd = timeout, None

    def __enter__(self):
        import time
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    raise RuntimeError("another qmcp project command holds the lock") from None
                time.sleep(0.2)

    def __exit__(self, *exc):
        os.close(self.fd)
        return False


def save(projects: dict, path: str | None = None) -> None:
    """Validate, then replace the file atomically (same directory, fsync, rename)."""
    path = PROJECTS_PATH if path is None else path
    text = dump_json(projects)
    parse(text)
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".projects.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
