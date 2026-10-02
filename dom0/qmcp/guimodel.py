"""qmcp.guimodel — what the operator's window decides, without GTK.

The window (`qmcp.gui`, started as `qmcp-gui`) is a front end over the `qmcp`
command, never a second implementation of it:

- it reads by running `qmcp ...` (JSON wherever the command offers it) as the
  operator's own dom0 user, and changes things only by running
  `/usr/bin/sudo -n qmcp ...`, the command a person would type, which it then
  shows. It never imports qubesadmin and never runs as root, so it can do
  nothing the command cannot, and every change it makes has a command the
  operator can read and replay;
- every string it displays passes through `esc()`, which shows text the way
  the command's JSON does. The audit log keeps text the hub or a lead chose
  (the names, keys and options of every call to a state-changing service,
  never a value being set, up to 128 characters each and logged before they
  are checked), so a newline, a bidi override or markup in it must reach the
  screen as visible escapes, never as layout;
- roles come from the project records and the badges, never from a qube's
  label colour, which the hub may set.

It cannot go stale: `tests/test_gui.py` walks the command's parser and the
JSON each read returns, and fails on any command, option or field the window
neither offers nor exempts here by name, with a reason.
"""
from __future__ import annotations

import json
import shlex

from qmcp import birth, fleet, projects

QMCP = "/usr/local/bin/qmcp"
SUDO = ("/usr/bin/sudo", "-n")
#: Audit lines the viewer reads.
AUDIT_TAIL = 200


# ======================================================================= text

class Shown(str):
    """Text that has been through `esc()` or `esc_lines()`: the only kind the
    window's widgets accept. Joining or formatting gives a plain `str` again,
    which they refuse, so composed text must be built raw and escaped once.
    Only `esc()`, `esc_lines()` and `audit_detail()` (which joins their
    output) make one; a test holds the module to that."""
    __slots__ = ()


def esc(value) -> Shown:
    """Text for a widget, shown as the command's JSON shows it.

    A string comes out printable ASCII: every control, format and non-ASCII
    character, DEL included, becomes a visible escape (`\\n`, `\\u202e`), as
    `json.dumps` with `ensure_ascii` writes it. Lists and dicts are shown as
    compact JSON. Names Qubes accepts are ASCII already, so they look
    unchanged."""
    if value is None:
        return Shown("-")
    if isinstance(value, bool):
        return Shown("yes" if value else "no")
    if isinstance(value, int):
        return Shown(str(value))
    if isinstance(value, str):
        text = json.dumps(value, ensure_ascii=True)[1:-1]
    else:
        try:
            text = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(", ", ": "))
        except (TypeError, ValueError):
            text = json.dumps(repr(value), ensure_ascii=True)[1:-1]
    return Shown(text)


def esc_lines(text) -> Shown:
    """The command's own multi-line output (a report, an error): each line
    escaped, the line breaks kept, so a report still reads as one."""
    return Shown("\n".join(esc(line) for line in str(text).splitlines()))


def size(n) -> Shown:
    if n is None:
        return esc(None)
    if not isinstance(n, int) or isinstance(n, bool):
        return esc(n)
    return esc(f"{n / 1024 ** 3:.1f} GiB")


def quota_text(n) -> str:
    """A quota as the command accepts it back: whole GiB as `20G`, else bytes."""
    if not isinstance(n, int) or isinstance(n, bool):
        return ""
    return f"{n // 1024 ** 3}G" if n % 1024 ** 3 == 0 else str(n)


# ======================================================================= commands

def read_cmd(*args) -> list:
    return [QMCP, *args]


def write_cmd(*args) -> list:
    return [*SUDO, QMCP, *args]


def shown(argv) -> Shown:
    """The command as the window shows it: exactly what ran, quoted for a shell."""
    return esc(shlex.join(argv))


#: Everything a refresh runs, as the operator's own dom0 user.
READS = {
    "fleet": read_cmd("list", "--all", "--json"),
    "projects": read_cmd("project", "list", "--json"),
    "check": read_cmd("check", "--json"),
    "settings": read_cmd("settings", "--json"),
    "audit": read_cmd("audit", "tail", str(AUDIT_TAIL)),
}
AUDIT_VERIFY = read_cmd("audit", "verify")


class Result:
    """One finished command."""

    __slots__ = ("argv", "rc", "out", "err")

    def __init__(self, argv, rc: int, out: str = "", err: str = "") -> None:
        self.argv, self.rc, self.out, self.err = list(argv), rc, out, err

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def __repr__(self):
        return f"<Result rc={self.rc} {self.argv[-3:]}>"


class FormError(ValueError):
    """A form the command would refuse anyway, caught before anything runs."""


def _qube(name, what: str) -> str:
    if not projects.valid_qube_name(name):
        raise FormError(f"{what}: choose a qube")
    return name


def _network(name, what: str) -> str:
    return "none" if name in (None, "none") else _qube(name, what)


def _key(key) -> str:
    """A project as the command names it: its label, or its slot."""
    if not isinstance(key, str) or not (projects.LABEL_RE.match(key) or key in projects.SLOTS):
        raise FormError("choose a project")
    return key


def _lead(source, origin, lead_name, lead_netvm) -> list:
    if source not in ("template", "clone", "promote"):
        raise FormError("say where the lead comes from")
    out = [f"--lead-{source}", _qube(origin, "the lead's source")]
    if lead_name:
        if source == "promote":
            raise FormError("a promoted lead keeps its own name")
        out += ["--lead-name", _qube(lead_name, "the lead's name")]
    if lead_netvm is not None:
        out += ["--lead-netvm", _network(lead_netvm, "the lead's network")]
    return out


def _quota(text) -> str:
    """Checked with the command's own parser, so the window never accepts a
    size the command refuses, or refuses one it accepts."""
    text = (text or "").strip()
    if not text:
        raise FormError("give the workers' disk quota, e.g. 20G")
    try:
        fleet.parse_size(text)
    except fleet.ProjectError as e:
        raise FormError(str(e)) from None
    except Exception:
        raise FormError("the quota is a size such as 20G") from None
    return text


def check_label(label) -> str:
    if not isinstance(label, str) or projects.label_refusal(label):
        raise FormError(projects.label_refusal(label) if isinstance(label, str) else "give a label")
    return label


def lead_name_from(typed, space):
    """A lead's full name from what the operator typed after the project's
    space (`ai-<label>-`), shown fixed in front of the field: the space goes in
    front unless it was typed already. None when nothing was typed: the command
    then names the lead `<space>lead`. Judged with the command's own rule."""
    typed = (typed or "").strip()
    if not typed:
        return None
    name = typed if typed.startswith(space) else space + typed
    why = birth.name_refusal(name, space)
    if why:
        raise FormError(f"lead name {name}: {why}")
    return name


def create_project(label, lead_source, lead_origin, lead_name=None, lead_netvm=None,
                   templates=(), networks=(), quota=None, dump=False) -> list:
    check_label(label)
    if not networks:
        raise FormError("tick at least one worker network (a gateway, or none)")
    argv = write_cmd("project", "create", label,
                     *_lead(lead_source, lead_origin, lead_name, lead_netvm))
    for t in templates:
        argv += ["--template", _qube(t, "an approved template")]
    for n in networks:
        argv += ["--network", _network(n, "a worker network")]
    argv += ["--quota", _quota(quota)]
    if dump:
        argv.append("--dump")
    return argv


def edit_project(key, templates=None, networks=None, quota=None) -> list:
    """Only what changed: None leaves a part as it is."""
    argv = write_cmd("project", "edit", _key(key))
    if templates is None and networks is None and quota is None:
        raise FormError("nothing changed")
    if templates is not None:
        if not templates:
            raise FormError("a project needs at least one approved template")
        for t in templates:
            argv += ["--template", _qube(t, "an approved template")]
    if networks is not None:
        if not networks:
            raise FormError("a project needs at least one worker network")
        for n in networks:
            argv += ["--network", _network(n, "a worker network")]
    if quota is not None:
        argv += ["--quota", _quota(quota)]
    return argv


def remove_lead(key) -> list:
    return write_cmd("project", "lead", _key(key), "--remove")


def change_lead(key, lead_source, lead_origin, lead_name=None, lead_netvm=None,
                keep_old=False) -> list:
    argv = write_cmd("project", "lead", _key(key),
                     *_lead(lead_source, lead_origin, lead_name, lead_netvm))
    if keep_old:
        argv.append("--keep-old")
    return argv


def add_dump(key, sink_name=None) -> list:
    argv = write_cmd("project", "dump", _key(key))
    if sink_name:
        argv += ["--name", _qube(sink_name, "the sink's name")]
    return argv


def move(qube, target, confirm=False) -> list:
    if target != "none":
        _key(target)
    argv = write_cmd("project", "move", _qube(qube, "the qube to move"), target)
    if confirm:
        argv.append("--yes")
    return argv


def delete_plan(key) -> list:
    """Without --yes the command prints what it would remove and changes
    nothing, so it runs as a read, without sudo."""
    return read_cmd("project", "delete", _key(key))


def delete_project(key) -> list:
    return write_cmd("project", "delete", _key(key), "--yes")


def role(action, qube, keep_running=False) -> list:
    if action not in ("manage", "guard", "revoke"):
        raise FormError(f"unknown action {action}")
    argv = write_cmd(action, _qube(qube, "the qube"))
    if keep_running:
        if action != "revoke":
            raise FormError("only revoke shuts a qube down")
        argv.append("--no-shutdown")
    return argv


def audit_rotate() -> list:
    return write_cmd("audit", "rotate")


#: Every builder the window calls. The parity test calls each one.
BUILDERS = (create_project, edit_project, remove_lead, change_lead, add_dump, move,
            delete_plan, delete_project, role, audit_rotate)

#: Commands and options the window does not offer, and why the operator types
#: them. An entry covers everything under it. Adding one is a decision, not a
#: way to get the suite green.
CLI_ONLY = {
    ("migrate",): "a one-time step from v0.9.16, run before the first install of this release",
    ("audit", "--path"): "reads a log other than the live one, such as a rotated file; "
                         "the window shows the live log",
}
#: Commands the window shows without running them, and where.
SHOWN_BY = {
    ("project", "show"): "the project's details pane: the same record, from `project list --json`",
    ("version",): "the Settings tab: `settings --json` carries the version",
}


# ======================================================================= what each read returns

#: Every field of a `list` row, as the details pane names it.
QUBE_FIELDS = (
    ("name", "Name"), ("state", "State"), ("klass", "Class"), ("template", "Template"),
    ("netvm", "Network"), ("power", "Power"), ("slot", "Slot badges"), ("lead", "Lead badge"),
    ("owner", "Created by"), ("gateway", "Provides network"), ("dvmt", "Disposable template"),
    ("badges", "Badges"),
)
#: Every field of a `project list` row.
PROJECT_FIELDS = (
    ("slot", "Slot"), ("label", "Label"), ("lead", "Lead"), ("members", "Members"),
    ("used", "Disk used"), ("quota", "Disk quota"), ("templates", "Approved templates"),
    ("networks", "Worker networks (first is the default)"), ("dump", "Dump sink"),
)
#: Every field of `settings --json`.
SETTINGS_FIELDS = (
    ("hub", "Hub (fixed at install)"), ("hub_power", "Hub power"),
    ("name_prefix", "Reserved name prefix"), ("pool_cap", "Pool cap (all of AI space)"),
    ("ai_space_bytes", "AI space disk used"), ("private_cap", "Private-volume cap (one qube)"),
    ("birth_egress", "Birth egress"), ("version", "qubes-mcp version"),
)
#: Every field of a `check --json` finding, and of the document.
CHECK_FIELDS = (("status", "Status"), ("check", "Check"), ("detail", "Detail"))
CHECK_DOC_FIELDS = ("result", "findings")
#: Every field of an audit line the viewer shows, and those it leaves to Verify.
AUDIT_FIELDS = (
    ("seq", "#"), ("ts", "Time (UTC)"), ("caller", "Caller"), ("service", "Service"),
    ("ok", "OK"), ("args", "Request (as logged)"), ("error", "Refusal"),
    ("error_class", "Failure class"),
)
AUDIT_NOT_SHOWN = {
    "v": "the record's schema version",
    "prev": "the chain link Verify checks",
    "hash": "the chain link Verify checks",
}
SIZE_FIELDS = frozenset({"used", "quota", "pool_cap", "private_cap", "ai_space_bytes"})


def field_text(key, value) -> Shown:
    if key in SIZE_FIELDS:
        return size(value)
    if key == "networks" and isinstance(value, list):
        return esc(["none" if n is None else n for n in value])
    return esc(value)


# ======================================================================= parsing

class ReadError(Exception):
    pass


def parse_json(result: Result):
    try:
        return json.loads(result.out)
    except ValueError:
        detail = (result.err or result.out).strip().splitlines()
        raise ReadError(f"{shlex.join(result.argv)} failed (status {result.rc}): "
                        f"{detail[-1] if detail else 'no output'}") from None


def parse_audit(result: Result) -> list:
    rows = []
    for line in result.out.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            rec = {"unparseable": line[:200]}
        rows.append(rec if isinstance(rec, dict) else {"unparseable": line[:200]})
    if result.rc != 0 and not rows:
        raise ReadError(f"{shlex.join(result.argv)} failed (status {result.rc})")
    return rows


def audit_cells(rec: dict) -> list:
    if "unparseable" in rec:
        return [esc(v) for v in ("?", "", "", "unparseable line", "", rec["unparseable"], "", "")]
    return [esc(rec.get(key)) if key != "ok" else esc(bool(rec.get("ok")))
            for key, _ in AUDIT_FIELDS]


def audit_detail(rec: dict) -> Shown:
    """One audit line in full, field by field, for the pane under the list."""
    if "unparseable" in rec:
        return Shown(f"unparseable line: {esc(rec['unparseable'])}")
    keys = [k for k, _ in AUDIT_FIELDS] + sorted(AUDIT_NOT_SHOWN)
    keys += sorted(k for k in rec if k not in keys)
    return Shown("\n".join(f"{esc(k)}: {esc(rec.get(k))}" for k in keys if k in rec))


def audit_hint(rows) -> str:
    """What the pane under the audit list says before a line is selected."""
    if not rows:
        return ("No calls from the hub or a lead on this log yet. It records what the hub and "
                "the leads asked dom0's state-changing services to do, and the line each "
                "rotation starts it with; your other commands are not on it.")
    first = rows[0] if isinstance(rows[0], dict) else {}
    if first.get("service") == "qmcp.audit-rotate":
        cont = (first.get("args") or {}).get("continues", "?")
        return (f"This log starts at a rotation. The lines before it are in /var/log/{cont}; "
                f"qmcp audit tail 200 --path /var/log/{cont} reads them. Select a line to "
                "see it in full.")
    return "Select a line to see it in full."


def settings_rows(values: dict) -> list:
    """(heading, text) for the Settings tab, every field of `settings --json`."""
    values = values if isinstance(values, dict) else {}
    return [(label, field_text(key, values.get(key))) for key, label in SETTINGS_FIELDS]


STATUS_ORDER = {"fail": 0, "error": 1, "warn": 2, "pass": 3}


def check_rows(doc: dict) -> list:
    """Findings, failures first, as escaped cells."""
    findings = doc.get("findings") if isinstance(doc, dict) else None
    rows = [f for f in findings or () if isinstance(f, dict)]
    rows.sort(key=lambda f: STATUS_ORDER.get(f.get("status"), 9))
    return [[esc(str(f.get("status", "?")).upper()), esc(f.get("check")), esc(f.get("detail"))]
            for f in rows]


def light(doc) -> str:
    """GREEN, FAILED, INCOMPLETE, or UNKNOWN when the check did not answer."""
    result = doc.get("result") if isinstance(doc, dict) else None
    return result if result in ("GREEN", "FAILED", "INCOMPLETE") else "UNKNOWN"


# ======================================================================= the tree

#: The tree's columns: (row field, heading).
COLUMNS = (("name", "Name"), ("role", "Role"), ("state", "State"), ("klass", "Class"),
           ("template", "Template"), ("netvm", "Network"), ("power", "Power"))


class Node:
    """One row of the tree. `kind` is group, hub, project, slot, qube or ref
    (a project's lead or sink that is shown elsewhere, or missing)."""

    __slots__ = ("key", "kind", "cells", "children", "data")

    def __init__(self, key, kind, cells, data=None):
        self.key, self.kind, self.cells = key, kind, cells
        self.children: list = []
        self.data = data or {}

    def __repr__(self):
        return f"<Node {self.key}>"


def _cells(name, role, row=None) -> list:
    row = row or {}
    values = {"name": name, "role": role}
    return [esc(values[key] if key in values else row.get(key)) for key, _ in COLUMNS]


def _is_template_row(row) -> bool:
    return row.get("klass") == "TemplateVM" or bool(row.get("dvmt"))


def badges(row) -> dict:
    """The badges the rulebook routes on, read from a `list` row."""
    tags = set(row.get("badges") or ())
    parts = [p for p in (projects.slot_badge_parts(t) for t in tags) if p]
    return {"umbrella": "ai-managed" in tags, "guarded": "qmcp-guarded" in tags,
            "lead_tag": projects.LEAD in tags, "drop_box": projects.DROP_BOX in tags,
            "member": {s for k, s in parts if k == "proj"},
            "lead": {s for k, s in parts if k == "lead"},
            "dump": {s for k, s in parts if k == "dump"}}


#: Why a qube is under Needs attention: (the Role column, the details pane).
#: Each is a state `qmcp check` fails on; the one with an action is a gateway
#: the operator can guard from here.
ATTENTION = {
    "hub": ("the hub in AI space", "the hub is in AI space"),
    "drop_box": ("drop box in AI space", "a drop box (ai-dump, or a sink badge) is in AI space"),
    "lead": ("lead badges, no record",
             "lead badges the records do not back: the rulebook acts on them"),
    "two_slots": ("in two slots", "member badges of two slots"),
    "template_member": ("template in a project", "a template or gateway wears a project's member badge"),
    "gateway": ("gateway not guarded",
                "a gateway without qmcp-guarded: the rulebook lets the hub run commands in it"),
    "outside": ("badges outside AI space", "slot badges outside AI space: the rulebook acts on them"),
    "sink": ("stray sink badge", "a sink badge that is not its record's"),
}


def _attention(code):
    return "attention", f"needs attention: {ATTENTION[code][0]}", code


def classify(row, records, hub=None):
    """(where, role, attention) for one qube, from its badges and the records.
    `where` is a slot, `templates`, `gateways`, `guarded`, `noslot`,
    `attention`, or None (not in the tree). `records` is None when they could
    not be read: then nothing is judged against them."""
    b = badges(row)
    name = row["name"]
    if row.get("state") is None:
        if b["member"] or b["lead"] or b["lead_tag"]:
            return _attention("outside")
        if b["dump"] and records is not None:
            slot = next(iter(b["dump"]))
            rec = records.get(slot)
            if len(b["dump"]) > 1 or rec is None or rec.get("dump") != name or not b["drop_box"]:
                return _attention("sink")
        return None, None, None
    if hub is not None and name == hub:
        return _attention("hub")
    if b["drop_box"] or b["dump"]:
        return _attention("drop_box")
    if b["lead_tag"] or b["lead"]:
        slot = next(iter(b["lead"])) if len(b["lead"]) == 1 else None
        if records is None and slot is not None:
            return slot, "lead (records not read)", None
        rec = (records or {}).get(slot) if slot else None
        if (not b["lead_tag"] or slot is None or b["member"] or b["guarded"]
                or rec is None or rec.get("lead") != name):
            return _attention("lead")
        return slot, "lead", None
    if len(b["member"]) > 1:
        return _attention("two_slots")
    if b["member"] and (row.get("gateway") or _is_template_row(row)):
        return _attention("template_member")
    if row.get("gateway") and not b["guarded"]:
        return _attention("gateway")
    if b["member"]:
        slot = next(iter(b["member"]))
        return slot, ("hub's qube" if slot == projects.HUB_SLOT else "worker"), None
    if row.get("gateway"):
        return "gateways", "gateway", None
    if _is_template_row(row):
        return "templates", ("disposable template" if row.get("dvmt") else "template"), None
    if row.get("state") == "guarded":
        return "guarded", "guarded", None
    return "noslot", "hub's qube, no slot", None


def _qube_node(row, role, attention=None) -> Node:
    return Node(f"qube:{row['name']}", "qube", _cells(row["name"], role, row),
                dict(row, role=role, attention=attention))


def _ref(slot, what, name, role) -> Node:
    """A project's lead or sink that is shown elsewhere, or missing: a key of
    its own, so no qube is ever two rows under one key."""
    return Node(f"ref:{slot}:{what}", "ref", _cells(name, role), {"name": name, "role": role})


def build_tree(fleet_rows, project_rows, settings) -> list:
    """The tree: the hub with p00 and the qubes in no slot, the projects with
    their leads, workers and sinks, templates, gateways, other guarded qubes,
    and Needs attention: the qubes whose badges the rulebook acts on against
    the records (see `ATTENTION`); every other failure of `qmcp check` is on
    the Check tab. `project_rows` None means the records could not be read,
    and nothing is judged against them."""
    rows = [r for r in fleet_rows or () if isinstance(r, dict) and isinstance(r.get("name"), str)]
    by_name = {r["name"]: r for r in rows}
    records = None if project_rows is None else {
        p["slot"]: p for p in project_rows if isinstance(p, dict) and p.get("slot")}
    settings = settings or {}
    hub_name = settings.get("hub")
    buckets: dict = {}
    placed: dict = {}
    for row in rows:
        where, role, attention = classify(row, records, hub_name)
        if where is None:
            continue
        buckets.setdefault(where, []).append(_qube_node(row, role, attention))
        placed[row["name"]] = where

    def sink_child(slot, name):
        row = by_name.get(name)
        if row is None:
            return _ref(slot, "dump", name, "dump sink (missing)")
        if placed.get(name) == "attention":
            return _ref(slot, "dump", name, "dump sink (see Needs attention)")
        return _qube_node(row, "dump sink")

    hub = Node("hub", "hub", _cells(hub_name or "(no hub)", "hub", {"power": settings.get("hub_power")}),
               {"name": hub_name})
    p00 = Node("slot:p00", "slot", _cells("p00", "the hub's own qubes"), {"slot": "p00"})
    p00.children = buckets.pop("p00", [])
    if records and records.get("p00", {}).get("dump"):
        p00.children.append(sink_child("p00", records["p00"]["dump"]))
    noslot = Node("group:noslot", "group", _cells("no slot", "hub-only, copies by dialog"))
    noslot.children = buckets.pop("noslot", [])
    hub.children = [p00] + ([noslot] if noslot.children else [])

    count = "?" if records is None else f"{len([s for s in records if s != 'p00'])} of 15"
    projects_node = Node("group:projects", "group", _cells("Projects", count))
    for slot in projects.PROJECT_SLOTS:
        rec = (records or {}).get(slot)
        members = buckets.pop(slot, [])
        if rec is None:
            if members:
                role = ("records not read" if records is None
                        else "no record: finish its delete")
                node = Node(f"slot:{slot}", "slot", _cells(slot, role),
                            {"slot": slot, "unknown": records is None})
                node.children = members
                projects_node.children.append(node)
            continue
        node = Node(f"project:{slot}", "project", _cells(f"{slot} {rec.get('label')}", "project"),
                    dict(rec))
        leads = [m for m in members if m.data.get("role") == "lead"]
        lead_name = rec.get("lead")
        if lead_name and not leads:
            role = ("lead (see Needs attention)" if placed.get(lead_name) == "attention"
                    else "lead (missing)")
            leads = [_ref(slot, "lead", lead_name, role)]
        node.children = leads + [m for m in members if m.data.get("role") != "lead"]
        if rec.get("dump"):
            node.children.append(sink_child(slot, rec["dump"]))
        projects_node.children.append(node)

    out = [hub, projects_node]
    for where, title, note in (("templates", "Templates", "the hub builds managed ones"),
                               ("gateways", "Gateways", "guarded"),
                               ("guarded", "Other guarded", "reference only"),
                               ("attention", "Needs attention", "qmcp check fails on these")):
        items = buckets.pop(where, [])
        if items:
            group = Node(f"group:{where}", "group", _cells(title, note))
            group.children = items
            out.append(group)
    for where, items in sorted(buckets.items()):          # a slot nothing expected
        group = Node(f"group:{where}", "group", _cells(where, "unexpected"))
        group.children = items
        out.append(group)
    return out


def walk(nodes):
    for node in nodes:
        yield node
        yield from walk(node.children)


def details(node: Node, project_rows=None) -> list:
    """(heading, text) pairs for the details pane."""
    if node.kind == "qube":
        rows = [(label, field_text(key, node.data.get(key))) for key, label in QUBE_FIELDS
                if key in node.data]
        why = ATTENTION.get(node.data.get("attention"))
        return ([("Role", esc(node.data.get("role")))] + ([("Why", esc(why[1]))] if why else [])
                + rows)
    if node.kind == "project":
        return [(label, field_text(key, node.data.get(key))) for key, label in PROJECT_FIELDS]
    if node.kind == "slot":
        return [("Slot", esc(node.data.get("slot")))]
    if node.kind == "ref":
        return [("Role", esc(node.data.get("role"))), ("Name", esc(node.data.get("name")))]
    if node.kind == "hub":
        return [("Hub", esc(node.data.get("name")))]
    return []


def actions(node: Node | None, records: dict) -> set:
    """The buttons that make sense for a selection. The command decides; a
    button left on is refused with the command's own reason."""
    out = {"new_project", "add_to_ai_space"}
    if node is None:
        return out
    if node.kind == "project":
        out |= {"edit_project", "change_lead", "delete_project"}
        if node.data.get("lead"):
            out.add("remove_lead")
        if not node.data.get("dump"):
            out.add("add_dump")
    elif node.kind == "slot" and node.key == "slot:p00":
        if not records.get("p00", {}).get("dump"):
            out.add("add_dump")
    elif node.kind == "slot" and not node.data.get("unknown"):
        out.add("finish_delete")
    elif node.kind == "qube":
        role, state = node.data.get("role") or "", node.data.get("state")
        attention = node.data.get("attention")
        if attention == "gateway":
            out.add("guard")
        if attention or state is None:
            return out
        if role in ("worker", "hub's qube", "hub's qube, no slot") and node.data.get("klass") == "AppVM":
            out.add("move")
        if state == "guarded" and role != "gateway":
            out.add("manage")
        if state == "managed" and role in ("hub's qube, no slot", "template", "disposable template"):
            out.add("guard")
        if not role.startswith("lead"):
            out.add("revoke")
    return out


def slot_of(node: Node) -> str | None:
    if node.kind in ("project", "slot"):
        return node.data.get("slot")
    return None


def project_key(node: Node) -> str | None:
    """The name the command takes for a project node: its label, or the slot."""
    if node.kind == "project":
        return node.data.get("label") or node.data.get("slot")
    if node.kind == "slot":
        return node.data.get("slot")
    return None


# ======================================================================= choices for the forms

def lead_templates(fleet_rows) -> list:
    """Any TemplateVM, in AI space or not: one outside it is the stronger
    choice for a lead, since the hub cannot edit it."""
    return sorted(r["name"] for r in fleet_rows if r.get("klass") == "TemplateVM")


def hubs_appvms(fleet_rows, hub=None) -> list:
    """Managed AppVMs of the hub's (p00 or no slot): a lead's clone source or a
    qube to promote."""
    out = []
    for r in fleet_rows:
        if (r.get("state") == "managed" and r.get("klass") == "AppVM" and not r.get("dvmt")
                and not r.get("gateway") and not r.get("lead")
                and (r.get("slot") in (None, projects.HUB_SLOT)) and r.get("name") != hub):
            out.append(r["name"])
    return sorted(out)


def approved_template_choices(fleet_rows) -> list:
    """TemplateVMs and disposable templates in AI space."""
    return sorted(r["name"] for r in fleet_rows if r.get("state") is not None and _is_template_row(r)
                  and not r.get("gateway"))


def worker_network_choices(fleet_rows) -> list:
    """Guarded gateways in AI space, and none first. A gateway without
    qmcp-guarded is under Needs attention, not offered."""
    return ["none"] + sorted(r["name"] for r in fleet_rows
                             if r.get("state") is not None and r.get("gateway")
                             and "qmcp-guarded" in (r.get("badges") or ()))


def lead_network_choices(fleet_rows) -> list:
    """Any qube that provides network, and none first."""
    return ["none"] + sorted(r["name"] for r in fleet_rows if r.get("gateway"))


def outside_choices(fleet_rows, hub=None, sinks=()) -> list:
    """Qubes a role action can bring into AI space: outside it, not the hub,
    not a dump sink."""
    return sorted(r["name"] for r in fleet_rows if r.get("state") is None
                  and r.get("name") not in (hub, *sinks))


def move_targets(records: dict) -> list:
    """(command target, shown text): p00, each project, or no slot."""
    out = [("p00", "p00, the hub's own qubes")]
    for slot in projects.PROJECT_SLOTS:
        rec = records.get(slot)
        if rec is not None and rec.get("label"):
            out.append((rec["label"], f"{slot} {rec['label']}"))
    out.append(("none", "no slot (hub-only, copies by dialog)"))
    return out
