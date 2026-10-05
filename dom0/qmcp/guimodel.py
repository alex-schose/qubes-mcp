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
  screen as visible escapes, never as layout. A proposal's title is the hub's
  own words too: escaped like everything else, and labelled as written by AI
  wherever it is shown;
- roles come from the project records and the badges, never from a qube's
  label colour, which the hub may set;
- a proposal is accepted with the fingerprint of the `proposal show` on
  display, so the command refuses a stored file that changed after the
  operator read it;
- the networks the forms offer are the enrolled gateways (`gateway list`),
  and a lead's firewall is shown from its own read (`project firewall NAME
  --json`): rules that could not be read are never shown as an empty list.

It cannot go stale: `tests/test_gui.py` walks the command's parser and the
JSON each read returns, and fails on any command, option or field the window
neither offers nor exempts here by name, with a reason.
"""
from __future__ import annotations

import json
import shlex

from qmcp import birth, firewall, fleet, gateways, projects, proposals

QMCP = "/usr/local/bin/qmcp"
SUDO = ("/usr/bin/sudo", "-n")
#: Audit lines the viewer reads.
AUDIT_TAIL = 200


# ======================================================================= text

class Shown(str):
    """Text that has been through `esc()` or `esc_lines()`: the only kind the
    window's widgets accept. Joining or formatting gives a plain `str` again,
    which they refuse, so composed text must be built raw and escaped once.
    Only `esc()`, `esc_lines()`, `esc_items()` and `audit_detail()` (the last
    two join `esc()` output) make one; a test holds the module to that."""
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


def esc_items(values) -> Shown:
    """Each value on a line of its own, escaped as `esc()` escapes it, for a
    list read line by line (firewall rules). `esc()` leaves no line break in a
    value, so whatever one holds it is one line: never two, never joined to
    the next."""
    return Shown("\n".join(esc(value) for value in values))


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
    "proposals": read_cmd("proposal", "list", "--json"),
    "gateways": read_cmd("gateway", "list", "--json"),
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


def _option(flag, value) -> list:
    """`--flag VALUE`; `--flag=VALUE` when the value would read as an option
    (a label may start with `-`)."""
    return [f"{flag}={value}"] if value.startswith("-") else [flag, value]


def _model(text) -> str:
    """A model endpoint, `host:port`, checked with the command's own check
    (`firewall.model_text`) and sent as typed: the command keeps its
    canonical form."""
    text = (text or "").strip()
    if not text:
        raise FormError("give the model endpoint, host:port, e.g. api.anthropic.com:443")
    try:
        firewall.model_text(text)
    except firewall.FirewallError as e:
        raise FormError(str(e)) from None
    return text


def _gateway_label(label) -> str:
    """A gateway's label, checked with the command's own check."""
    why = gateways.label_refusal(label) if isinstance(label, str) else "a label is text"
    if why:
        raise FormError(why)
    return label


def _quota(text) -> str:
    """Checked with the command's own check (`fleet._quota`, which create and
    edit run on the text they are given), so the window never accepts a size
    the command refuses, or refuses one it accepts."""
    text = (text or "").strip()
    if not text:
        raise FormError("give the workers' disk quota, e.g. 20G")
    try:
        fleet._quota(text)
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
                   templates=(), networks=(), quota=None, dump=False, model=None) -> list:
    """`model` is the lead's model endpoint, or None. Whether the lead needs
    one depends on its network, which `lead_model()` judges with the fleet."""
    check_label(label)
    if not networks:
        raise FormError("tick at least one worker network (a gateway, or none)")
    argv = write_cmd("project", "create", label,
                     *_lead(lead_source, lead_origin, lead_name, lead_netvm))
    if (model or "").strip():
        argv += ["--model", _model(model)]
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
                keep_old=False, model=None, add_old_network=False) -> list:
    """`model` None: a new lead with a network takes the project's model.
    `add_old_network` goes with `keep_old` only, as the command has it."""
    argv = write_cmd("project", "lead", _key(key),
                     *_lead(lead_source, lead_origin, lead_name, lead_netvm))
    if add_old_network and not keep_old:
        raise FormError("the old lead's network can be added only when it is kept as a worker")
    if keep_old:
        argv.append("--keep-old")
    if add_old_network:
        argv.append("--add-old-network")
    if (model or "").strip():
        argv += ["--model", _model(model)]
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


def enroll_gateway(qube, anonymising=False, label=None) -> list:
    """Let AI space use `qube` as a network. An empty label is no label."""
    argv = write_cmd("gateway", "enroll", _qube(qube, "the gateway"))
    if anonymising:
        argv.append("--anonymising")
    if label:
        argv += _option("--label", _gateway_label(label))
    return argv


def change_gateway(qube, anonymising=None, label=None) -> list:
    """Only what changed: None leaves a part as it is; an empty label clears it."""
    argv = write_cmd("gateway", "set", _qube(qube, "the gateway"))
    if anonymising is None and label is None:
        raise FormError("nothing changed")
    if anonymising is not None:
        argv += ["--anonymising", "yes" if anonymising else "no"]
    if label is not None:
        argv += _option("--label", _gateway_label(label))
    return argv


def remove_gateway(qube) -> list:
    return write_cmd("gateway", "remove", _qube(qube, "the gateway"))


def show_lead_firewall(key) -> list:
    """A project's lead firewall: its model, the rules accepted and the live
    ones. A read, run as the user whenever a project or its lead is selected."""
    return read_cmd("project", "firewall", _key(key), "--json")


def set_lead_model(key, model) -> list:
    """The lead's model endpoint changes, and its firewall becomes that
    endpoint, DNS and nothing else."""
    return write_cmd("project", "firewall", _key(key), "--model", _model(model))


def set_lead_rules(key, rules) -> list:
    """The lead's firewall becomes exactly `rules`, each checked with the
    command's own check; each is one `--rule`."""
    rules = list(rules or ())
    why = firewall.rules_refusal(rules)
    if why:
        raise FormError(why)
    argv = write_cmd("project", "firewall", _key(key))
    for rule in rules:
        argv += ["--rule", rule]
    return argv


def accept_lead_rules(key) -> list:
    """The lead's live rules become the accepted ones; the qube does not change."""
    return write_cmd("project", "firewall", _key(key), "--accept-current")


def _pid(pid) -> str:
    """A proposal's number, as the command takes it."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise FormError("choose a proposal")
    return str(pid)


def show_proposal(pid) -> list:
    """One proposal in full, with what accepting it does to the fleet as it is
    now: a read, run as the user whenever a proposal is selected."""
    return read_cmd("proposal", "show", _pid(pid), "--json")


def accept_proposal(pid, sha256, tick=None) -> list:
    """`sha256` is the fingerprint the last `show` gave, so the command refuses a
    stored file that no longer hashes to what the operator read. `tick` is the
    second tick: the digest that `show` gave of the reasons on display, sent
    only when the operator ticked them, so the command refuses it for any
    other reasons it finds by then. None when one click is enough."""
    # The command's own shape for a fingerprint and a tick: the window never
    # sends one it would refuse, nor refuses one it would take.
    if not proposals.valid_fingerprint(sha256):
        raise FormError("the proposal has no fingerprint on show: read it again")
    if tick is not None and not proposals.valid_fingerprint(tick):
        raise FormError("the second tick on show is not one: read it again")
    argv = write_cmd("proposal", "accept", _pid(pid), "--sha256", sha256)
    if tick is not None:
        argv += ["--yes", tick]
    return argv


def reject_proposal(pid) -> list:
    return write_cmd("proposal", "reject", _pid(pid))


#: Every builder the window calls. The parity test calls each one.
BUILDERS = (create_project, edit_project, remove_lead, change_lead, add_dump, move,
            delete_plan, delete_project, role, audit_rotate, show_proposal, accept_proposal,
            reject_proposal, enroll_gateway, change_gateway, remove_gateway,
            show_lead_firewall, set_lead_model, set_lead_rules, accept_lead_rules)

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
    ("model", "Lead's model endpoint"), ("lead_firewall", "Lead firewall you accepted"),
)
#: Every field of `settings --json`.
SETTINGS_FIELDS = (
    ("hub", "Hub (fixed at install)"), ("hub_power", "Hub power"),
    ("name_prefix", "Reserved name prefix"), ("pool_cap", "Pool cap (all of AI space)"),
    ("ai_space_bytes", "AI space disk used"), ("private_cap", "Private-volume cap (one qube)"),
    ("birth_egress", "Birth egress"), ("gateways_enrolled", "Gateways enrolled"),
    ("version", "qubes-mcp version"),
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
#: Fields that hold firewall rules: shown a rule per line.
RULE_FIELDS = frozenset({"lead_firewall", "accepted", "live", "rules"})


def rules_text(rules, missing) -> Shown:
    """Firewall rules a rule per line. Not a list: `missing`, which says why
    there are none to show; an empty list is shown as one, so rules that were
    not read never pass for a firewall with no rules."""
    if not isinstance(rules, list):
        return esc(missing)
    return esc_items(rules) if rules else esc("(no rules)")


def field_text(key, value) -> Shown:
    if key in SIZE_FIELDS:
        return size(value)
    if key == "networks" and isinstance(value, list):
        return esc(["none" if n is None else n for n in value])
    if key in RULE_FIELDS:
        return rules_text(value, "none on record")
    if key == "gateways_enrolled" and value is None:
        return esc("not known: the registry cannot be read")
    return esc(value)


# ======================================================================= parsing

class ReadError(Exception):
    pass


def _failed(result: Result) -> ReadError:
    detail = (result.err or result.out).strip().splitlines()
    return ReadError(f"{shlex.join(result.argv)} failed (status {result.rc}): "
                     f"{detail[-1] if detail else 'no output'}")


def parse_json(result: Result):
    try:
        return json.loads(result.out)
    except ValueError:
        raise _failed(result) from None


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
        return ("Nothing on this log yet. It records every call the hub and the leads make to "
                "dom0's state-changing services, and every command of yours that changes "
                "something, as caller operator: accepting and rejecting proposals included. A "
                "rotation starts a new log with a line of its own.")
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


#: What a `list` row holds for a value the command could not read.
UNREADABLE = fleet.UNREADABLE


def unread_row(row) -> bool:
    """A `list` row with a value the command could not read (`fleet.UNREADABLE`):
    its tags, class or role. The window places it by none of them and offers
    nothing on it: a failed read is never state."""
    return fleet.UNREADABLE in (row.get("state"), row.get("klass"), row.get("gateway"),
                                row.get("dvmt"))


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
#: Each but `unreadable` is a state `qmcp check` fails on; `unreadable` is a read
#: that failed. The one with an action is a gateway the operator can guard from here.
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
    "unreadable": ("cannot be read", "a read of its tags, class or role failed, so the window "
                                     "offers nothing on it. A command reads it again and "
                                     "refuses what it still cannot read. Refresh"),
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
    if unread_row(row):
        return _attention("unreadable")
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


def actions(node: Node | None, records: dict, firewall_pane=None, fleet_rows=None) -> set:
    """The buttons that make sense for a selection. The command decides; a
    button left on is refused with the command's own reason. The lead's
    firewall buttons come from `firewall_pane`, the selected project's last
    firewall read, and only while it is that project's and read; Set lead
    model unless `model_refusal` finds why the command refuses it."""
    out = {"new_project", "add_to_ai_space"}
    if node is None:
        return out
    if firewall_pane is not None:
        out |= firewall_pane.actions(firewall_key(node, records), fleet_rows)
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


def firewall_key(node: Node | None, records) -> str | None:
    """The project whose lead's firewall goes with a selection: a project, or
    the row of its lead (a lead its badges and record agree on). None for
    anything else."""
    if node is None:
        return None
    if node.kind == "project":
        return node.data.get("label") or None
    if node.kind == "qube" and node.data.get("role") == "lead":
        rec = (records or {}).get(node.data.get("slot"))
        if isinstance(rec, dict) and rec.get("lead") == node.data.get("name"):
            return rec.get("label") or None
    return None


# ======================================================================= proposals

#: Every field of a `proposal list --json` row, as the details pane names it;
#: `proposal show --json` carries each of them too.
PROPOSAL_FIELDS = (
    ("id", "Proposal"), ("state", "State"), ("type", "Type"), ("subject", "Subject"),
    ("title", "Title (written by AI)"), ("caller", "Submitted by"),
    ("submitted", "Submitted (UTC)"), ("expires", "Expires (UTC)"),
    ("sha256", "Fingerprint (sha256)"), ("problem", "Problem"),
    ("needs_closing", "Needs closing"),
)
#: The list's columns.
PROPOSAL_COLUMNS = (("id", "#"), ("state", "State"), ("type", "Type"), ("subject", "Project"),
                    ("title", "Title (written by AI)"), ("submitted", "Submitted (UTC)"))
#: What `proposal show --json` adds to a list row and the pane shows on a line
#: of its own. The second tick's reasons are also in red beside the tick box.
PROPOSAL_SHOW_FIELDS = (("command", "Equivalent command"), ("second_tick", "Second tick"),
                        ("tick", "Second tick digest"), ("plan", "Plan"))
#: What it adds and the pane shows a line per part.
PROPOSAL_BY_PART = {
    "proposal": "a line per option (PROPOSAL_OPTIONS)",
    "before": "a line per part, now -> after (EDIT_FIELDS); a lead firewall's, the rules "
              "now and after (FIREWALL_CHANGE)",
    "after": "a line per part, now -> after (EDIT_FIELDS); a lead firewall's, the rules "
             "now and after (FIREWALL_CHANGE)",
    "decision": "a line per field (DECISION_FIELDS)",
}
#: Every option a proposal can carry (`proposals.normalise`), as the pane names
#: it, in this order. `type` and `title` are the fields above them.
PROPOSAL_OPTIONS = (
    ("label", "Label"), ("project", "Project"),
    ("lead", "Lead"), ("lead_name", "Lead name"), ("lead_netvm", "Lead network"),
    ("model", "Lead's model endpoint"),
    ("remove", "Remove the lead"), ("keep_old", "Keep the old lead as a worker"),
    ("add_old_network", "Add the old lead's network to the worker networks"),
    ("templates", "More approved templates"),
    ("networks", "Worker networks (first is the default)"), ("quota", "Workers' disk quota"),
    ("dump", "Also create its dump sink"), ("name", "Sink name"),
    ("add_templates", "Templates to add"), ("remove_templates", "Templates to remove"),
    ("add_networks", "Worker networks to add"), ("remove_networks", "Worker networks to remove"),
    ("default_network", "New default worker network"),
    ("rules", "Lead firewall rules"),
)
#: An edit's project record now and after accepting, a line per part.
EDIT_FIELDS = (("templates", "Templates, now -> after"),
               ("networks", "Worker networks, now -> after"),
               ("quota", "Quota, now -> after"))
#: A lead-firewall proposal's lead now and after accepting, one above the
#: other: `before` holds the model, the accepted and live rules, and why the
#: live ones could not be read (shown in their line, in place of the rules);
#: `after` the model and the rules it sets.
FIREWALL_CHANGE = (("model", "Lead's model, now -> after"),
                   ("accepted", "Lead firewall now, as you accepted it"),
                   ("live", "Lead firewall now, live"),
                   ("read_error", "Lead firewall now, live"),
                   ("rules", "Lead firewall after accepting"))
#: Every field of a decision the pane shows, and those it does not.
DECISION_FIELDS = (("state", "Decision"), ("at", "Decided (UTC)"),
                   ("sha256", "Decided fingerprint"), ("report", "Report"))
DECISION_NOT_SHOWN = {
    "v": "the record's schema version",
    "id": "the proposal's number, shown above",
}
#: Beside a state word, where the word alone does not say it.
PROPOSAL_STATES = {
    "pending": "waiting for you",
    "accepting": "an accept is running its command",
    "expired": f"not decided within {proposals.EXPIRY_S // 86400} days; nothing ran",
    "unreadable": "its stored file does not read back",
}
#: Where a proposed lead comes from, in words.
LEAD_FROM = {"template": "a fresh qube from the template {}", "clone": "a clone of {}",
             "promote": "{}, promoted in place"}


def proposal_rows(rows) -> list:
    """The rows of `proposal list --json` that carry a number, newest first."""
    return [r for r in rows or () if isinstance(r, dict)
            and isinstance(r.get("id"), int) and not isinstance(r.get("id"), bool)]


def proposal_cells(row) -> list:
    """The list's cells. One that needs closing says so beside its state."""
    cells = []
    for key, _ in PROPOSAL_COLUMNS:
        value = row.get(key)
        if key == "state" and row.get("needs_closing") is True:
            value = f"{value}, needs closing"
        cells.append(esc(value))
    return cells


def proposals_tab(rows) -> str:
    """The tab's label: how many proposals wait for the operator, or `?` when
    the list has not been read."""
    if rows is None:
        return "Proposals (?)"
    return f"Proposals ({sum(1 for r in proposal_rows(rows) if r.get('state') == 'pending')})"


def parse_proposal(result: Result, pid) -> dict:
    """The answer of `proposal show N --json` about proposal `pid`, or ReadError:
    a show that failed is never taken for the proposal's state."""
    if not result.ok:
        raise _failed(result)
    doc = parse_json(result)
    if (not isinstance(doc, dict) or doc.get("id") != pid
            or not isinstance(doc.get("second_tick"), list)):
        raise ReadError(f"{shlex.join(result.argv)}: unexpected answer")
    return doc


def _reasons(doc) -> list:
    """Why accepting needs the second tick, as the command computed it when the
    proposal was read. The command computes it only while a proposal is
    pending."""
    if not isinstance(doc, dict) or doc.get("state") != "pending":
        return []
    reasons = doc.get("second_tick")
    return [str(r) for r in reasons] if isinstance(reasons, list) else []


def tick_of(doc):
    """The second tick `show` gave for the reasons on display: the digest that
    `accept --yes` takes back, or None when one click is enough."""
    if not isinstance(doc, dict) or doc.get("state") != "pending":
        return None
    tick = doc.get("tick")
    return tick if proposals.valid_fingerprint(tick) else None


def _needs_tick(doc) -> bool:
    return bool(_reasons(doc)) or tick_of(doc) is not None


def proposal_actions(doc, ticked=False) -> set:
    """Accept and Reject while a proposal is pending, Accept only once the
    second tick is given when the command says it needs one. Close for one the
    command says needs closing (`needs_closing`), which `reject` closes, but
    not while an accept is running: the command refuses that. Nothing in any
    other state: the proposal is closed."""
    if not isinstance(doc, dict):
        return set()
    if doc.get("state") == "pending":
        if _needs_tick(doc) and not ticked:
            return {"reject_proposal"}
        return {"accept_proposal", "reject_proposal"}
    if doc.get("needs_closing") is True and doc.get("state") != proposals.ACCEPTING:
        return {"close_proposal"}
    return set()


def closes_as(doc) -> str:
    """The state `reject` closes a proposal that needs closing in: one whose
    stored file does not read as rejected; an accept that never finished, or a
    decision file that does not read, as failed (its command may have run)."""
    return "rejected" if doc.get("state") == proposals.UNREADABLE else "failed"


def tick_key(doc):
    """What a second tick answers: the digest of these reasons, for this
    stored proposal. The window clears the tick when it changes. None when no
    tick can be given: then no box is offered, and while there are reasons
    Accept stays off."""
    tick = tick_of(doc)
    return (doc.get("id"), doc.get("sha256"), tick) if tick else None


def proposal_changed(opened, ident, pane, ticked) -> str | None:
    """Why a form opened on the show `opened` may no longer run `ident`, or
    None. Asked at OK: the pane's last show must still allow it, with the tick
    as it is now, and be the same proposal, fingerprint and second tick. A
    show that failed, is being read again, or reads differently refuses."""
    doc = pane.doc
    if (ident not in pane.actions(ticked) or not isinstance(doc, dict)
            or any(doc.get(k) != opened.get(k) for k in ("id", "sha256", "tick"))):
        return "the proposal changed since this form opened; read it again"
    return None


def second_tick_text(doc) -> Shown:
    """The reasons, one per line, for the red text above the tick box and in
    the form that accepts. Empty when one click is enough."""
    reasons = _reasons(doc)
    if not reasons:
        return esc("")
    return esc_lines("Accepting it needs the second tick:\n"
                     + "\n".join(f"- {r}" for r in reasons))


def _plain(key, value) -> str:
    """A record's value in plain words, for a line that is escaped once. A
    quota is exact, as the command takes it: whole GiB as `20G`, else bytes."""
    if key == "quota" and isinstance(value, int) and not isinstance(value, bool):
        return quota_text(value)
    if isinstance(value, list):
        return ", ".join("none" if v is None else str(v) for v in value) or "-"
    return "-" if value is None else str(value)


def _option_text(key, value) -> Shown:
    if key == "lead" and isinstance(value, dict) and value.get("from") in LEAD_FROM:
        return esc(LEAD_FROM[value["from"]].format(value.get("qube")))
    if key == "quota":
        return esc(_plain(key, value))      # exact: what the operator accepts is what runs
    return field_text(key, value)


def firewall_change(before, after) -> list:
    """(heading, text) for a lead-firewall proposal: the model now and after,
    then the rules the operator accepted, the live ones, and the ones
    accepting sets, a rule per line, one above the other. Live rules that
    were not read say why: they could not be read (and the error), or there
    was no lead's qube to read them from; never an empty list."""
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    h = dict(FIREWALL_CHANGE)
    if isinstance(before.get("live"), list) or not before.get("read_error"):
        live = rules_text(before.get("live"), "not read: the project has no lead, or no qube "
                                              "of that name")
    else:
        live = esc(f"could not be read ({before['read_error']})")
    return [(h["model"], esc(f"{_plain('model', before.get('model'))} -> "
                             f"{_plain('model', after.get('model'))}")),
            (h["accepted"], rules_text(before.get("accepted"), "none on record")),
            (h["live"], live),
            (h["rules"], rules_text(after.get("rules"), "-"))]


def proposal_details(doc) -> list:
    """(heading, text) pairs for the pane beside the list: every field of the
    last `show`. The title is the hub's own words and its heading says so."""
    if not isinstance(doc, dict):
        return []
    out = []
    for key, heading in PROPOSAL_FIELDS:
        value = doc.get(key)
        if key in ("problem", "needs_closing") and not value:
            continue
        if key == "state" and value in PROPOSAL_STATES:
            value = f"{value}: {PROPOSAL_STATES[value]}"
        if key == "needs_closing":
            value = (f"yes: it cannot be accepted, and qmcp check warns about it until it is "
                     f"closed. Close records it as {closes_as(doc)}; nothing in the fleet "
                     f"changes.")
        out.append((heading, esc(value)))
    options = doc.get("proposal") if isinstance(doc.get("proposal"), dict) else {}
    named = {key for key, _ in PROPOSAL_OPTIONS} | {"type", "title"}
    out += [(heading, _option_text(key, options[key])) for key, heading in PROPOSAL_OPTIONS
            if key in options]
    out += [(key, esc(options[key])) for key in sorted(options) if key not in named]
    headings = dict(PROPOSAL_SHOW_FIELDS)
    if doc.get("command") is not None:
        out.append((headings["command"], esc(doc["command"])))
    if doc.get("state") == "pending":
        out.append((headings["second_tick"], esc("needed: the reasons are in red below"
                                                 if _needs_tick(doc) else
                                                 "not needed: one click is enough")))
    if doc.get("tick") is not None:
        out.append((headings["tick"], esc(doc["tick"])))
    before, after = doc.get("before"), doc.get("after")
    if doc.get("type") == "project-firewall":
        if isinstance(before, dict) or isinstance(after, dict):
            out += firewall_change(before, after)
    elif isinstance(before, dict):
        after = after if isinstance(after, dict) else None
        for key, heading in EDIT_FIELDS:
            then = _plain(key, after.get(key)) if after is not None else "? (see Plan)"
            out.append((heading, esc(f"{_plain(key, before.get(key))} -> {then}")))
    if doc.get("plan") is not None:
        out.append((headings["plan"], esc(doc["plan"])))
    decision = doc.get("decision")
    if isinstance(decision, dict):
        for key, heading in DECISION_FIELDS:
            value = decision.get(key)
            if key == "report":
                lines = [str(line) for line in value] if isinstance(value, list) else []
                out.append((heading, esc_lines("\n".join(lines)) if lines else esc(None)))
            else:
                out.append((heading, esc(value)))
        known = {k for k, _ in DECISION_FIELDS} | set(DECISION_NOT_SHOWN)
        out += [(f"decision {k}", esc(decision[k])) for k in sorted(decision) if k not in known]
    return out


def accept_intro(doc) -> str:
    """What accepting does, for the form that asks before it runs."""
    command = doc.get("command")
    runs = (f"The equivalent command: {command}" if command else
            "It edits the project's record as it is when the command runs: see the lines "
            "now -> after beside the list.")
    if doc.get("type") == "project-firewall":
        runs += (" It changes what the lead can reach on the network: compare its firewall "
                 "now and after accepting, beside the list.")
    tick = (" The second tick goes with it: if the command finds other reasons than the ones "
            "in red, it refuses and runs nothing; if it finds none, one click was enough and "
            "it runs." if tick_of(doc) else "")
    return (f"Accepts proposal {doc.get('id')} from {doc.get('caller')}: {doc.get('type')} "
            f"{doc.get('subject')}. Its command runs as root and checks the fleet as it is "
            f"when it runs. Once it runs, the proposal closes: accepted, or failed with the "
            f"command's report.{tick} {runs}")


def reject_intro(doc) -> str:
    return (f"Closes proposal {doc.get('id')} from {doc.get('caller')}: {doc.get('type')} "
            f"{doc.get('subject')}, without running anything. The hub learns only that it was "
            f"rejected.")


def close_intro(doc) -> str:
    """What closing a proposal that needs closing does, for its form. It runs
    the same `reject` as Reject does."""
    return (f"Proposal {doc.get('id')} cannot be accepted, and qmcp check warns about it until "
            f"it is closed. Why: {doc.get('problem') or 'not given'}. Close runs qmcp proposal "
            f"reject {doc.get('id')}, which changes nothing in the fleet and records the "
            f"proposal as {closes_as(doc)}. A decision file that does not read is kept beside "
            f"the new one, never deleted.")


class ReadPane:
    """What one selection reads when it is selected (a proposal's `show`, a
    lead's firewall), as its last read answered.

    A read that fails keeps the last one that read (of the same selection,
    never another's), says so, and turns that selection's changes off until
    one reads again: a failed read must never pass for its state. Each read
    is numbered, so one that answers late never replaces a newer one."""

    def __init__(self) -> None:
        self.key = None          # what is selected
        self.doc = None          # its last read that answered
        self.read_at = None      # when that read ran
        self.error = None        # why the latest read failed, or None
        self.reading = False     # a read is running
        self._seq = 0

    def parse(self, result):
        """The answer about `self.key`, or ReadError."""
        raise NotImplementedError

    def select(self, key):
        """Select `key` (None: nothing), or read the selected one again.
        Returns the number its read answers with, or None."""
        if key != self.key:
            self.doc, self.read_at, self.error = None, None, None
        self.key = key
        self._seq += 1
        self.reading = key is not None
        return self._seq if self.reading else None

    def stale(self) -> None:
        """A refresh has started: anything may have changed since the last
        read, the operator's own change included. Nothing is allowed until the
        selection is read again, and a read already running is not taken,
        since it may have read before the change."""
        if self.key is not None:
            self._seq += 1
            self.reading = True

    def answer(self, seq, result, when=None) -> bool:
        """Take the answer of read `seq`. False, changing nothing, when another
        read was asked for since."""
        if seq != self._seq or self.key is None:
            return False
        self.reading = False
        try:
            doc = self.parse(result)
        except ReadError as e:
            self.error = str(e)
            return True
        self.doc, self.read_at, self.error = doc, when, None
        return True


class ProposalPane(ReadPane):
    """The proposal selected on the Proposals tab, as its last `show` read it.
    A show that fails turns Accept and Reject off until one reads again."""

    @property
    def pid(self):
        """The selected proposal's number."""
        return self.key

    def parse(self, result):
        return parse_proposal(result, self.key)

    def actions(self, ticked=False) -> set:
        """Accept and Reject, only from a show that read and is not being read
        again."""
        if self.reading or self.error is not None:
            return set()
        return proposal_actions(self.doc, ticked)

    def note(self, listed=True) -> str:
        """The line above the pane. `listed`: whether the list holds any
        proposal, or None when it has not been read."""
        if self.pid is None:
            if listed is None:
                return "The proposals have not been read."
            return ("Select a proposal to read it in full. Nothing it asks for changes until "
                    "you accept it." if listed else "No proposals from the hub.")
        if self.reading:
            return f"Reading proposal {self.pid}..."
        if self.error is not None:
            kept = f" Showing it as read at {self.read_at}." if self.doc is not None else ""
            return (f"Could not read proposal {self.pid}: {self.error}.{kept} Accept and "
                    f"Reject are off until it reads.")
        return f"Proposal {self.pid}, read at {self.read_at}."


# ======================================================================= gateways

#: Every field of a `gateway list --json` row, as the details pane names it.
GATEWAY_FIELDS = (
    ("name", "Gateway"), ("anonymising", "Anonymising"), ("label", "Label"),
    ("problem", "Problem"), ("in_ai_space", "In AI space"),
    ("upstream", "Upstream (its own network)"),
    ("upstream_ignores_firewall", "Its upstream ignores its firewall rules"),
    ("used_by", "AI qubes on it"), ("projects", "Projects that list it"),
)
#: The list's columns: (key, heading); `used` and `notes` are composed.
GATEWAY_COLUMNS = (("name", "Gateway"), ("anonymising", "Anonymising"), ("label", "Label"),
                   ("upstream", "Upstream"), ("used", "In use"), ("notes", "Notes"))
#: Beside an enrolled gateway whose own upstream is a Whonix gateway, which
#: hands its clients' traffic to Tor inside itself and applies none of their
#: firewall rules (measured on Qubes 4.3.1 with Whonix 18).
UPSTREAM_IGNORES = "its own firewall rules have no effect upstream"
#: The line above the Gateways tab's list.
GATEWAYS_NOTE = ("The networks AI space may use: a project lists some of them for its workers, "
                 "a lead is born on one, and the hub's own creates use one. Enroll routers of "
                 "your own, outside AI space or guarded. Enrolling, changing or removing one "
                 "changes no qube.")


def gateways_note(rows) -> str:
    """The line above the Gateways tab's list; `rows` None: never read."""
    if rows is None:
        return "The gateway registry has not been read."
    if not gateway_list(rows):
        return (GATEWAYS_NOTE + " None is enrolled: AI space can use no network until you "
                "enroll one.")
    return GATEWAYS_NOTE


def gateway_list(rows) -> list:
    """The rows of `gateway list --json` that carry a name."""
    return [r for r in rows or () if isinstance(r, dict) and isinstance(r.get("name"), str)]


def enrolled(gw_rows) -> list:
    """The enrolled gateways' names."""
    return sorted(r["name"] for r in gateway_list(gw_rows))


def gateway_notes(row) -> list:
    """What to know about an enrolled gateway before using it: that the
    command's checks no longer pass it, and that its upstream ignores its rules
    or that this cannot be read now."""
    out = []
    if row.get("problem"):
        out.append(f"NOT USABLE: {row['problem']}")
    if row.get("upstream_ignores_firewall") is True:
        out.append(UPSTREAM_IGNORES)
    elif row.get("upstream_ignores_firewall") == UNREADABLE:
        out.append("whether its upstream ignores its firewall rules cannot be read now; refresh")
    return out


def gateway_cells(row) -> list:
    """The list's cells. A gateway that is not usable, or whose upstream
    ignores its rules, says so on its row."""
    used = f"{len(row.get('used_by') or ())} qube(s)"
    if row.get("projects"):
        used += f"; listed by {', '.join(str(p) for p in row['projects'])}"
    values = {"used": used, "notes": "; ".join(gateway_notes(row))}
    return [esc(values[key] if key in values else row.get(key)) for key, _ in GATEWAY_COLUMNS]


def gateway_details(row) -> list:
    """(heading, text) for the pane beside the list: every field of the row."""
    if not isinstance(row, dict):
        return []
    out = []
    for key, heading in GATEWAY_FIELDS:
        value = row.get(key)
        if key == "problem":
            value = (f"NOT USABLE: {value}. qmcp check fails on it until that is fixed or it is "
                     f"removed" if value else "none: AI space may use it")
        elif key == "upstream_ignores_firewall":
            value = (f"yes: {UPSTREAM_IGNORES}. Its upstream, {row.get('upstream')}, is a "
                     f"Whonix gateway, which sends its clients' traffic to Tor inside itself "
                     f"and applies none of their firewall rules" if value is True
                     else "cannot be read now; refresh" if value == UNREADABLE else "no")
        elif key in ("used_by", "projects") and not value:
            value = "none"
        out.append((heading, esc(value)))
    return out


def gateway_actions(row) -> set:
    """Enroll, and Change and Remove for the selected gateway."""
    return {"enroll_gateway"} | ({"change_gateway", "remove_gateway"}
                                 if isinstance(row, dict) else set())


def gateway_in_use(row) -> str | None:
    """Why the command refuses to remove a gateway, as its row shows it, in
    the command's words (`fleet.remove_gateway`): a project lists it, or an
    AI qube is on it. None when the row shows neither."""
    listing = [str(p) for p in row.get("projects") or ()]
    users = [str(q) for q in row.get("used_by") or ()]
    if not listing and not users:
        return None
    return (f"'{row.get('name')}' is in use: projects {listing or '-'}, qubes {users or '-'}; "
            f"take it off their lists and clear their networks first")


def remove_gateway_intro(row) -> str:
    return (f"Takes {row.get('name')} out of the gateway registry: AI space may no longer use "
            f"it as a network, and the forms stop offering it. The qube itself does not "
            f"change. The command refuses while a project lists it or an AI qube is on it.")


def enroll_choices(fleet_rows, gw_rows, hub=None) -> list:
    """The qubes the enroll form offers: every qube that provides network
    (`list --all`), in AI space or not, that is not enrolled, but the hub."""
    have = set(enrolled(gw_rows))
    return sorted(r["name"] for r in fleet_rows or () if isinstance(r, dict)
                  and isinstance(r.get("name"), str) and r.get("gateway") is True
                  and r["name"] not in have and r["name"] != hub)


def _enroll_why(row, hub=None) -> str | None:
    b = badges(row)
    if unread_row(row):
        return "cannot be read now; refresh"
    if not row.get("gateway"):
        return "does not provide network"
    if row.get("name") == hub:
        return "is the hub"
    if b["drop_box"] or b["lead_tag"] or b["member"] or b["lead"]:
        return "is a drop box, a lead or a project's member"
    if row.get("state") is not None and not b["guarded"]:
        return f"is in AI space without qmcp-guarded (qmcp guard {row.get('name')})"
    return None


def enroll_refusal(row, hub=None) -> str | None:
    """Why the command refuses to enroll a qube, where the form can see it in
    the qube's `list` row, in the command's order and words
    (`fleet.gateway_refusal`): not a gateway; the hub; a drop box, a lead or a
    member; in AI space without qmcp-guarded. Qubes' firewall marker and the
    templates the qube is built on are the command's to check."""
    if not isinstance(row, dict):
        return "choose a qube that provides network"
    why = _enroll_why(row, hub)
    return None if why is None else f"'{row.get('name')}' cannot be enrolled: {why}"


def enroll_text(row, hub=None) -> str:
    """A qube as the enroll form lists it: its name, where it is, and why the
    command will refuse it, when the form can see why."""
    where = "in AI space" if row.get("state") is not None else "outside AI space"
    why = _enroll_why(row, hub)
    return f"{row['name']} ({where}" + (f"; cannot be enrolled: {why})" if why else ")")


def network_choices(gw_rows) -> list:
    """The networks a form offers a project or a lead: none first, then the
    enrolled gateways, the only ones the command takes. One that no longer
    qualifies is still listed and marked (`network_text`), so a list can be
    rid of it; choosing it is refused, as the command refuses it (`usable`)."""
    return ["none"] + enrolled(gw_rows)


def network_text(name, gw_rows) -> str:
    """A network as a form lists it: its name, and what to know about it."""
    if name == "none":
        return "none"
    row = next((r for r in gateway_list(gw_rows) if r["name"] == name), None)
    if row is None:
        return f"{name} (not enrolled)"
    notes = gateway_notes(row)
    return f"{name} ({'; '.join(notes)})" if notes else name


def usable(net, gw_rows) -> None:
    """A network given to a lead or put on a project's list, refused as the
    command refuses it (`fleet._usable_gateway`), in its words: not enrolled,
    or enrolled but no longer qualifying (the row's `problem`, which
    `qmcp check` fails on). Taking such a gateway off a list is never refused
    for not qualifying."""
    row = next((r for r in gateway_list(gw_rows) if r["name"] == net), None)
    if row is None:
        raise FormError(f"'{net}' is not an enrolled gateway (qmcp gateway enroll {net})")
    if row.get("problem"):
        raise FormError(f"'{net}' is enrolled but not usable: {row['problem']}")


def check_networks(networks, gw_rows) -> list:
    """A new list of worker networks as the command checks it
    (`fleet._check_networks`): every entry, in order, an enrolled gateway that
    still qualifies, or none. An entry already on the list is checked again:
    a new list that keeps a gateway that stopped qualifying is refused."""
    for n in networks:
        if n not in (None, "none"):
            usable(n, gw_rows)
    return list(networks)


def lead_network(source, origin, lead_netvm, fleet_rows, gw_rows):
    """The network a new lead will have, worked out as the command does
    (`fleet._lead_network`): a fresh lead's is the one chosen, or none; a
    promoted lead keeps its own, since no network moves, unless it is given
    none. It must be an enrolled gateway, or none, or the command refuses,
    and so does the form."""
    lead_netvm = lead_netvm or None
    if source == "promote":
        row = next((r for r in fleet_rows or () if isinstance(r, dict)
                    and r.get("name") == origin), None)
        current = row.get("netvm") if row else None
        if current == fleet.UNREADABLE:
            raise FormError(f"the network of '{origin}' cannot be read")
        if lead_netvm not in (None, "none", current):
            raise FormError("a promoted lead keeps its own network, since no network moves: "
                            "give it none (--lead-netvm none), or make a fresh lead")
        net = None if lead_netvm == "none" else current
    else:
        net = None if lead_netvm in (None, "none") else lead_netvm
    if net is not None:
        usable(net, gw_rows)
    return net


def lead_model(network, model, carried=None):
    """What the form sends as the lead's model endpoint, refused where the
    command refuses (`fleet._lead_rules`): a lead with a network needs one,
    typed or `carried` (a new lead of a project takes the project's), and a
    lead with no network takes none. The typed endpoint, or None."""
    typed = (model or "").strip()
    if typed:
        _model(typed)
        if network is None:
            raise FormError("a lead with no network reaches no model endpoint: leave the model "
                            "empty")
        return typed
    if network is not None and not carried:
        raise FormError("a lead with a network needs its model endpoint, host:port: dom0 writes "
                        "its firewall to allow that endpoint and DNS, nothing else")
    return None


def lead_info(network, carried=None, change=False) -> str:
    """The line under the lead's fields: where it will be, and what that asks
    of the model field. `change`: a new lead of a project, which takes the
    project's model, `carried`, when none is typed."""
    if network is None:
        return "The lead will have no network: leave the model empty. It needs no firewall."
    text = (f"The lead will be on {network}: dom0 writes its firewall to allow its model "
            f"endpoint and DNS, and nothing else.")
    if not change:
        return text + " Give its model endpoint."
    return text + (f" Left empty, the model is the project's, {carried}." if carried
                   else " The project has no model on record: give one.")


def old_lead_network(record, fleet_rows, gw_rows, keep_old, add_old_network) -> str:
    """What happens to the old lead's network, in words, as the command
    decides it: kept as a worker, it keeps its network if the project lists
    it; otherwise the tick adds that network to the list, and without the
    tick it goes to no network. Raises FormError where the command refuses."""
    old = record.get("lead")
    if add_old_network and not keep_old:
        raise FormError("the old lead's network can be added only when it is kept as a worker")
    row = next((r for r in fleet_rows or () if isinstance(r, dict) and r.get("name") == old),
               None) if old else None
    if not keep_old or row is None:
        return ""
    net, label = row.get("netvm"), record.get("label")
    if net == fleet.UNREADABLE:
        raise FormError(f"the network of the old lead {old} cannot be read")
    if net is None:
        return f"{old} has no network, and keeps none as a worker."
    if net in (record.get("networks") or ()):
        return f"{old} is on {net}, which {label} lists: it keeps it as a worker."
    if add_old_network:
        if len(record.get("networks") or ()) >= projects.MAX_NETWORKS:
            raise FormError(f"the project lists {projects.MAX_NETWORKS} networks already; take "
                            f"one off before adding the old lead's")
        # The command checks the whole new list, the entries already on it too.
        check_networks(list(record.get("networks") or ()) + [net], gw_rows)
        return (f"{old} is on {net}, which {label} does not list: the tick adds {net} to the "
                f"worker networks, and {old} keeps it.")
    return (f"{old} is on {net}, which {label} does not list: without the tick it goes to no "
            f"network as a worker.")


# ======================================================================= a lead's firewall

#: The fields of `project firewall NAME --json` that say whose firewall it is,
#: shown together on one line (a project's details show its slot and lead
#: already, so lines of their own would repeat those headings).
FIREWALL_OF = ("project", "slot", "lead")
#: Its other fields, a line each, as the view names them.
FIREWALL_FIELDS = (
    ("model", "Model endpoint"), ("accepted", "Rules you accepted"),
    ("live", "Rules it has now (live)"), ("read_error", "Live rules not read"),
    ("same", "Live rules are the ones you accepted"),
)


def parse_firewall(result: Result, key) -> dict:
    """The answer of `project firewall NAME --json` about project `key`, or
    ReadError: a read that failed is never taken for the lead's firewall."""
    if not result.ok:
        raise _failed(result)
    doc = parse_json(result)
    if (not isinstance(doc, dict) or key not in (doc.get("project"), doc.get("slot"))
            or any(k not in doc for k in FIREWALL_OF + tuple(k for k, _ in FIREWALL_FIELDS))
            or any(doc[k] is not None and not isinstance(doc[k], list)
                   for k in ("accepted", "live"))):
        raise ReadError(f"{shlex.join(result.argv)}: unexpected answer")
    return doc


def live_text(doc) -> Shown:
    """The lead's live rules, or why there are none to show: rules that were
    not read are never shown as an empty list."""
    live = doc.get("live")
    if isinstance(live, list):
        return rules_text(live, "")
    if doc.get("read_error"):
        return esc(f"could not be read ({doc['read_error']})")
    if not doc.get("lead"):
        return esc("none: the project has no lead")
    return esc(f"not read: no qube {doc['lead']} was found")


def same_text(doc) -> Shown:
    if doc.get("same") is True:
        return esc("yes")
    if not isinstance(doc.get("live"), list) or not isinstance(doc.get("accepted"), list):
        return esc("not known: the rules you accepted or the live ones are missing")
    return esc("no: they differ, and qmcp check fails on it while the lead has a network")


def firewall_details(doc) -> list:
    """(heading, text): every field of the read, the rules a rule per line."""
    if not isinstance(doc, dict):
        return []
    out = [("Lead firewall of", esc(f"{doc.get('project')} ({doc.get('slot')}), lead "
                                    f"{doc.get('lead') or 'none'}"))]
    for key, heading in FIREWALL_FIELDS:
        value = doc.get(key)
        if key == "read_error":
            if value is None:
                continue
            text = esc(value)
        elif key == "accepted":
            text = rules_text(value, "none on record")
        elif key == "live":
            text = live_text(doc)
        elif key == "same":
            text = same_text(doc)
        else:
            text = esc(value)
        out.append((heading, text))
    return out


def lead_on_network(doc, fleet_rows):
    """Whether the lead the view names has a network, from the lead's `list`
    row: True, False, or None when no row of that name is on show or its
    network could not be read, and the command decides."""
    lead = doc.get("lead") if isinstance(doc, dict) else None
    row = next((r for r in fleet_rows or () if isinstance(r, dict) and r.get("name") == lead),
               None) if lead else None
    if row is None or row.get("netvm") == fleet.UNREADABLE:
        return None
    return row.get("netvm") is not None


def model_refusal(doc, fleet_rows) -> str | None:
    """Why the command refuses `--model` for the view's lead where the window
    can see why, in its words (`fleet._set_lead_firewall`): a lead whose
    network cannot be read, and a lead with no network, which reaches no model
    endpoint. Its rules can still be set or accepted."""
    lead = doc.get("lead") if isinstance(doc, dict) else None
    if lead and any(isinstance(r, dict) and r.get("name") == lead
                    and r.get("netvm") == fleet.UNREADABLE for r in fleet_rows or ()):
        return f"the network of {lead} cannot be read"
    if lead_on_network(doc, fleet_rows) is False:
        return (f"{doc.get('lead')} has no network, so it reaches no model endpoint; set its "
                f"rules, or give the project a new lead on a network")
    return None


def firewall_actions(doc, fleet_rows=None) -> set:
    """Set rules while the project has a lead, and Set model too unless
    `model_refusal` finds, in `fleet_rows`, why the command refuses it; Accept current
    rules while its live rules were read, hold some, and are not the ones
    accepted. The command decides the rest."""
    if not isinstance(doc, dict) or not doc.get("lead"):
        return set()
    out = {"set_rules"}
    if model_refusal(doc, fleet_rows) is None:
        out.add("set_model")
    live = doc.get("live")
    if isinstance(live, list) and live and doc.get("same") is not True:
        out.add("accept_rules")
    return out


class FirewallPane(ReadPane):
    """The lead firewall of the project selected on the Qubes tab (the
    project, or its lead's row), as its last `project firewall NAME --json`
    read it. A read that fails keeps the last one of that project and turns
    its firewall changes off until one reads again."""

    def parse(self, result):
        return parse_firewall(result, self.key)

    def actions(self, key=None, fleet_rows=None) -> set:
        if key is None or key != self.key or self.reading or self.error is not None:
            return set()
        return firewall_actions(self.doc, fleet_rows)

    def note(self) -> str:
        if self.key is None:
            return ""
        if self.reading:
            return f"reading: qmcp project firewall {self.key} --json"
        if self.error is not None:
            kept = f" Showing it as read at {self.read_at}." if self.doc is not None else ""
            return f"could not be read: {self.error}.{kept} Its changes are off until it reads."
        return f"read at {self.read_at}: qmcp project firewall {self.key} --json"


def firewall_section(pane, key, fleet_rows=None) -> list:
    """The rows under a selection's details: how the lead's firewall was
    read, why Set lead model is off when the window can see the command's
    reason, then every field of that read. Nothing for a selection without a
    lead firewall, or before the pane is this selection's."""
    if key is None or pane.key != key:
        return []
    out = [("Lead firewall", esc(pane.note()))]
    why = model_refusal(pane.doc, fleet_rows)
    if why:
        out.append(("Set lead model", esc(f"off: {why}")))
    return out + firewall_details(pane.doc)


def firewall_changed(opened, ident, pane, fleet_rows=None) -> str | None:
    """Why a form opened on the read `opened` may no longer run `ident`, or
    None. Asked at OK: the pane must still allow it, with the fleet as it is
    now, and hold the same project, lead, model and rules, read again since
    if a refresh ran. A model for a lead that has lost its network since is
    refused in the command's words."""
    doc = pane.doc
    why = model_refusal(opened, fleet_rows) if ident == "set_model" else None
    if why:
        return why
    if (not isinstance(opened, dict)
            or ident not in pane.actions(opened.get("project"), fleet_rows)
            or not isinstance(doc, dict)
            or any(doc.get(k) != opened.get(k)
                   for k in ("project", "slot", "lead", "model", "accepted", "live"))):
        return ("the lead's firewall is being read again, or changed since this form opened: "
                "look at it again, and open the form again")
    return None


def rules_compare(doc, after=None, after_heading="After OK") -> list:
    """The rules side by side, for a form that changes a lead's firewall:
    the ones the operator accepted and the live ones, as the view read them,
    and `after` (rules, or why there are none yet) where the form knows it."""
    cols = [("Accepted now", rules_text(doc.get("accepted"), "none on record")),
            ("Live now", live_text(doc))]
    if after is not None:
        cols.append((after_heading, rules_text(after, "") if isinstance(after, list)
                     else esc(after)))
    return cols


def model_rules(text):
    """The rules `--model text` writes into the lead, or why there are none yet."""
    text = (text or "").strip()
    if not text:
        return "type the endpoint, host:port"
    try:
        return firewall.endpoint_rules(firewall.model_text(text))
    except firewall.FirewallError as e:
        return str(e)


def typed_rules(text, shown=()) -> list:
    """The rules typed into a form, a line each, blank lines skipped. A line
    left as the window showed one of `shown` is that rule exactly: a rule the
    window shows escaped is sent as it is, never as its escaped form."""
    back = {str(esc(rule)): rule for rule in shown}
    return [back.get(line.strip(), line.strip()) for line in str(text).splitlines()
            if line.strip()]


def model_intro(doc) -> str:
    return (f"Sets the model endpoint of {doc.get('lead')}, the lead of {doc.get('project')}: its "
            f"firewall becomes that endpoint, DNS and nothing else, and the project's record "
            f"keeps the endpoint as its model (now {doc.get('model') or 'none'}). This changes "
            f"what the lead can reach on the network: compare the rules below.")


def rules_intro(doc) -> str:
    return (f"The firewall of {doc.get('lead')}, the lead of {doc.get('project')}, becomes "
            f"exactly these rules, one per line in qubesd's format, as under Live now (e.g. "
            f"action=accept proto=tcp dsthost=example.com dstports=443). Blank lines are "
            f"skipped. The model on record does not change. This changes what the lead can "
            f"reach on the network: compare the rules below.")


def accept_rules_intro(doc, read_at=None) -> str:
    return (f"Records the rules {doc.get('lead')} has now as the ones you accept for it; "
            f"nothing on the qube changes, and from then on, while the lead has a network, qmcp "
            f"check compares its live rules with these. Only rules in qmcp's rule format can be "
            f"accepted (no comment or expire, at most 32). The command reads the live rules again when it runs; as read at "
            f"{read_at or '?'}, they are the ones under Live now.")


# ======================================================================= choices for the forms

def lead_templates(fleet_rows) -> list:
    """Any TemplateVM, in AI space or not: one outside it is the stronger
    choice for a lead, since the hub cannot edit it."""
    return sorted(r["name"] for r in fleet_rows if r.get("klass") == "TemplateVM"
                  and not unread_row(r))


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
                  and not r.get("gateway") and not unread_row(r))


def outside_choices(fleet_rows, hub=None, sinks=()) -> list:
    """Qubes a role action can bring into AI space: outside it, not the hub,
    not a dump sink."""
    return sorted(r["name"] for r in fleet_rows if r.get("state") is None
                  and r.get("name") not in (hub, *sinks) and not unread_row(r))


def move_targets(records: dict) -> list:
    """(command target, shown text): p00, each project, or no slot."""
    out = [("p00", "p00, the hub's own qubes")]
    for slot in projects.PROJECT_SLOTS:
        rec = records.get(slot)
        if rec is not None and rec.get("label"):
            out.append((rec["label"], f"{slot} {rec['label']}"))
    out.append(("none", "no slot (hub-only, copies by dialog)"))
    return out
