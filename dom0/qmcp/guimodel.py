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
  --json`): rules that could not be read are never shown as an empty list;
- a lead's model is a remote endpoint or a self-hosted model qube. The forms
  offer as a model qube only the qubes the command would take, as their `list`
  rows show it; choosing one takes the lead's network to none, which the form
  says in red before OK when the lead has one, and a qube that already serves
  another project carries the command's own warning that sharing it is a path
  between them;
- an anonymous project (`project create --anonymous`) is judged by the
  anonymity gate on every refresh (`gate --json`, which acts on what it finds,
  as its timer does). Its gate status, whether it is hidden from the hub and
  whether the gate stopped it are shown with the project, and every qube's
  anonymity badges are marked in the tree, read from the badges the rulebook
  routes on. A gate that did not answer keeps the last verdicts it gave, never
  "no anonymous project". The forms refuse what the command refuses for an
  anonymous project where the fields show why, and say in red what decides a
  hidden project's safety: that the hub may have operated what it runs on, and
  that a router it shares ties it to another project or the hub.

It cannot go stale: `tests/test_gui.py` walks the command's parser and the
JSON each read returns, and fails on any command, option or field the window
neither offers nor exempts here by name, with a reason.
"""
from __future__ import annotations

import json
import shlex

from qmcp import anon, birth, core, firewall, fleet, gateways, projects, proposals

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
    # The anonymity gate acts on what it finds (the badge, the kill), so it
    # runs first and alone (`FIRST_READS`): the reads after it show what it did.
    "gate": read_cmd("gate", "--json"),
    "fleet": read_cmd("list", "--all", "--json"),
    "projects": read_cmd("project", "list", "--json"),
    "check": read_cmd("check", "--json"),
    "settings": read_cmd("settings", "--json"),
    "audit": read_cmd("audit", "tail", str(AUDIT_TAIL)),
    "proposals": read_cmd("proposal", "list", "--json"),
    "gateways": read_cmd("gateway", "list", "--json"),
}
#: The reads a refresh runs before the others start.
FIRST_READS = ("gate",)
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


def _model_qube(name, allow_none=False) -> str:
    """A self-hosted model qube as the command takes it: a qube's name, or
    `none` where taking the project's away is meant (a lead change, a lead's
    firewall). A new project has none to take away."""
    if name == "none":
        if allow_none:
            return name
        raise FormError("choose the model qube")
    return _qube(name, "the model qube")


def _model_options(model, model_qube, lead_netvm, allow_none=False) -> list:
    """`--model HOST:PORT` or `--model-qube QUBE`, never both, refused where
    the command refuses them (`fleet._model_qube_lead_netvm`), in its words: a
    lead whose model is a qube has no network."""
    typed = (model or "").strip()
    if model_qube is None:
        return ["--model", _model(typed)] if typed else []
    if typed:
        raise FormError("say --model HOST:PORT or --model-qube QUBE, not both")
    if lead_netvm not in (None, "none"):
        raise FormError("a lead whose model is a qube has no network: drop --lead-netvm "
                        "(or give --lead-netvm none)")
    return ["--model-qube", _model_qube(model_qube, allow_none)]


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


def check_note(note) -> str:
    """An anonymous project's private note, checked with the command's own check."""
    why = projects.note_refusal(note)
    if why:
        raise FormError(why)
    return note


#: Why an anonymous project's lead comes only from a template, in the command's words.
FRESH_LEAD = ("an anonymous project's lead is only ever made fresh from a template "
              "(--lead-template), never a clone or a promoted qube with a past")


def create_project(label, lead_source, lead_origin, lead_name=None, lead_netvm=None,
                   templates=(), networks=(), quota=None, dump=False, model=None,
                   model_qube=None, anonymous=False, hub_sees=False, note=None) -> list:
    """`model` is the lead's model endpoint, or None. Whether the lead needs
    one depends on its network, which `lead_model()` judges with the fleet.
    `model_qube` is a self-hosted model qube instead; then the lead has no
    network. An `anonymous` project has no label (dom0 picks one at random) and
    no lead name, and its lead comes from a template; `hub_sees` and `note` go
    with it only, as the command has it (`fleet._create_project`)."""
    if anonymous:
        if label:
            raise FormError("an anonymous project's label is picked by dom0 at random, so a "
                            "name an agent leaks links to nothing: leave the label out")
        if lead_name:
            raise FormError("an anonymous project's lead is named by dom0 (<label>-lead): "
                            "leave --lead-name out")
        if note is not None:
            check_note(note)
    else:
        check_label(label)
        if hub_sees or note is not None:
            raise FormError("--hub-sees and --note go with --anonymous")
    if not networks:
        raise FormError("tick at least one worker network (a gateway, or none)")
    lead = _lead(lead_source, lead_origin, lead_name, lead_netvm)
    if anonymous and lead_source != "template":
        raise FormError(FRESH_LEAD)
    argv = write_cmd("project", "create", *([] if anonymous else [label]))
    if anonymous:
        argv.append("--anonymous")
    if hub_sees:
        argv.append("--hub-sees")
    if note is not None:
        argv += _option("--note", note)
    argv += lead
    argv += _model_options(model, model_qube, lead_netvm)
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
                keep_old=False, model=None, add_old_network=False, model_qube=None) -> list:
    """`model` None: a new lead with a network takes the project's model, and
    one without keeps the project's model qube. `model_qube` names another
    model qube, or `none` takes the project's away; either way the new lead
    has no network. `add_old_network` goes with `keep_old` only, as the
    command has it."""
    argv = write_cmd("project", "lead", _key(key),
                     *_lead(lead_source, lead_origin, lead_name, lead_netvm))
    if add_old_network and not keep_old:
        raise FormError("the old lead's network can be added only when it is kept as a worker")
    if keep_old:
        argv.append("--keep-old")
    if add_old_network:
        argv.append("--add-old-network")
    return argv + _model_options(model, model_qube, lead_netvm, allow_none=True)


def unblock_project(key) -> list:
    """Take the anonymity gate's stop off a project, once a fresh gate run
    finds it sound; autostart stays off."""
    return write_cmd("project", "unblock", _key(key))


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


def open_qube(qube, duration, firewall=False) -> list:
    """Open a guarded qube to the hub for a bounded time. `duration` is what
    the operator typed: the command parses it, so the form never has a second
    opinion about what "2h" means."""
    argv = write_cmd("open", _qube(qube, "the qube"), "--for", str(duration or "").strip())
    if firewall:
        argv.append("--firewall")
    return argv


def seal_qube(qube) -> list:
    return write_cmd("seal", _qube(qube, "the qube"))


def audit_rotate() -> list:
    return write_cmd("audit", "rotate")


def enroll_gateway(qube, anonymising=False, label=None, updates=False) -> list:
    """Let AI space use `qube` as a network. An empty label is no label.
    `updates`: the qube above it carries templates' updates anonymously."""
    argv = write_cmd("gateway", "enroll", _qube(qube, "the gateway"))
    if updates and not anonymising:
        raise FormError("templates' updates count only through an anonymising gateway")
    if anonymising:
        argv.append("--anonymising")
    if updates:
        argv.append("--updates")
    if label:
        argv += _option("--label", _gateway_label(label))
    return argv


def change_gateway(qube, anonymising=None, label=None, updates=None) -> list:
    """Only what changed: None leaves a part as it is; an empty label clears it."""
    argv = write_cmd("gateway", "set", _qube(qube, "the gateway"))
    if anonymising is None and label is None and updates is None:
        raise FormError("nothing changed")
    if anonymising is not None:
        argv += ["--anonymising", "yes" if anonymising else "no"]
    if updates is not None:
        argv += ["--updates", "yes" if updates else "no"]
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
    endpoint, DNS when it is a host name, and nothing else."""
    return write_cmd("project", "firewall", _key(key), "--model", _model(model))


def set_lead_model_qube(key, model_qube) -> list:
    """The project's model becomes the self-hosted model qube `model_qube`:
    the lead loses its network, and the qube leaves p00, loses its network
    and is guarded. `none` takes the project's model qube away."""
    return write_cmd("project", "firewall", _key(key), "--model-qube",
                     _model_qube(model_qube, allow_none=True))


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
            delete_plan, delete_project, role, open_qube, seal_qube,
            audit_rotate, show_proposal, accept_proposal,
            reject_proposal, enroll_gateway, change_gateway, remove_gateway,
            show_lead_firewall, set_lead_model, set_lead_model_qube, set_lead_rules,
            accept_lead_rules, unblock_project)

#: Commands and options the window does not offer, and why the operator types
#: them. An entry covers everything under it. Adding one is a decision, not a
#: way to get the suite green.
CLI_ONLY = {
    ("migrate",): "a one-time step from v0.9.16, run before the first install of this release",
    ("audit", "--path"): "reads a log other than the live one, such as a rotated file; "
                         "the window shows the live log",
    ("seal", "--all"): "the boot seal: qmcp-seal.service runs it before any user session exists, "
                       "so there is no window open for the operator to close by hand",
    ("seal", "--expired"): "the expiry pass: the gate's timer runs it every 15 seconds, and the "
                           "window closes a single qube's window with Seal",
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
    ("netvm", "Network"), ("power", "Power"), ("open", "Open window"),
    ("slot", "Slot badges"), ("lead", "Lead badge"),
    ("model", "Model qube of"), ("owner", "Created by"), ("gateway", "Provides network"),
    ("dvmt", "Disposable template"), ("badges", "Badges"),
)
#: Every field of a `project list` row.
PROJECT_FIELDS = (
    ("slot", "Slot"), ("label", "Label"), ("lead", "Lead"), ("members", "Members"),
    ("used", "Disk used"), ("quota", "Disk quota"), ("templates", "Approved templates"),
    ("networks", "Worker networks (first is the default)"), ("dump", "Dump sink"),
    ("model", "Lead's model endpoint"), ("model_qube", "Lead's model qube"),
    ("lead_firewall", "Lead firewall you accepted"),
    ("anonymous", "Anonymous"), ("hidden", "Hidden from the hub"), ("note", "Note (dom0 only)"),
    ("blocked", "Stopped by the anonymity gate"),
)
#: Every field of `settings --json`.
SETTINGS_FIELDS = (
    ("hub", "Hub (fixed at install)"), ("hub_power", "Hub power"),
    ("name_prefix", "Reserved name prefix"), ("pool_cap", "Pool cap (all of AI space)"),
    ("ai_space_bytes", "AI space disk used"), ("private_cap", "Private-volume cap (one qube)"),
    ("birth_egress", "Birth egress"), ("gateways_enrolled", "Gateways enrolled"),
    ("mode", "Mode (fixed at install)"), ("version", "qubes-mcp version"),
)
#: How the Settings tab says the mode.
MODE_TEXT = {
    "anonymous": ("anonymous: every project is anonymous, and the anonymity gate judges the hub "
                  "and the rest of AI space too. qmcp cannot check whose account the hub's model "
                  "uses, nor what the hub qube did before the mode. No qmcp command turns it "
                  "off; uninstall.sh --purge does"),
    "normal": "normal: anonymous projects are a per-project choice (install.sh --anonymous "
              "turns on anonymous mode)",
}
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
    if key == "mode":
        return esc(MODE_TEXT.get(value, f"{value}: /etc/qmcp/mode cannot be read, so the gate "
                                        f"blocks the hub"))
    if key == "blocked":
        return esc(BLOCKED_TEXT.get(value, value))
    if key == "open":
        # The command answers in seconds, which is the one form that cannot be
        # read two ways; a person reads a duration. Drawn on the box before
        # this was wired: the pane showed "899".
        return esc(window_left({"open": value}))
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


def light_text(doc) -> str:
    """What the light says. An open window is the one thing a GREEN check
    carries that the operator must see without opening the Check tab: it is
    their own deliberate exception, it clears itself, and while it lasts the
    hub is inside a qube that normally refuses it. Drawn on the dev box, a
    plain GREEN said nothing about it, though the window's own text promised
    the light would."""
    result = light(doc)
    note = open_window_note(doc)
    return f"qmcp check: {result}" + (f" — {note}" if note else "")


#: What the light adds while a window is open. A fixed phrase, not the check
#: item's own words: a light is a status and not a sentence, and the Check tab
#: and the details pane are where the qube and its time are named.
OPEN_NOTE = "a guarded qube is open"


def open_window_note(doc) -> str:
    """OPEN_NOTE while the open-windows item is the warning it is, else ""."""
    for row in (doc or {}).get("findings") or ():
        if row.get("check") == "open windows" and row.get("status") == "warn":
            return OPEN_NOTE
    return ""


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
            "dump": {s for k, s in parts if k == "dump"},
            "model": {s for k, s in parts if k == "model"},
            # The open window's badges, which the rulebook routes on exactly
            # as it does on the slot badges above.
            "open": tags & {core.OPEN, core.OPEN_FW}}


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
    "model_kind": ("model badge on a template or gateway",
                   "a model badge on a template, a disposable template, a disposable or a "
                   "gateway, which is never a model qube: the rulebook still lets the badge's "
                   f"lead reach it on port {projects.MODEL_PORT}"),
    "model_member": ("model qube in a slot",
                     "a model badge on a member of a slot, p00 included: a model qube is in no "
                     "slot. In one, it copies into the slot's members and its sink without a "
                     f"dialog, and the leads it serves reach a qube of that slot on port "
                     f"{projects.MODEL_PORT}"),
    "model_record": ("model badge, no record",
                     "a model badge its slot's record does not name: the rulebook still lets that "
                     f"slot's lead reach it on port {projects.MODEL_PORT}"),
    "model_network": ("model qube with a network",
                      "a model qube with a network: the leads it serves reach that network through "
                      "it, around the firewalls you accepted for them"),
    "model_template": ("model qube on a managed template",
                       "its template is one the hub manages (in AI space and not guarded): the hub "
                       "can change what runs in it at its next start"),
    "model_lead": ("lead with a network, model a qube",
                   "its project's model is a qube, so it has no network, and this lead was given "
                   "one: the project is no longer sealed. Set model qube... on the project, with "
                   "the same qube, takes the network away again (as qvm-prefs LEAD netvm '' does)"),
    "unreadable": ("cannot be read", "a read of its tags, class or role failed (for a model qube, "
                                     "its network or its template too), so the window offers "
                                     "nothing on it. A command reads it again and refuses what it "
                                     "still cannot read. Refresh"),
}


def _attention(code):
    return "attention", f"needs attention: {ATTENTION[code][0]}", code


def _and(items) -> str:
    """`a`, `a and b`, `a, b and c`."""
    items = [str(i) for i in items]
    return ", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else "".join(items)


def model_role(slots, guarded=True, records_read=True) -> str:
    """A model qube's role: the slots it serves, shared when more than one,
    and not guarded while the operator has it managed."""
    role = f"model qube of {_and(sorted(slots))}"
    if len(slots) > 1:
        role += ", shared"
    if not guarded:
        role += ", not guarded"
    return role if records_read else role + " (records not read)"


def classify(row, records, hub=None, by_name=None):
    """(where, role, attention) for one qube, from its badges and the records.
    `where` is a slot, `templates`, `gateways`, `models`, `guarded`, `noslot`,
    `attention`, or None (not in the tree). `records` is None when they could
    not be read: then nothing is judged against them. `by_name` holds every
    `list` row by name: a model qube is judged by its template's row too."""
    b = badges(row)
    name = row["name"]
    if unread_row(row):
        return _attention("unreadable")
    if row.get("state") is None:
        if b["member"] or b["lead"] or b["lead_tag"] or b["model"]:
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
        # What the badges alone show (`core.lead_badges_agree`) is judged
        # whether or not the records were read; only the record waits for them.
        if not b["lead_tag"] or slot is None or b["member"] or b["guarded"] or b["model"]:
            return _attention("lead")
        if records is None:
            return slot, "lead (records not read)", None
        rec = records.get(slot)
        if rec is None or rec.get("lead") != name:
            return _attention("lead")
        # A lead whose model is a qube has none; one that was given a network
        # outside qmcp fails the check (one whose network does not read leaves it
        # incomplete, and is shown as the lead it is).
        if rec.get("model_qube") and row.get("netvm") not in (None, UNREADABLE):
            return _attention("model_lead")
        return slot, "lead", None
    if len(b["member"]) > 1:
        return _attention("two_slots")
    if b["member"] and (row.get("gateway") or _is_template_row(row)):
        return _attention("template_member")
    if row.get("gateway") and not b["guarded"]:
        return _attention("gateway")
    if b["model"]:
        return _model_place(row, b, records, by_name)
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


def _model_why(row, by_name=None, hub=None):
    """(kind, why) when the command refuses `row`'s qube as a model qube
    (`fleet.model_qube_refusal`), as far as `list` rows show it, in the
    command's order and words; None when they show no reason. `kind` is
    `unreadable` (a value it needs could not be read, its template's
    included), `hub`, `kind` (a class, a disposable template or a gateway),
    `drop_box`, `outside` (outside AI space: the command never brings one
    in), `lead`, `member` (of a project other than p00) or `template` (one
    the hub manages, anywhere in its template chain, read from `by_name`)."""
    if unread_row(row) or UNREADABLE in row.values():
        return "unreadable", "cannot be read now; refresh"
    if hub is not None and row.get("name") == hub:
        return "hub", "is the hub"
    klass = row.get("klass")
    if klass not in ("AppVM", "StandaloneVM"):
        return "kind", f"is a {klass}; a model qube is an AppVM or a StandaloneVM"
    if row.get("dvmt"):
        return "kind", "is a disposable template"
    if row.get("gateway"):
        return "kind", "provides network"
    b = badges(row)
    if b["drop_box"] or b["dump"]:
        return "drop_box", "is a drop box"
    if row.get("state") is None:
        return "outside", f"is outside AI space: guard it first (qmcp guard {row.get('name')})"
    if b["lead_tag"] or b["lead"]:
        return "lead", "is a lead"
    others = b["member"] - {projects.HUB_SLOT}
    if others:
        return "member", f"is a member of {', '.join(sorted(others))}"
    tpl, seen = row.get("template"), set()
    while tpl is not None and tpl not in seen:
        seen.add(tpl)
        trow = (by_name or {}).get(tpl)
        if trow is None or unread_row(trow) or trow.get("template") == UNREADABLE:
            return "unreadable", f"its template {tpl} cannot be read now; refresh"
        tb = badges(trow)
        if tb["umbrella"] and not tb["guarded"]:
            return "template", (f"its template {tpl} is one the hub manages (guard it, or use "
                                f"another)")
        tpl = trow.get("template")
    return None


def _model_place(row, b, records, by_name):
    """Where a qube that wears a model badge goes, in the tree: Model qubes
    when it is one as the rulebook and the records need it, else Needs
    attention for the first thing `qmcp check` fails on it
    (`fleet.model_qube_findings`); one that is not guarded is only warned
    about, and stays a model qube. The hub, a drop box and a lead were
    placed before this is asked."""
    why = _model_why(row, by_name)
    kind = why[0] if why else None
    if kind == "kind":
        return _attention("model_kind")
    if b["member"]:
        return _attention("model_member")
    if kind == "unreadable":
        return _attention("unreadable")
    if records is not None and any(
            not (records.get(s) or {}).get("label") or (records.get(s) or {}).get("model_qube")
            != row["name"] for s in b["model"]):
        return _attention("model_record")
    if row.get("netvm") is not None:
        return _attention("model_network")
    if kind == "template":
        return _attention("model_template")
    return "models", model_role(b["model"], b["guarded"], records is not None), None


def _qube_node(row, role, attention=None) -> Node:
    """A qube's row. Its Role cell adds what its anonymity badges mean
    (`qube_marks`); the role the window acts on stays as it is."""
    marks = qube_marks(row)
    shown_role = ", ".join([role] + marks) if marks else role
    return Node(f"qube:{row['name']}", "qube", _cells(row["name"], shown_role, row),
                dict(row, role=role, attention=attention))


def _ref(slot, what, name, role, shared=None) -> Node:
    """A project's lead, sink or model qube that is shown elsewhere, or
    missing: a key of its own, so no qube is ever two rows under one key.
    `shared`: what a model qube that serves other projects too means."""
    data = {"name": name, "role": role}
    if shared:
        data["shared"] = shared
    return Node(f"ref:{slot}:{what}", "ref", _cells(name, role), data)


def build_tree(fleet_rows, project_rows, settings, gate=None) -> list:
    """The tree: the hub with p00 and the qubes in no slot, the projects with
    their leads, workers, sinks and model qubes, templates, gateways, model
    qubes, other guarded qubes, and Needs attention: the qubes whose badges
    the rulebook acts on against the records (see `ATTENTION`); every other
    failure of `qmcp check` is on the Check tab. A model qube may serve
    several projects, so it has one row, under Model qubes, and each project
    it serves a reference to it. `project_rows` None means the records could
    not be read, and nothing is judged against them. `gate`: the verdicts of
    `gate --json`, None when never read; an anonymous project's row says
    what kind it is, its note, whether the gate stopped it and what the gate
    found (`project_role`)."""
    rows = [r for r in fleet_rows or () if isinstance(r, dict) and isinstance(r.get("name"), str)]
    by_name = {r["name"]: r for r in rows}
    records = None if project_rows is None else {
        p["slot"]: p for p in project_rows if isinstance(p, dict) and p.get("slot")}
    settings = settings or {}
    hub_name = settings.get("hub")
    buckets: dict = {}
    placed: dict = {}
    for row in rows:
        where, role, attention = classify(row, records, hub_name, by_name)
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

    def model_child(slot, name):
        row = by_name.get(name)
        if row is None:
            return _ref(slot, "model", name, "model qube (missing)")
        if placed.get(name) == "attention":
            return _ref(slot, "model", name, "model qube (see Needs attention)")
        if slot not in badges(row)["model"]:
            return _ref(slot, "model", name, "model qube (no badge: its lead cannot reach it)")
        return _ref(slot, "model", name, "model qube (see Model qubes)",
                    model_shared(records.get(slot), rows))

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
        name = f"{slot} {rec.get('label')}" + (f": {rec['note']}" if rec.get("note") else "")
        node = Node(f"project:{slot}", "project",
                    _cells(name, project_role(rec, verdict_for(slot, gate))), dict(rec))
        leads = [m for m in members if m.data.get("role") == "lead"]
        lead_name = rec.get("lead")
        if lead_name and not leads:
            role = ("lead (see Needs attention)" if placed.get(lead_name) == "attention"
                    else "lead (missing)")
            leads = [_ref(slot, "lead", lead_name, role)]
        node.children = leads + [m for m in members if m.data.get("role") != "lead"]
        if rec.get("dump"):
            node.children.append(sink_child(slot, rec["dump"]))
        if rec.get("model_qube"):
            node.children.append(model_child(slot, rec["model_qube"]))
        projects_node.children.append(node)

    out = [hub, projects_node]
    for where, title, note in (("templates", "Templates", "the hub builds managed ones"),
                               ("gateways", "Gateways", "guarded"),
                               ("models", "Model qubes",
                                f"no network; their leads reach them on port {projects.MODEL_PORT}"),
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


def _row(fleet_rows, name):
    """The `list` row of `name`, or None."""
    return next((r for r in fleet_rows or () if isinstance(r, dict) and r.get("name") == name),
                None) if name else None


def model_shared(record, fleet_rows) -> str | None:
    """When a project's model qube serves other projects as well: which, and
    what sharing one means, in the command's words. None otherwise, and when
    its row is not on show or does not read."""
    q = (record or {}).get("model_qube")
    row = _row(fleet_rows, q)
    if row is None or unread_row(row):
        return None
    others = sorted(badges(row)["model"] - {record.get("slot")})
    return f"{q} also serves {', '.join(others)}: {fleet.SHARED_MODEL_WARNING}" if others else None


def model_notes(row, project_rows=None) -> list:
    """What to know about a model qube, under its role: the projects it
    serves, that one serving several is a path between them, and whether the
    hub may operate it now (the operator's maintenance window)."""
    b = badges(row)
    slots = sorted(b["model"])
    labels = {p.get("slot"): p.get("label") for p in project_rows or () if isinstance(p, dict)}
    serves = ", ".join(f"{s} {labels[s]}" if labels.get(s) else s for s in slots)
    who = "its lead reaches" if len(slots) == 1 else "the lead of each reaches"
    out = [("Serves", esc(f"{serves}: {who} it over qubes.ConnectTCP on port "
                          f"{projects.MODEL_PORT}"))]
    if len(slots) > 1:
        out.append(("Shared", esc(fleet.SHARED_MODEL_WARNING)))
    out.append(("Maintenance", esc(
        "guarded: the hub cannot operate it. Manage... opens it to the hub while it needs changes, "
        "and qmcp check warns until Guard... closes it again" if b["guarded"] else
        "not guarded: the hub may operate it (run commands in it as root, change it) until you "
        "guard it again with Guard...; qmcp check warns meanwhile")))
    return out


def details(node: Node, project_rows=None, fleet_rows=None, gate=None, hub=None) -> list:
    """(heading, text) pairs for the details pane. `fleet_rows` say whether
    a project's model qube serves other projects too, and with `hub` whether
    a hidden project shares a router; `gate` holds the anonymity gate's
    verdicts (None: never read)."""
    if node.kind == "qube":
        rows = [(label, field_text(key, node.data.get(key))) for key, label in QUBE_FIELDS
                if key in node.data]
        why = ATTENTION.get(node.data.get("attention"))
        notes = (model_notes(node.data, project_rows)
                 if str(node.data.get("role") or "").startswith("model qube") else [])
        return ([("Role", esc(node.data.get("role")))] + ([("Why", esc(why[1]))] if why else [])
                + anonymity_notes(node.data) + notes + rows)
    if node.kind == "project":
        out = [(label, field_text(key, node.data.get(key))) for key, label in PROJECT_FIELDS]
        shared = model_shared(node.data, fleet_rows)
        out += [("Its model qube is shared", esc(shared))] if shared else []
        if node.data.get("anonymous"):
            out.append(("Anonymity gate", esc(gate_status_text(
                verdict_for(node.data.get("slot"), gate), gate is not None))))
            routers = shared_routers(node.data, project_rows, fleet_rows, hub)
            if routers:
                out.append(("Shares a router", esc(shared_router_warning(routers))))
        return out
    if node.kind == "slot":
        return [("Slot", esc(node.data.get("slot")))]
    if node.kind == "ref":
        out = [("Role", esc(node.data.get("role"))), ("Name", esc(node.data.get("name")))]
        return out + ([("Shared", esc(node.data["shared"]))] if node.data.get("shared") else [])
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
    if blocked_project(node, records) is not None:
        out.add("unblock")
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
        if (role in ("worker", "hub's qube", "hub's qube, no slot")
                and node.data.get("klass") == "AppVM" and not stopped_qube(node.data)):
            out.add("move")
        if state == "guarded" and role != "gateway":
            out.add("manage")
        # The window is the bounded alternative to Manage, on a guarded qube
        # the command will take: never a gateway, never one the gate stopped
        # or a hidden project's (`attention` and `state is None` returned
        # above cover the rest). Seal shows whenever a badge is on, including
        # on a qube Open refuses, which is how the operator takes one off by
        # hand without waiting for the pass.
        if state == "guarded" and role != "gateway" and not open_window_of(node.data):
            out.add("open")
        if open_window_of(node.data) is not None:
            out.add("seal")
        # A model qube is managed only for its maintenance window, which Guard closes.
        if state == "managed" and (role in ("hub's qube, no slot", "template", "disposable template")
                                   or role.startswith("model qube")):
            out.add("guard")
        if not role.startswith("lead"):
            out.add("revoke")
    return out


def open_window_of(row) -> str | None:
    """What a row's badges say about its window: None when it is not open,
    else a short phrase for a button's reach and a form's text. Read from the
    badges, which is what the rulebook routes on, never from the `open` field,
    which is the record's view and may be UNREADABLE."""
    worn = set(badges(row or {}).get("open") or ())
    if not worn:
        return None
    return "open, firewall rules too" if core.OPEN_FW in worn else "open"


def window_left(row) -> str:
    """The `open` field as the details pane shows it (`field_text`)."""
    left = (row or {}).get("open")
    if left is None:
        return "sealed"
    if left == UNREADABLE:
        return f"{UNREADABLE} (a badge is on and its record will not read; qmcp check fails)"
    if left <= 0:
        return "ran out; the next pass of the gate's timer seals it"
    return f"{left // 60} min left" if left >= 60 else f"{left} s left"


def open_intro(row) -> str:
    """What opening a guarded qube does, for the form that asks."""
    name = (row or {}).get("name")
    return (f"{name} is guarded, so the rulebook refuses the hub every service into it. A window "
            f"lets the hub run commands in it as root, and copy a file in, which Qubes asks you "
            f"to confirm one file at a time. With the firewall box ticked it may also write the "
            f"qube's firewall rules; it can never change which network the qube is on, which "
            f"stays yours. The window ends by itself, and at every boot, and Seal ends it at "
            f"once. qmcp check shows amber while it is open.")


def seal_intro(row) -> str:
    """What sealing does, for the form that asks. The kill is the part worth
    saying plainly: it is why a window is closed deliberately and not left to
    run out while something is mid-install."""
    name = (row or {}).get("name")
    return (f"{name} goes back to sealed at once: the badges come off, and if it is running it is "
            f"KILLED, so nothing the hub started in it runs on. A package manager stopped "
            f"part-way may leave the qube needing repair. Its files stay: what the hub wrote "
            f"to disk is still there, and whatever is set to start from there runs at its next "
            f"start.")


def role_intro(action, row) -> str:
    """What Manage or Guard does to a qube, for the form that confirms it. A
    model qube's says what it means for the leads it serves: managed is the
    operator's maintenance window, during which the hub may operate it."""
    name = row.get("name")
    becomes, what = (("managed", "the hub may run commands in it as root and change it")
                     if action == "manage" else
                     ("guarded", "it is listed and referenced, never operated"))
    text = f"{name} becomes {becomes}: {what}."
    # Only a kind that can be a model qube is one, whatever it wears: Guard
    # never kills a gateway or a template.
    kind = row.get("klass") in ("AppVM", "StandaloneVM") and row.get("dvmt") is False \
        and row.get("gateway") is False
    serves = sorted(badges(row)["model"]) if kind else []
    if serves and action == "manage":
        text += (f" It stays the model qube of {_and(serves)}, and their leads still reach it on "
                 f"port {projects.MODEL_PORT}: this opens its maintenance window, and qmcp check "
                 f"warns until you guard it again.")
    elif serves:
        text += (f" It stays the model qube of {_and(serves)}; its maintenance window closes: if "
                 f"it runs, it is killed, so no process the hub started in it runs on. Its files "
                 f"stay: what the hub left in /home, /usr/local or /rw (anywhere, in a "
                 f"StandaloneVM), and whatever is set to start from there runs at its next "
                 f"start.")
    return text


def revoke_note(row) -> str:
    """What revoking a model qube means for the projects it serves, for the
    form that asks; empty for any other qube."""
    serves = sorted(badges(row or {})["model"])
    if not serves:
        return ""
    return (f"It is the model qube of {_and(serves)}: revoking takes its model badges too, so "
            f"their leads no longer reach it, and qmcp check warns until each project gets "
            f"another (Set model qube...).")


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
    ("anonymous", "Anonymous (dom0 picks its label; the hub is never told it)"),
    ("hub_sees", "The hub may see it"),
    ("lead", "Lead"), ("lead_name", "Lead name"), ("lead_netvm", "Lead network"),
    ("model", "Lead's model endpoint"), ("model_qube", "Lead's model qube"),
    ("remove", "Remove the lead"), ("keep_old", "Keep the old lead as a worker"),
    ("add_old_network", "Add the old lead's network to the worker networks"),
    ("templates", "More approved templates"),
    ("networks", "Worker networks (first is the default)"), ("quota", "Workers' disk quota"),
    ("dump", "Also create its dump sink"), ("name", "Sink name"),
    ("add_templates", "Templates to add"), ("remove_templates", "Templates to remove"),
    ("add_networks", "Worker networks to add"), ("remove_networks", "Worker networks to remove"),
    ("default_network", "New default worker network"),
    ("rules", "Lead firewall rules"),
    ("qube", "Guarded qube to open"), ("for", "The window lasts"),
    ("firewall", "Also lets the hub write that qube's firewall rules"),
)
#: An edit's project record now and after accepting, a line per part.
EDIT_FIELDS = (("templates", "Templates, now -> after"),
               ("networks", "Worker networks, now -> after"),
               ("quota", "Quota, now -> after"))
#: A lead-firewall proposal's lead now and after accepting, one above the
#: other: `before` holds the model and the model qube, the accepted and live
#: rules, and why the live ones could not be read (shown in their line, in
#: place of the rules); `after` the model, the model qube and the rules it
#: sets, none for a model qube change, which writes no rules.
FIREWALL_CHANGE = (("model", "Lead's model, now -> after"),
                   ("model_qube", "Lead's model qube, now -> after"),
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
    if key == "model_qube" and value == "none":
        return esc("none: the project's model qube is taken away")
    return field_text(key, value)


def firewall_change(before, after) -> list:
    """(heading, text) for a lead-firewall proposal: the model and the model
    qube now and after, then the rules the operator accepted, the live ones,
    and the ones accepting sets, a rule per line, one above the other. Live
    rules that were not read say why: they could not be read (and the error),
    or there was no lead's qube to read them from; never an empty list. A
    model qube change sets no rules, and says why. With no "after" (the
    change cannot apply), each "after" value points at the plan, which says
    why."""
    before = before if isinstance(before, dict) else {}
    known = isinstance(after, dict)
    after = after if known else {}
    h = dict(FIREWALL_CHANGE)

    def then(key):
        return _plain(key, after.get(key)) if known else "? (see Plan)"

    if isinstance(before.get("live"), list) or not before.get("read_error"):
        live = rules_text(before.get("live"), "not read: the project has no lead, or no qube "
                                              "of that name")
    else:
        live = esc(f"could not be read ({before['read_error']})")
    if not known:
        rules = esc("? (see Plan)")
    elif "model_qube" in after and after.get("rules") is None:
        rules = esc("(none: the lead has no network)" if after.get("model_qube") else
                    "(none: nothing is written to the lead)")
    else:
        rules = rules_text(after.get("rules"), "-")
    return [(h["model"], esc(f"{_plain('model', before.get('model'))} -> {then('model')}")),
            (h["model_qube"], esc(f"{_plain('model_qube', before.get('model_qube'))} -> "
                                  f"{then('model_qube')}")),
            (h["accepted"], rules_text(before.get("accepted"), "none on record")),
            (h["live"], live),
            (h["rules"], rules)]


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


def _subject(doc) -> str:
    """What a proposal is about, for a form's words: an anonymous create has
    no label until dom0 picks one."""
    if doc.get("subject"):
        return str(doc["subject"])
    options = doc.get("proposal") if isinstance(doc.get("proposal"), dict) else {}
    return "a new anonymous project" if options.get("anonymous") else "-"


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
            f"{_subject(doc)}. Its command runs as root and checks the fleet as it is "
            f"when it runs. Once it runs, the proposal closes: accepted, or failed with the "
            f"command's report.{tick} {runs}")


def reject_intro(doc) -> str:
    return (f"Closes proposal {doc.get('id')} from {doc.get('caller')}: {doc.get('type')} "
            f"{_subject(doc)}, without running anything. The hub learns only that it was "
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
    ("recorded_upstream", "Upstream recorded when marked anonymising"),
    ("updates", "Templates' updates may go to that upstream"),
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


def moved_note(row) -> str | None:
    """What to know about an anonymising gateway's upstream against the one
    recorded when it was marked (the gate's networks condition): none
    recorded, moved since, or not readable now. None otherwise."""
    if row.get("anonymising") is not True:
        return None
    recorded, now = row.get("recorded_upstream"), row.get("upstream")
    if recorded is None:
        return ("no upstream recorded: mark it anonymising again (Change...), or the gate stops "
                "every anonymous project on it")
    if now == UNREADABLE:
        return (f"whether it is still on {recorded}, as recorded, cannot be read now; refresh")
    if now != recorded:
        return (f"MOVED: it is on {now or 'no network'}, not on {recorded} as recorded: the gate "
                f"stops every anonymous project on it. Put it back, or mark it again (Change...)")
    return None


def gateway_notes(row) -> list:
    """What to know about an enrolled gateway before using it: that the
    command's checks no longer pass it, that an anonymising one is not on the
    upstream recorded for it, and that its upstream ignores its rules or that
    this cannot be read now."""
    out = []
    if row.get("problem"):
        out.append(f"NOT USABLE: {row['problem']}")
    moved = moved_note(row)
    if moved:
        out.append(moved)
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
        elif key == "recorded_upstream":
            value = ("- (not anonymising)" if row.get("anonymising") is not True else
                     moved_note(row) or f"{value}, where it is now")
        elif key == "updates":
            value = ("- (not anonymising)" if row.get("anonymising") is not True else
                     f"yes: you said {row.get('recorded_upstream')} carries them anonymously"
                     if value is True else
                     "no: a template whose updates go there stops an anonymous project (tick it "
                     "with Change... when the qube above this router is the anonymiser itself, "
                     "never sys-firewall)")
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


def anonymising_refusal(name, netvm) -> str | None:
    """Why the command refuses to mark gateway `name` anonymising, given its
    network now (`fleet._recorded_upstream`), in its words: one with no
    network carries nothing anonymously, and one whose network cannot be read
    cannot have it recorded."""
    if netvm == UNREADABLE:
        return f"the network of '{name}' cannot be read; try again"
    if netvm is None:
        return (f"'{name}' has no network of its own, so it cannot carry anything anonymously; "
                f"give it its upstream (sys-whonix, a VPN qube) first")
    return None


def mode_clearnet_refusal(mode) -> str:
    """Why a form refuses a gateway that is not anonymising, in the command's
    words (`fleet.MODE_CLEARNET`), or why it cannot tell."""
    if mode == "anonymous":
        return fleet.MODE_CLEARNET
    return ("whether anonymous mode is on is not known (Settings: Mode); a clearnet gateway is "
            "refused until it is")


def unmark_refusal(name, project_rows, fleet_rows) -> str | None:
    """Why the command refuses to take the anonymising mark off gateway
    `name` (`fleet.set_gateway`), in its words: an anonymous project uses it."""
    users = anonymous_users(name, project_rows, fleet_rows)
    if users:
        return (f"'{name}' carries the anonymous project(s) {', '.join(users)}; they would be "
                f"stopped. Delete them, or give them other networks, first")
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


def network_text(name, gw_rows, anonymising=False) -> str:
    """A network as a form lists it: its name, and what to know about it;
    with `anonymising`, also whether it is marked anonymising (a project
    form, where an anonymous project takes only those)."""
    if name == "none":
        return "none"
    row = next((r for r in gateway_list(gw_rows) if r["name"] == name), None)
    if row is None:
        return f"{name} (not enrolled)"
    notes = (["anonymising"] if anonymising and row.get("anonymising") is True else []) \
        + gateway_notes(row)
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
                        "its firewall to allow that endpoint, DNS when it is a host name, and "
                        "nothing else")
    return None


def lead_info(network, carried=None, change=False, qube=None, project_qube=None) -> str:
    """The line under the lead's fields: where it will be, and what that asks
    of the model field. `change`: a new lead of a project, which takes the
    project's model, `carried`, when none is typed, and with no network keeps
    the project's model qube, `project_qube`. `qube`: a self-hosted model
    chosen instead ("" keeps `project_qube`, "none" takes it away); then the
    lead has no network."""
    if qube is not None:
        if qube == "none":
            return (f"The lead will have no network and no model: {project_qube} stops being the "
                    f"project's model qube. It needs no firewall.")
        if not (qube or project_qube):
            return ("The lead will have no network: a lead whose model is a qube has none. "
                    "Choose its model qube.")
        return (f"The lead will have no network: a lead whose model is a qube has none. It "
                f"reaches {qube or project_qube} on port {projects.MODEL_PORT}, and needs no "
                f"firewall.")
    if network is None:
        if change and project_qube:
            return (f"The lead will have no network: leave the endpoint empty. It needs no "
                    f"firewall, and reaches the project's model qube {project_qube}.")
        return "The lead will have no network: leave the model empty. It needs no firewall."
    text = (f"The lead will be on {network}: dom0 writes its firewall to allow its model "
            f"endpoint, DNS when that is a host name, and nothing else.")
    if not change:
        return text + " Give its model endpoint."
    if project_qube:
        return text + (f" Give its model endpoint: a remote model replaces the project's model "
                       f"qube {project_qube}.")
    return text + (f" Left empty, the model is the project's, {carried}." if carried
                   else " The project has no model on record: give one.")


# ======================================================================= model qubes

#: Why a model-qube field offers nothing to choose.
NO_MODEL_QUBE = ("no qube here can be a model qube: an AppVM or a StandaloneVM in AI space that "
                 "is no disposable template, gateway, drop box, lead or member of a project but "
                 "p00, on no template the hub manages (a qube of yours outside AI space joins it "
                 "with qmcp guard NAME, once it has no network or sits on an enrolled gateway)")
#: Why it offers nothing when the hub is not known: the command refuses every qube then.
NO_HUB = ("the hub is not known (Settings: the hub file cannot be read), so the command refuses "
          "every model qube until it reads")


def no_model_qube(hub) -> str:
    """Why a model-qube field offers nothing to choose."""
    return NO_MODEL_QUBE if hub else NO_HUB


def model_qube_choices(fleet_rows, hub=None) -> list:
    """The qubes a form offers as a project's model qube: those the command
    would take (`fleet.model_qube_refusal`), as far as their `list` rows show
    it. Never one outside AI space: the command takes only a qube already in
    it. A row with a value that could not be read is not offered, nor one
    whose template's row does not read, and nothing is while the hub is not
    known; the command checks everything again when it runs."""
    if not hub:
        return []
    rows = [r for r in fleet_rows or () if isinstance(r, dict) and isinstance(r.get("name"), str)]
    by_name = {r["name"]: r for r in rows}
    return sorted(r["name"] for r in rows if _model_why(r, by_name, hub) is None)


def model_qube_text(row, slot=None) -> str:
    """A qube as a model-qube field lists it: its name, where it is, and the
    slots it serves already (`slot`'s own: the project's model qube now)."""
    b = badges(row)
    notes = [str(row.get("state"))]
    if projects.HUB_SLOT in b["member"]:
        notes.append("in p00")
    if row.get("netvm") is not None:
        notes.append(f"on {row['netvm']}")
    if slot in b["model"]:
        notes.append(f"{slot}'s model qube now")
    others = sorted(b["model"] - {slot})
    if others:
        notes.append(f"serves {', '.join(others)}")
    return f"{row['name']} ({'; '.join(notes)})"


def model_qube_options(fleet_rows, hub=None, slot=None, current=None, keep=False) -> list:
    """(id, text) for a form's model-qube field: every qube the command
    would take (`model_qube_choices`), said where it is and whom it serves.
    With `keep` (a lead change), first, the project's model qube now,
    `current`, kept as it is (id ""), and it is not listed again; with a
    `current`, last, taking it away (id "none")."""
    rows = {r["name"]: r for r in fleet_rows or () if isinstance(r, dict)
            and isinstance(r.get("name"), str)}
    out = [("", f"keep {current}, the project's model qube now")] if keep and current else []
    out += [(n, model_qube_text(rows[n], slot)) for n in model_qube_choices(fleet_rows, hub)
            if not (keep and n == current)]
    if current:
        out.append(("none", f"none: take {current} away; the lead reaches no model"))
    return out


def chosen_model_qube(choice, current=None) -> str:
    """The self-hosted model a form sends: a qube's name, "none", or "" to
    keep `current`, the project's model qube now. Nothing chosen is refused."""
    if choice is None or (choice == "" and not current):
        raise FormError("choose the model qube, or a remote endpoint")
    return choice


def model_qube_red(qube, lead=None, slot=None, fleet_rows=()) -> str:
    """What a form says in red before OK when `qube` becomes the model qube
    of `slot` (None: a project not made yet): that `lead`, the qube that will
    lead it, loses its network, since a lead whose model is a qube has none;
    and that `qube` already serves another project, with the command's own
    warning of what that means. Empty when neither, or when no qube is
    chosen."""
    if not qube or qube == "none":
        return ""
    lines = []
    lrow = _row(fleet_rows, lead)
    net = lrow.get("netvm") if lrow else None
    if net not in (None, UNREADABLE):
        lines.append(f"{lead} loses its network ({net}): a lead whose model is a qube has none, "
                     f"and going back to a remote model takes a new lead.")
    qrow = _row(fleet_rows, qube)
    others = sorted(badges(qrow)["model"] - {slot}) if qrow and not unread_row(qrow) else []
    if others:
        lines.append(f"WARNING: {qube} also serves {', '.join(others)}: "
                     f"{fleet.SHARED_MODEL_WARNING}")
    return "\n".join(lines)


def model_qube_info(qube, fleet_rows=(), slot=None, current=None) -> str:
    """What OK does to the chosen model qube, in the order the command does
    it (`fleet._set_model_qube`), or what taking `current` away does."""
    if qube is None:
        return ""
    if qube == "none":
        return (f"{current} loses {projects.model_badge(slot) if slot else 'its badge'} and stops "
                f"serving the project; it stays as it is otherwise. The lead reaches no model.")
    if qube == "":
        return f"{current} stays the project's model qube."
    row = _row(fleet_rows, qube)
    if row is None:
        return ""
    b, steps = badges(row), []
    if projects.HUB_SLOT in b["member"]:
        steps.append("leaves p00")
    if row.get("netvm") is not None:
        steps.append(f"loses its network ({row['netvm']})")
    if not b["guarded"]:
        steps.append("is guarded (the hub can no longer operate it)")
    if not b["guarded"] or not b["model"]:
        # The command spares only a guarded qube that already serves a project.
        steps.append("is killed if it runs")
    badge = projects.model_badge(slot) if slot else "the project's model badge"
    head = f"{qube} {_and(steps)}; then it" if steps else f"{qube}"
    return (f"{head} is recorded and wears {badge}, and the lead reaches it on port "
            f"{projects.MODEL_PORT}.")


def model_qube_refusal(doc, choice, fleet_rows) -> str | None:
    """Why the command refuses `--model-qube choice` for the firewall view's
    project, where the window can see why, in its words
    (`fleet._set_model_qube`): nothing chosen, and a lead whose network cannot
    be read, which it must take to none."""
    if not choice:
        return "choose the model qube, or none"
    lead = (doc or {}).get("lead")
    lrow = _row(fleet_rows, lead)
    if choice != "none" and lrow is not None and lrow.get("netvm") == UNREADABLE:
        return f"the network of {lead} cannot be read"
    return None


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
    ("model", "Model endpoint"), ("model_qube", "Model qube"), ("accepted", "Rules you accepted"),
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
    can see why, in its words (`fleet._set_lead_firewall`): a project whose
    model is a qube, whose lead has no network; a lead whose network cannot
    be read; and a lead with no network, which reaches no model endpoint. Its
    rules can still be set or accepted."""
    lead = doc.get("lead") if isinstance(doc, dict) else None
    if lead and doc.get("model_qube"):
        project = doc.get("project")
        return (f"the model of {project} is the qube {doc['model_qube']}, and its lead has no "
                f"network: a remote model takes a new lead on a network (qmcp project lead "
                f"{project} ... --lead-netvm NET --model HOST:PORT)")
    if lead and any(isinstance(r, dict) and r.get("name") == lead
                    and r.get("netvm") == fleet.UNREADABLE for r in fleet_rows or ()):
        return f"the network of {lead} cannot be read"
    if lead_on_network(doc, fleet_rows) is False:
        return (f"{doc.get('lead')} has no network, so it reaches no model endpoint; set its "
                f"rules, or give the project a new lead on a network")
    return None


def lead_rules_refusal(doc) -> str | None:
    """Why the command refuses `--rule` and `--accept-current` for the view's
    project, in its words (`fleet._set_lead_firewall`): its model is a qube,
    and its lead has no network, so no firewall to set or accept."""
    if isinstance(doc, dict) and doc.get("model_qube"):
        return (f"the model of {doc.get('project')} is the qube {doc['model_qube']}, and its lead "
                f"has no network, so it has no firewall to set or accept")
    return None


def firewall_actions(doc, fleet_rows=None) -> set:
    """Set model qube for any project read, one with no lead yet included, as
    the command takes it; Set rules while the project has a lead and its model
    is no qube (`lead_rules_refusal`), and Set model too unless
    `model_refusal` finds, in `fleet_rows`, why the command refuses it; Accept
    current rules on the same terms as Set rules, while its live rules were
    read, hold some, and are not the ones accepted. The command decides the
    rest."""
    if not isinstance(doc, dict):
        return set()
    if not doc.get("lead") or lead_rules_refusal(doc):
        return {"set_model_qube"}
    out = {"set_model_qube", "set_rules"}
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
    why = lead_rules_refusal(pane.doc)
    if why:
        out.append(("Lead rules", esc(f"Set lead rules and Accept current rules are off: {why}")))
    doc = pane.doc if isinstance(pane.doc, dict) else {}
    if firewall.dns_left_open(doc.get("model"), doc.get("accepted")):
        out.append(("Lead DNS", esc(f"open, as written before 0.9.22, though an endpoint given as "
                                    f"an address needs none; qmcp check warns. Set lead model with "
                                    f"the same endpoint, {doc.get('model')}, writes the rules "
                                    f"without it")))
    return out + firewall_details(pane.doc)


def firewall_changed(opened, ident, pane, fleet_rows=None) -> str | None:
    """Why a form opened on the read `opened` may no longer run `ident`, or
    None. Asked at OK: the pane must still allow it, with the fleet as it is
    now, and hold the same project, lead, model and rules, read again since
    if a refresh ran. A model for a lead that has lost its network since is
    refused in the command's words."""
    doc = pane.doc
    why = (model_refusal(opened, fleet_rows) if ident == "set_model" else
           lead_rules_refusal(doc) if ident in ("set_rules", "accept_rules") else None)
    if why:
        return why
    if (not isinstance(opened, dict)
            or ident not in pane.actions(opened.get("project"), fleet_rows)
            or not isinstance(doc, dict)
            or any(doc.get(k) != opened.get(k)
                   for k in ("project", "slot", "lead", "model", "model_qube", "accepted", "live"))):
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
            f"firewall becomes that endpoint, DNS when it is a host name, and nothing else, and "
            f"the project's record keeps the endpoint as its model (now "
            f"{doc.get('model') or 'none'}). This changes what the lead can reach on the "
            f"network: compare the rules below.")


def model_qube_intro(doc) -> str:
    """What Set model qube does, for its form."""
    now = (f"the model qube {doc['model_qube']}" if doc.get("model_qube") else
           f"the endpoint {doc['model']}" if doc.get("model") else "none")
    lead = (f"its lead, {doc['lead']}," if doc.get("lead") else
            "its lead, when it has one,")
    return (f"Makes a qube the self-hosted model of {doc.get('project')}: {lead} reaches it over "
            f"qubes.ConnectTCP on port {projects.MODEL_PORT}, and has no network, since a lead "
            f"whose model is a qube has none. In this order: the badge "
            f"{projects.model_badge(str(doc.get('slot')))} comes off any other qube, the lead "
            f"loses its network, the qube leaves p00, loses its network, is guarded and is "
            f"killed if it runs (unless it already serves a project as a guarded model qube), "
            f"the record names it (a model endpoint on record goes, with the rules you accepted "
            f"for the lead), and only then does it wear the badge. none takes the project's "
            f"model qube away. The project's model now: {now}.")


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


# ======================================================================= anonymous projects

#: What a qube's anonymity badges mean, as the rulebook routes on them, in the
#: order the Role cell names them: (badge, the mark, the details pane's line).
ANON_MARKS = (
    (projects.ANON, "anonymous",
     "a lead or member of an anonymous project: the anonymity gate watches it"),
    (projects.HUBBLIND, "hidden from the hub",
     "wears qmcp-hubblind: the rulebook refuses the hub every call into it, and the "
     "services leave it out of everything the hub reads"),
    (projects.BLOCKED, "BLOCKED by the gate",
     "wears qmcp-blocked: the anonymity gate stopped its project, and the rulebook refuses "
     "every call into it, so qrexec cannot wake it. You may still start it from dom0 to look "
     "at it. Unblock... takes the badge off once the gate finds the project sound"),
    (projects.STOPPED, "stopped by the gate",
     "wears qmcp-stopped: the gate stopped it for a violation (killed it, or found it halted). "
     "Running again, it was started by hand, from dom0, and the gate leaves it running; "
     "Unblock... takes this badge off too"),
)
#: A project's `blocked`, in words.
BLOCKED_TEXT = {
    True: "yes: the anonymity gate stopped it: it badges its qubes qmcp-blocked and turns their "
          "autostart off, and after a violation kills any running (after a read that failed "
          "twice, it kills none). Unblock... takes the badges off once the gate finds it sound",
    False: "no",
    None: "not known: its members could not be read",
}
#: A verdict's status, in words.
GATE_STATUS = {
    "green": "green: sound",
    "red": "RED: not anonymous",
    "unreadable": "could not be judged",
    None: "not judged",
}
#: Why a project has no verdict from a gate read that answered: it was made
#: after that run (a run that cannot have the gate answers nothing and exits 3,
#: which is a failed read, never an empty one).
NOT_JUDGED = ("not judged by this refresh's run: it was made after the gate ran. Refresh")
#: The line above the Anonymity tab's list.
GATE_NOTE = ("Each refresh runs qmcp gate --json, which judges every anonymous project now and "
             "stops one that is not sound: its lead and members are badged qmcp-blocked, killed, "
             "and their autostart turned off. Its timer runs it every 15 seconds as well, and "
             "every qmcp command that changes qubes, projects or gateways runs it at its end.")


def qube_marks(row) -> list:
    """The marks a qube's anonymity badges give it in the tree, from its
    `list` row: the badges the rulebook routes on, whatever the records say."""
    tags = set(row.get("badges") or ())
    return [mark for badge, mark, _ in ANON_MARKS if badge in tags]


def anonymity_notes(row) -> list:
    """(heading, text) for the details pane: what each anonymity badge a qube
    wears means."""
    tags = set(row.get("badges") or ())
    return [(mark[0].upper() + mark[1:], esc(text)) for badge, mark, text in ANON_MARKS
            if badge in tags]


def _slots_of(row) -> set:
    b = badges(row)
    return b["member"] | b["lead"]


def anonymous_qube(row, records) -> bool:
    """Whether the command refuses to move this qube as a qube of an
    anonymous project (`fleet.move`): it wears an anonymity badge, or is a
    member of a project recorded anonymous."""
    tags = set(row.get("badges") or ())
    if tags & {projects.ANON, projects.HUBBLIND, projects.BLOCKED}:
        return True
    return any((records or {}).get(s, {}).get("anonymous") for s in badges(row)["member"])


def blocked_project(node, records):
    """The record of the anonymous project the gate stopped that the selection
    is, or a lead or member of; None for anything else. A qube is placed by
    its badges, as the rulebook routes, and must be in the tree as one."""
    if node is None:
        return None
    if node.kind == "project":
        rec = node.data
    elif node.kind == "qube" and not node.data.get("attention") and node.data.get("state"):
        slots = _slots_of(node.data)
        rec = (records or {}).get(next(iter(slots))) if len(slots) == 1 else None
    else:
        return None
    if isinstance(rec, dict) and rec.get("anonymous") and rec.get("blocked") is True \
            and rec.get("label"):
        return rec
    return None


def verdict_for(slot, gate):
    """The gate's verdict on `slot` from the verdicts on show, or None."""
    return next((v for v in gate or () if isinstance(v, dict) and v.get("slot") == slot), None)


def _conditions(verdict) -> list:
    """The conditions a verdict fails, each once, in the gate's order."""
    order = anon.CONDITIONS + ("read",)
    found = {p.get("condition") for p in verdict.get("problems") or () if isinstance(p, dict)}
    return [c for c in order if c in found] + sorted(str(c) for c in found - set(order))


def _condition_words(verdict) -> str:
    return ", ".join(anon.CONDITION_WORDS.get(c, c) for c in _conditions(verdict))


def gate_status_text(verdict, read=True) -> str:
    """A project's gate status, naming the conditions it fails. `read`:
    whether the gate was read at all; a project it did not judge says so."""
    if not read:
        return "not known: the anonymity gate has not been read"
    if verdict is None or verdict.get("status") not in ("green", "red", "unreadable"):
        return NOT_JUDGED
    status = verdict["status"]
    if status == "green":
        return GATE_STATUS["green"]
    details = "; ".join(f"{p.get('condition')}: {p.get('detail')}"
                        for p in verdict.get("problems") or () if isinstance(p, dict))
    if status == "red":
        return f"{GATE_STATUS['red']}: {_condition_words(verdict)} ({details})"
    return (f"{GATE_STATUS['unreadable']}: {details}. The gate stops it without killing its "
            f"qubes until it can be judged")


def project_role(rec, verdict=None) -> str:
    """A project's Role cell: an anonymous one says whether the hub sees it,
    whether the gate stopped it, and what the gate found when it was not
    sound."""
    if not rec.get("anonymous"):
        return "project"
    out = ["anonymous project", "hidden from the hub" if rec.get("hidden") else "visible to the hub"]
    if rec.get("blocked") is True:
        out.append("BLOCKED by the gate")
    elif rec.get("blocked") is None:
        out.append("blocked: not known")
    status = verdict.get("status") if isinstance(verdict, dict) else None
    if status == "red":
        out.append(f"gate RED: {_condition_words(verdict)}")
    elif status == "unreadable":
        out.append("gate could not judge it")
    return ", ".join(out)


def qube_network(fleet_rows, name):
    """A qube's network from its `list` row; None when it has none, has no
    row, or its network cannot be read: the command's own reading for a
    warning (`fleet._qube_network`)."""
    row = _row(fleet_rows, name)
    net = row.get("netvm") if row else None
    return None if net == UNREADABLE else net


def routers_shared(mine, slot, project_rows, fleet_rows, hub) -> list:
    """The networks among `mine` that another project (its worker networks,
    its lead's) or the hub is on: `fleet.shared_routers` from the window's
    reads. `slot`: the project `mine` belongs to, None for a new one."""
    theirs = {qube_network(fleet_rows, hub)}
    for q in project_rows or ():
        if isinstance(q, dict) and q.get("slot") != slot and q.get("label"):
            theirs |= {n for n in q.get("networks") or () if n}
            theirs.add(qube_network(fleet_rows, q.get("lead")))
    return sorted(n for n in set(mine) & theirs if n)


def shared_routers(record, project_rows, fleet_rows, hub) -> list:
    """The routers a hidden project shares with another project or the hub:
    its worker networks and its lead's, against theirs. None for a project
    that is not hidden: the warning is about what ties a hidden one to them."""
    if not (isinstance(record, dict) and record.get("hidden")):
        return []
    mine = {n for n in record.get("networks") or () if n}
    mine.add(qube_network(fleet_rows, record.get("lead")))
    return routers_shared(mine, record.get("slot"), project_rows, fleet_rows, hub)


def shared_router_warning(shared) -> str:
    """The command's warning about shared routers, in its words."""
    if not shared:
        return ""
    return (f"WARNING: it shares {', '.join(shared)} with another project or the hub: "
            f"{fleet.SHARED_ROUTER_WARNING}")


def hidden_warning() -> str:
    """The command's warning for a hidden project, in its words."""
    return f"WARNING: {fleet.HIDDEN_WARNING}"


def _usable_row(net, gw_rows):
    usable(net, gw_rows)
    return next(r for r in gateway_list(gw_rows) if r["name"] == net)


def anonymous_networks(networks, gw_rows) -> None:
    """Networks an anonymous project may use, refused as the command refuses
    them (`fleet._anonymous_network`), in its words: an enrolled gateway that
    still qualifies, marked anonymising, still on the network recorded when it
    was marked; or none."""
    for net in networks:
        if net in (None, "", "none"):
            continue
        row = _usable_row(net, gw_rows)
        if row.get("anonymising") is not True:
            raise FormError(f"'{net}' is not an anonymising gateway: an anonymous project's "
                            f"networks are anonymising gateways, or none")
        recorded, now = row.get("recorded_upstream"), row.get("upstream")
        if recorded is None:
            raise FormError(f"'{net}' has no recorded network: mark it again (qmcp gateway set "
                            f"{net} --anonymising yes)")
        if now == UNREADABLE:
            raise FormError(f"the network of '{net}' cannot be read; try again")
        if now != recorded:
            raise FormError(f"'{net}' is on {now or 'no network'}, not on {recorded} as "
                            f"recorded: put it back, or mark it again (qmcp gateway set {net} "
                            f"--anonymising yes)")


def not_managed(name, fleet_rows, what) -> None:
    """A template an anonymous project's qubes come from: outside AI space or
    guarded, refused as the command refuses it (`fleet._not_managed`), in its
    words. A row that cannot be read is refused too; the command reads it again."""
    row = _row(fleet_rows, name)
    if row is None:
        return                          # the command says there is no such qube
    if unread_row(row):
        raise FormError(f"{what} '{name}' cannot be read now; refresh")
    if row.get("state") == "managed":
        raise FormError(f"{what} '{name}' is managed, so the hub can change it: guard it first "
                        f"(qmcp guard {name}), or use another")


def anonymous_lead(source, origin, lead_netvm, fleet_rows, gw_rows) -> None:
    """An anonymous project's new lead, refused as the command refuses it
    (`fleet._anonymous_lead`): made fresh, from a template the hub cannot
    change, on an anonymising gateway or none."""
    if source != "template":
        raise FormError(FRESH_LEAD)
    not_managed(origin, fleet_rows, "the lead's template")
    anonymous_networks([lead_netvm], gw_rows)


def anonymous_model_qube(qube, slot, anonymous, fleet_rows, project_rows) -> None:
    """A model qube refused as the command refuses it (`fleet._plan_model_qube`),
    in its words, where its `list` row shows why: an anonymous project's model
    qube serves it alone, and no project shares one that serves an anonymous
    project. `slot`: the project's, None for a new one."""
    if not qube or qube == "none":
        return
    row = _row(fleet_rows, qube)
    if row is None or unread_row(row):
        return
    others = badges(row)["model"] - {slot}
    anonymous_slots = {p.get("slot") for p in project_rows or ()
                       if isinstance(p, dict) and p.get("anonymous")}
    if others and anonymous:
        raise FormError(f"'{qube}' already serves {', '.join(sorted(others))}: an anonymous "
                        f"project's model qube serves it alone")
    if others & anonymous_slots:
        raise FormError(f"'{qube}' serves the anonymous project(s) "
                        f"{', '.join(sorted(others & anonymous_slots))}, which it serves alone")


def anonymous_users(name, project_rows, fleet_rows) -> list:
    """The anonymous projects that list gateway `name` or whose lead is on it
    (`fleet._anonymous_users`): a lead whose network cannot be read counts."""
    out = []
    for p in project_rows or ():
        if not (isinstance(p, dict) and p.get("anonymous")):
            continue
        row = _row(fleet_rows, p.get("lead"))
        on_it = row is not None and row.get("netvm") in (name, UNREADABLE)
        if name in (p.get("networks") or ()) or on_it:
            out.append(str(p.get("label")))
    return sorted(out)


def hub_record(verdict) -> dict | None:
    """What the Anonymity tab's Unblock works on for the hub's verdict
    (anonymous mode): p00, standing for the hub and every qube under its
    check, stopped while any of them wears qmcp-blocked. None for any other
    verdict."""
    if not isinstance(verdict, dict) or not verdict.get("hub"):
        return None
    return {"slot": "p00", "label": "p00", "anonymous": True, "hub": True,
            "blocked": verdict.get("blocked") is True}


def unblock_refusal(record, verdict) -> str | None:
    """Why the command refuses `project unblock` where the window can see it,
    in its words (`anon.unblock`): not an anonymous project, and a gate
    verdict on show that is not green. The command judges the project again
    when it runs; the verdict on show is this refresh's."""
    if record.get("hub"):
        if verdict is None or verdict.get("status") not in ("green", "red", "unreadable"):
            return "the gate did not judge the hub on this refresh: Refresh, then unblock it"
        details = "; ".join(str(p.get("detail")) for p in verdict.get("problems") or ()
                            if isinstance(p, dict))
        if verdict["status"] == "unreadable":
            return f"the gate could not judge the hub ({details}); it stays blocked"
        if verdict["status"] != "green":
            return f"the gate still finds the hub unsound, so it stays blocked: {details}"
        return None
    label = record.get("label")
    if not record.get("anonymous"):
        return f"'{label}' is not an anonymous project"
    if verdict is None or verdict.get("status") not in ("green", "red", "unreadable"):
        return f"the gate did not judge {label} on this refresh: Refresh, then unblock it"
    details = "; ".join(str(p.get("detail")) for p in verdict.get("problems") or ()
                        if isinstance(p, dict))
    if verdict["status"] == "unreadable":
        return f"the gate could not judge {label} ({details}); it stays blocked"
    if verdict["status"] != "green":
        return f"the gate still finds {label} unsound, so it stays blocked: {details}"
    return None


def unblock_intro(record) -> str:
    if record.get("hub"):
        return ("Takes qmcp-blocked off the hub and every qube under its check (p00, and the "
                "templates, disposable templates and disposables it made) once a fresh run of "
                "the anonymity gate finds them sound: the command judges them again, and refuses "
                "while they are not. Their autostart stays off. The gate stopped them because a "
                "condition failed; make sure whatever broke it is fixed, not only that it reads "
                "sound now.")
    note = f" ({record['note']})" if record.get("note") else ""
    return (f"Takes qmcp-blocked off the lead and members of {record.get('label')}{note}, "
            f"{record.get('slot')}, once a fresh run of the anonymity gate finds the project "
            f"sound: the command judges it again, and refuses while it is not. Their autostart "
            f"stays off: start the qubes you need by hand. The gate stopped the project because "
            f"one of its conditions failed; make sure whatever broke it is fixed, not only that "
            f"it reads sound now.")


# ======================================================================= the anonymity gate panel

#: Every field of a `gate --json` verdict, as the panel names it. Its
#: `blocked` is the project as it was once that run had acted: a project the
#: run just stopped reads yes, with what it did beside it.
GATE_FIELDS = (
    ("label", "Project"), ("slot", "Slot"), ("hidden", "Hidden from the hub"),
    ("status", "Gate status"), ("blocked", "Stopped, after this run"),
    ("problems", "What fails"), ("acted", "What this run did"),
)
#: The fields only the hub's verdict has (anonymous mode).
GATE_HUB_FIELDS = (("hub", "The hub's check"), ("offenders", "Qubes in violation"))
#: Every field of one of its problems.
GATE_PROBLEM_FIELDS = ("condition", "detail")
#: The list's columns: (key, heading); `note`, `kind` and `fails` are composed.
GATE_COLUMNS = (("label", "Project"), ("note", "Note (dom0 only)"), ("slot", "Slot"),
                ("kind", "Kind"), ("status", "Gate"), ("blocked", "Stopped"),
                ("fails", "Failing conditions"))


def parse_gate(result: Result) -> list:
    """The verdicts of `gate --json`, or ReadError. The command exits 1 when a
    project is not sound and 3 when one could not be judged, with its verdicts
    on stdout; without them (the records could not be read) the read failed,
    and is never taken for "no anonymous project"."""
    if result.rc not in (0, 1, 3):
        raise _failed(result)
    doc = parse_json(result)
    if not isinstance(doc, list) or not all(
            isinstance(v, dict) and isinstance(v.get("slot"), str)
            and v.get("status") in ("green", "red", "unreadable")
            and isinstance(v.get("problems"), list) and isinstance(v.get("acted"), list)
            for v in doc):
        raise ReadError(f"{shlex.join(result.argv)}: unexpected answer")
    return doc


def gate_rows(verdicts, project_rows) -> list:
    """One row per anonymous project for the panel, by slot: each verdict,
    with the record's note and whether it is stopped now (`blocked_now`, the
    record's: read after the gate, so it holds what the gate just did); and an
    anonymous project in the records that the gate did not judge, with no
    status. `verdicts` None: never read."""
    if verdicts is None:
        return []
    records = {p.get("slot"): p for p in project_rows or () if isinstance(p, dict)}
    out = {}
    for v in verdicts:
        if isinstance(v, dict) and isinstance(v.get("slot"), str):
            rec = None if v.get("hub") else records.get(v["slot"])
            out[v["slot"]] = dict(v, note=(rec or {}).get("note"),
                                  blocked_now=rec.get("blocked") if rec else v.get("blocked"))
    for slot, p in records.items():
        if p.get("anonymous") and slot not in out:
            out[slot] = {"slot": slot, "label": p.get("label"), "hidden": p.get("hidden"),
                         "status": None, "blocked": None, "problems": [], "acted": [],
                         "note": p.get("note"), "blocked_now": p.get("blocked")}
    return [out[s] for s in sorted(out)]


def _yes_no(value) -> str:
    return BLOCKED_TEXT[value].split(":")[0] if value in BLOCKED_TEXT else str(value)


def gate_cells(row) -> list:
    values = {"kind": "the hub and the rest of AI space (anonymous mode)" if row.get("hub")
              else "hidden" if row.get("hidden") else "visible to the hub",
              "status": GATE_STATUS.get(row.get("status"), row.get("status")),
              "fails": _condition_words(row) or "-",
              "blocked": _yes_no(row.get("blocked_now"))}
    return [esc(values[key] if key in values else row.get(key)) for key, _ in GATE_COLUMNS]


def gate_details(row) -> list:
    """(heading, text) for the pane beside the list: every field of the
    verdict, a problem and an action a line each, and the record's note."""
    if not isinstance(row, dict):
        return []
    out = []
    for key, heading in GATE_FIELDS + (GATE_HUB_FIELDS if row.get("hub") else ()):
        value = row.get(key)
        if key == "label" and row.get("note"):
            out.append((heading, esc(value)))
            out.append(("Note (dom0 only)", esc(row["note"])))
            continue
        if key == "hub":
            text = esc("yes: in anonymous mode the gate judges the hub qube, its qubes in p00 "
                       "and every other qube in AI space that is not an anonymous project's "
                       "lead, member or model qube, guarded routers aside")
        elif key == "offenders":
            text = (esc_items(str(n) for n in value) if value else esc("none")) \
                if isinstance(value, list) else esc(value)
        elif key == "hidden" and row.get("hub"):
            text = esc("- (the hub's own check)")
        elif key == "hidden":
            text = esc("yes: the hub can neither see nor reach its qubes" if value else
                       "no: the hub may see and operate it; it is hidden from the network, not "
                       "from the hub")
        elif key == "status":
            text = esc(gate_status_text(row) if value is not None else NOT_JUDGED)
        elif key == "blocked":
            out.append(("Stopped now", esc(BLOCKED_TEXT.get(row.get("blocked_now"),
                                                           row.get("blocked_now")))))
            text = esc("not judged" if row.get("status") is None else _yes_no(value))
        elif key == "problems":
            text = (esc_items(f"{anon.CONDITION_WORDS.get(p.get('condition'), p.get('condition'))}"
                              f": {p.get('detail')}" for p in value if isinstance(p, dict))
                    if value else esc("nothing"))
        elif key == "acted":
            text = esc_items(str(a) for a in value) if value else esc("nothing")
        else:
            text = esc(value)
        out.append((heading, text))
    return out


def gate_note(rows, read, records_read=True, error=None, read_at=None) -> str:
    """The line above the Anonymity tab's list. `read`: whether the gate has
    answered once; `error`: why this refresh's read failed, when it did, and
    `read_at` when the verdicts on show were read."""
    if not read:
        return ("The anonymity gate has not been read." if error is None else
                f"The anonymity gate did not answer: {error}.")
    head = GATE_NOTE
    if error is not None:
        head = (f"The anonymity gate did not answer on this refresh: {error}. Showing its "
                f"verdicts from {read_at or 'the last refresh that read everything'}. " + head)
    elif read_at:
        head = f"Judged at {read_at}. " + head
    if not rows:
        if not records_read:
            return head + " It judged no project, and the records have not been read."
        return head + (" No anonymous project: the gate has nothing to judge. New project... "
                       "makes one with Anonymous ticked.")
    if any(r.get("status") is None for r in rows):
        head += f" A project marked not judged: {NOT_JUDGED}."
    return head


def gate_tab(rows, read) -> str:
    """The tab's label: how many anonymous projects need you (not sound, not
    judged, or stopped), or `?` when the gate has not been read."""
    if not read:
        return "Anonymity (?)"
    return (f"Anonymity ({sum(1 for r in rows if r.get('status') != 'green' or r.get('blocked_now'))})")


# ======================================================================= choices for the forms

def lead_templates(fleet_rows) -> list:
    """Any TemplateVM, in AI space or not: one outside it is the stronger
    choice for a lead, since the hub cannot edit it."""
    return sorted(r["name"] for r in fleet_rows if r.get("klass") == "TemplateVM"
                  and not unread_row(r))


def hubs_appvms(fleet_rows, hub=None) -> list:
    """Managed AppVMs of the hub's (p00 or no slot): a lead's clone source or a
    qube to promote. Never a model qube, even one managed for its maintenance:
    the command refuses it (`fleet._hubs_own_appvm`)."""
    out = []
    for r in fleet_rows:
        if (r.get("state") == "managed" and r.get("klass") == "AppVM" and not r.get("dvmt")
                and not r.get("gateway") and not r.get("lead") and not r.get("model")
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
    """(command target, shown text): p00, each project, or no slot. An
    anonymous project is marked: a move into one needs the second tick."""
    out = [("p00", "p00, the hub's own qubes")]
    for slot in projects.PROJECT_SLOTS:
        rec = records.get(slot)
        if rec is not None and rec.get("label"):
            kind = "" if not rec.get("anonymous") else \
                (", anonymous, hidden from the hub" if rec.get("hidden") else ", anonymous")
            out.append((rec["label"], f"{slot} {rec['label']}{kind}"))
    out.append(("none", "no slot (hub-only, copies by dialog)"))
    return out


def stopped_qube(row) -> bool:
    """Wears qmcp-blocked or qmcp-stopped: the command moves it only once the
    gate's stop is cleared."""
    tags = row.get("badges") if isinstance(row, dict) else None
    return isinstance(tags, list) and bool({projects.BLOCKED, projects.STOPPED} & set(tags))


def move_warnings(records: dict, current, target_slot) -> list:
    """What the command says before a move into, out of or between anonymous
    projects (`fleet.move_warnings`), from the records on show; empty for a
    move inside clear space."""
    def anonymous(s):
        rec = records.get(s) if s is not None else None
        return isinstance(rec, dict) and bool(rec.get("anonymous")) and s != projects.HUB_SLOT

    def hidden(s):
        return anonymous(s) and bool(records[s].get("hidden"))
    current = [s for s in ([current] if isinstance(current, str) else current or ()) if s]
    if not any(anonymous(s) for s in current) and not anonymous(target_slot):
        return []
    out = [fleet.MOVE_PAST_WARNING]
    if any(hidden(s) for s in current) and not hidden(target_slot):
        out.append(fleet.MOVE_HIDDEN_WARNING)
    return out
