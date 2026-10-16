"""qmcp.proposals — the hub asks, the operator accepts.

A proposal is the options of one `qmcp` command, never a plan or a list of
commands: create a project, edit one, add a dump sink, change or remove a
lead, change a lead's firewall, delete a project, open a guarded qube for a
while, manage a qube (adopt it into AI space, or un-guard it), revoke one, and
install exact packages into a template in AI space (0.9.28). Only the hub submits them (`qmcp.SubmitProposal`) and
polls them (`qmcp.ProposalStatus`); the operator accepts or rejects them in the
window, which runs `qmcp proposal accept N --sha256 H` or `qmcp proposal reject
N`, or with those commands in a dom0 terminal. Nothing changes until the
operator accepts: the hub cannot create a project, remove a lead or give a
lead a network by itself.

- **Submit checks the shape only.** It looks no qube name up, so submitting is
  no oracle over names outside AI space: the hub may name a template it cannot
  see. The fleet is checked when the operator accepts, by the command's own
  checks, against the fleet as it is then; `accepted` or `failed` then tells
  the hub whether the names it used exist.
- **dom0 stores its own copy**: the normal form `normalise()` returns, written
  once as canonical JSON. Its sha256 is the proposal's fingerprint. The window
  shows it and passes it to `accept`, which refuses a stored file that no
  longer hashes to it: what the operator read is what runs.
- **An edit says what it adds, removes or sets**, and is applied to the record
  as it is when the operator accepts, changing only the entries it names: a
  later change of the operator's to anything else stands.
- **Accept runs the command's own code** with operator authority. That code
  checks everything it can before it changes anything, changes in the order
  that fails toward less authority, undoes what it can and reports any partial
  step. A removed qube cannot be put back: a lead change whose new lead fails
  after the old one was removed leaves the project without a lead, which is
  safe, and the report says so.
- **When the command refuses or fails, the accept closes the proposal** as
  `failed`, and the hub may submit again. A refusal before the command runs
  (another fingerprint, the second tick not given, unreadable records)
  changes nothing and leaves it pending.
- **The second tick** (`second_tick()`) is computed here, against the fleet as
  it is: removing a qube (deleting a project, removing a lead, or replacing one
  without keeping it), a network that neither the hub nor any non-gateway qube
  in AI space uses and no project lists, a promoted lead, a quota that would
  make the projects' quotas add up to more than the pool cap, a new project's
  model endpoint that no project uses, a lead change that gives the project a
  different model endpoint, every change to a lead's firewall, which the
  window shows as the old and new rules, and anything that makes a qube a
  model qube or takes one away (it touches a guarded qube; a model qube that
  would serve a second project is named, with what sharing one means), and
  every `qube-open`, `qube-manage`, `qube-revoke` and `template-install`,
  always, with what each would do to that qube as the fleet is now if the
  command takes it (`show`'s plan names the refusals it can see). The window shows
  the reasons, and `accept` refuses without `--yes TICK`, the digest of the
  reasons shown, while there are any.
- **The hub learns a state word only**: pending, accepted, rejected, expired or
  failed, plus its own stored proposal. Never the command's report, which
  holds dom0's exception classes and the operator's view of the fleet.
- **An anonymous project** (0.9.23) may be proposed: `anonymous: true`, and
  `hub_sees: true` for one the hub may see. It carries no label and no lead
  name, since dom0 picks the label at random and the hub is never told what
  was created; its lead comes from a template; it always takes the second
  tick. After that only the operator changes a hidden one: accepting a
  proposal that names it fails as for a project that does not exist.
- **A qube of a hidden project** named by `qube-manage`, `qube-revoke` or
  `template-install` fails at accept exactly as a name that does not exist
  does, and the second tick says nothing about it.
- **At most 10 pending, each for 7 days.** Expiry is read, not run: a pending
  proposal older than that is expired whenever it is looked at. No timer.
- **Announced** by a desktop notification whose text is fixed (the number,
  never the hub's words, because notification servers render markup in the
  body), one per submit, best-effort.

The store is `/var/lib/qmcp/proposals/`, root:qubes 2770, declared in tmpfiles
(which the installer installs and applies): the services, a non-root dom0 user
in `qubes`, write proposals there (0640), and the operator's accept and reject,
as root, write the decisions beside them. `/run/qmcp/proposals.lock` serialises
submits, rejects and an accept's check and mark. An accept takes the project
commands' locks first, then the store's, and lets the store's go once the
proposal is marked: the mark keeps every other accept and reject of that
proposal out while the command runs and its decision is written.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
import re
import shlex
import time

from qmcp import audit, budget, core, firewall, inqube, projects

PROPOSALS_DIR = "/var/lib/qmcp/proposals"
LOCK_PATH = "/run/qmcp/proposals.lock"
SCHEMA = 1

#: Pending proposals at once, and how long one waits for the operator.
MAX_PENDING = 10
EXPIRY_S = 7 * 24 * 3600
#: The hub's title: plain printable ASCII, so no bidi override, zero-width
#: character or line break is ever stored, whatever the window escapes later.
TITLE_MAX = 100
#: How long a submit waits for the store, and an accept or reject. Each holds
#: it for the moment it takes to check and mark a proposal, never while a
#: command runs.
SUBMIT_WAIT_S = 10.0
DECIDE_WAIT_S = 60.0
#: Bigger than any proposal the schema allows; a stored file past it is unreadable.
MAX_FILE_BYTES = 64 * 1024
#: Lines of a command's report kept with a decision, and characters per line.
REPORT_LINES = 200
REPORT_WIDTH = 300
NOTIFY_TIMEOUT_S = 5.0

TYPES = ("project-create", "project-edit", "project-dump", "project-lead", "project-firewall",
         "project-delete", "qube-open", "qube-manage", "qube-revoke", "template-install")
#: The types that name one qube rather than a project: the field it is in.
QUBE_FIELD = {"qube-open": "qube", "qube-manage": "qube", "qube-revoke": "qube",
              "template-install": "template"}
#: The states the hub may learn.
STATES = ("pending", "accepted", "rejected", "expired", "failed")
DECIDED = ("accepted", "rejected", "failed")
#: Two more the operator sees: an accept whose command is running (the hub
#: reads it as pending), and a stored file that does not read back.
ACCEPTING = "accepting"
UNREADABLE = "unreadable"
LEAD_SOURCES = ("template", "clone", "promote")
#: The network keyword, as the `qmcp project` commands take it.
NONE = "none"

_TITLE_RE = re.compile(r"\A[\x20-\x7e]{1,%d}\Z" % TITLE_MAX)
_FILE_RE = re.compile(r"\A([0-9]{6,9})\.(json|decision|accepting)\Z")
_ISO = "%Y-%m-%dT%H:%M:%SZ"
_SHA_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def valid_fingerprint(text) -> bool:
    """Is `text` the shape of a proposal's fingerprint (or of a tick): 64
    lowercase hex digits?"""
    return isinstance(text, str) and _SHA_RE.match(text) is not None


def tick_digest(reasons) -> str | None:
    """What a second tick answers: the digest of the reasons it was given for,
    or None when one click is enough. `show` gives it and `accept --yes` takes
    it back, so a tick given for one set of reasons never accepts another: the
    fleet can change between the two (a lead replaced, a network dropped)."""
    if not reasons:
        return None
    return hashlib.sha256("\n".join(reasons).encode("utf-8")).hexdigest()


class Invalid(ValueError):
    """The request does not have the shape of a proposal. The message names the
    caller's own fields, and nothing of dom0's but the reserved name prefix."""


class Refused(Exception):
    """An operation on the store that cannot go ahead."""


class Full(Refused):
    pass


class Busy(Refused):
    pass


# ======================================================================= the shape

def _clip(value, n: int = 40) -> str:
    text = repr(value)
    return text if len(text) <= n else text[:n - 4] + "...'"


def _fields(req: dict, required: set, optional: set) -> None:
    allowed = required | optional | {"type", "title"}
    extra = sorted(str(k) for k in req if k not in allowed)
    if extra:
        raise Invalid(f"unknown field {_clip(extra[0])}" + (f" (+{len(extra) - 1} more)" if len(extra) > 1 else ""))
    for key in sorted(required):
        if key not in req:
            raise Invalid(f"{key}: missing")


def _title(value) -> str:
    if not isinstance(value, str) or not _TITLE_RE.match(value) or not value.strip():
        raise Invalid(f"title: 1-{TITLE_MAX} printable ASCII characters")
    return value


def _qube(value, what: str) -> str:
    if value == NONE or not projects.valid_qube_name(value):
        raise Invalid(f"{what}: not a qube name")
    return value


def _network(value, what: str) -> str:
    return NONE if value == NONE else _qube(value, what)


def _list_network(value, what: str) -> str:
    """A worker-network list entry: a qube name, or "none" for no network,
    which null also means in a list, as the project records and the hub's
    pool stats write it. (A single network field keeps null for "not given".)"""
    return NONE if value is None else _network(value, what)


def _list(value, what: str, low: int, high: int, item) -> list:
    if not isinstance(value, list) or not low <= len(value) <= high:
        raise Invalid(f"{what}: a list of {low} to {high} entries")
    out = [item(v, what) for v in value]
    if len(set(out)) != len(out):
        raise Invalid(f"{what}: an entry is listed twice")
    return out


def _bool(value, what: str) -> bool:
    if not isinstance(value, bool):
        raise Invalid(f"{what}: true or false")
    return value


def _quota(value) -> int:
    # bool is an int subclass: True must not become a one-byte quota.
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= projects.MAX_QUOTA:
        raise Invalid("quota: a positive whole number of bytes, at most 1 EiB")
    return value


def _key(value, hub: bool = False) -> str:
    """A project by its label, or `p00` where the hub's slot can have the thing
    (a dump sink). Never by another slot: by the time the operator accepts, a
    slot can hold a project the proposal was not about."""
    if isinstance(value, str):
        if hub and value == projects.HUB_SLOT:
            return value
        if projects.label_refusal(value) is None:
            return value
    raise Invalid("project: a project's label" + (", or p00" if hub else ""))


def _lead(value) -> dict:
    if not isinstance(value, dict) or set(value) != {"from", "qube"}:
        raise Invalid('lead: {"from": "template", "clone" or "promote", "qube": NAME}')
    if value["from"] not in LEAD_SOURCES:
        raise Invalid('lead.from: "template", "clone" or "promote"')
    return {"from": value["from"], "qube": _qube(value["qube"], "lead.qube")}


def _lead_class(out: dict, req: dict, lead: dict) -> dict:
    """A fresh lead made from a template may be a StandaloneVM. Joins the
    normal form only as "standalone" (0.9.27), so a proposal stored before
    reads back as itself; "appvm" is the default and is left out."""
    value = req.get("lead_class")
    if value is None or value == "appvm":
        return out
    if value != "standalone":
        raise Invalid('lead_class: "appvm" or "standalone"')
    if lead["from"] != "template":
        raise Invalid('lead_class: a cloned or promoted lead keeps its own class; '
                      '"standalone" goes with "from": "template"')
    out["lead_class"] = "standalone"
    return out


def _lead_netvm(value, lead: dict | None = None):
    """A lead's network. A promoted lead keeps its own, since no network moves:
    for one, only none (disconnect it) or nothing is taken."""
    out = None if value is None else _network(value, "lead_netvm")
    if lead is not None and lead["from"] == "promote" and out not in (None, NONE):
        raise Invalid("lead_netvm: a promoted lead keeps its own network; give none or leave it out")
    return out


def _lead_name(value, lead: dict, prefix, space=None):
    """A fresh lead's name. Inside the project's names when they are known here
    (a create carries its label); otherwise the command checks it at accept."""
    if value is None:
        return None
    if lead["from"] == "promote":
        raise Invalid("lead_name: a promoted lead keeps its own name")
    _qube(value, "lead_name")
    if prefix is not None:
        from qmcp import birth
        within = space or prefix
        if not value.startswith(within) or birth.name_refusal(value, within):
            raise Invalid(f"lead_name: must be a name inside {within}")
    return value


def _model(value) -> str:
    try:
        return firewall.model_text(value)
    except firewall.FirewallError as e:
        raise Invalid(f"model: {e}") from None


def _model_qube(value, allow_none: bool) -> str:
    """A self-hosted model qube's name, or (where taking it away is meant)
    "none". The shape only: submit looks no name up."""
    if allow_none and value == NONE:
        return NONE
    return _qube(value, "model_qube")


#: Per type, the fields that join the normal form only when given (see below).
OPTIONAL = {"project-create": frozenset({"model", "model_qube", "anonymous", "hub_sees",
                                         "lead_class"}),
            "project-lead": frozenset({"model", "add_old_network", "model_qube", "lead_class"}),
            "project-firewall": frozenset({"model", "rules", "model_qube"})}


def _optional(out: dict, req: dict, model_qube_none: bool = False) -> dict:
    """Fields added in 0.9.21 and 0.9.22 join the normal form only when given,
    so a proposal stored by an earlier version still reads back as itself: its
    fingerprint, which the operator may already have seen, does not change."""
    if req.get("model") is not None:
        out["model"] = _model(req["model"])
    if req.get("add_old_network") is not None and _bool(req["add_old_network"], "add_old_network"):
        out["add_old_network"] = True
    if req.get("model_qube") is not None:
        out["model_qube"] = _model_qube(req["model_qube"], model_qube_none)
        if out["model_qube"] != NONE:
            if req.get("model") is not None:
                raise Invalid("model_qube: give model (an endpoint) or model_qube, not both")
            if req.get("lead_netvm") not in (None, NONE):
                raise Invalid("model_qube: a lead whose model is a qube has no network; leave "
                              "lead_netvm out")
    return out


def _default_sink(key: str) -> str:
    """The sink's name when none is given, as the command names it."""
    return "hub-dump" if key == projects.HUB_SLOT else f"{key}-dump"


def _sink_refusal(key: str, prefix) -> str | None:
    """Why the default sink name cannot be used, or None: it would start with
    the reserved prefix (a label such as "ai" makes "ai-dump"), or it is no
    qube name (a label starting with a digit makes "42-dump"). The command
    refuses both at accept; refused here, the hub learns why instead of
    "failed"."""
    sink = _default_sink(key)
    if not core.valid_qube_name(sink):
        return f"the sink would be named {sink}, which is no qube name"
    if prefix is not None and sink.startswith(prefix):
        return f"the sink would be named {sink}, inside the reserved prefix {prefix}"
    return None


def _create(req: dict, prefix) -> dict:
    _fields(req, {"lead", "networks", "quota"},
            {"label", "lead_netvm", "lead_name", "templates", "dump", "model", "model_qube",
             "anonymous", "hub_sees", "lead_class"})
    anonymous = _bool(req.get("anonymous", False), "anonymous")
    hub_sees = _bool(req.get("hub_sees", False), "hub_sees")
    lead = _lead(req["lead"])
    dump = _bool(req.get("dump", False), "dump")
    if anonymous:
        # dom0 picks the label, and the hub is never told what was created.
        if req.get("label") is not None:
            raise Invalid("label: an anonymous project's label is picked by dom0; leave it out")
        if req.get("lead_name") is not None:
            raise Invalid("lead_name: an anonymous project's lead is named by dom0; leave it out")
        if lead["from"] != "template":
            raise Invalid('lead.from: an anonymous project\'s lead is made fresh: "template"')
        label = None
    else:
        if hub_sees:
            raise Invalid("hub_sees: goes with anonymous: true")
        if "label" not in req:
            raise Invalid("label: missing")
        label = req["label"]
        why = projects.label_refusal(label)
        if why:
            raise Invalid(f"label: {why}")
        if dump and _sink_refusal(label, prefix):
            raise Invalid(f"dump: {_sink_refusal(label, prefix)}: choose another label, or "
                          f"propose the sink with a name once the project exists")
    space = None if prefix is None or label is None else f"{prefix}{label}-"
    extra = {"anonymous": True} if anonymous else {}
    if hub_sees:
        extra["hub_sees"] = True
    return extra | {"label": label, "lead": lead,
            "lead_netvm": _lead_netvm(req.get("lead_netvm"), lead),
            "lead_name": _lead_name(req.get("lead_name"), lead, prefix, space),
            # The lead's own template joins the list at accept when it is in AI
            # space, as with the command, so one place is kept for it.
            "templates": _list(req.get("templates", []), "templates", 0,
                               projects.MAX_TEMPLATES - 1, _qube),
            "networks": _list(req["networks"], "networks", 1, projects.MAX_NETWORKS,
                              _list_network),
            "quota": _quota(req["quota"]),
            "dump": dump} | _optional({}, req) | _lead_class({}, req, lead)


def _hidden(records: dict, key) -> bool:
    """Is the project `key` names hidden from the hub? Then no proposal may
    name it."""
    target = projects.find(records, key) if isinstance(key, str) else None
    return target is not None and target.hidden


def _edit(req: dict, prefix) -> dict:
    _fields(req, {"project"}, {"add_templates", "remove_templates", "add_networks",
                               "remove_networks", "default_network", "quota"})
    out = {"project": _key(req["project"]),
           "add_templates": _list(req.get("add_templates", []), "add_templates", 0,
                                  projects.MAX_TEMPLATES, _qube),
           "remove_templates": _list(req.get("remove_templates", []), "remove_templates", 0,
                                     projects.MAX_TEMPLATES, _qube),
           "add_networks": _list(req.get("add_networks", []), "add_networks", 0,
                                 projects.MAX_NETWORKS, _list_network),
           "remove_networks": _list(req.get("remove_networks", []), "remove_networks", 0,
                                    projects.MAX_NETWORKS, _list_network),
           "default_network": None, "quota": None}
    # null means "unchanged", as leaving the field out does; the normal form
    # carries both keys, so it reads back as itself.
    if req.get("default_network") is not None:
        out["default_network"] = _network(req["default_network"], "default_network")
    if req.get("quota") is not None:
        out["quota"] = _quota(req["quota"])
    if set(out["add_templates"]) & set(out["remove_templates"]):
        raise Invalid("a template cannot be both added and removed")
    if set(out["add_networks"]) & set(out["remove_networks"]):
        raise Invalid("a network cannot be both added and removed")
    if out["default_network"] is not None and out["default_network"] in out["remove_networks"]:
        raise Invalid("default_network: it is being removed")
    if not (out["add_templates"] or out["remove_templates"] or out["add_networks"]
            or out["remove_networks"] or out["default_network"] is not None
            or out["quota"] is not None):
        raise Invalid("an edit must change something")
    return out


def _dump(req: dict, prefix) -> dict:
    _fields(req, {"project"}, {"name"})
    key = _key(req["project"], hub=True)
    name = req.get("name")
    if name is not None:
        _qube(name, "name")
        if prefix is not None and name.startswith(prefix):
            raise Invalid(f"name: a dump sink is named outside {prefix}")
    elif _sink_refusal(key, prefix):
        raise Invalid(f"name: {_sink_refusal(key, prefix)}: give the sink a name")
    return {"project": key, "name": name}


def _open_window(req: dict, prefix) -> dict:
    """A window on a guarded qube. The shape only: submit looks no name
    up, so this is no oracle over a qube the hub cannot see, and it says
    nothing about whether the qube may be opened — `qmcp open`'s own refusals
    decide that at accept, on the fleet as it is then.

    `for` is parsed here, so a duration the command would refuse is refused at
    submit rather than at accept, and is STORED AS SENT: every field the hub
    sends is stored verbatim, so the operator reads the hub's own words and
    the command is built from them. The accept parses it again, with the same
    parser.
    """
    from qmcp import fleet
    _fields(req, {"qube", "for"}, {"firewall"})
    name = _qube(req["qube"], "qube")
    if not isinstance(req["for"], str):
        raise Invalid("for: a duration as text, e.g. 90s, 30m, 2h")
    try:
        seconds = fleet.duration_seconds(req["for"])
    except fleet.RoleError as e:
        raise Invalid(f"for: {e}") from None
    if seconds <= 0 or seconds > fleet.WINDOW_MAX_S:
        raise Invalid(f"for: above zero and at most {fleet.WINDOW_MAX_S // 3600}h")
    firewall = req.get("firewall")
    return {"qube": name, "for": req["for"],
            "firewall": False if firewall is None else _bool(firewall, "firewall")}


def _manage(req: dict, prefix) -> dict:
    """`qmcp manage QUBE`: adopt a qube into AI space, or take a guarded one
    out of the guarded state. The shape only, as for every type."""
    _fields(req, {"qube"}, set())
    return {"qube": _qube(req["qube"], "qube")}


def _revoke(req: dict, prefix) -> dict:
    """`qmcp revoke QUBE [--no-shutdown]`. The normal form carries `shutdown`
    whether or not it was sent, so it reads back as itself."""
    _fields(req, {"qube"}, {"shutdown"})
    shutdown = req.get("shutdown")
    return {"qube": _qube(req["qube"], "qube"),
            "shutdown": True if shutdown is None else _bool(shutdown, "shutdown")}


def _install(req: dict, prefix) -> dict:
    """`qmcp template install TEMPLATE PKG...`: exact package names, in the
    order sent. The shape here is the command's own (`inqube.packages_refusal`);
    whether each is a package's exact name is checked inside the template."""
    _fields(req, {"template", "packages"}, set())
    name = _qube(req["template"], "template")
    why = inqube.packages_refusal(req["packages"])
    if why:
        raise Invalid(f"packages: {why}")
    return {"template": name, "packages": list(req["packages"])}


def _lead_change(req: dict, prefix) -> dict:
    _fields(req, {"project"}, {"remove", "lead", "lead_netvm", "lead_name", "keep_old", "model",
                               "add_old_network", "model_qube", "lead_class"})
    project = _key(req["project"])
    remove = req.get("remove")
    if remove is True:
        if any(req.get(k) is not None for k in ("lead", "lead_netvm", "lead_name", "keep_old",
                                                "model", "add_old_network", "model_qube",
                                                "lead_class")):
            raise Invalid("remove: takes no other lead field")
        return {"project": project, "remove": True, "lead": None, "lead_netvm": None,
                "lead_name": None, "keep_old": None}
    if remove not in (None, False):
        raise Invalid("remove: true, or leave it out and name the new lead")
    if req.get("lead") is None:
        raise Invalid("lead: say where the new lead comes from, or remove: true")
    # What happens to the old lead is said, never defaulted: a forgotten
    # field must not remove a qube.
    if req.get("keep_old") is None:
        raise Invalid("keep_old: say whether the old lead stays as a worker (true) or is "
                      "removed with everything in it (false)")
    lead = _lead(req["lead"])
    out = {"project": project, "remove": False, "lead": lead,
           "lead_netvm": _lead_netvm(req.get("lead_netvm"), lead),
           "lead_name": _lead_name(req.get("lead_name"), lead, prefix),
           "keep_old": _bool(req["keep_old"], "keep_old")}
    _optional(out, req, model_qube_none=True)
    _lead_class(out, req, lead)
    if out.get("add_old_network") and not out["keep_old"]:
        raise Invalid("add_old_network: only with keep_old true")
    return out


def _lead_firewall(req: dict, prefix) -> dict:
    """A new model endpoint (the firewall becomes that endpoint, and DNS for a
    host name), a self-hosted model qube (the lead loses its network), none
    (the project's model qube is taken away, nothing else), or exactly these
    rules. The operator sees the old and new; a new endpoint, new rules, a
    model qube, and taking one away take the second tick."""
    _fields(req, {"project"}, {"model", "rules", "model_qube"})
    out = {"project": _key(req["project"])}
    if sum(req.get(k) is not None for k in ("model", "rules", "model_qube")) != 1:
        raise Invalid("say one of model (host:port), model_qube (a qube, or none) or rules "
                      "(a list of firewall rules)")
    if req.get("model_qube") is not None:
        out["model_qube"] = _model_qube(req["model_qube"], True)
    elif req.get("model") is not None:
        out["model"] = _model(req["model"])
    else:
        rules = req["rules"]
        err = firewall.rules_refusal(rules)
        if err:
            raise Invalid(f"rules: {err}")
        out["rules"] = list(rules)
    return out


def _delete(req: dict, prefix) -> dict:
    _fields(req, {"project"}, set())
    return {"project": _key(req["project"])}


_NORMALISE = {"project-create": _create, "project-edit": _edit, "project-dump": _dump,
              "project-lead": _lead_change, "project-firewall": _lead_firewall,
              "project-delete": _delete, "qube-open": _open_window, "qube-manage": _manage,
              "qube-revoke": _revoke, "template-install": _install}


def normalise(req, prefix: str | None = None) -> dict:
    """The proposal in normal form, or Invalid. Depends on `req` and `prefix`
    alone, never on the host: no qube is looked up. `prefix` (the reserved name
    prefix) adds the checks on names that need it; reading a stored file passes
    None, since the operator may have changed the prefix since, and the command
    checks names again at accept. The normal form is a fixed point."""
    if not isinstance(req, dict):
        raise Invalid("a proposal is a JSON object")
    kind = req.get("type")
    if kind not in TYPES:
        raise Invalid(f"type: one of {', '.join(TYPES)}")
    out = {"type": kind, "title": _title(req.get("title"))}
    out.update(_NORMALISE[kind](req, prefix))
    return out


def subject(p: dict) -> str | None:
    """What a proposal is about: the new project's label, the project it names,
    or the qube it names."""
    return p.get("label") or p.get("project") or p.get("qube") or p.get("template")


# ======================================================================= the store

def canonical(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n").encode("ascii")


def _iso(t: float) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime(_ISO)


def _when(text) -> float | None:
    try:
        return datetime.datetime.strptime(text, _ISO).replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _dir(directory) -> str:
    return PROPOSALS_DIR if directory is None else directory


class Entry:
    """One proposal on disk: its stored record and bytes, and its decision."""

    __slots__ = ("id", "record", "data", "decision", "decided", "claim", "problem")

    def __init__(self, pid: int) -> None:
        self.id = pid
        self.record = None      # the stored record, when it reads back exactly
        self.data = None        # its bytes, which the fingerprint covers
        self.decision = None    # the decision, when there is one that parses
        self.decided = False    # a decision file exists, whether or not it parses
        self.claim = None       # an accept's claim: None, "running" or "stale"
        self.problem = None     # why the record or the decision does not read

    @property
    def sha256(self):
        return None if self.data is None else hashlib.sha256(self.data).hexdigest()

    @property
    def proposal(self):
        return None if self.record is None else self.record["proposal"]

    @property
    def submitted(self):
        return None if self.record is None else _when(self.record["submitted"])

    def state(self, now: float) -> str:
        # A decision file closes the proposal even when it does not parse, and
        # so does an accept that started and never finished: nothing may make a
        # proposal acceptable again once its command may have run.
        if self.decided:
            return self.decision["state"] if self.decision else "failed"
        if self.claim == "running":
            return ACCEPTING
        if self.claim == "stale":
            return "failed"
        if self.record is None:
            return UNREADABLE
        return "expired" if now >= self.submitted + EXPIRY_S else "pending"

    @property
    def needs_closing(self) -> bool:
        """Should the operator read this one and close it with `reject`? A stored
        file that does not read, a decision file that does not read, or an
        accept that never finished. `qmcp check` warns about each until then."""
        if self.decided:
            return self.decision is None
        return self.record is None or self.claim == "stale"

    def hub_state(self, now: float) -> str:
        """The state as the hub may learn it: one of STATES."""
        state = self.state(now)
        return "pending" if state == ACCEPTING else state if state in STATES else "failed"

    def expires(self):
        s = self.submitted
        return None if s is None else _iso(s + EXPIRY_S)


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("too large")
    return data


def _load_record(entry: Entry, path: str) -> None:
    try:
        data = _read_bytes(path)
        rec = json.loads(data)
        if (not isinstance(rec, dict) or set(rec) != {"v", "id", "submitted", "caller", "proposal"}
                or rec["v"] != SCHEMA or rec["id"] != entry.id or _when(rec["submitted"]) is None
                or not projects.valid_qube_name(rec["caller"])):
            raise ValueError("not a proposal record")
        if normalise(rec["proposal"]) != rec["proposal"]:
            raise ValueError("not in normal form")
        if canonical(rec) != data:
            raise ValueError("not as dom0 wrote it")
    except Exception as e:
        # Whatever a file makes the parser do, it is unreadable, never pending.
        entry.problem = f"proposal file: {e}" if isinstance(e, ValueError) else \
            f"proposal file: cannot read ({type(e).__name__})"
        return
    entry.record, entry.data = rec, data


def _load_decision(entry: Entry, path: str) -> None:
    entry.decided = True
    try:
        dec = json.loads(_read_bytes(path))
        if (not isinstance(dec, dict) or set(dec) != {"v", "id", "state", "at", "sha256", "report"}
                or dec["v"] != SCHEMA or dec["id"] != entry.id or dec["state"] not in DECIDED
                or _when(dec["at"]) is None or not isinstance(dec["report"], list)
                or not all(isinstance(line, str) for line in dec["report"])):
            raise ValueError("not a decision")
    except Exception as e:
        entry.problem = (entry.problem + "; " if entry.problem else "") + \
            f"decision file unreadable ({type(e).__name__})"
        return
    entry.decision = dec


def _probe_claim(entry: Entry, path: str, decision: str) -> None:
    """Is the accept that wrote this claim still running? It holds the claim
    locked for as long as its command runs, so a lock we can take means it
    stopped without deciding: the proposal is failed, never pending again. An
    accept writes its decision before it lets the claim go, so a claim that is
    gone or free with a decision beside it is an accept that just finished."""
    def finished() -> bool:
        if not entry.decided and os.path.exists(decision):
            _load_decision(entry, decision)
        return entry.decided
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        if finished():
            return
        entry.claim = "stale"
    except OSError:
        entry.claim = "stale"
    else:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            entry.claim = "stale"
        except OSError:
            entry.claim = "running"
        finally:
            os.close(fd)
        if entry.claim == "stale" and finished():
            entry.claim = None
            return
    if entry.claim == "stale" and not entry.decided:
        entry.problem = (entry.problem + "; " if entry.problem else "") + \
            "an accept started and did not finish: check the fleet (qmcp check) and the audit log"


def entries(directory: str | None = None) -> list:
    """Every proposal in the store, oldest first. A store that cannot be listed
    raises OSError: it is never shown as an empty one."""
    d = _dir(directory)
    found: dict = {}
    for name in os.listdir(d):
        m = _FILE_RE.match(name)
        if m:
            found.setdefault(int(m.group(1)), set()).add(m.group(2))
    out = []
    for pid in sorted(found):
        e = Entry(pid)
        if "json" in found[pid]:
            _load_record(e, os.path.join(d, f"{pid:06d}.json"))
        else:
            e.problem = "proposal file missing"
        if "decision" in found[pid]:
            _load_decision(e, os.path.join(d, f"{pid:06d}.decision"))
        if "accepting" in found[pid]:
            _probe_claim(e, os.path.join(d, f"{pid:06d}.accepting"),
                         os.path.join(d, f"{pid:06d}.decision"))
        out.append(e)
    return out


def _entry(pid: int, directory: str | None = None) -> Entry:
    e = next((x for x in entries(directory) if x.id == pid), None)
    if e is None:
        raise Refused(f"no proposal {pid}")
    return e


class _Locked:
    """The store's lock: an flock on a file the services and the operator share.
    Opened with umask 007 whoever opens it first, and declared root:qubes 0660 in
    tmpfiles, so a root operator creating it never locks the services out."""

    def __init__(self, timeout: float, path: str | None = None) -> None:
        self.timeout, self.path, self.fd = timeout, LOCK_PATH if path is None else path, None

    def __enter__(self):
        old = os.umask(0o007)
        try:
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o660)
        except OSError:
            raise Refused("the proposal store is unavailable") from None
        finally:
            os.umask(old)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    raise Busy("busy: try again in a moment") from None
                time.sleep(0.2)

    def __exit__(self, *exc):
        os.close(self.fd)
        return False


def _write_new(path: str, data: bytes, mode: int) -> None:
    """Write a file that must not exist yet, durably. Never replaces one."""
    old = os.umask(0o027)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    finally:
        os.umask(old)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def submit(proposal: dict, caller: str, now: float | None = None,
           directory: str | None = None, lock_path: str | None = None) -> tuple:
    """Store a proposal in normal form. Returns (id, sha256, expires). Raises
    Full past MAX_PENDING, Busy while an accept holds the store, OSError when
    the store cannot be written."""
    now = time.time() if now is None else now
    d = _dir(directory)
    with _Locked(SUBMIT_WAIT_S, lock_path):
        found = entries(d)
        if sum(1 for e in found if e.state(now) == "pending") >= MAX_PENDING:
            raise Full(f"too many pending proposals (at most {MAX_PENDING})")
        pid = max((e.id for e in found), default=0) + 1
        record = {"v": SCHEMA, "id": pid, "submitted": _iso(now), "caller": caller,
                  "proposal": proposal}
        data = canonical(record)
        _write_new(os.path.join(d, f"{pid:06d}.json"), data, 0o640)
    return pid, hashlib.sha256(data).hexdigest(), _iso(now + EXPIRY_S)


def _hub_row(e: Entry, now: float) -> dict:
    p = e.proposal
    return {"id": e.id, "state": e.hub_state(now), "type": p["type"],
            "title": p["title"], "submitted": e.record["submitted"], "expires": e.expires(),
            "sha256": e.sha256}


def hub_view(caller: str, pid: int | None = None, now: float | None = None,
             directory: str | None = None) -> dict:
    """What the hub may know about its proposals: state words, its own stored
    proposal, never a report or a reason."""
    now = time.time() if now is None else now
    mine = [e for e in entries(directory) if e.record is not None and e.record["caller"] == caller]
    if pid is None:
        return {"proposals": [_hub_row(e, now) for e in reversed(mine)]}
    e = next((x for x in mine if x.id == pid), None)
    if e is None:
        raise Refused("no such proposal")
    return dict(_hub_row(e, now), proposal=e.proposal)


#: Every field of a `qmcp proposal list --json` row. The window shows each one.
LIST_FIELDS = ("id", "state", "type", "title", "subject", "caller", "submitted", "expires",
               "sha256", "problem", "needs_closing")


def listing(now: float | None = None, directory: str | None = None) -> list:
    """The operator's view, newest first: every proposal, unreadable ones too."""
    now = time.time() if now is None else now
    rows = []
    for e in reversed(entries(directory)):
        p, rec = e.proposal, e.record
        rows.append({"id": e.id, "state": e.state(now),
                     "type": p and p["type"], "title": p and p["title"],
                     "subject": p and subject(p), "caller": rec and rec["caller"],
                     "submitted": rec and rec["submitted"], "expires": e.expires(),
                     "sha256": e.sha256, "problem": e.problem, "needs_closing": e.needs_closing})
    return rows


# ======================================================================= what accepting does

def command(p: dict) -> str | None:
    """The `qmcp` command a proposal is the options of, as the operator would
    type it. None for an edit: it is applied to the record as it is at
    accept, so `show` gives before and after instead of a command."""
    t = p["type"]
    argv = None
    if t == "project-create":
        argv = ["qmcp", "project", "create"] + ([p["label"]] if p["label"] else [])
        if p.get("anonymous"):
            argv.append("--anonymous")
        if p.get("hub_sees"):
            argv.append("--hub-sees")
        argv += [f"--lead-{p['lead']['from']}", p["lead"]["qube"]]
        if p.get("lead_class") is not None:
            argv += ["--lead-class", p["lead_class"]]
        if p["lead_netvm"] is not None:
            argv += ["--lead-netvm", p["lead_netvm"]]
        if p["lead_name"] is not None:
            argv += ["--lead-name", p["lead_name"]]
        for name in p["templates"]:
            argv += ["--template", name]
        for name in p["networks"]:
            argv += ["--network", name]
        q = p["quota"]
        argv += ["--quota", f"{q // 1024 ** 3}G" if q % 1024 ** 3 == 0 else str(q)]
        if p["dump"]:
            argv.append("--dump")
        if p.get("model") is not None:
            argv += ["--model", p["model"]]
        if p.get("model_qube") is not None:
            argv += ["--model-qube", p["model_qube"]]
    elif t == "project-lead":
        argv = ["qmcp", "project", "lead", p["project"]]
        if p["remove"]:
            argv.append("--remove")
        else:
            argv += [f"--lead-{p['lead']['from']}", p["lead"]["qube"]]
            if p.get("lead_class") is not None:
                argv += ["--lead-class", p["lead_class"]]
            if p["lead_netvm"] is not None:
                argv += ["--lead-netvm", p["lead_netvm"]]
            if p["lead_name"] is not None:
                argv += ["--lead-name", p["lead_name"]]
            if p["keep_old"]:
                argv.append("--keep-old")
            if p.get("add_old_network"):
                argv.append("--add-old-network")
            if p.get("model") is not None:
                argv += ["--model", p["model"]]
            if p.get("model_qube") is not None:
                argv += ["--model-qube", p["model_qube"]]
    elif t == "project-firewall":
        argv = ["qmcp", "project", "firewall", p["project"]]
        if p.get("model") is not None:
            argv += ["--model", p["model"]]
        if p.get("model_qube") is not None:
            argv += ["--model-qube", p["model_qube"]]
        for rule in p.get("rules", ()):
            argv += ["--rule", rule]
    elif t == "project-dump":
        argv = ["qmcp", "project", "dump", p["project"]]
        if p["name"] is not None:
            argv += ["--name", p["name"]]
    elif t == "project-delete":
        argv = ["qmcp", "project", "delete", p["project"], "--yes"]
    elif t == "qube-open":
        argv = ["qmcp", "open", p["qube"], "--for", p["for"]]
        if p["firewall"]:
            argv.append("--firewall")
    elif t == "qube-manage":
        argv = ["qmcp", "manage", p["qube"]]
    elif t == "qube-revoke":
        argv = ["qmcp", "revoke", p["qube"]] + ([] if p["shutdown"] else ["--no-shutdown"])
    elif t == "template-install":
        argv = ["qmcp", "template", "install", p["template"]] + list(p["packages"])
    return None if argv is None else shlex.join(argv)


def _netvm_name(vm):
    """The network's name, None for none, `core.UNREADABLE` when it cannot be
    read: no network's name, so it never makes a real one look used."""
    try:
        ref = vm.netvm
    except Exception:
        return core.UNREADABLE
    return None if ref is None else str(getattr(ref, "name", ref))


def networks_in_use(app, records: dict) -> set:
    """The networks AI space reaches today: the hub's, every AI-space qube's
    that is not itself a gateway, and every project's worker networks. A
    gateway's own upstream is not counted: a qube placed on it directly would
    skip the gateway, which is a new path. A qube whose tags or network role
    cannot be read proves no use: what it is on counts as new."""
    hub = core.read_hub()
    used = set()
    for vm in app.domains:
        if vm.name != hub:
            try:
                if not core.in_scope(vm) or core.is_gateway(vm):
                    continue
            except core.Unreadable:
                continue
        name = _netvm_name(vm)
        if name:
            used.add(name)
    for p in records.values():
        used.update(p.named_networks())
    return used


def _wears_lead_badge(app, target):
    """Does the project's recorded lead wear its slot's lead badge? None when
    that cannot be read."""
    try:
        if target.lead not in app.domains:
            return False
        return projects.lead_badge(target.slot) in set(app.domains[target.lead].tags)
    except Exception:
        return None


def _gib(n: int) -> str:
    return f"{n / 1024 ** 3:.1f} GiB"


def _model_slots_of(app, name):
    """The slots `name` serves as a model qube; empty when there is no such
    qube; None when its tags cannot be read."""
    try:
        return projects.model_slots(set(app.domains[name].tags)) if name in app.domains else set()
    except Exception:
        return None


def _model_qube_reasons(app, p: dict, target) -> list:
    """Why a proposal that names a model qube, or takes one away, needs the
    second tick: it touches a guarded qube, takes a lead's network, and may
    share one model qube between projects (a path between them)."""
    from qmcp import fleet
    q = p.get("model_qube")
    current = None if target is None else target.model_qube
    out = []
    if q == NONE:
        if current:
            out.append(f"takes the model qube {current} away from {target.label}: it loses that "
                       f"project's badge" + ("" if p.get("model") else
                                             " and the lead reaches no model"))
        return out
    if q is None:
        if p["type"] == "project-lead" and p.get("model") and current:
            out.append(f"the model qube {current} stops serving {target.label}: a remote model "
                       f"replaces it")
        return out
    who = p.get("label") or p.get("project") or "the new anonymous project"
    out.append(f"makes {q} the model qube of {who}: dom0 takes it out of p00, removes its "
               f"network, guards it and kills it if it runs (unless it is already a guarded "
               f"model qube), and the lead has no network")
    slots = _model_slots_of(app, q)
    if slots is None:
        out.append(f"{q} may already serve other projects: its badges could not be read")
        return out
    others = sorted(slots - ({target.slot} if target is not None else set()))
    if others:
        out.append(f"{q} already serves {', '.join(others)}: {fleet.SHARED_MODEL_WARNING}")
    return out


def _named_qube(app, p: dict):
    """(qube, its tags) for a proposal that names one qube: (None, None) when
    no such qube exists, (vm, None) when its tags cannot be read. Raises
    core.Unreadable when the lookup itself fails: a lookup that failed is
    never "no such qube", which would skip every check that needs the qube."""
    name = p.get(QUBE_FIELD.get(p["type"], ""))
    if not isinstance(name, str):
        return None, None
    try:
        if name not in app.domains:
            return None, None
        vm = app.domains[name]
    except Exception as e:
        raise core.Unreadable(f"cannot look up {name}") from e
    try:
        return vm, core.tags_of(vm)
    except core.Unreadable:
        return vm, None


def _built_on(app, name: str):
    """(how many qubes come from `name` through their template chain, the
    enrolled gateways and the hub among them), or None when the fleet could
    not be read: a chain it cannot read is never a short one."""
    from qmcp import fleet, gateways
    hub = core.read_hub()
    try:
        enrolled = set(gateways.load())
    except gateways.GatewaysUnreadable:
        return None
    count, named = 0, []
    try:
        for vm in list(app.domains):
            if core.name_of(vm) == name or core.klass_of(vm) == "AdminVM":
                continue
            if name in {t.name for t in fleet._template_chain(vm)}:
                count += 1
                if vm.name == hub or vm.name in enrolled:
                    named.append(vm.name)
    except (core.Unreadable, core.Gone):
        return None
    except Exception:
        return None
    return count, sorted(named)


def _approving(records: dict, name: str) -> list:
    """The projects that approve `name` as a template, a hidden one marked."""
    return sorted(f"{r.label or r.slot}" + (" (hidden)" if r.hidden else "")
                  for r in records.values() if name in r.templates)


def _qube_reasons(app, p: dict, records: dict) -> list:
    """Why `qube-manage`, `qube-revoke` and `template-install` take the second
    tick: always, with what each would do to that qube as the fleet is now, if
    the command takes it (`show`'s plan names the refusals it can see). A qube
    of a hidden project gets only the lines that come from the proposal itself,
    none read from the fleet: accepting fails as for a name that does not
    exist, which the plan says."""
    t = p["type"]
    q = p.get(QUBE_FIELD[t])
    try:
        vm, tags = _named_qube(app, p)
        unknown = False
    except core.Unreadable:
        vm, tags, unknown = None, None, True
    hidden = tags is not None and projects.HUBBLIND in tags
    out = []
    if t == "qube-manage":
        out.append(f"MANAGES {q}: the hub may then run commands in it as root, copy files out of "
                   f"it, write its firewall rules, clone it and remove it, with no time limit "
                   f"(an open window is the bounded way into a guarded qube)")
    elif t == "qube-revoke":
        out.append(f"REVOKES {q}: every qmcp badge comes off, so it leaves AI space and any slot "
                   f"it is in; after that the hub reaches it only through your dialogs, and "
                   f"what it left on its disk stays"
                   + ("; it is killed if it runs, so nothing the hub started in it runs on"
                      if p["shutdown"] else "; it keeps running"))
    else:
        out.append(f"INSTALLS {len(p['packages'])} package(s) into the template {q} as root, "
                   f"with its own package manager, from the repositories it already trusts, "
                   f"and what they depend on: {' '.join(p['packages'])}")
        out.append("every qube built on it runs them from its first start after the template "
                   "has shut down; on Arch the install also upgrades the whole template "
                   "(pacman -Su), as Qubes' own updater does")
        out.append("the install scripts of each package and each dependency run as root, and a "
                   "package can itself add a repository or download more software when it is "
                   "installed (an -installer package, or one that configures repositories): "
                   "read the names")
        out.append("an install that would remove an installed package is refused (apt-get "
                   "--no-remove; dnf never removes one without --allowerasing), and dnf ignores "
                   "obsoletes; an installed package may still be upgraded when a new one needs "
                   "it, and on Arch -Su upgrades and replaces what the repositories say")
    if unknown:
        out.append(f"{q} could not be looked up, so what this changes is not known")
        return out
    if vm is None or hidden:
        return out
    if tags is None:
        out.append(f"{q}'s badges could not be read, so what else this changes is not known")
        return out
    try:
        is_template = core.is_template(vm)
    except core.Unreadable:
        # Never "not a template": the line goes into the reasons, and so into
        # the tick, so a read that failed is said, not dropped.
        is_template = None
        out.append(f"whether {q} is a template could not be read, so whether every qube built "
                   f"on it would run what changes in it is not known")
    users = _approving(records, q) if is_template is not False else []
    serves = sorted(projects.model_slots(tags))
    is_open = bool(tags & {core.OPEN, core.OPEN_FW})
    if is_template is not False and t in ("qube-manage", "template-install"):
        built = _built_on(app, q)
        if built is None:
            out.append(f"which qubes are built on {q} could not be read")
        elif built[0]:
            out.append(f"{built[0]} qube(s) are built on {q}"
                       + (f", among them {', '.join(built[1])} (the hub or an enrolled gateway, "
                          f"which applies AI space's egress rules)" if built[1] else ""))
    if t == "qube-manage":
        if core.UMBRELLA not in tags:
            out.append(f"brings {q} into AI space: today the hub cannot see it")
        elif core.GUARDED in tags:
            out.append(f"takes {q} out of the guarded state")
        if is_template:
            out.append(f"{q} is a template: what the hub puts in it runs in every qube built on it"
                       + (f"; the projects {', '.join(users)} approve it" if users else ""))
        try:
            dvmt = core.is_dvmt(vm)
        except core.Unreadable:
            dvmt = None
            out.append(f"whether {q} is a disposable template could not be read")
        if dvmt and core.UMBRELLA not in tags:
            out.append(f"{q} is a disposable template: once it is in AI space the rulebook "
                       f"refuses every qube a disposable from it, so a qube whose default "
                       f"disposable template it is loses its disposables; one dom0 or the hub "
                       f"starts from it joins AI space managed")
        elif dvmt:
            out.append(f"{q} is a disposable template: a disposable dom0 or the hub starts from "
                       f"it takes its tags, so joins AI space managed, not guarded, and the hub "
                       f"may run commands in it")
        if is_open:
            out.append(f"{q} is open to the hub now: managing it ends the window, with no kill")
        if serves:
            out.append(f"{q} is the model qube of {', '.join(serves)}: while it is managed the hub "
                       f"may operate it, and qmcp check warns until it is guarded again")
        from qmcp import fleet
        # Judged as the gate would judge the fleet after it, never from the
        # list alone: a template in the chain of a lead or a member, off the
        # approved list, stops a project too. A judgement that cannot be made
        # is said, never dropped.
        try:
            labels = fleet._would_stop(app, overlay={q: fleet.tags_after_manage(tags)})
        except fleet.RoleError as e:
            labels = [f"(cannot tell: {e})"]
        hidden_labels = {r.label for r in records.values() if r.hidden}
        unsure = sorted(x for x in labels if "(cannot tell" in x)
        stopped = sorted(f"{x} (hidden)" if x in hidden_labels else x
                         for x in labels if x not in unsure)
        if stopped:
            out.append(f"the anonymity gate stops {', '.join(stopped)} right after: an anonymous "
                       f"project's templates and model qube must be guarded")
        if unsure:
            out.append(f"whether the anonymity gate stops a project right after could not be "
                       f"told: {'; '.join(unsure)}")
    elif t == "qube-revoke":
        slots = sorted(projects.member_slots(tags))
        if slots:
            out.append(f"it leaves {', '.join(slots)}, with what it holds")
        if is_open:
            out.append(f"{q} is open to the hub now: revoking it ends the window")
        try:
            gateway = core.is_gateway(vm)
            disposable = core.klass_of(vm) == "DispVM"
            # A named disposable is kept when it stops; one Qubes made for a
            # single use is removed (its auto_cleanup).
            cleaned = bool(vm.auto_cleanup) if disposable else False
        except Exception:
            gateway = disposable = cleaned = None
            out.append(f"whether {q} is a gateway or a disposable removed when it stops could "
                       f"not be read")
        if gateway and p["shutdown"]:
            out.append(f"{q} provides network: killing it cuts the network of every qube on it")
        if cleaned and p["shutdown"]:
            out.append(f"{q} is a disposable that is removed when it stops: killing it "
                       f"removes it")
        if serves:
            out.append(f"{', '.join(serves)} lose their model qube: the record still names it, and "
                       f"qmcp check warns until it is set again")
        if users:
            out.append(f"{q} is a template the projects {', '.join(users)} approve: their leads can "
                       f"no longer spawn from it")
    else:
        if users:
            out.append(f"the projects {', '.join(users)} approve {q}")
        if core.UMBRELLA in tags and core.GUARDED not in tags:
            out.append(f"{q} is managed: the hub could install them itself")
    return out


def second_tick(app, p: dict, records: dict) -> list:
    """Why accepting `p` needs the second tick, against the fleet as it is.
    Empty when one click is enough."""
    from qmcp import fleet
    t, reasons = p["type"], []
    target = projects.find(records, p["project"]) if "project" in p else None
    if target is not None and target.hidden:
        # The hub may not name a hidden project: accepting fails, as for a
        # project that does not exist, so nothing here is said about it.
        target = None
    if t == "project-create" and p.get("anonymous"):
        reasons.append("creates an anonymous project: dom0 picks its label and the hub is "
                       "never told what was created; after this only you change it"
                       if not p.get("hub_sees") else
                       "creates an anonymous project the hub may see and operate: hidden from "
                       "the network, not from the hub or its model provider")
        if not p.get("hub_sees"):
            reasons.append(f"WARNING: {fleet.HIDDEN_WARNING}")
    if t == "qube-open":
        # Always: anything touching a guarded or sealed qube needs the
        # second tick, and this is the only proposal that opens one. The
        # window shows these words in red: they are the disclaimer.
        reasons.append(f"OPENS the guarded qube {p['qube']} to the hub for "
                       f"{p['for']}: while it is open the hub may run "
                       f"commands in it as root and copy files in, which is what guarded "
                       f"normally refuses")
        if p["firewall"]:
            reasons.append(f"and lets the hub write {p['qube']}'s firewall rules, which are "
                           f"otherwise yours alone")
        reasons.append("the window closes by itself, at every boot, and on Seal, which kills "
                       "the qube if it is running")
        warning = fleet.hidden_open_warning(app, p["qube"])
        if warning:
            reasons.append(f"WARNING: {warning}")
    if t in ("qube-manage", "qube-revoke", "template-install"):
        # Always: adopting or revoking a qube needs the second tick, and so
        # does a template's root, which every qube built on it runs.
        reasons += _qube_reasons(app, p, records)
    if t == "project-delete":
        reasons.append(f"deletes the project {p['project']}: its lead and every worker are removed "
                       f"with everything in them; its dump sink is kept")
    if t == "project-lead" and target is not None and target.lead \
            and (p["remove"] or not p["keep_old"]):
        # Only a lead wearing its slot's badge is removed (`fleet._remove_lead`):
        # a recorded name whose qube is gone, or that no longer wears the badge,
        # is left alone, so nothing is removed and one click is enough. A badge
        # that cannot be read counts as worn: the command reads it again, and a
        # failed read here must never turn a removal into one click.
        which = "the" if p["remove"] else "the old"
        wears = _wears_lead_badge(app, target)
        if wears is None:
            reasons.append(f"may remove {which} lead {target.lead}: its badges could not be read")
        elif wears:
            reasons.append(f"removes {which} lead {target.lead} with everything in it")
    if p.get("lead") and p["lead"]["from"] == "promote":
        keeps = "files, template and network" if p.get("lead_netvm") is None \
            and p.get("model_qube") in (None, NONE) else \
            "files and template, and loses its network"
        reasons.append(f"promotes {p['lead']['qube']}, one of the hub's own qubes, into a lead: it "
                       f"keeps its {keeps}")
    # A model endpoint decides who answers the lead's agent: a new one is
    # never one click. "New" as for a network: one no project uses today.
    if t == "project-create" and p.get("model") and \
            p["model"] not in {r.model for r in records.values() if r.model}:
        reasons.append(f"gives the lead a model endpoint no project uses today: {p['model']}, "
                       f"the only place it may reach besides DNS for a host name")
    if t == "project-lead" and not p["remove"] and p.get("model") and target is not None \
            and p["model"] != target.model:
        reasons.append(f"changes the project's model endpoint from {target.model or 'none'} to "
                       f"{p['model']}: the new lead may reach that, and DNS for a host name, "
                       f"nothing else")
    if t == "project-firewall" and p.get("model_qube") is None:
        new = f"model {firewall.endpoint_summary(p['model'])}" if p.get("model") \
            else f"{len(p['rules'])} rules"
        reasons.append(f"changes the lead firewall of {p['project']} to {new}: compare the old and "
                       f"new rules")
    reasons += _model_qube_reasons(app, p, target)
    asked = []
    if t == "project-create":
        asked = [p["lead_netvm"]] + p["networks"]
    elif t == "project-lead" and not p["remove"]:
        asked = [p["lead_netvm"]]
    elif t == "project-edit":
        asked = p["add_networks"]
    asked = [n for n in dict.fromkeys(asked) if n not in (None, NONE)]
    if asked:
        used = networks_in_use(app, records)
        fresh = [n for n in asked if n not in used]
        if fresh:
            reasons.append("gives AI space a network it does not use today: " + ", ".join(fresh))
    quota = p.get("quota")
    if quota is not None:
        others = sum(r.quota for r in records.values()
                     if r.quota and (target is None or r.slot != target.slot))
        cap = budget.read_cap()
        if cap is None:
            reasons.append("the pool cap cannot be read, so the quota cannot be weighed against it")
        elif others + quota > cap:
            reasons.append(f"the projects' quotas would add up to {_gib(others + quota)}, more than "
                           f"the pool cap ({_gib(cap)})")
    return reasons


def _execute(app, p: dict) -> list:
    """Run the command a proposal is the options of; returns its report. One
    that names a hidden anonymous project fails as one naming a project that
    does not exist."""
    from qmcp import fleet
    t = p["type"]
    if "project" in p and _hidden(projects.load(), p["project"]):
        raise fleet.ProjectError(f"no project '{p['project']}'")
    if t.startswith("project-"):
        _refuse_hidden_names(app, p)
    if t == "project-create":
        return fleet.create_project(app, p["label"], p["lead"]["from"], p["lead"]["qube"],
                                    p["templates"], p["networks"], p["quota"], p["lead_netvm"],
                                    p["dump"], p["lead_name"], p.get("model"),
                                    p.get("model_qube"), bool(p.get("anonymous")),
                                    bool(p.get("hub_sees")),
                                    lead_class=p.get("lead_class", "appvm"))
    if t == "project-edit":
        return fleet.edit_project_changes(app, p["project"], p["add_templates"],
                                          p["remove_templates"], p["add_networks"],
                                          p["remove_networks"], p["default_network"], p["quota"])
    if t == "project-dump":
        return fleet.add_dump(app, p["project"], p["name"])
    if t == "project-lead":
        if p["remove"]:
            return fleet.remove_lead(app, p["project"])
        return fleet.set_lead(app, p["project"], p["lead"]["from"], p["lead"]["qube"],
                              p["lead_netvm"], p["keep_old"], p["lead_name"], p.get("model"),
                              bool(p.get("add_old_network")), p.get("model_qube"),
                              p.get("lead_class", "appvm"))
    if t == "project-firewall":
        return fleet.set_lead_firewall(app, p["project"], p.get("model"), p.get("rules"),
                                       model_qube=p.get("model_qube"))
    if t == "project-delete":
        return fleet.delete_project(app, p["project"])
    if t == "qube-open":
        # Parsed again here, by the same parser that refused a bad duration at
        # submit: the stored proposal holds the hub's own words.
        return fleet.open_window_report(app, p["qube"], fleet.duration_seconds(p["for"]),
                                        firewall=p["firewall"])
    if t in ("qube-manage", "qube-revoke", "template-install"):
        _refuse_hidden_qube(app, p)
    if t == "qube-manage":
        report = fleet.Report()
        report.append(fleet.manage(app, p["qube"], from_hub=True))
        return report
    if t == "qube-revoke":
        report = fleet.Report()
        report.append(fleet.revoke(app, p["qube"], shutdown=p["shutdown"], from_hub=True))
        return report
    if t == "template-install":
        return install_report(app, p["template"], p["packages"])
    raise Refused(f"unknown type {t}")


def _recorded_lead_of(name: str):
    """The label (or slot) of the project whose record names `name` its lead,
    or None, also when the records do not read (show only informs)."""
    try:
        records = projects.load()
    except projects.ProjectsUnreadable:
        return None
    p = projects.by_lead(records, name)
    return None if p is None else (p.label or p.slot)


def _refusal_seen(app, p: dict, vm, tags):
    """A refusal the command would make that `show` can see without writing
    anything, in words, or None. Informational: the command checks again at
    accept, and a read that fails here proves nothing either way."""
    from qmcp import fleet
    name = p[QUBE_FIELD[p["type"]]]
    try:
        if p["type"] == "template-install":
            return inqube.install_refusal(vm, name)
        if core.klass_of(vm) == "AdminVM":
            return f"{name} is dom0"
        hub = core.read_hub()
        if hub is None:
            return f"{core.HUB_PATH} cannot be read, so whether {name} is the hub is not known"
        if name == hub:
            return f"{name} is the hub"
        if tags is None:
            return None
        if "ai-dump" in tags:
            return f"{name} is a drop box"
        if core.QUARANTINE in tags:
            return f"{name} is held for your review"
        if p["type"] == "qube-revoke" and (projects.LEAD in tags or projects.lead_slots(tags)):
            # Only the lead a record names; a stray lead badge is revoke's to take off.
            led = _recorded_lead_of(name)
            if led is not None:
                return f"{name} is the lead of {led}"
        # In the command's own order (`fleet._manage`): the slot badges, the
        # devices, then the qubes built on it.
        if p["type"] == "qube-manage" and (why := fleet.slot_badge_refusal(tags, name)):
            return why.replace(f"'{name}'", name, 1)
        if p["type"] == "qube-manage":
            held = fleet.pci_devices(vm)
            if held:
                return f"{name} holds {held} PCI device(s), which a hub's proposal cannot manage"
        if p["type"] == "qube-manage":
            outside = fleet.outside_dependants(app, name)
            if outside:
                return (f"{name} is the template of qubes the hub does not operate "
                        f"(outside AI space or guarded) "
                        f"({fleet._named_few(outside)}), which a hub's proposal cannot manage")
        if p["type"] == "qube-manage" and core.is_gateway(vm):
            return f"{name} provides network, and gateways are always guarded"
        if p["type"] == "qube-revoke" and not p["shutdown"] and (
                core.GUARDED not in tags or tags & {core.OPEN, core.OPEN_FW}):
            return (f"the hub could run commands in {name}, so a hub's proposal to revoke it "
                    f"kills it")
    except (core.Unreadable, fleet.RoleError):
        return None
    return None


def _hidden_names(p: dict) -> list:
    """(qube name, the command's own words for it when it does not exist) for
    every qube a project proposal names that the command would look up: a
    lead's clone source or promoted qube, an approved template, a model qube."""
    out = []
    lead = p.get("lead") or {}
    if lead.get("from") in ("clone", "promote"):
        q = lead["qube"]
        out.append((q, f"no qube '{q}' in AI space"))
    for t in list(p.get("templates") or ()) + list(p.get("add_templates") or ()):
        out.append((t, f"'{t}' is not a template or disposable template in AI space"))
    mq = p.get("model_qube")
    if mq is not None and mq != NONE:
        out.append((mq, f"'{mq}' cannot be a model qube: no such qube"))
    return out


def _refuse_hidden_names(app, p: dict) -> None:
    """A project proposal that names a hidden project's qube (a disposable
    template, a model qube, a lead's source) fails as one naming a qube that
    does not exist, in the command's own words for that, before the command
    reads anything else about it. A qube that cannot be looked up, or whose
    tags cannot be read, refuses too, since it may be one."""
    from qmcp import fleet
    for name, missing in _hidden_names(p):
        if not core.valid_qube_name(name):
            continue                        # the command refuses it in its own words
        try:
            present = name in app.domains
        except Exception:
            raise fleet.ProjectError(f"'{name}' cannot be looked up; try again") from None
        if not present:
            continue
        try:
            tags = core.tags_of(app.domains[name])
        except core.Gone:
            continue
        except core.Unreadable:
            raise fleet.ProjectError(f"'{name}''s badges cannot be read; try again") from None
        if projects.HUBBLIND in tags:
            raise fleet.ProjectError(missing)


def _refuse_hidden_qube(app, p: dict) -> None:
    """A qube of a hidden project, named by the hub, fails as a name that does
    not exist: the same message as the command gives for one. A qube whose
    tags cannot be read refuses too, since it may be one. The command makes
    the hub's other refusals itself, on the tags it reads (`from_hub`)."""
    from qmcp import fleet
    name = p[QUBE_FIELD[p["type"]]]
    try:
        vm, tags = _named_qube(app, p)
    except core.Unreadable:
        raise fleet.RoleError(f"'{name}' cannot be looked up; try again") from None
    if vm is not None and tags is None:
        raise fleet.RoleError(f"'{name}''s badges cannot be read; try again")
    if p["type"] == "template-install" and tags is not None and projects.HUBBLIND in tags:
        # The install's own words for a name that does not exist (its own
        # refusal of a hidden project's template names it as one). For a
        # manage or a revoke the command refuses it itself, on its own read.
        raise fleet.RoleError(f"no qube '{name}'")


def install_report(app, name: str, packages) -> "list":
    """`qmcp template install`, as a report: a refusal before the install's
    script ran is a RoleError, a script that failed or did not finish a failed
    step, and the template's own last lines follow, escaped and said to be its
    words."""
    from qmcp import fleet
    try:
        r = inqube.install(app, name, packages)
    except (inqube.InQubeError, core.Unreadable) as e:
        raise fleet.RoleError(str(e)) from None
    report = fleet.Report()
    line = f"{r['qube']}: {r['status']}: {' '.join(r['packages'])}"
    if r["ok"]:
        report.append(line)
    else:
        report.fail(line)
    if r["started"] and r.get("stopped"):
        report.append(f"{r['qube']} was started for this and shut down again"
                      + (": the qubes built on it get the packages at their next start"
                         if r["ok"] else ""))
    elif r["started"]:
        report.fail(f"{r['qube']} was started for this, and its shutdown did not complete: "
                    f"qvm-shutdown {r['qube']}, or qvm-kill {r['qube']}")
    elif r["ok"]:
        report.append(f"{r['qube']} keeps running: the qubes built on it get the packages once "
                      f"it has shut down and they start again")
    if r["lines"]:
        report.append(f"the last lines {r['manager']} wrote in {r['qube']}, escaped:")
        report += [f"  {line}" for line in r["lines"]]
    return report


#: The types whose command may run for minutes: their accept lets the project
#: commands' locks go once the proposal is marked.
LONG_TYPES = frozenset({"template-install"})

#: Every field of `qmcp proposal show --json`. The window shows each one.
SHOW_FIELDS = ("id", "state", "type", "title", "subject", "caller", "submitted", "expires",
               "sha256", "problem", "needs_closing", "proposal", "command", "second_tick",
               "tick", "before", "after", "plan", "decision")


def _records_or_refuse() -> dict:
    try:
        return projects.load()
    except projects.ProjectsUnreadable as e:
        raise Refused(f"{projects.PROJECTS_PATH} is unreadable ({e}); fix it first "
                      f"(qmcp check names the problem)") from None


def show(app, pid: int, now: float | None = None, directory: str | None = None) -> dict:
    """One proposal for the operator: what it is, what accepting it does to the
    fleet as it is now, and why it needs the second tick, if it does."""
    from qmcp import fleet
    now = time.time() if now is None else now
    e = _entry(pid, directory)
    p, rec = e.proposal, e.record
    doc = {"id": e.id, "state": e.state(now), "type": p and p["type"], "title": p and p["title"],
           "subject": p and subject(p), "caller": rec and rec["caller"],
           "submitted": rec and rec["submitted"], "expires": e.expires(), "sha256": e.sha256,
           "problem": e.problem, "needs_closing": e.needs_closing, "proposal": p,
           "command": p and command(p), "second_tick": [], "tick": None,
           "before": None, "after": None, "plan": None, "decision": e.decision}
    if doc["state"] != "pending":
        return doc
    records = _records_or_refuse()
    doc["second_tick"] = second_tick(app, p, records)
    doc["tick"] = tick_digest(doc["second_tick"])
    target = projects.find(records, p["project"]) if "project" in p else None
    if p["type"] == "project-edit" and target is not None and target.label:
        doc["before"] = {"templates": list(target.templates),
                         "networks": [NONE if n is None else n for n in target.networks],
                         "quota": target.quota}
        try:
            tpls, nets, quota = fleet.edited(target, p["add_templates"], p["remove_templates"],
                                             p["add_networks"], p["remove_networks"],
                                             p["default_network"], p["quota"])
            doc["after"] = {"templates": tpls, "networks": [NONE if n is None else n for n in nets],
                            "quota": quota}
        except fleet.ProjectError as err:
            doc["plan"] = f"this edit cannot apply to the record as it is now: {err}"
    if p["type"] == "project-firewall" and target is not None and target.label:
        view = fleet.lead_firewall_view(app, records, p["project"])
        doc["before"] = {"model": view["model"], "model_qube": view["model_qube"],
                         "accepted": view["accepted"], "live": view["live"],
                         "read_error": view["read_error"]}
        if p.get("model_qube") not in (None, NONE):
            # A model qube: the lead loses its network, so no rules apply after.
            doc["after"] = {"model": None, "model_qube": p["model_qube"], "rules": None}
        elif p.get("model_qube") == NONE:
            # none: only the model qube goes. A lead with a model qube has no
            # network and stays so; a remote model and its rules stay as they are.
            doc["after"] = {"model": view["model"], "model_qube": None,
                            "rules": None if view["model_qube"] else view["accepted"]}
        elif view["model_qube"]:
            # The command refuses a remote model and rules for a lead whose
            # model is a qube, so nothing changes: no "after" to show.
            doc["plan"] = (f"the model of {target.label} is the qube {view['model_qube']}, and its "
                           f"lead has no network: a remote model or rules cannot apply to it, so "
                           f"accepting it will fail")
        else:
            doc["after"] = {"model": p.get("model") or view["model"],
                            "model_qube": None if p.get("model") else view["model_qube"],
                            "rules": firewall.endpoint_rules(p["model"]) if p.get("model")
                            else list(p["rules"])}
    if p["type"] in ("qube-manage", "qube-revoke", "template-install"):
        name = p[QUBE_FIELD[p["type"]]]
        try:
            vm, tags = _named_qube(app, p)
        except core.Unreadable:
            vm, tags = False, None
        if vm is False:
            doc["plan"] = f"{name} could not be looked up now: read it again before you decide"
        elif vm is None:
            doc["plan"] = f"there is no qube {name} now: accepting it will fail"
        elif tags is not None and projects.HUBBLIND in tags:
            doc["plan"] = (f"{name} is a qube of a hidden project: accepting it fails, as for a "
                           f"name that does not exist, and the hub is told only that")
        elif p["type"] == "qube-revoke" and tags is not None and core.UMBRELLA not in tags:
            doc["plan"] = (f"{name} is not in AI space: the hub revokes only a qube it can see, "
                           f"so accepting it will fail and change nothing")
        else:
            why = _refusal_seen(app, p, vm, tags)
            if why:
                doc["plan"] = f"{why}, so accepting it will fail and change nothing"
    if p["type"] == "project-delete":
        # The command's own plan, which also covers finishing a half-done delete.
        doc["plan"] = fleet.delete_plan(app, records, p["project"])[1]
    elif "project" in p and target is None:
        doc["plan"] = f"there is no project {p['project']} now: accepting it will fail"
    return doc


# ======================================================================= deciding

def _report(lines) -> list:
    return [str(line)[:REPORT_WIDTH] for line in list(lines)[:REPORT_LINES]]


def _claim(e: Entry, now: float, directory: str | None) -> tuple:
    """Mark proposal `e` as being accepted, before its command runs, and hold
    the mark locked until the decision is written. The mark is made under a
    temporary name, locked, then linked into place, so no reader ever sees it
    unlocked while the accept runs. Returns (path, descriptor)."""
    d = _dir(directory)
    final = os.path.join(d, f"{e.id:06d}.accepting")
    tmp = os.path.join(d, f".claim-{e.id:06d}-{os.getpid()}")
    old = os.umask(0o027)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    finally:
        os.umask(old)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, canonical({"v": SCHEMA, "id": e.id, "at": _iso(now), "sha256": e.sha256}))
        os.fsync(fd)
        os.link(tmp, final)
    except BaseException:
        os.close(fd)
        raise
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return final, fd


def _decision_bytes(e: Entry, state: str, report, now: float) -> bytes:
    return canonical({"v": SCHEMA, "id": e.id, "state": state, "at": _iso(now),
                      "sha256": e.sha256, "report": _report(report)})


def _decide(e: Entry, state: str, report, now: float, directory: str | None) -> None:
    _write_new(os.path.join(_dir(directory), f"{e.id:06d}.decision"),
               _decision_bytes(e, state, report, now), 0o640)


def _redecide(e: Entry, state: str, report, now: float, directory: str | None) -> str:
    """Replace a decision file that does not read, keeping it beside as
    `NNNNNN.decision.unreadable` (evidence, never read back). The new one is
    renamed over the old, so at no moment is there no decision: the proposal
    never reads as pending. Returns the name the unreadable file was kept as."""
    d = _dir(directory)
    path = os.path.join(d, f"{e.id:06d}.decision")
    aside = f"{path}.unreadable"
    n = 1
    while os.path.lexists(aside):
        n += 1
        aside = f"{path}.unreadable.{n}"
    os.link(path, aside)
    tmp = os.path.join(d, f".decision-{e.id:06d}-{os.getpid()}")
    _write_new(tmp, _decision_bytes(e, state, report, now), 0o640)
    os.replace(tmp, path)
    return os.path.basename(aside)


def _audit(service: str, summary: dict, ok: bool, error=None) -> None:
    audit.audit(service, "operator", summary, ok, error)


def _open(e: Entry, now: float) -> None:
    """Refuse anything but a pending proposal; changes nothing."""
    state = e.state(now)
    if state == ACCEPTING:
        raise Refused(f"proposal {e.id} is being accepted")
    if state == UNREADABLE:
        raise Refused(f"proposal {e.id} cannot be read ({e.problem}); reject it")
    if state == "expired":
        raise Refused(f"proposal {e.id} expired on {e.expires()}")
    if state != "pending":
        raise Refused(f"proposal {e.id} was already {state}")


def accept(app, pid: int, sha256: str, tick: str | None = None, now: float | None = None,
           directory: str | None = None, lock_path: str | None = None) -> tuple:
    """Accept proposal `pid`, which must still hash to `sha256` (the fingerprint
    the operator was shown). `tick` is the second tick: the digest `show` gave
    of the reasons it needs one, refused when there are reasons now and they
    are not exactly those; with none, one click is enough and a well-formed
    tick is ignored. Returns (accepted, report).

    Refusals before the command runs (another fingerprint, not pending, the
    second tick not given, the records unreadable) change nothing and leave the
    proposal as it was. Once the command runs, its outcome closes the proposal:
    `accepted`, or `failed` with the report of what it did before it stopped.
    Every attempt leaves one line on the audit chain, as the operator."""
    from qmcp import fleet
    now = time.time() if now is None else now
    summary = {"id": pid, "sha256": str(sha256)[:64], "yes": tick is not None}
    held, interrupted = None, None
    try:
        if not valid_fingerprint(sha256):
            raise Refused("--sha256 wants the proposal's 64-character fingerprint, as shown")
        if tick is not None and not valid_fingerprint(tick):
            raise Refused("--yes wants the second tick `qmcp proposal show` gave: 64 characters")
        # The project commands' locks first, then the store's (submit and reject
        # take only the store's, so no wait here ever holds them up). Taken
        # before the second tick and the mark: the tick is judged on the fleet
        # the command will find, and locks that cannot be had now refuse before
        # anything is marked, so the proposal stays pending.
        try:
            held = fleet.hold_project_locks()
            held.__enter__()
        except (fleet.ProjectError, RuntimeError) as err:
            held = None
            raise Refused(f"proposal {pid} cannot be accepted now ({err}); nothing was run, "
                          f"and it is still pending") from None
        with _Locked(DECIDE_WAIT_S, lock_path):
            e = _entry(pid, directory)
            if e.proposal is not None:
                summary.update({"type": e.proposal["type"], "subject": subject(e.proposal)})
            _open(e, now)
            if e.sha256 != sha256:
                raise Refused(f"proposal {pid} is not the one shown: its fingerprint differs; "
                              f"refresh and read it again")
            p = e.proposal
            reasons = second_tick(app, p, _records_or_refuse())
            if reasons and tick is None:
                needs = Refused(f"proposal {pid} needs the second tick (--yes {tick_digest(reasons)}): "
                                + "; ".join(reasons))
                needs.logged = "needs the second tick"      # the reasons hold figures
                raise needs
            if reasons and tick != tick_digest(reasons):
                moved = Refused(f"proposal {pid}: the reasons for the second tick are not the ones "
                                f"it was given for; read it again: " + "; ".join(reasons))
                moved.logged = "the second tick answers other reasons"
                raise moved
            try:
                claim_path, claim_fd = _claim(e, now, directory)
            except OSError as err:
                raise Refused(f"proposal {pid} cannot be marked as being accepted "
                              f"({type(err).__name__}); nothing was run") from None
        # The store's lock is free while the command runs: the mark keeps every
        # other accept and reject of this proposal out, and a submit never waits
        # on a running command (so it cannot tell that one is running).
        if p["type"] in LONG_TYPES and held is not None:
            # An install may take half an hour, and the project commands' locks
            # include the create lock every create of the hub and the leads
            # waits on. Nothing the install does rests on a project record, and
            # its reasons were judged under the locks; the mark keeps it from
            # running twice.
            h, held = held, None
            h.__exit__(None, None, None)
        try:
            report = _execute(app, p)
            failure = "a step did not complete" if getattr(report, "failed", None) else None
            ok, report = failure is None, list(report)
        except BaseException as err:
            report = list(getattr(err, "report", []))
            # The command's own message, as `qmcp project` prints it; any other
            # exception by its class only. An interrupt (Ctrl-C, a signal turned
            # into SystemExit) is recorded as one, then raised again: the
            # command stopped part-way, and a long install may have left the
            # template needing repair.
            if not isinstance(err, Exception):
                interrupted = err
                failure = ("interrupted while its command ran: check what it was doing (an "
                           "install may have left the template needing repair)")
            else:
                failure = str(err) if isinstance(err, (fleet.RoleError, RuntimeError)) \
                    else type(err).__name__
            report.append(f"stopped: {failure}")
            ok = False
        try:
            _decide(e, "accepted" if ok else "failed", report, now, directory)
            os.unlink(claim_path)
        except OSError as err:
            # The mark stays: once released below it reads as an accept that
            # never finished, so the proposal is failed and is never run again.
            unrecorded = Refused(
                f"proposal {pid}: the command ran ({'it completed' if ok else 'it failed'}), "
                f"but its decision could not be written ({type(err).__name__}); it reads "
                f"as failed")
            unrecorded.report = _report(report)
            raise unrecorded from None
        finally:
            os.close(claim_fd)
    except Refused as r:
        _audit("qmcp proposal accept", summary, False, getattr(r, "logged", str(r)))
        raise
    except Exception as e:
        # Before its command ran (reading the fleet for the second tick, say):
        # nothing changed and the proposal is as it was.
        _audit("qmcp proposal accept", summary, False, type(e).__name__)
        raise
    finally:
        if held is not None:
            held.__exit__(None, None, None)
    _audit("qmcp proposal accept", summary, ok, failure)
    if interrupted is not None:
        raise interrupted
    return ok, _report(report)


def reject(pid: int, now: float | None = None, directory: str | None = None,
           lock_path: str | None = None) -> str:
    """Reject proposal `pid`: it closes, and nothing changes in the fleet.
    Returns the state it closed in. It also closes a proposal that needs
    closing, so `qmcp check` stops warning about it: an unreadable proposal
    (rejected); an accept that started and never finished (failed, since its
    command may have run part of the way); and a decision file that does not
    read (failed, the file kept beside the new one)."""
    now = time.time() if now is None else now
    summary = {"id": pid}
    try:
        with _Locked(DECIDE_WAIT_S, lock_path):
            e = _entry(pid, directory)
            summary["sha256"] = e.sha256
            if e.proposal is not None:
                summary.update({"type": e.proposal["type"], "subject": subject(e.proposal)})
            state = e.state(now)
            if e.decided and e.decision is None:
                closed = "failed"
                kept = _redecide(e, closed, ["its decision file did not read; closed by the "
                                             "operator"], now, directory)
                summary["kept"] = kept
            elif e.claim == "stale" and not e.decided:
                closed = "failed"
                _decide(e, closed, ["an accept started and did not finish; closed by the operator"],
                        now, directory)
                try:
                    os.unlink(os.path.join(_dir(directory), f"{e.id:06d}.accepting"))
                except OSError:
                    pass
            else:
                if state not in ("pending", UNREADABLE):
                    _open(e, now)
                closed = "rejected"
                _decide(e, closed, [], now, directory)
    except Refused as r:
        _audit("qmcp proposal reject", summary, False, str(r))
        raise
    summary["closed"] = closed
    _audit("qmcp proposal reject", summary, True)
    return closed


# ======================================================================= the notification

NOTICE = "Proposal {} from the hub is waiting in the qubes-mcp window."
#: Where a desktop session's bus lives, per uid (the tests point it elsewhere).
BUS_DIR = "/run/user"
#: The programs that can post a notification, tried in order; the first one
#: present is used. Each gets the fixed text as its last argument but the
#: gdbus call's own trailing fields, which `_notifier_argv` places.
NOTIFIERS = ("/usr/bin/notify-send", "/usr/bin/gdbus")


def _notifier_argv(program: str, text: str) -> list:
    if os.path.basename(program) == "gdbus":
        return [program, "call", "--session", "--dest", "org.freedesktop.Notifications",
                "--object-path", "/org/freedesktop/Notifications", "--method",
                "org.freedesktop.Notifications.Notify", "qubes-mcp", "0", "", "qubes-mcp", text,
                "[]", "{}", "-1"]
    return [program, "--app-name=qubes-mcp", "qubes-mcp", text]


def announce(pid: int, uid: int | None = None) -> bool:
    """Put a desktop notification in front of the operator. Its text is fixed,
    with the proposal's number only, never the hub's words: notification servers
    render markup in the body. Best-effort: False when it could not be shown,
    and it never raises."""
    try:
        return notify_text(NOTICE.format(int(pid)), uid)
    except Exception:
        return False


def notify_text(text: str, uid: int | None = None) -> bool:
    """A desktop notification with text dom0 wrote (never AI's words), as
    `announce`. The services and the anonymity gate's timer run as the
    operator's dom0 user, so the desktop session's bus is that user's: a root
    process cannot reach it (measured on Qubes 4.3.1: the bus closes the
    connection). Without a session there is none. Never raises."""
    import subprocess
    try:
        uid = os.getuid() if uid is None else uid
        runtime = os.path.join(BUS_DIR, str(uid))
        bus = os.path.join(runtime, "bus")
        if not os.path.exists(bus):
            return False
        env = {"PATH": "/usr/bin:/bin", "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
               "XDG_RUNTIME_DIR": runtime}
        for program in NOTIFIERS:
            if os.access(program, os.X_OK):
                # stdout must never be inherited: it is the qrexec reply channel.
                done = subprocess.run(_notifier_argv(program, text), env=env,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, timeout=NOTIFY_TIMEOUT_S,
                                      check=False)
                return done.returncode == 0
    except Exception:
        pass
    return False
