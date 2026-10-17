"""qmcp.services — the twelve qmcp.* qrexec services.

Each one is installed in dom0 under its service name by `dom0/rpc/qmcp-service`,
which calls `main(<name>)`. Every call runs the same funnel: the caller holds
one of its concurrency slots, sends at most 64 KiB, must then be a principal
(the hub, or a lead whose badges and record agree), and gets exactly one JSON
reply. State-changing services leave one audit line.

The hub operates all of AI space. A lead operates its own project's members,
spawns only from its project's approved templates, puts new workers only on
its project's worker networks, creates only inside its project's name space
and disk quota, and has no event stream. Every network a create gives a qube,
for the hub or a lead, is an enrolled gateway (`qmcp.gateways`) or none. Everything else a lead names answers
like a qube that does not exist.

No exception text reaches the caller: every failure answers with a
fixed phrase, and the exception's CLASS goes to the audit line, which the
operator can read and AI cannot.

Two services are the hub's alone and touch no qube: `qmcp.SubmitProposal`
stores a proposal for the operator (`qmcp.proposals`), and
`qmcp.ProposalStatus` tells the hub what became of its proposals, in state
words only.
"""
from __future__ import annotations

import os
import re
import sys
import time

from qmcp import audit as audit_mod
from qmcp import birth, budget, core, gateways, inqube, projects, proposals, restored, scope
from qmcp.core import refuse

LABELS = frozenset({"red", "orange", "yellow", "green", "gray", "blue", "purple", "black"})

#: What the hub may change on a managed qube. `template`,
#: `name`, `default_dispvm` and `provides_network` are operator-only, and netvm
#: may only be cleared.
SETTABLE_PROPS = frozenset({"label", "memory", "maxmem", "vcpus", "netvm"})

#: The only feature keys the hub may set. Each changes nothing
#: outside the qube itself. Every other key, including any a future Qubes adds,
#: is operator-only.
FEATURE_KEYS = frozenset({"menu-items", "default-menu-items"})
FEATURE_PREFIXES = ("service.", "vm-config.")
_FEATURE_SUFFIX_RE = re.compile(r"\A[A-Za-z0-9_.-]{1,64}\Z")
MAX_FEATURE_VALUE = 4096

LIFECYCLE_ACTIONS = frozenset({"start", "shutdown", "kill", "pause", "unpause", "remove"})
#: DispVMTemplate is here because the hub may build disposable templates. A
#: StandaloneVM is made from a TemplateVM and keeps its own copy of its root.
SPAWN_KLASSES = frozenset({"AppVM", "StandaloneVM", "DispVMTemplate", "DispVM"})
#: A lead builds workloads only: disposable templates are never project members.
LEAD_SPAWN_KLASSES = frozenset({"AppVM", "StandaloneVM", "DispVM"})
#: The classes that join a slot.
WORKLOAD_KLASSES = frozenset({"AppVM", "StandaloneVM", "DispVM"})

#: How long a failed rollback keeps retrying the removal of a disposable.
DISPOSE_TRIES = 20
DISPOSE_WAIT_S = 0.5

EVENTS_MIN_S, EVENTS_MAX_S = 1, 120
#: An Events filter is bounded so one call cannot make dom0 match
#: every event against an unbounded list.
EVENTS_MAX_FILTERS = 16
EVENTS_MAX_FILTER_LEN = 64
TAG_EVENT_BASES = ("domain-tag-add", "domain-tag-delete")

_PROP_RE = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")

#: Properties whose value is an address of the qube's NETVM, not of the qube:
#: they describe that netvm, so they are redacted whenever its name is.
NETVM_ADDRESS_PROPS = frozenset({"visible_gateway", "visible_gateway6", "gateway",
                                 "gateway6", "dns"})


def _clip(value):
    """A request value as it may appear in an audit summary."""
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return value[:128]
    return f"<{type(value).__name__}>"


def _string(req: dict, key: str) -> str:
    value = req.get(key)
    if not isinstance(value, str) or not value:
        raise refuse(f"{key} must be a non-empty string")
    return value


def _name_of(value):
    if value is None:
        return None
    return str(getattr(value, "name", value))


def _local_app():
    try:
        import qubesadmin.app
        return qubesadmin.app.QubesLocal()
    except Exception:
        raise refuse("qubesadmin unavailable") from None


def _slot_of(tags) -> str | None:
    """The slot a qube belongs to, as a list shows it: a member's, or a lead's."""
    slots = projects.member_slots(tags) | projects.lead_slots(tags)
    return next(iter(slots)) if len(slots) == 1 else None


def hub_space(prefix: str) -> str:
    """The hub's own name space, `ai-hub-`. `hub` is never a project label,
    so no project's space overlaps it."""
    return f"{prefix}{projects.HUB_LABEL}-"


def _create_name_refusal(name, who) -> str | None:
    """Judged on the name and the prefix alone, before any qube is looked up,
    so a create is no oracle over names. A lead creates only inside its
    project's space (`ai-<label>-`), the hub inside its own (`ai-hub-`), but
    for its clone of a project's member, which is named inside that project's
    space once the source is known (`_clone_name_refusal`): a name says which
    slot holds the qube, so a lead collides only with its own workers or with
    a qube the operator named inside its space or moved out of it."""
    prefix = birth.read_name_prefix()
    space = hub_space(prefix) if who.is_hub() else who.project.space(prefix)
    return birth.name_refusal(name, space)


def _slot_badge(who, new_klass: str, template_for_dispvms: bool = False):
    """The slot badge a spawned qube wears. A lead's workloads join its
    project. The hub's AppVMs and standalones join p00; its disposables do
    not, since one often opens hostile content and in p00 it could drop files
    into the hub's other qubes without a dialog. Templates and disposable
    templates join no slot."""
    if new_klass not in WORKLOAD_KLASSES or template_for_dispvms:
        return None
    if not who.is_hub():
        return projects.member_badge(who.slot)
    return projects.member_badge(projects.HUB_SLOT) if new_klass != "DispVM" else None


def _clone_slot(source_tags, src_is_template: bool) -> str | None:
    """The slot a clone lands in: its source's, for the hub and a lead alike.
    A p00 qube's clone joins p00, a project member's that project, and a clone
    of a qube in no slot joins none. So do a template's clone and a lead's:
    a lead's carries its agent and model credential, and a second holder of a
    lead badge is what the check refuses. The hub never takes a project's
    qube into p00 by cloning it: p00's qubes copy files among themselves
    without a dialog, so that move stays the operator's."""
    if src_is_template:
        return None
    tags = set(source_tags)
    if projects.LEAD in tags or projects.lead_slots(tags):
        return None
    slots = projects.member_slots(tags)
    return next(iter(slots)) if len(slots) == 1 else None


def _hub_mode() -> bool:
    """Anonymous mode, for a hub's call; a mode file that cannot be read refuses."""
    try:
        return core.anonymous_mode()
    except core.ModeUnreadable:
        raise refuse("anonymous mode cannot be read") from None


def _project_badges(who, project=None) -> set:
    """What a new qube wears besides its slot badge: a lead's, its project's
    anonymous badges; the hub's, `qmcp-anon` in anonymous mode (so the
    rulebook's OpenURL and OpenInVM denies cover it, and a disposable template
    passes it to its disposables) and nothing otherwise, plus `project`'s
    anonymous badges when its clone lands in a project. Read before the
    create, so a mode that cannot be read makes nothing."""
    if who.is_hub():
        return ({projects.ANON} if _hub_mode() else set()) \
            | (project.badges() if project is not None else set())
    return who.project.badges()


def _recheck(app, call, template=None, netvm=None) -> None:
    """Under the create lock or a qube's lock, the caller must still be what it
    was: a project command holds the same lock, so a call that waited for one
    must not run on authority it took away. A lead's template and network are checked again
    against its record as it is now. The caller's acting lock is taken first
    and held to the reply, so a lead's removal or change, which takes it
    exclusively, waits for this call once it is past here, and a call that
    reaches here while it runs is checked against what it left."""
    if not call.acting:
        call.fds.append(core.hold_acting(call.caller))
        call.acting = True
    who = core.principal(app, call.caller, core.read_hub())
    if who.kind != call.principal.kind or who.slot != call.principal.slot:
        raise core.Refusal(core.NOT_AUTHORIZED)
    call.principal = who
    if netvm is not None and not gateways.is_enrolled(netvm):
        raise refuse("netvm must be an enrolled gateway")
    if netvm is not None and who.is_hub() and _hub_mode():
        try:
            g = gateways.load()[netvm]
        except (gateways.GatewaysUnreadable, KeyError):
            g = None
        if g is None or not g.anonymising:
            raise refuse("anonymous mode: netvm must be an anonymising gateway")
        # Still on the network recorded for it: a router moved to clearnet is
        # one the gate is about to stop; nothing new is born on it meanwhile.
        router = core.lookup(app, netvm)
        try:
            now = None if router is None else core.netvm_of(router)
        except core.Unreadable:
            now = core.UNREADABLE
        if g.upstream is None or now != g.upstream:
            raise refuse("anonymous mode: netvm is not on the network recorded for it")
    if not who.is_hub():
        if template is not None and template not in who.project.templates:
            raise refuse("template is not on this project's approved list")
        if netvm is not None and netvm not in who.project.named_networks():
            raise refuse("netvm must be one of this project's worker networks")


# ------------------------------------------------------------------ reads

def svc_list(app, call, req):
    """One tag read per qube. A qube whose tags or class cannot be read is not
    listed: never as some other state."""
    who = call.principal
    out = []
    for vm in app.domains:
        try:
            tags = core.tags_of(vm)
            if not core.visible(vm, who, tags):
                continue
            klass = core.klass_of(vm)
        except core.Unreadable:
            continue
        try:
            power = vm.get_power_state()
        except Exception:
            power = "unknown"
        try:
            label = vm.label.name if vm.label else None
        except Exception:
            label = core.UNREADABLE
        try:
            template = scope.scoped_name(app, core.template_of(vm), who)
        except core.Unreadable:
            template = core.UNREADABLE
        out.append({
            "name": vm.name,
            "klass": klass,
            "label": label,
            "template": template,
            "power_state": power,
            "guarded": core.is_guarded(vm, tags),
            "slot": _slot_of(tags),
            "lead": projects.LEAD in tags,
        })
    return {"ok": True, "qubes": out}


def svc_get_property(app, call, req):
    name, prop = _string(req, "name"), _string(req, "property")
    who = call.principal
    vm = core.readable(app, name, who)
    if prop == "power_state":
        return {"ok": True, "value": vm.get_power_state()}
    if prop == "tags":
        return {"ok": True, "value": scope.scoped_tags(vm.tags)}
    if prop == "label":
        try:
            return {"ok": True, "value": vm.label.name}
        except Exception:
            raise refuse("read failed") from None
    # Only properties qubesd itself lists are read, so a name such as `app`
    # or `qubesd_call` can never reach an attribute of the client library.
    if not _PROP_RE.match(prop):
        raise refuse("property does not exist")
    try:
        known = set(vm.property_list())
    except Exception:
        raise refuse("read failed") from None
    if prop not in known:
        raise refuse(f"property '{prop}' does not exist")
    if prop in NETVM_ADDRESS_PROPS:
        # Whose addresses these are decides what may be shown: an unread
        # network is refused, never taken for none (qubesadmin's read errors
        # are AttributeErrors, which getattr with a default would swallow).
        try:
            netvm = vm.netvm
        except Exception:
            raise refuse("read failed") from None
        if netvm is not None and scope.scoped_name(app, netvm, who) == scope.OUT_OF_SCOPE:
            return {"ok": True, "value": scope.OUT_OF_SCOPE}
    try:
        value = getattr(vm, prop)
    except Exception:
        # qubesd listed it, so this is a read that failed, never an absence.
        raise refuse("read failed") from None
    value = scope.scoped_value(app, value, who)
    if not isinstance(value, (str, int, float, bool, list, type(None))):
        raise refuse("property not readable")
    return {"ok": True, "value": value}


def svc_pool_stats(app, call, req):
    """The caller's disk budget: AI space against the fleet cap for the hub; the
    project's members against its quota for a lead, with the project's name
    space, approved templates, worker networks, dump sink and model (a remote
    endpoint, or the model qube it reaches over qubes.ConnectTCP on
    `model_port`). A lead never
    sees the fleet's figures; a create the fleet cap refuses inside its quota
    does tell it that the rest of AI space is full (`qmcp check` warns when the
    projects' quotas add up to more than the cap)."""
    who = call.principal
    prefix = birth.read_name_prefix()
    if who.is_hub():
        cap = budget.read_cap()
        if cap is None:
            raise refuse(budget.ERR_CAP_MISSING)
        badge = None
    else:
        cap, badge = who.project.quota, projects.member_badge(who.slot)
    try:
        used = budget.persistent_sum(app, badge)
    except Exception:
        raise refuse(budget.ERR_STATS_UNAVAILABLE) from None
    out = {"ok": True,
           "ai_managed_bytes_used": used,
           "ai_managed_bytes_cap": cap,
           "ai_managed_bytes_headroom": max(0, cap - used),
           "name_prefix": hub_space(prefix)}
    if who.is_hub():
        # The bare prefix a project's names build on: `name_prefix` is the
        # hub's own space, which no project shares.
        out["reserved_prefix"] = prefix
        out["projects"] = _project_rows(app)
        out["gateways"] = _gateway_rows()
    else:
        p = who.project
        # A model qube that left AI space is redacted, as every read redacts one.
        mq = p.model_qube
        if mq is not None and not core.in_ai_space_by_name(app, mq):
            mq = scope.OUT_OF_SCOPE
        # Never the operator's note: it is for the window and the command only.
        out.update({"project": p.label, "name_prefix": p.space(prefix),
                    "templates": list(p.templates), "networks": list(p.networks),
                    "dump": p.dump, "model": p.model, "model_qube": mq,
                    "model_port": projects.MODEL_PORT if p.model_qube else None,
                    "anonymous": p.anonymous, "hub_sees": not p.hidden})
    return out


def _gateway_rows():
    """The registry as the hub reads it, so it can propose networks by name:
    each enrolled gateway's name, whether it is anonymising, and its label.
    Null when the registry cannot be read, never an empty list."""
    try:
        registry = gateways.load()
    except gateways.GatewaysUnreadable:
        return None
    return [{"name": g.name, "anonymising": g.anonymising, "label": g.label}
            for g in sorted(registry.values(), key=lambda g: g.name)]


def _project_rows(app):
    """Every project's record as the hub may read it, so it can propose an edit
    that fits. A name in a record that is no longer in AI space (a template
    the operator took out, say) reads `<out-of-scope>`, as every read redacts
    one, unless it is an enrolled gateway, which the hub reads by name; the
    dump sink is outside AI space, so only whether there is one is told. The
    model is a remote endpoint, or the name of the project's model qube, read
    as any other name. One pass over the qubes gives both the names in scope and each
    slot's disk use; a slot's use that cannot be read is null, never zero, and
    records that cannot be read are null, never an empty list."""
    try:
        records = projects.load()
    except projects.ProjectsUnreadable:
        return None
    in_scope, used, unreadable = set(), {}, set()
    for vm in app.domains:
        try:
            tags = core.tags_of(vm)
        except core.Gone:
            continue                        # removed since the list was read: holds nothing
        except core.Unreadable:
            # Whose member it is cannot be told, so no slot's use is known.
            unreadable.update(records)
            continue
        if core.UMBRELLA not in tags:
            continue
        if projects.HUBBLIND not in tags:
            in_scope.add(vm.name)
        for slot in projects.member_slots(tags):
            try:
                used[slot] = used.get(slot, 0) + budget.persistent_bytes(vm)
            except Exception:
                unreadable.add(slot)
    enrolled = gateways.enrolled_names()
    shown = lambda name: (name if name is None or name in in_scope or name in enrolled  # noqa: E731
                          else scope.OUT_OF_SCOPE)
    out = []
    for slot, p in sorted(records.items()):
        if p.hidden:
            continue                        # a hidden anonymous project is not the hub's to see
        out.append({"slot": slot, "label": p.label, "lead": shown(p.lead),
                    "templates": [shown(t) for t in p.templates],
                    "networks": [shown(n) for n in p.networks], "quota": p.quota,
                    "used": None if slot in unreadable else used.get(slot, 0),
                    "has_dump": p.dump is not None, "model": p.model,
                    "model_qube": None if p.model_qube is None else shown(p.model_qube),
                    "anonymous": p.anonymous})
    return out


# ------------------------------------------------------------------ writes

def _operate(app, call, name):
    """The qube a call operates, under its lock: resolved as `core.operand`
    resolves it, then its lock is taken, then the caller and the qube are checked again, so a guard, revoke, move or
    hold of the operator's, or the restore check's, that landed while this call
    waited is honoured, and none lands between this check and the effect.
    The lock is taken only once the qube resolves, so a name the caller cannot
    see never waits on a lock and contention is no oracle; it is held until
    the reply (`call.fds`)."""
    core.operand(app, name, call.principal)
    fd = core.acquire_qube_lock(name, core.QUBE_WAIT_S)
    if fd is None:
        raise core.Refusal(core.BUSY_REFUSAL)
    call.fds.append(fd)
    _recheck(app, call)
    return core.operand(app, name, call.principal)



def svc_set_property(app, call, req):
    name, prop = _string(req, "name"), _string(req, "property")
    call.summary.update({"name": _clip(name), "property": _clip(prop)})
    vm = _operate(app, call, name)
    if prop not in SETTABLE_PROPS:
        raise refuse("property not settable")
    if "value" not in req:
        raise refuse("value is required")
    value = req["value"]
    if prop == "label":
        if not isinstance(value, str) or value not in LABELS:
            raise refuse(f"label must be one of: {sorted(LABELS)}")
    elif prop == "netvm":
        if value is not None:
            raise refuse("netvm change is operator-only; null (disconnect) is permitted")
    elif isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        # bool is an int subclass, so `True` must be refused explicitly.
        raise refuse(f"{prop} must be a positive integer")
    try:
        # A value still following its default is not the same: the set pins it.
        same = (not vm.property_is_default(prop)
                and _name_of(getattr(vm, prop)) == _name_of(value))
    except Exception:
        same = False                # not read: the set goes on, as a change
    if same:
        # Nothing to change: answered as a set, logged as a call that changed
        # nothing (capped), so repeating it cannot fill the audit log.
        call.noop = True
        return {"ok": True}
    try:
        setattr(vm, prop, value)
    except Exception as e:
        call.error_class = type(e).__name__
        raise refuse("set failed") from None
    return {"ok": True}


def _feature_allowed(key: str) -> bool:
    if key in FEATURE_KEYS:
        return True
    for prefix in FEATURE_PREFIXES:
        if key.startswith(prefix) and _FEATURE_SUFFIX_RE.match(key[len(prefix):]):
            return True
    return False


def svc_set_feature(app, call, req):
    name, feature = _string(req, "name"), _string(req, "feature")
    call.summary.update({"name": _clip(name), "feature": _clip(feature)})
    vm = _operate(app, call, name)
    if not _feature_allowed(feature):
        raise refuse("feature not settable")
    value = req.get("value")
    if isinstance(value, bool):
        text = "1" if value else ""
    elif isinstance(value, int):
        text = str(value)
    elif isinstance(value, str) and len(value) <= MAX_FEATURE_VALUE:
        text = value
    else:
        raise refuse("value must be a string, integer or boolean (removal is operator-only)")
    try:
        same = vm.features.get(feature, None) == text
    except Exception:
        same = False                # not read: the set goes on, as a change
    if same:
        call.noop = True            # as for a property: capped, answered as a set
        return {"ok": True, "feature": feature, "value": text}
    try:
        vm.features[feature] = text
    except Exception as e:
        call.error_class = type(e).__name__
        raise refuse("feature.Set failed") from None
    try:
        readback = vm.features.get(feature, None)
    except Exception:
        readback = core.UNREADABLE          # set; the read-back alone failed
    return {"ok": True, "feature": feature, "value": readback}


def svc_lifecycle(app, call, req):
    name, action = _string(req, "name"), _string(req, "action")
    call.summary.update({"name": _clip(name), "action": _clip(action)})
    if action not in LIFECYCLE_ACTIONS:
        raise refuse(f"action must be one of: {sorted(LIFECYCLE_ACTIONS)}")
    vm = _operate(app, call, name)
    # A lead is a project's identity: removing one takes the operator's approval.
    if action == "remove" and projects.LEAD in core.tags_of(vm):
        raise refuse("removing a lead takes the operator's approval")
    # The gate may stop the qube between the check above and the start: read
    # again right before waking it.
    if action in ("start", "unpause") and projects.BLOCKED in core.tags_of(vm):
        raise core.Refusal(core.BLOCKED_REFUSAL)
    try:
        if action == "remove":
            del app.domains[name]
        else:
            getattr(vm, action)()
    except Exception as e:
        call.error_class = type(e).__name__
        raise refuse("action failed") from None
    return {"ok": True}


# ------------------------------------------------------------------ creates

def _exists(app, name, call=None) -> bool | None:
    """Does `name` exist right now? None if that cannot be established; the
    exception's class then goes on `call`'s audit line, when there is one."""
    try:
        clear = getattr(app.domains, "clear_cache", None)
        if clear is not None:
            clear()
        return name in app.domains
    except Exception as e:
        if call is not None:
            call.error_class = type(e).__name__
        return None


def _remove(app, name) -> bool:
    """Remove a qube THIS call created. True only when it is demonstrably gone
    (a rollback is never reported that did not happen)."""
    if _exists(app, name) is False:
        return True
    try:
        vm = app.domains[name]
        if vm.is_running():
            vm.kill()
    except Exception:
        pass
    try:
        del app.domains[name]
    except Exception:
        pass
    return _exists(app, name) is False


def _rollback(app, call, name, step, exc) -> core.Refusal:
    """Undo a create that succeeded but could not be finished."""
    call.error_class = type(exc).__name__
    if _remove(app, name):
        return refuse(f"{step} failed (rolled back)")
    return refuse(f"{step} failed and rollback failed: qube '{name}' needs manual cleanup in dom0")


def _create_failed(app, call, name, what, exc) -> core.Refusal:
    """A create call that raised made nothing this call can prove is its own,
    so nothing is removed: qubesd rolls back a failed admin.vm.Create or
    CreateInPool itself, which is a copy's create too. Deleting by name here could
    take a qube someone else created under that name in the meantime."""
    call.error_class = type(exc).__name__
    exists = _exists(app, name)
    if exists is not False:
        call.landed = True          # it may be this call's: its line is never withheld
    if exists:
        return refuse(f"{what} failed; a qube named '{name}' exists and was left alone")
    return refuse(f"{what} failed")


def _claim_name(app, call, name) -> None:
    """Refuse a name that is taken, or that cannot be checked. Called again
    under the create lock: a name free before a 120 s wait may not be after."""
    taken = _exists(app, name, call)
    if taken is None:
        raise refuse("could not check the name")
    if taken:
        raise refuse(f"qube '{name}' already exists")


def _not_a_gateway(vm, what: str) -> None:
    """A qube spawned from a network-providing template provides network too,
    and the policy cannot see that: refuse it outright."""
    if core.is_gateway(vm):
        raise refuse(f"a {what} that provides network cannot be spawned from")


def _lead_netvm(app, req, project, source_vm, authoritative: bool):
    """A lead's create is born on its project's worker networks, never on the
    lead's own network. A clone source or a disposable template answers for
    itself, and its network must be on the list (or none). A spawn from a
    TemplateVM takes the requested listed network, or the list's first.
    Requests are judged against the list, which the lead knows, and the
    registry, before any lookup; every listed network must be enrolled. After
    birth a network can only be cleared, never moved."""
    named = project.named_networks()
    enrolled = gateways.enrolled_names()
    specified = "netvm" in req
    requested = req.get("netvm")
    if specified and requested is not None and not isinstance(requested, str):
        raise refuse("netvm must be a qube name or null")
    if authoritative:
        try:
            src = _name_of(source_vm.netvm)
        except Exception:
            raise refuse("birth egress could not be resolved") from None
        if src is not None and src not in named:
            raise refuse("the source's network is not one of this project's worker networks")
        if specified:
            if requested is None:
                return None
            if requested != src:
                raise refuse("netvm must match the inherited birth egress")
        if src is not None and src not in enrolled:
            raise refuse("birth egress could not be resolved")
        return src
    if specified:
        if requested is None:
            return None
        if requested not in named:
            raise refuse("netvm must be one of this project's worker networks")
        if requested not in enrolled:
            raise refuse("netvm must be an enrolled gateway")
        return requested
    default = project.networks[0]
    if default is not None and default not in enrolled:
        raise refuse("birth egress could not be resolved")
    return default


def _birth_netvm(app, call, req, source_vm, authoritative: bool):
    """The netvm a create must use (the birth chain in birth.py), honouring an explicit
    `netvm` in the request: for the hub, null is always allowed (offline
    cannot leak); a name must be an enrolled gateway AND equal the inherited
    answer. A lead's request is judged by `_lead_netvm`. Both are
    judged from the registry file and the chain, never by looking the name up,
    so it is no oracle."""
    if not call.principal.is_hub():
        return _lead_netvm(app, req, call.principal.project, source_vm, authoritative)
    specified = "netvm" in req
    requested = req.get("netvm")
    if specified and requested is not None and not isinstance(requested, str):
        raise refuse("netvm must be a qube name or null")
    if specified and requested is None:
        return None                         # no network: nothing to resolve or read
    caller_vm = core.lookup(app, call.caller)
    if caller_vm is None:
        # The hub exists, so a failed lookup is a read that failed, never "no
        # network of its own" (which would fall through to birth-egress).
        raise core.Unreadable(f"cannot look up {call.caller}")
    resolved, rule = birth.resolve_egress(app, caller_vm, source_vm, authoritative)
    if specified:
        if not gateways.is_enrolled(requested):
            raise refuse("netvm must be an enrolled gateway")
        if rule == "unresolved" or requested != resolved:
            raise refuse("netvm must match the inherited birth egress")
        return requested
    if rule == "unresolved":
        raise refuse("birth egress could not be resolved")
    return resolved


def _set_netvm(vm, netvm) -> None:
    """Set explicitly and read back, value AND that it no longer follows a
    default: a qube left following the global default would move when the
    operator changes it. Done before the first boot ("burn, don't repair")."""
    vm.netvm = netvm
    if _name_of(vm.netvm) != netvm or vm.property_is_default("netvm"):
        raise RuntimeError("netvm did not read back as set")


def _pin_default_dispvm(vm) -> None:
    """No default disposable template: Qubes' raw @dispvm shortcut from this
    qube then has nowhere to go, even if it later leaves AI space."""
    vm.default_dispvm = None
    if core.default_dispvm_of(vm) is not None or vm.property_is_default("default_dispvm"):
        raise RuntimeError("default_dispvm did not read back as None")


def _estimate(fn, *args) -> int:
    try:
        return fn(*args)
    except Exception as e:
        raise core.Refusal({"ok": False, "error": budget.ERR_STATS_UNAVAILABLE},
                           error_class=type(e).__name__) from None


def _check_budget(app, call, estimate: int, project=None) -> None:
    """Under the create lock: the quota of the project the new qube joins
    first (a lead's own, or the project the hub's clone lands in), so a request
    over its quota never reaches the fleet cap, then the fleet cap."""
    who = call.principal
    if not who.is_hub():
        project = who.project
    if project is not None:
        budget.check_quota(app, projects.member_badge(project.slot), project.quota, estimate)
    budget.check_cap(app, estimate)


def _private_size(req):
    size = req.get("private_size")
    if size is None:
        return None
    if isinstance(size, bool) or not isinstance(size, int):
        raise refuse("private_size must be an integer number of bytes")
    if size <= 0:
        raise refuse("private_size must be a positive number of bytes")
    return size


def _spawn_template(app, template, klass, who):
    """The template a spawn builds on, judged: in reach, not stopped by the
    gate, not held, of the class `klass` needs, and providing no network."""
    tpl = core.reference(app, template, "template", who)
    if klass in ("AppVM", "StandaloneVM", "DispVMTemplate"):
        if core.klass_of(tpl) != "TemplateVM":
            raise refuse(f"template '{template}' must be a TemplateVM for klass={klass}")
    elif not core.is_dvmt(tpl):
        raise refuse(f"template '{template}' must be a disposable template for klass=DispVM")
    _not_a_gateway(tpl, "template")
    return tpl


def svc_spawn(app, call, req):
    name = req.get("name")
    template = req.get("template")
    klass = req.get("klass", "AppVM")
    label = req.get("label", "gray")
    call.summary.update({"name": _clip(name), "template": _clip(template),
                         "klass": _clip(klass), "label": _clip(label),
                         "netvm": _clip(req.get("netvm")),
                         "private_size": _clip(req.get("private_size"))})
    who = call.principal
    # The name is judged on its shape alone, before anything is looked up.
    err = _create_name_refusal(name, who)
    if err:
        raise refuse(err)
    klasses = SPAWN_KLASSES if who.is_hub() else LEAD_SPAWN_KLASSES
    # Shape first: a list is unhashable, and `in` on a frozenset would raise.
    if not isinstance(klass, str) or klass not in klasses:
        raise refuse(f"klass must be one of: {sorted(klasses)}")
    if not isinstance(label, str) or label not in LABELS:
        raise refuse(f"label must be one of: {sorted(LABELS)}")
    private_size = _private_size(req)
    tpl = _spawn_template(app, template, klass, who)
    _claim_name(app, call, name)
    netvm = _birth_netvm(app, call, req, tpl, authoritative=(klass == "DispVM"))

    budget.check_private_size(private_size)
    call.fds.append(budget.acquire_create_lock())
    _recheck(app, call, template=template, netvm=netvm)
    who = call.principal
    _claim_name(app, call, name)
    # The template is looked up and judged again under the lock, as a clone's
    # source is: a stop, a revoke, a hold or a hidden project's approval that
    # landed while this call waited must not be built on. Its tags below come
    # from this read.
    tpl = _spawn_template(app, template, klass, who)
    estimate = budget.estimate_new_private(private_size)
    if klass == "StandaloneVM":
        # A standalone's root is its own, counted at the template root's size.
        estimate += _estimate(budget._vol_size, tpl, "root")
    elif klass == "DispVM":
        # qubesd gives a named DispVM its disposable template's private size,
        # whatever was asked, and the budget then counts it at that size.
        estimate = max(estimate, _estimate(budget._vol_size, tpl, "private"))
    _check_budget(app, call, estimate)
    # Read after the lock, right before the create: a restriction the template
    # carries (`anon-vm`) must reach the child, including one added while this
    # call waited, and a read that fails refuses here, before anything is made.
    tpl_tags = core.tags_of(tpl)
    _reviewed(tpl)
    extra = _project_badges(who)
    # Read BEFORE the copy, and again after it (`inqube.after_copy`): the root
    # copied is the one the template had when it last stopped.
    tpl_halted = klass != "StandaloneVM" or inqube.halted(tpl)

    create_klass = "AppVM" if klass == "DispVMTemplate" else klass
    try:
        if klass == "StandaloneVM":
            vm = birth.create_copy(app, tpl, name, "StandaloneVM", label, standalone=True)
        else:
            vm = app.add_new_vm(create_klass, name, label, template=template)
    except Exception as e:
        raise _create_failed(app, call, name, "create", e)
    call.landed = True
    step = "copy"
    try:
        if klass == "StandaloneVM":
            # Filled before it is in AI space: the stamp below is its first
            # badge of ours (`birth`, "A copy is built in dom0's own order").
            birth.fill_copy(app, vm, tpl, standalone=True)
        # The network and the default disposable template are set and read
        # back while the qube is still outside AI space, so no start of it,
        # the caller's or anyone's, can boot it on Qubes' default network.
        step = "netvm assignment"
        _set_netvm(vm, netvm)
        step = "default_dispvm pin"
        _pin_default_dispvm(vm)
        step = "network check"
        if core.is_gateway(vm):
            raise RuntimeError("the new qube provides network")
        if klass == "DispVMTemplate":
            step = "disposable template flag"
            vm.template_for_dispvms = True
            if not core.is_dvmt(vm):
                raise RuntimeError("template_for_dispvms did not read back")
        step = "label"
        restored.label(vm)
        if klass == "StandaloneVM":
            step = "services label"
            inqube.after_copy(vm, tpl, tpl_halted)
        step = "birth stamp"
        birth.stamp(birth.TagIO.for_vm(vm), tpl_tags, call.caller,
                    _slot_badge(who, create_klass, klass == "DispVMTemplate"), extra)
    except Exception as e:
        raise _rollback(app, call, name, step, e)
    if private_size is not None:
        try:
            vm.volumes["private"].resize(private_size)
        except Exception as e:
            call.error_class = type(e).__name__
            return {"ok": True, "name": name, "warning": "private_resize_failed"}
    return {"ok": True, "name": name}


def _reviewed(vm) -> None:
    """A qube a create copies or builds on must not be one the restore check
    holds, or would hold on its next pass: in scope with a label that is not
    its own (it came back from a backup or a copy). Asked under the create
    lock, which that pass takes too, so a copy, which gets a label of its own,
    never carries a restored qube past review. A read that fails refuses."""
    try:
        tags = core.tags_of(vm)
        if core.QUARANTINE in tags or (restored.in_scope(tags) and not restored.known(vm)):
            raise core.Refusal(core.QUARANTINE_REFUSAL)
    except core.Unreadable:
        raise core.Refusal(core.QUARANTINE_REFUSAL) from None


def _clone_base(who, src) -> None:
    """The template a clone is built on (an AppVM's, or a named DispVM's
    disposable template) is checked as a spawn checks its template: never one
    the anonymity gate stopped or the restore check holds or would hold, and
    for a lead one on its project's approved list."""
    tpl = core.template_of(src)
    if tpl is None:
        return
    tags = core.tags_of(tpl)
    # A hidden project's disposable template is not the hub's to build on,
    # whatever an older child of it still wears: its clone would snapshot the
    # template's home at every start. Answered as a source that does not exist.
    if who.is_hub() and projects.HUBBLIND in tags:
        raise core.Refusal(core.NOT_FOUND)
    if tags & {projects.BLOCKED, projects.STOPPED}:
        raise core.Refusal(core.BLOCKED_REFUSAL)
    _reviewed(tpl)
    if not who.is_hub() and core.name_of(tpl) not in who.project.templates:
        raise refuse("the source's template is not on this project's approved list")


def _clone_target(app, who, src):
    """(the slot a clone of `src` lands in, its project record or None for
    p00 and no slot). A project the source names that has no record refuses:
    the check reports such a badge, and a clone must not land on it. A hidden
    project is not the hub's: its member answers as a qube that does not
    exist, even one that lost its hidden badge."""
    if not who.is_hub():
        # A lead clones only its own members, so the clone joins its project
        # whatever stray badge the source wears.
        return who.slot, who.project
    slot = _clone_slot(core.tags_of(src), core.is_template(src))
    if slot is None or slot == projects.HUB_SLOT:
        return slot, None
    try:
        p = projects.load().get(slot)
    except Exception as e:
        raise core.Refusal({"ok": False, "error": "project records cannot be read"},
                           error_class=type(e).__name__) from None
    if p is not None and p.hidden:
        raise core.Refusal(core.NOT_FOUND)
    if p is None:
        raise refuse("the source's project has no record")
    return slot, p


def _clone_network(who, project, netvm) -> None:
    """The hub's clone into a project sits on one of the project's worker
    networks, as the project's members do (a lead's clone is judged by
    `_lead_netvm`)."""
    if who.is_hub() and project is not None and netvm is not None \
            and netvm not in project.named_networks():
        raise refuse("the source's network is not one of this project's worker networks")


def _clone_name_refusal(name, who, project) -> str | None:
    """A clone's name sits in the space of the slot it lands in: a lead's in its
    project's, the hub's in its own, or in the source's project's when the clone
    lands there. Judged once the source is resolved, which the hub can already
    list, so it tells the hub nothing new."""
    if project is None or not who.is_hub():
        return _create_name_refusal(name, who)
    return birth.name_refusal(name, project.space(birth.read_name_prefix()))


def svc_clone(app, call, req):
    source, name = req.get("source"), req.get("name")
    call.summary.update({"source": _clip(source), "name": _clip(name)})
    who = call.principal
    # The name's shape, and for a lead its project's space, are judged before
    # anything is looked up. The hub's space follows the source, so its
    # name is judged against the prefix here and the space once it is known.
    err = _create_name_refusal(name, who) if not who.is_hub() \
        else birth.name_refusal(name, birth.read_name_prefix())
    if err:
        raise refuse(err)
    if not isinstance(source, str):
        raise core.Refusal(core.NOT_FOUND)
    # The source must be managed: a clone is a managed, editable copy of
    # everything in it, which a guarded qube must never become. A guarded
    # qube may still be spawned FROM; see the residuals in CLAUDE.md for what a
    # spawn carries over. The hub may clone a template it manages.
    src = core.operand(app, source, who)
    src_is_template = core.is_template(src)
    if src_is_template and not who.is_hub():
        # Templates and disposable templates are never project members.
        raise core.Refusal(core.NOT_FOUND)
    slot, project = _clone_target(app, who, src)
    err = _clone_name_refusal(name, who, project)
    if err:
        raise refuse(err)
    _claim_name(app, call, name)
    # A clone is the same kind of qube as its source, so the source always
    # answers for its own network — a cloned template stays off the network.
    netvm = _birth_netvm(app, call, {}, src, authoritative=True)
    _clone_network(who, project, netvm)

    call.fds.append(budget.acquire_create_lock())
    _recheck(app, call, netvm=netvm)
    who = call.principal
    _claim_name(app, call, name)
    # Under the lock everything about the source is read again: a move, a
    # stop, a hold or a project command while this call waited must not be
    # copied past. The project's record is the one read now. The source's own
    # lock is held from here to the reply, so a revoke or guard of it waits
    # for the copy, and the copy for them.
    src = _operate(app, call, source)
    who = call.principal
    _reviewed(src)
    _clone_base(who, src)
    again, now = _clone_target(app, who, src)
    if again != slot or core.is_template(src) != src_is_template \
            or (now is None) != (project is None) \
            or (now is not None and now.label != project.label):
        raise refuse("the source moved while this call waited; try again")
    project = now
    _clone_network(who, project, netvm)
    _check_budget(app, call, _estimate(budget.persistent_bytes, src),
                  project if who.is_hub() else None)

    source_tags = core.tags_of(src)
    extra = _project_badges(who, project if who.is_hub() else None)
    # Read BEFORE the copy, and again after it (`inqube.after_copy`): the root
    # copied is the one the source had when it last stopped.
    src_halted = inqube.halted(src)
    try:
        vm = birth.create_copy(app, src, name, core.klass_of(src), _name_of(src.label))
    except Exception as e:
        raise _create_failed(app, call, name, "clone", e)
    call.landed = True
    # Filled before it is in AI space: the stamp is its first badge of ours.
    step = "copy"
    try:
        birth.fill_copy(app, vm, src, standalone=False)
        # Network and default disposable template before it joins AI space.
        step = "netvm assignment"
        _set_netvm(vm, netvm)
        step = "default_dispvm pin"
        _pin_default_dispvm(vm)
        step = "network check"
        if core.is_gateway(vm):
            raise RuntimeError("the new qube provides network")
        step = "label"
        restored.label(vm)
        step = "services label"
        inqube.after_copy(vm, src, src_halted)
        step = "birth stamp"
        birth.stamp(birth.TagIO.for_vm(vm), source_tags, call.caller,
                    None if slot is None else projects.member_badge(slot), extra)
    except Exception as e:
        raise _rollback(app, call, name, step, e)
    return {"ok": True, "name": name}


def _prop_direct(app, name, prop):
    """(follows a default?, value) via a direct admin call, which answers
    `default=<True|False> type=<type> <value>`; an unset value is empty."""
    text = app.qubesd_call(name, "admin.vm.property.Get", prop).decode(errors="replace")
    parts = text.split(" ", 2)
    value = parts[2].strip() if len(parts) == 3 else ""
    return parts[0] == "default=True", value


def _exists_direct(app, name) -> bool:
    try:
        raw = app.qubesd_call("dom0", "admin.vm.List").decode(errors="replace")
    except Exception:
        return True
    return any(line.split(" ", 1)[0] == name for line in raw.splitlines())


def _dispose(app, name) -> bool:
    """Remove a disposable this call created. A running one is killed and
    qubesd's auto-cleanup removes it; a halted one is removed. True only once
    it is gone."""
    try:
        app.qubesd_call(name, "admin.vm.Kill")
    except Exception:
        pass
    for _ in range(DISPOSE_TRIES):
        if not _exists_direct(app, name):
            return True
        try:
            app.qubesd_call(name, "admin.vm.Remove")
        except Exception:
            time.sleep(DISPOSE_WAIT_S)
    return not _exists_direct(app, name)


def _disposable_template(app, template, who):
    dvmt = core.reference(app, template, "template", who)
    if not core.is_dvmt(dvmt):
        raise refuse(f"template '{template}' must be a disposable template")
    _not_a_gateway(dvmt, "disposable template")
    return dvmt


def svc_spawn_disposable(app, call, req):
    template = req.get("template")
    call.summary.update({"template": _clip(template)})
    who = call.principal
    dvmt = _disposable_template(app, template, who)
    netvm = _birth_netvm(app, call, {}, dvmt, authoritative=True)

    call.fds.append(budget.acquire_create_lock())
    _recheck(app, call, template=template, netvm=netvm)
    who = call.principal
    # Judged again under the lock, as a spawn's template is; the tags below
    # come from this read.
    dvmt = _disposable_template(app, template, who)
    _check_budget(app, call, budget.estimate_new_private(_estimate(budget._vol_size, dvmt, "private")))
    _reviewed(dvmt)

    source_tags = core.tags_of(dvmt)
    extra = _project_badges(who)
    try:
        disp = app.qubesd_call(dvmt.name, "admin.vm.CreateDisposable").decode(errors="replace").strip()
    except Exception as e:
        call.error_class = type(e).__name__
        # Whether qubesd made one before it raised cannot be read without its
        # name: its line is never withheld.
        call.landed = True
        raise refuse("disposable creation failed") from None
    call.landed = True
    if not core.valid_qube_name(disp):
        raise refuse("disposable creation failed")
    call.summary["name"] = disp
    # Direct admin calls from here on: qubesadmin's domain cache lags
    # CreateDisposable by seconds, so `app.domains[disp]` would raise. A
    # preloaded disposable arrives already running on its template's network,
    # which is the network it must have; it is left following that default,
    # since a disposable lives only until it halts.
    step = "network check"
    try:
        if _prop_direct(app, disp, "provides_network")[1] == "True":
            raise RuntimeError("the new qube provides network")
        step = "netvm assignment"
        if (_prop_direct(app, disp, "netvm")[1] or None) != netvm:
            app.qubesd_call(disp, "admin.vm.property.Set", "netvm",
                            ("" if netvm is None else netvm).encode())
        if (_prop_direct(app, disp, "netvm")[1] or None) != netvm:
            raise RuntimeError("netvm did not read back as set")
        step = "default_dispvm pin"
        app.qubesd_call(disp, "admin.vm.property.Set", "default_dispvm", b"")
        if _prop_direct(app, disp, "default_dispvm") != (False, ""):
            raise RuntimeError("default_dispvm did not read back as None")
        step = "label"
        restored.label_direct(app, disp)
        step = "birth stamp"
        birth.stamp(birth.TagIO.for_qubesd(app, disp), source_tags, call.caller,
                    _slot_badge(who, "DispVM"), extra)
    except Exception as e:
        call.error_class = type(e).__name__
        if _dispose(app, disp):
            raise refuse(f"{step} failed (rolled back)") from None
        raise refuse(f"{step} failed and rollback failed: qube '{disp}' needs manual cleanup in dom0") from None
    return {"ok": True, "name": disp}


# ------------------------------------------------------------------ events

def _split_tag_event(event: str):
    for base in TAG_EVENT_BASES:
        if event == base:
            return base, None
        if event.startswith(base + ":"):
            return base, event[len(base) + 1:]
    return None, None


def _event_matches(event: str, filters) -> bool:
    return any(event == f or event.startswith(f + ":") for f in filters)


def _dispatcher(app):
    import qubesadmin.events
    return qubesadmin.events.EventsDispatcher(app)


def svc_events(app, call, req, dispatcher_factory=None):
    """A bounded window of admin events whose subject is in AI space.

    The filter is a security boundary: dom0 sees every event for every qube.
    A subject that can no longer be looked up (deleted) falls back to the set
    taken when the window opened, and so does the `ai-managed` tag-delete
    event, which fires after the tag is already gone. Tag events surface only
    for the badges the hub may see; any other tag is dropped whole, event name
    included, since real tag events carry the tag in their name.
    """
    if not call.principal.is_hub():
        # Not in this release: a lead polls instead.
        raise refuse("events are not available to leads")
    duration = req.get("duration")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        raise refuse(f"duration must be a number in [{EVENTS_MIN_S}, {EVENTS_MAX_S}]")
    duration = max(EVENTS_MIN_S, min(EVENTS_MAX_S, float(duration)))
    qube = req.get("qube")
    if qube is not None and not isinstance(qube, str):
        raise refuse("qube must be a string or null")
    filters = req.get("events")
    if filters is not None:
        if (not isinstance(filters, list) or len(filters) > EVENTS_MAX_FILTERS
                or not all(isinstance(f, str) and 0 < len(f) <= EVENTS_MAX_FILTER_LEN
                           for f in filters)):
            raise refuse(f"events must be a list of at most {EVENTS_MAX_FILTERS} "
                         f"non-empty strings of at most {EVENTS_MAX_FILTER_LEN} characters")
    if qube is not None:
        core.readable(app, qube, call.principal)

    snapshot = set()
    for vm in app.domains:
        try:
            tags = core.tags_of(vm)
            if core.UMBRELLA in tags and projects.HUBBLIND not in tags:
                snapshot.add(vm.name)
        except core.Unreadable:
            pass                            # removed since the list was read, or unread: left out

    collected: list = []
    warning: list = [None]

    def include(subject_name, event, kwargs) -> bool:
        base, tag = _split_tag_event(event)
        if tag is None:
            tag = kwargs.get("tag")
        if base == "domain-tag-delete" and tag == core.UMBRELLA:
            return subject_name in snapshot
        try:
            now = set(app.domains[subject_name].tags)
            return core.UMBRELLA in now and projects.HUBBLIND not in now
        except KeyError:
            return subject_name in snapshot
        except Exception:
            return False

    def handler(subject, event, **kwargs):
        if hasattr(subject, "name"):
            subject_name = subject.name
            try:
                klass = core.klass_of(subject)
            except core.Unreadable:
                klass = core.UNREADABLE
        elif isinstance(subject, str) and subject:
            subject_name = subject
            try:
                klass = app.domains[subject].klass
            except Exception:
                klass = core.UNREADABLE
        else:
            return
        if not include(subject_name, event, kwargs):
            return
        if qube is not None and subject_name != qube:
            return
        if filters is not None and not _event_matches(event, filters):
            return
        base, tag = _split_tag_event(event)
        if base is not None:
            tag = tag if tag is not None else kwargs.get("tag")
            if tag not in scope.TAG_VOCABULARY:
                return
            event = base
        item = {"event": event, "subject": subject_name,
                "subject_klass": klass, "ts": time.time()}
        if base is not None:
            item["tag"] = tag
        collected.append(item)

    import asyncio
    dispatcher = (dispatcher_factory or _dispatcher)(app)
    dispatcher.add_handler("*", handler)

    async def listen():
        try:
            await asyncio.wait_for(dispatcher.listen_for_events(reconnect=False),
                                   timeout=duration)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        except Exception:
            warning[0] = "event stream ended early"

    try:
        asyncio.run(listen())
    except Exception:
        warning[0] = "event stream failed"
    out = {"ok": True, "events": collected}
    if warning[0] is not None:
        out["warning"] = warning[0]
    return out


# ------------------------------------------------------------------ proposals

HUB_ONLY = "proposals are the hub's: only the hub submits them and reads them"


def svc_submit_proposal(app, call, req):
    """Store a proposal for the operator. Only its shape is checked: no qube
    is looked up, so the reply says nothing about names outside AI space."""
    call.summary["type"] = _clip(req.get("type"))
    if not call.principal.is_hub():
        raise refuse(HUB_ONLY)
    try:
        proposal = proposals.normalise(req, birth.read_name_prefix())
    except proposals.Invalid as e:
        raise refuse(f"invalid proposal: {e}") from None
    if proposal.get("type") == "project-create" and not proposal.get("anonymous") \
            and _hub_mode():
        raise refuse("invalid proposal: anonymous mode: every new project is anonymous "
                     "(anonymous: true)")
    call.summary["subject"] = _clip(proposals.subject(proposal))
    try:
        pid, sha256, expires = proposals.submit(proposal, call.caller)
    except proposals.Refused as e:
        # Full, Busy, or the store's lock unavailable: fixed phrases.
        raise refuse(str(e)) from None
    except OSError as e:
        call.error_class = type(e).__name__
        raise refuse("the proposal store is unavailable") from None
    call.summary.update({"id": pid, "sha256": sha256})
    proposals.announce(pid)
    return {"ok": True, "id": pid, "sha256": sha256, "state": "pending", "expires": expires}


def svc_proposal_status(app, call, req):
    """What became of the hub's proposals: state words and its own stored
    proposal, never the command's report or a reason."""
    if not call.principal.is_hub():
        raise refuse(HUB_ONLY)
    pid = req.get("id")
    if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0):
        raise refuse("id must be a positive integer")
    try:
        view = proposals.hub_view(call.caller, pid)
    except proposals.Refused as e:
        raise refuse(str(e)) from None
    except OSError:
        raise refuse("the proposal store is unavailable") from None
    return dict({"ok": True}, **view)


# ------------------------------------------------------------------ dispatch

#: name -> (handler, state-changing)
SERVICES = {
    "qmcp.ListAIManagedQubes": (svc_list, False),
    "qmcp.GetPropertyAIManaged": (svc_get_property, False),
    "qmcp.GetPoolStats": (svc_pool_stats, False),
    "qmcp.AIManagedEvents": (svc_events, False),
    "qmcp.SetPropertyAIManaged": (svc_set_property, True),
    "qmcp.SetFeatureAIManaged": (svc_set_feature, True),
    "qmcp.LifecycleAIManaged": (svc_lifecycle, True),
    "qmcp.SpawnAIManagedQube": (svc_spawn, True),
    "qmcp.CloneAIManagedQube": (svc_clone, True),
    "qmcp.SpawnDisposableAIManaged": (svc_spawn_disposable, True),
    "qmcp.SubmitProposal": (svc_submit_proposal, True),
    "qmcp.ProposalStatus": (svc_proposal_status, False),
}


#: Fixed vocabulary: says only that dom0's audit log is out of room.
NO_AUDIT_ROOM = "refused: dom0's audit log has no room"
#: Fixed vocabulary: this caller has put its day's share of lines on the log.
NO_AUDIT_BUDGET = "refused: this caller's audit budget for today is spent"
#: Fixed vocabulary: the caller's audit counter cannot be kept (qmcp check fails).
NO_AUDIT_COUNTER = "refused: this caller's audit counter cannot be kept"


def main(service: str, stdin=None, environ=None, app_factory=None, out=None) -> int:
    call = core.Call(service)
    entry = SERVICES.get(service)
    if entry is None:
        return core.emit(call, {"ok": False, "error": "unknown service"}, audit=False, out=out)
    handler, state_changing = entry
    # Audited only once the caller is a principal and the log has room: a
    # refusal before that (no call slot, no principal, no room) changes
    # nothing, and auditing it would let anything that can make the call fill
    # the log. A principal's calls that changed nothing (refused, failed, or a
    # feature, or a property set explicitly, set to the value already there)
    # are logged up to
    # `audit.REFUSALS_PER_HOUR` in each clock hour and counted past it. A
    # failed create that made a qube, or may have (`call.landed`), is always
    # logged. A call that changed something spends the caller's day's share
    # (`audit.AUDIT_LINES_PER_DAY`), refused before it acts once spent; a kill
    # acts past it, its line then under the hourly cap. So a principal adds
    # at most its budget and its hourly cap a day, kills included.
    audited, only_done, over, kill_capped = False, False, False, False
    counter = None
    try:
        call.caller = core.caller(environ)
        # Concurrency first, before any qubesd work: the hub has its own slots,
        # and every other caller draws on the leads' shared pool as well.
        hub = core.read_hub()
        if hub is not None and call.caller == hub:
            call.fds.append(core.acquire_call_slot(call.caller))
        else:
            call.fds.append(core.acquire_call_slot(call.caller, limit=core.LEAD_CALLS))
            call.fds.append(core.acquire_call_slot(core.LEADS_POOL_KEY, limit=core.LEADS_POOL))
        # The request is read before the caller's authority is checked, so a
        # request still arriving cannot outlast the authority it was checked
        # against: a lead removed meanwhile is refused here.
        req = core.read_request(sys.stdin if stdin is None else stdin)
        app = (app_factory or _local_app)()
        call.principal = core.principal(app, call.caller, hub)
        if state_changing:
            # Nothing changes without its line: below the floor, refused first.
            # A kill only takes away, so it goes on. Not a shut-down request:
            # dom0 accepts one again while the qube is still stopping, so it
            # could be repeated without end; a kill of a halted qube is refused.
            lowers = (service == "qmcp.LifecycleAIManaged" and isinstance(req, dict)
                      and req.get("action") == "kill")
            counter = os.path.join(core.RUN_DIR, "calls",
                                   f"{call.caller}{audit_mod.REFUSED_SUFFIX}")
            # A day's share of the log per caller: past it, refused before it
            # acts, and counted rather than logged, so one principal cannot
            # spend the others' room. A kill goes on.
            # A kill acts past the budget too, since it only takes away; but
            # its line then falls under the hourly cap, so start-and-kill
            # cycles cannot bring the shared floor nearer for everyone.
            kill_capped = lowers and audit_mod.budget_spent(counter)
            left = True if lowers else audit_mod.budget_left(counter)
            if not left:
                over = True
                raise core.Refusal({"ok": False, "error": NO_AUDIT_BUDGET if left is False
                                    else NO_AUDIT_COUNTER})
            if not audit_mod.room():
                if not lowers:
                    raise core.Refusal({"ok": False, "error": NO_AUDIT_ROOM})
                # Below the floor only a kill dom0 accepted is logged: a
                # refused one changes nothing, and logging it would let a
                # principal fill the disk past the floor.
                only_done = True
            audited = True
        payload = handler(app, call, req)
    except core.Refusal as r:
        payload = r.payload
        if r.error_class:
            call.error_class = r.error_class
    except core.Unreadable:
        # A read of a qube that failed: refused, and never with the qube's name.
        call.error_class = "Unreadable"
        payload = {"ok": False, "error": "read failed"}
    except Exception as e:
        # Never the message: it can carry pool names and volume paths.
        call.error_class = type(e).__name__
        print(f"{service}: unhandled {type(e).__name__}", file=sys.stderr)
        payload = {"ok": False, "error": "internal error"}
    ok = bool(payload.get("ok"))
    log = audited and (ok or not only_done) and not over
    changed = ok and not call.noop or call.landed
    if log and (not changed or kill_capped) and call.caller is not None:
        # A call that changed nothing (failed without creating a qube, or a
        # set to the value already there): capped per caller. A shut-down
        # request dom0 accepted is logged every time, repeated or not. A qubesd
        # call that raised after its change landed is, past the cap, only
        # counted (per caller, on tmpfs): qmcp check names the caller.
        log = audit_mod.take_refusal(counter)
    elif log and counter is not None:
        audit_mod.spend(counter)        # a line of a change: against the day's budget
    rc = core.emit(call, payload, audit=log, out=out)
    for fd in call.fds:
        try:
            os.close(fd)
        except OSError:
            pass
    return rc
