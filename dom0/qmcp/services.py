"""qmcp.services — the twelve qmcp.* qrexec services.

Each one is installed in dom0 under its service name by `dom0/rpc/qmcp-service`,
which calls `main(<name>)`. Every call runs the same funnel: the caller holds
one of its concurrency slots, sends at most 64 KiB, must then be a principal
(the hub, or a lead whose badges and record agree), and gets exactly one JSON
reply. State-changing services leave one audit line.

The hub operates all of AI space. A lead operates its own project's members,
spawns only from its project's approved templates, puts new workers only on
its project's worker networks, creates only inside its project's name space
and disk quota, and has no event stream. Everything else a lead names answers
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

from qmcp import birth, budget, core, projects, proposals, scope
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
#: DispVMTemplate is here because the hub may build disposable templates.
SPAWN_KLASSES = frozenset({"AppVM", "DispVMTemplate", "DispVM"})
#: A lead builds workloads only: disposable templates are never project members.
LEAD_SPAWN_KLASSES = frozenset({"AppVM", "DispVM"})

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
#: read on a qube whose netvm is outside AI space they would describe that
#: qube, so they are redacted with it.
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


def _records():
    """The project records, for a check that needs every project (the hub's
    name space). Unreadable records refuse: the check cannot be made."""
    try:
        return projects.load()
    except projects.ProjectsUnreadable:
        raise refuse("project records unreadable") from None


def _slot_of(tags) -> str | None:
    """The slot a qube belongs to, as a list shows it: a member's, or a lead's."""
    slots = projects.member_slots(tags) | projects.lead_slots(tags)
    return next(iter(slots)) if len(slots) == 1 else None


def _create_name_refusal(name, who) -> str | None:
    """Judged on the name, the prefix and the project records alone, before
    any qube is looked up, so a create is no oracle over names. A lead creates
    only inside its project's space; the hub, inside its prefix but outside
    every project's space, so a lead collides only with its own workers or
    with a qube the operator named inside its space or moved out of it."""
    prefix = birth.read_name_prefix()
    if not who.is_hub():
        return birth.name_refusal(name, who.project.space(prefix))
    err = birth.name_refusal(name, prefix)
    if err:
        return err
    if projects.in_a_project_space(name, _records(), prefix):
        return "name is inside a project's name space"
    return None


def _slot_badge(who, new_klass: str, template_for_dispvms: bool = False, source_tags=()):
    """The slot badge a new qube wears. A lead's workloads join its project.
    The hub's AppVMs join p00; its disposables do not, since one often opens
    hostile content and in p00 it could drop files into the hub's other qubes
    without a dialog, and nor does its clone of a project's qube or a lead, for
    the same reason. Templates and disposable templates join no slot."""
    if new_klass not in ("AppVM", "DispVM") or template_for_dispvms:
        return None
    if not who.is_hub():
        return projects.member_badge(who.slot)
    tags = set(source_tags)
    if projects.member_slots(tags) - {projects.HUB_SLOT} or projects.lead_slots(tags) \
            or projects.LEAD in tags:
        return None
    return projects.member_badge(projects.HUB_SLOT) if new_klass == "AppVM" else None


def _recheck(app, call, template=None, netvm=None) -> None:
    """Under the create lock, the caller must still be what it was: a project
    command holds the same lock, so a create that waited for one must not run
    on authority it took away. A lead's template and network are checked again
    against its record as it is now."""
    who = core.principal(app, call.caller, core.read_hub())
    if who.kind != call.principal.kind or who.slot != call.principal.slot:
        raise core.Refusal(core.NOT_AUTHORIZED)
    call.principal = who
    if not who.is_hub():
        if template is not None and template not in who.project.templates:
            raise refuse("template is not on this project's approved list")
        if netvm is not None and netvm not in who.project.named_networks():
            raise refuse("netvm must be one of this project's worker networks")


# ------------------------------------------------------------------ reads

def svc_list(app, call, req):
    who = call.principal
    out = []
    for vm in app.domains:
        if not core.visible(vm, who):
            continue
        try:
            power = vm.get_power_state()
        except Exception:
            power = "unknown"
        try:
            label = vm.label.name if vm.label else None
        except Exception:
            label = None
        try:
            template = getattr(vm, "template", None)
        except Exception:
            template = None
        tags = core.tags_of(vm)
        out.append({
            "name": vm.name,
            "klass": vm.klass,
            "label": label,
            "template": scope.scoped_name(app, template, who),
            "power_state": power,
            "guarded": core.is_guarded(vm),
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
        try:
            netvm = getattr(vm, "netvm", None)
        except Exception:
            netvm = None
        if netvm is not None and scope.scoped_name(app, netvm, who) == scope.OUT_OF_SCOPE:
            return {"ok": True, "value": scope.OUT_OF_SCOPE}
    try:
        value = getattr(vm, prop)
    except AttributeError:
        raise refuse(f"property '{prop}' does not exist") from None
    value = scope.scoped_value(app, value, who)
    if not isinstance(value, (str, int, float, bool, list, type(None))):
        raise refuse("property not readable")
    return {"ok": True, "value": value}


def svc_pool_stats(app, call, req):
    """The caller's disk budget: AI space against the fleet cap for the hub; the
    project's members against its quota for a lead, with the project's name
    space, approved templates, worker networks and dump sink. A lead never
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
           "name_prefix": prefix}
    if who.is_hub():
        out["projects"] = _project_rows(app)
    else:
        p = who.project
        out.update({"project": p.label, "name_prefix": p.space(prefix),
                    "templates": list(p.templates), "networks": list(p.networks),
                    "dump": p.dump})
    return out


def _project_rows(app):
    """Every project's record as the hub may read it, so it can propose an edit
    that fits. A name in a record that is no longer in AI space (a template
    the operator took out, say) reads `<out-of-scope>`, as every read redacts
    one; the dump sink is outside AI space, so only whether there is one is
    told. One pass over the qubes gives both the names in scope and each
    slot's disk use; a slot's use that cannot be read is null, never zero, and
    records that cannot be read are null, never an empty list."""
    try:
        records = projects.load()
    except projects.ProjectsUnreadable:
        return None
    in_scope, used, unreadable = set(), {}, set()
    for vm in app.domains:
        try:
            tags = set(vm.tags)
        except Exception:
            continue
        if core.UMBRELLA not in tags:
            continue
        in_scope.add(vm.name)
        for slot in projects.member_slots(tags):
            try:
                used[slot] = used.get(slot, 0) + budget.persistent_bytes(vm)
            except Exception:
                unreadable.add(slot)
    shown = lambda name: name if name is None or name in in_scope else scope.OUT_OF_SCOPE  # noqa: E731
    out = []
    for slot, p in sorted(records.items()):
        out.append({"slot": slot, "label": p.label, "lead": shown(p.lead),
                    "templates": [shown(t) for t in p.templates],
                    "networks": [shown(n) for n in p.networks], "quota": p.quota,
                    "used": None if slot in unreadable else used.get(slot, 0),
                    "has_dump": p.dump is not None})
    return out


# ------------------------------------------------------------------ writes

def svc_set_property(app, call, req):
    name, prop = _string(req, "name"), _string(req, "property")
    call.summary.update({"name": _clip(name), "property": _clip(prop)})
    vm = core.operand(app, name, call.principal)
    if prop not in SETTABLE_PROPS:
        raise refuse("property not settable")
    if "value" not in req:
        raise refuse("value is required")
    value = req["value"]
    if prop == "label":
        if value not in LABELS:
            raise refuse(f"label must be one of: {sorted(LABELS)}")
    elif prop == "netvm":
        if value is not None:
            raise refuse("netvm change is operator-only; null (disconnect) is permitted")
    elif isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        # bool is an int subclass, so `True` must be refused explicitly.
        raise refuse(f"{prop} must be a positive integer")
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
    vm = core.operand(app, name, call.principal)
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
        vm.features[feature] = text
    except Exception as e:
        call.error_class = type(e).__name__
        raise refuse("feature.Set failed") from None
    try:
        readback = vm.features.get(feature, None)
    except Exception:
        readback = None
    return {"ok": True, "feature": feature, "value": readback}


def svc_lifecycle(app, call, req):
    name, action = _string(req, "name"), _string(req, "action")
    call.summary.update({"name": _clip(name), "action": _clip(action)})
    if action not in LIFECYCLE_ACTIONS:
        raise refuse(f"action must be one of: {sorted(LIFECYCLE_ACTIONS)}")
    vm = core.operand(app, name, call.principal)
    # A lead is a project's identity: removing one takes the operator's approval.
    if action == "remove" and projects.LEAD in core.tags_of(vm):
        raise refuse("removing a lead takes the operator's approval")
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
    so nothing is removed: qubesd rolls back a failed admin.vm.Create itself,
    and clone_vm removes its own partial clone. Deleting by name here could
    take a qube someone else created under that name in the meantime."""
    call.error_class = type(exc).__name__
    if _exists(app, name):
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
    Requests are judged against the list, which the lead knows, before any
    lookup. After birth a network can only be cleared, never moved."""
    named = project.named_networks()
    specified = "netvm" in req
    requested = req.get("netvm")
    if specified and requested is not None and not isinstance(requested, str):
        raise refuse("netvm must be a qube name or null")
    if authoritative:
        try:
            src = _name_of(getattr(source_vm, "netvm", None))
        except Exception:
            raise refuse("birth egress could not be resolved") from None
        if src is not None and src not in named:
            raise refuse("the source's network is not one of this project's worker networks")
        if specified:
            if requested is None:
                return None
            if requested != src:
                raise refuse("netvm must match the inherited birth egress")
        if src is not None and not core.in_ai_space_by_name(app, src):
            raise refuse("birth egress could not be resolved")
        return src
    if specified:
        if requested is None:
            return None
        if requested not in named:
            raise refuse("netvm must be one of this project's worker networks")
        if not core.in_ai_space_by_name(app, requested):
            raise refuse("netvm must reference an ai-managed qube")
        return requested
    default = project.networks[0]
    if default is not None and not core.in_ai_space_by_name(app, default):
        raise refuse("birth egress could not be resolved")
    return default


def _birth_netvm(app, call, req, source_vm, authoritative: bool):
    """The netvm a create must use (the birth chain in birth.py), honouring an explicit
    `netvm` in the request: null is always allowed (offline cannot leak); a
    name must be in AI space AND equal the inherited answer. The explicit name
    is checked by name, in one round trip either way, so it is no oracle."""
    if not call.principal.is_hub():
        return _lead_netvm(app, req, call.principal.project, source_vm, authoritative)
    specified = "netvm" in req
    requested = req.get("netvm")
    if specified and requested is not None and not isinstance(requested, str):
        raise refuse("netvm must be a qube name or null")
    resolved, rule = birth.resolve_egress(app, core.lookup(app, call.caller),
                                          source_vm, authoritative)
    if specified:
        if requested is None:
            return None
        if not core.in_ai_space_by_name(app, requested):
            raise refuse("netvm must reference an ai-managed qube")
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
    if _name_of(getattr(vm, "netvm", None)) != netvm or vm.property_is_default("netvm"):
        raise RuntimeError("netvm did not read back as set")


def _pin_default_dispvm(vm) -> None:
    """No default disposable template: Qubes' raw @dispvm shortcut from this
    qube then has nowhere to go, even if it later leaves AI space."""
    vm.default_dispvm = None
    if getattr(vm, "default_dispvm", None) is not None or vm.property_is_default("default_dispvm"):
        raise RuntimeError("default_dispvm did not read back as None")


def _estimate(fn, *args) -> int:
    try:
        return fn(*args)
    except Exception as e:
        raise core.Refusal({"ok": False, "error": budget.ERR_STATS_UNAVAILABLE},
                           error_class=type(e).__name__) from None


def _check_budget(app, call, estimate: int) -> None:
    """Under the create lock: a lead's project quota first, so a request over
    its quota never reaches the fleet cap, then the fleet cap."""
    who = call.principal
    if not who.is_hub():
        budget.check_quota(app, projects.member_badge(who.slot), who.project.quota, estimate)
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
    if klass not in klasses:
        raise refuse(f"klass must be one of: {sorted(klasses)}")
    if label not in LABELS:
        raise refuse(f"label must be one of: {sorted(LABELS)}")
    private_size = _private_size(req)
    tpl = core.reference(app, template, "template", who)
    if klass in ("AppVM", "DispVMTemplate"):
        if tpl.klass != "TemplateVM":
            raise refuse(f"template '{template}' must be a TemplateVM for klass={klass}")
    elif not getattr(tpl, "template_for_dispvms", False):
        raise refuse(f"template '{template}' must be a disposable template for klass=DispVM")
    _not_a_gateway(tpl, "template")
    _claim_name(app, call, name)
    netvm = _birth_netvm(app, call, req, tpl, authoritative=(klass == "DispVM"))

    budget.check_private_size(private_size)
    call.fds.append(budget.acquire_create_lock())
    _recheck(app, call, template=template, netvm=netvm)
    _claim_name(app, call, name)
    _check_budget(app, call, budget.estimate_new_private(private_size))

    create_klass = "AppVM" if klass == "DispVMTemplate" else klass
    try:
        vm = app.add_new_vm(create_klass, name, label, template=template)
    except Exception as e:
        raise _create_failed(app, call, name, "create", e)
    step = "birth stamp"
    try:
        birth.stamp(birth.TagIO.for_vm(vm), core.tags_of(tpl), call.caller,
                    _slot_badge(who, create_klass, klass == "DispVMTemplate"))
        if klass == "DispVMTemplate":
            step = "disposable template flag"
            vm.template_for_dispvms = True
            if not getattr(vm, "template_for_dispvms", False):
                raise RuntimeError("template_for_dispvms did not read back")
        step = "network check"
        if core.is_gateway(vm):
            raise RuntimeError("the new qube provides network")
        step = "netvm assignment"
        _set_netvm(vm, netvm)
        step = "default_dispvm pin"
        _pin_default_dispvm(vm)
    except Exception as e:
        raise _rollback(app, call, name, step, e)
    if private_size is not None:
        try:
            vm.volumes["private"].resize(private_size)
        except Exception as e:
            call.error_class = type(e).__name__
            return {"ok": True, "name": name, "warning": "private_resize_failed"}
    return {"ok": True, "name": name}


def svc_clone(app, call, req):
    source, name = req.get("source"), req.get("name")
    call.summary.update({"source": _clip(source), "name": _clip(name)})
    who = call.principal
    err = _create_name_refusal(name, who)
    if err:
        raise refuse(err)
    if not isinstance(source, str):
        raise core.Refusal(core.NOT_FOUND)
    # The source must be managed: a clone is a managed, editable copy of
    # everything in it, which a guarded qube must never become. A guarded
    # qube may still be spawned FROM; see the residuals in CLAUDE.md for what a
    # spawn carries over. The hub may clone a template it manages.
    src = core.operand(app, source, who)
    src_is_template = src.klass == "TemplateVM" or bool(getattr(src, "template_for_dispvms", False))
    if src_is_template and not who.is_hub():
        # Templates and disposable templates are never project members.
        raise core.Refusal(core.NOT_FOUND)
    _claim_name(app, call, name)
    # A clone is the same kind of qube as its source, so the source always
    # answers for its own network — a cloned template stays off the network.
    netvm = _birth_netvm(app, call, {}, src, authoritative=True)

    call.fds.append(budget.acquire_create_lock())
    _recheck(app, call, netvm=netvm)
    _claim_name(app, call, name)
    _check_budget(app, call, _estimate(budget.persistent_bytes, src))

    source_tags = core.tags_of(src)
    try:
        vm = app.clone_vm(src, name)
    except Exception as e:
        raise _create_failed(app, call, name, "clone", e)
    step = "birth stamp"
    try:
        birth.stamp(birth.TagIO.for_vm(vm), source_tags, call.caller,
                    _slot_badge(who, src.klass, src_is_template, source_tags))
        step = "network check"
        if core.is_gateway(vm):
            raise RuntimeError("the new qube provides network")
        step = "netvm assignment"
        _set_netvm(vm, netvm)
        step = "default_dispvm pin"
        _pin_default_dispvm(vm)
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


def svc_spawn_disposable(app, call, req):
    template = req.get("template")
    call.summary.update({"template": _clip(template)})
    who = call.principal
    dvmt = core.reference(app, template, "template", who)
    if not getattr(dvmt, "template_for_dispvms", False):
        raise refuse(f"template '{template}' must be a disposable template")
    _not_a_gateway(dvmt, "disposable template")
    netvm = _birth_netvm(app, call, {}, dvmt, authoritative=True)

    call.fds.append(budget.acquire_create_lock())
    _recheck(app, call, template=template, netvm=netvm)
    _check_budget(app, call, budget.estimate_new_private(_estimate(budget._vol_size, dvmt, "private")))

    source_tags = core.tags_of(dvmt)
    try:
        disp = app.qubesd_call(dvmt.name, "admin.vm.CreateDisposable").decode(errors="replace").strip()
    except Exception as e:
        call.error_class = type(e).__name__
        raise refuse("disposable creation failed") from None
    if not core.valid_qube_name(disp):
        raise refuse("disposable creation failed")
    call.summary["name"] = disp
    # Direct admin calls from here on: qubesadmin's domain cache lags
    # CreateDisposable by seconds, so `app.domains[disp]` would raise. A
    # preloaded disposable arrives already running on its template's network,
    # which is the network it must have; it is left following that default,
    # since a disposable lives only until it halts.
    step = "birth stamp"
    try:
        birth.stamp(birth.TagIO.for_qubesd(app, disp), source_tags, call.caller,
                    _slot_badge(who, "DispVM"))
        step = "network check"
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
        if core.in_scope(vm):
            snapshot.add(vm.name)

    collected: list = []
    warning: list = [None]

    def include(subject_name, event, kwargs) -> bool:
        base, tag = _split_tag_event(event)
        if tag is None:
            tag = kwargs.get("tag")
        if base == "domain-tag-delete" and tag == core.UMBRELLA:
            return subject_name in snapshot
        try:
            return core.UMBRELLA in set(app.domains[subject_name].tags)
        except KeyError:
            return subject_name in snapshot
        except Exception:
            return False

    def handler(subject, event, **kwargs):
        if hasattr(subject, "name"):
            subject_name, klass = subject.name, getattr(subject, "klass", None)
        elif isinstance(subject, str) and subject:
            subject_name = subject
            try:
                klass = app.domains[subject].klass
            except Exception:
                klass = None
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


def main(service: str, stdin=None, environ=None, app_factory=None, out=None) -> int:
    call = core.Call(service)
    entry = SERVICES.get(service)
    if entry is None:
        return core.emit(call, {"ok": False, "error": "unknown service"}, audit=False, out=out)
    handler, state_changing = entry
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
        payload = handler(app, call, req)
    except core.Refusal as r:
        payload = r.payload
        if r.error_class:
            call.error_class = r.error_class
    except Exception as e:
        # Never the message: it can carry pool names and volume paths.
        call.error_class = type(e).__name__
        print(f"{service}: unhandled {type(e).__name__}", file=sys.stderr)
        payload = {"ok": False, "error": "internal error"}
    rc = core.emit(call, payload, audit=state_changing, out=out)
    for fd in call.fds:
        try:
            os.close(fd)
        except OSError:
            pass
    return rc
