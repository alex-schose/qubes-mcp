"""qmcp.anon — the anonymity gate.

An anonymous project (`anonymous` in its record, `qmcp-anon` on its lead and
every member) stays anonymous only while dom0 verifies, for each one:

1. **networks.** Every network on its worker list, and its lead's, is an
   enrolled gateway marked anonymising, or none; and each such gateway still
   sits on the network recorded when it was marked (`gateways.Gateway.upstream`),
   so a Tor router re-pointed at clearnet is caught. Every member is on one of
   the listed networks, or on none, and dom0's policy gives none of them, nor
   the lead, `qubes.UpdatesProxy`: an HTTP proxy around their router.
2. **model.** A remote endpoint needs nothing more. A self-hosted model qube
   has no network, serves this project alone, is guarded, and dom0's policy
   denies it `qubes.UpdatesProxy` (a qube wearing Whonix's `whonix-updatevm`
   tag is given the proxy even as an AppVM).
3. **templates.** Every template its qubes come from (the approved list, and
   the chains of its lead, members and model qube) is outside AI space or
   guarded. A TemplateVM has no network of its own, and dom0's policy sends its
   `qubes.UpdatesProxy` to the recorded upstream of an enrolled anonymising
   gateway the operator ticked for updates, or denies it: `sys-whonix` above a Tor
   router, never a qube further up the chain, where `sys-net` would count. A disposable template's network, which
   its disposables use, is one of the project's networks, or none; a hidden
   project's disposable template wears `qmcp-hubblind`, since every disposable
   is born with its template's tags.
4. **badges.** Every qube wearing the project's member or lead badge, which the
   rulebook routes on, is in AI space and wears the project's badges: a member
   of a hidden project without `qmcp-hubblind` is open to the hub, and one
   outside AI space would escape the rest of the gate. A hidden project's
   model qube wears `qmcp-hubblind` too.

**In anonymous mode** (`/etc/qmcp/mode`, from `install.sh --anonymous`) the
hub is judged too, as one more subject: the hub qube itself, and every qube in
AI space (or wearing p00's badge) that is not an anonymous project's lead,
member or model qube, guarded routers aside: its own qubes in p00, the
templates, disposable templates and disposables it made, which join no slot,
and anything else in AI space. Each wears `qmcp-anon`; each that is not a
TemplateVM is on an enrolled anonymising gateway still on its recorded
network, or on none, and is not given `qubes.UpdatesProxy`; each TemplateVM
it judges or that a subject comes from has no network of its own and updates
only through a ticked upstream (a managed one is the hub's own and may stay
managed); a disposable template a subject comes from is on an anonymising
gateway still on its recorded network, or on none. The hub's
own templates update through Qubes' update proxy, not the hub's network, so
this is where "updates over Tor" is checked for them. A violation by the hub
qube or a p00 qube stops the hub and every p00 qube with it; one by any other
subject stops that qube alone: the block refuses the hub every use of it, a
call into it, a start, a clone, and a create from it. A mode file that cannot be read blocks the hub and p00 without a kill, as
a read that failed twice does.

Where it runs: `qmcp gate` (a systemd timer runs it every 15 seconds, and once
shortly after boot), `qmcp check`, and the end of every `qmcp` command that changes qubes, projects or gateways
(and `proposal accept`). One run at a time; each completed run of the timer's leaves
a heartbeat, which `qmcp check` requires to be recent.

**On a confirmed violation** every lead and member is badged `qmcp-blocked`
first, the lead before the rest (the rulebook refuses every call into a blocked
qube, so qrexec cannot wake one, and the services refuse to start, change or
clone one); then each one not yet stopped is killed if it may be running, and badged
`qmcp-stopped` once it is known to be down; then their `autostart` is turned
off. Nothing is removed. One audit line says what was done, and the operator
is told: by a desktop notification from the timer's run, or by a line on the
command's output when a `qmcp` command's own run acted (a root process cannot
reach the desktop). A run that changes nothing and repeats no failed step
says nothing; one that repeats a failed step (a kill, a badge) says so again. A qube already stopped (`qmcp-stopped`) is not killed again: only the
operator can start one, by hand, to look at it. **A read the gate cannot
complete** is tried once more; a second failure blocks the project without
killing it, and a later confirmed violation still kills it. Only `qmcp project
unblock`, after a fresh run finds the project sound, takes the badges off;
`autostart` stays off.

The gate cannot stop a packet that leaves before it runs: a condition breaks by
the operator's own change, judged right after a `qmcp` command and within about
15 seconds of one made outside qmcp, and the kill stops what follows. Asking "where do this qube's updates go" uses qrexec's own policy
parser over the policy directory and qubesd's system information, as the
policy daemon does (its own evaluation service answers allow or deny, never
the target). Both work for the services' non-root dom0 user.
"""
from __future__ import annotations

import fcntl
import os
import time

from qmcp import audit, core, gateways, projects

POLICY_DIR = "/etc/qubes/policy.d"
POLICY_RUN_DIR = "/run/qubes/policy.d"
LOCK_PATH = "/run/qmcp/gate.lock"
#: Written at the end of every completed run of the timer's; `qmcp check`
#: requires it recent. Only the timer's runs write it (its unit sets HEARTBEAT_ENV),
#: so a check or a window refresh, which run the gate too, cannot hide a timer
#: that stopped.
HEARTBEAT_PATH = "/run/qmcp/gate.last"
HEARTBEAT_ENV = "QMCP_GATE_HEARTBEAT"
#: How old the heartbeat may be while an anonymous project exists (four timer runs).
HEARTBEAT_MAX_S = 60
#: How long a run waits for another to finish before leaving the work to it.
LOCK_WAIT_S = 10.0
#: How long a run waits before reading a project again after a read failed.
RETRY_WAIT_S = 1.0
UPDATES = "qubes.UpdatesProxy"
#: The audit line's service, and the caller it names.
SERVICE = "qmcp gate"
CALLER = "gate"
#: What the hub's verdict is named by, where a project's label would be.
HUB_LABEL = "the hub"

GREEN, RED, UNREADABLE = "green", "red", "unreadable"
CONDITIONS = ("networks", "model", "templates", "badges")
#: How a condition is named where the operator reads it.
CONDITION_WORDS = {"networks": "its networks", "model": "its model", "templates": "its templates",
                   "badges": "its badges", "read": "a read that failed twice"}
NOTICE = "qubes-mcp stopped the anonymous project {label} ({slot}): {why}."
NOTICE_HUB = "qubes-mcp stopped {who} (anonymous mode): {why}."

TIMER = "qmcp-gate.timer"
#: Tests replace this: whether the timer runs (None when that cannot be told).
TIMER_CHECK = None


def timer_active():
    """Whether systemd runs the gate's timer: True, False, or None when that
    cannot be told (no systemctl)."""
    if TIMER_CHECK is not None:
        return TIMER_CHECK()
    import subprocess
    try:
        done = subprocess.run(["systemctl", "is-active", "--quiet", TIMER],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.returncode == 0


def heartbeat_age(path: str | None = None):
    """Seconds since the last completed run, or None when there is no heartbeat."""
    try:
        return time.time() - os.stat(HEARTBEAT_PATH if path is None else path).st_mtime
    except OSError:
        return None


class PolicyUnreadable(Exception):
    """The policy or qubesd's system information could not be loaded."""


class HubSubject:
    """The hub's check in anonymous mode, where a verdict names a project."""
    slot, label, hidden, anonymous = projects.HUB_SLOT, HUB_LABEL, False, True


HUB = HubSubject()


class Verdict:
    """One anonymous project's result, or the hub's (`slot` p00, `label` the
    hub): `status` is green, red or unreadable, `problems` (condition, detail)
    pairs, `names` the qubes judged as this run read them, `blocked` whether
    all of a project's (any of the hub's) already wear `qmcp-blocked`,
    `offenders` the hub's qubes in violation, `acted` what this run did."""

    __slots__ = ("slot", "label", "hidden", "status", "problems", "blocked", "acted", "names",
                 "offenders", "p00")

    def __init__(self, p) -> None:
        self.slot, self.label, self.hidden = p.slot, p.label, p.hidden
        self.status, self.problems, self.blocked, self.acted = GREEN, [], False, []
        self.names, self.offenders, self.p00 = [], [], []

    @property
    def is_hub(self) -> bool:
        return self.label == HUB_LABEL and self.slot == projects.HUB_SLOT

    def fail(self, condition: str, detail: str, offender: str | None = None) -> None:
        assert condition in CONDITIONS
        self.status = RED
        if (condition, detail) not in self.problems:     # a router the lead sits on is listed too
            self.problems.append((condition, detail))
        if offender is not None and offender not in self.offenders:
            self.offenders.append(offender)

    def conditions(self) -> list:
        return sorted({c for c, _ in self.problems}, key=lambda c: (CONDITIONS + ("read",)).index(c))

    def to_json(self) -> dict:
        out = {"slot": self.slot, "label": self.label, "hidden": self.hidden,
               "status": self.status, "blocked": self.blocked,
               "problems": [{"condition": c, "detail": d} for c, d in self.problems],
               "acted": list(self.acted)}
        if self.is_hub:
            out.update(hub=True, offenders=list(self.offenders))
        return out


# ======================================================================= the policy question

def load_policy():
    """(policy, system information), as the policy daemon sees them. Raises
    PolicyUnreadable. qrexec's parser warns about transitional directives on
    every load; that warning is silenced, or a run every 15 seconds would
    write it to the journal four times a minute."""
    import logging
    import pathlib
    try:
        import qrexec.utils
        from qrexec.policy.parser import FilePolicy
    except ImportError:
        raise PolicyUnreadable("python3-qrexec is not importable") from None
    logging.disable(logging.WARNING)
    try:
        dirs = [pathlib.Path(d) for d in (POLICY_RUN_DIR, POLICY_DIR) if os.path.isdir(d)]
        policy = FilePolicy(policy_path=dirs)
        info = qrexec.utils.get_system_info()
    except Exception as e:
        raise PolicyUnreadable(f"the policy or qubesd's system information ({type(e).__name__})") \
            from None
    finally:
        logging.disable(logging.NOTSET)
    return policy, info


def update_target(policy, info, name: str):
    """Where dom0's policy sends `name`'s qubes.UpdatesProxy: the target's name,
    `@ask` when a dialog would decide, or None when it is denied. Raises
    PolicyUnreadable when it cannot tell.

    Asked as if the qube wore neither `qmcp-blocked` nor `qmcp-stopped`: the
    rulebook denies a blocked qube every call, its updates included, so asked
    as it is, a qube the gate stopped would read sound with its cause still in
    place, and an unblock would pass only for the next run to stop it again.
    The question is where its updates go once the stop is cleared."""
    from qrexec.exc import AccessDenied
    from qrexec.policy.parser import Request
    if name not in info.get("domains", {}):
        raise PolicyUnreadable(f"qubesd's system information has no {name}")
    tags = info["domains"][name].get("tags") or []
    if projects.BLOCKED in tags or projects.STOPPED in tags:
        domains = dict(info["domains"])
        domains[name] = dict(domains[name], tags=[t for t in tags if t not in
                                                  (projects.BLOCKED, projects.STOPPED)])
        info = dict(info, domains=domains)
    try:
        req = Request(UPDATES, "+", name, "@default", system_info=info)
        rule = policy.find_matching_rule(req)
        resolution = rule.action.evaluate(req)
    except AccessDenied:
        return None
    except Exception as e:
        raise PolicyUnreadable(f"the update policy for {name} ({type(e).__name__})") from None
    if type(resolution).__name__.lower().startswith("ask"):
        # A dialog decides: an anonymous project never rests on a click.
        return "@ask"
    target = getattr(resolution, "target", None)
    return None if target is None else str(target)


# ======================================================================= one project

def update_upstreams(registry: dict) -> set:
    """Where a template's updates may go: the recorded upstream of an enrolled
    anonymising gateway that the operator ticked for updates (`updates`). The
    qube above a VPN qube enrolled with no router in front is a clearnet one,
    and only the operator can tell the two apart."""
    return {g.upstream for g in registry.values() if g.anonymising and g.upstream and g.updates}


def _updates_detail(t: str, target: str, registry: dict) -> str:
    unticked = sorted(g.name for g in registry.values()
                      if g.anonymising and g.upstream == target and not g.updates)
    if unticked:
        return (f"dom0's policy sends {t}'s updates to {target}, the recorded upstream of "
                f"{', '.join(unticked)}, which is not ticked for updates (qmcp gateway set "
                f"{unticked[0]} --updates yes, if {target} itself is anonymous)")
    return (f"dom0's policy sends {t}'s updates to {target}, which is not the recorded "
            f"upstream of an anonymising gateway ticked for updates")


def _member_qubes(p, tags_by: dict) -> list:
    """Every qube wearing the project's member or lead badge, in AI space or
    not: the rulebook routes on those badges, so the gate judges every qube
    that wears one. The lead first."""
    slot_badges = {projects.member_badge(p.slot), projects.lead_badge(p.slot)}
    names = sorted(n for n, tags in tags_by.items() if tags & slot_badges)
    return sorted(names, key=lambda n: (projects.lead_badge(p.slot) not in tags_by[n], n))


def _chain(vm) -> list:
    """The templates a qube's system comes from, nearest first. Raises
    `core.Unreadable`."""
    chain, seen = [], set()
    ref = core.template_of(vm)
    while ref is not None and ref.name not in seen:
        seen.add(ref.name)
        chain.append(ref)
        ref = core.template_of(ref)
    return chain


def evaluate(app, p, registry: dict, policy_view, by_name: dict, tags_by: dict) -> Verdict:
    """Judge one anonymous project. Raises `core.Unreadable` or
    PolicyUnreadable when a read it needs fails: never a verdict of green over
    a read it could not make."""
    v = Verdict(p)
    names = v.names = _member_qubes(p, tags_by)
    v.blocked = bool(names) and all(projects.BLOCKED in tags_by[n] for n in names)
    anonymising = {n: g for n, g in registry.items() if g.anonymising}
    upstreams = update_upstreams(registry)
    listed = set(p.named_networks())
    policy, info = policy_view

    # 1. networks
    def router_ok(net: str, who: str) -> None:
        g = anonymising.get(net)
        if g is None:
            v.fail("networks", f"{who} is on {net}, which is not an enrolled anonymising gateway")
            return
        if g.upstream is None:
            v.fail("networks", f"{net} has no recorded network; mark it again (qmcp gateway set "
                               f"{net} --anonymising yes)")
            return
        vm = by_name.get(net)
        now = None if vm is None else core.netvm_of(vm)
        if now != g.upstream:
            v.fail("networks", f"{net} is on {now or 'no network'}, not on {g.upstream} as "
                               f"recorded")
    for net in sorted(listed):
        router_ok(net, "the worker list")
    for name in names:
        net = core.netvm_of(by_name[name])
        if net is not None:
            if projects.lead_badge(p.slot) in tags_by[name]:
                router_ok(net, f"the lead {name}")
            elif net not in listed:
                v.fail("networks", f"the member {name} is on {net}, which the project does not "
                                   f"list")
        target = update_target(policy, info, name)
        if target is not None:
            v.fail("networks", f"dom0's policy gives {name} the update proxy ({target}), a way "
                               f"around its router")

    # 4. badges, read once with the rest
    want = p.badges() | {core.UMBRELLA}
    for name in names:
        missing = want - tags_by[name]
        if missing:
            v.fail("badges", f"{name} does not wear {', '.join(sorted(missing))}")

    # 2. model
    chain_of = list(names)
    if p.model_qube is not None:
        mq = by_name.get(p.model_qube)
        if mq is None:
            v.fail("model", f"the model qube {p.model_qube} does not exist")
        else:
            chain_of.append(p.model_qube)
            mtags = tags_by[p.model_qube]
            if core.netvm_of(mq) is not None:
                v.fail("model", f"the model qube {p.model_qube} has a network")
            if core.GUARDED not in mtags:
                v.fail("model", f"the model qube {p.model_qube} is not guarded: the hub could "
                                f"read its stored conversations")
            if projects.model_slots(mtags) != {p.slot}:
                v.fail("model", f"the model qube {p.model_qube} serves "
                                f"{', '.join(sorted(projects.model_slots(mtags))) or 'no slot'}, "
                                f"not {p.slot} alone")
            if p.hidden and projects.HUBBLIND not in mtags:
                v.fail("badges", f"the model qube {p.model_qube} does not wear "
                                 f"{projects.HUBBLIND}")
            target = update_target(policy, info, p.model_qube)
            if target is not None:
                v.fail("model", f"dom0's policy gives the model qube {p.model_qube} the update "
                                f"proxy ({target})")

    # 3. templates
    templates = {}
    for t in p.templates:
        vm = by_name.get(t)
        if vm is None:
            v.fail("templates", f"the approved template {t} does not exist")
        else:
            templates[t] = vm
    for name in chain_of:
        for ref in _chain(by_name[name]):
            templates.setdefault(ref.name, by_name.get(ref.name, ref))
    for t, vm in sorted(templates.items()):
        tags = tags_by.get(t)
        if tags is None:
            raise core.Unreadable(f"cannot read the tags of {t}")
        if core.UMBRELLA in tags and core.GUARDED not in tags:
            v.fail("templates", f"{t} is managed: the hub can change it")
        klass = core.klass_of(vm)
        net = core.netvm_of(vm)
        if klass == "TemplateVM":
            if net is not None:
                v.fail("templates", f"{t} has a network of its own ({net}): it reaches the "
                                    f"internet around the update proxy")
            target = update_target(policy, info, t)
            if target is not None and target not in upstreams:
                v.fail("templates", _updates_detail(t, target, registry))
        elif core.is_dvmt(vm):
            if net is not None and net not in listed:
                v.fail("templates", f"the disposable template {t} is on {net}, which the "
                                    f"project does not list")
            if p.hidden and projects.HUBBLIND not in tags:
                v.fail("templates", f"the disposable template {t} does not wear "
                                    f"{projects.HUBBLIND}: its disposables would be born in "
                                    f"the hub's view")
    return v


# ======================================================================= the hub, in anonymous mode

def p00_qubes(tags_by: dict) -> list:
    """Every qube wearing p00's member badge, in AI space or not."""
    badge = projects.member_badge(projects.HUB_SLOT)
    return sorted(n for n, tags in tags_by.items() if badge in tags)


def hub_candidates(hub: str, records: dict, registry: dict, tags_by: dict) -> list:
    """The hub, then every qube in AI space or in p00 that no anonymous project
    judges (its lead, members and model qube). `hub_subjects` leaves out a
    guarded router among them."""
    owned = set()
    for p in records.values():
        if p.anonymous and p.slot != projects.HUB_SLOT:
            owned.update(_member_qubes(p, tags_by))
            if p.model_qube:
                owned.add(p.model_qube)
    p00 = set(p00_qubes(tags_by))
    names = sorted(n for n, tags in tags_by.items()
                   if (core.UMBRELLA in tags or n in p00) and n not in owned and n != hub)
    return [hub] + names


def hub_subjects(hub: str, records: dict, registry: dict, by_name: dict, tags_by: dict) -> list:
    """What the hub's check judges in anonymous mode, and what wears
    `qmcp-anon` because of it: `hub_candidates` but a guarded qube that
    provides network or is an enrolled gateway (a router kept in AI space),
    which nothing in AI space operates. An unguarded one stays: the rulebook
    cannot see `provides_network`, so the hub may run commands in it. Raises
    `core.Unreadable`."""
    out = []
    for name in hub_candidates(hub, records, registry, tags_by):
        vm = by_name[name]
        if name != hub and core.GUARDED in tags_by[name] and (
                name in registry
                or (core.klass_of(vm) != "TemplateVM" and core.is_gateway(vm))):
            continue
        out.append(name)
    return out


def evaluate_hub(app, hub, records: dict, registry: dict, policy_view, by_name: dict,
                 tags_by: dict) -> Verdict:
    """Judge the hub in anonymous mode. Raises `core.Unreadable` or
    PolicyUnreadable when a read it needs fails."""
    v = Verdict(HUB)
    if hub is None:
        raise core.Unreadable(f"{core.HUB_PATH} names no hub")
    if hub not in by_name or hub not in tags_by:
        raise core.Unreadable(f"the hub {hub} cannot be read")
    anonymising = {n: g for n, g in registry.items() if g.anonymising}
    upstreams = update_upstreams(registry)
    policy, info = policy_view
    names = v.names = hub_subjects(hub, records, registry, by_name, tags_by)
    v.p00 = [n for n in names if n != hub and n in set(p00_qubes(tags_by))]
    v.blocked = any(projects.BLOCKED in tags_by[n] for n in names)
    subjects = set(names)
    judged_templates: dict = {}

    def who(name):
        return f"the hub {name}" if name == hub else name

    def router_ok(net: str, name: str) -> None:
        g = anonymising.get(net)
        if g is None:
            v.fail("networks", f"{who(name)} is on {net}, which is not an enrolled anonymising "
                               f"gateway", name)
        elif g.upstream is None:
            v.fail("networks", f"{net} has no recorded network; mark it again (qmcp gateway set "
                               f"{net} --anonymising yes)", name)
        else:
            gw = by_name.get(net)
            now = None if gw is None else core.netvm_of(gw)
            if now != g.upstream:
                v.fail("networks", f"{net} is on {now or 'no network'}, not on {g.upstream} as "
                                   f"recorded", name)

    def template_problems(t: str, tvm) -> list:
        """What is wrong with a TemplateVM a subject's system comes from (or
        that is one), judged once per run: a network of its own, or updates
        sent anywhere but a ticked upstream."""
        if t not in judged_templates:
            found = []
            net = core.netvm_of(tvm)
            if net is not None:
                found.append(f"{t} has a network of its own ({net}): it reaches the internet "
                             f"around the update proxy")
            target = update_target(policy, info, t)
            if target is not None and target not in upstreams:
                found.append(_updates_detail(t, target, registry))
            judged_templates[t] = found
        return judged_templates[t]

    for name in names:
        vm, tags = by_name[name], tags_by[name]
        if projects.ANON not in tags:
            v.fail("badges", f"{who(name)} does not wear {projects.ANON}", name)
        if name != hub and core.UMBRELLA not in tags:
            v.fail("badges", f"{name} wears p00's badge outside AI space", name)
        if core.klass_of(vm) == "TemplateVM":
            for detail in template_problems(name, vm):
                v.fail("templates", detail, name)
            continue
        net = core.netvm_of(vm)
        if net is not None:
            router_ok(net, name)
        target = update_target(policy, info, name)
        if target is not None:
            v.fail("networks", f"dom0's policy gives {who(name)} the update proxy ({target}), a "
                               f"way around its router", name)
        for ref in _chain(vm):
            if ref.name in subjects:
                continue        # judged as a subject of its own
            tvm = by_name.get(ref.name, ref)
            if core.klass_of(tvm) == "TemplateVM":
                for detail in template_problems(ref.name, tvm):
                    v.fail("templates", detail, name)
            else:
                # A disposable template outside the hub's subjects (one of an
                # anonymous project's, or outside AI space): its network is
                # what this subject's disposables use.
                tnet = core.netvm_of(tvm)
                if tnet is not None:
                    router_ok(tnet, name)
    return v


def hub_stop_set(v: Verdict, hub: str | None) -> list:
    """What a hub verdict stops: on a violation by the hub or a p00 qube, the
    hub, every p00 qube and every other offender (the hub first); on any
    other, the offenders alone; on a read that failed twice, or a mode file
    that does not read, the hub and p00 (without a kill)."""
    whole = v.status == UNREADABLE or (hub is not None and hub in v.offenders) \
        or any(n in v.p00 for n in v.offenders)
    if whole:
        head = [hub] if hub else []
        return head + sorted((set(v.p00) | set(v.offenders)) - {hub})
    return sorted(v.offenders)


# ======================================================================= acting on it

def _tag(vm, tag: str, add: bool) -> str:
    try:
        (vm.tags.add if add else vm.tags.discard)(tag)
        return ""
    except Exception as e:
        return type(e).__name__


def block(app, v: Verdict, names, kill: bool) -> None:
    """Stop the project's qubes, in passes, so no moment has one killed while
    another can still act: every one (the lead first) badged `qmcp-blocked`;
    then, for a violation, each one not yet stopped is killed unless it reads
    halted, and badged `qmcp-stopped` once it is known to be down; then
    autostart off on each it touched. A qube already
    stopped is left as it is: only the operator can have started it, to look
    at it. A step that fails is reported and the next one still runs: the kill
    is what stops the traffic."""
    vms = {}
    for name in names:
        try:
            vms[name] = app.domains[name]
        except Exception:
            v.acted.append(f"{name}: NOT blocked (it cannot be looked up)")

    def tags(vm):
        try:
            return core.tags_of(vm)
        except core.Unreadable:
            return set()            # unknown: every step below runs on it
    touched = []
    for name, vm in vms.items():
        if projects.BLOCKED not in tags(vm):
            err = _tag(vm, projects.BLOCKED, True)
            v.acted.append(f"{name}: blocked" if not err else f"{name}: NOT blocked ({err})")
            touched.append(name)
    if kill:
        for name, vm in vms.items():
            if projects.STOPPED in tags(vm):
                continue
            # `qmcp-stopped` only on a qube known to be down: killed now, or read
            # as halted. A power state that cannot be read (qubesadmin's "NA")
            # is no halt: the kill is tried, and a qube still not known to be
            # down is left unmarked, so the next run tries again.
            down = _power(vm) == "Halted"
            killed = False
            if not down:
                try:
                    vm.kill()
                    v.acted.append(f"{name}: killed")
                    down = killed = True
                except Exception as e:
                    down = _power(vm) == "Halted"
                    if not down:
                        v.acted.append(f"{name}: NOT killed ({type(e).__name__}); tried again "
                                       f"on the next run")
            if down:
                err = _tag(vm, projects.STOPPED, True)
                if err:
                    v.acted.append(f"{name}: NOT marked stopped ({err})")
                elif not killed:
                    v.acted.append(f"{name}: halted, marked stopped")
            if name not in touched:
                touched.append(name)
    for name in touched:
        try:
            vms[name].autostart = False
        except Exception as e:
            v.acted.append(f"{name}: autostart NOT turned off ({type(e).__name__})")


def _power(vm) -> str:
    """The power state, `unknown` when it cannot be read; only `Halted` is down."""
    try:
        return str(vm.get_power_state())
    except Exception:
        return "unknown"


def notify(text: str) -> bool:
    """A desktop notification with fixed text, as the proposals' are."""
    from qmcp import proposals
    return proposals.notify_text(text)


def gate_lock(path: str | None = None, wait: float | None = None):
    """The gate's lock, for a command outside this module that changes qubes
    (`qmcp open`, `qmcp seal`): one run at a time, so a window never races the
    pass that expires one. `with gate_lock() as got:` is False when another
    run held it past its wait."""
    return _GateLock(path, wait)


class _GateLock:
    """One run at a time. False from __enter__ when another run holds it past
    `wait` seconds."""

    def __init__(self, path: str | None = None, wait: float | None = None):
        self.path = LOCK_PATH if path is None else path
        self.wait = LOCK_WAIT_S if wait is None else wait
        self.fd = None

    def __enter__(self) -> bool:
        old = os.umask(0o007)
        try:
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o660)
        finally:
            os.umask(old)
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.2)

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
        return False


def _snapshot(app, strict: bool = False):
    """(by_name, tags_by): every qube, and every tag set that could be read. A
    qube qubesd says is gone is left out. With `strict`, one whose tags cannot
    be read raises `core.Unreadable`: it may be a member, and a member the gate
    cannot see would leave its project judged sound without it. A domain list
    that cannot be read raises too."""
    try:
        by_name = {vm.name: vm for vm in app.domains}
    except Exception:
        raise core.Unreadable("cannot list the qubes") from None
    tags_by, unread = {}, []
    for name, vm in by_name.items():
        try:
            tags_by[name] = core.tags_of(vm)
        except core.Gone:
            by_name[name] = None
        except core.Unreadable:
            unread.append(name)
    if strict and unread:
        raise core.Unreadable(f"cannot read the tags of {', '.join(sorted(unread))}")
    return {n: vm for n, vm in by_name.items() if vm is not None}, tags_by


def _attempt(app, p, policy_loader, records=None, overlay=None, registry=None):
    try:
        registry = gateways.load() if registry is None else registry
    except gateways.GatewaysUnreadable as e:
        # A read the gate cannot make, like any other: tried again, then a block.
        raise PolicyUnreadable(f"the gateway registry ({e})") from None
    by_name, tags_by = _snapshot(app, strict=True)
    for name, tags in (overlay or {}).items():
        if name in by_name:
            tags_by[name] = set(tags)
    view = (policy_loader or load_policy)()
    if p is HUB:
        if records is None:
            records = projects.load()
        return evaluate_hub(app, core.read_hub(), records, registry, view, by_name, tags_by)
    return evaluate(app, p, registry, view, by_name, tags_by)


def _names_now(app, p) -> list:
    """The qubes as far as they can be read now, for a verdict that could not
    be made: a project's recorded lead and every qube whose tags read and wear
    its badges; the hub and every p00 qube."""
    try:
        by_name, tags_by = _snapshot(app)
    except core.Unreadable:
        if p is HUB:
            return [core.read_hub()] if core.read_hub() else []
        return [p.lead] if p.lead else []
    if p is HUB:
        hub = core.read_hub()
        return ([hub] if hub else []) + [n for n in p00_qubes(tags_by) if n != hub]
    names = _member_qubes(p, tags_by)
    if p.lead and p.lead in by_name and p.lead not in names:
        names.insert(0, p.lead)
    return names


def judge(app, p, policy_loader=None, records=None, overlay=None, registry=None) -> Verdict:
    """A fresh verdict on one project, or on the hub (`HUB`), acting on
    nothing. `overlay`: name -> tags, judged as if the qubes wore them (what a
    move would leave); `registry`: a gateway registry judged instead of the
    file (what a gateway change would leave). Raises `core.Unreadable` or
    PolicyUnreadable."""
    return _attempt(app, p, policy_loader, records, overlay, registry)


def subjects(records: dict) -> list:
    """What the gate judges now: every anonymous project, then the hub in
    anonymous mode. Raises `core.ModeUnreadable`."""
    out = [p for p in sorted(records.values(), key=lambda p: p.slot)
           if p.anonymous and p.slot != projects.HUB_SLOT]
    return out + ([HUB] if core.anonymous_mode() else [])


def _beat(path: str | None = None) -> None:
    old = os.umask(0o007)
    try:
        with open(HEARTBEAT_PATH if path is None else path, "w", encoding="ascii") as fh:
            fh.write(f"{time.time():.0f}\n")
    except OSError:
        pass                    # `qmcp check` reports a heartbeat that does not move
    finally:
        os.umask(old)


def mode_state():
    """(True, None) in anonymous mode, (False, None) in normal mode, (None,
    why) when the mode file cannot be read."""
    try:
        return core.anonymous_mode(), None
    except core.ModeUnreadable as e:
        return None, str(e)


def _verdict(app, p, records, policy_loader, retry_wait) -> Verdict:
    """A verdict, its read tried once more after a failure; a second failure
    is an unreadable verdict over the qubes that can be read now."""
    try:
        return _attempt(app, p, policy_loader, records)
    except (core.Unreadable, PolicyUnreadable):
        time.sleep(RETRY_WAIT_S if retry_wait is None else retry_wait)
        try:
            return _attempt(app, p, policy_loader, records)
        except (core.Unreadable, PolicyUnreadable) as e:
            v = Verdict(p)
            v.status = UNREADABLE
            v.problems.append(("read", str(e)))
            v.names = _names_now(app, p)
            if p is HUB:
                v.p00 = [n for n in v.names if n != core.read_hub()]
            return v


def run(app, act: bool = True, records=None, policy_loader=None, lock_path: str | None = None,
        retry_wait: float | None = None, beat: bool = False):
    """Judge every anonymous project, and the hub in anonymous mode, and act on
    what is found unless `act` is false. Returns the verdicts (the hub's last):
    an empty list when there is nothing to judge, None when another run held
    the gate past its wait (nothing was judged). `beat`: the timer's run, which
    leaves the heartbeat. Raises `projects.ProjectsUnreadable` when the project
    records cannot be read: then no project is known to be anonymous, and the
    services already refuse every lead (`qmcp check` fails on the records)."""
    records = projects.load() if records is None else records
    anon = [p for p in sorted(records.values(), key=lambda p: p.slot)
            if p.anonymous and p.slot != projects.HUB_SLOT]
    mode, mode_error = mode_state()
    subjects = anon + ([] if mode is False else [HUB])
    if not subjects:
        if beat:
            _beat()             # the timer runs: no false alarm when the first project comes
        return []
    with _GateLock(lock_path) as got:
        if not got:
            return None
        out = []
        for p in subjects:
            if p is HUB and mode is None:
                v = Verdict(HUB)
                v.status = UNREADABLE
                v.problems.append(("read", f"{mode_error}, so whether the hub is judged cannot "
                                           f"be told"))
                v.names = _names_now(app, HUB)
                v.p00 = [n for n in v.names if n != core.read_hub()]
            else:
                v = _verdict(app, p, records, policy_loader, retry_wait)
            stop = hub_stop_set(v, core.read_hub()) if p is HUB else v.names
            if act and v.status in (RED, UNREADABLE):
                block(app, v, stop, kill=v.status == RED)
                # What the operator reads: blocked as the qubes are now.
                try:
                    now = _snapshot(app)[1]
                    worn = [projects.BLOCKED in now.get(n, ()) for n in v.names]
                    v.blocked = (any(worn) if p is HUB else bool(worn) and all(worn))
                except core.Unreadable:
                    v.blocked = False
            if v.acted:
                why = ", ".join(CONDITION_WORDS[c] for c in
                                (v.conditions() if v.status == RED else ["read"]))
                try:
                    audit.audit(SERVICE, CALLER,
                                {"project": p.slot, "status": v.status,
                                 "conditions": ",".join(v.conditions() or ["read"]),
                                 "acted": len(v.acted)}
                                | ({"hub": True, "qubes": len(stop)} if p is HUB else {}),
                                False, f"{v.status}: {why}")
                except Exception:
                    pass
                if p is HUB:
                    hub = core.read_hub()
                    whom = ("the hub and its qubes in p00" if hub is not None and hub in stop
                            else ", ".join(stop))
                    notify(NOTICE_HUB.format(who=whom, why=why))
                else:
                    notify(NOTICE.format(label=p.label, slot=p.slot, why=why))
            out.append(v)
        if beat:
            _beat()
        return out


def unblock(app, records: dict, key: str, policy_loader=None, lock_path: str | None = None) -> list:
    """Take `qmcp-stopped` and `qmcp-blocked` off a project's qubes once a fresh
    run finds it sound, holding the gate so no run judges in between.
    `autostart` stays off. The caller holds the project locks."""
    if key in (projects.HUB_SLOT, "hub"):
        return unblock_hub(app, records, policy_loader, lock_path)
    p = projects.find(records, key)
    if p is None or p.slot == projects.HUB_SLOT:
        raise ValueError(f"no project '{key}'")
    if not p.anonymous:
        raise ValueError(f"'{p.label}' is not an anonymous project")
    with _GateLock(lock_path) as got:
        if not got:
            raise ValueError("the anonymity gate is running; try again in a moment")
        try:
            v = judge(app, p, policy_loader)
        except (core.Unreadable, PolicyUnreadable) as e:
            raise ValueError(f"the gate could not judge {p.label} ({e}); it stays blocked") \
                from None
        if v.status != GREEN:
            raise ValueError(f"the gate still finds {p.label} unsound, so it stays blocked: "
                             + "; ".join(d for _, d in v.problems))
        out = []
        for name in v.names:
            vm = app.domains[name]
            try:
                tags = core.tags_of(vm)
            except core.Unreadable:
                tags = {projects.BLOCKED, projects.STOPPED}
            if not tags & {projects.BLOCKED, projects.STOPPED}:
                continue
            # The stop comes off first: the block is what keeps every call out.
            err = _tag(vm, projects.STOPPED, False) or _tag(vm, projects.BLOCKED, False)
            out.append(f"{p.slot}: {name} unblocked (autostart stays off)" if not err
                       else f"{p.slot}: {name} NOT unblocked ({err})")
        if not out:
            out.append(f"{p.slot}: nothing was blocked")
        return out


def unblock_hub(app, records: dict, policy_loader=None, lock_path: str | None = None) -> list:
    """`qmcp project unblock p00`: take `qmcp-stopped` and `qmcp-blocked` off
    the hub and every qube under the hub's check. In anonymous mode only once
    a fresh run finds the hub sound; in normal mode nothing about the hub
    claims anonymity, so badges left from anonymous mode just come off. The
    caller holds the project locks; `autostart` stays off."""
    mode, why = mode_state()
    if mode is None:
        raise ValueError(f"{why}: whether the hub is under the gate cannot be told, so it stays "
                         f"blocked")
    with _GateLock(lock_path) as got:
        if not got:
            raise ValueError("the anonymity gate is running; try again in a moment")
        if mode:
            try:
                v = judge(app, HUB, policy_loader, records)
            except (core.Unreadable, PolicyUnreadable) as e:
                raise ValueError(f"the gate could not judge the hub ({e}); it stays blocked") \
                    from None
            if v.status != GREEN:
                raise ValueError("the gate still finds the hub unsound, so it stays blocked: "
                                 + "; ".join(d for _, d in v.problems))
            names = v.names
        else:
            try:
                registry = gateways.load()
            except gateways.GatewaysUnreadable:
                registry = {}
            names = hub_candidates(core.read_hub(), records, registry, _snapshot(app)[1]) \
                if core.read_hub() else []
        out = []
        for name in names:
            try:
                vm = app.domains[name]
            except Exception:
                out.append(f"p00: {name} NOT unblocked (it cannot be looked up)")
                continue
            try:
                tags = core.tags_of(vm)
            except core.Unreadable:
                tags = {projects.BLOCKED, projects.STOPPED}
            if not tags & {projects.BLOCKED, projects.STOPPED}:
                continue
            err = _tag(vm, projects.STOPPED, False) or _tag(vm, projects.BLOCKED, False)
            out.append(f"p00: {name} unblocked (autostart stays off)" if not err
                       else f"p00: {name} NOT unblocked ({err})")
        if not out:
            out.append("p00: nothing was blocked")
        return out
