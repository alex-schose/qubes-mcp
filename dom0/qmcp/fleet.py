"""qmcp.fleet — the operator's side: `check`, `migrate`, role actions, projects, listing.

This runs in dom0 as the operator (root, or a member of `qubes`), with full
Admin API authority, and never on behalf of an AI caller. Badges change only
through these role actions, so each one refuses a change that
would break an invariant `check` asserts. The project commands also write the
project records, or take their lock, which needs root.

`check` reports one of three overall results, and INCOMPLETE is not green:
  GREEN       every check ran and none failed (warnings allowed)
  FAILED      at least one check failed
  INCOMPLETE  a check could not run, so the fleet is unproven
"""
from __future__ import annotations

import os
import stat

from qmcp import audit, birth, budget, core, projects

POLICY_DIR = "/etc/qubes/policy.d"
POLICY_NAME = "30-mcp-control.policy"
LIB_DIR = "/usr/local/lib/qmcp"
RPC_DIR = "/etc/qubes-rpc"
TIER_DEFAULT_PATH = "/etc/qmcp/tier-default"

LEGACY_TIER_TAGS = birth.LEGACY_TIER_TAGS
TOMBSTONE_PREFIX = "qmcp-tombstone_"

#: Everything v0.9.16 installed that 0.9.17 no longer has. `check` fails while
#: any of it is present; the installer removes it.
LEGACY_PATHS = (
    "/etc/qubes-rpc/qmcp_audit.py", "/etc/qubes-rpc/qmcp_birth.py",
    "/etc/qubes-rpc/qmcp_budget.py", "/etc/qubes-rpc/qmcp_caps.py",
    "/etc/qubes-rpc/qmcp_consent.py", "/etc/qubes-rpc/qmcp_enforce.py",
    "/etc/qubes-rpc/qmcp_principal.py", "/etc/qubes-rpc/qmcp_scope.py",
    "/etc/qubes-rpc/qmcp_tier.py", "/etc/qubes-rpc/qmcp_tombstone.py",
    "/etc/qubes-rpc/qmcp.AttachDeviceAIManaged",
    "/etc/qubes-rpc/qmcp.DetachDeviceAIManaged",
    "/etc/qubes-rpc/qmcp.ListAttachedDevicesAIManaged",
    "/usr/local/lib/qmcp/qmcp-consentd", "/usr/local/lib/qmcp/qmcp-tombstone-reaper",
    "/etc/systemd/system/qmcp-consent.service",
    "/etc/systemd/system/qmcp-tombstone-reaper.service",
    "/etc/systemd/system/qmcp-tombstone-reaper.timer",
    "/etc/qmcp/tier-default", "/etc/qmcp/enforce-mode", "/etc/qmcp/birth-ceiling",
    "/etc/qmcp/principals", "/etc/qmcp/consent-policy", "/etc/qmcp/consent-timeout",
    "/etc/qmcp/budget.lock", "/etc/qmcp/tombstone-retention", "/etc/qmcp/guarded",
)

#: The other v0.9.16 flag a migration retires (TIER_DEFAULT_PATH is the first).
ENFORCE_MODE_PATH = "/etc/qmcp/enforce-mode"

#: v0.9.16's operator list of qube names its kernel always refused (in strict
#: or enforce mode). A migration makes every listed qube in AI space guarded, so
#: an upgrade never quietly un-guards a qube the operator protected.
GUARDED_LIST_PATH = "/etc/qmcp/guarded"
_UNREADABLE = object()


class Finding:
    __slots__ = ("status", "check", "detail")

    def __init__(self, status: str, check: str, detail: str = "") -> None:
        assert status in ("pass", "warn", "fail", "error")
        self.status, self.check, self.detail = status, check, detail

    def __repr__(self) -> str:
        return f"{self.status.upper():5s} {self.check}: {self.detail}"


def overall(findings) -> str:
    """GREEN / FAILED / INCOMPLETE. An empty list is INCOMPLETE: "all zero
    checks passed" is exactly what a crashed run looks like."""
    statuses = {f.status for f in findings}
    if not findings or "error" in statuses:
        return "INCOMPLETE" if "fail" not in statuses else "FAILED"
    return "FAILED" if "fail" in statuses else "GREEN"


def _tags(vm) -> set:
    return core.tags_of(vm)


def _owner(vm):
    for t in _tags(vm):
        if t.startswith(birth.OWNER_PREFIX):
            return t[len(birth.OWNER_PREFIX):]
    return None


def _read_word(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read(256).split("#", 1)[0].strip()
    except OSError:
        return ""


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


# ------------------------------------------------------------------ policy facts

POLICY_RUN_DIR = "/run/qubes/policy.d"

#: What our rulebook claims, as (label, service, source role, target). Each must
#: be decided by OUR file on the real merged policy set: a rule in a file that
#: sorts earlier, matching first, would silently override it, and parsing
#: alone never shows that.
PRECEDENCE_CLAIMS = (
    ("raw @dispvm from AI space", "qubes.VMShell", "ai", "@dispvm"),
    ("exec into another qube from AI space", "qubes.VMExec", "ai", "peer"),
    ("AI space reaching the hub", "qubes.OpenURL", "ai", "hub"),
    ("AI space reaching the hub with any service", "qubes.ConnectTCP", "ai", "hub"),
    ("the Admin API to dom0 from AI space", "admin.vm.List", "ai", "dom0"),
    ("the policy API from AI space", "policy.Replace", "ai", "dom0"),
    ("the policy API through @default from AI space", "policy.Replace", "ai", "@default"),
    ("a qmcp service from AI space", "qmcp.ListAIManagedQubes", "ai", "dom0"),
    ("the Admin API on a qube from AI space", "admin.vm.tag.Set", "ai", "peer"),
    ("the Admin API through @default from AI space", "admin.vm.List", "ai", "@default"),
    ("dom0 notifications from AI space", "qubes.Notifications", "ai", "@default"),
    ("qmcp exec from AI space", "qmcp.RunInAIManaged", "ai", "peer"),
    ("a copy into a guarded qube", "qubes.Filecopy", "ai", "guarded"),
    ("hub exec into a guarded qube", "qmcp.RunInAIManaged", "hub", "guarded"),
    ("the Admin API to dom0 from the hub", "admin.vm.List", "hub", "dom0"),
    ("hub exec outside AI space", "qmcp.RunInAIManaged", "hub", "outside"),
    ("a lead's exec into its own member", "qmcp.RunInAIManaged", "lead", "member"),
    ("a lead's exec into another project", "qmcp.RunInAIManaged", "lead", "other"),
    ("a lead's copy into another project", "qubes.Filecopy", "lead", "other"),
    ("a lead's event stream", "qmcp.AIManagedEvents", "lead", "dom0"),
    ("a worker reaching its lead", "qubes.Filecopy", "member", "lead"),
    ("a worker calling a qmcp service", "qmcp.ListAIManagedQubes", "member", "dom0"),
    ("a worker's copy into its dump sink", "qubes.Filecopy", "member", "sink"),
    ("a dump sink reaching back into its project", "qubes.Filecopy", "sink", "member"),
)
_PROBES = {"ai": "qmcp-probe-ai", "peer": "qmcp-probe-peer",
           "guarded": "qmcp-probe-guarded", "outside": "qmcp-probe-outside",
           "lead": "qmcp-probe-lead", "member": "qmcp-probe-member",
           "other": "qmcp-probe-other", "sink": "qmcp-probe-sink"}
#: Synthetic project p01 (lead, member, sink) and a member of p02.
_PROBE_TAGS = {
    "ai": [core.UMBRELLA], "peer": [core.UMBRELLA], "guarded": [core.UMBRELLA, core.GUARDED],
    "outside": [],
    "lead": [core.UMBRELLA, projects.LEAD, projects.lead_badge("p01")],
    "member": [core.UMBRELLA, projects.member_badge("p01")],
    "other": [core.UMBRELLA, projects.member_badge("p02")],
    "sink": [projects.DROP_BOX, projects.dump_badge("p01")],
}


def _probe_domain(tags):
    import uuid
    return {"tags": list(tags), "type": "AppVM", "template_for_dispvms": False,
            "default_dispvm": None, "icon": "", "power_state": "Halted",
            "internal": False, "uuid": str(uuid.uuid4())}


def precedence(policy, system_info, hub: str) -> list:
    """Claims of our file that another file decides first. Sources: every
    AI-space qube on the box plus a synthetic one; targets: synthetic qubes,
    the hub, dom0, and the keywords. Returns one line per problem."""
    from qrexec.exc import AccessDenied, RequestError
    from qrexec.policy.parser import Request
    domains = dict(system_info["domains"])
    for role, tags in _PROBE_TAGS.items():
        domains.setdefault(_PROBES[role], _probe_domain(tags))
    domains.setdefault(hub, _probe_domain([]))
    if "dom0" not in domains:
        domains["dom0"] = dict(_probe_domain([]), type="AdminVM")
    si = {"domains": domains}
    ai_sources = sorted({n for n, d in domains.items()
                         if not n.startswith("uuid:") and core.UMBRELLA in d.get("tags", [])
                         and n not in (_PROBES["peer"], _PROBES["guarded"])})
    problems = []
    for label, service, role, target in PRECEDENCE_CLAIMS:
        tgt = {"hub": hub, "dom0": "dom0"}.get(target, _PROBES.get(target, target))
        sources = (ai_sources if role == "ai" else [hub] if role == "hub"
                   else [_PROBES[role]])
        for src in sources:
            if src == tgt:
                continue
            try:
                req = Request(service, "+", src, tgt, system_info=si)
            except (AccessDenied, RequestError):
                continue                    # refused before any rule: the claim holds
            rule = next((r for r in policy.rules if r.is_match(req)), None)
            where = "no rule" if rule is None else os.path.basename(str(rule.filepath))
            if where != POLICY_NAME:
                problems.append(f"{label} ({src} -> {tgt}) is decided by "
                                f"{where}{'' if rule is None else ':' + str(rule.lineno)}, not ours")
    return problems


def policy_hub(path: str) -> str | None:
    """The hub a rendered policy names: the source of its last catch-all."""
    import re
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    hits = re.findall(r"^\*\s+\*\s+(\S+)\s+@anyvm\s+deny\s*$", text, re.M)
    return hits[-1] if hits else None


# ------------------------------------------------------------------ check

def check(app, policy_dir: str | None = None, lib_dir: str | None = None,
          rpc_dir: str | None = None, legacy_paths=None, system_info=None) -> list:
    policy_dir = POLICY_DIR if policy_dir is None else policy_dir
    lib_dir = LIB_DIR if lib_dir is None else lib_dir
    rpc_dir = RPC_DIR if rpc_dir is None else rpc_dir
    legacy_paths = LEGACY_PATHS if legacy_paths is None else legacy_paths
    out: list = []
    add = lambda *a: out.append(Finding(*a))  # noqa: E731

    try:
        vms = list(app.domains)
    except Exception as e:
        return [Finding("error", "fleet", f"cannot list qubes ({type(e).__name__})")]
    by_name = {vm.name: vm for vm in vms}

    # 1. the hub
    hub = core.read_hub()
    if hub is None:
        add("fail", "hub", f"{core.HUB_PATH} missing or malformed")
    elif hub not in by_name:
        add("fail", "hub", f"hub '{hub}' does not exist")
    else:
        bad = {t for t in _tags(by_name[hub]) if birth.controlled(t)}
        if bad:
            add("fail", "hub", f"hub '{hub}' carries AI-space badges {sorted(bad)}; "
                               f"remove them with: qvm-tags {hub} del <tag>")
        else:
            add("pass", "hub", f"hub is '{hub}', outside AI space")

    # 2. migration complete
    tiered = sorted(vm.name for vm in vms if _tags(vm) & LEGACY_TIER_TAGS)
    add("fail" if tiered else "pass", "tier tags",
        f"still tiered: {', '.join(tiered)} (run qmcp migrate)" if tiered else "none left")

    # 3. gateways are always guarded: the policy cannot see provides_network
    loose = sorted(vm.name for vm in vms if core.in_scope(vm) and core.is_gateway(vm)
                   and core.GUARDED not in _tags(vm))
    add("fail" if loose else "pass", "gateways guarded",
        f"gateway(s) without {core.GUARDED}: {', '.join(loose)} (qmcp guard <qube>)"
        if loose else "every gateway in AI space is guarded")

    # 4. the airlock: a drop box is never in AI space
    hybrids = sorted(vm.name for vm in vms if {"ai-dump", core.UMBRELLA} <= _tags(vm))
    add("fail" if hybrids else "pass", "drop boxes",
        f"ai-dump qube(s) also ai-managed: {', '.join(hybrids)}" if hybrids
        else "no ai-dump qube is in AI space")

    # 5. stray badges outside AI space. Slot badges are judged by the project
    # checks below, which fail on a misplaced one; a dump sink's badge belongs
    # outside AI space.
    stray = sorted(vm.name for vm in vms if not core.in_scope(vm)
                   and any(t == core.GUARDED or t.startswith(birth.NAMESPACE)
                           for t in _tags(vm) if not t.startswith(TOMBSTONE_PREFIX)
                           and not projects.is_slot_tag(t)))
    add("warn" if stray else "pass", "stray badges",
        f"qmcp badges outside AI space: {', '.join(stray)}" if stray else "none")

    # 6. v0.9.16 tombstones still on disk
    tombs = sorted(vm.name for vm in vms
                   if any(t.startswith(TOMBSTONE_PREFIX) for t in _tags(vm)))
    add("warn" if tombs else "pass", "tombstones",
        f"v0.9.16 tombstones awaiting removal by hand: {', '.join(tombs)}" if tombs else "none")

    # 7. the name-namespace residual
    prefix = birth.read_name_prefix()
    squat = sorted(vm.name for vm in vms if vm.name.startswith(prefix) and not core.in_scope(vm)
                   and vm.name not in tombs)
    add("warn" if squat else "pass", "name namespace",
        f"outside AI space but inside '{prefix}': {', '.join(squat)} (their names are "
        f"detectable through create collisions)" if squat else f"'{prefix}' holds only AI space")

    # 8. no default disposable template outside AI space on a managed qube
    dd = []
    for vm in vms:
        if core.state(vm) == "managed":
            ref = _safe(lambda: getattr(vm, "default_dispvm", None))
            name = None if ref is None else str(getattr(ref, "name", ref))
            if name and not (name in by_name and core.in_scope(by_name[name])):
                dd.append(vm.name)
    add("warn" if dd else "pass", "default_dispvm",
        f"managed qube(s) pointing at a disposable template outside AI space: "
        f"{', '.join(sorted(dd))} (qmcp migrate --apply pins them)" if dd else "none")

    # 9. the policy: installed, unmodified, and parseable by qrexec itself
    installed = os.path.join(policy_dir, POLICY_NAME)
    shipped = os.path.join(lib_dir, "share", POLICY_NAME)
    try:
        with open(installed, "rb") as a, open(shipped, "rb") as b:
            same = a.read() == b.read()
        add("pass" if same else "fail", "policy file",
            "installed file matches what the installer rendered" if same
            else f"{installed} differs from {shipped}")
    except OSError as e:
        add("fail", "policy file", f"cannot compare ({e.strerror}: {e.filename})")
    named = policy_hub(installed)
    if hub is not None and named != hub:
        add("fail", "policy hub", f"the policy names '{named}' as the hub, {core.HUB_PATH} says '{hub}'")
    else:
        add("pass", "policy hub", f"policy and {core.HUB_PATH} agree")
    try:
        import logging
        import pathlib
        from qrexec.policy.parser import FilePolicy
        import qrexec.utils
        logging.disable(logging.WARNING)
        try:
            dirs = [pathlib.Path(d) for d in (POLICY_RUN_DIR, policy_dir) if os.path.isdir(d)]
            policy = FilePolicy(policy_path=dirs)
        finally:
            logging.disable(logging.NOTSET)
        add("pass", "policy parses", f"{policy_dir} loads in qrexec's parser")
        try:
            si = qrexec.utils.get_system_info() if system_info is None else system_info
            problems = precedence(policy, si, hub or "mcp-control")
            add("fail" if problems else "pass", "policy precedence",
                "; ".join(problems[:5]) + (f" (+{len(problems) - 5} more)" if len(problems) > 5 else "")
                if problems else f"all {len(PRECEDENCE_CLAIMS)} claims decided by our file")
        except Exception as e:
            add("error", "policy precedence", f"could not evaluate ({type(e).__name__})")
    except ImportError:
        add("error", "policy parses", "python3-qrexec is not importable")
    except Exception as e:
        # qrexec's loader reports any OSError as AccessDenied. A file this user
        # cannot read is a check that could not run, not a policy that is wrong.
        cause = e.__cause__
        if isinstance(cause, PermissionError):
            add("error", "policy parses", f"cannot read {cause.filename} as this user; "
                                          f"run qmcp check as root")
        else:
            add("fail", "policy parses", f"qrexec's parser refuses {policy_dir}: {type(e).__name__}")

    # 10. the services
    from qmcp.services import SERVICES
    missing = sorted(s for s in SERVICES if not os.path.isfile(os.path.join(rpc_dir, s)))
    add("fail" if missing else "pass", "services",
        f"not installed: {', '.join(missing)}" if missing else f"{len(SERVICES)} installed")

    # 11. the runtime directory the caps rely on
    calls = os.path.join(core.RUN_DIR, "calls")
    st = _safe(lambda: os.stat(calls))
    if st is None:
        add("fail", "runtime dir", f"{calls} missing (systemd-tmpfiles --create)")
    elif not (st.st_mode & stat.S_IWGRP):
        add("fail", "runtime dir", f"{calls} is not group-writable")
    else:
        lock = _safe(lambda: os.stat(budget.LOCK_PATH))
        if lock is not None and not (lock.st_mode & stat.S_IWGRP):
            add("fail", "runtime dir", f"{budget.LOCK_PATH} is not group-writable: every create "
                                       f"refuses (systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
        else:
            add("pass", "runtime dir", calls)

    # 12. operator files
    caps_ok = budget.read_cap() is not None and budget.read_private_cap() is not None
    add("pass" if caps_ok else "fail", "disk caps",
        "pool-cap and private-cap readable" if caps_ok
        else f"{budget.CAP_PATH} or {budget.PRIVATE_CAP_PATH} missing or malformed")
    egress = _read_word(birth.BIRTH_EGRESS_PATH)
    if egress and not (egress in by_name and core.in_scope(by_name[egress])):
        add("warn", "birth egress", f"'{egress}' is not in AI space; template spawns will be refused")
    else:
        add("pass", "birth egress", egress or "not set (template spawns need the hub's netvm in AI space)")

    # 13. the audit chain
    ok, n, err = audit.verify()
    add("pass" if ok else "fail", "audit chain", f"{n} entries intact" if ok else err)
    size = _safe(lambda: os.path.getsize(audit.LOG_PATH), 0)
    if size > audit.ROTATE_AT_BYTES:
        add("warn", "audit size", f"{size // (1024 * 1024)} MiB; rotate with: qmcp audit rotate")

    # 14. nothing of v0.9.16 left behind
    left = [p for p in legacy_paths if os.path.lexists(p)]
    add("fail" if left else "pass", "v0.9.16 leftovers",
        f"still present: {', '.join(left)}" if left else "none")

    # 15. projects: the records, and the badges the rulebook routes on
    try:
        records = projects.load()
    except projects.ProjectsUnreadable as e:
        add("fail", "project records", f"{projects.PROJECTS_PATH}: {e}")
        return out
    if not os.path.exists(projects.PROJECTS_PATH):
        add("warn", "project records", f"{projects.PROJECTS_PATH} missing; no projects (the installer writes it)")
    else:
        add("pass", "project records",
            f"{sum(1 for p in records.values() if p.label)} project(s) in {projects.PROJECTS_PATH}")
    out.extend(project_findings(vms, by_name, records, prefix))
    quotas = sum(p.quota for p in records.values() if p.quota)
    cap = budget.read_cap()
    if cap is not None and quotas > cap:
        add("warn", "project quotas",
            f"they add up to {quotas // 1024 ** 3} GiB, more than the pool cap: a lead refused by "
            f"the cap inside its quota learns that the rest of AI space is full")
    return out


def _is_template(vm) -> bool:
    return (_safe(lambda: vm.klass) == "TemplateVM"
            or bool(_safe(lambda: getattr(vm, "template_for_dispvms", False), False)))


def _netvm_name(vm):
    ref = _safe(lambda: getattr(vm, "netvm", None))
    return None if ref is None else str(getattr(ref, "name", ref))


def project_findings(vms, by_name: dict, records: dict, prefix: str) -> list:
    """The project invariants. The rulebook matches tags, not records, so a
    badge in the wrong place is a fail, not a warning: a slot badge outside AI
    space or left over from a deleted project is a dialog-free path for a lead."""
    out: list = []
    add = lambda *a: out.append(Finding(*a))  # noqa: E731
    slots_on = {}
    bad_outside, bad_shape, stale, templates_in, stray_leads = [], [], [], [], []
    for vm in vms:
        tags = _tags(vm)
        members, leads = projects.member_slots(tags), projects.lead_slots(tags)
        dumps = {p[1] for p in map(projects.slot_badge_parts, tags) if p and p[0] == "dump"}
        has_lead_tag = projects.LEAD in tags
        if not (members or leads or dumps or has_lead_tag):
            continue
        slots_on[vm.name] = (members, leads, dumps)
        if not core.in_scope(vm) and (members or leads or has_lead_tag):
            bad_outside.append(vm.name)
        if dumps and (core.in_scope(vm) or projects.DROP_BOX not in tags):
            bad_outside.append(f"{vm.name} (a dump sink must be ai-dump and outside AI space)")
        if (len(members) + len(leads) > 1 or (members and has_lead_tag)
                or bool(leads) != has_lead_tag or len(dumps) > 1 or (dumps and (members or leads))):
            bad_shape.append(vm.name)
        for slot in members | leads | dumps:
            if slot != projects.HUB_SLOT and slot not in records:
                stale.append(f"{vm.name} ({slot})")
        if projects.HUB_SLOT in leads:
            bad_shape.append(f"{vm.name} (p00 has no lead)")
        # The rulebook gives a lead's reach to whoever wears its badges, so a
        # holder that is not its slot's recorded lead fails, record or not.
        if leads or has_lead_tag:
            rec = records.get(next(iter(leads))) if len(leads) == 1 else None
            if rec is None or rec.lead != vm.name:
                stray_leads.append(vm.name)
        if (members or leads) and (_is_template(vm) or core.is_gateway(vm)):
            templates_in.append(vm.name)
    add("fail" if bad_outside else "pass", "slot badges in AI space",
        f"badges a lead could route to: {', '.join(sorted(bad_outside))}" if bad_outside
        else "every member and lead is in AI space; every sink outside it")
    add("fail" if bad_shape else "pass", "one slot per qube",
        f"conflicting slot badges: {', '.join(sorted(bad_shape))}" if bad_shape else "none")
    add("fail" if stale else "pass", "slot badges have records",
        f"badges of a slot with no project (left after a delete?): {', '.join(sorted(stale))}"
        if stale else "none")
    add("fail" if templates_in else "pass", "no template in a project",
        f"templates, disposable templates or gateways with slot badges: {', '.join(sorted(templates_in))}"
        if templates_in else "none")

    lead_bad, leaderless, tpl_warn, net_warn, sink_bad, sink_warn = [], [], [], [], [], []
    for p in sorted(records.values(), key=lambda p: p.slot):
        if p.slot == projects.HUB_SLOT:
            names = [p.dump] if p.dump else []
        else:
            names = [p.dump] if p.dump else []
            if p.lead is None:
                leaderless.append(f"{p.label} ({p.slot})")
            else:
                vm = by_name.get(p.lead)
                if vm is None or not core.lead_badges_agree(_tags(vm), p.slot) or _is_template(vm) \
                        or core.is_gateway(vm):
                    lead_bad.append(f"{p.label}: {p.lead}")
            for t in p.templates:
                vm = by_name.get(t)
                if vm is None or not core.in_scope(vm) or not _is_template(vm):
                    tpl_warn.append(f"{p.label}: {t}")
            for n in p.named_networks():
                vm = by_name.get(n)
                if vm is None or not core.in_scope(vm) or not core.is_gateway(vm):
                    net_warn.append(f"{p.label}: {n}")
            for vm in vms:
                if core.is_member(vm, p.slot):
                    net = _netvm_name(vm)
                    if net is not None and net not in p.named_networks() \
                            and _safe(lambda: vm.klass) != "DispVM":
                        net_warn.append(f"{p.label}: member {vm.name} is on {net}, not on the list")
        for name in names:
            vm = by_name.get(name)
            if vm is None or core.in_scope(vm) or projects.dump_badge(p.slot) not in _tags(vm) \
                    or projects.DROP_BOX not in _tags(vm):
                sink_bad.append(f"{p.slot}: {name}")
            elif _netvm_name(vm) is not None:
                sink_warn.append(f"{p.slot}: {name} has a network")
        for name, (_, _, dumps) in slots_on.items():
            if p.slot in dumps and name not in names:
                sink_bad.append(f"{p.slot}: {name} wears the dump badge but is not the record's sink")
    lead_bad += [f"{name} wears lead badges but is not its slot's recorded lead" for name in stray_leads]
    add("fail" if lead_bad else "pass", "leads",
        f"record and badges disagree: {'; '.join(lead_bad)}" if lead_bad
        else "every lead wears exactly its slot's lead badges, and only leads do")
    if leaderless:
        add("warn", "projects without a lead", ", ".join(leaderless))
    if tpl_warn:
        add("warn", "approved templates", f"not a template in AI space (spawns refused): {'; '.join(tpl_warn)}")
    if net_warn:
        add("warn", "worker networks", "; ".join(net_warn))
    add("fail" if sink_bad else "pass", "dump sinks",
        "; ".join(sink_bad) if sink_bad else "every sink is ai-dump, outside AI space, and named in its record")
    if sink_warn:
        add("warn", "dump sink network", "; ".join(sink_warn))

    unslotted = sorted(vm.name for vm in vms if core.state(vm) == "managed"
                       and _safe(lambda: vm.klass) == "AppVM" and not _is_template(vm)
                       and not (_tags(vm) & {projects.LEAD})
                       and not projects.member_slots(_tags(vm)))
    if unslotted:
        add("warn", "managed qubes in no slot",
            f"{', '.join(unslotted)} (hub-only, copies by dialog; qmcp project move QUBE p00)")
    squat = []
    for p in records.values():
        if not p.label:
            continue
        space = p.space(prefix)
        squat += [vm.name for vm in vms if vm.name.startswith(space)
                  and not core.is_member(vm, p.slot) and vm.name != p.lead]
    if squat:
        add("warn", "project name spaces",
            f"inside a project's names but not its own: {', '.join(sorted(squat))} "
            f"(that project's lead can detect them through a create collision)")
    return out


# ------------------------------------------------------------------ migrate

class Step:
    __slots__ = ("qube", "remove", "add", "pin_dispvm", "note")

    def __init__(self, qube, remove=(), add=(), pin_dispvm=False, note=""):
        self.qube, self.remove, self.add = qube, set(remove), set(add)
        self.pin_dispvm, self.note = pin_dispvm, note

    def __repr__(self):
        bits = []
        if self.remove:
            bits.append("remove " + ",".join(sorted(self.remove)))
        if self.add:
            bits.append("add " + ",".join(sorted(self.add)))
        if self.pin_dispvm:
            bits.append("default_dispvm=None")
        return f"{self.qube}: {'; '.join(bits) or 'no change'}" + (f"  ({self.note})" if self.note else "")


def read_tier_default(path: str | None = None) -> str | None:
    try:
        with open(TIER_DEFAULT_PATH if path is None else path, encoding="utf-8") as fh:
            return fh.read(64).split("#", 1)[0].strip() or None
    except OSError:
        return None


def read_guarded_list(path: str | None = None):
    """The names on v0.9.16's guarded list: a set (empty when there is no
    list), or `_UNREADABLE` when the file exists but cannot be read."""
    try:
        with open(GUARDED_LIST_PATH if path is None else path, encoding="utf-8") as fh:
            return {s for s in (line.split("#", 1)[0].strip() for line in fh) if s}
    except FileNotFoundError:
        return set()
    except (OSError, UnicodeDecodeError):
        return _UNREADABLE


def plan_migration(app, choices: dict, exec_default: str | None = None,
                   compat_default: str | None = None, tier_default: str | None = "unset"):
    """(steps, problems). Nothing is changed.

    Mapping: `ai-full` -> managed; `ai-exec`/`ai-net` -> the
    operator's choice per qube; gateways -> guarded whatever they carried; a
    qube on v0.9.16's guarded list -> guarded unless `choices` says otherwise.
    An umbrella-only qube is read by the fleet's state:
      flipped (tier-default `ro`)   it was the read floor -> guarded
      tiered but never flipped      it held full authority -> the operator's choice
      no tier tag anywhere          already two-state (migrated, or never tiered)
                                    -> managed, unchanged
    Applying a migration retires tier-default and the guarded list
    (`finish_migration`), so a second run reads the fleet as two-state and
    changes nothing.
    """
    if tier_default == "unset":
        tier_default = read_tier_default()
    flipped = tier_default == "ro"
    tiered = any(_tags(vm) & LEGACY_TIER_TAGS for vm in app.domains)
    hub = core.read_hub()
    steps, problems = [], []
    listed = read_guarded_list()
    if listed is _UNREADABLE:
        problems.append(f"{GUARDED_LIST_PATH} exists but cannot be read; it may name qubes "
                        f"v0.9.16 always refused. Fix or remove it first")
        listed = set()
    for vm in app.domains:
        tags = _tags(vm)
        tiers = tags & LEGACY_TIER_TAGS
        if vm.name == hub and (core.UMBRELLA in tags or tiers):
            problems.append(f"{vm.name}: the hub must not be in AI space; "
                            f"remove its badges with qvm-tags first")
            continue
        if {"ai-dump", core.UMBRELLA} <= tags:
            problems.append(f"{vm.name}: carries both ai-dump and ai-managed; decide which it is")
            continue
        if core.UMBRELLA not in tags:
            if tiers:
                problems.append(f"{vm.name}: tier tag without the umbrella ({', '.join(sorted(tiers))})")
            continue
        if core.is_gateway(vm):
            want, note = "guarded", "gateway"
        elif vm.name in listed:
            want, note = choices.get(vm.name) or "guarded", f"on {GUARDED_LIST_PATH}"
        elif "ai-full" in tiers:
            want, note = "managed", "was ai-full"
        elif tiers:
            want = choices.get(vm.name) or exec_default
            note = f"was {', '.join(sorted(tiers))}"
        elif core.GUARDED in tags:
            want, note = "guarded", "already guarded"
        elif flipped:
            want, note = choices.get(vm.name) or "guarded", "was the read floor"
        elif tiered:
            want = choices.get(vm.name) or compat_default
            note = "umbrella only on a never-flipped fleet (held full authority)"
        else:
            want, note = choices.get(vm.name) or "managed", "already two-state"
        if want not in ("managed", "guarded"):
            problems.append(f"{vm.name}: needs a choice, managed or guarded ({note}); "
                            f"pass --map {vm.name}=managed|guarded")
            continue
        add = {core.GUARDED} if want == "guarded" else set()
        remove = set(tiers) | ({core.GUARDED} if want == "managed" else set())
        remove &= tags
        add -= tags
        pin = False
        if want == "managed":
            ref = _safe(lambda: getattr(vm, "default_dispvm", None))
            pin = ref is not None
        if remove or add or pin:
            steps.append(Step(vm.name, remove, add, pin, note))
    return steps, problems


def apply_migration(app, steps) -> list:
    """Apply the plan; one result line per step. Add before remove, so a
    failure halfway leaves a qube over-restricted rather than under."""
    results = []
    for s in steps:
        try:
            vm = app.domains[s.qube]
            for t in sorted(s.add):
                vm.tags.add(t)
            for t in sorted(s.remove):
                vm.tags.discard(t)
            if s.pin_dispvm:
                vm.default_dispvm = None
            results.append(f"done   {s!r}")
        except Exception as e:
            results.append(f"FAILED {s!r}: {type(e).__name__}")
    return results


def finish_migration(paths=None) -> list:
    """Retire the v0.9.16 files that say how to READ a tiered fleet, once a
    migration has been applied: afterwards an umbrella-only qube means managed,
    and the guarded list lives on as `qmcp-guarded` badges."""
    done = []
    for path in ((TIER_DEFAULT_PATH, ENFORCE_MODE_PATH, GUARDED_LIST_PATH)
                 if paths is None else paths):
        try:
            os.unlink(path)
            done.append(path)
        except FileNotFoundError:
            pass
    return done


# ------------------------------------------------------------------ role actions

class RoleError(Exception):
    pass


def _target(app, name):
    if not core.valid_qube_name(name) or name not in app.domains:
        raise RoleError(f"no qube named '{name}'")
    if name == core.read_hub():
        raise RoleError(f"'{name}' is the hub; the hub is never in AI space")
    vm = app.domains[name]
    if "ai-dump" in _tags(vm):
        raise RoleError(f"'{name}' is a drop box (ai-dump); a drop box is never in AI space")
    return vm


def manage(app, name) -> str:
    vm = _target(app, name)
    if core.is_gateway(vm):
        raise RoleError(f"'{name}' provides network; gateways are always guarded (qmcp guard)")
    vm.tags.add(core.UMBRELLA)
    for t in sorted((_tags(vm) & LEGACY_TIER_TAGS) | ({core.GUARDED} & _tags(vm))):
        vm.tags.discard(t)
    if _safe(lambda: getattr(vm, "default_dispvm", None)) is not None:
        vm.default_dispvm = None
    return f"{name}: managed"


def _not_in_a_slot(vm, name, action: str) -> None:
    tags = _tags(vm)
    if projects.LEAD in tags or projects.lead_slots(tags):
        raise RoleError(f"'{name}' is a lead; use qmcp project lead <project> --remove first")
    if projects.member_slots(tags) and action != "revoke":
        raise RoleError(f"'{name}' is in a project slot; qmcp project move {name} none first")


def guard(app, name) -> str:
    vm = _target(app, name)
    _not_in_a_slot(vm, name, "guard")
    vm.tags.add(core.GUARDED)
    vm.tags.add(core.UMBRELLA)
    for t in sorted(_tags(vm) & LEGACY_TIER_TAGS):
        vm.tags.discard(t)
    return f"{name}: guarded"


def revoke(app, name, shutdown: bool = True) -> str:
    """Strip every AI-space badge, pin default_dispvm, and shut the qube down
    Restrictions such as an egress lock go too: revoke is yours."""
    vm = _target(app, name)
    _not_in_a_slot(vm, name, "revoke")
    for t in sorted((t for t in _tags(vm) if birth.controlled(t)), key=_removal_order):
        vm.tags.discard(t)
    if _safe(lambda: getattr(vm, "default_dispvm", None)) is not None:
        vm.default_dispvm = None
    msg = f"{name}: revoked"
    if shutdown and _safe(vm.is_running, False):
        try:
            vm.shutdown()
            msg += ", shutdown requested"
        except Exception as e:
            msg += f", shutdown failed ({type(e).__name__}); kill it with qvm-kill {name}"
    return msg


def listing(app, everything: bool = False) -> list:
    """One row per qube in AI space. `everything` adds every other qube but
    dom0, with state None: the operator's window offers them when a qube joins
    AI space, and as a lead's template or network."""
    rows = []
    for vm in app.domains:
        st = core.state(vm)
        klass = _safe(lambda: vm.klass)
        if st is None and (not everything or klass == "AdminVM"):
            continue
        tpl = _safe(lambda: getattr(vm, "template", None))
        net = _safe(lambda: getattr(vm, "netvm", None))
        tags = _tags(vm)
        slots = projects.member_slots(tags) | projects.lead_slots(tags)
        rows.append({
            "name": vm.name, "state": st, "klass": klass,
            "template": None if tpl is None else str(getattr(tpl, "name", tpl)),
            "netvm": None if net is None else str(getattr(net, "name", net)),
            "power": _safe(vm.get_power_state, "unknown"),
            "slot": ",".join(sorted(slots)) or None,
            "lead": projects.LEAD in tags,
            "owner": _owner(vm),
            "gateway": core.is_gateway(vm),
            "dvmt": bool(_safe(lambda: getattr(vm, "template_for_dispvms", False), False)),
            "badges": sorted(t for t in tags if birth.controlled(t) or t == projects.DROP_BOX),
        })
    return rows


def settings(app) -> dict:
    """The operator files the services re-read on every call, read the way
    they read them, and the disk AI space uses against the cap."""
    hub = core.read_hub()
    hub_vm = core.lookup(app, hub) if hub else None
    try:
        used = budget.persistent_sum(app)
    except Exception:
        used = None
    return {
        "hub": hub,
        "hub_power": None if hub_vm is None else _safe(hub_vm.get_power_state, "unknown"),
        "name_prefix": birth.read_name_prefix(),
        "pool_cap": budget.read_cap(),
        "private_cap": budget.read_private_cap(),
        "ai_space_bytes": used,
        "birth_egress": _read_word(birth.BIRTH_EGRESS_PATH) or None,
    }


# ------------------------------------------------------------------ projects (operator)
#
# Every command below holds two locks: the record file's, and the create lock
# the services hold through a create. So a command waits for any create in
# flight, and a create that waited for a command checks its caller again
# before it acts. Each command checks everything it can before it changes
# anything. Adding authority, it writes the record last: a new lead is no
# principal until its record names it. Removing authority, it takes the
# lead's badges first, then the record, then the qubes. It touches a recorded
# lead only while that qube wears the slot's lead badge.
# The rulebook routes on badges, so a step that fails half-way leaves badges
# that `qmcp check` reports. A failed command's exception carries `report`,
# the steps it completed.

class ProjectError(RoleError):
    pass


_SIZE_UNITS = {"": 1, "B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
LEAD_LABEL = "purple"
SINK_LABEL = "black"
#: How long removing a project's qube waits for it to halt after a kill.
HALT_WAIT_S = 60.0


def _quota(value) -> int:
    if isinstance(value, bool) or value is None:
        raise ProjectError("a project needs a disk quota (e.g. 40G)")
    if isinstance(value, int):
        if value <= 0:
            raise ProjectError("a size must be positive")
        return value
    return parse_size(value)


def parse_size(text) -> int:
    """Bytes from `40G`, `512M`, `1T` or a plain number."""
    import re
    m = re.fullmatch(r"\s*([0-9]+)\s*([BKMGT]?)(?:i?B)?\s*", str(text), re.I | re.ASCII)
    if not m:
        raise ProjectError(f"'{text}' is not a size (e.g. 40G)")
    n = int(m.group(1)) * _SIZE_UNITS[m.group(2).upper()]
    if n <= 0:
        raise ProjectError("a size must be positive")
    return n


def _vm(app, name):
    if not core.valid_qube_name(name):
        return None
    try:
        return app.domains[name] if name in app.domains else None
    except Exception:
        return None


def _load_records() -> dict:
    try:
        return projects.load()
    except projects.ProjectsUnreadable as e:
        raise ProjectError(f"{projects.PROJECTS_PATH} is unreadable ({e}); fix it before changing projects")


def _project(records: dict, key: str):
    p = projects.find(records, key)
    if p is None or p.slot == projects.HUB_SLOT:
        raise ProjectError(f"no project '{key}'")
    return p


class _Exclusive:
    """Both locks, for one project command (see above)."""

    def __enter__(self):
        self.records_lock = projects.Locked()
        self.records_lock.__enter__()
        try:
            self.fd = budget.acquire_create_lock()
        except core.Refusal:
            self.records_lock.__exit__(None, None, None)
            raise ProjectError("a create is in progress; try again in a moment") from None
        return self

    def __exit__(self, *exc):
        os.close(self.fd)
        self.records_lock.__exit__(*exc)
        return False


def _run(command, *args, **kwargs) -> list:
    """Run a project command under both locks. Its exception, if any, carries
    `report`: the steps that completed before it failed."""
    report: list = []
    with _Exclusive():
        try:
            command(report, *args, **kwargs)
        except Exception as e:
            e.report = list(report)
            raise
    return report


def _template_name(vm):
    ref = _safe(lambda: getattr(vm, "template", None))
    return None if ref is None else str(getattr(ref, "name", ref))


def _check_templates(app, names) -> list:
    out = []
    for name in names:
        vm = _vm(app, name)
        if vm is None or not core.in_scope(vm) or not _is_template(vm):
            raise ProjectError(f"'{name}' is not a template or disposable template in AI space")
        if name not in out:
            out.append(name)
    if not out:
        raise ProjectError("a project needs at least one approved template in AI space")
    return out


def _check_networks(app, names) -> list:
    out = []
    for name in names:
        net = None if name in (None, "none") else name
        if net is not None:
            vm = _vm(app, net)
            if vm is None or not core.in_scope(vm) or not core.is_gateway(vm):
                raise ProjectError(f"'{net}' is not a gateway in AI space")
        if net in out:
            raise ProjectError(f"network '{name}' is listed twice")
        out.append(net)
    if not out:
        raise ProjectError("a project needs at least one worker network (a gateway, or none)")
    return out


def _check_lead_netvm(app, name):
    if name in (None, "none"):
        return None
    vm = _vm(app, name)
    if vm is None or not core.is_gateway(vm):
        raise ProjectError(f"'{name}' is not a qube that provides network")
    return name


def _hubs_own_appvm(app, name, what: str):
    """A managed AppVM of the hub's (p00 or no slot): a lead's clone source or a
    qube to promote. Never a template, gateway, guarded qube, lead, drop box
    or another project's member."""
    vm = _vm(app, name)
    if vm is None or not core.in_scope(vm):
        raise ProjectError(f"no qube '{name}' in AI space")
    tags = _tags(vm)
    if _safe(lambda: vm.klass) != "AppVM" or _is_template(vm) or core.is_gateway(vm):
        raise ProjectError(f"{what} must be an AppVM, not a template or gateway")
    if core.GUARDED in tags or projects.DROP_BOX in tags:
        raise ProjectError(f"'{name}' is guarded or a drop box")
    if projects.LEAD in tags or projects.lead_slots(tags):
        raise ProjectError(f"'{name}' already leads a project")
    if projects.member_slots(tags) - {projects.HUB_SLOT}:
        raise ProjectError(f"'{name}' is another project's member; move it to p00 first")
    return vm


def _lead_template(app, name):
    """A fresh lead's template: any TemplateVM. One outside AI space is the
    stronger choice, since the hub cannot edit it; it then stays off the
    project's approved list, which holds only AI space."""
    vm = _vm(app, name)
    if vm is None or _safe(lambda: vm.klass) != "TemplateVM":
        raise ProjectError(f"'{name}' is not a TemplateVM")
    return vm


def _badges_of_slot(app, slot: str) -> list:
    """Every qube still wearing a badge of `slot`."""
    out = []
    for vm in app.domains:
        tags = _tags(vm)
        if any((p := projects.slot_badge_parts(t)) and p[1] == slot for t in tags):
            out.append(vm.name)
    return out


def _removal_order(tag: str) -> tuple:
    """Badges come off in this order, and go on in the reverse: first the
    slot badges the rulebook routes on (`qmcp-lead-pNN` alone gives root exec
    into a slot's members, `qmcp-proj-pNN` makes a qube reachable from its
    lead), then the umbrella, then the rest. A failure part-way then leaves a
    qube with less authority than the command meant, never more."""
    if projects.slot_badge_parts(tag) is not None:
        return (0, tag)
    return (1, tag) if tag == core.UMBRELLA else (2, tag)


def _set_tags(vm, add=(), remove=()):
    """Remove, then add, each in authority order (see `_removal_order`),
    then read back exactly."""
    for t in sorted(remove, key=_removal_order):
        vm.tags.discard(t)
    for t in sorted(add, key=_removal_order, reverse=True):
        vm.tags.add(t)
    tags = _tags(vm)
    if not set(add) <= tags or tags & set(remove):
        raise RuntimeError("tags did not read back as set")


def _remove_qube(app, name) -> str:
    """Kill and remove a qube; '' when it is gone, else why not."""
    import time
    vm = _vm(app, name)
    if vm is None:
        return ""
    try:
        if _safe(vm.is_running, False):
            vm.kill()
        deadline = time.monotonic() + HALT_WAIT_S
        while _safe(vm.get_power_state, "Halted") not in ("Halted", None) and time.monotonic() < deadline:
            time.sleep(0.5)
        if name in app.domains:
            del app.domains[name]
    except KeyError:
        pass
    except Exception as e:
        return f"{name}: {type(e).__name__}"
    return "" if _vm(app, name) is None else f"{name}: still present"


def _plan_lead(app, space: str, source: str, origin: str, lead_netvm, name=None,
               freed: str | None = None) -> str:
    """Everything about a new lead that can be checked without changing
    anything; returns the name it will have. `freed` is a name that will be
    free by the time the lead is made (an old lead that is removed first)."""
    if source == "template":
        _lead_template(app, origin)
    elif source in ("clone", "promote"):
        _hubs_own_appvm(app, origin, "the lead")
    else:
        raise ProjectError(f"unknown lead source '{source}'")
    _check_lead_netvm(app, lead_netvm)
    if source == "promote":
        return origin
    name = name or f"{space}lead"
    if not name.startswith(space) or birth.name_refusal(name, space):
        raise ProjectError(f"the lead's name must be inside '{space}'")
    if _vm(app, name) is not None and name != freed:
        raise ProjectError(f"'{name}' exists; pass --lead-name for the new lead")
    return name


def _make_lead(app, slot: str, source: str, origin: str, name: str, lead_netvm):
    """Make `name` the lead of `slot`, as planned by `_plan_lead`. Returns
    (name, created, badges the qube had) so a later failure can undo exactly.
    A fresh lead is born on `lead_netvm`; a promoted one keeps its network
    unless `lead_netvm` is given. On failure nothing it made or badged remains."""
    want = {core.UMBRELLA, projects.LEAD, projects.lead_badge(slot)}
    if source == "promote":
        vm = _hubs_own_appvm(app, origin, "a promoted lead")
        netvm = _check_lead_netvm(app, lead_netvm)
        before = {projects.member_badge(s) for s in projects.member_slots(_tags(vm))}
        try:
            # Out of its slot first, then the lead badges: never both at once.
            _set_tags(vm, remove=before)
            _set_tags(vm, add=want)
            if lead_netvm is not None:
                vm.netvm = netvm
        except Exception:
            _undo_lead(app, origin, False, slot, before)
            raise
        return origin, False, before
    netvm = _check_lead_netvm(app, lead_netvm)
    if source == "template":
        _lead_template(app, origin)
        vm = app.add_new_vm("AppVM", name, LEAD_LABEL, template=origin)
    else:
        vm = app.clone_vm(_hubs_own_appvm(app, origin, "a lead's clone source"), name)
    try:
        birth.stamp(birth.TagIO.for_vm(vm), _tags(vm), "dom0", None)
        _set_tags(vm, add=want)
        vm.netvm = netvm
        vm.default_dispvm = None
        if _netvm_name(vm) != netvm or _safe(lambda: getattr(vm, "default_dispvm", None)) is not None:
            raise RuntimeError("the lead's network did not read back")
    except Exception as e:
        err = _remove_qube(app, name)
        if err:
            raise ProjectError(f"making the lead failed ({type(e).__name__}) and the new qube "
                               f"could not be removed: {err}") from e
        raise
    return name, True, set()


def _undo_lead(app, lead: str, fresh: bool, slot: str, before=frozenset()) -> None:
    """Undo `_make_lead`: remove a lead it made; give a promoted one back
    exactly the badges it had, removing first, so a failure never leaves a
    qube with more authority than before."""
    if fresh:
        _remove_qube(app, lead)
        return
    vm = _vm(app, lead)
    if vm is not None:
        _set_tags(vm, remove={projects.LEAD, projects.lead_badge(slot)})
        _set_tags(vm, add=set(before))


def _recorded_lead(app, p):
    """The project's recorded lead, only while it wears the slot's lead badge.
    A recorded name whose qube was removed by hand may since name another qube,
    which must be left alone."""
    vm = _vm(app, p.lead) if p.lead else None
    if vm is None or projects.lead_badge(p.slot) not in _tags(vm):
        return None
    return vm


def _demote_lead(app, p, report: list) -> bool:
    """Take the lead's authority first: its badges, which the rulebook routes on
    and the services require. Then a kill, so it starts no new call. A call it
    already started may still finish: a create re-checks its caller under the
    create lock, which this command holds; a lifecycle, property or feature
    change already past its check completes."""
    vm = _recorded_lead(app, p)
    if vm is None:
        if p.lead:
            report.append(f"{p.slot}: {p.lead} does not wear {p.slot}'s lead badge; left alone")
        return False
    _set_tags(vm, remove={projects.LEAD, projects.lead_badge(p.slot)})
    report.append(f"{p.slot}: {p.lead} is no longer the lead")
    if _safe(vm.is_running, False):
        try:
            vm.kill()
        except Exception as e:
            report.append(f"{p.slot}: kill of {p.lead} failed ({type(e).__name__})")
    return True


def create_project(app, label: str, lead_source: str, lead_origin: str, templates=(),
                   networks=(), quota=None, lead_netvm=None, dump: bool = False,
                   lead_name: str | None = None) -> list:
    """Make a project; returns the report lines. The record is written last, so
    the lead is no principal until everything else is in place."""
    return _run(_create_project, app, label, lead_source, lead_origin, templates, networks,
                quota, lead_netvm, dump, lead_name)


def _create_project(report, app, label, lead_source, lead_origin, templates, networks, quota,
                    lead_netvm, dump, lead_name):
    err = projects.label_refusal(label)
    if err:
        raise ProjectError(err)
    prefix = birth.read_name_prefix()
    space = f"{prefix}{label}-"
    quota = _quota(quota)
    records = _load_records()
    if projects.by_label(records, label):
        raise ProjectError(f"label '{label}' is taken")
    free = projects.free_slots(records)
    if not free:
        raise ProjectError("all 15 project slots are in use")
    slot = free[0]
    leftover = _badges_of_slot(app, slot)
    if leftover:
        raise ProjectError(f"slot {slot} still has badges on {', '.join(leftover)}; "
                           f"finish with: qmcp project delete {slot} --yes")
    squatters = [vm.name for vm in app.domains if vm.name.startswith(space)]
    if squatters:
        raise ProjectError(f"qubes already sit in '{space}': {', '.join(squatters)}")
    sink = f"{label}-dump" if dump else None
    if sink and (sink.startswith(prefix) or _vm(app, sink) is not None):
        raise ProjectError(f"the dump sink '{sink}' would be inside '{prefix}' or exists")
    name = _plan_lead(app, space, lead_source, lead_origin, lead_netvm, lead_name)
    lead_tpl = lead_origin if lead_source == "template" else _template_name(_vm(app, lead_origin))
    tpls = list(templates)
    if lead_tpl and (vm := _vm(app, lead_tpl)) is not None and core.in_scope(vm):
        tpls.insert(0, lead_tpl)
    tpls = _check_templates(app, tpls)
    nets = _check_networks(app, networks)
    lead, fresh, before = _make_lead(app, slot, lead_source, lead_origin, name, lead_netvm)
    report.append(f"{slot}: lead {lead} ({'created' if fresh else 'promoted'})")
    try:
        if sink:
            _make_sink(app, slot, sink)
            report.append(f"{slot}: dump sink {sink} created (no network)")
        records[slot] = projects.Project(slot, label, lead, tpls, nets, quota, sink)
        projects.save(records)
    except Exception:
        if sink:
            _remove_qube(app, sink)
        _undo_lead(app, lead, fresh, slot, before)
        report.append(f"{slot}: undone")
        raise
    report.append(f"{slot}: project '{label}' recorded; workers are named {space}*")


def _make_sink(app, slot: str, name: str):
    """A fresh drop box: ai-dump + the slot's dump badge, no network, outside AI space."""
    if _vm(app, name) is not None:
        raise ProjectError(f"'{name}' exists; a dump sink is always a fresh qube")
    tpl = _safe(lambda: getattr(app, "default_template", None))
    if tpl is None:
        raise ProjectError("Qubes has no default template for the dump sink")
    vm = app.add_new_vm("AppVM", name, SINK_LABEL, template=tpl)
    try:
        _set_tags(vm, add={projects.DROP_BOX, projects.dump_badge(slot)})
        vm.netvm = None
        vm.default_dispvm = None
        if _netvm_name(vm) is not None:
            raise RuntimeError("the sink's network did not read back as none")
    except Exception:
        _remove_qube(app, name)
        raise
    return name


def remove_lead(app, key: str) -> list:
    """The project stays and its workers are untouched; the lead is removed."""
    return _run(_remove_lead, app, key)


def _remove_lead(report, app, key):
    records = _load_records()
    p = _project(records, key)
    if p.lead is None:
        raise ProjectError(f"project '{p.label}' has no lead")
    ours = _demote_lead(app, p, report)
    old, p.lead = p.lead, None
    projects.save(records)
    report.append(f"{p.slot}: the record names no lead")
    if ours:
        err = _remove_qube(app, old)
        report.append(f"{p.slot}: removed {old}" if not err else f"{p.slot}: NOT removed: {err}")


def set_lead(app, key: str, lead_source: str, lead_origin: str, lead_netvm=None,
             keep_old: bool = False, lead_name: str | None = None) -> list:
    """Give a project a new lead. Everything about the new lead is checked
    before the old one is touched. The old one is removed, or kept as a worker
    of the same project (on one of its worker networks), never as one of the
    hub's qubes."""
    return _run(_set_lead, app, key, lead_source, lead_origin, lead_netvm, keep_old, lead_name)


def _set_lead(report, app, key, lead_source, lead_origin, lead_netvm, keep_old, lead_name):
    prefix = birth.read_name_prefix()
    records = _load_records()
    p = _project(records, key)
    old_vm = _recorded_lead(app, p)
    if keep_old and old_vm is not None:
        net = _netvm_name(old_vm)
        if net is not None and net not in p.named_networks():
            raise ProjectError(f"the old lead is on {net}, which is not one of the project's worker "
                               f"networks; drop --keep-old or add the network")
    freed = None if (keep_old or old_vm is None) else p.lead
    if (keep_old and old_vm is not None and lead_source != "promote"
            and (lead_name or f"{p.space(prefix)}lead") == p.lead):
        raise ProjectError(f"the old lead keeps the name {p.lead}; pass --lead-name for the new one")
    name = _plan_lead(app, p.space(prefix), lead_source, lead_origin, lead_netvm, lead_name, freed)
    old = p.lead
    if old is not None:
        ours = _demote_lead(app, p, report)
        p.lead = None
        projects.save(records)
        if ours and keep_old:
            _set_tags(_vm(app, old), add={projects.member_badge(p.slot)})
            report.append(f"{p.slot}: {old} kept as a worker")
        elif ours:
            err = _remove_qube(app, old)
            report.append(f"{p.slot}: removed {old}" if not err else f"{p.slot}: NOT removed: {err}")
    lead, fresh, before = _make_lead(app, p.slot, lead_source, lead_origin, name, lead_netvm)
    tpl = lead_origin if lead_source == "template" else _template_name(_vm(app, lead))
    if tpl and tpl not in p.templates and (vm := _vm(app, tpl)) is not None \
            and core.in_scope(vm) and _is_template(vm):
        p.templates = p.templates + (tpl,)
    p.lead = lead
    try:
        projects.save(records)
    except Exception:
        _undo_lead(app, lead, fresh, p.slot, before)
        raise
    report.append(f"{p.slot}: lead {lead} ({'created' if fresh else 'promoted'})")


def edit_project(app, key: str, templates=None, networks=None, quota=None) -> list:
    """Replace the approved templates or worker networks, or change the quota.
    Existing workers keep their networks: no network is moved after birth."""
    return _run(_edit_project, app, key, templates, networks, quota)


def _edit_project(report, app, key, templates, networks, quota):
    records = _load_records()
    p = _project(records, key)
    if templates is not None:
        p.templates = tuple(_check_templates(app, templates))
    if networks is not None:
        p.networks = tuple(_check_networks(app, networks))
    if quota is not None:
        p.quota = _quota(quota)
    projects.save(records)
    report.append(f"{p.slot}: templates {list(p.templates)}, networks "
                  f"{[n or 'none' for n in p.networks]}, quota {p.quota}")


def add_dump(app, key: str, name: str | None = None) -> list:
    """Give a project, or p00, its dump sink: a fresh offline drop box."""
    return _run(_add_dump, app, key, name)


def _add_dump(report, app, key, name):
    records = _load_records()
    p = records[projects.HUB_SLOT] if key == projects.HUB_SLOT else _project(records, key)
    if p.dump is not None:
        raise ProjectError(f"{p.slot} already has a dump sink, {p.dump}")
    prefix = birth.read_name_prefix()
    name = name or (f"{p.label}-dump" if p.label else "hub-dump")
    if name.startswith(prefix) or not core.valid_qube_name(name):
        raise ProjectError(f"a dump sink's name must be a qube name outside '{prefix}'")
    _make_sink(app, p.slot, name)
    p.dump = name
    try:
        projects.save(records)
    except Exception:
        _remove_qube(app, name)
        raise
    report.append(f"{p.slot}: dump sink {name} created (no network)")


def move(app, name: str, target: str, confirm: bool = False) -> list:
    """Move one of AI space's AppVMs into p00, a project, or no slot. Its network
    is not changed, so a project takes it only on one of its worker networks.
    Taking a qube out of one slot into another carries that slot's content
    across a trust boundary, and needs `confirm`."""
    return _run(_move, app, name, target, confirm)


def _move(report, app, name, target, confirm):
    records = _load_records()
    vm = _vm(app, name)
    if vm is None or not core.in_scope(vm):
        raise ProjectError(f"no qube '{name}' in AI space")
    tags = _tags(vm)
    if _safe(lambda: vm.klass) != "AppVM" or _is_template(vm) or core.is_gateway(vm) \
            or core.GUARDED in tags:
        raise ProjectError(f"'{name}' is not a managed AppVM; templates and gateways join no slot")
    if projects.LEAD in tags or projects.lead_slots(tags):
        raise ProjectError(f"'{name}' is a lead; use qmcp project lead")
    if target == "none":
        slot = None
    elif target == projects.HUB_SLOT:
        slot = projects.HUB_SLOT
    else:
        p = _project(records, target)
        slot = p.slot
        net = _netvm_name(vm)
        if net is not None and net not in p.named_networks():
            raise ProjectError(f"'{name}' is on {net}, which is not one of {p.label}'s worker networks")
    current = projects.member_slots(tags)
    if slot is not None and current and current != {slot} and not confirm:
        raise ProjectError(f"'{name}' is in {', '.join(sorted(current))}: moving it carries that "
                           f"slot's content into {slot}; re-run with --yes")
    # Remove before add: a moment in no slot is less authority, never more.
    _set_tags(vm, remove={projects.member_badge(s) for s in current})
    if slot is not None:
        _set_tags(vm, add={projects.member_badge(slot)})
    report.append(f"{name}: {'no slot' if slot is None else slot}")
    prefix = birth.read_name_prefix()
    for p in records.values():
        if p.label and p.slot != slot and name.startswith(p.space(prefix)):
            report.append(f"{name}: its name stays inside '{p.space(prefix)}', so {p.label}'s lead "
                          f"can still detect it by name")


def delete_project(app, key: str) -> list:
    """Remove the lead and every member, keep the dump sink (minus its slot
    badge), strip every badge of the slot, and free it. Authority goes first:
    the lead's badges, then the record, then the qubes. Given a slot with no
    record but leftover badges, it finishes a delete that stopped half-way."""
    return _run(_delete_project, app, key)


def _delete_project(report, app, key):
    records = _load_records()
    p = projects.find(records, key)
    if p is None and key in projects.PROJECT_SLOTS:
        p = projects.Project(key)
        report.append(f"{key}: no record; finishing a delete")
    elif p is None or p.slot == projects.HUB_SLOT:
        raise ProjectError(f"no project '{key}'")
    else:
        ours = _demote_lead(app, p, report)
        del records[p.slot]
        projects.save(records)
        report.append(f"{p.slot}: record of '{p.label}' deleted")
        if ours:
            err = _remove_qube(app, p.lead)
            report.append(f"{p.slot}: removed {p.lead}" if not err else f"{p.slot}: NOT removed: {err}")
    # Only qubes really in the project are removed. A stray badge on a qube
    # outside AI space is stripped below, never the qube.
    for name in [vm.name for vm in app.domains if core.is_member(vm, p.slot)]:
        err = _remove_qube(app, name)
        report.append(f"{p.slot}: removed {name}" if not err else f"{p.slot}: NOT removed: {err}")
    for name in _badges_of_slot(app, p.slot):
        vm = _vm(app, name)
        strip = {t for t in _tags(vm) if (q := projects.slot_badge_parts(t)) and q[1] == p.slot}
        if projects.LEAD in _tags(vm) and projects.lead_badge(p.slot) in strip:
            strip.add(projects.LEAD)
        try:
            _set_tags(vm, remove=strip)
            report.append(f"{p.slot}: stripped {', '.join(sorted(strip))} from {name}"
                          + (" (the dump sink, kept)" if name == p.dump else ""))
        except Exception as e:
            report.append(f"{p.slot}: could NOT strip badges from {name} ({type(e).__name__})")
    left = _badges_of_slot(app, p.slot)
    report.append(f"{p.slot}: free" if not left else
                  f"{p.slot}: NOT reusable until these lose its badges: {', '.join(left)}")


def project_rows(app, records: dict) -> list:
    rows = []
    for slot in projects.SLOTS:
        p = records.get(slot)
        if p is None:
            continue
        badge = projects.member_badge(slot)
        members = [vm.name for vm in app.domains if core.is_member(vm, slot)]
        try:
            used = budget.persistent_sum(app, badge)
        except Exception:
            used = None
        rows.append({"slot": slot, "label": p.label, "lead": p.lead, "members": len(members),
                     "used": used, "quota": p.quota, "templates": list(p.templates),
                     "networks": list(p.networks), "dump": p.dump})
    return rows
