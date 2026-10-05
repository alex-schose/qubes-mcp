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

from qmcp import audit, birth, budget, core, firewall, gateways, projects, proposals

POLICY_DIR = "/etc/qubes/policy.d"
POLICY_NAME = "30-mcp-control.policy"
LIB_DIR = "/usr/local/lib/qmcp"
RPC_DIR = "/etc/qubes-rpc"
TIER_DEFAULT_PATH = "/etc/qmcp/tier-default"
#: The group the qmcp services run in, as a non-root dom0 user. tmpfiles gives
#: it every runtime file they share with root, and `check` holds those files to it.
SERVICES_GROUP = "qubes"

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


def _owner(tags):
    for t in tags:
        if t.startswith(birth.OWNER_PREFIX):
            return t[len(birth.OWNER_PREFIX):]
    return None


def _read_word(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read(256).split("#", 1)[0].strip()
    except OSError:
        return ""


def _services_gid():
    """SERVICES_GROUP's gid, or None when this host has no such group."""
    import grp
    try:
        return grp.getgrnam(SERVICES_GROUP).gr_gid
    except KeyError:
        return None


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
    ("the hub writing a lead's firewall", "admin.vm.firewall.Set", "hub", "lead"),
    ("the Admin API to dom0 from the hub", "admin.vm.List", "hub", "dom0"),
    ("hub exec outside AI space", "qmcp.RunInAIManaged", "hub", "outside"),
    ("a lead's exec into its own member", "qmcp.RunInAIManaged", "lead", "member"),
    ("a lead's exec into another project", "qmcp.RunInAIManaged", "lead", "other"),
    ("a lead's copy into another project", "qubes.Filecopy", "lead", "other"),
    ("a lead's event stream", "qmcp.AIManagedEvents", "lead", "dom0"),
    ("a lead submitting a proposal", "qmcp.SubmitProposal", "lead", "dom0"),
    ("the hub submitting a proposal", "qmcp.SubmitProposal", "hub", "dom0"),
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
    # Every qube's tags, read once: the items below that judge tags judge these
    # reads. A qube whose tags cannot be read is reported here and skipped by
    # those items, never judged as a qube with none. One qubesd says is gone
    # (removed since the list was read) is skipped: it holds nothing.
    tags_by, unread = {}, []
    for vm in vms:
        try:
            tags_by[vm.name] = _tags(vm)
        except core.Gone:
            pass
        except core.Unreadable:
            unread.append(vm.name)
    if unread:
        add("error", "qube tags", f"cannot read the tags of: {', '.join(sorted(unread))}; the "
                                  f"items that judge tags skip them")
    vms = [vm for vm in vms if vm.name in tags_by]

    def judged(item, offenders, cannot, fail_text, pass_text, level="fail"):
        """An item's finding: its offenders, with what it could not read noted;
        what it could not read alone is an error, never a pass."""
        note = f"; cannot read {', '.join(sorted(cannot))}" if cannot else ""
        if offenders:
            add(level, item, fail_text + note)
        elif cannot:
            add("error", item, note[2:])
        else:
            add("pass", item, pass_text)

    def T(vm) -> set:
        return tags_by[vm.name]

    # 1. the hub
    hub = core.read_hub()
    if hub is None:
        add("fail", "hub", f"{core.HUB_PATH} missing or malformed")
    elif hub not in by_name:
        add("fail", "hub", f"hub '{hub}' does not exist")
    elif hub not in tags_by:
        add("error", "hub", f"cannot read the tags of the hub '{hub}'")
    else:
        bad = {t for t in tags_by[hub] if birth.controlled(t)}
        if bad:
            add("fail", "hub", f"hub '{hub}' carries AI-space badges {sorted(bad)}; "
                               f"remove them with: qvm-tags {hub} del <tag>")
        else:
            add("pass", "hub", f"hub is '{hub}', outside AI space")

    # 2. migration complete
    tiered = sorted(vm.name for vm in vms if T(vm) & LEGACY_TIER_TAGS)
    add("fail" if tiered else "pass", "tier tags",
        f"still tiered: {', '.join(tiered)} (run qmcp migrate)" if tiered else "none left")

    # 3. gateways are always guarded: the policy cannot see provides_network
    loose, role_unread = [], []
    for vm in vms:
        if core.UMBRELLA not in T(vm) or core.GUARDED in T(vm):
            continue
        try:
            if core.is_gateway(vm):
                loose.append(vm.name)
        except core.Unreadable:
            role_unread.append(f"whether {vm.name} provides network")
    judged("gateways guarded", loose, role_unread,
           f"gateway(s) without {core.GUARDED}: {', '.join(sorted(loose))} (qmcp guard <qube>)",
           "every gateway in AI space is guarded")

    # 3b. the gateway registry: every entry still a gateway AI space may use,
    # and every network an AI qube is on, enrolled. A qube's own firewall
    # rules are carried out by the qube above it, so that qube must be one
    # the operator chose.
    try:
        registry = gateways.load()
    except gateways.GatewaysUnreadable as e:
        registry = None
        add("fail", "gateway registry", f"{gateways.GATEWAYS_PATH}: {e}; no network is usable")
    if registry is not None:
        bad, gw_unread = [], []
        for name in sorted(registry):
            if name in unread:
                continue                    # its tags: the "qube tags" error names it
            try:
                why = _gateway_refusal(by_name, name, hub)
            except core.Unreadable as e:
                gw_unread.append(str(e).removeprefix("cannot read "))
                continue
            if why:
                bad.append(f"{name} ({why})")
        judged("gateway registry", bad, gw_unread, f"enrolled but not usable: {'; '.join(bad)}",
               f"{len(registry)} gateway(s) enrolled" if registry
               else "no gateway enrolled; AI qubes can have no network (qmcp gateway enroll QUBE)")
        loose, net_unread = [], []
        for vm in vms:
            if core.UMBRELLA not in T(vm):
                continue
            try:
                if core.is_gateway(vm):
                    continue
                net = _netvm(vm)
            except (core.Unreadable, NetvmUnreadable):
                net_unread.append(f"the network, or whether it provides network, of {vm.name}")
                continue
            if net is not None and net not in registry:
                loose.append(f"{vm.name} on {net}")
        judged("AI networks", loose, net_unread,
               f"AI qubes on a network that is not enrolled: {', '.join(sorted(loose))} (enroll "
               f"it with qmcp gateway enroll NAME, or clear the qube's network)",
               "every AI qube's network (gateways aside) is an enrolled gateway, or none")

    # 4. the airlock: a drop box is never in AI space
    hybrids = sorted(vm.name for vm in vms if {"ai-dump", core.UMBRELLA} <= T(vm))
    add("fail" if hybrids else "pass", "drop boxes",
        f"ai-dump qube(s) also ai-managed: {', '.join(hybrids)}" if hybrids
        else "no ai-dump qube is in AI space")

    # 5. stray badges outside AI space. Slot badges are judged by the project
    # checks below, which fail on a misplaced one; a dump sink's badge belongs
    # outside AI space.
    stray = sorted(vm.name for vm in vms if core.UMBRELLA not in T(vm)
                   and any(t == core.GUARDED or t.startswith(birth.NAMESPACE)
                           for t in T(vm) if not t.startswith(TOMBSTONE_PREFIX)
                           and not projects.is_slot_tag(t)))
    add("warn" if stray else "pass", "stray badges",
        f"qmcp badges outside AI space: {', '.join(stray)}" if stray else "none")

    # 6. v0.9.16 tombstones still on disk
    tombs = sorted(vm.name for vm in vms
                   if any(t.startswith(TOMBSTONE_PREFIX) for t in T(vm)))
    add("warn" if tombs else "pass", "tombstones",
        f"v0.9.16 tombstones awaiting removal by hand: {', '.join(tombs)}" if tombs else "none")

    # 7. the name-namespace residual
    prefix = birth.read_name_prefix()
    squat = sorted(vm.name for vm in vms if vm.name.startswith(prefix)
                   and core.UMBRELLA not in T(vm) and vm.name not in tombs)
    add("warn" if squat else "pass", "name namespace",
        f"outside AI space but inside '{prefix}': {', '.join(squat)} (their names are "
        f"detectable through create collisions)" if squat else f"'{prefix}' holds only AI space")

    # 8. no default disposable template outside AI space on a managed qube
    dd, dd_unread = [], []
    for vm in vms:
        # Managed qubes only. The role is read strictly here: `is_guarded` counts
        # one it cannot read as guarded, which would skip the qube unreported.
        if core.UMBRELLA not in T(vm) or core.GUARDED in T(vm):
            continue
        try:
            if core.is_gateway(vm):
                continue
            ref = core.default_dispvm_of(vm)
        except core.Unreadable as e:
            dd_unread.append(str(e).removeprefix("cannot read "))
            continue
        name = None if ref is None else str(getattr(ref, "name", ref))
        if name in unread:
            continue                        # its tags: the "qube tags" error names it
        if name and not (name in tags_by and core.UMBRELLA in tags_by[name]):
            dd.append(vm.name)
    if dd_unread:
        add("error", "default_dispvm", f"cannot read {', '.join(sorted(dd_unread))}")
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

    # 11. the runtime directory the caps rely on, and every file the services
    # share with root: each must be SERVICES_GROUP's and group-writable, or
    # their writes fail without a symptom.
    gid = _services_gid()
    if gid is None:
        add("fail", "services group", f"no group named {SERVICES_GROUP}: the services share "
                                      f"their runtime files with root through it")

    def shared(st) -> bool:
        return st is not None and bool(st.st_mode & stat.S_IWGRP) and st.st_gid == gid

    calls = os.path.join(core.RUN_DIR, "calls")
    run = _safe(lambda: os.stat(core.RUN_DIR))
    st = _safe(lambda: os.stat(calls))
    lock = _safe(lambda: os.stat(budget.LOCK_PATH))
    if st is None:
        add("fail", "runtime dir", f"{calls} missing (systemd-tmpfiles --create)")
    elif not (shared(run) and run.st_mode & stat.S_ISGID):
        # Where either side makes a lock again that went missing, so it must
        # stay the services' to open, whoever made it.
        add("fail", "runtime dir", f"{core.RUN_DIR} is not the services group's, group-writable "
                                   f"and setgid (2770 root:{SERVICES_GROUP}; systemd-tmpfiles "
                                   f"--create /etc/tmpfiles.d/qmcp.conf)")
    elif not shared(st):
        add("fail", "runtime dir", f"{calls} is not writable by the services group "
                                   f"(systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
    elif lock is not None and not shared(lock):
        add("fail", "runtime dir", f"{budget.LOCK_PATH} is not writable by the services group: "
                                   f"every create refuses (systemd-tmpfiles --create "
                                   f"/etc/tmpfiles.d/qmcp.conf)")
    else:
        add("pass", "runtime dir", calls)
    # The services cannot create a file in /var/log: a missing log, like one
    # of another group, stops their lines without a symptom.
    log = _safe(lambda: os.stat(audit.LOG_PATH))
    if not shared(log):
        add("fail", "audit log", f"{audit.LOG_PATH} is "
                                 f"{'missing' if log is None else 'not writable by the services group'}: "
                                 f"their audit lines stop without a symptom "
                                 f"(systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")

    # 11b. the proposal store: the services (a non-root dom0 user in `qubes`)
    # write proposals into it, and the operator's accept and reject (root)
    # write decisions the services must read back. Without the group's write
    # bit no proposal can be stored; without setgid a root-written decision is
    # root's group and unreadable to them.
    st = _safe(lambda: os.stat(proposals.PROPOSALS_DIR))
    lock = _safe(lambda: os.stat(proposals.LOCK_PATH))
    if st is None:
        add("fail", "proposal store", f"{proposals.PROPOSALS_DIR} missing "
                                      f"(systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
    elif not (shared(st) and st.st_mode & stat.S_ISGID):
        add("fail", "proposal store", f"{proposals.PROPOSALS_DIR} is not the services group's, "
                                      f"group-writable and setgid (2770 root:{SERVICES_GROUP}): "
                                      f"the hub's proposals cannot be stored, or their decisions "
                                      f"read back")
    elif lock is not None and not shared(lock):
        add("fail", "proposal store", f"{proposals.LOCK_PATH} is not writable by the services "
                                      f"group: every proposal the hub submits is refused "
                                      f"(systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
    else:
        try:
            rows = proposals.listing()
        except OSError as e:
            add("error", "proposal store", f"cannot read {proposals.PROPOSALS_DIR} "
                                           f"({e.strerror or type(e).__name__}); run as root")
        else:
            pending = sum(1 for r in rows if r["state"] == "pending")
            broken = [str(r["id"]) for r in rows if r["needs_closing"]]
            add("warn" if broken else "pass", "proposal store",
                f"proposal(s) {', '.join(broken)} with a file that does not read, or an accept "
                f"that did not finish: read them with qmcp proposal show N, then close them "
                f"with qmcp proposal reject N" if broken
                else f"{pending} pending, {len(rows) - pending} decided or expired")

    # 12. operator files
    caps_ok = budget.read_cap() is not None and budget.read_private_cap() is not None
    add("pass" if caps_ok else "fail", "disk caps",
        "pool-cap and private-cap readable" if caps_ok
        else f"{budget.CAP_PATH} or {budget.PRIVATE_CAP_PATH} missing or malformed")
    egress = _read_word(birth.BIRTH_EGRESS_PATH)
    if egress and not (registry and egress in registry):
        add("warn", "birth egress", f"'{egress}' is not an enrolled gateway; the hub's template "
                                    f"spawns will not use it")
    else:
        add("pass", "birth egress", egress or "not set (the hub's template spawns need the hub's "
                                              "own network enrolled)")

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
    out.extend(project_findings(vms, by_name, records, prefix, registry, tags_by))
    out.extend(lead_firewall_findings(app, by_name, records))
    quotas = sum(p.quota for p in records.values() if p.quota)
    cap = budget.read_cap()
    if cap is not None and quotas > cap:
        add("warn", "project quotas",
            f"they add up to {quotas // 1024 ** 3} GiB, more than the pool cap: a lead refused by "
            f"the cap inside its quota learns that the rest of AI space is full")
    return out


#: A value that could not be read, as a listing shows it: never a qube name or a
#: state, so nothing that compares it can take it for none or for a gateway's
#: name. In the true-or-false fields (`gateway`, `dvmt`, `lead`, and a gateway
#: row's `in_ai_space` and `upstream_ignores_firewall`) it is truthy: test those
#: with `is True`.
UNREADABLE = core.UNREADABLE


def _shown(read):
    """For display only: the value, or `UNREADABLE` when the read fails, never
    a default. Every decision reads through the strict readers instead."""
    try:
        return read()
    except Exception:
        return UNREADABLE


def _netvm_name(vm):
    """For display: the network's name, None for none, `UNREADABLE` when it
    cannot be read. Every decision reads it with `_netvm`, which raises."""
    try:
        return _netvm(vm)
    except NetvmUnreadable:
        return UNREADABLE


class NetvmUnreadable(Exception):
    pass


def _netvm(vm):
    """The qube's network, or None for none (dom0 and a RemoteVM have no
    network). Raises NetvmUnreadable when it cannot be read: a failed read is
    never "no network"."""
    try:
        if core.klass_of(vm) in core.NO_NETWORK_CLASSES:
            return None
        ref = vm.netvm      # never getattr with a default: qubesadmin's read errors are AttributeErrors
    except Exception:
        raise NetvmUnreadable(core.name_of(vm)) from None
    return None if ref is None else str(getattr(ref, "name", ref))


def project_findings(vms, by_name: dict, records: dict, prefix: str, registry=None,
                     tags_by=None) -> list:
    """The project invariants. The rulebook matches tags, not records, so a
    badge in the wrong place is a fail, not a warning: a slot badge outside AI
    space or left over from a deleted project is a dialog-free path for a lead.
    `tags_by` is the check's one tag read per qube; a qube missing from it is
    the check's "qube tags" error and judged by none of these."""
    if tags_by is None:
        tags_by = {}
        for vm in vms:
            try:
                tags_by[vm.name] = _tags(vm)
            except core.Unreadable:
                pass        # gone, or the check's "qube tags" error names it
    vms = [vm for vm in vms if vm.name in tags_by]
    out: list = []
    add = lambda *a: out.append(Finding(*a))  # noqa: E731
    slots_on, unread = {}, []
    bad_outside, bad_shape, stale, templates_in, stray_leads = [], [], [], [], []

    def role(vm):
        """'template', 'gateway' or None; None too, noted, when it cannot be read."""
        try:
            return "template" if core.is_template(vm) else "gateway" if core.is_gateway(vm) else None
        except core.Unreadable as e:
            unread.append(str(e))
            return None

    for vm in vms:
        tags = tags_by[vm.name]
        members, leads = projects.member_slots(tags), projects.lead_slots(tags)
        dumps = {p[1] for p in map(projects.slot_badge_parts, tags) if p and p[0] == "dump"}
        has_lead_tag = projects.LEAD in tags
        if not (members or leads or dumps or has_lead_tag):
            continue
        slots_on[vm.name] = (members, leads, dumps)
        if core.UMBRELLA not in tags and (members or leads or has_lead_tag):
            bad_outside.append(vm.name)
        if dumps and (core.UMBRELLA in tags or projects.DROP_BOX not in tags):
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
        if (members or leads) and role(vm):
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
                if vm is None:
                    lead_bad.append(f"{p.label}: {p.lead}")
                elif vm.name in tags_by and (not core.lead_badges_agree(tags_by[vm.name], p.slot)
                                             or role(vm)):
                    lead_bad.append(f"{p.label}: {p.lead}")
            for t in p.templates:
                vm = by_name.get(t)
                if vm is None or (vm.name in tags_by and (core.UMBRELLA not in tags_by[vm.name]
                                                          or role(vm) != "template")):
                    tpl_warn.append(f"{p.label}: {t}")
            for n in p.named_networks():
                if not registry or n not in registry:
                    net_warn.append(f"{p.label}: {n} is not an enrolled gateway")
            for vm in vms:
                if _member(tags_by[vm.name], p.slot):
                    try:
                        net = _netvm(vm)
                        disposable = core.klass_of(vm) == "DispVM"
                    except (NetvmUnreadable, core.Unreadable):
                        unread.append(f"cannot read the network or class of {p.label}'s member "
                                      f"{vm.name}")
                        continue
                    if net is not None and net not in p.named_networks() and not disposable:
                        net_warn.append(f"{p.label}: member {vm.name} is on {net}, not on the list")
        for name in names:
            vm = by_name.get(name)
            if vm is not None and name not in tags_by:
                continue                    # the check's "qube tags" error names it
            if vm is None or core.UMBRELLA in tags_by[name] \
                    or projects.dump_badge(p.slot) not in tags_by[name] \
                    or projects.DROP_BOX not in tags_by[name]:
                sink_bad.append(f"{p.slot}: {name}")
            else:
                try:
                    if _netvm(vm) is not None:
                        sink_warn.append(f"{p.slot}: {name} has a network")
                except NetvmUnreadable:
                    unread.append(f"cannot read the network of {p.slot}'s sink {name}")
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

    unslotted = []
    for vm in vms:
        tags = tags_by[vm.name]
        if core.UMBRELLA not in tags or core.GUARDED in tags or projects.LEAD in tags \
                or projects.member_slots(tags):
            continue
        try:
            if core.klass_of(vm) == "AppVM" and not core.is_template(vm) \
                    and not core.is_gateway(vm):
                unslotted.append(vm.name)
        except core.Unreadable as e:
            unread.append(str(e))
    if unslotted:
        add("warn", "managed qubes in no slot",
            f"{', '.join(unslotted)} (hub-only, copies by dialog; qmcp project move QUBE p00)")
    squat = []
    for p in records.values():
        if not p.label:
            continue
        space = p.space(prefix)
        squat += [vm.name for vm in vms if vm.name.startswith(space)
                  and not _member(tags_by[vm.name], p.slot) and vm.name != p.lead]
    if squat:
        add("warn", "project name spaces",
            f"inside a project's names but not its own: {', '.join(sorted(squat))} "
            f"(that project's lead can detect them through a create collision)")
    if unread:
        add("error", "project checks", "; ".join(sorted(set(unread))))
    return out


def _member(tags, slot: str) -> bool:
    """`core.is_member` on tags already read."""
    return core.UMBRELLA in tags and projects.member_badge(slot) in tags \
        and projects.LEAD not in tags


def lead_firewall_findings(app, by_name: dict, records: dict) -> list:
    """A lead's firewall is the operator's: it must still be the rules the
    operator accepted. A lead with no network needs none; a lead with one
    and no accepted rules on record (upgraded from 0.9.20) is warned about
    until the operator accepts its current rules or sets its model."""
    drift, unaccepted, unread = [], [], []
    for p in sorted(records.values(), key=lambda p: p.slot):
        if p.slot == projects.HUB_SLOT or p.lead is None or p.lead not in by_name:
            continue
        try:
            if _netvm(by_name[p.lead]) is None:
                continue
        except NetvmUnreadable:
            unread.append(f"{p.lead} (network)")
            continue
        if p.lead_firewall is None:
            unaccepted.append(f"{p.label}: {p.lead}")
            continue
        try:
            live = firewall.read_rules(app, p.lead)
        except Exception as e:
            unread.append(f"{p.lead} ({type(e).__name__})")
            continue
        if tuple(live) != tuple(p.lead_firewall):
            drift.append(f"{p.label}: {p.lead}")
    out = []
    if unread:
        out.append(Finding("error", "lead firewalls", f"cannot read: {', '.join(unread)}"))
    if drift:
        out.append(Finding("fail", "lead firewalls",
                           f"differ from the rules you accepted: {', '.join(drift)} "
                           f"(qmcp project firewall NAME shows both)"))
    elif not unread:
        out.append(Finding("pass", "lead firewalls", "every lead firewall you accepted is still as "
                                                     "you accepted it"))
    if unaccepted:
        out.append(Finding("warn", "lead firewalls not accepted",
                           f"{', '.join(unaccepted)}: accept the current rules with qmcp project "
                           f"firewall NAME --accept-current, or set the model with --model HOST:PORT"))
    return out


# ------------------------------------------------------------------ gateways

def _template_chain(vm) -> list:
    """The templates a qube's system comes from: its template, and that one's,
    up to the TemplateVM (a disposable's template is a disposable template).
    Raises `core.Unreadable`: a chain it cannot read is not a short one."""
    chain, seen = [], set()
    ref = core.template_of(vm)
    while ref is not None and ref.name not in seen:
        seen.add(ref.name)
        chain.append(ref)
        ref = core.template_of(ref)
    return chain


def gateway_refusal(by_name: dict, name: str, hub=None) -> str | None:
    """None if `name` may be an enrolled gateway, else why not.

    It provides network; it carries out its clients' firewall rules, by
    Qubes' own marker, and is not a Whonix gateway (Whonix's `anon-gateway`
    tag), which carries the marker and applies none of its clients' rules
    (measured on Whonix 18); its system comes from no template the hub manages
    (every template in its chain outside AI space or guarded), since a
    template the hub edits could switch its firewall off; it is not the hub,
    a drop box or a member or lead of a project; inside AI space it is guarded.
    A read that fails refuses it, until it reads.
    """
    try:
        return _gateway_refusal(by_name, name, hub)
    except core.Unreadable as e:
        return f"{e}, so it is refused until that reads"


def _gateway_refusal(by_name: dict, name: str, hub) -> str | None:
    vm = by_name.get(name)
    if vm is None or core.klass_of(vm) == "AdminVM":
        return "no such qube"
    if not core.is_gateway(vm):
        return "does not provide network"
    if name == (core.read_hub() if hub is None else hub):
        return "is the hub"
    try:
        tags = _tags(vm)
    except core.Gone:
        return "no such qube"
    if projects.DROP_BOX in tags or projects.LEAD in tags or projects.member_slots(tags) \
            or projects.lead_slots(tags):
        return "is a drop box, a lead or a project's member"
    if core.in_scope(vm) and core.GUARDED not in tags:
        return f"is in AI space without {core.GUARDED} (qmcp guard {name})"
    if gateways.WHONIX_GATEWAY_TAG in tags:
        return ("is a Whonix gateway, which applies none of its clients' firewall rules "
                "(measured): enroll a plain router in front of it instead")
    try:
        marker = vm.features.check_with_template(gateways.FIREWALL_FEATURE, None)
    except Exception:
        raise core.Unreadable(f"cannot read the {gateways.FIREWALL_FEATURE} feature of "
                              f"{name}") from None
    if marker in (None, "", "0", False, 0):
        return (f"Qubes' {gateways.FIREWALL_FEATURE} feature is not on for it (the qube's own "
                f"value, else its template's)")
    for tpl in _template_chain(vm):
        tpl_tags = _tags(tpl)
        if core.UMBRELLA in tpl_tags and core.GUARDED not in tpl_tags:
            return f"its template {tpl.name} is one the hub manages (guard it, or use another)"
    return None


def gateway_rows(app) -> list:
    """The registry as the operator reads it: each entry, whether it is still
    usable and why not, its upstream, and whether that upstream ignores its
    firewall rules (a Whonix gateway hands its clients' traffic to Tor
    locally; measured on Whonix 18). Also what uses it."""
    registry = gateways.load()
    by_name = {vm.name: vm for vm in app.domains}
    records = _load_records()
    # Each qube read once, for every entry: one in AI space, or whose tags
    # cannot be read (it may be), with its network, UNREADABLE when not read.
    # A qube qubesd says is gone is no user.
    on = []
    for v in by_name.values():
        try:
            if core.UMBRELLA not in core.tags_of(v):
                continue
        except core.Gone:
            continue
        except core.Unreadable:
            pass
        on.append((v.name, _netvm_name(v)))
    rows = []
    for name in sorted(registry):
        g, vm = registry[name], by_name.get(name)
        upstream = None if vm is None else _netvm_name(vm)
        up_vm = by_name.get(upstream) if upstream else None
        # A qube whose tags or network cannot be read may be on it: counted.
        users = sorted(n for n, net in on if net in (name, UNREADABLE))
        rows.append({"name": name, "anonymising": g.anonymising, "label": g.label,
                     "problem": gateway_refusal(by_name, name),
                     "in_ai_space": vm is not None and _shown(lambda: core.in_scope(vm)),
                     "upstream": upstream,
                     "upstream_ignores_firewall": UNREADABLE if upstream == UNREADABLE else
                     up_vm is not None and _shown(
                         lambda: gateways.WHONIX_GATEWAY_TAG in _tags(up_vm)),
                     "used_by": users,
                     "projects": sorted(p.label for p in records.values()
                                        if p.label and name in p.named_networks())})
    return rows


def enroll_gateway(app, name: str, anonymising: bool = False, label: str = "") -> str:
    err = gateways.label_refusal(label)
    if err:
        raise RoleError(err)
    with _Exclusive():
        registry = gateways.load()
        if name in registry:
            raise RoleError(f"'{name}' is enrolled already; change it with qmcp gateway set")
        if len(registry) >= gateways.MAX_GATEWAYS:
            raise RoleError(f"at most {gateways.MAX_GATEWAYS} gateways")
        why = gateway_refusal({vm.name: vm for vm in app.domains}, name)
        if why:
            raise RoleError(f"'{name}' cannot be enrolled: {why}")
        registry[name] = gateways.Gateway(name, bool(anonymising), label)
        gateways.save(registry)
    return f"{name}: enrolled{' (anonymising)' if anonymising else ''}"


def set_gateway(app, name: str, anonymising=None, label=None) -> str:
    if label is not None and gateways.label_refusal(label):
        raise RoleError(gateways.label_refusal(label))
    with _Exclusive():
        registry = gateways.load()
        g = registry.get(name)
        if g is None:
            raise RoleError(f"'{name}' is not enrolled")
        if anonymising is not None:
            g.anonymising = bool(anonymising)
        if label is not None:
            g.label = label
        gateways.save(registry)
    return f"{name}: {'anonymising' if g.anonymising else 'not anonymising'}, label '{g.label}'"


def remove_gateway(app, name: str) -> str:
    """Take a gateway out of the registry. Refused while a project lists it or
    an AI qube sits on it: they would be left on a network AI may not use."""
    with _Exclusive():
        registry = gateways.load()
        if name not in registry:
            raise RoleError(f"'{name}' is not enrolled")
        records = _load_records()
        listing_projects = sorted(p.label for p in records.values()
                                  if p.label and name in p.named_networks())
        users = []
        for vm in app.domains:
            try:
                if not core.in_scope(vm):
                    continue
            except core.Gone:
                continue
            except core.Unreadable:
                users.append(f"{vm.name} (tags unreadable)")
                continue
            try:
                if _netvm(vm) == name:
                    users.append(vm.name)
            except NetvmUnreadable:
                users.append(f"{vm.name} (network unreadable)")
        users.sort()
        if listing_projects or users:
            raise RoleError(f"'{name}' is in use: projects {listing_projects or '-'}, qubes "
                            f"{users or '-'}; take it off their lists and clear their networks first")
        del registry[name]
        gateways.save(registry)
    return f"{name}: no longer enrolled"


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
    steps, problems = [], []
    tags_by = {}
    for vm in app.domains:
        try:
            tags_by[vm.name] = _tags(vm)
        except core.Gone:
            pass
        except core.Unreadable as e:
            problems.append(f"{vm.name}: {e}; run the plan again")
    tiered = any(tags & LEGACY_TIER_TAGS for tags in tags_by.values())
    hub = core.read_hub()
    listed = read_guarded_list()
    if listed is _UNREADABLE:
        problems.append(f"{GUARDED_LIST_PATH} exists but cannot be read; it may name qubes "
                        f"v0.9.16 always refused. Fix or remove it first")
        listed = set()
    for vm in app.domains:
        if vm.name not in tags_by:
            continue
        tags = tags_by[vm.name]
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
        try:
            gateway = core.is_gateway(vm)
        except core.Unreadable as e:
            problems.append(f"{vm.name}: {e}; run the plan again")
            continue
        if gateway:
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
            try:
                pin = core.default_dispvm_of(vm) is not None
            except core.Unreadable as e:
                problems.append(f"{vm.name}: {e}; run the plan again")
                continue
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


def _read_tags(vm) -> set:
    """`_tags` for a role action: a read that fails stops it, in words."""
    try:
        return _tags(vm)
    except core.Unreadable as e:
        raise RoleError(f"{e}; try again") from None


def _target(app, name):
    if not core.valid_qube_name(name) or name not in app.domains:
        raise RoleError(f"no qube named '{name}'")
    if name == core.read_hub():
        raise RoleError(f"'{name}' is the hub; the hub is never in AI space")
    vm = app.domains[name]
    if "ai-dump" in _read_tags(vm):
        raise RoleError(f"'{name}' is a drop box (ai-dump); a drop box is never in AI space")
    return vm


def _is_gateway(vm) -> bool:
    try:
        return core.is_gateway(vm)
    except core.Unreadable as e:
        raise RoleError(f"{e}; try again") from None


def _pin_dispvm(vm, name) -> bool:
    """No default disposable template, set explicitly and read back: from AI
    space it could start a disposable outside it, and one that follows Qubes'
    global default would move with it. True when it changed the qube."""
    try:
        if core.default_dispvm_of(vm) is None and not vm.property_is_default("default_dispvm"):
            return False
        vm.default_dispvm = None
        if core.default_dispvm_of(vm) is not None or vm.property_is_default("default_dispvm"):
            raise RoleError(f"'{name}''s default disposable template did not read back as none")
        return True
    except core.Unreadable as e:
        raise RoleError(f"{e}; try again") from None
    except RoleError:
        raise
    except Exception as e:
        raise RoleError(f"'{name}''s default disposable template could not be pinned "
                        f"({type(e).__name__})") from None


def _network_enrolled(vm, name) -> None:
    """A qube joining AI space that is not itself a gateway must be on an
    enrolled gateway, or on none: `qmcp check` fails on any other, so the role
    action refuses first."""
    try:
        net = _netvm(vm)
    except NetvmUnreadable:
        raise RoleError(f"'{name}''s network cannot be read; try again") from None
    if net is not None and not _is_gateway(vm):
        try:
            enrolled = net in gateways.load()
        except gateways.GatewaysUnreadable:
            enrolled = False
        if not enrolled:
            raise RoleError(f"'{name}' is on {net}, which is not an enrolled gateway: enroll it "
                            f"(qmcp gateway enroll {net}) or clear the qube's network first")


def manage(app, name) -> str:
    vm = _target(app, name)
    if _is_gateway(vm):
        raise RoleError(f"'{name}' provides network; gateways are always guarded (qmcp guard)")
    _network_enrolled(vm, name)
    pinned = _pin_dispvm(vm, name)          # before it joins AI space
    try:
        vm.tags.add(core.UMBRELLA)
    except Exception as e:
        raise RoleError(f"'{name}' could not be added to AI space ({type(e).__name__})"
                        + ("; its default disposable template was cleared" if pinned else "")) from None
    try:
        tags = _tags(vm)
    except core.Unreadable as e:
        raise RoleError(f"'{name}' is in AI space now"
                        + ("; its default disposable template was cleared" if pinned else "")
                        + f", but {e}; run qmcp manage {name} again") from None
    for t in sorted((tags & LEGACY_TIER_TAGS) | ({core.GUARDED} & tags)):
        vm.tags.discard(t)
    return f"{name}: managed"


def _not_in_a_slot(vm, name, action: str) -> None:
    tags = _read_tags(vm)
    if projects.LEAD in tags or projects.lead_slots(tags):
        raise RoleError(f"'{name}' is a lead; use qmcp project lead <project> --remove first")
    if projects.member_slots(tags) and action != "revoke":
        raise RoleError(f"'{name}' is in a project slot; qmcp project move {name} none first")


def guard(app, name) -> str:
    vm = _target(app, name)
    _not_in_a_slot(vm, name, "guard")
    _network_enrolled(vm, name)
    vm.tags.add(core.GUARDED)
    vm.tags.add(core.UMBRELLA)
    try:
        tags = _tags(vm)
    except core.Unreadable as e:
        raise RoleError(f"'{name}' is guarded now, but {e}; run qmcp guard {name} again") from None
    for t in sorted(tags & LEGACY_TIER_TAGS):
        vm.tags.discard(t)
    return f"{name}: guarded"


def revoke(app, name, shutdown: bool = True) -> str:
    """Strip every AI-space badge, pin default_dispvm, and shut the qube down
    Restrictions such as an egress lock go too: revoke is yours."""
    vm = _target(app, name)
    _not_in_a_slot(vm, name, "revoke")
    for t in sorted((t for t in _read_tags(vm) if birth.controlled(t)), key=_removal_order):
        vm.tags.discard(t)
    try:
        left = sorted(t for t in _tags(vm) if birth.controlled(t))
    except core.Unreadable as e:
        raise RoleError(f"'{name}''s badges were taken off, but {e}; run qmcp revoke {name} "
                        f"again") from None
    if left:
        raise RoleError(f"'{name}' still wears {', '.join(left)}; run qmcp revoke {name} again")
    try:
        _pin_dispvm(vm, name)
    except RoleError as e:
        raise RoleError(f"'{name}' is out of AI space, but {e}") from None
    msg = f"{name}: revoked"
    if shutdown:
        power = _safe(vm.get_power_state, "unknown")
        if power in ("NA", "unknown"):
            msg += f", power state unreadable, so not shut down (qvm-shutdown {name})"
        elif power != "Halted":
            try:
                vm.shutdown()
                msg += ", shutdown requested"
            except Exception as e:
                msg += f", shutdown failed ({type(e).__name__}); kill it with qvm-kill {name}"
    return msg


def listing(app, everything: bool = False) -> list:
    """One row per qube in AI space. `everything` adds every other qube but
    dom0, with state None: the operator's window offers them when a qube joins
    AI space, as a lead's template, and as a gateway to enroll."""
    rows = []
    for vm in app.domains:
        klass = _shown(lambda: core.klass_of(vm))
        if klass == "AdminVM":
            continue
        try:
            tags = _tags(vm)
        except core.Gone:
            continue
        except core.Unreadable:
            tags = None             # listed as UNREADABLE: it may be in AI space
        st = UNREADABLE if tags is None else None if core.UMBRELLA not in tags else \
            "guarded" if core.is_guarded(vm, tags) else "managed"
        if st is None and not everything:
            continue
        tpl = _shown(lambda: core.template_of(vm))
        slots = set() if tags is None else projects.member_slots(tags) | projects.lead_slots(tags)
        rows.append({
            "name": vm.name, "state": st, "klass": klass,
            "template": tpl if tpl in (None, UNREADABLE) else str(getattr(tpl, "name", tpl)),
            "netvm": _netvm_name(vm),
            "power": _safe(vm.get_power_state, "unknown"),
            # What the tags say is not known when they cannot be read: never empty.
            "slot": UNREADABLE if tags is None else ",".join(sorted(slots)) or None,
            "lead": UNREADABLE if tags is None else projects.LEAD in tags,
            "owner": UNREADABLE if tags is None else _owner(tags),
            "gateway": _shown(lambda: core.is_gateway(vm)),
            "dvmt": _shown(lambda: core.is_dvmt(vm)),
            "badges": None if tags is None else
            sorted(t for t in tags if birth.controlled(t) or t == projects.DROP_BOX),
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
        "gateways_enrolled": _safe(lambda: len(gateways.load())),
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
        n = value
    else:
        n = parse_size(value)
    if n > projects.MAX_QUOTA:
        raise ProjectError("a quota is at most 1 EiB")
    return n


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
    """The qube called `name`, or None when there is none. A lookup that fails
    raises `core.Unreadable`: it is no proof that the qube is gone."""
    if not core.valid_qube_name(name):
        return None
    try:
        return app.domains[name] if name in app.domains else None
    except Exception:
        raise core.Unreadable(f"cannot look up {name}") from None


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


#: How deep this process holds both project locks: an accepted proposal takes
#: them before it runs its command, which then takes them again.
_HELD = [0]


class _Exclusive:
    """Both locks, for one project command (see above). Re-entrant within the
    process: a second flock on a new descriptor of the same file would wait
    for the first, here, and fail when the records lock gives up (30 s)."""

    def __enter__(self):
        if _HELD[0]:
            _HELD[0] += 1
            self.nested = True
            return self
        self.nested = False
        self.records_lock = projects.Locked()
        self.records_lock.__enter__()
        try:
            self.fd = budget.acquire_create_lock()
        except core.Refusal:
            self.records_lock.__exit__(None, None, None)
            raise ProjectError("a create is in progress; try again in a moment") from None
        _HELD[0] = 1
        return self

    def __exit__(self, *exc):
        _HELD[0] -= 1
        if not self.nested:
            os.close(self.fd)
            self.records_lock.__exit__(*exc)
        return False


def hold_project_locks():
    """Both project locks, held across several commands (an accepted proposal
    holds them from its second tick through its command)."""
    return _Exclusive()


class Report(list):
    """A command's report: its lines, and the steps that did not complete.
    Whether a command failed is read from `failed`, never from its text: a
    line holds names, and a name may hold any word."""

    def __init__(self):
        super().__init__()
        self.failed: list = []

    def fail(self, line: str) -> None:
        self.append(line)
        self.failed.append(line)


def _run(command, *args, **kwargs) -> Report:
    """Run a project command under both locks. Its exception, if any, carries
    `report`: the steps that completed before it failed."""
    report = Report()
    with _Exclusive():
        try:
            command(report, *args, **kwargs)
        except core.Unreadable as e:
            # A read that failed stops the command where it was, in words. The
            # report holds the steps that completed; a write after the last of
            # them may have landed too, so the message never says that nothing
            # changed.
            err = ProjectError(f"{e}; stopped there (qmcp check shows what is left)")
            err.report = list(report)
            raise err from None
        except Exception as e:
            e.report = list(report)
            raise
    return report


def _template_name(vm):
    ref = core.template_of(vm)
    return None if ref is None else str(getattr(ref, "name", ref))


def _check_templates(app, names) -> list:
    out = []
    for name in names:
        vm = _vm(app, name)
        if vm is None or not core.in_scope(vm) or not core.is_template(vm):
            raise ProjectError(f"'{name}' is not a template or disposable template in AI space")
        if name not in out:
            out.append(name)
    if not out:
        raise ProjectError("a project needs at least one approved template in AI space")
    return out


def _registry() -> dict:
    try:
        return gateways.load()
    except gateways.GatewaysUnreadable as e:
        raise ProjectError(f"{gateways.GATEWAYS_PATH} is unreadable ({e}); fix it before "
                           f"changing networks") from None


def _usable_gateway(app, registry: dict, net: str) -> None:
    """An enrolled gateway that still qualifies. One that stopped (`qmcp check`
    fails on it) is refused here, as a project's network or a lead's, until it
    is fixed or removed; the services still place new qubes on it while it
    stays enrolled."""
    if net not in registry:
        raise ProjectError(f"'{net}' is not an enrolled gateway (qmcp gateway enroll {net})")
    why = gateway_refusal({vm.name: vm for vm in app.domains}, net)
    if why:
        raise ProjectError(f"'{net}' is enrolled but not usable: {why}")


def _check_networks(app, names) -> list:
    registry = _registry()
    out = []
    for name in names:
        net = None if name in (None, "none") else name
        if net is not None:
            _usable_gateway(app, registry, net)
        if net in out:
            raise ProjectError(f"network '{name}' is listed twice")
        out.append(net)
    if not out:
        raise ProjectError("a project needs at least one worker network (a gateway, or none)")
    return out


def _check_lead_netvm(app, name):
    if name in (None, "none"):
        return None
    _usable_gateway(app, _registry(), name)
    return name


def _lead_network(app, source: str, origin: str, lead_netvm):
    """The network a new lead will have: the one given, or for a promoted
    lead its own. Either way it must be enrolled, or none."""
    if source == "promote":
        vm = _vm(app, origin)
        try:
            current = None if vm is None else _netvm(vm)
        except NetvmUnreadable:
            raise ProjectError(f"the network of '{origin}' cannot be read") from None
        if lead_netvm not in (None, "none", current):
            raise ProjectError("a promoted lead keeps its own network, since no network moves: "
                               "give it none (--lead-netvm none), or make a fresh lead")
        if lead_netvm == "none":
            return None
        return None if current is None else _check_lead_netvm(app, current)
    return _check_lead_netvm(app, lead_netvm)


def _lead_rules(app, source: str, origin: str, lead_netvm, model):
    """(canonical model or None, the rules dom0 writes into the new lead or None).
    A lead with a network gets "model endpoint only", so it needs a model; a
    promoted lead keeps its own network unless given none, and that network
    must be enrolled. A lead with no network needs no firewall."""
    net = _lead_network(app, source, origin, lead_netvm)
    if model is None:
        if net is not None:
            raise ProjectError("a lead with a network needs its model endpoint (--model HOST:PORT): "
                               "dom0 writes its firewall to allow that endpoint and DNS, "
                               "nothing else")
        return None, None
    try:
        model = firewall.model_text(model)
    except firewall.FirewallError as e:
        raise ProjectError(str(e)) from None
    if net is None:
        raise ProjectError("a lead with no network reaches no model endpoint; drop --model")
    return model, firewall.endpoint_rules(model)


def _hubs_own_appvm(app, name, what: str):
    """A managed AppVM of the hub's (p00 or no slot): a lead's clone source or a
    qube to promote. Never a template, gateway, guarded qube, lead, drop box
    or another project's member."""
    vm = _vm(app, name)
    tags = set() if vm is None else _tags(vm)
    if core.UMBRELLA not in tags:
        raise ProjectError(f"no qube '{name}' in AI space")
    if core.klass_of(vm) != "AppVM" or core.is_template(vm) or core.is_gateway(vm):
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
    if vm is None or core.klass_of(vm) != "TemplateVM":
        raise ProjectError(f"'{name}' is not a TemplateVM")
    return vm


def _badges_of_slot(app, slot: str) -> tuple:
    """(every qube still wearing a badge of `slot`, every qube whose tags
    cannot be read): either keeps the slot from being reused."""
    out, unread = [], []
    for vm in app.domains:
        try:
            tags = _tags(vm)
        except core.Gone:
            continue
        except core.Unreadable:
            unread.append(vm.name)
            continue
        if any((p := projects.slot_badge_parts(t)) and p[1] == slot for t in tags):
            out.append(vm.name)
    return out, unread


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


def _not_removed(report, slot: str, name: str, err: str) -> None:
    report.fail(f"{slot}: NOT removed: {err}; if it still runs, kill it by hand (qvm-kill {name})")


def _remove_qube(app, name) -> str:
    """Kill and remove a qube; '' when it is gone, else why not."""
    import time
    try:
        vm = _vm(app, name)
    except core.Unreadable:
        return f"{name}: cannot be looked up"
    if vm is None:
        return ""
    try:
        if _safe(vm.get_power_state, "unknown") != "Halted":
            try:
                vm.kill()
            except Exception:
                pass                # not running after all; the remove below decides
        deadline = time.monotonic() + HALT_WAIT_S
        # "NA": qubesadmin's answer for a qube it cannot read, one qubesd removed
        # when it was killed included; the remove below decides, as for any.
        while _safe(vm.get_power_state, "Halted") not in ("Halted", "NA", None) \
                and time.monotonic() < deadline:
            time.sleep(0.5)
        if name in app.domains:
            del app.domains[name]
    except KeyError:
        pass
    except Exception as e:
        return f"{name}: {type(e).__name__}"
    try:
        return "" if _vm(app, name) is None else f"{name}: still present"
    except core.Unreadable:
        return f"{name}: cannot be looked up, so not known to be removed"


def _plan_lead(app, space: str, source: str, origin: str, lead_netvm, name=None,
               freed: str | None = None, model=None) -> str:
    """Everything about a new lead that can be checked without changing
    anything; returns the name it will have. `freed` is a name that will be
    free by the time the lead is made (an old lead that is removed first)."""
    if source == "template":
        _lead_template(app, origin)
    elif source in ("clone", "promote"):
        _hubs_own_appvm(app, origin, "the lead")
    else:
        raise ProjectError(f"unknown lead source '{source}'")
    _lead_rules(app, source, origin, lead_netvm, model)
    if source == "promote":
        return origin
    name = name or f"{space}lead"
    if not name.startswith(space) or birth.name_refusal(name, space):
        raise ProjectError(f"the lead's name must be inside '{space}'")
    if _vm(app, name) is not None and name != freed:
        raise ProjectError(f"'{name}' exists; pass --lead-name for the new lead")
    return name


#: `_undo_lead`'s default: the promoted qube's network was left as it was.
_UNCHANGED = object()


def _make_lead(app, slot: str, source: str, origin: str, name: str, lead_netvm, model=None):
    """Make `name` the lead of `slot`, as planned by `_plan_lead`. Returns
    (name, created, badges the qube had, accepted rules, rules it had, network
    it had) so a later failure can undo exactly. A fresh lead is born on
    `lead_netvm`; a promoted one keeps its network unless given none. A lead
    with a network gets "model endpoint only", written once it wears
    `qmcp-lead`, which already bars the hub's firewall writes, and before its
    slot's lead badge, which the rulebook routes on; its network is set or
    cleared before that badge too. So a lead never holds the slot's badge with
    a wider firewall or the network it is leaving. On failure it undoes what it
    did (`_undo_lead`: a fresh lead is removed; a promoted one gets back its
    badges, then its rules, then its network), stops at the first step it
    cannot undo, and names it."""
    want = {core.UMBRELLA, projects.LEAD, projects.lead_badge(slot)}
    _, rules = _lead_rules(app, source, origin, lead_netvm, model)
    if source == "promote":
        vm = _hubs_own_appvm(app, origin, "a promoted lead")
        netvm = _lead_network(app, source, origin, lead_netvm)
        before = {projects.member_badge(s) for s in projects.member_slots(_tags(vm))}
        old_rules = firewall.read_rules(app, origin) if rules else None
        try:
            old_net = _netvm(vm) if lead_netvm == "none" else _UNCHANGED
        except NetvmUnreadable:
            raise ProjectError(f"the network of '{origin}' cannot be read") from None
        stored = None
        try:
            # `qmcp-lead` first: it grants nothing alone (the services refuse a
            # lead without its record, and the slot lines need the slot's
            # badge), and the rulebook denies the hub any firewall write to a
            # qube wearing it (A1b). A hub write admitted just before is
            # overwritten if it lands first, fails the read-back below if it
            # lands between the write and the read-back, and shows in
            # `qmcp check` if it lands later.
            _set_tags(vm, add={projects.LEAD})
            if rules:
                stored = firewall.write_rules(app, origin, rules)
            if lead_netvm == "none":
                vm.netvm = None
            if _netvm(vm) != netvm:
                raise RuntimeError("the lead's network did not read back")
            # Out of its slot, then the slot's lead badge: never both at once.
            _set_tags(vm, remove=before)
            _set_tags(vm, add=want)
        except Exception as e:
            err = _undo_lead(app, origin, False, slot, before, old_rules, old_net)
            if err:
                raise ProjectError(f"making the lead failed ({type(e).__name__}) and undoing it "
                                   f"did not finish: {err}") from e
            raise
        return origin, False, before, stored, old_rules, old_net
    netvm = _check_lead_netvm(app, lead_netvm)
    if source == "template":
        _lead_template(app, origin)
        vm = app.add_new_vm("AppVM", name, LEAD_LABEL, template=origin)
    else:
        vm = app.clone_vm(_hubs_own_appvm(app, origin, "a lead's clone source"), name)
    stored = None
    try:
        birth.stamp(birth.TagIO.for_vm(vm), _tags(vm), "dom0", None)
        # `qmcp-lead` before the rules (see promote above), the slot's badge last.
        _set_tags(vm, add={projects.LEAD})
        if rules:
            stored = firewall.write_rules(app, name, rules)
        vm.netvm = netvm
        vm.default_dispvm = None
        if _netvm(vm) != netvm or core.default_dispvm_of(vm) is not None:
            raise RuntimeError("the lead's network did not read back")
        _set_tags(vm, add=want)
    except Exception as e:
        err = _remove_qube(app, name)
        if err:
            raise ProjectError(f"making the lead failed ({type(e).__name__}) and the new qube "
                               f"could not be removed: {err}") from e
        raise
    return name, True, set(), stored, None, _UNCHANGED


def _undo_lead(app, lead: str, fresh: bool, slot: str, before=frozenset(),
               old_rules=None, old_net=_UNCHANGED) -> str:
    """Undo `_make_lead`: remove a lead it made; give a promoted one back
    exactly the badges it had, removing first, so a failure never leaves a
    qube with more authority than before, then its old firewall, then the
    network it had if it was cleared. '' when undone, else why not."""
    if fresh:
        return _remove_qube(app, lead)
    try:
        vm = _vm(app, lead)
    except core.Unreadable:
        return f"{lead}: cannot be looked up"
    if vm is not None:
        try:
            _set_tags(vm, remove={projects.LEAD, projects.lead_badge(slot)})
            _set_tags(vm, add=set(before))
        except Exception as e:
            return f"{lead}: badges {type(e).__name__}"
        if old_rules is not None:
            try:
                firewall.restore_rules(app, lead, old_rules)
            except Exception as e:
                return f"{lead}: firewall {type(e).__name__}"
        if old_net is not _UNCHANGED:
            try:
                vm.netvm = old_net
                if _netvm(vm) != old_net:
                    raise RuntimeError("did not read back")
            except Exception as e:
                return f"{lead}: network {type(e).__name__}"
    return ""


def _recorded_lead(app, p):
    """The project's recorded lead, only while it wears the slot's lead badge.
    A recorded name whose qube was removed by hand may since name another qube,
    which must be left alone. A lookup or tag read that fails raises: a lead it
    cannot read is never taken for one that does not wear the badge."""
    vm = _vm(app, p.lead) if p.lead else None
    if vm is None or projects.lead_badge(p.slot) not in _tags(vm):
        return None
    return vm


def _demote_lead(app, p, report: list, removing: bool = False) -> bool:
    """Take the lead's authority first: its badges, which the rulebook routes on
    and the services require. Then a kill. A call it already started may still
    finish: a create re-checks its caller under the create lock, which this
    command holds; a lifecycle, property or feature change already past its
    check completes. A recorded name whose qube does not wear the slot's lead
    badge is left alone and reported as a failure: what that qube is, the
    operator decides. A recorded name with no qube is noted. True when it
    demoted the recorded lead. `removing`: the caller removes the qube once the
    record is saved, and that removal's result says whether it is gone."""
    vm = _vm(app, p.lead) if p.lead else None
    if vm is None:
        if p.lead:
            report.append(f"{p.slot}: no qube is named {p.lead} now")
        return False
    if projects.lead_badge(p.slot) not in _tags(vm):
        if removing:
            report.fail(f"{p.slot}: {p.lead} does not wear {p.slot}'s lead badge, so it was not "
                        f"demoted or killed; if it is the old lead and still there after this "
                        f"command, remove it by hand")
        else:
            report.fail(f"{p.slot}: {p.lead} does not wear {p.slot}'s lead badge, so it was not "
                        f"demoted, killed or kept as a worker; if it is the old lead, take its "
                        f"lead badges off by hand and move it in (qmcp project move {p.lead} "
                        f"{p.label})")
        return False
    try:
        _set_tags(vm, remove={projects.LEAD, projects.lead_badge(p.slot)})
        report.append(f"{p.slot}: {p.lead} is no longer the lead")
    except core.Unreadable as e:
        # The removes went through; only their read-back failed. The kill and
        # the record must not wait on a read: a lead left running unrecorded
        # would keep its network and lose A1b's guard on its firewall.
        report.fail(f"{p.slot}: {p.lead}'s lead badges were taken off, but {e}; qmcp check "
                    f"shows whether any is left")
    power = _safe(vm.get_power_state, "unknown")
    if power != "Halted":
        try:
            vm.kill()
        except Exception as e:
            if removing:
                report.append(f"{p.slot}: kill of {p.lead} failed ({type(e).__name__}); its "
                              f"removal, once the record is saved, tries again")
            elif (after := _safe(vm.get_power_state, "unknown")) != "Halted":
                report.fail(f"{p.slot}: kill of {p.lead} failed ({type(e).__name__}, power "
                            f"state {after}): it no longer acts as the lead, but it may still "
                            f"be running; if it is, kill it by hand (qvm-kill {p.lead})")
    return True


def create_project(app, label: str, lead_source: str, lead_origin: str, templates=(),
                   networks=(), quota=None, lead_netvm=None, dump: bool = False,
                   lead_name: str | None = None, model: str | None = None) -> list:
    """Make a project; returns the report lines. The record is written last, so
    the lead is no principal until everything else is in place."""
    return _run(_create_project, app, label, lead_source, lead_origin, templates, networks,
                quota, lead_netvm, dump, lead_name, model)


def _create_project(report, app, label, lead_source, lead_origin, templates, networks, quota,
                    lead_netvm, dump, lead_name, model=None):
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
    leftover, unread = _badges_of_slot(app, slot)
    if leftover:
        raise ProjectError(f"slot {slot} still has badges on {', '.join(leftover)}; "
                           f"finish with: qmcp project delete {slot} --yes")
    if unread:
        raise ProjectError(f"cannot read the tags of {', '.join(unread)}, so slot {slot} is not "
                           f"known to be free; try again")
    squatters = [vm.name for vm in app.domains if vm.name.startswith(space)]
    if squatters:
        raise ProjectError(f"qubes already sit in '{space}': {', '.join(squatters)}")
    sink = f"{label}-dump" if dump else None
    if sink and (sink.startswith(prefix) or not core.valid_qube_name(sink)
                 or _vm(app, sink) is not None):
        raise ProjectError(f"the dump sink '{sink}' would be inside '{prefix}', is no qube name, "
                           f"or exists")
    name = _plan_lead(app, space, lead_source, lead_origin, lead_netvm, lead_name, model=model)
    model, _ = _lead_rules(app, lead_source, lead_origin, lead_netvm, model)
    lead_tpl = lead_origin if lead_source == "template" else _template_name(_vm(app, lead_origin))
    tpls = list(templates)
    if lead_tpl and (vm := _vm(app, lead_tpl)) is not None and core.in_scope(vm):
        tpls.insert(0, lead_tpl)
    tpls = _check_templates(app, tpls)
    nets = _check_networks(app, networks)
    lead, fresh, before, stored, old_rules, old_net = _make_lead(app, slot, lead_source,
                                                                 lead_origin, name, lead_netvm,
                                                                 model)
    report.append(f"{slot}: lead {lead} ({'created' if fresh else 'promoted'})"
                  + (f", firewall: {model} and DNS only" if stored else ""))
    try:
        if sink:
            _make_sink(app, slot, sink)
            report.append(f"{slot}: dump sink {sink} created (no network)")
        records[slot] = projects.Project(slot, label, lead, tpls, nets, quota, sink, model, stored)
        projects.save(records)
    except Exception:
        left = [err for err in ((_remove_qube(app, sink) if sink else ""),
                                _undo_lead(app, lead, fresh, slot, before, old_rules,
                                           old_net)) if err]
        if left:
            report.fail(f"{slot}: NOT undone: {'; '.join(left)}")
        else:
            report.append(f"{slot}: undone")
        raise
    report.append(f"{slot}: project '{label}' recorded; workers are named {space}*")


def _make_sink(app, slot: str, name: str):
    """A fresh drop box: ai-dump + the slot's dump badge, no network, outside AI space."""
    if _vm(app, name) is not None:
        raise ProjectError(f"'{name}' exists; a dump sink is always a fresh qube")
    try:
        tpl = app.default_template
    except Exception:
        raise ProjectError("cannot read Qubes' default template for the dump sink") from None
    if tpl is None:
        raise ProjectError("Qubes has no default template for the dump sink")
    vm = app.add_new_vm("AppVM", name, SINK_LABEL, template=tpl)
    try:
        _set_tags(vm, add={projects.DROP_BOX, projects.dump_badge(slot)})
        vm.netvm = None
        vm.default_dispvm = None
        if _netvm(vm) is not None:
            raise RuntimeError("the sink's network did not read back as none")
    except Exception as e:
        err = _remove_qube(app, name)
        if err:
            raise ProjectError(f"the dump sink {name} failed ({type(e).__name__}) and could not be "
                               f"removed: {err}") from e
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
    ours = _demote_lead(app, p, report, removing=True)
    # The accepted rules were the removed lead's; the model stays for the next one.
    old, p.lead, p.lead_firewall = p.lead, None, None
    projects.save(records)
    report.append(f"{p.slot}: the record names no lead")
    if ours:
        err = _remove_qube(app, old)
        report.append(f"{p.slot}: removed {old}") if not err else \
            _not_removed(report, p.slot, old, err)


def set_lead(app, key: str, lead_source: str, lead_origin: str, lead_netvm=None,
             keep_old: bool = False, lead_name: str | None = None, model: str | None = None,
             add_old_network: bool = False) -> list:
    """Give a project a new lead. Everything about the new lead is checked
    before the old one is touched. The old one is removed, or kept as a worker
    of the same project, never as one of the hub's qubes. A kept lead keeps
    its network when the project lists it; otherwise `add_old_network` adds
    it to the list, and without that the old lead loses its network. The new
    lead gets `model`; one with a network and no `model` takes the project's,
    and one with no network leaves the project with none."""
    return _run(_set_lead, app, key, lead_source, lead_origin, lead_netvm, keep_old, lead_name,
                model, add_old_network)


def _set_lead(report, app, key, lead_source, lead_origin, lead_netvm, keep_old, lead_name,
              model=None, add_old_network=False):
    prefix = birth.read_name_prefix()
    records = _load_records()
    p = _project(records, key)
    old_vm = _recorded_lead(app, p)
    old_net, disconnect = None, False
    if add_old_network and not keep_old:
        raise ProjectError("--add-old-network goes with --keep-old")
    if keep_old and old_vm is not None:
        try:
            old_net = _netvm(old_vm)
        except NetvmUnreadable:
            raise ProjectError(f"the network of the old lead {p.lead} cannot be read") from None
        if old_net is not None and old_net not in p.named_networks():
            if add_old_network:
                if len(p.networks) >= projects.MAX_NETWORKS:
                    raise ProjectError(f"the project lists {projects.MAX_NETWORKS} networks already; "
                                       f"take one off before adding the old lead's")
                p.networks = tuple(_check_networks(app, p.networks + (old_net,)))
            else:
                disconnect = True
    if model is None and _lead_network(app, lead_source, lead_origin, lead_netvm) is not None:
        model = p.model         # the project's model carries over to a new lead with a network
    freed = None if (keep_old or old_vm is None) else p.lead
    if (keep_old and old_vm is not None and lead_source != "promote"
            and (lead_name or f"{p.space(prefix)}lead") == p.lead):
        raise ProjectError(f"the old lead keeps the name {p.lead}; pass --lead-name for the new one")
    name = _plan_lead(app, p.space(prefix), lead_source, lead_origin, lead_netvm, lead_name, freed,
                      model=model)
    model, _ = _lead_rules(app, lead_source, lead_origin, lead_netvm, model)
    try:
        projects.parse(projects.dump_json(records))     # the record as it will be saved
    except projects.ProjectsUnreadable as e:
        raise ProjectError(f"the project's record would not be valid: {e}") from None
    old = p.lead
    if old is not None:
        ours = _demote_lead(app, p, report, removing=not keep_old)
        # The accepted rules were that lead's; the model stays for the next one.
        p.lead, p.lead_firewall = None, None
        projects.save(records)
        report.append(f"{p.slot}: the record names no lead now")
        if ours and keep_old:
            old_vm = _vm(app, old)
            if disconnect:
                # Off the network before it joins: never a moment as a worker
                # on a network its project does not list.
                old_vm.netvm = None
                report.append(f"{p.slot}: {old} lost its network ({old_net} is not on the list)")
            elif add_old_network and old_net is not None:
                report.append(f"{p.slot}: {old_net} added to the worker networks")
            try:
                _set_tags(old_vm, add={projects.member_badge(p.slot)})
                report.append(f"{p.slot}: {old} kept as a worker")
            except core.Unreadable as e:
                report.fail(f"{p.slot}: {old} was kept as a worker, but {e}")
        elif ours:
            err = _remove_qube(app, old)
            report.append(f"{p.slot}: removed {old}") if not err else \
                _not_removed(report, p.slot, old, err)
    lead, fresh, before, stored, old_rules, old_net = _make_lead(app, p.slot, lead_source,
                                                                 lead_origin, name, lead_netvm,
                                                                 model)
    try:
        tpl = lead_origin if lead_source == "template" else _template_name(_vm(app, lead))
        if tpl and tpl not in p.templates and (vm := _vm(app, tpl)) is not None \
                and core.in_scope(vm) and core.is_template(vm):
            p.templates = p.templates + (tpl,)
    except core.Unreadable as e:
        # The new lead is made: a read here must not leave it unrecorded. Its
        # template stays off the list, one fewer, never one more.
        report.append(f"{p.slot}: {e}, so the lead's template was not added to the approved list")
    p.lead, p.model, p.lead_firewall = lead, model, stored
    try:
        projects.save(records)
    except Exception as e:
        err = _undo_lead(app, lead, fresh, p.slot, before, old_rules, old_net)
        if err:
            report.fail(f"{p.slot}: the new lead NOT undone: {err}")
            raise ProjectError(f"saving the record failed ({type(e).__name__}) and undoing the "
                               f"new lead did not finish: {err}") from e
        raise
    report.append(f"{p.slot}: lead {lead} ({'created' if fresh else 'promoted'})"
                  + (f", firewall: {model} and DNS only" if stored else ""))


def edit_project(app, key: str, templates=None, networks=None, quota=None) -> list:
    """Replace the approved templates or worker networks, or change the quota.
    Existing workers keep their networks: no network is moved after birth."""
    return _run(_edit_project, app, key, templates, networks, quota)


def _edit_project(report, app, key, templates, networks, quota):
    records = _load_records()
    _apply_edit(report, app, records, _project(records, key), templates, networks, quota)


def _networks_in_use(app, p, gone) -> list:
    """The members of `p` sitting on one of the networks in `gone`; a member
    whose network cannot be read counts as one, and so does a qube whose tags
    cannot be read."""
    out = []
    for vm in app.domains:
        try:
            if not core.is_member(vm, p.slot):
                continue
        except core.Gone:
            continue
        except core.Unreadable:
            out.append(f"{vm.name} (tags unreadable)")
            continue
        try:
            net = _netvm(vm)
        except NetvmUnreadable:
            out.append(f"{vm.name} (network unreadable)")
            continue
        if net is not None and net in gone:
            out.append(f"{vm.name} on {net}")
    return sorted(out)


def _apply_edit(report, app, records, p, templates, networks, quota):
    if templates is not None:
        p.templates = tuple(_check_templates(app, templates))
    if networks is not None:
        new = tuple(_check_networks(app, networks))
        in_use = _networks_in_use(app, p, set(p.named_networks()) - set(new))
        if in_use:
            raise ProjectError(f"still in use: {', '.join(in_use)}; remove those workers, or "
                               f"clear their networks, before taking the network off the list")
        p.networks = new
    if quota is not None:
        p.quota = _quota(quota)
    projects.save(records)
    report.append(f"{p.slot}: templates {list(p.templates)}, networks "
                  f"{[n or 'none' for n in p.networks]}, quota {p.quota}")


def edited(p, add_templates=(), remove_templates=(), add_networks=(), remove_networks=(),
           default_network=None, quota=None) -> tuple:
    """A project's (templates, networks, quota) after an edit that says what it
    adds, removes or sets: an accepted proposal's, applied to the record as it
    is then, changing only the entries it names: a later change of the
    operator's to anything else stands. Adding what is there or removing what
    is not changes nothing. `none` is the no-network
    entry; the default network, if given, moves to the front."""
    nets = lambda names: [None if n in (None, "none") else n for n in names]  # noqa: E731
    gone = set(remove_templates)
    templates = [t for t in p.templates if t not in gone]
    templates += [t for t in add_templates if t not in templates]
    gone = set(nets(remove_networks))
    networks = [n for n in p.networks if n not in gone]
    networks += [n for n in nets(add_networks) if n not in networks]
    if default_network is not None:
        first = nets([default_network])[0]
        if first not in networks:
            raise ProjectError(f"the default network {default_network} is not on the list")
        networks.remove(first)
        networks.insert(0, first)
    return templates, networks, p.quota if quota is None else quota


def edit_project_changes(app, key: str, add_templates=(), remove_templates=(), add_networks=(),
                         remove_networks=(), default_network=None, quota=None) -> list:
    """An edit that says what it adds, removes or sets, computed from the record
    under the lock and then checked exactly as `edit_project` checks."""
    return _run(_edit_changes, app, key, add_templates, remove_templates, add_networks,
                remove_networks, default_network, quota)


def _edit_changes(report, app, key, add_templates, remove_templates, add_networks,
                  remove_networks, default_network, quota):
    records = _load_records()
    p = _project(records, key)
    templates, networks, new_quota = edited(p, add_templates, remove_templates, add_networks,
                                            remove_networks, default_network, quota)
    _apply_edit(report, app, records, p,
                templates if tuple(templates) != p.templates else None,
                networks if tuple(networks) != p.networks else None,
                new_quota if new_quota != p.quota else None)


def lead_firewall_view(app, records: dict, key: str) -> dict:
    """A project's lead firewall as the operator reads it: the model, the rules
    the operator accepted, and the lead's live rules (None when they cannot be
    read, never an empty list). Reads only; needs no root."""
    p = _project(records, key)
    live, error = None, None
    if p.lead is not None and _vm(app, p.lead) is not None:
        try:
            live = firewall.read_rules(app, p.lead)
        except Exception as e:
            error = type(e).__name__
    accepted = None if p.lead_firewall is None else list(p.lead_firewall)
    return {"project": p.label, "slot": p.slot, "lead": p.lead, "model": p.model,
            "accepted": accepted, "live": live, "read_error": error,
            "same": live is not None and accepted is not None and live == accepted}


def set_lead_firewall(app, key: str, model: str | None = None, rules=None,
                      accept_current: bool = False) -> list:
    """Change a lead's firewall, or accept the rules it has. With `model`, the
    lead's model endpoint changes and its firewall becomes "model endpoint
    only" (for a lead with a network); with `rules`, its firewall becomes
    exactly those rules; with `accept_current`, its live rules become the
    accepted ones and nothing on the qube changes, if they are in qmcp's rule
    format (no comment or expire, at most 32). The record keeps what qubesd
    reads back; a write that does not read back is undone."""
    return _run(_set_lead_firewall, app, key, model, rules, accept_current)


def _set_lead_firewall(report, app, key, model, rules, accept_current):
    if sum(x is not None and x is not False for x in (model, rules, accept_current or None)) != 1:
        raise ProjectError("say one of --model HOST:PORT, --rule RULE (repeatable) or --accept-current")
    records = _load_records()
    p = _project(records, key)
    vm = _recorded_lead(app, p)
    if vm is None:
        raise ProjectError(f"project '{p.label}' has no lead wearing its lead badge")
    if accept_current:
        try:
            stored = firewall.read_rules(app, p.lead)
        except UnicodeDecodeError:
            stored = None
        if stored is None or firewall.rules_refusal(stored):
            # A 0.9.20 hub could write any rule qubesd takes, a comment or an
            # expiry included; the record keeps only qmcp's own rule format.
            raise ProjectError(f"{p.lead}'s live rules are not in the form qmcp records ("
                               f"{'not ASCII' if stored is None else firewall.rules_refusal(stored)}): "
                               f"set them with --rule or --model instead")
        p.lead_firewall = tuple(stored)
        projects.save(records)
        report.append(f"{p.slot}: {p.lead}'s current firewall ({len(stored)} rules) accepted")
        return
    if model is not None:
        try:
            model = firewall.model_text(model)
        except firewall.FirewallError as e:
            raise ProjectError(str(e)) from None
        try:
            if _netvm(vm) is None:
                raise ProjectError(f"{p.lead} has no network, so it reaches no model endpoint; "
                                   f"set its rules, or give the project a new lead on a network")
        except NetvmUnreadable:
            raise ProjectError(f"the network of {p.lead} cannot be read") from None
        rules = firewall.endpoint_rules(model)
    err = firewall.rules_refusal(list(rules))
    if err:
        raise ProjectError(err)
    before = firewall.read_rules(app, p.lead)
    try:
        stored = firewall.write_rules(app, p.lead, list(rules))
    except Exception as e:
        # Never leave rules live that the record does not hold: put back what was.
        try:
            firewall.restore_rules(app, p.lead, before)
            undone = "its rules were put back as they were"
        except Exception as e2:
            undone = f"its old rules could NOT be put back ({type(e2).__name__})"
        raise ProjectError(f"{p.lead}'s firewall was not set ({type(e).__name__}): {undone}") from e
    if model is not None:
        p.model = model
    p.lead_firewall = tuple(stored)
    projects.save(records)
    report.append(f"{p.slot}: {p.lead}'s firewall set ({len(stored)} rules)"
                  + (f", model {model}" if model else ""))


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
    tags = set() if vm is None else _tags(vm)
    if core.UMBRELLA not in tags:
        raise ProjectError(f"no qube '{name}' in AI space")
    if core.klass_of(vm) != "AppVM" or core.is_template(vm) or core.is_gateway(vm) \
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
        try:
            net = _netvm(vm)
        except NetvmUnreadable:
            raise ProjectError(f"the network of '{name}' cannot be read") from None
        if net is not None and net not in p.named_networks():
            raise ProjectError(f"'{name}' is on {net}, which is not one of {p.label}'s worker networks")
    current = projects.member_slots(tags)
    if slot is not None and current and current != {slot} and not confirm:
        raise ProjectError(f"'{name}' is in {', '.join(sorted(current))}: moving it carries that "
                           f"slot's content into {slot}; re-run with --yes")
    # Remove before add: a moment in no slot is less authority, never more.
    if current:
        try:
            _set_tags(vm, remove={projects.member_badge(s) for s in current})
        except core.Unreadable as e:
            report.fail(f"{name}: taken out of {', '.join(sorted(current))}, but {e}; it was "
                        f"moved into nothing (qmcp check shows what is left)")
            return
        report.append(f"{name}: out of {', '.join(sorted(current))}")
    if slot is not None:
        try:
            _set_tags(vm, add={projects.member_badge(slot)})
        except core.Unreadable as e:
            report.fail(f"{name}: put in {slot}, but {e} (qmcp check shows what is left)")
            return
    report.append(f"{name}: {'no slot' if slot is None else slot}")
    prefix = birth.read_name_prefix()
    for p in records.values():
        if p.label and p.slot != slot and name.startswith(p.space(prefix)):
            report.append(f"{name}: its name stays inside '{p.space(prefix)}', so {p.label}'s lead "
                          f"can still detect it by name")


def delete_plan(app, records: dict, key: str) -> tuple:
    """What `qmcp project delete KEY --yes` would do, changing nothing: (it can
    run, the plan in words). Reads the records and the qube list only, so it
    needs no root, and the window and a proposal show it before anyone asks."""
    p = projects.find(records, key)
    if p is None and key in projects.PROJECT_SLOTS:
        return True, (f"{key} has no record: this finishes a delete, removing the qubes still "
                      f"wearing its member badge and stripping its badges everywhere")
    if p is None or p.slot == projects.HUB_SLOT:
        return False, f"no project '{key}'"
    members, unread = [], []
    for vm in app.domains:
        try:
            if core.is_member(vm, p.slot):
                members.append(vm.name)
        except core.Gone:
            pass
        except core.Unreadable:
            unread.append(vm.name)
    note = f"; the tags of {', '.join(sorted(unread))} cannot be read now" if unread else ""
    return True, (f"this removes {p.slot} '{p.label}': its lead {p.lead or '(none)'} and every "
                  f"member qube ({', '.join(sorted(members)) if members else 'none'}), and keeps "
                  f"its dump sink {p.dump or '(none)'}{note}")


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
        ours = _demote_lead(app, p, report, removing=True)
        del records[p.slot]
        projects.save(records)
        report.append(f"{p.slot}: record of '{p.label}' deleted")
        if ours:
            err = _remove_qube(app, p.lead)
            report.append(f"{p.slot}: removed {p.lead}") if not err else \
                _not_removed(report, p.slot, p.lead, err)
    # Only qubes really in the project are removed. A stray badge on a qube
    # outside AI space is stripped below, never the qube. A qube whose tags
    # cannot be read is neither removed nor stripped: the delete reports it,
    # and the slot stays in use until a run reads it.
    members = []
    for vm in app.domains:
        try:
            if core.is_member(vm, p.slot):
                members.append(vm.name)
        except core.Unreadable:
            pass                    # read again below: removed if a member, else reported
    for name in members:
        err = _remove_qube(app, name)
        report.append(f"{p.slot}: removed {name}") if not err else \
            _not_removed(report, p.slot, name, err)
    holders, _ = _badges_of_slot(app, p.slot)
    for name in holders:
        try:
            vm = _vm(app, name)
            tags = set() if vm is None else _tags(vm)
            if _member(tags, p.slot):
                # A member the first pass could not read: removed like the rest.
                err = _remove_qube(app, name)
                report.append(f"{p.slot}: removed {name}") if not err else \
                    _not_removed(report, p.slot, name, err)
                continue
            strip = {t for t in tags if (q := projects.slot_badge_parts(t)) and q[1] == p.slot}
            if projects.LEAD in tags and projects.lead_badge(p.slot) in strip:
                strip.add(projects.LEAD)
            if vm is not None:
                try:
                    _set_tags(vm, remove=strip)
                except core.Unreadable as e:
                    report.append(f"{p.slot}: stripped {', '.join(sorted(strip))} from {name}, "
                                  f"but {e}; read again below")
                    continue
            report.append(f"{p.slot}: stripped {', '.join(sorted(strip))} from {name}"
                          + (" (the dump sink, kept)" if name == p.dump else ""))
        except Exception as e:
            report.fail(f"{p.slot}: could NOT strip badges from {name} ({type(e).__name__})")
    left, unread = _badges_of_slot(app, p.slot)
    if left or unread:
        report.fail(f"{p.slot}: NOT reusable until these lose its badges: "
                    f"{', '.join(left + [f'{n} (tags unreadable)' for n in unread])}")
    else:
        report.append(f"{p.slot}: free")


def project_rows(app, records: dict) -> list:
    rows = []
    for slot in projects.SLOTS:
        p = records.get(slot)
        if p is None:
            continue
        badge = projects.member_badge(slot)
        members = 0
        for vm in app.domains:
            try:
                members += core.is_member(vm, slot)
            except core.Gone:
                pass
            except core.Unreadable:
                members = None      # not known, never a count that skipped a qube
                break
        try:
            used = budget.persistent_sum(app, badge)
        except Exception:
            used = None
        rows.append({"slot": slot, "label": p.label, "lead": p.lead, "members": members,
                     "used": used, "quota": p.quota, "templates": list(p.templates),
                     "networks": list(p.networks), "dump": p.dump, "model": p.model,
                     "lead_firewall": None if p.lead_firewall is None else list(p.lead_firewall)})
    return rows
