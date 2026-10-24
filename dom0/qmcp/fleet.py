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

import json
import os
import re
import stat
import time

from qmcp import anon, audit, birth, budget, core, firewall, gateways, inqube, projects, proposals, restored

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

#: v0.9.16's consent daemon ran as a systemd --user unit of the operator's (its
#: installer took SUDO_USER, else uid 1000), wanted by the graphical session,
#: and listened in /run/qmcp, which 0.9.17 took over. It is in a home, so it is
#: not in LEGACY_PATHS: `legacy_user_paths()` names it, `legacy_daemons()` finds
#: one still running, and the installer stops it and removes all of this.
LEGACY_USER_UNIT = "qmcp-consent.service"
LEGACY_DAEMON = "qmcp-consentd"
LEGACY_SOCKET = "/run/qmcp/consent.sock"


def legacy_users(group: str = "qubes") -> list:
    """[(user, home)] of every account v0.9.16's user unit may sit under: the
    members of `group`, then uid 1000, each once. Never root: its installer
    took SUDO_USER, and a dom0 operator does not run sudo from a root shell."""
    import grp
    import pwd
    names = []
    try:
        names += list(grp.getgrnam(group).gr_mem)
    except KeyError:
        pass
    try:
        names.append(pwd.getpwuid(1000).pw_name)
    except KeyError:
        pass
    out: list = []
    for name in names:
        if name == "root" or any(name == u for u, _ in out):
            continue
        try:
            home = pwd.getpwnam(name).pw_dir
        except KeyError:
            continue
        # Root resolves these paths: an empty or relative home would resolve
        # against its working directory; the installer reads one per line.
        if os.path.isabs(home) and home.strip("/") and not set(home) & {"\t", "\n"}:
            out.append((name, home))
    return out


def legacy_home_paths(home: str) -> list:
    """The unit and its wants link in one home."""
    d = os.path.join(home, ".config", "systemd", "user")
    return [os.path.join(d, LEGACY_USER_UNIT),
            os.path.join(d, "graphical-session.target.wants", LEGACY_USER_UNIT)]


def legacy_user_paths(users=None) -> list:
    """The unit and its wants link in each of `users`' homes
    (`legacy_users()` by default), then the daemon's socket."""
    users = legacy_users() if users is None else users
    return [p for _, home in users for p in legacy_home_paths(home)] + [LEGACY_SOCKET]


def legacy_daemons(proc: str = "/proc") -> list:
    """The pids whose command line runs v0.9.16's consent daemon (it keeps
    running from the file the installer deleted), lowest first. Raises
    OSError when `proc` does not list: none found is then not known."""
    out = []
    for pid in [n for n in os.listdir(proc) if n.isdigit()]:
        try:
            with open(os.path.join(proc, pid, "cmdline"), "rb") as fh:
                argv = fh.read(4096).split(b"\0")
        except OSError:
            continue        # gone, or not ours to read
        names = [os.path.basename(a) for a in argv[:2]] + [b""]
        # Run as its unit ran it (the script's #! line puts python first), never
        # a pager or an editor that has the file open.
        if names[0] == LEGACY_DAEMON.encode() or \
                (names[0].startswith(b"python") and names[1] == LEGACY_DAEMON.encode()):
            out.append(int(pid))
    return sorted(out)


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
    except (OSError, UnicodeDecodeError):
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
    ("anything into a qube the anonymity gate stopped", "qubes.Filecopy", "member", "blocked"),
    ("the hub's exec into a stopped qube", "qmcp.RunInAIManaged", "hub", "blocked"),
    ("a stopped qube calling a qmcp service", "qmcp.ListAIManagedQubes", "blocked", "dom0"),
    ("a stopped qube reaching another qube", "qubes.Filecopy", "blocked", "member"),
    ("a stopped qube's desktop notification", "qubes.Notifications", "blocked", "@default"),
    ("the hub's exec into a qube held for review", "qmcp.RunInAIManaged", "hub", "heldm"),
    ("a lead's exec into its member held for review", "qmcp.RunInAIManaged", "lead", "heldm"),
    ("a lead held for review calling a qmcp service", "qmcp.ListAIManagedQubes", "heldl", "dom0"),
    ("a lead held for review reaching its members", "qmcp.RunInAIManaged", "heldl", "member"),
    ("a held qube's desktop notification", "qubes.Notifications", "heldm", "@default"),
    ("a stopped qube's clock request", "qubes.GetDate", "blocked", "@default"),
    ("a held qube's clock request", "qubes.GetDate", "heldm", "@default"),
    ("a stopped qube's window icon", "qubes.WindowIconUpdater", "blocked", "dom0"),
    ("a held qube's window icon", "qubes.WindowIconUpdater", "heldm", "dom0"),
    ("AI space's window icon to dom0", "qubes.WindowIconUpdater", "member", "dom0"),
    ("the hub's window icon to dom0", "qubes.WindowIconUpdater", "hub", "dom0"),
    ("the hub reaching a hidden anonymous project", "qmcp.RunInAIManaged", "hub", "hidden"),
    ("the hub's copy into a hidden anonymous project", "qubes.Filecopy", "hub", "hidden"),
    ("AI space's dialog into a hidden anonymous project", "qubes.OpenInVM", "member", "hidden"),
    ("an anonymous qube opening a URL elsewhere", "qubes.OpenURL", "anon", "outside"),
    ("an anonymous qube opening a file elsewhere", "qubes.OpenInVM", "anon", "outside"),
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
    ("the hub's firewall write into a guarded qube", "admin.vm.firewall.Set", "hub", "guarded"),
    ("hub exec into an open qube", "qmcp.RunInAIManaged", "hub", "open"),
    ("the hub's copy into an open qube", "qubes.Filecopy", "hub", "open"),
    ("the hub's firewall write into an open qube without the firewall half",
     "admin.vm.firewall.Set", "hub", "open"),
    ("the hub's firewall write into an open qube with it", "admin.vm.firewall.Set",
     "hub", "openfw"),
    ("a lead's exec into an open qube", "qmcp.RunInAIManaged", "lead", "open"),
    ("AI space reaching an open qube", "qubes.Filecopy", "ai", "open"),
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
    ("a lead's connection to its model qube", "qubes.ConnectTCP+11434", "lead", "model"),
    ("a worker's connection to its slot's model qube", "qubes.ConnectTCP+11434", "member", "model"),
    ("the hub's connection to a model qube", "qubes.ConnectTCP+11434", "hub", "model"),
    ("a TCP connection from AI space into another qube", "qubes.ConnectTCP+22", "ai", "peer"),
    ("a TCP connection from AI space through @default", "qubes.ConnectTCP+11434", "ai", "@default"),
    ("an application started from AI space in a qube outside it", "qubes.StartApp", "ai",
     "outside"),
    ("an image read from AI space in a qube outside it", "qubes.GetImageRGBA", "ai", "outside"),
)
_PROBES = {"ai": "qmcp-probe-ai", "peer": "qmcp-probe-peer",
           "guarded": "qmcp-probe-guarded", "outside": "qmcp-probe-outside",
           "lead": "qmcp-probe-lead", "member": "qmcp-probe-member",
           "other": "qmcp-probe-other", "sink": "qmcp-probe-sink",
           "model": "qmcp-probe-model", "blocked": "qmcp-probe-blocked",
           "hidden": "qmcp-probe-hidden", "anon": "qmcp-probe-anon",
           "open": "qmcp-probe-open", "openfw": "qmcp-probe-openfw",
           "heldm": "qmcp-probe-heldm", "heldl": "qmcp-probe-heldl"}
#: Synthetic project p01 (lead, member, sink, model qube) and a member of p02.
_PROBE_TAGS = {
    "ai": [core.UMBRELLA], "peer": [core.UMBRELLA], "guarded": [core.UMBRELLA, core.GUARDED],
    "outside": [],
    "lead": [core.UMBRELLA, projects.LEAD, projects.lead_badge("p01")],
    "member": [core.UMBRELLA, projects.member_badge("p01")],
    "other": [core.UMBRELLA, projects.member_badge("p02")],
    "sink": [projects.DROP_BOX, projects.dump_badge("p01")],
    "model": [core.UMBRELLA, core.GUARDED, projects.model_badge("p01")],
    "open": [core.UMBRELLA, core.GUARDED, core.OPEN],
    "openfw": [core.UMBRELLA, core.GUARDED, core.OPEN, core.OPEN_FW],
    "blocked": [core.UMBRELLA, projects.member_badge("p01"), projects.ANON, projects.BLOCKED],
    "hidden": [core.UMBRELLA, projects.member_badge("p03"), projects.ANON, projects.HUBBLIND],
    "anon": [core.UMBRELLA, projects.member_badge("p04"), projects.ANON],
    # Restored with their badges, so the lines that would route them are live:
    # only A0's quarantine lines stand between them and their slot.
    "heldm": [core.UMBRELLA, projects.member_badge("p01"), core.QUARANTINE],
    "heldl": [core.UMBRELLA, projects.LEAD, projects.lead_badge("p01"), core.QUARANTINE],
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
                         and n not in (_PROBES["peer"], _PROBES["guarded"], _PROBES["model"],
                                       _PROBES["blocked"], _PROBES["hidden"], _PROBES["anon"],
                                       _PROBES["open"], _PROBES["openfw"])})
    problems = []
    for label, service, role, target in PRECEDENCE_CLAIMS:
        service, _, argument = service.partition("+")
        tgt = {"hub": hub, "dom0": "dom0"}.get(target, _PROBES.get(target, target))
        sources = (ai_sources if role == "ai" else [hub] if role == "hub"
                   else [_PROBES[role]])
        for src in sources:
            if src == tgt:
                continue
            try:
                req = Request(service, f"+{argument}", src, tgt, system_info=si)
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
    except (OSError, UnicodeDecodeError):
        return None
    hits = re.findall(r"^\*\s+\*\s+(\S+)\s+@anyvm\s+deny\s*$", text, re.M)
    return hits[-1] if hits else None


# ------------------------------------------------------------------ check

def check(app, policy_dir: str | None = None, lib_dir: str | None = None,
          rpc_dir: str | None = None, legacy_paths=None, system_info=None,
          legacy_procs=None) -> list:
    policy_dir = POLICY_DIR if policy_dir is None else policy_dir
    lib_dir = LIB_DIR if lib_dir is None else lib_dir
    rpc_dir = RPC_DIR if rpc_dir is None else rpc_dir
    legacy_paths = (LEGACY_PATHS + tuple(legacy_user_paths())) if legacy_paths is None \
        else legacy_paths
    legacy_procs = legacy_daemons if legacy_procs is None else legacy_procs
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

    # 0. the operator files: judged by their mode, not by whether this user
    # can open them, so a check run as root fails on a file the services and
    # the operator's own check cannot read.
    _operator_files(add)

    # 1. the hub
    hub = core.read_hub()
    if hub is None:
        add("fail", "hub", f"{core.HUB_PATH} missing or malformed")
    elif hub not in by_name:
        add("fail", "hub", f"hub '{hub}' does not exist")
    elif hub not in tags_by:
        add("error", "hub", f"cannot read the tags of the hub '{hub}'")
    else:
        # In anonymous mode the hub wears `qmcp-anon`, and the gate may stop
        # it; a mode that cannot be read fails its own item below.
        mode_badges = {projects.ANON, projects.BLOCKED, projects.STOPPED, core.QUARANTINE} \
            if anon.mode_state()[0] is not False else set()
        bad = {t for t in tags_by[hub] if birth.controlled(t)} - mode_badges
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

    # 3c. open windows. The badge is the whole gate — the services it
    # opens run inside the target qube, or are qubesd's own, so no dom0 code
    # sees those calls and none can read an expiry — and the record in /run is
    # what says when the window ends. So a badge without a readable, unexpired
    # record is a window nothing will close on time, and a badge on a qube
    # `qmcp open` refuses (a gateway above all, which the rulebook cannot tell
    # from any other guarded qube) is a window that should never have opened.
    # The expiry pass takes both off within the timer's interval; this fails
    # while they are on. A healthy window is a warning, not a failure: it is
    # the operator's own deliberate exception and it clears itself, and a red
    # light that is red on purpose stops being read.
    open_bad, open_unread, open_now = [], [], []
    for vm in vms:
        tags, name = T(vm), vm.name
        if not tags & {core.OPEN, core.OPEN_FW}:
            continue
        if core.OPEN_FW in tags and core.OPEN not in tags:
            open_bad.append(f"{name} wears {core.OPEN_FW} without {core.OPEN}: its firewall "
                            f"writes are open on their own")
        try:
            why = _open_refusal(vm, name, tags)
        except RoleError as e:
            open_unread.append(f"whether {name} may be open ({e})")
            continue
        if why:
            open_bad.append(f"{name} wears an open badge and {why[why.find(' ') + 1:]}")
            continue
        try:
            left = window_left(name)
        except WindowUnreadable as e:
            open_bad.append(str(e))
            continue
        if left <= 0:
            open_bad.append(f"{name}'s window ran out {-left}s ago and its badge is still on")
            continue
        open_now.append(f"{name} ({_span(left)} left"
                        + (", firewall too" if core.OPEN_FW in tags else "") + ")")
    # A seal whose kill was never read back: what the hub started there may
    # still run, though no badge is left for the items above to see.
    for name in pending_kills():
        open_bad.append(f"{name} was sealed and its kill was not read back, so a process the "
                        f"hub started in it may still run (the gate's timer tries again; or "
                        f"qvm-kill {name})")
    if open_bad or open_unread:
        judged("open windows", open_bad, open_unread, "; ".join(open_bad), "")
    elif open_now:
        add("warn", "open windows", f"open to the hub: {', '.join(sorted(open_now))}; "
                                    f"qmcp seal closes one at once")
    else:
        add("pass", "open windows", "no guarded qube is open")

    # 4. the airlock: a drop box is never in AI space
    hybrids = sorted(vm.name for vm in vms if {"ai-dump", core.UMBRELLA} <= T(vm))
    add("fail" if hybrids else "pass", "drop boxes",
        f"ai-dump qube(s) also ai-managed: {', '.join(hybrids)}" if hybrids
        else "no ai-dump qube is in AI space")

    # 5. stray badges outside AI space. Slot badges are judged by the project
    # checks below, which fail on a misplaced one; a dump sink's badge belongs
    # outside AI space.
    # `qmcp-hubblind` outside AI space is a hidden project's sink, or one kept
    # after its project was deleted: it only takes the hub's reach away.
    # In anonymous mode the hub wears `qmcp-anon`, and the gate may stop it:
    # item 1 judges those.
    hub_badges = {projects.ANON, projects.BLOCKED, projects.STOPPED} \
        if anon.mode_state()[0] is not False else set()
    stray = sorted(vm.name for vm in vms if core.UMBRELLA not in T(vm)
                   and any(t == core.GUARDED or t.startswith(birth.NAMESPACE)
                           for t in T(vm) if not t.startswith(TOMBSTONE_PREFIX)
                           and not projects.is_slot_tag(t) and t != projects.HUBBLIND
                           and t != core.QUARANTINE
                           and not (vm.name == hub and t in hub_badges)))
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
    # (kept for the model-qube item, which asks it where updates go)
    loaded_policy = loaded_si = None
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
            loaded_policy, loaded_si = policy, si
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
    qubes_dir = os.path.join(core.RUN_DIR, core.QUBE_LOCK_SUBDIR)
    state = core.state_dir()
    run = _safe(lambda: os.lstat(core.RUN_DIR))
    st = _safe(lambda: os.stat(calls))
    lock = _safe(lambda: os.stat(budget.LOCK_PATH))
    subdirs = [os.path.join(core.RUN_DIR, d) for d in
               ("calls", core.QUBE_LOCK_SUBDIR, "open", audit.RAM_SUBDIR, core.STATE_SUBDIR)]
    linked = [d for d in subdirs if (ls := _safe(lambda d=d: os.lstat(d))) is not None
              and not stat.S_ISDIR(ls.st_mode)]
    if st is None:
        add("fail", "runtime dir", f"{calls} missing (systemd-tmpfiles --create)")
    elif not (run is not None and stat.S_ISDIR(run.st_mode) and run.st_gid == gid
              and run.st_uid == RUN_DIR_OWNER
              and run.st_mode & stat.S_ISGID and not run.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        # Readable by the services, setgid so what root makes in it is the
        # group's, and writable by root alone: renaming or replacing an entry
        # takes write permission on its parent, so nobody else can swap a
        # subdirectory for a link that would send root's opens elsewhere.
        add("fail", "runtime dir", f"{core.RUN_DIR} is not the services group's, setgid and "
                                   f"writable by root alone (2750 root:{SERVICES_GROUP}; "
                                   f"systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
    elif linked:
        add("fail", "runtime dir", f"not a directory: {', '.join(linked)} (it was replaced: "
                                   f"remove it, then systemd-tmpfiles --create "
                                   f"/etc/tmpfiles.d/qmcp.conf)")
    elif not all((x := _safe(lambda d=d: os.stat(d))) is not None and shared(x)
                 and x.st_mode & stat.S_ISGID for d in (state, audit.ram_dir())):
        # The audit-dropped counter, the restore check's failure records and
        # the in-qube writer locks: made and removed by both sides.
        # state/: the locks both sides take and what the services make; audit/:
        # the RAM chains, which only root or tmpfiles makes now.
        add("fail", "runtime dir", f"{state} or {audit.ram_dir()} is missing, or not the services "
                                   f"group's, group-writable and setgid (systemd-tmpfiles "
                                   f"--create /etc/tmpfiles.d/qmcp.conf)")
    elif not shared(st):
        add("fail", "runtime dir", f"{calls} is not writable by the services group "
                                   f"(systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
    elif not ((qst := _safe(lambda: os.stat(qubes_dir))) is not None and shared(qst)
              and qst.st_mode & stat.S_ISGID):
        # The per-qube locks: a service that cannot open one refuses every
        # call that operates a qube.
        add("fail", "runtime dir", f"{qubes_dir} is missing, or not the services group's, "
                                   f"group-writable and setgid: every call that operates a qube "
                                   f"refuses (systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
    elif not shared(lock):
        # Missing too: in a 2750 /run/qmcp only root or tmpfiles makes it again.
        add("fail", "runtime dir", f"{budget.LOCK_PATH} is missing or not writable by the "
                                   f"services group: every create refuses (systemd-tmpfiles "
                                   f"--create /etc/tmpfiles.d/qmcp.conf)")
    elif not shared(_safe(lambda: os.stat(core.queue_path(budget.LOCK_PATH)))):
        # The create lock's turnstile: every create passes through it first.
        add("fail", "runtime dir", f"{core.queue_path(budget.LOCK_PATH)} is not writable by the "
                                   f"services group: every create refuses (systemd-tmpfiles "
                                   f"--create /etc/tmpfiles.d/qmcp.conf)")
    elif not ((wst := _safe(lambda: os.stat(WINDOW_DIR))) is not None and shared(wst)
              and wst.st_mode & stat.S_ISGID):
        # The window records: root writes one when a window opens, and the
        # expiry pass (as the services' user) turns it into a pending kill and
        # removes it; one it cannot write is a seal whose failed kill nothing
        # tries again.
        add("fail", "runtime dir", f"{WINDOW_DIR} is missing, or not the services group's, "
                                   f"group-writable and setgid (systemd-tmpfiles --create "
                                   f"/etc/tmpfiles.d/qmcp.conf)")
    elif not all(shared(st) for st in (_safe(lambda: os.stat(anon.LOCK_PATH)),
                                       _safe(lambda: os.stat(anon.HEARTBEAT_PATH)))):
        add("fail", "runtime dir", f"{anon.LOCK_PATH} or {anon.HEARTBEAT_PATH} is missing or not "
                                   f"writable by the services group: the anonymity gate's timer "
                                   f"cannot run (systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")
    else:
        add("pass", "runtime dir", calls)
    # The services cannot create a file in /var/log: a missing log, like one
    # of another group, stops their lines without a symptom. Only while the
    # install's lines go to disk: in mode ram or none nothing appends to it.
    audit_mode, audit_mode_problem = audit.install_mode()
    log = _safe(lambda: os.stat(audit.LOG_PATH))
    if audit_mode == "disk" and not shared(log):
        add("fail", "audit log", f"{audit.LOG_PATH} is "
                                 f"{'missing' if log is None else 'not writable by the services group'}: "
                                 f"their audit lines stop without a symptom "
                                 f"(systemd-tmpfiles --create /etc/tmpfiles.d/qmcp.conf)")

    # 11a. the record of what AI space removed: the services write it before
    # every remove of theirs, and the restore check reads it; a remove is
    # refused while it cannot be written.
    rst = _safe(lambda: os.stat(restored.REMOVED_DIR))
    if rst is None:
        add("fail", "removal record", f"{restored.REMOVED_DIR} missing: every remove of the "
                                      f"hub's and the leads' is refused (systemd-tmpfiles "
                                      f"--create /etc/tmpfiles.d/qmcp.conf)")
    elif not (shared(rst) and rst.st_mode & stat.S_ISGID):
        add("fail", "removal record", f"{restored.REMOVED_DIR} is not the services group's, "
                                      f"group-writable and setgid (2770 root:{SERVICES_GROUP}): "
                                      f"a remove of the hub's or a lead's may be refused, and "
                                      f"while the gate's user cannot list it no restore is "
                                      f"proven")
    else:
        add("pass", "removal record", f"{restored.REMOVED_DIR} is the services' to write")

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
    elif not shared(lock):
        add("fail", "proposal store", f"{proposals.LOCK_PATH} is missing or not writable by the "
                                      f"services group: every proposal the hub submits is refused "
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

    # 13. the audit chain. The records are judged in their own item below;
    # here they say only which projects keep their lines off disk.
    try:
        audit_records = projects.load()
    except projects.ProjectsUnreadable:
        audit_records = None
    _audit_modes(add, audit_records, audit_mode, audit_mode_problem)
    if audit_mode == "disk" or os.path.exists(audit.LOG_PATH):
        # In mode ram or none the lines on disk from before stay evidence.
        ok, n, err = audit.verify()
        add("pass" if ok else "fail", "audit chain", f"{n} entries intact" if ok else
            f"{err}: keep the file as the record of the break; sudo qmcp audit rotate starts a new "
            f"log, so a later break is not hidden behind this one")
        linked, why = audit.verify_links()
        if not linked:
            add("fail", "audit chain", f"{why}: keep the files as the record of the break")
    for name, _ in audit.ram_chains():
        path = os.path.join(audit.ram_dir(), name)
        ok, n, err = audit.verify(path)
        add("pass" if ok else "fail", "audit chain in RAM",
            f"{path}: {n} entries intact" if ok else
            f"{path}: {err}; it is gone at shutdown, so read it now if the break matters "
            f"(qmcp audit tail 200 --path {path})")
    lost = audit.dropped()
    if lost is not None:
        count, first = lost
        add("fail", "audit lines lost",
            (f"{count} line(s) could not be written to {audit.LOG_PATH} since {first}"
             if count is not None else f"{audit.DROPPED_PATH} does not read")
            + f": what they recorded is not on the chain. Free space under "
              f"{os.path.dirname(audit.LOG_PATH)} if that is why, then remove the marker "
              f"(sudo rm {audit.DROPPED_PATH})")
    # A caller's counter (the hourly cap and the day's budget, one file): one
    # the services cannot keep refuses that principal's every change but a
    # kill (`audit.budget_left` fails closed), so it fails here, whoever runs
    # the check: by its group and mode, not by whether this process reads it.
    for caller, rec in audit.counters(calls):
        path = os.path.join(calls, caller + audit.REFUSED_SUFFIX)
        cst = _safe(lambda path=path: os.stat(path))
        if rec is None or not (shared(cst) and cst.st_mode & stat.S_IRGRP):
            add("fail", "audit counter",
                f"{caller}: {path} does not read, or is not the services group's and "
                f"group-read-writable: every change of that principal but a kill is refused. "
                f"Remove it (sudo rm {path}); it is made again as it should be")
    for caller, count, first in audit.unlogged_refusals(calls):
        if count is None:
            continue                    # named above
        add("warn", "calls not logged",
            f"{caller}: {count} call(s) past {audit.REFUSALS_PER_HOUR} in an hour were "
            f"counted, not logged, since {first} (calls that changed nothing, and kills past its "
            f"daily budget); a principal that does that so often is worth a look. Removing the counter once read (sudo rm "
            f"{os.path.join(calls, caller + audit.REFUSED_SUFFIX)}) also gives it a new day's "
            f"budget")
    for caller, today, over, first in audit.spent_budgets(calls):
        add("warn", "audit budget spent",
            f"{caller}: {today} line(s) today of its {audit.AUDIT_LINES_PER_DAY} a day"
            + (f"; {over} change(s) refused for its budget since {first}" if over else "")
            + (": its changes are refused until its next day (24 h of dom0's uptime)" if today >= audit.AUDIT_LINES_PER_DAY
               else ": it has a new day's share now")
            + ". A principal that busy is worth a look; removing its counter (sudo rm "
              f"{os.path.join(calls, caller + audit.REFUSED_SUFFIX)}) gives it a new day's share "
              "and clears this")
    # The floor of every chain lines may go to: the log's disk while the
    # install writes there, and the RAM chains' tmpfs (dom0's memory) always,
    # since a project in RAM or an unknown place writes there in any mode but none.
    floors = ([audit.LOG_PATH] if audit_mode == "disk" else []) + \
        ([audit.ram_path()] if audit_mode != "none" else [])
    for chain in floors:
        if not audit.room(chain):
            add("fail", "audit room", f"less than {audit.FLOOR_BYTES // (1024 * 1024)} MiB free "
                                      f"under {os.path.dirname(chain)}, or that cannot be read: "
                                      f"the services refuse every call that would change "
                                      f"something, but a kill, wherever its line would go, "
                                      f"until there is")
    size = _safe(lambda: os.path.getsize(audit.LOG_PATH), 0)
    if size > audit.ROTATE_AT_BYTES:
        add("warn", "audit size", f"{size // (1024 * 1024)} MiB; the hourly timer rotates it "
                                  f"(qmcp-audit.timer), or by hand: sudo qmcp audit rotate")
    _audit_retention(add, audit_records, audit_mode)
    _boot_seal_item(add)

    # 14. nothing of v0.9.16 left behind
    left, unread = [], []
    for p in legacy_paths:
        try:
            os.lstat(p)
            left.append(p)
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError:
            unread.append(p)    # another user's home: absent is not known
    try:
        running, procs_read = legacy_procs(), True
    except OSError as e:
        running, procs_read = [], type(e).__name__
    if running:
        left.append(f"{LEGACY_DAEMON} running (pid {', '.join(map(str, running))}; "
                    f"sudo kill {' '.join(map(str, running))})")
    if left:
        add("fail", "v0.9.16 leftovers", f"still present: {', '.join(left)}")
    elif procs_read is not True:
        # The scan is what finds a daemon that runs, wherever its unit sits.
        add("error", "v0.9.16 leftovers", f"cannot tell: the process list does not read "
                                          f"({procs_read})")
    elif unread:
        # A unit whose program the installer removed runs nothing, and the
        # process scan above finds a daemon that runs: another user's private
        # home it cannot read is a note, not a warning on every run.
        add("pass", "v0.9.16 leftovers", f"none running or found; not looked at as this user: "
                                         f"{', '.join(unread)} (sudo qmcp check looks)")
    else:
        add("pass", "v0.9.16 leftovers", "none")

    # 14b. qubes back from a backup or a copy, held for the operator's review
    restored.findings(app, add)

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
    out.extend(model_qube_findings(app, vms, by_name, records, tags_by, hub,
                                   policy=loaded_policy, system_info=loaded_si))
    out.extend(lead_firewall_findings(app, by_name, records))
    out.extend(anonymity_findings(app, vms, records, tags_by, registry, hub))
    inqube.findings(vms, records, tags_by, add, os.path.join(lib_dir, "template-rpc"))
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
                # A lead the anonymity gate stopped is judged by the gate's own
                # item, and one held for review by the restore item's warning:
                # its record and badges still agree.
                elif vm.name in tags_by and (not core.lead_badges_agree(
                        tags_by[vm.name] - {projects.BLOCKED, projects.STOPPED,
                                            core.QUARANTINE}, p.slot)
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
    lead_bad += [f"{name} wears lead badges but is not its slot's recorded lead (qmcp revoke "
                 f"{name} takes them off, with every other badge)" for name in stray_leads]
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
    # A `project dump` that died after its create and before its last badge
    # leaves a qube under the sink's name that its own retry refuses.
    bare = []
    for p in sorted(records.values(), key=lambda p: p.slot):
        name = _sink_default_name(p)
        if p.dump is None and name in tags_by and not _sink_badged(tags_by[name]):
            bare.append(name)
    if bare:
        add("warn", "unfinished dump sinks",
            f"named as a project's dump sink, which its record does not name, and wearing no "
            f"dump badge: {', '.join(bare)}: a qmcp project dump that did not finish? If it is "
            f"not yours, remove it (qvm-remove) and run the command again")

    unslotted = []
    for vm in vms:
        tags = tags_by[vm.name]
        if core.UMBRELLA not in tags or core.GUARDED in tags or projects.LEAD in tags \
                or projects.member_slots(tags) or projects.model_slots(tags):
            continue            # a model qube joins no slot: the model checks judge it
        try:
            if _workload(vm):
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


def anonymity_findings(app, vms, records: dict, tags_by: dict, registry=None, hub=None) -> list:
    """Anonymous mode; the anonymity gate, run as every check runs it (it acts
    on what it finds), with its timer; the anonymous badges where neither an
    anonymous project nor the mode puts them; and a hidden project sharing a
    router."""
    out = []
    add = lambda *a: out.append(Finding(*a))  # noqa: E731
    anonymous = {p.slot: p for p in records.values() if p.anonymous}
    mode, why = anon.mode_state()
    if mode is None:
        add("fail", "anonymous mode", f"{why}: whether the hub is judged cannot be told, so the "
                                      f"gate blocks it (write the one word anonymous, or remove "
                                      f"the file on an installation in normal mode)")
    elif mode:
        ordinary = sorted(p.label for p in records.values() if p.label and not p.anonymous)
        clearnet = sorted(n for n, g in (registry or {}).items() if not g.anonymising)
        if ordinary:
            add("fail", "anonymous mode", f"projects that are not anonymous: "
                                          f"{', '.join(ordinary)} (delete them)")
        if clearnet:
            add("fail", "anonymous mode", f"gateways that are not anonymising: "
                                          f"{', '.join(clearnet)} (qmcp gateway remove)")
        if not ordinary and not clearnet:
            add("pass", "anonymous mode", "every project is anonymous, and the gate judges the "
                                          "hub and the rest of AI space")
    # In anonymous mode the hub and the rest of AI space wear `qmcp-anon`, and
    # the gate may stop any of them.
    expected = set()
    if mode is not False and hub is not None and hub in tags_by:
        expected = set(anon.hub_candidates(hub, records, tags_by))
        try:
            expected = set(anon.hub_subjects(hub, records, registry or {},
                                             {vm.name: vm for vm in vms}, tags_by))
        except core.Unreadable:
            pass                    # a read the gate's own item reports; no badge called stray
        # And the anonymous projects' model qubes, which wear it in the mode too.
        expected |= {p.model_qube for p in anonymous.values() if p.model_qube}
    stray = []
    for vm in vms:
        tags = tags_by[vm.name]
        slots = projects.member_slots(tags) | projects.lead_slots(tags)
        ours = any(s in anonymous for s in slots)
        if tags & {projects.ANON, projects.BLOCKED, projects.STOPPED} and not ours \
                and vm.name not in expected:
            stray.append(vm.name)
    if stray:
        add("warn", "anonymous badges", f"qmcp-anon, qmcp-blocked or qmcp-stopped on qubes of no "
                                        f"anonymous project: {', '.join(sorted(stray))}")
    # A qube the hub can reach built on a hidden disposable template: each
    # start of it hands the hub the template's home as it is then.
    hidden = {vm.name for vm in vms if projects.HUBBLIND in tags_by[vm.name]}
    reachable = []
    for vm in vms if hidden else ():
        tags = tags_by[vm.name]
        if core.UMBRELLA not in tags or projects.HUBBLIND in tags:
            continue
        try:
            tpl = core.template_of(vm)
        except core.Unreadable as e:
            add("error", "hidden templates", f"{e}: whether the hub reaches a hidden project's "
                                             f"disposable template through {vm.name} is not known")
            continue
        if tpl is not None and core.name_of(tpl) in hidden:
            reachable.append(f"{vm.name} (from {core.name_of(tpl)})")
    if reachable:
        add("fail", "hidden templates", f"the hub can reach qubes made from a hidden project's "
                                        f"disposable template: {', '.join(sorted(reachable))} "
                                        f"(remove them, or qmcp revoke them)")
    # A disposable template that is hidden from the hub, or that a hidden
    # project's record names, approved by a project the hub sees: that
    # project's disposables arrive hidden and are refused at birth. Judged on
    # the badge as well as the records, since `qmcp-hubblind` stays on a
    # template after its hidden project lets it go or is deleted. `project
    # create` and `edit` refuse the share since 0.9.38; one made before stays
    # until the operator gives that project another template.
    by_name = {vm.name: vm for vm in vms}
    by_hidden = {}
    for p in records.values():
        if p.hidden:
            for t in p.templates:
                by_hidden.setdefault(t, []).append(p.label or p.slot)
    shared = []
    for q in sorted(records.values(), key=lambda q: q.slot):
        if q.hidden:
            continue
        for t in q.templates:
            if t not in by_name or (t not in by_hidden
                                    and projects.HUBBLIND not in tags_by.get(t, ())):
                continue
            try:
                dvmt = core.is_dvmt(by_name[t])
            except core.Unreadable as e:
                add("error", "hidden templates", f"{e}: whether {q.label or q.slot} can make "
                                                 f"disposables from it is not known")
                continue
            if dvmt:
                why = (f"approved by the hidden project {', '.join(sorted(by_hidden[t]))}"
                       if t in by_hidden else f"wears {projects.HUBBLIND}")
                shared.append(f"{t} ({why}, and by {q.label or q.slot})")
    if shared:
        add("warn", "hidden templates", f"a disposable template hidden from the hub is approved "
                                        f"by a project the hub sees, whose disposables from it "
                                        f"are refused at birth: {', '.join(shared)}; give that "
                                        f"project a disposable template of its own (qmcp "
                                        f"project edit)")
    if not anonymous and mode is False:
        # The timer also ends open windows and holds restored qubes, in every
        # mode: its item stands without an anonymous project.
        _gate_timer_item(add, anonymous=False)
        return out
    # Only the timer's runs touch the heartbeat: this check's own run below does not.
    age = anon.heartbeat_age()
    # A negative age is a clock set back since the last run: the heartbeat then
    # proves nothing about the timer, so it is stale, never fresh.
    if age is None or age > anon.HEARTBEAT_MAX_S or age < -1:
        add("fail", "gate heartbeat", ("no run of the anonymity gate has completed" if age is None
                                       else f"the anonymity gate's last run is dated "
                                            f"{-age:.0f} s ahead of the clock" if age < 0
                                       else f"the anonymity gate last completed a run "
                                            f"{age:.0f} s ago")
            + f": nothing anonymous is being judged every 15 seconds (journalctl -u "
              f"qmcp-gate.service)")
    else:
        add("pass", "gate heartbeat", f"last completed run {age:.0f} s ago")
    try:
        verdicts = anon.run(app, records=records)
    except Exception as e:
        add("error", "anonymity gate", f"could not run ({type(e).__name__}: {e})")
        verdicts = []
    if verdicts is None:
        add("error", "anonymity gate", "another run held the gate past its wait, so nothing was "
                                       "judged; one that hangs stops the timer's runs too")
    for v in verdicts or ():
        name = f"{v.label} ({v.slot})"
        if v.status == anon.GREEN and not v.blocked:
            add("pass", "anonymity gate", f"{name} is sound")
        elif v.status == anon.GREEN:
            add("warn", "anonymity gate", f"{name} was stopped and is sound again: clear it with "
                                          f"sudo qmcp project unblock "
                                          f"{v.slot if v.is_hub else v.label}")
        elif v.status == anon.UNREADABLE:
            add("error", "anonymity gate", f"{name}: {v.problems[0][1]}"
                                           + ("; blocked" if v.blocked or v.acted else ""))
        else:
            add("fail", "anonymity gate", f"{name} is not anonymous ("
                + "; ".join(d for _, d in v.problems) + ")"
                + ("; it was stopped" if v.blocked or v.acted else ""))
    _gate_timer_item(add, anonymous=True)
    for p in sorted(anonymous.values(), key=lambda p: p.slot):
        if p.slot == projects.HUB_SLOT:
            continue
        shared, unread = shared_routers(app, records, p)
        if shared:
            add("warn", "shared routers", f"{p.label} ({p.slot}) shares {', '.join(shared)} with "
                                          f"another project or the hub: {SHARED_ROUTER_WARNING}")
        if unread:
            add("error", "shared routers", f"cannot read the network of {', '.join(unread)}, so "
                                           f"whether {p.label} ({p.slot}) shares a router with "
                                           f"another project or the hub cannot be told")
    return out


def _gate_timer_item(add, anonymous: bool) -> None:
    active = anon.timer_active()
    if active is None:
        add("error", "gate timer", f"cannot tell whether {anon.TIMER} runs")
    elif not active:
        does = ("the gate judges only when a qmcp command runs, and " if anonymous else "")
        add("fail", "gate timer", f"{anon.TIMER} is not running, so {does}no open window ends "
                                  f"at its time and no restored qube is held until a qmcp "
                                  f"command runs (sudo systemctl enable --now {anon.TIMER})")
    else:
        add("pass", "gate timer", f"{anon.TIMER} runs every 15 seconds"
                                  + (": the gate, " if anonymous else ": ")
                                  + "the window expiry and the restore hold")


#: The boot seal: its unit, and the drop-in on Qubes' own autostart unit that
#: orders every autostart qube after it (`deploy/qubes-vm-qmcp-seal.conf`).
SEAL_UNIT = "qmcp-seal.service"
SEAL_DROPIN = "/etc/systemd/system/qubes-vm@.service.d/10-qmcp-seal.conf"


def _boot_seal_item(add) -> None:
    """Every boot ends every window before any autostart qube starts: the unit
    must be enabled, and the drop-in must order Qubes' autostart after it."""
    enabled = anon.unit_enabled(SEAL_UNIT)
    try:
        with open(SEAL_DROPIN, encoding="utf-8") as fh:
            ordered = any(line.strip() == f"After={SEAL_UNIT}" for line in fh.read(8192).splitlines())
    except FileNotFoundError:
        ordered = False
    except (OSError, UnicodeDecodeError):
        ordered = None
    if enabled is None or ordered is None:
        add("error", "boot seal", f"cannot tell whether {SEAL_UNIT} is enabled and ordered "
                                  f"before Qubes' autostart ({SEAL_DROPIN})")
    elif not enabled:
        add("fail", "boot seal", f"{SEAL_UNIT} is not enabled, so a window open at shutdown "
                                 f"is still open at the next boot until the gate's timer runs "
                                 f"(sudo systemctl enable {SEAL_UNIT})")
    elif not ordered:
        add("fail", "boot seal", f"{SEAL_DROPIN} is missing or does not order Qubes' autostart "
                                 f"after {SEAL_UNIT}, so an autostart qube can start with a "
                                 f"window's badge still on (run the installer again)")
    else:
        add("pass", "boot seal", f"{SEAL_UNIT} ends every window at boot, before any autostart "
                                 f"qube")


def _member(tags, slot: str) -> bool:
    """`core.is_member` on tags already read."""
    return core.UMBRELLA in tags and projects.member_badge(slot) in tags \
        and projects.LEAD not in tags


def lead_firewall_findings(app, by_name: dict, records: dict) -> list:
    """A lead's firewall is the operator's: it must still be the rules the
    operator accepted. A lead with no network needs none; a lead with one
    and no accepted rules on record (upgraded from 0.9.20) is warned about
    until the operator accepts its current rules or sets its model. A lead
    with a network whose project's model is a qube fails: it should have
    none. One whose endpoint is an address and whose accepted rules still
    hold the DNS rule set before 0.9.22 is warned about."""
    drift, unaccepted, unread, dns, sealed = [], [], [], [], []
    for p in sorted(records.values(), key=lambda p: p.slot):
        if p.slot == projects.HUB_SLOT or p.lead is None or p.lead not in by_name:
            continue
        try:
            net = _netvm(by_name[p.lead])
        except NetvmUnreadable:
            unread.append(f"{p.lead} (network)")
            continue
        if net is None:
            continue
        if p.model_qube is not None:
            # A lead whose model is a qube has no network: this one was given
            # one outside qmcp, so its project is no longer sealed.
            sealed.append(f"{p.label}: {p.lead} is on {net}, though its model is the qube "
                          f"{p.model_qube}")
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
        elif firewall.dns_left_open(p.model, p.lead_firewall):
            dns.append(f"{p.label}: {p.lead} (qmcp project firewall {p.label} --model {p.model})")
    out = []
    if sealed:
        out.append(Finding("fail", "model-qube leads", f"{'; '.join(sealed)}: clear its network "
                           f"(qvm-prefs LEAD netvm ''), or give the project a remote model with a "
                           f"new lead"))
    if unread:
        out.append(Finding("error", "lead firewalls", f"cannot read: {', '.join(unread)}"))
    if drift:
        out.append(Finding("fail", "lead firewalls",
                           f"differ from the rules you accepted: {', '.join(drift)} "
                           f"(qmcp project firewall NAME shows both)"))
    elif not unread:
        out.append(Finding("pass", "lead firewalls", "every lead firewall you accepted is still as "
                                                     "you accepted it"))
    if dns:
        out.append(Finding("warn", "lead DNS",
                           f"leads whose model endpoint is an address still have the DNS rule "
                           f"set before 0.9.22, which they do not need: {'; '.join(dns)} "
                           f"rewrites the rules without it"))
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


def hidden_projects_on(app, records: dict, name: str):
    """The hidden projects whose qubes run from the template `name`: it is on
    their approved list, or in the template chain of their lead, a member or
    their model qube. None when a chain cannot be read, never an empty list."""
    hidden = {p.slot: p for p in records.values() if p.hidden}
    if not hidden:
        return []
    out = {p.slot for p in hidden.values() if name in p.templates}
    for vm in app.domains:
        if all(s in out for s in hidden):
            break
        try:
            tags = core.tags_of(vm)
        except core.Gone:
            continue
        except core.Unreadable:
            return None
        slots = (projects.member_slots(tags) | projects.lead_slots(tags)
                 | projects.model_slots(tags)) & set(hidden)
        if not slots - out:
            continue
        try:
            chain = [core.name_of(t) for t in _template_chain(vm)]
        except core.Unreadable:
            return None
        if name in chain:
            out |= slots
    return sorted(f"{hidden[s].label or s} ({s})" for s in out)


def hidden_open_warning(app, name: str):
    """The warning `qmcp open` and an accepted `qube-open` give for a template
    a hidden project runs from, or None. Said when it cannot be told too."""
    try:
        records = projects.load()
    except projects.ProjectsUnreadable:
        return (f"the project records cannot be read, so whether a hidden project runs from "
                f"{name} is not known")
    try:
        on = hidden_projects_on(app, records, name)
    except Exception:
        on = None
    if on is None:
        return f"which hidden projects run from {name} could not be read"
    if not on:
        return None
    return (f"the hidden project(s) {', '.join(on)} run from {name}: while it is open the hub "
            f"runs commands as root in what their lead and workers run from their next start, "
            f"and can learn what they hold")


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
    # A hub file that cannot be read means it is not known whether this qube is
    # the hub, which must refuse rather than enroll it: `read_hub` answers None
    # both for a file that is absent and for one it could not read, and `name
    # == None` is false for every qube. The model-qube refusal beside this one
    # has always read it this way; this one did not until 0.9.25.
    hub = core.read_hub() if hub is None else hub
    if hub is None:
        return f"{core.HUB_PATH} cannot be read, so it is not known whether it is the hub"
    if name == hub:
        return "is the hub"
    try:
        tags = _tags(vm)
    except core.Gone:
        return "no such qube"
    if projects.DROP_BOX in tags or projects.LEAD in tags or projects.member_slots(tags) \
            or projects.lead_slots(tags):
        return "is a drop box, a lead or a project's member"
    if _held(tags):
        return HELD_WHY
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
                     "recorded_upstream": g.upstream, "updates": g.updates,
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


def _recorded_upstream(app, name: str) -> str:
    """An anonymising gateway's own network, as it is now, to record. One
    with no network carries nothing anonymously, and is refused."""
    vm = _vm(app, name)
    try:
        up = None if vm is None else _netvm(vm)
    except NetvmUnreadable:
        raise RoleError(f"the network of '{name}' cannot be read; try again") from None
    if up is None:
        raise RoleError(f"'{name}' has no network of its own, so it cannot carry anything "
                        f"anonymously; give it its upstream (sys-whonix, a VPN qube) first")
    return up


def _anonymous_users(app, name: str) -> list:
    """The anonymous projects that list gateway `name` or whose lead sits on it."""
    out = []
    for p in _load_records().values():
        if not p.anonymous:
            continue
        lead = _vm(app, p.lead) if p.lead else None
        try:
            on_it = lead is not None and _netvm(lead) == name
        except NetvmUnreadable:
            on_it = True                    # cannot tell: counts as on it
        if name in p.named_networks() or on_it:
            out.append(p.label)
    return sorted(out)


MODE_CLEARNET = ("anonymous mode: AI space uses only anonymising gateways, so a clearnet one "
                 "is never enrolled")


def anonymous_mode() -> bool:
    """Whether anonymous mode is on; a mode file that cannot be read refuses
    the command that asked (each caller's restrictive answer)."""
    try:
        return core.anonymous_mode()
    except core.ModeUnreadable as e:
        raise RoleError(f"{e}; whether anonymous mode is on cannot be told, so this is "
                        f"refused") from None


def _gateway_text(g) -> str:
    if not g.anonymising:
        return f"not anonymising, label '{g.label}'"
    return (f"anonymising, on {g.upstream}; templates' updates "
            + (f"may go to {g.upstream}" if g.updates else "do not count there")
            + f"; label '{g.label}'")


def _would_stop(app, registry_after: dict | None = None, overlay: dict | None = None,
                detail: bool = True) -> list:
    """What the gate judges sound now and would not with `registry_after`, or
    with the qubes in `overlay` (name -> tags) wearing those tags: the labels,
    the hub's as "the hub". A read that fails counts as a stop. Without
    `detail` a failed read is said without its error, so text that is hashed
    (a proposal's second tick) does not change with a transient error."""
    def unsure(e) -> str:
        return f"cannot tell: {e}" if detail else "cannot tell"
    try:
        records = _load_records()
        subjects = anon.subjects(records)
    except (ProjectError, core.ModeUnreadable) as e:
        return [f"({unsure(e)})"]
    out = []
    for p in subjects:
        try:
            before = anon.judge(app, p, records=records)
            if before.status != anon.GREEN:
                continue
            after = anon.judge(app, p, records=records, registry=registry_after,
                               overlay=overlay)
        except (core.Unreadable, anon.PolicyUnreadable) as e:
            out.append(f"{p.label} ({unsure(e)})")
            continue
        if after.status != anon.GREEN:
            out.append(p.label)
    return out


def enroll_gateway(app, name: str, anonymising: bool = False, label: str = "",
                   updates: bool = False) -> str:
    """Let AI space use a gateway. `updates`: the operator's word that the qube
    above it carries templates' updates anonymously (an anonymising one only).
    In anonymous mode only an anonymising gateway is enrolled."""
    err = gateways.label_refusal(label)
    if err:
        raise RoleError(err)
    if updates and not anonymising:
        raise RoleError("--updates is for an anonymising gateway: it says the qube above it "
                        "carries updates anonymously")
    if not anonymising and anonymous_mode():
        raise RoleError(MODE_CLEARNET)
    with _Exclusive():
        registry = gateways.load()
        if name in registry:
            raise RoleError(f"'{name}' is enrolled already; change it with qmcp gateway set")
        if len(registry) >= gateways.MAX_GATEWAYS:
            raise RoleError(f"at most {gateways.MAX_GATEWAYS} gateways")
        why = gateway_refusal({vm.name: vm for vm in app.domains}, name)
        if why:
            raise RoleError(f"'{name}' cannot be enrolled: {why}")
        upstream = _recorded_upstream(app, name) if anonymising else None
        g = registry[name] = gateways.Gateway(name, bool(anonymising), label, upstream, updates)
        gateways.save(registry)
    return f"{name}: enrolled" + (f" ({_gateway_text(g)})" if anonymising else "")


def set_gateway(app, name: str, anonymising=None, label=None, updates=None) -> str:
    """Change a gateway's flag, label or updates tick. Marking it anonymising
    records its network as it is now, so after moving an anonymising router to
    a new upstream the operator marks it again; the updates tick stays only
    while the recorded network is the same, since it was given for that one.
    Taking the flag off one an anonymous project uses is refused (and in
    anonymous mode taking it off at all), as is taking the tick off where the
    gate would then stop a project or the hub."""
    if label is not None and gateways.label_refusal(label):
        raise RoleError(gateways.label_refusal(label))
    if anonymising is False and anonymous_mode():
        raise RoleError(MODE_CLEARNET)
    with _Exclusive():
        registry = gateways.load()
        g = registry.get(name)
        if g is None:
            raise RoleError(f"'{name}' is not enrolled")
        vm = _vm(app, name)
        if vm is not None and _held(_tags(vm)):
            raise RoleError(f"'{name}' {HELD_WHY}")
        before = gateways.Gateway(g.name, g.anonymising, g.label, g.upstream, g.updates)
        if anonymising is True:
            upstream = _recorded_upstream(app, name)
            keep = g.anonymising and g.updates and upstream == g.upstream
            g.anonymising, g.upstream, g.updates = True, upstream, keep
        elif anonymising is False and g.anonymising:
            users = _anonymous_users(app, name)
            if users:
                raise RoleError(f"'{name}' carries the anonymous project(s) {', '.join(users)}; "
                                f"they would be stopped. Delete them, or give them other "
                                f"networks, first")
            g.anonymising, g.upstream, g.updates = False, None, False
        if updates is True:
            if not g.anonymising or g.upstream is None:
                raise RoleError(f"'{name}' is not anonymising with a recorded network; mark it "
                                f"(--anonymising yes) to tick its updates")
            g.updates = True
        elif updates is False:
            g.updates = False
        if label is not None:
            g.label = label
        if before.updates and not g.updates:
            stopped = _would_stop(app, registry)
            if stopped:
                raise RoleError(f"without the updates tick on '{name}' the anonymity gate would "
                                f"stop {', '.join(stopped)}: their templates' updates go to "
                                f"{before.upstream}. Send them elsewhere first")
        gateways.save(registry)
    return f"{name}: {_gateway_text(g)}"


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
        # Its updates tick goes with it: refused where the gate would then stop
        # a project or the hub, as taking the tick off is.
        after = {n: g for n, g in registry.items() if n != name}
        stopped = _would_stop(app, after) if registry[name].updates else []
        if stopped:
            raise RoleError(f"without '{name}' the anonymity gate would stop "
                            f"{', '.join(stopped)}: their templates' updates go to "
                            f"{registry[name].upstream}. Send them elsewhere first")
        del registry[name]
        gateways.save(registry)
    return f"{name}: no longer enrolled"


# ------------------------------------------------------------------ model qubes
#
# A project's lead may use a self-hosted model: a model qube, guarded and with
# no network, which the lead reaches over qubes.ConnectTCP on port 11434 (the
# rulebook's A6 lines, one per slot, routed on `qmcp-model-pNN`). A lead whose
# model is a qube has no network itself. One model qube may serve several
# projects, one badge each; that is a path between them (`SHARED_MODEL_WARNING`).

MODEL_PORT = projects.MODEL_PORT

#: Said wherever a model qube is shared: the command's report, the window and
#: the docs. qmcp ships no filter.
SHARED_MODEL_WARNING = (
    "a model qube that serves several projects is a path between them: Ollama's API has "
    "no login and lets any client create, copy and delete models, so a hijacked lead can "
    "change the model another project's lead uses, or pass it data. It is safe only behind "
    "an API filter that lets inference calls through and nothing else; qmcp ships none")


def model_qube_refusal(by_name: dict, name: str, hub=None) -> str | None:
    """None if `name` may be a project's model qube, else why not.

    An AppVM or StandaloneVM in AI space (the command guards it; it never
    brings a qube into AI space, so neither can a proposal) that is no
    template, disposable template or gateway; not the hub, a drop box, a lead
    or a member of any project (one in p00 leaves p00 when it becomes a model
    qube); its system comes from no template the hub manages (every template in
    its chain outside AI space or guarded), since what runs in it comes from
    that template at every start. Serving another project already is no
    refusal: the command warns that it is shared. A read that fails refuses
    it, until it reads; so does a hub file that cannot be read."""
    try:
        return _model_qube_refusal(by_name, name, hub)
    except core.Unreadable as e:
        return f"{e}, so it is refused until that reads"


def _model_qube_refusal(by_name: dict, name: str, hub) -> str | None:
    vm = by_name.get(name)
    if vm is None or core.klass_of(vm) == "AdminVM":
        return "no such qube"
    hub = core.read_hub() if hub is None else hub
    if hub is None:
        return f"{core.HUB_PATH} cannot be read, so it is not known whether it is the hub"
    if name == hub:
        return "is the hub"
    klass = core.klass_of(vm)
    if klass not in ("AppVM", "StandaloneVM"):
        return f"is a {klass}; a model qube is an AppVM or a StandaloneVM"
    if core.is_dvmt(vm):
        return "is a disposable template"
    if core.is_gateway(vm):
        return "provides network"
    try:
        tags = _tags(vm)
    except core.Gone:
        return "no such qube"
    if projects.DROP_BOX in tags or _dump_slots(tags):
        return "is a drop box"
    if _held(tags):
        return HELD_WHY
    try:
        # Checked before anything changes: the model badge would refuse it
        # anyway, after the lead and the qube had lost their networks.
        if restored.in_scope(tags) and not restored.known(vm):
            return WAITS_WHY
    except core.Unreadable as e:
        return f"its qmcp-id label cannot be read ({e})"
    if core.UMBRELLA not in tags:
        return f"is outside AI space: guard it first (qmcp guard {name})"
    if projects.LEAD in tags or projects.lead_slots(tags):
        return "is a lead"
    others = projects.member_slots(tags) - {projects.HUB_SLOT}
    if others:
        return f"is a member of {', '.join(sorted(others))}"
    for tpl in _template_chain(vm):
        tpl_tags = _tags(tpl)
        if core.UMBRELLA in tpl_tags and core.GUARDED not in tpl_tags:
            return f"its template {tpl.name} is one the hub manages (guard it, or use another)"
    return None


def _dump_slots(tags) -> set:
    return {p[1] for p in map(projects.slot_badge_parts, tags) if p and p[0] == "dump"}


def model_qube_findings(app, vms, by_name: dict, records: dict, tags_by: dict, hub,
                        policy=None, system_info=None) -> list:
    """The model qubes, judged by the badges the rulebook routes on. A lead
    reaches whatever wears its slot's model badge on port 11434 (but the hub,
    a lead or a drop box, which the rulebook refuses first), so a badge in the
    wrong place fails: on a qube with a network (a model server with one is
    a way out for the lead around the firewall the operator owns: Ollama
    fetches a "model" from any host it is told to), outside AI space, on a
    member, lead, template, gateway, drop box or the hub, on a qube whose
    template the hub manages, or a badge its slot's record does not name; and
    on a qube dom0's policy gives Qubes' update proxy, an HTTP proxy out
    around "no network" (a `whonix-updatevm` tag, or a rule naming it), asked
    of qrexec's parser as the anonymity gate asks it. An
    un-guarded model qube is a warning: the operator's maintenance window,
    during which the hub may operate it. So is a recorded model qube that is
    gone or unbadged: its lead just cannot reach it."""
    out: list = []
    bad, warn, unread = [], [], []
    holders = {}
    for vm in vms:
        if vm.name not in tags_by:
            continue
        slots = projects.model_slots(tags_by[vm.name])
        if slots:
            holders[vm.name] = slots
    for name in sorted(holders):
        vm, tags, slots = by_name[name], tags_by[name], holders[name]
        for slot in sorted(slots):
            rec = records.get(slot)
            if rec is None or not rec.label:
                bad.append(f"{name} wears {projects.model_badge(slot)}, which no project's record names")
            elif rec.model_qube != name:
                bad.append(f"{name} wears {projects.model_badge(slot)}, but {rec.label}'s record names "
                           f"{rec.model_qube or 'no model qube'}")
        if core.UMBRELLA not in tags:
            # Not the command's advice to guard it: a stray badge comes off.
            bad.append(f"{name} is outside AI space but wears a model badge, which the rulebook "
                       f"still routes on")
            continue
        try:
            why = _model_qube_refusal(by_name, name, hub)
        except core.Unreadable as e:
            unread.append(str(e).removeprefix("cannot read "))
            why = None
        # A hold is the restore item's warning: nothing reaches a held qube
        # until the operator accepts it, its leads included.
        if why and why != HELD_WHY:
            bad.append(f"{name}: {why}")
        if projects.HUB_SLOT in projects.member_slots(tags):
            label = next((records[s].label for s in sorted(slots)
                          if s in records and records[s].label), "PROJECT")
            bad.append(f"{name} is in p00: it copies into the hub's p00 qubes without a dialog "
                       f"(qmcp project firewall {label} --model-qube {name} takes it out)")
        try:
            net = _netvm(vm)
        except NetvmUnreadable:
            unread.append(f"the network of {name}")
            net = None
        if net is not None:
            bad.append(f"{name} has a network ({net}): its leads reach that network through it")
        if policy is None or system_info is None:
            unread.append(f"where dom0's policy sends the updates of {name} (the policy did not load)")
        else:
            from qmcp import anon
            try:
                target = anon.update_target(policy, system_info, name)
            except anon.PolicyUnreadable as e:
                unread.append(str(e))
                target = None
            if target is not None:
                bad.append(f"{name}: dom0's policy gives it the update proxy ({target}), so its "
                           f"leads reach the network through it all the same")
        if core.GUARDED not in tags:
            warn.append(f"{name} is not guarded: while it serves "
                        f"{', '.join(sorted(slots))}, the hub may operate it (qmcp guard {name} "
                        f"when its changes are done)")
    for p in sorted(records.values(), key=lambda p: p.slot):
        if not p.label or p.model_qube is None:
            continue
        if p.model_qube not in by_name:
            warn.append(f"{p.label}: its model qube {p.model_qube} does not exist")
        elif p.model_qube in tags_by and p.slot not in holders.get(p.model_qube, set()):
            warn.append(f"{p.label}: its model qube {p.model_qube} does not wear "
                        f"{projects.model_badge(p.slot)}, so its lead cannot reach it "
                        f"(qmcp project firewall {p.label} --model-qube {p.model_qube})")
    note = f"; cannot read {', '.join(sorted(set(unread)))}" if unread else ""
    if bad:
        out.append(Finding("fail", "model qubes", "; ".join(bad) + note))
    elif unread:
        out.append(Finding("error", "model qubes", note[2:]))
    else:
        out.append(Finding("pass", "model qubes",
                           f"{len(holders)} model qube(s), each in AI space with no network and no update "
                           f"proxy, in no "
                           f"slot, and named by its projects' records" if holders else "none"))
    if warn:
        out.append(Finding("warn", "model qubes", "; ".join(warn)))
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
    except (OSError, UnicodeDecodeError):
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
                   compat_default: str | None = None, tier_default: str | None = "unset",
                   review: bool = True):
    """(steps, problems). Nothing is changed. With `review` (the migration
    itself), a qube held for review is refused, and so, once any qube in scope
    carries a label, is one whose label is missing or another's. The
    installer's preflight asks only whether the fleet is in the two-state
    shape (`review=False`): a restored qube is the restore check's to hold.

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
    # The restore check's labels. A migration never writes one: on a fleet
    # where no qube in scope carries a label yet (v0.9.16, which the installer
    # seeds), there is nothing to review. Once one does, a qube in scope that is
    # not known came back from a backup or a copy and waits for review, held
    # yet or not, and the migration refuses it.
    labels, unknown = {}, set()
    for vm in app.domains:
        if not review or vm.name not in tags_by or not restored.in_scope(tags_by[vm.name]):
            continue
        try:
            labels[vm.name] = restored.label_of(vm)
            if not restored.known(vm):
                unknown.add(vm.name)
        except core.Unreadable as e:
            problems.append(f"{vm.name}: {e}; run the plan again")
    labels_exist = any(v is not None for v in labels.values())
    for vm in app.domains:
        if vm.name not in tags_by:
            continue
        tags = tags_by[vm.name]
        if review and _held(tags):
            problems.append(f"{vm.name} {HELD_WHY}: accept or reject it first")
            continue
        if review and labels_exist and vm.name in unknown:
            problems.append(f"{vm.name} wears qmcp badges but its qmcp-id label is missing or "
                            f"another qube's: it came back from a backup or a copy and waits for "
                            f"review (qmcp restored list): accept or reject it first")
            continue
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


def _refuse_held(vm, name) -> None:
    if _held(_read_tags(vm)):
        raise RoleError(f"'{name}' {HELD_WHY}")


def _label(vm, name) -> None:
    """Label a qube before `manage` or `guard` adds a badge (`qmcp.restored`).
    A qube with no qmcp badge is the operator's to bring in, whatever label an
    earlier life left on it, so it is labelled afresh. One that wears a badge and
    carries another qube's label came back from a backup or a copy, and waits
    for review: refused, so a command can never stand in for an accept."""
    try:
        if restored.labelled(vm):
            return
        if restored.in_scope(_read_tags(vm)):
            raise RoleError(f"'{name}' wears qmcp badges but its qmcp-id label is missing or "
                            f"another qube's: it came back from a backup or a copy, or was "
                            f"badged outside qmcp, and waits for review (qmcp restored list)")
        restored.label(vm)
    except RoleError:
        raise
    except Exception as e:
        raise RoleError(f"'{name}' could not be labelled ({type(e).__name__}), so nothing was "
                        f"changed") from None


def _target(app, name, sealing: bool = False, from_hub: bool = False):
    """The qube a role action or a window acts on. With the hub file unread,
    any name may be the hub, so every action refuses but `sealing`: taking a
    window off only ever lowers authority, and must work then too (the boot
    seal and the expiry pass run it). `from_hub`: for an accepted proposal, a
    hidden project's qube answers first, as a name that does not exist, on
    the tags read here, before any refusal that would name what it is."""
    if not core.valid_qube_name(name) or name not in app.domains:
        raise RoleError(f"no qube named '{name}'")
    if from_hub and projects.HUBBLIND in _read_tags(app.domains[name]):
        raise RoleError(f"no qube named '{name}'")
    hub = core.read_hub()
    if hub is None and not sealing:
        raise RoleError(f"{core.HUB_PATH} cannot be read, so whether '{name}' is the hub is not "
                        f"known; fix it first (qmcp check)")
    if name == hub:
        raise RoleError(f"'{name}' is the hub; the hub is never in AI space")
    vm = app.domains[name]
    try:
        admin = core.klass_of(vm) == "AdminVM"
    except core.Unreadable as e:
        raise RoleError(f"{e}; try again") from None
    if admin:
        # Before any write: revoke would otherwise pin dom0's own default
        # disposable template before its shutdown failed.
        raise RoleError(f"'{name}' is dom0, which is never in AI space")
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
        except gateways.GatewaysUnreadable as e:
            raise RoleError(f"'{name}' is on {net}, and whether that is an enrolled gateway "
                            f"cannot be told: the gateway registry does not read ({e})") from None
        if not enrolled:
            raise RoleError(f"'{name}' is on {net}, which is not an enrolled gateway: enroll it "
                            f"(qmcp gateway enroll {net}) or clear the qube's network first")


def _mode_badge(vm, name) -> None:
    """In anonymous mode a qube wears `qmcp-anon` before it joins AI space, so
    no moment of it in AI space is outside the rulebook's anonymous denies."""
    if anonymous_mode():
        try:
            vm.tags.add(projects.ANON)
        except Exception as e:
            raise RoleError(f"'{name}' could not be given {projects.ANON} ({type(e).__name__}), "
                            f"so it was not added to AI space") from None


def tags_after_manage(tags) -> set:
    """The tags `qmcp manage` leaves on a qube that wears `tags`: in AI space,
    not guarded, its window ended, `qmcp-anon` in anonymous mode (RoleError
    when the mode does not read)."""
    return (set(tags) - LEGACY_TIER_TAGS - {core.GUARDED, core.OPEN, core.OPEN_FW}) \
        | {core.UMBRELLA} | ({projects.ANON} if anonymous_mode() else set())


def outside_dependants(app, name: str) -> list:
    """The qubes the hub does not operate (outside AI space, or guarded: a model
    qube, a gateway, a guarded disposable template) whose template chain holds
    `name`, sorted: managed, `name` would hand the hub root in what they run.
    Raises
    `core.Unreadable` when the qube list, a chain or a qube's tags do not
    read: one that cannot be read may be among them."""
    out = []
    try:
        vms = list(app.domains)
    except Exception:
        raise core.Unreadable("cannot list the qubes") from None
    for vm in vms:
        n = core.name_of(vm)
        try:
            if n == name or core.klass_of(vm) == "AdminVM":
                continue
            if name in {t.name for t in _template_chain(vm)}:
                tags = core.tags_of(vm)
                if core.UMBRELLA not in tags or core.GUARDED in tags:
                    out.append(n)
        except core.Gone:
            continue
    return sorted(out)


def _named_few(names, most: int = 8) -> str:
    return ", ".join(names[:most]) + (f" and {len(names) - most} more" if len(names) > most else "")


def pci_devices(vm) -> int:
    """How many PCI devices are assigned to the qube. Raises RoleError when
    that cannot be read: a failed read is never "none"."""
    try:
        return len(list(vm.devices["pci"].get_assigned_devices()))
    except Exception as e:
        raise RoleError(f"'{core.name_of(vm)}''s devices cannot be read ({type(e).__name__}); "
                        f"try again") from None


def _with_qube_lock(name, must: bool, fn, timeout=None, error=None, settle=None):
    """Run `fn(held)` holding the qube's lock (`core.qube_lock`), which the
    services hold from their check to their effect: a call already past its
    check lands before this command acts, and none lands after. `must`: a
    command that grants authority refuses when the lock is held past the
    wait. One that only takes authority away goes on without it, then waits
    for the lock again and runs `settle()`, whose words it adds: by then the
    calls that were in flight have finished, and no new one gets past its
    check, since the qube no longer resolves for it (out of AI space, guarded,
    open no more). Only when that second wait fails too does it say it went
    on without the lock. A name that is not a qube name takes no lock: the
    command refuses it in its own words."""
    if not core.valid_qube_name(name):
        return fn(False)
    lock = core.qube_lock(name, must=must, timeout=timeout)
    try:
        held = lock.__enter__()
    except core.QubeBusy as e:
        raise (error or RoleError)(str(e)) from None
    except core.Refusal as r:
        if not must:
            # A lock that cannot even be opened never stops a command that
            # only takes authority away: it goes on, unlocked, and says so.
            return fn(False) + UNLOCKED
        raise (error or RoleError)(f"'{name}''s lock cannot be taken ({r.payload.get('error')}), "
                                   f"so nothing was changed") from None
    if held:
        try:
            return fn(True)
        finally:
            lock.__exit__(None, None, None)
    out = fn(False)
    if settle is None:
        return out + UNLOCKED
    late = core.qube_lock(name, must=False, timeout=timeout)
    try:
        got = late.__enter__()
    except core.Refusal:
        got = False
    try:
        return out + (settle() if got else UNLOCKED)
    finally:
        late.__exit__(None, None, None)


#: Said when a command that takes authority away went on without the lock.
UNLOCKED = ("; its lock could not be had (a call held it past the wait, or the lock "
            "could not be opened), so the command went on without it: check the qube "
            "(qmcp list) once any call on it has finished")


def manage(app, name, from_hub: bool = False) -> str:
    """`qmcp manage`, under the qube's lock (`_manage`)."""
    return _with_qube_lock(name, True, lambda held: _manage(app, name, from_hub))


def _manage(app, name, from_hub: bool = False) -> str:
    """`qmcp manage`. Refuses a qube wearing lead badges, or a project's
    member badge without being a managed qube of it (`slot_badge_refusal`).
    `from_hub`: the command an accepted `qube-manage` runs, which also refuses
    a hidden project's qube (as a name that does not exist), a qube that holds
    a PCI device (the hub would have root over a USB or network controller),
    and a template that a qube the hub does not operate is built on, or whose
    dependants cannot be read (`outside_dependants`); the operator's own
    command takes those three."""
    vm = _target(app, name, from_hub=from_hub)
    _refuse_held(vm, name)
    why = slot_badge_refusal(_read_tags(vm), name)    # a read that fails refuses
    if why:
        raise RoleError(why)
    if from_hub:
        held = pci_devices(vm)
        if held:
            raise RoleError(f"'{name}' holds {held} PCI device(s): a hub's proposal cannot manage "
                            f"a qube that holds a device (qmcp manage {name} yourself if you "
                            f"mean it)")
        try:
            outside = outside_dependants(app, name)
        except core.Unreadable as e:
            raise RoleError(f"which qubes are built on '{name}' cannot be read ({e}), and one "
                            f"the hub does not operate may be: a hub's proposal cannot manage it "
                            f"(qmcp manage {name} yourself if you mean it)") from None
        if outside:
            raise RoleError(f"'{name}' is the template of qubes the hub does not operate "
                            f"(outside AI space or guarded) "
                            f"({_named_few(outside)}): a hub's proposal cannot manage it, since "
                            f"the hub would have root in what they run (qmcp manage {name} "
                            f"yourself if you mean it)")
    if _is_gateway(vm):
        raise RoleError(f"'{name}' provides network; gateways are always guarded (qmcp guard)")
    _network_enrolled(vm, name)
    _label(vm, name)
    _mode_badge(vm, name)
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
    # An open window ends: a managed qube needs none, and a badge left on it
    # would have the expiry pass kill it. No kill here: it is the hub's now.
    # Its badges come off while the qube is still guarded, so the expiry pass,
    # which reads without the qube's lock, never sees a managed qube that is
    # open, and a failure leaves it guarded and open, which a seal ends.
    ended = ""
    if tags & {core.OPEN, core.OPEN_FW}:
        try:
            _set_tags(vm, remove=sorted(tags & {core.OPEN, core.OPEN_FW}))
        except Exception as e:
            raise RoleError(f"'{name}' is in AI space now, but its open window's badges could "
                            f"not be taken off ({type(e).__name__}): run qmcp seal {name}, then "
                            f"qmcp manage {name} again") from None
        clear_window(name)
        ended = "; its open window ended, with no kill: it is managed now"
    elif kill_pending(name):
        # A seal whose kill failed left it pending: the expiry pass would
        # kill the qube the operator just handed to the hub.
        clear_window(name)
        ended = "; the kill its seal could not make is dropped: it is managed now"
    for t in sorted((tags & LEGACY_TIER_TAGS) | ({core.GUARDED} & tags)):
        vm.tags.discard(t)
    serves = projects.model_slots(tags)
    kind = _model_qube_kind(vm) if serves else False
    if kind is False:
        # No model qube, whatever it wears: qmcp check fails on the badge.
        return f"{name}: managed" + ended
    return (f"{name}: managed; it is still the model qube of {', '.join(sorted(serves))}: "
            f"while it is managed the hub may operate it (qmcp guard {name} when its changes "
            f"are done" + (", which kills it if it runs)" if kind else ")"))


def slot_badge_refusal(tags, name: str) -> str | None:
    """Why `manage` refuses a qube for the slot badges it wears, or None. The
    rulebook routes on badges, not records: a lead badge, or a project's member
    badge on a qube that is not already managed in AI space, would hand the
    hub, through the qube it then operates, what that badge routes to."""
    tags = set(tags)
    if projects.LEAD in tags or projects.lead_slots(tags):
        return (f"'{name}' wears a lead's badges: managing it would hand the hub what they route "
                f"to; a project's lead changes with qmcp project lead, and qmcp revoke {name} "
                f"takes stray ones off")
    members = projects.member_slots(tags) - {projects.HUB_SLOT}
    if members and (core.UMBRELLA not in tags or core.GUARDED in tags):
        return (f"'{name}' wears the member badge of {', '.join(sorted(members))} without being "
                f"a managed qube of that slot: managing it would make it one; qmcp revoke {name} "
                f"takes the badge off, and qmcp project move puts a managed qube in a slot")
    return None


def _not_in_a_slot(vm, name, action: str) -> set:
    """The qube's tags, read once. Refuses the lead a project's record names
    (`qmcp project lead --remove` takes it away), and a member unless revoking.
    A qube wearing a lead badge that no record names is no lead: revoke takes
    the badges off, which is its fix, and guard and open refuse it until then.
    While the records do not read, revoke goes on, since it only takes
    authority away, and guard and open refuse."""
    tags = _read_tags(vm)
    if projects.LEAD in tags or projects.lead_slots(tags):
        try:
            p = projects.by_lead(projects.load(), name)
        except projects.ProjectsUnreadable as e:
            if action != "revoke":
                raise RoleError(f"'{name}' wears a lead's badges and the project records do not "
                                f"read ({e}), so whether it leads a project cannot be told; if it "
                                f"does not, qmcp revoke {name} takes them off") from None
        else:
            if p is not None:
                key = p.label or p.slot
                raise RoleError(f"'{name}' is the lead of {key}; use qmcp project lead {key} "
                                f"--remove first")
            if action != "revoke":
                raise RoleError(f"'{name}' wears a lead's badges, but no project's record names "
                                f"it as its lead: qmcp revoke {name} takes them off, with every "
                                f"other badge (it leaves AI space, and is killed if it runs)")
    if projects.member_slots(tags) and action != "revoke":
        raise RoleError(f"'{name}' is in a project slot; qmcp project move {name} none first")
    return tags


def guard(app, name, in_ai_space_only: bool = False) -> str:
    """`qmcp guard`, under the qube's lock (`_guard`). `in_ai_space_only`
    (`--only-in-ai-space`, which the window always sends) refuses a qube
    outside AI space instead of adding it, guarded: the window's view may be
    older than a revoke, and its Guard only takes authority away."""
    return _with_qube_lock(name, False, lambda held: _guard(app, name, in_ai_space_only),
                           settle=lambda: _settle_guard(app, name))


def _settle_guard(app, name) -> str:
    """After a guard that went on without the lock: a remove that was already
    past its check when the guard landed has finished by now."""
    if _gone_by_name(app, name):
        raise RoleError(f"'{name}' was guarded, but a call that was already running then has "
                        f"removed it since")
    return ""


def _gone_by_name(app, name) -> bool:
    try:
        clear = getattr(app.domains, "clear_cache", None)
        if clear is not None:
            clear()
        return name not in app.domains
    except Exception:
        return False


def _guard(app, name, in_ai_space_only: bool = False) -> str:
    vm = _target(app, name)
    _refuse_held(vm, name)
    before = _not_in_a_slot(vm, name, "guard")      # a read that fails refuses
    if in_ai_space_only and core.UMBRELLA not in before:
        raise RoleError(f"'{name}' is outside AI space, and --only-in-ai-space refuses to add "
                        f"it (qmcp guard {name} without it adds it to AI space, guarded)")
    # The network and the mode decide only for a qube joining AI space: a
    # guard of one already in it only takes authority away, and a registry or
    # mode file that does not read must not stop it.
    joining = core.UMBRELLA not in before
    if joining:
        _network_enrolled(vm, name)
    mode = anonymous_mode() if joining else False     # read before anything is written
    _label(vm, name)
    serves = sorted(projects.model_slots(before))
    # A model qube's maintenance window closes (managed to guarded): what the
    # hub started in it while it was managed is stopped. It is killed right
    # after the guard lands, before any other read or write, so no later
    # failure leaves it guarded and still running (a second guard finds it
    # guarded and kills nothing). The kill ends the hub's processes, not its
    # files: what it left in /home, /usr/local or /rw (anywhere, in a
    # StandaloneVM) stays, and whatever is set to start from there runs at its
    # next start. One already guarded is left alone: the hub could not reach it, and
    # its leads may be using it. Only a kind of qube that can be a model qube is
    # killed: a gateway or a template wearing a stray badge is not (killing it
    # would take its clients' network, or break an update).
    candidate = bool(serves) and core.UMBRELLA in before and core.GUARDED not in before
    # A kind that cannot be read never stops the guard, which takes the hub's
    # authority away: it only stops the kill, and the operator is told.
    kind = _model_qube_kind(vm) if candidate else False
    window = candidate and kind is True
    # Said with every outcome from the guard on, since a second guard finds
    # the qube guarded and says nothing of a kill.
    unknown = (f"whether it can be a model qube could not be read, so it was not killed: if it "
               f"runs and is no gateway or disposable template, kill it by hand (qvm-kill {name})"
               if candidate and kind is None else "")
    try:
        vm.tags.add(core.GUARDED)
    except Exception as e:
        # qubesd may have set the tag before the call failed: kill as if it
        # had, or a second guard would find it guarded and spare it.
        failed, done = type(e).__name__, (_kill_if_running(vm) if window else "halted")
        if done not in ("halted", "killed"):
            raise RoleError(f"'{name}' may be guarded now, but the call failed ({failed}), and it "
                            f"could NOT be killed ({done}): a process the hub started in it may "
                            f"still run; kill it by hand (qvm-kill {name}), then run qmcp guard "
                            f"{name} again") from None
        raise RoleError(f"'{name}' may be guarded now, but the call failed ({failed})"
                        + ("; it was killed" if done == "killed" else "")
                        + (f"; {unknown}" if unknown else "")
                        + f"; run qmcp guard {name} again") from None
    tail = _kill_after_guard(vm, name, serves) if window else ""
    if mode and core.UMBRELLA not in before and not _is_gateway(vm):
        _mode_badge(vm, name)
    if unknown:
        # Right after the guard lands, before any other read or write can fail
        # and hide it. The umbrella is already on (a candidate is in AI space);
        # a second guard strips any old tier tags.
        raise RoleError(f"'{name}' is guarded now, but {unknown}; then run qmcp guard {name} "
                        f"again")
    try:
        vm.tags.add(core.UMBRELLA)
    except Exception as e:
        raise RoleError(f"'{name}' is guarded now" + ("; it was killed" if tail else "")
                        + f", but it could not be added to AI space ({type(e).__name__}); run "
                        f"qmcp guard {name} again") from None
    try:
        tags = _tags(vm)
    except core.Unreadable as e:
        raise RoleError(f"'{name}' is guarded now, but {e}; run qmcp guard {name} again") from None
    for t in sorted(tags & LEGACY_TIER_TAGS):
        vm.tags.discard(t)
    return f"{name}: guarded" + tail


def _kill_if_running(vm) -> str:
    """"halted" (it was not running), "killed", or the name of the error that
    left it running or its state unknown. Only "Halted" counts as not running:
    "NA" is qubesadmin's answer for a qube it cannot read, and a state that
    cannot be read is never taken for halted (a kill on a halted qube fails,
    and the state read after it decides)."""
    if _safe(vm.get_power_state, "unknown") == "Halted":
        return "halted"
    try:
        vm.kill()
    except Exception as e:
        return "halted" if _safe(vm.get_power_state, "unknown") == "Halted" else type(e).__name__
    # Read back: only a qube that reads halted, or one qubesd says is gone (a
    # disposable Qubes removed when it stopped), is down. One that reads up (a
    # start that landed right after the kill) or whose state cannot be read is
    # not known to be down.
    after = _safe(vm.get_power_state, "unknown")
    if after == "Halted" or _gone(vm):
        return "killed"
    return f"{after} after the kill" if after in ("NA", "unknown") else f"still {after} after the kill"


def _gone(vm) -> bool:
    """True only when qubesd says the qube no longer exists."""
    try:
        domains = vm.app.domains
        clear = getattr(domains, "clear_cache", None)
        if clear is not None:
            clear()
        return core.name_of(vm) not in domains
    except Exception:
        return False


def _model_qube_kind(vm):
    """True for an AppVM or a StandaloneVM that is no disposable template and
    provides no network (the kinds `model_qube_refusal` lets be a model qube),
    False for any other kind, None when that cannot be read."""
    try:
        return core.klass_of(vm) in ("AppVM", "StandaloneVM") and not core.is_dvmt(vm) \
            and not core.is_gateway(vm)
    except core.Unreadable:
        return None


def _kill_after_guard(vm, name, serves) -> str:
    """Kill a model qube that is running once its maintenance window closes:
    its leads' next connection starts it. The report's tail, in words; a kill
    that fails, its state not Halted, is a RoleError, so the command exits 1."""
    done = _kill_if_running(vm)
    if done == "halted":
        return ""
    if done != "killed":
        raise RoleError(f"'{name}' is guarded now, but it could NOT be killed ({done}): a process "
                        f"the hub started in it may still run; kill it by hand (qvm-kill {name})")
    return (f"; killed: what the hub had running in it while it was managed is stopped "
            f"(a lead of {', '.join(serves)} starts it again by connecting)")


def _kill_model_qube(report, slot, vm, name, managed: bool, guard_failed: str = "") -> None:
    """The model command's kill, in the report. A kill that fails stops the
    command before the record names the qube and before it wears this slot's
    badge, so the command gives no further lead a qube that may still run what
    was started in it. `guard_failed`: the guard step's own error, when that
    step failed and the guard may not have landed."""
    done = _kill_if_running(vm)
    started = ("the hub started in it while it was managed" if managed else
               "was started in it before it became a model qube")
    if done == "killed":
        report.append(f"{slot}: {name} killed: what {started} is stopped; its lead starts it "
                      f"again by connecting")
    elif done != "halted":
        state = (f"may not be guarded (that step failed too: {guard_failed})" if guard_failed
                 else "is guarded")
        raise ProjectError(f"{name} {state}, and it could NOT be killed ({done}): a process "
                           f"{started} may still run; kill it by hand (qvm-kill {name}), then "
                           f"run the command again")


def revoke(app, name, shutdown: bool = True, from_hub: bool = False, remove: bool = False) -> str:
    """`qmcp revoke`, under the qube's lock (`_revoke`). `remove`: then remove
    it (`--remove`, or an accepted `qube-revoke` with `remove`): the hub's way
    to have a qube without an owner badge removed, besides deleting a project
    it is a member of (the services refuse such a remove)."""
    out = _with_qube_lock(name, False,
                          lambda held: _revoke(app, name, shutdown, from_hub, remove),
                          settle=lambda: _settle_kill(app, name) if shutdown else "")
    if remove:
        # Removed: its lock file and turnstile go too, as for every remove qmcp
        # makes, once this command has let the lock go (a file a call holds by
        # then is left for the gate's sweep; it grants nothing).
        core.retire_qube_locks(name)
    return out


def _settle_kill(app, name) -> str:
    """After a revoke or a seal that went on without the lock: a start that
    was already past its check has landed by now, so the qube is killed again
    and read back."""
    if _gone_by_name(app, name):
        return ""
    done = _kill_if_running(app.domains[name])
    if done == "halted":
        return ""
    if done == "killed":
        return ("; a call that was already running started it again, so it was killed again "
                "once that call had finished")
    raise RoleError(f"'{name}': a call that was already running started it again, and it could "
                    f"NOT be killed ({done}): kill it by hand (qvm-kill {name})")


def _remove_refusal(app, vm, name, tags, plan: bool = False) -> str | None:
    """Why `revoke --remove` will not remove this qube, read before anything
    changes; None when it may. A guarded qube (a gateway is one), a model qube
    (by record or badge), a project's recorded lead, dump sink, approved
    template or worker network, a qube others are built on, start disposables
    from, reach the network through or use as their management disposable, GUI
    or audio qube, and one a global setting names. A lead
    by its badges and the drop box are refused before this (`_not_in_a_slot`,
    `_target`). A read that fails refuses: a remove cannot be undone. A remove
    Qubes refuses all the same fails after the revoke, which says so. `plan`: for `proposal show`, where a
    read that failed proves nothing, so it gives no reason (`_refusal_seen`)."""
    if plan:
        try:
            if core.GUARDED in tags or core.is_gateway(vm):
                return f"'{name}' is guarded: qmcp removes no guarded qube or gateway"
        except core.Unreadable:
            return None
    elif core.is_guarded(vm, tags):
        return (f"'{name}' is guarded: qmcp removes no guarded qube or gateway; qvm-remove it "
                f"by hand if you mean to")
    try:
        records = projects.load()
    except projects.ProjectsUnreadable as e:
        if plan:
            return None
        return f"the project records do not read ({e}), so whether '{name}' serves one is not known"
    serves = sorted(r.label or r.slot for r in records.values() if r.model_qube == name)
    if serves or projects.model_slots(tags):
        return (f"'{name}' is the model qube of {', '.join(serves) or 'a project'}: take it off "
                f"first (qmcp project firewall PROJECT --model-qube none)")
    named = sorted(r.label or r.slot for r in records.values() if name in (r.lead, r.dump))
    if named:
        return f"'{name}' is the lead or dump sink a project's record names ({', '.join(named)})"
    listing = sorted(r.label or r.slot for r in records.values()
                     if name in r.templates or name in r.networks)
    if listing:
        return (f"'{name}' is an approved template or worker network of {', '.join(listing)}: "
                f"take it off the list first (qmcp project edit)")
    users = []
    try:
        for other in list(app.domains):
            try:
                oname = core.name_of(other)
                if oname == name:
                    continue
                refs = (core.template_of(other), core.default_dispvm_of(other),
                        *core.service_qubes_of(other))
                if any(r is not None and _ref_name(r) == name for r in refs) \
                        or core.netvm_of(other) == name:
                    users.append(oname)
            except core.Gone:
                continue                # removed while it was read: it uses nothing
        for prop in _GLOBAL_QUBE_PREFS:
            if _ref_name(getattr(app, prop)) == name:
                users.append(f"the global {prop}")
    except Exception:
        if plan:
            return None
        return f"which qubes use '{name}' could not be read, so it is not removed"
    if users:
        shown = ", ".join(sorted(users)[:5]) + (", ..." if len(users) > 5 else "")
        return (f"'{name}' is in use by {len(users)} qube(s) (their template, default "
                f"disposable template, network, management disposable, GUI or audio qube): "
                f"{shown}; qubesd would refuse the remove")
    return None


#: Qubes' global settings that name a qube (`qubes-prefs`): qubesd refuses to
#: remove a qube one of them names, so `--remove` refuses it first.
_GLOBAL_QUBE_PREFS = ("default_dispvm", "default_netvm", "default_template",
                      "management_dispvm", "updatevm", "clockvm", "default_guivm",
                      "default_audiovm")


def _ref_name(ref):
    """The name a qube-valued property holds, None for none."""
    if ref is None or ref == "":
        return None
    return ref if isinstance(ref, str) else core.name_of(ref)


def _revoke(app, name, shutdown: bool = True, from_hub: bool = False,
            remove: bool = False) -> str:
    """Strip every AI-space badge, pin default_dispvm, and kill the qube if it
    runs, unless `shutdown` is false. `remove`: then remove it; every refusal
    of it is read first (`_remove_refusal`), so a refused remove changes
    nothing, and a remove that fails after the revoke leaves the qube revoked
    and killed, which is the safe end, and says so.
    Restrictions such as an egress lock go too: revoke is yours. `from_hub`:
    the command an accepted `qube-revoke` runs, which also refuses a hidden
    project's qube (as a name that does not exist), a qube outside AI space
    (the hub cannot see it), and keeping running a qube the hub could run
    commands in (managed, or open), whose processes would run on outside AI
    space."""
    vm = _target(app, name, from_hub=from_hub)
    before = _read_tags(vm)
    if _held(before):
        raise RoleError(f"'{name}' is held for your review: reject it instead (qmcp restored "
                        f"reject {name}), which also removes its label")
    if from_hub:
        if core.UMBRELLA not in before:
            raise RoleError(f"'{name}' is not in AI space: the hub revokes only a qube it can see")
        # A qube a seal could not kill yet still runs what the hub started in
        # it through the window: kept running, outside AI space, the revoke
        # would drop the kill the timer owes it.
        reachable = (core.GUARDED not in before) or bool(before & {core.OPEN, core.OPEN_FW}) \
            or kill_pending(name)
        if reachable and not shutdown:
            raise RoleError(f"the hub could run commands in '{name}', so a hub's proposal to "
                            f"revoke it kills it: propose it without shutdown false")
    _not_in_a_slot(vm, name, "revoke")
    if remove:
        if not shutdown:
            raise RoleError("--remove kills the qube first: it cannot be left running")
        if core.UMBRELLA not in before:
            raise RoleError(f"'{name}' is not in AI space: --remove removes only a qube in AI "
                            f"space (qvm-remove it if you mean to); nothing was changed")
        why = _remove_refusal(app, vm, name, before)
        if why:
            raise RoleError(f"{why}; nothing was changed")
    # A window (open, or a seal's kill still owed) becomes a pending kill
    # before anything comes off, as a seal does: then a kill of this revoke's
    # that fails, or a failure before it, leaves a kill the timer tries again.
    windowed = bool(before & {core.OPEN, core.OPEN_FW}) or kill_pending(name)
    owed = windowed and not (before & {core.OPEN, core.OPEN_FW})
    early = []
    if windowed and shutdown:
        try:
            mark_kill_pending(name, None, vm)
        except OSError as e:
            early.append(f"its window could not be marked for a kill ({type(e).__name__})")
    for t in sorted((t for t in _read_tags(vm) if birth.controlled(t)), key=_removal_order):
        vm.tags.discard(t)
    # Whatever fails after the badges came off, the kill still happens: a
    # qube out of AI space (or half out) must not run on what the hub started
    # in it because a later step failed. The failures are said together.
    problems = list(early)
    try:
        left = sorted(t for t in _tags(vm) if birth.controlled(t))
    except core.Unreadable as e:
        left = None
        problems.append(f"its badges were taken off, but {e}")
    if left:
        problems.append(f"it still wears {', '.join(left)}")
    dropped = False
    # Left running on purpose (--no-shutdown): the window's record goes with
    # its badges, and a seal's kill still owed is dropped, and said. With a
    # kill, the record goes only once that kill reads back (below).
    if windowed and not shutdown and not problems:
        clear_window(name)
        dropped = owed
    msg = f"{name}: revoked" + ("; the kill its seal could not make is dropped" if dropped
                                else "")
    if shutdown:
        # Killed, never asked: a guest the hub ran as root can ignore a
        # shutdown request, and a paused one refuses it, and either would run
        # on outside AI space with nothing watching it. Read back: a qube that
        # is not known to be down fails the command.
        done = _kill_if_running(vm)
        if done not in ("halted", "killed"):
            raise RoleError(f"'{name}' is revoked, but it could NOT be killed ({done}): a process "
                            f"the hub started in it may still run, outside AI space; kill it by "
                            f"hand (qvm-kill {name})"
                            + (f"; and {'; '.join(problems)}: run qmcp revoke {name} again"
                               if problems else ""))
        if done == "killed":
            msg += (", killed: what the hub had running in it was stopped"
                    + ("" if remove else "; what it wrote to disk stays"))
        if windowed:
            clear_window(name)              # this kill read back: none is owed now
            if owed:
                msg += "; the kill its seal could not make is made"
    try:
        _pin_dispvm(vm, name)
    except RoleError as e:
        problems.append(str(e))
    if problems:
        state = ("killed" if shutdown else "left running, as asked")
        raise RoleError(f"'{name}' is {state}, but {'; '.join(problems)}; run qmcp revoke "
                        f"{name} again" + ("; it was NOT removed" if remove else ""))
    if remove:
        err = _remove_qube(app, name)
        if err:
            raise RoleError(f"'{name}' is revoked, but it was NOT removed ({err}): qvm-remove "
                            f"{name} by hand once Qubes allows it")
        msg += ", removed"
    return msg


#: M5's open windows. `qmcp open` writes the record and THEN the badges; the
#: expiry pass, `qmcp seal` and the boot unit take the badges off. The record
#: lives in /run, so a boot leaves every badge without one — which is why
#: `qmcp-seal.service` strips the badges at boot, before any user session
#: exists, instead of trusting the record it would not find.
#: Declared root:qubes 2770 in tmpfiles: root writes the records and the
#: expiry pass, which runs as the services' user, unlinks them.
WINDOW_DIR = "/run/qmcp/open"
#: Who owns /run/qmcp: root, as tmpfiles makes it (a test sets its own user).
RUN_DIR_OWNER = 0
#: The longest window the command writes. There is no indefinite open:
#: that is `qmcp manage`, which leaves the guarded state altogether.
WINDOW_MAX_S = 24 * 60 * 60


class WindowUnreadable(Exception):
    """A window's record is absent, malformed or unreadable.

    This is a GATE, not instrumentation, so it fails toward LESS authority and
    sealing is an ACTION: the expiry pass takes the badges off, and `qmcp
    check` fails while they are on. It must never degrade into "no expiry
    could be read, so leave the window open" — the direction the best-effort
    helpers elsewhere in this tree fail in.
    """


#: `--for`: whole seconds, or one unit of s, m or h. No fractions, so no
#: rounding to argue about, and `bool` cannot sneak in as an `int`.
_DURATION = re.compile(r"([0-9]{1,7})([smh]?)")


def duration_seconds(text) -> int:
    """`"90s"`, `"30m"`, `"2h"` or bare digits as seconds. Raises `RoleError`
    on anything else, including an empty string, a float and any whitespace
    around it: the whole text is matched, so a duration that passes is
    exactly its own normal form (a proposal stores it as sent)."""
    m = _DURATION.fullmatch(text) if isinstance(text, str) else None
    if m is None:
        raise RoleError("--for wants a whole number of seconds, or one with s, m or h, "
                        "e.g. 90s, 30m, 2h")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600}[m.group(2)]


def _window_path(name: str, dir_: str | None = None) -> str:
    if not core.valid_qube_name(name):
        raise WindowUnreadable("that is no qube name")
    return os.path.join(WINDOW_DIR if dir_ is None else dir_, name)


def read_window(name: str, dir_: str | None = None) -> dict:
    """`{"opened": int, "expires": int, "firewall": bool, "boot_expires": int}`
    (`boot_expires` absent in a record before 0.9.39), or raise.

    A record that does not parse, or whose fields are the wrong shape, is
    unreadable rather than read as any expiry. `expires` must be an `int` and
    not a `bool`, which is an `int` in Python and would otherwise pass as an
    epoch of 0 or 1.
    """
    path = _window_path(name, dir_)
    try:
        rec = json.loads(core.read_run_file(path))
    except FileNotFoundError:
        raise WindowUnreadable(f"'{name}' wears an open badge and has no window record") from None
    except (OSError, ValueError, RecursionError) as e:
        raise WindowUnreadable(f"'{name}''s window record cannot be read "
                               f"({type(e).__name__})") from None
    ok = (isinstance(rec, dict)
          and isinstance(rec.get("expires"), int) and not isinstance(rec.get("expires"), bool)
          and isinstance(rec.get("opened"), int) and not isinstance(rec.get("opened"), bool)
          and isinstance(rec.get("firewall"), bool)
          and (rec.get("boot_expires") is None
               or (isinstance(rec.get("boot_expires"), int)
                   and not isinstance(rec.get("boot_expires"), bool))))
    if not ok:
        raise WindowUnreadable(f"'{name}''s window record is malformed")
    return rec


def _boot_clock() -> float:
    """Seconds since boot, which no one sets: `/run/qmcp/open` is cleared at
    every boot, so a record's reading of it is good for the record's life."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


#: How far ahead of the wall clock a record's opening may lie before the
#: clock is taken to have moved back.
CLOCK_SLACK_S = 60


def window_left(name: str, dir_: str | None = None, now: float | None = None) -> int:
    """Whole seconds left, zero or less when the window has run out. Judged by
    the wall clock and by the clock since boot, which nothing can set: the
    window is over when either says so, so a wall clock stepped back never
    lengthens it. A record whose opening lies ahead of the wall clock, or
    whose end lies further ahead than the longest window, means the clock
    moved: over."""
    rec = read_window(name, dir_)
    wall = int(time.time() if now is None else now)
    left = rec["expires"] - wall
    if left > WINDOW_MAX_S or rec["opened"] > wall + CLOCK_SLACK_S:
        return 0
    boot = rec.get("boot_expires")
    if boot is not None:
        left = min(left, int(boot - _boot_clock()))
    return left


def write_window(name: str, seconds: int, firewall: bool, dir_: str | None = None) -> dict:
    """Write the record, before any badge is written. A failure between the two
    leaves a record and no badge, which opens nothing. The end is written on
    both clocks (`window_left`)."""
    path = _window_path(name, dir_)
    now = int(time.time())
    rec = {"opened": now, "expires": now + seconds, "firewall": bool(firewall),
           "boot_expires": int(_boot_clock()) + seconds}
    core.write_run_file(path, json.dumps(rec, sort_keys=True) + "\n")
    return rec


def clear_window(name: str, dir_: str | None = None) -> None:
    """Delete the record. One that is already gone is success."""
    try:
        os.unlink(_window_path(name, dir_))
    except FileNotFoundError:
        pass


#: What a window's record says between its seal and a kill read back: the
#: badges are off, and what the hub started in the qube may still run. The
#: record outlives the badges until the kill is confirmed, so a kill that
#: fails, or a seal cut short between its badges and its kill, is tried again
#: by every pass and named by `qmcp check` (`pending_kills`).
KILL_PENDING = {"kill": True}


def _run_of(vm) -> dict:
    """Which qube, and which run of it, a pending kill means: its UUID and
    qubesd's `start_time` (empty while halted; None for a read that failed)."""
    out = {}
    for key, prop in (("uuid", "uuid"), ("start_time", "start_time")):
        try:
            value = getattr(vm, prop)
            out[key] = "" if value is None else str(value)
        except Exception:
            out[key] = None
    return out


def mark_kill_pending(name: str, dir_: str | None = None, vm=None) -> None:
    """Replace the record with a pending kill (`KILL_PENDING`, plus `_run_of`
    the qube when it is given), in one rename. Raises OSError."""
    rec = dict(KILL_PENDING, **({} if vm is None else _run_of(vm)))
    core.write_run_file(_window_path(name, dir_), json.dumps(rec, sort_keys=True) + "\n")


def _pending_record(name: str, dir_: str | None = None) -> dict | None:
    """The pending kill recorded for `name`, or None."""
    try:
        rec = json.loads(core.read_run_file(_window_path(name, dir_)))
    except (OSError, ValueError, RecursionError, WindowUnreadable):
        return None
    return rec if isinstance(rec, dict) and rec.get("kill") is True else None


def kill_pending(name: str, dir_: str | None = None) -> bool:
    """True when the qube's record is a pending kill."""
    return _pending_record(name, dir_) is not None


def pending_kills(dir_: str | None = None) -> list:
    """The qubes whose seal has not yet had its kill read back."""
    base = WINDOW_DIR if dir_ is None else dir_
    try:
        names = os.listdir(base)
    except OSError:
        return []
    return sorted(n for n in names if core.valid_qube_name(n) and kill_pending(n, dir_))


def _span(seconds: int) -> str:
    """A window's length or what is left of it, as a person reads it: whole
    minutes from one minute up, seconds below (a 30 s window is not "0 min")."""
    return f"{seconds // 60} min" if seconds >= 60 else f"{seconds} s"


def _open_refusal(vm, name, tags) -> str | None:
    """Why this qube is never opened, or None. Read before any write."""
    if core.UMBRELLA not in tags:
        return f"'{name}' is not in AI space, so nothing reaches it to be opened"
    if _is_gateway(vm):
        return (f"'{name}' provides network: a gateway carries AI space's egress rules and the "
                f"hub never operates one, window or none")
    if core.GUARDED not in tags:
        return f"'{name}' is managed already; the hub operates it without a window"
    if _held(tags):
        return f"'{name}' {HELD_WHY}"
    for badge, why in ((projects.BLOCKED, "the anonymity gate stopped it"),
                       (projects.HUBBLIND, "it belongs to a hidden anonymous project")):
        if badge in tags:
            return (f"'{name}' wears {badge}: {why}, and the rulebook refuses the hub every "
                    f"service into it above the window's own lines")
    return None


def open_window(app, name, seconds: int, firewall: bool = False, dir_: str | None = None) -> str:
    """`qmcp open`, under the qube's lock (`_open_window`). It runs under the
    gate's lock, which the gate's timer and the expiry pass wait for only a
    few seconds, so it waits briefly for the qube's and refuses after."""
    return _with_qube_lock(name, True,
                           lambda held: _open_window(app, name, seconds, firewall, dir_),
                           timeout=OPEN_LOCK_WAIT_S)


def _open_window(app, name, seconds: int, firewall: bool = False,
                 dir_: str | None = None) -> str:
    """Open a guarded qube to the hub for a bounded time.

    Everything is checked before anything is written, and the record before
    the badges. An `open` on a qube that is open already replaces its window,
    and drops the firewall half when this call did not ask for it.
    """
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
        raise RoleError("--for wants a duration above zero, e.g. 2h")
    if seconds > WINDOW_MAX_S:
        raise RoleError(f"--for is at most {WINDOW_MAX_S // 3600}h, and there is no indefinite "
                        f"open: qmcp manage {name} leaves the guarded state altogether")
    vm = _target(app, name)
    tags = _not_in_a_slot(vm, name, "open")
    why = _open_refusal(vm, name, tags)
    if why:
        raise RoleError(why)
    if kill_pending(name, dir_):
        raise RoleError(f"'{name}''s last seal could not kill it yet, so a process the hub "
                        f"started there may still run: qmcp seal {name} makes the kill, then "
                        f"open it again")
    # Read before anything is written: it only reads, and a failed read must
    # never turn an open that took effect into a reported failure.
    warning = hidden_open_warning(app, name)
    if not os.path.isdir(WINDOW_DIR if dir_ is None else dir_):
        raise RoleError(f"{WINDOW_DIR if dir_ is None else dir_} is missing, so no window can be "
                        f"recorded and none is opened; the installer declares it in tmpfiles")
    try:
        rec = write_window(name, seconds, firewall, dir_)
    except OSError as e:
        raise RoleError(f"'{name}''s window record could not be written ({type(e).__name__}), so "
                        f"no badge was given and nothing is open") from None
    add = [core.OPEN] + ([core.OPEN_FW] if firewall else [])
    remove = [] if firewall else [core.OPEN_FW]
    try:
        _set_tags(vm, add=add, remove=remove)
    except Exception as e:
        # The badge is the whole gate, so a half-written pair must not be left
        # on: take both off, then the record. Badges first — a record with no
        # badge opens nothing, while a badge with no record is exactly what
        # `qmcp check` fails on.
        failed = type(e).__name__
        if core.OPEN in tags:
            # A re-open: the window it was to replace was real, and the hub may
            # have work running in it, so it ends as any window ends, killed.
            try:
                line = _seal(app, name, dir_)
            except RoleError as err:
                raise RoleError(f"'{name}' was not re-opened ({failed}), and its window could "
                                f"not be sealed: {err}") from None
            raise RoleError(f"'{name}' was not re-opened ({failed}), so its window was sealed "
                            f"instead: {line}") from None
        try:
            _set_tags(vm, remove=(core.OPEN, core.OPEN_FW))
        except Exception:
            raise RoleError(f"'{name}' could not be opened ({failed}) and may still wear an open "
                            f"badge: run qmcp seal {name}") from None
        clear_window(name, dir_)
        raise RoleError(f"'{name}' was not opened ({failed}); nothing is left on it") from None
    ends = time.strftime("%H:%M:%S", time.localtime(rec["expires"]))
    return (f"{name}: open until {ends} ({_span(seconds)})"
            + (", firewall rules too" if firewall else "")
            + f"; qmcp seal {name} closes it at once"
            + (f"; WARNING: {warning}" if warning else ""))


def open_window_report(app, name, seconds: int, firewall: bool = False,
                       gate_held: bool = False) -> "Report":
    """`open_window` as a Report, for an accepted proposal: the accept
    path wants a report, while `qmcp open` wants a line.

    It runs under the gate's lock, which `qmcp open` takes at the command
    layer, so an accept never races the pass that expires a window. The lock
    cannot nest: `gate_held` says the caller holds it (an accept takes it
    before it marks the proposal); otherwise this takes it.
    """
    report = Report()
    if gate_held:
        report.append(open_window(app, name, seconds, firewall=firewall))
        return report
    with anon.gate_lock() as got:
        if not got:
            raise RoleError("another run held the gate past its wait; the window was not opened, "
                            "and the proposal may be submitted again")
        report.append(open_window(app, name, seconds, firewall=firewall))
    return report


#: How long `qmcp open` waits for a qube's lock, under the gate's lock.
OPEN_LOCK_WAIT_S = 5.0
#: How long the expiry pass and the boot seal wait for a qube's lock before
#: they seal without it: the pass runs every 15 seconds under the gate's 60 s
#: unit timeout.
SWEEP_WAIT_S = 2.0


def seal(app, name, dir_: str | None = None, wait=None) -> str:
    """`qmcp seal`, under the qube's lock (`_seal`); it takes authority away,
    so it seals without the lock once `wait` has passed."""
    return _with_qube_lock(name, False, lambda held: _seal(app, name, dir_),
                           timeout=wait, settle=lambda: _settle_seal(app, name, dir_))


def _settle_seal(app, name, dir_=None) -> str:
    """After a seal that went on without the lock, once it is had again: kill
    again what a call in flight started, or make the seal's own kill if it is
    still pending. A kill that fails leaves (or keeps) a pending kill, which
    every pass tries again. Never a kill the seal itself may not make."""
    try:
        if _seal_target(app, name)[1] is not None:
            return ""                   # never killed: the hub, or a qube it cannot tell from it
    except RoleError:
        return ""
    if not kill_pending(name, dir_):
        try:
            return _settle_kill(app, name)
        except RoleError:
            try:
                mark_kill_pending(name, dir_, app.domains[name])
            except Exception:
                pass
            raise
    # The seal's own kill failed: it is made now, the call that held the lock done.
    if _gone_by_name(app, name):
        return _clear_record(name, dir_)
    done = _kill_if_running(app.domains[name])
    if done in ("killed", "halted"):
        note = _clear_record(name, dir_)
        return ("; its kill was made once the call that held its lock had finished"
                if done == "killed" else
                "; it was down once the call that held its lock had finished") + note
    raise RoleError(f"'{name}''s kill could NOT be made ({done}), even once the call that held "
                    f"its lock had finished: every pass of the gate's timer tries again, and "
                    f"qmcp check fails until it is done (or qvm-kill {name})")


def _seal_target(app, name):
    """The qube a seal acts on, and why it is not to be killed (None when it
    may be). A seal only takes authority away, so it refuses only a name that
    is no qube and dom0. It takes the badges off a drop box or the hub too,
    which `qmcp open` refuses but a hand-written tag can still reach: the
    rulebook's window lines match the badge alone. It never kills the hub,
    nor a qube whose class or whose hub file cannot be read."""
    if not core.valid_qube_name(name) or name not in app.domains:
        raise RoleError(f"no qube named '{name}'")
    vm = app.domains[name]
    try:
        admin = core.klass_of(vm) == "AdminVM"
    except core.Unreadable as e:
        return vm, f"its class cannot be read ({e}), so whether it is dom0 is not known"
    if admin:
        raise RoleError(f"'{name}' is dom0, which is never in AI space")
    hub = core.read_hub()
    if hub is None:
        return vm, f"{core.HUB_PATH} cannot be read, so it may be the hub"
    if name == hub:
        return vm, "it is the hub"
    return vm, None


def _seal(app, name, dir_: str | None = None) -> str:
    """Close a window at once: the badges off, then the work the hub left
    running in the qube. Before the badges come off, the record becomes a
    pending kill (`KILL_PENDING`), and it goes only once the kill is read
    back, so a kill that fails, or a seal cut short, is tried again by every
    pass and named by `qmcp check`.

    A qube that was not open is left alone and said so, so this is safe to
    run twice. A qube whose tags cannot be read has both badges taken off
    all the same. Firewall rules the hub wrote through the window stay, and
    the report says so.
    """
    vm, no_kill = _seal_target(app, name)
    try:
        worn = sorted(_read_tags(vm) & {core.OPEN, core.OPEN_FW}, key=_removal_order)
    except (RoleError, core.Unreadable):
        worn = sorted({core.OPEN, core.OPEN_FW}, key=_removal_order)
    record_note = ""
    if not worn:
        if not kill_pending(name, dir_):
            _clear_record(name, dir_)   # a record without a badge opens nothing
            return f"{name}: not open"
        # An earlier seal's kill was never read back: it is made now.
    else:
        if name != core.read_hub():
            # Never for the hub, which no seal kills: a pending kill there could
            # never be made, and would fail `qmcp check` until a reboot.
            try:
                mark_kill_pending(name, dir_, vm)
            except OSError as e:
                record_note = (f"; its window record could not be written ({type(e).__name__}), "
                               f"so a kill that fails is not tried again")
        try:
            _set_tags(vm, remove=worn)
        except Exception as e:
            raise RoleError(f"'{name}' may still wear {', '.join(worn)} ({type(e).__name__}); "
                            f"run qmcp seal {name} again") from None
    # The window's firewall half let the hub replace the rules; a seal takes
    # the authority away, not what it wrote.
    fw_note = (f"; the firewall rules the hub wrote stay (qvm-firewall {name} lists them)"
               if core.OPEN_FW in worn else "")
    if no_kill is not None:
        # The badges are off; the record stays a pending kill, which a later
        # pass makes once it can tell this qube is not the hub (never the hub).
        return (f"{name}: sealed, but not killed: {no_kill}; if it is not the hub, kill it by "
                f"hand (qvm-kill {name})" + fw_note + record_note)
    done = _kill_if_running(vm)
    if done in ("killed", "halted"):
        note = _clear_record(name, dir_)
        if done == "halted":
            return f"{name}: sealed" + fw_note + note
        return (f"{name}: sealed and killed: what the hub had running in it was stopped; what "
                f"it wrote to disk stays" + fw_note + note)
    return (f"{name}: sealed, but it could NOT be killed ({done}): a process the hub started in "
            f"it may still run; every pass of the gate's timer tries the kill again, and "
            f"qmcp check fails until it is done (or kill it by hand: qvm-kill {name})"
            + fw_note + record_note)


def _clear_record(name: str, dir_: str | None = None) -> str:
    """`clear_window`, never raising: a record that cannot be removed is said."""
    try:
        clear_window(name, dir_)
        return ""
    except OSError as e:
        return f"; its window record could not be removed ({type(e).__name__})"


def open_badge_holders(app) -> list:
    """Every qube wearing an open badge, or whose tags cannot be read (it may)."""
    out = []
    for vm in app.domains:
        try:
            if _tags(vm) & {core.OPEN, core.OPEN_FW}:
                out.append(vm.name)
        except core.Gone:
            continue
        except core.Unreadable:
            out.append(f"{vm.name} (tags unreadable)")
    return out


def retry_kills(app, dir_: str | None = None, skip=()) -> list:
    """Kill again every qube whose seal has not had its kill read back, but
    those in `skip` (sealed by this pass already). Only the run the seal
    meant: a qube with another UUID (removed and made again under the name),
    or started again since (another `start_time`: the processes the hub left
    went with that run), drops the pending kill instead. Under the qube's
    lock, queued, as long as the expiry pass waits for one. One line per qube
    acted on; a kill still failing says NOT killed."""
    out = []
    for name in pending_kills(dir_):
        if name in skip:
            continue
        try:
            out += _retry_kill(app, name, dir_)
        except Exception as e:
            # Never the end of the pass: the next pending kill is tried all the same.
            out.append(f"{name}: NOT killed ({type(e).__name__}); tried again on the next pass")
    return out


def _retry_kill(app, name: str, dir_) -> list:
    """Make, or drop, a pending kill. A drop leaves its line on the audit
    chain, as a kill made here does; a retry that fails again leaves none
    (the timer runs every 15 seconds), and `qmcp check` fails until it is
    made or dropped."""
    rec = _pending_record(name, dir_) or {}
    if _gone_by_name(app, name):
        _clear_record(name, dir_)
        _swept(name, "pending kill dropped: the qube is gone", True, app=app)
        return []
    vm = app.domains[name]
    try:
        if _read_tags(vm) & {core.OPEN, core.OPEN_FW}:
            return []                   # open again: the seal of that window decides
    except (RoleError, core.Unreadable):
        pass
    try:
        _, no_kill = _seal_target(app, name)
    except RoleError as e:
        _clear_record(name, dir_)
        _swept(name, f"pending kill dropped: {e}", True, app=app)
        return [f"{name}: its pending kill was dropped: {e}"]
    if name == core.read_hub():
        # Recorded while the hub file did not read: no seal kills the hub.
        _clear_record(name, dir_)
        _swept(name, "pending kill dropped: it is the hub", True, app=app)
        return [f"{name}: its pending kill was dropped: it is the hub"]
    if no_kill is not None:
        return [f"{name}: NOT killed yet: {no_kill}"]
    now = _run_of(vm)
    if rec.get("uuid") and now.get("uuid") and now["uuid"] != rec["uuid"]:
        _clear_record(name, dir_)
        _swept(name, "pending kill dropped: another qube of that name now", True, app=app)
        return [f"{name}: its pending kill was dropped: it is another qube of that name now"]
    # A start time that could not be read at the seal cannot be compared: the
    # kill is made, the restrictive answer for what the hub may have left. A
    # qube halted now reads an empty start time, and its kill below finds it
    # down.
    if rec.get("start_time") and now.get("start_time") \
            and now["start_time"] != rec["start_time"]:
        _clear_record(name, dir_)
        _swept(name, "pending kill dropped: stopped and started again since its seal", True, app=app)
        return [f"{name}: its pending kill was dropped: it stopped and was started again "
                f"since its seal, which ended what the hub had left running"]
    try:
        fd = core.acquire_qube_lock(name, SWEEP_WAIT_S, queue=True)
    except core.Refusal:
        fd = None
    try:
        done = _kill_if_running(vm)
    finally:
        if fd is not None:
            os.close(fd)
    if done in ("killed", "halted"):
        _clear_record(name, dir_)
        _swept(name, "the kill a seal could not make", True, app=app)
        return [f"{name}: killed on a later pass, after its seal's kill failed"
                if done == "killed" else f"{name}: down, after its seal's kill failed"]
    return [f"{name}: NOT killed ({done}); tried again on the next pass"]


def expire_windows(app, dir_: str | None = None, now: float | None = None,
                   every: bool = False) -> list:
    """The pass the gate's timer runs: seal every window that has run
    out, that has no readable record, or that is on a qube `qmcp open` would
    refuse. With `every`, seal them all whatever their record says, which is
    what the boot unit does: a window never survives a reboot, and at
    boot the records are gone with /run anyway. Returns one line per qube it
    acted on or could not read.

    The last case is why this exists as well as the command's own refusals:
    the rulebook cannot tell a gateway from any other guarded qube — a gateway
    is one by its `provides_network` property, and no tag carries that — so a
    badge that reached one would make A6b live for it. Here it comes off.
    """
    out, sealed = [], set()
    for vm in app.domains:
        name = vm.name
        try:
            tags = _tags(vm)
        except core.Gone:
            continue
        except core.Unreadable as e:
            # Never silently: a qube whose tags will not read may be open. One
            # whose window record has run out, or does not read, is sealed all
            # the same, since `_seal` takes both badges off unread; one with no
            # record is only named, since nothing says it is open and the seal
            # would kill it. A record outlives a badge taken off by hand, so the
            # qube sealed here may no longer be open: it is killed if it runs
            # all the same, the restrictive answer when the tags cannot say.
            tags, reason = None, _record_over(name, dir_, now)
            if reason is None:
                out.append(f"{name}: {e}; its window could not be judged")
                continue
            reason = f"{reason}, and its tags do not read ({e})"
        if tags is None:
            pass
        elif not tags & {core.OPEN, core.OPEN_FW}:
            continue
        elif every:
            reason = "the boot seal: a window never survives a reboot"
        else:
            try:
                reason = _open_refusal(vm, name, tags)
            except RoleError as e:
                # A window whose qube cannot be judged is sealed: taking the
                # badges off needs none of the reads `qmcp open` makes.
                reason = f"{e}, so whether it may be open cannot be told"
        if reason is None:
            try:
                left = window_left(name, dir_, now)
            except WindowUnreadable as e:
                reason = str(e)
            else:
                if left > 0:
                    continue
                reason = f"'{name}''s window ran out"
        sealed.add(name)
        try:
            line = seal(app, name, dir_, wait=SWEEP_WAIT_S)
        except RoleError as e:
            out.append(f"{name}: NOT sealed: {e}")
            _swept(name, reason, False, str(e), app=app)
            continue
        except Exception as e:
            # Never the end of the pass: the next window is sealed all the same.
            out.append(f"{name}: NOT sealed: {type(e).__name__}")
            _swept(name, reason, False, type(e).__name__, app=app)
            continue
        out.append(f"{line}: {reason}")
        if kill_pending(name, dir_):
            _swept(name, reason, False, "sealed, not killed", app=app)
        else:
            _swept(name, reason, True, app=app)
    out += retry_kills(app, dir_, skip=sealed)
    return out


def _record_over(name: str, dir_, now) -> str | None:
    """Why the window recorded for `name` is over, or None: no record, a
    pending kill (`retry_kills` makes it), or time left."""
    try:
        if not os.path.exists(_window_path(name, dir_)) or kill_pending(name, dir_):
            return None
        left = window_left(name, dir_, now)
    except WindowUnreadable as e:
        return str(e)
    return None if left > 0 else f"'{name}''s window ran out"


def _swept(name: str, reason: str, ok: bool, error: str | None = None, app=None) -> None:
    """One audit line per window this sweep really closed, as the operator.

    The sweep itself leaves no line (`cli.operator_line`): the gate's timer
    runs one every 15 seconds and finds nothing almost every time, and a line
    per run would bury what the operator did. Best-effort, like every other
    audit write: a logging failure never changes what was sealed.
    """
    try:
        audit.audit("qmcp seal", "operator",
                    {"qube": name[:128], "swept": reason[:128]}, ok, error, app=app)
    except Exception:
        pass


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
            # The slots whose lead reaches it as their model qube.
            "model": UNREADABLE if tags is None else
            ",".join(sorted(projects.model_slots(tags))) or None,
            "open": _window_field(vm.name, tags),
            "owner": UNREADABLE if tags is None else _owner(tags),
            "gateway": _shown(lambda: core.is_gateway(vm)),
            "dvmt": _shown(lambda: core.is_dvmt(vm)),
            "badges": None if tags is None else
            sorted(t for t in tags if birth.controlled(t) or t == projects.DROP_BOX),
        })
    return rows


def _window_field(name: str, tags):
    """Seconds left on this qube's window for a listing row: None when it is
    not open, UNREADABLE when it wears a badge whose record will not read, and
    a number that may be zero or less when the window has run out and the
    expiry pass has not come round yet. The listing is a read and never acts
    on what it finds; `qmcp seal --expired` is what acts."""
    if tags is None or not tags & {core.OPEN, core.OPEN_FW}:
        return None
    try:
        return window_left(name)
    except WindowUnreadable:
        return UNREADABLE


#: dom0's journal keeps every qrexec call whatever qmcp's log mode: the
#: policy daemon logs each request. qmcp does not change it (a system-wide
#: setting); `qmcp check` prints this while any mode is not disk.
JOURNAL_VOLATILE = ("sudo mkdir -p /etc/systemd/journald.conf.d && printf '[Journal]\\n"
                    "Storage=volatile\\n' | sudo tee /etc/systemd/journald.conf.d/"
                    "10-qmcp-volatile.conf && sudo systemctl restart systemd-journald")


def _audit_modes(add, records, mode, problem) -> None:
    """The install's audit mode, and the journal while any mode is not disk."""
    if problem:
        add("fail", "audit mode", f"{problem}: every line goes to RAM until it reads "
                                  f"(write disk, ram or none, or run install.sh --audit-log)")
    elif mode != "disk":
        add("warn", "audit mode", f"{mode}: " + (
            "no qmcp audit line is written, of any call" if mode == "none" else
            "the install's lines go to a chain under /run, gone at shutdown"))
    else:
        add("pass", "audit mode", "disk")
    private = [] if records is None else sorted(
        f"{p.label or p.slot} ({p.slot}): {p.audit}" for p in records.values()
        if p.slot != projects.HUB_SLOT and p.audit != "disk")
    if private:
        add("pass", "project audit modes", "; ".join(private))
    if mode != "disk" or problem or private or records is None:
        add("warn", "dom0 journal",
            "dom0's journal still keeps every qrexec call (the policy daemon logs each "
            "request, with its caller, service and target) on dom0's disk. qmcp does not "
            "change it, a setting for all of dom0; to keep it in RAM only: "
            + JOURNAL_VOLATILE)


def _operator_files(add) -> None:
    """Every operator file under /etc/qmcp that is there must be a plain file
    every user can read and not every user can write: the services run as the
    dom0 user and read them on every call, and so does `qmcp check` run as
    that user. A file written with `tee` under sudo inherits dom0's umask
    (0077) and comes out 0600, which root reads and nobody else does."""
    from qmcp import opfiles
    bad, cannot = [], []
    for path in sorted(opfiles._paths().values()):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            cannot.append(path)
            continue
        mode = stat.S_IMODE(st.st_mode)
        if not stat.S_ISREG(st.st_mode):
            bad.append(f"{path} is not a plain file")
        elif not mode & 0o004:
            bad.append(f"{path} is {mode:04o}, which the services and the dom0 user cannot "
                       f"read (sudo chmod 0644 {path})")
        elif mode & 0o002:
            bad.append(f"{path} is {mode:04o}, which every user can write "
                       f"(sudo chmod 0644 {path})")
    if bad:
        add("fail", "operator files", "; ".join(bad)
            + (f"; cannot read the mode of {', '.join(cannot)}" if cannot else ""))
    elif cannot:
        add("error", "operator files", f"cannot read the mode of {', '.join(cannot)}")
    else:
        add("pass", "operator files", "plain files every user can read")


def _audit_retention(add, records, mode) -> None:
    """Rotated logs are removed by age: the setting must read, the timer that
    removes them must run, and the budgets of every principal for that many
    days must fit the log's disk."""
    active = anon.timer_active(audit.AUDIT_TIMER)
    if active is None:
        add("error", "audit timer", f"cannot tell whether {audit.AUDIT_TIMER} runs")
    elif not active:
        add("fail", "audit timer", f"{audit.AUDIT_TIMER} is not running, so the audit log is "
                                   f"neither rotated nor its old files removed (sudo systemctl "
                                   f"enable --now {audit.AUDIT_TIMER})")
    if os.path.exists(audit.LOG_PATH + audit.ROTATING_SUFFIX):
        add("warn", "audit retention", f"{audit.LOG_PATH}{audit.ROTATING_SUFFIX} is there: a "
                                       f"rotation stopped part-way; the next one takes it over")
    try:
        foreign = audit.unpruned()
    except OSError as e:
        foreign = None
        add("error", "audit retention", f"{os.path.dirname(audit.LOG_PATH)} does not list "
                                        f"({type(e).__name__})")
    if foreign:
        shown = ", ".join(foreign[:5]) + (f" and {len(foreign) - 5} more" if len(foreign) > 5 else "")
        add("warn", "audit retention", f"{shown} in {os.path.dirname(audit.LOG_PATH)}: not named "
                                       f"as `qmcp audit rotate` names a log, so no retention "
                                       f"removes it; once it is kept where you want it, remove "
                                       f"it by hand")
    try:
        with open(audit.CLOCK_MOVED_PATH, encoding="utf-8", errors="replace") as fh:
            moved = fh.read(512).strip() or "the clock moved"
    except FileNotFoundError:
        moved = None
    except OSError as e:
        moved = f"{audit.CLOCK_MOVED_PATH} does not read ({type(e).__name__})"
    if moved is not None:
        add("warn", "audit clock", f"removal of old audit logs is paused: {moved}; once dom0's "
                                   f"clock is right, sudo rm {audit.CLOCK_MOVED_PATH}")
    keep = audit.keep_days()
    if keep is None:
        add("fail", "audit retention", f"{audit.KEEP_DAYS_PATH} does not read, or holds neither "
                                       f"a number of days (1-{audit.KEEP_DAYS_MAX}) nor off: no "
                                       f"rotated log is removed until it does (qmcp settings set "
                                       f"--audit-keep-days)")
        return
    if keep == "off":
        add("warn", "audit retention", "off: rotated logs are never removed, and fill "
                                       f"{os.path.dirname(audit.LOG_PATH)} by the day")
        return
    if mode != "disk":
        add("pass", "audit retention", f"{keep} days (the install's lines are not on disk)")
        return
    principals = None if records is None else 1 + sum(1 for p in records.values() if p.lead)
    need = None if principals is None else audit.room_needed(principals, keep)
    free = audit.free_bytes()
    if need is None or free is None:
        add("warn", "audit retention", f"{keep} days; whether it fits cannot be read (the "
                                       f"records or the free space under "
                                       f"{os.path.dirname(audit.LOG_PATH)})")
    elif need > free:
        add("warn", "audit retention",
            f"{keep} days: {principals} principal(s) at their full {audit.AUDIT_LINES_PER_DAY} "
            f"lines a day, about {audit.LINE_BYTES} bytes each, need {need // 1024 ** 2} MiB, "
            f"and {os.path.dirname(audit.LOG_PATH)} has {free // 1024 ** 2} MiB free: free space, "
            f"or keep fewer days (qmcp settings set --audit-keep-days)")
    else:
        add("pass", "audit retention", f"{keep} days; a full budget for every principal fits")


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
        "mode": {True: "anonymous", False: "normal", None: UNREADABLE}[anon.mode_state()[0]],
        # None: the file does not read (lines go to RAM; nothing is removed).
        "audit_mode": (lambda m: None if m[1] else m[0])(audit.install_mode()),
        "audit_keep_days": audit.keep_days(),
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
            self.fd = budget.acquire_create_lock(queue=True)
        except core.Refusal:
            self.records_lock.__exit__(None, None, None)
            raise ProjectError("a create is in progress; try again in a moment") from None
        except BaseException:
            # Anything else (an OSError, an interrupt) lets go of the records
            # lock it took and is raised as itself; nothing is held after.
            self.records_lock.__exit__(None, None, None)
            raise
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
        if _held(_read_tags(vm)):
            raise ProjectError(f"'{name}' {HELD_WHY}")
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
                               "dom0 writes its firewall to allow that endpoint, and DNS for "
                               "a host name, nothing else")
        return None, None
    try:
        model = firewall.model_text(model)
    except firewall.FirewallError as e:
        raise ProjectError(str(e)) from None
    if net is None:
        raise ProjectError("a lead with no network reaches no model endpoint; drop --model")
    return model, firewall.endpoint_rules(model)


# Anonymous projects (M3c). An anonymous project's networks are anonymising
# gateways that still sit where they were recorded, its templates are
# outside AI space or guarded, its lead is only ever made fresh from such a
# template, and its model qube serves it alone. The commands refuse what
# would break the gate up front; the gate (`qmcp.anon`) catches what changes
# outside qmcp.

HIDDEN_WARNING = (
    "a hidden project is safe from the hub only if the hub never operated what it runs on: a "
    "template or model qube the hub edited before it was guarded can harm it, since guarding "
    "removes nothing the hub left there, and qmcp keeps no record of who operated a qube")
SHARED_ROUTER_WARNING = (
    "projects behind one anonymising router share its exit, so a destination can tie them "
    "together; a second router of the kind keeps them apart")


def _not_managed(app, name, what: str) -> None:
    """A template an anonymous project's qubes come from: outside AI space or
    guarded, so the hub cannot change it."""
    vm = _vm(app, name)
    if vm is None:
        raise ProjectError(f"{what} '{name}' does not exist")
    tags = _read_tags(vm)
    if core.UMBRELLA in tags and core.GUARDED not in tags:
        raise ProjectError(f"{what} '{name}' is managed, so the hub can change it: guard it "
                           f"first (qmcp guard {name}), or use another")


def _anonymous_network(app, registry: dict, net: str) -> None:
    """A network an anonymous project may use: an enrolled anonymising gateway
    that still sits on the network recorded when it was marked."""
    _usable_gateway(app, registry, net)
    g = registry[net]
    if not g.anonymising:
        raise ProjectError(f"'{net}' is not an anonymising gateway: an anonymous project's "
                           f"networks are anonymising gateways, or none")
    if g.upstream is None:
        raise ProjectError(f"'{net}' has no recorded network: mark it again (qmcp gateway set "
                           f"{net} --anonymising yes)")
    try:
        now = _netvm(_vm(app, net))
    except NetvmUnreadable:
        raise ProjectError(f"the network of '{net}' cannot be read; try again") from None
    if now != g.upstream:
        raise ProjectError(f"'{net}' is on {now or 'no network'}, not on {g.upstream} as "
                           f"recorded: put it back, or mark it again (qmcp gateway set {net} "
                           f"--anonymising yes)")


def _anonymous_networks(app, names) -> None:
    registry = _registry()
    for name in names:
        if name not in (None, "none"):
            _anonymous_network(app, registry, name)


def _anonymous_lead(app, source: str, origin: str, lead_netvm) -> None:
    """An anonymous project's lead is only ever made fresh, from a template the
    hub cannot change, on an anonymising gateway or on none."""
    if source != "template":
        raise ProjectError("an anonymous project's lead is only ever made fresh from a template "
                           "(--lead-template), never a clone or a promoted qube with a past")
    _lead_template(app, origin)
    _not_managed(app, origin, "the lead's template")
    _anonymous_networks(app, [lead_netvm])


def _dvmt_share_refusal(app, records: dict, p, names) -> None:
    """A hidden project's disposable templates are approved by hidden projects
    only. A disposable is born with its template's tags, and the birth stamp
    refuses a child that arrives wearing `qmcp-hubblind` unasked, so a project
    the hub sees, sharing one, could make no disposable from it: each would be
    rolled back, with nothing to say why. Refused when the project is made or
    edited, either way round, naming the other project; `names` are the
    entries to check (`_apply_edit`'s convention)."""
    for t in names:
        vm = _vm(app, t)
        if vm is None or not core.is_dvmt(vm):
            continue
        others = [q for s, q in records.items() if s != p.slot and t in q.templates]
        if p.hidden:
            seen = sorted(q.label or q.slot for q in others if not q.hidden)
            if seen:
                raise ProjectError(f"the disposable template {t} is approved by {', '.join(seen)}, "
                                   f"which the hub sees: a hidden project's disposable templates "
                                   f"are hidden from the hub, and that project's disposables "
                                   f"would then be refused at birth; give this project a "
                                   f"disposable template of its own")
            continue
        hiding = sorted(q.label or q.slot for q in others if q.hidden)
        if hiding or projects.HUBBLIND in _read_tags(vm):
            whose = (f"the hidden project {', '.join(hiding)}'s" if hiding
                     else f"hidden from the hub ({projects.HUBBLIND}), a hidden project's")
            raise ProjectError(f"the disposable template {t} is {whose}: a disposable made from "
                               f"it is born hidden from the hub and refused for a project the "
                               f"hub sees; give this project a disposable template of its own")


def _hide_disposable_templates(report, app, p) -> None:
    """A hidden project's approved disposable templates wear `qmcp-hubblind`:
    every disposable is born with its template's tags, so one made from an
    unhidden template would sit in the hub's view until its own stamp hid it,
    and a preloaded one indefinitely. The hub, which cannot operate a guarded
    template anyway, no longer sees these."""
    todo, seen = [], set()
    for t in p.templates:
        vm = _vm(app, t)
        if vm is None or not core.is_dvmt(vm):
            continue
        tags = _read_tags(vm)
        if projects.HUBBLIND in tags:
            continue
        todo.append((t, vm))
        if core.UMBRELLA in tags:
            seen.add(t)
    # Before any is hidden: a disposable or named DispVM the hub could reach,
    # made from one of them earlier, would stay the hub's, and each start of
    # it snapshots the template's home again. Refused, naming them.
    reachable, hiding = [], {t for t, _ in todo}
    for vm in app.domains if hiding else ():
        try:
            tags = core.tags_of(vm)
        except core.Gone:
            continue
        except core.Unreadable:
            reachable.append(f"{vm.name} (its tags cannot be read)")
            continue
        if core.UMBRELLA not in tags or projects.HUBBLIND in tags:
            continue                        # not the hub's to reach
        try:
            tpl = core.template_of(vm)
        except core.Unreadable:
            reachable.append(f"{vm.name} (its template cannot be read)")
            continue
        if tpl is not None and core.name_of(tpl) in hiding:
            reachable.append(vm.name)
    if reachable:
        raise ProjectError(f"the hub can still reach qubes made from these disposable templates: "
                           f"{', '.join(sorted(reachable))}; remove them, or take them out of AI "
                           f"space (qmcp revoke), first: each start of one hands the hub its "
                           f"template's home directory as it is then")
    for t, vm in todo:
        _set_tags(vm, add={projects.HUBBLIND})
        report.append(f"{p.slot}: the disposable template {t} is hidden from the hub now")
        if t in seen:
            # Its contents stay hidden; that a hidden project took it does not.
            report.append(f"{p.slot}: WARNING: the hub saw {t} in its list until now, so it "
                          f"learns from its leaving that a hidden project uses it; one made for "
                          f"this project alone tells it only that a hidden project took a new "
                          f"template")


def shared_routers(app, records: dict, p) -> tuple[list, list]:
    """The anonymising routers a hidden project shares with another project or
    the hub: its worker networks and its lead's, against theirs. Also the
    qubes whose network could not be read, so a warning that could not be
    worked out is said, never dropped."""
    if not p.hidden:
        return [], []
    unread = []

    def network(name):
        try:
            vm = _vm(app, name) if name else None
            return None if vm is None else _netvm(vm)
        except (core.Unreadable, NetvmUnreadable):
            unread.append(name)
            return None

    mine = set(p.named_networks()) | {network(p.lead)}
    theirs = {network(core.read_hub())}
    for q in records.values():
        if q.slot != p.slot and q.label:
            theirs |= set(q.named_networks()) | {network(q.lead)}
    return sorted(n for n in (mine & theirs) if n), sorted(set(unread))


#: The classes the operator's commands take as a lead's source or a qube to
#: move between slots (a lead's named disposables are members too, by birth).
WORKLOAD_KLASSES = ("AppVM", "StandaloneVM")
#: `--lead-class`: what a fresh lead made from a template is.
LEAD_CLASSES = ("appvm", "standalone")


def _workload(vm) -> bool:
    """An AppVM or a StandaloneVM that is no template, disposable template or
    gateway: a qube the operator's commands take as a lead's source or move
    between slots. Raises Unreadable."""
    return core.klass_of(vm) in WORKLOAD_KLASSES and not core.is_template(vm) \
        and not core.is_gateway(vm)


def _hubs_own_qube(app, name, what: str):
    """A managed AppVM or StandaloneVM of the hub's (p00 or no slot): a lead's
    clone source or a qube to promote. Never a template, gateway, guarded qube,
    lead, drop box or another project's member."""
    vm = _vm(app, name)
    tags = set() if vm is None else _tags(vm)
    if core.UMBRELLA not in tags:
        raise ProjectError(f"no qube '{name}' in AI space")
    if not _workload(vm):
        raise ProjectError(f"{what} must be an AppVM or a StandaloneVM, not a template or gateway")
    if core.GUARDED in tags or projects.DROP_BOX in tags:
        raise ProjectError(f"'{name}' is guarded or a drop box")
    if _held(tags):
        raise ProjectError(f"'{name}' {HELD_WHY}")
    if not restored.known(vm):
        raise ProjectError(f"'{name}' {WAITS_WHY}")
    if projects.LEAD in tags or projects.lead_slots(tags):
        raise ProjectError(f"'{name}' already leads a project")
    if projects.model_slots(tags):
        raise ProjectError(f"'{name}' is a model qube of {', '.join(sorted(projects.model_slots(tags)))}")
    if projects.member_slots(tags) - {projects.HUB_SLOT}:
        raise ProjectError(f"'{name}' is another project's member; move it to p00 first")
    return vm


def _label_name(vm) -> str:
    """A qube's label colour, by name."""
    label = vm.label
    return str(getattr(label, "name", label))


def _lead_template(app, name):
    """A fresh lead's template: any TemplateVM. One outside AI space is the
    stronger choice, since the hub cannot edit it; it then stays off the
    project's approved list, which holds only AI space."""
    vm = _vm(app, name)
    if vm is None or core.klass_of(vm) != "TemplateVM":
        raise ProjectError(f"'{name}' is not a TemplateVM")
    if why := _unreviewed(vm):
        raise ProjectError(f"'{name}' {why}")
    return vm


def _unreviewed(vm) -> str | None:
    """`HELD_WHY` for a qube held for review, `WAITS_WHY` for one in scope
    whose label is not its own (the gate's next pass holds it), else None.
    Whatever is built on such a template now would escape that review: a fresh
    or cloned lead, a standalone copy, a dump sink."""
    tags = _read_tags(vm)
    if _held(tags):
        return HELD_WHY
    if restored.in_scope(tags) and not restored.known(vm):
        return WAITS_WHY
    return None


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


def stale_slot_badges(app, records: dict) -> tuple:
    """The routed slot badges no record backs: ([(qube, [badges])], [qubes
    whose tags do not read]). The rulebook routes on badges, not records
    (`qmcp-lead-pNN` alone gives root exec into the slot's members), so after
    `uninstall.sh --purge` removed the records a fresh install would put the
    rulebook back over every project the qubes still wear. `qmcp-lead` goes
    with the last stale lead badge a qube wears."""
    stale, unread = [], []
    for vm in list(app.domains):
        try:
            if core.klass_of(vm) == "AdminVM":
                continue
            tags = core.tags_of(vm)
        except core.Gone:
            continue
        except core.Unreadable:
            unread.append(getattr(vm, "name", "?"))
            continue
        parts = [(t, projects.slot_badge_parts(t)) for t in tags]
        gone = sorted(t for t, part in parts if part and part[1] not in records)
        if not gone:
            continue
        leads_left = [t for t, part in parts if part and part[0] == "lead" and t not in gone]
        if projects.LEAD in tags and not leads_left \
                and any(projects.slot_badge_parts(t)[0] == "lead" for t in gone):
            gone.append(projects.LEAD)
        stale.append((core.name_of(vm), sorted(gone, key=_removal_order)))
    return stale, unread


def strip_stale_slot_badges(app, records: dict) -> list:
    """Take off the badges `stale_slot_badges` names, routed ones first, and
    read each qube back. Lines of what was done; raises `RoleError` naming the
    first qube that still wears one."""
    stale, unread = stale_slot_badges(app, records)
    if unread:
        raise RoleError(f"the tags of {', '.join(sorted(unread))} do not read, so whether they "
                        f"wear a slot's badges is not known")
    out = []
    for name, badges in stale:
        vm = app.domains[name]
        for t in badges:
            vm.tags.discard(t)
        left = sorted(set(badges) & _read_tags(vm))
        if left:
            raise RoleError(f"'{name}' still wears {', '.join(left)}")
        out.append(f"{name}: took off {', '.join(badges)} (no project record backs them)")
    return out


def _removal_order(tag: str) -> tuple:
    """Badges come off in this order, and go on in the reverse: first the
    badges the rulebook routes on (`qmcp-lead-pNN` alone gives root exec
    into a slot's members, `qmcp-proj-pNN` makes a qube reachable from its
    lead, and either open badge opens a guarded qube to the hub), then the
    umbrella, then the rest. A failure part-way then leaves a qube with less
    authority than the command meant, never more.

    The open badges are named here rather than left to fall in with "the
    rest", and the test suite pins it: A6b does not ask for the umbrella, so
    taking the umbrella off first would leave a window open on a qube that is
    no longer in AI space. Within the routed group the sort puts `qmcp-open`
    (exec) before `qmcp-open-fw` (the firewall writes), which is the order
    authority runs in."""
    if projects.slot_badge_parts(tag) is not None or tag in (core.OPEN, core.OPEN_FW):
        return (0, tag)
    return (1, tag) if tag == core.UMBRELLA else (2, tag)


HELD_WHY = "is held for your review: it came back from a backup or was copied by hand (qmcp restored)"
#: The same, for one the gate's next pass will hold: its label is not its own.
WAITS_WHY = ("waits for your review: its qmcp-id label is not its own, so it came back from a "
             "backup or was copied by hand (qmcp restored)")


def _held(tags) -> bool:
    return core.QUARANTINE in tags


def _set_tags(vm, add=(), remove=()):
    """Remove, then add, each in authority order (see `_removal_order`),
    then read back exactly. Before any badge goes on, a qube with no `qmcp-id`
    label gets one (`qmcp.restored`); one whose label names another qube's UUID
    is refused, since it came back from a backup or a copy and waits for review."""
    if add:
        restored.require_label(vm)
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
        while _safe(vm.get_power_state, "unknown") not in ("Halted", "NA", None) \
                and time.monotonic() < deadline:
            time.sleep(0.5)
        if name in app.domains:
            del app.domains[name]
    except KeyError:
        pass
    except Exception as e:
        return f"{name}: {type(e).__name__}"
    try:
        gone = _vm(app, name) is None
    except core.Unreadable:
        return f"{name}: cannot be looked up, so not known to be removed"
    if not gone:
        return f"{name}: still present"
    # Removed: its lock files go too, each under its own lock, never waited
    # for (`core.retire_qube_locks`); one in use is left until a reboot.
    core.retire_qube_locks(name)
    return ""


def _remove_qube_locked(app, name, lock=None) -> str:
    """`_remove_qube` of a lead or a member under the qube's lock, which the
    services hold from their check to their effect, so a hub's start admitted
    between the kill and the remove cannot leave it running. Goes on without
    the lock when it is held past the wait (a removal only takes authority
    away), and then, if the qube is still there, waits for the lock once more
    and kills and removes it again. `lock`: the qube's lock, already held by
    the caller (`_demote_lead`'s `keep`), which this lets go."""
    if not core.valid_qube_name(name):
        return _remove_qube(app, name)
    if lock is None:
        lock = core.qube_lock(name, must=False)
        try:
            held = lock.__enter__()
        except core.Refusal:
            held = False
    else:
        held = lock.fd is not None
    try:
        err = _remove_qube(app, name)
        if held and not err:
            # Its lock file goes under the lock this holds (`_remove_qube`
            # could only try it free, and it was not).
            core.retire_qube_locks(name, held=(lock.fd,))
    finally:
        if held:
            lock.__exit__(None, None, None)
    if err and not held:
        late = core.qube_lock(name, must=False)
        try:
            got = late.__enter__()
        except core.Refusal:
            got = False
        try:
            if got:
                err = _remove_qube(app, name)
                if not err:
                    core.retire_qube_locks(name, held=(late.fd,))
        finally:
            if got:
                late.__exit__(None, None, None)
    return err


def _plan_lead(app, space: str, source: str, origin: str, lead_netvm, name=None,
               freed: str | None = None, model=None, lead_class: str = "appvm") -> str:
    """Everything about a new lead that can be checked without changing
    anything; returns the name it will have. `freed` is a name that will be
    free by the time the lead is made (an old lead that is removed first).
    `lead_class` "standalone" makes a fresh lead from a template a
    StandaloneVM; a clone or a promoted lead keeps its source's class."""
    if lead_class not in LEAD_CLASSES:
        raise ProjectError(f"the lead's class is one of: {', '.join(LEAD_CLASSES)}")
    if lead_class != "appvm" and source != "template":
        raise ProjectError("--lead-class standalone goes with --lead-template: a cloned or "
                           "promoted lead keeps the class of the qube it comes from")
    if source == "template":
        _lead_template(app, origin)
    elif source in ("clone", "promote"):
        src = _hubs_own_qube(app, origin, "the lead")
        if source == "promote" and (why := _halted_refusal(src, origin, "into a lead's place")):
            raise ProjectError(why)
        # Its template joins the approved list, which never takes one held or
        # waiting for review.
        tpl = _template_name(_vm(app, origin))
        if tpl and (vm := _vm(app, tpl)) is not None and (why := _unreviewed(vm)):
            raise ProjectError(f"the template of {origin}, '{tpl}', {why}")
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


def _make_lead(app, slot: str, source: str, origin: str, name: str, lead_netvm, model=None,
               badges=frozenset(), lead_class: str = "appvm"):
    """Make `name` the lead of `slot`, as planned by `_plan_lead`. Returns
    (name, created, badges the qube had, accepted rules, rules it had, network
    it had) so a later failure can undo exactly. A fresh lead is born on
    `lead_netvm`; a promoted one keeps its network unless given none. A lead
    with a network gets "model endpoint only", written once it wears
    `qmcp-lead`, which already bars the hub's firewall writes, and before its
    slot's lead badge, which the rulebook routes on; `badges`, an anonymous
    project's, go on a fresh lead at its birth stamp, before `ai-managed`
    (an anonymous project's lead is never promoted). Its network is set or
    cleared before that badge too. So a lead never holds the slot's badge with
    a wider firewall or the network it is leaving. On failure it undoes what it
    did (`_undo_lead`: a fresh lead is removed; a promoted one gets back its
    badges, then its rules, then its network), stops at the first step it
    cannot undo, and names it.

    A clone, and a standalone lead made from a template, are built in dom0's
    own order (`birth.create_copy`, `fill_copy`): the new qube is in AI space
    only from its stamp on."""
    want = {core.UMBRELLA, projects.LEAD, projects.lead_badge(slot)}
    _, rules = _lead_rules(app, source, origin, lead_netvm, model)
    if source == "promote":
        vm = _hubs_own_qube(app, origin, "a promoted lead")
        # Its template joins the approved list: read again under the locks, as
        # a clone's is (the plan read it before an old lead went).
        tpl = _template_name(vm)
        if tpl and (tvm := _vm(app, tpl)) is not None and (why := _unreviewed(tvm)):
            raise ProjectError(f"the template of {origin}, '{tpl}', {why}")
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
            # qube wearing it (A8). A hub write admitted just before is
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
            # A start that landed since the read above (one the hub's command
            # into it wakes, which takes no lock) is undone with the rest.
            if _halted_refusal(vm, origin, "into a lead's place"):
                raise ProjectError(f"'{origin}' started while it was made the lead, so it was "
                                   f"given back its place; what this command did before, an "
                                   f"old lead's removal or demotion included, stays done; shut it "
                                   f"down (qvm-shutdown {origin}), then give the project its lead "
                                   f"again")
        except Exception as e:
            err = _undo_lead(app, origin, False, slot, before, old_rules, old_net)
            if err:
                raise ProjectError(f"making the lead failed ({type(e).__name__}) and undoing it "
                                   f"did not finish: {err}") from e
            raise
        return origin, False, before, stored, old_rules, old_net
    netvm = _check_lead_netvm(app, lead_netvm)
    standalone = source == "template" and lead_class == "standalone"
    if source == "template":
        src = _lead_template(app, origin)
    else:
        src = _hubs_own_qube(app, origin, "a lead's clone source")
        # Again under the locks: the plan read it before an old lead went.
        tpl = _template_name(src)
        if tpl and (tvm := _vm(app, tpl)) is not None and (why := _unreviewed(tvm)):
            raise ProjectError(f"the template of {origin}, '{tpl}', {why}")
    copied = standalone or source == "clone"
    # Read before the create: a restriction its template or source wears
    # (`anon-vm`) must reach the lead. A template-based AppVM gets it from
    # Whonix's own addon as well; a standalone has no template for that.
    restrictions = {t for t in _tags(src) if birth.is_restriction(t)}
    # Read BEFORE the copy, and again after it: a copied root is the one its
    # source had when it last stopped (`inqube.after_copy`).
    src_halted = inqube.halted(src) if copied else True
    if standalone:
        vm = birth.create_copy(app, src, name, "StandaloneVM", LEAD_LABEL, standalone=True)
    elif copied:
        vm = birth.create_copy(app, src, name, core.klass_of(src), _label_name(src))
    else:
        vm = app.add_new_vm("AppVM", name, LEAD_LABEL, template=origin)
    stored = None
    try:
        if copied:
            birth.fill_copy(app, vm, src, standalone=standalone)
        # Its network and default disposable template are set and read back
        # while it is still outside AI space: no start of it in between boots
        # it on Qubes' default network.
        vm.netvm = netvm
        vm.default_dispvm = None
        if _netvm(vm) != netvm or core.default_dispvm_of(vm) is not None:
            raise RuntimeError("the lead's network did not read back")
        # Its own label, never its source's.
        restored.label(vm)
        if copied:
            inqube.after_copy(vm, src, src_halted)
        birth.stamp(birth.TagIO.for_vm(vm), _tags(vm) | restrictions, "dom0", None, badges)
        # `qmcp-lead` before the rules (see promote above), the slot's badge last.
        _set_tags(vm, add={projects.LEAD})
        if rules:
            stored = firewall.write_rules(app, name, rules)
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


def _refuse_held_lead(app, p) -> None:
    """A lead change or removal refuses, before it changes anything, while the
    recorded lead is held for review: accepting or rejecting it comes first."""
    vm = _vm(app, p.lead) if p.lead else None
    if vm is not None and _held(_tags(vm)):
        raise ProjectError(f"the lead {p.lead} {HELD_WHY}: accept or reject it first")


def _recorded_lead(app, p):
    """The project's recorded lead, only while it wears the slot's lead badge.
    A recorded name whose qube was removed by hand may since name another qube,
    which must be left alone. A lookup or tag read that fails raises: a lead it
    cannot read is never taken for one that does not wear the badge."""
    vm = _vm(app, p.lead) if p.lead else None
    if vm is None or projects.lead_badge(p.slot) not in _tags(vm):
        return None
    return vm


def _demote_lead(app, p, report: list, removing: bool = False, keep=None) -> bool:
    """Take the lead's authority first: its badges, which the rulebook routes on
    and the services require. Then a kill, read back. A recorded name whose
    qube does not wear the slot's lead badge is left alone and reported as a
    failure: what that qube is, the operator decides. A recorded name with no
    qube is noted. True when it demoted the recorded lead. `removing`: the
    caller removes the qube once the record is saved, and that removal's
    result says whether it is gone.

    Under the lead's own lock, as a revoke, so a call of the hub's on the
    lead that is past its check lands first; and holding the lead's acting
    lock (`core.drain_caller`), so every call of the lead's own that is past
    its check has finished before a badge comes off, and one that reaches its
    check meanwhile is refused once they are off. A create of the lead's
    waits for the create lock, which this command holds, and is then refused.
    Only when the wait runs out can a call of the lead's finish after this
    command: one still running then, or one that reaches its check before the
    badges come off, each checked while the lead still had them; the report
    says the wait ran out.

    `keep`: a list; when the lead's lock is had, it is not let go but
    appended there, for the caller to remove the qube under it and then let
    it go, so no call lands between the kill and the remove."""
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
    lock = core.qube_lock(p.lead, must=False)
    try:
        held = lock.__enter__()
    except core.Refusal:
        held = False
    try:
        drained, opened = None, True
        try:
            drained = core.drain_caller(p.lead)
        except OSError as e:
            opened = False
            report.append(f"{p.slot}: {p.lead}'s acting lock could not be opened "
                          f"({type(e).__name__}), so its calls in flight were not waited for")
        try:
            _demote_and_kill(vm, p, report, removing)
            # Its badges are off, so it is no principal: its lock files go,
            # under the acting lock still held (`core.retire_caller`). Never
            # a failure of the command: a file left grants nothing.
            left = None
            if drained is not None:
                try:
                    left = core.retire_caller(p.lead, drained)
                except Exception as e:
                    left = [(os.path.join(core.RUN_DIR, "calls", p.lead), type(e).__name__)]
        finally:
            if drained is not None:
                os.close(drained)
        if drained is None and opened:
            report.append(f"{p.slot}: a call {p.lead} had started was still running after "
                          f"{core.OPERATOR_WAIT_S:.0f} s; it was checked while {p.lead} was the "
                          f"lead, and may finish after this command")
        if drained is None or left:
            report.append(f"{p.slot}: {p.lead}'s lock files under "
                          f"{os.path.join(core.RUN_DIR, 'calls')} were "
                          + ("left, since its acting lock was not had" if drained is None else
                             "not all removed: " + ", ".join(f"{os.path.basename(f)} ({why})"
                                                             for f, why in left))
                          + "; they grant nothing, and a reboot clears them")
    finally:
        if held and keep is not None:
            keep.append(lock)
        else:
            lock.__exit__(None, None, None)
    if not held:
        # A call of the hub's on the lead held its lock past the wait: once it
        # has finished, a start it made is killed again.
        late = core.qube_lock(p.lead, must=False)
        try:
            got = late.__enter__()
        except core.Refusal:
            got = False
        try:
            msg = _settle_kill(app, p.lead) if got else UNLOCKED
            if msg:
                report.append(f"{p.slot}: {p.lead}{msg}")
        except RoleError as e:
            report.fail(f"{p.slot}: {e}")
        finally:
            late.__exit__(None, None, None)
    return True


def _demote_and_kill(vm, p, report: list, removing: bool) -> None:
    try:
        _set_tags(vm, remove={projects.LEAD, projects.lead_badge(p.slot)})
        report.append(f"{p.slot}: {p.lead} is no longer the lead")
    except core.Unreadable as e:
        # The removes went through; only their read-back failed. The kill and
        # the record must not wait on a read: a lead left running unrecorded
        # would keep its network and lose A8's guard on its firewall.
        report.fail(f"{p.slot}: {p.lead}'s lead badges were taken off, but {e}; qmcp check "
                    f"shows whether any is left")
    except Exception:
        # A badge that did not come off stops the command, but not before the
        # kill: what the lead runs must not outlive a demotion that failed.
        _kill_if_running(vm)
        raise
    done = _kill_if_running(vm)
    if done in ("halted", "killed"):
        return
    if removing:
        report.append(f"{p.slot}: kill of {p.lead} failed ({done}); its removal, once the "
                      f"record is saved, tries again")
    else:
        report.fail(f"{p.slot}: kill of {p.lead} failed ({done}): it no longer acts as the "
                    f"lead, but it may still be running; if it is, kill it by hand "
                    f"(qvm-kill {p.lead})")


def create_project(app, label: str | None, lead_source: str, lead_origin: str, templates=(),
                   networks=(), quota=None, lead_netvm=None, dump: bool = False,
                   lead_name: str | None = None, model: str | None = None,
                   model_qube: str | None = None, anonymous: bool = False,
                   hub_sees: bool = False, note: str | None = None,
                   lead_class: str = "appvm") -> list:
    """Make a project; returns the report lines. The record is written last, so
    the lead is no principal until everything else is in place. With
    `model_qube` the lead has no network, and the qube becomes the project's
    model qube once the project is recorded (`_set_model_qube`). An
    `anonymous` project gets a random label from dom0 (none is given), is
    hidden from the hub unless `hub_sees`, and may carry the operator's `note`.
    `lead_class` "standalone" makes a lead from a template a StandaloneVM."""
    return _run(_create_promoting, app, label, lead_source, lead_origin, templates, networks,
                quota, lead_netvm, dump, lead_name, model, model_qube, anonymous, hub_sees, note,
                lead_class)


def _create_promoting(report, app, label, lead_source, lead_origin, *rest):
    """`_create_project`, holding a promoted qube's lock from before its plan to
    the end, as a lead change does (`_lock_promoted`)."""
    promoted = _lock_promoted(lead_origin) if lead_source == "promote" else None
    try:
        return _create_project(report, app, label, lead_source, lead_origin, *rest)
    finally:
        if promoted is not None:
            promoted.__exit__(None, None, None)


def _model_qube_lead_netvm(model, model_qube, lead_netvm):
    """A lead whose model is a qube has no network: the lead network it gets.
    `none` is no model qube, and asks nothing of the lead's network."""
    if model_qube in (None, "none"):
        return lead_netvm
    if model is not None:
        raise ProjectError("say --model HOST:PORT or --model-qube QUBE, not both")
    if lead_netvm not in (None, "none"):
        raise ProjectError("a lead whose model is a qube has no network: drop --lead-netvm "
                           "(or give --lead-netvm none)")
    return "none"


def _create_project(report, app, label, lead_source, lead_origin, templates, networks, quota,
                    lead_netvm, dump, lead_name, model=None, model_qube=None, anonymous=False,
                    hub_sees=False, note=None, lead_class="appvm"):
    prefix = birth.read_name_prefix()
    if not anonymous and anonymous_mode():
        if label:
            raise ProjectError("anonymous mode: every project is anonymous, and dom0 picks its "
                               "label: leave the label out")
        anonymous = True
    if anonymous:
        if label:
            raise ProjectError("an anonymous project's label is picked by dom0 at random, so a "
                               "name an agent leaks links to nothing: leave the label out")
        if lead_name is not None:
            raise ProjectError("an anonymous project's lead is named by dom0 (<label>-lead): "
                               "leave --lead-name out")
        if note is not None and projects.note_refusal(note):
            raise ProjectError(projects.note_refusal(note))
    elif hub_sees or note is not None:
        raise ProjectError("--hub-sees and --note go with --anonymous")
    if model_qube == "none":
        model_qube = None
    lead_netvm = _model_qube_lead_netvm(model, model_qube, lead_netvm)
    if anonymous:
        _anonymous_lead(app, lead_source, lead_origin, lead_netvm)
        _anonymous_networks(app, networks)
        for t in templates:
            _not_managed(app, t, "the template")
    records = _load_records()
    if anonymous:
        label = projects.random_label({p.label for p in records.values() if p.label}, prefix)
    err = projects.label_refusal(label)
    if err:
        raise ProjectError(err)
    space = f"{prefix}{label}-"
    quota = _quota(quota)
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
    if sink:
        # Before anything is made: the lead and the hidden templates would
        # otherwise come first, to be undone (`_make_sink` checks again).
        try:
            sink_tpl = app.default_template
        except Exception:
            raise ProjectError("cannot read Qubes' default template for the dump sink") from None
        _sink_template_refusal(sink_tpl)
    name = _plan_lead(app, space, lead_source, lead_origin, lead_netvm, lead_name, model=model,
                      lead_class=lead_class)
    model, _ = _lead_rules(app, lead_source, lead_origin, lead_netvm, model)
    lead_tpl = lead_origin if lead_source == "template" else _template_name(_vm(app, lead_origin))
    tpls = list(templates)
    if lead_tpl and (vm := _vm(app, lead_tpl)) is not None and core.in_scope(vm):
        tpls.insert(0, lead_tpl)
    tpls = _check_templates(app, tpls)
    nets = _check_networks(app, networks)
    new = projects.Project(slot, label, None, tpls, nets, quota, sink, model, None,
                           anonymous=anonymous, hidden=anonymous and not hub_sees, note=note)
    if model_qube is not None:
        if lead_source == "promote" and model_qube == lead_origin:
            raise ProjectError(f"'{model_qube}' cannot be both the lead and its model qube")
        _plan_model_qube(app, slot, model_qube, records, new)
    _dvmt_share_refusal(app, records, new, tpls)
    if new.hidden:
        _hide_disposable_templates(report, app, new)
    lead, fresh, before, stored, old_rules, old_net = _make_lead(app, slot, lead_source,
                                                                 lead_origin, name, lead_netvm,
                                                                 model, new.badges(), lead_class)
    report.append(f"{slot}: lead {lead} ({'created' if fresh else 'promoted'})"
                  + (f", firewall: {firewall.endpoint_summary(model)}" if stored else ""))
    try:
        if sink:
            _make_sink(app, slot, sink, new.hidden)
            report.append(f"{slot}: dump sink {sink} created (no network)")
        new.lead = lead
        new.lead_firewall = None if stored is None else tuple(stored)
        records[slot] = new
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
    report.append(f"{slot}: project '{label}' recorded; workers are named {space}*"
                  + ("" if not anonymous else
                     f"; anonymous, {'hidden from' if new.hidden else 'visible to'} the hub"))
    if model_qube is not None:
        _set_model_qube(report, app, records, records[slot], model_qube)
    if new.hidden:
        report.append(f"{slot}: WARNING: {HIDDEN_WARNING}")
        shared, unread = shared_routers(app, records, new)
        if shared:
            report.append(f"{slot}: WARNING: it shares {', '.join(shared)} with another project "
                          f"or the hub: {SHARED_ROUTER_WARNING}")
        if unread:
            report.append(f"{slot}: WARNING: cannot read the network of {', '.join(unread)}, so "
                          f"whether it shares a router with another project or the hub cannot "
                          f"be told (qmcp check says once it can)")


def _sink_template_refusal(tpl) -> None:
    """Refuse the template a dump sink is built on (Qubes' default) when there
    is none, or it is held or waits for review: a sink built on it now would
    escape that review. Called again when the sink is made."""
    if tpl is None:
        raise ProjectError("Qubes has no default template for the dump sink")
    if why := _unreviewed(tpl):
        raise ProjectError(f"Qubes' default template, '{tpl.name}', which the dump sink is built "
                           f"on, {why}")


def _sink_default_name(p) -> str:
    return f"{p.label}-dump" if p.label else "hub-dump"


def _sink_badged(tags) -> bool:
    """Wears a slot's dump badge: the last badge a sink is given."""
    return any(t.startswith(projects.DUMP_PREFIX) for t in tags)


def _make_sink(app, slot: str, name: str, hidden: bool = False):
    """A fresh drop box: ai-dump + the slot's dump badge, no network, outside AI
    space; a hidden project's also `qmcp-hubblind`, first."""
    vm = _vm(app, name)
    if vm is not None:
        if name.endswith("-dump") and not _sink_badged(_read_tags(vm)):
            raise ProjectError(f"'{name}' exists and wears no dump badge: a qmcp project dump "
                               f"that did not finish? If it is not yours, remove it (qvm-remove "
                               f"{name}) and run this again; a dump sink is always a fresh qube")
        raise ProjectError(f"'{name}' exists; a dump sink is always a fresh qube")
    try:
        tpl = app.default_template
    except Exception:
        raise ProjectError("cannot read Qubes' default template for the dump sink") from None
    _sink_template_refusal(tpl)
    vm = app.add_new_vm("AppVM", name, SINK_LABEL, template=tpl)
    try:
        # No network before any badge: a sink is never on Qubes' default one.
        vm.netvm = None
        vm.default_dispvm = None
        if _netvm(vm) is not None or core.default_dispvm_of(vm) is not None:
            raise RuntimeError("the sink's network or default disposable template did not "
                               "read back as none")
        restored.label(vm)
        if hidden:
            _set_tags(vm, add={projects.HUBBLIND})
        _set_tags(vm, add={projects.DROP_BOX, projects.dump_badge(slot)})
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
    _refuse_held_lead(app, p)
    kept = []
    try:
        ours = _demote_lead(app, p, report, removing=True, keep=kept)
        # The accepted rules were the removed lead's; the model stays for the next one.
        old, p.lead, p.lead_firewall = p.lead, None, None
        projects.save(records)
        report.append(f"{p.slot}: the record names no lead")
        if ours:
            err = _remove_qube_locked(app, old, kept.pop() if kept else None)
            report.append(f"{p.slot}: removed {old}") if not err else \
                _not_removed(report, p.slot, old, err)
    finally:
        for lock in kept:
            lock.__exit__(None, None, None)


def set_lead(app, key: str, lead_source: str, lead_origin: str, lead_netvm=None,
             keep_old: bool = False, lead_name: str | None = None, model: str | None = None,
             add_old_network: bool = False, model_qube: str | None = None,
             lead_class: str = "appvm") -> list:
    """Give a project a new lead. Everything about the new lead is checked
    before the old one is touched. The old one is removed, or kept as a worker
    of the same project, never as one of the hub's qubes. A kept lead keeps
    its network when the project lists it; otherwise `add_old_network` adds
    it to the list, and without that the old lead loses its network. The new
    lead gets `model`; one with a network and no `model` takes the project's,
    and one with no network leaves the project with no remote model. A
    project's model qube stays for a new lead with no network; `model_qube`
    changes it (a qube: the new lead then has no network; "none": the
    project's model qube is taken away, nothing else); a remote `model`
    takes it away before the old lead is touched. `lead_class` "standalone"
    makes a lead from a template a StandaloneVM."""
    return _run(_set_lead, app, key, lead_source, lead_origin, lead_netvm, keep_old, lead_name,
                model, add_old_network, model_qube, lead_class)


def _set_lead(report, app, key, lead_source, lead_origin, lead_netvm, keep_old, lead_name,
              model=None, add_old_network=False, model_qube=None, lead_class="appvm"):
    prefix = birth.read_name_prefix()
    records = _load_records()
    p = _project(records, key)
    # A member being promoted is locked from the plan to the end: a call of
    # the hub's on it that is past its check lands before the plan reads it,
    # and none lands once it is the lead (it grants, so it refuses on a wait).
    promoted = _lock_promoted(lead_origin) if lead_source == "promote" else None
    try:
        _refuse_held_lead(app, p)
        lead_netvm = _model_qube_lead_netvm(model, model_qube, lead_netvm)
        if p.anonymous:
            if lead_name is not None:
                raise ProjectError("an anonymous project's lead is named by dom0 (<label>-lead, "
                                   "or <label>-lead2 while the old one is kept): leave "
                                   "--lead-name out")
            _anonymous_lead(app, lead_source, lead_origin, lead_netvm)
            if keep_old and _vm(app, f"{p.space(prefix)}lead") is not None:
                lead_name = next(f"{p.space(prefix)}lead{n}" for n in range(2, 100)
                                 if _vm(app, f"{p.space(prefix)}lead{n}") is None)
        old_vm = _recorded_lead(app, p)
        old_net, disconnect, widened = None, False, None
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
                        raise ProjectError(f"the project lists {projects.MAX_NETWORKS} networks "
                                           f"already; take one off before adding the old "
                                           f"lead's")
                    if p.anonymous:
                        _anonymous_networks(app, [old_net])
                    # Saved only with the demotion below: a step that fails
                    # before it must not leave the old lead's own network on
                    # the list while it is still the lead.
                    widened = tuple(_check_networks(app, p.networks + (old_net,)))
                else:
                    disconnect = True
        if model is None and _lead_network(app, lead_source, lead_origin, lead_netvm) is not None:
            model = p.model         # the project's model carries over to a new lead with a network
        freed = None if (keep_old or old_vm is None) else p.lead
        if (keep_old and old_vm is not None and lead_source != "promote"
                and (lead_name or f"{p.space(prefix)}lead") == p.lead):
            raise ProjectError(f"the old lead keeps the name {p.lead}; pass --lead-name for the "
                               f"new one")
        name = _plan_lead(app, p.space(prefix), lead_source, lead_origin, lead_netvm, lead_name,
                          freed, model=model, lead_class=lead_class)
        model, _ = _lead_rules(app, lead_source, lead_origin, lead_netvm, model)
        if model_qube not in (None, "none"):
            if lead_source == "promote" and model_qube == lead_origin:
                raise ProjectError(f"'{model_qube}' cannot be both the lead and its model qube")
            _plan_model_qube(app, p.slot, model_qube, records, p)
        elif model is not None and p.model_qube is not None:
            _model_badge_holders(app, p.slot)
        kept_networks = p.networks
        try:
            if widened is not None:
                p.networks = widened
            projects.parse(projects.dump_json(records))     # the record as it will be saved
        except projects.ProjectsUnreadable as e:
            raise ProjectError(f"the project's record would not be valid: {e}") from None
        finally:
            p.networks = kept_networks
        if model is not None and p.model_qube is not None:
            # The project's model becomes a remote endpoint: its model qube goes
            # first, before any lead changes, so no lead ever has both.
            _set_model_qube(report, app, records, p, None)
        old = p.lead
        kept = []
        if old is not None:
            try:
                ours = _demote_lead(app, p, report, removing=not keep_old,
                                    keep=None if keep_old else kept)
                # The accepted rules were that lead's; the model stays for the next one.
                p.lead, p.lead_firewall = None, None
                if widened is not None:
                    p.networks = widened
                projects.save(records)
                report.append(f"{p.slot}: the record names no lead now")
                if ours and keep_old:
                    old_vm = _vm(app, old)
                    if disconnect:
                        # Off the network before it joins: never a moment as a worker
                        # on a network its project does not list.
                        old_vm.netvm = None
                        report.append(f"{p.slot}: {old} lost its network ({old_net} is not on the "
                                      f"list)")
                    elif add_old_network and old_net is not None:
                        report.append(f"{p.slot}: {old_net} added to the worker networks")
                    try:
                        _set_tags(old_vm, add={projects.member_badge(p.slot)})
                        report.append(f"{p.slot}: {old} kept as a worker")
                    except core.Unreadable as e:
                        report.fail(f"{p.slot}: {old} was kept as a worker, but {e}")
                elif ours:
                    err = _remove_qube_locked(app, old, kept.pop() if kept else None)
                    report.append(f"{p.slot}: removed {old}") if not err else \
                        _not_removed(report, p.slot, old, err)
            finally:
                for lock in kept:
                    lock.__exit__(None, None, None)
        lead, fresh, before, stored, old_rules, old_net = _make_lead(app, p.slot, lead_source,
                                                                     lead_origin, name, lead_netvm,
                                                                     model, p.badges(), lead_class)
        try:
            tpl = lead_origin if lead_source == "template" else _template_name(_vm(app, lead))
            if tpl and tpl not in p.templates and (vm := _vm(app, tpl)) is not None \
                    and core.in_scope(vm) and core.is_template(vm):
                p.templates = p.templates + (tpl,)
        except core.Unreadable as e:
            # The new lead is made: a read here must not leave it unrecorded. Its
            # template stays off the list, one fewer, never one more.
            report.append(f"{p.slot}: {e}, so the lead's template was not added to the "
                          f"approved list")
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
                      + (f", firewall: {firewall.endpoint_summary(model)}" if stored else ""))
        if model_qube is not None:
            _set_model_qube(report, app, records, p, None if model_qube == "none" else model_qube)
    finally:
        if promoted is not None:
            promoted.__exit__(None, None, None)


def _lock_promoted(name):
    if not core.valid_qube_name(name):
        return None                     # the plan refuses it in its own words
    lock = core.qube_lock(name, must=True)
    try:
        lock.__enter__()
    except core.QubeBusy as e:
        raise ProjectError(str(e)) from None
    except core.Refusal as r:
        raise ProjectError(f"'{name}''s lock cannot be taken ({r.payload.get('error')}), so "
                           f"nothing was changed") from None
    return lock


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


def _apply_edit(report, app, records, p, templates, networks, quota, added=None):
    """`added`, for an edit that names what it adds and removes: (templates,
    networks) it adds, the only entries checked. An entry it does not name
    stays as recorded even when it no longer qualifies (`qmcp check` reports
    that), so an edit that only takes something off is never refused for
    another entry. Without it, every entry of the new lists is checked."""
    if p.anonymous:
        # Refused here rather than stopped by the gate after it is saved.
        for t in (templates if added is None else added[0]) or ():
            _not_managed(app, t, "the template")
        if added is None or added[1]:
            _anonymous_networks(app, (networks if added is None else added[1]) or ())
    if templates is not None:
        if added is None:
            p.templates = tuple(_check_templates(app, templates))
        else:
            if not templates:
                raise ProjectError("a project needs at least one approved template in AI space")
            if added[0]:
                _check_templates(app, added[0])
            p.templates = tuple(templates)
        _dvmt_share_refusal(app, records, p, p.templates if added is None else added[0])
    if networks is not None:
        if added is None:
            new = tuple(_check_networks(app, networks))
        else:
            if not networks:
                raise ProjectError("a project needs at least one worker network (a gateway, "
                                   "or none)")
            if added[1]:
                _check_networks(app, added[1])
            new = tuple(networks)
        in_use = _networks_in_use(app, p, set(p.named_networks()) - set(new))
        if in_use:
            raise ProjectError(f"still in use: {', '.join(in_use)}; remove those workers, or "
                               f"clear their networks, before taking the network off the list")
        p.networks = new
    if quota is not None:
        p.quota = _quota(quota)
    if p.hidden:
        _hide_disposable_templates(report, app, p)
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
    added = ([t for t in templates if t not in p.templates],
             [n for n in networks if n not in p.networks])
    _apply_edit(report, app, records, p,
                templates if tuple(templates) != p.templates else None,
                networks if tuple(networks) != p.networks else None,
                new_quota if new_quota != p.quota else None, added)


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
            "model_qube": p.model_qube,
            "accepted": accepted, "live": live, "read_error": error,
            "same": live is not None and accepted is not None and live == accepted}


def set_lead_firewall(app, key: str, model: str | None = None, rules=None,
                      accept_current: bool = False, model_qube: str | None = None) -> list:
    """Change a lead's firewall, or accept the rules it has. With `model`, the
    lead's model endpoint changes and its firewall becomes "model endpoint
    only" (for a lead with a network); with `rules`, its firewall becomes
    exactly those rules; with `accept_current`, its live rules become the
    accepted ones and nothing on the qube changes, if they are in qmcp's rule
    format (no comment or expire, at most 32). The record keeps what qubesd
    reads back; a write that does not read back is undone. With `model_qube`,
    a qube: the project's model becomes that self-hosted model qube, and a
    lead with a network loses it (`_set_model_qube`); "none": the project's
    model qube is taken away, and nothing else changes."""
    return _run(_set_lead_firewall, app, key, model, rules, accept_current, model_qube)


def _set_lead_firewall(report, app, key, model, rules, accept_current, model_qube=None):
    if sum(x is not None and x is not False
           for x in (model, rules, accept_current or None, model_qube)) != 1:
        raise ProjectError("say one of --model HOST:PORT, --model-qube QUBE|none, --rule RULE "
                           "(repeatable) or --accept-current")
    records = _load_records()
    p = _project(records, key)
    if model_qube != "none":
        # Taking a model qube away only takes authority, and leaves the lead alone.
        _refuse_held_lead(app, p)
    if model_qube is not None:
        _set_model_qube(report, app, records, p, None if model_qube == "none" else model_qube)
        return
    if p.model_qube is not None and model is None:
        raise ProjectError(f"the model of {p.label} is the qube {p.model_qube}, and its lead has no "
                           f"network, so it has no firewall to set or accept")
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
        if p.model_qube is not None:
            raise ProjectError(f"the model of {p.label} is the qube {p.model_qube}, and its lead "
                               f"has no network: a remote model takes a new lead on a network "
                               f"(qmcp project lead {p.label} ... --lead-netvm NET --model HOST:PORT)")
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


def _model_badge_holders(app, slot: str) -> list:
    """Every qube wearing `slot`'s model badge. A qube whose tags cannot be
    read stops the command: it may wear the badge."""
    badge = projects.model_badge(slot)
    out, unread = [], []
    for vm in app.domains:
        try:
            if badge in _tags(vm):
                out.append(vm.name)
        except core.Gone:
            continue
        except core.Unreadable:
            unread.append(vm.name)
    if unread:
        raise ProjectError(f"cannot read the tags of {', '.join(sorted(unread))}, so whether they "
                           f"wear {badge} is not known; try again")
    return sorted(out)


def _plan_model_qube(app, slot: str, name, records=None, p=None) -> None:
    """Check `name` (or None: no model qube) as `slot`'s model qube, changing
    nothing. An anonymous project's model qube serves it alone, and no other
    project may share one that serves an anonymous project."""
    if name is not None:
        why = model_qube_refusal({vm.name: vm for vm in app.domains}, name)
        if why:
            raise ProjectError(f"'{name}' cannot be a model qube: {why}")
        others = projects.model_slots(_read_tags(_vm(app, name))) - {slot}
        records = _load_records() if records is None else records
        anonymous_others = sorted(s for s in others if s in records and records[s].anonymous)
        if others and p is not None and p.anonymous:
            raise ProjectError(f"'{name}' already serves {', '.join(sorted(others))}: an "
                               f"anonymous project's model qube serves it alone")
        if anonymous_others:
            raise ProjectError(f"'{name}' serves the anonymous project(s) "
                               f"{', '.join(anonymous_others)}, which it serves alone")
    _model_badge_holders(app, slot)


def _set_model_qube(report, app, records, p, name) -> None:
    """Make `name` the model qube of `p`'s slot, or with None give the slot
    none. In authority order: the slot's model badge comes off every other
    qube; the lead loses its network (a lead whose model is a qube has none);
    the model qube leaves p00, loses its network, is guarded and is killed if
    it runs (unless it is already a guarded model qube); the record names it;
    and only then does it wear the slot's model badge, which is what
    lets the lead reach it; a hidden project's wears `qmcp-hubblind` before
    the badge, and keeps it when it stops serving (it holds the project's
    conversations). Checked again here, against the fleet as it is
    now. A failure part-way leaves less authority than the command meant,
    never more, and the report says how far it got."""
    if name is None:
        return _set_model_qube_held(report, app, records, p, name)
    _project_qube_lock(name, True,
                       lambda held: _set_model_qube_held(report, app, records, p, name))


def _set_model_qube_held(report, app, records, p, name) -> None:
    """`_set_model_qube` with the model qube's lock held (none for None)."""
    _plan_model_qube(app, p.slot, name, records, p)
    badge = projects.model_badge(p.slot)
    for holder in _model_badge_holders(app, p.slot):
        if holder != name and (vm := _vm(app, holder)) is not None:
            _set_tags(vm, remove={badge})
            report.append(f"{p.slot}: {holder} is no longer its model qube"
                          + (" (it stays hidden from the hub: it holds the project's "
                             "conversations)" if p.hidden else ""))
    if name is None:
        p.model_qube = None
        projects.save(records)
        report.append(f"{p.slot}: the record names no model qube")
        return
    lead = _recorded_lead(app, p)
    if lead is not None:
        try:
            had = _netvm(lead)
        except NetvmUnreadable:
            raise ProjectError(f"the network of {p.lead} cannot be read") from None
        if had is not None:
            lead.netvm = None
            if _netvm(lead) is not None:
                raise ProjectError(f"{p.lead}'s network did not read back as none")
            report.append(f"{p.slot}: {p.lead} lost its network ({had}): a lead whose model "
                          f"is a qube has none")
    vm = _vm(app, name)
    tags = _tags(vm)
    if projects.member_badge(projects.HUB_SLOT) in tags:
        _set_tags(vm, remove={projects.member_badge(projects.HUB_SLOT)})
        report.append(f"{p.slot}: {name} is out of p00")
    try:
        had = _netvm(vm)
    except NetvmUnreadable:
        raise ProjectError(f"the network of {name} cannot be read") from None
    if had is not None:
        vm.netvm = None
        if _netvm(vm) is not None:
            raise ProjectError(f"{name}'s network did not read back as none")
        report.append(f"{p.slot}: {name} lost its network ({had})")
    managed = core.GUARDED not in tags
    # Guarding stops new calls from the hub, not the ones it started while the
    # qube was managed: those end with the qube, and so does anything started
    # in one the operator guarded before it became a model qube. One already a
    # guarded model qube is left alone: the hub could not reach it, and its
    # leads may be using it. A lead starts it again by connecting.
    kill = managed or not projects.model_slots(tags)
    if managed or tags & LEGACY_TIER_TAGS:
        try:
            _set_tags(vm, add={core.GUARDED}, remove=tags & LEGACY_TIER_TAGS)
        except Exception as e:
            # The guard may have landed before its read-back failed: a second
            # run would find it guarded, and spare it if it already serves
            # another project. So the kill comes first.
            if kill:
                _kill_model_qube(report, p.slot, vm, name, managed, type(e).__name__)
            raise
        report.append(f"{p.slot}: {name} is guarded")
    if kill:
        _kill_model_qube(report, p.slot, vm, name, managed)
    p.model, p.model_qube, p.lead_firewall = None, name, None
    projects.save(records)
    if p.hidden:
        _set_tags(vm, add={projects.HUBBLIND})
        report.append(f"{p.slot}: {name} is hidden from the hub")
    if anonymous_mode():
        # Under the hub's check once it serves no anonymous project (the
        # project deleted, or its model qube taken away): it wears the mode's
        # badge from now on, as everything there does.
        _set_tags(vm, add={projects.ANON})
    _set_tags(vm, add={badge})
    report.append(f"{p.slot}: model qube {name}; the lead reaches it on port {MODEL_PORT}")
    shared = sorted(projects.model_slots(_tags(vm)) - {p.slot})
    if shared:
        report.append(f"{p.slot}: WARNING: {name} also serves {', '.join(shared)}: "
                      f"{SHARED_MODEL_WARNING}")


def add_dump(app, key: str, name: str | None = None) -> list:
    """Give a project, or p00, its dump sink: a fresh offline drop box."""
    return _run(_add_dump, app, key, name)


def _add_dump(report, app, key, name):
    records = _load_records()
    p = records[projects.HUB_SLOT] if key == projects.HUB_SLOT else _project(records, key)
    if p.dump is not None:
        raise ProjectError(f"{p.slot} already has a dump sink, {p.dump}")
    prefix = birth.read_name_prefix()
    name = name or _sink_default_name(p)
    if name.startswith(prefix) or not core.valid_qube_name(name):
        raise ProjectError(f"a dump sink's name must be a qube name outside '{prefix}'")
    _make_sink(app, p.slot, name, p.hidden)
    p.dump = name
    try:
        projects.save(records)
    except Exception:
        _remove_qube(app, name)
        raise
    report.append(f"{p.slot}: dump sink {name} created (no network)")


def _halted_refusal(vm, name: str, where: str) -> str | None:
    """Why `name` may not go `where` while it runs, or None when it reads
    Halted. Whatever runs in it would go on there, with that place's reach. It
    is never killed for this, since a kill loses what is being written: the
    operator shuts it down. A power state that does not read refuses too."""
    state = _safe(vm.get_power_state, "unknown")
    if state == "Halted":
        return None
    now = ("its power state cannot be read" if state in ("NA", "unknown", None)
           else f"it is {state}")
    how = (f"qvm-unpause {name}, then qvm-shutdown {name}" if state == "Paused"
           else f"qvm-shutdown {name}")
    return (f"'{name}' goes {where} only when shut down, and {now}: what runs in it would go "
            f"on there; shut it down first ({how}), then run this again")


#: How long a qube moving between slots must read Halted, under
#: `qmcp-blocked`, before its badges change: Qubes' pre-start reads Halted,
#: and a start admitted before the badge, which the rulebook then refuses
#: anew, shows by then (the hub's teardown waits the same).
MOVE_SETTLE_S = 10.0


def _settled_halted(vm, seconds: float) -> str | None:
    """None when the qube reads Halted throughout `seconds`, else what it read."""
    deadline = time.monotonic() + seconds
    while True:
        state = _safe(vm.get_power_state, "unknown")
        if state != "Halted":
            return state
        if time.monotonic() >= deadline:
            return None
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


def _hub_only(slots) -> bool:
    """True when every slot in `slots` is the hub's own: p00 or no slot."""
    return all(s in (None, projects.HUB_SLOT) for s in slots)


MOVE_PAST_WARNING = ("a qube has a past: what it holds and what it was used for come with it, "
                     "and it may link the projects it has been in")
MOVE_HIDDEN_WARNING = "moving it out of a hidden project hands the hub its contents"


def move_warnings(records: dict, current: set, slot) -> list:
    """What a move into or out of anonymous space says before it runs: into,
    out of, or between anonymous projects. Empty for any other move. Needs
    `--yes`, like any move from one slot into another."""
    def anonymous(s):
        return s is not None and s in records and records[s].anonymous \
            and s != projects.HUB_SLOT

    def hidden(s):
        return anonymous(s) and records[s].hidden
    if not any(anonymous(s) for s in current) and not anonymous(slot):
        return []
    out = [MOVE_PAST_WARNING]
    if any(hidden(s) for s in current) and not hidden(slot):
        out.append(MOVE_HIDDEN_WARNING)
    return out


def move(app, name: str, target: str, confirm: bool = False) -> list:
    """Move one of AI space's AppVMs or StandaloneVMs into p00, a project, or no
    slot. Moving a standalone the operator built into a project is the
    operator's approval of its OS, as approving a template is. Its network
    is not changed, so a project takes it only on one of its worker networks.
    Taking a qube out of one slot into another carries that slot's content
    across a trust boundary, and needs `confirm`; so does a move into, out of
    or between anonymous projects, which says first that the qube has a past.
    The anonymity gate judges the project a qube moves into, and the hub in
    anonymous mode, as the move would leave them: the move is refused if the
    project would be unsound, or if the hub's check would stop more qubes or
    the moved qube itself."""
    return _run(_move_locked, app, name, target, confirm)


def _move_locked(report, app, name, target, confirm):
    """`_move` under the qube's lock, taken inside the project locks (the
    create lock first, then a qube's, as a clone takes them)."""
    _project_qube_lock(name, True, lambda held: _move(report, app, name, target, confirm))


def _project_qube_lock(name, must: bool, fn):
    """`_with_qube_lock` for a project command, whose refusals are
    ProjectErrors."""
    return _with_qube_lock(name, must, fn, error=ProjectError)


def _move(report, app, name, target, confirm):
    records = _load_records()
    mode = anonymous_mode()
    vm = _vm(app, name)
    tags = set() if vm is None else _tags(vm)
    if core.UMBRELLA not in tags:
        raise ProjectError(f"no qube '{name}' in AI space")
    if not _workload(vm) or core.GUARDED in tags:
        raise ProjectError(f"'{name}' is not a managed AppVM or StandaloneVM; templates and "
                           f"gateways join no slot")
    if projects.LEAD in tags or projects.lead_slots(tags):
        raise ProjectError(f"'{name}' is a lead; use qmcp project lead")
    if projects.model_slots(tags) and target != "none":
        raise ProjectError(f"'{name}' is a model qube; a model qube joins no slot")
    if tags & {projects.BLOCKED, projects.STOPPED}:
        raise ProjectError(f"'{name}' was stopped by the anonymity gate; clear it first (qmcp "
                           f"project unblock)")
    if _held(tags):
        raise ProjectError(f"'{name}' {HELD_WHY}")
    if target == "none":
        slot, p = None, None
    elif target == projects.HUB_SLOT:
        slot, p = projects.HUB_SLOT, None
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
    moving = current != ({slot} if slot is not None else set())
    # p00 and no slot are both the hub's, so a move between them carries
    # nothing across; any other slot change does.
    crossing = moving and not _hub_only(current | {slot})
    where = "no slot" if slot is None else f"{p.label} ({slot})" if p is not None and p.label \
        else slot
    if crossing and (why := _halted_refusal(vm, name, f"into {where}")):
        raise ProjectError(why)
    warnings = move_warnings(records, current, slot) if moving else []
    if moving and not confirm:
        if warnings:
            raise ProjectError(f"'{name}' moves into or out of anonymous space: "
                               + "; ".join(warnings) + "; re-run with --yes")
        if slot is not None and current:
            raise ProjectError(f"'{name}' is in {', '.join(sorted(current))}: moving it carries "
                               f"that slot's content into {slot}; re-run with --yes")
    # The badges it wears after: its new slot's, the anonymous project's, and
    # in anonymous mode `qmcp-anon` wherever it goes.
    anon_badges = {projects.ANON, projects.HUBBLIND}
    want_anon = (p.badges() if p is not None and p.anonymous else set()) \
        | ({projects.ANON} if mode else set())
    after = (tags - {projects.member_badge(s) for s in current} - anon_badges) \
        | ({projects.member_badge(slot)} if slot is not None else set()) | want_anon
    _gate_the_move(app, records, name, after, p if p is not None and p.anonymous else None, mode)
    for line in warnings:
        report.append(f"{name}: {line}")
    # Authority comes off and goes on in the order that is never more than
    # either end: the badges that keep the hub out go on first, the old slot's
    # badge comes off before the new one goes on, and the hidden badge comes
    # off last.
    add_first = want_anon - tags
    remove_last = (tags & anon_badges) - want_anon
    leaving = current - ({slot} if slot is not None else set())
    if crossing:
        # The rulebook refuses every call into a qube wearing `qmcp-blocked`,
        # so no start is admitted from here on; one admitted before it shows
        # while the qube must stay Halted. Only then do its slot badges change.
        try:
            _set_tags(vm, add={projects.BLOCKED})
        except core.Unreadable as e:
            raise ProjectError(f"'{name}' was given {projects.BLOCKED} for the move, but {e}, so "
                               f"it was moved nowhere; it may wear {projects.BLOCKED} now, which "
                               f"refuses every call into it: qvm-tags {name} del "
                               f"{projects.BLOCKED} once qmcp check is clean") from None
        state = _settled_halted(vm, MOVE_SETTLE_S)
        if state is not None:
            unblocked = _unblock_after_move(vm, name)
            raise ProjectError(_halted_refusal(vm, name, f"into {where}")
                               or f"'{name}' read {state} while it was to stay shut down; "
                                  f"nothing was moved" + unblocked)
        report.append(f"{name}: shut down throughout {MOVE_SETTLE_S:g} s, under "
                      f"{projects.BLOCKED}")
    # A step below that fails leaves the move's block on: nothing reaches a
    # qube in a half-done move until the operator has looked.
    held = (f"; it still wears {projects.BLOCKED}, so nothing reaches it until you take it off "
            f"(qvm-tags {name} del {projects.BLOCKED})") if crossing else ""
    if add_first:
        try:
            _set_tags(vm, add=add_first)
        except core.Unreadable as e:
            report.fail(f"{name}: given {', '.join(sorted(add_first))}, but {e}; it was moved "
                        f"nowhere (qmcp check shows what is left)" + held)
            return
    if leaving:
        try:
            _set_tags(vm, remove={projects.member_badge(s) for s in leaving})
        except core.Unreadable as e:
            report.fail(f"{name}: taken out of {', '.join(sorted(leaving))}, but {e}; it was "
                        f"moved into nothing (qmcp check shows what is left)" + held)
            return
        report.append(f"{name}: out of {', '.join(sorted(leaving))}")
    if slot is not None and slot not in current:
        try:
            _set_tags(vm, add={projects.member_badge(slot)})
        except core.Unreadable as e:
            report.fail(f"{name}: put in {slot}, but {e} (qmcp check shows what is left)" + held)
            return
    if remove_last:
        try:
            _set_tags(vm, remove=remove_last)
        except core.Unreadable as e:
            report.fail(f"{name}: put in {slot or 'no slot'}, and {', '.join(sorted(remove_last))} "
                        f"taken off, but {e} (qmcp check shows what is left)" + held)
            return
    if crossing and (state := _safe(vm.get_power_state, "unknown")) != "Halted":
        # Started meanwhile, though no call could be admitted into it (dom0,
        # say): the move is undone, to the badges it had, and said.
        how = ("its power state cannot be read now" if state in ("NA", "unknown", None)
               else f"it reads {state} now")
        try:
            _set_tags(vm, remove=after - tags, add=(tags - after) - {projects.BLOCKED})
            undone = "the move was undone"
        except Exception as e:
            undone = f"the move could NOT be undone ({type(e).__name__}; qmcp check shows it)"
        report.fail(f"{name}: {how}, so it may have started while it was moved: {undone}; "
                    f"shut it down (qvm-shutdown {name}), then move it again"
                    + _unblock_after_move(vm, name))
        return
    if crossing:
        unblocked = _unblock_after_move(vm, name)
        if unblocked:
            report.fail(f"{name}: moved" + unblocked)
            return
    report.append(f"{name}: {'no slot' if slot is None else slot}")
    prefix = birth.read_name_prefix()
    for q in records.values():
        if q.label and q.slot != slot and name.startswith(q.space(prefix)):
            report.append(f"{name}: its name stays inside '{q.space(prefix)}', so {q.label}'s lead "
                          f"can still detect it by name")


def _unblock_after_move(vm, name) -> str:
    """Take the move's `qmcp-blocked` off: "" when it came off, else words."""
    try:
        _set_tags(vm, remove={projects.BLOCKED})
        return ""
    except Exception as e:
        return (f"; it may still wear {projects.BLOCKED} ({type(e).__name__}), which refuses "
                f"every call into it: qvm-tags {name} del {projects.BLOCKED}")


def _gate_the_move(app, records: dict, name: str, after: set, p, mode: bool) -> None:
    """Refuse a move the anonymity gate would stop: the anonymous project it
    goes into, and in anonymous mode the hub, judged as if the qube already
    wore `after`. A judgement that cannot be made refuses too."""
    hub = core.read_hub()
    for subject in ([p] if p is not None else []) + ([anon.HUB] if mode else []):
        try:
            before = anon.judge(app, subject, records=records)
            v = anon.judge(app, subject, records=records, overlay={name: after})
        except (core.Unreadable, anon.PolicyUnreadable) as e:
            raise ProjectError(f"the anonymity gate could not judge {subject.label} with "
                               f"'{name}' in it ({e}); nothing was moved") from None
        if v.status == anon.GREEN:
            continue
        # Judged by what would be stopped, not by the words: a project is
        # stopped whole, so it must be sound; the hub's check stops by qube,
        # so the move may not add to what it stops, nor be among it.
        if subject is anon.HUB:
            more = set(anon.hub_stop_set(v, hub)) - set(anon.hub_stop_set(before, hub))
            if not more and name not in v.offenders:
                continue
        raise ProjectError(f"the anonymity gate would stop {subject.label} with '{name}' in "
                           f"it: " + "; ".join(d for _, d in v.problems) + "; nothing was moved")


def _kept_with_slot(vm, tags, slot: str) -> str | None:
    """Why a qube wearing `slot`'s member badge is not removed with the slot,
    or None. One that is a member of another slot too belongs to that project
    as well; a template, a disposable template or a gateway is something other
    qubes are built on or reach the network through; a model qube, a guarded
    qube, a dump sink and the hub are never a project's members. Each loses
    only `slot`'s badges. Raises `Unreadable` when its class cannot be read: the delete then
    neither removes nor strips it, as for a qube whose tags do not read."""
    others = sorted(projects.member_slots(tags) - {slot})
    if others:
        return f"also a member of {', '.join(others)}"
    models = sorted(projects.model_slots(tags))
    if models:
        return f"the model qube of {', '.join(models)}"
    if core.GUARDED in tags:
        return "guarded"
    if projects.DROP_BOX in tags:
        return "a dump sink"
    if vm.name == core.read_hub():
        return "the hub"
    if core.is_gateway(vm):
        return "a gateway"
    if core.is_template(vm):
        return "a template" if core.klass_of(vm) == "TemplateVM" else "a disposable template"
    return None


def _slot_members(app, slot: str) -> tuple:
    """([removed], [(kept, why)], [unread]) for the qubes wearing `slot`'s
    member badge, as a delete of it would treat them; unread: tags or class
    that do not read, neither removed nor stripped."""
    members, kept, unread = [], [], []
    for vm in app.domains:
        try:
            if core.is_member(vm, slot):
                why = _kept_with_slot(vm, core.tags_of(vm), slot)
                if why:
                    kept.append((vm.name, why))
                else:
                    members.append(vm.name)
        except core.Gone:
            pass
        except core.Unreadable:
            unread.append(vm.name)
    return sorted(members), sorted(kept), sorted(unread)


def delete_plan(app, records: dict, key: str) -> tuple:
    """What `qmcp project delete KEY --yes` would do, changing nothing: (it can
    run, the plan in words). Reads the records, the qubes and the hub file only, so it
    needs no root, and the window and a proposal show it before anyone asks.
    It names every qube the delete removes, record or not."""
    p = projects.find(records, key)
    if p is None and key in projects.PROJECT_SLOTS:
        slot = key
    elif p is None or p.slot == projects.HUB_SLOT:
        return False, f"no project '{key}'"
    else:
        slot = p.slot
    members, kept, unread = _slot_members(app, slot)
    names = ", ".join(members) if members else "none"
    keeps = "".join(f"; it keeps {n} ({why}), which loses only {slot}'s badges"
                    for n, why in kept)
    # Every other qube wearing a badge of the slot (a leftover lead, a sink, a
    # stray badge) loses it and stays; the record's own are named below.
    holders, _ = _badges_of_slot(app, slot)
    named = set(members) | {n for n, _ in kept} | set(unread) | (
        {p.lead, p.dump, p.model_qube} if p is not None else set())
    strays = sorted(set(holders) - named)
    if strays:
        keeps += f"; it strips {slot}'s badges from {', '.join(strays)}, which stay"
    note = (f"; {', '.join(unread)} cannot be read now: a delete leaves "
            f"{'it' if len(unread) == 1 else 'each'} as it is while it cannot be read, and "
            f"{slot} stays in use; once it reads, it is removed or stripped like the rest"
            if unread else "")
    if p is None:
        return True, (f"{key} has no record: this finishes a delete, removing the qubes still "
                      f"wearing its member badge ({names}) and stripping its badges "
                      f"everywhere{keeps}{note}")
    model = f"; its model qube {p.model_qube} is kept and loses {p.slot}'s badge" \
        if p.model_qube else ""
    return True, (f"this removes {p.slot} '{p.label}': its lead {p.lead or '(none)'} and every "
                  f"member qube ({names}), and keeps "
                  f"its dump sink {p.dump or '(none)'}{model}{keeps}{note}")


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
        held = []
        try:
            ours = _demote_lead(app, p, report, removing=True, keep=held)
            del records[p.slot]
            projects.save(records)
            report.append(f"{p.slot}: record of '{p.label}' deleted")
            if ours:
                err = _remove_qube_locked(app, p.lead, held.pop() if held else None)
                report.append(f"{p.slot}: removed {p.lead}") if not err else \
                    _not_removed(report, p.slot, p.lead, err)
        finally:
            for lock in held:
                lock.__exit__(None, None, None)
    # Only qubes really in the project are removed. A stray badge on a qube
    # outside AI space is stripped below, never the qube. A qube whose tags
    # cannot be read is neither removed nor stripped: the delete reports it,
    # and the slot stays in use until a run reads it.
    # A member of another slot too, a template, a disposable template, a
    # gateway, a model qube, a guarded qube, a dump sink or the hub is kept and
    # only loses this slot's badges, below (`_kept_with_slot`).
    members, kept, _ = _slot_members(app, p.slot)
    kept = dict(kept)
    for name in members:
        err = _remove_qube_locked(app, name)
        report.append(f"{p.slot}: removed {name}") if not err else \
            _not_removed(report, p.slot, name, err)
    holders, _ = _badges_of_slot(app, p.slot)
    for name in holders:
        try:
            vm = _vm(app, name)
            tags = set() if vm is None else _tags(vm)
            try:
                why = kept.get(name) or (_kept_with_slot(vm, tags, p.slot) if vm is not None
                                         and _member(tags, p.slot) else None)
            except core.Unreadable as e:
                # Neither removed nor stripped: still wearing the badge, it
                # keeps the slot in use until a run reads it.
                report.append(f"{p.slot}: left {name} as it is: {e}")
                continue
            if _member(tags, p.slot) and not why:
                # A member the first pass could not read: removed like the rest.
                err = _remove_qube_locked(app, name)
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
            hidden = projects.HUBBLIND in tags
            report.append(f"{p.slot}: stripped {', '.join(sorted(strip))} from {name}"
                          + (" (the dump sink, kept)" if name == p.dump else
                             " (the model qube, kept)" if name == p.model_qube else
                             f" (kept: {why})" if why else "")
                          + (": still hidden from the hub, since it holds the project's "
                             "output" if hidden else ""))
        except Exception as e:
            report.fail(f"{p.slot}: could NOT strip badges from {name} ({type(e).__name__})")
    left, unread = _badges_of_slot(app, p.slot)
    if left or unread:
        report.fail(f"{p.slot}: NOT reusable until these lose its badges: "
                    f"{', '.join(left + [f'{n} (tags unreadable)' for n in unread])}")
    else:
        report.append(f"{p.slot}: free")


#: What switching a project's audit lines away from disk leaves behind, as the
#: command and the window say it.
AUDIT_LEAVES_DISK = ("the lines this project wrote before stay in dom0's audit log on disk, in "
                     "its rotated files and in any backup, until the hourly timer removes a "
                     "rotated file by age; deleting a file on dom0's disk is not erasing it: "
                     "its bytes stay on the disk until they are overwritten")


def set_project_audit(app, key: str, mode: str) -> list:
    """Where a project's audit lines go from now: disk, ram (its own chain
    under /run, gone at shutdown) or off. Allowed while it runs. Leaves one
    line on the install's chain naming the slot only, so the chain explains
    the gap and the label stays off it."""
    return _run(_set_project_audit, app, key, mode)


def _set_project_audit(report, app, key, mode):
    if mode not in projects.AUDIT_MODES:
        raise ProjectError(f"an audit mode is one of {', '.join(projects.AUDIT_MODES)}")
    records = _load_records()
    p = _project(records, key)
    old = p.audit
    if old == mode:
        report.append(f"{p.slot}: its audit lines go to {mode} already; nothing changed")
        return
    p.audit = mode
    projects.save(records)
    audit.audit("qmcp project audit", "operator", {"slot": p.slot, "mode": mode}, True, slots=())
    report.append(f"{p.slot}: its audit lines go to {mode} from now"
                  + {"disk": "", "ram": " (its own chain under /run, gone at shutdown)",
                     "off": " (none is written)"}[mode])
    if old == "disk":
        report.append(AUDIT_LEAVES_DISK)
    if mode != "disk":
        report.append("dom0's journal still keeps every qrexec call: qmcp check says how to "
                      "keep it in RAM")


def unblock(app, key: str) -> list:
    """Take `qmcp-blocked` off an anonymous project's lead and members once a
    fresh gate run finds it sound; `autostart` stays off. `p00` (or `hub`)
    clears the hub and every qube under the hub's check in anonymous mode."""
    return _run(_unblock, app, key)


def _unblock(report, app, key):
    records = _load_records()
    slot = projects.HUB_SLOT if key in (projects.HUB_SLOT, "hub") else _project(records, key).slot
    try:
        for line in anon.unblock(app, records, slot):
            # A qube NOT unblocked is a failed step: the command exits 1 and
            # its audit line says so.
            (report.fail if isinstance(line, anon.NotUnblocked) else report.append)(line)
    except ValueError as e:
        raise ProjectError(str(e)) from None


def project_rows(app, records: dict) -> list:
    rows = []
    for slot in projects.SLOTS:
        p = records.get(slot)
        if p is None:
            continue
        badge = projects.member_badge(slot)
        members, blocked = 0, False
        for vm in app.domains:
            try:
                tags = core.tags_of(vm)
            except core.Gone:
                continue
            except core.Unreadable:
                members = None      # not known, never a count that skipped a qube
                break
            member = _member(tags, slot)
            members += member
            if projects.BLOCKED in tags and (member or (vm.name == p.lead and
                                                        projects.lead_badge(slot) in tags)):
                blocked = True
        try:
            used = budget.persistent_sum(app, badge)
        except Exception:
            used = None
        rows.append({"slot": slot, "label": p.label, "lead": p.lead, "members": members,
                     "used": used, "quota": p.quota, "templates": list(p.templates),
                     "networks": list(p.networks), "dump": p.dump, "model": p.model,
                     "model_qube": p.model_qube,
                     "lead_firewall": None if p.lead_firewall is None else list(p.lead_firewall),
                     "anonymous": p.anonymous, "hidden": p.hidden, "note": p.note,
                     "audit": p.audit,
                     "blocked": None if members is None else blocked})
    return rows
