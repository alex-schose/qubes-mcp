"""qmcp.fleet — the operator's side: `check`, `migrate`, role actions, listing.

This runs in dom0 as the operator (root, or a member of `qubes`), with full
Admin API authority, and never on behalf of an AI caller. Badges change only
through these role actions, so each one refuses a change that
would break an invariant `check` asserts.

`check` reports one of three overall results, and INCOMPLETE is not green:
  GREEN       every check ran and none failed (warnings allowed)
  FAILED      at least one check failed
  INCOMPLETE  a check could not run, so the fleet is unproven
"""
from __future__ import annotations

import os
import stat

from qmcp import audit, birth, budget, core

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
)
_PROBES = {"ai": "qmcp-probe-ai", "peer": "qmcp-probe-peer",
           "guarded": "qmcp-probe-guarded", "outside": "qmcp-probe-outside"}


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
    for role, tags in (("ai", [core.UMBRELLA]), ("peer", [core.UMBRELLA]),
                       ("guarded", [core.UMBRELLA, core.GUARDED]), ("outside", [])):
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
        for src in (ai_sources if role == "ai" else [hub]):
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

    # 5. stray badges outside AI space
    stray = sorted(vm.name for vm in vms if not core.in_scope(vm)
                   and any(t == core.GUARDED or t.startswith(birth.NAMESPACE)
                           for t in _tags(vm) if not t.startswith(TOMBSTONE_PREFIX)))
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


def guard(app, name) -> str:
    vm = _target(app, name)
    vm.tags.add(core.GUARDED)
    vm.tags.add(core.UMBRELLA)
    for t in sorted(_tags(vm) & LEGACY_TIER_TAGS):
        vm.tags.discard(t)
    return f"{name}: guarded"


def revoke(app, name, shutdown: bool = True) -> str:
    """Strip every AI-space badge, pin default_dispvm, and shut the qube down
    Restrictions such as an egress lock go too: revoke is yours."""
    vm = _target(app, name)
    for t in sorted(t for t in _tags(vm) if birth.controlled(t)):
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


def listing(app) -> list:
    rows = []
    for vm in app.domains:
        st = core.state(vm)
        if st is None:
            continue
        tpl = _safe(lambda: getattr(vm, "template", None))
        net = _safe(lambda: getattr(vm, "netvm", None))
        rows.append({
            "name": vm.name, "state": st, "klass": _safe(lambda: vm.klass),
            "template": None if tpl is None else str(getattr(tpl, "name", tpl)),
            "netvm": None if net is None else str(getattr(net, "name", net)),
            "power": _safe(vm.get_power_state, "unknown"),
            "owner": _owner(vm),
        })
    return rows
