"""Offline policy matrix: policy/30-mcp-control.policy on qrexec's REAL parser.

This is the M1 gate for the rulebook. It loads our file next to upstream Qubes
4.3's own default policy (tests/data/upstream-policy-4.3/) into
python3-qrexec's parser -- the same code dom0's policy daemon runs -- and
evaluates a matrix of (service, source, target) requests against a synthetic
fleet.

Two baselines:

  stock       upstream's defaults only.
  permissive  plus a file numbered AFTER ours that allows nearly everything.
              It models a careless include file or a later operator file. Every
              deny our file claims must still hold, because in that world our
              file is the only thing standing.

Teeth: every rule line in our file is removed in turn and the cases it decided
are re-evaluated. A rule whose removal changes no outcome, in either baseline,
fails the suite -- a rule that reads as a control and is not one is the defect
this project keeps shipping by accident.

The parser is required. Without python3-qrexec this suite cannot run, and a
gate that cannot run must not pass, so the import error is left to fail it.
"""
from __future__ import annotations

import logging
import os
import pathlib
import re
import shutil
import tempfile
import unittest
import uuid

from qrexec.exc import AccessDenied, RequestError
from qrexec.policy.parser import FilePolicy, Request

HERE = pathlib.Path(__file__).resolve().parent
OURS = HERE.parent / "policy" / "30-mcp-control.policy"
#: The baseline our file is evaluated against. Offline: upstream's defaults as
#: vendored. On a real dom0, point QMCP_POLICY_BASELINE at /etc/qubes/policy.d
#: to run the same matrix against that box's actual policy set (our own file in
#: it, if any, is replaced by the one under test).
UPSTREAM = pathlib.Path(os.environ.get("QMCP_POLICY_BASELINE")
                        or HERE / "data" / "upstream-policy-4.3")
ADMIN_METHODS = [m for m in (HERE / "data" / "qubesd-admin-methods-4.3.txt")
                 .read_text().split() if m]

HUB = "mcp-control"
AI = "ai-managed"
G = "qmcp-guarded"
SLOTS = [f"p{n:02d}" for n in range(16)]
PROJECT_SLOTS = SLOTS[1:]

WRAPPERS = ["qmcp.ListAIManagedQubes", "qmcp.GetPropertyAIManaged",
            "qmcp.SetPropertyAIManaged", "qmcp.SetFeatureAIManaged",
            "qmcp.LifecycleAIManaged", "qmcp.SpawnAIManagedQube",
            "qmcp.CloneAIManagedQube", "qmcp.SpawnDisposableAIManaged",
            "qmcp.AIManagedEvents", "qmcp.GetPoolStats",
            "qmcp.SubmitProposal", "qmcp.ProposalStatus"]
#: Proposals are the hub's: no lead line routes them, so D2 refuses a lead.
PROPOSAL_SERVICES = ["qmcp.SubmitProposal", "qmcp.ProposalStatus"]
#: A lead calls every dom0 service but the event stream and the hub's proposals.
LEAD_WRAPPERS = [w for w in WRAPPERS if w != "qmcp.AIManagedEvents" and w not in PROPOSAL_SERVICES]
LEAD_TO_MEMBER = [("qmcp.RunInAIManaged", "allow user=root"),
                  ("qmcp.CopyToAIManaged", "allow user=root"),
                  ("admin.vm.firewall.Get", "allow target=@adminvm"),
                  ("admin.vm.firewall.Set", "allow target=@adminvm"),
                  ("admin.vm.firewall.Reload", "allow target=@adminvm"),
                  ("qubes.Filecopy", "allow")]
POLICY_API = ["policy.List", "policy.include.List", "policy.Get", "policy.include.Get",
              "policy.GetFiles", "policy.Replace", "policy.include.Replace", "policy.Remove",
              "policy.include.Remove", "policy.RegisterArgument", "policy.UnregisterArgument",
              "policy.EvalSimulate", "policy.EvalGUI"]
EXEC_FAMILY = ["qubes.VMShell", "qubes.VMRootShell", "qubes.VMExec",
               "qubes.VMExecGUI"]
BOOT_SERVICES = ["qubes.FeaturesRequest", "qubes.NotifyTools",
                 "qubes.NotifyUpdates", "qubes.SyncAppMenus",
                 "qubes.GetRandomizedTime"]
HUB_SYSTEM = ["qubes.GetDate", "qubes.GetImageRGBA", "qubes.WaitForSession",
              "qubes.SyncAppMenus", "qubes.NotifyTools", "qubes.NotifyUpdates",
              "qubes.FeaturesRequest", "qubes.GetRandomizedTime"]
CHILD_TO_HUB = ["qubes.OpenInVM", "qubes.OpenURL", "qubes.StartApp",
                "qubes.ClipboardPaste", "qubes.GetImageRGBA", "qubes.Filecopy",
                "qubes.ConnectTCP", "qubes.SomethingNew"]


def _dom(type_="AppVM", tags=(), dvmt=False, default_dispvm=None):
    return {"tags": list(tags), "type": type_, "template_for_dispvms": dvmt,
            "default_dispvm": default_dispvm, "icon": "", "internal": False,
            "power_state": "Running", "uuid": str(uuid.uuid4())}


#: The synthetic fleet. Names describe the role, so a failing case reads.
FLEET = {
    "dom0": _dom("AdminVM"),
    HUB: _dom(default_dispvm="default-dvm"),
    "ai-work": _dom(tags=[AI]),
    "ai-work2": _dom(tags=[AI]),
    "ai-work-dd": _dom(tags=[AI], default_dispvm="default-dvm"),
    "ai-work-aidd": _dom(tags=[AI], default_dispvm="ai-dvm"),
    "ai-tpl": _dom("TemplateVM", tags=[AI]),
    "ai-tpl-g": _dom("TemplateVM", tags=[AI, G]),
    "ai-dvm": _dom(tags=[AI], dvmt=True),
    "ai-dvm-g": _dom(tags=[AI, G], dvmt=True),
    "ai-gw": _dom(tags=[AI, G]),
    "ai-revoked": _dom(default_dispvm="default-dvm"),
    "ai-revoked-aidd": _dom(default_dispvm="ai-dvm"),
    "ai-sink": _dom(tags=["ai-dump"]),
    "personal": _dom(default_dispvm="default-dvm"),
    "default-dvm": _dom(dvmt=True),
    "debian-13": _dom("TemplateVM"),
    "sys-net": _dom(),
    "sys-firewall": _dom(),
    "sys-usb": _dom(),
}
# Every slot: a lead (p01-p15), two members and a dump sink.
for _s in SLOTS:
    if _s != "p00":
        FLEET[f"lead-{_s}"] = _dom(tags=[AI, "qmcp-lead", f"qmcp-lead-{_s}"])
    FLEET[f"w-{_s}-a"] = _dom(tags=[AI, f"qmcp-proj-{_s}"])
    FLEET[f"w-{_s}-b"] = _dom(tags=[AI, f"qmcp-proj-{_s}"])
    FLEET[f"sink-{_s}"] = _dom(tags=["ai-dump", f"qmcp-dump-{_s}"])
FLEET["w-p01-g"] = _dom(tags=[AI, G, "qmcp-proj-p01"])
# Self-hosted model qubes: one per project slot, guarded; one shared by p01 and
# p02 (allowed, with a warning); and model badges in places qmcp check fails
# on, to show what the order of A3-A7 still stops and what it cannot.
for _s in PROJECT_SLOTS:
    FLEET[f"model-{_s}"] = _dom(tags=[AI, G, f"qmcp-model-{_s}"])
FLEET["model-shared"] = _dom(tags=[AI, G, "qmcp-model-p01", "qmcp-model-p02"])
FLEET["model-p01-open"] = _dom(tags=[AI, "qmcp-model-p01"])
FLEET["model-p01-outside"] = _dom(tags=["qmcp-model-p01"])
FLEET["sink-model-p01"] = _dom(tags=["ai-dump", "qmcp-dump-p01", "qmcp-model-p01"])
FLEET["lead-p03-model-p01"] = _dom(tags=[AI, "qmcp-lead", "qmcp-lead-p03", "qmcp-model-p01"])
# Anonymous projects (M3c): a member the gate stopped, and qubes of a hidden
# project, its lead included.
FLEET["w-p01-blocked"] = _dom(tags=[AI, "qmcp-proj-p01", "qmcp-anon", "qmcp-blocked"])
FLEET["lead-p06-blocked"] = _dom(tags=[AI, "qmcp-lead", "qmcp-lead-p06", "qmcp-anon",
                                       "qmcp-blocked"])
FLEET["w-p06-a"] = _dom(tags=[AI, "qmcp-proj-p06", "qmcp-anon"])
FLEET["model-p06"] = _dom(tags=[AI, "qmcp-guarded", "qmcp-model-p06"])
# A member the operator started by hand after the gate stopped its project.
FLEET["w-p06-blocked"] = _dom(tags=[AI, "qmcp-proj-p06", "qmcp-anon", "qmcp-blocked"])
FLEET["w-p05-hidden"] = _dom(tags=[AI, "qmcp-proj-p05", "qmcp-anon", "qmcp-hubblind"])
FLEET["lead-p07-hidden"] = _dom(tags=[AI, "qmcp-lead", "qmcp-lead-p07", "qmcp-anon",
                                      "qmcp-hubblind"])
FLEET["sink-p07-hidden"] = _dom(tags=["ai-dump", "qmcp-dump-p07", "qmcp-hubblind"])
# M5's open windows: a guarded qube the operator opened, with and without the
# firewall half, and a model qube in one (the common case). A badge on a qube
# `qmcp open` refuses is not a legitimate state and is not modelled as one: the
# expiry pass strips it and `qmcp check` fails on it. The two below exist only
# to prove A0 still outranks A6b.
FLEET["ai-tpl-open"] = _dom("TemplateVM", tags=[AI, G, "qmcp-open"])
FLEET["ai-tpl-open-fw"] = _dom("TemplateVM", tags=[AI, G, "qmcp-open", "qmcp-open-fw"])
FLEET["model-p04-open"] = _dom(tags=[AI, G, "qmcp-model-p04", "qmcp-open"])
FLEET["w-p01-blocked-open"] = _dom(tags=[AI, "qmcp-proj-p01", "qmcp-anon", "qmcp-blocked",
                                         "qmcp-open", "qmcp-open-fw"])
FLEET["w-p05-hidden-open"] = _dom(tags=[AI, "qmcp-proj-p05", "qmcp-anon", "qmcp-hubblind",
                                        "qmcp-open", "qmcp-open-fw"])

SYSINFO = {"domains": FLEET}


def _permissive_text() -> str:
    """A later file that allows nearly everything (see the module docstring)."""
    lines = ["# test-only: a careless file numbered after ours"]
    for m in ADMIN_METHODS + POLICY_API:
        lines.append(f"{m} * @anyvm @anyvm allow target=dom0")
        lines.append(f"{m} * @anyvm @adminvm allow target=dom0")
    for svc in WRAPPERS:
        lines.append(f"{svc} * @anyvm @adminvm allow")
    lines += [
        "qmcp.RunInAIManaged * @anyvm @anyvm allow user=root",
        "qmcp.CopyToAIManaged * @anyvm @anyvm allow user=root",
        "* * @anyvm @adminvm allow",
        "* * @anyvm @anyvm allow",
    ]
    return "\n".join(lines) + "\n"


def _load(extra: dict[str, str] | None = None) -> FilePolicy:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-policy-"))
    try:
        shutil.copytree(UPSTREAM, tmp, dirs_exist_ok=True, symlinks=True)
        (tmp / "README.md").unlink(missing_ok=True)
        shutil.copy(OURS, tmp / OURS.name)
        for name, text in (extra or {}).items():
            (tmp / name).write_text(text)
        return FilePolicy(policy_path=tmp)
    finally:
        shutil.rmtree(tmp)


def _first_rule(policy, rules, service, source, target):
    """(outcome, rule) for one request. `rules` overrides policy.rules.
    `service` may carry its argument: `qubes.ConnectTCP+11434`."""
    service, _, argument = service.partition("+")
    try:
        req = Request(service, f"+{argument}", source, target, system_info=SYSINFO)
    except (AccessDenied, RequestError):
        # Refused before any rule is read (e.g. @dispvm:<not a template>).
        return "deny", None
    for rule in rules:
        if rule.is_match(req):
            break
    else:
        return "deny", None
    act = type(rule.action).__name__.lower()
    if act == "allow":
        user = getattr(rule.action, "user", None)
        tgt = getattr(rule.action, "target", None)
        if user:
            act += f" user={user}"
        if tgt:
            act += f" target={tgt}"
    return act, rule


def _base(outcome: str) -> str:
    return outcome.split()[0]


class Case:
    __slots__ = ("label", "service", "source", "target", "stock", "permissive")

    def __init__(self, label, service, source, target, stock, permissive):
        self.label, self.service, self.source, self.target = label, service, source, target
        self.stock, self.permissive = stock, permissive

    def __repr__(self):
        return f"{self.label}: {self.service} {self.source} -> {self.target}"


def _cases() -> list[Case]:
    """The M1 intent, written independently of the policy text.

    Expected outcomes: "allow" (optionally with " user=..."/" target=..."),
    "ask" or "deny". "deny" covers a matching deny rule, no matching rule, and
    a request qrexec refuses before reading any rule. A permissive expectation
    of "allow" marks something this file does not claim.
    """
    c: list[Case] = []
    add = lambda *a: c.append(Case(*a))  # noqa: E731

    # --- the hub operates managed qubes, templates included
    for tgt in ("ai-work", "ai-tpl", "ai-dvm"):
        add("hub exec managed", "qmcp.RunInAIManaged", HUB, tgt, "allow user=root", "allow user=root")
        add("hub copy-out managed", "qmcp.CopyToAIManaged", HUB, tgt, "allow user=root", "allow user=root")
    for svc in ("admin.vm.firewall.Get", "admin.vm.firewall.Set", "admin.vm.firewall.Reload"):
        add("hub firewall managed", svc, HUB, "ai-work", "allow target=@adminvm", "allow target=@adminvm")
    # --- guarded qubes: read and referenced, never written
    for tgt in ("ai-tpl-g", "ai-dvm-g", "ai-gw"):
        add("hub exec guarded", "qmcp.RunInAIManaged", HUB, tgt, "deny", "deny")
        add("hub copy-out guarded", "qmcp.CopyToAIManaged", HUB, tgt, "deny", "deny")
        add("hub fw-set guarded", "admin.vm.firewall.Set", HUB, tgt, "deny", "deny")
        add("hub fw-reload guarded", "admin.vm.firewall.Reload", HUB, tgt, "deny", "deny")
        add("hub fw-get guarded", "admin.vm.firewall.Get", HUB, tgt, "allow target=@adminvm", "allow target=@adminvm")
        add("hub filecopy guarded", "qubes.Filecopy", HUB, tgt, "deny", "deny")
        add("ai filecopy guarded", "qubes.Filecopy", "ai-work", tgt, "deny", "deny")
        add("ai exec guarded", "qmcp.RunInAIManaged", "ai-work", tgt, "deny", "deny")
        add("ai open-in guarded", "qubes.OpenInVM", "ai-work", tgt, "deny", "deny")
        add("ai open-url guarded", "qubes.OpenURL", "ai-work", tgt, "deny", "deny")
    # --- M5: the operator's open window (A6b). The hub runs commands and copies
    # a file in by dialog; the firewall writes need the second badge; nothing
    # else in the window changes, and no other source gains anything.
    for tgt in ("ai-tpl-open", "model-p04-open"):
        add("hub exec open", "qmcp.RunInAIManaged", HUB, tgt, "allow user=root",
            "allow user=root")
        add("hub filecopy open", "qubes.Filecopy", HUB, tgt, "ask", "ask")
        add("hub fw-set open, no firewall half", "admin.vm.firewall.Set", HUB, tgt, "deny", "deny")
        add("hub fw-reload open, no firewall half", "admin.vm.firewall.Reload", HUB, tgt,
            "deny", "deny")
        add("hub fw-get open", "admin.vm.firewall.Get", HUB, tgt, "allow target=@adminvm",
            "allow target=@adminvm")
        add("hub copy-out open", "qmcp.CopyToAIManaged", HUB, tgt, "deny", "deny")
        add("ai exec open", "qmcp.RunInAIManaged", "ai-work", tgt, "deny", "deny")
        add("ai filecopy open", "qubes.Filecopy", "ai-work", tgt, "deny", "deny")
        add("lead exec open", "qmcp.RunInAIManaged", "lead-p01", tgt, "deny", "deny")
        add("lead filecopy open", "qubes.Filecopy", "lead-p01", tgt, "deny", "deny")
        add("sink into open", "qubes.Filecopy", "sink-p01", tgt, "deny", "deny")
    add("hub exec open+fw", "qmcp.RunInAIManaged", HUB, "ai-tpl-open-fw", "allow user=root",
        "allow user=root")
    add("hub fw-set open+fw", "admin.vm.firewall.Set", HUB, "ai-tpl-open-fw",
        "allow target=@adminvm", "allow target=@adminvm")
    add("hub fw-reload open+fw", "admin.vm.firewall.Reload", HUB, "ai-tpl-open-fw",
        "allow target=@adminvm", "allow target=@adminvm")
    # A0 outranks the window: a qube the gate stopped and a hidden one stay
    # unreachable however they are badged.
    for svc in ("qmcp.RunInAIManaged", "qubes.Filecopy", "admin.vm.firewall.Set"):
        add("hub into blocked+open", svc, HUB, "w-p01-blocked-open", "deny", "deny")
        add("hub into hubblind+open", svc, HUB, "w-p05-hidden-open", "deny", "deny")
    # The four Filecopy request shapes this project requires of any Filecopy
    # change: a named in-scope qube, a named out-of-scope one, a made-up name
    # and @default. The last two must not be distinguishable from each other.
    add("hub filecopy named out of scope", "qubes.Filecopy", HUB, "ai-tpl-g", "deny", "deny")
    add("hub filecopy made-up name", "qubes.Filecopy", HUB, "no-such-qube", "ask", "ask")
    add("hub filecopy @default", "qubes.Filecopy", HUB, "@default", "ask", "ask")
    # --- a lead's firewall is the operator's: the hub reads it and never writes it
    for tgt in ("lead-p01", "lead-p15"):
        add("hub fw-set lead", "admin.vm.firewall.Set", HUB, tgt, "deny", "deny")
        add("hub fw-reload lead", "admin.vm.firewall.Reload", HUB, tgt, "deny", "deny")
        add("hub fw-get lead", "admin.vm.firewall.Get", HUB, tgt, "allow target=@adminvm",
            "allow target=@adminvm")
        add("hub exec lead", "qmcp.RunInAIManaged", HUB, tgt, "allow user=root", "allow user=root")
    # ... and a lead cannot write its own, nor another lead's (it is no member)
    for svc in ("admin.vm.firewall.Set", "admin.vm.firewall.Reload"):
        add("lead fw-write itself", svc, "lead-p01", "lead-p01", "deny", "deny")
        add("lead fw-write another lead", svc, "lead-p01", "lead-p02", "deny", "deny")
    # --- the hub never reaches outside AI space, nor itself
    for tgt in ("personal", "sys-net", "debian-13", HUB):
        add("hub exec outside", "qmcp.RunInAIManaged", HUB, tgt, "deny", "deny")
        add("hub fw-set outside", "admin.vm.firewall.Set", HUB, tgt, "deny", "deny")
    # --- hub -> dom0: the wrappers, its own boot services, and nothing else
    for svc in WRAPPERS:
        add("hub wrapper", svc, HUB, "dom0", "allow", "allow")
    for svc in HUB_SYSTEM:
        add("hub system svc", svc, HUB, "dom0", "allow", "allow")
    # qvm-sync-clock asks @default; Qubes redirects it to dom0.
    add("hub clock sync", "qubes.GetDate", HUB, "@default", "allow target=dom0", "allow target=dom0")
    add("hub usb available", "admin.vm.device.usb.Available", HUB, "dom0", "ask", "ask")
    add("hub usb attach self", "admin.vm.device.usb.Attach", HUB, HUB, "ask", "ask")
    add("hub usb detach self", "admin.vm.device.usb.Detach", HUB, HUB, "ask", "ask")
    add("hub usb data", "qubes.USB", HUB, "sys-usb", "ask", "ask")
    for m in ADMIN_METHODS:
        if m != "admin.vm.device.usb.Available":
            add("hub admin->dom0", m, HUB, "dom0", "deny", "deny")
        if not m.startswith("admin.vm.firewall."):
            add("hub admin->ai", m, HUB, "ai-work", "deny", "deny")
    for m in POLICY_API:
        add("hub policy api", m, HUB, "dom0", "deny", "deny")
    add("hub unknown dom0 svc", "qubes.SomethingNew", HUB, "dom0", "deny", "deny")
    # --- the hub's own operator UX dialogs
    for svc in ("qubes.Filecopy", "qubes.OpenInVM", "qubes.OpenURL",
                "qubes.ClipboardCopy", "qubes.ClipboardPaste"):
        add("hub ux ask", svc, HUB, "personal", "ask", "ask")
    add("hub raw dispvm exec", "qubes.VMShell", HUB, "@dispvm", "deny", "deny")
    add("hub dispvm of ai template", "qubes.OpenInVM", HUB, "@dispvm:ai-dvm", "deny", "deny")

    # --- anonymous projects: nothing reaches a stopped qube, the hub no hidden one
    for svc, lead_out in (("qmcp.RunInAIManaged", "allow user=root"),
                          ("qmcp.CopyToAIManaged", "allow user=root"),
                          ("admin.vm.firewall.Set", "allow target=@adminvm"),
                          ("qubes.Filecopy", "allow")):
        add("lead into its stopped member", svc, "lead-p01", "w-p01-blocked", "deny", "deny")
        add("hub into a stopped member", svc, HUB, "w-p01-blocked", "deny", "deny")
        add("hub into a hidden member", svc, HUB, "w-p05-hidden", "deny", "deny")
        add("hub into a hidden lead", svc, HUB, "lead-p07-hidden", "deny", "deny")
        # The hidden badge keeps out the hub only: a lead runs its hidden project.
        add("lead into its hidden member", svc, "lead-p05", "w-p05-hidden", lead_out, lead_out)
    add("member copy into a stopped member", "qubes.Filecopy", "w-p01-a", "w-p01-blocked",
        "deny", "deny")
    add("hub reads a stopped qube's firewall", "admin.vm.firewall.Get", HUB, "w-p01-blocked",
        "deny", "deny")
    add("hub reads a hidden qube's firewall", "admin.vm.firewall.Get", HUB, "w-p05-hidden",
        "deny", "deny")
    add("hub exec into a stopped lead", "qmcp.RunInAIManaged", HUB, "lead-p06-blocked",
        "deny", "deny")
    # A stopped qube the operator started by hand reaches nothing: not dom0, not
    # its own members, not its model qube, not a peer in its slot.
    add("a stopped lead reaches no dom0 service", "qmcp.ListAIManagedQubes",
        "lead-p06-blocked", "dom0", "deny", "deny")
    add("a stopped lead runs nothing in its member", "qmcp.RunInAIManaged",
        "lead-p06-blocked", "w-p06-a", "deny", "deny")
    add("a stopped lead reaches no model qube", "qubes.ConnectTCP+11434", "lead-p06-blocked",
        "model-p06", "deny", "deny")
    add("a stopped member copies nothing into its slot", "qubes.Filecopy", "w-p06-blocked",
        "w-p06-a", "deny", "deny")
    add("a stopped member gets no clock through @default", "qubes.GetDate", "w-p06-blocked",
        "@default", "deny", "deny")
    for svc in ("qubes.Filecopy", "qubes.OpenInVM", "qubes.OpenURL", "qubes.ClipboardPaste"):
        add("hub dialog into a hidden qube", svc, HUB, "w-p05-hidden", "deny", "deny")
        add("hub dialog into a hidden sink", svc, HUB, "sink-p07-hidden", "deny", "deny")
    add("hidden member copies to its sink", "qubes.Filecopy", "w-p05-hidden", "sink-p05",
        "allow", "allow")
    # An anonymous qube opens nothing elsewhere, not even through a dialog.
    for svc in ("qubes.OpenURL", "qubes.OpenInVM"):
        for tgt in ("personal", "@default", "@dispvm:default-dvm", "w-p05-hidden"):
            add("anonymous qube opens elsewhere", svc, "w-p05-hidden", tgt, "deny", "deny")
        add("an ordinary member's dialog stays", svc, "w-p05-a", "personal", "ask", "allow")

    # --- AI -> dom0: boot services only
    for svc in BOOT_SERVICES:
        add("ai boot svc", svc, "ai-work", "dom0", "allow", "allow")
    for m in ADMIN_METHODS:
        add("ai admin->dom0", m, "ai-work", "dom0", "deny", "deny")
        add("ai admin->ai", m, "ai-work", "ai-work2", "deny", "deny")
        add("ai admin->outside", m, "ai-tpl", "personal", "deny", "deny")
    for m in POLICY_API:
        add("ai policy api", m, "ai-work", "dom0", "deny", "deny")
        add("ai policy api via @default", m, "ai-work", "@default", "deny", "deny")
    # Services Qubes redirects from @default to dom0: the D2 deny only sees a
    # dom0 target, so these are checked as @default requests.
    add("ai desktop notification", "qubes.Notifications", "ai-work", "@default", "deny", "deny")
    add("ai admin via @default", "admin.vm.List", "ai-work", "@default", "deny", "deny")
    add("ai unknown via @default", "qubes.SomethingNew", "ai-work", "@default", "deny", "allow")
    for svc in WRAPPERS:
        add("ai calls a wrapper", svc, "ai-work", "dom0", "deny", "deny")
    add("ai unknown dom0 svc", "qubes.SomethingNew", "ai-work", "dom0", "deny", "deny")
    # --- AI never drives qmcp's in-qube services
    add("ai exec ai", "qmcp.RunInAIManaged", "ai-work", "ai-work2", "deny", "deny")
    add("ai copy-out ai", "qmcp.CopyToAIManaged", "ai-work", "ai-work2", "deny", "deny")

    # --- disposables
    for svc in EXEC_FAMILY + ["qubes.OpenInVM", "qubes.OpenURL", "qubes.StartApp"]:
        add("ai bare dispvm", svc, "ai-work-dd", "@dispvm", "deny", "deny")
        add("ai dispvm ai-template", svc, "ai-work", "@dispvm:ai-dvm", "deny", "deny")
        add("ai dispvm guarded template", svc, "ai-work", "@dispvm:ai-dvm-g", "deny", "deny")
        add("operator dispvm ai-template", svc, "personal", "@dispvm:ai-dvm", "deny", "deny")
        add("revoked qube, default is ai template", svc, "ai-revoked-aidd", "@dispvm", "deny", "deny")
    for svc in EXEC_FAMILY:
        add("ai exec named non-ai template", svc, "ai-work", "@dispvm:default-dvm", "deny", "deny")
        add("ai exec named qube", svc, "ai-work", "personal", "deny", "deny")
    add("ai dispvm non-template", "qubes.VMShell", "ai-work", "@dispvm:personal", "deny", "deny")
    # Residuals, pinned so they stay visible (CLAUDE.md, residual risks):
    # a named template outside AI space still gets Qubes' own ask for Open*,
    # and a qube stripped of ai-managed keeps Qubes' shortcut to its default
    # template -- which is why the create path pins default_dispvm to None.
    add("RESIDUAL ai open in named non-ai template", "qubes.OpenInVM", "ai-work", "@dispvm:default-dvm", "ask", "allow")
    add("RESIDUAL revoked qube, non-ai default", "qubes.OpenInVM", "ai-revoked", "@dispvm", "allow", "allow")

    # --- AI never reaches the hub
    for svc in CHILD_TO_HUB:
        add("child->hub", svc, "ai-work", HUB, "deny", "deny")
        add("template->hub", svc, "ai-tpl", HUB, "deny", "deny")

    # --- copies out of AI space: the operator dialog
    for tgt in ("ai-work2", "ai-tpl", "ai-sink", "personal", "no-such-qube", "@default"):
        add("ai filecopy asks", "qubes.Filecopy", "ai-work", tgt, "ask", "ask")
    add("drop box back into AI space", "qubes.Filecopy", "ai-sink", "ai-work", "deny", "deny")
    add("drop box opens into AI space", "qubes.OpenInVM", "ai-sink", "ai-work", "deny", "deny")
    add("operator drains the drop box", "qubes.Filecopy", "ai-sink", "personal", "ask", "allow")

    # --- upstream behaviour this file leaves alone
    add("ai clock sync", "qubes.GetDate", "ai-work", "@default", "allow target=dom0", "allow")
    add("RESIDUAL managed template updates", "qubes.UpdatesProxy", "ai-tpl", "@default", "allow target=sys-net", "allow")
    add("appvm update proxy", "qubes.UpdatesProxy", "ai-work", "@default", "deny", "allow")
    add("operator qube untouched", "qubes.OpenInVM", "personal", "@dispvm", "allow", "allow")

    # --- projects: every slot's own lines
    for s in SLOTS:
        for a, b in ((f"w-{s}-a", f"w-{s}-b"), (f"w-{s}-b", f"w-{s}-a")):
            add(f"{s} member copies to member", "qubes.Filecopy", a, b, "allow", "allow")
        add(f"{s} member copies to its sink", "qubes.Filecopy", f"w-{s}-a", f"sink-{s}", "allow", "allow")
        add(f"{s} sink cannot copy back", "qubes.Filecopy", f"sink-{s}", f"w-{s}-a", "deny", "deny")
        if s == "p00":
            continue
        for svc, want in LEAD_TO_MEMBER:
            add(f"{s} lead -> member", svc, f"lead-{s}", f"w-{s}-a", want, want)
        add(f"{s} lead copies to its sink: dialog", "qubes.Filecopy", f"lead-{s}", f"sink-{s}", "ask", "ask")
        add(f"{s} worker reaches its lead", "qubes.Filecopy", f"w-{s}-a", f"lead-{s}", "deny", "deny")
        add(f"{s} worker drives its lead", "qmcp.RunInAIManaged", f"w-{s}-a", f"lead-{s}", "deny", "deny")
        for svc in LEAD_WRAPPERS:
            add(f"{s} lead -> dom0 wrapper", svc, f"lead-{s}", "dom0", "allow", "allow")
    # --- projects: nothing crosses a slot
    for svc, _ in LEAD_TO_MEMBER[:5]:
        add("lead -> another project's member", svc, "lead-p01", "w-p02-a", "deny", "deny")
        add("lead -> the hub's p00 qube", svc, "lead-p01", "w-p00-a", "deny", "deny")
        add("lead -> a guarded member", svc, "lead-p01", "w-p01-g", "deny", "deny")
    add("lead copy into another project: dialog", "qubes.Filecopy", "lead-p01", "w-p02-a", "ask", "ask")
    add("member copy into another project: dialog", "qubes.Filecopy", "w-p01-a", "w-p02-a", "ask", "ask")
    add("member copy into another project's sink: dialog", "qubes.Filecopy", "w-p01-a", "sink-p02", "ask", "ask")
    add("member copy into p00: dialog", "qubes.Filecopy", "w-p01-a", "w-p00-a", "ask", "ask")
    add("p00 copy into a project: dialog", "qubes.Filecopy", "w-p00-a", "w-p01-a", "ask", "ask")
    add("a guarded member is still guarded", "qubes.Filecopy", "w-p01-a", "w-p01-g", "deny", "deny")
    for svc in CHILD_TO_HUB:
        add("worker -> another lead", svc, "w-p01-a", "lead-p02", "deny", "deny")
        add("lead -> another lead", svc, "lead-p01", "lead-p02", "deny", "deny")
        add("sink -> its lead", svc, "sink-p01", "lead-p01", "deny", "deny")
        add("lead -> the hub", svc, "lead-p01", HUB, "deny", "deny")
    add("a lead's event stream", "qmcp.AIManagedEvents", "lead-p01", "dom0", "deny", "deny")
    for svc in PROPOSAL_SERVICES:
        add("a lead's proposal call", svc, "lead-p01", "dom0", "deny", "deny")
    for svc in WRAPPERS:
        add("worker -> dom0 wrapper", svc, "w-p01-a", "dom0", "deny", "deny")
        add("hub's p00 qube -> dom0 wrapper", svc, "w-p00-a", "dom0", "deny", "deny")
    add("lead admin.vm.List", "admin.vm.List", "lead-p01", "dom0", "deny", "deny")
    add("lead tags its member", "admin.vm.tag.Set", "lead-p01", "w-p01-a", "deny", "deny")
    add("lead property.Set on its member", "admin.vm.property.Set", "lead-p01", "w-p01-a", "deny", "deny")
    add("lead VMShell into its member", "qubes.VMShell", "lead-p01", "w-p01-a", "deny", "deny")
    add("lead raw @dispvm", "qubes.VMShell", "lead-p01", "@dispvm", "deny", "deny")
    add("lead policy.Replace", "policy.Replace", "lead-p01", "dom0", "deny", "deny")
    add("worker drives exec in a peer", "qmcp.RunInAIManaged", "w-p01-a", "w-p01-b", "deny", "deny")
    add("p00 qube drives exec in a peer", "qmcp.RunInAIManaged", "w-p00-a", "w-p00-b", "deny", "deny")
    # --- the hub operates every project
    add("hub exec in a lead", "qmcp.RunInAIManaged", HUB, "lead-p01", "allow user=root", "allow user=root")
    add("hub exec in a worker", "qmcp.RunInAIManaged", HUB, "w-p01-a", "allow user=root", "allow user=root")
    add("hub copies into a sink: dialog", "qubes.Filecopy", HUB, "sink-p01", "ask", "ask")
    add("hub exec in a sink", "qmcp.RunInAIManaged", HUB, "sink-p01", "deny", "deny")

    # --- self-hosted models: a lead reaches its own slot's model qube on 11434
    for s in PROJECT_SLOTS:
        add(f"{s} lead -> its model qube", "qubes.ConnectTCP+11434", f"lead-{s}", f"model-{s}",
            "allow", "allow")
    add("lead -> its model qube, another port", "qubes.ConnectTCP+22", "lead-p01", "model-p01",
        "deny", "deny")
    add("lead -> its model qube, any other service", "qubes.Filecopy", "lead-p01", "model-p01",
        "deny", "deny")
    add("lead -> another slot's model qube", "qubes.ConnectTCP+11434", "lead-p01", "model-p02",
        "deny", "deny")
    add("worker -> its slot's model qube", "qubes.ConnectTCP+11434", "w-p01-a", "model-p01",
        "deny", "deny")
    add("p00 qube -> a model qube", "qubes.ConnectTCP+11434", "w-p00-a", "model-p01",
        "deny", "deny")
    add("hub -> a model qube", "qubes.ConnectTCP+11434", HUB, "model-p01", "deny", "deny")
    add("hub exec in a model qube", "qmcp.RunInAIManaged", HUB, "model-p01", "deny", "deny")
    add("lead -> @default on 11434", "qubes.ConnectTCP+11434", "lead-p01", "@default", "deny", "deny")
    add("shared model qube, first slot", "qubes.ConnectTCP+11434", "lead-p01", "model-shared",
        "allow", "allow")
    add("shared model qube, second slot", "qubes.ConnectTCP+11434", "lead-p02", "model-shared",
        "allow", "allow")
    add("shared model qube, a slot it does not serve", "qubes.ConnectTCP+11434", "lead-p03",
        "model-shared", "deny", "deny")
    # A model badge where qmcp check fails on it: the order still stops these...
    add("model badge on a dump sink", "qubes.ConnectTCP+11434", "lead-p01", "sink-model-p01",
        "deny", "deny")
    add("model badge on another lead", "qubes.ConnectTCP+11434", "lead-p01",
        "lead-p03-model-p01", "deny", "deny")
    # ... and cannot stop these (qmcp check fails on the second; warns on the first).
    add("RESIDUAL un-guarded model qube still reached", "qubes.ConnectTCP+11434", "lead-p01",
        "model-p01-open", "allow", "allow")
    add("RESIDUAL model badge outside AI space reached", "qubes.ConnectTCP+11434", "lead-p01",
        "model-p01-outside", "allow", "allow")
    # --- every other TCP connection from AI space is ours to refuse (D4)
    for src, tgt in (("ai-work", "ai-work2"), ("ai-work", "personal"), ("w-p01-a", "w-p01-b"),
                     ("lead-p01", "w-p01-a"), ("ai-work", "@default")):
        add("ai connect-tcp", "qubes.ConnectTCP+22", src, tgt, "deny", "deny")
    return c


CASES = _cases()


class PolicyMatrix(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        logging.getLogger().setLevel(logging.ERROR)
        cls.stock = _load()
        cls.permissive = _load({"40-test-permissive.policy": _permissive_text()})
        cls.ours = {
            "stock": [r for r in cls.stock.rules if pathlib.Path(r.filepath).name == OURS.name],
            "permissive": [r for r in cls.permissive.rules if pathlib.Path(r.filepath).name == OURS.name],
        }

    def _run(self, policy, field):
        bad = []
        for case in CASES:
            got, _ = _first_rule(policy, policy.rules, case.service, case.source, case.target)
            want = getattr(case, field)
            if got != want:
                bad.append(f"{case!r}: got {got!r}, want {want!r}")
        return bad

    def test_stock_matrix(self):
        bad = self._run(self.stock, "stock")
        self.assertEqual(bad, [], "\n" + "\n".join(bad))

    def test_permissive_matrix(self):
        bad = self._run(self.permissive, "permissive")
        self.assertEqual(bad, [], "\n" + "\n".join(bad))

    def test_every_rule_is_load_bearing(self):
        """Teeth: remove each of our rules; some outcome must change."""
        # Guard against a vacuous pass: if the filter above matched nothing,
        # the loop below would have nothing to check and report green.
        n_lines = sum(1 for l in OURS.read_text().splitlines()
                      if l.strip() and not l.lstrip().startswith("#"))
        self.assertEqual(len(self.ours["stock"]), n_lines)
        self.assertEqual(len(self.ours["permissive"]), n_lines)
        idle = []
        for idx, rule in enumerate(self.ours["stock"]):
            changed = False
            for baseline in ("stock", "permissive"):
                policy = getattr(self, baseline)
                target_rule = self.ours[baseline][idx]
                without = [r for r in policy.rules if r is not target_rule]
                for case in CASES:
                    before, first = _first_rule(policy, policy.rules, case.service,
                                                case.source, case.target)
                    if first is not target_rule:
                        continue
                    after, _ = _first_rule(policy, without, case.service,
                                           case.source, case.target)
                    if after != before:
                        changed = True
                        break
                if changed:
                    break
            if not changed:
                idle.append(f"line {rule.lineno}: {str(rule).strip()}")
        self.assertEqual(idle, [], "rules that decide nothing:\n" + "\n".join(idle))


class PolicyShape(unittest.TestCase):
    """Structural facts about the file itself."""

    def setUp(self):
        self.lines = [(n, l) for n, l in enumerate(OURS.read_text().splitlines(), 1)
                      if l.strip() and not l.lstrip().startswith("#")]

    def test_parses_alone(self):
        FilePolicy(policy_path=self._alone())

    def _alone(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-alone-"))
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copy(OURS, tmp / OURS.name)
        return tmp

    def test_no_trailing_comments(self):
        bad = [n for n, l in self.lines if "#" in l]
        self.assertEqual(bad, [], "a rule line carries a comment")

    SLOT_SOURCES = ({"@tag:qmcp-lead"} | {f"@tag:qmcp-lead-{s}" for s in PROJECT_SLOTS}
                    | {f"@tag:qmcp-proj-{s}" for s in SLOTS})

    def test_sources_are_ours(self):
        # `@tag:qmcp-anon` and `@tag:qmcp-blocked` only deny (A0): the next test
        # holds every allow to a principal.
        allowed = {HUB, "@tag:ai-managed", "@anyvm", "@tag:ai-dump", "@tag:qmcp-anon",
                   "@tag:qmcp-blocked"} \
            | self.SLOT_SOURCES
        bad = [(n, l) for n, l in self.lines if l.split()[2] not in allowed]
        self.assertEqual(bad, [])

    def test_every_allow_names_a_known_principal(self):
        # No allow or ask for an open-ended source: @anyvm and @tag:ai-dump only deny.
        known = {HUB, "@tag:ai-managed"} | self.SLOT_SOURCES
        bad = [(n, l) for n, l in self.lines
               if l.split()[4] in ("allow", "ask") and l.split()[2] not in known]
        self.assertEqual(bad, [])

    def test_every_slot_has_exactly_its_block(self):
        """No slot line reaches across slots, and none is missing or extra: a
        typo in one slot of sixteen would otherwise read like all the rest."""
        slot_lines = {}
        for n, l in self.lines:
            f = l.split()
            tags = [x for x in (f[2], f[3]) if re.match(r"@tag:qmcp-(lead|proj|dump|model)-p\d\d$", x)]
            if tags:
                slots = {x[-3:] for x in tags}
                self.assertEqual(len(slots), 1, f"line {n} crosses slots: {l}")
                slot_lines.setdefault(slots.pop(), set()).add(" ".join(f))
        self.assertEqual(sorted(slot_lines), SLOTS)
        for s in SLOTS:
            L, M, D = f"@tag:qmcp-lead-{s}", f"@tag:qmcp-proj-{s}", f"@tag:qmcp-dump-{s}"
            want = {f"qubes.Filecopy * {M} {M} allow", f"qubes.Filecopy * {M} {D} allow"}
            if s != "p00":
                want |= {f"qmcp.RunInAIManaged * {L} {M} allow user=root",
                         f"qmcp.CopyToAIManaged * {L} {M} allow user=root",
                         f"admin.vm.firewall.Get * {L} {M} allow target=@adminvm",
                         f"admin.vm.firewall.Set * {L} {M} allow target=@adminvm",
                         f"admin.vm.firewall.Reload * {L} {M} allow target=@adminvm",
                         f"qubes.Filecopy * {L} {M} allow",
                         f"qubes.ConnectTCP +11434 {L} @tag:qmcp-model-{s} allow"}
            self.assertEqual(slot_lines[s], want, s)

    def test_model_lines_sit_between_the_denies_that_guard_them(self):
        """Above the guarded deny, which would refuse them; below the denies
        into the hub, the leads and the drop boxes, so a stray model badge on
        one of those opens nothing."""
        where = {}
        for n, l in self.lines:
            f = l.split()
            if f[0] == "qubes.ConnectTCP" and f[1] == "+11434":
                where.setdefault("model", []).append(n)
            elif f[:5] == ["*", "*", "@tag:ai-managed", "@tag:qmcp-guarded", "deny"]:
                where["guarded"] = n
            elif f[:5] == ["*", "*", "@tag:ai-managed", HUB, "deny"]:
                where["hub"] = n
            elif f[:5] == ["*", "*", "@tag:ai-managed", "@tag:qmcp-lead", "deny"]:
                where["lead"] = n
            elif f[:5] == ["qubes.ConnectTCP", "*", "@tag:ai-managed", "@tag:ai-dump", "deny"]:
                where["sink"] = n
        self.assertEqual(len(where["model"]), len(PROJECT_SLOTS))
        self.assertLess(max(where["model"]), where["guarded"])
        self.assertGreater(min(where["model"]), max(where["hub"], where["lead"], where["sink"]))

    def test_leads_reach_dom0_only_through_the_wrappers(self):
        lead = [(l.split()[0], l.split()[3], l.split()[4]) for n, l in self.lines
                if l.split()[2] == "@tag:qmcp-lead"]
        self.assertEqual(sorted(lead), sorted((w, "@adminvm", "allow") for w in LEAD_WRAPPERS))

    def test_admin_api_list_is_complete(self):
        denied = {l.split()[0] for n, l in self.lines
                  if l.split()[1:5] == ["*", "@tag:ai-managed", "@anyvm", "deny"]}
        missing = sorted(set(ADMIN_METHODS) - denied)
        self.assertEqual(missing, [], "admin methods with no AI-space deny")

    def test_dialog_free_copies_stay_inside_a_slot(self):
        # The only dialog-free copies are inside one slot or into its own sink.
        for n, l in self.lines:
            f = l.split()
            if f[0] == "qubes.Filecopy" and f[4] == "allow":
                self.assertRegex(f[2], r"^@tag:qmcp-(lead|proj)-p\d\d$", l)
                self.assertRegex(f[3], r"^@tag:qmcp-(proj|dump)-p\d\d$", l)
                self.assertEqual(f[2][-3:], f[3][-3:], l)

    def test_hub_is_a_name_never_a_tag(self):
        self.assertTrue(re.search(r"^\S+\s+\*\s+mcp-control\s", OURS.read_text(), re.M))


if __name__ == "__main__":
    unittest.main()
