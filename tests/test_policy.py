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

WRAPPERS = ["qmcp.ListAIManagedQubes", "qmcp.GetPropertyAIManaged",
            "qmcp.SetPropertyAIManaged", "qmcp.SetFeatureAIManaged",
            "qmcp.LifecycleAIManaged", "qmcp.SpawnAIManagedQube",
            "qmcp.CloneAIManagedQube", "qmcp.SpawnDisposableAIManaged",
            "qmcp.AIManagedEvents", "qmcp.GetPoolStats"]
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
    """(outcome, rule) for one request. `rules` overrides policy.rules."""
    try:
        req = Request(service, "+", source, target, system_info=SYSINFO)
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
    # Services Qubes redirects from @default to dom0: the A5 deny only sees a
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

    def test_sources_are_ours(self):
        allowed = {HUB, "@tag:ai-managed", "@anyvm", "@tag:ai-dump"}
        bad = [(n, l) for n, l in self.lines if l.split()[2] not in allowed]
        self.assertEqual(bad, [])

    def test_every_allow_names_a_known_principal(self):
        # No allow or ask for an open-ended source: @anyvm and @tag:ai-dump only deny.
        bad = [(n, l) for n, l in self.lines
               if l.split()[4] in ("allow", "ask") and l.split()[2] not in (HUB, "@tag:ai-managed")]
        self.assertEqual(bad, [])

    def test_admin_api_list_is_complete(self):
        denied = {l.split()[0] for n, l in self.lines
                  if l.split()[1:5] == ["*", "@tag:ai-managed", "@anyvm", "deny"]}
        missing = sorted(set(ADMIN_METHODS) - denied)
        self.assertEqual(missing, [], "admin methods with no AI-space deny")

    def test_no_dialog_free_copy_in_m1(self):
        # This release has no dialog-free copy from AI space at all.
        bad = [(n, l) for n, l in self.lines
               if l.split()[0] == "qubes.Filecopy" and l.split()[2] == "@tag:ai-managed"
               and l.split()[4] == "allow"]
        self.assertEqual(bad, [])

    def test_hub_is_a_name_never_a_tag(self):
        self.assertTrue(re.search(r"^\S+\s+\*\s+mcp-control\s", OURS.read_text(), re.M))


if __name__ == "__main__":
    unittest.main()
