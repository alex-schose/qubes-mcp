#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 2 — the WIRING into the three create paths.

`offline-validate-2.py` proves the logic — the clamp matrix, the two tag
classes, the egress chain. This proves the three wrappers actually CALL it,
verify what the platform did, and roll the create back when they cannot.

**The mocks here are faithful to qubesadmin's PROPAGATION, and that is the
whole reason this file exists as a separate suite.** The I-5 review found a
green suite hiding a live vulnerability: the mock's `clone_vm` returned a fresh
tagless clone, so "the clone carries no inherited tier" passed while real
`clone_vm` copied every tag. The mock agreed with the author instead of with
Qubes. So every propagation this stage depends on is modelled here —
`clone_vm` copies tags AND netvm, `admin.vm.CreateDisposable` inherits the
DVMT's tags AND netvm, `admin.vm.property.{Get,Set}` actually store and return
a value rather than the `b""` no-op that let an unverified netvm read back as
"matches" — and each is guarded by a **teeth** check asserting the mock still
reproduces the pre-fix behaviour. If a teeth check ever fails, the assertions
below it are vacuous and must not be believed.

**What this suite cannot prove, by design.** Tier tags and `qmcp-owner_*` are
deliberately outside `qmcp_scope.QMCP_TAG_VOCABULARY`, so the AI seat cannot
read a child's tier or owner at all — `deploy/test-stage-*.py` must not try.
That a clone of an `ai-full` source really is born `ai-full` on hardware is a
`qvm-tags` read IN DOM0, in the slot (the I-5 slot-62 pattern). Here the tags
are read straight off the fake collection, which proves the wrapper's intent
and nothing about Qubes.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import types
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(os.path.dirname(HERE), "dom0-rpc")

# Assigned, never setdefault — this is often already present in an operator
# shell (it reads `dom0`), and inheriting that value silently leaves the fleet
# with no gateway under the principal's name, so every create fails closed for
# a reason unrelated to what is being tested.
os.environ["QREXEC_REMOTE_DOMAIN"] = "mcp-control"

PASSED = 0
FAILED = 0


def check(label, cond, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}" + (f"  -- {detail}" if detail else ""))


# --------------------------------------------------------------------------
# Faithful mocked qubesadmin
# --------------------------------------------------------------------------

class FakeVolume:
    def __init__(self, size):
        self.size = size

    def resize(self, n):
        self.size = int(n)


class FakeVM:
    def __init__(self, name, klass="AppVM", tags=(), netvm=None,
                 template_for_dispvms=False, provides_network=False):
        self.name = name
        self.klass = klass
        self.tags = set(tags)
        self.netvm = netvm
        self.template_for_dispvms = template_for_dispvms
        self.provides_network = provides_network
        self.template = None
        self.volumes = {"private": FakeVolume(2 * 1024**3),
                        "root": FakeVolume(10 * 1024**3),
                        "volatile": FakeVolume(1 * 1024**3)}
        self._running = False

    # A real qubesadmin VM stringifies to its name; the birth-egress chain
    # turns a `netvm` property into a name that way.
    def __str__(self):
        return self.name

    def is_running(self):
        return self._running

    def kill(self):
        self._running = False


class FakeDomains(dict):
    def __delitem__(self, k):
        dict.__delitem__(self, k)


class FakeApp:
    """Models the three propagations Stage 2 depends on. See the header."""

    def __init__(self, vms):
        self.domains = FakeDomains({v.name: v for v in vms})
        self._disp = 0

    def add_new_vm(self, klass, name, label, template=None):
        # Fresh qube: inherits NO tags, and comes up on the SYSTEM default
        # netvm — which is exactly why the wrapper must set it explicitly.
        vm = FakeVM(name, klass=klass, netvm=self.domains.get("sys-firewall"))
        vm.template = template
        self.domains[name] = vm
        return vm

    def clone_vm(self, src, name):
        # Real clone_vm copies tags (all but created-by-*) AND prefs.
        vm = FakeVM(name, klass=src.klass, tags=set(src.tags),
                    netvm=src.netvm,
                    template_for_dispvms=src.template_for_dispvms)
        self.domains[name] = vm
        return vm

    def qubesd_call(self, vm_name, method, arg=None, payload=None):
        if method == "admin.vm.CreateDisposable":
            self._disp += 1
            dvmt = self.domains[vm_name]
            name = f"disp{self._disp}"
            # slot-16: the disposable INHERITS the DVMT's tags, and the
            # platform gives it the DVMT's netvm (F-F).
            self.domains[name] = FakeVM(name, klass="DispVM",
                                        tags=set(dvmt.tags), netvm=dvmt.netvm)
            return name.encode()
        if method == "admin.vm.tag.Set":
            self.domains[vm_name].tags.add(arg)
            return b""
        if method == "admin.vm.tag.Remove":
            self.domains[vm_name].tags.discard(arg)
            return b""
        if method == "admin.vm.tag.List":
            return (" ".join(sorted(self.domains[vm_name].tags))).encode()
        if method == "admin.vm.property.Set":
            value = (payload or b"").decode()
            self.domains[vm_name].netvm = self.domains.get(value) if value else None
            return b""
        if method == "admin.vm.property.Get":
            got = getattr(self.domains[vm_name], "netvm", None)
            return f"default=False type=vm {'' if got is None else got}".encode()
        if method == "admin.vm.Kill":
            self.domains.pop(vm_name, None)
            return b""
        return b""


def install_fake_qubesadmin(vms):
    qa = types.ModuleType("qubesadmin")
    qa_app = types.ModuleType("qubesadmin.app")
    app = FakeApp(vms)
    qa_app.QubesLocal = lambda *a, **kw: app
    qa.app = qa_app
    qa.Qubes = lambda *a, **kw: app
    exc = types.ModuleType("qubesadmin.exc")

    class QubesException(Exception):
        pass
    exc.QubesException = QubesException
    qa.exc = exc
    sys.modules["qubesadmin"] = qa
    sys.modules["qubesadmin.app"] = qa_app
    sys.modules["qubesadmin.exc"] = exc
    return app


def _load_lib(modname):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(DOM0_RPC, modname + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Assert against `birth.owner_tag(...)` rather than a literal: the separator is
# a platform constraint (qubesd rejects ':'), so a hardcoded tag string here
# would have to be edited in lockstep with SEP — and a test that lags the
# constant it tests fails for the wrong reason.
birth = _load_lib("qmcp_birth")


def load_wrapper(name):
    loader = SourceFileLoader("w_" + name.replace(".", "_"),
                              os.path.join(DOM0_RPC, name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class NoAudit:
    def audit(self, *a, **kw):
        return True


def run(name, request, vms, *, patch=None):
    """Run one create wrapper's main(); return (response dict, app)."""
    app = install_fake_qubesadmin(vms)
    mod = load_wrapper(name)
    mod._AUDIT = NoAudit()
    # The budget gate needs /etc/qmcp/pool-cap, which does not exist here and
    # is I-0's business, not Stage 2's.
    mod._load_budget_lib = lambda: _StubBudget()
    if patch:
        patch(mod)

    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(request))
    sys.stdout = io.StringIO()
    try:
        mod.main()
        raw = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    return json.loads(raw or "{}"), app


class _StubBudget:
    def check_private_size(self, *a, **kw):
        return None

    def check_cap_for_create(self, *a, **kw):
        return None

    def acquire_create_lock(self, *a, **kw):
        return -1

    def dvmt_private_bytes(self, *a, **kw):
        return 2 * 1024**3


# --------------------------------------------------------------------------
# The fleet — TWO egress classes, which is the only way a cross-egress test
# can fail for the right reason (Stage 0.5's finding: with one egress class
# every such test passes vacuously, and the refusal that does fire comes from
# the cross-ref guard rather than from any egress invariant).
# --------------------------------------------------------------------------

CLEAR = "ai-net-router"
TOR = "ai-net-alt"


def fleet():
    return [
        FakeVM("sys-firewall"),                                  # out of scope
        FakeVM(CLEAR, tags={"ai-managed", "ai-net"}, provides_network=True),
        FakeVM(TOR, tags={"ai-managed", "ai-net"}, provides_network=True),
        FakeVM("mcp-control", netvm=None),        # the gateway; netvm set below
        FakeVM("ai-debian-13", klass="TemplateVM",
               tags={"ai-managed", "ai-full"}, netvm=None),
        FakeVM("clear-work", tags={"ai-managed", "ai-full"}, netvm=None),
        FakeVM("tor-work", tags={"ai-managed", "ai-full"}, netvm=None),
        FakeVM("offline-vault", tags={"ai-managed", "ai-full"}, netvm=None),
        FakeVM("guarded-work", tags={"ai-managed", "ai-full", "qmcp-guarded"},
               netvm=None),
        FakeVM("ai-dvmt", tags={"ai-managed", "ai-full"},
               template_for_dispvms=True, netvm=None),
    ]


def wired(gateway_netvm=CLEAR, **netvms):
    """A fleet with the netvm graph filled in (names resolved to objects)."""
    vms = fleet()
    by = {v.name: v for v in vms}
    by["mcp-control"].netvm = by.get(gateway_netvm) if gateway_netvm else None
    by[CLEAR].netvm = by["sys-firewall"]
    by[TOR].netvm = by["sys-firewall"]
    by["clear-work"].netvm = by[CLEAR]
    by["tor-work"].netvm = by[TOR]
    by["guarded-work"].netvm = by[TOR]
    by["ai-dvmt"].netvm = by[CLEAR]
    for name, target in netvms.items():
        by[name].netvm = by.get(target) if target else None
    return vms


def netvm_of(app, name):
    vm = app.domains.get(name)
    got = None if vm is None else vm.netvm
    return None if got is None else str(got)


# --------------------------------------------------------------------------
# 0. Teeth — the mock must reproduce the propagation, or nothing below counts
# --------------------------------------------------------------------------
print("\n=== 0. Teeth: the mock models Qubes, not the author ===")

app = install_fake_qubesadmin(wired())
raw = app.clone_vm(app.domains["tor-work"], "raw")
check("(teeth) clone_vm COPIES the source's tags", "ai-full" in raw.tags)
check("(teeth) clone_vm COPIES the source's netvm", str(raw.netvm) == TOR)

app = install_fake_qubesadmin(wired())
dn = app.qubesd_call("ai-dvmt", "admin.vm.CreateDisposable").decode()
check("(teeth) CreateDisposable INHERITS the DVMT's tags",
      "ai-full" in app.domains[dn].tags)
check("(teeth) CreateDisposable INHERITS the DVMT's netvm",
      str(app.domains[dn].netvm) == CLEAR)

app = install_fake_qubesadmin(wired())
fresh = app.add_new_vm("AppVM", "fresh", "gray", template="ai-debian-13")
check("(teeth) a fresh add_new_vm lands on the SYSTEM default netvm, "
      "not the AI egress", str(fresh.netvm) == "sys-firewall",
      "if this stops being modelled, 'spawn sets netvm explicitly' is vacuous")

app = install_fake_qubesadmin(wired())
app.qubesd_call("ai-dvmt", "admin.vm.property.Set", "netvm", TOR.encode())
check("(teeth) property.Set/Get actually store and return a value",
      app.qubesd_call("ai-dvmt", "admin.vm.property.Get", "netvm")
      .decode().endswith(TOR),
      "a b'' no-op mock lets an unverified netvm read back as a match")

# --------------------------------------------------------------------------
# 1. Birth egress — the leak Stage 0.5 demonstrated, now closed
# --------------------------------------------------------------------------
print("\n=== 1. Birth egress (§3.4) ===")

SPAWN = "qmcp.SpawnAIManagedQube"
CLONE = "qmcp.CloneAIManagedQube"
DISP = "qmcp.SpawnDisposableAIManaged"

r, app = run(CLONE, {"source": "tor-work", "name": "ai-kid"}, wired())
check("clone of a Tor-side source is born on Tor, gateway on clearnet",
      r.get("ok") is True and netvm_of(app, "ai-kid") == TOR,
      f"{r} netvm={netvm_of(app, 'kid')}")

r, app = run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13"},
             wired(gateway_netvm=TOR))
check("template spawn inherits the PRINCIPAL's egress (row 2), not a constant",
      r.get("ok") is True and netvm_of(app, "ai-kid") == TOR,
      f"{r} netvm={netvm_of(app, 'kid')}")
check("the deleted DEFAULT_NETVM constant is really gone",
      not hasattr(load_wrapper(SPAWN), "DEFAULT_NETVM"),
      "a Tor-side gateway must not produce an ai-net-router child")

r, app = run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13",
                     "netvm": TOR}, wired(gateway_netvm=CLEAR))
check("explicit netvm DIFFERING from the inherited one is refused",
      r.get("ok") is not True and "ai-kid" not in app.domains,
      str(r))
check("...and the refusal names no out-of-scope qube",
      "sys-firewall" not in json.dumps(r))

r, app = run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13",
                     "netvm": CLEAR}, wired(gateway_netvm=CLEAR))
check("explicit netvm MATCHING the inherited one is allowed",
      r.get("ok") is True and netvm_of(app, "ai-kid") == CLEAR, str(r))

r, app = run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13",
                     "netvm": None}, wired(gateway_netvm=CLEAR))
check("explicit null is de-escalation and stays allowed",
      r.get("ok") is True and netvm_of(app, "ai-kid") is None, str(r))

r, app = run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13",
                     "netvm": "sys-firewall"}, wired())
check("an out-of-scope netvm still collapses to the opaque cross-ref message",
      r.get("error") == "netvm must reference an ai-managed qube", str(r))

# Row 4: the gateway sits outside the umbrella and no operator file exists.
r, app = run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13"},
             wired(gateway_netvm="sys-firewall"))
check("unresolvable chain REFUSES rather than birthing a network-less qube",
      r.get("ok") is not True and "ai-kid" not in app.domains, str(r))
check("...but an explicit null still succeeds — it never needed the chain",
      run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13", "netvm": None},
          wired(gateway_netvm="sys-firewall"))[0].get("ok") is True)

# F-J: a workload source that is deliberately offline.
r, app = run(CLONE, {"source": "offline-vault", "name": "ai-kid"},
             wired(gateway_netvm=CLEAR))
check("F-J: clone of an OFFLINE source stays offline, not on the gateway path",
      r.get("ok") is True and netvm_of(app, "ai-kid") is None,
      f"{r} netvm={netvm_of(app, 'kid')}")

r, app = run(DISP, {"template": "ai-dvmt"}, wired(gateway_netvm=TOR))
disp = r.get("name")
check("disposable takes the DVMT's egress, pinned explicitly before any start",
      r.get("ok") is True and netvm_of(app, disp) == CLEAR,
      f"{r} netvm={netvm_of(app, disp)}")

r, app = run(DISP, {"template": "ai-dvmt"}, wired(**{"ai-dvmt": None}))
check("F-J: disposable off an OFFLINE DVMT is born offline",
      r.get("ok") is True and netvm_of(app, r.get("name")) is None, str(r))

# --------------------------------------------------------------------------
# 2. Birth tier + ownership (D1/D2)
# --------------------------------------------------------------------------
print("\n=== 2. Birth tier and ownership ===")

for svc, req, who in ((CLONE, {"source": "clear-work", "name": "ai-kid"}, "ai-kid"),
                      (SPAWN, {"name": "ai-kid", "template": "ai-debian-13"},
                       "ai-kid")):
    r, app = run(svc, req, wired())
    tags = set(app.domains[who].tags) if who in app.domains else set()
    check(f"{svc.split('.')[1]}: child born at the source's tier (no ceiling)",
          "ai-full" in tags, str(sorted(tags)))
    check(f"{svc.split('.')[1]}: child carries the owner tag for this principal",
          birth.owner_tag("mcp-control") in tags, str(sorted(tags)))
    check(f"{svc.split('.')[1]}: child carries the umbrella",
          "ai-managed" in tags)

r, app = run(DISP, {"template": "ai-dvmt"}, wired())
dtags = set(app.domains[r["name"]].tags)
check("disposable: born at the DVMT's tier and owned",
      "ai-full" in dtags and any(t.startswith("qmcp-owner") for t in dtags),
      str(sorted(dtags)))

# Restriction inheritance — the F-E laundering hole.
r, app = run(CLONE, {"source": "guarded-work", "name": "ai-kid"}, wired())
ktags = set(app.domains["ai-kid"].tags) if "ai-kid" in app.domains else set()
check("a guarded source produces a guarded child (F-E: no laundering)",
      "qmcp-guarded" in ktags, str(sorted(ktags)))

# A foreign owner tag on the source must not survive onto the child.
vms = wired()
{v.name: v for v in vms}["clear-work"].tags.add(birth.owner_tag("someone-else"))
r, app = run(CLONE, {"source": "clear-work", "name": "ai-kid"}, vms)
ktags = set(app.domains["ai-kid"].tags) if "ai-kid" in app.domains else set()
check("the source's owner tag is replaced, never accumulated",
      birth.owner_tag("someone-else") not in ktags
      and sum(t.startswith("qmcp-owner") for t in ktags) == 1,
      str(sorted(ktags)))

# --------------------------------------------------------------------------
# 3. Rollback — a create we cannot prove must not survive
# --------------------------------------------------------------------------
print("\n=== 3. Rollback on an unprovable create ===")


def break_stamp(mod):
    mod._BIRTH = None          # helper missing => _birth_stamp raises


def break_egress_readback(mod):
    """Accept the netvm write, report something else back."""
    orig = mod._principal
    mod._principal = orig
    if hasattr(mod, "netvm_name"):
        mod.netvm_name = lambda vm: "sys-firewall"
    if hasattr(mod, "netvm_name_direct"):
        mod.netvm_name_direct = lambda app, n: "sys-firewall"


for svc, req, who in ((SPAWN, {"name": "ai-kid", "template": "ai-debian-13"}, "ai-kid"),
                      (CLONE, {"source": "clear-work", "name": "ai-kid"}, "ai-kid")):
    r, app = run(svc, req, wired(), patch=break_stamp)
    check(f"{svc.split('.')[1]}: a failed birth stamp rolls the qube back",
          r.get("ok") is not True and who not in app.domains, str(r))

for svc, req in ((CLONE, {"source": "clear-work", "name": "ai-kid"}),
                 (DISP, {"template": "ai-dvmt"})):
    r, app = run(svc, req, wired(), patch=break_egress_readback)
    check(f"{svc.split('.')[1]}: an egress read-back mismatch rolls it back",
          r.get("ok") is not True
          and not [n for n in app.domains if n.startswith(("ai-kid", "disp"))],
          str(r))

r, app = run(SPAWN, {"name": "ai-kid", "template": "ai-debian-13"}, wired(),
             patch=lambda m: setattr(m, "_CAPS", None))
check("a missing decision kernel REFUSES the create (fail-closed, unlike shadow)",
      r.get("ok") is not True and "ai-kid" not in app.domains, str(r))

# --------------------------------------------------------------------------
print(f"\n{'='*68}\nStage 2 wiring validation: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
