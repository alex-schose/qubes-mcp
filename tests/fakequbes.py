"""A fake qubesadmin for the dom0 library's offline suite.

It models the platform behaviour the library's security depends on, not just
return values: in 0.9.x a mock whose clone returned a clean qube kept a
self-escalation bug green through a whole stage. So:

- `clone_vm` copies the source's tags (all but `created-by-*`), properties,
  features and volume sizes;
- `admin.vm.CreateDisposable` copies the disposable template's tags and
  network, and the new qube stays invisible to `app.domains` until
  `clear_cache()` (qubesadmin's cache lags CreateDisposable by seconds);
- `add_new_vm` puts the new qube on the system default netvm and default
  disposable template, as qvm-create does;
- tag names are validated as qubesd validates them (no `:` or `.`);
- removing a running qube fails, as qubesd refuses it;
- features answer `check_with_template` through the template chain, as
  qubesadmin does (a template's `qubes-firewall` reaches the qubes built on it);
  a feature read (`features[key]`, `.get`, `in`) is `admin.vm.feature.Get` and
  can fail (`feature.get`, or `feature.get:<qube>`), as in qubesadmin, where only
  a missing feature is a KeyError;
- every qube has a `uuid`, read like any property, which qubesd never lets a
  client set; a clone gets a NEW one and keeps the source's features, as a
  `qvm-clone` and a backup restore do (measured 2026-10-10 on Qubes 4.3.1);
- a qube's firewall is a list of rule lines behind `admin.vm.firewall.Get` and
  `Set`; a new qube's is `action=accept`, and qubesd's own spelling is modelled
  where qmcp reads it back (`dstports=443` reads back as `dstports=443-443`);
- `vm.tags` is no set: iterating it is `admin.vm.tag.List` and `in` is
  `admin.vm.tag.Get`, each a read that can fail, as in qubesadmin;
- the network and disposable properties follow Qubes 4.3's classes: dom0 and
  a RemoteVM have no network properties, a RemoteVM no `default_dispvm`, and
  only an AppVM or a StandaloneVM has `template_for_dispvms` (measured on the
  dev box for dom0, a TemplateVM and an AppVM; the rest read from Qubes'
  source). A missing one raises AttributeError, as qubesadmin's
  QubesNoSuchPropertyError does. `template` is there only for an AppVM and a
  DispVM; the other properties modelled here are not trimmed per class;
- a removed qube's tag read raises a KeyError, as qubesadmin's
  QubesVMNotFoundError does; its property reads fail with the property-access
  error, and its power state reads `NA`, as qubesadmin's do; its class, which
  qubesadmin caches from the domain list, still reads;

Failures are injected by name through `app.fail`, every read under that key,
or `app.fail_reads(key, "ok fail")`, some reads in order. A tag read's keys are
`tag.List`, `tag.Get` and either with `:<qube>`; `lookup:<qube>` fails `name in
app.domains`. Each injected exception's
message carries SECRET, so a test can assert no raw exception text ever reaches
a reply.
"""
from __future__ import annotations

import collections
import re
import uuid as _uuid

GiB = 1024 ** 3
SECRET = "SECRET-qubes_dom0/vm-pool-private-lvm"

_TAG_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
#: A name qubesd accepts for a new qube (its validate_name): a letter first.
_NAME_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9_.-]{0,30}\Z")
# Properties each class has, as `property_list()` reports them.
_BASE_PROPS = ["label", "netvm", "provides_network", "default_dispvm", "memory",
               "maxmem", "vcpus", "kernel", "autostart", "template_for_dispvms",
               "name", "virt_mode", "management_dispvm", "guivm", "audiovm"]
#: What a class lacks in Qubes 4.3: dom0 has no network, and only an AppVM or a
#: StandaloneVM can be a disposable template. (`template` is added only for the
#: classes that have one.)
_CLASS_LACKS = {
    "AdminVM": {"netvm", "provides_network", "template_for_dispvms", "visible_gateway", "dns"},
    "RemoteVM": {"netvm", "provides_network", "template_for_dispvms", "default_dispvm",
                 "visible_gateway", "dns"},
    "TemplateVM": {"template_for_dispvms"},
    "DispVM": {"template_for_dispvms"},
}


class Injected(Exception):
    pass


class InjectedNotFound(Injected, KeyError):
    """A read of a qube qubesd no longer has, as qubesadmin raises it: its
    QubesVMNotFoundError is a KeyError."""


class InjectedPropertyAccess(Injected, AttributeError):
    """A property read that fails, as qubesadmin raises it: its
    QubesPropertyAccessError is an AttributeError too, so `getattr` with a
    default swallows it."""


class FakeLabel:
    def __init__(self, name):
        self.name = name


class FakeVolume:
    def __init__(self, vm, name, size):
        self._vm, self._name, self.size = vm, name, size

    def resize(self, size):
        self._vm.app._maybe_fail("resize")
        if size > self.size:
            self.size = size


class FakeTags:
    """vm.tags as qubesadmin has it: iterating is `admin.vm.tag.List` and `in`
    is `admin.vm.tag.Get`, each a qubesd call that can fail. Not a set subclass,
    so `set(vm.tags)` iterates, as it must against qubesd (CPython copies a set
    subclass without calling its `__iter__`)."""

    def __init__(self, vm, tags=()):
        self._vm, self._tags = vm, set(tags)

    def _read(self, method):
        app, name = self._vm.app, self._vm.__dict__["name"]
        if app.domains._any(name) is not self._vm:
            raise InjectedNotFound(f"QubesVMNotFoundError {name}")
        app._maybe_fail(method)
        app._maybe_fail(f"{method}:{name}")

    def raw(self) -> set:
        """The tags as they are, for the fake itself and a test's assertions:
        no qubesd read, so nothing injected fails it."""
        return set(self._tags)

    def __iter__(self):
        self._read("tag.List")
        return iter(sorted(self._tags))

    def __contains__(self, tag):
        self._read("tag.Get")
        return tag in self._tags

    def add(self, tag):
        self._vm.app._maybe_fail(f"tag.add:{tag}")
        self._vm.app._maybe_fail("tag.add")
        if not _TAG_RE.match(tag):
            raise ValueError("disallowed characters")
        self._tags.add(tag)
        # qubesd sets the tag, then saves and fires its event: either can
        # fail after the tag is set, so a write can land and still raise.
        self._vm.app._maybe_fail(f"tag.add.landed:{tag}")

    def discard(self, tag):
        self._vm.app._maybe_fail(f"tag.discard:{tag}")
        self._tags.discard(tag)

    def update(self, tags):
        for tag in tags:
            self.add(tag)

    def clear(self):
        self._tags.clear()


class FakeFeatures(dict):
    def __init__(self, vm, items=None):
        super().__init__(items or {})
        self._vm = vm

    def _read(self):
        app = self._vm.app
        app._maybe_fail("feature.get")
        app._maybe_fail(f"feature.get:{self._vm.__dict__['name']}")

    def __getitem__(self, key):
        self._read()
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        self._read()
        return dict.__contains__(self, key)

    def __setitem__(self, key, value):
        self._vm.app._maybe_fail("feature.set")
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self._vm.app._maybe_fail("feature.remove")
        super().__delitem__(key)

    def check_with_template(self, key, default=None):
        self._vm.app._maybe_fail("feature.check")
        vm = self._vm
        for _ in range(8):
            if key in vm.features:
                return dict.__getitem__(vm.features, key)
            vm = vm._props.get("template")
            if vm is None:
                break
        return default


#: qubesd's own order for a rule's options, as Qubes 4.3.1 states them back
#: (measured 2026-10-04): the action, the destination, proto, ports, ICMP type.
_QUBESD_ORDER = ("action", "dsthost", "dst4", "dst6", "proto", "dstports", "icmptype",
                 "specialtarget", "expire")
_IPV4 = re.compile(r"\A[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?\Z")


def _qubesd_rule(line: str) -> str:
    """A rule as qubesd states it back (measured on Qubes 4.3.1): in qubesd's
    own order, whatever order it was written in; a single port as a range; an
    IPv4 `dsthost` as `dst4` with its prefix length. A comment, which may hold
    spaces, comes last and is kept as it is."""
    line, sep, comment = line.partition("comment=")
    opts = {}
    for option in line.strip().split(" "):
        key, _, value = option.partition("=")
        if key == "dstports" and "-" not in value:
            value = f"{value}-{value}"
        if key == "dsthost" and _IPV4.match(value):
            key, value = "dst4", value if "/" in value else f"{value}/32"
        opts[key] = value
    order = [k for k in _QUBESD_ORDER if k in opts] + [k for k in opts if k not in _QUBESD_ORDER]
    return " ".join(f"{k}={opts[k]}" for k in order) + (f" comment={comment}" if sep else "")


class FakeVM:
    _INTERNAL = {"app", "name", "klass", "tags", "features", "volumes", "_props", "_power"}

    def __init__(self, app, name, klass="AppVM", tags=(), template=None, netvm=None,
                 provides_network=False, template_for_dispvms=False,
                 default_dispvm=None, label="gray", private=2 * GiB, root=10 * GiB,
                 power="Halted", features=None, memory=400, maxmem=4000, vcpus=2,
                 auto_cleanup=False):
        d = self.__dict__
        d["app"], d["name"], d["klass"] = app, name, klass
        d["tags"] = FakeTags(self, tags)
        d["features"] = FakeFeatures(self, features)
        d["volumes"] = {"private": FakeVolume(self, "private", private),
                        "root": FakeVolume(self, "root", root)}
        d["_power"] = power
        d["auto_cleanup"] = auto_cleanup
        d["_firewall"] = ["action=accept"]
        props = {"label": FakeLabel(label), "netvm": netvm,
                 "provides_network": provides_network,
                 "default_dispvm": default_dispvm, "memory": memory,
                 "maxmem": maxmem, "vcpus": vcpus, "kernel": "6.x",
                 "autostart": False, "template_for_dispvms": template_for_dispvms,
                 "virt_mode": "pvh", "management_dispvm": None,
                 "guivm": None, "audiovm": None,
                 "visible_gateway": "10.137.0.5", "dns": "10.139.1.1",
                 "uuid": str(_uuid.uuid4())}
        if klass in ("AppVM", "DispVM"):
            props["template"] = template
        for p in _CLASS_LACKS.get(klass, ()):
            props.pop(p, None)
        d["_props"] = props
        # Properties still following a default, as qubesd tracks them: a
        # qube created without an explicit netvm or default_dispvm follows the
        # global default and would move with it.
        d["_defaults"] = {"netvm", "default_dispvm"}

    # -- properties, the way qubesadmin exposes them
    def property_is_default(self, item):
        return item in self.__dict__["_defaults"]
    def property_list(self):
        self.app._maybe_fail("property_list")
        return sorted((set(_BASE_PROPS) | set(self._props)) - _CLASS_LACKS.get(self.klass, set()))

    def __getattr__(self, item):
        props = self.__dict__.get("_props", {})
        if item in props:
            app = self.__dict__["app"]
            if app.domains._any(self.__dict__["name"]) is not self:
                # Removed: qubesadmin turns qubesd's not-found into its
                # property-access error, as for any failed read.
                raise InjectedPropertyAccess(f"get.{item}: {self.__dict__['name']} is gone")
            app._maybe_fail(f"get.{item}")
            app._maybe_fail(f"get.{item}:{self.__dict__['name']}")
            return props[item]
        raise AttributeError(item)

    def __setattr__(self, key, value):
        if key not in self._props or key == "uuid":
            raise AttributeError(f"no such property {key}")
        self.app._maybe_fail(f"set.{key}")
        if key == "label":
            value = FakeLabel(value) if isinstance(value, str) else value
        if key in ("netvm", "default_dispvm", "template") and isinstance(value, str):
            value = self.app.domains[value]
        self._props[key] = value
        self.__dict__["_defaults"].discard(key)

    # -- lifecycle
    def get_power_state(self):
        # qubesadmin answers "NA", never an exception, for a qube it cannot read.
        if self.app.domains._any(self.__dict__["name"]) is not self:
            return "NA"
        return self._power

    def is_running(self):
        return self._power in ("Running", "Paused", "Transient")

    def start(self):
        self.app._maybe_fail("start")
        self.__dict__["_power"] = "Running"

    def shutdown(self, force=False, wait=False):
        self.app._maybe_fail("shutdown")
        self.__dict__["_power"] = "Halted"

    def run_service(self, service, user=None, autostart=True, **kw):
        """qubesadmin's run_service, for `qubes.VMShell` as root: the process it
        returns runs the script it is given, which may write files under
        /etc/qubes-rpc (read back with `rpc_files`). `app.vmshell[name]` makes
        one hang ("timeout") or fail ("exit1"). Without autostart a halted qube
        refuses, as qubesadmin's QubesVMNotRunningError does."""
        name = self.__dict__["name"]
        self.app._maybe_fail("run_service")
        self.app._maybe_fail(f"run_service:{name}")
        if not self.is_running():
            if not autostart:
                raise Injected("QubesVMNotRunningError")
            self.__dict__["_power"] = "Running"
        self.app.calls.append((name, "run_service", service, user))
        return FakeProc(self, self.app.vmshell.get(name, "ok"))

    def rpc_files(self) -> dict:
        return dict(self.__dict__.setdefault("_rpc", {}))

    def kill(self):
        self.app._maybe_fail("kill")
        if not self.is_running():
            raise Injected("QubesVMNotStartedError")
        self.__dict__["_power"] = "Halted"
        if self.__dict__.get("auto_cleanup"):
            self.app.domains._drop(self.name)

    def pause(self):
        self.__dict__["_power"] = "Paused"

    def unpause(self):
        self.__dict__["_power"] = "Running"


class FakeProc:
    """The process `run_service` returns. It reads the qmcp prepare script's
    `# qmcp file NAME` blocks and writes each file into the qube."""

    def __init__(self, vm, mode):
        self.vm, self.mode, self.returncode, self.killed = vm, mode, None, False

    def communicate(self, input=None, timeout=None):
        import base64
        import subprocess
        if self.mode == "timeout" and not self.killed:
            raise subprocess.TimeoutExpired("qrexec-client", timeout)
        if self.mode == "timeout":
            self.returncode = -9
            return None, None
        if input and self.mode == "ok":
            lines = input.decode("ascii").split("\n")
            files = self.vm.__dict__.setdefault("_rpc", {})
            i = 0
            while i < len(lines):
                if lines[i].startswith("# qmcp file "):
                    name = lines[i][len("# qmcp file "):]
                    start = next(j for j in range(i, len(lines)) if lines[j].endswith("<<'QMCP_B64_END'"))
                    end = lines.index("QMCP_B64_END", start + 1)
                    files[name] = base64.b64decode("".join(lines[start + 1:end]))
                    i = end
                i += 1
        self.returncode = 0 if self.mode == "ok" else 1
        return None, None

    def kill(self):
        self.killed = True


class FakeDomains:
    def __init__(self, app):
        self.app = app
        self._vms: dict = {}
        self._hidden: dict = {}
        self.lookups = 0

    def _add(self, vm, hidden=False):
        (self._hidden if hidden else self._vms)[vm.name] = vm
        return vm

    def _drop(self, name):
        self._vms.pop(name, None)
        self._hidden.pop(name, None)

    def _any(self, name):
        return self._vms.get(name) or self._hidden.get(name)

    def __iter__(self):
        return iter(list(self._vms.values()))

    def values(self):
        return list(self._vms.values())

    def __contains__(self, name):
        self.lookups += 1
        key = getattr(name, "name", name)
        self.app._maybe_fail(f"lookup:{key}")      # the domain list could not be read
        return key in self._vms

    def __getitem__(self, name):
        self.lookups += 1
        return self._vms[getattr(name, "name", name)]

    def __delitem__(self, name):
        self.app._maybe_fail("remove")
        vm = self._vms[name]
        if vm.is_running():
            raise Injected("QubesVMNotHaltedError")
        self._drop(name)

    def clear_cache(self):
        self._vms.update(self._hidden)
        self._hidden.clear()


class FakeApp:
    def __init__(self):
        self.domains = FakeDomains(self)
        self.fail: set = set()
        self.fail_plan: dict = {}
        #: Every key `_maybe_fail` was asked about, counted: a test that fails a
        #: key no call reads proves nothing, and can check that it was read.
        self.reads = collections.Counter()
        #: The failures it raised, by key: a position past the reads a call makes
        #: injects nothing, and a test that needs a failure can check one fired.
        self.failed = collections.Counter()
        self.default_netvm = None
        self.default_dispvm = None
        self.default_template = None
        self._disp_counter = 1000
        self.calls: list = []
        #: `run_service` per qube: "ok" (the default), "timeout" or "exit1".
        self.vmshell: dict = {}

    def fail_reads(self, key, pattern: str):
        """Fail some of the reads under `key`, in order: "ok fail" lets the
        first through and fails the second; reads after the pattern succeed."""
        self.fail_plan[key] = collections.deque(w == "fail" for w in pattern.split())

    def _maybe_fail(self, key):
        self.reads[key] += 1
        plan = self.fail_plan.get(key)
        planned = plan.popleft() if plan else False
        if key in self.fail or planned:
            self.failed[key] += 1
            if key.startswith("get."):
                raise InjectedPropertyAccess(f"{key} failed: {SECRET}")
            raise Injected(f"{key} failed: {SECRET}")

    def vm(self, name, labelled=True, **kw):
        """A qube as a test fleet has it. `labelled` (the default) gives it the
        `qmcp-id` label dom0 writes on every qube it brings into AI space or
        badges, set to its own UUID, unless `features` already names one: a
        fixture stands for a fleet qmcp built. A test of the restore check
        passes `labelled=False`, or a label naming another UUID."""
        vm = self.domains._add(FakeVM(self, name, **kw))
        if labelled and "qmcp-id" not in dict.keys(vm.features):
            dict.__setitem__(vm.features, "qmcp-id", vm._props["uuid"])
        return vm

    # -- creates
    def add_new_vm(self, klass, name, label, template=None):
        self._maybe_fail("add_new_vm")
        if not _NAME_RE.match(name):
            raise Injected("QubesValueError: invalid name")
        if name in self.domains._vms:
            raise Injected("QubesValueError: exists")
        tpl = self.domains[template] if isinstance(template, str) else template
        if klass == "DispVM":
            # Upstream DispVM.__init__ copies the template's tags, features and
            # cloneable properties (provides_network included), and takes its
            # network from it.
            return self.domains._add(FakeVM(
                self, name, klass="DispVM", template=tpl, label=label, tags=tpl.tags.raw(),
                features=dict(tpl.features), netvm=tpl._props["netvm"],
                provides_network=tpl._props["provides_network"],
                default_dispvm=tpl._props["default_dispvm"],
                private=tpl.volumes["private"].size))
        return self.domains._add(FakeVM(self, name, klass=klass, template=tpl, label=label,
                                        netvm=self.default_netvm,
                                        default_dispvm=self.default_dispvm))

    def clone_vm(self, src, new_name):
        self._maybe_fail("clone_vm")
        p = src._props
        vm = FakeVM(self, new_name, klass=src.klass,
                    tags=[t for t in src.tags if not t.startswith("created-by-")],
                    template=p.get("template"), netvm=p["netvm"],
                    provides_network=p["provides_network"],
                    template_for_dispvms=p.get("template_for_dispvms", False),
                    default_dispvm=p["default_dispvm"], label=p["label"].name,
                    private=src.volumes["private"].size, root=src.volumes["root"].size,
                    features=dict(src.features))
        # qubesadmin's clone_vm copies the firewall too.
        vm.__dict__["_firewall"] = list(src.__dict__["_firewall"])
        return self.domains._add(vm)

    # -- the raw admin calls the disposable path uses
    def qubesd_call(self, dest, method, arg=None, payload=None):
        self.calls.append((dest, method, arg))
        self._maybe_fail(method)
        if method == "admin.vm.CreateDisposable":
            dvmt = self.domains._vms[dest]
            self._disp_counter += 1
            name = f"disp{self._disp_counter}"
            vm = FakeVM(self, name, klass="DispVM", tags=dvmt.tags.raw(), template=dvmt,
                        netvm=dvmt._props["netvm"],
                        provides_network=dvmt._props["provides_network"],
                        features=dict(dvmt.features),
                        default_dispvm=dvmt._props["default_dispvm"],
                        private=dvmt.volumes["private"].size, auto_cleanup=True)
            self.domains._add(vm, hidden=True)
            return name.encode()
        if method == "admin.vm.List":
            names = list(self.domains._vms) + list(self.domains._hidden)
            return "\n".join(f"{n} class=AppVM state=Halted" for n in names).encode()
        vm = self.domains._any(dest)
        if vm is None:
            raise Injected("QubesVMNotFoundError")
        if method == "admin.vm.tag.Get":
            return b"1" if arg in vm.tags else b"0"
        if method == "admin.vm.tag.List":
            return "\n".join(sorted(vm.tags)).encode()
        if method == "admin.vm.tag.Set":
            vm.tags.add(arg)
            return b""
        if method == "admin.vm.tag.Remove":
            vm.tags.discard(arg)
            return b""
        if method == "admin.vm.property.Get":
            value = vm._props.get(arg)
            text = "" if value is None else getattr(value, "name", str(value))
            dflt = arg in vm.__dict__["_defaults"]
            return f"default={dflt} type=vm {text}".encode()
        if method == "admin.vm.property.Set":
            text = (payload or b"").decode()
            vm._props[arg] = None if text == "" else self.domains._any(text)
            vm.__dict__["_defaults"].discard(arg)
            return b""
        if method == "admin.vm.feature.Get":
            vm.features._read()
            if not dict.__contains__(vm.features, arg):
                raise Injected("QubesFeatureNotFoundError")
            return str(dict.__getitem__(vm.features, arg)).encode()
        if method == "admin.vm.feature.Set":
            vm.features[arg] = (payload or b"").decode()
            return b""
        if method == "admin.vm.firewall.Get":
            return "".join(f"{r}\n" for r in vm.__dict__["_firewall"]).encode()
        if method == "admin.vm.firewall.Set":
            lines = [l for l in (payload or b"").decode("ascii").splitlines() if l]
            vm.__dict__["_firewall"] = [_qubesd_rule(l) for l in lines]
            return b""
        if method == "admin.vm.Kill":
            vm.kill()
            return b""
        if method == "admin.vm.Remove":
            if vm.is_running():
                raise Injected("QubesVMNotHaltedError")
            self.domains._drop(dest)
            return b""
        raise Injected(f"unexpected call {method}")


def standard_fleet() -> FakeApp:
    """The fleet most tests start from. Names describe roles."""
    app = FakeApp()
    app.vm("dom0", klass="AdminVM")
    fw = app.vm("sys-firewall", provides_network=True)
    app.default_netvm = fw
    app.vm("mcp-control", netvm=fw)
    app.vm("personal", netvm=fw)
    ddvm = app.vm("default-dvm", template_for_dispvms=True, netvm=fw)
    app.default_dispvm = ddvm
    app.default_template = app.vm("debian-13", klass="TemplateVM")
    app.vm("ai-debian-13", klass="TemplateVM", tags={"ai-managed"})
    app.vm("ai-tpl-g", klass="TemplateVM", tags={"ai-managed", "qmcp-guarded"})
    router = app.vm("ai-net-router", provides_network=True, netvm=fw,
                    tags={"ai-managed", "qmcp-guarded"}, features={"qubes-firewall": "1"})
    app.vm("ai-gw-unbadged", provides_network=True, netvm=fw, tags={"ai-managed"})
    app.vm("ai-work", template=app.domains["ai-debian-13"], netvm=router,
           tags={"ai-managed", "qmcp-owner_mcp-control", "operator-note"},
           default_dispvm=ddvm, power="Running")
    app.vm("ai-work2", template=app.domains["ai-debian-13"], netvm=None, tags={"ai-managed"})
    app.vm("ai-on-operator-tpl", template=app.domains["debian-13"], netvm=router,
           tags={"ai-managed"})
    app.vm("ai-dvm", template=app.domains["ai-debian-13"], template_for_dispvms=True,
           netvm=router, tags={"ai-managed"})
    app.vm("ai-dvm-g", template=app.domains["ai-debian-13"], template_for_dispvms=True,
           netvm=None, tags={"ai-managed", "qmcp-guarded"})
    app.vm("ai-sink", tags={"ai-dump"})
    app.vm("ai-operator-squat", netvm=fw)
    return app
