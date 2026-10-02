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
- removing a running qube fails, as qubesd refuses it.

Failures are injected by name through `app.fail`; each injected exception's
message carries SECRET, so a test can assert no raw exception text ever reaches
a reply.
"""
from __future__ import annotations

import re

GiB = 1024 ** 3
SECRET = "SECRET-qubes_dom0/vm-pool-private-lvm"

_TAG_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
# Properties each class has, as `property_list()` reports them.
_BASE_PROPS = ["label", "netvm", "provides_network", "default_dispvm", "memory",
               "maxmem", "vcpus", "kernel", "autostart", "template_for_dispvms",
               "name", "virt_mode", "management_dispvm", "guivm", "audiovm"]


class Injected(Exception):
    pass


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


class FakeTags(set):
    def __init__(self, vm, tags=()):
        super().__init__(tags)
        self._vm = vm

    def add(self, tag):
        self._vm.app._maybe_fail(f"tag.add:{tag}")
        self._vm.app._maybe_fail("tag.add")
        if not _TAG_RE.match(tag):
            raise ValueError("disallowed characters")
        super().add(tag)

    def discard(self, tag):
        self._vm.app._maybe_fail(f"tag.discard:{tag}")
        super().discard(tag)


class FakeFeatures(dict):
    def __init__(self, vm, items=None):
        super().__init__(items or {})
        self._vm = vm

    def __setitem__(self, key, value):
        self._vm.app._maybe_fail("feature.set")
        super().__setitem__(key, value)


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
        props = {"label": FakeLabel(label), "netvm": netvm,
                 "provides_network": provides_network,
                 "default_dispvm": default_dispvm, "memory": memory,
                 "maxmem": maxmem, "vcpus": vcpus, "kernel": "6.x",
                 "autostart": False, "template_for_dispvms": template_for_dispvms,
                 "virt_mode": "pvh", "management_dispvm": None,
                 "guivm": None, "audiovm": None,
                 "visible_gateway": "10.137.0.5", "dns": "10.139.1.1"}
        if klass in ("AppVM", "DispVM"):
            props["template"] = template
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
        return sorted(set(_BASE_PROPS + list(self._props)))

    def __getattr__(self, item):
        props = self.__dict__.get("_props", {})
        if item in props:
            return props[item]
        raise AttributeError(item)

    def __setattr__(self, key, value):
        if key not in self._props:
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
        return self._power

    def is_running(self):
        return self._power in ("Running", "Paused", "Transient")

    def start(self):
        self.app._maybe_fail("start")
        self.__dict__["_power"] = "Running"

    def shutdown(self):
        self.app._maybe_fail("shutdown")
        self.__dict__["_power"] = "Halted"

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
        return getattr(name, "name", name) in self._vms

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
        self.default_netvm = None
        self.default_dispvm = None
        self.default_template = None
        self._disp_counter = 1000
        self.calls: list = []

    def _maybe_fail(self, key):
        if key in self.fail:
            raise Injected(f"{key} failed: {SECRET}")

    def vm(self, name, **kw):
        return self.domains._add(FakeVM(self, name, **kw))

    # -- creates
    def add_new_vm(self, klass, name, label, template=None):
        self._maybe_fail("add_new_vm")
        if name in self.domains._vms:
            raise Injected("QubesValueError: exists")
        tpl = self.domains[template] if isinstance(template, str) else template
        if klass == "DispVM":
            # Upstream DispVM.__init__ copies the template's tags, features and
            # cloneable properties (provides_network included), and takes its
            # network from it.
            return self.domains._add(FakeVM(
                self, name, klass="DispVM", template=tpl, label=label, tags=set(tpl.tags),
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
                    template_for_dispvms=p["template_for_dispvms"],
                    default_dispvm=p["default_dispvm"], label=p["label"].name,
                    private=src.volumes["private"].size, root=src.volumes["root"].size,
                    features=dict(src.features))
        return self.domains._add(vm)

    # -- the raw admin calls the disposable path uses
    def qubesd_call(self, dest, method, arg=None, payload=None):
        self.calls.append((dest, method, arg))
        self._maybe_fail(method)
        if method == "admin.vm.CreateDisposable":
            dvmt = self.domains._vms[dest]
            self._disp_counter += 1
            name = f"disp{self._disp_counter}"
            vm = FakeVM(self, name, klass="DispVM", tags=set(dvmt.tags), template=dvmt,
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
                    tags={"ai-managed", "qmcp-guarded"})
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
