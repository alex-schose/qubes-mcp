"""Offline suite for the dom0 library (dom0/qmcp) against tests/fakequbes.py.

Every security property M1 claims for the services and the operator commands,
with teeth: where a v0.9.16 defect is being closed,
the test first shows the fake can reproduce the dangerous behaviour, then
that the library does not let it through.
"""
from __future__ import annotations

import grp
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, birth, budget, core, fleet, projects, proposals, services  # noqa: E402
import fakequbes  # noqa: E402
from fakequbes import GiB, SECRET, standard_fleet  # noqa: E402

HUB = "mcp-control"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="qmcp-dom0-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self._saved = []
        for mod, attr, value in [
            (core, "HUB_PATH", self.tmp / "hub"),
            (core, "RUN_DIR", self.tmp / "run"),
            (budget, "CAP_PATH", self.tmp / "pool-cap"),
            (budget, "PRIVATE_CAP_PATH", self.tmp / "private-cap"),
            (budget, "LOCK_PATH", self.tmp / "run" / "create.lock"),
            (budget, "LOCK_TIMEOUT_S", 0.5),
            (birth, "NAME_PREFIX_PATH", self.tmp / "name-prefix"),
            (birth, "BIRTH_EGRESS_PATH", self.tmp / "birth-egress"),
            (audit, "LOG_PATH", self.tmp / "audit.log"),
            (fleet, "TIER_DEFAULT_PATH", self.tmp / "tier-default"),
            (fleet, "ENFORCE_MODE_PATH", self.tmp / "enforce-mode"),
            (fleet, "GUARDED_LIST_PATH", self.tmp / "guarded"),
            (services, "DISPOSE_WAIT_S", 0.01),
            (projects, "PROJECTS_PATH", self.tmp / "projects.json"),
            (projects, "LOCK_PATH", self.tmp / "run" / "projects.lock"),
            (proposals, "PROPOSALS_DIR", self.tmp / "proposals"),
            (proposals, "LOCK_PATH", self.tmp / "run" / "proposals.lock"),
            (proposals, "BUS_DIR", self.tmp / "no-session"),
            # The files the fixtures make are this user's group, as tmpfiles makes
            # them the services' group on a real dom0.
            (fleet, "SERVICES_GROUP", grp.getgrgid(os.getegid()).gr_name),
        ]:
            self._saved.append((mod, attr, getattr(mod, attr)))
            setattr(mod, attr, value if isinstance(value, float) else str(value))
        self.addCleanup(self._restore)
        (self.tmp / "run" / "calls").mkdir(parents=True)
        for d in ("run", "run/calls"):              # as tmpfiles makes them, whatever the umask
            os.chmod(self.tmp / d, 0o2770)
        (self.tmp / "proposals").mkdir(mode=0o2770)
        os.chmod(self.tmp / "proposals", 0o2770)
        # As the installer and tmpfiles leave it: present, group-writable.
        (self.tmp / "audit.log").touch(mode=0o660)
        os.chmod(self.tmp / "audit.log", 0o660)
        (self.tmp / "hub").write_text(HUB + "\n")
        (self.tmp / "pool-cap").write_text(str(1000 * GiB) + "\n")
        (self.tmp / "private-cap").write_text(str(20 * GiB) + "\n")
        self.app = standard_fleet()

    def _restore(self):
        for mod, attr, value in reversed(self._saved):
            setattr(mod, attr, value)

    def call(self, service, req=None, caller=HUB, raw=None, app=None):
        out = io.StringIO()
        data = raw if raw is not None else json.dumps(req or {}).encode()
        rc = services.main(service, stdin=io.BytesIO(data),
                           environ={"QREXEC_REMOTE_DOMAIN": caller} if caller else {},
                           app_factory=lambda: app or self.app, out=out)
        reply = json.loads(out.getvalue())
        self.assertEqual(rc, 0 if reply.get("ok") else 1)
        return reply

    def audit_lines(self):
        p = pathlib.Path(audit.LOG_PATH)
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def egress(self, name):
        pathlib.Path(birth.BIRTH_EGRESS_PATH).write_text(name + "\n")

    def tags(self, name):
        self.app.domains.clear_cache()
        return set(self.app.domains[name].tags)


# ======================================================================= funnel

class Funnel(Base):
    def test_caller_must_be_the_hub(self):
        for caller in (None, "", "ai-work", "dom0 ", "personal"):
            r = self.call("qmcp.ListAIManagedQubes", caller=caller)
            self.assertEqual(r, core.NOT_AUTHORIZED, caller)

    def test_no_hub_file_means_no_hub(self):
        (self.tmp / "hub").unlink()
        self.assertEqual(self.call("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)
        (self.tmp / "hub").write_text("not a name!\n")
        self.assertEqual(self.call("qmcp.ListAIManagedQubes"), core.NOT_AUTHORIZED)

    def test_request_cap_before_parse(self):
        big = json.dumps({"name": "ai-work", "pad": "x" * core.MAX_REQUEST_BYTES}).encode()
        r = self.call("qmcp.SetPropertyAIManaged", raw=big)
        self.assertEqual(r["error"], "request too large")
        # Type-confused or oversized input on a state-changing service is audited.
        self.assertEqual(self.audit_lines()[-1]["error"], "request too large")

    def test_invalid_json_is_not_echoed(self):
        r = self.call("qmcp.GetPropertyAIManaged", raw=b'{"name": "SECRET-ish')
        self.assertEqual(r, {"ok": False, "error": "invalid JSON input"})
        r = self.call("qmcp.GetPropertyAIManaged", raw=b'["a list"]')
        self.assertEqual(r["error"], "request must be a JSON object")

    def test_unknown_service(self):
        self.assertEqual(self.call("qmcp.Nope")["error"], "unknown service")

    def test_concurrency_cap(self):
        held = [core.acquire_call_slot(HUB) for _ in range(core.MAX_CONCURRENT_CALLS)]
        try:
            self.assertEqual(self.call("qmcp.ListAIManagedQubes")["error"],
                             "too many concurrent calls")
        finally:
            for fd in held:
                os.close(fd)
        self.assertTrue(self.call("qmcp.ListAIManagedQubes")["ok"])

    def test_runtime_dir_missing_fails_closed(self):
        shutil.rmtree(self.tmp / "run")
        self.assertEqual(self.call("qmcp.ListAIManagedQubes")["error"],
                         "qmcp runtime directory unavailable")

    def test_audit_carries_caller_never_value(self):
        self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 777})
        line = self.audit_lines()[-1]
        self.assertEqual((line["caller"], line["service"], line["v"]), (HUB, "qmcp.SetPropertyAIManaged", 2))
        self.assertEqual(line["args"], {"name": "ai-work", "property": "memory"})
        self.assertNotIn("777", json.dumps(line))
        ok, n, err = audit.verify()
        self.assertTrue(ok, err)

    def test_reads_are_not_audited(self):
        self.call("qmcp.ListAIManagedQubes")
        self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "memory"})
        self.assertEqual(self.audit_lines(), [])

    def test_audit_failure_changes_nothing(self):
        audit.LOG_PATH = str(self.tmp / "no" / "such" / "dir" / "log")
        r = self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work", "property": "memory", "value": 500})
        self.assertEqual(r, {"ok": True})

    def test_internal_error_is_opaque(self):
        self.app.fail.add("property_list")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "memory"})
        self.assertEqual(r, {"ok": False, "error": "read failed"})


# ======================================================================= reads

class Reads(Base):
    def test_list_is_ai_space_only(self):
        r = self.call("qmcp.ListAIManagedQubes")
        names = {q["name"]: q for q in r["qubes"]}
        self.assertEqual(set(names), {"ai-debian-13", "ai-tpl-g", "ai-net-router", "ai-gw-unbadged",
                                      "ai-work", "ai-work2", "ai-on-operator-tpl", "ai-dvm", "ai-dvm-g"})
        self.assertFalse(names["ai-work"]["guarded"])
        self.assertFalse(names["ai-debian-13"]["guarded"])    # a managed template
        self.assertTrue(names["ai-tpl-g"]["guarded"])
        self.assertTrue(names["ai-gw-unbadged"]["guarded"])   # a gateway is guarded, badge or not
        self.assertEqual(names["ai-work"]["template"], "ai-debian-13")
        self.assertEqual(names["ai-on-operator-tpl"]["template"], "<out-of-scope>")
        self.assertNotIn("debian-13", json.dumps(r).replace("ai-debian-13", ""))

    def test_get_property_scope(self):
        self.assertEqual(self.call("qmcp.GetPropertyAIManaged", {"name": "personal", "property": "memory"}),
                         core.NOT_FOUND)
        self.assertEqual(self.call("qmcp.GetPropertyAIManaged", {"name": "no-such", "property": "memory"}),
                         core.NOT_FOUND)
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-tpl-g", "property": "memory"})
        self.assertTrue(r["ok"])                              # guarded qubes are readable
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-net-router", "property": "netvm"})
        self.assertEqual(r["value"], "<out-of-scope>")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "default_dispvm"})
        self.assertEqual(r["value"], "<out-of-scope>")

    def test_tags_read_shows_only_badges(self):
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "tags"})
        self.assertEqual(r["value"], ["ai-managed"])
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-tpl-g", "property": "tags"})
        self.assertEqual(r["value"], ["ai-managed", "qmcp-guarded"])

    def test_only_qubesd_properties_are_read(self):
        for prop in ("app", "qubesd_call", "__class__", "_props", "tags_x", "Memory"):
            r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": prop})
            self.assertFalse(r["ok"], prop)
            self.assertIn("does not exist", r["error"])

    def test_power_state(self):
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "power_state"})
        self.assertEqual(r["value"], "Running")

    def test_pool_stats(self):
        r = self.call("qmcp.GetPoolStats")
        self.assertTrue(r["ok"])
        used = r["ai_managed_bytes_used"]
        # privates of every AI-space qube + roots of the two AI templates
        self.assertEqual(used, 9 * 2 * GiB + 2 * 10 * GiB)
        self.assertEqual(r["ai_managed_bytes_headroom"], 1000 * GiB - used)
        (self.tmp / "pool-cap").unlink()
        self.assertEqual(self.call("qmcp.GetPoolStats")["error"], budget.ERR_CAP_MISSING)


# ======================================================================= writes

class Writes(Base):
    def setp(self, name, prop, value):
        return self.call("qmcp.SetPropertyAIManaged", {"name": name, "property": prop, "value": value})

    def test_operator_only_properties(self):
        # default_dispvm is no longer settable; nor are template/name/provides_network.
        for prop in ("template", "name", "default_dispvm", "provides_network", "autostart",
                     "kernel", "template_for_dispvms", "guivm"):
            self.assertEqual(self.setp("ai-work", prop, "ai-work2")["error"], "property not settable", prop)

    def test_netvm_only_to_null(self):
        self.assertIn("operator-only", self.setp("ai-work", "netvm", "ai-net-router")["error"])
        self.assertEqual(self.setp("ai-work", "netvm", None), {"ok": True})
        self.assertIsNone(self.app.domains["ai-work"].netvm)

    def test_int_means_int(self):
        for bad in (True, 1.5, "512", -1, 0):
            self.assertIn("positive integer", self.setp("ai-work", "memory", bad)["error"], bad)
        self.assertEqual(self.setp("ai-work", "memory", 512), {"ok": True})
        self.assertEqual(self.app.domains["ai-work"].memory, 512)

    def test_label(self):
        self.assertIn("label must be", self.setp("ai-work", "label", "pink")["error"])
        self.assertEqual(self.setp("ai-work", "label", "red"), {"ok": True})

    def test_guarded_and_out_of_scope(self):
        self.assertEqual(self.setp("ai-tpl-g", "memory", 512), core.GUARDED_REFUSAL)
        self.assertEqual(self.setp("ai-gw-unbadged", "memory", 512), core.GUARDED_REFUSAL)
        self.assertEqual(self.setp("personal", "memory", 512), core.NOT_FOUND)
        self.assertEqual(self.setp("no-such-qube", "memory", 512), core.NOT_FOUND)
        # The hub operates the templates it manages.
        self.assertEqual(self.setp("ai-debian-13", "memory", 512), {"ok": True})

    def test_caller_is_never_its_own_object(self):
        # Only on a misconfigured fleet (the hub tagged into AI space).
        self.app.domains["mcp-control"].tags.add("ai-managed")
        self.assertEqual(self.setp("mcp-control", "memory", 512), core.NOT_FOUND)

    def feat(self, key, value="1", name="ai-work"):
        return self.call("qmcp.SetFeatureAIManaged", {"name": name, "feature": key, "value": value})

    def test_feature_allowlist(self):
        # preload-dispvm-max is the case that motivated the allowlist.
        for key in ("preload-dispvm-max", "internal", "guivm", "audiovm", "gui-allow-fullscreen",
                    "qrexec", "service.", "vm-config.", "service.a b", "qmcp-anything",
                    "a-key-qubes-adds-next-year"):
            self.assertEqual(self.feat(key)["error"], "feature not settable", key)
        self.assertEqual(self.feat("service.cups", True), {"ok": True, "feature": "service.cups", "value": "1"})
        self.assertEqual(self.feat("service.cups", False)["value"], "")
        self.assertEqual(self.feat("vm-config.x", 5)["value"], "5")
        self.assertTrue(self.feat("menu-items", "firefox.desktop")["ok"])
        self.assertIn("removal is operator-only", self.feat("service.cups", None)["error"])
        self.assertIn("removal is operator-only", self.feat("service.cups", "x" * 5000)["error"])
        self.assertEqual(self.feat("service.cups", True, name="ai-tpl-g"), core.GUARDED_REFUSAL)

    def life(self, name, action):
        return self.call("qmcp.LifecycleAIManaged", {"name": name, "action": action})

    def test_lifecycle(self):
        self.assertIn("action must be", self.life("ai-work", "destroy")["error"])
        self.assertEqual(self.life("ai-work2", "start"), {"ok": True})
        self.assertEqual(self.life("ai-work2", "pause"), {"ok": True})
        self.assertEqual(self.life("ai-work2", "unpause"), {"ok": True})
        self.assertEqual(self.life("ai-work2", "kill"), {"ok": True})
        self.assertEqual(self.life("ai-tpl-g", "start"), core.GUARDED_REFUSAL)
        self.assertEqual(self.life("personal", "kill"), core.NOT_FOUND)

    def test_remove_is_a_real_remove(self):
        self.assertEqual(self.life("ai-work", "remove")["error"], "action failed")   # running
        self.assertEqual(self.life("ai-work2", "remove"), {"ok": True})
        self.assertNotIn("ai-work2", self.app.domains)


# ======================================================================= creates

class Creates(Base):
    def spawn(self, **req):
        req.setdefault("name", "ai-new")
        req.setdefault("template", "ai-debian-13")
        return self.call("qmcp.SpawnAIManagedQube", req)

    def test_name_outside_namespace_is_refused_before_any_lookup(self):
        # No host lookup at all, so the refusal cannot depend on what exists.
        for svc, req in (("qmcp.SpawnAIManagedQube", {"name": "personal", "template": "ai-debian-13"}),
                         ("qmcp.CloneAIManagedQube", {"name": "vault", "source": "ai-work"})):
            self.app.domains.lookups = 0
            r = self.call(svc, req)
            self.assertIn("reserved for AI-created qubes", r["error"])
            self.assertEqual(self.app.domains.lookups, 0, svc)

    def test_spawn_birth(self):
        self.egress("ai-net-router")
        r = self.spawn()
        self.assertEqual(r, {"ok": True, "name": "ai-new"})
        vm = self.app.domains["ai-new"]
        # The hub's AppVMs join p00, its own slot.
        self.assertEqual(self.tags("ai-new"), {"ai-managed", "qmcp-owner_mcp-control", "qmcp-proj-p00"})
        self.assertEqual(vm.netvm.name, "ai-net-router")
        self.assertIsNone(vm.default_dispvm)     # the add_new_vm default was default-dvm
        # Pinned, not following a default: a qube left on the global default
        # would move when the operator changes it.
        self.assertFalse(vm.property_is_default("netvm"))
        self.assertFalse(vm.property_is_default("default_dispvm"))
        self.assertTrue(self.audit_lines()[-1]["ok"])

    def test_birth_egress_chain(self):
        # Row 4: nothing resolves -> refused, nothing created.
        r = self.spawn()
        self.assertEqual(r["error"], "birth egress could not be resolved")
        self.assertNotIn("ai-new", self.app.domains)
        # Row 2: the hub's own netvm, when it is in AI space.
        self.app.domains["mcp-control"]._props["netvm"] = self.app.domains["ai-net-router"]
        self.assertTrue(self.spawn()["ok"])
        self.assertEqual(self.app.domains["ai-new"].netvm.name, "ai-net-router")

    def test_explicit_netvm(self):
        self.egress("ai-net-router")
        self.assertEqual(self.spawn(name="ai-n1", netvm=None)["ok"], True)
        self.assertIsNone(self.app.domains["ai-n1"].netvm)
        self.assertTrue(self.spawn(name="ai-n2", netvm="ai-net-router")["ok"])
        self.assertEqual(self.spawn(name="ai-n3", netvm="ai-gw-unbadged")["error"],
                         "netvm must match the inherited birth egress")
        r = self.spawn(name="ai-n4", netvm="sys-firewall")
        self.assertEqual(r["error"], "netvm must reference an ai-managed qube")

    def test_template_references(self):
        self.egress("ai-net-router")
        r = self.spawn(template="debian-13")
        self.assertEqual(r["error"], "template must reference an ai-managed qube")
        self.assertTrue(self.spawn(name="ai-from-guarded", template="ai-tpl-g")["ok"])
        self.assertNotIn("qmcp-guarded", self.tags("ai-from-guarded"))
        self.assertIn("must be a TemplateVM", self.spawn(name="ai-x", template="ai-work")["error"])

    def test_dispvm_template_and_dispvm(self):
        self.egress("ai-net-router")
        r = self.spawn(name="ai-mydvm", klass="DispVMTemplate")
        self.assertTrue(r["ok"], r)
        vm = self.app.domains["ai-mydvm"]
        self.assertEqual((vm.klass, vm.template_for_dispvms), ("AppVM", True))
        self.assertEqual(self.tags("ai-mydvm"), {"ai-managed", "qmcp-owner_mcp-control"})
        # A named disposable off a guarded DVMT: the DVMT answers for its network (offline).
        r = self.spawn(name="ai-d1", klass="DispVM", template="ai-dvm-g")
        self.assertTrue(r["ok"], r)
        self.assertIsNone(self.app.domains["ai-d1"].netvm)
        self.assertIn("disposable template", self.spawn(name="ai-d2", klass="DispVM",
                                                         template="ai-debian-13")["error"])

    def test_restrictions_are_inherited(self):
        self.egress("ai-net-router")
        tpl = self.app.domains["ai-debian-13"]
        tpl.tags.add("anon-vm")
        tpl.tags.add("qmcp-egress-locked_ai-net-router")
        self.assertTrue(self.spawn()["ok"])
        self.assertEqual(self.tags("ai-new"), {"ai-managed", "qmcp-owner_mcp-control", "anon-vm",
                                               "qmcp-egress-locked_ai-net-router", "qmcp-proj-p00"})

    def test_private_size(self):
        self.egress("ai-net-router")
        for bad in (True, 1.5, "1", 0, -5):
            self.assertIn("private_size", self.spawn(private_size=bad)["error"], bad)
        self.assertEqual(self.spawn(private_size=21 * GiB)["error"], budget.ERR_PRIVATE_TOO_LARGE)
        self.assertTrue(self.spawn(private_size=8 * GiB)["ok"])
        self.assertEqual(self.app.domains["ai-new"].volumes["private"].size, 8 * GiB)
        self.app.fail.add("resize")
        r = self.spawn(name="ai-big", private_size=8 * GiB)
        self.assertEqual(r, {"ok": True, "name": "ai-big", "warning": "private_resize_failed"})

    def test_pool_cap(self):
        self.egress("ai-net-router")
        (self.tmp / "pool-cap").write_text(str(10 * GiB))
        self.assertEqual(self.spawn()["error"], budget.ERR_CAP_EXCEEDED)
        self.assertNotIn("ai-new", self.app.domains)

    def test_collision_inside_namespace(self):
        self.egress("ai-net-router")
        self.assertEqual(self.spawn(name="ai-work")["error"], "qube 'ai-work' already exists")

    def test_rollback_is_reported_truthfully(self):
        # "rolled back" only when the qube is really gone.
        self.egress("ai-net-router")
        self.app.fail.add("tag.add")
        r = self.spawn()
        self.assertEqual(r["error"], "birth stamp failed (rolled back)")
        self.assertNotIn("ai-new", self.app.domains)
        self.app.fail.add("remove")
        r = self.spawn(name="ai-stuck")
        self.assertEqual(r["error"], "birth stamp failed and rollback failed: "
                                     "qube 'ai-stuck' needs manual cleanup in dom0")
        self.assertIn("ai-stuck", self.app.domains)
        self.app.fail.clear()
        self.app.fail.add("set.netvm")
        self.assertEqual(self.spawn(name="ai-n")["error"], "netvm assignment failed (rolled back)")

    def test_no_exception_text_reaches_the_caller(self):
        # Inject a failure carrying SECRET into every step there is.
        self.egress("ai-net-router")
        steps = ["add_new_vm", "clone_vm", "tag.add", "set.netvm", "set.default_dispvm",
                 "set.template_for_dispvms", "resize", "remove", "feature.set", "set.memory",
                 "start", "kill", "admin.vm.CreateDisposable", "admin.vm.tag.Set",
                 "admin.vm.property.Set", "property_list"]
        replies = []
        for step in steps:
            self.app.fail = {step}
            replies += [
                self.spawn(name="ai-s1", private_size=4 * GiB, klass="DispVMTemplate"),
                self.call("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-c1"}),
                self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"}),
                self.call("qmcp.SetFeatureAIManaged", {"name": "ai-work2", "feature": "service.x", "value": 1}),
                self.call("qmcp.SetPropertyAIManaged", {"name": "ai-work2", "property": "memory", "value": 9}),
                self.call("qmcp.LifecycleAIManaged", {"name": "ai-work2", "action": "start"}),
                self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work2", "property": "memory"}),
            ]
            self.app = standard_fleet()
        self.assertTrue(replies)
        for r in replies:
            self.assertNotIn(SECRET, json.dumps(r))
            self.assertNotIn("Injected", json.dumps(r))

    # -------------------------------------------------------------- clone

    def test_fake_clone_copies_tags(self):
        # Teeth: the platform behaviour the strip exists for must be reproduced.
        src = self.app.domains["ai-work"]
        copy = self.app.clone_vm(src, "ai-raw")
        self.assertIn("qmcp-owner_mcp-control", copy.tags)
        self.assertIn("operator-note", copy.tags)

    def clone(self, source="ai-work", name="ai-clone"):
        return self.call("qmcp.CloneAIManagedQube", {"source": source, "name": name})

    def test_clone_strips_and_restamps(self):
        src = self.app.domains["ai-work"]
        for t in ("ai-full", "qmcp-owner_someone-else", "qmcp-guarded-not-really",
                  "qmcp-egress-locked_ai-net-router"):
            src.tags.add(t)
        src.tags.discard("qmcp-owner_mcp-control")
        r = self.clone()
        self.assertEqual(r, {"ok": True, "name": "ai-clone"})
        self.assertEqual(self.tags("ai-clone"), {"ai-managed", "qmcp-owner_mcp-control", "qmcp-proj-p00",
                                                 "qmcp-egress-locked_ai-net-router", "operator-note"})
        vm = self.app.domains["ai-clone"]
        self.assertEqual(vm.netvm.name, "ai-net-router")   # the source answers for itself
        self.assertIsNone(vm.default_dispvm)

    def test_clone_needs_a_managed_source(self):
        self.assertEqual(self.clone(source="ai-tpl-g"), core.GUARDED_REFUSAL)    # 2.11
        self.assertEqual(self.clone(source="ai-dvm-g"), core.GUARDED_REFUSAL)
        self.assertEqual(self.clone(source="personal"), core.NOT_FOUND)
        self.assertEqual(self.clone(source="ai-gw-unbadged"), core.GUARDED_REFUSAL)

    def test_clone_a_managed_template(self):
        # The hub builds templates; a cloned template stays off the network.
        r = self.clone(source="ai-debian-13", name="ai-tpl-dev")
        self.assertTrue(r["ok"], r)
        vm = self.app.domains["ai-tpl-dev"]
        self.assertEqual(vm.klass, "TemplateVM")
        self.assertIsNone(vm.netvm)
        self.assertEqual(core.state(vm), "managed")

    def test_clone_from_a_source_on_an_outside_network(self):
        self.app.domains["ai-work2"]._props["netvm"] = self.app.domains["sys-firewall"]
        self.assertEqual(self.clone(source="ai-work2")["error"], "birth egress could not be resolved")

    # -------------------------------------------------------------- disposables

    def test_fake_disposable_inherits_template_tags(self):
        name = self.app.qubesd_call("ai-dvm-g", "admin.vm.CreateDisposable").decode()
        self.assertIn("qmcp-guarded", self.app.domains._hidden[name].tags)

    def test_spawn_disposable(self):
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm-g"})
        self.assertTrue(r["ok"], r)
        name = r["name"]
        self.assertEqual(self.tags(name), {"ai-managed", "qmcp-owner_mcp-control"})
        vm = self.app.domains[name]
        self.assertIsNone(vm.netvm)
        self.assertIsNone(vm.default_dispvm)
        self.assertEqual(core.state(vm), "managed")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.app.domains.clear_cache()
        self.assertEqual(self.app.domains[r["name"]].netvm.name, "ai-net-router")

    def test_spawn_disposable_refusals(self):
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "default-dvm"})
        self.assertEqual(r["error"], "template must reference an ai-managed qube")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-work"})
        self.assertIn("must be a disposable template", r["error"])

    def test_disposable_rollback(self):
        self.app.fail.add("tag.add")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertEqual(r["error"], "birth stamp failed (rolled back)")
        self.assertEqual(self.app.domains._hidden, {})
        self.app.fail.add("admin.vm.Remove")
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
        self.assertIn("rollback failed", r["error"])


# ======================================================================= events

class FakeDispatcher:
    def __init__(self, app, script):
        self.app, self.script, self.handlers = app, script, []

    def add_handler(self, event, handler):
        self.handlers.append(handler)

    async def listen_for_events(self, reconnect=False):
        for subject, event, kwargs in self.script:
            if callable(subject):
                subject()
                continue
            subj = self.app.domains._vms.get(subject, subject)
            for h in self.handlers:
                h(subj, event, **kwargs)


class Events(Base):
    def run_events(self, script, **req):
        saved = services._dispatcher
        services._dispatcher = lambda app: FakeDispatcher(app, script)
        try:
            req.setdefault("duration", 1)
            return self.call("qmcp.AIManagedEvents", req)
        finally:
            services._dispatcher = saved

    def test_input_bounds(self):
        self.assertIn("duration", self.run_events([], duration=True)["error"])
        r = self.run_events([], events=["e"] * (services.EVENTS_MAX_FILTERS + 1))
        self.assertIn("at most", r["error"])
        r = self.run_events([], events=["x" * (services.EVENTS_MAX_FILTER_LEN + 1)])
        self.assertIn("at most", r["error"])
        self.assertEqual(self.run_events([], qube="personal"), core.NOT_FOUND)

    def test_scope_and_tag_redaction(self):
        def delete_ai_work2():
            self.app.domains._drop("ai-work2")
        script = [
            ("ai-work", "domain-start", {}),
            ("personal", "domain-start", {}),
            ("ai-work", "domain-tag-add:operator-secret", {}),
            ("ai-work", "domain-tag-add:qmcp-guarded", {}),
            ("ai-work", "domain-tag-add:ai-full", {}),
            (delete_ai_work2, None, None),
            ("ai-work2", "domain-shutdown", {}),
            ("ai-work2", "domain-tag-delete:ai-managed", {}),
        ]
        r = self.run_events(script)
        got = [(e["event"], e["subject"], e.get("tag")) for e in r["events"]]
        self.assertEqual(got, [("domain-start", "ai-work", None),
                               ("domain-tag-add", "ai-work", "qmcp-guarded"),
                               ("domain-shutdown", "ai-work2", None),
                               ("domain-tag-delete", "ai-work2", "ai-managed")])
        self.assertNotIn("operator-secret", json.dumps(r))
        self.assertNotIn("ai-full", json.dumps(r))

    def test_filters(self):
        script = [("ai-work", "property-set:netvm", {}), ("ai-work", "domain-start", {}),
                  ("ai-work2", "domain-start", {})]
        r = self.run_events(script, events=["property-set"])
        self.assertEqual([e["event"] for e in r["events"]], ["property-set:netvm"])
        r = self.run_events(script, qube="ai-work2")
        self.assertEqual([e["subject"] for e in r["events"]], ["ai-work2"])


# ======================================================================= fleet

class Fleet(Base):
    def test_check_reports_a_fresh_v0916_fleet(self):
        self.app.domains["ai-work"].tags.add("ai-full")
        self.app.domains["ai-sink"].tags.add("ai-managed")
        findings = {f.check: f for f in fleet.check(self.app, policy_dir=str(self.tmp / "pol"),
                                                    lib_dir=str(self.tmp / "lib"),
                                                    rpc_dir=str(self.tmp / "rpc"), legacy_paths=(),
                                                    system_info={"domains": {}})}
        self.assertEqual(findings["hub"].status, "pass")
        self.assertEqual(findings["tier tags"].status, "fail")
        self.assertEqual(findings["gateways guarded"].status, "fail")
        self.assertIn("ai-gw-unbadged", findings["gateways guarded"].detail)
        self.assertEqual(findings["drop boxes"].status, "fail")
        self.assertEqual(findings["name namespace"].status, "warn")
        self.assertIn("ai-operator-squat", findings["name namespace"].detail)
        self.assertEqual(findings["default_dispvm"].status, "warn")
        self.assertEqual(findings["services"].status, "fail")
        self.assertEqual(fleet.overall(list(findings.values())), "FAILED")

    def test_overall_has_three_answers(self):
        F = fleet.Finding
        self.assertEqual(fleet.overall([]), "INCOMPLETE")
        self.assertEqual(fleet.overall([F("pass", "a"), F("warn", "b")]), "GREEN")
        self.assertEqual(fleet.overall([F("pass", "a"), F("error", "b")]), "INCOMPLETE")
        self.assertEqual(fleet.overall([F("fail", "a"), F("error", "b")]), "FAILED")

    def test_hub_in_ai_space_fails_the_check(self):
        self.app.domains["mcp-control"].tags.add("ai-managed")
        f = {x.check: x for x in fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["hub"].status, "fail")

    def tiered_fleet(self):
        a = self.app
        a.domains["ai-work"].tags.add("ai-full")
        a.domains["ai-work2"].tags.add("ai-exec")
        a.domains["ai-dvm"].tags.add("ai-net")
        a.domains["ai-net-router"].tags.discard("qmcp-guarded")
        a.domains["ai-net-router"].tags.add("ai-full")
        return a

    def test_migration_plan_on_a_flipped_fleet(self):
        app = self.tiered_fleet()
        steps, problems = fleet.plan_migration(app, {}, tier_default="ro")
        self.assertEqual(sorted(p.split(":")[0] for p in problems), ["ai-dvm", "ai-work2"])
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed"}, exec_default="guarded",
                                               tier_default="ro")
        self.assertEqual(problems, [])
        plan = {s.qube: s for s in steps}
        self.assertEqual(plan["ai-work"].remove, {"ai-full"})
        self.assertTrue(plan["ai-work"].pin_dispvm)
        self.assertEqual(plan["ai-work2"].remove, {"ai-exec"})
        self.assertEqual(plan["ai-dvm"].add, {"qmcp-guarded"})
        self.assertEqual(plan["ai-net-router"].add, {"qmcp-guarded"})   # a gateway, whatever it was
        self.assertEqual(plan["ai-on-operator-tpl"].add, {"qmcp-guarded"})  # the read floor
        results = fleet.apply_migration(app, steps)
        self.assertTrue(all(r.startswith("done") for r in results), results)
        self.assertFalse(any(core.tags_of(vm) & birth.LEGACY_TIER_TAGS for vm in app.domains))
        self.assertIsNone(app.domains["ai-work"].default_dispvm)

    def test_migration_is_idempotent(self):
        # Without retiring tier-default, a second run would read every managed
        # (umbrella-only) qube as the old read floor and guard it.
        app = self.tiered_fleet()
        (self.tmp / "tier-default").write_text("ro\n")
        steps, problems = fleet.plan_migration(app, {}, exec_default="managed")
        self.assertEqual(problems, [])
        fleet.apply_migration(app, steps)
        self.assertEqual(fleet.finish_migration(), [str(self.tmp / "tier-default")])
        managed_before = {vm.name for vm in app.domains if core.state(vm) == "managed"}
        steps, problems = fleet.plan_migration(app, {})
        self.assertEqual((problems, [s for s in steps if s.add or s.remove]), ([], []))
        self.assertIn("ai-work", managed_before)
        self.assertEqual(managed_before, {vm.name for vm in app.domains if core.state(vm) == "managed"})

    def test_migration_on_a_never_flipped_fleet_asks(self):
        app = self.tiered_fleet()
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed", "ai-dvm": "managed"},
                                               tier_default=None)
        self.assertIn("ai-on-operator-tpl", " ".join(problems))
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed", "ai-dvm": "managed"},
                                               compat_default="managed", tier_default=None)
        self.assertEqual(problems, [])

    def test_migration_keeps_the_v0916_guarded_list(self):
        # v0.9.16 always refused the qubes named in /etc/qmcp/guarded. Dropping
        # the list on upgrade would make an ai-full qube on it managed.
        app = self.tiered_fleet()
        (self.tmp / "guarded").write_text("# wallets\nai-work\nno-such-qube  # gone\n")
        steps, problems = fleet.plan_migration(app, {"ai-work2": "managed", "ai-dvm": "managed"},
                                               tier_default="ro")
        self.assertEqual(problems, [])
        plan = {s.qube: s for s in steps}
        self.assertEqual((plan["ai-work"].add, plan["ai-work"].remove), ({"qmcp-guarded"}, {"ai-full"}))
        steps, _ = fleet.plan_migration(app, {"ai-work": "managed", "ai-work2": "managed",
                                              "ai-dvm": "managed"}, tier_default="ro")
        self.assertEqual({s.qube: s for s in steps}["ai-work"].add, set())   # an explicit choice wins
        self.assertIn("/etc/qmcp/guarded", fleet.LEGACY_PATHS)   # check and install treat it as a leftover
        fleet.apply_migration(app, [s for s in steps if s.qube != "ai-work"])
        self.assertIn(str(self.tmp / "guarded"), fleet.finish_migration())
        self.assertFalse((self.tmp / "guarded").exists())

    @unittest.skipIf(os.geteuid() == 0, "root reads a file whatever its mode")
    def test_an_unreadable_guarded_list_blocks_the_migration(self):
        (self.tmp / "guarded").write_text("ai-work\n")
        os.chmod(self.tmp / "guarded", 0o000)
        try:
            _, problems = fleet.plan_migration(self.tiered_fleet(), {}, tier_default="ro")
        finally:
            os.chmod(self.tmp / "guarded", 0o644)
        self.assertTrue(any(fleet.GUARDED_LIST_PATH in p for p in problems), problems)

    def test_migration_refuses_a_hub_or_a_hybrid_in_ai_space(self):
        self.app.domains["mcp-control"].tags.add("ai-managed")
        self.app.domains["ai-sink"].tags.add("ai-managed")
        _, problems = fleet.plan_migration(self.app, {}, tier_default="ro")
        self.assertEqual(sorted(p.split(":")[0] for p in problems), ["ai-sink", "mcp-control"])

    def test_role_actions(self):
        with self.assertRaises(fleet.RoleError):
            fleet.manage(self.app, "ai-net-router")      # gateways are always guarded
        with self.assertRaises(fleet.RoleError):
            fleet.manage(self.app, "mcp-control")        # the hub is never in AI space
        with self.assertRaises(fleet.RoleError):
            fleet.guard(self.app, "ai-sink")             # a drop box is never in AI space
        fleet.guard(self.app, "personal")
        self.assertEqual(core.state(self.app.domains["personal"]), "guarded")
        fleet.manage(self.app, "personal")
        self.assertEqual(core.state(self.app.domains["personal"]), "managed")
        self.assertIsNone(self.app.domains["personal"].default_dispvm)
        msg = fleet.revoke(self.app, "ai-work")
        vm = self.app.domains["ai-work"]
        self.assertEqual(core.tags_of(vm), {"operator-note"})
        self.assertIsNone(vm.default_dispvm)
        self.assertEqual(vm.get_power_state(), "Halted")
        self.assertIn("shutdown requested", msg)


# ======================================================================= audit findings

class AuditFindings(Base):
    """Regression tests from the pre-release review of M1 (2026-10-01). Each would fail on the
    code as it stood before the fix."""

    def spawn(self, **req):
        req.setdefault("name", "ai-new")
        req.setdefault("template", "ai-debian-13")
        return self.call("qmcp.SpawnAIManagedQube", req)

    def trace(self, service, req):
        self.app.calls.clear()
        self.app.domains.lookups = 0
        r = self.call(service, req)
        return r, [c[1] for c in self.app.calls], self.app.domains.lookups

    def test_missing_and_outside_names_cost_the_same(self):
        # one qubesd call either way, and no domain-list shortcut.
        cases = [
            ("qmcp.GetPropertyAIManaged", lambda n: {"name": n, "property": "memory"}),
            ("qmcp.SetPropertyAIManaged", lambda n: {"name": n, "property": "memory", "value": 5}),
            ("qmcp.SetFeatureAIManaged", lambda n: {"name": n, "feature": "service.x", "value": 1}),
            ("qmcp.LifecycleAIManaged", lambda n: {"name": n, "action": "start"}),
            ("qmcp.CloneAIManagedQube", lambda n: {"source": n, "name": "ai-oracle"}),
            ("qmcp.SpawnDisposableAIManaged", lambda n: {"template": n}),
            ("qmcp.SpawnAIManagedQube", lambda n: {"name": "ai-oracle", "template": n}),
            ("qmcp.AIManagedEvents", lambda n: {"duration": 1, "qube": n}),
        ]
        for svc, make in cases:
            missing = self.trace(svc, make("no-such-qube"))
            outside = self.trace(svc, make("personal"))
            self.assertEqual(missing, outside, svc)
            self.assertEqual(missing[1], ["admin.vm.tag.Get"], svc)
            self.assertEqual(missing[2], 0, svc)

    def test_explicit_netvm_is_checked_by_name(self):
        self.egress("ai-net-router")
        a = self.trace("qmcp.SpawnAIManagedQube", {"name": "ai-x1", "template": "ai-debian-13",
                                                   "netvm": "no-such-qube"})
        b = self.trace("qmcp.SpawnAIManagedQube", {"name": "ai-x1", "template": "ai-debian-13",
                                                   "netvm": "sys-firewall"})
        self.assertEqual(a[0], b[0])
        self.assertEqual(a[1].count("admin.vm.tag.Get"), b[1].count("admin.vm.tag.Get"))

    def test_a_name_taken_during_the_lock_wait_is_refused(self):
        # the name is re-checked under the create lock.
        self.egress("ai-net-router")
        real = budget.acquire_create_lock

        def slow_lock(*a, **kw):
            self.app.vm("ai-new", tags={"operator-made"})    # someone else, meanwhile
            return real(*a, **kw)
        budget.acquire_create_lock = slow_lock
        try:
            r = self.spawn()
        finally:
            budget.acquire_create_lock = real
        self.assertEqual(r["error"], "qube 'ai-new' already exists")
        self.assertIn("operator-made", self.tags("ai-new"))

    def test_a_failed_create_never_removes_someone_elses_qube(self):
        # a create call that raised is never "rolled back" by name.
        self.egress("ai-net-router")

        def racing_add(klass, name, label, template=None):
            self.app.vm(name, tags={"operator-made"})
            raise fakequbes.Injected(f"exists {SECRET}")
        self.app.add_new_vm = racing_add
        r = self.spawn()
        self.assertEqual(r["error"], "create failed; a qube named 'ai-new' exists and was left alone")
        self.assertIn("operator-made", self.tags("ai-new"))

    def test_a_template_netvm_never_decides(self):
        # a TemplateVM base does not answer for a child's network.
        self.egress("ai-net-router")
        self.app.domains["ai-debian-13"]._props["netvm"] = self.app.domains["ai-gw-unbadged"]
        self.assertTrue(self.spawn()["ok"])
        self.assertEqual(self.app.domains["ai-new"].netvm.name, "ai-net-router")

    def test_nothing_is_spawned_from_a_gateway(self):
        # the child would provide network with its guard stripped.
        router = self.app.domains["ai-net-router"]
        self.app.vm("ai-gw-dvm", template_for_dispvms=True, provides_network=True,
                    netvm=router, tags={"ai-managed", "qmcp-guarded"})
        r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-gw-dvm"})
        self.assertEqual(r["error"], "a disposable template that provides network cannot be spawned from")
        r = self.spawn(name="ai-gwd", klass="DispVM", template="ai-gw-dvm")
        self.assertEqual(r["error"], "a template that provides network cannot be spawned from")
        self.assertEqual(self.app.domains._hidden, {})
        self.assertNotIn("ai-gwd", self.app.domains)

    def test_a_child_that_provides_network_is_rolled_back(self):
        # Second line of defence: if the pre-check is ever bypassed.
        router = self.app.domains["ai-net-router"]
        self.app.vm("ai-gw-dvm", template_for_dispvms=True, provides_network=True,
                    netvm=router, tags={"ai-managed", "qmcp-guarded"})
        saved = services._not_a_gateway
        services._not_a_gateway = lambda vm, what: None
        try:
            r = self.call("qmcp.SpawnDisposableAIManaged", {"template": "ai-gw-dvm"})
        finally:
            services._not_a_gateway = saved
        self.assertEqual(r["error"], "network check failed (rolled back)")
        self.assertEqual(self.app.domains._hidden, {})

    def test_a_label_is_not_a_qube(self):
        # an operator qube named like a colour.
        self.app.vm("black")
        self.app.domains["ai-work"]._props["label"] = fakequbes.FakeLabel("black")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "label"})
        self.assertEqual(r["value"], "black")

    def test_an_unreadable_volume_refuses_creates_and_stats(self):
        # never budget against a guess.
        self.egress("ai-net-router")

        class Broken:
            def __getitem__(self, key):
                raise fakequbes.Injected("volume read failed")
        self.app.domains["ai-work2"].__dict__["volumes"] = Broken()
        self.assertEqual(self.spawn()["error"], budget.ERR_STATS_UNAVAILABLE)
        self.assertEqual(self.audit_lines()[-1].get("error_class"), "Injected")
        self.assertEqual(self.call("qmcp.GetPoolStats")["error"], budget.ERR_STATS_UNAVAILABLE)

    def test_an_unreadable_clone_source_is_refused_and_logged(self):
        class Broken:
            def __getitem__(self, key):
                raise fakequbes.Injected(f"volume read failed: {SECRET}")
        self.app.domains["ai-work2"].__dict__["volumes"] = Broken()
        r = self.call("qmcp.CloneAIManagedQube", {"source": "ai-work2", "name": "ai-copy"})
        self.assertEqual(r["error"], budget.ERR_STATS_UNAVAILABLE)
        self.assertEqual(self.audit_lines()[-1].get("error_class"), "Injected")

    def test_a_name_that_cannot_be_checked_is_refused_and_logged(self):
        self.egress("ai-net-router")

        def broken():
            raise fakequbes.Injected(f"lookup failed: {SECRET}")
        self.app.domains.clear_cache = broken
        r = self.spawn()
        self.assertEqual(r, {"ok": False, "error": "could not check the name"})
        self.assertEqual(self.audit_lines()[-1].get("error_class"), "Injected")

    def test_pins_hold_even_when_the_value_equals_the_default(self):
        # the global default already IS the birth network; still pin it.
        self.egress("ai-net-router")
        self.app.default_netvm = self.app.domains["ai-net-router"]
        self.assertTrue(self.spawn()["ok"])
        self.assertFalse(self.app.domains["ai-new"].property_is_default("netvm"))

    def test_netvm_addresses_follow_the_netvm(self):
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-net-router", "property": "visible_gateway"})
        self.assertEqual(r["value"], "<out-of-scope>")
        r = self.call("qmcp.GetPropertyAIManaged", {"name": "ai-work", "property": "visible_gateway"})
        self.assertEqual(r["value"], "10.137.0.5")

    def test_audit_rotation_keeps_the_chain(self):
        for i in range(3):
            audit.audit("svc", HUB, {"i": i}, True)
        aside = audit.rotate()
        audit.audit("svc", HUB, {"i": 3}, True)
        self.assertEqual(audit.verify(), (True, 2, None))
        self.assertEqual(audit.verify(aside), (True, 3, None))
        anchor = json.loads(pathlib.Path(audit.LOG_PATH).read_text().splitlines()[0])
        old_head = json.loads(pathlib.Path(aside).read_text().splitlines()[-1])
        self.assertEqual(anchor["prev"], old_head["hash"])

    def test_audit_appends_read_only_the_tail(self):
        # a log far longer than the tail window still chains.
        n = 3000
        for i in range(n):
            audit.audit("svc", HUB, {"i": i, "pad": "x" * 100}, True)
        self.assertGreater(pathlib.Path(audit.LOG_PATH).stat().st_size, audit.TAIL_BYTES * 4)
        self.assertEqual(audit.verify(), (True, n, None))


class PolicyFacts(Base):
    """qmcp check's policy facts: the hub the policy names, and precedence."""

    def test_check_catches_a_policy_naming_another_hub(self):
        # the installer once rendered `mcp-control` over a custom hub.
        pol, share = self.tmp / "pol", self.tmp / "lib" / "share"
        pol.mkdir(); share.mkdir(parents=True)
        text = "*  *  other-hub  @anyvm  deny\n"
        for d in (pol, share):
            (d / fleet.POLICY_NAME).write_text(text)
        f = {x.check: x for x in fleet.check(self.app, policy_dir=str(pol), lib_dir=str(self.tmp / "lib"),
                                             legacy_paths=(), system_info={"domains": {}})}
        self.assertEqual(f["policy hub"].status, "fail")
        self.assertIn("other-hub", f["policy hub"].detail)

    def _policy(self, extra=None):
        import logging
        from qrexec.policy.parser import FilePolicy
        logging.disable(logging.WARNING)
        d = self.tmp / "policy.d"
        shutil.copytree(HERE / "data" / "upstream-policy-4.3", d, dirs_exist_ok=True)
        shutil.copy(HERE.parent / "policy" / fleet.POLICY_NAME, d / fleet.POLICY_NAME)
        for name, text in (extra or {}).items():
            (d / name).write_text(text)
        try:
            return FilePolicy(policy_path=d)
        finally:
            logging.disable(logging.NOTSET)

    def test_precedence_is_clean_on_upstream_defaults(self):
        self.assertEqual(fleet.precedence(self._policy(), {"domains": {}}, HUB), [])

    def test_precedence_catches_an_earlier_file(self):
        # parsing passes, precedence does not.
        policy = self._policy({"20-operator.policy":
                               "qubes.VMExec * @anyvm @anyvm allow\n"
                               "admin.vm.tag.Set * @anyvm @anyvm allow target=dom0\n"})
        problems = fleet.precedence(policy, {"domains": {}}, HUB)
        self.assertTrue(any("20-operator.policy" in p and "qubes.VMExec" not in p for p in problems))
        self.assertTrue(any("Admin API on a qube" in p for p in problems), problems)

    def _check_with(self, extra_name, extra_text, mode=None):
        pol, share = self.tmp / "pol", self.tmp / "lib" / "share"
        pol.mkdir(); share.mkdir(parents=True)
        text = (HERE.parent / "policy" / fleet.POLICY_NAME).read_text()
        for d in (pol, share):
            (d / fleet.POLICY_NAME).write_text(text)
        (pol / extra_name).write_text(extra_text)
        if mode is not None:
            os.chmod(pol / extra_name, mode)
        try:
            return {x.check: x for x in fleet.check(self.app, policy_dir=str(pol),
                                                    lib_dir=str(self.tmp / "lib"), legacy_paths=(),
                                                    system_info={"domains": {}})}
        finally:
            os.chmod(pol / extra_name, 0o644)

    @unittest.skipIf(os.geteuid() == 0, "root reads a file whatever its mode")
    def test_an_unreadable_policy_file_is_incomplete_not_failed(self):
        # Measured on the dev box: a root-only 0600 file made check, run as the
        # dom0 user, report FAILED "parser refuses ... AccessDenied" for a policy
        # set that was fine. Mode 000 makes the file unreadable to its owner too.
        f = self._check_with("20-operator.policy", "qubes.OpenURL * @anyvm @anyvm deny\n", 0o000)
        self.assertEqual(f["policy parses"].status, "error")
        self.assertIn("run qmcp check as root", f["policy parses"].detail)

    def test_a_malformed_policy_file_still_fails(self):
        f = self._check_with("20-operator.policy", "qubes.OpenURL * @anyvm\n")
        self.assertEqual(f["policy parses"].status, "fail")


if __name__ == "__main__":
    unittest.main()
