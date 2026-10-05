"""Offline suite for proposals (M2c): the hub asks, the operator accepts.

It runs the dom0 library against tests/fakequbes.py, as test_projects.py does,
with the store in a temporary directory. The guarantees, each with a test that
fails when it breaks:

- **Only the hub proposes,** and only the operator decides: a lead, a worker
  or any other qube is refused by the services (the policy refuses them first;
  tests/test_policy.py), and accepting or rejecting is a root command in dom0.
- **Submitting checks the shape and looks nothing up:** a template the hub
  cannot see is stored, never refused by name.
- **What the operator read is what runs:** accept refuses a stored file whose
  fingerprint differs from the one shown, even when the changed file is a
  valid proposal.
- **The hub learns a state word only:** no report, no reason.
- **The second tick** is computed from the fleet and required by accept.
- **An edit is applied to the record as it is at accept,** changing only the
  entries it names: the operator's later change to anything else stands.
- **A proposal whose command may have run is never pending again:** a decision
  file that does not parse, and an accept that started and never finished,
  both read as failed.
- **Every change the operator makes is on the audit chain,** as caller
  "operator", with its names and options, a quota only as "set"; reads and
  plans leave nothing.
"""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import pathlib
import stat
import sys
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "dom0"))
sys.path.insert(0, str(HERE))

from qmcp import audit, budget, cli, core, fleet, projects, proposals, services  # noqa: E402
from fakequbes import GiB  # noqa: E402
from test_dom0 import HUB  # noqa: E402
from test_projects import LEAD, ProjectBase  # noqa: E402

DAY = 24 * 3600
#: The installed paths, read before any test points the modules at a temp dir.
REAL = {"store": proposals.PROPOSALS_DIR, "lock": proposals.LOCK_PATH, "log": audit.LOG_PATH}


def create(**over):
    req = {"type": "project-create", "title": "a scraping project", "label": "scrape",
           "lead": {"from": "template", "qube": "ai-debian-13"},
           "networks": ["ai-net-router"], "quota": 5 * GiB}
    req.update(over)
    return req


class PBase(ProjectBase):
    def submit(self, req=None, caller=HUB):
        return self.call("qmcp.SubmitProposal", create() if req is None else req, caller=caller)

    def status(self, req=None, caller=HUB):
        return self.call("qmcp.ProposalStatus", req or {}, caller=caller)

    def store(self):
        return pathlib.Path(proposals.PROPOSALS_DIR)

    def cli(self, *argv, root=True):
        saved = cli._app, os.geteuid
        cli._app = lambda: self.app
        if root:
            os.geteuid = lambda: 0
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    rc = cli.main(list(argv))
                except SystemExit as e:
                    rc = e.code
        finally:
            cli._app, os.geteuid = saved
        return rc, out.getvalue(), err.getvalue()

    def accept(self, pid, sha=None, yes=False):
        doc = proposals.show(self.app, pid)
        return proposals.accept(self.app, pid, sha or doc["sha256"], tick=doc["tick"] if yes else None)

    def operator_lines(self):
        return [line for line in self.audit_lines() if line["caller"] == "operator"]


# ======================================================================= the shape

class Shape(unittest.TestCase):
    def test_every_type_normalises_to_a_fixed_point_with_every_key(self):
        # (always, only when given): a field added in 0.9.21 joins the normal
        # form only when given, so a proposal 0.9.20 stored reads back as itself.
        keys = {
            "project-create": ({"label", "lead", "lead_netvm", "lead_name", "templates", "networks",
                                "quota", "dump"}, {"model"}),
            "project-edit": ({"project", "add_templates", "remove_templates", "add_networks",
                              "remove_networks", "default_network", "quota"}, set()),
            "project-dump": ({"project", "name"}, set()),
            "project-lead": ({"project", "remove", "lead", "lead_netvm", "lead_name", "keep_old"},
                             {"model", "add_old_network"}),
            "project-firewall": ({"project"}, {"model", "rules"}),
            "project-delete": ({"project"}, set()),
        }
        samples = [
            create(), create(lead={"from": "promote", "qube": "ai-work2"}, lead_netvm="none",
                             templates=["ai-dvm"], networks=["ai-net-router", "none"], dump=True),
            create(lead_name="ai-scrape-boss", lead_netvm="ai-net-router"),
            {"type": "project-edit", "title": "t", "project": "osint", "add_networks": ["none"],
             "default_network": "none", "quota": 30 * GiB},
            {"type": "project-edit", "title": "t", "project": "osint", "remove_templates": ["ai-dvm"]},
            {"type": "project-dump", "title": "t", "project": "p00"},
            {"type": "project-dump", "title": "t", "project": "osint", "name": "osint-sink"},
            {"type": "project-lead", "title": "t", "project": "osint", "remove": True},
            {"type": "project-lead", "title": "t", "project": "osint", "keep_old": False,
             "lead": {"from": "clone", "qube": "ai-work2"}, "lead_name": "ai-osint-lead2"},
            {"type": "project-delete", "title": "t", "project": "other"},
            create(lead_netvm="ai-net-router", model="api.anthropic.com:443"),
            {"type": "project-lead", "title": "t", "project": "osint", "keep_old": True,
             "add_old_network": True, "model": "api.anthropic.com:443",
             "lead": {"from": "template", "qube": "ai-debian-13"}, "lead_name": "ai-osint-lead2"},
            {"type": "project-firewall", "title": "t", "project": "osint", "model": "h.example:8443"},
            {"type": "project-firewall", "title": "t", "project": "osint",
             "rules": ["action=accept proto=tcp dsthost=h.example dstports=443", "action=drop"]},
        ]
        self.assertEqual({s["type"] for s in samples}, set(proposals.TYPES))
        for req in samples:
            p = proposals.normalise(req, "ai-")
            always, optional = keys[p["type"]]
            self.assertTrue(always | {"type", "title"} <= set(p) <= always | optional | {"type", "title"},
                            (req, set(p)))
            self.assertEqual({k for k in optional if k in req and req[k] not in (None, False)},
                             set(p) & optional, req)
            self.assertEqual(proposals.normalise(p), p, req)
            self.assertEqual(proposals.normalise(p, "ai-"), p, req)

    def test_refusals_name_the_field_and_nothing_else(self):
        bad = [
            ([], "a proposal is a JSON object"),
            ({"type": "qube-remove", "title": "t"}, "type"),
            (create(title=""), "title"),
            (create(title="x" * 101), "title"),
            (create(title="   "), "title"),
            (create(title="line\nbreak"), "title"),
            (create(title="bidi \u202e override"), "title"),
            (create(title="zero\u200bwidth"), "title"),
            (create(title="caf\u00e9"), "title"),
            (create(title=7), "title"),
            (create(extra=1), "unknown field"),
            ({k: v for k, v in create().items() if k != "quota"}, "quota: missing"),
            (create(label="Scrape"), "label"),
            (create(label="toolonglabel"), "label"),
            (create(label="p03"), "label"),
            (create(label="none"), "label"),
            (create(lead={"from": "template"}), "lead"),
            (create(lead={"from": "build", "qube": "x"}), "lead.from"),
            (create(lead={"from": "template", "qube": "none"}), "lead.qube"),
            (create(lead={"from": "template", "qube": "a b"}), "lead.qube"),
            (create(lead={"from": "promote", "qube": "ai-work2"}, lead_name="ai-scrape-x"), "lead_name"),
            (create(lead_name="ai-other-x"), "lead_name"),
            (create(networks=[]), "networks"),
            (create(networks=["ai-net-router", "ai-net-router"]), "networks"),
            (create(networks=["x"] * 9), "networks"),
            (create(networks="ai-net-router"), "networks"),
            (create(templates=["t%d" % i for i in range(16)]), "templates"),
            (create(quota=True), "quota"),
            (create(quota=0), "quota"),
            (create(quota=-1), "quota"),
            (create(quota=1.5), "quota"),
            (create(quota="40G"), "quota"),
            (create(dump=1), "dump"),
            ({"type": "project-edit", "title": "t", "project": "osint"}, "must change something"),
            ({"type": "project-edit", "title": "t", "project": "osint", "add_templates": ["a"],
              "remove_templates": ["a"]}, "both added and removed"),
            ({"type": "project-edit", "title": "t", "project": "osint", "remove_networks": ["none"],
              "default_network": "none"}, "default_network"),
            ({"type": "project-edit", "title": "t", "project": "p00", "quota": 1}, "project"),
            ({"type": "project-dump", "title": "t", "project": "osint", "name": "ai-sink2"}, "name"),
            ({"type": "project-lead", "title": "t", "project": "osint", "remove": True,
              "keep_old": True}, "remove"),
            ({"type": "project-lead", "title": "t", "project": "osint", "remove": "yes"}, "remove"),
            ({"type": "project-lead", "title": "t", "project": "osint"}, "lead"),
            # What happens to the old lead is said, never defaulted.
            ({"type": "project-lead", "title": "t", "project": "osint",
              "lead": {"from": "template", "qube": "ai-debian-13"}}, "keep_old"),
            ({"type": "project-lead", "title": "t", "project": "osint", "keep_old": 1,
              "lead": {"from": "template", "qube": "ai-debian-13"}}, "keep_old"),
            ({"type": "project-delete", "title": "t", "project": "p00"}, "project"),
            ({"type": "project-delete", "title": "t", "project": "p16"}, "project"),
            # Never by slot: by accept, a slot can hold another project.
            ({"type": "project-delete", "title": "t", "project": "p03"}, "project"),
            ({"type": "project-lead", "title": "t", "project": "p01", "remove": True}, "project"),
            ({"type": "project-dump", "title": "t", "project": "p02"}, "project"),
            (create(quota=2 ** 60 + 1), "quota"),
        ]
        for req, word in bad:
            with self.assertRaises(proposals.Invalid, msg=req) as ctx:
                proposals.normalise(req, "ai-")
            self.assertIn(word, str(ctx.exception), req)

    def test_a_default_sink_name_inside_the_prefix_is_refused_at_submit(self):
        # A label such as "ai" makes the default sink "ai-dump", inside "ai-":
        # the command refuses it at accept, so the submit refuses it, and says why.
        for req in (create(label="ai", dump=True),
                    {"type": "project-dump", "title": "t", "project": "ai"}):
            with self.assertRaises(proposals.Invalid, msg=req) as ctx:
                proposals.normalise(req, "ai-")
            self.assertIn("ai-dump", str(ctx.exception))
        # Without a sink, with a name, under another prefix or read back from a
        # stored file (no prefix), nothing is refused.
        proposals.normalise(create(label="ai", dump=False), "ai-")
        proposals.normalise({"type": "project-dump", "title": "t", "project": "ai",
                             "name": "box-ai"}, "ai-")
        proposals.normalise(create(label="ai", dump=True), "x-")
        proposals.normalise(create(label="ai", dump=True), None)
        proposals.normalise({"type": "project-dump", "title": "t", "project": "p00"}, "ai-")

    def test_null_in_a_network_list_is_none(self):
        # The records and the hub's pool stats write no network as null; in a
        # list it can mean nothing else, so it is stored as "none". A single
        # network field keeps null for "not given".
        p = proposals.normalise(create(networks=[None, "ai-net-router"]), "ai-")
        self.assertEqual(p["networks"], ["none", "ai-net-router"])
        e = proposals.normalise({"type": "project-edit", "title": "t", "project": "osint",
                                 "add_networks": [None], "remove_networks": ["ai-net-router"]}, "ai-")
        self.assertEqual((e["add_networks"], e["default_network"]), (["none"], None))
        with self.assertRaisesRegex(proposals.Invalid, "listed twice"):
            proposals.normalise(create(networks=[None, "none"]), "ai-")
        self.assertIsNone(proposals.normalise(create(lead_netvm=None), "ai-")["lead_netvm"])

    def test_an_unknown_field_is_shown_clipped(self):
        with self.assertRaises(proposals.Invalid) as ctx:
            proposals.normalise(create(**{"k" * 500: 1}), "ai-")
        self.assertLess(len(str(ctx.exception)), 80)

    def test_the_equivalent_command(self):
        p = proposals.normalise(create(templates=["ai-dvm"], networks=["ai-net-router", "none"],
                                       lead_netvm="ai-net-router", dump=True), "ai-")
        self.assertEqual(proposals.command(p),
                         "qmcp project create scrape --lead-template ai-debian-13 --lead-netvm "
                         "ai-net-router --template ai-dvm --network ai-net-router --network none "
                         "--quota 5G --dump")
        lead = proposals.normalise({"type": "project-lead", "title": "t", "project": "osint",
                                    "lead": {"from": "clone", "qube": "ai-work2"},
                                    "keep_old": True}, "ai-")
        self.assertEqual(proposals.command(lead),
                         "qmcp project lead osint --lead-clone ai-work2 --keep-old")
        edit = proposals.normalise({"type": "project-edit", "title": "t", "project": "osint",
                                    "quota": 1}, "ai-")
        self.assertIsNone(proposals.command(edit))


# ======================================================================= the services

class Services(PBase):
    def test_the_hub_submits_and_reads_state_words_only(self):
        r = self.submit()
        self.assertEqual((r["ok"], r["id"], r["state"]), (True, 1, "pending"))
        data = (self.store() / "000001.json").read_bytes()
        self.assertEqual(r["sha256"], hashlib.sha256(data).hexdigest())
        rows = self.status()["proposals"]
        self.assertEqual([(x["id"], x["state"]) for x in rows], [(1, "pending")])
        self.assertEqual(set(rows[0]), {"id", "state", "type", "title", "submitted", "expires",
                                        "sha256"})
        one = self.status({"id": 1})
        self.assertEqual(one["proposal"], proposals.normalise(create(), "ai-"))
        self.assertNotIn("decision", one)
        self.assertEqual(self.status({"id": 9}), {"ok": False, "error": "no such proposal"})
        for bad in (0, -1, True, "1", 1.0):
            self.assertFalse(self.status({"id": bad})["ok"], bad)

    def test_the_hub_sees_only_its_own_proposals(self):
        # Only the hub submits, but a record another caller left (a store kept
        # across a change of hub, say) must never be shown to this one.
        proposals.submit(proposals.normalise(create(label="theirs"), "ai-"), "other-hub")
        self.submit()
        self.assertEqual([p["id"] for p in self.status()["proposals"]], [2])
        self.assertEqual(self.status({"id": 1}), {"ok": False, "error": "no such proposal"})
        self.assertEqual(len(proposals.listing()), 2)              # the operator sees both

    def test_nobody_but_the_hub(self):
        for caller in (LEAD, "ai-osint-w1", "ai-hubq", "ai-work", "personal", "osint-dump"):
            for service in ("qmcp.SubmitProposal", "qmcp.ProposalStatus"):
                r = self.call(service, create(), caller=caller)
                self.assertFalse(r["ok"], (caller, service))
                if caller == LEAD:
                    self.assertEqual(r["error"], services.HUB_ONLY)
                else:
                    self.assertEqual(r, core.NOT_AUTHORIZED, caller)
        self.assertEqual(list(self.store().iterdir()), [])

    def test_submit_looks_no_name_up(self):
        # A template the hub cannot see, and one that does not exist: both are
        # stored, and the host is never consulted, so the reply says nothing
        # about names outside AI space.
        class NoHost:
            def __getattr__(self, name):
                raise AssertionError(f"a submit looked at the host: {name}")
        for i, tpl in enumerate(("debian-13", "no-such-template")):
            r = self.call("qmcp.SubmitProposal",
                          create(label=f"p{i}x", lead={"from": "template", "qube": tpl}),
                          app=NoHost())
            self.assertTrue(r["ok"], tpl)

    def test_a_refusal_is_audited_without_the_title(self):
        self.submit(create(title="SECRET-TITLE-TEXT", quota=True))
        self.submit(create(title="SECRET-TITLE-TEXT"))
        lines = [line for line in self.audit_lines() if line["service"] == "qmcp.SubmitProposal"]
        self.assertEqual([line["ok"] for line in lines], [False, True])
        self.assertIn("quota", lines[0]["error"])
        self.assertEqual(set(lines[1]["args"]), {"type", "subject", "id", "sha256"})
        self.assertNotIn("SECRET-TITLE-TEXT", json.dumps(self.audit_lines()))

    def test_ten_pending_at_most(self):
        for i in range(proposals.MAX_PENDING):
            self.assertTrue(self.submit(create(label=f"l{i}"))["ok"])
        r = self.submit(create(label="eleven"))
        self.assertEqual(r["error"], f"too many pending proposals (at most {proposals.MAX_PENDING})")
        proposals.reject(1)
        self.assertTrue(self.submit(create(label="eleven"))["ok"])

    def test_expired_and_decided_do_not_count(self):
        old = time.time() - 8 * DAY
        for i in range(proposals.MAX_PENDING):
            proposals.submit(proposals.normalise(create(label=f"o{i}"), "ai-"), HUB, now=old)
        self.assertTrue(self.submit()["ok"])
        self.assertEqual({x["state"] for x in self.status()["proposals"][1:]}, {"expired"})

    def test_a_missing_store_refuses_and_says_so(self):
        os.rmdir(self.store())
        self.assertEqual(self.submit()["error"], "the proposal store is unavailable")
        self.assertEqual(self.status()["error"], "the proposal store is unavailable")

    def test_a_busy_store_refuses_after_a_short_wait(self):
        saved = proposals.SUBMIT_WAIT_S
        proposals.SUBMIT_WAIT_S = 0.2
        self.addCleanup(setattr, proposals, "SUBMIT_WAIT_S", saved)
        fd = os.open(proposals.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.assertIn("busy", self.submit()["error"])

    def test_the_stored_file_is_dom0s_canonical_copy(self):
        self.submit(create(templates=[], dump=False))
        path = self.store() / "000001.json"
        rec = json.loads(path.read_bytes())
        self.assertEqual(set(rec), {"v", "id", "submitted", "caller", "proposal"})
        self.assertEqual(rec["caller"], HUB)
        self.assertEqual(proposals.canonical(rec), path.read_bytes())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)


class Notification(PBase):
    def setUp(self):
        super().setUp()
        self.bus = self.tmp / "session" / str(os.getuid())
        self.bus.mkdir(parents=True)
        (self.bus / "bus").write_text("")
        self.log = self.tmp / "notified"
        prog = self.tmp / "notify-send"
        prog.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {self.log}\nexit ${{FAIL:-0}}\n")
        prog.chmod(0o755)
        for attr, value in (("BUS_DIR", str(self.tmp / "session")), ("NOTIFIERS", (str(prog),))):
            self.addCleanup(setattr, proposals, attr, getattr(proposals, attr))
            setattr(proposals, attr, value)

    def test_fixed_text_never_the_hubs_words(self):
        r = self.submit(create(title="<a href='x'>click</a> & approve"))
        self.assertTrue(r["ok"])
        argv = self.log.read_text().splitlines()
        self.assertEqual(argv[-1], "Proposal 1 from the hub is waiting in the qubes-mcp window.")
        self.assertNotIn("click", self.log.read_text())

    def test_a_failed_or_missing_notifier_never_fails_the_submit(self):
        os.environ["FAIL"] = "1"
        self.addCleanup(os.environ.pop, "FAIL", None)
        self.assertTrue(self.submit()["ok"])
        proposals.NOTIFIERS = (str(self.tmp / "absent"),)
        self.assertTrue(self.submit(create(label="other2"))["ok"])
        (self.bus / "bus").unlink()
        self.assertFalse(proposals.announce(3))


class HubReadsProjects(PBase):
    def test_every_record_but_the_sinks_name(self):
        r = self.call("qmcp.GetPoolStats")
        rows = {x["slot"]: x for x in r["projects"]}
        self.assertEqual(set(rows), {"p00", "p01", "p02"})
        self.assertEqual(rows["p01"], {"slot": "p01", "label": "osint", "lead": LEAD,
                                       "templates": ["ai-debian-13", "ai-dvm"],
                                       "networks": ["ai-net-router", None], "quota": 20 * GiB,
                                       "used": rows["p01"]["used"], "has_dump": True})
        self.assertIsInstance(rows["p01"]["used"], int)
        self.assertNotIn("osint-dump", json.dumps(r))
        self.assertNotIn("projects", self.lcall("qmcp.GetPoolStats"))

    def test_unreadable_records_are_null_not_empty(self):
        pathlib.Path(projects.PROJECTS_PATH).write_text("{not json")
        r = self.call("qmcp.GetPoolStats")
        self.assertTrue(r["ok"])
        self.assertIsNone(r["projects"])


# ======================================================================= the store

class Store(PBase):
    def test_states_through_a_life(self):
        self.submit()
        e = proposals.entries()[0]
        now = e.submitted
        self.assertEqual(e.state(now), "pending")
        self.assertEqual(e.state(now + 7 * DAY - 1), "pending")
        self.assertEqual(e.state(now + 7 * DAY), "expired")
        with self.assertRaisesRegex(proposals.Refused, "expired"):
            proposals.accept(self.app, 1, e.sha256, now=now + 7 * DAY)
        with self.assertRaisesRegex(proposals.Refused, "expired"):
            proposals.reject(1, now=now + 7 * DAY)
        self.assertIsNone(projects.find(self.records(), "scrape"))
        self.assertEqual(self.status()["proposals"][0]["state"], "pending")

    def test_a_file_that_does_not_read_back_is_unreadable_never_pending(self):
        self.submit()
        path = self.store() / "000001.json"
        rec = json.loads(path.read_bytes())
        for why, data in [
            ("not JSON", b"{oops"),
            ("not canonical", json.dumps(rec, indent=1).encode()),
            ("not normal form", proposals.canonical(dict(rec, proposal=dict(rec["proposal"], x=1)))),
            ("another id", proposals.canonical(dict(rec, id=2))),
            ("bad caller", proposals.canonical(dict(rec, caller="a b"))),
        ]:
            path.write_bytes(data)
            rows = proposals.listing()
            self.assertEqual((rows[0]["state"], rows[0]["type"]), (proposals.UNREADABLE, None), why)
            self.assertIsNotNone(rows[0]["problem"], why)
            self.assertEqual(self.status()["proposals"], [], why)
            with self.assertRaisesRegex(proposals.Refused, "cannot be read", msg=why):
                proposals.accept(self.app, 1, hashlib.sha256(data).hexdigest())
        self.assertEqual(proposals.reject(1), "rejected")

    def test_a_decision_that_does_not_parse_closes_it_as_failed(self):
        self.submit()
        (self.store() / "000001.decision").write_text("garbage")
        self.assertEqual(proposals.listing()[0]["state"], "failed")
        self.assertEqual(self.status()["proposals"][0]["state"], "failed")
        with self.assertRaisesRegex(proposals.Refused, "already failed"):
            self.accept(1, sha=proposals.entries()[0].sha256)

    def test_what_check_warns_about_reject_closes(self):
        # Each case `qmcp check` warns about must be closable by the reject it
        # advises, or the warning could never clear.
        for label in ("c1", "c2", "c3"):
            self.submit(create(label=label))
        (self.store() / "000001.json").write_text("{")                   # does not read
        (self.store() / "000002.decision").write_text("garbage")         # decision does not read
        (self.store() / "000003.accepting").write_bytes(b"")             # accept never finished
        self.assertEqual([r["needs_closing"] for r in proposals.listing()], [True, True, True])
        self.assertEqual([proposals.reject(n) for n in (1, 2, 3)], ["rejected", "failed", "failed"])
        self.assertEqual([r["needs_closing"] for r in proposals.listing()], [False, False, False])
        kept = self.store() / "000002.decision.unreadable"
        self.assertEqual(kept.read_text(), "garbage")                    # kept as evidence
        self.assertIn("did not read", json.loads((self.store() / "000002.decision").read_bytes())
                      ["report"][0])
        self.assertEqual(self.status()["proposals"][0]["state"], "failed")

    def test_ids_never_repeat(self):
        for label in ("a1", "a2"):
            self.submit(create(label=label))
        proposals.reject(2)
        self.assertEqual(self.submit(create(label="a3"))["id"], 3)


# ======================================================================= the second tick

class SecondTick(PBase):
    def reasons(self, req):
        return proposals.second_tick(self.app, proposals.normalise(req, "ai-"), self.records())

    def add_gateway(self, name, upstream):
        up = self.app.vm(upstream, provides_network=True, netvm=None)
        self.app.vm(name, provides_network=True, netvm=up, tags={"ai-managed", "qmcp-guarded"})

    def test_one_click_when_nothing_widens(self):
        self.assertEqual(self.reasons(create()), [])
        self.assertEqual(self.reasons(create(networks=["none"], lead_netvm="none")), [])
        # The hub's own netvm is a network AI space already reaches.
        self.assertEqual(self.reasons(create(lead_netvm="sys-firewall")), [])

    def test_a_network_ai_space_does_not_use(self):
        self.add_gateway("ai-net-vpn", "sys-vpn")
        self.assertEqual(self.reasons(create(networks=["ai-net-vpn"])),
                         ["gives AI space a network it does not use today: ai-net-vpn"])
        # A gateway's own upstream is not counted as in use: a qube placed on it
        # directly would skip the gateway.
        self.assertEqual(self.reasons(create(lead_netvm="sys-vpn")),
                         ["gives AI space a network it does not use today: sys-vpn"])
        self.app.vm("ai-vpn-user", netvm=self.app.domains["ai-net-vpn"], tags={"ai-managed"})
        self.assertEqual(self.reasons(create(networks=["ai-net-vpn"])), [])
        edit = {"type": "project-edit", "title": "t", "project": "osint", "add_networks": ["sys-vpn"]}
        self.assertEqual(len(self.reasons(edit)), 1)

    def test_promoting_one_of_the_hubs_qubes(self):
        self.assertIn("promotes ai-hubq", self.reasons(create(lead={"from": "promote", "qube": "ai-hubq"}))[0])

    def test_quotas_past_the_pool_cap(self):
        cap = 1000 * GiB      # the base's pool cap; p01 and p02 hold 30 GiB
        self.assertEqual(self.reasons(create(quota=cap - 30 * GiB)), [])
        self.assertIn("more than the pool cap", self.reasons(create(quota=cap - 30 * GiB + 1))[0])
        # An edit replaces its own project's quota; it is not counted twice.
        edit = {"type": "project-edit", "title": "t", "project": "osint", "quota": cap - 10 * GiB}
        self.assertEqual(self.reasons(edit), [])
        os.unlink(self.tmp / "pool-cap")
        self.assertIn("cannot be read", self.reasons(create())[0])

    def test_removals(self):
        self.assertIn("deletes the project osint",
                      self.reasons({"type": "project-delete", "title": "t", "project": "osint"})[0])
        remove = {"type": "project-lead", "title": "t", "project": "osint", "remove": True}
        self.assertEqual(self.reasons(remove), [f"removes the lead {LEAD} with everything in it"])
        change = {"type": "project-lead", "title": "t", "project": "osint", "keep_old": False,
                  "lead": {"from": "template", "qube": "ai-debian-13"}, "lead_name": "ai-osint-l2"}
        self.assertEqual(self.reasons(change), [f"removes the old lead {LEAD} with everything in it"])
        self.assertEqual(self.reasons(dict(change, keep_old=True)), [])
        # A recorded lead that no longer wears its badge is left alone by the
        # command, so nothing is removed and one click is enough; so is a
        # recorded name whose qube is gone.
        self.app.domains[LEAD].tags.discard("qmcp-lead-p01")
        self.assertEqual(self.reasons(remove), [])
        self.app.domains[LEAD].kill()
        del self.app.domains[LEAD]
        self.assertEqual(self.reasons(remove), [])
        self.assertEqual(self.reasons(change), [])


# ======================================================================= accepting and rejecting

class Accept(PBase):
    def test_accept_runs_the_command_and_closes_it(self):
        pid = self.submit(create(dump=True))["id"]
        ok, report = self.accept(pid)
        self.assertTrue(ok)
        self.assertIn("p03: project 'scrape' recorded; workers are named ai-scrape-*", report)
        p = projects.find(self.records(), "scrape")
        self.assertEqual((p.lead, p.dump, p.quota), ("ai-scrape-lead", "scrape-dump", 5 * GiB))
        self.assertEqual(self.status({"id": pid})["state"], "accepted")
        dec = json.loads((self.store() / "000001.decision").read_bytes())
        self.assertEqual((dec["state"], dec["report"]), ("accepted", report))
        self.assertFalse((self.store() / "000001.accepting").exists())
        with self.assertRaisesRegex(proposals.Refused, "already accepted"):
            self.accept(pid, sha=dec["sha256"])

    def test_another_fingerprint_is_refused_even_for_a_valid_proposal(self):
        pid = self.submit()["id"]
        shown = proposals.show(self.app, pid)["sha256"]
        path = self.store() / "000001.json"
        rec = json.loads(path.read_bytes())
        rec["proposal"]["quota"] = 500 * GiB
        path.write_bytes(proposals.canonical(rec))
        # The tamper is real: the changed file is still a valid, pending proposal.
        self.assertEqual(proposals.listing()[0]["state"], "pending")
        with self.assertRaisesRegex(proposals.Refused, "not the one shown"):
            proposals.accept(self.app, pid, shown)
        self.assertIsNone(projects.find(self.records(), "scrape"))
        self.assertEqual(proposals.listing()[0]["state"], "pending")
        for bad in ("", "0" * 63, "Z" * 64, None):
            with self.assertRaisesRegex(proposals.Refused, "fingerprint"):
                proposals.accept(self.app, pid, bad)

    def test_the_second_tick_is_required_and_refusing_changes_nothing(self):
        pid = self.submit({"type": "project-delete", "title": "t", "project": "osint"})["id"]
        sha = proposals.show(self.app, pid)["sha256"]
        with self.assertRaisesRegex(proposals.Refused, r"needs the second tick \(--yes [0-9a-f]{64}\): deletes"):
            proposals.accept(self.app, pid, sha)
        self.assertIsNotNone(projects.find(self.records(), "osint"))
        self.assertEqual(proposals.listing()[0]["state"], "pending")
        tick = proposals.show(self.app, pid)["tick"]
        ok, _ = proposals.accept(self.app, pid, sha, tick=tick)
        self.assertTrue(ok)
        self.assertIsNone(projects.find(self.records(), "osint"))

    def test_a_tick_answers_only_the_reasons_it_was_given_for(self):
        # The fleet can change between show and accept: the tick shown for
        # "removes the old lead X" must not accept "removes the old lead Y".
        pid = self.submit({"type": "project-lead", "title": "t", "project": "osint", "keep_old": False,
                           "lead": {"from": "template", "qube": "ai-debian-13"},
                           "lead_name": "ai-osint-l3"})["id"]
        doc = proposals.show(self.app, pid)
        self.assertEqual(doc["second_tick"], [f"removes the old lead {LEAD} with everything in it"])
        fleet.set_lead(self.app, "osint", "template", "ai-debian-13", keep_old=True,
                       lead_name="ai-osint-l2")                       # the operator's own change
        with self.assertRaisesRegex(proposals.Refused, "not the ones it was given for"):
            proposals.accept(self.app, pid, doc["sha256"], tick=doc["tick"])
        self.assertIn("ai-osint-l2", self.app.domains)
        self.assertEqual(proposals.listing()[0]["state"], "pending")
        line = [x for x in self.operator_lines() if x["service"] == "qmcp proposal accept"][-1]
        self.assertEqual(line["error"], "the second tick answers other reasons")
        fresh = proposals.show(self.app, pid)
        self.assertNotEqual(fresh["tick"], doc["tick"])
        self.assertTrue(proposals.accept(self.app, pid, fresh["sha256"], tick=fresh["tick"])[0])
        for bad in ("yes", "0" * 63, "Z" * 64):
            with self.assertRaisesRegex(proposals.Refused, "--yes wants"):
                proposals.accept(self.app, pid, fresh["sha256"], tick=bad)

    def test_a_tick_is_harmless_when_one_click_is_enough(self):
        pid = self.submit()["id"]
        doc = proposals.show(self.app, pid)
        self.assertEqual((doc["second_tick"], doc["tick"]), ([], None))
        self.assertTrue(proposals.accept(self.app, pid, doc["sha256"], tick="0" * 64)[0])

    def test_a_command_that_refuses_closes_it_as_failed(self):
        pid = self.submit(create(label="osint"))["id"]          # the label is taken
        ok, report = self.accept(pid)
        self.assertFalse(ok)
        self.assertEqual(report[-1], "stopped: label 'osint' is taken")
        self.assertEqual(self.status({"id": pid})["state"], "failed")
        self.assertNotIn("report", json.dumps(self.status()))
        with self.assertRaisesRegex(proposals.Refused, "already failed"):
            self.accept(pid, sha=proposals.entries()[0].sha256)

    def test_reject(self):
        pid = self.submit()["id"]
        self.assertEqual(proposals.reject(pid), "rejected")
        self.assertEqual(self.status({"id": pid})["state"], "rejected")
        with self.assertRaisesRegex(proposals.Refused, "already rejected"):
            proposals.reject(pid)
        with self.assertRaisesRegex(proposals.Refused, "no proposal 7"):
            proposals.reject(7)

    def test_an_edit_applies_to_the_record_as_it_is_then(self):
        pid = self.submit({"type": "project-edit", "title": "t", "project": "osint",
                           "add_networks": ["none", "ai-net-router"], "default_network": "none",
                           "remove_templates": ["ai-dvm"]})["id"]
        doc = proposals.show(self.app, pid)
        self.assertEqual(doc["before"], {"templates": ["ai-debian-13", "ai-dvm"],
                                         "networks": ["ai-net-router", "none"], "quota": 20 * GiB})
        self.assertEqual(doc["after"], {"templates": ["ai-debian-13"],
                                        "networks": ["none", "ai-net-router"], "quota": 20 * GiB})
        # The operator's own edit after the proposal arrived survives the accept.
        fleet.edit_project(self.app, "osint", templates=["ai-debian-13", "ai-dvm", "ai-tpl-g"])
        ok, _ = self.accept(pid)
        self.assertTrue(ok)
        p = projects.find(self.records(), "osint")
        self.assertEqual((p.templates, p.networks), (("ai-debian-13", "ai-tpl-g"), (None, "ai-net-router")))

    def test_an_edit_that_cannot_apply_says_so_and_fails(self):
        empty = self.submit({"type": "project-edit", "title": "t", "project": "osint",
                             "remove_networks": ["none"]})["id"]
        gone = self.submit({"type": "project-edit", "title": "t", "project": "osint",
                            "default_network": "ai-net-router"})["id"]
        self.app.domains["ai-osint-w1"].netvm = None                 # off the network first
        fleet.edit_project(self.app, "osint", networks=["none"])     # the operator's own edit
        self.assertEqual(proposals.show(self.app, empty)["after"]["networks"], [])
        ok, report = self.accept(empty)
        self.assertFalse(ok)
        self.assertIn("at least one worker network", report[-1])
        self.assertIn("cannot apply", proposals.show(self.app, gone)["plan"])
        ok, report = self.accept(gone)
        self.assertFalse(ok)
        self.assertIn("not on the list", report[-1])
        self.assertEqual(projects.find(self.records(), "osint").networks, (None,))

    def test_dump_lead_and_delete_through_proposals(self):
        p1 = self.submit({"type": "project-dump", "title": "t", "project": "other"})["id"]
        self.assertTrue(self.accept(p1)[0])
        self.assertEqual(projects.find(self.records(), "other").dump, "other-dump")
        p2 = self.submit({"type": "project-lead", "title": "t", "project": "osint", "remove": True})["id"]
        self.assertTrue(self.accept(p2, yes=True)[0])
        self.assertIsNone(projects.find(self.records(), "osint").lead)
        self.assertNotIn(LEAD, self.app.domains)
        p3 = self.submit({"type": "project-lead", "title": "t", "project": "osint", "keep_old": False,
                          "lead": {"from": "template", "qube": "ai-debian-13"}})["id"]
        self.assertTrue(self.accept(p3)[0])
        self.assertEqual(projects.find(self.records(), "osint").lead, "ai-osint-lead")
        p4 = self.submit({"type": "project-delete", "title": "t", "project": "other"})["id"]
        self.assertIn("this removes p02 'other'", proposals.show(self.app, p4)["plan"])
        self.assertTrue(self.accept(p4, yes=True)[0])
        self.assertIsNone(projects.find(self.records(), "other"))

    def test_a_proposal_naming_no_project_says_it_will_fail(self):
        pid = self.submit({"type": "project-dump", "title": "t", "project": "ghost"})["id"]
        self.assertIn("there is no project ghost", proposals.show(self.app, pid)["plan"])

    def test_every_attempt_is_one_operator_line_with_the_fingerprint(self):
        pid = self.submit({"type": "project-delete", "title": "t", "project": "osint"})["id"]
        sha = proposals.show(self.app, pid)["sha256"]
        with self.assertRaises(proposals.Refused):
            proposals.accept(self.app, pid, sha)
        proposals.accept(self.app, pid, sha, tick=proposals.show(self.app, pid)["tick"])
        lines = [x for x in self.operator_lines() if x["service"] == "qmcp proposal accept"]
        self.assertEqual([x["ok"] for x in lines], [False, True])
        self.assertIn("needs the second tick", lines[0]["error"])
        self.assertEqual(lines[1]["args"], {"id": pid, "sha256": sha, "yes": True,
                                            "type": "project-delete", "subject": "osint"})


class Interrupted(PBase):
    """An accept whose command may have run must never read as pending again."""

    def claim(self, pid=1, hold=False):
        path = self.store() / f"{pid:06d}.accepting"
        path.write_bytes(proposals.canonical({"v": 1, "id": pid, "at": "2026-10-02T00:00:00Z",
                                              "sha256": "0" * 64}))
        if hold:
            fd = os.open(path, os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.addCleanup(os.close, fd)
        return path

    def test_a_running_accept_reads_as_accepting_and_pending_to_the_hub(self):
        self.submit()
        self.claim(hold=True)
        self.assertEqual(proposals.listing()[0]["state"], proposals.ACCEPTING)
        self.assertEqual(self.status()["proposals"][0]["state"], "pending")
        with self.assertRaisesRegex(proposals.Refused, "being accepted"):
            self.accept(1, sha=proposals.entries()[0].sha256)

    def test_an_accept_that_never_finished_is_failed_until_the_operator_closes_it(self):
        self.submit()
        path = self.claim()
        row = proposals.listing()[0]
        self.assertEqual(row["state"], "failed")
        self.assertIn("did not finish", row["problem"])
        self.assertEqual(self.status()["proposals"][0]["state"], "failed")
        with self.assertRaisesRegex(proposals.Refused, "already failed"):
            self.accept(1, sha=proposals.entries()[0].sha256)
        self.assertEqual(proposals.reject(1), "failed")
        self.assertFalse(path.exists())
        self.assertIsNone(proposals.listing()[0]["problem"])
        self.assertEqual(proposals.listing()[0]["state"], "failed")

    def test_a_decision_that_cannot_be_written_leaves_it_failed_not_pending(self):
        pid = self.submit()["id"]
        real = proposals._decide

        def broken(*a, **kw):
            raise OSError("disk full")
        proposals._decide = broken
        self.addCleanup(setattr, proposals, "_decide", real)
        with self.assertRaisesRegex(proposals.Refused, "decision could not be written") as ctx:
            self.accept(pid)
        self.assertTrue(ctx.exception.report)                     # what ran is still reported
        self.assertIsNotNone(projects.find(self.records(), "scrape"))
        self.assertEqual(proposals.listing()[0]["state"], "failed")
        self.assertEqual(self.status()["proposals"][0]["state"], "failed")

    def test_the_claim_is_never_seen_unlocked_while_the_command_runs(self):
        pid = self.submit()["id"]
        seen = []
        real = proposals._execute

        def watching(app, p):
            seen.append(proposals.listing()[0]["state"])
            return real(app, p)
        proposals._execute = watching
        self.addCleanup(setattr, proposals, "_execute", real)
        self.accept(pid)
        self.assertEqual(seen, [proposals.ACCEPTING])
        self.assertEqual(sorted(p.name for p in self.store().iterdir()),
                         ["000001.decision", "000001.json"])


class AuditFixes(PBase):
    """One test per finding of the pre-release audit, each failing before its fix."""

    def test_001_a_lead_badge_that_cannot_be_read_counts_as_a_removal(self):
        pid = self.submit({"type": "project-lead", "title": "t", "project": "osint", "remove": True})["id"]
        sha = proposals.show(self.app, pid)["sha256"]
        domains = type(self.app.domains)
        real = domains.__contains__
        calls = []

        def flaky(coll, name):
            calls.append(name)
            if name == LEAD and len(calls) == 1:          # once: the tick's read only
                raise OSError("qubesd hiccup")
            return real(coll, name)
        domains.__contains__ = flaky
        self.addCleanup(setattr, domains, "__contains__", real)
        with self.assertRaisesRegex(proposals.Refused, "may remove the lead ai-osint-lead"):
            proposals.accept(self.app, pid, sha)
        self.assertIn(LEAD, self.app.domains)
        self.assertEqual(proposals.listing()[0]["state"], "pending")

    def test_002_success_never_depends_on_words_in_a_name(self):
        # A name the hub chooses may hold any word; a line holding "NOT " once
        # made a completed accept, and the command's exit status, read failed.
        pid = self.submit({"type": "project-dump", "title": "t", "project": "other",
                           "name": "sinkNOT"})["id"]
        ok, report = self.accept(pid)
        self.assertTrue(ok and any("sinkNOT" in line for line in report), report)
        self.assertEqual(self.status({"id": pid})["state"], "accepted")
        pid2 = self.submit(create(label="nots", lead_name="ai-nots-NOT"))["id"]
        self.assertTrue(self.accept(pid2)[0])
        rc, out, _ = self.cli("project", "create", "noter", "--lead-template", "ai-debian-13",
                              "--lead-name", "ai-noter-NOT", "--network", "none", "--quota", "1G")
        self.assertEqual(rc, 0, out)
        self.assertIn("lead ai-noter-NOT (created)", out)

    def test_002_a_step_that_did_not_complete_is_a_failed_step(self):
        # The other half: a member that could not be removed fails the delete,
        # in the command's exit status and in the accept's outcome.
        real = fleet._remove_qube
        fleet._remove_qube = lambda app, name: (f"{name}: still present" if name == "ai-osint-w1"
                                                else real(app, name))
        self.addCleanup(setattr, fleet, "_remove_qube", real)
        pid = self.submit({"type": "project-delete", "title": "t", "project": "osint"})["id"]
        ok, report = self.accept(pid, yes=True)
        self.assertFalse(ok)
        self.assertIn("p01: NOT removed: ai-osint-w1: still present; if it still runs, kill it by "
                      "hand (qvm-kill ai-osint-w1)", report)
        self.assertEqual(self.status({"id": pid})["state"], "failed")
        rc, out, _ = self.cli("project", "delete", "other", "--yes")
        self.assertEqual(rc, 0, out)                       # a delete that completed exits 0

    def test_003_project_locks_that_cannot_be_had_leave_it_pending(self):
        pid = self.submit()["id"]
        sha = proposals.show(self.app, pid)["sha256"]
        fd = os.open(budget.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)                    # a create in flight
        with self.assertRaisesRegex(proposals.Refused, "still pending"):
            proposals.accept(self.app, pid, sha)
        self.assertEqual(proposals.listing()[0]["state"], "pending")
        self.assertFalse((self.store() / "000001.accepting").exists())
        fcntl.flock(fd, fcntl.LOCK_UN)
        self.assertTrue(proposals.accept(self.app, pid, sha)[0])

    def test_004_a_refused_accept_logs_no_figures(self):
        pid = self.submit(create(quota=999 * GiB))["id"]
        with self.assertRaises(proposals.Refused) as ctx:
            self.accept(pid)
        self.assertIn("GiB", str(ctx.exception))                  # the operator reads them
        line = [x for x in self.operator_lines() if x["service"] == "qmcp proposal accept"][-1]
        self.assertEqual(line["error"], "needs the second tick")

    def test_005_a_quota_past_any_disk_is_refused_everywhere(self):
        self.assertFalse(self.submit(create(quota=10 ** 320))["ok"])
        self.assertTrue(self.submit(create(quota=projects.MAX_QUOTA))["ok"])
        with self.assertRaises(fleet.RoleError):
            fleet.edit_project(self.app, "osint", quota=projects.MAX_QUOTA + 1)
        bad = json.loads(pathlib.Path(projects.PROJECTS_PATH).read_text())
        bad["slots"]["p01"]["quota"] = projects.MAX_QUOTA + 1
        with self.assertRaises(projects.ProjectsUnreadable):
            projects.parse(json.dumps(bad))

    def test_006_a_rollback_that_fails_says_so(self):
        real_save, real_remove = projects.save, fleet._remove_qube

        def broken_save(records, path=None):
            raise OSError("disk full")
        projects.save = broken_save
        fleet._remove_qube = lambda app, name: f"{name}: still present"
        self.addCleanup(setattr, projects, "save", real_save)
        self.addCleanup(setattr, fleet, "_remove_qube", real_remove)
        pid = self.submit()["id"]
        ok, report = self.accept(pid)
        self.assertFalse(ok)
        self.assertIn("p03: NOT undone: ai-scrape-lead: still present", report)
        self.assertNotIn("p03: undone", report)

    def test_007_a_claim_gone_with_a_decision_beside_it_is_decided(self):
        self.submit()
        e = proposals.Entry(1)
        dec = self.store() / "000001.decision"
        dec.write_bytes(proposals.canonical({"v": 1, "id": 1, "state": "accepted",
                                             "at": "2026-10-02T00:00:00Z", "sha256": None,
                                             "report": []}))
        proposals._probe_claim(e, str(self.store() / "000001.accepting"), str(dec))
        self.assertEqual((e.claim, e.decided, e.decision["state"]), (None, True, "accepted"))

    def test_008_an_audit_log_of_another_group_fails_the_check(self):
        self.cli("guard", "ai-work2")
        real = os.stat

        def other_group(path, *a, **kw):
            st = real(path, *a, **kw)
            if str(path) == audit.LOG_PATH:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
                                       st.st_gid + 1, st.st_size, st.st_atime, st.st_mtime,
                                       st.st_ctime))
            return st
        os.stat = other_group
        self.addCleanup(setattr, os, "stat", real)
        findings = fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})
        self.assertEqual(next(f for f in findings if f.check == "audit log").status, "fail")

    def test_009_the_hubs_read_redacts_a_name_outside_ai_space(self):
        self.app.domains["ai-dvm"].tags.discard("ai-managed")
        row = next(r for r in self.call("qmcp.GetPoolStats")["projects"] if r["slot"] == "p01")
        self.assertEqual(row["templates"], ["ai-debian-13", "<out-of-scope>"])
        self.assertNotIn("ai-dvm", json.dumps(self.call("qmcp.GetPoolStats")))

    def test_011_a_submit_never_waits_on_a_running_command(self):
        pid = self.submit()["id"]
        saved = proposals.SUBMIT_WAIT_S
        proposals.SUBMIT_WAIT_S = 0.2
        self.addCleanup(setattr, proposals, "SUBMIT_WAIT_S", saved)
        seen = []
        real = proposals._execute

        def submitting(app, p):
            seen.append(self.submit(create(label="during")))
            return real(app, p)
        proposals._execute = submitting
        self.addCleanup(setattr, proposals, "_execute", real)
        self.assertTrue(self.accept(pid)[0])
        self.assertTrue(seen[0]["ok"], seen[0])


# ======================================================================= the command

class Command(PBase):
    def test_list_show_accept_reject(self):
        pid = self.submit()["id"]
        rc, out, _ = self.cli("proposal", "list", "--json", root=False)
        rows = json.loads(out)
        self.assertEqual((rc, set(rows[0]), rows[0]["state"]), (0, set(proposals.LIST_FIELDS), "pending"))
        rc, out, _ = self.cli("proposal", "show", str(pid), "--json", root=False)
        doc = json.loads(out)
        self.assertEqual((rc, set(doc)), (0, set(proposals.SHOW_FIELDS)))
        rc, out, _ = self.cli("proposal", "accept", str(pid), "--sha256", doc["sha256"])
        self.assertEqual(rc, 0)
        self.assertIn(f"proposal {pid}: accepted", out)
        gone = self.submit({"type": "project-delete", "title": "t", "project": "other"})["id"]
        rc, out, _ = self.cli("proposal", "show", str(gone), root=False)
        tick = proposals.show(self.app, gone)["tick"]
        self.assertIn(f"accept with --yes {tick}", out)
        rc, _, err = self.cli("proposal", "accept", str(gone), "--sha256",
                              proposals.show(self.app, gone)["sha256"], "--yes", tick)
        self.assertEqual(rc, 0, err)
        pid2 = self.submit(create(label="second"))["id"]
        rc, out, _ = self.cli("proposal", "reject", str(pid2))
        self.assertEqual((rc, out.strip()), (0, f"proposal {pid2}: rejected"))
        rc, _, err = self.cli("proposal", "reject", str(pid2))
        self.assertEqual(rc, 1)
        self.assertIn("already rejected", err)

    @unittest.skipIf(os.geteuid() == 0, "the root check only refuses non-root")
    def test_deciding_needs_root(self):
        pid = self.submit()["id"]
        sha = proposals.show(self.app, pid)["sha256"]
        for argv in (("accept", str(pid), "--sha256", sha), ("reject", str(pid))):
            rc, _, _ = self.cli("proposal", *argv, root=False)
            self.assertIn("run as root", str(rc))
        self.assertEqual(proposals.listing()[0]["state"], "pending")
        self.assertEqual(self.operator_lines(), [])

    def test_a_failed_accept_prints_the_report_and_exits_1(self):
        pid = self.submit(create(label="osint"))["id"]
        sha = proposals.show(self.app, pid)["sha256"]
        rc, out, _ = self.cli("proposal", "accept", str(pid), "--sha256", sha)
        self.assertEqual(rc, 1)
        self.assertIn("stopped: label 'osint' is taken", out)
        self.assertIn(f"proposal {pid}: failed", out)


class OperatorLines(PBase):
    """Every change the operator makes, as caller "operator"."""

    def test_each_change_leaves_one_line_with_its_names_and_options_and_no_quota_figure(self):
        cases = [
            (("project", "create", "newp", "--lead-template", "ai-debian-13", "--network",
              "ai-net-router", "--quota", "7G", "--dump"), "qmcp project create",
             {"project": "newp", "lead_template": "ai-debian-13", "templates": [],
              "networks": ["ai-net-router"], "dump": True, "quota": "set"}),
            (("project", "edit", "newp", "--quota", "9G"), "qmcp project edit",
             {"project": "newp", "quota": "set"}),
            (("project", "move", "ai-work2", "p00"), "qmcp project move",
             {"qube": "ai-work2", "target": "p00", "yes": False}),
            (("project", "lead", "newp", "--remove"), "qmcp project lead",
             {"project": "newp", "remove": True, "keep_old": False, "add_old_network": False}),
            (("project", "delete", "newp", "--yes"), "qmcp project delete", {"project": "newp"}),
            (("guard", "ai-on-operator-tpl"), "qmcp guard", {"qube": "ai-on-operator-tpl"}),
            (("manage", "ai-on-operator-tpl"), "qmcp manage", {"qube": "ai-on-operator-tpl"}),
        ]
        for argv, service, summary in cases:
            before = len(self.operator_lines())
            rc, _, err = self.cli(*argv)
            self.assertEqual(rc, 0, (argv, err))
            lines = self.operator_lines()
            self.assertEqual(len(lines), before + 1, argv)
            self.assertEqual((lines[-1]["service"], lines[-1]["args"], lines[-1]["ok"]),
                             (service, summary, True), argv)
        text = json.dumps(self.operator_lines())
        self.assertNotIn("7G", text)
        self.assertNotIn(str(7 * GiB), text)

    def test_reads_plans_and_dry_runs_leave_nothing(self):
        for argv in (("project", "list", "--json"), ("project", "show", "osint"), ("list",),
                     ("settings",), ("audit", "tail"), ("project", "delete", "osint"),
                     ("migrate",), ("proposal", "list")):
            self.cli(*argv, root=False)
        self.assertEqual(self.operator_lines(), [])

    def test_a_refused_change_is_a_line_with_ok_false(self):
        rc, _, _ = self.cli("project", "create", "osint", "--lead-template", "ai-debian-13",
                            "--network", "none", "--quota", "1G")
        self.assertEqual(rc, 1)
        line = self.operator_lines()[-1]
        self.assertEqual((line["service"], line["ok"], line["error"]),
                         ("qmcp project create", False, "exit status 1"))

    @unittest.skipIf(os.geteuid() == 0, "the root check only refuses non-root")
    def test_a_command_refused_before_it_runs_leaves_nothing(self):
        self.cli("project", "delete", "osint", "--yes", root=False)
        self.assertEqual(self.operator_lines(), [])

    def test_a_malformed_map_leaves_nothing(self):
        rc, _, _ = self.cli("migrate", "--apply", "--map", "ai-work=sideways")
        self.assertIn("--map wants NAME=managed|guarded", str(rc))     # the exit message
        self.assertEqual(self.operator_lines(), [])

    def test_a_malformed_value_its_own_checks_refuse_is_a_line_with_ok_false(self):
        rc, _, _ = self.cli("project", "edit", "osint", "--quota", "40X")
        self.assertEqual(rc, 1)
        line = self.operator_lines()[-1]
        self.assertEqual((line["service"], line["ok"], line["args"]),
                         ("qmcp project edit", False, {"project": "osint", "quota": "set"}))

    def test_a_rotation_starts_the_new_log_as_the_operator(self):
        self.cli("guard", "ai-work2")
        audit.rotate()
        first = self.audit_lines()[0]
        self.assertEqual((first["service"], first["caller"]), (audit.ROTATE_SERVICE, "operator"))
        self.assertTrue(audit.verify()[0])


# ======================================================================= the install

class Install(PBase):
    def finding(self, name):
        findings = fleet.check(self.app, legacy_paths=(), system_info={"domains": {}})
        return next(f for f in findings if f.check == name)

    def in_another_group(self, *paths):
        """From now on, os.stat reports `paths` in a group one past their own."""
        real, moved = os.stat, {str(x) for x in paths}

        def other_group(path, *a, **kw):
            st = real(path, *a, **kw)
            if str(path) in moved:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
                                       st.st_gid + 1, st.st_size, st.st_atime, st.st_mtime,
                                       st.st_ctime))
            return st
        os.stat = other_group
        self.addCleanup(setattr, os, "stat", real)

    def test_the_store_check(self):
        self.assertEqual(self.finding("proposal store").status, "pass")
        self.submit()
        self.assertIn("1 pending", self.finding("proposal store").detail)
        os.chmod(self.store(), 0o770)                           # no setgid
        self.assertEqual(self.finding("proposal store").status, "fail")
        os.chmod(self.store(), 0o2750)                          # no group write
        self.assertEqual(self.finding("proposal store").status, "fail")
        os.chmod(self.store(), 0o2770)
        (self.store() / "000001.json").write_text("{")
        self.assertEqual(self.finding("proposal store").status, "warn")
        proposals.reject(1)
        self.assertEqual(self.finding("proposal store").status, "pass")
        (self.store() / "000001.json").write_text("{")
        os.rename(self.store(), self.tmp / "gone")
        self.assertEqual(self.finding("proposal store").status, "fail")

    def test_a_lock_the_services_cannot_write_fails_the_check(self):
        os.close(os.open(proposals.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660))
        os.chmod(proposals.LOCK_PATH, 0o660)
        self.assertEqual(self.finding("proposal store").status, "pass")
        os.chmod(proposals.LOCK_PATH, 0o640)
        self.assertEqual(self.finding("proposal store").status, "fail")
        os.chmod(proposals.LOCK_PATH, 0o660)
        self.in_another_group(proposals.LOCK_PATH)
        self.assertEqual(self.finding("proposal store").status, "fail")
        self.assertIn("not writable by the services group", self.finding("proposal store").detail)

    def test_the_audit_log_the_writer_creates_is_group_writable(self):
        os.unlink(audit.LOG_PATH)          # the base makes one; this proves the writer's own
        old = os.umask(0o022)              # sudo's umask: the writer must not depend on it
        try:
            self.cli("guard", "ai-work2")
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(audit.LOG_PATH).st_mode), 0o660)

    def test_a_create_lock_the_services_cannot_write_fails_the_check(self):
        os.close(os.open(budget.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660))
        os.chmod(budget.LOCK_PATH, 0o660)
        self.assertEqual(self.finding("runtime dir").status, "pass")
        os.chmod(budget.LOCK_PATH, 0o640)
        self.assertEqual(self.finding("runtime dir").status, "fail")
        os.chmod(budget.LOCK_PATH, 0o660)
        self.in_another_group(budget.LOCK_PATH)
        self.assertEqual(self.finding("runtime dir").status, "fail")
        self.assertIn("not writable by the services group", self.finding("runtime dir").detail)

    def test_a_directory_and_its_files_moved_together_still_fail(self):
        # The check holds each file to the services' group itself, never to its
        # neighbour's: moving a directory with its files must not pass.
        calls = os.path.join(core.RUN_DIR, "calls")
        os.close(os.open(budget.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660))
        os.close(os.open(proposals.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o660))
        for path in (budget.LOCK_PATH, proposals.LOCK_PATH):
            os.chmod(path, 0o660)
        self.cli("guard", "ai-work2")                     # an audit log with a line in it
        for name in ("runtime dir", "proposal store"):
            self.assertEqual(self.finding(name).status, "pass", name)
        self.assertNotIn("audit log", [f.check for f in fleet.check(
            self.app, legacy_paths=(), system_info={"domains": {}})])
        self.in_another_group(calls, budget.LOCK_PATH, audit.LOG_PATH,
                              proposals.PROPOSALS_DIR, proposals.LOCK_PATH)
        for name in ("runtime dir", "audit log", "proposal store"):
            self.assertEqual(self.finding(name).status, "fail", name)

    def test_a_runtime_directory_that_would_close_a_new_lock_fails_the_check(self):
        # A lock that goes missing is made again by whoever comes first, so the
        # directory must leave it the services' to open: theirs, writable, setgid.
        run = core.RUN_DIR
        self.assertEqual(self.finding("runtime dir").status, "pass")
        for mode in (0o0770, 0o2750):                  # no setgid; no group write
            os.chmod(run, mode)
            self.assertEqual(self.finding("runtime dir").status, "fail", oct(mode))
            self.assertIn(run, self.finding("runtime dir").detail)
        os.chmod(run, 0o2770)
        self.assertEqual(self.finding("runtime dir").status, "pass")
        self.in_another_group(run)
        self.assertEqual(self.finding("runtime dir").status, "fail")

    def test_each_shared_directory_alone_in_another_group_fails(self):
        calls = os.path.join(core.RUN_DIR, "calls")
        for path, name in ((calls, "runtime dir"), (proposals.PROPOSALS_DIR, "proposal store")):
            real = os.stat
            self.assertEqual(self.finding(name).status, "pass", name)
            self.in_another_group(path)
            self.assertEqual(self.finding(name).status, "fail", name)
            os.stat = real                                  # the next directory alone

    def test_a_host_without_the_services_group_fails_the_check(self):
        saved = fleet.SERVICES_GROUP
        fleet.SERVICES_GROUP = "qmcp-no-such-group"
        self.addCleanup(setattr, fleet, "SERVICES_GROUP", saved)
        self.assertEqual(self.finding("services group").status, "fail")
        for name in ("runtime dir", "audit log", "proposal store"):
            self.assertEqual(self.finding(name).status, "fail", name)

    def test_an_audit_log_the_services_cannot_write_fails_the_check(self):
        self.cli("guard", "ai-work2")
        self.assertNotIn("audit log", [f.check for f in fleet.check(
            self.app, legacy_paths=(), system_info={"domains": {}}) if f.status == "fail"])
        self.assertEqual(stat.S_IMODE(os.stat(audit.LOG_PATH).st_mode) & 0o060, 0o060)
        os.chmod(audit.LOG_PATH, 0o640)
        self.assertEqual(self.finding("audit log").status, "fail")
        os.unlink(audit.LOG_PATH)                         # the services cannot create it
        self.assertEqual(self.finding("audit log").status, "fail")
        self.assertIn("missing", self.finding("audit log").detail)

    def test_the_uninstaller_knows_every_service(self):
        text = (HERE.parent / "deploy" / "uninstall.sh").read_text()
        listed = set(text.split('LEGACY_RPC="', 1)[1].split('"', 1)[0].split())
        self.assertLessEqual(set(services.SERVICES), listed)

    def test_tmpfiles_declares_what_root_and_the_services_share(self):
        rows = {tuple(line.split()[:5]) for line in
                (HERE.parent / "deploy" / "qmcp-tmpfiles.conf").read_text().splitlines()
                if line.strip() and not line.startswith("#")}
        for row in [("d", REAL["store"], "2770", "root", "qubes"),
                    ("f", REAL["lock"], "0660", "root", "qubes"),
                    ("z", REAL["lock"], "0660", "root", "qubes"),
                    ("f", REAL["log"], "0660", "root", "qubes"),
                    ("z", REAL["log"], "0660", "root", "qubes")]:
            self.assertIn(row, rows, row)


if __name__ == "__main__":
    unittest.main()
