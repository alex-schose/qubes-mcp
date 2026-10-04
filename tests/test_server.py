"""Tests for the standard-library MCP server, the tool registry and the CLI.

Standard library only: no network, no Qubes. The server and the CLI run as
subprocesses with QUBES_MCP_QREXEC_CLIENT pointing at a launcher for
tests/fake_qrexec_client.py, which logs every qrexec call it receives and
answers from a per-test JSON file.

Run from the public/ directory:

    python3 -W error::DeprecationWarning -m unittest discover -s tests -p 'test_server.py' -v
"""
from __future__ import annotations

import io
import json
import os
import queue
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = TESTS_DIR.parent
FAKE_CLIENT = TESTS_DIR / "fake_qrexec_client.py"
if str(PUBLIC_DIR) not in sys.path:
    sys.path.insert(0, str(PUBLIC_DIR))

import qubes_mcp  # noqa: E402
from qubes_mcp import qrexec, server, tools  # noqa: E402

REFUSED = {"ok": False, "error": "not found or refused"}
A = "@adminvm"
LIFE = "qmcp.LifecycleAIManaged"
PROP = "qmcp.GetPropertyAIManaged"
RECV_TIMEOUT = 20.0

EXPECTED_TOOLS = [
    "qubes_list", "qubes_spawn", "qubes_state", "qubes_props_get", "qubes_props_set",
    "qubes_start", "qubes_shutdown", "qubes_remove", "qubes_run", "qubes_copy",
    "qubes_firewall_get", "qubes_firewall_set", "qubes_clone", "qubes_spawn_disposable",
    "qubes_run_disposable", "qubes_feature_set", "qubes_events", "qubes_get_pool_stats",
    "qubes_propose_project", "qubes_propose_project_edit", "qubes_propose_dump",
    "qubes_propose_lead", "qubes_propose_project_delete", "qubes_proposals",
]
# Each proposal tool and the dom0 proposal type it submits.
PROPOSAL_TYPES = {
    "qubes_propose_project": "project-create",
    "qubes_propose_project_edit": "project-edit",
    "qubes_propose_dump": "project-dump",
    "qubes_propose_lead": "project-lead",
    "qubes_propose_project_delete": "project-delete",
}
SUBMIT = "qmcp.SubmitProposal"
STATUS = "qmcp.ProposalStatus"
GiB = 1024 ** 3
# The smallest arguments each proposal tool accepts.
MINIMAL_PROPOSALS = {
    "qubes_propose_project": {"title": "OSINT", "label": "osint", "networks": ["ai-gw"],
                              "quota": 1, "lead": {"from": "template", "qube": "debian-12-xfce"}},
    "qubes_propose_project_edit": {"title": "More disk", "project": "osint", "quota": 1},
    "qubes_propose_dump": {"title": "A sink", "project": "osint"},
    "qubes_propose_lead": {"title": "No lead", "project": "osint", "remove": True},
    "qubes_propose_project_delete": {"title": "Done", "project": "osint"},
}
REMOVED_TOOLS = ["qubes_device_list", "qubes_device_attach", "qubes_device_detach",
                 "qubes_install_pkg"]
VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

class FakeQrexec:
    """A temp dir holding the fake client's launcher, call log and answer file."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="qmcp-test-")
        self.root = Path(self._tmp.name)
        self.log_path = self.root / "calls.jsonl"
        self.config_path = self.root / "answers.json"
        self.client = self.root / "qrexec-client-vm"
        # A launcher, so the suite does not depend on the fake's exec bit and
        # the fake runs on this interpreter. `exec` matters: a client-side
        # timeout kills the launcher's pid, which must be the fake itself.
        self.client.write_text("#!/bin/sh\nexec {} {} \"$@\"\n".format(
            shlex.quote(sys.executable), shlex.quote(str(FAKE_CLIENT))))
        self.client.chmod(0o755)
        self.log_path.touch()

    def overrides(self) -> dict:
        return {
            "QUBES_MCP_QREXEC_CLIENT": str(self.client),
            "QMCP_FAKE_LOG": str(self.log_path),
            "QMCP_FAKE_CONFIG": str(self.config_path),
        }

    def env(self) -> dict:
        env = dict(os.environ)
        env.update(self.overrides())
        env["PYTHONPATH"] = str(PUBLIC_DIR)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    def answer(self, config: dict) -> None:
        self.config_path.write_text(json.dumps(config))

    def reset(self) -> None:
        self.log_path.write_text("")
        if self.config_path.exists():
            self.config_path.unlink()

    def calls(self) -> list:
        """(target, service, payload) per call: payload is the parsed JSON
        request (None when empty), or the raw text for admin.* methods."""
        out = []
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            target, service = entry["argv"]
            text = entry["stdin"]
            if service.startswith("admin."):
                out.append((target, service, text))
            else:
                out.append((target, service, json.loads(text) if text else None))
        return out

    def cleanup(self) -> None:
        self._tmp.cleanup()


_EOF = object()


def _is_reply(message) -> bool:
    if isinstance(message, list):        # a batch reply: a non-empty array of replies
        return bool(message) and all(isinstance(m, dict) and _is_reply(m) for m in message)
    return (isinstance(message, dict) and message.get("jsonrpc") == "2.0"
            and "id" in message and (("result" in message) != ("error" in message)))


class ServerProcess:
    """`python3 -m qubes_mcp` with pipes; every stdout line is checked."""

    def __init__(self, env: dict) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-W", "error::DeprecationWarning", "-m", "qubes_mcp"],
            cwd=str(PUBLIC_DIR), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.replies: queue.Queue = queue.Queue()
        self.stdout_lines: list[bytes] = []
        self.foreign_lines: list[bytes] = []    # anything on stdout but a JSON-RPC reply line
        self._stderr: list[bytes] = []
        self._next_id = 0
        self._threads = [threading.Thread(target=self._read_stdout, daemon=True),
                         threading.Thread(target=self._read_stderr, daemon=True)]
        for thread in self._threads:
            thread.start()

    def _read_stdout(self) -> None:
        for line in self.proc.stdout:
            self.stdout_lines.append(line)
            try:
                message = json.loads(line)
            except ValueError:
                self.foreign_lines.append(line)
                continue
            # One reply per line, newline-terminated, pure ASCII.
            if not (line.endswith(b"\n") and line.count(b"\n") == 1 and line.isascii()
                    and _is_reply(message)):
                self.foreign_lines.append(line)
                continue
            self.replies.put(message)
        self.replies.put(_EOF)

    def _read_stderr(self) -> None:
        for chunk in self.proc.stderr:
            self._stderr.append(chunk)

    def stderr_text(self) -> str:
        return b"".join(self._stderr).decode("utf-8", "replace")

    def send(self, message) -> None:
        self.send_raw(json.dumps(message).encode("utf-8") + b"\n")

    def send_raw(self, data: bytes) -> None:
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def recv(self, timeout: float = RECV_TIMEOUT):
        try:
            message = self.replies.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError(f"no reply within {timeout}s; stderr:\n{self.stderr_text()}")
        if message is _EOF:
            raise AssertionError(f"server closed stdout; stderr:\n{self.stderr_text()}")
        return message

    def new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def request(self, method: str, params=None):
        msg_id = self.new_id()
        message = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        reply = self.recv()
        assert reply.get("id") == msg_id, f"expected a reply to {msg_id}, got {reply}"
        return reply

    def notify(self, method: str, params=None) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)

    def call(self, tool: str, arguments=None):
        params = {"name": tool}
        if arguments is not None:
            params["arguments"] = arguments
        return self.request("tools/call", params)

    def close(self, timeout: float = 30.0) -> int:
        if not self.proc.stdin.closed:
            self.proc.stdin.close()
        rc = self.proc.wait(timeout=timeout)
        for thread in self._threads:
            thread.join(timeout=5)
        return rc

    def stop(self) -> None:
        try:
            self.close(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for stream in (self.proc.stdout, self.proc.stderr):
            stream.close()


class FakeCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeQrexec()
        self.addCleanup(self.fake.cleanup)


class InProcessFakeCase(FakeCase):
    """Runs qubes_mcp code in this process, against the fake client."""

    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.dict(os.environ, self.fake.overrides())
        patcher.start()
        self.addCleanup(patcher.stop)


class ServerCase(FakeCase):
    def setUp(self) -> None:
        super().setUp()
        self._servers: list[ServerProcess] = []

    def tearDown(self) -> None:
        for proc in self._servers:
            proc.stop()
            self.assertEqual(proc.foreign_lines, [], "stdout carried something other than "
                             "JSON-RPC reply lines")

    def start_server(self, version: str | None = "2025-06-18") -> ServerProcess:
        proc = ServerProcess(self.fake.env())
        self._servers.append(proc)
        if version is not None:
            reply = proc.request("initialize", {"protocolVersion": version, "capabilities": {},
                                                "clientInfo": {"name": "test", "version": "0"}})
            self.assertEqual(reply["result"]["protocolVersion"], version)
            proc.notify("notifications/initialized")
        return proc

    def result_of(self, reply) -> dict:
        """The tool result of a tools/call reply, checked for shape."""
        self.assertIn("result", reply, reply)
        result = reply["result"]
        self.assertIs(result["isError"], False, result)
        [content] = result["content"]
        self.assertEqual(content["type"], "text")
        parsed = json.loads(content["text"])
        # Compact JSON of the result dict.
        self.assertEqual(content["text"],
                         json.dumps(parsed, separators=(",", ":"), ensure_ascii=False))
        if "structuredContent" in result:
            self.assertEqual(result["structuredContent"], parsed)
        return parsed

    def assert_error(self, reply, code: int, msg_id, fragment: str = "") -> None:
        self.assertEqual(reply.get("id"), msg_id, reply)
        self.assertIn("error", reply, reply)
        self.assertEqual(reply["error"]["code"], code, reply)
        self.assertIn(fragment, reply["error"]["message"])


# --------------------------------------------------------------------------
# Registry and validator (in process)
# --------------------------------------------------------------------------

_FORBIDDEN = re.compile(
    r"\btiers?\b|\bai-exec\b|\bai-net\b|\bai-full\b|compat|\bflip|consent|\brings?\b"
    r"|spend_gate|GATED_TIMEOUT|ai-net-router", re.IGNORECASE)


class RegistryTests(unittest.TestCase):
    def test_exactly_the_24_tools(self):
        self.assertEqual(list(tools.TOOLS), EXPECTED_TOOLS)
        for name in REMOVED_TOOLS:
            self.assertNotIn(name, tools.TOOLS)

    def test_schemas_are_well_formed(self):
        for tool in tools.TOOLS.values():
            with self.subTest(tool=tool.name):
                schema = tool.input_schema
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)
                self.assertIsInstance(schema["properties"], dict)
                required = schema.get("required", [])
                self.assertLessEqual(set(required), set(schema["properties"]))
                self.assertEqual(len(required), len(set(required)))
                self.assertLessEqual(set(schema), tools.SCHEMA_KEYWORDS)
                for key, prop in schema["properties"].items():
                    self._check_property(f"{tool.name}.{key}", prop, key in required)

    def _check_property(self, where: str, prop: dict, required: bool) -> None:
        # Only keywords the validator implements, so it cannot silently ignore one.
        self.assertLessEqual(set(prop), tools.SCHEMA_KEYWORDS, where)
        types = prop["type"] if isinstance(prop["type"], list) else [prop["type"]]
        for json_type in types:
            self.assertIn(json_type, ("string", "integer", "boolean", "array", "object", "null"),
                          where)
        self.assertTrue(prop["description"].strip(), where)
        if "items" in prop:
            self.assertIn("array", types, where)
            self.assertLessEqual(set(prop["items"]), tools.SCHEMA_KEYWORDS, where)
        if required:
            self.assertNotIn("default", prop, f"{where}: a required argument has a default")
        if "default" in prop:
            self.assertIsNone(tools._problem(prop, prop["default"], where), where)
        if "object" in types:
            # An object argument (a lead's source) is held to the same rules one
            # level down: named properties only, each described and checked.
            self.assertIsInstance(prop.get("properties"), dict, where)
            self.assertIs(prop.get("additionalProperties"), False, where)
            inner = prop.get("required", [])
            self.assertLessEqual(set(inner), set(prop["properties"]), where)
            for key, sub in prop["properties"].items():
                self._check_property(f"{where}.{key}", sub, key in inner)
        else:
            self.assertFalse({"properties", "required", "additionalProperties"} & set(prop),
                             where)

    def test_proposal_descriptions_say_how_proposals_work(self):
        # What the operator asked every proposal tool to tell the model,
        # checked on the text with its line breaks folded.
        def flat(name: str) -> str:
            tool = tools.TOOLS[name]
            return " ".join((tool.description + json.dumps(tool.input_schema)).split())

        for name in PROPOSAL_TYPES:
            with self.subTest(tool=name):
                text = flat(name)
                for phrase in ("Nothing changes until the operator accepts the proposal in dom0",
                               "Only the hub can propose; a project's lead is refused.",
                               'closes as "failed"', "submit it again", "qubes_proposals",
                               "written by AI"):
                    self.assertIn(phrase, text)
                # A dump sink removes nothing and adds no network: no second tick.
                self.assertEqual("second tick" in text, name != "qubes_propose_dump")
        for phrase in ("keep_old, which has no default", "true keeps the old lead as a worker",
                       "false removes it with everything in it"):
            self.assertIn(phrase, flat("qubes_propose_lead"))
        self.assertIn("as it is when the operator accepts it", flat("qubes_propose_project_edit"))
        for phrase in ("pending", "accepted", "rejected", "expired", "failed",
                       "a project's lead is refused", "never a reason"):
            self.assertIn(phrase, flat("qubes_proposals"))
        for phrase in ('"projects"', "has_dump", '"projects" is null when'):
            self.assertIn(phrase, flat("qubes_get_pool_stats"))

    def test_descriptions_speak_the_two_state_model(self):
        for tool in tools.TOOLS.values():
            with self.subTest(tool=tool.name):
                text = tool.description + json.dumps(tool.input_schema)
                found = _FORBIDDEN.search(text)
                self.assertIsNone(found, found and found.group(0))
                first = tool.description.splitlines()[0]
                self.assertTrue(first.strip())
                self.assertLessEqual(len(first), 80)
        listing = tools.TOOLS["qubes_list"].description
        for word in ("managed", "guarded", "not found"):
            self.assertIn(word, listing)


class ValidatorTests(unittest.TestCase):
    def validate(self, name: str, arguments):
        return tools.validate_arguments(tools.TOOLS[name], arguments)

    def assert_rejected(self, name: str, arguments, fragment: str) -> None:
        with self.assertRaises(tools.ArgumentError) as caught:
            self.validate(name, arguments)
        self.assertIn(fragment, str(caught.exception))

    def test_a_boolean_is_not_an_integer(self):
        self.assert_rejected("qubes_run", {"name": "ai-a", "cmd": ["id"], "timeout": True},
                             "argument 'timeout': expected integer, got boolean")
        self.assert_rejected("qubes_spawn", {"name": "ai-a", "template": "t", "private_size": False},
                             "expected integer or null, got boolean")
        self.assert_rejected("qubes_events", {"duration": True}, "got boolean")

    def test_a_float_is_not_an_integer(self):
        for value in (1.5, 5.0):
            self.assert_rejected("qubes_events", {"duration": value}, "got number")

    def test_unknown_argument(self):
        self.assert_rejected("qubes_list", {"verbose": True}, "unknown argument 'verbose'")
        self.assert_rejected("qubes_start", {"name": "ai-a", "nmae": "x"}, "unknown argument 'nmae'")

    def test_missing_required_argument(self):
        self.assert_rejected("qubes_start", {}, "missing required argument 'name'")
        self.assert_rejected("qubes_props_set", {"name": "ai-a", "property": "label"},
                             "missing required argument 'value'")

    def test_array_items_are_checked(self):
        self.assert_rejected("qubes_run", {"name": "ai-a", "cmd": ["id", 1]},
                             "argument 'cmd'[1]: expected string, got integer")
        self.assert_rejected("qubes_events", {"duration": 1, "events": "domain-start"},
                             "expected array or null, got string")

    def test_enum(self):
        self.assert_rejected("qubes_spawn", {"name": "ai-a", "template": "t",
                                             "klass": "StandaloneVM"}, "must be one of")

    def test_value_types(self):
        self.assert_rejected("qubes_feature_set", {"name": "ai-a", "feature": "service.x",
                                                   "value": None}, "got null")
        self.assert_rejected("qubes_props_set", {"name": "ai-a", "property": "memory",
                                                 "value": [1]}, "got array")
        self.validate("qubes_props_set", {"name": "ai-a", "property": "netvm", "value": None})

    def test_arguments_must_be_an_object(self):
        with self.assertRaises(tools.ArgumentError):
            self.validate("qubes_list", [])
        self.assertEqual(self.validate("qubes_list", None), {})

    def test_defaults_are_applied(self):
        self.assertEqual(self.validate("qubes_run", {"name": "ai-a", "cmd": "ls"}),
                         {"name": "ai-a", "cmd": "ls", "shell": False, "timeout": 60, "stdin": ""})
        self.assertEqual(self.validate("qubes_events", {"duration": 3}),
                         {"duration": 3, "qube": None, "events": None})
        self.assertEqual(self.validate("qubes_copy", {"source": "a", "target": "b", "path": "p"})
                         ["timeout"], 300)

    def test_omitted_netvm_and_explicit_null_stay_different(self):
        omitted = self.validate("qubes_spawn", {"name": "ai-a", "template": "t"})
        self.assertNotIn("netvm", omitted)
        self.assertEqual((omitted["klass"], omitted["label"], omitted["private_size"]),
                         ("AppVM", "gray", None))
        explicit = self.validate("qubes_spawn", {"name": "ai-a", "template": "t", "netvm": None})
        self.assertIn("netvm", explicit)
        self.assertIsNone(explicit["netvm"])

    def test_input_is_not_modified(self):
        arguments = {"name": "ai-a", "cmd": ["id"]}
        self.validate("qubes_run", arguments)
        self.assertEqual(arguments, {"name": "ai-a", "cmd": ["id"]})

    def test_strict_json(self):
        for text in ("NaN", "Infinity", "-Infinity", '{"a": NaN}'):
            with self.assertRaises(ValueError):
                tools.parse_json(text)
        self.assertEqual(tools.parse_json('{"a": 1}'), {"a": 1})

    def test_unknown_tool(self):
        with self.assertRaises(tools.UnknownTool):
            tools.call_tool("qubes_device_list", {})

    def test_proposal_arguments_are_checked_at_every_depth(self):
        lead = {"from": "template", "qube": "debian-12-xfce"}
        base = {"title": "OSINT", "label": "osint", "lead": lead, "networks": ["ai-gw"],
                "quota": 1}
        self.validate("qubes_propose_project", base)
        for arguments, fragment in [
                ({**base, "lead": {"from": "template"}}, "missing required argument 'lead'.qube"),
                ({**base, "lead": {**lead, "name": "x"}}, "unknown argument 'lead'.name"),
                ({**base, "lead": {"from": "copy", "qube": "t"}},
                 "argument 'lead'.from: must be one of \"template\", \"clone\", \"promote\""),
                ({**base, "lead": {"from": "clone", "qube": 7}},
                 "argument 'lead'.qube: expected string, got integer"),
                ({**base, "lead": "debian-12-xfce"}, "argument 'lead': expected object, got string"),
                ({**base, "lead": None}, "argument 'lead': expected object, got null"),
                ({**base, "networks": "ai-gw"}, "argument 'networks': expected array, got string"),
                ({**base, "networks": [7]},
                 "argument 'networks'[0]: expected string or null, got integer"),
                ({**base, "templates": ["t", 1]},
                 "argument 'templates'[1]: expected string, got integer"),
                ({**base, "dump": "yes"}, "argument 'dump': expected boolean, got string"),
                ({**base, "dump": None}, "argument 'dump': expected boolean, got null"),
                ({**base, "title": 5}, "argument 'title': expected string, got integer"),
                # The tool names the type itself; an agent cannot pick another.
                ({**base, "type": "project-delete"}, "unknown argument 'type'"),
                ({k: v for k, v in base.items() if k != "title"}, "missing required argument 'title'"),
                ({k: v for k, v in base.items() if k != "quota"}, "missing required argument 'quota'")]:
            with self.subTest(arguments=arguments):
                self.assert_rejected("qubes_propose_project", arguments, fragment)
        for name, minimal in MINIMAL_PROPOSALS.items():
            with self.subTest(tool=name):
                self.assertEqual(self.validate(name, minimal), minimal)
                self.assert_rejected(name, {k: v for k, v in minimal.items() if k != "title"},
                                     "missing required argument 'title'")
                self.assert_rejected(name, {**minimal, "yes": True}, "unknown argument 'yes'")
        self.assert_rejected("qubes_propose_project_edit",
                             {"title": "t", "project": "osint", "add_networks": [True]},
                             "argument 'add_networks'[0]: expected string or null, got boolean")
        self.assert_rejected("qubes_propose_dump", {"title": "t", "project": 3},
                             "argument 'project': expected string, got integer")
        self.assert_rejected("qubes_proposals", {"id": "3"},
                             "argument 'id': expected integer or null, got string")

    def test_a_boolean_is_not_an_integer_in_proposals(self):
        base = {"title": "t", "project": "osint"}
        self.assert_rejected("qubes_propose_project",
                             {**MINIMAL_PROPOSALS["qubes_propose_project"], "quota": True},
                             "argument 'quota': expected integer or string, got boolean")
        self.assert_rejected("qubes_propose_project_edit", {**base, "quota": False},
                             "argument 'quota': expected integer, string or null, got boolean")
        self.assert_rejected("qubes_proposals", {"id": True},
                             "argument 'id': expected integer or null, got boolean")
        self.assert_rejected("qubes_proposals", {"id": 3.0}, "got number")
        # ...and an integer is not a boolean either: keep_old must be said as one.
        self.assert_rejected("qubes_propose_lead", {**base, "remove": 1},
                             "argument 'remove': expected boolean or null, got integer")
        self.assert_rejected("qubes_propose_lead",
                             {**base, "lead": {"from": "clone", "qube": "ai-a"}, "keep_old": 0},
                             "argument 'keep_old': expected boolean or null, got integer")

    def test_proposal_arguments_pass_as_given_with_no_defaults(self):
        # dom0 fills in what an omitted field means; the tool adds nothing.
        removal = {"title": "t", "project": "osint", "remove": True, "lead": None, "keep_old": None}
        self.assertEqual(self.validate("qubes_propose_lead", removal), removal)
        delete = {"title": "t", "project": "osint"}
        self.assertEqual(self.validate("qubes_propose_project_delete", delete), delete)
        self.assertEqual(self.validate("qubes_proposals", {}), {"id": None})

    def test_a_long_key_inside_an_object_is_capped(self):
        with self.assertRaises(tools.ArgumentError) as caught:
            self.validate("qubes_propose_lead", {"title": "t", "project": "osint",
                                                 "lead": {"from": "clone", "qube": "ai-a",
                                                          "k" * 500: 1}})
        message = str(caught.exception)
        self.assertTrue(message.startswith("unknown argument 'lead'.kkk"), message)
        self.assertTrue(message.endswith("..."), message)
        self.assertLess(len(message), 100)


class QuotaTests(unittest.TestCase):
    """A quota reaches dom0 in bytes: a size string is converted on the way,
    and one that cannot be is an argument error, never a dom0 call."""

    CREATE = {"title": "OSINT", "label": "osint", "networks": ["ai-gw"],
              "lead": {"from": "template", "qube": "debian-12-xfce"}}
    EDIT = {"title": "More disk", "project": "osint"}

    def edit(self, quota) -> dict:
        return tools.validate_arguments(tools.TOOLS["qubes_propose_project_edit"],
                                        {**self.EDIT, "quota": quota})

    def assert_refused(self, quota, fragment: str) -> None:
        for name, base in (("qubes_propose_project", self.CREATE),
                           ("qubes_propose_project_edit", self.EDIT)):
            with self.subTest(tool=name, quota=quota), \
                    self.assertRaises(tools.ArgumentError) as caught:
                tools.validate_arguments(tools.TOOLS[name], {**base, "quota": quota})
            self.assertIn(fragment, str(caught.exception))

    def test_sizes_become_bytes(self):
        for text, expected in [("40G", 40 * GiB), ("512M", 512 * 1024 ** 2), ("1T", 1024 ** 4),
                               ("8K", 8192), ("100B", 100), ("4096", 4096), ("40GiB", 40 * GiB),
                               ("40gb", 40 * GiB), ("2t", 2 * 1024 ** 4), (" 40 G ", 40 * GiB),
                               ("1048576T", 2 ** 60)]:
            with self.subTest(text=text):
                self.assertEqual(self.edit(text)["quota"], expected)
        for number in (1, 40 * GiB, 2 ** 60):
            self.assertEqual(self.edit(number)["quota"], number)
        for past in ("9" * 20, 10 ** 30, 2 ** 60 + 1, "1048577T"):
            with self.subTest(past=past), self.assertRaises(tools.ArgumentError) as caught:
                self.edit(past)
            self.assertIn("at most 1 EiB", str(caught.exception))
        created = tools.validate_arguments(tools.TOOLS["qubes_propose_project"],
                                           {**self.CREATE, "quota": "40G"})
        self.assertEqual(created, {**self.CREATE, "quota": 40 * GiB})

    def test_junk_is_not_a_size(self):
        for text in ("", " ", "G", "40X", "forty", "1.5G", "-1G", "+1G", "1e9", "0x10", "40 G B",
                     "4O96", "40GG", "1" + "0" * 20, "40G\n\n1"):
            self.assert_refused(text, "is not a size: give bytes, or a whole number")

    def test_zero_and_negative_are_refused(self):
        for value in (0, -1, -(2 ** 40), "0", "0G", "000T"):
            self.assert_refused(value, "argument 'quota': must be more than zero bytes")

    def test_a_boolean_or_a_float_is_refused_by_type(self):
        self.assert_refused(True, "got boolean")
        self.assert_refused(False, "got boolean")
        self.assert_refused(4.5, "got number")
        self.assert_refused(4096.0, "got number")
        # The converter refuses a boolean by itself too, should a schema ever allow one.
        with self.assertRaises(tools.ArgumentError):
            tools._size_bytes(True, "argument 'quota'")

    def test_null_and_omitted_leave_an_edit_quota_unchanged(self):
        self.assertIsNone(self.edit(None)["quota"])
        omitted = tools.validate_arguments(tools.TOOLS["qubes_propose_project_edit"],
                                           {**self.EDIT, "add_templates": ["t"]})
        self.assertNotIn("quota", omitted)

    def test_a_new_project_needs_a_quota(self):
        with self.assertRaises(tools.ArgumentError) as caught:
            tools.validate_arguments(tools.TOOLS["qubes_propose_project"],
                                     {**self.CREATE, "quota": None})
        self.assertIn("argument 'quota': expected integer or string, got null",
                      str(caught.exception))

    def test_the_caller_s_arguments_are_not_modified(self):
        arguments = {**self.EDIT, "quota": "40G"}
        converted = tools.validate_arguments(tools.TOOLS["qubes_propose_project_edit"], arguments)
        self.assertEqual(converted["quota"], 40 * GiB)
        self.assertEqual(arguments["quota"], "40G")

    def test_only_the_tools_with_a_quota_convert(self):
        converting = {name for name, tool in tools.TOOLS.items() if tool.prepare is not None}
        self.assertEqual(converting, {"qubes_propose_project", "qubes_propose_project_edit"})


# --------------------------------------------------------------------------
# qrexec transport (in process, against the fake client)
# --------------------------------------------------------------------------

class QrexecTests(InProcessFakeCase):
    def test_target_shape(self):
        for name in ("ai-work", "a", "a" * 31, "Work_1.x-y"):
            self.assertTrue(qrexec._valid_target(name), name)
        for name in ("dom0", "DOM0", "Dom0", "@adminvm", "@dispvm", "@dispvm:ai-dvm",
                     "@tag:ai-managed", "@default", "a\n", "ai-x\n", "a\r", "a b", "", "-x",
                     "1abc", "a" * 32, "a\x00", "a/b", None, 5, ["a"]):
            self.assertFalse(qrexec._valid_target(name), repr(name))

    def test_default_client_path(self):
        self.assertEqual(qrexec.client_path(), str(self.fake.client))
        with mock.patch.dict(os.environ, {qrexec.CLIENT_ENV: ""}):
            self.assertEqual(qrexec.client_path(), "/usr/lib/qubes/qrexec-client-vm")
        with mock.patch.dict(os.environ):
            del os.environ[qrexec.CLIENT_ENV]
            self.assertEqual(qrexec.client_path(), "/usr/lib/qubes/qrexec-client-vm")

    def test_dom0_replies_pass_through(self):
        self.fake.answer({"qmcp.GetPoolStats": {"json": {"ok": True, "n": 1}}})
        self.assertEqual(qrexec.call_qmcp("qmcp.GetPoolStats"), {"ok": True, "n": 1})

    def test_a_dom0_refusal_passes_through_unchanged(self):
        # The dom0 services exit 1 after printing a refusal; it must still arrive.
        refusal = {"ok": False, "error": "pool cap exceeded", "detail": [1, 2]}
        self.fake.answer({"qmcp.GetPoolStats": {"json": refusal}})
        self.assertEqual(qrexec.call_qmcp("qmcp.GetPoolStats"), refusal)
        self.fake.answer({"ai-a qmcp.RunInAIManaged": {"json": refusal}})
        self.assertEqual(qrexec.call_service("ai-a", "qmcp.RunInAIManaged", {}), refusal)

    def test_every_transport_failure_is_the_same_refusal(self):
        cases = {
            "empty": {"raw": ""},
            "whitespace": {"raw": "  \n"},
            "garbage": {"raw": "Traceback (most recent call last):\n  oops"},
            "truncated": {"raw": '{"ok": tr'},
            "array": {"raw": "[1, 2]"},
            "string": {"raw": '"ok"'},
            "nan": {"raw": '{"ok": NaN}'},
            "not utf-8": {"raw_hex": "fffe7b7d"},
            "stderr detail": {"raw": "", "stderr": "qubesd: pool detail", "rc": 1},
            "policy denial": {"raw": "", "stderr": "Request refused", "rc": 126},
        }
        with self.assertLogs("qubes_mcp.qrexec", level="INFO"):
            for label, response in cases.items():
                with self.subTest(label):
                    self.fake.answer({"qmcp.GetPoolStats": response,
                                      "qmcp.RunInAIManaged": response})
                    self.assertEqual(qrexec.call_qmcp("qmcp.GetPoolStats"), REFUSED)
                    self.assertEqual(qrexec.call_service("ai-a", "qmcp.RunInAIManaged", {}),
                                     REFUSED)

    def test_a_timeout_is_the_same_refusal(self):
        self.fake.answer({"qmcp.GetPoolStats": {"sleep": 5, "json": {"ok": True}}})
        start = time.monotonic()
        with self.assertLogs("qubes_mcp.qrexec", level="WARNING") as logs:
            self.assertEqual(qrexec.call_qmcp("qmcp.GetPoolStats", timeout=0.5), REFUSED)
        self.assertLess(time.monotonic() - start, 4)
        self.assertIn("no answer within", "\n".join(logs.output))

    def test_an_absurd_timeout_is_clamped_not_raised(self):
        self.assertEqual(qrexec.call_qmcp("qmcp.GetPoolStats", timeout=10 ** 30), {"ok": True})

    def test_a_client_that_cannot_start_is_the_same_refusal(self):
        missing = self.fake.root / "absent"
        not_executable = self.fake.root / "plain-file"
        not_executable.write_text("#!/bin/sh\n")
        for client in (missing, not_executable):
            with self.subTest(client=client.name), \
                    mock.patch.dict(os.environ, {qrexec.CLIENT_ENV: str(client)}), \
                    self.assertLogs("qubes_mcp.qrexec", level="WARNING"):
                self.assertEqual(qrexec.call_qmcp("qmcp.GetPoolStats"), REFUSED)
                self.assertEqual(qrexec.call_service("ai-a", "qmcp.RunInAIManaged", {}), REFUSED)
                self.assertEqual(qrexec.call_admin("admin.vm.firewall.Get", "ai-a"), REFUSED)

    def test_invalid_targets_never_start_a_process(self):
        for name in ("dom0", "@adminvm", "a\n"):
            self.assertEqual(qrexec.call_service(name, "qmcp.RunInAIManaged", {}), REFUSED)
            self.assertEqual(qrexec.call_admin("admin.vm.firewall.Get", name), REFUSED)
        self.assertEqual(self.fake.calls(), [])

    def test_admin_framing(self):
        cases = [
            ({"raw": "0\x00action=drop\n"}, {"ok": True, "stdout": "action=drop\n"}),
            ({"raw": "0\x00"}, {"ok": True, "stdout": ""}),
            ({"raw": "2\x00QubesException\x00\x00internal detail\x00"}, REFUSED),
            ({"raw": "0\x00action=drop\n", "rc": 1}, REFUSED),
            ({"raw": "", "rc": 126}, REFUSED),
            ({"raw": "action=drop\n"}, {"ok": True, "stdout": "action=drop\n"}),  # unframed
        ]
        for response, expected in cases:
            with self.subTest(response=response):
                self.fake.answer({"admin.vm.firewall.Get": response})
                self.assertEqual(qrexec.call_admin("admin.vm.firewall.Get", "ai-a"), expected)

    def test_requests_are_ascii_json(self):
        qrexec.call_qmcp("qmcp.GetPoolStats", {"name": "café"})
        [entry] = self.fake.log_path.read_text().splitlines()
        stdin = json.loads(entry)["stdin"]
        self.assertTrue(stdin.isascii())
        self.assertEqual(json.loads(stdin), {"name": "café"})


class ClientTimeoutTests(unittest.TestCase):
    """Which target, service and client-side timeout each tool uses."""

    def calls_made(self, name: str, arguments: dict) -> list:
        seen = []

        def fake_run(target, service, stdin, timeout):
            seen.append((target, service, timeout))
            if service.startswith("admin."):
                out = b"0\x00"
            elif service == "qmcp.SpawnDisposableAIManaged":
                out = b'{"ok": true, "name": "disp7"}'
            elif service == PROP:
                out = b'{"ok": true, "value": "Running"}'
            else:
                out = b'{"ok": true}'
            return subprocess.CompletedProcess([target, service], 0, out, b"")

        with mock.patch.object(qrexec, "_run", fake_run):
            tools.call_tool(name, arguments)
        return seen

    def test_timeouts(self):
        cases = [
            ("qubes_list", {}, [(A, "qmcp.ListAIManagedQubes", 60)]),
            ("qubes_get_pool_stats", {}, [(A, "qmcp.GetPoolStats", 60)]),
            ("qubes_state", {"name": "ai-a"}, [(A, PROP, 60)] * 4),
            ("qubes_props_get", {"name": "ai-a", "properties": ["memory"]}, [(A, PROP, 60)]),
            ("qubes_props_set", {"name": "ai-a", "property": "vcpus", "value": 2},
             [(A, "qmcp.SetPropertyAIManaged", 60)]),
            ("qubes_feature_set", {"name": "ai-a", "feature": "service.x", "value": True},
             [(A, "qmcp.SetFeatureAIManaged", 60)]),
            ("qubes_spawn", {"name": "ai-b", "template": "ai-t"},
             [(A, "qmcp.SpawnAIManagedQube", 300)]),
            ("qubes_clone", {"source": "ai-a", "name": "ai-b"},
             [(A, "qmcp.CloneAIManagedQube", 300)]),
            ("qubes_spawn_disposable", {"template": "ai-dvm"},
             [(A, "qmcp.SpawnDisposableAIManaged", 300)]),
            ("qubes_start", {"name": "ai-a"}, [(A, LIFE, 120)]),
            ("qubes_shutdown", {"name": "ai-a"}, [(A, LIFE, 120)]),
            ("qubes_remove", {"name": "ai-a"}, [(A, LIFE, 120)]),
            ("qubes_events", {"duration": 45}, [(A, "qmcp.AIManagedEvents", 55)]),
            ("qubes_events", {"duration": 0}, [(A, "qmcp.AIManagedEvents", 11)]),
            ("qubes_events", {"duration": -7}, [(A, "qmcp.AIManagedEvents", 11)]),
            ("qubes_run", {"name": "ai-a", "cmd": "true"}, [("ai-a", "qmcp.RunInAIManaged", 90)]),
            ("qubes_run", {"name": "ai-a", "cmd": "true", "timeout": 7},
             [("ai-a", "qmcp.RunInAIManaged", 37)]),
            ("qubes_copy", {"source": "ai-a", "target": "ai-b", "path": "/x"},
             [("ai-a", "qmcp.CopyToAIManaged", 330)]),
            ("qubes_copy", {"source": "ai-a", "target": "ai-b", "path": "/x", "timeout": 10},
             [("ai-a", "qmcp.CopyToAIManaged", 40)]),
            ("qubes_firewall_get", {"name": "ai-a"}, [("ai-a", "admin.vm.firewall.Get", 60)]),
            ("qubes_firewall_set", {"name": "ai-a", "rules": "action=drop"},
             [("ai-a", "admin.vm.firewall.Set", 60), ("ai-a", "admin.vm.firewall.Reload", 60)]),
            ("qubes_run_disposable", {"template": "ai-dvm", "cmd": ["id"], "timeout": 5},
             [(A, "qmcp.SpawnDisposableAIManaged", 300), (A, LIFE, 120), (A, PROP, 60),
              ("disp7", "qmcp.RunInAIManaged", 35), (A, LIFE, 120)]),
            ("qubes_proposals", {}, [(A, STATUS, 60)]),
            ("qubes_proposals", {"id": 4}, [(A, STATUS, 60)]),
        ] + [(name, arguments, [(A, SUBMIT, 60)])
             for name, arguments in MINIMAL_PROPOSALS.items()]
        covered = {name for name, _, _ in cases}
        self.assertEqual(covered, set(EXPECTED_TOOLS))
        for name, arguments, expected in cases:
            with self.subTest(tool=name, arguments=arguments):
                self.assertEqual(self.calls_made(name, arguments), expected)


class RunDisposableWaitTests(InProcessFakeCase):
    def test_a_disposable_that_never_runs_is_killed(self):
        self.fake.answer({PROP: {"json": {"ok": True, "value": "Halted"}}})
        with mock.patch.object(tools, "_START_POLL_ATTEMPTS", 3), \
                mock.patch.object(tools, "_START_POLL_INTERVAL_SECONDS", 0.01):
            result = tools.call_tool("qubes_run_disposable", {"template": "ai-dvm", "cmd": ["id"]})
        self.assertEqual(result, {"ok": False, "name": "disp1234", "stage": "wait",
                                  "error": "disposable did not reach Running state in time"})
        poll = (A, PROP, {"name": "disp1234", "property": "power_state"})
        self.assertEqual(self.fake.calls(), [
            (A, "qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"}),
            (A, LIFE, {"name": "disp1234", "action": "start"}),
            poll, poll, poll,
            (A, LIFE, {"name": "disp1234", "action": "kill"}),
        ])


# --------------------------------------------------------------------------
# The server in process: failure paths that need a custom registry
# --------------------------------------------------------------------------

def _tool(name: str, handler) -> tools.Tool:
    return tools.Tool(name, "A test tool.", {"type": "object", "properties": {},
                                             "additionalProperties": False}, handler)


class InProcessServerTests(unittest.TestCase):
    def make(self, *registered: tools.Tool):
        out = io.BytesIO()
        srv = server.Server(out, registry={t.name: t for t in registered})
        self.addCleanup(srv.drain, 5)
        return srv, out

    @staticmethod
    def replies(out: io.BytesIO) -> list:
        return [json.loads(line) for line in out.getvalue().splitlines()]

    @staticmethod
    def call_line(name: str, msg_id=1) -> bytes:
        return json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
                           "params": {"name": name}}).encode() + b"\n"

    def test_an_exception_is_an_internal_error_and_its_text_stays_on_stderr(self):
        def boom(args):
            raise RuntimeError("detail that must not reach the agent")
        srv, out = self.make(_tool("boom", boom))
        with self.assertLogs("qubes_mcp.server", level="ERROR") as logs:
            srv.handle_line(self.call_line("boom"))
            self.assertTrue(srv.drain(5))
        [reply] = self.replies(out)
        self.assertEqual(reply["result"], {"content": [{"type": "text", "text": "internal error"}],
                                           "isError": True})
        self.assertNotIn(b"must not reach", out.getvalue())
        self.assertIn("detail that must not reach the agent", "\n".join(logs.output))

    def test_a_result_that_is_not_a_dict_or_not_json_is_an_internal_error(self):
        srv, out = self.make(_tool("listy", lambda args: ["x"]),
                             _tool("nan", lambda args: {"ok": True, "x": float("nan")}))
        with self.assertLogs("qubes_mcp.server", level="ERROR"):
            srv.handle_line(self.call_line("listy", 1))
            srv.handle_line(self.call_line("nan", 2))
            self.assertTrue(srv.drain(5))
        for reply in self.replies(out):
            self.assertIs(reply["result"]["isError"], True)

    def test_drain_reports_a_call_still_running(self):
        release = threading.Event()
        srv, out = self.make(_tool("slow", lambda args: (release.wait(10), {"ok": True})[1]))
        srv.handle_line(self.call_line("slow"))
        with self.assertLogs("qubes_mcp.server", level="WARNING"):
            self.assertFalse(srv.drain(0.2))
        release.set()

    def test_a_closed_stdout_does_not_stop_the_server(self):
        srv, out = self.make()
        out.close()
        with self.assertLogs("qubes_mcp.server", level="ERROR"):
            srv.handle_line(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        srv.handle_line(b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n')

    def test_claimed_stdout_carries_only_protocol_lines(self):
        # main() moves fd 1 to stderr: prints and child processes land there.
        script = ("import os, sys\n"
                  "from qubes_mcp import server\n"
                  "out = server._claim_stdout()\n"
                  "print('stray print')\n"
                  "os.system('echo child process')\n"
                  "out.write(b'protocol\\n'); out.flush()\n")
        done = subprocess.run([sys.executable, "-c", script], cwd=str(PUBLIC_DIR),
                              env={**os.environ, "PYTHONPATH": str(PUBLIC_DIR)},
                              capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, b"protocol\n")
        self.assertIn(b"stray print", done.stderr)
        self.assertIn(b"child process", done.stderr)


# --------------------------------------------------------------------------
# MCP protocol, over a real stdio subprocess
# --------------------------------------------------------------------------

class ProtocolTests(ServerCase):
    def test_initialize_echoes_each_supported_version(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                proc = self.start_server(version=None)
                reply = proc.request("initialize", {"protocolVersion": version, "capabilities": {},
                                                    "clientInfo": {"name": "t", "version": "0"}})
                self.assertEqual(reply["result"], {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "qubes-mcp", "version": qubes_mcp.__version__},
                })
                self.assertEqual(proc.close(), 0)

    def test_initialize_answers_the_latest_version_otherwise(self):
        proc = self.start_server(version=None)
        for params in ({"protocolVersion": "1999-01-01"}, {}, {"protocolVersion": 20250618}):
            with self.subTest(params=params):
                reply = proc.request("initialize", params)
                self.assertEqual(reply["result"]["protocolVersion"], "2025-06-18")

    def test_structured_content_only_on_2025_06_18(self):
        self.fake.answer({"qmcp.GetPoolStats": {"json": {"ok": True, "ai_managed_bytes_used": 5}}})
        for version in VERSIONS:
            with self.subTest(version=version):
                proc = self.start_server(version=version)
                result = proc.call("qubes_get_pool_stats")["result"]
                self.assertEqual(self.result_of({"result": result}),
                                 {"ok": True, "ai_managed_bytes_used": 5})
                if version == "2025-06-18":
                    self.assertEqual(result["structuredContent"],
                                     {"ok": True, "ai_managed_bytes_used": 5})
                else:
                    self.assertNotIn("structuredContent", result)

    def test_tools_list(self):
        proc = self.start_server()
        listed = proc.request("tools/list")["result"]["tools"]
        self.assertEqual([t["name"] for t in listed], EXPECTED_TOOLS)
        for entry in listed:
            with self.subTest(tool=entry["name"]):
                self.assertEqual(set(entry), {"name", "description", "inputSchema"})
                self.assertTrue(entry["description"].strip())
                schema = entry["inputSchema"]
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)
                self.assertLessEqual(set(schema.get("required", [])), set(schema["properties"]))

    def test_ping(self):
        proc = self.start_server(version=None)
        self.assertEqual(proc.request("ping")["result"], {})

    def test_unknown_method(self):
        proc = self.start_server()
        for method in ("resources/list", "prompts/list", "logging/setLevel"):
            reply = proc.request(method)
            self.assert_error(reply, server.METHOD_NOT_FOUND, reply["id"], method)

    def test_notifications_get_no_reply(self):
        proc = self.start_server()
        proc.notify("notifications/cancelled", {"requestId": 99, "reason": "test"})
        proc.notify("notifications/made-up")
        proc.notify("ping")
        # A tool call without an id is not executed.
        proc.notify("tools/call", {"name": "qubes_list"})
        proc.send({"jsonrpc": "2.0", "id": "after", "method": "ping"})
        self.assertEqual(proc.recv()["id"], "after")
        self.assertEqual(self.fake.calls(), [])

    def test_client_responses_are_ignored(self):
        proc = self.start_server()
        proc.send({"jsonrpc": "2.0", "id": 77, "result": {}})
        proc.send({"jsonrpc": "2.0", "id": 78, "error": {"code": 1, "message": "x"}})
        proc.send({"jsonrpc": "2.0", "id": "after", "method": "ping"})
        self.assertEqual(proc.recv()["id"], "after")

    def test_parse_errors(self):
        proc = self.start_server()
        for raw in (b"{not json\n", b"\xff\xfe\n", b"[1, 2\n", b'{"a": NaN}\n',
                    b"9" * 5000 + b"\n", b"[" * 100000 + b"\n"):
            with self.subTest(raw=raw[:20]):
                proc.send_raw(raw)
                self.assertEqual(proc.recv(), {"jsonrpc": "2.0", "id": None,
                                               "error": {"code": -32700, "message": "parse error"}})
        self.assertEqual(proc.request("ping")["result"], {})

    def test_blank_lines_are_ignored(self):
        proc = self.start_server()
        proc.send_raw(b"\n   \n\r\n")
        proc.send({"jsonrpc": "2.0", "id": "after", "method": "ping"})
        self.assertEqual(proc.recv()["id"], "after")

    def test_invalid_requests(self):
        proc = self.start_server()
        cases = [
            ({"jsonrpc": "2.0", "id": 1}, 1),                        # no method
            ({"jsonrpc": "1.0", "id": 2, "method": "ping"}, 2),
            ({"id": 3, "method": "ping"}, 3),                        # no jsonrpc
            ({"jsonrpc": "2.0", "id": 4, "method": 7}, 4),
            ({"jsonrpc": "2.0", "id": 5, "method": "ping", "params": 3}, 5),
            ({"jsonrpc": "2.0", "id": None, "method": "ping"}, None),
            ({"jsonrpc": "2.0", "id": True, "method": "ping"}, None),
            ({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}, None),
            ({"jsonrpc": "2.0", "id": [1], "method": "ping"}, None),
            (7, None),
            ("ping", None),
        ]
        for message, reply_id in cases:
            with self.subTest(message=message):
                proc.send(message)
                self.assert_error(proc.recv(), server.INVALID_REQUEST, reply_id)

    def test_string_and_integer_ids_are_echoed(self):
        proc = self.start_server()
        for msg_id in ("abc", 0, -5, 2 ** 40):
            proc.send({"jsonrpc": "2.0", "id": msg_id, "method": "ping"})
            self.assertEqual(proc.recv(), {"jsonrpc": "2.0", "id": msg_id, "result": {}})

    def test_bad_tools_call_params(self):
        proc = self.start_server()
        cases = [
            ({"name": "qubes_device_list"}, "unknown tool: 'qubes_device_list'"),
            ({"name": "qubes_install_pkg", "arguments": {}}, "unknown tool"),
            ({}, "params.name"),
            ({"name": 5}, "params.name"),
            ({"name": "qubes_list", "arguments": [1]}, "arguments must be an object"),
        ]
        for params, fragment in cases:
            with self.subTest(params=params):
                reply = proc.request("tools/call", params)
                self.assert_error(reply, server.INVALID_PARAMS, reply["id"], fragment)
        reply = proc.request("tools/call", [1, 2])
        self.assert_error(reply, server.INVALID_PARAMS, reply["id"], "params must be an object")
        self.assertEqual(self.fake.calls(), [])

    def test_invalid_arguments(self):
        proc = self.start_server()
        cases = [
            ("qubes_run", {"name": "ai-a", "cmd": ["id"], "timeout": True},
             "argument 'timeout': expected integer, got boolean"),
            ("qubes_spawn", {"name": "ai-a", "template": "ai-t", "private_size": True},
             "got boolean"),
            ("qubes_events", {"duration": 1.5}, "got number"),
            ("qubes_list", {"verbose": True}, "unknown argument 'verbose'"),
            ("qubes_start", {}, "missing required argument 'name'"),
            ("qubes_spawn", {"name": "ai-a", "template": "ai-t", "klass": "TemplateVM"},
             "must be one of"),
            ("qubes_feature_set", {"name": "ai-a", "feature": "service.x", "value": None},
             "got null"),
            ("qubes_propose_project_edit", {"title": "t", "project": "osint", "quota": "lots"},
             "argument 'quota': 'lots' is not a size"),
            ("qubes_propose_project_edit", {"title": "t", "project": "osint", "quota": 0},
             "argument 'quota': must be more than zero bytes"),
            ("qubes_propose_project", {**MINIMAL_PROPOSALS["qubes_propose_project"],
                                       "quota": True}, "got boolean"),
            ("qubes_propose_project", {**MINIMAL_PROPOSALS["qubes_propose_project"],
                                       "lead": {"from": "steal", "qube": "x"}},
             "argument 'lead'.from: must be one of"),
            ("qubes_propose_lead", {"title": "t", "project": "osint", "keep_old": "no"},
             "argument 'keep_old': expected boolean or null, got string"),
            ("qubes_propose_project_delete", {"title": "t", "project": "osint", "type": "x"},
             "unknown argument 'type'"),
            ("qubes_proposals", {"id": False}, "got boolean"),
        ]
        for tool, arguments, fragment in cases:
            with self.subTest(tool=tool, arguments=arguments):
                reply = proc.call(tool, arguments)
                self.assert_error(reply, server.INVALID_PARAMS, reply["id"], fragment)
                self.assertTrue(reply["error"]["message"].startswith(
                    f"invalid arguments for {tool}: "), reply)
        self.assertEqual(self.fake.calls(), [])

    def test_batch(self):
        proc = self.start_server()
        proc.send([
            {"jsonrpc": "2.0", "id": "a", "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": "b", "method": "tools/call", "params": {"name": "qubes_list"}},
            {"jsonrpc": "2.0", "id": "c", "method": "no/such/method"},
            5,
        ])
        replies = proc.recv()
        self.assertIsInstance(replies, list)
        self.assertEqual([r["id"] for r in replies], ["a", "b", "c", None])
        self.assertEqual(replies[0]["result"], {})
        self.assertEqual(self.result_of(replies[1]), {"ok": True, "qubes": []})
        self.assertEqual(replies[2]["error"]["code"], server.METHOD_NOT_FOUND)
        self.assertEqual(replies[3]["error"]["code"], server.INVALID_REQUEST)

    def test_empty_batch(self):
        proc = self.start_server()
        proc.send([])
        self.assert_error(proc.recv(), server.INVALID_REQUEST, None, "empty batch")

    def test_a_batch_of_notifications_gets_no_reply(self):
        proc = self.start_server()
        proc.send([{"jsonrpc": "2.0", "method": "notifications/initialized"},
                   {"jsonrpc": "2.0", "method": "notifications/cancelled"}])
        proc.send({"jsonrpc": "2.0", "id": "after", "method": "ping"})
        self.assertEqual(proc.recv()["id"], "after")

    def test_a_slow_events_call_does_not_block_a_fast_call(self):
        self.fake.answer({"qmcp.AIManagedEvents": {"sleep": 2.5, "json": {"ok": True, "events": []}}})
        proc = self.start_server()
        start = time.monotonic()
        proc.send({"jsonrpc": "2.0", "id": "slow", "method": "tools/call",
                   "params": {"name": "qubes_events", "arguments": {"duration": 2}}})
        proc.send({"jsonrpc": "2.0", "id": "fast", "method": "tools/call",
                   "params": {"name": "qubes_list"}})
        first = proc.recv()
        self.assertEqual(first["id"], "fast")
        self.assertLess(time.monotonic() - start, 2.0)
        second = proc.recv()
        self.assertEqual(second["id"], "slow")
        self.assertEqual(self.result_of(second), {"ok": True, "events": []})

    def test_clean_exit_on_eof(self):
        proc = self.start_server()
        self.assertEqual(proc.close(timeout=10), 0)
        quiet = self.start_server(version=None)
        self.assertEqual(quiet.close(timeout=10), 0)
        self.assertEqual(quiet.stdout_lines, [])

    def test_an_in_flight_call_is_answered_after_eof(self):
        self.fake.answer({"qmcp.RunInAIManaged": {"sleep": 1, "json": {"ok": True, "rc": 0}}})
        proc = self.start_server()
        proc.send({"jsonrpc": "2.0", "id": "last", "method": "tools/call",
                   "params": {"name": "qubes_run", "arguments": {"name": "ai-a", "cmd": ["true"]}}})
        proc.proc.stdin.close()
        reply = proc.recv()
        self.assertEqual(reply["id"], "last")
        self.assertEqual(self.result_of(reply), {"ok": True, "rc": 0})
        self.assertEqual(proc.close(timeout=10), 0)

    def test_stdout_carries_only_replies_while_logs_go_to_stderr(self):
        # A non-JSON reply from dom0 makes the transport log a warning.
        self.fake.answer({"qmcp.GetPoolStats": {"raw": "<html>not json</html>"},
                          "qmcp.RunInAIManaged": {"json": {"ok": True, "rc": 0,
                                                           "stdout": "café \u0085\nend"}}})
        proc = self.start_server()
        self.assertEqual(self.result_of(proc.call("qubes_get_pool_stats")), REFUSED)
        result = self.result_of(proc.call("qubes_run", {"name": "ai-a", "cmd": ["cat"]}))
        self.assertEqual(result["stdout"], "café \u0085\nend")
        self.assertEqual(proc.close(), 0)
        self.assertEqual(proc.foreign_lines, [])
        self.assertEqual(len(proc.stdout_lines), 3)        # initialize + two calls
        self.assertIn("not JSON", proc.stderr_text())


# --------------------------------------------------------------------------
# Tools, over the protocol, against the fake client
# --------------------------------------------------------------------------

D = "disp1234"
RUN_ARGS = {"template": "ai-dvm", "cmd": ["make", "test"], "timeout": 20, "stdin": "in"}
RUN_PAYLOAD = {"cmd": ["make", "test"], "shell": False, "timeout": 20, "stdin": "in"}
SPAWN = (A, "qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})
START = (A, LIFE, {"name": D, "action": "start"})
POLL = (A, PROP, {"name": D, "property": "power_state"})
RUN = (D, "qmcp.RunInAIManaged", RUN_PAYLOAD)
SHUTDOWN = (A, LIFE, {"name": D, "action": "shutdown"})
KILL = (A, LIFE, {"name": D, "action": "kill"})

_SPAWN_BASE = {"name": "ai-new", "template": "ai-tpl", "klass": "AppVM", "label": "gray"}
_RULES = "action=accept proto=tcp dstports=443\naction=drop\n"

PAYLOAD_CASES = [
    ("qubes_list", {}, [(A, "qmcp.ListAIManagedQubes", None)]),
    ("qubes_spawn", {"name": "ai-new", "template": "ai-tpl"},
     [(A, "qmcp.SpawnAIManagedQube", _SPAWN_BASE)]),
    ("qubes_spawn", {"name": "ai-new", "template": "ai-tpl", "private_size": None},
     [(A, "qmcp.SpawnAIManagedQube", _SPAWN_BASE)]),
    ("qubes_spawn", {"name": "ai-new", "template": "ai-tpl", "netvm": None},
     [(A, "qmcp.SpawnAIManagedQube", {**_SPAWN_BASE, "netvm": None})]),
    ("qubes_spawn", {"name": "ai-d", "template": "ai-dvm", "klass": "DispVM", "label": "red",
                     "netvm": "ai-gw", "private_size": 4294967296},
     [(A, "qmcp.SpawnAIManagedQube", {"name": "ai-d", "template": "ai-dvm", "klass": "DispVM",
                                      "label": "red", "netvm": "ai-gw",
                                      "private_size": 4294967296})]),
    ("qubes_state", {"name": "ai-a"},
     [(A, PROP, {"name": "ai-a", "property": p})
      for p in ("power_state", "netvm", "template", "provides_network")]),
    ("qubes_props_get", {"name": "ai-a", "properties": ["memory", "vcpus"]},
     [(A, PROP, {"name": "ai-a", "property": "memory"}),
      (A, PROP, {"name": "ai-a", "property": "vcpus"})]),
    ("qubes_props_set", {"name": "ai-a", "property": "memory", "value": 2048},
     [(A, "qmcp.SetPropertyAIManaged", {"name": "ai-a", "property": "memory", "value": 2048})]),
    ("qubes_props_set", {"name": "ai-a", "property": "netvm", "value": None},
     [(A, "qmcp.SetPropertyAIManaged", {"name": "ai-a", "property": "netvm", "value": None})]),
    ("qubes_start", {"name": "ai-a"}, [(A, LIFE, {"name": "ai-a", "action": "start"})]),
    ("qubes_shutdown", {"name": "ai-a"}, [(A, LIFE, {"name": "ai-a", "action": "shutdown"})]),
    ("qubes_shutdown", {"name": "ai-a", "force": True},
     [(A, LIFE, {"name": "ai-a", "action": "kill"})]),
    ("qubes_remove", {"name": "ai-a"}, [(A, LIFE, {"name": "ai-a", "action": "remove"})]),
    ("qubes_run", {"name": "ai-a", "cmd": ["id", "-u"]},
     [("ai-a", "qmcp.RunInAIManaged", {"cmd": ["id", "-u"], "shell": False, "timeout": 60,
                                        "stdin": ""})]),
    ("qubes_run", {"name": "ai-a", "cmd": "echo hi | wc -c", "shell": True, "timeout": 5,
                   "stdin": "x\n"},
     [("ai-a", "qmcp.RunInAIManaged", {"cmd": "echo hi | wc -c", "shell": True, "timeout": 5,
                                        "stdin": "x\n"})]),
    ("qubes_copy", {"source": "ai-a", "target": "ai-b", "path": "/srv/out.txt"},
     [("ai-a", "qmcp.CopyToAIManaged", {"target": "ai-b", "path": "/srv/out.txt"})]),
    ("qubes_firewall_get", {"name": "ai-a"}, [("ai-a", "admin.vm.firewall.Get", "")]),
    ("qubes_firewall_set", {"name": "ai-a", "rules": _RULES},
     [("ai-a", "admin.vm.firewall.Set", _RULES), ("ai-a", "admin.vm.firewall.Reload", "")]),
    ("qubes_firewall_set", {"name": "ai-a", "rules": _RULES, "reload": False},
     [("ai-a", "admin.vm.firewall.Set", _RULES)]),
    ("qubes_clone", {"source": "ai-a", "name": "ai-a2"},
     [(A, "qmcp.CloneAIManagedQube", {"source": "ai-a", "name": "ai-a2"})]),
    ("qubes_spawn_disposable", {"template": "ai-dvm"},
     [(A, "qmcp.SpawnDisposableAIManaged", {"template": "ai-dvm"})]),
    ("qubes_run_disposable", RUN_ARGS, [SPAWN, START, POLL, RUN, SHUTDOWN]),
    ("qubes_feature_set", {"name": "ai-a", "feature": "service.cups", "value": True},
     [(A, "qmcp.SetFeatureAIManaged", {"name": "ai-a", "feature": "service.cups", "value": True})]),
    ("qubes_feature_set", {"name": "ai-a", "feature": "vm-config.x", "value": 3},
     [(A, "qmcp.SetFeatureAIManaged", {"name": "ai-a", "feature": "vm-config.x", "value": 3})]),
    ("qubes_events", {"duration": 1},
     [(A, "qmcp.AIManagedEvents", {"duration": 1, "qube": None, "events": None})]),
    ("qubes_events", {"duration": 2, "qube": "ai-a", "events": ["domain-start", "property-set"]},
     [(A, "qmcp.AIManagedEvents", {"duration": 2, "qube": "ai-a",
                                   "events": ["domain-start", "property-set"]})]),
    ("qubes_get_pool_stats", {}, [(A, "qmcp.GetPoolStats", None)]),
] + [(name, arguments, [(A, SUBMIT, {"type": kind, **arguments})])
     for name, kind, arguments in (
        # Every field each proposal type takes, sent as given under its type,
        # with a quota in bytes. ProposalContractTests runs each of these
        # through dom0's own normalise().
        ("qubes_propose_project", "project-create", MINIMAL_PROPOSALS["qubes_propose_project"]),
        ("qubes_propose_project", "project-create", {
            "title": "OSINT scraping", "label": "osint",
            "lead": {"from": "clone", "qube": "ai-agent"}, "lead_name": "ai-osint-boss",
            "lead_netvm": "none", "templates": ["ai-deb", "ai-dvm"],
            "networks": ["ai-tor", "none"], "quota": 512 * 1024 ** 2, "dump": True}),
        ("qubes_propose_project", "project-create", {
            "title": "Promote", "label": "web2", "lead": {"from": "promote", "qube": "ai-agent"},
            "lead_name": None, "lead_netvm": None, "templates": [], "networks": ["ai-gw"],
            "quota": 40 * GiB, "dump": False}),
        ("qubes_propose_project_edit", "project-edit", MINIMAL_PROPOSALS["qubes_propose_project_edit"]),
        ("qubes_propose_project_edit", "project-edit", {
            "title": "Tor first", "project": "osint", "add_templates": ["ai-deb"],
            "remove_templates": ["ai-old"], "add_networks": ["ai-tor"],
            "remove_networks": ["none"], "default_network": "ai-tor", "quota": 1024 ** 4}),
        ("qubes_propose_project_edit", "project-edit", {
            "title": "Templates only", "project": "osint", "add_templates": ["ai-deb"],
            "default_network": None, "quota": None}),
        ("qubes_propose_dump", "project-dump", MINIMAL_PROPOSALS["qubes_propose_dump"]),
        ("qubes_propose_dump", "project-dump", {"title": "Hub sink", "project": "p00",
                                                "name": "hub-out"}),
        ("qubes_propose_dump", "project-dump", {"title": "Sink", "project": "p00", "name": None}),
        ("qubes_propose_lead", "project-lead", MINIMAL_PROPOSALS["qubes_propose_lead"]),
        ("qubes_propose_lead", "project-lead", {
            "title": "No lead", "project": "osint", "remove": True, "lead": None,
            "lead_name": None, "lead_netvm": None, "keep_old": None}),
        ("qubes_propose_lead", "project-lead", {
            "title": "Fresh lead", "project": "osint",
            "lead": {"from": "template", "qube": "debian-12-xfce"}, "keep_old": False}),
        ("qubes_propose_lead", "project-lead", {
            "title": "Keep the old lead", "project": "osint", "remove": False,
            "lead": {"from": "clone", "qube": "ai-agent"}, "lead_name": "ai-osint-lead2",
            "lead_netvm": "ai-gw", "keep_old": True}),
        ("qubes_propose_project_delete", "project-delete",
         MINIMAL_PROPOSALS["qubes_propose_project_delete"]),
     )
] + [
    ("qubes_proposals", {}, [(A, STATUS, {})]),
    ("qubes_proposals", {"id": None}, [(A, STATUS, {})]),
    ("qubes_proposals", {"id": 12}, [(A, STATUS, {"id": 12})]),
]
# A size string reaches dom0 in bytes; the expected payloads above give them so.
PAYLOAD_CASES += [
    ("qubes_propose_project", {**MINIMAL_PROPOSALS["qubes_propose_project"], "quota": "40G"},
     [(A, SUBMIT, {"type": "project-create",
                   **MINIMAL_PROPOSALS["qubes_propose_project"], "quota": 40 * GiB})]),
    ("qubes_propose_project_edit", {"title": "More disk", "project": "osint", "quota": "1T"},
     [(A, SUBMIT, {"type": "project-edit", "title": "More disk", "project": "osint",
                   "quota": 1024 ** 4})]),
]


class ToolCallTests(ServerCase):
    def setUp(self) -> None:
        super().setUp()
        self.proc = self.start_server()

    def call(self, tool: str, arguments=None) -> dict:
        return self.result_of(self.proc.call(tool, arguments))

    def test_every_tool_sends_the_right_target_service_and_payload(self):
        self.assertEqual({name for name, _, _ in PAYLOAD_CASES}, set(EXPECTED_TOOLS))
        for tool, arguments, expected in PAYLOAD_CASES:
            with self.subTest(tool=tool, arguments=arguments):
                self.fake.reset()
                self.call(tool, arguments)
                self.assertEqual(self.fake.calls(), expected)

    def test_a_refusal_passes_through_unchanged(self):
        refusal = {"ok": False, "error": "netvm may only be set to null", "hint": ["operator"]}
        self.fake.answer({"qmcp.SetPropertyAIManaged": {"json": refusal}})
        reply = self.proc.call("qubes_props_set", {"name": "ai-a", "property": "netvm",
                                                   "value": "ai-gw"})
        self.assertEqual(self.result_of(reply), refusal)
        self.assertEqual(reply["result"]["structuredContent"], refusal)

    def test_transport_failures_reach_the_agent_as_the_opaque_refusal(self):
        for label, response in {"empty": {"raw": ""},
                                "garbage": {"raw": "<html>oops</html>", "stderr": "detail"},
                                "denied": {"raw": "", "stderr": "Request refused", "rc": 126},
                                "not an object": {"raw": "[]"}}.items():
            with self.subTest(label):
                self.fake.answer({"qmcp.GetPoolStats": response})
                self.assertEqual(self.call("qubes_get_pool_stats"), REFUSED)

    def test_a_timeout_reaches_the_agent_as_the_opaque_refusal(self):
        # qubes_run waits timeout + 30 s: -29 leaves one second, and the fake takes five.
        self.fake.answer({"qmcp.RunInAIManaged": {"sleep": 5, "json": {"ok": True}}})
        start = time.monotonic()
        self.assertEqual(self.call("qubes_run", {"name": "ai-a", "cmd": ["true"], "timeout": -29}),
                         REFUSED)
        self.assertLess(time.monotonic() - start, 4.5)
        self.assertEqual(self.proc.request("ping")["result"], {})

    def test_invalid_target_names_never_reach_qrexec(self):
        for bad in ("dom0", "@adminvm", "a\n", "DOM0", "@dispvm", "@default", "", "-x", "a" * 32):
            for tool, arguments in (("qubes_run", {"name": bad, "cmd": ["id"]}),
                                    ("qubes_copy", {"source": bad, "target": "ai-b", "path": "/x"}),
                                    ("qubes_firewall_get", {"name": bad}),
                                    ("qubes_firewall_set", {"name": bad, "rules": "action=drop"})):
                with self.subTest(tool=tool, name=bad):
                    self.assertEqual(self.call(tool, arguments), REFUSED)
        self.assertEqual(self.fake.calls(), [])

    def test_props_get_reports_per_property_errors(self):
        missing = {"ok": False, "error": "property 'template' does not exist"}
        self.fake.answer({PROP: [{"match": {"property": "template"}, "json": missing}]})
        self.assertEqual(
            self.call("qubes_props_get", {"name": "ai-tpl",
                                          "properties": ["memory", "template", "vcpus"]}),
            {"ok": True, "values": {"memory": "memory-value", "vcpus": "vcpus-value"},
             "errors": {"template": "property 'template' does not exist"}})

    def test_props_get_returns_the_first_error_when_nothing_reads(self):
        first = {"ok": False, "error": "not found"}
        self.fake.answer({PROP: [{"match": {"property": "memory"}, "json": first},
                                 {"json": {"ok": False, "error": "something else"}}]})
        self.assertEqual(self.call("qubes_props_get", {"name": "ai-x",
                                                       "properties": ["memory", "vcpus"]}), first)
        self.fake.answer({PROP: {"raw": ""}})
        self.assertEqual(self.call("qubes_props_get", {"name": "ai-x",
                                                       "properties": ["memory"]}), REFUSED)

    def test_state_reports_per_property_errors(self):
        missing = {"ok": False, "error": "property 'template' does not exist"}
        self.fake.answer({PROP: [{"match": {"property": "template"}, "json": missing}]})
        self.assertEqual(self.call("qubes_state", {"name": "ai-tpl"}), {
            "ok": True, "name": "ai-tpl", "power_state": "Running", "netvm": "netvm-value",
            "provides_network": "provides_network-value",
            "errors": {"template": "property 'template' does not exist"}})

    def test_state_returns_the_first_error_when_nothing_reads(self):
        self.fake.answer({PROP: {"json": {"ok": False, "error": "not found"}}})
        self.assertEqual(self.call("qubes_state", {"name": "ai-x"}),
                         {"ok": False, "error": "not found"})

    def test_run_disposable_success(self):
        self.fake.answer({"qmcp.RunInAIManaged": {"json": {"ok": True, "rc": 3, "stdout": "o",
                                                           "stderr": "e"}}})
        self.assertEqual(self.call("qubes_run_disposable", RUN_ARGS),
                         {"ok": True, "name": D, "rc": 3, "stdout": "o", "stderr": "e"})
        self.assertEqual(self.fake.calls(), [SPAWN, START, POLL, RUN, SHUTDOWN])

    def test_run_disposable_failed_run_is_shut_down(self):
        self.fake.answer({"qmcp.RunInAIManaged": {"json": {"ok": False, "error": "no such file"}}})
        self.assertEqual(self.call("qubes_run_disposable", RUN_ARGS),
                         {"ok": False, "name": D, "stage": "run", "error": "no such file"})
        self.assertEqual(self.fake.calls(), [SPAWN, START, POLL, RUN, SHUTDOWN])

    def test_run_disposable_failed_run_and_shutdown_is_killed(self):
        self.fake.answer({
            "qmcp.RunInAIManaged": {"json": {"ok": False, "error": "no such file"}},
            LIFE: [{"match": {"action": "shutdown"}, "json": {"ok": False, "error": "busy"}}],
        })
        self.assertEqual(self.call("qubes_run_disposable", RUN_ARGS),
                         {"ok": False, "name": D, "stage": "run", "error": "no such file"})
        self.assertEqual(self.fake.calls(), [SPAWN, START, POLL, RUN, SHUTDOWN, KILL])

    def test_run_disposable_failed_shutdown_after_a_good_run_is_killed(self):
        self.fake.answer({LIFE: [{"match": {"action": "shutdown"},
                                  "json": {"ok": False, "error": "busy"}}]})
        self.assertEqual(self.call("qubes_run_disposable", RUN_ARGS),
                         {"ok": False, "name": D, "stage": "shutdown", "error": "busy",
                          "rc": 0, "stdout": "out\n", "stderr": ""})
        self.assertEqual(self.fake.calls(), [SPAWN, START, POLL, RUN, SHUTDOWN, KILL])

    def test_run_disposable_failed_start_is_killed(self):
        self.fake.answer({LIFE: [{"match": {"action": "start"},
                                  "json": {"ok": False, "error": "out of memory"}}]})
        self.assertEqual(self.call("qubes_run_disposable", RUN_ARGS),
                         {"ok": False, "name": D, "stage": "start", "error": "out of memory"})
        self.assertEqual(self.fake.calls(), [SPAWN, START, KILL])

    def test_run_disposable_failed_spawn_stops_there(self):
        self.fake.answer({"qmcp.SpawnDisposableAIManaged": {"json": {"ok": False,
                                                                     "error": "not found"}}})
        self.assertEqual(self.call("qubes_run_disposable", RUN_ARGS),
                         {"ok": False, "stage": "spawn", "error": "not found"})
        self.assertEqual(self.fake.calls(), [SPAWN])

    def test_run_disposable_waits_until_running(self):
        self.fake.answer({PROP: {"sequence": [{"json": {"ok": True, "value": "Halted"}},
                                              {"json": {"ok": True, "value": "Running"}}]}})
        self.assertTrue(self.call("qubes_run_disposable", RUN_ARGS)["ok"])
        self.assertEqual(self.fake.calls(), [SPAWN, START, POLL, POLL, RUN, SHUTDOWN])

    def test_run_disposable_never_targets_a_bad_name_from_dom0(self):
        self.fake.answer({"qmcp.SpawnDisposableAIManaged": {"json": {"ok": True, "name": "dom0"}}})
        result = self.call("qubes_run_disposable", RUN_ARGS)
        self.assertEqual(result, {"ok": False, "name": "dom0", "stage": "run",
                                  "error": "not found or refused"})
        calls = self.fake.calls()
        self.assertNotIn("dom0", [target for target, _, _ in calls])
        self.assertEqual(calls[-1], (A, LIFE, {"name": "dom0", "action": "shutdown"}))

    def test_firewall_set_reload_failure(self):
        self.fake.answer({"admin.vm.firewall.Reload": {"raw": "", "rc": 1}})
        self.assertEqual(self.call("qubes_firewall_set", {"name": "ai-a", "rules": _RULES}),
                         {"ok": False, "error": "set ok but reload failed: not found or refused"})

    def test_firewall_set_failure_skips_the_reload(self):
        self.fake.answer({"admin.vm.firewall.Set": {"raw": "2\x00QubesException\x00\x00x\x00"}})
        self.assertEqual(self.call("qubes_firewall_set", {"name": "ai-a", "rules": _RULES}),
                         REFUSED)
        self.assertEqual(self.fake.calls(), [("ai-a", "admin.vm.firewall.Set", _RULES)])

    def test_firewall_results(self):
        self.assertEqual(self.call("qubes_firewall_set", {"name": "ai-a", "rules": _RULES}),
                         {"ok": True, "reloaded": True})
        self.assertEqual(self.call("qubes_firewall_set", {"name": "ai-a", "rules": _RULES,
                                                          "reload": False}),
                         {"ok": True, "reloaded": False})
        self.fake.answer({"admin.vm.firewall.Get": {"raw": "0\x00action=drop\n"}})
        self.assertEqual(self.call("qubes_firewall_get", {"name": "ai-a"}),
                         {"ok": True, "rules": "action=drop\n"})

    def test_a_submitted_proposal_comes_back_as_dom0_says(self):
        stored = {"ok": True, "id": 7, "sha256": "ab" * 32, "state": "pending",
                  "expires": "2026-10-09T12:00:00Z"}
        self.fake.answer({SUBMIT: {"json": stored}})
        for name, arguments in MINIMAL_PROPOSALS.items():
            with self.subTest(tool=name):
                self.assertEqual(self.call(name, arguments), stored)
        refusal = {"ok": False, "error": "invalid proposal: keep_old: say whether the old lead "
                                         "stays as a worker (true) or is removed with "
                                         "everything in it (false)"}
        self.fake.answer({SUBMIT: {"json": refusal}})
        self.assertEqual(self.call("qubes_propose_lead", {
            "title": "New lead", "project": "osint",
            "lead": {"from": "template", "qube": "debian-12-xfce"}}), refusal)

    def test_a_lead_proposing_gets_the_opaque_refusal(self):
        # The policy refuses a lead's call before dom0 runs: an empty reply.
        self.fake.answer({SUBMIT: {"raw": "", "stderr": "Request refused", "rc": 126},
                          STATUS: {"raw": "", "stderr": "Request refused", "rc": 126}})
        self.assertEqual(self.call("qubes_propose_project_delete",
                                   MINIMAL_PROPOSALS["qubes_propose_project_delete"]), REFUSED)
        self.assertEqual(self.call("qubes_proposals"), REFUSED)

    def test_proposal_status_comes_back_as_dom0_says(self):
        row = {"id": 3, "state": "failed", "type": "project-delete", "title": "Done",
               "submitted": "2026-10-02T09:00:00Z", "expires": "2026-10-09T09:00:00Z",
               "sha256": "cd" * 32}
        listing = {"ok": True, "proposals": [row]}
        one = {"ok": True, **row, "proposal": {"type": "project-delete", "title": "Done",
                                               "project": "osint"}}
        self.fake.answer({STATUS: [{"match": {"id": 3}, "json": one},
                                   {"json": listing}]})
        self.assertEqual(self.call("qubes_proposals"), listing)
        self.assertEqual(self.call("qubes_proposals", {"id": 3}), one)
        self.assertEqual(self.fake.calls(), [(A, STATUS, {}), (A, STATUS, {"id": 3})])


class ProposalContractTests(unittest.TestCase):
    """The proposal tools against dom0's own schema, qmcp.proposals, which is
    standard library only, so this runs wherever the rest does. dom0 decides
    what a proposal is; these fail when the tools and dom0 come apart."""

    @classmethod
    def setUpClass(cls) -> None:
        dom0 = str(PUBLIC_DIR / "dom0")
        if dom0 not in sys.path:
            sys.path.insert(0, dom0)
        from qmcp import fleet, proposals
        cls.proposals, cls.fleet = proposals, fleet

    def submitted(self):
        for tool, arguments, expected in PAYLOAD_CASES:
            for _, service, payload in expected:
                if service == SUBMIT:
                    yield tool, arguments, payload

    def test_one_tool_per_proposal_type(self):
        self.assertEqual(sorted(PROPOSAL_TYPES.values()), sorted(self.proposals.TYPES))
        self.assertEqual(set(PROPOSAL_TYPES), set(MINIMAL_PROPOSALS))

    def test_dom0_stores_every_payload_as_the_tool_sent_it(self):
        seen = set()
        for tool, arguments, payload in self.submitted():
            with self.subTest(tool=tool, arguments=arguments):
                self.assertEqual(payload["type"], PROPOSAL_TYPES[tool])
                normal = self.proposals.normalise(payload, "ai-")
                self.assertEqual({key: normal[key] for key in payload}, payload)
                seen.add(tool)
        self.assertEqual(seen, set(PROPOSAL_TYPES))

    def test_each_tool_takes_exactly_the_fields_dom0_takes(self):
        # A proposal's normal form names every field its type stores, which is
        # every field it accepts, unless dom0 took a field and dropped it: a
        # dom0 bug this cannot see.
        for tool, arguments, payload in self.submitted():
            with self.subTest(tool=tool):
                normal = self.proposals.normalise(payload, "ai-")
                schema = tools.TOOLS[tool].input_schema["properties"]
                self.assertEqual(set(schema) | {"type"}, set(normal))
                with self.assertRaises(self.proposals.Invalid):
                    self.proposals.normalise({**payload, "extra": 1}, "ai-")

    def test_the_lead_source_is_dom0_s(self):
        for name in ("qubes_propose_project", "qubes_propose_lead"):
            with self.subTest(tool=name):
                lead = tools.TOOLS[name].input_schema["properties"]["lead"]
                self.assertEqual(lead["properties"]["from"]["enum"],
                                 list(self.proposals.LEAD_SOURCES))
                self.assertEqual(set(lead["properties"]), {"from", "qube"})
                self.assertEqual(sorted(lead["required"]), ["from", "qube"])

    def test_a_size_means_what_the_operator_s_quota_means(self):
        # Every string either side reads, read the same; every one either
        # refuses, refused by both, the 1 EiB bound included.
        for text in ("40G", "40g", "40GB", "40GiB", "40gib", " 40 G ", "512M", "1T", "8K",
                     "100B", "4096", "40iB", "40BB", "0", "0G", "", "G", "1.5G", "-1G",
                     "40X", "4O96", "40 G B", "1e9", "9" * 20, str(2 ** 60), str(2 ** 60 + 1),
                     "1048576T", "1048577T"):
            with self.subTest(text=text):
                try:
                    operator = self.fleet._quota(text)
                except self.fleet.ProjectError:
                    operator = None
                try:
                    tool = tools._size_bytes(text, "argument 'quota'")
                except tools.ArgumentError:
                    tool = None
                self.assertEqual(tool, operator)

    def test_a_size_past_twenty_digits_is_refused_here(self):
        # More than 20 digits is never read here; the operator's parser reads it
        # and the 1 EiB bound then refuses it, so the two still agree.
        text = "1" + "0" * 20
        self.assertEqual(self.fleet.parse_size(text), 10 ** 20)
        with self.assertRaises(self.fleet.ProjectError):
            self.fleet._quota(text)
        with self.assertRaises(tools.ArgumentError):
            tools._size_bytes(text, "argument 'quota'")


# --------------------------------------------------------------------------
# The qubes-mcp CLI
# --------------------------------------------------------------------------

class CliTests(FakeCase):
    def cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-W", "error::DeprecationWarning", "-m", "qubes_mcp.cli", *args],
            cwd=str(PUBLIC_DIR), env=self.fake.env(), capture_output=True, timeout=60)

    def test_list_tools(self):
        done = self.cli("list-tools")
        self.assertEqual(done.returncode, 0, done.stderr)
        lines = done.stdout.decode().splitlines()
        self.assertEqual([line.split()[0] for line in lines], EXPECTED_TOOLS)
        self.assertTrue(all(len(line.split(None, 1)) == 2 for line in lines))

    def test_key_value_arguments_parse_as_json_when_they_can(self):
        done = self.cli("qubes_run", "name=ai-a", 'cmd=["ls", "-l"]', "timeout=5",
                        "shell=false", "stdin=hello world")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout),
                         {"ok": True, "rc": 0, "stdout": "out\n", "stderr": ""})
        self.assertEqual(self.fake.calls(), [("ai-a", "qmcp.RunInAIManaged",
                                              {"cmd": ["ls", "-l"], "shell": False, "timeout": 5,
                                               "stdin": "hello world"})])

    def test_null_and_quoted_strings(self):
        self.assertEqual(self.cli("qubes_spawn", "name=ai-new", "template=ai-tpl",
                                  "netvm=null").returncode, 0)
        self.assertEqual(self.cli("qubes_props_set", "name=ai-a", "property=label",
                                  'value="null"').returncode, 0)
        self.assertEqual(self.cli("qubes_props_set", "name=ai-a", "property=label",
                                  "value=blue").returncode, 0)
        self.assertEqual(self.fake.calls(), [
            (A, "qmcp.SpawnAIManagedQube", {**_SPAWN_BASE, "netvm": None}),
            (A, "qmcp.SetPropertyAIManaged", {"name": "ai-a", "property": "label", "value": "null"}),
            (A, "qmcp.SetPropertyAIManaged", {"name": "ai-a", "property": "label", "value": "blue"}),
        ])

    def test_json_object_form(self):
        done = self.cli("qubes_shutdown", "--json", '{"name": "ai-a", "force": true}')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.fake.calls(), [(A, LIFE, {"name": "ai-a", "action": "kill"})])

    def test_output_is_indented_json(self):
        self.fake.answer({"qmcp.GetPoolStats": {"json": {"ok": True, "ai_managed_bytes_used": 1}}})
        done = self.cli("qubes_get_pool_stats")
        self.assertEqual(done.stdout.decode(),
                         json.dumps({"ok": True, "ai_managed_bytes_used": 1}, indent=2) + "\n")

    def test_a_refusal_exits_1(self):
        self.fake.answer({LIFE: {"json": {"ok": False, "error": "busy"}}})
        done = self.cli("qubes_start", "name=ai-a")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(json.loads(done.stdout), {"ok": False, "error": "busy"})
        self.fake.answer({"qmcp.GetPoolStats": {"raw": ""}})
        done = self.cli("qubes_get_pool_stats")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(json.loads(done.stdout), REFUSED)

    def test_invalid_arguments_exit_2_and_reach_nothing(self):
        for args, fragment in (
                (("qubes_run", "name=ai-a", "cmd=ls", "timeout=true"), "got boolean"),
                (("qubes_start", "name=ai-a", "colour=red"), "unknown argument 'colour'"),
                (("qubes_start",), "missing required argument 'name'"),
                (("qubes_events", "duration=1.5"), "got number")):
            with self.subTest(args=args):
                done = self.cli(*args)
                self.assertEqual(done.returncode, 2)
                self.assertIn(fragment, done.stderr.decode())
                self.assertEqual(done.stdout, b"")
        self.assertEqual(self.fake.calls(), [])

    def test_usage_errors_exit_2(self):
        for args in ((), ("qubes_device_list",), ("qubes_start", "name"), ("qubes_start", "=x"),
                     ("qubes_start", "name=a", "name=b"), ("qubes_start", "--json"),
                     ("qubes_start", "--json", "[1]"), ("qubes_start", "--json", "{"),
                     ("qubes_start", "--json", '{"name": "a"}', "force=true"),
                     ("list-tools", "extra")):
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args).returncode, 2)
        self.assertEqual(self.fake.calls(), [])

    def test_help(self):
        done = self.cli("--help")
        self.assertEqual(done.returncode, 0)
        self.assertIn(b"usage: qubes-mcp", done.stdout)
        done = self.cli("qubes_spawn", "--help")
        self.assertEqual(done.returncode, 0)
        self.assertIn(b"netvm", done.stdout)
        self.assertIn(b"required", done.stdout)
        done = self.cli("qubes_propose_lead", "--help")
        self.assertEqual(done.returncode, 0)
        self.assertIn(b"keep_old (boolean or null)", done.stdout)
        self.assertIn(b"lead (object or null)", done.stdout)

    def test_a_proposal_from_the_command_line(self):
        done = self.cli("qubes_propose_project", "title=Scrape OSINT", "label=osint",
                        'lead={"from": "template", "qube": "debian-12-xfce"}',
                        'networks=["ai-gw", "none"]', "quota=40G", "dump=true")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.fake.calls(), [(A, SUBMIT, {
            "type": "project-create", "title": "Scrape OSINT", "label": "osint",
            "lead": {"from": "template", "qube": "debian-12-xfce"},
            "networks": ["ai-gw", "none"], "quota": 40 * GiB, "dump": True})])

    def test_a_bad_quota_exits_2_and_reaches_nothing(self):
        for value, fragment in (("40X", "argument 'quota': '40X' is not a size"),
                                ("0", "argument 'quota': must be more than zero bytes"),
                                ("true", "got boolean")):
            with self.subTest(value=value):
                done = self.cli("qubes_propose_project_edit", "title=t", "project=osint",
                                f"quota={value}")
                self.assertEqual(done.returncode, 2)
                self.assertIn(fragment, done.stderr.decode())
                self.assertEqual(done.stdout, b"")
        self.assertEqual(self.fake.calls(), [])


if __name__ == "__main__":
    unittest.main()
