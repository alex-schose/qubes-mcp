"""The qubes-mcp tool registry: name -> description, inputSchema, handler.

server.py (MCP over stdio) and cli.py (the `qubes-mcp` command) share this
registry and its argument validator, so both accept exactly the same calls.

Nothing in this module is a security control. It runs in the hub qube or in a
project's lead, on the agent's side of the boundary, and an agent that controls the process skips any
check made here. dom0 is the only enforcement point: which qubes are in scope,
what is settable, which feature keys are allowed, the name prefix and the
network a new qube gets are all decided by the dom0 services and the qrexec
policy. A check up here that resembled one of those rules would only mislead
the next reader into thinking it enforces something, so none is made. The
validator checks the SHAPE of the arguments, so that a malformed call gets a
clear error and never reaches dom0 at all.
"""
from __future__ import annotations

import copy
import inspect
import json
import logging
import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable

from qubes_mcp import qrexec

log = logging.getLogger(__name__)

# Client-side timeouts, in seconds.
DOM0_TIMEOUT = 60.0
# A create may first wait in dom0 for the create lock (up to 120 s), then build.
CREATE_TIMEOUT = 300.0
# What a create says when its reply never came: dom0 goes on with a call whose
# client gave up, so the qube may exist. Only a timeout says this; a refusal,
# a policy denial among them, stays the opaque one.
SPAWN_LOST_QUBE = "no reply to the spawn in time: a qube may exist; check qubes_list"
CLONE_LOST = "no reply to the clone in time: a qube may exist; check qubes_list"
SPAWN_LOST = "no reply to the spawn in time: a disposable may exist; check qubes_list"
RULES_REFUSED = "firewall rules refused by qubesd"
LIFECYCLE_TIMEOUT = 120.0
# qubes_run and qubes_copy wait for the agent's own timeout plus this margin.
EXEC_MARGIN = 30
# qubes_events waits for the window plus this margin.
EVENTS_MARGIN = 10


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], dict]
    # Runs on the validated arguments, after the schema check, for what the
    # schema subset cannot say: it converts an argument that may be written
    # two ways (a quota as bytes or as "40G") and raises ArgumentError for a
    # value of the right type that cannot be sent. Shape only, like the rest
    # of the validator; never a security check.
    prepare: Callable[[dict], dict] | None = None


class UnknownTool(LookupError):
    """No tool has this name."""


class ArgumentError(ValueError):
    """The arguments do not match the tool's inputSchema."""


TOOLS: dict[str, Tool] = {}


def _register(name: str, description: str, properties: dict, required: tuple = (),
              prepare: Callable[[dict], dict] | None = None):
    schema: dict = {"type": "object", "properties": copy.deepcopy(properties),
                    "additionalProperties": False}
    if required:
        schema["required"] = list(required)

    def register(handler: Callable[[dict], dict]) -> Callable[[dict], dict]:
        if name in TOOLS:
            raise RuntimeError(f"tool {name} registered twice")
        TOOLS[name] = Tool(name, inspect.cleandoc(description), schema, handler, prepare)
        return handler
    return register


def _prop(json_type, description: str, **extra) -> dict:
    schema = {"type": json_type, "description": description}
    schema.update(extra)
    return schema


# --------------------------------------------------------------------------
# Argument validation: a small subset of JSON Schema (type, with unions as a
# list; items; properties; required; additionalProperties: false; enum;
# minimum and maximum, for integers), at any depth, then the tool's prepare
# hook, if it has one.
# --------------------------------------------------------------------------

SCHEMA_KEYWORDS = frozenset({
    "type", "description", "default", "enum", "items",
    "properties", "required", "additionalProperties", "minimum", "maximum",
})

_TYPE_CHECKS: dict[str, Callable[[object], bool]] = {
    "string": lambda v: isinstance(v, str),
    # bool is a subclass of int in Python, so True would otherwise pass as 1
    # and a boolean would silently become a byte count or a timeout. JSON keeps
    # the two apart, and so does this check. A float is refused even when it is
    # integral (5.0): dom0 checks integers by type and would refuse it anyway.
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def json_type(value) -> str:
    """The JSON type name of a decoded value, for error messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _shown(key: str) -> str:
    # Keys come from the caller; cap what is echoed back.
    text = repr(key)
    return text if len(text) <= 66 else text[:63] + "...'"


def _same(a, b) -> bool:
    # Type-strict equality, so True does not match an enum entry of 1.
    return type(a) is type(b) and a == b


def _problem(schema: dict, value, where: str) -> str | None:
    """The first way `value` fails `schema`, or None."""
    types = schema.get("type")
    if types is not None:
        allowed = [types] if isinstance(types, str) else list(types)
        if not any(_TYPE_CHECKS[t](value) for t in allowed):
            wanted = " or ".join(allowed) if len(allowed) < 3 else \
                ", ".join(allowed[:-1]) + " or " + allowed[-1]
            return f"{where}: expected {wanted}, got {json_type(value)}"
    if "enum" in schema and not any(_same(value, e) for e in schema["enum"]):
        choices = ", ".join(json.dumps(e) for e in schema["enum"])
        return f"{where}: must be one of {choices}"
    if _TYPE_CHECKS["integer"](value):
        low, high = schema.get("minimum"), schema.get("maximum")
        if (low is not None and value < low) or (high is not None and value > high):
            return f"{where}: must be from {low} to {high}"
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            problem = _problem(schema["items"], item, f"{where}[{index}]")
            if problem:
                return problem
    if isinstance(value, dict):
        properties = schema.get("properties", {})

        def named(key: str) -> str:
            # A key inside an object argument (lead.from) comes from the caller
            # too, so it is capped the same way, without the quotes.
            return f"{where}.{_shown(key)[1:-1]}" if where else f"argument {_shown(key)}"

        for key in schema.get("required", ()):
            if key not in value:
                return f"missing required {named(key)}"
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    return f"unknown {named(key)}"
        for key, sub in properties.items():
            if key in value:
                problem = _problem(sub, value[key], named(key))
                if problem:
                    return problem
    return None


def _reject_constant(token: str):
    raise ValueError(f"{token} is not JSON")


def parse_json(text: str):
    """json.loads, minus the non-standard NaN and Infinity it accepts by default.
    Shared by the server and the CLI. Raises ValueError (or RecursionError)."""
    return json.loads(text, parse_constant=_reject_constant)


def get_tool(name) -> Tool:
    tool = TOOLS.get(name) if isinstance(name, str) else None
    if tool is None:
        raise UnknownTool(name)
    return tool


def validate_arguments(tool: Tool, arguments) -> dict:
    """Check `arguments` against the tool's inputSchema and return a copy with
    the defaults of omitted optional arguments filled in, then passed through
    the tool's prepare hook if it has one. Raises ArgumentError."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ArgumentError(f"arguments must be an object, got {json_type(arguments)}")
    problem = _problem(tool.input_schema, arguments, "")
    if problem:
        raise ArgumentError(problem)
    out = dict(arguments)
    for key, sub in tool.input_schema["properties"].items():
        if key not in out and "default" in sub:
            out[key] = copy.deepcopy(sub["default"])
    return out if tool.prepare is None else tool.prepare(out)


def call_tool(name: str, arguments) -> dict:
    """Validate and run one tool (the CLI's path; the server validates on its
    reader thread and runs the handler on a worker)."""
    tool = get_tool(name)
    return tool.handler(validate_arguments(tool, arguments))


# --------------------------------------------------------------------------
# Shared pieces
# --------------------------------------------------------------------------

_CMD = _prop(["array", "string"],
             "The command: an argv list (the default), or one string run by "
             "/bin/sh -c when shell is true.",
             items={"type": "string"})
_SHELL = _prop("boolean", "Run cmd through /bin/sh -c.", default=False)
# The longest a command or a copy may be given inside a qube: one day. The
# in-qube services check the same bounds, for a caller that is not this server.
MAX_TIMEOUT = 86400
_RUN_TIMEOUT = _prop("integer", "Time limit for the command inside the qube, in seconds "
                                f"(1 to {MAX_TIMEOUT}).",
                     default=60, minimum=1, maximum=MAX_TIMEOUT)
_STDIN = _prop("string", "Text fed to the command's standard input.", default="")

# A size as the operator's `qmcp project --quota` reads one: a whole number and
# an optional unit in powers of 1024 (K, M, G or T), which may be followed by B
# or iB, in any letter case: "40G", "40GiB" and "40gb" are all 40 * 1024**3
# bytes; and, as there, at most 1 EiB, past any disk. At most 20 digits are
# read, so the number always converts before that bound is applied.
_SIZE_RE = re.compile(r"\s*([0-9]{1,20})\s*([BKMGT]?)(?:i?B)?\s*", re.IGNORECASE | re.ASCII)
_SIZE_UNITS = {"": 1, "B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
_MAX_QUOTA = 2 ** 60


def _size_bytes(value, where: str) -> int:
    """A positive whole number of bytes, from an integer or a size string.
    Raises ArgumentError, so a size that cannot be sent never reaches dom0."""
    # The schema refuses a boolean already. bool is an int subclass, so it is
    # refused here too rather than let True become one byte.
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ArgumentError(f"{where}: expected integer or string, got {json_type(value)}")
    if isinstance(value, str):
        match = _SIZE_RE.fullmatch(value)
        if match is None:
            raise ArgumentError(f"{where}: {_shown(value)} is not a size: give bytes, or a "
                                f"whole number and K, M, G or T (512M, 40G, 1T)")
        value = int(match.group(1)) * _SIZE_UNITS[match.group(2).upper()]
    if value <= 0:
        raise ArgumentError(f"{where}: must be more than zero bytes")
    if value > _MAX_QUOTA:
        raise ArgumentError(f"{where}: at most 1 EiB")
    return value


def _quota_in_bytes(args: dict) -> dict:
    """The prepare hook of the tools that take a quota, which dom0 takes in bytes."""
    if args.get("quota") is None:      # omitted, or null for "unchanged" in an edit
        return args
    return dict(args, quota=_size_bytes(args["quota"], "argument 'quota'"))


def _get_property(name: str, prop: str, timeout: float = DOM0_TIMEOUT) -> dict:
    return qrexec.call_qmcp("qmcp.GetPropertyAIManaged",
                            {"name": name, "property": prop}, timeout=timeout)


def _read_properties(name: str, props) -> tuple[dict, dict, dict | None]:
    """Read each property separately: (values, errors, first error reply).

    Per property, not abort-on-first-failure. A property that does not exist
    on the target's class (`template` on a TemplateVM, say) must not discard
    the ones that read fine, and dom0 already answers per property.

    Opacity: when NOTHING reads, the callers return the first error reply as
    it came, so a qube that is out of scope or does not exist collapses to the
    same opaque "not found" as on every other tool. The richer shape appears
    only once a property has been read, which itself proves the qube is in
    scope, so the per-property errors are no existence oracle.
    """
    values: dict = {}
    errors: dict = {}
    first_error: dict | None = None
    for prop in props:
        reply = _get_property(name, prop)
        if reply.get("ok"):
            values[prop] = reply.get("value")
        else:
            errors[prop] = reply.get("error", qrexec.REFUSED)
            if first_error is None:
                first_error = reply
    return values, errors, first_error


def _lifecycle(name: str, action: str, timeout: float | None = None) -> dict:
    return qrexec.call_qmcp("qmcp.LifecycleAIManaged", {"name": name, "action": action},
                            timeout=LIFECYCLE_TIMEOUT if timeout is None else timeout)


def _run_payload(args: dict) -> dict:
    return {"cmd": args["cmd"], "shell": args["shell"],
            "timeout": args["timeout"], "stdin": args["stdin"]}


# --------------------------------------------------------------------------
# The tools
# --------------------------------------------------------------------------

@_register("qubes_list", """
    List the qubes in the caller's scope.

    The hub's scope is all of AI space but the qubes of a hidden anonymous
    project. A project's lead sees its project's
    workers, the templates its project may spawn from, and those of its
    project's worker networks that are in AI space (qubes_get_pool_stats
    names them all).

    Each entry is {name, klass, label, template, power_state, guarded, slot,
    lead}. `slot` is the project slot a qube belongs to (p00 is the hub's own
    qubes, p01-p15 are projects), or null; `lead` is true for a project's lead.
    A qube whose tags or class dom0 cannot read at that moment is left out; a
    label or template it cannot read is "<unreadable>", and a power state it
    cannot read "NA" or "unknown".

    A qube in scope is in one of two states:
    - managed (guarded: false): the caller may operate it: start and shut it
      down, run commands in it, copy files, change its settings, clone or
      remove it. For the hub this includes the templates and disposable
      templates it manages, and the leads (which only the operator removes).
      A lead may operate only the entries in its own slot (`slot` set); its
      approved templates, and its networks that are in AI space, are listed
      so it can spawn from and onto them.
    - guarded (guarded: true): reference only. It is listed, can be read, and
      can be spawned from (as a template or a disposable template), but is
      never operated, except through a window the operator opened
      (qubes_propose_open).

    Qubes out of scope are not listed. Every tool answers a qube that is out of
    scope the way it answers one that does not exist: one opaque refusal per
    tool, given in its description ("not found", "not found or refused", or for
    a template "template must reference an ai-managed qube", and for a lead's
    template off its approved list "template is not on this project's approved
    list"). A
    template out of scope is redacted in the `template` field.

    Returns {"ok": true, "qubes": [...]} or {"ok": false, "error": "..."}.
    """, {})
def _qubes_list(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.ListAIManagedQubes", timeout=DOM0_TIMEOUT)


@_register("qubes_spawn", """
    Create a new qube. It is born managed.

    - name: must start with the caller's own names: for the hub, the
      operator's reserved prefix followed by "hub-" (by default "ai-hub-",
      e.g. "ai-hub-browser"); for a lead, its project's (e.g. "ai-osint-").
      qubes_get_pool_stats reports the prefix. Any other name is refused.
    - klass: "AppVM" (the default), "StandaloneVM" or "DispVMTemplate", all
      built on a TemplateVM; or "DispVM", built on a disposable template (a
      qube with template_for_dispvms=True). A lead cannot create a
      DispVMTemplate. A StandaloneVM gets its own copy of the template's root,
      as the template was when it last shut down: what is installed in it
      stays after a restart, and nothing reaches it from the template later.
      Its root counts against the disk budget at the template root's full
      size (often 20 GiB), on top of its private volume.
    - template: the qube to build on, managed or guarded. A lead may use only
      its project's approved templates. One that is out of scope or does not
      exist is refused with "template must reference an ai-managed qube",
      which never says which of the two it is.
    - netvm: omit it and the network is inherited. Every network must be a
      gateway the operator enrolled (qubes_get_pool_stats lists them for the
      hub). For the hub: a DispVM takes its disposable template's network,
      which must be enrolled (or none), else the create is refused; an AppVM,
      a StandaloneVM or a disposable template takes the hub's own network if it is enrolled,
      else the operator's configured default if that is enrolled, else the
      create is refused. A name must equal the inherited value. For a lead: its project's default worker network, or another one
      on the project's list; a DispVM keeps its disposable template's, which
      must be on the list. A lead's own network is never used. Pass null for
      no network. That is always allowed, except that a lead's DispVM still
      needs its disposable template on a listed network, or on none. After
      birth a qube's network can only be cleared (netvm null), never moved to
      another one.
    - private_size: optional, in bytes. Grows the persistent private volume
      beyond the Qubes default. It counts against the caller's disk budget
      (see qubes_get_pool_stats), and a size above the operator's per-qube
      limit is refused.

    dom0 runs one create at a time, so this call may wait for others to finish.

    Returns {"ok": true, "name": "<name>"}, with a "warning" if a secondary step
    failed, or {"ok": false, "error": "<reason>"}. A spawn whose reply never
    came says a qube may exist; check qubes_list.
    """, {
        "name": _prop("string", "Name of the new qube, inside the caller's own names "
                                "(the hub's: ai-hub-...)."),
        "template": _prop("string", "Template (or, for a DispVM, disposable template) "
                                    "to build on; managed or guarded."),
        "klass": _prop("string", "Kind of qube to create.",
                       enum=["AppVM", "StandaloneVM", "DispVMTemplate", "DispVM"],
                       default="AppVM"),
        "label": _prop("string", "Qubes label colour: red, orange, yellow, green, gray, "
                                 "blue, purple or black.", default="gray"),
        # No default on purpose: an omitted netvm (inherit) and an explicit
        # null (no network) are different requests, and dom0 tells them apart
        # by whether the key is present.
        "netvm": _prop(["string", "null"], "Omit to inherit the network; null for none; "
                                           "a name must equal the inherited one."),
        "private_size": _prop(["integer", "null"], "Size of the private volume in bytes; "
                                                   "omit for the Qubes default.", default=None),
    }, required=("name", "template"))
def _qubes_spawn(args: dict) -> dict:
    payload = {"name": args["name"], "template": args["template"],
               "klass": args["klass"], "label": args["label"]}
    if "netvm" in args:
        payload["netvm"] = args["netvm"]
    if args["private_size"] is not None:
        payload["private_size"] = args["private_size"]
    return qrexec.call_qmcp("qmcp.SpawnAIManagedQube", payload, timeout=CREATE_TIMEOUT,
                            on_timeout={"ok": False, "error": SPAWN_LOST_QUBE})


# A superset across classes on purpose: `template` exists on an AppVM and a
# DispVM but not on a TemplateVM or a StandaloneVM. Rather than branch on the
# class (an extra round trip, and a list that rots as Qubes adds properties),
# read them all and report per property.
_STATE_PROPS = ("power_state", "netvm", "template", "provides_network")


@_register("qubes_state", """
    Read a qube's power state and its core properties.

    Reads power_state, netvm, template and provides_network from a managed or
    guarded qube. A property the qube's class does not have (template on a
    TemplateVM, for example) is reported under "errors" and the rest are still
    returned. If nothing can be read the first error is returned as it is, so a
    qube that is out of scope or does not exist gives the usual opaque
    "not found".

    Returns {"ok": true, "name": ..., "power_state": ..., "netvm": ...,
    "template": ..., "provides_network": ...} plus "errors" when some could not
    be read, or {"ok": false, "error": "..."}.
    """, {
        "name": _prop("string", "The qube to read."),
    }, required=("name",))
def _qubes_state(args: dict) -> dict:
    name = args["name"]
    values, errors, first_error = _read_properties(name, _STATE_PROPS)
    if not values and first_error is not None:
        return first_error
    out: dict = {"ok": True, "name": name}
    out.update(values)
    if errors:
        out["errors"] = errors
    return out


@_register("qubes_props_get", """
    Read several properties of a managed or guarded qube.

    Each property is read separately. One that cannot be read (for example one
    the qube's class does not have) is reported under "errors" and the rest are
    still returned. If none can be read the first error is returned as it is,
    so a qube that is out of scope or does not exist gives the usual opaque
    "not found".

    Returns {"ok": true, "values": {property: value}} plus
    "errors": {property: reason} when some could not be read, or
    {"ok": false, "error": "..."}.
    """, {
        "name": _prop("string", "The qube to read."),
        "properties": _prop("array", "Property names, e.g. [\"memory\", \"vcpus\"].",
                            items={"type": "string"}),
    }, required=("name", "properties"))
def _qubes_props_get(args: dict) -> dict:
    values, errors, first_error = _read_properties(args["name"], args["properties"])
    if not values and first_error is not None:
        return first_error
    out: dict = {"ok": True, "values": values}
    if errors:
        out["errors"] = errors
    return out


@_register("qubes_props_set", """
    Set one property on a managed qube.

    Settable: label, memory, maxmem, vcpus, and netvm only to null (which
    disconnects the qube from the network). Every other property, and any
    netvm other than null, is operator-only and refused. A guarded qube is
    refused; one that is out of scope or does not exist is reported as
    "not found".

    Returns {"ok": true} or {"ok": false, "error": "<reason>"}.
    """, {
        "name": _prop("string", "The qube to change."),
        "property": _prop("string", "label, memory, maxmem, vcpus or netvm."),
        "value": _prop(["string", "integer", "boolean", "null"],
                       "The new value: a label name, an integer, or null for netvm."),
    }, required=("name", "property", "value"))
def _qubes_props_set(args: dict) -> dict:
    return qrexec.call_qmcp(
        "qmcp.SetPropertyAIManaged",
        {"name": args["name"], "property": args["property"], "value": args["value"]},
        timeout=DOM0_TIMEOUT)


@_register("qubes_start", """
    Start a managed qube.

    A guarded qube is refused; one that is out of scope or does not exist is
    reported as "not found".

    Returns {"ok": true} or {"ok": false, "error": "<reason>"}.
    """, {
        "name": _prop("string", "The qube to start."),
    }, required=("name",))
def _qubes_start(args: dict) -> dict:
    return _lifecycle(args["name"], "start")


@_register("qubes_shutdown", """
    Shut down a managed qube, or kill it with force=true.

    A guarded qube is refused; one that is out of scope or does not exist is
    reported as "not found".

    Returns {"ok": true} or {"ok": false, "error": "<reason>"}.
    """, {
        "name": _prop("string", "The qube to shut down."),
        "force": _prop("boolean", "Kill the qube instead of a clean shutdown.",
                       default=False),
    }, required=("name",))
def _qubes_shutdown(args: dict) -> dict:
    return _lifecycle(args["name"], "kill" if args["force"] else "shutdown")


@_register("qubes_remove", """
    Remove a managed qube and its storage. It must be shut down first.

    This cannot be undone. Only a qube qubes-mcp created (by any of its
    creates, the operator's included) can be removed this way: one the operator brought into AI space
    is refused ("removing a qube qmcp did not create takes the operator's
    approval"), and the hub may ask for it with qubes_propose_revoke and
    remove true (or by deleting a project it is a member of). A lead and a guarded qube are refused too; one that is out
    of scope or does not exist is reported as "not found".

    Returns {"ok": true} or {"ok": false, "error": "<reason>"}.
    """, {
        "name": _prop("string", "The qube to remove."),
    }, required=("name",))
def _qubes_remove(args: dict) -> dict:
    return _lifecycle(args["name"], "remove")


@_register("qubes_run", """
    Run a command as root inside a managed qube.

    The qube, or the template it is built on, must carry the qubes-mcp
    in-qube services (a standalone carries its own). A halted qube is started
    to deliver the call, and is left running. `cmd` is an argv list (the
    default), or one string run by /bin/sh -c when shell is true. `timeout`
    limits the command inside the qube, 1 to 86400 seconds: at the limit the
    command and every process it started in its group are killed. `stdin` is
    text fed to it.

    Returns {"ok": true, "rc": <int>, "stdout": "...", "stderr": "..."} or
    {"ok": false, "error": "<reason>"}. A qube the caller may not operate, or that
    does not exist, gives the opaque {"ok": false, "error": "not found or refused"}.
    A call that gets no answer within timeout + 30 seconds gives {"ok": false,
    "error": "no answer within N s; the work in the qube may have run, or may
    still be running"}.
    """, {
        "name": _prop("string", "The qube to run in."),
        "cmd": _CMD,
        "shell": _SHELL,
        "timeout": _RUN_TIMEOUT,
        "stdin": _STDIN,
    }, required=("name", "cmd"))
def _qubes_run(args: dict) -> dict:
    return qrexec.call_service(args["name"], "qmcp.RunInAIManaged", _run_payload(args),
                               timeout=args["timeout"] + EXEC_MARGIN,
                               on_timeout=_no_answer(args["timeout"] + EXEC_MARGIN))


def _no_answer(seconds: int) -> dict:
    """The reply for an in-qube call that got no answer in time. The qube was
    reached (a refused or missing one answers at once), and the service there
    stops its own work at the caller's timeout, so the work may have run."""
    return {"ok": False, "error": f"no answer within {seconds} s; the work in the qube may "
                                  f"have run, or may still be running"}


@_register("qubes_copy", """
    Copy a file or directory from a managed qube to another qube.

    A copy from a member to another member of its slot or to the slot's dump
    sink, or from a lead to its members, goes through at once. Every other
    copy goes through an operator confirmation dialog in dom0, so this call
    may wait for a human to answer it, and fails if the operator declines. A
    copy into a guarded qube, a lead, the hub, dom0, a new disposable, a qube
    stopped by the anonymity gate or held for review, or a hidden project's
    qube from outside it, is refused. The copy lands on the target at
    /home/user/QubesIncoming/<source>/<basename of path>.

    Returns {"ok": true, "target": "...", "path": "..."} or
    {"ok": false, "error": "<reason>"}. A source the caller may not operate, or
    that does not exist, and a target that is not a qube name, give the opaque
    {"ok": false, "error": "not found or refused"}. A call that gets no answer
    within timeout + 30 seconds gives {"ok": false, "error": "no answer within
    N s; the work in the qube may have run, or may still be running"}.
    """, {
        "source": _prop("string", "Managed qube holding the file."),
        "target": _prop("string", "Qube to copy into."),
        "path": _prop("string", "Absolute path of the file or directory on the source."),
        "timeout": _prop("integer", "Time limit for the whole copy, including the "
                                    f"operator's answer, in seconds (1 to {MAX_TIMEOUT}); "
                                    "the copy is stopped inside the source qube at it.",
                         default=300, minimum=1, maximum=MAX_TIMEOUT),
    }, required=("source", "target", "path"))
def _qubes_copy(args: dict) -> dict:
    if not qrexec._valid_target(args["target"]):
        # As for the source: byte-identical to a policy denial, nothing started.
        return qrexec.refused()
    return qrexec.call_service(args["source"], "qmcp.CopyToAIManaged",
                               {"target": args["target"], "path": args["path"],
                                "timeout": args["timeout"]},
                               timeout=args["timeout"] + EXEC_MARGIN,
                               on_timeout=_no_answer(args["timeout"] + EXEC_MARGIN))


@_register("qubes_firewall_get", """
    Read the firewall rules of a qube.

    For the hub, any qube in AI space, guarded ones included, but a hidden
    project's, one the gate stopped or one held for review; for a lead, its
    own workers. Returns {"ok": true, "rules": "<one rule per line>"} in the
    Qubes Admin API rule grammar, for example "action=accept proto=tcp
    dstports=443" and a final "action=drop". Any other qube, or one that does
    not exist, gives the opaque {"ok": false, "error": "not found or refused"}.
    """, {
        "name": _prop("string", "The qube whose rules to read."),
    }, required=("name",))
def _qubes_firewall_get(args: dict) -> dict:
    reply = qrexec.call_admin("admin.vm.firewall.Get", args["name"], timeout=DOM0_TIMEOUT)
    if not reply.get("ok"):
        return reply
    return {"ok": True, "rules": reply.get("stdout", "")}


@_register("qubes_firewall_set", """
    Replace the firewall rules of a managed qube.

    The hub may also write a guarded qube's while the operator has opened it
    with the firewall half (qubes_propose_open). A project's lead is the
    exception: its firewall is the operator's, dom0
    writes it, and the hub's write is refused.
    Ask for a change with qubes_propose_lead_firewall.

    `rules` is the whole new ruleset: rule lines in the Qubes Admin API
    grammar, separated by newlines. With reload (the default) the rules are
    also applied at once in the qube's netvm; pass reload=false when that netvm
    is not running yet: the rules are saved and apply when it starts.

    Returns {"ok": true, "reloaded": <bool>}, with a "warning" when the rules
    were saved but the reload failed (they apply when the netvm next loads
    them); {"ok": false, "error": "firewall rules refused by qubesd"} for a
    ruleset qubesd would not take (nothing was changed); or the opaque
    {"ok": false, "error": "not found or refused"} for a qube the caller may not
    operate or that does not exist.
    """, {
        "name": _prop("string", "The qube whose rules to replace."),
        "rules": _prop("string", "The new ruleset, one rule per line."),
        "reload": _prop("boolean", "Apply the rules in the netvm at once.", default=True),
    }, required=("name", "rules"))
def _qubes_firewall_set(args: dict) -> dict:
    name = args["name"]
    try:
        body = args["rules"].encode("utf-8")
    except UnicodeEncodeError:
        # Only a lone surrogate escape in the JSON string gets here.
        return {"ok": False, "error": "rules must be valid Unicode text"}
    set_reply = qrexec.call_admin("admin.vm.firewall.Set", name, payload=body,
                                  timeout=DOM0_TIMEOUT,
                                  in_band={"ok": False, "error": RULES_REFUSED})
    if not set_reply.get("ok"):
        return set_reply
    if not args["reload"]:
        return {"ok": True, "reloaded": False}
    reload_reply = qrexec.call_admin("admin.vm.firewall.Reload", name, timeout=DOM0_TIMEOUT)
    if not reload_reply.get("ok"):
        # The rules are in force in qubesd: a failure here must not read as
        # "nothing changed".
        return {"ok": True, "reloaded": False,
                "warning": f"rules saved, reload failed: {reload_reply.get('error')}"}
    return {"ok": True, "reloaded": True}


@_register("qubes_clone", """
    Clone a managed qube into a new managed qube.

    The source must be managed: for the hub, anything it operates, including
    the TemplateVMs it manages; for a lead, one of its project's workers. A
    guarded source is refused, and one that is out of scope or does not exist
    is reported as "not found". The clone copies the source's settings, files
    and class (a StandaloneVM's clone is one too) and keeps the source's
    network, "none" included; a source whose network is not an enrolled
    gateway (for a lead, or for the hub's clone of a project's member, one of
    that project's worker networks) is refused. So is a source built on a
    template the anonymity gate stopped, one held for the operator's review,
    and for a lead one off its project's approved list. A cloned template
    keeps its source's network, which for a TemplateVM is normally none.

    A clone lands where its source is: a clone of one of p00's qubes joins p00,
    and a clone of a project's member joins that project, counts against its
    quota and is named inside its names (for the hub too, e.g.
    "ai-osint-..." for a member of osint). A clone of a lead, of a template or
    of a qube in no slot joins no slot, and is named as for qubes_spawn.

    dom0 runs one create at a time, so this call may wait for others to finish.

    Returns {"ok": true, "name": "<new name>"} or {"ok": false, "error": "<reason>"}.
    A clone whose reply never came says a qube may exist; check qubes_list.
    """, {
        "source": _prop("string", "Managed qube to clone."),
        "name": _prop("string", "Name of the clone, inside the caller's own names "
                                "(the hub's: ai-hub-...)."),
    }, required=("source", "name"))
def _qubes_clone(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.CloneAIManagedQube",
                            {"source": args["source"], "name": args["name"]},
                            timeout=CREATE_TIMEOUT,
                            on_timeout={"ok": False, "error": CLONE_LOST})


@_register("qubes_spawn_disposable", """
    Create a disposable qube from a disposable template.

    `template` is a managed or guarded disposable template (a qube with
    template_for_dispvms=True); one that is out of scope or does not exist is
    refused with "template must reference an ai-managed qube". The hub's
    disposable template must be on an enrolled gateway, or on none. A lead
    may use only its project's approved disposable templates, and only one
    whose network is on its project's list (or none). The disposable is born
    managed (a lead's joins its project), gets an auto-assigned name, keeps
    its template's network ("none" included), and is removed by dom0 once it
    halts. Start it with
    qubes_start, use it with qubes_run or qubes_copy, and end it with
    qubes_shutdown. For a single command, qubes_run_disposable does the whole
    cycle in one call.

    Returns {"ok": true, "name": "<auto-assigned, e.g. disp1234>"} or
    {"ok": false, "error": "<reason>"}. A spawn whose reply never came says a
    disposable may exist; check qubes_list.
    """, {
        "template": _prop("string", "Disposable template to start from; managed or guarded."),
    }, required=("template",))
def _qubes_spawn_disposable(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.SpawnDisposableAIManaged",
                            {"template": args["template"]}, timeout=CREATE_TIMEOUT,
                            on_timeout={"ok": False, "error": SPAWN_LOST})


_RUNNING_STATES = ("Running", "Transient")
_START_POLL_INTERVAL_SECONDS = 2.0
_START_POLL_ATTEMPTS = 15        # about 30 s for the disposable to reach Running


def _wait_running(name: str) -> bool:
    for attempt in range(_START_POLL_ATTEMPTS):
        if _get_property(name, "power_state").get("value") in _RUNNING_STATES:
            return True
        if attempt + 1 < _START_POLL_ATTEMPTS:
            time.sleep(_START_POLL_INTERVAL_SECONDS)
    return False


# qubes_run_disposable's teardown. One deadline covers every kill and read-back
# of it, so the call ends within this much after its command, kill or no kill.
TEARDOWN_SECONDS = 120.0
_KILL_RETRY_FIRST_SECONDS = 1.0
_KILL_RETRY_MAX_SECONDS = 10.0
# After a start whose reply was lost, how long a disposable must keep reading
# Halted before it counts as down: Qubes' pre-start reads Halted too.
_START_SETTLE_SECONDS = 10.0

# dom0's answer for a qube that does not exist (Qubes removes a disposable once
# it halts), and for a kill on a halted qube. Only these two are answers about
# the qube; a busy refusal, full call slots or the transport's refusal are not.
# "not found" is also dom0's answer for a qube that has left the caller's scope
# (the operator revoked or moved it), so it means "gone" only after a sign
# that the qube was down.
_GONE = {"ok": False, "error": "not found"}
_KILL_FAILED = "action failed"

TEARDOWN_FAILED = "the disposable could not be confirmed killed; it may still be running"
TEARDOWN_OUT_OF_REACH = ("the disposable left the caller's reach before its kill was "
                         "confirmed; it may still be running")

# The disposables of qubes_run_disposable calls still running, so a server that
# leaves with calls in flight can end them first (end_abandoned). A name leaves
# when its call returns, whatever happened: dom0 reuses disposable names.
_live: set = set()
_live_lock = threading.Lock()


def _within(limit: float, deadline: float) -> float:
    """A call's client timeout: `limit`, cut to the whole seconds left before
    `deadline` (at least one), so no single call outlasts the deadline by more
    than a second."""
    return min(limit, max(1, math.ceil(deadline - time.monotonic())))


def _end_disposable(name: str, deadline: float, start_unsettled: bool = False) -> str:
    """Kill the disposable and confirm it is down, by `deadline` (a
    time.monotonic() value): "killed", "out of reach" or "failed".

    "killed" only once dom0 reads it Halted, or says it does not exist after a
    sign it was down: a Halted read, or a kill dom0 accepted while no start can
    be under way. A "not found" with no such sign may be a qube taken out of
    the caller's scope while it runs: "out of reach", and no further kill can
    reach it. "failed": the deadline passed first.

    A kill dom0 refuses (busy, its call slots full, no answer) is tried again
    with back-off, and the state is not read after it: a refusal as busy may be
    the start still holding the qube's lock, and a qube in Qubes' pre-start
    reads Halted. A kill dom0 ran ("ok", or "action failed" on a halted qube)
    is read back, and made again while the qube reads anything but Halted: a
    kill during pre-start returns success and the qube comes up anyway
    (measured on hardware). `start_unsettled`: the start's reply was lost, so
    it may still be under way where dom0's lock does not cover it, and Halted
    counts only once it has held for _START_SETTLE_SECONDS."""
    wait = _KILL_RETRY_FIRST_SECONDS
    halted_since = None
    was_down = False
    while time.monotonic() < deadline:
        ran = True
        if halted_since is None:
            kill = _lifecycle(name, "kill", timeout=_within(LIFECYCLE_TIMEOUT, deadline))
            if kill == _GONE:
                return "killed" if was_down else "out of reach"
            ran = kill.get("ok") is True or kill.get("error") == _KILL_FAILED
            if kill.get("ok") is True and not start_unsettled:
                was_down = True
            if not ran:
                log.info("qubes_run_disposable: kill of %s refused (%s); trying again",
                         name, kill.get("error"))
        if ran and time.monotonic() < deadline:
            state = _get_property(name, "power_state", timeout=_within(DOM0_TIMEOUT, deadline))
            if state == _GONE:
                if was_down:
                    return "killed"
                log.warning("qubes_run_disposable: %s is no longer in reach; its kill was not "
                            "confirmed", name)
                return "out of reach"
            if state.get("ok") is True and state.get("value") == "Halted":
                was_down = True
                if not start_unsettled:
                    return "killed"
                now = time.monotonic()
                halted_since = now if halted_since is None else halted_since
                if now - halted_since >= _START_SETTLE_SECONDS:
                    return "killed"
                time.sleep(max(0.0, min(_START_POLL_INTERVAL_SECONDS, deadline - now)))
                continue
            halted_since = None
            if state.get("ok") is True:
                # It reads up: whatever was down before, it is not now.
                was_down = False
            log.info("qubes_run_disposable: %s reads %s after its kill; killing again", name,
                     state.get("value") if state.get("ok") is True else "unreadable")
        time.sleep(max(0.0, min(wait, deadline - time.monotonic())))
        wait = min(wait * 2, _KILL_RETRY_MAX_SECONDS)
    log.warning("qubes_run_disposable: the kill of %s could not be confirmed; it may still be "
                "running", name)
    return "failed"


def end_abandoned(bound: float) -> list:
    """End the disposables of qubes_run_disposable calls still in flight, all
    within `bound` seconds; the server calls this before it leaves with calls
    running. Returns the names it could not confirm killed. A start may be
    under way in any of them, so Halted must hold (_START_SETTLE_SECONDS)."""
    with _live_lock:
        names = sorted(_live)
    deadline = time.monotonic() + bound
    ended: dict = {}

    def end(name: str) -> None:
        try:
            ended[name] = _end_disposable(name, deadline, start_unsettled=True)
        except Exception:
            log.exception("ending the abandoned disposable %s failed", name)

    threads = [threading.Thread(target=end, args=(name,), daemon=True,
                                name="qubes-mcp-end-disposable") for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        # Each call is cut to the deadline (_within), plus at most a second.
        thread.join(max(0.0, deadline + 2 - time.monotonic()))
    left = [name for name in names if ended.get(name) != "killed"]
    for name in left:
        log.warning("disposable %s of an abandoned qubes_run_disposable may still be running",
                    name)
    return left


def _teardown(name: str, start_unsettled: bool = False) -> str:
    """The "teardown" field: "killed", "out of reach" or "failed"."""
    return _end_disposable(name, time.monotonic() + TEARDOWN_SECONDS, start_unsettled)


@_register("qubes_run_disposable", """
    Run one command in a fresh disposable qube, then discard it.

    Spawns a disposable from `template` (a managed or guarded disposable
    template; for a lead, one of its project's, as for qubes_spawn_disposable),
    starts it, waits until it is running, runs the command as root,
    and kills it; dom0 then removes it. A shutdown would only ask the guest,
    which may ignore it. The kill is read back and tried again, for up to
    about two minutes, until the disposable reads halted or gone; if any step
    after the spawn fails, the same teardown runs. cmd, shell, timeout and
    stdin work as for qubes_run.

    Returns {"ok": true, "name": "disp1234", "rc": <int>, "stdout": "...",
    "stderr": "..."} only once the disposable is confirmed killed. Otherwise
    {"ok": false, "stage": "spawn|start|wait|run|kill", "error": "...",
    "name": "...", "teardown": "killed|failed|out of reach|not started"}, with
    "name" and "teardown" once the spawn succeeded. "not started" means dom0
    refused the start before acting (its audit log has no room, or the
    caller's budget there is spent or its counter cannot be kept) and the
    disposable read halted, and still did 10 s later (a disposable Qubes is
    starting reads halted too): it exists, halted, until it is removed. A
    preloaded disposable, running already when that refusal came, is killed,
    and "teardown" says how that went. "failed" means it may still be running;
    "out of reach" that dom0 no longer shows it to the caller (the operator
    may have taken it out of scope) and it may still be running. Stage
    "kill" (the command ran, its disposable could not be confirmed killed)
    also carries rc, stdout and stderr. A spawn whose reply never came says a
    disposable may exist; check qubes_list.
    """, {
        "template": _prop("string", "Disposable template to start from; managed or guarded."),
        "cmd": _CMD,
        "shell": _SHELL,
        "timeout": _RUN_TIMEOUT,
        "stdin": _STDIN,
    }, required=("template", "cmd"))
def _qubes_run_disposable(args: dict) -> dict:
    spawn = qrexec.call_qmcp("qmcp.SpawnDisposableAIManaged",
                             {"template": args["template"]}, timeout=CREATE_TIMEOUT,
                             on_timeout={"ok": False, "error": SPAWN_LOST})
    if not spawn.get("ok"):
        return {"ok": False, "stage": "spawn", "error": spawn.get("error")}
    name = spawn.get("name")
    if not isinstance(name, str) or not name:
        # A success without a usable name: nothing can be started, run or torn
        # down by name, so report it as a failed spawn.
        log.warning("qubes_run_disposable: spawn reported success without a name")
        return {"ok": False, "stage": "spawn", "error": qrexec.REFUSED}
    with _live_lock:
        _live.add(name)
    try:
        return _run_in_disposable(name, args)
    finally:
        with _live_lock:
            _live.discard(name)


#: dom0's refusals made before a call acts, for want of room on its audit log
#: or of the caller's budget there (dom0/qmcp/services.py): a start refused so
#: never began. A disposable that reads halted then is left so, with no kill
#: spent on it; a preloaded one, running already, is killed.
NOT_ACTED = frozenset({
    "refused: dom0's audit log has no room",
    "refused: this caller's audit budget for today is spent",
    "refused: this caller's audit counter cannot be kept",
})


def _run_in_disposable(name: str, args: dict) -> dict:
    start = _lifecycle(name, "start")
    if not start.get("ok") and start.get("error") in NOT_ACTED:
        # A preloaded disposable arrives running already: it is killed (a kill
        # goes on past the budget and below the floor). One that reads halted,
        # and still does after the settle time (Qubes' pre-start reads halted
        # too), is left so, with no kill spent on it.
        halted = _get_property(name, "power_state").get("value") == "Halted"
        if halted:
            time.sleep(_START_SETTLE_SECONDS)
            halted = _get_property(name, "power_state").get("value") == "Halted"
        return {"ok": False, "name": name, "stage": "start", "error": start.get("error"),
                "teardown": "not started" if halted else _teardown(name)}
    if not start.get("ok"):
        # The transport's refusal may be a reply lost to the timeout, while
        # dom0 goes on starting it: its teardown waits out a pre-start.
        return {"ok": False, "name": name, "stage": "start", "error": start.get("error"),
                "teardown": _teardown(name, start_unsettled=start == qrexec.refused())}

    if not _wait_running(name):
        return {"ok": False, "name": name, "stage": "wait",
                "error": "disposable did not reach Running state in time",
                "teardown": _teardown(name)}

    run = qrexec.call_service(name, "qmcp.RunInAIManaged", _run_payload(args),
                              timeout=args["timeout"] + EXEC_MARGIN,
                              on_timeout=_no_answer(args["timeout"] + EXEC_MARGIN))
    # Killed, never asked to stop: a guest can ignore a shutdown request, and
    # dom0's "ok" for one means only that it was sent.
    teardown = _teardown(name)

    if not run.get("ok"):
        return {"ok": False, "name": name, "stage": "run", "error": run.get("error"),
                "teardown": teardown}

    if teardown != "killed":
        # The command succeeded but the qube was not confirmed killed: say so,
        # and still hand back what the command produced.
        return {"ok": False, "name": name, "stage": "kill",
                "error": TEARDOWN_FAILED if teardown == "failed" else TEARDOWN_OUT_OF_REACH,
                "teardown": teardown,
                "rc": run.get("rc"), "stdout": run.get("stdout"), "stderr": run.get("stderr")}

    return {"ok": True, "name": name, "rc": run.get("rc"),
            "stdout": run.get("stdout", ""), "stderr": run.get("stderr", "")}


@_register("qubes_feature_set", """
    Set a feature on a managed qube.

    Allowed keys: service.*, vm-config.*, menu-items and default-menu-items.
    Every other key is operator-only and refused. Booleans are stored as "1"
    (true) or "" (false); integers and strings pass through. null is rejected:
    this sets a feature, it never removes one. A guarded qube is refused; one
    that is out of scope or does not exist is reported as "not found".

    Returns {"ok": true, "feature": "<key>", "value": "<value read back>"},
    with "<unreadable>" when it was set but could not be read back and null
    when the qube or the feature was gone by then, or
    {"ok": false, "error": "<reason>"}.
    """, {
        "name": _prop("string", "The qube to change."),
        "feature": _prop("string", "Feature key, e.g. service.cups."),
        "value": _prop(["string", "integer", "boolean"], "The value to set."),
    }, required=("name", "feature", "value"))
def _qubes_feature_set(args: dict) -> dict:
    return qrexec.call_qmcp(
        "qmcp.SetFeatureAIManaged",
        {"name": args["name"], "feature": args["feature"], "value": args["value"]},
        timeout=DOM0_TIMEOUT)


@_register("qubes_events", """
    Collect qube events over a bounded window. The hub only: a project's lead
    has no event stream in this release, and polls qubes_state instead.

    Blocks for `duration` seconds (dom0 clamps it to 1-120) and returns the
    events seen on qubes in scope, as a list of {event, subject, subject_klass,
    ts}; tag add and delete events also carry `tag`. Only events fired after
    the window opens are seen, so to catch the result of an action, open the
    window first (a concurrent tool call) and then act. Calls run concurrently,
    so a long window does not hold up other tools.

    - qube: only events whose subject is this qube; one that is out of scope or
      does not exist is reported as "not found".
    - events: only these event names. An entry matches exactly or as the part
      before a colon ("property-set" matches "property-set:netvm").

    Returns {"ok": true, "events": [...]}, with a "warning" and the events so
    far if the event stream dropped mid-window, or {"ok": false, "error": "..."}.
    """, {
        "duration": _prop("integer", "Window length in seconds (clamped to 1-120)."),
        "qube": _prop(["string", "null"], "Only events about this qube.", default=None),
        "events": _prop(["array", "null"], "Only these event names (prefix before ':' "
                                           "matches).", items={"type": "string"}, default=None),
    }, required=("duration",))
def _qubes_events(args: dict) -> dict:
    duration = args["duration"]
    # dom0 clamps the window to [1, 120]; floor the wait to match, so a zero or
    # negative duration still gets its one-second window instead of a timeout.
    # (No float() here: an absurd integer would overflow it; qrexec clamps.)
    return qrexec.call_qmcp(
        "qmcp.AIManagedEvents",
        {"duration": duration, "qube": args["qube"], "events": args["events"]},
        timeout=max(duration, 1) + EVENTS_MARGIN)


@_register("qubes_get_pool_stats", """
    Report the caller's disk budget and where its new qubes go.

    Returns {"ok": true, "ai_managed_bytes_used": <int>,
    "ai_managed_bytes_cap": <int>, "ai_managed_bytes_headroom": <int>,
    "name_prefix": "<prefix your spawns carry; a clone's: see qubes_clone>"}.
    For the hub the figures are all of AI space against the operator's pool
    cap, and the reply adds
    "reserved_prefix", the prefix reserved for the names AI creates, which
    a project's names build on (<reserved_prefix><label>-...), and
    "projects": one entry per slot in use, {slot, label, lead, templates,
    networks, quota, used, has_dump, model, model_qube, anonymous}, starting
    with p00 (a project hidden from the hub is not listed),
    the hub's own qubes, which has no label, lead, templates, networks or
    quota. model is the lead's remote model endpoint (host:port) and
    model_qube the project's self-hosted model qube; at most one is set. In networks null
    is "none" and the first entry is the default; a recorded name that has
    left AI space reads "<out-of-scope>", unless it is an enrolled gateway; used is the slot's disk, or null
    when it cannot be read; has_dump says whether the slot has a dump
    sink, whose name the hub is not told. "projects" is null when the
    operator's project records cannot be read. For the hub the reply also
    adds "gateways": the networks the operator enrolled, the only ones a
    qube in AI space may be given, [{name, anonymising, label}, ...] (null
    when the registry cannot be read). Name them in a proposal. Read it before proposing a
    change to a project (qubes_propose_project_edit and the other proposal
    tools). For a project's lead the figures are its project's workers
    against the project's quota, and the reply adds "project" (its label),
    "templates" (what it may spawn from), "networks" (where its workers may
    be born; null is "none", the first entry is the default), "dump" (its
    dump sink, or null), "model" (its remote model endpoint, host:port, or
    null), "model_qube" (its self-hosted model qube, "<out-of-scope>" once
    that has left AI space, or null), "model_port" (11434 with a model
    qube, else null), "anonymous" (true when the project must stay
    anonymous: its networks are anonymising and dom0 stops it within about
    15 seconds of that ceasing to hold) and "hub_sees" (false when the hub cannot see or
    reach it). A lead with a model qube has no network: it reaches the
    model qube's port "model_port" through Qubes' qubes.ConnectTCP, e.g. by
    running `qvm-connect-tcp 11434:<model_qube>:11434` in the lead, after
    which the model answers on the lead's own localhost:11434. No other qube
    in AI space reaches a model qube while it is guarded.
    "used" is provisioned size, not bytes written. Check the headroom before a
    create (qubes_spawn, qubes_clone, a disposable) and stop creating when it
    falls below the next allocation. The cap and the quota are the operator's
    and cannot be changed from here. {"ok": false, "error": "pool cap not
    configured"} means the operator has removed the cap: create nothing new,
    and ask the operator.
    """, {})
def _qubes_get_pool_stats(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.GetPoolStats", timeout=DOM0_TIMEOUT)


# --------------------------------------------------------------------------
# Proposals: the hub asks, and the operator accepts or rejects in dom0
# --------------------------------------------------------------------------

# Each tool sends its arguments as the caller gave them (a quota converted to
# bytes), under the proposal's type. dom0 checks the shape with its own rules
# and stores its own normal form, which fills in the optional fields it has
# defaults for, so no default is filled in here: there would be two places
# deciding what an omitted field means.

_PROPOSAL_TERMS = inspect.cleandoc("""
    Nothing changes until the operator accepts the proposal in dom0, in the
    qubes-mcp window or with its `qmcp proposal accept`. Only the hub can
    propose; a project's lead is refused.
    Submitting checks the proposal's shape and looks no qube up, so a name
    that does not fit the fleet fails when the operator accepts, against the
    fleet as it is then. At most 10 proposals are pending at a time, and each
    expires after 7 days. If the operator accepts it but the change is
    refused or fails, the proposal closes as "failed"; submit it again if it
    is still wanted. Follow it with qubes_proposals.

    Returns {"ok": true, "id": <int>, "sha256": "<fingerprint>", "state":
    "pending", "expires": "<UTC time>"} or {"ok": false, "error": "<reason>"}.
    """)


def _proposal_doc(text: str) -> str:
    """A proposal tool's description: its own part, then what every proposal shares."""
    return inspect.cleandoc(text) + "\n\n" + _PROPOSAL_TERMS


def _submit(kind: str, args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.SubmitProposal", dict(args, type=kind), timeout=DOM0_TIMEOUT)


_TITLE = _prop("string", "What the proposal asks for, in 1-100 printable ASCII characters. "
                         'The operator sees it labelled "written by AI".')
_PROJECT = _prop("string", "The project's label (never its slot: by the time the operator "
                           "accepts, a slot can hold another project).")
_LEAD = _prop("object", 'Where the lead comes from: {"from": "template", "clone" or '
                        '"promote", "qube": NAME}.',
              properties={
                  "from": _prop("string", "template: a fresh lead built on the TemplateVM "
                                          "`qube`. clone: a copy of `qube`, one of the hub's "
                                          "own managed AppVMs or StandaloneVMs. promote: "
                                          "`qube` itself, one of the hub's own AppVMs or "
                                          "StandaloneVMs, becomes the lead.",
                                enum=["template", "clone", "promote"]),
                  "qube": _prop("string", "The TemplateVM, or the hub's own AppVM or "
                                          "StandaloneVM, the lead comes from."),
              }, required=["from", "qube"], additionalProperties=False)
_LEAD_CLASS = _prop(["string", "null"], 'With "from": "template", "standalone" makes the lead '
                                        "a StandaloneVM: its own copy of the template's root, "
                                        "so its tools stay after a restart (and so does anything "
                                        'left in it). Omit for an AppVM. A cloned or promoted '
                                        "lead keeps its source's class.",
                   enum=["appvm", "standalone", None])
_LEAD_NAME = _prop(["string", "null"], "A fresh lead's name, inside the project's names; "
                                       "omit it for <reserved_prefix><label>-lead.")
_LEAD_NETVM = _prop(["string", "null"], "The lead's own network: an enrolled gateway "
                                        "(qubes_get_pool_stats lists them), or \"none\". "
                                        "Omitted or null (the same thing here, never \"none\"), "
                                        "a fresh lead has none and a promoted one keeps its own.")
_MODEL = _prop(["string", "null"], "The lead's model endpoint, host:port, e.g. "
                                   '"api.anthropic.com:443". Needed when the lead has a network, '
                                   "unless the project already has one: dom0 writes the lead's "
                                   "firewall to allow that endpoint, DNS when it is a host name, "
                                   "and nothing else.")
_MODEL_QUBE = _prop(["string", "null"], "The project's self-hosted model qube, instead of model: "
                                        "a qube the lead reaches on port 11434 through Qubes' "
                                        "qubes.ConnectTCP. A lead whose model is a qube has no "
                                        "network. At accept, dom0 takes "
                                        "the qube out of p00, removes its network, guards it and "
                                        "kills it if it runs (one that already serves a project "
                                        "as a guarded model qube is left running). "
                                        "A model qube may serve several projects, which is a "
                                        "path between them unless an API filter guards it.")
_QUOTA_TEXT = ("the workers' disk quota: bytes, or a whole number and K, M, G or T, powers of "
               '1024 (e.g. "40G").')
_NETWORKS_TEXT = ('Worker networks: enrolled gateways (qubes_get_pool_stats lists them), or '
                  '"none" (or null, as qubes_get_pool_stats shows it) for no network.')
_TEMPLATES_TEXT = "Templates or disposable templates in AI space the lead may spawn from."


@_register("qubes_propose_project", _proposal_doc("""
    Propose a new project, for the operator to accept or reject in dom0.

    A project is a lead, the workers it creates and optionally a dump sink, in
    the lowest free slot (p01-p15). A fresh lead and the qubes it creates
    are named <reserved_prefix><label>-..., e.g. "ai-osint-scraper"
    (qubes_get_pool_stats reports reserved_prefix); Qubes names
    disposables, and a promoted lead keeps its own name.

    - label: 1-8 lowercase letters or digits, not one that reads as a slot
      ("p03") or a keyword ("none", "hub"). Omitted for an anonymous project.
    - anonymous: true for a project that must stay anonymous. Its lead comes
      from a template ("from": "template"), its networks are anonymising
      gateways or "none", and its templates are guarded. dom0 picks its label
      at random, so give no label and no lead_name; you are never told what
      was created, and unless hub_sees is true you cannot see or reach it,
      and no later proposal may name it.
    - hub_sees: with anonymous, true for an anonymous project you may see and
      operate: hidden from the network, not from you.
    - lead: {"from": ..., "qube": NAME}. "template": a fresh lead built on the
      TemplateVM NAME. "clone": a copy of NAME, one of the hub's own managed
      AppVMs or StandaloneVMs (in p00 or in no slot). "promote": NAME itself,
      one of the hub's own AppVMs or StandaloneVMs, becomes the lead, keeping
      its files, its template if it has one, and its network.
    - lead_class: with "from": "template", "standalone" for a StandaloneVM
      lead, whose tools stay installed across restarts. Omit it for an AppVM.
    - lead_name: a fresh lead's name, inside <reserved_prefix><label>-; omit
      it for <reserved_prefix><label>-lead. A promoted lead keeps its own name.
    - lead_netvm: the lead's own network, an enrolled gateway, or "none".
      Omitted, a fresh lead has no network and a promoted one keeps its own;
      a promoted lead takes only "none", since no network moves.
      A lead's network is never moved, only cleared; for another, give the
      project a new lead (qubes_propose_lead).
    - model: the lead's model endpoint, host:port. Needed when the lead has a
      network: dom0 writes the lead's firewall to allow that endpoint, DNS
      when it is a host name, and nothing else. Change it later with
      qubes_propose_lead_firewall.
    - model_qube: instead of model, the project's self-hosted model qube,
      which the lead reaches on port 11434. The lead then has no network.
      At accept, dom0 takes the qube out of p00, removes its network, guards
      it and kills it if it runs (unless it already serves a project as a
      guarded model qube): what you started in it ends there.
    - templates: up to 15 templates or disposable templates in AI space that
      the lead may spawn from. The lead's own template goes first when it is
      in AI space; the list must not end up empty.
    - networks: 1-8 worker networks, enrolled gateways or "none" for no
      network; the first is the default for new workers.
    - quota: the workers' disk, in bytes or as a size ("512M", "40G", "1T";
      K, M, G and T are powers of 1024). The pool cap still applies.
    - dump: true to also make the project's dump sink, <label>-dump. Refused
      when that name would start with reserved_prefix (a label such as "ai")
      or would be no qube name (a label starting with a digit): then propose
      the sink with a name once the project exists.

    It needs the operator's second tick, an extra confirmation, when it is
    anonymous, when the lead
    is promoted, when lead_netvm or a worker network is one AI space does not
    use today, when the model is one no project uses today, when it names a
    model qube (it guards that qube), or when the quota makes the projects'
    quotas add up to more than the pool cap.
    """), {
        "title": _TITLE,
        "label": _prop("string", "The new project's label: 1-8 lowercase letters or digits. "
                                 "Omit it for an anonymous project: dom0 picks one."),
        "anonymous": _prop("boolean", "A project that must stay anonymous; omit for false."),
        "hub_sees": _prop("boolean", "With anonymous: a project you may see and operate; "
                                     "omit for false (hidden from you)."),
        "lead": _LEAD,
        "lead_class": _LEAD_CLASS,
        "lead_name": _LEAD_NAME,
        "lead_netvm": _LEAD_NETVM,
        "model": _MODEL,
        "model_qube": dict(_MODEL_QUBE, description=_MODEL_QUBE["description"]
                           + " Give no lead_netvm with it."),
        "templates": _prop("array", _TEMPLATES_TEXT + " Omit for none beyond the lead's own.",
                           items={"type": "string"}),
        "networks": _prop("array", _NETWORKS_TEXT + " The first is the default.",
                          items={"type": ["string", "null"]}),
        "quota": _prop(["integer", "string"], "The project's quota: " + _QUOTA_TEXT),
        "dump": _prop("boolean", "Also make the project's dump sink; omit for false."),
    }, required=("title", "lead", "networks", "quota"), prepare=_quota_in_bytes)
def _qubes_propose_project(args: dict) -> dict:
    return _submit("project-create", args)


@_register("qubes_propose_project_edit", _proposal_doc("""
    Propose a change to a project's templates, worker networks or quota.

    The edit says what it adds, removes or sets, and is applied to the project
    as it is when the operator accepts it, changing only the entries it
    names: a change made since to anything else stands. Adding what is
    already there, or removing what is not, changes nothing. Workers keep
    their networks, so a network a worker still sits on cannot be taken off
    the list: the accept fails until no worker uses it. qubes_get_pool_stats
    shows every project as it is now.

    - project: the project's label.
    - add_templates, remove_templates: templates or disposable templates in AI
      space that the lead may spawn from.
    - add_networks, remove_networks: worker networks, enrolled gateways or
      "none" for no network (null there means "none" too, as
      qubes_get_pool_stats shows it).
    - default_network: this network, already on the list or added here, goes
      first, as the default for new workers.
    - quota: the new disk quota, in bytes or as a size, as for
      qubes_propose_project.

    null in default_network or quota leaves it as it is, like leaving it out.
    An entry cannot be both added and removed, and an edit must change
    something. It needs the operator's second tick, an extra confirmation,
    when it adds a network AI space does not use today, or sets a quota that
    makes the projects' quotas add up to more than the pool cap.
    """), {
        "title": _TITLE,
        "project": _PROJECT,
        "add_templates": _prop("array", "Add these: " + _TEMPLATES_TEXT,
                               items={"type": "string"}),
        "remove_templates": _prop("array", "Remove these from the approved templates.",
                                  items={"type": "string"}),
        "add_networks": _prop("array", "Add these: " + _NETWORKS_TEXT,
                              items={"type": ["string", "null"]}),
        "remove_networks": _prop("array", 'Remove these from the worker networks ("none", or '
                                          "null, is the no-network entry).",
                                 items={"type": ["string", "null"]}),
        "default_network": _prop(["string", "null"], "Put this worker network first, as the "
                                                     "default; null or omitted leaves it."),
        "quota": _prop(["integer", "string", "null"],
                       "The new quota, " + _QUOTA_TEXT + " Null or omitted leaves it."),
    }, required=("title", "project"), prepare=_quota_in_bytes)
def _qubes_propose_project_edit(args: dict) -> dict:
    return _submit("project-edit", args)


@_register("qubes_propose_dump", _proposal_doc("""
    Propose a dump sink for a project, or for the hub's own slot p00.

    A dump sink is a fresh qube with no network, outside AI space, that the
    slot's members (a project's workers, or the hub's own qubes in p00) copy
    files into without the operator's dialog. Neither the hub nor any qube in
    AI space can run a command in it or read from it, and nothing in it can
    reach back into AI space. A slot has at most one.

    - project: the project's label, or "p00" for the hub's own qubes.
    - name: the sink's name, not starting with reserved_prefix; omit it for
      <label>-dump, or hub-dump for p00 (refused when that would start with
      reserved_prefix, as for a label such as "ai", or be no qube name, as for
      a label starting with a digit: then give a name).
    """), {
        "title": _TITLE,
        "project": _prop("string", 'The project: its label, or "p00" '
                                   "for the hub's own qubes."),
        "name": _prop(["string", "null"], "The sink's name, not starting with reserved_prefix; "
                                          "omit it for <label>-dump, or hub-dump for p00, "
                                          "unless that starts with reserved_prefix or is "
                                          "no qube name."),
    }, required=("title", "project"))
def _qubes_propose_dump(args: dict) -> dict:
    return _submit("project-dump", args)


@_register("qubes_propose_lead", _proposal_doc("""
    Propose a new lead for a project, or removing its lead.

    - To remove the lead: remove=true and no other lead field. The lead's qube
      is removed with everything in it; the project keeps its workers, which
      only the hub reaches until the project has a lead again.
    - To give the project a new lead: lead, and optionally lead_class,
      lead_name, lead_netvm and model or model_qube, as for
      qubes_propose_project
      (without model, a new lead with a network takes the project's
      endpoint, and is refused when the project's model is a qube; a new
      lead with no network keeps the project's model qube; model_qube
      "none" takes it away), and keep_old, which has no
      default: true keeps the old lead as a worker of the same project, false
      removes it with everything in it. A kept lead keeps its network when the
      project lists it; otherwise add_old_network=true adds that network to
      the worker networks, and without it the kept lead loses its network. A
      proposal without keep_old is refused, even for a project that has no
      lead now, where it changes nothing. A kept lead keeps its name, so when
      it is named <reserved_prefix><label>-lead, give a fresh new lead a
      lead_name (a promoted one keeps its own name), except in an anonymous
      project, where dom0 names it (<reserved_prefix><label>-lead2 while the
      kept one holds -lead) and refuses a lead_name when the proposal is
      accepted. This is
      also how a project's lead moves to another network: a new lead on it,
      which can take what it needs from the old one, kept as a worker.

    It needs the operator's second tick, an extra confirmation, when it
    removes a lead, promotes one of the hub's qubes into the lead, gives the
    lead a network AI space does not use today, gives the project a
    different model endpoint, names a model qube, or takes the project's
    away.
    """), {
        "title": _TITLE,
        "project": _PROJECT,
        "remove": _prop(["boolean", "null"], "true to remove the lead; then give no other "
                                             "lead field."),
        "lead": dict(_LEAD, type=["object", "null"]),
        "lead_class": _LEAD_CLASS,
        "lead_name": _LEAD_NAME,
        "lead_netvm": _LEAD_NETVM,
        "keep_old": _prop(["boolean", "null"], "Required with a new lead, no default: true keeps "
                                               "the old lead as a worker of the project, false "
                                               "removes it with everything in it."),
        "model": _MODEL,
        "model_qube": dict(_MODEL_QUBE, description=_MODEL_QUBE["description"]
                           + ' Give no lead_netvm with it. "none" takes the project\'s model '
                             'qube away.'),
        "add_old_network": _prop(["boolean", "null"], "With keep_old true: add the old lead's "
                                                      "network to the worker networks, so it keeps "
                                                      "it. Omitted, a kept lead on a network the "
                                                      "project does not list loses its network."),
    }, required=("title", "project"))
def _qubes_propose_lead(args: dict) -> dict:
    return _submit("project-lead", args)


@_register("qubes_propose_lead_firewall", _proposal_doc("""
    Propose a change to a project's lead firewall.

    A lead's firewall is the operator's: dom0 writes it, for a lead with a
    network when the lead is made (its model endpoint, DNS when that is a
    host name, and nothing else), and the hub's own writes to it are
    refused. Give one of:
    - model: a new model endpoint, host:port; the firewall becomes that
      endpoint, DNS when it is a host name, and nothing else. Refused while
      the project's model is a qube: a remote model takes a new lead on a
      network (qubes_propose_lead).
    - model_qube: the project's self-hosted model qube (the lead loses its
      network, if it has one; the qube leaves p00, loses its network, is
      guarded and, unless it is already a guarded model qube, is killed if it
      runs), or "none" (the project's model qube is taken away; nothing else
      changes).
    - rules: exactly these rules, in the Qubes Admin API grammar, one rule per
      entry, e.g. "action=accept proto=tcp dsthost=api.example.com
      dstports=443" (up to 32; keys action, proto, dsthost, dst4, dst6,
      dstname, dstports, specialtarget and icmptype; the last is usually
      "action=drop").
    While the project's model is a qube, model and rules are refused.

    qubes_firewall_get reads the lead's rules as they are. A new endpoint,
    new rules, a model qube, and taking the project's away each need the
    operator's second tick: the window shows the old and new.
    """), {
        "title": _TITLE,
        "project": _PROJECT,
        "model": _prop(["string", "null"], "A new model endpoint, host:port; the firewall becomes "
                                           "that endpoint, DNS when it is a host name, and "
                                           "nothing else. Give one of model, model_qube or "
                                           "rules."),
        "model_qube": dict(_MODEL_QUBE, description=_MODEL_QUBE["description"]
                           + ' "none" takes the project\'s model qube away. Give one of model, '
                             "model_qube or rules."),
        "rules": _prop(["array", "null"], "Exactly these rules, one per entry. Give one of model, "
                                          "model_qube or rules.",
                       items={"type": "string"}),
    }, required=("title", "project"))
def _qubes_propose_lead_firewall(args: dict) -> dict:
    return _submit("project-firewall", args)


@_register("qubes_propose_project_delete", _proposal_doc("""
    Propose deleting a project, with its lead and every worker.

    Accepting it removes the project's lead and every worker with everything
    in them, keeps its dump sink (outside AI space, no longer the project's)
    and frees the slot. It always needs the operator's second tick, an extra
    confirmation.
    """), {
        "title": _TITLE,
        "project": _PROJECT,
    }, required=("title", "project"))
def _qubes_propose_project_delete(args: dict) -> dict:
    return _submit("project-delete", args)


@_register("qubes_propose_open", _proposal_doc("""
    Propose opening a guarded qube to this hub for a bounded time.

    A guarded qube is a reference: it is listed and can be spawned from, and
    every attempt to run a command in it, copy a file into it or change its
    firewall is refused. A window lifts that for one qube, for as long as the
    operator accepts, and nothing else: while it is open this hub may run
    commands in the qube as root, and copy a file in, which the operator
    confirms one file at a time. It can never change which network the qube
    is on.

    Use it to get software into a guarded template, or to maintain a model
    qube. Say in the title what the qube is for and what will be done in it:
    this always needs the operator's second tick, and those words are what
    they read.

    - qube: the guarded qube to open.
    - for: how long: a whole number of seconds, or one ending in s, m or h
      (90s, 30m, 2h), with no space. At most 24h, and there is no indefinite
      form.
    - firewall: also let this hub write that qube's firewall rules while the
      window is open. Leave it out unless the work needs it.

    The window ends by itself, at the next boot of the machine, and whenever
    the operator closes it; when it ends, the qube is killed if it is running,
    so what this hub had running in it is stopped, and firewall rules this hub
    wrote stay (the operator's own manage of it ends the window with no
    kill). Nothing
    tells this hub when it ended: a call that worked before and is refused
    now means it is closed.
    """), {
        "title": _TITLE,
        "qube": _prop("string", "The guarded qube to open."),
        "for": _prop("string", "How long: seconds, or with s, m or h (90s, 30m, 2h). "
                               "At most 24h."),
        "firewall": _prop("boolean", "Also let the hub write that qube's firewall rules while "
                                     "it is open. Leave it out otherwise."),
    }, required=("title", "qube", "for"))
def _qubes_propose_open(args: dict) -> dict:
    return _submit("qube-open", args)


@_register("qubes_propose_manage", _proposal_doc("""
    Propose managing a qube: adopting it into AI space, or un-guarding it.

    Accepting runs `qmcp manage QUBE`. A qube outside AI space, which this
    hub cannot see today, joins it managed; a guarded qube leaves the guarded
    state. There is no time limit: from then on this hub may run commands in
    it as root, copy files out of it, write its firewall rules, clone it and
    remove it, until the operator guards or revokes it. It does not change
    the qube's network, and a qube adopted this way joins no slot.

    For a bounded stretch in a guarded qube, qubes_propose_open is the way
    in; ask for this only when the qube should stay the hub's. Say in the
    title which qube it is and what it is for: this always needs the
    operator's second tick, and those words are what they read.

    - qube: the qube to manage. The command refuses dom0, the hub, a drop
      box, a gateway (gateways are always guarded), a qube held for review, a
      qube wearing qmcp badges whose dom0 label is not its own, one on a
      network that is not an enrolled gateway, a qube wearing lead badges or a
      project's member badge without being a managed qube of it, and, from
      this hub, a qube that holds a PCI device (a USB or network controller)
      or whose devices cannot be read, and a template that a qube this hub
      does not operate (outside AI space, or guarded) is built on, or whose
      dependants cannot be read. Managing a template lets this
      hub change what every qube built on it runs, from their first start
      after the template has shut down.

    A qube of a hidden project fails at accept exactly as a name that does
    not exist.
    """), {
        "title": _TITLE,
        "qube": _prop("string", "The qube to manage: one outside AI space to adopt, or a guarded "
                                "one to take out of the guarded state."),
    }, required=("title", "qube"))
def _qubes_propose_manage(args: dict) -> dict:
    return _submit("qube-manage", args)


@_register("qubes_propose_revoke", _proposal_doc("""
    Propose revoking a qube: handing it back to the operator, out of reach.

    Accepting runs `qmcp revoke QUBE`: every qmcp badge comes off, so the
    qube leaves AI space and any project slot it is in, with what it holds,
    and its default disposable template is set to none. From then on dom0
    answers this hub and every lead about it as about a name that does not
    exist (an enrolled gateway stays enrolled, and is still named); bringing
    it back takes the operator, or an accepted
    qubes_propose_manage. It is killed if it runs, unless shutdown is false,
    so what this hub had running in it is stopped; killing a gateway cuts the
    network of every qube on it. Nothing is removed but a disposable, which
    Qubes removes when it stops, unless remove is true: the qube and its
    files stay, outside AI space. With remove true, accepting also removes
    the qube and its storage, which cannot be undone: the way to have a qube
    qubes-mcp did not create removed (qubes_remove refuses one), besides
    deleting a project it is a member of. The command
    then refuses, with nothing changed, a guarded qube, a project's model
    qube, a qube a project lists (its lead, dump sink, an approved template
    or a worker network), a qube others use as their template, default
    disposable template or network, and one a global setting names.

    The command refuses a project's lead (removed or replaced with
    qubes_propose_lead) and a qube held for review, and accepting fails for a
    qube outside AI space: this hub revokes only what it can see. Say in the title which
    qube it is and why it goes back: this always needs the operator's second
    tick, and those words are what they read.

    - qube: the qube to revoke.
    - remove: true to remove the qube after revoking it; it is killed first,
      so shutdown false with it is refused at submit. Omitted, null or false,
      nothing is removed.
    - shutdown: false to leave it running, which only a guarded qube that is
      not open may be: one this hub could run commands in is always killed,
      so what this hub started in it does not run on outside AI space, and
      false makes the accept fail. Omitted or null, it is killed if it runs;
      the stored proposal always holds which.

    A qube of a hidden project fails at accept exactly as a name that does
    not exist.
    """), {
        "title": _TITLE,
        "qube": _prop("string", "The qube to revoke."),
        "shutdown": _prop(["boolean", "null"], "false leaves the qube running. Omitted or null, "
                                               "it is killed if it runs (true)."),
        "remove": _prop(["boolean", "null"], "true also removes the qube and its storage, "
                                             "after the revoke. Omitted or null: false."),
    }, required=("title", "qube"))
def _qubes_propose_revoke(args: dict) -> dict:
    return _submit("qube-revoke", args)


@_register("qubes_propose_packages", _proposal_doc("""
    Propose installing exact distro packages into a template in AI space.

    Accepting runs `qmcp template install TEMPLATE PKG...`: dom0 installs
    those packages and what they depend on (not recommended or weak
    dependencies) into the TemplateVM, as root, with the template's own
    package manager (apt-get, dnf or pacman, whichever it has), from the
    repositories the template already trusts, over the path its updates
    already take. First the template checks that each name is a package's
    exact name in those repositories; one that is not refuses the whole
    install, and nothing is installed. An install that would remove an
    installed package is refused too, though one may be upgraded when a new
    one needs it, and on Arch -Su may replace a package as the repositories
    say. On Arch the install also upgrades the
    whole template (pacman -Sy, then -Su with the names), as Qubes' own
    updater does. Every qube built on the template runs the packages from
    its first start after the template has shut down. A halted template is
    started for the install and shut down again; an install may take
    minutes, and the proposal reads pending while it runs. After 30 minutes
    dom0 stops waiting and the proposal reads failed, though in a template
    that was already running the install may still be going on, or may have
    stopped part-way.

    This hub chooses the names, and the install runs no command this hub
    wrote. But the install scripts of each package and each dependency run
    there as root, and a package can itself add a repository or download more
    software when it is installed (one that configures repositories, or an
    "-installer" package): name only packages whose installing does what the
    work needs. Use it to get distro packages
    into a guarded template without opening it: qubes_propose_open gives
    root in a qube for a while, this gives exactly a package list. Say in the
    title what the packages are for: this always needs the operator's second
    tick, and those words are what they read.

    - template: a TemplateVM in AI space, guarded or managed (not a
      disposable template or a standalone), not stopped by the anonymity gate,
      not held for review, and with no other install or prepare running in it.
    - packages: 1-32 names, each exactly as the repositories name the
      package, each once: letters, digits, '.', '_', '+' and '-', a letter or
      digit first, at most 100 characters, not ending in '-'. No versions,
      groups, globs, patterns or architecture suffixes: apt would read an
      unknown name with a '.' as a regex, and dnf a versioned name as a
      downgrade, so the template refuses any name that is not a package's
      own.

    A template of a hidden project fails at accept exactly as a name that
    does not exist.
    """), {
        "title": _TITLE,
        "template": _prop("string", "The TemplateVM in AI space, guarded or managed."),
        "packages": _prop("array", "1-32 exact package names, each once: letters, digits, '.', "
                                   "'_', '+' and '-', a letter or digit first, at most 100 "
                                   "characters, not ending in '-'. No versions, groups, globs or "
                                   "architecture suffixes.",
                          items={"type": "string"}),
    }, required=("title", "template", "packages"))
def _qubes_propose_packages(args: dict) -> dict:
    return _submit("template-install", args)


@_register("qubes_proposals", """
    List the hub's proposals and what became of them, or show one in full.

    Returns {"ok": true, "proposals": [{id, state, type, title, submitted,
    expires, sha256}, ...]}, newest first. With id, the reply is that one
    entry's fields plus "proposal": the options as dom0 stored them, which
    is what the operator reads and accepts. dom0 fills in every optional
    field (a revoke always holds shutdown) but model and model_qube, which
    appear only when given, add_old_network, anonymous and hub_sees, which
    appear only when true, and lead_class, which appears only as
    "standalone"; a firewall proposal holds whichever of model, model_qube
    and rules it was given.

    state is one of:
    - pending: waiting for the operator (an accept running now reads pending).
    - accepted: the operator accepted it and the change was made.
    - rejected: the operator turned it down; nothing changed.
    - expired: 7 days passed without a decision; nothing changed.
    - failed: the operator accepted it, but the change was refused or stopped
      part of the way, so the fleet may show part of it. Submit it again if
      it is still wanted.

    The hub learns the state only, never a reason or the operator's report:
    read the fleet (qubes_list, qubes_get_pool_stats) to see what changed.
    Only the hub reads proposals; a project's lead is refused. An id that is
    not one of the hub's proposals gives {"ok": false, "error": "no such
    proposal"}.
    """, {
        "id": _prop(["integer", "null"], "A proposal's id, to show that one with its stored "
                                         "options; omit it to list them all.", default=None),
    })
def _qubes_proposals(args: dict) -> dict:
    payload = {} if args["id"] is None else {"id": args["id"]}
    return qrexec.call_qmcp("qmcp.ProposalStatus", payload, timeout=DOM0_TIMEOUT)
