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
import time
from dataclasses import dataclass
from typing import Callable

from qubes_mcp import qrexec

log = logging.getLogger(__name__)

# Client-side timeouts, in seconds.
DOM0_TIMEOUT = 60.0
# A create may first wait in dom0 for the create lock (up to 120 s), then build.
CREATE_TIMEOUT = 300.0
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


class UnknownTool(LookupError):
    """No tool has this name."""


class ArgumentError(ValueError):
    """The arguments do not match the tool's inputSchema."""


TOOLS: dict[str, Tool] = {}


def _register(name: str, description: str, properties: dict, required: tuple = ()):
    schema: dict = {"type": "object", "properties": copy.deepcopy(properties),
                    "additionalProperties": False}
    if required:
        schema["required"] = list(required)

    def register(handler: Callable[[dict], dict]) -> Callable[[dict], dict]:
        if name in TOOLS:
            raise RuntimeError(f"tool {name} registered twice")
        TOOLS[name] = Tool(name, inspect.cleandoc(description), schema, handler)
        return handler
    return register


def _prop(json_type, description: str, **extra) -> dict:
    schema = {"type": json_type, "description": description}
    schema.update(extra)
    return schema


# --------------------------------------------------------------------------
# Argument validation: a small subset of JSON Schema (type, with unions as a
# list; items; properties; required; additionalProperties: false; enum).
# --------------------------------------------------------------------------

SCHEMA_KEYWORDS = frozenset({
    "type", "description", "default", "enum", "items",
    "properties", "required", "additionalProperties",
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
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            problem = _problem(schema["items"], item, f"{where}[{index}]")
            if problem:
                return problem
    if isinstance(value, dict):
        properties = schema.get("properties", {})

        def named(key: str) -> str:
            return f"{where}.{key}" if where else f"argument {_shown(key)}"

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
    the defaults of omitted optional arguments filled in. Raises ArgumentError."""
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
    return out


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
_RUN_TIMEOUT = _prop("integer", "Time limit for the command inside the qube, in seconds.",
                     default=60)
_STDIN = _prop("string", "Text fed to the command's standard input.", default="")


def _get_property(name: str, prop: str) -> dict:
    return qrexec.call_qmcp("qmcp.GetPropertyAIManaged",
                            {"name": name, "property": prop}, timeout=DOM0_TIMEOUT)


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


def _lifecycle(name: str, action: str) -> dict:
    return qrexec.call_qmcp("qmcp.LifecycleAIManaged",
                            {"name": name, "action": action}, timeout=LIFECYCLE_TIMEOUT)


def _run_payload(args: dict) -> dict:
    return {"cmd": args["cmd"], "shell": args["shell"],
            "timeout": args["timeout"], "stdin": args["stdin"]}


# --------------------------------------------------------------------------
# The tools
# --------------------------------------------------------------------------

@_register("qubes_list", """
    List the qubes in the caller's scope.

    The hub's scope is all of AI space. A project's lead sees its project's
    workers, the templates its project may spawn from, and its project's worker
    networks.

    Each entry is {name, klass, label, template, power_state, guarded, slot,
    lead}. `slot` is the project slot a qube belongs to (p00 is the hub's own
    qubes, p01-p15 are projects), or null; `lead` is true for a project's lead.

    A qube in scope is in one of two states:
    - managed (guarded: false): the caller may operate it: start and shut it
      down, run commands in it, copy files, change its settings, clone or
      remove it. For the hub this includes the templates and disposable
      templates it manages, and the leads (which only the operator removes).
      A lead may operate only the entries in its own slot (`slot` set); its
      approved templates and networks are listed so it can spawn from and
      onto them.
    - guarded (guarded: true): reference only. It is listed, can be read, and
      can be spawned from (as a template or a disposable template), but is
      never operated.

    Qubes out of scope are not listed. Every tool answers a qube that is out of
    scope, or does not exist, with the same opaque "not found" refusal. A
    template out of scope is redacted in the `template` field.

    Returns {"ok": true, "qubes": [...]} or {"ok": false, "error": "..."}.
    """, {})
def _qubes_list(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.ListAIManagedQubes", timeout=DOM0_TIMEOUT)


@_register("qubes_spawn", """
    Create a new qube. It is born managed.

    - name: must start with the caller's name prefix (qubes_get_pool_stats
      reports it): for the hub, the operator's reserved prefix (default
      "ai-") but outside every project's names; for a lead, its project's
      prefix (e.g. "ai-osint-"). Any other name is refused.
    - klass: "AppVM" (the default) or "DispVMTemplate", both built on a
      TemplateVM; or "DispVM", built on a disposable template (a qube with
      template_for_dispvms=True). A lead cannot create a DispVMTemplate.
    - template: the qube to build on, managed or guarded. A lead may use only
      its project's approved templates. One that is out of scope or does not
      exist is refused with "template must reference an ai-managed qube",
      which never says which of the two it is.
    - netvm: omit it and the network is inherited. For the hub: the source's
      netvm (for a DispVM, its disposable template's), else the hub's own
      netvm if that is an AI qube, else the operator's configured default; if
      none applies the create is refused, and a name must equal the inherited
      value. For a lead: its project's default worker network, or another one
      on the project's list; a DispVM keeps its disposable template's, which
      must be on the list. A lead's own network is never used. Pass null for
      no network, which is always allowed. After birth a qube's network can
      only be cleared (netvm null), never moved to another one.
    - private_size: optional, in bytes. Grows the persistent private volume
      beyond the Qubes default. It counts against the caller's disk budget
      (see qubes_get_pool_stats), and a size above the operator's per-qube
      limit is refused.

    dom0 runs one create at a time, so this call may wait for others to finish.

    Returns {"ok": true, "name": "<name>"}, with a "warning" if a secondary step
    failed, or {"ok": false, "error": "<reason>"}.
    """, {
        "name": _prop("string", "Name of the new qube; must carry the caller's prefix."),
        "template": _prop("string", "Template (or, for a DispVM, disposable template) "
                                    "to build on; managed or guarded."),
        "klass": _prop("string", "Kind of qube to create.",
                       enum=["AppVM", "DispVMTemplate", "DispVM"], default="AppVM"),
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
    return qrexec.call_qmcp("qmcp.SpawnAIManagedQube", payload, timeout=CREATE_TIMEOUT)


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

    This cannot be undone. A guarded qube is refused; one that is out of scope
    or does not exist is reported as "not found".

    Returns {"ok": true} or {"ok": false, "error": "<reason>"}.
    """, {
        "name": _prop("string", "The qube to remove."),
    }, required=("name",))
def _qubes_remove(args: dict) -> dict:
    return _lifecycle(args["name"], "remove")


@_register("qubes_run", """
    Run a command as root inside a managed qube.

    The qube must be built on a template that carries the qubes-mcp in-qube
    services. A halted qube is started to deliver the call, and is left running.
    `cmd` is an argv list (the default), or one string run by /bin/sh -c when
    shell is true. `timeout` limits the command inside the qube; `stdin` is
    text fed to it.

    Returns {"ok": true, "rc": <int>, "stdout": "...", "stderr": "..."} or
    {"ok": false, "error": "<reason>"}. A qube the caller may not operate, or that
    does not exist, gives the opaque {"ok": false, "error": "not found or refused"}.
    """, {
        "name": _prop("string", "The qube to run in."),
        "cmd": _CMD,
        "shell": _SHELL,
        "timeout": _RUN_TIMEOUT,
        "stdin": _STDIN,
    }, required=("name", "cmd"))
def _qubes_run(args: dict) -> dict:
    return qrexec.call_service(args["name"], "qmcp.RunInAIManaged", _run_payload(args),
                               timeout=args["timeout"] + EXEC_MARGIN)


@_register("qubes_copy", """
    Copy a file or directory from a managed qube to another qube.

    A copy between two qubes of the same project slot, or into that slot's
    dump sink, goes through at once. Every other copy goes through an operator
    confirmation dialog in dom0, so this call may wait for a human to answer
    it, and fails if the operator declines. A copy into a guarded qube, a lead
    or the hub is refused. The copy lands on the target at
    /home/user/QubesIncoming/<source>/<basename of path>.

    Returns {"ok": true, "target": "...", "path": "..."} or
    {"ok": false, "error": "<reason>"}. A source the caller may not operate, or
    that does not exist, gives the opaque
    {"ok": false, "error": "not found or refused"}.
    """, {
        "source": _prop("string", "Managed qube holding the file."),
        "target": _prop("string", "Qube to copy into."),
        "path": _prop("string", "Absolute path of the file or directory on the source."),
        "timeout": _prop("integer", "Time limit for the whole copy, including the "
                                    "operator's answer, in seconds.", default=300),
    }, required=("source", "target", "path"))
def _qubes_copy(args: dict) -> dict:
    return qrexec.call_service(args["source"], "qmcp.CopyToAIManaged",
                               {"target": args["target"], "path": args["path"]},
                               timeout=args["timeout"] + EXEC_MARGIN)


@_register("qubes_firewall_get", """
    Read the firewall rules of a managed qube.

    Returns {"ok": true, "rules": "<one rule per line>"} in the Qubes Admin API
    rule grammar, for example "action=accept proto=tcp dstports=443" and a
    final "action=drop". A qube the caller may not operate, or that does not
    exist, gives the opaque {"ok": false, "error": "not found or refused"}.
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

    `rules` is the whole new ruleset: rule lines in the Qubes Admin API
    grammar, separated by newlines. With reload (the default) the rules are
    also applied at once in the qube's netvm; pass reload=false when that netvm
    is not running yet: the rules are saved and apply when it starts.

    Returns {"ok": true, "reloaded": <bool>}; the opaque
    {"ok": false, "error": "not found or refused"} for a qube the caller may not
    operate or that does not exist; or {"ok": false, "error": "set ok but
    reload failed: ..."} when the rules were saved but not applied.
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
                                  timeout=DOM0_TIMEOUT)
    if not set_reply.get("ok"):
        return set_reply
    if not args["reload"]:
        return {"ok": True, "reloaded": False}
    reload_reply = qrexec.call_admin("admin.vm.firewall.Reload", name, timeout=DOM0_TIMEOUT)
    if not reload_reply.get("ok"):
        return {"ok": False,
                "error": f"set ok but reload failed: {reload_reply.get('error')}"}
    return {"ok": True, "reloaded": True}


@_register("qubes_clone", """
    Clone a managed qube into a new managed qube.

    The source must be managed: for the hub, anything it operates, including
    the TemplateVMs it manages; for a lead, one of its project's workers. A
    guarded source is refused, and one that is out of scope or does not exist
    is reported as "not found". The new name must start with the caller's
    prefix, as for qubes_spawn. The clone copies the source's settings and
    keeps the source's network, "none" included; a source on a network outside
    the caller's scope (for a lead, off its project's list) is refused. A
    cloned template stays off the network.

    dom0 runs one create at a time, so this call may wait for others to finish.

    Returns {"ok": true, "name": "<new name>"} or {"ok": false, "error": "<reason>"}.
    """, {
        "source": _prop("string", "Managed qube to clone."),
        "name": _prop("string", "Name of the clone; must carry the caller's prefix."),
    }, required=("source", "name"))
def _qubes_clone(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.CloneAIManagedQube",
                            {"source": args["source"], "name": args["name"]},
                            timeout=CREATE_TIMEOUT)


@_register("qubes_spawn_disposable", """
    Create a disposable qube from a disposable template.

    `template` is a managed or guarded disposable template (a qube with
    template_for_dispvms=True); one that is out of scope or does not exist is
    refused with "template must reference an ai-managed qube". A lead may use
    only its project's approved disposable templates, and only one whose
    network is on its project's list (or none). The disposable is born
    managed (a lead's joins its project), gets an auto-assigned name, keeps
    its template's network ("none" included), and is removed by dom0 once it
    halts. Start it with
    qubes_start, use it with qubes_run or qubes_copy, and end it with
    qubes_shutdown. For a single command, qubes_run_disposable does the whole
    cycle in one call.

    Returns {"ok": true, "name": "<auto-assigned, e.g. disp1234>"} or
    {"ok": false, "error": "<reason>"}.
    """, {
        "template": _prop("string", "Disposable template to start from; managed or guarded."),
    }, required=("template",))
def _qubes_spawn_disposable(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.SpawnDisposableAIManaged",
                            {"template": args["template"]}, timeout=CREATE_TIMEOUT)


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


def _teardown(name: str, stage: str) -> None:
    """Kill the disposable so dom0 removes it. Best effort: the failure being
    reported is the original one, but a refused kill is logged for the
    operator, because it can leave a running disposable behind."""
    reply = _lifecycle(name, "kill")
    if not reply.get("ok"):
        log.warning("qubes_run_disposable: kill of %s after a failed %s step was refused: %s",
                    name, stage, reply.get("error"))


@_register("qubes_run_disposable", """
    Run one command in a fresh disposable qube, then discard it.

    Spawns a disposable from `template` (a managed or guarded disposable
    template; for a lead, one of its project's, as for qubes_spawn_disposable),
    starts it, waits until it is running, runs the command as root,
    and shuts it down; dom0 then removes it. If any step after the spawn fails,
    the disposable is shut down or killed so it is still removed. cmd, shell,
    timeout and stdin work as for qubes_run.

    Returns {"ok": true, "name": "disp1234", "rc": <int>, "stdout": "...",
    "stderr": "..."} on success, or {"ok": false, "stage":
    "spawn|start|wait|run|shutdown", "error": "...", "name": "..."} on
    failure, with "name" once the spawn succeeded.
    """, {
        "template": _prop("string", "Disposable template to start from; managed or guarded."),
        "cmd": _CMD,
        "shell": _SHELL,
        "timeout": _RUN_TIMEOUT,
        "stdin": _STDIN,
    }, required=("template", "cmd"))
def _qubes_run_disposable(args: dict) -> dict:
    spawn = qrexec.call_qmcp("qmcp.SpawnDisposableAIManaged",
                             {"template": args["template"]}, timeout=CREATE_TIMEOUT)
    if not spawn.get("ok"):
        return {"ok": False, "stage": "spawn", "error": spawn.get("error")}
    name = spawn.get("name")
    if not isinstance(name, str) or not name:
        # A success without a usable name: nothing can be started, run or torn
        # down by name, so report it as a failed spawn.
        log.warning("qubes_run_disposable: spawn reported success without a name")
        return {"ok": False, "stage": "spawn", "error": qrexec.REFUSED}

    start = _lifecycle(name, "start")
    if not start.get("ok"):
        _teardown(name, "start")
        return {"ok": False, "name": name, "stage": "start", "error": start.get("error")}

    if not _wait_running(name):
        _teardown(name, "wait")
        return {"ok": False, "name": name, "stage": "wait",
                "error": "disposable did not reach Running state in time"}

    run = qrexec.call_service(name, "qmcp.RunInAIManaged", _run_payload(args),
                              timeout=args["timeout"] + EXEC_MARGIN)
    shutdown = _lifecycle(name, "shutdown")

    if not run.get("ok"):
        # The run failed; a clean shutdown was still attempted above. If that
        # failed too, kill, so dom0 removes the disposable instead of leaving
        # it running.
        if not shutdown.get("ok"):
            _teardown(name, "run")
        return {"ok": False, "name": name, "stage": "run", "error": run.get("error")}

    if not shutdown.get("ok"):
        # The command succeeded but the qube did not shut down: kill it, and
        # still hand back what the command produced.
        _teardown(name, "shutdown")
        return {"ok": False, "name": name, "stage": "shutdown",
                "error": shutdown.get("error"),
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

    Returns {"ok": true, "feature": "<key>", "value": "<value read back>"} or
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
    "name_prefix": "<prefix new names must carry>"}. For the hub the figures
    are all of AI space against the operator's pool cap. For a project's lead
    they are its project's workers against the project's quota, and the reply
    adds "project" (its label), "templates" (what it may spawn from),
    "networks" (where its workers may be born; null is "none", the first entry
    is the default) and "dump" (its dump sink, or null).
    "used" is provisioned size, not bytes written. Check the headroom before a
    create (qubes_spawn, qubes_clone, a disposable) and stop creating when it
    falls below the next allocation. The cap and the quota are the operator's
    and cannot be changed from here. {"ok": false, "error": "pool cap not
    configured"} means the operator has removed the cap: create nothing new,
    and ask the operator.
    """, {})
def _qubes_get_pool_stats(args: dict) -> dict:
    return qrexec.call_qmcp("qmcp.GetPoolStats", timeout=DOM0_TIMEOUT)
