"""qubes-mcp command line: call one tool directly, without an MCP client.

It uses the same registry and argument validator as the MCP server, so a call
that works here works there, and the other way round.
"""
from __future__ import annotations

import json
import logging
import sys

from qubes_mcp import tools

log = logging.getLogger(__name__)

USAGE = """\
usage: qubes-mcp list-tools
       qubes-mcp <tool> [key=value ...]
       qubes-mcp <tool> --json '<object>'
       qubes-mcp <tool> --help

Calls one qubes-mcp tool directly, with the same argument checks as the MCP
server, and prints the result as JSON.

Each value is parsed as JSON when it parses, and taken as a string otherwise:
  timeout=30 -> 30          force=true -> true          netvm=null -> null
  'cmd=["ls", "-l"]' -> a list                          name=ai-work -> "ai-work"
To pass the word true, false or null as a string, quote it: name='"null"'.

Exit status: 0 the result is ok (or has no "ok" field); 1 the result is a
refusal ("ok": false), or an internal error; 2 a usage error or invalid
arguments.
"""

EXIT_OK, EXIT_REFUSED, EXIT_USAGE = 0, 1, 2


class _UsageError(Exception):
    pass


def _write_out(text: str) -> None:
    # UTF-8 whatever the locale says, so a result can always be printed.
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.flush()


def _usage_error(message: str) -> int:
    sys.stderr.write(f"qubes-mcp: {message}\n")
    return EXIT_USAGE


def _parse_value(text: str):
    try:
        return tools.parse_json(text)
    except (ValueError, RecursionError):
        return text


def _parse_arguments(rest: list[str]) -> dict:
    if "--json" in rest:
        if len(rest) != 2 or rest[0] != "--json":
            raise _UsageError("--json takes one argument and cannot be mixed with key=value")
        try:
            arguments = tools.parse_json(rest[1])
        except (ValueError, RecursionError) as exc:
            raise _UsageError(f"--json: not valid JSON ({exc})") from None
        if not isinstance(arguments, dict):
            raise _UsageError("--json: expected a JSON object")
        return arguments
    arguments: dict = {}
    for item in rest:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise _UsageError(f"expected key=value, got {item!r}")
        if key in arguments:
            raise _UsageError(f"{key} is given twice")
        arguments[key] = _parse_value(value)
    return arguments


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else ""


def _list_tools() -> str:
    width = max(len(name) for name in tools.TOOLS) + 2
    return "".join(f"{name:<{width}}{_first_line(tool.description)}\n"
                   for name, tool in tools.TOOLS.items())


def _tool_help(tool: tools.Tool) -> str:
    schema = tool.input_schema
    required = set(schema.get("required", ()))
    lines = [tool.description, "", "Arguments:" if schema["properties"] else "Arguments: none"]
    for key, prop in schema["properties"].items():
        kind = prop.get("type", "any")
        kind = " or ".join(kind) if isinstance(kind, list) else kind
        notes = [kind]
        if key in required:
            notes.append("required")
        if "default" in prop:
            notes.append(f"default {json.dumps(prop['default'])}")
        if "enum" in prop:
            notes.append("one of " + ", ".join(json.dumps(e) for e in prop["enum"]))
        lines.append(f"  {key} ({'; '.join(notes)})")
        if prop.get("description"):
            lines.append(f"      {prop['description']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                        format="qubes-mcp: %(levelname)s: %(message)s")
    if not args:
        sys.stderr.write(USAGE)
        return EXIT_USAGE
    command, rest = args[0], args[1:]
    if command in ("-h", "--help", "help"):
        _write_out(USAGE)
        return EXIT_OK
    if command == "list-tools":
        if rest:
            return _usage_error("list-tools takes no arguments")
        _write_out(_list_tools())
        return EXIT_OK

    try:
        tool = tools.get_tool(command)
    except tools.UnknownTool:
        return _usage_error(f"unknown tool {command!r} (see: qubes-mcp list-tools)")
    if rest in (["-h"], ["--help"]):
        _write_out(_tool_help(tool))
        return EXIT_OK
    try:
        validated = tools.validate_arguments(tool, _parse_arguments(rest))
    except (_UsageError, tools.ArgumentError) as exc:
        return _usage_error(f"{tool.name}: {exc}")

    try:
        result = tool.handler(validated)
        if not isinstance(result, dict):
            raise TypeError(f"{tool.name} returned {type(result).__name__}, not a dict")
        text = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False)
    except Exception:
        log.exception("%s raised", tool.name)
        sys.stderr.write("qubes-mcp: internal error\n")
        return EXIT_REFUSED
    _write_out(text + "\n")
    # Fail closed: anything but a literal true in a present "ok" is a refusal.
    return EXIT_OK if result.get("ok", True) is True else EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
