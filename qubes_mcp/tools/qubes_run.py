from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_service


@ring_tool(Ring.EXEC)
def qubes_run(
    name: str,
    cmd: list[str] | str,
    shell: bool = False,
    timeout: int = 60,
    stdin: str = "",
) -> dict:
    """Execute a command inside an ai-managed qube as root.

    The qube must be running and based on an ai-managed template (which
    carries the qmcp.RunInAIManaged service). Returns:
      {"ok": true,  "rc": <int>, "stdout": "...", "stderr": "..."}
      {"ok": false, "error": "<reason>"}

    Args:
      name:    target ai-managed qube
      cmd:     list of strings (argv form, default) or single string when shell=True
      shell:   run via /bin/sh -c (default False — argv form is safer)
      timeout: command timeout in seconds inside the qube
      stdin:   text to feed the command's stdin
    """
    return call_service(
        name,
        "qmcp.RunInAIManaged",
        {"cmd": cmd, "shell": shell, "timeout": timeout, "stdin": stdin},
        timeout=timeout + 30,
    )
