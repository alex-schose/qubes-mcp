from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_service


@ring_tool(Ring.EXEC)
def qubes_copy(source: str, target: str, path: str, timeout: int = 300) -> dict:
    """Copy a file or directory from one ai-managed qube to another.

    Both qubes must be ai-managed and running. Uses qubes.Filecopy under
    the hood; the file lands on the target at:
        /home/user/QubesIncoming/<source>/<basename(path)>

    Args:
      source:  ai-managed qube holding the file
      target:  ai-managed qube to copy into
      path:    absolute path on the source qube
      timeout: total transfer timeout in seconds
    """
    return call_service(
        source,
        "qmcp.CopyToAIManaged",
        {"target": target, "path": path},
        timeout=timeout + 30,
    )
