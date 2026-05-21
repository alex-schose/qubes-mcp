from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_service


@ring_tool(Ring.EXEC)
def qubes_install_pkg(name: str, packages: list[str], update_first: bool = True) -> dict:
    """Install Debian packages in an ai-managed (Debian-based) qube.

    Convenience wrapper over qmcp.RunInAIManaged with DEBIAN_FRONTEND=noninteractive
    set so apt won't hang on prompts. Usually called against an ai-managed
    template so installs persist for future AppVMs.

    Returns the install step's stdout/stderr/rc, plus the update step if it failed.
    """
    if update_first:
        upd = call_service(
            name,
            "qmcp.RunInAIManaged",
            {"cmd": ["apt-get", "update"], "timeout": 180},
            timeout=210,
        )
        if not upd.get("ok") or upd.get("rc") != 0:
            return {"ok": False, "step": "update", "details": upd}

    inst = call_service(
        name,
        "qmcp.RunInAIManaged",
        {
            "cmd": ["env", "DEBIAN_FRONTEND=noninteractive",
                    "apt-get", "install", "-y", *packages],
            "timeout": 600,
        },
        timeout=630,
    )
    return {
        "ok": bool(inst.get("ok")) and inst.get("rc") == 0,
        "rc": inst.get("rc"),
        "stdout": inst.get("stdout", ""),
        "stderr": inst.get("stderr", ""),
        "error": inst.get("error"),
    }
