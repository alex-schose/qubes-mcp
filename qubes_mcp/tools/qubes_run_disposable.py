from __future__ import annotations

import time

from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import call_qmcp, call_service


_RUNNING_STATES = ("Running", "Transient")
_START_POLL_INTERVAL_SECONDS = 2.0
_START_POLL_ATTEMPTS = 15        # up to ~30s for the disposable to reach Running


@ring_tool(Ring.LIFECYCLE)
def qubes_run_disposable(
    template: str,
    cmd: list[str] | str,
    shell: bool = False,
    timeout: int = 60,
    stdin: str = "",
) -> dict:
    """Spin up an ephemeral DispVM, run a command, shut it down.

    One-shot composition: spawn (via qmcp.SpawnDisposableAIManaged) →
    start (via qmcp.LifecycleAIManaged) → poll for Running → execute
    inside via qmcp.RunInAIManaged → shutdown. Because the disposable
    has auto_cleanup=True, dom0 removes it after shutdown. No new dom0
    surface — pure MCP-side composition of existing Stage B/D/E2
    wrappers.

    Args:
      template: ai-managed DispVMTemplate (template_for_dispvms=True).
      cmd:      list-of-strings (argv form, default) or single string when shell=True.
      shell:    run via /bin/sh -c inside the disposable.
      timeout:  command timeout in seconds inside the disposable.
      stdin:    text fed to the command's stdin.

    Returns (on full success):
      {"ok": true, "name": "disp1234", "rc": <int>,
       "stdout": "...", "stderr": "..."}

    Returns (on any failure — `name` is included whenever the spawn
    succeeded, so the operator can locate any straggler in dom0 if
    auto_cleanup somehow misfires):
      {"ok": false, "name": "...", "stage": "spawn|start|wait|run|shutdown",
       "error": "<reason>"}
      {"ok": false, "stage": "spawn", "error": "..."}   -- no name yet
    """
    spawn_r = call_qmcp("qmcp.SpawnDisposableAIManaged", {"template": template})
    if not spawn_r.get("ok"):
        return {"ok": False, "stage": "spawn", "error": spawn_r.get("error")}
    name = spawn_r["name"]

    start_r = call_qmcp("qmcp.LifecycleAIManaged",
                        {"name": name, "action": "start"})
    if not start_r.get("ok"):
        _best_effort_teardown(name)
        return {"ok": False, "name": name, "stage": "start",
                "error": start_r.get("error")}

    if not _wait_running(name):
        _best_effort_teardown(name)
        return {"ok": False, "name": name, "stage": "wait",
                "error": "disposable did not reach Running state in time"}

    run_r = call_service(name, "qmcp.RunInAIManaged",
                         {"cmd": cmd, "shell": shell,
                          "timeout": timeout, "stdin": stdin},
                         timeout=timeout + 30)

    shutdown_r = call_qmcp("qmcp.LifecycleAIManaged",
                           {"name": name, "action": "shutdown"})

    if not run_r.get("ok"):
        # run failed but we still tried to shut down cleanly above. If
        # shutdown also failed, kill as a fallback to ensure auto_cleanup
        # fires (an orphaned disposable would otherwise persist until the
        # next dom0 reboot).
        if not shutdown_r.get("ok"):
            _best_effort_teardown(name)
        return {"ok": False, "name": name, "stage": "run",
                "error": run_r.get("error")}

    if not shutdown_r.get("ok"):
        # Command succeeded but the qube refuses to shut down — kill it
        # so auto_cleanup removes it; surface the kill outcome.
        _best_effort_teardown(name)
        return {"ok": False, "name": name, "stage": "shutdown",
                "error": shutdown_r.get("error"),
                "rc": run_r.get("rc"),
                "stdout": run_r.get("stdout"),
                "stderr": run_r.get("stderr")}

    return {"ok": True, "name": name,
            "rc": run_r.get("rc"),
            "stdout": run_r.get("stdout", ""),
            "stderr": run_r.get("stderr", "")}


def _wait_running(name: str) -> bool:
    for _ in range(_START_POLL_ATTEMPTS):
        s = call_qmcp("qmcp.GetPropertyAIManaged",
                      {"name": name, "property": "power_state"})
        if s.get("value") in _RUNNING_STATES:
            return True
        time.sleep(_START_POLL_INTERVAL_SECONDS)
    return False


def _best_effort_teardown(name: str) -> None:
    """Kill the disposable so auto_cleanup removes it. Ignore errors —
    this is a best-effort safety net during failure paths."""
    call_qmcp("qmcp.LifecycleAIManaged", {"name": name, "action": "kill"})
