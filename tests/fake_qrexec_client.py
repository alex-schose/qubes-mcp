#!/usr/bin/env python3
"""Stand-in for /usr/lib/qubes/qrexec-client-vm in tests/test_server.py.

Called the way qubes_mcp.qrexec calls the real client:

    fake_qrexec_client.py <target> <service>

It reads the request from stdin, appends {"argv": [target, service], "stdin":
"<text>", ...} as one JSON line to the file named by QMCP_FAKE_LOG, and answers as
the JSON file named by QMCP_FAKE_CONFIG says (that file is optional):

    {"<service>" or "<target> <service>": <rule> or [<rule>, ...]}

A rule is a response plus an optional "match": {...}, a subset the JSON request
must contain; the first matching rule wins. A response may set:

    "json": <value>      printed as one JSON line; exit 0 if value["ok"] is true,
                         else 1, the way the dom0 services exit
    "raw": "<text>"      written as is, UTF-8 ("\\u0000" gives a NUL byte)
    "raw_hex": "<hex>"   arbitrary bytes
    "big": {"head": "<text>", "fill": "<text>", "size": <bytes>, "tail": "<text>"}
                         head, then fill repeated until `size` bytes of it are
                         written, then tail, streamed in chunks the way a qube
                         streams a command's output
    "stderr": "<text>"   written to stderr
    "stderr_size": <n>   n bytes written to stderr before anything on stdout
    "rc": <int>          exit status (overrides the default above)
    "sleep": <seconds>   wait this long before answering
    "linger": <seconds>  after the answer, close stdout and stay alive this long,
                         as a client whose exit lags its reply
    "reply_first": true  answer before reading the request, as a service that
                         writes before it has read its stdin; a rule with this
                         set must have no "match" (the request is not read yet)
    "unlocked": true     on a start: one dom0's qube lock does not cover (a
                         qrexec auto-start), so a kill meanwhile is not refused
                         as busy
    "sequence": [<response>, ...]
                         the Nth call matching this rule gets the Nth entry;
                         the last entry repeats

With no matching rule the answer is a plausible success (see _default).

Power states are modelled from the log the way dom0 and Qubes behave, so a
test of a teardown cannot pass against a fake that halts whatever is killed:

- A start that dom0 accepts makes the qube Running once it is done, `sleep`
  seconds after the call. Until then the qube is in Qubes' pre-start: it reads
  Halted, and a kill then returns success and changes nothing (measured on
  hardware). dom0's qube lock covers its own start, so a lifecycle call on that
  qube meanwhile is refused as busy, unless the start was "unlocked".
- A kill dom0 accepts outside a pre-start halts the qube; a kill on a qube that
  is already Halted fails "action failed", as qubesd's does.
- A qube no start or kill was logged for reads Running.
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import time

LIFE = "qmcp.LifecycleAIManaged"
BUSY = {"ok": False, "error": "busy: the qube is being changed; try again"}
_CHUNK = 65536


def _parse(text: str):
    try:
        return json.loads(text) if text.strip() else None
    except ValueError:
        return None


def _power(entries: list, name, now: float) -> tuple[str, dict | None]:
    """(power state, the start still in pre-start or None) of `name` at `now`."""
    state, starting, changes = "Running", None, []
    for entry in entries:
        payload = _parse(entry.get("stdin", ""))
        if (entry["argv"][1:2] != [LIFE] or not isinstance(payload, dict)
                or payload.get("name") != name or not entry.get("ok")):
            continue
        if payload.get("action") == "start":
            if entry["done"] > now:
                starting = entry
            else:
                changes.append((entry["done"], "Running"))
        elif payload.get("action") == "kill" and entry.get("effect"):
            changes.append((entry["done"], "Halted"))
    for _, value in sorted(changes, key=lambda change: change[0]):
        state = value
    return ("Halted" if starting is not None else state), starting


def _default(service: str, payload, entries: list, now: float) -> dict:
    if service == "admin.vm.firewall.Get":
        return {"raw": "0\x00action=accept\n"}
    if service.startswith("admin."):
        return {"raw": "0\x00"}
    name = payload.get("name") if isinstance(payload, dict) else None
    if service == "qmcp.GetPropertyAIManaged":
        prop = payload.get("property") if isinstance(payload, dict) else None
        value = _power(entries, name, now)[0] if prop == "power_state" else f"{prop}-value"
        return {"json": {"ok": True, "value": value}}
    if service == LIFE and isinstance(payload, dict) and payload.get("action") == "kill":
        state, starting = _power(entries, name, now)
        if starting is None and state == "Halted":
            return {"json": {"ok": False, "error": "action failed"}}
        return {"json": {"ok": True}}
    if service == "qmcp.SpawnDisposableAIManaged":
        return {"json": {"ok": True, "name": "disp1234"}}
    if service == "qmcp.RunInAIManaged":
        return {"json": {"ok": True, "rc": 0, "stdout": "out\n", "stderr": ""}}
    if service == "qmcp.ListAIManagedQubes":
        return {"json": {"ok": True, "qubes": []}}
    return {"json": {"ok": True}}


def _matches(rule: dict, payload) -> bool:
    wanted = rule.get("match")
    if not wanted:
        return True
    return isinstance(payload, dict) and all(
        key in payload and payload[key] == value for key, value in wanted.items())


def _load_rules(target: str, service: str) -> list:
    path = os.environ.get("QMCP_FAKE_CONFIG")
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        config = json.load(fh)
    rules = config.get(f"{target} {service}", config.get(service, []))
    return rules if isinstance(rules, list) else [rules]


def _decide(target: str, service: str, payload, rule, entries: list, now: float) -> dict:
    """The response to this call, given the calls before it."""
    if rule is not None and "sequence" in rule:
        # Count the earlier calls this same rule answered.
        seen = sum(1 for entry in entries
                   if entry["argv"] == [target, service]
                   and _matches(rule, _parse(entry["stdin"])))
        steps = rule["sequence"]
        return steps[min(seen, len(steps) - 1)]
    if rule is not None:
        return rule
    return _default(service, payload, entries, now)


def _emit(response: dict) -> int:
    time.sleep(response.get("sleep", 0))
    left = response.get("stderr_size", 0)
    while left > 0:
        piece = b"E" * min(left, _CHUNK)
        sys.stderr.buffer.write(piece)
        left -= len(piece)
    sys.stderr.buffer.flush()
    out = sys.stdout.buffer
    rc = 0
    if "json" in response:
        value = response["json"]
        out.write(json.dumps(value).encode("utf-8") + b"\n")
        rc = 0 if isinstance(value, dict) and value.get("ok") else 1
    elif "raw_hex" in response:
        out.write(bytes.fromhex(response["raw_hex"]))
    elif "raw" in response:
        out.write(response["raw"].encode("utf-8"))
    elif "big" in response:
        big = response["big"]
        out.write(big.get("head", "").encode("utf-8"))
        fill = big["fill"].encode("utf-8")
        chunk = fill * max(1, _CHUNK // len(fill))
        left = big["size"]
        while left > 0:
            piece = chunk[:left]
            out.write(piece)
            left -= len(piece)
        out.write(big.get("tail", "").encode("utf-8"))
    out.flush()
    if "stderr" in response:
        sys.stderr.write(response["stderr"])
        sys.stderr.flush()
    if response.get("linger"):
        os.close(sys.stdout.fileno())
        time.sleep(response["linger"])
    return response.get("rc", rc)


def _log(entry: dict) -> None:
    log_path = os.environ.get("QMCP_FAKE_LOG")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as log:
            fcntl.flock(log, fcntl.LOCK_EX)
            log.write(json.dumps(entry) + "\n")
            log.flush()
            fcntl.flock(log, fcntl.LOCK_UN)


def main() -> int:
    target, service = (sys.argv[1:3] + ["", ""])[:2]
    rules = _load_rules(target, service)

    early = next((r for r in rules if r.get("reply_first") and not r.get("match")), None)
    if early is not None:
        rc = _emit(early)
        text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        _log({"argv": sys.argv[1:], "stdin": text, "ok": None})
        return rc

    data = sys.stdin.buffer.read()
    text = data.decode("utf-8", errors="replace")
    payload = _parse(text)
    rule = next((r for r in rules if _matches(r, payload)), None)

    entry = {"argv": sys.argv[1:], "stdin": text}
    log_path = os.environ.get("QMCP_FAKE_LOG")
    if not log_path:
        response = _decide(target, service, payload, rule, [], time.time())
    else:
        with open(log_path, "a+", encoding="utf-8") as log:
            fcntl.flock(log, fcntl.LOCK_EX)
            log.seek(0)
            entries = [json.loads(line) for line in log]
            now = time.time()
            response = _decide(target, service, payload, rule, entries, now)
            action = payload.get("action") if isinstance(payload, dict) else None
            if service == LIFE and isinstance(payload, dict):
                _, starting = _power(entries, payload.get("name"), now)
                if starting is not None and not starting.get("unlocked"):
                    # dom0's qube lock: the start holds it until it is done, and
                    # any other lifecycle call on the qube is refused as busy.
                    response = {"json": BUSY}
                answer = response.get("json")
                entry["ok"] = isinstance(answer, dict) and answer.get("ok") is True
                # The state changes once dom0 has done the call, not when it was made:
                # a client that gives up waiting does not stop dom0.
                entry["done"] = now + response.get("sleep", 0)
                entry["unlocked"] = bool(response.get("unlocked"))
                # A kill during pre-start returns success and changes nothing.
                entry["effect"] = action == "kill" and entry["ok"] and starting is None
            log.write(json.dumps(entry) + "\n")
            log.flush()
            fcntl.flock(log, fcntl.LOCK_UN)
    return _emit(response)


if __name__ == "__main__":
    sys.exit(main())
