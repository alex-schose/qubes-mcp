#!/usr/bin/env python3
"""Stand-in for /usr/lib/qubes/qrexec-client-vm in tests/test_server.py.

Called the way qubes_mcp.qrexec calls the real client:

    fake_qrexec_client.py <target> <service>

It reads the request from stdin, appends {"argv": [target, service], "stdin":
"<text>"} as one JSON line to the file named by QMCP_FAKE_LOG, and answers as
the JSON file named by QMCP_FAKE_CONFIG says (that file is optional):

    {"<service>" or "<target> <service>": <rule> or [<rule>, ...]}

A rule is a response plus an optional "match": {...}, a subset the JSON request
must contain; the first matching rule wins. A response may set:

    "json": <value>      printed as one JSON line; exit 0 if value["ok"] is true,
                         else 1, the way the dom0 services exit
    "raw": "<text>"      written as is, UTF-8 ("\\u0000" gives a NUL byte)
    "raw_hex": "<hex>"   arbitrary bytes
    "stderr": "<text>"   written to stderr
    "rc": <int>          exit status (overrides the default above)
    "sleep": <seconds>   wait this long before answering
    "sequence": [<response>, ...]
                         the Nth call matching this rule gets the Nth entry;
                         the last entry repeats

With no matching rule the answer is a plausible success (see _default).
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import time


def _default(service: str, payload) -> dict:
    if service == "admin.vm.firewall.Get":
        return {"raw": "0\x00action=accept\n"}
    if service.startswith("admin."):
        return {"raw": "0\x00"}
    if service == "qmcp.GetPropertyAIManaged":
        prop = payload.get("property") if isinstance(payload, dict) else None
        value = "Running" if prop == "power_state" else f"{prop}-value"
        return {"json": {"ok": True, "value": value}}
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


def _parse(text: str):
    try:
        return json.loads(text) if text.strip() else None
    except ValueError:
        return None


def main() -> int:
    target, service = (sys.argv[1:3] + ["", ""])[:2]
    data = sys.stdin.buffer.read()
    text = data.decode("utf-8", errors="replace")
    payload = _parse(text)

    rule = next((r for r in _load_rules(target, service) if _matches(r, payload)), None)
    response = rule if rule is not None else _default(service, payload)

    log_path = os.environ.get("QMCP_FAKE_LOG")
    if log_path:
        with open(log_path, "a+", encoding="utf-8") as log:
            fcntl.flock(log, fcntl.LOCK_EX)
            if rule is not None and "sequence" in rule:
                # Count the earlier calls this same rule answered.
                log.seek(0)
                seen = 0
                for line in log:
                    entry = json.loads(line)
                    if (entry["argv"] == [target, service]
                            and _matches(rule, _parse(entry["stdin"]))):
                        seen += 1
                steps = rule["sequence"]
                response = steps[min(seen, len(steps) - 1)]
            log.write(json.dumps({"argv": sys.argv[1:], "stdin": text}) + "\n")
            log.flush()
            fcntl.flock(log, fcntl.LOCK_UN)

    time.sleep(response.get("sleep", 0))
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
    out.flush()
    if "stderr" in response:
        sys.stderr.write(response["stderr"])
        sys.stderr.flush()
    return response.get("rc", rc)


if __name__ == "__main__":
    sys.exit(main())
