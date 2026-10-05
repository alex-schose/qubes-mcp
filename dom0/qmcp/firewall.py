"""qmcp.firewall — a lead's firewall: its model endpoint, and the rules dom0 writes.

A lead's firewall is the operator's. dom0 writes it when the lead is created,
from the lead's model endpoint ("model endpoint only": the endpoint, DNS, and
nothing else), and again only when the operator changes it, directly or by
accepting the hub's proposal; the rulebook denies the hub any write to a
lead's firewall, and a lead cannot write its own. The rules the operator
accepted are kept in the project's record, and `qmcp check` fails when the
lead's live rules differ from them while the lead has a network.

Rules travel in qubesd's own line format (`admin.vm.firewall.Get`/`Set`),
which qubesd states back in its own spelling (measured on Qubes 4.3.1):
`action=accept dsthost=api.example.com proto=tcp dstports=443-443`. Before
qmcp sends a rule list, each line is checked against the subset of that format
qmcp writes, and qubesd validates it again when it is set; the one exception
is an undo, which puts back qubesd's own lines as they were. What is stored as
accepted is what qubesd reads back after the write, so the comparison is never
between two spellings of one rule.

DNS stays open for every lead with a model endpoint, one given as an address
included: "model endpoint only" is the endpoint, DNS and nothing else. A lead
that may ask DNS questions can hide data in them; that is an accepted residual
(a hijacked lead can send data out through any networked worker anyway).
"""
from __future__ import annotations

import ipaddress
import re

MAX_RULES = 32
MAX_RULE_LEN = 256
#: The keys qmcp writes or accepts in a rule. qubesd knows more (`expire`,
#: `comment`); qmcp never needs them, and a comment may hold spaces.
RULE_KEYS = frozenset({"action", "proto", "dsthost", "dst4", "dst6", "dstname",
                       "dstports", "specialtarget", "icmptype"})
_VALUE_RE = re.compile(r"\A[\x21-\x7e]{1,253}\Z")
_HOST_RE = re.compile(r"\A(?=.{1,253}\Z)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                      r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\Z")
_PORT_RE = re.compile(r"\A[0-9]{1,5}\Z")
_IPV4_RE = re.compile(r"\A[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?\Z")


class FirewallError(Exception):
    pass


def parse_model(text) -> tuple:
    """(host, port) from `host:port`: a host name or an IPv4 address, and a port
    1-65535. Raises FirewallError."""
    if not isinstance(text, str) or text.count(":") != 1:
        raise FirewallError("a model endpoint is host:port, e.g. api.anthropic.com:443")
    host, port = text.split(":")
    if not _HOST_RE.match(host) or not _PORT_RE.match(port) or not 1 <= int(port) <= 65535:
        raise FirewallError("a model endpoint is host:port: a host name or IPv4 address, "
                            "and a port from 1 to 65535")
    return host.lower(), int(port)


def model_text(text) -> str:
    """The canonical `host:port` for a model endpoint. Raises FirewallError."""
    host, port = parse_model(text)
    return f"{host}:{port}"


def endpoint_rules(model: str) -> list:
    """"Model endpoint only": the endpoint over TCP, DNS so the lead can find
    it, and nothing else."""
    host, port = parse_model(model)
    return [f"action=accept proto=tcp dsthost={host} dstports={port}",
            "action=accept specialtarget=dns",
            "action=drop"]


def rule_refusal(rule) -> str | None:
    """None if `rule` is a line qmcp may send, else why not."""
    if not isinstance(rule, str) or not 0 < len(rule) <= MAX_RULE_LEN:
        return f"a firewall rule is 1-{MAX_RULE_LEN} characters"
    keys = []
    for option in rule.split(" "):
        key, eq, value = option.partition("=")
        if not eq or key not in RULE_KEYS or not _VALUE_RE.match(value):
            return f"a firewall rule is key=value options from {sorted(RULE_KEYS)}, one space apart"
        keys.append(key)
    if len(set(keys)) != len(keys) or keys.count("action") != 1:
        return "a firewall rule names each option once and has exactly one action"
    if dict(o.split("=", 1) for o in rule.split(" "))["action"] not in ("accept", "drop"):
        return "a firewall rule's action is accept or drop"
    return None


def rules_refusal(rules) -> str | None:
    if not isinstance(rules, (list, tuple)) or not 1 <= len(rules) <= MAX_RULES:
        return f"a firewall is 1-{MAX_RULES} rules"
    for rule in rules:
        err = rule_refusal(rule)
        if err:
            return err
    return None


def _canonical(rule: str) -> dict:
    """A rule as qubesd states it back: options in any order (measured on
    Qubes 4.3.1: action, destination, proto, ports), ports as a range of plain
    numbers (`443` reads back `443-443`), an address as `dst4` or `dst6` with
    its prefix length (`dsthost=1.2.3.4` reads back `dst4=1.2.3.4/32`). An
    IPv6 address is compressed on both sides here, so either spelling of it
    compares equal."""
    out = {}
    for option in rule.split(" "):
        key, _, value = option.partition("=")
        if key == "dstports":
            lo, _, hi = value.partition("-")
            if lo.isdigit() and (hi.isdigit() or not hi):
                value = f"{int(lo)}-{int(hi or lo)}"
        elif key in ("dsthost", "dstname", "dst4", "dst6"):
            addr, slash, plen = value.partition("/")
            if _IPV4_RE.match(addr):
                key, value = "dst4", f"{addr}/{plen or 32}"
            elif ":" in addr:
                try:
                    key, value = "dst6", f"{ipaddress.IPv6Address(addr).compressed}/{plen or 128}"
                except ValueError:
                    pass
            elif key == "dstname":
                key = "dsthost"
        out[key] = value
    return out


def same_rules(written, read_back) -> bool:
    """Did qubesd store what was written? Compared rule by rule, in order,
    allowing only for qubesd's own spelling. Anything else, a rule written
    by someone else in between included, is not the same."""
    return len(written) == len(read_back) and all(
        _canonical(a) == _canonical(b) for a, b in zip(written, read_back))


def read_rules(app, name) -> list:
    """The qube's rules, one line each, as qubesd states them. Raises when they
    cannot be read: an unreadable firewall is never shown as an empty one."""
    raw = app.qubesd_call(name, "admin.vm.firewall.Get")
    return [line for line in raw.decode("ascii", errors="strict").splitlines() if line.strip()]


def write_rules(app, name, rules) -> list:
    """Set the qube's rules, then read them back: what qubesd stored, in its
    own spelling, which is what the record keeps as accepted."""
    err = rules_refusal(rules)
    if err:
        raise FirewallError(err)
    app.qubesd_call(name, "admin.vm.firewall.Set", None,
                    "".join(f"{r}\n" for r in rules).encode("ascii"))
    stored = read_rules(app, name)
    if not same_rules(rules, stored):
        raise FirewallError("the firewall did not read back as set")
    return stored


def restore_rules(app, name, lines) -> None:
    """Put back rules exactly as qubesd stated them (undoing a promotion, or a
    write that did not read back as set). They
    are qubesd's own lines, so they skip qmcp's narrower subset: a rule with a
    comment the operator wrote goes back as it was."""
    app.qubesd_call(name, "admin.vm.firewall.Set", None,
                    "".join(f"{r}\n" for r in lines).encode("ascii"))
    if read_rules(app, name) != list(lines):
        raise FirewallError("the firewall did not read back as restored")
