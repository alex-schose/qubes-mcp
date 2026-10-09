"""qmcp.gateways — the gateway registry: the only networks AI space may use.

The operator enrolls the gateways AI qubes may sit on (`qmcp gateway enroll`),
normally plain routers of their own, one per kind (clearnet, Tor, proxy, VPN),
each in front of the qube that kind uses for the operator's own work. An entry
holds whether the gateway is anonymising, and a label (a jurisdiction, say).

AI space uses a network only if it is enrolled: as a project's worker network,
as a lead's network, and as the birth network of the hub's own creates. A
gateway is normally outside AI space; one kept inside it must be guarded.
Whether a name is enrolled is decided from this file alone, before any qube is
looked up, so asking is no oracle over the names of qubes outside AI space.

A qube's own firewall rules are carried out by the qube directly above it, so
an enrolled gateway must carry them out: enrolling requires Qubes' own marker
for that, the `qubes-firewall` feature (the qube's own value, else its
template's). The marker is
not proof. A qube that hands its clients' traffic to a local program skips
their rules: measured on Qubes 4.3.1, `sys-whonix` (Whonix 18) carries the
marker and applies none of its clients' rules, because Whonix sends their TCP
and DNS to Tor inside the gateway. So the registry is meant for plain routers,
and a gateway whose own upstream is a Whonix gateway is marked: its own rules
have no effect there.

An anonymising gateway also records its own network when it is enrolled (and
again whenever the operator marks it anonymising): `upstream`. The anonymity
gate (`qmcp.anon`) is red for every anonymous project on it while its network
differs, so a Tor router re-pointed at clearnet is caught, and a template's
updates count as anonymous only when they go to one of these recorded
upstreams, never a qube further up the chain. The key is optional, as the
project records' newer keys are, so a registry written before 0.9.23 still
reads; an anonymising entry without it carries no anonymous project until it
is marked again.

Whether that upstream carries updates anonymously is the operator's word too
(`updates`, from 0.9.24): the qube above a plain router in front of
`sys-whonix` or a VPN qube is the anonymiser itself, but the qube above a VPN
qube enrolled with no router in front is `sys-firewall`, which dom0 cannot tell
apart from the first case. So a template's updates count only when they go to
the recorded upstream of an anonymising gateway the operator ticked. Absent
means unticked, so an entry written before 0.9.24 counts for no template's
updates until it is ticked.

The file is root-owned, written by `qmcp gateway` under the project records'
lock, by atomic rename; the services only read it. A file that exists but
cannot be read or validated means that no gateway is enrolled, so every create
that needs a network is refused. An absent file means none is enrolled yet,
which is how an install starts.
"""
from __future__ import annotations

import json
import os
import re
import tempfile

GATEWAYS_PATH = "/etc/qmcp/gateways.json"
VERSION = 1
MAX_GATEWAYS = 32
MAX_LABEL = 40

#: Whonix's own tag on its gateway: a qube behind one has its firewall rules ignored.
WHONIX_GATEWAY_TAG = "anon-gateway"
#: The feature a template advertises when it runs Qubes' firewall for its clients.
FIREWALL_FEATURE = "qubes-firewall"

_QUBE_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9_.-]{0,30}\Z")
_LABEL_RE = re.compile(r"\A[\x20-\x7e]{0,%d}\Z" % MAX_LABEL)


class GatewaysUnreadable(Exception):
    """The registry exists but cannot be read or does not validate."""


class Gateway:
    __slots__ = ("name", "anonymising", "label", "upstream", "updates")

    def __init__(self, name: str, anonymising: bool = False, label: str = "",
                 upstream: str | None = None, updates: bool = False) -> None:
        self.name, self.anonymising, self.label = name, anonymising, label
        #: The network an anonymising gateway sat on when the operator marked it.
        self.upstream = upstream if anonymising else None
        #: The operator's word that templates' updates may go to that network.
        self.updates = bool(updates) and self.upstream is not None

    def to_json(self) -> dict:
        out = {"anonymising": self.anonymising, "label": self.label}
        if self.upstream is not None:
            out["upstream"] = self.upstream
        if self.updates:
            out["updates"] = True
        return out

    def __repr__(self):
        return f"<Gateway {self.name}{' anonymising' if self.anonymising else ''}>"


def valid_name(name) -> bool:
    return isinstance(name, str) and _QUBE_RE.match(name) is not None


def label_refusal(label) -> str | None:
    if not isinstance(label, str) or not _LABEL_RE.match(label):
        return f"a gateway's label is up to {MAX_LABEL} printable ASCII characters"
    return None


def parse(text: str) -> dict:
    """name -> Gateway, from the file's text. Raises GatewaysUnreadable."""
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        raise GatewaysUnreadable("not JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != VERSION or set(doc) != {"version", "gateways"}:
        raise GatewaysUnreadable(f"top level must be {{'version': {VERSION}, 'gateways': {{...}}}}")
    entries = doc["gateways"]
    if not isinstance(entries, dict) or len(entries) > MAX_GATEWAYS:
        raise GatewaysUnreadable(f"gateways must map at most {MAX_GATEWAYS} qube names to entries")
    out = {}
    for name, entry in entries.items():
        if not valid_name(name):
            raise GatewaysUnreadable("a gateway's name is not a qube name")
        if not isinstance(entry, dict) or not {"anonymising", "label"} <= set(entry) \
                <= {"anonymising", "label", "upstream", "updates"}:
            raise GatewaysUnreadable(f"{name}: keys must be 'anonymising' and 'label', and "
                                     f"optionally 'upstream' and 'updates'")
        if not isinstance(entry["anonymising"], bool) or label_refusal(entry["label"]):
            raise GatewaysUnreadable(f"{name}: bad anonymising flag or label")
        upstream = entry.get("upstream")
        if upstream is not None and not (entry["anonymising"] and valid_name(upstream)):
            raise GatewaysUnreadable(f"{name}: upstream is a qube name, on an anonymising gateway")
        updates = entry.get("updates", False)
        if updates is not False and not (updates is True and upstream is not None):
            raise GatewaysUnreadable(f"{name}: updates is true, on an anonymising gateway with a "
                                     f"recorded upstream")
        out[name] = Gateway(name, entry["anonymising"], entry["label"], upstream, updates)
    return out


def load(path: str | None = None) -> dict:
    """name -> Gateway. Absent file: none enrolled. Present but bad: raises."""
    path = GATEWAYS_PATH if path is None else path
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(256 * 1024 + 1)
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as e:
        raise GatewaysUnreadable(f"cannot read ({type(e).__name__})") from None
    if len(text) > 256 * 1024:
        raise GatewaysUnreadable("file too large")
    return parse(text)


def enrolled_names(path: str | None = None) -> frozenset:
    """The enrolled gateways' names; none at all when the file cannot be read,
    so every check that needs one refuses (fail closed)."""
    try:
        return frozenset(load(path))
    except GatewaysUnreadable:
        return frozenset()


def is_enrolled(name, path: str | None = None) -> bool:
    return valid_name(name) and name in enrolled_names(path)


def dump_json(gateways: dict) -> str:
    return json.dumps({"version": VERSION,
                       "gateways": {n: g.to_json() for n, g in sorted(gateways.items())}},
                      indent=2, sort_keys=True) + "\n"


def save(gateways: dict, path: str | None = None) -> None:
    """Validate, then replace the file atomically (same directory, fsync, rename).
    The caller holds the project records' lock (`projects.Locked`)."""
    path = GATEWAYS_PATH if path is None else path
    text = dump_json(gateways)
    parse(text)
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".gateways.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
