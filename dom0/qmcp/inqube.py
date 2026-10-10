"""qmcp.inqube — qmcp's two in-qube services, kept in dom0 and written into
the qubes that carry a root of their own.

The hub's and a lead's exec and copy-out run INSIDE the target qube, through
the two scripts of `template-rpc/` installed under `/etc/qubes-rpc/`. An AppVM
takes its root from its template at every boot, so for an AppVM they live in
the template. A StandaloneVM copied a root once, when it was made, and never
reads a template again, so it carries its own. The installer keeps the two
files in `SERVICES_DIR`, so a qube can be prepared at any time, not only while
a fetched release is still unpacked.

- `prepare(app, name)`, the operator's `qmcp template prepare`, writes them
  into a TemplateVM or a StandaloneVM as root. It starts a halted qube for that
  and shuts it down again afterwards. Then it labels the qube with the feature
  `qmcp-services`, set to their version.
- `refresh(app)`, `qmcp template refresh` on its own timer, writes them into
  every RUNNING qube whose label exists and is not the installed version. It
  never starts a qube, and it skips one never prepared (no label) and one the
  gate stopped or the restore check holds.
- `label_state(vm)` answers what `qmcp check` reports.

The label records what dom0 wrote, never what the qube's disk holds now: a
check that read the disk would have to start the qube. Neither the hub nor a
lead can write it: their feature allowlist holds only `menu-items`,
`default-menu-items`, `service.*` and `vm-config.*`, and no rule gives the hub
or AI space an `admin.vm.feature` method. dom0 reads nothing back but the exit status. The qube may be
hostile, so its output is discarded and every write has a timeout.
"""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess

from qmcp import core, projects

SERVICES_DIR = "/usr/local/lib/qmcp/template-rpc"
SERVICE_NAMES = ("qmcp.CopyToAIManaged", "qmcp.RunInAIManaged")
LABEL = "qmcp-services"
#: The classes with a root of their own, which a prepare writes into.
OWN_ROOT = frozenset({"TemplateVM", "StandaloneVM"})
#: Seconds one write may take. Two files of a few kilobytes take well under one.
TIMEOUT_S = 30
#: A qube in any of these is not written into by the refresh. The gate stopped
#: one, and the restore check holds one for the operator's review.
SKIP_BADGES = frozenset({projects.BLOCKED, projects.STOPPED, core.QUARANTINE})


class InQubeError(Exception):
    """A prepare or a refresh that did not happen; the message names why, in
    fixed words, never the qube's own output."""


def read_services(directory: str | None = None) -> dict:
    """{name: bytes} of the two services dom0 keeps. Raises InQubeError when
    either is missing or empty: an install that lost them is reported, never
    worked around."""
    directory = SERVICES_DIR if directory is None else directory
    out = {}
    for name in SERVICE_NAMES:
        try:
            with open(os.path.join(directory, name), "rb") as fh:
                data = fh.read(256 * 1024)
        except OSError:
            raise InQubeError(f"{directory}/{name} cannot be read: reinstall qmcp") from None
        if not data:
            raise InQubeError(f"{directory}/{name} is empty: reinstall qmcp")
        out[name] = data
    return out


def version(files: dict) -> str:
    """The version of a set of services: one digest over names and contents."""
    h = hashlib.sha256()
    for name in sorted(files):
        data = files[name]
        h.update(name.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
    return "sha256:" + h.hexdigest()


def installed_version(directory: str | None = None) -> str:
    return version(read_services(directory))


def script(files: dict) -> bytes:
    """The shell script `qubes.VMShell` runs as root to write the services.
    Each file goes to a temporary name first and is renamed into place, so a
    qube never holds half a service. The `# qmcp file NAME` line before each
    block is what the offline fake reads back."""
    lines = ["set -e", "umask 022", "d=/etc/qubes-rpc", "mkdir -p \"$d\"",
             "t=", "trap 'rm -f \"$t\"' EXIT"]
    for name in sorted(files):
        payload = base64.encodebytes(files[name]).decode("ascii").rstrip("\n")
        lines += [f"# qmcp file {name}",
                  't=$(mktemp "$d/.qmcp.XXXXXX")',
                  "base64 -d > \"$t\" <<'QMCP_B64_END'", payload, "QMCP_B64_END",
                  'chmod 0755 "$t"', f'mv -f "$t" "$d/{name}"', "t="]
    lines.append("exit 0")
    return ("\n".join(lines) + "\n").encode("ascii")


def _push(vm, files: dict, timeout: float) -> None:
    """Write the services into a RUNNING qube. Raises InQubeError."""
    try:
        proc = vm.run_service("qubes.VMShell", user="root", autostart=False,
                              stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except Exception as e:
        raise InQubeError(f"could not reach it ({type(e).__name__})") from None
    try:
        proc.communicate(script(files), timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.communicate(timeout=5)
        except Exception:
            pass
        raise InQubeError(f"the write did not finish in {int(timeout)} s") from None
    except Exception as e:
        raise InQubeError(f"the write failed ({type(e).__name__})") from None
    if proc.returncode != 0:
        raise InQubeError(f"the write exited {proc.returncode}")


def label_of(vm):
    """The `qmcp-services` label, or None when the qube has none. Raises
    core.Unreadable when the feature cannot be read: a failed read is never
    "not prepared"."""
    try:
        value = vm.features.get(LABEL, None)
    except Exception as e:
        raise core.Unreadable(f"cannot read the {LABEL} feature of {core.name_of(vm)}") from e
    return None if value is None else str(value)


def label_state(vm, current: str) -> str:
    """"current", "behind" (prepared for another version) or "missing"."""
    label = label_of(vm)
    if label is None:
        return "missing"
    return "current" if label == current else "behind"


def prepare(app, name: str, timeout: float = TIMEOUT_S) -> dict:
    """Write the services into the TemplateVM or StandaloneVM `name` and label
    it. Returns {"qube", "version", "started"}. Raises InQubeError or
    core.Unreadable; on either, the label is untouched."""
    vm = core.lookup(app, name)
    if vm is None or core.klass_of(vm) == "AdminVM":
        raise InQubeError(f"no qube '{name}'")
    klass = core.klass_of(vm)
    if klass not in OWN_ROOT:
        raise InQubeError(f"'{name}' is a {klass}, which takes its root from its template: "
                          f"prepare the template instead")
    tags = core.tags_of(vm)
    if tags & {projects.BLOCKED, projects.STOPPED}:
        raise InQubeError(f"'{name}' was stopped by the anonymity gate, and preparing it "
                          f"would start it: clear it first (qmcp project unblock)")
    if core.QUARANTINE in tags:
        raise InQubeError(f"'{name}' is held for your review: accept or reject it first "
                          f"(qmcp restored)")
    files = read_services()
    current = version(files)
    power = vm.get_power_state()
    started = False
    if power == "Halted":
        try:
            vm.start()
        except Exception as e:
            raise InQubeError(f"'{name}' did not start ({type(e).__name__})") from None
        started = True
    elif power != "Running":
        raise InQubeError(f"'{name}' is {power}: prepare it while it runs or is halted")
    try:
        _push(vm, files, timeout)
        try:
            vm.features[LABEL] = current
        except Exception as e:
            raise InQubeError(f"the services were written, but the {LABEL} label was not "
                              f"({type(e).__name__}): run the prepare again") from None
    finally:
        if started:
            try:
                vm.shutdown(wait=True)
            except Exception:
                pass
    return {"qube": name, "version": current, "started": started}


def refresh(app, timeout: float = TIMEOUT_S) -> list:
    """Bring every RUNNING prepared qube up to the installed services. Returns
    [(name, outcome)], outcome "updated" or a reason it was not; qubes already
    current, never prepared or not running are left out. Raises InQubeError
    when dom0's own copy cannot be read."""
    files = read_services()
    current = version(files)
    out = []
    for vm in list(app.domains):
        try:
            name = core.name_of(vm)
            if core.klass_of(vm) not in OWN_ROOT:
                continue
            label = label_of(vm)
            if label is None or label == current:
                continue
            if core.tags_of(vm) & SKIP_BADGES:
                continue
            if vm.get_power_state() != "Running":
                continue
        except core.Unreadable as e:
            out.append((getattr(vm, "name", "?"), f"not judged: {e}"))
            continue
        try:
            _push(vm, files, timeout)
            vm.features[LABEL] = current
        except InQubeError as e:
            out.append((name, f"not updated: {e}"))
            continue
        except Exception as e:
            out.append((name, f"not updated: the label write failed ({type(e).__name__})"))
            continue
        out.append((name, "updated"))
    return out


def _own_root(vm):
    """The qube that holds `vm`'s root: itself for a TemplateVM or a
    StandaloneVM, else the end of its template chain. None when it has none.
    Raises core.Unreadable."""
    seen = 0
    while vm is not None and seen < 8:
        if core.klass_of(vm) in OWN_ROOT:
            return vm
        vm = core.template_of(vm)
        seen += 1
    return None


def findings(vms, records: dict, tags_by: dict, add, directory: str | None = None) -> None:
    """`qmcp check`'s item: amber for every qube whose root qmcp runs commands
    in (a template a project approves, a managed qube's template, a managed
    standalone) and whose `qmcp-services` label is missing or not the installed
    version. It reads the label dom0 wrote at prepare time, not the qube's disk."""
    try:
        current = installed_version(directory)
    except InQubeError as e:
        add("fail", "in-qube services", str(e))
        return
    by_name = {getattr(vm, "name", None): vm for vm in vms}
    wanted = set()
    for p in records.values():
        wanted.update(p.templates)
    roots = {}
    for name in sorted(wanted):
        vm = by_name.get(name)
        if vm is None:
            continue
        try:
            root = _own_root(vm)
        except core.Unreadable as e:
            add("error", "in-qube services", str(e))
            continue
        if root is not None:
            roots[root.name] = root
    for vm in vms:
        tags = tags_by.get(getattr(vm, "name", None))
        if tags is None or core.UMBRELLA not in tags or core.GUARDED in tags:
            continue
        try:
            if core.klass_of(vm) == "AdminVM" or core.is_gateway(vm):
                continue
            root = _own_root(vm)
        except core.Unreadable as e:
            add("error", "in-qube services", str(e))
            continue
        if root is not None:
            roots[root.name] = root
    missing, behind = [], []
    for name in sorted(roots):
        try:
            state = label_state(roots[name], current)
        except core.Unreadable as e:
            add("error", "in-qube services", str(e))
            continue
        if state == "missing":
            missing.append(name)
        elif state == "behind":
            behind.append(name)
    if missing or behind:
        parts = []
        if missing:
            parts.append(f"no record that qmcp's services were written into {', '.join(missing)}")
        if behind:
            parts.append(f"an older version of them in {', '.join(behind)} (a running one's own "
                         f"disk is brought up to date within a minute; the qubes built on a "
                         f"template get it once the template has shut down and they restart)")
        add("warn", "in-qube services",
            "; ".join(parts) + ": sudo qmcp template prepare QUBE (this reads dom0's record, "
            "not the qube's disk)")
    else:
        add("pass", "in-qube services",
            f"{len(roots)} template(s) and standalone(s) qmcp runs commands in carry the "
            f"installed version")
