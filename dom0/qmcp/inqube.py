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
- `after_copy(vm, source, halted_before)`, on every qube made by copying a root (a
  clone of a template or a standalone, and a standalone made from a template).
  A copy gets its source's root as it was when the source last stopped
  (measured 2026-10-10 on Qubes 4.3.1), and its source's label as it is when
  the features are copied. Unless the source read as halted, with that same
  label, just before and just after the copy, the refresh may have written
  newer services into it and labelled it
  since it started, so the copy's label could claim services its disk lacks: it
  gets `UNKNOWN` instead, which reads as behind, and the refresh writes into it
  the next time it runs. A source never prepared gives a copy with no label,
  which the check reports and the refresh skips.

The label records what dom0 wrote, never what the qube's disk holds now: a
check that read the disk would have to start the qube. Neither the hub nor a
lead can write it: their feature allowlist holds only `menu-items`,
`default-menu-items`, `service.*` and `vm-config.*`, and no rule gives the hub
or AI space an `admin.vm.feature` method. Prepare and refresh read nothing back
but the exit status: the qube may be hostile, so their output is discarded, and
every write has a timeout. Install keeps the last lines of its output, read in
bounded chunks and escaped, for the operator's report (below).

- `install(app, name, packages)`, the operator's `qmcp template install` and
  an accepted `template-install` proposal (0.9.28), installs exact package
  names into a TemplateVM in AI space with the template's own package manager,
  from the repositories it already trusts, over the path its updates already
  use. dom0 runs one fixed script as root: a probe whose exit status names the
  package manager, then that manager's install, which first checks inside the
  template that every name is a package's exact name, not an expression its
  package manager would widen (apt reads a name it does not know as a
  regular expression, dnf a versioned name as a downgrade, pacman a group as
  its members). dom0 decides on the exit status alone; the last lines of the
  output are kept, read in bounded chunks, for the operator to read, escaped.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import threading
import time

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
#: The label of a copy made while its source ran: never a version, so the check
#: reads it as behind and the refresh brings the copy up to date when it runs.
UNKNOWN = "unknown: copied from a running qube"


#: A writer's lock found held is tried this many times, this far apart, before
#: it is another writer's: the gate's sweep holds it for a moment only.
LOCK_TRIES = 5
LOCK_RETRY_S = 0.1


class InQubeError(Exception):
    """A prepare or a refresh that did not happen; the message names why, in
    fixed words, never the qube's own output."""


class _OneWriter:
    """One prepare or install in a qube at a time. Either may start a halted
    qube and shut it down when it is done, which would stop the other one's
    write part-way (a dpkg run, say), so the second refuses within half a
    second rather than waiting for it. An flock on a file in /run/qmcp, released with the process.
    The refresh never starts or stops a qube, so it takes none.

    The file is 0640, in the `qubes` group of the setgid directory, so the
    gate's timer (the dom0 user) can open it to remove it once its qube is
    gone (`core.sweep_qube_locks`), under its lock; it holds nothing. That
    removal is why a writer checks, once it has the lock, that its file is
    still the one at the path, and opens the path again when it is not: two
    writers never hold the lock on two files."""

    def __init__(self, name: str) -> None:
        self.path = os.path.join(core.RUN_DIR, f"{core.INQUBE_LOCK_PREFIX}{name}"
                                               f"{core.INQUBE_LOCK_SUFFIX}")
        self.fd = None

    def __enter__(self):
        for _ in range(3):
            self.fd = self._open()
            if core._is_current(self.fd, self.path):
                return self
            os.close(self.fd)
        raise InQubeError("its lock was removed while it was taken: try again")

    def _open(self) -> int:
        import fcntl
        import stat
        old = os.umask(0o027)
        try:
            # Never through a link, and only a regular file of this process's
            # owner: /run/qmcp is the services group's to write in.
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o640)
        except OSError as e:
            raise InQubeError(f"its lock cannot be opened ({type(e).__name__})") from None
        finally:
            os.umask(old)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            os.close(fd)
            raise InQubeError(f"{self.path} is not a lock this command made: remove it")
        # The gate's sweep takes the lock for a moment to remove a gone
        # qube's file, so a lock held now is tried again a few times before
        # it is called another writer's.
        for attempt in range(LOCK_TRIES):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except OSError:
                if attempt + 1 < LOCK_TRIES:
                    time.sleep(LOCK_RETRY_S)
        os.close(fd)
        raise InQubeError("another prepare or install is running in it: try again when it "
                          "has finished")

    def __exit__(self, *exc):
        os.close(self.fd)
        return False


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


def halted(vm) -> bool:
    """True only when the qube reads as halted: a state that cannot be read
    is not halted, which keeps a copy's label from claiming too much."""
    try:
        return vm.get_power_state() == "Halted"
    except Exception:
        return False


def _stop(vm) -> bool:
    """Shut down a qube this started; True when it is halted after. A
    shutdown that raises for a qube already halted (killed meanwhile, say)
    has still left it stopped, and one whose state cannot be read is not."""
    try:
        vm.shutdown(wait=True)
        return True
    except Exception:
        return halted(vm)


def _lookup(app, name):
    """The qube called `name`, or None when there is none. A lookup that
    fails raises core.Unreadable: it is no proof that the qube is missing."""
    if not core.valid_qube_name(name):
        return None
    try:
        return app.domains[name] if name in app.domains else None
    except Exception:
        raise core.Unreadable(f"'{name}' cannot be looked up now, so nothing was "
                              f"done") from None


def after_copy(vm, source, halted_before: bool) -> None:
    """Keep a copy's label only when its source read as halted before the copy
    (`halted_before`) and after it, with the same label. That leaves one narrow
    case, a start, a refresh and a stop all between the two reads with the
    root copied while it ran; it does not catch every interleaving. Otherwise
    write `UNKNOWN`. A copy with no label keeps none. Raises when a label
    cannot be read or written, so the caller rolls the copy back."""
    label = label_of(vm)
    if label is None:
        return
    if halted_before and halted(source) and label_of(source) == label:
        return
    vm.features[LABEL] = UNKNOWN
    if label_of(vm) != UNKNOWN:
        raise RuntimeError(f"the {LABEL} label did not read back")


def prepare(app, name: str, timeout: float = TIMEOUT_S) -> dict:
    """Write the services into the TemplateVM or StandaloneVM `name` and label
    it. Returns {"qube", "version", "started", "stopped"}: `stopped` says
    whether a qube this started is halted again (None when it was already
    running). Raises InQubeError or core.Unreadable; on either, the label is
    untouched."""
    vm = _lookup(app, name)
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
    with _OneWriter(name):
        return _prepare(vm, name, files, current, timeout)


def _prepare(vm, name, files, current, timeout) -> dict:
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
    except InQubeError as e:
        # The stop's outcome goes with the failure: a template that was halted
        # and is left running must be said, as an install says it.
        if started and not _stop(vm):
            raise InQubeError(f"{e}; it was started for this, and its shutdown did not "
                              f"complete: qvm-shutdown {name}, or qvm-kill {name}") from None
        raise
    except BaseException:
        if started:
            _stop(vm)
        raise
    stopped = _stop(vm) if started else None
    return {"qube": name, "version": current, "started": started, "stopped": stopped}


#: How long one refresh run may go on starting writes: inside the unit's
#: `TimeoutStartSec=300`, with room for the write in flight (`TIMEOUT_S`).
REFRESH_BUDGET_S = 240


def refresh(app, timeout: float = TIMEOUT_S, done=None, budget_s: float | None = None) -> list:
    """Bring every RUNNING prepared qube up to the installed services. Returns
    [(name, outcome)], outcome "updated" or a reason it was not; qubes already
    current, never prepared or not running are left out. Raises InQubeError
    when dom0's own copy cannot be read.

    `done(name, outcome, wrote)` is called for each qube as soon as it is
    settled, so its audit line is written then, not at the end of a run the
    unit's timeout may cut short; `wrote` is True when the services were
    written into it, also when its label then failed. The qubes are taken in
    a random order, and no write starts once `budget_s` has passed, so qubes
    that stall each write (a qube the hub has root in can) cannot keep the
    same others from ever being refreshed."""
    import random
    files = read_services()
    current = version(files)
    budget = REFRESH_BUDGET_S if budget_s is None else budget_s
    deadline = time.monotonic() + budget
    out = []

    def settle(name, outcome, wrote=False):
        out.append((name, outcome))
        if done is not None:
            done(name, outcome, wrote)
    vms = list(app.domains)
    random.shuffle(vms)
    for vm in vms:
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
            settle(getattr(vm, "name", "?"), f"not judged: {e}")
            continue
        if time.monotonic() >= deadline:
            settle(name, f"not updated: this run's {budget:.0f} s ran out; the next run tries "
                         f"again")
            continue
        try:
            _push(vm, files, timeout)
        except InQubeError as e:
            settle(name, f"not updated: {e}")
            continue
        except Exception as e:
            settle(name, f"not updated: the write failed ({type(e).__name__})")
            continue
        try:
            vm.features[LABEL] = current
        except Exception as e:
            settle(name, f"written, but its label was not ({type(e).__name__}): the next run "
                         f"writes it again", wrote=True)
            continue
        settle(name, "updated", wrote=True)
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
            parts.append(f"another version of them than the installed one in "
                         f"{', '.join(behind)} (a running one's own disk is brought to the "
                         f"installed one within a minute; the qubes built on a template get it "
                         f"once the template has shut down and they restart)")
        add("warn", "in-qube services",
            "; ".join(parts) + ": sudo qmcp template prepare QUBE (this reads dom0's record, "
            "not the qube's disk)")
    else:
        add("pass", "in-qube services",
            f"{len(roots)} template(s) and standalone(s) qmcp runs commands in carry the "
            f"installed version")


# ======================================================================= packages (0.9.28)

#: A package name: letters, digits, `.`, `_`, `+` and `-`, a letter or digit
#: first. No `/`, `:`, `=`, `@`, `*`, `?`, `(` or space, so no release, arch,
#: version, group, glob, path, URL or provides expression gets past the shape;
#: and never a `-` last, which apt reads as "remove this package". What is left
#: is checked again inside the template (`install`), against its own
#: repositories, because apt still reads a name with a `.` that it does not know
#: as a regular expression and dnf a name with a version as that version.
PACKAGE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+-]{0,99}\Z")
MAX_PACKAGES = 32
#: Seconds an install may take: a template's package lists refreshed through
#: its update proxy, and on Arch the whole template upgraded (`-Su`).
INSTALL_TIMEOUT_S = 1800
#: Seconds the probe for the package manager may take.
PROBE_TIMEOUT_S = 60
#: Bytes of the install's output kept for the operator (the last ones), and the
#: lines of that shown: room for a version line for each of MAX_PACKAGES, last.
TAIL_BYTES = 64 * 1024
TAIL_LINES = 40
#: The probe's exit status for each package manager it finds, in this order.
MANAGERS = {10: "apt-get", 11: "dnf", 12: "pacman"}
PROBE = (b"if command -v apt-get >/dev/null 2>&1; then exit 10; fi\n"
         b"if command -v dnf >/dev/null 2>&1; then exit 11; fi\n"
         b"if command -v pacman >/dev/null 2>&1; then exit 12; fi\n"
         b"exit 13\n")
#: What the install script's own exit statuses mean; any other is the package
#: manager's.
NOT_A_NAME = 20
NO_REFRESH = 21


def package_refusal(name) -> str | None:
    """Why `name` is not a package name dom0 passes on, or None."""
    if not isinstance(name, str) or not PACKAGE_RE.match(name):
        # Its own escapes inside plain quotes: the window escapes the message
        # again, and JSON's quotes would show there as \".
        if not isinstance(name, str):
            return "a package name is text: letters, digits, '.', '_', '+' and '-'"
        shown = json.dumps(name, ensure_ascii=True)[1:-1][:60]
        return (f"'{shown}' is not a package name: letters, digits, '.', '_', '+' and '-', a "
                f"letter or digit first, at most 100")
    if name.endswith("-"):
        return f"'{name}' ends in '-', which apt reads as removing the package"
    return None


def packages_refusal(packages) -> str | None:
    """Why `packages` is not a list dom0 installs, or None."""
    if not isinstance(packages, (list, tuple)) or not 1 <= len(packages) <= MAX_PACKAGES:
        return f"name 1 to {MAX_PACKAGES} packages"
    for name in packages:
        why = package_refusal(name)
        if why:
            return why
    if len(set(packages)) != len(packages):
        return "a package is named twice"
    return None


def install_script(manager: str, packages) -> bytes:
    """The script `qubes.VMShell` runs as root to install `packages`: check
    that each one is a package's exact name in the template's repositories,
    then install them non-interactively, keeping a changed configuration
    file on apt as Qubes' own updater does, never recommended or weak
    dependencies, refusing an install that would remove an installed package
    (apt's `--no-remove`, since `-y` would otherwise remove one that conflicts;
    dnf removes none without `--allowerasing`) and ignoring dnf's obsoletes,
    and on Arch through `-Sy` then `-Su`, never a partial upgrade. Every name has passed `packages_refusal`, and is quoted
    anyway. Its exit status is the install's; after a successful one it
    prints each package's installed version last, because the lines before
    can be anything (on Debian, Qubes' own hook lists every pending upgrade
    after each run, measured: 20 of them buried the install)."""
    names = " ".join(shlex.quote(p) for p in packages)
    if manager == "apt-get":
        # `apt-cache pkgnames` matches a prefix, never a pattern; the exact
        # line must be there. A virtual package is no package name here.
        lines = ["export DEBIAN_FRONTEND=noninteractive",
                 f"apt-get -q update || exit {NO_REFRESH}",
                 f"for n in {names}; do",
                 '  apt-cache pkgnames "$n" | grep -qxF -- "$n" || '
                 f'{{ echo "not a package name here: $n"; exit {NOT_A_NAME}; }}',
                 "done",
                 "apt-get install -y -q --no-remove -o Dpkg::Options::=--force-confdef "
                 "-o Dpkg::Options::=--force-confold --no-install-recommends -- " + names
                 + " || exit $?",
                 "dpkg-query -W -f='installed: ${Package} ${Version}\\n' -- " + names
                 + " || true"]
    elif manager == "dnf":
        # dnf5 refuses `--`; no name starts with `-`. A versioned or
        # arch-qualified name resolves to another name, and is refused. The
        # metadata is fetched first, so a name is never refused for lists it
        # could not fetch; weak dependencies stay out, as apt's recommends do.
        lines = [f"dnf -q makecache || exit {NO_REFRESH}",
                 f"for n in {names}; do",
                 '  [ "$(dnf -q repoquery --qf \'%{name}\\n\' "$n" 2>/dev/null | sort -u)" = "$n" ] || '
                 f'{{ echo "not a package name here: $n"; exit {NOT_A_NAME}; }}',
                 "done",
                 "dnf -y -q --setopt=install_weak_deps=False --setopt=obsoletes=0 install "
                 + names + " || exit $?",
                 "rpm -q --qf 'installed: %{NAME} %{VERSION}-%{RELEASE}\\n' " + names
                 + " || true"]
    elif manager == "pacman":
        # `-Sy`, the check, then `-Su` with the names: `-Syu` in two steps,
        # never a partial upgrade. A group or a provided name is no package.
        # No 10 s download timeout: through an anonymising update proxy the
        # first answer took 17 s (measured, Arch on Qubes 4.3.2), and every
        # mirror then failed; dom0 bounds the whole install anyway.
        lines = [f"pacman --noconfirm --disable-download-timeout -Sy || exit {NO_REFRESH}",
                 f"for n in {names}; do",
                 '  pacman -Si "$n" >/dev/null 2>&1 || '
                 f'{{ echo "not a package name here: $n"; exit {NOT_A_NAME}; }}',
                 "done",
                 "pacman --noconfirm --disable-download-timeout --needed -Su " + names
                 + " || exit $?",
                 "pacman -Q " + names + " | sed 's/^/installed: /' || true"]
    else:
        raise InQubeError(f"no install for the package manager {manager}")
    return ("\n".join(["set -u"] + lines + ["exit 0"]) + "\n").encode("ascii")


def _run_bounded(vm, script: bytes, timeout: float, keep: int = TAIL_BYTES) -> tuple:
    """Run `script` as root in the RUNNING qube `vm` and return (exit status,
    the last `keep` bytes of its output). The output is read in chunks and only
    its tail kept, so a qube that writes without end costs dom0 `keep` bytes
    and the timeout, never more. Raises InQubeError."""
    try:
        proc = vm.run_service("qubes.VMShell", user="root", autostart=False,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    except Exception as e:
        raise InQubeError(f"could not reach it ({type(e).__name__})") from None
    tail = bytearray()

    def read() -> None:
        try:
            while True:
                chunk = proc.stdout.read1(65536)
                if not chunk:
                    return
                tail.extend(chunk)
                if len(tail) > keep:
                    del tail[:len(tail) - keep]
        except Exception:
            return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        proc.stdin.write(script)
    except Exception:
        pass                    # it stopped reading: its exit status says why
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        late = InQubeError(f"it did not finish in {int(timeout)} s")
        late.timed_out = True
        reader.join(5)
        late.tail = bytes(tail)
        raise late from None
    finally:
        reader.join(5)
        # Closed only once the reader has finished: closing a pipe another
        # thread is still blocked reading waits on that read, and a qube
        # that kept the pipe open would hang the command for good. A reader
        # still blocked is a daemon thread, gone when the command exits.
        if not reader.is_alive():
            try:
                proc.stdout.close()
            except Exception:
                pass
    return rc, bytes(tail)


def shown_tail(data: bytes, lines: int = TAIL_LINES) -> list:
    """The last `lines` lines of a qube's output, each escaped as JSON escapes
    a string (a control character, a bidi override, any non-ASCII as `\\uXXXX`),
    so the operator reads its words and never its layout."""
    text = data.decode("utf-8", errors="replace")
    out = [json.dumps(line[:300], ensure_ascii=True)[1:-1]
           for line in text.replace("\r", "\n").split("\n") if line.strip()]
    return out[-lines:]


def probe_manager(vm, timeout: float = PROBE_TIMEOUT_S) -> str:
    """The template's package manager, by the probe's exit status alone."""
    try:
        rc, _ = _run_bounded(vm, PROBE, timeout, keep=0)
    except InQubeError as e:
        raise InQubeError(f"the probe for its package manager: {e}") from None
    if rc not in MANAGERS:
        raise InQubeError("it has none of apt-get, dnf and pacman" if rc == 13
                          else f"the probe for its package manager exited {rc}")
    return MANAGERS[rc]


def install_refusal(vm, name: str) -> str | None:
    """Why `install` refuses the qube `vm`, or None. Raises core.Unreadable."""
    klass = core.klass_of(vm)
    if klass != "TemplateVM":
        return (f"'{name}' is a {klass}: packages go into a TemplateVM, whose qubes take its "
                f"root at every start")
    tags = core.tags_of(vm)
    if core.UMBRELLA not in tags:
        return f"'{name}' is not in AI space: qmcp installs packages only in AI space's templates"
    if tags & {projects.BLOCKED, projects.STOPPED}:
        return (f"'{name}' was stopped by the anonymity gate, and an install would start it: "
                f"clear it first (qmcp project unblock)")
    if core.QUARANTINE in tags:
        return f"'{name}' is held for your review: accept or reject it first (qmcp restored)"
    if projects.HUBBLIND in tags:
        return f"'{name}' is a hidden project's qube"
    if tags & {core.OPEN, core.OPEN_FW}:
        # The window's expiry kills the qube, which would stop the install
        # part-way and leave the template needing repair.
        return f"'{name}' is open to the hub: seal it first (qmcp seal {name})"
    return None


def install(app, name: str, packages, timeout: float = INSTALL_TIMEOUT_S) -> dict:
    """Install `packages` into the TemplateVM `name`. Returns {"qube",
    "manager", "packages", "ok", "status", "started", "lines"}: `ok` is the
    exit status alone, `lines` the escaped tail of the output, `stopped`
    whether a template this started shut down again (None when it was already
    running). A halted template is started for it and shut down again after; a
    running one keeps running. Raises InQubeError or core.Unreadable before the install's script
    ran, saying what became of a template it started (shut down again, or a
    shutdown that did not complete); a script that did not finish in
    `timeout` is a result, not an error, since it may have changed the
    template."""
    why = packages_refusal(packages)
    if why:
        raise InQubeError(why)
    vm = _lookup(app, name)
    if vm is None or core.klass_of(vm) == "AdminVM":
        raise InQubeError(f"no qube '{name}'")
    why = install_refusal(vm, name)
    if why:
        raise InQubeError(why)
    with _OneWriter(name):
        return _install(vm, name, packages, timeout)


def _install(vm, name, packages, timeout) -> dict:
    power = vm.get_power_state()
    started = False
    if power == "Halted":
        try:
            vm.start()
        except Exception as e:
            raise InQubeError(f"'{name}' did not start ({type(e).__name__})") from None
        started = True
    elif power != "Running":
        raise InQubeError(f"'{name}' is {power}: install while it runs or is halted")
    late, stopped, early = None, None, None
    try:
        try:
            manager = probe_manager(vm)
            t0 = time.monotonic()
            rc, out = _run_bounded(vm, install_script(manager, packages), timeout)
        except InQubeError as e:
            if not getattr(e, "timed_out", False):
                early = e
            else:
                late, rc, out = e, None, e.tail
        took = int(time.monotonic() - t0) if early is None else 0
    finally:
        if started:
            stopped = _stop(vm)
    if early is not None:
        # Stopped before the install's script ran (the probe, or reaching the
        # qube): said with what became of a template this started.
        tail = ("" if not started else
                "; it was started for this and shut down again" if stopped else
                f"; it was started for this, and its shutdown did not complete: qvm-kill {name}")
        raise InQubeError(f"{early}{tail}") from None
    if late is not None:
        # Killing dom0's end stops nothing inside the qube: in a template that
        # was running, the script runs on; one this started is shut down now,
        # which stops it wherever it was.
        if stopped:
            then = ("the template was shut down, which stopped the install part-way, so it may "
                    "need repair")
        elif started:
            then = (f"its shutdown did not complete, so the install may still be running: "
                    f"qvm-kill {name}")
        else:
            then = ("dom0 stopped reading its output, so the install may still be running, or "
                    "may have stopped part-way: check the template (dpkg --audit, dnf check, "
                    "pacman -Dk) before relying on it")
        status = f"{manager} did not finish in {took} s, and dom0 stopped waiting: {then}"
    elif rc == 0:
        status = f"installed with {manager} in {took} s (the template's exit status)"
    elif rc == NOT_A_NAME:
        status = (f"refused inside the template before anything was installed, by its report: a "
                  f"name is not a package's exact name in its repositories (its output, below, "
                  f"says which)")
    elif rc == NO_REFRESH:
        status = (f"{manager} could not refresh the package lists, by the template's report, so "
                  f"nothing was installed: is its update proxy reachable (Global Config, "
                  f"Updates)?")
    else:
        status = f"{manager} exited {rc} after {took} s: read its output below"
    return {"qube": name, "manager": manager, "packages": list(packages), "ok": rc == 0,
            "status": status, "started": started, "stopped": stopped, "lines": shown_tail(out)}
