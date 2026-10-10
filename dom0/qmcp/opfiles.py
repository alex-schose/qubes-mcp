"""qmcp.opfiles — the operator files under /etc/qmcp: `qmcp settings set`,
`qmcp export` and `qmcp import`.

A Qubes backup takes dom0 in as its user's home directory only (measured on
Qubes 4.3.1, 2026-10-09: nothing of /etc/qmcp, /var/lib/qmcp or the audit log
comes back from a restore). So `export` writes the operator files into one
file in that home, where the ordinary `qvm-backup` with dom0 ticked carries
them, and `import` puts them back on a fresh install. Not exported: the
proposals, which expire in 7 days and would revive requests against a fleet
that has moved on; the audit chain, which a fresh install starts anew (and
re-chaining an old one would forge continuity); and anything under /run.

Every write under /etc/qmcp here is atomic (a temporary file, fsync, rename)
and happens holding both the project records' lock and the create lock, so no
create and no project command runs while a cap or a record changes. The export
is a new file, created exclusively and never renamed over another. Every path is read
at call time, so a test can point it elsewhere.
"""
from __future__ import annotations

import datetime
import json
import os
import pwd
import tempfile

from qmcp import birth, budget, core, gateways, projects

FORMAT = "qubes-mcp-export/1"
MAX_FILE = 1024 * 1024
MAX_EXPORT = 4 * 1024 * 1024


class OpFilesError(Exception):
    pass


def _paths() -> dict:
    """name -> path, read at call time."""
    return {"hub": core.HUB_PATH, "mode": core.MODE_PATH,
            "pool-cap": budget.CAP_PATH, "private-cap": budget.PRIVATE_CAP_PATH,
            "birth-egress": birth.BIRTH_EGRESS_PATH, "name-prefix": birth.NAME_PREFIX_PATH,
            "gateways.json": gateways.GATEWAYS_PATH, "projects.json": projects.PROJECTS_PATH}


def _read(path: str):
    """A file's text, or None when it is absent. Raises OpFilesError when it
    exists and cannot be read: an export missing a file it should hold is
    worse than none."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(MAX_FILE + 1)
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:
        raise OpFilesError(f"{path} cannot be read ({type(e).__name__})") from None
    if len(text) > MAX_FILE:
        raise OpFilesError(f"{path} is larger than {MAX_FILE} bytes")
    return text


def _write(path: str, text: str, mode: int = 0o644) -> None:
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".qmcp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _locks():
    from qmcp import fleet
    return fleet._Exclusive()


# ------------------------------------------------------------------ settings

def settings_set(app, pool_cap=None, private_cap=None, birth_egress=None) -> list:
    """Change the pool cap, the private-volume cap or birth egress. Each is
    checked before anything is written, and the writes happen under both
    locks. Returns one line per change."""
    from qmcp import fleet
    if pool_cap is None and private_cap is None and birth_egress is None:
        raise OpFilesError("nothing to change: give --pool-cap, --private-cap or --birth-egress")
    pool = None if pool_cap is None else _size(fleet, pool_cap)
    private = None if private_cap is None else _size(fleet, private_cap)
    egress = None
    if birth_egress is not None:
        egress = str(birth_egress).strip()
        if egress != "none" and not core.valid_qube_name(egress):
            raise OpFilesError(f"'{egress}' is not a qube name")
    paths = _paths()
    out = []
    with _locks():
        if egress is not None and egress != "none":
            try:
                enrolled = gateways.enrolled_names()
            except Exception:
                raise OpFilesError("the gateway registry cannot be read") from None
            if egress not in enrolled:
                raise OpFilesError(f"'{egress}' is not an enrolled gateway (qmcp gateway enroll "
                                   f"{egress} first)")
            vm = core.lookup(app, egress)
            if vm is None or core.QUARANTINE in core.tags_of(vm):
                raise OpFilesError(f"'{egress}' is held for your review (qmcp restored list)"
                                   if vm is not None else f"no qube '{egress}'")
        if pool is not None:
            try:
                used = budget.persistent_sum(app)
            except Exception:
                raise OpFilesError("the disk AI space uses cannot be read, so a new pool cap "
                                   "cannot be checked against it") from None
            if pool < used:
                raise OpFilesError(f"a pool cap of {pool} bytes is below the {used} AI space "
                                   f"already uses")
        if pool is not None:
            _write(paths["pool-cap"], f"{pool}\n")
            out.append(f"pool-cap: {pool}")
        if private is not None:
            _write(paths["private-cap"], f"{private}\n")
            out.append(f"private-cap: {private}")
        if egress == "none":
            _remove(paths["birth-egress"])
            out.append("birth-egress: not set")
        elif egress is not None:
            _write(paths["birth-egress"], f"{egress}\n")
            out.append(f"birth-egress: {egress}")
    return out


def _size(fleet, text) -> int:
    try:
        return fleet.parse_size(text)
    except fleet.ProjectError as e:
        raise OpFilesError(str(e)) from None


# ------------------------------------------------------------------ export

def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def export(version: str, path: str | None = None, user: str | None = None) -> str:
    """Write every operator file into one JSON file, never over an existing
    one, mode 0600 and owned by `user` when given. With no path, the file is
    `qmcp-export-<UTC time>.json` in `user`'s home. Returns the path."""
    files = {name: _read(p) for name, p in _paths().items()}
    if files["hub"] is None:
        raise OpFilesError(f"{core.HUB_PATH} is missing: there is no install to export")
    doc = {"format": FORMAT, "version": str(version)[:32], "exported": _now(), "files": files}
    owner = None
    if user is not None:
        try:
            owner = pwd.getpwnam(user)
        except KeyError:
            raise OpFilesError(f"no user '{user}'") from None
    if path is None:
        if owner is None:
            raise OpFilesError("give a file to write, or run it under sudo, which names your home")
        path = os.path.join(owner.pw_dir, f"qmcp-export-{_now()}.json")
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise OpFilesError(f"{path} exists; nothing was written") from None
    except OSError as e:
        raise OpFilesError(f"{path} cannot be created ({type(e).__name__})") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if owner is not None and os.geteuid() == 0:
            os.chown(path, owner.pw_uid, owner.pw_gid)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


# ------------------------------------------------------------------ import

def _word(text):
    return None if text is None else text.split("#", 1)[0].strip() or None


def _load_export(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read(MAX_EXPORT + 1)
    except (OSError, UnicodeDecodeError) as e:
        raise OpFilesError(f"{path} cannot be read ({type(e).__name__})") from None
    if len(raw) > MAX_EXPORT:
        raise OpFilesError(f"{path} is larger than an export can be")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise OpFilesError(f"{path} is not JSON") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise OpFilesError(f"{path} is not a qubes-mcp export ({FORMAT})")
    files = doc.get("files")
    if not isinstance(files, dict) or set(files) != set(_paths()) or \
            any(v is not None and not isinstance(v, str) for v in files.values()):
        raise OpFilesError(f"{path} does not hold the operator files an export holds")
    return doc


def plan_import(path: str) -> tuple:
    """Check an export against this install, changing nothing. Returns
    (doc, what it would write: [(name, text or None)])."""
    doc = _load_export(path)
    files = doc["files"]
    hub = core.read_hub()
    if hub is None:
        raise OpFilesError(f"{core.HUB_PATH} is missing: install first, then import")
    if _word(files["hub"]) != hub:
        raise OpFilesError(f"the export is of a hub named '{_word(files['hub'])}', this install's "
                           f"is '{hub}': the hub is fixed at install")
    try:
        mode = core.anonymous_mode()
    except core.ModeUnreadable:
        raise OpFilesError(f"{core.MODE_PATH} cannot be read") from None
    anonymous_export = _word(files["mode"]) == core.ANONYMOUS
    # An install in anonymous mode cannot be made fresh (turning the mode on
    # needs enrolled gateways, and an import needs none), so an export of one
    # goes onto a normal install, and `install.sh --anonymous` turns the mode on
    # once the qubes are restored. The other way round is refused: an ordinary
    # project cannot live in anonymous mode.
    if mode and not anonymous_export:
        raise OpFilesError("this install is in anonymous mode and the export is not: its "
                           "projects could not live here")
    try:
        records = projects.load()
        registry = gateways.load()
    except Exception as e:
        raise OpFilesError(f"this install's records cannot be read ({type(e).__name__})") from None
    if set(records) - {projects.HUB_SLOT} or records[projects.HUB_SLOT].dump or registry:
        raise OpFilesError("this install already has projects or gateways: an import is for a "
                           "fresh install, and changes nothing here")
    write = []
    for name in ("pool-cap", "private-cap"):
        text = files[name]
        if text is None:
            raise OpFilesError(f"the export has no {name}")
        if not _word(text) or not _word(text).isdigit() or int(_word(text)) <= 0:
            raise OpFilesError(f"the export's {name} is not a positive number of bytes")
        write.append((name, f"{int(_word(text))}\n"))
    egress = _word(files["birth-egress"])
    if egress is not None and not core.valid_qube_name(egress):
        raise OpFilesError("the export's birth-egress is not a qube name")
    prefix = _word(files["name-prefix"])
    if prefix is not None and not birth._PREFIX_RE.match(prefix):
        raise OpFilesError("the export's name-prefix is not one qmcp accepts")
    # An absent registry or record file is no gateway and no project, as the
    # readers take it; the import then leaves this install's file absent too.
    try:
        text = files["gateways.json"]
        new_registry = None if text is None else gateways.parse(text)
    except Exception as e:
        raise OpFilesError(f"the export's gateways.json does not validate: {e}") from None
    try:
        text = files["projects.json"]
        new_records = None if text is None else projects.parse(text)
    except Exception as e:
        raise OpFilesError(f"the export's projects.json does not validate: {e}") from None
    if egress is not None and egress not in (new_registry or {}):
        raise OpFilesError(f"the export's birth-egress '{egress}' is not in its gateway registry")
    write += [("birth-egress", None if egress is None else f"{egress}\n"),
              ("name-prefix", None if prefix is None else f"{prefix}\n"),
              ("gateways.json", new_registry), ("projects.json", new_records)]
    return doc, write


def import_(path: str) -> list:
    """Write an export's operator files onto a fresh install, under both
    locks: the caps and words first, then the gateway registry, then the
    project records, which name the gateways. Returns one line per file, and
    for an export of an install in anonymous mode, what turns the mode on."""
    doc, write = plan_import(path)
    paths = _paths()
    out = []
    with _locks():
        # Checked again under the locks: a project made meanwhile stops it.
        _, write = plan_import(path)
        for name, value in write:
            if name.endswith(".json") and value is None:
                out.append(f"{name}: none in the export, left as it is")
            elif name == "gateways.json":
                gateways.save(value, paths[name])
                out.append(f"{name}: {len(value)} gateway(s)")
            elif name == "projects.json":
                projects.save(value, paths[name])
                out.append(f"{name}: {len(set(value) - {projects.HUB_SLOT})} project(s)")
            elif value is None:
                _remove(paths[name])
                out.append(f"{name}: not set")
            else:
                _write(paths[name], value)
                out.append(f"{name}: {value.strip()}")
    if _word(doc["files"]["mode"]) == core.ANONYMOUS:
        try:
            on = core.anonymous_mode()
        except core.ModeUnreadable:
            on = False
        if not on:
            out.append("mode: the export is of an install in anonymous mode; once the qubes are "
                       "restored and accepted, turn it on with install.sh --anonymous, and start "
                       "neither the hub nor any AI qube, nor mark one to start at boot, before "
                       "then")
    return out
