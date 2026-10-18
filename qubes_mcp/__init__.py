"""qubes_mcp — a tag-scoped Qubes Admin API sandbox for AI assistants."""

import pathlib
import re
from importlib.metadata import PackageNotFoundError, version as _version


def _from_pyproject() -> str | None:
    """The version from the tree this module was imported out of.

    Every documented install runs the server from a checkout or the release
    tarball and installs no package, so the metadata read below always failed
    and the server reported 0.0.0+unknown. The file sits two directories up
    from this one; parsed with a regexp rather than a TOML reader, because the
    server depends on nothing outside the standard library and tomllib is not
    in every Python this runs on.
    """
    path = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    # The first `version = "..."` of the [project] table, which is the first
    # table in this file; a stray match elsewhere would still be a version.
    m = re.search(r'(?m)^version\s*=\s*"([^"]{1,64})"', text)
    return m.group(1) if m else None


def _installed() -> str | None:
    try:
        return _version("qubes-mcp")
    except PackageNotFoundError:
        return None


# The tree's own pyproject.toml first: it describes the code that is running.
# Installed metadata names whichever qubes-mcp was installed, which is not this
# code when a checkout is run beside an older install. An installed copy has
# no pyproject.toml beside its package, and falls through to its metadata.
__version__ = _from_pyproject() or _installed() or "0.0.0+unknown"

__all__ = ["__version__"]
