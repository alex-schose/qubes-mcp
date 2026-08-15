"""qubes_mcp — a tag-scoped Qubes Admin API sandbox for AI assistants."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    # Read the version from installed package metadata rather than repeating the
    # literal here, so it cannot drift from pyproject.toml.
    __version__ = _version("qubes-mcp")
except PackageNotFoundError:          # running from a source checkout, not installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
