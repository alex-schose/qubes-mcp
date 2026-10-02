"""qmcp.scope — what a read may say about qubes its caller may not see: nothing.

A read returns a referenced qube's name (a `netvm`, a `template`, a
`default_dispvm`) only when the caller may see that qube itself: anything in
AI space for the hub; for a lead, its members, its approved templates and its
worker networks. Anything else collapses to the opaque `<out-of-scope>`, which
carries no information about whether the qube exists. A named object that is
not a qube (a label, whose `.name` is a colour) passes through. Fail-closed
throughout.

The `tags` read is filtered to the two badges the hub may see. Operator tags
and `qmcp-owner_*` provenance stay invisible.
"""
from __future__ import annotations

from qmcp.core import GUARDED, UMBRELLA, visible

OUT_OF_SCOPE = "<out-of-scope>"
TAG_VOCABULARY = frozenset({UMBRELLA, GUARDED})


def scoped_name(app, value, who=None):
    """A reference's name if `who` may see it (AI space, for the hub or for
    `who=None`), else `<out-of-scope>`.

    A qube is recognised by being one (it has a class), never by its name: a
    label called `black` is not the qube called `black`.
    """
    name = getattr(value, "name", None)
    if name is None or isinstance(value, (str, bytes)):
        return value
    if not isinstance(name, str):
        return name
    if not hasattr(value, "klass"):
        return name
    try:
        return name if visible(value, who) else OUT_OF_SCOPE
    except Exception:
        return OUT_OF_SCOPE


def scoped_value(app, value, who=None):
    if isinstance(value, (list, tuple, set)):
        return [scoped_name(app, v, who) for v in value]
    return scoped_name(app, value, who)


def scoped_tags(value) -> list:
    try:
        present = set(value)
    except Exception:
        return []
    return sorted(t for t in present if t in TAG_VOCABULARY)
