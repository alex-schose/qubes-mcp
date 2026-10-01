"""qmcp.scope — what a read may say about qubes outside AI space: nothing.

A read returns a referenced qube's name (a `netvm`, a `template`, a
`default_dispvm`) only when that qube is itself in AI space; anything else
collapses to the opaque `<out-of-scope>`, which carries no information about
whether the qube exists. A named object that is not a qube (a label, whose
`.name` is a colour) passes through. Fail-closed throughout.

The `tags` read is filtered to the two badges the hub may see. Operator tags
and `qmcp-owner_*` provenance stay invisible.
"""
from __future__ import annotations

from qmcp.core import GUARDED, UMBRELLA, in_scope

OUT_OF_SCOPE = "<out-of-scope>"
TAG_VOCABULARY = frozenset({UMBRELLA, GUARDED})


def scoped_name(app, value):
    """A reference's name if it is in AI space, else `<out-of-scope>`.

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
        return name if in_scope(value) else OUT_OF_SCOPE
    except Exception:
        return OUT_OF_SCOPE


def scoped_value(app, value):
    if isinstance(value, (list, tuple, set)):
        return [scoped_name(app, v) for v in value]
    return scoped_name(app, value)


def scoped_tags(value) -> list:
    try:
        present = set(value)
    except Exception:
        return []
    return sorted(t for t in present if t in TAG_VOCABULARY)
