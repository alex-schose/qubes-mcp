"""qmcp.scope — what a read may say about qubes its caller may not see: nothing.

A read returns a referenced qube's name (a `netvm`, a `template`, a
`default_dispvm`) only when the caller may see that qube itself: anything in
AI space for the hub; for a lead, its members, its approved templates and its
worker networks. An enrolled gateway is named too, wherever it sits: the hub
reads the whole registry, and a lead its own worker networks. Anything else
collapses to the opaque `<out-of-scope>`, which carries no information about
whether the qube exists. The one named object that is not a qube, a label
(whose `.name` is a colour), is answered by `GetPropertyAIManaged` itself and
never reaches here. Fail-closed throughout: a reference whose tags cannot be
read is out of scope, unless it is an enrolled gateway the caller reads by
name.

The `tags` read is filtered to the two badges the hub may see. Operator tags
and `qmcp-owner_*` provenance stay invisible.
"""
from __future__ import annotations

from qmcp import gateways
from qmcp.core import GUARDED, UMBRELLA, Unreadable, visible

OUT_OF_SCOPE = "<out-of-scope>"
TAG_VOCABULARY = frozenset({UMBRELLA, GUARDED})


def scoped_name(app, value, who=None):
    """A reference's name if `who` may see it (AI space, for the hub or for
    `who=None`; or an enrolled gateway: any, for the hub, and a lead's own
    worker networks, for a lead), else `<out-of-scope>`.

    Every named object here is a qube. Whether it is one was once asked of its
    class, and a class that failed to read then passed the name through.
    """
    name = getattr(value, "name", None)
    if name is None or isinstance(value, (str, bytes)):
        return value
    if not isinstance(name, str):
        return name
    try:
        if visible(value, who):
            return name
        if name in gateways.enrolled_names() and (
                who is None or who.is_hub() or name in who.project.named_networks()):
            return name
        return OUT_OF_SCOPE
    except Exception:
        return OUT_OF_SCOPE


def scoped_value(app, value, who=None):
    if isinstance(value, (list, tuple, set)):
        return [scoped_name(app, v, who) for v in value]
    return scoped_name(app, value, who)


def scoped_tags(value) -> list:
    """The two badges the hub may see. Tags that cannot be read raise
    `Unreadable`, never an empty list."""
    try:
        present = set(value)
    except Exception:
        raise Unreadable("cannot read the tags") from None
    return sorted(t for t in present if t in TAG_VOCABULARY)
