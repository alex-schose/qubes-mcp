"""qmcp_scope — shared dom0 helper for read-surface scope redaction.

Stage I-1. Closes finding F-3 (design §18.6). The *write* path has been
opaque since the Stage F2 cross-ref backport, but the *read* surfaces
still emitted out-of-scope qube names with no scope check:

  - `qmcp.GetPropertyAIManaged` serialised any VM-valued property
    (`netvm`, `template`, `default_dispvm`, `guivm`, `audiovm`,
    `management_dispvm`, …) to the referent's `.name` unconditionally.
  - `qmcp.ListAIManagedQubes` did the same for its `template` field.

One read of `ai-net-router` on 2026-06-10 disclosed `sys-firewall`,
`fedora-43-xfce`, `default-dvm`, `default-mgmt-dvm` — every one an
out-of-scope name that returns the opaque `"not found"` on direct
lookup. Invariant 2/8 ("untagged qubes are invisible … their
properties do not leak") was therefore false on the read-value path.
This helper is the symmetric read-path fix.

The fix is structural, not a denylist (design §4.1 — the MCP tool
layer is not a boundary, so the fix lives in the dom0 wrappers and any
present-or-future VM-valued property inherits it): a value is
scope-checked iff its `.name` resolves to a live domain. A qube
reference collapses to its name only when that qube is ai-managed,
else to the opaque `<out-of-scope>` sentinel. A named non-domain
object (a `label`, whose `.name` is a colour) is not a qube, so its
name passes through untouched. Scalars pass through unchanged.

Fail-closed throughout: any error establishing that a referent is
ai-managed redacts it (returns the sentinel) rather than risk a leak.

`tags` gets a deliberate path (`scoped_tags`): it is hidden today only
by accident — the `Tags` object is not JSON-serialisable, so the
wrapper crashes to the opaque error. The moment tier tags land (I-3) a
serialisation fix would silently turn `tags` reads into an
authority-topology oracle. `scoped_tags` filters to the qmcp tag
vocabulary so the read is deliberate and non-leaking now.

Loaded by the wrappers via `importlib.util.spec_from_file_location`
against `os.path.dirname(os.path.realpath(__file__))`, so the same
code runs in dom0 (`/etc/qubes-rpc/qmcp_scope.py`) and in
offline-validation on mcp-control (`public/dom0-rpc/qmcp_scope.py`)
with no sys.path or PYTHONPATH dependency — the same sibling-import
pattern Stage I-0 introduced for `qmcp_budget.py` (deviation from the
Qubes self-contained-rpc-script convention is recorded as reviewer
ask #12 in `public/README.md`).
"""
from __future__ import annotations

#: Opaque stand-in for any qube reference that is not ai-managed. Carries
#: no information about whether the referent exists — a non-ai-managed
#: qube and (after a fail-closed error) an unreadable one collapse to it.
OUT_OF_SCOPE = "<out-of-scope>"

#: Tags AI is allowed to OBSERVE on an ai-managed qube. Everything else is
#: filtered out: operator tags (e.g. `created-by-dom0`) and — the decision
#: I-3 settles — the tier tags (`ai-exec`/`ai-net`/`ai-full`/`ai-dump`). This
#: set is deliberately DISJOINT from the tier model's own namespace
#: (`qmcp_tier.QMCP_TIER_TAGS`) except for the umbrella: tiers are ENFORCED off
#: those tags in dom0 but never READ back by AI, so a `tags` read stays
#: `["ai-managed"]` and the authority topology is not an AI-readable oracle.
#: (Keystone invariant 2 already forbids AI MUTATING tags; this forbids AI
#: reading the tier ones — knowing the fleet's tier map is recon an injected
#: agent has no need for, and capability is discovered through opaque refusals,
#: not a tag read.) So `QMCP_TAG_VOCABULARY` stays `{ai-managed}`: the I-1
#: fail-closed filter (only listed tags pass) means the tier tags are hidden
#: the moment they exist, with no change here.
QMCP_TAG_VOCABULARY = frozenset({"ai-managed"})


def is_ai_managed(app, name) -> bool:
    """True iff `name` is a live domain carrying the `ai-managed` tag.

    Self-contained and fail-closed: a missing domain, an unreadable tag
    set, or any other error returns False. Callers treat False on a
    known-existing domain as "redact" — never as "leak the name".
    """
    try:
        if name not in app.domains:
            return False
        return "ai-managed" in app.domains[name].tags
    except Exception:
        return False


def scoped_name(app, value):
    """Collapse a property value to a JSON-safe, scope-redacted form.

    - A qube reference (its `.name` is a live domain): the name if the
      qube is ai-managed, else the opaque `OUT_OF_SCOPE` sentinel.
    - A named non-domain object (e.g. a `label` whose `.name` is a
      colour): its `.name`, passed through — it is not a qube.
    - Anything else (str / bytes / int / bool / None / …): unchanged.

    Fail-closed: if membership can't be established the value is treated
    as a non-qube and passed through only when it has no `.name`; a
    named object whose name *is* a domain but whose tag read fails is
    redacted by `is_ai_managed` returning False.
    """
    name = getattr(value, "name", None)
    if name is None or isinstance(value, (str, bytes)):
        return value
    if not isinstance(name, str):
        return name
    try:
        is_domain = name in app.domains
    except Exception:
        is_domain = False
    if not is_domain:
        # Named object that is not a qube (a label colour, etc.). Its
        # name is not a qube identity, so it is safe to surface.
        return name
    return name if is_ai_managed(app, name) else OUT_OF_SCOPE


def scoped_value(app, value):
    """Apply `scoped_name` to a property value or each element of a
    list/tuple/set value. The single entry point a read wrapper uses to
    serialise an arbitrary property result with scope redaction."""
    if isinstance(value, (list, tuple, set)):
        return [scoped_name(app, v) for v in value]
    return scoped_name(app, value)


def scoped_tags(value) -> list:
    """Filter a `tags` collection to the qmcp vocabulary, sorted.

    Returns a JSON-safe list (the raw `Tags` object is not
    serialisable). Fail-closed: any error iterating the tags yields the
    empty list rather than leaking the operator's tag namespace.
    """
    try:
        present = set(value)
    except Exception:
        return []
    return sorted(t for t in present if t in QMCP_TAG_VOCABULARY)
