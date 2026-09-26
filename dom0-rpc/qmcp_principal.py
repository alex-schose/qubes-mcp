"""qmcp_principal — the calling principal is never a legitimate OBJECT.

Wave 2 Stage 3d. Closes the mutate-path twin of the invariant I-5 already
enforces on the create path.

I-5 strips every tier tag from a freshly created qube so AI cannot mint
authority for itself. The identical invariant on the MUTATE path was never
built: nothing in any wrapper compares its target against the calling
principal. `_principal()` exists in the two create wrappers and only to
stamp `qmcp-owner_<principal>`.

What that leaves open, measured 2026-09-01 by source-read:

  - `name` is in `qmcp.SetPropertyAIManaged`'s SETTABLE_PROPS.
  - The 13 wrapper services are `* mcp-control @adminvm allow`, so the
    qrexec TARGET is dom0 and the qube name being mutated is *payload*.
    The policy engine therefore cannot filter it. Only the wrapper can.
  - `/etc/qmcp/tier-default` absent resolves to COMPAT (untiered umbrella
    = ai-full) and the base install never writes "ro" -- only the separate
    flip step (install-stage-flip.sh) does -- so a fresh install starts in
    the state where an umbrella-tagged gateway is fully mutable.

Net, on a stock install whose gateway carries the umbrella:
`SetProperty(<principal>, name, ...)` is one call, and it severs every
policy line that names the principal literally — unrecoverable without
dom0.

WHY THIS IS NOT IN qmcp_caps
----------------------------
This is an object-identity question, not a capability question, and the
distinction is load-bearing rather than stylistic. `qmcp_caps.decide()` is
bound by `/etc/qmcp/enforce-mode`, which is ABSENT (= shadow) in
production — precisely the state the gap is live in. A guard placed in the
kernel would be inert exactly where it is needed. So the wrappers call
this module as an UNCONDITIONAL pre-gate, ahead of the umbrella check, the
tier gate and the mode flag, and the refusal is identical under shadow,
strict and enforce.

WHY THE FAIL-CLOSED DIRECTION IS INVERTED FROM I-2
--------------------------------------------------
I-2's lesson ("an additive kwarg behind a best-effort guard is a silent
blackout") says to degrade gracefully so a stale helper costs only the new
field. That is correct for INSTRUMENTATION. This module is a GATE, and the
direction reverses: a dom0 still holding a pre-3d deploy has no
`qmcp_principal.py` at all, the wrapper's loader returns None, and the
call site must REFUSE. A session pattern-matching on the I-2 lesson will
get this backwards and re-open the gap the stage closes. The call sites
say so in a comment for that reason.

ANTI-THEATRE (invariant 1) — the partition below is DRAWN, not assumed
----------------------------------------------------------------------
AI runs *as* the principal; it already holds arbitrary code execution
there. Gating an operation the seat can already perform from inside
deletes nothing and reads as a control, which is invariant 2's
no-illusion defect. So this module guards only the operations exec-inside
genuinely cannot reach — the Admin-API-only object operations — and
`PRINCIPAL_GUARDED_ROLES` / `LIFECYCLE_DOMINATED` are the enumeration.
`offline-validate-3d.py` pins the whole partition, both halves, so a
later stage that moves a row fails a check instead of quietly inverting
the invariant.

Loaded by the wrappers via `importlib.util.spec_from_file_location`
against `os.path.dirname(os.path.realpath(__file__))`, the same
sibling-import pattern as qmcp_tier / qmcp_caps / qmcp_enforce, so the
same code runs in dom0 (`/etc/qubes-rpc/qmcp_principal.py`) and in
offline-validation on mcp-control (`public/dom0-rpc/qmcp_principal.py`).
"""
from __future__ import annotations

import os

#: Operator-owned file naming ADDITIONAL protected principals, one per line,
#: for a fleet that grows past a single gateway. Blank lines and `#` comments
#: are ignored (the F-N lesson: `tier-default` ignoring the comment form was a
#: shipped bug).
#:
#: **"Fail closed" points the F-1 direction here, not the usual one.** For
#: `tier-default` the restrictive value is a non-empty string; for this file
#: and for `name-prefix` the restrictive state is the DEFAULT one, and an
#: empty/absent file must never read as "protect nothing". It cannot: the
#: calling principal is derived from the qrexec source domain and is always in
#: the set, with or without this file. The file only ever ADDS.
#:
#: **Mode 0644.** The wrappers run as a NON-root dom0 user (uid 1000, group
#: qubes — I-2/slot-51), so a `root:0600` file here is unreadable to them and
#: contributes nothing while looking installed. The caller stays protected
#: either way, so this fails quiet rather than open: only the sibling gateways
#: named in the file go unprotected, and nothing says so. `install-stage-3d.sh`
#: reports the mode and warns when the wrapper user cannot read it.
PRINCIPALS_PATH = "/etc/qmcp/principals"

#: Refusal for a call whose object is a protected principal. Byte-identical to
#: every wrapper's own NOT_FOUND, and decided on SHAPE before any host lookup,
#: in constant time — the F-1 create-path pattern. No oracle is created: the
#: principal's own name is known to AI by construction, because AI *is* it.
NOT_FOUND = {"ok": False, "error": "not found"}

#: (service -> roles guarded when the named qube is a protected principal).
#:
#: A service absent from this map is NOT guarded, and each absence is a
#: decision recorded here rather than an oversight:
#:
#:   qmcp.CloneAIManagedQube      source  -- DOMINATED *for data*. AI can
#:       already read every byte of the principal from inside it and exfil
#:       over exec, so refusing the clone removes no capability. Guarding it
#:       would be theatre. Do not "fix" this omission.
#:   qmcp.SpawnAIManagedQube      template
#:   qmcp.SpawnDisposableAIManaged dvmt
#:       -- the principal is an AppVM, so neither call can name it in these
#:       roles without failing on class anyway; and F-1's `ai-` namespace
#:       already refuses the CREATED name on shape.
#:   every read surface           target
#:       -- AI knows its own name and can read its own properties from inside.
#:       Invariant-2 theatre.
PRINCIPAL_GUARDED_ROLES = {
    "qmcp.SetPropertyAIManaged":   frozenset({"target"}),
    "qmcp.SetFeatureAIManaged":    frozenset({"target"}),
    "qmcp.LifecycleAIManaged":     frozenset({"target"}),
    "qmcp.AttachDeviceAIManaged":  frozenset({"backend", "frontend"}),
    "qmcp.DetachDeviceAIManaged":  frozenset({"backend", "frontend"}),
}

#: Mutating services deliberately NOT guarded, each with the reason it is safe
#: to leave open. This exists so the exclusion is a DECISION the suite can check
#: rather than a paragraph nobody re-reads: `offline-validate-3d.py` asserts that
#: every CAP_FULL-gated service in `qmcp_caps.SERVICE_TABLE` appears in exactly
#: one of `PRINCIPAL_GUARDED_ROLES` or this set. A sixth mutation wrapper added
#: later therefore FAILS a check until someone decides which side it belongs on,
#: instead of arriving silently unguarded — which is what happened before this
#: set existed (found by re-audit 2026-09-02).
PRINCIPAL_EXCLUDED = {
    # Dominated *for data*: the agent can already read every byte of the
    # principal from inside it and exfil over exec, so refusing the clone
    # removes no capability and would be invariant-2 theatre.
    "qmcp.CloneAIManagedQube": "dominated-for-data",
    # The principal is an AppVM, so it cannot occupy these roles without
    # failing on class; and F-1's reserved `ai-` namespace already refuses the
    # CREATED name on shape, before any host lookup.
    "qmcp.SpawnAIManagedQube": "class-impossible",
    "qmcp.SpawnDisposableAIManaged": "class-impossible",
}

#: Lifecycle actions exec-inside ALREADY reaches, so guarding them on the
#: principal is theatre. Mirrors `qmcp_caps.DOMINATION` for the three actions
#: it lists as dominated by CAP_EXEC, and deliberately does NOT include
#: `pause`: exec into a paused qube blocks, so exec does not reach `unpause`,
#: and a self-pause is a denial of service with no AI-side recovery. `remove`
#: is likewise guarded — `qmcp_tombstone.entomb` refuses an unhalted qube and
#: the principal is running by construction, so it self-blocks today, but the
#: gate must not depend on that accident.
LIFECYCLE_DOMINATED = frozenset({"kill", "shutdown", "start"})


def calling_principal(environ=None) -> str:
    """The calling principal — the qrexec source domain (D1).

    Identical derivation to `_principal()` in the two create wrappers. Returns
    the empty string when the variable is absent or blank, which callers treat
    as "no principal to protect" for the derived half; the operator file half
    is unaffected. Never raises.
    """
    env = os.environ if environ is None else environ
    try:
        return (env.get("QREXEC_REMOTE_DOMAIN") or "").strip()
    except Exception:
        return ""


#: Hard cap on the operator file, in bytes. A principals file lists gateway
#: names; 64 KiB is thousands of them.
#:
#: **This is a bound on the READ, not a style choice.** `open(...).read()` with
#: no argument is unbounded, and `/etc/qmcp/principals` is a path an operator
#: can point anywhere. Measured on hardware 2026-09-02: symlinked to
#: `/dev/zero` it never returns, so every guarded call hangs — a gate that
#: fails neither open nor closed but simply stops answering, which for a qrexec
#: service means the caller blocks too. Reading CAP+1 and rejecting anything
#: larger turns that into the ordinary fail-quiet below. It also bounds the
#: per-call cost: a 200k-line file measured 61 ms per call before this.
MAX_PRINCIPALS_BYTES = 64 * 1024


def _read_extra(path) -> frozenset:
    """Names from the operator file. Absent/unreadable/malformed/oversized ->
    empty.

    Empty is the correct failure here and is NOT a fail-open: the derived
    principal is added by `protected_principals` regardless, so losing this
    file narrows the protected set to exactly the caller, never to nothing.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read(MAX_PRINCIPALS_BYTES + 1)
        if len(raw) > MAX_PRINCIPALS_BYTES:
            # Oversized or unbounded (a device, a fifo, a runaway file). Treat
            # it as malformed rather than truncating, because a truncated read
            # would silently drop the names past the cap and report nothing.
            return frozenset()
    except Exception:
        return frozenset()
    out = set()
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return frozenset(out)


def protected_principals(path=PRINCIPALS_PATH, environ=None) -> frozenset:
    """Every qube name that may not be the OBJECT of a guarded mutation.

    The calling principal is always a member when it is derivable; the
    operator file only ever adds to that.
    """
    names = set(_read_extra(path))
    caller = calling_principal(environ)
    if caller:
        names.add(caller)
    return frozenset(names)


def guards(service, role, action=None) -> bool:
    """Is (service, role[, action]) a guarded position at all?

    Pure, host-free and total — this is the partition `offline-validate-3d.py`
    pins and `install-stage-3d.sh` executes the staged module against.
    """
    roles = PRINCIPAL_GUARDED_ROLES.get(service)
    if not roles or role not in roles:
        return False
    if service == "qmcp.LifecycleAIManaged":
        if action is None:
            # An unparsed action cannot be shown to be dominated, so it is
            # guarded. Fail-closed by omission, the same shape as Stage 3c's
            # "the key must be PRESENT or the refusal stands".
            return True
        return str(action) not in LIFECYCLE_DOMINATED
    return True


def refuses_as_principal(service, role, name, action=None,
                         path=PRINCIPALS_PATH, environ=None) -> bool:
    """True iff this call must be refused because `name` is a protected
    principal in a guarded position.

    The single entry point the wrappers call. Decided on shape only — no
    `app.domains` lookup, no tag read, no qubesd round trip — so it costs the
    same whether the name exists or not.
    """
    if not name or not guards(service, role, action):
        return False
    caller = calling_principal(environ)
    if not caller:
        # **Fail CLOSED on an undeterminable caller.** qrexec sets
        # QREXEC_REMOTE_DOMAIN on every service invocation, so a guarded
        # position reached without it is not the invocation this guard was
        # written for, and the honest answer is "I cannot tell whether this
        # target is the principal" — which must refuse, not wave through.
        #
        # This was a fail-OPEN until the 2026-09-02 re-audit: an absent, empty
        # or whitespace-only variable made `protected_principals` return the
        # empty set and the guard silently protected nothing, in a stage whose
        # every other failure path refuses. Worse, the offline suite asserted
        # that behaviour as expected, so the hole had a test defending it.
        # Same direction as a missing/stale qmcp_principal at the call sites:
        # a gate that cannot decide refuses.
        return True
    return str(name) in protected_principals(path, environ)
