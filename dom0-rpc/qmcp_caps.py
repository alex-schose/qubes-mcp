"""qmcp_caps — the dom0 decision kernel (Wave 2, Stage 1: SHADOW MODE).

Wave 2 replaces a hand-authored gate matrix with a kernel that *derives* the
answer from a domination lattice (decision **D4**). This module is that kernel.
It ships INERT: the wrappers call `decide()`, log any divergence from what they
actually did to the I-2 audit chain, and then proceed exactly as before. Nothing
here enforces anything until Stage 3 flips the call sites over. The I-6 pattern —
land the mechanism, prove it by invariance, enforce later.

**The three invariants this kernel exists to hold (brief §3.1).**

1. **Anti-theatre.** A gate on operation B is forbidden if the actor already
   holds a capability producing every effect of B. Gating `remove` while the
   actor holds exec is theatre: exec reaches `rm -rf` and `shutdown` already,
   so the dialog protects nothing and trains the operator to click through.
2. **No-illusion.** Every allowed op is enforced at the dom0 boundary; nothing
   above it may resemble a control. This module runs in dom0 and is never
   reachable, readable or observable from AI.
3. **Escalation is never dominated.** Tag writes, tier grants,
   `provides_network`, `template` retarget, any egress change, TemplateVM
   create — operator-only at every tier, forever. No capability, however high,
   reaches these, and no amount of domination argues them away.

**Decision order (brief §4 Stage 1) — first match wins.**

    1. any target outside the ai-managed umbrella?  -> DENY  (existence boundary)
    2. (service, action) in the escalation class?   -> DENY  (invariant 3)
    3. any target carries the guarded hard class?   -> GATE  (Stage 7 / I-7a)
    4. does an already-held capability dominate it? -> ALLOW (invariant 1)
    5. otherwise                                    -> the CAP_* ladder lookup

Steps 1 and 2 come first *deliberately*: they are the two that must never be
argued away by the domination logic in step 4. Step 3 sits above step 4 for the
same reason — the guarded class is checked fail-closed BEFORE anything can
dominate it, which is the whole point of it being "hard".

**Set-returning, rank-free — the I-3 lesson, kept.** Like `qmcp_tier`, nothing
here returns or accepts a tier *rank*. Callers ask for a verdict; the taxonomy
stays behind `qmcp_tier.effective_capabilities()`. If the ladder is ever
replaced by a genuinely orthogonal model, this module's tables move and the
wrappers do not.

**Fail-closed, everywhere.** Any exception, any missing helper, any unreadable
tag set resolves to DENY. A kernel that fails open is not a kernel. The one
deliberate exception is `explain()`, a diagnostic that never gates anything.

**Not an AI surface.** No `qmcp.*` service exposes this module, no policy line
reaches it, and its verdict strings are never returned to AI — a wrapper's
refusal stays the same opaque `"not found"` it is today. The reason strings
here exist for the dom0 audit chain and for the operator, and they name tiers
and rules freely *because* nothing carries them across the boundary. Keep it
that way: the moment a `decide()` reason reaches an AI-visible response, the
tier topology becomes the read oracle that `qmcp_tier`'s tag-hiding exists to
prevent.

Sibling-loaded by path like `qmcp_budget` / `qmcp_scope` / `qmcp_audit` /
`qmcp_tier`, so the same file runs in dom0 (`/etc/qubes-rpc/qmcp_caps.py`) and
under offline validation on mcp-control (`public/dom0-rpc/qmcp_caps.py`).
"""
from __future__ import annotations

import importlib.util
import os

# --- verdicts -------------------------------------------------------------

ALLOW = "allow"
DENY = "deny"
GATE = "gate"   #: operator consent required (the I-6 channel; Stage 7 arms it)


class Decision:
    """A verdict plus the rule that produced it.

    `rule` is a stable short identifier (`"escalation-class"`,
    `"dominated:exec"`, …) so the Stage 1 divergence log can be grouped by
    cause without parsing prose, and so a property test can assert *which*
    rule fired rather than merely that the verdict matched. A test that only
    checks the verdict passes for the right answer reached the wrong way.
    """

    __slots__ = ("verdict", "rule", "reason")

    def __init__(self, verdict: str, rule: str, reason: str = "") -> None:
        self.verdict = verdict
        self.rule = rule
        self.reason = reason

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "rule": self.rule, "reason": self.reason}

    def __eq__(self, other) -> bool:
        if not isinstance(other, Decision):
            return NotImplemented
        return (self.verdict, self.rule) == (other.verdict, other.rule)

    def __repr__(self) -> str:
        return f"Decision({self.verdict!r}, {self.rule!r}, {self.reason!r})"


# --- sibling helper load ---------------------------------------------------

def _load_sibling(modname: str):
    """Load a sibling dom0 helper by path. Returns None on any failure.

    Same shim as every other wrapper uses. A None result is NOT tolerated by
    `decide()` — it denies (see `_tier_or_deny`). The tolerant variant belongs
    to the best-effort audit hook, never to a gate.
    """
    try:
        here = os.path.dirname(os.path.realpath(__file__))
        spec = importlib.util.spec_from_file_location(
            modname, os.path.join(here, f"{modname}.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_TIER = _load_sibling("qmcp_tier")


# --- the reserved namespace and the guarded hard class ---------------------

#: Operator-authored list of qube names that are ALWAYS gated, checked before
#: the domination logic so it can never be argued away (Stage 7 / I-7a-reduced).
#: Absent file = empty set = no guarded qubes, which is the shipped default.
#: Unreadable-but-present fails CLOSED: the operator created it, so we are in
#: the managed regime and an unreadable value must not silently un-guard a
#: wallet. Same posture as `qmcp_tier`'s malformed `tier-default`.
GUARDED_LIST_PATH = "/etc/qmcp/guarded"

#: Operator-owned birth-egress fallback (row 3 of the precedence chain below).
#: Written by `install-stage-c.sh` from its own `EGRESS_QUBE`, which is why the
#: fleet-specific `DEFAULT_NETVM` constant in `qmcp.SpawnAIManagedQube` can go.
BIRTH_EGRESS_PATH = "/etc/qmcp/birth-egress"

_GUARDED_UNREADABLE = object()   #: sentinel distinguishing "absent" from "broken"


def _guarded_names(path: str = GUARDED_LIST_PATH):
    """The operator's guarded-qube name set, or the fail-closed sentinel.

    Absent -> empty set (nothing guarded — the shipped default).
    Present but unreadable/malformed -> `_GUARDED_UNREADABLE`, which `decide()`
    turns into a GATE on every target rather than silently un-guarding.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return {
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            }
    except FileNotFoundError:
        return set()
    except Exception:
        return _GUARDED_UNREADABLE


# --- the escalation class (invariant 3) ------------------------------------

#: Properties no capability may ever write. `provides_network` mints an egress
#: qube; `template` retargets a qube's whole userspace; `netvm` is the
#: deanonymisation event §3.4 exists to prevent (birth on a different egress is
#: a separate, weaker thing — see `resolve_birth_egress`). `name` is here for a
#: reason the taxonomy does not make obvious: renaming the gateway severs every
#: policy line that names it literally, executed from AI's own seat and
#: unrecoverable without dom0 (see NEXT.md's named-principal open question).
ESCALATION_PROPS = frozenset({"provides_network", "template", "netvm", "name"})

#: Klasses AI may never create. TemplateVM is the root of every qube's
#: userspace; minting one is escalation regardless of tier (D7).
ESCALATION_KLASSES = frozenset({"TemplateVM"})

#: Services that are operator-only in their entirety, at every tier, forever.
#: These have no wrapper today — they are policy-denied — but the kernel must
#: still answer for them, or a later stage that adds a surface inherits a
#: silent ALLOW by omission.
ESCALATION_SERVICES = frozenset({
    "admin.vm.tag.Set",
    "admin.vm.tag.Remove",
})


# --- the service table -----------------------------------------------------

#: Which endpoints a service gates, and the capability each endpoint must
#: grant. Mirrors the shipped enforcement exactly (public/CLAUDE.md's
#: per-surface table + the I-5 wrapper gates) so Stage 1 divergence is a real
#: signal and not a transcription error. Roles are the keys `decide()` expects
#: in `targets`.
#:
#: The policy-enforced surfaces (exec, firewall, Filecopy) are modelled here
#: even though no wrapper consults the kernel for them. Completeness is the
#: point: a lattice with holes cannot be property-tested for "no ALLOW in the
#: escalation class", because the holes answer nothing at all.
CAP_READ = "read"
CAP_EXEC = "exec"
CAP_NET = "net"
CAP_FULL = "full"
CAP_DUMP_IN = "dump-in"

SERVICE_TABLE = {
    # --- wrapper surfaces, gated in dom0 code (I-5) ------------------------
    "qmcp.LifecycleAIManaged":          {"target": CAP_FULL},
    "qmcp.SetPropertyAIManaged":        {"target": CAP_FULL},
    "qmcp.SetFeatureAIManaged":         {"target": CAP_FULL},
    "qmcp.CloneAIManagedQube":          {"source": CAP_FULL},
    "qmcp.SpawnAIManagedQube":          {"template": CAP_FULL},
    "qmcp.SpawnDisposableAIManaged":    {"dvmt": CAP_FULL},
    "qmcp.AttachDeviceAIManaged":       {"backend": CAP_FULL, "frontend": CAP_FULL},
    "qmcp.DetachDeviceAIManaged":       {"backend": CAP_FULL, "frontend": CAP_FULL},
    # --- read surfaces -----------------------------------------------------
    "qmcp.GetPropertyAIManaged":            {"target": CAP_READ},
    "qmcp.ListAttachedDevicesAIManaged":    {"target": CAP_READ},
    "qmcp.ListAIManagedQubes":              {},
    "qmcp.AIManagedEvents":                 {},
    "qmcp.GetPoolStats":                    {},
    # --- policy-enforced surfaces, modelled for completeness ---------------
    "qmcp.RunInAIManaged":      {"target": CAP_EXEC},
    "qmcp.CopyToAIManaged":     {"target": CAP_EXEC},
    "admin.vm.firewall.Get":    {"target": CAP_READ},
    "admin.vm.firewall.Set":    {"target": CAP_NET},
    "admin.vm.firewall.Reload": {"target": CAP_NET},
    "qubes.Filecopy":           {"source": CAP_EXEC, "target": CAP_EXEC},
}

#: Services whose targets are exempt from the step-1 umbrella check because the
#: service takes no qube target at all. Listed explicitly rather than inferred
#: from an empty role map, so adding a service with targets can never silently
#: land here.
NO_TARGET_SERVICES = frozenset({
    "qmcp.ListAIManagedQubes",
    "qmcp.AIManagedEvents",
    "qmcp.GetPoolStats",
})


# --- the domination lattice (invariant 1) ----------------------------------

#: (service, action) -> the capability that already produces every effect of
#: this operation, making a separate gate theatre.
#:
#: **`remove` is here and that is load-bearing.** An actor holding exec on a
#: qube can already destroy its contents; refusing `remove` leaves the same
#: data gone and the empty qube behind. What makes this safe to ALLOW is D3:
#: an AI-initiated remove becomes a *tombstone* — shutdown, drop the umbrella,
#: tag it, reap on a 24h dom0 timer — so the operator keeps a window to
#: inspect. **Stage 3 must land the tombstone in the same change that honours
#: this table.** Enforcing domination without tombstoning turns a recoverable
#: op into an irreversible one, which is the opposite of the intent.
#:
#: `attach`/`detach` are deliberately ABSENT: crossing the qube boundary to
#: physical hardware is the one action exec-inside genuinely cannot reach, so
#: nothing dominates it. That asymmetry is the whole reason the 2026-08-08
#: frozen gated set was judged to be protecting the wrong thing.
#: **`pause`/`unpause` are deliberately ABSENT, and the reason is a rule for
#: extending this table.** Domination must be *airtight*, not merely plausible.
#: `remove`/`kill`/`shutdown` are airtight (exec reaches `rm -rf` and
#: `shutdown`), and `start` is airtight because a qrexec call auto-starts its
#: target — holding exec already starts the qube. `unpause` is not: exec into a
#: paused qube blocks, so exec does not reach it. Including a merely-plausible
#: entry deletes a real gate; excluding a real one leaves harmless theatre.
#: When those are the two errors available, take the second.
DOMINATION = {
    ("qmcp.LifecycleAIManaged", "remove"):   CAP_EXEC,
    ("qmcp.LifecycleAIManaged", "kill"):     CAP_EXEC,
    ("qmcp.LifecycleAIManaged", "shutdown"): CAP_EXEC,
    ("qmcp.LifecycleAIManaged", "start"):    CAP_EXEC,
}


# --- public entry points ---------------------------------------------------

def capabilities(vm=None, *, tags=None, tier_default_path=None) -> frozenset:
    """The capability tokens granted on `vm` — a thin, fail-closed delegate.

    Exists so call sites depend on the kernel rather than reaching around it
    into `qmcp_tier`. Returns the empty set if the tier helper is missing or
    the tag read fails, never a partial answer.
    """
    if _TIER is None:
        return frozenset()
    try:
        if tier_default_path is None:
            return _TIER.effective_capabilities(vm, tags=tags)
        return _TIER.effective_capabilities(
            vm, tags=tags, tier_default_path=tier_default_path)
    except Exception:
        return frozenset()


def _in_umbrella(vm=None, *, tags=None) -> bool:
    """True iff the qube carries the existence boundary. Fail-closed."""
    if _TIER is None:
        return False
    try:
        tagset = set(tags) if tags is not None else set(vm.tags)
    except Exception:
        return False
    return _TIER.UMBRELLA in tagset


def _name_of(vm) -> str:
    """Best-effort display name for a target, for guarded-list matching."""
    try:
        return str(getattr(vm, "name", vm))
    except Exception:
        return ""


def explain(vm=None, *, tags=None, tier_default_path=None) -> dict:
    """Operator/audit diagnostic for one qube. NEVER a gate, never AI-visible.

    Returns the tier label, the capability set, and umbrella membership. This
    is the one function here that does not fail closed — it reports what it
    could not determine instead of denying, because a diagnostic that silently
    reads "no capability" for a broken tag read is worse than useless when the
    operator is trying to work out why something refused.
    """
    out = {"name": _name_of(vm), "umbrella": False, "capabilities": [],
           "tier_label": "unknown", "error": None}
    if _TIER is None:
        out["error"] = "tier helper unavailable"
        return out
    try:
        out["umbrella"] = _in_umbrella(vm, tags=tags)
        out["capabilities"] = sorted(
            capabilities(vm, tags=tags, tier_default_path=tier_default_path))
        out["tier_label"] = _TIER.tier_label(vm, tags=tags)
    except Exception as exc:            # diagnostic only — report, don't deny
        out["error"] = type(exc).__name__
    return out


def resolve_birth_egress(actor_vm=None, source_vm=None, *,
                         birth_egress_path: str = BIRTH_EGRESS_PATH,
                         is_ai_managed=None, source_authoritative=None):
    """Which netvm a qube created right now must be born on, and why.

    Returns `(name_or_None, rule)`. A `None` name with the rule
    `"birth-egress:unresolved"` means **refuse the create** — never "leave it
    unset", which is what `qmcp.SpawnAIManagedQube` does today and how a qube
    silently comes up with no network on any fleet whose egress qube is not
    named `ai-net-router`. A `None` name with `"birth-egress:source-offline"`
    is the opposite: a *resolved* answer of "no network", inherited from a
    source that deliberately has none. Callers must branch on the RULE, not on
    the name being None.

    **`source_authoritative` — Stage 2, finding F-J.** Row 1 as originally
    worded ("the source's netvm, when it has one of its own") silently falls
    through to row 2 when the source's netvm is `None`, which is right for a
    TemplateVM — a template's netvm is an update path, not a workload egress —
    and wrong for every other source. A clone of a deliberately-offline qube,
    or a disposable off an offline DVMT, would be *granted* network the source
    never had; today's `clone_vm` copies `netvm=None` and keeps it, so applying
    row 2 there is a regression, not a fix. Pass `True` when the source is a
    workload qube (clone source, DVMT) so its netvm — **including `None`** — is
    the answer; pass `False`/omit for a TemplateVM base. Omitted preserves the
    Stage 1 behaviour exactly.

    **The precedence chain (operator decision, 2026-08-17), first match wins:**

        1. the creation SOURCE's netvm      clone source / DVMT — anything that
                                            has one of its own
        2. the calling PRINCIPAL's netvm    template creates from the gateway,
                                            when the gateway itself sits inside
                                            the umbrella
        3. /etc/qmcp/birth-egress           operator-owned; installer-written
        4. (nothing resolved)               -> refuse

    **Source outranks principal deliberately.** A clone of a Tor-side qube must
    stay on Tor even when the gateway sits on the clearnet path; reversing 1
    and 2 re-creates exactly the leak this chain exists to close — an agent
    working behind one egress producing a qube behind another, which then does
    a DNS lookup or an update check on first boot.

    **A create sourced from an ai-managed qube is row 1 by construction** — the
    caller *is* the source — so no separate in-qube branch is needed when
    `SpawnDisposableFromQube` (D6) lands.

    Every candidate must itself be inside the umbrella: `CROSS_REF_PROPS`
    already refuses a netvm outside it, so a chain that proposed one would only
    produce a refusal attributed to the wrong mechanism (the slot-60 lesson —
    assert the mechanism that enforces the property, never a proxy).

    `is_ai_managed` is an injectable predicate `name -> bool` so this is
    testable offline without a qubesadmin collection; production passes one
    backed by the real domain collection.
    """
    def _ok(name) -> bool:
        if not name:
            return False
        if is_ai_managed is None:
            return False
        try:
            return bool(is_ai_managed(str(name)))
        except Exception:
            return False

    # Row 1 — the creation source's own egress.
    src_netvm = None
    try:
        src_netvm = getattr(source_vm, "netvm", None)
    except Exception:
        src_netvm = None
    if _ok(src_netvm):
        return str(src_netvm), "birth-egress:source"
    # Row 1b (F-J) — an AUTHORITATIVE source is final, whatever it says. Two
    # cases reach here, and falling through would be wrong for both:
    #   netvm is None            the source is deliberately offline; row 2
    #                            would hand its child network it never had
    #   netvm set, out of scope  the source sits on an egress we cannot
    #                            inherit; row 2 would silently re-home the
    #                            child onto a DIFFERENT path, which is the
    #                            cross-egress birth §3.4 exists to prevent
    # Only a non-authoritative source (a TemplateVM base, whose netvm is an
    # update path rather than a workload egress) may fall through to row 2.
    if source_authoritative and source_vm is not None:
        if src_netvm is None:
            return None, "birth-egress:source-offline"
        return None, "birth-egress:unresolved"

    # Row 2 — the calling principal's egress, when the gateway is in-umbrella.
    actor_netvm = None
    try:
        actor_netvm = getattr(actor_vm, "netvm", None)
    except Exception:
        actor_netvm = None
    if _ok(actor_netvm):
        return str(actor_netvm), "birth-egress:principal"

    # Row 3 — the operator's fallback, for a gateway outside the umbrella.
    try:
        with open(birth_egress_path, encoding="utf-8") as fh:
            configured = fh.read().strip()
    except Exception:
        configured = ""
    if _ok(configured):
        return configured, "birth-egress:configured"

    # Row 4 — refuse. Better a clear failure than a network-less qube.
    return None, "birth-egress:unresolved"


def shadow_record(actor, service, action, targets=None, params=None, *,
                  wrapper_allowed, **kw):
    """Stage 1's whole enforcement footprint: compare, never act.

    Returns **None when the kernel and the wrapper agree** — which is the
    common case and the reason the audit line stays byte-identical — and a
    compact dict when they diverge. Never raises: a shadow that can throw into
    a wrapper's success path is a shadow that changes behaviour, which is the
    one thing this stage promises not to do.

    The returned dict carries only **fixed-vocabulary** fields (the kernel's
    verdict, its rule id, and the wrapper's own verdict). Deliberately NOT the
    `reason` free text: the I-2 caller-sanitises contract says a logged summary
    is built from named fields, never forwarded prose, and a rule id is all the
    divergence log needs to be grouped and counted.

    GATE counts as "not allowed" for the comparison. That is correct rather
    than convenient — under shadow nothing can actually gate, so a wrapper that
    proceeded where the kernel says GATE really is a divergence Stage 7 has to
    resolve.
    """
    try:
        dec = decide(actor, service, action, targets, params, **kw)
        if (dec.verdict == ALLOW) == bool(wrapper_allowed):
            return None
        return {
            "kernel": dec.verdict,
            "rule": dec.rule,
            "wrapper": ALLOW if wrapper_allowed else DENY,
        }
    except Exception:
        return None


def decide(actor, service, action, targets=None, params=None, *,
           tier_default_path=None, guarded_list_path: str = GUARDED_LIST_PATH):
    """The kernel. Returns a `Decision` for one (actor, service, action, targets).

    `targets` maps the roles in `SERVICE_TABLE[service]` to qube objects (or
    anything exposing `.tags` / `.name`). `params` carries the operation's
    scalar arguments — `{"property": "netvm"}`, `{"klass": "TemplateVM"}` —
    which the escalation check reads.

    `actor` is the calling principal's NAME (the wrappers pass
    `os.environ["QREXEC_REMOTE_DOMAIN"]`). It is recorded rather than gated on
    today; when the fleet grows past one gateway it becomes D1's
    `qmcp-owner_<principal>` and I-9's delegation `principal` without a schema
    change. Reserving it now is free; retrofitting it is not.

    SHADOW MODE: nothing calls this to gate. Wrappers compare it against what
    they did and log the delta.
    """
    try:
        return _decide_inner(actor, service, action, targets or {},
                             params or {}, tier_default_path, guarded_list_path)
    except Exception as exc:
        # A kernel that throws must deny, not propagate into a wrapper's
        # success path. Stage 1 is best-effort at the CALL SITE (the wrappers
        # guard the call), but the kernel itself is fail-closed on its own
        # terms so the two postures can never disagree.
        return Decision(DENY, "kernel-error", type(exc).__name__)


def _decide_inner(actor, service, action, targets, params,
                  tier_default_path, guarded_list_path):
    roles = SERVICE_TABLE.get(service)
    if roles is None and service not in ESCALATION_SERVICES:
        # Default-deny on an unknown service. A surface added without a table
        # entry gets refused, not waved through — the G0a `SETTABLE_PROPS`
        # posture applied to the kernel itself.
        return Decision(DENY, "unknown-service", f"no lattice entry for {service}")

    present = {role: vm for role, vm in targets.items() if vm is not None}

    # --- step 1: the existence boundary ------------------------------------
    # Runs first so nothing below can reason about a qube outside the model.
    if service not in NO_TARGET_SERVICES:
        if not present and roles:
            return Decision(DENY, "no-target", "service requires a target")
        for role, vm in present.items():
            if not _in_umbrella(vm):
                return Decision(DENY, "outside-umbrella",
                                f"{role} is not ai-managed")

    # --- step 2: the escalation class (invariant 3) ------------------------
    if service in ESCALATION_SERVICES:
        return Decision(DENY, "escalation-class", f"{service} is operator-only")
    prop = params.get("property")
    if service == "qmcp.SetPropertyAIManaged" and prop in ESCALATION_PROPS:
        return Decision(DENY, "escalation-class",
                        f"property '{prop}' is operator-only at every tier")
    klass = params.get("klass")
    if klass in ESCALATION_KLASSES:
        return Decision(DENY, "escalation-class",
                        f"klass '{klass}' is operator-only")
    # A create proposing an egress the chain did not resolve to is the birth
    # half of §3.4. Stage 2 supplies `resolved_netvm`; until then the key is
    # absent and this is inert.
    proposed = params.get("netvm")
    resolved = params.get("resolved_netvm")
    if proposed is not None and resolved is not None and str(proposed) != str(resolved):
        return Decision(DENY, "escalation-class",
                        "birth egress differs from the resolved inheritance")

    # --- step 3: the guarded hard class (checked BEFORE domination) --------
    guarded = _guarded_names(guarded_list_path)
    if guarded is _GUARDED_UNREADABLE:
        return Decision(GATE, "guarded-unreadable",
                        "guarded list present but unreadable — gating")
    if guarded:
        for role, vm in present.items():
            if _name_of(vm) in guarded:
                return Decision(GATE, "guarded", f"{role} is in the guarded class")

    # --- step 4: domination (invariant 1) ----------------------------------
    dominating_cap = DOMINATION.get((service, action))
    if dominating_cap is not None:
        gated_roles = [r for r in (roles or {}) if r in present]
        if gated_roles and all(
            dominating_cap in capabilities(present[r],
                                           tier_default_path=tier_default_path)
            for r in gated_roles
        ):
            return Decision(ALLOW, f"dominated:{dominating_cap}",
                            f"{action} adds no effect beyond '{dominating_cap}'")

    # --- step 5: the ladder lookup -----------------------------------------
    for role, required in (roles or {}).items():
        vm = present.get(role)
        if vm is None:
            return Decision(DENY, "no-target", f"missing required role '{role}'")
        caps = capabilities(vm, tier_default_path=tier_default_path)
        if required not in caps:
            return Decision(DENY, f"insufficient:{required}",
                            f"{role} does not grant '{required}'")
    return Decision(ALLOW, "ladder", "capability held on every gated endpoint")
