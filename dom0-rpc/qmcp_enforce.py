"""qmcp_enforce — the Wave 2 Stage 3b enforcement-mode flag (SHIPPED INERT).

Stage 1 landed `qmcp_caps.decide()` in SHADOW: the kernel computes a verdict,
the wrapper ignores it, and the divergence is logged. Stage 3c flips the
wrappers to obey the kernel. This module is the switch between those states and
the way back — an operator-owned file, re-read per call, in the two-phase shape
`/etc/qmcp/tier-default` established.

**Nothing sources this module yet.** 3c wires it into the wrappers; until then
`git diff --stat -- 'dom0-rpc/qmcp.*' 'policy/' 'template-rpc/'` is empty and
behaviour-neutrality holds by construction, not by measurement (the I-3
pattern).

Why there is no policy backstop, though the plan asked for one
----------------------------------------------------------------
`tier-default` needed paired COMPAT lines in `30-mcp-control.policy` because
the surfaces it governed were `@tag:`-scoped — the qrexec policy engine matches
tags literally and cannot read an operator file, so a helper flag could not move
them (the I-4 lesson).

The lattice in `qmcp_caps.SERVICE_TABLE` spans both kinds, so the distinction
has to be drawn service by service rather than asserted over the whole table:

  - **13 dom0 wrapper surfaces** — `qmcp.{Lifecycle,SetProperty,SetFeature,
    Spawn,SpawnDisposable,Clone,Attach,Detach,GetProperty,GetPoolStats,
    List*,AIManagedEvents}` — are scoped `* mcp-control @adminvm allow` with no
    tag matching. The decision is made inside our own wrapper, which *can* read
    this file. **These are what Stage 3c flips, and they need no backstop.**
  - **6 `@tag:`-scoped surfaces** — `qmcp.{RunIn,CopyTo}AIManaged` (template
    services), `admin.vm.firewall.{Get,Set,Reload}`, and `qubes.Filecopy` — are
    decided by the qrexec engine before any code of ours runs. This module
    cannot govern them and must not claim to. They were graduated to the ladder
    already, by Stages I-4, I-5 and G0c, each with its own COMPAT backstop, and
    those flips are done.
  - **`admin.vm.tag.{Set,Remove}`** are already `deny` at `@anyvm`. There is
    nothing to flip.

So every tag-scoped surface in the lattice already had its backstop, at the
stage that graduated it. Adding one here would back up nothing while reading as
a control — invariant 2 (no-illusion), the same defect as the `_RING_MIN_TIER`
table Stage 2 deleted. Revert is `echo shadow > /etc/qmcp/enforce-mode`, or
removing the file; no policy reload, no `slot-revert`.

**A note Stage 3c must not skip:** the kernel keeps `SERVICE_TABLE` entries for
those 6 policy-decided surfaces so it can model the whole lattice, and
`shadow_record` legitimately compares against them. But flipping this flag does
not enforce them, so 3c must not read "the flag is `enforce`" as "the lattice is
enforced everywhere". That is the same shape as the unreachable
`resolved_netvm` branch 3c already has to resolve.

Why there are THREE modes and not two
-------------------------------------
Every previous flip in this project was monotone — flipping only ever removed
authority, so "fail closed" had one direction and a malformed value could drop
to least privilege. **This flip is bidirectional**, and that is not an accident
of implementation but the point of the lattice:

  - kernel DENY where the wrapper allows  -> NARROWS. The escalation class
    (`netvm`, `template`, `name`, `provides_network`) stops being writable.
  - kernel ALLOW where the wrapper denies -> WIDENS. Invariant 1 (anti-theatre)
    says a `CAP_EXEC` actor that can already `rm -rf` inside a qube gains
    nothing from a `CAP_FULL` gate on `remove`, so `DOMINATION` grants
    remove/kill/shutdown/start at `CAP_EXEC`.

So `enforce` is not uniformly safer than `shadow`, and a corrupt flag must not
resolve to it. `strict` is the state that is safer than both: allow only what
the wrapper AND the kernel allow. It takes every narrowing and no widening.

That makes it the correct malformed-value target — and, once it exists as a
target, the correct intermediate rollout step. Stage 3a shipped the tombstone
specifically to make the `remove` widening survivable; `strict` lets the
narrowing half arm now, ahead of 3c, without arming the half that needs the
tombstone. Modes are ordered by how much they trust the kernel:

    shadow  ->  strict  ->  enforce
    (none)      (veto)      (full)

Both `shadow` and `enforce` are reachable in one write from any state, so this
is a ladder for rollout, not a required path.

The 0644 trap
-------------
These wrappers run under qrexec as a NON-ROOT dom0 user. An operator file
written with `sudo bash -c 'echo enforce > /etc/qmcp/enforce-mode'` lands
`root:root 0600` and is unreadable here — the setting is then silently ignored.
It is not silently ignored: an existing-but-unreadable file resolves to
`strict`, which is louder than `shadow` and safe in the meanwhile.
`install-stage-3b.sh` checks the mode when the file is present.
"""
from __future__ import annotations

#: The operator's flag. Absent is the shipped default and means SHADOW, so
#: installing this module changes nothing.
MODE_PATH = "/etc/qmcp/enforce-mode"

SHADOW = "shadow"     #: wrapper decides; the kernel only logs divergence
STRICT = "strict"     #: allow only what BOTH allow — every narrowing, no widening
ENFORCE = "enforce"   #: the kernel's verdict is the verdict

#: Every value the operator may write. Anything else is malformed.
MODES = (SHADOW, STRICT, ENFORCE)

#: The kernel's verdict vocabulary, declared here so this module loads
#: standalone (no sibling import at module scope, the convention every dom0 lib
#: in this tree follows). `offline-validate-3b.py` asserts these three literals
#: are identical to `qmcp_caps`' — the drift guard, the same one Stage 3a used
#: on the two `TOMBSTONE_PREFIX` copies.
ALLOW = "allow"
DENY = "deny"
GATE = "gate"

#: How restrictive each verdict is. `max` over this order is "the stricter of
#: the two", which is exactly what STRICT means. GATE sits between: it is not
#: an allow, but it routes to the I-6 consent channel rather than refusing
#: outright, and collapsing it to DENY would throw that channel away.
_SEVERITY = {ALLOW: 0, GATE: 1, DENY: 2}


def read_mode(path: str = MODE_PATH) -> str:
    """Resolve the operator's enforcement mode. Always returns one of `MODES`.

    Absent                     -> SHADOW  (the shipped default; byte-neutral)
    "shadow"/"strict"/"enforce"-> that mode
    present but unreadable     -> STRICT  (fail-closed; see below)
    anything else (malformed)  -> STRICT

    **Fail-closed here is STRICT, not ENFORCE, and that is the whole design.**
    Enforcing on a corrupt flag would arm the `DOMINATION` widenings — handing
    every `CAP_EXEC` actor irreversible qube destruction — on the strength of a
    typo. STRICT is the only value that is more restrictive than both of its
    neighbours, so it is the only safe thing to fall into.

    A trailing `# comment` is stripped and the value is lowercased, matching
    `qmcp_tier._read_operator_word`. That behaviour is deliberately duplicated
    rather than imported: F-N was a bug where one operator file honoured the
    comment form and another did not, and the fix is that every operator file
    parses identically — which a shared helper would also give, at the cost of
    a module-scope sibling import this file exists to avoid.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return SHADOW
    except Exception:
        return STRICT
    word = raw.split("#", 1)[0].strip().lower()
    return word if word in MODES else STRICT


def effective_verdict(mode: str, wrapper_allowed: bool, kernel_verdict: str) -> str:
    """The verdict a wrapper must act on, given the mode and the two opinions.

    A total function over (mode, bool, verdict) — there is no input for which
    it raises, because a wrapper calling it on the mutation path cannot afford
    one. An unrecognised `mode` is treated as STRICT for the same reason
    `read_mode` falls there, and an unrecognised `kernel_verdict` is treated as
    DENY (an opinion we cannot read is not an allow).

        SHADOW  -> the wrapper's own verdict, unchanged. This is today.
        STRICT  -> the stricter of the two, on ALLOW < GATE < DENY.
        ENFORCE -> the kernel's verdict verbatim, including GATE.

    Note ENFORCE can return GATE where the wrapper would have allowed: that is
    `qmcp_caps` reporting the guarded hard class, or a guarded list it could
    not read. Stage 7 arms that path; a wrapper reaching it before then should
    treat GATE as DENY, which is what the I-6 fail-closed helper already does.
    """
    wrapper = ALLOW if wrapper_allowed else DENY
    kernel = kernel_verdict if kernel_verdict in _SEVERITY else DENY

    if mode == SHADOW:
        return wrapper
    if mode == ENFORCE:
        return kernel
    return wrapper if _SEVERITY[wrapper] >= _SEVERITY[kernel] else kernel


def is_enforcing(mode: str) -> bool:
    """True iff the kernel's verdict can change what the wrapper does.

    False only for SHADOW. Wrappers use this to decide whether to keep the
    Stage 1 divergence record: under SHADOW the record IS the enforcement
    footprint, while under STRICT/ENFORCE a divergence has already been acted
    on and the audit line carries the outcome instead.
    """
    return mode != SHADOW
