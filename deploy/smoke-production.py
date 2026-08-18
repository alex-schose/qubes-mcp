#!/usr/bin/env python3
"""Wave 2 Stage 3b — the production smoke suite that gates the Stage 3c flip.

Implements the seven items of the redesign brief's "production smoke suite,
required before any enforcement flip". Run it **from mcp-control** (the AI
seat) against the real fleet:

    public/.venv/bin/python public/deploy/smoke-production.py

Exit status is the whole point of this file — read it, do not read the output:

    0  GREEN      every item PASSed. The flip may proceed.
    2  FAILED     at least one item failed. Do not flip.
    3  INCOMPLETE nothing failed, but at least one item did not really run
                  (NOT-RUN or VACUOUS). **This is not green.** Do not flip.

**Why INCOMPLETE is its own status, and not a pass.** Two of the brief's seven
items name tools that do not live in this repository, and a third can only fail
on a fleet with more than one egress class. A suite that quietly counted those
as passes would report GREEN while 3/7 of the gate never executed — which is
exactly the failure mode the anti-grep audit had for four months, where a
checker that could not run looked identical to a checker that found nothing.
So: a check that could not run says so, and drags the verdict with it.

The four outcomes
-----------------
  PASS     ran, asserted, held.
  FAIL     ran, asserted, did not hold.
  VACUOUS  ran, but the fleet's shape means it could not have failed. Item 7 on
           a single-egress fleet is the canonical case (Stage 0.5's finding:
           every pre-0.5 "cross-egress" test was passing on the cross-ref
           guard, not on any egress invariant).
  NOT-RUN  needs something this repo does not contain, or was disabled by a
           flag. Items 2 and 3.

Which side proves what
----------------------
This runs from the AI seat, so it can only assert AI-observable properties.
Three of the brief's assertions are dom0-side by construction and are marked in
place rather than faked here:

  - item 1's "to each ai-managed qube" — an ai-managed AppVM built from an
    operator template has no `qmcp.RunInAIManaged` service to answer, and from
    the seat that is byte-identical to a tier refusal, deliberately (I-1/G0
    collapse both so exec is not a tier oracle). Distinguishing them would mean
    undoing that property, so item 1 asserts what the flip gate actually needs
    instead: nothing that could exec before can't now, measured against a
    baseline file. Which qube holds which capability is a dom0 read.
  - item 4's "with no dialog" — the consent daemon's records are in dom0. What
    the seat CAN prove is the contrapositive: I-6 is fail-closed and nobody is
    at the machine during a smoke run, so a gated op would hit T_gate and
    refuse. A prompt success under MIN_TIMEOUT is therefore evidence no dialog
    fired. Asserted as such, and labelled.
  - item 6's "read back before it was started" — the read-back lives in the
    dom0 create wrapper. The seat asserts the resulting netvm; the ordering is
    proven by `offline-validate-2.py` and by the Stage 2 hardware slot.
  - item 7's "with no approval record present" — approval records are dom0
    files with no qmcp service and no policy line. The refusal is seat-visible;
    the absence of a record is not.

This is the I-2 trust-boundary split, and naming which side proves what is the
project's standing rule for a test that cannot see everything it asserts.

The external-check contract (items 2 and 3)
-------------------------------------------
Two of the seven items assert properties of the *deployment's own* file-transfer
and context-sync tooling — a push/pull round-trip with its SHA-256 verification
intact, and a drift check reporting clean. That tooling is deployment-specific:
it is not part of qubes-mcp, is not in this repository, and must not be
reimplemented here, because a smoke suite that ships its own copy of the thing
it is smoke-testing tests the copy.

So the suite declares a contract instead of naming a tool. A conf file supplies
one shell command per item; the suite runs it and PASSes on exit 0.

    --external-conf PATH   (default: $QMCP_SMOKE_EXTERNAL, else
                            ~/.config/qmcp/smoke-external.conf)

    # one `item<N> = <command>` per line; blank lines and # comments ignored
    item2 = <command asserting the transfer round-trip>
    item3 = <command asserting the sync check is clean>

Absent file, or a missing item, is NOT-RUN — never a pass. The conf lives
outside this repo on purpose: the commands name paths belonging to one
deployment, which is exactly what does not belong in a published tree.

Fixtures
--------
Items 6 and 7 create qubes, named `qmcp-smoke-*`. They are reaped in the
preamble and again in a `finally`, because an uncleaned fixture fills the
Stage I-0 pool cap and the next run's `pool cap exceeded` is indistinguishable
from a tier refusal. `--no-create` skips both items (reported NOT-RUN) for a
strictly read-only run.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp, call_service  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
VACUOUS = "VACUOUS"
NOT_RUN = "NOT-RUN"

#: Only PASS contributes to a green verdict.
_GREEN = {PASS}

#: The consent gate's minimum T_gate (qmcp_consent.MIN_TIMEOUT). An op that
#: completes well inside this cannot have waited on an unanswered dialog.
CONSENT_MIN_TIMEOUT = 5.0

FIXTURE_PREFIX = "qmcp-smoke-"
FIXTURE_PARENT = FIXTURE_PREFIX + "parent"
FIXTURE_CLONE = FIXTURE_PREFIX + "clone"
FIXTURE_CROSS = FIXTURE_PREFIX + "cross"
FIXTURES = (FIXTURE_PARENT, FIXTURE_CLONE, FIXTURE_CROSS)

DEFAULT_EXTERNAL_CONF = "~/.config/qmcp/smoke-external.conf"
DEFAULT_BASELINE = "~/.config/qmcp/smoke-baseline.json"

RESULTS: list[tuple[int, str, str, str]] = []   # (n, title, outcome, detail)


# ---------------------------------------------------------------- reporting
def header(s: str) -> None:
    print(f"\n{'=' * 68}\n  {s}\n{'=' * 68}")


def show(label: str, r) -> None:
    out = dict(r) if isinstance(r, dict) else r
    if isinstance(out, dict):
        for k in ("stdout", "stderr", "rules"):
            if isinstance(out.get(k), str) and len(out[k]) > 160:
                out[k] = out[k][:160] + "… (truncated)"
    print(f"    {label:52s} → {json.dumps(out)}")


def record(n: int, title: str, outcome: str, detail: str = "") -> None:
    RESULTS.append((n, title, outcome, detail))
    print(f"  {outcome:8s} item {n} — {title}" + (f"  [{detail}]" if detail else ""))


def note(s: str) -> None:
    print(f"    · {s}")


# ---------------------------------------------------------------- fleet reads
def ai_managed() -> list[dict]:
    r = call_qmcp("qmcp.ListAIManagedQubes")
    return r.get("qubes", []) if r.get("ok") else []


def prop(name: str, which: str):
    """One property, or None if it did not read. Never raises."""
    r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": name, "property": which})
    return r.get("value") if r.get("ok") else None


def egress_qubes(fleet: list[dict]) -> list[str]:
    """ai-managed qubes that provide network — the fleet's egress classes.

    Read per qube rather than trusted from the list payload, because
    `provides_network` is what makes a qube an egress and the list is a
    redacted view.
    """
    out = []
    for q in fleet:
        if prop(q["name"], "provides_network") is True:
            out.append(q["name"])
    return sorted(out)


def reap(*names: str) -> None:
    """Best-effort fixture removal. Kill first — remove refuses a running qube."""
    for n in names:
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "kill"})
        time.sleep(0.5)
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "remove"})


# ================================================================= item 1
def item1(start_halted: bool, baseline_path: str) -> list[str]:
    """qmcp.RunInAIManaged still works as root wherever it worked before.

    Returns the observed exec set, for item 4 to target.

    **Why this is an INVARIANCE check and not the brief's absolute.** §6 words
    item 1 as "to each ai-managed qube", and that is false on any fleet whose
    egress qubes are built from an operator template: `qmcp.RunInAIManaged` is
    a service installed into ai-managed TEMPLATES, so an ai-managed AppVM off a
    non-qmcp template legitimately has no service to answer — and requiring one
    would mean putting the exec service inside the network path, which is a
    widening nobody asked for.

    The seat cannot tell that case apart from a tier refusal, and that is
    deliberate rather than a gap: I-1/G0 collapse both to `not found or
    refused` precisely so exec is not a tier oracle. Asking the suite to
    distinguish them would be asking it to undo a security property.

    So the assertion is the one the flip gate actually needs — *the flip broke
    nothing that worked* — measured against a baseline captured before it. A
    first run with no baseline records the set and reports VACUOUS: one
    observation cannot demonstrate invariance, and calling it a pass would be
    the vacuous green this suite exists to refuse.
    """
    title = "RunInAIManaged still works as root wherever it did before"
    fleet = ai_managed()
    if not fleet:
        record(1, title, FAIL, "no ai-managed qubes visible")
        return []

    can_exec, cannot, skipped = [], [], []
    for q in sorted(x["name"] for x in fleet):
        state = prop(q, "power_state")
        if state != "Running" and not start_halted:
            skipped.append(f"{q}({state})")
            continue
        r = call_service(q, "qmcp.RunInAIManaged",
                         {"cmd": ["id", "-u"], "shell": False,
                          "timeout": 30, "stdin": ""}, timeout=60)
        ok = bool(r.get("ok")) and r.get("rc") == 0 and r.get("stdout", "").strip() == "0"
        show(q, r)
        (can_exec if ok else cannot).append(q)

    if skipped:
        note(f"not exercised (halted; --start-halted covers them): {', '.join(skipped)}")
    if cannot:
        note(f"no exec: {', '.join(cannot)} — a tier refusal and an absent "
             f"template service are the same answer from here, by design")
    note(f"exec set: {can_exec or 'empty'}")

    base = _read_baseline(baseline_path)
    if base is None:
        _write_baseline(baseline_path, can_exec)
        record(1, title, VACUOUS,
               f"baseline written to {baseline_path} ({len(can_exec)} qube(s)) — "
               f"re-run after the flip to compare")
        return can_exec

    lost = [q for q in base if q not in can_exec and q not in
            {s.split("(")[0] for s in skipped}]
    gained = [q for q in can_exec if q not in base]
    if gained:
        # Not a failure: exec is a policy-layer surface the kernel flip does
        # not widen, so a new executable qube is a fleet change, not a flip
        # effect. Worth saying out loud rather than silently absorbing.
        note(f"newly executable since the baseline (fleet change, not a flip "
             f"effect): {', '.join(gained)}")
    if lost:
        record(1, title, FAIL,
               f"REGRESSION — exec worked before and does not now: {', '.join(lost)}")
    elif not can_exec:
        record(1, title, VACUOUS, "no qube was exercised")
    else:
        record(1, title, PASS,
               f"{len(can_exec)} qube(s) exec as root; none of the "
               f"{len(base)} baselined qube(s) regressed")
    return can_exec


def _read_baseline(path: str):
    """The recorded exec set, or None if there is no baseline yet."""
    try:
        raw = json.loads(Path(os.path.expanduser(path)).read_text(encoding="utf-8"))
    except Exception:
        return None
    # Shape-check before reaching in. Well-formed JSON of the wrong shape (a
    # bare list, a string, null) is not an exception, so `except` above does not
    # cover it — and an operator hand-editing this file produces exactly that.
    if not isinstance(raw, dict):
        return None
    got = raw.get("exec_set")
    return got if isinstance(got, list) else None


def _write_baseline(path: str, exec_set: list[str]) -> None:
    """Record the exec set. Best-effort: an unwritable baseline must not turn a
    measurement run into a crash, it just means the next run baselines again."""
    try:
        p = Path(os.path.expanduser(path))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"exec_set": sorted(exec_set)}, indent=2) + "\n",
                     encoding="utf-8")
    except Exception as exc:
        note(f"could not write the baseline ({type(exc).__name__}) — "
             f"item 1 will baseline again next run")


# ================================================================= items 2, 3
def _load_external(path: str) -> dict[str, str]:
    """Parse the operator's external-check conf. Missing file → {}."""
    try:
        raw = Path(os.path.expanduser(path)).read_text(encoding="utf-8")
    except Exception:
        return {}
    cmds = {}
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key and val:
            cmds[key] = val
    return cmds


def external_item(n: int, title: str, cmds: dict[str, str], conf_path: str) -> None:
    """Run one externally-declared check. Undeclared → NOT-RUN, never a pass."""
    cmd = cmds.get(f"item{n}")
    if not cmd:
        record(n, title, NOT_RUN,
               f"no 'item{n} = …' line in {conf_path} — see this file's header")
        return
    note(f"$ {cmd}")
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=300)
    except Exception as exc:
        record(n, title, FAIL, f"{type(exc).__name__} running the declared command")
        return
    tail = (p.stdout or p.stderr or "").strip().splitlines()
    for line in tail[-4:]:
        note(line[:160])
    if p.returncode == 0:
        record(n, title, PASS, "declared command exited 0")
    else:
        record(n, title, FAIL, f"declared command exited {p.returncode}")


# ================================================================= item 4
def item4(exec_set: list[str]) -> None:
    """A session in a qube can run, read and write there — with no dialog.

    Targets a qube item 1 observed answering exec. Picking "the first running
    ai-managed qube" instead makes this item fail on any fleet whose first
    ai-managed qube by name is an egress qube with no template service — which
    is a fact about the fleet, not about the session path this item guards.
    """
    title = "session path: run + write + read back in a qube, no dialog"
    if not exec_set:
        record(4, title, VACUOUS,
               "item 1 found no qube answering exec — nothing to exercise")
        return

    target = exec_set[0]
    marker = f"qmcp-smoke-{int(time.time())}"
    path = "/tmp/qmcp-smoke-probe"
    t0 = time.monotonic()
    w = call_service(target, "qmcp.RunInAIManaged",
                     {"cmd": ["tee", path], "shell": False,
                      "timeout": 30, "stdin": marker}, timeout=60)
    r = call_service(target, "qmcp.RunInAIManaged",
                     {"cmd": ["cat", path], "shell": False,
                      "timeout": 30, "stdin": ""}, timeout=60)
    elapsed = time.monotonic() - t0
    call_service(target, "qmcp.RunInAIManaged",
                 {"cmd": ["rm", "-f", path], "shell": False,
                  "timeout": 30, "stdin": ""}, timeout=60)
    show(f"write+read in {target}", r)

    wrote = bool(w.get("ok")) and w.get("rc") == 0
    read_back = bool(r.get("ok")) and r.get("stdout", "").strip() == marker
    note(f"round trip in {elapsed:.2f}s (consent T_gate floor is "
         f"{CONSENT_MIN_TIMEOUT:.0f}s; a dialog nobody answers fails closed)")

    if not (wrote and read_back):
        record(4, title, FAIL, f"write={wrote} read_back={read_back} in {target}")
    elif elapsed >= CONSENT_MIN_TIMEOUT:
        # Succeeded, but slowly enough that a dialog could have been answered.
        # Not a failure of the capability; a failure of the "no dialog" half,
        # which only dom0 can settle.
        record(4, title, VACUOUS,
               f"round trip took {elapsed:.1f}s — confirm no gate fired in the dom0 audit")
    else:
        record(4, title, PASS, f"{target}: wrote, read back, {elapsed:.2f}s")


# ================================================================= item 5
def item5() -> None:
    """qubes_list / qubes_state / qubes_props_get answer for every klass present."""
    title = "read tools answer for every klass present on the fleet"
    fleet = ai_managed()
    if not fleet:
        record(5, title, FAIL, "ListAIManagedQubes returned nothing")
        return

    by_klass: dict[str, str] = {}
    for q in sorted(fleet, key=lambda x: x["name"]):
        by_klass.setdefault(q.get("klass") or "unknown", q["name"])

    broken = []
    for klass, name in sorted(by_klass.items()):
        # The F-G case: a TemplateVM has no `template`, a StandaloneVM has
        # neither. Stage 0.2 made these report PER PROPERTY instead of
        # discarding the whole call, so "some property read" is the assertion.
        got = {p: prop(name, p) for p in
               ("power_state", "netvm", "template", "provides_network")}
        read_any = any(v is not None for v in got.values())
        show(f"{klass:14s} {name}", got)
        if not read_any:
            broken.append(f"{klass}/{name}")

    note(f"klasses present: {', '.join(sorted(by_klass))}")
    absent = {"AppVM", "TemplateVM", "StandaloneVM", "DispVM"} - set(by_klass)
    if absent:
        note(f"klasses not on this fleet (out of scope for 'every klass present'): "
             f"{', '.join(sorted(absent))}")
    if broken:
        record(5, title, FAIL, f"no property read for: {', '.join(broken)}")
    else:
        record(5, title, PASS, f"{len(by_klass)} klass(es) all readable")


# ================================================================= item 6
def item6(template: str) -> str | None:
    """Birth egress is INHERITED. Returns the resolved egress, or None.

    Two halves, and the first is the one that matters:
      6a  a CLONE takes its source's netvm — precedence row 1, the rule that
          keeps a Tor-side clone on Tor. Fully seat-observable, because the
          source is ai-managed and its netvm reads.
      6b  a template-based SPAWN comes up on a real egress — rows 2/3. The
          exact value is dom0-side (the gateway's netvm, or /etc/qmcp/
          birth-egress; neither is AI-readable), so the seat asserts the
          weaker, still-meaningful property: not None, ai-managed, providing
          network. That is precisely what the deleted DEFAULT_NETVM fallback
          failed to guarantee.
    """
    title = "created qube inherits its creator's egress"
    reap(*FIXTURES)

    r = call_qmcp("qmcp.SpawnAIManagedQube",
                  {"name": FIXTURE_PARENT, "template": template,
                   "klass": "AppVM", "label": "gray"}, timeout=360)
    show("spawn parent (netvm omitted → inherited)", r)
    if not r.get("ok"):
        record(6, title, FAIL, f"could not create the fixture: {r.get('error')}")
        return None

    parent_netvm = prop(FIXTURE_PARENT, "netvm")
    note(f"parent netvm resolved to {parent_netvm!r}")
    if not parent_netvm:
        record(6, title, FAIL,
               "spawn produced a network-less qube — row 4 should have refused instead")
        return None
    if prop(parent_netvm, "provides_network") is not True:
        record(6, title, FAIL,
               f"birth egress {parent_netvm!r} is not an ai-managed network provider")
        return None

    c = call_qmcp("qmcp.CloneAIManagedQube",
                  {"source": FIXTURE_PARENT, "name": FIXTURE_CLONE}, timeout=360)
    show("clone parent", c)
    if not c.get("ok"):
        record(6, title, FAIL, f"clone failed: {c.get('error')}")
        return parent_netvm

    clone_netvm = prop(FIXTURE_CLONE, "netvm")
    note(f"clone netvm is {clone_netvm!r} (row 1: must equal the source's)")
    note("the 'set and read back BEFORE start' half is enforced in the dom0 "
         "create wrapper and proven by offline-validate-2.py — not observable here")
    if clone_netvm != parent_netvm:
        record(6, title, FAIL,
               f"clone came up on {clone_netvm!r}, source is on {parent_netvm!r}")
    else:
        record(6, title, PASS, f"spawn and clone both on {parent_netvm}")
    return parent_netvm


# ================================================================= item 7
def item7(template: str, resolved: str | None, egress: list[str]) -> None:
    """A create on an egress other than the creator's is refused."""
    title = "cross-egress create is refused"
    if resolved is None:
        record(7, title, NOT_RUN, "item 6 did not resolve a birth egress to differ from")
        return
    others = [e for e in egress if e != resolved]
    if not others:
        # Stage 0.5's whole reason for existing. On one egress class the
        # refusal cannot fire, and a suite that called that a pass would be
        # reporting the same vacuous green every pre-0.5 test reported.
        record(7, title, VACUOUS,
               f"single egress class ({resolved}) — no second class to cross to")
        return

    other = others[0]
    note(f"attempting a create pinned to {other!r} while the inherited egress is {resolved!r}")
    r = call_qmcp("qmcp.SpawnAIManagedQube",
                  {"name": FIXTURE_CROSS, "template": template, "klass": "AppVM",
                   "label": "gray", "netvm": other}, timeout=360)
    show("spawn pinned to the other egress", r)
    note("the 'no approval record present' half is a dom0 file with no qmcp "
         "service and no policy line — not observable here")

    if r.get("ok"):
        record(7, title, FAIL, f"the create SUCCEEDED on {other} — §3.4 is not enforced")
        return
    err = str(r.get("error", ""))
    # slot-60's lesson: assert the mechanism, not a proxy. A refusal carrying
    # the cross-ref message means the guard fired on `other` not being
    # ai-managed — which would pass this test for entirely the wrong reason.
    if err == "netvm must match the inherited birth egress":
        record(7, title, PASS, f"refused: {err}")
    else:
        record(7, title, FAIL,
               f"refused for the WRONG reason ({err!r}) — expected the birth-egress guard")


# ================================================================= verdict
def verdict(results) -> tuple[int, str]:
    """Map the recorded outcomes to (exit status, one-line summary).

    Pure and separate from `main` so `offline-validate-3b.py` can assert the
    mapping directly. That separation is not cosmetic: this function IS the
    gate. Every other line in this file only decides what to append to
    `results`, while this one decides whether the operator is told they may
    flip — so it is the line that must not be wrong, and it is the only one
    testable without a fleet.

        any FAIL                         -> 2, FAILED
        no FAIL but any VACUOUS/NOT-RUN  -> 3, INCOMPLETE
        every item PASS                  -> 0, GREEN
        no items at all                  -> 3, INCOMPLETE

    An empty result set is INCOMPLETE rather than GREEN. A suite that crashed
    before recording anything must never report that the flip may proceed, and
    "all zero of the items passed" is exactly the vacuous truth that would.
    """
    failed = [r for r in results if r[2] == FAIL]
    incomplete = [r for r in results if r[2] != FAIL and r[2] not in _GREEN]
    total = len(results)
    if failed:
        return 2, (f"FAILED — {len(failed)} of {total} items failed. Do not flip.")
    if incomplete or total == 0:
        which = ", ".join(str(r[0]) for r in incomplete) or "none recorded"
        return 3, (f"INCOMPLETE — {len(incomplete)} of {total} items did not really "
                   f"run ({which}). Nothing failed, but this is NOT green "
                   f"and does not gate the flip.")
    return 0, f"GREEN — all {total} items passed. Stage 3c may proceed."


# ================================================================= main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Wave 2 §6 production smoke suite — the Stage 3c flip gate.")
    ap.add_argument("--template", default="ai-debian-13",
                    help="ai-managed TemplateVM the fixtures are built from")
    ap.add_argument("--external-conf",
                    default=os.environ.get("QMCP_SMOKE_EXTERNAL", DEFAULT_EXTERNAL_CONF),
                    help="conf file declaring the item2/item3 commands")
    ap.add_argument("--start-halted", action="store_true",
                    help="item 1: also exercise halted qubes (starts them)")
    ap.add_argument("--no-create", action="store_true",
                    help="skip items 6 and 7 (they create and remove qubes)")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE,
                    help="item 1: JSON file recording the pre-flip exec set")
    args = ap.parse_args()

    print(__doc__.split("\n\n")[0])
    print(f"\nfleet read from the AI seat · template={args.template}"
          f"\nexternal-conf={args.external_conf}"
          f"\nbaseline={args.baseline}")

    cmds = _load_external(args.external_conf)

    try:
        header("1 — RunInAIManaged as root")
        exec_set = item1(args.start_halted, args.baseline)

        header("2 — file-transfer round-trip (externally declared)")
        external_item(2, "push/pull round-trips with SHA-256 verification intact",
                      cmds, args.external_conf)

        header("3 — context-sync drift check (externally declared)")
        external_item(3, "the deployment's sync check reports no drift",
                      cmds, args.external_conf)

        header("4 — session path, no dialog")
        item4(exec_set)

        header("5 — read tools across klasses")
        item5()

        resolved = None
        if args.no_create:
            header("6, 7 — skipped (--no-create)")
            record(6, "created qube inherits its creator's egress", NOT_RUN, "--no-create")
            record(7, "cross-egress create is refused", NOT_RUN, "--no-create")
        else:
            header("6 — birth egress is inherited")
            resolved = item6(args.template)
            header("7 — cross-egress create refused")
            item7(args.template, resolved, egress_qubes(ai_managed()))
    finally:
        if not args.no_create:
            header("cleanup — reaping fixtures")
            # Not optional. A leftover fixture eats the Stage I-0 pool cap and
            # the next run's "pool cap exceeded" is indistinguishable from a
            # tier refusal, which has already invalidated whole measurement runs.
            reap(*FIXTURES)
            leftover = [q["name"] for q in ai_managed()
                        if q["name"].startswith(FIXTURE_PREFIX)]
            print(f"  fixtures remaining: {leftover if leftover else 'none'}")
            if leftover:
                print("  WARNING: reap these by hand before the next run.")

    # ---------------------------------------------------------- verdict
    header("VERDICT")
    for n, title, outcome, detail in sorted(RESULTS):
        print(f"  {outcome:8s} {n}. {title}" + (f"  [{detail}]" if detail else ""))
    code, line = verdict(RESULTS)
    print()
    print(f"  {line}")
    return code


if __name__ == "__main__":
    sys.exit(main())
