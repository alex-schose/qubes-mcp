#!/usr/bin/env python3
"""Stage I-6 test plan — run from mcp-control after the I-6 deploy slot applied.

I-6 ships the operator-consent MECHANISM but leaves it INERT: the installed
/etc/qmcp/consent-policy gates the EMPTY set, so consent_required() returns False
for every call, no wrapper ever opens the daemon socket, and behaviour is
byte-neutral vs the pre-I-6 tree. The property to prove is therefore INVARIANCE
(the Stage I-3 pattern), not a new capability. Enforcement — a non-empty operator
policy that actually pops the consent dialog — is Stage I-7.

Like I-2/I-5, the consent daemon + policy live behind the dom0 trust boundary
that mcp-control (the AI's seat) CANNOT cross, so the proof splits three ways —
and this file is only ONE of the three:

  - OFFLINE (operator-local, pure python: deploy/offline-validate-I-6.py) is the
    BULK of coverage: it imports qmcp_consent, exercises every consent_required
    branch (empty=>none gated; missing/malformed=>fail-closed DEFAULT_GATED;
    exact + '*' matching) and drives request_consent/gate against an IN-PROCESS
    MOCK AF_UNIX daemon faithful to the wire protocol — including the TEETH check
    that the empty-gate path never opens the socket at all.
  - THE SLOT (dom0) is the hardware proof: the daemon starts under systemd
    --user, the socket is 0660 root:qubes-reachable, and the empty gate pops NO
    dialog (invariance on real hardware). Only dom0 can observe the daemon,
    the socket perms, or the operator's screen.
  - THIS script (mcp-control) proves the AI-SIDE invariants that hold with NO
    dom0 reach: the empty consent gate added NOTHING on top of the tier gate that
    I-5 already installed (spawn still works, an untiered qube's CAP_FULL ops are
    still the same opaque refusal, no new round-trip/timeout), NO qmcp.* service
    or MCP tool exposes the consent-policy or the socket, and a refusal on a
    gate-able surface is the SAME opaque sentinel as a not-found / untagged target
    (no consent oracle).

FLIP-AWARE (post fleet-flip, /etc/qmcp/tier-default=ro): the invariance baseline
is the I-5 POST-FLIP truth, not compat. A self-spawned qube is born UNTIERED
(Spawn strips all tier tags), so it resolves ai-ro: its reads succeed but every
CAP_FULL op (lifecycle/property/feature/attach/detach) is DENIED with the opaque
{"ok": false, "error": "not found"}. The empty I-6 gate must leave that EXACTLY
as I-5 left it — it gates the empty set, so it changes nothing. Proving a
CAP_FULL op SUCCEEDS needs an operator-tiered ai-full fixture (QMCP_I6_FULL); the
denial path needs no fixture and always runs.

By construction mcp-control CANNOT read /etc/qmcp/consent-policy or open
/run/qmcp/consent.sock — that inability IS the security property, so this script
never tries. It asserts what AI *can* observe: that I-6 changed nothing vs I-5.

Spawns its own test qube; never tags, never touches an operator qube. Post-flip
AI CANNOT remove its own untiered qube, so cleanup is best-effort and any
leftover is clearly noted for the slot/dom0 to remove. Read-only or
self-cleaned-where-possible only.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp  # noqa: E402

# ====================================================================
PROBE_TEMPLATE = "ai-debian-13"
GHOST = "qmcp-i6-no-such-qube-zzz"
TEST_QUBE = "ai-i6-probe"

# Optional operator-tagged ai-full fixture (only dom0 can tag it; the slot
# creates + tags it and passes the name via QMCP_I6_FULL). Absent → the
# happy-path CAP_FULL probe SKIPs. The DENIAL path needs no fixture.
PROBE_AI_FULL = os.environ.get("QMCP_I6_FULL") or None

# The wrapper's opaque refusal for a missing/untagged/under-tier target. POST-FLIP
# (tier-default=ro) the empty consent gate still never fires, and the tier gate
# from I-5 DENIES every CAP_FULL op on an untiered qube — so a self-spawned qube
# (born untiered → ai-ro) refuses lifecycle/property/feature/attach/detach with
# this SAME object, byte-identical to a ghost/dom0/untagged target. The empty
# consent gate adds nothing on top of that tier denial. A CAP_FULL op SUCCEEDS
# only on an operator-tiered ai-full fixture (QMCP_I6_FULL).
NOT_FOUND = {"ok": False, "error": "not found"}

# The load-bearing consent SURFACE that must NOT be REACHABLE from the MCP tool
# layer: importing the consent helper, connecting to the consent socket, or
# reading the socket/policy path. A tool that did any of these could read the
# policy, open the socket, or forge an approval — the surfaces I-6 keeps strictly
# in dom0. If a wrapper leaked the consent verdict to AI it would be a consent
# oracle distinct from a tag/tier denial; I-6 keeps the verdict on the dom0 audit
# line only.
#
# WHY CODE-ONLY, COMMENT-STRIPPED: a bare mention of "consent" in a COMMENT is NOT
# a reachable surface. tools/_qrexec.py documents the T_gate<recv<T_mcp ordering
# (GATED_TIMEOUT=360) and names qmcp_consent.py / qmcp-consentd / the
# /etc/qmcp/consent-timeout path in COMMENTS — the contract-mandated honest caveat,
# not code that reads the file. A blunt substring scan would false-fail on that
# caveat; whitelisting _qrexec.py wholesale would go the other way and blind the
# scan to a FUTURE real leak added to that same file. So instead we strip comments
# first and then match only reachable CODE patterns:
#   - an actual import of the consent helper:  `import qmcp_consent`
#   - a socket connect to a consent endpoint:  `.connect(` on a line naming a
#     consent socket, or the consent socket/rundir path in a live string literal
#   - a read of the consent policy/socket path: `consent.sock`, `/run/qmcp`,
#     `consent-policy`
# These stay STRICT: a tool that really does `import qmcp_consent` or opens
# `/run/qmcp/consent.sock` still trips the scan. The tokens below are matched only
# in COMMENT-STRIPPED source; the import/connect patterns are matched as regexes.
CONSENT_PATH_TOKENS = ("consent-policy", "consent.sock", "/run/qmcp")
CONSENT_IMPORT_RE = re.compile(r"^\s*(?:from\s+qmcp_consent\b|import\s+qmcp_consent\b)", re.M)
CONSENT_CONNECT_RE = re.compile(r"\.connect\s*\([^)]*consent", re.I)


def _strip_comments(src: str) -> str:
    """Drop full-line and trailing `#` comments so a documentation mention of the
    consent contract (all of _qrexec.py's mentions live in comments) does not
    false-trip the scanner. Not a full tokenizer — a `#` inside a string literal
    could be clipped — but the consent tokens we hunt for do not legitimately
    appear inside a tool's string data, and clipping only REMOVES text (it can
    never manufacture a false positive), so erring toward stripping is safe here."""
    out = []
    for line in src.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue                      # whole-line comment
        hashpos = line.find("#")
        if hashpos != -1:
            line = line[:hashpos]         # trailing comment (see caveat above)
        out.append(line)
    return "\n".join(out)


def _consent_surface_hits(src: str) -> list:
    """Return the reachable consent-surface patterns present in CODE (comments
    stripped). Empty list => the file names no reachable consent artifact."""
    code = _strip_comments(src)
    hits = []
    if CONSENT_IMPORT_RE.search(code):
        hits.append("import qmcp_consent")
    if CONSENT_CONNECT_RE.search(code):
        hits.append("connect(...consent...)")
    hits += [tok for tok in CONSENT_PATH_TOKENS if tok in code]
    return hits


def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r) -> None:
    out = dict(r) if isinstance(r, dict) else r
    if isinstance(out, dict):
        for k in ("stdout", "stderr", "value"):
            if isinstance(out.get(k), str) and len(out[k]) > 160:
                out[k] = out[k][:160] + "... (truncated)"
    print(f"  {label:46s} → {json.dumps(out)}")


def ai_managed() -> list:
    r = call_qmcp("qmcp.ListAIManagedQubes")
    return [q["name"] for q in r.get("qubes", [])]


def cleanup(*names: str) -> None:
    """Best-effort teardown. POST-FLIP a self-spawned qube is UNTIERED, so kill +
    remove are CAP_FULL ops that the tier gate DENIES — AI cannot remove its own
    spawned qube until an operator tiers it ai-full. We attempt anyway, tolerate
    the opaque refusal, and CLEARLY note any survivor for the slot/dom0 to remove.
    Never assert-fail on a leftover untiered probe."""
    live = set(ai_managed())
    for n in names:
        if n not in live:
            continue
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "kill"})
        time.sleep(1)
        call_qmcp("qmcp.LifecycleAIManaged", {"name": n, "action": "remove"})
    still = [n for n in names if n in set(ai_managed())]
    if still:
        print(f"  NOTE — could not remove {still} (untiered → CAP_FULL denied post-flip).")
        print(f"         This is EXPECTED, not a failure. The slot/dom0 removes {still}.")


# ====================================================================
def test_1_empty_gate_invariance() -> bool:
    header("1. Empty-gate INVARIANCE — I-6 changed NOTHING vs the I-5 post-flip baseline")
    print("   POST-FLIP the invariance baseline is I-5, not compat. The empty I-6")
    print("   consent policy gates the EMPTY set, so consent_required() is False for")
    print("   every call and no wrapper opens the daemon socket. The proof is that")
    print("   the empty gate adds NOTHING on top of the I-5 tier gate:")
    print("    (a) a self-spawned qube is born UNTIERED (Spawn strips tier tags) →")
    print("        it resolves ai-ro: READS succeed, every CAP_FULL op is DENIED with")
    print("        the SAME opaque {ok:false,error:'not found'} the tier gate alone")
    print("        returned — the empty consent gate added no new refusal/oracle.")
    print("    (b) IF QMCP_I6_FULL set, a NON-DESTRUCTIVE CAP_FULL op on an operator-")
    print("        tiered ai-full qube SUCCEEDS and returns PROMPTLY — proving the")
    print("        empty gate lets the CAP_FULL-granted path (the one I-7 will gate)")
    print("        through unchanged: no daemon round-trip, no consent-timeout stall.")
    cleanup(TEST_QUBE)
    ok = True

    # --- (a) self-spawned untiered probe: born ai-ro; reads work, CAP_FULL denied
    sp = call_qmcp("qmcp.SpawnAIManagedQube",
                   {"name": TEST_QUBE, "template": PROBE_TEMPLATE, "label": "gray"})
    show("spawn probe (create gates on ai-full TEMPLATE; result born UNTIERED)", sp)
    if not sp.get("ok"):
        print("  FAIL — could not spawn (empty consent gate not byte-neutral vs I-5?)")
        return False

    # A read on the untiered probe must SUCCEED (ai-ro floor is unchanged by I-6).
    rd = call_qmcp("qmcp.GetPropertyAIManaged", {"name": TEST_QUBE, "property": "klass"})
    show("GetProperty klass (ai-ro read on untiered probe)", rd)
    if not rd.get("ok"):
        print("  FAIL — a read on the self-spawned untiered probe was denied (ai-ro floor broken?)")
        ok = False

    # Every CAP_FULL op on the untiered probe must be the opaque NOT_FOUND — the
    # I-5 tier-gate truth, UNCHANGED by the empty I-6 consent gate. If any of these
    # SUCCEEDED it would be a self-escalation on an untiered qube; this stays strict.
    cap_full_ops = [
        ("Lifecycle start", {"service": "qmcp.LifecycleAIManaged",
                             "payload": {"name": TEST_QUBE, "action": "start"}}),
        ("Lifecycle kill (I-7 typed-confirm surface)",
         {"service": "qmcp.LifecycleAIManaged", "payload": {"name": TEST_QUBE, "action": "kill"}}),
        ("Lifecycle remove (I-7 typed-confirm surface)",
         {"service": "qmcp.LifecycleAIManaged", "payload": {"name": TEST_QUBE, "action": "remove"}}),
        ("SetProperty memory=400",
         {"service": "qmcp.SetPropertyAIManaged",
          "payload": {"name": TEST_QUBE, "property": "memory", "value": "400"}}),
        ("SetFeature qmcp-i6-probe=1",
         {"service": "qmcp.SetFeatureAIManaged",
          "payload": {"name": TEST_QUBE, "feature": "qmcp-i6-probe", "value": "1"}}),
    ]
    for label, call in cap_full_ops:
        r = call_qmcp(call["service"], call["payload"])
        show(f"{label} on untiered probe → must be NOT_FOUND", r)
        if r != NOT_FOUND:
            print(f"  FAIL — {label} on an UNTIERED qube was not the opaque refusal: {r}")
            print("         (a CAP_FULL op succeeding on an untiered qube is self-escalation)")
            ok = False

    # --- (b) OPTIONAL happy path: the empty gate lets a CAP_FULL-granted op through
    # unchanged and promptly. NON-DESTRUCTIVE: a GetProperty→SetProperty memory
    # round-trip on an operator-tiered ai-full fixture (never remove/kill it).
    if PROBE_AI_FULL:
        t0 = time.monotonic()
        cur = call_qmcp("qmcp.GetPropertyAIManaged",
                        {"name": PROBE_AI_FULL, "property": "memory"})
        show(f"GetProperty memory on ai-full {PROBE_AI_FULL}", cur)
        orig = cur.get("value") if cur.get("ok") else None
        setr = call_qmcp("qmcp.SetPropertyAIManaged",
                         {"name": PROBE_AI_FULL, "property": "memory", "value": "400"})
        elapsed = time.monotonic() - t0
        show(f"SetProperty memory=400 on ai-full {PROBE_AI_FULL} (CAP_FULL granted)", setr)
        if not setr.get("ok"):
            print("  FAIL — a CAP_FULL op on the ai-full fixture was refused under the empty gate")
            print("         (the empty gate must let the granted path through unchanged)")
            ok = False
        # Promptness: the empty gate must NOT trigger a daemon round-trip / consent
        # timeout. A granted CAP_FULL op returns in seconds; a stalled gate would
        # sit near GATED_TIMEOUT (360s). Assert it returned well under that.
        if elapsed >= 60:
            print(f"  FAIL — CAP_FULL op took {elapsed:.1f}s — the empty gate is stalling on a")
            print("         daemon round-trip/timeout (it must be a no-op, returning promptly)")
            ok = False
        else:
            print(f"  (CAP_FULL op returned in {elapsed:.1f}s — no consent round-trip)")
        # Non-destructive: restore the fixture's memory if we changed it.
        if orig is not None:
            call_qmcp("qmcp.SetPropertyAIManaged",
                      {"name": PROBE_AI_FULL, "property": "memory", "value": str(orig)})
    else:
        print("  SKIP (happy path) — no QMCP_I6_FULL fixture (slot proves CAP_FULL success).")

    print(f"  {'PASS' if ok else 'FAIL'}: empty gate is a no-op — untiered CAP_FULL still opaque-denied,")
    print("        granted CAP_FULL still succeeds promptly (I-6 == I-5 post-flip).")
    return ok


def test_2_opaque_refusal_parity() -> bool:
    header("2. Opaque-refusal parity — a gate-able surface leaks no consent signal")
    print("   A refused op on a ghost / dom0 target returns the SAME")
    print("   {ok:false,error:'not found'} as pre-I-6. If a consent gate ever")
    print("   ran and leaked a distinct verdict to AI, this parity would break.")
    ok = True

    probes = [
        ("Lifecycle remove(ghost)",
         call_qmcp("qmcp.LifecycleAIManaged", {"name": GHOST, "action": "remove"})),
        ("Lifecycle kill(ghost)",
         call_qmcp("qmcp.LifecycleAIManaged", {"name": GHOST, "action": "kill"})),
        ("Lifecycle start(dom0)",
         call_qmcp("qmcp.LifecycleAIManaged", {"name": "dom0", "action": "start"})),
        ("Attach(ghost→ghost)",
         call_qmcp("qmcp.AttachDeviceAIManaged",
                   {"backend": GHOST, "frontend": GHOST,
                    "device_class": "block", "device_id": "dev0"})),
        ("Detach(ghost→ghost)",
         call_qmcp("qmcp.DetachDeviceAIManaged",
                   {"backend": GHOST, "frontend": GHOST,
                    "device_class": "block", "device_id": "dev0"})),
    ]
    for label, r in probes:
        show(label, r)
        if r != NOT_FOUND:
            print(f"  FAIL — {label} not the opaque sentinel: {r}")
            ok = False
    if ok:
        print(f"  PASS — every refusal is byte-identical to {json.dumps(NOT_FOUND)}")
        print("         (no 'refused'/'denied'/'timeout' consent verdict leaks to AI).")
    return ok


def test_3_no_aifacing_consent_surface() -> bool:
    header("3. No REACHABLE AI-facing consent surface (the daemon/policy are dom0-only)")
    # Silent static scan of the MCP tool layer (no fake-service probes — those
    # trip the qrexec catch-all deny and pop denial dialogs on the operator's
    # screen). I-6 enforces in the dom0 wrappers + a dom0 daemon; the tool layer
    # must hold NO REACHABLE reference to the consent policy, socket, or helper —
    # it inherits enforcement, it does not gain a consent read/set/probe.
    #
    # NARROWED (post-flip): scan CODE ONLY (comments stripped) for a REACHABLE
    # surface — an `import qmcp_consent`, a `.connect(...consent...)`, or a live
    # consent socket/policy path string. A documentation mention in a comment
    # (tools/_qrexec.py's GATED_TIMEOUT caveat names qmcp_consent / qmcp-consentd /
    # /etc/qmcp/consent-timeout) is NOT a surface and must scan CLEAN. We do NOT
    # whitelist _qrexec.py — a FUTURE real `import qmcp_consent` or socket open
    # added to that same file MUST still trip this scan.
    tools = Path(__file__).resolve().parents[1] / "qubes_mcp" / "tools"
    offenders = []
    for pyf in tools.rglob("*.py"):
        txt = pyf.read_text(encoding="utf-8", errors="replace")
        hits = _consent_surface_hits(txt)
        if hits:
            offenders.append(f"{pyf.name}:{hits}")
    if offenders:
        print(f"  FAIL — a tool has a REACHABLE consent surface (code, not comment): {offenders}")
        return False
    print("  PASS — no MCP tool imports the consent helper, opens the socket, or")
    print("         names the consent policy/socket path in CODE (comment mentions")
    print("         of the timeout contract are correctly ignored).")
    return True


def test_4_read_path_intact() -> bool:
    header("4. Unrelated read path intact (I-6 added no new oracle)")
    r_list = call_qmcp("qmcp.ListAIManagedQubes")
    show("ListAIManagedQubes ok", {"ok": r_list.get("ok"), "n": len(r_list.get("qubes", []))})
    if not r_list.get("ok"):
        print(f"  FAIL — list no longer answers: {r_list}")
        return False
    # A path-shaped name aimed at the consent artifacts must stay opaque — the
    # policy file and socket are NOT reachable as a qube name / read oracle.
    for probe_name in ("/etc/qmcp/consent-policy", "/run/qmcp/consent.sock"):
        r = call_qmcp("qmcp.GetPropertyAIManaged", {"name": probe_name, "property": "netvm"})
        show(f"GetProperty({probe_name})", r)
        if r != NOT_FOUND:
            print(f"  FAIL — consent-artifact path not opaque not-found: {r}")
            return False
    print("  PASS — list answers; consent-artifact-shaped reads stay opaque.")
    return True


def main() -> int:
    tests = [
        test_1_empty_gate_invariance,
        test_2_opaque_refusal_parity,
        test_3_no_aifacing_consent_surface,
        test_4_read_path_intact,
    ]
    results = []
    for t in tests:
        try:
            results.append((t.__name__, t()))
        except Exception as e:
            print(f"  EXCEPTION in {t.__name__}: {e}")
            results.append((t.__name__, False))

    header("Cleanup")
    cleanup(TEST_QUBE)
    print(f"  Remaining ai-managed qubes: {ai_managed()}")

    header("Summary")
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{passed}/{len(results)} tests green.")
    print("\nNOTE — the consent MECHANISM (parser branches, wire protocol, the")
    print("       empty-gate TEETH that the socket is never opened) is proven")
    print("       OFFLINE (deploy/offline-validate-I-6.py); the daemon start +")
    print("       socket perms + no-dialog-on-empty-gate are proven on dom0")
    print("       hardware by the deploy slot. This script proves only the")
    print("       AI-side invariance: from mcp-control, I-6 changed NOTHING.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
