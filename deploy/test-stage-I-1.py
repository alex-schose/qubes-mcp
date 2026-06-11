#!/usr/bin/env python3
"""Stage I-1 test plan — run from mcp-control after slot-47.sh applied.

Verifies F-3 (design §18.6) is closed: the read surfaces
(qmcp.GetPropertyAIManaged, qmcp.ListAIManagedQubes) no longer emit
out-of-scope qube names.

Core property — the ROUND-TRIP INVARIANT: no name a read surface emits
(a VM-valued property value, or the list `template` field) is a name a
direct lookup denies. A reference to an ai-managed qube keeps its name; a
reference to anything else (operator qube, dom0, nonexistent) collapses
to the opaque "<out-of-scope>" sentinel.

Tests (all HARD):
  1. List `template` field: every non-null, non-sentinel template is an
     ai-managed name (present in the list) and resolves on direct lookup.
  2. GetProperty VM-valued props: for every ai-managed qube and every
     VM-valued property, any emitted name is ai-managed (round-trips) or
     the sentinel. THE core F-3 check. Reports how often redaction fired.
  3. `tags` read is deliberate: returns a list (no crash) holding only
     the qmcp vocabulary — no operator/auto tags (created-by-dom0, *-dom0).
  4. `label` still returns its colour (the redactor must not eat non-qube
     named objects).
  5. Existence-hiding baseline: dom0 and a nonexistent name both return
     the opaque "not found" on a VM-valued read, byte-identical (Stage A).

Pure read probes — does NOT create or modify any qube.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qubes_mcp.tools._qrexec import call_qmcp  # noqa: E402

SENTINEL = "<out-of-scope>"
VM_VALUED = ["netvm", "template", "default_dispvm",
             "guivm", "audiovm", "management_dispvm"]
COLOURS = {"red", "orange", "yellow", "green",
           "gray", "grey", "blue", "purple", "black"}
NOT_FOUND = {"ok": False, "error": "not found"}


# ====================================================================
def header(s: str) -> None:
    print(f"\n{'=' * 64}\n  {s}\n{'=' * 64}")


def show(label: str, r: dict) -> None:
    print(f"  {label:40s} → {json.dumps(r)}")


_LIST_CACHE: dict = {}


def ai_managed() -> tuple[list, dict]:
    """(names, raw list response), cached for the run."""
    if "r" not in _LIST_CACHE:
        _LIST_CACHE["r"] = call_qmcp("qmcp.ListAIManagedQubes")
    r = _LIST_CACHE["r"]
    return [q["name"] for q in r.get("qubes", [])], r


def getprop(name: str, prop: str) -> dict:
    return call_qmcp("qmcp.GetPropertyAIManaged",
                     {"name": name, "property": prop})


# ====================================================================
def test_1_list_template() -> bool:
    header("1. ListAIManagedQubes — template field redaction + round-trip")
    names, r = ai_managed()
    if not r.get("ok"):
        print(f"  FAIL — list returned not-ok: {r}")
        return False
    nameset = set(names)
    print(f"  {len(names)} ai-managed qube(s): {names}")
    ok = True
    for q in r["qubes"]:
        t = q.get("template")
        if t is None or t == SENTINEL:
            continue
        if t not in nameset:
            print(f"  FAIL — {q['name']}.template='{t}' is not ai-managed (LEAK)")
            ok = False
            continue
        rr = getprop(t, "klass")
        if not rr.get("ok"):
            print(f"  FAIL — emitted template '{t}' denies on direct lookup: {rr}")
            ok = False
    if ok:
        print("  PASS — no list template name out of scope.")
    return ok


def test_2_getprop_vm_valued() -> bool:
    header("2. GetPropertyAIManaged — VM-valued props redacted + round-trip")
    names, _ = ai_managed()
    if not names:
        print("  WARN — no ai-managed qubes to probe.")
        print("  PASS — vacuously (nothing to leak).")
        return True
    nameset = set(names)
    ok = True
    sentinel_hits = 0
    in_scope_emitted = 0
    for q in names:
        for p in VM_VALUED:
            r = getprop(q, p)
            if not r.get("ok"):
                continue  # property absent on this klass — not a leak
            val = r["value"]
            for v in (val if isinstance(val, list) else [val]):
                if not isinstance(v, str):
                    continue
                if v == SENTINEL:
                    sentinel_hits += 1
                    continue
                in_scope_emitted += 1
                if v not in nameset:
                    print(f"  FAIL — {q}.{p} emitted out-of-scope name '{v}' (LEAK)")
                    ok = False
                    continue
                rr = getprop(v, "klass")
                if not rr.get("ok"):
                    print(f"  FAIL — {q}.{p}='{v}' denies on direct lookup (round-trip)")
                    ok = False
    print(f"  redaction fired {sentinel_hits}× (→ sentinel); "
          f"{in_scope_emitted} in-scope name(s) emitted, all ai-managed")
    if sentinel_hits == 0:
        print("  NOTE — no out-of-scope reference existed to redact on this")
        print("         fleet (every ai-managed qube references only ai-managed")
        print("         qubes / None). Invariant holds; redaction not exercised.")
    if ok:
        print("  PASS — every emitted VM-valued name is in-scope; no leak.")
    return ok


def test_3_tags_deliberate() -> bool:
    header("3. GetPropertyAIManaged — tags read deliberate (vocabulary only)")
    names, _ = ai_managed()
    if not names:
        print("  PASS — vacuously (no qubes).")
        return True
    q = names[0]
    r = getprop(q, "tags")
    show(f"tags of {q}", r)
    if not r.get("ok"):
        print(f"  FAIL — tags read not ok (must be a deliberate list now): {r}")
        return False
    val = r["value"]
    if not isinstance(val, list):
        print(f"  FAIL — tags value is not a list: {val!r}")
        return False
    leaked = [t for t in val
              if t.endswith("-dom0") or t.startswith(("created-by-", "guivm-", "audiovm-"))]
    if leaked:
        print(f"  FAIL — tags leaked operator/auto vocabulary: {leaked}")
        return False
    if "ai-managed" not in val:
        print(f"  WARN — 'ai-managed' absent from a listed ai-managed qube: {val}")
    print(f"  PASS — tags = {val} (qmcp vocabulary only, no crash).")
    return True


def test_4_label_preserved() -> bool:
    header("4. GetPropertyAIManaged — label still returns its colour")
    names, _ = ai_managed()
    if not names:
        print("  PASS — vacuously (no qubes).")
        return True
    q = names[0]
    r = getprop(q, "label")
    show(f"label of {q}", r)
    if not r.get("ok"):
        print(f"  FAIL — label read not ok: {r}")
        return False
    v = r["value"]
    if v == SENTINEL:
        print("  FAIL — redactor ate the label (returned sentinel)")
        return False
    if not (isinstance(v, str) and v):
        print(f"  FAIL — label not a colour string: {v!r}")
        return False
    if v not in COLOURS:
        print(f"  WARN — label '{v}' not in the known colour set (still not redacted).")
    print(f"  PASS — label = '{v}' (not redacted).")
    return True


def test_5_existence_hiding() -> bool:
    header("5. Existence-hiding baseline — dom0 + nonexistent → opaque not found")
    nonexistent = "qmcp-i1-no-such-qube-zzz"
    r_dom0 = getprop("dom0", "netvm")
    r_ghost = getprop(nonexistent, "netvm")
    show("dom0.netvm", r_dom0)
    show(f"{nonexistent}.netvm", r_ghost)
    if r_dom0 != NOT_FOUND:
        print(f"  FAIL — dom0 not opaque not-found: {r_dom0}")
        return False
    if r_ghost != NOT_FOUND:
        print(f"  FAIL — nonexistent not opaque not-found: {r_ghost}")
        return False
    if r_dom0 != r_ghost:
        print("  FAIL — dom0 and nonexistent not byte-identical")
        return False
    print("  PASS — both opaque + byte-identical.")
    return True


# ====================================================================
def main() -> int:
    tests = [
        test_1_list_template,
        test_2_getprop_vm_valued,
        test_3_tags_deliberate,
        test_4_label_preserved,
        test_5_existence_hiding,
    ]
    results = []
    for t in tests:
        try:
            results.append((t.__name__, t()))
        except Exception as e:
            print(f"  EXCEPTION in {t.__name__}: {e}")
            results.append((t.__name__, False))

    header("Summary")
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{passed}/{len(results)} tests green.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
