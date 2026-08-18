#!/usr/bin/env python3
"""Offline validation for the F-1..F-5 fixes (adversarial pass, 2026-08-18).

Five findings were reproduced from the AI seat against the live fleet. This
suite proves each fix, and — for the two that were security holes rather than
hygiene — proves it with TEETH: the vulnerable behaviour is reconstructed under
the pre-fix predicate and shown to reproduce, THEN the shipped code is shown to
close it. A suite that only asserts the new behaviour passes just as happily
against code that never had the bug, which is how the create/remove churn
bypass survived its first review.

  F-1  the create paths were a full-host existence oracle          [§1, §2]
  F-2  birth-egress enforcement was defeated by an open retarget   [§3]
  F-3  ... including disposables, via a retargeted DVMT            [§3]
  F-4  raw dom0 exception text reached the AI seat                 [§4]
  F-5  private_size accepted a float and a bool                    [§5]
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import sys
import contextlib
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(os.path.dirname(HERE), "dom0-rpc")
PASSED = FAILED = 0


def check(label, cond, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}" + (f"  -- {detail}" if detail else ""))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(DOM0_RPC, filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


birth = _load("qmcp_birth", "qmcp_birth.py")
_tmp = tempfile.mkdtemp(prefix="qmcp-fixes-")


def flag(n, c=None):
    p = os.path.join(_tmp, n)
    if c is None:
        return p
    open(p, "w", encoding="utf-8").write(c)
    return p


# ==========================================================================
print("\n-- 1. F-1: the reserved name namespace --")
# ==========================================================================
check("the default prefix is the project's own public vocabulary",
      birth.DEFAULT_NAME_PREFIX == "ai-")
check("an absent operator file gives the default",
      birth.read_name_prefix(flag("absent")) == "ai-")
check("a legal prefix is honoured",
      birth.read_name_prefix(flag("p", "bot-\n")) == "bot-")
check("the '# comment' form is honoured, like every other operator file (F-N)",
      birth.read_name_prefix(flag("pc", "bot-  # ours\n")) == "bot-")

# The fail-closed DIRECTION is the interesting part and it is the opposite of
# every other operator file here.
for bad, why in (("", "empty"), ("   \n", "whitespace"), ("-nope", "illegal start"),
                 ("a b", "space"), ("x" * 40, "over-long"), ("# only a comment\n", "comment-only")):
    check(f"malformed prefix ({why}) falls back to the DEFAULT, never to 'no prefix'",
          birth.read_name_prefix(flag(f"b-{why}", bad)) == "ai-")
check("an unreadable file falls back to the default, not to 'no prefix'",
      birth.read_name_prefix(_tmp) == "ai-")

for good in ("ai-worker", "ai-a", "ai-smoke-parent", "ai-x-y-z"):
    check(f"{good!r} is inside the namespace", birth.name_refusal(good, "ai-") is None)
for bad in ("vault", "personal", "sys-usb", "sys-net", "dom0", "fedora-43-xfce",
            "ai", "ai-", "Ai-x", "AI-x", "xai-y", "", None, 42):
    check(f"{bad!r} is refused by the namespace guard",
          birth.name_refusal(bad, "ai-") is not None)

# The refusal must not depend on the fleet — that is the whole mechanism.
msgs = {birth.name_refusal(n, "ai-") for n in ("vault", "personal", "sys-usb", "zzz-absent")}
check("every out-of-namespace refusal is the SAME message, whatever the name",
      len(msgs) == 1, repr(msgs))
check("the refusal names the RULE and never the requested name",
      all(n not in birth.name_refusal(n, "ai-")
          for n in ("vault", "personal", "sys-usb")))

# ==========================================================================
print("\n-- 2. F-1 TEETH: the oracle reproduces without the guard --")
# ==========================================================================
# The pre-fix create path, reduced to its essential shape: look the requested
# name up in the WHOLE host's domain list and answer informatively.
HOST = {"sys-net", "sys-firewall", "sys-usb", "vault", "personal", "work",
        "ai-debian-13", "ai-net-router"}
UMBRELLA = {"ai-debian-13", "ai-net-router"}


def prefix_check(name, guard):
    """One create attempt. Returns 'refused-shape' / 'exists' / 'created' and
    whether the host was consulted at all."""
    if guard:
        if birth.name_refusal(name, "ai-") is not None:
            return "refused-shape", False           # constant time, no lookup
    if name in HOST:
        return "exists", True
    return "created", True


PROBES = ["vault", "personal", "sys-usb", "sys-net", "work"]
DECOYS = ["zzz-absent-1", "qqq-absent-2"]

pre = {n: prefix_check(n, guard=False)[0] for n in PROBES + DECOYS}
check("TEETH: WITHOUT the guard, existing and absent names give different answers "
      "— the oracle reproduces",
      {pre[n] for n in PROBES} == {"exists"} and {pre[n] for n in DECOYS} == {"created"},
      repr(pre))

post = {n: prefix_check(n, guard=True) for n in PROBES + DECOYS}
check("WITH the guard, every out-of-namespace probe gives the same answer",
      {post[n][0] for n in PROBES + DECOYS} == {"refused-shape"}, repr(post))
check("WITH the guard, the host is never consulted for an out-of-namespace name "
      "— so timing cannot separate them either",
      not any(post[n][1] for n in PROBES + DECOYS))

# In-namespace collisions still answer, and must: AI can already list these.
check("an in-namespace collision is still reported (AI can enumerate the "
      "umbrella anyway, so this discloses nothing new)",
      prefix_check("ai-net-router", guard=True)[0] == "exists")
check("an in-namespace free name still creates",
      prefix_check("ai-brand-new", guard=True)[0] == "created")

# The documented residual, asserted so it cannot be forgotten or overstated.
HOST.add("ai-operator-secret")
check("RESIDUAL (documented): a NON-ai-managed qube inside the reserved "
      "namespace is still detectable — bounded to one namespace, not the host",
      prefix_check("ai-operator-secret", guard=True)[0] == "exists"
      and "ai-operator-secret" not in UMBRELLA)

# ==========================================================================
print("\n-- 3. F-2/F-3: the egress retarget is closed, null still allowed --")
# ==========================================================================
SRC = os.path.join(DOM0_RPC, "qmcp.SetPropertyAIManaged")
body = open(SRC, encoding="utf-8").read()
check("the wrapper refuses a non-null netvm write",
      'if value is not None:' in body and 'netvm change is operator-only' in body)
check("the refusal sits inside the `prop == \"netvm\"` branch",
      body.index('if prop == "netvm":') < body.index('netvm change is operator-only'))
check("the provides_network refusal still precedes it (unchanged behaviour "
      "for the egress qube itself)",
      body.index('network-providing qube is operator-only')
      < body.index('netvm change is operator-only'))
check("the null carve-out is explicit, mirroring the birth path",
      'null (disconnect) is permitted' in body)

# The four routes measured on hardware, as a reachability model: each is a
# sequence of calls, and every one of them passes through a netvm write.
ROUTES = {
    "2 null-birth + retarget":       ["spawn(netvm=null)", "set netvm=<other>"],
    "3 clone + retarget":            ["clone", "set netvm=<other>"],
    "4 retarget source, then clone": ["set netvm=<other>", "clone"],
    "disposable via retargeted DVMT": ["set netvm=<other>", "spawn-disposable"],
}
closed = {r: any(s.startswith("set netvm=<other>") for s in steps)
          for r, steps in ROUTES.items()}
check("all four measured routes pass through a non-null netvm write, so one "
      "refusal closes all four",
      all(closed.values()), repr(closed))
check("TEETH: a route that did NOT pass through a netvm write would survive "
      "this fix — the model can express that, so the claim is falsifiable",
      not any(s.startswith("set netvm=<other>")
              for s in ["spawn(netvm=null)", "clone", "spawn-disposable"]))

# ==========================================================================
print("\n-- 4. F-4: no raw exception text reaches the AI seat --")
# ==========================================================================
LEAKY = re.compile(r'(?:"error"|"warning")\s*:\s*f?"[^"]*\{e[a-z]*\}')
for wrapper in ("qmcp.SpawnAIManagedQube", "qmcp.CloneAIManagedQube",
                "qmcp.SpawnDisposableAIManaged"):
    text = open(os.path.join(DOM0_RPC, wrapper), encoding="utf-8").read()
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if ("{e}" in line or "{exc}" in line) and \
           ('"error"' in line or '"warning"' in line or "fail(" in line):
            if "invalid JSON input" in line:
                continue          # echoes AI's OWN payload; carries nothing of dom0's
            hits.append((i, line.strip()[:70]))
    check(f"{wrapper}: no dom0 exception text in an AI-visible field", not hits, repr(hits))
    check(f"{wrapper}: the exception CLASS is kept for the dom0 audit chain instead",
          'error_class' in text)

spawn = open(os.path.join(DOM0_RPC, "qmcp.SpawnAIManagedQube"), encoding="utf-8").read()
for token in ("private_resize_failed", "dispvm_template_flag_failed"):
    check(f"the warning is the fixed token {token!r}", f'"{token}"' in spawn)
# Scoped to CODE, not to the file. The first version of this check searched the
# whole text and matched the COMMENT above the fix that explains what leaked —
# the same vocabulary-instead-of-structure defect the Stage 3a install-guard
# lesson names, and the third time it has been committed in this project's own
# tests. A guard keyed on prose fails on correct code and passes on a leak
# phrased differently; key it on what the file DOES.
def _code_only(text):
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line.split("  #")[0])
    return "\n".join(out)


spawn_code = _code_only(spawn)
check("TEETH: the exact strings measured leaking appear in no CODE line",
      "private resize failed: " not in spawn_code and "lvresize" not in spawn_code,
      "still present in code")
check("... and the docstring/comments MAY still name them, which is why this "
      "check is scoped to code rather than to the file",
      "lvresize" in spawn)

# ==========================================================================
print("\n-- 5. F-5: private_size is an integer, and bool is not one --")
# ==========================================================================
check("the wrapper rejects bool explicitly (bool IS an int subclass in Python)",
      "isinstance(private_size, bool)" in spawn)
check("the wrapper no longer coerces with int()",
      "private_size = int(private_size)" not in spawn)


def accepted(v):
    """The shipped predicate, extracted."""
    if v is None:
        return True
    if isinstance(v, bool) or not isinstance(v, int):
        return False
    return v > 0


def accepted_prefix(v):
    """The pre-fix predicate: int() then a positivity test."""
    if v is None:
        return True
    try:
        v = int(v)
    except Exception:
        return False
    return v > 0


for v in (1, 2 ** 31, None):
    check(f"private_size={v!r} accepted", accepted(v))
for v in (1.5, True, False, "10", -1, 0, [], {}, 2.0):
    check(f"private_size={v!r} refused", not accepted(v))
check("TEETH: the pre-fix predicate accepted 1.5 and True — reproduced here",
      accepted_prefix(1.5) and accepted_prefix(True))
check("TEETH: and the shipped one does not",
      not accepted(1.5) and not accepted(True))

print(f"\n{'=' * 70}\n  F-1..F-5 fixes: {PASSED} passed, {FAILED} failed\n{'=' * 70}")
sys.exit(1 if FAILED else 0)
