#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 3b — the enforcement flag + the §6 gate.

Runs on mcp-control with no dom0 and no qubesadmin. Stage 3b ships INERT: it
adds `dom0-rpc/qmcp_enforce.py`, which nothing sources yet, and
`deploy/smoke-production.py`, which is a test. No wrapper, no policy file and
no template RPC moves, so behaviour-neutrality holds **by construction** and is
shown by an empty

    git diff --stat -- 'dom0-rpc/qmcp.*' 'policy/' 'template-rpc/'

rather than by a state-changing hardware regression (the I-3 pattern — the
empty diff is the most honest evidence available, and it is free).

That leaves this file carrying the stage's entire risk surface, which is pure
logic: one operator-file parse, one total function over (mode, bool, verdict),
and the smoke suite's exit-status mapping.

**§5 is the teeth, and it is the reason the stage looks the way it does.**
Every previous flip in this project was monotone — `tier-default` only ever
removed authority — so a corrupt flag could fail closed to least privilege and
a two-valued flag was enough. The enforcement flip is NOT monotone: it narrows
the escalation class and simultaneously WIDENS lifecycle, because invariant 1
(anti-theatre) says a `CAP_EXEC` actor that can already `rm -rf` inside a qube
gains nothing from a `CAP_FULL` gate on `remove`. §5 composes the REAL
`qmcp_caps.decide()` with `effective_verdict` and asserts both directions on
the same fleet, then asserts that a malformed flag lands in the one mode that
takes the narrowing without the widening. Without those checks the three-mode
design is an assertion in a docstring; with them it is a measurement.
"""
from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(os.path.dirname(HERE), "dom0-rpc")

PASSED = 0
FAILED = 0


def _load(modname, path):
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


enf = _load("qmcp_enforce", os.path.join(DOM0_RPC, "qmcp_enforce.py"))
caps = _load("qmcp_caps", os.path.join(DOM0_RPC, "qmcp_caps.py"))
tier = _load("qmcp_tier", os.path.join(DOM0_RPC, "qmcp_tier.py"))
smoke = _load("smoke_production", os.path.join(HERE, "smoke-production.py"))


def check(label, cond, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}" + (f"  -- {detail}" if detail else ""))


_tmp = tempfile.mkdtemp(prefix="qmcp-3b-validate-")


def flag(name, content=None, mode=0o644):
    """An operator flag file. `content=None` means "do not create it"."""
    path = os.path.join(_tmp, name)
    if content is None:
        return path
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, mode)
    return path


class FakeVM:
    """Minimal qubesadmin VM stand-in — name and tags are all the kernel reads."""

    def __init__(self, name, tags=()):
        self.name = name
        self.tags = set(tags)


UMB = tier.UMBRELLA
VM_EXEC = FakeVM("worker", (UMB, tier.TAG_EXEC))
VM_FULL = FakeVM("admin-ish", (UMB, tier.TAG_FULL))

FLAG_RO = flag("tier-default-ro", "ro\n")
NO_GUARDED = flag("guarded-absent")


def kernel(service, action="", targets=None, params=None):
    return caps.decide("mcp-control", service, action, targets or {},
                       params or {}, tier_default_path=FLAG_RO,
                       guarded_list_path=NO_GUARDED)


# --------------------------------------------------------------------------
print("\n-- 1. structure and the vocabulary drift guard --")
# --------------------------------------------------------------------------
check("MODES is exactly (shadow, strict, enforce)",
      enf.MODES == (enf.SHADOW, enf.STRICT, enf.ENFORCE), repr(enf.MODES))
check("the three mode labels are distinct",
      len(set(enf.MODES)) == 3)
check("MODE_PATH is under /etc/qmcp, like every other operator flag",
      enf.MODE_PATH.startswith("/etc/qmcp/"), enf.MODE_PATH)
check("MODE_PATH is not a path any other operator flag already owns",
      enf.MODE_PATH not in {tier.TIER_DEFAULT_PATH, caps.GUARDED_LIST_PATH},
      enf.MODE_PATH)

# The 3a lesson applied to a vocabulary rather than a prefix: two modules hold
# the same three literals, and a rename in one that missed the other would make
# every comparison silently false — i.e. every kernel verdict would read as
# unrecognised and collapse to DENY, which fails safe but bricks the fleet.
for name in ("ALLOW", "DENY", "GATE"):
    check(f"qmcp_enforce.{name} is byte-identical to qmcp_caps.{name}",
          getattr(enf, name) == getattr(caps, name),
          f"{getattr(enf, name)!r} != {getattr(caps, name)!r}")

check("every verdict qmcp_caps can return is ranked by qmcp_enforce",
      {caps.ALLOW, caps.DENY, caps.GATE} <= set(enf._SEVERITY))
check("the severity order is ALLOW < GATE < DENY",
      enf._SEVERITY[enf.ALLOW] < enf._SEVERITY[enf.GATE] < enf._SEVERITY[enf.DENY])


# --------------------------------------------------------------------------
print("\n-- 2. read_mode: every input the operator can produce --")
# --------------------------------------------------------------------------
check("absent file -> shadow (the shipped default; this is what makes 3b inert)",
      enf.read_mode(flag("absent")) == enf.SHADOW)
for word in enf.MODES:
    check(f"{word!r} -> {word}", enf.read_mode(flag(f"mode.{word}", word + "\n")) == word)
check("leading/trailing whitespace tolerated",
      enf.read_mode(flag("mode.whitespace", "  enforce  \n")) == enf.ENFORCE)
check("uppercase tolerated",
      enf.read_mode(flag("mode.uppercase", "ENFORCE\n")) == enf.ENFORCE)
# F-N: one operator file honoured the `# comment` form and another did not.
check("trailing '# comment' stripped (F-N: every operator file parses alike)",
      enf.read_mode(flag("mode.comment", "enforce   # armed 2026-08-18\n")) == enf.ENFORCE)
check("a whole-line comment leaves nothing -> strict, not shadow",
      enf.read_mode(flag("mode.comment.only", "# not yet\n")) == enf.STRICT)

for bad, label in ((" ", "empty"), ("enforced\n", "near-miss typo"),
                   ("full\n", "a value from a DIFFERENT operator flag"),
                   ("1\n", "numeric"), ("enforce strict\n", "two words")):
    check(f"malformed ({label}) -> strict, NEVER enforce",
          enf.read_mode(flag(f"mode.bad.{label[:6]}", bad)) == enf.STRICT)

unreadable = flag("mode.unreadable", "enforce\n", mode=0o000)
if os.geteuid() == 0:
    print("SKIP  the 0600 trap — running as root, which can read anything")
else:
    check("present but unreadable (the root:0600 trap) -> strict",
          enf.read_mode(unreadable) == enf.STRICT)
check("a directory in place of the file -> strict, not a crash",
      enf.read_mode(_tmp) == enf.STRICT)


# --------------------------------------------------------------------------
print("\n-- 3. effective_verdict: total, and correct per mode --")
# --------------------------------------------------------------------------
GARBAGE = ("", "ALLOW", "permit", None, 0, "gate ")
ALL_MODES = list(enf.MODES) + list(GARBAGE)
ALL_VERDICTS = [enf.ALLOW, enf.DENY, enf.GATE] + list(GARBAGE)

total_ok = True
for m in ALL_MODES:
    for w in (True, False):
        for k in ALL_VERDICTS:
            try:
                out = enf.effective_verdict(m, w, k)
            except Exception as exc:
                total_ok = False
                print(f"      raised on ({m!r},{w},{k!r}): {exc!r}")
                continue
            if out not in (enf.ALLOW, enf.DENY, enf.GATE):
                total_ok = False
                print(f"      returned {out!r} for ({m!r},{w},{k!r})")
check(f"total over {len(ALL_MODES)}x2x{len(ALL_VERDICTS)} inputs: never raises, "
      f"always a known verdict", total_ok)

check("unknown mode is treated as strict (same landing as a malformed file)",
      all(enf.effective_verdict(g, w, k) == enf.effective_verdict(enf.STRICT, w, k)
          for g in GARBAGE for w in (True, False) for k in ALL_VERDICTS))
check("an unreadable kernel verdict counts as deny, never as allow",
      all(enf.effective_verdict(enf.ENFORCE, True, g) == enf.DENY for g in GARBAGE))

# shadow
check("shadow: wrapper allow + kernel deny -> allow",
      enf.effective_verdict(enf.SHADOW, True, enf.DENY) == enf.ALLOW)
check("shadow: wrapper deny + kernel allow -> deny",
      enf.effective_verdict(enf.SHADOW, False, enf.ALLOW) == enf.DENY)
# strict
check("strict: wrapper allow + kernel deny -> deny (the narrowing arms)",
      enf.effective_verdict(enf.STRICT, True, enf.DENY) == enf.DENY)
check("strict: wrapper deny + kernel allow -> deny (the widening does NOT)",
      enf.effective_verdict(enf.STRICT, False, enf.ALLOW) == enf.DENY)
check("strict: both allow -> allow",
      enf.effective_verdict(enf.STRICT, True, enf.ALLOW) == enf.ALLOW)
check("strict: wrapper allow + kernel gate -> gate, not deny "
      "(the I-6 consent channel is not thrown away)",
      enf.effective_verdict(enf.STRICT, True, enf.GATE) == enf.GATE)
# enforce
check("enforce: the kernel's verdict verbatim, including gate",
      all(enf.effective_verdict(enf.ENFORCE, w, k) == k
          for w in (True, False) for k in (enf.ALLOW, enf.DENY, enf.GATE)))

check("is_enforcing is false only for shadow",
      (not enf.is_enforcing(enf.SHADOW)
       and enf.is_enforcing(enf.STRICT) and enf.is_enforcing(enf.ENFORCE)))


# --------------------------------------------------------------------------
print("\n-- 4. INVARIANCE: under shadow the kernel cannot change anything --")
# --------------------------------------------------------------------------
# This is Stage 3b's behaviour-neutrality proof, and it is stronger than a
# measurement: under the shipped default the kernel's verdict is not merely
# ignored in practice, it is mathematically absent from the result.
check("shadow: the result is a function of the wrapper alone, for EVERY kernel verdict",
      all(enf.effective_verdict(enf.SHADOW, w, k) == (enf.ALLOW if w else enf.DENY)
          for w in (True, False) for k in ALL_VERDICTS))
check("an absent flag resolves to shadow, so an unconfigured fleet is unchanged",
      enf.effective_verdict(enf.read_mode(flag("still-absent")), True, enf.DENY) == enf.ALLOW)


# --------------------------------------------------------------------------
print("\n-- 5. TEETH: the flip is bidirectional, against the REAL kernel --")
# --------------------------------------------------------------------------
# Composed with qmcp_caps.decide() rather than with hand-written verdicts, so
# these assertions track the lattice as it changes instead of a snapshot of it.

# (a) The WIDENING. Invariant 1: remove is dominated by CAP_EXEC, so the kernel
#     allows what the I-5 wrapper (CAP_FULL) refuses.
widen = kernel("qmcp.LifecycleAIManaged", "remove", {"target": VM_EXEC})
check("kernel ALLOWs remove on an ai-exec qube (dominated) — the widening exists",
      widen.verdict == caps.ALLOW and widen.rule.startswith("dominated:"),
      f"{widen.verdict}/{widen.rule}")
check("  shadow keeps the wrapper's refusal (today's behaviour)",
      enf.effective_verdict(enf.SHADOW, False, widen.verdict) == enf.DENY)
check("  strict keeps the refusal too — a corrupt flag cannot arm destruction",
      enf.effective_verdict(enf.STRICT, False, widen.verdict) == enf.DENY)
check("  enforce ALLOWs it — this is the widening Stage 3a's tombstone exists for",
      enf.effective_verdict(enf.ENFORCE, False, widen.verdict) == enf.ALLOW)

# (b) The NARROWING. The escalation class: netvm is operator-only at every
#     tier, while today's wrapper allows the write. Stage 1 measured exactly
#     this divergence on hardware.
narrow = kernel("qmcp.SetPropertyAIManaged", "set", {"target": VM_FULL},
                {"property": "netvm"})
check("kernel DENIEs a netvm write even on ai-full (escalation class) — the narrowing",
      narrow.verdict == caps.DENY and narrow.rule == "escalation-class",
      f"{narrow.verdict}/{narrow.rule}")
check("  shadow lets the write through (today's behaviour)",
      enf.effective_verdict(enf.SHADOW, True, narrow.verdict) == enf.ALLOW)
check("  strict refuses it — the narrowing arms WITHOUT the widening",
      enf.effective_verdict(enf.STRICT, True, narrow.verdict) == enf.DENY)
check("  enforce refuses it too",
      enf.effective_verdict(enf.ENFORCE, True, narrow.verdict) == enf.DENY)

# (c) The claim the three-mode design rests on, stated as one assertion: no
#     single mode is uniformly safest, so "fail closed" cannot mean a mode
#     that widens.
shadow_set = {enf.effective_verdict(enf.SHADOW, False, widen.verdict),
              enf.effective_verdict(enf.SHADOW, True, narrow.verdict)}
enforce_set = {enf.effective_verdict(enf.ENFORCE, False, widen.verdict),
               enf.effective_verdict(enf.ENFORCE, True, narrow.verdict)}
check("neither shadow nor enforce is uniformly more restrictive than the other",
      enf.ALLOW in shadow_set and enf.ALLOW in enforce_set,
      f"shadow={shadow_set} enforce={enforce_set}")
check("strict allows NEITHER case — it is the unique fail-closed landing",
      enf.effective_verdict(enf.STRICT, False, widen.verdict) == enf.DENY
      and enf.effective_verdict(enf.STRICT, True, narrow.verdict) == enf.DENY)

# (d) The bug a two-mode flag would have shipped, reproduced. This is the
#     pre-fix behaviour asserted directly: had malformed fallen through to
#     enforce (the obvious reading of "fail closed"), a typo in the operator's
#     file would hand every ai-exec actor irreversible qube destruction.
typo = enf.read_mode(flag("mode.typo", "enforece\n"))
check("TEETH: a typo'd flag under a two-mode 'fail closed to enforce' rule "
      "WOULD have armed the widening",
      enf.effective_verdict(enf.ENFORCE, False, widen.verdict) == enf.ALLOW)
check("TEETH: the shipped rule lands that same typo in strict, which refuses it",
      typo == enf.STRICT
      and enf.effective_verdict(typo, False, widen.verdict) == enf.DENY)


# --------------------------------------------------------------------------
print("\n-- 5b. which surfaces this flag can actually govern --")
# --------------------------------------------------------------------------
# The "no policy backstop" argument is only sound for the surfaces a WRAPPER
# decides. It was first written as a blanket claim over the whole lattice and
# that claim is false — six SERVICE_TABLE entries are @tag:-scoped and settled
# by the qrexec engine before any code of ours runs, so this module cannot
# govern them. It does not need to: I-4, I-5 and G0c graduated each of those
# with its own COMPAT backstop, and those flips are done.
#
# Pinning the partition here so the claim cannot rot. If a future stage moves a
# service between the two halves, this fails and the docs get corrected with the
# code rather than months later.
policy_lines = [l.split() for l in open(os.path.join(os.path.dirname(HERE),
                "policy", "30-mcp-control.policy"))
                if l.strip() and not l.lstrip().startswith("#")]
targets = {}
for f in policy_lines:
    if len(f) >= 4:
        targets.setdefault(f[0], set()).add(f[3])

WRAPPER_DECIDED = {
    "qmcp.AIManagedEvents", "qmcp.AttachDeviceAIManaged", "qmcp.CloneAIManagedQube",
    "qmcp.DetachDeviceAIManaged", "qmcp.GetPoolStats", "qmcp.GetPropertyAIManaged",
    "qmcp.LifecycleAIManaged", "qmcp.ListAIManagedQubes",
    "qmcp.ListAttachedDevicesAIManaged", "qmcp.SetFeatureAIManaged",
    "qmcp.SetPropertyAIManaged", "qmcp.SpawnAIManagedQube",
    "qmcp.SpawnDisposableAIManaged",
}
POLICY_DECIDED = {
    "qmcp.RunInAIManaged", "qmcp.CopyToAIManaged", "qubes.Filecopy",
    "admin.vm.firewall.Get", "admin.vm.firewall.Set", "admin.vm.firewall.Reload",
}

check("the two halves partition SERVICE_TABLE exactly, with no service missed",
      WRAPPER_DECIDED | POLICY_DECIDED == set(caps.SERVICE_TABLE),
      f"symmetric difference: "
      f"{(WRAPPER_DECIDED | POLICY_DECIDED) ^ set(caps.SERVICE_TABLE)}")
check("the two halves do not overlap", not (WRAPPER_DECIDED & POLICY_DECIDED))
check(f"all {len(WRAPPER_DECIDED)} wrapper-decided surfaces are @adminvm-scoped, "
      f"never @tag: — this is what makes a backstop unnecessary",
      all(targets.get(s) == {"@adminvm"} for s in WRAPPER_DECIDED),
      repr({s: targets.get(s) for s in sorted(WRAPPER_DECIDED)
            if targets.get(s) != {"@adminvm"}}))
check(f"all {len(POLICY_DECIDED)} policy-decided surfaces carry at least one "
      f"@tag: line — the flag cannot govern them",
      all(any(t.startswith("@tag:") for t in targets.get(s, ()))
          for s in POLICY_DECIDED),
      repr({s: targets.get(s) for s in sorted(POLICY_DECIDED)}))
check("every escalation service is already denied at the policy layer, so the "
      "flip has nothing to move there",
      all(any(f[0] == s and f[-1] == "deny" for f in policy_lines)
          for s in caps.ESCALATION_SERVICES),
      repr(sorted(caps.ESCALATION_SERVICES)))
check("every DOMINATION entry names a wrapper-decided surface — the widening "
      "the flag arms is one it can actually reach",
      all(svc in WRAPPER_DECIDED for svc, _ in caps.DOMINATION),
      repr([svc for svc, _ in caps.DOMINATION if svc not in WRAPPER_DECIDED]))


# --------------------------------------------------------------------------
print("\n-- 6. the §6 smoke suite: the exit status IS the gate --")
# --------------------------------------------------------------------------
P, F, V, N = smoke.PASS, smoke.FAIL, smoke.VACUOUS, smoke.NOT_RUN


def res(*outcomes):
    return [(i + 1, f"item {i + 1}", o, "") for i, o in enumerate(outcomes)]


check("all seven PASS -> 0 (GREEN)", smoke.verdict(res(*([P] * 7)))[0] == 0)
check("one FAIL -> 2", smoke.verdict(res(P, P, P, F, P, P, P))[0] == 2)
check("FAIL outranks NOT-RUN", smoke.verdict(res(N, N, F, P, P, P, P))[0] == 2)
# The whole reason this suite has four outcomes and not two.
check("a NOT-RUN item -> 3 (INCOMPLETE), never 0",
      smoke.verdict(res(P, N, N, P, P, P, P))[0] == 3)
check("a VACUOUS item -> 3 (INCOMPLETE), never 0",
      smoke.verdict(res(P, P, P, P, P, P, V))[0] == 3)
check("the realistic run — items 2/3 undeclared, item 7 single-egress -> 3",
      smoke.verdict(res(P, N, N, P, P, P, V))[0] == 3)
check("no items recorded at all -> 3, never 0 (a crashed run is not green)",
      smoke.verdict([])[0] == 3)
check("only PASS counts toward green", smoke._GREEN == {P})
check("the four outcome labels are distinct", len({P, F, V, N}) == 4)

for code, needle in ((0, "GREEN"), (2, "FAILED"), (3, "INCOMPLETE")):
    sample = {0: res(P), 2: res(F), 3: res(V)}[code]
    got_code, line = smoke.verdict(sample)
    check(f"exit {code} is reported as {needle}", got_code == code and needle in line, line)

check("the GREEN line names Stage 3c, so the operator knows what it unlocks",
      "3c" in smoke.verdict(res(P))[1])
check("the INCOMPLETE line says it is NOT green",
      "NOT green" in smoke.verdict(res(V))[1])


# --------------------------------------------------------------------------
print("\n-- 7. the external-check contract (items 2 and 3) --")
# --------------------------------------------------------------------------
conf = flag("ext.conf",
            "# operator-local paths live here, not in the repo\n"
            "\n"
            "item2 = /opt/example/roundtrip --selftest\n"
            "item3=/opt/example/driftcheck --check   # trailing note\n"
            "garbage line with no equals\n")
cmds = smoke._load_external(conf)
check("item2 command parsed", cmds.get("item2", "").endswith("--selftest"), repr(cmds))
check("item3 parsed without spaces around '='",
      cmds.get("item3", "").startswith("/opt"), repr(cmds))
check("a trailing '# comment' is stripped from the command",
      "#" not in cmds.get("item3", ""), repr(cmds.get("item3")))
check("blank and unparseable lines ignored, not crashed on", len(cmds) == 2, repr(cmds))
check("a missing conf file is {} — not an error, and not a pass",
      smoke._load_external(os.path.join(_tmp, "no-such.conf")) == {})
check("a directory in place of the conf file is {}, not a crash",
      smoke._load_external(_tmp) == {})

# Items 2 and 3 must not be quietly satisfiable from inside this repo: a suite
# that ships its own copy of the tooling it smoke-tests, tests the copy. The
# property is that the suite has NO built-in command for them — an undeclared
# item is NOT-RUN and nothing in the tree can turn it green by itself.
repo_root = os.path.dirname(HERE)
for n in (2, 3):
    _t = f"externally declared item {n}"
    smoke.RESULTS.clear()
    smoke.external_item(n, _t, {}, "/nonexistent/conf")
    check(f"item {n} with nothing declared is NOT-RUN, not a pass",
          smoke.RESULTS and smoke.RESULTS[-1][2] == smoke.NOT_RUN,
          repr(smoke.RESULTS))
smoke.RESULTS.clear()
check("the suite carries no default command for the external items — "
      "the tooling they assert is deployment-specific and is not vendored here",
      not any(k in smoke._load_external("/nonexistent/conf") for k in ("item2", "item3")))
check("the default conf path is outside the repo tree",
      not os.path.expanduser(smoke.DEFAULT_EXTERNAL_CONF).startswith(repo_root + os.sep),
      smoke.DEFAULT_EXTERNAL_CONF)

# item 1's baseline — the file that turns "exec works everywhere" (false on any
# fleet with a non-qmcp egress template) into "the flip broke nothing".
bpath = os.path.join(_tmp, "baseline.json")
check("a missing baseline is None, so the first run measures instead of asserting",
      smoke._read_baseline(bpath) is None)
smoke._write_baseline(bpath, ["b", "a"])
check("the baseline round-trips, sorted", smoke._read_baseline(bpath) == ["a", "b"])
for junk in ("not json", "{}", '{"exec_set": "a"}', '{"exec_set": null}', "[]"):
    jp = flag("bad-baseline-%d" % len(junk), junk)
    check(f"a malformed baseline ({junk[:18]!r}) is None, not a crash and not a pass",
          smoke._read_baseline(jp) is None)
check("a directory in place of the baseline is None",
      smoke._read_baseline(_tmp) is None)
check("an unwritable baseline path does not raise — a measurement run must not crash",
      smoke._write_baseline(os.path.join(_tmp, "baseline.json", "nested"), ["x"]) is None)
check("the default baseline path is outside the repo tree",
      not os.path.expanduser(smoke.DEFAULT_BASELINE).startswith(repo_root + os.sep),
      smoke.DEFAULT_BASELINE)

check("fixture names share one prefix, so a leftover is greppable and reapable",
      all(n.startswith(smoke.FIXTURE_PREFIX) for n in smoke.FIXTURES))
check("the consent floor the 'no dialog' check leans on matches qmcp_consent",
      smoke.CONSENT_MIN_TIMEOUT == 5.0)


# --------------------------------------------------------------------------
print(f"\n{'=' * 68}\n  {PASSED} passed, {FAILED} failed\n{'=' * 68}")
sys.exit(1 if FAILED else 0)
