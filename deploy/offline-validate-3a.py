#!/usr/bin/env python3
"""Offline validation for Wave 2 Stage 3a — tombstone + reaper + the pool charge.

Runs on mcp-control with no dom0 and no qubesadmin. Stage 3a's entire risk
surface is pure logic — a tag transition, one operator file, a veto matrix, and
a summation predicate — so **this is where all of its coverage lives**. There is
no AI-seat half to write: a tombstone is outside the umbrella by construction,
so `test-stage-*.py` cannot observe one at all, and the inability to is the
security property (the I-2 trust-boundary split; the I-5 slot-62 pattern is the
dom0 half).

**Which side proves what:**

  - HERE (offline)  — the transition and its ordering, the two-sided verify,
                      the reaper's veto matrix, the retention file's
                      fail-closed direction, and the pool-cap charge INCLUDING
                      teeth that reproduce the bypass the charge closes.
  - dom0 (Stage 3c) — that the flipped wrapper produces a real tombstone on
                      hardware and that the timer fires. Nothing here can prove
                      a systemd unit runs.

**§7 is why this stage is safe to ship ahead of the flip.** Stage 3a lands
before anything creates tombstones, so it must be behaviour-neutral on today's
fleet. §7 proves that by INVARIANCE rather than by regression: with no tombstone
present the new summation is byte-identical to the pre-change one, so
`qmcp.GetPoolStats` and every create gate answer exactly as before.

**§6 carries teeth, and they are the point of the stage.** The tombstone spec as
written in the brief and NEXT.md is self-contradictory: it drops the umbrella so
AI cannot see the qube, *and* requires the qube to keep counting against the
pool cap — but the cap summed over `"ai-managed" in tags`, so dropping the
umbrella made a tombstone free. §6.3 reimplements that pre-fix predicate and
asserts the create/remove churn bypass reproduces under it, then asserts the
shipped predicate closes it. A test that only checked the new behaviour would
pass just as happily against code that never had the bug — and would not have
caught the spec.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
DOM0_RPC = os.path.join(os.path.dirname(HERE), "dom0-rpc")

PASSED = 0
FAILED = 0


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(DOM0_RPC, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tier = _load("qmcp_tier", "qmcp_tier.py")
birth = _load("qmcp_birth", "qmcp_birth.py")
scope = _load("qmcp_scope", "qmcp_scope.py")
budget = _load("qmcp_budget", "qmcp_budget.py")
tomb = _load("qmcp_tombstone", "qmcp_tombstone.py")

UMB = tier.UMBRELLA
VOCAB = tier.QMCP_TIER_TAGS
GIB = 1024 ** 3


def check(label, cond, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}" + (f"  -- {detail}" if detail else ""))


def raises(fn):
    """True iff `fn()` raised. The transition's contract is 'raise, and the
    caller must treat that as the remove not having happened', so every refusal
    case below asserts the raise AND what state was left behind."""
    try:
        fn()
    except Exception:
        return True
    return False


TMP = tempfile.mkdtemp(prefix="qmcp-v3a-")
_seq = [0]


def retention_file(content):
    """Write an operator retention file. `None` returns a path that does not
    exist, which is the 'operator never configured this' case."""
    if content is None:
        return os.path.join(TMP, "definitely-absent")
    _seq[0] += 1
    path = os.path.join(TMP, f"ret-{_seq[0]}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class RecordingTagIO:
    """A TagIO over a plain set that records the op sequence.

    Faithful in the one way that matters: `add`/`remove` mutate the same set
    `read` returns, so a test cannot pass by reading a snapshot the writes never
    reached. `fail_on_remove` models a mid-transition crash so §3 can assert
    WHICH half-state is left behind — the entire justification for the
    add-before-remove ordering.
    """

    def __init__(self, tags, fail_on_remove=False):
        self.tags = set(tags)
        self.ops = []
        self.fail_on_remove = fail_on_remove

    def read(self):
        return set(self.tags)

    def add(self, tag):
        self.ops.append(("add", tag))
        self.tags.add(tag)

    def remove(self, tag):
        self.ops.append(("remove", tag))
        if self.fail_on_remove:
            raise RuntimeError("simulated qubesd failure mid-transition")
        self.tags.discard(tag)


class FakeVol:
    def __init__(self, size):
        self.size = size


class FakeVM:
    """Faithful enough for `persistent_bytes` AND for the reaper's own probes:
    tags, klass, volumes, name, and a power state. `power=None` models a qube
    whose state cannot be read, which the reaper must treat as running."""

    def __init__(self, name, tags, private=2 * GIB, klass="AppVM", root=0,
                 power="Halted"):
        self.name = name
        self.tags = set(tags)
        self.klass = klass
        self.volumes = {"private": FakeVol(private), "root": FakeVol(root)}
        self._power = power

    def get_power_state(self):
        if self._power is None:
            raise RuntimeError("power state unavailable")
        return self._power


class FakeApp:
    def __init__(self, vms):
        self.domains = list(vms)


def old_sum(app):
    """The PRE-Stage-3a summation, verbatim. Used for teeth and for invariance."""
    total = 0
    for vm in app.domains:
        try:
            tags = vm.tags
        except Exception:
            continue
        if "ai-managed" not in tags:
            continue
        total += budget.persistent_bytes(vm)
    return total


# =====================================================================
print("\n--- §1 the duplicated constants agree (anti-drift) ---")

check("1.1 budget and tombstone agree on the marker prefix",
      budget.TOMBSTONE_PREFIX == tomb.TOMBSTONE_PREFIX,
      f"{budget.TOMBSTONE_PREFIX!r} vs {tomb.TOMBSTONE_PREFIX!r}")
check("1.2 the marker lives in the reserved qmcp- namespace",
      tomb.TOMBSTONE_PREFIX.startswith(birth.NAMESPACE))
check("1.3 the marker uses the measured separator",
      tomb.TOMBSTONE_PREFIX.endswith(birth.SEP))
check("1.4 the marker is qubesd-legal (alnum, '-' and '_' only)",
      all(c.isalnum() or c in "-_" for c in tomb.tombstone_tag(1755500000)))

_SAMPLE = {"qmcp-guarded", "anon-vm", "qmcp-egress-locked_ai-net-alt",
           "qmcp-owner_mcp-control", UMB, tier.TAG_FULL, "created-by-dom0",
           "operator-label", tomb.tombstone_tag(1755500000)}
check("1.5 tombstone's restriction vocabulary matches qmcp_birth's exactly",
      tomb._restrictions(_SAMPLE) == birth.inherited_restrictions(_SAMPLE),
      f"{sorted(tomb._restrictions(_SAMPLE))} vs "
      f"{sorted(birth.inherited_restrictions(_SAMPLE))}")
check("1.6 the marker is CONTROLLED by both modules (so verify() asserts it)",
      tomb.controlled(tomb.tombstone_tag(1), VOCAB)
      and birth.controlled(tomb.tombstone_tag(1), VOCAB))
check("1.7 the marker is NOT a restriction (a clone must not inherit it)",
      not birth.is_restriction(tomb.tombstone_tag(1)))
check("1.8 the marker is invisible to AI (outside the scope vocabulary)",
      tomb.tombstone_tag(1) not in scope.QMCP_TAG_VOCABULARY
      and scope.scoped_tags({tomb.tombstone_tag(1), UMB}) == [UMB])

# =====================================================================
print("\n--- §2 marker parsing ---")

check("2.1 tombstone_tag round-trips through tombstone_epoch",
      tomb.tombstone_epoch({tomb.tombstone_tag(1755500000)}) == 1755500000)
check("2.2 is_tombstoned true on a marked qube",
      tomb.is_tombstoned({UMB, tomb.tombstone_tag(5)}))
check("2.3 is_tombstoned false on an unmarked qube",
      not tomb.is_tombstoned({UMB, tier.TAG_FULL}))
check("2.4 several markers -> the LATEST wins (destroys least)",
      tomb.tombstone_epoch({tomb.tombstone_tag(100),
                            tomb.tombstone_tag(900)}) == 900)
check("2.5 an undatable marker contributes nothing",
      tomb.tombstone_epoch({"qmcp-tombstone_notanumber"}) is None)
check("2.6 datable wins alongside undatable",
      tomb.tombstone_epoch({"qmcp-tombstone_xyz",
                            tomb.tombstone_tag(42)}) == 42)
check("2.7 undatable is still 'tombstoned' (so the reaper reports it)",
      tomb.is_tombstoned({"qmcp-tombstone_xyz"}))
check("2.8 no markers -> None",
      tomb.tombstone_epoch({UMB, "created-by-dom0"}) is None)
check("2.9 an unreadable tag set never raises",
      tomb.tombstone_epoch(None) is None and not tomb.is_tombstoned(None))

# =====================================================================
print("\n--- §3 the transition ---")

LIVE = {UMB, tier.TAG_FULL, "qmcp-owner_mcp-control", "qmcp-guarded",
        "qmcp-egress-locked_ai-net-alt", "anon-vm",
        "created-by-dom0", "operator-label"}
WHEN = 1755500000

io = RecordingTagIO(LIVE)
want = tomb.entomb(io, VOCAB, when=WHEN, umbrella=UMB, is_halted=lambda: True)
final = io.read()

check("3.1 the umbrella is gone", UMB not in final)
check("3.2 the tier tag is gone", tier.TAG_FULL not in final)
check("3.3 the owner tag is gone (a privilege tag)",
      not any(t.startswith(birth.OWNER_PREFIX) for t in final))
check("3.4 the marker is present", tomb.tombstone_tag(WHEN) in final)
check("3.5 restrictions survive (§3.2 / F-E)",
      {"qmcp-guarded", "qmcp-egress-locked_ai-net-alt", "anon-vm"} <= final)
check("3.6 uncontrolled tags are untouched",
      {"created-by-dom0", "operator-label"} <= final)
# `want` and "the controlled tags" are deliberately DIFFERENT sets, and
# conflating them is easy enough that the first draft of this check did.
# `anon-vm` is a platform restriction: `expected_tags` asserts it is still
# PRESENT after the transition (F-E — a restriction our own strip can remove is
# a laundering hole), but `controlled()` excludes it because we must never
# remove it and have no business policing its appearance. Same asymmetry as
# `qmcp_birth`. So the contract is three separate statements, not one equality.
check("3.7a want is exactly the marker plus the inherited restrictions",
      want == {tomb.tombstone_tag(WHEN)} | tomb._restrictions(LIVE))
check("3.7b every asserted tag survived the transition", want <= final)
check("3.7c no controlled tag outside want survived",
      {t for t in final if tomb.controlled(t, VOCAB)} <= want,
      f"stray={sorted({t for t in final if tomb.controlled(t, VOCAB)} - want)}")

_first_remove = min([i for i, (op, _) in enumerate(io.ops) if op == "remove"],
                    default=10 ** 6)
_last_add = max([i for i, (op, _) in enumerate(io.ops) if op == "add"],
                default=-1)
check("3.8 every add precedes every remove (the ordering invariant)",
      _last_add < _first_remove, f"ops={io.ops}")

io_unhalted = RecordingTagIO(LIVE)
check("3.9 an unhalted qube is refused",
      raises(lambda: tomb.entomb(io_unhalted, VOCAB, when=WHEN, umbrella=UMB,
                                 is_halted=lambda: False)))
check("3.10 a refused transition writes NOTHING",
      io_unhalted.ops == [] and io_unhalted.read() == LIVE)

io_raise = RecordingTagIO(LIVE)
check("3.11 a raising is_halted predicate is treated as 'not halted'",
      raises(lambda: tomb.entomb(io_raise, VOCAB, when=WHEN, umbrella=UMB,
                                 is_halted=lambda: 1 / 0))
      and io_raise.ops == [])

io_crash = RecordingTagIO(LIVE, fail_on_remove=True)
check("3.12 a crash mid-transition raises",
      raises(lambda: tomb.entomb(io_crash, VOCAB, when=WHEN, umbrella=UMB,
                                 is_halted=lambda: True)))
_crashed = io_crash.read()
check("3.13 ...and leaves the LOUD half-state: marker present, still visible",
      tomb.tombstone_tag(WHEN) in _crashed and UMB in _crashed,
      f"left={sorted(_crashed)}")
check("3.14 ...so it is still charged to the cap and still findable",
      budget.counts_toward_cap(_crashed))

io_retry = RecordingTagIO(_crashed)
tomb.entomb(io_retry, VOCAB, when=WHEN, umbrella=UMB, is_halted=lambda: True)
check("3.15 retrying after a crash converges (idempotent)",
      io_retry.read() == final, f"{sorted(io_retry.read())} vs {sorted(final)}")

io_reclock = RecordingTagIO(final)
tomb.entomb(io_reclock, VOCAB, when=WHEN + 500, umbrella=UMB,
            is_halted=lambda: True)
check("3.16 a retry at a new time REPLACES the marker (no double-marking)",
      tomb.tombstone_epoch(io_reclock.read()) == WHEN + 500
      and sum(1 for t in io_reclock.read() if tomb.is_tombstone(t)) == 1)

check("3.17 verify() names a surviving umbrella specifically",
      raises(lambda: tomb.verify(RecordingTagIO(final | {UMB}), want, VOCAB, UMB)))
check("3.18 verify() catches a stray tier tag",
      raises(lambda: tomb.verify(RecordingTagIO(final | {tier.TAG_EXEC}),
                                 want, VOCAB, UMB)))
check("3.19 verify() catches a missing marker",
      raises(lambda: tomb.verify(
          RecordingTagIO(final - {tomb.tombstone_tag(WHEN)}), want, VOCAB, UMB)))
check("3.20 verify() ignores uncontrolled tags",
      not raises(lambda: tomb.verify(RecordingTagIO(final | {"someone-elses"}),
                                     want, VOCAB, UMB)))

io_bare = RecordingTagIO({UMB})
tomb.entomb(io_bare, VOCAB, when=WHEN, umbrella=UMB, is_halted=lambda: True)
check("3.21 an untiered, unowned qube tombstones cleanly",
      io_bare.read() == {tomb.tombstone_tag(WHEN)})

# =====================================================================
print("\n--- §4 the retention file (fail-closed AWAY from deletion) ---")

check("4.1 absent -> the shipped 24h default",
      tomb.read_retention(retention_file(None))
      == tomb.DEFAULT_RETENTION_SECONDS == 86400)
check("4.2 a plain integer is honoured",
      tomb.read_retention(retention_file("3600")) == 3600)
check("4.3 surrounding whitespace is tolerated",
      tomb.read_retention(retention_file("  7200\n")) == 7200)
check("4.4 '0' is legal (reap on the next tick) and is NOT None",
      tomb.read_retention(retention_file("0")) == 0)
check("4.5 empty -> None (never reap)",
      tomb.read_retention(retention_file("")) is None)
check("4.6 non-numeric -> None (never reap)",
      tomb.read_retention(retention_file("soon")) is None)
check("4.7 negative -> None (never reap)",
      tomb.read_retention(retention_file("-1")) is None)
check("4.8 float -> None (never reap)",
      tomb.read_retention(retention_file("3600.5")) is None)
check("4.9 unreadable (a directory) -> None (never reap)",
      tomb.read_retention(TMP) is None)
check("4.10 a comment-only file -> None, not a silent default",
      tomb.read_retention(retention_file("# 3600\n")) is None)

# =====================================================================
print("\n--- §5 the reaper's veto matrix ---")

NOW = 1755600000
DEAD = {tomb.tombstone_tag(NOW - 90000), "qmcp-guarded"}     # 25h old
FRESH = {tomb.tombstone_tag(NOW - 60), "qmcp-guarded"}       # 1m old

check("5.1 past the window -> due",
      tomb.due_for_reap(DEAD, NOW, 86400, umbrella=UMB))
check("5.2 inside the window -> not due",
      not tomb.due_for_reap(FRESH, NOW, 86400, umbrella=UMB))
check("5.3 exactly at the boundary -> due (>=, not >)",
      tomb.due_for_reap({tomb.tombstone_tag(NOW - 86400)}, NOW, 86400,
                        umbrella=UMB))
check("5.4 one second short of the boundary -> not due",
      not tomb.due_for_reap({tomb.tombstone_tag(NOW - 86399)}, NOW, 86400,
                            umbrella=UMB))
check("5.5 retention None (malformed config) -> never due",
      not tomb.due_for_reap(DEAD, NOW, None, umbrella=UMB))
check("5.6 still inside the umbrella -> never due (stuck, not dead)",
      not tomb.due_for_reap(DEAD | {UMB}, NOW, 86400, umbrella=UMB))
check("5.7 running -> never due (someone is looking at it)",
      not tomb.due_for_reap(DEAD, NOW, 86400, umbrella=UMB, running=True))
check("5.8 undatable marker -> never due (a bug for a person)",
      not tomb.due_for_reap({"qmcp-tombstone_xyz"}, NOW, 86400, umbrella=UMB))
check("5.9 not tombstoned at all -> never due",
      not tomb.due_for_reap({UMB, tier.TAG_FULL}, NOW, 86400, umbrella=UMB))
check("5.10 a marker dated in the FUTURE -> never due (clock skew)",
      not tomb.due_for_reap({tomb.tombstone_tag(NOW + 99999)}, NOW, 86400,
                            umbrella=UMB))
check("5.11 retention 0 reaps a fresh tombstone (operator's explicit choice)",
      tomb.due_for_reap(FRESH, NOW, 0, umbrella=UMB))
check("5.12 an unreadable tag set -> never due",
      not tomb.due_for_reap(None, NOW, 86400, umbrella=UMB))
check("5.13 every veto is independent: umbrella beats an otherwise-due qube",
      not tomb.due_for_reap(DEAD | {UMB}, NOW, 0, umbrella=UMB))

# =====================================================================
print("\n--- §6 the pool-cap charge, with teeth ---")

check("6.1 an ai-managed qube is charged",
      budget.counts_toward_cap({UMB, tier.TAG_EXEC}))
check("6.2 a tombstone is charged even without the umbrella",
      budget.counts_toward_cap({tomb.tombstone_tag(WHEN)}))
check("6.3 an unrelated qube is not charged",
      not budget.counts_toward_cap({"created-by-dom0", "operator-label"}))
check("6.4 an unreadable tag set is not charged (fail-safe, as before)",
      not budget.counts_toward_cap(None))
check("6.5 a stuck half-tombstone is charged exactly once",
      budget.counts_toward_cap({UMB, tomb.tombstone_tag(WHEN)}))

app = FakeApp([
    FakeVM("live-a", {UMB, tier.TAG_EXEC}, private=2 * GIB),
    FakeVM("live-b", {UMB, tier.TAG_FULL}, private=3 * GIB),
    FakeVM("tomb-a", {tomb.tombstone_tag(WHEN)}, private=4 * GIB),
    FakeVM("outsider", {"created-by-dom0"}, private=9 * GIB),
])
check("6.6 the sum charges live + tombstoned, never the outsider",
      budget.sum_ai_managed_persistent_bytes(app) == 9 * GIB,
      f"got {budget.sum_ai_managed_persistent_bytes(app) / GIB} GiB")
check("6.7 TEETH: the pre-fix predicate lets the tombstone go free",
      old_sum(app) == 5 * GIB,
      f"pre-fix sum was {old_sum(app) / GIB} GiB; if this is 9 the teeth are blunt")

# The churn bypass, end to end. Cap 10 GiB, 2 GiB per qube. Create five, remove
# all five (they become tombstones), then try to create a sixth.
budget.CAP_PATH = retention_file(str(10 * GIB))
churn = FakeApp([FakeVM(f"t{i}", {tomb.tombstone_tag(WHEN)}, private=2 * GIB)
                 for i in range(5)])
check("6.8 TEETH: under the pre-fix rule the churned tombstones read as 0 used",
      old_sum(churn) == 0)
check("6.9 under the shipped rule they read as the full 10 GiB",
      budget.sum_ai_managed_persistent_bytes(churn) == 10 * GIB)
check("6.10 ...so the sixth create is REFUSED, closing the churn bypass",
      budget.check_cap_for_create(churn, None, None) == budget.ERR_CAP_EXCEEDED)
check("6.11 GetPoolStats and the gate share one function (cannot drift)",
      budget.sum_ai_managed_persistent_bytes.__module__
      == budget.check_cap_for_create.__module__)

# =====================================================================
print("\n--- §7 invariance: behaviour-neutral with no tombstone present ---")

FLEETS = [
    [],
    [FakeVM("solo", {UMB})],
    [FakeVM("a", {UMB, tier.TAG_EXEC}, private=1 * GIB),
     FakeVM("b", {UMB}, private=7 * GIB, klass="StandaloneVM", root=20 * GIB),
     FakeVM("tpl", {UMB}, private=1 * GIB, klass="TemplateVM", root=15 * GIB),
     FakeVM("out", {"created-by-dom0"}, private=99 * GIB),
     FakeVM("dump", {UMB, tier.TAG_DUMP}, private=2 * GIB)],
    [FakeVM("guarded", {UMB, "qmcp-guarded"}, private=5 * GIB),
     FakeVM("locked", {UMB, "qmcp-egress-locked_ai-net-alt"}, private=5 * GIB),
     FakeVM("owned", {UMB, "qmcp-owner_mcp-control"}, private=5 * GIB)],
]
_ok = True
for idx, vms in enumerate(FLEETS):
    a = FakeApp(vms)
    if budget.sum_ai_managed_persistent_bytes(a) != old_sum(a):
        _ok = False
        print(f"      fleet {idx}: new={budget.sum_ai_managed_persistent_bytes(a)} "
              f"old={old_sum(a)}")
check("7.1 tombstone-free fleets sum identically to the pre-change code", _ok)
check("7.2 the qmcp-* tags Stage 2 already ships do NOT accidentally charge",
      not budget.counts_toward_cap({"qmcp-owner_mcp-control"})
      and not budget.counts_toward_cap({"qmcp-guarded"})
      and not budget.counts_toward_cap({"qmcp-egress-locked_ai-net-alt"}))
check("7.3 only the tombstone prefix charges outside the umbrella",
      budget.counts_toward_cap({tomb.TOMBSTONE_PREFIX + "1"})
      and not budget.counts_toward_cap({"qmcp-tombstonelike"}))

# =====================================================================
print("\n--- §8 the reaper artifact itself ---")

# The reaper has no .py extension, so SourceFileLoader — the pattern this repo
# already documents for the extension-less dom0 wrappers. Loading it is safe:
# `import qubesadmin` lives inside main(), not at module scope.
from importlib.machinery import SourceFileLoader

_rl = SourceFileLoader("qmcp_reaper",
                       os.path.join(DOM0_RPC, "qmcp-tombstone-reaper"))
_rspec = importlib.util.spec_from_loader(_rl.name, _rl)
reaper = importlib.util.module_from_spec(_rspec)
_rl.exec_module(reaper)

check("8.1 the reaper loaded its qmcp_tombstone sibling (offline layout)",
      reaper._TOMB is not None)

# The production and offline layouts diverge (see the reaper's INSTALLED_LIB_DIR
# docstring): dom0 puts libs in /etc/qubes-rpc/ while the reaper lives at
# /usr/local/lib/qmcp/, so the sibling-load pattern the wrappers use — resolve
# against __file__ — does not apply. The first rig deploy hit this: the reaper
# was installed but its library was in a directory it did not consult, and the
# --list smoke exited 2 with "qmcp_tombstone.py not loadable". The fix was a
# loader that tries INSTALLED_LIB_DIR first and __file__ second; these teeth
# prove the fix stays in the artifact.
check("8.1a INSTALLED_LIB_DIR is the dom0 install path (/etc/qubes-rpc)",
      reaper.INSTALLED_LIB_DIR == "/etc/qubes-rpc")
_reaper_src = open(os.path.join(DOM0_RPC, "qmcp-tombstone-reaper"),
                   encoding="utf-8").read()
check("8.1b the loader tries INSTALLED_LIB_DIR before __file__'s directory",
      _reaper_src.index("INSTALLED_LIB_DIR") < _reaper_src.index("_own_dir"))

# The flag ALLOWLIST, asserted here as well as in the installer. Reaping is
# timer-only, so every flag is a potential way to reap outside the timer; the
# surface is default-deny (the G0a SETTABLE_PROPS posture) rather than a grep
# for suspicious words. A lexical guard was tried first and matched the
# reaper's own docstring explaining why no early-reap path exists — it failed
# on correct code, and would have passed on a flag named innocuously.
_src = open(os.path.join(DOM0_RPC, "qmcp-tombstone-reaper"), encoding="utf-8").read()
_flags = sorted(set(__import__("re").findall(r'ap\.add_argument\("--([a-z-]+)"', _src)))
check("8.2 the reaper's flag surface is exactly the two read-only ones",
      _flags == ["dry-run", "list"], f"found {_flags}")
check("8.3 the reaper deletes through exactly one call site",
      _src.count("del app.domains[") == 1)

_DEAD_TAGS = {tomb.tombstone_tag(NOW - 90000)}
_cases = [
    ("due", FakeVM("d", _DEAD_TAGS), 86400),
    ("within-window", FakeVM("w", {tomb.tombstone_tag(NOW - 60)}), 86400),
    ("stuck-in-umbrella", FakeVM("s", _DEAD_TAGS | {UMB}), 86400),
    ("undatable", FakeVM("u", {"qmcp-tombstone_xyz"}), 86400),
    ("running", FakeVM("r", _DEAD_TAGS, power="Running"), 86400),
]
for expect, vm, ret in _cases:
    got, _age = reaper._classify(vm, NOW, ret, UMB)
    check(f"8.4 _classify({expect}) -> {expect}", got == expect, f"got {got}")

check("8.5 an unreadable power state counts as running (never reaped)",
      reaper._classify(FakeVM("x", _DEAD_TAGS, power=None), NOW, 86400,
                       UMB)[0] == "running")
check("8.6 retention 0 still cannot reap a qube inside the umbrella",
      reaper._classify(FakeVM("s", _DEAD_TAGS | {UMB}), NOW, 0,
                       UMB)[0] == "stuck-in-umbrella")
check("8.7 _classify reports an age for a datable tombstone",
      reaper._classify(FakeVM("d", _DEAD_TAGS), NOW, 86400, UMB)[1] == 90000)
check("8.8 _classify reports no age for an undatable one",
      reaper._classify(FakeVM("u", {"qmcp-tombstone_xyz"}), NOW, 86400,
                       UMB)[1] is None)
check("8.9 _classify is pure — it mutates no tags",
      (lambda v: (reaper._classify(v, NOW, 86400, UMB),
                  v.tags == _DEAD_TAGS)[1])(FakeVM("p", _DEAD_TAGS)))

# =====================================================================
print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
