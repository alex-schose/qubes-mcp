# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Development up to 0.9.0 was tracked as lettered **stages** (A … F3, G0, I-0 … I-6).
That vocabulary is retained in `deploy/` filenames and in the design document as
the as-built record; from 0.9.0 onward, releases are versioned. The stage names
in `deploy/` will be renamed to match in a later release — a mechanical change
kept separate so it stays independently reviewable.

**Every commit ships a version.** One commit, one patch bump, one entry here, one
tag. There is no accumulating "unreleased" pile: if a change is worth committing
it is worth saying what it changed, and a reader who has `0.9.7` installed can
tell exactly what `0.9.9` adds. Versions **0.9.1 … 0.9.9 were assigned
retroactively** on 2026-08-19 to commits that were already public — the history
itself is unchanged, because this project does not rewrite published history, so
those versions are a record laid over it rather than a rebase.

While the major version is `0`, a breaking change takes a patch bump and is
labelled **BREAKING** in its entry. That is SemVer's own rule for `0.y.z`, not a
shortcut: nothing here is stable until 1.0.0, and pretending otherwise by
burning minor versions would misrepresent it.

## [Unreleased]

Nothing — the working tree is the last released version.

## [0.9.12] — 2026-08-19

Intra-umbrella `qubes.Filecopy` by operator dialog. Policy-only.

### Fixed

- **An operator could not hand-copy a file between two qubes they own, and got
  no dialog explaining why.** G0c replaced the single
  `@tag:ai-managed -> @tag:ai-managed` peer-copy line with the 3×3 tiered mesh
  and left **no compat backstop** — the only tag-scoped surface graduated
  without one (`install-stage-flip.sh` deletes exactly four, and this is not
  among them). Because the qrexec engine matches tags *literally* and cannot
  read `/etc/qmcp/tier-default`, an **untiered** umbrella qube has matched none
  of those lines since G0c, in compat as much as post-flip, and fell to the
  dialog-free deny.

### Changed

- `qubes.Filecopy * @tag:ai-managed @tag:ai-managed ask` — intra-umbrella peer
  copy returns as an **ask**, which is tighter than the pre-G0c `allow` and
  tighter than the backstop G0c should have left. It changes exactly the five
  pairs the mesh missed (elevated→untiered, untiered→elevated,
  untiered→untiered); every pair the mesh already covers keeps its dialog-free
  `allow`, so nothing that works today starts prompting.
  **The target selector is `@tag:ai-managed`, never `@anyvm`, and that is the
  safety argument.** qrexec cannot tell the operator from the agent, so an ask
  is a control only because AI cannot click zenity — a human-attention control.
  What a rule *can* bound is what the agent learns by asking: with `@anyvm` the
  agent names any qube on the host and observes whether a dialog appeared, an
  existence oracle over every out-of-scope qube (the class F-1 closed on the
  create paths). With `@tag:ai-managed` the target set is exactly what
  `qmcp.ListAIManagedQubes` already returns.
- **Leaving the umbrella is unchanged** and still a dialog-free deny. The
  handoff-to-a-vault case uses the `ai-dump` sink that already exists as a
  one-way buffer — no new tag and no second mechanism.

### Added

- `qubes.Filecopy * @tag:ai-dump @tag:ai-managed deny` — the price of
  introducing an ask at all. A misconfigured hybrid (`ai-managed` **and**
  `ai-dump`, the invariant the I-4 installer warns about) would otherwise match
  the new ask as a *source* and be dialogued back into the fleet, defeating the
  Biba valve. This also closes a pre-existing hole: a **pure** sink copying back
  in previously matched no rule here and landed on the Qubes system-default
  `ask` — finding [8]'s fallthrough hazard, in the one direction G0c did not
  cover. `ai-dump` → out-of-umbrella is deliberately untouched, so an operator
  can still drain a buffer by hand.
- `deploy/install-stage-peercopy.sh` — validates the staged policy with the real
  qrexec parser, resolves the whole Filecopy matrix off the staged file and
  aborts before touching `/etc/qubes/policy.d/` if anything drifted, backs up
  the live policy, reloads the daemon, then re-resolves off the **installed**
  file.
- `offline-validate-G0c.py` grows from 23 to 42 checks, including teeth that
  remove each new rule from the parsed set and re-resolve — proving the ask
  restores a capability that was genuinely absent and the deny closes a hole
  that would genuinely open.

## [0.9.11] — 2026-08-19

Wave 2 Stage 3c — the enforcement flip, shipped inert.

### Added

- `deploy/install-stage-3c.sh`, `deploy/uninstall-stage-3c.sh`,
  `deploy/offline-validate-3c.py` (82 checks).
- `_gate()` in all 8 mutation wrappers, replacing Stage 1's `_shadow_note`. It
  composes the wrapper's own capability verdict with the kernel's through
  `qmcp_enforce.effective_verdict`, treats `GATE` as a refusal until Stage 7
  arms that channel, and keeps the I-2 divergence record — carrying `mode` and
  `effective` as well, once a mode is armed.
- `qmcp.LifecycleAIManaged:remove` routes through `qmcp_tombstone.entomb` **when
  enforcing**. The tombstone arms with enforcement rather than with the install,
  in the same predicate, so no ordering of writes can separate the `CAP_EXEC`
  widening from the control that makes it survivable.
- The installer gates behaviourally rather than structurally: it *runs* the
  staged kernel against the decisions this stage changes, *runs* each staged
  wrapper's gate through the mode ladder including both partial-deploy
  directions, and *runs* a real tombstone transition from the installed layout.
  It refuses to install if `/etc/qmcp/enforce-mode` already exists, so the code
  and its arming cannot land in one step.

### Changed

- **BREAKING (behind the flag): `qmcp_caps` now permits `netvm = null`.** Every
  `netvm` write was modelled as escalation-class, which was right while the
  kernel only logged and wrong the moment it decides — both halves of §3.4
  deliberately permit the disconnect as de-escalation. The carve-out is a
  *direction*, not a value, and is opt-in by the caller: a call site that does
  not state the value still gets the refusal. Under `shadow` nothing changes.
- `qmcp.SetPropertyAIManaged` passes the property `value` to the kernel, which
  is what makes the carve-out decidable.
- `deploy/install-stage-1.sh` and `deploy/offline-validate-1-wiring.py` follow
  the hook's rename from `_shadow_note` to `_gate`.

### Removed

- The unreachable `resolved_netvm` branch in `qmcp_caps._decide_inner`. §3.4's
  birth half is enforced in the create wrappers and no caller ever populated the
  key; a branch that reads as an enforcement path and is not one is the
  no-illusion defect. `offline-validate-1.py` pins the cut structurally, and the
  property itself is asserted where it is enforced.

## [0.9.10] — 2026-08-19

`pending` — changelog backfill, retroactive per-commit versions, and the first GitHub release

### Changed
- **Every commit now ships its own version.** Versions 0.9.1 … 0.9.9 are
  assigned retroactively below to commits that were already public, and tagged
  to match. Nothing was rewritten: the history is unchanged and the versions are
  a record laid over it, which is the only honest way to backfill a repo that
  forbids force-pushing.
- **A disclaimer for the reserved-namespace residual** in `README.md`, under
  *Qube naming*. The bounded disclosure it describes is accepted, not
  outstanding, and the README now says so plainly rather than leaving a reader
  to infer it from an installer warning.

## [0.9.9] — 2026-08-18

`761bae1` — close an existence oracle and an egress-retarget bypass found by attack

Found by an adversarial pass against the shipped tree: five findings,
each reproduced against a live fleet before being fixed and re-attacked after.

### Changed
- **BREAKING — qubes created by an agent must be named inside a reserved
  prefix.** `qmcp.SpawnAIManagedQube` and `qmcp.CloneAIManagedQube` now refuse a
  requested name that does not start with the prefix in
  `/etc/qmcp/name-prefix` (absent = `ai-`). The refusal happens on the name's
  *shape*, before dom0's qube list is consulted at all. A create that previously
  succeeded under another naming convention now returns `name must start with
  '<prefix>' …`; set the operator file, or rename the convention.

  This is a security boundary, not tidiness — see the existence-oracle entry
  under **Fixed**. It constrains only what an agent may *ask to create*: a qube
  the operator names anything and tags `ai-managed` is fully usable, and
  disposables keep the platform-generated `disp<N>` names.

- **BREAKING — an agent can no longer retarget a qube's network.**
  `qmcp.SetPropertyAIManaged` refuses a non-null `netvm` write on an ai-managed
  qube. Setting `netvm = null` (disconnecting) remains allowed, mirroring the
  create path's carve-out: de-escalation cannot leak.

  Birth-egress inheritance shipped without this and was worth very little
  without it. With birth enforced and retarget open, an agent could retarget a
  source qube and then *clone* it — and the clone was born on the new path with
  no `netvm` argument for the birth guard to inspect, because inheriting from
  the creation source is precisely what the birth rule is supposed to do. The
  same move through a DispVMTemplate minted disposables on the foreign egress,
  which is the case the rule exists for. The two halves are one guarantee.

### Fixed
- **The create paths were an existence oracle over every qube on the host.**
  Both validated a requested name against dom0's full qube list — not the
  ai-managed subset — and answered `qube '<name>' already exists`, echoing it
  back. An agent could confirm any qube name it could guess, including qubes
  every *read* surface deliberately redacts.

  Fixed by reserving a namespace rather than by rewording the error, and the
  distinction is the substance of the fix. A create has three outcomes: the name
  is free, it is taken by a qube the agent can already enumerate, or it is taken
  by one it cannot. Collapsing the messages leaves the third resolvable by
  subtraction, and the timing separates them regardless — a free name goes on to
  do real work while a taken one returns at once. Restricting *what an agent may
  ask for* is what makes a collision only ever concern a name it could already
  see. One residual, documented and reported by the installer: a qube inside the
  reserved prefix that is not `ai-managed` stays inferable. One namespace
  instead of the whole machine.

- **Raw dom0 exception text no longer reaches the caller.** Eleven sites across
  the three create wrappers forwarded a Python exception string into a
  caller-visible field; one returned dom0's storage pool name, the LVM volume
  path and `lvresize` remediation advice inside an `ok: true` response. Those
  fields now carry fixed vocabulary (`private_resize_failed`, `clone failed`, …)
  and the exception class goes to the dom0 audit chain. The JSON-parse error is
  deliberately unchanged: it echoes the caller's own payload.

- **`private_size` rejects a float and a boolean.** It was validated with
  `int()`, which truncated `1.5` to `1` and — `bool` being an `int` subclass in
  Python — accepted `true` as a byte count. Neither breached the pool cap, since
  the estimate clamps to the default floor, but the documented contract is an
  integer and the surrounding posture is default-deny on input shape.

## [0.9.8] — 2026-08-18

`1239065` — Wave 2 Stage 3b — enforcement-mode flag and production smoke suite, INERT

### Added
- **An operator-owned enforcement-mode flag, shipped inert**
  (`dom0-rpc/qmcp_enforce.py`, `/etc/qmcp/enforce-mode`, absent = `shadow`).
  The switch the enforcement flip is made and unmade with, and the way back: one
  write, no policy reload, no daemon restart. **Three modes rather than two,**
  because this flip is not monotone the way earlier ones were — it narrows the
  escalation class and simultaneously *widens* lifecycle, since an actor that
  can already `rm -rf` inside a qube gains nothing from a separate gate on
  removing it. So `enforce` is not uniformly safer than `shadow`, and a
  malformed flag must not land there. `strict` — allow only what the wrapper
  **and** the kernel allow — is safer than both, which makes it the only correct
  fail-closed target and, in practice, the right first value to arm.

- **A production smoke suite** (`deploy/smoke-production.py`), the gate the
  enforcement flip is required to pass. It reports **four** outcomes, not two:
  `PASS`, `FAIL`, `VACUOUS` (ran, but the fleet's shape means it could not have
  failed) and `NOT-RUN` (needs tooling outside this repository, declared in an
  operator-local conf). Exit `0` GREEN, `2` FAILED, `3` INCOMPLETE — and
  INCOMPLETE is **not** green, because a suite that counts an unrunnable check
  as a pass reports success while part of the gate never ran.

## [0.9.7] — 2026-08-18

`6e6dfaf` — Wave 2 Stage 3a — tombstone mechanism and reaper, INERT

### Added
- **A tombstone and its reaper, shipped inert** (`dom0-rpc/qmcp_tombstone.py`,
  `dom0-rpc/qmcp-tombstone-reaper`, `deploy/install-stage-3a.sh`). The
  compensating control the coming enforcement flip needs, landed ahead of it so
  the window exists before the capability that needs it. An AI-initiated remove
  will, once enforcement flips, halt the qube, add a `qmcp-tombstone_<epoch>`
  marker, strip the umbrella and every privilege tag while carrying restrictions
  forward, then read back and roll back on mismatch. A root systemd oneshot
  reaps on a timer only — never under pool pressure, because an early-reap path
  is one an agent could drive to destroy evidence before the operator reads it.
  `qmcp_budget` now charges tombstones as well as ai-managed qubes: dropping the
  umbrella would otherwise make a tombstone free, and create/remove churn would
  park unbounded disk outside the accounting. Nothing creates a tombstone yet,
  so the summation is byte-identical on a fleet without one.

## [0.9.6] — 2026-08-18

`a4f9ebf` — replace deprecated `load_module()` calls (removed in Python 3.15)

### Fixed
- **Three `SourceFileLoader.load_module()` calls replaced** with the
  `spec_from_loader` + `exec_module` idiom the rest of the tree uses (the I-6
  installer heredoc, and the G0a and G0d validators). The call is removed in
  Python 3.15, so a stage re-install would have aborted on a future interpreter.
  Invisible under a plain `python3`; surfaced by running every validator under
  `-W error::DeprecationWarning`, which is now a standing pre-commit step.

## [0.9.5] — 2026-08-18

`6744bf9` — Wave 2 Stage 2 — ownership, birth tier, birth egress

### Added
- **Ownership, birth tier and birth egress on every create path**
  (`dom0-rpc/qmcp_birth.py`, `deploy/install-stage-2.sh`). A qube created by
  `qmcp.SpawnAIManagedQube` / `qmcp.CloneAIManagedQube` /
  `qmcp.SpawnDisposableAIManaged` is now stamped atomically with the
  `ai-managed` umbrella, `qmcp-owner_<principal>`, the source's tier clamped by
  the operator-owned `/etc/qmcp/birth-ceiling`, and every restriction its source
  carried — then the tag state is **read back** and any mismatch rolls the
  create back.

  A new reserved `qmcp-*` namespace splits tags into two classes with a
  deliberate asymmetry. *Privilege* tags (the tier ladder, the owner tag) are
  **clamped** to the authority held on the source. *Restriction* tags
  (`qmcp-egress-locked_*`, `qmcp-guarded`, and the platform's `anon-vm`) are
  **inherited unconditionally**, because a restriction the clamp can remove is a
  laundering hole: clone the guarded qube, lose the guard. Tags the project does
  not own — an operator's own labels, the platform's `created-by-*` — are left
  untouched.

  Ownership is carried by that stamped tag and **never** by `created-by-*`.
  qubesd stamps `created-by-` with the *calling* domain, which is dom0 for every
  qmcp create, so an AI-spawned qube and an operator-created one are
  byte-identical under it; `disp-created-by-*` is worse, escaping qubesd's guard
  entirely and so forgeable by anything holding `tag.Set`.

  Birth tier reads the source's **literal** tag, not its effective capability,
  and the distinction is load-bearing: while the fleet is in compat an untiered
  qube resolves to `ai-full`, so clamping on the effective value would mint
  permanently-`ai-full` children throughout the migration — qubes that keep full
  authority through the least-privilege flip when everything else drops to the
  read floor. Reading the literal tag keeps this change invisible in compat and
  correct after the flip. Nothing is ever born above its source, and a source's
  tier is operator-assigned because AI cannot write tags.

  This is what makes least privilege *operable*: a created qube is usable by its
  creator with no operator action in between, which is the gap 0.9.0 documented
  as a known limitation.

### Changed
- **BREAKING — a created qube's `netvm` is inherited, not defaulted.** The
  hardcoded `DEFAULT_NETVM = "ai-net-router"` in `qmcp.SpawnAIManagedQube` is
  gone. Birth egress now resolves first-match-wins: the creation source's netvm
  (a clone source or DVMT answers for itself, including when the answer is *no
  network*), else the calling principal's netvm, else the name in
  `/etc/qmcp/birth-egress` (written by `install-stage-c.sh`, which already knows
  it), else the create is **refused**. A `TemplateVM` source is not
  authoritative — a template's netvm is an update path, not a workload egress —
  so template-based spawns inherit the gateway's egress.

  Two real bugs close with it. The constant was fleet-specific and already
  public: on an install whose egress qube is named anything else, every spawned
  qube silently came up with **no network**. And on a fleet with more than one
  egress class it produced the leak the invariant exists to prevent — an agent
  working behind Tor spawning a clearnet qube, which then resolves DNS or checks
  for updates on first boot.

  A caller-supplied `netvm` is accepted only when it equals the inherited value;
  any other value is escalation-class and refused at every tier. Explicit `null`
  remains allowed with no approval, since de-escalation cannot leak.
  **What this does NOT close, stated plainly.** Stage 2 governs **birth** egress
  only. Moving an **existing** qube across egress classes is still permitted at
  `ai-full` — and that is the more dangerous of the two: a newly born qube is
  empty and has nothing to leak, while an existing one may already hold
  Tor-derived data, a session, or an identity. The decision kernel already
  answers `escalation-class` DENY for a `netvm` write, but it runs in shadow, so
  the wrapper still allows it and only the disagreement is recorded. Retarget
  closes when enforcement flips to `decide()`. Until then, "egress is enforced"
  is true of creation and false of mutation.

- **A create whose egress cannot be proven is rolled back.** A failed `netvm`
  assignment used to return `ok: true` with a warning, leaving a tagged qube on
  whatever the system default was — possibly the operator's own upstream. It now
  rolls the qube back. Disposables have their netvm pinned explicitly and read
  back *before* they are ever started, so a mismatch costs a kill and no leak.

- **Removed `_RING_MIN_TIER` from `qubes_mcp/server.py`.** It mapped each ring
  to the tier its write surface needs — accurate, and enforced nowhere. This
  layer runs inside `mcp-control`, the untrusted side; the real check is the
  dom0 helper read across the trust boundary. Nothing above that boundary should
  resemble a control, because a reader who finds a tier table in the server
  reasons about the system's authority from a table that has never denied
  anything, and a comment saying "declarative only" does not survive a skim.

## [0.9.4] — 2026-08-18

`226b3cb` — installer pulls only the first wrapper; operator files ignore comments

### Fixed
- **An installer's multi-file pull archived only the first file** and executed
  the rest. The file list reached the remote shell containing newlines, which it
  read as command separators. Collapsed to one line before it becomes a remote
  command.
- **`/etc/qmcp/tier-default` ignored the `value  # comment` form**, so an
  operator annotating the file the way neighbouring files are annotated got a
  silently malformed value — and malformed fails closed, so the setting appeared
  to do nothing at all.

## [0.9.3] — 2026-08-17

`5732e4e` — Wave 2 Stage 1 — capability decision kernel, shipped SHADOW

### Added
- **A dom0 capability decision kernel, running in shadow mode**
  (`dom0-rpc/qmcp_caps.py`, `deploy/install-stage-1.sh`). `decide(actor,
  service, action, targets)` derives a verdict from a domination lattice rather
  than a hand-authored matrix, resolving first-match-wins: a target outside the
  `ai-managed` umbrella denies; an escalation-class operation denies at every
  tier, forever (tag writes, `provides_network`, `template` retarget, `netvm`,
  `name`, TemplateVM create); a target in the operator's guarded hard class
  gates, checked *before* the domination logic so it can never be argued away;
  an operation that an already-held capability fully dominates is allowed; and
  anything left falls through to the `CAP_*` ladder. The kernel also exposes
  `capabilities()`, `explain()` and `resolve_birth_egress()`.

  **It enforces nothing.** Each of the eight state-changing wrappers asks the
  kernel the same question its `CAP_FULL` gate just answered — on both outcomes
  — and records only a *disagreement*, through its existing single response
  funnel, as a new optional `shadow` field on the hash-chained dom0 audit line.
  The field is **omitted when they agree**, following the same byte-neutral
  contract the `consent` field already had, so an agreeing call's audit line and
  chain hash are identical to before and a wrapper still audits correctly
  against an older `qmcp_audit.py`. A missing or broken kernel changes nothing
  at all: this is the one component in the codebase that fails **open**, because
  it is not a gate — the tier and consent helpers fail closed precisely because
  they are.

  The divergence log is the deliverable. It is dom0-side and unreachable by AI,
  and the later release that flips enforcement onto `decide()` is gated on it
  holding nothing unexplained. Until then two divergences are expected and
  documented: a lifecycle operation on an `ai-exec` target (the kernel allows
  what exec already dominates; the wrapper still refuses) and a `netvm` /
  `template` / `name` property write (the kernel refuses as escalation class;
  the wrapper still allows).

  No policy change, no daemon restart, no new RPC service, no AI-visible
  surface. Covered by `deploy/offline-validate-1.py` (46 checks over the
  lattice) and `deploy/offline-validate-1-wiring.py` (26 checks, which prove
  invariance by running every case twice — kernel loaded and kernel absent —
  and asserting byte-identical responses, and confirm a *raising* kernel changes
  nothing either).

## [0.9.2] — 2026-08-17

`01d1f26` — forbid scoping any gate on `created-by-*` / `disp-created-by-*`

### Changed
- **Documented an anti-goal:** no policy, ownership or gate may ever be scoped
  on `created-by-*` or `disp-created-by-*`. qubesd stamps `created-by-` plus the
  *calling* domain — dom0 for every create this project makes — so the tag
  cannot distinguish an AI-created qube from an operator-created one; and
  `disp-created-by-*` escapes qubesd's own `created-by-` write guard, so anything
  holding `tag.Set` can forge it. Ownership is a wrapper-stamped tag in the
  reserved namespace instead.

## [0.9.1] — 2026-08-17

`d8839b8` — report property reads per property instead of aborting on the first failure

### Fixed
- **Reads no longer discard a whole call over one class-specific property.**
  `qubes_state` and `qubes_props_get` composed `qmcp.GetPropertyAIManaged` per
  property but returned on the FIRST failure, so a StandaloneVM or a TemplateVM
  — neither of which has a `template` property — yielded nothing usable even
  though `power_state`, `netvm` and `provides_network` all read fine. Both tools
  now report per property: `{"ok": true, "values": {...}}` plus an `"errors"`
  map naming only what could not be read. The dom0 wrapper already answered per
  property; the granularity was being thrown away in the MCP layer, so no dom0
  change was needed and the tools stay class-agnostic (no extra round trip to
  learn the klass, and it keeps working for properties added later).
  Opacity is unchanged: when NOTHING reads, the first error is returned
  verbatim, so an out-of-scope or nonexistent qube still collapses to the same
  opaque `"not found"` / `"not found or refused"` it always did. The
  per-property error can only surface alongside a successful read, which itself
  proves the target is inside the umbrella — the same post-scope-check ordering
  the cross-ref and egress refusals follow, so it is no existence oracle.
  Covered by `deploy/offline-validate-0-2.py` (24 checks, including teeth
  asserting the pre-fix control flow fails the same cases).

## [0.9.0] — 2026-08-15

First versioned release. Deliberately **pre-1.0**: the resource axis (tiers) is
complete and enforced, but least privilege is not yet *operable* end to end —
see the create-path note under Known limitations. 1.0.0 is reserved for the
release where an agent can work within least privilege without an operator
action between every create and its first use.

### Added
- `CHANGELOG.md` (this file) and semantic versioning.

### Changed
- **BREAKING — reserved feature namespace.** `qmcp.SetFeatureAIManaged` now
  refuses any feature key beginning with `qmcp` (`DENIED_FEATURE_PREFIXES`),
  alongside the existing operator-only `internal`. A call that previously
  succeeded now returns `feature namespace qmcp* is reserved`; any caller
  setting keys in that namespace must rename them.
  Nothing in the codebase reads a feature to make an authorization decision
  today — exec is gated by the policy tag plus the service file's presence in
  the template — so this is *reservation*, not a fix for a live escalation. It
  ensures the project's own namespace cannot be pre-seeded if a future release
  ever does consult it.

### Fixed
- **Policy-daemon restarts are now verified.** 14 installers restarted
  `qubes-qrexec-policy-daemon` without checking it came back. Run back-to-back,
  the sixth restart inside systemd's 10 s `StartLimitIntervalSec` trips
  `StartLimitBurst` and leaves the unit `failed`; qrexec then falls back to
  spawning `qrexec-policy-exec` per call, which is functional but costs roughly
  7× call latency, forks a dom0 interpreter per call, and breaks inter-qube
  clipboard paste. That failing restart *does* return `rc=1` — the installers
  missed it because they never checked `$?`. Each now clears any prior failure,
  restarts once, waits for `active`, and aborts loudly with recovery
  instructions if the daemon does not return. `install-stage-flip.sh` gets the
  same treatment, and rolls the flip back rather than reporting success on a
  daemon that never came home.
- **`install-stage-flip.sh` could never complete as documented.** It staged its
  candidate policy with `sudo python3` and validated it with unprivileged
  `python3`; dom0's root umask is `0077`, so the staged file was unreadable and
  the flip aborted (fail-closed, but unrunnable). The validator now runs with
  the same privilege that wrote the file, and the script checks for root up
  front instead of failing at the last step.
- **Consistent `SOURCE_PATH`.** Nine installers still defaulted to the
  pre-restructure `/home/user/qubes_mcp`; the rest used
  `/home/user/qubes_mcp/public`. Running the band with default arguments
  installed a mix or failed. All installers now agree. The copy-paste *fetch*
  lines carried the same stale path in every installer and uninstaller header
  and 14 times in `README.md` (42 occurrences); followed verbatim they failed at
  step one with `cat: No such file or directory`. All corrected.
- **`install-stage-a.sh` no longer claims policy is re-read per call.** Its
  completion message said no daemon restart was needed because "qrexec re-reads
  policy on each call". The policy daemon caches — which is the entire reason
  the other 14 policy-writing installers restart it. It now states that and
  gives the command for anyone stopping after Stage A.
- **`install-stage-I-2.sh` no longer dies on a missing venv.** Its final smoke
  requires the MCP server's virtualenv in the source qube, which nothing earlier
  in the band builds, so a clean-room install failed with `rc=127` *after*
  installing the audit log — leaving the one check that proves the non-root
  qrexec write path silently unrun. It now skips loudly and prints how to
  complete the verification.
- **Test suites no longer assume the fleet flip has happened.**
  `test-stage-a.py`, `test-stage-I-5.py` and `test-stage-I-6.py` asserted
  post-flip least privilege unconditionally and therefore reported failures on a
  correct, freshly installed (compat) system, where an untiered qube resolving
  to `ai-full` is the documented default. These suites run from the AI seat and
  by design cannot read `/etc/qmcp/tier-default`, so they now assert
  **coherence**: every CAP_FULL surface on an untiered qube must agree — all
  refused (post-flip) or all allowed (compat). A *mixed* result is the real
  defect and is what fails the run.
- **A stage reinstall could silently un-flip the fleet.** 16 installers write
  `/etc/qubes/policy.d/30-mcp-control.policy` from the shipped, pre-flip
  artifact, which still carries the four `@tag:ai-managed` compat backstops;
  only `install-stage-flip.sh` manages `/etc/qmcp/tier-default`. So after the
  flip, reinstalling any stage restored the backstops while the flag stayed
  `ro`, leaving the two halves of the coupled flip disagreeing — and failing
  **permissive**: exec, file-copy and firewall-write reopened to every umbrella
  qube while the wrapper surfaces kept denying, with nothing to announce it.
  This is the split-brain the I-4 design note warns about, reached by routine
  stage maintenance rather than a partial flip. Those 16 installers now refuse
  to run on a flipped fleet, naming the consequence and pointing at the flip;
  `QMCP_ALLOW_UNFLIP=1` proceeds deliberately with a warning to re-flip
  afterwards.
- Test feature keys renamed off the now-reserved `qmcp-*` namespace: the
  a/I-5/I-6/I-2 probes (`qmcp-a-probe` → `ai-a-probe` and siblings) and
  `test-stage-f1.py`'s `qmcp-test-marker` / `qmcp-test-flag` →
  `ai-test-marker` / `ai-test-flag`.

### Known limitations
- **A created qube is unusable until an operator tiers it.** Create paths strip
  every inherited tier tag (the un-self-escalatability keystone, working as
  designed), so post-flip a newly created qube is untiered and therefore has no
  capability at all — it cannot be started, cloned, retargeted, or executed in.
  Every create-then-use workflow needs an operator action in dom0 in between.
  The consent-and-grant framework is what closes this; until it lands, running
  post-flip is operator-manual for each created qube.
- Consequently there is no single configuration in which the entire shipped test
  suite passes: the create-then-operate suites require capability on qubes they
  just created. Fixture tiering is documented per suite rather than assumed.

## Earlier work (stage-tracked, pre-versioning)

Condensed; the per-stage as-built record is the design document's stage rollout.

- **I-0 … I-6** — graduated authority: pool cap promoted to a hard create-gate;
  read-surface name-leak closed; hash-chained AI-unreachable dom0 audit log;
  tier taxonomy and dom0 resolver; tiers enforced at the policy layer and then
  at the wrapper/exec layer, with create-path tag stripping; consent mechanism
  shipped inert.
- **G0** — gateway input boundary: settable-property allowlist, qrexec
  target-name validation, device enumeration through a dom0 redactor, file-copy
  re-tiered on both endpoints, error-detail masking.
- **A … F3** — the base sandbox: tag-scoped policy and the `qmcp.*` wrapper
  catalog, exec and file transfer, single-egress networking, clone and
  disposable lifecycle, device attach/detach, features, filtered events, and
  AI-scoped disk accounting.
