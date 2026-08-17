# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Development up to 0.9.0 was tracked as lettered **stages** (A … F3, G0, I-0 … I-6).
That vocabulary is retained in `deploy/` filenames and in the design document as
the as-built record; from 0.9.0 onward, releases are versioned. The stage names
in `deploy/` will be renamed to match in a later release — a mechanical change
kept separate so it stays independently reviewable.

## [Unreleased]

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
