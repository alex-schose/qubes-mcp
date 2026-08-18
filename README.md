# qubes_mcp

**Autonomous AI workflows inside a Qubes-isolated sandbox.** AI agents get
real capabilities — provisioning qubes, building templates, running pentests,
moving files between them — while the operator's actual system stays
structurally invisible to the agent. Qubes provides kernel-level isolation;
this project provides the *capability surface* AI agents need, mediated by
dom0 wrappers so the trust boundary is enforced, not trusted.

> **Threat-model-driven implementation: human-designed boundaries, AI-assisted code.
> Review from Qubes engineers welcome and needed.**

FastMCP server that exposes a **tag-scoped Qubes Admin API sandbox** to AI
assistants. An untrusted-AI principal runs inside a dedicated qube
(`mcp-control`) and can manage a subset of qubes carrying the `ai-managed`
tag — without dom0 access, without visibility into untagged qubes, and
without the ability to mutate tags.

Stages A through F3 and the Stage I Wave-1 sub-stages (I-0..I-5) are tested and
working on Qubes R4.3-era systems — see the Status table below. Stages G–H are
designed but deferred until Stage I completes.

## Architecture

Every privileged action the AI takes is mediated by dom0. The MCP principal
reaches dom0 only through qrexec; dom0 enforces the invariants and acts on the
sandbox on its behalf. The AI never touches qubesd directly and never sees
outside its tag scope.

```
  ── dom0  (TRUSTED) ────────────────────────────────────────────────
     qrexec policy:   policy/30-mcp-control.policy
     qmcp.* wrappers: force-tag on create, cross-ref checks, opaque errors
     operator sets the `ai-managed` tag here, by hand (qvm-tags)
          ▲
          │  qrexec only — no dom0 shell; target=@adminvm routes to dom0
          │
  ── mcp-control  (UNTRUSTED — the AI / MCP principal) ───────────────
     cannot reach a dom0 shell · cannot see untagged qubes · cannot set/remove tags
          │
          │  dom0 acts on its behalf, only on tagged qubes ↓
          ▼
  ── qubes tagged `ai-managed`  (THE SANDBOX) ────────────────────────
     ai-vm-1   ai-vm-2   ai-dvm   …
     network egress funnels through one qube — ai-net-router — whose
     upstream only the operator sets in dom0 (Stage C)

  untagged qubes  =  the operator's real system  =  invisible to the AI
```

## Design highlights

- **Tag-scoped trust boundary.** AI sees and modifies only qubes carrying the
  `ai-managed` tag. The qrexec policy hard-denies `admin.vm.tag.{Set,Remove}`
  for the MCP source qube; tagging happens only in two places: the operator's
  hand in dom0 (`qvm-tags <vm> add|del ai-managed`) and the create-time wrapper
  `qmcp.SpawnAIManagedQube`, which force-tags every qube it creates.
- **Dom0-mediated wrappers (`qmcp.*`).** State-changing calls route through
  small Python scripts in `/etc/qubes-rpc/` that enforce invariants in dom0
  before touching qubesd: forced tagging on creation, cross-reference
  validation on `template`/`netvm`/`default_dispvm`, opaque error responses.
- **Wrapped reads hide existence.** `qmcp.GetPropertyAIManaged` returns the
  literal string `"not found"` indistinguishably whether the target qube
  doesn't exist or simply isn't tagged. The MCP-side helper normalises all
  qrexec failure modes (policy deny, no-such-VM, transport error) to the same
  opaque `"not found or refused"` so the lifecycle path doesn't leak either.
- **Multi-stage rollout, reversible at each step.** See `CLAUDE.md` for the
  full 8-stage design. Each stage has its own `install-*.sh`, `uninstall-*.sh`,
  and `test-*.py` in `deploy/`.

## Reviewer asks

This is human-designed, AI-assisted code, and review from people who know the
Qubes Admin API and qrexec policy (R4.2+) is genuinely wanted. The detailed,
numbered questions — existence-oracle robustness at the qrexec layer, `@tag:`
matching on `klass=DispVM`, single-egress vs. cascade as a Qubes idiom,
event-stream payload minimisation, cap-as-contract disk budgeting,
security-tag inheritance on `clone_vm` / `CreateDisposable` (a created qube
must be stripped to its umbrella, not assumed clean), and more — are written
up in **[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md)**.

Where this has been discussed:

- **qubes-devel design review** — five Admin API / qrexec questions, answered
  point by point by the Qubes project lead:
  <https://groups.google.com/g/qubes-devel/c/4NuSqL64DVE>
- **Qubes forum thread** — original write-up and discussion:
  <https://forum.qubes-os.org/t/41387>
- **Background** — the threat-model case for moving MCP trust boundaries below
  the protocol:
  <https://alexschose.com/writing/mcp-trust-boundaries-belong-below-the-protocol.html>

## Status

**Current version: 0.9.0** (pre-1.0 — see [CHANGELOG.md](CHANGELOG.md)).

Development up to 0.9.0 was tracked as lettered *stages*; that vocabulary is kept
in `deploy/` filenames and in the design document as the as-built record, and the
table below is still organised that way. Releases are versioned from 0.9.0 on.

0.9.0 is deliberately pre-1.0: the resource axis is complete and enforced, but
least privilege is not yet operable end to end — a newly created qube is born
untiered and so has no capability until an operator tiers it, which means an
operator action sits between every create and its first use. 1.0.0 is reserved
for the release that closes that gap.

Stages A through F3 land the binary trust boundary: a qube tagged
`ai-managed` is visible and acted on through the `qmcp.*` wrappers;
an untagged qube is invisible. The F band closes that surface with
disk-budget visibility (F3).

**Stage I (graduated authority) is the current work line.** It adds
*graduated* authority within `ai-managed` — resource tiers, an
action gate (per-call consent for destructive ops), per-trust-class
source qubes, a sign-only secrets vault, and persona presets — so a
hallucinating or prompt-injected agent cannot destroy real data
*inside* the boundary just because it has a qrexec channel.
Stage I lands as sub-stages I-0..I-11 in three waves; I-0 (cap-as-
gate), I-1 (read-surface scope redaction), I-2 (dom0 audit log),
I-3 (the tier taxonomy + resolution helper, landed behaviour-neutral),
I-4 (tiers on the policy-scoped surfaces), and I-5 (tiers on the wrapper
+ exec surfaces, with the least-privilege flip available) are done — all
listed below. **Wave 1 (I-0..I-5) is complete**, behaviour-neutral until
the operator tiers the fleet and runs the flip. **Wave 2 was redesigned
after a clean-room install run**: instead of an operator-authored
per-class gate matrix, a dom0 kernel *derives* each verdict from a
domination lattice, so a gate that an existing capability already
dominates cannot be written at all. Its Stage 1 (the kernel, in shadow
mode), Stage 2 (ownership, birth tier, birth egress), Stage 3a (the
tombstone and its reaper) and Stage 3b (the enforcement-mode flag and
the production smoke suite) are below — every one of them inert or in
shadow, so none has yet changed what the AI may do.
**Stage G0 (gateway input boundary) was pulled ahead of Wave 2** — a
2026-07-24 architecture review found reachable boundary breaks in the
shipped tree, so the tier-independent hardening that closes them shipped
now (see the G0 row). **The rest of Stage G (mcp-control host hardening,
G1/G2) and Stage H remain deferred** until Stage I completes — both depend
on a non-binary trust model (G1's lockdown is per-tier; H's remote reach
needs Stage I's dom0 gate-lift).

| Stage | Capability | State |
|---|---|---|
| A | Tag-scoped lifecycle + spawn + wrapped property read/write + existence hiding | tested |
| B | Root command execution + inter-qube file transfer inside ai-managed qubes | tested |
| C | Single-egress network sandbox (`ai-net-router` chokepoint, operator-chosen upstream, tag-scoped firewall control) | tested |
| D | Clone (`qmcp.CloneAIManagedQube`) + DispVMTemplate/DispVM klass support in `qmcp.SpawnAIManagedQube` + dom0 lifecycle wrapper (`qmcp.LifecycleAIManaged`) covering klass=DispVM uniformly | tested |
| E1 | Device attach/detach (`qmcp.AttachDeviceAIManaged` / `qmcp.DetachDeviceAIManaged`) between ai-managed qubes, plus tag-scoped block/usb/mic enumeration | tested |
| E2 | Ephemeral DispVMs via `qmcp.SpawnDisposableAIManaged` (auto-cleanup on shutdown) + `qubes_run_disposable` one-shot | tested |
| F1 | Wrapped `feature.Set` (`qmcp.SetFeatureAIManaged`) — `internal` denied (operator-only), opaque cross-ref for `audiovm`/`guivm`, echoes post-set value; direct `feature.Set` stays denied | tested |
| F2 | Filtered event stream (`qmcp.AIManagedEvents`) — bounded-window batch (duration clamped `[1, 120]s`) of admin events whose subject is ai-managed; minimal `{event, subject, subject_klass, ts}` payload with whitelisted `tag` kwarg for tag-add/delete; ships with the opaque-cross-ref backport on `SetPropertyAIManaged` + `SpawnAIManagedQube` (closes reviewer ask #8) | tested |
| F3 | AI-scoped disk-budget visibility (`qmcp.GetPoolStats`) — sum of the **persistent footprint** of every ai-managed qube (each `private`, plus `root` for persistent-root klasses; COW root + ephemeral volatile excluded) + operator cap from `/etc/qmcp/pool-cap` (re-read per call); returns `{used, cap, headroom}`; pool topology and operator-side volumes intentionally absent. Cap is a contract operator → AI, not a sensor. *(Accounting corrected 2026-06-12 — was every volume's provisioned size, which over-stated real usage ~8×.)* | tested |
| I-0 | F3 cap promoted from advisory signal to a hard gate on every create path (`qmcp.SpawnAIManagedQube` / `qmcp.CloneAIManagedQube` / `qmcp.SpawnDisposableAIManaged`). Refuses with opaque `"pool cap exceeded"` before the Admin API call; measurement is byte-identical to F3 (shared `qmcp_budget.py`) so AI's `(used, cap, headroom)` predicts the gate. A per-qube ceiling `/etc/qmcp/private-cap` bounds any one qube's persistent `private` (a spawn may request a bigger `private_size` up to it). Because a volume can't exceed its size, Σ persistent ≤ cap is a hard ceiling on real usage. Cross-ref refusal still wins; caps fail closed. No new RPC, no policy change. First sub-stage of Stage I. | tested |
| I-1 | Read-surface name-leak fix (finding F-3): every VM-valued property read (`netvm`/`template`/`default_dispvm`/`guivm`/`audiovm`/`management_dispvm`) and the list `template` field is routed through a shared dom0 redactor (`qmcp_scope.py`) — a referenced qube's name survives only if it is itself ai-managed, else collapses to the opaque `<out-of-scope>` sentinel; `tags` reads are filtered to the qmcp vocabulary. The read-path sibling of the F2 write-path cross-ref opacity. Patches the two read wrappers; no policy change, no new RPC. | tested |
| I-2 | Hash-chained, AI-unreachable dom0 audit log of every state-changing `qmcp.*` call. A shared dom0 helper (`qmcp_audit.py`) appends one JSON line per call to `/var/log/qmcp-audit.log` (`root:qubes` `0660`, `O_APPEND` + `flock`); each line carries the sha256 of the previous, so any edit/delete/reorder breaks the chain (`verify()` + a `python3 qmcp_audit.py verify` CLI re-check it). The 8 state-changing wrappers route their single `emit()` funnel through `audit()` and log a whitelisted summary (qube names / property + feature keys / action) — never a property/feature value. Best-effort (never blocks an op); AI-unreachable by construction (no service reads the log; no policy line exposes it). Foundational before the tier model. No new RPC, no policy change. | tested |
| I-3 | Tier taxonomy + dom0 tier-resolution helper — the keystone of the resource axis. Graduates the binary boundary into a cumulative ladder within ai-managed: `ai-managed` (read floor) < `ai-exec` (+commands) < `ai-net` (+firewall write) < `ai-full` (+lifecycle/property/clone/spawn/feature/attach/detach); `ai-dump` is an orthogonal copy-IN-only sink. A shared dom0 helper (`qmcp_tier.py`, sibling-loaded like `qmcp_budget`/`qmcp_scope`/`qmcp_audit`) exposes `effective_capabilities(vm)` → a frozenset of capability tokens, so the wrappers ask `CAP_FULL in caps` and stay decoupled from the taxonomy. Behaviour-neutral: ships inert (no wrapper sources it until I-5) in compat mode (untiered ai-managed = full = today's boundary). AI can neither mutate tags (keystone) nor read the tier tags (a `tags` read stays `["ai-managed"]` — the authority topology is not an oracle). Two-phase migration: enforce in I-4/I-5, then flip `/etc/qmcp/tier-default` to `ro` for least privilege. No new RPC, no policy change. | tested |
| I-4 | First enforcement step of the resource axis — a single-file policy diff graduating the directly-`@tag:`-scoped surfaces. `firewall.Get` + device-list stay at the `ai-managed` ro-floor; `firewall.{Set,Reload}` move to `@tag:ai-net` + `@tag:ai-full`; `ai-dump` gets a dedicated copy-IN-only `qubes.Filecopy * @tag:ai-managed @tag:ai-dump allow` (the Biba write-only sink — a **pure** `ai-dump` qube is push-only and invisible to reads/list/exec because it lacks the umbrella; the write-only property rests on the operator invariant that an `ai-dump` qube is never also `ai-managed`, which the installer checks and I-5 enforces). The policy layer matches tags literally and cannot call `qmcp_tier`, so firewall-write ships with a `@tag:ai-managed` **compat backstop** (keeps untiered qubes writable through migration → A–F3 stays green and the live egress qube keeps firewall control on deploy; behaviour-neutral on firewall in compat — only the `ai-dump` valve is new live behaviour). The flip (end of I-5) deletes the backstop **and** writes `ro` to `/etc/qmcp/tier-default` in one change. Policy-only; no new RPC, no new qube, no wrapper change. Proven offline (100-check policy simulation, compat + post-flip), a per-tier hardware slot, and an AI-side transparency test. | tested |
| I-5 | Second enforcement step — tiers on the `@adminvm` **wrapper** surfaces (dom0 code) + the **exec** surfaces (policy), then the least-privilege flip. Lifecycle/SetProperty/SetFeature require `ai-full` on the target, Clone on the source, Spawn on the template, SpawnDisposable on the DVMT, Attach/Detach on **both** endpoints — via the sibling-loaded `qmcp_tier` helper, **fail-closed** (a missing/broken resolver denies, never allows). `RunInAIManaged`/`CopyToAIManaged` graduate in policy to `@tag:ai-exec`/`ai-net`/`ai-full` + a `@tag:ai-managed` compat backstop (mirrors I-4 firewall). Every create path **strips** any tier tag the platform propagates — `clone_vm` copies the source's tags, `CreateDisposable` inherits the DVMT's — so a created qube is always untiered (umbrella only); without the strip, AI could clone an `ai-full` qube into another and self-escalate past the flip. Behaviour-neutral in compat (untiered = full). The flip (separate slot, after the operator tiers the fleet) deletes **four** compat backstops (firewall.Set/Reload + Run/Copy) **and** writes `ro` to `/etc/qmcp/tier-default` in one coupled change. No new RPC, no new qube, no new ring. Proven offline (260 checks: wrapper-gate suite + policy simulator + I-4 regression) and on dom0 hardware (per-tier gate + the create-path strip, read back via `qvm-tags` in dom0 since tier tags are AI-unreachable). | tested |
| G0 | Gateway input boundary (pulled ahead of Wave 2 after the 2026-07-24 review). Property allowlist — `provides_network` operator-only (no self-minted egress); qrexec target-name validator (`@adminvm`/`dom0`/malformed rejected before any call); device enumeration (attached + available) routed through the dom0 redactor `qmcp.ListAttachedDevicesAIManaged` that hides out-of-scope backend/consuming-frontend qube names, with direct `admin.vm.device.*` enumeration denied; `qubes.Filecopy` re-tiered to `ai-exec` on **both** endpoints + explicit deny (no fleet-wide push into `ai-ro` qubes); `mask_error_details` + opaque error collapse. Closes four review findings; offline + per-fix hardware slots green. | tested |
| W2-1 | Wave 2 Stage 1 — the capability decision kernel (`qmcp_caps.py`), in **shadow mode**. `decide(actor, service, action, targets)` resolves first-match-wins: a target outside the umbrella → DENY; an escalation-class op (tag writes, `provides_network`, `template`, `netvm`, `name`, TemplateVM create) → DENY at every tier forever; a target in the operator's guarded class → GATE, checked *before* the domination logic so it cannot be argued away; an op an already-held capability fully dominates → ALLOW; else the `CAP_*` ladder. The anti-theatre rule is why gating `remove` while the actor holds exec is refused as a design — exec already reaches `rm -rf`, so the dialog protects nothing and trains the operator to click through. Enforces nothing: each of the 8 state-changing wrappers asks the kernel the question its I-5 gate just answered and records only a *disagreement*, as an optional `shadow` field omitted when they agree, so an agreeing call's audit line and chain hash are byte-identical to pre-Stage-1. Fail-**open** by design — the one inversion in the codebase, because it is not a gate. That divergence log is the deliverable and gates the later flip. | tested |
| W2-2 | Wave 2 Stage 2 — **ownership + birth tier + birth egress**; the first stage that deliberately changes create-path behaviour, because it is what makes least privilege *operable*. A created qube is stamped atomically with the umbrella, `qmcp-owner_<principal>` (provenance in the project's reserved namespace — never `created-by-*`, which qubesd stamps with the calling domain and so cannot distinguish AI-created from operator-created), the source's **literal** tier clamped by the operator-owned `/etc/qmcp/birth-ceiling`, and every **restriction** the source carried (`qmcp-guarded`, `qmcp-egress-locked_*`, `anon-vm`) — restrictions inherit unconditionally, since a restriction the privilege clamp can remove is a laundering hole. The stamp is read back and any mismatch **rolls the create back**. Netvm is likewise **inherited** rather than defaulted: the source's egress, else the calling gateway's, else `/etc/qmcp/birth-egress`, else refuse — replacing a hardcoded `ai-net-router` that gave adopters network-less qubes and, on a multi-egress fleet, let a Tor-side agent spawn a clearnet qube. Reading the source's *literal* tag rather than its effective capability keeps the stage neutral in compat (an untiered source still yields an untiered child) and correct after the flip. **Scope, stated plainly: this governs BIRTH egress only** — retargeting an *existing* qube across egress classes is still permitted at `ai-full`, and that is the more dangerous half (a new qube is empty; an existing one may hold Tor-derived data). The kernel already answers escalation-class DENY for a `netvm` write but runs in shadow, so retarget closes when enforcement flips to `decide()`. Self-escalation stays impossible — nothing is born above its source, and tiers are operator-assigned because AI cannot write tags. Also deletes `server.py`'s declarative `_RING_MIN_TIER`: nothing above the dom0 boundary may resemble a control. Proven offline (96 checks across a logic suite and a wiring suite whose mocks reproduce qubesadmin's real tag/netvm propagation and carry teeth asserting they still do); the tier and owner tags are AI-unreachable by design, so hardware proof is a `qvm-tags` read in dom0. | built — pending hardware |
| W2-3a | Wave 2 Stage 3a — **the tombstone mechanism and its reaper, INERT**. The compensating control the enforcement flip needs, shipped ahead of it so the window exists before the capability that needs it. New shared dom0 lib (`qmcp_tombstone.py`) owns the transition an AI-initiated remove will take when Stage 3c flips: halted-first (enforced, not assumed), add the `qmcp-tombstone_<epoch>` marker, strip the umbrella and every privilege tag, carry restrictions forward, read back and roll back on any mismatch. Add-before-strip so a crash mid-transition leaves the loud half-state (visible, charged, reported stuck) rather than the silent one (invisible, uncharged, unreapable — a permanent pool leak). New root systemd oneshot (`qmcp-tombstone-reaper`) runs on a 1h timer with an `OnBootSec=15min` grace so the operator has a chance to look before the boot's first reap; its veto matrix is umbrella-present, running, undatable, malformed retention, marker dated in the future — every veto is independent. **Reaping is timer-only** by decision: an under-pressure early-reap path is one an AI could drive to destroy evidence before the operator reads it (the I-2 chain records operations, not contents). And `qmcp_budget.sum_ai_managed_persistent_bytes` now charges anything carrying the umbrella OR the tombstone marker — the security half of the tombstone, because the pre-fix predicate would have made a tombstone free, letting an `ai-exec` actor create-and-remove in a loop to park unbounded disk outside the accounting for the whole retention window. `qmcp.GetPoolStats` and every create gate share the one function so they cannot drift. **Behaviour-neutral: proven by invariance, not regression.** Nothing creates a tombstone yet — `qmcp.LifecycleAIManaged` still removes outright — so with no tombstone present the new summation is byte-identical to the old one; the AI seat's `GetPoolStats` reads exactly the pre-deploy bytes. Proven offline (92 checks including teeth that reproduce the create/remove churn bypass under the pre-fix predicate before asserting the shipped one closes it) and on dom0 hardware (pre/post pool sum byte-identical, timer active + enabled, one systemd service run finished clean, reaper `--list`/`--dry-run` both report zero tombstones). No policy change; no qrexec daemon restart; no new RPC service. | tested |
| W2-3b | Wave 2 Stage 3b — **the enforcement-mode flag and the production smoke suite, INERT**. The switch the coming flip is made and unmade with, plus the gate that decides whether it may happen. New shared dom0 lib (`qmcp_enforce.py`) re-reads the operator file `/etc/qmcp/enforce-mode` per call. **Three modes, not two, and the third is forced rather than chosen.** Every previous flip here was monotone — `tier-default` only ever removed authority, so a corrupt file could fail closed to least privilege. The enforcement flip is *bidirectional*: it narrows the escalation class (`netvm`/`template`/`name`/`provides_network` stop being writable) and simultaneously **widens** lifecycle, because the anti-theatre invariant grants `remove`/`kill`/`shutdown`/`start` at `CAP_EXEC`. So `enforce` is not uniformly safer than `shadow`, and a malformed flag must not land there — it would arm irreversible qube destruction for every `ai-exec` actor on the strength of a typo. `strict` (allow only what the wrapper **and** the kernel allow) is safer than both: every narrowing, no widening. That makes it the only correct fail-closed target, and having been forced into existence it is also the right intermediate rollout step — Stage 3a's tombstone is what makes the widening survivable, so `strict` lets the narrowing half arm ahead of the flip. **No policy backstop, deliberately**, though every prior flip had one. Of the decision kernel's 19 lattice surfaces, the 13 this flip governs are dom0 *wrapper* services scoped `* mcp-control @adminvm allow` with no tag matching — the wrapper reads the flag directly, so a backstop line would back up nothing while reading as a control. The other 6 are `@tag:`-scoped and decided by the qrexec engine before any of this code runs; the flag cannot govern them and does not need to, because Stages I-4, I-5 and G0c graduated each of them with its own COMPAT backstop and those flips are done. Revert is one write — no policy reload, no daemon restart. **The gate** (`deploy/smoke-production.py`) implements the seven-item production smoke suite and reports **four** outcomes, because two would be a lie: PASS / FAIL / VACUOUS (ran, but the fleet's shape means it could not have failed) / NOT-RUN (needs a tool outside this repo). Exit 0 GREEN, 2 FAILED, **3 INCOMPLETE — and INCOMPLETE is not green**; a suite counting an unrunnable check as a pass reports green while a third of the gate never ran. Two items assert properties of deployment-specific tooling that is deliberately **not vendored** here (a suite shipping its own copy of the thing it smoke-tests tests the copy); they are declared in an operator-local conf, and undeclared is NOT-RUN. Item 1 is an **invariance** check against a recorded baseline rather than "exec works in every ai-managed qube" — an ai-managed AppVM off an operator template has no exec service to answer, and from the AI seat that is byte-identical to a tier refusal *by design*, so the absolute is false on a normal fleet. **Behaviour-neutral: proven by invariance, not regression** — nothing sources the flag until Stage 3c, so the diff over the wrappers, the policy and the template RPCs is empty. Proven offline (91 checks, with teeth that reproduce both directions of divergence against the real decision kernel and the destruction a two-mode rule would have armed on a typo) and on dom0 hardware (installs idempotently, resolves to `shadow`, fleet unchanged). No policy change; no qrexec daemon restart; no new RPC service; no operator file created. | tested |
| FIX | **Security fixes from an adversarial pass (2026-08-18)** — five findings, each reproduced from the AI seat against a live fleet before being fixed and re-attacked afterwards. **The create paths were a full-host existence oracle**: both validated a requested name against the whole host's domain list and echoed it back (`qube 'vault' already exists`), so AI could confirm any qube name it could guess — measured at 11 out-of-scope qubes, through the agent-facing tool, while every *read* surface redacts exactly those. Fixed with a **reserved name namespace**, not a better message: a create has three outcomes and AI can already enumerate one of them, so a uniform refusal still leaks by subtraction and by timing; the only way to remove the oracle is to make the third outcome impossible. AI now proposes names only inside a reserved prefix (`/etc/qmcp/name-prefix`, absent = `ai-`), and anything outside it is refused **on shape alone, before any host lookup**, in constant time. **An egress retarget is now refused** (`netvm = null` still allowed, mirroring the birth path's de-escalation carve-out): with birth enforced but retarget open, four routes still reached a cross-egress qube, the sharpest needing no `netvm` argument at all — retarget a source, then clone it, and §3.4's own source-outranks-principal rule inherits the egress the agent just chose. Birth-egress enforcement is worth exactly what retarget enforcement is worth. Also: **no raw dom0 exception text reaches the AI seat** (eleven sites; one was measured leaking the dom0 storage pool name and LVM path), and `private_size` now rejects a float and a bool instead of coercing them. **BREAKING** for adopters whose agents create qubes outside the `ai-` prefix, or rely on retargeting an existing qube's netvm. Proven by 69 offline checks with teeth reproducing each vulnerable behaviour under the pre-fix predicate, plus a re-run of every original attack against the deployed fix. | tested |
| G1/G2 | mcp-control host hardening (sudo lockdown, dedicated MCP user) + Tor hidden service for sshd → mobile CLI reach | designed — deferred until Stage I completes |
| H | FastMCP HTTP/SSE bound to a second .onion → mobile-app reach | designed — deferred until Stage I completes |

See `CLAUDE.md` for the full design document — trust model, anti-goals, file
layout, and operating protocol.

## Naming conventions (load-bearing)

The qrexec policy file references two names that must match your system:

- **`mcp-control`** — the qube that runs this MCP server. The policy file
  hard-codes this as the source for every `allow` rule. If you must use a
  different name, change every `mcp-control` token in
  `policy/30-mcp-control.policy` *and* in the install scripts before deploying.
- **`ai-managed`** — the qrexec tag that defines the sandbox. Don't rename
  unless you also update every `@tag:ai-managed` reference in the policy and
  every `"ai-managed"` literal in the `qmcp.*` scripts.

The Python package directory is `qubes_mcp/` inside the repo root. If you
`pip install -e .` inside your venv (recommended), the package resolves
natively and the test scripts' fallback `sys.path` insert is harmless.

## Setup

This involves three locations on a Qubes host:

1. The `mcp-control` qube — runs the MCP server, holds the working tree.
2. Dom0 — receives the qrexec policy and the `qmcp.*` services.
3. One ai-managed template — receives `qmcp.RunInAIManaged` and `qmcp.CopyToAIManaged`
   in Stage B (the install script handles this).

### Step 1 — Create `mcp-control` and install dependencies

In dom0:

```
qvm-create --class StandaloneVM --label gray --template debian-13 mcp-control
```

Then in the new qube:

```
sudo apt install -y qubes-core-admin-client openssh-server ca-certificates git python3-venv
git clone https://github.com/alex-schose/qubes-mcp.git qubes_mcp
cd qubes_mcp
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e .
```

`--system-site-packages` lets the venv see `qubesadmin` (provided by the
`qubes-core-admin-client` apt package). `pip install -e .` installs the
`qubes_mcp` package in editable mode using `pyproject.toml`; this provides
the `qubes-mcp-server` console entrypoint and lets the tests find the
package by name from any working directory.

### Step 2 — Deploy Stage A (from dom0)

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-a.sh' > /tmp/install-a.sh
less /tmp/install-a.sh         # review before executing
bash /tmp/install-a.sh mcp-control ~user/qubes_mcp
```

The two positional arguments are the source qube and the path to the repo
inside it. Defaults: `mcp-control` and `/home/user/qubes_mcp`. Pass them
explicitly if you cloned to a different location.

The script clones `debian-13` → `ai-debian-13` (if needed), tags it
`ai-managed`, and installs the policy + qmcp scripts.

### Step 3 — Verify Stage A (from mcp-control)

```
cd ~/qubes_mcp
.venv/bin/python deploy/test-stage-a.py
```

(All test scripts work from any cwd — they self-locate the package.)

Expect five PASS markers: existence-leak hidden; SetProperty cross-ref
opaque byte-identical; Spawn template cross-ref opaque byte-identical;
policy refusal on untagged; remove confirmation. The opaque-cross-ref
assertions land in the Stage A wrappers that `install-stage-a.sh`
ships today (they were backported in the Stage F2 bundle — see
reviewer ask #8), so a fresh install passes 5/5. If you're upgrading
an older deployment, expect the SetProperty and Spawn cross-ref
markers to FAIL until you ship Step 10 (which replaces the older
wrappers with the opaque-collapse versions).

### Step 4 — (Optional) Deploy Stage B for command exec + file transfer

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-b.sh' > /tmp/install-b.sh
bash /tmp/install-b.sh mcp-control ~user/qubes_mcp
```

Stage B briefly starts the `ai-debian-13` template, installs the two
template-side services into `/etc/qubes-rpc/`, and shuts the template back
down to commit changes.

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-b.py
```

Four more PASS markers.

### Step 5 — (Optional) Deploy Stage C for the single-egress network sandbox

Stage C creates one ai-managed network qube — `ai-net-router` — that all
AI qubes route through by default. The operator chooses ai-net-router's
upstream in dom0 (`sys-firewall` for clearnet, `sys-whonix` for Tor, a
VPN qube, or `""` for offline); AI cannot change this. AI can still read
and set firewall rules on `ai-net-router` and on its own qubes.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-c.sh' > /tmp/install-c.sh
EGRESS_UPSTREAM=sys-firewall bash /tmp/install-c.sh mcp-control ~user/qubes_mcp
```

Configurable via env vars (with defaults):

- `EGRESS_UPSTREAM=sys-firewall` — ai-net-router's netvm (any existing qube, or `""`).
- `EGRESS_TEMPLATE=fedora-43-xfce` — the AppVM template for ai-net-router.
- `EGRESS_LABEL=red` — Qubes colour.
- `EGRESS_MEMORY=500` — RAM in MiB.

Switch the upstream any time:

```
qvm-prefs ai-net-router netvm <new-upstream>
```

**Gateway placement (load-bearing — put `mcp-control` behind the egress qube).**

```
qvm-prefs mcp-control netvm ai-net-router
```

From Wave 2 Stage 2 on, a qube the AI creates inherits its network path rather
than getting a hardcoded default: the creation source's netvm if it has one,
else the calling gateway's, else the name recorded in `/etc/qmcp/birth-egress`,
else the create is refused. A spawn from a *template* has no source egress to
inherit — a template's netvm is an update path, not a workload egress — so the
gateway's own placement is what answers, and a gateway parked outside the
sandbox falls back to the configured constant for every such create. Stage C's
installer writes that constant and warns when the gateway is not behind an
ai-managed egress qube, so nothing silently breaks either way; placing the
gateway correctly is what makes inheritance mean the fleet's real topology.

**The trade-off, stated rather than buried.** A gateway behind an
AI-controllable netvm means an agent holding `ai-net` or `ai-full` on that
egress qube can rewrite its firewall or shut it down — and take out its own
transport. That is self-denial-of-service, recoverable only from dom0. It is
not an escalation (the agent gains nothing it did not already have on that
qube), and the alternative — parking the gateway outside the sandbox — trades
it for birth egress that no longer tracks the real topology. Pick knowingly.

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-c.py
```

Eight PASS markers — egress visibility, default-netvm application,
explicit-null preservation, egress-qube lock, AI-qube netvm retarget,
firewall rules round-trip, untagged-target refusal, and former-ai-sys
invisibility.

### Step 6 — (Optional) Deploy Stage D for cloning + DispVM klass support

Stage D adds three things: `qmcp.CloneAIManagedQube` (clone an ai-managed
qube into a new ai-managed qube), the `DispVMTemplate` and `DispVM`
klasses in `qmcp.SpawnAIManagedQube`, and `qmcp.LifecycleAIManaged` (a
dom0 wrapper that replaces the Stage A `admin.vm.*` tag-scoped lifecycle
allow lines because qrexec's `@tag:` selector doesn't reach klass=DispVM
targets — see reviewer ask #6). No new dom0 provisioning — only the
policy + RPC scripts change.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-d.sh' > /tmp/install-d.sh
bash /tmp/install-d.sh mcp-control ~user/qubes_mcp
```

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-d.py
```

Six PASS markers — clone of ai-managed succeeds, clone of untagged
refuses opaquely, DispVMTemplate spawn sets `template_for_dispvms`,
DispVM spawn inherits template + ai-managed tag, DispVM from a plain
TemplateVM is refused by the `template_for_dispvms` cross-ref, and
end-to-end usability (start ai-dvm + run `whoami` as root inside via
`qmcp.RunInAIManaged` + clean shutdown — proves the
ai-debian-13 → DVMT → DispVM service-inheritance chain).

### Step 7 — (Optional) Deploy Stage E1 for device attach between ai-managed qubes

Stage E1 adds two dom0 wrappers (`qmcp.AttachDeviceAIManaged`,
`qmcp.DetachDeviceAIManaged`) that attach virtual block/USB/mic devices
between ai-managed qubes. Both backend and frontend must be ai-managed;
the wrapper collapses missing/untagged on either side to opaque
`"not found"`. Read-only enumeration (`admin.vm.device.{class}.{List,
Available}`) is tag-scoped at the policy layer — same shape as Stage C
firewall reads. No new qube provisioning.

In practice, **block** is the useful case (e.g. shared scratch volume
between two ai-managed AppVMs). **USB** requires `sys-usb` to be
ai-managed and **mic** requires the audio backend to be ai-managed —
both operator opt-ins. Default install leaves these dormant; the
wrappers are ready when the operator chooses to tag those backends.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-e1.sh' > /tmp/install-e1.sh
bash /tmp/install-e1.sh mcp-control ~user/qubes_mcp
```

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-e1.py
```

Six PASS markers (hard): tag-scoped list on ai-managed backend
succeeds; list on untagged refuses opaquely; attach refuses when
either endpoint is untagged; same for detach. Plus a SOFT block of
informational checks for a real loop-device round-trip (template-
dependent — qubes-core-agent's block enumerator may or may not
auto-expose `/dev/loop*` on a given Debian build, so those are
reported but not counted toward the pass total).

### Step 8 — (Optional) Deploy Stage E2 for ephemeral DispVMs

Stage E2 adds `qmcp.SpawnDisposableAIManaged` — a dom0 wrapper around
`admin.vm.CreateDisposable`. The DVMT (DispVMTemplate, created in
Stage D) must be ai-managed and have `template_for_dispvms=True`;
the auto-named disposable (`dispXXXX`) is force-tagged before AI
sees it; `auto_cleanup=True` is the Admin API default, so dom0
removes the qube once it halts. `admin.vm.CreateDisposable` stays
denied — the wrapper is the only allowed path.

MCP also ships `qubes_run_disposable(template, cmd)` — a one-shot
that composes spawn → start → run → shutdown without adding any
new dom0 surface. The typical "fire a throwaway, get its output,
move on" pattern collapses to a single call.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-e2.sh' > /tmp/install-e2.sh
bash /tmp/install-e2.sh mcp-control ~user/qubes_mcp
```

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-e2.py
```

Five PASS markers: spawn+tag+klass+template+auto_cleanup; start+
whoami=root+shutdown+auto-removed; plain-TemplateVM cross-ref
refusal; untagged-DVMT opaque refusal; one-shot end-to-end.

### Step 9 — (Optional) Deploy Stage F1 for feature.Set

Stage F1 adds `qmcp.SetFeatureAIManaged` — a dom0 wrapper around
`admin.vm.feature.Set` on ai-managed qubes. The `internal` feature is
refused (operator-only — AI must not hide a qube from your menus), and
the cross-VM keys `audiovm`/`guivm` must point at an ai-managed qube
(refused opaquely otherwise). Direct `admin.vm.feature.Set` stays
denied — the wrapper is the only path — and no feature-read surface is
exposed (the wrapper echoes the post-set value instead). No new dom0
provisioning — only the policy + RPC script change.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-f1.sh' > /tmp/install-f1.sh
bash /tmp/install-f1.sh mcp-control ~user/qubes_mcp
```

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-f1.py
```

Five PASS markers: round-trip set + value echo + boolean coercion;
`internal` refused; cross-ref to an ai-managed qube accepted;
cross-ref to an untagged AND a nonexistent qube both refused with the
same opaque message (no existence leak); feature.Set on an untagged
qube refused with the opaque `"not found"`.

### Step 10 — (Optional) Deploy Stage F2 for filtered event streaming

Stage F2 adds `qmcp.AIManagedEvents` — a dom0 wrapper that subscribes
to `admin.Events` with full admin authority, filters every event by
the ai-managed tag on its subject, and returns the collected batch
when the caller-given duration (clamped to `[1, 120]` seconds)
elapses. No persistent dom0 process — one invocation, one window,
one JSON response, exit. Direct `admin.Events` stays denied — the
wrapper is the only path. AI catches the immediate consequence of an
action by opening the window FIRST (a concurrent tool call) and then
acting; the bounded-window model trades inter-call event coverage for
a stateless dom0 footprint.

This step also backports the opaque-cross-ref collapse to
`qmcp.SetPropertyAIManaged` and `qmcp.SpawnAIManagedQube` (closes
reviewer ask #8 — the same existence-oracle gap F1 closed on
SetFeatureAIManaged, finally aligned across all write/spawn surfaces).

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-f2.sh' > /tmp/install-f2.sh
bash /tmp/install-f2.sh mcp-control ~user/qubes_mcp
```

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-a.py    # 5 PASS — re-verifies the opaque-collapse backport
.venv/bin/python deploy/test-stage-f1.py   # 5 PASS — unchanged
.venv/bin/python deploy/test-stage-f2.py   # 5 PASS — new events surface
```

Stage F2's five PASS markers: ai-managed `domain-start` IS surfaced
inside the window; no event with a non-ai-managed subject leaks
through; `qube` filter restricts the batch to the requested qube;
`qube` filter is opaque on missing/untagged (byte-identical
`"not found"`); `events` filter restricts the batch to event names
matching exactly OR as a `"<entry>:"` prefix.

### Step 11 — (Optional) Deploy Stage F3 for AI disk-budget visibility

Stage F3 adds `qmcp.GetPoolStats` — a dom0 wrapper that returns the
total **persistent** provisioned footprint across every ai-managed
qube (each `private`, plus `root` for persistent-root klasses; COW
root and ephemeral volatile excluded — corrected 2026-06-12, was every
volume), plus an operator-set ceiling read from `/etc/qmcp/pool-cap`.
AI gets `{used, cap, headroom}` and can self-throttle spawn loops
before the cap is hit. Pool names, free-space, total-pool-size, and
any operator-side volume are intentionally absent — the wrapper
returns only AI's own footprint and the budget the operator gave it.

The cap is operator-defined, not operator-observed (a "free-space"
shape would have been a streaming operator-side oracle — free bytes
drop whenever the operator does anything). The cap file is a single
integer (bytes); the install script seeds it with 50 GiB if absent,
and the wrapper re-reads it on every call so operator edits take
effect immediately with no daemon restart. Direct `admin.pool.*` and
`admin.vm.volume.{List,Info}` stay denied — the wrapper bypasses
those over the local dom0 socket. No new dom0 provisioning beyond
the wrapper + policy + cap file.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-f3.sh' > /tmp/install-f3.sh
bash /tmp/install-f3.sh mcp-control ~user/qubes_mcp
```

To change the budget any time (no redeploy needed):

```
sudo sh -c 'echo 107374182400 > /etc/qmcp/pool-cap'   # 100 GiB
```

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-f3.py
```

Four PASS markers: response shape + arithmetic invariant
(`used + headroom == cap` when within cap); untagged operator
volumes excluded (sanity bound); spawn-delta positive + remove
returns to baseline; payload ignored (empty kwargs whitelist).
Plus a SOFT manual block confirming cap-file edits take effect on
the next call without a policy-daemon restart.

### Step 12 — (Optional) Deploy Stage I-0 to enforce the F3 pool cap

Stage I-0 promotes the F3 pool cap from an advisory signal that AI
is expected to self-throttle on into a hard gate that runs in every
create wrapper before the Admin API call. Without this, a
hallucinating or prompt-injected agent can ignore F3's
`(used, cap, headroom)` and spawn past the budget (the F-1 finding
that motivated this sub-stage). With it, every
`qmcp.SpawnAIManagedQube`, `qmcp.CloneAIManagedQube`, and
`qmcp.SpawnDisposableAIManaged` call computes
`projected = current_ai_managed_used + estimate_from(new_qube)`
and refuses with the opaque `"pool cap exceeded"` if
`projected > cap`. *(Accounting corrected 2026-06-12 — matching the I-0
row in the Status table above: `used` meters the **persistent**
footprint (each `private`, plus `root` only for persistent-root
klasses), the estimate is the new qube's `private`, and a per-qube
`/etc/qmcp/private-cap` bounds any single qube. The form that shipped
first summed every volume's provisioned size, ~8× over-counting.)*

Measurement is byte-identical to F3's `qmcp.GetPoolStats`, so AI's
view of `(used, cap, headroom)` predicts the gate's behaviour
exactly — there's no new oracle. The cross-ref refusal still fires
first, so an untagged template surfaces the same opaque cross-ref
message before the gate runs. Cap-missing/malformed/negative fail
closed with F3's existing `"pool cap not configured"` (F3's install
seeds the cap, so the unconfigured state is a deliberate operator
action). The enforcement logic lives in a shared dom0 helper
(`/etc/qubes-rpc/qmcp_budget.py`) sibling-loaded by each wrapper.

I-0 does **not** add a new RPC service, does **not** change the
qrexec policy, and does **not** restart the policy daemon.
`qmcp.GetPoolStats` stays read-only — enforcement lives in the
writes, the read is the signal.

Stage F3 is a prerequisite (it seeds `/etc/qmcp/pool-cap`).

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-0.sh' > /tmp/install-I-0.sh
bash /tmp/install-I-0.sh mcp-control ~user/qubes_mcp
```

Then from mcp-control:

```
.venv/bin/python deploy/test-stage-I-0.py
```

Four probes (Spawn / Clone / SpawnDisposable + GetPoolStats
shape). Each probe always attempts its create surface and
classifies the response across three valid outcomes:

- `ok=True` → wrapper proceeded under headroom (HARD).
- `"pool cap exceeded"` → gate fired under cap pressure (SOFT S1).
- `"pool cap not configured"` → gate fired fail-closed (SOFT S2).

Any other response is a FAIL. The same test therefore PASSes
under every cap state; reading the response JSON above each
probe tells you which gate path actually fired.

Two SOFT operator-driven cap manipulations exercise S1 and S2:

1. **Lower the cap below the current `used`** (in dom0:
   `sudo sh -c 'echo <NEW_BYTES> > /etc/qmcp/pool-cap'`), re-run
   the test, and the response lines now carry
   `"error": "pool cap exceeded"` across all three create
   surfaces.
2. **Remove the cap file** (`sudo rm /etc/qmcp/pool-cap`), re-run,
   and the response lines now carry
   `"error": "pool cap not configured"`.

Restore the original cap value after testing.

### Step 13 — (Optional) Deploy Stage I-1 to close the read-surface name leak

Stage I-1 closes finding F-3. The wrapped reads were opaque on a qube's
*existence* (a missing or untagged target returns the uniform
`"not found"`) but not on a property *value* that referenced another
qube: `qmcp.GetPropertyAIManaged` serialised any VM-valued property
(`netvm`, `template`, `default_dispvm`, `guivm`, `audiovm`,
`management_dispvm`) to the referent's raw name, and
`qmcp.ListAIManagedQubes` did the same for its `template` field — so a
single read of an ai-managed qube could enumerate out-of-scope operator
qube names.

With I-1 both wrappers route every VM-valued result through a shared
dom0 redactor (`/etc/qubes-rpc/qmcp_scope.py`): a referenced qube's name
is emitted only if that qube is itself `ai-managed`, otherwise it
collapses to the opaque `<out-of-scope>` sentinel. The `tags` read is
filtered to the qmcp vocabulary (it was previously hidden only by the
accidental non-serialisability of the `Tags` object). Labels and scalars
pass through unchanged, and existence-hiding on the lookup channel is
unchanged. This is the read-path sibling of the Stage F2 write-path
cross-ref opacity, and it is fail-closed: a read refuses if the redactor
can't load.

I-1 does **not** add a new RPC service, change the qrexec policy, or
restart the policy daemon.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-1.sh' > /tmp/install-I-1.sh
bash /tmp/install-I-1.sh mcp-control ~user/qubes_mcp/public
```

Then verify from mcp-control:

```sh
.venv/bin/python deploy/test-stage-I-1.py     # 5 PASS
```

`deploy/uninstall-stage-I-1.sh` reverts (restore the pre-I-1 wrappers,
then remove the helper).

### Step 14 — (Optional) Deploy Stage I-2 for the dom0 audit log

Stage I-2 adds a tamper-evident, AI-unreachable record of every
state-changing `qmcp.*` call. A shared dom0 helper
(`/etc/qubes-rpc/qmcp_audit.py`) appends one JSON line per call to
`/var/log/qmcp-audit.log` (`root:qubes` `0660`, `O_APPEND` + `flock`); each
line carries the sha256 of the previous line, so any deletion or edit
breaks the chain. The 8 state-changing wrappers (Spawn / Clone /
SpawnDisposable / SetProperty / SetFeature / Lifecycle / Attach /
Detach) each route their single response funnel through `audit()`, so
every call leaves exactly one chained line, and log only a whitelisted
summary (qube names / property + feature keys / action) — never a
property or feature value.

The log is owned `root:qubes` `0660`: dom0 qrexec services run as a
non-root user that is in the `qubes` group (it must be, to reach
qubesd), so group-write is what lets the wrappers append — a `root:0600`
log would be silently unwritable by them. The installer sets this
ownership; the wrappers only append.

Logging is **best-effort**: a failure never blocks or alters an
operation. The log is **AI-unreachable by construction** — no `qmcp.*`
service reads or writes an arbitrary dom0 path and no policy line
exposes it, so an ai-managed qube can neither read past entries nor
forge new ones (AI has no dom0 file access at all; the `qubes`-group
write applies only to dom0-local processes, never to AI). I-2 does
**not** add a new RPC service, change the qrexec policy, or restart the
policy daemon.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-2.sh' > /tmp/install-I-2.sh
bash /tmp/install-I-2.sh mcp-control ~user/qubes_mcp/public
```

Inspect and verify the trail in dom0:

```sh
sudo tail -n 5 /var/log/qmcp-audit.log
sudo python3 /etc/qubes-rpc/qmcp_audit.py verify     # walks the chain
```

Then check transparency from mcp-control (the log is unreadable from
here by design — chain integrity is verified in dom0, above):

```sh
.venv/bin/python deploy/test-stage-I-2.py     # 3 PASS
```

`deploy/uninstall-stage-I-2.sh` removes the helper (safe — the hook is
best-effort, so the wrappers keep working without it); `/tmp/run.sh
revert` restores the pre-I-2 wrapper source too.

### Step 15 — (Optional) Deploy Stage I-4 for tiered policy surfaces

Stage I-4 is the first enforcement step of the resource axis — a
**single-file policy diff** (no new RPC script, no new qube, no wrapper
change). It graduates the directly-`@tag:`-scoped surfaces:

- `firewall.Get` and `device.*.{List,Available}` stay at the `ai-managed`
  ro-floor (unchanged).
- `firewall.{Set,Reload}` move to `@tag:ai-net` + `@tag:ai-full`.
- `ai-dump` gets a dedicated `qubes.Filecopy * @tag:ai-managed @tag:ai-dump
  allow` — a copy-IN-only sink. A **pure** `ai-dump` qube is **not** tagged
  `ai-managed`, so every read / exec / firewall / device surface misses it
  by construction: AI can push data to it but never read it back. **Operator
  invariant:** an `ai-dump` qube must never also be `ai-managed` — a hybrid is
  fully readable (the inter-copy line matches it as a source), defeating the
  valve. AI cannot create one (it cannot mutate tags), and the installer warns
  on any hybrid; I-5 machine-refuses it at fleet-tiering.

The policy layer matches `@tag:` selectors literally and cannot call the
`qmcp_tier` helper, so it cannot honour the helper's "untiered = `ai-full`
(compat)" default. I-4 therefore ships firewall-write with a `@tag:ai-managed`
**compat backstop** that keeps untiered umbrella qubes writable through
migration — so the A–F3 regression stays green and the live egress qube keeps
firewall control the moment you deploy. While the backstop is present the
firewall-write surface is **behaviour-neutral**; the one new live capability is
the `ai-dump` valve. The **flip** (end of Stage I-5) deletes the two backstop
lines **and** writes `ro` to `/etc/qmcp/tier-default` in the same change, so the
policy surface and the wrapper surface drop to least-privilege together. This
step does not require the I-3 helper to be installed (the policy layer never
sources it).

From dom0 (the installer validates the policy before replacing the live file —
a malformed policy can break all of qrexec):

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-4.sh' > /tmp/install-I-4.sh
bash /tmp/install-I-4.sh mcp-control ~user/qubes_mcp/public
```

Then verify from mcp-control:

```sh
.venv/bin/python deploy/test-stage-I-4.py     # 4 PASS — compat invariance + oracle hygiene
.venv/bin/python deploy/test-stage-c.py       # firewall regression: unchanged
```

The per-tier behaviour (ro/exec denied firewall-write after the flip;
net/full allowed) is proven on dom0 hardware by the operator's slot with
operator-tagged fixtures, and exhaustively offline by a policy simulator that
parses the real file and checks the full (surface × tier) matrix for both
compat and post-flip. `deploy/uninstall-stage-I-4.sh` reverts the policy
(or `/tmp/run.sh revert` restores the pre-I-4 file byte-exact).

### Step 16 — (Optional) Deploy Stage I-5 for tiered wrapper + exec surfaces

Stage I-5 is the second enforcement step — it tiers the `@adminvm`
**wrapper** surfaces (in dom0 code) and the **exec** surfaces (in policy),
completing the resource axis (Wave 1).

- The eight state-changing wrappers (Lifecycle / SetProperty / Clone /
  Spawn / SetFeature / Attach / Detach / SpawnDisposable) now require
  `ai-full` via the sibling-loaded `qmcp_tier` helper — Lifecycle/
  SetProperty/SetFeature gate the target, Clone the source, Spawn the
  template, SpawnDisposable the DVMT, Attach/Detach **both** endpoints. The
  gate is **fail-closed**: if the resolver can't load, the call is refused
  (opaque `"not found"`), never allowed (unlike the best-effort audit hook).
- `RunInAIManaged` / `CopyToAIManaged` graduate in the policy to
  `@tag:ai-exec` / `ai-net` / `ai-full` plus a `@tag:ai-managed` compat
  backstop — the same Option-A pattern Stage I-4 used for firewall write.
- Every create path **strips** any tier tag inherited from its source:
  `qubesadmin.clone_vm` copies all of the source's tags (except
  `created-by-*`) and `admin.vm.CreateDisposable` inherits the DVMT's, so
  without the strip a clone/disposable of an `ai-full` qube would emerge
  `ai-full` — letting AI self-escalate past the flip. The wrappers remove
  every non-umbrella tier tag on create, verify, and roll back on failure,
  so a created qube is always untiered.

In **compat** (the default — `/etc/qmcp/tier-default` absent → untiered =
`ai-full`) all of this is behaviour-neutral: every A–F3 operation still
works. Enforcement bites only once the operator tiers the fleet and runs
the **flip** (a separate step): delete the four compat backstops
(firewall.Set/Reload + RunInAIManaged/CopyToAIManaged) **and** write `ro`
to `/etc/qmcp/tier-default` in one coupled change, so the policy and
wrapper surfaces drop to least-privilege together.

`qmcp_tier.py` (from Stage I-3) must already be in dom0. The installer
verifies it, **refuses** to install if any qube carries both `ai-managed`
and `ai-dump` (the hybrid the I-4 valve warns about — I-5 enforces the
disjointness), and validates the policy before replacing the live file.

From dom0:

```
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/public/deploy/install-stage-I-5.sh' > /tmp/install-I-5.sh
bash /tmp/install-I-5.sh mcp-control ~user/qubes_mcp/public
```

Then verify from mcp-control:

```sh
.venv/bin/python deploy/test-stage-I-5.py     # compat invariance + opaque tier refusals
.venv/bin/python deploy/test-stage-a.py        # A–F3 regression: unchanged in compat
```

The per-tier gate (an `ai-exec` qube refused an `ai-full` op), the
behaviour-neutral compat path, and the **create-path strip** (a clone of
an `ai-full` source comes back untiered) are proven on dom0 hardware by
the operator's slot — the strip is read back via `qvm-tags` in dom0
because tier tags are deliberately invisible to AI. `deploy/uninstall-stage-I-5.sh`
reverts (or `/tmp/run.sh revert` restores the pre-I-5 wrappers + policy
byte-exact).

### Wave 2 (pre-1.0) — the enforcement chain and its gate

The Wave 2 stages are **not part of the adopter path yet**: each ships inert or
in shadow, and together they prepare an enforcement flip that has not happened.
They install in order (`install-stage-1.sh`, `-2`, `-3a`, `-3b`) with the same
dom0 invocation as every step above. Nothing changes behaviour until an operator
writes the flag Stage 3b provides.

What is worth knowing before then is the gate. Stage 3b ships the production
smoke suite, and it is the thing that decides whether the flip may happen:

```
.venv/bin/python deploy/smoke-production.py
```

Read its **exit status**, not its output:

| Exit | Meaning |
|---|---|
| `0` | GREEN — all seven items passed. The flip may proceed. |
| `2` | FAILED — at least one item failed. |
| `3` | INCOMPLETE — nothing failed, but an item did not really run. **Not green.** |

Two of the seven items exercise deployment-specific tooling that is deliberately
not part of this repository, and one cannot fail on a fleet with a single egress
class. Those report `NOT-RUN` and `VACUOUS` rather than passing, which is why
exit `3` exists and why it does not gate the flip. Declare the external checks
in `~/.config/qmcp/smoke-external.conf` (one `item2 = <command>` /
`item3 = <command>` line each) to turn them green.

The suite creates and reaps its own `ai-smoke-*` fixtures; `--no-create` runs
it read-only. Its first run records a baseline of which qubes answer
`qmcp.RunInAIManaged` and reports `VACUOUS`, because one observation cannot show
that a later flip changed nothing.

### Qube naming — AI creates inside a reserved prefix

Every qube qubes-mcp creates on the AI's behalf must be named inside a reserved
prefix, `ai-` by default. A create requesting a name outside it is refused
before dom0 is consulted at all.

This is a security boundary, not a convention. The create path validates the
requested name against the host's qube list, so without the prefix an agent
could confirm the existence of any qube it could guess — `vault`, `personal`,
`sys-usb` — by attempting a create and reading the error, while every *read*
surface deliberately redacts exactly those names. Restricting the namespace is
what makes a collision only ever concern a name the agent could already
enumerate.

Change it by writing the prefix to `/etc/qmcp/name-prefix` (mode `0644`; the
dom0 services run as a non-root user and cannot read a `0600` file):

```
printf 'bot-\n' | sudo tee /etc/qmcp/name-prefix >/dev/null
sudo chmod 0644 /etc/qmcp/name-prefix
```

A malformed or unreadable file falls back to `ai-` rather than to "no prefix" —
for this one file, "no prefix" would be *more* authority, so the safe landing is
the restrictive default.

**One residual, worth knowing:** a qube inside the reserved prefix that is *not*
`ai-managed` can still be inferred, because the agent can list the ai-managed
ones and subtract. That is one namespace instead of the whole machine.
`install-stage-fixes-F1-F5.sh` reports any such qube on your fleet so you can
rename it or accept it.

### Egress: birth is inherited, retarget is operator-only

A qube AI creates inherits its creator's network path, and AI cannot move an
existing qube to a different one — `netvm` writes are refused. Setting
`netvm = null` (disconnecting) is still allowed: taking a qube off the network
cannot leak.

Both halves are needed together. With birth enforced but retarget open, an
agent could retarget a source qube and then *clone* it, and the clone would be
born on the new path with no `netvm` argument for the birth guard to inspect —
because inheriting from the creation source is exactly what the birth rule is
supposed to do.

### Step 17 — Connect a client

From your workstation, configure an MCP client to invoke the server via
SSH + stdio. Example for Claude Code (`~/.claude.json`):

```json
{
  "mcpServers": {
    "qubes": {
      "command": "ssh",
      "args": [
        "-T",
        "user@<mcp-control-host>",
        "/home/user/qubes_mcp/.venv/bin/python",
        "-m",
        "qubes_mcp"
      ]
    }
  }
}
```

Replace `<mcp-control-host>` with whatever address reaches your mcp-control
qube — typically an isolated overlay network (tailnet, Headscale, WireGuard).

## Quick tour

```
qubes_mcp/                          # repo root
├── CLAUDE.md                       # source-of-truth design doc
├── README.md                       # this file
├── LICENSE                         # MIT
├── pyproject.toml                  # package metadata; `pip install -e .` works
├── qubes_mcp/                      # the Python package
│   ├── server.py                   # FastMCP, Ring enum, ring_tool decorator, spend_gate
│   ├── __main__.py                 # `python -m qubes_mcp` entrypoint
│   └── tools/                      # one file per MCP tool
├── policy/30-mcp-control.policy    # qrexec policy → /etc/qubes/policy.d/ in dom0
├── dom0-rpc/                       # qmcp.* scripts → /etc/qubes-rpc/ in dom0
├── template-rpc/                   # qmcp.* scripts → /etc/qubes-rpc/ inside ai-managed templates
└── deploy/                         # install/uninstall/test for each stage
```

## License

MIT — see `LICENSE`.

## Caveat

This is operator-grade infrastructure for a specific use case (sandboxed AI
agents managing Qubes-isolated workloads). It is not a hardened product. The
threat model treats the MCP source qube (`mcp-control`) as itself the trust
boundary, and the dom0/policy layer is what enforces it: the `qmcp.*` wrappers
and qrexec policy are built so a compromised `mcp-control` cannot read,
enumerate, mutate, or act on qubes outside its `ai-managed` tag scope, cannot
mint its own network egress, and cannot escalate the authority the operator
granted. The gateway-input boundary breaks a 2026-07-24 architecture review
surfaced — an unrestricted property write (self-minted egress), device-enumeration
oracles reaching dom0, out-of-scope qube names leaking through reads and device
lists, and inter-qube file-copy over-reach — are closed in **Stage G0**. Within
its granted scope the AI can do anything. Two honest limits remain: a few
pre-existing failure-path error messages can still surface a referenced qube
name (being collapsed to opaque refusals), and hardening `mcp-control` itself
(sudo lockdown, dedicated MCP user) is deferred Stage G1/G2 work. Stage I
(graduated authority — current work line) tiers authority below the umbrella tag
so a compromised or hallucinating agent need not hold full authority on every
qube it can see.
Run on your own infrastructure; report bugs in issues.
