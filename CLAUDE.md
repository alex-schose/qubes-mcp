# qubes_mcp — design document

FastMCP server that runs in a dedicated qube (`mcp-control`) and exposes a
tag-scoped Qubes Admin API sandbox to AI assistants. Assistants on the
operator's workstation (and eventually a phone) call into it over
stdio-via-SSH or HTTP/SSE to manage a subset of qubes inside Qubes OS.

**This file is the source of truth — read it first in any session opened in
this directory.**

## Trust model (load-bearing — do not modify without operator sign-off)

- The qrexec **tag `ai-managed`** is the trust boundary. AI can read and modify
  only qubes carrying this tag. Untagged qubes are invisible: their existence,
  properties, and events do not leak to AI.
- **Tag mutation is forbidden** for AI. `admin.vm.tag.Set` and `admin.vm.tag.Remove`
  are hard-denied at the policy layer. Tagging happens only in two places:
  1. The dom0 `qmcp.*` create-and-tag wrappers (`qmcp.SpawnAIManagedQube`,
     `qmcp.CloneAIManagedQube`, `qmcp.SpawnDisposableAIManaged`), which
     force-tag every qube they create. Each wrapper applies the tag via
     direct admin authority in dom0; the policy deny only gates inter-qube
     calls coming in over qrexec, which the wrappers don't use.
  2. The operator's hand in dom0 (`qvm-tags <vm> add|del ai-managed`).
- AI never has direct access to admin write methods. Every state-changing
  call is routed through a `qmcp.*` dom0 RPC wrapper that enforces
  invariants in dom0 (forced tagging on creation, cross-reference
  validation, ai-managed-tag check, opaque error responses). The
  remaining tag-scoped qrexec policy allows are surfaces where the qrexec
  `@tag:` matcher is sufficient:
  - `qmcp.RunInAIManaged` and `qmcp.CopyToAIManaged` from `mcp-control`
    to any `@tag:ai-managed` qube (Stage B — exec and file-copy land in
    the target's qubes-rpc service, which only ai-managed templates
    install);
  - `qubes.Filecopy` from `@tag:ai-managed` to `@tag:ai-managed` (Stage B
    — inter-ai-managed transfer without the operator dialog);
  - `admin.vm.firewall.Get` on `@tag:ai-managed` targets (Stage C; the
    ro-floor) and `admin.vm.firewall.{Set,Reload}` on `@tag:ai-net` +
    `@tag:ai-full` targets (Stage I-4 — graduated to the firewall-write
    tier; plus a `@tag:ai-managed` compat backstop, removed at the flip);
  - device enumeration: `admin.vm.device.*.Available` was a ro-floor read
    (Stage E1); Stage G0 routes ALL of it (attached + available) through the
    dom0 redactor `qmcp.ListAttachedDevicesAIManaged` (which hides out-of-scope
    backend / consuming-frontend qube names) and DENIES the direct
    `admin.vm.device.*.{Available,Attached,Assigned}` methods to AI;
  - `qubes.Filecopy` from `@tag:ai-managed` to `@tag:ai-dump` (Stage I-4 —
    the write-only sink; copy-IN only).
- AI has **root inside its sandbox qubes** (via `qmcp.RunInAIManaged`, Stage B)
  but no privilege inside `mcp-control` itself. mcp-control is an RPC gateway,
  not a workhorse. Hardening `mcp-control` (sudo lockdown, dedicated MCP
  user) is the Stage G work — deferred until Stage I (graduated authority)
  completes, since G's lockdown becomes meaningfully different per-tier and
  is best designed once the tier model exists.
- The "wrapped reads" pattern (`qmcp.GetPropertyAIManaged`) returns the literal
  string `"not found"` indistinguishably whether the named qube doesn't exist
  or simply isn't tagged `ai-managed`. The MCP-side helper normalises all
  qrexec failures (policy deny, no-such-VM, transport) to the same opaque
  `"not found or refused"`, so AI cannot use either the read surface or the
  lifecycle surface as an existence oracle. The same opacity holds on the
  *value* channel (Stage I-1, finding F-3): when a property's value — or a
  list field such as `qmcp.ListAIManagedQubes`' `template` — references
  another qube, the wrapper emits that qube's name only if it is itself
  ai-managed, else the opaque `<out-of-scope>` sentinel. So AI cannot read an
  out-of-scope qube's name off an in-scope qube's `netvm` / `template` /
  `default_dispvm` / `guivm` / `audiovm` / `management_dispvm`, and the `tags`
  read is filtered to the qmcp vocabulary (no operator tags; no future tier
  topology). This is the read-path sibling of the Stage F2 write-path
  cross-ref opacity. *(Visibility ≠ capability: a held capability — e.g. a
  future sign-only service — is not a name leak; it enumerates nothing it can
  act on.)*
- **Audit trail (Stage I-2).** Every state-changing `qmcp.*` call is recorded
  on a hash-chained, AI-unreachable dom0 log (`/var/log/qmcp-audit.log`,
  `root:qubes` `0660`): each line carries the sha256 of the previous, so deletion or edit
  breaks the chain. The log is unreachable by construction — no `qmcp.*`
  service reads or writes an arbitrary dom0 path and no policy line exposes it,
  so AI can neither read past entries nor forge new ones. Entries log a
  whitelisted summary (qube names / property + feature keys / action) and
  **never a property or feature value**. Logging is best-effort — it never
  blocks or alters an operation (the Stage I-10 vault upgrades to a fail-closed
  variant for `SignTransaction`).
- **Resource tiers (Stage I-3 — taxonomy landed; enforcement I-4/I-5).** The
  binary boundary graduates into a tier ladder *within* `ai-managed` so a
  hallucinating or prompt-injected agent need not hold full lifecycle authority
  on every qube it can see. The taxonomy is umbrella + at most one elevation tag:
  - `ai-managed` — umbrella: existence boundary **and** the read floor (= `ai-ro`).
  - `ai-exec` — `+` run commands (`RunInAIManaged`/`CopyToAIManaged`/install-pkg).
  - `ai-net` — `+` firewall write (`firewall.Set`/`Reload`).
  - `ai-full` — `+` lifecycle / property-set / clone / spawn / feature / attach / detach.
  - `ai-dump` — copy-IN only, a write-only sink (the Biba valve); **orthogonal**
    to the ladder and **not** `ai-managed`, so it is invisible to reads.

  The ladder is **cumulative** (`ai-net` ⊃ `ai-exec` ⊃ read floor): capabilities
  nest, since anyone who may rewrite a qube's firewall may already run commands
  in it. A genuine non-ladder capability is expressed as a separate orthogonal
  tag (as `ai-dump` is), not by exploding every qube's tag set. **AI still cannot
  mutate tags** (`admin.vm.tag.Set/Remove` denied) — tiers are operator-assigned,
  the keystone that makes them un-self-escalatable — **and cannot read the tier
  tags either**: a `tags` read stays `["ai-managed"]`, so the fleet's authority
  topology is not an AI-readable oracle (capability is discovered through opaque
  refusals, not a tag read). The resolver is a dom0 helper (`qmcp_tier.py`,
  sibling-loaded like `qmcp_budget`/`qmcp_scope`/`qmcp_audit`) returning a
  **capability set** — so the wrappers ask "is `full` granted?", decoupled from
  the taxonomy. **Migration is two reversible phases:** I-3..I-5
  ship in **compat** (an untiered `ai-managed` qube = `ai-full`, i.e. today's
  boundary exactly), enforcement lands in I-4/I-5, then the operator tiers the
  fleet and flips the dom0 flag `/etc/qmcp/tier-default` to `ro` for
  least-privilege. No intermediate state is less safe than today.
  - **I-4 — tiers on the policy-scoped surfaces (landed).** The directly
    `@tag:`-scoped surfaces graduate by a single-file policy diff: `firewall.Get`
    + `device-list` stay at the `ai-managed` ro-floor; `firewall.{Set,Reload}`
    require `@tag:ai-net` or `@tag:ai-full`; and `ai-dump` gets a dedicated
    copy-IN-only `qubes.Filecopy` line (the Biba valve — for a pure sink AI
    pushes but cannot read back; rests on the operator invariant that an
    `ai-dump` qube is never also `ai-managed`, which the installer checks). **The policy layer matches tags literally and cannot
    call `qmcp_tier`,** so it cannot honour the helper's "untiered = `ai-full`
    (compat)" default. I-4 therefore ships firewall-write with a `@tag:ai-managed`
    **compat backstop** (Option A) that keeps untiered qubes writable during
    migration — so A–F3 stays green and the live egress qube keeps firewall
    control on deploy. The backstop subsumes the net/full lines, so firewall
    write is behaviour-neutral in compat; the one new live capability is the
    `ai-dump` valve. **The flip (end of I-5) deletes the four compat backstops AND
    writes `ro` to `/etc/qmcp/tier-default` in one change**, so the policy
    surface and the wrapper surface drop to least-privilege together — removing
    only one leaves them incoherent. I-5 then tiers the wrapper surfaces
    (lifecycle/property/clone/spawn/feature/attach/exec require `ai-full`; exec
    requires `ai-exec`).
  - **I-5 — tiers on the wrapper + exec surfaces (landed).** The eight
    `@adminvm` state-changing wrappers now read the target's effective
    capability in dom0 code and require `CAP_FULL` before the privileged op —
    Lifecycle/SetProperty/SetFeature gate the **target**, Clone the **source**,
    Spawn the **template**, SpawnDisposable the **DVMT**, Attach/Detach **both**
    endpoints — **fail-closed** (a missing/broken `qmcp_tier` denies, the
    opposite of the best-effort audit hook; a refusal is the same opaque
    `"not found"` as an untagged target, so no tier oracle). The exec surfaces
    (`RunInAIManaged`/`CopyToAIManaged`) graduate in **policy** to
    `@tag:ai-exec`/`ai-net`/`ai-full` + a `@tag:ai-managed` compat backstop
    (the I-4 firewall pattern). **Keystone enforcement on create:** because
    `qubesadmin.clone_vm` copies the source's tags and `admin.vm.CreateDisposable`
    inherits the DVMT's, every create path now **strips** every tier tag except
    the umbrella (verify + roll back on failure) — so a created qube is always
    **untiered** (= full in compat, ro post-flip). Without the strip, AI could
    clone an `ai-full` qube into another `ai-full` qube and self-escalate past
    the flip, defeating the un-self-escalatability keystone. **The flip now
    deletes FOUR compat backstops** (firewall.Set/Reload from I-4, RunInAIManaged/
    CopyToAIManaged from I-5) **and** writes `ro` to `/etc/qmcp/tier-default` in
    one coupled change. Behaviour-neutral in compat; no new RPC/qube/ring.
- **Disk budget = persistent footprint, hard-capped (I-0/F3, corrected
  2026-06-12).** AI cannot exhaust the host pool. The I-0 create-gate and
  `qmcp.GetPoolStats` meter the **persistent** provisioned footprint of
  ai-managed qubes — each `private` volume, plus `root` only for klasses whose
  root persists (TemplateVM/StandaloneVM); a COW AppVM root and ephemeral
  volatile are **not** counted (they were, and over-stated real usage ~8×).
  Because a volume can't exceed its own size, Σ persistent ≤ `/etc/qmcp/pool-cap`
  is a **hard ceiling on the persistent footprint** — but only that: a running
  qube's volatile/COW-root is real pool space that the meter intentionally skips
  (transient, reclaimed on shutdown), so the cap bounds **persistent**
  exhaustion, not transient runtime pool pressure. A second operator file,
  `/etc/qmcp/private-cap`, bounds any single qube's `private`: a spawn may
  request a larger persistent volume (`private_size`) up to that ceiling, so AI
  can make big qubes *under the limit* but no qube can hog the pool. Both caps
  are operator-owned; AI cannot read or change them (it sees only its
  `(used, cap, headroom)`), and every create path fails closed if a cap is
  unreadable.

## What lives where

- **`mcp-control` qube** runs the FastMCP server at `/home/user/qubes_mcp/`.
  No workload; only RPC translation. Reachable from the operator's
  workstation via SSH over the local tailnet (Stage A) or Tor (Stage G).
- **dom0** hosts the qrexec policy file (`/etc/qubes/policy.d/30-mcp-control.policy`)
  and the `qmcp.*` RPC scripts (`/etc/qubes-rpc/qmcp.*`). The operator installs both.
  **This codebase NEVER edits dom0 files.** It only generates drafts in
  `policy/` and `dom0-rpc/` for the operator to review and copy.
- **ai-managed templates** (Stage B onward) hold custom qrexec services
  (`qmcp.RunInAIManaged`, `qmcp.CopyToAIManaged`). AI's templates carry these
  services; the operator's templates do not.

## The `qmcp.*` RPC catalog (locked)

| Service | Purpose | Stage |
|---|---|---|
| `qmcp.ListAIManagedQubes` | Discovery — returns only qubes carrying `ai-managed`. | A |
| `qmcp.SpawnAIManagedQube` | Create AppVM (A); DispVMTemplate + DispVM klasses (D). Auto-tags. Validates name + klass + template (incl. `template_for_dispvms` cross-ref for DispVM) + (optional) netvm. Optional `private_size` grows the persistent volume up to the per-qube cap. | A → D |
| `qmcp.GetPropertyAIManaged` | Wrapped read. `"not found"` is indistinguishable from `"not tagged"`. | A |
| `qmcp.SetPropertyAIManaged` | Wrapped write with an explicit settable-property allowlist (`provides_network` operator-only — Stage G0) + cross-ref validation on `template`/`netvm`/`default_dispvm`. | A |
| `qmcp.LifecycleAIManaged` | start/shutdown/kill/pause/unpause/remove on ai-managed qubes. Replaces direct `admin.vm.*` lifecycle in Stage D — qrexec's `@tag:` matcher doesn't reach klass=DispVM targets, so we do the tag check in dom0. | D |
| `qmcp.GetPoolStats` | AI-scoped disk-budget visibility — sum of the **persistent footprint** of every ai-managed qube (each `private`, plus `root` for klasses whose root persists; COW root + ephemeral volatile are not counted), plus an operator-set cap from `/etc/qmcp/pool-cap` (re-read per call). Returns `{used, cap, headroom}`; no pool names, no free-space, no operator-side volumes. Cap is an operator → AI contract, not a sensor in the other direction. | F3 |
| `qmcp.RunInAIManaged` | Execute command inside ai-managed qube as root. Custom qrexec service in ai-managed templates. | B |
| `qmcp.CopyToAIManaged` | File transfer; both source and target must be ai-managed. | B |
| `qmcp.CloneAIManagedQube` | Clone an existing ai-managed qube; auto-tags the clone. | D |
| `qmcp.AttachDeviceAIManaged` | Virtual device attach. Both qubes (backend and frontend) must be ai-managed; dom0 wrapper enforces the tag check on both ends, then shells out to `qvm-device` (absorbs DeviceAssignment-API drift across Qubes 4.1 → 4.2 → 4.3). | E1 |
| `qmcp.DetachDeviceAIManaged` | Mirror of Attach. | E1 |
| `qmcp.ListAttachedDevicesAIManaged` | Redacted device enumeration (attached + available modes) — replaces the direct `admin.vm.device.*` reads (now denied to AI); out-of-scope backend / consuming-frontend qube names collapse to `<out-of-scope>` via a fail-closed allowlist. | G0 |
| `qmcp.SpawnDisposableAIManaged` | Ephemeral DispVM creation via `admin.vm.CreateDisposable`. DVMT must be ai-managed; the auto-named disposable is force-tagged before AI sees it; auto-removed on shutdown. | E2 |
| `qmcp.SetFeatureAIManaged` | `feature.Set` on ai-managed qubes. `internal` denied (operator-only); cross-VM keys (`audiovm`/`guivm`) must reference an ai-managed qube via an opaque refusal; echoes the post-set value back (no feature-read surface). | F1 |
| `qmcp.AIManagedEvents` | Filtered event stream — events whose subject is `@tag:ai-managed`. Bounded-window batch: tool blocks for a caller-given duration, wrapper collects ai-managed-filtered events, returns the batch. | F2 |

## Stage rollout (locked)

```
A. Policy + qmcp (List/Spawn/GetProperty/SetProperty) + tag-scoped
   lifecycle (Start/Shutdown/Kill/Pause/Unpause/Remove). Prereq: one ai-managed
   template. (qmcp.GetPoolStats was scoped here but deferred for shape
   reasons — ships as Stage F3 with an AI-scoped sum + operator cap.)
B. qmcp.RunInAIManaged + qmcp.CopyToAIManaged. AI gets root inside its qubes
   and can move files between them.
C. Single-egress network sandbox. `ai-net-router` is the only ai-managed
   qube with `provides_network=true`; AI's qubes default to it as netvm.
   The operator chooses ai-net-router's upstream in dom0 (sys-firewall,
   sys-whonix, a VPN qube, or null for offline) — that one prefs flip
   reroutes all AI traffic. Tag-scoped `admin.vm.firewall.{Get,Set,Reload}`
   allows AI to read and write firewall rules on its own qubes and on
   ai-net-router; SetPropertyAIManaged refuses netvm mutation on any
   ai-managed qube with `provides_network=true` (egress invariant).
D. qmcp.CloneAIManagedQube + DispVMTemplate/DispVM klass support in
   qmcp.SpawnAIManagedQube + qmcp.LifecycleAIManaged (uniform
   dom0-mediated lifecycle covering klass=DispVM, which qrexec's
   `@tag:` selector won't reach). AI manages its own template lineage
   and the full lifecycle of every klass it can create.
E1. qmcp.AttachDeviceAIManaged + qmcp.DetachDeviceAIManaged (virtual
    block/USB/mic between ai-managed qubes). Both endpoints must be
    ai-managed — dom0 wrapper does the tag check on backend AND
    frontend (qrexec policy can only gate one side of the call), then
    shells out to `qvm-device` which absorbs the DeviceAssignment-API
    drift across Qubes 4.1 → 4.2 → 4.3. Read-only enumeration is
    tag-scoped via policy (same shape as Stage C firewall.Get). New
    Ring.DEVICE. In practice the block class is the useful default;
    USB/mic require operator opt-in (`sys-usb` / audio-backend
    ai-managed tag), which the trust model leaves to the operator.
E2. qmcp.SpawnDisposableAIManaged — ephemeral DispVMs via
    `admin.vm.CreateDisposable`. Stage D ships persistent klass=DispVM
    disposables; this adds the typical "spin up, run, auto-destroy on
    shutdown" pattern, with a DVMT-must-be-ai-managed precondition and
    forced-tagging of the auto-named disposable before AI sees it. No
    new ring (Ring.LIFECYCLE covers it). MCP also ships a
    `qubes_run_disposable(template, cmd)` one-shot that composes
    spawn + start + run + shutdown without adding dom0 surface.
F1. qmcp.SetFeatureAIManaged — feature.Set on ai-managed qubes.
    `internal` is denied (operator-only — AI must not hide a qube from
    the operator's app menu / qube manager); the cross-VM keys
    `audiovm`/`guivm` must reference an ai-managed qube, refused
    *opaquely* (missing and untagged collapse to one message so the
    surface is not an existence oracle); booleans coerce to Qubes
    convention (True→"1", False→""); the response echoes the post-set
    value read back from qubesd, so no feature-read surface is needed
    (admin.vm.feature.Get stays denied). Direct admin.vm.feature.Set
    stays denied — the wrapper is the only path. New Ring.FEATURE.
F2. qmcp.AIManagedEvents — filtered event stream. Bounded-window batch
    model: the tool blocks for a caller-given duration while a dom0
    wrapper subscribes to admin.Events and collects only events whose
    subject carries the ai-managed tag, then returns the batch and
    exits (no persistent dom0 daemon — admin.Events is denied to AI, so
    the wrapper sees everything and the tag filter is a security
    boundary kept small and stateless). New Ring.EVENTS.
F3. qmcp.GetPoolStats — AI-scoped disk-budget visibility. Closes the
    F band. Returns the sum of provisioned bytes across every volume
    on every ai-managed qube, plus an operator-set ceiling from
    `/etc/qmcp/pool-cap` (single integer, re-read per call — operator
    edits take effect with no daemon restart). Response is
    `{used, cap, headroom}`; pool names, free space, and operator-side
    volumes are intentionally absent. The cap is a contract operator
    → AI (operator allocates a budget) rather than a sensor in the
    other direction (which a "free-space" shape would have been —
    free_bytes moves when the operator acts and would be a streaming
    operator-side oracle). Direct admin.pool.* and
    admin.vm.volume.{List,Info} stay denied; the wrapper bypasses
    those over the local dom0 socket (qrexec policy does not gate
    in-dom0 calls). No new ring — fits Ring.READ_ONLY.
I-0. Pool-cap promoted from advisory signal to a hard gate on every
    create path (qmcp.SpawnAIManagedQube / qmcp.CloneAIManagedQube /
    qmcp.SpawnDisposableAIManaged). Each wrapper computes the
    projected post-create provisioned-sum (current ai-managed `used`
    + conservative estimate from the template's/source's
    `sum(vol.size)`) and refuses BEFORE the Admin API call if the
    projection would exceed the cap. Measurement is byte-identical to
    F3's `qmcp.GetPoolStats` so AI's `(used, cap, headroom)` view
    predicts the gate exactly. Refusal is opaque: `"pool cap
    exceeded"` (no numbers echoed; AI can call GetPoolStats for the
    diagnostic triple). Cap-missing/malformed/negative fail closed
    with F3's existing `"pool cap not configured"`. Cross-ref refusal
    still wins (the gate adds no new existence oracle: untagged
    template/source still surfaces the same opaque cross-ref message
    before the gate runs). The enforcement lives in a shared dom0
    helper (`qmcp_budget.py`) loaded by each wrapper via
    `importlib.util.spec_from_file_location` against `__file__`'s
    directory — so the same module works in `/etc/qubes-rpc/` and in
    offline-validation. No new RPC surface; no policy change; no new
    ring. First sub-stage of Stage I (graduated authority);
    backward-compatible.
I-1. Close the read-surface name leak (finding F-3).
    The wrapped reads were opaque on existence (missing/untagged →
    "not found") but not on VALUE: any VM-valued property (netvm,
    template, default_dispvm, guivm, audiovm, management_dispvm) and
    qmcp.ListAIManagedQubes' `template` field serialised the
    referent's raw name with no scope check, leaking out-of-scope
    qube names. I-1 routes every VM-valued result through a shared
    dom0 redactor (qmcp_scope.py, sibling-loaded like qmcp_budget):
    a referenced qube's name survives only if it is itself
    ai-managed, else collapses to the opaque "<out-of-scope>"
    sentinel; `tags` reads are filtered to the qmcp vocabulary
    (previously hidden only by an accidental serialisation crash).
    The MCP tool layer is not a boundary — the fix is in the dom0
    wrappers and the tools inherit it. Fail-closed: a read refuses
    if the redactor can't load. The read-path sibling of the Stage
    F2 write-path cross-ref opacity. No new RPC service; no policy
    change; no new ring.
I-2. dom0 audit log. A hash-chained, AI-unreachable record of every
    state-changing qmcp.* call (Spawn / Clone / SpawnDisposable /
    SetProperty / SetFeature / Lifecycle / Attach / Detach). A shared
    dom0 helper (qmcp_audit.py, sibling-loaded like qmcp_budget /
    qmcp_scope) appends one JSON line per call to
    /var/log/qmcp-audit.log (root:qubes, 0660 — group-writable by the
    non-root qrexec wrapper user; O_APPEND + flock); each line
    carries the sha256 of the previous, so any edit / delete / reorder
    breaks the chain (verify() walks it; a CLI re-checks it). Each
    wrapper routes its single response funnel through audit() and logs
    a WHITELISTED summary — qube names / property + feature KEYS /
    action — never a property or feature VALUE. AI-unreachable by
    construction: no qmcp.* service reads or writes an arbitrary dom0
    path and no policy line exposes the log, so AI can neither read
    past entries nor forge new ones. Logging is best-effort — it never
    blocks or alters an operation (the I-10 vault upgrades it to a
    fail-closed variant for SignTransaction). Foundational before the
    tier model (I-3+). No new RPC service; no policy change; no new
    ring; read wrappers are not logged.
I-3. Tier taxonomy + dom0 tier-resolution helper. The keystone of the
    resource axis: the binary boundary graduates into a tier ladder
    within ai-managed — ai-managed (umbrella + read floor) < ai-exec
    (+commands) < ai-net (+firewall write) < ai-full (+lifecycle/
    property/clone/spawn/feature/attach/detach); ai-dump is an
    orthogonal copy-IN-only sink. The ladder is cumulative (net⊃exec):
    capabilities nest, and a genuine non-ladder need is a separate
    orthogonal tag, not a per-qube tag explosion. A new shared dom0
    helper (qmcp_tier.py, sibling-loaded like qmcp_budget/qmcp_scope/
    qmcp_audit) exposes effective_capabilities(vm) -> frozenset of
    capability tokens; callers ask "is full granted?" so the resolver's
    SET interface decouples the wrappers from the taxonomy (a future
    non-ladder model swaps the helper internals, not the call sites).
    BEHAVIOUR-NEUTRAL: the helper installs inert (no wrapper sources it
    until I-5) in COMPAT mode — an untiered ai-managed qube resolves to
    ai-full, exactly today's boundary, so every A–F3 surface is
    unchanged. AI cannot mutate tags (keystone, unchanged) NOR read the
    tier tags: a tags read stays ["ai-managed"], so the authority
    topology is not an AI oracle. Migration is two reversible phases
    (two reversible phases): ship I-3..I-5 in compat; enforce in I-4/I-5; then the
    operator tiers the fleet and flips the dom0 flag /etc/qmcp/
    tier-default to "ro" for least privilege. The Ring enum gains a
    declarative tier annotation (UX only — enforcement is dom0).
    No new RPC service; no policy change; no daemon restart; no new ring.
I-4. Tiers on the policy-scoped surfaces — the first enforcement step,
    a single-file policy diff. firewall.Get + device-list stay at the
    ai-managed ro-floor; firewall.Set/Reload graduate to @tag:ai-net +
    @tag:ai-full; ai-dump gets a dedicated copy-IN-only qubes.Filecopy
    line (the Biba write-only sink). The policy layer matches @tag:
    selectors literally and cannot call qmcp_tier, so firewall-write
    ships with a @tag:ai-managed COMPAT BACKSTOP (Option A) keeping
    untiered umbrella qubes writable through migration — A–F3 stays
    green, the live egress qube keeps firewall control on deploy, and
    the WRITE surface stays behaviour-neutral in compat (the net/full
    lines are subsumed until the flip). The one new live capability is
    the ai-dump valve. THE FLIP (end of I-5) deletes the four compat
    backstops AND writes "ro" to /etc/qmcp/tier-default in one change, so
    the policy surface and the wrapper surface flip together. No new RPC
    service; no new qube; no wrapper change; no new ring — policy-only.
I-5. Tiers on the wrapper + exec surfaces — the second enforcement
    step, completing the resource axis (Wave 1). The eight @adminvm
    state-changing wrappers (Lifecycle/SetProperty/SetFeature gate the
    target; Clone the source; Spawn the template; SpawnDisposable the
    DVMT; Attach/Detach both endpoints) require CAP_FULL via the
    sibling-loaded qmcp_tier helper, FAIL-CLOSED (a missing/broken
    resolver denies — opposite of the best-effort audit hook). The exec
    surfaces (RunInAIManaged/CopyToAIManaged) graduate in POLICY to
    @tag:ai-exec/ai-net/ai-full + a @tag:ai-managed COMPAT BACKSTOP
    (the I-4 firewall pattern). KEYSTONE enforcement on create: because
    qubesadmin.clone_vm copies the source's tags and CreateDisposable
    inherits the DVMT's, every create path STRIPS every tier tag except
    the umbrella (verify + roll back on failure) — a created qube is
    always untiered, so AI cannot clone an ai-full qube into another and
    self-escalate past the flip. THE FLIP (separate operator slot, after
    fleet-tiering) now deletes FOUR backstops (firewall.Set/Reload +
    RunInAIManaged/CopyToAIManaged) AND writes "ro" to
    /etc/qmcp/tier-default in one coupled change. Behaviour-neutral in
    compat; no new RPC service, no new qube, no new ring.
W2-1. Wave 2 Stage 1 — the capability decision kernel, in SHADOW mode.
    A new dom0 lib (qmcp_caps.py, sibling-loaded like qmcp_tier) derives a
    verdict from a domination lattice instead of a hand-authored matrix:
    decide(actor, service, action, targets) resolves, first match wins —
    (1) any target outside the ai-managed umbrella -> DENY; (2) an
    escalation-class operation -> DENY at every tier, forever (tag writes,
    provides_network, template retarget, netvm, name, TemplateVM create);
    (3) a target in the operator's guarded hard class -> GATE, checked
    BEFORE the domination logic so it cannot be argued away; (4) an
    operation an already-held capability fully dominates -> ALLOW; (5)
    otherwise the CAP_* ladder. Steps 1-3 sit above step 4 deliberately:
    they are exactly the decisions domination must never reach.
    The anti-theatre rule (step 4) is why gating `remove` while the actor
    holds exec is refused as a design: exec already reaches `rm -rf` and
    `shutdown`, so the gate protects nothing and trains the operator to
    click through. Domination entries must be AIRTIGHT — `pause`/`unpause`
    are excluded because exec cannot reach a paused qube, and device
    attach/detach are excluded because crossing to physical hardware is the
    one thing exec-inside genuinely cannot do.
    BEHAVIOUR-NEUTRAL: the kernel enforces nothing. Each of the 8
    state-changing wrappers asks it the same question its Stage I-5 CAP_FULL
    gate just answered — on BOTH outcomes, since a hook consulted only on
    the allow path measures half the lattice — and records ONLY a
    disagreement, through its existing single emit() funnel, as a new
    optional `shadow` field on the I-2 audit line. The field is OMITTED when
    they agree (the byte-neutral contract `consent` already follows), so an
    agreeing call's line and chain hash are identical to pre-Stage-1, and a
    wrapper still audits correctly against an older qmcp_audit.py.
    Fail-OPEN by design, the one inversion in the codebase: a missing or
    broken qmcp_caps.py must change nothing, because it is not a gate. The
    tier and consent helpers fail closed precisely because they are.
    That divergence log is the deliverable — it is dom0-side and
    AI-unreachable, and the later stage that flips enforcement over to
    decide() is gated on it holding nothing unexplained. No policy change;
    no daemon restart; no new RPC service (a lib is not a service); no new
    ring; no AI-visible surface of any kind.
G0. [SHIPPED — pulled ahead of Wave 2 after the 2026-07-24 review]
   Gateway input boundary: SetProperty settable-property allowlist
   (provides_network operator-only), qrexec target-name validator, device
   enumeration wrapped through a dom0 backend/attachment redactor (direct
   admin.vm.device.* enumeration denied), qubes.Filecopy re-tiered to ai-exec
   on both endpoints + explicit deny, and error-detail masking. Tier-independent;
   closes four review boundary findings.
G1/G2. [DEFERRED until Stage I completes] mcp-control host hardening (sudo
   lockdown, dedicated MCP user) + Tor hidden service for sshd →
   mobile CLI reach.
H. [DEFERRED until Stage I completes] FastMCP HTTP/SSE transport
   bound to a second .onion → mobile-app reach.
```

**Stage I (graduated authority) — current work line.** Reordering
decision of 2026-06-08: Stage I jumps ahead of G/H. Today the trust
boundary is binary — a qube tagged `ai-managed` gets every right
the policy + wrappers grant; an untagged qube is invisible. That's
necessary but not sufficient against a hallucinating or
prompt-injected agent that destroys real data inside the boundary.
Stage I adds *graduated* authority within `ai-managed`: read/audit
hardening (I-0 cap-as-gate, I-1 read-surface leak fix, I-2 dom0
audit log) then resource tiers (I-3..I-5 the tier model + helper +
write-surface enforcement); an action gate (I-6..I-8) for
per-call/per-blast-radius consent; a per-trust-class principal axis
(I-9); a sign-only secrets vault (I-10); persona presets (I-11). G
and H both depend on a non-binary trust model: G's mcp-control
lockdown becomes meaningfully different per-tier, and H's
HTTP/SSE-over-Tor reach requires the explicit dom0 gate-lift the
action axis introduces. So they are deferred — not cancelled — and
will be re-scoped once Stage I lands.

Each stage is verifiable in isolation and reversible (revert the policy file
+ remove the qmcp scripts to undo). The operator approves before each deploy;
the stage's test plan runs from `mcp-control`. Do not begin the next stage
until the current one's tests pass.

## Anti-goals (immutable)

- **No MCP code in dom0.** Dom0 holds only the policy file and `qmcp.*` scripts,
  both operator-installed.
- **No direct `admin.vm.tag.Set` or `tag.Remove`** anywhere. Tag mutation is
  the operator's exclusive authority.
- **No direct `admin.vm.Create.*` or `admin.vm.Clone`** in MCP tools. Always
  via `qmcp.SpawnAIManagedQube` / `qmcp.CloneAIManagedQube`.
- **No direct `admin.vm.property.Set`** — always via `qmcp.SetPropertyAIManaged`
  so cross-reference validation runs.
- **No `qvm-run` wrapper.** Command execution uses `qmcp.RunInAIManaged` (Stage B),
  a custom qrexec service installed only in ai-managed templates. The operator's
  templates don't have it; an AI qube based on an operator template cannot
  receive `qmcp.RunInAIManaged` calls.
- **No edits to `/etc/qubes-rpc/qmcp.*` or `/etc/qubes/policy.d/30-mcp-control.policy`
  from this codebase.** Drafts only; the operator installs.
- **No `.DS_Store`** or other Mac-platform files committed.
- **No third-party SaaS / SSO.** Self-host everything (e.g., Headscale instead
  of Tailscale-corp; own VPN; own Tor).
- **No `admin.Events` direct subscription.** Use `qmcp.AIManagedEvents` (Stage F2)
  for filtered streaming.
- **Never scope policy, ownership, or any gate on `created-by-*` or
  `disp-created-by-*`.** Neither tag can carry AI provenance, for two independent
  reasons. (1) qubesd stamps `created-by-` + the name of the *calling* domain, and
  every `qmcp.*` create runs inside a dom0 wrapper that calls qubesd over the
  dom0-local socket — so an AI-spawned qube and an operator-created one are
  byte-identically `created-by-dom0`. A rule keyed on it would grant AI authority
  over every qube in dom0. (2) `disp-created-by-*` is not covered by qubesd's
  guard at all, because `"disp-created-by-x".startswith("created-by-")` is
  `False` — anything holding `admin.vm.tag.Set` can forge it. Provenance is
  carried by a wrapper-stamped tag in the project's own reserved namespace
  instead. (Upstream has not solved this either: `qubes/ext/admin.py` carries a
  TODO for passing the management VM's name.)

## File layout

```
qubes_mcp/                          # repo root
├── CLAUDE.md                       # this file — source of truth
├── README.md                       # public-facing intro + reviewer asks
├── LICENSE                         # MIT
├── pyproject.toml                  # package metadata; `pip install -e .`
├── qubes_mcp/                      # the Python package
│   ├── __init__.py
│   ├── __main__.py                 # `python -m qubes_mcp` entrypoint
│   ├── server.py                   # FastMCP, Ring enum, ring_tool, spend_gate (with budget scaffold)
│   └── tools/
│       ├── _qrexec.py              # call_qmcp / call_admin / call_service helpers
│       ├── qubes_list.py
│       ├── qubes_spawn.py
│       ├── qubes_state.py
│       ├── qubes_props_get.py
│       ├── qubes_props_set.py
│       ├── qubes_start.py
│       ├── qubes_shutdown.py
│       ├── qubes_remove.py
│       ├── qubes_run.py            # Stage B
│       ├── qubes_copy.py           # Stage B
│       ├── qubes_install_pkg.py    # Stage B convenience
│       ├── qubes_firewall_get.py   # Stage C
│       ├── qubes_firewall_set.py   # Stage C
│       ├── qubes_clone.py          # Stage D
│       ├── qubes_device_list.py    # Stage E1
│       ├── qubes_device_attach.py  # Stage E1
│       ├── qubes_device_detach.py  # Stage E1
│       ├── qubes_spawn_disposable.py  # Stage E2
│       ├── qubes_run_disposable.py    # Stage E2 (one-shot composition)
│       ├── qubes_feature_set.py       # Stage F1
│       ├── qubes_events.py            # Stage F2
│       └── qubes_get_pool_stats.py    # Stage F3
├── policy/
│   └── 30-mcp-control.policy       # draft → /etc/qubes/policy.d/ in dom0
├── dom0-rpc/                       # drafts → /etc/qubes-rpc/ in dom0
│   ├── qmcp.ListAIManagedQubes
│   ├── qmcp.SpawnAIManagedQube      # atomic tag-on-create + klass extension (Stage D)
│   ├── qmcp.GetPropertyAIManaged
│   ├── qmcp.SetPropertyAIManaged
│   ├── qmcp.CloneAIManagedQube       # Stage D
│   ├── qmcp.LifecycleAIManaged       # Stage D (start/shutdown/kill/pause/unpause/remove)
│   ├── qmcp.AttachDeviceAIManaged    # Stage E1
│   ├── qmcp.DetachDeviceAIManaged    # Stage E1
│   ├── qmcp.SpawnDisposableAIManaged # Stage E2
│   ├── qmcp.SetFeatureAIManaged      # Stage F1
│   ├── qmcp.AIManagedEvents          # Stage F2
│   ├── qmcp.GetPoolStats             # Stage F3
│   ├── qmcp_budget.py                # Stage I-0 — shared cap-gate helper
│                                      # loaded by Spawn/Clone/SpawnDisposable
│   ├── qmcp_scope.py                 # Stage I-1 — shared read-scope redactor
│                                      # loaded by GetProperty/List
│   ├── qmcp_audit.py                 # Stage I-2 — shared hash-chained audit log
│                                      # loaded by the 8 state-changing wrappers
│   ├── qmcp_tier.py                  # Stage I-3 — shared tier-resolution helper
│                                      # (Stage I-5 sources it: the 8 wrappers gate
│                                      # on CAP_FULL + strip inherited tier tags on
│                                      # create. I-5 added NO new dom0-rpc file —
│                                      # it modified the 8 wrappers + the policy.)
│   └── qmcp_caps.py                  # Wave 2 Stage 1 — the decision kernel, SHADOW
│                                      # mode: decide() derives a verdict from the
│                                      # domination lattice, the 8 wrappers compare it
│                                      # against what they did and log only the
│                                      # difference. Enforces nothing (see below).
├── template-rpc/                   # drafts → /etc/qubes-rpc/ inside ai-managed templates
│   ├── qmcp.RunInAIManaged
│   └── qmcp.CopyToAIManaged
└── deploy/                         # one install/uninstall/test per stage
    ├── install-stage-a.sh
    ├── uninstall-stage-a.sh
    ├── test-stage-a.py
    ├── install-stage-b.sh
    ├── uninstall-stage-b.sh
    ├── test-stage-b.py
    ├── install-stage-c.sh
    ├── uninstall-stage-c.sh
    ├── test-stage-c.py
    ├── install-stage-d.sh
    ├── uninstall-stage-d.sh
    ├── test-stage-d.py
    ├── install-stage-e1.sh
    ├── uninstall-stage-e1.sh
    ├── test-stage-e1.py
    ├── install-stage-e2.sh
    ├── uninstall-stage-e2.sh
    ├── test-stage-e2.py
    ├── install-stage-f1.sh
    ├── uninstall-stage-f1.sh
    ├── test-stage-f1.py
    ├── install-stage-f2.sh
    ├── uninstall-stage-f2.sh
    ├── test-stage-f2.py
    ├── install-stage-f3.sh
    ├── uninstall-stage-f3.sh
    ├── test-stage-f3.py
    ├── install-stage-I-0.sh
    ├── uninstall-stage-I-0.sh
    ├── test-stage-I-0.py
    ├── install-stage-I-1.sh
    ├── uninstall-stage-I-1.sh
    ├── test-stage-I-1.py
    ├── install-stage-I-2.sh
    ├── uninstall-stage-I-2.sh
    ├── test-stage-I-2.py
    ├── install-stage-I-3.sh
    ├── uninstall-stage-I-3.sh
    ├── test-stage-I-3.py
    ├── install-stage-I-4.sh
    ├── uninstall-stage-I-4.sh
    ├── test-stage-I-4.py
    ├── install-stage-I-5.sh
    ├── uninstall-stage-I-5.sh
    └── test-stage-I-5.py
```

## Operating protocol

- **The operator edits dom0.** This codebase produces drafts; the operator
  reviews and copies them to dom0 via `qvm-run --pass-io`. MCP never has
  write access to dom0.
- **The operator tags.** `qvm-tags <vm> add|del ai-managed` enrolls or revokes
  existing qubes. New qubes spawned via `qmcp.SpawnAIManagedQube` are
  auto-tagged.
- **Stage gates.** Each stage's deliverable lands as a single reviewable set:
  policy diff + new qmcp scripts + MCP tool changes. The operator approves
  before deploy. After deploy, the stage's test plan runs from mcp-control.
  Do not begin the next stage until the current one's tests pass.

## Versioning

**Releases are semantically versioned from 0.9.0 onward** (see `CHANGELOG.md`).
The lettered *stage* vocabulary below is retained as the as-built design record
and in `deploy/` filenames; those filenames will be renamed to match in a later
release, kept as a separate mechanical change so it stays reviewable.

0.9.0 is pre-1.0 on purpose. The resource axis is complete and enforced, but
least privilege is not yet *operable*: the create path strips every inherited
tier tag (the keystone, working as designed), so post-flip a created qube is
untiered and has no capability at all — an operator must tier it before it can
be started, cloned, retargeted or executed in. 1.0.0 is reserved for the release
where an agent can work inside least privilege without an operator action
between every create and its first use.

## Stage status

All stages **A–F3 + I-0..I-5 are implemented and tested**; the per-stage *state*
is the Status table in `README.md`, and the *design* of each is the "Stage
rollout" block above. **Wave 1 of Stage I (I-0..I-5) is complete** — the resource
axis is live and behaviour-neutral until the operator tiers the fleet and runs
the coordinated least-privilege flip (delete the four compat backstops + write
`ro` to `/etc/qmcp/tier-default`).

**Wave 2 was redesigned after a clean-room install run.** The original
I-6..I-8 plan had the operator *author* a per-class `(tag, service, action)`
gate matrix; that is dropped. The matrix is **derived** by the dom0 kernel
`qmcp_caps.decide()` from a domination lattice, so a gate that an existing
capability already dominates cannot be written at all. **Stage 1 of that wave —
the kernel itself, in shadow mode — is what ships here** (see `W2-1` above):
it enforces nothing and exists to produce the divergence log that gates the
later flip. The stages after it, not yet built, are ownership + birth tier +
birth egress; flipping enforcement to `decide()`; klass handling; the remaining
egress work; then grants and a sign-only vault. **Stages G and H** stay
deferred.

### Per-surface enforcement decision table (where each tier check lives)

| Surface | Method(s) | Tier required | Enforced at |
|---|---|---|---|
| reads / discovery | `GetProperty`, `List`, `AIManagedEvents` | `ai-ro` (umbrella) | wrapper (dom0 tag-check) |
| firewall read | `firewall.Get` | `ai-ro` (umbrella) | **policy** `@tag:ai-managed` |
| device enumerate | `qmcp.ListAttachedDevicesAIManaged` (attached + available) | `ai-ro` (umbrella) | **wrapper (dom0 redactor)** — direct `device.*` denied (G0) |
| firewall write | `firewall.{Set,Reload}` | `ai-net` / `ai-full` | **policy (I-4)** `@tag:ai-net` + `@tag:ai-full` (+ compat backstop) |
| copy-IN sink | `qubes.Filecopy → ai-dump` | `ai-dump` (orthogonal) | **policy (I-4)** `@tag:ai-dump` target |
| exec / copy | `RunInAIManaged`, `CopyToAIManaged` | `ai-exec` | **policy (I-5)** `@tag:ai-exec`/`ai-net`/`ai-full` (+ compat backstop) |
| lifecycle / property / clone / spawn / feature / attach / detach | the `qmcp.*` `@adminvm` wrappers | `ai-full` | **wrapper (dom0 CAP_FULL gate)** |

*Create paths (Spawn/Clone/SpawnDisposable) strip every inherited tier tag on
create, so a newly-created qube is always **untiered** (umbrella only) — never an
elevation tag AI could leverage to self-escalate.*

## References

- Qubes Admin API: https://doc.qubes-os.org/en/latest/developer/services/admin-api.html
- Qrexec R4.2+ policy: https://forum.qubes-os.org/t/qrexec-policy-format-for-r4-2-and-r4-3/40407
- Community Admin API guide: https://forum.qubes-os.org/t/how-to-use-the-qubes-admin-policies-api-despite-the-lack-of-documentation-wip/29863
