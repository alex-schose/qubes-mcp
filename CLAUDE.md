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
  - `admin.vm.firewall.{Get,Set,Reload}` on `@tag:ai-managed` targets
    (Stage C);
  - `admin.vm.device.{block,usb,mic}.{List,Available}` on
    `@tag:ai-managed` targets (Stage E1, read-only enumeration).
- AI has **root inside its sandbox qubes** (via `qmcp.RunInAIManaged`, Stage B)
  but no privilege inside `mcp-control` itself. mcp-control is an RPC gateway,
  not a workhorse. Locking down `mcp-control` is Stage G.
- The "wrapped reads" pattern (`qmcp.GetPropertyAIManaged`) returns the literal
  string `"not found"` indistinguishably whether the named qube doesn't exist
  or simply isn't tagged `ai-managed`. The MCP-side helper normalises all
  qrexec failures (policy deny, no-such-VM, transport) to the same opaque
  `"not found or refused"`, so AI cannot use either the read surface or the
  lifecycle surface as an existence oracle.

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
| `qmcp.SpawnAIManagedQube` | Create AppVM (A); DispVMTemplate + DispVM klasses (D). Auto-tags. Validates name + klass + template (incl. `template_for_dispvms` cross-ref for DispVM) + (optional) netvm. | A → D |
| `qmcp.GetPropertyAIManaged` | Wrapped read. `"not found"` is indistinguishable from `"not tagged"`. | A |
| `qmcp.SetPropertyAIManaged` | Wrapped write with cross-ref validation on `template`/`netvm`/`default_dispvm`. | A |
| `qmcp.LifecycleAIManaged` | start/shutdown/kill/pause/unpause/remove on ai-managed qubes. Replaces direct `admin.vm.*` lifecycle in Stage D — qrexec's `@tag:` matcher doesn't reach klass=DispVM targets, so we do the tag check in dom0. | D |
| `qmcp.GetPoolStats` | Free-space pressure on the default pool. Side-channel: aggregate pool usage leaks operator disk footprint. Three candidate shapes (raw stats / free-only / AI-scoped sum) — decision pending. | designed, deferred |
| `qmcp.RunInAIManaged` | Execute command inside ai-managed qube as root. Custom qrexec service in ai-managed templates. | B |
| `qmcp.CopyToAIManaged` | File transfer; both source and target must be ai-managed. | B |
| `qmcp.CloneAIManagedQube` | Clone an existing ai-managed qube; auto-tags the clone. | D |
| `qmcp.AttachDeviceAIManaged` | Virtual device attach. Both qubes (backend and frontend) must be ai-managed; dom0 wrapper enforces the tag check on both ends, then shells out to `qvm-device` (absorbs DeviceAssignment-API drift across Qubes 4.1 → 4.2 → 4.3). | E1 |
| `qmcp.DetachDeviceAIManaged` | Mirror of Attach. | E1 |
| `qmcp.SpawnDisposableAIManaged` | Ephemeral DispVM creation via `admin.vm.CreateDisposable`. DVMT must be ai-managed; the auto-named disposable is force-tagged before AI sees it; auto-removed on shutdown. | E2 |
| `qmcp.SetFeatureAIManaged` | `feature.Set` on ai-managed qubes. `internal` denied (operator-only); cross-VM keys (`audiovm`/`guivm`) must reference an ai-managed qube via an opaque refusal; echoes the post-set value back (no feature-read surface). | F1 |
| `qmcp.AIManagedEvents` | Filtered event stream — events whose subject is `@tag:ai-managed`. Bounded-window batch: tool blocks for a caller-given duration, wrapper collects ai-managed-filtered events, returns the batch. | F2 |

## Stage rollout (locked)

```
A. Policy + qmcp (List/Spawn/GetProperty/SetProperty) + tag-scoped
   lifecycle (Start/Shutdown/Kill/Pause/Unpause/Remove). Prereq: one ai-managed
   template. (qmcp.GetPoolStats was scoped here but deferred — the side-
   channel shape is unresolved; see the catalog row.)
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
G. mcp-control hardening (sudo lockdown, dedicated MCP user) + Tor hidden
   service for sshd → mobile CLI reach.
H. FastMCP HTTP/SSE transport bound to a second .onion → mobile-app reach.
```

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
│       └── qubes_events.py            # Stage F2
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
│   └── qmcp.AIManagedEvents          # Stage F2
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
    └── test-stage-f2.py
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

## Stage status

- **Stage A — DONE.** Policy + 4 qmcp.* dom0 RPC services + tag-scoped lifecycle.
  AI can list / spawn / inspect / lifecycle ai-managed qubes; untagged qubes
  are invisible. All PASS markers in `deploy/test-stage-a.py` green. (Stage D
  later replaced the tag-scoped `admin.vm.*` lifecycle policy lines with a
  dom0 wrapper, `qmcp.LifecycleAIManaged`, to handle klass=DispVM targets
  uniformly. The Stage A test still passes and exercises the new wrapper.)
- **Stage B — DONE.** `qmcp.RunInAIManaged` + `qmcp.CopyToAIManaged` (template-side
  services), `qubes.Filecopy` policy allow for ai-managed → ai-managed, and
  MCP tools `qubes_run` / `qubes_copy` / `qubes_install_pkg`. All PASS markers
  in `deploy/test-stage-b.py` green.
- **Stage C — DONE (tested).** Single-egress topology: `ai-net-router` is the
  only ai-managed network-providing qube. The operator chooses its upstream
  in dom0 (sys-firewall for clearnet, or a Tor/VPN qube to force all AI
  traffic through that route). MCP tools `qubes_firewall_get` /
  `qubes_firewall_set` wrap `admin.vm.firewall.Get/Set/Reload`,
  policy-allowed only for `@tag:ai-managed` targets. `qmcp.SpawnAIManagedQube`
  defaults new qubes' netvm to `ai-net-router` (explicit `null` opts out;
  explicit string requires an ai-managed value). `qmcp.SetPropertyAIManaged`
  refuses netvm changes on any ai-managed qube with `provides_network=true`,
  keeping the egress chokepoint operator-only. All 8 PASS markers in
  `deploy/test-stage-c.py` green.
- **Stage D — DONE (tested).** Three concrete changes:
  - `qmcp.CloneAIManagedQube` (new) — atomic clone + force-tag mirroring
    `qmcp.SpawnAIManagedQube`. Source must be ai-managed, else the opaque
    `"not found"`.
  - `qmcp.SpawnAIManagedQube` extended to accept `klass="DispVMTemplate"`
    (creates an AppVM with `template_for_dispvms` force-set True — the
    version-agnostic canonical form) and `klass="DispVM"` (a persistent
    named disposable; template must have `template_for_dispvms=True`).
  - `qmcp.LifecycleAIManaged` (new) — six-action wrapper covering
    start/shutdown/kill/pause/unpause/remove on ai-managed qubes,
    replacing the Stage A `admin.vm.*` tag-scoped allow lines. The
    rewrite was forced by Qubes R4.3 behaviour: qrexec's `@tag:`
    selector does NOT match klass=DispVM targets, even when the tag
    is set directly on the DispVM and visible via the Admin API from
    dom0. The wrapper does the ai-managed check in dom0 with qubesadmin
    authority, so the qrexec quirk doesn't apply and lifecycle works
    uniformly across all klasses.

  Policy: removes the six `admin.vm.{Start,Shutdown,Kill,Pause,Unpause,Remove}`
  tag-scoped allow lines (they were silently broken for klass=DispVM);
  adds two allow lines for `qmcp.CloneAIManagedQube` and
  `qmcp.LifecycleAIManaged`. MCP tools: new `qubes_clone` (Ring.CLONE);
  `qubes_spawn` gains a `klass` parameter;
  `qubes_start`/`qubes_shutdown`/`qubes_remove` route through
  `qmcp.LifecycleAIManaged`. Deploy: `deploy/install-stage-d.sh`. All
  6 PASS markers in `deploy/test-stage-d.py` green, including end-to-end
  DispVM start + run-as-root + shutdown — the ai-debian-13 → DVMT →
  DispVM service-inheritance chain works end-to-end. The prior Stages
  A/B/C tests also exercise the new lifecycle wrapper and remain green.
  (Stage A's test plan later grew to 5 PASS markers in the F2 bundle;
  B and C are unchanged.)
- **Stage E1 — DONE (tested).** Two new dom0 wrappers
  (`qmcp.AttachDeviceAIManaged`, `qmcp.DetachDeviceAIManaged`) attach
  virtual block/USB/mic devices between two ai-managed qubes; both
  ends must carry the tag, with the wrapper collapsing missing-or-
  untagged on either side to the same opaque `"not found"` so the
  device surface is not an existence oracle. The wrappers shell out
  to `qvm-device` rather than building DeviceAssignment objects in
  Python — qvm-device is the stable surface across Qubes 4.1 → 4.2 →
  4.3, while the Python class moved between `qubesadmin.devices` and
  `qubes.device_protocol` across releases. Read-only enumeration
  (`admin.vm.device.{block,usb,mic}.{List,Available}`) is tag-scoped
  via policy directly — same shape as Stage C `admin.vm.firewall.Get`.
  MCP tools: new `qubes_device_list` / `qubes_device_attach` /
  `qubes_device_detach`, all in a new `Ring.DEVICE`. Test plan in
  `deploy/test-stage-e1.py` has six HARD pass criteria (list-on-
  ai-managed-ok, list-on-untagged-opaque, attach-refuses-bad-frontend,
  attach-refuses-bad-backend, detach-refuses-bad-frontend, detach-
  refuses-bad-backend) plus a SOFT block exercising a real loop-device
  round-trip (informational because qubes-core-agent's block
  enumerator may not auto-expose `/dev/loop*` on a given template).
- **Stage E2 — DONE (tested).** `qmcp.SpawnDisposableAIManaged` is a
  thin dom0 wrapper around `admin.vm.CreateDisposable`: it validates
  the source is ai-managed AND has `template_for_dispvms=True`, calls
  the Admin API directly via `qubesd_call(tpl, "admin.vm.CreateDisposable")`
  (the stable Admin-protocol surface — qubesadmin's high-level helper
  name has drifted across versions), force-tags the auto-named result
  (`dispXXXX`), and rolls back (kill → auto_cleanup-removal) if the
  tag fails to apply. **All admin operations on the new disposable
  use `app.qubesd_call(disp_name, ...)` directly, NOT
  `app.domains[disp_name]`.** The qubesadmin `VMCollection` populates
  lazily and does not refresh synchronously after CreateDisposable —
  `app.domains[disp_name]` raises `KeyError(disp_name)` for several
  seconds post-create. Going through qubesd_call sidesteps the cache
  entirely. (This path also bypasses the `admin.vm.tag.Set @anyvm
  deny` policy line, which is fine: the deny gates inter-qube calls
  via qrexec, while qubesd_call uses the local dom0 socket with full
  admin authority.) The created qube inherits `auto_cleanup=True`
  from the Admin API default, so dom0 removes it when it halts — no
  separate cleanup wrapper needed. The trust posture mirrors
  `qmcp.SpawnAIManagedQube`: opaque `"not found"` for missing or
  untagged source, informative cross-ref message when the source IS
  ai-managed but lacks `template_for_dispvms`. `admin.vm.CreateDisposable`
  stays denied — the wrapper is the only allowed path. No new ring;
  disposable spawn fits Ring.LIFECYCLE. MCP tools: `qubes_spawn_disposable`
  (1:1 with the wrapper) and `qubes_run_disposable` (pure MCP-side
  composition: spawn → start + wait Running → RunInAIManaged → shutdown,
  with kill-as-fallback so a stuck disposable doesn't orphan after an
  error). Test plan in `deploy/test-stage-e2.py`: five PASS criteria
  covering full lifecycle invariants (klass + template + auto_cleanup),
  run-and-auto-remove cycle, plain-TemplateVM cross-ref refusal,
  untagged opaque refusal, and an end-to-end one-shot smoke test.
  Preamble cleanup is order-aware: it removes any leftover disposable
  tied to the test DVMT before removing the DVMT itself (Qubes refuses
  to remove a DVMT while any qube references it as `template`).
- **Stage F1 — DONE (tested).** `qmcp.SetFeatureAIManaged` wraps
  `admin.vm.feature.Set` on ai-managed qubes with the same posture as
  `qmcp.SetPropertyAIManaged`: opaque `"not found"` for a missing or
  untagged target. Two key classes get extra handling — `internal` is
  refused (operator-only; AI setting it could hide a qube from the
  operator's menus), and the cross-VM keys `audiovm`/`guivm` must
  reference an ai-managed qube, refused *opaquely* (missing and untagged
  collapse to one message — same posture every cross-ref across the
  write/spawn surfaces now ships with; the older `SetPropertyAIManaged`
  and `SpawnAIManagedQube` cross-refs originally distinguished the two
  and got the same opaque collapse in the Stage F2 bundle, closing
  reviewer ask #8). Values coerce to the Qubes string
  convention (bool True→`"1"`, False→`""`); `null` is rejected (set
  only — `admin.vm.feature.Remove` stays denied, removal is the
  operator's call). The response echoes the post-set value read back
  live from qubesd, so the round-trip is verifiable without a separate
  feature-read surface (`admin.vm.feature.Get` stays denied). Direct
  `admin.vm.feature.Set` stays denied — the wrapper is the only path.
  MCP tool `qubes_feature_set` in a new `Ring.FEATURE`. Test plan in
  `deploy/test-stage-f1.py`: five PASS criteria (round-trip + echo +
  bool coercion; `internal` refused; cross-ref to ai-managed accepted;
  cross-ref to untagged AND nonexistent both opaque + non-leaking;
  untagged target opaque `"not found"`). 5/5 green.
- **Stage F2 — DONE (tested).** `qmcp.AIManagedEvents` is a
  bounded-window event-stream wrapper. AI passes a `duration` (clamped
  to `[1, 120]` seconds) and optional `qube` / `events` filters; the
  wrapper subscribes to `admin.Events` in dom0 with full admin
  authority, filters every event by the ai-managed tag on its subject,
  and returns the collected batch when the window closes. No
  persistent dom0 process — one invocation, one window, one JSON
  response, exit. The tag filter is layered: live `vm.tags` check at
  handler time, with a fallback to a snapshot of ai-managed names
  taken at window-open for subjects that have vanished
  (`domain-shutdown` / `domain-delete` fire after the VM is gone). A
  special case includes `domain-tag-delete:ai-managed` when the
  subject was in the snapshot — that event IS the boundary
  revocation, the very signal AI most needs to see, and a strict
  live-tag-check would drop it. Payload is minimal:
  `{event, subject, subject_klass, ts}`, with the `tag` kwarg
  whitelisted for `domain-tag-add` / `domain-tag-delete` so AI can
  tell which tag changed. All other kwargs are dropped — a downstream
  stage can whitelist specific fields if a clear use case surfaces
  (reviewer ask #9). Direct `admin.Events` stays denied — the wrapper
  is the only path. New `Ring.EVENTS` (budget None — the
  block-for-duration shape is itself the rate limit). MCP tool
  `qubes_events(duration, qube=None, events=None)` returns the parsed
  batch. The bounded-window model trades inter-call event coverage for
  a stateless dom0 footprint; AI catches the immediate consequence of
  an action by opening the window FIRST (a concurrent tool call) and
  then acting. Test plan in `deploy/test-stage-f2.py`: five PASS
  criteria (basic surfacing, no untagged-subject leak, qube-filter
  positive, qube-filter opaque byte-identical, events-filter
  prefix-or-exact). 5/5 green.

  Shipped alongside the **opaque-cross-ref backport** to
  `qmcp.SetPropertyAIManaged` (template/netvm/default_dispvm) and
  `qmcp.SpawnAIManagedQube` (template/netvm): both wrappers'
  cross-ref errors used to distinguish `"not found"` from `"is not
  ai-managed"`, a latent existence oracle on every untagged qube
  name in dom0 (the same gap F1 deliberately closed on
  `SetFeatureAIManaged`). The backport collapses them to one opaque
  message that does not echo the value — consistent with the F1
  posture. Klass-mismatch / `template_for_dispvms`-missing /
  egress-invariant messages stay informative: they fire only after
  the referenced qube has been confirmed ai-managed, so AI already
  has the bit they would reveal. `deploy/test-stage-a.py` updated to
  assert byte-identical opaqueness on both SetProperty and Spawn
  cross-refs (5/5 green; reviewer ask #8 resolved).

- **Stage G onward** — designed, not yet implemented. See the stage
  rollout table above.

## References

- Qubes Admin API: https://doc.qubes-os.org/en/latest/developer/services/admin-api.html
- Qrexec R4.2+ policy: https://forum.qubes-os.org/t/qrexec-policy-format-for-r4-2-and-r4-3/40407
- Community Admin API guide: https://forum.qubes-os.org/t/how-to-use-the-qubes-admin-policies-api-despite-the-lack-of-documentation-wip/29863
