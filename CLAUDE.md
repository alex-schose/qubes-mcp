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
  1. The `qmcp.SpawnAIManagedQube` dom0 script (force-tags every qube it creates).
  2. The operator's hand in dom0 (`qvm-tags <vm> add|del ai-managed`).
- AI never has direct access to admin write methods. Every state-changing call
  is either tag-scoped via qrexec policy (lifecycle: Start/Shutdown/Remove/etc.)
  or routed through a `qmcp.*` dom0 RPC wrapper that enforces invariants in dom0.
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
| `qmcp.SpawnAIManagedQube` | Create AppVM (A); other classes in D. Auto-tags. Validates name + template + (optional) netvm. | A → D |
| `qmcp.GetPropertyAIManaged` | Wrapped read. `"not found"` is indistinguishable from `"not tagged"`. | A |
| `qmcp.SetPropertyAIManaged` | Wrapped write with cross-ref validation on `template`/`netvm`/`default_dispvm`. | A |
| `qmcp.GetPoolStats` | Free-space pressure on the default pool. | A |
| `qmcp.RunInAIManaged` | Execute command inside ai-managed qube as root. Custom qrexec service in ai-managed templates. | B |
| `qmcp.CopyToAIManaged` | File transfer; both source and target must be ai-managed. | B |
| `qmcp.CloneAIManagedQube` | Clone an existing ai-managed qube; auto-tags the clone. | D |
| `qmcp.AttachDeviceAIManaged` | Virtual device attach. Both qubes (provider and consumer) must be ai-managed. | E |
| `qmcp.DetachDeviceAIManaged` | Mirror of Attach. | E |
| `qmcp.SetFeatureAIManaged` | `feature.Set` with `internal`-key denied + cross-ref validation. | F |
| `qmcp.AIManagedEvents` | Filtered event stream — events whose subject is `@tag:ai-managed`. | F |

## Stage rollout (locked)

```
A. Policy + qmcp (List/Spawn/GetProperty/SetProperty/GetPoolStats) + tag-scoped
   lifecycle (Start/Shutdown/Kill/Pause/Unpause/Remove). Prereq: one ai-managed
   template.
B. qmcp.RunInAIManaged + qmcp.CopyToAIManaged. AI gets root inside its qubes
   and can move files between them.
C. Network sandbox: ai-sys-firewall + ai-sys-vpn + ai-sys-tor cascade. AI's
   qubes get tag-scoped netvm validation in SetPropertyAIManaged.
D. qmcp.CloneAIManagedQube + DispVM template support. AI manages its own
   template lineage.
E. qmcp.AttachDeviceAIManaged + Detach. Virtual block/USB/mic between
   ai-managed qubes.
F. qmcp.SetFeatureAIManaged (deny `internal`, validate cross-ref keys
   `audiovm`/`guivm`) + qmcp.AIManagedEvents.
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
- **No `admin.Events` direct subscription.** Use `qmcp.AIManagedEvents` (Stage F)
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
│       └── qubes_install_pkg.py    # Stage B convenience
├── policy/
│   └── 30-mcp-control.policy       # draft → /etc/qubes/policy.d/ in dom0
├── dom0-rpc/                       # drafts → /etc/qubes-rpc/ in dom0
│   ├── qmcp.ListAIManagedQubes
│   ├── qmcp.SpawnAIManagedQube      # atomic tag-on-create + post-condition check
│   ├── qmcp.GetPropertyAIManaged
│   └── qmcp.SetPropertyAIManaged
├── template-rpc/                   # drafts → /etc/qubes-rpc/ inside ai-managed templates
│   ├── qmcp.RunInAIManaged
│   └── qmcp.CopyToAIManaged
└── deploy/                         # one install/uninstall/test per stage
    ├── install-stage-a.sh
    ├── uninstall-stage-a.sh
    ├── test-stage-a.py
    ├── install-stage-b.sh
    ├── uninstall-stage-b.sh
    └── test-stage-b.py
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
  are invisible. All PASS markers in `deploy/test-stage-a.py` green.
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
- **Stage D onward** — designed, not yet implemented. See the stage rollout
  table above.

## References

- Qubes Admin API: https://doc.qubes-os.org/en/latest/developer/services/admin-api.html
- Qrexec R4.2+ policy: https://forum.qubes-os.org/t/qrexec-policy-format-for-r4-2-and-r4-3/40407
- Community Admin API guide: https://forum.qubes-os.org/t/how-to-use-the-qubes-admin-policies-api-despite-the-lack-of-documentation-wip/29863
