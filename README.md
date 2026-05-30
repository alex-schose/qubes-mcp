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

Stages A through F2 (below) are tested and working on Qubes R4.3-era
systems. Stages G–H are designed but not yet implemented.

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

If you're a Qubes engineer (core team or otherwise familiar with the Admin API
and qrexec policy R4.2+), the concrete questions I'd value review on:

1. **Wrapped-reads existence-hiding.** Is returning a uniform `"not found"`
   from a dom0 qmcp wrapper a robust primitive against existence oracles, or
   are there qrexec-layer leaks (timing, error chains, side effects) I'm
   missing?
2. **`qubes.Filecopy` `@tag:ai-managed → @tag:ai-managed` allow.** Stage B
   adds a policy line bypassing the default `ask` dialog for inter-qube file
   transfer between ai-managed qubes. Are there assumptions in
   `qubes.Filecopy`'s implementation that depend on the dialog being present?
3. **`target=@adminvm` documentation gap.** Without that clause on
   tag-scoped admin allows, qrexec attempts to start the target VM during
   read-only operations. This is subtle, easy to miss, and not surfaced in
   current Qubes docs. Worth a docs PR? Happy to write it.
4. **Single-egress chokepoint + `provides_network` egress invariant.**
   Stage C designates one ai-managed qube (`ai-net-router`) with
   `provides_network=true` as the only egress AI sees, then refuses (via
   `qmcp.SetPropertyAIManaged`) any netvm mutation on ai-managed qubes
   carrying `provides_network=true`. Intent: only the operator changes
   the route, in dom0. Is this invariant tight enough — are there paths
   AI could use to bypass it (creating another provides_network qube
   through a side door, mutating `provides_network` through a property
   wrapper I haven't blocked, abusing network-stack properties I haven't
   thought of)?
5. **Single-egress vs. cascade as a Qubes idiom.** The original Stage C
   design was a cascade (`ai-sys-firewall` ← `ai-sys-tor` / `ai-sys-vpn`)
   with multiple ai-managed network qubes. The implemented design is one
   egress qube with the operator-chosen upstream (`sys-firewall` /
   `sys-whonix` / a VPN qube / null). Documented Qubes patterns lean on
   cascades; is the single-egress chokepoint an established pattern I
   missed, or a reinvention? Are there reasons (memory pressure, boot
   ordering, sys-net interactions) the cascade is preferred that I'm not
   seeing?
6. **`@tag:` matching on klass=DispVM targets.** Stage D testing
   surfaced this: a persistent DispVM (`app.add_new_vm("DispVM", …)`)
   carries the `ai-managed` tag directly (verified via the Admin API
   from dom0), but qrexec policy refuses
   `admin.vm.Remove * mcp-control @tag:ai-managed allow target=@adminvm`
   with "Request refused" — i.e., the rule never matches a klass=DispVM
   target on Qubes R4.3. The same rule works for klass=AppVM and
   klass=TemplateVM. The same effect was observed for
   `admin.vm.{Start,Shutdown,Kill,Pause,Unpause}`. We worked around
   this in Stage D by routing all lifecycle through a single dom0
   wrapper (`qmcp.LifecycleAIManaged`) that does the ai-managed check
   in dom0 with qubesadmin authority, sidestepping qrexec policy
   evaluation entirely — same posture as
   `qmcp.{Get,Set}PropertyAIManaged`. Is the underlying qrexec
   `@tag:`-on-DispVM behaviour intentional (lifecycle of disposables
   restricted to dom0 by design?), a bug, or a configuration step I'm
   missing? Even with the workaround in place, a definitive answer
   would let us decide whether the wrapper is permanent architecture
   or temporary scaffolding.
7. **qubesadmin `VMCollection` cache lag after
   `admin.vm.CreateDisposable`.** Stage E2's `qmcp.SpawnDisposableAIManaged`
   wrapper calls `admin.vm.CreateDisposable` via `qubesd_call`, gets
   back the new disposable's name, and then needs to set the
   `ai-managed` tag on it before returning. The natural code —
   `app.domains[disp_name].tags.add("ai-managed")` — raises
   `KeyError(disp_name)` for several seconds after creation: the
   `qubesadmin.app.VMCollection` populates lazily and doesn't refresh
   synchronously after CreateDisposable. We worked around it by
   routing tag.Set / tag.List / Kill through
   `app.qubesd_call(disp_name, ...)` directly, bypassing the cache.
   Is the lazy `VMCollection` the intended client-side contract
   (callers expected to handle the read-after-write lag themselves),
   or is it a missing cache-invalidation hook in the Admin client?
   A definitive answer would let us decide whether the direct-call
   pattern should propagate to other "create-then-mutate" wrappers
   (`SpawnAIManagedQube`, `CloneAIManagedQube`) that may have the
   same latent bug — we haven't hit it there because they apply the
   tag through the VM object returned by `add_new_vm`/`clone_vm`,
   which is freshly-fetched and doesn't go through the collection
   cache.
8. **Cross-ref error messages as an existence oracle — RESOLVED in
   Stage F2 bundle.** Stage F1's `qmcp.SetFeatureAIManaged` collapsed
   cross-VM-key cross-refs to a single opaque refusal so AI cannot
   probe whether an arbitrary qube name exists; the older
   `qmcp.SetPropertyAIManaged` and `qmcp.SpawnAIManagedQube` wrappers
   distinguished `"not found"` from `"is not ai-managed"` on their
   cross-refs, a latent existence oracle on the write/spawn surface.
   The Stage F2 bundle backports the same opaque collapse to both
   older wrappers (template/netvm/default_dispvm for SetProperty,
   template/netvm for Spawn). Klass-mismatch and egress-invariant
   messages stay informative: they fire only after the referenced
   qube has been confirmed ai-managed, so AI already has the bit
   they would reveal. The read and lifecycle surfaces remain
   uniformly opaque; cross-ref refusals on every write/spawn surface
   are now opaque too. Reviewers welcome to flag any remaining
   distinguishable refusal on the write side.

9. **Event-stream payload — kwargs whitelist.** Stage F2's
   `qmcp.AIManagedEvents` returns a minimal payload per event:
   `{event, subject, subject_klass, ts}`, plus a whitelisted `tag`
   kwarg for `domain-tag-add` / `domain-tag-delete` (the one piece
   of payload data that's load-bearing — AI must see which tag
   changed to act on a boundary revocation). All other kwargs are
   dropped by default because some events (notably `property-set`)
   carry references to other qube names that could leak operator
   qubes into AI's view. Is the no-kwargs default the right cut, or
   are there specific kwargs a downstream stage will need (e.g.
   `exit_code` on `domain-stopped`, `value` on property-set)? Easy
   to expand the whitelist; hard to retract leaked fields. We're
   inclined to expand only with a concrete use case and a per-event
   leak analysis.

10. **Event-stream tag check for vanished subjects.** Admin events
    like `domain-shutdown` / `domain-delete` fire *after* the VM
    is removed from the dom0 collection, so a live `vm.tags` check
    at handler time raises `KeyError`. Our wrapper falls back to a
    snapshot of ai-managed names taken at window-open. Live wins
    over snapshot when the VM still exists, so newly-tagged
    qubes surface their post-tag events and newly-untagged qubes
    drop out (except for `domain-tag-delete:ai-managed` itself —
    the boundary-revocation event has a special case that includes
    it when the subject was in the snapshot). The snapshot is
    never refreshed during the window. Cost: a `domain-tag-add`
    + immediate delete on a qube that was *not* in the snapshot
    drops the delete event (snapshot says no, live says no
    because the VM is gone). The bounded duration `[1, 120]s`
    keeps this window small; reviewers welcome to flag a tighter
    design.

## Status

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
| G | mcp-control hardening + Tor hidden service for sshd → mobile CLI reach | designed |
| H | FastMCP HTTP/SSE bound to a second .onion → mobile-app reach | designed |

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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-a.sh' > /tmp/install-a.sh
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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-b.sh' > /tmp/install-b.sh
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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-c.sh' > /tmp/install-c.sh
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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-d.sh' > /tmp/install-d.sh
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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-e1.sh' > /tmp/install-e1.sh
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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-e2.sh' > /tmp/install-e2.sh
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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-f1.sh' > /tmp/install-f1.sh
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
qvm-run --pass-io mcp-control 'cat ~/qubes_mcp/deploy/install-stage-f2.sh' > /tmp/install-f2.sh
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

### Step 11 — Connect a client

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
threat model assumes the MCP source qube (`mcp-control`) is itself the trust
boundary — compromising it does not let AI escape the `ai-managed` tag scope
at the dom0/policy layer, but the AI in question can do anything inside its
sandbox. Stage G adds further hardening (sudo lockdown, dedicated MCP user).
Run on your own infrastructure; report bugs in issues.
