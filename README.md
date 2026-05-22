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

Stages A, B, and C (below) are tested and working on Qubes R4.3-era
systems. Stages D–H are designed but not yet implemented.

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
and qrexec policy R4.2+), the three concrete questions I'd value review on:

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

## Status

| Stage | Capability | State |
|---|---|---|
| A | Tag-scoped lifecycle + spawn + wrapped property read/write + existence hiding | tested |
| B | Root command execution + inter-qube file transfer inside ai-managed qubes | tested |
| C | Single-egress network sandbox (`ai-net-router` chokepoint, operator-chosen upstream, tag-scoped firewall control) | tested |
| D | Template cloning + DispVM support | designed |
| E | Device attach (block/USB/mic) between ai-managed qubes | designed |
| F | Wrapped `feature.Set` (deny `internal`, validate cross-ref) + filtered event stream | designed |
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

(Both test scripts work from any cwd — they self-locate the package.)

Expect four PASS markers. If one fails, the test script's docstring describes
what each step verifies.

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

### Step 6 — Connect a client

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
