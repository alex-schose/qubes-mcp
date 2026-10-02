# qubes-mcp

**Autonomous AI workflows inside a Qubes-isolated sandbox.** AI agents get real
capabilities — creating qubes, building templates, running commands, moving
files — while the rest of the machine stays invisible to them. Qubes provides
the isolation; this project provides the capability surface, mediated by dom0
so the boundary is enforced, not trusted.

> **Threat-model-driven implementation: human-designed boundaries, AI-assisted
> code. Review from Qubes engineers welcome and needed.**

An MCP server runs in one qube, the **hub** (`mcp-control`), and in each
project's **lead**. Agents connect to it over stdio (usually through SSH) and
call its tools. Every tool is a qrexec
call, and dom0 decides it. Most go to a small library in dom0 that decides
which qube is in scope, what may change and what a new qube is born with;
running a command, copying a file out and the firewall go to the qube or the
Admin API under dom0's qrexec policy. The hub, and each lead, can do what dom0
allows it, and nothing more.

**Status: 0.9.19 — the operator's window.** Besides the hub, up to 15
projects, each with its own lead agent that creates and runs its own workers
inside the project's names, templates, networks and disk quota, and sees
nothing outside it; a copy out of the project needs the operator's dialog. The
operator runs it all from `qmcp-gui`, a window in dom0 that is the `qmcp`
command with forms: every change it makes is a command it shows first. Next:
proposals (the hub asks, the operator accepts in the window); then gateways
and anonymity (M3), other distributions (M4), sealed qubes (M5) and the
complete GUI (1.0.0). 0.9.17 replaced the tier model of 0.9.0–0.9.16; see
`CHANGELOG.md`.

## How it works

```
  dom0 (trusted)
    30-mcp-control.policy     static rulebook, checked by qrexec's own parser at install
    qmcp.* services           one shared, fail-closed check; identity = the qrexec caller
    qmcp (command)            the operator's tool: check, list, manage, guard, revoke,
                              project, migrate
        ▲  qrexec only
        │
  mcp-control (the hub)       MCP server, standard library only; reaches what dom0 allows
        │  qrexec, decided in dom0
        ▼
  AI space (tag ai-managed)
    the hub's own qubes       slot p00: the hub operates them
    project p01 … p15         a lead (its own MCP server and agent) and the workers it makes;
                              the hub operates these too, the lead only its own project
    guarded qubes             listed, read, spawned from — never operated (gateways always)
```

- **AI space** is every qube carrying `ai-managed`. Everything else is
  invisible: a qube outside AI space answers exactly like one that does not
  exist, and reads redact references to it.
- **Managed or guarded.** The hub operates managed qubes, including the
  templates and disposable templates it manages, so it can build them.
  Guarded qubes — gateways, and any template the operator wants kept clean —
  are references only.
- **Projects.** A lead operates only its project's workers, spawns only from
  the templates the operator approved for the project, puts workers only on
  the project's networks, and creates only inside its names (`ai-<label>-`)
  and disk quota. Workers call no qmcp service, cannot reach their lead or
  the hub, and reach another project only by a copy through the operator's
  dialog. Copies inside a project, and into its dump sink, need no dialog.
  What a project's qubes can reach is bounded by its egress, which you choose;
  inside it the hub and the lead narrow with firewall rules.
- **Creates** take only names the hub chooses inside a reserved prefix
  (default `ai-`; Qubes names disposables itself), strip the qmcp badges a new
  qube must not carry, stamp it, and prove its network before handing it back.
- **AI space cannot call dom0** beyond the services a qube needs to boot and
  keep its clock (a lead also calls nine qmcp services), cannot reach the hub
  or a lead, cannot use Qubes' raw disposable shortcut, and cannot touch the
  Admin API, except a lead's firewall methods on its own workers. A copy needs
  the operator's dialog unless it stays inside one slot or goes into that
  slot's dump sink, and a copy into a guarded qube, the hub or a lead is
  refused.
- **Every change made through a dom0 service** (creates, removes, lifecycle,
  properties, features) is recorded on a hash-chained log in dom0 that AI
  cannot read. Logging is best-effort: a failed write never blocks the change.
  Commands, copies and firewall writes are decided by the policy and are not
  on it.

The full design, and the risks it accepts, are in [CLAUDE.md](CLAUDE.md).

## Tools

| Tool | |
|---|---|
| `qubes_list`, `qubes_state`, `qubes_props_get` | what is in scope, and its properties |
| `qubes_spawn`, `qubes_clone`, `qubes_remove` | create (AppVM, disposable template, named disposable) and remove |
| `qubes_start`, `qubes_shutdown` | lifecycle |
| `qubes_props_set`, `qubes_feature_set` | label/memory/maxmem/vcpus, netvm only to none; features on an allowlist |
| `qubes_run`, `qubes_copy` | run a command as root in a managed qube; copy a file out of one (operator dialog) |
| `qubes_spawn_disposable`, `qubes_run_disposable` | disposables, or one command in a fresh disposable |
| `qubes_firewall_get`, `qubes_firewall_set` | read any AI-space qube's firewall; replace a managed one's |
| `qubes_events` | a window of events for qubes in scope |
| `qubes_get_pool_stats` | the caller's disk budget: AI space for the hub, the project for a lead, with the names, templates and networks a lead may use |

The hub and a lead run the same server and see the same tools; dom0 scopes
each call to its caller. A lead has no event stream.

From `~/qubes-mcp` in the hub, `python3 -m qubes_mcp.cli <tool> key=value ...`
runs any tool from a shell.

## Setup

Three places: the hub, dom0, and an AI template. The paths below assume the
repository is cloned to `~/qubes-mcp` in the hub.

**1. The hub.** Any AppVM with Python 3.10 or later. It must not carry
`ai-managed`.

```sh
# in dom0
qvm-create --class AppVM --template "$(qubes-prefs default_template)" --label gray mcp-control
# in mcp-control
git clone https://github.com/alex-schose/qubes-mcp.git ~/qubes-mcp
```

Nothing to install: the server uses only the standard library and talks to dom0
through `qrexec-client-vm`, which every qube has.

**2. dom0.** The installer runs as root, so fetch it somewhere AI cannot
write: a fresh disposable, not the hub. Any disposable template with curl and
network will do; Qubes' stock `default-dvm` does.

```sh
qvm-run --dispvm=default-dvm --pass-io \
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.19.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh
```

The installer runs every preflight check before it changes anything: its
options, the fleet's shape, and the policy, which it validates with qrexec's own
parser against your policy directory, including that no file sorting earlier
overrides its 24 checked claims. It installs the policy last and ends with
`qmcp check`. Options: `--hub NAME`, `--birth-egress QUBE`, `--pool-cap BYTES`,
`--private-cap BYTES`, `--dry-run`. `deploy/uninstall.sh` removes the policy
first, then the rest, and ends with a clean-state check that names what it
keeps.

It also installs **the operator's window**: *qubes-mcp* in the Qubes menu
under Settings > Qubes Tools, or `qmcp-gui` in a dom0 terminal, run as your own
user. It shows AI
space and the projects as a tree, the `qmcp check` light, the audit log and the
settings, and offers every command that changes something, but `migrate`, as
a form. Each form shows the command it will run (`sudo -n qmcp ...`); the
window runs nothing but the `qmcp` command.
Text that AI chose, such as a name in the audit log, is shown escaped:
`\u202e`, never a reversed line.

Coming from 0.9.17? Install over it; nothing is retagged. Coming from 0.9.16?
Run the staged migration first; see "Install, migrate, uninstall" in
[CLAUDE.md](CLAUDE.md).

**3. AI space.** Agents run commands only in qubes whose template carries the
two in-qube services. Install them into a template, then put it and your AI
gateway in AI space:

```sh
# in dom0
qvm-clone <a Debian template> ai-debian-13    # a template for AI qubes, if you have none
for s in qmcp.RunInAIManaged qmcp.CopyToAIManaged; do
  qvm-run --pass-io -u root ai-debian-13 \
    "cat > /etc/qubes-rpc/$s && chmod 0755 /etc/qubes-rpc/$s" < /tmp/qubes-mcp/template-rpc/$s
done
sudo qmcp manage ai-debian-13       # the hub may build on it; `guard` keeps it a reference only
sudo qmcp guard ai-net-router       # a gateway is always guarded
echo ai-net-router | sudo tee /etc/qmcp/birth-egress   # where template-based qubes go online
```

The birth-egress file is needed unless the hub's own netvm is in AI space.

**4. Connect a client.** For Claude Code (`~/.claude.json`):

```json
{
  "mcpServers": {
    "qubes": {
      "command": "ssh",
      "args": ["-T", "user@<mcp-control-host>",
               "cd ~/qubes-mcp && exec python3 -m qubes_mcp"]
    }
  }
}
```

Reach the hub over a network you control (a tailnet, Headscale, WireGuard).

**5. Projects (optional).** A project gets its own lead agent and workers.
*New project...* in the window, or in dom0, as root:

```sh
sudo qmcp project create osint --lead-template ai-debian-13 --lead-netvm ai-net-router \
  --network ai-net-router --network none --quota 40G --dump
```

The lead is born as `ai-osint-lead`; its workers will be named `ai-osint-*`,
built from the approved templates (the lead's own when it is in AI space, plus
any `--template`), on the listed networks, inside the quota. `--lead-clone
QUBE` copies one of the hub's own qubes that you prepared as an agent instead,
and `--lead-promote QUBE` makes one of the hub's qubes the lead in place. Put the client in the lead as you did in the hub, give it its
own model key, and connect its agent the same way. `qmcp project`, and the
window, also edit, move qubes between slots, remove or change a lead, and
delete a project.

## Tests

```sh
python3 -W error::DeprecationWarning -m unittest discover -s tests -p 'test_*.py'
```

The policy suite runs every rule through qrexec's real parser (it needs
`python3-qrexec`), next to upstream Qubes 4.3's default policy, and fails if any
rule decides nothing. `tests/seat_suite.py`, `tests/redteam_suite.py` and
`tests/project_suite.py` run in the hub against a real dom0; the last carries
`tests/lead_seat.py` into a project's lead and runs it there. On a test
machine running Qubes 4.3.1 they passed 38 of 38 checks, 23 of 23 probes and
66 of 66 checks on 2026-10-01. `tests/test_gui.py` drives the window's forms
through the real `qmcp` command and fails if the command has a command,
option or field the window neither offers nor exempts; `tests/GUI-CHECKLIST.md`
is the click-through for a person.

## Reviewer asks

Review from people who know qrexec policy and the Admin API is genuinely
wanted. The specific questions are in
**[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md)**.

Where this has been discussed:

- **qubes-devel design review**, answered point by point by the Qubes project
  lead: <https://groups.google.com/g/qubes-devel/c/4NuSqL64DVE>
- **Qubes forum thread**: <https://forum.qubes-os.org/t/41387>
- **Background**, the case for putting MCP trust boundaries below the protocol:
  <https://alexschose.com/writing/mcp-trust-boundaries-belong-below-the-protocol.html>

## Caveat

This is operator-grade infrastructure for one use case: AI agents working in
Qubes-isolated qubes. It is not a hardened product. The hub is itself part of
the trust boundary: a compromised hub controls all of AI space, and the audit
log records what it does through the dom0 services.

## License

MIT — see `LICENSE`.
