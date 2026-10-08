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

**Status: 0.9.23 — anonymous projects.** Besides the hub, up to 15
projects, each with its own lead agent that creates and runs its own workers
inside the project's names, templates, networks and disk quota, and sees
nothing outside it; a copy out of the project needs the operator's dialog.
Every network an AI qube is given is a gateway the operator enrolled, and a
lead's firewall, which dom0 writes to allow its model endpoint (and DNS for a
host name), nothing else, is the operator's. A lead can instead use a
self-hosted model in a **model qube** with no network, which, while it is
guarded, nothing in AI space reaches but the leads it serves (the hub only
through your dialog); the lead then has no network either.
A project can be **anonymous**: its qubes sit only on anonymising routers (Tor,
a VPN), its templates update only through the qube above one, and a gate in
dom0 checks that every 15 seconds and after every `qmcp` change, and stops the
project when it is not so. One hidden from
the hub (the default) is out of the hub's reach, its names are random, and the
hub's services answer about them as about names that do not exist.
The operator runs it all from `qmcp-gui`, a window in dom0 that is the `qmcp`
command with forms: every change it makes is a command it shows first. The hub
may ask for a project, a change to one, a new lead, a lead's new firewall or a
deletion; nothing happens until the operator accepts it in dom0, in that
window or with `qmcp proposal accept`. Next: an installation-wide anonymous
mode (the rest of M3), other distributions (M4), sealed qubes
(M5) and the complete GUI (1.0.0). 0.9.17 replaced the tier model of
0.9.0–0.9.16; see `CHANGELOG.md`.

## How it works

```
  dom0 (trusted)
    30-mcp-control.policy     static rulebook, checked by qrexec's own parser at install
    qmcp.* services           one shared, fail-closed check; identity = the qrexec caller
    qmcp (command)            the operator's tool: check, list, gateway, manage, guard,
                              revoke, project, proposal, migrate
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
  exist, and reads redact references to it, except the gateways the operator
  enrolled, which the hub reads by name. Three things still tell the hub
  whether a name exists: a create colliding inside the reserved prefix; a
  proposal the operator accepted, which succeeds or fails; and a call to
  `@dispvm:<name>`, which Qubes refuses at once unless the name is a
  disposable template (see the residual risks in [CLAUDE.md](CLAUDE.md)).
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
  What a project's workers can reach is bounded by the gateways you list for
  it, which must be enrolled; inside that, the hub and the lead narrow each
  worker's reach with its firewall rules. The lead's own reach is its
  firewall, which is yours.
- **Proposals.** The hub cannot create a project, change or remove a lead,
  delete a project, change a project's templates, networks or quota, or
  change a lead's firewall. It
  may propose each of those, as the options of one `qmcp project` command,
  and the operator accepts or rejects it in dom0, in the window or with
  `qmcp proposal accept` or `reject`: accepting runs that command's own
  code, refused if the stored proposal is not the one shown. Removing a lead
  or a project, a network AI space does not use yet, promoting one of the
  hub's qubes, an over-committed quota, a model endpoint no project uses,
  giving a project a different model endpoint, every change to a lead's
  firewall, and naming a model qube or taking one away need a second tick. The hub learns
  only whether it was accepted, rejected, expired or failed; dom0 announces
  each proposal with a desktop notification whose text the hub cannot choose.
- **Anonymous projects.** dom0's anonymity gate judges each one every 15
  seconds and after every `qmcp` command that changes qubes, projects or gateways: its networks
  and its lead's are anonymising gateways still on the network recorded for
  them, no qube of it has an update proxy around its router, its self-hosted
  model qube (if any) has no way out, its templates are guarded or outside AI
  space, a TemplateVM has no network and its updates go only to the qube
  directly above an anonymising gateway (or nowhere), and its qubes wear its
  badges. When one condition breaks, the gate badges the project's lead and
  every member `qmcp-blocked` (the rulebook and the dom0 services then refuse
  every call that would reach or wake one), then kills them, turns their autostart off, logs it and tells you (a desktop notification, or the
  command's output when a `qmcp` command broke it); it removes
  nothing, and only you clear it. An anonymous qube opens no URL or file in
  another qube, not even through a dialog. A hidden one has a random label, its
  qubes are out of the hub's reach by the rulebook, and the services answer the
  hub about them as about names that do not exist.
- **Creates** take only names inside the caller's own space under a reserved
  prefix (default `ai-`: the hub's `ai-hub-`, a lead's `ai-<label>-`; Qubes
  names disposables itself), strip the qmcp badges a new
  qube must not carry, stamp it, and prove its network before handing it back.
- **AI space cannot call dom0** beyond the services a qube needs to boot and
  keep its clock (a lead also calls nine qmcp services), cannot reach the hub
  or a lead, cannot use Qubes' raw disposable shortcut, and cannot touch the
  Admin API, except a lead's firewall methods on its own workers. A copy needs
  the operator's dialog unless it stays inside one slot or goes into that
  slot's dump sink, and a copy into a guarded qube, the hub or a lead is
  refused.
- **Every change made through a dom0 service** (creates, removes, lifecycle,
  properties, features, proposals), and every change the operator makes with
  the `qmcp` command or the window, is recorded on a hash-chained log in dom0
  that AI cannot read. Logging is best-effort: a failed write never blocks the change.
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
| `qubes_firewall_get`, `qubes_firewall_set` | read any AI-space qube's firewall; replace a managed one's (a lead's is the operator's: propose it) |
| `qubes_events` | a window of events for qubes in scope |
| `qubes_get_pool_stats` | the caller's disk budget: AI space, every project's record and the enrolled gateways for the hub, the project for a lead, with the names, templates and networks a lead may use and its model (an endpoint, or a model qube and its port) |
| `qubes_propose_project`, `qubes_propose_project_edit`, `qubes_propose_dump`, `qubes_propose_lead`, `qubes_propose_lead_firewall`, `qubes_propose_project_delete` | the hub asks the operator for a project, a change to one, a dump sink, a new lead or none, a lead's new firewall, a deletion |
| `qubes_proposals` | what became of the hub's proposals: pending, accepted, rejected, expired or failed |

The hub and a lead run the same server and see the same tools; dom0 scopes
each call to its caller. A lead has no event stream and cannot propose.

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
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.23.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh
```

The installer runs every preflight check before it changes anything: its
options, the fleet's shape, and the policy, which it validates with qrexec's own
parser against your policy directory, including that no file sorting earlier
overrides its 38 checked claims. It starts the anonymity gate's timer as your
dom0 user, installs the policy last and ends with `qmcp check`. Options:
`--hub NAME`, `--birth-egress QUBE`, `--pool-cap BYTES`, `--private-cap BYTES`,
`--gate-user NAME`, `--dry-run`. `deploy/uninstall.sh` removes the policy
first, then the rest, and ends with a clean-state check that names what it
keeps.

It also installs **the operator's window**: *qubes-mcp* in the Qubes menu
under Settings > Qubes Tools, or `qmcp-gui` in a dom0 terminal, run as your own
user. It shows AI
space and the projects as a tree, the gateways AI space may use, each lead's
model endpoint and firewall, the `qmcp check` light, the audit log and the
settings, each anonymous project with what the anonymity gate found, and
offers every command that changes something, but `migrate`, as a form. Each form shows the command it will run (`sudo -n qmcp ...`); the
window runs nothing but the `qmcp` command.
Text that AI chose, such as a name in the audit log, is shown escaped:
`\u202e`, never a reversed line.

Coming from 0.9.22? Install over it; nothing changes until you create an
anonymous project (step 7). Rolling back to 0.9.22 needs every anonymous
project deleted first, then the `upstream` keys removed from
`/etc/qmcp/gateways.json`: 0.9.22 refuses both, and has nothing that keeps the
hub out of a hidden project. Then run this release's `uninstall.sh` (it keeps
`/etc/qmcp`) before installing 0.9.22, or 0.9.22 leaves `qmcp-gate.timer`
running a command it does not have.
Coming from 0.9.21? Install over it. A lead whose model endpoint is an address
keeps the DNS rule 0.9.21 gave it until you set its model again (`sudo qmcp
project firewall NAME --model ADDRESS:PORT`); `qmcp check` warns until you do.
Coming from 0.9.17 to 0.9.20? Install over it; nothing is retagged. Then enroll
the gateways AI space uses (step 3): the registry starts empty, and until then
no AI qube can be given a network and `qmcp check` fails on every one (other
than a gateway) that has one. A Whonix gateway cannot be enrolled: put AI
qubes that sit directly on `sys-whonix` on a router in front of it
(`qvm-prefs QUBE netvm ROUTER`), or clear their network. Then accept each
lead's current firewall, or give it a model (`sudo qmcp project firewall NAME
--accept-current` or `--model HOST:PORT`); `--accept-current` takes only rules
in qmcp's format (no comment or expire, at most 32), so a lead with others
needs `--model` or `--rule`. `qmcp check` warns until you do. The hub's spawns
and clones must be named `ai-hub-…`.
Coming from 0.9.16?
Run the staged migration first; see "Install, migrate, uninstall" in
[CLAUDE.md](CLAUDE.md).

**3. AI space.** Agents run commands only in qubes whose template carries the
two in-qube services. Install them into a template and put it in AI space;
then enroll the gateways AI qubes may sit on. Use a plain router of your own
per kind of network (clearnet, Tor, a proxy, a VPN), in front of the qube that
kind uses for your own work, named so it reads as yours: `sys-ai-net`,
`sys-ai-tor`, `sys-ai-proxy`, `sys-ai-vpn`. A qube's own firewall rules are
carried out by the qube directly above it, and only a router that passes its
clients' traffic on carries them out: `sys-whonix` does not, so a Tor router
goes in front of it, and a limit for all your Tor AI belongs inside that router.

```sh
# in dom0
qvm-clone <a Debian template> ai-debian-13    # a template for AI qubes, if you have none
for s in qmcp.RunInAIManaged qmcp.CopyToAIManaged; do
  qvm-run --pass-io -u root ai-debian-13 \
    "cat > /etc/qubes-rpc/$s && chmod 0755 /etc/qubes-rpc/$s" < /tmp/qubes-mcp/template-rpc/$s
done
sudo qmcp manage ai-debian-13       # the hub may build on it; `guard` keeps it a reference only
qvm-create --class AppVM --template "$(qubes-prefs default_template)" --label red sys-ai-net
qvm-prefs sys-ai-net provides_network True
qvm-prefs sys-ai-net netvm sys-firewall
sudo qmcp gateway enroll sys-ai-net --label clearnet   # AI qubes may sit on it
echo sys-ai-net | sudo tee /etc/qmcp/birth-egress      # where the hub's template-based qubes go online
```

`qmcp gateway list` shows what is enrolled and whether each is still usable,
and marks a router whose upstream is a Whonix gateway. The birth-egress file is
needed unless the hub's own netvm is enrolled.

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
sudo qmcp project create osint --lead-template ai-debian-13 --lead-netvm sys-ai-net \
  --model api.anthropic.com:443 --network sys-ai-net --network none --quota 40G --dump
```

The lead is born as `ai-osint-lead`, with a firewall that allows its model
endpoint, DNS (for a host name) and nothing else (`qmcp project firewall osint` shows it, and
changes it); the qubes it creates will be named `ai-osint-*` (Qubes names
disposables), built from the approved templates (the lead's own when it is in AI space, plus
any `--template`), on the listed networks, inside the quota. `--lead-clone
QUBE` copies one of the hub's own qubes that you prepared as an agent instead,
and `--lead-promote QUBE` makes one of the hub's qubes the lead in place.
The lead's firewall lets it reach its model endpoint and DNS (for a host
name) only, so it cannot fetch software, `git clone` included: its agent and qubes-mcp come from
outside. Prepare both in one of the hub's qubes and make the lead with
`--lead-clone` or `--lead-promote`. Or install the agent in the lead's
template yourself, and copy qubes-mcp in from dom0, from step 2's tarball (if
dom0 has restarted since, `/tmp` is empty: fetch it again as step 2 does):

```sh
qvm-run --pass-io ai-osint-lead \
  'mkdir -p ~/qubes-mcp && tar -xzf - -C ~/qubes-mcp --strip-components=1' < /tmp/qmcp.tgz
```

Give the lead's agent its own model key. The agent runs in the lead, so its
MCP client starts the server there (`cd ~/qubes-mcp && exec python3 -m
qubes_mcp`), with no ssh. `qmcp project`, and the window, also edit, move
qubes between slots, remove or change a lead, and delete a project.

Or let the hub ask: its agent calls `qubes_propose_project` (or another
`qubes_propose_*` tool), dom0 shows a notification, and you accept or reject
the proposal in the window, where the options the hub sent, what accepting
does now and anything that needs a second tick are shown first.

**6. A self-hosted model (optional).** A lead can use a model that runs in a
qube of yours instead of a remote API: a **model qube**, guarded and with no
network, which the leads of the projects it serves reach on port 11434
through Qubes' `qubes.ConnectTCP`, and, while it is guarded, nothing else in
AI space (the hub only through your dialog). The lead then has no network either, so a
project with a self-hosted model, a lead with no network and workers on no
network is sealed.

Set the model qube up while it still has a network. The hub can, like any
qube it manages: spawned from a template the hub does not manage (a guarded
one) that carries the two in-qube services, with room on its private volume
(`private_size`). A qube you set up yourself outside AI space joins it with
`sudo qmcp guard QUBE` once it has no network (`qvm-prefs QUBE netvm ''`) or sits
on an enrolled gateway; `guard` refuses any other network. An AppVM keeps `/usr/local`,
`/home` and `/rw/config/rc.local` across restarts. With Ollama, as root in
the model qube:

```sh
cd /home/user
V=$(curl -fsSL https://api.github.com/repos/ollama/ollama/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')
B=https://github.com/ollama/ollama/releases/download/$V
curl -fsSL -o sha256sum.txt "$B/sha256sum.txt"
curl -fsSL -o ollama-linux-amd64.tar.zst "$B/ollama-linux-amd64.tar.zst"
want=$(awk '$2 ~ /(^|\/)ollama-linux-amd64\.tar\.zst$/ {print $1}' sha256sum.txt)
got=$(sha256sum ollama-linux-amd64.tar.zst | cut -d' ' -f1)
if [ -n "$want" ] && [ "$want" = "$got" ]; then
  tar --zstd -xf ollama-linux-amd64.tar.zst -C /usr/local --exclude='cuda_*' --exclude='rocm*' --exclude='vulkan*'
else
  echo "checksum MISMATCH: nothing installed"
fi
rm -f ollama-linux-amd64.tar.zst
cat > /rw/config/rc.local <<'EOF'
#!/bin/sh
runuser -u user -- env HOME=/home/user OLLAMA_HOST=127.0.0.1:11434 setsid /usr/local/bin/ollama serve >/home/user/ollama.log 2>&1 < /dev/null &
EOF
chmod 0755 /rw/config/rc.local && /rw/config/rc.local
sleep 5; runuser -u user -- env HOME=/home/user /usr/local/bin/ollama pull qwen2.5:0.5b
```

A qube has no IPv6 route, so a pull can stop at `network is unreachable` on an
IPv6 address; run the pull again, and it resumes.

Then, in dom0, make it the project's model qube. One command takes the lead's
network away, takes the qube out of p00, removes its network, guards it and
kills it if it runs, and only then lets the lead reach it (`--model-qube` on
`project create` and `project lead` does the same):

```sh
sudo qmcp project firewall osint --model-qube ai-hub-model
```

In the lead, `qvm-connect-tcp 11434:ai-hub-model:11434` (it runs until
stopped) makes the model answer on the lead's own `localhost:11434`; point
the agent there. `qubes_get_pool_stats` tells the lead the model qube's name
and port. To change the model qube later, un-guard it for a while (`sudo qmcp
manage ai-hub-model`; `qmcp check` warns until you guard it again, and `sudo
qmcp guard ai-hub-model` kills it if it runs, so no process the hub started in
it runs on; what it left in `/home`, `/usr/local` or `/rw` stays, and whatever
is set to start from there runs at its next start). Pulling
another model needs a network: take the qube off its projects first (`sudo
qmcp project firewall osint --model-qube none`), because a model qube with a
network would be its leads' way out, and `qmcp check` fails on one.

**A model qube may serve several projects, and that is a path between
them:** Ollama's API has no login and lets any client create, copy and delete
models, so a hijacked lead can change the model another project's lead uses,
or pass it data. It is safe only behind an API filter that lets inference
calls through and nothing else, and qmcp ships none: the command and the
window say so whenever a model qube is shared. One model qube per project
needs no filter. Several can share one copy of the server and the weights if a
guarded template holds both in its root filesystem (under `/opt`, say: a qube
based on a template has its own `/usr/local` and `/home`, never the
template's).

**7. Anonymous projects (optional).** Put a plain router of yours in front of
`sys-whonix` (or a VPN qube) and enroll it as anonymising: dom0 records the
network it sits on, and the gate stops any anonymous project on it if that ever
changes. In Qubes' Global Config (Updates), send your templates' updates
through `sys-whonix`, the qube directly above the router. Give the project a
template the hub never touched, guarded so it never can:

```sh
# in dom0
qvm-create --class AppVM --template "$(qubes-prefs default_template)" --label red sys-ai-tor
qvm-prefs sys-ai-tor provides_network True
qvm-prefs sys-ai-tor netvm sys-whonix
sudo qmcp gateway enroll sys-ai-tor --anonymising --label tor
qvm-clone <a Debian template of yours> anon-debian-13   # one the hub never touched
for s in qmcp.RunInAIManaged qmcp.CopyToAIManaged; do
  qvm-run --pass-io -u root anon-debian-13 \
    "cat > /etc/qubes-rpc/$s && chmod 0755 /etc/qubes-rpc/$s" < /tmp/qubes-mcp/template-rpc/$s
done
qvm-shutdown --wait anon-debian-13
sudo qmcp guard anon-debian-13
sudo qmcp project create --anonymous --lead-template anon-debian-13 --lead-netvm sys-ai-tor \
  --model api.anthropic.com:443 --network sys-ai-tor --quota 20G --note "what it is for"
```

dom0 picks the label and prints it with the lead's name; the note is yours
alone. `qmcp project list` shows each anonymous project, its kind and whether
it is stopped; `qmcp gate` and the window's Anonymity tab show what the gate
found; `sudo qmcp project unblock NAME` clears a
stop once the gate finds the project sound again. `--hub-sees` makes one the
hub may see and operate (hidden from the network, not from the hub). A model
qube or a template the hub operated before you guarded it can harm a hidden
project, since guarding removes nothing the hub left; projects behind one
router share its exit. Mark no anonymous qube to start at boot: the gate's
first run after boot is not ordered before Qubes' autostart.

## Tests

```sh
python3 -W error::DeprecationWarning -m unittest discover -s tests -p 'test_*.py'
```

The policy suite runs every rule through qrexec's real parser (it needs
`python3-qrexec`), next to upstream Qubes 4.3's default policy, and fails if any
rule decides nothing. `tests/seat_suite.py`, `tests/redteam_suite.py` and
`tests/project_suite.py` run in the hub against a real dom0; the last carries
`tests/lead_seat.py` into a project's lead and runs it there. On a test
machine running Qubes 4.3.1 they passed 41 of 41 checks, 39 of 39 probes and
80 of 80 checks on 2026-10-05, the lead seat inside a lead with no network that
asked its self-hosted model qube (Ollama, `qwen2.5:0.5b`) a question through
`qvm-connect-tcp`.
`tests/test_strict_reads.py` fails qube reads one at a time, at each point a
call makes them, and requires the restrictive answer: a failed read is never
taken for "no tags", "no network" or "not a gateway".
`tests/test_proposals.py` covers proposals: who may submit, the store, the
second tick, accepting and rejecting through the real commands.
`tests/test_gateways.py` covers the gateway registry, the networks AI qubes may
be given and leads' firewalls. `tests/test_anon.py` covers anonymous projects:
each gate condition broken on its own, with dom0's update question asked of
qrexec's real parser, the block and its order, a read that fails once and
twice, unblock, and what the hub can no longer see.
`tests/test_gui.py` drives the window's forms through the real `qmcp` command
and fails if the command has a command, option or field the window neither
offers nor exempts; `tests/GUI-CHECKLIST.md` is the click-through for a
person.

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
the trust boundary: a compromised hub controls all of AI space but hidden
anonymous projects, and the audit log records what it does through the dom0
services.

## License

MIT — see `LICENSE`.
