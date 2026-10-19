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

**Status: 0.9.37 — a hand copy loses its owner badge.** Besides the hub, up to 15
projects, each with its own lead agent that creates and runs its own workers
inside the project's names, templates, networks and disk quota, and sees
nothing outside it; a copy out of the project needs the operator's dialog.
A worker or a lead may be a **standalone**: its own copy of a template's
root, so the tools installed in it stay across restarts.
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
An installation can be in **anonymous mode**: every project is anonymous, and
the gate judges the hub too, with its own qubes and the templates it made.
A **guarded** qube — a template kept as a clean root, a model qube, any
reference — is sealed: the rulebook refuses the hub every way into it but
reading its firewall and your own dialogs. The
operator can open one for a bounded time with `qmcp open QUBE --for 2h`, to
install software in it or maintain it; the hub may then run commands in it and
copy a file in behind your dialog, and with `--firewall` write its firewall
rules, never its network. The window ends by itself, at every boot, and on
`qmcp seal`, which kills the qube, so what the hub had running in it was
stopped; firewall rules it wrote through the window stay, and the seal says so.
The operator runs it all from `qmcp-gui`, a window in dom0 that is the `qmcp`
command with forms: every change it makes is a command it shows first. The hub
may ask for a project, a change to one, a dump sink, a new lead or none, a
lead's new firewall, a deletion, a window on a guarded qube, a qube brought into AI space or out of
the guarded state, a qube taken out of AI space, or exact packages installed
into a template by its own package manager;
nothing happens until the operator accepts it in dom0, in that window or with
`qmcp proposal accept`. The two
in-qube services need python3 and `qvm-copy-to-vm` and nothing else; measured
on Qubes 4.3.1, a lead and its workers run on Debian 13, Fedora 43 and Arch
templates alike, and dom0 keeps its own copy of them, so
`qmcp template prepare` writes them into a template or a standalone at any
time. A qube that comes back from a backup, or is copied by hand, is held for
your review rather than rejoining a project that may have changed, and
`qmcp export` puts qmcp's settings where a Qubes backup carries them. The
audit round of 0.9.28 is being fixed by severity: 0.9.29 fixed the high
findings, 0.9.30 and 0.9.31 the medium ones, 0.9.32 the window's, with limits
on what one principal can put on the audit log (60 lines an hour of calls that
changed nothing, about 20,000 a day of changes), and this release the low ones
and the docs.
Next: 1.0.0 once all of it is green on a reinstalled machine. 0.9.17 replaced the tier model of 0.9.0–0.9.16; see `CHANGELOG.md`.

## How it works

```
  dom0 (trusted)
    30-mcp-control.policy     static rulebook, checked by qrexec's own parser at install
    qmcp.* services           one shared, fail-closed check; identity = the qrexec caller
    qmcp (command)            the operator's tool: check, list, settings, template,
                              restored, export, import, manage, guard, revoke,
                              open, seal, gateway, project, gate, proposal,
                              migrate, audit, version
        ▲  qrexec only
        │
  mcp-control (the hub)       MCP server, standard library only; reaches what dom0 allows
        │  qrexec, decided in dom0
        ▼
  AI space (tag ai-managed)
    the hub's own qubes       slot p00: the hub operates them
    project p01 … p15         a lead (its own MCP server and agent) and the workers it makes;
                              the hub operates these too, the lead only its own project
    guarded qubes             listed, read, spawned from; never operated but through a
                              window you open (gateways never)
```

- **AI space** is every qube carrying `ai-managed`. Everything else is
  invisible: a qube outside AI space answers exactly like one that does not
  exist, and reads redact references to it, except the gateways the operator
  enrolled, which the hub reads by name. Several things still tell the hub
  whether a name exists: a create colliding inside the reserved prefix; a
  proposal the operator accepted, which succeeds or fails; a dialog service,
  which is refused at once for a hidden project's qube, a held one or one the
  gate stopped, where a missing name gets the dialog; and a call to
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
  the hub, and reach another project only through the operator's dialog (a
  copy, or opening a file or URL in it), never a hidden one. Copies among a
  project's members, from its lead to them, and from a member into the dump
  sink, need no dialog.
  What a project's workers can reach is bounded by the gateways you list for
  it, which must be enrolled; inside that, the hub and the lead narrow each
  worker's reach with its firewall rules. The lead's own reach is its
  firewall, which is yours.
- **Proposals.** The hub cannot create a project, change or remove a lead,
  delete a project, change a project's templates, networks or quota, change
  a lead's firewall, open a guarded qube, bring a qube into AI space or take
  one out, remove a qube qmcp did not create (one you brought into AI space),
  or install packages into a guarded template. It
  may propose each of those, as the options of one `qmcp` command,
  and the operator accepts or rejects it in dom0, in the window or with
  `qmcp proposal accept` or `reject`: accepting runs that command's own
  code, refused if the stored proposal is not the one shown. Removing a lead
  or a project, a network AI space does not use yet, promoting one of the
  hub's qubes, an over-committed quota, a model endpoint no project uses,
  giving a project a different model endpoint, every change to a lead's
  firewall, naming a model qube or taking one away, creating an anonymous
  project, and every window,
  manage, revoke and package install need a second tick. The hub learns
  only whether it was accepted, rejected, expired or failed; dom0 announces
  each proposal with a desktop notification whose text the hub cannot choose.
- **Anonymous projects.** dom0's anonymity gate judges each one every 15
  seconds and after every `qmcp` command that changes qubes, projects or gateways: its networks
  and its lead's are anonymising gateways still on the network recorded for
  them, no qube of it has an update proxy around its router, its self-hosted
  model qube (if any) has no way out, its templates are guarded or outside AI
  space, a TemplateVM has no network and its updates go only to the qube
  directly above an anonymising gateway you ticked for updates (or nowhere),
  and its qubes wear its badges. When one condition breaks, the gate badges the project's lead and
  every member `qmcp-blocked` (the rulebook and the dom0 services then refuse
  every call that would reach or wake one), then kills them, turns their autostart off, logs it and tells you (a desktop notification, or the
  command's output when a `qmcp` command broke it); it removes
  nothing, and only you clear it. An anonymous qube opens no URL or file in
  another qube, not even through a dialog. A hidden one has a random label, its
  qubes are out of the hub's reach by the rulebook, and the services answer the
  hub about them as about names that do not exist. A stopped qube you start by
  hand reaches no other qube and no dom0 service (it keeps its network). In
  **anonymous mode** the gate also judges the hub qube and every qube in AI
  space that is not an anonymous project's lead, member or model qube, guarded
  routers aside; each of them wears `qmcp-anon`. A violation by the hub or a
  p00 qube stops the hub and p00; one by any other of them stops that qube
  alone.
- **Creates** take only names under a reserved prefix (default `ai-`): the
  hub's `ai-hub-`, a lead's `ai-<label>-`, and for the hub's clone of a
  project's member, that project's names; Qubes names disposables itself. They
  strip the qmcp badges a new
  qube must not carry, stamp it, and prove its network before handing it back.
- **AI space cannot call dom0** beyond the services a qube needs to boot and
  keep its clock (a lead also calls nine qmcp services), cannot reach the hub
  or a lead, cannot use Qubes' raw disposable shortcut, and cannot touch the
  Admin API, except a lead's firewall methods on its own workers. A copy needs
  the operator's dialog unless it goes between a slot's members, from a lead
  to its members, or from a member into its slot's dump sink; a copy into a
  guarded qube, the hub, a lead, a held or stopped qube, or a hidden project
  from outside it is refused, as is every other dialog into a hidden
  project.
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
| `qubes_spawn`, `qubes_clone`, `qubes_remove` | create (AppVM, standalone, disposable template, named disposable), and remove a qube qmcp created |
| `qubes_start`, `qubes_shutdown` | lifecycle |
| `qubes_props_set`, `qubes_feature_set` | label/memory/maxmem/vcpus, netvm only to none; features on an allowlist |
| `qubes_run`, `qubes_copy` | run a command as root in a managed qube; copy a file out of one (by your dialog, but inside a slot) |
| `qubes_spawn_disposable`, `qubes_run_disposable` | disposables, or one command in a fresh disposable |
| `qubes_firewall_get`, `qubes_firewall_set` | read an AI-space qube's firewall (the hub: any but a hidden project's, a stopped or a held one; a lead: its workers'); replace a managed one's (a lead's is the operator's: propose it) |
| `qubes_events` | a window of events for qubes in scope |
| `qubes_get_pool_stats` | the caller's disk budget: AI space, every project's record but a hidden one's, and the enrolled gateways for the hub, the project for a lead, with the names, templates and networks a lead may use and its model (an endpoint, or a model qube and its port) |
| `qubes_propose_project`, `qubes_propose_project_edit`, `qubes_propose_dump`, `qubes_propose_lead`, `qubes_propose_lead_firewall`, `qubes_propose_project_delete` | the hub asks the operator for a project, a change to one, a dump sink, a new lead or none, a lead's new firewall, a deletion |
| `qubes_propose_open`, `qubes_propose_manage`, `qubes_propose_revoke`, `qubes_propose_packages` | the hub asks for a window on a guarded qube, a qube brought into AI space or out of the guarded state, a qube taken out of AI space (and removed, with `remove`), or exact packages installed into a template in AI space |
| `qubes_proposals` | what became of the hub's proposals: pending, accepted, rejected, expired or failed |

The hub and a lead run the same server and see the same tools; dom0 scopes
each call to its caller. A lead has no event stream and cannot propose. A
client's `notifications/cancelled` drops a call that has not started yet; one
already running is not interrupted. `qubes_run` and `qubes_copy` take a
timeout of 1 to 86,400 s, which the in-qube service enforces by killing the
process group it started; a call that gets no answer by its timeout plus 30 s says so, since
the work may have run.

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

`git` is not in every template, and the hub's template is whatever
`qubes-prefs default_template` names — measured on Qubes 4.3.1: the Debian 13
xfce template ships git, the Fedora 43 xfce and Arch templates do not. Install
git in the hub's template, or skip the clone and copy the release in from dom0
the way step 5 does for a lead.

**2. dom0.** The installer runs as root, so fetch it somewhere AI cannot
write: a fresh disposable, not the hub. Any disposable template with curl and
network will do; Qubes' stock `default-dvm` does.

```sh
qvm-run --dispvm=default-dvm --pass-io \
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.37.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh
```

The installer runs every preflight check before it changes anything: its
options, the fleet's shape, and the policy, which it validates with qrexec's own
parser against your policy directory, including that no file sorting earlier
overrides its 54 checked claims. It installs the anonymity gate's timer as
your dom0 user, keeps it stopped while it changes things, installs the policy
after the code, starts the timer again and ends with `qmcp check`. Options: `--hub NAME`,
`--birth-egress QUBE`, `--pool-cap BYTES`, `--private-cap BYTES`, `--gate-user
NAME`, `--anonymous` (step 8), `--updates-via GATEWAY`, `--dry-run`. `deploy/uninstall.sh` removes the policy
first, then the rest, and ends with a clean-state check that names what it
keeps.

**The audit log.** One more installer option, `--audit-log disk|ram|none`,
says where qmcp's audit lines go for the whole install: `disk` (the default)
is `/var/log/qmcp-audit.log`; `ram` is a chain under `/run/qmcp/audit`, gone
at shutdown; `none` writes none. Each project can keep its own lines more
private still, while it runs: `sudo qmcp project audit LABEL ram` (or `off`,
or back to `disk`), or the project's Audit log... form in the window. A line
follows the most private mode of the install and of every project it is
about: the lead's calls, the hub's calls into the project's qubes and your
commands on it. Switching away from disk does not take back what is already
there: the old lines stay on dom0's disk, and deleting a file there is not
erasing it. dom0's journal keeps every qrexec call whatever the mode;
`qmcp check` warns while any mode is not disk and prints the command that
makes journald keep it in RAM only, which qmcp does not run itself. On disk,
root's `qmcp-audit.timer` rotates the log once a UTC day, or past 32 MiB, and
removes rotated logs once they are older than `sudo qmcp settings set
--audit-keep-days N` days (90 by default; `off` keeps them all), by their age,
never their size. The RAM chains are bounded by size instead, since they take
dom0's memory: the same hourly run removes the oldest rotated RAM files while
they all hold more than 64 MiB, so a flood can push earlier RAM lines off. A
line kept nowhere still counts against its caller's budget and hourly cap.
The window's Audit tab shows the log's size, the free space
against the 64 MiB floor and each principal's share of its daily budget.

It also installs **the operator's window**: *qubes-mcp* in the Qubes menu
under Settings > Qubes Tools, or `qmcp-gui` in a dom0 terminal, run as your own
user. It shows AI
space and the projects as a tree, the gateways AI space may use, each lead's
model endpoint and firewall, the `qmcp check` light, the audit log and the
settings, each anonymous project with what the anonymity gate found, and
offers every command that changes something as a form, but `migrate`,
`restored accept --all` (its Accept all names the qubes it shows) and what
the timers and the boot unit run. Each form shows the command it will run (`sudo -n qmcp ...`); the
window runs nothing but the `qmcp` command.
Text that AI chose, such as a name in the audit log, is shown escaped:
`\u202e`, never a reversed line.

Coming from 0.9.36? Install over it. **Breaking:** a hand copy of a qube qmcp
made (`qvm-clone`) carried its `qmcp-owner_*` badge, so the hub could remove
your copy. Now the hub cannot remove a qube waiting for review, and the gate
takes the owner badge off a copy right after it holds it; a qube restored from
a backup, with its label, whose original is gone keeps its badge, so the hub may
still remove what qmcp made. `restored accept` takes off any owner badge the
gate did not record as kept. A copy 0.9.36 held is decided on the first pass
after the install: if its source was removed while 0.9.36 ran, it reads as a
restore and keeps the badge, so check `qmcp restored list` for such a copy and
reject it, or take the badge off by hand (`qvm-tags QUBE del qmcp-owner_...`). A
copy you accepted before 0.9.37 is labelled as its own and is never looked at
again: it keeps its badge until you take it off the same way (the audit log's
`qmcp restored accept` lines name the qubes you accepted, except a `restored accept --all` run on 0.9.32 or earlier, whose one line names none).
To roll back to 0.9.36, run this release's `uninstall.sh` before 0.9.36's
installer (not drilled for this release; the uninstaller is unchanged since
0.9.33): a copy whose badge 0.9.37 took off stays without it, and a new copy carries its source's
badge again, as before.

Coming from 0.9.35? See the note above too. **Breaking:** the hub and a lead can no
longer remove a qube qmcp did not create, such as one you brought into AI
space with `qmcp manage`: `qubes_remove` refuses it ("removing a qube qmcp did
not create takes the operator's approval"). The hub asks with
`qubes_propose_revoke` and `remove` true, and accepting revokes, kills and
removes it; `sudo qmcp revoke QUBE --remove` does the same by hand. It refuses
a qube outside AI space, a guarded qube, a model qube, a qube a project lists
(its lead, dump sink, an approved template or a worker network), and a qube
other qubes or a global setting use,
before it changes anything (a qube Qubes refuses to remove for another reason
is revoked and killed, and the command says it was not removed). Qubes qmcp created
(the hub's `ai-hub-*`, a lead's workers, their clones and disposables) are
removed as before. Anything you bring into AI space should still have a
backup: root in a managed qube can destroy its data without removing it. To
roll back to 0.9.35, run this release's `uninstall.sh` before 0.9.35's
installer; a revoke proposal with `remove` that is not yet decided (pending or
expired) then reads as unreadable, and `qmcp proposal reject N` closes it.

Coming from 0.9.34? Install over it. `qmcp export` names every qube held for
review, or about to be, and says to accept or reject it before you back up: after
a restore every AI qube is held alike, and `restored accept --all` would take it
with the rest. The gate's timer now also removes the in-qube services' lock of a
qube removed by hand, and a removed lead's call locks under `/run/qmcp/calls`
(never its `.refused` counter). An in-qube lock 0.9.34 made is root's and
0600, so the gate's user cannot open it: it stays until the next boot. `qmcp
check` says "another version" of the in-qube services, not "an older version",
since after a rollback it is newer. To
roll back to 0.9.34, run this release's `uninstall.sh` before 0.9.34's installer
(not drilled for this release; the uninstaller is unchanged since 0.9.33).

Coming from 0.9.33? Install over it. If you created `/etc/qmcp/audit-keep-days`
with the `tee` line of the note for upgrading from 0.9.32, `qmcp check` as your
user failed on it (dom0's umask makes such a file 0600): the installer now sets
every operator file under `/etc/qmcp` that is a plain file to 0644, and `qmcp check` fails on one that not every user can
read, as root too. A refused call's audit line no longer names, or follows, a
qube out of the caller's reach: it records `<out-of-reach>` and goes where the
caller's own lines go (a qube refused as guarded, stopped or held that is in no
project is still named). A lifecycle call with an action that is not one (a
non-empty string) checks its qube first, so for a qube out of reach it answers `not found`. To roll
back to 0.9.33, run this release's `uninstall.sh` before 0.9.33's installer (not
drilled for this release; the uninstaller is unchanged since 0.9.33).

Coming from 0.9.32? Read the 0.9.33 note too. **Breaking:** within the hour after the install, the new
`qmcp-audit.timer` removes rotated audit logs (`qmcp-audit.log.<UTC time>`)
older than 90 days, the new default. 0.9.32's `qmcp settings set` has no option
for it, and the installer leaves the setting's value alone, so to keep them, write
the file before installing: `echo off | sudo tee /etc/qmcp/audit-keep-days` (or a
number of days instead of `off`). Then install over it. The two in-qube services change (a
timeout of at most a day that kills the command's whole process group, and a
copy that takes its timeout from `qubes_copy`), so `qmcp check` warns on every
template and standalone qmcp runs commands in until it is brought up to date (see
"Updating"); `qmcp check` fails in every mode while `qmcp-gate.timer` is not
running, since the timer also ends windows and holds restored qubes;
`qubes_firewall_set` answers ok, with `reloaded` false and a warning, when it
saved the rules but the reload failed; the rulebook refuses AI space starting
an app in another qube or reading an image from one, which Qubes' own policy
put to your dialog. The CHANGELOG's 0.9.33 entry has the
whole list. To roll back, set every project back to disk (`sudo qmcp project
audit LABEL disk`) and copy out the RAM chains under `/run/qmcp/audit` you
want to keep, since `uninstall.sh` removes `/run/qmcp` and them with it; run
this release's `uninstall.sh`, then 0.9.32's installer. 0.9.32 ignores `/etc/qmcp/audit-mode` and
`/etc/qmcp/audit-keep-days`: it writes every line to disk and removes no
rotated log.
Coming from 0.9.31? Install over it, then read the 0.9.32 note. A principal's calls that changed nothing,
past 60 in a clock hour, are counted rather than logged, and its changes past
20,000 lines a day are refused; `qmcp check` warns on both; deleting a project keeps a qube that is also another project's member,
or is a template, a disposable template, a gateway, a model qube, a guarded
qube, a dump sink or the hub, and its plan names every
qube it removes, keeps or strips; the window keeps Seal, Revoke and Reject
restored on when a read fails, and turns the rest off from the moment a
refresh starts. The CHANGELOG's 0.9.32 entry has the
whole list. To roll back, run this release's `uninstall.sh` before 0.9.31's
installer.
Coming from 0.9.30? Install over it, then read the 0.9.31 note. A qube that changes slot (but between
p00 and no slot), or becomes a lead, does so only once it is shut down (nothing
is killed), and such a move waits 10 s under `qmcp-blocked` to be sure it
stays so; a hub proposal
cannot manage a template your own qubes, or guarded ones, run on; dom0's
services refuse every change but a kill while less than 64 MiB is free
under `/var/log`, and `qmcp check` fails
on audit lines that could not be written; `qmcp restored reject` refuses the
hub; `qubes_run_disposable` says ok only once its disposable reads back
halted or gone. The CHANGELOG's 0.9.31 entry has the whole list. To roll back, run this
release's `uninstall.sh` before 0.9.30's installer.
Coming from 0.9.29? Install over it, then read the 0.9.30 note. Nothing in AI space reaches a hidden
project's qubes from outside it any more, not even through a dialog (a hidden
lead's dialog copy into its own sink goes with it); `qmcp seal` takes an open
badge off a drop box or the hub, and a seal whose kill fails is tried again
and fails `qmcp check` until it is made or no longer needed. The CHANGELOG's 0.9.30 entry has the
whole list. To roll back, run this release's `uninstall.sh` before 0.9.29's
installer.
Coming from 0.9.28? Install over it, then read the 0.9.29 note. `qmcp revoke`, an accepted revoke
proposal and `qubes_run_disposable` kill the qube instead of asking it to shut
down, and a revoke whose qube still runs exits 1; the anonymity gate kills a
stopped project's qube it finds running, on every run, so you can no longer
start one by hand while its project is unsound; approving a disposable
template for a hidden project is refused while the hub can reach a qube made
from it. The CHANGELOG's 0.9.29 entry has the whole list. To roll back, run
this release's `uninstall.sh` before 0.9.28's installer.
Coming from 0.9.27? Install over it, then read the 0.9.28 note. Besides the new proposal types and
`sudo qmcp template install`: `qmcp manage`, `guard`, `revoke` and `open`
refuse dom0, and every name while `/etc/qmcp/hub` cannot be read (a seal still
takes a window off then, and only skips the kill); `template prepare` refuses
while an install or another prepare runs in the same qube; managing an open
qube ends its window with no kill; the window's proposal list heads its subject
column "Subject". The CHANGELOG's 0.9.28 entry has the whole list. To roll back,
run this release's `uninstall.sh` before 0.9.27's installer; a pending
proposal of a new type then reads as unreadable, and `qmcp proposal reject N`
closes it.
Coming from 0.9.26? Install over it, then read the 0.9.27 note. Clones, the hub's and a lead's, change:
a clone lands where its source is, so the hub's clone of a project's member
joins that project (named inside its names, counted against its quota, on its
worker networks) and its clone of an AppVM in no slot joins none (0.9.26 put
it in p00); a clone, a lead cloned from one of the hub's qubes included, no
longer copies its source's device assignments, menu entries or a disposable
template's `preload-dispvm-max`; and a clone is refused when its template is
stopped by the gate, waits for review, or, for a lead, is off its approved
list. Every create also refuses to copy or build on a qube in AI space whose
`qmcp-id` label is not its own. The CHANGELOG's 0.9.27 entry has the whole list.
Coming from any release before 0.9.26? Besides that release's own note below,
the installer labels every qube that wears a qmcp badge and has no label, for
the restore check (see
"Backing up and restoring"). Then prepare,
once, each template `qmcp check` names under "in-qube services"
(`sudo qmcp template prepare QUBE`): dom0 keeps no record of what an earlier
copy loop wrote into it. Rolling back to 0.9.25 needs every held qube accepted
or rejected first (`qmcp restored list`), then this release's `uninstall.sh`
before 0.9.25's installer.
Coming from 0.9.23? Install over it, then read the note for any release
before 0.9.26. If you have anonymous projects, the
installer first checks them against this release's rule for template updates
(step 7): a template's updates count only through a gateway you ticked. It
names each project that would be stopped and changes nothing; run it again
with `--updates-via GATEWAY` for each gateway whose upstream is the anonymiser
itself (`sys-whonix`, a VPN qube), never `sys-firewall`. Rolling back to 0.9.23
needs the tick off every gateway first (0.9.23 refuses a registry that carries
it), then this release's `uninstall.sh` (it keeps `/etc/qmcp`) before 0.9.23's
installer.
Coming from 0.9.22? Install over it, then read the 0.9.23 note. Nothing of
0.9.23's own changes until you create an anonymous project (step 7). Rolling back to 0.9.22 needs every anonymous
project deleted first, then the `upstream` keys removed from
`/etc/qmcp/gateways.json`: 0.9.22 refuses both, and has nothing that keeps the
hub out of a hidden project. Then run this release's `uninstall.sh` (it keeps
`/etc/qmcp`) before installing 0.9.22, or 0.9.22 leaves `qmcp-gate.timer`
running a command it does not have.
Coming from 0.9.21? Install over it, then read the 0.9.22 note. A lead whose model endpoint is an address
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
and clones must be named `ai-hub-…` (from 0.9.27, a clone of a project's member
is named inside that project's names instead).
Coming from 0.9.16?
Run the staged migration first; see "Install, migrate, uninstall" in
[CLAUDE.md](CLAUDE.md).

**3. AI space.** Agents run commands only in qubes whose root carries the
two in-qube services: a template's, or a standalone's own. Install them into a template and put it in AI space;
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
sudo qmcp template prepare ai-debian-13       # writes the in-qube services in, from dom0's copy
sudo qmcp manage ai-debian-13       # the hub may build on it; `guard` keeps it a reference only
qvm-create --class AppVM --template "$(qubes-prefs default_template)" --label red sys-ai-net
qvm-prefs sys-ai-net provides_network True
qvm-prefs sys-ai-net netvm sys-firewall
sudo qmcp gateway enroll sys-ai-net --label clearnet   # AI qubes may sit on it
sudo qmcp settings set --birth-egress sys-ai-net     # where the hub's template-based qubes go online
```

`qmcp template prepare` takes a TemplateVM or a StandaloneVM: it starts a
halted one, writes the two services in as root, labels it with their version,
and shuts it down again. dom0 keeps its own copy of the services, so this works
at any time, not only while a fetched release is unpacked; `qmcp check` warns
on a template it runs commands in that was never prepared, or carries another
version than the installed one (an older one after an update, a newer one after
a rollback). After an update, a running prepared qube's own disk is brought up to
date within a minute, and a halted one's the next time it runs (none is started
for it); the qubes built on a template get the new services once it has shut
down and they restart.

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
and `--lead-promote QUBE` makes one of the hub's qubes the lead in place;
either may be a standalone, and the lead keeps its class.
`--lead-template T --lead-class standalone` makes the lead a standalone: its
own copy of T's root, so an agent you install in it stays after a restart, and
so does anything a compromised agent leaves there. A lead may spawn standalone
workers from its approved templates too (`qubes_spawn` with `klass`
`StandaloneVM`). A standalone's root counts at the template root's full size,
often 20 GiB, against the pool cap and, for a worker, the project's quota: a
40 GiB quota holds one standalone and a few AppVMs. Sizes count as
provisioned, not as used, so what AI space keeps (private volumes, and the
roots of templates and standalones) cannot outgrow the cap through its own
creates even on a thin pool; volatile volumes and an AppVM's changes to its
template's root are not counted, and a lead you make with `qmcp project` is not
checked against the cap. A Linux standalone you built yourself joins a project
once it is in AI space: `sudo qmcp manage QUBE`, `sudo qmcp template prepare
QUBE` (so the lead can run commands in it), then `sudo qmcp project move QUBE
LABEL`. Moving it in is your approval of what it runs, as approving a template
is. Build it from a template outside AI space: `qvm-create --standalone -t T`
copies T's tags and features, so a copy of a template in AI space comes up
wearing `ai-managed` and another qube's label, and the restore check holds it
as a hand copy (`sudo qmcp restored reject QUBE` takes it out again). Windows
qubes are not supported.
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
qmcp guard ai-hub-model` kills it if it runs, so what the hub had running in
it is stopped; what it left in `/home`, `/usr/local` or `/rw` stays, and whatever
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
through `sys-whonix`, the qube directly above the router, and tick the router
for updates (`--updates`): your word that this upstream is the anonymiser
itself. Never tick a router whose upstream is `sys-firewall`. Give the project a
template the hub never touched, guarded so it never can:

```sh
# in dom0
qvm-create --class AppVM --template "$(qubes-prefs default_template)" --label red sys-ai-tor
qvm-prefs sys-ai-tor provides_network True
qvm-prefs sys-ai-tor netvm sys-whonix
sudo qmcp gateway enroll sys-ai-tor --anonymising --updates --label tor
qvm-clone <a Debian template of yours> anon-debian-13   # one the hub never touched
sudo qmcp template prepare anon-debian-13
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
first run after boot is not ordered before Qubes' autostart. A qube may move
into or out of an anonymous project (`qmcp project move QUBE NAME --yes`): the
command says first that it has a past, and refuses a move the gate would stop.

**8. Anonymous mode (optional).** Every project is anonymous and the gate
judges the hub as well. Turn it on with no ordinary project and no clearnet
gateway enrolled, with the hub on an anonymising router (or on none) and its
template's updates going through the anonymiser, as in step 7:

```sh
# in dom0, after step 7's router is enrolled and ticked
qvm-prefs mcp-control netvm sys-ai-tor
sudo bash /tmp/qubes-mcp/deploy/install.sh --anonymous
```

The installer refuses, and names why, while any of that is not so. It lists
every qube already in AI space that the hub's check will cover (guarded routers
and anonymous projects' qubes aside): each has a past, and all of them, with
the hub, get `qmcp-anon`, which keeps them from opening a URL or a file in another qube.
qmcp cannot check whose account the hub's model uses, nor what the hub qube
did before: use a hub qube and a model account that never ran on clearnet.
From then on `qmcp project create` makes anonymous projects (hidden unless
`--hub-sees`), the hub's own qubes and templates are judged every 15 seconds,
and a stopped hub is cleared with `sudo qmcp project unblock p00`. No qmcp
command turns the mode off; `uninstall.sh --purge` does. Then remove `qmcp-anon` from the
hub (`qvm-tags mcp-control del qmcp-anon`), or `qmcp check` fails on it.

### Updating

Fetch the new release exactly as in step 2, into a fresh
`/tmp/qubes-mcp`, and run the installer again: it is idempotent, backs up what
it replaces and ends with `qmcp check`. Before it installs the new policy it
seals every open window (`qmcp seal --all`, which kills an open qube that runs),
so an install never leaves one open: if you still want one, open it again
afterwards (`sudo qmcp open QUBE --for 2h`). Then:

- **Prepare what the check names.** A release that changes the in-qube services
  marks every prepared template and standalone as behind. A running one's own
  disk is brought up to date within a minute, a halted one's the next time it
  runs, and the qubes built on a template get it once it has shut down and they
  restart. To do one now, `sudo qmcp template prepare QUBE`, which starts it if
  it is halted.
- **Restart the window** if it is open: one opened before the install runs the
  old code.
- **Update the hub's copy** of `qubes_mcp/` (step 1) and each lead's. A hub
  cloned with git: `git -C ~/qubes-mcp pull` in the hub (the head of
  `main` is always the newest release). One without git, and
  each lead, from step 2's tarball in dom0 (name the lead in place of
  `mcp-control`; nothing in `~/qubes-mcp` is kept):

  ```sh
  qvm-run --pass-io mcp-control \
    'rm -rf ~/qubes-mcp && mkdir ~/qubes-mcp && tar -xzf - -C ~/qubes-mcp --strip-components=1' \
    < /tmp/qmcp.tgz
  ```

  Then restart its agent's MCP client, which starts the server afresh.

The CHANGELOG's entry for each version says what else an update from the one
before it needs.

### Backing up and restoring

A Qubes backup takes dom0 in as your home directory and nothing else, so it
never holds qmcp's own settings. Export them into your home first, then back up
with dom0 ticked. Accept or reject every qube held for review before you export
(`qmcp restored list`): after a restore every AI qube is held alike, and
`restored accept --all` takes one held before the backup with the rest. The
export names any it finds, and is written all the same:

```sh
# in dom0
sudo qmcp export                  # writes ~/qmcp-export-<time>.json, mode 0600
```

To restore onto a reinstalled Qubes:

```sh
# in dom0
qvm-backup-restore --skip-conflicting ...   # everything, dom0 ticked; nothing operates the AI qubes yet
# fetch and unpack the release into /tmp/qubes-mcp as in step 2, then:
sudo bash /tmp/qubes-mcp/deploy/install.sh --hub mcp-control   # the same hub
sudo qmcp import ~/home-restore-<time>/dom0-home/<you>/qmcp-export-<time>.json
sudo qmcp restored accept --all   # the restored AI qubes, back into their projects
```

Pending proposals are not in the export: they expire in 7 days, and would ask
for changes to a fleet that has moved on. The hub may submit again what it
still needs.

The installer's closing check is FAILED until the import and the accept: no
gateway is enrolled yet, and the restored AI qubes are held. That is expected
here; for an export of an install in anonymous mode, until the mode is on
again (step 8).

A restore gives every qube a new identity and keeps its tags, so the installed
qubes-mcp holds each restored AI qube for your review: no call from another
qube reaches it, and it reaches nothing, until you accept it (its network is
unchanged). `qmcp restored
list` shows what each came back as and whether that agrees with the projects.
With anonymous projects, send your templates' updates through the anonymiser
again (step 7) before the import: a Qubes backup does not carry dom0's update
routing, and the gate, which runs right after the import, would stop each
anonymous project (clear one with `sudo qmcp project unblock NAME` once it is
sound). An export of an install in anonymous mode is imported onto a normal
install the same way; once the qubes are accepted, turn the mode on (step 8),
and start neither the hub nor any AI qube, nor mark one to start at boot,
before then.

**Do not restore AI qubes into a running install whose projects have changed.**
Until the gate's next pass holds it, normally within about 15 seconds, a worker
restored months later is routed by its old badges into whatever project holds
its slot now. If you must, shut the hub and the leads down first, then review
each one (`sudo qmcp restored accept QUBE` or `sudo qmcp restored reject QUBE`). The same hold catches
an AI qube you copy by hand with `qvm-clone`.

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
`tests/test_inqube_services.py` runs the two in-qube services as a qube
runs them: the timeout and the process group it kills, and the copy's target
and path. `tests/test_audit_modes.py` covers where audit lines go (the
install's and each project's mode), what a line kept in RAM or nowhere costs,
the hourly rotation, removal by age and the RAM chains' bound by size, and
the timer, installer and check wired to them.
`tests/test_proposals.py` covers proposals: who may submit, the store, the
second tick, accepting and rejecting through the real commands.
`tests/test_gateways.py` covers the gateway registry, the networks AI qubes may
be given and leads' firewalls. `tests/test_anon.py` covers anonymous projects:
each gate condition broken on its own, with dom0's update question asked of
qrexec's real parser, the block and its order, a read that fails once and
twice, unblock, and what the hub can no longer see. `tests/test_mode.py` covers
anonymous mode: the hub's check and what each violation stops, the updates
tick, creates and proposals in the mode, and moves into and out of anonymous
projects.
`tests/test_operator_tools.py` covers 0.9.26's tools: preparing templates and
standalones and keeping them up to date, the restore check that holds a qube
back from a backup or a copy, the settings, and export and import.
`tests/test_gui.py` drives the window's forms through the real `qmcp` command
and fails if the command has a command, option or field the window neither
offers nor exempts; `tests/GUI-CHECKLIST.md` is the click-through for a
person.

## Reviewer asks

Review from people who know qrexec policy and the Admin API is genuinely
wanted. The specific questions are in
**[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md)**.

Where this has been discussed:

- **qubes-devel design review** of the May 2026 design, answered by the Qubes
  project lead (the design has changed since):
  <https://groups.google.com/g/qubes-devel/c/4NuSqL64DVE>
- **Qubes forum thread**: <https://forum.qubes-os.org/t/41387>
- **Background**, the case for putting MCP trust boundaries below the protocol:
  <https://alexschose.com/writing/mcp-trust-boundaries-belong-below-the-protocol.html>

## Caveat

This is operator-grade infrastructure for one use case: AI agents working in
Qubes-isolated qubes. It is not a hardened product. The hub is itself part of
the trust boundary: a compromised hub controls every managed qube but a
hidden anonymous project's (a guarded one only through a window you open), and the audit log records what it does through the dom0
services (past 60 calls that changed nothing in a clock hour, those are only
counted).

## License

MIT — see `LICENSE`.
