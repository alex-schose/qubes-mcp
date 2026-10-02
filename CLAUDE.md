# qubes-mcp — design document

An MCP server that lets AI agents operate a scoped part of a Qubes OS machine.
It runs in one qube, the **hub** (`mcp-control`), and in each project's
**lead**. Agents reach it over stdio (usually through SSH) and call its tools.
Most tools call `qmcp.*` services in dom0, which decide everything about the
qubes they touch; running a command, copying a file out and reading or writing
a firewall go straight to the qube or the Admin API, decided by the qrexec
policy in dom0.

**This file describes the code at this version (0.9.19). Read it first in any
session opened in this directory.** The release history is in `CHANGELOG.md`.

## Trust model

These are load-bearing. Do not change them without the operator's sign-off.

- **dom0 is the only enforcement point, and qrexec's caller is the only
  identity.** Every dom0 `qmcp.*` service reads `QREXEC_REMOTE_DOMAIN`, which
  dom0's qrexec daemon sets, and the policy matches on the same identity.
  Nothing sits between a principal and dom0: a relay would make every call come
  from the relay, and ownership, network choice and audit would all collapse
  onto it.
- **Two kinds of principal.** The **hub** is named in `/etc/qmcp/hub`
  (written once, at install) and in the policy. A project's **lead** is named
  in its project's record and wears that slot's lead badges; a lead whose
  record and badges disagree is no principal at all. Nothing else calls a
  dom0 service: a project's workers, the hub's own qubes and every other qube
  in AI space are refused by the policy and again by the services.
- **The hub is not in AI space.** It never carries `ai-managed`, so it is
  never the object of its own calls; `qmcp check` fails if it does, or if the
  policy names a different hub than the file. A lead is in AI space: the hub
  operates it, and every AI-space rule applies to it unless a line for leads
  deliberately sorts above that rule.
- **AI space is the tag `ai-managed`.** A qube outside it is invisible: every
  dom0 service answers a qube outside AI space exactly as it answers a qube that
  does not exist — the same reply, after the same single qubesd call — and
  reads redact any reference to one as `<out-of-scope>`. The one exception is a
  create colliding with a name inside the reserved prefix (see the residual
  risks).
- **Two states.** A qube in AI space is **managed** (the hub may operate it) or
  **guarded** (listed, read and used as a reference — spawned from — but never
  operated). Guarded means the tag `qmcp-guarded`, or providing network: a
  gateway is guarded whatever it carries, and nothing is spawned from one.
- **Templates.** A TemplateVM or disposable template in AI space is the hub's
  to build and edit when it is managed. The operator guards any template that
  must stay a clean root: a template the hub edited is only as clean as the
  hub.
- **Badges and project records change only through the operator.** Neither
  the hub nor AI space can call the Admin API's tag methods. The `qmcp`
  command in dom0 is the operator's tool for changing badges and projects; the
  only tags qmcp writes on its own are the stamp a create puts on the qube it
  just made.
- **Strip on create.** `clone_vm` copies the source's tags and a disposable
  copies its template's, so every create path removes every tag in qmcp's
  vocabulary the platform copied (`qmcp-guarded`, every role and slot badge,
  the v0.9.16 tier tags, other principals' provenance), stamps `ai-managed`,
  `qmcp-owner_<caller>` (provenance only, never a gate) and the caller's slot
  badge (below), carries restrictions forward (`qmcp-egress-locked_*`, the
  platform's `anon-vm`), reads the result back, and rolls the qube back if it
  is not exact. Tags outside qmcp's vocabulary (the operator's own) are left as
  Qubes copied them.
- **The rulebook is static.** `/etc/qubes/policy.d/30-mcp-control.policy` is
  installed once and never written at runtime. Before it is installed it is
  parsed by qrexec's own parser against the box's real policy directory, and
  24 of its claims are checked to be decided by it, not by a file that sorts
  earlier.
- **No dom0 exception text reaches a caller.** Every dom0 service failure
  answers with a fixed phrase, which may name the caller's own input, the
  reserved name prefix or a qube in AI space; for a state-changing service, the
  class of the exception behind a failed change goes to the audit log, which
  the operator can read and AI cannot. (The in-qube services return a
  command's own output and errors, from inside the qube the hub is operating.)
- **Audit.** Every call to a state-changing dom0 service — spawn, clone,
  disposable, property, feature, lifecycle — leaves one line on a hash-chained
  log in dom0 (`/var/log/qmcp-audit.log`, `root:qubes 0660`), with the caller,
  the service and a summary of the names, keys and options in the request.
  The value of a property or feature being set is never logged. No service and
  no policy line exposes the log. Logging is best-effort: it never changes what
  the caller sees. Running a command, copying out and firewall writes are
  decided by the policy, not by a dom0 service, and are not on this log.

## Projects

Sixteen slots. **p00** holds the hub's own working qubes; **p01–p15** are
projects. A project is one **lead**, the qubes it creates (its **workers**),
and optionally a **dump sink**. Its record, in `/etc/qmcp/projects.json`
(root-owned, written by `qmcp project`; the installer writes it empty), holds
what a tag cannot:

| Field | |
|---|---|
| label | 1–8 lowercase letters or digits, and not one a command could read as a slot (`p03`) or keyword (`none`, `hub`). The project's names are `<prefix><label>-…` (`ai-osint-scraper`); the hub may not create names inside any project's space, so a lead collides only with its own workers, or with a qube the operator named inside its space or moved out of it (`qmcp check` lists those). |
| lead | the qube that leads it, or none (a project without a lead keeps its workers; only the hub reaches them). |
| templates | the TemplateVMs and disposable templates the lead may spawn from, managed or guarded. A template on one project's list only is that project's alone. |
| networks | where the lead's workers may be born: guarded gateways, or none. The first is the default. A worker's network is never moved to another one after birth; it can only be cleared. |
| quota | the workers' disk, counted like the pool cap. The pool cap still applies. |
| dump | the dump sink's name, or none. |

The badges the rulebook routes on: `qmcp-proj-pNN` on a member, `qmcp-lead` and
`qmcp-lead-pNN` on a lead (which wears no member badge), and `qmcp-dump-pNN`
with `ai-dump` on a sink, which is never in AI space.

**A lead** calls nine of the ten dom0 services (not the event stream; it
polls instead). It operates only its project's members, references only its
approved templates and worker networks, creates AppVMs and disposables (never a
disposable template) inside its name space and quota, and its workers are
born on its project's networks; the lead's own network is never inherited.
Through the rulebook
it runs commands, copies files and reads or writes the firewall in its
members, and copies files into them. Everything else answers like a name
that does not exist, at the same cost.

**Workers** call no qmcp service. They cannot reach their lead, the hub or
another lead; they copy among themselves and into their sink without a dialog,
reach another project only by a copy through the operator's dialog, and
nothing else.

**The hub** operates every project: its leads (it may clone one, but only the
operator removes one) and its workers. Its own AppVMs join p00 when it creates
them; its disposables join no slot, because a disposable often opens hostile
content and in p00 it could drop files into the hub's other qubes without a
dialog, and nor does its clone of a project's qube or of a lead, for the same
reason. Templates and disposable templates join no slot.

**The operator** creates a project with `qmcp project create`, which makes
the lead in one of three ways: fresh from a template, as a clone of one of
the hub's own AppVMs that the operator prepared as an agent, or by promoting
one of the hub's own AppVMs in place. Every project
command checks everything it can before it changes anything, and holds the
create lock as well as the record file's, so it waits for any create in
flight. The record is written last, so a lead is no principal until it is
complete. Removing a lead takes its badges first, then its record, then the
qube, and touches the recorded lead only while it wears the slot's lead badge;
the project keeps its workers. The rulebook routes on the slot's lead badge
(`qmcp-lead-pNN` alone gives exec into the members), so every command adds it
last and removes it first: a failure part-way never leaves it without
`qmcp-lead`. Deleting a project removes the lead and every
member, keeps the dump sink (minus its badge), and strips every badge of the
slot from every qube before the slot can be reused; `qmcp project delete pNN
--yes` finishes a delete that stopped half-way. Moving a qube into a project
needs its network on the project's list, and moving one out of a slot into
another needs `--yes`.

**Firewalls do not inherit.** A Qubes firewall rule filters only the qube it
is set on, enforced in that qube's netvm. The ceiling is the egress: a worker's
traffic leaves through its gateway, so what that gateway lets through bounds
every qube behind it, and nothing in AI space can change a guarded gateway's
rules (`qmcp check` fails on a gateway that is not guarded). Inside that
ceiling the hub and a lead both write a worker's own rules, and the last writer
wins; the hub also writes a lead's rules, which the lead cannot change. A
lead's rules do not limit its workers, which do not route through it. A project
that needs a ceiling of its own gets an egress of its own: a gateway with its
rules, listed as that project's network.

**Authority is checked when the work is done.** A service reads its request
before it checks the caller, so a lead removed while its request is still
arriving is refused; a create checks its caller again once it holds the create
lock, which every project command holds too. A call already past its check
finishes (see the residual risks).

## What lives where

| Where | What |
|---|---|
| hub (`mcp-control`) | `qubes_mcp/`: the MCP server and the `qubes-mcp` CLI. Standard library only. It reaches AI space through the policy's hub section; beyond that, only its own boot services and the operator's dialogs. |
| each lead | the same `qubes_mcp/`, which reaches its project through the policy's slot lines and the leads' section. |
| dom0 | `/usr/local/lib/qmcp/qmcp/` (the library), `/etc/qubes-rpc/qmcp.*` (one shim under each service name), `/usr/local/bin/qmcp` (the operator's command), `/usr/local/bin/qmcp-gui` and its menu entry (the operator's window), the policy, `/etc/qmcp/` (operator files, `projects.json` among them), `/run/qmcp/` (lock files). |
| AI templates | `template-rpc/`: `qmcp.RunInAIManaged` and `qmcp.CopyToAIManaged`, installed in the templates AI qubes are built on. A qube on a template without them cannot be exec'd into. |

## The services

### In dom0

Each is the same shim (`dom0/rpc/qmcp-service`), installed under its name and
dispatching to `dom0/qmcp/services.py`. Every call runs one funnel
(`dom0/qmcp/core.py`): the caller holds one of its concurrency slots (the hub
8; a lead 4, and all leads together 16, from a pool separate from the hub's,
so no lead can lock the hub out), sends at most 64 KiB (refused before it is
parsed), must then be a principal, and gets exactly one JSON reply. Measured on
Qubes 4.3.1, a call costs dom0 about 14 MiB, so the worst case of 24 calls
stays near 330 MiB.

The table says what each service does for the hub. For a lead, "AI space"
means its project: its members, plus its approved templates and worker
networks where they are read or referenced.

| Service | What it does |
|---|---|
| `qmcp.ListAIManagedQubes` | AI space: name, class, label, template (redacted if out of scope), power state, `guarded`, `slot` and `lead`. |
| `qmcp.GetPropertyAIManaged` | One property of a managed or guarded qube. Only properties qubesd lists; references out of scope redacted, and so are the netvm's addresses (`visible_gateway`, `dns`, …) when the netvm is out of scope; `tags` filtered to `ai-managed` and `qmcp-guarded`. |
| `qmcp.SetPropertyAIManaged` | `label`, `memory`, `maxmem`, `vcpus`, and `netvm` only to null. Everything else (`template`, `name`, `default_dispvm`, `provides_network`, …) is operator-only. |
| `qmcp.SetFeatureAIManaged` | Allowlist: `service.*`, `vm-config.*`, `menu-items`, `default-menu-items`. Every other key, including any a future Qubes adds, is operator-only. |
| `qmcp.LifecycleAIManaged` | start, shutdown, kill, pause, unpause, remove. Remove is a real remove; removing a lead is the operator's. |
| `qmcp.SpawnAIManagedQube` | AppVM or DispVMTemplate from a TemplateVM, or a named DispVM from a disposable template. The template may be managed or guarded, but not one that provides network. A lead spawns AppVMs and DispVMs from its approved templates only. |
| `qmcp.CloneAIManagedQube` | Clone a managed qube, templates included. A guarded source is refused: a clone is a managed, editable copy of everything in it. |
| `qmcp.SpawnDisposableAIManaged` | A disposable from a managed or guarded disposable template, born managed. Uses Qubes 4.3's preloaded disposables when the template has `preload-dispvm-max` (measured: a `qubes_run_disposable` cycle took 1.5 s with `preload-dispvm-max=1`, about 8 s without). |
| `qmcp.AIManagedEvents` | The hub only. A window of admin events (1–120 s) whose subject is in AI space; at most 16 filters of at most 64 characters. Tag events surface only for the two visible badges. |
| `qmcp.GetPoolStats` | `ai_managed_bytes_used`, `_cap` and `_headroom`, and `name_prefix`: for the hub, AI space against the operator's cap; for a lead, its workers against its quota, with its project's label, approved templates, worker networks and dump sink. A lead never sees the fleet's figures. |

**Creates.** A name the hub chooses must carry the reserved prefix
(`/etc/qmcp/name-prefix`, default `ai-`) and lie outside every project's name
space; a lead's must lie inside its own (`ai-<label>-`). Either way it is
judged on its shape and the project records alone, before anything is looked
up, so a create is no oracle over names outside the caller's space. (Qubes
names disposables itself.) Creates are serialised by a lock held
from the disk-budget check through the create, with a 120 s wait, and the name
is checked again under the lock. A create call that fails is never cleaned up
by name: qubesd and `clone_vm` clean up their own failures, and a qube someone
else made under that name meanwhile is left alone. A create that succeeds but
cannot be finished is rolled back; the one exception is a failed `private`
resize, which keeps the qube and says so (`warning: private_resize_failed`).
Spawn and clone set the new qube's network
and `default_dispvm` explicitly, so neither follows a global default; a
disposable gets `default_dispvm` set to none and keeps its template's network.

**Network at birth.** For a lead, the project's worker networks decide: a
spawn from a TemplateVM is born on the list's first entry or on another listed
one the request names, a clone source or a disposable template must already
be on a listed network (or none), and the lead's own network is never used.
For the hub, a clone source or a disposable template decides: the
child gets its netvm (none, if it has none), and the create is refused if that
netvm is outside AI space. A TemplateVM used as a base never decides, because
its netvm is an update path; the child then gets the hub's netvm if that is in
AI space, else `/etc/qmcp/birth-egress` if that is in AI space, else the
create is refused. A spawn may ask for `netvm: null`, which is always allowed,
or name the netvm it would get anyway; any other name is refused. A qube whose
network cannot be proven is rolled back before the call returns: a fresh qube
before its first boot; a preloaded disposable, already running on its
template's network, is killed.

**Disk budget.** The sum of every AI-space qube's `private` volume, plus `root`
for TemplateVMs and StandaloneVMs, is capped by `/etc/qmcp/pool-cap`; one
qube's requested `private` by `/etc/qmcp/private-cap`; a project's workers by
its quota, on top. All are re-read on every call. A volume that cannot be read refuses the create rather than being
counted as empty. Without a pool cap every create is refused; without a
private cap, any create that asks for a `private` size.

### In AI qubes

| Service | What it does |
|---|---|
| `qmcp.RunInAIManaged` | Runs a command as root and returns rc/stdout/stderr. The hub drives it in any managed qube; a lead in its own members. |
| `qmcp.CopyToAIManaged` | Runs `qvm-copy-to-vm` from this qube. The copy itself is `qubes.Filecopy`: no dialog inside one slot or into its sink, refused into a guarded qube, the hub or a lead, the operator's dialog anywhere else. |

## The rulebook

`policy/30-mcp-control.policy`, first match wins. Three kinds of source
appear in it: the hub by name, the leads (`@tag:qmcp-lead`, and
`@tag:qmcp-lead-pNN` in their slot's lines), and AI space (`@tag:ai-managed`). A few denies also name
any source (`@anyvm`) or the drop boxes (`@tag:ai-dump`). A lead is in AI
space, so the order matters: the hard denies come first, then the lines that
let leads and members do what AI space otherwise may not, then the rest of AI
space's denies.

- **A. Hard denies, first.**
  - A1: the hub cannot run, copy or write firewall rules in a guarded qube (it
    may read its firewall), and nothing from AI space reaches a guarded qube by
    any service.
  - A2: Qubes' raw disposable shortcut is closed for AI space. A `@dispvm` rule
    target matches only the bare keyword, so a second rule works from the
    template's side: `@dispvm:@tag:ai-managed`, any source, any form.
  - A3: no command execution from AI space into another qube, whatever form
    the target takes.
  - A4: AI space never reaches the hub, by any service.
  - A5: nothing in AI space reaches a lead, by any service: not its workers,
    not another project, not another lead.
  - A6: a drop box (`ai-dump`) never reaches back into AI space, by any
    service, even by dialog. It sits above the project lines so no slot line
    can let a sink in.
- **B. The project slots.** One block per slot. A lead runs commands, copies
  files out and reads or writes the firewall in its own project's members, and
  copies files into them; members copy among themselves and into their slot's
  dump sink. p00 has only its members' copies: the hub reaches its own qubes
  through E. No line crosses a slot.
- **C. Leads to dom0:** nine of the ten dom0 services, not the event stream.
- **D. The rest of AI space.**
  - D1: nobody else in AI space drives qmcp's in-qube services.
  - D2: AI space talks to dom0 only through the five services a qube needs to
    boot and report itself; every other service addressed to dom0 is refused.
    Qubes itself forwards two services to dom0 when a qube addresses them
    elsewhere (`qubes.GetDate` from any target, `qubes.Notifications` from
    `@default`). GetDate stays (Qubes' own rule refuses Whonix qubes);
    Notifications is denied, so no AI qube can put a desktop notification in
    front of the operator.
  - D3: the Admin API (the 122 methods qubesd 4.3 registers, the two volume
    Import services) and the policy API are denied to AI space for every target
    form other than dom0, which D2 covers.
- **E. The hub:** the ten dom0 services; exec, copy-out and firewall on AI
  space.
- **F. Copies from AI space:** the operator's dialog, unless A refused them
  (into a guarded qube, the hub or a lead) or B allowed them (inside one slot,
  or into its sink). Every copy across projects gets the dialog. qrexec turns
  a target that does not exist into `@default`, so the dialog reveals no
  names.
- **G. The hub's own operator UX:** its boot services, clock sync and dialogs.
- **H. The hub's catch-alls:** everything else is refused.

`tests/test_policy.py` checks every rule against a matrix of requests on
qrexec's real parser, next to upstream Qubes 4.3's default policy — and again
with a later file that allows everything, which our denies must survive. It
removes each rule in turn and fails if any of them decides nothing, and it
checks that every slot has exactly its own block and no line crosses a slot.

## The operator's command (dom0)

| Command | |
|---|---|
| `qmcp check [--json]` | Fails on: the hub missing, in AI space, or named differently in the policy; tier tags; a gateway without `qmcp-guarded`; a drop box in AI space; the policy modified, refused by qrexec's parser, or overridden by an earlier file for any of its 24 checked claims; services, runtime directory or caps missing, or a create lock the services cannot write; a broken audit chain; v0.9.16 leftovers; unreadable project records; a member or lead badge outside AI space, a sink inside it; a qube in two slots; a slot badge with no project; a template or gateway in a project; a lead whose badges and record disagree, or any qube wearing lead badges that is not its slot's recorded lead; a sink that is not its record's. Warns on stray badges, v0.9.16 tombstones, qubes outside AI space inside the name prefix or a project's names, managed qubes pointing at a disposable template outside it, a birth-egress qube outside AI space, an audit log due for rotation, a project without a lead, an approved template or worker network that is not one, a member on a network off its project's list, a sink with a network, managed AppVMs in no slot, and project quotas that add up to more than the pool cap. Exit 0 GREEN, 1 FAILED, 3 INCOMPLETE — INCOMPLETE is not green. |
| `qmcp list [--all] [--json]` | AI space with state, class, template, network, power, slot and provenance; with `--json`, each row adds whether the qube provides network, whether it is a disposable template, and its badges. `--all` adds every other qube but dom0, with no state. |
| `qmcp settings [--json]` | The operator files the services read (hub, name prefix, pool and private caps, birth egress), the disk AI space uses, and the version. |
| `qmcp manage QUBE` / `qmcp guard QUBE` | The role actions. Both refuse the hub and a drop box; `manage` also refuses a gateway; `guard` refuses a lead or a member. |
| `qmcp revoke QUBE` | Strips every qmcp badge, pins `default_dispvm` to none, shuts the qube down. Refuses a lead. |
| `qmcp project list` / `show NAME` | The slots in use; one project's record. |
| `qmcp project create LABEL ...` | A new project in the lowest free slot: `--lead-template T`, `--lead-clone QUBE` or `--lead-promote QUBE`; `--lead-netvm`; `--template` (more approved templates; the lead's own goes first when it is in AI space); `--network QUBE` or `none`, the first the default; `--quota`; `--dump`. |
| `qmcp project edit NAME ...` | Replace the approved templates or the worker networks, or change the quota. Workers keep their networks. |
| `qmcp project lead NAME --remove` / `--lead-…` | Remove the lead (the project keeps its workers), or give the project a new one; `--keep-old` keeps the old lead as a worker. |
| `qmcp project dump NAME` | Create a dump sink for a project, or for p00 (`hub-dump`). |
| `qmcp project move QUBE TARGET` | Move a managed AppVM into p00, a project, or no slot. Its network does not change, so a project takes it only on one of its worker networks; out of one slot into another needs `--yes`. |
| `qmcp project delete NAME --yes` | Remove the lead and every member, keep the dump sink without its badge, strip every badge of the slot, free it. Given a slot with no record, finish a delete that stopped half-way. Without `--yes` it prints what it would remove and changes nothing; that needs no root. |
| `qmcp migrate [--apply]` | v0.9.16 tiers to two states (below). Dry run by default. |
| `qmcp audit verify` / `tail` / `rotate` | The chain. `rotate` moves the log aside and starts a new one anchored on the old head; it needs root. |

Every `qmcp project` command that changes something needs root: it writes
`/etc/qmcp/projects.json` under a lock, by atomic rename, or (`move`) takes
that lock.

## The operator's window (dom0)

`qmcp-gui` is the `qmcp` command as a window: in the Qubes menu under
Settings > Qubes Tools, or in a dom0 terminal. Run it as your own dom0 user;
it refuses to run as root.

- **It runs the `qmcp` command and nothing else.** Every read is `qmcp ...`,
  run as you, in JSON wherever the command offers it, and stopped after 120 s;
  every change is `/usr/bin/sudo -n qmcp ...`, the command you would type, one
  at a time. Each form shows that command under its fields before OK runs it,
  and the report after it shows the command, its exit status and its output.
  The window never imports qubesadmin, so it can do nothing the command cannot.
- **What it shows.** The Qubes tab is a tree: the hub with p00 and the qubes in
  no slot, each project with its lead, workers and sink, then templates,
  gateways, other guarded qubes, and Needs attention. A qube's place comes from
  the badges the rulebook routes on, never its label colour, which the hub may
  set. Needs attention holds the qubes whose badges the rulebook acts on
  against the records: lead badges the records do not back, a gateway without
  `qmcp-guarded` (Guard is offered there), a drop box or the hub inside AI
  space, slot badges outside it, a qube in two slots, a template in a project.
  Every other failure of `qmcp check` is on the Check tab. Beside the tree, the
  selection's every field, and the actions that fit it. The light is
  `qmcp check`'s result with the time it ran; the Check tab lists its findings,
  failures first. The Audit tab shows the last 200 lines, newest first, the
  selected one in full, and verifies or rotates the chain. It holds the calls
  the hub and the leads make to state-changing services, and the line each
  rotation starts a log with, which names the file the earlier lines moved to;
  the operator's own commands are not on it. The Settings tab shows
  `qmcp settings`, read-only.
- **What it does.** Every command that changes something, but `migrate` (a
  one-time step from v0.9.16), is a form: create, edit and delete projects,
  change or remove a lead, add a dump sink, move a qube between slots, manage,
  guard, revoke, add a qube to AI space, and rotate the audit log. A delete
  first reads the command's plan, which changes nothing, and shows it; moving a
  qube from one slot into another needs a tick, and the move form shows whether
  the qube's network is one the project takes. A form refuses what the command
  would refuse for a reason it can see in its own fields (a kept lead's name,
  say), before anything runs. A lead's name is typed after the project's name
  space, which the form shows in front of the field, and is judged by the
  command's own rule. Replacing a lead asks what happens to the old one (kept
  as a worker, or removed) with nothing chosen in advance, and every form whose
  OK removes a qube says so in red first.
- **A failed read is never shown as the fleet.** Once a refresh has read
  everything, a later one with a failed read keeps the qubes, records, audit
  lines and settings of the last complete one, says which read failed and when
  those were read, and turns every change off until a refresh reads
  everything. The light and the Check tab always show the latest check, which
  judges the fleet by itself, or UNKNOWN if it did not answer. Before the first
  complete refresh, nothing that needs the records (a lead's standing, a slot
  left without one) is judged until they are read.
- **Text from AI space is shown as text.** The audit log keeps the names, keys
  and options of every call the hub or a lead makes to a state-changing service
  (never a value being set), refused calls included, up to 128 characters each
  and before they are checked. The window shows every string as the command's JSON does: ASCII,
  with a newline, a bidi override or a zero-width character as a visible
  escape (`\n`, `\u202e`), and markup as literal text. Widgets take plain text
  only, and its text helpers refuse anything that has not been escaped.
- **It refreshes** when it opens, after every change, and when you press
  Refresh; there is no timer, and the light says when the check last ran.
- **It cannot go stale.** `tests/test_gui.py` walks the command's parser and
  the fields of every read, and fails on any command, option or field the
  window neither offers nor exempts by name, with a reason. The exemptions
  today: `migrate` and `audit --path` (typed by hand), and `project show` and
  `version`, which the window shows from other reads.
  `tests/GUI-CHECKLIST.md` is the click-through for a person.

## Install, migrate, uninstall

The installer runs as root in dom0, so the tree it runs from must come from
somewhere AI cannot write. A tree copied out of the hub is only as
trustworthy as the hub. Fetch a tagged release in a fresh disposable (any
disposable template with curl and network; Qubes' stock `default-dvm` has both):

```sh
# in dom0
qvm-run --dispvm=default-dvm --pass-io \
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.19.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh   # --hub, --birth-egress, --pool-cap, --private-cap, --dry-run
```

`install.sh` runs every preflight check before it changes anything: its options
must be well-formed, the fleet must be in the two-state shape, existing project
records must load, and the rendered policy must parse on this box and decide
each of the 24 claims itself. It removes what v0.9.16 installed, backs up what it
replaces under `/var/lib/qmcp-rollback/`, writes an empty
`/etc/qmcp/projects.json` if there is none, installs the policy last, and exits
with `qmcp check`'s status. It changes no qube's tags. `uninstall.sh` removes the policy first (so no AI
caller reaches a half-removed service), then everything else, and ends with a
clean-state check that names what it keeps; `--purge` also removes
`/etc/qmcp`, the audit log and its rotated files. Backups under `/var/lib/qmcp-rollback/` are
never removed, nor is `/var/log/qmcp-changes.log`, the change history some
older installers kept. Qubes keep their tags.

**From v0.9.17**: install. Managed qubes from 0.9.17 stay in no slot: the hub
reaches them as before and copies between them still ask you. `qmcp check`
lists them; `sudo qmcp project move QUBE p00` puts one in the hub's slot,
where copies among the hub's qubes need no dialog.

**From v0.9.16**: run the staged migration, then install straight away.

```sh
sudo PYTHONPATH=/tmp/qubes-mcp/dom0 python3 -m qmcp.cli migrate                          # the plan
sudo PYTHONPATH=/tmp/qubes-mcp/dom0 python3 -m qmcp.cli migrate --apply --map ai-work=managed
sudo bash /tmp/qubes-mcp/deploy/install.sh
```

Mapping: `ai-full` becomes managed; `ai-exec` and `ai-net` are the operator's
choice per qube (`--map QUBE=managed` or `--map QUBE=guarded`, or
`--exec-default` for all of them); gateways become guarded; an umbrella-only
qube becomes guarded on a flipped fleet (it was the read floor) and is the
operator's choice on a tiered fleet that was never flipped (it held full
authority there; `--compat-default` sets them all). A qube named in v0.9.16's
guarded list, `/etc/qmcp/guarded`, becomes guarded unless `--map` says
otherwise, and an unreadable list stops the migration. Applying retires
`/etc/qmcp/tier-default`, `enforce-mode` and the guarded list, so a second run
changes nothing.

## Tests

| Suite | Where | |
|---|---|---|
| `tests/test_policy.py` | anywhere with python3-qrexec | the rulebook matrix above |
| `tests/test_dom0.py` | anywhere with python3-qrexec | the dom0 library against `tests/fakequbes.py`, a fake qubesadmin that copies tags, features and properties on clones and disposables as the platform does |
| `tests/test_projects.py` | anywhere with python3-qrexec | projects against the same fake: who is a lead, what a lead sees and does (and at what cost), what the hub's creates join, and every `qmcp project` command and project check |
| `tests/test_server.py` | anywhere | the MCP server and CLI against a fake qrexec client |
| `tests/test_gui.py` | anywhere; the widget tests where GTK 3 and a display exist | the operator's window, driving the real `qmcp` command against the same fake: the tree, the escaping, every form's command, and that no command, option or field is left out |
| `tests/seat_suite.py` | in the hub, on a real box | the tools through the real chain |
| `tests/redteam_suite.py` | in the hub, on a real box | attacks from the hub and from a managed qube, with positive controls; a probe that hangs on a dialog fails |
| `tests/project_suite.py` | in the hub, on a real box | carries the client and `tests/lead_seat.py` into a project's lead and runs it there: the lead's tools through the real chain, the lead's raw calls, and probes as root from inside its workers |

```sh
python3 -W error::DeprecationWarning -m unittest discover -s tests -p 'test_*.py'
```

`QMCP_POLICY_BASELINE=/etc/qubes/policy.d` runs the policy matrix against a
real dom0's policy set.

## Residual risks, accepted

- **A compromised hub controls all of AI space,** every project included: it
  runs commands in leads and workers, so it can read a lead's model key. The
  audit log records what it does through the dom0 services; its exec,
  copy-out and firewall writes are not on that log.
- **A compromised lead controls its own project:** every worker, and through
  them what lands in its sink. It reaches another project or the hub's qubes
  only by a copy through the operator's dialog, never the hub or any dom0
  service beyond its nine, and every create it makes stays inside its name
  space, templates, networks and quota. Give each project its own model
  key with a spend limit.
- **Copies inside a slot need no dialog.** A compromised worker can drop files
  into every member of its project and into its sink, and one of the hub's
  qubes into every p00 qube. Files land in `QubesIncoming` and are not run.
- **The rulebook matches badges, not records.** A slot badge on a qube outside
  AI space would let that slot's lead reach it; `qmcp check` fails until it is
  removed, and only the operator can put it there.
- **A lead learns its own project:** the names in its name space (through a
  create collision, including any qube named inside it or moved out of it,
  which `qmcp check` lists), its approved templates and its worker networks by
  name.
- **A busy lead can delay the other leads,** whose dom0 calls are refused as
  busy while the leads' shared pool is full. The hub's calls are never in that
  pool.
- **A lead refused by the pool cap inside its own quota** learns that the rest
  of AI space is full. `qmcp check` warns when the projects' quotas add up to
  more than the cap.
- **A lead's call that is already past its check finishes** when the operator
  removes the lead at that moment: a lifecycle, property or feature change,
  a few milliseconds wide. A create is checked again under the create lock.
- **A disposable template's home directory reaches every project that may
  spawn from it.** Keep project data out of disposable templates that several
  projects use.
- **A promoted lead keeps its history:** its files and whatever networks it
  was on. A cloned lead starts with its source's files, on the network it is
  given; a fresh lead starts empty.
- **The audit log grows until the operator rotates it.** `qmcp check` warns
  past 32 MiB; a compromised hub can fill it faster.
- **A template the hub edited is only as clean as the hub.** Guard the ones you
  rebuild from.
- **A qube spawned from a guarded template carries that template's contents**
  (its root, and a disposable template's home directory), **and a disposable
  also carries its template's non-qmcp tags**, because Qubes copies them.
  Guarded protects a template from change, not its contents from what is
  spawned from it; keep authority-granting tags off disposable templates you
  guard.
- **Templates reach the network through Qubes' update proxy**, outside the AI
  network path.
- **A named disposable template outside AI space** (`@dispvm:<name>`) still gets
  Qubes' own `ask` for OpenInVM, OpenURL, StartApp and GetImageRGBA from AI
  space; the exec services are denied. Qubes refuses a name that is not a
  disposable template before reading any rule, so those names are probeable.
- **A qube taken out of AI space by hand** keeps Qubes' disposable shortcut to
  its `default_dispvm`; creates and `qmcp revoke` pin it to none.
- **The policy cannot see `provides_network`.** A gateway without
  `qmcp-guarded` is refused by the services but not by the policy's
  guarded-qube denies (A1); `qmcp check` fails until it is guarded.
- **A name inside the reserved prefix** that belongs to a qube outside AI space
  is detectable through a create collision; `qmcp check` lists such qubes.
- **A preloaded disposable** waits in AI space with its template's tags —
  guarded if the template is, managed if it is not — until it is claimed.

## Roadmap

M2 adds projects in three releases: 0.9.18 projects themselves, operated
with the `qmcp` command; 0.9.19 (this one) the core of a dom0 GUI; then
proposals, with which the hub asks for a project, a new lead or a deletion and
the operator accepts it in the GUI, the only approval path. M3 adds networks: a gateway registry, locked or free
networks per project, an anonymity gate and model endpoints. M4 runs the
in-qube services on Arch and Fedora templates, M5 adds sealed qubes, and
1.0.0 completes the GUI.

## Anti-goals (immutable)

- **No proxy or relay between a principal and dom0.** Identity is the qrexec
  caller.
- **No runtime writes to qrexec policy.** A bad policy file can stop all of
  qrexec.
- **No Admin API for AI space, and no tag writes by the hub.** The one
  exception in AI space is a project's lead, which may read and write the
  firewall of its own project's members and nothing else. The hub's direct
  Admin API calls are the firewall methods on AI-space qubes (writes only on
  managed ones) and, behind the operator's dialog, USB attach, detach and
  listing for itself. The only tags the services write are a create's stamp on
  the qube it just made; every other badge change is the operator's `qmcp`
  command.
- **Never scope policy, ownership or any gate on `created-by-*` or
  `disp-created-by-*`.** qubesd stamps `created-by-` with the *calling* domain —
  dom0 for every qmcp create — so it cannot tell an AI-created qube from an
  operator-created one; and `"disp-created-by-x".startswith("created-by-")` is
  `False`, so anything holding `admin.vm.tag.Set` can forge it.
- **No MCP code in dom0.** dom0 holds the library, the shims, the operator's
  command and window, and the policy.
- **No third-party dependencies on the hub.** The server uses only Python's
  standard library.
- **No third-party SaaS or SSO.**
- **qmcp never depends on the operator's own notification tooling.**

## File layout

```
qubes_mcp/          the hub and the leads: server.py (MCP over stdio), tools.py
                    (the 18 tools), qrexec.py (transport), cli.py
dom0/qmcp/          the dom0 library: core (the shared check), services, projects,
                    birth, budget, scope, audit, fleet (check/migrate/roles/projects), cli,
                    and the window: gui (GTK) over guimodel (what it decides, no GTK)
dom0/rpc/           qmcp-service, the one shim installed under every service name
dom0/bin/qmcp       the operator's command
dom0/bin/qmcp-gui   the operator's window
policy/             30-mcp-control.policy
template-rpc/       the two in-qube services
deploy/             install.sh, uninstall.sh, qmcp-tmpfiles.conf, qubes-mcp.desktop
tests/              the suites above, GUI-CHECKLIST.md; data/ holds the upstream policy
                    baseline and qubesd's method list
```

## Versioning

Semantic versioning from 0.9.0. Every commit takes one patch bump, one
`CHANGELOG.md` entry and one tag. Before 1.0.0 a breaking change still takes a
patch bump and is labelled `BREAKING`.

## References

- Qubes Admin API: https://doc.qubes-os.org/en/latest/developer/services/admin-api.html
- Qrexec policy (R4.2+): https://forum.qubes-os.org/t/qrexec-policy-format-for-r4-2-and-r4-3/40407
- MCP specification: https://modelcontextprotocol.io/specification
