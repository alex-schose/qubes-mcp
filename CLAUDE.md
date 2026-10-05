# qubes-mcp — design document

An MCP server that lets AI agents operate a scoped part of a Qubes OS machine.
It runs in one qube, the **hub** (`mcp-control`), and in each project's
**lead**. Agents reach it over stdio (usually through SSH) and call its tools.
Most tools call `qmcp.*` services in dom0, which decide everything about the
qubes they touch; running a command, copying a file out and reading or writing
a firewall go straight to the qube or the Admin API, decided by the qrexec
policy in dom0.

**This file describes the code at this version (0.9.21). Read it first in any
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
  reads redact any reference to one as `<out-of-scope>`, except an enrolled
  gateway, which the operator chose to name: the hub reads every one, with its
  flag, label and addresses, and a lead its own worker networks. Two things
  still tell the hub whether another name exists: a create colliding with a
  name inside the reserved prefix, and the outcome of a proposal the operator
  accepts, which tells the hub whether the names it used exist (see the
  residual risks).
- **Two states.** A qube in AI space is **managed** (the hub may operate it) or
  **guarded** (listed, read and used as a reference — spawned from — but never
  operated). Guarded means the tag `qmcp-guarded`, or providing network: a
  gateway is guarded whatever it carries, and nothing is spawned from one.
- **A failed read is never an answer.** A read of a qube that fails (an empty
  qubesd reply, say) is not "no tags", "no network" or "not a gateway": each
  decision takes its restrictive answer. A service refuses, leaves the qube out
  of its list, or shows the value as `<unreadable>` (a power state as `NA` or
  `unknown`); a qube whose network role cannot be read is guarded. An operator
  command refuses, stops, or goes on without what it could not read; its report
  says which and lists the steps it completed, and a change after the last of
  them may have landed too. `qmcp check` reports an error for each read it
  could not make, so a failed read never leaves it GREEN. `qmcp list` shows
  what it could not read as `<unreadable>`, a power state as `NA` or `unknown`,
  and the window puts a qube whose tags, class or role cannot be read under
  Needs attention. A qube qubesd says no longer exists (one
  removed since the list was read) is skipped where the fleet is counted, when
  its tags are read: it holds nothing. No qube property a decision rests on is
  read with a default (qubesadmin's property errors are AttributeErrors, which
  `getattr` with a default would swallow). `tests/test_strict_reads.py`
  refuses `getattr` with a default, `hasattr` and `_safe` on a qube property
  in the dom0 library, and a `try` that swallows such a read unless it is
  listed with the reason its answer is restrictive or its failure reported.
- **Networks are the operator's.** A qube in AI space is given a network only
  if it is a gateway the operator enrolled (`qmcp gateway enroll`), or none.
  Whether a name is enrolled is read from the registry file, never by looking
  that name up. A lead's own firewall is the operator's too: dom0 writes it
  from the lead's model endpoint, and neither the hub nor the lead can write
  it (below).
- **Templates.** A TemplateVM or disposable template in AI space is the hub's
  to build and edit when it is managed. The operator guards any template that
  must stay a clean root: a template the hub edited is only as clean as the
  hub.
- **Badges and project records change only through the operator.** Neither
  the hub nor AI space can call the Admin API's tag methods. The `qmcp`
  command in dom0 is the operator's tool for changing badges and projects; the
  only tags qmcp writes on its own are the stamp a create puts on the qube it
  just made.
- **The hub asks; only the operator decides.** The hub cannot create a
  project, add a dump sink, change or remove a lead, delete a project, edit a
  project's templates, networks or quota, give a lead a network, or change
  a lead's firewall or model endpoint. It may
  propose each of those, as the options of one `qmcp project` command, and
  nothing changes until the operator accepts the proposal in dom0: in the
  window, or with the command the window runs. Leads cannot propose.
- **Strip on create.** `clone_vm` copies the source's tags and a disposable
  copies its template's, so every create path removes every tag in qmcp's
  vocabulary the platform copied (`qmcp-guarded`, every role and slot badge,
  the v0.9.16 tier tags, other principals' provenance), stamps `ai-managed`,
  `qmcp-owner_<caller>` (provenance only, never a gate) and the caller's slot
  badge (below), carries the platform's `anon-vm` forward (v0.9.16's
  `qmcp-egress-locked_*` is stripped like the rest: nothing reads it), reads
  the result back, and rolls the qube back if it is not exact. Tags outside
  qmcp's vocabulary (the operator's own) are left as Qubes copied them.
- **The rulebook is static.** `/etc/qubes/policy.d/30-mcp-control.policy` is
  installed once and never written at runtime. Before it is installed it is
  parsed by qrexec's own parser against the box's real policy directory, and
  27 of its claims are checked to be decided by it, not by a file that sorts
  earlier.
- **No dom0 exception text reaches a caller.** Every dom0 service failure
  answers with a fixed phrase, which may name the caller's own input, the
  reserved name prefix or a qube in AI space; for a state-changing service, the
  class of the exception behind a failed change goes to the audit log, which
  the operator can read and AI cannot. (The in-qube services return a
  command's own output and errors, from inside the qube the hub is operating.)
- **Audit.** Every call to a state-changing dom0 service — spawn, clone,
  disposable, property, feature, lifecycle, a submitted proposal — leaves one
  line on a hash-chained log in dom0 (`/var/log/qmcp-audit.log`, `root:qubes
  0660`), with the caller, the service and a summary of the names, keys and
  options in the request. So does every command of the operator's that changes
  something, as caller `operator`, with the command and the names it acts on;
  accepting or rejecting a proposal names its fingerprint. The value of a
  property or feature being set, a quota and a proposal's title are never
  logged. No service and no policy line exposes the log. Logging is
  best-effort: it never changes what the caller sees, or whether the operator's
  command runs. Running a command, copying out and firewall writes are decided
  by the policy, not by a dom0 service, and are not on this log.

## Projects

Sixteen slots. **p00** holds the hub's own working qubes; **p01–p15** are
projects. A project is one **lead**, the qubes it creates (its **workers**),
and optionally a **dump sink**. Its record, in `/etc/qmcp/projects.json`
(root-owned, written by `qmcp project`; the installer writes it empty), holds
what a tag cannot:

| Field | |
|---|---|
| label | 1–8 lowercase letters or digits, and not one a command could read as a slot (`p03`) or keyword (`none`, `hub`). The project's names are `<prefix><label>-…` (`ai-osint-scraper`); the hub creates only `<prefix>hub-…`, so a lead collides only with its own workers, or with a qube the operator named inside its space or moved out of it (`qmcp check` lists those). |
| lead | the qube that leads it, or none (a project without a lead keeps its workers; only the hub reaches them). |
| templates | the TemplateVMs and disposable templates the lead may spawn from, managed or guarded. A template on one project's list only is that project's alone. |
| networks | where the lead's workers may be born: enrolled gateways, or none. The first is the default. A worker's network is never moved to another one after birth; it can only be cleared. A network a member still sits on cannot be taken off the list. |
| quota | the workers' disk, counted like the pool cap. The pool cap still applies. |
| dump | the dump sink's name, or none. |
| model | the lead's model endpoint, `host:port`, or none. A new lead with a network and none given takes it; a new lead with no network leaves none; removing the lead keeps it. |
| lead_firewall | the current lead's firewall rules the operator accepted, as qubesd read them back, or none: a lead with no network unless its rules were set or accepted, and one upgraded from 0.9.20 until the operator accepts its rules. |

The badges the rulebook routes on: `qmcp-proj-pNN` on a member, `qmcp-lead` and
`qmcp-lead-pNN` on a lead (which wears no member badge), and `qmcp-dump-pNN`
with `ai-dump` on a sink, which is never in AI space.

**A lead** calls nine of the twelve dom0 services: not the event stream (it
polls instead), and not the hub's two proposal services. It operates only its project's members, references only its
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
operator removes one, and it never writes a lead's firewall) and its workers. Its own AppVMs join p00 when it creates
them; its disposables join no slot, because a disposable often opens hostile
content and in p00 it could drop files into the hub's other qubes without a
dialog, and nor does its clone of a project's qube or of a lead, for the same
reason. Templates and disposable templates join no slot.

**The operator** creates a project with `qmcp project create`, or by
accepting the hub's proposal to create one (below). Either way the command
makes the lead in one of three ways: fresh from a template, as a clone of one of
the hub's own AppVMs that the operator prepared as an agent, or by promoting
one of the hub's own AppVMs in place, which keeps its network (or, given none,
loses it: no network moves). Every project
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

**Gateways and firewalls.** A Qubes firewall rule filters only the qube it is
set on, and is carried out by the qube directly above it. So every qube in AI
space that has a network, gateways aside, sits directly on an enrolled
gateway, which carries out that qube's own rules: the operator builds one plain router per kind (clearnet, Tor, a proxy,
a VPN), each in front of the qube that kind uses for the operator's own work,
and enrolls the routers. Enrolling requires Qubes' own marker for a qube that
applies its clients' rules, the `qubes-firewall` feature (the qube's own
value, else its template's), and a template chain the hub does not manage. The marker is not
proof: a qube that hands its clients' traffic to a local program skips their
rules. Measured on Qubes 4.3.1 with Whonix 18, `sys-whonix` carries the marker
and applies none of its clients' rules, TCP or DNS, because Whonix sends their
traffic to Tor inside the gateway. So a Whonix gateway (Whonix's own
`anon-gateway` tag) is refused, and `qmcp gateway list` marks a router whose
upstream is one. The ceiling for all AI of one kind is that
router's own rules, carried out by the qube above it: behind `sys-whonix` they
have no effect, so a limit for the Tor router belongs inside the router. Inside
the ceiling the hub and a lead both write a worker's own rules, and the last
writer wins. **A lead's own rules are the operator's**: dom0 writes them when
the lead is made, from its model endpoint ("model endpoint only": the endpoint,
DNS, nothing else), once it wears `qmcp-lead`, which already bars the hub's
firewall writes, and before its slot's lead badge; and again only when the
operator changes them (`qmcp project firewall`), directly or by accepting the
hub's proposal; the rulebook denies the hub any write to a lead's firewall, and
a lead cannot write its own. `qmcp check` fails when the live rules of a lead
with a network differ from the ones the operator accepted. A lead's rules do not limit its workers,
which do not route through it. No qube's network ever moves: a worker keeps
the network it was born on and a lead its own (either can only be cleared),
and a project gets a lead on another network only by a new lead, which can
take what it needs from the old one kept as a worker. An enrolled gateway that
stops qualifying is refused by the operator's commands and fails `qmcp check`;
the services still place new qubes on it until it is fixed or removed.

**Authority is checked when the work is done.** A service reads its request
before it checks the caller, so a lead removed while its request is still
arriving is refused; a create checks its caller again once it holds the create
lock, which every project command holds too. A call already past its check
finishes (see the residual risks).

## Proposals

The hub asks for what only the operator may do by **submitting a proposal**
(`qmcp.SubmitProposal`): the options of one `qmcp project` command, never a
plan or a list of commands. A proposal names a project by its label (or `p00`
for the hub's own dump sink), never by its slot: by the time the operator
accepts, a slot can hold a project the proposal was not about. Six kinds:

| Type | The command it is the options of |
|---|---|
| `project-create` | `qmcp project create`: the label, where the lead comes from (`template`, `clone` or `promote`), its network, name and model, more approved templates, the worker networks, the quota, a dump sink or not |
| `project-edit` | `qmcp project edit`, but as changes: templates and worker networks to add or remove, a new default network, a new quota |
| `project-dump` | `qmcp project dump` |
| `project-lead` | `qmcp project lead`: remove the lead, or a new one (with its model), saying whether the old lead stays as a worker or is removed (there is no default), and whether a kept old lead's network joins the worker networks |
| `project-firewall` | `qmcp project firewall`: a new model endpoint for the lead (its firewall becomes that endpoint and DNS), or exactly these rules |
| `project-delete` | `qmcp project delete --yes` |

- **Submitting checks the shape only.** dom0 looks no qube up, so submitting
  is no oracle over names outside AI space: the hub may name a template it
  cannot see. Once the operator accepts, `accepted` or `failed` tells the hub
  whether the names it used exist. dom0 stores its own normalised copy, canonical JSON in
  `/var/lib/qmcp/proposals/`, and the copy's sha256 is the proposal's
  fingerprint. A title of 1–100 printable ASCII characters goes with it; the
  window shows it labelled "written by AI". A quota is at most 1 EiB. At most
  10 may be pending; each expires after 7 days, which is read whenever the
  store is, with no timer.
- **The operator is told** by a desktop notification in dom0, whose text is
  fixed ("Proposal N from the hub is waiting in the qubes-mcp window."), never
  the hub's words: notification servers render markup and links in the body
  (measured on Qubes 4.3.1: xfce4-notifyd advertises `body-markup` and
  `body-hyperlinks`). It is best-effort: a submit never fails because no
  notification could be shown.
- **Accepting runs that command's own code**, with the operator's authority:
  `qmcp proposal accept N --sha256 F`, which the window runs with the
  fingerprint it showed. A stored file that no longer hashes to `F` is refused,
  so what the operator read is what runs. The command checks everything it
  can before it changes anything, against the fleet as it is then; it changes
  in the order that fails toward less authority, undoes what it can (a create
  that fails is undone), and reports any partial step. A removed qube cannot be
  put back: a lead change whose new lead fails after the old one was removed
  leaves the project without a lead, which is safe, and the report says so.
  Its outcome closes the proposal: `accepted`, or `failed` with the report.
  A refusal before the command runs (another fingerprint, the second tick not
  given, unreadable records) changes nothing, and the proposal stays pending.
  An edit is applied to the record as it is at accept and changes only the
  entries it names, so a later change of the operator's to anything else
  stands.
- **The second tick.** `qmcp proposal show` computes, against the fleet as it
  is, why a proposal needs more than one click: any removal (deleting a
  project, removing a lead, replacing one without keeping the old); a network
  that neither the hub nor any qube in AI space uses today and no project
  lists (a gateway's own upstream does not count as in use: a qube placed on
  it directly would skip the gateway); promoting one of the hub's qubes into a
  lead; a quota that would make the projects' quotas add up to more than the
  pool cap; a model endpoint no project uses today, or a lead change that
  gives the project a different model endpoint; and every change to a lead's firewall, which
  `show` gives as the old model, accepted and live rules beside the new ones. A lead whose badges cannot be read counts as one that will be
  removed, and a network that cannot be read as a new one: a failed read never
  makes a removal one click. `accept` computes the reasons again while it
  holds the project commands' locks, so no project command and no create can
  change what they rest on before its command runs. The networks AI space
  uses can still change meanwhile (the hub may clear a qube's network at any
  time); the network a proposal names is in the command shown either way. The window shows them in red. `show` gives a tick, the
  digest of exactly those reasons, and `accept` refuses without `--yes TICK`
  while there are any, and with a tick given for other reasons: a tick given
  for "removes the old lead X" never accepts "removes the old lead Y".
- **The hub learns a state word**: pending, accepted, rejected, expired or
  failed, with its own stored proposal (`qmcp.ProposalStatus`). Never the
  command's report or a reason: the report holds dom0's exception classes and
  the operator's view of the fleet.
- **A proposal whose command may have run is never pending again.** An accept
  marks the proposal before its command runs and holds the mark locked until
  the decision is written; a mark that outlives its accept (dom0 stopped
  part-way) reads as `failed`, and so does a decision file that does not parse.
  `qmcp check` warns about them until the operator reads them
  (`qmcp proposal show N`) and closes them (`qmcp proposal reject N`).
- **Where.** The store is `root:qubes 2770`, declared in tmpfiles: the services
  (a non-root dom0 user in `qubes`)
  write the proposals, and the operator's accept and reject, as root, write the
  decisions beside them, which the services read back. `/run/qmcp/proposals.lock`
  serialises them for the moment it takes to check and mark a proposal; an
  accept takes the project commands' locks first and holds them through its
  command, but lets the store's go once the proposal is marked, so a submit
  never waits on a running command.

## What lives where

| Where | What |
|---|---|
| hub (`mcp-control`) | `qubes_mcp/`: the MCP server and the `qubes-mcp` CLI. Standard library only. It reaches AI space through the policy's hub section; beyond that, only its own boot services and the operator's dialogs. |
| each lead | the same `qubes_mcp/`, which reaches its project through the policy's slot lines and the leads' section. |
| dom0 | `/usr/local/lib/qmcp/qmcp/` (the library), `/etc/qubes-rpc/qmcp.*` (one shim under each service name), `/usr/local/bin/qmcp` (the operator's command), `/usr/local/bin/qmcp-gui` and its menu entry (the operator's window), the policy, `/etc/qmcp/` (operator files, `projects.json` among them), `/var/lib/qmcp/proposals/` (the hub's proposals and their decisions), `/run/qmcp/` (lock files). |
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
| `qmcp.ListAIManagedQubes` | AI space: name, class, label, template (redacted if out of scope), power state, `guarded`, `slot` and `lead`. A qube whose tags or class cannot be read is left out; a label or template that cannot be read is `<unreadable>`, and a power state that cannot be read `NA` (qubesadmin's word for it) or `unknown`. |
| `qmcp.GetPropertyAIManaged` | One property of a managed or guarded qube. Only properties qubesd lists; references out of scope redacted, and so are the netvm's addresses (`visible_gateway`, `dns`, …) when the netvm is out of scope, and refused when it cannot be read; an enrolled gateway is named (for a lead, one of its worker networks); `tags` filtered to `ai-managed` and `qmcp-guarded`, and refused when they cannot be read. |
| `qmcp.SetPropertyAIManaged` | `label`, `memory`, `maxmem`, `vcpus`, and `netvm` only to null. Everything else (`template`, `name`, `default_dispvm`, `provides_network`, …) is operator-only. |
| `qmcp.SetFeatureAIManaged` | Allowlist: `service.*`, `vm-config.*`, `menu-items`, `default-menu-items`. Every other key, including any a future Qubes adds, is operator-only. |
| `qmcp.LifecycleAIManaged` | start, shutdown, kill, pause, unpause, remove. Remove is a real remove; removing a lead is the operator's. |
| `qmcp.SpawnAIManagedQube` | AppVM or DispVMTemplate from a TemplateVM, or a named DispVM from a disposable template. The template may be managed or guarded, but not one that provides network. A lead spawns AppVMs and DispVMs from its approved templates only. |
| `qmcp.CloneAIManagedQube` | Clone a managed qube, templates included. A guarded source is refused: a clone is a managed, editable copy of everything in it. |
| `qmcp.SpawnDisposableAIManaged` | A disposable from a managed or guarded disposable template, born managed. Uses Qubes 4.3's preloaded disposables when the template has `preload-dispvm-max` (measured: a `qubes_run_disposable` cycle took 1.5 s with `preload-dispvm-max=1`, about 8 s without). |
| `qmcp.AIManagedEvents` | The hub only. A window of admin events (1–120 s) whose subject is in AI space; at most 16 filters of at most 64 characters. Tag events surface only for the two visible badges. |
| `qmcp.GetPoolStats` | `ai_managed_bytes_used`, `_cap` and `_headroom`, and `name_prefix`, the prefix the caller's new names carry (the hub's `ai-hub-`, a lead's `ai-<label>-`): for the hub, AI space against the operator's cap, `reserved_prefix` (the bare prefix a project's names build on), and every project's record (slot, label, lead, templates, worker networks, quota, disk used, and whether it has a dump sink, never the sink's name, which is outside AI space; a recorded name that has left AI space reads `<out-of-scope>`, unless it is an enrolled gateway; null when the records cannot be read) and the gateway registry (`gateways`: name, anonymising, label; null when it cannot be read); for a lead, its workers against its quota, with its project's label, approved templates, worker networks and dump sink. A lead never sees the fleet's figures. |
| `qmcp.SubmitProposal` | The hub only. Stores a proposal for the operator after checking its shape (see Proposals); touches no qube. |
| `qmcp.ProposalStatus` | The hub only. Its proposals' states, newest first; with `id`, one of them with its stored copy. |

**Creates.** A name says who owns the qube: the hub's must lie inside its own
space, the reserved prefix (`/etc/qmcp/name-prefix`, default `ai-`) followed by
`hub-` (`ai-hub-browser`), and a lead's inside its project's (`ai-<label>-`).
`hub` is never a project's label, so no two spaces overlap. A name is judged on
its shape alone, before anything is looked up, so a create is no oracle over
names outside the caller's space. (Qubes
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
netvm is not an enrolled gateway. A TemplateVM used as a base never decides,
because its netvm is an update path; the child then gets the hub's netvm if
that is enrolled, else `/etc/qmcp/birth-egress` if that is enrolled, else the
create is refused. A lead's worker networks must be enrolled too, and are
checked again under the create lock. A spawn may ask for `netvm: null`, which is always allowed,
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
  - A1b: the hub cannot write a lead's firewall (it may read it): a lead's
    firewall is the operator's.
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
- **C. Leads to dom0:** nine of the twelve dom0 services: not the event
  stream, and not the hub's two proposal services, which D2 then refuses.
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
- **E. The hub:** the twelve dom0 services; exec, copy-out and firewall on
  AI space (firewall writes to a guarded qube or a lead were refused in A).
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
| `qmcp check [--json]` | Fails on: the hub missing, in AI space, or named differently in the policy; tier tags; a gateway in AI space without `qmcp-guarded`; a drop box in AI space; the policy modified, refused by qrexec's parser, or overridden by an earlier file for any of its 27 checked claims; a gateway registry that does not read, or an enrolled gateway that no longer qualifies; a qube in AI space (not a gateway itself) on a network that is not enrolled; a lead with a network whose firewall differs from the rules the operator accepted; services, runtime directory or caps missing; no `qubes` group; a runtime directory, create lock, proposal lock or audit log the services cannot write, that is, not group-writable or not the `qubes` group's (an audit log missing, since they cannot create one), or `/run/qmcp` not setgid; the proposal store missing, or not the `qubes` group's, group-writable and setgid; a broken audit chain; v0.9.16 leftovers; unreadable project records; a member or lead badge outside AI space, a sink inside it; a qube in two slots; a slot badge with no project; a template or gateway in a project; a lead whose badges and record disagree, or any qube wearing lead badges that is not its slot's recorded lead; a sink that is not its record's. Warns on a missing `projects.json`, stray badges, v0.9.16 tombstones, qubes outside AI space inside the name prefix, any qube in a project's names that is not its lead or member, managed qubes pointing at a disposable template outside it, a birth-egress qube that is not enrolled, a lead with a network and no accepted firewall, an audit log due for rotation, a project without a lead, an approved template that is not one, a worker network that is not enrolled, a member on a network off its project's list, a sink with a network, managed AppVMs in no slot, project quotas that add up to more than the pool cap, and a proposal that cannot be read or whose accept never finished. Reports an error for each read it could not make: a qube's tags, network, role, class, template or default disposable template, a gateway's `qubes-firewall` feature, a lead's firewall. A qube whose tags cannot be read is skipped by the items that judge tags, the registry item included (the "qube tags" error names it). So is one qubesd says is gone when its tags are read, except an enrolled gateway: the registry item reports that one. Exit 0 GREEN, 1 FAILED, 3 INCOMPLETE — INCOMPLETE is not green. |
| `qmcp list [--all] [--json]` | AI space with state, class, template, network, power, slot and provenance. A state, class, template, network, slot or provenance that cannot be read is `<unreadable>`, and a power state `NA` or `unknown`; a qube whose tags cannot be read is still listed, and one qubesd says is gone is not. With `--json`, each row adds the lead flag, whether the qube provides network and whether it is a disposable template (each `<unreadable>` when it cannot be read), and its badges (`null` when its tags cannot be read). `--all` adds every other qube but dom0, with no state. |
| `qmcp settings [--json]` | The operator files the services read (hub, name prefix, pool and private caps, birth egress), how many gateways are enrolled, the disk AI space uses, and the version. |
| `qmcp gateway list [--json]` | The gateway registry: each entry, whether it is still usable and why not, its upstream (marked when that is a Whonix gateway, whose clients' firewall rules have no effect), and the qubes and projects that use it. |
| `qmcp gateway enroll QUBE [--anonymising] [--label TEXT]` / `set QUBE [--anonymising yes\|no] [--label TEXT]` / `remove QUBE` | Let AI space use a gateway, change its entry, stop AI space using it. Enrolling refuses a qube that does not provide network, lacks Qubes' `qubes-firewall` marker, is a Whonix gateway, sits on a template the hub manages, is the hub, a drop box, a lead or a member, or is in AI space unguarded; removing refuses while a project lists it or a qube in AI space sits on it. Root. |
| `qmcp manage QUBE` / `qmcp guard QUBE` | The role actions. Both refuse the hub, a drop box, and a qube (other than a gateway) on a network that is not enrolled; `manage` also refuses a gateway; `guard` refuses a lead or a member. |
| `qmcp revoke QUBE` | Strips every qmcp badge, pins `default_dispvm` to none, shuts the qube down. Refuses a lead. |
| `qmcp project list` / `show NAME` | The slots in use; one project's record. |
| `qmcp project create LABEL ...` | A new project in the lowest free slot: `--lead-template T`, `--lead-clone QUBE` or `--lead-promote QUBE`; `--lead-netvm` (an enrolled gateway, or none); `--model HOST:PORT` (needed for a lead with a network: its firewall allows only that and DNS); `--template` (more approved templates; the lead's own goes first when it is in AI space); `--network QUBE` or `none` (enrolled gateways), the first the default; `--quota`; `--dump`. |
| `qmcp project edit NAME ...` | Replace the approved templates or the worker networks, or change the quota. Workers keep their networks, so a network a member sits on cannot be taken off the list. |
| `qmcp project lead NAME --remove` / `--lead-…` | Remove the lead (the project keeps its workers), or give the project a new one, with `--model` (else the project's, for a new lead with a network); `--keep-old` keeps the old lead as a worker, on its network if the project lists it, otherwise with none unless `--add-old-network` adds that network to the list. |
| `qmcp project firewall NAME [--json]` | The lead's model, the firewall rules the operator accepted and its live ones. With `--model HOST:PORT`, `--rule RULE` (repeatable) or `--accept-current`, set a new model (for a lead with a network; its firewall becomes that endpoint and DNS), exactly these rules, or accept the live rules as they are, if they are in qmcp's rule format (no comment or expire, at most 32). A write that does not read back as set is undone. Each change needs root. |
| `qmcp project dump NAME` | Create a dump sink for a project, or for p00 (`hub-dump`). |
| `qmcp project move QUBE TARGET` | Move a managed AppVM into p00, a project, or no slot. Its network does not change, so a project takes it only on one of its worker networks; out of one slot into another needs `--yes`. |
| `qmcp project delete NAME --yes` | Remove the lead and every member, keep the dump sink without its badge, strip every badge of the slot, free it. Given a slot with no record, finish a delete that stopped half-way. Without `--yes` it prints what it would remove and changes nothing; that needs no root. |
| `qmcp proposal list [--json]` / `show N [--json]` | The hub's proposals, newest first; one proposal with its stored options, the command it is the options of (an edit shows its project before and after instead; a lead-firewall proposal adds the lead's model and rules now and after), why it needs the second tick, the plan of a delete, and its decision and report once decided. Reads, as any member of `qubes`. |
| `qmcp proposal accept N --sha256 F [--yes TICK]` | Run proposal `N`'s command as the operator, if its stored file still hashes to `F`; `--yes TICK` is the second tick, the tick `show` gave for the reasons it showed, refused if those reasons have changed. Root. |
| `qmcp proposal reject N` | Close it without running anything. Also closes a proposal that needs closing: an unreadable one (rejected), one whose accept never finished, and one whose decision file does not read (both `failed`; the unreadable decision file is kept beside the new one). Root. |
| `qmcp migrate [--apply]` | v0.9.16 tiers to two states (below). Dry run by default. |
| `qmcp audit verify` / `tail` / `rotate` | The chain. `rotate` moves the log aside and starts a new one anchored on the old head; it needs root. |

Every `qmcp project` command that changes something needs root: it writes
`/etc/qmcp/projects.json` under a lock, by atomic rename, or (`move`) takes
that lock. So do `qmcp proposal accept` and `reject`. Every command that
changes something leaves one line on the audit chain as caller `operator`
(the command, the names it acts on and its options; a quota only as "set");
reads, plans and dry runs leave none, and neither does a command the argument
parser refuses (`migrate`'s `--map` check included) or one refused for not
running as root; one its own checks refuse, a malformed `--quota` or lead name
among them, leaves a line with `ok` false.

## The operator's window (dom0)

`qmcp-gui` is the `qmcp` command as a window: in the Qubes menu under
Settings > Qubes Tools, or in a dom0 terminal. Run it as your own dom0 user;
it refuses to run as root.

- **It runs the `qmcp` command and nothing else.** Every read is `qmcp ...`,
  run as you, in JSON wherever the command offers it, and stopped after 120 s;
  every change is `/usr/bin/sudo -n qmcp ...`, the command you would type, one
  at a time. Each form shows that command under its fields before OK runs it
  (while OK is off, that line says why instead, under *OK is off:*), and the
  report after it shows the command, its exit status and its output.
  The window never imports qubesadmin, so it can do nothing the command cannot.
- **What it shows.** The Qubes tab is a tree: the hub with p00 and the qubes in
  no slot, each project with its lead, workers and sink, then templates,
  gateways, other guarded qubes, and Needs attention. A qube's place comes from
  the badges the rulebook routes on, never its label colour, which the hub may
  set. Needs attention holds the qubes whose badges the rulebook acts on
  against the records: lead badges the records do not back, a gateway without
  `qmcp-guarded` (Guard is offered there), a drop box or the hub inside AI
  space, slot badges outside it, a qube in two slots, a template in a project;
  and a qube whose tags, class or role could not be read, which offers nothing.
  Every other failure of `qmcp check` is on the Check tab. Beside the tree, the
  selection's every field, and the actions that fit it. The light is
  `qmcp check`'s result with the time it ran; the Check tab lists its findings,
  failures first. The Audit tab shows the last 200 lines, newest first, the
  selected one in full, and verifies or rotates the chain. It holds the calls
  the hub and the leads make to state-changing services, every command of the
  operator's that changes something (caller `operator`, accepting and
  rejecting proposals included), and the line each rotation starts a log with,
  which names the file the earlier lines moved to. The Settings tab shows
  `qmcp settings`, read-only. The Gateways tab lists the gateway registry:
  each gateway's upstream, how many qubes in AI space use it and which projects
  list it, and every field of the selected one. A gateway that no longer
  qualifies, or whose upstream ignores its clients' firewall rules (a Whonix
  gateway), says so on its row. Selecting a project or its lead also reads
  `qmcp project firewall NAME --json`: the lead's model endpoint, the rules you
  accepted, the live ones, and whether they are the same.
- **The Proposals tab** lists the hub's proposals, newest first, and its label
  counts the pending ones ("Proposals (2)"). Selecting one runs
  `qmcp proposal show N --json` and shows every field: the options dom0
  stored, the equivalent command (an edit shows each part of its project now
  and after instead), a delete's plan, the decision and report of a decided
  one, and the title, labelled "written by AI". A lead-firewall proposal shows
  the lead's model now and after, then the rules you accepted, the live ones
  and the ones accepting sets, one above the other; live rules that could not
  be read say so, never an empty list. A pending proposal can be
  accepted or rejected through a form that shows the command it will run;
  Accept's carries the fingerprint from that `show`. When accepting needs the
  second tick,
  the reasons are in red and Accept stays off until the tick box is ticked,
  which adds `--yes` with the tick `show` gave for those reasons. The tick
  box clears when the proposal's fingerprint or
  reasons change. A proposal that needs closing (a file that does not read, or
  an accept that never finished) can be closed with `qmcp proposal reject`;
  no other closed proposal has a button. A `show` that fails keeps the last
  good view of that proposal and turns its buttons off.
- **What it does.** Every command that changes something, but `migrate` (a
  one-time step from v0.9.16), is a form: create, edit and delete projects,
  change or remove a lead, add a dump sink, move a qube between slots, manage,
  guard, revoke, add a qube to AI space, accept or reject the hub's proposals,
  enroll, change and remove gateways, set a lead's model endpoint or rules or
  accept its live rules, and rotate the audit log. The forms offer as a
  network none and the enrolled gateways (a lead's may also be left unset);
  one that no longer qualifies is listed and marked, and choosing it is
  refused, as the command refuses it, and the edit form also lists the
  project's current networks that are not enrolled, marked, so they can be
  taken off. A lead with a network needs its model endpoint (a new lead of a
  project takes the project's), and Set lead model is off for a lead with no
  network, or one whose network cannot be read. The model and rules forms show the rules accepted now, live now and
  after OK side by side; accepting the live rules shows the first two; a
  lead-firewall proposal's accept form points to the rules in the pane. Keeping an old lead as a
  worker offers to add its network to the project's list, unticked. A delete
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
  everything, a later one with a failed read keeps the qubes, records,
  proposals, gateway registry, audit lines and settings of the last complete
  one, says which read failed and when
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
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.21.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh   # --hub, --birth-egress, --pool-cap, --private-cap, --dry-run
```

`install.sh` runs every preflight check before it changes anything: its options
must be well-formed, the fleet must be in the two-state shape, existing project
records and gateway registry must load, and the rendered policy must parse on this box and decide
each of the 27 claims itself. It removes what v0.9.16 installed, backs up what it
replaces under `/var/lib/qmcp-rollback/`, writes an empty
`/etc/qmcp/projects.json` if there is none, installs the policy last, and exits
with `qmcp check`'s status. It changes no qube's tags. `uninstall.sh` removes the policy first (so no AI
caller reaches a half-removed service), then everything else, and ends with a
clean-state check that names what it keeps; `--purge` also removes
`/etc/qmcp`, the proposal store `/var/lib/qmcp`, the audit log and its rotated
files. Backups under `/var/lib/qmcp-rollback/` are
never removed, nor is `/var/log/qmcp-changes.log`, the change history some
older installers kept. Qubes keep their tags.

**From v0.9.20**: install, then enroll the routers AI space uses. The gateway
registry starts empty: until you enroll, no qube in AI space can be given a
network, and `qmcp check` fails on every one (gateways aside) that has one,
naming the command. A Whonix gateway cannot be enrolled: put AI qubes that sit
directly on `sys-whonix` on a router in front of it (`qvm-prefs QUBE netvm
ROUTER`), or clear their network. Then give the firewall of each lead with a
network its owner:
`sudo qmcp project firewall NAME --accept-current` accepts its current rules if
they are in qmcp's rule format (no comment or expire, at most 32), and
`--model HOST:PORT` replaces them with that endpoint and DNS; `qmcp check`
warns until you do. The hub's spawns and clones must be named `ai-hub-…`.
Proposals still pending from 0.9.20: a `project-create` that makes a lead with
a network has no model, so accepting it fails; a `project-lead` takes the
project's model if it has one by then; one that promotes a qube onto a network
no longer reads, and is closed with `qmcp proposal reject N`. The hub can
submit any of them again.

**From v0.9.18 or v0.9.19**: install, then do the steps the v0.9.20 note gives after its install.
The proposal store starts empty.

**From v0.9.17**: install, then do the steps the v0.9.20 note gives after its install. Managed
qubes from 0.9.17 stay in no slot: the hub
reaches them as before and copies between them still ask you. `qmcp check`
lists them; `sudo qmcp project move QUBE p00` puts one in the hub's slot,
where copies among the hub's qubes need no dialog.

**From v0.9.16**: run the staged migration, then install straight away, then do the steps the
v0.9.20 note gives after its install.

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
| `tests/test_gateways.py` | anywhere with python3-qrexec | the gateway registry, the networks AI space may use, leads' firewalls and their proposal, against the same fake |
| `tests/test_proposals.py` | anywhere with python3-qrexec | proposals against the same fake: who may submit, the shape, the store, the second tick, accepting and rejecting through the real commands, an accept that never finished, and the operator's audit lines |
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
- **A hijacked lead can send data out through any of its workers that has a
  network** (it runs commands in them and sets their firewalls), whatever its
  own firewall says, and through DNS, which its firewall keeps open whatever
  form its model endpoint takes. Its own firewall makes that traffic go
  through the qmcp services and the policy, rather than out of the lead. A
  project that must be sealed gets a lead with no network and workers on no
  network.
- **Behind a gateway that hands traffic to a local program, its clients'
  firewall rules have no effect**: measured for `sys-whonix`, possibly true of
  a proxy qube. Each qube's own rules hold only behind a plain router; a
  router's own limit behind `sys-whonix` belongs inside the router.
- **The marker is a claim.** Enrolling trusts the `qubes-firewall` feature
  (the gateway's own value, else its template's); a VPN or proxy
  program that rewrites the firewall inside the gateway can still skip its
  clients' rules. Test a new kind of router before relying on it.
- **A hostname rule allows the addresses the router looked up.** An endpoint
  whose addresses change between lookups can be refused now and then.
- **A named disposable template outside AI space** (`@dispvm:<name>`) still gets
  Qubes' own `ask` for OpenInVM, OpenURL, StartApp and GetImageRGBA from AI
  space, and this policy's own `ask` for Filecopy, OpenInVM, OpenURL and the
  clipboard from the hub; the exec services are denied. Qubes refuses a name
  that is not a disposable template before reading any rule, so those names
  are probeable from both.
- **A qube taken out of AI space by hand** keeps Qubes' disposable shortcut to
  its `default_dispvm`; creates and `qmcp revoke` pin it to none.
- **The policy cannot see `provides_network`.** A gateway without
  `qmcp-guarded` is refused by the services but not by the policy's
  guarded-qube denies (A1); `qmcp check` fails until it is guarded.
- **A name inside the reserved prefix** that belongs to a qube outside AI space
  is detectable through a create collision; `qmcp check` lists such qubes.
- **A preloaded disposable** waits in AI space with its template's tags —
  guarded if the template is, managed if it is not — until it is claimed.
- **The hub can put a notification in front of the operator**: one per
  proposal, with fixed text and its number, at most 10 pending at a time.
- **A proposal's title is the hub's text.** The window labels it "written by
  AI" and shows it escaped, beside the options dom0 checked; read the options.
- **Accepting tells the hub something.** `accepted` or `failed` says whether
  the names it used exist; that happens only when the operator accepts, and a
  rejection tells it nothing.
- **A compromised hub can fill the queue:** an eleventh proposal is refused
  until the operator rejects some or they expire after 7 days.
- **An accept that never finished** (dom0 stopped while its command ran)
  closes the proposal as `failed`; its command may have run part of the way,
  and `qmcp check` warns until the operator reads it and closes it.

## Roadmap

M2 added projects in three releases: 0.9.18 projects themselves, operated
with the `qmcp` command; 0.9.19 the core of a dom0 GUI; 0.9.20 proposals, with
which the hub asks for a project, a change to one, a new lead or a deletion and
the operator accepts it in dom0, the only approval path. M3 adds networks in
three: 0.9.21 (this one) the gateway registry and leads' firewalls; next,
self-hosted model qubes reached over `qubes.ConnectTCP`; then anonymous
projects, which the hub cannot see into, with a gate that stops a project
whose path stops being anonymous. M4 runs the
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
  managed ones that are not leads) and, behind the operator's dialog, USB attach, detach and
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
                    (the 25 tools), qrexec.py (transport), cli.py
dom0/qmcp/          the dom0 library: core (the shared check), services, projects,
                    proposals, gateways (the registry), firewall (a lead's), birth,
                    budget, scope, audit, fleet (check/migrate/roles/projects/
                    gateways), cli,
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
