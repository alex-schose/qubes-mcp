# qubes-mcp — design document

An MCP server that lets AI agents operate a scoped part of a Qubes OS machine.
It runs in one qube, the **hub** (`mcp-control`), and in each project's
**lead**. Agents reach it over stdio (usually through SSH) and call its tools.
Most tools call `qmcp.*` services in dom0, which decide everything about the
qubes they touch; running a command, copying a file out and reading or writing
a firewall go straight to the qube or the Admin API, decided by the qrexec
policy in dom0.

**This file describes the code at this version (0.9.25). Read it first in any
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
  policy names a different hub than the file. In anonymous mode it wears
  `qmcp-anon`, and the anonymity gate may badge it `qmcp-blocked` and
  `qmcp-stopped`; the check allows those three on it then. A lead is in AI space: the hub
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
- **A guarded qube is sealed, and the operator may open it for a while.** Being
  guarded is a refusal, not a state the hub can change: the rulebook denies it
  every way into such a qube. `qmcp open QUBE --for 2h` lifts part of that for
  one qube and one stretch of time — the hub may then run commands in it as
  root and copy a file in, which Qubes asks the operator to confirm one file at
  a time, and with `--firewall` write that qube's firewall rules as well. It
  can never change which network the qube is on. `qmcp seal QUBE` ends the
  window at once and kills the qube if it is running, so nothing the hub
  started in it runs on; a dom0 timer ends one that has run out, and every boot
  ends every window. The hub may ask for a window with a proposal, which always
  needs the operator's second tick; it can never open one itself. There is no
  indefinite window: that is `qmcp manage`, which takes the qube out of the
  guarded state altogether.
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
  it (below). A lead whose model is a self-hosted model qube has no network,
  and reaches that qube only on port 11434 (below).
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
  a lead's firewall or model (an endpoint, or a model qube). It may
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
  40 of its claims are checked to be decided by it, not by a file that sorts
  earlier.
- **An anonymous project is checked, not trusted.** dom0's anonymity gate
  judges every anonymous project every 15 seconds and after every `qmcp`
  command that changes qubes, projects or gateways, and stops one whose path stops being
  anonymous. A hidden one is not the hub's: the rulebook keeps the hub out of
  every qube wearing `qmcp-hubblind`, and the services answer the hub about
  one exactly as about a name that does not exist (see "Anonymous projects").
  In anonymous mode the gate judges the hub too, with every qube in AI space
  that is not an anonymous project's lead, member or model qube, guarded
  routers aside (see "Anonymous mode").
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
| model | the lead's remote model endpoint, `host:port`, or none. A new lead with a network and none given takes it; a new lead with no network leaves none; removing the lead keeps it. |
| model_qube | the project's self-hosted model qube, or none; never set together with `model`. A new lead keeps it unless it is given a network and a remote model, another model qube, or none; removing the lead keeps it. |
| lead_firewall | the current lead's firewall rules the operator accepted, as qubesd read them back, or none: a lead with no network unless its rules were set or accepted, and one upgraded from 0.9.20 until the operator accepts its rules. |
| anonymous | true for an anonymous project (see "Anonymous projects"); absent otherwise. |
| hidden | true for an anonymous project the hub may not see; absent otherwise. |
| note | the operator's private note on an anonymous project, 1–80 printable characters, or absent: shown by `qmcp project list` and the window, never to the lead or the hub. |

The badges the rulebook routes on: `qmcp-proj-pNN` on a member, `qmcp-lead` and
`qmcp-lead-pNN` on a lead (which wears no member badge and no model badge),
`qmcp-dump-pNN` with `ai-dump` on a sink, which is never in AI space, and
`qmcp-model-pNN` on a model qube, one for each project it serves. An anonymous
project's lead and members also wear `qmcp-anon`; every qube of a hidden one
(its sink, model qube and approved disposable templates too) wears
`qmcp-hubblind`; and the anonymity gate puts `qmcp-blocked` on the lead and
members of a project it stopped (in anonymous mode, on the hub and p00, or on
another qube under the hub's check), and `qmcp-stopped` on each of those once
it knows it is down (killed, or found halted). In anonymous mode the hub and
every qube under the hub's check wear `qmcp-anon` too.

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
another needs `--yes`; so does a move into, out of or between anonymous
projects (see "Anonymous projects").

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
DNS when the endpoint is a host name, nothing else; an endpoint given as an
address gets no DNS rule), once it wears `qmcp-lead`, which already bars the hub's
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

**Model qubes.** A project's lead may use a self-hosted model instead of a
remote endpoint: a **model qube**, guarded and with no network, which the lead
reaches on port 11434 through Qubes' `qubes.ConnectTCP` (`qvm-connect-tcp
11434:<model qube>:11434` in the lead; the model qube's own qrexec agent
connects the call to its 127.0.0.1:11434, Ollama's default). A lead whose model
is a qube has no network. While it is guarded, nothing else in AI space
reaches a model qube, and the hub reaches it only through your dialog (its
OpenInVM, OpenURL and clipboard asks). The hub sets one up while it
is managed (in p00, named `ai-hub-…`); then one command, `qmcp project firewall
NAME --model-qube QUBE` (or `--model-qube` on `project create` and `project
lead`), does the rest, in the order that fails toward less authority: the
slot's model badge comes off any other qube, the lead loses its network, the
qube leaves p00, loses its network, is guarded and is killed if it runs, the
record names it, and only then does it wear the slot's model badge. The kill
spares only a qube that is already a guarded model qube, of this project or
another, whose leads may be using it; otherwise no process started in it
before, the hub's included, runs on. A power state that cannot be read is never
taken for halted, and a kill that fails stops the command before the record and
the badge. The kill ends processes, not files: what the hub left in `/home`,
`/usr/local` or `/rw` (anywhere, in a StandaloneVM) stays, and whatever is set
to start from there runs at its next start, normally when its lead first
connects (see the residual risks). It
refuses a qube outside AI space (guard it
first, with no network or on an enrolled gateway: the command never brings a
qube into AI space, so neither can a hub proposal), a template, a disposable
template, a disposable, a gateway, the hub, a drop box, a lead, a member of
any project (a qube in p00 leaves p00) and a qube whose system comes from a
template the hub manages
(what runs in it comes from that template at every start).
`--model-qube none` takes the slot's model qube away. A project whose model is
a qube refuses `--rule` and `--accept-current`: its lead has no firewall to
set. The operator un-guards a model qube (`qmcp manage`) for a while when it
needs changes, and `qmcp check` warns until it is guarded again (`qmcp guard`
then kills it if it runs; guarding one already guarded kills nothing); to give it a
network, take it off its projects first (`--model-qube none`), since
`qmcp check` fails on a model qube with a network. **One
model qube may serve several projects, one badge each, and that is a path
between them**: Ollama's API has no login and lets any client create, copy and
delete models, so a hijacked lead can change the model another project's lead
uses, or pass it data. It is safe only behind an API filter that lets
inference calls through and nothing else; qmcp ships none, and the command and
the window say so whenever a model qube is shared. A model qube that serves
one project needs no filter. Several can share one copy of the server and the
weights if a guarded template holds both in its root filesystem (under `/opt`,
say: a qube based on a template has its own `/usr/local` and `/home`, never
the template's).

**Anonymous projects.** `qmcp project create --anonymous` (or the hub's
proposal, which the operator accepts) makes a project that must stay
anonymous, and dom0 keeps checking that it is:

- **What it is made of.** dom0 picks its label at random (eight lowercase
  letters and digits, a letter first) and names its lead `<prefix><label>-lead`:
  a Debian qube's hostname is its name, and qubesdb and every qrexec call tell
  an agent its real names anyway, so a name it leaks links to nothing. Its lead
  is only ever made fresh, from a TemplateVM outside AI space or guarded,
  never a clone or a promoted qube with a past. Its lead's network and every
  worker network are enrolled anonymising gateways (or none) that still sit on
  the network recorded for them; its approved templates are guarded. The
  operator may give it a private note. A qube may move into it, out of it or
  between two of them, with `--yes` after the command's warning: the qube has
  a past, what it holds and what it was used for come with it, and it may link
  the projects it has been in; out of a hidden project, the move hands the hub
  its contents. The gate judges the project a qube goes into, and in
  anonymous mode the hub, as the move would leave them, and the move is
  refused if the project would be unsound, or if the hub's check would stop
  more qubes or the moved qube itself; a stopped qube does not move. A qube
  moved in wears the project's anonymous badges before its slot badge, and the
  hidden badge comes off last. Its model qube serves it alone.
  `project create`, `edit`, `lead` and `firewall` refuse what they can see
  would break it (a network, a template's guard, the lead's source, a shared
  model qube); whatever else breaks it, such as where a template's updates go,
  the gate stops right after the command.
- **Hidden or visible**, fixed at creation. A hidden one (the default) is not
  the hub's: every qube of it wears `qmcp-hubblind`: its lead and workers from
  birth, before `ai-managed`; its dump sink from creation; its model qube once
  it is guarded, before its model badge; and its approved disposable templates
  from when they are approved, so a disposable made from one after that, which
  Qubes gives its template's tags, is hidden from its first moment, a
  preloaded one included; the rulebook
  refuses the hub every call into one; the services leave it out of the hub's
  lists, reads, events and project rows, and answer the hub about one of its
  qubes exactly as about a name that does not exist, after the same single
  qubesd call; and a proposal that names it fails at accept as one naming a
  project that does not exist. The hub may still propose
  creating one: such a proposal carries no label and no lead name, takes the
  second tick, and the hub is never told what was created. A visible one is
  hidden from the network, not from the hub, which operates it like any other
  project.
- **The gate** (`qmcp gate`; `dom0/qmcp/anon.py`). For each anonymous project:
  1. *networks*: its listed networks and its lead's are anonymising gateways
     still on their recorded network, each member is on a listed network, or
     on none, and dom0's policy gives neither the lead nor any member
     `qubes.UpdatesProxy`, an HTTP proxy around its router;
  2. *model*: a self-hosted model qube has no network, serves this project
     alone, is guarded, and dom0's policy denies it `qubes.UpdatesProxy` (a qube wearing Whonix's
     `whonix-updatevm` is given the proxy even as an AppVM); a remote endpoint
     needs nothing more;
  3. *templates*: every template its qubes come from (the approved list, and
     the chains of its lead, members and model qube) is guarded or outside AI
     space; a TemplateVM has no network of its own, and dom0's policy sends its
     `qubes.UpdatesProxy` to the recorded upstream of an enrolled anonymising
     gateway that the operator ticked for updates, the qube directly above one
     (`sys-whonix` above a Tor router), never a qube further up the chain and
     never a dialog; updates denied outright leak nothing; a disposable template's network, which its
     disposables use, is one of the project's networks or none, and a hidden
     project's wears `qmcp-hubblind`;
  4. *badges*: every qube wearing the project's member or lead badge (which
     the rulebook routes on) is in AI space and wears the project's badges, so
     a member taken out of AI space by hand is still judged; and a hidden
     project's model qube wears `qmcp-hubblind`.

  The update question is asked with qrexec's own policy parser over the policy
  directory and qubesd's system information, as the policy daemon asks it (its
  own evaluation service answers allow or deny, never the target); both work
  for the services' non-root user. A stopped qube is asked about as if it were
  not stopped: the rulebook denies a stopped qube its updates too, and the
  question is where they go once the stop is cleared. The parser's warnings are silenced, or a run
  every 15 seconds would fill the journal.
- **When it runs**: every 15 seconds and 10 seconds after boot
  (`qmcp-gate.timer`, as a dom0 user in `qubes`, normally the one the services
  run as, never root: a root process cannot reach the operator's desktop to
  notify it), on `qmcp check`,
  and after every `qmcp` command that changes qubes, projects or gateways (each
  that leaves an operator audit line, and `proposal accept`). One run at a time
  (`/run/qmcp/gate.lock`, declared in tmpfiles); a run that cannot have the
  lock judges nothing and says so (`qmcp gate` exits 3; after a command, a line
  saying the timer will), and the unit stops a run that hangs after 60 s. Each completed run of the timer's touches
  `/run/qmcp/gate.last`, and `qmcp check` fails while an anonymous project
  exists, or anonymous mode is on, and that is more than 60 s old: a check or a window refresh runs the
  gate too, but only the timer's runs prove the timer. The services do not run
  it on each call; they refuse a lead that wears `qmcp-blocked`. The boot run
  is not ordered before Qubes' own autostart, so a qube marked to start at
  boot may run for those seconds first: mark no anonymous qube to start at
  boot.
- **On a violation** it acts in passes, so no qube is killed while another
  can still act: first `qmcp-blocked` on every lead and member, the lead
  first (the rulebook refuses every call into a blocked qube, so qrexec cannot
  wake one, and every call from one, so one the operator starts by hand
  reaches no other qube and no dom0 service, though it keeps its network; and the services refuse to start, change or clone one, checking
  again right before a start); then each one not yet stopped is killed unless
  it reads halted, and badged `qmcp-stopped` once it is known to be down (a
  power state that cannot be read is no halt: the kill is tried, and a qube not
  known to be down is tried again on the next run); then their `autostart` is
  turned off. One audit line says what was done, and the operator is told: a
  desktop notification from the timer's run, or a line on the command's output
  when a `qmcp` command's own run acted (a root process cannot reach the
  desktop). A run that changes nothing and repeats no failed step says
  nothing; one that repeats a failed step (a kill, a badge) says so again. It removes nothing: every qube and its data stay as they were. A
  qube already stopped (`qmcp-stopped`) is not killed again: only the operator
  can start one, by hand, to look at it. A read the gate cannot make is tried
  once more; a second failure blocks the project without killing it, and a
  later confirmed violation still kills it. A qube whose tags cannot be read
  makes the run unable to judge any project, since it may be a member. `qmcp
  project unblock NAME`, holding the gate, takes both badges off once a fresh
  run finds the project sound; `autostart` stays off.
- **Gateways.** Enrolling a gateway as anonymising, or marking it so later,
  records its network then (`upstream` in `gateways.json`); marking it again
  records a new one after it moved. One with no network of its own cannot be
  marked, and unmarking one an anonymous project uses is refused. An entry
  written before 0.9.23 has no recorded network and carries no anonymous
  project until it is marked again. **The updates tick** (`--updates`,
  `updates` in `gateways.json`) is the operator's word that the recorded
  upstream carries templates' updates anonymously: the qube above a plain
  router in front of `sys-whonix` or a VPN qube is the anonymiser itself, but
  the qube above a VPN qube enrolled with no router in front is
  `sys-firewall`, and dom0 cannot tell the two apart. Only a ticked upstream
  counts for condition 3. Marking a gateway again keeps the tick only on the
  same network; taking it off is refused where the gate would then stop a
  project or the hub. An entry written before 0.9.24 is unticked.
- **Anonymous mode** (`install.sh --anonymous`, `/etc/qmcp/mode`). Every
  project is anonymous: `project create` makes one without `--anonymous` and
  refuses a label, and the hub's proposal for an ordinary one is refused when
  it is submitted. No clearnet gateway is enrolled. The hub, every qube under
  the hub's check (below) and every anonymous project's lead, member and model
  qube wear `qmcp-anon`, so the rulebook's OpenURL and OpenInVM denies cover them: dom0 puts it on the hub and on every qube under the
  hub's check at install (and again on an update in the mode), the services on every qube the hub creates, `manage`
  and `guard` on a qube joining AI space (not a gateway) before
  `ai-managed`; a disposable gets it from its template.
  The gate judges the hub as one more subject: the hub qube, and every qube in
  AI space or wearing p00's badge that is not an anonymous project's lead,
  member or model qube, but a guarded router (an enrolled gateway, or
  another qube that provides network, wearing `qmcp-guarded`), which nothing
  in AI space operates; an unguarded one is judged, since the rulebook cannot
  see `provides_network` and the hub may run commands in it. Each wears
  `qmcp-anon`; each that is not a TemplateVM is
  on an enrolled anonymising gateway still on its recorded network, or on
  none, and dom0's policy gives it no `qubes.UpdatesProxy`; each TemplateVM
  it judges or that a subject comes from has no network of its own and sends
  its updates only to a ticked upstream (a template the hub manages may stay
  managed: building templates is the hub's work), and a disposable template a
  subject comes from is on an anonymising gateway still on its recorded
  network, or on none. The hub's own
  templates reach the network only through Qubes' update proxy, so this is
  where "updates over Tor" is checked for them. A violation by the hub or a
  p00 qube blocks and kills the hub, every p00 qube and every other
  offender; one by any other subject, that qube alone: the block refuses the hub every use of it, a call
  into it, a start, a clone and a create from it (the services refuse a
  stopped qube as a template to create from). In the mode the hub's create is
  also refused on a router no longer on its recorded network, and the
  services refuse a stopped hub, as they refuse a stopped lead.
  A mode file that does not read blocks the hub and p00 without a kill, and
  every command or service whose answer depends on the mode refuses. `qmcp
  project unblock p00` clears the hub's stop once a fresh run finds it sound.
  The installer refuses the mode while an ordinary project exists, a clearnet
  gateway is enrolled, or the gate would stop the hub; it lists every qube
  already in AI space that the hub's check will cover, each with a past, and,
  after the policy, stamps them, writes the mode file and stamps once more. No
  qmcp command turns it off; `uninstall.sh --purge` does. qmcp cannot check whose account the
  hub's model uses, nor what the hub qube did before the mode.

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
accepts, a slot can hold a project the proposal was not about. Seven kinds:

| Type | The command it is the options of |
|---|---|
| `project-create` | `qmcp project create`: the label, where the lead comes from (`template`, `clone` or `promote`), its network, name and model (an endpoint or a model qube), more approved templates, the worker networks, the quota, a dump sink or not |
| `project-edit` | `qmcp project edit`, but as changes: templates and worker networks to add or remove, a new default network, a new quota |
| `project-dump` | `qmcp project dump` |
| `project-lead` | `qmcp project lead`: remove the lead, or a new one (with its model: an endpoint, a model qube or none), saying whether the old lead stays as a worker or is removed (there is no default), and whether a kept old lead's network joins the worker networks |
| `project-firewall` | `qmcp project firewall`: a new model endpoint for the lead (its firewall becomes that endpoint, and DNS for a host name), a model qube or none, or exactly these rules |
| `project-delete` | `qmcp project delete --yes` |
| `qube-open` | `qmcp open`: the guarded qube, how long the window lasts, and whether the firewall half comes with it. It always needs the second tick; only the operator opens a window, and the hub can never put the badges on itself |

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
  gives the project a different model endpoint; every change to a lead's firewall, which
  `show` gives as the old model, accepted and live rules beside the new ones;
  and anything that makes a qube a model qube or takes one away (it touches a
  guarded qube and takes the lead's network), naming any other project the
  model qube already serves with what sharing one means; and every `qube-open`
  proposal, always, since it opens a guarded qube — the reasons name the qube,
  how long, the firewall half when it is asked for, and that sealing kills the
  qube. A lead whose badges cannot be read counts as one that will be
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
| dom0 | `/usr/local/lib/qmcp/qmcp/` (the library), `/etc/qubes-rpc/qmcp.*` (one shim under each service name), `/usr/local/bin/qmcp` (the operator's command), `/usr/local/bin/qmcp-gui` and its menu entry (the operator's window), the policy, `/etc/qmcp/` (operator files, `projects.json` among them), `/var/lib/qmcp/proposals/` (the hub's proposals and their decisions), `/run/qmcp/` (lock files, and `open/`: a record per open guarded qube, cleared by every boot). |
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
| `qmcp.ListAIManagedQubes` | AI space (for the hub, but hidden anonymous projects): name, class, label, template (redacted if out of scope), power state, `guarded`, `slot` and `lead`. A qube whose tags or class cannot be read is left out; a label or template that cannot be read is `<unreadable>`, and a power state that cannot be read `NA` (qubesadmin's word for it) or `unknown`. |
| `qmcp.GetPropertyAIManaged` | One property of a managed or guarded qube. Only properties qubesd lists; references out of scope redacted, and so are the netvm's addresses (`visible_gateway`, `dns`, …) when the netvm is out of scope, and refused when it cannot be read; an enrolled gateway is named (for a lead, one of its worker networks); `tags` filtered to `ai-managed` and `qmcp-guarded`, and refused when they cannot be read. |
| `qmcp.SetPropertyAIManaged` | `label`, `memory`, `maxmem`, `vcpus`, and `netvm` only to null. Everything else (`template`, `name`, `default_dispvm`, `provides_network`, …) is operator-only. |
| `qmcp.SetFeatureAIManaged` | Allowlist: `service.*`, `vm-config.*`, `menu-items`, `default-menu-items`. Every other key, including any a future Qubes adds, is operator-only. |
| `qmcp.LifecycleAIManaged` | start, shutdown, kill, pause, unpause, remove. Remove is a real remove; removing a lead is the operator's. |
| `qmcp.SpawnAIManagedQube` | AppVM or DispVMTemplate from a TemplateVM, or a named DispVM from a disposable template. The template may be managed or guarded, but not one that provides network. A lead spawns AppVMs and DispVMs from its approved templates only. |
| `qmcp.CloneAIManagedQube` | Clone a managed qube, templates included. A guarded source is refused: a clone is a managed, editable copy of everything in it. |
| `qmcp.SpawnDisposableAIManaged` | A disposable from a managed or guarded disposable template, born managed. Uses Qubes 4.3's preloaded disposables when the template has `preload-dispvm-max` (measured: a `qubes_run_disposable` cycle took 1.5 s with `preload-dispvm-max=1`, about 8 s without). |
| `qmcp.AIManagedEvents` | The hub only. A window of admin events (1–120 s) whose subject is in AI space and not of a hidden anonymous project; at most 16 filters of at most 64 characters. Tag events surface only for the two visible badges. |
| `qmcp.GetPoolStats` | `ai_managed_bytes_used`, `_cap` and `_headroom`, and `name_prefix`, the prefix the caller's new names carry (the hub's `ai-hub-`, a lead's `ai-<label>-`): for the hub, AI space against the operator's cap, `reserved_prefix` (the bare prefix a project's names build on), and every project's record but a hidden anonymous one's (slot, label, lead, templates, worker networks, quota, disk used, whether it is anonymous, and whether it has a dump sink, never the sink's name, which is outside AI space; a recorded name that has left AI space reads `<out-of-scope>`, unless it is an enrolled gateway; null when the records cannot be read), each project's model (`model`, an endpoint, or `model_qube`), and the gateway registry (`gateways`: name, anonymising, label; null when it cannot be read); for a lead, its workers against its quota, with its project's label, approved templates, worker networks, dump sink, model (`model`, or `model_qube` with `model_port`, 11434), and whether it is anonymous and whether the hub sees it (`anonymous`, `hub_sees`). A lead never sees the fleet's figures. |
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
space, so the order matters. The hard denies come first, with the leads' model
lines among them, above the guarded deny. Then come the lines that let leads
and members do what AI space otherwise may not. Then come the rest of AI
space's denies.

- **A. Hard denies, first, and the leads' model lines above the guarded deny.**
  - A0: nothing reaches a qube the anonymity gate stopped (`qmcp-blocked`), by
    any service, so qrexec can never wake it (dom0 starts it by hand, which no
    rule governs), and one started by hand reaches no other qube and no dom0
    service (it keeps its network); the
    hub reaches no qube of a hidden anonymous project
    (`qmcp-hubblind`), by any service; and an anonymous project's qube opens no
    URL or file in another qube, not even through a dialog, since that qube's
    traffic leaves outside its router.
  - A1: Qubes' raw disposable shortcut is closed for AI space. A `@dispvm` rule
    target matches only the bare keyword, so a second rule works from the
    template's side: `@dispvm:@tag:ai-managed`, any source, any form.
  - A2: no command execution from AI space into another qube, whatever form
    the target takes.
  - A3: AI space never reaches the hub, by any service.
  - A4: nothing in AI space reaches a lead, by any service: not its workers,
    not another project, not another lead.
  - A5: a drop box (`ai-dump`) never reaches back into AI space, by any
    service, even by dialog. It sits above the project lines so no slot line
    can let a sink in.
  - A6: a lead reaches its own slot's model qube (`qmcp-model-pNN`) through
    `qubes.ConnectTCP` on port 11434, one line per project slot. A model qube
    is guarded, so these lines sort above A7; they sort below A3, A4 and a
    ConnectTCP deny into drop boxes, so a model badge on the hub, a lead or a
    sink still opens nothing.
  - A6b: the operator's open window. `qmcp open` puts `qmcp-open` on one
    guarded qube, and these lines are the window: the hub runs commands in it,
    and copies a file in with Qubes' own copy, which asks the operator to
    confirm each one. With `--firewall` the second badge `qmcp-open-fw` adds
    the two firewall writes; reading the rules is not here, because A7 never
    denied it. The source is the hub alone, so nothing here widens what a lead
    reaches, and the lines sort below A0 — a qube the gate stopped and a hidden
    project's stay unreachable however they are badged — and above A7, which
    they exist to except. These badges are the only gate those services have:
    the exec service runs inside the target qube, the copy is Qubes' and the
    firewall methods are qubesd's, so no dom0 code sees the calls and none can
    read an expiry. dom0 takes the badges off when the window ends, and at
    every boot before any user session exists. Only dom0 writes them: H
    refuses the hub every dom0 service its own lines do not name,
    `admin.vm.tag.Set` included, so the hub may ask for a window with a
    proposal and can never open one.
  - A7: the hub cannot run, copy or write firewall rules in a guarded qube (it
    may read its firewall), and nothing from AI space reaches a guarded qube by
    any service, but a lead its model qube through A6 and the hub an open qube
    through A6b.
  - A8: the hub cannot write a lead's firewall (it may read it): a lead's
    firewall is the operator's.
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
  - D4: no TCP connection from AI space into another qube through
    `qubes.ConnectTCP`, but a lead's into its model qube (A6). Qubes' own
    default file refuses it too; this makes the refusal ours.
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
checks that every slot has exactly its own block and no line crosses a slot,
and that the model lines sit between the denies that guard them.

## The operator's command (dom0)

| Command | |
|---|---|
| `qmcp check [--json]` | Fails on: the hub missing, in AI space, or named differently in the policy; tier tags; a gateway in AI space without `qmcp-guarded`; a drop box in AI space; the policy modified, refused by qrexec's parser, or overridden by an earlier file for any of its 47 checked claims; a gateway registry that does not read, or an enrolled gateway that no longer qualifies; a qube in AI space (not a gateway itself) on a network that is not enrolled; a lead with a network whose firewall differs from the rules the operator accepted; services, runtime directory or caps missing; no `qubes` group; a runtime directory, create lock, proposal lock or audit log the services cannot write, that is, not group-writable or not the `qubes` group's (an audit log missing, since they cannot create one), or `/run/qmcp` not setgid; the proposal store missing, or not the `qubes` group's, group-writable and setgid; a guarded qube wearing an open badge with no window record, an expired one or one that does not read, wearing `qmcp-open-fw` without `qmcp-open`, or wearing either where `qmcp open` would refuse it (a gateway above all, which the rulebook cannot tell from any other guarded qube); a broken audit chain; v0.9.16 leftovers; unreadable project records; a member or lead badge outside AI space, a sink inside it; a qube in two slots; a slot badge with no project; a template or gateway in a project; a lead whose badges and record disagree, or any qube wearing lead badges that is not its slot's recorded lead; a sink that is not its record's; a lead whose project's model is a qube but which has a network; a model badge on a qube with a network, outside AI space, on a member, lead, template, disposable, gateway, drop box or the hub, in p00, on a qube whose template the hub manages, or that its slot's record does not name; a mode file that does not read, and in anonymous mode a project that is not anonymous or a gateway that is not anonymising; an anonymous project, or in anonymous mode the hub, that the gate finds unsound (it runs the gate, and acts on what it finds), and, while an anonymous project exists or the mode is on, the gate's timer not running or no run of it completed in the last 60 s; the gate's lock or heartbeat file missing or not the services group's to write. Warns on a guarded qube that is open, with the time it has left — the window is your own deliberate exception and it clears itself, so it is amber and not red; a stopped anonymous project that is sound again, a hidden project sharing an anonymising router with another project or the hub, `qmcp-anon`, `qmcp-blocked` or `qmcp-stopped` where neither an anonymous project nor anonymous mode puts them, a missing `projects.json`, stray badges, v0.9.16 tombstones, qubes outside AI space inside the name prefix, any qube in a project's names that is not its lead or member, managed qubes pointing at a disposable template outside it, a birth-egress qube that is not enrolled, a lead with a network and no accepted firewall, a lead whose endpoint is an address and whose accepted rules still hold the DNS rule set before 0.9.22, a model qube that is not guarded, a recorded model qube that is gone or does not wear its badge, an audit log due for rotation, a project without a lead, an approved template that is not one, a worker network that is not enrolled, a member on a network off its project's list, a sink with a network, managed AppVMs in no slot, project quotas that add up to more than the pool cap, and a proposal that cannot be read or whose accept never finished. Reports an error for each read it could not make: a qube's tags, network, role, class, template or default disposable template, a gateway's `qubes-firewall` feature, a lead's firewall; and for a gate run that could not run, or found the gate's lock held past its wait. A qube whose tags cannot be read is skipped by the items that judge tags, the registry item included (the "qube tags" error names it). So is one qubesd says is gone when its tags are read, except an enrolled gateway: the registry item reports that one. Exit 0 GREEN, 1 FAILED, 3 INCOMPLETE — INCOMPLETE is not green. |
| `qmcp list [--all] [--json]` | AI space with state, class, template, network, power, slot and provenance. A state, class, template, network, slot or provenance that cannot be read is `<unreadable>`, and a power state `NA` or `unknown`; a qube whose tags cannot be read is still listed, and one qubesd says is gone is not. With `--json`, each row adds the lead flag, the slots it serves as a model qube, whether the qube provides network and whether it is a disposable template (each `<unreadable>` when it cannot be read), and its badges (`null` when its tags cannot be read). `--all` adds every other qube but dom0, with no state. |
| `qmcp settings [--json]` | The operator files the services read (hub, name prefix, pool and private caps, birth egress), how many gateways are enrolled, the disk AI space uses, the mode (`anonymous`, `normal`, or `<unreadable>`), and the version. |
| `qmcp gateway list [--json]` | The gateway registry: each entry, whether it is still usable and why not, its upstream (marked when that is a Whonix gateway, whose clients' firewall rules have no effect), and the qubes and projects that use it. |
| `qmcp gateway enroll QUBE [--anonymising [--updates]] [--label TEXT]` / `set QUBE [--anonymising yes\|no] [--updates yes\|no] [--label TEXT]` / `remove QUBE` | Let AI space use a gateway, change its entry, stop AI space using it. Marking one anonymising records its network as it is then; one with no network is refused, and unmarking one an anonymous project uses is refused. `--updates` ticks it for templates' updates (see "Anonymous projects"); marking it again keeps the tick only on the same network, and taking the tick off is refused where the gate would then stop a project or the hub. In anonymous mode a gateway that is not anonymising is refused, and so is unmarking one. Enrolling refuses a qube that does not provide network, lacks Qubes' `qubes-firewall` marker, is a Whonix gateway, sits on a template the hub manages, is the hub, a drop box, a lead or a member, or is in AI space unguarded; removing refuses while a project lists it or a qube in AI space sits on it, and, for a gateway ticked for updates, where the gate would then stop a project or the hub. Root. |
| `qmcp manage QUBE` / `qmcp guard QUBE` | The role actions. Both refuse the hub, a drop box, and a qube (other than a gateway) on a network that is not enrolled; `manage` also refuses a gateway; `guard` refuses a lead or a member. Guarding a model qube that was managed kills it if it runs (never a gateway or a template, whatever badge it wears); a kind that cannot be read stops only the kill, and the command says so and exits 1. In anonymous mode both put `qmcp-anon` on a qube joining AI space (not a gateway) before `ai-managed`. |
| `qmcp revoke QUBE` | Strips every qmcp badge, pins `default_dispvm` to none, shuts the qube down. Refuses a lead. |
| `qmcp open QUBE --for DURATION [--firewall]` | Open a guarded qube to the hub for a bounded time: `qmcp-open` lets the hub run commands in it and copy a file in (Qubes asks you to confirm each file), and `--firewall` adds `qmcp-open-fw`, which lets it write that qube's firewall rules. It can never change the qube's network. `DURATION` is `90s`, `30m` or `2h`, at most 24h; there is no indefinite window, which is `qmcp manage`. Refuses a gateway (its egress rules are AI space's), a managed qube (it needs no window), a lead or a member, a qube the anonymity gate stopped or a hidden project's, and anything outside AI space. Opening a qube that is open replaces its window, and drops the firewall half when this call did not ask for it. The window's end is recorded under `/run/qmcp/open/`, which a reboot clears. |
| `qmcp seal QUBE` / `--expired` / `--all` | Close a window. Named: the badges come off, the record goes, and the qube is KILLED if it runs, so nothing the hub started in it runs on — a package manager stopped part-way may leave the qube needing repair, and its files stay. A qube that was not open is left alone and says so. `--expired` seals every window that has run out, whose record does not read, or that sits on a qube `qmcp open` refuses (the gate's timer runs it every 15 s); `--all` seals every one whatever its record says (`qmcp-seal.service` runs it at every boot). Exit 0, or 3 when something could not be judged, never 1. |
| `qmcp project list` / `show NAME` | The slots in use; one project's record. |
| `qmcp project create [LABEL] ...` | A new project in the lowest free slot; with `--anonymous` (and `--hub-sees` for a visible one, `--note TEXT` for a private note) an anonymous project, whose label dom0 picks (see "Anonymous projects"); in anonymous mode every project is one, without `--anonymous`, and a LABEL is refused: `--lead-template T`, `--lead-clone QUBE` or `--lead-promote QUBE`; `--lead-netvm` (an enrolled gateway, or none); `--model HOST:PORT` (needed for a lead with a network: its firewall allows only that, and DNS for a host name) or `--model-qube QUBE` (a self-hosted model qube; the lead then has no network); `--template` (more approved templates; the lead's own goes first when it is in AI space); `--network QUBE` or `none` (enrolled gateways), the first the default; `--quota`; `--dump`. |
| `qmcp project edit NAME ...` | Replace the approved templates or the worker networks, or change the quota. Workers keep their networks, so a network a member sits on cannot be taken off the list. |
| `qmcp project lead NAME --remove` / `--lead-…` | Remove the lead (the project keeps its workers), or give the project a new one, with `--model` (else the project's, for a new lead with a network; a remote model takes the project's model qube away first), or `--model-qube QUBE` (the new lead then has no network), or `--model-qube none` (takes the project's model qube away); with neither, a new lead with no network keeps the project's model qube; `--keep-old` keeps the old lead as a worker, on its network if the project lists it, otherwise with none unless `--add-old-network` adds that network to the list. |
| `qmcp project firewall NAME [--json]` | The lead's model (an endpoint or a model qube), the firewall rules the operator accepted and its live ones. With `--model HOST:PORT`, `--model-qube QUBE\|none`, `--rule RULE` (repeatable) or `--accept-current`, set a new model endpoint (for a lead with a network; its firewall becomes that endpoint, and DNS for a host name; refused while the model is a qube), a model qube (see "Model qubes") or none, exactly these rules, or accept the live rules as they are, if they are in qmcp's rule format (no comment or expire, at most 32). A write that does not read back as set is undone. Each change needs root. |
| `qmcp project dump NAME` | Create a dump sink for a project, or for p00 (`hub-dump`). |
| `qmcp project unblock NAME` | Clear the anonymity gate's stop once a fresh run finds the project sound; `autostart` stays off. `p00` (or `hub`): the hub's stop, and every qube under the hub's check, once the gate finds the hub sound; in normal mode it takes off what anonymous mode left. Root. |
| `qmcp gate [--json]` | Judge every anonymous project now, and in anonymous mode the hub (its verdict has `hub` and `offenders`), and stop what is not sound (the timer runs this). Prints only what is not sound and what it did, unless `--json`. Exit 0 all sound, 1 one is not, 3 one could not be judged. Runs as any member of `qubes`. |
| `qmcp project move QUBE TARGET` | Move a managed AppVM into p00, a project, or no slot. Its network does not change, so a project takes it only on one of its worker networks; out of one slot into another needs `--yes`, and so does a move into, out of or between anonymous projects, which says first what the qube carries with it. A move is refused if the anonymous project it goes into would be unsound or, in anonymous mode, if the hub's check would stop more qubes or the moved qube itself. A qube the gate stopped does not move. |
| `qmcp project delete NAME --yes` | Remove the lead and every member, keep the dump sink and the model qube without the slot's badge, strip every badge of the slot, free it. Given a slot with no record, finish a delete that stopped half-way. Without `--yes` it prints what it would remove and changes nothing; that needs no root. |
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
  no slot, each project with its lead, workers, sink and model qube, then
  templates, gateways, model qubes, other guarded qubes, and Needs attention. A
  qube's place comes from the badges the rulebook routes on, never its label
  colour, which the hub may set. A model qube has one row, under Model qubes,
  naming the projects it serves, and each of them a row pointing to it; a
  shared one says so, with what sharing means. Needs attention holds the qubes
  whose badges the rulebook acts on against the records: lead badges the
  records do not back, a gateway without `qmcp-guarded` (Guard is offered
  there), a drop box or the hub inside AI space, slot badges outside it, a qube
  in two slots, a template in a project, a model badge on a template, gateway,
  member or p00 qube, a model badge no record names, a model qube with a
  network or on a template the hub manages, and a lead with a network whose
  project's model is a qube; and a qube whose tags, class or role could not be
  read, which offers nothing.
  Every other failure of `qmcp check` is on the Check tab. Beside the tree, the
  selection's every field, and the actions that fit it. The light is
  `qmcp check`'s result with the time it ran; the Check tab lists its findings,
  failures first. The Audit tab shows the last 200 lines, newest first, the
  selected one in full, and verifies or rotates the chain. It holds the calls
  the hub and the leads make to state-changing services, every command of the
  operator's that changes something (caller `operator`, accepting and
  rejecting proposals included), and the line each rotation starts a log with,
  which names the file the earlier lines moved to. The Settings tab shows
  `qmcp settings`, read-only, the mode included. The Gateways tab lists the gateway registry:
  each gateway's upstream, how many qubes in AI space use it and which projects
  list it, and every field of the selected one. A gateway that no longer
  qualifies, or whose upstream ignores its clients' firewall rules (a Whonix
  gateway), says so on its row; so does an anonymising one that sits elsewhere
  than its recorded network, or has none recorded. The Anonymity tab lists
  every anonymous project with the gate's verdict: hidden or visible, the
  private note, whether it is stopped, and each failing condition with its
  detail; a project the gate did not judge says so, never vanishes. In
  anonymous mode it lists the hub's verdict too, with the qubes in violation. In the
  tree, an anonymous project's row and its qubes are marked anonymous, hidden
  from the hub, blocked or stopped, from their badges; its details add its
  kind, note, gate status and, for a hidden one, any router it shares. Selecting a project or its lead also reads
  `qmcp project firewall NAME --json`: the lead's model (an endpoint or a model
  qube), the rules you accepted, the live ones, and whether they are the same.
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
  enroll, change and remove gateways, set a lead's model endpoint, model qube
  or rules or accept its live rules, and rotate the audit log. The forms offer as a
  network none and the enrolled gateways (a lead's may also be left unset);
  one that no longer qualifies is listed and marked, and choosing it is
  refused, as the command refuses it, and the edit form also lists the
  project's current networks that are not enrolled, marked, so they can be
  taken off. A lead's model is a remote endpoint or a self-hosted model qube:
  choosing a model qube sets the lead's network to none and greys it out. The
  model-qube choices are the qubes the command would take, in AI space, and a
  form that takes a lead's network away for one says so in red before OK, as
  does one whose model qube already serves another project, with what sharing
  means. A lead with a network needs its model endpoint (a new lead of a
  project takes the project's), and Set lead model is off for a lead with no
  network, or one whose network cannot be read; for a project whose model is a
  qube, Set lead model, Set lead rules and Accept current rules are off, with
  the command's reason, and Set model qube changes or takes away the qube. The model and rules forms show the rules accepted now, live now and
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
  OK removes a qube says so in red first. *New project* has an Anonymous tick:
  it greys out the label (dom0 picks it), fixes the lead to a fresh template
  and greys out its name, and enables "the hub may see it" and a private
  note; the networks and templates are refused as the command refuses them,
  and a hidden one shows in red that a template or model qube the hub operated
  before it was guarded can harm it, and any router it would share with
  another project or the hub. The model-qube form, and a lead change that picks
  a model qube, show that warning for a hidden project too. Unblock, on a
  stopped project or its qubes and on the Anonymity tab, runs `qmcp project
  unblock`; its OK stays off, with the gate's reason, until the gate finds the
  project sound; on the hub's verdict it runs `qmcp project unblock p00`.
  Change gateway can mark a router anonymising again, which records its
  network now; Enroll and Change gateway have the updates tick. In anonymous
  mode *New project*'s Anonymous tick is on and stays on, and the gateway
  forms refuse a gateway that is not anonymising. Move offers the anonymous
  projects, marked, and shows the command's warning in red before its tick.
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
- **A guarded qube's window** is an Open form (how long, from a list of
  durations the command accepts, and a tick for the firewall half) and a Seal
  confirmation, whose red line says the qube is killed and a part-finished
  install interrupted. The details pane shows what is left of a window, or
  `sealed`. Both buttons come from the badges the rulebook routes on, so a
  qube wearing one shows Seal even where Open would have refused it. While any
  guarded qube is open the check light is amber and says so, though the check
  itself is GREEN: the Check tab and the details pane name the qube and its
  time, and the light is the one place the operator sees it without looking.
- **It refreshes** when it opens, after every change, and when you press
  Refresh; there is no timer, and the light says when the check last ran.
  Each refresh runs `qmcp gate --json` first, alone, and every other read
  after it, so what they show includes what the gate just did; a gate read
  that fails keeps the last verdicts on show and turns changes off, as any
  failed read does.
- **It cannot go stale.** `tests/test_gui.py` walks the command's parser and
  the fields of every read, and fails on any command, option or field the
  window neither offers nor exempts by name, with a reason. The exemptions
  today: `migrate` and `audit --path` (typed by hand), `seal --all` and
  `seal --expired` (run by the boot unit and the gate's timer, never by a
  person), and `project show` and `version`, which the window shows from other
  reads.
  `tests/GUI-CHECKLIST.md` is the click-through for a person.

## Install, migrate, uninstall

The installer runs as root in dom0, so the tree it runs from must come from
somewhere AI cannot write. A tree copied out of the hub is only as
trustworthy as the hub. Fetch a tagged release in a fresh disposable (any
disposable template with curl and network; Qubes' stock `default-dvm` has both):

```sh
# in dom0
qvm-run --dispvm=default-dvm --pass-io \
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.25.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh   # --hub, --birth-egress, --pool-cap, --private-cap, --gate-user, --anonymous, --updates-via, --dry-run
```

`install.sh` runs every preflight check before it changes anything: its options
must be well-formed, the fleet must be in the two-state shape, existing project
records and gateway registry must load, the rendered policy must parse on this box and decide
each of the 40 claims itself, and the gate, as this release judges, must not leave an anonymous
project, or (with `--anonymous` or in anonymous mode) the hub, stopped only for want of an updates
tick: the entry is named, with `--updates-via GATEWAY` to tick it in the same install. One unsound
for another reason is noted, except the hub when `--anonymous` turns the mode on, which is
refused. It removes what v0.9.16 installed, backs up what it
replaces under `/var/lib/qmcp-rollback/`, writes an empty
`/etc/qmcp/projects.json` if there is none, installs the anonymity
gate's timer (`qmcp-gate.timer`, as `--gate-user` if given, else the dom0 user
who ran it with sudo, else the `qubes` group's only member; it refuses root and
a user outside `qubes`), keeping it stopped while it changes things (after a
run already going has finished; a `qmcp` command run meanwhile still runs the
gate) and starting it again at the end (also when it fails part-way, so
anonymous projects stay judged over whatever it left), installs the boot
seal (`qmcp-seal.service`, enabled, with a drop-in on Qubes' own
`qubes-vm@.service` so no autostart qube starts before it) and runs
`qmcp seal --all` once, before the new policy, so an install never leaves a
window open under lines that would honour it, installs the policy
after the code, with `--anonymous` then puts `qmcp-anon` on the hub and on every qube under its
check, writes `/etc/qmcp/mode` and puts it on once more, for a qube the hub
made meanwhile (an update in the mode puts it back where it is missing), runs
the gate once,
and exits with `qmcp check`'s status. It changes no other qube tag. `uninstall.sh` removes the policy first (so no AI
caller reaches a half-removed service), then everything else, and ends with a
clean-state check that names what it keeps; `--purge` also removes
`/etc/qmcp`, the proposal store `/var/lib/qmcp`, the audit log and its rotated
files, so it is also what turns anonymous mode off. Backups under
`/var/lib/qmcp-rollback/` are never removed, nor is `/var/log/qmcp-changes.log`,
the change history some older installers kept. Qubes keep their tags: after
anonymous mode, remove `qmcp-anon` from the hub, or `qmcp check` fails on it.

**From v0.9.23**: install. An anonymous project whose templates update
through an anonymising gateway's upstream needs that gateway ticked (0.9.24
counts only a ticked upstream): the installer names each one it would stop and
changes nothing; `--updates-via GATEWAY` ticks it in the same install. Tick
only a gateway whose upstream is the anonymiser itself (`sys-whonix`, a VPN
qube). Rolling back to 0.9.23 needs the tick off every gateway (0.9.23 refuses
`updates` in `gateways.json`), then this release's `uninstall.sh` (it keeps
`/etc/qmcp`) before 0.9.23's installer; an installation in anonymous mode
rolls back only through `uninstall.sh --purge`.

**From v0.9.22**: install, then see the v0.9.23 note for the tick on any
anonymising gateway you enroll. Nothing changes until you create an anonymous
project. To use one, enroll a plain router in front of `sys-whonix` (or a VPN
qube) as anonymising, or mark an enrolled one again
(`sudo qmcp gateway set NAME --anonymising yes`) so its network is recorded,
and send your templates' updates through the qube above it in Qubes' Global
Config (Updates: the default update qube, or a per-template exception).
Rolling back to 0.9.22 needs every anonymous project deleted first (0.9.22
refuses their records, and has neither the rulebook lines nor the services'
checks that keep the hub out of a hidden one), then `upstream` removed from
`gateways.json`, which 0.9.22 refuses too; then this release's `uninstall.sh`
(it keeps `/etc/qmcp`) before 0.9.22's installer, which would leave
`qmcp-gate.timer` running a command 0.9.22 does not have.

**From v0.9.21**: install; for anonymous projects, see the v0.9.22 note. A lead whose model endpoint is an address keeps the
DNS rule 0.9.21 gave it, which it does not need, until you set its model again
(`sudo qmcp project firewall NAME --model ADDRESS:PORT`); `qmcp check` warns
until you do. Our policy now refuses every `qubes.ConnectTCP` from AI space but
a lead's into its model qube, so a later policy file of yours that allowed one
no longer does. Nothing else changes until you set a model qube.

**From v0.9.20**: install, then enroll the routers AI space uses. The gateway
registry starts empty: until you enroll, no qube in AI space can be given a
network, and `qmcp check` fails on every one (gateways aside) that has one,
naming the command. A Whonix gateway cannot be enrolled: put AI qubes that sit
directly on `sys-whonix` on a router in front of it (`qvm-prefs QUBE netvm
ROUTER`), or clear their network. Then give the firewall of each lead with a
network its owner:
`sudo qmcp project firewall NAME --accept-current` accepts its current rules if
they are in qmcp's rule format (no comment or expire, at most 32), and
`--model HOST:PORT` replaces them with that endpoint, and DNS for a host name; `qmcp check`
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
| `tests/test_models.py` | anywhere with python3-qrexec | model qubes and model endpoints against the same fake: the one command and the order it changes authority in, each refusal, sharing, creates and lead changes, the check's findings, what the lead and the hub are told, the record, proposals, and the DNS rule an address endpoint no longer gets |
| `tests/test_anon.py` | anywhere with python3-qrexec | anonymous projects against the same fake, with dom0's update question asked of qrexec's real parser: each gate condition broken on its own from a sound project, the block in its order, a read that fails once and twice, unblock, hub-blind services answering as for a missing name (`test_dom0.py` pins the cost), the commands' refusals, and proposals |
| `tests/test_mode.py` | anywhere with python3-qrexec | anonymous mode against the same fake, with the update question asked of qrexec's real parser (and of our rulebook, for a stopped qube): the mode file, the updates tick, the hub's check and what each violation stops, unblock p00, the hub's creates and proposals in the mode, and moves into, out of and between anonymous projects |
| `tests/test_proposals.py` | anywhere with python3-qrexec | proposals against the same fake: who may submit, the shape, the store, the second tick, accepting and rejecting through the real commands, an accept that never finished, and the operator's audit lines |
| `tests/test_server.py` | anywhere | the MCP server and CLI against a fake qrexec client |
| `tests/test_gui.py` | anywhere; the widget tests where GTK 3 and a display exist | the operator's window, driving the real `qmcp` command against the same fake: the tree, the escaping, every form's command, and that no command, option or field is left out |
| `tests/seat_suite.py` | in the hub, on a real box | the tools through the real chain |
| `tests/redteam_suite.py` | in the hub, on a real box | attacks from the hub and from a managed qube, with positive controls; a probe that hangs on a dialog fails |
| `tests/project_suite.py` | in the hub, on a real box | carries the client and `tests/lead_seat.py` into a project's lead and runs it there: the lead's tools through the real chain, the lead's raw calls, probes as root from inside its workers, and, given the project's model qube, a question to the model through `qvm-connect-tcp` |

```sh
python3 -W error::DeprecationWarning -m unittest discover -s tests -p 'test_*.py'
```

`QMCP_POLICY_BASELINE=/etc/qubes/policy.d` runs the policy matrix against a
real dom0's policy set.

## Residual risks, accepted

- **A compromised hub controls all of AI space but hidden anonymous projects:** it
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
  which `qmcp check` lists), its approved templates, its worker networks and
  its model qube by name.
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
- **A model qube's maintenance window hands the hub its contents.** While it is
  managed, the hub may run commands in it as root. Guarding it again kills it,
  which ends the hub's processes, not its files: what the hub left in `/home`,
  `/usr/local` or `/rw` (anywhere, in a StandaloneVM) stays, and whatever is
  set to start from there runs at its next start. A hub call that qrexec allowed just
  before the guard landed can also start it once more after the kill, since
  qrexec starts a halted target after its decision; that gives the hub nothing
  those files do not. Rebuild a model qube you do not trust rather than guard
  it again.
- **A qube spawned from a guarded template carries that template's contents**
  (its root, and a disposable template's home directory), **and a disposable
  also carries its template's non-qmcp tags**, because Qubes copies them.
  Guarded protects a template from change, not its contents from what is
  spawned from it; keep authority-granting tags off disposable templates you
  guard.
- **Templates reach the network through Qubes' update proxy**, outside the AI
  network path. In anonymous mode the gate checks where every template the hub
  can reach sends its updates.
- **A hijacked lead can send data out through any of its workers that has a
  network** (it runs commands in them and sets their firewalls), whatever its
  own firewall says, and through DNS when its model endpoint is a host name.
  Its own firewall makes that traffic go through the qmcp services and the
  policy, rather than out of the lead. A project that must be sealed gets a
  self-hosted model, a lead with no network and workers on no network.
- **A model qube shared by several projects is a path between them.** Ollama's
  API has no login and lets any client create, copy and delete models, so a
  hijacked lead can change the model another project's lead uses, or pass it
  data. It is safe only behind an API filter that lets inference calls through
  and nothing else; qmcp ships none. A model qube that serves one project
  needs none.
- **A model qube keeps what was put on it before it was guarded.** The hub sets
  one up while it is managed; guarding stops the hub getting back in, but its
  own disk (`/home`, `/usr/local`, `/rw/config/rc.local`, which runs as root at
  every start) and the weights it downloaded stay as the hub left them. For a
  project the hub can already reach, that adds nothing; while the operator
  un-guards it for changes, the hub may operate it again, and `qmcp check`
  warns.
- **The anonymity gate cannot stop a packet that leaves before it runs.** A
  condition breaks by the operator's own change: one made with `qmcp` (`manage`
  on a template or model qube it uses, marking a moved router again) is judged
  right after the command; one made outside qmcp (re-pointing a router, giving
  a template a network, an update setting) within about 15 seconds; the kill stops
  what follows. Anonymity
  against network observers is not anonymity against the model provider,
  which sees all content and knows the account.
- **A hidden project is safe from the hub only if the hub never operated what
  it runs on.** A template or model qube the hub edited before it was guarded
  can harm it: guarding removes nothing the hub left there, and qmcp keeps no
  record of who operated a qube. The command and the window warn.
- **The hub can tell that a hidden project exists**: a slot missing from its
  list, the pool figure, which counts its disk, and its own proposal's
  `accepted`. Never its contents. Its names are random, and the services
  answer about them as about missing names; but the hub's dialog services
  (Filecopy, OpenInVM, OpenURL, the clipboard) are refused at once for a hidden
  name, where a missing one becomes `@default` and a dialog, so a hub that
  already guessed a name could tell. It cannot guess one: a label is eight
  random characters.
- **A visible anonymous project is hidden from the network, not from the hub.**
  A prompt injection that climbs worker, lead, hub can steer the hub into a
  clearnet project's qube to touch the same target from the operator's own
  address; the ladder and the agents' own guards are the defence. In
  anonymous mode there is no clearnet project to steer it into.
- **The updates tick is the operator's word.** A gateway ticked for updates
  whose upstream is in fact a clearnet qube (a VPN qube enrolled with no
  router in front has `sys-firewall` above it) lets template updates leave
  outside the anonymiser while the gate reads sound. Tick only an upstream
  that is the anonymiser itself; put a plain router in front of every
  anonymising qube, as for Tor.
- **Anonymous mode cannot check the hub's model account or the hub qube's
  past**, nor that of any qube already in AI space when the mode was turned
  on: the installer lists those, and the docs say so. It also leaves the hub
  its dialogs for copying files and the clipboard into other qubes: data, not
  a network path, and only by the operator's click.
- **A qube moved into an anonymous project has a past.** What it holds and
  what it was used for come with it, and it may link the projects it has been
  in; out of a hidden project, the move hands the hub its contents. The
  command and the window say so before the tick.
- **Projects behind one anonymising router share its exit**, so a destination
  can tie them together; the command and `qmcp check` warn for a hidden one,
  and a second router of the kind keeps them apart.
- **The gate's boot run is not ordered before Qubes' autostart**: a qube marked
  to start at boot may run a few seconds before it. Mark no anonymous qube to
  start at boot.
- **A model qube with a network would be a way out for its leads** (Ollama
  fetches a "model" from any host it is told to). The command removes its
  network, and `qmcp check` fails if it gets one back.
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
  guarded-qube denies (A7); `qmcp check` fails until it is guarded.
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
four: 0.9.21 the gateway registry and leads' firewalls; 0.9.22 self-hosted
model qubes reached over `qubes.ConnectTCP`; 0.9.23 anonymous projects, hidden
from the hub or visible to it, with a gate that stops a project whose path
stops being anonymous; 0.9.24 (this one) anonymous mode, in which every project
is anonymous and the hub is checked too. M4 runs the
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
                    proposals, gateways (the registry), firewall (a lead's), anon (the
                    anonymity gate), birth,
                    budget, scope, audit, fleet (check/migrate/roles/projects/
                    gateways), cli,
                    and the window: gui (GTK) over guimodel (what it decides, no GTK)
dom0/rpc/           qmcp-service, the one shim installed under every service name
dom0/bin/qmcp       the operator's command
dom0/bin/qmcp-gui   the operator's window
policy/             30-mcp-control.policy
template-rpc/       the two in-qube services
deploy/             install.sh, uninstall.sh, qmcp-tmpfiles.conf, qubes-mcp.desktop,
                    qmcp-gate.service and qmcp-gate.timer, qmcp-seal.service and
                    qubes-vm-qmcp-seal.conf (its drop-in on Qubes' autostart unit)
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
