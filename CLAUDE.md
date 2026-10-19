# qubes-mcp — design document

An MCP server that lets AI agents operate a scoped part of a Qubes OS machine.
It runs in one qube, the **hub** (`mcp-control`), and in each project's
**lead**. Agents reach it over stdio (usually through SSH) and call its tools.
Most tools call `qmcp.*` services in dom0, which decide everything about the
qubes they touch; running a command, copying a file out and reading or writing
a firewall go straight to the qube or the Admin API, decided by the qrexec
policy in dom0.

**This file describes the code at this version (0.9.36). Read it first in any
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
  `qmcp-stopped`, and the restore check may hold it (`qmcp-quarantine`); the
  check allows those four on it then. A lead is in AI space: the hub
  operates it, and every AI-space rule applies to it unless a line for leads
  deliberately sorts above that rule.
- **AI space is the tag `ai-managed`.** A qube outside it is invisible: every
  dom0 service answers a qube outside AI space exactly as it answers a qube that
  does not exist — the same reply, after the same qubesd calls, each read of a
  name followed by one of the other kind (qubesd answers a missing qube
  sooner than it reads an existing one's tags) — and
  reads redact any reference to one as `<out-of-scope>`, except an enrolled
  gateway, which the operator chose to name: the hub reads every one, with its
  flag, label and addresses, and a lead its own worker networks. A lead's
  `qmcp.GetPoolStats` also gives its own project's record as recorded: its
  dump sink, which is never in AI space, and its approved templates and worker
  networks. Several things still tell the hub whether another name exists: a
  create colliding with a name inside the reserved prefix; the outcome of a
  proposal the operator accepts, which tells the hub whether the names it used
  exist; its dialog services, which a deny refuses at once for a hidden
  project's qube, a qube held for review or one the gate stopped, where a
  missing name gets the dialog; and `@dispvm:<name>`, which Qubes refuses at
  once unless the name is a disposable template (see the residual risks).
- **Two states.** A qube in AI space is **managed** (the hub may operate it) or
  **guarded** (listed, read and used as a reference — spawned from — but never
  operated). Guarded means the tag `qmcp-guarded`, or providing network: a
  gateway is guarded whatever it carries, and nothing is spawned from one.
- **A guarded qube is sealed, and the operator may open it for a while.** Being
  guarded is a refusal, not a state the hub can change: the rulebook denies it
  every service into such a qube but reading its firewall rules and its dialog
  asks (OpenInVM, OpenURL and the clipboard), which you confirm. `qmcp open QUBE --for 2h` lifts part of that for
  one qube and one stretch of time — the hub may then run commands in it as
  root and copy a file in, which Qubes asks the operator to confirm one file at
  a time, and with `--firewall` write that qube's firewall rules as well. It
  can never change which network the qube is on. `qmcp seal QUBE` ends the
  window at once and kills the qube if it is running, so what the hub had
  running in it is stopped (the firewall rules it wrote through the window
  stay); a kill that fails is tried again by every pass of the
  gate's timer, and `qmcp check` fails until it is made. A dom0 timer ends a
  window that has run out, and every boot ends every window. A re-open whose
  badge write fails seals the window it was to replace, kill included. The hub may ask for a window with a proposal, which always
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
  command in dom0 is the operator's tool for changing badges and projects. The
  tags qmcp writes on its own are the stamp a create puts on the qube it just
  made, and those of dom0's own passes, which its timers, the boot unit, a
  check and each changing command run: the anonymity gate's `qmcp-blocked` and
  `qmcp-stopped`, the restore check's `qmcp-quarantine`, and the open badges
  taken off when a window ends.
- **A qube back from a backup waits for review.** dom0 labels every qube it
  brings into AI space, and every qube before one of its commands gives it a
  badge, with the feature `qmcp-id`, set to the qube's own UUID; neither the hub
  nor a lead can write that feature. A Qubes restore and `qvm-clone` give a qube
  a new UUID and keep its tags and features (measured on Qubes 4.3.1, for
  `qvm-clone`, a restore beside the original and one with the original gone),
  so a restored or hand-copied qube's label stops matching; a qube in AI space with
  no label counts the same (a disposable that Qubes makes itself and cleans up,
  from a labelled disposable template, carries the template's label and is not
  held). On its next pass, normally within about 15 seconds,
  the gate puts `qmcp-quarantine` on it: the rulebook refuses every qrexec call
  into and out of it, and the services refuse to operate it, create from it or
  take it as a principal (a create also refuses to copy or build on a qube in
AI space whose label is not its own, before the pass holds it, since its copy
would get a label of its own), until the operator accepts it (`qmcp restored
  accept`, which labels it) or rejects it. Meanwhile the operator's commands
  refuse to manage, guard, revoke, open, move or prepare it, to take it as a
  template (a cloned or promoted lead's included), a lead's source, a model
  qube, a project's or lead's network or birth egress, to change, remove or
  set the firewall or model of a held lead, and to migrate it. Every operator
  command that gives a badge refuses a qube that wears one with no label or
  another's, held yet or not, but `migrate` on a fleet where no qube in scope
  carries a label yet (v0.9.16's, which the installer then labels). These
  still act on it: `seal`, `gateway remove`, taking a model qube away, `project
  unblock` (the hold stays), `import`, which brings back records that may name
  it, `project delete`, which removes a held lead or member and strips the
  slot's badges from every qube that wears them, and dom0's own passes, which
  may still put a badge that only restricts on it (the anonymity gate's stop,
  the installer's `qmcp-anon`). So a worker restored months later joins no
  project unless the operator accepts it; until the pass holds it, the rulebook
  still routes on its badges.
- **The hub asks; only the operator decides.** The hub cannot create a
  project, add a dump sink, change or remove a lead, delete a project, edit a
  project's templates, networks or quota, give a lead a network, change
  a lead's firewall or model (an endpoint, or a model qube), open a guarded
  qube, bring a qube into AI space or take a guarded one out of the guarded
  state, take a qube out of AI space, remove a qube qmcp did not create, or
  install packages into a guarded template. It may propose each of those, as the options of one `qmcp`
  command, and
  nothing changes until the operator accepts the proposal in dom0: in the
  window, or with the command the window runs. Leads cannot propose.
- **A new copy is in AI space only from its stamp** (a named disposable's clone
  excepted, below). Every copy dom0 makes (a
  clone, a standalone made from a template, a lead cloned from one of the hub's
  qubes) is built in dom0's own order: the qube is created with none of its
  source's tags, filled (properties, features, notes, the operator's tags,
  firewall rules, the volumes its source keeps, each in its source's pool),
  labelled, and only then stamped. qubesadmin's `clone_vm`, which `qvm-clone`
  and `qvm-create --standalone` run, copies the source's tags right after its
  properties, before its features and volumes, one by one in the sorted order
  qubesd lists them, so `ai-managed` would land before `qmcp-anon` and
  `qmcp-hubblind`; qmcp does not use it. A disposable, and a named DispVM's
  clone, are the platform's own create, which gives the new qube its disposable
  template's tags in the one call; a hidden project's disposable templates
  wear `qmcp-hubblind`, so their disposables do from their first moment
  (below).
- **Strip on create.** Every create path removes every tag in qmcp's
  vocabulary the platform copied (`qmcp-guarded`, every role and slot badge,
  the v0.9.16 tier tags, other principals' provenance), stamps `ai-managed`,
  `qmcp-owner_<caller>` (provenance, and the one gate below) and its slot badge (a
  spawn's is its caller's, a clone's its source's; below), the badges that take
  authority away first (and takes a copied badge that routes a caller in off
  before `qmcp-guarded`), carries the platform's `anon-vm` forward from a spawn's
  template or a clone's source (v0.9.16's `qmcp-egress-locked_*` is stripped
  like the rest: nothing reads it), reads the result back, and rolls the qube
  back if it is not exact. A clone keeps its source's tags outside qmcp's
  vocabulary (the operator's own). A spawn, of an AppVM or a standalone, and a
  lead made from a template take none of the template's tags but `anon-vm`
  (an AppVM, spawned or a lead, on a Whonix template also gets what Whonix's
  own addon puts on a qube built on it, such as `sdwdate-gui-client`; a
  standalone does not).
- **AI removes only what qmcp created.** The lifecycle service removes, for
  the hub or a lead, only a qube that wears a `qmcp-owner_*` badge, which
  every qmcp create stamps, a revoke takes off, and only dom0 writes: a qube
  the operator brought into AI space with none (`qmcp manage`, an accepted
  `qube-manage`), a qube revoked and brought back, and a qube from a release
  before owner badges are refused ("removing a qube qmcp did not create takes
  the operator's approval"), on a strict tag read, so a read that fails
  refuses. (A hand `qvm-clone` of a qube that wears one copies it.) Such a
  qube is removed by the operator: `qmcp revoke QUBE --remove`, or by
  accepting the hub's `qube-revoke` proposal with `remove`, or its
  `project-delete` when it is a member. The badge gates in this one direction
  only: lacking it takes authority away.
- **The rulebook is static.** `/etc/qubes/policy.d/30-mcp-control.policy` is
  installed once and never written at runtime. Before it is installed it is
  parsed by qrexec's own parser against the box's real policy directory, and
  54 of its claims are checked to be decided by it, not by a file that sorts
  earlier.
- **An anonymous project is checked, not trusted.** dom0's anonymity gate
  judges every anonymous project every 15 seconds and after every `qmcp`
  command that changes qubes, projects or gateways, and stops one whose path stops being
  anonymous. A hidden one is not the hub's: the rulebook keeps the hub, and
  every qube of AI space outside the project, out of every qube wearing
  `qmcp-hubblind`, dialogs included, and the services answer the hub about
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
  disposable, property, feature, lifecycle, a submitted proposal — that gets
  past the caller check, the caller's daily budget and the free-space floor
  below leaves one line (past a caller's cap on calls that changed nothing,
  below, such a call is only counted; below the floor a kill leaves one only when dom0 accepted it) on a hash-chained log in dom0 (`/var/log/qmcp-audit.log`, `root:qubes
  0660`), with the caller, the service and a summary of the names, keys and
  options in the request. So does every command of the operator's that changes
  something, as caller `operator`, with the command and the names it acts on
  (`restored accept --all` leaves one line per qube it acted on), and so do the
  installer's own changes to the fleet (an updates tick, anonymous mode's
  stamps); accepting or rejecting a proposal names its fingerprint. What dom0's
  passes do is logged by the pass, and only what it changed: the restore check
  and the anonymity gate as caller `gate` (also when `qmcp gate`, `qmcp check`
  or another command runs them), the refresh as caller `refresh`, one line per
  qube it wrote into, and `qmcp seal --expired` or `--all` one line per window
  it closed or failed to close and per pending kill it made or dropped (these
  as caller `operator`, with `swept`). The value of a
  property or feature being set, a quota and a proposal's title are never
  logged. No service and no policy line exposes the log. A refusal made
  before the caller is known to be a principal changes nothing and is not
  logged. A principal's calls that changed nothing (refused, failed, or a
  feature, or a property set explicitly, set to the value it already has) are
  logged up to 60
  in each clock hour (UTC) for each caller; past that they are counted in
  `/run/qmcp/calls/<caller>.refused`, which `qmcp check` warns on until the
  operator removes it or a reboot clears it; the first call so counted in an
  hour leaves one line, `qmcp.calls-capped`, under that caller, where its own
  lines go (its project's, for a lead), never where a qube the withheld call
  named would send it, so the chain keeps that the counting began. A failed create that made a
  qube, or may have, is always logged (below the floor, only a kill
  dom0 accepted is). Each principal may also put about 20,000 lines a day
  (UTC) on the log for calls that changed something (calls already under way
  can each pass at the limit); past that, its state-changing calls but a kill
  are refused before they act, counted in the same file and not logged (the
  first of them in a day leaves one `qmcp.calls-capped` line), and
  its kills still act but their lines fall under the hourly cap (past both,
  a kill is counted rather than logged: the one change that can happen
  without its own line, and it only takes authority away); and `qmcp check` warns while today's share is
  spent and keeps naming the refusals until the operator removes the counter
  (which also gives that principal a new day's share) or a reboot clears it.
  One principal spends only its own share.
  The dom0 services refuse every state-changing call, before it
  acts, while less than 64 MiB is free on any chain the install may write (in
  install mode disk, under `/var/log` and on the RAM chains' tmpfs; in mode
  ram, on the tmpfs; in mode none there is no floor), so no service changes
  anything without its line (but a qubesd call that raised after its change
  landed, past the cap, which is only counted; a kill goes on, since it only takes away; the
  operator's commands and the timers are not refused); a line that cannot be written all the same is counted in
  `/run/qmcp/audit-dropped`, which `qmcp check` fails on until the operator
  removes it, or a reboot or `uninstall.sh` clears `/run/qmcp`. Beyond that
  floor, logging is best-effort: a write that fails never changes what the
  caller sees, or whether the operator's command runs. A write cut short (a
  kill, a full disk) leaves a torn last line, where the chain then reads
  broken; the next record starts a line of its own. Running a command, copying out and firewall writes are decided
  by the policy, not by a dom0 service, and are not on this log.
- **Where audit lines go, and for how long (0.9.33).** The install has an
  audit mode, set by `install.sh --audit-log disk|ram|none` and kept in
  `/etc/qmcp/audit-mode`: `disk` (the default) is the log above; `ram` is a
  hash chain of its own under `/run/qmcp/audit`, gone at shutdown; `none`
  writes no qmcp audit line at all. A project has one too, switchable while it
  runs (`qmcp project audit LABEL disk|ram|off`, the record's `audit`): `ram`
  gives it its own chain under `/run/qmcp/audit/pNN.log`, `off` writes none of
  its lines. A line belongs to a project when its caller is the project's lead,
  a qube it names wears one of the project's slot badges (read with one
  `admin.vm.tag.List` per named qube, before the call acts and again after, so
  a qube the call removes and one it creates both count; before it acts only
  the request keys its service acts on are read, `name` for a property,
  feature or lifecycle call, `template` for a spawn and `source` for a clone,
  never another key the caller sends), or it names the
  project by label or slot: so the lead's calls, the hub's calls into the
  project's qubes and the operator's commands on it all follow the project's
  mode. A refused call is placed only by the qubes its service judged within
  the caller's reach, by the same check that lets it act on them or build
  from them, and by a qube the call created: a qube the caller may not see or
  act on (another project's, a hidden project's, a guarded one, the caller
  itself), a name that does not exist, and a name the call was refused before
  it judged (a create's name outside the caller's space, an argument refused
  first) place nothing. Its line then goes where the caller's own lines go
  (its project's mode for a lead, the install's for the hub) and records
  `<out-of-reach>` in place of each such name, the three alike, so a
  principal cannot send its own refused line after a qube it may not reach,
  and the line keeps no such name in the keys that say what it is about (a
  spawn's `netvm` is recorded as the caller gave it, and places nothing). A
  qube refused for its state (guarded, stopped by the gate, held) that wears no
  slot badge, such as a template or a gateway, is named on the line all the
  same, and places nothing; a project's qube refused so stays `<out-of-reach>`.
  A create's
  proposed name inside the caller's own space is kept as given and places
  nothing. A lifecycle call judges its qube before the action's value (an action
  that is missing, empty or not a string is refused first), so a refused
  action on a qube in reach keeps that qube's place. A call that succeeds, a
  refusal of a qube in reach, and the operator's own commands are placed as
  above. The hub's submission of a proposal leaves its line where the hub's own
  lines go, whatever the subject names: there the subject is the hub's words,
  not a qube the call acts on. The operator's accept or reject line follows the
  subject's project.
  A line goes to the most private of the install's mode and the modes of
  every project it belongs to (none, then ram, then disk); one whose project
  cannot be worked out (a badge read that fails, project records that do not
  read, a slot badge with no record) goes to RAM (nowhere only in install
  mode none), never to disk; an install mode file that does not read counts
  as ram, so a line of a project set to `off` still goes nowhere (`qmcp check`
  fails on the file). A RAM line goes to its project's own chain when it belongs to
  one project only and that project asked for RAM, otherwise to the install's
  RAM chain. A mode switch leaves one line on the install's chain naming the
  slot, not the label, so the chain has no unexplained gap; an install-mode
  change leaves one on the less private of the two modes. Leaving disk keeps
  the lines already there, and the command and the form say so: deleting a
  file on dom0's disk is not erasing it. The daily budget and the hourly cap
  cover every line, disk, RAM or nowhere: a line meant for nowhere is counted,
  capped and spends its caller's budget like any other, so the time a call
  takes does not tell which names belong to a project logging nowhere. Only
  install mode none, where every line goes nowhere, counts nothing. The floor
  is judged on every chain the install may write, for every line whatever its
  own place (`/run` being dom0's memory), so a refusal for room never says
  where a line was going. Whatever the modes, dom0's journal keeps every
  qrexec call (the policy daemon logs each request); `qmcp check` warns while
  any mode is not disk and prints the drop-in that makes journald volatile,
  which qmcp does not install itself.
  Root's `qmcp-audit.timer` runs `qmcp audit rotate --auto` every hour: it
  rotates the log (the same gap-free rotation as `qmcp audit rotate`) when its
  first line is from an earlier UTC day, or it is past 32 MiB, and then
  removes the rotated logs older than the keep-days setting
  (`/etc/qmcp/audit-keep-days`, `qmcp settings set --audit-keep-days N|off`, 90
  by default), judged by the time in their names and never by their size, so a
  flood cannot push the record of anyone's earlier actions off the disk. A
  setting that does not read removes nothing (`qmcp check` fails on it). A run
  writes a line only for what it did: the rotation's anchor, and one line,
  caller `rotate`, on the install's chain (none in install mode none), naming
  the files it removed (the first 32, and how many more; a removal that failed
  leaves it too, not ok), and one more for the RAM files it removed.
  In install mode ram or none the log is not rotated (nothing is appended to
  it); old rotated files are still removed by age. The RAM chains are bounded
  by size instead, since they hold dom0's memory: the same hourly run rotates
  a RAM chain past 8 MiB and removes the oldest rotated RAM files while the
  regular files under `/run/qmcp/audit` together hold more than 64 MiB, never a
  live chain and never through a link; one it cannot remove is named on its
  line, and it goes on to the next. So a
  flood can push earlier RAM lines off; a reboot clears them all anyway.
  `qmcp audit status` lists the rotated RAM files with the chains. `qmcp
  check` fails while `qmcp-audit.timer` does not run (`audit timer`), warns
  when a `qmcp-audit.log.rotating` file shows a rotation stopped part-way (the
  next rotation takes it over), and warns, in install mode disk, when the hub
  and every recorded lead at their full budget, about 400 bytes a line, for
  keep-days days would not fit the free space under `/var/log`, and when
  removal is off.

## Projects

Sixteen slots. **p00** holds the hub's own working qubes; **p01–p15** are
projects. A project is one **lead**, the qubes it creates (its **workers**),
and optionally a **dump sink**. Its record, in `/etc/qmcp/projects.json`
(root-owned, written by `qmcp project`, by an accepted proposal, which runs
it, and by `qmcp import`; the installer writes it empty), holds
what a tag cannot:

| Field | |
|---|---|
| label | 1–8 lowercase letters or digits, and not one a command could read as a slot (`p03`) or keyword (`none`, `hub`). The project's names are `<prefix><label>-…` (`ai-osint-scraper`); the hub creates in `<prefix>hub-…`, but for its clone of a project's member, which is named inside that project's names, so a lead collides only with its own workers, the hub's clones of them, or a qube the operator named inside its space or moved out of it (`qmcp check` lists those). |
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
approved templates and worker networks, creates AppVMs, standalones and
disposables (never a disposable template) inside its name space and quota, and
its workers are
born on its project's networks; the lead's own network is never inherited.
Through the rulebook
it runs commands, copies files and reads or writes the firewall in its
members, and copies files into them. Every other dom0 service call answers
like a name that does not exist, at the same cost. A copy, or a file or URL
opened in another qube, does not: one into another lead, a guarded qube, the
hub, a hidden project's qube, or a qube held for review or stopped by the gate
is refused at once, where a name that does not exist gets the dialog,
so a lead can test a guessed name (another project's `ai-<label>-lead`) at the
cost of a dialog.

**Workers** call no qmcp service. They cannot reach their lead, the hub or
another lead; they copy among themselves and into their sink without a dialog,
and reach another project only through the operator's dialog: a copy, or
Qubes' own asks to open a file or URL there, which this rulebook leaves to
Qubes' default policy; never a hidden project they are not in. Starting an
app in another qube or reading an image from one is refused (D5).

**The hub** operates every project but a hidden anonymous one: its leads (it may clone one, but only the
operator removes one, and it never writes a lead's firewall) and its workers. Its own AppVMs and
standalones join p00 when it creates them; its disposables join no slot,
because a disposable often opens hostile content and in p00 it could drop files
into the hub's other qubes without a dialog. **A clone lands where its source
is**, for the hub and a lead alike: a clone of a p00 qube joins p00, and a clone
of a project's member joins that project, is named inside its names and counts
against its quota. A clone of a lead (it carries the lead's agent and model
credential), of a template or of a qube in no slot joins no slot. Taking a
project's qube into p00 stays the operator's move, for the same reason as a
disposable. Templates and disposable templates join no slot.

**A standalone** (a StandaloneVM) is a worker, a lead or one of the hub's
qubes with its own copy of a template's root, so what is installed in it stays
across restarts, and so does anything a compromised agent leaves in it. One
made from a template comes, for a lead's worker, from an approved template;
for the hub's, from any template it may spawn from; and for a lead made with
`--lead-class standalone`, from the TemplateVM given, as for an AppVM lead. It
takes the template's features (as `qvm-create --standalone` does), the
template's own values of the properties an AppVM follows from its template
(not its boot mode, which an AppVM takes from the template's
`appvm_default_bootmode`), and its root as it was when the template last shut
down (measured), in the
template root's pool; its private volume is new. It takes none of the
template's tags, firewall rules or devices (its stamp then carries `anon-vm`,
as above). Its root counts at the template root's full size against the pool cap
and, for a member, the project's quota; a lead the operator makes is checked
against neither. Its copy of the in-qube services came with that root: its
`qmcp-services` label is the template's when the template read as halted,
with that same label, just before and just after the copy, and otherwise reads `unknown: copied from a running qube`,
which the check counts as behind until the refresh writes into it; a template
never prepared gives a copy with no label. A standalone the operator built
joins a project with `qmcp project move`, which is the operator's approval of
what it runs. Windows qubes are not supported.

**The operator** creates a project with `qmcp project create`, or by
accepting the hub's proposal to create one (below). Either way the command
makes the lead in one of three ways: fresh from a template (an AppVM, or with
`--lead-class standalone` a standalone), as a clone of one of the hub's own
AppVMs or standalones that the operator prepared as an agent, or by promoting
one of them in place, which keeps its network (or, given none, loses it: no
network moves). A cloned or promoted lead keeps its source's class. Every project
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
--yes` finishes a delete that stopped half-way. A qube wearing the slot's
member badge that is also a member of another slot, or is a template, a
disposable template, a gateway, a model qube, a guarded qube, a dump sink or
the hub, is kept and loses only the slot's badges;
one whose tags or class do not read is left as it is, and the slot stays in
use until a run reads it. The plan a delete prints first names, with or
without a record, the qubes it removes, the ones it keeps, and the ones that
only lose the slot's badges; a member made after the plan was printed is
removed too. Moving a qube into a project
needs it to have no network or one on the project's list, and moving one out of a slot into
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
another, whose leads may be using it; otherwise what runs in it, the hub's
processes included, is stopped. A power state that cannot be read is never
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
needs changes, and `qmcp check` warns until it is guarded again (for an
anonymous project's model qube it fails, and the anonymity gate stops the
project, since it needs that model qube guarded) (`qmcp guard`
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
  preloaded one included (approving one is refused while the hub can reach a
  disposable or named DispVM made from it earlier, since each start of one
  hands the hub the template's home as it is then; a create whose new qube
  arrives wearing `qmcp-hubblind`, or the gate's stop, that it did not ask for
  is rolled back, never stripped; and the hub's clone of a qube whose
  template is hidden answers as a source that does not exist); the rulebook
  refuses the hub every call into one, and every qube of AI space outside the
  project too, dialogs included, since the hub runs commands in those; the services leave it out of the hub's
  lists, reads, events and project rows, and answer the hub about one of its
  qubes exactly as about a name that does not exist, after the same qubesd
  calls, balanced to cost the same; and a proposal that names it, or one of its qubes, fails at
  accept as one naming a project or a qube that does not exist. The hub may still propose
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
  for the services' non-root user. A stopped or held qube is asked about as if
  it were neither: the rulebook denies a stopped or held qube its updates too,
  and the question is where they go once the stop or the hold is cleared. The parser's warnings are silenced, or a run
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
  exists, or anonymous mode is on, and that is more than 60 s old or dated
  ahead of the clock; it fails in every mode while the timer is not running,
  since the timer's unit also ends windows that have run out and holds restored
  qubes. A check or a window refresh runs the gate too, but only the timer's
  runs prove the timer. The services do not run
  it on each call; they refuse a lead that wears `qmcp-blocked`. The boot run
  is not ordered before Qubes' own autostart, so a qube marked to start at
  boot may run for those seconds first: mark no anonymous qube to start at
  boot.
- **On a violation** it acts in passes, so no qube is killed while another
  can still act: first `qmcp-blocked` on every lead and member, the lead
  first (the rulebook refuses every call into a blocked qube, so qrexec cannot
  wake one, and every call from one, so one the operator starts by hand
  reaches no other qube and no dom0 service, though it keeps its network; and the services refuse to start, change or clone one, checking
  again right before a start, under the qube's lock); then each one is killed
  unless it reads halted, at once, and killed again if it runs once the
  gate has its lock or has waited 5 s for the run (see "Authority is checked
  when the work is done"), and badged `qmcp-stopped` once it is known to be down (a
  power state that cannot be read is no halt: the kill is tried, and a qube not
  known to be down is tried again on the next run); then their `autostart` is
  turned off where it is still on, on every run, so a write that failed is
  tried again. One audit line says what was done, and the operator is told: a
  desktop notification from the timer's run, or a line on the command's output
  when a `qmcp` command's own run acted (a root process cannot reach the
  desktop); when a block did not land, both say the gate could NOT stop the
  project, and `qmcp check` names what is left. A run that changes nothing and repeats no failed step says
  nothing; one that repeats a failed step (a kill, a badge) says so again. It removes nothing: every qube and its data stay as they were. Every
  run that finds the project unsound kills whatever of it runs, `qmcp-stopped`
  or not: a start qubesd accepted reads halted until its domain exists (so a
  run can mark it stopped just before it comes up), a block or an autostart
  write can fail, and a qube can start at boot. Whoever started it, it runs on
  the path the gate found broken, so the operator cannot start one to look at
  it while the project is unsound (its volumes stay readable from dom0). A read the gate cannot make is tried
  once more; a second failure blocks the project without killing it (records
  that do not read twice block every project member, lead and hub wearing
  `qmcp-anon`, none killed, and name any qube whose badges do not read), and a
  later confirmed violation still kills it. A qube whose tags cannot be read
  makes the run unable to judge any project, since it may be a member. `qmcp
  project unblock NAME`, holding the gate, takes both badges off once a fresh
  run finds the project sound, and names a qube it cannot look up as not
  unblocked; `autostart` stays off.
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
  In normal mode it takes off, with no gate run, the stop badges
  (`qmcp-blocked`, `qmcp-stopped`) anonymous mode left on the hub and the
  qubes under its check, and names any whose tags cannot be
  read as not unblocked.
  The installer refuses the mode while an ordinary project exists, a clearnet
  gateway is enrolled, or the gate would stop the hub; it lists every qube
  already in AI space that the hub's check will cover, each with a past, and,
  after the policy, stamps them, writes the mode file and stamps once more. No
  qmcp command turns it off; `uninstall.sh --purge` does. qmcp cannot check whose account the
  hub's model uses, nor what the hub qube did before the mode.

**Authority is checked when the work is done.** A service reads its request
before it checks the caller, so a lead removed while its request is still
arriving is refused; a create checks its caller, and its template or source,
again once it holds the create lock, which every project command holds too.
**One lock per qube** (`/run/qmcp/qubes/`, declared in tmpfiles) serialises
the services that operate a qube with the commands listed here: the
lifecycle, property and feature services, and a clone for its source, take it
once the qube resolves (a name the caller cannot see never waits on one, so
contention tells it nothing), check the caller and the qube again, and hold it
until their reply; `manage`, `guard`, `revoke`, `open`, `seal`, `project move`,
setting a model qube, and the restore check's hold, accept and reject take it
too, the create lock first where they hold both; so do a lead's promotion,
by `project lead` or `project create --lead-promote` (the promoted qube's
lock, from before the plan to the end), and a lead's removal or change and a
project's delete (the old lead's lock, for its demotion and kill). The gate
kills at once, then takes the locks of the qubes it stops, waiting at most 5 s
in all for one run, and kills again any that runs once it has them or the 5 s
are up. A command that
grants authority refuses when the lock stays held past its wait
(60 s; `open`, which runs under the gate's lock, 5 s; a service's is 30 s).
`guard`, `revoke`, `seal` and a lead's demotion go on without it, then wait
for the lock again: by then the calls that were in flight have finished, and
no new one gets past its check, since the qube no longer resolves for it (a
demoted lead still does for the hub, and the hub's new calls on it are ordinary
ones).
They then make their effect hold (a revoke, a seal or a demotion kills again
what such a call started; a guard reports a remove that won), and say they
went on without the lock only when that second wait fails too. The restore
check's hold goes on without it after 2 s, then waits up to 5 s more and
reads the hold back (a remove that won is reported, not counted as held; one
still waited on is reported, and `qmcp gate` exits 3); reject goes on after
60 s and says so. A qube whose lock the gate did not have in time is killed
again by the next run that still finds its project unsound, if a start lands
after. Whenever qmcp removes a qube itself (among them the lifecycle service's
remove, a create it rolls back or a disposable it disposes of, every qube a
project's delete, a lead's removal or a lead change removes, and the rollback
of a new project's lead or dump sink), it then removes that qube's lock
file and turnstile: the lock under the one the service holds, otherwise only
a file free at that moment, never waited for, so the remove is never slowed
or failed by it. Every taker checks, once it has a lock, that its file is
still the one at the path (below). A file in use then is left, and so are the
files of a qube removed outside qmcp (`qvm-remove`, or a disposable Qubes
removes when it stops, as after the hub's run in a disposable); they grant
nothing, and each pass of the gate's timer (`qmcp gate`) removes, with no
audit line, the free lock files of every name qubesd no longer lists: its
qube lock and turnstile, its in-qube writer lock (`/run/qmcp/inqube-<name>.lock`,
0640 so the gate's user can open it), and its call slots, acting lock and
acting turnstile under `/run/qmcp/calls`, never its counter (`.refused`), never
the hub's call files, and nothing there while `/etc/qmcp/hub` does not read. A list
that does not read, or reads without dom0 (then it is not qubesd's list),
removes nothing; a list wrong some other way costs nothing, since each file
goes only under its own lock, taken without waiting, and every taker checks its
file is still the one at the path. A file a call or a prepare holds is left for
the next pass; a prepare or install that finds its lock held tries it again for
about 0.4 s, so the pass's moment on it is not read as another writer.
**Qube locks, the create lock and the acting locks are taken through a
turnstile** (`<name>.queue` beside a qube's lock, `/run/qmcp/create.queue`
beside the create lock, `<caller>.acting.queue` beside an acting lock). A
service passes straight through it; an operator's command, the restore check
and the gate wait in it, so a call that arrives after one of them waits behind
it, and only the calls already past the turnstile go first. A busy hub can
therefore no longer hold a lock off the operator for longer than its own calls
in flight take.
**A caller's calls are drained before its authority goes.** Every call of a
service that changes something (lifecycle, property, feature, spawn, clone,
disposable) holds its caller's acting lock (`/run/qmcp/calls/<caller>.acting`),
shared, from the moment its caller is checked again under a qube's lock or
the create lock to its reply. A lead's removal, change or project delete takes
the old lead's acting lock exclusively, in its turnstile, before a badge comes
off, so every such call of the lead's already past that check has finished
first, and one reaching it meanwhile waits and is then checked against what
the command left, and refused. A create of the lead's waits for the create
lock, which the command holds, and is then refused. The drain covers the dom0
services only: commands the lead runs in its members through the rulebook
(`qmcp.RunInAIManaged`, `qmcp.CopyToAIManaged`) and its firewall writes reach
no dom0 code, and a command it started in a member runs on there after the
lead is gone. Once the old lead's badges are off, the same command removes
its lock files under `/run/qmcp/calls` (its acting lock, that lock's
turnstile and its call slots), each one only while it holds that file's lock;
every taker of these locks checks, once it has one, that its file is still
the one at the path, and takes the new one when it is not, so no lock is ever
held on two files. The command never waits for one of them: a file a call
holds at that moment is left, and so are all of them when the lead's calls
outlast the drain's wait, which the report says; it is only a lock and
grants nothing, and the gate's timer removes it once qubesd no longer lists
the name (a reboot clears it too). The old lead's counter
(`<caller>.refused`) stays: it is the record `qmcp check` warns on, and
removing it would give that name a new day's share.

## Proposals

The hub asks for what only the operator may do by **submitting a proposal**
(`qmcp.SubmitProposal`): the options of one `qmcp` command, never a plan or a
list of commands. A proposal names a project by its label (or `p00`
for the hub's own dump sink), never by its slot: by the time the operator
accepts, a slot can hold a project the proposal was not about. Ten kinds:

| Type | The command it is the options of |
|---|---|
| `project-create` | `qmcp project create`: the label, where the lead comes from (`template`, `clone` or `promote`) and, from a template, whether it is a standalone, its network, name and model (an endpoint or a model qube), more approved templates, the worker networks, the quota, a dump sink or not |
| `project-edit` | `qmcp project edit`, but as changes: templates and worker networks to add or remove, a new default network, a new quota |
| `project-dump` | `qmcp project dump` |
| `project-lead` | `qmcp project lead`: remove the lead, or a new one (a standalone or not, with its model: an endpoint, a model qube or none), saying whether the old lead stays as a worker or is removed (there is no default), and whether a kept old lead's network joins the worker networks |
| `project-firewall` | `qmcp project firewall`: a new model endpoint for the lead (its firewall becomes that endpoint, and DNS for a host name), a model qube or none, or exactly these rules |
| `project-delete` | `qmcp project delete --yes` |
| `qube-open` | `qmcp open`: the guarded qube, how long the window lasts, and whether the firewall half comes with it. It always needs the second tick; only the operator opens a window, and the hub can never put the badges on itself |
| `qube-manage` | `qmcp manage`: a qube to bring into AI space, or a guarded one to take out of the guarded state, with no time limit (a window is the bounded way into a guarded qube; managing an open qube ends its window, with no kill). Accepting refuses a qube that holds a PCI device (the hub would have root over a USB or network controller) or whose devices cannot be read, and a template that a qube the hub does not operate (outside AI space, or guarded) is built on, or whose dependants cannot be read; the operator's own `qmcp manage` takes both. The command refuses a qube wearing lead badges, or a project's member badge without being a managed qube of it. It always needs the second tick |
| `qube-revoke` | `qmcp revoke`: a qube to take out of AI space and out of any slot, killed if it runs unless `shutdown` is false (`--no-shutdown`), and with `remove` true then removed with its storage (`--remove`; `shutdown` false with it is refused at submit, and a proposal without it reads back as before). The command refuses, with `remove`, what `qmcp revoke --remove` refuses (below), before it changes anything; a qube Qubes refuses to remove for another reason is revoked and killed, and the report says it was not removed. The command refuses the lead a project's record names; accepting refuses a qube outside AI space, which the hub cannot see, since `qmcp revoke` would still pin its default disposable template and kill it, and `shutdown` false for a qube the hub could run commands in (managed, or open), whose processes would run on outside AI space. It always needs the second tick |
| `template-install` | `qmcp template install`: a TemplateVM in AI space and 1 to 32 exact package names, installed by its own package manager from the repositories it already trusts (see the operator's command). It always needs the second tick |

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
  given, unreadable records, a read that the check for a hidden project's names
  needs and that failed) changes nothing, and the proposal stays pending.
  An edit is applied to the record as it is at accept and changes only the
  entries it names, so a later change of the operator's to anything else
  stands; only what it adds is checked, so an entry it leaves in place that no
  longer qualifies (`qmcp check` names it) does not refuse it.
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
  qube; and every `qube-manage`, `qube-revoke` and `template-install`, always,
  with what each would do to that qube as the fleet is now if the command takes
  it (`show`'s plan names the refusals it can see before anything runs: a
  qube it could not look up, a missing qube, a hidden project's, dom0, the hub
  or an unreadable hub file, a drop box, a held qube, for a manage a qube
  holding a PCI device, a template a qube the hub does not operate (outside
  AI space, or guarded) is built on, a qube wearing lead badges or a project's
  member badge without being a managed qube of it, and a gateway, for a revoke the lead a project's record names, a qube outside AI
  space, `shutdown` false for a qube the hub could run commands in and,
  with `remove`, a guarded qube, a model qube, an approved template or worker
  network, or a qube other qubes or a global setting use (a read that fails is
  no refusal there), and a
  template the install refuses; the rest, such as a network that is not
  enrolled, only the command finds at accept): whether a qube comes
  into AI space or out of the guarded state, that it is a template and which
  projects approve it, the projects whose model qube it is, any anonymous
  project the gate would then stop (the gate's own judgement of the fleet as
  the manage would leave it), the slot a revoked qube leaves and whether
  it is shut down, that a revoke with `remove` removes it and cannot be undone, the qubes built on a template (the hub and enrolled
  gateways named), what managing a disposable template does to the
  disposables made from it and to the qubes that use it, that a qube is open
  now, that Qubes refuses to shut down a gateway with a qube running on it,
  that revoking a disposable Qubes removes when it stops removes it, and for
  an install the packages, that an install that would remove an installed
  package is refused (an installed one may still be upgraded), and that
  their
  dependencies come too, that every qube built on the template runs them from
  its first start after the template has shut down, that on Arch it upgrades
  the template, and that the install scripts of each package and dependency
  run as root and can add a repository or download more. A qube of a hidden
  project named by one of the three gets only the lines that come from the
  proposal itself, none read from the fleet, and accepting it fails with the
  command's own words for a name that does not exist. A lead whose badges cannot be read counts as one that will be
  removed, and a network that cannot be read as a new one: a failed read never
  makes a removal one click. `accept` computes the reasons again while it
  holds the project commands' locks, so no project command and no create can
  change what they rest on before its command runs. A `template-install` lets
  those locks go once the proposal is marked, so a create or a project command
  may land between its tick and its install. The networks AI space
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
  command (an install only until the proposal is marked), but lets the store's go once the proposal is marked, so a submit
  never waits on a running command.

## What lives where

| Where | What |
|---|---|
| hub (`mcp-control`) | `qubes_mcp/`: the MCP server and the `qubes-mcp` CLI. Standard library only. It reaches AI space through the policy's hub section and, in a guarded qube you opened, the window lines (A6b); beyond that, only its own boot services and the operator's dialogs. A client's `notifications/cancelled` drops a call that has not started yet, unanswered; one already running is not interrupted. |
| each lead | the same `qubes_mcp/`, which reaches its project through the policy's slot lines and the leads' section. |
| dom0 | `/usr/local/lib/qmcp/qmcp/` (the library), `/usr/local/lib/qmcp/template-rpc/` (dom0's copy of the in-qube services), `/etc/qubes-rpc/qmcp.*` (one shim under each service name), `/usr/local/bin/qmcp` (the operator's command), `/usr/local/bin/qmcp-gui` and its menu entry (the operator's window), the policy, `/etc/qmcp/` (operator files, `projects.json` among them), `/var/lib/qmcp/proposals/` (the hub's proposals and their decisions), `/run/qmcp/` (lock files, and `open/`: a record per open guarded qube, cleared by every boot), the units the seal, the gate, the refresh and the audit rotation run from (`qmcp-seal.service` with a drop-in on `qubes-vm@.service`, `qmcp-gate.service` and `.timer`, `qmcp-refresh.service` and `.timer`, `qmcp-audit.service` and `.timer`), `/etc/tmpfiles.d/qmcp.conf`, the audit log `/var/log/qmcp-audit.log` with its pad file `/var/log/qmcp-audit.log.pad`, and the RAM chains under `/run/qmcp/audit/`. |
| AI templates and standalones | `template-rpc/`: `qmcp.RunInAIManaged` and `qmcp.CopyToAIManaged`, which `qmcp template prepare` writes into the templates AI qubes are built on and into standalones, and labels with their version (`qmcp-services`). A qube on a template without them cannot be exec'd into, unless its own `/usr/local/etc/qubes-rpc` holds them. |

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
| `qmcp.GetPropertyAIManaged` | One property of a managed or guarded qube. Only properties qubesd lists, and `power_state` and `tags`; references out of scope redacted, and so are the netvm's addresses (`visible_gateway`, `dns`, …) when the netvm is out of scope, and refused when it cannot be read; an enrolled gateway is named (for a lead, one of its worker networks); `tags` filtered to `ai-managed` and `qmcp-guarded`, and refused when they cannot be read. |
| `qmcp.SetPropertyAIManaged` | `label`, `memory`, `maxmem`, `vcpus`, and `netvm` only to null. Everything else (`template`, `name`, `default_dispvm`, `provides_network`, …) is operator-only. |
| `qmcp.SetFeatureAIManaged` | Allowlist: `service.*`, `vm-config.*`, `menu-items`, `default-menu-items`. Every other key, including any a future Qubes adds, is operator-only. |
| `qmcp.LifecycleAIManaged` | start, shutdown, kill, pause, unpause, remove. Remove is a real remove, of a qube qmcp created (one wearing a `qmcp-owner_*` badge) only; removing a lead, and any qube qmcp did not create, is the operator's. |
| `qmcp.SpawnAIManagedQube` | AppVM, StandaloneVM or DispVMTemplate from a TemplateVM, or a named DispVM from a disposable template. The template may be managed or guarded, but not one that provides network. A lead spawns AppVMs, StandaloneVMs and DispVMs from its approved templates only. |
| `qmcp.CloneAIManagedQube` | Clone a managed qube, templates and standalones included; the clone lands where its source is (see Projects). A guarded source is refused: a clone is a managed, editable copy of everything in it. The template a clone is built on is checked (not stopped by the gate, not held or waiting for review, for a lead on its approved list), and the source, that template and the project it lands in are read again under the create lock and the source's own lock. The hub's clone of a qube whose template is hidden answers as a source that does not exist. |
| `qmcp.SpawnDisposableAIManaged` | A disposable from a managed or guarded disposable template, born managed. Uses Qubes 4.3's preloaded disposables when the template has `preload-dispvm-max` (measured: a `qubes_run_disposable` cycle took 1.5 s with `preload-dispvm-max=1`, about 8 s without). |
| `qmcp.AIManagedEvents` | The hub only. A window of admin events (1–120 s) whose subject is in AI space and not of a hidden anonymous project; at most 16 filters of at most 64 characters. Tag events surface only for the two visible badges. The caller is checked again when the window ends: one that is no longer the hub (stopped by the gate, or held, while it listened) gets the refusal, not the events. |
| `qmcp.GetPoolStats` | `ai_managed_bytes_used`, `_cap` and `_headroom`, and `name_prefix`, the prefix the caller's spawns are named with (the hub's `ai-hub-`, a lead's `ai-<label>-`): for the hub, AI space against the operator's cap, `reserved_prefix` (the bare prefix a project's names build on), and every project's record but a hidden anonymous one's (slot, label, lead, templates, worker networks, quota, disk used, whether it is anonymous, and whether it has a dump sink, never the sink's name, which is outside AI space; a recorded name that has left AI space reads `<out-of-scope>`, unless it is an enrolled gateway; null when the records cannot be read), each project's model (`model`, an endpoint, or `model_qube`), and the gateway registry (`gateways`: name, anonymising, label; null when it cannot be read); for a lead, its workers against its quota, with its project's label, approved templates, worker networks, dump sink, model (`model`, or `model_qube` with `model_port`, 11434), and whether it is anonymous and whether the hub sees it (`anonymous`, `hub_sees`). A lead never sees the fleet's figures. |
| `qmcp.SubmitProposal` | The hub only. Stores a proposal for the operator after checking its shape (see Proposals); touches no qube. |
| `qmcp.ProposalStatus` | The hub only. Its proposals' states, newest first; with `id`, one of them with its stored copy. |

**Creates.** A name says which slot holds the qube: the hub's must lie inside
its own space, the reserved prefix (`/etc/qmcp/name-prefix`, default `ai-`)
followed by `hub-` (`ai-hub-browser`), and a lead's inside its project's
(`ai-<label>-`). `hub` is never a project's label, so no two spaces overlap.
A name is judged on its shape alone, before anything is looked up, so a create
is no oracle over names outside the caller's space. One exception: the hub's
clone of a project's member is named inside that project's space, judged once
the source is resolved; the hub can already list that project, so a collision
there tells it no more than a collision inside the reserved prefix does (see
the residual risks), and a hidden project's names stay out of its reach, since
it cannot name a hidden member as a source. (Qubes
names disposables itself.) Creates are serialised by a lock held
from the disk-budget check through the create, with a 120 s wait, and the name
is checked again under the lock. A create call that fails is never cleaned up
by name: qubesd cleans up its own failures, and a qube someone else made under
that name meanwhile is left alone. A create that succeeds but
cannot be finished is rolled back; the one exception is a failed `private`
resize, which keeps the qube and says so (`warning: private_resize_failed`).
Spawn and clone set the new qube's network
and `default_dispvm` explicitly and read them back before it is labelled or
stamped, so neither follows a global default and no start of it boots it on
Qubes' default network while it is in AI space; a spawn judges its template
again under the create lock (in reach, not stopped by the gate, not held), as
a clone does its source. A disposable gets `default_dispvm` set to none and
keeps its template's network, both set before its stamp.

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
checked again under the create lock, where the birth network is worked out
again from what is read there: a create whose network changed while it waited
is refused (try again). A spawn may ask for `netvm: null`, which is always
allowed. Otherwise the hub's may name only the netvm it would get anyway, and
a lead's spawn from a TemplateVM any of its project's worker networks; any
other name is refused. A qube whose
network cannot be proven is rolled back before the call returns: a fresh qube
before its first boot; a preloaded disposable, already running on its
template's network, is killed.

**Disk budget.** The sum of every AI-space qube's `private` volume, plus `root`
for TemplateVMs and StandaloneVMs, is capped by `/etc/qmcp/pool-cap`; one
qube's requested `private` by `/etc/qmcp/private-cap`; a project's workers by
its quota, on top. All are re-read on every call. A named DispVM is
counted at its disposable template's `private` size, or at the size it asks
for when that is larger, since qubesd gives it at least the template's. A volume that cannot be read refuses the create rather than being
counted as empty. Without a pool cap every create is refused; without a
private cap, any create that asks for a `private` size.

### In AI qubes

| Service | What it does |
|---|---|
| `qmcp.RunInAIManaged` | Runs a command as root and returns rc/stdout/stderr. Its timeout is 1 to 86,400 s (default 60); at the timeout it kills the command's whole process group, so what a shell started stops with it; a process that left the group (`setsid`) survives, and the service then waits at most 5 s more for the output pipes it may hold before it answers. The hub drives it in any managed qube but a hidden anonymous project's, one the gate stopped or one held for review, and in a guarded qube you opened; a lead in its own managed members that are not stopped or held. |
| `qmcp.CopyToAIManaged` | Runs `qvm-copy-to-vm -- TARGET PATH` from this qube, once the target has a qube name's shape (never `dom0`) and the path is absolute. Its timeout is 1 to 86,400 s (default 300; `qubes_copy` sends its own), and at the timeout it kills the copy's whole process group, waiting at most 5 s more for its output pipes before it answers. The copy itself is `qubes.Filecopy`: no dialog from a member to another member of its slot or to the slot's sink, or from a lead to its members; refused into a guarded qube, the hub, a lead, dom0, a new disposable (the service takes no `@dispvm` form at all; the policy also refuses `@dispvm` and `@dispvm:` an AI-space template), a qube the gate stopped or one held for review, and into a hidden project from outside its slot; the operator's dialog anywhere else, a lead's own copy into its sink included (a hidden lead's is refused). |

The server in the hub or a lead waits for either service for the call's
timeout plus 30 s (its cap on any wait is a day plus 60 s, past every timeout
plus 30 s, so it never gives up before the service in the qube). A call with no answer by then gets `no answer within N s; the work in
the qube may have run, or may still be running`: a refused call, or one to a
qube that does not exist, is answered at once, so the reply tells the caller
nothing about other names.

## The rulebook

`policy/30-mcp-control.policy`, first match wins. Four kinds of source
appear in it: the hub by name, the leads (`@tag:qmcp-lead`, and
`@tag:qmcp-lead-pNN` in their slot's lines), a slot's members
(`@tag:qmcp-proj-pNN`, in their slot's copy lines) and AI space
(`@tag:ai-managed`). A few denies also name any source (`@anyvm`), the drop
boxes (`@tag:ai-dump`), or a stopped, held or anonymous qube
(`@tag:qmcp-blocked`, `@tag:qmcp-quarantine`, `@tag:qmcp-anon`). A lead is in AI
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
    traffic leaves outside its router. A qube held for review
    (`qmcp-quarantine`) is refused both ways, as a stopped one is, whatever
    badges it came back with.
  - A1: Qubes' raw disposable shortcut is closed for AI space. A `@dispvm` rule
    target matches only the bare keyword, so a second rule works from the
    template's side: `@dispvm:@tag:ai-managed`, any source, any form.
  - A2: none of Qubes' own exec services (`qubes.VMShell`, `VMRootShell`,
    `VMExec`, `VMExecGUI`) from AI space, whatever form the target takes.
    qmcp's own exec service is D1's, with a lead's into its own members in B.
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
  - A8: the hub cannot write a lead's firewall (it may read it): a lead's
    firewall is the operator's. These lines sit above A6b, so a qube that
    wears a lead badge and an open window's firewall badge, which only a
    mistake in dom0 makes, keeps its firewall the operator's.
  - A6b: the operator's open window. `qmcp open` puts `qmcp-open` on one
    guarded qube, and these lines are the window: the hub runs commands in it,
    and copies a file in with Qubes' own copy, which asks the operator to
    confirm each one. With `--firewall` the second badge `qmcp-open-fw` adds
    the two firewall writes; reading the rules is not here, because A7 never
    denied it. The source is the hub alone, so nothing here widens what a lead
    reaches, and the lines sort below A0 — a qube the gate stopped and a hidden
    project's stay unreachable however they are badged — and below A8, and
    above A7, which they exist to except. These badges are the only gate those services have:
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
  - D5: no `qubes.StartApp` or `qubes.GetImageRGBA` from AI space into any
    qube, `@default` and a named disposable included, dialog or not: nothing
    in AI space needs either, and an allowed GetImageRGBA hands over any image
    the target can read. Qubes' own default file asks for both; OpenInVM and
    OpenURL keep that dialog.
- **E. The hub:** the twelve dom0 services; exec, copy-out and firewall on
  AI space (firewall writes to a guarded qube or a lead were refused in A).
- **F. Copies from AI space:** the operator's dialog, unless A refused them
  (into a guarded, stopped or held qube, the hub, a lead, `@dispvm`, or a new
  disposable of an AI-space template; out of a stopped or held qube), D2 did
  (into dom0), B
  allowed them (inside one slot, or into its sink), or the line at the head of F refused them. That line refuses
  AI space every service into a hidden project's qube, dialogs included (a
  copy, a file or URL opened there, an app started there, a window's image
  read), and sits below B,
  so the project's own lines still decide inside it; a hidden lead's own copy
  into its sink is refused with it, where its members copy without a dialog.
  Every other copy across projects gets the dialog. qrexec turns a target that
  does not exist into `@default`, so the dialog reveals no names.
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
| `qmcp check [--json]` | Fails on: an operator file under `/etc/qmcp` that is not a plain file, that not every user can read (the services and the dom0 user read them; it is judged by the file's mode, so a check run as root fails on it too) or that every user can write; the hub missing, in AI space, or named differently in the policy; tier tags; a gateway in AI space without `qmcp-guarded`; a drop box in AI space; the policy modified, refused by qrexec's parser, or overridden by an earlier file for any of its 54 checked claims; a gateway registry that does not read, or an enrolled gateway that no longer qualifies; a qube in AI space (not a gateway itself) on a network that is not enrolled; a lead with a network whose firewall differs from the rules the operator accepted; services, runtime directory (the per-qube lock directory included) or caps missing; no `qubes` group; a runtime directory (the window records' included), create lock or its turnstile, proposal lock or (in install mode disk) audit log the services cannot write, that is, not group-writable or not the `qubes` group's (an audit log missing, since they cannot create one), or `/run/qmcp` not setgid; the proposal store missing, or not the `qubes` group's, group-writable and setgid; a guarded qube wearing an open badge with no window record, an expired one or one that does not read, wearing `qmcp-open-fw` without `qmcp-open`, or wearing either where `qmcp open` would refuse it (a gateway above all, which the rulebook cannot tell from any other guarded qube); a sealed qube whose kill was not read back (a pending kill); a broken audit chain (the check says to keep the file as the record and start a new log with `qmcp audit rotate`); audit lines that could not be written (`/run/qmcp/audit-dropped`); a caller's counter under `/run/qmcp/calls` that does not read or that the services cannot write (every change of that principal but a kill is refused until it is removed); less than 64 MiB free under `/var/log` (in install mode disk) or on the RAM chains' tmpfs (in modes disk and ram), or free space that cannot be read; an audit mode file or keep-days file that does not read; `qmcp-audit.timer` not running; a RAM chain that does not verify; v0.9.16 leftovers; unreadable project records; a member or lead badge outside AI space, a sink inside it; a qube in two slots; a slot badge with no project; a template or gateway in a project; a qube the hub can reach (in AI space, not hidden) made from a hidden project's disposable template; a lead whose badges and record disagree, or any qube wearing lead badges that is not its slot's recorded lead; a sink that is not its record's; a lead whose project's model is a qube but which has a network; a model badge on a qube with a network, outside AI space, on a member, lead, template, disposable, gateway, drop box or the hub, in p00, on a qube whose template the hub manages, or that its slot's record does not name; a mode file that does not read, and in anonymous mode a project that is not anonymous or a gateway that is not anonymising; an anonymous project, or in anonymous mode the hub, that the gate finds unsound (it runs the gate, and acts on what it finds), the gate's timer not running, in every mode (it also ends windows that have run out and holds restored qubes), and, while an anonymous project exists or the mode is on, no run of it completed in the last 60 s, or one dated ahead of the clock; the gate's lock or heartbeat file missing or not the services group's to write; a qube wearing `ai-managed`, `ai-dump` or a qmcp badge whose `qmcp-id` label is missing or not its own UUID and that the gate has not yet held; dom0's copy of the in-qube services missing. A lead or model qube held for review is the hold's warning, not a failure of the lead or model items. Warns on a qube held for review; a template a project approves, a managed qube's template or a managed standalone whose `qmcp-services` label is missing or not the installed version (dom0's record, not the qube's disk); a guarded qube that is open, with the time it has left — the window is your own deliberate exception and it clears itself, so it is amber and not red; a stopped anonymous project that is sound again, a hidden project sharing an anonymising router with another project or the hub, `qmcp-anon`, `qmcp-blocked` or `qmcp-stopped` where neither an anonymous project nor anonymous mode puts them, a missing `projects.json`, stray badges, v0.9.16 tombstones, qubes outside AI space inside the name prefix, any qube in a project's names that is not its lead or member, managed qubes pointing at a disposable template outside it, a birth-egress qube that is not enrolled, a lead with a network and no accepted firewall, a lead whose endpoint is an address and whose accepted rules still hold the DNS rule set before 0.9.22, a model qube that is not guarded, a recorded model qube that is gone or does not wear its badge, an audit log past 32 MiB, a `qmcp-audit.log.rotating` file left by a rotation that stopped part-way, an install audit mode that is not disk, dom0's journal while any audit mode is not disk (with the drop-in that makes it volatile), keep-days off or, in install mode disk, a full budget for keep-days days that would not fit under `/var/log`, a principal's calls that changed nothing counted rather than logged past 60 in a clock hour, a principal that spent its 20,000 lines of the day or was refused for it (`/run/qmcp/calls/<caller>.refused`), a project without a lead, an approved template that is not one, a worker network that is not enrolled, a member on a network off its project's list, a sink with a network, a qube under a project's default dump sink name (`<label>-dump`, `hub-dump`) that its record does not name and that wears no dump badge (a `qmcp project dump` that did not finish), managed AppVMs and standalones in no slot, project quotas that add up to more than the pool cap, and a proposal that cannot be read or whose accept never finished. Reports each read it could not make, as an error, or as a note on the failure of an item that fails anyway: a qube's tags, network, role, class, template or default disposable template, a qube's `qmcp-id` or `qmcp-services` label or its UUID, a gateway's `qubes-firewall` feature, a lead's firewall, the network of a lead or the hub when a hidden project's shared routers are worked out; and an error when it cannot tell whether `qmcp-audit.timer` or `qmcp-gate.timer` runs, and for a gate run that could not run, or found the gate's lock held past its wait. A qube whose tags cannot be read is skipped by the items that judge tags, the registry item included (the "qube tags" error names it). So is one qubesd says is gone when its tags are read, except an enrolled gateway: the registry item reports that one. The restore check and the anonymity gate read tags again themselves and act on a read that fails: the first reports it, the second blocks the project without a kill. Exit 0 GREEN, 1 FAILED, 3 INCOMPLETE — INCOMPLETE is not green. |
| `qmcp list [--all] [--json]` | AI space with state, class, template, network, power, slot and provenance. A state, class, template, network, slot or provenance that cannot be read is `<unreadable>`, and a power state `NA` or `unknown`; a qube whose tags cannot be read is still listed, and one qubesd says is gone is not. With `--json`, each row adds the lead flag, the slots it serves as a model qube, whether the qube provides network and whether it is a disposable template (each `<unreadable>` when it cannot be read), whether it is open (`open`: the seconds its window has left, `null` when it is not open, `<unreadable>` when its record does not read), and its badges (`null` when its tags cannot be read). `--all` adds every other qube but dom0, with no state. |
| `qmcp settings [--json]` | The operator files the services read (hub, name prefix, pool and private caps, birth egress), how many gateways are enrolled, the disk AI space uses, the mode (`anonymous`, `normal`, or `<unreadable>`), and the version. |
| `qmcp settings set [--pool-cap SIZE] [--private-cap SIZE] [--birth-egress QUBE\|none]` | Change the caps (in a quota's format, `200G`) or birth egress, under the create lock and the records' lock. A pool cap below what AI space holds is refused; birth egress must be an enrolled gateway that is not held for review, `none` unsets it. Each file is written whole; a write that fails prints the changes already made before the error. It cannot change the hub, the mode or the name prefix (an import onto a fresh install brings the export's name prefix). Root. |
| `qmcp template prepare QUBE` / `refresh` | Write the two in-qube services, from dom0's copy, into a TemplateVM or a StandaloneVM as root, and label it with their version (`qmcp-services`): a halted one is started for it and shut down again, and a stop that did not complete is said and exits 1. A lookup that fails is said as such, never as no such qube. Refuses another class, a qube the anonymity gate stopped and one held for review, and refuses, within half a second, while an install or another prepare runs in it. Root. `refresh` (`qmcp-refresh.timer`, every minute, as the gate's user) does the same for every RUNNING prepared qube whose label is behind, never starting one, and leaves one audit line per qube it wrote into, as caller `refresh` (a write that fails goes to the unit's journal and makes the run exit 3, with no line). A template's own disk is up to date at once; the qubes built on it get the new services once it has shut down and they restart. |
| `qmcp template install TEMPLATE PACKAGE...` | Install exact packages, and what they depend on (never recommended or weak dependencies; an install that would remove an installed package is refused, though one may be upgraded when a new one needs it, and on Arch `-Su` may replace a package as the repositories say), into a TemplateVM in AI space, guarded or managed, as root, with its own package manager (apt-get, dnf or pacman, which a probe names by its exit status), from the repositories it already trusts, over its update proxy; a halted template is started for it and shut down again, a running one keeps running (the qubes built on it get the packages once it has shut down and they restart). A name is letters, digits, `.`, `_`, `+` and `-`, a letter or digit first, never a `-` last (apt reads `sl-` as removing `sl`), at most 32 of them. Inside the template, before anything is installed, each must be a package's exact name in its repositories, or the whole install is refused: apt reads a name it does not know that holds a `.` as a regular expression, and dnf a name with a version as that version, a downgrade included (both measured on Qubes 4.3.1 templates). apt-get runs non-interactive and keeps a changed configuration file, as Qubes' own updater runs it, with `--no-install-recommends` and `--no-remove` (with `-y` alone it removes a package that conflicts: measured, `chrony` removes `systemd-timesyncd`); dnf refreshes its metadata first (a name is never refused for lists it could not fetch), takes no weak dependencies, ignores obsoletes, removes nothing (it never does without `--allowerasing`) and takes no `--`, which dnf5 refuses; on Arch it runs `pacman -Sy`, the check, then `pacman --needed -Su` with the names, so the install upgrades the whole template, never a partial upgrade. dom0 decides on the exit status alone; the last 40 lines the package manager wrote follow, escaped, as the template's words, read in bounded chunks, and after a successful install they end with each package's installed version (on Debian, Qubes' own hook lists every pending upgrade after each run, which would otherwise fill them). On Arch, a name refused inside the template leaves its package lists refreshed and the template not upgraded, until its next install or update. Refuses another class, a template outside AI space, one the anonymity gate stopped, one held for review, a hidden project's and one open to the hub (the window's expiry would kill it part-way: seal it first), and refuses, within half a second, while a prepare or another install runs in the same qube (either may shut down a qube it started, which would stop the other part-way). Waits up to 30 minutes; one that does not finish is a failed step that says whether dom0 shut the template down, stopping the install part-way, the shutdown did not complete, or, in a template that was already running, the install may still be running or may have stopped part-way, with the lines written so far. Root. |
| `qmcp restored list [--json]` / `accept QUBE...\|--all` / `reject QUBE` | The qubes waiting for review: each one wearing `ai-managed`, `ai-dump` or a qmcp badge whose label is not its own UUID, held or not yet, and each one held whatever its label says; what its badges make it, and whether that agrees with the project records now (`null`, not known, when the records do not read). `accept` takes the qubes named, or with `--all` every qube held when it runs (after an import), with one audit line per qube it acted on; a qube whose tags or label cannot be read then is named, not accepted, and makes it exit 1, never "nothing is held". It writes the label first and only then lifts the hold, so a failure leaves it held; its badges stay as they came back. `reject` takes every qmcp badge, `ai-managed` and `ai-dump` off, the routed ones first and the hold last, then its label; the qube and its data stay. It refuses the hub, which is the hub by `/etc/qmcp/hub` and not by a badge (a reject would take the gate's stop off it), and any qube while that file does not read. `manage` and `guard` label a qube with no qmcp badge afresh, and refuse a badged one whose label is missing or another qube's; `revoke` refuses a held qube (reject it instead). Both root. |
| `qmcp export [FILE]` / `import FILE` | `export` writes the operator files under `/etc/qmcp` into one JSON file, by default `qmcp-export-<UTC time>.json` in the sudo user's home, mode 0600, never over an existing file: a Qubes backup takes dom0 in as its user's home and nothing else (measured), so a backup with dom0 ticked carries it. It holds the audit log's keep-days and the install's audit mode too; `import` writes keep-days, and only names the mode when it differs from this install's (it is chosen at install: `install.sh --audit-log`), and takes an export from before 0.9.33, which has neither. Not in it: the proposals and the audit chain. It names on standard error every qube waiting for review then (held, or not yet held), and each whose tags or label cannot be read, or says the review could not be read at all, and says to accept or reject them before backing up: after a restore every AI qube is held alike, and `restored accept --all` takes them with the rest. It writes the export either way and exits 0. `import` writes an export back onto a fresh install, the records and the registry through their own parsers and the rest checked by shape, refusing while any project, gateway or p00 sink is recorded (a gateway registry that is exactly the export's excepted: the records are written last, so an import that failed part-way prints what it wrote and is finished by running it again), for an export of another hub, and for an ordinary export onto an install in anonymous mode. An export of an install in anonymous mode goes onto a normal install; `install.sh --anonymous` then turns the mode on once the qubes are restored and accepted. A backup does not carry dom0's update routing: with anonymous projects, send templates' updates through the anonymiser again (Global Config) before the import, since the gate runs right after it. Both root. |
| `qmcp gateway list [--json]` | The gateway registry: each entry, whether it is still usable and why not, its upstream (marked when that is a Whonix gateway, whose clients' firewall rules have no effect), and the qubes and projects that use it. |
| `qmcp gateway enroll QUBE [--anonymising [--updates]] [--label TEXT]` / `set QUBE [--anonymising yes\|no] [--updates yes\|no] [--label TEXT]` / `remove QUBE` | Let AI space use a gateway, change its entry, stop AI space using it. Marking one anonymising records its network as it is then; one with no network is refused, and unmarking one an anonymous project uses is refused. `--updates` ticks it for templates' updates (see "Anonymous projects"); marking it again keeps the tick only on the same network, and taking the tick off is refused where the gate would then stop a project or the hub. In anonymous mode a gateway that is not anonymising is refused, and so is unmarking one. Enrolling refuses a qube that does not provide network, lacks Qubes' `qubes-firewall` marker, is a Whonix gateway, sits on a template the hub manages, is the hub, a drop box, a lead or a member, or is in AI space unguarded; removing refuses while a project lists it or a qube in AI space sits on it, and, for a gateway ticked for updates, where the gate would then stop a project or the hub. Root. |
| `qmcp manage QUBE` / `qmcp guard QUBE [--only-in-ai-space]` | The role actions. Both refuse dom0, the hub (and any name while `/etc/qmcp/hub` cannot be read), a drop box, and a qube (other than a gateway) on a network that is not enrolled; `manage` also refuses a gateway, a qube wearing lead badges, and one wearing a project's member badge that is not a managed qube of that slot (the rulebook routes on badges); `guard` refuses a lead or a member: the lead a project's record names by its project's name, and a qube wearing lead badges that no record names, or any lead badge holder while the records do not read, with the advice to revoke it (`open` does the same). Guarding a model qube that was managed kills it if it runs (never a gateway or a template, whatever badge it wears); a kind that cannot be read stops only the kill, and the command says so and exits 1. In anonymous mode both put `qmcp-anon` on a qube joining AI space (not a gateway) before `ai-managed`. `manage` of an open guarded qube ends its window with no kill: the window's badges come off while it is still guarded, and one that cannot be taken off fails the command, which leaves it guarded and open and says to seal it. `guard --only-in-ai-space` refuses a qube outside AI space (no `ai-managed`) instead of adding it, read under the qube's lock, and a tag read that fails refuses; the window's Guard always sends it, and its Add to AI space does not. |
| `qmcp revoke QUBE [--no-shutdown] [--remove]` | Strips every qmcp badge, pins `default_dispvm` to none, kills the qube if it runs (never only a shutdown request, which a guest the hub ran as root can ignore and a paused one refuses), reads its power state back, and ends an open window (its record goes with the badges). A qube still running after the kill fails the command (exit 1), with its badges already off. `--no-shutdown` leaves it running. Refuses dom0, the hub (and every name while `/etc/qmcp/hub` cannot be read), a drop box, the lead a project's record names and a qube held for review; a qube wearing lead badges that no record names is revoked (so are its badges taken off), and while the records do not read a lead badge holder is revoked too. `--remove` then removes the qube with its storage, which cannot be undone; it kills first, so `--no-shutdown` with it is refused, and before anything changes it refuses a qube outside AI space, a guarded qube (a gateway is one), a qube a project's record names as its model qube, lead, dump sink, approved template or worker network, a qube a model badge marks, a qube another qube (dom0 included) uses as its template, default disposable template or network, a qube a global setting (`qubes-prefs`) names, and a read of any of those that fails. A remove that fails after the revoke (Qubes refuses more than this sees, such as another qube's management disposable) leaves the qube revoked and killed, and exits 1 saying it was not removed. |
| `qmcp open QUBE --for DURATION [--firewall]` | Open a guarded qube to the hub for a bounded time: `qmcp-open` lets the hub run commands in it and copy a file in (Qubes asks you to confirm each file), and `--firewall` adds `qmcp-open-fw`, which lets it write that qube's firewall rules. It can never change the qube's network. Refuses dom0, and every name while `/etc/qmcp/hub` cannot be read. `DURATION` is a whole number of seconds, or one ending in s, m or h (`90s`, `30m`, `2h`), with nothing around it, a space included, above zero and at most 24h; there is no indefinite window, which is `qmcp manage`. Refuses a gateway (its egress rules are AI space's), a managed qube (it needs no window), a lead or a member, a qube the anonymity gate stopped or a hidden project's, and anything outside AI space. Opening a qube that is open replaces its window, and drops the firewall half when this call did not ask for it. The window's end is recorded under `/run/qmcp/open/`, which a reboot clears. Exit 0 opened; 1 refused, or the command could not run; 3 the gate's lock was held past its wait (nothing changed). |
| `qmcp seal QUBE` / `--expired` / `--all` | Close a window. It refuses only a name that is no qube, and dom0; a failed read stops it only when the qube cannot be looked up (its tags, its class or whether it provides network may fail to read), and it takes the badges off a drop box or the hub too, which `open` refuses but a hand-written tag can reach. Named: the record becomes a pending kill (naming the qube's UUID and when it started), the badges come off, and the qube is KILLED if it runs, so what the hub had running in it was stopped — a package manager stopped part-way may leave the qube needing repair, and its files stay, as do the firewall rules the hub wrote through the window's firewall half, which the report says. The record goes once the kill is read back. The hub is never killed, and a pending kill recorded on it while `/etc/qmcp/hub` did not read is dropped by the first pass that reads it; a qube is not killed while `/etc/qmcp/hub` or its class cannot be read: the badges still come off, the kill is skipped and said, and it stays pending. A kill that fails, or a seal cut short after the badges, leaves the pending kill, which every `--expired` or `--all` pass tries again, under the qube's lock when it is had within 2 s, and `qmcp check` fails on until it is made or dropped; a pass drops it, without a kill, once the qube is down, has been started again (when its start time reads, at the seal and now), or is another qube of that name, and leaves one audit line for each kill it makes or drops (a retry that fails again leaves none). `qmcp open` refuses a qube with a pending kill. A qube that was not open is left alone and says so, unless it has a pending kill, which a named seal makes. `--expired` seals every window that has run out, whose record does not read, that sits on a qube `qmcp open` refuses, or on a qube whether it provides network cannot be read (one whose tags cannot be read is sealed when its window record has run out or does not read, only reported when it has time left or no record, and left to the kill's retry when its record is a pending kill); the gate's timer runs it every 15 s; `--all` seals every one whatever its record says (one whose tags cannot be read as under `--expired`: with no record, as at boot, it is only reported) (`qmcp-seal.service` runs it at every boot). Exit 0, or 3 when something could not be judged, a kill is pending (a named seal: its own; a sweep: any), or the gate's lock was held past its wait (nothing changed); 1 when the command could not run, a named seal refuses, its badges could not be taken off, or its second kill after a wait it lost failed. |
| `qmcp project list` / `show NAME` | The slots in use; one project's record. |
| `qmcp project create [LABEL] ...` | A new project in the lowest free slot; with `--anonymous` (and `--hub-sees` for a visible one, `--note TEXT` for a private note) an anonymous project, whose label dom0 picks (see "Anonymous projects"); in anonymous mode every project is one, without `--anonymous`, and a LABEL is refused: `--lead-template T` (with `--lead-class standalone` for a standalone lead), `--lead-clone QUBE` or `--lead-promote QUBE` (one of the hub's AppVMs or standalones); `--lead-name NAME` (a fresh lead's name inside the project's names, default `<names>lead`; refused for an anonymous project); `--lead-netvm` (an enrolled gateway, or none); `--model HOST:PORT` (needed for a lead with a network: its firewall allows only that, and DNS for a host name) or `--model-qube QUBE` (a self-hosted model qube; the lead then has no network); `--template` (more approved templates; the lead's own goes first when it is in AI space); `--network QUBE` or `none` (enrolled gateways), the first the default; `--quota`; `--dump`. |
| `qmcp project edit NAME ...` | Replace the approved templates or the worker networks, or change the quota. Workers keep their networks, so a network a member sits on cannot be taken off the list. |
| `qmcp project lead NAME --remove` / `--lead-…` | Remove the lead (the project keeps its workers), or give the project a new one, with `--model` (else the project's, for a new lead with a network; a remote model takes the project's model qube away first), or `--model-qube QUBE` (the new lead then has no network), or `--model-qube none` (takes the project's model qube away); with neither, a new lead with no network keeps the project's model qube; `--keep-old` keeps the old lead as a worker, on its network if the project lists it, otherwise with none unless `--add-old-network` adds that network to the list. A qube promoted to lead (here or by `project create --lead-promote`) must be shut down: it is refused before the old lead is touched, never killed; a start that shows by the read after its badges change gives it back its place (one Qubes is still preparing then does not: see the residual risks), and what the command did before stays done (an old lead it removed or kept), which it says. A clone's or a promoted qube's template is read again under the locks. |
| `qmcp project firewall NAME [--json]` | The lead's model (an endpoint or a model qube), the firewall rules the operator accepted and its live ones. With `--model HOST:PORT`, `--model-qube QUBE\|none`, `--rule RULE` (repeatable) or `--accept-current`, set a new model endpoint (for a lead with a network; its firewall becomes that endpoint, and DNS for a host name; refused while the model is a qube), a model qube (see "Model qubes") or none, exactly these rules, or accept the live rules as they are, if they are in qmcp's rule format (no comment or expire, at most 32). A write that does not read back as set is undone. Each change needs root. |
| `qmcp project dump NAME` | Create a dump sink for a project, or for p00 (`hub-dump`). A dump sink is always a fresh qube: a qube of that name refuses it, and one that wears no dump badge is named as a `project dump` that did not finish, to remove (`qvm-remove`) before running the command again. |
| `qmcp project unblock NAME` | Clear the anonymity gate's stop once a fresh run finds the project sound; `autostart` stays off. `p00` (or `hub`): the hub's stop, and every qube under the hub's check, once the gate finds the hub sound; in normal mode it takes off the stop badges anonymous mode left (`qmcp-blocked`, `qmcp-stopped`), with no gate run. A qube that cannot be looked up, or in normal mode whose tags cannot be read, is named as not unblocked. Root. |
| `qmcp gate [--json]` | First hold for review every qube wearing `ai-managed`, `ai-dump` or a qmcp badge whose `qmcp-id` label is missing or not its own UUID (the restore check; what it holds goes to standard error), then judge every anonymous project now, and in anonymous mode the hub (its verdict has `hub` and `offenders`), and stop what is not sound (the timer runs this). Prints only what is not sound and what it did, unless `--json`. Exit 0 all sound, 1 one is not, 3 one could not be judged, or the restore check could not run, a hold or a read in it failed, or a hold was made while a call kept the qube's lock past both its waits (said on standard error, as is a qube that a call already running removed, before or after the hold's own write). Runs as any member of `qubes`. |
| `qmcp project move QUBE TARGET` | Move a managed AppVM or StandaloneVM into p00, a project, or no slot. Its network does not change, so a project takes it only with no network or on one of its worker networks; out of one slot into another needs `--yes`, and so does a move into, out of or between anonymous projects, which says first what the qube carries with it. A move is refused if the anonymous project it goes into would be unsound or, in anonymous mode, if the hub's check would stop more qubes or the moved qube itself. A qube the gate stopped does not move. A qube that is not shut down (running, paused, or its power state does not read) moves from one slot to another only once it is: refused, never killed, since a kill loses what is being written; between p00 and no slot, both the hub's, it moves running. Such a move puts `qmcp-blocked` on the qube first (the rulebook refuses every call into it), requires it to read Halted for 10 s, a start admitted just before having time to show, changes the slot badges, and takes the block off last; a start that shows refuses the move, one that lands after the badges changed undoes it, and a step that fails half-way leaves the block on and says so. |
| `qmcp project delete NAME --yes` | Remove the lead and every member, keep the dump sink and the model qube without the slot's badge, strip every badge of the slot, free it. A member of another slot too, a template, a disposable template, a gateway, a model qube, a guarded qube, a dump sink or the hub is kept without the slot's badges. Given a slot with no record, finish a delete that stopped half-way. Without `--yes` it prints, by name, what it would remove, keep and strip, and changes nothing; that needs no root. |
| `qmcp proposal list [--json]` / `show N [--json]` | The hub's proposals, newest first; one proposal with its stored options, the command it is the options of (an edit shows its project before and after instead; a lead-firewall proposal adds the lead's model and rules now and after), why it needs the second tick, the plan of a delete, and its decision and report once decided. Reads, as any member of `qubes`. |
| `qmcp proposal accept N --sha256 F [--yes TICK]` | Run proposal `N`'s command as the operator, if its stored file still hashes to `F`; `--yes TICK` is the second tick, the tick `show` gave for the reasons it showed, refused if those reasons have changed. Expiry is judged once the locks are held, and the decision is stamped when it is written. A read that the check for a hidden project's names needs and that fails refuses before anything runs, and the proposal stays pending. Root. |
| `qmcp proposal reject N` | Close it without running anything. Also closes a proposal that needs closing: an unreadable one (rejected), one whose accept never finished, and one whose decision file does not read (both `failed`; the unreadable decision file is kept beside the new one). Root. |
| `qmcp migrate [--apply]` | v0.9.16 tiers to two states (below). Dry run by default; `--apply` is root. It writes no `qmcp-id` label (the installer labels a v0.9.16 fleet). It refuses a qube held for review and, once any qube in scope carries a label, one in scope whose label is missing or another's; the installer's own check of the fleet's shape does neither. |
| `qmcp audit verify` / `tail` / `rotate` | The chain. `rotate` starts a new log anchored on the old head and keeps the old one beside it under a dated name: the new log is written in full first, so there is no moment with no log at its path, in which a writer would start an unanchored one. It frees no disk until the old file is moved off or removed. Refused unless run as root. |
| `qmcp audit rotate --auto` | What `qmcp-audit.timer` runs every hour, as root: rotate the log when its first line is from an earlier UTC day (and it holds more than the last rotation's anchor) or it is past 32 MiB; then rotate each RAM chain past 8 MiB and remove the oldest rotated RAM files while the files under `/run/qmcp/audit` hold more than 64 MiB, even when the keep-days file does not read; then remove the rotated logs (`qmcp-audit.log.<UTC time>`, exactly that name) older than the keep-days setting, by the time in their names, never by their size. Writes a line only for what it did. The log is not rotated in install mode ram or none. A rotation by hand (`qmcp audit rotate` without `--path`) rotates the install's own log: the log on disk, or in mode ram its RAM chain; in mode none, or when the mode file does not read, it is refused and nothing is rotated. Exit 1 when the mode file does not read (the log is not rotated), when the keep-days file does not read (no rotated log is removed), or when a file could not be rotated or removed. Root. |
| `qmcp audit status [--json]` | The window's gauge: the install's mode and keep-days, the log's size, the rotated files, the RAM chains and their rotated files (`ram` in the JSON), the free space under the log against the 64 MiB floor, the principals (the hub and every recorded lead) and the room a full budget for keep-days days needs, and the lines today against the 20,000 of each caller with a counter (one that has made no state-changing call since boot is not listed). A value that does not read is `null`, never 0. `verify` and `tail` read the install's chain: the log, or in mode ram its RAM chain (`--path` reads any other). |
| `qmcp project audit LABEL disk\|ram\|off` | Where the project's audit lines go from now (above), while it runs or not: the record's `audit`. Leaves one line on the install's chain naming the slot only, and leaving disk says that the old lines stay on dom0's disk and that deleting a file there is not erasing it. Root. |
| `qmcp settings set --audit-keep-days N\|off` | How long a rotated audit log is kept, 1 to 36500 days, or off: never removed. Carried by `qmcp export` and written back by `qmcp import`. Root. |

Every `qmcp project` command that changes something needs root: it writes
`/etc/qmcp/projects.json` under a lock, by atomic rename, or (`move`,
`unblock`) takes that lock. So do `qmcp proposal accept` and `reject`. Every
command that changes something leaves one line on the audit chain as caller
`operator` (the command, the names it acts on and its options; a quota only as
"set"), but `restored accept --all`, which leaves one per qube it acted on (one
naming none when nothing was held), and what dom0's passes do: the anonymity
gate and the restore check log as caller `gate` (also when `qmcp gate`,
`qmcp check` or another command runs them), the refresh as `refresh`, and
`seal --expired` and `--all` one line per window they close or fail to close
and per pending kill they make or drop, none when they find nothing. Reads, plans and dry runs
leave none, and neither does a command the argument parser refuses, or one of
its usage checks that exit the same way (`migrate`'s `--map`, `restored`'s
names or `--all`, `seal`'s qube or flag), or one refused for not running as
root; one its own checks refuse, a malformed `--quota` or lead name among
them, leaves a line with `ok` false.

## The operator's window (dom0)

`qmcp-gui` is the `qmcp` command as a window: in the Qubes menu under
Settings > Qubes Tools, or in a dom0 terminal. Run it as your own dom0 user;
it refuses to run as root.

- **It runs the `qmcp` command and nothing else.** Every read is `qmcp ...`,
  run as you, in JSON wherever the command offers it, and stopped after 120 s,
  but for `qmcp gate` and `qmcp check`, which act: at 120 s the window stops
  waiting for those and lets them run to their end, so a stop is never cut off
  half-way;
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
  there), a drop box or the hub inside AI space, slot badges outside it, a
  sink badge that is not its record's sink, an open window's badge outside it (Seal is offered there), a qube
  in two slots, a template in a project, a model badge on a template, gateway,
  member or p00 qube, a model badge no record names, a model qube with a
  network or on a template the hub manages, and a lead with a network whose
  project's model is a qube; a qube held for review (`qmcp-quarantine`), or one
  the restore check lists and the gate has not held yet, with its row of
  `qmcp restored list` in the details pane and Accept and Reject; and a qube
  whose tags, class or role could not be read, which offers nothing. A
  template or standalone row offers Prepare, unless the gate stopped it or it
  is under Needs attention; a template's row in AI space also offers Install
  packages, a form with a field for the names that shows the command as they
  are typed and refuses, before OK, a name or a template the command would
  refuse.
  Every other failure of `qmcp check` is on the Check tab. Beside the tree, the
  selection's every field, and the actions that fit it. The light is
  `qmcp check`'s result with the time it ran; the Check tab lists its findings,
  failures first. The Audit tab shows the last 200 lines, newest first, the
  selected one in full, and verifies or rotates the chain. It holds the calls
  the hub and the leads make to state-changing services, every command of the
  operator's that changes something (caller `operator`, accepting and
  rejecting proposals included), what dom0's own passes did (the gate's holds
  and stops, as caller `gate`, the refresh's writes, as caller `refresh`, and
  each window a sweep closed), and the line each rotation starts a log with,
  which names the file the earlier lines moved to. The Settings tab shows
  `qmcp settings`, the mode included, with Edit settings (the pool cap, the
  private-volume cap and birth egress; the command cannot change the hub, the
  mode or the name prefix), Export (a full path, or empty for the default) and
  Import (a full path; it says in red that it is for a fresh install and what
  comes after it). The Check tab
  has Prepare a template (any TemplateVM or StandaloneVM, those outside AI
  space included, which have no row) and Accept all held, which names the held
  qubes it shows and accepts exactly those. The Gateways tab lists the gateway registry:
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
  one-time step from v0.9.16), `restored accept --all` (Accept all names the
  qubes it shows) and what the timers and the boot unit run, is a
  form: create, edit and delete projects, change or remove a lead, add a dump
  sink, move a qube between slots, manage, guard, revoke (with a Remove tick, which says in red that it cannot be undone), add a qube to AI
  space, accept or reject the hub's proposals, enroll, change and remove
  gateways, set a lead's model endpoint, model qube or rules or accept its live
  rules, rotate the audit log, prepare a template or standalone, install
  packages into a template, edit the settings, export and import, and accept
  or reject a restored qube. The forms offer as a
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
  would refuse for a reason it can see in its own fields or in the view (a
  kept lead's name, a label already taken, a new project with no approved
  template in AI space, a lead held for review, say), before anything runs. A lead's name is typed after the project's name
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
  project sound; on the hub's verdict it runs `qmcp project unblock p00`. In
  normal mode a qube still wearing `qmcp-blocked` or `qmcp-stopped` from
  anonymous mode (the hub, or one in AI space or p00 that no anonymous project
  owns) offers Unblock too, which runs `qmcp project unblock p00` with no
  verdict to wait for, as the command takes it then.
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
  everything, but Seal, Revoke (without Remove), Guard and Reject restored,
  which only take authority away and whose commands decide for themselves. Guard is one
  because the window sends `qmcp guard --only-in-ai-space`, which refuses a
  qube revoked since the view was read instead of adding it to AI space
  (Add to AI space, which does add one, stays off). Revoke on a
  qube that left AI space since the view was read still sets its default
  disposable template to none and kills it if it runs. A view goes
  stale when a refresh starts: from then until it lands, after every change,
  the same holds. A form opened on an older view refuses at OK unless it
  re-checks what it shows against the view as it is then; the four forms
  that only take authority away run on any view. The light and the Check tab always show the latest check, which
  judges the fleet by itself, or UNKNOWN if it did not answer. Before the first
  complete refresh, nothing that needs the records (a lead's standing, a slot
  left without one) is judged until they are read.
- **Text from AI space is shown as text.** The audit log keeps the names, keys
  and options of every call the hub or a lead makes to a state-changing service
  (never a value being set), refused calls included but those refused at or
  before the caller check, by the free-space floor, below it (a kill), past
  a caller's 60 calls that changed nothing in a clock hour, or past its daily
  budget, up
  to 128 characters each
  and before they are checked, but for a refused call's names of qubes it did
  not judge within its caller's reach, which it records as `<out-of-reach>`. The window shows every string as the command's JSON does: ASCII,
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
- **Manage on the model qube of an anonymous project** says in red that it
  stops the project: the anonymity gate needs that model qube guarded, so it
  blocks and kills the lead and members when the command ends, or at the
  gate's next pass, within about 15 s. The model qube itself stays managed,
  and the hub may operate it as any managed qube until it is guarded again,
  unless the project is hidden.
- **Closing the window while a command runs** asks first: the command does
  not stop, it runs to its end unseen, and a change's line on the audit log
  says how it ended (a command whose output nobody reads any more still
  records its own outcome, not a failed print).
- **It refreshes** when it opens, after every change, and when you press
  Refresh; there is no timer, and the light says when the check last ran.
  Each refresh runs `qmcp gate --json` first, alone, and every other read
  after it, so what they show includes what the gate just did; a gate read
  that fails keeps the last verdicts on show and turns changes off, as any
  failed read does (but Seal, Revoke without Remove, Guard and Reject restored).
- **The audit log's gauge and modes (0.9.33).** The Audit tab shows
  `qmcp audit status --json` above the lines: the install's mode and keep-days,
  the log and its rotated files, the RAM chains, a bar of the free space against
  the floor and one per principal of its budget used today; it is shown from
  its first good read; after the first complete refresh it changes only on a
  complete refresh, and it says "not read" before any read. Settings shows the
  install's audit mode, read-only (`install.sh --audit-log` sets it), and Edit
  settings has a keep-days field, sent only when changed. A project's Audit
  log... form sets its mode; leaving disk says in red that the old lines stay on
  dom0's disk and that deleting a file there is not erasing it. `audit --auto`
  is exempt from the parity check: the timer runs it.
- **It cannot go stale.** `tests/test_gui.py` walks the command's parser and
  the fields of every read, and fails on any command, option or field the
  window neither offers nor exempts by name, with a reason. The exemptions
  today: `migrate` and `audit --path` (typed by hand), `seal --all`,
  `seal --expired`, `template refresh` and `audit rotate --auto` (run by the
  boot unit and the timers, never by a person), `restored accept --all` (typed after an import;
  the window names the qubes it showed), and `project show` and `version`,
  which the window shows from other reads.
  `tests/GUI-CHECKLIST.md` is the click-through for a person.

## Install, migrate, uninstall

The installer runs as root in dom0, so the tree it runs from must come from
somewhere AI cannot write. A tree copied out of the hub is only as
trustworthy as the hub. Fetch a tagged release in a fresh disposable (any
disposable template with curl and network; Qubes' stock `default-dvm` has both):

```sh
# in dom0
qvm-run --dispvm=default-dvm --pass-io \
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.36.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh   # --hub, --birth-egress, --pool-cap, --private-cap, --gate-user, --anonymous, --updates-via, --dry-run
```

`install.sh` runs every preflight check before it changes anything: its options
must be well-formed, the fleet must be in the two-state shape, existing project
records and gateway registry must load, the rendered policy must parse on this box and decide
each of the 54 claims itself, and the gate, as this release judges, must not leave an anonymous
project, or (with `--anonymous` or in anonymous mode) the hub, stopped only for want of an updates
tick: the entry is named, with `--updates-via GATEWAY` to tick it in the same install. One unsound
for another reason is noted, except the hub when `--anonymous` turns the mode on, which is
refused. It removes what v0.9.16 installed, backs up the policy, the
services, `/etc/qmcp`, the library, its tmpfiles file and the gate's, the
refresh's and the audit rotation's units under `/var/lib/qmcp-rollback/` (the command, the window, its
menu entry, the seal's unit and its drop-in are written from the release with
no copy, and v0.9.16's units are removed with none), writes an empty
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
window open under lines that would honour it, keeps dom0's copy of the
in-qube services in `/usr/local/lib/qmcp/template-rpc/`, installs
`qmcp-refresh.timer` (as the gate's user) and root's hourly `qmcp-audit.timer`
with its `qmcp-audit.service`, on an upgrade from a release before
0.9.26 (v0.9.16, which wrote no version file, known by the files it installed),
or a reinstall over the operator files a plain `uninstall.sh` of one
kept (when no qube carries a label or a hold yet), labels every qube already wearing
`ai-managed`, `ai-dump` or a qmcp
badge that has no label and is not held with its own UUID (once, while the gate's timer is
stopped; a fresh install seeds none, since a badged qube with no label of its
own there came back from a backup or a copy, or was badged by a release before
0.9.26 and kept through `uninstall.sh --purge`, and with `--anonymous` it labels
only the hub, as it gets `qmcp-anon`), writes the version file after that seed
and leaves a marker until then, so a seed that did not finish runs again on the
next install (after an `uninstall.sh` in between, the gate holds what it
missed),
installs the policy
after the code, with `--anonymous` then puts `qmcp-anon` on the hub and on every qube under its
check, writes `/etc/qmcp/mode` and puts it on once more, for a qube the hub
made meanwhile, all under the gate's lock so no gate run judges in between (an
update in the mode puts it back where it is missing), sets every operator file under `/etc/qmcp` that is a plain file to 0644 (one written with `tee`
under sudo comes out 0600 under dom0's umask), runs the gate once, and exits
with the status of `qmcp check`, which it runs as the gate's user, as the
operator does, not as root. Besides `qmcp-anon`, the open badges
the seal takes off, and what the gate's run and the closing `qmcp check` hold
or stop, it changes no qube tag. `uninstall.sh` removes the policy first (so no AI
caller reaches a half-removed service), then everything else, and ends with a
clean-state check that names what it keeps; `--purge` also removes
`/etc/qmcp`, the proposal store `/var/lib/qmcp`, the audit log and its rotated
files, so it is also what turns anonymous mode off. Backups under
`/var/lib/qmcp-rollback/` are never removed, nor is `/var/log/qmcp-changes.log`,
the change history some older installers kept. Qubes keep their tags: after
anonymous mode, remove `qmcp-anon` from the hub, or `qmcp check` fails on it.

**From v0.9.35**: install. **breaking:** the lifecycle service refuses the hub
and a lead `remove` for a qube with no `qmcp-owner_*` badge (above); the hub
asks with a `qube-revoke` proposal with `remove`, and `qmcp revoke QUBE
--remove` does it by hand. To roll back to 0.9.35, run this release's
`uninstall.sh` before 0.9.35's installer; a revoke proposal with `remove`
that is not yet decided (pending or expired) then reads as unreadable, and
`qmcp proposal reject N` closes it.

**From v0.9.34**: install. `qmcp export` names every qube waiting for review,
and each whose state cannot be read, and is written all the same; the gate's
timer also removes the in-qube writer lock and the call locks of a name qubesd
no longer lists (never a counter), though an in-qube lock 0.9.34 made is
root's and 0600 and stays until the next boot; the in-qube services item says "another
version" for a label that is not the installed version, which after a rollback
is a newer one. To roll back to 0.9.34, run this release's `uninstall.sh`
before 0.9.34's installer (not drilled for this release; the uninstaller is
unchanged since 0.9.33).

**From v0.9.33**: install. The installer sets every operator file under
`/etc/qmcp` that is a plain file to 0644, so a keep-days file written with the v0.9.32 note's `tee`
line (the note for upgrading from v0.9.32), which dom0's umask made 0600 when
it created the file, reads for the dom0 user again; `qmcp check`
fails on an operator file not every user can read, as root too. A refused
call's audit line no longer names or follows a qube out of the caller's reach
(`<out-of-reach>`, placed by the caller), and a lifecycle call with an unknown
action checks its qube first, so for a qube out of reach it answers `not
found`. To roll back to 0.9.33, run this release's `uninstall.sh` before
0.9.33's installer (not drilled for this release; the uninstaller is unchanged
since 0.9.33).

**From v0.9.32**: see the v0.9.33 note too. **breaking:** within the hour after the install,
`qmcp-audit.timer` removes rotated audit logs older than 90 days, the new
default. 0.9.32's `qmcp settings set` has no option for it, and the installer
leaves the setting's value alone, so to keep them, write it before installing:
`echo off | sudo tee /etc/qmcp/audit-keep-days` (or a number of days). Then install. The two in-qube services change (a timeout of at
most a day that kills the command's whole process group, and a copy that takes
its timeout from `qubes_copy`), so `qmcp check` warns on every prepared
template and standalone qmcp runs commands in until the refresh, or `sudo qmcp template prepare
QUBE`, brings it up to date; `qmcp check` fails in every mode while
`qmcp-gate.timer` is not running; `qubes_firewall_set` answers ok, with
`reloaded` false and a warning, when it saved the rules but the reload failed;
the rulebook refuses `qubes.StartApp` and `qubes.GetImageRGBA` from AI space
into any qube, which Qubes' own policy put to a dialog, and checks 54 claims.
To roll back to 0.9.32, set every project back to disk (`sudo qmcp project
audit LABEL disk`) and copy out the RAM chains under `/run/qmcp/audit` you
want to keep, since `uninstall.sh` removes `/run/qmcp` and them with it; run
this release's `uninstall.sh`, then 0.9.32's installer. 0.9.32 ignores `/etc/qmcp/audit-mode` and `/etc/qmcp/audit-keep-days`: it
writes every line to disk and removes no rotated log.

**From v0.9.31**: install, then see the v0.9.32 note. A principal's calls that changed nothing, past 60
in a clock hour, are counted rather than logged, and its changes past 20,000
lines a day are refused; `qmcp check` warns on both; `qmcp project delete` keeps a qube that is also another slot's
member, or is a template, a disposable template, a gateway, a model qube, a
guarded qube, a dump sink or the hub, and its plan names every qube; the window keeps Seal, Revoke and Reject restored on when a read
fails. To roll back to 0.9.31, run this release's `uninstall.sh` before
0.9.31's installer.

**From v0.9.30**: install, then see the v0.9.31 note. A qube that changes slot (but between p00 and no
slot), or becomes a lead, does so only once it is shut down (nothing is
killed), and such a move waits 10 s under `qmcp-blocked` to be sure it stays
so; an accepted `qube-manage` refuses a template that a qube the hub does not
operate (outside AI space, or guarded) is built on, and `qmcp manage` a qube
wearing lead badges; the services refuse every change but a kill while less
than 64 MiB is free under `/var/log`, and `qmcp check`
fails on audit lines that could not be written; `qmcp restored reject`
refuses the hub; `qubes_run_disposable` answers ok only once its disposable
is read back halted or gone, and every MCP tool can answer "reply too large". To roll
back to 0.9.30, run this release's `uninstall.sh` before 0.9.30's installer.

**From v0.9.29**: install, then see the v0.9.30 note. Nothing in AI space
reaches a hidden project's qubes from outside it any more, not even through a
dialog (a hidden lead's dialog copy into its own sink goes with it); `qmcp
seal` takes an open badge off a drop box or the hub, and a seal whose kill
fails is tried again and fails `qmcp check` until it is made or no longer
needed. To roll back to 0.9.29, run this release's `uninstall.sh` before
0.9.29's installer.

**From v0.9.28**: install, then see the v0.9.29 note. `qmcp revoke`, an accepted `qube-revoke` and
`qubes_run_disposable` now kill the qube rather than ask it to shut down, and a
revoke whose qube still runs afterwards exits 1; the anonymity gate kills a
stopped project's qube it finds running on every run, so a qube of an unsound
anonymous project can no longer be started by hand to look at it; the services
and the role commands share a lock per qube under `/run/qmcp/qubes/`, which the
installer's tmpfiles creates; approving a disposable template for a hidden
project is refused while the hub can reach a qube made from it. To roll back to
0.9.28, run this release's `uninstall.sh` (it keeps `/etc/qmcp`) before
0.9.28's installer.

**From v0.9.27**: install, then see the v0.9.28 note. Besides the three new proposal types and `qmcp
template install`: the role actions and `qmcp open` refuse dom0, and every
name while `/etc/qmcp/hub` cannot be read (a seal then still takes a window
off and only skips the kill); `qmcp template prepare` refuses while an
install or another prepare runs in the same qube; `qmcp manage` of an open
qube ends its window with no kill, and `qmcp revoke` clears its record; an
accept interrupted while its command runs is recorded as failed; the window's
proposal list heads its subject column "Subject". To roll back to 0.9.27, run
this release's `uninstall.sh` (it keeps `/etc/qmcp`) before 0.9.27's
installer; a pending proposal of a new type then reads as unreadable, and
`qmcp proposal reject N` closes it.

**From v0.9.26**: install, then see the v0.9.27 note. The hub's clones land where their source is (see
Projects): one of a project's member must now be named inside the project's
names and fit its quota, and one of a qube in no slot joins no slot instead of
p00. A clone, a lead cloned from one of the hub's qubes included, no longer
copies its source's device assignments, menu entries or a disposable
template's `preload-dispvm-max`; a clone is refused when its template is
stopped by the gate, waits for review, or, for a lead, is off its approved
list, and the hub's clone into a project must sit on its worker networks.
Every create refuses to copy or build on a qube in AI space whose `qmcp-id`
label is not its own. To roll back to 0.9.26, run this release's `uninstall.sh` (it keeps
`/etc/qmcp`) before 0.9.26's installer. A pending proposal stored with `lead_class`
then reads as unreadable, and `qmcp proposal reject N` closes it; standalones
made meanwhile keep running, but 0.9.26's `project move` refuses one.

**From v0.9.24 or v0.9.25**: install. The installer labels AI space for the
restore check. Then prepare each template and standalone `qmcp check` names
under "in-qube services" (`sudo qmcp template prepare QUBE`, once each): dom0
has no record of what an earlier install loop wrote into them, so the check is
amber until it does. Rolling back to 0.9.25 needs every held qube accepted or
rejected first (0.9.25 does not know `qmcp-quarantine`), then this release's
`uninstall.sh` (it keeps `/etc/qmcp`) before 0.9.25's installer; the labels
stay on the qubes and nothing older reads them; upgrading again holds each qube
that 0.9.25 cloned meanwhile from a labelled one, for review.

**From v0.9.23**: install, then see the v0.9.24 note. An anonymous project whose templates update
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
warns until you do. The hub's spawns and clones must be named `ai-hub-…` (from
0.9.27, a clone of a project's member is named inside that project's names
instead).
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
v0.9.20 note gives after its install. v0.9.16 wrote no version file; the installer knows it by
the files it installed, and labels AI space for the restore check as on any upgrade.

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
| `tests/test_dom0.py` | anywhere with python3-qrexec | the dom0 library against `tests/fakequbes.py`, a fake qubesadmin that copies tags, features and properties on disposables, and on a hand clone (`clone_vm`, tags one by one in sorted order), as the platform does, and copies a root as its qube last stopped |
| `tests/test_projects.py` | anywhere with python3-qrexec | projects against the same fake: who is a lead, what a lead sees and does (and at what cost), what the hub's creates join, where a clone lands, standalone workers and leads, and every `qmcp project` command but `firewall` (`test_gateways.py`, `test_models.py`) and `unblock` (`test_anon.py`, `test_mode.py`), and the project check |
| `tests/test_gateways.py` | anywhere with python3-qrexec | the gateway registry, the networks AI space may use, leads' firewalls and their proposal, against the same fake |
| `tests/test_models.py` | anywhere with python3-qrexec | model qubes and model endpoints against the same fake: the one command and the order it changes authority in, each refusal, sharing, creates and lead changes, the check's findings, what the lead and the hub are told, the record, proposals, and the DNS rule an address endpoint no longer gets |
| `tests/test_anon.py` | anywhere with python3-qrexec | anonymous projects against the same fake, with dom0's update question asked of qrexec's real parser: each gate condition broken on its own from a sound project, the block in its order, a read that fails once and twice, unblock, hub-blind services answering as for a missing name (`test_dom0.py` pins the cost), the commands' refusals, and proposals |
| `tests/test_mode.py` | anywhere with python3-qrexec | anonymous mode against the same fake, with the update question asked of qrexec's real parser (and of our rulebook, for a stopped qube): the mode file, the updates tick, the hub's check and what each violation stops, unblock p00, the hub's creates and proposals in the mode, and moves into, out of and between anonymous projects |
| `tests/test_operator_tools.py` | anywhere with python3-qrexec | 0.9.26's and 0.9.28's tools against the same fake: `template install` (each package manager's script, the shape of a name, every refusal before anything runs, a name the template refuses, a failed, hung or endless install, the escaped tail), `template prepare` and the refresh (what is written, what is never started or written into, a write that fails or hangs), the restore check (every create labelled, a restored or hand-copied qube held and refused by the services and the commands, review, accept and reject in authority order), `settings set`, export and import, their audit lines, and the installer's seed: when it runs, its place while the gate's timer is stopped, and its own program on both paths, run again after it stopped part-way |
| `tests/test_proposals.py` | anywhere with python3-qrexec | proposals against the same fake: who may submit, the shape, the store, the second tick, accepting and rejecting through the real commands, an accept that never finished, the operator's audit lines, and the qube types: managing, revoking (never a qube outside AI space, never dom0), installing (with no project lock held), and a hidden project's qube named by one |
| `tests/test_interleave.py` | anywhere with python3-qrexec | 25 pairs of operations (a hub's call against an operator command, two commands, two calls, an accept against an accept or a reject) run at once on the same fake: each pauses the first at every qubesd call it makes, runs the second in a thread with real lock waits, and fails unless the end state, and what each side was told, is one some serial order gives, with no new authority, no deadlock and no lock taken in the other order (`tests/racefixture.py`) |
| `tests/test_crashpoints.py` | anywhere with python3-qrexec | 41 state-changing operations (the hub's and leads' service calls, the role actions, windows, project, gateway and settings commands, the restore check and accepted proposals) interrupted at every qubesd call, by a failure the code handles and by a death it cannot: no qube gains authority or loses a restriction, none is lost, a state between before and after is named by `qmcp check`, and no failed change reports success |
| `tests/test_audit_modes.py` | anywhere with python3-qrexec | where audit lines go (the install's and the projects' modes, the place read before and after a call), the budget and the room for lines kept nowhere or in RAM, rotation, removal by age and the RAM chains' bound by size, and their wiring (the timer, the installer, `qmcp check`) |
| `tests/test_strict_reads.py` | anywhere with python3-qrexec | a failed read is never an answer: each read of each key failed in turn, and the dom0 source walked for a read with a default |
| `tests/test_server.py` | anywhere | the MCP server and CLI against a fake qrexec client |
| `tests/test_inqube_services.py` | anywhere | the two in-qube services run as a qube runs them, with a fake `qvm-copy-to-vm`: the timeout and the process group it kills, the target's shape, the path, and `--` |
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

- **A compromised hub controls every managed qube, lead and worker but a
  hidden anonymous project's;** guarded qubes it may only read, but through a
  window you opened, and held or stopped ones not at all: it
  runs commands in leads and workers, so it can read a lead's model key. The
  audit log records what it does through the dom0 services (past 60 calls
  that changed nothing in a clock hour, those are only counted); its exec,
  copy-out and firewall writes are not on that log.
- **A compromised lead controls its own project:** every worker, and through
  them what lands in its sink. It reaches another project or the hub's qubes
  only through the operator's dialog (a copy, or Qubes' own asks to open a
  file or URL), never a hidden project's and never the hub, and dom0 only through its nine services, the
  firewall methods on its own members and the boot and report services every
  AI qube has, and every create it makes stays inside its name
  space, templates, networks and quota. Give each project its own model
  key with a spend limit.
- **Qubes' own open dialogs still reach across projects.** This rulebook
  leaves `qubes.OpenInVM` and `qubes.OpenURL` from AI space to Qubes' default
  policy, which asks: a worker or a lead can put a dialog in front of you that
  opens its file or URL in another project's qube, one of yours, `@default` or
  a new disposable of a template outside AI space. Into a hidden project they
  are refused, and an anonymous project's qube opens no file or URL
  elsewhere; `qubes.StartApp` and `qubes.GetImageRGBA` from AI space are
  refused everywhere (D5). Decline such a dialog unless you started the
  action.
- **Commands already running outlive a change of role.** When a lead is
  removed, commands it started in its project's workers that are still
  running are not ended, and when a qube other than a model qube is guarded,
  commands the hub started in it run on until it stops. Kill the qube
  (`qvm-kill QUBE`) or revoke it to end them.
- **A window's firewall half outlives it.** A seal takes the hub's authority
  away, not what it wrote: firewall rules it set through `--firewall` stay on
  the qube, and the seal's report says so (`qvm-firewall QUBE` lists them).
- **The remove refusal tells the caller one bit of provenance:** that a qube
  it already operates wears no owner badge (qmcp did not make it, or it was
  revoked since). The tag read behind it shows the
  caller nothing else; `qmcp-owner_*` stays out of every read.
- **Root in a managed qube can still destroy its data** without removing it:
  the hub runs commands in the managed qubes it operates, and a lead in its
  members. Keep
  a backup of any qube you bring into AI space; volume revisions only help
  across a shutdown.
- **Copies inside a slot need no dialog.** A compromised worker can drop files
  into every member of its project and into its sink, and one of the hub's
  qubes into every p00 qube. Files land in `QubesIncoming` and are not run.
- **The rulebook matches badges, not records.** A slot badge on a qube outside
  AI space would let that slot's lead reach it; `qmcp check` fails until it is
  removed, and only the operator can put it there.
- **A lead learns its own project:** the names in its name space (through a
  create collision, including any qube named inside it or moved out of it,
  which `qmcp check` lists), its approved templates, its worker networks and
  its model qube by name; and, through a copy, or a file or URL opened in the
  guessed qube, which is refused at once where a missing name gets the dialog,
  whether a guessed name (another project's `ai-<label>-lead`) is a lead, a
  guarded qube, the hub, a hidden project's qube, or a qube held or stopped, at
  the cost of a dialog when it is not. An anonymous project's lead has only the
  copy: the rulebook refuses it every file or URL opened in another qube.
- **Busy leads can delay the others.** A lead holds at most 4 dom0 calls and
  all leads 16, so four leads at their limit leave the rest refused as busy
  (the hub's calls are never in that pool); and a lead's create holds the one
  create lock every create waits on, the hub's included.
- **A lead refused by the pool cap inside its own quota** learns that the rest
  of AI space is full. `qmcp check` warns when the projects' quotas add up to
  more than the cap.
- **A lead's call still running 60 s after its removal starts waiting for it
  can finish after the removal**: the removal waits that long for the lead's
  calls already past their check, then goes on and says so. Such a call was checked while the lead had its
  badges.
- **A hub's calls already past a qube's turnstile go before the operator's
  command on it**, so a grant command can still refuse if they outlast its
  wait (60 s; `open`'s is 5 s); calls arriving after the command wait behind
  it.
- **A qrexec call admitted just before a revoke, a seal or the gate's stop can
  start the qube once more after the kill**, since qrexec starts a halted
  target after its decision. For a revoked qube, which nothing in qmcp watches
  afterwards, that start runs what the call asked for and whatever the hub left
  to start from its disk; the revoke's own kill reads the qube back, but a
  start that lands later is not seen. After the gate's stop, its next run kills
  such a start, within about 15 seconds; after a revoke or a seal, nothing
  does.
- **A disposable template's home directory reaches every project that may
  spawn from it.** Keep project data out of disposable templates that several
  projects use.
- **A promoted lead keeps its history:** its files and whatever networks it
  was on. A cloned lead starts with its source's files, on the network it is
  given; a fresh lead starts empty.
- **A standalone keeps what its agent leaves.** An AppVM's root comes back
  from its template at every start, and only `/rw`, `/home` and `/usr/local`
  persist; a standalone keeps its whole root, so whatever a compromised agent
  installs there survives a restart. A standalone made from a template is a
  copy of its root as of the template's last shutdown: later updates to the
  template do not reach it.
- **The audit log grows between rotations.** The hourly timer rotates it daily
  or past 32 MiB, and removes rotated files only by age; a compromised
  principal can fill it faster, within its daily budget (below). Below 64 MiB free under
  `/var/log` the services refuse every state-changing call but a kill (logged
  only when dom0 accepted it), so their changes stop well before the disk is
  full (commands the rulebook lets the hub run in its qubes go on, and kills
  still add lines: see below), and the floor tells a caller that dom0 is short of disk.
- **A hidden project that takes a disposable template the hub could see tells
  the hub so:** the template leaves the hub's list when the project takes it.
  Its contents stay hidden; the command warns. A disposable template made for
  the project alone still leaves the hub's list, and the command still warns,
  but it tells the hub only that a hidden project took a new template, not
  which of the ones it used.
- **A start Qubes prepares for longer than 10 s can outlast a move's check.**
  qrexec starts a halted target when a call is admitted, without the qube's
  lock, and the qube reads Halted until its domain exists, which waits for a
  halted network qube above it to start first. A move blocks new calls, waits
  10 s and undoes itself on a start it sees afterwards, but one still being
  prepared past both reads lands in the new slot. The same start can land in a
  disposable that `qubes_run_disposable` has just read back halted, and a
  server killed with SIGKILL ends none of its disposables.
- **Each principal can add up to about 14 MiB of audit log a day:** 20,000 lines of changes (about 350 bytes each, about 7 MiB) and
  60 lines an hour of calls that changed nothing (a refused call keeps its
  fields up to 128 characters, escaped, so such a line can reach about 5 KB:
  up to about 7 MiB more). With the hub and all 15 leads at that rate the log
  grows by roughly 225 MiB a day. That is a rate, not a total: rotated files
  are removed only once older than the keep-days setting (90 days by
  default), never for their size, so at a steady rate high enough for long
  enough the log reaches the 64 MiB floor first, and below it every
  principal's changes are refused but a kill; `qmcp check` warns when a full
  budget for that many days would not fit. Below the floor an
  accepted kill is logged within the budget, and past the budget under the
  hourly cap, like any other line of that principal.
- **RAM chains are bounded by size, not by age.** The hourly run removes the
  oldest rotated RAM files while the files under `/run/qmcp/audit` hold more
  than 64 MiB, so a principal that floods a RAM chain can push earlier lines
  of that chain, and of the other RAM chains, out of dom0's memory. A reboot
  clears every RAM line anyway.
- **A mode away from disk is not erasure, and the journal stays.** Lines
  already written stay in the log, its rotated files and any backup until
  they are removed by age, and a removed file's bytes stay on the disk until
  they are overwritten. dom0's journal keeps every qrexec call (caller,
  service, target) whatever qmcp's modes, until journald is made volatile.
- **The time a reply takes is made the same, and measured only in part.** A
  line kept off the install's log (to RAM or nowhere) takes the same lock and
  tail read as one written there and syncs the same fixed block of zeros
  (`/var/log/qmcp-audit.log.pad`), it is counted and capped like any other,
  and the reads that decide where a line goes (a badge read per named qube,
  and the project records, read for every line unless a badge read failed,
  which sends the line to RAM) are the same in number for every name.
  Measured on the development box, for the hub's refused property sets naming
  the lead of a project with audit off, ram or disk: past the hourly cap, off
  against disk and ram against disk could not be told apart (paired median
  differences -0.06 ms and +0.12 ms, 240 pairs each). Under the cap, ram
  against disk could not be told apart either (+0.12 ms, 285 pairs); off
  against disk came out 0.41 ms slower for disk over 285 pairs, at the edge of
  what the probe resolves: the first 75 pairs told the two apart, a replicate
  of 150 did not. Only the hub's refused calls were timed: other call types
  and a lead as the caller were not.
- **A hidden project's qube and a missing name cost the same, as far as
  measured.** qubesd answers a missing qube 0.21-0.22 ms sooner than it reads
  an existing one's tags (`tag.List` and `tag.Get` alike), which in 0.9.33 made
  a refused hub call naming a hidden project's qube about 1 ms slower than one
  naming no qube. Every tag read of a name the caller chose is now balanced
  by a second one of the other kind (`core.tag_read_by_name`). Measured on the development box
  for the hub's refused property sets, the hidden lead against a missing name:
  -0.11 ms under the hourly cap (CI -0.59 to +0.29, 195 pairs) and -0.07 ms
  past it (CI -0.19 to +0.15, 480 pairs), not told apart; single batches past
  the cap differed by about 0.3 ms either way. A lead's calls were not timed
  end to end; a lead's scope checks read with `tag.Get`, whose gap was
  0.21 ms (the placement reads use `tag.List` for every caller), and a balanced pair of `tag.List` reads alone measured 0.003 ms apart (600
  pairs). A hub call measured about 1.5-3.5 ms slower than in 0.9.33 (passes
  hours apart, not interleaved). A hidden project's names come from a random label
  (26 x 36^7 choices, `projects.random_label`).
- **A promotion reads the qube's power once, after its badges change.** A
  start Qubes is still preparing then reads Halted and lands as the lead. The
  hub could run commands in that lead anyway (a visible project's lead is in
  AI space, and an anonymous project's lead is never promoted), so it gains
  nothing it did not have.
- **A reply near the 16 MiB cap takes several times that in the server** of
  the hub or a lead (measured: about 170 MiB more than the server's own for a
  reply of non-ASCII text), and parallel calls add up.
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
  answer about them as about missing names; but the dialog services
  (Filecopy, OpenInVM and OpenURL from the qubes it runs commands in; Filecopy, OpenInVM, OpenURL and the clipboard from the hub
  itself) are refused at once for a hidden name, where a
  missing one becomes `@default` and a dialog, so a hub that holds a name can
  tell it is a hidden qube's. It cannot guess one, since a label is eight
  random characters, but it can learn one: a member moved out of a hidden
  project keeps a folder in `~/QubesIncoming/` named after each qube that
  copied a file into it, its old siblings included.
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
  Qubes' own `ask` for OpenInVM and OpenURL, and this policy's Filecopy
  `ask`, from AI space (StartApp and GetImageRGBA are refused by D5 into any
  qube, this one included), and this
  policy's own `ask` for Filecopy, OpenInVM, OpenURL and the clipboard from
  the hub; the exec services are denied. Qubes refuses a name
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
- **A package the operator accepts runs as root in the template, and in every
  qube built on it.** dom0 installs only exact package names from the
  repositories the template already trusts, with what they depend on, and the
  install runs no command the hub wrote; but the install scripts of each
  package and dependency run as root, and a package can itself add a
  repository or download more software when it is installed (one that
  configures repositories, or an `-installer` package). Read the names; the
  second tick says so.
- **Accepting tells the hub something.** `accepted` or `failed` says whether
  the names it used exist; that happens only when the operator accepts, and a
  rejection tells it nothing.
- **A compromised hub can fill the queue:** an eleventh proposal is refused
  until the operator rejects some or they expire after 7 days.
- **A restored qube is held on the gate's next pass, normally within about 15
  seconds, not at once.** qmcp
  cannot hook a Qubes restore; the gate's pass holds a restored qube on its next
  run, which a create in flight or a failed read can delay. Until then a qrexec
  call into it can start it: shut the hub and the leads down before restoring AI
  qubes into a running install.
- **The labels are dom0's word, not proof.** `qmcp-id` says dom0 badged this
  qube, or, on a disposable that cleans itself up, its template; `qmcp-services` says what dom0 wrote into a template, not what is in it
  now. The hub cannot write either, but anything the operator runs in dom0 can.
- **A fresh install holds every badged qube whose label is missing or not its
  own,** one restored before qubes-mcp was installed included, until
  `qmcp restored accept`. A qube kept through `uninstall.sh --purge` keeps its
  label and is not held.
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
stops being anonymous; 0.9.24 anonymous mode, in which every project is
anonymous and the hub is checked too. M4 measured the in-qube services on Arch
and Fedora templates (they needed no change), and M5 (0.9.25) added sealed
qubes. 1.0.0 comes in releases: 0.9.26 the operator's tools, the
restore check and backups; 0.9.27 standalone workers and leads; 0.9.28 the
last proposal types: managing and revoking a qube, and a template's packages; then an
audit round from both seats, whose fixes ship by severity from 0.9.29 (the high
ones; 0.9.30 and 0.9.31 the medium ones; 0.9.32 the window's; 0.9.33
the low ones and the docs; 0.9.34 what their gates and the box left; 0.9.35 what
the reinstall rehearsal left), 0.9.36, this one, which removes only what qmcp
created and asks the operator for the rest, and 1.0.0
once all of it is green on a reinstalled machine.

## Anti-goals (immutable)

- **No proxy or relay between a principal and dom0.** Identity is the qrexec
  caller.
- **No runtime writes to qrexec policy.** A bad policy file can stop all of
  qrexec.
- **No Admin API for AI space, and no tag writes by the hub.** The one
  exception in AI space is a project's lead, which may read and write the
  firewall of its own project's members and nothing else. The hub's direct
  Admin API calls are the firewall methods on AI-space qubes (writes only on
  managed ones that are not leads, and on a guarded qube while its window is
  open with `--firewall`) and, behind the operator's dialog, USB attach, detach and
  listing for itself. The only tags the services write are a create's stamp on
  the qube it just made; every other badge change is the operator's (a `qmcp`
  command, or the installer's `qmcp-anon` in anonymous mode) or one of dom0's
  own passes (the anonymity gate, the restore check, the end of an open
  window).
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
                    (the 29 tools), qrexec.py (transport), cli.py
dom0/qmcp/          the dom0 library: core (the shared check), services, projects,
                    proposals, gateways (the registry), firewall (a lead's), anon (the
                    anonymity gate), birth,
                    budget, scope, audit, fleet (check/migrate/roles/projects/
                    gateways), restored (the restore check), inqube (the in-qube
                    services kept in dom0), opfiles (settings, export, import), cli,
                    and the window: gui (GTK) over guimodel (what it decides, no GTK)
dom0/rpc/           qmcp-service, the one shim installed under every service name
dom0/bin/qmcp       the operator's command
dom0/bin/qmcp-gui   the operator's window
policy/             30-mcp-control.policy
template-rpc/       the two in-qube services
deploy/             install.sh, uninstall.sh, qmcp-tmpfiles.conf, qubes-mcp.desktop,
                    qmcp-gate.service and qmcp-gate.timer, qmcp-refresh.service and
                    qmcp-refresh.timer, qmcp-seal.service and
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
