# qubes-mcp — design document

An MCP server that lets AI agents operate a scoped part of a Qubes OS machine.
It runs in one qube, the **hub** (`mcp-control`). Agents reach it over stdio
(usually through SSH) and call its tools. Most tools call `qmcp.*` services in
dom0, which decide everything about the qubes they touch; running a command,
copying a file out and reading or writing a firewall go straight to the qube or
the Admin API, decided by the qrexec policy in dom0.

**This file describes the code at this version (0.9.17). Read it first in any
session opened in this directory.** The release history is in `CHANGELOG.md`.

## Trust model

These are load-bearing. Do not change them without the operator's sign-off.

- **dom0 is the only enforcement point, and qrexec's caller is the only
  identity.** Every dom0 `qmcp.*` service reads `QREXEC_REMOTE_DOMAIN`, which
  dom0's qrexec daemon sets, and the policy matches on the same identity.
  Nothing sits between a principal and dom0: a relay would make every call come
  from the relay, and ownership, network choice and audit would all collapse
  onto it.
- **The hub is not in AI space.** It is named in `/etc/qmcp/hub` (written once,
  at install) and in the policy. It never carries `ai-managed`, so it is never
  the object of its own calls; `qmcp check` fails if it does, or if the policy
  names a different hub than the file.
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
- **Badges change only through the operator.** Neither the hub nor AI space can
  call the Admin API's tag methods. The `qmcp` command in dom0 is the
  operator's tool for changing badges; the only tags qmcp writes on its own are
  the stamp a create puts on the qube it just made.
- **Strip on create.** `clone_vm` copies the source's tags and a disposable
  copies its template's, so every create path removes every tag in qmcp's
  vocabulary the platform copied (`qmcp-guarded`, the v0.9.16 tier tags, other
  principals' provenance), stamps `ai-managed` and `qmcp-owner_<caller>`
  (provenance only, never a gate), carries restrictions forward
  (`qmcp-egress-locked_*`, the platform's `anon-vm`), reads the result back,
  and rolls the qube back if it is not exact. Tags outside qmcp's vocabulary
  (the operator's own) are left as Qubes copied them.
- **The rulebook is static.** `/etc/qubes/policy.d/30-mcp-control.policy` is
  installed once and never written at runtime. Before it is installed it is
  parsed by qrexec's own parser against the box's real policy directory, and
  16 of its claims are checked to be decided by it, not by a file that sorts
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

## What lives where

| Where | What |
|---|---|
| hub (`mcp-control`) | `qubes_mcp/`: the MCP server and the `qubes-mcp` CLI. Standard library only. It reaches AI space through the policy's hub section; beyond that, only its own boot services and the operator's dialogs. |
| dom0 | `/usr/local/lib/qmcp/qmcp/` (the library), `/etc/qubes-rpc/qmcp.*` (one shim under each service name), `/usr/local/bin/qmcp` (the operator's command), the policy, `/etc/qmcp/` (operator files), `/run/qmcp/` (lock files). |
| AI templates | `template-rpc/`: `qmcp.RunInAIManaged` and `qmcp.CopyToAIManaged`, installed in the templates AI qubes are built on. A qube on a template without them cannot be exec'd into. |

## The services

### In dom0

Each is the same shim (`dom0/rpc/qmcp-service`), installed under its name and
dispatching to `dom0/qmcp/services.py`. Every call runs one funnel
(`dom0/qmcp/core.py`): the caller must be a principal (the hub, in this
release), holds one of its 8 concurrency slots, sends at most 64 KiB (refused
before it is parsed), and gets exactly one JSON reply.

| Service | What it does |
|---|---|
| `qmcp.ListAIManagedQubes` | AI space: name, class, label, template (redacted if out of scope), power state, `guarded`. |
| `qmcp.GetPropertyAIManaged` | One property of a managed or guarded qube. Only properties qubesd lists; references out of scope redacted, and so are the netvm's addresses (`visible_gateway`, `dns`, …) when the netvm is out of scope; `tags` filtered to `ai-managed` and `qmcp-guarded`. |
| `qmcp.SetPropertyAIManaged` | `label`, `memory`, `maxmem`, `vcpus`, and `netvm` only to null. Everything else (`template`, `name`, `default_dispvm`, `provides_network`, …) is operator-only. |
| `qmcp.SetFeatureAIManaged` | Allowlist: `service.*`, `vm-config.*`, `menu-items`, `default-menu-items`. Every other key, including any a future Qubes adds, is operator-only. |
| `qmcp.LifecycleAIManaged` | start, shutdown, kill, pause, unpause, remove. Remove is a real remove. |
| `qmcp.SpawnAIManagedQube` | AppVM or DispVMTemplate from a TemplateVM, or a named DispVM from a disposable template. The template may be managed or guarded, but not one that provides network. |
| `qmcp.CloneAIManagedQube` | Clone a managed qube, templates included. A guarded source is refused: a clone is a managed, editable copy of everything in it. |
| `qmcp.SpawnDisposableAIManaged` | A disposable from a managed or guarded disposable template, born managed. Uses Qubes 4.3's preloaded disposables when the template has `preload-dispvm-max` (measured: a `qubes_run_disposable` cycle took 1.5 s with `preload-dispvm-max=1`, about 8 s without). |
| `qmcp.AIManagedEvents` | A window of admin events (1–120 s) whose subject is in AI space; at most 16 filters of at most 64 characters. Tag events surface only for the two visible badges. |
| `qmcp.GetPoolStats` | `ai_managed_bytes_used`, `_cap` and `_headroom`: AI space's persistent disk footprint against the operator's cap. |

**Creates.** A name the hub chooses must carry the reserved prefix
(`/etc/qmcp/name-prefix`, default `ai-`) and is judged on its shape alone,
before anything is looked up, so a create is no oracle over names outside the
prefix. (Qubes names disposables itself.) Creates are serialised by a lock held
from the disk-budget check through the create, with a 120 s wait, and the name
is checked again under the lock. A create call that fails is never cleaned up
by name: qubesd and `clone_vm` clean up their own failures, and a qube someone
else made under that name meanwhile is left alone. A create that succeeds but
cannot be finished is rolled back; the one exception is a failed `private`
resize, which keeps the qube and says so (`warning: private_resize_failed`).
Spawn and clone set the new qube's network
and `default_dispvm` explicitly, so neither follows a global default; a
disposable gets `default_dispvm` set to none and keeps its template's network.

**Network at birth.** A clone source or a disposable template decides: the
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
qube's requested `private` by `/etc/qmcp/private-cap`. Both are re-read on
every call. A volume that cannot be read refuses the create rather than being
counted as empty. Without a pool cap every create is refused; without a
private cap, any create that asks for a `private` size.

### In AI qubes

| Service | What it does |
|---|---|
| `qmcp.RunInAIManaged` | Runs a command as root and returns rc/stdout/stderr. |
| `qmcp.CopyToAIManaged` | Runs `qvm-copy-to-vm` from this qube. The copy itself is `qubes.Filecopy` and gets the operator's dialog. |

## The rulebook

`policy/30-mcp-control.policy`, first match wins. Two principals appear in it:
the hub by name, and AI space (`@tag:ai-managed`). A few denies also name any
source (`@anyvm`) or the drop boxes (`@tag:ai-dump`).

- **A. Denies, first.**
  - A1: the hub cannot run, copy or write firewall rules in a guarded qube (it
    may read its firewall), and nothing from AI space reaches a guarded qube by
    any service.
  - A2: Qubes' raw disposable shortcut is closed for AI space. A `@dispvm` rule
    target matches only the bare keyword, so a second rule works from the
    template's side: `@dispvm:@tag:ai-managed`, any source, any form.
  - A3: no command execution from AI space into another qube, whatever form
    the target takes.
  - A4: AI space never reaches the hub, by any service, and never drives
    qmcp's in-qube services.
  - A5: AI space talks to dom0 only through the five services a qube needs to
    boot and report itself; every other service addressed to dom0 is refused.
    Qubes itself forwards two services to dom0 when a qube addresses them
    elsewhere (`qubes.GetDate` from any target, `qubes.Notifications` from
    `@default`). GetDate stays (Qubes' own rule refuses Whonix qubes);
    Notifications is denied, so no AI qube can put a desktop notification in
    front of the operator.
  - A6: the Admin API (the 122 methods qubesd 4.3 registers, the two volume
    Import services) and the policy API are denied to AI space for every target
    form other than dom0, which A5 covers.
- **B. The hub:** the ten dom0 services; exec, copy-out and firewall on AI
  space.
- **C. Copies from AI space:** the operator's dialog, unless A refused them
  (into a guarded qube or the hub). qrexec turns a target that does not exist
  into `@default`, so the dialog reveals no names. A drop box (`ai-dump`)
  cannot reach back into AI space by any service.
- **D. The hub's own operator UX:** its boot services, clock sync and dialogs.
- **E. The hub's catch-alls:** everything else is refused.

`tests/test_policy.py` checks every rule against a matrix of requests on
qrexec's real parser, next to upstream Qubes 4.3's default policy — and again
with a later file that allows everything, which our denies must survive. It
removes each rule in turn and fails if any of them decides nothing.

## The operator's command (dom0)

| Command | |
|---|---|
| `qmcp check` | Fails on: the hub missing, in AI space, or named differently in the policy; tier tags; a gateway without `qmcp-guarded`; a drop box in AI space; the policy modified, refused by qrexec's parser, or overridden by an earlier file for any of its 16 checked claims; services, runtime directory or caps missing; a broken audit chain; v0.9.16 leftovers. Warns on stray badges, v0.9.16 tombstones, qubes outside AI space inside the name prefix, managed qubes pointing at a disposable template outside it, a birth-egress qube outside AI space, and an audit log due for rotation. Exit 0 GREEN, 1 FAILED, 3 INCOMPLETE — INCOMPLETE is not green. |
| `qmcp list` | AI space with state, class, template, network, power, provenance. |
| `qmcp manage QUBE` / `qmcp guard QUBE` | The role actions. Both refuse the hub and a drop box; `manage` also refuses a gateway. |
| `qmcp revoke QUBE` | Strips every qmcp badge, pins `default_dispvm` to none, shuts the qube down. |
| `qmcp migrate [--apply]` | v0.9.16 tiers to two states (below). Dry run by default. |
| `qmcp audit verify` / `tail` / `rotate` | The chain. `rotate` moves the log aside and starts a new one anchored on the old head; it needs root. |

## Install, migrate, uninstall

The installer runs as root in dom0, so the tree it runs from must come from
somewhere AI cannot write. A tree copied out of the hub is only as
trustworthy as the hub. Fetch a tagged release in a fresh disposable (any
disposable template with curl and network; Qubes' stock `default-dvm` has both):

```sh
# in dom0
qvm-run --dispvm=default-dvm --pass-io \
  'curl -fsSL https://github.com/alex-schose/qubes-mcp/archive/refs/tags/v0.9.17.tar.gz' \
  > /tmp/qmcp.tgz
rm -rf /tmp/qubes-mcp && mkdir /tmp/qubes-mcp
tar -xzf /tmp/qmcp.tgz -C /tmp/qubes-mcp --strip-components=1
sudo bash /tmp/qubes-mcp/deploy/install.sh   # --hub, --birth-egress, --pool-cap, --private-cap, --dry-run
```

`install.sh` runs every preflight check before it changes anything: its options
must be well-formed, the fleet must be in the two-state shape, and the rendered
policy must parse on this box and decide each of the 16 claims itself. It removes what v0.9.16 installed, backs up what it
replaces under `/var/lib/qmcp-rollback/`, installs the policy last, and exits
with `qmcp check`'s status. `uninstall.sh` removes the policy first (so no AI
caller reaches a half-removed service), then everything else, and ends with a
clean-state check that names what it keeps; `--purge` also removes
`/etc/qmcp` and the audit log. Backups under `/var/lib/qmcp-rollback/` are
never removed, nor is `/var/log/qmcp-changes.log`, the change history some
older installers kept. Qubes keep their tags.

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
| `tests/test_server.py` | anywhere | the MCP server and CLI against a fake qrexec client |
| `tests/seat_suite.py` | in the hub, on a real box | the tools through the real chain |
| `tests/redteam_suite.py` | in the hub, on a real box | attacks from the hub and from a managed qube, with positive controls; a probe that hangs on a dialog fails |

```sh
python3 -W error::DeprecationWarning -m unittest discover -s tests -p 'test_*.py'
```

`QMCP_POLICY_BASELINE=/etc/qubes/policy.d` runs the policy matrix against a
real dom0's policy set.

## Residual risks, accepted

- **A compromised hub controls all of AI space.** The audit log records what
  it does through the dom0 services; its exec, copy-out and firewall writes
  are not on that log.
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

M2 adds projects: a lead per project operating its own workers, sixteen static
policy slots, scoped reads, and the core of a dom0 GUI whose proposals are the
only approval path. M3 adds networks: a gateway registry, locked or free
networks per project, an anonymity gate and model endpoints. M4 runs the
in-qube services on Arch and Fedora templates, M5 adds sealed qubes, and
1.0.0 completes the GUI.

## Anti-goals (immutable)

- **No proxy or relay between a principal and dom0.** Identity is the qrexec
  caller.
- **No runtime writes to qrexec policy.** A bad policy file can stop all of
  qrexec.
- **No Admin API for AI space, and no tag writes by the hub.** The hub's direct
  Admin API calls are the firewall methods on AI-space qubes (writes only on
  managed ones) and, behind the operator's dialog, USB attach, detach and
  listing for itself. The
  only tags the services write are a create's stamp on the qube it just made;
  every other badge change is the operator's `qmcp` command.
- **Never scope policy, ownership or any gate on `created-by-*` or
  `disp-created-by-*`.** qubesd stamps `created-by-` with the *calling* domain —
  dom0 for every qmcp create — so it cannot tell an AI-created qube from an
  operator-created one; and `"disp-created-by-x".startswith("created-by-")` is
  `False`, so anything holding `admin.vm.tag.Set` can forge it.
- **No MCP code in dom0.** dom0 holds the library, the shims, the operator's
  command and the policy.
- **No third-party dependencies on the hub.** The server uses only Python's
  standard library.
- **No third-party SaaS or SSO.**
- **qmcp never depends on the operator's own notification tooling.**

## File layout

```
qubes_mcp/          the hub: server.py (MCP over stdio), tools.py (the 18 tools),
                    qrexec.py (transport), cli.py
dom0/qmcp/          the dom0 library: core (the shared check), services, birth,
                    budget, scope, audit, fleet (check/migrate/roles), cli
dom0/rpc/           qmcp-service, the one shim installed under every service name
dom0/bin/qmcp       the operator's command
policy/             30-mcp-control.policy
template-rpc/       the two in-qube services
deploy/             install.sh, uninstall.sh, qmcp-tmpfiles.conf
tests/              the suites above; data/ holds the upstream policy baseline
                    and qubesd's method list
```

## Versioning

Semantic versioning from 0.9.0. Every commit takes one patch bump, one
`CHANGELOG.md` entry and one tag. Before 1.0.0 a breaking change still takes a
patch bump and is labelled `BREAKING`.

## References

- Qubes Admin API: https://doc.qubes-os.org/en/latest/developer/services/admin-api.html
- Qrexec policy (R4.2+): https://forum.qubes-os.org/t/qrexec-policy-format-for-r4-2-and-r4-3/40407
- MCP specification: https://modelcontextprotocol.io/specification
