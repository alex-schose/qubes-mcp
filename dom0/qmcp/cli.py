"""`qmcp` — the operator's command in dom0.

    qmcp check [--json]            is the fleet sound? (exit 0 GREEN, 1 FAILED, 3 INCOMPLETE)
    qmcp list [--all] [--json]     AI space: state, class, template, network, slot, owner
    qmcp settings [--json]         the operator files and the disk AI space uses
    qmcp settings set ...          change the pool cap, the private cap or birth egress
    qmcp template prepare|refresh  write qmcp's in-qube services into a template or standalone
    qmcp restored list|accept|reject   qubes back from a backup or a copy, held for review
    qmcp export [FILE] / import FILE   the operator files, as one file a backup carries
    qmcp manage|guard|revoke QUBE  role actions
    qmcp gateway ...               the networks AI space may use: list, enroll, set, remove
    qmcp project ...               projects: list, show, create, edit, lead, firewall, dump,
                                   move, delete, unblock
    qmcp gate [--json]             judge the anonymous projects, and stop one that is not
    qmcp proposal ...              the hub's proposals: list, show, accept, reject
    qmcp migrate [--apply] ...     move a v0.9.16 tiered fleet to two states
    qmcp audit verify|tail [N]|rotate   the hash-chained record of state changes
    qmcp version

The operator's window, `qmcp-gui`, runs these same commands: reads as you,
changes under `sudo -n`.

Run it as root, or as a member of the `qubes` group. The project and gateway
commands that change anything write /etc/qmcp/projects.json or
/etc/qmcp/gateways.json, or take the records' lock, so they need root; so do
accepting and rejecting a proposal.

Every command that changes something leaves one line on the audit chain, as
caller "operator": the command, the names it acts on and its options, a quota
only as "set". Reads, plans and dry runs leave none, nor does a command the
argument parser refuses (migrate's --map check included) or one refused for not
running as root; one its own checks refuse leaves a line with ok false.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from qmcp import anon, audit, core, fleet, inqube, opfiles, projects, proposals, restored

EXIT = {"GREEN": 0, "FAILED": 1, "INCOMPLETE": 3}


def _app():
    import qubesadmin.app
    return qubesadmin.app.QubesLocal()


def _version() -> str:
    try:
        with open(os.path.join(fleet.LIB_DIR, "VERSION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "unknown"


def cmd_check(args) -> int:
    findings = fleet.check(_app())
    result = fleet.overall(findings)
    if args.json:
        print(json.dumps({"result": result,
                          "findings": [{"status": f.status, "check": f.check, "detail": f.detail}
                                       for f in findings]}, indent=2))
        return EXIT[result]
    for f in findings:
        print(repr(f))
    print(f"\nqmcp check: {result}" + ("  (INCOMPLETE is not green)" if result == "INCOMPLETE" else ""))
    return EXIT[result]


def cmd_list(args) -> int:
    rows = fleet.listing(_app(), everything=args.all)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    cols = ("name", "state", "klass", "template", "netvm", "power", "slot", "owner")
    widths = {c: max([len(c)] + [len(str(r[c] or "-")) for r in rows]) for c in cols}
    print("  ".join(c.upper().ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r[c] or "-").ljust(widths[c]) for c in cols))
    return 0


def cmd_settings(args) -> int:
    if getattr(args, "what", None) == "set":
        _need_root("set", "settings")
        try:
            lines = opfiles.settings_set(_app(), pool_cap=args.pool_cap,
                                         private_cap=args.private_cap,
                                         birth_egress=args.birth_egress)
        except opfiles.OpFilesError as e:
            print(f"qmcp settings set: {e}; nothing was changed", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"qmcp settings set: {type(e).__name__}", file=sys.stderr)
            return 1
        for line in lines:
            print(line)
        return 0
    values = dict(fleet.settings(_app()), version=_version())
    if args.json:
        print(json.dumps(values, indent=2))
        return 0
    for key, value in values.items():
        print(f"{key}: {'-' if value is None else value}")
    return 0


def cmd_role(args) -> int:
    action = {"manage": fleet.manage, "guard": fleet.guard}.get(args.cmd)
    try:
        if args.cmd == "revoke":
            print(fleet.revoke(_app(), args.qube, shutdown=not args.no_shutdown))
        else:
            print(action(_app(), args.qube))
    except fleet.RoleError as e:
        print(f"qmcp {args.cmd}: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"qmcp {args.cmd}: {type(e).__name__}", file=sys.stderr)
        return 1
    return 0


def cmd_window(args) -> int:
    """`qmcp open` and `qmcp seal`, both under the gate's lock, so a window
    never races the pass that expires one. `--expired` is the pass itself,
    which the gate's timer runs, and `--all` the boot seal: both report what
    they did and exit 3 when something could not be judged, never 1, so the
    unit's other command still runs."""
    if args.cmd == "seal" and not args.all and not args.expired and args.qube is None:
        raise SystemExit("qmcp seal: name a qube, or --all, or --expired")
    if args.cmd == "seal" and args.qube is not None and (args.all or args.expired):
        raise SystemExit("qmcp seal: a qube, or --all, or --expired, not both")
    try:
        if args.cmd == "open":
            seconds = fleet.duration_seconds(args.duration)
    except fleet.RoleError as e:
        print(f"qmcp open: {e}", file=sys.stderr)
        return 1
    try:
        with anon.gate_lock() as got:
            if not got:
                print(f"qmcp {args.cmd}: another run held the gate past its wait; nothing was "
                      f"changed", file=sys.stderr)
                return 3
            if args.cmd == "open":
                print(fleet.open_window(_app(), args.qube, seconds, firewall=args.firewall))
                return 0
            if args.qube is not None:
                print(fleet.seal(_app(), args.qube))
                return 0
            lines = fleet.expire_windows(_app(), every=args.all)
    except fleet.RoleError as e:
        print(f"qmcp {args.cmd}: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"qmcp {args.cmd}: {type(e).__name__}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    # "NOT sealed" and "could not be judged" are the two a window may be left
    # open by; `qmcp check` fails on the badge either way.
    return 3 if any("NOT sealed" in l or "could not be judged" in l for l in lines) else 0


def _need_root(what: str, command: str = "project") -> None:
    if os.geteuid() != 0:
        cmd = " ".join(w for w in (command, what) if w)
        raise SystemExit(f"qmcp {cmd}: run as root (sudo qmcp {cmd} ...); "
                         f"it writes /etc/qmcp or takes the records' lock")


def cmd_gateway(args) -> int:
    what = args.what
    try:
        if what == "list":
            rows = fleet.gateway_rows(_app())
            if args.json:
                print(json.dumps(rows, indent=2))
                return 0
            for r in rows:
                notes = [n for n in (
                    "anonymising" if r["anonymising"] else "",
                    f"label '{r['label']}'" if r["label"] else "",
                    f"upstream {r['upstream'] or 'none'}",
                    "" if not r["anonymising"] else
                    f"recorded on {r['recorded_upstream']}" if r["recorded_upstream"]
                    else "no recorded network (mark it again)",
                    "" if not r["anonymising"] else
                    f"templates' updates may go to {r['recorded_upstream']}" if r["updates"]
                    else "templates' updates do not count there",
                    "upstream ignores its firewall rules" if r["upstream_ignores_firewall"] is True
                    else "whether its upstream ignores its firewall rules cannot be read"
                    if r["upstream_ignores_firewall"] == fleet.UNREADABLE
                    else "",
                    f"NOT USABLE: {r['problem']}" if r["problem"] else "",
                    f"used by {len(r['used_by'])} qube(s)",
                    f"listed by {', '.join(r['projects'])}" if r["projects"] else "") if n]
                print(f"{r['name']}: {'; '.join(notes)}")
            if not rows:
                print("no gateway enrolled")
            return 0
        _need_root(what, "gateway")
        app = _app()
        if what == "enroll":
            print(fleet.enroll_gateway(app, args.qube, args.anonymising, args.label or "",
                                       args.updates))
        elif what == "set":
            anon = None if args.anonymising is None else args.anonymising == "yes"
            updates = None if args.updates is None else args.updates == "yes"
            print(fleet.set_gateway(app, args.qube, anon, args.label, updates))
        else:
            print(fleet.remove_gateway(app, args.qube))
    except (fleet.RoleError, RuntimeError) as e:
        print(f"qmcp gateway {what}: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"qmcp gateway {what}: {type(e).__name__}", file=sys.stderr)
        return 1
    return 0


def _lead_source(args):
    for source in ("template", "clone", "promote"):
        value = getattr(args, f"lead_{source}", None)
        if value:
            return source, value
    return None, None


def cmd_project(args) -> int:
    app = _app()
    what = args.what
    try:
        if what == "list":
            rows = fleet.project_rows(app, fleet._load_records())
            if args.json:
                print(json.dumps(rows, indent=2))
                return 0
            for r in rows:
                used = "?" if r["used"] is None else f"{r['used'] / 1024 ** 3:.1f}"
                quota = "-" if r["quota"] is None else f"{r['quota'] / 1024 ** 3:.1f}"
                kind = "" if not r["anonymous"] else \
                    f"  anonymous, {'hidden' if r['hidden'] else 'visible'}" + \
                    ("  BLOCKED" if r["blocked"] else "  blocked=?" if r["blocked"] is None
                     else "") + \
                    (f"  note: {json.dumps(r['note'])}" if r["note"] else "")
                print(f"{r['slot']}  {r['label'] or '(hub)':8s}  lead={r['lead'] or '-'}  "
                      f"members={'?' if r['members'] is None else r['members']}  "
                      f"disk={used}/{quota} GiB  sink={r['dump'] or '-'}  "
                      f"model={r['model'] or r['model_qube'] or '-'}{kind}")
            return 0
        if what == "show":
            p = projects.find(fleet._load_records(), args.name)
            if p is None:
                raise fleet.ProjectError(f"no project '{args.name}'")
            print(json.dumps(dict(p.to_json(), slot=p.slot), indent=2))
            return 0
        if what == "firewall" and args.model is None and not args.rule and not args.accept_current \
                and args.model_qube is None:
            # Reading needs no root: the window shows it beside the lead.
            view = fleet.lead_firewall_view(app, fleet._load_records(), args.name)
            if args.json:
                print(json.dumps(view, indent=2))
                return 0
            model = (f"model qube {view['model_qube']}" if view["model_qube"]
                     else f"model {view['model'] or '-'}")
            print(f"{view['slot']} {view['project']}: lead {view['lead'] or '-'}, {model}")
            for title, rules in (("accepted", view["accepted"]), ("live", view["live"])):
                if rules:
                    print(f"{title}:")
                    for r in rules:
                        print(f"  {r}")
                elif title == "accepted":
                    print("accepted: none on record")
                else:
                    print(f"live: {'unreadable (' + view['read_error'] + ')' if view['read_error'] else 'none'}")
            if view["model_qube"]:
                # A lead whose model is a qube has no network: no rule applies to it.
                print("the lead's model is a qube: it should have no network, and qmcp check "
                      "fails if it has one; with none, no firewall rule applies to it")
            else:
                print("same" if view["same"] else "DIFFERENT, or not both known")
            return 0
        if what == "delete" and not args.yes:
            # The plan changes nothing and reads only the records and the qube
            # list, so it needs no root: the operator's window shows it before
            # it asks, and so does a proposal to delete.
            runs, plan = fleet.delete_plan(app, fleet._load_records(), args.name)
            if not runs:
                raise fleet.ProjectError(plan)
            print(f"qmcp project delete: {plan}. Re-run with --yes.")
            return 1
        _need_root(what)
        if what == "create":
            source, origin = _lead_source(args)
            if source is None:
                raise fleet.ProjectError("say where the lead comes from: --lead-template, "
                                         "--lead-clone or --lead-promote")
            if args.name is None and not args.anonymous and not fleet.anonymous_mode():
                raise fleet.ProjectError("give the project a LABEL (an anonymous project's is "
                                         "picked by dom0)")
            report = fleet.create_project(app, args.name, source, origin, args.template or (),
                                          args.network or (), args.quota, args.lead_netvm,
                                          args.dump, args.lead_name, args.model,
                                          args.model_qube, args.anonymous, args.hub_sees,
                                          args.note)
        elif what == "edit":
            report = fleet.edit_project(app, args.name, args.template, args.network, args.quota)
        elif what == "lead":
            if args.remove:
                report = fleet.remove_lead(app, args.name)
            else:
                source, origin = _lead_source(args)
                if source is None:
                    raise fleet.ProjectError("--remove, or a new lead: --lead-template, "
                                             "--lead-clone or --lead-promote")
                report = fleet.set_lead(app, args.name, source, origin, args.lead_netvm,
                                        args.keep_old, args.lead_name, args.model,
                                        args.add_old_network, args.model_qube)
        elif what == "firewall":
            report = fleet.set_lead_firewall(app, args.name, args.model, args.rule or None,
                                             args.accept_current, args.model_qube)
        elif what == "dump":
            report = fleet.add_dump(app, args.name, args.sink_name)
        elif what == "move":
            report = fleet.move(app, args.name, args.target, confirm=args.yes)
        elif what == "unblock":
            report = fleet.unblock(app, args.name)
        elif what == "delete":
            p = projects.find(fleet._load_records(), args.name)
            if (p is not None and p.slot == projects.HUB_SLOT) or \
                    (p is None and args.name not in projects.PROJECT_SLOTS):
                raise fleet.ProjectError(f"no project '{args.name}'")
            report = fleet.delete_project(app, args.name)
        else:
            raise fleet.ProjectError(f"unknown command {what}")
    except Exception as e:
        # A command that failed part-way says what it had already done.
        for line in getattr(e, "report", []):
            print(line)
        detail = str(e) if isinstance(e, (fleet.RoleError, RuntimeError)) else type(e).__name__
        print(f"qmcp project {what}: {detail}", file=sys.stderr)
        return 1
    for line in report:
        print(line)
    # A failed step is recorded as one; a line's text holds names, and a name
    # may hold any word.
    return 1 if getattr(report, "failed", None) else 0


def cmd_template(args) -> int:
    """`prepare`: the operator writes the in-qube services into one qube.
    `refresh`: the timer brings every running prepared qube up to date, and
    leaves one audit line per qube it wrote into, as caller "refresh". A qube
    it could not judge or write into is printed (the unit's journal) and makes
    the run exit 3, with no line: the chain records changes, and a qube that
    keeps failing would otherwise add one every minute."""
    if args.what == "prepare":
        _need_root("prepare", "template")
        try:
            r = inqube.prepare(_app(), args.qube)
        except (inqube.InQubeError, core.Unreadable) as e:
            print(f"qmcp template prepare: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"qmcp template prepare: {type(e).__name__}", file=sys.stderr)
            return 1
        print(f"{r['qube']}: prepared ({r['version']})"
              + ("; it was started for this and shut down again" if r["started"] else ""))
        return 0
    try:
        done = inqube.refresh(_app())
    except inqube.InQubeError as e:
        print(f"qmcp template refresh: {e}", file=sys.stderr)
        return 3
    rc = 0
    for name, outcome in done:
        print(f"{name}: {outcome}")
        if outcome != "updated":
            rc = 3
            continue
        try:
            audit.audit("qmcp template refresh", "refresh", {"qube": str(name)[:128]}, True)
        except Exception:
            pass
    return rc


def cmd_restored(args) -> int:
    if args.what == "list":
        try:
            records = projects.load()
        except projects.ProjectsUnreadable:
            records = None
            print("qmcp restored: the project records cannot be read, so no row says whether "
                  "it agrees with them", file=sys.stderr)
        rows = restored.review(_app(), records)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        if not rows:
            print("none waiting for review")
        for r in rows:
            if "unreadable" in r:
                print(f"{r['name']}: {r['unreadable']}")
                continue
            print(f"{r['name']}: {'held' if r['held'] else 'NOT YET HELD'}; came back as "
                  f"{r['role']}; label {r['label']}; "
                  + ("agreement with the records not known" if r["agrees"] is None else
                     "agrees with the records" if r["agrees"] else "; ".join(r["why"])))
        return 0
    _need_root(args.what, "restored")
    app = _app()
    if args.what == "accept" and args.all:
        if args.qube:
            raise SystemExit("qmcp restored accept: name the qubes, or give --all, not both")
        names = [r["name"] for r in restored.review(app, None) if r.get("held")]
        if not names:
            print("nothing is held")
            return 0
    elif not args.qube:
        raise SystemExit(f"qmcp restored {args.what}: name a qube"
                         + (", or give --all" if args.what == "accept" else ""))
    else:
        # accept takes the names the operator saw (the window passes the ones it showed)
        names = list(args.qube) if isinstance(args.qube, list) else [args.qube]
    rc = 0
    for name in names:
        try:
            print((restored.accept if args.what == "accept" else restored.reject)(app, name))
        except restored.ReviewError as e:
            print(f"qmcp restored {args.what}: {e}", file=sys.stderr)
            rc = 1
        except Exception as e:
            print(f"qmcp restored {args.what}: {name}: {type(e).__name__}; see qmcp "
                  f"restored list",
                  file=sys.stderr)
            rc = 1
    return rc


def cmd_export(args) -> int:
    _need_root("", "export")
    try:
        path = opfiles.export(_version(), args.file, os.environ.get("SUDO_USER"))
    except opfiles.OpFilesError as e:
        print(f"qmcp export: {e}", file=sys.stderr)
        return 1
    print(f"wrote {path}: back it up with dom0 ticked. On a reinstalled Qubes: restore "
          f"everything, install qubes-mcp with the same --hub, sudo qmcp import FILE (it comes "
          f"back under ~/home-restore-<time>/dom0-home/), then sudo qmcp restored accept --all")
    return 0


def cmd_import(args) -> int:
    _need_root("", "import")
    try:
        lines = opfiles.import_(args.file)
    except opfiles.OpFilesError as e:
        print(f"qmcp import: {e}; nothing was changed", file=sys.stderr)
        return 1
    except fleet.ProjectError as e:
        print(f"qmcp import: {e}; nothing was changed", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    print("next: accept the restored AI qubes, which the gate holds until you do: sudo qmcp "
          "restored accept --all (qmcp restored list shows each first)")
    return 0


def cmd_gate(args) -> int:
    """Judge every anonymous project now, and stop one that is not (the timer
    runs this). Prints only what is not sound, or what it did, unless --json.
    Exit 0 all sound, 1 one is not, 3 one could not be judged, or another run
    held the gate so nothing was."""
    held = None
    try:
        held = restored.hold(_app())
        restored.notify(held)
    except Exception as e:
        print(f"qmcp gate: the restore check could not run ({type(e).__name__})", file=sys.stderr)
    if held is not None:
        # On stderr: `--json` is the gate's verdicts alone, which the window reads.
        for name in held.held:
            print(f"{name}: held for review (it came back from a backup or a copy)",
                  file=sys.stderr)
        for name, err in held.failed:
            print(f"{name}: NOT held ({err}); tried again next run", file=sys.stderr)
        if not held.judged:
            print("qmcp gate: a create held the lock, so no restored qube was looked for; the "
                  "next run looks", file=sys.stderr)
    try:
        verdicts = anon.run(_app(), beat=os.environ.get(anon.HEARTBEAT_ENV) == "1")
    except projects.ProjectsUnreadable as e:
        print(f"qmcp gate: {e}; the anonymous projects were not judged", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"qmcp gate: {type(e).__name__}; the anonymous projects were not judged",
              file=sys.stderr)
        return 3
    if verdicts is None:
        print("qmcp gate: another run held the gate past its wait; nothing was judged",
              file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps([v.to_json() for v in verdicts], indent=2))
    else:
        for v in verdicts:
            if v.status == anon.GREEN and not v.acted:
                continue
            print(f"{v.slot} {v.label}: {v.status}{' (blocked)' if v.blocked else ''}")
            for _, detail in v.problems:
                print(f"  {detail}")
            for line in v.acted:
                print(f"  {line}")
    if any(v.status == anon.RED for v in verdicts):
        return 1
    unjudged = held is None or not held.judged or bool(held.failed or held.unread)
    return 3 if unjudged or any(v.status == anon.UNREADABLE for v in verdicts) else 0


def _gate_after(args) -> None:
    """After a command that changed something, judge the anonymous projects:
    a change the command made that breaks one stops it now, not up to 15
    seconds later. Only what was stopped is printed."""
    try:
        verdicts = anon.run(_app())
    except Exception as e:
        print(f"qmcp: the anonymity gate could not run after this command "
              f"({type(e).__name__}); its timer runs it within about 15 seconds", file=sys.stderr)
        return
    if verdicts is None:
        print("qmcp: the anonymity gate was busy after this command; its timer judges the "
              "anonymous projects within about 15 seconds", file=sys.stderr)
    for v in verdicts or ():
        if v.acted:
            print(f"qmcp: the anonymity gate stopped {v.label} ({v.slot}): "
                  + "; ".join(d for _, d in v.problems), file=sys.stderr)


def cmd_proposal(args) -> int:
    what = args.what
    try:
        if what == "list":
            rows = proposals.listing()
            if args.json:
                print(json.dumps(rows, indent=2))
                return 0
            for r in rows:
                print(f"{r['id']:>4}  {r['state']:<10}  {r['type'] or '?':<14}  "
                      f"{r['subject'] or '-':<8}  {r['title'] or r['problem']}")
            return 0
        if what == "show":
            doc = proposals.show(_app(), args.id)
            if args.json:
                print(json.dumps(doc, indent=2))
                return 0
            for key in proposals.SHOW_FIELDS:
                value = doc[key]
                if key == "second_tick":
                    value = "; ".join(value) if value else "not needed"
                elif key == "tick" and value:
                    value = f"{value}  (accept with --yes {value})"
                elif isinstance(value, (dict, list)):
                    value = json.dumps(value, sort_keys=True)
                print(f"{key}: {'-' if value is None else value}")
            return 0
        if os.geteuid() != 0:
            raise SystemExit(f"qmcp proposal {what}: run as root (sudo qmcp proposal {what} ...); "
                             f"it runs the proposal's command, or writes its decision")
        if what == "accept":
            ok, report = proposals.accept(_app(), args.id, args.sha256, tick=args.yes)
            for line in report:
                print(line)
            print(f"proposal {args.id}: {'accepted' if ok else 'failed'}")
            return 0 if ok else 1
        closed = proposals.reject(args.id)
        print(f"proposal {args.id}: {closed}")
        return 0
    except proposals.Refused as e:
        for line in getattr(e, "report", []):
            print(line)
        print(f"qmcp proposal {what}: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"qmcp proposal {what}: cannot read {proposals.PROPOSALS_DIR} "
              f"({e.strerror or type(e).__name__})", file=sys.stderr)
        return 1
    except Exception as e:
        # qubesd unreachable while reading the fleet, say: the class only.
        print(f"qmcp proposal {what}: {type(e).__name__}", file=sys.stderr)
        return 1


def _add_lead_options(p) -> None:
    p.add_argument("--lead-template", metavar="TEMPLATE", help="a fresh lead from this TemplateVM")
    p.add_argument("--lead-clone", metavar="QUBE", help="a fresh lead cloned from one of the hub's AppVMs")
    p.add_argument("--lead-promote", metavar="QUBE", help="make one of the hub's AppVMs the lead, in place")
    p.add_argument("--lead-netvm", metavar="QUBE|none", help="the lead's network (a fresh lead is born on it)")
    p.add_argument("--lead-name", metavar="NAME", help="a fresh lead's name (default: <space>lead)")
    p.add_argument("--model", metavar="HOST:PORT",
                   help="the lead's model endpoint: dom0 writes its firewall to allow that "
                        "endpoint, and DNS when it is a host name, nothing else (needed for a "
                        "lead with a network, unless the project already has one)")
    p.add_argument("--model-qube", metavar="QUBE|none",
                   help="instead of --model, the project's self-hosted model qube, which the "
                        "lead reaches on port 11434: the lead then has no network, and the qube "
                        "leaves p00, loses its network, is guarded and, unless it is already a "
                        "guarded model qube, is killed if it runs; none takes the project's "
                        "model qube away")


def _choices(pairs) -> dict:
    out = {}
    for pair in pairs or ():
        name, _, state = pair.partition("=")
        if state not in ("managed", "guarded"):
            raise SystemExit(f"qmcp migrate: --map wants NAME=managed|guarded, got '{pair}'")
        out[name] = state
    return out


def cmd_migrate(args) -> int:
    app = _app()
    steps, problems = fleet.plan_migration(app, _choices(args.map),
                                           exec_default=args.exec_default,
                                           compat_default=args.compat_default)
    for s in steps:
        print(("apply  " if args.apply else "plan   ") + repr(s))
    for p in problems:
        print(f"BLOCKED {p}")
    if problems:
        print("\nqmcp migrate: resolve the BLOCKED items first; nothing was changed.")
        return 1
    if not steps:
        print("qmcp migrate: nothing to do.")
        return 0
    if not args.apply:
        print("\nqmcp migrate: dry run. Re-run with --apply to make these changes.")
        return 0
    results = fleet.apply_migration(app, steps)
    for r in results:
        print(r)
    if any(r.startswith("FAILED") for r in results):
        return 1
    for path in fleet.finish_migration():
        print(f"retired {path}")
    return 0


def cmd_audit(args) -> int:
    if args.what == "rotate":
        print(f"rotated: the old log is now {audit.rotate(args.path)}")
        return 0
    if args.what == "verify":
        ok, n, err = audit.verify(args.path)
        print(json.dumps({"ok": ok, "entries": n, "error": err}))
        return 0 if ok else 1
    try:
        records = audit.tail(args.n, args.path)
    except OSError as e:
        print(f"qmcp audit tail: cannot read the log ({e.strerror or type(e).__name__})",
              file=sys.stderr)
        return 1
    for rec in records:
        print(json.dumps(rec, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Every command and option. The operator's window is tested against this
    parser: a command or option it neither offers nor exempts fails its suite."""
    ap = argparse.ArgumentParser(prog="qmcp", description="qubes-mcp operator command (dom0)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check", help="verify the fleet and the install")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("list", help="list AI space")
    p.add_argument("--json", action="store_true")
    p.add_argument("--all", action="store_true", help="also every qube outside AI space but dom0")
    p = sub.add_parser("settings", help="the operator files and the disk AI space uses")
    p.add_argument("--json", action="store_true")
    ssub = p.add_subparsers(dest="what")
    q = ssub.add_parser("set", help="change the pool cap, the private-volume cap or birth "
                                    "egress (root)")
    q.add_argument("--pool-cap", metavar="SIZE", help="the disk all of AI space may hold, e.g. 200G")
    q.add_argument("--private-cap", metavar="SIZE", help="the largest private volume one qube "
                                                         "may ask for, e.g. 20G")
    q.add_argument("--birth-egress", metavar="QUBE|none",
                   help="where the hub's template-based qubes go online (an enrolled gateway)")
    p = sub.add_parser("template", help="qmcp's in-qube services in a template or standalone")
    tsub = p.add_subparsers(dest="what", required=True)
    q = tsub.add_parser("prepare", help="write them into a TemplateVM or StandaloneVM, starting "
                                        "it if halted (root)")
    q.add_argument("qube")
    tsub.add_parser("refresh", help="bring every RUNNING prepared qube up to the installed "
                                    "services; never starts one (its timer runs this)")
    p = sub.add_parser("restored", help="qubes back from a backup or a copy, held for review")
    rsub = p.add_subparsers(dest="what", required=True)
    q = rsub.add_parser("list", help="every badged qube whose label is not its own, and every "
                                     "held one, with what it came back as")
    q.add_argument("--json", action="store_true")
    q = rsub.add_parser("accept", help="label each and lift the hold; its badges stay (root)")
    q.add_argument("qube", nargs="*", help="the qubes you reviewed")
    q.add_argument("--all", action="store_true",
                   help="every qube held when it runs (after qmcp import)")
    q = rsub.add_parser("reject", help="take every qmcp badge off; the qube stays (root)")
    q.add_argument("qube")
    p = sub.add_parser("export", help="the operator files, as one file in your dom0 home (root)")
    p.add_argument("file", nargs="?", help="where to write it (default: your home)")
    p = sub.add_parser("import", help="an export's operator files, onto a fresh install (root)")
    p.add_argument("file")
    for name, text in (("manage", "make a qube managed (the hub may operate it)"),
                       ("guard", "make a qube guarded (reference only); a model qube that was "
                                 "managed is killed if it runs (never a gateway or a template)"),
                       ("revoke", "take a qube out of AI space and shut it down")):
        p = sub.add_parser(name, help=text)
        p.add_argument("qube")
        if name == "revoke":
            p.add_argument("--no-shutdown", action="store_true")
    p = sub.add_parser("open", help="open a guarded qube to the hub for a bounded time; the "
                                    "timer, qmcp seal and every boot close it")
    p.add_argument("qube")
    p.add_argument("--for", dest="duration", required=True, metavar="DURATION",
                   help="how long the window lasts: 90s, 30m, 2h; at most 24h, and there is no "
                        "indefinite open (qmcp manage leaves the guarded state altogether)")
    p.add_argument("--firewall", action="store_true",
                   help="also let the hub write this qube's firewall rules while it is open")
    p = sub.add_parser("seal", help="close a guarded qube's window now, and kill what the hub "
                                    "left running in it")
    p.add_argument("qube", nargs="?")
    p.add_argument("--all", action="store_true",
                   help="every open qube, whatever its record says (qmcp-seal.service runs this "
                        "at every boot)")
    p.add_argument("--expired", action="store_true",
                   help="only the windows that ran out, that have no readable record, or that "
                        "sit on a qube qmcp open refuses (the gate's timer runs this)")
    p = sub.add_parser("gateway", help="the networks AI space may use")
    gsub = p.add_subparsers(dest="what", required=True)
    q = gsub.add_parser("list", help="every enrolled gateway, and whether it is still usable")
    q.add_argument("--json", action="store_true")
    q = gsub.add_parser("enroll", help="let AI space use a gateway (root)")
    q.add_argument("qube")
    q.add_argument("--anonymising", action="store_true", help="it reaches the network anonymously (Tor)")
    q.add_argument("--updates", action="store_true",
                   help="with --anonymising: the qube above it carries templates' updates "
                        "anonymously (sys-whonix, a VPN qube), so updates may go there")
    q.add_argument("--label", metavar="TEXT", help="a label, e.g. a jurisdiction (40 characters)")
    q = gsub.add_parser("set", help="change an enrolled gateway's flag, label or updates tick "
                                    "(root)")
    q.add_argument("qube")
    q.add_argument("--anonymising", choices=("yes", "no"))
    q.add_argument("--updates", choices=("yes", "no"),
                   help="whether templates' updates may go to the qube above it")
    q.add_argument("--label", metavar="TEXT")
    q = gsub.add_parser("remove", help="stop AI space using a gateway (root; refused while in use)")
    q.add_argument("qube")
    p = sub.add_parser("project", help="projects: a lead and its workers in one of 15 slots")
    psub = p.add_subparsers(dest="what", required=True)
    q = psub.add_parser("list", help="every slot in use")
    q.add_argument("--json", action="store_true")
    q = psub.add_parser("show", help="one project's record")
    q.add_argument("name", help="label or slot")
    q = psub.add_parser("create", help="a new project (root)")
    q.add_argument("name", metavar="LABEL", nargs="?",
                   help="1-8 lowercase letters or digits (none for --anonymous, or in anonymous "
                        "mode: dom0 picks one)")
    q.add_argument("--anonymous", action="store_true",
                   help="under the anonymity gate: anonymising networks, guarded templates, a "
                        "fresh lead; hidden from the hub unless --hub-sees")
    q.add_argument("--hub-sees", action="store_true",
                   help="an anonymous project the hub may see and operate")
    q.add_argument("--note", metavar="TEXT",
                   help="an anonymous project's private note: dom0 only, shown in the window")
    _add_lead_options(q)
    q.add_argument("--template", action="append", metavar="TEMPLATE",
                   help="an approved template besides the lead's (repeatable)")
    q.add_argument("--network", action="append", metavar="QUBE|none", required=True,
                   help="a worker network, the first is the default (repeatable)")
    q.add_argument("--quota", required=True, help="the workers' disk quota, e.g. 40G")
    q.add_argument("--dump", action="store_true", help="also create the project's dump sink")
    q = psub.add_parser("edit", help="replace templates or networks, or change the quota (root)")
    q.add_argument("name", help="label or slot")
    q.add_argument("--template", action="append", metavar="TEMPLATE")
    q.add_argument("--network", action="append", metavar="QUBE|none")
    q.add_argument("--quota")
    q = psub.add_parser("lead", help="remove or change a project's lead (root)")
    q.add_argument("name", help="label or slot")
    q.add_argument("--remove", action="store_true", help="remove the lead; the project and its workers stay")
    _add_lead_options(q)
    q.add_argument("--keep-old", action="store_true", help="keep the old lead as a worker of the project")
    q.add_argument("--add-old-network", action="store_true",
                   help="with --keep-old: add the old lead's network to the worker networks; "
                        "without it, an old lead on an unlisted network loses its network")
    q = psub.add_parser("firewall", help="a lead's firewall: show it, or change it (root)")
    q.add_argument("name", help="label or slot")
    q.add_argument("--json", action="store_true")
    q.add_argument("--model", metavar="HOST:PORT",
                   help="a new model endpoint for a lead with a network; its firewall becomes "
                        "that endpoint, and DNS when it is a host name, nothing else")
    q.add_argument("--model-qube", metavar="QUBE|none",
                   help="the project's self-hosted model qube (the lead loses its network, and "
                        "the qube leaves p00, loses its network, is guarded and, unless it is "
                        "already a guarded model qube, is killed if it runs), or none (the "
                        "project's model qube is taken away; nothing else changes)")
    q.add_argument("--rule", action="append", metavar="RULE",
                   help="set exactly these rules, in qubesd's format, e.g. "
                        "'action=accept proto=tcp dsthost=example.com dstports=443' (repeatable)")
    q.add_argument("--accept-current", action="store_true",
                   help="record the lead's current rules as accepted, if they are in qmcp's rule "
                        "format (no comment or expire, at most 32); the qube does not change")
    q = psub.add_parser("dump", help="create a dump sink for a project or p00 (root)")
    q.add_argument("name", help="label, slot, or p00")
    q.add_argument("--name", dest="sink_name", metavar="NAME")
    q = psub.add_parser("move", help="move an AppVM into p00, a project, or no slot (root)")
    q.add_argument("name", metavar="QUBE")
    q.add_argument("target", help="p00, a project's label or slot, or none")
    q.add_argument("--yes", action="store_true",
                   help="confirm moving a qube out of one slot into another, or into or out of "
                        "an anonymous project")
    q = psub.add_parser("unblock", help="clear the anonymity gate's stop once it finds the "
                                        "project sound, or the hub's: p00 (root)")
    q.add_argument("name", help="label or slot, or p00 for the hub and its qubes")
    q = psub.add_parser("delete", help="remove a project's lead and members, keep its sink "
                                         "(root; without --yes, the plan only)")
    q.add_argument("name", help="label or slot; a slot with no record finishes a delete")
    q.add_argument("--yes", action="store_true")
    p = sub.add_parser("gate", help="judge the anonymous projects (and the hub, in anonymous mode) "
                                    "now, and stop what is not sound")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("proposal", help="the hub's proposals: what it asks you to do")
    psub = p.add_subparsers(dest="what", required=True)
    q = psub.add_parser("list", help="every proposal, newest first")
    q.add_argument("--json", action="store_true")
    q = psub.add_parser("show", help="one proposal: what accepting it does now, and why it needs "
                                     "the second tick if it does")
    q.add_argument("id", type=int)
    q.add_argument("--json", action="store_true")
    q = psub.add_parser("accept", help="run a proposal's command as you (root)")
    q.add_argument("id", type=int)
    q.add_argument("--sha256", required=True, metavar="FINGERPRINT",
                   help="the fingerprint `show` gave: a stored file that differs is refused")
    q.add_argument("--yes", metavar="TICK",
                   help="the second tick, for a proposal `show` says needs one: the tick `show` "
                        "gave, which names the reasons it answers")
    q = psub.add_parser("reject", help="close a proposal without running it (root)")
    q.add_argument("id", type=int)
    p = sub.add_parser("migrate", help="map v0.9.16 tiers to managed/guarded")
    p.add_argument("--apply", action="store_true", help="make the changes (default: dry run)")
    p.add_argument("--map", action="append", metavar="QUBE=managed|guarded")
    p.add_argument("--exec-default", choices=("managed", "guarded"),
                   help="state for every ai-exec/ai-net qube not given --map")
    p.add_argument("--compat-default", choices=("managed", "guarded"),
                   help="state for umbrella-only qubes on a never-flipped fleet")
    p = sub.add_parser("audit", help="the audit chain")
    p.add_argument("what", choices=("verify", "tail", "rotate"))
    p.add_argument("n", nargs="?", type=int, default=20)
    p.add_argument("--path", default=None)
    sub.add_parser("version")
    return ap


def _names(values) -> list:
    return [str(v)[:128] for v in list(values or ())[:32]]


def operator_line(args):
    """(command, summary) for the audit line a command leaves, or None for one
    that changes nothing: a read, a plan, a dry run. The summary holds the
    names it acts on and its options; a quota only as "set". Accept
    and reject write their own line, with the proposal's fingerprint; a
    rotation writes the first line of the new log itself."""
    c = args.cmd
    if c == "settings":
        if getattr(args, "what", None) != "set":
            return None
        return "qmcp settings set", {"pool_cap": None if args.pool_cap is None else "set",
                                     "private_cap": None if args.private_cap is None else "set",
                                     "birth_egress": None if args.birth_egress is None
                                     else str(args.birth_egress)[:128]}
    if c == "template":
        # The refresh is the timer's: it writes one line per qube it changed.
        return None if args.what == "refresh" else ("qmcp template prepare",
                                                    {"qube": str(args.qube)[:128]})
    if c == "restored":
        if args.what == "list":
            return None
        qubes = args.qube if isinstance(args.qube, list) else ([] if args.qube is None
                                                               else [args.qube])
        return f"qmcp restored {args.what}", {"qubes": _names(qubes),
                                              "all": bool(getattr(args, "all", False))}
    if c == "export":
        return "qmcp export", {"file": None if args.file is None else str(args.file)[:128]}
    if c == "import":
        return "qmcp import", {"file": str(args.file)[:128]}
    if c in ("manage", "guard", "revoke"):
        summary = {"qube": str(args.qube)[:128]}
        if c == "revoke":
            summary["no_shutdown"] = bool(args.no_shutdown)
        return f"qmcp {c}", summary
    if c == "open":
        return "qmcp open", {"qube": str(args.qube)[:128], "for": str(args.duration)[:32],
                             "firewall": bool(args.firewall)}
    if c == "seal":
        if args.qube is None:
            # A sweep: the gate's timer runs one every 15 seconds and the boot
            # unit one at every boot, and almost all of them find nothing. A
            # line per run would be 5,760 a day, which buries what the
            # operator actually did and rotates the log for no reason.
            # `expire_windows` writes one line per qube it really seals, so a
            # quiet run leaves nothing and a real one is recorded in full.
            return None
        return "qmcp seal", {"qube": str(args.qube)[:128]}
    if c == "gateway":
        if args.what == "list":
            return None
        summary = {"qube": str(args.qube)[:128]}
        if args.what in ("enroll", "set"):
            summary["anonymising"] = args.anonymising if args.what == "set" else bool(args.anonymising)
            summary["label"] = None if args.label is None else str(args.label)[:128]
        return f"qmcp gateway {args.what}", summary
    if c == "migrate" and args.apply:
        return "qmcp migrate", {"map": _names(args.map), "exec_default": args.exec_default,
                                "compat_default": args.compat_default}
    if c != "project" or args.what in ("list", "show") or \
            (args.what == "delete" and not args.yes) or \
            (args.what == "firewall" and args.model is None and not args.rule
             and not args.accept_current and args.model_qube is None):
        return None
    w = args.what
    summary = {"project": str(args.name)[:128] if args.name is not None else None}
    if w in ("create", "lead"):
        source, origin = _lead_source(args)
        if source:
            summary[f"lead_{source}"] = str(origin)[:128]
        for key in ("lead_netvm", "lead_name", "model", "model_qube"):
            if getattr(args, key) is not None:
                summary[key] = str(getattr(args, key))[:128]
    if w == "create":
        summary.update({"templates": _names(args.template), "networks": _names(args.network),
                        "dump": bool(args.dump)})
        # Only when given, so the line of an ordinary create keeps its shape.
        if args.anonymous:
            summary["anonymous"] = True
        if args.hub_sees:
            summary["hub_sees"] = True
        if args.note is not None:
            summary["note"] = "set"
        if args.quota is not None:
            summary["quota"] = "set"
    elif w == "edit":
        if args.template is not None:
            summary["templates"] = _names(args.template)
        if args.network is not None:
            summary["networks"] = _names(args.network)
        if args.quota is not None:
            summary["quota"] = "set"
    elif w == "lead":
        summary.update({"remove": bool(args.remove), "keep_old": bool(args.keep_old),
                        "add_old_network": bool(args.add_old_network)})
    elif w == "firewall":
        summary.update({"model": None if args.model is None else str(args.model)[:128],
                        "model_qube": None if args.model_qube is None else str(args.model_qube)[:128],
                        "rules": len(args.rule or ()), "accept_current": bool(args.accept_current)})
    elif w == "dump":
        summary["name"] = None if args.sink_name is None else str(args.sink_name)[:128]
    elif w == "move":
        summary = {"qube": str(args.name)[:128], "target": str(args.target)[:128],
                   "yes": bool(args.yes)}
    return f"qmcp project {w}", summary


def _record(line, rc: int) -> None:
    command, summary = line
    audit.audit(command, "operator", summary, rc == 0, None if rc == 0 else f"exit status {rc}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "version":
        print(_version())
        return 0
    handler = {"check": cmd_check, "list": cmd_list, "settings": cmd_settings,
               "manage": cmd_role, "guard": cmd_role, "revoke": cmd_role,
               "open": cmd_window, "seal": cmd_window,
               "gateway": cmd_gateway, "project": cmd_project, "proposal": cmd_proposal, "migrate": cmd_migrate,
               "audit": cmd_audit, "gate": cmd_gate, "template": cmd_template,
               "restored": cmd_restored, "export": cmd_export, "import": cmd_import}[args.cmd]
    line = operator_line(args)
    if line is None:
        rc = handler(args)
        if args.cmd == "proposal" and args.what == "accept":
            _gate_after(args)
        return rc
    try:
        rc = handler(args)
    except SystemExit:
        raise                   # refused before it ran: not root, or a malformed --map
    except BaseException:
        _record(line, 1)
        _gate_after(args)
        raise
    _record(line, rc)
    _gate_after(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())
