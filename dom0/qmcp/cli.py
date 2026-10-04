"""`qmcp` — the operator's command in dom0.

    qmcp check [--json]            is the fleet sound? (exit 0 GREEN, 1 FAILED, 3 INCOMPLETE)
    qmcp list [--all] [--json]     AI space: state, class, template, network, slot, owner
    qmcp settings [--json]         the operator files and the disk AI space uses
    qmcp manage|guard|revoke QUBE  role actions
    qmcp project ...               projects: list, show, create, edit, lead, dump, move, delete
    qmcp proposal ...              the hub's proposals: list, show, accept, reject
    qmcp migrate [--apply] ...     move a v0.9.16 tiered fleet to two states
    qmcp audit verify|tail [N]|rotate   the hash-chained record of state changes
    qmcp version

The operator's window, `qmcp-gui`, runs these same commands: reads as you,
changes under `sudo -n`.

Run it as root, or as a member of the `qubes` group. The project commands that
change anything write /etc/qmcp/projects.json or take its lock, so they need
root; so do accepting and rejecting a proposal.

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

from qmcp import audit, fleet, projects, proposals

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
    return 0


def _need_root(what: str) -> None:
    if os.geteuid() != 0:
        raise SystemExit(f"qmcp project {what}: run as root (sudo qmcp project {what} ...); "
                         f"it writes {projects.PROJECTS_PATH} or takes its lock")


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
                print(f"{r['slot']}  {r['label'] or '(hub)':8s}  lead={r['lead'] or '-'}  "
                      f"members={r['members']}  disk={used}/{quota} GiB  sink={r['dump'] or '-'}")
            return 0
        if what == "show":
            p = projects.find(fleet._load_records(), args.name)
            if p is None:
                raise fleet.ProjectError(f"no project '{args.name}'")
            print(json.dumps(dict(p.to_json(), slot=p.slot), indent=2))
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
            report = fleet.create_project(app, args.name, source, origin, args.template or (),
                                          args.network or (), args.quota, args.lead_netvm,
                                          args.dump, args.lead_name)
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
                                        args.keep_old, args.lead_name)
        elif what == "dump":
            report = fleet.add_dump(app, args.name, args.sink_name)
        elif what == "move":
            report = fleet.move(app, args.name, args.target, confirm=args.yes)
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
    for name, text in (("manage", "make a qube managed (the hub may operate it)"),
                       ("guard", "make a qube guarded (reference only)"),
                       ("revoke", "take a qube out of AI space and shut it down")):
        p = sub.add_parser(name, help=text)
        p.add_argument("qube")
        if name == "revoke":
            p.add_argument("--no-shutdown", action="store_true")
    p = sub.add_parser("project", help="projects: a lead and its workers in one of 15 slots")
    psub = p.add_subparsers(dest="what", required=True)
    q = psub.add_parser("list", help="every slot in use")
    q.add_argument("--json", action="store_true")
    q = psub.add_parser("show", help="one project's record")
    q.add_argument("name", help="label or slot")
    q = psub.add_parser("create", help="a new project (root)")
    q.add_argument("name", metavar="LABEL", help="1-8 lowercase letters or digits")
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
    q = psub.add_parser("dump", help="create a dump sink for a project or p00 (root)")
    q.add_argument("name", help="label, slot, or p00")
    q.add_argument("--name", dest="sink_name", metavar="NAME")
    q = psub.add_parser("move", help="move an AppVM into p00, a project, or no slot (root)")
    q.add_argument("name", metavar="QUBE")
    q.add_argument("target", help="p00, a project's label or slot, or none")
    q.add_argument("--yes", action="store_true",
                   help="confirm moving a qube out of one slot into another")
    q = psub.add_parser("delete", help="remove a project's lead and members, keep its sink "
                                         "(root; without --yes, the plan only)")
    q.add_argument("name", help="label or slot; a slot with no record finishes a delete")
    q.add_argument("--yes", action="store_true")
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
    if c in ("manage", "guard", "revoke"):
        summary = {"qube": str(args.qube)[:128]}
        if c == "revoke":
            summary["no_shutdown"] = bool(args.no_shutdown)
        return f"qmcp {c}", summary
    if c == "migrate" and args.apply:
        return "qmcp migrate", {"map": _names(args.map), "exec_default": args.exec_default,
                                "compat_default": args.compat_default}
    if c != "project" or args.what in ("list", "show") or \
            (args.what == "delete" and not args.yes):
        return None
    w = args.what
    summary = {"project": str(args.name)[:128]}
    if w in ("create", "lead"):
        source, origin = _lead_source(args)
        if source:
            summary[f"lead_{source}"] = str(origin)[:128]
        for key in ("lead_netvm", "lead_name"):
            if getattr(args, key) is not None:
                summary[key] = str(getattr(args, key))[:128]
    if w == "create":
        summary.update({"templates": _names(args.template), "networks": _names(args.network),
                        "dump": bool(args.dump)})
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
        summary.update({"remove": bool(args.remove), "keep_old": bool(args.keep_old)})
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
               "project": cmd_project, "proposal": cmd_proposal, "migrate": cmd_migrate,
               "audit": cmd_audit}[args.cmd]
    line = operator_line(args)
    if line is None:
        return handler(args)
    try:
        rc = handler(args)
    except SystemExit:
        raise                   # refused before it ran: not root, or a malformed --map
    except BaseException:
        _record(line, 1)
        raise
    _record(line, rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
