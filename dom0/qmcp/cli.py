"""`qmcp` — the operator's command in dom0.

    qmcp check                     is the fleet sound? (exit 0 GREEN, 1 FAILED, 3 INCOMPLETE)
    qmcp list                      AI space: state, class, template, network, owner
    qmcp manage|guard|revoke QUBE  role actions: the only way badges change
    qmcp migrate [--apply] ...     move a v0.9.16 tiered fleet to two states
    qmcp audit verify|tail [N]|rotate   the hash-chained record of state changes
    qmcp version

Run it as root, or as a member of the `qubes` group.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from qmcp import audit, fleet

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
    for f in findings:
        print(repr(f))
    result = fleet.overall(findings)
    print(f"\nqmcp check: {result}" + ("  (INCOMPLETE is not green)" if result == "INCOMPLETE" else ""))
    return EXIT[result]


def cmd_list(args) -> int:
    rows = fleet.listing(_app())
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    cols = ("name", "state", "klass", "template", "netvm", "power", "owner")
    widths = {c: max([len(c)] + [len(str(r[c] or "-")) for r in rows]) for c in cols}
    print("  ".join(c.upper().ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r[c] or "-").ljust(widths[c]) for c in cols))
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
    for rec in audit.tail(args.n, args.path):
        print(json.dumps(rec, sort_keys=True))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="qmcp", description="qubes-mcp operator command (dom0)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="verify the fleet and the install")
    p = sub.add_parser("list", help="list AI space")
    p.add_argument("--json", action="store_true")
    for name, text in (("manage", "make a qube managed (the hub may operate it)"),
                       ("guard", "make a qube guarded (reference only)"),
                       ("revoke", "take a qube out of AI space and shut it down")):
        p = sub.add_parser(name, help=text)
        p.add_argument("qube")
        if name == "revoke":
            p.add_argument("--no-shutdown", action="store_true")
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
    args = ap.parse_args(argv)
    if args.cmd == "version":
        print(_version())
        return 0
    handler = {"check": cmd_check, "list": cmd_list, "manage": cmd_role,
               "guard": cmd_role, "revoke": cmd_role, "migrate": cmd_migrate,
               "audit": cmd_audit}[args.cmd]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
