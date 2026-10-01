# Upstream Qubes OS 4.3 qrexec policy (test baseline)

`tests/test_policy.py` loads these files next to `policy/30-mcp-control.policy`
so the offline matrix runs against Qubes' real default policy rather than a
hand-written subset. They are test data only: the installer never ships them.

Fetched on 2026-10-01 from the `release4.3` branches:

| File | Source |
|---|---|
| `90-default.policy`, `85-admin-backup-restore.policy`, `91-admin-default-deny.policy`, `include/admin-{global,local}-{ro,rwx}` | `QubesOS/qubes-core-admin`, `qubes-rpc-policy/` |
| `90-admin-policy-default.policy`, `include/admin-policy-{ro,rwx}` | `QubesOS/qubes-core-qrexec`, `policy.d/` |
| `90-admin-default.policy` | generated: upstream builds it at package time with `qubes-rpc-policy/generate-admin-policy`, which prepends `90-admin-default.policy.header` and adds one `!include-service` line per method registered in `qubes/api/admin.py`. It was rebuilt here from the release4.3 `admin.py`, with device classes pci, block, usb, mic and VM classes AdminVM, AppVM, DispVM, RemoteVM, StandaloneVM, TemplateVM. |

These files are part of Qubes OS and keep its licence (LGPL-2.1-or-later). They
are a record of upstream's defaults on that date, not of any particular dom0.
On a real install, other packages add files of their own; the installer checks
the policy against the box's actual `/etc/qubes/policy.d/`.
