"""qmcp — the dom0 side of qubes-mcp.

One library behind every `qmcp.*` qrexec service (`services`), the operator's
`qmcp` command (`cli`, `fleet`) and, later, the dom0 GUI. The installer puts it
under /usr/local/lib/qmcp/; the service shim and the CLI shim add that
directory to sys.path and import from here.
"""
