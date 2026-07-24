from qubes_mcp.server import Ring, ring_tool
from qubes_mcp.tools._qrexec import GATED_TIMEOUT, call_qmcp


@ring_tool(Ring.LIFECYCLE)
def qubes_spawn(
    name: str,
    template: str,
    klass: str = "AppVM",
    label: str = "gray",
    netvm: str | None = None,
    private_size: int | None = None,
) -> dict:
    """Create a new AI-managed qube.

    The new qube is auto-tagged `ai-managed` by the dom0 wrapper. `template`
    must itself be ai-managed; the wrapper validates the template's shape
    matches the requested klass (AppVM/DispVMTemplate need a TemplateVM;
    DispVM needs a qube with template_for_dispvms=True). If `netvm` is
    given, it must be ai-managed too. The wrapper refuses on validation
    failure.

    Klass support: AppVM (Stage A); DispVMTemplate and DispVM (Stage D).
    StandaloneVM and TemplateVM creation are not currently supported —
    every ai-managed qube derives from an operator-vetted ai-managed
    TemplateVM, which keeps the template-supply-chain narrow.

    Netvm defaulting:
      - not specified  → defaults to "ai-net-router" if it exists + ai-managed
      - explicit name  → used as-is; must be ai-managed

    `private_size` (bytes, optional) grows the new qube's persistent `private`
    volume beyond the Qubes default — for a qube that needs more working disk.
    It is the only disk dimension that counts against the pool budget (root is
    COW, volatile is ephemeral). The dom0 wrapper refuses a request above the
    operator's per-qube limit, and the overall create still refuses if it would
    exceed the pool cap. Omit it for the default size.
    """
    payload: dict = {"name": name, "template": template, "klass": klass, "label": label}
    if netvm is not None:
        payload["netvm"] = netvm
    if private_size is not None:
        payload["private_size"] = private_size
    return call_qmcp("qmcp.SpawnAIManagedQube", payload, timeout=GATED_TIMEOUT)
