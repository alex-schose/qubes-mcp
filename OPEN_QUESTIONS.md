# Open questions — qubes-mcp

Design questions I want review on, from people who know the Qubes Admin API and
qrexec policy (R4.2+). Rewritten for 0.9.17, which replaced the tier model with
two states (managed and guarded) and a static rulebook; questions about the
removed mechanisms are gone, and the git history keeps them.

Discuss in the **[qubes-devel design review](https://groups.google.com/g/qubes-devel/c/4NuSqL64DVE)**,
the **[Qubes forum thread](https://forum.qubes-os.org/t/41387)**, or a GitHub
issue.

---

1. **Closing the disposable shortcut for a group of qubes.** A `@dispvm` rule
   target matches only the bare keyword, so `* * @tag:ai-managed @dispvm deny`
   does not cover `@dispvm:<name>`. The rulebook adds `* * @anyvm
   @dispvm:@tag:ai-managed deny`, which matches a bare `@dispvm` whose source's
   `default_dispvm` carries the tag and any `@dispvm:<name>` whose template does
   — from any source. That leaves a named template outside the group: the exec
   services are denied by their own `@anyvm` rules, but OpenInVM, OpenURL,
   StartApp and GetImageRGBA still reach Qubes' default `ask`. Read from
   `qrexec/policy/parser.py` (4.3.14) and confirmed against a real 4.3.1 policy
   set and from inside a qube. Is there a rule form that denies every
   `@dispvm:<name>` for a source group without enumerating templates, or should
   upstream have one?

2. **No prefix wildcard for services.** To refuse the Admin API to a group of
   qubes regardless of include files, the rulebook lists every method qubesd 4.3
   registers (122, device classes expanded), the two volume Import services and
   the policy API, each with an `@anyvm` target, and adds `* * @tag:ai-managed
   @adminvm deny` behind an allowlist of the five services a qube needs to boot.
   A method added by a later extension is covered only by Qubes' empty default
   includes. Would a service-prefix match (`admin.*`) be acceptable upstream, or
   is there a better shape?

3. **`target=@adminvm` documentation gap.** Without that clause on a
   tag-scoped admin allow, qrexec tries to start the target qube during a read.
   Subtle, easy to miss, and not in the current docs. Worth a docs PR?

4. **`@tag:` matching on DispVM targets for admin methods.** In 0.9.x testing,
   `admin.vm.Remove * mcp-control @tag:ai-managed allow target=@adminvm` never
   matched a persistent `klass=DispVM` target that carried the tag, while the
   same rule matched AppVMs and TemplateVMs. qmcp routes lifecycle through a
   dom0 service anyway, and `@tag:` matching on DispVM targets works for an
   ordinary service (`qmcp.RunInAIManaged` into a disposable, measured on
   4.3.1). Is the admin-method behaviour intended?

5. **`VMCollection` cache lag after `admin.vm.CreateDisposable`.**
   `app.domains[name]` raises `KeyError` for seconds after the call returns the
   new disposable's name, so qmcp stamps and checks the disposable through
   direct `qubesd_call`s. Is the lazy collection the intended client contract,
   or a missing invalidation hook?

6. **What creates copy.** `clone_vm` copies the source's tags (all but
   `created-by-*`) and `admin.vm.CreateDisposable` copies the template's, so
   after every create qmcp removes each of its badges the new qube must not
   carry, reads the tags back, and rolls the qube back on any mismatch. Is there
   a documented list of what each create path copies — or a way to create
   without copying tags — so this does not depend on observing the platform?

7. **Preloaded disposables in a tag-scoped world.** With `preload-dispvm-max`
   on a disposable template, qmcp's `CreateDisposable` path uses a preloaded
   qube (measured: a `qubes_run_disposable` cycle took 1.5 s with
   `preload-dispvm-max=1`, about 8 s without). While it waits, the preloaded
   qube carries its template's tags, so it shows up in AI space, guarded or
   managed like its template, until it is claimed. Is `is_preload` (or the
   `internal` feature) the intended way for a tool to recognise and skip it?

8. **Templates reaching the network.** A template the hub may edit can reach
   the network through `qubes.UpdatesProxy`, outside the network path AI qubes
   use. The plan is Qubes' per-template update-proxy setting, routed through
   the project's gateway. Is that the right lever, and does it cover
   `qubes-dom0-update`-style flows as well as in-template package managers?

9. **Event payloads.** `qmcp.AIManagedEvents` returns `{event, subject,
   subject_klass, ts}` plus `tag` for tag events, and drops every other kwarg
   (a `property-set` can carry other qubes' names). A subject that has
   vanished (`domain-shutdown`, `domain-delete`) falls back to the set taken
   when the window opened. Is the default-drop the right cut, and is there a
   tighter answer for subjects that come and go inside one window?

10. **Disk budget as a contract.** AI space sees `{used, cap, headroom}` of its
    persistent footprint against an operator-set cap, never free space (which
    would move with the operator's own actions and leak them). Transient
    volatile and copy-on-write root are not metered. Sound, or is there a
    platform pool-pressure signal that should also gate creates?

11. **A library behind the qrexec services.** qrexec services in dom0 are
    usually self-contained scripts. qmcp installs one library under
    `/usr/local/lib/qmcp/` and one identical shim under each service name that
    imports it. Reasonable, or is there an upstream convention for shared code
    between dom0 services?
