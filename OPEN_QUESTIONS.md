# Open questions — qubes-mcp

Design questions I actively want review on, from people familiar with the Qubes
Admin API and qrexec policy (R4.2+). These moved out of the README to keep it
focused on setup; the content below is unchanged. Several have since been taken
up on qubes-devel (linked below) — this file is the standing list.

Discuss in the **[qubes-devel design review](https://groups.google.com/g/qubes-devel/c/4NuSqL64DVE)**,
the **[Qubes forum thread](https://forum.qubes-os.org/t/41387)**, or open a
GitHub issue.

---

1. **Wrapped-reads existence-hiding.** Is returning a uniform `"not found"`
   from a dom0 qmcp wrapper a robust primitive against existence oracles, or
   are there qrexec-layer leaks (timing, error chains, side effects) I'm
   missing? *(Stage I-1 extends this primitive to the read **value** channel:
   a VM-valued property or list field that references an out-of-scope qube now
   collapses to an opaque `<out-of-scope>` sentinel — the read-path sibling of
   the F2 write-path cross-ref opacity in #8.)*
2. **`qubes.Filecopy` `@tag:ai-managed → @tag:ai-managed` allow.** Stage B
   adds a policy line bypassing the default `ask` dialog for inter-qube file
   transfer between ai-managed qubes. Are there assumptions in
   `qubes.Filecopy`'s implementation that depend on the dialog being present?
3. **`target=@adminvm` documentation gap.** Without that clause on
   tag-scoped admin allows, qrexec attempts to start the target VM during
   read-only operations. This is subtle, easy to miss, and not surfaced in
   current Qubes docs. Worth a docs PR? Happy to write it.
4. **Single-egress chokepoint + `provides_network` egress invariant.**
   Stage C designates one ai-managed qube (`ai-net-router`) with
   `provides_network=true` as the only egress AI sees, then refuses (via
   `qmcp.SetPropertyAIManaged`) any netvm mutation on ai-managed qubes
   carrying `provides_network=true`. Intent: only the operator changes
   the route, in dom0. Is this invariant tight enough — are there paths
   AI could use to bypass it (creating another provides_network qube
   through a side door, mutating `provides_network` through a property
   wrapper I haven't blocked, abusing network-stack properties I haven't
   thought of)?
5. **Single-egress vs. cascade as a Qubes idiom.** The original Stage C
   design was a cascade (`ai-sys-firewall` ← `ai-sys-tor` / `ai-sys-vpn`)
   with multiple ai-managed network qubes. The implemented design is one
   egress qube with the operator-chosen upstream (`sys-firewall` /
   `sys-whonix` / a VPN qube / null). Documented Qubes patterns lean on
   cascades; is the single-egress chokepoint an established pattern I
   missed, or a reinvention? Are there reasons (memory pressure, boot
   ordering, sys-net interactions) the cascade is preferred that I'm not
   seeing?
6. **`@tag:` matching on klass=DispVM targets.** Stage D testing
   surfaced this: a persistent DispVM (`app.add_new_vm("DispVM", …)`)
   carries the `ai-managed` tag directly (verified via the Admin API
   from dom0), but qrexec policy refuses
   `admin.vm.Remove * mcp-control @tag:ai-managed allow target=@adminvm`
   with "Request refused" — i.e., the rule never matches a klass=DispVM
   target on Qubes R4.3. The same rule works for klass=AppVM and
   klass=TemplateVM. The same effect was observed for
   `admin.vm.{Start,Shutdown,Kill,Pause,Unpause}`. We worked around
   this in Stage D by routing all lifecycle through a single dom0
   wrapper (`qmcp.LifecycleAIManaged`) that does the ai-managed check
   in dom0 with qubesadmin authority, sidestepping qrexec policy
   evaluation entirely — same posture as
   `qmcp.{Get,Set}PropertyAIManaged`. Is the underlying qrexec
   `@tag:`-on-DispVM behaviour intentional (lifecycle of disposables
   restricted to dom0 by design?), a bug, or a configuration step I'm
   missing? Even with the workaround in place, a definitive answer
   would let us decide whether the wrapper is permanent architecture
   or temporary scaffolding.
7. **qubesadmin `VMCollection` cache lag after
   `admin.vm.CreateDisposable`.** Stage E2's `qmcp.SpawnDisposableAIManaged`
   wrapper calls `admin.vm.CreateDisposable` via `qubesd_call`, gets
   back the new disposable's name, and then needs to set the
   `ai-managed` tag on it before returning. The natural code —
   `app.domains[disp_name].tags.add("ai-managed")` — raises
   `KeyError(disp_name)` for several seconds after creation: the
   `qubesadmin.app.VMCollection` populates lazily and doesn't refresh
   synchronously after CreateDisposable. We worked around it by
   routing tag.Set / tag.List / Kill through
   `app.qubesd_call(disp_name, ...)` directly, bypassing the cache.
   Is the lazy `VMCollection` the intended client-side contract
   (callers expected to handle the read-after-write lag themselves),
   or is it a missing cache-invalidation hook in the Admin client?
   A definitive answer would let us decide whether the direct-call
   pattern should propagate to other "create-then-mutate" wrappers
   (`SpawnAIManagedQube`, `CloneAIManagedQube`) that may have the
   same latent bug — we haven't hit it there because they apply the
   tag through the VM object returned by `add_new_vm`/`clone_vm`,
   which is freshly-fetched and doesn't go through the collection
   cache.
8. **Cross-ref error messages as an existence oracle — RESOLVED in
   Stage F2 bundle.** Stage F1's `qmcp.SetFeatureAIManaged` collapsed
   cross-VM-key cross-refs to a single opaque refusal so AI cannot
   probe whether an arbitrary qube name exists; the older
   `qmcp.SetPropertyAIManaged` and `qmcp.SpawnAIManagedQube` wrappers
   distinguished `"not found"` from `"is not ai-managed"` on their
   cross-refs, a latent existence oracle on the write/spawn surface.
   The Stage F2 bundle backports the same opaque collapse to both
   older wrappers (template/netvm/default_dispvm for SetProperty,
   template/netvm for Spawn). Klass-mismatch and egress-invariant
   messages stay informative: they fire only after the referenced
   qube has been confirmed ai-managed, so AI already has the bit
   they would reveal. The read and lifecycle surfaces remain
   uniformly opaque; cross-ref refusals on every write/spawn surface
   are now opaque too. Reviewers welcome to flag any remaining
   distinguishable refusal on the write side.

9. **Event-stream payload — kwargs whitelist.** Stage F2's
   `qmcp.AIManagedEvents` returns a minimal payload per event:
   `{event, subject, subject_klass, ts}`, plus a whitelisted `tag`
   kwarg for `domain-tag-add` / `domain-tag-delete` (the one piece
   of payload data that's load-bearing — AI must see which tag
   changed to act on a boundary revocation). All other kwargs are
   dropped by default because some events (notably `property-set`)
   carry references to other qube names that could leak operator
   qubes into AI's view. Is the no-kwargs default the right cut, or
   are there specific kwargs a downstream stage will need (e.g.
   `exit_code` on `domain-stopped`, `value` on property-set)? Easy
   to expand the whitelist; hard to retract leaked fields. We're
   inclined to expand only with a concrete use case and a per-event
   leak analysis.

10. **Event-stream tag check for vanished subjects.** Admin events
    like `domain-shutdown` / `domain-delete` fire *after* the VM
    is removed from the dom0 collection, so a live `vm.tags` check
    at handler time raises `KeyError`. Our wrapper falls back to a
    snapshot of ai-managed names taken at window-open. Live wins
    over snapshot when the VM still exists, so newly-tagged
    qubes surface their post-tag events and newly-untagged qubes
    drop out (except for `domain-tag-delete:ai-managed` itself —
    the boundary-revocation event has a special case that includes
    it when the subject was in the snapshot). The snapshot is
    never refreshed during the window. Cost: a `domain-tag-add`
    + immediate delete on a qube that was *not* in the snapshot
    drops the delete event (snapshot says no, live says no
    because the VM is gone). The bounded duration `[1, 120]s`
    keeps this window small; reviewers welcome to flag a tighter
    design.

11. **Cap-as-contract vs. free-space-as-sensor for AI disk
    budgeting.** Stage F3's `qmcp.GetPoolStats` returns
    `{used, cap, headroom}` where `used` sums provisioned bytes
    across ai-managed qubes and `cap` is read from
    `/etc/qmcp/pool-cap` (a single integer the operator edits in
    dom0; re-read per call). We deliberately did NOT expose
    `free_bytes` of the underlying pool because that's a streaming
    operator-side oracle (free bytes drop whenever the operator
    creates a VM, untars a backup, etc., so AI polling free_bytes
    would have a sensor into operator behaviour). The cap goes the
    other direction: it's a contract operator → AI (the budget the
    operator allocated AI for spawn loops), not a sensor AI →
    operator. (a) Is this the right cut, or is there a Qubes idiom
    for tag-scoped resource accounting that already solves this
    cleanly? (b) `vol.size` is provisioned size, so for thin-LVM
    over-provisioning AI seeing 20 GiB headroom isn't a
    write-success guarantee — we've treated this as correctly
    operator-side (the cap is what the operator allocated; whether
    the underlying pool can fulfill it is operator concern). Is
    that the right division, or would AI benefit from a
    physically-grounded headroom number that doesn't widen the
    side-channel? (c) Cap-file format: single integer in a
    plain-text file, edited with `sudo sh -c 'echo N > ...'`.
    Anything more structured (TOML, per-pool caps, time-window
    quotas) feels like premature complexity, but happy to be told
    otherwise.

12. **Sibling-import for shared dom0 helpers vs. installed-package
    convention.** Stage I-0 introduces a shared dom0 helper
    (`qmcp_budget.py`) consumed by three create wrappers
    (`qmcp.SpawnAIManagedQube` / `CloneAIManagedQube` /
    `SpawnDisposableAIManaged`) via
    `importlib.util.spec_from_file_location` against
    `os.path.dirname(os.path.realpath(__file__))`. The same loader
    works in `/etc/qubes-rpc/` (production) and in
    `public/dom0-rpc/` (offline-validation) without any sys.path or
    PYTHONPATH dependency. This deviates from Qubes' own
    convention: every Python script in
    `qubes-core-admin/qubes-rpc/` (e.g. `qubes.GetDate`) and every
    tool in `qubes-core-admin-client/qubesadmin/tools/` (e.g.
    `qvm_run.py`) is self-contained — shared infrastructure is
    consumed via the globally installed `qubesadmin` package, and
    no qubes-rpc script sibling-imports another. We deviate
    because our deployment is tarball + slot runner, not RPM, so
    installing a shared Python module under
    `/usr/lib/python3/dist-packages/` per slot adds packaging
    overhead disproportionate to a ~150-line helper. As Stage I
    grows (I-1 tier-resolution helper, I-3 wrapper-surface
    enforcement, I-4+ action gate), the shared-helper surface
    grows too. (a) Is the sibling-import workaround acceptable for
    a project of this scope, or is shipping a tiny
    `qubes-mcp-helpers` RPM the cleaner long-term answer once the
    helper count justifies it (rough threshold: >300 shared lines
    or >3 helpers)? (b) If we stay sibling-import, is the explicit
    `importlib.util.spec_from_file_location` we chose preferable
    to the more idiomatic
    `sys.path.insert(0, helper_dir); import qmcp_budget` — i.e.
    are there `__file__` / sys.path edge cases in the qrexec
    policy-daemon's invocation environment (symlinks under
    `/usr/local/etc/qubes-rpc/`, chdir, custom argv[0]) that argue
    for the more explicit form? (c) Either way: any direct
    precedent in the Qubes ecosystem we should be borrowing from
    that we missed?
