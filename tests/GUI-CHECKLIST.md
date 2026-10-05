# The window, by hand

A click-through of `qmcp-gui` for a person, after any install that changes the
window. `tests/test_gui.py` proves the window's logic offline, against the real
command; this list proves it on a real box, with real hands.

Run it in dom0, as your own user. You need a TemplateVM in AI space
(`<template>` below), an enrolled gateway (`<gateway>`: the Gateways tab lists
the enrolled ones), and `qmcp check` GREEN. The names `t1`, `ai-t1h`,
`ai-t1-lead`, `ai-t1-boss` and `t1-dump` must not exist yet. Answer by step
number: "pass", or what you saw instead.

Steps 18 to 21 and 29 play the hub's part as well, so they also need a terminal in
the hub (the qube the Settings tab names under *Hub (fixed at install)*), from
which they send the requests an agent would. The names `t2`, `t3` and
`ai-t2-lead` must not exist yet. The projects' quotas (*Disk quota* in each
project's details) plus 4 GiB must stay within *Pool cap (all of AI space)* on
the Settings tab: past it, the proposal in step 18 asks for a second tick that
the step does not expect.

Steps 23 to 29 cover the gateway registry and the leads' firewalls. They also
need: a TemplateVM outside AI space for a router, `<router-template>`, whose
`qvm-features <router-template> qubes-firewall` prints `1` (enrolling refuses a
router for which that feature is not on: its own value, else its template's); Whonix's
`sys-whonix`, whose `qvm-tags sys-whonix` lists `anon-gateway` (the tag
`qmcp gateway list` reads to mark the gateway in step 25); and a model endpoint, `<model>`, in the form `host:port` with a host name
(not an address, which qubesd states back as `dst4=`), such as
`api.anthropic.com:443`. The names `sys-ai-t4`, `t4`, `t5`, `ai-t4-lead` and
`ai-t5-lead` must not exist yet.

Every form shows, under its fields, the exact command OK will run. Check it
against the step each time; it is the window's promise that what you see is
what runs. While OK is off, that line says why instead, in orange, under
*OK is off:*.

1. **Open it from the menu.** In the Qubes menu, open the settings page
   (the gear), then *Qubes Tools*: *qubes-mcp* is listed beside Qube Manager.
   Also try `qmcp-gui` in a dom0 terminal. Expect: the window opens on the
   Qubes tab, and the light reads `qmcp check: GREEN` next to the time it ran.
2. **The tree matches the command.** Run `qmcp list` in a dom0 terminal.
   Expect: every qube it lists appears exactly once, under the hub (p00, or no
   slot), a project, Templates, Gateways or Other guarded.
3. **Add a qube.** Make one outside AI space, with no network (step 8 moves it
   into a project, which takes a qube only on one of its worker networks):
   `qvm-create --class AppVM --template <template> --label gray ai-t1h`, then
   `qvm-prefs ai-t1h netvm ''`. Press Refresh, *Add a qube to AI space...*,
   choose `ai-t1h`, tick *managed* (the form starts on *guarded*), OK.
   Expect: a report window that says done and shows the command it ran;
   `ai-t1h` under the hub's "no slot".
4. **Into p00.** Select `ai-t1h`, *Move...*, choose p00, OK. Expect: it moves
   under p00.
5. **A new project.** *New project...*. Expect OK greyed out while the form is
   incomplete. Fill: label `t1` (the *Lead name* field now shows `ai-t1-` in
   front, and stays empty for the default); the lead a fresh qube from
   `<template>`; worker networks `none` and `<gateway>`, default `none`; quota
   `4G`; OK. Expect: project `t1` with its lead `ai-t1-lead`.
6. **Edit it.** Select the project, *Edit project...*. Expect OK greyed out and
   "nothing changed". Set the quota to `6G`, OK. Expect: the details pane
   reads 6.0 GiB.
7. **A dump sink.** *Dump sink...*, OK. Expect: `t1-dump` under the project.
8. **Across slots.** Select `ai-t1h`, *Move...*, into `t1`. Expect the form's
   *Network* line to say `ai-t1h` is on none, and that `t1` takes qubes on
   none and `<gateway>`; OK greyed out until you tick the box saying it leaves
   p00. Tick it, OK. Expect: `ai-t1h` is a worker of `t1`.
9. **Change the lead.** Select the project, *Change lead...*. Choose *a fresh
   qube from a template*, *Made from* `<template>`. Expect OK greyed out until
   you choose what happens to the old lead: *The old lead* has no default.
   Choose *remove ...*: expect a red line saying `ai-t1-lead` will be removed
   with everything in it. Change it to *keep ai-t1-lead as a worker*: the red
   line goes, and OK stays greyed out, saying the old lead keeps the name
   `ai-t1-lead`. Type `boss` into *Lead name* (after the `ai-t1-` shown in
   front), OK. Expect: `ai-t1-boss` leads; `ai-t1-lead` is a worker.
10. **Remove the lead.** *Remove lead...*. Expect a red line saying
    `ai-t1-boss` will be removed with everything in it. OK. Expect: the project
    shows no lead; its workers stay; `ai-t1-boss` is gone.
11. **Revoke.** Select `ai-t1h`, *Revoke...*. The form says it takes the qube
    out of AI space without removing it. OK. Expect: it leaves the tree (it is
    no longer `ai-managed`; `qvm-ls` still lists it).
12. **A hostile name.** In the hub, as a person or an agent might:

    ```sh
    printf '%s' '{"name": "ai-x\u202egnp.exe\nFAKE <b>bold</b>", "action": "start"}' \
      | qrexec-client-vm dom0 qmcp.LifecycleAIManaged
    ```

    It is refused. Press Refresh, open the Audit tab. Expect: the newest row
    shows the name on one line, with `\u202e` and `\n` as visible text, never
    reversed or broken across lines, and `<b>` as plain text. Select the row:
    the pane below shows the whole line, still escaped.
13. **Verify and rotate.** Before rotating, expect the Audit tab to hold a line
    with caller `operator` for each change you made in steps 3 to 11 (services
    `qmcp manage`, `qmcp project move`, `qmcp project create` and so on), and
    none for Refresh or for *Verify the chain*: the log holds the calls the hub
    and the leads make to state-changing services, and every command of yours
    that changes something. *Verify the chain*: "chain OK". *Rotate...*, OK;
    verify again: "chain OK". Expect the list to hold one line, the rotation,
    with caller `operator`, and the pane under it to name the file the earlier
    lines moved to.
14. **The light.** In dom0, `qvm-tags ai-t1h add qmcp-proj-p09`, then Refresh.
    Expect: `qmcp check: FAILED`, and the Check tab lists the failure first.
    `qvm-tags ai-t1h del qmcp-proj-p09`, Refresh: GREEN again.
15. **Delete the project.** Select it, *Delete project...*. Expect: before
    anything is removed, the form shows the command's own account of what
    will go. OK. Expect: the project and its members are gone, and `t1-dump`
    is kept.
16. **Settings.** The Settings tab shows the hub, the name prefix, the caps,
    the disk AI space uses, the birth egress, the number of gateways enrolled,
    and the version, with no way to edit them.
17. **Busy.** Start any change, and while it runs, try another button.
    Expect: every action button is greyed out until the first one reports.
18. **A proposal arrives.** In the hub, propose a project as an agent would,
    with markup in its title:

    ```sh
    printf '%s' '{"type": "project-create", "title": "<b>t2</b> for testing",
      "label": "t2", "lead": {"from": "template", "qube": "<template>"},
      "networks": ["none"], "quota": 4294967296}' \
      | qrexec-client-vm dom0 qmcp.SubmitProposal
    ```

    Expect a one-line reply with `"ok": true` and `"id": N`; note N. A reply
    with `"ok": false` means the request is malformed (the error names the
    field): fix the command, not the window. In dom0, expect a desktop
    notification "Proposal N from the hub is waiting in the qubes-mcp window.",
    without the title. Press Refresh. Expect the tab to read *Proposals (1)*
    (one more than before, if others are waiting), and the list's top row to
    read N, `pending`, `project-create`, `t2`, with the title as plain text,
    `<b>t2</b> for testing`, never bold.
19. **Read it and accept it.** Select it. Expect the pane to show, among its
    lines: *State* `pending: waiting for you`; *Title (written by AI)* the
    same plain text; *Lead* `a fresh qube from the template <template>`;
    *Worker networks (first is the default)* `["none"]`; *Workers' disk quota*
    `4G` (a quota that is not whole GiB shows in bytes, exactly);
    *Equivalent command* `qmcp project create t2 --lead-template
    <template> --network none --quota 4G`; *Second tick* `not needed: one
    click is enough`. No red text and no tick box below it. Press *Accept...*.
    The form shows `/usr/bin/sudo -n /usr/local/bin/qmcp proposal accept N
    --sha256` followed by 64 hex digits: compare them with the pane's
    *Fingerprint (sha256)*, which must be the same. OK. Expect a report ending
    in `proposal N: accepted`; the tab count back down by one; the pane reading
    *Decision* `accepted`, with the command's own report under *Report*;
    *Accept...*, *Reject...* and *Close...* all greyed out; and on the Qubes
    tab the project `t2` with its lead `ai-t2-lead`.
20. **The second tick.** In the hub, propose deleting it:

    ```sh
    printf '%s' '{"type": "project-delete", "title": "remove t2", "project": "t2"}' \
      | qrexec-client-vm dom0 qmcp.SubmitProposal
    ```

    Refresh, select it. Expect: *Plan* naming `ai-t2-lead`; red text under the
    pane saying accepting it needs the second tick, because it deletes the
    project t2; *Second tick digest*, 64 hex digits; a tick box *I have read
    these reasons*, empty; *Accept...* and *Close...* greyed out, *Reject...*
    not. Tick the box: *Accept...* turns on. Press Refresh: afterwards the box
    is still ticked, since the reasons are the same. Press *Accept...*: the
    command now ends in `--yes` and 64 hex digits, which must be the same as
    *Second tick digest*, and the form repeats the red text. OK. Expect
    `proposal M: accepted`, and `t2` and `ai-t2-lead` gone from the Qubes tab.
21. **A refusal, and a rejection.** In the hub, propose a project whose lead
    template does not exist:

    ```sh
    printf '%s' '{"type": "project-create", "title": "no such template",
      "label": "t3", "lead": {"from": "template", "qube": "no-such-template"},
      "networks": ["none"], "quota": 1073741824}' \
      | qrexec-client-vm dom0 qmcp.SubmitProposal
    ```

    Expect `"ok": true`: the hub's request is checked for its shape only,
    never for whether a qube exists. Refresh, select it, *Accept...*, OK.
    Expect a report marked FAILED, with `stopped: 'no-such-template' is not a
    TemplateVM` and then `proposal K: failed`. That is the command refusing:
    nothing was created, and the proposal is closed, *Decision* `failed`; the
    hub may submit it again. Send the same request once more, Refresh, select
    the new proposal, *Reject...*, OK. Expect `proposal L: rejected`, *Report*
    `-`, and nothing created. On the Audit tab, expect a `qmcp.SubmitProposal`
    line with the hub as caller for each of the four requests, and a
    `qmcp proposal accept` or `qmcp proposal reject` line with caller
    `operator` for each of your four decisions.
22. **A proposal that needs closing.** This step damages one file in the
    proposal store on purpose, as a disk fault might, and the window repairs
    it. In a dom0 terminal, with NNNNNN the number L from step 21 written as
    six digits (proposal 4 is `000004`):
    `sudo sh -c 'printf garbage > /var/lib/qmcp/proposals/NNNNNN.decision'`.
    Press Refresh. Expect the row of L to read `failed, needs closing`, and the
    Check tab a WARN for *proposal store* naming L. Select it. Expect *Problem*
    `decision file unreadable (JSONDecodeError)`; *Needs closing* saying Close
    records it as failed and nothing in the fleet changes; *Close...* on,
    *Accept...* and *Reject...* greyed out, and no tick box. Press *Close...*:
    the form gives the same reason and shows `/usr/bin/sudo -n
    /usr/local/bin/qmcp proposal reject L`. OK. Expect `proposal L: failed`;
    the row reading `failed`; the pane reading *Decision* `failed` and *Report*
    `its decision file did not read; closed by the operator`, with no *Needs
    closing* line; the Check tab's *proposal store* PASS; and
    `ls /var/lib/qmcp/proposals/` listing `NNNNNN.decision.unreadable` beside
    `NNNNNN.decision`: the damaged file is kept, never deleted.
23. **Enroll a gateway.** Open the Gateways tab. Expect `<gateway>` listed,
    and when selected, *Problem* `none: AI space may use it`. Make a router of
    your own, outside AI space:
    `qvm-create --class AppVM --template <router-template> --label orange sys-ai-t4`,
    then `qvm-prefs sys-ai-t4 provides_network True` and
    `qvm-prefs sys-ai-t4 netvm sys-firewall`. Press Refresh, then *Enroll...*.
    Expect *Qube* with nothing chosen and OK greyed out; its list holds the
    qubes that provide network and are not enrolled, each marked *outside AI
    space* or *in AI space*, and not `<gateway>`. Choose `sys-ai-t4`, leave
    *Anonymising* unticked, type `t4 test` into *Label*. Expect the command
    `/usr/bin/sudo -n /usr/local/bin/qmcp gateway enroll sys-ai-t4 --label 't4 test'`.
    OK. Expect a report ending `sys-ai-t4: enrolled`, and the list gaining
    `sys-ai-t4` with *Upstream* `sys-firewall`, *In use* `0 qube(s)` and no
    *Notes*; the Settings tab's *Gateways enrolled* one more than before.
24. **Offered in the project forms.** On the Qubes tab, *New project...*.
    Expect *Worker networks* to list `none`, `<gateway>` and `sys-ai-t4`, and
    any other enrolled gateway, and nothing else (no `sys-firewall`, unless you
    enrolled it); *Lead network* the same after its first entry, *not set*.
    Cancel. Then make `sys-ai-t4` stop qualifying, as a template change could:
    `qvm-features sys-ai-t4 qubes-firewall ''`, and Refresh. On the Gateways
    tab, expect its row's *Notes* to read `NOT USABLE: Qubes' qubes-firewall
    feature is not on for it (the qube's own value, else its template's)`, and
    the light `FAILED` (the Check tab's *gateway registry*). Back on the Qubes
    tab, *New project...*: type `t9` into *Label*, tick `none` under *Worker
    networks* and type `1G` into *Workers' disk quota*, so OK is on. `sys-ai-t4` is still
    listed, marked NOT USABLE; tick it, and OK greys out, saying
    `'sys-ai-t4' is enrolled but not usable:` and the same reason. Cancel.
    `qvm-features --unset sys-ai-t4 qubes-firewall`, Refresh: the mark is
    gone, and the light is `GREEN` again.
25. **The Whonix mark.** `qvm-prefs sys-ai-t4 netvm sys-whonix`, then Refresh,
    and the Gateways tab. Expect `sys-ai-t4`'s *Notes* to read
    `its own firewall rules have no effect upstream`. Select it: the same text
    in orange under its fields, and *Its upstream ignores its firewall rules*
    starting `yes: its own firewall rules have no effect upstream`. Press
    *Change...*: OK is greyed out, saying `nothing changed`. Set *Anonymising*
    to *yes*; the command ends `--anonymising yes`. OK. Expect its row's
    *Anonymising* `yes`. Then `qvm-prefs sys-ai-t4 netvm sys-firewall`,
    Refresh: the mark is gone. *Change...*, *Anonymising* *no*, OK.
26. **A project with a model.** *New project...*: label `t4`; the lead a fresh
    qube from `<template>`; *Lead network* `sys-ai-t4`; worker network `none`;
    quota `4G`. Expect OK greyed out, saying a lead with a network needs its
    model endpoint, and the line *The lead's network* saying the lead will be
    on `sys-ai-t4`. Type `<model>` into *Lead's model endpoint*: the command
    now holds `--lead-netvm sys-ai-t4 --model <model>`. OK. Expect project `t4`
    with its lead `ai-t4-lead`. Select `t4`. Expect *Lead's model endpoint*
    `<model>`; *Lead firewall you accepted* three lines: the endpoint
    (`action=accept dsthost=... proto=tcp dstports=...`, qubesd's own
    spelling), `action=accept specialtarget=dns`
    and `action=drop`; *Lead firewall* `read at` a time; *Rules it has now
    (live)* the same three lines; *Live rules are the ones you accepted* `yes`.
    *Set lead model...* and *Set lead rules...* are on, *Accept current
    rules...* greyed out. Select `ai-t4-lead` in the tree: the same lead
    firewall lines and buttons.
27. **Set the rules; the check stays green.** Select `t4`, *Set lead
    rules...*. Expect *Rules, one per line* to hold the three accepted rules,
    and under it three columns: *Accepted now*, *Live now*, *After OK*. On a
    new line above `action=drop` type
    `action=accept proto=tcp dsthost=example.com dstports=443`: *After OK*
    shows four lines. On a line of its own type `action=allow`: OK greys out,
    saying a rule's action is accept or drop. Delete that line. OK. Expect a
    report ending `ai-t4-lead's firewall set (4 rules)`; *Rules you accepted*
    and *Rules it has now (live)* four lines each, *Live rules are the ones you
    accepted* `yes`; the light still `GREEN`, and the Check tab's *lead
    firewalls* PASS.
28. **A lead with no rules accepted.** *New project...*: label `t5`, the lead
    a fresh qube from `<template>`, *Lead network* `none`, worker network
    `none`, quota `1G`. Type `<model>` into *Lead's model endpoint*: OK greys
    out, saying a lead with no network reaches no model endpoint. Empty the
    field, OK. Select `t5`: *Set lead model...* is greyed out, *Set lead
    rules...* is on, and the details say *Set lead model* `off: ai-t5-lead has
    no network, so it reaches no model endpoint; set its rules, or give the
    project a new lead on a network`. Then, in dom0, give that lead a network
    by hand, as an upgrade from 0.9.20 leaves a lead:
    `qvm-prefs ai-t5-lead netvm sys-ai-t4`. Refresh. The *Set lead model* line
    is gone, and the button is on.
    Expect the Check tab to hold a WARN *lead firewalls not accepted* naming
    `t5: ai-t5-lead`, and the light still `GREEN` (a warning is not a
    failure). Select `t5`: *Rules you accepted* `none on record`, *Rules it
    has now (live)* the qube's own rules (Qubes gives a new qube
    `action=accept`), *Accept current rules...* on. Press it: the form shows
    *Accepted now* `none on record` beside *Live now*, and the command
    `/usr/bin/sudo -n /usr/local/bin/qmcp project firewall t5 --accept-current`.
    OK. Expect *Live rules are the ones you accepted* `yes`, the WARN gone,
    and *Accept current rules...* greyed out. Then *Set lead model...*: OK is
    greyed out until you type `<model>`; *After OK* then shows the three
    endpoint rules. OK. Expect *Lead's model endpoint* `<model>`, and the live
    rules the three endpoint rules.
29. **The hub proposes a lead's firewall.** In the hub:

    ```sh
    printf '%s' '{"type": "project-firewall", "title": "example.net for t4",
      "project": "t4", "rules": ["action=accept proto=tcp dsthost=example.net dstports=443",
      "action=accept specialtarget=dns", "action=drop"]}' \
      | qrexec-client-vm dom0 qmcp.SubmitProposal
    ```

    Expect `"ok": true` and an id P. Refresh, select P on the Proposals tab.
    Expect: *Type* `project-firewall`; *Lead firewall rules* the three lines
    you sent; *Lead's model, now -> after* `<model> -> <model>`; *Lead
    firewall now, as you accepted it* and *Lead firewall now, live* the four
    rules of step 27; *Lead firewall after accepting* the three new ones; red
    text saying accepting it needs the second tick because it changes the lead
    firewall of t4 to 3 rules, to compare the old and new rules; the tick box
    empty and *Accept...* greyed out. Tick it, *Accept...*: the command ends in
    `--yes` and the *Second tick digest*. OK. Expect `proposal P: accepted`; on
    the Qubes tab, `t4`'s *Rules you accepted* and *Rules it has now (live)*
    the three new rules; the light `GREEN`.
30. **Clean up.** On the Gateways tab select `sys-ai-t4`, *Remove...*: expect
    OK greyed out, the form saying `'sys-ai-t4' is in use` by `ai-t4-lead` and
    `ai-t5-lead`, and no red line (it removes no qube). Cancel. Delete `t4`
    and `t5` (*Delete project...*, OK, each). Select `sys-ai-t4` again,
    *Remove...*, OK: expect `sys-ai-t4: no longer enrolled`. Then
    `qvm-remove -f sys-ai-t4` (`qvm-shutdown --wait sys-ai-t4` first if it
    runs), and `qvm-remove -f t1-dump ai-t1h`, the two
    qubes steps 1 to 17 leave behind; skip what a step you did not run never
    made. Expect: `qmcp check` GREEN. The decided proposals stay in the list:
    nothing removes them.
