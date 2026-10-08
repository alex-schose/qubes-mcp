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

Steps 31 to 37 cover self-hosted model qubes. Start them with `qmcp check`
GREEN. Besides `<template>`, `<gateway>` and `<model>` as above, they need a
TemplateVM outside AI space for the model qube, `<model-template>` (such as
your default template): `qmcp` refuses a model qube whose template the hub
manages, and `<template>` is usually one. Step 34 needs the hub's terminal, as
steps 18 to 21 do. The names `ai-hub-llm`, `t6`, `t7`, `t8`, `ai-t6-lead`,
`ai-t7-lead` and `ai-t8-lead` must not exist yet, and three slots must be
free; their quotas are 1 GiB each, which must fit under *Pool cap (all of AI
space)* with the others. Each project's slot is shown in the tree beside its
label (`p03 t6`); below, `pT6`, `pT7` and `pT8` stand for the slots of `t6`,
`t7` and `t8`. A model qube serves projects; the window lists it once, under
*Model qubes*, and each project it serves points to it.

31. **A qube to serve a model.** Make the qube the hub would have set up, in
    p00 and on a network:
    `qvm-create --class AppVM --template <model-template> --label gray ai-hub-llm`,
    then `qvm-prefs ai-hub-llm netvm <gateway>`. Press Refresh, *Add a qube to
    AI space...*, choose `ai-hub-llm`, tick *managed*, OK; then select it,
    *Move...*, choose p00, OK. Expect `ai-hub-llm` under p00, *Role*
    `hub's qube`, *Network* `<gateway>`.
32. **A project whose model is a qube.** *New project...*: *Label* `t6`; *The
    lead is* a fresh qube from a template, *Made from* `<template>`; under
    *Worker networks* tick `none`; *Workers' disk quota* `1G`. Under *The lead's
    model*, choose *a self-hosted model qube: the lead then has no network*.
    Expect *Lead network* to change to `none` and grey out, and *Lead's model
    endpoint* to grey out; OK greyed out, saying
    `choose the model qube, or a remote endpoint`; and *The lead's network*
    reading `The lead will have no network: a lead whose model is a qube has
    none. Choose its model qube.` Open *Model qube*: it lists the qubes `qmcp`
    would take as a model qube, each saying where it is, and only qubes in AI
    space (one of yours outside it would have to be guarded first). Expect
    `ai-hub-llm (managed; in p00; on <gateway>)`. Choose it. Expect: *The
    model qube* reading
    `ai-hub-llm leaves p00, loses its network (<gateway>), is guarded (the hub
    can no longer operate it) and is killed if it runs; then it is recorded and
    wears the project's model badge, and the lead reaches it on port 11434.`; *The
    lead's network* reading `... It reaches ai-hub-llm on port 11434, and needs
    no firewall.`; no red line (the lead is new, and the qube serves no other
    project); and the command `/usr/bin/sudo -n /usr/local/bin/qmcp project
    create t6 --lead-template <template> --lead-netvm none --model-qube
    ai-hub-llm --network none --quota 1G`. Choose *a remote endpoint* once:
    *Lead network* comes back on, at its first entry, *not set*; then choose
    the model qube again. OK. Expect a report ending
    `pT6: model qube ai-hub-llm; the lead reaches it on port 11434`, after
    `ai-hub-llm is out of p00`, `ai-hub-llm lost its network (<gateway>)` and
    `ai-hub-llm is guarded`. In the tree: the project `t6` with its lead
    `ai-t6-lead`, and under it a row `ai-hub-llm` whose *Role* reads
    `model qube (see Model qubes)`; a group *Model qubes* holding `ai-hub-llm`,
    *Role* `model qube of pT6`. Select that row. Expect *Serves*
    `pT6 t6: its lead reaches it over qubes.ConnectTCP on port 11434`,
    *Maintenance* starting `guarded: the hub cannot operate it`, *Network*
    `-`; *Manage...* and *Revoke...* on, *Move...* and *Guard...* greyed
    out. The light stays `GREEN`; the Check tab's *model qubes* PASS. In a
    dom0 terminal, `qvm-prefs ai-t6-lead netvm` prints nothing: the lead has
    no network.
33. **A lead with a network gets a shared model qube.** First a project like
    step 26's: *New project...*, *Label* `t7`, the lead a fresh qube from
    `<template>`, *Lead network* `<gateway>`, *The lead's model* left at *a
    remote endpoint*, *Lead's model endpoint* `<model>`, worker network
    `none`, quota `1G`, OK. Select `t7`, press *Set model qube...*. Expect the
    form to say what OK does, in order, ending `The project's model now: the
    endpoint <model>.`; *Model qube* with nothing chosen and OK greyed out,
    saying `choose the model qube, or none`; and no `none` among the choices,
    since `t7` has no model qube to take away. Choose
    `ai-hub-llm (guarded; serves pT6)`. Expect two red paragraphs:
    `ai-t7-lead loses its network (<gateway>): a lead whose model is a qube has
    none, and going back to a remote model takes a new lead.`, and
    `WARNING: ai-hub-llm also serves pT6: a model qube that serves several
    projects is a path between them: Ollama's API has no login ...`, ending
    `... It is safe only behind an API filter that lets inference calls through
    and nothing else; qmcp ships none`. *What OK does* reads `ai-hub-llm is
    recorded and wears qmcp-model-pT7, and the lead reaches it on port 11434.`,
    and the command `/usr/bin/sudo -n /usr/local/bin/qmcp project firewall t7
    --model-qube ai-hub-llm`. OK. Expect a report holding
    `pT7: ai-t7-lead lost its network (<gateway>): a lead whose model is a
    qube has none` and the same WARNING line. Select `ai-hub-llm`: *Role*
    `model qube of pT6 and pT7, shared`, and a *Shared* line holding the
    warning word for word. Select `t7`: *Lead's model endpoint* `-`, *Lead's
    model qube* `ai-hub-llm`, *Its model qube is shared* `ai-hub-llm also serves
    pT6: ...`, and *Set lead model* `off: the model of t7 is the qube
    ai-hub-llm, and its lead has no network: a remote model takes a new lead on
    a network (qmcp project lead t7 ... --lead-netvm NET --model HOST:PORT)`,
    and *Lead rules* `Set lead rules and Accept current rules are off: the
    model of t7 is the qube ai-hub-llm, and its lead has no network, so it has
    no firewall to set or accept`; *Set lead model...*, *Set lead rules...*
    and *Accept current rules...* greyed out, *Set model qube...* on. The
    light stays `GREEN`.
34. **The hub proposes a project with a model qube.** In the hub:

    ```sh
    printf '%s' '{"type": "project-create", "title": "a sealed project",
      "label": "t8", "lead": {"from": "template", "qube": "<template>"},
      "networks": ["none"], "quota": 1073741824, "model_qube": "ai-hub-llm"}' \
      | qrexec-client-vm dom0 qmcp.SubmitProposal
    ```

    Expect `"ok": true` and an id M. Refresh, select M on the Proposals tab.
    Expect *Lead's model qube* `ai-hub-llm`; *Equivalent command* `qmcp project
    create t8 --lead-template <template> --network none --quota 1G
    --model-qube ai-hub-llm`; and red text saying accepting it needs the
    second tick, for two reasons: `- makes ai-hub-llm the model qube of t8:
    dom0 takes it out of p00, removes its network, guards it and kills it if it
    runs (unless it is already a guarded model qube), and the lead has no
    network`, and `- ai-hub-llm already serves pT6, pT7:` followed by
    the same warning as in step 33. The tick box is empty and *Accept...*
    greyed out. Tick it, *Accept...*: the command ends in `--yes` and the
    *Second tick digest*, and the form repeats the red text. OK. Expect a
    report ending `proposal M: accepted`, after `pT8: model qube ai-hub-llm;
    the lead reaches it on port 11434` and a WARNING line naming pT6 and pT7.
    On the Qubes tab, `t8` with its lead `ai-t8-lead`, and `ai-hub-llm`
    reading `model qube of pT6, pT7 and pT8, shared`.
35. **A model qube given a network outside qmcp.** In dom0:
    `qvm-prefs ai-hub-llm netvm <gateway>`, then Refresh. Expect the light
    `FAILED`, and the Check tab's *model qubes* FAIL
    `ai-hub-llm has a network (<gateway>): its leads reach that network
    through it`. In the tree, *Model qubes* is gone and `ai-hub-llm` is under
    *Needs attention*, *Role* `needs attention: model qube with a network`;
    selected, its *Why* reads `a model qube with a network: the leads it
    serves reach that network through it, around the firewalls you accepted
    for them`, and only *New project...* and *Add a qube to AI space...* are
    on. Each of `t6`, `t7` and `t8` points to it with
    `model qube (see Needs attention)`. Then `qvm-prefs ai-hub-llm netvm ''`
    and Refresh: the light `GREEN` again, and `ai-hub-llm` back under *Model
    qubes*. Now its lead: `qvm-prefs ai-t6-lead netvm <gateway>`, Refresh.
    Expect the light `FAILED`, the Check tab's *model-qube leads* FAIL
    `t6: ai-t6-lead is on <gateway>, though its model is the qube ai-hub-llm:
    clear its network (qvm-prefs LEAD netvm ''), or give the project a remote
    model with a new lead`, and `ai-t6-lead` under *Needs attention*, *Role*
    `needs attention: lead with a network, model a qube`, while `t6` shows
    `lead (see Needs attention)`. Select `t6`, *Set model qube...*, choose
    `ai-hub-llm (guarded; pT6's model qube now; serves pT7, pT8)`. Expect a
    red line `ai-t6-lead loses its network (<gateway>): a lead whose model is
    a qube has none, ...`, followed by the WARNING paragraph (it serves pT7
    and pT8 too). OK. Expect a report holding `ai-t6-lead lost its network
    (<gateway>)`, `ai-t6-lead` back under `t6`, and the light `GREEN`.
36. **Its maintenance window.** Select `ai-hub-llm`, *Manage...*. The form
    reads `ai-hub-llm becomes managed: the hub may run commands in it as root
    and change it. It stays the model qube of pT6, pT7 and pT8, and their leads
    still reach it on port 11434: this opens its maintenance window, and qmcp
    check warns until you guard it again.` OK. Expect a report
    `ai-hub-llm: managed; it is still the model qube of pT6, pT7, pT8: while it
    is managed the hub may operate it (qmcp guard ai-hub-llm when its changes
    are done, which kills it if it runs)`; its *Role* `model qube of pT6, pT7
    and pT8, shared, not guarded`, still under *Model qubes*; *Maintenance* starting
    `not guarded: the hub may operate it`; *Guard...* and *Revoke...* on,
    *Manage...* greyed out; the Check tab's *model qubes* WARN
    `ai-hub-llm is not guarded: ...`, and the light still `GREEN` (a warning
    is not a failure). Press *Revoke...* and read it: the form adds `It is the
    model qube of pT6, pT7 and pT8: revoking takes its model badges too, ...`;
    Cancel. Press *Guard...*: the form reads `ai-hub-llm becomes guarded: it
    is listed and referenced, never operated. It stays the model qube of pT6,
    pT7 and pT8; its maintenance window closes: if it runs, it is killed, so no
    process the hub started in it runs on. Its files stay: what the hub left in
    /home, /usr/local or /rw (anywhere, in a StandaloneVM), and whatever is set
    to start from there runs at its next start.` OK. Expect a report
    `ai-hub-llm: guarded`; if it was running, followed by `; killed, so no
    process the hub started in it while it was managed runs on (...)`, and
    `qvm-ls ai-hub-llm` in a dom0 terminal shows it Halted. Expect the *Role*
    without `not guarded`, and the WARN gone.
37. **Take it away, and clean up.** Select `t7`, *Set model qube...*. Expect
    `ai-hub-llm (guarded; pT7's model qube now; serves pT6, pT8)` among the
    choices, and last `none: take ai-hub-llm away; the lead reaches no model`.
    Choose that: no red line, *What OK does* `ai-hub-llm loses qmcp-model-pT7
    and stops serving the project; it stays as it is otherwise. The lead
    reaches no model.`, and the command ending `project firewall t7
    --model-qube none`. OK. Expect a report `pT7: ai-hub-llm is no longer its
    model qube` and `pT7: the record names no model qube`; `t7` no longer
    points to it. Delete `t6` (*Delete project...*): the plan before OK ends
    `its model qube ai-hub-llm is kept and loses pT6's badge.`; OK. Delete `t8`
    and `t7` the same way. Expect `ai-hub-llm` under *Other guarded*, *Role*
    `guarded`. *Revoke...* it, OK; then `qvm-remove -f ai-hub-llm`
    (`qvm-shutdown --wait ai-hub-llm` first if it runs). Expect: `qmcp check`
    GREEN.

Steps 38 to 46 cover anonymous projects. Start them with `qmcp check` GREEN,
and `systemctl is-active qmcp-gate.timer` printing `active` in a dom0
terminal (the check fails while an anonymous project exists and the timer
does not run). Besides `<template>`, `<gateway>`, `<router-template>` and
`<model>` as above, they need Whonix's `sys-whonix`, whose `qvm-tags
sys-whonix` lists `anon-gateway`, and a TemplateVM outside AI space for the
lead, `<anon-template>` (such as your default template): an anonymous
project's templates must be ones the hub cannot change, and `<template>` is
usually one it manages. dom0's update policy must send `<anon-template>`'s
updates to `sys-whonix` (Qubes Global Config, *Updates*): the gate judges a
template whose updates go anywhere else unsound, and step 40's *Anonymity gate*
line then says so. The name `sys-ai-tor` must not exist yet, and one slot must
be free, with 1 GiB of room under *Pool cap (all of AI space)*. The label of
the project step 40 makes is picked by dom0; below, `<label>` stands for it
and `pA` for its slot, both shown in the tree (`pA <label>: t9 checklist`).

38. **Enroll an anonymising router.** Make it, behind Whonix:
    `qvm-create --class AppVM --template <router-template> --label purple sys-ai-tor`,
    then `qvm-prefs sys-ai-tor provides_network True` and
    `qvm-prefs sys-ai-tor netvm sys-whonix`. Press Refresh. On the Gateways tab,
    *Enroll...*, choose `sys-ai-tor`. Expect *Its upstream* `sys-ai-tor is on
    sys-whonix now`. Tick *Anonymising*: the line adds `; ticked, that is
    recorded as its upstream`, and the command reads
    `/usr/bin/sudo -n /usr/local/bin/qmcp gateway enroll sys-ai-tor --anonymising`.
    OK. Expect a report ending `sys-ai-tor: enrolled (anonymising, on
    sys-whonix)`. Select `sys-ai-tor`: *Upstream recorded when marked
    anonymising* `sys-whonix, where it is now`, and *Notes* `its own firewall
    rules have no effect upstream`.
39. **The Anonymity tab, empty.** Open the Anonymity tab. Expect its label
    `Anonymity (0)`, an empty list, and the line above it ending `No anonymous
    project: the gate has nothing to judge. New project... makes one with
    Anonymous ticked.`
40. **A hidden project.** On the Qubes tab, *New project...*. Type `t9` into
    *Label*. Expect *The hub may see it* and *Note (dom0 only)* greyed out.
    Tick *Anonymous*: *Label* empties, greys out and reads `picked by dom0 at
    random`; *The hub may see it* and *Note (dom0 only)* come on; under *The
    lead is*, only *a fresh qube from a template* is on, and chosen; *Lead
    name* is greyed out, reading `named by dom0`, with `ai-<picked by dom0>-`
    in front (those words: dom0 picks the label when OK runs). Expect one red paragraph,
    `WARNING: a hidden project is safe from the hub only if the hub never
    operated what it runs on: a template or model qube the hub edited before
    it was guarded can harm it, since guarding removes nothing the hub left
    there, and qmcp keeps no record of who operated a qube`. Untick
    *Anonymous*: `t9` is back in *Label* and the red paragraph is gone; tick
    it again. Choose *Made from* `<template>`, tick `none` under *Worker
    networks*, type `1G` into *Workers' disk quota*: OK greys out, saying
    `the lead's template '<template>' is managed, so the hub can change it:
    guard it first (qmcp guard <template>), or use another`. Choose *Made from*
    `<anon-template>`: OK comes on. Tick `<gateway>` (an enrolled gateway not
    marked anonymising) under *Worker networks*: OK greys out, saying `'<gateway>' is not an anonymising gateway: an
    anonymous project's networks are anonymising gateways, or none`. Untick
    it and `none`; tick `sys-ai-tor`, listed as `sys-ai-tor (anonymising; its
    own firewall rules have no effect upstream)`. Choose *Lead network*
    `sys-ai-tor`, type `<model>` into *Lead's model endpoint* and
    `t9 checklist` into *Note (dom0 only)*. Expect the command
    `/usr/bin/sudo -n /usr/local/bin/qmcp project create --anonymous --note
    't9 checklist' --lead-template <anon-template> --lead-netvm sys-ai-tor
    --model <model> --network sys-ai-tor --quota 1G`, and still the one red
    paragraph. OK. Expect a report holding `pA: project '<label>' recorded;
    workers are named ai-<label>-*; anonymous, hidden from the hub` and
    `pA: WARNING: a hidden project is safe ...`. In the tree, `pA <label>: t9
    checklist`, *Role* `anonymous project, hidden from the hub`, and under it
    `ai-<label>-lead`, *Role* `lead, anonymous, hidden from the hub`. Select
    the project: *Anonymous* `yes`, *Hidden from the hub* `yes`, *Note (dom0
    only)* `t9 checklist`, *Stopped by the anonymity gate* `no`, *Anonymity
    gate* `green: sound`. On the Anonymity tab, one row: `<label>`,
    `t9 checklist`, `pA`, `hidden`, `green: sound`, *Stopped* `no`, *Failing
    conditions* `-`; the label still `Anonymity (0)`. The light stays `GREEN`.
41. **A shared router, in red.** On the Qubes tab, *New project...*, tick
    *Anonymous*, choose *Made from* `<anon-template>`, tick `sys-ai-tor` under
    *Worker networks*. Expect a second red paragraph under the first:
    `WARNING: it shares sys-ai-tor with another project or the hub: projects
    behind one anonymising router share its exit, so a destination can tie
    them together; a second router of the kind keeps them apart`. Tick *The
    hub may see it*: both red paragraphs go (they are about a hidden
    project). Cancel.
42. **The gate stops it.** Move the router to clearnet, as a mistake outside
    qmcp would: `qvm-prefs sys-ai-tor netvm sys-firewall`. Press Refresh.
    Expect a desktop notification `qubes-mcp stopped the anonymous project
    <label> (pA): its networks.` On the Anonymity tab: its label
    `Anonymity (1)`; the row's *Gate* `RED: not anonymous`, *Stopped* `yes`,
    *Failing conditions* `its networks`. Select it: red text starting
    `RED: not anonymous: its networks (networks: sys-ai-tor is on
    sys-firewall, not on sys-whonix as recorded`. *What this run did* holds
    `ai-<label>-lead: blocked` (and `ai-<label>-lead: killed`, if it was
    running) when this refresh's gate run stopped it; when the timer's run,
    every 15 seconds, got there first, it reads `nothing`, *Stopped, after this
    run* still reads `yes`, and the notification came from the timer. On the Qubes tab, the project's *Role* `anonymous project,
    hidden from the hub, BLOCKED by the gate, gate RED: its networks`, and the
    lead's `lead, anonymous, hidden from the hub, BLOCKED by the gate`,
    followed by `, stopped by the gate`; selected, the lead's
    details say *BLOCKED by the gate* `wears qmcp-blocked: ...` (and *Stopped by
    the gate* `wears qmcp-stopped: ...`). On the Gateways tab, `sys-ai-tor`'s *Notes* start
    `MOVED: it is on sys-firewall, not on sys-whonix as recorded: the gate
    stops every anonymous project on it.` The light is `FAILED`, and the Check
    tab's *anonymity gate* FAIL reads `<label> (pA) is not anonymous (...); it
    was stopped`. In a dom0 terminal, `qvm-tags ai-<label>-lead` lists
    `qmcp-blocked`, and `qvm-prefs ai-<label>-lead autostart` prints `False`.
43. **Unblock refuses while it is unsound.** Select the project on the Qubes
    tab: *Unblock...* is on. Press it. Expect OK greyed out, saying `the gate
    still finds <label> unsound, so it stays blocked: sys-ai-tor is on
    sys-firewall, not on sys-whonix as recorded` and the rest of the reasons.
    Cancel. The same from its row on the Anonymity tab.
44. **Put back, then unblock.** `qvm-prefs sys-ai-tor netvm sys-whonix`, and
    Refresh. On the Anonymity tab, the row's *Gate* `green: sound`, *Stopped*
    still `yes`, the label still `Anonymity (1)`; the Check tab's *anonymity
    gate* WARN `<label> (pA) was stopped and is sound again: clear it with sudo
    qmcp project unblock <label>`, and the light `GREEN` (a warning is not a
    failure). Select the row, *Unblock...*. Expect the form to say the gate
    judges it again first and that autostart stays off, and the command
    `/usr/bin/sudo -n /usr/local/bin/qmcp project unblock <label>`. OK. Expect a
    report `pA: ai-<label>-lead unblocked (autostart stays off)`; the row's
    *Stopped* `no`, the label `Anonymity (0)`, and `BLOCKED by the gate` gone
    from the Qubes tab. `qvm-prefs ai-<label>-lead autostart` still prints
    `False`.
45. **Its other forms.** Select the project, *Change lead...*. Expect *a clone
    of one of the hub's AppVMs* and *one of the hub's AppVMs, promoted in
    place* greyed out, *Lead name* greyed out reading `named by dom0`, with
    `ai-<label>-` in front, and the form's text saying dom0 names the new lead.
    Cancel.
    *Set model qube...*: expect the red paragraph `WARNING: a hidden project
    is safe from the hub only if ...` before anything is chosen. Cancel. On
    the Gateways tab, select `sys-ai-tor`, *Change...*. Expect a tick *record
    its network again: it is on sys-whonix now, and sys-whonix is recorded*.
    Set *Anonymising* to *no*: the tick greys out, and OK greys out, saying
    `'sys-ai-tor' carries the anonymous project(s) <label>; they would be
    stopped. Delete them, or give them other networks, first`. Cancel.
46. **Clean up.** Select the project, *Delete project...*, OK. On the Gateways
    tab select `sys-ai-tor`, *Remove...*, OK: expect `sys-ai-tor: no longer
    enrolled`. Then `qvm-remove -f sys-ai-tor` (`qvm-shutdown --wait
    sys-ai-tor` first if it runs). Expect the Anonymity tab `Anonymity (0)`
    with `No anonymous project`, and `qmcp check` GREEN.
