# The window, by hand

A click-through of `qmcp-gui` for a person, after any install that changes the
window. `tests/test_gui.py` proves the window's logic offline, against the real
command; this list proves it on a real box, with real hands.

Run it in dom0, as your own user. You need a TemplateVM in AI space
(`<template>` below) and a gateway in AI space (`<gateway>`), and `qmcp check`
GREEN. The names `t1`, `ai-t1h`, `ai-t1-lead`, `ai-t1-boss` and `t1-dump` must
not exist yet. Answer by step number: "pass", or what you saw instead.

Steps 18 to 21 play the hub's part as well, so they also need a terminal in
the hub (the qube the Settings tab names under *Hub (fixed at install)*), from
which they send the requests an agent would. The names `t2`, `t3` and
`ai-t2-lead` must not exist yet. The projects' quotas (*Disk quota* in each
project's details) plus 4 GiB must stay within *Pool cap (all of AI space)* on
the Settings tab: past it, the proposal in step 18 asks for a second tick that
the step does not expect.

Every form shows, under its fields, the exact command OK will run. Check it
against the step each time; it is the window's promise that what you see is
what runs.

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
    the disk AI space uses, and the version, with no way to edit them.
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
23. **Clean up.** `qvm-remove -f t1-dump ai-t1h`, the two qubes steps 1 to 17
    leave behind; skip it if you ran only steps 18 to 22. Expect: `qmcp check` GREEN.
    The decided proposals stay in the list: nothing removes them.
