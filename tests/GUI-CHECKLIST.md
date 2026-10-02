# The window, by hand

A click-through of `qmcp-gui` for a person, after any install that changes the
window. `tests/test_gui.py` proves the window's logic offline, against the real
command; this list proves it on a real box, with real hands.

Run it in dom0, as your own user. You need a TemplateVM in AI space
(`<template>` below) and a gateway in AI space (`<gateway>`), and `qmcp check`
GREEN. The names `t1`, `ai-t1h`, `ai-t1-lead`, `ai-t1-boss` and `t1-dump` must
not exist yet. Answer by step number: "pass", or what you saw instead.

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
13. **Verify and rotate.** *Verify the chain*: "chain OK". *Rotate...*, OK;
    verify again: "chain OK". Expect the list to hold one line, the rotation,
    and the pane under it to name the file the earlier lines moved to. The log
    holds the calls the hub and the leads make to state-changing services, and
    that rotation line; your other commands are not on it.
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
18. **Clean up.** `qvm-remove -f t1-dump ai-t1h`. Expect: `qmcp check` GREEN.
