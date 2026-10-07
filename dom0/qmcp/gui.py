"""qmcp.gui — the operator's window in dom0, started as `qmcp-gui`.

It runs the `qmcp` command and nothing else (see `qmcp.guimodel`): every read
as the operator's own dom0 user, every change under `sudo -n`, shown first in
the form that makes it and again in the report after it. It never runs as
root. A proposal from the hub is read with `qmcp proposal show` when it is
selected, and accepted with the fingerprint that show gave; a project's lead
firewall is read with `qmcp project firewall NAME --json` when the project or
its lead is selected, and the forms that change it show its rules now and
after, side by side. A lead's model is a remote endpoint or a self-hosted
model qube; a form that takes a lead's network away for one says so in red
before OK, and so does one that shares a model qube between projects.

Every text a widget shows is set by one of the helpers between the two rules
below, and they accept only `guimodel.Shown`, which only `esc()`,
`esc_lines()` and `esc_items()` make (`audit_detail()` joins their output).
`tests/test_gui.py` fails if any other line sets widget text from a value, or
if a markup API appears anywhere in this file.
"""
from __future__ import annotations

import os
import shlex
import sys
import time

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango  # noqa: E402

from qmcp import guimodel as gm  # noqa: E402
from qmcp.guimodel import esc, esc_lines  # noqa: E402

CSS = b"""
.qmcp-light { font-weight: bold; }
.qmcp-GREEN { color: #2e7d32; }
.qmcp-FAILED { color: #c62828; }
.qmcp-INCOMPLETE { color: #ef6c00; }
.qmcp-UNKNOWN { color: #757575; }
.qmcp-note { color: #ef6c00; }
"""
LIGHTS = ("GREEN", "FAILED", "INCOMPLETE", "UNKNOWN")
#: A form's heading over the command OK runs, and over why OK is off.
RUNS, OK_OFF = "Runs:", "OK is off:"


# ======================================================================= text helpers
# The only functions that put text on a widget. Each refuses anything that
# has not been through esc() or esc_lines().

def _need(text) -> gm.Shown:
    if not isinstance(text, gm.Shown):
        raise TypeError("widget text must come from esc() or esc_lines()")
    return text


def _label(text, *, wrap=False, selectable=False, xalign=0.0) -> Gtk.Label:
    label = Gtk.Label(label=_need(text), xalign=xalign)
    if wrap:
        label.set_line_wrap(True)
        label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    label.set_selectable(selectable)
    return label


def _set(widget, text) -> None:
    """A label's or an entry's text."""
    widget.set_text(_need(text))


def _set_lines(view, text) -> None:
    view.get_buffer().set_text(_need(text))


def _title(window, text) -> None:
    window.set_title(_need(text))


def _named(widget, text) -> None:
    """The name assistive technology reads."""
    widget.get_accessible().set_name(_need(text))


def _button(text, on_click=None) -> Gtk.Button:
    button = Gtk.Button(label=_need(text))
    if on_click is not None:
        button.connect("clicked", on_click)
    return button


def _add_button(dialog, text, response) -> Gtk.Widget:
    """A dialog button without a mnemonic: `Gtk.Dialog.add_button` turns
    use-underline on, which would eat the underscore in a name."""
    button = Gtk.Button(label=_need(text))
    dialog.add_action_widget(button, response)
    return button


def _placeholder(entry, text) -> None:
    entry.set_placeholder_text(_need(text))


def _check(text) -> Gtk.CheckButton:
    return Gtk.CheckButton(label=_need(text))


def _radio(group, text) -> Gtk.RadioButton:
    return Gtk.RadioButton.new_with_label_from_widget(group, _need(text))


def _fill(combo, choices) -> None:
    """(id, text) pairs into a ComboBoxText; the id is what the command gets."""
    combo.remove_all()
    for ident, text in choices:
        combo.append(ident, _need(text))


def _column(view, heading, index, *, expand=False, wrap=0, clip=False) -> None:
    """A text column at its natural width. Only the one long column of a list
    expands, and wraps or clips: a clipped short column hides the very word
    (a role, a check, a service) the list is read for."""
    cell = Gtk.CellRendererText()
    if wrap:
        cell.set_property("wrap-width", wrap)
        cell.set_property("wrap-mode", Pango.WrapMode.WORD_CHAR)
    elif clip:
        cell.set_property("ellipsize", Pango.EllipsizeMode.END)
    column = Gtk.TreeViewColumn(title=_need(heading), cell_renderer=cell, text=index)
    column.set_resizable(True)
    column.set_expand(expand)
    view.append_column(column)


def _tree_append(store, parent, key, cells):
    for cell in cells:
        _need(cell)
    return store.append(parent, [key, *cells])


def _list_append(store, key, cells):
    for cell in cells:
        _need(cell)
    return store.append([key, *cells])

# ======================================================================= end of text helpers


def _clear(container) -> None:
    for child in container.get_children():
        container.remove(child)
        child.destroy()


def _scrolled(child, min_height=0) -> Gtk.ScrolledWindow:
    sw = Gtk.ScrolledWindow()
    sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    if min_height:
        sw.set_min_content_height(min_height)
    sw.add(child)
    return sw


def _screen_room(widget, reserve: int) -> int:
    """The height a scrolled part may take on the monitor `widget` is on (the
    first one before it is shown), less `reserve` for what stays outside it:
    title bar, buttons, the command line. Never less than 160."""
    display = Gdk.Display.get_default()
    monitor = None
    if display is not None:
        window = widget.get_window() if widget is not None else None
        monitor = display.get_monitor_at_window(window) if window is not None else None
        if monitor is None:
            monitor = display.get_primary_monitor() or (
                display.get_monitor(0) if display.get_n_monitors() else None)
    height = monitor.get_workarea().height if monitor is not None else 768
    return max(160, height - reserve)


def _bounded(child, max_height: int) -> Gtk.ScrolledWindow:
    """`child` at its natural height up to `max_height`, scrolled beyond it:
    a long text never pushes what follows it off the screen."""
    sw = Gtk.ScrolledWindow()
    sw.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    sw.set_propagate_natural_height(True)
    sw.set_max_content_height(max_height)
    sw.add(child)
    return sw


def _text_view() -> Gtk.TextView:
    view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
    view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    return view


#: A read that takes longer is killed and reported; changes have no limit,
#: since a create may legitimately take minutes.
READ_TIMEOUT_S = 120


class Runner:
    """Runs one command without blocking the window, then calls `done(Result)`.
    stdin is /dev/null, so `sudo -n` can only refuse, never prompt."""

    def run(self, argv, done, timeout=None) -> None:
        argv = list(argv)
        try:
            proc = Gio.Subprocess.new(argv, Gio.SubprocessFlags.STDOUT_PIPE
                                      | Gio.SubprocessFlags.STDERR_PIPE)
        except GLib.Error as e:
            message = e.message

            def failed():
                done(gm.Result(argv, 127, "", f"cannot start: {message}"))
                return False
            GLib.idle_add(failed)
            return

        expired = []

        def expire():
            expired.append(True)
            proc.force_exit()
            return False
        timer = GLib.timeout_add_seconds(timeout, expire) if timeout else None

        def finished(p, res):
            if timer is not None and not expired:
                GLib.source_remove(timer)
            try:
                _, out, err = p.communicate_finish(res)
                rc = p.get_exit_status() if p.get_if_exited() else 128 + p.get_term_sig()
            except GLib.Error as e:
                done(gm.Result(argv, 1, "", f"failed: {e.message}"))
                return

            def text(buf):
                return "" if buf is None else bytes(buf.get_data()).decode("utf-8", "replace")
            err_text = text(err) + (f"\ntimed out after {timeout} s" if expired else "")
            done(gm.Result(argv, rc, text(out), err_text))
        proc.communicate_async(None, None, finished)


# ======================================================================= forms

class Form(Gtk.Dialog):
    """One command, built by a guimodel builder from the fields, and shown
    under them before anything runs. OK stays off while the builder refuses."""

    def __init__(self, parent, title, ok_label, intro=None):
        super().__init__(transient_for=parent, modal=True, destroy_with_parent=True)
        self._ready = False          # signals fire while the fields are being built
        _title(self, esc(title))
        self.set_default_size(620, -1)
        _add_button(self, esc("Cancel"), Gtk.ResponseType.CANCEL)
        self.ok = _add_button(self, esc(ok_label), Gtk.ResponseType.OK)
        box = self.get_content_area()
        box.set_spacing(8)
        for side in ("start", "end", "top", "bottom"):
            getattr(box, f"set_margin_{side}")(12)
        # The intro, the fields and the red text scroll, within the screen; the
        # command line and the buttons below them stay in view, whatever the
        # length of the text (a shared model qube's warning is long).
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.body = _bounded(body, _screen_room(parent, 260))
        box.pack_start(self.body, True, True, 0)
        self.intro = None
        if intro is not None:
            self.intro = _label(intro if isinstance(intro, gm.Shown) else esc(intro),
                                wrap=True, selectable=True)
            body.pack_start(self.intro, False, False, 0)
        self.grid = Gtk.Grid(column_spacing=12, row_spacing=6)
        body.pack_start(self.grid, False, False, 0)
        self.rows = 0
        # What OK destroys, in red, before it runs.
        self.warning = _label(esc(""), wrap=True)
        self.warning.get_style_context().add_class("qmcp-FAILED")
        _named(self.warning, esc("warning"))
        body.pack_start(self.warning, False, False, 0)
        # One line under one heading: the command OK runs, or why OK is off, in
        # orange, so a reason is never taken for the command. show_all() leaves
        # the two alone; _line() shows one.
        self.runs = _label(esc(RUNS))
        box.pack_start(self.runs, False, False, 0)
        self.preview = _label(esc(""), wrap=True, selectable=True)
        _named(self.preview, esc("command preview"))
        box.pack_start(self.preview, False, False, 0)
        self.error = _label(esc(""), wrap=True)
        self.error.get_style_context().add_class("qmcp-note")
        _named(self.error, esc("form problem"))
        box.pack_start(self.error, False, False, 0)
        for line in (self.preview, self.error):
            line.set_no_show_all(True)

    def row(self, heading, widget):
        self.grid.attach(_label(esc(heading)), 0, self.rows, 1, 1)
        self.grid.attach(widget, 1, self.rows, 1, 1)
        widget.set_hexpand(True)
        self.rows += 1
        if not isinstance(widget, (Gtk.Box, Gtk.Grid)):
            _named(widget, esc(heading))
        return widget

    def entry(self, heading, placeholder=None, text=None) -> Gtk.Entry:
        e = Gtk.Entry()
        if placeholder is not None:
            _placeholder(e, esc(placeholder))
        if text is not None:
            _set(e, esc(text))
        e.connect("changed", self.update)
        return self.row(heading, e)

    def combo(self, heading, choices, active=None, preselect=True) -> Gtk.ComboBoxText:
        c = Gtk.ComboBoxText()
        _fill(c, choices)
        if active is not None:
            c.set_active_id(active)
        elif choices and preselect:
            c.set_active(0)
        c.connect("changed", self.update)
        return self.row(heading, c)

    def wide(self, widget):
        """A widget across both columns, under the fields so far."""
        self.grid.attach(widget, 0, self.rows, 2, 1)
        widget.set_hexpand(True)
        self.rows += 1
        return widget

    def checks(self, heading, names, ticked=(), texts=None) -> dict:
        """A tick box per name; `texts` may say more beside a name."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        out = {}
        for name in names:
            cb = _check(esc((texts or {}).get(name, name)))
            cb.set_active(name in ticked)
            cb.connect("toggled", self.update)
            box.pack_start(cb, False, False, 0)
            out[name] = cb
        if not names:
            box.pack_start(_label(esc("(none in AI space)")), False, False, 0)
        self.row(heading, box)
        return out

    def _line(self, command=None, why=None) -> None:
        """Under the heading, the command (a shown argv), or why OK is off."""
        _set(self.runs, esc(RUNS if why is None else OK_OFF))
        _set(self.preview, command if why is None else esc(""))
        _set(self.error, esc("" if why is None else why))
        self.preview.set_visible(why is None)
        self.error.set_visible(why is not None)

    def refuse(self, why) -> None:
        self._line(why=why)
        self.ok.set_sensitive(False)

    def build(self) -> list:
        raise NotImplementedError

    def argv(self) -> list:
        return self.build()

    def done_building(self):
        self._ready = True
        self.update()

    def update(self, *_):
        if not self._ready:
            return
        try:
            argv = self.build()
        except gm.FormError as e:
            self.refuse(str(e))
            return
        except Exception as e:                # never leave an old command on show
            self.refuse(f"the form cannot build a command ({type(e).__name__})")
            return
        self._line(command=gm.shown(argv))
        self.ok.set_sensitive(True)


class ConfirmForm(Form):
    """No fields: the command and what it does, to read before OK. `refusal`:
    why the command would refuse it, as the window can see, so OK stays off."""

    def __init__(self, parent, title, ok_label, intro, argv, warning=None, refusal=None):
        super().__init__(parent, title, ok_label, intro)
        self._argv = argv
        self._refusal = refusal
        if warning:
            _set(self.warning, esc(warning))
        self.done_building()

    def build(self):
        if self._refusal:
            raise gm.FormError(self._refusal)
        return list(self._argv)


class LeadFields:
    """The lead's source, name, network and model, shared by the new-project
    form and the change-lead form. The model is a remote endpoint or a
    self-hosted model qube; choosing a model qube takes the lead's network to
    none, which the form shows in the network field and in its command."""

    SOURCES = (("template", "a fresh qube from a template"),
               ("clone", "a clone of one of the hub's AppVMs"),
               ("promote", "one of the hub's AppVMs, promoted in place"))
    MODELS = (("remote", "a remote endpoint, host:port, reached through the lead's network"),
              ("qube", "a self-hosted model qube: the lead then has no network"))

    def add_lead_fields(self, fleet_rows, gw_rows, hub, space, model_hint, slot=None,
                        current_qube=None):
        """`space` gives the project's name space (`ai-<label>-`) when called.
        The networks offered are the enrolled gateways, from `gw_rows`. `slot`
        and `current_qube`: a lead change's project, and its model qube now,
        which the model-qube field offers to keep or to take away."""
        self._fleet, self._gateways, self._hub, self._space = fleet_rows, gw_rows, hub, space
        self._slot, self._current_qube = slot, current_qube
        self._netvm_before = None
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.source = {}
        group = None
        for ident, text in self.SOURCES:
            rb = _radio(group, esc(text))
            group = group or rb
            _named(rb, esc(f"lead from {ident}"))
            rb.connect("toggled", self._source_changed)
            box.pack_start(rb, False, False, 0)
            self.source[ident] = rb
        self.row("The lead is", box)
        self.origin = self.combo("Made from", [])
        name_box = Gtk.Box(spacing=2)
        self.lead_space = _label(esc(space()))
        _named(self.lead_space, esc("lead name prefix"))
        self.lead_name = Gtk.Entry()
        _placeholder(self.lead_name, esc("lead"))
        _named(self.lead_name, esc("Lead name"))
        self.lead_name.connect("changed", self.update)
        name_box.pack_start(self.lead_space, False, False, 0)
        name_box.pack_start(self.lead_name, True, True, 0)
        self.row("Lead name", name_box)
        self.lead_netvm = self.combo(
            "Lead network",
            [("", esc("not set: a new lead gets none, a promoted one keeps its own"))]
            + [(n, esc(gm.network_text(n, gw_rows))) for n in gm.network_choices(gw_rows)])
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.model_kind = {}
        group = None
        for ident, text in self.MODELS:
            rb = _radio(group, esc(text))
            group = group or rb
            _named(rb, esc(f"lead's model: {ident}"))
            box.pack_start(rb, False, False, 0)
            self.model_kind[ident] = rb
        self.row("The lead's model", box)
        self.model = self.entry("Lead's model endpoint", model_hint)
        options = gm.model_qube_options(fleet_rows, hub, slot, current_qube, keep=True)
        self.model_qube = self.combo("Model qube", [(i, esc(t)) for i, t in options],
                                     active="" if current_qube else None, preselect=False)
        self.qube_info = _label(esc(""), wrap=True)
        self.row("The model qube", self.qube_info)
        self.lead_info = _label(esc(""), wrap=True)
        self.row("The lead's network", self.lead_info)
        if current_qube:
            self.model_kind["qube"].set_active(True)
        for rb in self.model_kind.values():
            rb.connect("toggled", self._model_changed)
        self._source_changed()
        self._model_changed()

    def _model_changed(self, *_):
        """A model qube means no network for the lead: the network field shows
        none and is off while it is chosen, and gets back what it had after."""
        qube = self.model_kind["qube"].get_active()
        self.model.set_sensitive(not qube)
        self.model_qube.set_sensitive(qube)
        if qube and self.lead_netvm.get_sensitive():
            self._netvm_before = self.lead_netvm.get_active_id()
            self.lead_netvm.set_active_id("none")
            self.lead_netvm.set_sensitive(False)
        elif not qube and not self.lead_netvm.get_sensitive():
            self.lead_netvm.set_active_id(self._netvm_before or "")
            self.lead_netvm.set_sensitive(True)
        self.update()

    def model_choice(self):
        """("remote", None), or ("qube", the field's choice): a qube's name,
        "" to keep the project's model qube, "none" to take it away, or None
        while nothing is chosen."""
        if not self.model_kind["qube"].get_active():
            return "remote", None
        return "qube", self.model_qube.get_active_id()

    def model_red_lines(self, fleet_rows) -> list:
        """What the form says in red about the model, worked out from
        `fleet_rows`: a promoted lead that loses its network, and a model qube
        that already serves another project."""
        kind, qube = self.model_choice()
        if kind != "qube":
            return []
        lead = self.origin.get_active_id() if self.lead_source() == "promote" else None
        return gm.model_qube_red(qube, lead, self._slot, fleet_rows).splitlines()

    def lead_model_values(self, source, origin, netvm, typed, carried=None, change=False):
        """(model endpoint, model qube) as the form sends them, each refused
        where the command refuses it, with the lines under the fields said
        first: where the lead will be, and what OK does to the model qube. A
        lead change that keeps the project's model qube sends neither."""
        kind, choice = self.model_choice()
        _set(self.qube_info, esc(gm.model_qube_info(choice, self._fleet, self._slot,
                                                    self._current_qube) if kind == "qube" else ""))
        if kind == "remote":
            net = self.lead_network(source, origin, netvm, carried, change)
            return gm.lead_model(net, typed, carried), None
        self.lead_network(source, origin, netvm, carried, change, qube=choice or "")
        if not len(self.model_qube.get_model()):
            raise gm.FormError(gm.no_model_qube(self._hub))
        return None, gm.chosen_model_qube(choice, self._current_qube) or None

    def red_changed(self, fleet_rows):
        """Why OK may no longer run what the form showed in red, or None: the
        red text, worked out from the fleet as it is now, `fleet_rows`, is
        not the text worked out from the fleet the form was opened on."""
        if self.red_text(fleet_rows) != self.red_text(self._fleet):
            return ("what this form says in red has changed since it opened (a qube's network, "
                    "or the projects a model qube serves): open the form again")
        return None

    def red_text(self, fleet_rows) -> str:
        return "\n".join(self.model_red_lines(fleet_rows))

    def lead_source(self):
        return next((k for k, rb in self.source.items() if rb.get_active()), None)

    def _source_changed(self, *_):
        source = self.lead_source()
        names = (gm.lead_templates(self._fleet) if source == "template"
                 else gm.hubs_appvms(self._fleet, self._hub))
        _fill(self.origin, [(n, esc(n)) for n in names])
        if names:
            self.origin.set_active(0)
        self.lead_name.set_sensitive(source != "promote")
        self.lead_space.set_sensitive(source != "promote")
        self.update()

    def lead_values(self):
        """(source, origin, full name or None, network, model as typed). A
        promoted lead keeps its own name, so the field is ignored for it."""
        source = self.lead_source()
        netvm = self.lead_netvm.get_active_id() or None
        space = self._space()
        _set(self.lead_space, esc(space))
        typed = self.lead_name.get_text() if source != "promote" else ""
        return (source, self.origin.get_active_id(), gm.lead_name_from(typed, space), netvm,
                self.model.get_text())

    def lead_network(self, source, origin, netvm, carried=None, change=False, qube=None):
        """The network the new lead will have, said under the fields with what
        it asks of the model; the command's refusal of one that is not
        enrolled, before OK. `qube`: the model qube chosen, if any."""
        try:
            net = gm.lead_network(source, origin, netvm, self._fleet, self._gateways)
        except gm.FormError:
            _set(self.lead_info, esc(""))
            raise
        _set(self.lead_info, esc(gm.lead_info(net, carried, change, qube, self._current_qube)))
        return net


class NetworkFields:
    """Worker networks: tick the allowed ones, choose the default among them.
    The choices are the enrolled gateways and none, each marked with what to
    know about it."""

    def add_network_fields(self, choices, ticked=(), default=None, gw_rows=()):
        self.nets = self.checks("Worker networks", choices, ticked,
                                {n: gm.network_text(n, gw_rows) for n in choices})
        self.default_net = self.combo("Default worker network", [])
        for cb in self.nets.values():
            cb.connect("toggled", self._nets_changed)
        self._nets_changed(default=default)

    def _nets_changed(self, *_, default=None):
        current = default or self.default_net.get_active_id()
        ticked = [n for n, cb in self.nets.items() if cb.get_active()]
        _fill(self.default_net, [(n, esc(n)) for n in ticked])
        if current in ticked:
            self.default_net.set_active_id(current)
        elif ticked:
            self.default_net.set_active(0)
        self.update()

    def network_values(self) -> list:
        ticked = [n for n, cb in self.nets.items() if cb.get_active()]
        first = self.default_net.get_active_id()
        return ([first] if first in ticked else []) + [n for n in ticked if n != first]


class ProjectForm(Form, LeadFields, NetworkFields):
    def __init__(self, parent, fleet_rows, gw_rows, hub, prefix="ai-"):
        super().__init__(parent, "New project", "Create project",
                         "A project is a lead, the workers it creates, and optionally a dump "
                         "sink. The lead's own template is approved first when it is in AI space. "
                         "The networks are the enrolled gateways (the Gateways tab). The lead's "
                         "model is a remote endpoint or a self-hosted model qube. A lead with a "
                         "network needs its model endpoint: dom0 writes the lead's firewall to "
                         "allow that endpoint, DNS when it is a host name, and nothing else; a "
                         "lead with no network takes none. A lead whose model is a qube has no "
                         "network, and reaches the qube on port 11434: the qube leaves p00, loses "
                         "its network and is guarded.")
        self.prefix = prefix
        self.label_entry = self.entry("Label", "1-8 lowercase letters or digits")
        self.add_lead_fields(fleet_rows, gw_rows, hub, self.space,
                             "host:port, e.g. api.anthropic.com:443")
        self.templates = self.checks("More approved templates",
                                     gm.approved_template_choices(fleet_rows))
        self.add_network_fields(gm.network_choices(gw_rows), gw_rows=gw_rows)
        self.quota = self.entry("Workers' disk quota", "e.g. 20G")
        self.dump = _check(esc("also create its dump sink"))
        self.dump.connect("toggled", self.update)
        self.row("Dump sink", self.dump)
        self.done_building()

    def space(self) -> str:
        label = self.label_entry.get_text().strip()
        return f"{self.prefix}{label or '<label>'}-"

    def build(self):
        _set(self.warning, esc_lines(self.red_text(self._fleet)))
        gm.check_label(self.label_entry.get_text().strip())   # the label first: it makes the space
        source, origin, name, netvm, typed = self.lead_values()
        model, qube = self.lead_model_values(source, origin, netvm, typed)
        return gm.create_project(
            self.label_entry.get_text().strip(), source, origin, name, netvm,
            [n for n, cb in self.templates.items() if cb.get_active()],
            gm.check_networks(self.network_values(), self._gateways), self.quota.get_text(),
            self.dump.get_active(), model, qube)


class EditForm(Form, NetworkFields):
    def __init__(self, parent, fleet_rows, gw_rows, record):
        super().__init__(parent, f"Edit project {record.get('label')}", "Apply",
                         "Only what you change is sent. Workers keep their networks, and a "
                         "network still in use by a worker cannot be taken off the list. A "
                         "changed list holds only enrolled gateways that still qualify, or none: "
                         "one marked NOT USABLE can be taken off it, not kept on it.")
        self.record = record
        self._gateways = gw_rows
        current_t = list(record.get("templates") or ())
        names = sorted(set(gm.approved_template_choices(fleet_rows)) | set(current_t))
        self.templates = self.checks("Approved templates", names, current_t)
        current_n = ["none" if n is None else n for n in record.get("networks") or ()]
        choices = gm.network_choices(gw_rows)
        choices += [n for n in current_n if n not in choices]
        self.add_network_fields(choices, current_n, current_n[0] if current_n else None,
                                gw_rows=gw_rows)
        self.quota = self.entry("Workers' disk quota", "e.g. 20G",
                                gm.quota_text(record.get("quota")))
        self.done_building()

    def build(self):
        rec = self.record
        templates = [n for n, cb in self.templates.items() if cb.get_active()]
        networks = self.network_values()
        current_n = ["none" if n is None else n for n in rec.get("networks") or ()]
        same_networks = (networks[:1] == current_n[:1] and set(networks) == set(current_n))
        quota = self.quota.get_text().strip()
        return gm.edit_project(
            rec.get("label"),
            templates=None if set(templates) == set(rec.get("templates") or ()) else templates,
            networks=None if same_networks else gm.check_networks(networks, self._gateways),
            quota=None if quota == gm.quota_text(rec.get("quota")) else quota)


class LeadForm(Form, LeadFields):
    def __init__(self, parent, fleet_rows, gw_rows, hub, record, prefix="ai-"):
        old = record.get("lead")
        carried, qube = record.get("model"), record.get("model_qube")
        super().__init__(
            parent, f"Change the lead of {record.get('label')}", "Change lead",
            (f"A new lead takes over. The old lead, {old}, is kept as a worker of this project "
             "or removed, as you choose below; a kept lead keeps its name, so the new one needs "
             "another. Kept, it keeps its network if the project lists it; otherwise the tick "
             "below adds that network to the list, and without the tick it goes to no network."
             if old else "The project has no lead: the new one takes over its workers.")
            + (f" The project's model is the model qube {qube}: a new lead with no network keeps "
               "it, and one with a network needs a model endpoint, which replaces it; dom0 writes "
               "its firewall to allow that endpoint, DNS when it is a host name, and nothing "
               "else." if qube else
               " A new lead with a network takes the model endpoint you give, or else the "
               f"project's ({carried or 'none on record'}); dom0 writes its firewall to allow "
               "that endpoint, DNS when it is a host name, and nothing else. A new lead whose "
               "model is a qube has no network."))
        self.record = record
        self.prefix = prefix
        self.add_lead_fields(fleet_rows, gw_rows, hub, self.space,
                             f"empty: the project's, {carried}" if carried else
                             "host:port; the project has none on record",
                             record.get("slot"), qube)
        self.old_lead = None
        self.add_old = None
        if old:
            # No default: removing a qube must be chosen, never left to a missed tick.
            self.old_lead = self.combo("The old lead", [
                ("keep", esc(f"keep {old} as a worker of this project")),
                ("remove", esc(f"remove {old}, with everything in it")),
            ], preselect=False)
            # Only with keep, as the command has it: unticked and off otherwise.
            self.add_old = _check(esc(f"add {old}'s network to the worker networks, so it "
                                      "keeps it as a worker"))
            self.add_old.set_sensitive(False)
            self.add_old.connect("toggled", self.update)
            self.row("Its network", self.add_old)
            self.old_info = _label(esc(""), wrap=True)
            self.row("Kept as a worker", self.old_info)
            self.old_lead.connect("changed", self._old_changed)
        self.done_building()

    def space(self) -> str:
        return f"{self.prefix}{self.record.get('label')}-"

    def _old_changed(self, *_):
        keep = self.old_lead.get_active_id() == "keep"
        if not keep and self.add_old.get_active():
            self.add_old.set_active(False)
        self.add_old.set_sensitive(keep)

    def red_text(self, fleet_rows) -> str:
        """A removal, then what the model choice does that the form says in red."""
        old = self.record.get("lead")
        lines = ([f"{old} will be removed, with everything in it. This cannot be undone."]
                 if old and self.old_lead.get_active_id() == "remove" else [])
        return "\n".join(lines + self.model_red_lines(fleet_rows))

    def build(self):
        old = self.record.get("lead")
        keep = add = False
        _set(self.warning, esc_lines(self.red_text(self._fleet)))
        if old:
            choice = self.old_lead.get_active_id()
            _set(self.old_info, esc(""))
            if choice is None:
                raise gm.FormError(f"choose what happens to the old lead, {old}")
            keep = choice == "keep"
            add = self.add_old.get_active()
        source, origin, name, netvm, typed = self.lead_values()
        default = f"{self.space()}lead"
        if keep and source != "promote" and not name and old == default:
            raise gm.FormError(f"the old lead keeps the name {default}: type a lead name "
                               "for the new one")
        if old:
            _set(self.old_info, esc(gm.old_lead_network(self.record, self._fleet,
                                                        self._gateways, keep, add)))
        model, qube = self.lead_model_values(source, origin, netvm, typed,
                                             self.record.get("model"), change=True)
        return gm.change_lead(self.record.get("label"), source, origin, name, netvm, keep,
                              model, add, qube)


class DumpForm(Form):
    def __init__(self, parent, key, default_name):
        super().__init__(parent, f"Dump sink for {key}", "Create sink",
                         "A fresh qube with no network, outside AI space, that the members "
                         "copy into without a dialog.")
        self.key = key
        self.sink_name = self.entry("Sink name", f"default: {default_name}")
        self.done_building()

    def build(self):
        return gm.add_dump(self.key, self.sink_name.get_text().strip() or None)


class MoveForm(Form):
    def __init__(self, parent, row, records):
        super().__init__(parent, f"Move {row.get('name')}", "Move",
                         "Its network does not change, so a project takes it only on one of "
                         "its worker networks.")
        self.row_data = row
        self.current = (row.get("slot") or "") or None
        self._records = records
        targets = [(t, esc(text)) for t, text in gm.move_targets(records)]
        self.target = self.combo("Into", targets)
        self.confirm = _check(esc(f"yes, move it out of {self.current}: its content goes with it"))
        self.confirm.connect("toggled", self.update)
        self.row("Across slots", self.confirm)
        self.netinfo = _label(esc(""), wrap=True)
        _named(self.netinfo, esc("network fit"))
        self.row("Network", self.netinfo)
        self.done_building()

    def network_fit(self, target) -> str:
        """What the command will judge, shown before OK: a project takes a qube
        only on one of its worker networks. The command decides."""
        net = self.row_data.get("netvm") or "none"
        rec = next((r for r in self._records.values() if r.get("label") == target), None)
        if rec is None:
            on = "'s network cannot be read" if net == gm.UNREADABLE else f" is on {net}"
            return f"{self.row_data.get('name')}{on}; p00 and no slot take any network."
        if net == gm.UNREADABLE:
            return (f"the network of {self.row_data.get('name')} cannot be read, so the command "
                    f"will refuse the move into {target} until it reads.")
        nets = ["none" if n is None else n for n in rec.get("networks") or ()]
        fits = net in nets
        return (f"{self.row_data.get('name')} is on {net}; {target} takes qubes on: "
                f"{', '.join(nets) or '-'}." + ("" if fits else
                " Not on that list, so the command will refuse it: change its network first."))

    def _target_slot(self, target):
        if target in (None, "none"):
            return None
        if target == "p00":
            return "p00"
        return next((s for s, r in self._records.items() if r.get("label") == target), None)

    def build(self):
        target = self.target.get_active_id()
        _set(self.netinfo, esc(self.network_fit(target)))
        crossing = bool(self.current) and self._target_slot(target) not in (None, self.current)
        self.confirm.set_sensitive(crossing)
        if crossing and not self.confirm.get_active():
            raise gm.FormError(f"tick the box: it leaves {self.current}")
        return gm.move(self.row_data.get("name"), target, confirm=crossing)


class RevokeForm(Form):
    def __init__(self, parent, name, note=""):
        """`note`: what revoking it means beyond that (`guimodel.revoke_note`)."""
        super().__init__(parent, f"Revoke {name}", "Revoke",
                         "Takes it out of AI space: removes ai-managed and every other qmcp "
                         "badge, so the hub and every lead lose it and this window stops "
                         "listing it (Add a qube to AI space brings it back). Its default "
                         "disposable is set to none, and it is shut down unless you leave it "
                         "running. The qube itself is not removed." + (f" {note}" if note else ""))
        self.qube_name = name
        self.keep = _check(esc("leave it running"))
        self.keep.connect("toggled", self.update)
        self.row("Power", self.keep)
        self.done_building()

    def build(self):
        return gm.role("revoke", self.qube_name, keep_running=self.keep.get_active())


class AddForm(Form):
    def __init__(self, parent, fleet_rows, hub, sinks):
        super().__init__(parent, "Add a qube to AI space", "Add",
                         "Managed: the hub may run commands in it as root and change it. "
                         "Guarded: listed and used as a reference, never operated. A qube "
                         "that provides network can only be guarded.")
        names = gm.outside_choices(fleet_rows, hub, sinks)
        self.qube = self.combo("Qube", [(n, esc(n)) for n in names], preselect=False)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.guarded = _radio(None, esc("guarded"))           # the default: the lesser authority
        self.managed = _radio(self.guarded, esc("managed"))
        for rb in (self.guarded, self.managed):
            rb.connect("toggled", self.update)
            box.pack_start(rb, False, False, 0)
        self.row("As", box)
        self.done_building()

    def build(self):
        name = self.qube.get_active_id()
        return gm.role("manage" if self.managed.get_active() else "guard", name)


class ProposalForm(Form):
    """Accept, reject or close one proposal. Accept's command carries the
    fingerprint of the `show` on display, and, when the second tick was given
    beside the reasons (which its form repeats in red), `--yes` with the digest
    of those reasons from the same show. Close runs the same `reject` as
    Reject, for a proposal the command says needs closing. At OK the window
    checks that the show on display is still the one this form was opened on."""

    #: action -> (title, OK button, what the form says it does)
    KINDS = {
        "accept_proposal": ("Accept proposal {}", "Accept", gm.accept_intro),
        "reject_proposal": ("Reject proposal {}", "Reject", gm.reject_intro),
        "close_proposal": ("Close proposal {}", "Close", gm.close_intro),
    }

    def __init__(self, parent, doc, ident, ticked=False):
        title, ok, intro = self.KINDS[ident]
        super().__init__(parent, title.format(doc.get("id")), ok, intro(doc))
        if ident == "accept_proposal":
            _set(self.warning, gm.second_tick_text(doc))
        self.doc, self.ident, self.ticked = doc, ident, ticked
        self.done_building()

    def build(self):
        if self.ident == "accept_proposal":
            return gm.accept_proposal(self.doc.get("id"), self.doc.get("sha256"),
                                      gm.tick_of(self.doc) if self.ticked else None)
        return gm.reject_proposal(self.doc.get("id"))


class EnrollForm(Form):
    """Enroll a qube that provides network as a gateway AI space may use."""

    def __init__(self, parent, fleet_rows, gw_rows, hub):
        super().__init__(parent, "Enroll a gateway", "Enroll",
                         "AI space may use an enrolled gateway as a network: a project lists "
                         "it, a lead is born on it, the hub's creates use it. Enroll a plain "
                         "router of your own, outside AI space or guarded, in front of the qube "
                         "it uses (sys-firewall, sys-whonix, a VPN qube). The command also checks "
                         "what this form cannot see: that it is not a Whonix gateway itself, "
                         "that Qubes' qubes-firewall feature is on for it (its own value, else "
                         "its template's), and that no template the hub manages builds it. The "
                         "qube itself does not change.")
        self._rows = {r["name"]: r for r in fleet_rows
                      if isinstance(r, dict) and isinstance(r.get("name"), str)}
        self._hub = hub
        self.qube = self.combo("Qube", [(n, esc(gm.enroll_text(self._rows[n], hub)))
                                        for n in gm.enroll_choices(fleet_rows, gw_rows, hub)],
                               preselect=False)
        self.anonymising = _check(esc("it reaches the network anonymously (Tor)"))
        self.anonymising.connect("toggled", self.update)
        self.row("Anonymising", self.anonymising)
        self.label_entry = self.entry("Label", "optional, up to 40 characters, e.g. a jurisdiction")
        self.done_building()

    def build(self):
        name = self.qube.get_active_id()
        why = gm.enroll_refusal(self._rows.get(name), self._hub) if name else None
        if why:
            raise gm.FormError(why)
        return gm.enroll_gateway(name, self.anonymising.get_active(), self.label_entry.get_text())


class GatewayForm(Form):
    """Change an enrolled gateway's flag or label: only what changed is sent."""

    def __init__(self, parent, row):
        super().__init__(parent, f"Change gateway {row.get('name')}", "Apply",
                         "Only what you change is sent. The qube itself does not change.")
        self.row_data = row
        self.anonymising = self.combo("Anonymising", [
            ("yes", esc("yes: it reaches the network anonymously (Tor)")), ("no", esc("no"))],
            active="yes" if row.get("anonymising") is True else "no")
        self.label_entry = self.entry("Label", "up to 40 characters; empty: no label",
                                      row.get("label") or "")
        self.done_building()

    def build(self):
        row = self.row_data
        anonymising = self.anonymising.get_active_id() == "yes"
        label = self.label_entry.get_text()
        # The field shows the label escaped: left as shown, it is unchanged.
        return gm.change_gateway(
            row.get("name"),
            None if anonymising == (row.get("anonymising") is True) else anonymising,
            None if label == gm.esc(row.get("label") or "") else label)


class FirewallForm(Form):
    """A change to a lead's firewall, made from the view's last read: the
    rules now, as you accepted them and live, and what they become, side by
    side under the fields."""

    def __init__(self, parent, title, ok_label, intro, doc):
        super().__init__(parent, title, ok_label, intro)
        self.set_default_size(900, -1)
        self.doc = doc
        self.key = doc.get("project")

    def add_compare(self, columns):
        grid = Gtk.Grid(column_spacing=12, row_spacing=4, column_homogeneous=True)
        self.compare = []
        for i, (heading, text) in enumerate(columns):
            grid.attach(_label(esc(heading)), i, 0, 1, 1)
            view = _text_view()
            _set_lines(view, text)
            _named(view, esc(heading))
            grid.attach(_scrolled(view, 110), i, 1, 1, 1)
            self.compare += [view]
        self.wide(grid)

    def show_compare(self, columns):
        for view, (_, text) in zip(self.compare, columns):
            _set_lines(view, text)


class ModelForm(FirewallForm):
    def __init__(self, parent, doc, read_at=None):
        super().__init__(parent, f"The lead's model endpoint, {doc.get('project')}", "Set model",
                         gm.model_intro(doc), doc)
        self.model = self.entry("Model endpoint", f"host:port; now {doc.get('model') or 'none'}")
        self.add_compare(gm.rules_compare(self.doc, gm.model_rules("")))
        self.done_building()

    def build(self):
        text = self.model.get_text()
        self.show_compare(gm.rules_compare(self.doc, gm.model_rules(text)))
        return gm.set_lead_model(self.key, text)


class RulesForm(FirewallForm):
    def __init__(self, parent, doc, read_at=None):
        super().__init__(parent, f"The lead's firewall rules, {doc.get('project')}", "Set rules",
                         gm.rules_intro(doc), doc)
        start = doc.get("accepted") if isinstance(doc.get("accepted"), list) else doc.get("live")
        self._shown = list(start) if isinstance(start, list) else []
        self.rules_view = Gtk.TextView(monospace=True)
        _named(self.rules_view, esc("rules, one per line"))
        if self._shown:
            _set_lines(self.rules_view, gm.esc_items(self._shown))
        self.rules_view.get_buffer().connect("changed", self.update)
        self.row("Rules, one per line", _scrolled(self.rules_view, 120))
        self.add_compare(gm.rules_compare(self.doc, self._shown))
        self.done_building()

    def typed(self) -> list:
        buf = self.rules_view.get_buffer()
        return gm.typed_rules(buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False),
                              self._shown)

    def build(self):
        rules = self.typed()
        self.show_compare(gm.rules_compare(self.doc, rules))
        return gm.set_lead_rules(self.key, rules)


class AcceptRulesForm(FirewallForm):
    def __init__(self, parent, doc, read_at=None):
        super().__init__(parent, f"Accept the current rules of {doc.get('lead')}",
                         "Accept rules", gm.accept_rules_intro(doc, read_at), doc)
        self.add_compare(gm.rules_compare(self.doc))
        self.done_building()

    def build(self):
        return gm.accept_lead_rules(self.key)


class ModelQubeForm(FirewallForm):
    """The project's self-hosted model qube, or none. A model qube means no
    network for the lead: on a lead that has one, the form says in red before
    OK that it loses it; a qube that already serves another project carries
    the command's warning, in red too. Both are worked out from the fleet the
    form opened on, and OK refuses once they read differently."""

    def __init__(self, parent, doc, read_at=None, fleet_rows=(), hub=None):
        super().__init__(parent, f"The lead's model qube, {doc.get('project')}", "Set model qube",
                         gm.model_qube_intro(doc), doc)
        self.set_default_size(620, -1)              # no rules side by side: nothing is written
        self._fleet, self._hub = list(fleet_rows or ()), hub
        options = gm.model_qube_options(self._fleet, hub, doc.get("slot"), doc.get("model_qube"))
        self.model_qube = self.combo("Model qube", [(i, esc(t)) for i, t in options],
                                     preselect=False)
        self.info = _label(esc(""), wrap=True)
        self.row("What OK does", self.info)
        self.done_building()

    def red_text(self, fleet_rows) -> str:
        return gm.model_qube_red(self.model_qube.get_active_id(), self.doc.get("lead"),
                                 self.doc.get("slot"), fleet_rows)

    def red_changed(self, fleet_rows):
        if self.red_text(fleet_rows) != self.red_text(self._fleet):
            return ("what this form says in red has changed since it opened (the lead's network, "
                    "or the projects the model qube serves): open the form again")
        return None

    def build(self):
        choice = self.model_qube.get_active_id()
        _set(self.warning, esc_lines(self.red_text(self._fleet)))
        _set(self.info, esc(gm.model_qube_info(choice, self._fleet, self.doc.get("slot"),
                                               self.doc.get("model_qube"))))
        if not len(self.model_qube.get_model()):
            raise gm.FormError(gm.no_model_qube(self._hub))
        why = gm.model_qube_refusal(self.doc, choice, self._fleet)
        if why:
            raise gm.FormError(why)
        return gm.set_lead_model_qube(self.key, choice)


# ======================================================================= the window

class Window(Gtk.Window):
    """The tree of AI space and projects with each lead's firewall, the hub's
    proposals, the gateway registry, the check light, the audit log and the
    settings; every command that changes something, but `migrate`, is a
    button and a form."""

    ACTIONS = (
        ("new_project", "New project..."), ("edit_project", "Edit project..."),
        ("change_lead", "Change lead..."), ("remove_lead", "Remove lead..."),
        ("add_dump", "Dump sink..."), ("delete_project", "Delete project..."),
        ("finish_delete", "Finish delete..."), ("move", "Move..."), ("manage", "Manage..."),
        ("guard", "Guard..."), ("revoke", "Revoke..."), ("add_to_ai_space", "Add a qube to AI space..."),
        ("set_model", "Set lead model..."), ("set_rules", "Set lead rules..."),
        ("accept_rules", "Accept current rules..."), ("set_model_qube", "Set model qube..."),
    )
    #: The forms that change a lead's firewall or model: action -> (form, title).
    FIREWALL_FORMS = {"set_model": (ModelForm, "Set lead model"),
                      "set_rules": (RulesForm, "Set lead rules"),
                      "accept_rules": (AcceptRulesForm, "Accept current rules"),
                      "set_model_qube": (ModelQubeForm, "Set model qube")}
    GATEWAY_ACTIONS = (("enroll_gateway", "Enroll..."), ("change_gateway", "Change..."),
                       ("remove_gateway", "Remove..."))

    def __init__(self, runner=None, report=None, show_forms=True):
        super().__init__(title="qubes-mcp")
        self.set_default_size(1240, 760)
        self.runner = runner or Runner()
        self.report = report or self._report_dialog
        self.show_forms = show_forms
        self.busy = False
        self.pending = 0
        self.again = False
        #: Every read of the last refresh succeeded. Until one has, the window
        #: changes nothing: a failed read must never pass for the fleet's state.
        self.complete = False
        self.records_read = False
        #: When the qubes, records, audit lines and settings on show were read,
        #: in one complete refresh; None before the first.
        self.view_time = None
        self.reads: dict = {}
        self.errors: dict = {}
        self.fleet: list = []
        self.project_rows: list = []
        self.records: dict = {}
        self.settings: dict = {}
        self.check_doc = None
        self.audit_rows: list = []
        self.proposal_rows: list = []
        self.proposals_read = False
        self.gateways: list = []
        self.gateways_read = False
        self.gateway_selected = None
        #: The selected proposal, as its last `show` read it.
        self.pane = gm.ProposalPane()
        #: The selected project's lead firewall, as its last read gave it.
        self.fw_pane = gm.FirewallPane()
        self._filling = False         # the list is being rebuilt: not a new selection
        self._gateways_filling = False
        self._tree_filling = False
        self._tick_key = None         # what the second tick on show answers
        self.nodes: dict = {}
        self.selected = None
        self.last_form = None
        self._css()
        self._build()

    # ------------------------------------------------------------------ layout
    def _css(self):
        screen = Gdk.Screen.get_default()
        if screen is None:
            return
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_screen(screen, provider,
                                                 Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def _build(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(outer)
        top = Gtk.Box(spacing=12)
        for side in ("start", "end", "top"):
            getattr(top, f"set_margin_{side}")(8)
        self.light = _label(esc("qmcp check: not run yet"))
        self.light.get_style_context().add_class("qmcp-light")
        self.light.get_style_context().add_class("qmcp-UNKNOWN")
        _named(self.light, esc("check light"))
        self.checked = _label(esc(""))
        self.status = _label(esc("Starting"))
        _named(self.status, esc("status"))
        self.status.set_ellipsize(Pango.EllipsizeMode.END)
        self.spinner = Gtk.Spinner()
        top.pack_start(self.light, False, False, 0)
        top.pack_start(self.checked, False, False, 0)
        top.pack_start(self.status, True, True, 0)
        top.pack_end(_button(esc("Refresh"), lambda *_: self.refresh()), False, False, 0)
        top.pack_end(self.spinner, False, False, 0)
        outer.pack_start(top, False, False, 0)

        self.notebook = Gtk.Notebook()
        outer.pack_start(self.notebook, True, True, 0)
        self.notebook.append_page(self._qubes_page(), _label(esc("Qubes")))
        self.proposals_tab = _label(esc(gm.proposals_tab(None)))
        self.notebook.append_page(self._proposals_page(), self.proposals_tab)
        self.notebook.append_page(self._gateways_page(), _label(esc("Gateways")))
        self.notebook.append_page(self._check_page(), _label(esc("Check")))
        self.notebook.append_page(self._audit_page(), _label(esc("Audit")))
        self.notebook.append_page(self._settings_page(), _label(esc("Settings")))

    def _qubes_page(self):
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.store = Gtk.TreeStore(*([str] * (1 + len(gm.COLUMNS))))
        self.tree = Gtk.TreeView(model=self.store)
        for i, (_, heading) in enumerate(gm.COLUMNS):
            _column(self.tree, esc(heading), i + 1, expand=(i == 0))
        _named(self.tree, esc("qubes and projects"))
        self.tree.get_selection().connect("changed", self._on_select)
        paned.pack1(_scrolled(self.tree), True, False)

        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        for side in ("start", "end", "top", "bottom"):
            getattr(right, f"set_margin_{side}")(8)
        self.details = Gtk.Grid(column_spacing=12, row_spacing=4)
        right.pack_start(_scrolled(self.details, 260), True, True, 0)
        self.buttons = {}
        grid = Gtk.Grid(column_spacing=6, row_spacing=6, column_homogeneous=True)
        for i, (ident, text) in enumerate(self.ACTIONS):
            button = _button(esc(text), lambda _b, ident=ident: self.act(ident))
            self.buttons[ident] = button
            grid.attach(button, i % 2, i // 2, 1, 1)
        right.pack_start(grid, False, False, 0)
        right.set_size_request(380, -1)
        paned.pack2(right, False, False)
        paned.set_position(820)
        return paned

    def _proposals_page(self):
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.proposal_store = Gtk.ListStore(*([str] * (1 + len(gm.PROPOSAL_COLUMNS))))
        view = Gtk.TreeView(model=self.proposal_store)
        for i, (key, heading) in enumerate(gm.PROPOSAL_COLUMNS):
            _column(view, esc(heading), i + 1, expand=(key == "title"), clip=(key == "title"))
        _named(view, esc("proposals"))
        view.get_selection().connect("changed", self._on_proposal_select)
        self.proposal_view = view
        paned.pack1(_scrolled(view), True, False)

        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        for side in ("start", "end", "top", "bottom"):
            getattr(right, f"set_margin_{side}")(8)
        self.proposal_note = _label(esc(self.pane.note(None)), wrap=True)
        _named(self.proposal_note, esc("proposal status"))
        right.pack_start(self.proposal_note, False, False, 0)
        self.proposal_details = Gtk.Grid(column_spacing=12, row_spacing=4)
        right.pack_start(_scrolled(self.proposal_details, 160), True, True, 0)
        # Why accepting needs the second tick, in red, and the tick that gives it.
        # The reasons scroll past a fifth of the screen, so the tick and the
        # buttons under them never leave it.
        self.proposal_warning = _label(esc(""), wrap=True, selectable=True)
        self.proposal_warning.get_style_context().add_class("qmcp-FAILED")
        _named(self.proposal_warning, esc("second tick reasons"))
        right.pack_start(_bounded(self.proposal_warning, _screen_room(None, 0) // 5), False, False, 0)
        self.proposal_tick = _check(esc("I have read these reasons"))
        _named(self.proposal_tick, esc("second tick"))
        self.proposal_tick.set_no_show_all(True)
        self.proposal_tick.set_visible(False)
        self.proposal_tick.connect("toggled", lambda *_: self._sync())
        right.pack_start(self.proposal_tick, False, False, 0)
        bar = Gtk.Box(spacing=6, homogeneous=True)
        self.proposal_buttons = {}
        for ident, text in (("accept_proposal", "Accept..."), ("reject_proposal", "Reject..."),
                            ("close_proposal", "Close...")):
            button = _button(esc(text), lambda _b, ident=ident: self.act(ident))
            self.proposal_buttons[ident] = button
            bar.pack_start(button, True, True, 0)
        right.pack_start(bar, False, False, 0)
        right.set_size_request(420, -1)
        paned.pack2(right, False, False)
        paned.set_position(780)
        return paned

    def _gateways_page(self):
        """The gateway registry: a list, the selection's every field, and its
        actions. A separate tab, not a group in the tree: an entry is a record
        of the registry, its qube usually outside AI space, and possibly gone."""
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.gateway_store = Gtk.ListStore(*([str] * (1 + len(gm.GATEWAY_COLUMNS))))
        view = Gtk.TreeView(model=self.gateway_store)
        for i, (key, heading) in enumerate(gm.GATEWAY_COLUMNS):
            _column(view, esc(heading), i + 1, expand=(key == "notes"),
                    wrap=(360 if key == "notes" else 0))
        _named(view, esc("gateways"))
        view.get_selection().connect("changed", self._on_gateway_select)
        self.gateway_view = view
        paned.pack1(_scrolled(view), True, False)

        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        for side in ("start", "end", "top", "bottom"):
            getattr(right, f"set_margin_{side}")(8)
        self.gateway_note = _label(esc(gm.gateways_note(None)), wrap=True)
        _named(self.gateway_note, esc("gateway registry status"))
        right.pack_start(self.gateway_note, False, False, 0)
        self.gateway_details = Gtk.Grid(column_spacing=12, row_spacing=4)
        right.pack_start(_scrolled(self.gateway_details, 260), True, True, 0)
        # What to know about the selected gateway, beside its fields.
        self.gateway_warning = _label(esc(""), wrap=True, selectable=True)
        self.gateway_warning.get_style_context().add_class("qmcp-note")
        _named(self.gateway_warning, esc("gateway notes"))
        right.pack_start(self.gateway_warning, False, False, 0)
        bar = Gtk.Box(spacing=6, homogeneous=True)
        self.gateway_buttons = {}
        for ident, text in self.GATEWAY_ACTIONS:
            button = _button(esc(text), lambda _b, ident=ident: self.act(ident))
            self.gateway_buttons[ident] = button
            bar.pack_start(button, True, True, 0)
        right.pack_start(bar, False, False, 0)
        right.set_size_request(420, -1)
        paned.pack2(right, False, False)
        paned.set_position(780)
        return paned

    def _check_page(self):
        self.check_store = Gtk.ListStore(*([str] * 4))
        view = Gtk.TreeView(model=self.check_store)
        for i, (_, heading) in enumerate(gm.CHECK_FIELDS):
            _column(view, esc(heading), i + 1, expand=(i == 2), wrap=(700 if i == 2 else 0))
        _named(view, esc("check findings"))
        self.check_view = view
        return _scrolled(view)

    def _audit_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        for side in ("start", "end", "top", "bottom"):
            getattr(box, f"set_margin_{side}")(6)
        bar = Gtk.Box(spacing=8)
        bar.pack_start(_button(esc("Verify the chain"), lambda *_: self.verify()), False, False, 0)
        self.rotate_button = _button(esc("Rotate..."), lambda *_: self.act("rotate"))
        bar.pack_start(self.rotate_button, False, False, 0)
        self.verify_label = _label(esc(f"Calls from the hub and the leads to dom0's state-changing "
                                       f"services, and every command of yours that changes "
                                       f"something (caller operator), newest first (the last "
                                       f"{gm.AUDIT_TAIL})."), wrap=True)
        _named(self.verify_label, esc("verify result"))
        bar.pack_start(self.verify_label, True, True, 0)
        box.pack_start(bar, False, False, 0)
        self.audit_store = Gtk.ListStore(*([str] * (1 + len(gm.AUDIT_FIELDS))))
        view = Gtk.TreeView(model=self.audit_store)
        for i, (key, heading) in enumerate(gm.AUDIT_FIELDS):
            _column(view, esc(heading), i + 1, expand=(key == "args"), clip=(key == "args"))
        _named(view, esc("audit lines"))
        view.get_selection().connect("changed", self._on_audit_select)
        self.audit_view = view
        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned.pack1(_scrolled(view), True, False)
        self.audit_detail = _text_view()
        _named(self.audit_detail, esc("audit line in full"))
        paned.pack2(_scrolled(self.audit_detail, 120), False, False)
        paned.set_position(430)
        box.pack_start(paned, True, True, 0)
        return box

    def _settings_page(self):
        self.settings_grid = Gtk.Grid(column_spacing=16, row_spacing=6)
        for side in ("start", "end", "top", "bottom"):
            getattr(self.settings_grid, f"set_margin_{side}")(12)
        return _scrolled(self.settings_grid)

    # ------------------------------------------------------------------ reads
    def refresh(self):
        # Whatever this refresh will show, the selected proposal's last show may
        # predate it (an accept that just ran, a lead changed): its buttons stay
        # off until it is read again. So may the selected lead's firewall.
        self.pane.stale()
        self.fw_pane.stale()
        self._render_proposal()
        self._render_details()
        if self.pending:
            self.again = True
            return
        self.pending = len(gm.READS)
        self.spinner.start()
        self.reads = {}
        for name, argv in gm.READS.items():
            self.runner.run(argv, lambda result, name=name: self._read_done(name, result),
                            timeout=READ_TIMEOUT_S)

    def _read_done(self, name, result):
        self.reads[name] = result
        self.pending -= 1
        if self.pending:
            return
        self._absorb()
        self._render()
        if not self.busy:
            self.spinner.stop()
        if self.again:
            self.again = False
            self.refresh()

    def _absorb(self):
        """Take the qubes, records, proposals, gateways, audit lines and
        settings of a refresh together, or not at all. Once a refresh has read
        everything, a later one with a failed read keeps those from the last
        complete one (never fresh qubes judged against old records, nor fresh
        records against an old registry) and turns changes off.
        The light and the Check tab always show this refresh's check, which
        judges the fleet by itself, or UNKNOWN if it did not answer. Before the
        first complete refresh, what was read is shown, and nothing that needs
        the records is judged until they are read."""
        self.errors = {}

        def parsed(name, parse, kind):
            result = self.reads.get(name)
            try:
                if result is None:
                    raise gm.ReadError(f"{name}: no answer")
                value = parse(result)
                if not isinstance(value, kind):
                    raise gm.ReadError(f"{name}: unexpected answer")
                if name == "check" and gm.light(value) == "UNKNOWN":
                    raise gm.ReadError("check: no result")
                return value
            except gm.ReadError as e:
                self.errors[name] = str(e)
                return None
        fleet = parsed("fleet", gm.parse_json, list)
        rows = parsed("projects", gm.parse_json, list)
        settings = parsed("settings", gm.parse_json, dict)
        check = parsed("check", gm.parse_json, dict)
        audit_rows = parsed("audit", gm.parse_audit, list)
        proposal_rows = parsed("proposals", gm.parse_json, list)
        gateways = parsed("gateways", gm.parse_json, list)
        self.check_doc = check            # a light from a failed read would be a guess
        self.complete = not self.errors
        if self.view_time is not None and not self.complete:
            return                        # keep the last complete view, whole
        if fleet is not None:
            self.fleet = fleet
        if rows is not None:
            self.project_rows = rows
            self.records_read = True
            self.records = {r["slot"]: r for r in rows
                            if isinstance(r, dict) and isinstance(r.get("slot"), str)}
        if settings is not None:
            self.settings = settings
        if audit_rows is not None:
            self.audit_rows = audit_rows
        if proposal_rows is not None:
            self.proposal_rows = proposal_rows
            self.proposals_read = True
        if gateways is not None:
            self.gateways = gateways
            self.gateways_read = True
        if self.complete:
            self.view_time = time.strftime("%H:%M:%S")

    def _render(self):
        selected = self.selected
        # While the tree is rebuilt the selection comes and goes: that is no
        # new selection, so the lead's firewall is read once, after it.
        self._tree_filling = True
        try:
            self.store.clear()
            self.nodes = {}
            tree = gm.build_tree(self.fleet, self.project_rows if self.records_read else None,
                                 self.settings)

            def add(parent, nodes):
                for node in nodes:
                    it = _tree_append(self.store, parent, node.key, node.cells)
                    self.nodes[node.key] = node
                    add(it, node.children)
            add(None, tree)
            self.tree.expand_all()
            self._reselect(selected)
        finally:
            self._tree_filling = False
        self._read_firewall(gm.firewall_key(self.node(), self.records))
        self._render_details()

        self.check_store.clear()
        for i, cells in enumerate(gm.check_rows(self.check_doc)):
            _list_append(self.check_store, str(i), cells)
        result = gm.light(self.check_doc)
        ctx = self.light.get_style_context()
        for name in LIGHTS:
            ctx.remove_class(f"qmcp-{name}")
        ctx.add_class(f"qmcp-{result}")
        _set(self.light, esc(f"qmcp check: {result}"))
        if self.check_doc is not None:
            _set(self.checked, esc("checked " + time.strftime("%H:%M:%S")))
        else:
            _set(self.checked, esc("the check did not answer"))

        self.audit_store.clear()
        for i, rec in reversed(list(enumerate(self.audit_rows))):
            _list_append(self.audit_store, str(i), gm.audit_cells(rec))
        _set_lines(self.audit_detail, esc_lines(gm.audit_hint(self.audit_rows)))

        _clear(self.settings_grid)
        for i, (heading, text) in enumerate(gm.settings_rows(self.settings)):
            self.settings_grid.attach(_label(esc(heading)), 0, i, 1, 1)
            self.settings_grid.attach(_label(text, selectable=True), 1, i, 1, 1)
        n = len(gm.SETTINGS_FIELDS)
        self.settings_grid.attach(_label(esc(
            "Read-only here. The installer writes each file in /etc/qmcp only if it is absent "
            "(deploy/install.sh --pool-cap, --private-cap, --birth-egress); to change one, edit "
            "it as root. The name prefix is /etc/qmcp/name-prefix. The hub is fixed at install. "
            "The gateway registry, /etc/qmcp/gateways.json, changes on the Gateways tab."),
            wrap=True), 0, n, 2, 1)
        self.settings_grid.show_all()
        self._render_proposals()
        self._render_gateways()

        if self.errors:
            shown = (f"Showing the qubes and records read at {self.view_time}. "
                     if self.view_time else "")
            _set(self.status, esc("Could not read: " + "; ".join(self.errors.values()) + ". "
                                  + shown + "Changes are off until a refresh reads everything."))
        elif not self.busy:
            _set(self.status, esc("Up to date"))
        self._sync()

    def _reselect(self, key):
        if key is None:
            return

        def visit(model, path, it):
            if model[it][0] == key:
                self.tree.get_selection().select_iter(it)
                return True
            return False
        self.store.foreach(visit)

    def node(self):
        return self.nodes.get(self.selected)

    def _on_select(self, selection):
        model, it = selection.get_selected()
        self.selected = model[it][0] if it is not None else None
        if not self._tree_filling:
            self._read_firewall(gm.firewall_key(self.node(), self.records))
        self._render_details()
        self._sync()

    def _render_details(self):
        """The selection's every field; under a project's, or its lead's, the
        lead's firewall as its last read gave it."""
        _clear(self.details)
        node = self.node()
        if node is None:
            return
        rows = gm.details(node, self.project_rows, self.fleet)
        rows += gm.firewall_section(self.fw_pane, gm.firewall_key(node, self.records), self.fleet)
        for i, (heading, text) in enumerate(rows):
            self.details.attach(_label(esc(heading)), 0, i, 1, 1)
            value = _label(text, selectable=True, wrap=True)
            _named(value, esc(heading))
            self.details.attach(value, 1, i, 1, 1)
        self.details.show_all()

    def _read_firewall(self, key):
        """Read the lead firewall of the selected project, or of the project
        whose lead is selected, as the user. Until it answers, its changes
        are off; `key` None clears it."""
        seq = self.fw_pane.select(key)
        if seq is not None:
            self.runner.run(gm.show_lead_firewall(key),
                            lambda result, seq=seq: self._firewall_read(seq, result),
                            timeout=READ_TIMEOUT_S)

    def _firewall_read(self, seq, result):
        if self.fw_pane.answer(seq, result, time.strftime("%H:%M:%S")):
            self._render_details()
            self._sync()

    def gateway_row(self):
        """The selected gateway's row, from the registry on show."""
        return next((r for r in gm.gateway_list(self.gateways)
                     if r["name"] == self.gateway_selected), None)

    def _render_gateways(self):
        rows = gm.gateway_list(self.gateways)
        name = self.gateway_selected
        self._gateways_filling = True
        try:
            self.gateway_store.clear()
            for row in rows:
                it = _list_append(self.gateway_store, row["name"], gm.gateway_cells(row))
                if row["name"] == name:
                    self.gateway_view.get_selection().select_iter(it)
        finally:
            self._gateways_filling = False
        if not any(r["name"] == name for r in rows):
            self.gateway_selected = None
        _set(self.gateway_note, esc(gm.gateways_note(self.gateways if self.gateways_read
                                                     else None)))
        self._render_gateway()

    def _on_gateway_select(self, selection):
        if self._gateways_filling:
            return
        model, it = selection.get_selected()
        self.gateway_selected = model[it][0] if it is not None else None
        self._render_gateway()

    def _render_gateway(self):
        _clear(self.gateway_details)
        row = self.gateway_row()
        for i, (heading, text) in enumerate(gm.gateway_details(row)):
            self.gateway_details.attach(_label(esc(heading)), 0, i, 1, 1)
            value = _label(text, selectable=True, wrap=True)
            _named(value, esc(heading))
            self.gateway_details.attach(value, 1, i, 1, 1)
        self.gateway_details.show_all()
        _set(self.gateway_warning, esc("; ".join(gm.gateway_notes(row)) if row else ""))
        self._sync()

    def _on_audit_select(self, selection):
        model, it = selection.get_selected()
        if it is None:
            return
        index = int(model[it][0])
        if 0 <= index < len(self.audit_rows):
            _set_lines(self.audit_detail, gm.audit_detail(self.audit_rows[index]))

    def _render_proposals(self):
        """The list and the tab's count, from the view on show. The selected
        proposal is read again, so its pane is never older than the list."""
        rows = gm.proposal_rows(self.proposal_rows)
        pid = self.pane.pid
        self._filling = True
        try:
            self.proposal_store.clear()
            for row in rows:
                it = _list_append(self.proposal_store, str(row["id"]), gm.proposal_cells(row))
                if row["id"] == pid:
                    self.proposal_view.get_selection().select_iter(it)
        finally:
            self._filling = False
        _set(self.proposals_tab, esc(gm.proposals_tab(self.proposal_rows if self.proposals_read
                                                      else None)))
        self._read_proposal(pid if any(r["id"] == pid for r in rows) else None)

    def _on_proposal_select(self, selection):
        if self._filling:
            return
        model, it = selection.get_selected()
        self._read_proposal(int(model[it][0]) if it is not None else None)

    def _read_proposal(self, pid):
        """Read the selected proposal with `qmcp proposal show`, as the user.
        Until it answers, Accept and Reject are off."""
        seq = self.pane.select(pid)
        self._render_proposal()
        if seq is not None:
            self.runner.run(gm.show_proposal(pid),
                            lambda result, seq=seq: self._shown(seq, result),
                            timeout=READ_TIMEOUT_S)

    def _shown(self, seq, result):
        if self.pane.answer(seq, result, time.strftime("%H:%M:%S")):
            self._render_proposal()

    def _render_proposal(self):
        """Every field of the selected proposal's last show; the reasons it
        needs the second tick, in red, and the tick, which answers exactly
        those reasons for exactly that stored proposal."""
        pane = self.pane
        _clear(self.proposal_details)
        for i, (heading, text) in enumerate(gm.proposal_details(pane.doc)):
            self.proposal_details.attach(_label(esc(heading)), 0, i, 1, 1)
            value = _label(text, selectable=True, wrap=True)
            _named(value, esc(heading))
            self.proposal_details.attach(value, 1, i, 1, 1)
        self.proposal_details.show_all()
        listed = bool(gm.proposal_rows(self.proposal_rows)) if self.proposals_read else None
        _set(self.proposal_note, esc(pane.note(listed)))
        _set(self.proposal_warning, gm.second_tick_text(pane.doc))
        key = gm.tick_key(pane.doc)
        if key != self._tick_key:
            self._tick_key = key
            self.proposal_tick.set_active(False)
        self.proposal_tick.set_visible(key is not None)
        self._sync()

    def _sync(self):
        writable = self.complete and not self.busy
        available = (gm.actions(self.node(), self.records, self.fw_pane, self.fleet)
                     if writable else set())
        for ident, button in self.buttons.items():
            button.set_sensitive(ident in available)
        self.rotate_button.set_sensitive(writable)
        decide = self._deciding()
        for ident, button in self.proposal_buttons.items():
            button.set_sensitive(ident in decide)
        registry = self._registry_actions()
        for ident, button in self.gateway_buttons.items():
            button.set_sensitive(ident in registry)

    def _registry_actions(self) -> set:
        """What the Gateways tab allows now: Enroll, and Change and Remove for
        the selected gateway, while changes are on."""
        if not self.complete or self.busy:
            return set()
        return gm.gateway_actions(self.gateway_row())

    def _deciding(self) -> set:
        """What the Proposals tab allows now, buttons and forms alike: what the
        selected proposal's last show allows, with the tick as it is, while
        changes are on."""
        if not self.complete or self.busy:
            return set()
        return self.pane.actions(self.proposal_tick.get_active())

    # ------------------------------------------------------------------ changes
    def _open(self, form, title, then=None, check=None):
        """`check`, asked at OK, returns why what the form was opened on no
        longer holds, or None; then the form refuses and nothing runs."""
        def response(dialog, resp):
            if resp != Gtk.ResponseType.OK:
                dialog.destroy()
                return
            if self.busy or not self.complete:
                dialog.refuse("another command is running, or the last refresh failed")
                return
            why = check() if check is not None else None
            if why:
                dialog.refuse(why)
                return
            try:
                argv = dialog.argv()
            except gm.FormError as e:
                dialog.refuse(str(e))
                return
            except Exception as e:
                dialog.refuse(f"the form cannot build a command ({type(e).__name__})")
                return
            dialog.destroy()
            self.write(title, argv, then)
        form.connect("response", response)
        self.last_form = form
        if self.show_forms:
            form.show_all()
        return form

    def write(self, title, argv, then=None, timeout=None):
        """Run one change, or the plan a change shows first; then report it
        and refresh, or hand the result to `then`. One at a time: reads may
        run beside it, another change may not."""
        if self.busy or not self.complete:
            return False
        self.busy = True
        self._sync()
        self.spinner.start()
        _set(self.status, esc("Running: " + shlex.join(argv)))

        def done(result):
            self.busy = False
            if not self.pending:
                self.spinner.stop()
            _set(self.status, esc(f"Last: {shlex.join(argv)}  (status {result.rc})"))
            if then is not None:
                then(result)
            else:
                self.report(title, result)
                self.refresh()
            self._sync()
        self.runner.run(argv, done, timeout=timeout)
        return True

    def act(self, ident):
        node = self.node()
        key = gm.project_key(node) if node is not None else None
        hub = self.settings.get("hub")
        prefix = self.settings.get("name_prefix") or "ai-"
        if ident == "new_project":
            form = ProjectForm(self, self.fleet, self.gateways, hub, prefix)
            return self._open(form, "Create project", check=lambda: form.red_changed(self.fleet))
        if ident == "add_to_ai_space":
            sinks = [r.get("dump") for r in self.records.values() if r.get("dump")]
            return self._open(AddForm(self, self.fleet, hub, sinks), "Add to AI space")
        if ident == "rotate":
            return self._open(ConfirmForm(
                self, "Rotate the audit log", "Rotate",
                "Moves the log aside and starts a new one anchored on the old head hash.",
                gm.audit_rotate()), "Rotate the audit log")
        if ident in ProposalForm.KINDS:
            return self.decide(ident)
        if ident in dict(self.GATEWAY_ACTIONS):
            return self.registry(ident)
        if ident in self.FIREWALL_FORMS:
            return self.lead_firewall(ident)
        if node is None:
            return None
        if ident == "edit_project":
            return self._open(EditForm(self, self.fleet, self.gateways, node.data), "Edit project")
        if ident == "change_lead":
            form = LeadForm(self, self.fleet, self.gateways, hub, node.data, prefix)
            return self._open(form, "Change lead", check=lambda: form.red_changed(self.fleet))
        if ident == "remove_lead":
            lead = node.data.get("lead")
            return self._open(ConfirmForm(
                self, f"Remove the lead of {key}", "Remove lead",
                f"Removes {lead}: its badges, then the record, then the qube. The project keeps "
                "its workers; only the hub reaches them until it has a new lead.",
                gm.remove_lead(key),
                warning=f"{lead} will be removed, with everything in it. This cannot be undone."),
                "Remove lead")
        if ident == "add_dump":
            slot = gm.slot_of(node) or "p00"
            label = node.data.get("label")
            return self._open(DumpForm(self, key or slot, f"{label}-dump" if label else "hub-dump"),
                              "Dump sink")
        if ident in ("delete_project", "finish_delete"):
            return self.delete(key)
        if node.kind != "qube":
            return None
        name = node.data.get("name")
        if ident == "move":
            return self._open(MoveForm(self, node.data, self.records), "Move")
        if ident == "revoke":
            return self._open(RevokeForm(self, name, gm.revoke_note(node.data)), "Revoke")
        if ident in ("manage", "guard"):
            return self._open(ConfirmForm(self, f"{ident.capitalize()} {name}", ident.capitalize(),
                                          gm.role_intro(ident, node.data),
                                          gm.role(ident, name)), ident.capitalize())
        return None

    def delete(self, key):
        """Ask the command for its plan first (no --yes changes nothing), then
        show that plan as the confirmation."""
        title = f"Delete project {key}"

        def planned(result):
            plan = (result.out or "").strip()
            if "Re-run with --yes" not in plan:
                self.report(title, result)
                return
            plan = plan.replace("qmcp project delete: ", "").replace(" Re-run with --yes.", "")
            self._open(ConfirmForm(self, title, "Delete", esc_lines(plan), gm.delete_project(key),
                                   warning="The lead and every member qube are removed, with "
                                           "everything in them. This cannot be undone."), title)
        return self.write(title, gm.delete_plan(key), planned, timeout=READ_TIMEOUT_S)

    def decide(self, ident):
        """Accept, reject or close the selected proposal, through a form that
        shows the command first: only what its last show allows, and Accept
        with the tick given when the command asks for the second tick. At OK
        the form runs only if the show on display still allows it and is the
        same proposal, fingerprint and second tick as when it opened."""
        ticked = self.proposal_tick.get_active()
        if ident not in self._deciding():
            return None
        doc = self.pane.doc
        form = ProposalForm(self, doc, ident, ticked=(ident == "accept_proposal" and ticked
                                                      and gm.tick_key(doc) is not None))
        return self._open(form, ProposalForm.KINDS[ident][0].format(doc.get("id")),
                          check=lambda: gm.proposal_changed(doc, ident, self.pane,
                                                            self.proposal_tick.get_active()))

    def registry(self, ident):
        """Enroll a gateway, or change or remove the selected one, through a
        form that shows the command first; only what the tab allows now."""
        if ident not in self._registry_actions():
            return None
        if ident == "enroll_gateway":
            return self._open(EnrollForm(self, self.fleet, self.gateways,
                                         self.settings.get("hub")), "Enroll a gateway")
        row = self.gateway_row()
        if ident == "change_gateway":
            return self._open(GatewayForm(self, row), "Change gateway")
        # It removes authority, never a qube: no red line. The command refuses
        # a gateway still in use, and so does the form, from the row on show.
        return self._open(ConfirmForm(self, f"Remove gateway {row['name']}", "Remove",
                                      gm.remove_gateway_intro(row), gm.remove_gateway(row["name"]),
                                      refusal=gm.gateway_in_use(row)), "Remove gateway")

    def lead_firewall(self, ident):
        """Set the selected lead's model or rules, or accept its current
        rules, through a form made from the firewall view on show. At OK the
        form runs only if the view still allows it and reads the same."""
        key = gm.firewall_key(self.node(), self.records)
        if not self.complete or self.busy or ident not in self.fw_pane.actions(key, self.fleet):
            return None
        doc = self.fw_pane.doc
        form_class, title = self.FIREWALL_FORMS[ident]
        if form_class is ModelQubeForm:
            form = form_class(self, doc, self.fw_pane.read_at, self.fleet, self.settings.get("hub"))
            return self._open(form, title, check=lambda: (
                gm.firewall_changed(doc, ident, self.fw_pane, self.fleet)
                or form.red_changed(self.fleet)))
        return self._open(form_class(self, doc, self.fw_pane.read_at), title,
                          check=lambda: gm.firewall_changed(doc, ident, self.fw_pane, self.fleet))

    def verify(self):
        def done(result):
            try:
                doc = gm.parse_json(result)
                ok = bool(doc.get("ok"))
                text = (f"chain OK: {doc.get('entries')} entries" if ok
                        else f"chain BROKEN: {doc.get('error')} (at entry {doc.get('entries')})")
            except (gm.ReadError, AttributeError) as e:
                text = f"verify did not answer: {e}"
            _set(self.verify_label, esc(text))
        self.runner.run(gm.AUDIT_VERIFY, done, timeout=READ_TIMEOUT_S)

    def idle(self) -> bool:
        return not self.busy and not self.pending

    # ------------------------------------------------------------------ the report
    def _report_dialog(self, title, result):
        dialog = Gtk.Dialog(transient_for=self, modal=False, destroy_with_parent=True)
        _title(dialog, esc(f"{title}: {'done' if result.ok else 'FAILED'}"))
        dialog.set_default_size(720, 360)
        _add_button(dialog, esc("Close"), Gtk.ResponseType.CLOSE)
        dialog.connect("response", lambda d, _r: d.destroy())
        box = dialog.get_content_area()
        box.set_spacing(6)
        for side in ("start", "end", "top", "bottom"):
            getattr(box, f"set_margin_{side}")(10)
        box.pack_start(_label(esc("Ran:")), False, False, 0)
        box.pack_start(_label(gm.shown(result.argv), wrap=True, selectable=True), False, False, 0)
        box.pack_start(_label(esc(f"Exit status {result.rc}: {'ok' if result.ok else 'failed'}")),
                       False, False, 0)
        view = _text_view()
        _set_lines(view, esc_lines((result.out or "") + (result.err or "")))
        _named(view, esc("command output"))
        box.pack_start(_scrolled(view, 200), True, True, 0)
        dialog.show_all()
        return dialog


def main(argv=None) -> int:
    if os.geteuid() == 0:
        print("qmcp-gui: run it as your own dom0 user, not root; it makes changes "
              "through sudo -n qmcp", file=sys.stderr)
        return 2
    if not Gtk.init_check(sys.argv[:1])[0]:
        print("qmcp-gui: no display", file=sys.stderr)
        return 1
    win = Window()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    win.refresh()
    Gtk.main()
    return 0
