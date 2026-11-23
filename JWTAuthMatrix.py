# -*- coding: utf-8 -*-
"""JWT Authorization Matrix: a Burp Suite extension (Jython 2.7, legacy Extender API).

Builds an endpoint x user matrix of HTTP status codes from requests that carry a JWT,
and replays every captured request with each known user's token to expose
authorization flaws.
"""

import base64
import json
import re
import threading
from collections import Counter, OrderedDict

from burp import (IBurpExtender, IContextMenuFactory, IExtensionStateListener,
                  IHttpListener, IMessageEditorController, ITab)
from java.awt import BorderLayout, Color, Cursor, Dimension, FlowLayout, Font
from java.awt.event import MouseAdapter
from java.lang import Object, String
from java.util import ArrayList, Date
from java.util.concurrent import Executors, RejectedExecutionException, TimeUnit
from java.util.regex import Pattern
from javax.swing import (BorderFactory, Box, BoxLayout, ButtonGroup, JButton, JCheckBox,
                         JColorChooser, JComboBox, JFileChooser, JFrame, JLabel, JMenuItem,
                         JOptionPane, JPanel, JPopupMenu, JProgressBar, JRadioButton,
                         JScrollPane, JSpinner, JSplitPane, JTabbedPane, JTable, JTextArea,
                         JTextField, ListSelectionModel, RowFilter, SpinnerNumberModel,
                         SwingUtilities, WindowConstants)
from javax.swing.event import DocumentListener
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import (AbstractTableModel, DefaultTableCellRenderer, DefaultTableModel,
                               TableRowSorter)

EXTENSION_NAME = "JWT Authorization Matrix"
LOCATION_AUTH = "auth"
LOCATION_COOKIE = "cookie"
DEFAULT_COOKIE_NAME = "jwt"
MAX_REPLAY_THREADS = 50

# (status pattern, RGB colour, legend label). A pattern is a code ("401"), a class ("4xx"),
# or a comma-separated combination ("2xx,5xx") that matches cells containing every part.
DEFAULT_CODE_GROUPS = [
    ("2xx", 0x387723, "Success (2xx)"),
    ("3xx", 0x87CEEB, "Redirect (3xx)"),
    ("4xx", 0xFFFF66, "Client Error (4xx)"),
    ("5xx", 0xFF8C00, "Server Error (5xx)"),
]
DEFAULT_NO_REQUESTS_COLOR = 0x333333


def log(message):
    print("[%s] %s" % (EXTENSION_NAME, message))


# =============================================================================
# Pure helpers (no Burp or Swing state)
# =============================================================================

def endpoint_key(method, path, query):
    return "%s %s%s" % (method, path, "?" + query if query else "")


def request_endpoint(request_info):
    url = request_info.getUrl()
    return endpoint_key(request_info.getMethod(), url.getPath(), url.getQuery())


def url_text(url):
    """URL as users write it: Burp's getUrl() spells out default ports (https://h:443/)."""
    default = {"http": 80, "https": 443}.get(url.getProtocol())
    port = "" if url.getPort() in (-1, default) else ":%d" % url.getPort()
    query = "?" + url.getQuery() if url.getQuery() else ""
    return "%s://%s%s%s%s" % (url.getProtocol(), url.getHost(), port, url.getPath(), query)


def status_code(helpers, response):
    return str(helpers.analyzeResponse(response).getStatusCode())


def group_endpoints(endpoints):
    """Map each base endpoint (method + path) to its full variants, in first-seen order."""
    groups = OrderedDict()
    for endpoint in endpoints:
        groups.setdefault(endpoint.split("?", 1)[0], []).append(endpoint)
    return groups


def _split_header(header):
    name, sep, value = header.partition(":")
    return (name.strip().lower(), value.strip()) if sep else (None, None)


def _parse_cookies(value):
    """Split a Cookie header value into [name, value] pairs; value is None for bare flags."""
    pairs = []
    for part in value.split(";"):
        name, sep, val = part.strip().partition("=")
        if name:
            pairs.append([name.strip(), val.strip() if sep else None])
    return pairs


def _format_cookies(pairs):
    return "; ".join(name if val is None else "%s=%s" % (name, val) for name, val in pairs)


def extract_token(headers, location, cookie_name):
    """Return the JWT found in the configured location, or None."""
    for header in headers:
        name, value = _split_header(header)
        if location == LOCATION_AUTH and name == "authorization":
            parts = value.split()
            if len(parts) >= 2 and parts[0].lower() == "bearer":
                return parts[1]
        elif location == LOCATION_COOKIE and name == "cookie":
            for cookie, token in _parse_cookies(value):
                if cookie == cookie_name and token:
                    return token
    return None


def replace_token(headers, token, location, cookie_name):
    """Return a copy of the request headers carrying `token` in the configured location."""
    result, replaced, cookie_index = [], False, None
    for header in headers:
        name, value = _split_header(header)
        if location == LOCATION_AUTH and name == "authorization":
            header, replaced = "Authorization: Bearer %s" % token, True
        elif location == LOCATION_COOKIE and name == "cookie":
            pairs = _parse_cookies(value)
            for pair in pairs:
                if pair[0] == cookie_name:
                    pair[1], replaced = token, True
            header = "Cookie: " + _format_cookies(pairs)
            if cookie_index is None:
                cookie_index = len(result)
        result.append(header)

    if not replaced:
        if location == LOCATION_AUTH:
            result.append("Authorization: Bearer %s" % token)
        elif cookie_index is not None:
            result[cookie_index] += "; %s=%s" % (cookie_name, token)
        else:
            result.append("Cookie: %s=%s" % (cookie_name, token))
    return result


def jwt_claim(token, claim):
    """Read a (dot-separated) claim from the JWT payload without verifying it; None if absent."""
    try:
        payload = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(str(payload + "=" * (-len(payload) % 4))))
        for key in claim.split("."):
            value = value[key]
    except Exception:
        return None
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return unicode(value)


def code_matches(code, pattern):
    pattern = pattern.strip().lower()
    if len(pattern) == 3 and pattern.endswith("xx"):
        return code[:1] == pattern[0]
    return code == pattern


def group_matches(codes, pattern):
    """Single patterns must match every code; combined patterns need each part present."""
    if "," in pattern:
        return all(any(code_matches(code, part) for code in codes) for part in pattern.split(","))
    return all(code_matches(code, pattern) for code in codes)


def pick_group(codes, groups):
    """Choose the colour group for a cell's status codes.

    The fully matching group with the most combined parts wins; otherwise fall back to the
    last group matching at least one code (so a 200/403 mix shows as 4xx by default).
    """
    best, best_parts, fallback = None, -1, None
    for group in groups:
        pattern = group[0]
        if group_matches(codes, pattern):
            if pattern.count(",") > best_parts:
                best, best_parts = group, pattern.count(",")
            fallback = group
        elif any(code_matches(code, pattern) for code in codes):
            fallback = group
    return best or fallback


def format_code_groups(groups):
    return "\n".join("%s:0x%06x:%s" % group for group in groups)


def parse_code_groups(text):
    """Parse `pattern:COLOR:label` lines. Returns (groups, error messages)."""
    groups, errors = [], []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        try:
            pattern = parts[0].strip()
            rgb = int(parts[1].strip().lstrip("#"), 16)
            if not pattern or not 0 <= rgb <= 0xFFFFFF:
                raise ValueError()
        except (IndexError, ValueError):
            errors.append("Line %d: %s" % (number, line))
            continue
        label = parts[2].strip() if len(parts) > 2 else ""
        groups.append((pattern, rgb, label or pattern))
    return groups, errors


def format_codes(codes):
    if not codes:
        return "0"
    return ", ".join("%s: %d" % item for item in sorted(codes.items()))


def matrix_to_csv(snapshot):
    endpoints, users, counts = snapshot

    def quote(value):
        return '"%s"' % value.replace('"', '""')
    lines = [",".join(quote(h) for h in ["Endpoint"] + list(users))]
    for endpoint in endpoints:
        row = counts.get(endpoint, {})
        lines.append(",".join([quote(endpoint)] + [quote(format_codes(row.get(u))) for u in users]))
    return "\n".join(lines)


def matrix_to_json(snapshot, user_claim):
    endpoints, users, counts = snapshot
    return json.dumps({
        "jwt_field": user_claim,
        "users": users,
        "endpoints": [{"endpoint": endpoint,
                       "users": dict((u, counts.get(endpoint, {}).get(u, {})) for u in users)}
                      for endpoint in endpoints],
    }, indent=2)


# =============================================================================
# State
# =============================================================================

class MatrixStore(object):
    """Thread-safe (endpoint, user) -> [(status code, message)] record, in first-seen order."""

    def __init__(self):
        self._lock = threading.Lock()
        self.clear()

    def clear(self):
        with self._lock:
            self._endpoints = OrderedDict()   # used as ordered sets
            self._users = OrderedDict()
            self._cells = {}                  # (endpoint, user) -> [(code, message)]
            self._counts = {}                 # endpoint -> user -> Counter(code)

    def add_user(self, user):
        with self._lock:
            self._users[user] = None

    def add(self, endpoint, user, code, message):
        with self._lock:
            self._endpoints[endpoint] = None
            self._users[user] = None
            self._cells.setdefault((endpoint, user), []).append((code, message))
            self._counts.setdefault(endpoint, {}).setdefault(user, Counter())[code] += 1

    def remove(self, endpoints):
        with self._lock:
            for endpoint in endpoints:
                self._endpoints.pop(endpoint, None)
                self._counts.pop(endpoint, None)
            self._cells = dict((key, entries) for key, entries in self._cells.items()
                               if key[0] in self._endpoints)

    def snapshot(self):
        """Return (endpoints, users, counts) where counts[endpoint][user][code] = n."""
        with self._lock:
            counts = dict((endpoint, dict((user, dict(codes)) for user, codes in row.items()))
                          for endpoint, row in self._counts.items())
            return list(self._endpoints), list(self._users), counts

    def messages(self, endpoints, user):
        with self._lock:
            return [msg for endpoint in endpoints
                    for _, msg in self._cells.get((endpoint, user), [])]

    def all_messages(self):
        """Every stored message once, ordered by endpoint then user."""
        with self._lock:
            seen, result = set(), []
            for endpoint in self._endpoints:
                for user in self._users:
                    for _, msg in self._cells.get((endpoint, user), []):
                        if id(msg) not in seen:
                            seen.add(id(msg))
                            result.append(msg)
            return result


class Settings(object):
    """User preferences, persisted in Burp's extension settings. Tokens are never persisted."""

    KEY = "settings"
    DEFAULTS = OrderedDict([
        ("listen_proxy", True),
        ("listen_repeater", True),
        ("listen_intruder", True),
        ("location", LOCATION_AUTH),
        ("cookie_name", DEFAULT_COOKIE_NAME),
        ("user_claim", "sub"),
        ("replay_threads", 5),
        ("history_url_filter", ""),
        ("code_groups", DEFAULT_CODE_GROUPS),
        ("no_requests_color", DEFAULT_NO_REQUESTS_COLOR),
    ])

    def __init__(self, callbacks):
        self._callbacks = callbacks
        for name, value in self.DEFAULTS.items():
            setattr(self, name, list(value) if isinstance(value, list) else value)
        try:
            self._load(json.loads(callbacks.loadExtensionSetting(self.KEY) or "{}"))
        except Exception as e:
            log("Ignoring unreadable saved settings: %s" % e)

    def _load(self, saved):
        for name, default in self.DEFAULTS.items():
            if name not in saved:
                continue
            value = saved[name]
            try:
                if name == "code_groups":
                    value = [(unicode(p), int(rgb), unicode(label)) for p, rgb, label in value]
                elif isinstance(default, bool):
                    value = bool(value)
                elif isinstance(default, int):
                    value = int(value)
                elif not isinstance(value, basestring):
                    raise TypeError("expected text")
            except (TypeError, ValueError) as e:
                log("Ignoring saved setting %s: %s" % (name, e))
                continue
            setattr(self, name, value)
        if self.location not in (LOCATION_AUTH, LOCATION_COOKIE):
            self.location = LOCATION_AUTH
        self.replay_threads = min(max(self.replay_threads, 1), MAX_REPLAY_THREADS)

    def save(self):
        data = dict((name, getattr(self, name)) for name in self.DEFAULTS)
        self._callbacks.saveExtensionSetting(self.KEY, json.dumps(data))

    def effective_cookie_name(self):
        return self.cookie_name.strip() or DEFAULT_COOKIE_NAME


# =============================================================================
# Replay
# =============================================================================

class ReplayJob(object):
    """Re-send every captured request once per user token, on a bounded thread pool.

    Results go into `store`. `on_progress(done, total)` and `on_finished(cancelled)` run on
    the Swing event thread.
    """

    def __init__(self, callbacks, store, messages, tokens, location, cookie_name, threads,
                 on_progress, on_finished):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._store = store
        self._messages = messages
        self._tokens = tokens
        self._location = location
        self._cookie_name = cookie_name
        self._threads = threads
        self._on_progress = on_progress
        self._on_finished = on_finished
        self._executor = Executors.newFixedThreadPool(threads)
        self._cancelled = False
        self._done = 0
        self._done_lock = threading.Lock()
        self.total = len(messages) * len(tokens)

    def start(self):
        for user in self._tokens:
            self._store.add_user(user)
        worker = threading.Thread(target=self._run, name="jwt-matrix-replay")
        worker.setDaemon(True)
        worker.start()

    def cancel(self):
        """Skip everything not yet sent; requests already in flight finish (one per thread)."""
        self._cancelled = True
        self._executor.shutdown()

    def _run(self):
        try:
            try:
                for msg in self._messages:
                    self._executor.execute(lambda m=msg: self._replay_message(m))
            except RejectedExecutionException:
                pass   # cancelled while submitting
            self._executor.shutdown()
            while not self._executor.awaitTermination(250, TimeUnit.MILLISECONDS):
                pass   # requests already in flight must finish before the store is reused
        finally:
            SwingUtilities.invokeLater(lambda: self._on_finished(self._cancelled))

    def _replay_message(self, msg):
        """Send one captured request once per token. Runs on a pool thread."""
        info = self._helpers.analyzeRequest(msg)
        endpoint = request_endpoint(info)
        headers = list(info.getHeaders())
        body = msg.getRequest()[info.getBodyOffset():]
        for user, token in self._tokens.items():
            if self._cancelled:
                return
            try:
                raw = self._helpers.buildHttpMessage(
                    replace_token(headers, token, self._location, self._cookie_name), body)
                result = self._callbacks.makeHttpRequest(msg.getHttpService(), raw)
                response = result.getResponse() if result is not None else None
                if response is None:
                    log("No response for %s as %s" % (endpoint, user))
                else:
                    self._store.add(endpoint, user, status_code(self._helpers, response), result)
            except Exception as e:
                log("Error replaying %s as %s: %s" % (endpoint, user, e))
            finally:
                with self._done_lock:
                    self._done += 1
                    done = self._done
                SwingUtilities.invokeLater(lambda: self._on_progress(done, self.total))


# =============================================================================
# Swing components
# =============================================================================

class _DocumentChange(DocumentListener):
    def __init__(self, callback):
        self._callback = callback

    def insertUpdate(self, event):
        self._callback()

    def removeUpdate(self, event):
        self._callback()

    def changedUpdate(self, event):
        self._callback()


def on_text_change(text_component, callback):
    text_component.getDocument().addDocumentListener(_DocumentChange(callback))


def bold_label(text):
    label = JLabel(text)
    label.setFont(label.getFont().deriveFont(Font.BOLD))
    return label


def readable_text_color(background):
    luminance = (0.299 * background.getRed() + 0.587 * background.getGreen()
                 + 0.114 * background.getBlue())
    return Color.BLACK if luminance > 140 else Color.WHITE


class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


class TokenTableModel(DefaultTableModel):
    """User -> JWT used for replay. Filled from captured traffic and editable by hand."""

    def __init__(self):
        DefaultTableModel.__init__(self, ["User", "JWT Token", "Last Seen"], 0)

    def isCellEditable(self, row, col):
        return col < 2

    def upsert(self, user, token, seen):
        for row in range(self.getRowCount()):
            if self.getValueAt(row, 0) == user:
                self.setValueAt(token, row, 1)
                self.setValueAt(seen, row, 2)
                return
        self.addRow([user, token, seen])

    def tokens(self):
        tokens = OrderedDict()
        for row in range(self.getRowCount()):
            user = (self.getValueAt(row, 0) or "").strip()
            token = (self.getValueAt(row, 1) or "").strip()
            if user and token:
                tokens[user] = token
        return tokens


class MatrixTableModel(AbstractTableModel):
    """Rows are base endpoints (method + path), expandable into their query-string variants;
    columns are users; cells show status code counts."""

    BASE, CHILD = "base", "child"

    def __init__(self):
        self._users = []
        self._counts = {}
        self._groups = OrderedDict()
        self._expanded = set()
        self._rows = []   # (kind, label endpoint, endpoints aggregated by the row)
        self._row_codes = []   # per row, per user: {code: count}

    def load(self, endpoints, users, counts):
        structure_changed = users != self._users
        self._users, self._counts = users, counts
        self._groups = group_endpoints(endpoints)
        self._expanded &= set(self._groups)
        self._rebuild_rows()
        if structure_changed:
            self.fireTableStructureChanged()
        else:
            self.fireTableDataChanged()

    def _expandable(self, base):
        return self._groups[base] != [base]

    def _rebuild_rows(self):
        rows = []
        for base, variants in self._groups.items():
            rows.append((self.BASE, base, variants))
            if base in self._expanded:
                rows.extend((self.CHILD, variant, [variant]) for variant in variants)
        self._rows = rows
        self._row_codes = [[self._aggregate(endpoints, user) for user in self._users]
                           for _, _, endpoints in rows]

    def _aggregate(self, endpoints, user):
        total = Counter()
        for endpoint in endpoints:
            total.update(self._counts.get(endpoint, {}).get(user, {}))
        return total

    def toggle(self, row):
        """Expand or collapse a base row; returns False when the row cannot expand."""
        kind, endpoint, _ = self._rows[row]
        if kind != self.BASE or not self._expandable(endpoint):
            return False
        self._expanded ^= set([endpoint])
        self._rebuild_rows()
        self.fireTableDataChanged()
        return True

    def row_key(self, row):
        return self._rows[row][:2]

    def endpoints_at(self, row):
        return self._rows[row][2]

    def label_at(self, row):
        return self._rows[row][1]

    def user_at(self, col):
        return self._users[col - 1]

    def codes_at(self, row, col):
        return self._row_codes[row][col - 1]

    def base_count(self):
        return len(self._groups)

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return 1 + len(self._users)

    def getColumnClass(self, col):
        # Status columns get their own class so only they use MatrixCellRenderer.
        return Object if col == 0 else String

    def getColumnName(self, col):
        return "Endpoint" if col == 0 else self.user_at(col)

    def getValueAt(self, row, col):
        if col > 0:
            return format_codes(self.codes_at(row, col))
        kind, endpoint, _ = self._rows[row]
        if kind == self.CHILD:
            return "    " + endpoint
        if self._expandable(endpoint):
            return ("[-] " if endpoint in self._expanded else "[+] ") + endpoint
        return endpoint


class _FilterOnlySorter(TableRowSorter):
    """Filtering without sorting: sorting would separate variant rows from their base row."""

    def isSortable(self, column):
        return False


class MatrixCellRenderer(DefaultTableCellRenderer):
    def __init__(self, settings):
        DefaultTableCellRenderer.__init__(self)
        self._settings = settings

    def getTableCellRendererComponent(self, table, value, selected, focused, row, col):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focused, row, col)
        codes = table.getModel().codes_at(table.convertRowIndexToModel(row),
                                          table.convertColumnIndexToModel(col))
        if not codes:
            rgb = self._settings.no_requests_color
        else:
            group = pick_group(codes.keys(), self._settings.code_groups)
            rgb = group[1] if group else 0xFFFFFF
        background = Color(rgb).darker() if selected else Color(rgb)
        component.setBackground(background)
        component.setForeground(readable_text_color(background))
        return component


class _MatrixMouse(MouseAdapter):
    def __init__(self, view):
        self._view = view

    def mousePressed(self, event):
        self._view.on_mouse(event)

    def mouseReleased(self, event):
        self._view.on_mouse(event)

    def mouseClicked(self, event):
        self._view.on_click(event)


class _SwatchClick(MouseAdapter):
    def __init__(self, callback):
        self._callback = callback

    def mouseClicked(self, event):
        self._callback()


class MatrixView(object):
    """Filterable matrix table with colour legend, stats and export, bound to a MatrixStore."""

    def __init__(self, extender, store, name, toolbar_controls=()):
        self._ext = extender
        self.store = store
        self._name = name
        self._refresh_lock = threading.Lock()
        self._refresh_pending = False

        self.model = MatrixTableModel()
        self.table = JTable(self.model)
        self._sorter = _FilterOnlySorter(self.model)
        self.table.setRowSorter(self._sorter)
        self.table.setDefaultRenderer(String, MatrixCellRenderer(extender.settings))
        self.table.setRowHeight(30)
        self.table.getTableHeader().setReorderingAllowed(False)
        self.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.table.addMouseListener(_MatrixMouse(self))

        self._filter = JTextField()
        on_text_change(self._filter, self._apply_filter)
        toolbar = JPanel(BorderLayout(8, 0))
        toolbar.add(JLabel("Filter endpoints: "), BorderLayout.WEST)
        toolbar.add(self._filter, BorderLayout.CENTER)
        if toolbar_controls:
            controls = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
            for control in toolbar_controls:
                controls.add(control)
            toolbar.add(controls, BorderLayout.EAST)

        self._stats = JLabel()
        self._legend = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        exports = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        exports.add(JButton("Export CSV", actionPerformed=lambda e: self._export("csv")))
        exports.add(JButton("Export JSON", actionPerformed=lambda e: self._export("json")))
        bottom = JPanel(BorderLayout())
        bottom.add(self._stats, BorderLayout.WEST)
        bottom.add(self._legend, BorderLayout.CENTER)
        bottom.add(exports, BorderLayout.EAST)

        self.component = JPanel(BorderLayout(0, 4))
        self.component.add(toolbar, BorderLayout.NORTH)
        self.component.add(JScrollPane(self.table), BorderLayout.CENTER)
        self.component.add(bottom, BorderLayout.SOUTH)
        self.rebuild_legend()
        self.refresh()

    # --- data

    def schedule_refresh(self):
        """Coalesce refreshes requested from any thread into one Swing update."""
        with self._refresh_lock:
            if self._refresh_pending:
                return
            self._refresh_pending = True
        SwingUtilities.invokeLater(self.refresh)

    def refresh(self):
        with self._refresh_lock:
            self._refresh_pending = False
        endpoints, users, counts = self.store.snapshot()
        self._keeping_selection(lambda: self.model.load(endpoints, users, counts))
        self._stats.setText("  Endpoints: %d (base: %d)   Users: %d  " % (
            len(endpoints), self.model.base_count(), len(users)))

    def _apply_filter(self):
        text = self._filter.getText().strip()
        self._sorter.setRowFilter(
            RowFilter.regexFilter("(?i)" + Pattern.quote(text), [0]) if text else None)

    def endpoints_for_rows(self, model_rows):
        endpoints = set()
        for row in model_rows:
            endpoints.update(self.model.endpoints_at(row))
        return endpoints

    def delete_endpoints(self, endpoints):
        self.store.remove(endpoints)
        self.refresh()

    def _keeping_selection(self, change):
        """Run a model change, then reselect the rows that were selected before it."""
        selected = set(self.model.row_key(self.table.convertRowIndexToModel(r))
                       for r in self.table.getSelectedRows())
        change()
        for row in range(self.model.getRowCount()):
            if self.model.row_key(row) in selected:
                view_row = self.table.convertRowIndexToView(row)
                if view_row >= 0:
                    self.table.addRowSelectionInterval(view_row, view_row)

    # --- mouse

    def on_mouse(self, event):
        if not event.isPopupTrigger():
            return
        row = self.table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        if not self.table.isRowSelected(row):
            self.table.setRowSelectionInterval(row, row)
        rows = self.table.getSelectedRows()
        # Resolve endpoints now: live traffic may reorder rows before the menu is clicked.
        endpoints = self.endpoints_for_rows([self.table.convertRowIndexToModel(r) for r in rows])
        popup = JPopupMenu()
        label = "Delete endpoint" if len(rows) == 1 else "Delete %d rows" % len(rows)
        popup.add(JMenuItem(label, actionPerformed=lambda e: self.delete_endpoints(endpoints)))
        popup.show(event.getComponent(), event.getX(), event.getY())

    def on_click(self, event):
        if not SwingUtilities.isLeftMouseButton(event):
            return
        row = self.table.rowAtPoint(event.getPoint())
        col = self.table.columnAtPoint(event.getPoint())
        if row < 0 or col < 0:
            return
        row = self.table.convertRowIndexToModel(row)
        col = self.table.convertColumnIndexToModel(col)
        if col == 0:
            if not (event.isControlDown() or event.isShiftDown()):   # those extend selection
                self._keeping_selection(lambda: self.model.toggle(row))
            return
        user = self.model.user_at(col)
        self._ext.show_messages("%s: %s as %s" % (self._name, self.model.label_at(row), user),
                                self.store.messages(self.model.endpoints_at(row), user))

    # --- legend & export

    def rebuild_legend(self):
        settings = self._ext.settings
        self._legend.removeAll()
        self._legend.add(bold_label("Legend:"))
        for index, (_, rgb, label) in enumerate(settings.code_groups):
            self._legend.add(self._swatch(rgb, label, index))
        self._legend.add(self._swatch(settings.no_requests_color, "No requests", None))
        self._legend.revalidate()
        self._legend.repaint()
        self.table.repaint()

    def _swatch(self, rgb, label, group_index):
        swatch = JLabel(label)
        swatch.setOpaque(True)
        swatch.setBackground(Color(rgb))
        swatch.setForeground(readable_text_color(Color(rgb)))
        swatch.setToolTipText("Click to change colour")
        swatch.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        swatch.addMouseListener(_SwatchClick(lambda: self._ext.choose_color(group_index)))
        return swatch

    def _export(self, fmt):
        snapshot = self.store.snapshot()
        if not snapshot[0]:
            JOptionPane.showMessageDialog(self.component, "The %s is empty." % self._name)
            return
        if fmt == "csv":
            content = matrix_to_csv(snapshot)
        else:
            content = matrix_to_json(snapshot, self._ext.settings.user_claim)
        self._ext.save_file("Save %s as %s" % (self._name, fmt.upper()), fmt, content)


class _MessageController(IMessageEditorController):
    """Gives Burp's message editors the selected message, for their context-menu actions."""

    def __init__(self):
        self.message = None

    def getHttpService(self):
        return self.message and self.message.getHttpService()

    def getRequest(self):
        return self.message and self.message.getRequest()

    def getResponse(self):
        return self.message and self.message.getResponse()


# =============================================================================
# Extension
# =============================================================================

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory,
                   IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        self.settings = Settings(callbacks)
        self.captured = MatrixStore()
        self.replayed = MatrixStore()
        self.tokens = TokenTableModel()
        self._replay_job = None
        self._build_ui()

        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)
        log("Loaded.")

    # --- Burp interfaces

    def getTabCaption(self):
        return "JWT Auth Matrix"

    def getUiComponent(self):
        return self._panel

    def extensionUnloaded(self):
        if self._replay_job is not None:
            self._replay_job.cancel()

    def processHttpMessage(self, tool_flag, is_request, message):
        if is_request or not self._listens_to(tool_flag):
            return
        try:
            if self._capture(message, persist=True):
                self.matrix_view.schedule_refresh()
        except Exception as e:
            log("Error processing message: %s" % e)

    def createMenuItems(self, invocation):
        items = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages:
            items.add(JMenuItem("Send to JWT Authorization Matrix",
                                actionPerformed=lambda e: self.send_to_matrix(list(messages))))
        return items

    # --- capture

    def _listens_to(self, tool_flag):
        cb, s = self._callbacks, self.settings
        return ((tool_flag == cb.TOOL_PROXY and s.listen_proxy)
                or (tool_flag == cb.TOOL_REPEATER and s.listen_repeater)
                or (tool_flag == cb.TOOL_INTRUDER and s.listen_intruder))

    def _capture(self, message, persist=False, url_filter=None):
        """Record a request/response carrying a JWT. Returns True when it was recorded."""
        response = message.getResponse()
        if response is None:
            return False
        info = self._helpers.analyzeRequest(message)
        if url_filter is not None and not url_filter.search(url_text(info.getUrl())):
            return False
        token = extract_token(info.getHeaders(), self.settings.location,
                              self.settings.effective_cookie_name())
        if not token:
            return False

        claim = self.settings.user_claim
        user = jwt_claim(token, claim)
        code = status_code(self._helpers, response)
        if persist:   # listener messages are transient; keep them on disk, not in memory
            message = self._callbacks.saveBuffersToTempFiles(message)
        self.captured.add(request_endpoint(info), user or "<no-%s>" % claim, code, message)
        if user:
            seen = Date().toString()
            SwingUtilities.invokeLater(lambda: self.tokens.upsert(user, token, seen))
        return True

    def send_to_matrix(self, messages, on_done=None):
        """Add selected messages to the matrix (context menu), in the background."""
        self._capture_in_background(lambda: messages, "selected messages", on_done=on_done)

    def import_history(self, url_filter=None, on_done=None):
        """Rebuild the matrix from Proxy history in the background.

        url_filter: compiled regex the full URL must match, or None for everything.
        """
        self.captured.clear()
        self._capture_in_background(self._callbacks.getProxyHistory, "Proxy history items",
                                    url_filter, on_done)

    def _capture_in_background(self, load_items, description, url_filter=None, on_done=None):
        def run():
            added = total = 0
            try:
                for item in load_items():
                    total += 1
                    try:
                        added += self._capture(item, url_filter=url_filter)
                    except Exception as e:
                        log("Skipping message: %s" % e)
                log("Added %d of %d %s (others had no JWT, no response or no URL match)."
                    % (added, total, description))
            finally:
                def finish():
                    self.matrix_view.refresh()
                    if on_done:
                        on_done()
                SwingUtilities.invokeLater(finish)

        worker = threading.Thread(target=run, name="jwt-matrix-capture")
        worker.setDaemon(True)
        worker.start()

    # --- UI

    def _build_ui(self):
        self._history_filter = JTextField(self.settings.history_url_filter, 16)
        self._history_filter.setToolTipText(
            "Regex on the full URL: only matching Proxy history requests are imported")
        on_text_change(self._history_filter, lambda: self._set(
            "history_url_filter", self._history_filter.getText()))
        self._import_button = JButton("Rebuild from Proxy history",
                                      actionPerformed=self._on_import_history)
        self.matrix_view = MatrixView(self, self.captured, "Authorization matrix", [
            JLabel("History URL regex:"), self._history_filter, self._import_button,
            JButton("Clear", actionPerformed=lambda e: self._clear_matrix()),
        ])
        self.replay_view = MatrixView(self, self.replayed, "Replay matrix")

        replay_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._build_token_panel(),
                                  self.replay_view.component)
        replay_split.setResizeWeight(0.3)

        self._tabs = JTabbedPane()
        self._tabs.addTab("Matrix", self.matrix_view.component)
        self._tabs.addTab("Replay", replay_split)
        self._tabs.addTab("Settings", self._build_settings_panel())
        self._panel = JPanel(BorderLayout())
        self._panel.add(self._tabs, BorderLayout.CENTER)

    def _set(self, name, value):
        setattr(self.settings, name, value)
        self.settings.save()

    def _build_token_panel(self):
        table = JTable(self.tokens)
        table.setAutoCreateRowSorter(True)
        table.setRowHeight(26)
        table.getColumnModel().getColumn(1).setPreferredWidth(500)

        threads = JSpinner(SpinnerNumberModel(self.settings.replay_threads, 1, MAX_REPLAY_THREADS, 1))
        threads.addChangeListener(lambda e: self._set("replay_threads", threads.getValue()))
        self._replay_button = JButton("Replay all captured requests with these tokens",
                                      actionPerformed=lambda e: self._start_replay())

        def delete_selected(event):
            rows = sorted((table.convertRowIndexToModel(r) for r in table.getSelectedRows()),
                          reverse=True)
            for row in rows:
                self.tokens.removeRow(row)

        buttons = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        buttons.add(JButton("Add row", actionPerformed=lambda e: self.tokens.addRow(["", "", ""])))
        buttons.add(JButton("Delete selected", actionPerformed=delete_selected))
        buttons.add(Box.createHorizontalStrut(20))
        buttons.add(JLabel("Threads:"))
        buttons.add(threads)
        buttons.add(self._replay_button)

        panel = JPanel(BorderLayout(0, 4))
        panel.add(bold_label("Tokens used for replay (captured automatically, editable):"),
                  BorderLayout.NORTH)
        panel.add(JScrollPane(table), BorderLayout.CENTER)
        panel.add(buttons, BorderLayout.SOUTH)
        return panel

    def _build_settings_panel(self):
        s = self.settings
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(0, 12, 12, 12))

        def section(title, description, *components):
            panel.add(Box.createVerticalStrut(16))
            for component in (bold_label(title), JLabel(description)) + components:
                component.setAlignmentX(0.0)
                panel.add(component)
                panel.add(Box.createVerticalStrut(4))

        def tool_box(label, name):
            return JCheckBox(label, getattr(s, name),
                             actionPerformed=lambda e: self._set(name, e.getSource().isSelected()))

        section("Capture", "Burp tools whose traffic feeds the matrix:",
                tool_box("Proxy", "listen_proxy"),
                tool_box("Repeater", "listen_repeater"),
                tool_box("Intruder", "listen_intruder"))

        auth = JRadioButton("Authorization header (Bearer)", s.location == LOCATION_AUTH,
                            actionPerformed=lambda e: self._set("location", LOCATION_AUTH))
        cookie = JRadioButton("Cookie named:", s.location == LOCATION_COOKIE,
                              actionPerformed=lambda e: self._set("location", LOCATION_COOKIE))
        group = ButtonGroup()
        group.add(auth)
        group.add(cookie)
        cookie_name = JTextField(s.cookie_name, 16)
        on_text_change(cookie_name, lambda: self._set("cookie_name", cookie_name.getText()))
        cookie_row = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        cookie_row.add(cookie)
        cookie_row.add(cookie_name)
        section("Token location", "Where requests carry the JWT (also used when replaying):",
                auth, cookie_row)

        claims = JComboBox([s.user_claim] + [c for c in ("sub", "email", "username", "id", "user_id")
                                             if c != s.user_claim])
        claims.setEditable(True)
        claims.setMaximumSize(Dimension(300, 28))
        # Fires on selection, Enter and focus loss; never applied half-typed.
        claims.addActionListener(lambda e: self._set(
            "user_claim", unicode(claims.getSelectedItem() or "").strip() or "sub"))
        section("User claim", "JWT claim identifying the user (dots for nested claims, e.g. "
                "user.email). Applies to new captures; rebuild from history to re-group.",
                claims)

        section("Colours", "Status code groups colour the cells. Click a legend swatch to "
                "change one colour.",
                JButton("Edit code groups...", actionPerformed=lambda e: self._edit_code_groups()))

        panel.add(Box.createVerticalGlue())
        wrapper = JPanel(BorderLayout())
        wrapper.add(panel, BorderLayout.NORTH)
        scroll = JScrollPane(wrapper)
        scroll.setBorder(None)
        return scroll

    # --- actions

    def _clear_matrix(self):
        self.captured.clear()
        self.matrix_view.refresh()

    def _on_import_history(self, event):
        pattern = self._history_filter.getText().strip()
        try:
            url_filter = re.compile(pattern) if pattern else None
        except re.error as e:
            JOptionPane.showMessageDialog(self._panel, "Invalid URL regex: %s" % e,
                                          EXTENSION_NAME, JOptionPane.ERROR_MESSAGE)
            return
        self._import_button.setEnabled(False)
        self.import_history(url_filter, on_done=lambda: self._import_button.setEnabled(True))

    def _start_replay(self):
        tokens = self.tokens.tokens()
        messages = self.captured.all_messages()
        if not tokens or not messages:
            JOptionPane.showMessageDialog(self._panel, "Replay needs captured requests and at "
                                          "least one user with a token.", EXTENSION_NAME,
                                          JOptionPane.INFORMATION_MESSAGE)
            return

        window = JFrame("Replaying requests...")
        window.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE)

        def on_progress(done, total):
            progress.setValue(done)
            progress.setString("%d / %d" % (done, total))
            self.replay_view.schedule_refresh()

        def on_finished(cancelled):
            window.dispose()
            self._replay_job = None
            self._replay_button.setEnabled(True)
            self.replay_view.refresh()
            log("Replay %s." % ("cancelled" if cancelled else "finished"))

        self.replayed.clear()
        job = self._replay_job = ReplayJob(
            self._callbacks, self.replayed, messages, tokens, self.settings.location,
            self.settings.effective_cookie_name(), self.settings.replay_threads,
            on_progress, on_finished)
        progress = JProgressBar(0, job.total)
        progress.setStringPainted(True)

        cancel_row = JPanel(FlowLayout(FlowLayout.RIGHT))
        cancel_row.add(JButton("Cancel", actionPerformed=lambda e: job.cancel()))
        window.add(progress, BorderLayout.CENTER)
        window.add(cancel_row, BorderLayout.SOUTH)
        window.setSize(420, 110)
        window.setLocationRelativeTo(self._panel)
        window.setVisible(True)

        self._replay_button.setEnabled(False)
        self._tabs.setSelectedIndex(1)
        job.start()

    def choose_color(self, group_index):
        """Recolour a code group, or the empty-cell colour when group_index is None."""
        s = self.settings
        if group_index is None:
            chosen = JColorChooser.showDialog(self._panel, "Colour for empty cells",
                                              Color(s.no_requests_color))
            if chosen is not None:
                s.no_requests_color = chosen.getRGB() & 0xFFFFFF
        else:
            pattern, rgb, label = s.code_groups[group_index]
            chosen = JColorChooser.showDialog(self._panel, "Colour for %s" % label, Color(rgb))
            if chosen is not None:
                s.code_groups[group_index] = (pattern, chosen.getRGB() & 0xFFFFFF, label)
        if chosen is not None:
            self._colors_changed()

    def _edit_code_groups(self):
        text = JTextArea(format_code_groups(self.settings.code_groups), 12, 40)
        panel = JPanel(BorderLayout(0, 6))
        panel.add(JLabel("One group per line: pattern:0xRRGGBB:label  (e.g. 2xx,5xx:0x9933cc:Mixed)"),
                  BorderLayout.NORTH)
        panel.add(JScrollPane(text), BorderLayout.CENTER)
        while JOptionPane.showConfirmDialog(self._panel, panel, "Response code groups",
                                            JOptionPane.OK_CANCEL_OPTION,
                                            JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION:
            groups, errors = parse_code_groups(text.getText())
            if not errors and groups:
                self.settings.code_groups = groups
                self._colors_changed()
                return
            JOptionPane.showMessageDialog(
                self._panel, "\n".join(errors) or "Define at least one group.",
                "Invalid code groups", JOptionPane.ERROR_MESSAGE)

    def _colors_changed(self):
        self.settings.save()
        self.matrix_view.rebuild_legend()
        self.replay_view.rebuild_legend()

    def save_file(self, title, extension, content):
        chooser = JFileChooser()
        chooser.setDialogTitle(title)
        chooser.setFileFilter(FileNameExtensionFilter(extension.upper() + " files", [extension]))
        if chooser.showSaveDialog(self._panel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith("." + extension):
            path += "." + extension
        try:
            with open(path, "wb") as out:
                out.write(content.encode("utf-8") if isinstance(content, unicode) else content)
            log("Saved %s" % path)
        except IOError as e:
            JOptionPane.showMessageDialog(self._panel, "Could not save %s: %s" % (path, e),
                                          EXTENSION_NAME, JOptionPane.ERROR_MESSAGE)

    def show_messages(self, title, messages):
        """Open a window listing messages, with Burp's request/response viewers."""
        rows = []
        for number, msg in enumerate(messages, 1):
            info = self._helpers.analyzeRequest(msg)
            status = self._helpers.analyzeResponse(msg.getResponse()).getStatusCode()
            rows.append([number, info.getMethod(), url_text(info.getUrl()), status])
        table = JTable(ReadOnlyTableModel(rows, ["#", "Method", "URL", "Status"]))
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table.getColumnModel().getColumn(2).setPreferredWidth(500)

        controller = _MessageController()
        request_viewer = self._callbacks.createMessageEditor(controller, False)
        response_viewer = self._callbacks.createMessageEditor(controller, False)

        def on_select(event):
            row = table.getSelectedRow()
            if event.getValueIsAdjusting() or row < 0:
                return
            controller.message = messages[row]
            request_viewer.setMessage(controller.message.getRequest(), True)
            response_viewer.setMessage(controller.message.getResponse(), False)

        table.getSelectionModel().addListSelectionListener(on_select)
        viewers = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, request_viewer.getComponent(),
                             response_viewer.getComponent())
        viewers.setResizeWeight(0.5)
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), viewers)
        split.setResizeWeight(0.3)

        window = JFrame("%s (%d requests)" % (title, len(messages)))
        window.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
        window.add(split)
        window.setSize(1000, 700)
        window.setLocationRelativeTo(self._panel)
        window.setVisible(True)
        if messages:
            table.setRowSelectionInterval(0, 0)
