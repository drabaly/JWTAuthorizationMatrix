# -*- coding: UTF-8 -*-
# Burp JWT Authorization Matrix extension (Jython)
# Save as JwtAuthMatrix.py and load in Burp's Extender using Jython standalone.
#
# NOTE: This is written for Burp's Jython environment.
# Tested conceptually against Burp Extender API patterns (IHttpListener + ITab).
# Adjust minor API/constant name differences if your Burp edition varies.

from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from java.lang import Object
from java.awt import BorderLayout, Dimension, Color
from javax.swing import (JPanel, JFrame, JTable, JScrollPane, JLabel,
                         JButton, JComboBox, Box, BoxLayout, SwingUtilities,
                         JSplitPane)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
import base64
import json
from collections import defaultdict, OrderedDict


class ColorCellRenderer(DefaultTableCellRenderer):
    """Custom cell renderer for coloring based on response codes."""
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        try:
            if col == 0:
                # Endpoint column (text only)
                c.setBackground(Color(0x2b, 0x2b, 0x2b))
            else:
                # Parse the value to determine color
                # value format: "200: 5, 403: 2" or "0" if no requests
                if value == "0" or value == "" or value == "No requests":
                    c.setBackground(Color(0xf3, 0x2a, 0x4c))  # red - no requests
                else:
                    # Check for success codes (2xx)
                    has_success = False
                    has_client_error = False
                    has_server_error = False
                    
                    parts = str(value).split(',')
                    for part in parts:
                        if ':' in part:
                            code = part.split(':')[0].strip()
                            if code.startswith('2'):
                                has_success = True
                            elif code.startswith('4'):
                                has_client_error = True
                            elif code.startswith('5'):
                                has_server_error = True
                    
                    # Color priority: server error > client error > success
                    if has_server_error:
                        c.setBackground(Color(0xff, 0x8c, 0x00))  # orange - server errors
                    elif has_client_error and not has_success:
                        c.setBackground(Color(0xff, 0xff, 0x66))  # yellow - only client errors
                    elif has_client_error and has_success:
                        c.setBackground(Color(0x87, 0xce, 0xeb))  # light blue - mixed
                    else:
                        c.setBackground(Color(0x38, 0x77, 0x23))  # green - only success

        except:
            c.setBackground(Color.WHITE)
        return c

class JwtMatrixModel(AbstractTableModel):
    """
    TableModel where rows = endpoints, columns = users.
    First column is 'Endpoint', others are users, cell values are response code counts.
    """
    def __init__(self, extender):
        self.extender = extender
        self.endpoints = []   # ordered list of endpoint keys
        self.users = []       # ordered list of user identifiers
        self.data = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))  # endpoint -> user -> code -> count

    # helpers to update data
    def set_matrix(self, endpoints, users, data):
        self.endpoints = endpoints
        self.users = users
        self.data = data
        self.fireTableStructureChanged()

    def update_cell(self, endpoint, user, response_code, inc=1):
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
        if user not in self.users:
            self.users.append(user)
        self.data[endpoint][user][response_code] += inc
        self.fireTableDataChanged()

    # AbstractTableModel methods
    def getRowCount(self):
        return len(self.endpoints)

    def getColumnCount(self):
        # first column is Endpoint
        return 1 + len(self.users)

    def getColumnName(self, col):
        if col == 0:
            return "Endpoint"
        else:
            return self.users[col - 1]

    def getValueAt(self, row, col):
        if row >= len(self.endpoints):
            return ""
        endpoint = self.endpoints[row]
        if col == 0:
            return endpoint
        user = self.users[col - 1]
        code_dict = self.data.get(endpoint, {}).get(user, {})
        
        if not code_dict:
            return "0"
        
        # Format: "200: 5, 403: 2"
        sorted_codes = sorted(code_dict.items())
        return ", ".join(["%s: %d" % (code, count) for code, count in sorted_codes])

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Authorization Matrix")

        # configuration defaults
        self.jwt_user_field = "sub"

        # data: endpoint -> user -> response_code -> count
        self.matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        self.endpoints_order = []
        self.users_order = []

        # --- build UI immediately so _panel exists before Burp asks for it
        self._build_ui()

        # register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        # constants
        self.TOOL_PROXY = callbacks.TOOL_PROXY
        self.TOOL_REPEATER = callbacks.TOOL_REPEATER
        self.TOOL_INTRUDER = callbacks.TOOL_INTRUDER

        print("JWT Authorization Matrix loaded – listening to Proxy/Repeater/Intruder.")

    #
    # IHttpListener
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We need both request (for JWT/endpoint) and response (for status code)
        try:
            interested = ((toolFlag & self.TOOL_PROXY) or
                          (toolFlag & self.TOOL_REPEATER) or
                          (toolFlag & self.TOOL_INTRUDER))
        except:
            # fallback if constants don't behave as expected
            interested = True

        if not interested:
            return

        # Only process responses (we'll get the request data from the same messageInfo)
        if messageIsRequest:
            return

        try:
            # Get request info
            request = messageInfo.getRequest()
            analyzed_req = self._helpers.analyzeRequest(messageInfo)
            headers = analyzed_req.getHeaders()
            url = analyzed_req.getUrl()
            method = headers[0].split(' ')[0] if headers and len(headers)>0 else "GET"
            endpoint = "%s %s" % (method, url.getPath() + (("?" + url.getQuery()) if url.getQuery() else ""))
            
            # Get response code
            response = messageInfo.getResponse()
            if response is None:
                return
            analyzed_resp = self._helpers.analyzeResponse(response)
            response_code = str(analyzed_resp.getStatusCode())
            
            # find Authorization header in request
            auth_header = None
            for h in headers:
                lower = h.lower()
                if lower.startswith("authorization:"):
                    auth_header = h
                    break
            if not auth_header:
                return
            
            # parse token
            # header looks like "Authorization: Bearer <token>"
            parts = auth_header.split(":",1)[1].strip().split()
            if len(parts) < 2:
                return
            token = parts[1].strip()
            user = self._parse_jwt_get_field(token, self.jwt_user_field)
            if user is None:
                user = "<no-%s>" % self.jwt_user_field
            
            # update internal matrix
            # ensure stable ordering
            if endpoint not in self.endpoints_order:
                self.endpoints_order.append(endpoint)
            if user not in self.users_order:
                self.users_order.append(user)
            self.matrix[endpoint][user][response_code] += 1
            
            # notify table model to update
            # UI update must be on Swing thread
            SwingUtilities.invokeLater(lambda: self._update_table_model())
        except Exception as e:
            # do not crash Burp; log for user
            print("JWT Matrix: error processing message - %s" % str(e))

    #
    # JWT parsing helper
    #
    def _parse_jwt_get_field(self, token, field):
        try:
            parts = token.split('.')
            if len(parts) < 2:
                return None
            payload_b64 = parts[1]
            # base64 urlsafe decode with padding fix
            rem = len(payload_b64) % 4
            if rem > 0:
                payload_b64 += '=' * (4 - rem)
            payload_json = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
            payload = json.loads(payload_json.decode('utf-8'))
            # allow dotted field like "user.name" optionally
            if '.' in field:
                cur = payload
                for p in field.split('.'):
                    if isinstance(cur, dict) and p in cur:
                        cur = cur[p]
                    else:
                        return None
                return str(cur)
            else:
                val = payload.get(field)
                return None if val is None else str(val)
        except Exception as e:
            # silently return None when parsing fails
            # print("JWT parse error: %s" % str(e))
            return None

    #
    # Swing UI building
    #
    def _build_ui(self):
        # top-level panel for ITab
        self._panel = JPanel(BorderLayout())

        # matrix model & table
        self.table_model = JwtMatrixModel(self)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setDefaultRenderer(Object, ColorCellRenderer())  # colorize all cells
        scroll = JScrollPane(self.table)

        # simple stats label
        self.stats_label = JLabel("Endpoints: 0    Users: 0")

        matrix_panel = JPanel(BorderLayout())
        matrix_panel.add(scroll, BorderLayout.CENTER)
        matrix_panel.add(self.stats_label, BorderLayout.SOUTH)

        # config panel
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setPreferredSize(Dimension(400, 200))
        config_panel.add(JLabel("JWT field to use as user identifier (e.g. sub, email, username):"))
        self.field_combo = JComboBox([self.jwt_user_field, "email", "username", "sub", "id"])
        # set default editable so user can type arbitrary value
        self.field_combo.setEditable(True)
        config_panel.add(self.field_combo)
        config_panel.add(Box.createVerticalStrut(10))
        parse_button = JButton("Parse Proxy History and Build Matrix", actionPerformed=self._on_parse_proxy_history)
        config_panel.add(parse_button)
        config_panel.add(Box.createVerticalStrut(10))
        clear_button = JButton("Clear Matrix", actionPerformed=self._on_clear_matrix)
        config_panel.add(clear_button)
        config_panel.add(Box.createVerticalStrut(10))
        config_panel.add(JLabel("Note: The matrix updates live for Proxy/Repeater/Intruder requests as they occur."))
        config_panel.add(Box.createVerticalStrut(10))
        config_panel.add(JLabel("<html><b>Color Legend:</b><br>" +
                               "Green = 2xx only<br>" +
                               "Light Blue = Mixed 2xx and 4xx<br>" +
                               "Yellow = 4xx only<br>" +
                               "Orange = 5xx present<br>" +
                               "Red = No requests</html>"))

        # main split: left matrix, right config
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, matrix_panel, config_panel)
        split.setDividerLocation(700)
        self._panel.add(split, BorderLayout.CENTER)

        # small header with title
        header = JLabel("<html><b>JWT Authorization Matrix (with Response Codes)</b></html>")
        self._panel.add(header, BorderLayout.NORTH)

    def _on_clear_matrix(self, event=None):
        # reset data structures
        self.matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        self.endpoints_order = []
        self.users_order = []
        SwingUtilities.invokeLater(lambda: self._update_table_model())

    def _on_parse_proxy_history(self, event=None):
        # get configured field
        try:
            chosen = self.field_combo.getEditor().getItem().strip()
            if chosen:
                self.jwt_user_field = chosen
        except:
            pass
        # fetch proxy history and process each request
        try:
            history = self._callbacks.getProxyHistory()
            # reset matrix first
            self.matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
            self.endpoints_order = []
            self.users_order = []
            for item in history:
                try:
                    # Get request info
                    analyzed_req = self._helpers.analyzeRequest(item)
                    headers = analyzed_req.getHeaders()
                    url = analyzed_req.getUrl()
                    method = headers[0].split(' ')[0] if headers and len(headers)>0 else "GET"
                    endpoint = "%s %s" % (method, url.getPath() + (("?" + url.getQuery()) if url.getQuery() else ""))
                    
                    # Get response code
                    response = item.getResponse()
                    if response is None:
                        continue
                    analyzed_resp = self._helpers.analyzeResponse(response)
                    response_code = str(analyzed_resp.getStatusCode())
                    
                    # find Authorization header
                    auth_header = None
                    for h in headers:
                        if h.lower().startswith("authorization:"):
                            auth_header = h
                            break
                    if not auth_header:
                        continue
                    parts = auth_header.split(":",1)[1].strip().split()
                    if len(parts) < 2:
                        continue
                    token = parts[1].strip()
                    user = self._parse_jwt_get_field(token, self.jwt_user_field)
                    if user is None:
                        user = "<no-%s>" % self.jwt_user_field
                    if endpoint not in self.endpoints_order:
                        self.endpoints_order.append(endpoint)
                    if user not in self.users_order:
                        self.users_order.append(user)
                    self.matrix[endpoint][user][response_code] += 1
                except Exception:
                    # skip single items on error
                    continue
            # finally update UI
            SwingUtilities.invokeLater(lambda: self._update_table_model())
        except Exception as e:
            print("Error parsing proxy history: %s" % str(e))

    def _update_table_model(self):
        # prepare ordered lists to preserve stable columns/rows
        endpoints = list(self.endpoints_order)
        users = list(self.users_order)
        # convert nested defaultdict to plain dict for model
        data = defaultdict(lambda: defaultdict(dict))
        for ep in endpoints:
            for u in users:
                data[ep][u] = dict(self.matrix.get(ep, {}).get(u, {}))
        self.table_model.set_matrix(endpoints, users, data)
        self.stats_label.setText("Endpoints: %d    Users: %d" % (len(endpoints), len(users)))

    #
    # ITab methods
    #
    def getTabCaption(self):
        return "JWT Auth Matrix"

    def getUiComponent(self):
        # Fallback if Burp queries UI before build (shouldn't happen with the above fix)
        if not hasattr(self, "_panel"):
            self._build_ui()
        return self._panel