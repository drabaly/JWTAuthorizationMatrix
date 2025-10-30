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
from java.awt import BorderLayout, Color, Dimension, Font
from javax.swing import (JPanel, JFrame, JTable, JScrollPane, JLabel, JTextArea,
                         JButton, JComboBox, Box, BoxLayout, SwingUtilities,
                         JSplitPane, JTabbedPane, JTextField, RowFilter, JCheckBox)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import DocumentListener
import javax.swing
import base64
import json
from collections import defaultdict, OrderedDict
import re


class FilterListener(DocumentListener):
    """Listener to filter table rows based on text input."""
    def __init__(self, extender):
        self.extender = extender
    
    def insertUpdate(self, e):
        self.extender._apply_filter()
    
    def removeUpdate(self, e):
        self.extender._apply_filter()
    
    def changedUpdate(self, e):
        self.extender._apply_filter()


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
        
        # tool listening flags (enabled by default)
        self.listen_proxy = True
        self.listen_repeater = True
        self.listen_intruder = True

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
            # Check if we should listen to this tool based on user preferences
            should_listen = False
            if (toolFlag & self.TOOL_PROXY) and self.listen_proxy:
                should_listen = True
            if (toolFlag & self.TOOL_REPEATER) and self.listen_repeater:
                should_listen = True
            if (toolFlag & self.TOOL_INTRUDER) and self.listen_intruder:
                should_listen = True
        except:
            # fallback if constants don't behave as expected
            should_listen = True

        if not should_listen:
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
            
            # Also update listening preferences in case checkboxes changed
            self._update_listening_preferences()
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

        # Create tabbed pane
        self.tabbed_pane = JTabbedPane()

        # === Matrix Tab ===
        matrix_tab = self._create_matrix_tab()
        self.tabbed_pane.addTab("Authorization Matrix", matrix_tab)

        # === Configuration Tab ===
        config_tab = self._create_config_tab()
        self.tabbed_pane.addTab("Configuration", config_tab)

        # Add tabbed pane to main panel
        self._panel.add(self.tabbed_pane, BorderLayout.CENTER)

    def _create_matrix_tab(self):
        """Create the matrix visualization tab."""
        matrix_panel = JPanel(BorderLayout())

        # Filter panel at the top
        filter_panel = JPanel(BorderLayout())
        filter_panel.add(JLabel("Filter endpoints: "), BorderLayout.WEST)
        self.filter_field = JTextField()
        self.filter_field.getDocument().addDocumentListener(FilterListener(self))
        filter_panel.add(self.filter_field, BorderLayout.CENTER)

        # matrix model & table
        self.table_model = JwtMatrixModel(self)
        self.table = JTable(self.table_model)
        self.table_sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.table_sorter)
        self.table.setDefaultRenderer(Object, ColorCellRenderer())  # colorize all cells
        scroll = JScrollPane(self.table)

        # simple stats label
        self.stats_label = JLabel("Endpoints: 0    Users: 0")

        # Color legend panel
        legend_panel = JPanel()
        legend_panel.setLayout(BoxLayout(legend_panel, BoxLayout.X_AXIS))
        label = JLabel("    Color Legend: ")
        font = label.getFont()
        label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        legend_panel.add(label)
        legend_panel.add(self._create_color_box(Color(0x38, 0x77, 0x23), "2xx only"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(Color(0x87, 0xce, 0xeb), "Mixed 2xx+4xx"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(Color(0xff, 0xff, 0x66), "4xx only"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(Color(0xff, 0x8c, 0x00), "5xx present"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(Color(0xf3, 0x2a, 0x4c), "No requests"))
        legend_panel.add(Box.createHorizontalGlue())

        # Bottom panel with stats and legend
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(self.stats_label, BorderLayout.WEST)
        bottom_panel.add(legend_panel, BorderLayout.CENTER)

        matrix_panel.add(filter_panel, BorderLayout.NORTH)
        matrix_panel.add(scroll, BorderLayout.CENTER)
        matrix_panel.add(bottom_panel, BorderLayout.SOUTH)

        return matrix_panel

    def _create_color_box(self, color, label):
        """Helper to create a colored box with label for the legend."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        
        box = JLabel("   ")
        box.setOpaque(True)
        box.setBackground(color)
        box.setPreferredSize(Dimension(20, 15))
        
        panel.add(box)
        panel.add(Box.createHorizontalStrut(5))
        panel.add(JLabel(label))
        
        return panel

    def _create_config_tab(self):
        """Create the configuration tab."""
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        
        # Add padding
        config_panel.add(Box.createVerticalStrut(20))
        
        # Listening Tools Section
        tools_label = JLabel("Listen to Tools: ")
        font = tools_label.getFont()
        tools_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        tools_label.setAlignmentX(0.0)
        config_panel.add(tools_label)
        config_panel.add(Box.createVerticalStrut(5))
        
        tools_desc = JLabel("Select which Burp tools to monitor for JWT requests:")
        tools_desc.setAlignmentX(0.0)
        config_panel.add(tools_desc)
        config_panel.add(Box.createVerticalStrut(10))
        
        # Create a sub-panel for checkboxes with left padding
        checkbox_panel = JPanel()
        checkbox_panel.setLayout(BoxLayout(checkbox_panel, BoxLayout.Y_AXIS))
        checkbox_panel.setAlignmentX(0.0)
        
        self.proxy_checkbox = JCheckBox("Proxy", self.listen_proxy, actionPerformed=lambda e: self._update_listening_preferences())
        self.proxy_checkbox.setAlignmentX(0.0)
        checkbox_panel.add(self.proxy_checkbox)
        checkbox_panel.add(Box.createVerticalStrut(5))
        
        self.repeater_checkbox = JCheckBox("Repeater", self.listen_repeater, actionPerformed=lambda e: self._update_listening_preferences())
        self.repeater_checkbox.setAlignmentX(0.0)
        checkbox_panel.add(self.repeater_checkbox)
        checkbox_panel.add(Box.createVerticalStrut(5))
        
        self.intruder_checkbox = JCheckBox("Intruder", self.listen_intruder, actionPerformed=lambda e: self._update_listening_preferences())
        self.intruder_checkbox.setAlignmentX(0.0)
        checkbox_panel.add(self.intruder_checkbox)
        
        config_panel.add(checkbox_panel)
        
        config_panel.add(Box.createVerticalStrut(30))
        
        # JWT Field Configuration
        field_label = JLabel("JWT User Identifier Field: ")
        font = field_label.getFont()
        field_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        field_label.setAlignmentX(0.0)
        config_panel.add(field_label)
        config_panel.add(Box.createVerticalStrut(5))
        
        field_desc = JLabel("Specify which JWT claim field to use as the user identifier:")
        field_desc.setAlignmentX(0.0)
        config_panel.add(field_desc)
        config_panel.add(Box.createVerticalStrut(5))
        
        self.field_combo = JComboBox([self.jwt_user_field, "email", "username", "sub", "id", "user_id"])
        self.field_combo.setEditable(True)
        self.field_combo.setMaximumSize(Dimension(300, 25))
        self.field_combo.setAlignmentX(0.0)
        config_panel.add(self.field_combo)
        
        config_panel.add(Box.createVerticalStrut(10))
        
        update_field_button = JButton("Update JWT Field", actionPerformed=self._on_update_jwt_field)
        update_field_button.setMaximumSize(Dimension(300, 30))
        update_field_button.setAlignmentX(0.0)
        config_panel.add(update_field_button)
        
        config_panel.add(Box.createVerticalStrut(30))
        
        # Actions section
        actions_label = JLabel("Actions: ")
        font = actions_label.getFont()
        actions_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        actions_label.setAlignmentX(0.0)
        config_panel.add(actions_label)
        config_panel.add(Box.createVerticalStrut(10))
        
        parse_button = JButton("Parse Proxy History and Build Matrix", actionPerformed=self._on_parse_proxy_history)
        parse_button.setMaximumSize(Dimension(300, 30))
        parse_button.setAlignmentX(0.0)
        config_panel.add(parse_button)
        
        config_panel.add(Box.createVerticalStrut(10))
        
        clear_button = JButton("Clear Matrix", actionPerformed=self._on_clear_matrix)
        clear_button.setMaximumSize(Dimension(300, 30))
        clear_button.setAlignmentX(0.0)
        config_panel.add(clear_button)
        
        config_panel.add(Box.createVerticalStrut(30))
        
        # Info section
        info_label = JLabel("Information: ")
        font = info_label.getFont()
        info_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        info_label.setAlignmentX(0.0)
        config_panel.add(info_label)
        config_panel.add(Box.createVerticalStrut(5))
        
        info_text = JTextArea("The matrix updates live as requests pass through:\n" +
                          "* Proxy\n" +
                          "* Repeater\n" +
                          "* Intruder\n\n" +
                          "Each cell shows HTTP response codes and their counts.\n" +
                          "Use this to identify authorization issues and access patterns.")
        info_text.setAlignmentX(0.0)
        config_panel.add(info_text)
        
        config_panel.add(Box.createVerticalGlue())
        
        # Wrap in scroll pane
        scroll = JScrollPane(config_panel)
        scroll.setBorder(None)
        return scroll

    def _on_clear_matrix(self, event=None):
        # reset data structures
        self.matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        self.endpoints_order = []
        self.users_order = []
        SwingUtilities.invokeLater(lambda: self._update_table_model())

    def _on_parse_proxy_history(self, event=None):
        # Update listening preferences from checkboxes
        self._update_listening_preferences()
        
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
        # Re-apply filter after model update
        self._apply_filter()

    def _apply_filter(self):
        """Apply the filter to the table based on the filter text field."""
        try:
            filter_text = self.filter_field.getText().strip()
            if not filter_text:
                # No filter, show all rows
                self.table_sorter.setRowFilter(None)
            else:
                # Create a case-insensitive regex filter for the endpoint column (column 0)
                self.table_sorter.setRowFilter(javax.swing.RowFilter.regexFilter("(?i)" + re.escape(filter_text), 0))
        except Exception as e:
            # If regex is invalid, show all rows
            print("Filter error: %s" % str(e))
            self.table_sorter.setRowFilter(None)

    def _update_listening_preferences(self):
        """Update listening preferences from checkboxes."""
        try:
            self.listen_proxy = self.proxy_checkbox.isSelected()
            self.listen_repeater = self.repeater_checkbox.isSelected()
            self.listen_intruder = self.intruder_checkbox.isSelected()
        except:
            pass

    def _on_update_jwt_field(self, event=None):
        """Update the JWT field from the combo box."""
        try:
            chosen = self.field_combo.getEditor().getItem().strip()
            if chosen:
                old_field = self.jwt_user_field
                self.jwt_user_field = chosen
                print("JWT field updated from '%s' to '%s'" % (old_field, chosen))
                print("Note: This will apply to new requests. To rebuild the matrix with the new field, click 'Parse Proxy History'.")
        except Exception as e:
            print("Error updating JWT field: %s" % str(e))

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