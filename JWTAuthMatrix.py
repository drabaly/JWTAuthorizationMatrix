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
from burp import IMessageEditorController
from java.lang import Object
from java.awt import BorderLayout, Color, Dimension, Font
from javax.swing import (JPanel, JFrame, JTable, JScrollPane, JLabel, JTextArea,
                         JButton, JComboBox, Box, BoxLayout, SwingUtilities,
                         JSplitPane, JTabbedPane, JTextField, RowFilter, JCheckBox, JFileChooser, 
                         JColorChooser, JDialog, JPopupMenu, JMenuItem, ListSelectionModel, ImageIcon)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt.event import MouseAdapter
from javax.swing.tree import DefaultMutableTreeNode
import javax.swing
import base64
import json
from collections import defaultdict, OrderedDict
import re
import java.util.Date


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
    def __init__(self, extender):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender
    
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
                    c.setBackground(self.extender.color_no_requests)
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
                        c.setBackground(self.extender.color_server_error)
                    elif has_client_error and not has_success:
                        c.setBackground(self.extender.color_client_error)
                    elif has_client_error and has_success:
                        c.setBackground(self.extender.color_mixed)
                    else:
                        c.setBackground(self.extender.color_success)

        except:
            c.setBackground(Color.WHITE)
        return c

class JwtMatrixModel(AbstractTableModel):
    """
    TableModel where rows = endpoints (with expandable sub-rows for parameters), columns = users.
    First column is 'Endpoint', others are users, cell values are response code counts.
    """
    def __init__(self, extender):
        self.extender = extender
        self.endpoints = []   # ordered list of base endpoint keys (without params)
        self.endpoint_variants = {}  # base_endpoint -> list of full endpoints with params
        self.users = []       # ordered list of user identifiers
        self.data = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))  # endpoint -> user -> code -> count
        self.expanded_rows = set()  # set of base endpoints that are expanded
        self.visible_rows = []  # actual rows to display (base + expanded children)

    def _rebuild_visible_rows(self):
        """Rebuild the list of visible rows based on expansion state."""
        self.visible_rows = []
        for base_endpoint in self.endpoints:
            self.visible_rows.append(('base', base_endpoint))
            if base_endpoint in self.expanded_rows:
                # Add child rows
                variants = self.endpoint_variants.get(base_endpoint, [])
                for variant in sorted(variants):
                    if variant != base_endpoint:  # Don't duplicate if no params
                        self.visible_rows.append(('child', variant))

    def toggle_expansion(self, row):
        """Toggle expansion of a base endpoint row."""
        if row < len(self.visible_rows):
            row_type, endpoint = self.visible_rows[row]
            if row_type == 'base':
                if endpoint in self.expanded_rows:
                    self.expanded_rows.remove(endpoint)
                else:
                    self.expanded_rows.add(endpoint)
                self._rebuild_visible_rows()
                self.fireTableDataChanged()
                return True
        return False

    def is_expandable(self, row):
        """Check if a row can be expanded (has variants)."""
        if row < len(self.visible_rows):
            row_type, endpoint = self.visible_rows[row]
            if row_type == 'base':
                variants = self.endpoint_variants.get(endpoint, [])
                return len(variants) > 1 or (len(variants) == 1 and variants[0] != endpoint)
        return False

    def is_expanded(self, row):
        """Check if a row is currently expanded."""
        if row < len(self.visible_rows):
            row_type, endpoint = self.visible_rows[row]
            if row_type == 'base':
                return endpoint in self.expanded_rows
        return False

    # helpers to update data
    def set_matrix(self, endpoints, endpoint_variants, users, data):
        self.endpoints = endpoints
        self.endpoint_variants = endpoint_variants
        self.users = users
        self.data = data
        self._rebuild_visible_rows()
        self.fireTableStructureChanged()

    def update_cell(self, endpoint, user, response_code, inc=1):
        # This method is not used anymore but kept for compatibility
        pass

    # AbstractTableModel methods
    def getRowCount(self):
        return len(self.visible_rows)

    def getColumnCount(self):
        # first column is Endpoint
        return 1 + len(self.users)

    def getColumnName(self, col):
        if col == 0:
            return "Endpoint"
        else:
            return self.users[col - 1]

    def getValueAt(self, row, col):
        if row >= len(self.visible_rows):
            return ""
        
        row_type, endpoint = self.visible_rows[row]
        
        if col == 0:
            # Endpoint column
            if row_type == 'base':
                # Check if expandable
                if self.is_expandable(row):
                    icon = "[-] " if self.is_expanded(row) else "[+] "
                    return icon + endpoint
                else:
                    return endpoint
            else:  # child
                return "    " + endpoint  # Indent child rows
        
        user = self.users[col - 1]
        
        if row_type == 'base':
            # Aggregate data from all variants
            variants = self.endpoint_variants.get(endpoint, [endpoint])
            aggregated_codes = defaultdict(int)
            for variant in variants:
                code_dict = self.data.get(variant, {}).get(user, {})
                for code, count in code_dict.items():
                    aggregated_codes[code] += count
            
            if not aggregated_codes:
                return "0"
            
            sorted_codes = sorted(aggregated_codes.items())
            return ", ".join(["%s: %d" % (code, count) for code, count in sorted_codes])
        else:  # child
            # Show data for specific variant
            code_dict = self.data.get(endpoint, {}).get(user, {})
            
            if not code_dict:
                return "0"
            
            sorted_codes = sorted(code_dict.items())
            return ", ".join(["%s: %d" % (code, count) for code, count in sorted_codes])

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    
    #
    # ITab methods - implemented first for Jython compatibility
    #
    def getTabCaption(self):
        return "JWT Auth Matrix"

    def getUiComponent(self):
        return self._panel
    
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
        
        # color scheme for response codes (customizable)
        self.color_success = Color(0x38, 0x77, 0x23)      # green - 2xx only
        self.color_mixed = Color(0x87, 0xce, 0xeb)        # light blue - mixed 2xx+4xx
        self.color_client_error = Color(0xff, 0xff, 0x66) # yellow - 4xx only
        self.color_server_error = Color(0xff, 0x8c, 0x00) # orange - 5xx present
        self.color_no_requests = Color(0xf3, 0x2a, 0x4c)  # red - no requests

        # data: endpoint -> user -> response_code -> count
        self.matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        # store actual request details: endpoint -> user -> response_code -> list of IHttpRequestResponse objects
        self.request_details = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
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
            
            # Store the complete IHttpRequestResponse object
            self.request_details[endpoint][user][response_code].append(messageInfo)
            
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
        self.table.setDefaultRenderer(Object, ColorCellRenderer(self))  # colorize all cells
        
        # Add mouse listener for cell clicks
        class CellClickListener(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def mouseClicked(self, event):
                table = event.getSource()
                row = table.rowAtPoint(event.getPoint())
                col = table.columnAtPoint(event.getPoint())
                
                if col == 0:
                    # Clicked on endpoint column - toggle expansion
                    model_row = table.convertRowIndexToModel(row)
                    if self.extender.table_model.toggle_expansion(model_row):
                        return  # Expansion toggled, don't show details
                
                # Don't process clicks on endpoint column for details
                if col > 0 and row >= 0:
                    # Get actual row index (accounting for sorting/filtering)
                    model_row = table.convertRowIndexToModel(row)
                    if model_row < len(self.extender.table_model.visible_rows):
                        row_type, endpoint = self.extender.table_model.visible_rows[model_row]
                        user = self.extender.table_model.users[col - 1]
                        
                        # For base rows, show aggregated details
                        if row_type == 'base':
                            variants = self.extender.table_model.endpoint_variants.get(endpoint, [endpoint])
                            self.extender._show_aggregated_request_details(variants, user)
                        else:
                            # For child rows, show specific endpoint details
                            self.extender._show_request_details(endpoint, user)
        
        self.table.addMouseListener(CellClickListener(self))
        
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
        legend_panel.add(self._create_color_box(self.color_success, "2xx only", "success"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(self.color_mixed, "Mixed 2xx+4xx", "mixed"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(self.color_client_error, "4xx only", "client_error"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(self.color_server_error, "5xx present", "server_error"))
        legend_panel.add(Box.createHorizontalStrut(10))
        legend_panel.add(self._create_color_box(self.color_no_requests, "No requests", "no_requests"))
        legend_panel.add(Box.createHorizontalGlue())

        # Bottom panel with stats and legend
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(self.stats_label, BorderLayout.WEST)
        bottom_panel.add(legend_panel, BorderLayout.CENTER)

        matrix_panel.add(filter_panel, BorderLayout.NORTH)
        matrix_panel.add(scroll, BorderLayout.CENTER)
        matrix_panel.add(bottom_panel, BorderLayout.SOUTH)

        return matrix_panel

    def _create_color_box(self, color, label, color_type):
        """Helper to create a colored box with label for the legend."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        
        box = JLabel("   ")
        box.setOpaque(True)
        box.setBackground(color)
        box.setPreferredSize(Dimension(20, 15))
        
        # Make the color box clickable
        class ColorClickListener(MouseAdapter):
            def __init__(self, extender, color_type):
                self.extender = extender
                self.color_type = color_type
            
            def mouseClicked(self, event):
                self.extender._on_color_change(self.color_type)
        
        box.addMouseListener(ColorClickListener(self, color_type))
        box.setToolTipText("Click to change color")
        
        # Make cursor change to hand on hover
        from java.awt import Cursor
        box.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        
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
        
        # Export section
        export_label = JLabel("Export: ")
        font = export_label.getFont()
        export_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        export_label.setAlignmentX(0.0)
        config_panel.add(export_label)
        config_panel.add(Box.createVerticalStrut(10))
        
        export_csv_button = JButton("Export to CSV", actionPerformed=self._on_export_csv)
        export_csv_button.setMaximumSize(Dimension(300, 30))
        export_csv_button.setAlignmentX(0.0)
        config_panel.add(export_csv_button)
        
        config_panel.add(Box.createVerticalStrut(10))
        
        export_json_button = JButton("Export to JSON", actionPerformed=self._on_export_json)
        export_json_button.setMaximumSize(Dimension(300, 30))
        export_json_button.setAlignmentX(0.0)
        config_panel.add(export_json_button)
        
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
        info_text.setEditable(False)
        info_text.setOpaque(False)
        config_panel.add(info_text)
        
        config_panel.add(Box.createVerticalGlue())
        
        # Wrap in scroll pane
        scroll = JScrollPane(config_panel)
        scroll.setBorder(None)
        return scroll

    def _on_clear_matrix(self, event=None):
        # reset data structures
        self.matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        self.request_details = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
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
            self.request_details = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
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
                    
                    # Store the IHttpRequestResponse object
                    self.request_details[endpoint][user][response_code].append(item)
                except Exception:
                    # skip single items on error
                    continue
            # finally update UI
            SwingUtilities.invokeLater(lambda: self._update_table_model())
        except Exception as e:
            print("Error parsing proxy history: %s" % str(e))

    def _update_table_model(self):
        # prepare ordered lists to preserve stable columns/rows
        # Group endpoints by base path (without query parameters)
        endpoint_groups = defaultdict(list)  # base_endpoint -> list of full endpoints
        
        for full_endpoint in self.endpoints_order:
            # Extract base endpoint (method + path without query params)
            if '?' in full_endpoint:
                base_endpoint = full_endpoint.split('?')[0]
            else:
                base_endpoint = full_endpoint
            endpoint_groups[base_endpoint].append(full_endpoint)
        
        # Create ordered list of base endpoints
        base_endpoints = []
        seen = set()
        for full_endpoint in self.endpoints_order:
            if '?' in full_endpoint:
                base = full_endpoint.split('?')[0]
            else:
                base = full_endpoint
            if base not in seen:
                base_endpoints.append(base)
                seen.add(base)
        
        users = list(self.users_order)
        
        # Convert nested defaultdict to plain dict for model
        data = defaultdict(lambda: defaultdict(dict))
        for ep in self.endpoints_order:
            for u in users:
                data[ep][u] = dict(self.matrix.get(ep, {}).get(u, {}))
        
        self.table_model.set_matrix(base_endpoints, endpoint_groups, users, data)
        self.stats_label.setText("Endpoints: %d (Base: %d)    Users: %d" % 
                                (len(self.endpoints_order), len(base_endpoints), len(users)))
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

    def _on_color_change(self, color_type):
        """Open color picker to change a color scheme."""
        try:
            # Get current color
            current_color = None
            title = ""
            
            if color_type == "success":
                current_color = self.color_success
                title = "Choose color for 2xx responses"
            elif color_type == "mixed":
                current_color = self.color_mixed
                title = "Choose color for mixed 2xx+4xx responses"
            elif color_type == "client_error":
                current_color = self.color_client_error
                title = "Choose color for 4xx responses"
            elif color_type == "server_error":
                current_color = self.color_server_error
                title = "Choose color for 5xx responses"
            elif color_type == "no_requests":
                current_color = self.color_no_requests
                title = "Choose color for no requests"
            
            # Show color chooser
            new_color = JColorChooser.showDialog(self._panel, title, current_color)
            
            if new_color is not None:
                # Update the color
                if color_type == "success":
                    self.color_success = new_color
                elif color_type == "mixed":
                    self.color_mixed = new_color
                elif color_type == "client_error":
                    self.color_client_error = new_color
                elif color_type == "server_error":
                    self.color_server_error = new_color
                elif color_type == "no_requests":
                    self.color_no_requests = new_color
                
                # Refresh the table to apply new colors
                self.table.repaint()
                
                # Rebuild the legend with new colors
                self._rebuild_matrix_tab()
                
                print("Color updated for %s" % color_type)
        except Exception as e:
            print("Error changing color: %s" % str(e))

    def _rebuild_matrix_tab(self):
        """Rebuild the matrix tab to reflect new colors in the legend."""
        try:
            # Get the current matrix tab
            matrix_tab = self._create_matrix_tab()
            self.tabbed_pane.setComponentAt(0, matrix_tab)
        except Exception as e:
            print("Error rebuilding matrix tab: %s" % str(e))

    def _show_request_details(self, endpoint, user):
        """Show a dialog with details of all requests for a specific endpoint/user combination."""
        try:
            # Get all request details for this endpoint/user
            code_dict = self.request_details.get(endpoint, {}).get(user, {})
            
            if not code_dict:
                # No requests found
                return
            
            # Collect all IHttpRequestResponse objects
            all_requests = []
            for response_code in sorted(code_dict.keys()):
                for http_message in code_dict[response_code]:
                    all_requests.append(http_message)
            
            if not all_requests:
                return
            
            # Create dialog
            dialog = JDialog(SwingUtilities.getWindowAncestor(self._panel), "Request Details", False)
            dialog.setSize(1200, 800)
            dialog.setLocationRelativeTo(self._panel)
            
            # Create main split pane
            main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
            
            # Left side: List of requests
            left_panel = JPanel(BorderLayout())
            
            # Header info
            header = JLabel("Endpoint: %s User: %s Total Requests: %d" % 
                          (endpoint, user, len(all_requests)))
            left_panel.add(header, BorderLayout.NORTH)
            
            # Create table model for requests list
            column_names = ["#", "Response Code", "Method"]
            data = []
            
            for i, http_message in enumerate(all_requests):
                analyzed_req = self._helpers.analyzeRequest(http_message)
                headers = analyzed_req.getHeaders()
                method = headers[0].split(' ')[0] if headers and len(headers)>0 else "GET"
                
                response = http_message.getResponse()
                if response:
                    analyzed_resp = self._helpers.analyzeResponse(response)
                    response_code = str(analyzed_resp.getStatusCode())
                else:
                    response_code = "N/A"
                
                data.append([str(i + 1), response_code, method])
            
            # Create table
            from javax.swing.table import DefaultTableModel
            table_model = DefaultTableModel(data, column_names)
            requests_table = JTable(table_model)
            requests_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            
            # Create message editor controller
            message_controller = RequestDetailsController(self, all_requests)
            
            # Create request/response viewers
            request_viewer = self._callbacks.createMessageEditor(message_controller, False)
            response_viewer = self._callbacks.createMessageEditor(message_controller, False)
            
            # Right side: Request/Response viewers
            right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            
            request_panel = JPanel(BorderLayout())
            request_panel.add(JLabel("Request"), BorderLayout.NORTH)
            request_panel.add(request_viewer.getComponent(), BorderLayout.CENTER)
            
            response_panel = JPanel(BorderLayout())
            response_panel.add(JLabel("Response"), BorderLayout.NORTH)
            response_panel.add(response_viewer.getComponent(), BorderLayout.CENTER)
            
            right_split.setTopComponent(request_panel)
            right_split.setBottomComponent(response_panel)
            right_split.setDividerLocation(400)
            
            # Selection listener for the table
            class RequestSelectionListener(ListSelectionListener):
                def __init__(self, controller, req_viewer, resp_viewer, requests):
                    self.controller = controller
                    self.req_viewer = req_viewer
                    self.resp_viewer = resp_viewer
                    self.requests = requests
                
                def valueChanged(self, e):
                    if not e.getValueIsAdjusting():
                        table = e.getSource()
                        selected_row = table.getMinSelectionIndex()
                        if selected_row >= 0:
                            http_message = self.requests[selected_row]
                            self.controller.setCurrentMessage(http_message)
                            self.req_viewer.setMessage(http_message.getRequest(), True)
                            response = http_message.getResponse()
                            if response:
                                self.resp_viewer.setMessage(response, False)
                            else:
                                self.resp_viewer.setMessage(None, False)
            
            requests_table.getSelectionModel().addListSelectionListener(
                RequestSelectionListener(message_controller, request_viewer, response_viewer, all_requests))
            
            # Right-click menu for sending to other tools
            class RequestTableMouseListener(MouseAdapter):
                def __init__(self, extender, requests):
                    self.extender = extender
                    self.requests = requests
                
                def mousePressed(self, e):
                    self.maybeShowPopup(e)
                
                def mouseReleased(self, e):
                    self.maybeShowPopup(e)
                
                def maybeShowPopup(self, e):
                    if e.isPopupTrigger():
                        table = e.getSource()
                        row = table.rowAtPoint(e.getPoint())
                        if row >= 0:
                            table.setRowSelectionInterval(row, row)
                            http_message = self.requests[row]
                            popup = self.createPopupMenu(http_message)
                            popup.show(e.getComponent(), e.getX(), e.getY())
                
                def createPopupMenu(self, http_message):
                    popup = JPopupMenu()
                    
                    send_to_repeater = JMenuItem("Send to Repeater")
                    send_to_repeater.addActionListener(lambda e: self.sendToRepeater(http_message))
                    popup.add(send_to_repeater)
                    
                    send_to_intruder = JMenuItem("Send to Intruder")
                    send_to_intruder.addActionListener(lambda e: self.sendToIntruder(http_message))
                    popup.add(send_to_intruder)
                    
                    send_to_comparer = JMenuItem("Send to Comparer")
                    send_to_comparer.addActionListener(lambda e: self.sendToComparer(http_message))
                    popup.add(send_to_comparer)
                    
                    return popup
                
                def sendToRepeater(self, http_message):
                    analyzed = self.extender._helpers.analyzeRequest(http_message)
                    url = analyzed.getUrl()
                    self.extender._callbacks.sendToRepeater(
                        url.getHost(),
                        url.getPort(),
                        url.getProtocol() == "https",
                        http_message.getRequest(),
                        None
                    )
                    print("Sent request to Repeater")
                
                def sendToIntruder(self, http_message):
                    analyzed = self.extender._helpers.analyzeRequest(http_message)
                    url = analyzed.getUrl()
                    self.extender._callbacks.sendToIntruder(
                        url.getHost(),
                        url.getPort(),
                        url.getProtocol() == "https",
                        http_message.getRequest()
                    )
                    print("Sent request to Intruder")
                
                def sendToComparer(self, http_message):
                    self.extender._callbacks.sendToComparer(http_message.getRequest())
                    print("Sent request to Comparer")
            
            requests_table.addMouseListener(RequestTableMouseListener(self, all_requests))
            
            # Add table to scroll pane
            scroll = JScrollPane(requests_table)
            left_panel.add(scroll, BorderLayout.CENTER)
            
            # Set up split pane
            main_split.setLeftComponent(left_panel)
            main_split.setRightComponent(right_split)
            main_split.setDividerLocation(300)
            
            # Show dialog
            dialog.setContentPane(main_split)
            
            # Select first request by default
            if len(all_requests) > 0:
                requests_table.setRowSelectionInterval(0, 0)
            
            dialog.setVisible(True)
            
        except Exception as e:
            import traceback
            print("Error showing request details: %s" % str(e))
            traceback.print_exc()

    def _show_aggregated_request_details(self, endpoint_variants, user):
        """Show aggregated request details for multiple endpoint variants."""
        try:
            # Collect all IHttpRequestResponse objects from all variants
            all_requests = []
            for endpoint in endpoint_variants:
                code_dict = self.request_details.get(endpoint, {}).get(user, {})
                for response_code in sorted(code_dict.keys()):
                    for http_message in code_dict[response_code]:
                        all_requests.append(http_message)
            
            if not all_requests:
                return
            
            # Use the base endpoint name for the dialog title
            base_endpoint = endpoint_variants[0].split('?')[0] if endpoint_variants else "Unknown"
            
            # Create dialog
            dialog = JDialog(SwingUtilities.getWindowAncestor(self._panel), "Request Details", False)
            dialog.setSize(1200, 800)
            dialog.setLocationRelativeTo(self._panel)
            
            # Create main split pane
            main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
            
            # Left side: List of requests
            left_panel = JPanel(BorderLayout())
            
            # Header info
            header = JLabel("Endpoint: %s (all variants) User: %s Total Requests: %d" % 
                          (base_endpoint, user, len(all_requests)))
            left_panel.add(header, BorderLayout.NORTH)
            
            # Create table model for requests list
            column_names = ["#", "Response Code", "Method", "Query"]
            data = []
            
            for i, http_message in enumerate(all_requests):
                analyzed_req = self._helpers.analyzeRequest(http_message)
                headers = analyzed_req.getHeaders()
                url = analyzed_req.getUrl()
                method = headers[0].split(' ')[0] if headers and len(headers)>0 else "GET"
                query = url.getQuery() if url.getQuery() else ""
                
                response = http_message.getResponse()
                if response:
                    analyzed_resp = self._helpers.analyzeResponse(response)
                    response_code = str(analyzed_resp.getStatusCode())
                else:
                    response_code = "N/A"
                
                data.append([str(i + 1), response_code, method, query])
            
            # Create table
            from javax.swing.table import DefaultTableModel
            table_model = DefaultTableModel(data, column_names)
            requests_table = JTable(table_model)
            requests_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            
            # Create message editor controller
            message_controller = RequestDetailsController(self, all_requests)
            
            # Create request/response viewers
            request_viewer = self._callbacks.createMessageEditor(message_controller, False)
            response_viewer = self._callbacks.createMessageEditor(message_controller, False)
            
            # Right side: Request/Response viewers
            right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            
            request_panel = JPanel(BorderLayout())
            request_panel.add(JLabel("Request"), BorderLayout.NORTH)
            request_panel.add(request_viewer.getComponent(), BorderLayout.CENTER)
            
            response_panel = JPanel(BorderLayout())
            response_panel.add(JLabel("Response"), BorderLayout.NORTH)
            response_panel.add(response_viewer.getComponent(), BorderLayout.CENTER)
            
            right_split.setTopComponent(request_panel)
            right_split.setBottomComponent(response_panel)
            right_split.setDividerLocation(400)
            
            # Selection listener for the table
            class RequestSelectionListener(ListSelectionListener):
                def __init__(self, controller, req_viewer, resp_viewer, requests):
                    self.controller = controller
                    self.req_viewer = req_viewer
                    self.resp_viewer = resp_viewer
                    self.requests = requests
                
                def valueChanged(self, e):
                    if not e.getValueIsAdjusting():
                        table = e.getSource()
                        selected_row = table.getMinSelectionIndex()
                        if selected_row >= 0:
                            http_message = self.requests[selected_row]
                            self.controller.setCurrentMessage(http_message)
                            self.req_viewer.setMessage(http_message.getRequest(), True)
                            response = http_message.getResponse()
                            if response:
                                self.resp_viewer.setMessage(response, False)
                            else:
                                self.resp_viewer.setMessage(None, False)
            
            requests_table.getSelectionModel().addListSelectionListener(
                RequestSelectionListener(message_controller, request_viewer, response_viewer, all_requests))
            
            # Right-click menu for sending to other tools
            class RequestTableMouseListener(MouseAdapter):
                def __init__(self, extender, requests):
                    self.extender = extender
                    self.requests = requests
                
                def mousePressed(self, e):
                    self.maybeShowPopup(e)
                
                def mouseReleased(self, e):
                    self.maybeShowPopup(e)
                
                def maybeShowPopup(self, e):
                    if e.isPopupTrigger():
                        table = e.getSource()
                        row = table.rowAtPoint(e.getPoint())
                        if row >= 0:
                            table.setRowSelectionInterval(row, row)
                            http_message = self.requests[row]
                            popup = self.createPopupMenu(http_message)
                            popup.show(e.getComponent(), e.getX(), e.getY())
                
                def createPopupMenu(self, http_message):
                    popup = JPopupMenu()
                    
                    send_to_repeater = JMenuItem("Send to Repeater")
                    send_to_repeater.addActionListener(lambda e: self.sendToRepeater(http_message))
                    popup.add(send_to_repeater)
                    
                    send_to_intruder = JMenuItem("Send to Intruder")
                    send_to_intruder.addActionListener(lambda e: self.sendToIntruder(http_message))
                    popup.add(send_to_intruder)
                    
                    send_to_comparer = JMenuItem("Send to Comparer")
                    send_to_comparer.addActionListener(lambda e: self.sendToComparer(http_message))
                    popup.add(send_to_comparer)
                    
                    return popup
                
                def sendToRepeater(self, http_message):
                    analyzed = self.extender._helpers.analyzeRequest(http_message)
                    url = analyzed.getUrl()
                    self.extender._callbacks.sendToRepeater(
                        url.getHost(),
                        url.getPort(),
                        url.getProtocol() == "https",
                        http_message.getRequest(),
                        None
                    )
                    print("Sent request to Repeater")
                
                def sendToIntruder(self, http_message):
                    analyzed = self.extender._helpers.analyzeRequest(http_message)
                    url = analyzed.getUrl()
                    self.extender._callbacks.sendToIntruder(
                        url.getHost(),
                        url.getPort(),
                        url.getProtocol() == "https",
                        http_message.getRequest()
                    )
                    print("Sent request to Intruder")
                
                def sendToComparer(self, http_message):
                    self.extender._callbacks.sendToComparer(http_message.getRequest())
                    print("Sent request to Comparer")
            
            requests_table.addMouseListener(RequestTableMouseListener(self, all_requests))
            
            # Add table to scroll pane
            scroll = JScrollPane(requests_table)
            left_panel.add(scroll, BorderLayout.CENTER)
            
            # Set up split pane
            main_split.setLeftComponent(left_panel)
            main_split.setRightComponent(right_split)
            main_split.setDividerLocation(300)
            
            # Show dialog
            dialog.setContentPane(main_split)
            
            # Select first request by default
            if len(all_requests) > 0:
                requests_table.setRowSelectionInterval(0, 0)
            
            dialog.setVisible(True)
            
        except Exception as e:
            import traceback
            print("Error showing aggregated request details: %s" % str(e))
            traceback.print_exc()

    def _on_export_csv(self, event=None):
        """Export the matrix to CSV format."""
        try:
            # Show file chooser
            chooser = JFileChooser()
            chooser.setDialogTitle("Save Matrix as CSV")
            chooser.setFileFilter(FileNameExtensionFilter("CSV files", ["csv"]))
            result = chooser.showSaveDialog(self._panel)
            
            if result == JFileChooser.APPROVE_OPTION:
                file_path = chooser.getSelectedFile().getAbsolutePath()
                if not file_path.endswith('.csv'):
                    file_path += '.csv'
                
                # Build CSV content
                csv_lines = []
                
                # Header row
                header = ["Endpoint"] + list(self.users_order)
                csv_lines.append(",".join(['"%s"' % h.replace('"', '""') for h in header]))
                
                # Data rows
                for endpoint in self.endpoints_order:
                    row = ['"%s"' % endpoint.replace('"', '""')]
                    for user in self.users_order:
                        code_dict = self.matrix.get(endpoint, {}).get(user, {})
                        if code_dict:
                            cell_value = ", ".join(["%s: %d" % (code, count) for code, count in sorted(code_dict.items())])
                        else:
                            cell_value = "0"
                        row.append('"%s"' % cell_value.replace('"', '""'))
                    csv_lines.append(",".join(row))
                
                # Write to file
                with open(file_path, 'w') as f:
                    f.write("\n".join(csv_lines))
                
                print("Matrix exported to CSV: %s" % file_path)
        except Exception as e:
            print("Error exporting to CSV: %s" % str(e))

    def _on_export_json(self, event=None):
        """Export the matrix to JSON format."""
        try:
            # Show file chooser
            chooser = JFileChooser()
            chooser.setDialogTitle("Save Matrix as JSON")
            chooser.setFileFilter(FileNameExtensionFilter("JSON files", ["json"]))
            result = chooser.showSaveDialog(self._panel)
            
            if result == JFileChooser.APPROVE_OPTION:
                file_path = chooser.getSelectedFile().getAbsolutePath()
                if not file_path.endswith('.json'):
                    file_path += '.json'
                
                # Build JSON structure
                export_data = {
                    "jwt_field": self.jwt_user_field,
                    "users": list(self.users_order),
                    "endpoints": []
                }
                
                for endpoint in self.endpoints_order:
                    endpoint_data = {
                        "endpoint": endpoint,
                        "users": {}
                    }
                    for user in self.users_order:
                        code_dict = self.matrix.get(endpoint, {}).get(user, {})
                        if code_dict:
                            endpoint_data["users"][user] = dict(code_dict)
                        else:
                            endpoint_data["users"][user] = {}
                    export_data["endpoints"].append(endpoint_data)
                
                # Write to file
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                print("Matrix exported to JSON: %s" % file_path)
        except Exception as e:
            print("Error exporting to JSON: %s" % str(e))

class RequestDetailsController(IMessageEditorController):
    """Controller for the message editors in the request details dialog."""
    def __init__(self, extender, requests):
        self.extender = extender
        self.requests = requests
        self.current_message = None
    
    def setCurrentMessage(self, message):
        self.current_message = message
    
    def getHttpService(self):
        if self.current_message:
            return self.current_message.getHttpService()
        return None
    
    def getRequest(self):
        if self.current_message:
            return self.current_message.getRequest()
        return None
    
    def getResponse(self):
        if self.current_message:
            return self.current_message.getResponse()
        return None
