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
from burp import IContextMenuFactory
from java.lang import Object, Thread, Runnable
from java.util.concurrent import Executors, TimeUnit, Callable
from java.util.concurrent.atomic import AtomicInteger
from java.util.concurrent.locks import ReentrantLock
from java.awt import BorderLayout, Color, Dimension, Font
from javax.swing import (JPanel, JFrame, JTable, JScrollPane, JLabel, JTextArea,
                         JButton, JComboBox, Box, BoxLayout, SwingUtilities,
                         JSplitPane, JTabbedPane, JTextField, RowFilter, JCheckBox, JFileChooser, 
                         JColorChooser, JDialog, JPopupMenu, JMenuItem, ListSelectionModel, ImageIcon,
                         JProgressBar, WindowConstants)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter, DefaultTableModel
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt.event import MouseAdapter, MouseEvent
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing import ButtonGroup, JRadioButton
import javax.swing
import base64
import json
from collections import defaultdict, OrderedDict
import re
import java.util.Date
from java.util import ArrayList


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
                c.setBackground(DefaultTableCellRenderer().getBackground())  # keep default background for endpoint column
            else:
                # Parse the value to determine color
                # value format: "200: 5, 403: 2" or "0" if no requests
                if value == "0" or value == "" or value == "No requests":
                    c.setBackground(self.extender.color_no_requests_group[0])
                else:
                    # Extract all codes present in this cell
                    codes = []
                    parts = str(value).split(',')
                    for part in parts:
                        if ':' in part:
                            code = part.split(':')[0].strip()
                            codes.append(code)
                    
                    # Find the best matching group (prioritize more specific patterns)
                    best_match = None
                    best_specificity = -1
                    last_matched_group = None  # Fallback to last matching group
                    
                    for group_pattern, (color, label) in self.extender.code_color_groups.items():
                        # Check if codes match this group pattern (all codes must match)
                        if self.extender._matches_code_group_pattern(codes, group_pattern):
                            # More specific patterns (with commas) get higher priority
                            specificity = group_pattern.count(',')
                            if specificity > best_specificity:
                                best_specificity = specificity
                                best_match = group_pattern
                            # Track the last matched group as fallback
                            last_matched_group = group_pattern
                        # Also track if ANY code matches this group (for fallback)
                        elif any(self.extender._matches_code_pattern(code, group_pattern) for code in codes):
                            last_matched_group = group_pattern
                    
                    if best_match:
                        c.setBackground(self.extender.code_color_groups[best_match][0])
                    elif last_matched_group:
                        # Fallback: use the last matched group's color
                        c.setBackground(self.extender.code_color_groups[last_matched_group][0])
                    else:
                        c.setBackground(Color.WHITE)

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

class ReplayTaskCallable(Callable):
    """Callable wrapper for replaying a single request with a specific token."""
    def __init__(self, extender, req, endpoint, user, token, headers, analyzed_req, progress, progress_counter, total_requests, replay_lock):
        self.extender = extender
        self.req = req
        self.endpoint = endpoint
        self.user = user
        self.token = token
        self.headers = headers
        self.analyzed_req = analyzed_req
        self.progress = progress
        self.progress_counter = progress_counter
        self.total_requests = total_requests
        self.replay_lock = replay_lock
    
    def call(self):
        """Execute the replay task."""
        try:
            # Create new request with replaced JWT
            new_headers = []
            if self.extender.jwt_location_auth.isSelected():
                # Replace Authorization header
                auth_found = False
                for header in self.headers:
                    if header.lower().startswith("authorization:"):
                        new_headers.append("Authorization: Bearer %s" % self.token)
                        auth_found = True
                    else:
                        new_headers.append(header)
                if not auth_found:
                    new_headers.append("Authorization: Bearer %s" % self.token)
            else:
                # Replace Cookie
                cookie_name = self.extender.cookie_name_field.getText().strip() or "jwt"
                cookie_found = False
                for header in self.headers:
                    if header.lower().startswith("cookie:"):
                        cookies = header.split(":",1)[1].strip().split(";")
                        new_cookies = []
                        for cookie in cookies:
                            if "=" in cookie:
                                name, value = cookie.split("=", 1)
                                if name.strip() == cookie_name:
                                    new_cookies.append("%s=%s" % (name.strip(), self.token))
                                    cookie_found = True
                                else:
                                    new_cookies.append(cookie)
                        new_headers.append("Cookie: %s" % "; ".join(new_cookies))
                    else:
                        new_headers.append(header)
                if not cookie_found:
                    new_headers.append("Cookie: %s=%s" % (cookie_name, self.token))

            # Build new request
            body = self.req.getRequest()[self.analyzed_req.getBodyOffset():]
            new_request = self.extender._helpers.buildHttpMessage(new_headers, body)

            # Make request
            response = self.extender._callbacks.makeHttpRequest(
                self.req.getHttpService(),
                new_request
            )

            # Skip if makeHttpRequest returned None or no response bytes
            if response is None:
                print("No response received for request to %s with user %s" % (self.endpoint, self.user))
            else:
                resp_bytes = None
                try:
                    resp_bytes = response.getResponse()
                except:
                    resp_bytes = None
                
                if resp_bytes is None:
                    print("No response bytes for request to %s with user %s" % (self.endpoint, self.user))
                else:
                    # Process response
                    analyzed_resp = self.extender._helpers.analyzeResponse(response.getResponse())
                    response_code = str(analyzed_resp.getStatusCode())

                    # Update replay matrix (thread-safe with lock)
                    self.replay_lock.lock()
                    try:
                        self.extender.replay_matrix[self.endpoint][self.user][response_code] += 1
                        self.extender.replay_request_details[self.endpoint][self.user][response_code].append(response)
                    finally:
                        self.replay_lock.unlock()
        
        except Exception as e:
            print("Error replaying request to %s with user %s: %s" % (self.endpoint, self.user, str(e)))
        
        finally:
            # Update progress counter
            self.progress_counter.incrementAndGet()
            current = self.progress_counter.get()
            SwingUtilities.invokeLater(lambda: self.extender._update_replay_progress(self.progress, current, self.total_requests))
        
        return None

class CellClickListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
    
    def mouseClicked(self, event):
        table = event.getSource()
        row = table.rowAtPoint(event.getPoint())
        col = table.columnAtPoint(event.getPoint())
        
        # Handle right click
        if event.getButton() == MouseEvent.BUTTON3 and row >= 0:  # BUTTON3 is right click
            # Ensure the clicked row is selected
            if not table.isRowSelected(row):
                table.setRowSelectionInterval(row, row)
            
            # Get all selected rows
            selected_rows = table.getSelectedRows()
            
            if len(selected_rows) > 0:
                # Create popup menu
                popup = JPopupMenu()
                
                if len(selected_rows) == 1:
                    deleteItem = JMenuItem("Delete endpoint")
                else:
                    deleteItem = JMenuItem("Delete %d endpoints" % len(selected_rows))
                
                deleteItem.addActionListener(lambda e: self.deleteMultipleEndpoints(table, selected_rows))
                popup.add(deleteItem)
                
                # Show popup menu
                popup.show(event.getComponent(), event.getX(), event.getY())
                return
        
        # Handle left click (existing logic)
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

    def deleteMultipleEndpoints(self, table, selected_rows):
        """Delete multiple selected endpoints."""
        try:
            # Collect all endpoints to delete from selected rows
            endpoints_to_delete = set()
            row_types_to_delete = {}
            
            for row in selected_rows:
                model_row = table.convertRowIndexToModel(row)
                if model_row < len(self.extender.table_model.visible_rows):
                    row_type, endpoint = self.extender.table_model.visible_rows[model_row]
                    endpoints_to_delete.add(endpoint)
                    row_types_to_delete[endpoint] = row_type
            
            # Delete each endpoint
            for endpoint in endpoints_to_delete:
                row_type = row_types_to_delete[endpoint]
                self._delete_single_endpoint(endpoint, row_type)
            
            # Update the table once after all deletions
            SwingUtilities.invokeLater(lambda: self.extender._update_table_model())
            
        except Exception as e:
            print("Error deleting endpoints: %s" % str(e))

    def _delete_single_endpoint(self, endpoint, row_type):
        """Delete a single endpoint from data structures."""
        try:
            if row_type == 'base':
                # Delete base endpoint and all its variants
                variants = self.extender.table_model.endpoint_variants.get(endpoint, [endpoint])
                for variant in variants:
                    # Remove from data structures
                    if variant in self.extender.matrix:
                        del self.extender.matrix[variant]
                    if variant in self.extender.request_details:
                        del self.extender.request_details[variant]
                    if variant in self.extender.endpoints_order:
                        self.extender.endpoints_order.remove(variant)
            else:
                # Delete specific variant only
                if endpoint in self.extender.matrix:
                    del self.extender.matrix[endpoint]
                if endpoint in self.extender.request_details:
                    del self.extender.request_details[endpoint]
                if endpoint in self.extender.endpoints_order:
                    self.extender.endpoints_order.remove(endpoint)
        except Exception as e:
            print("Error deleting single endpoint: %s" % str(e))

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
        
        # replay thread count setting
        self.replay_thread_count = 5
        
        # tool listening flags (enabled by default)
        self.listen_proxy = True
        self.listen_repeater = True
        self.listen_intruder = True
        
        # color scheme for response codes (customizable)
        # Keep legacy color references for backward compatibility
        self.color_success = Color(0x38, 0x77, 0x23)      # green
        self.color_mixed = Color(0x87, 0xce, 0xeb)        # light blue
        self.color_client_error = Color(0xff, 0xff, 0x66) # yellow
        self.color_server_error = Color(0xff, 0x8c, 0x00) # orange
        self.color_no_requests = Color(0xf3, 0x2a, 0x4c)  # red
        
        # code-to-color mappings: code_pattern -> (color, label)
        # Patterns can be individual codes (200) or ranges (2xx, 4xx)
        self.code_color_groups = OrderedDict([
            ('2xx', (Color(0x38, 0x77, 0x23), 'Success (2xx)')),
            ('3xx', (Color(0x87, 0xce, 0xeb), 'Redirect (3xx)')),
            ('4xx', (Color(0xff, 0xff, 0x66), 'Client Error (4xx)')),
            ('5xx', (Color(0xff, 0x8c, 0x00), 'Server Error (5xx)')),
        ])
        self.color_no_requests_group = (Color(0x33, 0x33, 0x33), 'No Requests')

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
        callbacks.registerContextMenuFactory(JwtMatrixContextMenu(self))

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
            
            token = None
            if self.jwt_location_auth.isSelected():
                # Look in Authorization header
                for h in headers:
                    if h.lower().startswith("authorization:"):
                        parts = h.split(":",1)[1].strip().split()
                        if len(parts) >= 2 and parts[0].lower() == "bearer":
                            token = parts[1].strip()
                            break
            else:
                # Look in Cookies
                cookie_name = self.cookie_name_field.getText().strip()
                if not cookie_name:
                    cookie_name = "jwt"
                
                for h in headers:
                    if h.lower().startswith("cookie:"):
                        cookies = h.split(":",1)[1].strip().split(";")
                        for cookie in cookies:
                            if "=" in cookie:
                                name, value = cookie.split("=", 1)
                                if name.strip() == cookie_name:
                                    token = value.strip()
                                    break
                        if token:
                            break
            
            if not token:
                return
            
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
            
            # Update JWT table if we have a valid user and token
            if user and token and not user.startswith("<no-"):
                self._update_jwt_table(user, token)
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
        
        # === Replay Tab ===
        replay_tab = self._create_replay_matrix_tab()
        self.tabbed_pane.addTab("Replay Matrix", replay_tab)

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
        
        # Increase row height for matrix table
        self.table.setRowHeight(30)  # Set default row height
        self.table.getTableHeader().setPreferredSize(Dimension(self.table.getTableHeader().getPreferredSize().width, 25))

        # Enable multiple row selection
        self.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        # Add mouse listener for cell clicks
        
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
        
        # Add color boxes for each code group
        for group_pattern, (color, group_label) in self.code_color_groups.items():
            legend_panel.add(self._create_color_box(color, group_label, group_pattern))
            legend_panel.add(Box.createHorizontalStrut(10))
        
        # Add no requests color box
        legend_panel.add(self._create_color_box(self.color_no_requests_group[0], self.color_no_requests_group[1], "no_requests"))
        legend_panel.add(Box.createHorizontalGlue())
        
        # Store reference for legend rebuilding
        self.legend_panel_ref = legend_panel

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

    def _rebuild_legend(self):
        """Rebuild the legend panel with current code groups."""
        try:
            # Find the legend panel in the bottom_panel (it's in CENTER)
            # The matrix_panel is in tabbed_pane, and bottom_panel is in SOUTH
            # We need to find and update the legend_panel component
            if hasattr(self, 'legend_panel_ref'):
                # Clear old components
                self.legend_panel_ref.removeAll()
                
                # Rebuild legend
                label = JLabel("    Color Legend: ")
                font = label.getFont()
                label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
                self.legend_panel_ref.add(label)
                
                # Add color boxes for each code group
                for group_pattern, (color, group_label) in self.code_color_groups.items():
                    self.legend_panel_ref.add(self._create_color_box(color, group_label, group_pattern))
                    self.legend_panel_ref.add(Box.createHorizontalStrut(10))
                
                # Add no requests color box
                self.legend_panel_ref.add(self._create_color_box(self.color_no_requests_group[0], self.color_no_requests_group[1], "no_requests"))
                self.legend_panel_ref.add(Box.createHorizontalGlue())
                
                self.legend_panel_ref.revalidate()
                self.legend_panel_ref.repaint()
        except Exception as e:
            print("Error rebuilding legend: %s" % str(e))

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
        
        # JWT Location Configuration
        location_label = JLabel("JWT Token Location: ")
        font = location_label.getFont()
        location_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        location_label.setAlignmentX(0.0)
        config_panel.add(location_label)
        config_panel.add(Box.createVerticalStrut(5))
        
        location_desc = JLabel("Specify where to look for the JWT token:")
        location_desc.setAlignmentX(0.0)
        config_panel.add(location_desc)
        config_panel.add(Box.createVerticalStrut(10))
        
        # Create radio buttons
        self.jwt_location_auth = JRadioButton("Authorization Header (Bearer token)", True)
        self.jwt_location_auth.setAlignmentX(0.0)
        self.jwt_location_cookie = JRadioButton("Cookie", False)
        self.jwt_location_cookie.setAlignmentX(0.0)
        
        # Cookie name field
        cookie_panel = JPanel()
        cookie_panel.setLayout(BoxLayout(cookie_panel, BoxLayout.X_AXIS))
        cookie_panel.setAlignmentX(0.0)
        self.cookie_name_field = JTextField("jwt", 20)
        self.cookie_name_field.setMaximumSize(Dimension(200, 25))
        cookie_panel.add(Box.createHorizontalStrut(20))
        cookie_panel.add(JLabel("Cookie name: "))
        cookie_panel.add(self.cookie_name_field)
        cookie_panel.add(Box.createHorizontalGlue())
        
        # Group radio buttons
        button_group = ButtonGroup()
        button_group.add(self.jwt_location_auth)
        button_group.add(self.jwt_location_cookie)
        
        config_panel.add(self.jwt_location_auth)
        config_panel.add(Box.createVerticalStrut(5))
        config_panel.add(self.jwt_location_cookie)
        config_panel.add(cookie_panel)
        
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
        
        # Code Groups Configuration
        groups_label = JLabel("Response Code Groups: ")
        font = groups_label.getFont()
        groups_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        groups_label.setAlignmentX(0.0)
        config_panel.add(groups_label)
        config_panel.add(Box.createVerticalStrut(5))
        
        groups_desc = JLabel("Manage color-coded response code groupings:")
        groups_desc.setAlignmentX(0.0)
        config_panel.add(groups_desc)
        config_panel.add(Box.createVerticalStrut(10))
        
        manage_groups_button = JButton("Manage Code Groups", actionPerformed=self._on_manage_code_groups)
        manage_groups_button.setMaximumSize(Dimension(300, 30))
        manage_groups_button.setAlignmentX(0.0)
        config_panel.add(manage_groups_button)
        
        config_panel.add(Box.createVerticalStrut(30))
        
        # Actions section
        actions_label = JLabel("Actions: ")
        font = actions_label.getFont()
        actions_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        actions_label.setAlignmentX(0.0)
        config_panel.add(actions_label)
        config_panel.add(Box.createVerticalStrut(10))
        
        # URL filter (regex) for parsing proxy history
        url_filter_panel = JPanel()
        url_filter_panel.setLayout(BoxLayout(url_filter_panel, BoxLayout.X_AXIS))
        url_filter_panel.setAlignmentX(0.0)
        url_filter_panel.add(JLabel("URL filter (regex, optional): "))
        self.history_url_filter_field = JTextField("", 25)
        self.history_url_filter_field.setMaximumSize(Dimension(250, 25))
        self.history_url_filter_field.setToolTipText(
            "Only proxy history requests whose full URL matches this regular "
            "expression will be included when building the matrix. Leave blank to include all requests.")
        url_filter_panel.add(self.history_url_filter_field)
        url_filter_panel.add(Box.createHorizontalGlue())
        config_panel.add(url_filter_panel)
        config_panel.add(Box.createVerticalStrut(10))
        
        parse_button = JButton("Parse Proxy History and Build Matrix", actionPerformed=self._on_parse_proxy_history)
        parse_button.setMaximumSize(Dimension(500, 30))
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
        
        # JWT Management Section
        jwt_label = JLabel("JWT Management: ")
        font = jwt_label.getFont()
        jwt_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        jwt_label.setAlignmentX(0.0)
        config_panel.add(jwt_label)
        config_panel.add(Box.createVerticalStrut(5))
        
        jwt_desc = JLabel("Track JWT tokens for each user:")
        jwt_desc.setAlignmentX(0.0)
        config_panel.add(jwt_desc)
        config_panel.add(Box.createVerticalStrut(10))
        
        # Create JWT table
        self.jwt_table_model = JwtTableModel()
        jwt_table = JTable(self.jwt_table_model)
        jwt_table.setAutoCreateRowSorter(True)
        
        # Set column widths
        jwt_table.getColumnModel().getColumn(0).setPreferredWidth(100)  # User
        jwt_table.getColumnModel().getColumn(1).setPreferredWidth(300)  # JWT
        jwt_table.getColumnModel().getColumn(2).setPreferredWidth(150)  # Last Seen
        
        # Add table to scroll pane
        jwt_scroll = JScrollPane(jwt_table)
        jwt_scroll.setPreferredSize(Dimension(600, 200))
        jwt_scroll.setMaximumSize(Dimension(1000, 200))
        jwt_scroll.setAlignmentX(0.0)
        config_panel.add(jwt_scroll)
        
        # Increase row height for JWT table
        jwt_table.setRowHeight(30)  # Set default row height
        jwt_table.getTableHeader().setPreferredSize(Dimension(jwt_table.getTableHeader().getPreferredSize().width, 25))

        # Add buttons panel
        jwt_buttons = JPanel()
        jwt_buttons.setLayout(BoxLayout(jwt_buttons, BoxLayout.X_AXIS))
        jwt_buttons.setAlignmentX(0.0)
        
        add_jwt_button = JButton("Add Row", actionPerformed=self._on_add_jwt_row)
        delete_jwt_button = JButton("Delete Selected", actionPerformed=lambda e: self._on_delete_jwt_row(jwt_table))
        
        jwt_buttons.add(add_jwt_button)
        jwt_buttons.add(Box.createHorizontalStrut(10))
        jwt_buttons.add(delete_jwt_button)
        jwt_buttons.add(Box.createHorizontalGlue())
        
        config_panel.add(Box.createVerticalStrut(10))
        config_panel.add(jwt_buttons)
        
        config_panel.add(Box.createVerticalStrut(30))
        
        # Replay section
        replay_label = JLabel("Replay Settings: ")
        font = replay_label.getFont()
        replay_label.setFont(Font(font.getFontName(), Font.BOLD, font.getSize()))
        replay_label.setAlignmentX(0.0)
        config_panel.add(replay_label)
        config_panel.add(Box.createVerticalStrut(10))
        
        # Thread count field
        thread_panel = JPanel()
        thread_panel.setLayout(BoxLayout(thread_panel, BoxLayout.X_AXIS))
        thread_panel.setAlignmentX(0.0)
        thread_panel.add(JLabel("Number of replay threads: "))
        self.replay_thread_count_field = JTextField(str(self.replay_thread_count), 5)
        self.replay_thread_count_field.setMaximumSize(Dimension(100, 25))
        thread_panel.add(self.replay_thread_count_field)
        thread_panel.add(Box.createHorizontalGlue())
        config_panel.add(thread_panel)
        config_panel.add(Box.createVerticalStrut(10))

        replay_button = JButton("Replay All Requests with JWT Tokens", actionPerformed=self._replay_requests)
        replay_button.setMaximumSize(Dimension(500, 30))
        replay_button.setAlignmentX(0.0)
        config_panel.add(replay_button)

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

    def _create_replay_matrix_tab(self):
        """Create a tab for displaying replay results."""
        replay_panel = JPanel(BorderLayout())
        
        # Filter panel at the top
        filter_panel = JPanel(BorderLayout())
        filter_panel.add(JLabel("Filter endpoints: "), BorderLayout.WEST)
        self.replay_filter_field = JTextField()

        # Create custom FilterListener for replay matrix
        class ReplayFilterListener(DocumentListener):
            def __init__(self, extender):
                self.extender = extender
            
            def insertUpdate(self, e):
                self._apply_replay_filter()
            
            def removeUpdate(self, e):
                self._apply_replay_filter()
            
            def changedUpdate(self, e):
                self._apply_replay_filter()
            
            def _apply_replay_filter(self):
                try:
                    filter_text = self.extender.replay_filter_field.getText().strip()
                    if not filter_text:
                        # No filter, show all rows
                        self.extender.replay_table_sorter.setRowFilter(None)
                    else:
                        # Create a case-insensitive regex filter for the endpoint column
                        self.extender.replay_table_sorter.setRowFilter(
                            RowFilter.regexFilter("(?i)" + re.escape(filter_text), 0)
                        )
                except Exception as e:
                    # If regex is invalid, show all rows
                    print("Replay filter error: %s" % str(e))
                    self.extender.replay_table_sorter.setRowFilter(None)
    
        self.replay_filter_field.getDocument().addDocumentListener(ReplayFilterListener(self))

        filter_panel.add(self.replay_filter_field, BorderLayout.CENTER)
        
        # Create table with same model as main matrix
        self.replay_table_model = JwtMatrixModel(self)
        self.replay_table = JTable(self.replay_table_model)
        self.replay_table_sorter = TableRowSorter(self.replay_table_model)
        self.replay_table.setRowSorter(self.replay_table_sorter)
        self.replay_table.setDefaultRenderer(Object, ColorCellRenderer(self))
        
        # Set row height
        self.replay_table.setRowHeight(30)
        self.replay_table.getTableHeader().setPreferredSize(Dimension(self.replay_table.getTableHeader().getPreferredSize().width, 25))
        
        # Add mouse listener for cell clicks
        class ReplayCellClickListener(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender
            
            def mouseClicked(self, event):
                table = event.getSource()
                row = table.rowAtPoint(event.getPoint())
                col = table.columnAtPoint(event.getPoint())
        
                if col == 0:
                    # Clicked on endpoint column - toggle expansion
                    model_row = table.convertRowIndexToModel(row)
                    if self.extender.replay_table_model.toggle_expansion(model_row):
                        return  # Expansion toggled, don't show details
        
                # Don't process clicks on endpoint column for details
                if col > 0 and row >= 0:
                    model_row = table.convertRowIndexToModel(row)
                    if model_row < len(self.extender.replay_table_model.visible_rows):
                        row_type, endpoint = self.extender.replay_table_model.visible_rows[model_row]
                        user = self.extender.replay_table_model.users[col - 1]

                        if row_type == 'base':
                            variants = self.extender.replay_table_model.endpoint_variants.get(endpoint, [endpoint])
                            self.extender._show_aggregated_request_details(variants, user, True)  # Pass is_replay=True
                        else:
                            self.extender._show_request_details(endpoint, user, True)  # Pass is_replay=True
        
        self.replay_table.addMouseListener(ReplayCellClickListener(self))
        
        scroll = JScrollPane(self.replay_table)
        
        # Stats label
        self.replay_stats_label = JLabel("Endpoints: 0    Users: 0")
        
        # Bottom panel with stats
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(self.replay_stats_label, BorderLayout.WEST)
        
        replay_panel.add(filter_panel, BorderLayout.NORTH)
        replay_panel.add(scroll, BorderLayout.CENTER)
        replay_panel.add(bottom_panel, BorderLayout.SOUTH)
        
        return replay_panel
    
    def _replay_requests(self, event):
        """Replay all recorded requests with all JWTs using a thread pool."""
        # Create a background thread for replay coordination
        class ReplayCoordinatorThread(Thread):
            def __init__(self, extender):
                Thread.__init__(self)
                self.extender = extender
                self.cancelled = False
                self.executor = None
            
            def run(self):
                try:
                    # Get thread count from UI and validate
                    try:
                        thread_count = int(self.extender.replay_thread_count_field.getText().strip())
                        if thread_count < 1:
                            thread_count = 1
                        elif thread_count > 50:
                            thread_count = 50
                        self.extender.replay_thread_count = thread_count
                    except:
                        thread_count = self.extender.replay_thread_count
                    
                    # Create new data structures for replay results
                    self.extender.replay_matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
                    self.extender.replay_request_details = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
                    self.extender.replay_endpoints_order = []
                    self.extender.replay_users_order = []
                    
                    # Get all unique requests and tokens
                    unique_requests = set()
                    for endpoint in self.extender.request_details:
                        for user in self.extender.request_details[endpoint]:
                            for code in self.extender.request_details[endpoint][user]:
                                for req in self.extender.request_details[endpoint][user][code]:
                                    unique_requests.add(req)
                    
                    jwt_tokens = {}  # user -> token
                    for row in range(self.extender.jwt_table_model.getRowCount()):
                        user = self.extender.jwt_table_model.getValueAt(row, 0)
                        token = self.extender.jwt_table_model.getValueAt(row, 1)
                        if user and token:
                            jwt_tokens[user] = token
                            # Add user to replay_users_order immediately
                            if user not in self.extender.replay_users_order:
                                self.extender.replay_users_order.append(user)
                    
                    if not jwt_tokens:
                        print("No JWT tokens found in JWT Management table")
                        return
                    
                    # Calculate total requests
                    total_requests = len(unique_requests) * len(jwt_tokens)
                    
                    # Create progress dialog on EDT
                    dialog_ref = [None]
                    progress_ref = [None]
                    cancel_button_ref = [None]
                    SwingUtilities.invokeAndWait(lambda: self._create_progress_dialog(dialog_ref, progress_ref, cancel_button_ref, total_requests))
                    dialog = dialog_ref[0]
                    progress = progress_ref[0]
                    
                    # Create atomic counter for thread-safe progress updates
                    progress_counter = AtomicInteger(0)
                    
                    # Create lock for thread-safe replay matrix updates
                    replay_lock = ReentrantLock()
                    
                    # Store reference to cancel button listener
                    coordinator_ref = [self]
                    
                    def on_cancel_click(event):
                        """Handle cancel button click"""
                        coordinator_ref[0].cancelled = True
                        if coordinator_ref[0].executor:
                            coordinator_ref[0].executor.shutdownNow()
                        dialog.dispose()
                        print("Replay cancelled by user")
                    
                    cancel_button_ref[0].addActionListener(lambda e: on_cancel_click(e))
                    
                    try:
                        # Create thread pool
                        self.executor = Executors.newFixedThreadPool(thread_count)
                        
                        # Create tasks for each (request, user, token) combination
                        tasks = []
                        for req in unique_requests:
                            if self.cancelled:
                                break
                            try:
                                analyzed_req = self.extender._helpers.analyzeRequest(req)
                                headers = analyzed_req.getHeaders()
                                url = analyzed_req.getUrl()
                                method = headers[0].split(' ')[0] if headers and len(headers)>0 else "GET"
                                endpoint = "%s %s" % (method, url.getPath() + (("?" + url.getQuery()) if url.getQuery() else ""))
                                
                                # Add endpoint to replay_endpoints_order
                                if endpoint not in self.extender.replay_endpoints_order:
                                    self.extender.replay_endpoints_order.append(endpoint)
                                
                                # Create task for each user/token combination
                                for user, token in jwt_tokens.items():
                                    if self.cancelled:
                                        break
                                    task = ReplayTaskCallable(
                                        self.extender,
                                        req,
                                        endpoint,
                                        user,
                                        token,
                                        headers,
                                        analyzed_req,
                                        progress,
                                        progress_counter,
                                        total_requests,
                                        replay_lock
                                    )
                                    tasks.append(self.executor.submit(task))
                            
                            except Exception as e:
                                print("Error preparing replay task: %s" % str(e))
                        
                        # Wait for all tasks to complete or cancellation
                        self.executor.shutdown()
                        self.executor.awaitTermination(300, TimeUnit.SECONDS)  # Wait up to 5 minutes
                        
                    finally:
                        # Close progress dialog on EDT only if not already disposed
                        def close_dialog():
                            try:
                                dialog.dispose()
                            except:
                                pass
                        SwingUtilities.invokeLater(close_dialog)
                    
                    # Only update replay matrix tab if not cancelled
                    if not self.cancelled:
                        # Update replay matrix tab and switch to it
                        SwingUtilities.invokeLater(lambda: self.extender._update_replay_table_model())
                        SwingUtilities.invokeLater(lambda: self.extender.tabbed_pane.setSelectedIndex(2))
                        print("Replay completed with %d threads" % thread_count)
                    else:
                        print("Replay was cancelled")
                
                except Exception as e:
                    print("Error during replay: %s" % str(e))

            def _create_progress_dialog(self, dialog_ref, progress_ref, cancel_button_ref, total_requests):
                """Create progress dialog with cancel button (called on EDT)"""
                dialog = JFrame("Replaying Requests...")
                dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE)

                # Create panel for progress bar and button
                panel = JPanel(BorderLayout())
                
                progress = JProgressBar(0, total_requests)
                progress.setStringPainted(True)
                panel.add(progress, BorderLayout.CENTER)
                
                # Create button panel
                button_panel = JPanel()
                button_panel.setLayout(BoxLayout(button_panel, BoxLayout.X_AXIS))
                button_panel.add(Box.createHorizontalGlue())
                
                cancel_button = JButton("Cancel")
                button_panel.add(cancel_button)
                button_panel.add(Box.createHorizontalStrut(10))
                
                panel.add(button_panel, BorderLayout.SOUTH)
                
                dialog.add(panel)
                dialog.setSize(400, 120)
                dialog.setLocationRelativeTo(None)
                dialog.setVisible(True)

                dialog_ref[0] = dialog
                progress_ref[0] = progress
                cancel_button_ref[0] = cancel_button

            def _update_progress(self, progress, counter, total):
                """Update progress bar (called on EDT)"""
                current = counter.get()
                progress.setValue(current)
                progress.setString(str(current) + '/' + str(total) + ' (' + str(int((current*100)/total)) + '%)')
        
        ReplayCoordinatorThread(self).start()

    def _update_replay_progress(self, progress, current, total):
        """Update progress bar (called on EDT)"""
        progress.setValue(current)
        progress.setString(str(current) + '/' + str(total) + ' (' + str(int((current*100)/total)) + '%)')

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

    def _update_replay_table_model(self):
        """Update the replay matrix table model."""
        # Group endpoints by base path
        endpoint_groups = defaultdict(list)
        for full_endpoint in self.replay_endpoints_order:
            if '?' in full_endpoint:
                base_endpoint = full_endpoint.split('?')[0]
            else:
                base_endpoint = full_endpoint
            endpoint_groups[base_endpoint].append(full_endpoint)
        
        # Create ordered list of base endpoints
        base_endpoints = []
        seen = set()
        for full_endpoint in self.replay_endpoints_order:
            if '?' in full_endpoint:
                base = full_endpoint.split('?')[0]
            else:
                base = full_endpoint
            if base not in seen:
                base_endpoints.append(base)
                seen.add(base)
        
        users = list(self.replay_users_order)
        
        # Convert nested defaultdict to plain dict for model
        data = defaultdict(lambda: defaultdict(dict))
        for ep in self.replay_endpoints_order:
            for u in users:
                data[ep][u] = dict(self.replay_matrix.get(ep, {}).get(u, {}))
        
        self.replay_table_model.set_matrix(base_endpoints, endpoint_groups, users, data)
        self.replay_stats_label.setText(
            "Endpoints: %d (Base: %d)    Users: %d" % 
            (len(self.replay_endpoints_order), len(base_endpoints), len(users))
        )
        # Re-apply filter after model update
        try:
            filter_text = self.replay_filter_field.getText().strip()
            if not filter_text:
                self.replay_table_sorter.setRowFilter(None)
            else:
                self.replay_table_sorter.setRowFilter(
                    RowFilter.regexFilter("(?i)" + re.escape(filter_text), 0)
                )
        except Exception as e:
            print("Replay filter error: %s" % str(e))
            self.replay_table_sorter.setRowFilter(None)

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

    def _on_manage_code_groups(self, event=None):
        """Open dialog to manage response code groups and their colors."""
        try:
            dialog = JDialog(JFrame(), "Manage Response Code Groups", True)
            dialog.setSize(600, 400)
            dialog.setLocationRelativeTo(self._panel)
            dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
            
            # Main panel
            main_panel = JPanel(BorderLayout())
            main_panel.add(JLabel("Configure response code groups and their colors (one pattern per line):"), BorderLayout.NORTH)
            
            # Text area for editing groups
            text_area = JTextArea()
            text_area.setLineWrap(True)
            text_area.setWrapStyleWord(True)
            # Build text from current groups
            lines = []
            for pattern, (color, label) in self.code_color_groups.items():
                r = color.getRed()
                g = color.getGreen()
                b = color.getBlue()
                hex_color = "%02x%02x%02x" % (r, g, b)
                lines.append("%s:0x%s:%s" % (pattern, hex_color, label))
            text_area.setText("\n".join(lines))
            
            scroll = JScrollPane(text_area)
            main_panel.add(scroll, BorderLayout.CENTER)
            
            # Format help
            help_label = JLabel("Format: pattern:0xHEXCOLOR:label (e.g., 2xx:0x387723:Success)")
            help_label.setFont(Font(help_label.getFont().getFontName(), Font.ITALIC, 10))
            help_panel = JPanel(BorderLayout())
            help_panel.add(help_label, BorderLayout.WEST)
            main_panel.add(help_panel, BorderLayout.SOUTH)
            
            # Button panel
            button_panel = JPanel()
            button_panel.setLayout(BoxLayout(button_panel, BoxLayout.X_AXIS))
            
            def apply_changes():
                try:
                    new_groups = OrderedDict()
                    for line in text_area.getText().split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split(':')
                        if len(parts) >= 3:
                            pattern = parts[0].strip()
                            hex_color = parts[1].strip()
                            label = ':'.join(parts[2:]).strip()
                            
                            # Parse hex color
                            if hex_color.startswith('0x'):
                                hex_color = hex_color[2:]
                            try:
                                color_int = int(hex_color, 16)
                                r = (color_int >> 16) & 0xFF
                                g = (color_int >> 8) & 0xFF
                                b = color_int & 0xFF
                                new_groups[pattern] = (Color(r, g, b), label)
                            except ValueError:
                                print("Invalid color format: %s" % hex_color)
                                continue
                    
                    if new_groups:
                        self.code_color_groups = new_groups
                        # Rebuild the legend to show new groups
                        self._rebuild_legend()
                        self.table.repaint()
                        print("Code groups updated")
                        dialog.dispose()
                except Exception as e:
                    print("Error applying code groups: %s" % str(e))
            
            apply_button = JButton("Apply", actionPerformed=lambda e: apply_changes())
            cancel_button = JButton("Cancel", actionPerformed=lambda e: dialog.dispose())
            
            button_panel.add(Box.createHorizontalGlue())
            button_panel.add(apply_button)
            button_panel.add(Box.createHorizontalStrut(10))
            button_panel.add(cancel_button)
            
            main_panel.add(button_panel, BorderLayout.PAGE_END)
            
            dialog.setContentPane(main_panel)
            dialog.setVisible(True)
        except Exception as e:
            print("Error opening manage code groups dialog: %s" % str(e))

    def _matches_code_pattern(self, code, pattern):
        """Check if a response code matches a pattern (e.g., 200 matches 2xx)."""
        # This method now only checks if a single code matches a single pattern part
        # For comma-separated patterns, use _matches_code_group_pattern instead
        if pattern == code:
            return True
        # Pattern matching for xx (e.g., 2xx, 4xx)
        if len(pattern) == 3 and pattern.endswith('xx'):
            return code.startswith(pattern[0])
        return False
    
    def _matches_code_group_pattern(self, codes, pattern):
        """Check if a list of codes matches a group pattern (including comma-separated)."""
        # Handle comma-separated patterns (e.g., "2xx,5xx")
        if ',' in pattern:
            # For comma-separated patterns, we need at least one code matching EACH part
            parts = [p.strip() for p in pattern.split(',')]
            for part in parts:
                # Check if at least one code matches this part
                if not any(self._matches_code_pattern(code, part) for code in codes):
                    return False
            # All parts have at least one matching code
            return True
        else:
            # For single patterns, all codes must match
            return all(self._matches_code_pattern(code, pattern) for code in codes)

    def _on_color_change(self, color_type):
        """Open color picker to change a color scheme."""
        try:
            # Get current color
            current_color = None
            title = ""
            
            if color_type == "no_requests":
                current_color = self.color_no_requests_group[0]
                title = "Choose color for no requests"
            elif color_type in self.code_color_groups:
                current_color, label = self.code_color_groups[color_type]
                title = "Choose color for %s" % label
            else:
                return
            
            # Show color chooser
            new_color = JColorChooser.showDialog(self._panel, title, current_color)
            
            if new_color is not None:
                # Update the color
                if color_type == "no_requests":
                    old_label = self.color_no_requests_group[1]
                    self.color_no_requests_group = (new_color, old_label)
                elif color_type in self.code_color_groups:
                    old_label = self.code_color_groups[color_type][1]
                    self.code_color_groups[color_type] = (new_color, old_label)
                
                # Refresh the table and legend to apply new colors
                self._rebuild_legend()
                self.table.repaint()
                
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

    def _show_request_details(self, endpoint, user, is_replay=False):
        """Show details for requests at a specific endpoint/user combination."""
        # Select correct data structure based on is_replay flag
        request_data = self.replay_request_details if is_replay else self.request_details
        
        dialog = JFrame('Replay ' if is_replay else '' + 'Requests for %s - User: %s' % (endpoint, user))
        dialog.setSize(800, 600)
        
        # Create main split pane
        mainSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        mainSplitPane.setResizeWeight(0.3) # Give 30% to top component
        
        # Create request list panel
        requests = []
        for code in request_data[endpoint][user]:
            valid_requests = [r for r in request_data[endpoint][user][code] 
                         if r and r.getResponse() is not None]
            requests.extend(valid_requests)
        
         # Create table model for requests with null checks
        request_table = JTable(DefaultTableModel(
            [[str(i+1), r.getHttpService().getHost(), 
              self._helpers.analyzeResponse(r.getResponse()).getStatusCode() if r.getResponse() else "N/A"] 
             for i,r in enumerate(requests)],
            ["#", "Host", "Status"]))
        
        request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        list_scroll = JScrollPane(request_table)
        
        # Create request/response viewers
        controller = RequestDetailsController(self, requests)
        req_viewer = self._callbacks.createMessageEditor(controller, False)
        resp_viewer = self._callbacks.createMessageEditor(controller, False)
        
        # Create viewer split pane
        viewerSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        viewerSplitPane.setResizeWeight(0.5) # Equal split
        viewerSplitPane.setLeftComponent(req_viewer.getComponent())
        viewerSplitPane.setRightComponent(resp_viewer.getComponent())
        
        # Add components to main split pane
        mainSplitPane.setTopComponent(list_scroll)
        mainSplitPane.setBottomComponent(viewerSplitPane)
        
        # Add selection listener
        def selection_changed(event):
            if not event.getValueIsAdjusting():
                row = request_table.getSelectedRow()
                if row >= 0:
                    req_viewer.setMessage(requests[row].getRequest(), True)
                    resp_viewer.setMessage(requests[row].getResponse(), False)
        
        request_table.getSelectionModel().addListSelectionListener(selection_changed)
        
        # Select first row by default
        if len(requests) > 0:
            request_table.setRowSelectionInterval(0, 0)
        
        # Add to dialog with proper layout
        dialog.add(mainSplitPane)
        dialog.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        dialog.setVisible(True)

    def _show_aggregated_request_details(self, endpoint_variants, user, is_replay=False):
        """Show details for requests across multiple endpoint variants for a user."""
        # Select correct data structure based on is_replay flag
        request_data = self.replay_request_details if is_replay else self.request_details
        
        dialog = JFrame('Replay ' if is_replay else '' + "Requests for %d endpoints - User: %s" % (len(endpoint_variants), user))
        dialog.setSize(800, 600)
        
        # Create main split pane
        mainSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        mainSplitPane.setResizeWeight(0.3)
        
        # Collect all requests
        all_requests = []
        for endpoint in endpoint_variants:
            for code in request_data[endpoint][user]:
                valid_requests = [r for r in request_data[endpoint][user][code] 
                            if r and r.getResponse() is not None]
                all_requests.extend(valid_requests)
        
        # Create table model with null checks
        request_table = JTable(DefaultTableModel(
            [[str(i+1), r.getHttpService().getHost(),
              self._helpers.analyzeRequest(r).getUrl().getPath(),
              self._helpers.analyzeResponse(r.getResponse()).getStatusCode() if r.getResponse() else "N/A"]
             for i,r in enumerate(all_requests)],
            ["#", "Host", "Path", "Status"]))
        
        request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        list_scroll = JScrollPane(request_table)
        
        # Create request/response viewers
        controller = RequestDetailsController(self, all_requests)
        req_viewer = self._callbacks.createMessageEditor(controller, False)
        resp_viewer = self._callbacks.createMessageEditor(controller, False)
        
        # Create viewer split pane
        viewerSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        viewerSplitPane.setResizeWeight(0.5)
        viewerSplitPane.setLeftComponent(req_viewer.getComponent())
        viewerSplitPane.setRightComponent(resp_viewer.getComponent())
        
        # Add components to main split pane
        mainSplitPane.setTopComponent(list_scroll)
        mainSplitPane.setBottomComponent(viewerSplitPane)
        
        # Add selection listener
        def selection_changed(event):
            if not event.getValueIsAdjusting():
                row = request_table.getSelectedRow()
                if row >= 0:
                    req_viewer.setMessage(all_requests[row].getRequest(), True)
                    resp_viewer.setMessage(all_requests[row].getResponse(), False)
        
        request_table.getSelectionModel().addListSelectionListener(selection_changed)
        
        # Select first row by default
        if len(all_requests) > 0:
            request_table.setRowSelectionInterval(0, 0)
        
        # Add to dialog with proper layout
        dialog.add(mainSplitPane)
        dialog.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        dialog.setVisible(True)

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
            # Compile optional URL regex filter
            url_filter_pattern = None
            try:
                url_filter_text = self.history_url_filter_field.getText().strip()
                if url_filter_text:
                    url_filter_pattern = re.compile(url_filter_text)
            except Exception as filter_err:
                print("Invalid URL filter regex, ignoring filter: %s" % str(filter_err))
                url_filter_pattern = None
            for item in history:
                try:
                    # Get request info
                    analyzed_req = self._helpers.analyzeRequest(item)
                    headers = analyzed_req.getHeaders()
                    url = analyzed_req.getUrl()
                    method = headers[0].split(' ')[0] if headers and len(headers)>0 else "GET"
                    endpoint = "%s %s" % (method, url.getPath() + (("?" + url.getQuery()) if url.getQuery() else ""))
                    
                    # Skip requests that don't match the configured URL filter
                    if url_filter_pattern is not None:
                        if not url_filter_pattern.search(str(url)):
                            continue
                    
                    # Get response code
                    response = item.getResponse()
                    if response is None:
                        continue
                    analyzed_resp = self._helpers.analyzeResponse(response)
                    response_code = str(analyzed_resp.getStatusCode())

                    # Find JWT token based on configured location
                    token = None
                    if self.jwt_location_auth.isSelected():
                        # Look in Authorization header
                        for h in headers:
                            if h.lower().startswith("authorization:"):
                                parts = h.split(":",1)[1].strip().split()
                                if len(parts) >= 2 and parts[0].lower() == "bearer":
                                    token = parts[1].strip()
                                    break
                    else:
                        # Look in Cookies
                        cookie_name = self.cookie_name_field.getText().strip() or "jwt"
                        for h in headers:
                            if h.lower().startswith("cookie:"):
                                cookies = h.split(":",1)[1].strip().split(";")
                                for cookie in cookies:
                                    if "=" in cookie:
                                        name, value = cookie.split("=", 1)
                                        if name.strip() == cookie_name:
                                            token = value.strip()
                                            break
                                if token:
                                    break
                
                    if not token:
                        continue

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

    def _on_add_jwt_row(self, event):
        """Add a new empty row to the JWT table."""
        self.jwt_table_model.addRow(["", "", ""])

    def _on_delete_jwt_row(self, table):
        """Delete selected rows from the JWT table."""
        rows = table.getSelectedRows()
        if rows:
            # Convert view indices to model indices
            model_rows = [table.convertRowIndexToModel(row) for row in rows]
            # Remove rows in reverse order to maintain indices
            for row in sorted(model_rows, reverse=True):
                self.jwt_table_model.removeRow(row)
                # Update user_rows mapping
                new_mapping = {}
                for user, idx in self.jwt_table_model.user_rows.items():
                    if idx < row:
                        new_mapping[user] = idx
                    elif idx > row:
                        new_mapping[user] = idx - 1
                self.jwt_table_model.user_rows = new_mapping

    def _update_jwt_table(self, user, jwt):
        """Update the JWT table with a new token."""
        timestamp = java.util.Date().toString()
        SwingUtilities.invokeLater(lambda: self.jwt_table_model.update_jwt(user, jwt, timestamp))

class JwtMatrixContextMenu(IContextMenuFactory):
    """Adds context menu to send requests to JWT Matrix"""
    
    def __init__(self, extender):
        self.extender = extender

    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        
        # Only show menu item for requests with JWT tokens
        ctx = invocation.getSelectedMessages()
        if ctx is None or len(ctx) == 0:
            return menu_items

        request = ctx[0]  # Get first selected request
        analyzed_req = self.extender._helpers.analyzeRequest(request)
        headers = analyzed_req.getHeaders()

        # Check for JWT token in configured location
        has_jwt = False
        if self.extender.jwt_location_auth.isSelected():
            # Check Authorization header
            for header in headers:
                if header.lower().startswith("authorization:") and "bearer" in header.lower():
                    has_jwt = True
                    break
        else:
            # Check Cookies
            cookie_name = self.extender.cookie_name_field.getText().strip() or "jwt"
            for header in headers:
                if header.lower().startswith("cookie:"):
                    cookies = header.split(":",1)[1].strip().split(";")
                    for cookie in cookies:
                        if "=" in cookie:
                            name, value = cookie.split("=", 1)
                            if name.strip() == cookie_name:
                                has_jwt = True
                                break
                    if has_jwt:
                        break 
        
        if has_jwt:
            # Create action listener class instead of using lambda
            class MenuItemAction(java.awt.event.ActionListener):
                def __init__(self, context, matrix):
                    self.context = context
                    self.matrix = matrix
                
                def actionPerformed(self, e):
                    self.matrix.send_to_matrix(self.context)
            
            menu_item = JMenuItem("Send to JWT Authorization Matrix")
            menu_item.addActionListener(MenuItemAction(ctx, self))
            menu_items.add(menu_item)
        
        return menu_items


    def send_to_matrix(self, messages):
        """Process selected message(s) and add to matrix"""
        for message in messages:
            try:
                # Similar logic as processHttpMessage
                analyzed_req = self.extender._helpers.analyzeRequest(message)
                headers = analyzed_req.getHeaders()
                url = analyzed_req.getUrl()
                method = headers[0].split(' ')[0] if headers and len(headers)>0 else "GET"
                endpoint = "%s %s" % (method, url.getPath() + (("?" + url.getQuery()) if url.getQuery() else ""))
                
                # Get response if available
                response = message.getResponse()
                if response is None:
                    continue
                    
                analyzed_resp = self.extender._helpers.analyzeResponse(response)
                response_code = str(analyzed_resp.getStatusCode())
                
                # Find JWT token based on configured location
                token = None
                if self.extender.jwt_location_auth.isSelected():
                    # Look in Authorization header
                    for h in headers:
                        if h.lower().startswith("authorization:"):
                            parts = h.split(":",1)[1].strip().split()
                            if len(parts) >= 2 and parts[0].lower() == "bearer":
                                token = parts[1].strip()
                                break
                else:
                    # Look in Cookies
                    cookie_name = self.extender.cookie_name_field.getText().strip() or "jwt"
                    for h in headers:
                        if h.lower().startswith("cookie:"):
                            cookies = h.split(":",1)[1].strip().split(";")
                            for cookie in cookies:
                                if "=" in cookie:
                                    name, value = cookie.split("=", 1)
                                    if name.strip() == cookie_name:
                                        token = value.strip()
                                        break
                            if token:
                                break
                
                if not token:
                    continue
                    
                user = self.extender._parse_jwt_get_field(token, self.extender.jwt_user_field)
                if user is None:
                    user = "<no-%s>" % self.extender.jwt_user_field
                
                # Add to matrix data structures
                if endpoint not in self.extender.endpoints_order:
                    self.extender.endpoints_order.append(endpoint)
                if user not in self.extender.users_order:
                    self.extender.users_order.append(user)
                    
                self.extender.matrix[endpoint][user][response_code] += 1
                self.extender.request_details[endpoint][user][response_code].append(message)
                
                # Update UI
                SwingUtilities.invokeLater(lambda: self.extender._update_table_model())
                
                print("Added request to JWT Matrix: %s" % endpoint)
                
            except Exception as e:
                print("Error processing request for JWT Matrix: %s" % str(e))

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

class JwtTableModel(DefaultTableModel):
    def __init__(self):
        super(JwtTableModel, self).__init__(
            [], 
            ["User", "JWT Token", "Last Seen"]
        )
        self.user_rows = {}  # user -> row index mapping
    
    def isCellEditable(self, row, col):
        return col < 2  # Only User and JWT columns are editable
    
    def update_jwt(self, user, jwt, timestamp):
        if user in self.user_rows:
            row = self.user_rows[user]
            self.setValueAt(jwt, row, 1)
            self.setValueAt(timestamp, row, 2)
        else:
            row = self.getRowCount()
            self.addRow([user, jwt, timestamp])
            self.user_rows[user] = row
