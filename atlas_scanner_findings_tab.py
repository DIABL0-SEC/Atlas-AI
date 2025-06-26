# -*- coding: utf-8 -*-
# Atlas Scanner Findings Tab - Dedicated top-level tab for scanner findings AI analysis

from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color, Dimension, FlowLayout
from java.awt.event import ActionListener, MouseAdapter
from javax.swing import (
    JPanel, JLabel, JButton, JTextArea, JScrollPane, JTable, JSplitPane,
    JComboBox, BorderFactory, Box, BoxLayout, SwingUtilities, JTextField,
    ListSelectionModel, JTabbedPane, Timer
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
import threading
import time
from datetime import datetime

class AtlasScannerFindingsTab:
    """Dedicated tab for scanner findings AI analysis in the main Atlas AI extension."""
    
    def __init__(self, extension):
        self.extension = extension
        self._stdout = extension.get_stdout()
        self._stderr = extension.get_stderr()
        
        # Scanner findings storage
        self._scanner_findings = []
        self._findings_lock = threading.Lock()
        
        # UI Components
        self._findings_table_model = None
        self._findings_table = None
        self._analysis_tabs = None
        self._selected_issue = None
        
        # Tab color management
        self._original_tab_color = None
        self._tab_index = -1
        self._flash_timer = None
        
        # Analysis areas
        self._overview_area = None
        self._analysis_area = None
        self._exploit_area = None
        
        # Create UI
        self.panel = self._create_ui()
    
    def get_component(self):
        """Return the main panel component."""
        return self.panel
    
    def set_tab_index(self, index):
        """Set the tab index for color management."""
        self._tab_index = index
    
    def _create_ui(self):
        """Create the main UI panel."""
        main_panel = JPanel(BorderLayout())
        
        # Header
        header = self._create_header()
        main_panel.add(header, BorderLayout.NORTH)
        
        # Create split pane
        split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split_pane.setDividerLocation(700)
        
        # Left panel - findings list
        left_panel = self._create_findings_panel()
        split_pane.setLeftComponent(left_panel)
        
        # Right panel - analysis
        right_panel = self._create_analysis_panel()
        split_pane.setRightComponent(right_panel)
        
        main_panel.add(split_pane, BorderLayout.CENTER)
        
        return main_panel
    
    def _create_header(self):
        """Create header panel."""
        header = JPanel()
        header.setLayout(BoxLayout(header, BoxLayout.X_AXIS))
        header.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        header.setBackground(Color(240, 240, 240))
        
        # Title
        title = JLabel("Scanner Findings AI Analysis")
        title.setFont(Font("Arial", Font.BOLD, 20))
        title.setForeground(Color(50, 50, 50))
        header.add(title)
        
        header.add(Box.createHorizontalGlue())
        
        # Status label
        self._status_label = JLabel("Ready")
        self._status_label.setFont(Font("Arial", Font.PLAIN, 14))
        header.add(self._status_label)
        
        header.add(Box.createRigidArea(Dimension(20, 0)))
        
        # Refresh button
        refresh_btn = JButton("Refresh Findings")
        refresh_btn.setFont(Font("Arial", Font.PLAIN, 14))
        refresh_btn.addActionListener(lambda e: self._refresh_findings())
        header.add(refresh_btn)
        
        header.add(Box.createRigidArea(Dimension(10, 0)))
        
        # Clear button
        clear_btn = JButton("Clear All")
        clear_btn.setFont(Font("Arial", Font.PLAIN, 14))
        clear_btn.addActionListener(lambda e: self._clear_all_findings())
        header.add(clear_btn)
        
        return header
    
    def _create_findings_panel(self):
        """Create scanner findings list panel."""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            "Scanner Findings",
            0,
            0,
            Font("Arial", Font.BOLD, 16)
        ))
        
        # Table columns
        columns = ["Severity", "Issue", "Host", "Path", "Confidence", "Status"]
        self._findings_table_model = DefaultTableModel(columns, 0)
        
        # Create table
        self._findings_table = JTable(self._findings_table_model)
        self._findings_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._findings_table.setRowHeight(30)
        self._findings_table.setFont(Font("Arial", Font.PLAIN, 14))
        self._findings_table.getTableHeader().setFont(Font("Arial", Font.BOLD, 14))
        
        # Set column widths
        column_model = self._findings_table.getColumnModel()
        column_model.getColumn(0).setPreferredWidth(80)   # Severity
        column_model.getColumn(1).setPreferredWidth(250)  # Issue
        column_model.getColumn(2).setPreferredWidth(150)  # Host
        column_model.getColumn(3).setPreferredWidth(200)  # Path
        column_model.getColumn(4).setPreferredWidth(100)  # Confidence
        column_model.getColumn(5).setPreferredWidth(100)  # Status
        
        # Custom renderer for severity column
        severity_renderer = SeverityRenderer()
        column_model.getColumn(0).setCellRenderer(severity_renderer)
        
        # Custom renderer for status column
        status_renderer = StatusRenderer()
        column_model.getColumn(5).setCellRenderer(status_renderer)
        
        # Selection listener
        class SelectionListener(MouseAdapter):
            def __init__(self, tab):
                self.tab = tab
            def mouseClicked(self, event):
                row = self.tab._findings_table.getSelectedRow()
                if row >= 0:
                    self.tab._on_finding_selected(row)
        
        self._findings_table.addMouseListener(SelectionListener(self))
        
        # Scroll pane
        scroll_pane = JScrollPane(self._findings_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Action buttons panel
        action_panel = self._create_action_panel()
        panel.add(action_panel, BorderLayout.SOUTH)
        
        return panel
    
    def _create_action_panel(self):
        """Create action buttons panel."""
        panel = JPanel(FlowLayout(FlowLayout.LEFT))
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Analyze button
        self._analyze_btn = JButton("Analyze & Explain")
        self._analyze_btn.setFont(Font("Arial", Font.BOLD, 14))
        self._analyze_btn.setEnabled(False)
        self._analyze_btn.addActionListener(lambda e: self._analyze_selected_finding())
        panel.add(self._analyze_btn)
        
        # Suggest exploitation button
        self._exploit_btn = JButton("Suggest Exploitation")
        self._exploit_btn.setFont(Font("Arial", Font.BOLD, 14))
        self._exploit_btn.setEnabled(False)
        self._exploit_btn.addActionListener(lambda e: self._suggest_exploitation())
        panel.add(self._exploit_btn)
        
        # Analyze all button
        analyze_all_btn = JButton("Analyze All")
        analyze_all_btn.setFont(Font("Arial", Font.PLAIN, 14))
        analyze_all_btn.addActionListener(lambda e: self._analyze_all_findings())
        panel.add(analyze_all_btn)
        
        return panel
    
    def _create_analysis_panel(self):
        """Create analysis panel."""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            "AI Analysis Results",
            0,
            0,
            Font("Arial", Font.BOLD, 16)
        ))
        
        # Tabbed pane for different analysis types
        self._analysis_tabs = JTabbedPane()
        self._analysis_tabs.setFont(Font("Arial", Font.BOLD, 14))
        
        # Overview tab
        self._overview_area = JTextArea()
        self._overview_area.setEditable(False)
        self._overview_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self._overview_area.setLineWrap(True)
        self._overview_area.setWrapStyleWord(True)
        overview_scroll = JScrollPane(self._overview_area)
        self._analysis_tabs.addTab("Overview", overview_scroll)
        
        # Analysis & Explanation tab
        self._analysis_area = JTextArea()
        self._analysis_area.setEditable(False)
        self._analysis_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self._analysis_area.setLineWrap(True)
        self._analysis_area.setWrapStyleWord(True)
        analysis_scroll = JScrollPane(self._analysis_area)
        self._analysis_tabs.addTab("Analysis & Explanation", analysis_scroll)
        
        # Exploitation tab
        self._exploit_area = JTextArea()
        self._exploit_area.setEditable(False)
        self._exploit_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self._exploit_area.setLineWrap(True)
        self._exploit_area.setWrapStyleWord(True)
        exploit_scroll = JScrollPane(self._exploit_area)
        self._analysis_tabs.addTab("Exploitation Suggestions", exploit_scroll)
        
        panel.add(self._analysis_tabs, BorderLayout.CENTER)
        
        # Progress panel
        progress_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        progress_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        self._progress_label = JLabel("")
        self._progress_label.setFont(Font("Arial", Font.ITALIC, 14))
        progress_panel.add(self._progress_label)
        
        panel.add(progress_panel, BorderLayout.SOUTH)
        
        return panel
    
    def add_scanner_finding(self, issue):
        """Add a scanner finding to the tab."""
        try:
            if not issue:
                return
            
            with self._findings_lock:
                # Check if already exists
                for finding in self._scanner_findings:
                    try:
                        if (finding.getUrl() == issue.getUrl() and 
                            finding.getIssueName() == issue.getIssueName()):
                            return  # Already exists
                    except:
                        continue  # Skip comparison if methods fail
                
                self._scanner_findings.append(issue)
            
            # Update UI on EDT
            SwingUtilities.invokeLater(lambda: self._add_finding_to_table(issue))
        except Exception as e:
            self.extension.get_stderr().println("[Atlas AI] Error adding scanner finding: " + str(e))
    
    def _add_finding_to_table(self, issue):
        """Add a scanner finding to the table."""
        # Extract issue details with null checks
        severity = issue.getSeverity() if issue.getSeverity() else "Unknown"
        name = issue.getIssueName() if issue.getIssueName() else "Unknown Issue"
        url = issue.getUrl()
        host = url.getHost() if url and url.getHost() else "unknown"
        path = url.getPath() if url and url.getPath() else "/"
        confidence = issue.getConfidence() if issue.getConfidence() else "Unknown"
        status = "New"
        
        # Add row to table
        row_data = [severity, name, host, path, confidence, status]
        self._findings_table_model.addRow(row_data)
        
        # Flash the tab to indicate new finding
        self._flash_tab()
        
        # Update status
        self._update_status("New finding: " + name)
    
    def _flash_tab(self):
        """Flash the tab orange to indicate new content."""
        if self._tab_index < 0:
            return
        
        # Get the parent tabbed pane
        parent = self.panel.getParent()
        if parent and hasattr(parent, 'setBackgroundAt'):
            # Store original color if not stored
            if self._original_tab_color is None:
                try:
                    self._original_tab_color = parent.getBackgroundAt(self._tab_index)
                except:
                    self._original_tab_color = Color.WHITE
            
            # Set tab to orange
            try:
                parent.setBackgroundAt(self._tab_index, Color.ORANGE)
            except:
                return  # Tab index might be invalid
            
            # Create timer to reset color after 3 seconds
            if self._flash_timer:
                self._flash_timer.stop()
            
            def reset_color():
                try:
                    if parent and self._tab_index >= 0:
                        parent.setBackgroundAt(self._tab_index, self._original_tab_color)
                except:
                    pass  # Parent might be gone
            
            self._flash_timer = Timer(3000, lambda e: reset_color())
            self._flash_timer.setRepeats(False)
            self._flash_timer.start()
    
    def _on_finding_selected(self, row):
        """Handle finding selection."""
        with self._findings_lock:
            try:
                if row < 0 or row >= len(self._scanner_findings):
                    return
                
                self._selected_issue = self._scanner_findings[row]
                
                # Enable analysis buttons
                self._analyze_btn.setEnabled(True)
                self._exploit_btn.setEnabled(True)
                
                # Show basic info in overview
                self._show_issue_overview(self._selected_issue)
            except Exception as e:
                self.extension.get_stderr().println("[Atlas AI] Error selecting finding: " + str(e))
                self._show_error("Error selecting finding: " + str(e))
    
    def _show_issue_overview(self, issue):
        """Show issue overview in the overview tab."""
        overview = "SCANNER FINDING OVERVIEW\n"
        overview += "=" * 60 + "\n\n"
        overview += "Issue: " + (issue.getIssueName() if issue.getIssueName() else "Unknown") + "\n"
        overview += "URL: " + (str(issue.getUrl()) if issue.getUrl() else "Unknown") + "\n"
        overview += "Severity: " + (issue.getSeverity() if issue.getSeverity() else "Unknown") + "\n"
        overview += "Confidence: " + (issue.getConfidence() if issue.getConfidence() else "Unknown") + "\n\n"
        
        if issue.getIssueDetail():
            overview += "Details:\n" + issue.getIssueDetail() + "\n\n"
        
        if issue.getIssueBackground():
            overview += "Background:\n" + issue.getIssueBackground() + "\n\n"
        
        if issue.getRemediationDetail():
            overview += "Remediation:\n" + issue.getRemediationDetail()
        
        self._overview_area.setText(overview)
        self._overview_area.setCaretPosition(0)
        self._analysis_tabs.setSelectedIndex(0)  # Switch to overview tab
    
    def _analyze_selected_finding(self):
        """Analyze the selected finding with AI."""
        if not self._selected_issue:
            self._show_error("No finding selected")
            return
        
        if not self.extension.get_current_adapter():
            self._show_error("Atlas AI not configured. Please configure it in the Settings tab.")
            return
        
        # Store the issue reference to avoid race conditions
        current_issue = self._selected_issue
        
        # Update status in table
        self._update_finding_status(current_issue, "Analyzing...")
        
        self._progress_label.setText("Analyzing finding...")
        self._analyze_btn.setEnabled(False)
        
        # Flash tab to indicate activity
        self._flash_tab()
        
        def analyze():
            try:
                from atlas_prompts import AtlasPrompts
                
                # Build issue text
                issue_text = self._build_issue_details(current_issue)
                
                # Use the scanner finding analysis prompt
                prompt = AtlasPrompts.SCANNER_FINDING_ANALYSIS.format(issue_text=issue_text)
                
                # Get AI response
                adapter = self.extension.get_current_adapter()
                response = adapter.send_message(prompt)
                
                # Format and display
                result = "AI SECURITY ANALYSIS\n"
                result += "=" * 60 + "\n"
                result += "Generated: " + str(datetime.now()) + "\n"
                result += "=" * 60 + "\n\n"
                result += response
                
                SwingUtilities.invokeLater(lambda: self._show_analysis_result(result))
                SwingUtilities.invokeLater(lambda: self._update_finding_status(current_issue, "Analyzed"))
                
            except Exception as e:
                error_msg = "Analysis error: " + str(e)
                self.extension.get_stderr().println("[Atlas AI] " + error_msg)
                SwingUtilities.invokeLater(lambda: self._show_error(error_msg))
                SwingUtilities.invokeLater(lambda: self._update_finding_status(current_issue, "Error"))
            finally:
                SwingUtilities.invokeLater(lambda: self._analyze_btn.setEnabled(True))
        
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()
    
    def _suggest_exploitation(self):
        """Suggest exploitation vectors for the selected finding."""
        if not self._selected_issue:
            self._show_error("No finding selected")
            return
        
        if not self.extension.get_current_adapter():
            self._show_error("Atlas AI not configured. Please configure it in the Settings tab.")
            return
        
        # Store the issue reference to avoid race conditions
        current_issue = self._selected_issue
        
        # Update status in table
        self._update_finding_status(current_issue, "Exploiting...")
        
        self._progress_label.setText("Generating exploitation suggestions...")
        self._exploit_btn.setEnabled(False)
        
        # Flash tab to indicate activity
        self._flash_tab()
        
        def exploit():
            try:
                from atlas_prompts import AtlasPrompts
                
                # Build issue text
                issue_text = self._build_issue_details(current_issue)
                
                # Use the exploitation vectors prompt
                prompt = AtlasPrompts.SCANNER_EXPLOITATION_VECTORS.format(issue_text=issue_text)
                
                # Get AI response
                adapter = self.extension.get_current_adapter()
                response = adapter.send_message(prompt)
                
                # Format and display
                result = "EXPLOITATION SUGGESTIONS\n"
                result += "=" * 60 + "\n"
                result += "Generated: " + str(datetime.now()) + "\n"
                result += "=" * 60 + "\n\n"
                result += response
                
                SwingUtilities.invokeLater(lambda: self._show_exploitation_result(result))
                SwingUtilities.invokeLater(lambda: self._update_finding_status(current_issue, "Exploited"))
                
            except Exception as e:
                error_msg = "Exploitation error: " + str(e)
                self.extension.get_stderr().println("[Atlas AI] " + error_msg)
                SwingUtilities.invokeLater(lambda: self._show_error(error_msg))
                SwingUtilities.invokeLater(lambda: self._update_finding_status(current_issue, "Error"))
            finally:
                SwingUtilities.invokeLater(lambda: self._exploit_btn.setEnabled(True))
        
        thread = threading.Thread(target=exploit)
        thread.daemon = True
        thread.start()
    
    def _build_issue_details(self, issue):
        """Build detailed issue text for prompts."""
        try:
            text = "Issue: " + (issue.getIssueName() if issue.getIssueName() else "Unknown") + "\n"
            text += "URL: " + (str(issue.getUrl()) if issue.getUrl() else "Unknown") + "\n"
            text += "Severity: " + (issue.getSeverity() if issue.getSeverity() else "Unknown") + "\n"
            text += "Confidence: " + (issue.getConfidence() if issue.getConfidence() else "Unknown") + "\n\n"
            
            if issue.getIssueDetail():
                text += "Scanner Details:\n" + issue.getIssueDetail() + "\n\n"
            
            if issue.getIssueBackground():
                text += "Background:\n" + issue.getIssueBackground() + "\n\n"
            
            # Include request/response if available
            try:
                messages = issue.getHttpMessages()
                if messages and len(messages) > 0:
                    message = messages[0]
                    
                    try:
                        request = message.getRequest()
                        if request and len(request) > 0:
                            text += "Sample Request:\n"
                            request_bytes = request[:min(1000, len(request))]
                            text += self.extension.get_helpers().bytesToString(request_bytes)
                            if len(request) > 1000:
                                text += "\n[... truncated ...]\n"
                            text += "\n\n"
                    except Exception as e:
                        text += "Request: Error reading request data\n\n"
                    
                    try:
                        response = message.getResponse()
                        if response and len(response) > 0:
                            text += "Sample Response:\n"
                            response_bytes = response[:min(1000, len(response))]
                            text += self.extension.get_helpers().bytesToString(response_bytes)
                            if len(response) > 1000:
                                text += "\n[... truncated ...]\n"
                            text += "\n\n"
                    except Exception as e:
                        text += "Response: Error reading response data\n\n"
            except Exception as e:
                text += "HTTP Messages: Error accessing messages\n\n"
            
            return text
        except Exception as e:
            return "Error building issue details: " + str(e)
    
    def _show_analysis_result(self, result):
        """Show analysis result in the UI."""
        self._analysis_area.setText(result)
        self._analysis_area.setCaretPosition(0)
        self._analysis_tabs.setSelectedIndex(1)  # Switch to analysis tab
        self._progress_label.setText("Analysis complete")
        self._analyze_btn.setEnabled(True)
    
    def _show_exploitation_result(self, result):
        """Show exploitation result in the UI."""
        self._exploit_area.setText(result)
        self._exploit_area.setCaretPosition(0)
        self._analysis_tabs.setSelectedIndex(2)  # Switch to exploitation tab
        self._progress_label.setText("Exploitation analysis complete")
        self._exploit_btn.setEnabled(True)
    
    def _show_error(self, error):
        """Show error message."""
        self._progress_label.setText("Error: " + error)
        self._analyze_btn.setEnabled(True)
        self._exploit_btn.setEnabled(True)
    
    def _update_finding_status(self, issue, status):
        """Update the status of a finding in the table."""
        with self._findings_lock:
            try:
                # Find the issue in our findings list
                issue_index = -1
                for i, finding in enumerate(self._scanner_findings):
                    if finding == issue:
                        issue_index = i
                        break
                
                # Update table if issue found and index is valid
                if issue_index >= 0 and issue_index < self._findings_table_model.getRowCount():
                    self._findings_table_model.setValueAt(status, issue_index, 5)
            except Exception as e:
                self.extension.get_stderr().println("[Atlas AI] Error updating finding status: " + str(e))
    
    def _refresh_findings(self):
        """Refresh scanner findings from Burp."""
        self._update_status("Refreshing findings...")
        
        # Get all scan issues from Burp
        all_issues = self.extension._callbacks.getScanIssues(None)
        
        if all_issues:
            for issue in all_issues:
                self.add_scanner_finding(issue)
        
        self._update_status("Found " + str(len(self._scanner_findings)) + " issues")
    
    def _analyze_all_findings(self):
        """Analyze all findings in sequence."""
        if not self._scanner_findings:
            self._show_error("No findings to analyze")
            return
        
        self._progress_label.setText("Analyzing all findings...")
        
        # TODO: Implement batch analysis with progress tracking
        self._show_error("Batch analysis coming soon")
    
    def _clear_all_findings(self):
        """Clear all findings from the table."""
        with self._findings_lock:
            self._scanner_findings = []
            self._findings_table_model.setRowCount(0)
            self._selected_issue = None
            self._clear_analysis_tabs()
            self._update_status("All findings cleared")
    
    def _clear_analysis_tabs(self):
        """Clear all analysis tabs."""
        self._overview_area.setText("")
        self._analysis_area.setText("")
        self._exploit_area.setText("")
        self._analyze_btn.setEnabled(False)
        self._exploit_btn.setEnabled(False)
    
    def _update_status(self, message):
        """Update status label."""
        self._status_label.setText(message)
    
    def process_scanner_context_menu(self, issue, analysis_type):
        """Process scanner finding from context menu."""
        # Add the issue if not already present
        self.add_scanner_finding(issue)
        
        # Find and select the issue in the table
        def find_and_select():
            with self._findings_lock:
                try:
                    for i, finding in enumerate(self._scanner_findings):
                        if finding == issue:
                            SwingUtilities.invokeLater(lambda row=i: self._select_and_analyze(row, analysis_type))
                            return
                    # If not found, try again after a short delay
                    SwingUtilities.invokeLater(lambda: self._show_error("Finding not found in table"))
                except Exception as e:
                    self.extension.get_stderr().println("[Atlas AI] Error in context menu processing: " + str(e))
        
        # Execute with a small delay to ensure UI is updated
        threading.Timer(0.1, find_and_select).start()
    
    def _select_and_analyze(self, row, analysis_type):
        """Select a row and start analysis."""
        try:
            # Validate row index
            if row < 0 or row >= self._findings_table_model.getRowCount():
                self._show_error("Invalid row index: " + str(row))
                return
            
            self._findings_table.setRowSelectionInterval(row, row)
            self._on_finding_selected(row)
            
            if analysis_type == "analysis":
                self._analyze_selected_finding()
            elif analysis_type == "exploitation":
                self._suggest_exploitation()
        except Exception as e:
            self.extension.get_stderr().println("[Atlas AI] Error in select and analyze: " + str(e))
            self._show_error("Error selecting finding: " + str(e))


class SeverityRenderer(DefaultTableCellRenderer):
    """Custom renderer for severity column with colors."""
    
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        
        # Set colors based on severity
        if not isSelected:
            severity = str(value)
            if severity == "High":
                component.setForeground(Color(200, 0, 0))
                component.setFont(component.getFont().deriveFont(Font.BOLD))
            elif severity == "Medium":
                component.setForeground(Color(255, 140, 0))
                component.setFont(component.getFont().deriveFont(Font.BOLD))
            elif severity == "Low":
                component.setForeground(Color(0, 0, 200))
            else:
                component.setForeground(Color(100, 100, 100))
        
        return component


class StatusRenderer(DefaultTableCellRenderer):
    """Custom renderer for status column."""
    
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        
        # Set colors based on status
        if not isSelected:
            status = str(value)
            if status == "Analyzing..." or status == "Exploiting...":
                component.setForeground(Color.BLUE)
                component.setFont(component.getFont().deriveFont(Font.ITALIC))
            elif status == "Analyzed" or status == "Exploited":
                component.setForeground(Color(0, 150, 0))
                component.setFont(component.getFont().deriveFont(Font.BOLD))
            elif status == "Error":
                component.setForeground(Color.RED)
                component.setFont(component.getFont().deriveFont(Font.BOLD))
        
        return component