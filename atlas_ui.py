# -*- coding: utf-8 -*-
# Atlas AI UI Builder

from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color
from java.awt.event import ActionListener, KeyAdapter, KeyEvent
from javax.swing import (
    JPanel, JLabel, JButton, JTextArea, JScrollPane,
    JTextField, JPasswordField, BorderFactory, JComboBox,
    JSplitPane, Box, BoxLayout, SwingUtilities, JTabbedPane
)
import threading

class AtlasUIBuilder:
    """Handles UI creation for Atlas AI extension."""
    
    def __init__(self, extension):
        self.extension = extension
        self.chat_area = None
        self.analysis_area = None
        self.input_area = None
        
        # UI components that need to be accessible
        self.backend_combo = None
        self.api_key_field = None
        self.local_url_field = None
        self.local_api_key_field = None
        self.model_field = None
        self.timeout_field = None
        self.api_key_label = None
        self.local_url_label = None
        self.local_api_key_label = None
        
        # Scanner analysis components
        self.scanner_analysis_area = None
        self.analysis_tabbed_pane = None
    
    def create_settings_panel(self):
        """Create settings panel."""
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        
        row = 0
        
        # Title
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.anchor = GridBagConstraints.CENTER
        title = JLabel("AI Backend Configuration")
        title.setFont(Font("Arial", Font.BOLD, 18))
        panel.add(title, gbc)
        
        row += 1
        
        # Backend selection
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 1
        gbc.anchor = GridBagConstraints.WEST
        panel.add(JLabel("Backend:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.backend_combo = JComboBox(["OpenAI", "Local LLM"])
        config_data = self.extension.get_config().get_all()
        self.backend_combo.setSelectedItem("OpenAI" if config_data.get("backend") == "openai" else "Local LLM")
        
        class BackendAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.update_backend_fields()
        
        self.backend_combo.addActionListener(BackendAction(self))
        panel.add(self.backend_combo, gbc)
        
        row += 1
        
        # API Key (OpenAI)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.api_key_label = JLabel("API Key:")
        panel.add(self.api_key_label, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.api_key_field = JPasswordField(30)
        self.api_key_field.setText(config_data.get("api_key", ""))
        panel.add(self.api_key_field, gbc)
        
        row += 1
        
        # Local LLM URL
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.local_url_label = JLabel("Local LLM URL:")
        panel.add(self.local_url_label, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.local_url_field = JTextField(config_data.get("local_url", "http://localhost:1234/v1/chat/completions"))
        panel.add(self.local_url_field, gbc)
        
        row += 1
        
        # Local LLM API Key
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.local_api_key_label = JLabel("Local LLM API Key:")
        panel.add(self.local_api_key_label, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.local_api_key_field = JPasswordField(30)
        self.local_api_key_field.setText(config_data.get("local_api_key", ""))
        panel.add(self.local_api_key_field, gbc)
        
        row += 1
        
        # Custom Header Name (for Local LLM)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.local_custom_header_label = JLabel("Custom Header Name:")
        panel.add(self.local_custom_header_label, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.local_custom_header_field = JTextField(config_data.get("local_custom_header", ""))
        self.local_custom_header_field.setToolTipText("e.g., x-api-key, Authorization, api-key")
        panel.add(self.local_custom_header_field, gbc)
        
        row += 1
        
        # Header Format (for Local LLM)
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.local_header_format_label = JLabel("Header Format:")
        panel.add(self.local_header_format_label, gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.local_header_format_combo = JComboBox(["Bearer", "Basic", "None"])
        selected_format = config_data.get("local_header_format", "Bearer")
        self.local_header_format_combo.setSelectedItem(selected_format)
        self.local_header_format_combo.setToolTipText("Bearer: 'Bearer {key}', Basic: 'Basic {key}', None: '{key}'")
        panel.add(self.local_header_format_combo, gbc)
        
        row += 1
        
        # Model
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        panel.add(JLabel("Model:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.model_field = JTextField(config_data.get("model", "gpt-3.5-turbo"))
        panel.add(self.model_field, gbc)
        
        row += 1
        
        # Timeout
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        panel.add(JLabel("Timeout (seconds):"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.timeout_field = JTextField(str(config_data.get("timeout", 60)))
        panel.add(self.timeout_field, gbc)
        
        row += 1
        
        # Buttons
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER
        
        button_panel = JPanel()
        
        save_btn = JButton("Save Settings")
        save_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class SaveAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.save_settings()
        save_btn.addActionListener(SaveAction(self))
        button_panel.add(save_btn)
        
        test_btn = JButton("Test Connection")
        test_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class TestAction(ActionListener):
            def __init__(self, extension):
                self.extension = extension
            def actionPerformed(self, event):
                self.extension.test_connection()
        test_btn.addActionListener(TestAction(self.extension))
        button_panel.add(test_btn)
        
        panel.add(button_panel, gbc)
        
        row += 1
        
        # Signature
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER
        gbc.insets = Insets(20, 10, 10, 10)
        signature = JLabel("Diabl0-Sec")
        signature.setFont(Font("Arial", Font.ITALIC, 14))
        signature.setForeground(Color(128, 128, 128))
        panel.add(signature, gbc)
        
        # Update field visibility
        self.update_backend_fields()
        
        return panel
    
    
    def create_chat_panel(self):
        """Create chat interface."""
        panel = JPanel(BorderLayout())
        
        # Chat area
        self.chat_area = JTextArea()
        self.chat_area.setEditable(False)
        self.chat_area.setFont(Font("Monospaced", Font.BOLD, 17))  # Bold 17pt font for AI responses
        self.chat_area.setLineWrap(True)
        self.chat_area.setWrapStyleWord(True)
        self.chat_area.setText("Chat with Atlas AI for security questions...\n\n")
        
        chat_scroll = JScrollPane(self.chat_area)
        chat_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        
        # Input area
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        self.input_area = JTextArea(4, 50)
        self.input_area.setFont(Font("Monospaced", Font.PLAIN, 14))  # Bigger font
        self.input_area.setLineWrap(True)
        self.input_area.setWrapStyleWord(True)
        
        # Enter key handler
        class ChatKeyListener(KeyAdapter):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def keyPressed(self, event):
                if event.getKeyCode() == KeyEvent.VK_ENTER and not event.isControlDown():
                    self.ui_builder.send_chat_message()
                    event.consume()
        self.input_area.addKeyListener(ChatKeyListener(self))
        
        input_scroll = JScrollPane(self.input_area)
        input_panel.add(input_scroll, BorderLayout.CENTER)
        
        # Buttons
        button_panel = JPanel()
        
        send_btn = JButton("Send")
        send_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class SendAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.send_chat_message()
        send_btn.addActionListener(SendAction(self))
        button_panel.add(send_btn)
        
        clear_btn = JButton("Clear")
        clear_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class ClearAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.chat_area.setText("")
                self.ui_builder.append_to_chat("Chat cleared\n")
        clear_btn.addActionListener(ClearAction(self))
        button_panel.add(clear_btn)
        
        input_panel.add(button_panel, BorderLayout.EAST)
        
        # Split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, chat_scroll, input_panel)
        split_pane.setDividerLocation(400)
        split_pane.setResizeWeight(0.8)
        
        panel.add(split_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_help_panel(self):
        """Create help panel."""
        panel = JPanel(BorderLayout())
        
        help_text = JTextArea()
        help_text.setEditable(False)
        help_text.setFont(Font("Monospaced", Font.BOLD, 17))  # Bold 17pt font
        help_text.setLineWrap(True)
        help_text.setWrapStyleWord(True)
        
        help_content = """Atlas AI Pro - Advanced Security Analysis

EXTENSION STRUCTURE:

1. ATLAS AI CONFIG TAB
   • Settings: Configure AI backend (OpenAI or Local LLM)
   • Chat: Interactive chat with Atlas AI
   • Help: This documentation

2. ATLAS AI ANALYSIS TAB
   • General Analysis: Results from context menu actions
   • Scanner Findings: Scanner issue analyses and exploitation vectors

FEATURES:

1. HTTP REQUEST ANALYSIS
   • Right-click any HTTP message → "Analyze Request"
   • Analyzes request headers, parameters, and body
   • Results appear in Atlas AI Analysis → General Analysis

2. HTTP RESPONSE ANALYSIS
   • Right-click any HTTP message → "Analyze Response"
   • Analyzes response headers and body
   • Results appear in Atlas AI Analysis → General Analysis

3. FULL VULNERABILITY DETECTION
   • Right-click any HTTP message → "Find Vulnerabilities (Full)"
   • Complete analysis of both request and response
   • Detects: SQLi, XSS, XXE, SSRF, Command Injection, IDOR, etc.

4. EXPLAIN SELECTION
   • Highlight any text in Burp → Right-click → "Explain Selection"
   • AI explains what the selected content does
   • Shows in message editor Atlas AI tab

5. SCANNER FINDING ANALYSIS
   • Right-click scanner issue → "Analyze & Explain Finding"
   • Detailed vulnerability explanation
   • Results appear in Atlas AI Analysis → Scanner Findings

6. EXPLOITATION VECTORS
   • Right-click scanner issue → "Suggest Exploitation"
   • Multiple attack vectors and payloads
   • Results appear in Atlas AI Analysis → Scanner Findings

7. REQUEST/RESPONSE IN MESSAGE TABS
   • Click "Atlas AI" tab in any HTTP message editor
   • Full security analysis of the exchange

USAGE:
1. Configure AI backend in Atlas AI Config → Settings
2. Use context menus for analysis
3. View results in Atlas AI Analysis tab
4. Chat for specific questions in Atlas AI Config → Chat

Version: 5.2.0
Compatible with Burp Suite 2025.x"""
        
        help_text.setText(help_content)
        help_scroll = JScrollPane(help_text)
        panel.add(help_scroll, BorderLayout.CENTER)
        
        return panel
    
    def update_backend_fields(self):
        """Update field visibility based on backend selection."""
        is_openai = self.backend_combo.getSelectedItem() == "OpenAI"
        
        self.api_key_label.setVisible(is_openai)
        self.api_key_field.setVisible(is_openai)
        self.local_url_label.setVisible(not is_openai)
        self.local_url_field.setVisible(not is_openai)
        self.local_api_key_label.setVisible(not is_openai)
        self.local_api_key_field.setVisible(not is_openai)
        self.local_custom_header_label.setVisible(not is_openai)
        self.local_custom_header_field.setVisible(not is_openai)
        self.local_header_format_label.setVisible(not is_openai)
        self.local_header_format_combo.setVisible(not is_openai)
        
        if is_openai:
            self.model_field.setText("gpt-3.5-turbo")
        else:
            self.model_field.setText("local-model")
    
    def save_settings(self):
        """Save settings from UI."""
        try:
            backend = "openai" if self.backend_combo.getSelectedItem() == "OpenAI" else "local"
            api_key = "".join(self.api_key_field.getPassword())
            local_url = self.local_url_field.getText().strip()
            local_api_key = "".join(self.local_api_key_field.getPassword())
            model = self.model_field.getText().strip()
            
            try:
                timeout = int(self.timeout_field.getText().strip())
                if timeout < 10:
                    timeout = 10
                elif timeout > 300:
                    timeout = 300
            except:
                timeout = 60
            
            local_custom_header = self.local_custom_header_field.getText().strip()
            local_header_format = self.local_header_format_combo.getSelectedItem()
            
            settings = {
                "backend": backend,
                "api_key": api_key,
                "local_url": local_url,
                "local_api_key": local_api_key,
                "local_custom_header": local_custom_header,
                "local_header_format": local_header_format,
                "model": model,
                "timeout": timeout
            }
            
            self.extension.save_settings(settings)
            
        except Exception as e:
            self.append_to_chat("ERROR: Failed to save settings - " + str(e) + "\n")
    
    def send_chat_message(self):
        """Send chat message."""
        message = self.input_area.getText().strip()
        if not message:
            return
        
        self.input_area.setText("")
        self.extension.send_chat_message(message)
    
    def append_to_chat(self, text):
        """Append text to chat area."""
        if self.chat_area:
            self.chat_area.append(text)
            self.chat_area.setCaretPosition(self.chat_area.getDocument().getLength())
    
    def show_in_analysis_panel(self, text):
        """Show text in analysis panel."""
        if self.analysis_area:
            self.analysis_area.setText(text)
            self.analysis_area.setCaretPosition(0)
    
    def create_config_panel(self):
        """Create combined config panel with settings and help."""
        panel = JPanel(BorderLayout())
        
        # Create tabbed pane for config
        config_tabs = JTabbedPane()
        
        # Settings tab
        settings_panel = self.create_settings_panel()
        config_tabs.addTab("Settings", settings_panel)
        
        # Chat tab
        chat_panel = self.create_chat_panel()
        config_tabs.addTab("Chat", chat_panel)
        
        # Help tab
        help_panel = self.create_help_panel()
        config_tabs.addTab("Help", help_panel)
        
        panel.add(config_tabs, BorderLayout.CENTER)
        return panel
    
    def create_enhanced_analysis_panel(self):
        """Create enhanced analysis panel with tabs for different analysis types."""
        panel = JPanel(BorderLayout())
        
        # Title
        title_panel = JPanel()
        title = JLabel("Security Analysis Results")
        title.setFont(Font("Arial", Font.BOLD, 16))
        title_panel.add(title)
        panel.add(title_panel, BorderLayout.NORTH)
        
        # Tabbed pane for different analysis types
        self.analysis_tabbed_pane = JTabbedPane()
        
        # General Analysis tab (for context menu analyses)
        general_panel = JPanel(BorderLayout())
        self.analysis_area = JTextArea()
        self.analysis_area.setEditable(False)
        self.analysis_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self.analysis_area.setLineWrap(True)
        self.analysis_area.setWrapStyleWord(True)
        self.analysis_area.setText("Analysis results will appear here...\n\nUse the context menu in Burp to analyze requests, responses, or scanner findings.")
        
        analysis_scroll = JScrollPane(self.analysis_area)
        general_panel.add(analysis_scroll, BorderLayout.CENTER)
        
        # Control panel for general analysis
        general_control = JPanel()
        clear_btn = JButton("Clear")
        clear_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class ClearGeneralAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.analysis_area.setText("")
        clear_btn.addActionListener(ClearGeneralAction(self))
        general_control.add(clear_btn)
        general_panel.add(general_control, BorderLayout.SOUTH)
        
        self.analysis_tabbed_pane.addTab("General Analysis", general_panel)
        
        # Scanner Findings tab
        scanner_panel = JPanel(BorderLayout())
        self.scanner_analysis_area = JTextArea()
        self.scanner_analysis_area.setEditable(False)
        self.scanner_analysis_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self.scanner_analysis_area.setLineWrap(True)
        self.scanner_analysis_area.setWrapStyleWord(True)
        self.scanner_analysis_area.setText("Scanner finding analyses will appear here...\n\nRight-click on scanner issues and select 'Atlas AI: Analyze & Explain Finding' or 'Atlas AI: Suggest Exploitation'.")
        
        scanner_scroll = JScrollPane(self.scanner_analysis_area)
        scanner_panel.add(scanner_scroll, BorderLayout.CENTER)
        
        # Control panel for scanner analysis
        scanner_control = JPanel()
        clear_scanner_btn = JButton("Clear")
        clear_scanner_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class ClearScannerAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.scanner_analysis_area.setText("")
        clear_scanner_btn.addActionListener(ClearScannerAction(self))
        scanner_control.add(clear_scanner_btn)
        scanner_panel.add(scanner_control, BorderLayout.SOUTH)
        
        self.analysis_tabbed_pane.addTab("Scanner Findings", scanner_panel)
        
        panel.add(self.analysis_tabbed_pane, BorderLayout.CENTER)
        return panel
    
    def analyze_scanner_finding_in_tab(self, issue, analysis_type):
        """Analyze scanner finding and show in the main analysis tab."""
        # Switch to scanner findings tab
        if self.analysis_tabbed_pane:
            self.analysis_tabbed_pane.setSelectedIndex(1)  # Scanner Findings tab
        
        # Show loading message
        if analysis_type == "exploitation":
            self.scanner_analysis_area.setText("Generating exploitation vectors...\n\n" + self._get_issue_summary(issue))
        else:
            self.scanner_analysis_area.setText("Analyzing scanner finding...\n\n" + self._get_issue_summary(issue))
        
        # Build issue text
        issue_text = self.extension._build_scanner_issue_text(issue)
        
        # Analyze in background
        def analyze():
            try:
                if analysis_type == "exploitation":
                    # Exploitation-focused prompt
                    prompt = """Exploitation vectors:

""" + issue_text + """

IMPORTANT: Technical output only. Focus on practical exploitation.

ATTACK VECTORS:
- Specific attack techniques
- Step-by-step exploitation
- Required conditions

PAYLOADS:
- Working exploit payloads
- Variations for different contexts
- Bypass techniques

TOOLS:
- Recommended tools
- Tool commands/configuration
- Automation scripts

CHAINING:
- How to chain with other vulnerabilities
- Privilege escalation paths
- Full compromise scenarios

IMPACT DEMONSTRATION:
- Proof of concept code
- Data extraction methods
- System compromise indicators"""
                    title = "EXPLOITATION ANALYSIS"
                else:
                    # Standard comprehensive analysis
                    prompt = """Comprehensive security analysis of this scanner finding.

""" + issue_text + """

IMPORTANT: Provide a detailed technical analysis. Be concise but thorough.

VULNERABILITY ANALYSIS:
- Type and classification
- Root cause
- Attack vectors

VERIFICATION:
- How to confirm this is a true positive
- Manual testing steps
- Expected behavior vs actual behavior

EXPLOITATION:
- Proof of concept
- Potential impact
- Attack scenarios

FALSE POSITIVE CHECK:
- Common false positive indicators
- Verification methods

REMEDIATION:
- Specific code fixes
- Security controls needed
- Testing approach"""
                    title = "AI VULNERABILITY ANALYSIS"
                
                response = self.extension.get_current_adapter().send_message(prompt)
                result = title + "\n" + "=" * 60 + "\n\n"
                result += "Issue: " + issue.getIssueName() + "\n"
                result += "URL: " + str(issue.getUrl()) + "\n"
                result += "=" * 60 + "\n\n"
                result += response
                
                SwingUtilities.invokeLater(lambda: self.show_scanner_result(result))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self.show_scanner_result("Error during analysis: " + str(e)))
        
        import threading
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()
    
    def _get_issue_summary(self, issue):
        """Get a brief summary of the issue."""
        summary = "Issue: " + issue.getIssueName() + "\n"
        summary += "URL: " + str(issue.getUrl()) + "\n"
        summary += "Severity: " + issue.getSeverity() + "\n"
        summary += "Confidence: " + issue.getConfidence()
        return summary
    
    def show_scanner_result(self, result):
        """Show scanner analysis result."""
        if self.scanner_analysis_area:
            self.scanner_analysis_area.setText(result)
            self.scanner_analysis_area.setCaretPosition(0)