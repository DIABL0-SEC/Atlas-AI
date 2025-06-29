# -*- coding: utf-8 -*-
# Atlas AI Extension - Main Extension Class

from burp import IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation, IMessageEditorTabFactory, IScanIssue, IScannerListener
from java.awt import BorderLayout, Font, Color
from java.awt.event import ActionListener
from javax.swing import (
    JPanel, JLabel, JTabbedPane, JOptionPane, BorderFactory, 
    BoxLayout, Box, SwingUtilities
)
from java.util import ArrayList
from javax.swing import JMenuItem
from java.io import PrintWriter
import json
import threading
import time

from atlas_ui import AtlasUIBuilder
from atlas_tab import AtlasAITab
from atlas_scanner_tab import AtlasScannerTab
from atlas_scanner_findings_tab import AtlasScannerFindingsTab
from atlas_adapters import OpenAIAdapter, LocalLLMAdapter
from atlas_config import AtlasConfig

class AtlasAIExtension(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory, IScannerListener):
    """Main Atlas AI Extension class."""
    
    def registerExtenderCallbacks(self, callbacks):
        """Register extension with Burp Suite."""
        # Store references
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set up logging
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Set extension name
        callbacks.setExtensionName("Atlas AI Pro")
        
        self._stdout.println("[Atlas AI] Initializing extension...")
        
        # Initialize configuration
        self._config = AtlasConfig(callbacks)
        
        # Initialize components
        self._current_adapter = None
        self._ui_builder = AtlasUIBuilder(self)
        
        # Cache for AI responses (with size limit)
        self._response_cache = {}
        self._cache_lock = threading.Lock()
        self._max_cache_size = 100
        
        # Store pending selection analysis
        self._pending_selection_analysis = None
        
        # Store pending analysis request (for context menu actions)
        self._pending_analysis_request = None
        
        # Store pending exploitation request (for scanner issues)
        self._pending_exploitation_request = None
        
        # Scanner findings tab
        self._scanner_findings_tab = None
        
        # Create UI
        self._create_ui()
        
        # Initialize adapter if configured
        self._init_adapter()
        
        # Register with Burp
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerScannerListener(self)
        
        self._stdout.println("[Atlas AI] Extension loaded successfully!")
        self._log_to_ui("Welcome to Atlas AI Pro! Configure your settings in the 'Atlas AI Config' tab to get started.")
    
    def getTabCaption(self):
        """Return tab caption."""
        return "Atlas AI"
    
    def getUiComponent(self):
        """Return UI component."""
        return self._main_panel
    
    def createNewInstance(self, controller, editable):
        """Create a new instance of Atlas AI tab for message editors."""
        # Check if this is a scanner issue tab
        try:
            # Try to get the issue from the controller
            if hasattr(controller, 'getIssue'):
                issue = controller.getIssue()
                if issue and isinstance(issue, IScanIssue):
                    # This is a scanner issue tab
                    return AtlasScannerTab(self, controller, editable, issue)
        except Exception as e:
            self._stderr.println("[Atlas AI] Error checking for scanner issue: " + str(e))
        
        # Regular message editor tab
        return AtlasAITab(self, controller, editable)
    
    def createMenuItems(self, invocation):
        """Create context menu items."""
        menu_items = ArrayList()
        context = invocation.getInvocationContext()
        
        # HTTP message contexts
        if context in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE,
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY
        ]:
            # Analyze Request
            req_item = JMenuItem("Atlas AI: Analyze Request")
            class ReqAction(ActionListener):
                def __init__(self, ext, inv):
                    self.extender = ext
                    self.invocation = inv
                def actionPerformed(self, event):
                    self.extender.analyze_in_tab(self.invocation, "request")
            req_item.addActionListener(ReqAction(self, invocation))
            menu_items.add(req_item)
            
            # Analyze Response
            resp_item = JMenuItem("Atlas AI: Analyze Response")
            class RespAction(ActionListener):
                def __init__(self, ext, inv):
                    self.extender = ext
                    self.invocation = inv
                def actionPerformed(self, event):
                    self.extender.analyze_in_tab(self.invocation, "response")
            resp_item.addActionListener(RespAction(self, invocation))
            menu_items.add(resp_item)
            
            # Explain selected text
            explain_item = JMenuItem("Atlas AI: Explain Selection")
            class ExplainAction(ActionListener):
                def __init__(self, ext, inv):
                    self.extender = ext
                    self.invocation = inv
                def actionPerformed(self, event):
                    self.extender.explain_selection(self.invocation)
            explain_item.addActionListener(ExplainAction(self, invocation))
            menu_items.add(explain_item)
            
            # Generate payloads
            payload_item = JMenuItem("Atlas AI: Generate Attack Vectors")
            class PayloadAction(ActionListener):
                def __init__(self, ext, inv):
                    self.extender = ext
                    self.invocation = inv
                def actionPerformed(self, event):
                    self.extender.analyze_in_tab(self.invocation, "payloads")
            payload_item.addActionListener(PayloadAction(self, invocation))
            menu_items.add(payload_item)
        
        # Scanner results context or Target tab with issues
        if context in [IContextMenuInvocation.CONTEXT_SCANNER_RESULTS, 
                       IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                       IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE]:
            # Check if scanner issues are selected
            issues = invocation.getSelectedIssues()
            if issues and len(issues) > 0:
                # Analyze scanner finding
                scanner_item = JMenuItem("Atlas AI: Analyze & Explain Finding")
                class ScannerAction(ActionListener):
                    def __init__(self, ext, inv):
                        self.extender = ext
                        self.invocation = inv
                    def actionPerformed(self, event):
                        self.extender.analyze_scanner_finding(self.invocation)
                scanner_item.addActionListener(ScannerAction(self, invocation))
                menu_items.add(scanner_item)
                
                # Suggest exploitation
                exploit_item = JMenuItem("Atlas AI: Suggest Exploitation")
                class ExploitAction(ActionListener):
                    def __init__(self, ext, inv):
                        self.extender = ext
                        self.invocation = inv
                    def actionPerformed(self, event):
                        self.extender.suggest_exploitation(self.invocation)
                exploit_item.addActionListener(ExploitAction(self, invocation))
                menu_items.add(exploit_item)
        
        return menu_items
    
    def _create_ui(self):
        """Create the main UI panel."""
        self._main_panel = JPanel(BorderLayout())
        
        # Header
        header = self._create_header()
        self._main_panel.add(header, BorderLayout.NORTH)
        
        # Tabbed pane
        self._tabbed_pane = JTabbedPane()
        
        # Atlas AI Config tab (combines settings and help)
        self._config_panel = self._ui_builder.create_config_panel()
        self._tabbed_pane.addTab("Atlas AI Config", self._config_panel)
        
        # Atlas AI Analysis tab (includes scanner findings and general analysis)
        self._analysis_panel = self._ui_builder.create_enhanced_analysis_panel()
        self._tabbed_pane.addTab("Atlas AI Analysis", self._analysis_panel)
        
        # Scanner Findings AI tab
        self._scanner_findings_tab = AtlasScannerFindingsTab(self)
        self._tabbed_pane.addTab("Scanner Findings AI", self._scanner_findings_tab.get_component())
        self._scanner_findings_tab.set_tab_index(2)  # Third tab (0-indexed)
        
        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)
    
    def _create_header(self):
        """Create header panel."""
        header = JPanel()
        header.setLayout(BoxLayout(header, BoxLayout.X_AXIS))
        header.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        title = JLabel("Atlas AI Pro - Advanced Security Analysis")
        title.setFont(Font("Arial", Font.BOLD, 20))
        header.add(title)
        
        header.add(Box.createHorizontalGlue())
        
        self._status_label = JLabel("Not Configured")
        self._status_label.setForeground(Color.RED)
        self._status_label.setFont(Font("Arial", Font.PLAIN, 14))
        header.add(self._status_label)
        
        return header
    
    def _init_adapter(self):
        """Initialize the AI adapter based on saved configuration."""
        config_data = self._config.get_all()
        backend = config_data.get("backend", "openai")
        
        if backend == "openai" and config_data.get("api_key"):
            self._current_adapter = OpenAIAdapter(
                config_data["api_key"],
                config_data.get("model", "gpt-3.5-turbo"),
                timeout=config_data.get("timeout", 60)
            )
            # Set Burp callbacks for HTTP requests
            self._current_adapter.set_burp_callbacks(self._callbacks)
            self._update_status("Connected to OpenAI", Color.GREEN)
        elif backend == "local" and config_data.get("local_url"):
            self._current_adapter = LocalLLMAdapter(
                config_data["local_url"],
                config_data.get("model", "local-model"),
                timeout=config_data.get("timeout", 60),
                api_key=config_data.get("local_api_key", None),
                config=config_data
            )
            # Set Burp callbacks for HTTP requests
            self._current_adapter.set_burp_callbacks(self._callbacks)
            self._update_status("Connected to Local LLM", Color.GREEN)
        else:
            self._current_adapter = None
            self._update_status("Not Configured", Color.RED)
    
    def save_settings(self, settings):
        """Save settings and reinitialize adapter."""
        self._config.update(settings)
        self._init_adapter()
        
        if self._current_adapter:
            self._log_to_ui("Settings saved! AI analysis ready.")
        else:
            self._log_to_ui("Please configure your AI backend.")
    
    def test_connection(self):
        """Test the AI connection."""
        if not self._current_adapter:
            JOptionPane.showMessageDialog(self._main_panel,
                "Please save your settings first",
                "No Configuration",
                JOptionPane.WARNING_MESSAGE)
            return
        
        self._log_to_ui("Testing connection...")
        
        def test():
            try:
                from atlas_prompts import AtlasPrompts
                response = self._current_adapter.send_message(AtlasPrompts.CONNECTION_TEST)
                self._log_to_ui("SUCCESS: " + response)
            except Exception as e:
                self._log_to_ui("ERROR: Connection failed - " + str(e))
        
        thread = threading.Thread(target=test)
        thread.daemon = True
        thread.start()
    
    def analyze_message(self, request_bytes, response_bytes, service, analysis_type="request"):
        """Analyze HTTP message and return result."""
        if not self._current_adapter:
            return "Atlas AI not configured. Please configure API settings."
        
        try:
            # Build cache key using SHA256 for better collision resistance
            import hashlib
            cache_content = str(request_bytes) + str(response_bytes) + analysis_type
            cache_key = hashlib.sha256(cache_content.encode('utf-8')).hexdigest()
            
            # Check cache (skip cache for payloads to allow regeneration)
            if analysis_type != "payloads":
                with self._cache_lock:
                    if cache_key in self._response_cache:
                        return self._response_cache[cache_key]
            
            # Build analysis based on type
            if analysis_type == "request":
                analysis = self._build_http_analysis(request_bytes, None, service)
            elif analysis_type == "response":
                analysis = self._build_http_analysis(None, response_bytes, service)
            else:
                analysis = self._build_http_analysis(request_bytes, response_bytes, service)
            
            # Get appropriate prompt
            prompt = self._get_analysis_prompt(analysis_type)
            
            # Get AI response
            if analysis_type == "payloads" and "{http_context}" in prompt:
                # For payload generation, format the prompt with the HTTP context
                formatted_prompt = prompt.format(http_context=analysis)
                ai_response = self._current_adapter.send_message(formatted_prompt)
            else:
                ai_response = self._current_adapter.send_message(prompt + "\n\n" + analysis)
            
            # Format result
            result = self._format_analysis_result(ai_response, service, analysis_type)
            
            # Cache result with size limit (skip caching for payloads)
            if analysis_type != "payloads":
                with self._cache_lock:
                    self._response_cache[cache_key] = result
                    # Remove oldest entries if cache is too large
                    if len(self._response_cache) > self._max_cache_size:
                        # Remove the first (oldest) item
                        oldest_key = next(iter(self._response_cache))
                        del self._response_cache[oldest_key]
            
            return result
            
        except Exception as e:
            import traceback
            error_msg = str(e) if str(e).strip() else repr(e)
            full_error = traceback.format_exc()
            self._stderr.println("[Atlas AI] Analysis error: " + error_msg)
            self._stderr.println("[Atlas AI] Full traceback:\n" + full_error)
            return "Error during analysis: " + error_msg
    
    def _build_http_analysis(self, request_bytes, response_bytes, service):
        """Build HTTP analysis text."""
        analysis = ""
        
        # Analyze request
        if request_bytes:
            request_info = self._helpers.analyzeRequest(service, request_bytes)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            headers = request_info.getHeaders()
            
            analysis += "=== REQUEST ===\n"
            analysis += "URL: " + url + "\n"
            analysis += "Method: " + method + "\n\n"
            
            # Headers
            analysis += "Headers:\n"
            for i, header in enumerate(headers):
                if i == 0:  # Skip request line
                    continue
                analysis += header + "\n"
                if i > 15:
                    analysis += "[... more headers ...]\n"
                    break
            
            # Body
            body_offset = request_info.getBodyOffset()
            if body_offset < len(request_bytes):
                body = self._helpers.bytesToString(request_bytes[body_offset:])
                if len(body) > 3000:
                    body = body[:3000] + "\n[TRUNCATED]"
                if body:
                    analysis += "\nBody:\n" + body + "\n"
        
        # Analyze response
        if response_bytes:
            response_info = self._helpers.analyzeResponse(response_bytes)
            analysis += "\n=== RESPONSE ===\n"
            analysis += "Status: " + str(response_info.getStatusCode()) + "\n"
            
            # Response headers
            resp_headers = response_info.getHeaders()
            analysis += "\nHeaders:\n"
            for i, header in enumerate(resp_headers):
                if i == 0:  # Skip status line
                    continue
                analysis += header + "\n"
                if i > 15:
                    analysis += "[... more headers ...]\n"
                    break
            
            # Response body
            resp_body_offset = response_info.getBodyOffset()
            if resp_body_offset < len(response_bytes):
                resp_body = self._helpers.bytesToString(response_bytes[resp_body_offset:])
                if len(resp_body) > 3000:
                    resp_body = resp_body[:3000] + "\n[TRUNCATED]"
                if resp_body:
                    analysis += "\nBody:\n" + resp_body
        
        return analysis
    
    def _get_analysis_prompt(self, analysis_type):
        """Get the appropriate prompt for the analysis type."""
        from atlas_prompts import AtlasPrompts
        
        prompts = {
            "request": AtlasPrompts.REQUEST_ANALYSIS,
            "response": AtlasPrompts.RESPONSE_ANALYSIS,
            "payloads": AtlasPrompts.PAYLOAD_GENERATION,
            "explain": AtlasPrompts.SELECTION_EXPLANATION
        }
        
        return prompts.get(analysis_type, AtlasPrompts.REQUEST_ANALYSIS)
    
    def _format_analysis_result(self, ai_response, service, analysis_type):
        """Format the analysis result."""
        url = "Unknown"
        if service:
            try:
                url = str(service.getProtocol()) + "://" + str(service.getHost())
                if service.getPort() not in [80, 443]:
                    url += ":" + str(service.getPort())
            except:
                pass
        
        result = "ATLAS AI SECURITY ANALYSIS\n" + "=" * 60 + "\n"
        result += "Target: " + url + "\n"
        result += "Analysis Type: " + analysis_type.title() + "\n"
        result += "Time: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n"
        result += "=" * 60 + "\n\n"
        result += ai_response
        
        return result
    
    def analyze_in_tab(self, invocation, analysis_type):
        """Trigger analysis to show in the Atlas AI tab."""
        self._stdout.println("[Atlas AI] Analysis requested: " + analysis_type)
        
        # Get selected messages
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        
        # Store the pending analysis request for the message editor tab
        message = messages[0]
        request = message.getRequest()
        response = message.getResponse()
        service = message.getHttpService()
        
        self._pending_analysis_request = {
            'type': analysis_type,
            'request': request,
            'response': response,
            'service': service
        }
        
        # Perform analysis immediately in the main analysis tab
        def perform_analysis():
            try:
                result = self.analyze_message(request, response, service, analysis_type)
                SwingUtilities.invokeLater(lambda: self._ui_builder.show_in_analysis_panel(result))
                SwingUtilities.invokeLater(lambda: self._tabbed_pane.setSelectedIndex(1))  # Switch to analysis tab
            except Exception as e:
                self._stderr.println("[Atlas AI] Error in analyze_in_tab: " + str(e))
        
        # Run analysis in background thread
        thread = threading.Thread(target=perform_analysis)
        thread.daemon = True
        thread.start()
        
        # Log notification
        self._log_to_ui("Analysis in progress. Check the Atlas AI Analysis tab.")
    
    def explain_selection(self, invocation):
        """Explain the selected text."""
        # Get selected text from the invocation
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        
        # Get the selection bounds if available
        selection_bounds = invocation.getSelectionBounds()
        if selection_bounds:
            start = selection_bounds[0]
            end = selection_bounds[1]
            
            # Get the selected content
            message = messages[0]
            content = message.getRequest() if invocation.getInvocationContext() in [
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
            ] else message.getResponse()
            
            if content:
                selected_text = self._helpers.bytesToString(content[start:end])
                self._show_selection_analysis(selected_text)
                # Log notification to user
                self._log_to_ui("Selection analysis in progress. Check the Atlas AI Analysis tab.")
    
    def _show_selection_analysis(self, selected_text):
        """Show analysis of selected text."""
        # Store the pending analysis for the tab
        self._pending_selection_analysis = selected_text
        
        # Also analyze and show in main analysis tab
        def analyze_selection():
            try:
                prompt = "Explain this selected text from a security perspective:\n\n" + selected_text
                response = self._current_adapter.send_message(prompt)
                
                result = "SELECTION ANALYSIS\n" + "=" * 60 + "\n\n"
                result += "Selected Text:\n" + selected_text[:500]
                if len(selected_text) > 500:
                    result += "\n[... truncated ...]"
                result += "\n\n" + "=" * 60 + "\n\n"
                result += response
                
                SwingUtilities.invokeLater(lambda: self._ui_builder.show_in_analysis_panel(result))
                SwingUtilities.invokeLater(lambda: self._tabbed_pane.setSelectedIndex(1))  # Switch to analysis tab
            except Exception as e:
                self._stderr.println("[Atlas AI] Selection analysis error: " + str(e))
        
        # Run analysis in background
        thread = threading.Thread(target=analyze_selection)
        thread.daemon = True
        thread.start()
    
    def analyze_scanner_finding(self, invocation):
        """Analyze and explain a scanner finding."""
        issues = invocation.getSelectedIssues()
        if not issues:
            return
        
        if not self._current_adapter:
            self._log_to_ui("Atlas AI not configured. Please configure API settings.")
            return
        
        # Route to Scanner Findings AI tab
        self._scanner_findings_tab.process_scanner_context_menu(issues[0], "analysis")
        
        # Switch to Scanner Findings AI tab
        self._tabbed_pane.setSelectedIndex(2)  # Scanner Findings AI tab
        
        # Log notification
        self._log_to_ui("Scanner finding analysis in progress. Check the Scanner Findings AI tab.")
    
    def suggest_exploitation(self, invocation):
        """Suggest exploitation vectors for a scanner finding."""
        issues = invocation.getSelectedIssues()
        if not issues:
            return
        
        if not self._current_adapter:
            self._log_to_ui("Atlas AI not configured. Please configure API settings.")
            return
        
        # Route to Scanner Findings AI tab
        self._scanner_findings_tab.process_scanner_context_menu(issues[0], "exploitation")
        
        # Switch to Scanner Findings AI tab
        self._tabbed_pane.setSelectedIndex(2)  # Scanner Findings AI tab
        
        # Log notification
        self._log_to_ui("Exploitation analysis in progress. Check the Scanner Findings AI tab.")
    
    def _build_scanner_issue_text(self, issue):
        """Build text representation of a scanner issue."""
        text = "Issue: " + issue.getIssueName() + "\n"
        text += "URL: " + str(issue.getUrl()) + "\n"
        text += "Severity: " + issue.getSeverity() + "\n"
        text += "Confidence: " + issue.getConfidence() + "\n\n"
        
        detail = issue.getIssueDetail()
        if detail:
            text += "Details:\n" + detail[:1000]
            if len(detail) > 1000:
                text += "\n[... truncated ...]"
        
        background = issue.getIssueBackground()
        if background:
            text += "\n\nBackground:\n" + background[:500]
        
        remediation = issue.getRemediationDetail()
        if remediation:
            text += "\n\nRemediation:\n" + remediation[:500]
        
        return text
    
    def send_chat_message(self, message):
        """Send a chat message."""
        if not self._current_adapter:
            self._log_to_ui("Please configure your API settings first")
            return
        
        self._ui_builder.append_to_chat("You: " + message + "\n\n")
        
        def send():
            try:
                response = self._current_adapter.send_message(message)
                SwingUtilities.invokeLater(lambda: self._ui_builder.append_to_chat("Atlas AI: " + response + "\n\n" + "-" * 80 + "\n\n"))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self._ui_builder.append_to_chat("ERROR: " + str(e) + "\n\n"))
        
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()
    
    def _log_to_ui(self, message):
        """Log message to UI."""
        timestamp = time.strftime("%H:%M:%S")
        self._ui_builder.append_to_chat("[" + timestamp + "] " + message + "\n")
    
    def _update_status(self, status, color):
        """Update status label."""
        self._status_label.setText(status)
        self._status_label.setForeground(color)
    
    def newScanIssue(self, issue):
        """Handle new scanner issue from IScannerListener."""
        # Add to scanner findings tab
        if self._scanner_findings_tab:
            self._scanner_findings_tab.add_scanner_finding(issue)
    
    # Getters for other modules
    def get_config(self):
        return self._config
    
    def get_helpers(self):
        return self._helpers
    
    def get_stdout(self):
        return self._stdout
    
    def get_stderr(self):
        return self._stderr
    
    def get_current_adapter(self):
        return self._current_adapter
    
    def get_pending_selection_analysis(self):
        """Get and clear pending selection analysis."""
        if self._pending_selection_analysis:
            analysis = self._pending_selection_analysis
            self._pending_selection_analysis = None
            return analysis
        return None
    
    def get_pending_analysis_request(self):
        """Get and clear pending analysis request."""
        if self._pending_analysis_request:
            request = self._pending_analysis_request
            self._pending_analysis_request = None
            return request
        return None
    
    def clear_response_cache(self):
        """Clear the AI response cache."""
        self._response_cache = {}
        self._log_to_ui("Response cache cleared.")
    
    def get_pending_exploitation_request(self):
        """Get and clear pending exploitation request."""
        if self._pending_exploitation_request:
            request = self._pending_exploitation_request
            self._pending_exploitation_request = None
            return request
        return None