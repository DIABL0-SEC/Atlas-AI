# -*- coding: utf-8 -*-
# Atlas AI Scanner Tab - Scanner Issue Tab

from burp import IMessageEditorTab
from java.awt import Font
from javax.swing import JTextArea, JScrollPane, SwingUtilities
import threading

class AtlasScannerTab(IMessageEditorTab):
    """Atlas AI tab that appears in scanner issue details."""
    
    def __init__(self, extension, controller, editable, issue):
        self.extension = extension
        self.controller = controller
        self.editable = editable
        self.issue = issue
        
        # Create UI
        self.text_area = JTextArea()
        self.text_area.setEditable(False)
        self.text_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self.text_area.setLineWrap(True)
        self.text_area.setWrapStyleWord(True)
        
        self.scroll_pane = JScrollPane(self.text_area)
        
        # Analysis state
        self.analyzed = False
        self.analysis_type = "standard"  # standard or exploitation
    
    def getTabCaption(self):
        """Return tab caption."""
        return "AI Analysis"
    
    def getUiComponent(self):
        """Return UI component."""
        return self.scroll_pane
    
    def isEnabled(self, content, isRequest):
        """Check if tab should be enabled."""
        # Only enable if extension is configured and we have an issue
        return self.extension.get_current_adapter() is not None and self.issue is not None
    
    def setMessage(self, content, isRequest):
        """Handle when user switches to this tab."""
        # Check for pending exploitation request
        pending_exploitation = self.extension.get_pending_exploitation_request()
        if pending_exploitation and pending_exploitation == self.issue:
            self.analysis_type = "exploitation"
            self.analyzed = False  # Force re-analysis for exploitation
        
        # Only analyze once per issue/type
        if self.analyzed:
            return
        
        if not self.extension.get_current_adapter():
            self.text_area.setText("Atlas AI not configured.\n\nPlease configure your API settings in the Atlas AI tab.")
            return
        
        if not self.issue:
            self.text_area.setText("No scanner issue to analyze")
            return
        
        # Perform analysis
        self.analyze_scanner_issue()
        self.analyzed = True
    
    def analyze_scanner_issue(self):
        """Analyze the scanner issue."""
        # Show loading message
        if self.analysis_type == "exploitation":
            self.text_area.setText("Generating exploitation vectors...\n\n" + self._get_issue_summary())
        else:
            self.text_area.setText("Analyzing scanner finding...\n\n" + self._get_issue_summary())
        
        # Build detailed issue text
        issue_text = self.extension._build_scanner_issue_text(self.issue)
        
        # Analyze in background
        def analyze():
            try:
                if self.analysis_type == "exploitation":
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
                result += "Issue: " + self.issue.getIssueName() + "\n"
                result += "URL: " + str(self.issue.getUrl()) + "\n"
                result += "=" * 60 + "\n\n"
                result += response
                
                SwingUtilities.invokeLater(lambda: self.show_result(result))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self.show_result("Error during analysis: " + str(e)))
        
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()
    
    def _get_issue_summary(self):
        """Get a brief summary of the issue."""
        summary = "Issue: " + self.issue.getIssueName() + "\n"
        summary += "URL: " + str(self.issue.getUrl()) + "\n"
        summary += "Severity: " + self.issue.getSeverity() + "\n"
        summary += "Confidence: " + self.issue.getConfidence()
        return summary
    
    def show_result(self, result):
        """Show analysis result."""
        self.text_area.setText(result)
        self.text_area.setCaretPosition(0)
    
    def getMessage(self):
        """Return the currently displayed message."""
        # This tab doesn't modify messages
        return None
    
    def isModified(self):
        """Check if content has been modified."""
        # This tab is read-only
        return False
    
    def getSelectedData(self):
        """Return selected data."""
        return self.text_area.getSelectedText()