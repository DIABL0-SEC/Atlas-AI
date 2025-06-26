# -*- coding: utf-8 -*-
# Atlas AI Tab - Message Editor Tab

from burp import IMessageEditorTab
from java.awt import Font
from javax.swing import JTextArea, JScrollPane, SwingUtilities
import threading

class AtlasAITab(IMessageEditorTab):
    """Atlas AI tab that appears in HTTP message editors."""
    
    def __init__(self, extension, controller, editable):
        self.extension = extension
        self.controller = controller
        self.editable = editable
        
        # Create UI with bold 17pt font
        self.text_area = JTextArea()
        self.text_area.setEditable(False)
        self.text_area.setFont(Font("Monospaced", Font.BOLD, 17))  # Bold 17pt font for AI responses
        self.text_area.setLineWrap(True)
        self.text_area.setWrapStyleWord(True)
        
        self.scroll_pane = JScrollPane(self.text_area)
        
        # Analysis state
        self.current_content = None
        self.analyzing = False
        self.last_analysis_key = None  # Track what analysis was performed
    
    def getTabCaption(self):
        """Return tab caption."""
        return "Atlas AI"
    
    def getUiComponent(self):
        """Return UI component."""
        return self.scroll_pane
    
    def isEnabled(self, content, isRequest):
        """Check if tab should be enabled."""
        # Only enable if extension is configured
        return self.extension.get_current_adapter() is not None
    
    def setMessage(self, content, isRequest):
        """Handle when user switches to this tab."""
        if content is None:
            self.text_area.setText("No content to analyze")
            return
        
        # Get the request and response
        request = self.controller.getRequest()
        response = self.controller.getResponse()
        service = self.controller.getHttpService()
        
        # Create a key for the current state
        current_key = (request, response)
        
        # Check for pending analysis request (from context menu)
        pending_request = self.extension.get_pending_analysis_request()
        if pending_request:
            # Process the analysis request
            self.perform_analysis(pending_request['type'], 
                                pending_request['request'], 
                                pending_request['response'], 
                                pending_request['service'])
            self.current_content = current_key
            return
        
        # Check for pending selection analysis
        pending_analysis = self.extension.get_pending_selection_analysis()
        if pending_analysis:
            # Process the selection analysis
            self.analyze_selection(pending_analysis)
            self.current_content = current_key
            return
        
        # Don't reset if we're already showing content for this message
        # unless a new analysis was explicitly requested
        if self.current_content == current_key and not self.analyzing:
            return
        
        self.current_content = current_key
        
        if not self.extension.get_current_adapter():
            self.text_area.setText("Atlas AI not configured.\n\nPlease configure your API settings in the Atlas AI tab.")
            return
        
        if not request:
            self.text_area.setText("No request to analyze")
            return
        
        # Only set placeholder if we haven't analyzed this content yet
        if self.last_analysis_key != current_key:
            self.text_area.setText("No AI query yet")
            self.analyzing = False
    
    def show_result(self, result):
        """Show analysis result."""
        self.text_area.setText(result)
        self.text_area.setCaretPosition(0)
        # Update the analysis key to prevent resetting when switching tabs
        if self.current_content:
            self.last_analysis_key = self.current_content
    
    def analyze_selection(self, selected_text):
        """Analyze selected text and show result in this tab."""
        if not self.extension.get_current_adapter():
            self.text_area.setText("Atlas AI not configured.\n\nPlease configure your API settings in the Atlas AI tab.")
            return
        
        # Show loading message
        self.text_area.setText("Analyzing selection...\n\nSelected text:\n" + selected_text[:200] + "...")
        self.analyzing = True
        
        # Analyze in background
        def analyze():
            try:
                prompt = """Security analysis of selected text.

IMPORTANT: Be concise and technical. No recommendations.

Text: """ + selected_text
                
                response = self.extension.get_current_adapter().send_message(prompt)
                result = "SELECTION ANALYSIS\n" + "=" * 60 + "\n\n" + response
                SwingUtilities.invokeLater(lambda: self.show_result(result))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self.show_result("Error: " + str(e)))
            finally:
                self.analyzing = False
        
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()
    
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
    
    def perform_analysis(self, analysis_type, request, response, service):
        """Perform the requested analysis type."""
        if not self.extension.get_current_adapter():
            self.text_area.setText("Atlas AI not configured.\n\nPlease configure your API settings in the Atlas AI tab.")
            return
        
        # Show loading message
        self.text_area.setText("Performing " + analysis_type + " analysis...")
        self.analyzing = True
        
        # Analyze in background
        def analyze():
            try:
                # Use the extension's analyze_message method
                result = self.extension.analyze_message(request, response, service, analysis_type)
                SwingUtilities.invokeLater(lambda: self.show_result(result))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self.show_result("Error: " + str(e)))
            finally:
                self.analyzing = False
        
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()