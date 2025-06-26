# -*- coding: utf-8 -*-
# Atlas AI Burp Suite Extension - Main Entry Point
# Compatible with Burp Suite Professional 2025.x

from burp import IBurpExtender

# Import the main extension class
from atlas_extension import AtlasAIExtension

class BurpExtender(IBurpExtender):
    """Main entry point for Burp Suite to load the extension."""
    
    def registerExtenderCallbacks(self, callbacks):
        """Register the extension with Burp Suite."""
        # Create and register the actual extension
        extension = AtlasAIExtension()
        extension.registerExtenderCallbacks(callbacks)