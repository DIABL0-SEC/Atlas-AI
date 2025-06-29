# -*- coding: utf-8 -*-
# Atlas AI Configuration Manager

import json

class AtlasConfig:
    """Manages configuration for Atlas AI extension."""
    
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.config = {
            "backend": "openai",  # openai or local
            "api_key": "",
            "local_url": "http://localhost:1234/v1/chat/completions",
            "local_api_key": "",
            "local_custom_header": "",  # Custom header name for local LLM
            "local_header_format": "Bearer",  # Header format: Bearer, Basic, or None
            "model": "gpt-3.5-turbo",
            "temperature": 0.3,
            "max_tokens": 3000,
            "timeout": 60
        }
        self.load()
    
    def load(self):
        """Load configuration from Burp Suite settings."""
        try:
            saved_config = self.callbacks.loadExtensionSetting("atlas_ai_config")
            if saved_config:
                loaded = json.loads(saved_config)
                self.config.update(loaded)
        except Exception as e:
            print("[Atlas AI] Error loading config: " + str(e))
    
    def save(self):
        """Save configuration to Burp Suite settings."""
        try:
            config_json = json.dumps(self.config)
            self.callbacks.saveExtensionSetting("atlas_ai_config", config_json)
        except Exception as e:
            print("[Atlas AI] Error saving config: " + str(e))
    
    def get(self, key, default=None):
        """Get a configuration value."""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set a configuration value."""
        self.config[key] = value
        self.save()
    
    def update(self, updates):
        """Update multiple configuration values."""
        self.config.update(updates)
        self.save()
    
    def get_all(self):
        """Get all configuration values."""
        return self.config.copy()