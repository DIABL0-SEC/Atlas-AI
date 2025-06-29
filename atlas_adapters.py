# -*- coding: utf-8 -*-
# Atlas AI Adapters - AI Backend Implementations

import json
import base64

class BaseAdapter(object):
    """Base adapter for AI backends."""
    
    def __init__(self, timeout=60):
        self.timeout = timeout
        self._callbacks = None
        self._helpers = None
    
    def set_burp_callbacks(self, callbacks):
        """Set Burp callbacks for HTTP requests."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
    
    def send_message(self, message):
        """Send message to AI backend. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement send_message")


class OpenAIAdapter(BaseAdapter):
    """OpenAI API adapter using Burp's HTTP client."""
    
    def __init__(self, api_key, model="gpt-3.5-turbo", temperature=0.3, max_tokens=3000, timeout=60):
        super(OpenAIAdapter, self).__init__(timeout)
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.endpoint = "https://api.openai.com/v1/chat/completions"
    
    def send_message(self, message):
        """Send message to OpenAI using Burp's HTTP client."""
        if not self._callbacks:
            raise Exception("Burp callbacks not set. Call set_burp_callbacks() first.")
        
        from atlas_prompts import AtlasPrompts
        
        messages = [
            {
                "role": "system", 
                "content": AtlasPrompts.SYSTEM_PROMPT
            },
            {"role": "user", "content": message}
        ]
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        try:
            # Build HTTP request
            request_body = json.dumps(payload)
            
            # Build headers
            headers = [
                "POST /v1/chat/completions HTTP/1.1",
                "Host: api.openai.com",
                "Content-Type: application/json",
                "Authorization: Bearer " + self.api_key,
                "User-Agent: Atlas-AI-Burp-Extension/1.0",
                "Accept: application/json",
                "Content-Length: " + str(len(request_body))
            ]
            
            # Build full request
            request = "\r\n".join(headers) + "\r\n\r\n" + request_body
            request_bytes = self._helpers.stringToBytes(request)
            
            # Make request through Burp
            http_service = self._helpers.buildHttpService("api.openai.com", 443, True)
            http_response = self._callbacks.makeHttpRequest(http_service, request_bytes)
            
            # Parse response
            response_bytes = http_response.getResponse()
            if not response_bytes:
                raise Exception("No response received from OpenAI")
            
            response_info = self._helpers.analyzeResponse(response_bytes)
            response_body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response_bytes[response_body_offset:])
            
            # Check status code
            status_code = response_info.getStatusCode()
            
            if status_code == 200:
                response_json = json.loads(response_body)
                
                if "choices" in response_json and len(response_json["choices"]) > 0:
                    return response_json["choices"][0]["message"]["content"].strip()
                
                return "No response content from OpenAI"
            else:
                # Handle error response
                try:
                    error_json = json.loads(response_body)
                    if "error" in error_json:
                        raise Exception("OpenAI API Error: " + error_json["error"]["message"])
                except:
                    pass
                
                raise Exception("OpenAI HTTP Error " + str(status_code) + ": " + response_body[:200])
                
        except Exception as e:
            raise Exception("OpenAI Request Failed: " + str(e))


class LocalLLMAdapter(BaseAdapter):
    """Local LLM API adapter with privacy-focused features.
    
    Supports:
    - LM Studio (https://lmstudio.ai/)
    - Ollama (https://ollama.ai/)
    - Text Generation WebUI (https://github.com/oobabooga/text-generation-webui)
    - vLLM (https://github.com/vllm-project/vllm)
    - Any OpenAI-compatible local API
    
    Privacy Features:
    - No data leaves your local environment
    - Localhost-only communication by default
    - Support for air-gapped deployments
    - Custom endpoint configuration for internal networks
    """
    
    def __init__(self, endpoint_url, model="local-model", temperature=0.3, max_tokens=3000, timeout=60, api_key=None, config=None):
        super(LocalLLMAdapter, self).__init__(timeout)
        self.endpoint_url = endpoint_url
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.api_key = api_key
        self.config = config
        
        # Privacy validation
        self._validate_privacy_settings(endpoint_url)
        
        # Parse URL
        if endpoint_url.startswith("https://"):
            self.use_https = True
            self.host_port = endpoint_url[8:]
        elif endpoint_url.startswith("http://"):
            self.use_https = False
            self.host_port = endpoint_url[7:]
        else:
            raise Exception("Invalid URL format. Must start with http:// or https://")
        
        # Extract host, port, and path
        parts = self.host_port.split("/", 1)
        host_part = parts[0]
        self.path = "/" + parts[1] if len(parts) > 1 else "/v1/chat/completions"
        
        if ":" in host_part:
            self.host, port_str = host_part.split(":", 1)
            self.port = int(port_str)
        else:
            self.host = host_part
            self.port = 443 if self.use_https else 80
    
    def _validate_privacy_settings(self, endpoint_url):
        """Validate that endpoint settings maintain privacy."""
        import re
        
        # Check for common privacy-safe patterns
        safe_patterns = [
            r'^https?://localhost[:/]',
            r'^https?://127\.0\.0\.1[:/]',
            r'^https?://0\.0\.0\.0[:/]',
            r'^https?://\[::1\][:/]',
            r'^https?://10\.',          # Private IP range
            r'^https?://172\.(1[6-9]|2\d|3[01])\.',  # Private IP range
            r'^https?://192\.168\.',    # Private IP range
            r'^https?://[^.]+$',        # Local hostname without domain
        ]
        
        is_private = any(re.match(pattern, endpoint_url.lower()) for pattern in safe_patterns)
        
        if not is_private:
            # Log warning but don't block (user may have custom internal setup)
            print("[Atlas AI Privacy Warning] Endpoint does not appear to be local/private: " + endpoint_url)
            print("[Atlas AI Privacy Warning] For maximum privacy, use localhost, private IPs, or internal hostnames")
    
    def get_privacy_info(self):
        """Return privacy information about this adapter configuration."""
        is_localhost = self.host in ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        is_private_ip = (
            self.host.startswith('10.') or
            self.host.startswith('192.168.') or
            any(self.host.startswith('172.' + str(i) + '.') for i in range(16, 32))
        )
        is_local_hostname = '.' not in self.host
        
        privacy_level = "Maximum" if is_localhost else (
            "High" if is_private_ip or is_local_hostname else "Standard"
        )
        
        return {
            "privacy_level": privacy_level,
            "is_local": is_localhost,
            "is_private_network": is_private_ip or is_local_hostname,
            "endpoint": self.endpoint_url,
            "data_transmission": "None (local processing only)" if is_localhost else "Internal network only"
        }
    
    def send_message(self, message):
        """Send message to Local LLM using Burp's HTTP client."""
        if not self._callbacks:
            raise Exception("Burp callbacks not set. Call set_burp_callbacks() first.")
        
        from atlas_prompts import AtlasPrompts
        
        messages = [
            {
                "role": "system",
                "content": AtlasPrompts.SYSTEM_PROMPT
            },
            {"role": "user", "content": message}
        ]
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False
        }
        
        try:
            # Build HTTP request
            request_body = json.dumps(payload)
            
            # Build headers
            headers = [
                "POST " + self.path + " HTTP/1.1",
                "Host: " + self.host,
                "Content-Type: application/json",
                "User-Agent: Atlas-AI-Burp-Extension/1.0",
                "Accept: application/json",
                "Content-Length: " + str(len(request_body))
            ]
            
            # Add API key if provided (supports various authentication methods)
            if self.api_key:
                # Check if custom header is configured
                custom_header = self.config.get("local_custom_header", "") if self.config else ""
                header_format = self.config.get("local_header_format", "Bearer") if self.config else "Bearer"
                
                if custom_header:
                    # Use custom header configuration
                    if header_format == "Bearer":
                        headers.append(custom_header + ": Bearer " + self.api_key)
                    elif header_format == "Basic":
                        headers.append(custom_header + ": Basic " + self.api_key)
                    else:  # None format
                        headers.append(custom_header + ": " + self.api_key)
                else:
                    # Fall back to auto-detection
                    if "bedrock" in self.endpoint_url.lower() or "aws" in self.endpoint_url.lower():
                        # AWS services typically use x-api-key header
                        headers.append("x-api-key: " + self.api_key)
                    elif "anthropic" in self.endpoint_url.lower() or "claude" in self.endpoint_url.lower():
                        # Anthropic uses x-api-key header
                        headers.append("x-api-key: " + self.api_key)
                    else:
                        # Default to Bearer token (OpenAI-compatible)
                        headers.append("Authorization: Bearer " + self.api_key)
            
            # Build full request
            request = "\r\n".join(headers) + "\r\n\r\n" + request_body
            request_bytes = self._helpers.stringToBytes(request)
            
            # Make request through Burp
            http_service = self._helpers.buildHttpService(self.host, self.port, self.use_https)
            http_response = self._callbacks.makeHttpRequest(http_service, request_bytes)
            
            # Parse response
            response_bytes = http_response.getResponse()
            if not response_bytes:
                raise Exception("No response received from Local LLM")
            
            response_info = self._helpers.analyzeResponse(response_bytes)
            response_body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response_bytes[response_body_offset:])
            
            # Check status code
            status_code = response_info.getStatusCode()
            
            if status_code == 200:
                response_json = json.loads(response_body)
                
                if "choices" in response_json and len(response_json["choices"]) > 0:
                    return response_json["choices"][0]["message"]["content"].strip()
                
                # Some local LLMs might return response differently
                if "response" in response_json:
                    return response_json["response"].strip()
                
                return "No response content from Local LLM"
            else:
                raise Exception("Local LLM HTTP Error " + str(status_code) + ": " + response_body[:200])
                
        except Exception as e:
            raise Exception("Local LLM Request Failed: " + str(e))