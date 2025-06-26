# -*- coding: utf-8 -*-
# Atlas AI Prompts - Advanced prompts for pentesters and bug bounty hunters
# This file contains technical, actionable prompts for security professionals

class AtlasPrompts:
    """Central repository for all Atlas AI prompts optimized for pentesters and bug bounty hunters."""
    
    # ============================================================================
    # HTTP REQUEST/RESPONSE ANALYSIS PROMPTS
    # ============================================================================
    
    REQUEST_ANALYSIS = """Perform a detailed security analysis of this HTTP request from a penetration testing perspective.

CRITICAL OUTPUT REQUIREMENTS:
- PLAIN TEXT ONLY - No HTML, markdown, JSON, XML, or any formatting
- No special characters like *, -, #, <, >, [], {{}}, etc. for formatting
- No code blocks, tables, or structured markup
- Use simple line breaks and spaces only
- Output should be readable in any plain text viewer

FOCUS AREAS:
1. Authentication & Authorization bypass opportunities
2. Input validation weaknesses and injection vectors
3. Business logic vulnerabilities
4. Information disclosure through request parameters
5. HTTP method and protocol-level attacks

ANALYSIS OUTPUT (be specific and actionable):

AUTHENTICATION/AUTHORIZATION:
Authentication mechanism in use
Session management implementation
Authorization bypass techniques to test
Privilege escalation opportunities

INJECTION VECTORS:
SQL injection test points (specific parameters)
XSS potential in reflected parameters
Command injection possibilities
LDAP/NoSQL injection opportunities
Template injection vectors

BUSINESS LOGIC:
Parameter manipulation opportunities
Race condition potential
Workflow bypass techniques
Price/quantity manipulation vectors

PROTOCOL ATTACKS:
HTTP verb tampering opportunities
Host header injection potential
HTTP smuggling/desync vectors
Cache poisoning possibilities

INFORMATION DISCLOSURE:
Sensitive data in parameters
Debug information exposure
Internal system details leaked

SPECIFIC PAYLOADS TO TEST:
Provide 3 to 5 specific payloads for the most promising attack vectors"""
    
    RESPONSE_ANALYSIS = """Analyze this HTTP response for security vulnerabilities from a bug bounty hunter perspective.

CRITICAL OUTPUT REQUIREMENTS:
- PLAIN TEXT ONLY - No HTML, markdown, JSON, XML, or any formatting
- No special characters like *, -, #, <, >, [], {{}}, etc. for formatting
- No code blocks, tables, or structured markup
- Use simple line breaks and spaces only
- Output should be readable in any plain text viewer

FOCUS AREAS:
1. Information disclosure and data leakage
2. Missing security headers and misconfigurations
3. Client-side vulnerabilities
4. Authentication/session management issues
5. Error handling weaknesses

ANALYSIS OUTPUT (provide actionable findings):

INFORMATION DISCLOSURE:
Sensitive data in response body
Debug information exposure
Stack traces or error details
Internal system information leaked
Database schema hints
File system paths revealed

SECURITY HEADERS:
Missing CSP (Content Security Policy)
Absent X-Frame-Options
Missing HSTS headers
Insecure CORS configuration
Cache-control misconfigurations

CLIENT-SIDE VULNERABILITIES:
Reflected XSS opportunities
DOM-based XSS potential
Client-side template injection
JavaScript library vulnerabilities
PostMessage vulnerabilities

SESSION MANAGEMENT:
Insecure cookie attributes
Session fixation vulnerabilities
Token entropy analysis
Logout functionality issues

ERROR HANDLING:
Information leakage in errors
Different responses for valid/invalid users
Path traversal error messages
SQL error information

EXPLOITATION TECHNIQUES:
Provide specific techniques to exploit identified issues

BURP SCANNER INTEGRATION:
Suggest specific Burp Scanner or Intruder payloads to test findings"""
    
    PAYLOAD_GENERATION = """Generate advanced attack payloads for penetration testing.

CRITICAL OUTPUT REQUIREMENTS:
- PLAIN TEXT ONLY - No HTML, markdown, JSON, XML, or any formatting
- No special characters like *, -, #, <, >, [], {{}}, etc. for formatting
- No code blocks, tables, or structured markup
- Use simple line breaks and spaces only
- Output should be readable in any plain text viewer

PAYLOAD CATEGORIES (generate 5-7 payloads per category where applicable):

SQL INJECTION:
Boolean-based blind SQLi
Time-based blind SQLi
Union-based SQLi
Error-based SQLi
Second-order SQLi

XSS (CROSS-SITE SCRIPTING):
Reflected XSS bypass techniques
DOM XSS payloads
Filter bypass payloads
Event handler injection
JavaScript protocol abuse

COMMAND INJECTION:
OS command injection
Blind command injection
Filter bypass techniques
Time-based detection

DIRECTORY TRAVERSAL:
Path traversal variants
Encoding bypass techniques
Double encoding payloads

XXE (XML EXTERNAL ENTITY):
Classic XXE payloads
Blind XXE payloads
XXE via file upload

SSRF (SERVER-SIDE REQUEST FORGERY):
Internal network probing
Cloud metadata access
Protocol smuggling

NoSQL INJECTION:
MongoDB injection
CouchDB injection
Authentication bypass

TEMPLATE INJECTION:
Jinja2 template injection
Twig template injection
Freemarker injection

DESERIALIZATION:
Java deserialization
Python pickle injection
.NET deserialization

Format each payload with:
PARAMETER: [parameter_name]
PAYLOAD: [specific_payload]
PURPOSE: [what vulnerability this tests]
DETECTION: [how to identify success]"""
    
    SELECTION_EXPLANATION = """Analyze this selected code/content from a security perspective for bug bounty hunting.

CRITICAL OUTPUT REQUIREMENTS:
- PLAIN TEXT ONLY - No HTML, markdown, JSON, XML, or any formatting
- No special characters like *, -, #, <, >, [], {{}}, etc. for formatting
- No code blocks, tables, or structured markup
- Use simple line breaks and spaces only
- Output should be readable in any plain text viewer

ANALYSIS FOCUS:
1. Identify security-relevant functionality
2. Find potential attack vectors
3. Discover information disclosure opportunities
4. Locate input validation weaknesses

OUTPUT FORMAT:

FUNCTIONALITY ANALYSIS:
What this code/content does
Data flow and processing logic
User interaction points
Trust boundaries

VULNERABILITY ASSESSMENT:
Input validation weaknesses
Output encoding issues
Authentication/authorization flaws
Business logic vulnerabilities

ATTACK VECTORS:
Specific exploitation techniques
Payload injection points
Bypass methods
Chaining opportunities

PENTESTING RECOMMENDATIONS:
Manual testing steps
Automated testing approaches
Burp Suite extensions to use
Specific payloads to try

INFORMATION GATHERING:
Sensitive information exposed
System details revealed
Technology stack hints
Internal architecture clues"""
    
    # ============================================================================
    # SCANNER FINDING ANALYSIS PROMPTS
    # ============================================================================
    
    SCANNER_FINDING_ANALYSIS = """Perform expert-level analysis of this Burp Scanner finding for advanced penetration testing.

CRITICAL OUTPUT REQUIREMENTS:
- PLAIN TEXT ONLY - No HTML, markdown, JSON, XML, or any formatting
- No special characters like *, -, #, <, >, [], {{}}, etc. for formatting
- No code blocks, tables, or structured markup
- Use simple line breaks and spaces only
- Output should be readable in any plain text viewer

{issue_text}

VULNERABILITY VALIDATION AND EXPLOITATION:

TECHNICAL ANALYSIS:
Root cause explanation (code-level understanding)
Attack surface mapping
Data flow analysis
Trust boundary violations

EXPLOITATION METHODOLOGY:
Manual verification steps (detailed)
Proof-of-concept development
Payload refinement techniques
Bypass strategy for mitigations

IMPACT ASSESSMENT:
Real-world exploitation scenarios
Business impact quantification
Data compromise potential
System compromise pathways
Lateral movement opportunities

ADVANCED TESTING:
Multi-stage attack chaining
Privilege escalation paths
Persistence mechanisms
Steganography opportunities

FALSE POSITIVE ANALYSIS:
Technical indicators of false positives
Edge cases that might cause false flags
Validation methodology
Confidence level assessment

TOOL INTEGRATION:
Burp Intruder configuration
Custom payload lists
Collaborator usage
Third-party tool integration

REPORTING ELEMENTS:
Technical description for developers
Business risk explanation for management
Step-by-step reproduction guide
Remediation validation steps

ADVANCED SCENARIOS:
WAF bypass techniques
Rate limiting circumvention
CAPTCHA bypass methods
Multi-factor authentication bypass"""
    
    SCANNER_EXPLOITATION_VECTORS = """Develop comprehensive exploitation strategies for this vulnerability.

CRITICAL OUTPUT REQUIREMENTS:
- PLAIN TEXT ONLY - No HTML, markdown, JSON, XML, or any formatting
- No special characters like *, -, #, <, >, [], {{}}, etc. for formatting
- No code blocks, tables, or structured markup
- Use simple line breaks and spaces only
- Output should be readable in any plain text viewer

{issue_text}

EXPLOITATION ROADMAP:

RECONNAISSANCE:
Information gathering techniques
Technology stack fingerprinting
Attack surface enumeration
Defensive mechanism identification

PAYLOAD DEVELOPMENT:
Basic exploitation payloads
Obfuscation techniques
Encoding bypass methods
Polymorphic payload generation

DELIVERY MECHANISMS:
Direct parameter injection
HTTP header manipulation
File upload exploitation
WebSocket message injection
API endpoint abuse

EXPLOITATION TECHNIQUES:
Manual exploitation steps
Automated exploitation scripts
Time-based exploitation
Blind exploitation methods

DEFENSIVE EVASION:
WAF bypass strategies
IDS/IPS evasion techniques
Rate limiting circumvention
Logging mechanism bypass
SIEM detection avoidance

PERSISTENCE & PIVOTING:
Backdoor installation methods
Session persistence techniques
Network pivoting opportunities
Credential harvesting

TOOL ARSENAL:
Burp Suite configuration
Custom Burp extensions
SQLMap configuration
Metasploit modules
Custom Python scripts
OWASP ZAP integration

CHAINING OPPORTUNITIES:
Vulnerability combination strategies
Multi-stage attack scenarios
Cross-protocol exploitation
Social engineering integration

DATA EXFILTRATION:
Data extraction methods
Steganographic techniques
Covert channel establishment
DNS exfiltration methods

IMPACT DEMONSTRATION:
Proof-of-concept scripts
Visual impact evidence
Data compromise examples
System access demonstrations"""
    
    # ============================================================================
    # SELECTION ANALYSIS PROMPTS
    # ============================================================================
    
    SELECTION_ANALYSIS = """Analyze this selected content from an advanced penetration testing perspective.

CRITICAL OUTPUT REQUIREMENTS:
- PLAIN TEXT ONLY - No HTML, markdown, JSON, XML, or any formatting
- No special characters like *, -, #, <, >, [], {{}}, etc. for formatting
- No code blocks, tables, or structured markup
- Use simple line breaks and spaces only
- Output should be readable in any plain text viewer

SELECTED CONTENT: {selected_text}

SECURITY ANALYSIS:

FUNCTIONALITY BREAKDOWN:
Core functionality description
Input/output data flow
Processing logic analysis
Security control mechanisms

VULNERABILITY SURFACE:
Input validation points
Output encoding mechanisms
Authentication/authorization checks
Session management components

ATTACK VECTOR IDENTIFICATION:
Direct exploitation opportunities
Indirect attack pathways
Chain attack possibilities
Social engineering angles

EXPLOITATION TECHNIQUES:
Manual testing methodologies
Automated testing approaches
Custom payload requirements
Tool-specific configurations

INFORMATION DISCLOSURE:
Sensitive data exposure
System architecture details
Technology stack information
Configuration details

PENETRATION TESTING STRATEGY:
Testing methodology recommendations
Tool selection guidance
Payload customization needs
Verification approaches"""
    
    # ============================================================================
    # ENHANCED SYSTEM PROMPT
    # ============================================================================
    
    SYSTEM_PROMPT = """You are an elite cybersecurity AI assistant specializing in offensive security, penetration testing, and bug bounty hunting.

CRITICAL OUTPUT REQUIREMENTS:
- ALWAYS output PLAIN TEXT ONLY - Never use HTML, markdown, JSON, XML, or any formatting
- NO special characters for formatting: no *, -, #, <, >, [], {}, backticks, etc.
- NO code blocks, tables, bullet points, or structured markup
- NO indentation for formatting purposes
- Use simple line breaks and colons for organization
- Output must be readable in any basic text viewer
- Treat this as the most important requirement

You have deep expertise in:

TECHNICAL EXPERTISE:
Advanced web application security testing
Network penetration testing methodologies
Binary exploitation and reverse engineering
Cloud security assessment
Mobile application security
API security testing
Cryptographic implementation analysis

SPECIALIZED KNOWLEDGE:
OWASP Top 10 and beyond
CVE research and exploitation
Zero-day vulnerability discovery
Advanced persistent threat (APT) techniques
Red team operations
Social engineering methodologies

TOOLCHAIN MASTERY:
Burp Suite Professional (extensions, macros, custom scripts)
OWASP ZAP advanced features
Metasploit framework
Custom Python/PowerShell exploitation scripts
SQLMap advanced usage
Nmap scripting engine
Wireshark analysis
Ghidra/IDA Pro for reverse engineering

ANALYSIS APPROACH:
1. Always think like an attacker - identify the most creative and effective attack vectors
2. Provide technically accurate, actionable intelligence
3. Focus on real-world exploitation scenarios
4. Consider defensive bypass techniques
5. Analyze from both manual and automated testing perspectives
6. Prioritize findings based on actual exploitability and impact

RESPONSE CHARACTERISTICS:
Be highly technical and specific
Provide actionable exploitation steps
Include specific payloads and proof-of-concept code
Consider defensive evasion techniques
Focus on findings that lead to actual system compromise
Avoid generic security advice - be specific to the context
Always validate findings to avoid false positives
Consider attack chaining and multi-stage exploitation

CRITICAL MINDSET:
Question every assumption about security controls
Look for unconventional attack vectors
Consider business logic vulnerabilities
Identify privilege escalation opportunities
Focus on data exfiltration and persistence
Analyze for lateral movement possibilities

OUTPUT FORMAT:
Use clear, structured technical analysis in plain text only
Provide specific, testable exploitation steps
Include tool-specific configurations
Suggest custom payloads where appropriate
Maintain professional penetration testing standards
Remember: PLAIN TEXT ONLY with no formatting whatsoever"""
    
    # ============================================================================
    # CONNECTION TEST PROMPT
    # ============================================================================
    
    CONNECTION_TEST = "Respond with: Atlas AI Pro - Advanced Security Analysis Ready"
    
    # ============================================================================
    # PROMPT TEMPLATES FOR FINE-TUNING
    # ============================================================================
    
    @staticmethod
    def get_request_analysis_template():
        """Template for request analysis fine-tuning."""
        return {
            "system": AtlasPrompts.SYSTEM_PROMPT,
            "user": AtlasPrompts.REQUEST_ANALYSIS + "\n\n{http_request}",
            "assistant": "{expected_analysis}"
        }
    
    @staticmethod
    def get_response_analysis_template():
        """Template for response analysis fine-tuning."""
        return {
            "system": AtlasPrompts.SYSTEM_PROMPT,
            "user": AtlasPrompts.RESPONSE_ANALYSIS + "\n\n{http_response}",
            "assistant": "{expected_analysis}"
        }
    
    @staticmethod
    def get_payload_generation_template():
        """Template for payload generation fine-tuning."""
        return {
            "system": AtlasPrompts.SYSTEM_PROMPT,
            "user": AtlasPrompts.PAYLOAD_GENERATION + "\n\n{target_context}",
            "assistant": "{expected_payloads}"
        }
    
    @staticmethod
    def get_scanner_analysis_template():
        """Template for scanner finding analysis fine-tuning."""
        return {
            "system": AtlasPrompts.SYSTEM_PROMPT,
            "user": AtlasPrompts.SCANNER_FINDING_ANALYSIS.format(issue_text="{scanner_issue}"),
            "assistant": "{expected_analysis}"
        }
    
    @staticmethod
    def get_exploitation_template():
        """Template for exploitation vectors fine-tuning."""
        return {
            "system": AtlasPrompts.SYSTEM_PROMPT,
            "user": AtlasPrompts.SCANNER_EXPLOITATION_VECTORS.format(issue_text="{scanner_issue}"),
            "assistant": "{expected_exploitation_vectors}"
        }
    
    
