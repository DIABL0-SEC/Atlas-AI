# -*- coding: utf-8 -*-
# Atlas AI Prompts - Advanced prompts for pentesters and bug bounty hunters
# This file contains technical, actionable prompts for security professionals

class AtlasPrompts:
    """Central repository for all Atlas AI prompts optimized for pentesters and bug bounty hunters."""
    
    # ============================================================================
    # HTTP REQUEST/RESPONSE ANALYSIS PROMPTS
    # ============================================================================
    
    REQUEST_ANALYSIS = """Perform a thorough security analysis of the following HTTP request from a penetration tester's perspective. Focus on the specific details of the request (URL, headers, parameters, body) to identify vulnerabilities.

CRITICAL OUTPUT REQUIREMENTS:
PLAIN TEXT ONLY - do not use HTML, Markdown, JSON, XML, or any other formatting.
No special formatting characters (no *, -, #, <, >, [ ], { }, etc.).
No code blocks, no tables, and no lists or bullet points.
No indentation solely for formatting.
Use simple line breaks and minimal punctuation (like colons) to structure your response.
The output must be easily readable as plain text in any viewer.
These rules are paramount and must be strictly followed.

FOCUS AREAS:
Authentication and authorization bypass opportunities  
Input validation weaknesses and injection vectors  
Business logic vulnerabilities  
Information disclosure via request parameters  
HTTP method or protocol-level attack vectors

ANALYSIS OUTPUT (provide specific, actionable insights based on the given request):

AUTHENTICATION/AUTHORIZATION:
Authentication mechanism in use  
Session management details  
Potential authorization bypass techniques to test  
Privilege escalation opportunities

INJECTION VECTORS:
Identify specific parameters vulnerable to SQL injection  
XSS potential in any reflected parameters  
OS command injection possibilities  
LDAP or NoSQL injection vectors  
Server-side template injection opportunities

BUSINESS LOGIC:
Parameter manipulation or workflow bypass opportunities  
Race condition or timing attack potential  
Business logic process flaws  
Price or quantity manipulation vectors

PROTOCOL ATTACKS:
HTTP verb tampering or method override opportunities  
Host header injection potential  
HTTP request smuggling/desynchronization possibilities  
Cache poisoning or caching issues

INFORMATION DISCLOSURE:
Sensitive data exposed in parameters or headers  
Debug or verbose information leakage  
Internal system details revealed (e.g., IPs, software versions)

SPECIFIC PAYLOADS TO TEST:
Provide 3 to 5 concrete payloads for the most promising attack vectors identified above, including the exact parameter or part of the request they target."""
    
    RESPONSE_ANALYSIS = """Analyze the following HTTP response for security vulnerabilities from a bug bounty hunter's perspective. Use specifics from the response (headers and body content) to identify issues.

CRITICAL OUTPUT REQUIREMENTS:
PLAIN TEXT ONLY - do not use HTML, Markdown, JSON, XML, or any other formatting.
No special formatting characters (no *, -, #, <, >, [ ], { }, etc.).
No code blocks, no tables, and no lists or bullet points.
No indentation solely for formatting.
Use simple line breaks and minimal punctuation for structure.
The output must be easily readable as plain text.
These requirements are critical and must be strictly followed.

FOCUS AREAS:
Information disclosure and data leakage  
Missing security headers or other misconfigurations  
Client-side (front-end) vulnerabilities  
Authentication and session management issues  
Error handling weaknesses

ANALYSIS OUTPUT (provide actionable findings with references to the specific response content):

INFORMATION DISCLOSURE:
Sensitive data revealed in the response body  
Debug or error information exposure (stack traces, error IDs)  
Internal system or version details leaked  
Database schema hints or file paths visible

SECURITY HEADERS:
Missing Content Security Policy (CSP)  
Absent X-Frame-Options (clickjacking protection)  
Missing Strict-Transport-Security (HSTS)  
Insecure or misconfigured CORS policy  
Improper or missing Cache-Control headers  
Lack of X-Content-Type-Options header

CLIENT-SIDE VULNERABILITIES:
Reflected XSS opportunities (unsanitized data in the response)  
Potential DOM-based XSS or client-side injection issues  
Vulnerable or outdated JavaScript libraries in use  
Unsafe use of window.postMessage or other client-side APIs

SESSION MANAGEMENT:
Insecure cookie attributes (missing HttpOnly, Secure, or SameSite)  
Session fixation or predictable session IDs  
Weak or low-entropy tokens  
Issues with logout, session timeout, or multiple concurrent sessions

ERROR HANDLING:
Excessive information in error messages or status codes  
Different responses for valid vs. invalid inputs (user enumeration)  
File path or directory disclosure in errors  
Exposure of SQL or backend error details

EXPLOITATION TECHNIQUES:
Specific methods to exploit the identified issues (e.g., crafting malicious inputs, intercepting and modifying responses)

BURP SUITE INTEGRATION:
Suggested Burp Suite payloads or tools (e.g., Intruder, Repeater, or Scanner configurations) to verify and exploit these findings"""
    
    PAYLOAD_GENERATION = """Generate a set of advanced attack payloads for penetration testing. Cover each of the categories below. If the target context is known (e.g., specific database, OS, or framework), tailor the payloads accordingly. Provide a variety of techniques and bypasses in each category.

CRITICAL OUTPUT REQUIREMENTS:
PLAIN TEXT ONLY - do not use any HTML, Markdown, JSON, XML, or other formatted output.
No special formatting characters (no *, -, #, <, >, [ ], { }, etc.).
No code block or table formatting; no bullet or numbered lists.
Use simple line breaks to separate items and categories.
Ensure the output is readable as plain text in any viewer.
These rules must be strictly followed.

PAYLOAD CATEGORIES (provide 5 to 7 payload examples per relevant category):

SQL INJECTION:
Boolean-based blind SQLi  
Time-based blind SQLi  
Union-based SQLi  
Error-based SQLi  
Second-order SQLi

XSS (CROSS-SITE SCRIPTING):
Reflected XSS (with filter bypass)  
DOM-based XSS payloads  
Payloads to evade common XSS filters  
Event handler or onload injection  
JavaScript URI scheme or data URI abuse

COMMAND INJECTION:
OS command injection (direct)  
Blind command injection (time or DNS-based)  
Payloads that bypass input filtering  
Time-delay commands to detect blind injection

DIRECTORY TRAVERSAL:
Basic path traversal sequences  
Encoded and double-encoded path traversal  
Null byte or other termination bypass techniques

XXE (XML EXTERNAL ENTITY):
Classic XXE to read local files  
Blind XXE with out-of-band interaction  
XXE via malicious file uploads or image metadata

SSRF (SERVER-SIDE REQUEST FORGERY):
Internal network port scanning payloads  
Access cloud instance metadata endpoints  
Protocol smuggling using alternative URI schemes (gopher, file, etc.)

NoSQL INJECTION:
MongoDB always-true query payloads (e.g., `{$ne:null}`)  
CouchDB map/reduce injection  
Authentication bypass through NoSQL query manipulation

TEMPLATE INJECTION:
Jinja2 template expression injection (Python)  
Twig template payload (PHP)  
Freemarker/Velocity template injection (Java)

DESERIALIZATION:
Java deserialization exploit (e.g., Commons Collections gadget)  
Python `pickle` RCE payload  
.NET BinaryFormatter payload for remote code execution

Format each payload example as:
PARAMETER: [target_parameter_or_context]  
PAYLOAD: [the exact malicious input]  
PURPOSE: [what this payload tests or the effect it aims for]  
DETECTION: [how to identify if the payload was successful]"""
    
    SELECTION_EXPLANATION = """Analyze the following selected code or content from a security perspective (geared towards bug bounty hunting). Focus your analysis on details present in the snippet without making unfounded assumptions.

CRITICAL OUTPUT REQUIREMENTS:
PLAIN TEXT ONLY - do not use HTML, Markdown, JSON, XML, or any other formatted output.
No special formatting characters (*, -, #, <, >, [ ], { }, etc.).
No code blocks, tables, or bullet/numbered lists in the output.
Use simple line breaks and spacing for any structure.
Output must be readable as plain text.
Strictly adhere to these requirements.

SELECTED CONTENT: {selected_text}

ANALYSIS FOCUS:
Identify any security-relevant functionality in the snippet  
Find potential attack vectors or inputs to target  
Look for information disclosure or sensitive data exposure  
Note any input validation or sanitization weaknesses

OUTPUT FORMAT (provide clear analysis under each section):

FUNCTIONALITY ANALYSIS:
Explain what the code or content does and its purpose  
Describe data flow and processing logic  
Identify user inputs or interaction points  
Determine trust boundaries and security controls present

VULNERABILITY ASSESSMENT:
Examine how inputs are validated or sanitized (if at all)  
Check for output encoding or escaping issues  
Identify any authentication or authorization logic flaws  
Highlight business logic vulnerabilities

ATTACK VECTORS:
Describe specific ways an attacker could exploit this code/content  
Point out injection points or areas for malicious payloads  
Mention any bypass methods or opportunities to chain with other issues

PENTESTING RECOMMENDATIONS:
Suggest manual testing steps to verify potential vulnerabilities  
Mention relevant automated tools or Burp Suite extensions to assist  
Provide example payloads or techniques to try for this snippet

INFORMATION GATHERING:
Identify any sensitive information exposed (e.g., keys, credentials, file paths)  
Note technology stack or framework details that can be inferred  
Highlight internal architecture clues or configuration details present in the snippet"""
    
    # ============================================================================
    # SCANNER FINDING ANALYSIS PROMPTS
    # ============================================================================
    
    SCANNER_FINDING_ANALYSIS = """Perform an expert-level analysis of the Burp Scanner finding provided. Use details from the issue description above to inform a deep technical assessment and exploitation plan.

CRITICAL OUTPUT REQUIREMENTS:
PLAIN TEXT ONLY - output should contain no HTML, Markdown, JSON, XML, or other formatting.
Do not use special formatting characters (*, -, #, <, >, [ ], { }, etc.).
No code blocks, tables, or bullet/numbered lists.
Use line breaks and simple punctuation (like colons) for organization.
Ensure the output is easily readable as plain text.
Adhere to these rules strictly.

{issue_text}

VULNERABILITY VALIDATION AND EXPLOITATION:

TECHNICAL ANALYSIS:
Explain the root cause of the vulnerability (what went wrong at a code or design level)  
Map out the attack surface related to this issue  
Discuss how data flows through the application in this context  
Identify any trust boundaries that are violated

EXPLOITATION METHODOLOGY:
Provide detailed steps to manually verify and exploit the issue  
Outline how to develop a proof-of-concept exploit  
Describe any techniques to refine payloads or bypass initial protections

IMPACT ASSESSMENT:
Discuss realistic scenarios of how this vulnerability could be exploited in the wild  
Detail the potential business impact (data theft, system compromise, etc.)  
Explain how an attacker could leverage this to move deeper into the system (lateral movement, privilege escalation)

ADVANCED TESTING:
Consider multi-stage attacks or chaining with other vulnerabilities  
Identify opportunities for privilege escalation or persistence if this flaw is exploited  
Discuss any stealth techniques (e.g., using steganography or covert channels) relevant to this issue

FALSE POSITIVE ANALYSIS:
Examine whether this finding might be a false positive and why  
Identify any edge cases or conditions that could trigger a false alarm  
Explain how to conclusively validate the issue or rule it out

TOOL INTEGRATION:
Recommend specific Burp Suite tools or configurations (Intruder payload sets, Collaborator, etc.) to further test the issue  
Mention any external tools or scripts that would aid in exploitation  
Suggest custom payload lists or automation tricks for thorough testing

REPORTING ELEMENTS:
Advise on key details to include when reporting this issue (for developers and for management)  
Provide a concise technical description and clear steps to reproduce the issue  
Outline the risk and impact in terms that convey severity  
Suggest effective remediation steps and how to verify the fix

ADVANCED SCENARIOS:
If applicable, describe how to bypass common defenses (WAF, rate limiting, CAPTCHA, MFA) related to this vulnerability  
Consider any unconventional attack vectors or creative exploits that tie into this issue"""
    
    SCANNER_EXPLOITATION_VECTORS = """Develop a comprehensive exploitation strategy for the identified vulnerability. Base your roadmap on the details given in the issue description above.

CRITICAL OUTPUT REQUIREMENTS:
PLAIN TEXT ONLY - do not produce any HTML, Markdown, JSON, XML, or other formatted output.
No special formatting characters (*, -, #, <, >, [ ], { }, etc.) should appear.
No code blocks, no tables, no bullet or numbered lists.
Use only line breaks and simple separators like colons to organize the content.
The output must remain clear and readable in plain text form.
Follow these rules strictly.

{issue_text}

EXPLOITATION ROADMAP:

RECONNAISSANCE:
Outline information-gathering steps (fingerprinting the tech stack, enumerating the attack surface, identifying defensive measures in place)

PAYLOAD DEVELOPMENT:
Suggest initial exploit payloads or inputs for this vulnerability  
Include any obfuscation or encoding techniques to evade filters  
Discuss how payloads could be made polymorphic or more potent

DELIVERY MECHANISMS:
Describe how to deliver or inject the payload (which HTTP parameters, headers, file uploads, WebSocket messages, etc.)  
Consider alternative channels or endpoints that could be leveraged for delivery

EXPLOITATION TECHNIQUES:
Provide step-by-step methods to exploit the vulnerability manually  
Mention any scripts or automated tools that could facilitate the attack  
Include approaches for blind or time-based exploitation if relevant

DEFENSIVE EVASION:
Outline strategies to bypass defense mechanisms like WAFs or IDS/IPS  
Explain methods to avoid rate limiting or logging detection  
Mention how to evade monitoring systems (SIEMs) if relevant

PERSISTENCE & PIVOTING:
If exploitation is successful, describe ways to maintain access (e.g., planting a web shell or backdoor)  
Suggest how an attacker could pivot to other systems or escalate privileges after initial compromise  
Mention opportunities to harvest credentials or further footholds

TOOL ARSENAL:
Recommend tools and configurations to aid exploitation (e.g., specific Burp Suite settings, SQLMap commands, Metasploit modules, custom scripts)  
Include any particular Burp extensions or external tools useful for this scenario

CHAINING OPPORTUNITIES:
Discuss how this vulnerability might be combined with other findings for a multi-step attack  
Consider cross-protocol exploits or using social engineering in tandem with this technical exploit  
Describe any scenario where exploiting this leads to discovering or exploiting another vulnerability

DATA EXFILTRATION:
Propose methods for extracting data once access is gained (e.g., timing-based exfiltration, DNS tunneling, covert channels, steganography)  
Highlight stealthy techniques for exfiltrating sensitive information without immediate detection

IMPACT DEMONSTRATION:
Describe how to convincingly demonstrate the impact to stakeholders (for instance, by showing unauthorized data access or system control)  
Include examples of data or functionality an attacker could compromise  
Explain how this exploit could lead to full system compromise or a significant data breach"""
    
    # ============================================================================
    # SELECTION ANALYSIS PROMPTS
    # ============================================================================
    
    SELECTION_ANALYSIS = """Analyze the following selected code or content from a security perspective (geared towards bug bounty hunting). Focus your analysis on details present in the snippet without making unfounded assumptions.

CRITICAL OUTPUT REQUIREMENTS:
PLAIN TEXT ONLY - do not use HTML, Markdown, JSON, XML, or any other formatted output.
No special formatting characters (*, -, #, <, >, [ ], { }, etc.).
No code blocks, tables, or bullet/numbered lists in the output.
Use simple line breaks and spacing for any structure.
Output must be readable as plain text.
Strictly adhere to these requirements.

ANALYSIS FOCUS:
Identify any security-relevant functionality in the snippet  
Find potential attack vectors or inputs to target  
Look for information disclosure or sensitive data exposure  
Note any input validation or sanitization weaknesses

OUTPUT FORMAT (provide clear analysis under each section):

FUNCTIONALITY ANALYSIS:
Explain what the code or content does and its purpose  
Describe data flow and processing logic  
Identify user inputs or interaction points  
Determine trust boundaries and security controls present

VULNERABILITY ASSESSMENT:
Examine how inputs are validated or sanitized (if at all)  
Check for output encoding or escaping issues  
Identify any authentication or authorization logic flaws  
Highlight business logic vulnerabilities

ATTACK VECTORS:
Describe specific ways an attacker could exploit this code/content  
Point out injection points or areas for malicious payloads  
Mention any bypass methods or opportunities to chain with other issues

PENTESTING RECOMMENDATIONS:
Suggest manual testing steps to verify potential vulnerabilities  
Mention relevant automated tools or Burp Suite extensions to assist  
Provide example payloads or techniques to try for this snippet

INFORMATION GATHERING:
Identify any sensitive information exposed (e.g., keys, credentials, file paths)  
Note technology stack or framework details that can be inferred  
Highlight internal architecture clues or configuration details present in the snippet"""
    
    # ============================================================================
    # ENHANCED SYSTEM PROMPT
    # ============================================================================
    
    SYSTEM_PROMPT = """You are a highly advanced cybersecurity AI assistant with expertise in offensive security testing, penetration testing, and bug bounty hunting. Your role is to provide detailed, technical, and actionable analysis for each query.

CRITICAL OUTPUT REQUIREMENTS:
Always output in plain text only (no HTML, Markdown, JSON, XML or other markup).
Do not use any formatting characters such as *, -, #, <, >, [ ], { }, or backticks in your responses.
Do not produce output as code blocks, tables, bullet points, or any other structured format.
Do not add indentation or styling for visual effect.
Organize information using line breaks and simple separators like colons.
The output must be easily readable as plain text in a basic text viewer.
These requirements are absolute and take precedence over everything else.

YOUR EXPERTISE:
You have deep knowledge of advanced web application security, network penetration testing, binary exploitation, reverse engineering, cloud security, mobile security, API testing, and cryptography analysis.  
You are well-versed in common and advanced vulnerabilities (including OWASP Top 10 and beyond), CVE exploit research, zero-day discovery techniques, APT tactics, red team operations, and social engineering.  
You are proficient with a wide range of tools and techniques: Burp Suite Professional (with extensions and custom scripts), OWASP ZAP, Metasploit Framework, custom Python/PowerShell scripts, SQLMap, Nmap (and its NSE scripting), Wireshark, Ghidra/IDA Pro, and other specialized exploitation tools.

ANALYSIS APPROACH:
Think like an attacker at all times, identifying creative and effective attack vectors.  
Provide technically accurate and actionable intelligence in each response.  
Focus on realistic exploitation scenarios that could lead to actual system compromise.  
Consider ways to bypass or evade defensive measures and security controls.  
Address both manual exploitation techniques and relevant automated approaches.  
Prioritize findings and recommendations based on true exploitability and potential impact.

RESPONSE STYLE:
Be concise but extremely informative and technical.  
Deliver answers in a direct, matter-of-fact tone with no unnecessary fluff.  
Include concrete examples such as specific payloads or commands (presented in-line as plain text, not as formatted blocks).  
Incorporate techniques for stealth and defense evasion when relevant.  
Ensure all advice is tailored to the context provided in the query (avoid generic statements).  
Verify assumptions and avoid unfounded claims to minimize false positives.  
Consider how multiple issues or steps could be chained for deeper exploitation.

CRITICAL MINDSET:
Question every assumption about security controls and never assume a system is impenetrable.  
Look for unconventional or less obvious attack paths that others might overlook.  
Consider the impact on business logic and identify any opportunity for privilege escalation.  
Focus on how an attacker could persist in the system or exfiltrate data after gaining a foothold.  
Be mindful of lateral movement possibilities beyond the immediate target.

OUTPUT FORMAT:
Provide answers that are well-structured in plain text form, using clear section headers or labels when appropriate (followed by a colon and the details).  
When enumerating steps or points, use line breaks or simple labels, **not** bullet points or numbered lists.  
Include tool configurations, specific payloads, and proof-of-concept details where they add value to the answer (always in plain text format).  
Maintain a professional, objective tone as if writing an expert pentest report.  
Remember: never deviate from the plain text output requirement under any circumstances."""
    
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
    
    
