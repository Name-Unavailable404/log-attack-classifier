RULES = [
    {
        "attack_type": "Cross-Site Scripting",
        "rule_name": "xss_script_tag",
        "pattern": r"<script.*?>",
        "confidence": "High",
        "explanation": "Script tags in request parameters often indicate an XSS attempt."
    },
    {
        "attack_type": "Cross-Site Scripting",
        "rule_name": "xss_javascript_alert",
        "pattern": r"alert\s*\(",
        "confidence": "Medium",
        "explanation": "JavaScript alert calls are commonly used when testing reflected XSS."
    },
    {
        "attack_type": "SQL Injection",
        "rule_name": "sql_union_select",
        "pattern": r"union\s+select",
        "confidence": "High",
        "explanation": "UNION SELECT is commonly used in SQL injection attempts to combine attacker-controlled query results."
    },
    {
        "attack_type": "SQL Injection",
        "rule_name": "sql_or_true_condition",
        "pattern": r"('|%27)\s*or\s*('|%27)?1('|%27)?\s*=\s*('|%27)?1",
        "confidence": "High",
        "explanation": "OR 1=1 style conditions are commonly used to bypass authentication or force SQL queries to return true."
    },
    {
        "attack_type": "Command Injection",
        "rule_name": "cmd_shell_separator",
        "pattern": r"(;|&&|\|\|)\s*(whoami|id|uname|cat|ls|dir|ipconfig|ifconfig)",
        "confidence": "High",
        "explanation": "Shell separators followed by system commands can indicate command injection."
    },
    {
        "attack_type": "Command Injection",
        "rule_name": "cmd_shell_reference",
        "pattern": r"(/bin/sh|/bin/bash|cmd\.exe|powershell\.exe)",
        "confidence": "High",
        "explanation": "References to system shells can indicate an attempt to execute commands on the server."
    },
    {
        "attack_type": "Path Traversal",
        "rule_name": "path_traversal_dot_dot_slash",
        "pattern": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|%252e%252e%252f)",
        "confidence": "High",
        "explanation": "Directory traversal sequences are commonly used to access files outside the intended web directory."
    },
    {
        "attack_type": "Path Traversal",
        "rule_name": "path_traversal_sensitive_file",
        "pattern": r"(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)",
        "confidence": "High",
        "explanation": "Requests for sensitive system files often indicate path traversal attempts."
    }
]