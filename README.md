# Log Attack Classifier

A Python command-line tool that classifies suspicious web log lines using rule-based detection patterns.

This project focuses on basic log analysis and common web attack indicators such as XSS, SQL injection, command injection, and path traversal.

## Current Features

- Classifies a single log line from the command line
- Uses regex-based detection rules
- Detects common web attack patterns
- Separates detection rules from classifier logic
- Displays matched rule names, confidence levels, and explanations

## Supported Attack Types

- Cross-Site Scripting
- SQL Injection
- Command Injection
- Path Traversal

## Requirements

- Python 3.12+

This project currently uses only Python's built-in libraries.

## Usage

```powershell
python classifier.py "LOG LINE HERE"
```

## Examples

### Cross-Site Scripting

```powershell
python classifier.py "GET /search?q=<script>alert(1)</script> HTTP/1.1"
```

Example output:

```text
Log Line:
GET /search?q=<script>alert(1)</script> HTTP/1.1

Suspicious patterns detected:

Attack Type: Cross-Site Scripting
Confidence: High
Matched Rule: xss_script_tag
Explanation: Script tags in request parameters often indicate an XSS attempt.

Attack Type: Cross-Site Scripting
Confidence: Medium
Matched Rule: xss_javascript_alert
Explanation: JavaScript alert calls are commonly used when testing reflected XSS.
```

### SQL Injection

```powershell
python classifier.py "GET /login?user=admin' OR '1'='1 HTTP/1.1"
```

### Command Injection

```powershell
python classifier.py "GET /ping?host=127.0.0.1; whoami HTTP/1.1"
```

### Path Traversal

```powershell
python classifier.py "GET /download?file=../../../../etc/passwd HTTP/1.1"
```

## Project Structure

```text
log-attack-classifier/
│
├── classifier.py
├── rules.py
├── README.md
├── requirements.txt
├── .gitignore
│
└── samples/
    └── sample_logs.txt
```

## How It Works

The classifier loads detection rules from `rules.py`, checks the provided log line against each regex pattern, and prints any matching attack indicators.

Each rule includes:

- Attack type
- Rule name
- Regex pattern
- Confidence level
- Explanation

## Planned Features

- Add file scanning support for multiple log lines
- Add scoring by attack type
- Add JSON or CSV output
- Add more attack categories such as SSRF, XXE, LDAP injection, and brute force indicators
- Add sample log files for testing
- Add unit tests

## Project Status

This project is complete as a first working CLI version. Future improvements may expand it into a more complete log analysis and detection tool.