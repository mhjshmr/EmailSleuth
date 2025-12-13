# EmailSleuth – Email Header Forensics & Phishing Analyzer

EmailSleuth is a Python-based cybersecurity and digital forensics tool designed to analyze .eml email files and identify phishing indicators.
<p> It performs header forensics, sender validation, authentication checks, URL and image analysis, and assigns a heuristic-based threat score to assist in phishing triage and investigation.</p>

<br>

<div align="center">
  <img src="https://github.com/mhjshmr/EmailSleuth/blob/main/Analyzis%20Output.png" alt="EmailAnlysis Output Report" width="400">
</div>


## Overview

EmailSleuth helps security students and analysts understand how phishing emails operate by examining multiple technical and social engineering indicators commonly used in real-world attacks.

The tool focuses on analysis and explainability, making it suitable for academic use, SOC training, and forensic learning.

## Features

### Email Header & Sender Analysis
- Parses key email headers (From, Reply-To, Return-Path, Message-ID, etc.).
- Detects sender spoofing and impersonation attempts.
- Flags free webmail usage with corporate-looking display names.
- Identifies domain mismatches between sender name and email domain.

### Authentication Checks (SPF / DKIM / DMARC)
- Analyzes Authentication-Results and Received-SPF headers.
- Detects authentication failures, softfails, and passes.
- Highlights misconfigured or unauthenticated emails.

### URL Analysis
- Extracts all URLs from email body (plain text and HTML).
- Detects obfuscated URLs:
   hxxp://, [.], http[:]//
- Flags:
     - Suspicious or low-reputation TLDs
     - IP-based URLs
     - Unicode/homoglyph domains
     - Brand impersonation using leetspeak
- Identifies URL shorteners and attempts expansion.

### Image Analysis
- Extracts inline and attachment images.
- Detects login-page or screenshot-like images using:
     - Image resolution heuristics
     - Filename and Content-ID keywords (login, password, secure, etc.)
- Flags embedded base64 images in HTML emails.
- Uses Pillow for image inspection when available.

### Attachment Analysis
- Detects all attachments
- Flags risky file types:
     - `.exe`, `.bat`, `.cmd`, `.docm`, `.xlsm`, `.pptm`, `.html`, `.js`, `.jar`
- Adds attachment threat score
- Reports suspicious attachments in the report 

### Threat Scoring System

- Calculates a 0–100 phishing threat score using weighted heuristics.
- Scoring factors include:
     - SPF/DKIM/DMARC failures
     - Suspicious URLs and obfuscation
     - Sender impersonation indicators
     - Risky inline images
- Helps prioritize emails for manual investigation.

### Report Generation

- Generates a detailed, human-readable analysis report.
- Displays:
     - Header summary
     - Sender findings
     - Authentication results
     - URL and image analysis
     - Final threat score
- Supports saving reports to a .txt file.

## Getting Started

### Prerequisites

- Python 3.x
- Optional: Pillow (for image analysis)
- Optional: requests (for URL shortener expansion)

### Installation

Clone the repository:
```bash
git clone https://github.com/mhjshmr/EmailSleuth.git
cd EmailSleuth
```

(Optional dependencies)
```bash
pip install pillow requests
```
### Usage

Run the analyzer on an `.eml` file:
```bash
python email_analyzer.py sample_email.eml
```
Follow the prompt to optionally save the analysis report.

### How It Works

Analysis Flow
1. Parse email headers and body
2. Validate sender and authentication mechanisms
3. Extract and analyze URLs
4. Inspect embedded images
5. Assign weighted heuristic scores
6. Generate a structured forensic report

## Best Practices

- Always verify sender domains manually for high-risk emails
- Do not rely on a single indicator—use combined signals
- Treat high threat scores as triage alerts, not final verdicts
- Follow organizational phishing response procedures

## Security Considerations

- This tool uses heuristic analysis, not machine learning.
- Threat scores are indicative, not definitive.
- Real-world phishing detection should include sandboxing and user awareness training.

## Technical Details

- Language: Python 3.x
- Libraries Used:
     - email, re, urllib, base64 (standard library)
     - pillow (optional)
     - requests (optional)

## Core Functions

- `analyze_sender()` – Detects spoofing and impersonation
- `analyze_authentication()` – SPF/DKIM/DMARC analysis
- `analyze_url()` – URL reputation and obfuscation checks
- `analyze_images()` – Login screenshot detection
- `compute_threat_score()` – Heuristic-based scoring
- `generate_report_text()` – Report creation

## Use Case

- Cybersecurity academic projects
- Digital forensics learning
- SOC analyst training
- Phishing awareness demonstrations

## References

- OWASP Phishing Defense Cheat Sheet
- RFC 7208 – SPF
- RFC 6376 – DKIM
- RFC 7489 – DMARC
<br><br>
**Stay vigilant. Think before you click. 🔐📧**
