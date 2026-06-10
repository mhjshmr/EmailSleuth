# EmailSleuth – Email Header Forensics & Phishing Analyzer

EmailSleuth is a Flask and Python-based cybersecurity and digital forensics web application designed to analyze `.eml` email files and identify phishing indicators through automated forensic analysis.

The platform enables users to investigate suspicious emails by examining message headers, sender identity, authentication records, embedded URLs, images, and attachments. Using a weighted heuristic scoring model, EmailSleuth highlights potential phishing characteristics and generates structured analysis reports to support triage and investigation workflows.

Developed for cybersecurity education, phishing awareness, digital forensics training, and incident response exercises, EmailSleuth combines a browser-based interface with a standalone analysis engine to provide both accessibility and technical depth.

<br>
<div align="center"> 
  <img src="https://raw.githubusercontent.com/mhjshmr/EmailSleuth/main/UI%20Screenshots/Analyzis%20Output.png" alt="EmailSlueth Home Page" width="900" height="700"> 
</div>



## Overview

Email-based attacks remain one of the most common vectors for credential theft, malware delivery, business email compromise (BEC), and social engineering. EmailSleuth is designed to help cybersecurity students, SOC analysts, and incident responders investigate suspicious emails through automated forensic analysis.

The platform combines a standalone Python analysis engine with a Flask-powered web interface, enabling users to upload and analyze `.eml` files through an intuitive browser-based workflow. EmailSleuth examines multiple technical indicators commonly associated with phishing campaigns, including email headers, sender metadata, authentication records, embedded URLs, images, and attachments.

Key analysis areas include:

* Email header integrity and routing information
* Sender validation and impersonation detection
* SPF, DKIM, and DMARC authentication analysis
* URL extraction and phishing-related link inspection
* Embedded image analysis and phishing heuristics
* Attachment risk assessment
* Heuristic-based threat scoring and risk classification

The core analysis engine is implemented in `Email_Analyzer.py`, while `app.py` provides the web application layer for file uploads, result visualization, and report generation. Analysis results are presented through an interactive dashboard and can be exported as structured reports to support investigation, documentation, and phishing triage workflows.


## Key Features

### Email Forensics & Header Analysis

* Extracts and analyzes email headers from `.eml` files using Python's built-in `email` package.
* Captures critical metadata including `From`, `To`, `Reply-To`, `Return-Path`, `Message-ID`, `Subject`, `Date`, `Authentication-Results`, `Received-SPF`, `DKIM-Signature`, and `Received` headers.
* Uses fallback parsing techniques to recover header information from multipart and raw email content when standard extraction is unsuccessful.
* Examines message routing and authentication traces to support forensic investigations.

### Sender & Identity Validation

* Parses sender display names, email addresses, local parts, and domains.
* Detects potential sender impersonation and spoofing indicators.
* Flags display name and domain mismatches commonly associated with phishing attempts.
* Identifies potentially deceptive use of free webmail providers with corporate-looking sender identities.

### SPF, DKIM & DMARC Authentication Analysis

* Evaluates email authentication evidence using `Authentication-Results`, `Received-SPF`, and `DKIM-Signature` headers.
* Detects authentication outcomes including pass, fail, softfail, and missing validation records.
* Highlights authentication anomalies that may indicate spoofing or phishing activity.
* Reports missing or incomplete authentication-related headers.

### URL & Link Analysis

* Extracts URLs from email body content and analyzes embedded links.
* Supports extraction of HTML `href` links during CLI-based analysis.
* Detects obfuscated URLs such as:

  * `hxxp://`
  * `[.]`
  * `http[:]//`
* Identifies suspicious or low-reputation top-level domains (TLDs).
* Detects IP-based URLs and Unicode/homoglyph domains.
* Flags potential brand impersonation through leetspeak-based domain manipulation.
* Identifies URL shortening services and optionally expands shortened links when `requests` is available.

### Image Analysis

* Extracts and analyzes inline and attached images contained within email messages.
* Uses Pillow (when installed) to inspect image dimensions and file characteristics associated with phishing screenshots or fake login pages.
* Applies filename and Content-ID keyword heuristics when image inspection is unavailable.
* Detects embedded Base64 (`data:image`) content in HTML emails.
* Flags images embedded within clickable hyperlinks.

### Attachment Inspection

* Detects and enumerates email attachments.
* Identifies potentially dangerous attachment types, including:

  * `.exe`
  * `.bat`
  * `.cmd`
  * `.docm`
  * `.xlsm`
  * `.pptm`
  * `.html`
  * `.js`
  * `.jar`
* Evaluates attachment-related risk and incorporates findings into the overall threat assessment.

### Threat Scoring & Classification

* Applies a weighted heuristic scoring model to assess phishing likelihood.
* Combines findings from authentication analysis, URL inspection, sender validation, image analysis, and attachment inspection.
* Produces a normalized threat score ranging from 0–100.
* Uses category-based scoring with weighted contributions:

  * Authentication Analysis — up to 40 points
  * URL Analysis — up to 40 points
  * Sender Validation — up to 20 points
  * Image Analysis — up to 10 points
  * Attachment Analysis — up to 10 points
* Classifies emails into risk levels:

  * Low Risk
  * Moderate Risk
  * High Risk
* Derives likely threat categories based on dominant risk indicators.

### Reporting & Export

* Generates structured forensic analysis reports with detailed findings.
* Provides score breakdowns and risk-factor summaries.
* Displays raw analysis output for technical review.
* Supports report export as:

  * Plain text (`.txt`) via the CLI analyzer
  * Microsoft Word (`.docx`) via the web interface

### Web-Based Analysis Interface

* Provides a Flask-powered web application for email analysis.
* Supports `.eml` file uploads through a browser-based workflow.
* Presents results through an interactive dashboard.
* Displays threat scores, risk classifications, technical findings, and analysis summaries in an accessible format.
* Enables report generation and download directly from the web interface.


## Screenshots

- [Upload Interface](https://raw.githubusercontent.com/mhjshmr/EmailSleuth/main/UI%20Screenshots/127.0.0.1_5000_.png) — Initial upload interface for submitting documents.
- [Analysis Dashboard](https://raw.githubusercontent.com/mhjshmr/EmailSleuth/main/UI%20Screenshots/127.0.0.1_5000_analyze.png) — Main analysis dashboard displaying extracted insights and results.
- [Raw Report Output](https://raw.githubusercontent.com/mhjshmr/EmailSleuth/main/UI%20Screenshots/127.0.0.1_5000_analyze_raw.report.png) — Raw generated report output before export/formatting.

## Installation

```bash
git clone https://github.com/mhjshmr/EmailSleuth.git
cd EmailSleuth
```

### Create a Python virtual environment

```bash
python -m venv .venv
.\.venv\Scripts\activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

> `requirements.txt` currently includes `Flask`, `requests`, `Pillow`, and `python-docx`.

## Usage

### CLI Mode

Analyze a `.eml` file from the command line:

```bash
python Email_Analyzer.py path/to/email.eml
```

The CLI prints the generated report and prompts to save it as a `.txt` file. The CLI analyzer also attempts to extract HTML `href` links from the raw email body.

### Web Interface

Start the Flask application:

```bash
python app.py
```

Open the browser at:

```text
http://127.0.0.1:5000
```

Upload a `.eml` file, review the analysis results, and download a `.docx` report if needed.

## Web Interface Overview

The web UI provides:
- `.eml` file upload via drag-and-drop or browse.
- Summary risk score and risk level.
- Category score breakdown for authentication, URLs, sender, and images.
- Key risk factor cards and threat classification.
- Technical sections for headers, sender findings, authentication results, URL analysis, image analysis, and attachment analysis.
- A raw report text section and `.docx` download form.

## Project Structure

```
app.py
Email_Analyzer.py
requirements.txt
README.md
PROJECT_REPORT.md
static/
  └── style.css
templates/
  ├── index.html
  └── result.html
```

- `app.py` — Flask routes, upload handling, analysis orchestration, and `.docx` report export.
- `Email_Analyzer.py` — core parser, analysis functions, scoring engine, and report builders.
- `requirements.txt` — dependency list.
- `static/style.css` — shared UI styling.
- `templates/index.html` — email upload page.
- `templates/result.html` — analysis result page with export controls.
- `PROJECT_REPORT.md` — project documentation and academic report.

## Analysis Workflow

1. Upload or open a `.eml` file.
2. Parse the message into an `EmailMessage` object.
3. Extract headers with robust fallback parsing.
4. Parse sender identity and detect anomalies.
5. Extract and analyze email body URLs and obfuscation patterns.
6. Extract and analyze images and attachments.
7. Compute the final threat score.
8. Display results and generate downloadable reports.

## Threat Scoring Methodology

Threat scoring is implemented in `Email_Analyzer.py` and uses category-based heuristics.

- **Authentication:** evaluates SPF/DKIM/DMARC evidence and missing headers.
- **URL analysis:** counts obfuscated URLs, suspicious TLDs, IP-based URLs, and shortener use.
- **Sender anomalies:** flags free webmail usage with corporate display names and domain mismatches.
- **Images:** scores suspicious inline/attachment image traits.
- **Attachments:** adds risk from dangerous file types.

The aggregate score is capped at 100 and mapped to risk tiers:
- `Low risk` — below 20
- `Moderate risk` — 20 to 49
- `High risk` — 50 and above

## Technical Details

- Language: Python 3.x
- Framework: Flask
- Email parsing: Python standard library `email`
- Document export: `python-docx`
- Image analysis: `Pillow` (optional)
- URL expansion: `requests` (optional)
- Frontend: HTML, CSS, Jinja2 templates

## Core Functions and Modules

- `load_email_from_bytes()` — parse raw `.eml` bytes.
- `extract_headers()` — extract headers with case-insensitive fallback.
- `parse_sender()` — split the sender display name and email address.
- `analyze_sender()` — detect spoofing and impersonation signals.
- `analyze_authentication()` — parse SPF/DKIM/DMARC results.
- `get_email_body_text()` — extract plain text body and raw HTML.
- `extract_urls()` — extract plain text HTTP(S) URLs.
- `find_obfuscated_urls()` — detect obfuscated links like `hxxp` and bracketed dots.
- `analyze_url()` — evaluate URL risk signals and optional shortener expansion.
- `extract_images()` — collect inline and attachment images.
- `analyze_images()` — apply image heuristics and fallback filename checks.
- `analyze_attachments()` — identify risky attachment extensions.
- `compute_threat_score()` — aggregate category scores.
- `generate_risk_factors()` — summarize key risk findings.
- `derive_threat_types()` — identify likely threat categories.
- `generate_report_text()` — build the text report.
- `download_report()` — serve `.docx` exports from the web UI.

## Security Considerations

- EmailSleuth is a forensic triage tool, not a malware sandbox.
- It does not execute email attachments or perform active threat intelligence lookups.
- The score is a heuristic indicator, not a final verdict.
- The Flask app runs with `debug=True` and a hard-coded secret key in `app.py`; do not expose it in production without hardening.

## Use Cases

- Phishing triage for suspicious `.eml` samples.
- Cybersecurity training and awareness demonstrations.
- Email header forensic analysis.
- Incident response support for email-based threats.

## Future Improvements

- Add dedicated HTML `href` extraction to the web analysis path.
- Add unit tests for parsing, scoring, and report generation.
- Improve URL reputation scoring with threat intelligence sources.
- Support additional email formats such as `.msg`.
- Harden and containerize the Flask deployment for production.

## References

- RFC 7208 — SPF
- RFC 6376 — DKIM
- RFC 7489 — DMARC
- OWASP Phishing Defense Cheat Sheet

## Contributing

Contributions are welcome. Open issues or submit pull requests for bug fixes, feature requests, and documentation improvements.

## Stay Vigilant

**Think before you click.**
