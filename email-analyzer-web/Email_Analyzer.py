#!/usr/bin/env python3
"""
Simple Phishing Email Analyzer

Usage:
    python email_analyzer.py path/to/email.eml
"""

import sys
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
import io
import base64

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def safe_print(text: str):
    """Safely print text, handling encoding errors gracefully."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))


# Common free webmail providers
FREE_WEBMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
}

# TLDs often seen in suspicious / low-reputation campaigns
SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".su", ".tk", ".gq", ".ml", ".ga", ".cf",
    ".xyz", ".top", ".click", ".work", ".biz", ".zip", ".mov",
    ".rest", ".monster", ".support"
}

# Additional helpers for malicious URL detection
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly"
}

BRAND_KEYWORDS = {
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "bankofamerica", "chase", "wellsfargo"
}


def load_email_from_file(path: str):
    """Load and parse a .eml file into an EmailMessage object."""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def load_email_from_bytes(raw_data: bytes):
    """Load and parse a .eml message from raw bytes."""
    return BytesParser(policy=policy.default).parsebytes(raw_data)


def get_all_headers(msg):
    """
    Extract ALL headers from a message using multiple methods.
    Returns dict of lowercase header names -> values.
    """
    all_headers = {}
    
    # Method 1: iterate through msg.items() - gets top-level headers
    for key, val in msg.items():
        key_lower = key.lower()
        if key_lower not in all_headers:
            all_headers[key_lower] = val
        else:
            all_headers[key_lower] = all_headers[key_lower] + " | " + val
    
    # Method 2: for multipart messages, also check payload messages
    if msg.is_multipart():
        for part in msg.walk():
            if part is msg:
                continue
            try:
                for key, val in part.items():
                    key_lower = key.lower()
                    if key_lower not in all_headers:
                        all_headers[key_lower] = val
            except Exception:
                pass
    
    # Method 3: Try to get headers from the message's _headers attribute (raw storage)
    if not all_headers.get('authentication-results'):
        try:
            if hasattr(msg, '_headers'):
                for key, val in msg._headers:
                    key_lower = key.lower()
                    if key_lower not in all_headers:
                        all_headers[key_lower] = val
        except Exception:
            pass
    
    # Method 4: Try iterating message keys directly
    if not all_headers.get('authentication-results'):
        try:
            for key in msg.keys():
                val = msg.get(key)
                key_lower = key.lower()
                if key_lower not in all_headers and val:
                    all_headers[key_lower] = val
        except Exception:
            pass
    
    return all_headers


def extract_headers(msg):
    """
    Return a dict of interesting headers from the email.
    Uses multiple extraction methods to ensure headers are not lost.
    """
    # Get all headers using robust method
    all_headers = get_all_headers(msg)
    
    # Helper to get header with case-insensitive matching
    def get_header(name):
        name_lower = name.lower()
        return all_headers.get(name_lower)

    headers = {
        "From": get_header("From"),
        "To": get_header("To"),
        "Reply-To": get_header("Reply-To"),
        "Return-Path": get_header("Return-Path"),
        "Subject": get_header("Subject"),
        "Date": get_header("Date"),
        "Message-ID": get_header("Message-ID"),
        "Authentication-Results": get_header("Authentication-Results"),
        "Received-SPF": get_header("Received-SPF"),
        "DKIM-Signature": get_header("DKIM-Signature"),
        "Received": get_header("Received"),
    }
    
    # FIX 2: Add fallback for auth headers from raw email
    raw_email = msg.as_string()
    
    if not headers.get("Authentication-Results") and "Authentication-Results:" in raw_email:
        headers["Authentication-Results"] = "fallback_detected"
    
    if not headers.get("Received-SPF") and "Received-SPF:" in raw_email:
        headers["Received-SPF"] = "fallback_detected"
    
    if not headers.get("DKIM-Signature") and "DKIM-Signature:" in raw_email:
        headers["DKIM-Signature"] = "fallback_detected"
    
    return headers


def parse_sender(from_header: str):
    """
    Parse the From header into a (display_name, email_address, domain) tuple.
    """
    if not from_header:
        return None, None, None

    display_name, email_addr = parseaddr(from_header)
    if "@" in email_addr:
        local, _, domain = email_addr.rpartition("@")
    else:
        domain = None

    return display_name, email_addr, domain


def analyze_sender(display_name: str, email_addr: str, domain: str):
    """
    Perform basic checks on the sender and return a list of findings.
    """
    findings = []

    if not email_addr:
        findings.append("â— Could not parse a valid sender email address.")
        return findings

    if not domain:
        findings.append(f"â— Sender email address missing domain: {email_addr}")
        return findings

    # Check free webmail + "corporate-looking" display name
    if domain.lower() in FREE_WEBMAIL_DOMAINS and display_name:
        # Heuristic: display name has a space and a capitalized word -> might look corporate
        words = display_name.split()
        if any(len(w) > 3 and w[0].isupper() for w in words):
            findings.append(
                "âš ï¸ Display name looks like a company/person but sender uses a free webmail domain "
                f"({domain}). Possible impersonation attempt."
            )

    # Simple mismatch heuristic: if display name contains a word that doesn't appear in domain
    # (e.g., 'PayPal Support' but domain is 'random-mailer.com')
    if display_name:
        cleaned_name = re.sub(r"[^a-zA-Z0-9 ]", "", display_name).lower()
        name_tokens = [t for t in cleaned_name.split() if len(t) > 3]

        domain_core = domain.lower()
        domain_core = domain_core.replace("www.", "")

        if name_tokens and not any(token in domain_core for token in name_tokens):
            findings.append(
                "âš ï¸ Display name does not seem to match the sender domain. "
                "Check for possible spoofing or brand impersonation."
            )

    # Free webmail in general
    if domain.lower() in FREE_WEBMAIL_DOMAINS:
        findings.append(f"â„¹ï¸ Sender is using a free webmail provider: {domain}.")

    return findings


def analyze_authentication(headers):
    """
    Look at SPF/DKIM/DMARC related headers and return a summary list.
    Handles multiple auth headers and case variations.
    """
    findings = []
    seen_findings = set()  # Deduplication
    
    def add_finding(finding):
        if finding not in seen_findings:
            seen_findings.add(finding)
            findings.append(finding)
    
    # Get Authentication-Results - try multiple possible keys
    auth_results = (
        headers.get("Authentication-Results") or
        headers.get("authentication-results") or
        headers.get("Authentication-Results".lower())
    )
    
    # Get Received-SPF - may have multiple (one per hop)
    received_spf = (
        headers.get("Received-SPF") or
        headers.get("received-spf") or
        headers.get("Received-SPF".lower())
    )

    if auth_results and auth_results.strip():
        add_finding("Authentication-Results header present:")
        add_finding(f"    {auth_results}")

        auth_lower = auth_results.lower()
        if "spf=fail" in auth_lower:
            add_finding("â— SPF appears to have FAILED based on Authentication-Results.")
        elif "spf=softfail" in auth_lower:
            add_finding("âš ï¸ SPF SOFTFAIL in Authentication-Results.")
        elif "spf=pass" in auth_lower:
            add_finding("âœ… SPF PASS indicated in Authentication-Results.")

        if "dkim=fail" in auth_lower:
            add_finding("â— DKIM appears to have FAILED.")
        elif "dkim=pass" in auth_lower:
            add_finding("âœ… DKIM PASS indicated.")

        if "dmarc=fail" in auth_lower:
            add_finding("â— DMARC appears to have FAILED.")
        elif "dmarc=pass" in auth_lower:
            add_finding("âœ… DMARC PASS indicated.")
    else:
        add_finding("â„¹ï¸ No Authentication-Results header found.")

    if received_spf and received_spf.strip():
        add_finding("Received-SPF header present:")
        add_finding(f"    {received_spf}")
        spf_lower = received_spf.lower()
        if "fail" in spf_lower:
            add_finding("â— Received-SPF suggests SPF FAILURE.")
        elif "pass" in spf_lower:
            add_finding("âœ… Received-SPF suggests SPF PASS.")
    else:
        add_finding("â„¹ï¸ No Received-SPF header found.")
    
    # Check for DKIM-Signature header presence
    dkim_sig = headers.get("DKIM-Signature") or headers.get("dkim-signature")
    if dkim_sig and dkim_sig.strip():
        add_finding("â„¹ï¸ DKIM-Signature header present (signed email).")

    return findings


def get_email_body_text(msg):
    """
    Extract a combined text representation of the email body.
    Returns plain_text (str) and raw_html (str or None)
    """
    parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    text = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode("utf-8", errors="ignore")
                    else:
                        text = ""

                if ctype == "text/html":
                    # keep raw html for image analysis too
                    html_parts.append(text)
                    # Very naive HTML tag removal
                    text = re.sub(r"<[^>]+>", " ", text)
                parts.append(text)
    else:
        try:
            text = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            text = payload.decode("utf-8", errors="ignore") if payload else ""
        parts.append(text)

    plain = "\n".join(parts)
    raw_html = "\n".join(html_parts) if html_parts else None
    return plain, raw_html


def extract_images(msg):
    """
    Extract inline/attachment images from the email.
    Returns list of dicts: {cid, filename, content_type, data_bytes}
    """
    images = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype.startswith("image/"):
            cid = part.get("Content-ID")
            filename = part.get_filename()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            images.append({
                "cid": cid.strip("<>") if cid else None,
                "filename": filename,
                "content_type": ctype,
                "data": payload
            })
    return images

def analyze_attachments(msg):
    """
    Analyze attachments for suspicious file types.
    Returns:
        attachments_list: list of filenames
        attachment_score: int (threat contribution)
        findings: list of strings describing suspicious attachments
    """
    attachments_list = []
    attachment_score = 0
    findings = []
    found_filenames = set()  # Track to avoid duplicates

    # FIX 3: Use extract_attachments that checks all parts for filename
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            # Deduplicate by filename
            if filename in found_filenames:
                continue
            found_filenames.add(filename)
            
            attachments_list.append(filename)
            
            # Define high-risk file types
            risky_types = ['.exe', '.bat', '.cmd', '.docm', '.xlsm', '.pptm', '.html', '.js', '.jar']
            if any(filename.lower().endswith(ext) for ext in risky_types):
                attachment_score += 10
                findings.append(f"⚠️ Suspicious attachment detected: {filename}")
            else:
                findings.append(f"ℹ️ Attachment detected: {filename}")

    return attachments_list, attachment_score, findings

def analyze_images(images, raw_html=None):
    """
    Basic heuristics to detect screenshots or login-page-like images.
    Uses Pillow if available. Flags:
     - large inline images with screenshot-like resolution (>=600px wide)
     - filenames or cids containing login/signin/password/account
     - many inline images embedded as data: URIs in HTML (suspicious if large)
     - images wrapped in anchor tags (phishing pattern)
    """
    findings = []
    suspicious_count = 0
    seen_findings = set()  # Deduplication

    # keyword hints
    kw_pattern = re.compile(r"(login|signin|sign-in|password|account|secure)", re.IGNORECASE)

    # check for data:image URIs in raw HTML
    if raw_html and "data:image" in raw_html.lower():
        finding = "âš ï¸ HTML contains embedded data:image URIs (base64). Could be used to embed fake login screenshots."
        if finding not in seen_findings:
            seen_findings.add(finding)
            findings.append(finding)
            suspicious_count += 1

    # Check for images inside anchor tags (phishing pattern)
    if raw_html:
        # Pattern: <a ...><img ...></a> or <a ...><img .../>...</a>
        img_in_anchor_pattern = re.compile(r'<a\s+[^>]*>\s*<img\s+[^>]*>', re.IGNORECASE)
        if img_in_anchor_pattern.search(raw_html):
            finding = "âš ï¸ Detected images wrapped in clickable links - common phishing pattern to disguise malicious URLs."
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
                suspicious_count += 1

    try:
        from PIL import Image, UnidentifiedImageError
    except Exception:
        for img in images:
            fname = img.get("filename") or img.get("cid") or ""
            if kw_pattern.search(str(fname)):
                finding = f"âš ï¸ Image filename or CID suggests a login screen: {fname}"
                if finding not in seen_findings:
                    seen_findings.add(finding)
                    findings.append(finding)
                    suspicious_count += 1
        if not findings:
            findings.append("â„¹ï¸ Pillow not installed; image content not analyzed. Install pillow to enable image heuristics.")
        return findings, suspicious_count

    for img in images:
        data = img.get("data")
        fname = img.get("filename") or img.get("cid") or "<no-name>"
        if not data:
            continue
        try:
            im = Image.open(io.BytesIO(data))
            w, h = im.size
            # heuristic: screenshots often have wide aspect and decent resolution
            if w >= 600 and h >= 200:
                finding = f"âš ï¸ Image '{fname}' looks like a screenshot (resolution {w}x{h})."
                if finding not in seen_findings:
                    seen_findings.add(finding)
                    findings.append(finding)
                    suspicious_count += 1
            # small file but screenshot-like dims can be compressed login images
            size_kb = len(data) / 1024
            if size_kb < 200 and (w >= 600 or h >= 200):
                finding = f"âš ï¸ Image '{fname}' is relatively small ({int(size_kb)} KB) but large resolution -> possible screenshot/compressed login image."
                if finding not in seen_findings:
                    seen_findings.add(finding)
                    findings.append(finding)
                    suspicious_count += 1
            # filename hints
            if kw_pattern.search(fname):
                finding = f"âš ï¸ Image filename/CID contains login-related word: {fname}"
                if finding not in seen_findings:
                    seen_findings.add(finding)
                    findings.append(finding)
                    suspicious_count += 1
        except UnidentifiedImageError:
            finding = f"â„¹ï¸ Unable to parse image '{fname}' for analysis."
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
        except Exception:
            finding = f"â„¹ï¸ Error analyzing image '{fname}'."
            if finding not in seen_findings:
                seen_findings.add(finding)
                findings.append(finding)
    return findings, suspicious_count


def extract_urls(text: str):
    """
    Extract http(s) URLs from text, strip common trailing punctuation,
    and return unique ordered list.
    """
    if not text:
        return []

    # Basic URL match (stop at whitespace or common delimiters)
    raw = re.findall(r"https?://[^\s\"'<>)]+", text, flags=re.IGNORECASE)

    cleaned = []
    for u in raw:
        # Strip trailing punctuation that often follows URLs in plain text
        u = u.rstrip(".,;:!)\"'")
        cleaned.append(u)

    # keep order, remove duplicates
    return list(dict.fromkeys(cleaned))


def find_obfuscated_urls(text: str):
    """
    Detect obfuscated URL forms like hxxp://, user[.]example[.]com, http[:]//, and unicode hostnames.
    Returns a list of normalized candidate URLs (converted to http(s) where possible).
    """
    candidates = []

    if not text:
        return candidates

    # hxxp/hxxps -> http/https
    for m in re.findall(r"hxxps?://[^\s\"'<>)+]+", text, flags=re.IGNORECASE):
        candidates.append(re.sub(r"^hxxp", "http", m, flags=re.IGNORECASE))

    # bracketed dots (e.g., example[.]com)
    bracket_dot_pattern = re.compile(r"(?:https?://)?[A-Za-z0-9\-\[\]\(\)\.]{3,}\[[\.\]]+[A-Za-z0-9\-\[\]\(\)\.]{2,}")
    for m in re.findall(r"[A-Za-z0-9\-\._]+\[\.\][A-Za-z0-9\-\._]+", text):
        candidate = m.replace("[.]", ".").replace("(. )", ".").replace("(.)", ".")
        if not candidate.startswith("http"):
            candidate = "http://" + candidate
        candidates.append(candidate)

    # http[:]// style
    for m in re.findall(r"http\[:\]//[^\s\"'<>]+", text, flags=re.IGNORECASE):
        candidates.append(m.replace("http[:]//", "http://").replace("https[:]//", "https://"))

    # unicode hostnames (non-ascii)
    for m in re.findall(r"https?://[^\s\"'<>]+", text):
        hostname = urlparse(m).hostname or ""
        if any(ord(c) > 127 for c in hostname):
            candidates.append(m)

    # dedupe
    return list(dict.fromkeys(candidates))


def normalize_leet(s: str):
    """Simple leetspeak normalizer for domain misleading detection"""
    return s.replace("1", "l").replace("0", "o").replace("3", "e").replace("5", "s").replace("4", "a")


def analyze_url(url: str, body_text=None, seen_flags=None):
    """
    Return (domain, findings_for_this_url) for a single URL.
    Extended: detects suspicious TLDs, IP links, obfuscation, unicode lookalikes,
    misleading brand substitutions, and URL shorteners (with optional expansion).
    """
    findings = []
    
    # FIX 4: Use seen_flags to prevent duplicate warnings
    if seen_flags is None:
        seen_flags = set()
    
    # Handle unparseable URLs (e.g., malformed brackets, invalid IPv6)
    try:
        parsed = urlparse(url)
    except ValueError as e:
        findings.append(f"â— URL contains invalid syntax and could not be parsed: {str(e)}")
        return None, findings
    
    hostname = parsed.hostname

    if not hostname:
        findings.append("â— Could not parse hostname from URL.")
        return None, findings

    hostname_lower = hostname.lower()
    tld = "." + hostname_lower.split(".")[-1]
    if any(hostname_lower.endswith(tld_candidate) for tld_candidate in SUSPICIOUS_TLDS):
        # FIX 4: Deduplicate suspicious TLD warning
        if "suspicious_tld" not in seen_flags:
            findings.append(
                f"âš ï¸ URL uses suspicious or low-reputation TLD ({tld}). Verify legitimacy before clicking."
            )
            seen_flags.add("suspicious_tld")

    # IP address in URL
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname_lower):
        # FIX 4: Deduplicate IP URL warning
        if "ip_url" not in seen_flags:
            findings.append("âš ï¸ URL uses a raw IP address instead of a domain. May be suspicious.")
            seen_flags.add("ip_url")

    # unicode / homoglyphs
    if any(ord(c) > 127 for c in hostname_lower):
        if "unicode" not in seen_flags:
            findings.append("âš ï¸ Hostname contains non-ASCII characters (possible unicode homoglyphs).")
            seen_flags.add("unicode")

    # URL-specific checks (TLD, IP, brand) - these run for EACH URL
    # (kept inside loop as they are per-URL)
    
    # simple misleading domain detection via leet normalization and brand keywords
    norm = normalize_leet(hostname_lower)
    for brand in BRAND_KEYWORDS:
        if brand in norm and brand not in hostname_lower:
            findings.append(f"âš ï¸ Hostname '{hostname}' may be impersonating '{brand}' (character substitution/leetspeak).")

    # URL shortener detection & optional expansion
    if hostname_lower in SHORTENER_DOMAINS:
        findings.append(f"â„¹ï¸ URL uses shortener domain: {hostname_lower}")
        try:
            import requests
            r = requests.head(url, allow_redirects=True, timeout=5)
            final = r.url
            if final and final != url:
                findings.append(f"â„¹ï¸ Shortener expands to: {final}")
            else:
                findings.append("â„¹ï¸ Shortener attempted but final URL equals initial or could not be expanded.")
        except Exception:
            findings.append("â„¹ï¸ Could not expand shortener (requests module or network may be unavailable).")

    return hostname_lower, findings


def compute_threat_score(
    headers,
    sender_info,
    auth_findings,
    url_analysis,
    image_suspicious_count,
    sender_findings,
    attachment_score   # âœ… Parameter included
):
    """
    Compute a 0-100 threat score using weighted category-based heuristics.
    
    Categories with caps:
      - Authentication (SPF/DKIM/DMARC): max 40 points
      - URL analysis: max 40 points
      - Sender analysis: max 20 points
      - Images: max 10 points
    
    Design principles:
      - Combined auth failures (not stacked linearly)
      - Diminishing returns for repeated URL issues
      - Strong indicators (obfuscation, IP URLs) weighted higher
      - Weak indicators (free webmail) weighted lower
    """
    
    # ============================================
    # CATEGORY 1: AUTHENTICATION (max 40)
    # ============================================
    auth_score = 0
    
    # FIX 1: Check raw header values for fallback_detected
    auth_results = headers.get("Authentication-Results", "")
    received_spf = headers.get("Received-SPF", "")
    dkim_sig = headers.get("DKIM-Signature", "")
    
    # If auth headers exist (including fallback_detected), add base score
    if auth_results and auth_results.strip():
        if auth_results == "fallback_detected":
            # Header exists but couldn't be parsed - moderate risk
            auth_score = 15
        else:
            auth_lower = auth_results.lower()
            if "spf=fail" in auth_lower or "dkim=fail" in auth_lower or "dmarc=fail" in auth_lower:
                auth_score = 30
            elif "spf=softfail" in auth_lower:
                auth_score = 15
    
    if received_spf and received_spf.strip():
        spf_lower = received_spf.lower()
        if "fail" in spf_lower:
            auth_score = min(auth_score + 20, 40)
        elif "softfail" in spf_lower:
            auth_score = min(auth_score + 15, 40)
        elif received_spf == "fallback_detected":
            auth_score = min(auth_score + 10, 40)
    
    # Also check findings for legacy support (only if auth_score is still 0)
    if auth_score == 0:
        spf_fail = False
        dkim_fail = False
        dmarc_fail = False
        spf_pass = False
        dkim_pass = False
        dmarc_pass = False
        
        for f in auth_findings:
            low = f.lower()
            
            # Failures
            if "spf appears to have failed" in low or "spf failure" in low or "spf suggests spf failure" in low or "spf=fail" in low:
                spf_fail = True
            if "dkim appears to have failed" in low or "dkim=fail" in low:
                dkim_fail = True
            if "dmarc appears to have failed" in low or "dmarc=fail" in low:
                dmarc_fail = True
            
            # Passes (reduce score)
            if "spf pass" in low:
                spf_pass = True
            if "dkim pass" in low:
                dkim_pass = True
            if "dmarc pass" in low:
                dmarc_pass = True
        
        # Calculate auth score with combined failures
        fail_count = sum([spf_fail, dkim_fail, dmarc_fail])
        pass_count = sum([spf_pass, dkim_pass, dmarc_pass])
        
        if fail_count == 3:
            auth_score = 40
        elif fail_count == 2:
            auth_score = 30
        elif fail_count == 1:
            auth_score = 20
        
        # Softfail adds moderate risk
        for f in auth_findings:
            if "softfail" in f.lower():
                auth_score = min(auth_score + 10, 40)
        
        # Passes reduce concern
        if pass_count >= 2 and fail_count == 0:
            auth_score = max(auth_score - 10, 0)
    
    # Cap at 40
    auth_score = min(auth_score, 40)
    
    # ============================================
    # CATEGORY 2: URL ANALYSIS (max 40)
    # ============================================
    url_score = 0
    url_count = len(url_analysis)
    
    # Track issue types for diminishing returns
    suspicious_tld_count = 0
    obfuscated_count = 0
    ip_url_count = 0
    shortener_count = 0
    
    for url, (hostname, findings) in url_analysis.items():
        if not findings:
            continue
            
        for f in findings:
            lf = f.lower()
            
            # Strong indicators (high weight)
            if "obfuscated" in lf or "hxxp" in lf or "[.]" in lf:
                obfuscated_count += 1
            if "raw ip address" in lf:
                ip_url_count += 1
            
            # Moderate indicators
            if "suspicious or low-reputation tld" in lf:
                suspicious_tld_count += 1
            if "shortener" in lf:
                shortener_count += 1
    
    # Apply weights with diminishing returns
    # Strong indicators: +15 each (capped)
    url_score += min(obfuscated_count * 15, 20)  # max 20 from obfuscation
    url_score += min(ip_url_count * 15, 15)      # max 15 from IP URLs
    
    # Moderate indicators: +5 each with diminishing returns
    # First 2 count full, then diminishing
    url_score += min(suspicious_tld_count * 5, 10)  # max 10 from TLDs
    url_score += min(shortener_count * 3, 5)        # max 5 from shorteners
    
    # Cap at 40
    url_score = min(url_score, 40)
    
    # ============================================
    # CATEGORY 3: SENDER ANALYSIS (max 20)
    # ============================================
    sender_score = 0
    
    # From vs Return-Path mismatch (strong indicator)
    from_addr = sender_info[1] or ""
    rp = headers.get("Return-Path") or ""
    if rp and "@" in rp and "@" in from_addr:
        from_domain = from_addr.split("@")[-1].strip(">").lower()
        rp_domain = rp.split("@")[-1].strip(">").lower()
        if from_domain != rp_domain:
            sender_score += 15  # Significant mismatch
    
    # Sender findings analysis
    for f in sender_findings:
        low = f.lower()
        
        # Strong indicator: display name mismatch
        if "display name does not seem to match" in low:
            sender_score += 10
        
        # Weak indicator: free webmail (low weight)
        if "free webmail provider" in low:
            sender_score += 3  # Low weight - common but not necessarily suspicious
    
    # Cap at 20
    sender_score = min(sender_score, 20)
    
    # ============================================
    # CATEGORY 4: IMAGES (max 10)
    # ============================================
    image_score = min(image_suspicious_count * 5, 10)
    attachment_score = min(attachment_score, 10)  # âœ… Capped at 10
    
    # ============================================
    # TOTAL SCORE (max 100)
    # ============================================
    total_score = auth_score + url_score + sender_score + image_score + attachment_score

    # Return tuple: includes attachment_score
    return total_score, auth_score, url_score, sender_score, image_score, attachment_score


def categorize_threat_score(score: int):
    """
    Convert a numeric threat score into a risk tier label.
    
    Updated thresholds based on the new category-based scoring:
      - 0-20: Low risk   (mostly clean, minor issues)
      - 21-50: Moderate risk  (some concerns, investigate)
      - 51+: High risk   (significant threats detected)
    """
    if score >= 50:
        return "High risk"
    if score >= 20:
        return "Moderate risk"
    return "Low risk"


def generate_risk_factors(sender_findings, auth_findings, url_analysis, image_findings, attachments_findings):
    """
    Collect and group risk factors from findings into structured data.
    Returns list of dicts: {title, details: [], impact}
    """
    # Group findings by category
    auth_issues = []
    sender_issues = []
    url_issues = []
    image_issues = []
    attachment_issues = []
    
    # Process auth findings - group SPF/DKIM/DMARC
    spf_issues = []
    dkim_issues = []
    dmarc_issues = []
    
    for f in auth_findings:
        f_lower = f.lower()
        if 'spf' in f_lower and ('fail' in f_lower or 'softfail' in f_lower):
            spf_issues.append(f)
        elif 'dkim' in f_lower and 'fail' in f_lower:
            dkim_issues.append(f)
        elif 'dmarc' in f_lower and 'fail' in f_lower:
            dmarc_issues.append(f)
        elif 'fail' in f_lower:
            auth_issues.append(f)
    
    # Build grouped auth factor
    if spf_issues or dkim_issues or dmarc_issues:
        details = []
        if spf_issues:
            details.append("SPF validation failed or softfailed")
        if dkim_issues:
            details.append("DKIM signature verification failed")
        if dmarc_issues:
            details.append("DMARC policy check failed")
        auth_issues.append({
            "title": "Email Authentication Failed",
            "details": details,
            "impact": "The email failed one or more authentication checks, indicating potential spoofing."
        })
    
    # Sender findings
    for f in sender_findings:
        if any(x in f.lower() for x in ['impersonation', 'does not match', 'spoofing', 'mismatch']):
            sender_issues.append(f)
    
    # URL findings - group by URL
    url_by_severity = {}
    for url, (hostname, findings) in url_analysis.items():
        for f in findings:
            if any(x in f.lower() for x in ['obfuscated', 'raw ip', 'suspicious tld', 'impersonating', 'homoglyph']):
                if hostname not in url_by_severity:
                    url_by_severity[hostname] = []
                url_by_severity[hostname].append(f)
    
    for hostname, findings in url_by_severity.items():
        url_issues.append({
            "title": f"Suspicious Link: {hostname}",
            "details": findings[:3],  # Limit to 3 findings per URL
            "impact": "This link contains suspicious characteristics commonly used in phishing."
        })
    
    # Image findings
    for f in image_findings:
        if 'screenshot' in f.lower() or 'login' in f.lower():
            image_issues.append(f)
    
    # Attachment findings
    for f in attachments_findings:
        attachment_issues.append(f)
    
    # Build final risk factors list
    factors = []
    
    # Auth issues (highest priority)
    for issue in auth_issues:
        if isinstance(issue, str):
            factors.append({"title": "Authentication Issue", "details": [issue], "impact": None})
        else:
            factors.append(issue)
    
    # Sender issues
    for issue in sender_issues:
        factors.append({
            "title": "Sender Impersonation Detected",
            "details": [issue],
            "impact": "The sender's display name may be attempting to impersonate a trusted entity."
        })
    
    # URL issues
    for issue in url_issues:
        factors.append(issue)
    
    # Image issues
    if image_issues:
        factors.append({
            "title": "Suspicious Image Content",
            "details": image_issues[:2],
            "impact": "Images may contain hidden phishing content or fake login screens."
        })
    
    # Attachment issues
    for issue in attachment_issues:
        factors.append({
            "title": "Suspicious Attachment",
            "details": [issue],
            "impact": "This attachment type may contain malicious code."
        })
    
    return factors[:5]  # Limit to top 5


def derive_threat_types(auth_score, url_score, sender_score, image_score):
    """
    Derive threat classification based on which category contributed most to the score.
    Returns list of threat type strings.
    """
    threats = []
    
    # Map scores to threat types
    if auth_score >= 20:
        threats.append("Authentication Failure")
    if url_score >= 15:
        threats.append("Suspicious Link")
    if sender_score >= 10:
        threats.append("Impersonation")
    if image_score >= 5:
        threats.append("Suspicious Image")
    
    return threats if threats else ["No Specific Threat Detected"]


def print_report(headers, sender_info, sender_findings, auth_findings, urls, url_analysis, image_findings, attachments_list, attachment_findings, threat_score):

    output = []
    add = output.append

    risk_level = categorize_threat_score(threat_score)
    add("=" * 70)
    add(f"THREAT SCORE: {threat_score}/100")
    add(f"RISK LEVEL  : {risk_level}")
    add("NOTE: Higher scores indicate greater suspicion (heuristic).")
    add("=" * 70)
    add("EMAIL HEADER SUMMARY")
    add("=" * 70)
    add(f"From           : {headers.get('From')}")
    add(f"Reply-To       : {headers.get('Reply-To')}")
    add(f"Return-Path    : {headers.get('Return-Path')}")
    add(f"To             : {headers.get('To')}")
    add(f"Subject        : {headers.get('Subject')}")
    add(f"Date           : {headers.get('Date')}")
    add(f"Message-ID     : {headers.get('Message-ID')}")
    add("")

    display_name, email_addr, domain = sender_info
    add("Parsed Sender:")
    add(f"  Display Name : {display_name}")
    add(f"  Email        : {email_addr}")
    add(f"  Domain       : {domain}")
    add("")

    add("=== SENDER ANALYSIS ===")
    if sender_findings:
        for f in sender_findings:
            add(f" - {f}")
    else:
        add(" - No obvious sender issues detected.")
    add("")
    add("=== AUTHENTICATION (SPF/DKIM/DMARC) ===")
    for f in auth_findings:
        add(f" - {f}")
    add("")

    add("=== URL ANALYSIS ===")
    if not urls:
        add("No URLs found in email body.")
    else:
        for idx, url in enumerate(urls, start=1):
            hostname, findings = url_analysis[url]
            add(f"[{idx}] {url}")
            if hostname:
                add(f"    Domain: {hostname}")
            if findings:
                for f in findings:
                    add(f"    - {f}")
            else:
                add("    - No obvious URL issues detected by basic heuristics.")
            add("")

    add("=== IMAGE ANALYSIS ===")
    if image_findings:
        for f in image_findings:
            add(f" - {f}")
    else:
        add(" - No suspicious images detected or no images present.")
    add("")

    add("=" * 70)
    add("NOTE: This tool uses simple heuristics and is for triage only.")
    add("Always follow your organization's phishing response procedures.")
    add("=" * 70)

    return "\n".join(output)


def save_report_to_txt(report_text, filename="email_report.txt"):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\nðŸ“„ Report saved as: {filename}")
    except Exception as e:
        print(f"Error saving report: {e}")

def generate_report_text(headers, sender_info, sender_findings, auth_findings, urls, url_analysis, image_findings, attachments_list, attachment_findings, threat_score, risk_level):

    output = []
    add = output.append

    add("=" * 70)
    add(f"THREAT SCORE: {threat_score}/100")
    add(f"RISK LEVEL  : {risk_level}")
    add("NOTE: Higher scores indicate greater suspicion (heuristic).")
    add("=" * 70)

    add("EMAIL HEADER SUMMARY")
    add("=" * 70)
    add(f"From           : {headers.get('From')}")
    add(f"Reply-To       : {headers.get('Reply-To')}")
    add(f"Return-Path    : {headers.get('Return-Path')}")
    add(f"To             : {headers.get('To')}")
    add(f"Subject        : {headers.get('Subject')}")
    add(f"Date           : {headers.get('Date')}")
    add(f"Message-ID     : {headers.get('Message-ID')}")
    add("")

    display_name, email_addr, domain = sender_info
    add("Parsed Sender:")
    add(f"  Display Name : {display_name}")
    add(f"  Email        : {email_addr}")
    add(f"  Domain       : {domain}")
    add("")

    add("=== SENDER ANALYSIS ===")
    if sender_findings:
        for f in sender_findings:
            add(f" - {f}")
    else:
        add(" - No obvious sender issues detected by basic heuristics.")
    add("")

    add("=== AUTHENTICATION (SPF/DKIM/DMARC) ===")
    for f in auth_findings:
        add(f" - {f}")
    add("")

    add("=== URL ANALYSIS ===")
    if not urls:
        add("No URLs found in email body.")
    else:
        for idx, url in enumerate(urls, start=1):
            hostname, findings = url_analysis[url]
            add(f"[{idx}] {url}")
            if hostname:
                add(f"    Domain: {hostname}")
            if findings:
                for f in findings:
                    add(f"    - {f}")
            else:
                add("    - No obvious URL issues detected by basic heuristics.")
            add("")

    add("=== IMAGE ANALYSIS ===")
    if image_findings:
        for f in image_findings:
            add(f" - {f}")
    else:
        add(" - No suspicious images detected or no images present.")
    add("")

    add("=== ATTACHMENT ANALYSIS ===")
    if attachments_list:
        for f in attachment_findings:
            add(f" - {f}")
        if not attachment_findings:
            for f in attachments_list:
                add(f" - Attachment detected: {f}")
    else:
        add(" - No attachments found.")
    add("")

    add("=" * 70)
    add("NOTE: This tool uses simple heuristics and is for triage only.")
    add("Always follow your organization's phishing response procedures.")
    add("=" * 70)

    return "\n".join(output)



def main():
    if len(sys.argv) != 2:
        safe_print("Usage: python email_analyzer.py path/to/email.eml")
        sys.exit(1)

    eml_path = sys.argv[1]

    try:
        msg = load_email_from_file(eml_path)
    except FileNotFoundError:
        safe_print(f"Error: File not found: {eml_path}")
        sys.exit(1)
    except Exception as e:
        safe_print(f"Error parsing email file: {e}")
        sys.exit(1)

    headers = extract_headers(msg)

    # Sender analysis
    display_name, email_addr, domain = parse_sender(headers.get("From"))
    sender_info = (display_name, email_addr, domain)
    sender_findings = analyze_sender(display_name, email_addr, domain)

    # SPF/DKIM/DMARC
    auth_findings = analyze_authentication(headers)

    # URL analysis
    body_text, raw_html = get_email_body_text(msg)
    obf_candidates = find_obfuscated_urls(body_text)
    urls = extract_urls(body_text)
    
    # FIX 5: Extract URLs from HTML href attributes
    if raw_html:
        html_links = re.findall(r'href=["\\\'](.*?)["\\\']', raw_html)
        for link in html_links:
            if link not in urls:
                urls.append(link)
    
    for c in obf_candidates:
        if c not in urls:
            urls.append(c)

    # FIX 4: Create seen_flags for deduplication - OUTSIDE URL LOOP
    seen_flags = set()
    
    # FIX 2: Check for obfuscation patterns ONCE globally
    has_obfuscation = False
    if body_text:
        obf_patterns = ["hxxp", "[.]", "http[:]"]
        if any(p in body_text.lower() for p in obf_patterns):
            has_obfuscation = True
    
    url_analysis = {}
    obfuscation_added = False  # Track if obfuscation warning already added
    
    for url in urls:
        hostname, findings = analyze_url(url, body_text, seen_flags)
        
        # FIX 2: Add obfuscation finding only ONCE to first matching URL
        if has_obfuscation and hostname and not obfuscation_added:
            if any(hostname in s for s in re.findall(r"[A-Za-z0-9\-\._\[\]\(\)]+", body_text.lower())):
                findings.append("âš ï¸ Obfuscated URL pattern detected nearby in message body (e.g., hxxp, [.] ).")
                obfuscation_added = True
        
        url_analysis[url] = (hostname, findings)

    # Image analysis
    images = extract_images(msg)
    image_findings, image_suspicious_count = analyze_images(images, raw_html)
    
    # FIX: Add image phishing detection AFTER image analysis
    if raw_html and "<a" in raw_html and "<img" in raw_html:
        image_suspicious_count += 2
        if "image_phishing" not in seen_flags:
            image_findings.append("âš ï¸ Image used as clickable phishing element")
            seen_flags.add("image_phishing")

    # Attachment analysis
    attachments_list, attachment_score, attachment_findings = analyze_attachments(msg)
    attachment_score = min(attachment_score, 10)

    # Threat scoring
    # FIX 7: Fix scoring return bug - compute_threat_score returns a tuple
    threat_score, auth_score, url_score, sender_score, image_score, attachment_score = compute_threat_score(
        headers, sender_info, auth_findings, url_analysis, image_suspicious_count, sender_findings, attachment_score
    )

    threat_score = min(threat_score, 100)

    risk_level = categorize_threat_score(threat_score)

    # Generate report text as string
    report_text = generate_report_text(
        headers, sender_info, sender_findings, auth_findings,
        urls, url_analysis, image_findings, attachments_list, attachment_findings, threat_score, risk_level
    )


    # Print to console
    print(report_text)

    # Ask user if they want to save the report
    save_choice = input("\nDo you want to save the report to a file? (y/n): ").strip().lower()
    if save_choice == 'y':
        filename = input("Enter the filename (default: analysis_output.txt): ").strip()
        if not filename:
            filename = "analysis_output.txt"
        save_report_to_txt(report_text, filename)
    else:
        print("Report not saved.")


if __name__ == "__main__":
    main()





