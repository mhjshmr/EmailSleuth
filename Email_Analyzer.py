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


def extract_headers(msg):
    """Return a dict of interesting headers from the email."""
    headers = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Reply-To": msg.get("Reply-To"),
        "Return-Path": msg.get("Return-Path"),
        "Subject": msg.get("Subject"),
        "Date": msg.get("Date"),
        "Message-ID": msg.get("Message-ID"),
        "Authentication-Results": msg.get("Authentication-Results"),
        "Received-SPF": msg.get("Received-SPF"),
    }
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
        findings.append("❗ Could not parse a valid sender email address.")
        return findings

    if not domain:
        findings.append(f"❗ Sender email address missing domain: {email_addr}")
        return findings

    # Check free webmail + "corporate-looking" display name
    if domain.lower() in FREE_WEBMAIL_DOMAINS and display_name:
        # Heuristic: display name has a space and a capitalized word -> might look corporate
        words = display_name.split()
        if any(len(w) > 3 and w[0].isupper() for w in words):
            findings.append(
                "⚠️ Display name looks like a company/person but sender uses a free webmail domain "
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
                "⚠️ Display name does not seem to match the sender domain. "
                "Check for possible spoofing or brand impersonation."
            )

    # Free webmail in general
    if domain.lower() in FREE_WEBMAIL_DOMAINS:
        findings.append(f"ℹ️ Sender is using a free webmail provider: {domain}.")

    return findings


def analyze_authentication(headers):
    """
    Look at SPF/DKIM/DMARC related headers and return a summary list.
    """
    findings = []
    auth_results = headers.get("Authentication-Results")
    received_spf = headers.get("Received-SPF")

    if auth_results:
        findings.append("Authentication-Results header present:")
        findings.append(f"    {auth_results}")

        if "spf=fail" in auth_results.lower():
            findings.append("❗ SPF appears to have FAILED based on Authentication-Results.")
        elif "spf=softfail" in auth_results.lower():
            findings.append("⚠️ SPF SOFTFAIL in Authentication-Results.")
        elif "spf=pass" in auth_results.lower():
            findings.append("✅ SPF PASS indicated in Authentication-Results.")

        if "dkim=fail" in auth_results.lower():
            findings.append("❗ DKIM appears to have FAILED.")
        elif "dkim=pass" in auth_results.lower():
            findings.append("✅ DKIM PASS indicated.")

        if "dmarc=fail" in auth_results.lower():
            findings.append("❗ DMARC appears to have FAILED.")
        elif "dmarc=pass" in auth_results.lower():
            findings.append("✅ DMARC PASS indicated.")
    else:
        findings.append("ℹ️ No Authentication-Results header found.")

    if received_spf:
        findings.append("Received-SPF header present:")
        findings.append(f"    {received_spf}")
        if "fail" in received_spf.lower():
            findings.append("❗ Received-SPF suggests SPF FAILURE.")
        elif "pass" in received_spf.lower():
            findings.append("✅ Received-SPF suggests SPF PASS.")
    else:
        findings.append("ℹ️ No Received-SPF header found.")

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


def analyze_images(images, raw_html=None):
    """
    Basic heuristics to detect screenshots or login-page-like images.
    Uses Pillow if available. Flags:
     - large inline images with screenshot-like resolution (>=600px wide)
     - filenames or cids containing login/signin/password/account
     - many inline images embedded as data: URIs in HTML (suspicious if large)
    """
    findings = []
    suspicious_count = 0

    # keyword hints
    kw_pattern = re.compile(r"(login|signin|sign-in|password|account|secure)", re.IGNORECASE)

    # check for data:image URIs in raw HTML
    if raw_html and "data:image" in raw_html.lower():
        findings.append("⚠️ HTML contains embedded data:image URIs (base64). Could be used to embed fake login screenshots.")
        suspicious_count += 1

    try:
        from PIL import Image, UnidentifiedImageError
    except Exception:
        # Pillow not installed; do filename/size checks only
        for img in images:
            fname = img.get("filename") or img.get("cid") or ""
            if kw_pattern.search(str(fname)):
                findings.append(f"⚠️ Image filename or CID suggests a login screen: {fname}")
                suspicious_count += 1
        if not findings:
            findings.append("ℹ️ Pillow not installed; image content not analyzed. Install pillow to enable image heuristics.")
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
                findings.append(f"⚠️ Image '{fname}' looks like a screenshot (resolution {w}x{h}).")
                suspicious_count += 1
            # small file but screenshot-like dims can be compressed login images
            size_kb = len(data) / 1024
            if size_kb < 200 and (w >= 600 or h >= 200):
                findings.append(f"⚠️ Image '{fname}' is relatively small ({int(size_kb)} KB) but large resolution -> possible screenshot/compressed login image.")
                suspicious_count += 1
            # filename hints
            if kw_pattern.search(fname):
                findings.append(f"⚠️ Image filename/CID contains login-related word: {fname}")
                suspicious_count += 1
        except UnidentifiedImageError:
            findings.append(f"ℹ️ Unable to parse image '{fname}' for analysis.")
        except Exception:
            findings.append(f"ℹ️ Error analyzing image '{fname}'.")
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


def analyze_url(url: str, body_text=None):
    """
    Return (domain, findings_for_this_url) for a single URL.
    Extended: detects suspicious TLDs, IP links, obfuscation, unicode lookalikes,
    misleading brand substitutions, and URL shorteners (with optional expansion).
    """
    findings = []
    
    # Handle unparseable URLs (e.g., malformed brackets, invalid IPv6)
    try:
        parsed = urlparse(url)
    except ValueError as e:
        findings.append(f"❗ URL contains invalid syntax and could not be parsed: {str(e)}")
        return None, findings
    
    hostname = parsed.hostname

    if not hostname:
        findings.append("❗ Could not parse hostname from URL.")
        return None, findings

    hostname_lower = hostname.lower()
    tld = "." + hostname_lower.split(".")[-1]
    if any(hostname_lower.endswith(tld_candidate) for tld_candidate in SUSPICIOUS_TLDS):
        findings.append(
            f"⚠️ URL uses suspicious or low-reputation TLD ({tld}). Verify legitimacy before clicking."
        )

    # IP address in URL
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname_lower):
        findings.append("⚠️ URL uses a raw IP address instead of a domain. May be suspicious.")

    # unicode / homoglyphs
    if any(ord(c) > 127 for c in hostname_lower):
        findings.append("⚠️ Hostname contains non-ASCII characters (possible unicode homoglyphs).")

    # obfuscated patterns in source body near url
    if body_text:
        obf_patterns = ["hxxp", "[.]", "http[:]"]
        if any(p in body_text.lower() for p in obf_patterns):
            if any(hostname_lower in s for s in re.findall(r"[A-Za-z0-9\-\._\[\]\(\)]+", body_text.lower())):
                findings.append("⚠️ Obfuscated URL pattern detected nearby in message body (e.g., hxxp, [.] ).")

    # simple misleading domain detection via leet normalization and brand keywords
    norm = normalize_leet(hostname_lower)
    for brand in BRAND_KEYWORDS:
        if brand in norm and brand not in hostname_lower:
            findings.append(f"⚠️ Hostname '{hostname}' may be impersonating '{brand}' (character substitution/leetspeak).")

    # URL shortener detection & optional expansion
    if hostname_lower in SHORTENER_DOMAINS:
        findings.append(f"ℹ️ URL uses shortener domain: {hostname_lower}")
        try:
            import requests
            r = requests.head(url, allow_redirects=True, timeout=5)
            final = r.url
            if final and final != url:
                findings.append(f"ℹ️ Shortener expands to: {final}")
            else:
                findings.append("ℹ️ Shortener attempted but final URL equals initial or could not be expanded.")
        except Exception:
            findings.append("ℹ️ Could not expand shortener (requests module or network may be unavailable).")

    return hostname_lower, findings


def compute_threat_score(headers, sender_info, auth_findings, url_analysis, image_suspicious_count, sender_findings):
    """
    Compute a 0-100 threat score using simple weighted heuristics.
    Heuristic weights:
      - SPF/DKIM/DMARC FAIL: +30
      - SPF/DKIM softfail: +10
      - Suspicious URL TLD: +15 per URL
      - Obfuscated URL: +25 per occurrence
      - IP-based URL: +20 per URL
      - Shortener with expansion to suspicious: +10
      - From/Return-Path mismatch: +20
      - Suspicious inline images/screenshots: +10 each
      - Sender using free webmail with brand-like display name: +10
    """
    score = 0

    # Auth header signals
    for f in auth_findings:
        low = f.lower()
        if "spf appears to have failed" in low or "spf failure" in low or "spf suggests spf failure" in low or "spf=fail" in low:
            score += 30
        elif "spf softfail" in low or "softfail" in low:
            score += 10
        if "dkim appears to have failed" in low or "dkim=fail" in low:
            score += 30
        elif "dkim pass" in low:
            score += 0
        if "dmarc appears to have failed" in low or "dmarc=fail" in low:
            score += 30

    # URL analysis
    for url, (hostname, findings) in url_analysis.items():
        for f in findings:
            lf = f.lower()
            if "suspicious or low-reputation tld" in lf:
                score += 15
            if "obfuscated" in lf or "hxxp" in lf or "[.]" in lf:
                score += 25
            if "raw ip address" in lf:
                score += 20
            if "shortener" in lf and "expands to" in lf:
                score += 10

    # From vs Return-Path mismatch
    from_addr = sender_info[1] or ""
    rp = headers.get("Return-Path") or ""
    if rp and "@" in rp and "@" in from_addr and rp.split("@")[-1].strip(">") != from_addr.split("@")[-1]:
        score += 20

    # Image suspicious
    score += image_suspicious_count * 10

    # Sender findings (free webmail impersonation)
    for f in sender_findings:
        if "free webmail provider" in f.lower():
            score += 10
        if "display name does not seem to match" in f.lower():
            score += 15

    # bound score
    if score > 100:
        score = 100
    return int(score)


def print_report(headers, sender_info, sender_findings, auth_findings, urls, url_analysis, image_findings, threat_score):
    output = []
    add = output.append

    add("=" * 70)
    add(f"THREAT SCORE: {threat_score}/100")
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
        print(f"\n📄 Report saved as: {filename}")
    except Exception as e:
        print(f"Error saving report: {e}")

def generate_report_text(headers, sender_info, sender_findings, auth_findings, urls, url_analysis, image_findings, threat_score):
    output = []
    add = output.append

    add("=" * 70)
    add(f"THREAT SCORE: {threat_score}/100")
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
    for c in obf_candidates:
        if c not in urls:
            urls.append(c)

    url_analysis = {}
    for url in urls:
        hostname, findings = analyze_url(url, body_text)
        url_analysis[url] = (hostname, findings)

    # Image analysis
    images = extract_images(msg)
    image_findings, image_suspicious_count = analyze_images(images, raw_html)

    # Threat scoring
    threat_score = compute_threat_score(
        headers, sender_info, auth_findings, url_analysis, image_suspicious_count, sender_findings
    )

    # Generate report text as string
    report_text = print_report(
       headers, sender_info, sender_findings, auth_findings,
       urls, url_analysis, image_findings, threat_score
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

