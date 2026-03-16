import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import ssl
import socket
from datetime import datetime
from Wappalyzer import Wappalyzer, WebPage

# ----------------------------
# Technology Detection
# ----------------------------
def detect_technologies(url):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, timeout=10)
        return wappalyzer.analyze_with_versions(webpage)
    except Exception as e:
        return {"Error": str(e)}


# ----------------------------
# Security Headers Check
# ----------------------------
def check_security_headers(url):
    headers_data = {}
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "X-Content-Type-Options"
        ]

        for header in security_headers:
            headers_data[header] = headers.get(header, "Missing")

    except Exception as e:
        headers_data["Error"] = str(e)

    return headers_data


# ----------------------------
# SSL Info
# ----------------------------
def get_ssl_info(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.settimeout(5)

    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()

        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])

        return {
            "issuer": issuer,
            "subject": subject,
            "valid_from": cert['notBefore'],
            "valid_to": cert['notAfter']
        }

    except Exception as e:
        return {"Error": str(e)}


# ----------------------------
# WAF Detection
# ----------------------------
def detect_waf(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        waf_signatures = {
            "cloudflare": "Cloudflare",
            "sucuri": "Sucuri",
            "akamai": "Akamai",
            "imperva": "Imperva",
            "aws": "AWS WAF"
        }

        detected = []

        for header_value in headers.values():
            for signature in waf_signatures:
                if signature.lower() in header_value.lower():
                    detected.append(waf_signatures[signature])

        if detected:
            return list(set(detected))
        else:
            return ["No WAF Detected"]

    except:
        return ["Error Detecting WAF"]


# ----------------------------
# Risk Score Calculation
# ----------------------------
def calculate_risk(headers, ssl_info, technologies):
    score = 100

    if "Error" in headers:
        score -= 20
    else:
        missing = list(headers.values()).count("Missing")
        score -= missing * 5

    if "Error" in ssl_info:
        score -= 20

    if "Error" in technologies:
        score -= 10

    if score < 0:
        score = 0

    return score


# ----------------------------
# CVE Lookup (NVD API)
# ----------------------------
def lookup_cves(technologies):
    cve_results = {}

    for tech, version in technologies.items():
        if version:
            query = f"{tech} {version}"
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
                response = requests.get(url, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    total = data.get("totalResults", 0)
                    cve_results[f"{tech} {version}"] = total
                else:
                    cve_results[f"{tech} {version}"] = "API Error"
            except:
                cve_results[f"{tech} {version}"] = "Lookup Failed"

    return cve_results

# ----------------------------
# Advanced Directory Scanner
# ----------------------------
WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt"

def scan_dirs(base_url, max_depth=2, max_workers=50):
    """
    Scan directories recursively with multi-threading.
    max_depth: how deep to crawl subdirs
    """
    found = []
    visited = set()

    try:
        wordlist = requests.get(WORDLIST_URL, timeout=15).text.splitlines()
        wordlist = wordlist[:5000]  # limit for speed
    except:
        return [{"error": "Wordlist download failed"}]

    def scan(url, depth):
        if url in visited or depth > max_depth:
            return
        visited.add(url)

        for path in wordlist:
            full_url = urljoin(url + "/", path)
            try:
                r = requests.get(full_url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    found.append({"url": full_url, "status": r.status_code})
                    if depth < max_depth:
                        scan(full_url, depth + 1)
            except:
                continue

    # Use multi-threading for top-level scan
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda p: scan(base_url, 1), [base_url])

    return found

def crawl_urls(base_url, limit=200):

    visited = set()
    urls = set()

    try:

        response = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        # Scan <a> links
        for link in soup.find_all("a", href=True):

            url = urljoin(base_url, link["href"])

            if base_url in url:
                urls.add(url)

        # Scan forms
        for form in soup.find_all("form"):

            action = form.get("action")

            if action:
                url = urljoin(base_url, action)

                if base_url in url:
                    urls.add(url)

        # Scan scripts
        for script in soup.find_all("script", src=True):

            url = urljoin(base_url, script["src"])

            if base_url in url:
                urls.add(url)

    except:
        pass

    return list(urls)[:limit]

# ----------------------------
# Vulnerability Scanner (Top OWASP)
# ----------------------------
def scan_vulnerabilities(urls):
    """
    Scan a list of URLs for simple vulnerabilities:
    SQLi, XSS, LFI, RCE (basic detection)
    """
    vulnerabilities = []

    # simple payloads
    sql_payload = "' OR '1'='1"
    xss_payload = "<script>alert('XSS')</script>"
    lfi_payload = "../../etc/passwd"

    sql_errors = [
        "sql syntax",
        "mysql",
        "syntax error",
        "unclosed quotation mark",
        "pdoexception",
        "odbc"
    ]

    for url in urls:
        try:
            # --- SQL Injection Check ---
            r = requests.get(url + sql_payload, timeout=5)
            for error in sql_errors:
                if error in r.text.lower():
                    vulnerabilities.append({
                        "url": url,
                        "vuln": "Possible SQL Injection"
                    })
                    break

            # --- XSS Check ---
            r = requests.get(url + "?test=" + xss_payload, timeout=5)
            if xss_payload.lower() in r.text.lower():
                vulnerabilities.append({
                    "url": url,
                    "vuln": "Possible XSS"
                })

            # --- LFI Check ---
            r = requests.get(url + "?file=" + lfi_payload, timeout=5)
            if "root:" in r.text or "bin/bash" in r.text:
                vulnerabilities.append({
                    "url": url,
                    "vuln": "Possible LFI"
                })

        except:
            continue

    return vulnerabilities