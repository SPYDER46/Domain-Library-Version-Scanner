import requests
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
# Basic CVE Lookup (NVD API)
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