from flask import Flask, render_template, request
from urllib.parse import urlparse
from scanner import (
    detect_technologies,
    check_security_headers,
    get_ssl_info,
    detect_waf,
    calculate_risk,
    lookup_cves
)

app = Flask(__name__)
scan_history = []

@app.route("/", methods=["GET", "POST"])
def index():
    results = None

    if request.method == "POST":
        domain = request.form["domain"]

        if not domain.startswith("http"):
            domain = "https://" + domain

        parsed_url = urlparse(domain)
        hostname = parsed_url.netloc

        tech = detect_technologies(domain)
        headers = check_security_headers(domain)
        ssl_info = get_ssl_info(hostname)

        waf = detect_waf(domain)
        risk = calculate_risk(headers, ssl_info, tech)
        cves = lookup_cves(tech)

        results = {
            "domain": domain,
            "technologies": tech,
            "headers": headers,
            "ssl": ssl_info,
            "waf": waf,
            "risk": risk,
            "cves": cves
          }

        scan_history.append(results)

    return render_template("index.html", results=results, history=scan_history)

if __name__ == "__main__":
    app.run(debug=True)