
from flask import Flask, render_template, request, redirect, url_for, jsonify
from datetime import datetime
import re
import urllib.parse

app = Flask(__name__)

captured_credentials = []


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "amazon", "google", "microsoft", "apple",
    "password", "credential", "confirm", "wallet", "support"
]

TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "github.com",
    "linkedin.com", "instagram.com"
]

def analyze_url(url: str) -> dict:
    """
    Analyze a URL for phishing indicators using rule-based heuristics.
    Returns a dict with a risk score (0-100) and list of detected red flags.
    """
    flags = []
    score = 0

 
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        full   = url.lower()
    except Exception:
        return {"score": 100, "flags": ["❌ Could not parse URL"], "verdict": "DANGEROUS"}

    if parsed.scheme == "http":
        flags.append("🔓 Uses HTTP instead of HTTPS — connection is unencrypted")
        score += 20

   
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain):
        flags.append("🖥️  IP address used instead of a domain name")
        score += 30

   
    subdomain_count = domain.count(".")
    if subdomain_count >= 3:
        flags.append(f"🔗 Suspicious subdomain depth ({subdomain_count} dots) — possible domain spoofing")
        score += 15

    # ── Rule 4: Trusted brand name in subdomain (homograph / typosquatting) ───
    for trusted in TRUSTED_DOMAINS:
        brand = trusted.split(".")[0]           # e.g. "paypal"
        if brand in domain and trusted not in domain:
            flags.append(f"🎭 '{brand}' appears in domain but is NOT the real {trusted}")
            score += 35
            break

    # ── Rule 5: Suspicious keywords in URL ────────────────────────────────────
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if len(keyword_hits) >= 2:
        flags.append(f"🔑 High-risk keywords found: {', '.join(keyword_hits[:4])}")
        score += 10

    if len(url) > 100:
        flags.append(f"📏 Unusually long URL ({len(url)} chars) — may be hiding true destination")
        score += 10

  
    if "@" in url:
        flags.append("⚠️  '@' symbol found — everything before it is ignored by the browser")
        score += 40

    if "//" in path:
        flags.append("↪️  Double slashes in path — possible open redirect trick")
        score += 15

    # ── Rule 9: Punycode / IDN homograph attack ───────────────────────────────
    if "xn--" in domain:
        flags.append("🌐 Punycode detected — domain may impersonate another via lookalike characters")
        score += 35

    # ── Rule 10: Suspicious TLDs commonly used in abuse ──────────────────────
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        flags.append("🏴 High-abuse TLD (.tk, .ml, .xyz, etc.)")
        score += 20

    # ── Cap score at 100 & assign verdict ────────────────────────────────────
    score = min(score, 100)

    if score == 0:
        verdict = "SAFE"
    elif score <= 30:
        verdict = "SUSPICIOUS"
    elif score <= 60:
        verdict = "LIKELY PHISHING"
    else:
        verdict = "DANGEROUS"

    if not flags:
        flags.append("✅ No obvious red flags detected — but always verify manually!")

    return {"score": score, "flags": flags, "verdict": verdict, "url": url}


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Dashboard — shows both the fake login demo and the URL checker."""
    return render_template("index.html")


@app.route("/fake-login")
def fake_login():
    """
    Renders a convincing fake login page that mimics a popular service.
    This shows how attackers clone legitimate UIs to steal credentials.
    """
    return render_template("fake_login.html")


@app.route("/capture", methods=["POST"])
def capture():
    """
    Simulates what a phishing server does: harvests submitted credentials.
    In a real attack the attacker would log these and redirect to the real site.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    ip_address = request.remote_addr
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Store the captured data (demo only — never do this on real users!)
    entry = {
        "username":  username,
        "password":  password,
        "ip":        ip_address,
        "timestamp": timestamp,
        "user_agent": request.headers.get("User-Agent", "Unknown")[:80]
    }
    captured_credentials.append(entry)

    # After harvesting, a real attacker redirects to the legitimate site
    # so the victim thinks they just mis-typed their password.
    return redirect(url_for("captured", index=len(captured_credentials) - 1))


@app.route("/captured/<int:index>")
def captured(index):
    """Shows the 'caught you!' educational reveal screen."""
    entry = captured_credentials[index] if 0 <= index < len(captured_credentials) else {}
    return render_template("captured.html", entry=entry)


@app.route("/dashboard")
def dashboard():
    """Admin dashboard showing all captured credentials (for demo visualization)."""
    return render_template("dashboard.html", credentials=captured_credentials)


@app.route("/url-checker")
def url_checker():
    """URL phishing detection page."""
    return render_template("url_checker.html")


@app.route("/api/check-url", methods=["POST"])
def check_url_api():
    """JSON API endpoint that returns phishing analysis for a given URL."""
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_url(url)
    return jsonify(result)


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════╗
    ║    Phishing Simulator — Educational Demo       ║
    ║   http://localhost:5000                          ║
    ║                                                  ║
    ║    FOR LEARNING PURPOSES ONLY                 ║
    ╚══════════════════════════════════════════════════╝
    """)
    app.run(debug=True, port=5000)
