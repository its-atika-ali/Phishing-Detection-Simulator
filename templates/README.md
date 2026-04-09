# 🎓 Phishing Attack Simulator

> **⚠️ FOR EDUCATIONAL USE ONLY**  
> This tool is designed to teach how phishing attacks work.  
> Never use these techniques on real users or systems without explicit authorization.  
> Unauthorized phishing is illegal and unethical.

---

## What's Inside

| File | Purpose |
|------|---------|
| `app.py` | Flask server — routes, credential capture, URL analysis engine |
| `templates/base.html` | Shared layout & navigation |
| `templates/index.html` | Homepage / dashboard |
| `templates/fake_login.html` | Cloned login page demo |
| `templates/captured.html` | "You've been phished!" reveal & lessons |
| `templates/dashboard.html` | Attacker view of captured credentials |
| `templates/url_checker.html` | Interactive URL phishing detector |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
python app.py

# 3. Open your browser
# http://localhost:5000
```

---

## Features

### 🎭 Fake Login Page (`/fake-login`)
- Pixel-perfect clone of a fictional banking site
- Demonstrates how attackers replicate trusted UIs
- Shows false trust indicators (HTTPS badge, padlock)
- Submits to `/capture` which logs credentials and redirects

### 🔍 URL Phishing Detector (`/url-checker`)
10+ heuristic rules checked per URL:
1. HTTP (no HTTPS)
2. IP address instead of domain
3. Excessive subdomain depth
4. Trusted brand in subdomain (typosquatting)
5. Multiple high-risk keywords
6. Overly long URL (>100 chars)
7. @ symbol in URL
8. Double slashes in path
9. Punycode / IDN homograph
10. High-abuse TLD (.tk, .ml, .xyz…)

### 📊 Dashboard (`/dashboard`)
- Simulates attacker's credential collection view
- Shows username, password, IP, timestamp, user agent

---

## Learning Objectives

After using this tool you should be able to:
- Recognize a cloned login page
- Identify red flags in URLs before clicking
- Understand why HTTPS ≠ legitimate
- Know why password managers protect against phishing
- Explain why MFA is critical even if credentials leak

---

## License
MIT — for educational purposes only.
