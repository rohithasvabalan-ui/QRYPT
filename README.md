# QRYPT – QR Code Protection
### *Scan Smart. Stay Secure.*
**Developed by Team Cyber Titans**

---

## 1. Project Overview & Mission

**QRYPT** is a complete, working cybersecurity prototype designed to shield users from **Quishing** (QR Code Phishing) attacks, malicious website redirects, deceptive typosquatted domains, and fraudulent UPI payment traps.

QR codes are visually opaque to humans. Attackers exploit this blind spot by placing fraudulent QR stickers over genuine payment boards, transit posters, restaurant tables, and utility bills. When scanned with standard phone camera apps, devices frequently auto-navigate or prompt users to visit dangerous links without security analysis.

**QRYPT solves this challenge by implementing an isolated, client-side inspection sandbox that:**
1. Decodes QR codes completely client-side without executing or automatically opening links.
2. Evaluates the decoded payload against **11 transparent security heuristic rules**.
3. Calculates an objective **Risk Score (0–100)** and outputs one of three clear verdicts:
   - `SUSPICIOUS`
   - `NO OBVIOUS THREATS DETECTED`
   - `UNKNOWN`
4. Inspects **UPI payment QR codes (`upi://pay`)**, validates NPCI Virtual Payment Addresses (VPAs), checks bank handles, and prevents the rampant **"Reverse QR Cashback Scam"**.
5. Preserves a persistent **Scan History log** in browser storage with JSON export capabilities.

---

## 2. Technology Stack & Architecture

- **Frontend:** HTML5, CSS3 (Modern cyber dark navy, blue & neon purple glassmorphism design), Vanilla JavaScript (ES6+ modular architecture).
- **QR Decoding:** `jsQR` (bundled locally in `js/libs/jsQR.js` for 100% offline resilience, with CDN fallback).
- **Backend:**
  - `app.py`: Python Flask backend with REST endpoints (`/api/analyze-url`, `/api/verify-upi`, `/api/health`).
  - `server.js`: Zero-dependency Node.js HTTP server (ready to run with standard `node server.js`).
  - Fully functional standalone: Can also run without any server by opening `index.html` or via VS Code Live Server.

### Directory Structure
```
QRYPT/
├── index.html                 # Cybersecurity dashboard interface
├── css/
│   └── styles.css             # Responsive cyber dark theme, glowing UI, animations
├── js/
│   ├── libs/
│   │   └── jsQR.js            # Bundled local offline QR decoder
│   ├── analyzer.js            # Transparent security rules engine & threat scoring
│   ├── upi-verifier.js        # Dedicated UPI VPA verification & NPCI handle registry
│   ├── qr-engine.js           # QR file dropzone, camera feed, and decoding engine
│   ├── history.js             # LocalStorage scan log, clear, and JSON export
│   └── app.js                 # Application coordinator, tabs, and sample tests
├── samples/                   # Real QR code images for instant testing
│   ├── sample-safe.png        # Safe Government Portal QR
│   ├── sample-phishing.png    # Deceptive Brand Phishing QR
│   ├── sample-ip.png          # Raw IP Address QR
│   ├── sample-shortener.png   # Masked URL Shortener QR
│   ├── sample-punycode.png    # Punycode Homograph QR
│   ├── sample-upi.png         # Payment UPI QR
│   └── sample-wifi.png        # Raw Wi-Fi Config QR
├── app.py                     # Python Flask backend (optional REST API & static server)
├── requirements.txt           # Python dependencies (Flask>=2.3.0)
├── server.js                  # Zero-dependency Node.js local dev server
└── README.md                  # Comprehensive project documentation
```

---

## 3. How to Run Locally in VS Code

You can run QRYPT using any of the four options below:

### Option A: Using Node.js Server (Recommended & Ready)
Node.js is pre-installed on this machine. No npm packages need to be installed.
1. Open the project folder `c:\Users\ELCOT\Desktop\QRYPT` in VS Code.
2. Open the integrated terminal (`Ctrl + \``).
3. Run:
   ```bash
   node server.js
   ```
4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

### Option B: Using VS Code "Live Server" Extension
1. Install the **Live Server** extension by Ritwick Dey in VS Code (if not already installed).
2. Right-click on `index.html` in the VS Code file explorer.
3. Select **"Open with Live Server"**.
4. The dashboard will launch in your default browser at `http://127.0.0.1:5500`.

### Option C: Using Python Flask (If Python is Installed)
1. Open the VS Code terminal.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Flask application:
   ```bash
   python app.py
   ```
4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

### Option D: Direct Browser Launch (Zero-Setup)
1. Open Windows File Explorer to `c:\Users\ELCOT\Desktop\QRYPT`.
2. Double-click `index.html` to open it in Chrome, Edge, Brave, or Firefox.
3. All image decoding, heuristic rules, UPI checks, and scan history work client-side.

---

## 4. Transparent Security Rule Engine

QRYPT evaluates extracted URLs against 11 transparent, auditable heuristic checks:

| # | Security Rule | Detection Logic | Severity | Penalty |
|---|---------------|-----------------|----------|---------|
| 1 | **Protocol Encryption (HTTPS)** | Checks if URL protocol is `https:`. Flags unencrypted `http:` connections vulnerable to eavesdropping and MitM tampering. | HIGH | +25 |
| 2 | **Raw IP Address Hostname** | Detects IPv4 (e.g., `192.168.1.1`), hex/octal, or IPv6 hostnames. Legitimate consumer services use registered domains with SSL certificates. | HIGH | +35 |
| 3 | **URL Shortener Masking** | Matches host against known shortening services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) that conceal the true destination. | MEDIUM | +25 |
| 4 | **Brand Impersonation Traps** | Detects high-value brand names (`paytm`, `phonepe`, `google`, `paypal`, `sbi`, etc.) nested within unauthorized domains (e.g., `secure-paytm-login.com`). | HIGH | +40 |
| 5 | **Typosquatting Detection** | Computes Levenshtein edit distance between the target domain and official brand domains to catch deceptive lookalikes (e.g., `paypa1.com`). | HIGH | +35 |
| 6 | **Punycode / Homograph (xn--)** | Flags internationalized domain names (`xn--`) that use Cyrillic or Greek lookalike glyphs to deceive users. | HIGH | +35 |
| 7 | **High-Abuse TLD Scrutiny** | Flags top-level domains statistically associated with spam and ephemeral phishing campaigns (`.zip`, `.mov`, `.top`, `.xyz`, `.cam`, `.work`). | MEDIUM | +20 |
| 8 | **Embedded User Credentials (@ trick)** | Catches the `@` delimiter trick (`http://bank.com@evil.com`) where browsers navigate to the host following the `@` symbol. | CRITICAL | +45 |
| 9 | **Non-Standard Network Ports** | Flags explicit ports other than default 80/443 (e.g., `:8080`, `:8443`, `:22`) often used on compromised disposable servers. | MEDIUM | +15 |
| 10 | **Phishing & Urgent Lure Keywords** | Scans path and query parameters for sensitive or urgent bait keywords (`login`, `verify`, `kyc`, `otp`, `cashback`, `lottery`, `apk`). | MEDIUM | +15–25 |
| 11 | **Abnormal URL Structure & Nesting** | Identifies URLs with excessive character length (>130 chars) or deep subdomain nesting (>=4 labels) designed to obscure mobile address bars. | LOW | +10 |

### Verdict Calculation:
- **`SUSPICIOUS`**: Triggered when Risk Score $\ge 25$ or when any `HIGH` / `CRITICAL` severity rule triggers.
- **`NO OBVIOUS THREATS DETECTED`**: Triggered when the payload is a valid URL that passes all heuristic rules without triggering warnings.
- **`UNKNOWN`**: Triggered when the decoded payload is plain text, Wi-Fi configuration, or an unsupported scheme.

---

## 5. UPI Receiver Verification & Fraud Prevention

The UPI Payment Protection module is located in a dedicated dashboard section.

### The Three Strict Verification States:
1. **`VERIFIED`**:
   - Displayed **ONLY** when the VPA matches a verified institutional directory (e.g. `pmcares@sbi` or `bharatbillpay@icici`).
   - The UI transparently states the directory match.
2. **`UNVERIFIED`**:
   - Displayed when the VPA format is syntactically valid and uses a recognized NPCI bank PSP handle (e.g., `merchant@okhdfcbank` or `vendor@ybl`), but is **NOT** present in a verified enterprise directory.
   - **Crucial Cybersecurity Honesty:** The system explicitly informs the user that account ownership cannot be confirmed without an authorized NPCI VPA lookup banking gateway.
3. **`UNKNOWN`**:
   - Displayed when the input does not conform to valid NPCI VPA syntax or uses an unrecognized bank handle.

### The "Reverse QR Scam" Warning
A major form of digital payment fraud in India is the **Reverse QR Scam**, where scammers convince victims: *"Scan this QR code to receive your ₹5,000 lottery cashback / refund."*
QRYPT displays a prominent educational banner explaining:
> **Golden Rule of UPI:** Scanning a QR code only **DEBITS** money from your account. You **NEVER** need to scan a QR code or enter your secret 4/6-digit UPI PIN to receive money.

---

## 6. Built-In Test Cases

You can test QRYPT immediately using the one-click test buttons in the dashboard, or by uploading the generated test images from the `samples/` directory:

| Test Case | Sample Payload | Expected Verdict | Reason |
|-----------|----------------|------------------|--------|
| **1. Legitimate Government Portal** | `https://cybercrime.gov.in` | `NO OBVIOUS THREATS DETECTED` | Clean HTTPS, official government domain, no suspicious patterns. |
| **2. Phishing Brand Spoof** | `http://secure-login-paytm.verify-account.top/login.php?otp=true` | `SUSPICIOUS` (Risk: 100/100) | Plain HTTP, Paytm brand impersonation, high-abuse `.top` TLD, sensitive `login`/`otp` keywords. |
| **3. Raw IP Address & Port** | `http://192.168.1.105:8080/claim-reward` | `SUSPICIOUS` (Risk: 90/100) | Unencrypted HTTP, direct IP host, non-standard port 8080, reward bait keyword. |
| **4. Masked URL Shortener** | `https://bit.ly/3xPhishCode` | `SUSPICIOUS` (Risk: 25/100) | Known URL shortener masking the true landing destination. |
| **5. Punycode Homograph Attack** | `https://xn--appl-45a.com/verify-account` | `SUSPICIOUS` (Risk: 55/100) | Internationalized `xn--` domain spoofing lookalike brand glyphs. |
| **6. Payment UPI QR** | `upi://pay?pa=lottery-claim@ybl&pn=Jackpot%20Rewards&am=1000` | Analyzed in UPI Module | Flags scam keywords in UPI username; explains receiver verification state. |
| **7. Raw Wi-Fi Config** | `WIFI:T:WPA;S:OfficeNet;P:CyberTitans2026;;` | `UNKNOWN` (Score: 0) | Non-web payload; classified as unclassified data for manual inspection. |

---

## 7. Limitations of Rule-Based Detection

As an honest cybersecurity tool, QRYPT clearly communicates the technical boundaries of client-side heuristic inspection:

1. **Heuristics vs. Zero-Day Threats:**
   Rule-based detection checks for structural anomalies, protocol misconfigurations, and known deception patterns. A newly registered domain with a valid SSL certificate that hosts a cloned login form may not trigger structural heuristic rules.
2. **Absence of Live Threat Intelligence Feeds:**
   Without paid enterprise feeds (like Google Safe Browsing API, VirusTotal, or live DNS reputation databases), heuristics alone cannot guarantee that an unflagged link is safe.
3. **No NPCI Switch Integration:**
   Real-time UPI account holder verification requires a Reserve Bank of India (RBI) regulated banking license and licensed PSP integration with signed TLS client certificates. Client-side tools cannot query live bank switches.

---

## 8. Verification & Test Evidence

All modules have been tested with automated test suites:
- **Security Analyzer:** Verified against safe URLs, brand spoofs, IP addresses, shorteners, and Punycode attacks.
- **UPI Verifier:** Verified against trusted directories, valid handles, unrecognized handles, and full `upi://pay` URIs.
- **History Manager:** Verified record addition, retrieval, persistence in `localStorage`, JSON export, and clearing.
- **Server:** Verified HTTP 200 responses across all static assets.

---
**Team Cyber Titans** &bull; *Scan Smart. Stay Secure.*
