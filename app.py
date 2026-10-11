"""
QRYPT – QR Code Protection
Developed by Team Cyber Titans

Backend Service: Python Flask Server (app.py)
Provides static asset serving for local execution and optional
REST API endpoints for URL security analysis and UPI verification.
"""

import re
import urllib.parse
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder='.', static_url_path='')

# Recognized URL Shorteners
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrand.ly', 'rb.gy', 'clck.ru', 'tiny.cc', 'shorturl.at',
    'cutt.ly', 'qr.ae', 'shorte.st', 'bc.vc', 'v.gd', 's.id'
}

# High-risk TLDs
HIGH_RISK_TLDS = {
    'zip', 'mov', 'top', 'xyz', 'cam', 'work', 'click', 'party',
    'gq', 'cf', 'ml', 'tk', 'loan', 'surf', 'country', 'buzz', 'stream'
}

# High-Value Brands for Spoof Detection
HIGH_VALUE_BRANDS = [
    ('Paytm', re.compile(r'paytm', re.I), 'paytm.com'),
    ('PhonePe', re.compile(r'phonepe', re.I), 'phonepe.com'),
    ('Google', re.compile(r'google', re.I), 'google.com'),
    ('PayPal', re.compile(r'paypal', re.I), 'paypal.com'),
    ('Amazon', re.compile(r'amazon', re.I), 'amazon.in'),
    ('Apple', re.compile(r'apple', re.I), 'apple.com'),
    ('SBI', re.compile(r'onlinesbi|sbicard', re.I), 'onlinesbi.sbi'),
    ('HDFC Bank', re.compile(r'hdfcbank', re.I), 'hdfcbank.com'),
    ('ICICI Bank', re.compile(r'icicibank', re.I), 'icicibank.com')
]

# Sensitive phishing keywords
SENSITIVE_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'kyc', 'otp',
    'password', 'bank', 'account-suspended', 'update-billing',
    'lottery', 'cashback', 'free-gift', 'claim-reward', 'apk'
]

# NPCI Bank Handles
NPCI_HANDLES = {
    'okaxis': ('Google Pay', 'Axis Bank'),
    'okhdfcbank': ('Google Pay', 'HDFC Bank'),
    'okicici': ('Google Pay', 'ICICI Bank'),
    'oksbi': ('Google Pay', 'State Bank of India'),
    'ybl': ('PhonePe', 'YES Bank'),
    'ibl': ('PhonePe', 'ICICI Bank'),
    'axl': ('PhonePe', 'Axis Bank'),
    'paytm': ('Paytm', 'Paytm Payments Bank / Partner Banks'),
    'apl': ('Amazon Pay', 'Axis Bank'),
    'upi': ('BHIM', 'NPCI Central Switch'),
    'sbi': ('YONO SBI', 'State Bank of India'),
    'hdfcbank': ('HDFC Mobile Banking', 'HDFC Bank'),
    'icici': ('iMobile Pay', 'ICICI Bank')
}

TRUSTED_LOCAL_VPAS = {
    'pmcares@sbi': 'Prime Minister Citizen Assistance Fund',
    'bharatbillpay@icici': 'NPCI Bharat BillPay Service',
    'cybertitans.demo@okaxis': 'Team Cyber Titans Official Lab'
}


@app.route('/')
def index():
    """Serves the main QRYPT cybersecurity dashboard."""
    return send_from_directory('.', 'index.html')


@app.route('/<path:path>')
def static_proxy(path):
    """Serves static assets (css, js, samples)."""
    return send_from_directory('.', path)


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'app': 'QRYPT – QR Code Protection',
        'team': 'Team Cyber Titans',
        'version': '2.0.0'
    })


@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    """
    Analyzes a target URL using server-side security heuristics.
    Returns: VERDICT ("SUSPICIOUS" | "NO OBVIOUS THREATS DETECTED" | "UNKNOWN"),
             risk score (0-100), and detected warning reasons.
    """
    data = request.get_json(silent=True) or {}
    raw_input = (data.get('url') or '').strip()

    if not raw_input:
        return jsonify({
            'verdict': 'UNKNOWN',
            'riskScore': 0,
            'message': 'No URL provided'
        }), 400

    effective_url = raw_input
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?(/.*)?$', raw_input):
        effective_url = 'http://' + raw_input

    try:
        parsed = urllib.parse.urlparse(effective_url)
    except Exception:
        parsed = None

    if not parsed or parsed.scheme.lower() not in ('http', 'https'):
        return jsonify({
            'verdict': 'UNKNOWN',
            'riskScore': 0,
            'input': raw_input,
            'isUrl': False,
            'message': 'Decoded data is not an HTTP/HTTPS URL.'
        })

    hostname = (parsed.hostname or '').lower()
    port = parsed.port
    path_and_query = (parsed.path + '?' + parsed.query).lower()
    warnings = []
    risk_score = 0

    # 1. HTTPS Check
    if parsed.scheme.lower() != 'https':
        risk_score += 25
        warnings.append({
            'name': 'Unencrypted HTTP Connection',
            'severity': 'HIGH',
            'desc': 'URL uses plain HTTP. Traffic and submitted credentials can be intercepted.'
        })

    # 2. Raw IP Check
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname) or (hostname.startswith('[') and hostname.endswith(']')):
        risk_score += 35
        warnings.append({
            'name': 'Raw IP Address Hostname',
            'severity': 'HIGH',
            'desc': f'Direct IP address host ({hostname}) used instead of a registered domain.'
        })

    # 3. Shortener Check
    if hostname in URL_SHORTENERS or any(hostname.endswith('.' + s) for s in URL_SHORTENERS):
        risk_score += 25
        warnings.append({
            'name': 'URL Shortener Detected',
            'severity': 'MEDIUM',
            'desc': f'Shortening domain ({hostname}) obscures final landing destination.'
        })

    # 4. Punycode Check
    if 'xn--' in hostname:
        risk_score += 35
        warnings.append({
            'name': 'Punycode / Homograph Domain',
            'severity': 'HIGH',
            'desc': 'Internationalized character encoding detected. May spoof legitimate brand glyphs.'
        })

    # 5. Risky TLD
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    if tld in HIGH_RISK_TLDS:
        risk_score += 20
        warnings.append({
            'name': f'High-Risk TLD (.{tld})',
            'severity': 'MEDIUM',
            'desc': f'The .{tld} extension has high statistical association with phishing spam.'
        })

    # 6. Brand Spoofing Check
    for brand_name, pattern, genuine_domain in HIGH_VALUE_BRANDS:
        if pattern.search(hostname) and not (hostname == genuine_domain or hostname.endswith('.' + genuine_domain)):
            risk_score += 40
            warnings.append({
                'name': f'Brand Impersonation ({brand_name})',
                'severity': 'HIGH',
                'desc': f'Hostname contains brand keyword "{brand_name}" but does not belong to "{genuine_domain}".'
            })
            break

    # 7. Non-standard port
    if port and port not in (80, 443):
        risk_score += 15
        warnings.append({
            'name': f'Non-Standard Port (:{port})',
            'severity': 'MEDIUM',
            'desc': f'Port :{port} is uncommon for public web properties.'
        })

    # 8. Phishing keywords
    matched_kw = [kw for kw in SENSITIVE_KEYWORDS if kw in path_and_query]
    if matched_kw:
        risk_score += min(25, len(matched_kw) * 10)
        warnings.append({
            'name': 'Sensitive / Phishing Action Keywords',
            'severity': 'MEDIUM',
            'desc': f'Path/query contains security or incentive keywords: {", ".join(matched_kw)}.'
        })

    # Calculate Verdict
    risk_score = min(100, max(0, risk_score))
    verdict = 'SUSPICIOUS' if (risk_score >= 25 or any(w['severity'] == 'HIGH' for w in warnings)) else 'NO OBVIOUS THREATS DETECTED'

    return jsonify({
        'verdict': verdict,
        'riskScore': risk_score,
        'effectiveUrl': effective_url,
        'hostname': hostname,
        'warnings': warnings,
        'warningCount': len(warnings)
    })


@app.route('/api/verify-upi', methods=['POST'])
def verify_upi():
    """
    Validates a UPI ID (VPA) format, checks official NPCI handle registry,
    and returns transparent verification status (VERIFIED, UNVERIFIED, or UNKNOWN).
    """
    data = request.get_json(silent=True) or {}
    upi_id = (data.get('upiId') or '').strip()

    if not upi_id:
        return jsonify({
            'verdict': 'UNKNOWN',
            'message': 'No UPI ID provided'
        }), 400

    # Basic regex validation
    if not re.match(r'^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9]{2,64}$', upi_id):
        return jsonify({
            'verdict': 'UNKNOWN',
            'upiId': upi_id,
            'message': 'Invalid UPI VPA syntax format.'
        })

    username, handle = upi_id.split('@', 1)
    handle_lower = handle.lower()
    bank_info = NPCI_HANDLES.get(handle_lower)

    if not bank_info:
        return jsonify({
            'verdict': 'UNKNOWN',
            'upiId': upi_id,
            'handle': handle_lower,
            'message': f'Bank handle "@{handle_lower}" is not recognized in the standard NPCI registry.'
        })

    # Check local trusted allowlist
    if upi_id.lower() in TRUSTED_LOCAL_VPAS:
        return jsonify({
            'verdict': 'VERIFIED',
            'upiId': upi_id,
            'managingApp': bank_info[0],
            'partnerBank': bank_info[1],
            'entityName': TRUSTED_LOCAL_VPAS[upi_id.lower()],
            'message': f'Matched trusted local directory: {TRUSTED_LOCAL_VPAS[upi_id.lower()]}'
        })

    # Transparent UNVERIFIED status (no live bank gateway integrated)
    return jsonify({
        'verdict': 'UNVERIFIED',
        'upiId': upi_id,
        'managingApp': bank_info[0],
        'partnerBank': bank_info[1],
        'message': 'Format and bank handle are structurally valid, but receiver identity is UNVERIFIED without live NPCI banking switch integration.'
    })


if __name__ == '__main__':
    print("=" * 60)
    print(" QRYPT – QR Code Protection Server")
    print(" Developed by Team Cyber Titans")
    print(" Running locally at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=True)
