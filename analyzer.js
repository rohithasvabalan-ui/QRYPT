/**
 * QRYPT – QR Code Protection
 * Developed by Team Cyber Titans
 *
 * Module: Security Rules & Threat Analyzer (js/analyzer.js)
 * Purpose: Evaluates URLs and raw data against transparent cybersecurity heuristic rules.
 * Outputs: VERDICT ("SUSPICIOUS" | "NO OBVIOUS THREATS DETECTED" | "UNKNOWN"),
 *          Risk Score (0-100), Triggered Rules, Evaluated Checklist, and Safety Next Steps.
 */

(function (window) {
  'use strict';

  // Recognized URL Shorteners
  const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrand.ly', 'rb.gy', 'clck.ru', 'tiny.cc', 'shorturl.at',
    'cutt.ly', 'qr.ae', 'shorte.st', 'bc.vc', 'v.gd', 'soo.gd',
    's.id', 'goo.gl', 'bl.ink', 'adf.ly', 'snip.ly'
  ]);

  // High-Abuse / High-Risk Top-Level Domains (frequently leveraged in ephemeral phishing campaigns)
  const HIGH_RISK_TLDS = new Set([
    'zip', 'mov', 'top', 'xyz', 'cam', 'work', 'click', 'party',
    'gq', 'cf', 'ml', 'tk', 'loan', 'surf', 'country', 'buzz',
    'stream', 'racing', 'link', 'kim', 'win', 'men', 'trade'
  ]);

  // High-Value Brand Targets for Impersonation / Typosquatting Checks
  const HIGH_VALUE_BRANDS = [
    { name: 'Paytm', pattern: /paytm/i, genuineDomain: 'paytm.com' },
    { name: 'PhonePe', pattern: /phonepe/i, genuineDomain: 'phonepe.com' },
    { name: 'Google Pay / GPay', pattern: /(gpay|googlepay)/i, genuineDomain: 'pay.google.com' },
    { name: 'Google', pattern: /google/i, genuineDomain: 'google.com' },
    { name: 'PayPal', pattern: /paypal/i, genuineDomain: 'paypal.com' },
    { name: 'Amazon', pattern: /amazon/i, genuineDomain: 'amazon.in' },
    { name: 'Apple', pattern: /apple/i, genuineDomain: 'apple.com' },
    { name: 'Microsoft', pattern: /microsoft/i, genuineDomain: 'microsoft.com' },
    { name: 'Netflix', pattern: /netflix/i, genuineDomain: 'netflix.com' },
    { name: 'State Bank of India (SBI)', pattern: /(onlinesbi|sbicard|sbipay)/i, genuineDomain: 'onlinesbi.sbi' },
    { name: 'HDFC Bank', pattern: /hdfcbank/i, genuineDomain: 'hdfcbank.com' },
    { name: 'ICICI Bank', pattern: /icicibank/i, genuineDomain: 'icicibank.com' },
    { name: 'Axis Bank', pattern: /axisbank/i, genuineDomain: 'axisbank.com' },
    { name: 'BHIM UPI', pattern: /bhimupi/i, genuineDomain: 'bhimupi.org.in' },
    { name: 'Razorpay', pattern: /razorpay/i, genuineDomain: 'razorpay.com' },
    { name: 'WhatsApp', pattern: /whatsapp/i, genuineDomain: 'whatsapp.com' },
    { name: 'Facebook / Meta', pattern: /(facebook|meta)/i, genuineDomain: 'facebook.com' },
    { name: 'Instagram', pattern: /instagram/i, genuineDomain: 'instagram.com' }
  ];

  // Sensitive / Phishing Action Keywords in Path or Query
  const SENSITIVE_KEYWORDS = [
    { term: 'login', label: 'Account login' },
    { term: 'signin', label: 'Sign-in prompt' },
    { term: 'verify', label: 'Verification prompt' },
    { term: 'verification', label: 'Identity verification' },
    { term: 'kyc', label: 'KYC update bait' },
    { term: 'otp', label: 'One-Time Password capture' },
    { term: 'password', label: 'Password field' },
    { term: 'bank', label: 'Banking action' },
    { term: 'account-suspended', label: 'Account suspension scare' },
    { term: 'update-billing', label: 'Billing update lure' },
    { term: 'lottery', label: 'Lottery reward lure' },
    { term: 'cashback', label: 'Cashback reward lure' },
    { term: 'free-gift', label: 'Free gift bait' },
    { term: 'claim-reward', label: 'Prize claim lure' },
    { term: 'urgent', label: 'Artificial urgency' },
    { term: 'download-apk', label: 'Direct APK mobile payload' },
    { term: 'wallet-recovery', label: 'Cryptocurrency/wallet seed lure' }
  ];

  // Helper: Levenshtein distance for typosquatting detection
  function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  // Helper: Extract root domain and TLD (e.g. sub.domain.co.uk or sub.domain.com)
  function extractDomainDetails(hostname) {
    const parts = hostname.toLowerCase().split('.').filter(Boolean);
    if (parts.length === 0) return { rootDomain: hostname, tld: '', subdomains: [] };

    const tld = parts[parts.length - 1];
    let rootDomain = hostname;
    let subdomains = [];

    // Handle common two-part ccTLDs like .co.uk, .gov.in, .ac.in
    const twoPartCcTlds = ['co.uk', 'gov.in', 'co.in', 'net.in', 'org.in', 'ac.in', 'com.au', 'co.jp'];
    const lastTwo = parts.slice(-2).join('.');

    if (parts.length >= 3 && twoPartCcTlds.includes(lastTwo)) {
      rootDomain = parts.slice(-3).join('.');
      subdomains = parts.slice(0, -3);
    } else if (parts.length >= 2) {
      rootDomain = parts.slice(-2).join('.');
      subdomains = parts.slice(0, -2);
    }

    return { rootDomain, tld, subdomains };
  }

  /**
   * Main Analyzer Function
   * @param {string} rawInput - Text or URL extracted from QR code or user input
   * @returns {Object} Full security analysis report
   */
  function analyzeSecurity(rawInput) {
    const trimmed = (rawInput || '').trim();

    if (!trimmed) {
      return {
        status: 'EMPTY',
        verdict: 'UNKNOWN',
        riskScore: 0,
        riskRating: 'None',
        input: '',
        isUrl: false,
        warnings: [],
        rules: [],
        recommendations: ['Provide a valid QR code image or paste a URL to begin analysis.']
      };
    }

    // Check if input is a UPI Payment URI
    if (/^upi:\/\/pay(?:\?|$)/i.test(trimmed)) {
      return analyzeUpiString(trimmed);
    }

    // Check if input looks like a web URL or domain
    let parsedUrl = null;
    let effectiveUrl = trimmed;

    // If starts with www. or domain-like string, treat as potential URL for analysis
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?(\/.*)?$/i.test(trimmed)) {
      effectiveUrl = 'http://' + trimmed;
    }

    try {
      if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(effectiveUrl)) {
        parsedUrl = new URL(effectiveUrl);
      }
    } catch (e) {
      parsedUrl = null;
    }

    // If not a recognized HTTP/HTTPS URL
    if (!parsedUrl || !['http:', 'https:'].includes(parsedUrl.protocol.toLowerCase())) {
      return handleUnknownOrNonUrlData(trimmed, parsedUrl);
    }

    // --- URL SECURITY RULES EVALUATION ---
    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname;
    const search = parsedUrl.search;
    const fullPathAndQuery = (pathname + search).toLowerCase();
    const { rootDomain, tld, subdomains } = extractDomainDetails(hostname);

    const rules = [];
    const warnings = [];
    let riskScore = 0;

    // Rule 1: Protocol Encryption (HTTPS vs HTTP)
    const isHttps = parsedUrl.protocol.toLowerCase() === 'https:';
    if (!isHttps) {
      const penalty = 25;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_HTTP_UNENCRYPTED',
        name: 'Unencrypted Connection (Plain HTTP)',
        severity: 'HIGH',
        penalty,
        description: 'The URL uses unencrypted HTTP instead of HTTPS. All data transmitted can be intercepted or altered by eavesdroppers on the same network (Man-in-the-Middle attacks).'
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_HTTPS_ENCRYPTED',
        name: 'Transport Layer Security (HTTPS)',
        severity: 'INFO',
        passed: true,
        description: 'The URL specifies HTTPS encryption for data in transit.'
      });
    }

    // Rule 2: IP Address in Hostname (IPv4 / IPv6)
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
    if (isIpv4 || isIpv6) {
      const penalty = 35;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_IP_ADDRESS_HOST',
        name: 'Raw IP Address Hostname',
        severity: 'HIGH',
        penalty,
        description: `The URL connects directly to an IP address (${hostname}) instead of a verified domain name. Legitimate commercial web services use registered domain names with valid SSL certificates.`
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_IP_ADDRESS_HOST',
        name: 'Domain-Based Hostname',
        severity: 'INFO',
        passed: true,
        description: 'The URL uses a registered domain name rather than a raw IP address.'
      });
    }

    // Rule 3: URL Shortener Detection
    const isShortener = URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(rootDomain);
    if (isShortener) {
      const penalty = 25;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_URL_SHORTENER',
        name: 'URL Shortening Service Detected',
        severity: 'MEDIUM',
        penalty,
        description: `The domain (${hostname}) is a known URL shortening redirector. QR scammers use shorteners to conceal the actual final destination from scanners and human inspection.`
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_URL_SHORTENER',
        name: 'Direct Non-Shortened Destination',
        severity: 'INFO',
        passed: true,
        description: 'The domain does not match known public URL shortening networks.'
      });
    }

    // Rule 4: Embedded Credentials or Userinfo (@ Trick)
    const hasUserInfo = Boolean(parsedUrl.username || parsedUrl.password || effectiveUrl.includes('@'));
    if (hasUserInfo) {
      const penalty = 40;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_EMBEDDED_CREDENTIALS',
        name: 'Embedded Credentials / URL Obfuscation (@ symbol)',
        severity: 'CRITICAL',
        penalty,
        description: "The URL contains an '@' symbol or embedded credentials. Browsers may ignore the preceding text and redirect to the host located after the '@' symbol."
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_EMBEDDED_CREDENTIALS',
        name: 'Clean Authority (No embedded userinfo)',
        severity: 'INFO',
        passed: true,
        description: 'No obfuscating user credentials or @ authority redirection detected.'
      });
    }

    // Rule 5: Homograph / Punycode (xn--) Domain
    const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
    if (isPunycode) {
      const penalty = 35;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_PUNYCODE_HOMOGRAPH',
        name: 'Punycode / Internationalized Domain Name (IDN)',
        severity: 'HIGH',
        penalty,
        description: 'The domain uses Punycode encoding (xn--). Cyber attackers frequently use lookalike non-Latin characters (homoglyphs) to forge identical-looking brand names.'
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_PUNYCODE_HOMOGRAPH',
        name: 'Standard Character Set Domain',
        severity: 'INFO',
        passed: true,
        description: 'Domain uses standard ASCII characters without Punycode disguise.'
      });
    }

    // Rule 6: High-Abuse / Risky TLD
    const isRiskyTld = HIGH_RISK_TLDS.has(tld);
    if (isRiskyTld) {
      const penalty = 20;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_RISKY_TLD',
        name: `High-Risk Top-Level Domain (.${tld})`,
        severity: 'MEDIUM',
        penalty,
        description: `The top-level domain (.${tld}) is statistically associated with disposable phishing infrastructure and malware distribution.`
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_RISKY_TLD',
        name: 'Conventional Top-Level Domain',
        severity: 'INFO',
        passed: true,
        description: `Domain uses standard TLD (.${tld}).`
      });
    }

    // Rule 7: Deceptive Brand Patterns & Typosquatting
    let brandWarningFound = false;
    for (const brand of HIGH_VALUE_BRANDS) {
      const mentionsBrandInHost = brand.pattern.test(hostname);
      const isGenuineHost = rootDomain === brand.genuineDomain || hostname.endsWith('.' + brand.genuineDomain);

      if (mentionsBrandInHost && !isGenuineHost) {
        brandWarningFound = true;
        const penalty = 40;
        riskScore += penalty;
        const w = {
          ruleId: 'SEC_BRAND_IMPERSONATION',
          name: `Brand Impersonation Trap (${brand.name})`,
          severity: 'HIGH',
          penalty,
          description: `The hostname contains the brand name '${brand.name}' but the root domain is '${rootDomain}', NOT the official domain '${brand.genuineDomain}'. Scammers use compound names to trick victims.`
        };
        warnings.push(w);
        rules.push({ ...w, passed: false });
        break;
      }

      // Check simple typosquatting on root domain (e.g. paypa1 vs paypal)
      const brandBase = brand.genuineDomain.split('.')[0];
      const hostBase = rootDomain.split('.')[0];
      if (!isGenuineHost && hostBase !== brandBase && hostBase.length >= 4 && brandBase.length >= 4) {
        const dist = levenshteinDistance(hostBase, brandBase);
        if (dist === 1 || (dist === 2 && hostBase.length > 6)) {
          brandWarningFound = true;
          const penalty = 35;
          riskScore += penalty;
          const w = {
            ruleId: 'SEC_TYPOSQUATTING',
            name: `Potential Typosquatting (${brand.name})`,
            severity: 'HIGH',
            penalty,
            description: `Domain name '${rootDomain}' is deceptively similar to '${brand.genuineDomain}' (edit distance: ${dist}). This is a classic typosquatting pattern.`
          };
          warnings.push(w);
          rules.push({ ...w, passed: false });
          break;
        }
      }
    }

    if (!brandWarningFound) {
      rules.push({
        ruleId: 'SEC_BRAND_INTEGRITY',
        name: 'Brand Spoofing & Typosquatting Check',
        severity: 'INFO',
        passed: true,
        description: 'No obvious imitation of high-profile financial or technology brands detected.'
      });
    }

    // Rule 8: Excessive Subdomain Depth
    if (subdomains.length >= 3) {
      const penalty = 15;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_EXCESSIVE_SUBDOMAINS',
        name: 'Excessive Subdomain Nesting',
        severity: 'MEDIUM',
        penalty,
        description: `The hostname has ${subdomains.length + 1} domain levels (${subdomains.join('.')}.${rootDomain}). Attackers nest subdomains to disguise the true owning domain.`
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_EXCESSIVE_SUBDOMAINS',
        name: 'Standard Domain Nesting',
        severity: 'INFO',
        passed: true,
        description: 'Hostname has normal subdomain hierarchy.'
      });
    }

    // Rule 9: Non-Standard Port Specification
    const port = parsedUrl.port;
    if (port && port !== '80' && port !== '443') {
      const penalty = 20;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_NONSTANDARD_PORT',
        name: `Non-Standard Network Port (:${port})`,
        severity: 'MEDIUM',
        penalty,
        description: `The URL explicitly specifies non-standard port :${port}. Malicious hosting setups often run on non-standard ports to bypass standard web filters.`
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_NONSTANDARD_PORT',
        name: 'Standard Web Port',
        severity: 'INFO',
        passed: true,
        description: 'URL communicates over standard default web ports (80/443).'
      });
    }

    // Rule 10: Phishing & Sensitive Action Keywords in Path/Query
    const matchedKeywords = SENSITIVE_KEYWORDS.filter(k => fullPathAndQuery.includes(k.term));
    if (matchedKeywords.length > 0) {
      const penalty = Math.min(25, matchedKeywords.length * 10);
      riskScore += penalty;
      const kwLabels = matchedKeywords.map(k => k.label).join(', ');
      const w = {
        ruleId: 'SEC_SENSITIVE_KEYWORDS',
        name: 'Sensitive Credential / Urgent Lure Keywords',
        severity: 'MEDIUM',
        penalty,
        description: `Path or query contains suspicious intent keywords: ${kwLabels}. These keywords frequently occur in phishing forms and fake lottery/cashback traps.`
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_SENSITIVE_KEYWORDS',
        name: 'Clean Path & Query Semantics',
        severity: 'INFO',
        passed: true,
        description: 'No obvious sensitive credential or incentive bait terms in path or query.'
      });
    }

    // Rule 11: Abnormal Length or URL Obfuscation
    const isAbnormallyLong = effectiveUrl.length > 130 || hostname.length > 45;
    const hasMultipleHyphens = /--+/.test(hostname);
    if (isAbnormallyLong || hasMultipleHyphens) {
      const penalty = 10;
      riskScore += penalty;
      const w = {
        ruleId: 'SEC_URL_OBFUSCATION',
        name: 'Structural URL Obfuscation / Abnormal Length',
        severity: 'LOW',
        penalty,
        description: 'The URL exhibits unusual structural characteristics (excessive character length or repeated hyphens) often seen in automated phishing generation tools.'
      };
      warnings.push(w);
      rules.push({ ...w, passed: false });
    } else {
      rules.push({
        ruleId: 'SEC_URL_OBFUSCATION',
        name: 'Normal URL Structural Length',
        severity: 'INFO',
        passed: true,
        description: 'URL length and hostname structure are within normal parameters.'
      });
    }

    // Cap Risk Score at 100
    riskScore = Math.min(100, Math.max(0, riskScore));

    // Determine Final Verdict (Must strictly be one of the three required results)
    let verdict;
    let riskRating;

    if (riskScore >= 25 || warnings.some(w => w.severity === 'HIGH' || w.severity === 'CRITICAL')) {
      verdict = 'SUSPICIOUS';
      riskRating = riskScore >= 60 ? 'High' : 'Moderate';
    } else {
      verdict = 'NO OBVIOUS THREATS DETECTED';
      riskRating = 'Low';
    }

    // Build Actionable Recommendations
    const recommendations = buildRecommendations(verdict, warnings);

    return {
      status: 'PROCESSED',
      verdict,
      riskScore,
      riskRating,
      input: trimmed,
      effectiveUrl,
      isUrl: true,
      urlDetails: {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? '443' : '80'),
        pathname: parsedUrl.pathname,
        search: parsedUrl.search,
        rootDomain,
        tld
      },
      warnings,
      rules,
      recommendations,
      timestamp: new Date().toISOString()
    };
  }

  // Handle UPI string if detected during URL analysis
  function analyzeUpiString(upiString) {
    let parsedUpi;
    try {
      parsedUpi = new URL(upiString);
    } catch (e) {
      parsedUpi = null;
    }

    const params = parsedUpi ? parsedUpi.searchParams : new URLSearchParams(upiString.replace(/^upi:\/\/pay\??/i, ''));
    const pa = (params.get('pa') || '').trim();
    const pn = (params.get('pn') || '').trim();
    const am = params.get('am') || '';

    const warnings = [];
    let riskScore = 20; // Default caution for payment QRs

    if (!pa) {
      warnings.push({
        ruleId: 'UPI_MISSING_PA',
        name: 'Missing Payee VPA Address',
        severity: 'HIGH',
        description: 'Payment QR does not specify a valid receiver Virtual Payment Address (VPA).'
      });
      riskScore += 30;
    }

    if (am && parseFloat(am) > 2000) {
      warnings.push({
        ruleId: 'UPI_HIGH_AMOUNT',
        name: 'High Amount Pre-Populated',
        severity: 'MEDIUM',
        description: `This QR requests an automatic transfer of ₹${am}. Verify payee before approving.`
      });
      riskScore += 15;
    }

    const verdict = warnings.length > 0 ? 'SUSPICIOUS' : 'NO OBVIOUS THREATS DETECTED';

    return {
      status: 'PROCESSED',
      verdict,
      riskScore: Math.min(100, riskScore),
      riskRating: riskScore > 35 ? 'Moderate' : 'Low',
      input: upiString,
      isUrl: false,
      isUpi: true,
      upiDetails: { pa, pn, am },
      warnings,
      rules: [
        {
          ruleId: 'UPI_SCHEME_DETECTED',
          name: 'UPI Payment Link Format',
          severity: 'INFO',
          passed: true,
          description: 'Payload is an NPCI Unified Payments Interface (UPI) deep link.'
        }
      ],
      recommendations: [
        'Inspect this QR in the QRYPT UPI Verification module below.',
        'Never scan a payment QR expecting to RECEIVE money.',
        'Double-check the merchant name shown on your bank UPI app screen before entering your secret PIN.'
      ],
      timestamp: new Date().toISOString()
    };
  }

  // Handle Non-URL / Plain Text Data
  function handleUnknownOrNonUrlData(rawText, parsedUrl) {
    let scheme = 'plain-text';
    if (parsedUrl && parsedUrl.protocol) {
      scheme = parsedUrl.protocol.replace(':', '');
    } else if (/^[a-zA-Z0-9_-]+:/.test(rawText)) {
      scheme = rawText.split(':')[0];
    }

    return {
      status: 'PROCESSED',
      verdict: 'UNKNOWN',
      riskScore: 0,
      riskRating: 'Unclassified',
      input: rawText,
      isUrl: false,
      scheme,
      warnings: [],
      rules: [
        {
          ruleId: 'DATA_NON_URL_FORMAT',
          name: 'Format Classification',
          severity: 'INFO',
          passed: false,
          description: `Decoded payload is not a standard web URL (detected format: ${scheme}). QRYPT URL heuristic rules only apply to HTTP/HTTPS websites.`
        }
      ],
      recommendations: [
        'This QR code contains non-web data (such as plain text, Wi-Fi configuration, or a custom application link).',
        'Do not paste unknown commands or script snippets into a terminal or browser console.',
        'If this was meant to be a website, verify that the QR code image was not corrupted or misprinted.'
      ],
      timestamp: new Date().toISOString()
    };
  }

  // Build Actionable Cybersecurity Recommendations
  function buildRecommendations(verdict, warnings) {
    const list = [];

    if (verdict === 'SUSPICIOUS') {
      list.push('DO NOT open or visit this URL on your browser or mobile device.');
      list.push('DO NOT enter usernames, passwords, credit card numbers, or OTPs on any page linked by this QR code.');

      if (warnings.some(w => w.ruleId === 'SEC_URL_SHORTENER')) {
        list.push('Use a trusted URL expansion previewer if you need to know the true destination without loading it.');
      }
      if (warnings.some(w => w.ruleId === 'SEC_BRAND_IMPERSONATION' || w.ruleId === 'SEC_TYPOSQUATTING')) {
        list.push('Navigate directly to the official brand website using your own trusted bookmark or official search engine.');
      }
      if (warnings.some(w => w.ruleId === 'SEC_HTTP_UNENCRYPTED')) {
        list.push('Avoid submitting any form data over plain HTTP networks.');
      }
      list.push('Report suspicious physical QR stickers (quishing) to venue staff or local cyber defense authorities.');
    } else if (verdict === 'NO OBVIOUS THREATS DETECTED') {
      list.push('Heuristic rules did not flag known indicators of compromise.');
      list.push('Always examine the final address bar in your browser before authenticating or making transactions.');
      list.push('Remember: Zero-day phishing sites or newly purchased domains may temporarily bypass heuristic rules.');
    } else {
      list.push('Scanned payload is not a web URL. Inspect the decoded raw text carefully.');
    }

    return list;
  }

  // Export to window
  window.QryptAnalyzer = {
    analyze: analyzeSecurity,
    extractDomainDetails,
    levenshteinDistance
  };

})(window);
