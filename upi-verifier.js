/**
 * QRYPT – QR Code Protection
 * Developed by Team Cyber Titans
 *
 * Module: UPI Payment Protection & Receiver Verification (js/upi-verifier.js)
 * Purpose: Analyzes UPI IDs (VPAs) and QR payment strings, checks syntax,
 *          identifies official bank PSP handles, checks against local trusted registries,
 *          and provides rigorous, transparent verification states (VERIFIED, UNVERIFIED, UNKNOWN).
 *
 * Cybersecurity Transparency Disclosure:
 * Real bank-grade account holder verification in India requires an active NPCI
 * VPA-Lookup API gateway via a licensed banking PSP. QRYPT NEVER fabricates fake
 * verification or pretends to have contacted live banking switches.
 */

(function (window) {
  'use strict';

  // Comprehensive Registry of Official NPCI Bank / Third-Party Application Provider (TPAP) Handles
  const NPCI_PSP_REGISTRY = {
    // Google Pay
    'okaxis': { psp: 'Google Pay', bank: 'Axis Bank', type: 'TPAP' },
    'okhdfcbank': { psp: 'Google Pay', bank: 'HDFC Bank', type: 'TPAP' },
    'okicici': { psp: 'Google Pay', bank: 'ICICI Bank', type: 'TPAP' },
    'oksbi': { psp: 'Google Pay', bank: 'State Bank of India', type: 'TPAP' },

    // PhonePe
    'ybl': { psp: 'PhonePe', bank: 'YES Bank', type: 'TPAP' },
    'ibl': { psp: 'PhonePe', bank: 'ICICI Bank', type: 'TPAP' },
    'axl': { psp: 'PhonePe', bank: 'Axis Bank', type: 'TPAP' },

    // Paytm
    'paytm': { psp: 'Paytm', bank: 'Paytm Payments Bank / Partner Banks', type: 'TPAP' },
    'ptaxis': { psp: 'Paytm', bank: 'Axis Bank', type: 'TPAP' },
    'pthdfc': { psp: 'Paytm', bank: 'HDFC Bank', type: 'TPAP' },
    'ptsbi': { psp: 'Paytm', bank: 'State Bank of India', type: 'TPAP' },

    // Amazon Pay
    'apl': { psp: 'Amazon Pay', bank: 'Axis Bank', type: 'TPAP' },
    'rapl': { psp: 'Amazon Pay', bank: 'RBL Bank', type: 'TPAP' },

    // BHIM / Official NPCI
    'upi': { psp: 'BHIM', bank: 'NPCI Central Switch', type: 'Official' },

    // Major Public & Private Sector Banks (Direct Bank UPI Apps)
    'sbi': { psp: 'YONO SBI', bank: 'State Bank of India', type: 'Bank' },
    'hdfcbank': { psp: 'HDFC Mobile Banking', bank: 'HDFC Bank', type: 'Bank' },
    'icici': { psp: 'iMobile Pay', bank: 'ICICI Bank', type: 'Bank' },
    'axisbank': { psp: 'Axis Mobile', bank: 'Axis Bank', type: 'Bank' },
    'kotak': { psp: 'Kotak 811', bank: 'Kotak Mahindra Bank', type: 'Bank' },
    'pnb': { psp: 'PNB ONE', bank: 'Punjab National Bank', type: 'Bank' },
    'barodampay': { psp: 'bob World', bank: 'Bank of Baroda', type: 'Bank' },
    'canarabank': { psp: 'Canara ai1', bank: 'Canara Bank', type: 'Bank' },
    'unionbank': { psp: 'Vyom', bank: 'Union Bank of India', type: 'Bank' },
    'indus': { psp: 'IndusMobile', bank: 'IndusInd Bank', type: 'Bank' },
    'federal': { psp: 'FedMobile', bank: 'Federal Bank', type: 'Bank' },
    'idbi': { psp: 'IDBI Bank GO Mobile+', bank: 'IDBI Bank', type: 'Bank' },
    'rbl': { psp: 'MoBank', bank: 'RBL Bank', type: 'Bank' },
    'postbank': { psp: 'IPPB Mobile Banking', bank: 'India Post Payments Bank', type: 'Bank' }
  };

  // Local Verified Trusted Directory (e.g. Official Public Utilities / Demonstration Allowlist)
  // Only entries strictly present in this verified list will receive the "VERIFIED" state.
  const LOCAL_TRUSTED_DIRECTORY = [
    {
      vpa: 'pmcares@sbi',
      name: 'Prime Minister Citizen Assistance Fund',
      category: 'Government / Public Trust',
      verifiedBy: 'Official National Relief Directory'
    },
    {
      vpa: 'bharatbillpay@icici',
      name: 'NPCI Bharat BillPay Service',
      category: 'Public Utility Payments',
      verifiedBy: 'NPCI BBPS Central Directory'
    },
    {
      vpa: 'cybertitans.demo@okaxis',
      name: 'Cyber Titans Official Security Lab',
      category: 'QRYPT Project Demonstration Account',
      verifiedBy: 'Team Cyber Titans Demo Registry'
    },
    {
      vpa: 'redcross.india@hdfcbank',
      name: 'Indian Red Cross Society',
      category: 'Humanitarian Non-Profit',
      verifiedBy: 'Verified NGO Register'
    }
  ];

  /**
   * Validates standard NPCI UPI Virtual Payment Address (VPA) syntax.
   * According to NPCI specifications:
   * Format: <username>@<handle>
   * Username: 2 to 256 alphanumeric characters plus permitted characters (._-)
   * Handle: 2 to 64 alphanumeric characters
   */
  function isValidVpaFormat(upiId) {
    if (!upiId || typeof upiId !== 'string') return false;
    const vpaRegex = /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9]{2,64}$/;
    return vpaRegex.test(upiId.trim());
  }

  /**
   * Verifies and inspects a UPI ID
   * @param {string} upiId - The UPI ID to inspect (e.g. merchant@okhdfcbank)
   * @param {string} [expectedName] - Optional expected receiver name for comparison
   * @param {string} [expectedUpi] - Optional expected UPI ID for cross-checking
   * @returns {Object} Comprehensive verification assessment
   */
  function verifyUpiReceiver(upiId, expectedName = '', expectedUpi = '') {
    const trimmedId = (upiId || '').trim();

    if (!trimmedId) {
      return {
        status: 'EMPTY',
        verdict: 'UNKNOWN',
        message: 'No UPI ID provided for verification.',
        upiId: '',
        handle: '',
        bankInfo: null,
        isTrustedDirectory: false,
        warnings: [],
        details: null
      };
    }

    // 1. Check Format Syntax
    if (!isValidVpaFormat(trimmedId)) {
      return {
        status: 'INVALID_SYNTAX',
        verdict: 'UNKNOWN',
        message: 'The provided UPI ID does not match valid NPCI VPA format syntax (e.g., username@bankname).',
        upiId: trimmedId,
        handle: '',
        bankInfo: null,
        isTrustedDirectory: false,
        warnings: [
          'Invalid character set or missing "@" delimiter.',
          'Characters must be alphanumeric with standard separators (. _ -).'
        ],
        details: {
          syntaxValid: false,
          explanation: 'Because this string fails basic UPI syntax rules, its destination cannot be recognized.'
        }
      };
    }

    // Extract handle and username
    const parts = trimmedId.split('@');
    const username = parts[0];
    const handle = parts[1].toLowerCase();
    const bankInfo = NPCI_PSP_REGISTRY[handle] || null;

    // 2. Check if handle is recognized in NPCI PSP Registry
    if (!bankInfo) {
      return {
        status: 'UNRECOGNIZED_HANDLE',
        verdict: 'UNKNOWN',
        message: `The bank handle '@${handle}' is not recognized in the standard NPCI PSP registry.`,
        upiId: trimmedId,
        username,
        handle,
        bankInfo: null,
        isTrustedDirectory: false,
        warnings: [
          `Unrecognized bank handle: @${handle}`,
          'Could be an unregistered handle, private gateway, or typographical error.'
        ],
        details: {
          syntaxValid: true,
          handleRecognized: false,
          explanation: 'Standard UPI transactions in India route through registered bank PSP handles. Unknown handles cannot be resolved.'
        }
      };
    }

    // 3. Check Local Verified Trusted Directory
    const trustedMatch = LOCAL_TRUSTED_DIRECTORY.find(
      item => item.vpa.toLowerCase() === trimmedId.toLowerCase()
    );

    if (trustedMatch) {
      return {
        status: 'TRUSTED_MATCH',
        verdict: 'VERIFIED',
        message: `Verified against local trusted entity directory: ${trustedMatch.name} (${trustedMatch.category}).`,
        upiId: trimmedId,
        username,
        handle,
        bankInfo,
        isTrustedDirectory: true,
        trustedEntity: trustedMatch,
        warnings: [],
        details: {
          syntaxValid: true,
          handleRecognized: true,
          directoryMatched: true,
          verifiedSourceName: trustedMatch.verifiedBy,
          explanation: 'This UPI ID matches an authorized, pre-registered institutional profile in the local verified directory.'
        }
      };
    }

    // 4. Valid Syntax & Recognized Bank Handle, BUT No External Live Banking API Integrated
    // STRICT REQUIREMENT: "Do not claim to verify a real receiver unless a trusted verification service is integrated."
    // MUST output UNVERIFIED with complete cybersecurity honesty.
    const warnings = [];

    // Heuristics on username patterns (e.g. scam keywords)
    const suspiciousUsernamePatterns = /(lottery|jackpot|cashback|reward|free-money|customer-care|support-team|urgent-pay)/i;
    if (suspiciousUsernamePatterns.test(username)) {
      warnings.push(`The UPI prefix '${username}' contains high-risk marketing/scam lure keywords.`);
    }

    // Comparison with user's expected values if provided
    let comparison = null;
    if (expectedUpi || expectedName) {
      const upiMatches = expectedUpi ? trimmedId.toLowerCase() === expectedUpi.trim().toLowerCase() : null;
      comparison = {
        expectedUpi: expectedUpi || 'Not specified',
        actualUpi: trimmedId,
        upiMatches
      };

      if (upiMatches === false) {
        warnings.push(`MISMATCH: Scanned UPI ID (${trimmedId}) does NOT match your expected UPI ID (${expectedUpi}).`);
      }
    }

    return {
      status: 'SYNTAX_VALID_NO_API',
      verdict: 'UNVERIFIED',
      message: 'Format and bank PSP handle are structurally valid, but receiver identity is UNVERIFIED.',
      upiId: trimmedId,
      username,
      handle,
      bankInfo,
      isTrustedDirectory: false,
      comparison,
      warnings,
      details: {
        syntaxValid: true,
        handleRecognized: true,
        directoryMatched: false,
        pspApp: bankInfo.psp,
        associatedBank: bankInfo.bank,
        explanation: 'In India, proving account holder ownership requires a licensed banking PSP gateway connection with NPCI VPA lookup credentials. This client-side prototype does not connect to live banking networks; therefore, genuine account ownership cannot be confirmed.'
      }
    };
  }

  /**
   * Parses and inspects an entire upi://pay URI
   * @param {string} upiUri - e.g. upi://pay?pa=shop@upi&pn=DemoShop&am=150
   * @param {string} [expectedName]
   * @param {string} [expectedUpi]
   */
  function parseAndInspectUpiUri(upiUri, expectedName = '', expectedUpi = '') {
    if (!/^upi:\/\/pay(?:\?|$)/i.test(upiUri)) {
      return {
        isUpiUri: false,
        error: 'String is not a valid upi://pay payment URI.'
      };
    }

    let searchParams;
    try {
      const parsed = new URL(upiUri);
      searchParams = parsed.searchParams;
    } catch (e) {
      searchParams = new URLSearchParams(upiUri.replace(/^upi:\/\/pay\??/i, ''));
    }

    const pa = (searchParams.get('pa') || '').trim(); // Payee VPA
    const pn = (searchParams.get('pn') || '').trim(); // Payee display name
    const am = (searchParams.get('am') || '').trim(); // Amount
    const cu = (searchParams.get('cu') || 'INR').trim(); // Currency
    const mc = (searchParams.get('mc') || '').trim(); // Merchant Category Code
    const tr = (searchParams.get('tr') || '').trim(); // Transaction Ref
    const tn = (searchParams.get('tn') || '').trim(); // Transaction Note

    const vpaResult = verifyUpiReceiver(pa, expectedName, expectedUpi);

    // Cross-check expected name if supplied
    let nameMatches = null;
    if (expectedName && pn) {
      nameMatches = pn.toLowerCase().includes(expectedName.trim().toLowerCase()) ||
                    expectedName.trim().toLowerCase().includes(pn.toLowerCase());
      if (!nameMatches) {
        vpaResult.warnings.push(`Name discrepancy: QR specifies receiver name '${pn}', but you expected '${expectedName}'.`);
      }
    }

    return {
      isUpiUri: true,
      rawUri: upiUri,
      params: { pa, pn, am, cu, mc, tr, tn },
      vpaResult,
      nameComparison: {
        expectedName: expectedName || 'Not specified',
        actualName: pn || 'Not provided in QR',
        nameMatches
      }
    };
  }

  // Export to window
  window.QryptUpi = {
    verifyUpiReceiver,
    parseAndInspectUpiUri,
    isValidVpaFormat,
    NPCI_PSP_REGISTRY,
    LOCAL_TRUSTED_DIRECTORY
  };

})(window);
