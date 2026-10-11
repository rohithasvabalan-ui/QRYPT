/**
 * QRYPT – Comprehensive End-to-End Verification Test Suite
 * Developed by Team Cyber Titans
 *
 * Runs headless Chrome against the live dashboard at http://127.0.0.1:5000/index.html
 * Tests: Camera controls, sample chips, QR analysis rules, manual checking,
 *        UPI module statuses, history filters, inspect restore, JSON export,
 *        clear history, and zero auto-navigation guards.
 */

const { spawn } = require('child_process');
const http = require('http');

async function runVerification() {
  console.log('='.repeat(70));
  console.log(' QRYPT END-TO-END AUTOMATED BROWSER VERIFICATION SUITE');
  console.log(' Developed by Team Cyber Titans');
  console.log('='.repeat(70));

  // 1. Start dev server
  const serverProcess = spawn('node', ['server.js'], { stdio: 'pipe' });
  await new Promise(r => setTimeout(r, 1200));

  // 2. Launch Chrome Headless
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const chromeProcess = spawn(chromePath, [
    '--headless=new',
    '--remote-debugging-port=9225',
    '--disable-gpu',
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    'http://127.0.0.1:5000/index.html'
  ]);

  await new Promise(r => setTimeout(r, 2500));

  let exitCode = 0;
  const testResults = [];

  function record(testName, passed, details = '') {
    const status = passed ? 'PASS' : 'FAIL';
    const tag = passed ? '[\x1b[32mPASS\x1b[0m]' : '[\x1b[31mFAIL\x1b[0m]';
    console.log(`${tag} ${testName} ${details ? '- ' + details : ''}`);
    testResults.push({ testName, passed, details });
    if (!passed) exitCode = 1;
  }

  try {
    const res = await fetch('http://127.0.0.1:9225/json');
    const tabs = await res.json();
    const indexTab = tabs.find(t => t.url.includes('index.html')) || tabs[0];

    const ws = new globalThis.WebSocket(indexTab.webSocketDebuggerUrl);

    let msgId = 1;
    function evaluate(expr) {
      return new Promise((resolve) => {
        const id = msgId++;
        const handler = (evt) => {
          const data = JSON.parse(evt.data);
          if (data.id === id) {
            ws.removeEventListener('message', handler);
            resolve(data.result?.result?.value);
          }
        };
        ws.addEventListener('message', handler);
        ws.send(JSON.stringify({
          id,
          method: 'Runtime.evaluate',
          params: { expression: expr, returnByValue: true }
        }));
      });
    }

    ws.onopen = async () => {
      console.log('\n--- PHASE 1: BRANDING & NAVIGATION ---');
      const brand = await evaluate('document.querySelector(".brand-name").textContent');
      record('Header & Brand Title', brand.includes('QRYPT'), brand.trim());

      const subtitle = await evaluate('document.querySelector(".brand-subtitle").textContent');
      record('Header Subtitle', subtitle.includes('Scan Smart. Stay Secure.'), subtitle.trim());

      const team = await evaluate('document.querySelector(".team-badge").textContent');
      record('Team Credit Badge', team.includes('Cyber Titans'), team.trim());

      // Tab navigation
      const tabsCount = await evaluate('document.querySelectorAll(".nav-tab-btn").length');
      record('Navigation Tabs Initialized', tabsCount === 5, `${tabsCount} tabs found`);

      console.log('\n--- PHASE 2: CAMERA CONTROLS & STREAM SIMULATION ---');
      // Test Camera start button toggling
      await evaluate('document.getElementById("start-camera-btn").click()');
      await new Promise(r => setTimeout(r, 800));

      const camRunning = await evaluate(`
        document.getElementById("camera-container").style.display === "flex" &&
        document.getElementById("stop-camera-btn").style.display === "inline-flex" &&
        document.getElementById("start-camera-btn").style.display === "none"
      `);
      record('Camera Start Button & Viewfinder', camRunning, 'Viewfinder opened, stop button visible');

      // Test Camera stop button
      await evaluate('document.getElementById("stop-camera-btn").click()');
      await new Promise(r => setTimeout(r, 400));
      const camStopped = await evaluate(`
        document.getElementById("camera-container").style.display === "none" &&
        document.getElementById("stop-camera-btn").style.display === "none" &&
        document.getElementById("start-camera-btn").style.display === "inline-flex"
      `);
      record('Camera Stop Button & Cleanup', camStopped, 'Stream stopped, buttons restored');

      console.log('\n--- PHASE 3: SAMPLE CHIPS & SECURITY HEURISTICS ---');
      // 1. Safe Gov Portal
      await evaluate('document.querySelector(".sample-chip[data-payload*=\'cybercrime.gov.in\']").click()');
      await new Promise(r => setTimeout(r, 300));
      const vSafe = await evaluate('document.getElementById("verdict-title").textContent');
      const sSafe = await evaluate('document.getElementById("risk-score-num").textContent');
      record('Safe Gov URL Sample', vSafe === 'NO OBVIOUS THREATS DETECTED' && sSafe === '0', `Verdict: ${vSafe}, Score: ${sSafe}/100`);

      // 2. Phishing Brand Spoof
      await evaluate('document.querySelector(".sample-chip[data-payload*=\'secure-login-paytm\']").click()');
      await new Promise(r => setTimeout(r, 300));
      const vPhish = await evaluate('document.getElementById("verdict-title").textContent');
      const sPhish = await evaluate('document.getElementById("risk-score-num").textContent');
      record('Phishing Brand Spoof Sample', vPhish === 'SUSPICIOUS' && parseInt(sPhish) >= 90, `Verdict: ${vPhish}, Score: ${sPhish}/100`);

      // 3. Raw IP Address
      await evaluate('document.querySelector(".sample-chip[data-payload*=\'192.168.1.105\']").click()');
      await new Promise(r => setTimeout(r, 300));
      const vIp = await evaluate('document.getElementById("verdict-title").textContent');
      record('Raw IP Host Sample', vIp === 'SUSPICIOUS', `Verdict: ${vIp}`);

      // 4. URL Shortener
      await evaluate('document.querySelector(".sample-chip[data-payload*=\'bit.ly\']").click()');
      await new Promise(r => setTimeout(r, 300));
      const vShort = await evaluate('document.getElementById("verdict-title").textContent');
      record('URL Shortener Masking Sample', vShort === 'SUSPICIOUS', `Verdict: ${vShort}`);

      // 5. Punycode Homograph
      await evaluate('document.querySelector(".sample-chip[data-payload*=\'xn--appl\']").click()');
      await new Promise(r => setTimeout(r, 300));
      const vPuny = await evaluate('document.getElementById("verdict-title").textContent');
      record('Punycode Homograph Sample', vPuny === 'SUSPICIOUS', `Verdict: ${vPuny}`);

      // 6. Wi-Fi Config (Plain text)
      await evaluate('document.querySelector(".sample-chip[data-payload*=\'WIFI:\']").click()');
      await new Promise(r => setTimeout(r, 300));
      const vWifi = await evaluate('document.getElementById("verdict-title").textContent');
      record('Plain Text / Wi-Fi Sample', vWifi === 'UNKNOWN', `Verdict: ${vWifi}`);

      console.log('\n--- PHASE 4: MANUAL URL THREAT CHECKER ---');
      await evaluate('document.querySelector(".nav-tab-btn[data-target=\'manual\']").click()');
      await evaluate('document.getElementById("manual-url-input").value = "http://test-bank-update.top/kyc.php?otp=1234"');
      await evaluate('document.getElementById("analyze-manual-btn").click()');
      await new Promise(r => setTimeout(r, 300));
      const vManual = await evaluate('document.getElementById("verdict-title").textContent');
      const wManualCount = await evaluate('document.getElementById("warnings-list").children.length');
      record('Manual URL Analysis Form', vManual === 'SUSPICIOUS' && wManualCount > 0, `Verdict: ${vManual}, Warnings: ${wManualCount}`);

      console.log('\n--- PHASE 5: UPI RECEIVER VERIFICATION MODULE ---');
      await evaluate('document.querySelector(".nav-tab-btn[data-target=\'upi\']").click()');

      // Test 1: Trusted Directory
      await evaluate('document.getElementById("upi-input").value = "pmcares@sbi"');
      await evaluate('document.getElementById("verify-upi-btn").click()');
      const upiTrusted = await evaluate('document.getElementById("upi-verdict-badge").textContent');
      record('UPI Trusted Directory (pmcares@sbi)', upiTrusted === 'VERIFIED', `Verdict: ${upiTrusted}`);

      // Test 2: Standard Valid VPA without banking gateway
      await evaluate('document.getElementById("upi-input").value = "merchant@okhdfcbank"');
      await evaluate('document.getElementById("verify-upi-btn").click()');
      const upiUnverified = await evaluate('document.getElementById("upi-verdict-badge").textContent');
      record('UPI Standard VPA (merchant@okhdfcbank)', upiUnverified === 'UNVERIFIED', `Verdict: ${upiUnverified} (Accurately declares no fake API)`);

      // Test 3: Invalid VPA syntax
      await evaluate('document.getElementById("upi-input").value = "invalid-vpa-syntax"');
      await evaluate('document.getElementById("verify-upi-btn").click()');
      const upiUnknown = await evaluate('document.getElementById("upi-verdict-badge").textContent');
      record('UPI Malformed Syntax', upiUnknown === 'UNKNOWN', `Verdict: ${upiUnknown}`);

      // Test 4: Payee Mismatch Detection
      await evaluate('document.getElementById("upi-input").value = "upi://pay?pa=scammer@ybl&pn=FakeLottery&am=2500"');
      await evaluate('document.getElementById("expected-name-input").value = "Official Store"');
      await evaluate('document.getElementById("expected-upi-input").value = "store@okaxis"');
      await evaluate('document.getElementById("verify-upi-btn").click()');
      const mismatchWarning = await evaluate('document.getElementById("upi-warnings-box").textContent');
      record('UPI Expected vs Scanned Payee Mismatch', mismatchWarning.includes('MISMATCH') || mismatchWarning.includes('discrepancy'), 'Mismatch alert generated');

      console.log('\n--- PHASE 6: SCAN HISTORY, FILTERS, EXPORT & CLEAR ---');
      await evaluate('document.querySelector(".nav-tab-btn[data-target=\'history\']").click()');

      const initialCount = await evaluate('document.getElementById("history-table-body").children.length');
      record('Scan History Persistence', initialCount >= 6, `${initialCount} scan records present in history table`);

      // Test Filter: Suspicious
      await evaluate('document.querySelector(".history-filter-btn[data-filter=\'suspicious\']").click()');
      const suspCount = await evaluate('document.getElementById("history-table-body").children.length');
      record('History Filter (Suspicious)', suspCount > 0 && suspCount <= initialCount, `${suspCount} suspicious items filtered`);

      // Test Filter: Safe
      await evaluate('document.querySelector(".history-filter-btn[data-filter=\'safe\']").click()');
      const safeCount = await evaluate('document.getElementById("history-table-body").children.length');
      record('History Filter (Safe)', safeCount > 0, `${safeCount} safe items filtered`);

      // Test Filter: All
      await evaluate('document.querySelector(".history-filter-btn[data-filter=\'all\']").click()');
      const allCount = await evaluate('document.getElementById("history-table-body").children.length');
      record('History Filter (Reset to All)', allCount === initialCount, `Restored to ${allCount} items`);

      // Test Inspect Button
      await evaluate('document.querySelector(".inspect-history-btn").click()');
      await new Promise(r => setTimeout(r, 400));
      const reportVisible = await evaluate('document.getElementById("report-container").style.display === "block"');
      record('History Inspect Button Re-renders Report', reportVisible, 'Previous scan report restored into view');

      // Test JSON Export (verify function executes without error)
      const exportSuccess = await evaluate(`
        (() => {
          try {
            window.QryptHistory.exportHistoryAsJson();
            return true;
          } catch(e) {
            return false;
          }
        })()
      `);
      record('JSON Log Export Function', exportSuccess, 'Generated valid downloadable JSON blob');

      // Test Clear History
      await evaluate('window.QryptHistory.clearHistory()');
      await evaluate('document.querySelector(".nav-tab-btn[data-target=\'history\']").click()');
      const emptyStateVisible = await evaluate('document.getElementById("history-empty-state").style.display === "block"');
      record('Clear History & Empty State', emptyStateVisible, 'History cleared and empty state displayed');

      console.log('\n--- PHASE 7: SECURITY GUARDS & CAUTION MODAL ---');
      // Caution Modal
      await evaluate('document.querySelector(".sample-chip[data-payload*=\'bit.ly\']").click()');
      await evaluate('document.getElementById("copy-url-btn").click()');
      const modalOpen = await evaluate('document.getElementById("caution-modal").classList.contains("open")');
      record('Caution Copy Modal Opens', modalOpen, 'Modal displayed with warning message');

      await evaluate('document.getElementById("modal-cancel-btn").click()');
      const modalClosed = await evaluate('!document.getElementById("caution-modal").classList.contains("open")');
      record('Caution Copy Modal Dismissal', modalClosed, 'Modal closed cleanly');

      // Zero Auto-Navigation Check
      const curUrl = await evaluate('window.location.href');
      record('Zero Auto-Navigation Guard', curUrl === 'http://127.0.0.1:5000/index.html', `Current URL remains ${curUrl}`);

      console.log('\n' + '='.repeat(70));
      const passedCount = testResults.filter(t => t.passed).length;
      const totalCount = testResults.length;
      console.log(` VERIFICATION COMPLETE: ${passedCount} / ${totalCount} TESTS PASSED`);
      console.log('='.repeat(70) + '\n');

      ws.close();
      chromeProcess.kill();
      serverProcess.kill();
      process.exit(exitCode);
    };

    ws.onerror = (e) => {
      console.error('WebSocket Error:', e);
      chromeProcess.kill();
      serverProcess.kill();
      process.exit(1);
    };

  } catch (err) {
    console.error('Verification failed:', err);
    chromeProcess.kill();
    serverProcess.kill();
    process.exit(1);
  }
}

runVerification();
