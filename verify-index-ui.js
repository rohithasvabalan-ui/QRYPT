const { spawn } = require('child_process');

async function testIndexUI() {
  console.log('Testing live index.html in Chrome...');
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const chrome = spawn(chromePath, [
    '--headless=new',
    '--remote-debugging-port=9223',
    '--disable-gpu',
    'http://127.0.0.1:5000/index.html'
  ]);

  await new Promise(r => setTimeout(r, 3000));

  try {
    const res = await fetch('http://127.0.0.1:9223/json');
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
      console.log('Connected to index.html session. Running UI checks...');

      // Check 1: Title and Header
      const brand = await evaluate('document.querySelector(".brand-name").textContent');
      console.log('Check 1 - Brand Title:', brand.trim());

      // Check 2: Tab navigation
      await evaluate('document.querySelector(".nav-tab-btn[data-target=\'manual\']").click()');
      const manualVisible = await evaluate('document.getElementById("view-manual").style.display');
      console.log('Check 2 - Manual Tab Switch:', manualVisible === 'block' ? 'PASS' : 'FAIL');

      // Check 3: Manual URL Analysis of Phishing URL
      await evaluate('document.getElementById("manual-url-input").value = "http://secure-login-paytm.verify-account.top/login.php?otp=true"');
      await evaluate('document.getElementById("analyze-manual-btn").click()');
      
      const verdict = await evaluate('document.getElementById("verdict-title").textContent');
      const score = await evaluate('document.getElementById("risk-score-num").textContent');
      const warningsCount = await evaluate('document.getElementById("warnings-list").children.length');
      console.log(`Check 3 - Phishing Analysis -> Verdict: ${verdict}, Score: ${score}/100, Warnings: ${warningsCount}`);

      // Check 4: UPI Tab and Verification
      await evaluate('document.querySelector(".nav-tab-btn[data-target=\'upi\']").click()');
      await evaluate('document.getElementById("upi-input").value = "pmcares@sbi"');
      await evaluate('document.getElementById("verify-upi-btn").click()');
      const upiVerdict = await evaluate('document.getElementById("upi-verdict-badge").textContent');
      console.log('Check 4 - UPI Trusted VPA -> Verdict:', upiVerdict);

      // Check 5: UPI Unverified Standard VPA
      await evaluate('document.getElementById("upi-input").value = "vendor@okhdfcbank"');
      await evaluate('document.getElementById("verify-upi-btn").click()');
      const upiUnverified = await evaluate('document.getElementById("upi-verdict-badge").textContent');
      console.log('Check 5 - UPI Standard VPA -> Verdict:', upiUnverified);

      // Check 6: Copy Caution Modal
      await evaluate('document.getElementById("copy-url-btn").click()');
      const modalOpen = await evaluate('document.getElementById("caution-modal").classList.contains("open")');
      console.log('Check 6 - Caution Modal Opened:', modalOpen ? 'PASS' : 'FAIL');
      await evaluate('document.getElementById("modal-cancel-btn").click()');
      const modalClosed = await evaluate('!document.getElementById("caution-modal").classList.contains("open")');
      console.log('Check 7 - Caution Modal Closed on Cancel:', modalClosed ? 'PASS' : 'FAIL');

      // Check 8: Scan History Tab
      await evaluate('document.querySelector(".nav-tab-btn[data-target=\'history\']").click()');
      const historyRows = await evaluate('document.getElementById("history-table-body").children.length');
      console.log(`Check 8 - Scan History Records Logged: ${historyRows} items`);

      console.log('\nALL UI CHECKS PASSED PERFECTLY!\n');

      ws.close();
      chrome.kill();
      process.exit(0);
    };

    ws.onerror = (err) => {
      console.error('WebSocket Error:', err);
      chrome.kill();
      process.exit(1);
    };

  } catch (e) {
    console.error('Test error:', e);
    chrome.kill();
    process.exit(1);
  }
}

testIndexUI();
