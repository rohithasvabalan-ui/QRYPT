const { spawn } = require('child_process');
const http = require('http');

async function main() {
  console.log('Launching headless Chrome with Remote Debugging...');
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const chrome = spawn(chromePath, [
    '--headless=new',
    '--remote-debugging-port=9222',
    '--disable-gpu',
    'http://127.0.0.1:5000/test-harness.html'
  ]);

  chrome.on('error', (err) => {
    console.error('Failed to spawn Chrome:', err);
    process.exit(1);
  });

  // Wait 3 seconds for tests to execute in browser
  await new Promise(r => setTimeout(r, 3500));

  // Query Chrome CDP targets
  try {
    const res = await fetch('http://127.0.0.1:9222/json');
    const tabs = await res.json();
    console.log('Discovered browser targets:', tabs.length);
    const testTab = tabs.find(t => t.url.includes('test-harness.html')) || tabs[0];

    if (testTab && testTab.webSocketDebuggerUrl) {
      const ws = new globalThis.WebSocket(testTab.webSocketDebuggerUrl);

      ws.onopen = () => {
        ws.send(JSON.stringify({
          id: 1,
          method: 'Runtime.evaluate',
          params: {
            expression: 'document.getElementById("output").textContent',
            returnByValue: true
          }
        }));
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.id === 1) {
          console.log('\n================ BROWSER TEST LOG ================');
          console.log(data.result?.result?.value || 'No value returned');
          console.log('===================================================\n');
          ws.close();
          chrome.kill();
          process.exit(0);
        }
      };

      ws.onerror = (e) => {
        console.error('WebSocket error:', e);
        chrome.kill();
        process.exit(1);
      };
    } else {
      console.log('No debugger URL found');
      chrome.kill();
      process.exit(1);
    }
  } catch (err) {
    console.error('CDP communication error:', err);
    chrome.kill();
    process.exit(1);
  }
}

main();
