/**
 * QRYPT – QR Code Protection
 * Developed by Team Cyber Titans
 *
 * Main UI Controller & Coordinator (js/app.js)
 * Manages view tabs, event bindings, drag-and-drop, sample loading,
 * modal dialogs, copy operations, and results rendering.
 */

(function () {
  'use strict';

  // DOM Elements
  const tabs = document.querySelectorAll('.nav-tab-btn');
  const viewPanels = {
    scanner: document.getElementById('view-scanner'),
    manual: document.getElementById('view-manual'),
    upi: document.getElementById('view-upi'),
    history: document.getElementById('view-history'),
    rules: document.getElementById('view-rules')
  };

  // QR Upload & Camera elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const selectFileBtn = document.getElementById('select-file-btn');
  const startCameraBtn = document.getElementById('start-camera-btn');
  const stopCameraBtn = document.getElementById('stop-camera-btn');
  const cameraContainer = document.getElementById('camera-container');
  const videoElement = document.getElementById('camera-video');
  const spinner = document.getElementById('scanner-spinner');

  // Manual URL elements
  const manualUrlInput = document.getElementById('manual-url-input');
  const analyzeManualBtn = document.getElementById('analyze-manual-btn');

  // Report elements
  const reportContainer = document.getElementById('report-container');
  const verdictBanner = document.getElementById('verdict-banner');
  const verdictIcon = document.getElementById('verdict-icon');
  const verdictTitle = document.getElementById('verdict-title');
  const verdictTagline = document.getElementById('verdict-tagline');
  const riskScoreNum = document.getElementById('risk-score-num');
  const riskLevelPill = document.getElementById('risk-level-pill');
  const decodedContent = document.getElementById('decoded-content');
  const copyUrlBtn = document.getElementById('copy-url-btn');
  const warningsSection = document.getElementById('warnings-section');
  const warningsList = document.getElementById('warnings-list');
  const recList = document.getElementById('recommendations-list');
  const rulesList = document.getElementById('rules-list');

  // UPI module elements
  const upiInput = document.getElementById('upi-input');
  const expectedNameInput = document.getElementById('expected-name-input');
  const expectedUpiInput = document.getElementById('expected-upi-input');
  const verifyUpiBtn = document.getElementById('verify-upi-btn');
  const upiReport = document.getElementById('upi-report');
  const upiVerdictBadge = document.getElementById('upi-verdict-badge');
  const upiVerdictMsg = document.getElementById('upi-verdict-msg');
  const upiTableBody = document.getElementById('upi-table-body');
  const upiWarningsBox = document.getElementById('upi-warnings-box');

  // History elements
  const historyTableWrapper = document.getElementById('history-table-wrapper');
  const historyTableBody = document.getElementById('history-table-body');
  const historyEmptyState = document.getElementById('history-empty-state');
  const clearHistoryBtn = document.getElementById('clear-history-btn');
  const exportHistoryBtn = document.getElementById('export-history-btn');
  const historyFilterBtns = document.querySelectorAll('.history-filter-btn');

  // Modal elements
  const cautionModal = document.getElementById('caution-modal');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalCancelBtn = document.getElementById('modal-cancel-btn');
  const modalConfirmCopyBtn = document.getElementById('modal-confirm-copy-btn');
  const modalPayloadText = document.getElementById('modal-payload-text');

  // Toast container
  const toastContainer = document.getElementById('toast-container');

  // State
  let currentScannedPayload = '';
  let activeHistoryFilter = 'all';

  // --- INITIALIZATION ---
  function init() {
    setupTabNavigation();
    setupDropzone();
    setupCameraControls();
    setupManualInput();
    setupUpiModule();
    setupHistoryView();
    setupSampleChips();
    setupCautionModal();
    setupGlobalClipboardPaste();
    renderHistory();
  }

  // --- TOAST NOTIFICATIONS ---
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg width="18" height="18" fill="none" stroke="#10b981" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg width="18" height="18" fill="none" stroke="#ef4444" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>';
    } else {
      iconSvg = '<svg width="18" height="18" fill="none" stroke="#00e5ff" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
    }

    toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3800);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    })[m]);
  }

  // --- TAB NAVIGATION ---
  function setupTabNavigation() {
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.target;
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        Object.keys(viewPanels).forEach(key => {
          if (viewPanels[key]) {
            viewPanels[key].style.display = key === target ? 'block' : 'none';
          }
        });

        if (target === 'history') {
          renderHistory();
        }
      });
    });
  }

  function switchTab(tabKey) {
    const targetTab = document.querySelector(`.nav-tab-btn[data-target="${tabKey}"]`);
    if (targetTab) targetTab.click();
  }

  // --- QR DROPZONE & UPLOAD ---
  function setupDropzone() {
    selectFileBtn.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('click', (e) => {
      if (e.target !== selectFileBtn && !selectFileBtn.contains(e.target)) {
        fileInput.click();
      }
    });

    ['dragenter', 'dragover'].forEach(name => {
      dropzone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(name => {
      dropzone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      if (files && files.length > 0) {
        handleImageFile(files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleImageFile(e.target.files[0]);
      }
    });
  }

  // --- GLOBAL CLIPBOARD PASTE (Ctrl+V) ---
  function setupGlobalClipboardPaste() {
    window.addEventListener('paste', (e) => {
      const items = e.clipboardData?.items;
      if (!items) return;

      for (let i = 0; i < items.length; i++) {
        if (items[i].type.startsWith('image/')) {
          const file = items[i].getAsFile();
          if (file) {
            showToast('Pasted image from clipboard detected.', 'info');
            switchTab('scanner');
            handleImageFile(file);
            break;
          }
        }
      }
    });
  }

  // Process image file
  async function handleImageFile(file) {
    if (!file.type.startsWith('image/')) {
      showToast('Please select a valid image file (PNG, JPG, WEBP, etc.).', 'error');
      return;
    }

    setSpinner(true, 'Decoding QR Code Image...');
    window.QryptEngine.stopCamera(videoElement);
    cameraContainer.style.display = 'none';
    startCameraBtn.disabled = false;

    try {
      const res = await window.QryptEngine.decodeImageFile(file);
      if (res.success && res.text) {
        showToast('QR Code successfully detected and decoded!', 'success');
        processScannedData(res.text, 'Upload');
      } else {
        showToast(res.error || 'No readable QR code found in the image.', 'error');
      }
    } catch (err) {
      showToast(err.message || 'Error processing image file.', 'error');
    } finally {
      setSpinner(false);
      fileInput.value = '';
    }
  }

  function setSpinner(show, text = 'Processing...') {
    if (spinner) {
      spinner.style.display = show ? 'flex' : 'none';
      const spinnerText = spinner.querySelector('.spinner-text');
      if (spinnerText) spinnerText.textContent = text;
    }
  }

  // --- CAMERA SCANNER CONTROLS ---
  function setupCameraControls() {
    startCameraBtn.addEventListener('click', async () => {
      try {
        cameraContainer.style.display = 'flex';
        startCameraBtn.style.display = 'none';
        stopCameraBtn.style.display = 'inline-flex';
        stopCameraBtn.disabled = false;

        await window.QryptEngine.startCamera(
          videoElement,
          (scannedText) => {
            showToast('Camera scan complete!', 'success');
            cameraContainer.style.display = 'none';
            stopCameraBtn.style.display = 'none';
            stopCameraBtn.disabled = true;
            startCameraBtn.style.display = 'inline-flex';
            startCameraBtn.disabled = false;
            processScannedData(scannedText, 'Camera');
          },
          (errorMsg) => {
            showToast(errorMsg, 'error');
            cameraContainer.style.display = 'none';
            stopCameraBtn.style.display = 'none';
            stopCameraBtn.disabled = true;
            startCameraBtn.style.display = 'inline-flex';
            startCameraBtn.disabled = false;
          }
        );
      } catch (err) {
        showToast(err.message, 'error');
        cameraContainer.style.display = 'none';
        stopCameraBtn.style.display = 'none';
        stopCameraBtn.disabled = true;
        startCameraBtn.style.display = 'inline-flex';
        startCameraBtn.disabled = false;
      }
    });

    stopCameraBtn.addEventListener('click', () => {
      window.QryptEngine.stopCamera(videoElement);
      cameraContainer.style.display = 'none';
      stopCameraBtn.style.display = 'none';
      stopCameraBtn.disabled = true;
      startCameraBtn.style.display = 'inline-flex';
      startCameraBtn.disabled = false;
      showToast('Camera stopped.', 'info');
    });
  }

  // --- MANUAL URL INPUT ---
  function setupManualInput() {
    analyzeManualBtn.addEventListener('click', () => {
      const text = manualUrlInput.value.trim();
      if (!text) {
        showToast('Please enter a URL or text string to analyze.', 'error');
        manualUrlInput.focus();
        return;
      }
      processScannedData(text, 'Manual');
    });

    manualUrlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        analyzeManualBtn.click();
      }
    });
  }

  // --- PROCESS AND RENDER SCANNED DATA ---
  function processScannedData(payload, source = 'Upload') {
    currentScannedPayload = payload;

    // Analyze using QryptAnalyzer
    const report = window.QryptAnalyzer.analyze(payload);
    report.source = source;

    // Save to history
    window.QryptHistory.addRecord(report);

    // If payload is a UPI payment QR, also update UPI verification module
    if (report.isUpi) {
      prefillUpiModuleFromUri(payload);
    }

    // Render report UI
    renderSecurityReport(report);

    // Scroll report into view
    reportContainer.style.display = 'block';
    reportContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // --- RENDER SECURITY REPORT ---
  function renderSecurityReport(report) {
    const verdict = report.verdict; // 'SUSPICIOUS' | 'NO OBVIOUS THREATS DETECTED' | 'UNKNOWN'
    const riskScore = report.riskScore || 0;

    // 1. Reset verdict banner styling
    verdictBanner.className = 'verdict-banner';
    verdictTitle.textContent = verdict;

    if (verdict === 'SUSPICIOUS') {
      verdictBanner.classList.add('suspicious');
      verdictIcon.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>';
      verdictTagline.textContent = 'High-probability threat indicators or deceptive structural patterns detected.';
      riskLevelPill.textContent = `${report.riskRating.toUpperCase()} RISK`;
      riskLevelPill.style.background = 'rgba(239, 68, 68, 0.2)';
      riskLevelPill.style.color = '#fca5a5';
    } else if (verdict === 'NO OBVIOUS THREATS DETECTED') {
      verdictBanner.classList.add('safe');
      verdictIcon.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>';
      verdictTagline.textContent = 'Passed all heuristic rule checks. No known structural red flags identified.';
      riskLevelPill.textContent = 'LOW RISK';
      riskLevelPill.style.background = 'rgba(16, 185, 129, 0.2)';
      riskLevelPill.style.color = '#6ee7b7';
    } else {
      verdictBanner.classList.add('unknown');
      verdictIcon.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
      verdictTagline.textContent = 'Scanned payload is not a standard web URL. Manual review required.';
      riskLevelPill.textContent = 'UNCLASSIFIED';
      riskLevelPill.style.background = 'rgba(148, 163, 184, 0.2)';
      riskLevelPill.style.color = '#cbd5e1';
    }

    riskScoreNum.textContent = riskScore;

    // 2. Extracted Data Display
    decodedContent.textContent = report.input || 'No data decoded';

    // 3. Warnings List
    warningsList.innerHTML = '';
    const warnings = report.warnings || [];
    if (warnings.length > 0) {
      warningsSection.style.display = 'block';
      warnings.forEach(w => {
        const item = document.createElement('div');
        item.className = `warning-item severity-${w.severity || 'HIGH'}`;
        item.innerHTML = `
          <span class="warning-badge ${w.severity || 'HIGH'}">${w.severity || 'HIGH'}</span>
          <div class="warning-body">
            <div class="warning-name">${escapeHtml(w.name || 'Security Warning')}</div>
            <div class="warning-desc">${escapeHtml(w.description || '')}</div>
          </div>
        `;
        warningsList.appendChild(item);
      });
    } else {
      warningsSection.style.display = 'none';
    }

    // 4. Actionable Next Steps
    recList.innerHTML = '';
    (report.recommendations || []).forEach(rec => {
      const li = document.createElement('li');
      li.className = 'rec-item';
      li.innerHTML = `
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
        <span>${escapeHtml(rec)}</span>
      `;
      recList.appendChild(li);
    });

    // 5. Transparent Rules Checklist
    rulesList.innerHTML = '';
    (report.rules || []).forEach(r => {
      const row = document.createElement('div');
      row.className = 'rule-check-row';
      const isPassed = Boolean(r.passed);
      row.innerHTML = `
        <span class="rule-check-name">${escapeHtml(r.name)}</span>
        <span class="rule-check-status ${isPassed ? 'status-passed' : 'status-flagged'}">
          ${isPassed 
            ? '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg> Passed' 
            : '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg> Flagged'}
        </span>
      `;
      rulesList.appendChild(row);
    });
  }

  // --- CAUTION MODAL & SAFE COPY ---
  function setupCautionModal() {
    copyUrlBtn.addEventListener('click', () => {
      if (!currentScannedPayload) return;
      modalPayloadText.textContent = currentScannedPayload;
      cautionModal.classList.add('open');
    });

    modalCloseBtn.addEventListener('click', () => cautionModal.classList.remove('open'));
    modalCancelBtn.addEventListener('click', () => cautionModal.classList.remove('open'));

    modalConfirmCopyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(currentScannedPayload);
        showToast('Extracted URL copied to clipboard. Handle with care!', 'success');
      } catch (err) {
        // Fallback
        const textarea = document.createElement('textarea');
        textarea.value = currentScannedPayload;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Extracted URL copied to clipboard.', 'success');
      }
      cautionModal.classList.remove('open');
    });

    cautionModal.addEventListener('click', (e) => {
      if (e.target === cautionModal) cautionModal.classList.remove('open');
    });
  }

  // --- SAMPLE TEST CHIPS ---
  function setupSampleChips() {
    const chips = document.querySelectorAll('.sample-chip');
    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        const payload = chip.dataset.payload;
        if (!payload) return;

        showToast(`Loading test sample: ${chip.textContent.trim()}`, 'info');

        // Check if UPI test or URL test
        if (/^upi:\/\/pay/i.test(payload)) {
          switchTab('upi');
          upiInput.value = payload.replace(/^upi:\/\/pay\?pa=/i, '').split('&')[0];
          verifyUpiBtn.click();
        } else {
          switchTab('manual');
          manualUrlInput.value = payload;
          processScannedData(payload, 'Sample');
        }
      });
    });
  }

  // --- UPI MODULE SETUP ---
  function setupUpiModule() {
    verifyUpiBtn.addEventListener('click', () => {
      const upiId = upiInput.value.trim();
      const expectedName = expectedNameInput.value.trim();
      const expectedUpi = expectedUpiInput.value.trim();

      if (!upiId) {
        showToast('Please enter a UPI ID (e.g. merchant@okhdfcbank).', 'error');
        upiInput.focus();
        return;
      }

      // Check if user entered a full upi://pay URI
      let result;
      if (/^upi:\/\/pay/i.test(upiId)) {
        const fullInspect = window.QryptUpi.parseAndInspectUpiUri(upiId, expectedName, expectedUpi);
        result = fullInspect.vpaResult;
      } else {
        result = window.QryptUpi.verifyUpiReceiver(upiId, expectedName, expectedUpi);
      }

      renderUpiReport(result);
    });

    upiInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') verifyUpiBtn.click();
    });
  }

  function prefillUpiModuleFromUri(uri) {
    const parsed = window.QryptUpi.parseAndInspectUpiUri(uri);
    if (parsed.isUpiUri) {
      upiInput.value = parsed.params.pa || uri;
      if (parsed.params.pn) {
        expectedNameInput.placeholder = `QR specifies name: ${parsed.params.pn}`;
      }
    }
  }

  function renderUpiReport(result) {
    upiReport.style.display = 'block';

    const verdict = result.verdict; // 'VERIFIED' | 'UNVERIFIED' | 'UNKNOWN'
    upiVerdictBadge.className = `upi-verdict-badge ${verdict}`;
    upiVerdictBadge.textContent = verdict;
    upiVerdictMsg.textContent = result.message || '';

    // Populate Table
    upiTableBody.innerHTML = '';
    const addRow = (label, val) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(label)}</td><td>${escapeHtml(val || 'N/A')}</td>`;
      upiTableBody.appendChild(tr);
    };

    addRow('UPI ID (VPA)', result.upiId);
    addRow('VPA Syntax Format', result.details?.syntaxValid ? 'Valid NPCI standard' : 'Invalid syntax');

    if (result.bankInfo) {
      addRow('Managing App / TPAP', result.bankInfo.psp);
      addRow('Partner / Clearing Bank', result.bankInfo.bank);
      addRow('Handle Category', result.bankInfo.type);
    } else if (result.handle) {
      addRow('Bank Handle', `@${result.handle} (Unrecognized)`);
    }

    if (result.isTrustedDirectory && result.trustedEntity) {
      addRow('Directory Entity', result.trustedEntity.name);
      addRow('Verification Registry', result.details?.verifiedSourceName || 'Trusted List');
    }

    // Comparison details if provided
    if (result.comparison) {
      addRow('Expected UPI ID', result.comparison.expectedUpi);
      addRow('UPI Match Result', result.comparison.upiMatches ? 'MATCH' : 'MISMATCH');
    }

    // Warnings list
    upiWarningsBox.innerHTML = '';
    if (result.warnings && result.warnings.length > 0) {
      upiWarningsBox.style.display = 'block';
      result.warnings.forEach(w => {
        const p = document.createElement('div');
        p.className = 'warning-item severity-HIGH';
        p.style.marginBottom = '6px';
        p.innerHTML = `<span class="warning-badge HIGH">ALERT</span> <div class="warning-desc" style="color:#ffffff;">${escapeHtml(w)}</div>`;
        upiWarningsBox.appendChild(p);
      });
    } else {
      upiWarningsBox.style.display = 'none';
    }

    upiReport.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // --- HISTORY VIEW SETUP ---
  function setupHistoryView() {
    clearHistoryBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
        window.QryptHistory.clearHistory();
        renderHistory();
        showToast('Scan history cleared successfully.', 'info');
      }
    });

    exportHistoryBtn.addEventListener('click', () => {
      const records = window.QryptHistory.getHistory();
      if (records.length === 0) {
        showToast('No scan history records to export.', 'info');
        return;
      }
      window.QryptHistory.exportHistoryAsJson();
      showToast('Scan history exported as JSON file.', 'success');
    });

    historyFilterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        historyFilterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeHistoryFilter = btn.dataset.filter || 'all';
        renderHistory();
      });
    });
  }

  function renderHistory() {
    const allRecords = window.QryptHistory.getHistory();
    let records = allRecords;

    if (activeHistoryFilter === 'suspicious') {
      records = allRecords.filter(r => r.verdict === 'SUSPICIOUS');
    } else if (activeHistoryFilter === 'safe') {
      records = allRecords.filter(r => r.verdict === 'NO OBVIOUS THREATS DETECTED');
    } else if (activeHistoryFilter === 'unknown') {
      records = allRecords.filter(r => r.verdict === 'UNKNOWN');
    }

    if (records.length === 0) {
      historyTableWrapper.style.display = 'none';
      historyEmptyState.style.display = 'block';
      return;
    }

    historyTableWrapper.style.display = 'block';
    historyEmptyState.style.display = 'none';
    historyTableBody.innerHTML = '';

    records.forEach(rec => {
      const tr = document.createElement('tr');
      const timeStr = new Date(rec.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const dateStr = new Date(rec.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });

      let verdictBadgeClass = 'UNKNOWN';
      if (rec.verdict === 'SUSPICIOUS') verdictBadgeClass = 'SUSPICIOUS';
      if (rec.verdict === 'NO OBVIOUS THREATS DETECTED') verdictBadgeClass = 'NO_OBVIOUS_THREATS';

      tr.innerHTML = `
        <td style="color:var(--text-dim); font-size:0.8rem; white-space:nowrap;">
          ${dateStr} <br><span style="font-size:0.75rem;">${timeStr}</span>
        </td>
        <td style="white-space:nowrap;">
          <span style="font-size:0.75rem; background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:4px;">
            ${escapeHtml(rec.source)}
          </span>
        </td>
        <td>
          <div class="history-payload-cell" title="${escapeHtml(rec.payload)}">
            ${escapeHtml(rec.payload)}
          </div>
        </td>
        <td>
          <span class="history-verdict-badge ${verdictBadgeClass}">
            ${escapeHtml(rec.verdict)}
          </span>
        </td>
        <td style="font-family:var(--font-mono); font-weight:700;">
          ${rec.riskScore}/100
        </td>
        <td style="text-align:right;">
          <button class="btn btn-secondary btn-sm inspect-history-btn" data-id="${rec.id}">
            Inspect
          </button>
        </td>
      `;

      tr.querySelector('.inspect-history-btn').addEventListener('click', () => {
        inspectHistoryRecord(rec.id);
      });

      historyTableBody.appendChild(tr);
    });
  }

  function inspectHistoryRecord(id) {
    const record = window.QryptHistory.getRecordById(id);
    if (!record || !record.fullReport) {
      showToast('Record details not available.', 'error');
      return;
    }

    currentScannedPayload = record.payload;
    renderSecurityReport(record.fullReport);
    switchTab('scanner');
    reportContainer.style.display = 'block';
    reportContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    showToast(`Restored scan report from ${new Date(record.timestamp).toLocaleTimeString()}`, 'info');
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
