/**
 * QRYPT – QR Code Protection
 * Developed by Team Cyber Titans
 *
 * Module: Scan History Manager (js/history.js)
 * Purpose: Manages persistent scan records in browser localStorage,
 *          supports log filtering, detail inspection, JSON export, and clearing.
 */

(function (window) {
  'use strict';

  const STORAGE_KEY = 'qrypt_scan_history_v2';
  const MAX_RECORDS = 50;

  /**
   * Loads history array from localStorage
   * @returns {Array} Array of scan record objects
   */
  function getHistory() {
    try {
      const data = localStorage.getItem(STORAGE_KEY);
      if (!data) return [];
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      console.warn('QRYPT: Failed to read scan history from localStorage:', e);
      return [];
    }
  }

  /**
   * Saves a new scan record
   * @param {Object} record - Scan result details
   * @returns {Array} Updated history array
   */
  function addRecord(record) {
    const history = getHistory();
    const entry = {
      id: 'scan_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
      timestamp: new Date().toISOString(),
      source: record.source || 'Upload', // 'Upload' | 'Camera' | 'Manual' | 'Sample'
      type: record.type || (record.isUpi ? 'UPI Payment' : (record.isUrl ? 'Web URL' : 'Data/Text')),
      payload: record.input || '',
      verdict: record.verdict || 'UNKNOWN',
      riskScore: record.riskScore || 0,
      riskRating: record.riskRating || 'None',
      warningCount: (record.warnings || []).length,
      warningsSummary: (record.warnings || []).map(w => w.name || w),
      fullReport: record
    };

    // Prepend new record to the front
    history.unshift(entry);

    // Keep within capacity limit
    if (history.length > MAX_RECORDS) {
      history.length = MAX_RECORDS;
    }

    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    } catch (e) {
      console.warn('QRYPT: Failed to write scan history to localStorage:', e);
    }

    return history;
  }

  /**
   * Retrieves a single record by its ID
   * @param {string} id
   */
  function getRecordById(id) {
    const history = getHistory();
    return history.find(item => item.id === id) || null;
  }

  /**
   * Clears all scan history
   */
  function clearHistory() {
    try {
      localStorage.removeItem(STORAGE_KEY);
      return true;
    } catch (e) {
      console.warn('QRYPT: Failed to clear history:', e);
      return false;
    }
  }

  /**
   * Exports scan history as a downloadable JSON file
   */
  function exportHistoryAsJson() {
    const history = getHistory();
    const jsonStr = JSON.stringify({
      application: 'QRYPT – QR Code Protection',
      team: 'Cyber Titans',
      exportDate: new Date().toISOString(),
      totalRecords: history.length,
      records: history
    }, null, 2);

    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `QRYPT_Scan_History_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Export to window
  window.QryptHistory = {
    getHistory,
    addRecord,
    getRecordById,
    clearHistory,
    exportHistoryAsJson
  };

})(window);
