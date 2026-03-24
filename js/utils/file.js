/*
  file.js
  FileReader helpers.

  Reads as ArrayBuffer and decodes to text with a UTF-8 vs Windows-1252 heuristic.
*/
(function () {
  'use strict';

  const logger = window.VulScanReport?.logger;

  function countReplacementChars(str) {
    // U+FFFD replacement char.
    let count = 0;
    for (let i = 0; i < str.length; i++) {
      if (str.charCodeAt(i) === 0xfffd) count++;
    }
    return count;
  }

  function decodeSmart(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);

    const utf8 = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const win1252 = new TextDecoder('windows-1252', { fatal: false }).decode(bytes);

    const utf8Bad = countReplacementChars(utf8);
    const winBad = countReplacementChars(win1252);

    // Prefer fewer replacement chars. If tied, prefer UTF-8.
    if (winBad < utf8Bad) {
      logger?.info('Decoded file as windows-1252 due to fewer replacement characters', { utf8Bad, winBad });
      return win1252;
    }

    return utf8;
  }

  function readFileAsTextSmart(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(reader.error || new Error('File read error'));
      reader.onload = () => {
        try {
          const text = decodeSmart(reader.result);
          resolve(text);
        } catch (e) {
          reject(e);
        }
      };
      reader.readAsArrayBuffer(file);
    });
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.utils = window.VulScanReport.utils || {};
  window.VulScanReport.utils.readFileAsTextSmart = readFileAsTextSmart;
})();
