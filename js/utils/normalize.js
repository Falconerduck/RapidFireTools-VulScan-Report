/*
  normalize.js
  Canonical issue key normalization.
  Requirements:
    - Trim
    - Collapse whitespace
    - Unicode normalize
    - Preserve meaning (do NOT rewrite titles)
*/
(function () {
  'use strict';

  function collapseWhitespace(text) {
    // Replace any run of whitespace (including newlines/tabs) with a single space.
    return text.replace(/\s+/g, ' ');
  }

  function normalizeIssueKey(issueText) {
    if (issueText == null) return '';
    const raw = String(issueText);

    // Normalize unicode to reduce accidental mismatches.
    // NFKC is a common choice for compatibility normalization.
    let normalized;
    try {
      normalized = raw.normalize('NFKC');
    } catch (e) {
      normalized = raw; // Older engines might not support normalize()
    }

    normalized = collapseWhitespace(normalized).trim();
    return normalized;
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.utils = window.VulScanReport.utils || {};
  window.VulScanReport.utils.normalizeIssueKey = normalizeIssueKey;
})();
