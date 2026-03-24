/*
  parseByDeviceCsv.js
  Parses RapidFireTools VulScan "Vulnerability Scan Report (By Device)" CSV.

  This module is designed for future/expanded accuracy.
  Current usage: host metadata seeding (IP/Hostname/MAC) and optional cross-checking.
*/
(function () {
  'use strict';

  const logger = window.VulScanReport?.logger;
  const normalizeIssueKey = window.VulScanReport?.utils?.normalizeIssueKey;

  const REQUIRED_COLUMNS = ['IP Address', 'Severity', 'Issue'];

  function buildHeaderIndex(headerRow) {
    const index = {};
    headerRow.forEach((h, i) => {
      const key = String(h ?? '').trim();
      if (!key) return;
      if (typeof index[key] === 'number') return;
      index[key] = i;
    });
    return index;
  }

  function validateHeaders(headerIndex) {
    const missing = REQUIRED_COLUMNS.filter((c) => typeof headerIndex[c] !== 'number');
    if (missing.length) {
      const err = new Error(`Missing required column(s): ${missing.join(', ')}`);
      err.code = 'MissingColumns';
      err.missing = missing;
      throw err;
    }
  }

  function getCell(row, headerIndex, colName) {
    const idx = headerIndex[colName];
    if (typeof idx !== 'number') return '';
    return row[idx] ?? '';
  }

  
  function resolveColumnIndex(headerIndex, headerRow, candidates, regex) {
    for (const name of candidates || []) {
      const idx = headerIndex[name];
      if (typeof idx === 'number') return idx;
    }
    if (regex) {
      for (let i = 0; i < (headerRow || []).length; i++) {
        const h = String(headerRow[i] ?? '').trim();
        if (!h) continue;
        if (regex.test(h)) return i;
      }
    }
    return null;
  }


  function asBoolYesNo(value) {
    const v = String(value ?? '').trim().toLowerCase();
    if (!v) return null;

    if (v === 'yes' || v === 'true' || v === 'y' || v === '1') return true;
    if (v.startsWith('yes')) return true;
    if (v.includes('kev') || v.includes('known exploited')) return true;

    if (v === 'no' || v === 'false' || v === 'n' || v === '0') return false;
    if (v.startsWith('no')) return false;

    return null;
  }

  function parseByDeviceCsv(csvText) {
    const parsed = window.CsvParseLite.parse(csvText);
    if (parsed.errors?.length) {
      logger?.warn('CSV parse returned errors', parsed.errors);
    }

    const rows = parsed.data || [];
    if (!rows.length) {
      const err = new Error('CSV appears to be empty.');
      err.code = 'EmptyCsv';
      throw err;
    }

    const headerRow = rows[0].map((h) => String(h ?? '').replace(/^\uFEFF/, '').trim());
    const headerIndex = buildHeaderIndex(headerRow);
    validateHeaders(headerIndex);
    const knownExploitedIdx = resolveColumnIndex(headerIndex, headerRow, ['Known Exploited Vulnerability', 'Known Exploited Vulnerabilities', 'Known Exploited'], /known\s*exploited/i);

    const records = [];

    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      if (!row || (row.length === 1 && String(row[0] ?? '').trim() === '')) continue;

      const ip = String(getCell(row, headerIndex, 'IP Address') ?? '').trim();
      const issue = String(getCell(row, headerIndex, 'Issue') ?? '').trim();
      if (!ip || !issue) continue;

      records.push({
        ip,
        hostname: String(getCell(row, headerIndex, 'Hostname') ?? '').trim(),
        mac: String(getCell(row, headerIndex, 'MAC Address') ?? '').trim(),
        severity: String(getCell(row, headerIndex, 'Severity') ?? '').trim() || 'Unknown',
        cvss: String(getCell(row, headerIndex, 'CVSS') ?? '').trim(),
        issue,
        issueKey: normalizeIssueKey(issue),
        ports: String(getCell(row, headerIndex, 'Ports') ?? '').trim(),
        oid: String(getCell(row, headerIndex, 'OID') ?? '').trim(),
        cve: String(getCell(row, headerIndex, 'CVE') ?? '').trim(),
        lastDetected: String(getCell(row, headerIndex, 'Last Detected') ?? '').trim(),
        knownExploited: asBoolYesNo(knownExploitedIdx != null ? (row[knownExploitedIdx] ?? '') : ''),
        ransomwareFlag: String(getCell(row, headerIndex, 'Known To Be Used In Ransomware Campaigns') ?? '').trim(),

        summary: String(getCell(row, headerIndex, 'Summary') ?? '').trim(),
        detectionResult: String(getCell(row, headerIndex, 'Vulnerability Detection Result') ?? '').trim(),
        impact: String(getCell(row, headerIndex, 'Impact') ?? '').trim(),
        solution: String(getCell(row, headerIndex, 'Solution') ?? '').trim(),
        insight: String(getCell(row, headerIndex, 'Vulnerability Insight') ?? '').trim(),
        detectionMethod: String(getCell(row, headerIndex, 'Vulnerability Detection Method') ?? '').trim(),
        references: String(getCell(row, headerIndex, 'References') ?? '').trim(),
      });
    }

    logger?.info('Parsed By-Device CSV', {
      rows: rows.length - 1,
      records: records.length,
    });

    return {
      records,
      meta: {
        type: 'byDevice',
        rowCount: rows.length - 1,
        recordCount: records.length,
        headers: headerRow,
      },
    };
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.parsers = window.VulScanReport.parsers || {};
  window.VulScanReport.parsers.parseByDeviceCsv = parseByDeviceCsv;
})();
