/*
  parseByIssueCsv.js
  Parses RapidFireTools VulScan "Vulnerability Scan Report (By Issue)" CSV.

  Output model: array of findings grouped by normalized Issue key.
*/
(function () {
  'use strict';

  const logger = window.VulScanReport?.logger;
  const normalizeIssueKey = window.VulScanReport?.utils?.normalizeIssueKey;

  const REQUIRED_COLUMNS = [
    'Severity',
    'Issue',
    'Affected Devices',
    'Number of Device(s)',
  ];

  function buildHeaderIndex(headerRow) {
    const index = {};
    headerRow.forEach((h, i) => {
      const key = String(h ?? '').trim();
      if (!key) return;
      // If duplicate header names exist, keep the first.
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


  function splitAffectedDevices(raw) {
    if (!raw) return [];
    // VulScan exports typically separate devices by commas.
    // Hostnames are unlikely to contain commas. This is a pragmatic approach.
    return String(raw)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function asBoolYesNo(value) {
    const v = String(value ?? '').trim().toLowerCase();
    if (!v) return null;

    // Common truthy patterns in exports: Yes/True/Y/1/KEV
    if (v === 'yes' || v === 'true' || v === 'y' || v === '1') return true;
    if (v.startsWith('yes')) return true;
    if (v.includes('kev') || v.includes('known exploited')) return true;

    // Common falsy patterns: No/False/N/0
    if (v === 'no' || v === 'false' || v === 'n' || v === '0') return false;
    if (v.startsWith('no')) return false;

    return null;
  }

  function toNumber(value) {
    const n = Number(String(value ?? '').trim());
    return Number.isFinite(n) ? n : null;
  }

  function mergeFinding(target, incoming) {
    // Merge affected devices (unique, preserve order)
    const seen = new Set(target.affectedDevices);
    for (const d of incoming.affectedDevices) {
      if (seen.has(d)) continue;
      seen.add(d);
      target.affectedDevices.push(d);
    }

    // Merge ports (unique, preserve order)
    const ports = new Set(target.portsList);
    for (const p of incoming.portsList) {
      if (!p) continue;
      if (ports.has(p)) continue;
      ports.add(p);
      target.portsList.push(p);
    }

    // Keep the most recent lastDetected if parseable, otherwise keep existing.
    if (incoming.lastDetected && !target.lastDetected) {
      target.lastDetected = incoming.lastDetected;
    }

    // Prefer non-empty text blocks.
    for (const k of ['summary', 'detectionResult', 'impact', 'solution', 'insight', 'detectionMethod', 'references']) {
      if (!target[k] && incoming[k]) target[k] = incoming[k];
    }

    // Merge identifiers.
    if (!target.oid && incoming.oid) target.oid = incoming.oid;
    if (!target.cve && incoming.cve) target.cve = incoming.cve;

    // Merge Known Exploited flag (true wins)
    if (incoming.knownExploited === true) target.knownExploited = true;
    else if (target.knownExploited == null && incoming.knownExploited != null) target.knownExploited = incoming.knownExploited;

    // Prefer non-empty ransomware flag
    if (!target.ransomwareFlag && incoming.ransomwareFlag) target.ransomwareFlag = incoming.ransomwareFlag;

    // Recompute device count.
    target.deviceCount = target.affectedDevices.length;

    return target;
  }

  function parseByIssueCsv(csvText) {
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

    const rawFindings = [];

    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      if (!row || (row.length === 1 && String(row[0] ?? '').trim() === '')) continue;

      const issue = String(getCell(row, headerIndex, 'Issue') ?? '').trim();
      if (!issue) continue;

      const issueKey = normalizeIssueKey(issue);

      const portsRaw = String(getCell(row, headerIndex, 'Ports') ?? '').trim();
      const portsList = portsRaw ? portsRaw.split(',').map((p) => p.trim()).filter(Boolean) : [];

      const finding = {
        severity: String(getCell(row, headerIndex, 'Severity') ?? '').trim() || 'Unknown',
        cvss: String(getCell(row, headerIndex, 'CVSS') ?? '').trim(),
        issue,
        issueKey,
        portsRaw,
        portsList,
        oid: String(getCell(row, headerIndex, 'OID') ?? '').trim(),
        cve: String(getCell(row, headerIndex, 'CVE') ?? '').trim(),
        affectedDevicesRaw: String(getCell(row, headerIndex, 'Affected Devices') ?? '').trim(),
        affectedDevices: splitAffectedDevices(getCell(row, headerIndex, 'Affected Devices')),
        deviceCount: toNumber(getCell(row, headerIndex, 'Number of Device(s)')),
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

        // computed later
        isNew: false,
      };

      // If deviceCount is missing, compute from affected devices list.
      if (finding.deviceCount == null) finding.deviceCount = finding.affectedDevices.length;

      rawFindings.push(finding);
    }

    // Group by issueKey.
    const byIssueKey = new Map();
    for (const f of rawFindings) {
      const existing = byIssueKey.get(f.issueKey);
      if (!existing) {
        byIssueKey.set(f.issueKey, f);
        continue;
      }
      mergeFinding(existing, f);
    }

    const findings = Array.from(byIssueKey.values());

    logger?.info('Parsed By-Issue CSV', {
      rows: rows.length - 1,
      findings: findings.length,
    });

    return {
      findings,
      meta: {
        type: 'byIssue',
        rowCount: rows.length - 1,
        findingCount: findings.length,
        headers: headerRow,
      },
    };
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.parsers = window.VulScanReport.parsers || {};
  window.VulScanReport.parsers.parseByIssueCsv = parseByIssueCsv;
})();
