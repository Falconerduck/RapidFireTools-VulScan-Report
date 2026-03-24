/*
  computeNewFindings.js
  Computes NEW vulnerabilities.

  Rules:
    - Primary key is normalized Issue key.
    - A finding is considered NEW when:
        (A) the Issue key exists in Current but NOT in Previous, OR
        (B) the Issue key exists in both, but Current contains one or more NEW affected hosts.

  Notes:
    - Resolved items (missing from Current) are ignored.
    - Host comparisons use deterministic host-key extraction (prefer IPv4 when present).

  Output:
    - Mutates currentFindings by setting:
        - isNewIssue: boolean
        - newHosts: string[] (host keys newly affected; empty if none)
        - isNew: boolean (isNewIssue || newHosts.length)
*/
(function () {
  'use strict';

  const hostsUtil = window.VulScanReport?.utils?.hosts;

  function hostKeyFromAffectedEntry(entry) {
    if (hostsUtil?.hostKeyFromAffectedEntry) return hostsUtil.hostKeyFromAffectedEntry(entry);

    // Fallback (should match hosts.js behavior): IPv4 > hostname before '(' > raw
    const raw = String(entry == null ? '' : entry).trim();
    const m = raw.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    const ip = m && m[1] ? m[1] : '';

    let hostname = '';
    const parenIdx = raw.indexOf('(');
    if (parenIdx > 0) hostname = raw.slice(0, parenIdx).trim();

    return ip || hostname || raw;
  }

  function buildPreviousIndex(previousFindingsOrKeys) {
    const prevKeys = new Set();
    const prevHostsByIssue = new Map();

    for (const item of previousFindingsOrKeys || []) {
      if (!item) continue;

      if (typeof item === 'string') {
        prevKeys.add(item);
        continue;
      }

      const issueKey = typeof item.issueKey === 'string' ? item.issueKey : '';
      if (!issueKey) continue;

      prevKeys.add(issueKey);

      const set = new Set();
      const affected = Array.isArray(item.affectedDevices) ? item.affectedDevices : [];
      for (const dev of affected) {
        const hk = hostKeyFromAffectedEntry(dev);
        if (hk) set.add(hk);
      }
      prevHostsByIssue.set(issueKey, set);
    }

    return { prevKeys, prevHostsByIssue };
  }

  function computeNewFindings(previousFindingsOrKeys, currentFindings) {
    const { prevKeys, prevHostsByIssue } = buildPreviousIndex(previousFindingsOrKeys);
    const newKeys = new Set();

    for (const finding of currentFindings || []) {
      if (!finding) continue;

      const issueKey = finding.issueKey;
      const isNewIssue = !prevKeys.has(issueKey);

      const currentHostSet = new Set();
      const affected = Array.isArray(finding.affectedDevices) ? finding.affectedDevices : [];
      for (const dev of affected) {
        const hk = hostKeyFromAffectedEntry(dev);
        if (hk) currentHostSet.add(hk);
      }

      let newHosts = [];

      if (isNewIssue) {
        newHosts = Array.from(currentHostSet.values());
      } else {
        const prevSet = prevHostsByIssue.get(issueKey);
        if (prevSet && prevSet.size) {
          for (const hk of currentHostSet) {
            if (!prevSet.has(hk)) newHosts.push(hk);
          }
        }
      }

      const isNew = Boolean(isNewIssue || newHosts.length);

      finding.isNewIssue = Boolean(isNewIssue);
      finding.newHosts = Array.isArray(newHosts) ? newHosts : [];
      finding.isNew = isNew;

      if (isNew) newKeys.add(issueKey);
    }

    return { newKeys, previousKeys: prevKeys };
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.parsers = window.VulScanReport.parsers || {};
  window.VulScanReport.parsers.computeNewFindings = computeNewFindings;
})();
