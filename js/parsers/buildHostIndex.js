/*
  buildHostIndex.js
  Builds per-host index and metadata.

  Host sources:
    1) Optional By-Device CSV (preferred for host metadata)
    2) Fallback: derive hosts from "Affected Devices" field in By-Issue CSV

  Notes:
    - Host key extraction must be deterministic and should match computeNewFindings() logic.
    - Per-host NEW counts are host-specific:
        NEW for host when finding.isNewIssue OR hostKey is in finding.newHosts.
*/
(function () {
  'use strict';

  const config = window.VulScanReport?.config;
  const hostsUtil = window.VulScanReport?.utils?.hosts;

  function parseAffectedDeviceEntry(entry) {
    if (hostsUtil?.parseAffectedDeviceEntry) return hostsUtil.parseAffectedDeviceEntry(entry);

    // Fallback: IPv4 > hostname before '(' > raw
    const raw = String(entry == null ? '' : entry).trim();
    const m = raw.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    const ip = m && m[1] ? m[1] : '';

    let hostname = '';
    const parenIdx = raw.indexOf('(');
    if (parenIdx > 0) hostname = raw.slice(0, parenIdx).trim();

    const key = ip || hostname || raw;
    return { key, ip: ip || '', hostname, raw };
  }

  function ensureHost(hostMap, hostKey) {
    if (!hostMap[hostKey]) {
      hostMap[hostKey] = {
        key: hostKey,
        ip: '',
        hostname: '',
        mac: '',
        displayName: hostKey,
        issueKeys: [],
        severityCounts: {
          Critical: 0,
          High: 0,
          Medium: 0,
          Low: 0,
          Informational: 0,
        },
        newCount: 0,
      };
    }
    return hostMap[hostKey];
  }

  function applyHostMetadata(host, meta) {
    if (!host) return;
    if (meta.ip && !host.ip) host.ip = meta.ip;
    if (meta.hostname && !host.hostname) host.hostname = meta.hostname;
    if (meta.mac && !host.mac) host.mac = meta.mac;

    // Display name preference: Hostname (IP) > IP > Key
    if (host.hostname && host.ip) host.displayName = `${host.hostname} (${host.ip})`;
    else if (host.ip) host.displayName = host.ip;
    else if (host.hostname) host.displayName = host.hostname;
    else host.displayName = host.key;
  }

  function maxSeverityForHost(host) {
    let best = 'Unknown';
    let bestRank = 0;
    for (const sev in host.severityCounts) {
      const count = host.severityCounts[sev];
      if (!count) continue;
      const r = config.severityRank[sev] ?? 0;
      if (r > bestRank) {
        bestRank = r;
        best = sev;
      }
    }
    return best;
  }

  function isNewForHost(finding, hostKey) {
    if (!finding) return false;
    if (finding.isNewIssue) return true;
    const list = Array.isArray(finding.newHosts) ? finding.newHosts : [];
    return list.includes(hostKey);
  }

  function buildHostIndex(findings, byDeviceRecords) {
    const hostMap = {};

    // Seed host list and metadata from By-Device records (preferred).
    if (Array.isArray(byDeviceRecords) && byDeviceRecords.length) {
      for (const rec of byDeviceRecords) {
        if (!rec) continue;
        const key = rec.ip || rec.hostname;
        if (!key) continue;
        const host = ensureHost(hostMap, key);
        applyHostMetadata(host, { ip: rec.ip, hostname: rec.hostname, mac: rec.mac });
      }
    }

    // Build mapping from By-Issue findings.
    for (const f of findings || []) {
      if (!f) continue;

      const sev = f.severity || 'Unknown';
      const affected = Array.isArray(f.affectedDevices) ? f.affectedDevices : [];

      for (const entry of affected) {
        const parsed = parseAffectedDeviceEntry(entry);
        if (!parsed.key) continue;

        const host = ensureHost(hostMap, parsed.key);
        applyHostMetadata(host, parsed);

        // Issue keys are unique per finding list.
        if (!host.issueKeys.includes(f.issueKey)) host.issueKeys.push(f.issueKey);

        if (host.severityCounts[sev] != null) host.severityCounts[sev] += 1;
        if (isNewForHost(f, host.key)) host.newCount += 1;
      }
    }

    const hosts = Object.values(hostMap);

    // Sort hosts similarly to Nessus-style reports:
    // - By highest severity bucket
    // - Within bucket, by total findings desc
    // - Then by key
    for (const h of hosts) {
      h.maxSeverity = maxSeverityForHost(h);
      h.totalFindings = Object.values(h.severityCounts).reduce((a, b) => a + b, 0);
    }

    hosts.sort((a, b) => {
      const ar = config.severityRank[a.maxSeverity] ?? 0;
      const br = config.severityRank[b.maxSeverity] ?? 0;
      if (br !== ar) return br - ar;
      if (b.totalFindings !== a.totalFindings) return b.totalFindings - a.totalFindings;
      return String(a.key).localeCompare(String(b.key));
    });

    return {
      hosts,
      hostMap,
    };
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.parsers = window.VulScanReport.parsers || {};
  window.VulScanReport.parsers.buildHostIndex = buildHostIndex;
})();
