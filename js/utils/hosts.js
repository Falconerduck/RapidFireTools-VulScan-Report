/*
  hosts.js
  Host parsing + display helpers.

  Goals:
    - Deterministic host key extraction from VulScan "Affected Devices" entries
    - Consistent host label formatting (supports device renames)
    - Lightweight lookups for resolving an entry to a known host

  Notes:
    - Host key preference: IPv4 (if present) > hostname (before first '(') > raw entry
    - Device renames are keyed by hostKey.
*/
(function () {
  'use strict';

  function isValidIpv4(ip) {
    const parts = String(ip || '').split('.');
    if (parts.length !== 4) return false;
    for (let i = 0; i < parts.length; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) return false;
    }
    return true;
  }

  function extractIpv4(text) {
    const m = String(text == null ? '' : text).match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    if (!m) return '';
    const ip = m[1];
    return isValidIpv4(ip) ? ip : '';
  }

  function parseAffectedDeviceEntry(entry) {
    const raw = String(entry == null ? '' : entry).trim();
    const ip = extractIpv4(raw);

    // Try to extract hostname before first '(' if present.
    let hostname = '';
    const parenIdx = raw.indexOf('(');
    if (parenIdx > 0) hostname = raw.slice(0, parenIdx).trim();

    const key = ip || hostname || raw;

    return { key, ip: ip || '', hostname, raw };
  }

  function hostKeyFromAffectedEntry(entry) {
    return parseAffectedDeviceEntry(entry).key;
  }

  function buildHostLookup(hosts) {
    const byKey = {};
    const byIp = {};
    const byHostname = {};

    const list = Array.isArray(hosts) ? hosts : [];
    for (let i = 0; i < list.length; i++) {
      const h = list[i];
      if (!h || !h.key) continue;
      byKey[String(h.key)] = h;
      if (h.ip) byIp[String(h.ip)] = h;
      if (h.hostname) byHostname[String(h.hostname)] = h;
    }

    return { byKey, byIp, byHostname };
  }

  function resolveHostFromEntry(entry, lookup) {
    const parsed = parseAffectedDeviceEntry(entry);
    const hostKey = parsed.key;

    const lk = lookup || { byKey: {}, byIp: {}, byHostname: {} };

    let host = lk.byKey ? lk.byKey[hostKey] : null;
    if (!host && parsed.ip && lk.byIp) host = lk.byIp[parsed.ip];
    if (!host && parsed.hostname && lk.byHostname) host = lk.byHostname[parsed.hostname];

    const resolvedKey = host && host.key ? String(host.key) : hostKey;

    return { hostKey: resolvedKey, host: host || null, parsed };
  }

  function defaultHostDisplay(host) {
    if (!host) return '';

    if (host.hostname && host.ip) return `${host.hostname} (${host.ip})`;
    if (host.ip) return String(host.ip);
    if (host.hostname) return String(host.hostname);
    if (host.displayName) return String(host.displayName);
    return String(host.key || '');
  }

  function formatHostLabel(host, deviceRenames) {
    if (!host) return '';
    const renames = deviceRenames && typeof deviceRenames === 'object' ? deviceRenames : {};

    const key = String(host.key || '');
    const alias = String(renames[key] || '').trim();

    if (alias) {
      const ip = host.ip || (isValidIpv4(key) ? key : '');
      const suffix = ip || key;
      return `${alias} (${suffix})`;
    }

    return defaultHostDisplay(host);
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.utils = window.VulScanReport.utils || {};
  window.VulScanReport.utils.hosts = Object.freeze({
    isValidIpv4,
    extractIpv4,
    parseAffectedDeviceEntry,
    hostKeyFromAffectedEntry,
    buildHostLookup,
    resolveHostFromEntry,
    formatHostLabel,
    defaultHostDisplay,
  });
})();
