/*
  mergeNotes.js
  Merges imported client data JSON with current findings.

  Current schema (v2):
    {
      schemaVersion: 2,
      client: { id, name },
      updatedAt: "...",
      notes: {
        "<issueKey>": { note: "...", lastUpdated: "..." }
      },
      deviceRenames: {
        "<hostKey>": "Alias"
      }
    }

  Backward compatibility:
    - v1 files (notes-only) are accepted and upgraded in-memory.

  Default behavior:
    - prune notes for issues not present in the current scan.
    - prune deviceRenames for hosts not present in the current scan.
*/
(function () {
  'use strict';

  const config = window.VulScanReport?.config;
  const hostsUtil = window.VulScanReport?.utils?.hosts;

  function nowIso() {
    return new Date().toISOString();
  }

  function createEmptyRemediation() {
    return {
      schemaVersion: 1,
      known: {
        hosts: {},
        vulns: {},
        combos: {},
      },
      reviewQueue: {},
      log: {},
    };
  }

  function ensureRemediationDoc(doc) {
    if (!doc || typeof doc !== 'object') return;
    if (!doc.remediation || typeof doc.remediation !== 'object') {
      doc.remediation = createEmptyRemediation();
      return;
    }

    const r = doc.remediation;
    if (typeof r.schemaVersion !== 'number') r.schemaVersion = 1;
    if (!r.known || typeof r.known !== 'object') r.known = { hosts: {}, vulns: {}, combos: {} };
    if (!r.known.hosts || typeof r.known.hosts !== 'object') r.known.hosts = {};
    if (!r.known.vulns || typeof r.known.vulns !== 'object') r.known.vulns = {};
    if (!r.known.combos || typeof r.known.combos !== 'object') r.known.combos = {};
    if (!r.reviewQueue || typeof r.reviewQueue !== 'object') r.reviewQueue = {};
    if (!r.log || typeof r.log !== 'object') r.log = {};
  }

  function parseTime(iso) {
    if (!iso) return 0;
    const t = new Date(iso).getTime();
    return Number.isFinite(t) ? t : 0;
  }

  function minIso(a, b) {
    if (!a) return b || '';
    if (!b) return a || '';
    return parseTime(a) <= parseTime(b) ? a : b;
  }

  function maxIso(a, b) {
    if (!a) return b || '';
    if (!b) return a || '';
    return parseTime(a) >= parseTime(b) ? a : b;
  }

  function pickByUpdatedAt(localEntry, importedEntry) {
    if (!localEntry) return importedEntry;
    if (!importedEntry) return localEntry;

    const lt = parseTime(localEntry.updatedAt);
    const it = parseTime(importedEntry.updatedAt);
    // Prefer imported when tied or newer; keep local when it is newer (don't drop local edits).
    return lt > it ? localEntry : importedEntry;
  }

  function mergeKnownMap(localMap, importedMap, mode) {
    const out = {};
    const a = localMap && typeof localMap === 'object' ? localMap : {};
    const b = importedMap && typeof importedMap === 'object' ? importedMap : {};

    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const k of keys) {
      const la = a[k];
      const ib = b[k];
      const firstSeenAt = minIso(la?.firstSeenAt, ib?.firstSeenAt);
      const lastSeenAt = maxIso(la?.lastSeenAt, ib?.lastSeenAt);

      // Choose the title from the entry that has the latest lastSeenAt. If tied, prefer imported.
      const laLast = parseTime(la?.lastSeenAt);
      const ibLast = parseTime(ib?.lastSeenAt);
      const pickImported = ibLast >= laLast;

      if (mode === 'combo') {
        const base = pickImported ? ib : la;
        out[k] = {
          firstSeenAt,
          lastSeenAt,
          hostKey: base?.hostKey || la?.hostKey || ib?.hostKey,
          issueKey: base?.issueKey || la?.issueKey || ib?.issueKey,
          hostTitle: base?.hostTitle || la?.hostTitle || ib?.hostTitle || '',
          vulnTitle: base?.vulnTitle || la?.vulnTitle || ib?.vulnTitle || '',
        };
      } else {
        const base = pickImported ? ib : la;
        out[k] = {
          firstSeenAt,
          lastSeenAt,
          title: base?.title || la?.title || ib?.title || '',
        };
      }
    }

    return out;
  }

  function mergeRemediation(localRemediation, importedRemediation) {
    const local = localRemediation && typeof localRemediation === 'object' ? localRemediation : createEmptyRemediation();
    const imp = importedRemediation && typeof importedRemediation === 'object' ? importedRemediation : createEmptyRemediation();

    const merged = createEmptyRemediation();

    merged.known.hosts = mergeKnownMap(local.known?.hosts, imp.known?.hosts, 'host');
    merged.known.vulns = mergeKnownMap(local.known?.vulns, imp.known?.vulns, 'vuln');
    merged.known.combos = mergeKnownMap(local.known?.combos, imp.known?.combos, 'combo');

    const reviewQueue = {};
    const rqKeys = new Set([...
      Object.keys(local.reviewQueue || {}),
      ...Object.keys(imp.reviewQueue || {}),
    ]);
    for (const k of rqKeys) {
      reviewQueue[k] = pickByUpdatedAt(local.reviewQueue?.[k], imp.reviewQueue?.[k]);
    }

    const log = {};
    const logKeys = new Set([...
      Object.keys(local.log || {}),
      ...Object.keys(imp.log || {}),
    ]);
    for (const k of logKeys) {
      log[k] = pickByUpdatedAt(local.log?.[k], imp.log?.[k]);
    }

    // Log wins over queue.
    for (const k of Object.keys(log)) {
      if (reviewQueue[k]) delete reviewQueue[k];
    }

    merged.reviewQueue = reviewQueue;
    merged.log = log;

    return merged;
  }

  function updateRemediationOnScan(doc, currentFindings, hostIndexHosts, previousSnapshot) {
    if (!doc || typeof doc !== 'object') return doc;
    ensureRemediationDoc(doc);

    const hostsUtil = window.VulScanReport?.utils?.hosts;
    const hostKeyFromAffectedEntry = hostsUtil?.hostKeyFromAffectedEntry;
    const formatHostLabel = hostsUtil?.formatHostLabel;

    const rem = doc.remediation;
    const now = nowIso();

    // Seed baseline "known" sets from the previous scan snapshot (when available).
    // This enables "missing" detection on the first run for a client that has no prior remediation history.
    const prev = previousSnapshot && typeof previousSnapshot === 'object' ? previousSnapshot : null;
    const prevIssueKeys = Array.isArray(prev?.issueKeys) ? prev.issueKeys : [];
    const prevIssueTitleByKey = prev?.issueTitleByKey && typeof prev.issueTitleByKey === 'object' ? prev.issueTitleByKey : {};
    const prevHostKeys = Array.isArray(prev?.hostKeys) ? prev.hostKeys : [];
    const prevHostTitleByKey = prev?.hostTitleByKey && typeof prev.hostTitleByKey === 'object' ? prev.hostTitleByKey : {};
    const prevComboKeys = Array.isArray(prev?.comboKeys) ? prev.comboKeys : [];

    // Apply device renames (if present) when creating baseline titles.
    const renames = doc.deviceRenames && typeof doc.deviceRenames === 'object' ? doc.deviceRenames : {};

    for (const rawKey of prevHostKeys) {
      const hk = String(rawKey || '').trim();
      if (!hk) continue;
      if (rem.known.hosts[hk]) continue;

      const alias = String(renames[hk] || '').trim();
      const title = alias ? `${alias} (${hk})` : (String(prevHostTitleByKey[hk] || '').trim() || hk);

      rem.known.hosts[hk] = {
        firstSeenAt: now,
        lastSeenAt: now,
        title,
      };
    }

    for (const rawKey of prevIssueKeys) {
      const ik = String(rawKey || '').trim();
      if (!ik) continue;
      if (rem.known.vulns[ik]) continue;

      const title = String(prevIssueTitleByKey[ik] || '').trim() || ik;
      rem.known.vulns[ik] = {
        firstSeenAt: now,
        lastSeenAt: now,
        title,
      };
    }

    // Seed baseline combos (host::issue) from previous scan snapshot when available.
    // This enables showing affected devices/vulns for missing items on the first run.
    for (const rawKey of prevComboKeys) {
      const ck = String(rawKey || '').trim();
      if (!ck) continue;
      if (rem.known.combos[ck]) continue;

      const parts = ck.split('::');
      const hk = String(parts[0] || '').trim();
      const ik = String(parts[1] || '').trim();
      if (!hk || !ik) continue;

      const alias = String(renames[hk] || '').trim();
      const hostTitle = alias ? `${alias} (${hk})` : (String(prevHostTitleByKey[hk] || '').trim() || hk);
      const vulnTitle = String(prevIssueTitleByKey[ik] || '').trim() || ik;

      rem.known.combos[ck] = {
        firstSeenAt: now,
        lastSeenAt: now,
        hostKey: hk,
        issueKey: ik,
        hostTitle,
        vulnTitle,
      };
    }

    const findings = Array.isArray(currentFindings) ? currentFindings : [];
    const hostList = Array.isArray(hostIndexHosts) ? hostIndexHosts : [];
    const hostMap = {};
    for (const h of hostList) {
      if (h && h.key) hostMap[String(h.key)] = h;
    }

    const currentHosts = new Set();
    const currentVulns = new Set();
    const currentCombos = new Set();

    // Hosts from host index (preferred)
    for (const h of hostList) {
      if (h && h.key) currentHosts.add(String(h.key));
    }

    const issueTitleByKey = {};

    // Vulns + combos from findings
    for (const f of findings) {
      if (!f || !f.issueKey) continue;
      const issueKey = String(f.issueKey);
      currentVulns.add(issueKey);
      if (!issueTitleByKey[issueKey]) issueTitleByKey[issueKey] = String(f.issue || issueKey);

      const affected = Array.isArray(f.affectedDevices) ? f.affectedDevices : [];
      for (const entry of affected) {
        const hk = hostKeyFromAffectedEntry ? hostKeyFromAffectedEntry(entry) : String(entry || '').trim();
        if (!hk) continue;
        currentHosts.add(String(hk));

        const comboKey = `${String(hk)}::${issueKey}`;
        currentCombos.add(comboKey);
      }
    }

    // Update known hosts
    for (const hostKey of currentHosts) {
      const hk = String(hostKey);
      const existing = rem.known.hosts[hk];
      const host = hostMap[hk] || { key: hk };
      const title = formatHostLabel ? formatHostLabel(host, doc.deviceRenames) : String(host.displayName || hk);

      if (!existing) {
        rem.known.hosts[hk] = {
          firstSeenAt: now,
          lastSeenAt: now,
          title,
        };
      } else {
        existing.firstSeenAt = existing.firstSeenAt || now;
        existing.lastSeenAt = now;
        existing.title = title || existing.title || hk;
      }
    }

    // Update known vulns
    for (const issueKey of currentVulns) {
      const ik = String(issueKey);
      const existing = rem.known.vulns[ik];
      const title = issueTitleByKey[ik] || ik;

      if (!existing) {
        rem.known.vulns[ik] = {
          firstSeenAt: now,
          lastSeenAt: now,
          title,
        };
      } else {
        existing.firstSeenAt = existing.firstSeenAt || now;
        existing.lastSeenAt = now;
        existing.title = title || existing.title || ik;
      }
    }

    // Update known combos (host::issue)
    for (const comboKey of currentCombos) {
      const ck = String(comboKey);
      const parts = ck.split('::');
      const hk = String(parts[0] || '').trim();
      const ik = String(parts[1] || '').trim();
      if (!hk || !ik) continue;

      const hostTitle = rem.known.hosts[hk]?.title || hk;
      const vulnTitle = rem.known.vulns[ik]?.title || issueTitleByKey[ik] || ik;

      const existing = rem.known.combos[ck];
      if (!existing) {
        rem.known.combos[ck] = {
          firstSeenAt: now,
          lastSeenAt: now,
          hostKey: hk,
          issueKey: ik,
          hostTitle,
          vulnTitle,
        };
      } else {
        existing.firstSeenAt = existing.firstSeenAt || now;
        existing.lastSeenAt = now;
        existing.hostKey = existing.hostKey || hk;
        existing.issueKey = existing.issueKey || ik;
        existing.hostTitle = hostTitle || existing.hostTitle || hk;
        existing.vulnTitle = vulnTitle || existing.vulnTitle || ik;
      }
    }

    // Refresh titles for combos even when they are not present in the current scan
    // (e.g., after importing a client JSON with device renames).
    for (const ck of Object.keys(rem.known.combos)) {
      const c = rem.known.combos[ck];
      if (!c) continue;
      const hk = String(c.hostKey || '').trim();
      const ik = String(c.issueKey || '').trim();
      if (hk && rem.known.hosts[hk]?.title) c.hostTitle = rem.known.hosts[hk].title;
      if (ik && rem.known.vulns[ik]?.title) c.vulnTitle = rem.known.vulns[ik].title;
    }

    // Detect missing hosts
    for (const hk of Object.keys(rem.known.hosts)) {
      if (currentHosts.has(hk)) continue;
      const reviewKey = `HOST::${hk}`;
      if (rem.reviewQueue[reviewKey] || rem.log[reviewKey]) continue;

      const known = rem.known.hosts[hk];
      rem.reviewQueue[reviewKey] = {
        kind: 'host',
        hostKey: hk,
        title: known?.title || hk,
        firstSeenAt: now,
        lastSeenAt: known?.lastSeenAt || '',
        reason: '',
        notes: '',
        updatedAt: now,
      };
    }

    // Detect missing vulns
    for (const ik of Object.keys(rem.known.vulns)) {
      if (currentVulns.has(ik)) continue;
      const reviewKey = `VULN::${ik}`;
      if (rem.reviewQueue[reviewKey] || rem.log[reviewKey]) continue;

      const known = rem.known.vulns[ik];
      rem.reviewQueue[reviewKey] = {
        kind: 'vuln',
        issueKey: ik,
        title: known?.title || ik,
        firstSeenAt: now,
        lastSeenAt: known?.lastSeenAt || '',
        reason: '',
        notes: '',
        updatedAt: now,
      };
    }

    // Refresh titles for items still in review queue (do not auto-resolve).
    for (const rk of Object.keys(rem.reviewQueue)) {
      const entry = rem.reviewQueue[rk];
      if (!entry) continue;

      if (entry.kind === 'host' && entry.hostKey) {
        const hk = String(entry.hostKey);
        const title = rem.known.hosts[hk]?.title;
        if (title) entry.title = title;
      }

      if (entry.kind === 'vuln' && entry.issueKey) {
        const ik = String(entry.issueKey);
        const title = rem.known.vulns[ik]?.title;
        if (title) entry.title = title;
      }

      if (entry.kind === 'combo') {
        const ck = String(entry.comboKey || (entry.hostKey && entry.issueKey ? `${entry.hostKey}::${entry.issueKey}` : ''));
        const combo = ck ? rem.known.combos[ck] : null;
        if (combo) {
          entry.comboKey = ck;
          entry.hostKey = combo.hostKey;
          entry.issueKey = combo.issueKey;
          entry.title = `${combo.hostTitle || combo.hostKey} — ${combo.vulnTitle || combo.issueKey}`;
        }
      }
    }

    return doc;
  }

  function createEmptyNotesDoc() {
    return {
      schemaVersion: config.notes.schemaVersion,
      client: { id: config.client.id, name: config.client.name },
      updatedAt: nowIso(),
      notes: {},
      deviceRenames: {},
      remediation: createEmptyRemediation(),
    };
  }

  function isValidNotesDoc(doc) {
    if (!doc || typeof doc !== 'object') return false;
    if (typeof doc.schemaVersion !== 'number') return false;
    if (!doc.notes || typeof doc.notes !== 'object') return false;
    // deviceRenames is optional (v1)
    return true;
  }

  function hostKeyFromAffectedEntry(entry) {
    if (hostsUtil?.hostKeyFromAffectedEntry) return hostsUtil.hostKeyFromAffectedEntry(entry);
    const raw = String(entry == null ? '' : entry).trim();
    const m = raw.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    const ip = m && m[1] ? m[1] : '';

    let hostname = '';
    const parenIdx = raw.indexOf('(');
    if (parenIdx > 0) hostname = raw.slice(0, parenIdx).trim();

    return ip || hostname || raw;
  }

  function mergeNotes(importedDoc, currentFindings) {
    const doc = isValidNotesDoc(importedDoc) ? importedDoc : createEmptyNotesDoc();

    const findings = Array.isArray(currentFindings) ? currentFindings : [];

    const currentIssueKeys = new Set(findings.map((f) => f.issueKey));
    const currentHostKeys = new Set();

    for (const f of findings) {
      const affected = Array.isArray(f.affectedDevices) ? f.affectedDevices : [];
      for (const dev of affected) {
        const hk = hostKeyFromAffectedEntry(dev);
        if (hk) currentHostKeys.add(hk);
      }
    }

    // Upgrade / normalize top-level fields.
    doc.schemaVersion = config.notes.schemaVersion;

    doc.client = doc.client && typeof doc.client === 'object'
      ? doc.client
      : { id: config.client.id, name: config.client.name };

    doc.updatedAt = nowIso();

    if (!doc.notes || typeof doc.notes !== 'object') doc.notes = {};
    if (!doc.deviceRenames || typeof doc.deviceRenames !== 'object') doc.deviceRenames = {};

    // Remediation is optional in older files.
    ensureRemediationDoc(doc);

    // Prune notes and renames for items not present in current scan.
    if (config.notes.pruneResolvedOnExport) {
      for (const key of Object.keys(doc.notes)) {
        if (!currentIssueKeys.has(key)) delete doc.notes[key];
      }

      for (const hostKey of Object.keys(doc.deviceRenames)) {
        if (!currentHostKeys.has(hostKey)) delete doc.deviceRenames[hostKey];
      }
    }

    // Ensure every current issue has at least an empty entry.
    for (const key of currentIssueKeys) {
      if (!doc.notes[key]) {
        doc.notes[key] = { note: '', lastUpdated: '' };
      }
    }

    return doc;
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.parsers = window.VulScanReport.parsers || {};
  window.VulScanReport.parsers.mergeNotes = mergeNotes;
  window.VulScanReport.parsers.createEmptyNotesDoc = createEmptyNotesDoc;
  window.VulScanReport.parsers.ensureRemediationDoc = ensureRemediationDoc;
  window.VulScanReport.parsers.mergeRemediation = mergeRemediation;
  window.VulScanReport.parsers.updateRemediationOnScan = updateRemediationOnScan;
})();
