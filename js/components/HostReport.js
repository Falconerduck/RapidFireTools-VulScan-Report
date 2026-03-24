/*
  HostReport.js
  Renders per-host vulnerabilities (host selected via ?host=... or hash).

  Listens:
    - data:loaded
    - data:cleared
    - notes:changed
    - filters:changed
    - hashchange

  Emits:
    - notes:updated { issueKey, note }
*/
(function () {
  'use strict';

  const config = window.VulScanReport?.config;
  const hostsUtil = window.VulScanReport?.utils?.hosts;
  const { escapeHtml, on, findByDataset } = window.VulScanReport?.utils || {};

  function sevLabelClass(sev) {
    const s = String(sev || '').toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium') return 'medium';
    if (s === 'low') return 'low';
    return 'info';
  }

  function normalizeQuery(q) {
    return String(q || '').trim().toLowerCase();
  }

  function getSelectedHostKey() {
    try {
      const params = new URLSearchParams(window.location.search || '');
      const q = params.get('host');
      if (q) return String(q);
    } catch (e) {
      // Ignore and fall back.
    }

    const hash = String(window.location.hash || '').replace(/^#/, '');
    return hash ? decodeURIComponent(hash) : '';
  }

  function isNewForHost(finding, hostKey) {
    if (!finding) return false;
    if (finding.isNewIssue) return true;
    const list = Array.isArray(finding.newHosts) ? finding.newHosts : [];
    return list.includes(hostKey);
  }

  function matchesQuery(finding, q) {
    if (!q) return true;
    const hay = [
      finding.issue,
      finding.cve,
      finding.oid,
      finding.portsRaw,
      finding.affectedDevicesRaw,
    ].join(' ').toLowerCase();
    return hay.includes(q);
  }

  function passesFilters(finding, filters, hostKey) {
    if (!finding) return false;
    if (filters?.severities?.length && !filters.severities.includes(finding.severity)) return false;
    if (filters?.newOnly && !isNewForHost(finding, hostKey)) return false;
    if (filters?.exploitedOnly && finding.knownExploited !== true) return false;
    if (!matchesQuery(finding, filters?.qNorm)) return false;
    return true;
  }

  function getNotesMap(state) {
    return state?.notesDoc?.notes || {};
  }

  function getDeviceRenames(state) {
    return state?.notesDoc?.deviceRenames || {};
  }

  function renderSidebarCounts(root, host) {
    const set = (role, val) => {
      const el = root.querySelector(`[data-role="${role}"]`);
      if (el) el.textContent = String(val);
    };

    set('summary-totalFindings', host?.totalFindings ?? 0);
    set('summary-newFindings', host?.newCount ?? 0);

    set('summary-critical', host?.severityCounts?.Critical ?? 0);
    set('summary-high', host?.severityCounts?.High ?? 0);
    set('summary-medium', host?.severityCounts?.Medium ?? 0);
    set('summary-low', host?.severityCounts?.Low ?? 0);
    set('summary-info', host?.severityCounts?.Informational ?? 0);
  }

  function renderHostHeader(root, host, hostKey, deviceRenames) {
    const container = root.querySelector('[data-role="hostHeader"]');
    if (!container) return;

    const label = host && hostsUtil?.formatHostLabel
      ? hostsUtil.formatHostLabel(host, deviceRenames)
      : (host?.displayName || hostKey || 'Unknown Host');

    const ip = host?.ip ? `<strong>IP:</strong> ${escapeHtml(host.ip)}` : '';
    const hn = host?.hostname ? `<strong>Hostname:</strong> ${escapeHtml(host.hostname)}` : '';

    const details = [ip, hn].filter(Boolean).join(' &nbsp; | &nbsp; ');

    container.innerHTML = `
      <div class="host-header">
        <div class="host-header-title">
          <h3>${escapeHtml(label)}</h3>
          <div class="host-header-links">
            <a href="../index.html">Back to Dashboard</a>
            &nbsp;|&nbsp;
            <a href="../reportsbyvuln/allvulns.html">Back to Vulnerability Report</a>
          </div>
        </div>
        <div class="host-header-meta">${details || '<em>No additional host metadata available.</em>'}</div>
      </div>
    `;

    // Let AppShell update the header title with the resolved host label.
    window.dispatchEvent(new CustomEvent('host:selected', { detail: { hostLabel: label } }));
  }

  function renderDeviceRow(entry, finding, opts) {
    const lookup = opts?.hostLookup;
    const renames = opts?.deviceRenames;

    const resolved = hostsUtil?.resolveHostFromEntry
      ? hostsUtil.resolveHostFromEntry(entry, lookup)
      : { hostKey: String(entry || ''), host: null, parsed: { key: String(entry || ''), ip: '', hostname: '', raw: String(entry || '') } };

    const hostKey = String(resolved.hostKey || '').trim() || String(entry || '');

    const hostObj = resolved.host || {
      key: hostKey,
      ip: resolved.parsed?.ip || '',
      hostname: resolved.parsed?.hostname || '',
      displayName: resolved.parsed?.raw || hostKey,
    };

    const label = hostsUtil?.formatHostLabel
      ? hostsUtil.formatHostLabel(hostObj, renames)
      : (hostObj.displayName || hostObj.key);

    const href = `../reportsbyhost/host.html?host=${encodeURIComponent(hostKey)}`;

    const isNewHost = Boolean(
      finding?.isNewIssue || (Array.isArray(finding?.newHosts) && finding.newHosts.includes(hostKey))
    );

    const badge = isNewHost ? '<span class="vuln-badge-device-new">NEW</span>' : '';

    return `<tr><td><a class="vuln-device-link" href="${href}">${escapeHtml(label)}</a>${badge}</td></tr>`;
  }

  function renderFindingBody(f, notesMap, opts) {
    const sections = opts?.sections || {};
    const noteVal = notesMap?.[f.issueKey]?.note ?? '';

    const metaRows = [
      ['Severity', escapeHtml(f.severity)],
      ['CVSS', escapeHtml(f.cvss || '—')],
      ['OID', escapeHtml(f.oid || '—')],
      ['CVE', escapeHtml(f.cve || '—')],
      ['Ports', escapeHtml(f.portsRaw || '—')],
      ['Last Detected', escapeHtml(f.lastDetected || '—')],
      ['Known Exploited', f.knownExploited === true ? 'Yes' : (f.knownExploited === false ? 'No' : 'Unknown')],
      ['Ransomware Flag', escapeHtml(f.ransomwareFlag || '—')],
      ['Affected Devices', `${f.affectedDevices?.length ?? 0}`],
    ];

    const devicesTable = (f.affectedDevices?.length)
      ? `
        <table class="vuln-devices">
          <thead><tr><th>Affected Device</th></tr></thead>
          <tbody>
            ${f.affectedDevices.map((d) => renderDeviceRow(d, f, opts)).join('')}
          </tbody>
        </table>
      `
      : '<p class="vuln-muted">No affected devices listed.</p>';

    function block(title, text) {
      if (!text) return '';
      return `
        <div class="vuln-block">
          <strong>${escapeHtml(title)}</strong><br /><br />
          <div class="vuln-pre">${escapeHtml(text).replace(/\n/g, '<br />')}</div>
        </div>
      `;
    }

    const metaSection = sections.meta !== false
      ? `
        <strong>Summary Information</strong><br /><br />
        <table class="vuln-meta">
          ${metaRows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${v}</td></tr>`).join('')}
        </table>
        <br />
      `
      : '';

    const blocks = [
      sections.summary !== false ? block('Summary', f.summary) : '',
      sections.detectionResult !== false ? block('Detection Result', f.detectionResult) : '',
      sections.impact !== false ? block('Impact', f.impact) : '',
      sections.solution !== false ? block('Solution', f.solution) : '',
      sections.insight !== false ? block('Vulnerability Insight', f.insight) : '',
      sections.detectionMethod !== false ? block('Detection Method', f.detectionMethod) : '',
      sections.references !== false ? block('References', f.references) : '',
    ].join('');

    const affectedSection = sections.affectedDevices !== false
      ? `
        <div class="vuln-block">
          <strong>Affected Devices</strong><br /><br />
          ${devicesTable}
        </div>
      `
      : '';

    const notesSection = sections.notes !== false
      ? `
        <div class="notes-panel">
          <strong>Remediation Notes</strong><br /><br />
          <textarea class="notes-textarea" data-role="note" data-issue-key="${escapeHtml(f.issueKey)}" placeholder="Add freeform remediation notes for this issue...">${escapeHtml(noteVal)}</textarea>
          <div class="notes-actions">
            <button type="button" class="notes-save-btn" data-action="note-save" data-issue-key="${escapeHtml(f.issueKey)}">Save</button>
            <span class="notes-status" data-role="note-status" data-issue-key="${escapeHtml(f.issueKey)}"></span>
          </div>
          <div class="notes-hint">Use the Dashboard to export updated notes/renames JSON.</div>
        </div>
      `
      : '';

    return `
      <div class="vuln-details">
        ${metaSection}
        ${blocks}
        ${affectedSection}
        ${notesSection}
      </div>
    `;
  }

  function renderFindings(root, findings, notesMap, filters, renderOpts, hostKey) {
    const container = root.querySelector('[data-role="hostAccordion"]');
    if (!container) return;

    if (!findings?.length) {
      container.innerHTML = '<p class="host-muted">No vulnerabilities available for this host.</p>';
      return;
    }

    const filtered = [];
    for (const f of findings) {
      if (passesFilters(f, filters, hostKey)) filtered.push(f);
    }

    if (!filtered.length) {
      container.innerHTML = '<p class="host-muted">No results match the selected filters.</p>';
      return;
    }

    const order = config.severities;

    const grouped = {};
    for (const sev of order) grouped[sev] = [];
    for (const f of filtered) {
      const sev = order.includes(f.severity) ? f.severity : 'Informational';
      grouped[sev].push(f);
    }

    const html = order.map((sev) => {
      const list = grouped[sev] || [];
      if (!list.length) return '';

      const sevHeader = `<div class="host-sev-header ${sevLabelClass(sev)}">${escapeHtml(sev)}</div>`;

      const items = list.map((f) => {
        const isNewHost = isNewForHost(f, hostKey);
        const newBadge = isNewHost ? '<span class="host-badge-new">NEW</span>' : '';
        const kevBadge = f.knownExploited === true ? '<span class="host-badge-kev" title="Known Exploited Vulnerability">KEV</span>' : '';
        const itemClass = isNewHost ? 'host-item host-item-new' : 'host-item';

        return `
          <div class="${itemClass}" data-issue-key="${escapeHtml(f.issueKey)}">
            <input class="toggle" type="checkbox" checked />
            <h6>
              <span class="arrow"></span>
              <span class="vulnlabel ${sevLabelClass(f.severity)}">${escapeHtml(String(f.severity || '').toUpperCase())}</span>
              &nbsp;${newBadge}${kevBadge}
              <span class="vulnname">${escapeHtml(f.issue)}</span>
            </h6>
            <div>
              ${renderFindingBody(f, notesMap, renderOpts)}
            </div>
          </div>
        `;
      }).join('');

      return `<div class="host-sev-group">${sevHeader}${items}</div>`;
    }).join('');

    container.innerHTML = html;
  }

  function factory(root, context) {
    const { logger } = context;

    let activeFilters = {
      q: '',
      qNorm: '',
      severities: config.severities.slice(),
      newOnly: false,
      exploitedOnly: false,
      sections: {
        meta: true,
        summary: true,
        detectionResult: true,
        impact: true,
        solution: true,
        insight: true,
        detectionMethod: true,
        references: true,
        affectedDevices: true,
        notes: true,
      },
    };

    function loadState() {
      return window.VulScanReport?.storage?.loadState?.();
    }

    function setNoteStatus(issueKey, text) {
      const el = findByDataset(root, '[data-role="note-status"]', 'issueKey', issueKey);
      if (el) el.textContent = String(text || '');
    }

    function findHost(state, hostKey) {
      const hosts = state?.hostIndex?.hosts || [];
      return hosts.find((h) => String(h.key) === String(hostKey)) || null;
    }

    function buildHostFindings(state, host) {
      if (!state?.current?.findings?.length || !host?.issueKeys?.length) return [];
      const set = new Set(host.issueKeys);
      return state.current.findings.filter((f) => set.has(f.issueKey));
    }

    function render() {
      const hostKey = getSelectedHostKey();
      const state = loadState();

      if (!state?.current?.findings?.length) {
        renderHostHeader(root, null, hostKey, {});
        renderSidebarCounts(root, null);
        renderFindings(root, [], {}, activeFilters, { sections: activeFilters.sections }, hostKey);
        return;
      }

      const host = findHost(state, hostKey);
      const deviceRenames = getDeviceRenames(state);

      renderHostHeader(root, host, hostKey, deviceRenames);
      renderSidebarCounts(root, host);

      const hostFindings = buildHostFindings(state, host);
      const notesMap = getNotesMap(state);

      const hosts = state?.hostIndex?.hosts || [];
      const hostLookup = hostsUtil?.buildHostLookup ? hostsUtil.buildHostLookup(hosts) : { byKey: {}, byIp: {}, byHostname: {} };

      const renderOpts = {
        sections: activeFilters.sections,
        hostLookup,
        deviceRenames,
      };

      renderFindings(root, hostFindings, notesMap, activeFilters, renderOpts, hostKey);
    }

    function onDataLoaded() { render(); }
    function onDataCleared() { render(); }

    function onNotesChanged(evt) {
      const reason = evt?.detail?.reason || '';

      if (reason === 'noteUpdated' && evt?.detail?.issueKey) {
        setNoteStatus(String(evt.detail.issueKey), 'Saved');
        return;
      }

      render();
    }

    function onFiltersChanged(evt) {
      const filters = evt?.detail?.filters || {};
      activeFilters = {
        q: filters.q || '',
        qNorm: normalizeQuery(filters.q),
        severities: Array.isArray(filters.severities) && filters.severities.length ? filters.severities : config.severities.slice(),
        newOnly: Boolean(filters.newOnly),
        exploitedOnly: Boolean(filters.exploitedOnly),
        sections: filters.sections && typeof filters.sections === 'object'
          ? {
            meta: filters.sections.meta !== false,
            summary: filters.sections.summary !== false,
            detectionResult: filters.sections.detectionResult !== false,
            impact: filters.sections.impact !== false,
            solution: filters.sections.solution !== false,
            insight: filters.sections.insight !== false,
            detectionMethod: filters.sections.detectionMethod !== false,
            references: filters.sections.references !== false,
            affectedDevices: filters.sections.affectedDevices !== false,
            notes: filters.sections.notes !== false,
          }
          : activeFilters.sections,
      };
      render();
    }

    window.addEventListener('data:loaded', onDataLoaded);
    window.addEventListener('data:cleared', onDataCleared);
    window.addEventListener('notes:changed', onNotesChanged);
    window.addEventListener('filters:changed', onFiltersChanged);

    // Mark note panels "Unsaved" locally while typing.
    on(root, 'input', 'textarea[data-role="note"]', (evt, el) => {
      const issueKey = String(el.getAttribute('data-issue-key') || '');
      if (!issueKey) return;
      setNoteStatus(issueKey, 'Unsaved');
    });

    // Save button (explicit save; no auto-save)
    on(root, 'click', 'button[data-action="note-save"]', (evt, btn) => {
      evt.preventDefault();
      const issueKey = String(btn.getAttribute('data-issue-key') || '');
      if (!issueKey) return;

      const textarea = findByDataset(root, 'textarea[data-role="note"]', 'issueKey', issueKey);
      const note = textarea ? textarea.value : '';

      setNoteStatus(issueKey, 'Saving...');

      window.dispatchEvent(new CustomEvent('notes:updated', {
        detail: { issueKey, note },
      }));
    });

    // Re-render when URL changes (hash navigation)
    function onHashChange() { render(); }
    window.addEventListener('hashchange', onHashChange);

    render();

    logger?.info('HostReport rendered');

    return {
      destroy() {
        window.removeEventListener('data:loaded', onDataLoaded);
        window.removeEventListener('data:cleared', onDataCleared);
        window.removeEventListener('notes:changed', onNotesChanged);
        window.removeEventListener('filters:changed', onFiltersChanged);
        window.removeEventListener('hashchange', onHashChange);
      },
    };
  }

  window.ComponentRegistry.register('HostReport', factory);
})();
