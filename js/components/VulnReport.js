/*
  VulnReport.js
  Renders the All Vulnerabilities report (grouped by severity).

  Listens:
    - data:loaded
    - data:cleared
    - notes:changed
    - filters:changed

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

  function passesFilters(finding, filters) {
    if (!finding) return false;
    if (filters?.severities?.length && !filters.severities.includes(finding.severity)) return false;
    if (filters?.newOnly && !finding.isNew) return false;
    if (filters?.exploitedOnly && finding.knownExploited !== true) return false;
    if (!matchesQuery(finding, filters?.qNorm)) return false;
    return true;
  }

  function renderSidebarCounts(root, stats) {
    const set = (role, val) => {
      const el = root.querySelector(`[data-role="${role}"]`);
      if (el) el.textContent = String(val);
    };

    set('summary-totalHosts', stats?.totalHosts ?? 0);
    set('summary-totalFindings', stats?.totalFindings ?? 0);
    set('summary-newFindings', stats?.newFindings ?? 0);

    set('summary-critical', stats?.severityCounts?.Critical ?? 0);
    set('summary-high', stats?.severityCounts?.High ?? 0);
    set('summary-medium', stats?.severityCounts?.Medium ?? 0);
    set('summary-low', stats?.severityCounts?.Low ?? 0);
    set('summary-info', stats?.severityCounts?.Informational ?? 0);
  }

  function getNotesMap(state) {
    return state?.notesDoc?.notes || {};
  }

  function getDeviceRenames(state) {
    return state?.notesDoc?.deviceRenames || {};
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

  function renderFindings(root, findings, notesMap, filters, renderOpts) {
    const container = root.querySelector('[data-role="vulnAccordion"]');
    if (!container) return;

    if (!findings?.length) {
      container.innerHTML = '<p class="vuln-muted">No vulnerabilities available.</p>';
      return;
    }

    const filtered = [];
    for (const f of findings) {
      if (passesFilters(f, filters)) filtered.push(f);
    }

    if (!filtered.length) {
      container.innerHTML = '<p class="vuln-muted">No results match the selected filters.</p>';
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

      const sevHeader = `<div class="vuln-sev-header ${sevLabelClass(sev)}">${escapeHtml(sev)}</div>`;

      const items = list.map((f) => {
        const newBadge = f.isNew ? '<span class="vuln-badge-new">NEW</span>' : '';
        const kevBadge = f.knownExploited === true ? '<span class="vuln-badge-kev" title="Known Exploited Vulnerability">KEV</span>' : '';
        const itemClass = f.isNew ? 'vuln-item vuln-item-new' : 'vuln-item';

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

      return `<div class="vuln-sev-group">${sevHeader}${items}</div>`;
    }).join('');

    container.innerHTML = html;
  }

  function renderStatus(root, state) {
    const statusEl = root.querySelector('[data-role="dataStatus"]');
    if (!statusEl) return;

    if (state?.current?.findings?.length) {
      statusEl.innerHTML = '';
      return;
    }

    statusEl.innerHTML = '<div class="vuln-banner">No scan data loaded. Go to the <a href="../index.html">Dashboard</a> to import your VulScan CSV exports.</div>';
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

    function render() {
      const state = loadState();
      renderStatus(root, state);
      renderSidebarCounts(root, state?.current?.stats);

      const findings = state?.current?.findings || [];
      const notesMap = getNotesMap(state);

      const hosts = state?.hostIndex?.hosts || [];
      const hostLookup = hostsUtil?.buildHostLookup ? hostsUtil.buildHostLookup(hosts) : { byKey: {}, byIp: {}, byHostname: {} };
      const deviceRenames = getDeviceRenames(state);

      const renderOpts = {
        sections: activeFilters.sections,
        hostLookup,
        deviceRenames,
      };

      renderFindings(root, findings, notesMap, activeFilters, renderOpts);
    }

    function onDataLoaded() { render(); }
    function onDataCleared() { render(); }

    function onNotesChanged(evt) {
      const reason = evt?.detail?.reason || '';

      // For single note updates, avoid a full re-render to prevent disrupting the page.
      if (reason === 'noteUpdated' && evt?.detail?.issueKey) {
        setNoteStatus(String(evt.detail.issueKey), 'Saved');
        return;
      }

      // Import/dataLoaded/deviceRenames: full render.
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

    render();

    logger?.info('VulnReport rendered');

    return {
      destroy() {
        window.removeEventListener('data:loaded', onDataLoaded);
        window.removeEventListener('data:cleared', onDataCleared);
        window.removeEventListener('notes:changed', onNotesChanged);
        window.removeEventListener('filters:changed', onFiltersChanged);
      },
    };
  }

  window.ComponentRegistry.register('VulnReport', factory);
})();
