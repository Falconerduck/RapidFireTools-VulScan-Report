/*
  DeviceRenames.js
  UI for assigning friendly names to devices/hosts.

  Storage:
    - Saved into the same JSON doc as remediation notes (notesDoc.deviceRenames)

  Listens:
    - data:loaded
    - data:cleared
    - notes:changed

  Emits:
    - deviceRenames:updated { hostKey, alias }
    - notes:exportRequested
*/
(function () {
  'use strict';

  const hostsUtil = window.VulScanReport?.utils?.hosts;
  const { escapeHtml, on, findByDataset } = window.VulScanReport?.utils || {};

  function loadState() {
    return window.VulScanReport?.storage?.loadState?.();
  }

  function getDeviceRenames(state) {
    return state?.notesDoc?.deviceRenames || {};
  }

  function normalizeQuery(q) {
    return String(q || '').trim().toLowerCase();
  }

  function buildRows(hosts, renames, qNorm, sortState) {
    const list = Array.isArray(hosts) ? hosts : [];

    const filtered = !qNorm
      ? list
      : list.filter((h) => {
        const label = hostsUtil?.formatHostLabel ? hostsUtil.formatHostLabel(h, renames) : (h.displayName || h.key);
        const hay = [h.key, h.ip, h.hostname, label, renames?.[h.key]].join(' ').toLowerCase();
        return hay.includes(qNorm);
      });

    if (!filtered.length) {
      return '<tr><td colspan="4"><em>No hosts match your search.</em></td></tr>';
    }

    const rows = filtered.map((h, idx) => {
      const savedAlias = String(renames?.[h.key] || '').trim();
      const label = hostsUtil?.formatHostLabel ? hostsUtil.formatHostLabel(h, renames) : (h.displayName || h.key);

      return {
        idx,
        host: h,
        key: String(h.key || ''),
        ip: String(h.ip || ''),
        display: String(label || ''),
        alias: String(savedAlias || ''),
        savedAlias,
        label,
      };
    });

    if (sortState?.key) {
      const dir = sortState.dir === 'desc' ? -1 : 1;
      const key = String(sortState.key);

      rows.sort((a, b) => {
        const cmp = (x, y) => String(x || '').localeCompare(String(y || ''));
        if (key === 'key') return dir * (cmp(a.key, b.key) || (a.idx - b.idx));
        if (key === 'ip') return dir * (cmp(a.ip, b.ip) || cmp(a.key, b.key));
        if (key === 'display') return dir * (cmp(a.display, b.display) || cmp(a.key, b.key));
        if (key === 'alias') return dir * (cmp(a.alias, b.alias) || cmp(a.key, b.key));
        return a.idx - b.idx;
      });
    }

    return rows.map((r) => {
      const h = r.host;
      return `
        <tr>
          <td>${escapeHtml(h.ip || '—')}</td>
          <td>${escapeHtml(r.label)}</td>
          <td>
            <input class="rename-input" type="text" data-role="alias" data-host-key="${escapeHtml(h.key)}" value="${escapeHtml(r.savedAlias)}" placeholder="Enter Hostname Alias" />
            <div class="rename-hint">Saved as: <strong>${escapeHtml(r.savedAlias || '—')}</strong></div>
          </td>
          <td style="white-space:nowrap;">
            <button type="button" class="rename-btn" data-action="save" data-host-key="${escapeHtml(h.key)}">Save</button>
            <button type="button" class="rename-btn rename-btn-secondary" data-action="clear" data-host-key="${escapeHtml(h.key)}">Clear</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function factory(root, context) {
    const { logger } = context;

    let qNorm = '';
    let sortState = { key: 'ip', dir: 'asc' };

    function sortGlyph(key) {
      if (!sortState || sortState.key !== key) return '';
      return sortState.dir === 'desc' ? ' ▼' : ' ▲';
    }

    function render() {
      const state = loadState();
      const hosts = state?.hostIndex?.hosts || [];
      const renames = getDeviceRenames(state);

      if (!state?.current?.findings?.length) {
        root.innerHTML = `
          <div class="rename-banner">No scan data loaded. Go to the <a href="index.html">Dashboard</a> to import your VulScan CSV exports.</div>
        `;
        return;
      }

      root.innerHTML = `
        <div class="rename-card noPrint">
          <h3>Device Names</h3>
          <p class="rename-help">
            Assign friendly device names for report display. Renames are display-only and will appear as
            <strong>"&lt;Hostname&gt; (IP)"</strong> throughout the report.
          </p>

          <div class="rename-block">
            <label class="rename-label" for="rename-search">Search</label>
            <input id="rename-search" class="rename-search" type="text" placeholder="Search by IP or Hostname" data-role="search" />
          </div>

          <div class="rename-actions">
            <button type="button" class="rename-btn" data-action="export">Export Device Data JSON</button>
            <span class="rename-status" data-role="status"></span>
          </div>

          <table class="rename-table">
            <thead>
              <tr>
                <th data-sort="ip">IP${sortGlyph('ip')}</th>
                <th data-sort="display">Current Device Display${sortGlyph('display')}</th>
                <th data-sort="alias">Hostname${sortGlyph('alias')}</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody data-role="rows">
              ${buildRows(hosts, renames, qNorm, sortState)}
            </tbody>
          </table>
        </div>
      `;

      const search = root.querySelector('[data-role="search"]');
      if (search) search.value = qNorm ? qNorm : '';

      // Update AppShell title if present.
      window.dispatchEvent(new CustomEvent('host:selected', { detail: { hostLabel: 'Device Names' } }));
    }

    function setStatus(text) {
      const el = root.querySelector('[data-role="status"]');
      if (el) el.textContent = String(text || '');
    }

    function refreshRows() {
      const state = loadState();
      const hosts = state?.hostIndex?.hosts || [];
      const renames = getDeviceRenames(state);

      const tbody = root.querySelector('[data-role="rows"]');
      if (!tbody) return;

      tbody.innerHTML = buildRows(hosts, renames, qNorm, sortState);
    }

    function onDataLoaded() {
      render();
    }

    function onDataCleared() {
      render();
    }

    function onNotesChanged(evt) {
      const reason = evt?.detail?.reason || '';
      if (reason === 'deviceRenames' || reason === 'import' || reason === 'dataLoaded') {
        refreshRows();
      }
    }

    window.addEventListener('data:loaded', onDataLoaded);
    window.addEventListener('data:cleared', onDataCleared);
    window.addEventListener('notes:changed', onNotesChanged);

    // Search
    on(root, 'input', 'input[data-role="search"]', (evt, el) => {
      qNorm = normalizeQuery(el.value);
      refreshRows();
    });

    // Sort
    on(root, 'click', 'th[data-sort]', (evt, th) => {
      evt.preventDefault();
      const key = String(th.getAttribute('data-sort') || '');
      if (!key) return;

      if (sortState.key === key) sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
      else {
        sortState.key = key;
        sortState.dir = 'asc';
      }

      render();
    });


    // Save / clear buttons
    on(root, 'click', 'button[data-action="save"]', (evt, btn) => {
      evt.preventDefault();
      const hostKey = String(btn.getAttribute('data-host-key') || '');
      if (!hostKey) return;

      const input = findByDataset(root, 'input[data-role="alias"]', 'hostKey', hostKey);
      const alias = input ? String(input.value || '').trim() : '';

      window.dispatchEvent(new CustomEvent('deviceRenames:updated', {
        detail: { hostKey, alias },
      }));

      setStatus(`Saved alias for ${hostKey}`);
      refreshRows();
    });

    on(root, 'click', 'button[data-action="clear"]', (evt, btn) => {
      evt.preventDefault();
      const hostKey = String(btn.getAttribute('data-host-key') || '');
      if (!hostKey) return;

      const input = findByDataset(root, 'input[data-role="alias"]', 'hostKey', hostKey);
      if (input) input.value = '';

      window.dispatchEvent(new CustomEvent('deviceRenames:updated', {
        detail: { hostKey, alias: '' },
      }));

      setStatus(`Cleared alias for ${hostKey}`);
      refreshRows();
    });

    // Export
    on(root, 'click', 'button[data-action="export"]', (evt) => {
      evt.preventDefault();
      window.dispatchEvent(new CustomEvent('notes:exportRequested'));
      setStatus('Export requested (download will start).');
    });

    render();

    logger?.info('DeviceRenames rendered');

    return {
      destroy() {
        window.removeEventListener('data:loaded', onDataLoaded);
        window.removeEventListener('data:cleared', onDataCleared);
        window.removeEventListener('notes:changed', onNotesChanged);
      },
    };
  }

  window.ComponentRegistry.register('DeviceRenames', factory);
})();
