/*
  RemediationReport.js
  Client-specific remediation workflow + long-term log.

  UI:
    - View toggle: By Vulnerability | By Device
    - Sections: Needs Review (reviewQueue) + Mitigations Log (log)
    - Bulk apply in Needs Review

  Persistence:
    - Stored inside notesDoc.remediation in sessionStorage via NotesStore export/import.
*/
(function () {
  'use strict';

  const { escapeHtml, on: onEvent } = window.VulScanReport?.utils || {};
  const createEmptyNotesDoc = window.VulScanReport?.parsers?.createEmptyNotesDoc;

  const REASONS = [
    'Mitigated',
    'Accepted Risk',
    'False Positive',
    'Removed Device',
    'Other',
  ];

  function nowIso() {
    return new Date().toISOString();
  }

  function formatLocalDateTime(iso) {
    if (!iso) return '';
    const d = iso instanceof Date ? iso : new Date(iso);
    if (!(d instanceof Date) || isNaN(d.getTime())) return String(iso);

    const pad2 = (n) => String(n).padStart(2, '0');
    const mm = pad2(d.getMonth() + 1);
    const dd = pad2(d.getDate());
    const yyyy = d.getFullYear();

    let h = d.getHours();
    const ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12;
    if (h === 0) h = 12;
    const min = pad2(d.getMinutes());
    const sec = pad2(d.getSeconds());
    return `${mm}/${dd}/${yyyy} ${h}:${min}:${sec} ${ampm}`;
  }

  function snippet(text, maxLen) {
    const s = String(text == null ? '' : text).trim();
    if (!s) return '';
    const n = typeof maxLen === 'number' ? maxLen : 120;
    if (s.length <= n) return s;
    return `${s.slice(0, n).trim()}…`;
  }

  function csvEscape(value) {
    const s = String(value == null ? '' : value);
    if (/[",\n\r]/.test(s)) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  }

  function downloadText(filename, text, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }


  function autoGrowTextarea(el) {
    if (!(el instanceof HTMLTextAreaElement)) return;
    // Grow to fit content; do not shrink if user manually expanded.
    const prev = el.offsetHeight || 0;
    el.style.height = 'auto';
    const next = el.scrollHeight || 0;
    const target = Math.max(prev, next, 60);
    el.style.height = target + 'px';
  }

  function loadState() {
    return window.VulScanReport?.storage?.loadState?.();
  }

  function saveState(state) {
    return window.VulScanReport?.storage?.saveState?.(state);
  }

  function getNotesDoc(state) {
    if (state?.notesDoc) return state.notesDoc;
    return typeof createEmptyNotesDoc === 'function' ? createEmptyNotesDoc() : { schemaVersion: 2, notes: {}, deviceRenames: {} };
  }

  function ensureRemediation(doc) {
    if (!doc || typeof doc !== 'object') return;
    if (!doc.remediation || typeof doc.remediation !== 'object') {
      doc.remediation = {
        schemaVersion: 1,
        known: { hosts: {}, vulns: {}, combos: {} },
        reviewQueue: {},
        log: {},
      };
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

  function viewToKind(view) {
    if (view === 'host') return 'host';
    return 'vuln';
  }

  function buildReasonOptions(selected) {
    const sel = String(selected || '');
    const opts = ['<option value="">All Reasons</option>'];
    for (const r of REASONS) {
      const s = r === sel ? ' selected' : '';
      opts.push(`<option value="${escapeHtml(r)}"${s}>${escapeHtml(r)}</option>`);
    }
    return opts.join('');
  }

  function buildReasonDropdown(selected, includeBlankLabel) {
    const sel = String(selected || '');
    const blank = includeBlankLabel ? `<option value="">${escapeHtml(includeBlankLabel)}</option>` : '<option value=""></option>';
    const opts = [blank];
    for (const r of REASONS) {
      const s = r === sel ? ' selected' : '';
      opts.push(`<option value="${escapeHtml(r)}"${s}>${escapeHtml(r)}</option>`);
    }
    return opts.join('');
  }

  function makeRowKeyBlock(item) {
    const title = escapeHtml(item.title || '');
    if (item.kind === 'combo') {
      const hk = escapeHtml(item.hostKey || '');
      const ik = escapeHtml(item.issueKey || '');
      return `
        <div class="rem-key-title">${title}</div>
        <div class="rem-key-sub">${hk}${hk && ik ? ' :: ' : ''}${ik}</div>
      `;
    }

    if (item.kind === 'host') {
      const hk = escapeHtml(item.hostKey || '');
      return `
        <div class="rem-key-title">${title}</div>
        <div class="rem-key-sub">${hk}</div>
      `;
    }

    // For vulnerability rows, show only the human-readable title.
    // (Issue keys can be long/noisy and were previously confusing in the UI.)
    const ik = escapeHtml(item.issueKey || '');
    const tip = ik ? ` title="${ik}"` : '';
    return `<div class="rem-key-title"${tip}>${title}</div>`;
  }

  function sortRows(rows, sortKey, sortDir) {
    const dir = sortDir === 'desc' ? -1 : 1;
    const key = String(sortKey || '');
    const list = Array.isArray(rows) ? rows.slice() : [];

    function asTime(v) {
      if (!v) return 0;
      const t = new Date(v).getTime();
      return Number.isFinite(t) ? t : 0;
    }

    list.sort((a, b) => {
      if (key === 'title') return dir * String(a.title || '').localeCompare(String(b.title || ''));
      if (key === 'firstSeenAt') return dir * (asTime(a.firstSeenAt) - asTime(b.firstSeenAt));
      if (key === 'lastSeenAt') return dir * (asTime(a.lastSeenAt) - asTime(b.lastSeenAt));
      if (key === 'resolvedAt') return dir * (asTime(a.resolvedAt) - asTime(b.resolvedAt));
      if (key === 'reason') return dir * String(a.reason || '').localeCompare(String(b.reason || ''));
      return dir * String(a.title || '').localeCompare(String(b.title || ''));
    });

    return list;
  }

  function filterRows(rows, { searchText, reason }) {
    const q = String(searchText || '').trim().toLowerCase();
    const reasonFilter = String(reason || '');

    return (rows || []).filter((r) => {
      if (reasonFilter && String(r.reason || '') !== reasonFilter) return false;
      if (!q) return true;

      const hay = [
        r.title,
        r.hostKey,
        r.issueKey,
        r.comboKey,
        r.relatedText,
      ].map((s) => String(s || '').toLowerCase());

      return hay.some((s) => s.includes(q));
    });
  }

  function parseTime(iso) {
    if (!iso) return 0;
    const t = new Date(iso).getTime();
    return Number.isFinite(t) ? t : 0;
  }

  function buildComboIndex(rem) {
    const byIssue = new Map();
    const byHost = new Map();

    const combos = rem?.known?.combos && typeof rem.known.combos === 'object' ? rem.known.combos : {};
    const knownHosts = rem?.known?.hosts && typeof rem.known.hosts === 'object' ? rem.known.hosts : {};
    const knownVulns = rem?.known?.vulns && typeof rem.known.vulns === 'object' ? rem.known.vulns : {};

    for (const c of Object.values(combos)) {
      if (!c) continue;
      const hk = String(c.hostKey || '').trim();
      const ik = String(c.issueKey || '').trim();
      if (!hk || !ik) continue;
      const ts = String(c.lastSeenAt || '').trim();
      const hostTitle = String(c.hostTitle || knownHosts[hk]?.title || hk);
      const vulnTitle = String(c.vulnTitle || knownVulns[ik]?.title || ik);

      if (!byIssue.has(ik)) byIssue.set(ik, new Map());
      const issueMap = byIssue.get(ik);
      if (!issueMap.has(ts)) issueMap.set(ts, new Map());
      issueMap.get(ts).set(hk, hostTitle);

      if (!byHost.has(hk)) byHost.set(hk, new Map());
      const hostMap = byHost.get(hk);
      if (!hostMap.has(ts)) hostMap.set(ts, new Map());
      hostMap.get(ts).set(ik, vulnTitle);
    }

    return { byIssue, byHost };
  }

  function pickTimeBucket(timeMap, preferredIso) {
    if (!timeMap || !(timeMap instanceof Map) || !timeMap.size) return null;
    const preferred = String(preferredIso || '').trim();
    if (preferred && timeMap.has(preferred)) return preferred;

    // Pick the latest bucket by timestamp.
    let best = '';
    let bestT = -1;
    for (const k of timeMap.keys()) {
      const t = parseTime(k);
      if (t > bestT) {
        bestT = t;
        best = k;
      }
    }
    return best || null;
  }

  function relatedForIssue(index, issueKey, preferredLastSeenAt) {
    if (!index?.byIssue) return [];
    const ik = String(issueKey || '').trim();
    if (!ik) return [];
    const timeMap = index.byIssue.get(ik);
    const bucket = pickTimeBucket(timeMap, preferredLastSeenAt);
    if (!bucket) return [];
    const items = timeMap.get(bucket);
    return Array.from(items.values()).sort((a, b) => String(a).localeCompare(String(b)));
  }

  function relatedForHost(index, hostKey, preferredLastSeenAt) {
    if (!index?.byHost) return [];
    const hk = String(hostKey || '').trim();
    if (!hk) return [];
    const timeMap = index.byHost.get(hk);
    const bucket = pickTimeBucket(timeMap, preferredLastSeenAt);
    if (!bucket) return [];
    const items = timeMap.get(bucket);
    return Array.from(items.values()).sort((a, b) => String(a).localeCompare(String(b)));
  }

  function renderPills(list) {
    const items = Array.isArray(list) ? list : [];
    if (!items.length) return '<span class="rem-muted">—</span>';

    const max = 6;
    const shown = items.slice(0, max);
    const more = items.length - shown.length;
    const pills = shown.map((t) => `<span class="rem-pill">${escapeHtml(t)}</span>`).join('');
    const moreHtml = more > 0 ? `<span class="rem-pill rem-pill-more">+${more} more</span>` : '';
    return `<div class="rem-pills">${pills}${moreHtml}</div>`;
  }

  function renderTable({
    section,
    rows,
    kind,
    mode,
    relatedLabel,
    sortKey,
    sortDir,
    selected,
    editingKey,
  }) {
    const showSelection = section === 'queue';
    const showLastSeen = section === 'queue';
    const showFirstSeen = false;
    const showResolvedAt = section === 'log';

    const headers = [];
    if (showSelection) headers.push('<th class="rem-nosort rem-col-select" data-sort="">&nbsp;</th>');
    headers.push(`<th class="rem-col-key" data-sort="title">Key / Name</th>`);
    headers.push(`<th class="rem-nosort rem-col-related" data-sort="">${escapeHtml(relatedLabel || '')}</th>`);
    if (showLastSeen) headers.push('<th class="rem-col-lastseen" data-sort="lastSeenAt">Last Seen At</th>');
    if (showResolvedAt) headers.push('<th class="rem-col-resolved" data-sort="resolvedAt">Resolved At</th>');
    headers.push('<th class="rem-col-reason" data-sort="reason">Reason</th>');
    headers.push('<th class="rem-nosort rem-col-notes" data-sort="">Notes</th>');
    headers.push('<th class="rem-nosort rem-col-actions" data-sort="">Actions</th>');

    const body = [];

    const emptyMsg = section === 'queue'
      ? 'No items currently need review for this view.'
      : 'No mitigation log entries for this view.';

    if (!rows.length) {
      body.push(`<tr><td colspan="${headers.length}"><div class="rem-empty">${escapeHtml(emptyMsg)}</div></td></tr>`);
    } else {
      for (const r of rows) {
        const key = section === 'queue' ? r.reviewKey : r.logKey;
        const isEditing = key && editingKey === key;
        const isChecked = selected && selected.has(key);

        const cells = [];

        if (showSelection) {
          const ck = isChecked ? ' checked' : '';
          cells.push(`<td class="rem-col-select"><input type="checkbox" data-role="rowSelect" data-key="${escapeHtml(key)}"${ck} /></td>`);
        }

        cells.push(`<td class="rem-col-key">${makeRowKeyBlock(r)}</td>`);

        // Related list (inverse view)
        cells.push(`<td class="rem-col-related">${renderPills(r.related || [])}</td>`);

        if (showLastSeen) cells.push(`<td class="rem-col-lastseen">${escapeHtml(formatLocalDateTime(r.lastSeenAt))}</td>`);
        if (showResolvedAt) cells.push(`<td class="rem-col-resolved">${escapeHtml(formatLocalDateTime(r.resolvedAt))}</td>`);

        if (!isEditing) {
          cells.push(`<td class="rem-col-reason">${escapeHtml(r.reason || '')}</td>`);
          cells.push(`<td class="rem-col-notes rem-snippet">${escapeHtml(snippet(r.notes, 140))}</td>`);
          cells.push(`
            <td class="rem-col-actions rem-row-actions">
              <button class="rem-link" data-action="edit" data-key="${escapeHtml(key)}">Edit</button>
            </td>
          `);
        } else {
          const reasonHtml = `
            <select class="rem-select" data-role="editReason">${buildReasonDropdown(r.reason, 'Select...')}</select>
          `;
          const notesHtml = `
            <textarea class="rem-textarea" data-role="editNotes">${escapeHtml(r.notes || '')}</textarea>
          `;
          cells.push(`<td class="rem-col-reason">${reasonHtml}</td>`);
          cells.push(`<td class="rem-col-notes">${notesHtml}</td>`);
          cells.push(`
            <td class="rem-col-actions rem-row-actions">
              <button data-action="save" data-key="${escapeHtml(key)}" data-section="${escapeHtml(section)}">Save</button>
              <button data-action="cancelEdit" data-key="${escapeHtml(key)}">Cancel</button>
            </td>
          `);
        }

        body.push(`<tr data-kind="${escapeHtml(kind)}" data-key="${escapeHtml(key)}">${cells.join('')}</tr>`);
      }
    }

    const sortGlyph = (k) => {
      if (k !== sortKey) return '';
      return sortDir === 'desc' ? ' ▼' : ' ▲';
    };

    const headHtml = headers.join('').replace(/data-sort="(.*?)">(.*?)<\/th>/g, (m, sk, label) => {
      if (!sk) return m;
      return `data-sort="${sk}">${label}${sortGlyph(sk)}</th>`;
    });

    return `
      <table class="rem-table" data-role="${escapeHtml(section)}Table" data-section="${escapeHtml(section)}">
        <thead><tr>${headHtml}</tr></thead>
        <tbody>${body.join('')}</tbody>
      </table>
    `;
  }

  function factory(root, context) {
    const { config, logger } = context;

    const state = {
      view: 'vuln',
      searchText: '',
      reasonFilter: '',
      sort: {
        queue: { key: 'lastSeenAt', dir: 'desc' },
        log: { key: 'resolvedAt', dir: 'desc' },
      },
      selected: new Set(),
      editingKey: '',
      bulkReason: '',
      bulkNotes: '',
      status: '',
    };

    function setStatus(msg) {
      state.status = String(msg || '');
      const el = root.querySelector('[data-role="status"]');
      if (el) el.textContent = state.status;
    }

    function getDataForView(doc) {
      ensureRemediation(doc);
      const kind = viewToKind(state.view);
      const rem = doc.remediation;

      const comboIndex = buildComboIndex(rem);

      const queue = [];
      for (const [reviewKey, v] of Object.entries(rem.reviewQueue || {})) {
        if (!v || v.kind !== kind) continue;
        const related = (kind === 'vuln')
          ? relatedForIssue(comboIndex, v.issueKey, v.lastSeenAt)
          : relatedForHost(comboIndex, v.hostKey, v.lastSeenAt);
        queue.push({ reviewKey, ...v, related, relatedText: related.join(' ') });
      }

      const logRows = [];
      for (const [logKey, v] of Object.entries(rem.log || {})) {
        if (!v || v.kind !== kind) continue;
        const related = (kind === 'vuln')
          ? relatedForIssue(comboIndex, v.issueKey, '')
          : relatedForHost(comboIndex, v.hostKey, '');
        logRows.push({ logKey, ...v, related, relatedText: related.join(' ') });
      }

      return { kind, queue, logRows };
    }

    function render() {
      // Guard against stale/invalid view values from older builds.
      if (state.view !== 'vuln' && state.view !== 'host') state.view = 'vuln';

      const st = loadState();
      const hasScan = !!(st?.current?.findings?.length);
      const doc = getNotesDoc(st || {});
      ensureRemediation(doc);

      const { kind, queue, logRows } = getDataForView(doc);

      const filteredQueue = filterRows(queue, { searchText: state.searchText, reason: state.reasonFilter });
      const filteredLog = filterRows(logRows, { searchText: state.searchText, reason: state.reasonFilter });

      // Keep selection only for keys still visible.
      const visibleKeys = new Set(filteredQueue.map((r) => r.reviewKey));
      for (const k of Array.from(state.selected)) {
        if (!visibleKeys.has(k)) state.selected.delete(k);
      }

      const sortedQueue = sortRows(filteredQueue, state.sort.queue.key, state.sort.queue.dir);
      const sortedLog = sortRows(filteredLog, state.sort.log.key, state.sort.log.dir);

      const viewBtn = (v, label) => {
        const cls = v === state.view ? 'rem-view-btn rem-active' : 'rem-view-btn';
        return `<button class="${cls}" data-action="setView" data-view="${escapeHtml(v)}">${escapeHtml(label)}</button>`;
      };

      const scanHint = hasScan
        ? ''
        : `<div class="rem-empty" style="margin-top: 10px;">No scan data loaded yet. Import your CSV exports on the Dashboard to begin tracking remediation.</div>`;

      root.innerHTML = `
        <div class="rem-toolbar noPrint">
          <div class="rem-toolbar-row">
            <div class="rem-view-toggle" role="tablist" aria-label="View">
              ${viewBtn('vuln', 'By Vulnerability')}
              ${viewBtn('host', 'By Device')}
            </div>

            <input class="rem-input" type="text" placeholder="Search..." value="${escapeHtml(state.searchText)}" data-role="search" />

            <select class="rem-select" data-role="reasonFilter">${buildReasonOptions(state.reasonFilter)}</select>

            <div class="rem-actions" style="margin-left:auto;">
              <button class="rem-btn rem-btn-primary" data-action="exportClientJson">Export Client Data JSON</button>
              <button class="rem-btn" data-action="exportReviewCsv">Export Review CSV</button>
              <button class="rem-btn" data-action="exportLogCsv">Export Log CSV</button>
            </div>
          </div>
          <div class="rem-status" data-role="status">${escapeHtml(state.status || '')}</div>
        </div>

        ${scanHint}

        <div class="rem-section">
          <h3>Needs Review</h3>

          <div class="rem-bulk noPrint">
            <div class="rem-bulk-grid">
              <div>
                <label class="rem-muted" style="display:block; font-weight:700; margin-bottom:4px;">Bulk Reason (required)</label>
                <select class="rem-select" data-role="bulkReason">
                  ${buildReasonDropdown(state.bulkReason, 'Select...')}
                </select>
              </div>
              <div>
                <label class="rem-muted" style="display:block; font-weight:700; margin-bottom:4px;">Bulk Notes (required)</label>
                <textarea class="rem-textarea" data-role="bulkNotes" placeholder="Notes to apply to selected rows...">${escapeHtml(state.bulkNotes || '')}</textarea>
              </div>
              <div>
                <label class="rem-muted" style="display:block; font-weight:700; margin-bottom:4px;">&nbsp;</label>
                <button class="rem-btn rem-btn-primary" data-action="applyBulk">Apply to Selected</button>
                <div class="rem-muted" style="margin-top:6px;">Selected: <span data-role="selectedCount">${state.selected.size}</span></div>
              </div>
            </div>
          </div>

          <div class="noPrint" style="margin: 6px 0 10px 0;">
            <label style="display:inline-flex; align-items:center; gap:8px;">
              <input type="checkbox" data-role="selectAllFiltered" ${state.selected.size && state.selected.size === sortedQueue.length ? 'checked' : ''} />
              <span>Select all (filtered)</span>
            </label>
          </div>

          ${renderTable({
            section: 'queue',
            rows: sortedQueue,
            kind,
            mode: state.view,
            relatedLabel: state.view === 'host' ? 'Vulnerabilities' : 'Devices',
            sortKey: state.sort.queue.key,
            sortDir: state.sort.queue.dir,
            selected: state.selected,
            editingKey: state.editingKey,
          })}
        </div>

        <div class="rem-section">
          <h3>Mitigations Log</h3>
          ${renderTable({
            section: 'log',
            rows: sortedLog,
            kind,
            mode: state.view,
            relatedLabel: state.view === 'host' ? 'Vulnerabilities' : 'Devices',
            sortKey: state.sort.log.key,
            sortDir: state.sort.log.dir,
            selected: null,
            editingKey: state.editingKey,
          })}
        </div>
      `;

      // Auto-grow textareas to fit content (bulk + edit)
      root.querySelectorAll('textarea.rem-textarea').forEach(autoGrowTextarea);

      const countEl = root.querySelector('[data-role="selectedCount"]');
      if (countEl) countEl.textContent = String(state.selected.size);
      setStatus(state.status);
    }

    function persistDoc(doc) {
      const st = loadState() || {};
      st.notesDoc = doc;
      saveState(st);
    }

    function applyBulkToSelected() {
      if (!state.selected.size) {
        setStatus('No rows selected.');
        return;
      }

      const reason = String(root.querySelector('[data-role="bulkReason"]')?.value || '').trim();
      const notes = String(root.querySelector('[data-role="bulkNotes"]')?.value || '').trim();
      if (!reason || !notes) {
        setStatus('Bulk Reason and Notes are required.');
        return;
      }

      const st = loadState();
      if (!st) {
        setStatus('No data available yet. Import your scan first.');
        return;
      }

      const doc = getNotesDoc(st);
      ensureRemediation(doc);
      const rem = doc.remediation;

      const ts = nowIso();
      let moved = 0;

      for (const key of Array.from(state.selected)) {
        const entry = rem.reviewQueue[key];
        if (!entry) continue;

        const resolved = {
          kind: entry.kind,
          hostKey: entry.hostKey,
          issueKey: entry.issueKey,
          comboKey: entry.comboKey,
          title: entry.title,
          resolvedAt: ts,
          reason,
          notes,
          updatedAt: ts,
        };

        delete rem.reviewQueue[key];
        rem.log[key] = resolved;
        moved += 1;
      }

      doc.updatedAt = ts;
      persistDoc(doc);

      state.selected.clear();
      state.bulkReason = '';
      state.bulkNotes = '';
      state.editingKey = '';

      setStatus(`Applied to ${moved} row(s).`);
      window.dispatchEvent(new CustomEvent('notes:changed', { detail: { reason: 'remediationUpdated' } }));
      render();
    }

    function saveEdit(section, key, rowEl) {
      if (!key) return;
      const reason = String(rowEl.querySelector('[data-role="editReason"]')?.value || '').trim();
      const notes = String(rowEl.querySelector('[data-role="editNotes"]')?.value || '').trim();
      const ts = nowIso();

      const st = loadState();
      if (!st) {
        setStatus('No data available yet. Import your scan first.');
        return;
      }

      const doc = getNotesDoc(st);
      ensureRemediation(doc);
      const rem = doc.remediation;

      if (section === 'queue') {
        const entry = rem.reviewQueue[key];
        if (!entry) {
          setStatus('Row no longer exists.');
          state.editingKey = '';
          render();
          return;
        }

        entry.reason = reason;
        entry.notes = notes;
        entry.updatedAt = ts;

        // Resolve when both are completed.
        if (reason && notes) {
          const resolved = {
            kind: entry.kind,
            hostKey: entry.hostKey,
            issueKey: entry.issueKey,
            comboKey: entry.comboKey,
            title: entry.title,
            resolvedAt: ts,
            reason,
            notes,
            updatedAt: ts,
          };
          delete rem.reviewQueue[key];
          rem.log[key] = resolved;
          setStatus('Saved and moved to Mitigations Log.');
        } else {
          setStatus('Saved (still in Needs Review until Reason + Notes are completed).');
        }
      } else {
        const entry = rem.log[key];
        if (!entry) {
          setStatus('Row no longer exists.');
          state.editingKey = '';
          render();
          return;
        }

        entry.reason = reason;
        entry.notes = notes;
        entry.updatedAt = ts;
        setStatus('Log entry updated.');
      }

      doc.updatedAt = ts;
      persistDoc(doc);

      state.editingKey = '';
      window.dispatchEvent(new CustomEvent('notes:changed', { detail: { reason: 'remediationUpdated' } }));
      render();
    }

    function exportCsv(section) {
      const st = loadState();
      if (!st) {
        setStatus('No data available yet.');
        return;
      }

      const doc = getNotesDoc(st);
      ensureRemediation(doc);
      const { kind, queue, logRows } = getDataForView(doc);

      const rows = section === 'queue' ? queue : logRows;
      const filtered = filterRows(rows, { searchText: state.searchText, reason: state.reasonFilter });
      const sorted = sortRows(
        filtered,
        section === 'queue' ? state.sort.queue.key : state.sort.log.key,
        section === 'queue' ? state.sort.queue.dir : state.sort.log.dir,
      );

      const stamp = new Date().toISOString().slice(0, 10);
      const viewLabel = state.view === 'host' ? 'by-device' : 'by-vuln';
      const filename = `remediation__${config.client.id}__${section}__${viewLabel}__${stamp}.csv`;

      const cols = [];
      const header = [];

      if (kind === 'host') {
        header.push('Device');
        cols.push((r) => r.title || '');
        header.push('Host Key');
        cols.push((r) => r.hostKey || '');

        header.push('Vulnerabilities');
        cols.push((r) => Array.isArray(r.related) ? r.related.join('; ') : '');
      } else {
        header.push('Vulnerability');
        cols.push((r) => r.title || '');
        header.push('Issue Key');
        cols.push((r) => r.issueKey || '');

        header.push('Devices');
        cols.push((r) => Array.isArray(r.related) ? r.related.join('; ') : '');
      }

      if (section === 'queue') {
        header.push('Last Seen At');
        cols.push((r) => r.lastSeenAt || '');
      } else {
        header.push('Resolved At');
        cols.push((r) => r.resolvedAt || '');
      }

      header.push('Reason', 'Notes');
      cols.push((r) => r.reason || '', (r) => r.notes || '');

      const lines = [];
      lines.push(header.map(csvEscape).join(','));
      for (const r of sorted) {
        lines.push(cols.map((fn) => csvEscape(fn(r))).join(','));
      }

      downloadText(filename, lines.join('\n'), 'text/csv');
      setStatus(`Exported ${sorted.length} row(s) to CSV.`);
    }

    // Events
    function onNotesChanged() {
      render();
    }

    function onDataCleared() {
      state.selected.clear();
      state.editingKey = '';
      state.status = '';
      render();
    }

    // Initial render
    render();

    // UI events (delegated)
    onEvent(root, 'click', '[data-action]', (evt, el) => {
      const action = el.getAttribute('data-action');
      evt.preventDefault();

      if (action === 'setView') {
        state.view = el.getAttribute('data-view') || 'vuln';
        state.selected.clear();
        state.editingKey = '';
        setStatus('');
        render();
        return;
      }

      if (action === 'exportClientJson') {
        window.dispatchEvent(new CustomEvent('notes:exportRequested'));
        setStatus('Export requested.');
        return;
      }

      if (action === 'exportReviewCsv') {
        exportCsv('queue');
        return;
      }

      if (action === 'exportLogCsv') {
        exportCsv('log');
        return;
      }

      if (action === 'applyBulk') {
        applyBulkToSelected();
        return;
      }

      if (action === 'edit') {
        const key = el.getAttribute('data-key') || '';
        state.editingKey = key;
        render();
        return;
      }

      if (action === 'cancelEdit') {
        state.editingKey = '';
        render();
        return;
      }

      if (action === 'save') {
        const key = el.getAttribute('data-key') || '';
        const section = el.getAttribute('data-section') || '';
        const row = el.closest('tr');
        if (!row) return;
        saveEdit(section, key, row);
      }
    });

    onEvent(root, 'input', '[data-role="search"]', (evt, el) => {
      state.searchText = el.value || '';
      render();
    });

    onEvent(root, 'change', '[data-role="reasonFilter"]', (evt, el) => {
      state.reasonFilter = el.value || '';
      state.selected.clear();
      render();
    });

    onEvent(root, 'change', '[data-role="bulkReason"]', (evt, el) => {
      state.bulkReason = el.value || '';
    });

    onEvent(root, 'input', '[data-role="bulkNotes"]', (evt, el) => {
      state.bulkNotes = el.value || '';
      autoGrowTextarea(el);
    });

    onEvent(root, 'input', '[data-role="editNotes"]', (evt, el) => {
      autoGrowTextarea(el);
    });

    onEvent(root, 'change', '[data-role="rowSelect"]', (evt, el) => {
      const key = el.getAttribute('data-key') || '';
      if (!key) return;
      if (el.checked) state.selected.add(key);
      else state.selected.delete(key);
      const countEl = root.querySelector('[data-role="selectedCount"]');
      if (countEl) countEl.textContent = String(state.selected.size);
    });

    onEvent(root, 'change', '[data-role="selectAllFiltered"]', (evt, el) => {
      const checked = !!el.checked;
      if (!checked) {
        state.selected.clear();
        render();
        return;
      }

      // Select only the currently visible (filtered) queue rows.
      const st = loadState();
      const doc = getNotesDoc(st || {});
      ensureRemediation(doc);
      const { queue } = getDataForView(doc);
      const filteredQueue = filterRows(queue, { searchText: state.searchText, reason: state.reasonFilter });
      state.selected.clear();
      for (const r of filteredQueue) state.selected.add(r.reviewKey);
      render();
    });

    onEvent(root, 'click', 'th[data-sort]', (evt, th) => {
      const sort = th.getAttribute('data-sort') || '';
      if (!sort) return;

      const table = th.closest('table');
      const section = table?.getAttribute('data-section') || '';
      const bucket = section === 'log' ? state.sort.log : state.sort.queue;

      if (bucket.key === sort) bucket.dir = bucket.dir === 'asc' ? 'desc' : 'asc';
      else {
        bucket.key = sort;
        bucket.dir = 'asc';
      }
      render();
    });

    window.addEventListener('notes:changed', onNotesChanged);
    window.addEventListener('data:loaded', onNotesChanged);
    window.addEventListener('data:cleared', onDataCleared);

    logger?.info('RemediationReport rendered');

    return {
      destroy() {
        window.removeEventListener('notes:changed', onNotesChanged);
        window.removeEventListener('data:loaded', onNotesChanged);
        window.removeEventListener('data:cleared', onDataCleared);
      },
    };
  }

  window.ComponentRegistry.register('RemediationReport', factory);
})();
