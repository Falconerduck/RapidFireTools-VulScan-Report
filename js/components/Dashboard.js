/*
  Dashboard.js
  Renders Dashboard summary + Reports By Host list.

  Listens:
    - data:loaded
    - data:cleared
    - notes:changed
*/
(function () {
  'use strict';

  const hostsUtil = window.VulScanReport?.utils?.hosts;
  const { escapeHtml } = window.VulScanReport?.utils || {};

  function sevLabelClass(sev) {
    const s = String(sev || '').toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium') return 'medium';
    if (s === 'low') return 'low';
    return 'info';
  }

  function sevRank(sev) {
    const s = String(sev || '').toLowerCase();
    if (s === 'critical') return 5;
    if (s === 'high') return 4;
    if (s === 'medium') return 3;
    if (s === 'low') return 2;
    return 1;
  }

  function renderCounts(root, stats) {
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

  function sortGlyph(sortState, key) {
    if (!sortState || sortState.key !== key) return '';
    return sortState.dir === 'desc' ? ' ▼' : ' ▲';
  }

  function renderHostTable(root, hosts, deviceRenames, sortState) {
    const container = root.querySelector('[data-role="hostTable"]');
    if (!container) return;

    if (!hosts?.length) {
      container.innerHTML = '<p class="dash-muted">No hosts available. Import scan data to generate host reports.</p>';
      return;
    }

    const rowsData = hosts.map((h, idx) => {
      const href = `reportsbyhost/host.html?host=${encodeURIComponent(h.key)}`;
      const maxSev = h.maxSeverity || 'Informational';
      const sevCls = sevLabelClass(maxSev);

      const label = hostsUtil?.formatHostLabel
        ? hostsUtil.formatHostLabel(h, deviceRenames)
        : (h.displayName || h.key);

      return {
        idx,
        key: h.key,
        label,
        maxSev,
        sevCls,
        totalFindings: Number(h.totalFindings ?? 0),
        newCount: Number(h.newCount ?? 0),
        href,
      };
    });

    let list = rowsData.slice();
    if (sortState?.key) {
      const dir = sortState.dir === 'desc' ? -1 : 1;
      const key = sortState.key;

      list.sort((a, b) => {
        if (key === 'host') {
          return dir * String(a.label || '').localeCompare(String(b.label || ''));
        }
        if (key === 'severity') {
          const d = sevRank(b.maxSev) - sevRank(a.maxSev); // default descending severity
          return dir * (-d) || String(a.label || '').localeCompare(String(b.label || ''));
        }
        if (key === 'total') {
          return dir * ((a.totalFindings - b.totalFindings) || String(a.label || '').localeCompare(String(b.label || '')));
        }
        if (key === 'new') {
          return dir * ((a.newCount - b.newCount) || String(a.label || '').localeCompare(String(b.label || '')));
        }
        return a.idx - b.idx;
      });
    }

    const rows = list.map((r) => {
      return `
        <tr>
          <td>
            <a class="dash-host-link" href="${r.href}">
              <span class="dash-host-name">${escapeHtml(r.label)}</span>
            </a>
          </td>
          <td><span class="vulnlabel ${r.sevCls}">${escapeHtml(String(r.maxSev || '').toUpperCase())}</span></td>
          <td>${r.totalFindings}</td>
          <td>${r.newCount}</td>
        </tr>
      `;
    }).join('');

    container.innerHTML = `
      <table class="dash-host-table" data-role="dashHostTable">
        <thead>
          <tr>
            <th data-sort="host">Host${sortGlyph(sortState, 'host')}</th>
            <th data-sort="severity">Highest Severity${sortGlyph(sortState, 'severity')}</th>
            <th data-sort="total">Total Vulnerabilities${sortGlyph(sortState, 'total')}</th>
            <th data-sort="new">New${sortGlyph(sortState, 'new')}</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    `;
  }

  function getCssVar(name) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return String(v || '').trim();
  }

  function clamp(n, a, b) {
    return Math.max(a, Math.min(b, n));
  }

  function percent(value, total) {
    if (!total) return '0%';
    const p = (value / total) * 100;
    return `${p.toFixed(p >= 10 ? 0 : 1)}%`;
  }

  function renderStatus(root, state) {
    const statusEl = root.querySelector('[data-role="dataStatus"]');
    if (!statusEl) return;

    if (state?.current?.findings?.length) {
      statusEl.innerHTML = '<div class="dash-banner dash-banner-ok">Report data is successfully loaded. Use the "Vulnerability Report" tab above to view reports.</div>';
      return;
    }

    statusEl.innerHTML = '<div class="dash-banner">No scan data loaded. Use <strong>Data Import</strong> to load your VulScan exports.</div>';
  }


  function renderSeverityChart(root, stats) {
    const host = root.querySelector('[data-role="severityChart"]');
    if (!host) return;

    const counts = stats?.severityCounts || {};
    const data = [
      { key: 'Critical', css: '--sev-critical', href: 'reportsbyvuln/allvulns.html?sev=Critical' },
      { key: 'High', css: '--sev-high', href: 'reportsbyvuln/allvulns.html?sev=High' },
      { key: 'Medium', css: '--sev-medium', href: 'reportsbyvuln/allvulns.html?sev=Medium' },
      { key: 'Low', css: '--sev-low', href: 'reportsbyvuln/allvulns.html?sev=Low' },
      { key: 'Informational', css: '--sev-info', href: 'reportsbyvuln/allvulns.html?sev=Informational' },
    ].map((d) => ({
      ...d,
      value: Number(counts[d.key] || 0),
      color: getCssVar(d.css) || '#999',
    }));

    const total = data.reduce((a, d) => a + (d.value || 0), 0);

    host.innerHTML = `
      <div class="dash-chart-card">
        <div class="dash-chart-header">
          <div class="dash-chart-title">Severity Breakdown</div>
          <div class="dash-chart-sub">Hover for percentage</div>
        </div>
        <div class="dash-chart-body">
          <div class="dash-chart-canvas-wrap">
            <canvas data-role="chartCanvas" width="240" height="240" aria-label="Severity chart" role="img"></canvas>
            <div class="dash-chart-tooltip" data-role="chartTooltip" style="display:none"></div>
          </div>
          <div class="dash-chart-legend" data-role="chartLegend"></div>
        </div>
      </div>
    `;

    const canvas = host.querySelector('[data-role="chartCanvas"]');
    const tooltip = host.querySelector('[data-role="chartTooltip"]');
    const legend = host.querySelector('[data-role="chartLegend"]');
    if (!(canvas instanceof HTMLCanvasElement) || !legend) return;

    // Legend (counts visible; % in tooltip)
    legend.innerHTML = data.map((d, idx) => {
      const disabled = d.value ? '' : ' dash-legend-disabled';
      return `
        <div class="dash-legend-item${disabled}" data-idx="${idx}" tabindex="0" role="button" aria-label="Filter ${escapeHtml(d.key)}">
          <span class="dash-legend-swatch" style="background:${escapeHtml(d.color)}"></span>
          <span class="dash-legend-label">${escapeHtml(d.key)}</span>
          <span class="dash-legend-count">${d.value}</span>
        </div>
      `;
    }).join('');

    // Responsive sizing (prevents sidebar overflow)
    const card = host.querySelector('.dash-chart-card');
    const cardWidth = (card && card.clientWidth) ? card.clientWidth : 280;
    const cssSize = clamp(cardWidth - 36, 140, 240);

    // HiDPI
    const ratio = window.devicePixelRatio || 1;
    canvas.style.width = cssSize + 'px';
    canvas.style.height = cssSize + 'px';
    canvas.width = Math.floor(cssSize * ratio);
    canvas.height = Math.floor(cssSize * ratio);

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    const rOuter = Math.min(cx, cy) * 0.92;
    const rInner = rOuter * 0.62;

    let activeIdx = -1;
    let arcs = [];

    function rebuildArcs() {
      arcs = [];
      let start = -Math.PI / 2;
      for (let i = 0; i < data.length; i++) {
        const v = data[i].value;
        if (!total || v <= 0) {
          arcs.push(null);
          continue;
        }
        const angle = (v / total) * Math.PI * 2;
        const end = start + angle;
        arcs.push({ start, end });
        start = end;
      }
    }

    function clear() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }

    function draw() {
      clear();
      rebuildArcs();

      // Donut slices
      for (let i = 0; i < data.length; i++) {
        const arc = arcs[i];
        if (!arc) continue;

        const pop = (i === activeIdx) ? 1.04 : 1.0;
        const ro = rOuter * pop;
        const ri = rInner * pop;

        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.fillStyle = data[i].color;
        ctx.arc(cx, cy, ro, arc.start, arc.end);
        ctx.lineTo(cx, cy);
        ctx.fill();

        // Cutout
        ctx.globalCompositeOperation = 'destination-out';
        ctx.beginPath();
        ctx.arc(cx, cy, ri, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalCompositeOperation = 'source-over';
      }

      // Center label
      ctx.fillStyle = getCssVar('--muted') || '#666';
      ctx.font = `${Math.round(14 * ratio)}px system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('Total', cx, cy - 10 * ratio);
      ctx.fillStyle = getCssVar('--text') || '#111';
      ctx.font = `700 ${Math.round(18 * ratio)}px system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial`;
      ctx.fillText(String(total), cx, cy + 14 * ratio);
    }

    function showTooltip(idx, x, y) {
      if (!tooltip) return;
      if (idx < 0 || idx >= data.length) {
        tooltip.style.display = 'none';
        return;
      }
      const d = data[idx];
      tooltip.style.display = 'block';
      tooltip.textContent = `${d.key}: ${d.value} • ${percent(d.value, total)}`;

      // Position within wrapper
      const wrap = tooltip.parentElement;
      const rect = wrap?.getBoundingClientRect();
      if (!rect) return;
      const left = clamp(x - rect.left + 10, 8, rect.width - 8);
      const top = clamp(y - rect.top - 10, 8, rect.height - 8);
      tooltip.style.left = `${left}px`;
      tooltip.style.top = `${top}px`;
    }

    function pickIndex(evt) {
      const rect = canvas.getBoundingClientRect();
      const x = (evt.clientX - rect.left) * ratio;
      const y = (evt.clientY - rect.top) * ratio;
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < rInner || dist > rOuter * 1.08) return -1;

      let ang = Math.atan2(dy, dx);
      // normalize to [0, 2pi) relative to -pi/2 start
      ang = ang - (-Math.PI / 2);
      while (ang < 0) ang += Math.PI * 2;
      while (ang >= Math.PI * 2) ang -= Math.PI * 2;

      // Find slice
      for (let i = 0; i < arcs.length; i++) {
        const a = arcs[i];
        if (!a) continue;
        const s = a.start - (-Math.PI / 2);
        const e = a.end - (-Math.PI / 2);
        const ss = (s < 0) ? s + Math.PI * 2 : s;
        const ee = (e < 0) ? e + Math.PI * 2 : e;
        if (ang >= ss && ang < ee) return i;
      }
      return -1;
    }

    function navTo(idx) {
      const d = data[idx];
      if (!d || !d.value) return;
      window.location.href = d.href;
    }

    canvas.addEventListener('mousemove', (evt) => {
      const idx = pickIndex(evt);
      if (idx !== activeIdx) {
        activeIdx = idx;
        draw();
        // Legend highlight
        legend.querySelectorAll('.dash-legend-item').forEach((el) => el.classList.remove('dash-legend-active'));
        const le = legend.querySelector(`[data-idx="${idx}"]`);
        if (le) le.classList.add('dash-legend-active');
      }
      showTooltip(idx, evt.clientX, evt.clientY);
    });

    canvas.addEventListener('mouseleave', () => {
      activeIdx = -1;
      draw();
      if (tooltip) tooltip.style.display = 'none';
      legend.querySelectorAll('.dash-legend-item').forEach((el) => el.classList.remove('dash-legend-active'));
    });

    canvas.addEventListener('click', (evt) => {
      const idx = pickIndex(evt);
      if (idx >= 0) navTo(idx);
    });

    legend.addEventListener('mouseover', (evt) => {
      const item = evt.target.closest('.dash-legend-item');
      if (!item) return;
      const idx = Number(item.getAttribute('data-idx'));
      if (!Number.isFinite(idx)) return;
      activeIdx = idx;
      draw();
      legend.querySelectorAll('.dash-legend-item').forEach((el) => el.classList.remove('dash-legend-active'));
      item.classList.add('dash-legend-active');
      if (tooltip) {
        const rect = canvas.getBoundingClientRect();
        showTooltip(idx, rect.left + rect.width * 0.5, rect.top + rect.height * 0.3);
      }
    });

    legend.addEventListener('mouseout', (evt) => {
      const rel = evt.relatedTarget;
      if (rel && legend.contains(rel)) return;
      activeIdx = -1;
      draw();
      if (tooltip) tooltip.style.display = 'none';
      legend.querySelectorAll('.dash-legend-item').forEach((el) => el.classList.remove('dash-legend-active'));
    });

    legend.addEventListener('click', (evt) => {
      const item = evt.target.closest('.dash-legend-item');
      if (!item) return;
      const idx = Number(item.getAttribute('data-idx'));
      if (!Number.isFinite(idx)) return;
      navTo(idx);
    });

    legend.addEventListener('keydown', (evt) => {
      if (evt.key !== 'Enter' && evt.key !== ' ') return;
      const item = evt.target.closest('.dash-legend-item');
      if (!item) return;
      evt.preventDefault();
      const idx = Number(item.getAttribute('data-idx'));
      if (!Number.isFinite(idx)) return;
      navTo(idx);
    });

    draw();
  }


  function factory(root, context) {
    const { logger } = context;

    const ui = {
      hostSort: { key: '', dir: 'asc' },
    };




    function render() {
      const state = window.VulScanReport?.storage?.loadState?.();
      const stats = state?.current?.stats;
      renderCounts(root, stats);
      renderHostTable(root, state?.hostIndex?.hosts || [], state?.notesDoc?.deviceRenames || {}, ui.hostSort);
      renderStatus(root, state);
      renderSeverityChart(root, stats);
    }

    function onDataLoaded() {
      render();
    }

    function onDataCleared() {
      ui.hostSort.key = '';
      ui.hostSort.dir = 'asc';
      render();
    }

    function onNotesChanged() {
      render();
    }

    root.addEventListener('click', (evt) => {
      const th = evt.target.closest('.dash-host-table th[data-sort]');
      if (!th) return;
      const k = th.getAttribute('data-sort') || '';
      if (!k) return;

      if (ui.hostSort.key === k) {
        ui.hostSort.dir = ui.hostSort.dir === 'asc' ? 'desc' : 'asc';
      } else {
        ui.hostSort.key = k;
        ui.hostSort.dir = 'asc';
      }
      render();
    });

    window.addEventListener('data:loaded', onDataLoaded);
    window.addEventListener('data:cleared', onDataCleared);
    window.addEventListener('notes:changed', onNotesChanged);

    render();

    logger?.info('Dashboard rendered');

    return {
      destroy() {
        window.removeEventListener('data:loaded', onDataLoaded);
        window.removeEventListener('data:cleared', onDataCleared);
        window.removeEventListener('notes:changed', onNotesChanged);
      },
    };
  }

  window.ComponentRegistry.register('Dashboard', factory);
})();




