/*
  Filters.js
  Search + filter UI.

  Emits:
    - filters:changed { filters }

  Notes:
    - Filters are hidden in print via template's .noPrint wrapper.
    - Also emits display/visibility toggles for vulnerability detail sections.
*/
(function () {
  'use strict';

  // Requested defaults:
  // - Severities: Critical + High
  // - Detail sections: Summary Info (meta), Affected Devices, Remediation Notes
  const DEFAULT_SEVERITIES = Object.freeze(['Critical', 'High']);
  const DEFAULT_SECTIONS = Object.freeze({
    meta: true,
    summary: false,
    detectionResult: false,
    impact: false,
    solution: false,
    insight: false,
    detectionMethod: false,
    references: false,
    affectedDevices: true,
    notes: true,
  });

  function normalizeSev(s) {
    return String(s || '').trim().toLowerCase();
  }

  function parseSevParam(configSeverities) {
    try {
      const params = new URLSearchParams(window.location.search || '');
      const raw = params.get('sev');
      if (!raw) return null;
      const wanted = raw.split(',').map((x) => normalizeSev(x)).filter(Boolean);
      if (!wanted.length) return null;
      const allowed = (configSeverities || []).map((s) => ({ raw: s, norm: normalizeSev(s) }));
      const resolved = [];
      for (const w of wanted) {
        const hit = allowed.find((a) => a.norm === w);
        if (hit) resolved.push(hit.raw);
      }
      return resolved.length ? resolved : null;
    } catch (e) {
      return null;
    }
  }

  function factory(root, context) {
    const { config } = context;

    root.innerHTML = `
      <section class="filters-panel noPrint">
        <header>
          <h2>Filters</h2>
        </header>

        <div class="filters-block">
          <label class="filters-label" for="filters-search">Search</label>
          <input id="filters-search" class="filters-search" type="text" placeholder="Issue, CVE, OID, host..." data-role="search" />
        </div>

        <div class="filters-block">
          <div class="filters-label">Severity</div>
          <div class="filters-sev">
            ${config.severities.map((s) => {
              const checked = DEFAULT_SEVERITIES.includes(s) ? 'checked' : '';
              return `<label class="filters-sev-item"><input type="checkbox" data-role="sev" value="${s}" ${checked} /> ${s}</label>`;
            }).join('')}
          </div>
        </div>

        <div class="filters-block">
          <label class="filters-toggle"><input type="checkbox" data-role="newOnly" /> NEW only</label>
          <label class="filters-toggle"><input type="checkbox" data-role="exploitedOnly" /> Known exploited only</label>
        </div>

        <div class="filters-block">
          <div class="filters-label">Detail Sections</div>
          <div class="filters-sections">
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="meta" ${DEFAULT_SECTIONS.meta ? 'checked' : ''} /> Summary Info (CVSS / IDs)</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="summary" ${DEFAULT_SECTIONS.summary ? 'checked' : ''} /> Summary</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="detectionResult" ${DEFAULT_SECTIONS.detectionResult ? 'checked' : ''} /> Detection Result</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="impact" ${DEFAULT_SECTIONS.impact ? 'checked' : ''} /> Impact</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="solution" ${DEFAULT_SECTIONS.solution ? 'checked' : ''} /> Solution</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="insight" ${DEFAULT_SECTIONS.insight ? 'checked' : ''} /> Vulnerability Insight</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="detectionMethod" ${DEFAULT_SECTIONS.detectionMethod ? 'checked' : ''} /> Detection Method</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="references" ${DEFAULT_SECTIONS.references ? 'checked' : ''} /> References</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="affectedDevices" ${DEFAULT_SECTIONS.affectedDevices ? 'checked' : ''} /> Affected Devices</label>
            <label class="filters-sections-item"><input type="checkbox" data-role="section" value="notes" ${DEFAULT_SECTIONS.notes ? 'checked' : ''} /> Remediation Notes</label>
          </div>
        </div>

        <div class="filters-actions">
          <button type="button" class="filters-btn" data-action="reset">Reset</button>
        </div>
      </section>
    `;

    function readFilters() {
      const q = (root.querySelector('[data-role="search"]')?.value || '').trim();
      const sevChecks = Array.from(root.querySelectorAll('input[data-role="sev"]'));
      const severities = sevChecks
        .filter((c) => c.checked)
        .map((c) => c.value);

      const newOnly = Boolean(root.querySelector('input[data-role="newOnly"]')?.checked);
      const exploitedOnly = Boolean(root.querySelector('input[data-role="exploitedOnly"]')?.checked);

      const sectionChecks = Array.from(root.querySelectorAll('input[data-role="section"]'));
      const sections = { ...DEFAULT_SECTIONS };
      for (const cb of sectionChecks) {
        const key = cb.value;
        if (!key) continue;
        sections[key] = Boolean(cb.checked);
      }

      return { q, severities, newOnly, exploitedOnly, sections };
    }

    function emit() {
      const filters = readFilters();
      window.dispatchEvent(new CustomEvent('filters:changed', { detail: { filters } }));
    }

    function reset() {
      const search = root.querySelector('[data-role="search"]');
      if (search) search.value = '';

      for (const cb of root.querySelectorAll('input[data-role="sev"]')) {
        cb.checked = DEFAULT_SEVERITIES.includes(cb.value);
      }
      const newOnly = root.querySelector('input[data-role="newOnly"]');
      if (newOnly) newOnly.checked = false;
      const exploitedOnly = root.querySelector('input[data-role="exploitedOnly"]');
      if (exploitedOnly) exploitedOnly.checked = false;

      for (const cb of root.querySelectorAll('input[data-role="section"]')) {
        cb.checked = DEFAULT_SECTIONS[cb.value] === true;
      }

      emit();
    }

    root.addEventListener('input', (evt) => {
      const el = evt.target;
      if (!(el instanceof Element)) return;
      if (el.matches('[data-role="search"], input[data-role="sev"], input[data-role="newOnly"], input[data-role="exploitedOnly"], input[data-role="section"]')) {
        emit();
      }
    });

    root.addEventListener('click', (evt) => {
      const btn = evt.target.closest('[data-action]');
      if (!btn) return;
      evt.preventDefault();
      if (btn.getAttribute('data-action') === 'reset') reset();
    });

    // URL overrides (e.g. Dashboard chart: ?sev=Critical)
    const urlSev = parseSevParam(config.severities);
    if (Array.isArray(urlSev) && urlSev.length) {
      const allowed = new Set(urlSev);
      for (const cb of root.querySelectorAll('input[data-role="sev"]')) {
        cb.checked = allowed.has(cb.value);
      }
    }

    // Initial emit must occur after other components have attached listeners.
    // (ComponentRegistry initializes Filters before VulnReport/HostReport)
    setTimeout(emit, 0);

    return { destroy() {} };
  }

  window.ComponentRegistry.register('Filters', factory);
})();
