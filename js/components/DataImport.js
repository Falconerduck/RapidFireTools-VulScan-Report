/*
  DataImport.js
  Dashboard-only import gate.

  Uploads:
    - Current By-Issue CSV (required)
    - Previous By-Issue CSV (required)
    - Client Data JSON (optional)
    - By-Device CSV (optional)

  Emits:
    - data:loaded
    - notes:fileLoaded
    - data:cleared
*/
(function () {
  'use strict';

  const readFileAsTextSmart = window.VulScanReport?.utils?.readFileAsTextSmart;
  const parseByIssueCsv = window.VulScanReport?.parsers?.parseByIssueCsv;
  const parseByDeviceCsv = window.VulScanReport?.parsers?.parseByDeviceCsv;
  const computeNewFindings = window.VulScanReport?.parsers?.computeNewFindings;
  const buildHostIndex = window.VulScanReport?.parsers?.buildHostIndex;
  const createEmptyNotesDoc = window.VulScanReport?.parsers?.createEmptyNotesDoc;
  const hostsUtil = window.VulScanReport?.utils?.hosts;

  function buildPreviousSnapshot(previousFindings) {
    const findings = Array.isArray(previousFindings) ? previousFindings : [];

    const issueKeys = [];
    const issueTitleByKey = {};

    const hostKeysSet = new Set();
    const hostTitleByKey = {};

    const parseEntry = hostsUtil?.parseAffectedDeviceEntry;
    const defaultHostDisplay = hostsUtil?.defaultHostDisplay;

    const comboKeysSet = new Set();

    for (const f of findings) {
      if (!f || !f.issueKey) continue;
      const ik = String(f.issueKey);
      issueKeys.push(ik);
      if (!issueTitleByKey[ik]) issueTitleByKey[ik] = String(f.issue || ik);

      const affected = Array.isArray(f.affectedDevices) ? f.affectedDevices : [];
      for (const raw of affected) {
        const parsed = parseEntry ? parseEntry(raw) : { key: String(raw || '').trim(), ip: '', hostname: '' };
        const hk = String(parsed?.key || '').trim();
        if (!hk) continue;

        hostKeysSet.add(hk);
        if (!hostTitleByKey[hk]) {
          if (typeof defaultHostDisplay === 'function') {
            hostTitleByKey[hk] = defaultHostDisplay({
              key: hk,
              ip: parsed?.ip || '',
              hostname: parsed?.hostname || '',
              displayName: hk,
            }) || hk;
          } else {
            hostTitleByKey[hk] = hk;
          }
        }

        // Track host+vulnerability combos for remediation relationships.
        comboKeysSet.add(`${hk}::${ik}`);
      }
    }

    return {
      issueKeys,
      issueTitleByKey,
      hostKeys: Array.from(hostKeysSet),
      hostTitleByKey,
      comboKeys: Array.from(comboKeysSet),
    };
  }

  function computeSeverityCounts(findings) {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0, Unknown: 0 };
    for (const f of findings || []) {
      const sev = f.severity || 'Unknown';
      if (typeof counts[sev] !== 'number') counts[sev] = 0;
      counts[sev] += 1;
    }
    return counts;
  }

  function computeNewCount(findings) {
    let c = 0;
    for (const f of findings || []) if (f.isNew) c += 1;
    return c;
  }

  function safeJsonParse(text) {
    try {
      return JSON.parse(text);
    } catch (e) {
      const err = new Error('JSON file is not valid client-data JSON.');
      err.code = 'InvalidJson';
      throw err;
    }
  }

  function factory(root, context) {
    const { config, logger } = context;

    root.innerHTML = `
      <div class="import-card noPrint">
        <h3>Data Import</h3>
        <p class="import-help">Load your VulScan CSV exports to generate the report. All processing happens locally on your device and in your browser.</p>

        <div class="import-grid">
          <div class="import-field">
            <label class="import-label">Current Scan - By Issue CSV <span class="import-required">(required)</span></label>
            <input class="import-input" type="file" accept=".csv,text/csv" data-role="currentByIssue" />
            <p class="import-hint">Must be the most recent scan export.</p>

          </div>

          <div class="import-field">
            <label class="import-label">Previous Scan - By Issue CSV <span class="import-required">(required)</span></label>
            <input class="import-input" type="file" accept=".csv,text/csv" data-role="previousByIssue" />
            <p class="import-hint">Must be the prior scan export.</p>

          </div>

          <div class="import-field">
            <label class="import-label">Client Data JSON <span class="import-optional">(optional)</span></label>
            <input class="import-input" type="file" accept=".json,application/json" data-role="notesJson" />
            <p class="import-hint">Must be imported to carry data between between scans.</p>
          </div>

          <div class="import-field">
            <label class="import-label">By Device CSV <span class="import-optional">(optional)</span></label>
            <input class="import-input" type="file" accept=".csv,text/csv" data-role="byDevice" />
            <p class="import-hint">If provided, host data will prefer this export.</p>
          </div>
        </div>

        <div class="import-actions">
          <button class="import-btn" data-action="import">Import & Build Vulnerability Report</button>
          <button class="import-btn import-btn-secondary" data-action="exportNotes" title="Exports notes/renames for items present in the current scan">Export Device Data JSON</button>
          <button class="import-btn import-btn-danger" data-action="clear">Clear Loaded Data</button>
        </div>

        <div class="import-status" data-role="status" aria-live="polite"></div>
      </div>
    `;

    const statusEl = root.querySelector('[data-role="status"]');

    function setStatus(kind, message, detail) {
      const extra = detail ? `\n${detail}` : '';
      statusEl.className = `import-status import-status-${kind}`;
      statusEl.textContent = `${message}${extra}`;
    }

    function clearStatus() {
      statusEl.className = 'import-status';
      statusEl.textContent = '';
    }

    function getFile(role) {
      const input = root.querySelector(`[data-role="${role}"]`);
      return input?.files?.[0] || null;
    }

    async function handleImport() {
      clearStatus();

      const currentFile = getFile('currentByIssue');
      const previousFile = getFile('previousByIssue');

      if (!currentFile) {
        setStatus('error', 'Current By-Issue CSV is required.');
        return;
      }
      if (!previousFile) {
        setStatus('error', 'Previous By-Issue CSV is required.');
        return;
      }

      setStatus('info', 'Reading files...');

      try {
        const [currentText, previousText] = await Promise.all([
          readFileAsTextSmart(currentFile),
          readFileAsTextSmart(previousFile),
        ]);

        setStatus('info', 'Parsing By-Issue CSVs...');
        const currentParsed = parseByIssueCsv(currentText);
        const previousParsed = parseByIssueCsv(previousText);

        // Snapshot a minimal view of the previous scan for remediation "missing" detection.
        const previousSnapshot = buildPreviousSnapshot(previousParsed.findings);

        // Optional By-Device
        let byDeviceParsed = null;
        const byDeviceFile = getFile('byDevice');
        if (byDeviceFile) {
          const byDeviceText = await readFileAsTextSmart(byDeviceFile);
          byDeviceParsed = parseByDeviceCsv(byDeviceText);
        }

        // Compute NEW findings (mutates current findings to set isNew)
        computeNewFindings(previousParsed.findings, currentParsed.findings);

        // Build host index
        const hostIndex = buildHostIndex(currentParsed.findings, byDeviceParsed?.records);

        const severityCounts = computeSeverityCounts(currentParsed.findings);
        const newCount = computeNewCount(currentParsed.findings);

        const state = {
          schemaVersion: 2,
          generatedAt: new Date().toISOString(),
          client: { id: config.client.id, name: config.client.name },
          current: {
            findings: currentParsed.findings,
            meta: currentParsed.meta,
            stats: {
              totalFindings: currentParsed.findings.length,
              totalHosts: hostIndex.hosts.length,
              newFindings: newCount,
              severityCounts,
            },
          },
          previous: {
            issueKeys: previousParsed.findings.map((f) => f.issueKey),
            meta: previousParsed.meta,
          },
          byDevice: byDeviceParsed ? { meta: byDeviceParsed.meta } : null,
          hostIndex: {
            hosts: hostIndex.hosts,
          },
        };

        // Preserve existing notes doc if present.
        const existing = window.VulScanReport?.storage?.loadState?.();
        if (existing?.notesDoc) state.notesDoc = existing.notesDoc;
        else state.notesDoc = createEmptyNotesDoc();

        const saved = window.VulScanReport?.storage?.saveState?.(state);
        if (!saved) {
          setStatus('warn', 'Data parsed, but could not persist to session storage (file may be large).', 'You can still view this page, but other pages may require re-import.');
        } else {
          setStatus('success', 'Import complete. Report data is ready.');
        }

        // Client Data JSON (optional)
        const notesFile = getFile('notesJson');
        if (notesFile) {
          const notesText = await readFileAsTextSmart(notesFile);
          const doc = safeJsonParse(notesText);
          window.dispatchEvent(new CustomEvent('notes:fileLoaded', { detail: { doc } }));
        }

        window.dispatchEvent(new CustomEvent('data:loaded', { detail: { stats: state.current.stats, previousSnapshot } }));

      } catch (e) {
        logger?.error('Import failed', { error: String(e), code: e.code, missing: e.missing });
        const detail = e.code === 'MissingColumns' ? `Missing: ${e.missing?.join(', ')}` : '';
        setStatus('error', e.message || 'Import failed.', detail);
      }
    }

    function handleClear() {
      window.VulScanReport?.storage?.clearState?.();
      window.dispatchEvent(new CustomEvent('data:cleared'));
      setStatus('success', 'Cleared loaded data from this browser session.');
    }

    function handleExportNotes() {
      window.dispatchEvent(new CustomEvent('notes:exportRequested'));
    }

    root.addEventListener('click', (evt) => {
      const btn = evt.target.closest('[data-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-action');
      evt.preventDefault();

      if (action === 'import') handleImport();
      if (action === 'clear') handleClear();
      if (action === 'exportNotes') handleExportNotes();
    });

    // On load, show whether data is already available.
    const existing = window.VulScanReport?.storage?.loadState?.();
    if (existing?.current?.findings?.length) {
      setStatus('success', 'Report data is already loaded in this browser session.');
    } else {
      setStatus('info', 'No scan data loaded. Import your CSV exports to begin.');
    }

    return { destroy() {} };
  }

  window.ComponentRegistry.register('DataImport', factory);
})();
