/*
  config.js
  Central configuration.
  Client identity is sourced from js/client-settings.js so the package can be reused safely.
*/
(function () {
  'use strict';

  function slugify(value) {
    return String(value || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .replace(/-{2,}/g, '-');
  }

  const supplied = window.VulScanReportClientSettings || {};
  const clientName = String(supplied.clientName || 'Client Name').trim() || 'Client Name';
  const clientId = String(supplied.clientId || '').trim() || slugify(clientName) || 'client-template';
  const logoFileName = String(supplied.logoFileName || 'companylogo.png').trim() || 'companylogo.png';

  const client = { id: clientId, name: clientName };

  const CONFIG = Object.freeze({
    app: { name: 'VulScan Offline Report', version: '1.1.0' },
    client,
    branding: {
      logoFileName,
    },
    storage: {
      stateKey: `vulscan_reporter_state__${client.id}__v1`,
      notesKey: `vulscan_reporter_notes__${client.id}__v1`,
    },
    notes: { schemaVersion: 2, pruneResolvedOnExport: true },
    severities: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
    severityRank: { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1, Unknown: 0 },
  });

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.config = CONFIG;
})();
