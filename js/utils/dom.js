/*
  dom.js
  Small DOM helpers (no external dependencies).
*/
(function () {
  'use strict';

  function escapeHtml(unsafe) {
    if (unsafe == null) return '';
    return String(unsafe)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function createEl(tag, options) {
    const el = document.createElement(tag);
    if (!options) return el;

    if (options.className) el.className = options.className;
    if (options.text != null) el.textContent = String(options.text);
    if (options.html != null) el.innerHTML = String(options.html);
    if (options.attrs) {
      for (const [k, v] of Object.entries(options.attrs)) {
        el.setAttribute(k, String(v));
      }
    }
    return el;
  }

  function on(root, eventName, selector, handler) {
    // Simple delegated event handler.
    root.addEventListener(eventName, (evt) => {
      const target = evt.target;
      if (!(target instanceof Element)) return;
      const match = target.closest(selector);
      if (!match || !root.contains(match)) return;
      handler(evt, match);
    });
  }

  function findByDataset(root, selector, datasetKey, value) {
    if (!root || !selector || !datasetKey) return null;
    const nodes = root.querySelectorAll(selector);
    const target = String(value == null ? '' : value);

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!n || !n.dataset) continue;
      const v = n.dataset[datasetKey];
      if (String(v == null ? '' : v) === target) return n;
    }
    return null;
  }


  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.utils = window.VulScanReport.utils || {};
  window.VulScanReport.utils.escapeHtml = escapeHtml;
  window.VulScanReport.utils.createEl = createEl;
  window.VulScanReport.utils.on = on;
  window.VulScanReport.utils.findByDataset = findByDataset;
})();
