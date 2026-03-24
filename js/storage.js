/*
  storage.js
  SessionStorage helpers for cross-page navigation.
*/
(function () {
  'use strict';

  const logger = window.VulScanReport?.logger;
  const config = window.VulScanReport?.config;

  function safeParse(json) {
    try {
      return JSON.parse(json);
    } catch (e) {
      return null;
    }
  }

  function loadState() {
    try {
      const raw = sessionStorage.getItem(config.storage.stateKey);
      if (!raw) return null;
      return safeParse(raw);
    } catch (e) {
      logger?.warn('Failed to load state from sessionStorage', { error: String(e) });
      return null;
    }
  }

  function saveState(state) {
    try {
      const raw = JSON.stringify(state);
      sessionStorage.setItem(config.storage.stateKey, raw);
      return true;
    } catch (e) {
      logger?.warn('Failed to save state to sessionStorage (possibly too large)', { error: String(e) });
      return false;
    }
  }

  function clearState() {
    try {
      sessionStorage.removeItem(config.storage.stateKey);
      return true;
    } catch (e) {
      logger?.warn('Failed to clear state', { error: String(e) });
      return false;
    }
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.storage = Object.freeze({
    loadState,
    saveState,
    clearState,
  });
})();
