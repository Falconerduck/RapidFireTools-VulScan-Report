/*
  NotesStore.js
  Maintains client data JSON (remediation notes + device renames) in-memory + sessionStorage.

  Events:
    - listens: notes:fileLoaded          { doc }
    - listens: data:loaded
    - listens: notes:updated             { issueKey, note }
    - listens: deviceRenames:updated     { hostKey, alias }
    - listens: notes:exportRequested

  Emits:
    - notes:changed
        { reason: 'import' | 'dataLoaded' | 'noteUpdated' | 'deviceRenames', ... }
*/
(function () {
  'use strict';

  const mergeNotes = window.VulScanReport?.parsers?.mergeNotes;
  const createEmptyNotesDoc = window.VulScanReport?.parsers?.createEmptyNotesDoc;
  const mergeRemediation = window.VulScanReport?.parsers?.mergeRemediation;
  const updateRemediationOnScan = window.VulScanReport?.parsers?.updateRemediationOnScan;

  function nowIso() {
    return new Date().toISOString();
  }

  function downloadJson(filename, obj) {
    const json = JSON.stringify(obj, null, 2);
    const blob = new Blob([json], { type: 'application/json' });

    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();

    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function factory(root, context) {
    const { config, logger } = context;

    let importedDoc = null;

    function loadState() {
      return window.VulScanReport?.storage?.loadState?.();
    }

    function saveState(state) {
      return window.VulScanReport?.storage?.saveState?.(state);
    }

    function getNotesDocFromState(state) {
      if (state?.notesDoc) return state.notesDoc;
      return createEmptyNotesDoc();
    }

    function applyNotesDocToState(doc) {
      const state = loadState() || {};
      state.notesDoc = doc;
      saveState(state);
    }

    function ensureMergedWithCurrent(doc, state) {
      const findings = state?.current?.findings || [];
      return mergeNotes(doc, findings);
    }

    function mergeRemediationForImport(importDoc, stateDoc) {
      if (!importDoc || typeof importDoc !== 'object') return importDoc;
      if (typeof mergeRemediation !== 'function') return importDoc;

      const localRem = stateDoc && typeof stateDoc === 'object' ? stateDoc.remediation : null;
      const importedRem = importDoc.remediation;
      importDoc.remediation = mergeRemediation(localRem, importedRem);
      return importDoc;
    }

    function applyScanRemediation(doc, state, previousSnapshot) {
      if (typeof updateRemediationOnScan !== 'function') return doc;
      const findings = state?.current?.findings || [];
      if (!findings.length) return doc;
      return updateRemediationOnScan(doc, findings, state?.hostIndex?.hosts, previousSnapshot);
    }

    function handleNotesFileLoaded(evt) {
      importedDoc = evt?.detail?.doc || null;
      const state = loadState();

      // Preserve existing remediation edits by merging remediation objects.
      const existingDoc = state ? getNotesDocFromState(state) : null;
      importedDoc = mergeRemediationForImport(importedDoc, existingDoc);

      // Merge immediately if we have current findings; otherwise store pending.
      if (state?.current?.findings?.length) {
        let merged = ensureMergedWithCurrent(importedDoc, state);
        merged = applyScanRemediation(merged, state, null);
        applyNotesDocToState(merged);
        window.dispatchEvent(new CustomEvent('notes:changed', { detail: { reason: 'import' } }));
        logger?.info('Client data imported and merged');
      } else {
        logger?.info('Client data imported (pending merge until data:loaded)');
      }
    }

    function handleDataLoaded(evt) {
      const state = loadState();
      if (!state?.current?.findings?.length) return;

      const previousSnapshot = evt?.detail?.previousSnapshot || null;

      const baseDoc = importedDoc || getNotesDocFromState(state);
      let merged = ensureMergedWithCurrent(baseDoc, state);
      merged = applyScanRemediation(merged, state, previousSnapshot);
      applyNotesDocToState(merged);
      window.dispatchEvent(new CustomEvent('notes:changed', { detail: { reason: 'dataLoaded' } }));
    }

    function handleNotesUpdated(evt) {
      const issueKey = String(evt?.detail?.issueKey || '');
      if (!issueKey) return;

      const note = String(evt?.detail?.note ?? '');

      const state = loadState();
      if (!state) return;

      const doc = getNotesDocFromState(state);
      const merged = ensureMergedWithCurrent(doc, state);

      if (!merged.notes[issueKey]) merged.notes[issueKey] = { note: '', lastUpdated: '' };
      merged.notes[issueKey].note = note;
      merged.notes[issueKey].lastUpdated = nowIso();
      merged.updatedAt = nowIso();

      applyNotesDocToState(merged);

      window.dispatchEvent(new CustomEvent('notes:changed', {
        detail: { reason: 'noteUpdated', issueKey },
      }));
    }

    function handleDeviceRenamesUpdated(evt) {
      const hostKey = String(evt?.detail?.hostKey || '');
      if (!hostKey) return;

      const alias = String(evt?.detail?.alias ?? '').trim();

      const state = loadState();
      if (!state) return;

      const doc = getNotesDocFromState(state);
      const merged = ensureMergedWithCurrent(doc, state);

      if (!merged.deviceRenames || typeof merged.deviceRenames !== 'object') merged.deviceRenames = {};

      if (alias) merged.deviceRenames[hostKey] = alias;
      else delete merged.deviceRenames[hostKey];

      merged.updatedAt = nowIso();

      applyNotesDocToState(merged);

      window.dispatchEvent(new CustomEvent('notes:changed', {
        detail: { reason: 'deviceRenames', hostKey, alias },
      }));
    }

    function handleExportRequested() {
      const state = loadState();
      if (!state?.current?.findings?.length) return;

      const doc = getNotesDocFromState(state);
      const merged = ensureMergedWithCurrent(doc, state);

      merged.updatedAt = nowIso();
      merged.client = { id: config.client.id, name: config.client.name };

      const stamp = new Date().toISOString().slice(0, 10);
      const filename = `${config.client.id}_${stamp}_client-data.json`;
      downloadJson(filename, merged);

      logger?.info('Client data exported', { filename });
    }

    // NotesStore has no visible UI right now, but it still must own a root.
    root.innerHTML = '';

    window.addEventListener('notes:fileLoaded', handleNotesFileLoaded);
    window.addEventListener('data:loaded', handleDataLoaded);
    window.addEventListener('notes:updated', handleNotesUpdated);
    window.addEventListener('deviceRenames:updated', handleDeviceRenamesUpdated);
    window.addEventListener('notes:exportRequested', handleExportRequested);

    // Ensure state has a notes doc, even before data load.
    const initState = loadState();
    if (initState && !initState.notesDoc) {
      initState.notesDoc = createEmptyNotesDoc();
      saveState(initState);
    }

    return {
      destroy() {
        window.removeEventListener('notes:fileLoaded', handleNotesFileLoaded);
        window.removeEventListener('data:loaded', handleDataLoaded);
        window.removeEventListener('notes:updated', handleNotesUpdated);
        window.removeEventListener('deviceRenames:updated', handleDeviceRenamesUpdated);
        window.removeEventListener('notes:exportRequested', handleExportRequested);
      },
    };
  }

  window.ComponentRegistry.register('NotesStore', factory);
})();
