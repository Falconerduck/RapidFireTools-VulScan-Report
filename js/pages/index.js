/*
  pages/index.js
  Dashboard bootstrap.
*/
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    window.ComponentRegistry.init([
      'AppShell',
      'NotesStore',
      'DataImport',
      'Dashboard',
    ]);
  });
})();
