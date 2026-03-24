/*
  pages/allvulns.js
  All vulnerabilities report bootstrap.
*/
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    window.ComponentRegistry.init([
      'AppShell',
      'NotesStore',
      'Filters',
      'VulnReport',
    ]);
  });
})();
