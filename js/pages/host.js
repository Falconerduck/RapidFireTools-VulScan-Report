/*
  pages/host.js
  Host report bootstrap.
*/
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    window.ComponentRegistry.init([
      'AppShell',
      'NotesStore',
      'Filters',
      'HostReport',
    ]);
  });
})();
