/*
  pages/devices.js
  Device rename page bootstrap.
*/
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    window.ComponentRegistry.init([
      'AppShell',
      'NotesStore',
      'DeviceRenames',
    ]);
  });
})();
