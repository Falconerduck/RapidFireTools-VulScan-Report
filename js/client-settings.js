/*
  client-settings.js
  Edit this file for each client deployment.

  Required:
    - clientName

  Optional:
    - clientId       (if omitted, it is auto-generated from clientName)
    - logoFileName   (must exist in the top-level images/ folder)

  Example:
    clientName: 'Example Client',
    clientId: 'example-client',
    logoFileName: 'companylogo.png'
*/
(function () {
  'use strict';

  window.VulScanReportClientSettings = Object.freeze({
    clientName: 'Client Name',
    clientId: '',
    logoFileName: 'companylogo.png',
  });
})();
