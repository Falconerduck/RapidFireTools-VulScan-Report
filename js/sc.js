/*
  sc.js
  Small template helpers.
  - showLoading(): displays the "Loading" banner if present.

  This file exists because the provided template referenced it.
*/
(function () {
  'use strict';

  window.showLoading = function showLoading() {
    const el = document.getElementById('loading');
    if (el) el.style.display = 'block';
  };
})();
