/*
  AppShell.js
  Handles top-of-page header text (client + generated timestamp) in a Nessus-style layout.

  Communication:
    - listens for `data:loaded` to refresh timestamp
    - listens for `host:selected` to update Host page header
*/
(function () {
  'use strict';

  const { escapeHtml } = window.VulScanReport?.utils || {};

  const THEME_KEY = 'vulscanTheme';

  function getTheme() {
    try {
      const t = localStorage.getItem(THEME_KEY);
      return t === 'dark' ? 'dark' : 'light';
    } catch (e) {
      return 'light';
    }
  }

  function applyTheme(theme) {
    const t = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', t);
  }

  function setTheme(theme) {
    const t = theme === 'dark' ? 'dark' : 'light';
    try {
      localStorage.setItem(THEME_KEY, t);
    } catch (e) {}
    applyTheme(t);
    window.dispatchEvent(new CustomEvent('theme:changed', { detail: { theme: t } }));
  }

  function ensureThemeToggle(root) {
    // Render once per page load.
    let actions = root.querySelector('.app-shell-actions');
    if (!actions) {
      actions = document.createElement('div');
      actions.className = 'app-shell-actions noPrint';
      root.appendChild(actions);
    }

    let btn = actions.querySelector('[data-role="themeToggle"]');
    if (!btn) {
      btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'theme-toggle';
      btn.setAttribute('data-role', 'themeToggle');
      btn.setAttribute('aria-label', 'Toggle dark mode');
      btn.innerHTML =
        '<span class="dot" aria-hidden="true"></span><span data-role="themeLabel">Theme</span>';
      actions.appendChild(btn);
    }

    const label = btn.querySelector('[data-role="themeLabel"]');
    const updateLabel = () => {
      const t = getTheme();
      if (label) label.textContent = t === 'dark' ? 'Dark' : 'Light';
    };

    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const next = getTheme() === 'dark' ? 'light' : 'dark';
      setTheme(next);
      updateLabel();
    });

    window.addEventListener('theme:changed', updateLabel);

    updateLabel();

    return { updateLabel };
  }

  function markActiveNav(page) {
    const nav = document.getElementById('nav');
    if (!nav) return;
    const map = {
      dashboard: 'index.html',
      vuln: 'reportsbyvuln/allvulns.html',
      host: 'reportsbyhost/host.html',
      devices: 'devices.html',
      remediation: 'remediation.html',
    };
    const want = map[String(page || '')] || '';
    const links = Array.from(nav.querySelectorAll('a'));
    for (const a of links) {
      a.classList.remove('nav-active');
      a.removeAttribute('aria-current');
      const href = a.getAttribute('href') || '';
      if (!want) continue;
      // Match by pathname tail to tolerate ../ relative links.
      if (href.endsWith(want)) {
        a.classList.add('nav-active');
        a.setAttribute('aria-current', 'page');
      }
    }
  }

  function formatLocalDateTime(date) {
    // Use browser locale but force 2-digit month/day and time with seconds.
    // Output resembles: 02/24/2026 3:06:57 PM
    const d = date instanceof Date ? date : new Date(date);
    const pad2 = (n) => String(n).padStart(2, '0');

    const mm = pad2(d.getMonth() + 1);
    const dd = pad2(d.getDate());
    const yyyy = d.getFullYear();

    let h = d.getHours();
    const ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12;
    if (h === 0) h = 12;

    const min = pad2(d.getMinutes());
    const sec = pad2(d.getSeconds());

    return `${mm}/${dd}/${yyyy} ${h}:${min}:${sec} ${ampm}`;
  }

  function resolveLogoSrc(page, logoFileName) {
    const fileName = String(logoFileName || 'companylogo.png').trim() || 'companylogo.png';
    const prefix = (page === 'vuln' || page === 'host') ? '../images/' : 'images/';
    return `${prefix}${fileName}`;
  }

  function buildTitle({ page, clientName, generatedAt, hostLabel }) {
    const dt = formatLocalDateTime(generatedAt);

    if (page === 'vuln') {
      return `Vulnerability Report for - ${clientName}. Generated on ${dt}`;
    }

    if (page === 'host') {
      const hostPart = hostLabel ? `Host: ${hostLabel}` : 'Host Report';
      return `Vulnerability Findings for ${hostPart} - ${clientName}. Generated on ${dt}`;
    }

    if (page === 'devices') {
      return `Device Names - ${clientName}. Generated on ${dt}`;
    }

    if (page === 'remediation') {
      return `Remediation Report - ${clientName}. Generated on ${dt}`;
    }

    // default: dashboard
    return `Dashboard - ${clientName}. Generated on ${dt}`;
  }

  function factory(root, context) {
    const { config, logger } = context;

    const page = root.getAttribute('data-page') || 'dashboard';
    const titleEl = root.querySelector('.app-shell-title');
    const logoEl = root.querySelector('#logo');

    // Ensure theme is applied even if a page was opened directly.
    applyTheme(getTheme());
    const themeHooks = ensureThemeToggle(root);
    markActiveNav(page);

    if (logoEl) {
      logoEl.setAttribute('src', resolveLogoSrc(page, config?.branding?.logoFileName));
      logoEl.setAttribute('alt', `${config?.client?.name || 'Client'} logo`);
    }

    function render(hostLabel) {
      const state = window.VulScanReport?.storage?.loadState?.();
      const generatedAt = state?.generatedAt ? new Date(state.generatedAt) : new Date();
      const title = buildTitle({
        page,
        clientName: config.client.name,
        generatedAt,
        hostLabel,
      });

      // Populate any client-name placeholders anywhere on the page
      document.querySelectorAll('[data-role="clientName"]').forEach((el) => {
        el.textContent = config.client.name;
      });

      if (titleEl) titleEl.innerHTML = escapeHtml(title);
      document.title = title;
    }

    function onDataLoaded() {
      render();
    }

    function onHostSelected(evt) {
      const hostLabel = evt?.detail?.hostLabel || '';
      render(hostLabel);
    }

    window.addEventListener('data:loaded', onDataLoaded);
    window.addEventListener('host:selected', onHostSelected);

    render();

    logger?.info('AppShell rendered', { page });

    return {
      destroy() {
        window.removeEventListener('data:loaded', onDataLoaded);
        window.removeEventListener('host:selected', onHostSelected);
        if (themeHooks?.updateLabel)
          window.removeEventListener('theme:changed', themeHooks.updateLabel);
      },
    };
  }

  window.ComponentRegistry.register('AppShell', factory);
})();