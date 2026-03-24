/*
  logger.js
  Central logging helper. No UI debug toggles.
  Use: VulScanReport.logger.info('msg', data)
*/
(function () {
  'use strict';

  const LEVELS = Object.freeze({
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3,
  });

  const DEFAULT_LEVEL = LEVELS.INFO;

  function safeJson(value) {
    try {
      return JSON.stringify(value);
    } catch (e) {
      return '[unserializable]';
    }
  }

  function createLogger(options) {
    const level = typeof options?.level === 'number' ? options.level : DEFAULT_LEVEL;

    function shouldLog(msgLevel) {
      return msgLevel <= level;
    }

    function fmt(prefix, message, data) {
      const ts = new Date().toISOString();
      const base = `[${ts}] ${prefix} ${message}`;
      if (typeof data === 'undefined') return base;
      if (typeof data === 'string') return `${base} | ${data}`;
      return `${base} | ${safeJson(data)}`;
    }

    return Object.freeze({
      LEVELS,
      error(message, data) {
        if (!shouldLog(LEVELS.ERROR)) return;
        console.error(fmt('[ERROR]', message, data));
      },
      warn(message, data) {
        if (!shouldLog(LEVELS.WARN)) return;
        console.warn(fmt('[WARN ]', message, data));
      },
      info(message, data) {
        if (!shouldLog(LEVELS.INFO)) return;
        console.info(fmt('[INFO ]', message, data));
      },
      debug(message, data) {
        if (!shouldLog(LEVELS.DEBUG)) return;
        console.debug(fmt('[DEBUG]', message, data));
      },
    });
  }

  window.VulScanReport = window.VulScanReport || {};
  window.VulScanReport.logger = createLogger({ level: DEFAULT_LEVEL });
})();
