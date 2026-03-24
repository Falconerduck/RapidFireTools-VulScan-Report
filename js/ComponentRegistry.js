/*
  ComponentRegistry.js
  Central component initialization registry.

  Requirements:
    - deterministic init order
    - supports reinitialization of a single component

  Each component is registered with:
    ComponentRegistry.register('Name', (rootEl, context) => { ... return { destroy? } })

  Components must own only their root element.
*/
(function () {
  'use strict';

  const logger = window.VulScanReport?.logger;
  const config = window.VulScanReport?.config;

  const registry = new Map();
  const instances = new Map();

  function register(name, factory) {
    if (!name || typeof name !== 'string') throw new Error('ComponentRegistry.register requires a string name');
    if (typeof factory !== 'function') throw new Error(`ComponentRegistry.register("${name}") requires a factory function`);

    registry.set(name, factory);
  }

  function findRoot(name) {
    return document.querySelector(`[data-component="${name}"]`);
  }

  function destroyInstance(name) {
    const inst = instances.get(name);
    if (!inst) return;

    try {
      if (typeof inst.destroy === 'function') inst.destroy();
    } catch (e) {
      logger?.warn(`Component destroy failed: ${name}`, { error: String(e) });
    }

    instances.delete(name);
  }

  function init(names) {
    const list = Array.isArray(names) && names.length
      ? names
      : Array.from(registry.keys());

    for (const name of list) {
      const factory = registry.get(name);
      if (!factory) {
        logger?.warn(`Component not registered: ${name}`);
        continue;
      }

      const root = findRoot(name);
      if (!root) {
        logger?.info(`Component root not found on this page: ${name}`);
        continue;
      }

      // Re-init safe.
      destroyInstance(name);

      try {
        const context = Object.freeze({
          config,
          logger,
        });

        const inst = factory(root, context) || {};
        instances.set(name, inst);
        logger?.info(`Component initialized: ${name}`);
      } catch (e) {
        logger?.error(`Component init failed: ${name}`, { error: String(e) });
      }
    }
  }

  function reinit(name) {
    init([name]);
  }

  function getInstance(name) {
    return instances.get(name);
  }

  window.ComponentRegistry = Object.freeze({
    register,
    init,
    reinit,
    getInstance,
  });
})();
