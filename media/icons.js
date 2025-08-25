(function () {
  const ICONS = {
    refresh:
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"/><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"/></svg>',
    package:
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 22l-8 -4.5v-9l8 -4.5l8 4.5v9z"/><path d="M12 12l8 -4.5"/><path d="M12 12v10"/><path d="M12 12l-8 -4.5"/><path d="M16 5.25l-8 4.5"/></svg>',
    file: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"/></svg>',
    stats:
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M4 20l0 -10"/><path d="M8 20l0 -4"/><path d="M12 20l0 -6"/><path d="M16 20l0 -2"/><path d="M20 20l0 -12"/></svg>',
    search:
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M10 10m-7 0a7 7 0 1 0 14 0a7 7 0 1 0 -14 0"/><path d="M21 21l-6 -6"/></svg>',
    clipboard:
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M9 5h-2a2 2 0 0 0 -2 2v11a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-11a2 2 0 0 0 -2 -2h-2"/><path d="M9 3m0 2a2 2 0 0 0 2 2h2a2 2 0 0 0 2 -2v0a2 2 0 0 0 -2 -2h-2a2 2 0 0 0 -2 2z"/></svg>',
    check:
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10"/></svg>',
    key: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M16 10a4 4 0 1 0 -4 4"/><path d="M10 14l-6 6l3 -3l3 3l3 -3"/></svg>',
    hourglass:
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M6 7a6 6 0 0 0 6 6a6 6 0 0 0 6 -6"/><path d="M6 17a6 6 0 0 1 6 -6a6 6 0 0 1 6 6"/><path d="M6 4h12"/><path d="M6 20h12"/></svg>',
    spinner:
      '<svg class="spin" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" stroke-width="1.5" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 3a9 9 0 1 0 9 9"/></svg>',
  };

  function getIcon(name, size) {
    const svg = ICONS[name];
    if (!svg) return "";
    if (!size) return svg;
    return svg
      .replace('width="16"', `width="${size}"`)
      .replace('height="16"', `height="${size}"`);
  }

  function injectDataIcons(root) {
    const scope = root || document;
    const nodes = scope.querySelectorAll("[data-icon]");
    nodes.forEach((el) => {
      const name = el.getAttribute("data-icon");
      const sizeAttr = el.getAttribute("data-size");
      const size = sizeAttr ? parseInt(sizeAttr, 10) : undefined;
      el.innerHTML = getIcon(name, size);
    });
  }

  window.VulnZapIcons = { getIcon, injectDataIcons };
})();
