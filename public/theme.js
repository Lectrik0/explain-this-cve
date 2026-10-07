'use strict';

// Applies a saved day/night choice BEFORE the page is painted, so there is no flash of the wrong theme.
// It runs from a separate file because the Content Security Policy forbids inline scripts.
// Only the two exact words "light" and "dark" are accepted from storage; anything else is ignored.
(() => {
  try {
    const saved = localStorage.getItem('theme');
    if (saved === 'light' || saved === 'dark') document.documentElement.setAttribute('data-theme', saved);
  } catch {
    // Storage can be blocked (private mode, site settings): the system theme is used instead.
  }
})();
