/* CARTINT — Theme Toggle (shared across all pages) */
(function () {
  var STORAGE_KEY = 'cartint_theme';
  var MOON_SVG = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
  var SUN_SVG = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';

  // Apply saved theme immediately (before paint)
  var saved = localStorage.getItem(STORAGE_KEY);
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  }

  function updateIcon(theme) {
    var btn = document.getElementById('themeToggle');
    if (!btn) return;
    var svg = btn.querySelector('svg');
    if (!svg) return;
    svg.innerHTML = theme === 'light' ? SUN_SVG : MOON_SVG;
  }

  function toggle() {
    var current = document.documentElement.getAttribute('data-theme');
    var next = current === 'light' ? 'dark' : 'light';
    if (next === 'dark') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
    }
    localStorage.setItem(STORAGE_KEY, next);
    updateIcon(next);
  }

  function initMobileMenu() {
    var toggleBtn = document.getElementById('mobileMenuToggle');
    var overlay = document.getElementById('mobileMenuOverlay');
    if (!toggleBtn || !overlay) return;

    toggleBtn.addEventListener('click', function () {
      overlay.classList.toggle('open');
    });

    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) {
        overlay.classList.remove('open');
      }
    });
  }

  function init() {
    var theme = localStorage.getItem(STORAGE_KEY) || 'dark';
    updateIcon(theme);
    var btn = document.getElementById('themeToggle');
    if (btn) btn.addEventListener('click', toggle);
    initMobileMenu();
  }

  // Wire up immediately if DOM is ready, otherwise wait
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
