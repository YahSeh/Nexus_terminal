// /static/logout.js
(() => {
  let isFormSubmission = false;
  let isReload = false;
  let isInternalNavigation = false;

  // Guard: only add if a form exists on the page
  const firstForm = document.querySelector('form');
  if (firstForm) {
    firstForm.addEventListener('submit', () => {
      isFormSubmission = true;
      sessionStorage.setItem('lastAction', 'form_submit');
    });
  }

  // Detect reload shortcuts
  window.addEventListener('keydown', (e) => {
    const r = (e.key || '').toLowerCase();
    if (r === 'f5' || ((e.ctrlKey || e.metaKey) && r === 'r')) {
      isReload = true;
      sessionStorage.setItem('lastAction', 'reload');
    }
  });

  // Mark internal navigation (same-origin <a> clicks)
  document.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a[href]');
    if (!a) return;
    try {
      const url = new URL(a.getAttribute('href'), location.href);
      if (url.origin === location.origin) {
        isInternalNavigation = true;
        sessionStorage.setItem('lastAction', 'nav');
      }
    } catch {}
  });

  function logoutBeacon() {
    try { navigator.sendBeacon('/logout'); } catch {}
  }

  // Primary: beforeunload
  window.addEventListener('beforeunload', () => {
    const last = sessionStorage.getItem('lastAction');
    if (last === 'reload' || last === 'form_submit' || last === 'nav') return;
    if (isReload || isFormSubmission || isInternalNavigation) return;
    logoutBeacon(); // closing tab/window
  });

  // Extra safety: pagehide (Safari/Firefox)
  window.addEventListener('pagehide', (e) => {
    if (e.persisted) return; // bfcache
    if (isReload || isFormSubmission || isInternalNavigation) return;
    logoutBeacon();
  });

  // Extra-extra safety: when page becomes hidden
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden' && !isReload && !isFormSubmission && !isInternalNavigation) {
      logoutBeacon();
    }
  });

  // Reset flags after a normal load
  window.addEventListener('load', () => {
    setTimeout(() => {
      sessionStorage.removeItem('lastAction');
      isFormSubmission = isReload = isInternalNavigation = false;
    }, 1000);
  });
})();
