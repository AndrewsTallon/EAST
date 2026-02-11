/**
 * Minimal hash-based SPA router.
 *
 * Lifecycle guarantees:
 * - Each navigation gets a monotonic ID; only the latest navigation renders.
 * - Previous view's cleanup runs synchronously before new view starts.
 * - An AbortController is created per navigation and passed to the handler;
 *   it is aborted on the next navigation so in-flight fetches cancel.
 * - Async handlers that resolve after a newer navigation are silently dropped.
 */

const DEBUG = typeof window !== 'undefined' && window.EAST_DEBUG;
function log(...args) { if (DEBUG) console.log('[EAST:router]', ...args); }

const routes = [];
let currentCleanup = null;
let currentAbort = null;
let navId = 0;          // monotonic navigation counter

export function addRoute(pattern, handler) {
  // Convert :param patterns to regex capture groups
  const regex = new RegExp(
    '^' + pattern.replace(/:\w+/g, '([^/]+)') + '$'
  );
  routes.push({ pattern, regex, handler });
}

export function navigate(hash) {
  window.location.hash = hash;
}

export function currentHash() {
  const raw = window.location.hash.slice(1) || '/';
  return raw.split('?')[0] || '/';
}

function matchRoute(path) {
  for (const route of routes) {
    const match = path.match(route.regex);
    if (match) {
      return { handler: route.handler, params: match.slice(1) };
    }
  }
  return null;
}

function updateNav(path) {
  document.querySelectorAll('.nav-item').forEach((el) => {
    const href = el.getAttribute('href') || '';
    const route = href.replace('#', '');
    const isActive =
      (route === '/' && (path === '/' || path === '/dashboard')) ||
      (route !== '/' && path.startsWith(route));
    el.classList.toggle('active', isActive);
  });
}

async function handleRoute() {
  const path = currentHash();
  const container = document.getElementById('viewContainer');
  const thisNav = ++navId;

  log('navigate', path, 'nav#' + thisNav);

  // --- Cleanup previous view ---
  // Abort any in-flight requests from previous view
  if (currentAbort) {
    currentAbort.abort();
    currentAbort = null;
  }
  // Run view-specific cleanup (intervals, SSE, listeners)
  if (currentCleanup) {
    try { currentCleanup(); } catch (e) { log('cleanup error', e); }
    currentCleanup = null;
  }

  updateNav(path);

  const matched = matchRoute(path);
  if (!matched) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-title">Page Not Found</div>
        <div class="empty-state-desc">The page you're looking for doesn't exist.</div>
        <a href="#/" class="btn btn-primary">Go to Dashboard</a>
      </div>
    `;
    return;
  }

  // Create AbortController for this navigation
  const abort = new AbortController();
  currentAbort = abort;

  // Clear container and restart animation
  container.innerHTML = '';
  container.style.animation = 'none';
  void container.offsetHeight;
  container.style.animation = '';

  // Call view handler, passing signal for fetch cancellation
  const cleanup = await matched.handler(container, ...matched.params, abort.signal);

  // If a newer navigation happened while we were awaiting, discard this result
  if (navId !== thisNav) {
    log('stale nav#' + thisNav + ' discarded (current is nav#' + navId + ')');
    if (typeof cleanup === 'function') {
      try { cleanup(); } catch (e) { /* stale cleanup */ }
    }
    return;
  }

  if (typeof cleanup === 'function') {
    currentCleanup = cleanup;
  }
}

export function startRouter() {
  window.addEventListener('hashchange', handleRoute);
  handleRoute();
}
