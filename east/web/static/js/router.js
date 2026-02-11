/**
 * Minimal hash-based SPA router.
 */

const routes = [];
let currentCleanup = null;

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
  return window.location.hash.slice(1) || '/';
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

  // Run cleanup of previous view if any
  if (currentCleanup) {
    currentCleanup();
    currentCleanup = null;
  }

  updateNav(path);

  const matched = matchRoute(path);
  if (matched) {
    // Clear container and call handler
    container.innerHTML = '';
    container.style.animation = 'none';
    // Force reflow to restart animation
    void container.offsetHeight;
    container.style.animation = '';
    const cleanup = await matched.handler(container, ...matched.params);
    if (typeof cleanup === 'function') {
      currentCleanup = cleanup;
    }
  } else {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-title">Page Not Found</div>
        <div class="empty-state-desc">The page you're looking for doesn't exist.</div>
        <a href="#/" class="btn btn-primary">Go to Dashboard</a>
      </div>
    `;
  }
}

export function startRouter() {
  window.addEventListener('hashchange', handleRoute);
  handleRoute();
}
