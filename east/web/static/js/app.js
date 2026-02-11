/**
 * EAST Web Scanner — Main Application
 * SPA entry point: registers routes, initializes theme, starts router.
 */
import { addRoute, startRouter } from './router.js';
import { renderDashboard } from './views/dashboard.js';
import { renderNewScan } from './views/new-scan.js';
import { renderScanProgress } from './views/scan-progress.js';
import { renderReports } from './views/reports.js';

// --- Routes ---
addRoute('/', renderDashboard);
addRoute('/dashboard', renderDashboard);
addRoute('/scan/new', renderNewScan);
addRoute('/scan/:id', renderScanProgress);
addRoute('/reports', renderReports);

// --- Theme ---
function initTheme() {
  const saved = localStorage.getItem('east-theme');
  const theme = saved || 'dark';
  document.documentElement.setAttribute('data-theme', theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('east-theme', next);
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  initTheme();

  const themeBtn = document.getElementById('themeToggle');
  if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

  startRouter();
});
