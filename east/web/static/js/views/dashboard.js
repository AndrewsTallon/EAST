/**
 * Dashboard View
 * Overview of recent scans, stats, and quick actions.
 *
 * Lifecycle: accepts AbortSignal from router, returns cleanup function.
 * All DOM writes are guarded by signal.aborted to prevent stale updates.
 */
import { api } from '../api.js';
import { el, formatDate, formatDuration, statusBadge, escapeHtml, scannerDisplay } from '../utils.js';

const DEBUG = typeof window !== 'undefined' && window.EAST_DEBUG;
function log(...args) { if (DEBUG) console.log('[EAST:dashboard]', ...args); }

export async function renderDashboard(container, signal) {
  // signal is the AbortSignal from the router

  container.innerHTML = `
    <div class="page-header">
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Dashboard</h1>
          <p class="page-subtitle">External Attack Surface Testing overview</p>
        </div>
        <a href="#/scan/new" class="btn btn-primary btn-lg">
          <svg viewBox="0 0 20 20" fill="currentColor" style="width:18px;height:18px"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v2H7a1 1 0 100 2h2v2a1 1 0 102 0v-2h2a1 1 0 100-2h-2V7z" clip-rule="evenodd"/></svg>
          New Scan
        </a>
      </div>
    </div>
    <div class="stats-grid" id="statsGrid">
      <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
      <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
      <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
      <div class="stat-card"><div class="skeleton skeleton-card"></div></div>
    </div>
    <div class="section">
      <div class="section-title">Recent Scans</div>
      <div id="recentScans"><div class="skeleton skeleton-card" style="height:200px"></div></div>
    </div>
  `;

  try {
    const data = await api.listJobs({ order: 'desc' }, signal);

    // Guard: if aborted while awaiting, do not touch DOM
    if (signal && signal.aborted) return;

    renderStats(data.jobs);
    renderRecentScans(data.jobs.slice(0, 8));

    log('rendered', data.jobs.length, 'jobs');
  } catch (err) {
    // AbortError means navigation changed — do not render error
    if (err.name === 'AbortError') return;

    const el = document.getElementById('recentScans');
    if (el) {
      el.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">Unable to load data</div>
          <div class="empty-state-desc">${escapeHtml(err.message)}</div>
        </div>`;
    }
  }

  // Return cleanup (no intervals to clear, but satisfies the router contract)
  return () => { log('cleanup'); };
}

function renderStats(jobs) {
  const total = jobs.length;
  const completed = jobs.filter(j => j.status === 'completed').length;
  const failed = jobs.filter(j => j.status === 'failed').length;
  const running = jobs.filter(j => j.status === 'running' || j.status === 'queued').length;
  const domains = new Set(jobs.flatMap(j => j.domains)).size;

  const statsGrid = document.getElementById('statsGrid');
  if (!statsGrid) return;

  statsGrid.innerHTML = `
    <div class="stat-card">
      <div class="stat-label">Total Scans</div>
      <div class="stat-value">${total}</div>
      <div class="stat-change neutral">${running ? `${running} active` : 'No active scans'}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Completed</div>
      <div class="stat-value" style="color:var(--success)">${completed}</div>
      <div class="stat-change positive">${total > 0 ? Math.round(completed / total * 100) : 0}% success rate</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Failed</div>
      <div class="stat-value" style="color:var(--error)">${failed}</div>
      <div class="stat-change ${failed > 0 ? 'negative' : 'neutral'}">${failed > 0 ? 'Review errors' : 'All clear'}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Unique Domains</div>
      <div class="stat-value">${domains}</div>
      <div class="stat-change neutral">Across all scans</div>
    </div>
  `;
}

function renderRecentScans(jobs) {
  const container = document.getElementById('recentScans');
  if (!container) return;

  if (!jobs.length) {
    container.innerHTML = `
      <div class="empty-state">
        <svg class="empty-state-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd"/></svg>
        <div class="empty-state-title">No scans yet</div>
        <div class="empty-state-desc">Start your first security scan to see results here.</div>
        <a href="#/scan/new" class="btn btn-primary">Create New Scan</a>
      </div>`;
    return;
  }

  const now = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  let html = `<div class="table-container"><table class="data-table">
    <thead><tr>
      <th>Status</th>
      <th>Client</th>
      <th>Domains</th>
      <th>Tests</th>
      <th>Started</th>
      <th>Duration</th>
      <th></th>
    </tr></thead><tbody>`;

  for (const job of jobs) {
    const domainStr = job.domains.map(d => `<span class="text-mono">${escapeHtml(d)}</span>`).join(', ');
    const duration = formatDuration(job.created_at, job.completed_at);
    html += `<tr class="row-clickable" onclick="location.hash='#/scan/${job.id}'">
      <td>${statusBadge(job.status)}</td>
      <td>${escapeHtml(job.client || '—')}</td>
      <td>${domainStr}</td>
      <td>${job.tests?.length || 0}</td>
      <td class="text-muted">${formatDate(job.created_at)}</td>
      <td class="duration">${duration}</td>
      <td>
        <a href="#/scan/${job.id}" class="btn btn-ghost btn-sm">View</a>
      </td>
    </tr>`;
  }

  html += '</tbody></table></div>';
  html += `<div class="text-muted text-sm" style="text-align:right;margin-top:8px">Last updated: ${now}</div>`;
  container.innerHTML = html;
}
