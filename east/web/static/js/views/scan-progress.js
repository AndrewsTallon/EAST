/**
 * Scan Progress / Detail View
 * Shows live progress during execution and full results when complete.
 *
 * Lifecycle safety:
 * - Accepts AbortSignal from router; all fetches use it.
 * - Uses getJobWithRetry for initial load to avoid spurious "Scan Not Found".
 * - Single completion path: a `done` flag prevents SSE + poll race.
 * - `loadJob` is guarded against concurrent invocation.
 * - Cleanup closes SSE, clears all intervals, and sets `destroyed` flag
 *   so no stale callbacks touch the DOM.
 */
import { api } from '../api.js';
import {
  el, formatDate, formatDuration, elapsedSince, statusBadge, gradeBadge,
  escapeHtml, scannerDisplay, scannerIcon, scoreClass, toast,
} from '../utils.js';

const DEBUG = typeof window !== 'undefined' && window.EAST_DEBUG;
function log(...args) { if (DEBUG) console.log('[EAST:scan-progress]', ...args); }

export async function renderScanProgress(container, jobId, signal) {
  container.innerHTML = `
    <div class="page-header" id="scanHeader">
      <div class="skeleton skeleton-title"></div>
      <div class="skeleton skeleton-text" style="width:40%"></div>
    </div>
    <div id="scanBody"><div class="skeleton skeleton-card" style="height:400px"></div></div>
  `;

  let eventSource = null;
  let pollInterval = null;
  let timerInterval = null;
  let destroyed = false;     // set true on cleanup — no more DOM writes
  let loading = false;       // guard against concurrent loadJob calls
  let completionHandled = false; // single completion path

  async function loadJob() {
    if (destroyed || loading) return;
    loading = true;
    try {
      const job = await api.getJobWithRetry(jobId, signal);
      if (destroyed) return;

      renderHeader(job);

      if (job.status === 'running' || job.status === 'queued') {
        renderProgress(job);
        startLiveUpdates(job);
      } else {
        renderCompleted(job);
      }
    } catch (err) {
      if (destroyed || (err.name === 'AbortError')) return;

      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">Scan Not Found</div>
          <div class="empty-state-desc">${escapeHtml(err.message)}</div>
          <a href="#/" class="btn btn-primary">Back to Dashboard</a>
        </div>`;
    } finally {
      loading = false;
    }
  }


  async function handleDelete() {
    const ok = window.confirm('Delete this scan and its generated report file? This cannot be undone.');
    if (!ok) return;

    try {
      await api.deleteJob(jobId, signal);
      toast('Scan deleted', 'success');
      location.hash = '#/reports';
    } catch (err) {
      if (err.name === 'AbortError') return;
      toast('Failed to delete scan: ' + err.message, 'error');
    }
  }

  function renderHeader(job) {
    if (destroyed) return;
    const headerEl = document.getElementById('scanHeader');
    if (!headerEl) return;

    const duration = job.completed_at
      ? formatDuration(job.created_at, job.completed_at)
      : `<span id="liveTimer">${elapsedSince(job.created_at)}</span>`;

    headerEl.innerHTML = `
      <div class="page-header-row">
        <div>
          <h1 class="page-title">${escapeHtml(job.client || 'Scan')} ${statusBadge(job.status)}</h1>
          <p class="page-subtitle">
            ${job.domains.map(d => `<span class="text-mono">${escapeHtml(d)}</span>`).join(' &middot; ')}
            &nbsp;&mdash;&nbsp; ${formatDate(job.created_at)}
            &nbsp;&middot;&nbsp; Duration: <span class="duration">${duration}</span>
          </p>
        </div>
        <div class="flex gap-2">
          ${job.status === 'completed' ? `
            <a href="${api.downloadUrl(jobId)}" class="btn btn-primary" download>
              <svg viewBox="0 0 20 20" fill="currentColor" style="width:16px;height:16px"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
              DOCX
            </a>
            <button class="btn btn-secondary" id="downloadJsonBtn">
              <svg viewBox="0 0 20 20" fill="currentColor" style="width:16px;height:16px"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
              JSON
            </button>
          ` : ''}
          <a href="#/scan/new?clone=${jobId}" class="btn btn-secondary">Clone Scan</a>
          <button class="btn btn-danger" id="deleteScanBtn">Delete Scan</button>
        </div>
      </div>
    `;

    // Bind JSON download
    const jsonBtn = document.getElementById('downloadJsonBtn');
    if (jsonBtn) {
      jsonBtn.addEventListener('click', async () => {
        try {
          const data = await api.getResults(jobId, signal);
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `EAST_${jobId.slice(0, 8)}.json`;
          a.click();
          URL.revokeObjectURL(url);
        } catch (err) {
          if (err.name === 'AbortError') return;
          toast('Failed to download JSON: ' + err.message, 'error');
        }
      });
    }


    const deleteBtn = document.getElementById('deleteScanBtn');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', () => {
        handleDelete();
      });
    }
  }

  function renderProgress(job) {
    if (destroyed) return;
    const bodyEl = document.getElementById('scanBody');
    if (!bodyEl) return;

    const testEntries = Object.entries(job.test_status || {});
    const total = testEntries.length;
    const done = testEntries.filter(([, s]) => s === 'success' || s === 'failed').length;
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;

    let html = `
      <div class="card mb-4">
        <div class="card-header">
          <div class="card-title">Scan Progress</div>
          <span class="text-muted text-sm">${done} / ${total} tests &middot; ${pct}%</span>
        </div>
        <div class="progress-bar" style="margin-bottom:20px">
          <div class="progress-fill animated" style="width:${pct}%"></div>
        </div>
        <div class="test-progress-grid">`;

    for (const [key, status] of testEntries) {
      const [domain, testName] = key.split(':', 2);
      const icon = status === 'success' ? '&#10003;' : status === 'failed' ? '&#10007;' :
                   status === 'running' ? '<span class="spinner spinner-sm"></span>' : '&#8943;';
      html += `
        <div class="test-progress-card ${status}">
          <div class="test-progress-icon">${icon}</div>
          <div class="test-progress-info">
            <div class="test-progress-name">${scannerIcon(testName)} ${escapeHtml(scannerDisplay(testName))}</div>
            <div class="test-progress-domain">${escapeHtml(domain)}</div>
          </div>
          <div class="test-progress-status">${statusBadge(status)}</div>
        </div>`;
    }

    html += `</div></div>`;

    // Log viewer
    html += `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Live Log</div>
          <span class="badge badge-running"><span class="badge-dot"></span>Streaming</span>
        </div>
        <div class="log-viewer" id="logViewer"></div>
      </div>`;

    bodyEl.innerHTML = html;
  }

  function startLiveUpdates(job) {
    if (destroyed) return;

    // Timer
    timerInterval = setInterval(() => {
      if (destroyed) return;
      const el = document.getElementById('liveTimer');
      if (el) el.textContent = elapsedSince(job.created_at);
    }, 1000);

    // SSE log stream
    const logViewer = document.getElementById('logViewer');
    eventSource = api.streamLogs(
      jobId,
      (data) => {
        if (destroyed) return;

        if (logViewer && logViewer.isConnected) {
          const line = document.createElement('div');
          line.className = 'log-line';
          const parts = data.line.split(' ');
          const time = parts[0] || '';
          const msg = parts.slice(1).join(' ');
          const isError = msg.toLowerCase().includes('error') || msg.toLowerCase().includes('failed');
          const isSuccess = msg.toLowerCase().includes('complete') || msg.toLowerCase().includes('finished');
          line.innerHTML = `
            <span class="log-time">${escapeHtml(time.split('T')[1]?.split('.')[0] || time)}</span>
            <span class="log-message ${isError ? 'error' : isSuccess ? 'success' : ''}">${escapeHtml(msg)}</span>
          `;
          logViewer.appendChild(line);
          logViewer.scrollTop = logViewer.scrollHeight;
        }

        // Check if done — single completion path
        if ((data.status === 'completed' || data.status === 'failed') && !completionHandled) {
          completionHandled = true;
          log('completion via SSE');
          stopLiveUpdates();
          loadJob();
        }
      },
      () => {
        // SSE error — fall back to polling only if we don't already have one
        if (!destroyed && !pollInterval) {
          log('SSE error, starting fallback poll');
          startPolling();
        }
      }
    );

    // Poll job status to update progress cards (incremental, not full re-render)
    pollInterval = setInterval(async () => {
      if (destroyed || completionHandled) return;
      try {
        const updated = await api.getJob(jobId, signal);
        if (destroyed || completionHandled) return;

        if (updated.status === 'completed' || updated.status === 'failed') {
          if (!completionHandled) {
            completionHandled = true;
            log('completion via poll');
            stopLiveUpdates();
            loadJob();
          }
          return;
        }
        // Update progress grid without full re-render
        updateProgressCards(updated.test_status);
        updateProgressBar(updated.test_status);
      } catch (e) {
        if (e.name === 'AbortError') return;
        /* ignore transient errors */
      }
    }, 2000);
  }

  function startPolling() {
    if (destroyed || pollInterval) return; // Already polling or destroyed
    pollInterval = setInterval(async () => {
      if (destroyed || completionHandled) return;
      try {
        const updated = await api.getJob(jobId, signal);
        if (destroyed || completionHandled) return;

        if (updated.status === 'completed' || updated.status === 'failed') {
          if (!completionHandled) {
            completionHandled = true;
            log('completion via fallback poll');
            stopLiveUpdates();
            loadJob();
          }
          return;
        }
        renderProgress(updated);
        // Append new logs
        const logViewer = document.getElementById('logViewer');
        if (logViewer && updated.logs) {
          logViewer.innerHTML = '';
          for (const line of updated.logs) {
            const div = document.createElement('div');
            div.className = 'log-line';
            const parts = line.split(' ');
            const time = parts[0] || '';
            const msg = parts.slice(1).join(' ');
            div.innerHTML = `
              <span class="log-time">${escapeHtml(time.split('T')[1]?.split('.')[0] || time)}</span>
              <span class="log-message">${escapeHtml(msg)}</span>`;
            logViewer.appendChild(div);
          }
          logViewer.scrollTop = logViewer.scrollHeight;
        }
      } catch (e) {
        if (e.name === 'AbortError') return;
        /* ignore transient errors */
      }
    }, 3000);
  }

  function updateProgressCards(testStatus) {
    if (destroyed || !testStatus) return;
    for (const [key, status] of Object.entries(testStatus)) {
      const cards = document.querySelectorAll('.test-progress-card');
      for (const card of cards) {
        const nameEl = card.querySelector('.test-progress-domain');
        const name = card.querySelector('.test-progress-name');
        if (!nameEl || !name) continue;
        const [domain, testName] = key.split(':', 2);
        if (nameEl.textContent === domain && name.textContent.includes(scannerDisplay(testName))) {
          card.className = `test-progress-card ${status}`;
          const icon = card.querySelector('.test-progress-icon');
          if (icon) {
            icon.innerHTML = status === 'success' ? '&#10003;' : status === 'failed' ? '&#10007;' :
                             status === 'running' ? '<span class="spinner spinner-sm"></span>' : '&#8943;';
          }
          const statusEl = card.querySelector('.test-progress-status');
          if (statusEl) statusEl.innerHTML = statusBadge(status);
        }
      }
    }
  }

  function updateProgressBar(testStatus) {
    if (destroyed || !testStatus) return;
    const entries = Object.entries(testStatus);
    const total = entries.length;
    const done = entries.filter(([, s]) => s === 'success' || s === 'failed').length;
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
    const fill = document.querySelector('.progress-fill');
    if (fill) fill.style.width = `${pct}%`;
  }

  function renderCompleted(job) {
    if (destroyed) return;
    const bodyEl = document.getElementById('scanBody');
    if (!bodyEl) return;

    let html = '';

    // Config snapshot
    if (job.config_snapshot && Object.keys(job.config_snapshot).length) {
      html += `<div class="section">
        <div class="section-title">Configuration</div>
        <div class="config-grid">
          <div class="config-item">
            <div class="config-label">Client</div>
            <div class="config-value">${escapeHtml(job.client)}</div>
          </div>
          <div class="config-item">
            <div class="config-label">Domains</div>
            <div class="config-value">${job.domains.map(d => `<span class="tag-item">${escapeHtml(d)}</span>`).join(' ')}</div>
          </div>
          <div class="config-item">
            <div class="config-label">Tests Run</div>
            <div class="config-value">${job.tests.length} scanners</div>
          </div>
          <div class="config-item">
            <div class="config-label">Duration</div>
            <div class="config-value duration">${formatDuration(job.created_at, job.completed_at)}</div>
          </div>
        </div>
      </div>`;
    }

    // Error cards for failed tests
    const errors = [];
    if (job.results) {
      for (const [domain, results] of Object.entries(job.results)) {
        for (const r of results) {
          if (!r.success && r.error) {
            errors.push({ domain, test: r.test_name, error: r.error });
          }
        }
      }
    }

    if (errors.length) {
      html += `<div class="section">
        <div class="section-title" style="color:var(--error)">Errors (${errors.length})</div>`;
      for (const err of errors) {
        html += `<div class="error-card">
          <div class="error-card-title">${scannerIcon(err.test)} ${escapeHtml(scannerDisplay(err.test))} &mdash; ${escapeHtml(err.domain)}</div>
          <div class="error-card-message">${escapeHtml(err.error)}</div>
        </div>`;
      }
      html += '</div>';
    }

    // Results by domain
    if (job.results && Object.keys(job.results).length) {
      const domainKeys = Object.keys(job.results);

      // Domain tabs if multiple
      if (domainKeys.length > 1) {
        html += `<div class="domain-tabs" id="domainTabs">`;
        domainKeys.forEach((d, i) => {
          html += `<button class="domain-tab ${i === 0 ? 'active' : ''}" data-domain="${escapeHtml(d)}">${escapeHtml(d)}</button>`;
        });
        html += `</div>`;
      }

      html += `<div id="domainResults">`;
      for (const [domain, results] of Object.entries(job.results)) {
        html += `<div class="domain-result-section" data-domain="${escapeHtml(domain)}" ${domainKeys.indexOf(domain) > 0 ? 'style="display:none"' : ''}>`;

        // Summary stats
        const passed = results.filter(r => r.success).length;
        const failed = results.filter(r => !r.success).length;
        html += `<div class="stats-grid" style="margin-bottom:20px">
          <div class="stat-card">
            <div class="stat-label">Tests Passed</div>
            <div class="stat-value" style="color:var(--success)">${passed}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Tests Failed</div>
            <div class="stat-value" style="color:var(--error)">${failed}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Avg Score</div>
            <div class="stat-value">${calcAvgScore(results)}</div>
          </div>
        </div>`;

        // Result cards
        html += `<div class="results-grid">`;
        for (const r of results) {
          html += renderResultCard(r);
        }
        html += `</div>`;

        // Recommendations
        const recs = results.flatMap(r => (r.recommendations || []).map(rec => ({ ...rec, test: r.test_name })));
        if (recs.length) {
          html += `<div class="section" style="margin-top:24px">
            <div class="section-title">Recommendations</div>`;
          for (const rec of recs) {
            const sev = rec.severity || 'info';
            const sevClass = sev === 'critical' || sev === 'high' ? 'critical' : sev === 'warning' || sev === 'medium' ? 'warning' : 'info';
            html += `<div class="recommendation ${sevClass}">
              <span class="recommendation-icon">${sevClass === 'critical' ? '!!!' : sevClass === 'warning' ? '!!' : 'i'}</span>
              <div>
                <strong>${escapeHtml(scannerDisplay(rec.test))}</strong>: ${escapeHtml(rec.text)}
              </div>
            </div>`;
          }
          html += '</div>';
        }

        html += `</div>`;
      }
      html += `</div>`;
    }

    // Logs (collapsed)
    if (job.logs && job.logs.length) {
      html += `
        <div class="section" style="margin-top:24px">
          <div class="expandable" id="logsExpand">
            <div class="expandable-header" id="logsToggle">
              <span class="section-title" style="margin:0">Scan Log (${job.logs.length} entries)</span>
              <svg class="expandable-arrow" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            </div>
            <div class="expandable-content">
              <div class="log-viewer" style="max-height:500px">
                ${job.logs.map(line => {
                  const parts = line.split(' ');
                  const time = parts[0] || '';
                  const msg = parts.slice(1).join(' ');
                  return `<div class="log-line">
                    <span class="log-time">${escapeHtml(time.split('T')[1]?.split('.')[0] || time)}</span>
                    <span class="log-message">${escapeHtml(msg)}</span>
                  </div>`;
                }).join('')}
              </div>
            </div>
          </div>
        </div>`;
    }

    bodyEl.innerHTML = html;

    // Domain tab switching
    document.querySelectorAll('.domain-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.domain-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        const domain = tab.dataset.domain;
        document.querySelectorAll('.domain-result-section').forEach(sec => {
          sec.style.display = sec.dataset.domain === domain ? '' : 'none';
        });
      });
    });

    // Logs expandable
    const logsToggle = document.getElementById('logsToggle');
    if (logsToggle) {
      logsToggle.addEventListener('click', () => {
        document.getElementById('logsExpand').classList.toggle('open');
      });
    }
  }

  function renderResultCard(r) {
    const sc = r.score != null ? `<span class="result-score ${scoreClass(r.score)}">${r.score}</span>` : '';
    const gradeHtml = r.grade ? gradeBadge(r.grade) : '';
    return `
      <div class="result-card">
        <div class="result-header">
          <div class="result-test-name">${scannerIcon(r.test_name)} ${escapeHtml(scannerDisplay(r.test_name))}</div>
          <div class="flex gap-2 items-center">
            ${sc}
            ${gradeHtml}
          </div>
        </div>
        <div class="result-summary">${escapeHtml(r.summary || (r.success ? 'Test passed' : 'Test failed'))}</div>
        <div class="result-meta">
          ${statusBadge(r.success ? 'success' : 'failed')}
          ${r.score != null ? `<span class="text-muted">Score: ${r.score}/100</span>` : ''}
        </div>
      </div>`;
  }

  function calcAvgScore(results) {
    const scored = results.filter(r => r.score != null);
    if (!scored.length) return '—';
    const avg = Math.round(scored.reduce((a, r) => a + r.score, 0) / scored.length);
    return `<span class="${scoreClass(avg)}">${avg}</span>`;
  }

  /** Stop all live update mechanisms (SSE, poll, timer) without setting destroyed. */
  function stopLiveUpdates() {
    if (eventSource) { eventSource.close(); eventSource = null; }
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
    log('live updates stopped');
  }

  /** Full cleanup — called by router on navigation away. */
  function cleanup() {
    destroyed = true;
    stopLiveUpdates();
    log('cleanup (destroyed)');
  }

  // Initial load
  await loadJob();

  // Return cleanup function for router
  return cleanup;
}
