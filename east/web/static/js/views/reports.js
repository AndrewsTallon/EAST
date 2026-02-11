/**
 * Reports Library View
 * Full list of historical scans with search, filter, and sort.
 *
 * Lifecycle: accepts AbortSignal from router, returns cleanup function.
 */
import { api } from '../api.js';
import {
  formatDate, formatDuration, statusBadge, escapeHtml, debounce, toast,
} from '../utils.js';

export async function renderReports(container, signal) {
  let allJobs = [];
  let filteredJobs = [];
  let sortBy = 'created_at';
  let sortOrder = 'desc';
  let filterStatus = '';
  let searchQuery = '';

  container.innerHTML = `
    <div class="page-header">
      <div class="page-header-row">
        <div>
          <h1 class="page-title">Reports</h1>
          <p class="page-subtitle">Browse and manage scan history</p>
        </div>
        <a href="#/scan/new" class="btn btn-primary">
          <svg viewBox="0 0 20 20" fill="currentColor" style="width:16px;height:16px"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v2H7a1 1 0 100 2h2v2a1 1 0 102 0v-2h2a1 1 0 100-2h-2V7z" clip-rule="evenodd"/></svg>
          New Scan
        </a>
      </div>
    </div>

    <div class="filter-bar">
      <div class="search-input-wrapper">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/></svg>
        <input type="text" class="form-input" id="searchInput" placeholder="Search by client or domain...">
      </div>
      <div class="flex gap-2" id="filterChips">
        <button class="filter-chip active" data-status="">All</button>
        <button class="filter-chip" data-status="completed">Completed</button>
        <button class="filter-chip" data-status="running">Running</button>
        <button class="filter-chip" data-status="failed">Failed</button>
      </div>
    </div>

    <div id="reportsTable">
      <div class="skeleton skeleton-card" style="height:300px"></div>
    </div>

    <div class="flex justify-between items-center mt-4" id="reportsPagination" style="display:none">
      <span class="text-muted text-sm" id="resultCount"></span>
    </div>
  `;

  // Load data
  try {
    const data = await api.listJobs({}, signal);
    if (signal && signal.aborted) return;
    allJobs = data.jobs;
    applyFilters();
  } catch (err) {
    if (err.name === 'AbortError') return;
    const el = document.getElementById('reportsTable');
    if (el) {
      el.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">Failed to load reports</div>
          <div class="empty-state-desc">${escapeHtml(err.message)}</div>
        </div>`;
    }
    return;
  }

  // Search
  const searchInput = document.getElementById('searchInput');
  searchInput.addEventListener('input', debounce(() => {
    searchQuery = searchInput.value.trim().toLowerCase();
    applyFilters();
  }, 250));

  // Filter chips
  document.getElementById('filterChips').addEventListener('click', (e) => {
    const chip = e.target.closest('.filter-chip');
    if (!chip) return;
    filterStatus = chip.dataset.status;
    document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    applyFilters();
  });


  async function handleDelete(jobId) {
    const ok = window.confirm('Delete this scan and its generated report file? This cannot be undone.');
    if (!ok) return;

    try {
      await api.deleteJob(jobId, signal);
      allJobs = allJobs.filter(j => j.id !== jobId);
      toast('Scan deleted', 'success');
      applyFilters();
    } catch (err) {
      if (err.name === 'AbortError') return;
      toast('Failed to delete scan: ' + err.message, 'error');
    }
  }

  function applyFilters() {
    // Create new array — never mutate allJobs
    filteredJobs = allJobs.filter(j => {
      if (filterStatus && j.status !== filterStatus) return false;
      if (searchQuery) {
        const hay = `${j.client} ${j.domains.join(' ')}`.toLowerCase();
        if (!hay.includes(searchQuery)) return false;
      }
      return true;
    });

    // Sort the copy
    filteredJobs.sort((a, b) => {
      let va = a[sortBy] || '';
      let vb = b[sortBy] || '';
      if (sortBy === 'created_at') {
        va = new Date(va).getTime();
        vb = new Date(vb).getTime();
      }
      if (va < vb) return sortOrder === 'asc' ? -1 : 1;
      if (va > vb) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    renderTable();
  }

  function renderTable() {
    const pagination = document.getElementById('reportsPagination');
    const countEl = document.getElementById('resultCount');
    if (!pagination || !countEl) return;

    if (!filteredJobs.length) {
      const tableEl = document.getElementById('reportsTable');
      if (tableEl) {
        tableEl.innerHTML = `
          <div class="empty-state">
            <svg class="empty-state-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd"/></svg>
            <div class="empty-state-title">${searchQuery || filterStatus ? 'No matching scans' : 'No scans yet'}</div>
            <div class="empty-state-desc">${searchQuery || filterStatus ? 'Try adjusting your filters' : 'Start your first scan to see reports here'}</div>
          </div>`;
      }
      pagination.style.display = 'none';
      return;
    }

    pagination.style.display = 'flex';
    countEl.textContent = `${filteredJobs.length} scan${filteredJobs.length !== 1 ? 's' : ''}`;

    const sortIcon = (col) => {
      if (sortBy !== col) return '';
      return sortOrder === 'asc' ? ' &#9650;' : ' &#9660;';
    };

    let html = `<div class="table-container"><table class="data-table">
      <thead><tr>
        <th class="sortable ${sortBy === 'status' ? 'sorted' : ''}" data-sort="status">Status${sortIcon('status')}</th>
        <th class="sortable ${sortBy === 'client' ? 'sorted' : ''}" data-sort="client">Client${sortIcon('client')}</th>
        <th>Domains</th>
        <th>Tests</th>
        <th class="sortable ${sortBy === 'created_at' ? 'sorted' : ''}" data-sort="created_at">Date${sortIcon('created_at')}</th>
        <th>Duration</th>
        <th>Actions</th>
      </tr></thead><tbody>`;

    for (const job of filteredJobs) {
      const domains = job.domains.map(d => `<span class="text-mono">${escapeHtml(d)}</span>`).join(', ');
      const duration = formatDuration(job.created_at, job.completed_at);

      // Count results summary
      let passCount = 0, failCount = 0;
      if (job.results) {
        for (const results of Object.values(job.results)) {
          for (const r of results) {
            if (r.success) passCount++; else failCount++;
          }
        }
      }
      const resultSummary = job.status === 'completed'
        ? `<span class="text-sm"><span style="color:var(--success)">${passCount} passed</span> / <span style="color:var(--error)">${failCount} failed</span></span>`
        : `<span class="text-muted text-sm">${job.tests?.length || 0} selected</span>`;

      html += `<tr class="row-clickable" onclick="location.hash='#/scan/${job.id}'">
        <td>${statusBadge(job.status)}</td>
        <td>${escapeHtml(job.client || '—')}</td>
        <td style="max-width:240px" class="truncate">${domains}</td>
        <td>${resultSummary}</td>
        <td class="text-muted">${formatDate(job.created_at)}</td>
        <td class="duration">${duration}</td>
        <td>
          <div class="flex gap-2" onclick="event.stopPropagation()">
            ${job.status === 'completed' ? `<a href="${api.downloadUrl(job.id)}" class="btn btn-ghost btn-sm" title="Download DOCX" download>
              <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            </a>
            <a href="${api.downloadPackageUrl(job.id)}" class="btn btn-ghost btn-sm" title="Download ZIP package" download>
              <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
            </a>` : ''}
            <a href="#/scan/new?clone=${job.id}" class="btn btn-ghost btn-sm" title="Clone scan">
              <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px"><path d="M7 9a2 2 0 012-2h6a2 2 0 012 2v6a2 2 0 01-2 2H9a2 2 0 01-2-2V9z"/><path d="M5 3a2 2 0 00-2 2v6a2 2 0 002 2V5h8a2 2 0 00-2-2H5z"/></svg>
            </a>
            <a href="#/scan/${job.id}" class="btn btn-ghost btn-sm" title="View details">
              <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px"><path d="M10 12a2 2 0 100-4 2 2 0 000 4z"/><path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd"/></svg>
            </a>
            <button class="btn btn-danger btn-sm" title="Delete scan" data-delete-job="${job.id}">
              <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px"><path fill-rule="evenodd" d="M6 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm6-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd"/><path fill-rule="evenodd" d="M4 5a1 1 0 011-1h3V3a1 1 0 112 0v1h3a1 1 0 110 2h-.2l-.867 10.142A2 2 0 0110.94 18H9.06a2 2 0 01-1.993-1.858L6.2 6H6a1 1 0 01-1-1z" clip-rule="evenodd"/></svg>
            </button>
          </div>
        </td>
      </tr>`;
    }

    html += '</tbody></table></div>';
    const tableEl = document.getElementById('reportsTable');
    if (tableEl) tableEl.innerHTML = html;

    // Sortable headers
    document.querySelectorAll('th.sortable').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.sort;
        if (sortBy === col) {
          sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
        } else {
          sortBy = col;
          sortOrder = 'desc';
        }
        applyFilters();
      });
    });

    document.querySelectorAll('[data-delete-job]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const { deleteJob } = btn.dataset;
        if (deleteJob) handleDelete(deleteJob);
      });
    });
  }

  // Return cleanup for router
  return () => {};
}
