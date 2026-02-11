/**
 * New Scan View
 * Full-featured scan creation with scanner discovery, domain tags, config.
 */
import { api } from '../api.js';
import { el, toast, escapeHtml, scannerDisplay, scannerIcon, groupScannersByCategory } from '../utils.js';
import { navigate } from '../router.js';

let scannersCache = null;

export async function renderNewScan(container) {
  // Check if cloning from a previous scan
  const urlParams = new URLSearchParams(window.location.hash.split('?')[1] || '');
  const cloneId = urlParams.get('clone');
  let cloneData = null;
  if (cloneId) {
    try { cloneData = await api.getJob(cloneId); } catch (e) { /* ignore */ }
  }

  container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">${cloneData ? 'Clone Scan' : 'New Scan'}</h1>
      <p class="page-subtitle">Configure and launch an external attack surface test</p>
    </div>
    <div class="card" id="scanForm">
      <div class="form-group">
        <label class="form-label">Client Name</label>
        <input type="text" class="form-input" id="clientInput" placeholder="e.g. Acme Corporation" value="${escapeHtml(cloneData?.client || '')}">
      </div>

      <div class="form-group">
        <label class="form-label">Target Domains</label>
        <div class="tag-input-container" id="domainContainer">
          <input type="text" class="tag-input" id="domainInput" placeholder="Type a domain and press Enter">
        </div>
        <div class="form-hint">Press Enter, Tab, or comma to add a domain. Supports multiple domains.</div>
      </div>

      <div class="section">
        <div class="section-title" style="margin-bottom:4px">
          Scanners
        </div>
        <p class="text-muted text-sm mb-2">Select which security tests to run against your targets.</p>
        <div class="select-actions" id="selectActions">
          <button class="btn btn-ghost btn-sm" id="selectAll">Select All</button>
          <button class="btn btn-ghost btn-sm" id="clearAll">Clear All</button>
        </div>
        <div id="scannerList"><div class="skeleton skeleton-card" style="height:200px"></div></div>
      </div>

      <div class="section">
        <div class="expandable" id="configExpand">
          <div class="expandable-header" id="configToggle">
            <span class="section-title" style="margin:0">Advanced Configuration</span>
            <svg class="expandable-arrow" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
          </div>
          <div class="expandable-content">
            <div class="config-section">
              <div class="form-group">
                <label class="form-label">SSL Labs Email</label>
                <input type="email" class="form-input" id="ssllabsEmail" placeholder="Required for SSL Labs API v4" value="${escapeHtml(cloneData?.config_snapshot?.ssllabs_email || '')}">
                <div class="form-hint">SSL Labs API v4 requires a registered email address.</div>
              </div>
              <div class="form-group" style="margin-bottom:0">
                <label class="checkbox-item" style="padding-left:0">
                  <input type="checkbox" class="checkbox-input" id="ssllabsCache" ${cloneData?.config_snapshot?.ssllabs_usecache !== false ? 'checked' : ''}>
                  <div>
                    <div class="checkbox-label">Use SSL Labs Cache</div>
                    <div class="checkbox-desc">Request cached results (up to 24h old) for faster scans</div>
                  </div>
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="action-row">
        <a href="#/" class="btn btn-ghost">Cancel</a>
        <button class="btn btn-primary btn-lg" id="startScanBtn">
          <svg viewBox="0 0 20 20" fill="currentColor" style="width:18px;height:18px"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd"/></svg>
          Start Scan
        </button>
      </div>
    </div>
  `;

  // State
  const domains = [];
  if (cloneData?.domains) {
    cloneData.domains.forEach(d => addDomain(d));
  }

  // Load scanners
  let scanners = [];
  let selectedScanners = new Set();
  try {
    if (!scannersCache) {
      const data = await api.getScanners();
      scannersCache = data.scanners;
    }
    scanners = scannersCache;
    // Pre-select all by default, or clone selection
    if (cloneData?.tests) {
      selectedScanners = new Set(cloneData.tests);
    } else {
      selectedScanners = new Set(scanners.map(s => s.id));
    }
    renderScannerList();
  } catch (err) {
    document.getElementById('scannerList').innerHTML = `
      <div class="error-card">
        <div class="error-card-title">Failed to load scanners</div>
        <div class="error-card-message">${escapeHtml(err.message)}</div>
      </div>`;
  }

  // --- Domain tag input ---
  const domainInput = document.getElementById('domainInput');
  const domainContainer = document.getElementById('domainContainer');

  domainInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === 'Tab' || e.key === ',') {
      e.preventDefault();
      const val = domainInput.value.trim().replace(/,/g, '');
      if (val) addDomain(val);
      domainInput.value = '';
    }
    if (e.key === 'Backspace' && !domainInput.value && domains.length) {
      removeDomain(domains.length - 1);
    }
  });

  domainInput.addEventListener('paste', (e) => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text');
    text.split(/[\s,;]+/).filter(Boolean).forEach(d => addDomain(d.trim()));
  });

  domainContainer.addEventListener('click', () => domainInput.focus());

  function addDomain(val) {
    val = val.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    if (!val || domains.includes(val)) return;
    domains.push(val);
    const tag = el('span', { className: 'tag-item', dataset: { domain: val } },
      val,
      el('button', {
        className: 'tag-remove',
        onClick: () => { removeDomain(domains.indexOf(val)); }
      }, '\u00d7')
    );
    domainContainer.insertBefore(tag, domainInput);
  }

  function removeDomain(idx) {
    if (idx < 0 || idx >= domains.length) return;
    const val = domains[idx];
    domains.splice(idx, 1);
    const tag = domainContainer.querySelector(`[data-domain="${CSS.escape(val)}"]`);
    if (tag) tag.remove();
  }

  // --- Scanner selection ---
  function renderScannerList() {
    const grouped = groupScannersByCategory(scanners);
    let html = '';
    for (const [category, items] of Object.entries(grouped)) {
      html += `<div class="scanner-category">
        <div class="scanner-category-title">${escapeHtml(category)}</div>
        <div class="scanner-grid">`;
      for (const s of items) {
        const checked = selectedScanners.has(s.id);
        html += `<div class="scanner-card ${checked ? 'selected' : ''}" data-scanner="${escapeHtml(s.id)}">
          <input type="checkbox" class="checkbox-input" ${checked ? 'checked' : ''} data-sid="${escapeHtml(s.id)}">
          <div class="scanner-info">
            <div class="scanner-name">${scannerIcon(s.id)} ${escapeHtml(scannerDisplay(s.id))}</div>
            <div class="scanner-desc">${escapeHtml(s.description)}</div>
          </div>
        </div>`;
      }
      html += '</div></div>';
    }
    document.getElementById('scannerList').innerHTML = html;

    // Bind click handlers
    document.querySelectorAll('.scanner-card').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('.checkbox-input')) return; // handled below
        const sid = card.dataset.scanner;
        toggleScanner(sid);
      });
    });
    document.querySelectorAll('.scanner-card .checkbox-input').forEach(cb => {
      cb.addEventListener('change', () => {
        toggleScanner(cb.dataset.sid);
      });
    });
  }

  function toggleScanner(id) {
    if (selectedScanners.has(id)) {
      selectedScanners.delete(id);
    } else {
      selectedScanners.add(id);
    }
    // Update UI
    const card = document.querySelector(`.scanner-card[data-scanner="${CSS.escape(id)}"]`);
    if (card) {
      card.classList.toggle('selected', selectedScanners.has(id));
      const cb = card.querySelector('.checkbox-input');
      if (cb) cb.checked = selectedScanners.has(id);
    }
  }

  document.getElementById('selectAll').addEventListener('click', () => {
    scanners.forEach(s => selectedScanners.add(s.id));
    renderScannerList();
  });

  document.getElementById('clearAll').addEventListener('click', () => {
    selectedScanners.clear();
    renderScannerList();
  });

  // --- Config expandable ---
  document.getElementById('configToggle').addEventListener('click', () => {
    document.getElementById('configExpand').classList.toggle('open');
  });

  // --- Start scan ---
  document.getElementById('startScanBtn').addEventListener('click', async () => {
    const client = document.getElementById('clientInput').value.trim();
    const email = document.getElementById('ssllabsEmail').value.trim();
    const useCache = document.getElementById('ssllabsCache').checked;

    if (!domains.length) {
      toast('Please add at least one domain', 'error');
      domainInput.focus();
      return;
    }

    if (!selectedScanners.size) {
      toast('Please select at least one scanner', 'error');
      return;
    }

    // Check if ssl_labs is selected but no email
    if (selectedScanners.has('ssl_labs') && !email) {
      toast('SSL Labs requires an email address. Add it in Advanced Configuration or deselect SSL Labs.', 'warning');
      document.getElementById('configExpand').classList.add('open');
      document.getElementById('ssllabsEmail').focus();
      return;
    }

    const btn = document.getElementById('startScanBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Starting...';

    try {
      const payload = {
        domains,
        client: client || 'Web UI Client',
        tests: [...selectedScanners],
        ssllabs_email: email,
        ssllabs_usecache: useCache,
      };
      const result = await api.startScan(payload);
      toast('Scan started successfully', 'success');
      navigate(`/scan/${result.job_id}`);
    } catch (err) {
      toast(`Failed to start scan: ${err.message}`, 'error');
      btn.disabled = false;
      btn.innerHTML = `
        <svg viewBox="0 0 20 20" fill="currentColor" style="width:18px;height:18px"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd"/></svg>
        Start Scan`;
    }
  });
}
