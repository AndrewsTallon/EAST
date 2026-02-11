/**
 * Shared utilities: DOM helpers, formatting, etc.
 */

/** Create an element with optional attributes and children. */
export function el(tag, attrs = {}, ...children) {
  const elem = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'className') elem.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(elem.style, v);
    else if (k.startsWith('on')) elem.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(elem.dataset, v);
    else if (k === 'htmlContent') elem.innerHTML = v;
    else elem.setAttribute(k, v);
  }
  for (const child of children) {
    if (child == null) continue;
    if (typeof child === 'string') elem.appendChild(document.createTextNode(child));
    else if (child instanceof Node) elem.appendChild(child);
  }
  return elem;
}

/** Format a date string to a human-readable format. */
export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

/** Format a short date. */
export function formatDateShort(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

/** Duration between two ISO dates in human-readable form. */
export function formatDuration(startIso, endIso) {
  if (!startIso || !endIso) return '—';
  const ms = new Date(endIso) - new Date(startIso);
  if (ms < 1000) return `${ms}ms`;
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const remSecs = secs % 60;
  return `${mins}m ${remSecs}s`;
}

/** Elapsed seconds from start to now. */
export function elapsedSince(startIso) {
  const ms = Date.now() - new Date(startIso).getTime();
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}

/** Status badge HTML. */
export function statusBadge(status) {
  const labels = {
    queued: 'Queued',
    running: 'Running',
    completed: 'Completed',
    failed: 'Failed',
    success: 'Passed',
  };
  const label = labels[status] || status;
  return `<span class="badge badge-${status}"><span class="badge-dot"></span>${label}</span>`;
}

/** Grade badge HTML. */
export function gradeBadge(grade) {
  if (!grade) return '<span class="grade grade-f">—</span>';
  const letter = grade.charAt(0).toUpperCase();
  const cls = letter === 'A' ? 'a' : letter === 'B' ? 'b' : letter === 'C' ? 'c' : letter === 'D' ? 'd' : 'f';
  return `<span class="grade grade-${cls}">${escapeHtml(grade)}</span>`;
}

/** Score color class. */
export function scoreClass(score) {
  if (score == null) return '';
  if (score >= 70) return 'good';
  if (score >= 40) return 'fair';
  return 'poor';
}

/** Escape HTML entities. */
export function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

/** Show a toast notification. */
export function toast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const t = el('div', { className: `toast ${type}` }, message);
  container.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transform = 'translateX(100px)';
    t.style.transition = 'all 300ms ease-in';
    setTimeout(() => t.remove(), 300);
  }, 4000);
}

/** Scanner metadata for nice display names and categories. */
const SCANNER_META = {
  ssl_labs:             { display: 'SSL/TLS Analysis',       category: 'Encryption & Certificates', icon: '🔒' },
  mozilla_observatory:  { display: 'Mozilla Observatory',    category: 'Encryption & Certificates', icon: '🛡' },
  dns_lookup:           { display: 'DNS Records & DNSSEC',   category: 'DNS & Infrastructure',      icon: '🌐' },
  email_auth:           { display: 'Email Authentication',   category: 'Email Security',            icon: '📧' },
  spf:                  { display: 'SPF Check',              category: 'Email Security',            icon: '📧' },
  dkim:                 { display: 'DKIM Check',             category: 'Email Security',            icon: '📧' },
  dmarc:                { display: 'DMARC Check',            category: 'Email Security',            icon: '📧' },
  blacklist:            { display: 'Blacklist Check',        category: 'Reputation',                icon: '🚫' },
  subdomains:           { display: 'Subdomain Enumeration',  category: 'DNS & Infrastructure',      icon: '🔍' },
  security_headers:     { display: 'Security Headers',       category: 'Web Security',              icon: '🔐' },
  performance:          { display: 'Performance (Lighthouse)', category: 'Performance',             icon: '⚡' },
  cookies:              { display: 'Cookie Security',        category: 'Web Security',              icon: '🍪' },
  open_ports:           { display: 'Open Ports Scan',        category: 'Network',                   icon: '🔌' },
  screenshots:          { display: 'Screenshot Capture',     category: 'Visual',                    icon: '📸' },
};

export function scannerDisplay(id) {
  return SCANNER_META[id]?.display || id;
}

export function scannerCategory(id) {
  return SCANNER_META[id]?.category || 'Other';
}

export function scannerIcon(id) {
  return SCANNER_META[id]?.icon || '🔧';
}

/** Group scanners by category, preserving backend order within each group. */
export function groupScannersByCategory(scanners) {
  const groups = {};
  for (const s of scanners) {
    const cat = scannerCategory(s.id);
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(s);
  }
  return groups;
}

/** Debounce a function. */
export function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}
