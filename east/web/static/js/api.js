/**
 * EAST API Client
 * Centralized HTTP client for all backend communication.
 * Supports AbortController, content-type verification, and retry logic.
 */

const BASE = '';  // Same origin
const DEBUG = typeof window !== 'undefined' && window.EAST_DEBUG;

function log(...args) {
  if (DEBUG) console.log('[EAST:api]', ...args);
}

/**
 * Check that a response has a JSON content-type before parsing.
 * Returns parsed JSON or throws a descriptive error.
 */
async function parseJsonSafe(res) {
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('application/json')) {
    // Likely an auth page, Cloudflare challenge, or proxy redirect
    const preview = await res.text().catch(() => '');
    const isHtml = ct.includes('text/html') || preview.trimStart().startsWith('<');
    if (isHtml) {
      throw new Error('Received HTML instead of JSON — possible auth redirect or proxy page');
    }
    throw new Error(`Unexpected content-type: ${ct || 'none'}`);
  }
  return res.json();
}

async function request(method, path, body = null, signal = null) {
  const opts = {
    method,
    headers: {},
  };
  if (signal) opts.signal = signal;
  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  log(method, path);
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) {
    const detail = await parseJsonSafe(res).catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || `HTTP ${res.status}`);
  }
  return parseJsonSafe(res);
}


async function requestMultipart(method, path, formData, signal = null) {
  const opts = {
    method,
    body: formData,
  };
  if (signal) opts.signal = signal;
  log(method, path, '[multipart]');
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) {
    const detail = await parseJsonSafe(res).catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || `HTTP ${res.status}`);
  }
  return parseJsonSafe(res);
}

export const api = {
  /** Fetch available scanners from the backend. */
  getScanners(signal) {
    return request('GET', '/api/scanners', null, signal);
  },

  /** Start a new scan job. */
  startScan(payload, signal) {
    return request('POST', '/api/scan', payload, signal);
  },

  /** List uploaded logos for scan branding. */
  listLogos(signal) {
    return request('GET', '/api/logos', null, signal);
  },

  /** Upload a logo image for scan branding. */
  uploadLogo(file, signal) {
    const formData = new FormData();
    formData.append('file', file);
    return requestMultipart('POST', '/api/logos', formData, signal);
  },

  /** List jobs with optional filters. */
  listJobs(params = {}, signal) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v != null && v !== '') qs.set(k, v);
    }
    const q = qs.toString();
    return request('GET', `/api/jobs${q ? '?' + q : ''}`, null, signal);
  },

  /** Get a single job with full details and logs. */
  getJob(jobId, signal) {
    return request('GET', `/api/jobs/${jobId}`, null, signal);
  },

  /**
   * Get a single job with one automatic retry on failure.
   * Handles transient errors, auth redirects, slow backend starts.
   */
  async getJobWithRetry(jobId, signal) {
    try {
      return await request('GET', `/api/jobs/${jobId}`, null, signal);
    } catch (err) {
      if (signal && signal.aborted) throw err;
      log('getJob retry after error:', err.message);
      // Wait briefly, then retry once
      await new Promise(r => setTimeout(r, 800));
      if (signal && signal.aborted) throw new DOMException('Aborted', 'AbortError');
      return request('GET', `/api/jobs/${jobId}`, null, signal);
    }
  },

  /** Get results as JSON for download. */
  getResults(jobId, signal) {
    return request('GET', `/api/jobs/${jobId}/results`, null, signal);
  },

  /** Download report URL (returns the URL string, not fetched). */
  downloadUrl(jobId) {
    return `/jobs/${jobId}/download`;
  },

  /** Download ZIP package URL (report + test artifacts). */
  downloadPackageUrl(jobId) {
    return `/jobs/${jobId}/download-package`;
  },

  /** Delete a job and any generated report artifact. */
  deleteJob(jobId, signal) {
    return request('DELETE', `/api/jobs/${jobId}`, null, signal);
  },

  /**
   * Connect to the SSE log stream for a job.
   * Returns an EventSource instance. Caller must close it.
   * @param {string} jobId
   * @param {function} onMessage - called with {line, status}
   * @param {function} onError - called on stream error
   */
  streamLogs(jobId, onMessage, onError) {
    const es = new EventSource(`/jobs/${jobId}/logs`);
    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch (e) {
        log('SSE parse error:', e.message);
      }
    };
    es.onerror = () => {
      if (onError) onError();
      es.close();
    };
    return es;
  },
};
