/**
 * EAST API Client
 * Centralized HTTP client for all backend communication.
 */

const BASE = '';  // Same origin

async function request(method, path, body = null) {
  const opts = {
    method,
    headers: {},
  };
  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  /** Fetch available scanners from the backend. */
  getScanners() {
    return request('GET', '/api/scanners');
  },

  /** Start a new scan job. */
  startScan(payload) {
    return request('POST', '/api/scan', payload);
  },

  /** List jobs with optional filters. */
  listJobs(params = {}) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v != null && v !== '') qs.set(k, v);
    }
    const q = qs.toString();
    return request('GET', `/api/jobs${q ? '?' + q : ''}`);
  },

  /** Get a single job with full details and logs. */
  getJob(jobId) {
    return request('GET', `/api/jobs/${jobId}`);
  },

  /** Get results as JSON for download. */
  getResults(jobId) {
    return request('GET', `/api/jobs/${jobId}/results`);
  },

  /** Download report URL (returns the URL string, not fetched). */
  downloadUrl(jobId) {
    return `/jobs/${jobId}/download`;
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
        // ignore parse errors
      }
    };
    es.onerror = () => {
      if (onError) onError();
      es.close();
    };
    return es;
  },
};
