const state = { snapshot: null };

const basePath = (() => {
  const pathName = window.location.pathname || '';
  for (const marker of ['/ui/', '/widgets/', '/.well-known/']) {
    const idx = pathName.indexOf(marker);
    if (idx >= 0) return pathName.slice(0, idx);
  }
  return '';
})();

function getCookie(name) {
  const parts = (document.cookie || '').split(';').map((value) => value.trim());
  const key = `${name}=`;
  const hit = parts.find((item) => item.startsWith(key));
  return hit ? decodeURIComponent(hit.slice(key.length)) : '';
}

function token() {
  return getCookie('auth_token') || localStorage.getItem('hn.jwt') || localStorage.getItem('auth_token') || '';
}

function authHeaders(extra = {}) {
  const value = token();
  return value ? { ...extra, Authorization: `Bearer ${value}` } : extra;
}

function withBasePath(path) {
  if (!path.startsWith('/')) return path;
  return `${basePath}${path}`;
}

async function fetchJSON(path, options = {}) {
  const headers = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers || {}),
  };
  const res = await fetch(withBasePath(path), {
    credentials: 'include',
    ...options,
    headers: authHeaders(headers),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed with ${res.status}`);
  }
  return data;
}

function formatAgo(value) {
  if (!value) return 'never';
  const delta = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.round(delta / 60)}m ago`;
  return `${Math.round(delta / 3600)}h ago`;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function numberValue(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function formatValue(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number') return Number.isInteger(value) ? `${value}` : `${Math.round(value * 10) / 10}`;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (Array.isArray(value)) return value.map(formatValue).filter(Boolean).join(' · ');
  if (typeof value === 'object') {
    return Object.entries(value)
      .map(([key, item]) => `${key}: ${formatValue(item)}`)
      .filter(Boolean)
      .join(' · ');
  }
  return String(value);
}

function statusText(status) {
  return formatValue(status) || 'Unknown';
}

function isMovingStatus(status) {
  const text = statusText(status).toLowerCase();
  return text.includes('opening') || text.includes('closing');
}

function batteryText(value) {
  if (value == null) return '';
  if (typeof value === 'number') return `${Math.round(value)}%`;
  return formatValue(value);
}

window.connectorApp = {
  state,
  basePath,
  token,
  authHeaders,
  fetchJSON,
  formatAgo,
  clamp,
  numberValue,
  formatValue,
  statusText,
  isMovingStatus,
  batteryText,
  withBasePath,
};
