(function () {
  const debugLog = document.getElementById('debug-log');

  function appendDebug(message, details) {
    if (!debugLog) return;
    const timestamp = new Date().toLocaleTimeString();
    const suffix = details === undefined
      ? ''
      : ` ${typeof details === 'string' ? details : JSON.stringify(details)}`;
    debugLog.textContent += `[${timestamp}] ${message}${suffix}\n`;
    debugLog.scrollTop = debugLog.scrollHeight;
  }

  window.addEventListener('error', (event) => {
    appendDebug('Window error:', event.message || 'unknown error');
  });

  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason && event.reason.message ? event.reason.message : String(event.reason || 'unknown rejection');
    appendDebug('Unhandled promise rejection:', reason);
  });

  function fallbackConnectorApp() {
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

    function authHeaders(extra) {
      const value = token();
      return value ? { ...extra, Authorization: `Bearer ${value}` } : extra;
    }

    function withBasePath(path) {
      if (!path.startsWith('/')) return path;
      return `${basePath}${path}`;
    }

    function clamp(value, min, max) {
      return Math.max(min, Math.min(max, value));
    }

    function formatAgo(value) {
      if (!value) return 'never';
      const delta = Math.round((Date.now() - new Date(value).getTime()) / 1000);
      if (delta < 60) return `${delta}s ago`;
      if (delta < 3600) return `${Math.round(delta / 60)}m ago`;
      return `${Math.round(delta / 3600)}h ago`;
    }

    async function fetchJSON(path, options) {
      const opts = options || {};
      const headers = {
        ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
        ...(opts.headers || {}),
      };
      const response = await fetch(withBasePath(path), {
        credentials: 'include',
        ...opts,
        headers: authHeaders(headers),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || `Request failed with ${response.status}`);
      }
      return data;
    }

    return { basePath, fetchJSON, formatAgo, clamp };
  }

  const connectorApp = window.connectorApp || fallbackConnectorApp();
  const fetchJSON = async (path, options) => {
    const opts = options || {};
    const method = opts.method || 'GET';
    appendDebug(`HTTP ${method} ${path}`);
    try {
      const result = await connectorApp.fetchJSON(path, opts);
      appendDebug(`HTTP ${method} ${path} succeeded`);
      return result;
    } catch (error) {
      appendDebug(`HTTP ${method} ${path} failed`, error.message || String(error));
      throw error;
    }
  };
  const formatAgo = connectorApp.formatAgo;
  const clamp = connectorApp.clamp;
  const statusText = connectorApp.statusText || ((value) => value == null ? 'Unknown' : String(value));
  const isMovingStatus = connectorApp.isMovingStatus || ((value) => {
    const text = statusText(value).toLowerCase();
    return text.includes('opening') || text.includes('closing');
  });
  const batteryText = connectorApp.batteryText || ((value) => typeof value === 'number' ? `${Math.round(value)}%` : '');
  const numberValue = connectorApp.numberValue || ((value, fallback = 0) => {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallback;
  });
  const notice = document.getElementById('notice');
  const summaryGrid = document.getElementById('summary-grid');
  const deviceList = document.getElementById('device-list');
  const gatewayMeta = document.getElementById('gateway-meta');
  const refreshButton = document.getElementById('refresh-button');
  const gatewayDot = document.getElementById('gateway-dot');
  const gatewayPillText = document.getElementById('gateway-pill-text');

  appendDebug('Dashboard page booting', {
    path: window.location.pathname,
    hasSharedApp: Boolean(window.connectorApp),
  });

  function setNotice(message, isError, quiet) {
    notice.className = `hn-alert hn-small ${quiet ? 'hn-muted' : isError ? 'hn-alert--err' : 'hn-alert--ok'}`;
    notice.textContent = message;
    appendDebug(`Notice (${isError ? 'error' : quiet ? 'muted' : 'ok'})`, message);
  }

  async function postCommand(deviceId, state) {
    await fetchJSON(`/api/device/${encodeURIComponent(deviceId)}/command`, {
      method: 'POST',
      body: JSON.stringify({ state }),
    });
    await loadSnapshot();
  }

  function renderSummary(snapshot) {
    const devices = snapshot.devices || [];
    const online = devices.filter((device) => device.online).length;
    const moving = devices.filter((device) => isMovingStatus(device.status)).length;
    const average = devices.length
      ? Math.round(devices.reduce((acc, device) => acc + numberValue(device.open_percent, 0), 0) / devices.length)
      : 0;
    const items = [
      { label: 'Configured', value: snapshot.configured ? 'Yes' : 'No', detail: snapshot.gateway && snapshot.gateway.host ? snapshot.gateway.host : 'Setup required' },
      { label: 'Online', value: `${online}/${devices.length}`, detail: snapshot.gateway && snapshot.gateway.status ? snapshot.gateway.status : 'Unknown' },
      { label: 'Moving', value: `${moving}`, detail: 'Blinds currently in motion' },
      { label: 'Average open', value: `${average}%`, detail: 'Across all discovered blinds' },
    ];
    summaryGrid.innerHTML = items.map((item) => `
      <article class="hn-kpi">
        <div class="hn-kpi__label">${item.label}</div>
        <div class="hn-kpi__value">${item.value}</div>
        <p class="hn-kpi__detail hn-muted hn-small">${item.detail}</p>
      </article>
    `).join('');
  }

  function renderGateway(snapshot) {
    const gateway = snapshot.gateway || {};
    gatewayPillText.textContent = gateway.available ? 'Gateway: online' : 'Gateway: offline';
    gatewayDot.classList.remove('hn-dot--ok', 'hn-dot--err');
    gatewayDot.classList.add(gateway.available ? 'hn-dot--ok' : 'hn-dot--err');
    const parts = [
      gateway.host ? `Host: ${gateway.host}` : 'Host unknown',
      gateway.firmware_version ? `Firmware ${gateway.firmware_version}` : '',
      gateway.last_sync_at ? `Last sync ${formatAgo(gateway.last_sync_at)}` : '',
    ].filter(Boolean);
    gatewayMeta.textContent = parts.join(' · ');
  }

  function renderDevices(snapshot) {
    const devices = snapshot.devices || [];
    if (!devices.length) {
      deviceList.innerHTML = '<div class="hn-empty">No blinds discovered yet. Save your gateway details in setup and trigger a sync.</div>';
      return;
    }
    deviceList.innerHTML = devices.map((device) => {
      const open = clamp(numberValue(device.open_percent, 0), 0, 100);
      const status = statusText(device.status);
      const tilt = device.tilt_percent == null ? '' : `
        <div class="hn-range">
          <label class="hn-label">Tilt
            <input type="range" min="0" max="100" step="1" value="${Math.round(device.tilt_percent)}" data-device="${device.id}" data-kind="tilt" />
          </label>
          <output>${Math.round(device.tilt_percent)}%</output>
        </div>`;
      const battery = device.battery_level != null ? ` · Battery ${batteryText(device.battery_level)}` : '';
      return `
        <article class="hn-device">
          <div class="hn-device__header">
            <div>
              <h3 class="hn-device__title">${device.name}</h3>
              <p class="hn-device__meta">${device.blind_type || device.device_type || 'Blind'} · ${device.mac}</p>
            </div>
            <span class="hn-pill"><span class="hn-dot ${device.online ? 'hn-dot--ok' : 'hn-dot--err'}"></span><span>${status}</span></span>
          </div>
          <div class="hn-progress"><span style="width:${open}%"></span></div>
          <p class="hn-device__summary hn-muted hn-small">Open ${Math.round(open)}%${battery}</p>
          <div class="hn-range">
            <label class="hn-label">Position
              <input type="range" min="0" max="100" step="1" value="${Math.round(open)}" data-device="${device.id}" data-kind="position" />
            </label>
            <output>${Math.round(open)}%</output>
          </div>
          ${tilt}
          <div class="hn-actions">
            <button class="hn-btn hn-btn--primary" data-device="${device.id}" data-action="open">Open</button>
            <button class="hn-btn" data-device="${device.id}" data-action="stop">Stop</button>
            <button class="hn-btn" data-device="${device.id}" data-action="close">Close</button>
            <button class="hn-btn" data-device="${device.id}" data-action="favorite">Favorite</button>
          </div>
        </article>
      `;
    }).join('');

    deviceList.querySelectorAll('button[data-action]').forEach((button) => {
      button.addEventListener('click', async () => {
        button.disabled = true;
        try {
          await postCommand(button.dataset.device, { action: button.dataset.action });
          setNotice('Command sent.');
        } catch (error) {
          setNotice(error.message, true);
        } finally {
          button.disabled = false;
        }
      });
    });

    deviceList.querySelectorAll('input[type="range"]').forEach((input) => {
      input.addEventListener('input', () => {
        input.closest('.hn-range').querySelector('output').textContent = `${input.value}%`;
      });
      input.addEventListener('change', async () => {
        const state = input.dataset.kind === 'tilt'
          ? { tilt_percent: Number(input.value) }
          : { open_percent: Number(input.value) };
        try {
          await postCommand(input.dataset.device, state);
          setNotice('Position updated.');
        } catch (error) {
          setNotice(error.message, true);
        }
      });
    });
  }

  async function loadSnapshot() {
    try {
      const snapshot = await fetchJSON('/api/realtime/snapshot');
      appendDebug('Snapshot loaded', {
        configured: Boolean(snapshot.configured),
        devices: Array.isArray(snapshot.devices) ? snapshot.devices.length : 0,
        gateway_available: Boolean(snapshot.gateway && snapshot.gateway.available),
      });
      renderGateway(snapshot);
      renderSummary(snapshot);
      renderDevices(snapshot);
      const hasGatewayError = Boolean(snapshot.gateway && snapshot.gateway.last_error);
      setNotice(hasGatewayError ? snapshot.gateway.last_error : 'Connector dashboard ready.', hasGatewayError, !hasGatewayError);
    } catch (error) {
      setNotice(error.message, true);
    }
  }

  refreshButton.addEventListener('click', async () => {
    refreshButton.disabled = true;
    try {
      await fetchJSON('/api/sync', { method: 'POST' });
      await loadSnapshot();
    } catch (error) {
      setNotice(error.message, true);
    } finally {
      refreshButton.disabled = false;
    }
  });

  loadSnapshot();
  setInterval(loadSnapshot, 10000);
})();