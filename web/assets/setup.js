(function () {
  const debugLog = document.getElementById('debug-log');
  const draftKey = 'connector.setup.draft';

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

    return { basePath, fetchJSON };
  }

  const connectorApp = window.connectorApp || fallbackConnectorApp();
  const basePath = connectorApp.basePath || '';
  const fetchJSON = async (path, options) => {
    const opts = options || {};
    const method = opts.method || 'GET';
    appendDebug(`HTTP ${method} ${path}`, { basePath });
    try {
      const result = await connectorApp.fetchJSON(path, opts);
      appendDebug(`HTTP ${method} ${path} succeeded`);
      return result;
    } catch (error) {
      appendDebug(`HTTP ${method} ${path} failed`, error.message || String(error));
      throw error;
    }
  };

  const form = document.getElementById('setup-form');
  const discoverButton = document.getElementById('discover-button');
  const saveButton = document.getElementById('save-button');
  const syncButton = document.getElementById('sync-button');
  const notice = document.getElementById('notice');

  appendDebug('Setup page booting', {
    path: window.location.pathname,
    basePath,
    hasSharedApp: Boolean(window.connectorApp),
  });

  function setNotice(message, kind) {
    const noticeKind = kind || 'ok';
    const klass = noticeKind === 'error'
      ? 'hn-alert--err'
      : noticeKind === 'muted'
        ? 'hn-muted'
        : 'hn-alert--ok';
    notice.className = `hn-alert hn-small ${klass}`;
    notice.textContent = message;
    appendDebug(`Notice (${noticeKind})`, message);
  }

  function readFormValues() {
    return {
      gateway_host: document.getElementById('gateway_host').value.trim(),
      api_key: document.getElementById('api_key').value.trim(),
      poll_interval_sec: Number(document.getElementById('poll_interval_sec').value || 60),
    };
  }

  function applyFormValues(values, preserveExisting) {
    const data = values || {};
    const keepExisting = Boolean(preserveExisting);
    const gatewayHost = document.getElementById('gateway_host');
    const apiKey = document.getElementById('api_key');
    const pollInterval = document.getElementById('poll_interval_sec');

    if (!keepExisting || data.gateway_host) {
      gatewayHost.value = data.gateway_host || gatewayHost.value || '';
    }
    if (!keepExisting || data.api_key) {
      apiKey.value = data.api_key || apiKey.value || '';
    }
    if (!keepExisting || data.poll_interval_sec) {
      pollInterval.value = data.poll_interval_sec || pollInterval.value || 60;
    }
  }

  function saveDraft() {
    const values = readFormValues();
    localStorage.setItem(draftKey, JSON.stringify(values));
    appendDebug('Saved local draft', {
      gateway_host: values.gateway_host,
      poll_interval_sec: values.poll_interval_sec,
      api_key_length: values.api_key.length,
    });
  }

  function restoreDraft() {
    const raw = localStorage.getItem(draftKey);
    if (!raw) {
      appendDebug('No local draft found');
      return;
    }
    try {
      const parsed = JSON.parse(raw);
      applyFormValues(parsed, false);
      appendDebug('Restored local draft', {
        gateway_host: parsed.gateway_host || '',
        poll_interval_sec: parsed.poll_interval_sec || 60,
        api_key_length: (parsed.api_key || '').length,
      });
    } catch (error) {
      appendDebug('Failed to restore draft', error.message || String(error));
    }
  }

  async function loadSetup() {
    restoreDraft();
    try {
      const config = await fetchJSON('/api/setup');
      appendDebug('Loaded setup payload', {
        gateway_host: config.gateway_host || '',
        poll_interval_sec: config.poll_interval_sec || 60,
        api_key_length: (config.api_key || '').length,
      });
      applyFormValues(config, true);
      saveDraft();
      setNotice('Loaded current Connector setup.', 'muted');
    } catch (error) {
      setNotice(error.message, 'error');
    }
  }

  discoverButton.addEventListener('click', async () => {
    discoverButton.disabled = true;
    setNotice('Scanning the LAN for Connector endpoints…', 'muted');
    try {
      appendDebug('Starting LAN discovery');
      const result = await fetchJSON('/api/discover');
      const gateways = Array.isArray(result.gateways) ? result.gateways : [];
      const hosts = Array.isArray(result.hosts) ? result.hosts.filter(Boolean) : [];
      appendDebug('LAN discovery result', {
        gateways: gateways.length,
        hosts,
      });
      if (!hosts.length) {
        setNotice('No Connector endpoints responded to discovery. If your blinds do not advertise on the LAN, enter the host manually.', 'error');
        return;
      }
      document.getElementById('gateway_host').value = hosts.join(', ');
      saveDraft();
      const details = gateways.map((gateway) => {
        const parts = [gateway.host];
        if (gateway.gateway_mac) parts.push(gateway.gateway_mac);
        if (gateway.device_count != null) parts.push(`${gateway.device_count} devices`);
        return parts.filter(Boolean).join(' · ');
      }).join(' | ');
      setNotice(`Discovered ${hosts.length} Connector endpoint(s). Review the hosts and save to verify. ${details}`, 'ok');
    } catch (error) {
      setNotice(`Discovery failed: ${error.message}`, 'error');
    } finally {
      discoverButton.disabled = false;
    }
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    discoverButton.disabled = true;
    saveButton.disabled = true;
    setNotice('Saving settings and verifying bridge access…', 'muted');
    try {
      const payload = readFormValues();
      saveDraft();
      appendDebug('Submitting setup payload', {
        gateway_host: payload.gateway_host,
        poll_interval_sec: payload.poll_interval_sec,
        api_key_length: payload.api_key.length,
      });
      const result = await fetchJSON('/api/setup', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      appendDebug('Setup verification result', result);
      const gateway = result.gateway || {};
      const details = [
        `Saved successfully for ${result.gateway && result.gateway.host ? result.gateway.host : payload.gateway_host}.`,
        `Verified ${result.device_count} device(s).`,
        gateway.firmware_version ? `Firmware ${gateway.firmware_version}.` : '',
      ].filter(Boolean).join(' ');
      setNotice(details, 'ok');
    } catch (error) {
      setNotice(`Save failed: ${error.message}`, 'error');
    } finally {
      discoverButton.disabled = false;
      saveButton.disabled = false;
    }
  });

  syncButton.addEventListener('click', async () => {
    syncButton.disabled = true;
    setNotice('Triggering a background sync…', 'muted');
    try {
      appendDebug('Manual sync requested');
      await fetchJSON('/api/sync', { method: 'POST' });
      setNotice('Sync requested successfully.', 'ok');
    } catch (error) {
      setNotice(`Sync failed: ${error.message}`, 'error');
    } finally {
      syncButton.disabled = false;
    }
  });

  form.addEventListener('input', () => {
    saveDraft();
  });

  loadSetup();
})();