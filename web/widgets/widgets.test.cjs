const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const webDir = path.resolve(__dirname, '..');
const sharedScript = fs.readFileSync(path.join(webDir, 'assets/app.js'), 'utf8');

async function loadWidget(name, devices) {
  const html = fs.readFileSync(path.join(__dirname, name, 'index.html'), 'utf8');
  const script = html.match(/<script>\s*([\s\S]*?)\s*<\/script>/);
  assert.ok(script, 'widget inline script exists');

  const elements = new Map();
  const requests = [];
  const document = {
    cookie: '',
    getElementById(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          innerHTML: '',
          textContent: '',
          value: '65',
          listeners: {},
          addEventListener(event, handler) { this.listeners[event] = handler; },
          querySelectorAll() { return []; },
        });
      }
      return elements.get(id);
    },
  };
  const context = vm.createContext({
    document,
    window: { location: { pathname: `/widgets/${name}/`, href: `http://localhost/widgets/${name}/` } },
    localStorage: { getItem() { return null; } },
    URL,
    setInterval() {},
    async fetch(url, options) {
      requests.push({ url, options });
      return { ok: true, async json() { return { devices }; } };
    },
  });
  vm.runInContext(sharedScript, context);
  vm.runInContext(script[1], context);
  await new Promise(setImmediate);
  return { elements, requests };
}

const blind = { id: 'one', name: 'Living room blind', status: 'Open', online: true, open_percent: 65 };

test('overview widget renders devices with the shared script loaded', async () => {
  const { elements } = await loadWidget('connector-overview', [blind]);
  assert.match(elements.get('content').innerHTML, /Living room blind/);
  assert.match(elements.get('content').innerHTML, /65%/);
});

test('overview widget renders multiple devices in its list', async () => {
  const { elements } = await loadWidget('connector-overview', [blind, { ...blind, id: 'two', name: 'Bedroom blind', open_percent: 30 }]);
  assert.match(elements.get('content').innerHTML, /Living room blind/);
  assert.match(elements.get('content').innerHTML, /Bedroom blind/);
  assert.match(elements.get('content').innerHTML, /30%/);
});

test('widgets expose their scoped layout classes', () => {
  for (const [name, layout] of [['connector-overview', 'overview'], ['connector-device', 'device']]) {
    const html = fs.readFileSync(path.join(__dirname, name, 'index.html'), 'utf8');
    assert.match(html, /<html\b[^>]*class="hn-widget-root"/);
    assert.match(html, new RegExp(`class="hn-widget-page hn-widget-page--${layout}"`));
  }
});

test('device widget renders controls and sends commands', async () => {
  const { elements, requests } = await loadWidget('connector-device', [blind]);
  assert.match(elements.get('content').innerHTML, /Living room blind/);
  await elements.get('close').listeners.click();
  const command = requests.find((request) => request.options.method === 'POST');
  assert.equal(command.url, '/api/device/one/command');
  assert.deepEqual(JSON.parse(command.options.body), { state: { action: 'close' } });
});

test('widgets show empty states when no devices are available', async () => {
  for (const name of ['connector-overview', 'connector-device']) {
    const { elements } = await loadWidget(name, []);
    assert.match(elements.get('content').innerHTML, /No (blinds available|matching blind found)/);
  }
});

test('Connector widgets request compact dashboard sizes', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(webDir, '../manifest/homenavi-integration.json'), 'utf8'));
  assert.deepEqual(manifest.widgets.map((widget) => widget.default_size_hint), ['sm', 'sm']);
});