const storageKey = 'codexhost-manager.devices.v1';
const defaults = [];
const $ = (selector) => document.querySelector(selector);
let devices = defaults;
let editing = null;
let generation = 0;
const states = new Map();
const overviews = new Map();
let boundOrigins = new Set();
let proxyPaths = {};
let authenticated = false;
let managerTrust = false;
let connecting = null;

function normalizeUrl(value) {
  if (!value.trim()) return '';
  const url = new URL(value.trim());
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error('请填写不含账号、密码、查询参数的 HTTP(S) 地址');
  }
  const octets = url.hostname.split('.').map(Number);
  const [a, b] = octets;
  const privateIp = octets.length === 4 && octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)
    && (a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 100 && b >= 64 && b <= 127));
  if (url.hostname !== 'localhost' && !privateIp && !url.hostname.endsWith('.ts.net')) {
    throw new Error('仅支持本机、局域网或 Tailscale 地址');
  }
  return url.href;
}

try {
  const stored = localStorage.getItem(storageKey);
  if (stored !== null) {
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed) || parsed.length > 100 || parsed.some((d) => !d || typeof d.id !== 'string'
      || typeof d.name !== 'string' || typeof d.role !== 'string' || typeof d.url !== 'string')
      || new Set(parsed.map((d) => d.id)).size !== parsed.length) throw new Error();
    devices = parsed.map((d) => ({ ...d, url: normalizeUrl(d.url) }));
  }
} catch {
  $('#notice').textContent = '无法读取已保存列表，暂时显示默认设备；保存设备将替换当前浏览器中的列表。';
  $('#notice').hidden = false;
}

function render() {
  const list = $('#devices');
  list.replaceChildren();
  let reachable = 0;
  devices.forEach((device, index) => {
    const card = $('#card-template').content.firstElementChild.cloneNode(true);
    const state = states.get(device.id);
    const status = !device.url ? 'unconfigured' : state?.kind || 'checking';
    if (status === 'reachable') reachable++;
    const labels = { unconfigured: '待配置', checking: '检测中', reachable: '可连接', unreachable: '未连通', error: '检测失败' };
    card.querySelector('.device-index').textContent = String(index + 1).padStart(2, '0');
    card.querySelector('h3').textContent = device.name;
    card.querySelector('.role').textContent = device.role || '未填写用途';
    card.querySelector('.address').textContent = device.url || '尚未设置 CodexHost 地址';
    card.querySelector('.status').dataset.kind = status;
    card.querySelector('.status span').textContent = labels[status] + (status === 'reachable' ? ` · ${state.latency} ms` : '');
    card.querySelector('.edit').addEventListener('click', () => edit(device));
    const overview = overviews.get(device.id);
    const overviewStatus = card.querySelector('.overview-status');
    const connect = card.querySelector('.connect');
    overviewStatus.textContent = overview?.loading ? '读取中…' : overview?.error || (overview?.data
      ? overview.data.errors.length ? '部分接口未就绪' : '汇总已读取' : '尚未读取汇总');
    connect.textContent = !managerTrust && overview?.data?.errors.some((error) => error.code === 'AUTH_REQUIRED') ? '连接设备' : '读取汇总';
    connect.disabled = !device.url || !!overview?.loading;
    connect.addEventListener('click', () => {
      if (!managerTrust && overview?.data?.errors.some((error) => error.code === 'AUTH_REQUIRED')) showConnection(device);
      else void loadOverview(device);
    });
    if (device.url && boundOrigins.has(new URL(device.url).origin)) {
      const disconnect = document.createElement('button');
      disconnect.className = 'disconnect';
      disconnect.textContent = '解除绑定';
      disconnect.type = 'button';
      disconnect.addEventListener('click', async () => {
        overviews.delete(device.id);
        disconnect.disabled = true;
        try {
          const response = await apiFetch('/api/bindings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: device.url, token: '' }) });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error);
          boundOrigins = new Set(result.boundOrigins);
          delete proxyPaths[new URL(device.url).origin];
        } catch {
          $('#notice').textContent = '解除绑定失败，请重试';
          $('#notice').hidden = false;
        }
        render();
      });
      card.querySelector('.card-overview').append(disconnect);
    }
    const link = card.querySelector('.open');
    if (device.url) {
      const path = proxyPaths[new URL(device.url).origin];
      link.href = path || '#';
      if (!path) link.addEventListener('click', (event) => { event.preventDefault(); showConnection(device); });
    }
    else {
      link.textContent = '设置地址 ↗';
      link.href = '#';
      link.addEventListener('click', (event) => { event.preventDefault(); edit(device); });
    }
    list.append(card);
  });
  $('#summary').textContent = `${devices.length} 台设备 / ${reachable} 台可连接`;
  $('#empty').hidden = devices.length !== 0;
  renderOverview();
}

function renderOverview() {
  const container = $('#overview-results');
  container.replaceChildren();
  const labels = { active: '运行中', idle: '空闲', notLoaded: '未加载', systemError: '异常', unknown: '未知' };
  for (const device of devices) {
    const view = overviews.get(device.id);
    if (!view) continue;
    const section = document.createElement('article');
    section.className = 'overview-device';
    const heading = document.createElement('h3');
    heading.textContent = device.name;
    section.append(heading);
    const note = document.createElement('p');
    note.className = 'hint';
    if (view.loading || view.error) {
      note.textContent = view.loading ? '正在读取项目和任务…' : view.error;
      section.append(note);
      container.append(section);
      continue;
    }
    const data = view.data;
    note.textContent = `读取于 ${new Date(data.observedAt).toLocaleTimeString('zh-CN')} · 仅含当前目录范围`;
    section.append(note);
    for (const error of data.errors) {
      const warning = document.createElement('p');
      warning.className = 'notice';
      warning.textContent = error.message;
      section.append(warning);
    }
    const projects = document.createElement('p');
    projects.className = 'project-list';
    projects.textContent = data.projects === null ? '项目：读取失败' : data.projects.length
      ? `项目：${data.projects.map((project) => project.name).join(' / ')}${data.projectsLimited ? '（仅显示前 200 项）' : ''}` : '项目：未返回项目';
    section.append(projects);
    if (data.tasks === null || !data.tasks.length) {
      const empty = document.createElement('p');
      empty.className = 'hint';
      empty.textContent = data.tasks === null ? '任务：读取失败' : '当前目录未返回任务';
      section.append(empty);
    }
    for (const task of data.tasks || []) {
      const row = document.createElement('div');
      row.className = 'task-row';
      const title = document.createElement('a');
      const link = new URL(proxyPaths[new URL(device.url).origin] || '#', location.origin);
      link.searchParams.set('session', task.id);
      title.href = link.href;
      title.target = '_blank';
      title.rel = 'noopener noreferrer';
      title.textContent = task.title;
      const project = document.createElement('span');
      project.className = 'task-project';
      project.textContent = task.project || '未返回项目归属';
      const status = document.createElement('span');
      status.className = 'task-status';
      status.dataset.kind = task.status;
      status.textContent = labels[task.status] || '未知';
      row.append(title, project, status);
      section.append(row);
    }
    if (data.limited) {
      const limited = document.createElement('p');
      limited.className = 'hint';
      limited.textContent = '仅显示本次目录返回的最近任务（最多 100 条），更多历史请打开对应 CodexHost。';
      section.append(limited);
    }
    container.append(section);
  }
  if (!container.children.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = '点击设备的“读取汇总”或“刷新汇总”。需要认证时手动连接，不使用已有浏览器登录信息。';
    container.append(empty);
  }
}

async function loadOverview(device) {
  if (!authenticated) return;
  const request = {};
  overviews.set(device.id, { loading: true, request });
  render();
  let result;
  try {
    const response = await apiFetch('/api/overview', {
      method: 'POST', signal: AbortSignal.timeout(12000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: device.url }),
    });
    if (!response.ok) throw new Error();
    result = { data: await response.json() };
  } catch {
    result = { error: '汇总读取失败，请检查管理台或设备服务后重试' };
  }
  if (overviews.get(device.id)?.request !== request) return;
  overviews.set(device.id, result);
  render();
}

function showConnection(device) {
  if (managerTrust) {
    $('#notice').textContent = '管理台信任未配置，请在后台配置设备信任';
    $('#notice').hidden = false;
    return;
  }
  connecting = device.id;
  $('#connection-device').textContent = `${device.name} · ${device.url}`;
  $('#connection-form').reset();
  $('#connection-error').hidden = true;
  $('#connection').showModal();
}

async function refresh() {
  const current = ++generation;
  states.clear();
  $('#refresh').disabled = true;
  $('#refresh').textContent = '检测中…';
  render();
  await Promise.all(devices.filter((device) => device.url).map(async (device) => {
    let state;
    try {
      const response = await apiFetch(`/api/status?url=${encodeURIComponent(device.url)}`, { signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw new Error();
      const result = await response.json();
      state = { kind: result.reachable ? 'reachable' : 'unreachable', latency: result.latency };
    } catch {
      state = { kind: 'error' };
    }
    if (current !== generation) return;
    states.set(device.id, state);
    render();
  }));
  if (current !== generation) return;
  $('#refresh').disabled = false;
  $('#refresh').textContent = '刷新状态';
}

function edit(device) {
  editing = device?.id ?? null;
  $('#device-form').reset();
  $('#editor-title').textContent = device ? '编辑设备' : '添加设备';
  $('#name').value = device?.name || '';
  $('#role').value = device?.role || '';
  $('#url').value = device?.url || '';
  $('#form-error').hidden = true;
  $('#delete').hidden = !device;
  $('#editor').showModal();
}

async function save(next) {
  try {
    const nextOrigins = new Set(next.filter((device) => device.url).map((device) => new URL(device.url).origin));
    for (const device of devices) {
      if (!device.url) continue;
      const origin = new URL(device.url).origin;
      if (boundOrigins.has(origin) && !nextOrigins.has(origin)) {
        const response = await apiFetch('/api/bindings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: device.url, token: '' }) });
        if (!response.ok) throw new Error();
        boundOrigins = new Set((await response.json()).boundOrigins);
      }
    }
    localStorage.setItem(storageKey, JSON.stringify(next));
  } catch {
    $('#form-error').textContent = '本地存储或绑定更新失败，设备未保存。';
    $('#form-error').hidden = false;
    return;
  }
  overviews.clear();
  devices = next;
  $('#notice').hidden = true;
  $('#editor').close();
  void refresh();
}

$('#device-form').addEventListener('submit', (event) => {
  event.preventDefault();
  try {
    const name = $('#name').value.trim();
    if (!name) throw new Error('请填写设备名称');
    if (!editing && devices.length >= 100) throw new Error('最多保存 100 台设备');
    const device = { id: editing || crypto.randomUUID(), name, role: $('#role').value.trim(), url: normalizeUrl($('#url').value) };
    save(editing ? devices.map((d) => d.id === editing ? device : d) : [...devices, device]);
  } catch (error) {
    $('#form-error').textContent = error.message;
    $('#form-error').hidden = false;
  }
});
$('#delete').addEventListener('click', () => {
  if (confirm('删除此设备入口？不会影响目标电脑或 CodexHost。')) save(devices.filter((d) => d.id !== editing));
});
$('#cancel').addEventListener('click', () => $('#editor').close());
$('#add').addEventListener('click', () => edit());
$('#refresh').addEventListener('click', () => void refresh());
async function loadAll() {
  $('#load-overviews').disabled = true;
  try { await Promise.all(devices.filter((device) => device.url).map(loadOverview)); }
  finally { $('#load-overviews').disabled = false; }
}
$('#load-overviews').addEventListener('click', () => void loadAll());
$('#connection-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const device = devices.find((d) => d.id === connecting);
  const token = $('#access-token').value.trim();
  if (!device || !token) return;
  const submit = $('#connection-form button[type="submit"]');
  submit.disabled = true;
  try {
    const response = await apiFetch('/api/bindings', {
      method: 'POST', signal: AbortSignal.timeout(15000), headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: device.url, name: device.name, role: device.role, token }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    if (!authenticated) return;
    boundOrigins = new Set(result.boundOrigins);
    $('#connection').close();
    const status = await (await apiFetch('/api/auth/status')).json();
    proxyPaths = status.proxyPaths || {};
    void loadOverview(device);
  } catch (error) {
    $('#connection-error').textContent = error.message || '连接失败，未保存令牌';
    $('#connection-error').hidden = false;
  } finally {
    $('#access-token').value = '';
    submit.disabled = false;
  }
});
$('#connection-cancel').addEventListener('click', () => $('#connection').close());
$('#connection').addEventListener('close', () => {
  $('#connection-form').reset();
  connecting = null;
});
function lock() {
  authenticated = false;
  managerTrust = false;
  generation++;
  boundOrigins.clear();
  proxyPaths = {};
  overviews.clear();
  states.clear();
  $('#dashboard').hidden = true;
  $('#login-panel').hidden = false;
  $('#logout').hidden = true;
  $('#manager-token').value = '';
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  $('#devices').replaceChildren();
  $('#overview-results').replaceChildren();
}

async function apiFetch(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) lock();
  return response;
}

async function boot() {
  try {
    const response = await fetch('/api/auth/status');
    const status = await response.json();
    if (!response.ok) throw new Error(status.error);
    if (!status.authenticated) { lock(); return; }
    authenticated = true;
    managerTrust = status.accessMode === 'manager';
    boundOrigins = new Set(status.boundOrigins);
    proxyPaths = status.proxyPaths || {};
    for (const bound of status.boundDevices) {
      if (!devices.some((device) => device.url && new URL(device.url).origin === new URL(bound.url).origin)) {
        devices.push({ id: crypto.randomUUID(), name: bound.name, role: bound.role, url: bound.url });
      }
    }
    $('#login-panel').hidden = true;
    $('#dashboard').hidden = false;
    $('#logout').hidden = false;
    void refresh();
    void loadAll();
  } catch (error) {
    lock();
    $('#login-error').textContent = error.message || '管理台连接失败';
    $('#login-error').hidden = false;
  }
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#login-submit').disabled = true;
  $('#login-error').hidden = true;
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: $('#manager-token').value }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    $('#manager-token').value = '';
    await boot();
  } catch (error) {
    $('#login-error').textContent = error.message || '登录失败';
    $('#login-error').hidden = false;
  } finally { $('#login-submit').disabled = false; }
});
$('#logout').addEventListener('click', async () => {
  const response = await fetch('/api/auth/logout', { method: 'POST' });
  if (response.ok) { lock(); await boot(); }
});
void boot();
