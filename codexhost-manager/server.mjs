import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createConnection, isIPv4 } from 'node:net';
import { lookup } from 'node:dns';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname, join } from 'node:path';
import { makeAuth } from './auth.mjs';
import { makeProxy, browserBridge, deviceKey } from './proxy.mjs';
import { makeManagerAccess } from './manager-access.mjs';

function isPrivate(address) {
  if (!isIPv4(address)) return false;
  const [a, b] = address.split('.').map(Number);
  return a === 127 || a === 10 || (a === 192 && b === 168)
    || (a === 172 && b >= 16 && b <= 31) || (a === 100 && b >= 64 && b <= 127);
}

function privateLookup(host, options, callback) {
  lookup(host === 'localhost' ? '127.0.0.1' : host, { family: 4 }, (error, address, family) => {
    if (error || !isPrivate(address)) callback(error || new Error('地址不在私有网络内'));
    else if (options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  });
}

export function parseTarget(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error('请使用不含账号、密码、查询参数的 HTTP(S) 地址');
  }
  if (url.hostname !== 'localhost' && !isPrivate(url.hostname) && !url.hostname.endsWith('.ts.net')) {
    throw new Error('仅支持本机、局域网或 Tailscale 地址');
  }
  return url;
}

export function probe(value, timeout = 2500) {
  const url = parseTarget(value);
  return new Promise((done) => {
    const started = performance.now();
    let finished = false;
    const socket = createConnection({
      host: url.hostname === 'localhost' ? '127.0.0.1' : url.hostname,
      port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)),
      // Pin DNS resolution to a private address; never probe a public destination.
      lookup: privateLookup,
    });
    const timer = setTimeout(() => finish(false), timeout);
    function finish(reachable) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      socket.destroy();
      done({ reachable, latency: reachable ? Math.round(performance.now() - started) : null });
    }
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

function rpc(url, method, token, timeout) {
  return new Promise((done, reject) => {
    const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(new URL('/api/ch/v1/rpc', url), {
      method: 'POST', agent: false, family: 4, lookup: privateLookup,
      signal: AbortSignal.timeout(timeout),
      headers: { 'Content-Type': 'application/json', ...(typeof token === 'function' ? token('POST', '/api/ch/v1/rpc') : token ? { Authorization: `Bearer ${token}` } : {}) },
    }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error([401, 403].includes(response.statusCode) ? 'AUTH_REQUIRED'
          : response.statusCode === 429 ? 'RATE_LIMITED' : 'UNSUPPORTED'));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 4 * 1024 * 1024) {
          reject(new Error('RESPONSE_TOO_LARGE'));
          request.destroy();
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        try {
          const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (value.error || !value.result || typeof value.result !== 'object') throw new Error('UNSUPPORTED');
          done(value.result);
        } catch { reject(new Error('UNSUPPORTED')); }
      });
    });
    request.on('error', () => reject(new Error('UNREACHABLE')));
    request.end(JSON.stringify({ method, params: method === 'codexhost/thread/catalog/read' ? { includeArchived: false } : {} }));
  });
}

const overviewErrors = {
  AUTH_REQUIRED: '需要连接：请手动输入此设备的 Web 访问令牌',
  RATE_LIMITED: '认证尝试过多，请稍后重试',
  UNSUPPORTED: '接口不可用或版本不支持，请更新 CodexHost',
  UNREACHABLE: '无法读取，请检查网络、HTTPS 证书或服务状态',
  RESPONSE_TOO_LARGE: '返回数据过大，本次未读取',
};

export async function readOverview(value, token = '', timeout = 10000) {
  const url = parseTarget(value);
  if (typeof token !== 'function' && (typeof token !== 'string' || token.length > 4096 || /[\s\x00-\x1f\x7f]/.test(token))) throw new Error('Invalid token');
  const [workspace, catalog] = await Promise.allSettled([
    rpc(url, 'codexhost/workspace/read', token, timeout),
    rpc(url, 'codexhost/thread/catalog/read', token, timeout),
  ]);
  const errorFor = (section) => section.status === 'rejected'
    ? section.reason.message in overviewErrors ? section.reason.message : 'UNREACHABLE' : null;
  let projectError = errorFor(workspace);
  let taskError = errorFor(catalog);
  const projectRows = workspace.status === 'fulfilled' && Array.isArray(workspace.value.projects) ? workspace.value.projects : null;
  const taskRows = catalog.status === 'fulfilled' && Array.isArray(catalog.value.threads) ? catalog.value.threads : null;
  if (!projectRows && !projectError) projectError = 'UNSUPPORTED';
  if (!taskRows && !taskError) taskError = 'UNSUPPORTED';
  const projects = (projectRows || []).filter((row) => row && typeof row.id === 'string' && typeof row.name === 'string')
    .slice(0, 200).map((row) => ({ id: row.id, name: row.name.slice(0, 200) }));
  const projectNames = new Map(projects.map((row) => [row.id, row.name]));
  const assignments = workspace.status === 'fulfilled' ? workspace.value.assignments : null;
  const knownStatuses = new Set(['active', 'idle', 'notLoaded', 'systemError']);
  const tasks = (taskRows || []).filter((row) => row && typeof row.id === 'string').slice(0, 100)
    .map((row) => ({
      id: row.id,
      title: typeof row.name === 'string' && row.name.trim() ? row.name.slice(0, 200) : '未命名会话',
      status: knownStatuses.has(row.status?.type) ? row.status.type : 'unknown',
      project: projectNames.get(assignments?.[row.id]) || null,
    }));
  return {
    projects: projectError ? null : projects,
    tasks: taskError ? null : tasks,
    projectError, taskError,
    errors: [...new Set([projectError, taskError].filter(Boolean))].map((code) => ({ code, message: overviewErrors[code] })),
    limited: taskRows ? taskRows.length > 100 || catalog.value.officialCursor?.live != null : false,
    projectsLimited: projectRows ? projectRows.length > 200 : false,
    observedAt: new Date().toISOString(),
  };
}

const files = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
};

async function jsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > 8192) { req.resume(); throw Object.assign(new Error('Request too large'), { status: 413 }); }
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export function makeServer({ vaultPath = fileURLToPath(new URL('.local/vault.json', import.meta.url)), configPath = join(dirname(vaultPath), 'config.json'), devicesPath = join(dirname(vaultPath), 'manager-devices.json'), publicOrigin = '' } = {}) {
  if (publicOrigin && (new URL(publicOrigin).protocol !== 'https:' || new URL(publicOrigin).origin !== publicOrigin)) throw new Error('Invalid HTTPS origin');
  const auth = makeAuth(vaultPath, configPath, !!publicOrigin);
  const managerAccess = makeManagerAccess(devicesPath, parseTarget);
  const proxy = makeProxy(auth, privateLookup, managerAccess, publicOrigin);
  const status = async (req) => {
    const result = await auth.status(req);
    const signed = managerAccess.configured();
    if (!signed || !result.authenticated) return { ...result, accessMode: signed ? 'manager' : 'legacy' };
    const devices = managerAccess.devices();
    return { configured: true, authenticated: true, accessMode: 'manager',
      boundOrigins: [], boundDevices: devices.map(({ url, name, role }) => ({ url, name, role })),
      proxyPaths: Object.fromEntries(devices.map((device) => [device.origin, `/device/${deviceKey(device.origin)}/`])) };
  };
  const allowed = (req) => {
    const origins = [`http://127.0.0.1:${req.socket.localPort}`, ...(publicOrigin ? [publicOrigin] : [])];
    return origins.some((value) => new URL(value).host === req.headers.host)
      && (!req.headers.origin || origins.includes(req.headers.origin))
      && req.headers['sec-fetch-site'] !== 'cross-site';
  };
  const server = createServer((req, res) => {
    const json = (status, value) => res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(value));
    void (async () => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    const origin = `http://127.0.0.1:${req.socket.localPort}`;
    const origins = publicOrigin ? [origin, publicOrigin] : [origin];
    const homeNavigation = req.method === 'GET' && req.url === '/'
      && req.headers['sec-fetch-mode'] === 'navigate'
      && req.headers['sec-fetch-dest'] === 'document';
    if (!origins.some((value) => new URL(value).host === req.headers.host)
      || (req.headers.origin && !origins.includes(req.headers.origin))
      || (req.headers['sec-fetch-site'] === 'cross-site' && !homeNavigation)) {
      res.writeHead(403).end('Forbidden');
      return;
    }
    const url = URL.parse(req.url, origin);
    if (!url) {
      res.writeHead(400).end('Bad request');
      return;
    }
    if (url.pathname.startsWith('/device/')) {
      const bridge = /^(\/device\/[a-f0-9]{32})\/__manager_bridge\.js$/.exec(url.pathname);
      if (bridge) {
        await auth.access(req);
        res.removeHeader('Content-Security-Policy');
        res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' }).end(browserBridge(bridge[1]));
      } else { res.removeHeader('Content-Security-Policy'); await proxy.handle(req, res); }
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/auth/status') {
      json(200, await status(req));
      return;
    }
    if (url.pathname === '/api/auth/setup') {
      json(404, { error: '管理台令牌由本机配置文件管理' });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/auth/login') {
      const input = await jsonBody(req);
      await auth.login(input.token, res);
      json(200, { authenticated: true });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/auth/logout') {
      auth.logout(req, res);
      json(200, { authenticated: false });
      return;
    }
    let bindings = [];
    if (url.pathname.startsWith('/api/')) bindings = await auth.credentials(req);
    if (req.method === 'POST' && url.pathname === '/api/bindings') {
      if (managerAccess.configured()) { json(409, { error: '设备信任由后台配置，无需设备令牌' }); return; }
      const input = await jsonBody(req);
      const target = parseTarget(input.url);
      const token = input.token;
      if (typeof token !== 'string' || token.length > 4096 || /[\s\x00-\x1f\x7f]/.test(token)) {
        throw Object.assign(new Error('设备令牌无效'), { status: 400 });
      }
      if (token) {
        const overview = await readOverview(target.href, token);
        if (overview.projectError && overview.taskError) {
          json(400, { error: '设备认证或接口验证失败，未保存令牌', overview });
          return;
        }
      }
      await auth.bind(req, target.origin, token, { url: target.href,
        name: typeof input.name === 'string' ? input.name.slice(0, 60) : '',
        role: typeof input.role === 'string' ? input.role.slice(0, 100) : '' });
      json(200, { boundOrigins: (await auth.status(req)).boundOrigins });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/overview') {
      try {
        const input = await jsonBody(req);
        const target = parseTarget(input.url);
        let token = bindings.find((binding) => binding.origin === target.origin)?.token || '';
        if (managerAccess.configured()) {
          const device = managerAccess.devices().find((row) => row.origin === target.origin);
          if (!device) { json(409, { error: '管理台信任未配置' }); return; }
          const session = await auth.access(req);
          token = (method, path) => managerAccess.headers(device, session, method, path, publicOrigin || origin);
        }
        const result = await readOverview(target.href, token);
        if (managerAccess.configured()) {
          for (const error of result.errors) if (error.code === 'AUTH_REQUIRED')
            error.message = '设备拒绝管理台信任，请检查插件、公钥和设备标识';
        }
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(result));
      } catch (error) {
        if (!res.destroyed) json(error?.status || 400, { error: '地址或连接参数无效' });
      }
      return;
    }
    if (req.method !== 'GET') {
      res.writeHead(405, { Allow: 'GET' }).end('Method not allowed');
      return;
    }
    if (url.pathname === '/favicon.ico') {
      res.writeHead(204).end();
      return;
    }
    if (url.pathname === '/api/status') {
      try {
        const result = await probe(url.searchParams.get('url'));
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(result));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: '地址无效：仅支持无凭证、无查询参数的本机、局域网或 Tailscale HTTP(S) 地址' }));
      }
      return;
    }
    const file = Object.hasOwn(files, url.pathname) ? files[url.pathname] : null;
    if (!file) {
      res.writeHead(404).end('Not found');
      return;
    }
    try {
      const data = await readFile(new URL(file[0], import.meta.url));
      res.writeHead(200, { 'Content-Type': file[1] }).end(data);
    } catch {
      res.writeHead(500).end('Unable to load page');
    }
    })().catch((error) => {
      if (!res.headersSent && !res.destroyed) json(error.status || 400, { error: error.status ? error.message : '请求无效或本地保存失败' });
      else res.destroy();
    });
  });
  server.on('upgrade', (req, socket, head) => {
    if (!allowed(req) || !req.headers.origin) { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
    void proxy.handle(req, socket, head).catch((error) => socket.end(`HTTP/1.1 ${error.status || 400} Rejected\r\nConnection: close\r\n\r\n`));
  });
  server.on('close', () => { proxy.close(); managerAccess.close(); auth.close(); });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.argv[2] || 4410);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
  const server = makeServer({ publicOrigin: process.argv[3] || '', ...(process.argv[4] ? { devicesPath: resolve(process.argv[4]) } : {}) });
  server.on('error', (error) => {
    console.error(error.code === 'EADDRINUSE' ? `端口 ${port} 已被占用，可使用 node server.mjs 4411` : error.message);
    process.exitCode = 1;
  });
  server.listen(port, '127.0.0.1', () => console.log(`CodexHost Manager: http://127.0.0.1:${port}`));
}
