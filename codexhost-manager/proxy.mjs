import { request as httpRequest, Agent as HttpAgent } from 'node:http';
import { request as httpsRequest, Agent as HttpsAgent } from 'node:https';
import { createHash } from 'node:crypto';
import { createGunzip, gzip } from 'node:zlib';
import { promisify } from 'node:util';

const compress = promisify(gzip);

export const deviceKey = (origin) => createHash('sha256').update(origin).digest('hex').slice(0, 32);
const fail = (status) => Object.assign(new Error('代理访问不可用，请登录并连接设备'), { status });
const hop = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const credentialMethod = (method) => method === 'codexhost/accessTokenGet' || method === 'codexhost/accessTokenRegenerate';
function clean(headers) {
  const excluded = new Set([...hop, ...(headers.connection || '').toLowerCase().split(',').map((s) => s.trim())]);
  return Object.fromEntries(Object.entries(headers).filter(([key]) => !excluded.has(key)));
}

function acceptsGzip(header = '') {
  const encodings = header.toLowerCase().split(',').map((value) => value.trim().split(/\s*;\s*/));
  const encoding = encodings.find(([name]) => name === 'gzip') || encodings.find(([name]) => name === '*');
  const quality = encoding?.slice(1).find((value) => /^q\s*=/.test(value));
  return !!encoding && (!quality || (Number(quality.split('=')[1]) > 0 && Number(quality.split('=')[1]) <= 1));
}

// The browser receives only a device identifier. Credentials remain in the vault.
export function makeProxy(auth, lookup, managerAccess, publicOrigin = '') {
  const active = new Set();
  const agents = {
    'http:': new HttpAgent({ keepAlive: true, maxFreeSockets: 8, timeout: 30000 }),
    'https:': new HttpsAgent({ keepAlive: true, maxFreeSockets: 8, timeout: 30000 }),
  };
  auth.onRevoke((session, origin) => {
    for (const entry of active) if ((!session || entry.session === session) && (!origin || entry.origin === origin)) entry.destroy();
  });
  managerAccess?.onRevoke(() => { for (const entry of active) entry.destroy(); });
  async function handle(req, output, head) {
    const websocket = head !== undefined;
    const match = /^\/device\/([a-f0-9]{32})(\/[^#]*)?$/.exec(req.url);
    if (!match) throw fail(404);
    const session = await auth.access(req);
    const signed = managerAccess?.configured();
    const bindings = signed ? managerAccess.devices() : await auth.credentials(req);
    const binding = bindings.find((row) => deviceKey(row.origin) === match[1]);
    if (!binding) throw fail(403);
    const prefix = `/device/${match[1]}`;
    if (!match[2]) {
      if (websocket) throw fail(400);
      output.writeHead(308, { Location: `${prefix}/` }).end();
      return;
    }
    // Never interpret the supplied path as a URL authority, or accept credential inputs.
    const path = new URL(`http://proxy.invalid${match[2]}`);
    if (path.pathname.startsWith('/device/') || [...path.searchParams.keys()].some((key) => /token|authorization/i.test(key))) throw fail(400);
    if (/^\/api\/auth\/(login|logout)/.test(path.pathname) || path.pathname === '/sw.js') throw fail(403);
    let pathname;
    try { pathname = decodeURIComponent(path.pathname); } catch { throw fail(400); }
    if (credentialMethod(pathname.slice('/api/'.length))) throw fail(403);
    let body;
    if (!websocket && req.method === 'POST' && pathname.startsWith('/api/')
      && !['/api/desktop/screenshot', '/api/voice/transcribe', '/api/session/uploadFileBinary'].includes(path.pathname)) {
      // CodexHost dispatches the envelope method, not necessarily the HTTP route.
      const chunks = []; let size = 0;
      for await (const chunk of req.iterator({ destroyOnReturn: false })) {
        size += chunk.length;
        if (size > 16 * 1024 * 1024) { req.resume(); throw fail(413); }
        chunks.push(chunk);
      }
      body = Buffer.concat(chunks);
      let input;
      try { input = JSON.parse(body.toString('utf8')); } catch { throw fail(400); }
      if (credentialMethod(String(input?.method ?? ''))) throw fail(403);
      if (await auth.access(req) !== session
        || !(signed ? managerAccess.devices() : await auth.credentials(req)).some((row) => row === binding || (!signed && row.origin === binding.origin && row.token === binding.token))) throw fail(403);
    }
    const target = new URL(binding.origin);
    const headers = clean(req.headers);
    for (const name of Object.keys(headers)) if (/^(cookie|authorization|host|origin|referer|forwarded|x-forwarded-.*|x-codexhost-manager-.*|sec-fetch-.*|accept-encoding)$/i.test(name)) delete headers[name];
    const gzipAllowed = !websocket && req.method === 'GET' && !pathname.startsWith('/api/')
      && !req.headers.range && !req.headers.accept?.toLowerCase().includes('text/event-stream')
      && acceptsGzip(req.headers['accept-encoding']);
    headers['accept-encoding'] = gzipAllowed ? 'gzip' : 'identity';
    headers.host = target.host;
    if (signed) Object.assign(headers, managerAccess.headers(binding, session, req.method, path.pathname + path.search,
      publicOrigin || `http://127.0.0.1:${req.socket.localPort}`));
    else headers.authorization = `Bearer ${binding.token}`;
    if (req.headers.origin) headers.origin = target.origin;
    if (websocket) {
      if (req.method !== 'GET' || req.headers.upgrade?.toLowerCase() !== 'websocket') throw fail(400);
      headers.connection = 'Upgrade';
      headers.upgrade = 'websocket';
    }
    let upstreamSocket;
    const entry = { session, origin: binding.origin, destroy() {
      if (!upstream.res?.complete) upstream.destroy();
      upstreamSocket?.destroy(); output.destroy();
    } };
    const upstream = (target.protocol === 'https:' ? httpsRequest : httpRequest)(target, {
      path: path.pathname + path.search, method: req.method, headers, lookup, family: 4,
      agent: websocket ? false : agents[target.protocol],
    });
    active.add(entry);
    const expiry = setTimeout(() => entry.destroy(), Math.max(1, session.expires - Date.now()));
    expiry.unref();
    const release = () => { clearTimeout(expiry); active.delete(entry); };
    output.once('close', () => {
      release();
      // Completed responses may already have returned their socket to another request.
      if (!upstream.res?.complete) upstream.destroy();
      upstreamSocket?.destroy();
    });
    upstream.setTimeout(30000, () => upstream.destroy());
    upstream.on('error', () => {
      release();
      if (websocket) output.destroy();
      else if (!output.headersSent) output.writeHead(502).end('设备代理连接失败');
      else output.destroy();
    });
    upstream.on('upgrade', (response, socket, initial) => {
      upstreamSocket = socket;
      socket.setTimeout(0);
      if (!websocket || response.statusCode !== 101 || !active.has(entry)) { socket.destroy(); output.destroy(); return; }
      const reply = clean(response.headers);
      delete reply['set-cookie'];
      reply.connection = 'Upgrade'; reply.upgrade = 'websocket';
      output.write('HTTP/1.1 101 Switching Protocols\r\n' + Object.entries(reply).map(([k, v]) => `${k}: ${v}\r\n`).join('') + '\r\n');
      if (initial.length) output.write(initial);
      if (head.length) socket.write(head);
      socket.on('error', () => output.destroy());
      socket.once('close', () => { release(); output.destroy(); });
      socket.pipe(output).pipe(socket);
    });
    upstream.on('response', (response) => {
      if (websocket) { response.resume(); output.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); return; }
      if (signed && [401, 403].includes(response.statusCode)) {
        response.resume();
        output.writeHead(response.statusCode, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' })
          .end('设备拒绝管理台信任，请检查 CodexHost 版本、插件与公钥配置');
        return;
      }
      const reply = clean(response.headers);
      for (const key of ['set-cookie', 'content-security-policy', 'content-security-policy-report-only', 'service-worker-allowed', 'access-control-allow-origin', 'access-control-allow-credentials', 'authorization', 'proxy-authorization']) delete reply[key];
      reply['cache-control'] = 'no-store';
      reply['referrer-policy'] = 'no-referrer';
      reply['content-security-policy'] = "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'self' blob:";
      if (reply.location) {
        const redirect = new URL(reply.location, new URL(path.pathname + path.search, target));
        if (redirect.origin !== target.origin || [...redirect.searchParams.keys()].some((key) => /token/i.test(key))) {
          response.resume(); output.writeHead(502).end('设备返回了不允许的跳转'); return;
        }
        reply.location = prefix + redirect.pathname + redirect.search + redirect.hash;
      }
      const type = reply['content-type'] || '';
      if (req.method === 'HEAD' || [204, 304].includes(response.statusCode)) {
        response.resume(); output.writeHead(response.statusCode, reply).end();
      } else if (/text\/html|(?:java|ecma)script|text\/css/.test(type)) {
        const encoding = (reply['content-encoding'] || 'identity').toLowerCase();
        if (!['identity', 'gzip'].includes(encoding)) { entry.destroy(); return; }
        const content = encoding === 'gzip' ? createGunzip() : response;
        if (content !== response) {
          content.on('error', () => entry.destroy());
          output.once('close', () => content.destroy());
          response.pipe(content);
        }
        const chunks = []; let size = 0;
        content.on('data', (chunk) => { size += chunk.length; if (size > 16 * 1024 * 1024) entry.destroy(); else chunks.push(chunk); });
        content.on('end', async () => {
          try {
            if (output.destroyed) return;
            let body = Buffer.concat(chunks).toString('utf8');
            // Root asset references and static module imports must stay in this device mount.
            if (/text\/html/.test(type)) body = body.replace(/((?:src|href|action)=['"])\/(?!\/)/gi, `$1${prefix}/`);
            else if (/text\/css/.test(type)) body = body.replace(/(url\(['"]?)\/(?!\/)/g, `$1${prefix}/`);
            else body = body.replace(/((?:from\s*|import\s*(?:\(\s*)?)['"])\/(?!\/)/g, `$1${prefix}/`);
            if (/text\/html/.test(type)) body = body.replace(/<head(?:\s[^>]*)?>/i, (tag) => `${tag}<script src="${prefix}/__manager_bridge.js"></script>`);
            delete reply['content-length']; delete reply.etag; delete reply['content-encoding'];
            reply.vary = reply.vary ? `${reply.vary}, Accept-Encoding` : 'Accept-Encoding';
            let result = Buffer.from(body);
            if (gzipAllowed && result.length >= 1024) {
              result = await compress(result, { level: 6 });
              reply['content-encoding'] = 'gzip';
            }
            if (output.destroyed || !active.has(entry)) return;
            output.writeHead(response.statusCode, reply).end(result);
          } catch { entry.destroy(); }
        });
      } else { output.writeHead(response.statusCode, reply); response.pipe(output); }
      response.on('error', () => output.destroy());
    });
    if (websocket || body !== undefined) upstream.end(body); else req.pipe(upstream);
  }
  return { handle, close() {
    for (const entry of active) entry.destroy();
    for (const agent of Object.values(agents)) agent.destroy();
  } };
}

export function browserBridge(prefix) {
  return `(() => {
    const prefix = ${JSON.stringify(prefix)};
    function route(value) {
      const url = new URL(String(value), location.href);
      if (url.host === location.host && !url.pathname.startsWith(prefix + '/')) url.pathname = prefix + url.pathname;
      return url.href;
    }
    // CodexHost preferences/databases must not collide with another device or the manager.
    for (const name of ['localStorage', 'sessionStorage']) {
      const store = window[name], keyPrefix = prefix + ':';
      const keys = () => Object.keys(store).filter(key => key.startsWith(keyPrefix));
      const methods = {
        getItem: key => store.getItem(keyPrefix + key),
        setItem: (key, value) => store.setItem(keyPrefix + key, value),
        removeItem: key => store.removeItem(keyPrefix + key),
        clear: () => keys().forEach(key => store.removeItem(key)),
        key: index => keys()[index]?.slice(keyPrefix.length) ?? null,
      };
      Object.defineProperty(window, name, { value: new Proxy({}, {
        get: (_, key) => key === 'length' ? keys().length : methods[key] || (typeof key === 'string' ? methods.getItem(key) : undefined),
        set: (_, key, value) => { methods.setItem(key, value); return true; },
        deleteProperty: (_, key) => { methods.removeItem(key); return true; },
        ownKeys: () => keys().map(key => key.slice(keyPrefix.length)),
        getOwnPropertyDescriptor: () => ({ enumerable: true, configurable: true }),
      }) });
    }
    for (const method of ['open', 'deleteDatabase']) {
      const original = indexedDB[method].bind(indexedDB);
      indexedDB[method] = (name, ...args) => original(prefix + ':' + name, ...args);
    }
    const Channel = window.BroadcastChannel;
    if (Channel) window.BroadcastChannel = class extends Channel { constructor(name) { super(prefix + ':' + name); } };
    for (const method of ['pushState', 'replaceState']) {
      const original = history[method].bind(history);
      history[method] = (state, title, url) => original(state, title, url == null ? url : route(url));
    }
    const send = window.fetch;
    window.fetch = (input, init) => send(input instanceof Request ? new Request(route(input.url), input) : route(input), init);
    for (const name of ['WebSocket', 'EventSource']) {
      const Original = window[name];
      if (Original) window[name] = class extends Original { constructor(url, options) { super(route(url), options); } };
    }
    const open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...args) { return open.call(this, method, route(url), ...args); };
    if (navigator.serviceWorker) navigator.serviceWorker.register = () => Promise.reject(new Error('代理入口不支持 Service Worker'));
  })();`;
}
