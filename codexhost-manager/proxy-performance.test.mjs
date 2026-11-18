import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { once } from 'node:events';
import { gzipSync, gunzipSync } from 'node:zlib';
import { testServer } from './test-support.mjs';
import { deviceKey } from './proxy.mjs';

async function fixture(t) {
  const calls = [];
  const sources = {
    '/large.js': 'import "/module.js";\n' + '// static resource for compression regression\n'.repeat(8192),
    '/large.css': 'body{background:url("/image.png")}\n'.repeat(8192),
    '/large.html': '<head></head><body><a href="/">home</a></body>' + ' '.repeat(16384),
  };
  const upstream = createServer(async (req, res) => {
    req.resume();
    calls.push({ path: req.url, encoding: req.headers['accept-encoding'], connection: req.socket.remotePort });
    if (req.headers.authorization !== 'Bearer performance-fixture-only') { res.writeHead(401).end(); return; }
    if (req.url === '/api/ch/v1/rpc') { res.end(JSON.stringify({ result: { projects: [], threads: [] } })); return; }
    if (req.url === '/api/probe') { res.setHeader('Content-Type', 'application/json'); res.end('{"ok":true}'); return; }
    if (req.url === '/events') { res.setHeader('Content-Type', 'text/event-stream'); res.end('data: fixture\n\n'); return; }
    if (req.url === '/binary') {
      const body = gzipSync(Buffer.from([0, 255, 23, 44]));
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Encoding': 'gzip', 'Content-Length': body.length });
      res.end(body); return;
    }
    if (req.url === '/broken.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript', 'Content-Encoding': 'gzip' });
      res.end('invalid gzip'); return;
    }
    if (req.url === '/oversized.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript', 'Content-Encoding': 'gzip' });
      res.end(gzipSync(Buffer.alloc(16 * 1024 * 1024 + 1, 32))); return;
    }
    const url = new URL(req.url, 'http://fixture.invalid');
    const source = sources[url.pathname];
    if (!source) { res.writeHead(404).end(); return; }
    const type = url.pathname.endsWith('.js') ? 'text/javascript' : url.pathname.endsWith('.css') ? 'text/css' : 'text/html';
    const compressed = req.headers['accept-encoding'] === 'gzip' && !url.searchParams.has('identity');
    const body = compressed ? gzipSync(source) : Buffer.from(source);
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': body.length, ETag: '"original"', Vary: 'Origin',
      ...(compressed ? { 'Content-Encoding': 'gzip' } : {}) });
    res.end(body);
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => { upstream.closeAllConnections(); upstream.close(); });
  const manager = await testServer(t);
  const origin = `http://127.0.0.1:${upstream.address().port}`;
  const bound = await manager.request('/api/bindings', { method: 'POST', body: JSON.stringify({ url: origin, token: 'performance-fixture-only' }) });
  assert.equal(bound.status, 200);
  const prefix = `/device/${deviceKey(origin)}`;
  const get = (path, headers = {}, method = 'GET') => new Promise((resolve, reject) => {
    const pending = request(manager.base + prefix + path, { method, headers: { Cookie: manager.cookie(), ...headers }, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    pending.on('error', reject);
    pending.setTimeout(5000, () => pending.destroy(new Error('Fixture request timed out')));
    pending.end();
  });
  return { manager, calls, sources, prefix, get };
}

test('proxy reuses upstream connections across completed HTTP responses', async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < 4; i++) assert.equal((await f.get('/large.js')).status, 200);
  assert.equal(new Set(f.calls.filter((call) => call.path === '/large.js').map((call) => call.connection)).size, 1);
  const concurrent = await Promise.all(Array.from({ length: 12 }, () => f.get('/large.js')));
  assert.ok(concurrent.every((res) => res.status === 200));
});

test('proxy decodes upstream gzip, rewrites mounts, and compresses HTML/JS/CSS without caching', async (t) => {
  const f = await fixture(t);
  for (const path of Object.keys(f.sources)) {
    const res = await f.get(path, { 'Accept-Encoding': 'br, gzip' });
    assert.equal(res.status, 200);
    assert.equal(f.calls.at(-1).encoding, 'gzip');
    assert.equal(res.headers['content-encoding'], 'gzip');
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers.etag, undefined);
    assert.match(res.headers.vary, /Origin/i);
    assert.match(res.headers.vary, /Accept-Encoding/i);
    const decoded = gunzipSync(res.body).toString();
    assert.ok(decoded.includes(f.prefix + '/'));
    if (path.endsWith('.html')) assert.ok(decoded.includes(f.prefix + '/__manager_bridge.js'));
    assert.ok(res.body.length < Buffer.byteLength(decoded) / 10);
  }
});

test('proxy compresses identity upstream responses after rewriting', async (t) => {
  const f = await fixture(t);
  const res = await f.get('/large.js?identity', { 'Accept-Encoding': 'gzip' });
  assert.equal(res.headers['content-encoding'], 'gzip');
  assert.ok(gunzipSync(res.body).toString().includes(f.prefix + '/module.js'));
});

test('proxy respects gzip negotiation and does not compress API traffic', async (t) => {
  const f = await fixture(t);
  for (const encoding of ['', 'identity', 'br', 'gzip;q=0', 'gzip; q=0.000, *;q=1']) {
    const res = await f.get('/large.js', { 'Accept-Encoding': encoding });
    assert.equal(res.headers['content-encoding'], undefined);
    assert.equal(f.calls.at(-1).encoding, 'identity');
    assert.ok(res.body.toString().includes(f.prefix + '/module.js'));
  }
  for (const encoding of ['gzip;q=0.5', 'GZip', '*;q=1']) {
    const res = await f.get('/large.js', { 'Accept-Encoding': encoding });
    assert.equal(res.headers['content-encoding'], 'gzip');
    assert.ok(gunzipSync(res.body).toString().includes(f.prefix + '/module.js'));
  }
  const api = await f.get('/api/probe', { 'Accept-Encoding': 'gzip' });
  assert.equal(api.headers['content-encoding'], undefined);
  assert.equal(f.calls.at(-1).encoding, 'identity');
  assert.deepEqual(JSON.parse(api.body), { ok: true });
  const stream = await f.get('/events', { 'Accept-Encoding': 'gzip', Accept: 'text/event-stream' });
  assert.equal(f.calls.at(-1).encoding, 'identity');
  assert.equal(stream.headers['content-encoding'], undefined);
  assert.equal(stream.body.toString(), 'data: fixture\n\n');
  const range = await f.get('/large.js', { 'Accept-Encoding': 'gzip', Range: 'bytes=0-128' });
  assert.equal(f.calls.at(-1).encoding, 'identity');
  assert.equal(range.headers['content-encoding'], undefined);
});

test('proxy preserves HEAD and byte-for-byte compressed binary responses', async (t) => {
  const f = await fixture(t);
  const head = await f.get('/large.js', { 'Accept-Encoding': 'gzip' }, 'HEAD');
  assert.equal(head.status, 200);
  assert.equal(head.body.length, 0);
  assert.equal(f.calls.at(-1).encoding, 'identity');
  const binary = await f.get('/binary', { 'Accept-Encoding': 'gzip' });
  assert.equal(binary.headers['content-encoding'], 'gzip');
  assert.equal(Number(binary.headers['content-length']), binary.body.length);
  assert.deepEqual(gunzipSync(binary.body), Buffer.from([0, 255, 23, 44]));
});

test('malformed gzip and inflated text over 16 MiB fail without poisoning later requests', async (t) => {
  const f = await fixture(t);
  for (const path of ['/broken.js', '/oversized.js']) {
    await assert.rejects(f.get(path, { 'Accept-Encoding': 'gzip' }));
    const healthy = await f.get('/large.js', { 'Accept-Encoding': 'gzip' });
    assert.equal(healthy.status, 200);
    assert.ok(gunzipSync(healthy.body).toString().includes(f.prefix + '/module.js'));
  }
});
