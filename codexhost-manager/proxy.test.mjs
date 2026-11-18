import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { connect } from 'node:net';
import { testServer } from './test-support.mjs';
import { deviceKey } from './proxy.mjs';

async function fixture(t, token) {
  const calls = [];
  const sockets = new Set();
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    calls.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
    if (req.headers.authorization !== `Bearer ${token}`) { res.writeHead(401).end(); return; }
    if (req.url === '/api/ch/v1/rpc') { res.end(JSON.stringify({ result: { projects: [], threads: [] } })); return; }
    if (req.url === '/redirect') { res.writeHead(302, { Location: '/?session=abc', 'Set-Cookie': `secret=${token}` }).end(); return; }
    if (req.url === '/external') { res.writeHead(302, { Location: 'https://example.com/' }).end(); return; }
    if (req.url === '/stream') { res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.write('data: hello\n\n'); return; }
    if (req.url === '/assets/imports.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript' });
      res.end('import "/assets/side-effect.js"; export { value } from "/assets/value.js"; import("/assets/lazy.js");'); return;
    }
    if (req.url === '/api/session/uploadFileBinary') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ bytes: Buffer.concat(chunks).length })); return;
    }
    if (req.method === 'POST' && req.url.startsWith('/api/')) {
      res.setHeader('Content-Type', 'application/json');
      const input = JSON.parse(Buffer.concat(chunks).toString());
      const value = ['codexhost/accessTokenGet', 'codexhost/accessTokenRegenerate'].includes(String(input.method ?? '')) ? { secret: token } : { saved: true };
      res.end(JSON.stringify({ result: { ok: true, value } })); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': `secret=${token}` });
    res.end('<head><script src="/assets/app.js"></script></head><body>fixture</body>');
  });
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.on('upgrade', (req, socket) => {
    calls.push({ url: req.url, headers: req.headers });
    if (req.headers.authorization !== `Bearer ${token}`) { socket.destroy(); return; }
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on('data', (data) => socket.write(data));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/`;
  return { url, path: `/device/${deviceKey(new URL(url).origin)}`, calls, token };
}
async function bind(manager, device) {
  assert.equal((await manager.request('/api/bindings', { method: 'POST', body: JSON.stringify({ url: device.url, token: device.token }) })).status, 200);
}
async function ws(manager, path, origin = manager.base) {
  const socket = connect(new URL(manager.base).port, '127.0.0.1');
  await once(socket, 'connect');
  socket.write(`GET ${path}/events HTTP/1.1\r\nHost: ${new URL(manager.base).host}\r\nOrigin: ${origin}\r\nCookie: ${manager.cookie()}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
  const [data] = await once(socket, 'data');
  return { socket, reply: data.toString() };
}

test('HTTP proxy uses only its binding, rewrites assets/redirects and strips cookies', async (t) => {
  const manager = await testServer(t);
  const a = await fixture(t, 'test-device-a'), b = await fixture(t, 'test-device-b');
  await bind(manager, a); await bind(manager, b);
  for (const device of [a, b]) {
    const res = await manager.request(device.path + '/?session=example', { headers: { Authorization: 'Bearer browser-input' } });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('set-cookie'), null);
    const body = await res.text();
    assert.ok(body.includes(`${device.path}/assets/app.js`));
    assert.ok(body.includes(`${device.path}/__manager_bridge.js`));
    assert.ok(!body.includes(device.token));
    assert.equal(device.calls.at(-1).headers.cookie, undefined);
    assert.equal(device.calls.at(-1).headers.authorization, `Bearer ${device.token}`);
  }
  const redirect = await manager.request(a.path + '/redirect', { redirect: 'manual' });
  assert.equal(redirect.headers.get('location'), a.path + '/?session=abc');
  assert.equal((await manager.request(a.path + '/external')).status, 502);
  assert.equal((await manager.request(a.path + '/?token=bad')).status, 400);
  assert.equal((await manager.request(a.path + '/api/auth/login', { method: 'POST' })).status, 403);
  assert.equal((await manager.request(a.path + '/', { headers: { Origin: 'http://evil.invalid' } })).status, 403);
  assert.equal((await fetch(manager.base + a.path + '/')).status, 401);
  await manager.request('/api/bindings', { method: 'POST', body: JSON.stringify({ url: a.url, token: '' }) });
  assert.equal((await manager.request(a.path + '/')).status, 403);
  assert.equal((await manager.request(b.path + '/')).status, 200);
});

test('proxy rejects credential RPCs even when the HTTP route disguises the envelope method', async (t) => {
  const manager = await testServer(t), device = await fixture(t, 'test-credential-boundary');
  await bind(manager, device);
  const initialCalls = device.calls.length;
  for (const method of ['codexhost/accessTokenGet', 'codexhost/accessTokenRegenerate', ['codexhost/accessTokenGet'], [['codexhost/accessTokenRegenerate']]]) {
    for (const route of [`/api/${method}`, '/api/settings/get', '/api/codexhost%2faccessTokenGet', '/api/voice/%74ranscribe', '/api/session/uploadFile%42inary']) {
      const response = await manager.request(device.path + route, {
        method: 'POST', headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ type: 'client-request', rpcId: 'test', method, payload: { args: {} } }),
      });
      assert.equal(response.status, 403);
      assert.ok(!(await response.text()).includes(device.token));
    }
  }
  assert.equal(device.calls.length, initialCalls);
  const ordinary = await manager.request(device.path + '/api/settings/get', {
    method: 'POST', body: JSON.stringify({ method: 'settings/get' }),
  });
  assert.equal(ordinary.status, 200);
  assert.deepEqual((await ordinary.json()).result.value, { saved: true });
  assert.equal(device.calls.at(-1).body, JSON.stringify({ method: 'settings/get' }));
});

test('proxy keeps side-effect imports, re-exports and dynamic imports in the device mount', async (t) => {
  const manager = await testServer(t), device = await fixture(t, 'test-module-resources');
  await bind(manager, device);
  const response = await manager.request(device.path + '/assets/imports.js');
  const body = await response.text();
  assert.ok(body.includes(`import "${device.path}/assets/side-effect.js"`));
  assert.ok(body.includes(`from "${device.path}/assets/value.js"`));
  assert.ok(body.includes(`import("${device.path}/assets/lazy.js")`));
});

test('RPC validation bounds JSON without breaking binary uploads or reusing revoked bindings', async (t) => {
  const manager = await testServer(t), device = await fixture(t, 'test-rpc-boundaries');
  await bind(manager, device);
  const initialCalls = device.calls.length;
  assert.equal((await manager.request(device.path + '/api/settings/get', { method: 'POST', body: '{' })).status, 400);
  assert.equal((await manager.request(device.path + '/api/settings/get', {
    method: 'POST', body: ' '.repeat(16 * 1024 * 1024 + 1),
  })).status, 413);
  assert.equal(device.calls.length, initialCalls);
  const upload = await manager.request(device.path + '/api/session/uploadFileBinary', {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: new Uint8Array([0, 255, 1]),
  });
  assert.equal(upload.status, 200);
  assert.deepEqual(await upload.json(), { bytes: 3 });
  const socket = connect(new URL(manager.base).port, '127.0.0.1');
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  socket.write(`POST ${device.path}/api/settings/get HTTP/1.1\r\nHost: ${new URL(manager.base).host}\r\nCookie: ${manager.cookie()}\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{"method":`);
  await manager.request('/api/bindings', { method: 'POST', body: JSON.stringify({ url: device.url, token: '' }) });
  const reply = once(socket, 'data');
  socket.write('"settings/get"}');
  assert.match((await reply)[0].toString(), /^HTTP\/1.1 403/);
  assert.equal(device.calls.length, initialCalls + 1);
});

test('WebSocket forwarding and live HTTP streams stop on unbind and logout', async (t) => {
  const manager = await testServer(t), device = await fixture(t, 'test-websocket-device');
  await bind(manager, device);
  const { socket, reply } = await ws(manager, device.path);
  assert.match(reply, /101 Switching/);
  t.after(() => socket.destroy());
  socket.write('test-frame');
  assert.equal((await once(socket, 'data'))[0].toString(), 'test-frame');
  assert.equal(device.calls.at(-1).headers.cookie, undefined);
  const closed = once(socket, 'close');
  await manager.request('/api/bindings', { method: 'POST', body: JSON.stringify({ url: device.url, token: '' }) });
  await closed;
  await bind(manager, device);
  const second = await ws(manager, device.path);
  const secondClosed = once(second.socket, 'close');
  const stream = await manager.request(device.path + '/stream');
  const reader = stream.body.getReader(); await reader.read();
  await manager.request('/api/auth/logout', { method: 'POST' });
  await secondClosed;
  await assert.rejects(reader.read());
  assert.equal((await manager.request(device.path + '/')).status, 401);
});

test('logout revokes only its session; unbind revokes the device across sessions', async (t) => {
  const manager = await testServer(t), device = await fixture(t, 'test-session-isolation');
  await bind(manager, device);
  const firstCookie = manager.cookie();
  const { testManagerToken } = await import('./test-support.mjs');
  await manager.request('/api/auth/login', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) });
  const secondCookie = manager.cookie();
  const first = await ws({ ...manager, cookie: () => firstCookie }, device.path);
  const second = await ws(manager, device.path);
  t.after(() => { first.socket.destroy(); second.socket.destroy(); });
  const firstClosed = once(first.socket, 'close');
  await manager.request('/api/auth/logout', { method: 'POST', headers: { Cookie: firstCookie } });
  await firstClosed;
  assert.equal((await manager.request(device.path + '/', { headers: { Cookie: secondCookie } })).status, 200);
  second.socket.write('still-connected');
  assert.equal((await once(second.socket, 'data'))[0].toString(), 'still-connected');
  const secondClosed = once(second.socket, 'close');
  await manager.request('/api/bindings', { method: 'POST', headers: { Cookie: secondCookie }, body: JSON.stringify({ url: device.url, token: '' }) });
  await secondClosed;
  const rejected = await ws({ ...manager, cookie: () => secondCookie }, device.path);
  assert.match(rejected.reply, /403 Rejected/);
  rejected.socket.destroy();
});
