import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import createProvider from './plugins/manager-access.mjs';
import { browserLoginPath, signRequest } from './manager-access.mjs';
import { deviceKey } from './proxy.mjs';
import { testServer } from './test-support.mjs';

async function fixture(t, name = 'device-a') {
  const root = await mkdtemp(join(tmpdir(), 'manager-access-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const device = { id: name, keyId: `${name}-key`, privateKey, origin: 'http://127.0.0.1:1' };
  const origin = 'https://manager.test';
  const trustPath = join(root, 'trust.json');
  const trust = { deviceId: name, managers: [{ keyId: device.keyId, origin,
    mountPath: `/device/${deviceKey(device.origin)}`, publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }] };
  await writeFile(trustPath, JSON.stringify(trust));
  const provider = createProvider({ configFile: trustPath });
  t.after(() => provider.dispose());
  const request = (headers) => ({ method: 'GET', url: '/api/auth/status?a=1', headers });
  const headers = () => signRequest(device, 'test-session', 'GET', '/api/auth/status?a=1', origin);
  return { root, device, origin, trust, trustPath, provider, request, headers };
}

test('Ed25519 provider rejects tampering, expiry, replay, device/method/path/origin/mount mismatch', async (t) => {
  const f = await fixture(t);
  assert.equal(f.provider.authenticate(f.request({})).status, 'not-applicable');
  const original = f.headers();
  assert.equal(f.provider.authenticate(f.request(original)).status, 'authenticated');
  assert.equal(f.provider.authenticate(f.request(original)).status, 'denied');
  assert.equal(f.provider.authenticate({ ...f.request(f.headers()), method: 'POST' }).status, 'denied');
  assert.equal(f.provider.authenticate({ ...f.request(f.headers()), url: '/api/auth/status?a=2' }).status, 'denied');
  const now = Math.floor(Date.now() / 1000);
  for (const change of [
    { audience: 'other-device' }, { keyId: 'unknown' }, { publicOrigin: 'https://evil.test' },
    { mountPath: `/device/${'0'.repeat(32)}` }, { issuedAt: now - 50, expiresAt: now - 20 },
    { issuedAt: now + 10, expiresAt: now + 30 }, { issuedAt: now, expiresAt: now + 31 },
    { issuedAt: now, expiresAt: now }, { sessionId: null }, { sessionId: undefined }, { nonce: 'bad' },
  ]) {
    const claim = { ...JSON.parse(Buffer.from(f.headers()['x-codexhost-manager-proof'], 'base64url')), ...change };
    const proof = Buffer.from(JSON.stringify(claim)).toString('base64url');
    const headers = { 'x-codexhost-manager-proof': proof,
      'x-codexhost-manager-signature': sign(null, Buffer.from(proof), f.device.privateKey).toString('base64url') };
    assert.equal(f.provider.authenticate(f.request(headers)).status, 'denied', JSON.stringify(change));
  }
  const altered = f.headers();
  altered['x-codexhost-manager-proof'] += 'A';
  assert.equal(f.provider.authenticate(f.request(altered)).status, 'denied');
  assert.equal(f.provider.authenticate(f.request({ 'x-codexhost-manager-proof': 'A'.repeat(4097) })).status, 'denied');
  assert.equal(f.provider.authenticate(f.request({ 'x-codexhost-manager-signature': [] })).status, 'denied');
  const other = await fixture(t, 'device-b');
  assert.equal(other.provider.authenticate(other.request(f.headers())).status, 'denied');
});

test('provider revokes on public trust removal, invalid configuration and disposal', async (t) => {
  const f = await fixture(t);
  let revoked = 0;
  f.provider.onRevoke(() => revoked++);
  await writeFile(f.trustPath, JSON.stringify({ ...f.trust, managers: [] }));
  assert.equal(f.provider.authenticate(f.request(f.headers())).status, 'denied');
  assert.equal(revoked, 1);
  await writeFile(f.trustPath, '{');
  assert.equal(f.provider.authenticate(f.request(f.headers())).status, 'denied');
  assert.ok(revoked > 1);
  await writeFile(f.trustPath, JSON.stringify(f.trust));
  assert.equal(f.provider.authenticate(f.request(f.headers())).status, 'authenticated');
  f.provider.dispose();
  assert.equal(f.provider.authenticate(f.request(f.headers())).status, 'denied');
});

test('browser handoff is origin-bound, single-use, separate from proxy proofs, and revocable', async (t) => {
  const f = await fixture(t);
  f.device.origin = 'https://127.0.0.1:8181';
  f.trust.managers[0].mountPath = `/device/${deviceKey(f.device.origin)}`;
  await writeFile(f.trustPath, JSON.stringify({ ...f.trust, directOrigin: f.device.origin }));
  const host = new URL(f.device.origin).host;
  const issued = signRequest(f.device, 'test-session', 'POST', browserLoginPath, f.origin, 'session / 1');
  const post = (headers, ticket = issued) => ({ method: 'POST', url: browserLoginPath,
    headers: { host, origin: f.origin, 'content-type': 'application/x-www-form-urlencoded', ...headers },
    async *iterator() { yield Buffer.from(new URLSearchParams({ proof: ticket['x-codexhost-manager-proof'],
      signature: ticket['x-codexhost-manager-signature'] }).toString()); } });
  assert.equal(await f.provider.browserLogin(post({ origin: 'https://other.test' })), undefined);
  assert.equal(await f.provider.browserLogin(post({ host: 'localhost' })), undefined);
  assert.equal(f.provider.authenticate(post(issued), true).status, 'denied');
  assert.equal(await f.provider.browserLogin(post({}, signRequest(f.device, 'test-session', 'POST', browserLoginPath, f.origin))), undefined);
  const result = await f.provider.browserLogin(post({}));
  assert.equal(result.location, '/?session=session+%2F+1');
  assert.match(result.cookie, /^__Host-codexhost_manager=[^;]+; Path=\/; Secure; HttpOnly; SameSite=Lax;/);
  assert.equal(await f.provider.browserLogin(post({})), undefined);
  const request = f.request({ host, cookie: result.cookie.split(';')[0] });
  const admission = f.provider.authenticate(request, true);
  assert.equal(admission.status, 'authenticated');
  assert.equal(f.provider.authenticate(request, false).status, 'not-applicable');
  let revoked;
  f.provider.onRevoke((id) => { revoked = id; });
  assert.match(f.provider.browserLogout(request), /Max-Age=0$/);
  assert.equal(revoked, admission.credential);
  assert.equal(f.provider.authenticate(request, true).status, 'not-applicable');
});

test('single manager login signs metadata, HTTP and WebSocket without binding or credential exposure', async (t) => {
  const f = await fixture(t);
  const devicesPath = join(f.root, 'manager-devices.json');
  const manager = await testServer(t, { devicesPath });
  const calls = [], sockets = new Set();
  const upstream = createServer((req, res) => {
    const result = f.provider.authenticate(req);
    calls.push({ url: req.url, headers: req.headers, result });
    if (result.status !== 'authenticated') { res.writeHead(401).end(); return; }
    if (req.url === '/denied') { res.writeHead(401, { 'Content-Type': 'text/html' }).end('<form>Enter the access token</form>'); return; }
    if (req.url === '/api/ch/v1/rpc') { req.resume(); res.end(JSON.stringify({ result: { projects: [], threads: [] } })); return; }
    if (req.url === '/stream') { res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.write('data: signed\n\n'); return; }
    res.end('signed-device');
  });
  upstream.on('connection', (socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  upstream.on('upgrade', (req, socket) => {
    const result = f.provider.authenticate(req);
    calls.push({ url: req.url, headers: req.headers, result });
    socket.write(result.status === 'authenticated' ? 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n' : 'HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); upstream.close(); });
  f.device.origin = `http://127.0.0.1:${upstream.address().port}`;
  const mount = `/device/${deviceKey(f.device.origin)}`;
  f.trust.managers[0].origin = manager.base;
  f.trust.managers[0].mountPath = mount;
  await writeFile(f.trustPath, JSON.stringify(f.trust));
  const privateKeyFile = join(f.root, 'generated-private.pem');
  await writeFile(privateKeyFile, f.device.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const manifest = [{ id: f.device.id, keyId: f.device.keyId, url: f.device.origin, privateKeyFile }];
  await writeFile(devicesPath, JSON.stringify(manifest), { mode: 0o600 });
  const status = await (await manager.request('/api/auth/status')).json();
  assert.equal(status.accessMode, 'manager');
  assert.equal(status.proxyPaths[f.device.origin], mount + '/');
  assert.equal(JSON.stringify(status).includes('PRIVATE KEY'), false);
  assert.equal(JSON.stringify(status).includes('privateKeyFile'), false);
  assert.equal((await manager.request('/api/bindings', { method: 'POST', body: '{}' })).status, 409);
  const overview = await manager.request('/api/overview', { method: 'POST', body: JSON.stringify({ url: f.device.origin }) });
  assert.deepEqual((await overview.json()).errors, []);
  assert.equal((await manager.request(mount + '/hello?x=1', { headers: {
    Authorization: 'Bearer untrusted-browser', 'x-codexhost-manager-proof': 'forged', 'x-codexhost-manager-signature': 'forged',
  } })).status, 200);
  const sent = calls.at(-1);
  assert.equal(sent.headers.authorization, undefined);
  assert.equal(sent.headers.cookie, undefined);
  assert.notEqual(sent.headers['x-codexhost-manager-proof'], 'forged');
  assert.equal((await fetch(f.device.origin + '/hello?x=1', { headers: sent.headers })).status, 401);
  assert.equal((await fetch(manager.base + mount + '/')).status, 401);
  assert.equal((await fetch(f.device.origin + '/')).status, 401);
  const denied = await manager.request(mount + '/denied');
  assert.equal(denied.status, 401);
  const denial = await denied.text();
  assert.match(denial, /设备拒绝管理台信任/);
  assert.equal(denial.includes('access token'), false);
  const stream = await manager.request(mount + '/stream');
  const reader = stream.body.getReader();
  assert.match(Buffer.from((await reader.read()).value).toString(), /signed/);
  const socket = connect(new URL(manager.base).port, '127.0.0.1');
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  socket.write(`GET ${mount}/events HTTP/1.1\r\nHost: ${new URL(manager.base).host}\r\nOrigin: ${manager.base}\r\nCookie: ${manager.cookie()}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n\r\n`);
  assert.match((await once(socket, 'data'))[0].toString(), /101 Switching Protocols/);
  const closed = once(socket, 'close');
  const ended = reader.read().catch(() => null);
  await manager.request('/api/auth/logout', { method: 'POST' });
  await closed;
  await ended;
  assert.equal((await manager.request(mount + '/')).status, 401);
});

test('removing or disabling configured trust never falls back to legacy bindings', async (t) => {
  const f = await fixture(t);
  const devicesPath = join(f.root, 'devices.json');
  const manager = await testServer(t, { devicesPath });
  await writeFile(devicesPath, '[]');
  assert.equal((await (await manager.request('/api/auth/status')).json()).accessMode, 'manager');
  await rm(devicesPath);
  assert.equal((await (await manager.request('/api/auth/status')).json()).accessMode, 'manager');
  assert.equal((await manager.request('/api/overview', { method: 'POST', body: JSON.stringify({ url: f.device.origin }) })).status, 409);
  await writeFile(devicesPath, '{');
  assert.equal((await manager.request('/api/auth/status')).status, 503);
  await writeFile(devicesPath, '[]');
  assert.equal((await manager.request('/api/auth/status')).status, 200);
});

test('two configured devices cannot reuse proofs and disabling one removes only its future access', async (t) => {
  const a = await fixture(t, 'device-a'), b = await fixture(t, 'device-b');
  const devicesPath = join(a.root, 'devices.json');
  const manager = await testServer(t, { devicesPath });
  const rows = [];
  let captured;
  for (const f of [a, b]) {
    const server = createServer((req, res) => {
      const allowed = f.provider.authenticate(req).status === 'authenticated';
      if (f === a) captured = req.headers;
      res.writeHead(allowed ? 200 : 401).end(allowed ? f.device.id : 'rejected');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => { server.closeAllConnections(); server.close(); });
    f.device.origin = `http://127.0.0.1:${server.address().port}`;
    f.trust.managers[0].origin = manager.base;
    f.trust.managers[0].mountPath = `/device/${deviceKey(f.device.origin)}`;
    await writeFile(f.trustPath, JSON.stringify(f.trust));
    const privateKeyFile = join(f.root, 'private.pem');
    await writeFile(privateKeyFile, f.device.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    rows.push({ id: f.device.id, keyId: f.device.keyId, url: f.device.origin, privateKeyFile });
  }
  await writeFile(devicesPath, JSON.stringify(rows));
  const path = (f) => `/device/${deviceKey(f.device.origin)}/`;
  assert.equal(await (await manager.request(path(a))).text(), 'device-a');
  const proof = { ...captured };
  assert.equal(await (await manager.request(path(b))).text(), 'device-b');
  assert.equal((await fetch(b.device.origin + '/', { headers: proof })).status, 401);
  rows[0].enabled = false;
  await writeFile(devicesPath, JSON.stringify(rows));
  assert.equal((await manager.request(path(a))).status, 403);
  assert.equal(await (await manager.request(path(b))).text(), 'device-b');
  const status = await (await manager.request('/api/auth/status')).json();
  assert.equal(Object.keys(status.proxyPaths).length, 1);
  await writeFile(devicesPath, '{');
  assert.equal((await manager.request(path(b))).status, 503);
  await writeFile(devicesPath, JSON.stringify(rows));
  assert.equal(await (await manager.request(path(b))).text(), 'device-b');
});

test('provisioning creates independent per-device keys and refuses overwrites', async (t) => {
  const f = await fixture(t);
  const output = join(f.root, 'new-provision');
  const run = promisify(execFile);
  const args = [fileURLToPath(new URL('./provision-access.mjs', import.meta.url)), output, 'https://manager.test',
    'a', 'http://127.0.0.1:1001/', 'b', 'http://127.0.0.1:1002/'];
  await run(process.execPath, args);
  await assert.rejects(run(process.execPath, args));
  const { readFile } = await import('node:fs/promises');
  const rows = JSON.parse(await readFile(join(output, 'manager-devices.json')));
  assert.equal(rows.length, 2);
  const a = JSON.parse(await readFile(join(output, 'a-trust.json')));
  const b = JSON.parse(await readFile(join(output, 'b-trust.json')));
  assert.notEqual(a.managers[0].publicKey, b.managers[0].publicKey);
  assert.equal(JSON.stringify(a).includes('PRIVATE KEY'), false);
  assert.equal(JSON.stringify(rows).includes('PRIVATE KEY'), false);
});
