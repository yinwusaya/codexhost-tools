import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { makeServer } from './server.mjs';
import { testServer, testManagerToken } from './test-support.mjs';
import { loadConfiguration } from './auth.mjs';
import { randomBytes, scryptSync, createCipheriv } from 'node:crypto';

test('manager login gates every data API and never exposes vault or credentials', async (t) => {
  const { base, request, cookie } = await testServer(t);
  for (const path of ['/api/status?url=http://127.0.0.1/', '/api/overview', '/api/bindings']) {
    assert.equal((await fetch(base + path, { method: path.includes('status') ? 'GET' : 'POST', body: path.includes('status') ? undefined : '{}' })).status, 401);
  }
  const status = await (await request('/api/auth/status')).json();
  assert.equal(status.authenticated, true);
  assert.deepEqual(status.boundOrigins, []);
  assert.equal((await request('/.local/vault.json')).status, 404);
  assert.equal((await request('/.local/config.json')).status, 404);
  assert.equal((await request('/auth.mjs')).status, 404);
  assert.equal((await request('/api/auth/setup', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) })).status, 404);
  const oldCookie = cookie();
  await request('/api/auth/logout', { method: 'POST' });
  assert.equal((await request('/api/status?url=http://127.0.0.1/')).status, 401);
  assert.equal((await fetch(base + '/api/status?url=http://127.0.0.1/', { headers: { Cookie: oldCookie } })).status, 401);
  assert.equal((await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ token: 'wrong-test-only-token' }) })).status, 401);
  const login = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) });
  assert.equal(login.status, 200);
  assert.match(login.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  assert.doesNotMatch(await login.text(), /manager-test-only/);
});

test('bound credentials are encrypted, origin-scoped, survive restart, and can be removed', async (t) => {
  const { base, request, server, vaultPath, configPath, cookie } = await testServer(t);
  const target = createServer(async (req, res) => {
    assert.equal(req.headers.authorization, 'Bearer generated-device-test-token');
    const parts = [];
    for await (const chunk of req) parts.push(chunk);
    const input = JSON.parse(Buffer.concat(parts));
    res.end(JSON.stringify({ result: input.method.includes('workspace') ? { projects: [{ id: 'p', name: 'project' }] } : { threads: [{ id: 't', name: 'task', status: { type: 'active' } }] } }));
  });
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  t.after(() => new Promise((done) => target.close(done)));
  const url = `http://127.0.0.1:${target.address().port}/`;
  const bind = await request('/api/bindings', { method: 'POST', body: JSON.stringify({ url, token: 'generated-device-test-token' }) });
  assert.equal(bind.status, 200);
  assert.doesNotMatch(await bind.text(), /generated-device-test-token/);
  assert.doesNotMatch(await readFile(vaultPath, 'utf8'), /generated-device-test-token|manager-test-only|127\.0\.0\.1/);
  const overview = await request('/api/overview', { method: 'POST', body: JSON.stringify({ url }) });
  assert.equal((await overview.json()).tasks[0].title, 'task');
  const other = createServer((req, res) => {
    assert.equal(req.headers.authorization, undefined);
    res.writeHead(401).end();
  });
  other.listen(0, '127.0.0.1');
  await once(other, 'listening');
  t.after(() => new Promise((done) => other.close(done)));
  const unrelated = await request('/api/overview', { method: 'POST', body: JSON.stringify({ url: `http://127.0.0.1:${other.address().port}/` }) });
  assert.equal((await unrelated.json()).errors[0].code, 'AUTH_REQUIRED');
  const oldCookie = cookie();
  await new Promise((done) => { server.close(done); server.closeAllConnections(); });
  const config = await loadConfiguration(configPath);
  config.token = 'rotated-manager-test-only-placeholder';
  await writeFile(configPath, JSON.stringify(config));
  const restarted = makeServer({ vaultPath });
  restarted.listen(0, '127.0.0.1');
  await once(restarted, 'listening');
  t.after(() => new Promise((done) => { restarted.close(done); restarted.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${restarted.address().port}`;
  assert.equal((await fetch(origin + '/api/overview', { method: 'POST', headers: { Cookie: oldCookie }, body: JSON.stringify({ url }) })).status, 401);
  assert.equal((await fetch(origin + '/api/auth/login', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) })).status, 401);
  const login = await fetch(origin + '/api/auth/login', { method: 'POST', body: JSON.stringify({ token: config.token }) });
  const headers = { Cookie: login.headers.get('set-cookie').split(';')[0] };
  const result = await fetch(origin + '/api/overview', { method: 'POST', headers, body: JSON.stringify({ url }) });
  assert.equal((await result.json()).tasks[0].title, 'task');
  const unbind = await fetch(origin + '/api/bindings', { method: 'POST', headers, body: JSON.stringify({ url, token: '' }) });
  assert.deepEqual((await unbind.json()).boundOrigins, []);
  assert.equal((await fetch(base + '/').catch(() => null)), null);
});

test('failed bindings are not saved; public auth endpoints reject cross-origin requests', async (t) => {
  const { base, request } = await testServer(t);
  const target = createServer((req, res) => res.writeHead(401).end());
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  t.after(() => new Promise((done) => target.close(done)));
  const url = `http://127.0.0.1:${target.address().port}/`;
  assert.equal((await request('/api/bindings', { method: 'POST', body: JSON.stringify({ url, token: 'test-invalid-device-token' }) })).status, 400);
  assert.deepEqual((await (await request('/api/auth/status')).json()).boundOrigins, []);
  for (const route of ['login', 'setup', 'logout']) {
    assert.equal((await fetch(`${base}/api/auth/${route}`, { method: 'POST', headers: { Origin: 'http://example.com' }, body: '{}' })).status, 403);
  }
});

test('auth rate limits attempts and fails closed on corrupt vaults', async (t) => {
  const { request, vaultPath, server } = await testServer(t);
  for (let i = 0; i < 4; i++) {
    assert.equal((await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ token: 'invalid-test-token-long' }) })).status, 401);
  }
  assert.equal((await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) })).status, 429);
  await new Promise((done) => { server.close(done); server.closeAllConnections(); });
  await writeFile(vaultPath, '{');
  const broken = makeServer({ vaultPath });
  broken.listen(0, '127.0.0.1');
  await once(broken, 'listening');
  t.after(() => new Promise((done) => { broken.close(done); broken.closeAllConnections(); }));
  const url = `http://127.0.0.1:${broken.address().port}`;
  assert.equal((await fetch(url + '/api/auth/status')).status, 503);
  assert.equal((await fetch(url + '/api/auth/login', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) })).status, 503);
  assert.equal(await readFile(vaultPath, 'utf8'), '{');
});

test('configuration is generated once and invalid files are never overwritten', async (t) => {
  const { configPath } = await testServer(t);
  const generatedPath = `${configPath}.generated`;
  const first = await loadConfiguration(generatedPath);
  assert.equal(first.token.length, 43);
  assert.equal(Buffer.from(first.encryptionKey, 'base64').length, 32);
  assert.deepEqual(await loadConfiguration(generatedPath), first);
  await writeFile(generatedPath, '{');
  await assert.rejects(() => loadConfiguration(generatedPath));
  assert.equal(await readFile(generatedPath, 'utf8'), '{');
  const legacyPath = `${configPath}.legacy-missing`;
  await assert.rejects(() => loadConfiguration(legacyPath, true), /旧版令牌库/);
});

test('legacy vault migrates without dropping bindings when configured with the original token', async (t) => {
  const { server, vaultPath, configPath } = await testServer(t);
  await new Promise((done) => { server.close(done); server.closeAllConnections(); });
  const salt = randomBytes(16);
  const key = scryptSync(testManagerToken, salt, 32, { N: 32768, maxmem: 64 * 1024 * 1024 });
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('codexhost-manager-vault-v1'));
  const payload = { bindings: [{ origin: 'http://127.0.0.1:4400', token: 'legacy-device-test-placeholder' }] };
  const data = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()]);
  await writeFile(vaultPath, JSON.stringify({ version: 1, salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') }));
  const restarted = makeServer({ vaultPath, configPath });
  restarted.listen(0, '127.0.0.1');
  await once(restarted, 'listening');
  t.after(() => new Promise((done) => { restarted.close(done); restarted.closeAllConnections(); }));
  const base = `http://127.0.0.1:${restarted.address().port}`;
  const login = await fetch(base + '/api/auth/login', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) });
  assert.equal(login.status, 200);
  const status = await fetch(base + '/api/auth/status', { headers: { Cookie: login.headers.get('set-cookie').split(';')[0] } });
  assert.deepEqual((await status.json()).boundOrigins, ['http://127.0.0.1:4400']);
  const migrated = await readFile(vaultPath, 'utf8');
  assert.equal(JSON.parse(migrated).version, 2);
  assert.doesNotMatch(migrated, /legacy-device-test-placeholder/);
});
