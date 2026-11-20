import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfiguration, makeAuth } from './auth.mjs';
import { deviceKey } from './proxy.mjs';
import { makeServer } from './server.mjs';
import { testManagerToken } from './test-support.mjs';

if (!process.argv[2] || !process.argv[3]) throw new Error('Usage: node test-packed-ui.mjs <playwright/index.mjs> <web-entry> [tsx-loader --source] [--manager-access | --direct-login]');
const { chromium } = await import(pathToFileURL(resolve(process.argv[2])).href);
const entry = resolve(process.argv[3]);
const directLogin = process.argv.includes('--direct-login');
const signedAccess = directLogin || process.argv.includes('--manager-access');
const sourceEntry = process.argv.includes('--source');
await mkdir(new URL('tmp/', import.meta.url), { recursive: true });
const root = await mkdtemp(new URL('tmp/packed-ui-', import.meta.url));
const upstreamToken = 'isolated-packed-ui-only-placeholder';
let child, browser, manager, host;
const tlsFronts = [];
async function httpsFront(tls, hostname, target) {
  const forward = (req) => httpRequest(target() + req.url, { method: req.method,
    headers: { ...req.headers, 'x-forwarded-proto': 'https' } });
  const server = createHttpsServer(tls, (req, res) => {
    const upstream = forward(req);
    upstream.on('response', (reply) => { res.writeHead(reply.statusCode, reply.headers); reply.pipe(res); });
    upstream.on('error', () => res.destroy());
    req.pipe(upstream);
  });
  server.on('upgrade', (req, socket, head) => {
    const upstream = forward(req);
    upstream.on('upgrade', (reply, peer, buffer) => {
      socket.write('HTTP/1.1 101 Switching Protocols\r\n' + reply.rawHeaders.flatMap((item, i) => i % 2 ? [] : [`${item}: ${reply.rawHeaders[i + 1]}\r\n`]).join('') + '\r\n');
      if (buffer.length) socket.write(buffer);
      if (head.length) peer.write(head);
      socket.pipe(peer).pipe(socket);
      socket.on('close', () => peer.destroy());
      peer.on('error', () => socket.destroy());
    });
    upstream.on('response', (reply) => { reply.resume(); socket.end(`HTTP/1.1 ${reply.statusCode} Rejected\r\n\r\n`); });
    upstream.on('error', () => socket.destroy());
    upstream.end();
  });
  tlsFronts.push(server);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return `https://${hostname}:${server.address().port}`;
}
try {
  await mkdir(join(root, 'plugins'));
  const epoch = randomUUID(), hostToken = randomBytes(32).toString('hex');
  host = createServer(async (req, res) => {
    if (req.headers.authorization !== `Bearer ${hostToken}`) { res.writeHead(401).end(); return; }
    if (req.url === '/v1/events') {
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
      res.write(JSON.stringify({ type: 'hello', version: 1, cursor: { epoch, sequence: 0 }, reset: true }) + '\n'); return;
    }
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const { method } = JSON.parse(Buffer.concat(chunks).toString());
    const values = {
      'codexhost/workspace/read': { projects: [], assignments: {}, projectless: [], pinned: [] },
      'codexhost/thread/catalog/read': { threads: [], ownership: [], officialCursor: { live: null } },
      'codexhost/thread/tree/read': { parents: {} },
      'codexhost/thread/pins/list': { threadIds: [] },
      'codexhost/harness/plugins/list': { plugins: [] },
      'codexhost/harness/display-settings/capabilities': { events: false },
      'thread/list': { data: [], nextCursor: null },
    };
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(Object.hasOwn(values, method) ? { result: values[method] }
      : { error: { code: -32601, message: 'Unsupported by isolated Host fixture' } }));
  });
  host.listen(0, '127.0.0.1');
  await once(host, 'listening');
  const controls = join(root, 'host', 'client-hosts');
  await mkdir(controls, { recursive: true });
  await writeFile(join(controls, `host-${process.pid}.json`), JSON.stringify({ version: 1, owner: 'service',
    pid: process.pid, port: host.address().port, token: hostToken, startedAt: Date.now(), epoch }), { mode: 0o600 });
  const vaultPath = join(root, 'manager', 'vault.json');
  const configPath = join(root, 'manager', 'config.json');
  const devicesPath = join(root, 'manager', 'manager-devices.json');
  const trustPath = join(root, 'public-trust.json');
  const keyPair = signedAccess ? generateKeyPairSync('ed25519') : undefined;
  let publicTrust;
  let managerOrigin, deviceOrigin, deviceBackend;
  if (directLogin) {
    const key = join(root, 'test-tls.key'), cert = join(root, 'test-tls.crt');
    const config = join(root, 'openssl.cnf');
    await writeFile(config, '[req]\ndistinguished_name=dn\n[dn]\n');
    const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', cert,
      '-days', '1', '-nodes', '-subj', '/CN=localhost', '-config', config], { stdio: 'ignore', cwd: root });
    assert.equal(generated.status, 0, 'OpenSSL must generate fixture-only TLS material');
    const tls = { key: await readFile(key), cert: await readFile(cert) };
    managerOrigin = await httpsFront(tls, 'localhost', () => `http://127.0.0.1:${manager.address().port}`);
    deviceOrigin = await httpsFront(tls, '127.0.0.1', () => deviceBackend);
  }
  const seed = makeAuth(vaultPath, configPath);
  const config = await loadConfiguration(configPath);
  await writeFile(configPath, JSON.stringify({ ...config, token: testManagerToken }), { mode: 0o600 });
  if (signedAccess) {
    await writeFile(devicesPath, '[]', { mode: 0o600 });
    manager = makeServer({ vaultPath, configPath, devicesPath, publicOrigin: managerOrigin });
    manager.listen(0, '127.0.0.1');
    await once(manager, 'listening');
    publicTrust = { deviceId: 'isolated-device', ...(directLogin ? { directOrigin: deviceOrigin } : {}), managers: [{ keyId: 'isolated-key',
      origin: managerOrigin || `http://127.0.0.1:${manager.address().port}`, mountPath: `/device/${'0'.repeat(32)}`,
      publicKey: keyPair.publicKey.export({ type: 'spki', format: 'pem' }) }] };
    await writeFile(trustPath, JSON.stringify(publicTrust));
  }
  const sourceArgs = sourceEntry ? ['--import', pathToFileURL(resolve(process.argv[4])).href] : [];
  child = spawn(process.execPath, [...sourceArgs, entry, '--host', '127.0.0.1', '--port', '0',
    '--data', join(root, 'web'), '--workspace', join(root, 'workspace'),
    '--ch-data', join(root, 'host'), '--ch-codex-home', join(root, 'codex'),
    '--ch-host-runtime', join(dirname(entry), 'host-runtime.mjs'),
    '--ch-launcher', join(root, 'disabled-launcher'), '--ch-plugins', join(root, 'plugins'),
    '--token', upstreamToken,
    ...(directLogin ? ['--trusted-proxy', '127.0.0.1'] : []),
    ...(signedAccess ? ['--auth-provider', resolve(import.meta.dirname, 'plugins/manager-access.mjs'), '--auth-provider-config', trustPath] : [])], {
    cwd: root, env: { HOME: root, USERPROFILE: root, LOCALAPPDATA: root,
      XDG_CONFIG_HOME: join(root, 'config'), XDG_DATA_HOME: join(root, 'data'),
      XDG_CACHE_HOME: join(root, 'cache'), XDG_RUNTIME_DIR: root,
      CODEX_HOME: join(root, 'codex'), PATH: dirname(process.execPath), LANG: 'C.UTF-8' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // A deliberately missing launcher prevents fallback to any real Host or Harness.
  let diagnostic = '';
  child.stderr.on('data', (chunk) => { diagnostic = (diagnostic + chunk).slice(-8192).replaceAll(upstreamToken, '<test-token>'); });
  const upstream = await new Promise((done, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error('Isolated packed Web startup timed out')), 30000);
    const finish = (error, value) => { clearTimeout(timeout); error ? reject(error) : done(value); };
    child.once('error', () => finish(new Error('Unable to start isolated packed Web')));
    child.once('exit', () => finish(new Error('Isolated packed Web exited before readiness: ' + diagnostic)));
    child.stdout.on('data', (chunk) => {
      output = (output + chunk).slice(-65536);
      const match = /codexhost web: (http:\/\/[^\s]+)/.exec(output);
      if (match) finish(null, new URL(match[1]).origin);
    });
  });
  deviceBackend = upstream;
  let cookie;
  try {
    if (signedAccess) {
      publicTrust.managers[0].mountPath = `/device/${deviceKey(deviceOrigin || upstream)}`;
      await writeFile(trustPath, JSON.stringify(publicTrust));
      const privateKeyFile = join(root, 'generated-private.pem');
      await writeFile(privateKeyFile, keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      await writeFile(devicesPath, JSON.stringify([{ id: 'isolated-device', keyId: 'isolated-key', name: 'Isolated Device',
        url: deviceOrigin || upstream, directLogin, privateKeyFile }]), { mode: 0o600 });
    } else {
      await seed.login(testManagerToken, { setHeader: (_, value) => { cookie = value.split(';')[0]; } });
      await seed.bind({ headers: { cookie } }, upstream, upstreamToken);
    }
  } finally { seed.close(); }
  if (!manager) {
    manager = makeServer({ vaultPath, configPath });
    manager.listen(0, '127.0.0.1');
    await once(manager, 'listening');
  }
  const base = managerOrigin || `http://127.0.0.1:${manager.address().port}`;
  const mount = `/device/${deviceKey(upstream)}/`;
  browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const context = await browser.newContext({ ignoreHTTPSErrors: directLogin });
  const page = await context.newPage();
  if (signedAccess) {
    await page.goto(base);
    await page.locator('#manager-token').fill(testManagerToken);
    await page.locator('#login-submit').click();
    await page.locator('#dashboard').waitFor({ state: 'visible' });
    const card = page.locator('.card').filter({ has: page.getByRole('heading', { name: 'Isolated Device', exact: true }) });
    await card.waitFor();
    assert.equal(await page.locator('#connection').isVisible(), false);
    assert.equal(await card.locator('.open').getAttribute('href'), directLogin ? '/api/direct-open/isolated-device' : mount);
    const popupPromise = context.waitForEvent('page');
    await card.locator('.open').click();
    const popup = await popupPromise;
    if (directLogin) await popup.waitForURL(deviceOrigin + '/');
    else await popup.waitForLoadState();
    assert.equal(new URL(popup.url()).pathname, directLogin ? '/' : mount);
    assert.equal(await popup.locator('#token').count(), 0);
    if (directLogin) {
      await popup.locator('#root button').first().waitFor();
      assert.equal((await context.request.get(deviceOrigin + '/api/auth/status')).status(), 200);
      const forbidden = await popup.evaluate(async () => {
        const method = 'codexhost/accessTokenGet';
        const reply = await fetch('/api/' + method, { method: 'POST', body: JSON.stringify({ method, payload: { args: {} } }) });
        return (await reply.json()).result?.error?.code;
      });
      assert.equal(forbidden, 'auth/forbidden');
      const unauthenticated = await browser.newContext({ ignoreHTTPSErrors: true });
      assert.equal((await unauthenticated.request.get(deviceOrigin + '/api/auth/status')).status(), 401);
      await unauthenticated.close();
      const result = await popup.evaluate(async () => {
        const socket = new WebSocket(location.origin.replace('https:', 'wss:') + '/api/remote.mux');
        await new Promise((done, reject) => { socket.onopen = done; socket.onerror = reject; });
        const closed = new Promise((done) => { socket.onclose = done; });
        const logout = await fetch('/api/auth/logout', { method: 'POST' });
        await closed;
        return { logout: logout.status, after: (await fetch('/api/auth/status')).status };
      });
      assert.deepEqual(result, { logout: 200, after: 401 });
      assert.equal((await context.request.get(base + '/api/auth/status')).status(), 200);
      console.log('PASS: browser signs in on the device origin, opens the real Web UI and a direct WebSocket, then revokes the device session on logout.');
    }
    await popup.close();
  } else {
    assert.equal((await context.request.post(base + '/api/auth/login', { data: { token: testManagerToken } })).status(), 200);
  }
  if (!directLogin) {
  const errors = [], failedAssets = [];
  let scripts = 0;
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('response', (response) => {
    if (['script', 'stylesheet'].includes(response.request().resourceType())) {
      scripts++;
      if (!response.ok()) failedAssets.push(new URL(response.url()).pathname);
    }
  });
  assert.equal((await page.goto(base + mount)).status(), 200);
  await page.locator('#root button').first().waitFor({ timeout: 30000 });
  assert.equal(await page.locator('[data-dsh-boot]').count(), 0);
  assert.equal(await page.getByText('Failed to load plugins', { exact: true }).count(), 0);
  assert.ok(scripts > 3);
  assert.deepEqual(failedAssets, []);
  assert.deepEqual(errors, []);
  const transfer = await page.evaluate(() => performance.getEntriesByType('resource')
    .filter((entry) => ['script', 'link'].includes(entry.initiatorType))
    .reduce((sum, entry) => ({ encoded: sum.encoded + entry.encodedBodySize, decoded: sum.decoded + entry.decodedBodySize }), { encoded: 0, decoded: 0 }));
  console.log('Isolated static-resource bytes: ' + JSON.stringify(transfer));
  assert.ok(transfer.decoded > 0 && transfer.encoded > 0);
  assert.ok(transfer.encoded < transfer.decoded * 0.9, 'Real packed resources must arrive compressed');
  assert.deepEqual(await page.evaluate(async () => (await fetch('api/auth/status')).json()), { authenticated: true, local: !signedAccess });
  assert.equal(await page.evaluate(async () => (await fetch('api/codexhost/accessTokenGet', {
    method: 'POST', body: JSON.stringify({ type: 'client-request', method: 'codexhost/accessTokenGet', payload: { args: {} } }),
  })).status), 403);
  assert.equal(await page.locator('body').evaluate((element, token) => element.innerHTML.includes(token), upstreamToken), false);
  if (signedAccess) {
    assert.equal((await fetch(upstream + '/api/auth/status')).status, 401);
    const status = await (await context.request.get(base + '/api/auth/status')).json();
    assert.equal(status.accessMode, 'manager');
    assert.deepEqual(status.boundOrigins, []);
    const result = await page.evaluate(async () => {
      const socket = new WebSocket(new URL('api/remote.mux', location.href).href.replace('http:', 'ws:'));
      await new Promise((done, reject) => { socket.onopen = done; socket.onerror = () => reject(new Error('socket refused')); });
      globalThis.managerTestSocket = socket;
      return socket.readyState;
    });
    assert.equal(result, 1);
    const closed = page.evaluate(() => new Promise((done) => { globalThis.managerTestSocket.onclose = () => done(true); }));
    await writeFile(trustPath, JSON.stringify({ ...publicTrust, managers: [] }));
    assert.equal(await closed, true);
    assert.equal((await context.request.get(base + mount + 'api/auth/status')).status(), 401);
    await writeFile(trustPath, JSON.stringify(publicTrust));
    assert.equal((await context.request.get(base + mount + 'api/auth/status')).status(), 200);
    await context.request.post(base + '/api/auth/logout');
    assert.equal((await context.request.get(base + mount)).status(), 401);
  }
  console.log(`PASS: real ${sourceEntry ? 'source' : 'packed'} CodexHost Web shell, plugins, assets, ${signedAccess ? 'signed remote provider' : 'legacy proxy'} authentication and credential boundary; fake Host, models disabled.`);
  }
} finally {
  await browser?.close();
  for (const front of tlsFronts) await new Promise((done) => { front.close(done); front.closeAllConnections(); });
  if (manager) await new Promise((done) => { manager.close(done); manager.closeAllConnections(); });
  if (child?.pid && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit');
    child.kill('SIGTERM');
    const timeout = setTimeout(() => child.kill('SIGKILL'), 5000);
    try { await exited; } finally { clearTimeout(timeout); }
  }
  if (host) await new Promise((done) => { host.close(done); host.closeAllConnections(); });
  await rm(root, { recursive: true, force: true });
}
