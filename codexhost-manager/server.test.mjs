import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { get, createServer as httpServer } from 'node:http';
import { makeServer, parseTarget, probe, readOverview } from './server.mjs';
import { testServer, testManagerToken } from './test-support.mjs';

test('only private HTTP(S) targets without credentials or parameters are allowed', () => {
  for (const value of ['http://127.0.0.1:4400/', 'http://localhost:4400/', 'http://100.64.0.10:4400/', 'http://192.168.1.2/', 'https://device.example.ts.net/', 'http://10.1.1.2/', 'http://172.16.1.2/']) {
    assert.ok(parseTarget(value));
  }
  for (const value of ['file:///tmp/test', 'javascript:alert(1)', 'http://example.com/', 'http://169.254.169.254/', 'http://100.128.0.1/', 'http://172.32.0.1/', 'http://user:secret@127.0.0.1/', 'http://127.0.0.1/?token=placeholder', 'http://127.0.0.1/#placeholder', null, 'broken']) {
    assert.throws(() => parseTarget(value));
  }
});

async function overviewFixture(t, handler) {
  const calls = [];
  const server = httpServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    calls.push({ method: input.method, params: input.params, path: req.url, cookie: req.headers.cookie });
    handler(req, res, input);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((done) => { server.close(done); server.closeAllConnections(); }));
  return { url: `http://127.0.0.1:${server.address().port}/`, calls };
}

test('overview reads only two metadata methods and discards previews, paths and history', async (t) => {
  const fixture = await overviewFixture(t, (req, res, input) => {
    const result = input.method === 'codexhost/workspace/read'
      ? { projects: [{ id: 'project-1', name: '示例项目', rootPaths: ['/private/example'] }], assignments: { 'task-1': 'project-1' } }
      : { threads: [
        { id: 'task-1', name: '任务标题', status: { type: 'active' }, preview: 'DO_NOT_EXPORT_PREVIEW', turns: [{ items: ['DO_NOT_EXPORT_HISTORY'] }] },
        { id: 'task-2', preview: 'DO_NOT_EXPORT_PREVIEW', status: { type: 'future-state' } },
      ], officialCursor: { live: 'next-page' } };
    res.end(JSON.stringify({ result }));
  });
  const result = await readOverview(fixture.url);
  assert.deepEqual(result.projects, [{ id: 'project-1', name: '示例项目' }]);
  assert.deepEqual(result.tasks[0], { id: 'task-1', title: '任务标题', status: 'active', project: '示例项目' });
  assert.deepEqual(result.tasks[1], { id: 'task-2', title: '未命名会话', status: 'unknown', project: null });
  assert.equal(result.limited, true);
  assert.deepEqual(result.errors, []);
  assert.doesNotMatch(JSON.stringify(result), /DO_NOT_EXPORT|private\/example/);
  assert.deepEqual(fixture.calls.map((call) => call.method).sort(), ['codexhost/thread/catalog/read', 'codexhost/workspace/read']);
  assert.ok(fixture.calls.every((call) => call.path === '/api/ch/v1/rpc' && call.cookie === undefined));
  assert.deepEqual(fixture.calls.find((call) => call.method.includes('catalog')).params, { includeArchived: false });
});

test('overview authentication, partial failure and malformed responses never become empty success', async (t) => {
  let mode = 'auth';
  const fixture = await overviewFixture(t, (req, res, input) => {
    if (mode === 'auth' && req.headers.authorization !== 'Bearer test-only-placeholder') {
      res.writeHead(401).end();
    } else if (mode === 'partial' && input.method.includes('catalog')) {
      res.writeHead(503).end('do not expose upstream errors');
    } else if (mode === 'malformed') res.end('{');
    else if (mode === 'wrong-shape') res.end(JSON.stringify({ result: {} }));
    else res.end(JSON.stringify({ result: input.method.includes('workspace') ? { projects: [] } : { threads: [] } }));
  });
  const anonymous = await readOverview(fixture.url);
  assert.equal(anonymous.projects, null);
  assert.equal(anonymous.tasks, null);
  assert.equal(anonymous.errors[0].code, 'AUTH_REQUIRED');
  const connected = await readOverview(fixture.url, 'test-only-placeholder');
  assert.deepEqual(connected.errors, []);
  mode = 'partial';
  const partial = await readOverview(fixture.url);
  assert.deepEqual(partial.projects, []);
  assert.equal(partial.tasks, null);
  assert.equal(partial.taskError, 'UNSUPPORTED');
  for (mode of ['malformed', 'wrong-shape']) {
    const result = await readOverview(fixture.url);
    assert.equal(result.projects, null);
    assert.equal(result.tasks, null);
    assert.equal(result.projectError, 'UNSUPPORTED');
  }
});

test('overview bounds output, preserves identities, and does not follow redirects', async (t) => {
  let redirect = false;
  const longId = 'x'.repeat(400);
  const fixture = await overviewFixture(t, (req, res, input) => {
    if (redirect) { res.writeHead(302, { Location: 'http://example.com/' }).end(); return; }
    const result = input.method.includes('workspace')
      ? { projects: Array.from({ length: 201 }, (_, i) => ({ id: i === 0 ? longId : `p${i}`, name: `项目${i}` })), assignments: { [longId]: longId } }
      : { threads: Array.from({ length: 101 }, (_, i) => ({ id: i === 0 ? longId : `t${i}`, name: `任务${i}`, status: { type: 'idle' } })), officialCursor: { live: null } };
    res.end(JSON.stringify({ result }));
  });
  const result = await readOverview(fixture.url);
  assert.equal(result.projects.length, 200);
  assert.equal(result.tasks.length, 100);
  assert.equal(result.tasks[0].id, longId);
  assert.equal(result.tasks[0].project, '项目0');
  assert.equal(result.limited, true);
  assert.equal(result.projectsLimited, true);
  redirect = true;
  assert.equal((await readOverview(fixture.url)).errors[0].code, 'UNSUPPORTED');
  assert.equal(fixture.calls.length, 4);
});

test('overview times out and rejects oversized responses', async (t) => {
  let mode = 'timeout';
  const fixture = await overviewFixture(t, (req, res) => {
    if (mode === 'timeout') return;
    res.end(' '.repeat(4 * 1024 * 1024 + 1));
  });
  assert.equal((await readOverview(fixture.url, '', 30)).errors[0].code, 'UNREACHABLE');
  mode = 'oversized';
  assert.equal((await readOverview(fixture.url)).errors[0].code, 'RESPONSE_TOO_LARGE');
});

test('overview HTTP endpoint rejects invalid, oversized and cross-origin requests', async (t) => {
  const { request } = await testServer(t);
  const path = '/api/overview';
  assert.equal((await request(path, { method: 'POST', body: '{' })).status, 400);
  assert.equal((await request(path, { method: 'POST', body: ' '.repeat(9000) })).status, 413);
  assert.equal((await request(path, { method: 'POST', body: '{"url":"http://example.com/"}' })).status, 400);
  assert.equal((await request(path, { method: 'POST', headers: { Origin: 'https://example.com' }, body: '{}' })).status, 403);
});

test('TCP probe reports a listening port and a closed port', async () => {
  const target = createServer((socket) => socket.end());
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  const url = `http://127.0.0.1:${target.address().port}`;
  try {
    const result = await probe(url);
    assert.equal(result.reachable, true);
    assert.ok(result.latency >= 0);
  } finally {
    await new Promise((done) => target.close(done));
  }
  assert.deepEqual(await probe(url), { reachable: false, latency: null });
});

test('HTTP server serves assets, probes ports and rejects cross-origin access', async (t) => {
  const { base, request } = await testServer(t);
  for (const path of ['/', '/app.js', '/styles.css']) {
    const response = await fetch(base + path);
    assert.equal(response.status, 200);
    assert.ok(response.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
    assert.ok((await response.text()).length > 100);
  }
  const status = await request(`/api/status?url=${encodeURIComponent(base)}`);
  assert.equal((await status.json()).reachable, true);
  assert.equal((await request('/api/status?url=file:///example')).status, 400);
  assert.equal((await request('/api/status?url=http://example.com')).status, 400);
  assert.equal((await fetch(base, { headers: { Origin: 'https://example.com' } })).status, 403);
  const rebindingStatus = await new Promise((done, reject) => {
    get(base, { headers: { Host: 'rebind.example' } }, (response) => {
      response.resume();
      done(response.statusCode);
    }).on('error', reject);
  });
  assert.equal(rebindingStatus, 403);
  assert.equal((await fetch(base, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await fetch(base, { method: 'POST' })).status, 405);
  assert.equal((await fetch(base + '/server.mjs')).status, 404);
  assert.equal((await fetch(base + '/favicon.ico')).status, 204);
});

test('HTTPS proxy accepts only the configured origin and uses secure sessions', async (t) => {
  const publicOrigin = 'https://manager.example.ts.net:8443';
  const { base, request } = await testServer(t, { publicOrigin });
  for (const [Host, expected] of [[new URL(publicOrigin).host, 200], ['attacker.example', 403]]) {
    const status = await new Promise((done, reject) => {
      get(base, { headers: { Host, Origin: publicOrigin } }, (response) => {
        response.resume();
        done(response.statusCode);
      }).on('error', reject);
    });
    assert.equal(status, expected);
  }
  const headers = { Origin: publicOrigin };
  const login = await request('/api/auth/login', { method: 'POST', headers, body: JSON.stringify({ token: testManagerToken }) });
  assert.equal(login.status, 200);
  assert.match(login.headers.get('set-cookie'), /; Secure/);
  assert.equal((await (await request('/api/auth/status', { headers })).json()).authenticated, true);
  const logout = await request('/api/auth/logout', { method: 'POST', headers });
  assert.match(logout.headers.get('set-cookie'), /; Secure/);
  for (const headers of [
    { Host: new URL(publicOrigin).host, Origin: 'https://attacker.example' },
    { Origin: 'http://manager.example.ts.net:8443' },
    { Origin: 'https://attacker.example', 'X-Forwarded-Host': new URL(publicOrigin).host, 'X-Forwarded-Proto': 'https' },
    { Origin: publicOrigin, 'Sec-Fetch-Site': 'cross-site' },
  ]) assert.equal((await request('/api/auth/login', { method: 'POST', headers, body: '{}' })).status, 403);
  assert.throws(() => makeServer({ publicOrigin: 'http://manager.example.ts.net' }));
  assert.throws(() => makeServer({ publicOrigin: publicOrigin + '/' }));
});

test('external top-level links may open home while cross-site API and proxy requests remain blocked', async (t) => {
  const { base } = await testServer(t);
  const raw = (path, headers, method = 'GET') => new Promise((done, reject) => {
    const req = get(base + path, { headers, method }, (response) => { response.resume(); done(response.statusCode); });
    req.on('error', reject);
  });
  const headers = { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' };
  assert.equal(await raw('/', headers), 200);
  for (const path of ['/api/auth/status', '/api/overview', '/device/' + '0'.repeat(32) + '/']) {
    assert.equal(await raw(path, headers), 403);
  }
  assert.equal(await raw('/', { ...headers, 'Sec-Fetch-Dest': 'iframe' }), 403);
  assert.equal(await raw('/', { ...headers, Origin: 'https://attacker.example' }), 403);
  assert.equal(await raw('/', headers, 'POST'), 403);
});
