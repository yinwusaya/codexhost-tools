import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { rm } from 'node:fs/promises';
import { deviceKey } from './proxy.mjs';
import { makeServer } from './server.mjs';
import { testServer, testManagerToken } from './test-support.mjs';

if (!process.argv[2]) throw new Error('Usage: node test-ui.mjs <path-to-playwright/index.mjs>');
const { chromium } = await import(pathToFileURL(resolve(process.argv[2])).href);
const browser = await chromium.launch({ ...(process.env.PLAYWRIGHT_CHANNEL ? { channel: process.env.PLAYWRIGHT_CHANNEL } : {}), headless: true });
const fixture = await testServer();
const app = fixture.server;
let fixtureMode = 'normal';
const fixtureMethods = [];
const target = createServer(async (req, res) => {
  if (req.url === '/assets/probe.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript' }).end('import "/assets/side-effect.js"; export { value } from "/assets/value.js"; import("/assets/lazy.js").then(module => { globalThis.proxyLazy = module.value; }); globalThis.proxyAssetLoaded = true;'); return;
  }
  if (req.url === '/assets/side-effect.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript' }).end('globalThis.proxySideEffect = true;'); return;
  }
  if (req.url === '/assets/value.js' || req.url === '/assets/lazy.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript' }).end('export const value = "device-module";'); return;
  }
  if (req.url === '/probe') {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ authenticated: req.headers.authorization === 'Bearer ui-test-only-placeholder', cookie: !!req.headers.cookie })); return;
  }
  if (!req.url.startsWith('/api/')) {
    res.writeHead(200, { 'Content-Type': 'text/html' }).end('<head><script type="module" src="/assets/probe.js"></script></head><body>Fixture CodexHost entry</body>'); return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  fixtureMethods.push(input.method);
  if (req.headers.authorization !== 'Bearer ui-test-only-placeholder') { res.writeHead(401).end(); return; }
  if (fixtureMode === 'partial' && input.method.includes('catalog')) { res.writeHead(503).end(); return; }
  if (fixtureMode === 'slow') await new Promise((done) => setTimeout(done, 250));
  res.end(JSON.stringify({ result: input.method.includes('workspace')
    ? { projects: [{ id: 'project1', name: '测试项目', rootPaths: ['/private/test'] }], assignments: { task1: 'project1' } }
    : { threads: [{ id: 'task1', name: '只读任务 <img src=x>', status: { type: 'active' } }, { id: 'task2', name: '空闲任务', status: { type: 'idle' } }], officialCursor: { live: 'next-page' } } }));
});
target.listen(0, '127.0.0.1');
await once(target, 'listening');
const base = `http://127.0.0.1:${app.address().port}`;
const targetUrl = `http://127.0.0.1:${target.address().port}/`;
const errors = [];
const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
const page = await context.newPage();
page.on('pageerror', (error) => errors.push(error.message));

async function fillDevice(name, url, role = '测试设备') {
  await page.locator('#name').fill(name);
  await page.locator('#role').fill(role);
  await page.locator('#url').fill(url);
  await page.getByRole('button', { name: '保存设备', exact: true }).click();
}

try {
  await page.goto(base);
  await page.locator('#login-title').waitFor();
  assert.equal(await page.locator('#dashboard').isVisible(), false);
  await page.locator('#manager-token').fill(testManagerToken);
  await page.locator('#login-submit').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });
  await page.locator('#refresh:not([disabled])').waitFor();
  assert.equal(await page.locator('.card').count(), 0);
  assert.equal(await page.locator('#empty').isVisible(), true);
  await page.evaluate(() => localStorage.setItem('codexhost-manager.devices.v1', '[]'));
  await page.reload();
  assert.equal(await page.locator('#empty').isVisible(), true);

  await page.locator('#add').click();
  await fillDevice('本地测试', targetUrl);
  await page.locator('.status[data-kind="reachable"]').waitFor();
  assert.match(await page.locator('#summary').textContent(), /1 台设备 \/ 1 台可连接/);
  await page.reload();
  await page.locator('.status[data-kind="reachable"]').waitFor();
  assert.equal(await page.locator('.card h3').textContent(), '本地测试');
  await page.locator('.open').click();
  await page.locator('#connection').waitFor({ state: 'visible' });
  await page.locator('#connection-cancel').click();

  await page.getByRole('button', { name: '连接设备', exact: true }).waitFor();
  assert.match(await page.locator('#overview-results').textContent(), /需要连接/);
  await page.getByRole('button', { name: '连接设备', exact: true }).click();
  await page.locator('#access-token').fill('invalid-test-device-token');
  await page.getByRole('button', { name: '连接并读取' }).click();
  await page.locator('#connection-error').waitFor({ state: 'visible' });
  assert.equal(await page.locator('.disconnect').count(), 0);
  await page.locator('#access-token').fill('ui-test-only-placeholder');
  await page.getByRole('button', { name: '连接并读取' }).click();
  await page.locator('.task-row').first().waitFor();
  assert.equal(await page.locator('.task-row').count(), 2);
  assert.equal(await page.locator('.task-status[data-kind="active"]').textContent(), '运行中');
  assert.equal(await page.locator('.task-project').first().textContent(), '测试项目');
  assert.equal(await page.locator('#overview-results img').count(), 0);
  assert.match(await page.locator('#overview-results').textContent(), /更多历史/);
  assert.equal(await page.locator('#access-token').inputValue(), '');
  const stored = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  assert.doesNotMatch(stored, /ui-test-only-placeholder|只读任务|测试项目/);
  const taskPopupPromise = context.waitForEvent('page');
  await page.locator('.task-row a').first().click();
  const taskPopup = await taskPopupPromise;
  taskPopup.on('pageerror', (error) => errors.push(error.message));
  await taskPopup.waitForLoadState();
  assert.equal(taskPopup.url(), `${base}/device/${deviceKey(new URL(targetUrl).origin)}/?session=task1`);
  await taskPopup.waitForFunction(() => globalThis.proxyAssetLoaded === true);
  await taskPopup.waitForFunction(() => globalThis.proxySideEffect === true && globalThis.proxyLazy === 'device-module');
  assert.deepEqual(await taskPopup.evaluate(async () => (await fetch('/probe')).json()), { authenticated: true, cookie: false });
  assert.deepEqual(await taskPopup.evaluate(async () => (await fetch(new Request(new URL('/probe', location.href)))).json()), { authenticated: true, cookie: false });
  assert.equal(await taskPopup.evaluate(async () => (await fetch('/api/settings/get', {
    method: 'POST', body: JSON.stringify({ method: 'codexhost/accessTokenGet' }),
  })).status), 403);
  await taskPopup.evaluate(() => { localStorage.setItem('proxy-test', 'device-only'); sessionStorage.setItem('session-test', 'device-only'); });
  assert.equal(await taskPopup.evaluate(() => localStorage.getItem('proxy-test')), 'device-only');
  assert.equal(await page.evaluate(() => localStorage.getItem('proxy-test')), null);
  assert.equal(await taskPopup.evaluate(() => localStorage.getItem('codexhost-manager.devices.v1')), null);
  await taskPopup.close();

  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.setViewportSize({ width: 1280, height: 1000 });
  fixtureMode = 'partial';
  await page.locator('#load-overviews').click();
  await page.locator('#load-overviews:not([disabled])').waitFor();
  assert.match(await page.locator('#overview-results').textContent(), /测试项目/);
  assert.match(await page.locator('#overview-results').textContent(), /任务：读取失败/);
  assert.equal(await page.locator('.task-row').count(), 0);

  fixtureMode = 'slow';
  await page.locator('.connect').click();
  await page.locator('.disconnect').click();
  await page.waitForTimeout(400);
  assert.equal(await page.locator('.task-row').count(), 0);
  await page.locator('.disconnect').waitFor({ state: 'detached' });
  fixtureMode = 'normal';
  await page.locator('.connect').click();
  await page.getByRole('button', { name: '连接设备', exact: true }).click();
  await page.locator('#access-token').fill('ui-test-only-placeholder');
  await page.getByRole('button', { name: '连接并读取' }).click();
  await page.locator('.task-row').first().waitFor();
  await page.reload();
  await page.locator('.task-row').first().waitFor();
  assert.equal(await page.locator('.disconnect').count(), 1);
  await page.locator('#logout').click();
  await page.locator('#dashboard').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('.task-row').count(), 0);
  await page.locator('#manager-token').fill(testManagerToken);
  await page.locator('#login-submit').click();
  await page.locator('.task-row').first().waitFor();
  assert.equal(await page.locator('#manager-token').inputValue(), '');
  const cleanContext = await browser.newContext();
  const cleanPage = await cleanContext.newPage();
  await cleanPage.goto(base);
  await cleanPage.locator('#manager-token').fill(testManagerToken);
  await cleanPage.locator('#login-submit').click();
  await cleanPage.locator('.task-row').first().waitFor();
  assert.equal(await cleanPage.getByRole('heading', { name: '本地测试', exact: true }).count(), 2);
  await cleanContext.close();
  assert.ok(fixtureMethods.every((method) => ['codexhost/workspace/read', 'codexhost/thread/catalog/read'].includes(method)));

  await page.locator('.edit').click();
  await fillDevice('<img src=x onerror=alert(1)>', targetUrl);
  assert.equal(await page.locator('.card h3').textContent(), '<img src=x onerror=alert(1)>');
  assert.equal(await page.locator('.card img').count(), 0);
  await page.locator('.edit').click();
  await page.locator('#url').fill('http://127.0.0.1/?token=placeholder');
  await page.getByRole('button', { name: '保存设备', exact: true }).click();
  assert.equal(await page.locator('#editor').isVisible(), true);
  assert.equal(await page.locator('#form-error').isVisible(), true);
  await page.locator('#cancel').click();

  await page.locator('#add').click();
  await fillDevice('待配置设备', '');
  assert.equal(await page.locator('.status[data-kind="unconfigured"]').count(), 1);
  await page.getByRole('link', { name: '设置地址' }).click();
  await page.locator('#name').fill('改名设备');
  await page.getByRole('button', { name: '保存设备', exact: true }).click();
  await page.reload();
  assert.equal(await page.getByRole('heading', { name: '改名设备' }).count(), 1);

  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.equal(await page.locator('#devices').evaluate((el) => getComputedStyle(el).gridTemplateColumns.split(' ').length), 1);
  await page.setViewportSize({ width: 1280, height: 1000 });
  assert.equal(await page.locator('#devices').evaluate((el) => getComputedStyle(el).gridTemplateColumns.split(' ').length), 2);

  page.on('dialog', (dialog) => dialog.accept());
  if (await page.locator('.disconnect').count()) {
    await page.locator('.disconnect').click();
    await page.locator('.disconnect').waitFor({ state: 'detached' });
  }
  while (await page.locator('.card').count()) {
    await page.locator('.edit').first().click();
    await page.locator('#delete').click();
    await page.locator('#editor').waitFor({ state: 'hidden' });
  }
  await page.reload();
  assert.equal(await page.locator('#empty').isVisible(), true);
  assert.equal(await page.locator('.card').count(), 0);

  await page.evaluate(() => localStorage.setItem('codexhost-manager.devices.v1', 'invalid-json'));
  await page.reload();
  assert.equal(await page.locator('#notice').isVisible(), true);
  assert.equal(await page.locator('.card').count(), 0);
  assert.equal(await page.evaluate(() => localStorage.getItem('codexhost-manager.devices.v1')), 'invalid-json');
  await page.evaluate(() => {
    Storage.prototype.setItem = () => { throw new Error('Storage unavailable'); };
  });
  await page.locator('#add').click();
  await fillDevice('不能保存', '');
  assert.match(await page.locator('#form-error').textContent(), /未保存/);
  assert.equal(await page.locator('#editor').isVisible(), true);
  assert.equal(await page.locator('.card').count(), 0);
  assert.deepEqual(errors, []);
  const firstRun = makeServer({ vaultPath: `${fixture.vaultPath}.first-run` });
  firstRun.listen(0, '127.0.0.1');
  await once(firstRun, 'listening');
  const firstContext = await browser.newContext();
  try {
    const firstPage = await firstContext.newPage();
    await firstPage.goto(`http://127.0.0.1:${firstRun.address().port}`);
    await firstPage.getByRole('heading', { name: '登录管理台' }).waitFor();
    assert.equal(await firstPage.getByRole('heading', { name: '设置管理台令牌' }).count(), 0);
    await firstPage.locator('#manager-token').fill(testManagerToken);
    await firstPage.locator('#login-submit').click();
    await firstPage.locator('#dashboard').waitFor({ state: 'visible' });
    assert.equal(await firstPage.locator('#manager-token').inputValue(), '');
    assert.equal(await firstPage.locator('#login-panel').isVisible(), false);
  } finally {
    await firstContext.close();
    await new Promise((done) => { firstRun.close(done); firstRun.closeAllConnections(); });
  }
  console.log('PASS: unified login/logout, encrypted bindings restored on refresh and fresh browser login, metadata, device management, errors, races, XSS, responsive layout.');
} finally {
  await browser.close();
  await Promise.all([new Promise((done) => app.close(done)), new Promise((done) => target.close(done))]);
  await rm(dirname(fixture.vaultPath), { recursive: true, force: true });
}
