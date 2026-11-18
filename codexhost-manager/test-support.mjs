import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { once } from 'node:events';
import { makeServer } from './server.mjs';
import { loadConfiguration } from './auth.mjs';

export const testManagerToken = 'manager-test-only-placeholder-2026';

export async function testServer(t, options = {}) {
  const root = fileURLToPath(new URL('tmp/', import.meta.url));
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, 'test-'));
  const vaultPath = join(directory, 'vault.json');
  const configPath = join(directory, 'config.json');
  const config = await loadConfiguration(configPath);
  config.token = testManagerToken;
  await writeFile(configPath, JSON.stringify(config));
  const server = makeServer({ ...options, vaultPath });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  if (t) t.after(async () => {
    await new Promise((done) => { server.close(done); server.closeAllConnections(); });
    await rm(directory, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  let cookie = '';
  const request = async (path, options = {}) => {
    const response = await fetch(new URL(path, base), { ...options, headers: { ...(cookie ? { Cookie: cookie } : {}), ...options.headers } });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return response;
  };
  const setup = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ token: testManagerToken }) });
  if (!setup.ok) throw new Error('Test setup failed');
  return { server, base, request, vaultPath, configPath, cookie: () => cookie };
}
