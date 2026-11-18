import { generateKeyPairSync } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { deviceKey } from './proxy.mjs';
import { parseTarget } from './server.mjs';

const [output, origin, ...pairs] = process.argv.slice(2);
if (!output || !origin || pairs.length === 0 || pairs.length % 2 !== 0)
  throw new Error('Usage: node provision-access.mjs <new-directory> <manager-origin> <device-id> <device-url> [...]');
if (new URL(origin).origin !== origin || !['https:', 'http:'].includes(new URL(origin).protocol))
  throw new Error('Expected a manager HTTP(S) origin');
const devices = [];
const seen = new Set();
for (let i = 0; i < pairs.length; i += 2) {
  const id = pairs[i], url = parseTarget(pairs[i + 1]);
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(id) || seen.has(id) || seen.has(url.origin) || url.pathname !== '/')
    throw new Error('Invalid or duplicate device');
  seen.add(id); seen.add(url.origin);
  devices.push({ id, url: url.href, name: id, keyId: `manager-${id}-v1`, privateKeyFile: `${id}-private.pem` });
}
const root = resolve(output);
// Exclusive creation prevents overwriting an existing deployment or key set.
await mkdir(root, { mode: 0o700 });
for (const device of devices) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  await writeFile(join(root, device.privateKeyFile), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  const trust = { deviceId: device.id, managers: [{ keyId: device.keyId, origin,
    mountPath: `/device/${deviceKey(new URL(device.url).origin)}`,
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }) }] };
  await writeFile(join(root, `${device.id}-trust.json`), JSON.stringify(trust, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
}
await writeFile(join(root, 'manager-devices.json'), JSON.stringify(devices, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
console.log(`Created independent manager keys and public device trust in ${root}`);
