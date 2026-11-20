import { createPrivateKey, randomBytes, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { deviceKey } from './proxy.mjs';

export const browserLoginPath = '/api/auth/provider/login';

export function signRequest(device, session, method, target, publicOrigin, browserSession) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const proof = Buffer.from(JSON.stringify({
    version: 1, keyId: device.keyId, audience: device.id, sessionId: session,
    method, target, publicOrigin, mountPath: `/device/${deviceKey(device.origin)}`,
    issuedAt, expiresAt: issuedAt + 30, nonce: randomBytes(24).toString('base64url'),
    ...(browserSession === undefined ? {} : { directOrigin: device.origin, browserSession }),
  })).toString('base64url');
  return {
    'x-codexhost-manager-proof': proof,
    'x-codexhost-manager-signature': sign(null, Buffer.from(proof), device.privateKey).toString('base64url'),
  };
}

export function makeManagerAccess(path, parseTarget) {
  let previous;
  let devices = [];
  let configured = false;
  const sessionIds = new WeakMap();
  const listeners = new Set();
  const revoke = () => { for (const listener of listeners) listener(); };
  function refresh() {
    let source;
    try { source = readFileSync(path, 'utf8'); }
    catch (error) {
      if (configured) { devices = []; previous = undefined; revoke(); }
      if (error.code !== 'ENOENT') throw Object.assign(new Error('管理台信任配置无法读取'), { status: 503 });
      // Once enabled, deleting the manifest must not reactivate legacy credentials.
      return;
    }
    configured = true;
    if (source === previous) return;
    previous = undefined;
    devices = [];
    revoke();
    try {
      const rows = JSON.parse(source);
      if (!Array.isArray(rows) || rows.length > 100) throw new Error();
      const origins = new Set(), ids = new Set(), keyIds = new Set();
      const next = rows.map((row) => {
        if (typeof row.id !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(row.id)
          || typeof row.keyId !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(row.keyId)
          || typeof row.privateKeyFile !== 'string') throw new Error();
        const url = parseTarget(row.url);
        if (url.pathname !== '/' || origins.has(url.origin) || ids.has(row.id) || keyIds.has(row.keyId)
          || (row.directLogin === true && url.protocol !== 'https:')) throw new Error();
        origins.add(url.origin); ids.add(row.id); keyIds.add(row.keyId);
        if (row.enabled === false) return null;
        const keyFile = isAbsolute(row.privateKeyFile) ? row.privateKeyFile : resolve(dirname(path), row.privateKeyFile);
        const privateKey = createPrivateKey(readFileSync(keyFile));
        if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error();
        return { id: row.id, keyId: row.keyId, origin: url.origin, url: url.href,
          name: typeof row.name === 'string' ? row.name.slice(0, 60) : row.id,
          role: typeof row.role === 'string' ? row.role.slice(0, 100) : '', directLogin: row.directLogin === true, privateKey };
      }).filter(Boolean);
      devices = next;
      previous = source;
    } catch { throw Object.assign(new Error('管理台信任配置无效'), { status: 503 }); }
  }
  const timer = setInterval(() => { try { refresh(); } catch { /* Requests fail closed until repaired. */ } }, 1000);
  timer.unref();
  return {
    onRevoke(listener) { listeners.add(listener); },
    configured() { refresh(); return configured; },
    devices() { refresh(); return devices; },
    headers(device, session, method, target, origin, browserSession) {
      refresh();
      if (!devices.includes(device)) throw Object.assign(new Error('管理台信任已撤销'), { status: 403 });
      if (!sessionIds.has(session)) sessionIds.set(session, randomBytes(24).toString('base64url'));
      return signRequest(device, sessionIds.get(session), method, target, origin, browserSession);
    },
    close() { clearInterval(timer); devices = []; revoke(); listeners.clear(); },
  };
}
