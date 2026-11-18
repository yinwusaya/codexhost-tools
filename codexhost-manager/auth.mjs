import { deviceKey } from './proxy.mjs';
import { randomBytes, scrypt, createCipheriv, createDecipheriv, createHash, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { readFile, mkdir, writeFile, rename, rm } from 'node:fs/promises';
import { dirname } from 'node:path';

const derive = promisify(scrypt);
const cookieName = 'codexhost_manager_session';
const lifetime = 8 * 60 * 60 * 1000;
const fault = (status, message) => Object.assign(new Error(message), { status });

export async function loadConfiguration(path, legacy = false) {
  let config;
  try { config = JSON.parse(await readFile(path, 'utf8')); }
  catch (error) {
    if (error.code !== 'ENOENT') throw fault(503, '管理台配置无法读取，不会自动覆盖');
    if (legacy) throw fault(503, '检测到旧版令牌库，请在配置文件的 token 字段填写原管理台令牌');
    config = { token: randomBytes(32).toString('base64url'), encryptionKey: randomBytes(32).toString('base64') };
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    try { await writeFile(path, JSON.stringify(config, null, 2) + '\n', { mode: 0o600, flag: 'wx' }); }
    catch (error) { if (error.code === 'EEXIST') return loadConfiguration(path, legacy); throw error; }
  }
  if (typeof config?.token !== 'string' || config.token.length < 16 || config.token.length > 256) throw fault(503, '配置文件的 token 需为 16 至 256 个字符');
  if (!config.encryptionKey) {
    config.encryptionKey = randomBytes(32).toString('base64');
    const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      await writeFile(temporary, JSON.stringify(config, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      await rename(temporary, path);
    } finally { await rm(temporary, { force: true }); }
  }
  if (typeof config.encryptionKey !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(config.encryptionKey)) throw fault(503, '配置文件的 encryptionKey 无效');
  return config;
}

function seal(data, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('codexhost-manager-vault-v2'));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
  return { version: 2, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: encrypted.toString('base64') };
}

function open(record, key) {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'base64'));
  decipher.setAAD(Buffer.from(`codexhost-manager-vault-v${record.version}`));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  const data = JSON.parse(Buffer.concat([decipher.update(Buffer.from(record.data, 'base64')), decipher.final()]).toString());
  if (!Array.isArray(data.bindings)) throw new Error('Invalid vault');
  return data;
}

export function makeAuth(path, configPath, secureCookies = false) {
  const sessions = new Map();
  const listeners = new Set();
  const revoke = (current, origin) => { for (const listener of listeners) listener(current, origin); };
  let record;
  let loaded;
  let config;
  let queue = Promise.resolve();
  let attempts = [];
  const exclusive = (work) => {
    const result = queue.then(work);
    queue = result.catch(() => {});
    return result;
  };
  async function load() {
    loaded ??= (async () => {
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
        if (![1, 2].includes(record.version) || !['iv', 'tag', 'data'].every((key) => typeof record[key] === 'string')
          || (record.version === 1 && typeof record.salt !== 'string')) throw new Error();
      } catch (error) {
        if (error.code !== 'ENOENT') throw fault(503, '令牌库无法读取，请检查本地文件；不会自动覆盖');
      }
      config = await loadConfiguration(configPath, record?.version === 1);
    })();
    await loaded;
  }
  async function persist(next, initial = false) {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    if (initial) await writeFile(path, JSON.stringify(next), { mode: 0o600, flag: 'wx' });
    else {
      const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
      try {
        await writeFile(temporary, JSON.stringify(next), { mode: 0o600, flag: 'wx' });
        await rename(temporary, path);
      } finally { await rm(temporary, { force: true }); }
    }
    record = next;
  }
  function session(req) {
    for (const [id, value] of sessions) {
      if (value.expires <= Date.now()) { revoke(value); value.key.fill(0); sessions.delete(id); }
    }
    const id = (req.headers.cookie || '').split(';').map((part) => part.trim())
      .find((part) => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
    return sessions.get(id);
  }
  return {
    onRevoke(listener) { listeners.add(listener); },
    async access(req) {
      await load();
      const current = session(req);
      if (!current) throw fault(401, '请先登录管理台');
      return current;
    },
    async status(req) {
      await load();
      const current = session(req);
      const bindings = current ? open(record, current.key).bindings : [];
      return { configured: true, authenticated: !!current,
        boundOrigins: bindings.map((binding) => binding.origin),
        proxyPaths: Object.fromEntries(bindings.map((binding) => [binding.origin, `/device/${deviceKey(binding.origin)}/`])),
        boundDevices: bindings.map((binding) => ({ url: binding.url || binding.origin, name: binding.name || new URL(binding.origin).hostname, role: binding.role || '' })) };
    },
    async login(token, res) {
      return exclusive(async () => {
        await load();
        attempts = attempts.filter((at) => at > Date.now() - 60_000);
        if (attempts.length >= 5) throw fault(429, '尝试过多，请一分钟后重试');
        attempts.push(Date.now());
        if (typeof token !== 'string' || token.length < 16 || token.length > 256) throw fault(400, '管理台令牌需为 16 至 256 个字符');
        const digest = (value) => createHash('sha256').update(value).digest();
        if (!timingSafeEqual(digest(token), digest(config.token))) throw fault(401, '管理台令牌不正确');
        const key = Buffer.from(config.encryptionKey, 'base64');
        try {
          if (record?.version === 1) {
            const legacyKey = await derive(token, Buffer.from(record.salt, 'base64'), 32, { N: 32768, maxmem: 64 * 1024 * 1024 });
            try { await persist(seal(open(record, legacyKey), key)); }
            finally { legacyKey.fill(0); }
          } else if (!record) await persist(seal({ bindings: [] }, key), true);
          else open(record, key);
        } catch {
          key.fill(0);
          throw fault(503, '令牌库无法解密或保存，请检查 encryptionKey 或旧版 token；未自动重置绑定');
        }
        if (sessions.size >= 32) {
          const first = sessions.keys().next().value;
          revoke(sessions.get(first));
          sessions.get(first).key.fill(0);
          sessions.delete(first);
        }
        const id = randomBytes(32).toString('hex');
        sessions.set(id, { key, expires: Date.now() + lifetime });
        res.setHeader('Set-Cookie', `${cookieName}=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${lifetime / 1000}${secureCookies ? '; Secure' : ''}`);
      });
    },
    async credentials(req) {
      await load();
      const current = session(req);
      if (!current) throw fault(401, '请先登录管理台');
      return open(record, current.key).bindings;
    },
    async bind(req, origin, token, details = {}) {
      return exclusive(async () => {
        await load();
        const current = session(req);
        if (!current) throw fault(401, '请先登录管理台');
        const data = open(record, current.key);
        data.bindings = data.bindings.filter((binding) => binding.origin !== origin);
        if (token) {
          if (data.bindings.length >= 100) throw fault(400, '最多绑定 100 台设备');
          data.bindings.push({ origin, token, ...details });
        }
        await persist(seal(data, current.key));
        revoke(undefined, origin);
      });
    },
    logout(req, res) {
      const current = session(req);
      for (const [id, value] of sessions) {
        if (value === current) { revoke(value); value.key.fill(0); sessions.delete(id); }
      }
      res.setHeader('Set-Cookie', `${cookieName}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookies ? '; Secure' : ''}`);
    },
    close() {
      for (const value of sessions.values()) { revoke(value); value.key.fill(0); }
      sessions.clear();
    },
  };
}
