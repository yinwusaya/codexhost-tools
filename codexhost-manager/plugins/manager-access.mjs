import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const proofHeader = 'x-codexhost-manager-proof';
const signatureHeader = 'x-codexhost-manager-signature';
const id = /^[A-Za-z0-9_-]{1,96}$/;
const encoded = /^[A-Za-z0-9_-]+$/;
const cookieName = '__Host-codexhost_manager';
const browserSeconds = 8 * 60 * 60;
const browserCookie = (value, age) => `${cookieName}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`;
const browserKey = (value) => createHash('sha256').update(value).digest('base64url');
function browserId(request) {
  const value = request.headers.cookie?.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
  if (value && /^[A-Za-z0-9_-]{43}$/.test(value)) return browserKey(value);
}

// This module is loaded only through the server's explicit --auth-provider option.
export default function createProvider({ configFile } = {}) {
  if (!configFile) throw new Error('manager-access requires a public trust configuration');
  let previous;
  let configuration;
  let keys = new Map();
  let disposed = false;
  const listeners = new Set();
  const nonces = new Map();
  const browsers = new Map();
  const revoke = () => { for (const listener of listeners) listener(); };
  function refresh(initial = false) {
    try {
      const source = readFileSync(configFile, 'utf8');
      if (source === previous) return;
      const next = JSON.parse(source);
      if (typeof next.deviceId !== 'string' || !id.test(next.deviceId) || !Array.isArray(next.managers) || next.managers.length > 32) throw new Error();
      if (next.directOrigin !== undefined) {
        const direct = new URL(next.directOrigin);
        if (direct.protocol !== 'https:' || direct.origin !== next.directOrigin) throw new Error();
      }
      const nextKeys = new Map();
      for (const row of next.managers) {
        const origin = new URL(row.origin);
        if (typeof row.keyId !== 'string' || !id.test(row.keyId) || nextKeys.has(row.keyId)
          || !['http:', 'https:'].includes(origin.protocol) || origin.origin !== row.origin
          || !/^\/device\/[a-f0-9]{32}$/.test(row.mountPath)) throw new Error();
        const key = createPublicKey(row.publicKey);
        if (key.asymmetricKeyType !== 'ed25519') throw new Error();
        nextKeys.set(row.keyId, { key, origin: row.origin, mountPath: row.mountPath });
      }
      previous = source;
      configuration = next;
      keys = nextKeys;
      browsers.clear();
      revoke();
    } catch {
      previous = undefined;
      configuration = undefined;
      keys = new Map();
      browsers.clear();
      revoke();
      if (initial) throw new Error('Invalid manager-access public trust configuration');
    }
  }
  refresh(true);
  const timer = setInterval(() => refresh(), 1000);
  timer.unref();
  function verifyProof(request, proof, signature, browser = false) {
      if (disposed) return;
      refresh();
      try {
        if (!configuration || typeof proof !== 'string' || typeof signature !== 'string'
          || proof.length > 4096 || signature.length !== 86 || !encoded.test(proof) || !encoded.test(signature)) return;
        const claim = JSON.parse(Buffer.from(proof, 'base64url').toString('utf8'));
        const trusted = keys.get(claim.keyId);
        const now = Math.floor(Date.now() / 1000);
        if (!trusted || claim.version !== 1 || claim.audience !== configuration.deviceId
          || claim.method !== request.method || claim.target !== request.url
          || claim.publicOrigin !== trusted.origin || claim.mountPath !== trusted.mountPath
          || typeof claim.sessionId !== 'string' || !id.test(claim.sessionId) || typeof claim.nonce !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(claim.nonce)
          || !Number.isSafeInteger(claim.issuedAt) || !Number.isSafeInteger(claim.expiresAt)
          || claim.issuedAt > now + 5 || claim.expiresAt <= now || claim.expiresAt <= claim.issuedAt
          || claim.expiresAt - claim.issuedAt > 30 || now - claim.issuedAt > 35
          || (browser ? trusted.origin !== request.headers.origin || !trusted.origin.startsWith('https://')
            || claim.directOrigin !== configuration.directOrigin || typeof claim.browserSession !== 'string'
            || claim.browserSession.length > 256 : claim.directOrigin !== undefined)
          || !verify(null, Buffer.from(proof), trusted.key, Buffer.from(signature, 'base64url'))) return;
        for (const [nonce, until] of nonces) if (until <= now) nonces.delete(nonce);
        const nonce = `${claim.keyId}:${claim.nonce}`;
        if (nonces.has(nonce) || nonces.size >= 10000) return;
        nonces.set(nonce, claim.expiresAt);
        return claim;
      } catch { return; }
  }
  function directHost(request) {
    return !!configuration?.directOrigin && request.headers.host === new URL(configuration.directOrigin).host;
  }
  return {
    authenticate(request, secure) {
      const proof = request.headers[proofHeader];
      const signature = request.headers[signatureHeader];
      if (proof !== undefined || signature !== undefined) {
        const claim = verifyProof(request, proof, signature);
        return claim ? { status: 'authenticated', credential: `${claim.keyId}:${claim.sessionId}`, expiresAt: Date.now() + 300000 }
          : { status: 'denied' };
      }
      const value = secure && browserId(request);
      if (value) {
        const expiresAt = browsers.get(value);
        if (directHost(request) && expiresAt > Date.now()) return { status: 'authenticated', credential: `browser:${value}`, expiresAt, browserSession: true };
      }
      return { status: 'not-applicable' };
    },
    async browserLogin(request) {
      if (!directHost(request) || !request.headers['content-type']?.startsWith('application/x-www-form-urlencoded')) return;
      const chunks = []; let size = 0;
      for await (const chunk of request.iterator({ destroyOnReturn: false })) {
        if ((size += chunk.length) > 8192) return;
        chunks.push(chunk);
      }
      const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      const claim = verifyProof(request, body.get('proof'), body.get('signature'), true);
      if (!claim || !directHost(request)) return;
      const now = Date.now();
      for (const [value, expiry] of browsers) if (expiry <= now) browsers.delete(value);
      if (browsers.size >= 1000) return;
      const value = randomBytes(32).toString('base64url');
      browsers.set(browserKey(value), now + browserSeconds * 1000);
      return { cookie: browserCookie(value, browserSeconds), location: claim.browserSession
        ? `/?${new URLSearchParams({ session: claim.browserSession })}` : '/' };
    },
    browserLogout(request) {
      const value = browserId(request);
      if (request.headers[proofHeader] !== undefined || request.headers[signatureHeader] !== undefined
        || !directHost(request) || !browsers.delete(value)) return;
      for (const listener of listeners) listener(`browser:${value}`);
      return browserCookie('', 0);
    },
    onRevoke(listener) { listeners.add(listener); },
    dispose() { disposed = true; clearInterval(timer); revoke(); listeners.clear(); keys.clear(); nonces.clear(); browsers.clear(); },
  };
}
