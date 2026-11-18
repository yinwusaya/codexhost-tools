import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const proofHeader = 'x-codexhost-manager-proof';
const signatureHeader = 'x-codexhost-manager-signature';
const id = /^[A-Za-z0-9_-]{1,96}$/;
const encoded = /^[A-Za-z0-9_-]+$/;

// This module is loaded only through the server's explicit --auth-provider option.
export default function createProvider({ configFile } = {}) {
  if (!configFile) throw new Error('manager-access requires a public trust configuration');
  let previous;
  let configuration;
  let keys = new Map();
  let disposed = false;
  const listeners = new Set();
  const nonces = new Map();
  const revoke = () => { for (const listener of listeners) listener(); };
  function refresh(initial = false) {
    try {
      const source = readFileSync(configFile, 'utf8');
      if (source === previous) return;
      const next = JSON.parse(source);
      if (typeof next.deviceId !== 'string' || !id.test(next.deviceId) || !Array.isArray(next.managers) || next.managers.length > 32) throw new Error();
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
      revoke();
    } catch {
      previous = undefined;
      configuration = undefined;
      keys = new Map();
      revoke();
      if (initial) throw new Error('Invalid manager-access public trust configuration');
    }
  }
  refresh(true);
  const timer = setInterval(() => refresh(), 1000);
  timer.unref();
  return {
    authenticate(request) {
      const proof = request.headers[proofHeader];
      const signature = request.headers[signatureHeader];
      if (proof === undefined && signature === undefined) return { status: 'not-applicable' };
      const denied = { status: 'denied' };
      if (disposed) return denied;
      refresh();
      try {
        if (!configuration || typeof proof !== 'string' || typeof signature !== 'string'
          || proof.length > 4096 || signature.length !== 86 || !encoded.test(proof) || !encoded.test(signature)) return denied;
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
          || !verify(null, Buffer.from(proof), trusted.key, Buffer.from(signature, 'base64url'))) return denied;
        for (const [nonce, until] of nonces) if (until <= now) nonces.delete(nonce);
        const nonce = `${claim.keyId}:${claim.nonce}`;
        if (nonces.has(nonce) || nonces.size >= 10000) return denied;
        nonces.set(nonce, claim.expiresAt);
        return { status: 'authenticated', credential: `${claim.keyId}:${claim.sessionId}`, expiresAt: Date.now() + 300000 };
      } catch { return denied; }
    },
    onRevoke(listener) { listeners.add(listener); },
    dispose() { disposed = true; clearInterval(timer); revoke(); listeners.clear(); keys.clear(); nonces.clear(); },
  };
}
