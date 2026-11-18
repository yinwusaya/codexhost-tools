# CodexHost Manager

A standalone, zero-runtime-dependency dashboard for your own CodexHost devices.
Includes device management, TCP reachability checks, project/task metadata,
authenticated HTTP/WebSocket proxying, and a standalone signed-access plugin.
It does not start or restart the core Host.

## Start

Requires Node.js 22 or newer. From this directory:

```sh
npm start
```

Open http://127.0.0.1:4410. The server listens only on loopback. Use
`node server.mjs 4411` to choose another port.

On the first page request, the server generates `.local/config.json` containing
the manager login token and vault encryption key. The administrator retrieves
the token locally and enters it in the login form; never publish this file.
Do not replace an existing configuration or vault when upgrading.

The initial device list is empty. Add a local, LAN, or Tailscale HTTP(S) address
without user information, query parameters, or a fragment. TCP reachability alone
does not prove application health, TLS validity, or successful authentication.

## Authentication Modes

Without a signed device manifest, legacy mode asks for each device's Web access
token. Bindings are encrypted in the server-side `.local/vault.json`; device
tokens are not stored in browser storage or forwarded to the browser.

Signed mode requires a CodexHost Web build supporting the generic authentication
provider extension. Installing this plugin alone does not add that extension to
an older Web build. Core Host changes belong in the separate CodexHost repository;
the device plugin is maintained here as `plugins/manager-access.mjs`.

Generate independent Ed25519 keys in a new, nonexistent directory:

```sh
node provision-access.mjs .local/signed-access https://manager.example.com \
  workstation https://workstation.example.ts.net/
```

The manager keeps `manager-devices.json` and `*-private.pem`. Copy only the
corresponding `*-trust.json` and `plugins/manager-access.mjs` to each device.
The example domains are placeholders; replace them with your private endpoints.

Start the manager with the same HTTPS origin configured in device trust:

```sh
node server.mjs 4410 https://manager.example.com .local/signed-access/manager-devices.json
```

Configure the supporting device Node Web entry with:

```sh
node /absolute/path/web-server.mjs \
  --auth-provider /absolute/path/plugins/manager-access.mjs \
  --auth-provider-config /absolute/path/workstation-trust.json
```

Preserve the device's other launch options and Web data directory. Refer to
CodexHost's `docs/product/web-auth-providers.md` for background service options.
Changing the Web service does not require replacing or restarting the core Host.

The manifest enables signed mode: one manager login grants access to configured
devices without per-device token entry. Existing legacy bindings are retained
but unused. Removing a manifest from a running signed manager fails closed;
returning to legacy mode requires an explicit configuration change and restart.

## Security And Limitations

- Every request and WebSocket handshake has a short-lived, replay-resistant
  signature bound to device, session, method, path, origin, and mount path.
- Invalid trust fails closed. Logout and trust changes revoke proxy connections.
  Private key rotation must also update the manager manifest.
- Deploy only on trusted private networks, using HTTPS for remote access. Device
  targets are restricted to loopback, private IPv4, and privately resolved Tailscale.
- Device pages share the manager origin. Use only trusted devices; the path proxy
  is not a browser security boundary between mutually untrusted applications.
- Device Service Workers/PWA are not supported through the path proxy.
- The dashboard overview reads metadata only, but proxied device access is not
  read-only. Device token read/reset RPCs are blocked by the proxy.
- HTTP connection reuse and gzip reduce connection and asset transfer overhead;
  they cannot remove poor underlying network routing or relay latency.

## Deployment Templates

`deploy/` contains example systemd, Caddy, and certificate-renewal configurations.
Replace example paths, domain, private bind address, and Node executable before
installation. Keep manager origin and device trust consistent. The Caddy template
binds a placeholder private address; do not expose it publicly by accident.
Templates contain no certificates or credentials and do not deploy automatically.

## Tests

```sh
npm run check
npm test
node test-ui.mjs /absolute/path/playwright/index.mjs
node test-packed-ui.mjs /absolute/path/playwright/index.mjs /absolute/path/web-server.mjs
node test-packed-ui.mjs /absolute/path/playwright/index.mjs /absolute/path/web-server.mjs --manager-access
```

Browser tests require an existing Playwright installation and Chromium; optionally
set `PLAYWRIGHT_CHANNEL` to an installed compatible browser. Packed tests require
a compatible CodexHost Web build and its adjacent runtime resources. They use an
isolated fixture Host and generated temporary credentials, not real conversations
or model calls. Runtime test artifacts stay under ignored `tmp/`.
