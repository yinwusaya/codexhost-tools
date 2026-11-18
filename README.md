# CodexHost Tools

Tools for [CodexHost](https://github.com/yinwusaya/codex-host). This repository
contains companion tools, not the core Host implementation.

## Tools

- [codexhost-manager](codexhost-manager/): multi-device dashboard, project/task
  metadata overview, authenticated HTTP/WebSocket proxy, and device access plugin.

## Quick Start

Requires Node.js 22 or newer. No runtime dependencies to install.

```sh
cd codexhost-manager
npm start
```

Open http://127.0.0.1:4410 and follow the tool's [setup guide](codexhost-manager/README.md).
Development uses `dev`. Runtime data, credentials, and deployment-specific settings
do not belong in this repository.
