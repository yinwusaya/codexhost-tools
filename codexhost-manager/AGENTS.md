# CodexHost Manager

- This directory is a tool in `codexhost-tools`, not a standalone Git repository.
- Read `README.md` for setup, authentication modes, and test commands.
- Keep device-specific settings and runtime data outside version control.
- Do not read existing credentials or real conversation bodies during testing.
  Use isolated fixtures and generated test credentials.
- Preserve original device authentication and fail closed on invalid signed trust.
- Run `npm run check`, `npm test`, and browser regressions before publication.
- Do not restart shared Hosts or deploy production changes without explicit approval.
