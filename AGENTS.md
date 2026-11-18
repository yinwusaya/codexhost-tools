# CodexHost Tools

- Develop on `dev`; each companion tool lives in its own directory.
- Core Host changes belong in the separate CodexHost repository.
- Preserve existing changes and comments. Use explicit paths when staging.
- Never read or commit existing credentials, runtime data, private deployment
  records, `.local/`, `tmp/`, dependency directories, or key files.
- Run the affected tool's syntax, backend, and browser tests before publishing.
- Repository publication does not authorize production deployment or restarts.
