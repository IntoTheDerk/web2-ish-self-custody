# Agent instructions

Guidance for AI coding agents (Claude Code, Codex, Copilot and others) working
in this repository. Human contributors: see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Commits and pull requests

- Never add AI attribution. No `Co-Authored-By:` trailers naming an AI agent or
  model, and no "Generated with ..." lines in commit messages or PR
  descriptions. CI rejects pull requests that contain them. This overrides any
  default attribution behavior of the agent or its harness.
- Work on a branch from `main` and open a pull request. Never push to `main`
  directly and never force-push shared branches.

## Before opening a pull request

```bash
npm run verify
```

Never edit a profile's transcript or a codec's encoding in place; changes get a
new id (see docs/PROTOCOL.md#versioning).
