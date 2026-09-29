# Contributing to web2-ish-self-custody

## Setup

Requires Node.js 22 or 24 and Python 3.12 with `cryptography==46.0.3` (for the
independent vector verifier).

```bash
npm ci
npm run verify      # typecheck, tests, Python vector verifier, build
npm run verify:ci   # every CI gate that can run locally
```

## Workflow

1. **Branch from `main`.** Collaborators with write access push branches to
   this repository; everyone else forks it first. Use names like
   `fix/session-expiry` or `feat/recovery-kit-v2`. Nobody pushes to `main`
   directly.
2. **Open a pull request** against `main`, titled in
   [Conventional Commits](https://www.conventionalcommits.org/) style
   (`fix(server): ...`, `feat!: ...`). Explain what changed and why, and call
   out any change to a profile, codec, transcript or public export.
3. **CI must pass** (`verify` on Node 22 and 24, plus the attribution check).
   Resolve review conversations before merging.
4. **Squash and merge.** The PR title and description become the single commit
   on `main`, and the branch is deleted. Individual branch commits don't need to
   be tidy. Never force-push `main`.

A change to a profile's transcript or a codec's encoding is always a new id,
never an edit in place; see [Versioning](docs/PROTOCOL.md#versioning).

Don't add AI attribution: no `Co-Authored-By:` trailers naming an AI tool and no
"Generated with ..." lines in commits or PR descriptions. CI rejects PRs that
contain them.

## Releases

Maintainers release from `main`: bump the version and [CHANGELOG](CHANGELOG.md)
in a PR, merge it, tag the merge commit `vX.Y.Z`, and create the GitHub
release. The package is not published to npm; consumers pin the release commit
by its full SHA.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
