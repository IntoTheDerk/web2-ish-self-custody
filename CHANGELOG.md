# Changelog

All notable changes to this package. Versions are Git tags; the package is not
published to npm, and consumers pin a reviewed commit SHA (see the
[README](README.md#install)). Entries are drawn from the annotated tag messages
and the commit history.

## Unreleased

Tooling and documentation only. No change to any runtime source file, public
API, profile, codec, vector, or wire format; `v0.8.0` (`051b4bc`) remains the
commit consumers pin.

- **CI**: `package-lock.json` is back in sync with `package.json`. It was
  missing the `pg` and `@types/pg` dev dependencies and still declared
  `engines.node >=20`, so `npm ci` had failed on every CI run since `v0.3.0`.
  The only other lock change is the dev-only transitive `nanoid` 3.3.16 →
  3.3.19 (advisory GHSA-2v37-7h3g-55p8); runtime dependencies are unchanged.
- **CI**: the Node matrix is `[22, 24]`, matching `engines.node >=22` (it was
  `[20, 24]`). `actions/checkout`, `actions/setup-node`, and
  `actions/setup-python` are bumped to v7, which run on the Node 24 Actions
  runtime, and stay pinned by commit SHA.
- **Typecheck**: `tsconfig.json` sets `"types": []`. The synced lock installs
  `@types/node` (a dependency of `@types/pg`), which would otherwise load Node
  globals into the browser-first typecheck and trip the deliberate
  `@ts-expect-error` in `test/zera-ed25519.test.ts`. Emitted `dist/` is
  byte-identical either way.
- **Build**: `npm run build` now removes `dist/` first (new `clean` script,
  plain Node, no new dependency), so outputs of deleted modules such as
  `dist/profiles.*` and `dist/zera-ed25519.*` can no longer linger locally or
  be packed.
- **Docs**: the README documents the wallet vault and recovery code (shipped in
  `v0.5.0`) and no longer claims the package cannot encrypt or recover a
  wallet. The install snippet uses the `git+https://…#<sha>` form consumers
  use, a "Used by" section lists the consumers, and the API tables include the
  vault and platform-salt exports. `docs/INTEGRATION.md`'s encrypted-vault
  guidance, `SECURITY.md`, and `docs/SECURITY_MODEL.md` are aligned with the
  vault.
- Added this changelog.

## v0.8.0 — 2026-08-20

Hashed-IP credential rate limits.

- The identity service's challenge, registration, and login rate-limit buckets
  now combine the rule, the normalized username, and the caller's hashed IP, so
  requests from one source cannot exhaust another source's per-username budget.
  A request without an IP hash falls into a shared conservative bucket rather
  than a global username-only one. (`8e5f0ae`)
- `package-lock.json` is re-versioned to track `package.json`. (`051b4bc`)

## v0.7.0 — 2026-08-08

Optional friendly name.

- `display_name` is nullable. Registration leaves it unset unless one is
  supplied, and `updateAccount` accepts `null` to clear it (`undefined` still
  leaves it unchanged). Migration 4 is a single, concurrency-safe
  `ALTER COLUMN … DROP NOT NULL`. (`afa411d`)

## v0.6.0 — 2026-08-08

The platform salt as a first-class SDK export.

- `web2-ish-self-custody/server` exports `platformSaltMigration`,
  `provisionPlatformSalt`, and `readPlatformSalt`, so a host with its own
  accounts and sessions can own the durable 32-byte public salt without
  adopting the full identity service. The emitted SQL is byte-identical to
  version 1 of the identity schema, so the two are interchangeable. `readPlatformSalt`
  refuses a stored salt whose profile, application, or network disagrees with
  the running configuration. (`d919428`)

## v0.5.0 — 2026-08-08

Wallet vault with a recovery kit.

- New wallet vault: a random data key encrypts the seed, and that key is wrapped
  independently under the password (scrypt at the profile's cost) and under a
  generated 256-bit recovery code. Changing the password re-wraps the data key
  and keeps the seed and address. The identity is authenticated as associated
  data, and opening re-derives and checks the address. Exports:
  `createWalletVault`, `createWalletVaultFromCredentials`,
  `openWalletVaultWithPassword`, `openWalletVaultWithRecoveryCode`,
  `rewrapWalletVaultPassword`, `parseWalletVault`, `generateRecoveryCode`,
  `normalizeRecoveryCode`, and `WALLET_VAULT_FORMAT`. (`d14d80e`)
- `npm run verify:ci` (`scripts/verify-ci.sh`) runs the CI gates locally with
  per-gate PASS/FAIL/SKIP. (`422f850`)

## v0.4.0 — 2026-08-07

Chain-agnostic core with pluggable identity codecs.

- The core no longer knows about any chain. An `IdentityCodec` supplies address
  and public-key encoding, and a `DerivationProfile` object carries the KDF
  parameters, salt policy, domain strings, and codec. ZERA moves to
  `web2-ish-self-custody/chains/zera`, which owns the only `bs58` import.
  Derived wallets and committed vectors are unchanged.
- Fixes concurrent migration runners racing on system catalogs: statements are
  retried on concurrency error codes, and triggers are created inside an
  exception handler.
- Wallets record the codec that produced their address.
- **Breaking:** `credentials.profile` is a `DerivationProfile` object rather than
  a profile-id string; `IdentityServiceConfig.profileId` becomes `profile`; the
  `./zera-ed25519` subpath is now `./chains/zera`; `getProfile`,
  `builtInProfiles`, `ServerProfileId`, and `serverProfileIds` are removed.
  (`0e320e1`)

## v0.3.0 — 2026-08-07

Ed25519-only derivation plus the portable server identity module. First tagged
release; it includes the history before it.

- Initial deterministic self-custody SDK with committed vectors and independent
  Python verifiers. (`b91afaf`, `b0fc8af`)
- Externally salted ZERA wallet profile (`web2ish-zera-ed25519-external-salt-v1`).
  (`cc12677`)
- Direct-seed ZERA identity helper, with hardened input validation. (`8805f89`,
  `ef146ff`)
- `web2-ish-self-custody/server`: a framework-agnostic identity service for
  external-salt profiles. It owns one immutable public salt per service,
  verifies Ed25519 signatures over single-use challenges, and issues opaque
  sessions. It never receives a password, seed, or ciphertext, and runs on
  Neon's HTTP driver or a pooled `pg` connection. `adoptPublicSaltHex` lets an
  existing deployment adopt its live salt. (`60d3650`)
- secp256k1 support is removed entirely; the package is Ed25519 only.
  (`60d3650`)
