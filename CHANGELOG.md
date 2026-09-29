# Changelog

All notable changes to this package. Versions are Git tags; the package is not
published to npm, and consumers pin a reviewed commit SHA (see the
[README](README.md#install)). Entries are drawn from the annotated tag messages
and the commit history.

## v0.10.0-alpha.1 — 2026-09-29 (alpha pre-release)

- **kalvora.js `0.0.1-alpha.1`.** The optional peer dependency moves from
  `0.0.1-alpha.0`, which is withdrawn from npm, to `0.0.1-alpha.1`, installed
  from npm (the vendored tarball is removed). kalvora.js reports key derivation
  and every derived address as byte-identical to `0.0.1-alpha.0`; the committed
  Kalvora vector and the cross-check against kalvora.js's `createWallet` still
  pass, so no wallet changes.
- Consumers migrating from v0.9.x add `kalvora.js@0.0.1-alpha.1` rather than
  `0.0.1-alpha.0`.

## v0.10.0-alpha.0 — 2026-09-29 (alpha pre-release)

**Alpha.** This release depends on kalvora.js `0.0.1-alpha.0`, and neither it
nor the Kalvora network is live. Any `0.10.0-alpha.x` release may change the
Kalvora surface; do not derive funded wallets under it.

Kalvora replaces ZERA as the bundled chain, provided by kalvora.js, with the
wallet key derived by standard SLIP-0010 at SLIP-44 coin type 5258.

### Breaking changes

- **ZERA removed; Kalvora added.** `web2-ish-self-custody/chains/zera` is gone,
  and `web2-ish-self-custody/chains/kalvora` replaces it: `kalvoraEd25519Codec`
  (`kalvora-ed25519-base58-v1`), `kalvoraEd25519ExternalSalt`
  (`web2ish-kalvora-ed25519-external-salt-v1`), `kalvoraProfiles`,
  `deriveKalvoraEd25519IdentityFromSeed`, `kalvoraSlip10Ed25519`,
  `KALVORA_SLIP44_COIN_TYPE` (5258), and `KALVORA_DERIVATION_PATH`
  (`m/44'/5258'/0'/0'/0'`). The Kalvora profile is a **new wallet family**:
  the same credentials derive a different address than under the ZERA profile,
  because its entropy domain differs and its key is the SLIP-0010 node of the
  scrypt output rather than the scrypt output itself. Its algorithm label is
  `scrypt-sha512-slip10-ed25519-external-32-v1`, so an identity-service
  database provisioned for the ZERA profile refuses the new one instead of
  mixing wallets. The ZERA ids and domain strings are retired (see
  `docs/PROTOCOL.md`).
- **kalvora.js is an optional peer dependency** (`0.0.1-alpha.0`), required
  only by `chains/kalvora`. Its `kalvora.js/wallet` entry computes the
  SLIP-0010 step and the address encoding, so a password wallet here is
  exactly kalvora.js's first Ed25519 wallet for the scrypt output; that entry
  has no network or protobuf code.

### Migrating from v0.9.x

- Replace `chains/zera` imports with `chains/kalvora` and each `zera*` export
  with its `kalvora*` counterpart, and add `kalvora.js@0.0.1-alpha.0` as a
  dependency.
- Treat the switch as new wallets, not a rename: re-enroll users, and give the
  identity service a new `serviceProfileId` (or a fresh database) for the
  Kalvora profile.
- Fixtures that copied `vectors/zera-ed25519-external-salt-v1.json` use
  `vectors/kalvora-ed25519-external-salt-v1.json`, whose `networkId` is
  `kalvora-mainnet`.

### Other changes

- **`DerivationProfile.keyDerivation`**: an optional, chain-supplied step from
  the 32-byte scrypt output to the 32-byte wallet key, typed `KeyDerivation`
  (`{ id, deriveKey }`). The core gives it a copy of the scrypt output,
  requires exactly 32 bytes back, reports a failure as `invalid-profile`
  without its message, and zeroes both buffers. Profiles without it derive
  exactly as before.
- The Python verifier is now `scripts/verify_kalvora_external_salt_vector.py`.
  It implements SLIP-0010 itself, checks that implementation against the
  specification's test vector 1, and reproduces the committed Kalvora vector
  without kalvora.js or this package.
- The suite checks the Kalvora profile against kalvora.js directly: the same
  seed gives the same key and address as kalvora.js's `createWallet`, and the
  pinned path and coin type agree with kalvora.js's constants.
- The challenge worked example in `docs/SERVER_API.md` is recomputed for
  `networkId = kalvora-mainnet`.

## v0.9.1 — 2026-09-29

Verification codes can now be delivered. Nothing changes for a router built
without the new option, and derivation and the schema are untouched.

- **`emailVerification` router option.** `POST /email-verifications` renders
  the code into an email and sends it through a configured `EmailSender`
  before answering; the code is still never in the response. A failed send
  answers the new `email-delivery-failed` (502).
- **Providers:** `createEmailSender({ provider })` with `resend`, `postmark`,
  and `sendgrid`, each also exported as its own factory. Plain `fetch`, no new
  dependency; credentials are kept off the sender object and provider response
  bodies are never surfaced.
- **Host-owned content and design:** theme the built-in template
  (`VerificationEmailTheme`: copy, colors, fonts, optional logo, footer) or
  replace it with `render`. `renderVerificationEmail`, `escapeHtml`,
  `formatVerificationCode`, `parseMailbox`, `deliverEmailVerification`, and
  `EmailDeliveryError` are exported. A rendered message that drops the code is
  refused.
- **Tighter start limits.** Verification starts are now also limited to 8 per
  recipient per hour across usernames, and to 20 per hashed IP per hour when
  the host supplies `hashRequestIp`.

## v0.9.0 — 2026-09-27

A normal password floor, and the legacy surface removed. Derivation is
unchanged: every password the new rules accept derives exactly the wallet it
derived under v0.8.0. For every configuration that did not adopt a salt, the
generated migration SQL is byte-identical to v0.8.0's, so a provisioned
database needs nothing.

### Breaking changes

- **Password floor: 10 characters, not 24 bytes.** `MINIMUM_PASSWORD_BYTES`
  (24) is replaced by `MINIMUM_PASSWORD_CHARACTERS` (10), counted as Unicode
  code points of the password bytes. `MAXIMUM_PASSWORD_BYTES` (1,024) is
  unchanged. Passwords are still not normalized, so the count is over exactly
  the bytes that are hashed; counting code points means the bytes must now be
  well-formed UTF-8. The floor applies where it did before: every derivation,
  vault creation, and vault password re-wrap, all failing with
  `invalid-password` before any KDF work. It is a length check, not a strength
  check; the docs now say the application owns the strength policy when a
  password is chosen. (`404dc51`)
- **`zeraEd25519` removed.** The self-salting built-in profile
  `web2ish-zera-ed25519-v1` is no longer exported from
  `web2-ish-self-custody/chains/zera`, and `zeraProfiles` no longer contains
  it. Its vector (`vectors/built-in-v1.json`) and Python verifier
  (`scripts/verify_zera_vector.py`) are gone. The generic
  `derived-from-username` salt policy remains in the core. (`aa0eb44`)
- **`adoptPublicSaltHex` removed.** `IdentityServiceConfig`,
  `ResolvedIdentityServiceConfig`, and `PlatformSaltConfig` no longer have it.
  A configuration that still passes it is refused with
  `invalid-service-profile` before any SQL runs rather than silently ignored,
  since ignoring it would mint a fresh salt for a caller that expected to keep
  an old one. The salt is always minted by the database on first provisioning.
  (`d1b4f48`)

### Migrating from v0.8.0

- Replace `MINIMUM_PASSWORD_BYTES` with `MINIMUM_PASSWORD_CHARACTERS`, and
  count characters as code points (`[...value].length` in JavaScript, not
  `value.length`). A password of 10–23 ASCII characters is now accepted; one of
  24 or more bytes but fewer than 10 characters (six 4-byte emoji, for
  example) is now rejected, as is any byte string that is not well-formed
  UTF-8. `TextEncoder` output is always well-formed.
- Import `zeraEd25519ExternalSalt` wherever `zeraEd25519` was imported. They
  derive **different** wallets for the same credentials, so an application
  that had users on `zeraEd25519` would need an enrollment migration; no known
  consumer did.
- Delete any `adoptPublicSaltHex` from identity-service and platform-salt
  configuration. A database that is already provisioned keeps its salt; nothing
  else changes for it.
- Fixtures that copied `vectors/zera-ed25519-external-salt-v1.json` must pick
  up its new expected values (see below).

### Other changes

- **Knight-Armor decoupled.** Tests and docs use neutral example ids
  (`example-app`, `example-app-password-wallet-v1`, `example_identity`). The
  external-salt vector's application id changed accordingly, which changes its
  public key, address, identifier, and signature; the v0.8.0 and v0.9.0 builds
  and the independent Python verifier agree on the new values, and both builds
  still reproduce the old ones from the old input. The challenge worked example
  in `docs/SERVER_API.md` is recomputed for the new ids. The README "Used by"
  table lists DemocracyOS only. (`633e08d`)
- `test/server/saltAdoption.integration.test.ts` is now
  `test/server/platformSalt.integration.test.ts`, covering minting, idempotent
  re-runs, immutability, concurrent first provisioning, and the refusal of the
  removed option against a real PostgreSQL. (`d1b4f48`)
- **CI**: `package-lock.json` is back in sync with `package.json`. It was
  missing the `pg` and `@types/pg` dev dependencies and still declared
  `engines.node >=20`, so `npm ci` had failed on every CI run since `v0.3.0`.
  The only other lock change is the dev-only transitive `nanoid` 3.3.16 →
  3.3.19 (advisory GHSA-2v37-7h3g-55p8); runtime dependencies are unchanged.
  (`5425002`)
- **CI**: the Node matrix is `[22, 24]`, matching `engines.node >=22` (it was
  `[20, 24]`). `actions/checkout`, `actions/setup-node`, and
  `actions/setup-python` are bumped to v7, which run on the Node 24 Actions
  runtime, and stay pinned by commit SHA. (`5425002`)
- **Typecheck**: `tsconfig.json` sets `"types": []`. The synced lock installs
  `@types/node` (a dependency of `@types/pg`), which would otherwise load Node
  globals into the browser-first typecheck and trip the deliberate
  `@ts-expect-error` in `test/zera-ed25519.test.ts`. Emitted `dist/` is
  byte-identical either way. (`5425002`)
- **Build**: `npm run build` now removes `dist/` first (new `clean` script,
  plain Node, no new dependency), so outputs of deleted modules can no longer
  linger locally or be packed. (`2b2be8b`)
- **Docs**: the README documents the wallet vault and recovery code (shipped in
  `v0.5.0`), the install snippet uses the `git+https://…#<sha>` form consumers
  use, a "Used by" section lists the consumers, and the API tables include the
  vault and platform-salt exports. `docs/INTEGRATION.md`'s encrypted-vault
  guidance, `SECURITY.md`, and `docs/SECURITY_MODEL.md` are aligned with the
  vault. Added this changelog. (`b6e750c`)

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
