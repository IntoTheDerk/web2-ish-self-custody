# Changelog

All notable changes to this package. Versions are Git tags; the package is not
published to npm, and consumers pin a reviewed commit SHA (see the
[README](README.md#install)). Entries are drawn from the annotated tag messages
and the commit history.

## Unreleased

- Add opt-in per-account deterministic and random-vault modes, with persistent
  random account UUIDs/salts and client helpers. Existing derivation profiles,
  codecs, vectors, and legacy service mode are unchanged.
- Limit SDK password changes to encrypted vaults. Deterministic password
  changes, wallet reassignment, and account recovery remain platform-owned.
- Store vault ciphertext at enrollment, authorize multi-device downloads through
  a host hook, and use revision checks for password-wrapper updates.
- Add PostgreSQL migration 5, integration tests, and a wallet-modes guide.
- With v0.10.1-alpha.0 merged in: `withAccountWallet` takes an optional fifth
  argument and passes `applicationSecrets` to `withDerivedWallet`, so the
  callback receives application secrets as its second parameter and
  `per-account-deterministic` mode can serve the sign-in profile.
  `random-vault` mode refuses the sign-in profile (`invalid-service-profile`
  from the service configuration, `invalid-profile` from
  `createRandomAccountWallet`): a random key runs no password derivation and
  so has no application secret to derive a wallet from.

### Session management

A sessions list and signing out of other sessions, for the caller's own
account. **Additive at runtime and opt-in:** the new routes are off unless
configured, existing routes, responses and session objects gain no field, no
`IdentityErrorCode` is added and `enumerationSensitiveCodes` is unchanged.
Derivation, every profile, codec, transcript and vector are untouched; no
vector is added. The breaking changes, a deploy order and TypeScript-only
edges, are listed at the end of this section.

- **Migration 6 `session-client-labels`**: one statement,
  `ALTER TABLE <p>_sessions ADD COLUMN IF NOT EXISTS client_label text
  CONSTRAINT <p>_sessions_client_label CHECK (client_label IS NULL OR
  client_label ~ '^[A-Za-z0-9 .()-]{1,64}$')`. One statement so that concurrent
  runners serialize on the table lock and a re-run skips the column and its
  constraint together. No index is added, so the `last_seen_at` update of every
  `authenticate` stays a HOT update. Run `migrate()` before serving this
  version: `register` and `login` write the column and fail on a schema without
  it.
- **`RequestContext.clientLabel?: string`** (new optional field): a coarse,
  display-only client label stored on the session that `register` or `login`
  issues. A value outside the CHECK is dropped, never an error.
- **`IdentityRouterOptions.clientLabel?: (request: Request) => string |
  undefined`** (new optional field): the host's label hook, called only on
  `POST /accounts` and `POST /sessions`. An invalid result or a throwing hook
  stores no label and never fails the sign-in. A non-function is refused with a
  `TypeError` when the router is created.
- **`IdentityRouterOptions.accountSecurityRoutes?: boolean`** (new optional
  field, **default `false`**): mounts the opt-in routes `GET /sessions` (list),
  `DELETE /sessions` (revoke every other session) and `DELETE /sessions/{id}`
  (revoke one other session). Off, those paths answer 405 and 404 as before. A
  non-boolean is refused with a `TypeError`.
- **`IdentityServiceConfig.storeSessionClientHashes?: boolean`** (new optional
  field, default `true`, unchanged behavior): `false` writes NULL to new
  sessions' `ip_hash` and `user_agent_hash`; rate limits still hash
  `RequestContext.ipHash`. A non-boolean is refused with
  `invalid-service-profile`. `ResolvedIdentityServiceConfig` gains the
  required field `storeSessionClientHashes: boolean`, and the exported
  `identityServiceDefaults` gains `storeSessionClientHashes: true`.
- **New `IdentityService` methods**, each one statement that authenticates the
  caller's token like `authenticate` (`session-not-found`, `session-expired`):
  - `listSessions(token, context?)`: `readonly ListedSession[]`, the account's
    live sessions, most recently active first, at most 50, display only. It
    slides the caller's `last_seen_at` and always includes the caller's row.
  - `liveSessionIds(token, context?)`: every live session id of the account,
    uncapped, for reconciliation; not routed.
  - `revokeSessionById(token, sessionId, context?)`: `{ revoked }`. Another
    account's session, an unknown id and an already revoked or expired session
    all answer `{ revoked: false }`; the caller's own id and a non-UUID are
    `invalid-request`. Audit `session.revoke` with `{ scope: "other" }`.
  - `revokeOtherSessions(token, context?)`: `{ revokedSessionIds }`, keeping the
    caller's session. Audit `session.revoke-others` with
    `{ scope: "others", revoked }`.
  The revoke statements never lock the caller's own row; `revokeSessionById`
  locks at most its target and `revokeOtherSessions` locks the account's other
  live sessions in id order, so concurrent revocations, two sessions revoking
  each other included, cannot deadlock one another.
- **Lock order of the existing multi-row session statements** (no signature
  change): `revokeAllSessions` now also locks its rows in id order before
  revoking them, so it and `revokeOtherSessions` take locks in one order, and
  `pruneExpired` deletes only dead session rows that no other statement holds
  locked (`FOR UPDATE SKIP LOCKED`), leaving a locked row for the next run
  instead of waiting on it. A plain multi-row `UPDATE` locks rows in scan
  order, which `authenticate` traffic reorders between snapshots, so two
  overlapping multi-row revocations of one account (released versions: two
  `revokeAllSessions` calls) could fail with PostgreSQL `40P01 deadlock
  detected`.
- **New type export** `ListedSession` from `web2-ish-self-custody/server`:
  `{ id, issuedAt, lastSeenAt, expiresAt, clientLabel: string | null, current }`.
- Tests: `test/server/sessions.integration.test.ts` (real PostgreSQL: migration
  6 re-run and from two concurrent runners, listing, revocation, the label and
  hashes, pruning, concurrent mutual revocation, the id-order lock of
  `revokeOtherSessions` and `revokeAllSessions` observed through a held row,
  six concurrent `revokeOtherSessions` under `authenticate` traffic with no
  error but `session-not-found`, `pruneExpired` skipping a locked row, the
  routes) and
  `test/server/router-sessions.test.ts` (no database: routing, option
  validation, the label hook). The migration pins in the other server suites
  become `[1..6]`.
- Docs: `docs/SERVER_API.md` "Session management (opt-in)", the
  `<p>_sessions` schema, configuration, "Not exposed over HTTP" and the custody
  lists; the README's server notes.

#### Breaking changes

All but the first are TypeScript-only: none changes runtime behavior for an
existing deployment that has run migration 6.

- **Deploy order.** `register` and `login` write `client_label`, so they fail
  on a schema without migration 6. Run `migrate()` before this version serves
  traffic.
- **Hand-written `IdentityService` implementations and test doubles:** the
  interface gains four required methods (`listSessions`, `liveSessionIds`,
  `revokeSessionById`, `revokeOtherSessions`). Services made by
  `createIdentityService` and the adapters already have them.
- **`ResolvedIdentityServiceConfig`** gains the required field
  `storeSessionClientHashes`, so a hand-built one (for example one passed to
  `identityMigrations` or `runIdentityMigrations` without
  `resolveIdentityServiceConfig`) needs it.
- An exact-equality assertion on `identityServiceDefaults` or on a resolved
  config sees the new key.

## v0.10.1-alpha.0 — 2026-10-18 (alpha pre-release)

Application secrets, and a sign-in profile with a Kalvora wallet from a master
seed. **Additive.** Wallet derivation and every existing profile, codec,
transcript and committed vector are unchanged, and a call that requests no
secret computes nothing new. The narrow source-compatibility edges are listed in
the compatibility note below. There are no breaking changes.

### Application secrets

- **`withDerivedWallet(credentials, useWallet, options?)`** takes an optional
  third parameter, `{ applicationSecrets?: readonly string[] }`. Each label
  yields a 32-byte secret, HKDF-SHA256 of the same scrypt output as the wallet
  under the domain `web2-ish-self-custody application secret v1`, bound to the
  profile id, context, normalized username and label (see
  `docs/PROTOCOL.md#application-secrets`). The callback receives them as a new
  second parameter, `secrets: ReadonlyMap<string, Uint8Array>`, which is empty
  when none are requested; the arrays are zeroed when the callback returns or
  throws, and the intermediate PRK before it runs. Each array is the HMAC
  output itself, so no other copy is left behind. A callback that returns the
  map, a secret's array, a view of one or its buffer fails with the existing
  `wallet-scope-closed` code instead of returning bytes that are already zero.
  `DerivedWallet` is unchanged, and a one-parameter callback still type-checks.
- **`DerivationErrorCode`** gains `invalid-secret-label` (a label outside
  `^[a-z0-9][a-z0-9._:-]{2,79}$`, a repeated label, or malformed options),
  raised before any KDF work, and `secret-unavailable`, for secrets requested
  from a profile whose wallet key is the scrypt output itself. That is a
  profile without a key-derivation step, refused before any KDF work, or one
  whose step returns the scrypt output unchanged, refused once scrypt has run.
  Secrets are independent of the wallet key only when the step is one-way,
  which the core cannot check; the `KeyDerivation` documentation now says so.
- The wallet vault is untouched: its package-internal seed path never computes
  the PRK, and the vault-opened wallets take no secrets.
- **Vector** `vectors/kalvora-ed25519-external-salt-v1.application-secret-v1.json`:
  the committed credentials with the labels `example-secret-v1` and
  `example-secret-v2`, their `info` strings, the PRK and the secrets.
  `scripts/verify_kalvora_external_salt_vector.py` loads it as a second fixture
  by its explicit path with the same strict shape checks, requires its
  credentials to equal the wallet vector's, and reproduces it with the standard
  library's `hmac` (its HKDF checked against RFC 5869 test case 1).
- Docs: `docs/PROTOCOL.md` "Application secrets" (the exact strings, why the
  scrypt output rather than the wallet key, the refusals without a one-way
  key-derivation step, and how the construction is versioned), a
  `docs/SECURITY_MODEL.md` section and failure mode, and the README.

### Sign-in profile and Kalvora wallet from a master seed

A key that signs in to an identity service without being a wallet, and the
wallet as an application secret of the same password entry. Every addition is
new API; nothing existing changes.

- **New core exports** (`web2-ish-self-custody`, which still imports no chain
  SDK):
  - `signInEd25519ExternalSalt`, the `DerivationProfile`
    `web2ish-sign-in-ed25519-external-salt-v1`: algorithm
    `scrypt-sha512-hkdf-sha256-ed25519-external-32-v1`, `external-32`, scrypt
    N=65536, r=8, p=1, dkLen=32, and its own domains
    (`web2-ish-self-custody sign-in password hash v1\n`,
    `web2-ish-self-custody sign-in Ed25519 external salt entropy v1`).
  - `signInHkdfEd25519`, its `KeyDerivation` `hkdf-sha256-sign-in-key-v1`:
    HKDF-SHA256 of the scrypt output with `SIGN_IN_KEY_DOMAIN` as salt and
    info, computed as its single block with `hmac`, its PRK zeroed. It is
    one-way, so the profile takes application secrets.
  - `signInEd25519Codec`, the `IdentityCodec`
    `web2ish-sign-in-ed25519-hex-v1`: `S_` and 64 lowercase hex digits for both
    the address and the identifier. Decoding accepts exactly
    `^S_[0-9a-f]{64}$` and throws `invalid-public-key` for anything else; no
    Kalvora parser accepts the form.
  - `SIGN_IN_KEY_DOMAIN`, `web2-ish-self-custody sign-in key v1`.
- **New `web2-ish-self-custody/chains/kalvora` exports:**
  `withKalvoraWalletFromMasterSeed(masterSeed, useWallet)` and the type
  `KalvoraMasterSeedWallet`. It opens the Kalvora wallet (SLIP-0010 at
  `m/44'/5258'/0'/0'/0'` through `kalvoraSlip10Ed25519`, Kalvora codec) of a
  32-byte master seed, such as an application secret, synchronously and on an
  internal copy. Its identity carries `derivation`, `codecId`, `curve`,
  `address`, `publicKey`, `publicKeyBytes` and `fingerprint`. It signs 1 to
  1,048,576 bytes like `withDerivedWallet`, zeroes its copy and the key,
  closes the signer after the callback (`wallet-scope-closed`), and refuses a
  thenable result (`async-wallet-scope`). It refuses with `invalid-seed`, before
  deriving, a seed that is not a plain `Uint8Array` of exactly 32 bytes (a
  Buffer or other subclass is refused, a genuine cross-realm Uint8Array is
  accepted, and the length and bytes are read from internal slots, not from
  overridable properties) and an all-zero seed, which is what an application
  secret holds after its scope has ended.
- **Identity service: no code change.** It accepts the sign-in profile as it
  accepts any serviceable profile, enrolls and verifies `S_` keys, and under
  that profile refuses a Kalvora key at registration (`invalid-public-key`).
  Doc comments now say that `<p>_account_wallets`, `IdentityWallet`, the
  `wallets` field and `listWallets` hold the enrolled key, which is a wallet
  only under a chain wallet profile; no name changes.
- **Vector** `vectors/sign-in-ed25519-external-salt-v1.json`: the Kalvora
  vector's credentials and salt under the sign-in profile, with the transcript
  intermediates, the sign-in key (PRK, seed, public key, `S_` identifier,
  fingerprint, signature), the application-secret PRK and the secrets
  `example-secret-v1` and `example-wallet-seed-v1`, and the Kalvora wallet
  opened from the latter (path, public key, `A_` identifier, address,
  fingerprint, signature). `scripts/verify_kalvora_external_salt_vector.py`
  loads it as a third fixture by its explicit path with the same strict shape
  checks, reproduces every value with its own HKDF and SLIP-0010, and checks
  that the sign-in key, that wallet and the Kalvora password wallet differ.
  No existing vector changes.
- Docs: `docs/PROTOCOL.md` "Part 3 — the sign-in profile" and "Kalvora wallet
  from a master seed"; `docs/INTEGRATION.md` "A sign-in key separate from the
  wallet"; the `docs/SERVER_API.md` custody model and
  `docs/SECURITY_MODEL.md` "Sign-in profile" for both patterns, keeping the
  offline-guessing caveat; the README and `SECURITY.md`, which now say per
  profile what a stolen database gives an attacker.

**Compatibility note.** These edges all come from application secrets; the
sign-in additions are new exports only. An exhaustive `switch` over
`DerivationErrorCode` with a `never` check needs the two new cases. A
hand-written double typed as `typeof withDerivedWallet` that calls the callback
with one argument must pass the map as well; doubles that declare their own
one-parameter callback type are unaffected. The callback now always receives a
second argument, an empty map when no secrets are requested. A callback that
declares its own optional second parameter no longer type-checks (TS2345), and
in plain JavaScript that parameter now receives the map.

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
