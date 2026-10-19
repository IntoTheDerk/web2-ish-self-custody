# Changelog

All notable changes to this package. Versions are Git tags; the package is not
published to npm, and consumers pin a reviewed commit SHA (see the
[README](README.md#install)). Entries are drawn from the annotated tag messages
and the commit history.

## v0.11.0-alpha.0 — 2026-10-18 (alpha pre-release)

Account wallet modes (#5), session management (#10), and account changes and
recovery keys (#11). The new features are opt-in, and outside `random-vault`
mode the new `/wallet-vault` routes refuse every request. Derivation and every
existing profile, codec, transcript and committed vector are unchanged; one
vector is added, `vectors/account-change-v1.json`. The release is breaking for
existing deployments, which must migrate first, and for code that implements,
parses exactly or matches exhaustively the server's types. Each feature's
subsection below also lists its narrower edges.

### Breaking changes

- **Apply migrations 5, 6 and 7 before this version serves traffic.** Run
  `migrate()` first. Challenges read migration 5's wallet policy, `register`
  and `login` write migration 6's `client_label`, and `pruneExpired` deletes
  from migration 7's `<p>_account_recoveries`, so each fails on a schema
  without its migration. Migration 5 records the namespace's wallet mode once,
  as `service-deterministic` when accounts already exist, and a configuration
  whose `walletMode` differs from the stored mode is refused
  (`invalid-service-profile`).
- **`GET /profile` gains `walletMode`** (#5), as does the
  `PublishedDerivationProfile` that `derivationProfile()` returns. A parser
  that accepts an exact set of keys, or an exact-equality assertion, sees the
  new key.
- **`IdentityService` gains sixteen required methods**, which breaks
  hand-written implementations and test doubles: `getWalletVault` and
  `updateWalletVault` (#5); `listSessions`, `liveSessionIds`,
  `revokeSessionById` and `revokeOtherSessions` (#10); `rotateSignInKey`,
  `changeEmail`, `enrollRecoveryKey`, `removeRecoveryKey`, `recoveryStatus`,
  `beginRecovery`, `authenticateRecovery`, `completeRecovery`,
  `listSecurityEvents` and `revokeRecoveryKeys` (#11). Services made by
  `createIdentityService` and the adapters already have them.
- **`IdentityErrorCode` gains `key-unchanged` and `stale-key`** (#11), and
  `wallet-conflict` (#5), all 409. **`DerivationErrorCode`** gains
  `invalid-email` (#11). Each breaks exhaustive switches.
  `enumerationSensitiveCodes` is unchanged.
- **Registration refuses small-order and non-canonical public keys**
  (`invalid-public-key`, #11). No key a profile derives is either.
- **Email addresses with control characters are refused** (`invalid-email`,
  #11): `normalizeEmail`, and so registration, `updateAccount`, email
  verification and `changeEmail`, refuses a C0 control, DEL or a C1 control in
  the local part. Addresses already stored are not touched.
- **`ResolvedIdentityServiceConfig` and `identityServiceDefaults`** gain
  `walletMode` (#5), `storeSessionClientHashes` (#10), and `accountSecurity`,
  `onSecurityEvent` and `auditRetentionDays` (#11). A hand-built resolved
  config needs them, and an exact-equality assertion sees them.

### New opt-in routes and configuration

Each is off, or keeps the released behavior, unless configured.

- **`walletMode`** (#5, `IdentityServiceConfig`): `service-deterministic`, the
  default and the released behavior, `per-account-deterministic` or
  `random-vault`, fixed per namespace by migration 5. In `random-vault` mode the
  service stores each account's encrypted vault. The new `/wallet-vault`
  routes serve it: `POST` returns a vault only for the account that the
  router's new `authorizeVaultRead` hook returns (401 without the hook), and
  `PUT` updates one under the session token with a revision check.
- **`accountSecurityRoutes`** (#10, `IdentityRouterOptions`, default `false`):
  mounts `GET /sessions`, `DELETE /sessions` and `DELETE /sessions/{id}`.
- **`clientLabel`** (#10, `IdentityRouterOptions`): the host's hook for a
  display-only session label, called on `POST /accounts` and `POST /sessions`.
- **`storeSessionClientHashes`** (#10, `IdentityServiceConfig`, default
  `true`): `false` stores no IP or user-agent hash on new sessions.
- **`accountSecurity`** (#11, `IdentityServiceConfig`):
  `{ signInKeyRotation, recoveryKeys }`, both default `false`, in the
  deterministic modes only. None of the account-change methods is routed.
- **`onSecurityEvent`** (#11, `IdentityServiceConfig`): a hook awaited for at
  most 3 s after an account change commits, its errors ignored.
- **`auditRetentionDays`** (#11, `IdentityServiceConfig`, default unset): when
  set, `pruneExpired` deletes this service's `account.*` and `session.*` audit
  rows older than it.
- **`createSessionResponder(service, options)`** (#11, new export from
  `web2-ish-self-custody/server`): the router's own session response, for a
  host route that issues the session of `completeRecovery`.

### Account wallet modes

- Add opt-in per-account deterministic and random-vault modes, with persistent
  random account UUIDs/salts and client helpers. Existing derivation profiles,
  codecs, vectors, and legacy service mode are unchanged.
- Limit the SDK's vault password changes to encrypted vaults. Deterministic
  accounts change keys through the opt-in sign-in-key rotation and recovery keys
  of "Account changes and recovery keys" below.
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
- The optional peer dependency kalvora.js accepts `0.0.1-alpha.1 ||
  0.0.1-alpha.2`; the development dependency, and so the suite, moves to
  `0.0.1-alpha.2`.

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

### Account changes and recovery keys

Sign-in-key rotation (a password change for a deterministic key), a signed
email change, and account recovery with a recovery key, for the caller's own
account. **Opt-in:** rotation and recovery keys are off unless
`accountSecurity` turns them on, they run only in the deterministic wallet
modes, and none of the new methods is routed by `createIdentityRouter`. Every
change is authorized by signatures over a new ten-line account-change message,
verified strictly. Derivation, every profile, codec, transcript and existing
vector are unchanged; one vector is added. The breaking changes are listed at
the end of this section.

- **Account-change message** (core entry, so a browser worker builds the bytes
  it signs): `web2-ish-self-custody account change v1`, then the service
  profile, application, network, action, normalized username, the `rotation`
  challenge's nonce and expiry, a typed authorizer and a typed subject
  (`docs/PROTOCOL.md` Part 4). Actions: `sign-in-key-rotation`,
  `email-change`, `recovery-key-enrollment`, `recovery-key-removal`,
  `recovery-begin`, `recovery-reset`; principals `key:<codec public key>`,
  `recovery-key:<64 hex>`, `email:<normalized address>`, `none`.
- **New core exports** from `web2-ish-self-custody`:
  `buildAccountChangeMessage(input)` (refuses, with `invalid-message`, a line
  break in any field, an unknown action and any principal form but the
  action's), `normalizeEmail(address)` (the service's rule, which now also
  refuses C0 and C1 control characters and DEL in the local part, so that
  every address it returns is an `email:` subject the builder accepts;
  `invalid-email`),
  `ACCOUNT_CHANGE_DOMAIN`, `accountChangeActions`, and the types
  `AccountChangeAction` and `AccountChangeMessageInput`.
  `DerivationErrorCode` gains `invalid-email`.
- **Strict Ed25519 for account changes**: S < L, canonical A and R, A not of
  small order, then noble's `zip215: false`. Under noble's default rule (and
  OpenSSL 3.5's) a small-order key with R = identity and S = 0 verifies for
  every message. Every submitted key, `newKey`, a recovery key and **the key of a
  registration**, must be canonical and not of small order
  (`invalid-public-key`, before any account lookup). Login's
  `verifyChallengeSignature` is unchanged.
- **Migration 7 `account-recovery-keys`**: `<p>_account_recovery_keys` (public
  key, `active`/`used`/`removed`, one active per account, every key unique per
  service) and `<p>_account_recoveries` (SHA-256 token digests, 15 minutes, one
  live per account). Six `CREATE … IF NOT EXISTS` statements with their
  constraints inline, safe to re-run and from concurrent runners. The live-token
  index is **unique**, not a plain index: two overlapping begins cannot see
  each other's new row to revoke it, so only the index keeps one live token per
  account (the second begin retries on a fresh
  snapshot and revokes the first token). Two plain indexes,
  `<p>_account_recovery_keys_account_idx (account_id, created_at DESC)` and
  `<p>_account_recoveries_key_idx (recovery_key_id)`, serve `recoveryStatus`,
  a retired key's tokens and the account-delete cascade, since used and
  removed keys are kept.
- **A usable recovery token** is unspent, unrevoked, unexpired and its recovery
  key `active`; every method that reads a token checks all four. Retiring a
  key (a replacing enrollment, `removeRecoveryKey`, `revokeRecoveryKeys`)
  makes its tokens unusable and stamps the ones its statement sees revoked; a
  token that a begin overlapping the retirement issued can stay unstamped
  until the next begin or `pruneExpired`, and the audit's `revokedTokens` does
  not count it. Code that reads `<p>_account_recoveries` directly must join the
  key as `active`.
- **New `IdentityService` methods**, each change one statement that re-checks
  its session or recovery token, the account's `active` status and the enrolled
  key under row locks: `rotateSignInKey`, `changeEmail`, `enrollRecoveryKey`,
  `removeRecoveryKey`, `recoveryStatus`, `beginRecovery`,
  `authenticateRecovery`, `completeRecovery`, `listSecurityEvents`, and the
  server-only `revokeRecoveryKeys(accountId)`. A rotation updates the one
  enrolled-key row in place and revokes every other session; a completed
  recovery replaces the key, spends the recovery key, revokes every session and
  issues a new one. Audit actions `account.key-rotate`, `account.email-change`,
  `account.recovery-key.enroll`, `account.recovery-key.remove`,
  `account.recovery-key.revoke`, `account.recovery-begin`, `account.recover`,
  with field names and counts only.
- **Lock order**: every account change takes the account row `FOR SHARE`
  (`FOR NO KEY UPDATE` for the email change), never `FOR UPDATE`, then the
  enrolled key, the recovery key and token, and sessions in id order, the same
  order `revokeOtherSessions` and `revokeAllSessions` use, so neither can
  deadlock the other: their audit insert's `FOR KEY SHARE` on the account
  passes. A test drives the interleaving that deadlocks under `FOR UPDATE`.
- **`createSessionResponder(service, options)`** (new export from
  `web2-ish-self-custody/server`, with type `SessionResponder`): the router's
  own session response, cookie or bearer body, for a host route that issues the
  session of `completeRecovery`. It takes the service, like
  `createIdentityRouter`, because the cookie's `Max-Age` is the service's
  `sessionTtlSeconds`.
- **Config** (new optional `IdentityServiceConfig` fields):
  `accountSecurity: { signInKeyRotation?, recoveryKeys? }` (both default
  `false`; strict booleans, unknown keys refused); `onSecurityEvent` (a hook
  awaited for at most 3 s after a change commits, its errors ignored;
  `revokeOtherSessions`, and so the opt-in `DELETE /sessions` route, also
  reports `session.revoke-others` to it when it revoked a session, and can
  answer up to 3 s later while a slow hook runs); and `auditRetentionDays` (1
  to 36,500; when set, `pruneExpired` deletes this service's `account.*` and
  `session.*` audit rows older than it; a row whose account was deleted names
  no service profile and is never pruned, so an operator deletes an account's
  audit rows before the account). `pruneExpired` also deletes recovery-token
  rows a day after they expire.
- **Rate limits** `account-change` (10 per 300 s per hashed IP and account, a
  recovery completion included), `recovery-begin` (5 per hour per hashed IP and
  username) and `recovery-begin-ip` (20 per hour per hashed IP).
- **Errors** `key-unchanged` (409) and `stale-key` (409). Recovery failures
  reuse `invalid-signature`; `enumerationSensitiveCodes` is unchanged.
- **Login** issues its session only while the key it verified is still
  enrolled, checked in the session's insert statement, so a rotation or
  recovery that commits after login read the keys leaves that login no session
  (`invalid-signature`). A login whose insert overlaps the rotation's statement
  can still keep one; the sessions list shows it.
- **Security events**: audit rows written by a session's own action or by an
  action that issued a session name it in `metadata.sessionId`
  (`account.register`, `account.login`, `session.revoke`,
  `session.revoke-others` and the new account changes), which is how
  `listSecurityEvents` shows the session's label while its row exists.
- **New type exports** from `web2-ish-self-custody/server`:
  `AccountSecurityOptions`, `AuthenticatedRecovery`, `EmailChangeInput`,
  `EnrolledKeyInput`, `IdentityRecoveryKey`, `IssuedRecovery`,
  `RecoveryBeginInput`, `RecoveryCompletionInput`,
  `RecoveryKeyEnrollmentInput`, `RecoveryKeyRemovalInput`, `RecoveryStatus`,
  `SecurityEvent`, `SecurityEventAction`, `SecurityEventHook`,
  `SecurityEventNotice`, `SessionResponder`, `SignInKeyRotationInput`.
- **Vector** `vectors/account-change-v1.json`: the message of each action,
  signatures by the committed sign-in vector's key, by a second password's
  sign-in key and by a fixture recovery key, and four signatures that must
  verify false (a small-order A with R = identity and S = 0, a non-canonical A,
  a non-canonical R, S + L). Reproduced by the new
  `scripts/verify_account_change_vector.py` (`cryptography` after explicit
  RFC 8032 checks, and its own pure-Python ZIP-215 check), which
  `verify:vectors:python` and `verify-ci.sh` run and `package.json` `files`
  ships; `verify-ci.sh` gains a gate that every `scripts/verify_*_vector.py` is
  both run and shipped.
- Tests: `test/accountChange.test.ts` (the message against the vector, every
  refusal, `normalizeEmail`, including control characters and that every
  address it returns is a subject the builder accepts), `test/server/accountChangeSignature.test.ts`
  (strict verification against the vector, the small-order forgery noble's
  default accepts), `test/server/accountChanges.test.ts` (opt-ins, the mode rule
  and key checks before any SQL, the hook's 3 s bound),
  `test/server/sessionResponder.test.ts` (byte-for-byte parity with the
  router), `test/server/config.test.ts` additions, and
  `test/server/accountChanges.integration.test.ts` (real PostgreSQL: migration 7
  re-run and from concurrent runners, and its indexes serving the key history
  and a key's tokens; rotation in place, the old key refused and
  the new one accepted at login, other sessions revoked, atomicity under a
  concurrent rotation, `stale-key`, the login race guard, refusals of unchanged
  keys, bad signatures, foreign challenges, the negative vectors' shapes and a
  small-order `newKey`; `wallet-conflict`; the email change, and a control
  character refused before the challenge is spent; enrollment,
  replacement, idempotence and removal, concurrent enrollments; begin spends
  nothing, a second begin revokes the first token, completion is single use;
  uniform 401s; concurrent begins and completions; a begin overlapping each kind
  of key retirement, whose token is refused; the status rule for every
  operation, including a suspension that commits mid-change;
  `revokeRecoveryKeys`; the security events; pruning, an audit row of a deleted
  account kept; the hook; the
  rate limits; the lock order observed through held rows, the orchestrated
  revoke-others interleaving, and a stress run with revoke-others, revoke-all,
  authenticate and login traffic). The migration pins in the other server
  suites become `[1..7]`.
- Docs: `docs/PROTOCOL.md` Part 4 and "Account wallet modes",
  `docs/SERVER_API.md` "Account changes and recovery keys (opt-in)", the two
  schema entries, configuration, errors, rate limits and the operator's insider
  alerts (now also the in-place key UPDATE and recovery keys),
  `docs/WALLET_MODES.md`, `docs/SECURITY_MODEL.md` ("Account changes"),
  `docs/INTEGRATION.md`, `SECURITY.md` and the README: deterministic password
  changes and account recovery are no longer described as platform-owned.

#### Breaking changes

- **Deploy order.** `pruneExpired` deletes from `<p>_account_recoveries`, so it
  fails on a schema without migration 7. Run `migrate()` before this version
  serves traffic.
- **Registration refuses small-order and non-canonical public keys**
  (`invalid-public-key`). No key derived by a profile is either; a key that is
  could be "signed for" without a private key.
- **Email addresses with control characters are refused** (`invalid-email`):
  `normalizeEmail`, and so registration, `updateAccount`, email verification
  and `changeEmail`, refuses an address whose local part contains a C0 control
  (U+0000 to U+001F, NUL included), DEL (U+007F) or a C1 control (U+0080 to
  U+009F, NEL included). The released rule accepted most of them. Addresses
  already stored are not touched.
- **Login** fails with `invalid-signature`, instead of issuing a session, when
  the key it verified was replaced between its read and its session insert.
- **Hand-written `IdentityService` implementations and test doubles:** the
  interface gains ten required methods (`rotateSignInKey`, `changeEmail`,
  `enrollRecoveryKey`, `removeRecoveryKey`, `recoveryStatus`,
  `beginRecovery`, `authenticateRecovery`, `completeRecovery`,
  `listSecurityEvents`, `revokeRecoveryKeys`), and `pruneExpired`'s result
  gains `recoveryTokens` and `auditEvents`.
- **`IdentityErrorCode`** gains `key-unchanged` and `stale-key`, and
  **`DerivationErrorCode`** gains `invalid-email`, which breaks exhaustive
  switches. `enumerationSensitiveCodes` is unchanged.
- **`ResolvedIdentityServiceConfig`** gains the required fields
  `accountSecurity`, `onSecurityEvent` and `auditRetentionDays`, and the
  exported `identityServiceDefaults` gains the same three keys; a hand-built
  resolved config needs them, and an exact-equality assertion sees them.
- **Audit metadata** of `account.register`, `account.login`, `session.revoke`
  and `session.revoke-others` gains `sessionId`, for a consumer that parses it
  exactly.

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
