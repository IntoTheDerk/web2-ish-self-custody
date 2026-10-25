# Server API

Operator and integrator reference for `web2-ish-self-custody/server`.

This module is the server half of any service-salted derivation profile. It owns
one immutable 32-byte public salt per service, publishes the pinned KDF
parameters, verifies signatures over single-use challenges, and issues opaque
sessions. It is the only stateful part of this package.

That is the legacy default. New deployments can select
`walletMode: "per-account-deterministic"` or `"random-vault"`. See
[Account wallet modes](WALLET_MODES.md) for configuration, new client helpers,
authorized vault download/update routes, and vault password changes and recovery.
In the deterministic modes the service offers opt-in sign-in-key rotation and
recovery keys ([account changes](#account-changes-and-recovery-keys-opt-in)),
and account recovery by email and the signed-in reset
([account resets](#account-resets-opt-in)), each off unless configured.
`/profile` reports `walletMode`; in either new mode use `/challenges`'s
`walletSetup`, not the service salt, to create the wallet.
An optional [second sign-in factor](#second-sign-in-factor-opt-in) that the
host verifies gates every session a password proof would issue, and
[`deleteAccount`](#account-deletion) permanently deletes one account.

It is chain-agnostic. The deployment hands it a `DerivationProfile` object, and
every address and public-key operation runs through that profile's
`IdentityCodec` — there is no encoding convention hardcoded anywhere in this
module. The examples below use Kalvora because that is the chain that ships in the
box, not because the service knows what Kalvora is.

The profile is the profile of the key that signs in. Under a chain wallet
profile, such as the Kalvora profile, the enrolled key is the user's wallet.
Under the chain-neutral sign-in profile (`signInEd25519ExternalSalt`) it is a
sign-in key that is not a key on any chain, and the user's wallet, if the
application has one, never reaches the service. The tables, the wire field
`wallets` and the `IdentityWallet` type keep their names either way: they hold
the enrolled key, which is a wallet only when the profile is a chain wallet
profile.

`src/server/contract.ts` is the authoritative TypeScript surface and
`src/server/router.ts` the authoritative wire behavior. This document describes
both.

## Custody model

What the server holds depends on the configured profile: the lists below hold
for both, and the enrolled key is a wallet only under a chain wallet profile.

### What the server holds

- the per-service 32-byte public salt and the pinned scrypt parameters
- normalized usernames, display names, optional emails and verification state
- the enrolled key's public material: address, encoded public key, codec id,
  fingerprint. Under a chain wallet profile that is the user's wallet; under
  the sign-in profile it is the sign-in key, and the server holds no chain key
- single-use challenge nonces with their expiry and consumption state
- SHA-256 hashes of session tokens and of email verification codes
- per session, a SHA-256 hash of the user agent and a caller-computed IP hash,
  unless `storeSessionClientHashes` is `false`
- per session, an optional coarse client label such as `Firefox on macOS`
  (migration 6), supplied by the host, never the raw User-Agent
- rate-limit counters keyed by a SHA-256 bucket over the rule and its subject,
  which for most rules includes the caller-computed IP hash (alone, or with the
  normalized username or account id), whatever `storeSessionClientHashes` says;
  `pruneExpired` removes a counter 24 hours after its last update
- append-only audit rows
- immutable account UUID/salt setup and wallet policy (migration 5)
- encrypted vaults and revisions, only when `walletMode` is `random-vault`
- with recovery keys enabled, each account's recovery public keys (raw Ed25519,
  with status and times) and SHA-256 digests of recovery tokens (migration 7)
- each account's two reset settings and, with account resets enabled, its reset
  rows: their kind, times, attempt count, the initiating session's id and the
  SHA-256 digest of an emailed reset code (migration 8)

### What the server never holds

- a password or recovery code, or any hash or transform of a password. The
  enrolled public key itself is the one password verifier it holds in the
  deterministic modes; in `random-vault` mode each stored vault is another
  (see below)
- a plaintext seed, private key, or secret scalar, or an application secret
- in the deterministic modes, any ciphertext, encrypted vault, or key-escrow
  blob. `random-vault` mode accepts encrypted wallet material, never a
  plaintext key: each account's vault, which the server cannot open and which
  must be access-controlled
- under the sign-in profile, anything about the user's wallet: no wallet
  address, public key or signature reaches it, unless the application sends one.
  The sign-in profile is served only in the deterministic modes;
  `resolveIdentityServiceConfig` refuses it with `random-vault`

There is no password column, and no recovery secret: the recovery tables hold
public keys and token digests only, and the reset table code digests only. In the deterministic
modes no input to any method in `IdentityService` carries secret wallet
material, so there is no code path in which the service could store it even by
mistake. In `random-vault` mode registration and `updateWalletVault` accept a
vault, checked against the enrolled identity and the profile's KDF, but never
the seed, password or recovery code that opens it.

### Why a stolen database yields no wallet

In the deterministic modes every enrolled key comes from
`scrypt(entropy, publicSalt, N, r, p, dkLen)`, where `publicSalt` is the
service's salt or, in `per-account-deterministic` mode, the account's, and
`entropy` is a domain-separated SHA-512 transcript over the normalized
username and the user's password bytes, followed by the profile's key step. The
database holds the salt, the parameters and the enrolled public key. It does not
hold the password, and the password is the only high-entropy input.

- **Under a chain wallet profile** the enrolled key is the wallet. An attacker
  with a full dump has exactly what any holder of the public address already
  has: the ability to run an offline guessing attack against a known public key.
- **Under the sign-in profile** the enrolled key is a sign-in key, and the
  database holds nothing about the wallet. The wallet's master seed is an
  application secret of the same scrypt output under a different HKDF domain
  ([protocol](PROTOCOL.md#part-3--the-sign-in-profile)), so neither the sign-in public
  key nor any number of its signatures yields it. The offline attack remains:
  the sign-in public key is a password oracle at scrypt cost, and a correct
  guess gives the password, from which the public transcript and salt give the
  wallet. So does a published wallet address, to anyone who also knows the
  username, with no database at all.
- **In `random-vault` mode**, which serves chain wallet profiles only, the
  enrolled key is a random seed rather than a function of the password, so a
  published address is no password oracle. The database does hold each
  account's vault: that seed under a random data key, wrapped once by a key
  stretched from the password at the profile's scrypt cost and once by a key
  derived from the 256-bit recovery code. The vault is an offline password
  oracle at that cost, and a correct guess opens it and gives the wallet. It is
  not published, so stealing the database adds it.

In the deterministic modes, under a chain wallet profile, stealing the
database does not improve the guessing attack: the salt is not a secret and was
already published to every client that ever derived, and the public key is the
address the user shares. Under the sign-in profile it does give the attacker one
thing that may not be public otherwise: an oracle for every account, including
accounts whose wallet address was never published. In `random-vault` mode it
gives the attacker each account's vault, the oracle that mode otherwise keeps
unpublished. The work per guess is the same.

The corollary is the uncomfortable one and must not be softened: a weak password
is recoverable by anyone who learns a public address or an enrolled public key
in the deterministic modes, or who obtains a stored vault in `random-vault`
mode, and this module cannot detect or prevent that. Deterministic password-derived
custody is not equivalent to a random wallet seed. See
[the security model](SECURITY_MODEL.md).

### Serviceable profiles

Serviceability is a **policy**, not a list of blessed ids. A profile is
serviceable when the following hold, and `resolveIdentityServiceConfig` checks
them at construction:

1. **`saltPolicy` is `external-32`.** A service exists to own and publish a
   salt. A profile that derives its own salt from the username has nothing for a
   server to hold, and configuring one here would publish a salt clients must
   ignore. Anything else throws `invalid-service-profile` with a message naming
   the offending policy.
2. **Its codec round-trips.** `assertCodecRoundTrip(profile.codec, …)` runs once
   at startup against a fixed 32-byte key. A codec whose `decodePublicKey` does
   not invert its `encodePublicKey` would let the service enroll wallets it can
   never authenticate again, so this fails the deployment rather than the
   thousandth login.
3. **In `random-vault` mode, it is not the sign-in profile.** A configuration
   whose codec is the sign-in codec (`web2ish-sign-in-ed25519-hex-v1`) throws
   `invalid-service-profile` there. A random-vault key comes from no password
   derivation, so there would be no application secret, and the application
   could derive no wallet beside the sign-in key. The deterministic modes serve
   the sign-in profile.

Nothing else is required. Any chain that satisfies those conditions can be
served by this module without a change to it.

The profile the deployment supplies is the single source of the curve, the
algorithm label, the KDF parameters, and the codec. Migration 1 bakes
`profile.id`, `profile.algorithm`, `profile.curve`, and every KDF value into the
CHECK constraint on `<p>_service_profiles`; migration 2 bakes `profile.id` and
`profile.codec.id` into the binding CHECK on `<p>_account_wallets`. A deployment
whose configuration has drifted from its database cannot write a row at all.

The bundled profiles, which satisfy the policy:

| `profileId` | codec | curve | algorithm | scrypt | enrolled key |
| --- | --- | --- | --- | --- | --- |
| `web2ish-kalvora-ed25519-external-salt-v1` | `kalvora-ed25519-base58-v1` | ed25519 | `scrypt-sha512-slip10-ed25519-external-32-v1` | N=65536, r=8, p=1, dkLen=32 | the Kalvora wallet (`A_…`) |
| `web2ish-sign-in-ed25519-external-salt-v1` | `web2ish-sign-in-ed25519-hex-v1` | ed25519 | `scrypt-sha512-hkdf-sha256-ed25519-external-32-v1` | N=65536, r=8, p=1, dkLen=32 | a sign-in key (`S_…`), not a wallet |
| `web2ish-sign-in-ed25519-external-salt-v2` | `web2ish-sign-in-ed25519-hex-v1` | ed25519 | `scrypt-sha512-hkdf-sha256-ed25519-external-32-v2` | N=262144, r=8, p=1, dkLen=32 | a sign-in key (`S_…`), not a wallet, at four times v1's scrypt cost |

A service configured with the sign-in profile refuses a Kalvora key at
registration (`invalid-public-key`): the codec decodes only `S_` identifiers.

A profile that derives its own salt from the username (the generic
`derived-from-username` policy) is not serviceable.

## Registration sequence

The client derives. The server verifies. No step reverses that.

1. **Client** `GET /profile`.
2. **Client** asserts the response matches the profile object it imported:
   exact `profileId`, exact `codecId`, exact `algorithm`, exact `applicationId`
   and `networkId`, exact KDF parameters, and a 64-character `publicSaltHex`.
   Take the salt and nothing else. A client that accepts server-supplied KDF
   parameters has handed the server a downgrade lever, and one that accepts a
   server-supplied `codecId` has let it choose what an address means.
3. **Client** (only when the deployment sets `requireVerifiedEmail`) completes
   `POST /email-verifications` and `POST /email-verifications/confirm` first.
4. **Client** `POST /challenges` with `purpose: "registration"`.
5. **Server** mints a 32-byte nonce, stores it, and returns the exact message to
   sign. It does this for unknown usernames too — see
   [anti-enumeration](#anti-enumeration).
6. **Client** validates the returned `message` field by field against its own
   pinned values rather than signing it blind: domain prefix, service profile,
   application, network, purpose, its own normalized username, and a future
   `expiresAt`.
7. **Client** derives the wallet inside a dedicated worker from the username,
   the password bytes, and the published salt. The password and the seed never
   leave the worker.
8. **Client** signs the raw UTF-8 bytes of the challenge message with Ed25519,
   producing a 64-byte signature, lowercase hex on the wire.
9. **Client** `POST /accounts` with the username, address, public key,
   `challengeId`, and signature. It then zeroes its password buffer and drops
   the wallet scope.
10. **Server** recomputes the address from the submitted public key and rejects
    any mismatch, so a caller cannot enroll a key under an address it does not
    control.
11. **Server** verifies the signature against that public key and, in one
    statement, consumes the challenge, inserts the account, inserts the primary
    wallet, and issues a session. A consumed challenge cannot be reused.
12. **Server** returns `201` with the account, the wallet, and the session. The
    session token is set as an `HttpOnly` cookie, or returned in the body when
    the router runs in bearer-only mode — never both. Only its SHA-256 hash is
    stored.

## Login sequence

1. **Client** `GET /profile` and pin-check as in registration. The salt must be
   byte-identical to the one used at registration; a different salt derives a
   different wallet, which the server sees as an unenrolled key.
2. **Client** `POST /challenges` with `purpose: "login"`.
3. **Client** validates the message field by field, as in registration.
4. **Client** derives the wallet in a worker and signs the message.
5. **Client** `POST /sessions` with the username, `challengeId`, and signature.
6. **Server** verifies the signature against the enrolled public key, consumes
   the challenge, and issues a session — again as one statement.
7. **Server** returns `200` with the account and session, plus the cookie or the
   bearer token.
8. **Client** authenticates subsequent requests with that cookie or with
   `Authorization: Bearer <token>`.

Nothing in this sequence transmits a password or a seed. The server's entire
cryptographic role is step 6.

## HTTP wire format

`createIdentityRouter(service, options)` returns a plain Fetch handler,
`(request: Request) => Promise<Response>`. It is expressed only in Web Fetch
primitives — no framework, no Node globals — which is what lets the identical
handler serve a Vercel Function and a `node:http` server.

Routes hang off `basePath`, default `/identity`. Paths below are relative to it.

### Request rules

- `Content-Type: application/json` is required on every request with a body;
  anything else is `415 unsupported-media-type`.
- Bodies are capped at 64 KiB. Oversize is `413 payload-too-large`, detected
  while streaming rather than after buffering.
- The body must be a JSON **object**. Arrays, scalars, and empty bodies are
  `invalid-request`.
- **Unknown fields are rejected**, not ignored, so a mistyped field name never
  silently drops a value.
- A path with no route is `404 not-found`; a known path with an unrouted method
  is `405 method-not-allowed` with an `Allow` header. There is no `OPTIONS`
  handler and no CORS preflight — see [CSRF and CORS](#csrf-and-cors).

Every response carries `Content-Type: application/json; charset=utf-8`,
`Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.

### Authentication

Two modes, chosen by the `useCookies` option (default `true`):

| | cookie mode | bearer mode |
| --- | --- | --- |
| token delivery | `Set-Cookie` on register and login | `token` field in the response body |
| token in body | withheld | present |
| client sends | the cookie automatically | `Authorization: Bearer <token>` |
| cookie attributes | `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=<sessionTtlSeconds>` | — |

The default cookie name is `__Host-w2sc_session`. The router refuses to
construct if a `__Host-`-prefixed name is combined with `cookieDomain`, because
browsers only honor the prefix's guarantees when no `Domain` attribute is
present, and silently dropping those guarantees would be worse than failing to
boot.

In cookie mode the token is deliberately absent from the response body: the
cookie is `HttpOnly` precisely so page scripts cannot read it, and echoing it
would hand it straight back.

An `Authorization` header always wins over the cookie when both are present.

### `GET /profile`

Public. No request body.

```json
{
  "serviceProfileId": "example-app-password-wallet-v1",
  "profileId": "web2ish-kalvora-ed25519-external-salt-v1",
  "codecId": "kalvora-ed25519-base58-v1",
  "algorithm": "scrypt-sha512-slip10-ed25519-external-32-v1",
  "curve": "ed25519",
  "applicationId": "example-app",
  "networkId": "kalvora-mainnet",
  "publicSaltHex": "3f8a…64 hex characters…c1",
  "kdf": { "N": 65536, "r": 8, "p": 1, "dkLen": 32 }
}
```

`codecId` names the address encoding this deployment uses, so a client can
confirm it will encode addresses the way the server does before it enrolls one.
Every other field is read from the immutable `<p>_service_profiles` row;
`codecId` comes from the configured profile object, and the service cross-checks
the stored `profileId`, `applicationId`, and `networkId` against its
configuration on every fresh read, raising `invalid-service-profile` on drift.

Errors: `service-profile-missing` (503) when the profile row is absent, which
means migrations have not run or the row was deleted.

### `POST /challenges`

Public.

```json
{ "username": "ada@example.org", "purpose": "login" }
```

`purpose` is one of `registration`, `login`, `rotation`.

```json
{
  "id": "3a1f7c2e-9b64-4f0d-8c5a-1e2d3f4a5b6c",
  "purpose": "login",
  "usernameNormalized": "ada@example.org",
  "message": "web2-ish-self-custody auth challenge v1\nexample-app-password-wallet-v1\n…",
  "expiresAt": "2026-08-07T18:24:05.000Z"
}
```

Errors: `invalid-username` (400), `invalid-purpose` (400), `rate-limited` (429).
Never `account-not-found` — the route answers identically for unknown usernames.

### `POST /accounts`

Public. Registration. Returns `201`.

```json
{
  "username": "ada@example.org",
  "displayName": "Ada",
  "email": "ada@example.org",
  "address": "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB",
  "publicKey": "A_GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB",
  "challengeId": "3a1f7c2e-9b64-4f0d-8c5a-1e2d3f4a5b6c",
  "signature": "16e3…128 hex characters…07"
}
```

`displayName` and `email` are optional. `email` is required, and must already be
confirmed, when the deployment sets `requireVerifiedEmail`.

```json
{
  "account": {
    "id": "8d2c…",
    "serviceProfileId": "example-app-password-wallet-v1",
    "usernameNormalized": "ada@example.org",
    "displayName": "Ada",
    "email": "ada@example.org",
    "emailVerifiedAt": "2026-08-07T18:20:00.000Z",
    "status": "active",
    "createdAt": "2026-08-07T18:24:07.000Z",
    "updatedAt": "2026-08-07T18:24:07.000Z"
  },
  "wallet": {
    "id": "6b0e…",
    "accountId": "8d2c…",
    "serviceProfileId": "example-app-password-wallet-v1",
    "profileId": "web2ish-kalvora-ed25519-external-salt-v1",
    "codecId": "kalvora-ed25519-base58-v1",
    "curve": "ed25519",
    "applicationId": "example-app",
    "networkId": "kalvora-mainnet",
    "address": "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB",
    "addressNormalized": "gmadrppbc7p5arkv8g3djiwp89vz1jlk23v2gbjuaegb",
    "publicKey": "A_GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB",
    "fingerprint": "GMAD RPPB C7P5 ARKV",
    "isPrimary": true,
    "createdAt": "2026-08-07T18:24:07.000Z"
  },
  "session": {
    "id": "b41a…",
    "accountId": "8d2c…",
    "issuedAt": "2026-08-07T18:24:07.000Z",
    "expiresAt": "2026-08-21T18:24:07.000Z",
    "lastSeenAt": "2026-08-07T18:24:07.000Z"
  }
}
```

In bearer mode the body additionally carries `"token": "<43-character
base64url>"`. It appears there once and never again.

Errors: `invalid-request`, `invalid-username`, `invalid-display-name`,
`invalid-email`, `invalid-public-key`, `invalid-address` (400);
`challenge-not-found` (404); `challenge-expired` (410); `challenge-consumed`,
`account-exists`, `wallet-registered` (409); `rate-limited` (429); and the
collapsed authentication failure below.

### `POST /sessions`

Public. Login. Returns `200`.

```json
{
  "username": "ada@example.org",
  "challengeId": "3a1f7c2e-9b64-4f0d-8c5a-1e2d3f4a5b6c",
  "signature": "16e3…128 hex characters…07"
}
```

Returns `{ "account": …, "session": … }`, plus `token` in bearer mode.

With the [second sign-in factor](#second-sign-in-factor-opt-in) and an account
that needs it, it returns `200` with `{ "secondFactor": "totp", "ticket": "…",
"expiresAt": "…" }` instead: no session, no cookie and no account. The client
sends the ticket with the code to `POST /sessions/second-factor`.

Errors: `challenge-not-found` (404), `challenge-expired` (410),
`challenge-consumed` (409), `rate-limited` (429, also rule `login-account`
with the factor), and the collapsed authentication failure described in
[anti-enumeration](#anti-enumeration).

### `POST /sessions/second-factor`

Public, and mounted only on a service configured with `secondFactor`
(otherwise `404`). The second sign-in step.

```json
{ "ticket": "kQ3…43 base64url characters…x0", "code": "123456" }
```

Returns `200` with `{ "account": …, "session": … }` (and `token` in bearer
mode) and the session cookie, as `POST /sessions` does. The session's client
label and hashes are the ones the login request supplied.

Errors: `second-factor-invalid` (401, a wrong code; the ticket has attempts
left), `second-factor-locked` (423, the host's verifier refused),
`second-factor-ticket-invalid` (401, sign in again), `invalid-request` (400, a
missing or overlong code).

### `GET /sessions/current`

Authenticated. Resolves the token and slides `last_seen_at`.

```json
{ "account": { … }, "wallets": [ { … } ], "session": { … } }
```

Errors: `session-not-found` (401), `session-expired` (401).

### `DELETE /sessions/current`

Authenticated. Revokes the presented session and, in cookie mode, clears the
cookie.

```json
{ "revoked": true }
```

Revocation is **idempotent**: an already-revoked, expired, or unknown token
still returns `200` and still clears the cookie. Failing here would strand a
browser holding a dead cookie it cannot clear, and the desired end state has
already been reached.

### Session management (opt-in)

The caller's account-wide session control: a sessions list, signing out one
other session, and signing out every other session. The three routes below are
mounted only when the router option `accountSecurityRoutes` is `true`. **The
default is `false`**, and then `GET /sessions` and `DELETE /sessions` answer
`405` (`Allow: POST`) and `DELETE /sessions/{id}` answers `404 not-found`, as
for any unrouted path. `POST /sessions` (login) and `GET|DELETE
/sessions/current` are the same either way. A host that runs its own statements
around a revocation (for example deleting state it keeps per session) leaves the
option off and calls the service methods from its own routes.

```ts
const handler = createIdentityRouter(service, {
  basePath: "/api/identity",
  trustedOrigins: ["https://app.example.com"],
  accountSecurityRoutes: true,
  // Coarse and allowlisted; never the raw header.
  clientLabel: (request) => labelFromUserAgent(request.headers.get("user-agent")),
});
```

All three are authenticated with the caller's session token, by cookie or
bearer, with the answers of `GET /sessions/current`: a missing, unknown or
revoked token is `401 session-not-found`, an expired one `401 session-expired`.
Only the list slides the caller's `lastSeenAt`.
`DELETE` requests are unsafe methods, so in cookie mode they pass the
`trustedOrigins` gate first (see [CSRF and CORS](#csrf-and-cors)). They take no
body. No response of an existing route gains a field.

**The client label.** The router option `clientLabel?: (request) => string |
undefined` returns a display label for the client. The router calls it only on
the two routes that issue a session, `POST /accounts` and `POST /sessions`, and
passes the result to the service as `RequestContext.clientLabel`. The service
stores it on the new session row when it matches the column's CHECK,
`^[A-Za-z0-9 .()-]{1,64}$`. Any other value, and a hook that throws, are
dropped: the session is issued without a label, never refused. A host that
issues sessions through the service directly passes `clientLabel` in the
`RequestContext` of `register` or `login`, with the same rule. Build the label
from an allowlist of browser and operating-system families, such as
`"<Browser> on <OS>"`; keep no version, model or other token, and never pass the
raw User-Agent. The label is deleted with its session row (see
[`<p>_sessions`](#p_sessions)).

#### `GET /sessions`

Calls `listSessions(token)`. Returns the account's live sessions (not revoked,
not expired), most recently active first, **at most 50**, for display:

```json
{
  "sessions": [
    {
      "id": "b41a…",
      "issuedAt": "2026-10-09T09:12:40.000Z",
      "lastSeenAt": "2026-10-18T18:24:07.000Z",
      "expiresAt": "2026-10-23T09:12:40.000Z",
      "clientLabel": "Firefox on macOS",
      "current": true
    },
    {
      "id": "7c09…",
      "issuedAt": "2026-10-11T20:01:13.000Z",
      "lastSeenAt": "2026-10-12T07:45:51.000Z",
      "expiresAt": "2026-10-25T20:01:13.000Z",
      "clientLabel": null,
      "current": false
    }
  ]
}
```

`current` is `true` on exactly one row, the session whose token made the call.
The call slides that session's `lastSeenAt` as `GET /sessions/current` does, and
the caller's row is always on the page whatever the other rows' activity. A row
carries only these six fields: no hash, address, token or IP. `clientLabel` is
`null` for a session issued without one, including every session made before
migration 6. The list is display-only; use `liveSessionIds` (below) to decide
which sessions exist.

#### `DELETE /sessions/{id}`

Calls `revokeSessionById(token, id)`. Signs out one other live session of the
caller's account.

```json
{ "revoked": true }
```

`revoked` is `false`, with the same `200`, when the id names a session of
another account, no session at all, or a session already revoked or expired:
the answer does not reveal which. The caller's own session id is `400
invalid-request`, because signing out is `DELETE /sessions/current`; so is an id
that is not a UUID. A revocation writes the audit row `session.revoke` with
metadata `{ "scope": "other" }`; an answer of `false` writes none. The revoked
session's next request answers `401 session-not-found`.

#### `DELETE /sessions`

Calls `revokeOtherSessions(token)`. Signs out every live session of the
caller's account except the caller's own.

```json
{ "revokedSessionIds": ["7c09…", "e5d2…"] }
```

The list is empty when there was nothing to revoke. Each call writes one audit
row `session.revoke-others` with metadata `{ "scope": "others", "revoked": n }`.

**Concurrency.** Each revocation is one statement that reads the caller's
session and never locks it. `DELETE /sessions/{id}` locks at most its target.
`DELETE /sessions` locks the account's other live sessions in id order before
revoking them, as `revokeAllSessions` does, so any number of concurrent
revocations take their locks in one order and cannot deadlock one another,
however `authenticate` traffic has moved the rows. A row that another statement
revoked first is skipped, so each session is revoked, and reported, once. If
two devices sign each other out and the statements overlap, both act on a
snapshot in which the other was live and both end revoked; if one commits
first, the other finds its own session revoked and answers `401`.
`pruneExpired` skips session rows another statement holds locked, so
maintenance never waits on a revocation.

**A pending signed-in reset.** While a [signed-in reset](#the-signed-in-reset)
started by the caller's session is pending, `DELETE /sessions` and
`DELETE /sessions/{id}` from that session answer `409 reset-pending` and
revoke nothing, so it cannot sign out the sessions that show the reset. Every
other session of the account revokes as before, the initiating one included.

### `GET /accounts/me`

Authenticated.

```json
{ "account": { … }, "wallets": [ { … } ] }
```

### `PATCH /accounts/me`

Authenticated. Both fields optional; omitted fields are unchanged.

```json
{ "displayName": "Ada L.", "email": "ada@lovelace.example" }
```

Returns `{ "account": { … } }`. Submitting an `email` that differs from the
stored one clears `emailVerifiedAt`; the new address must be verified again.
Resubmitting the same address leaves verification intact.

This route (and `updateAccount`) changes the email with the session alone and
reports nothing to `onSecurityEvent`. A host that treats the email as a
security channel refuses `email` here and changes it only through the signed
[`changeEmail`](#methods). Either way an address change turns the account's
account recovery by email off and closes its live codes, in the same statement
([the email-change interlock](#the-email-change-interlock)).

Errors: `invalid-display-name`, `invalid-email` (400).

### `POST /email-verifications`

Public, because verification may precede account creation.

```json
{ "username": "ada@example.org", "email": "ada@example.org" }
```

```json
{
  "verificationId": "c7e1…",
  "email": "ada@example.org",
  "expiresAt": "2026-08-07T18:39:05.000Z"
}
```

**The minted code is never in this response.** Returning it would let anyone
who can name an address verify it. It reaches the address only through the
router's `emailVerification` option (see [Email delivery](#email-delivery)):
the router renders the message, hands it to the configured provider, and
answers only after the provider accepted it. Without that option the route
still mints and stores a code that nobody receives, which only suits a host
that calls `service.startEmailVerification(...)` and delivers the code itself.

Errors: `invalid-username`, `invalid-email` (400); `rate-limited` (429,
including while the username or the address has spent its daily wrong-code
budget); `email-delivery-failed` (502) when the provider refused or could not be
reached. The stored code is left to expire, and a retry mints a fresh one.

### Email delivery

Pass `emailVerification` to `createIdentityRouter` to have the start route send
the code:

```ts
import {
  createEmailSender,
  createIdentityRouter,
} from "web2-ish-self-custody/server";

const router = createIdentityRouter(service, {
  // …
  emailVerification: {
    sender: createEmailSender({ provider: "resend", apiKey: process.env.RESEND_API_KEY! }),
    from: "Example <verify@example.com>",
    replyTo: "support@example.com",          // optional
    theme: { productName: "Example", accentColor: "#2f6fed" },
    onFailure: (failure) => console.warn("verification email not sent", failure),
  },
});
```

**Providers.** `createEmailSender({ provider, … })` selects one from
configuration; each also has its own factory. All are a single HTTPS `POST`
through `fetch` with no added dependency, a 10-second timeout (`timeoutMs`),
and redirects refused.

| `provider` | factory | credential option |
| --- | --- | --- |
| `resend` | `createResendEmailSender` | `apiKey` |
| `postmark` | `createPostmarkEmailSender` | `serverToken` (and `messageStream`, default `outbound`) |
| `sendgrid` | `createSendGridEmailSender` | `apiKey` |

Any object with a `provider` label and `send(message) → { provider, messageId }`
is an `EmailSender`, so another transport (SES, SMTP through a relay, a queue)
plugs in without a change here. Resend receives `Idempotency-Key:
email-verification/<verificationId>`, so a retried send is one message.

**Content and design** belong to the host. Either:

- set `theme` to style the built-in template — `productName` is required;
  `subject`, `heading`, `intro`, `ignoreNotice`, `footerText`, `supportUrl`,
  `logoUrl`/`logoAlt`/`logoWidth`, eight colors (`backgroundColor`,
  `cardColor`, `borderColor`, `textColor`, `mutedTextColor`, `accentColor`,
  `codeBackgroundColor`, `codeTextColor`) and three font stacks
  (`headingFontFamily`, `bodyFontFamily`, `codeFontFamily`) are optional; or
- set `render(input) → { subject, text, html }` to replace the template
  entirely. `input` carries `code`, `formattedCode` (`ABCD-2345`, or `123 456`
  with `digits6`; confirm accepts either form), `email`, `expiresAt`, and
  `expiresInMinutes`.
  `renderVerificationEmail(input, theme)` and `escapeHtml` are exported for a
  render that only wraps the built-in one.

The built-in template is a table-laid card with inline styles and a plain-text
part, and loads no remote resource unless the theme names a `logoUrl`. Every
host-supplied string is HTML-escaped; colors must be hex, font stacks plain
lists, URLs `https:`, and the subject one line, all checked when the router is
built. A rendered message that does not contain the code in both its text and
HTML parts is refused rather than sent.

**Secrets and logging.** A provider credential is held in a closure, not on the
sender object, so logging or serializing a sender cannot print it. Nothing in
the delivery path logs. A failure is an `EmailDeliveryError` whose fields —
`provider`, `reason` (`timeout`, `network`, `rejected`, `invalid-response`,
`render`), and HTTP `status` — are all that `onFailure` receives; provider
response bodies are never read into it, because providers echo recipients and
request fields there.

The recipient is a caller-named address, so delivery makes the start route a
way to send mail. See [Rate limits](#rate-limits) for the per-recipient and
per-address bounds, and add an edge limit in front of it.

### `POST /email-verifications/confirm`

Public.

```json
{ "verificationId": "c7e1…", "code": "K7M2QRTX" }
```

```json
{
  "email": "ada@example.org",
  "usernameNormalized": "ada@example.org",
  "verifiedAt": "2026-08-07T18:26:11.000Z"
}
```

By default (`emailVerificationCodeFormat: "symbols8"`) codes are 8 characters
from a 32-symbol alphabet that omits `O`/`0` and `I`/`1`, so a code read aloud
or off a screen is unambiguous; confirm uppercases the submission and drops
everything but `A-Z` and `0-9`, so `k7m2-qrtx` matches. With `"digits6"` codes
are 6 decimal digits (`{ "code": "042917" }`), drawn uniformly by rejection
sampling, shown as `042 917`; confirm drops everything but `0-9`, so `042 917`
and `042-917` match. A deployment that switches formats strands the codes
already issued in the other one: confirm normalizes to the configured format,
and those codes then fail until they expire. Either way codes are stored only
as a SHA-256 digest bound to the domain string, the service profile, and the
verification id — so a code minted for one verification cannot validate against
another that happened to draw the same characters — and compared in constant
time.

Every comparison counts against two daily wrong-code budgets, the username's
and the recipient address's (20 each per 24 hours, see [Rate
limits](#rate-limits)), and a match gives both units back. Past either budget
every confirmation for it, the right code included, is refused, and so is a new
start.

Errors: `email-verification-failed` (400), also returned once the attempt budget
is spent; `email-verification-expired` (410); `rate-limited` (429, also rules
`email-verification-account-failures` and
`email-verification-recipient-failures`).

### Not exposed over HTTP

These `IdentityService` methods have no route, deliberately. Call
`revokeAllSessions`, `pruneExpired`, `migrate` and `deleteAccount` only from
code that already holds operator trust:

| method | why it is not routed |
| --- | --- |
| `revokeAllSessions(accountId)` | takes an account id rather than a token, and revokes the caller's session too; expose it behind your own authorization if you want a "sign out everywhere" control |
| `pruneExpired()` | maintenance; run it on a schedule (Vercel Cron, systemd timer, job runner). A dead session row that another statement holds locked is skipped, not waited on, and goes on the next run |
| `migrate()` | provisions the salt on first run; belongs to a deploy step, not to traffic |
| `liveSessionIds(token)` | every live session id of the caller's account, the caller's included, with no cap: for a host reconciling state it keeps per session against the sessions that still exist, never for display |
| `deleteAccount(accountId, options?)` | permanent and server-side: the host decides who may delete what, and when ([account deletion](#account-deletion)) |

`listSessions`, `revokeSessionById` and `revokeOtherSessions` are routed only
with `accountSecurityRoutes` ([Session management](#session-management-opt-in)).
None of the [account changes](#account-changes-and-recovery-keys-opt-in) or
[account resets](#account-resets-opt-in) is routed, `revokeRecoveryKeys(accountId)`
above all: it takes an account id and belongs to operator tooling.

```ts
const removed = await service.pruneExpired();
// { challenges, sessions, emailVerifications, rateLimits, recoveryTokens, accountResets,
//   auditEvents, secondFactorTickets }
```

### Error envelope

Every failure returns the same shape:

```json
{ "error": { "code": "challenge-expired", "message": "Challenge has expired." } }
```

`code` is stable API surface and safe to branch on. `message` is
operator-facing English and may change. It never contains credential material.
On `rate-limited`, a `Retry-After` header is present when the service supplied a
`retryAfterSeconds` detail.

Service codes, from `IdentityError`:

| code | HTTP |
| --- | --- |
| `account-exists` | 409 |
| `account-not-found` | 404 |
| `challenge-consumed` | 409 |
| `challenge-expired` | 410 |
| `challenge-not-found` | 404 |
| `email-delivery-failed` | 502 |
| `email-verification-expired` | 410 |
| `email-verification-failed` | 400 |
| `invalid-address` | 400 |
| `invalid-email` | 400 |
| `invalid-display-name` | 400 |
| `invalid-public-key` | 400 |
| `invalid-purpose` | 400 |
| `invalid-request` | 400 |
| `invalid-service-profile` | 500 |
| `invalid-signature` | 401 |
| `invalid-username` | 400 |
| `key-unchanged` | 409 |
| `rate-limited` | 429 |
| `reset-pending` | 409 |
| `reset-setting-refused` | 409 |
| `reset-unavailable` | 409 |
| `service-profile-missing` | 503 |
| `session-expired` | 401 |
| `session-not-found` | 401 |
| `stale-key` | 409 |
| `wallet-conflict` | 409 |
| `wallet-mismatch` | 409 |
| `wallet-registered` | 409 |

`identityErrorStatus(code)` returns the same mapping in TypeScript.

Transport codes, raised by the router before the service is reached, and kept
out of the `IdentityErrorCode` union so that union stays exactly the service's
stable surface:

| code | HTTP |
| --- | --- |
| `not-found` | 404 |
| `method-not-allowed` | 405 |
| `forbidden-origin` | 403 |
| `payload-too-large` | 413 |
| `unsupported-media-type` | 415 |
| `internal-error` | 500 |

An unexpected throw never reaches the client in any form: it becomes
`internal-error` with a fixed message.

## Account changes and recovery keys (opt-in)

Ten `IdentityService` methods change what signs in to an account or report on
it. None is routed by `createIdentityRouter`: a host calls them from its own
routes, around its own statements if it has any, and answers a recovery with
`createSessionResponder` ([below](#answering-a-recovery-from-a-host-route)).
Every change is authorized by signatures over the
[account-change message](PROTOCOL.md#part-4--the-account-change-message) for a
`rotation` challenge of the account's username (`POST /challenges` with
`purpose: "rotation"`, unchanged), verified strictly
([below](#strict-verification)).

### Opt-ins, modes and status

| rule | rotation | email change | recovery-key enrollment | removal, status, events | recovery begin, authenticate, complete | `revokeRecoveryKeys` |
| --- | --- | --- | --- | --- | --- | --- |
| opt-in (`accountSecurity`, both default `false`) | `signInKeyRotation` | none | `recoveryKeys` | none | `recoveryKeys` | none |
| wallet mode | deterministic modes only | any | deterministic modes only | any | deterministic modes only | any |
| account status | `active` | `active` | `active` | `active` | `active` | any (operator control) |

A refused opt-in or mode is `invalid-request` before any SQL runs. In
`random-vault` mode a password change is a vault re-wrap and the vault has its
own recovery code ([wallet modes](WALLET_MODES.md)). The status is checked when
the method reads the account and again inside its statement, under the account
row's lock, so a suspension that commits while a change waits refuses it. A
suspended account's caller gets `invalid-signature` ("Account is not active."),
as at login.

### Methods

| method | signed by | effect, in one statement |
| --- | --- | --- |
| `rotateSignInKey(token, { challengeId, newKey: { address, publicKey }, authorizerSignature, subjectSignature }, context?)` | the current key (authorizer) and `newKey` (subject) | updates the account's one enrolled-key row in place (address, `address_normalized`, public key, fingerprint; its id and creation time stay), revokes every other live session (the caller's stays), audits `account.key-rotate { method: "password", revokedSessions, sessionId }`. Returns `{ wallets, revokedSessionIds }`. |
| `changeEmail(token, { challengeId, email, authorizerSignature }, context?)` | the current key | sets the email, clearing `email_verified_at` when the address changes (as `updateAccount` does), audits `account.email-change { emailChanged, verificationCleared, sessionId }`. Returns `{ account, previousVerifiedEmail }`: the replaced address when it was verified, for the host to notify. It is never audited. Unlike [`PATCH /accounts/me`](#patch-accountsme) and `updateAccount`, which need only a session, it needs the enrolled key's signature. |
| `enrollRecoveryKey(token, { challengeId, recoveryPublicKey, authorizerSignature, subjectSignature }, context?)` | the current key and the recovery key | makes the key the account's one `active` recovery key, marks the previous one `removed`, which makes its tokens unusable, and stamps the ones it sees revoked ([tokens](#p_account_recoveries-migration-7)), audits `account.recovery-key.enroll { replaced, sessionId }`. Enrolling the active key again changes nothing (`changed: false`); a key the service has seen in any other state, on any account, is `invalid-public-key`. Returns `{ recoveryKey, changed }`. |
| `removeRecoveryKey(token, { challengeId, authorizerSignature }, context?)` | the current key | marks the active key `removed`, which makes its tokens unusable, stamps the ones it sees revoked, audits `account.recovery-key.remove { revokedTokens, sessionId }`. Returns `{ removed }`. |
| `recoveryStatus(token, context?)` | — | `{ recoveryKey }`: the active key, else the most recent key when it was `used` (prompt for a new one), else `null`. |
| `beginRecovery({ username, challengeId, recoveryPublicKey, signature }, context?)` | the recovery key | proves the key for the username and spends nothing: issues a recovery token (32 random bytes, 15 minutes, stored as SHA-256, good for one completion) and revokes the account's earlier live token, audits `account.recovery-begin { method: "recovery-key", supersededTokens }`. Returns `{ accountId, recoveryToken, expiresAt }`. |
| `authenticateRecovery(recoveryToken, context?)` | — | resolves a live token (unspent, unrevoked, unexpired, its key `active`, the account `active`): `{ accountId, usernameNormalized, expiresAt }`. |
| `completeRecovery(recoveryToken, { challengeId, newKey, authorizerSignature, subjectSignature }, context?)` | the recovery key (authorizer) and `newKey` (subject) | replaces the enrolled key with `newKey`, marks the recovery key `used` and the token completed, revokes **every** session, issues a new one with `context.clientLabel`, audits `account.recover { method: "recovery-key", revokedSessions, sessionId }`. Returns `{ account, wallets, session, revokedSessionIds }`. |
| `listSecurityEvents(token, context?)` | — | the account's last 20 audit events as `{ id, action, createdAt, clientLabel }`: no metadata, IP, key or address. `clientLabel` is the label of the session that acted or was issued, while that session's row exists. |
| `revokeRecoveryKeys(accountId, context?)` | — (server-only) | marks the active recovery key `removed`, which makes every token of the account unusable, and stamps the ones it sees revoked, whatever the account's status, audits `account.recovery-key.revoke { revoked, revokedTokens }`. Returns the number of keys removed. |

The challenge is consumed in its own statement before any signature is
checked, as login's is, and must be for the account's username. The username
never changes: a different username is a different account.

**Why an in-place update.** Login tries every enrolled-key row of an account.
Keeping the old row with a revocation mark would need a filter in login,
`listWallets` and the address-uniqueness rule; one row per account leaves all
three unchanged. A rotation or recovery therefore requires the account to have
exactly one enrolled key (`wallet-conflict` otherwise), which every account the
service registers has. The old address cannot be taken by another account: it
derives from this account's username.

### Strict verification

Every account-change signature must be 128 lowercase hex characters and pass
RFC 8032's strict checks (S < L, canonical A and R, A not of small order) and
noble's `zip215: false` verification. Every submitted public key (`newKey`, a
recovery key, and at registration the enrolled key) must be a canonical
encoding of a point that is not of small order, or it is `invalid-public-key`
before any account lookup, so the answer says nothing about any account. Under
noble's default rule, which login's `verifyChallengeSignature` keeps, a
small-order key with R = identity and S = 0 verifies for every message; such a
key can no longer be registered.

### Errors

| code | HTTP | when |
| --- | --- | --- |
| `invalid-signature` | 401 | a bad signature, a challenge of another username, a suspended account; every recovery failure an unauthenticated caller can cause (unknown username, no or another recovery key, a spent, revoked or expired token) |
| `key-unchanged` | 409 | `newKey` is the key already enrolled |
| `stale-key` | 409 | the enrolled key changed after the change was signed (another change won) |
| `wallet-conflict` | 409 | the account does not have exactly one enrolled key |
| `wallet-registered` | 409 | `newKey` is enrolled for another account |
| `invalid-public-key` | 400 | a non-canonical or small-order key, a malformed recovery key, or a recovery key enrolled before |
| `invalid-request` | 400 | the opt-in or the mode refuses the method, or a malformed input |
| `invalid-email` | 400 | `changeEmail`: the address is not one `normalizeEmail` accepts |
| `invalid-address` | 400 | a `newKey` whose address does not match its public key |
| `invalid-username` | 400 | `beginRecovery`: the username does not normalize |
| `challenge-not-found` | 404 | the `rotation` challenge does not exist |
| `challenge-expired` | 410 | the `rotation` challenge has expired |
| `challenge-consumed` | 409 | the `rotation` challenge was already used |
| `invalid-purpose` | 400 | the challenge was issued for another purpose |
| `rate-limited` | 429 | `account-change` or `recovery-begin` |

None of these methods is routed, so a host maps these codes in its own routes
(`identityErrorStatus(code)` gives the status). None of the input and challenge
codes depends on whether the account exists: the inputs are checked before any
lookup, and a challenge is issued and consumed alike for every username.

`enumerationSensitiveCodes` is unchanged: recovery failures reuse
`invalid-signature`, and `key-unchanged` and `stale-key` need a session or a
recovery token. A token or session failure is `session-not-found` or
`session-expired`, as with `authenticate`.

### Statements and lock order

Each change is one statement that re-checks, under row locks, the session (or
recovery token), the account's status and the enrolled key the signature was
checked against. Every statement takes its locks in one order, and never
`FOR UPDATE` on the account row:

1. the account row: `FOR SHARE` (`FOR NO KEY UPDATE` for the email change);
2. the enrolled-key row;
3. the recovery key, then the recovery token;
4. sessions, in id order (`FOR NO KEY UPDATE`), never the caller's own row;
5. inserts: a new session, the audit row.

`revokeOtherSessions` and `revokeAllSessions` lock sessions in id order and then
insert their audit row, whose foreign key takes `FOR KEY SHARE` on the account
row. `FOR KEY SHARE` conflicts with none of the account locks above, so a
revocation never waits on an account change, and both lock sessions in the same
order. `authenticate` locks one session row and nothing after it; login only
inserts. Had a rotation taken the account `FOR UPDATE` and then waited on a
session row held by a revoke-others, that revoke-others' audit insert would have
waited on the account: a deadlock. `accountChanges.integration.test.ts` drives
exactly that interleaving with a lock holder and fails with PostgreSQL 40P01
when the account lock is `FOR UPDATE`.

Two rotations at once: both read the same current key; one statement updates
the row, the other's guard then fails and it answers `stale-key`. Two begins at
once: the unique live-token index refuses the second insert and its retry, on a
fresh snapshot, revokes the first token, so at most one token is ever live. Two
completions with one token: one wins; the other finds the key `used`. A begin
that holds the recovery key while an enrollment, a removal or
`revokeRecoveryKeys` retires it: the retirement waits on the key, then marks it
`removed`, but its token update runs on a snapshot taken before the begin
committed, so the begin's new token is left unstamped (and the audit's
`revokedTokens` does not count it). That token is refused all the same,
because every reader of a token requires its key to be `active`; the next
begin stamps it, or `pruneExpired` deletes it.

**A residual race.** A login that read and verified the old key issues its
session only while that key is still enrolled, checked in the session's insert
statement. A login whose insert runs while the rotation's statement runs can
still keep a session, because neither statement can see the other's rows. The
window is one statement long; the sessions list shows the session, and
revoking other sessions ends it.

### Account-change rate limits

| rule | limit | subject |
| --- | --- | --- |
| `account-change` | 10 per 300 s | hashed IP and account id: every signed change of the account, recovery completion included |
| `recovery-begin` | 5 per 3,600 s | hashed IP and normalized username |
| `recovery-begin-ip` | 20 per 3,600 s | hashed IP, only when the host supplies one |

They are counted before the challenge is consumed, so a refused attempt still
counts. A recovery token is 256 bits and needs no limit of its own.

### The security-event hook

`onSecurityEvent` (config) receives `{ action, accountId, occurredAt,
clientLabel, revokedSessions?, previousVerifiedEmail?, setting?, enabled?,
availableAt?, abortedBy? }` after the statement of
`account.key-rotate`, `account.email-change` (when the address changed),
`account.recovery-key.enroll` (when it changed), `account.recovery-key.remove`,
`account.recovery-key.revoke`, `account.recovery-begin`, `account.recover`,
`session.revoke-others` (when it revoked a session) and the
[account resets' events](#reset-events) has committed. The service
awaits it for at most 3 seconds and ignores what it throws, so a slow or failing
notice provider never fails or rolls back a change. A host that sends notices
from its own route after its own statements can leave it unset.

### Answering a recovery from a host route

`createSessionResponder(service, options)` returns `(payload, issued, status =
200) => Response`, the router's own session response: with the same `service`
and the same options as `createIdentityRouter`, the cookie (name, `Domain`,
`Max-Age` = `sessionTtlSeconds`, `Path=/; HttpOnly; Secure; SameSite=Lax`) or,
with `useCookies: false`, the token in the body, are the router's byte for
byte. It validates the cookie options as the router does.

```ts
const respond = createSessionResponder(service, routerOptions);
const recovered = await service.completeRecovery(recoveryToken, input, context);
return respond({ account: recovered.account }, recovered.session, 200);
```

### Audit retention

With `auditRetentionDays`, `pruneExpired` deletes this service's `account.*`
and `session.*` audit rows older than that many days. Other audit rows
(`email.*`, `wallet.*`) are kept. Unset keeps every audit row, as before. A row
whose account an operator deleted by hand (`account_id` is `ON DELETE SET
NULL`) names no service profile, so no service's retention prunes it, and one
service never prunes another's rows on a shared prefix: an operator that
deletes an account by hand deletes its audit rows first (`DELETE FROM
<p>_audit_events WHERE account_id = $1`), or uses `deleteAccount`, whose kept
rows stay under the deleting service's retention
([account deletion](#account-deletion)). Recovery-token and second-factor
ticket rows are deleted one day after they expire, whatever the retention.

## Account deletion

`deleteAccount(accountId, options?, context?)` permanently deletes one account
and everything this service stores for it. It is server-side only: no route
mounts it, and the host authorizes and schedules it (for example a purge after
a retention period).

```ts
const result = await service.deleteAccount(accountId, { revokeLiveSessions: true });
// { deleted: true, revokedSessions: 2 }; { deleted: false, revokedSessions: 0 } when no such account
```

- **One statement.** It deletes the account row, its enrolled keys
  (`<p>_account_wallets`, with any vault), its sessions, recovery keys and
  recovery tokens, account resets and second-factor tickets, the challenges and
  email verifications stored under its username, and its `login-account`
  rate-limit row. Other rate-limit rows stay until `pruneExpired` removes them,
  a day after their last use: those keyed with a caller's IP hash, three
  keyed by the account's email address alone or with its username
  (`email-verification`, `email-verification-recipient`,
  `account-reset-recipient`), and the two daily wrong-code budgets, keyed by
  the username (`email-verification-account-failures`) and by the address
  (`email-verification-recipient-failures`). These are unsalted SHA-256
  digests, so whoever knows the address or the username can tell for that day
  that it was counted. Deleting the recipient caps would let a caller reset a
  mail-flood cap by deleting and re-registering, and deleting a wrong-code
  budget would hand a guesser a fresh one, so they are kept.
- **Live sessions.** An account with a live session (neither revoked nor
  expired) is refused with `account-has-sessions` (409,
  `details.liveSessions`) and nothing is deleted, unless `revokeLiveSessions:
  true` revokes and deletes them in the same statement. `revokedSessions`
  counts them. The check runs after the account lock, in a fresh snapshot
  (the statement calls `<p>_delete_account`, migration 13), so a session that
  a login or second-factor completion committed while the deletion waited for
  that lock is counted, never cascaded away unseen.
- **Idempotent.** A missing account resolves `{ deleted: false,
  revokedSessions: 0 }`; a malformed id is `invalid-request`.
- **Audit.** Rows older than `auditRetentionDays` that its rule would prune
  (`account.*`, `session.*`) are deleted now. The others are kept, detached:
  `account_id` NULL, `deleted_account_id` the account's id and
  `deleted_service_profile_id` the service's (migration 13), so `pruneExpired`
  keeps applying the retention to them. An `account.deleted` row records the
  deletion with `deleted_account_id` and counts only (`revokedSessions`,
  `keptAuditEvents`, `prunedAuditEvents`): no email, username, key or address.
  Audit rows are detached in a snapshot taken after the locks, so one that a
  concurrent statement committed while the deletion waited is detached like
  the others. One committed later still, before the account row goes, is
  detached by the foreign key's cascade; a trigger (migration 13) keeps its
  `deleted_account_id`, and `pruneExpired` reaches it through the
  `account.deleted` row.
- **Lock order** (that of the account changes): the account `FOR NO KEY
  UPDATE` (never `FOR UPDATE` first), then its enrolled keys, recovery keys,
  recovery tokens, resets and tickets, then its sessions in id order, as
  `revokeOtherSessions` and `rotateSignInKey` lock them, then the deletes. The
  children are locked before the account row goes, so the cascade never takes
  a lock after the account's. A login or a second-factor completion locks the
  account first, so it waits, and then finds no account.
- **Not deleted: `<p>_wallet_setups`.** Its rows are immutable by trigger
  (migration 5), keyed by username, created for any username that requests a
  challenge in the per-account modes, and hold the public salt of a
  per-account wallet: deleting one would make a wallet that still exists
  outside the service underivable. It holds no account id. In
  `service-deterministic` mode it stays empty.

## Second sign-in factor (opt-in)

A service created from a `SecondFactorIdentityServiceConfig`, whose
`secondFactor` is `{ required(accountId, context), verify(accountId,
ticketId, code) }`, is an `IdentityService<true>`. Every step that would
issue a session after a password proof asks the host first:

| step | `context.purpose` | the ticket is bound to |
| --- | --- | --- |
| `login` (`POST /sessions`) | `login` | the key that signed the login challenge |
| `completeAccountReset` | `email-reset` | the new key it enrolled |
| `completeRecovery` | `recovery` | the new key it enrolled |

When `required` answers anything but `false` (a throw refuses the step), the
step issues no session. In the statement that would have inserted the
session it inserts a ticket instead, and it answers `{ secondFactor:
"totp", ticket, expiresAt }` in place of `session` (a reset or recovery still
replaces the key, revokes the sessions and closes the resets as before; only
its new session waits). `completeSecondFactor({ ticket, code })` (routed as
`POST /sessions/second-factor`) then:

1. reserves one of the ticket's five attempts in a single-row `UPDATE`, so
   parallel guesses cannot share one, or refuses an unknown, used, expired or
   exhausted ticket (`second-factor-ticket-invalid`) without calling the host;
2. counts the code against the account's `login-account` rate limit (25 an
   hour, keyed by the account alone, whatever the ticket, its purpose or the
   caller's address), refusing with `rate-limited` past it, then calls
   `verify(accountId, ticketId, code)`; `ticketId` is the ticket row's id,
   never its secret. An `"ok"` or `"locked"` verdict gives the unit back, so
   only wrong codes and verifier failures stay counted. A full bucket refuses
   every outstanding ticket of the account, and a login or recovery that
   needs the factor checks it before it issues a ticket;
3. on `"ok"`, issues the session in the statement that consumes the ticket,
   while the account is active and the ticket's key still enrolled; that
   statement also advances the reset generation and aborts a pending signed-in
   reset, as a login does. Audit: `session.second-factor-ok { purpose,
   sessionId }`, plus `account.login { …, secondFactor: true }` for a login;
4. on `"invalid"` (or any value but `"ok"` and `"locked"`), audits
   `session.second-factor-failed { purpose, reason, attempts, exhausted }`
   and answers `second-factor-invalid` with `details.attemptsRemaining`; the
   fifth kills the ticket (`second-factor-ticket-invalid`);
5. on `"locked"`, audits the failure (`reason: "locked"`) and answers
   `second-factor-locked` (423).

A ticket is 32 random bytes (base64url), valid 5 minutes, stored only as a
domain-separated SHA-256 (`web2-ish-self-custody second-factor ticket v1`,
the service profile id and the ticket, joined by newlines) in
`<p>_second_factor_tickets` (migration 12), one per challenge. The SDK stores
no factor data and never sees a secret: the code goes to `verify` and nowhere
else.

`completeSignedInReset` issues no session (the initiating session stays), so
there is nothing to gate: that session was issued through the gate, and the
next sign-in with the new password asks for the factor. `register` issues its
session at once: a new account has no factor.

For an account recovery by email, `required` runs before the emailed code is
checked (the code is checked in the completion's statement), so it must
answer from the account alone, change nothing, and not vary its timing in a
way the host's response padding does not cover. The account-limit check is
skipped there, so a refusal never tells an unauthenticated caller that the
account exists.

Without the option nothing above runs: each statement is the one earlier
releases ran, the route is not mounted, and `completeSecondFactor` answers
`invalid-request`.

## Account resets (opt-in)

Account recovery by email and the signed-in reset replace the enrolled key
without the old password, as a recovery key does; reauthentication proves the
current password to the host and changes nothing. Nine `IdentityService`
methods, none routed by `createIdentityRouter`: a host calls them from its own
routes and answers `completeAccountReset` with `createSessionResponder`
([above](#answering-a-recovery-from-a-host-route)). Key replacements, setting
changes, and reauthentication are signed over
the [account-change message](PROTOCOL.md#part-4--the-account-change-message)
for a `rotation` challenge of the account's username and verified
[strictly](#strict-verification), as the account changes are.

### Opt-ins, settings and status

Two service opt-ins, both **default `false`**, and two per-account settings
(migration 8):

| | account recovery by email | signed-in reset |
| --- | --- | --- |
| service opt-in | `accountSecurity.emailReset` | `accountSecurity.signedInReset` |
| account setting, default | `email-reset`, **off** | `signed-in-reset`, **on** |
| turning the setting on | needs the opt-in and a verified email | needs the opt-in |
| turning the setting off | always works; closes its live codes | only while an active recovery key (with `recoveryKeys` on) or account recovery by email is set; aborts a pending reset, which counts as pending, and completes, only while the setting is on |
| methods | `startAccountReset`, `cancelUndeliveredAccountReset`, `completeAccountReset` | `startSignedInReset`, `completeSignedInReset` |

`abortSignedInReset`, `accountResetStatus`, turning a setting off and
`verifyReauthentication` need no opt-in. The resets and the settings run only
in the deterministic wallet modes (`invalid-request` in `random-vault` mode,
before any SQL); reauthentication runs in every mode. Apart from host cleanup
of a failed send, every method requires an `active` account, checked again
under the account row's lock; a suspended
account's caller gets `invalid-signature`, and `startAccountReset` answers as
for any other username. The rule for turning the signed-in reset off is
checked when it is turned off: removing the other method later leaves it off.
A change of either setting, in either direction, cancels pending signed-in
resets; changing the email-reset setting also closes its open email codes.
Failed-send cancellation is host cleanup and can close a code after an
account is suspended or the service email-reset opt-in is turned off.
Migration 9 adds a durable reset generation to each account and reset. A
signed-in reset is pending or completable only while the generations match,
including when a concurrent start was invisible to the cancelling statement's
snapshot. The next start closes such a stale row before issuing a new reset.

With `signedInReset` on, every account's signed-in reset is on until its owner
turns it off: a stolen session can then replace the enrolled key after the
72-hour wait unless another session aborts it, the owner signs in with the
password or changes it, or an email or recovery factor changes
([security model](SECURITY_MODEL.md#account-resets)). The
initiating session must outlive the wait, since only it completes the reset
and a session's expiry is fixed: without an emailed code, `startSignedInReset`
refuses a session that expires before `availableAt` (`reset-unavailable`,
`details.reason: "session-expires-first"`) rather than accept a reset that can
never complete, and it never extends the session. With `sessionTtlSeconds` at
or below 72 hours every such start is refused; at the default 14 days a
session can start one during its first 11 days.

### Reset methods

| method | signed by | effect |
| --- | --- | --- |
| `setAccountResetSetting(token, { challengeId, setting, enabled, authorizerSignature }, context?)` | the current key, action `email-reset-setting` or `signed-in-reset-setting`, subject `setting:on` or `setting:off` | one statement: sets the setting (the account row `FOR NO KEY UPDATE`, the key and any recovery key `FOR SHARE`, so a change that committed while it waited is seen), cancels pending signed-in resets and closes email codes when the email-reset setting changes ([above](#opt-ins-settings-and-status)), audits `account.reset-setting { setting, enabled, closedResets, sessionId }`. Returns `{ settings, changed }`; `changed: false` when it already had the value. |
| `accountResetStatus(token, context?)` | — | `{ settings: { emailReset, signedInReset }, emailVerified, pendingSignedInReset }`. The pending reset is `{ id, createdAt, availableAt, expiresAt, initiatedByCaller, codeUsable }`, or `null` when none is live, its session is gone, or the signed-in reset setting is off. A host shows every other session a banner with **Abort** from it. |
| `startAccountReset({ username }, context?)` | — | [below](#account-recovery-by-email). Returns `{ resetId, expiresAt, delivery }`. |
| `cancelUndeliveredAccountReset({ resetId, code }, context?)` | issued id and code, host only | After a failed mail send, closes only that live email challenge under the account lock. Returns `{ cancelled }`; missing, wrong, expired, completed or already closed resets return `false`. The mail attempt still counts toward recipient quota. |
| `completeAccountReset({ username, resetId, code, challengeId, newKey, subjectSignature }, context?)` | `newKey` only, action `email-reset`, authorizer `email:<resetId>` | one statement: replaces the enrolled key, marks the reset completed, closes the account's other live resets, revokes **every** session and issues a new one, audits `account.email-reset { method: "email", revokedSessions, closedResets, sessionId }`. Returns `{ account, wallets, session, revokedSessionIds }`. |
| `startSignedInReset(token, context?)` | — | [below](#the-signed-in-reset). Returns `{ reset, delivery }`. |
| `abortSignedInReset(token, context?)` | — | aborts the account's pending signed-in reset, from any of its sessions, audits `account.signed-in-reset.abort { abortedBy: "session", sessionId }`. Returns `{ aborted }`. |
| `completeSignedInReset(token, { challengeId, resetId, newKey, subjectSignature, code? }, context?)` | `newKey` only, action `signed-in-reset`, authorizer `session-reset:<resetId>` | one statement, from the initiating session only: replaces the enrolled key, marks the reset completed, closes the account's other live resets, revokes every **other** session (the caller's stays), audits `account.signed-in-reset { method: "wait" or "email-code", revokedSessions, closedResets, sessionId }`. Returns `{ wallets, revokedSessionIds }`. |
| `verifyReauthentication(token, { challengeId, label, authorizerSignature }, context?)` | the current key, action `reauthentication`, subject `host:<label>` | one statement: re-checks the session, the status and the key under their locks and audits `account.reauth { label, sessionId }`; nothing else. Returns `{ accountId, sessionId, label, verifiedAt }`. |

A reset's authorizer is not a key: the emailed code, or the elapsed wait from
the same session, is what authorizes it, so only the subject, the new key,
signs (proof of possession). A setting's and a reauthentication's authorizer is
the current key, which signs, so a stolen session alone can change neither.

### Account recovery by email

`startAccountReset` answers **every username the same way**: a fresh random
decoy `resetId` and an `expiresAt` 15 minutes on, whether or not the account
exists, has a verified email, has the setting on or is active. An account row
lock coalesces starts while one email challenge is open. Only a new challenge
counts against the address's per-recipient cap (`account-reset-recipient`,
[below](#reset-rate-limits)). Then, and only then, `delivery` is
`{ email, resetId, code }`, for the host to send; otherwise it is `null`.
The usable `delivery.resetId` must reach the mailbox owner with the code.
Never return it in the anonymous start response. The public decoy cannot
spend the challenge's five attempts.
An unexpired challenge whose five attempts are spent is closed under the
account lock before coalescing, allowing a new code while recipient quota
remains. The old code cannot complete.
The code is 16 symbols of `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (80 bits),
returned ungrouped; a host may show it in four groups of four, since a
completion ignores case and separators. It replaces the enrolled key with no
password, so it is long enough that its stored digest cannot be searched
offline within its 15 minutes.

```ts
const issued = await service.startAccountReset({ username }, context);
if (issued.delivery !== null) {
  const delivery = await sendResetCode(issued.delivery); // 'sent' | 'failed' | 'uncertain'
  if (delivery === 'failed') { // only a definitive provider refusal or pre-send failure
    await service.cancelUndeliveredAccountReset({
      resetId: issued.delivery.resetId,
      code: issued.delivery.code,
    }, context);
  }
}
await padTo(start, 3_500); // the same total time for every username
return Response.json({ resetId: issued.resetId, expiresAt: issued.expiresAt });
```

A provider timeout, network error, or malformed success response is
`uncertain`: the email may still arrive, so leave its challenge valid. A
definitive refusal may be cancelled to let the owner retry immediately.

Never put `delivery` in a response, never answer differently when it is
`null`, and pad every response to one fixed time: the SDK's internal work and
mail delivery vary by eligibility. No hook runs for a start, for the same
reason. The client signs the `email-reset` message over `email:<resetId>` and
`key:<new key>` with the new key, and completes with the id and code the email
carries, including in a different browser from the one that started it.
Only the server host calls `cancelUndeliveredAccountReset` after the mail
provider reports failure. Pass both values from `delivery`; the anonymous
decoy id cannot close the real challenge. A successful cancellation releases
the challenge slot immediately so another start can issue a code, while the
recipient quota still bounds repeated failed send attempts. Never expose the
cancellation method as an anonymous endpoint.
Deploy the host's email template and completion form with this SDK change:
an old host that mails only the code leaves the new challenge unusable.
Run migration 10 before enabling the new start path, and stop older SDK
instances from serving it; they can still expose a usable id and spend the
shared username quota. Migration 9 is the signed-in reset generation fence;
both migrations must be applied before this combined SDK serves traffic.
Migration 10 closes open email challenges whose ids earlier SDKs exposed and
clears legacy reset-recipient counters. A mailbox owner can request a new
challenge after the cutover.
Migration 11 reapplies only the current email-reset function definitions on
databases that already recorded an earlier migration 10. It does not replay
migration 10's cutover UPDATE or recipient-quota DELETE. Run it before serving
this SDK on such a database.

Every failure of `completeAccountReset` that an unauthenticated caller can
cause is one `invalid-signature`: an unknown username or reset id, a wrong,
spent or expired code, a code out of attempts, the setting turned off, the
email changed or unverified, a suspended account, a bad signature, a challenge
of another username. One SQL statement locks the account, then the reset,
counts an attempt, and completes when the code and account checks pass.
Parallel guesses cannot share an attempt; a concurrent start cannot retire a
valid fifth attempt between counting and completion. The statement checks
the code's digest, the attempts, the expiry, the setting
and the verified email (verified before the code was issued) under the row
locks. A code that verified but names the current key is `key-unchanged`.

#### The email-change interlock

An address change turns account recovery by email off and closes the
account's live emailed codes in the same statement, in `changeEmail` and in
`updateAccount` (`PATCH /accounts/me`) alike: the new address is not yet a
recovery channel, and the codes went to the old one. Turning it back on needs
the new address verified and a signature by the key. The audit rows say so
(`account.email-change` and `account.update` gain `emailResetDisabled` and
`closedResets`).

### The signed-in reset

For a user who has forgotten the password but is still signed in.
`startSignedInReset` starts a reset bound to the caller's session, available to
that session **72 hours** later and completable for 7 days after that. With
account recovery by email on (the opt-in, the setting and a verified email) it
also issues an emailed code, returned as `delivery`, that completes the reset
at once (15 minutes, 5 attempts); when the code runs out or expires, the wait
remains. The hook receives `availableAt`, so a host can send its owner a notice
at the start and another before the reset becomes available.

- **One at a time.** A second start, from any session, answers `409
  reset-pending`; the unique live index refuses a concurrent second insert,
  whose retry finds the first. A reset that lapsed, or whose session is gone, is
  closed by the next start.
- **Abort.** Any session of the account aborts it (`abortSignedInReset`). A
  sign-in with the password aborts it **in the login statement**
  (`account.signed-in-reset.abort { abortedBy: "login", sessionId }`), and a
  password change (`rotateSignInKey`) **in the rotation's statement**
  (`abortedBy: "rotation"`), because each proves the password is not
  forgotten. The rotation keeps the caller's session, which may be the very
  session (or a stolen copy of it) that started the reset, so without this
  the reset would outlive the new password. Revoking the initiating session
  ends it too, since only that session can complete it.
- **Session lifetime.** Without an emailed code, a start from a session that
  expires before `availableAt` is refused (`reset-unavailable`,
  `details: { reason: "session-expires-first", sessionExpiresAt }`).
- **No hiding.** While it is pending, the initiating session's
  `revokeOtherSessions` and `revokeSessionById` answer `409 reset-pending`.
- **Completion.** Only the initiating session, with `resetId`, a new
  `rotation` challenge and the new key's signature; `code` to complete before
  `availableAt`. `reset-unavailable` when there is no such pending reset of
  this session (aborted, completed, expired, another session's) or it is not
  available yet (`details.availableAt`); `email-verification-failed` for a
  wrong, expired or exhausted code; `stale-key` when the enrolled key changed
  after the call began (another change won).

### Reauthentication

`verifyReauthentication` lets a host require a fresh current-password run for
an action of its own, with an audit row naming it. `label` is the host's
constant for that action, 3 to 80 characters from `[a-z0-9._:-]` starting with
a letter or digit, never user data. A label is part of the signed subject, so a
signature for one label proves nothing for another. It consumes the challenge,
counts under `account-change`, and changes nothing else; the host acts on the
result in its own statement.

### Reset errors

| code | HTTP | when |
| --- | --- | --- |
| `invalid-signature` | 401 | a bad signature, a challenge of another username, a suspended account; every failure of `completeAccountReset` an unauthenticated caller can cause |
| `reset-setting-refused` | 409 | account recovery by email without a verified email (`details.reason: "email-unverified"`); the signed-in reset off with no other method (`"no-other-reset-method"`); a signed-in reset while the account's setting is off (`"signed-in-reset-off"`) |
| `reset-pending` | 409 | a second signed-in reset; a revocation by the session that started a pending one |
| `reset-unavailable` | 409 | no pending signed-in reset of this session to complete, or not yet available (`details.availableAt`); a `startSignedInReset` without an emailed code whose session expires before the reset would be available (`details.reason: "session-expires-first"`, `details.sessionExpiresAt`) |
| `email-verification-failed` | 400 | `completeSignedInReset`: a wrong, expired or exhausted code |
| `key-unchanged`, `stale-key`, `wallet-conflict`, `wallet-registered` | 409 | as for the account changes |
| `invalid-request` | 400 | the opt-in or the mode refuses the method, or a malformed input (setting, value, label, reset id) |
| `invalid-public-key`, `invalid-address`, `invalid-username` | 400 | a submitted key or username, checked before any lookup |
| `rate-limited` | 429 | the rules [below](#reset-rate-limits) |

The three new codes are 409s that need a session; none is added to
`enumerationSensitiveCodes`.

### Reset statements and lock order

Each change is one statement, in the [account changes' order](#statements-and-lock-order),
with the resets after the enrolled key and before the sessions, and never
`FOR UPDATE` on the account row:

1. the account row: `FOR SHARE` (`FOR NO KEY UPDATE` for login, abort, rotation,
   email start and completion, reset-setting and recovery-factor changes, an address change and
   `updateAccount`);
2. the enrolled-key row (`FOR UPDATE` to replace it, `FOR SHARE` to check it);
3. a setting change only: the active recovery key, `FOR SHARE`;
4. the reset being completed (`FOR UPDATE`), then the other live resets it
   closes;
5. sessions, in id order (`FOR NO KEY UPDATE`), never the caller's own row;
6. inserts: a new session, the audit rows.

Login locks the account `FOR NO KEY UPDATE` and rechecks the enrolled key
`FOR SHARE` before inserting its session, advancing the reset generation and
closing visible resets. A concurrent signed-in completion holds the account
`FOR SHARE`: login first invalidates its reset, even if the completion's
snapshot cannot see the new session; completion first makes login recheck the
moved key after it waits. `abortSignedInReset` also takes the account
`FOR NO KEY UPDATE` and then the reset row; rotation takes the account, key, pending
reset and sessions in that order. Revocations only read resets.
`accountResets.integration.test.ts` forces both login/completion orders and
the existing lock-order cases.

A completion that is already waiting when a revoke-others revokes its
initiating session can still commit: its snapshot saw the session live. The
abort, password login and password change also fence a start that their
statement snapshot could not see.

A setting change cannot close a reset that a start inserted while the change
waited for the account row, because the change's snapshot predates the row.
The account generation prevents that reset from counting as pending or
completing; the next start closes the stale row.

### Reset rate limits

| rule | limit | subject |
| --- | --- | --- |
| `account-reset-start-ip` | 20 per 3,600 s | hashed IP, only when the host supplies one |
| `account-reset-recipient` | 8 per 3,600 s | the address, counted only for a fresh challenge; coalesced starts spend no recipient quota and over-cap starts answer as always |
| `account-change` | 10 per 300 s | hashed IP and account id for the signed-in methods; hashed IP and normalized username for `completeAccountReset` |

There is no shared anonymous per-username quota to exhaust.
`account-reset-recipient` is a bucket of
its own, read by nothing but the start, whose answer is uniform. Sharing email
verification's `email-verification-recipient` bucket would leak and silence:
`startEmailVerification` is unauthenticated and answers `429` from that
bucket, so its threshold would reveal that a start found an eligible account
at a guessed address, and eight verification requests an hour would stop the
owner's reset codes without a trace. An edge limiter in front of
`startAccountReset` is still the host's.

### Reset events

`onSecurityEvent` receives, after commit: `account.reset-setting` (when it
changed; `setting`, `enabled`), `account.email-reset` and
`account.signed-in-reset` (`revokedSessions`), `account.signed-in-reset.start`
(`availableAt`) and `account.signed-in-reset.abort` (`abortedBy`: `session`,
`login` or `rotation`). The start of
an account recovery by email and a reauthentication are audited
(`account.email-reset.start`, `account.reauth`) but not reported.

## Challenge message format

The signed message is UTF-8 text: eight fields joined by single `\n` (U+000A).
There is no trailing newline, no BOM, and no `\r`.

```
1  web2-ish-self-custody auth challenge v1     fixed domain string
2  <serviceProfileId>
3  <applicationId>
4  <networkId>
5  <purpose>                                   registration | login | rotation
6  <usernameNormalized>
7  <nonceHex>                                  32 bytes, 64 lowercase hex chars
8  <expiresAt>                                 Date.toISOString()
```

Every component is newline-free by construction — username normalization rejects
anything outside printable ASCII, and `buildChallengeMessage` rejects line breaks
in the three identifier fields — so the line-delimited encoding is unambiguous and
two different field tuples cannot produce the same message. The leading domain
string keeps these signatures from being replayable against any other protocol
that signs with the same key.

### Worked example

Field values:

| field | value |
| --- | --- |
| `serviceProfileId` | `example-app-password-wallet-v1` |
| `applicationId` | `example-app` |
| `networkId` | `kalvora-mainnet` |
| `purpose` | `login` |
| `usernameNormalized` | `ada@example.org` |
| `nonceHex` | `8f1c2b4d6e0a93571fb2c8d40e5a6719bc3d2e8f04a1b5c69d7e8f0a1b2c3d4e` |
| `expiresAt` | `2026-08-07T18:24:05.000Z` |

The exact message, 210 UTF-8 bytes:

```
web2-ish-self-custody auth challenge v1
example-app-password-wallet-v1
example-app
kalvora-mainnet
login
ada@example.org
8f1c2b4d6e0a93571fb2c8d40e5a6719bc3d2e8f04a1b5c69d7e8f0a1b2c3d4e
2026-08-07T18:24:05.000Z
```

As a JavaScript string literal:

```
"web2-ish-self-custody auth challenge v1\nexample-app-password-wallet-v1\nexample-app\nkalvora-mainnet\nlogin\nada@example.org\n8f1c2b4d6e0a93571fb2c8d40e5a6719bc3d2e8f04a1b5c69d7e8f0a1b2c3d4e\n2026-08-07T18:24:05.000Z"
```

First 48 bytes, hex:

```
776562322d6973682d73656c662d637573746f64792061757468206368616c6c656e67652076310a6578616d706c652d
```

`SHA-256` of the full message bytes:

```
5c7d93e0e4e3889c59af2b8426d858aa37cf17933051c63e602a4750809eaf8d
```

Signed with the synthetic Ed25519 seed of 32 `0x07` bytes — for reproduction
only, never a real wallet. The address and identifier rows are the
`kalvora-ed25519-base58-v1` encoding of that public key; the raw key and the
signature are codec-independent and are what a deployment on another chain would
reproduce.

| | |
| --- | --- |
| public key (raw hex) | `ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c` |
| address (Kalvora codec) | `GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB` |
| public key identifier (Kalvora codec) | `A_GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB` |
| fingerprint | `GMAD RPPB C7P5 ARKV` |
| signature | `e89133e0ca01513b23bc29f76f2fdd3d53796294666541fa63d50193c1ccda550fcd59bc97e9ec0453e03fb33123dbc4a81d45138a61091c160482bde8482105` |

### Signature conventions

The client signs the **raw UTF-8 message bytes** with Ed25519 through
`signExactMessageUnsafe` — RFC 8032 PureEdDSA, no prehash and no context string.
The result is a 64-byte signature, sent as 128 lowercase hex characters. There is
no digest step on either side: the server verifies against exactly those message
bytes.

The server normalizes a submitted signature with `trim().toLowerCase()` and
rejects anything that is not 128 hex characters. Verification returns `false`
rather than throwing, so a malformed signature and a wrong signature are
indistinguishable to the caller.

### Address and public key binding

The server recomputes the address from the submitted public key and rejects any
mismatch, so a caller cannot register a key under an address it does not
control. `canonicalWalletIdentity(codec, { publicKey, address })` takes the
deployment's codec as its first argument and applies the same four rules for
every chain:

1. `codec.decodePublicKey(publicKey)` must succeed — a throw becomes
   `invalid-public-key` (400).
2. The decoded key must be exactly 32 bytes.
3. `codec.encodeAddress(decoded)` must equal the submitted `address` after
   trimming, or the request is `invalid-address` (400).
4. The stored `publicKey` is the **re-encoded** `codec.encodePublicKey(decoded)`,
   not the caller's string, so a non-canonical encoding of a key the caller does
   control cannot be smuggled in either.

`addressNormalized` is the lowercased address; `codecId` is recorded from the
codec that produced it.

For the bundled Kalvora codec those rules read as: the public key must be
`A_<base58>`; the base58 body must decode to exactly 32 bytes; the address is
the Base58 encoding of those bytes. A deployment on a different chain gets the
same guarantees with its own encoding, because the rules above never mention
one.

The `fingerprint` is a display aid: alphanumerics of the address, uppercased,
first 16 characters, in groups of four. It is not a security control and must
never be compared in place of the address.

## Schema reference

Tables are namespaced by `tablePrefix` (default `w2sc`), so several services can
share one database. Below, `<p>` is that prefix.

Every statement the service issues is positionally parameterized, and every
mutation that needs atomicity is a single statement built from CTEs — there are
no interactive transactions, because Neon's HTTP transport has none. `bytea`
columns are read with `encode(col, 'hex')` and written with `decode($n, 'hex')`,
so no driver-specific decoding behavior leaks in.

### `<p>_schema_migrations`

Applied migration versions. `runIdentityMigrations` skips versions already
recorded, so `migrate()` is safe to call repeatedly and concurrently.

### `<p>_service_profiles`

**The salt lives here. This is the most important table in the schema.**

One row, ever. Columns: `service_profile_id` (PK), `profile_id`, `algorithm`,
`curve`, `application_id`, `network_id`, `public_salt bytea`, `kdf_n`, `kdf_r`,
`kdf_p`, `kdf_dk_len`, `created_at`.

Invariants, enforced by the `<p>_service_profiles_exact` CHECK constraint:

- every identity and KDF column equals the literal value baked in at migration
  time, so a deployment whose configuration has drifted cannot insert a second,
  differently-shaped row
- `octet_length(public_salt) = 32`
- `public_salt <> decode(repeat('00', 32), 'hex')` — an all-zero salt is
  rejected outright

**Immutability triggers.** `<p>_service_profiles_immutable` fires
`BEFORE UPDATE OR DELETE … FOR EACH ROW`, and
`<p>_service_profiles_no_truncate` fires `BEFORE TRUNCATE … FOR EACH STATEMENT`.
Both raise SQLSTATE `55000` with the message
`wallet derivation service profile is immutable`. There is no supported way to
rotate a salt in place, because rotating it is not a configuration change — it
is the destruction of every wallet in the namespace. `INSERT` remains permitted
so that first provisioning can write the row; the bootstrap guard below is what
stops a second, different row from appearing later.

The row is inserted by the migration using `gen_random_bytes(32)` from
`pgcrypto`. The salt is generated by the database, not by application code.

### `<p>_service_profile_bootstrap`

One row per `service_profile_id`, recording that a salt was ever minted. It is
separate from the profile table for exactly one reason: so that a *dropped*
profile row is detectable.

**The bootstrap guard**, in migration 1: if a bootstrap row exists but the
profile row does not, the migration raises
`service profile <id> is missing; restore its original public salt from backup`
and fails closed. Without it, a wiped profile table would silently mint a fresh
salt and orphan every existing wallet. The same immutability and no-truncate
triggers protect this table.

> **Losing the public salt orphans every wallet derived from it.** The salt is
> public, so it needs no confidentiality — and it is irreplaceable, so it needs
> real durability. Every user's wallet is a function of it. There is no
> recovery, no reissue, and no migration path: a lost salt is indistinguishable
> from having deleted every account in the service. It must be in backups, those
> backups must be restore-tested, and a restore must be verified byte-for-byte
> against the `publicSaltHex` your clients have been deriving with. The bootstrap
> guard converts silent loss into a loud failure; it cannot convert loss into
> recovery.

### `<p>_accounts`

`id uuid` (PK, `gen_random_uuid()`), `service_profile_id` (FK to the profile),
`username_normalized`, `display_name`, `email`, `email_verified_at`, `status`,
`created_at`, `updated_at`.

Migration 8 adds `email_reset_enabled boolean NOT NULL DEFAULT false` and
`signed_in_reset_enabled boolean NOT NULL DEFAULT true`, each one `ADD COLUMN
IF NOT EXISTS`: the account's [reset settings](#opt-ins-settings-and-status).

Invariants: `status IN ('active','suspended')`; `username_normalized` is 3–320
characters; `display_name` is 1–120 characters; `email_verified_at` may only be
set when `email` is non-null; `UNIQUE (service_profile_id, username_normalized)`
scopes uniqueness to the service rather than to the database. A partial index on
`(service_profile_id, email) WHERE email IS NOT NULL` supports lookup without
forcing emails to be unique or present.

### `<p>_account_wallets`

`id uuid` (PK), `account_id` (FK, `ON DELETE CASCADE`), `service_profile_id`
(FK), `profile_id`, `codec_id`, `curve`, `application_id`, `network_id`,
`address`, `address_normalized`, `public_key`, `fingerprint`, `is_primary`,
`created_at`.

`codec_id` records which address encoding produced the stored address. It is
written on every registration from `profile.codec.id` and surfaced on the
`IdentityWallet` type. The address is only resolvable if you know how it was
encoded, so a deployment that ever moved between codecs must still be able to
tell, row by row, which one applies — a column, not an assumption.

Invariants: the `<p>_account_wallets_binding` CHECK pins `profile_id`,
`codec_id`, `curve`, `application_id`, and `network_id` to the literals baked in
at migration time, so a wallet from a different derivation namespace *or a
different address encoding* cannot be stored here at all;
`char_length(address) BETWEEN 8 AND 128`; `address_normalized = lower(address)`;
`char_length(public_key) BETWEEN 8 AND 160`; `UNIQUE (service_profile_id,
address_normalized)` means one address enrolls once per service; a partial
unique index on `(account_id) WHERE is_primary` allows exactly one primary
wallet per account without needing a trigger.

Because `codec_id` is inside the binding CHECK, changing a deployment's codec is
not a configuration change: existing rows become unwritable under the new
literal, and the migration's own CHECK rejects the mismatch. That is the
intended outcome — a new codec is a new address convention, which is a new
wallet namespace.

### `<p>_auth_challenges`

`id uuid` (PK), `service_profile_id` (FK), `username_normalized`, `purpose`,
`nonce bytea`, `expires_at`, `consumed_at`, `created_at`.

Invariants: `purpose IN ('registration','login','rotation')`;
`octet_length(nonce) = 32`. `consumed_at` is what makes a challenge single-use;
it is set in the same statement that verifies the signature, so two concurrent
redemptions cannot both succeed.

### `<p>_sessions`

`id uuid` (PK), `account_id` (FK, cascade), `token_hash text UNIQUE`,
`issued_at`, `expires_at`, `last_seen_at`, `revoked_at`, `ip_hash`,
`user_agent_hash`, `client_label` (migration 6).

Invariants: `token_hash ~ '^[0-9a-f]{64}$'` — the column is structurally
incapable of holding a plaintext token. Tokens are 32 CSPRNG bytes rendered as
43 base64url characters, returned once and thereafter recognized only by digest.
`ip_hash` is supplied pre-hashed by the host through the router's
`hashRequestIp` option; the service never receives or stores a raw IP address.
`user_agent_hash` is `SHA-256` of the `User-Agent` header, computed by the
router. With `storeSessionClientHashes: false` new rows store `NULL` in both:
the service never reads them back from a session row, and the rate limits hash
`RequestContext.ipHash` directly, so turning them off changes nothing else. Rows
written before the change keep their hashes until `pruneExpired` removes them.
An unkeyed hash of an IPv4 address can be reversed by enumerating the address
space, so a deployment that does not need the stored hashes should turn them
off. The option does not touch `<p>_rate_limits`: its buckets are derived from
the same `ipHash`, and an operator can reverse them the same way while they are
kept (until `pruneExpired` removes them, 24 hours after their last update). A
host that wants no reversible IP-derived data at rest should key
`hashRequestIp` with a server secret.

`client_label` is a nullable display label, at most 64 characters, under the
`<p>_sessions_client_label` CHECK `client_label IS NULL OR client_label ~
'^[A-Za-z0-9 .()-]{1,64}$'`. Migration 6 adds it with one `ALTER TABLE …
ADD COLUMN IF NOT EXISTS … CONSTRAINT … CHECK` statement, which concurrent
migration runners serialize on the table lock and which skips the column and
its constraint together on a re-run. It lives exactly as long as its row:
`pruneExpired` deletes revoked and expired sessions, and the label with them.

`last_seen_at` is rewritten by every `authenticate`, so no index contains it,
and migration 6 adds none: that keeps the per-request update a HOT update.
`listSessions` filters through `<p>_sessions_account_idx`
(`account_id, expires_at DESC`) and sorts the account's few rows by
`last_seen_at`.

### `<p>_email_verifications`

`id uuid` (PK), `service_profile_id` (FK), `username_normalized`, `email`,
`code_hash`, `attempts`, `expires_at`, `consumed_at`, `created_at`.

Invariants: `code_hash ~ '^[0-9a-f]{64}$'` — codes are stored hashed, like
session tokens, and bound to the verification id; `attempts >= 0`, compared
against `emailVerificationMaxAttempts` to bound guessing.

### `<p>_rate_limits`

`bucket text` (PK), `rule_id`, `count`, `window_start`, `updated_at`. A fixed
window counter keyed by an opaque bucket string, incremented with a single
upsert so behavior is identical on both transports.

### `<p>_audit_events`

`id uuid` (PK), `account_id` (FK, `ON DELETE SET NULL`), `action`,
`metadata jsonb`, `created_at`. Append-only by convention. `action` is 1–64
characters. `metadata` is for operational context such as a challenge purpose or
a revocation reason; it carries operational values (field names, counts, session
and profile ids, purposes, methods and scopes, and for
`email.verification-start` the address's domain), never credential material, a
key, a wallet address or a full email address. A row written by a session's own action, or
by an action that issued a session, names that session in `sessionId`, which is
how `listSecurityEvents` shows its label while the session row exists.
`pruneExpired` deletes this service's `account.*` and `session.*` rows older
than `auditRetentionDays` when that is set ([audit retention](#audit-retention)).
Migration 13 adds `deleted_account_id uuid` and `deleted_service_profile_id
text`, NULL except on the rows `deleteAccount` kept and its `account.deleted`
row ([account deletion](#account-deletion)), a partial index on
`deleted_account_id`, and a `BEFORE UPDATE OF account_id` trigger that fills
`deleted_account_id` when the foreign key's cascade detaches a row. It also
adds the `<p>_delete_account(...)` function that `deleteAccount` calls, which
locks the account before it reads the account's sessions.

### `<p>_account_recovery_keys` (migration 7)

`id uuid` (PK), `account_id` (FK, cascade), `service_profile_id` (FK),
`public_key` (64 lowercase hex), `status` (`active`, `used` or `removed`),
`created_at`, `used_at`, `removed_at`. CHECKs tie `used_at` to `used` and
`removed_at` to `removed`. `UNIQUE (service_profile_id, public_key)` keeps every
key the service has seen, so none is enrolled twice, and the partial unique
index `<p>_account_recovery_keys_active_idx` on `(account_id) WHERE status =
'active'` allows one active key per account. Used and removed keys are kept, so
`<p>_account_recovery_keys_account_idx` on `(account_id, created_at DESC)`
serves `recoveryStatus` and the account-delete cascade without scanning every
key the service has enrolled.

### `<p>_account_recoveries` (migration 7)

`id uuid` (PK), `account_id` (FK, cascade), `recovery_key_id` (FK, cascade),
`token_hash text UNIQUE` (64 lowercase hex), `created_at`, `expires_at`,
`completed_at`, `revoked_at`, `CHECK (expires_at > created_at)`. A live token is
neither completed nor revoked; a **usable** token is live, unexpired, and its
recovery key is `active`. Every method that reads a token applies all of these,
and code that reads this table directly must too: a begin that overlaps a key's
retirement can leave a live row whose key is `removed`
([details](#statements-and-lock-order)). The partial index
`<p>_account_recoveries_live_idx` on `(account_id) WHERE completed_at IS NULL
AND revoked_at IS NULL` is **unique**: two overlapping begins cannot both see
the other's new row to revoke it, so only the index can keep one live token per
account. `<p>_account_recoveries_key_idx` on `(recovery_key_id)` serves a
retired key's tokens and the cascade from a deleted key. `pruneExpired` deletes
a row a day after it expires. Each of migration 7's six statements is one
`CREATE … IF NOT EXISTS` with its constraints inline, safe to re-run and to run
from concurrent runners.

### `<p>_account_resets` (migration 8)

`id uuid` (PK), `account_id` (FK, cascade), `kind` (`email` or `signed-in`),
`code_hash` (64 lowercase hex, or NULL), `attempts`, `session_id` (the
initiating session; no foreign key), `created_at`, `available_at`,
`expires_at`, `completed_at`, `aborted_at`, `reset_generation` (migration 9).
The account also stores `reset_generation`; both default to zero for existing
rows. CHECKs: an `email` row has a code
digest, no session and `available_at = created_at`; a `signed-in` row has a
session; `available_at >= created_at` and `expires_at > available_at`; never
both completed and aborted; `attempts >= 0`. A live reset is neither completed
nor aborted; `aborted_at` also closes a superseded or lapsed one (an email
change, a setting change, a completion, a password sign-in or password change
for a signed-in reset, or the next start). The partial
**unique** index `<p>_account_resets_signed_in_live_idx` on `(account_id)
WHERE kind = 'signed-in' AND completed_at IS NULL AND aborted_at IS NULL`
allows one live signed-in reset per account and serves the login abort and the
status; `<p>_account_resets_account_idx` on `(account_id, created_at DESC)`
serves the closing of an account's live codes and the cascade; and
`<p>_account_resets_expires_idx` on `(expires_at)` serves `pruneExpired`, which
deletes a row a day after it expires. `session_id` has no foreign key on
purpose: `pruneExpired` deletes dead sessions under `SKIP LOCKED`, and a cascade
from them would lock reset rows behind session locks, against the order every
reset statement takes. A reset whose session is gone cannot complete. Each of
migration 8's six statements is one `ADD COLUMN IF NOT EXISTS` or `CREATE …
IF NOT EXISTS` with its constraints inline, safe to re-run and to run from
concurrent runners. Migration 9 adds its two columns with
`ADD COLUMN IF NOT EXISTS`.

### `<p>_second_factor_tickets` (migration 12)

`id uuid` (PK; the `ticketId` passed to `verify`), `account_id` (FK, cascade),
`ticket_hash` (64 lowercase hex, UNIQUE), `challenge_id` (UNIQUE; no foreign
key, since `pruneExpired` deletes challenges first), `public_key` (the bound
enrolled key), `purpose` (`login`, `email-reset` or `recovery`), `attempts`
(0 to 5), `ip_hash`, `user_agent_hash`, `client_label` (what the session will
store, under the same rules as `<p>_sessions`), `created_at`, `expires_at`
(after `created_at`), `consumed_at`. Indexes on `(account_id)` and
`(expires_at)`; `pruneExpired` deletes a row a day after it expires. Each
statement is one `CREATE … IF NOT EXISTS` with its constraints inline.

### There is no salt adoption

Every deployment's salt is minted by the database on its first `migrate()`
(`gen_random_bytes(32)`) and is immutable from then on. There is no supported
way to supply a salt, and none to rotate one: a different salt is a different
wallet namespace, which is indistinguishable from deleting every wallet in it.

The `adoptPublicSaltHex` option that earlier versions accepted was removed in
v0.9.0. A configuration that still carries it is refused with
`invalid-service-profile` before any SQL runs, rather than ignored, because
ignoring it would mint a fresh salt for a caller that expected to keep an old
one. A deployment whose wallets already depend on a salt must keep the database
that holds it, and must back that database up and restore-test it.

`test/server/platformSalt.integration.test.ts` covers minting, idempotent
re-runs, immutability, concurrent first provisioning, and the refusal of the
removed option against a real PostgreSQL.

## Deployment

### Configuration

The config surface is:

```ts
type IdentityServiceConfig = {
  serviceProfileId: string;
  profile: DerivationProfile;   // the object, imported from a chain package
  applicationId: string;
  networkId: string;
  tablePrefix?: string;
  sessionTtlSeconds?: number;
  challengeTtlSeconds?: number;
  emailVerificationTtlSeconds?: number;
  emailVerificationMaxAttempts?: number;
  emailVerificationCodeFormat?: "symbols8" | "digits6";
  requireVerifiedEmail?: boolean;
  storeSessionClientHashes?: boolean;
  walletMode?: "service-deterministic" | "per-account-deterministic" | "random-vault";
  accountSecurity?: {
    signInKeyRotation?: boolean;
    recoveryKeys?: boolean;
    emailReset?: boolean;
    signedInReset?: boolean;
  };
  onSecurityEvent?: (event: SecurityEventNotice) => void | Promise<void>;
  auditRetentionDays?: number;
};

// IdentityServiceConfig plus the second sign-in factor; createIdentityService
// (and the adapters) given one return an IdentityService<true>.
type SecondFactorIdentityServiceConfig = Omit<IdentityServiceConfig, "secondFactor"> & {
  secondFactor: {
    required(accountId: string, context: SecondFactorContext): Promise<boolean>;
    verify(accountId: string, ticketId: string, code: string): Promise<"ok" | "invalid" | "locked">;
  };
};
```

`profile` is the profile **object**, not an id string. There is no registry to
resolve an id against, which is deliberate: the profile's KDF parameters,
algorithm label, domain strings, and codec all arrive as one reviewed unit that
a config value cannot partially override.

Pin `serviceProfileId`, `profile`, `applicationId`, and `networkId` in source,
not in environment variables. Changing any of them is a wallet migration, not a
config tweak, and a value that can be changed by editing a dashboard field will
eventually be changed by editing a dashboard field. The database CHECK
constraints reject the drift either way, but source-pinning turns that into a
failed code review rather than a failed production deploy.

| variable | required | notes |
| --- | --- | --- |
| `DATABASE_URL` | yes | PostgreSQL connection string |

Tunables and defaults, all range-checked by `resolveIdentityServiceConfig`,
which throws `invalid-service-profile` rather than silently clamping:

| option | default |
| --- | --- |
| `tablePrefix` | `w2sc` |
| `sessionTtlSeconds` | 1209600 (14 days) |
| `challengeTtlSeconds` | 300 |
| `emailVerificationTtlSeconds` | 900 |
| `emailVerificationMaxAttempts` | 5 |
| `emailVerificationCodeFormat` | `symbols8` (8 symbols, `ABCD-2345`); `digits6` is 6 digits (`123 456`); anything else is refused. Absent from the resolved config unless set. Account reset codes are unaffected ([`POST /email-verifications/confirm`](#post-email-verificationsconfirm)) |
| `requireVerifiedEmail` | `false` |
| `storeSessionClientHashes` | `true`; `false` writes `NULL` to a new session's `ip_hash` and `user_agent_hash` ([`<p>_sessions`](#p_sessions)); a value that is not a boolean is refused |
| `accountSecurity` | `{ signInKeyRotation: false, recoveryKeys: false, emailReset: false, signedInReset: false }`; each a strict boolean, an unknown key refused ([account changes](#account-changes-and-recovery-keys-opt-in), [account resets](#account-resets-opt-in)) |
| `onSecurityEvent` | none; a function, awaited for at most 3 s after a change commits ([the hook](#the-security-event-hook)) |
| `auditRetentionDays` | none (audit rows are kept); an integer from 1 to 36,500 ([audit retention](#audit-retention)) |
| `secondFactor` | none; exactly `{ required, verify }`, both functions, any other shape refused ([second sign-in factor](#second-sign-in-factor-opt-in)) |

### Vercel + Neon

```ts
// app/api/identity/[...path]/route.ts
import { neon } from "@neondatabase/serverless";
import { kalvoraEd25519ExternalSalt } from "web2-ish-self-custody/chains/kalvora";
import {
  createIdentityRouter,
  createNeonIdentityService,
} from "web2-ish-self-custody/server";

const service = createNeonIdentityService({
  neon,
  connectionString: process.env.DATABASE_URL!,
  config: {
    serviceProfileId: "example-app-password-wallet-v1",
    profile: kalvoraEd25519ExternalSalt,
    applicationId: "example-app",
    networkId: "kalvora-mainnet",
  },
});

const handler = createIdentityRouter(service, {
  basePath: "/api/identity",
  trustedOrigins: ["https://app.example.com"],
});

export { handler as GET, handler as POST, handler as PATCH, handler as DELETE };
```

`neon` is passed in, not imported by the SDK. That is what keeps
`@neondatabase/serverless` out of this package's dependencies.

**Migrations.** Do not call `migrate()` on every cold start. It is safe to — the
runner skips applied versions — but it adds round trips to user-facing requests
and, worse, makes salt provisioning a side effect of traffic. Run it from a
one-off script or a deploy step, and treat its first successful run against a
new database as the moment the salt came into existence.

**Migration 9 cutover.** Do not run old and new SDK workers together. An old
worker ignores `reset_generation`; migration 9 alone cannot stop its login or
reset-completion statements from bypassing the cancellation fence. On a
platform with no live accounts or data, stop identity traffic and drain all
old workers, run `migrate()` with the new SDK against the configured database,
then start only new workers and reopen traffic. If draining cannot be
confirmed, keep identity routes closed; do not use a rolling cutover. Verify
that `<p>_schema_migrations` records version 9 before reopening. The new
SDK's login and reset SQL requires the migration 9 columns and fails before
issuing a session or reset when they are absent. Preserve the existing `.env`
file and credentials throughout; a disposable database does not make them
disposable.

**pgcrypto.** Migration 1 issues `CREATE EXTENSION IF NOT EXISTS pgcrypto` and
depends on `gen_random_bytes` and `gen_random_uuid`. Neon permits this. On a
managed PostgreSQL that restricts extension creation, have a superuser install
pgcrypto first.

**Connection pooling.** The Neon HTTP driver is stateless: each `query()` is one
HTTPS request, with no persistent connection, no session state, and no
interactive transactions. Consequences an operator must respect:

- Use the **pooled** connection string (the `-pooler` host) so Neon's PgBouncer
  manages backend connections. Serverless functions have no long-lived pool of
  their own to size.
- Never depend on session state across queries: no `SET`, no session GUCs, no
  temporary tables, no advisory locks held between statements. Nothing in this
  module does, and nothing added to it may.
- Latency is per statement. This is the second reason multi-step mutations are
  expressed as one CTE statement: correctness without transactions, and one
  round trip instead of several.

### Self-hosted

```ts
import { createServer } from "node:http";
import { Pool } from "pg";
import { kalvoraEd25519ExternalSalt } from "web2-ish-self-custody/chains/kalvora";
import {
  createIdentityRouter,
  createPgIdentityService,
  nodeRequestListener,
} from "web2-ish-self-custody/server";

const service = createPgIdentityService({
  pool: new Pool({ connectionString: process.env.DATABASE_URL, max: 10 }),
  config: {
    serviceProfileId: "example-app-password-wallet-v1",
    profile: kalvoraEd25519ExternalSalt,
    applicationId: "example-app",
    networkId: "kalvora-mainnet",
  },
});

const handler = createIdentityRouter(service, {
  basePath: "/api/identity",
  trustedOrigins: ["https://app.example.com"],
});

createServer(nodeRequestListener(handler)).listen(8080);
```

`nodeRequestListener` wraps the **same** Fetch handler; it does not take the
service. It types Node's request and response structurally rather than importing
them, so the module compiles in a DOM-only build and this package needs no
`@types/node`.

**No application code changes between the two deployments.** Same service, same
SQL, same statements, same schema, same wire format. Only the driver and the
HTTP bridge differ, and both are injected. That is the entire point of the
`SqlDriver` seam: every statement is positionally parameterized so the text runs
unchanged on both, and no mutation depends on an interactive transaction even
though `pg` would happily provide one. Adding a `BEGIN`/`COMMIT` block to gain
atomicity on the self-hosted path would silently break the Vercel path — the
prohibition is load-bearing, not stylistic.

Behind a reverse proxy the listener trusts `X-Forwarded-Proto` when present to
reconstruct the request URL, so terminate TLS at a proxy you control and strip
that header from client input.

Other self-hosted notes: size the pool to your CPU count rather than to request
concurrency; set a `statement_timeout`; schedule `pruneExpired()` on a timer;
and back up `<p>_service_profiles` as if the business depends on it, because it
does.

Neither `@neondatabase/serverless` nor `pg` is a dependency of this package.
Both adapters accept an already-constructed, structurally-typed client
(`NeonQueryable` / `PgQueryable`), so the SDK never pins a driver version on a
consumer and nothing imports a driver at module scope.

### Gated integration test

`npm run test:server:integration` runs the service against a real PostgreSQL. It
is gated on a database URL environment variable and skips without one, so CI
stays offline by default. The other suites under `test/server/*.integration.test.ts`
use the same gate; `sessions.integration.test.ts` covers migration 6 (re-run and
concurrent runners), the client label and hashes, listing and revocation, and
the session routes, `accountChanges.integration.test.ts` covers migration 7,
every account change, the status and mode rules, the rate limits, the hook, and
the lock order against concurrent revocations, and
`accountResets.integration.test.ts` covers migration 8, the settings, the
uniform start answer, both resets, the login and password-change aborts,
reauthentication, the email-change interlock, the setting race and the lock
order against revocations and rotations. `pg` and `@types/pg` are devDependencies only; moving
either into `dependencies` would defeat the injected-client design.

## Threat notes

### Anti-enumeration

`POST /challenges` issues a challenge for usernames that do not exist. The
response is shaped like the real thing, so it is not an existence oracle.

Three service codes are enumeration-sensitive and are collapsed by the router
into one indistinguishable response — `401` with code `invalid-signature` and
the message `Authentication failed.`:

- `account-not-found` — the username has no account
- `invalid-signature` — the signature did not verify
- `wallet-mismatch` — the key is not enrolled for this account

`enumerationSensitiveCodes` is the exported set the router consults; route code
must never hardcode the list. The account changes and resets add no code to it:
every recovery or emailed-reset failure an unauthenticated caller can cause is
`invalid-signature`, `key-unchanged` and `stale-key` need a session, a recovery
token or an emailed code, and the reset codes need a session.
`startAccountReset` answers every username alike
([account recovery by email](#account-recovery-by-email)). The service-level codes stay distinct for logging,
which is where the distinction is actually useful.

Registration cannot hide existence: `account-exists` is a real `409`, because a
caller who just tried to register a name learns it is taken either way.

### Rate limits

`<p>_rate_limits` backs fixed-window counters keyed by an opaque bucket string.
Challenge creation, login, registration, and email verification use separate
rules; a shared bucket would let cheap requests exhaust the budget for expensive
ones. Challenge, registration, and login buckets combine the rule, normalized
username, and caller's **hashed** IP so requests from one source cannot exhaust
another source's username budget. The opaque stored bucket is itself hashed, so
neither the username nor the supplied IP hash is persisted in the clear. Never
pass a raw IP: supply a hash through the router's `hashRequestIp` option, which
receives the `Request` and returns a string the host has already hashed. If the
host omits that context, these credential routes intentionally share a
conservative missing-IP bucket rather than falling back to a global
username-only bucket.

A fixed window is not a token bucket: a burst straddling a window boundary can
deliver up to two windows' worth of requests. Size the window accordingly, and
do not treat this table as a substitute for an edge rate limiter or DDoS
protection. It exists to bound credential guessing, not traffic.

Account changes and recovery begins have rules of their own
([account-change rate limits](#account-change-rate-limits)): `account-change`, 10 per
300 s per hashed IP and account; `recovery-begin`, 5 per hour per hashed IP and
username; and `recovery-begin-ip`, 20 per hour per hashed IP. Starting an
account recovery by email is bounded per username whoever asks (3 per hour, 10
per day) and per hashed IP (20 per hour), and by a recipient bound of its own
([reset rate limits](#reset-rate-limits)).

With the [second sign-in factor](#second-sign-in-factor-opt-in), each ticket
allows 5 codes, and `login-account` counts, per account whatever the ticket or
the IP, every code submitted to the factor, giving the unit back on `"ok"` or
`"locked"`. At 25 wrong codes in an hour every submission on every outstanding
ticket of the account is refused (`rate-limited`, rule `login-account`), as is
a login or recovery that needs the factor, so a holder of the password gets at
most 25 wrong guesses at the factor per hour, however many tickets it starts
or abandons. It locks the owner out for that hour too; the host's own
`"locked"` can be stricter.

Starting an email verification is bounded three ways, each per hour: 5 per
normalized username and address pair, 8 per recipient address whatever the
username, and 20 per hashed IP. The recipient bound is what stops one caller
rotating usernames at a single inbox. The per-IP bound applies only when the
host supplies `hashRequestIp`; without it every caller would share one bucket
and throttle the whole deployment.

Email verification carries a further, independent bound: `attempts` on each
verification row, compared against `emailVerificationMaxAttempts` (default 5).
An 8-character code from a 32-symbol alphabet is roughly 40 bits, but the
attempt bound is what makes a *specific* code unguessable within its 15-minute
lifetime. Its digest could be searched offline from a database read, which
yields only the confirmation of an address. An account reset code replaces the
enrolled key, so it is 16 symbols (80 bits) instead
([account recovery by email](#account-recovery-by-email)).

Wrong codes are also bounded per day, in both formats, by two rules counted
only by confirmation: `email-verification-account-failures`, 20 per 24 hours
per normalized username, and `email-verification-recipient-failures`, 20 per
24 hours per recipient address, each across every verification and caller.
Each comparison reserves a unit in both before the digests are compared and a
match gives them back, so only wrong codes stay counted and a burst of parallel
guesses cannot overshoot. A full bucket refuses every confirmation and every
new start for its username or address (`rate-limited`) until its window
passes; the starts only read the buckets. The address bucket exists because a
verification may precede registration, so its username is the caller's to
choose: per username alone, rotating usernames at one address would allow 8
starts an hour × 5 attempts, 960 guesses a day.

With `emailVerificationCodeFormat: "digits6"` a code is 6 digits, about 20
bits, and these budgets are what keep it unguessable online: at most 5 guesses
in 10^6 against one code (5 × 10^-6), and at most 20 wrong guesses a day per
username and per address, so a guesser's chance of confirming an address it
does not read is at most about 20 / 10^6 = 2 × 10^-5 a day per target. The
budgets need no credential to spend, so whoever spends one also denies email
verification to that username or address for the day. That adds little:
whoever can name an address could already deny it by spending its 8 starts
every hour, and whoever can name a username by superseding its open code with
a new start. A database read yields any
`digits6` code from its digest at once (10^6 SHA-256 evaluations), as it
yields a `symbols8` code within minutes: either confirms only that an address
received mail, and never replaces a key.

### Challenge replay protection

Five properties, four of them enforced in the database rather than in
application logic:

1. **Single use.** `consumed_at` is set in the same statement that verifies the
   signature. Two concurrent redemptions cannot both win.
2. **Expiry.** `expires_at`, default 300 seconds, is both a column and a field
   inside the signed message — so a client that validates the message detects a
   stale challenge before signing, and the server rejects it after.
3. **Purpose binding.** `purpose` is inside the signed bytes. A registration
   signature cannot be replayed as a login.
4. **Namespace binding.** `serviceProfileId`, `applicationId`, and `networkId`
   are inside the signed bytes. A signature captured from one service is
   meaningless at another, even for the same wallet.
5. **Protocol binding.** The fixed domain string prevents these signatures from
   being replayed against any other protocol the same key signs for — including
   real transactions on whatever chain the deployment's codec belongs to.

Point 5 has a mirror image that the client owns. `signExactMessageUnsafe` is
named that way because it signs whatever bytes it is handed. A client that signs
a server-supplied `message` without checking it field by field has delegated to
the server the choice of what its wallet attests to. Validate, then sign.

### CSRF and CORS

In **bearer mode** there is nothing to forge: the token travels in an
`Authorization` header, which browsers never attach automatically.

In **cookie mode** the cookie is ambient, so the router provides an origin gate.
Set `trustedOrigins` to your exact browser origins and every unsafe request
(`POST`, `PUT`, `PATCH`, `DELETE`) that relies on the cookie must present a
matching `Origin`, or it fails `403 forbidden-origin`. Requests carrying an
explicit `Authorization` header are exempt, because only ambient credentials are
forgeable.

**Leaving `trustedOrigins` unset disables the check.** That is only safe for a
deployment with no browser clients. Any deployment serving a browser in cookie
mode must set it. `SameSite=Lax` on the cookie is defense in depth behind that
gate, not a replacement for it — it does not cover top-level cross-site `GET`
navigations, and it is a browser-side control the server cannot verify.

The router sets **no CORS headers** and answers no `OPTIONS` preflight. A
deployment needing cross-origin access must add an explicit, narrow allowlist in
front of the handler — never reflect `Origin` back, which would nullify the
origin gate above.

Two cookie details worth stating plainly: `Secure` is always set, so cookie mode
does not work over plain HTTP even in development; and the `__Host-` prefix
means the cookie cannot be scoped to a parent domain, which is a deliberate
limitation, not an oversight.

### What an operator with database access can and cannot do

**Can:** read every username, display name, email, verification state, enrolled
address, public key and fingerprint (a wallet's only under a chain wallet
profile), and the public salt (per account in `per-account-deterministic`
mode); in `random-vault` mode, every account's encrypted vault and its
revisions; read hashed session
tokens, hashed IPs and hashed user agents on session rows (where
`storeSessionClientHashes` is on), rate-limit buckets derived from the
caller-supplied IP hash (kept until `pruneExpired` removes them, 24 hours after
their last update), session client labels, and audit rows; suspend accounts; delete
sessions; and — with write access — enroll an attacker-controlled public key
against an existing account, or plant an attacker-controlled recovery key and
recover the account with it. Those are the real insider risk in this design and
deserve the same monitoring as any other privileged write. Alert on any INSERT
into `<p>_account_wallets`, any UPDATE of its `public_key` or `address`, and any
INSERT or `status` change in `<p>_account_recovery_keys`, when no audit row of
`account.register`, `account.key-rotate`, `account.recover`,
`account.email-reset`, `account.signed-in-reset` or `account.recovery-key.*`
for the same account carries the same `created_at` (each statement writes its
audit row with its own clock). With account resets, an operator with write
access can also turn an account's account recovery by email on or point its
verified email at another inbox, then complete a reset with a code it reads
from its own row; alert on a change of `email_reset_enabled` or
`signed_in_reset_enabled` without an `account.reset-setting` (or
`account.email-change` / `account.update`) audit row at the same time, and on
any INSERT into `<p>_account_resets` of kind `email` without an
`account.email-reset.start` row.

**Cannot:** recover, derive, reconstruct, decrypt, or sign with any user's
enrolled key or wallet without that user's password or, in `random-vault` mode,
recovery code. No material capable of producing one without them is present, and
no amount of database access creates it. Under the sign-in profile the database
does not even say which wallet a user has. Nor can they mint a usable session token from the
stored hashes, read a plaintext email verification code, or, from a read alone,
recover a live account reset code: it is 80 bits, and only its SHA-256 is
stored, which cannot be searched within the code's 15 minutes.

Their remaining path to a specific wallet is an offline guessing attack. In the
deterministic modes it is the one every holder of a public address already has;
under the sign-in profile the oracle is the enrolled sign-in public key. In
`random-vault` mode the oracle is the stored vault, which is not public
otherwise. It is bounded by password entropy and
scrypt cost — the two things a server can neither improve nor weaken.
