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
Deterministic password changes, key reassignment, and account recovery are the
integrating platform's responsibility; this service provides no such workflow.
`/profile` reports `walletMode`; in either new mode use `/challenges`'s
`walletSetup`, not the service salt, to create the wallet.

It is chain-agnostic. The deployment hands it a `DerivationProfile` object, and
every address and public-key operation runs through that profile's
`IdentityCodec` — there is no encoding convention hardcoded anywhere in this
module. The examples below use Kalvora because that is the chain that ships in the
box, not because the service knows what Kalvora is.

`src/server/contract.ts` is the authoritative TypeScript surface and
`src/server/router.ts` the authoritative wire behavior. This document describes
both.

## Custody model

### What the server holds

- the per-service 32-byte public salt and the pinned scrypt parameters
- normalized usernames, display names, optional emails and verification state
- public wallet material: address, encoded public key, codec id, fingerprint
- single-use challenge nonces with their expiry and consumption state
- SHA-256 hashes of session tokens and of email verification codes
- a SHA-256 hash of the user agent, and a caller-computed IP hash
- append-only audit rows
- immutable account UUID/salt setup and wallet policy (migration 5)
- encrypted vaults and revisions, only when `walletMode` is `random-vault`

### What the server never holds

- a plaintext wallet password or recovery code
- a wallet seed, private key, or secret scalar
Vault mode accepts encrypted wallet material, never a plaintext key. Vault
ciphertext can verify password guesses offline and must be access-controlled.
The discussion below about public-only storage describes deterministic modes.

### Why a stolen database yields no wallet

A wallet is `scrypt(entropy, publicSalt, N, r, p, dkLen)`, where `entropy` is a
domain-separated SHA-512 transcript over the normalized username and the user's
password bytes. The database holds the salt and the parameters. It does not hold
the password, and the password is the only high-entropy input.

An attacker with a full dump therefore has exactly what any holder of a public
identity already has: the ability to run an offline guessing attack against a
known public key. Stealing the database does not improve that attack, because
the salt is not a secret and was already published to every client that ever
derived.

The corollary is the uncomfortable one and must not be softened: a weak password
is recoverable by anyone who learns a public address, and this module cannot
detect or prevent that. Deterministic password-derived custody is not equivalent
to a random wallet seed. See [the security model](SECURITY_MODEL.md).

### Serviceable profiles

Serviceability is a **policy**, not a list of blessed ids. A profile is
serviceable when both of the following hold, and
`resolveIdentityServiceConfig` checks both at construction:

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

Nothing else is required. Any chain that satisfies those two conditions can be
served by this module without a change to it.

The profile the deployment supplies is the single source of the curve, the
algorithm label, the KDF parameters, and the codec. Migration 1 bakes
`profile.id`, `profile.algorithm`, `profile.curve`, and every KDF value into the
CHECK constraint on `<p>_service_profiles`; migration 2 bakes `profile.id` and
`profile.codec.id` into the binding CHECK on `<p>_account_wallets`. A deployment
whose configuration has drifted from its database cannot write a row at all.

The bundled Kalvora profile, which satisfies the policy:

| `profileId` | codec | curve | algorithm | scrypt |
| --- | --- | --- | --- | --- |
| `web2ish-kalvora-ed25519-external-salt-v1` | `kalvora-ed25519-base58-v1` | ed25519 | `scrypt-sha512-slip10-ed25519-external-32-v1` | N=65536, r=8, p=1, dkLen=32 |

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

Errors: `challenge-not-found` (404), `challenge-expired` (410),
`challenge-consumed` (409), `rate-limited` (429), and the collapsed
authentication failure described in [anti-enumeration](#anti-enumeration).

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

Errors: `invalid-username`, `invalid-email` (400); `rate-limited` (429);
`email-delivery-failed` (502) when the provider refused or could not be
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
  entirely. `input` carries `code`, `formattedCode` (`ABCD-2345`; confirm
  accepts either form), `email`, `expiresAt`, and `expiresInMinutes`.
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

Codes are 8 characters from a 32-symbol alphabet that omits `O`/`0` and `I`/`1`,
so a code read aloud or off a screen is unambiguous. They are stored only as a
SHA-256 digest bound to the domain string, the service profile, and the
verification id — so a code minted for one verification cannot validate against
another that happened to draw the same characters — and compared in constant
time.

Errors: `email-verification-failed` (400), also returned once the attempt budget
is spent; `email-verification-expired` (410); `rate-limited` (429).

### Not exposed over HTTP

Three `IdentityService` methods have no route, deliberately. Call them from code
that already holds operator trust:

| method | why it is not routed |
| --- | --- |
| `revokeAllSessions(accountId)` | takes an account id rather than a token; expose it behind your own authorization if you want a "sign out everywhere" control |
| `pruneExpired()` | maintenance; run it on a schedule (Vercel Cron, systemd timer, job runner) |
| `migrate()` | provisions the salt on first run; belongs to a deploy step, not to traffic |

```ts
const removed = await service.pruneExpired();
// { challenges, sessions, emailVerifications, rateLimits }
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
| `rate-limited` | 429 |
| `service-profile-missing` | 503 |
| `session-expired` | 401 |
| `session-not-found` | 401 |
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
`user_agent_hash`.

Invariants: `token_hash ~ '^[0-9a-f]{64}$'` — the column is structurally
incapable of holding a plaintext token. Tokens are 32 CSPRNG bytes rendered as
43 base64url characters, returned once and thereafter recognized only by digest.
`ip_hash` is supplied pre-hashed by the host through the router's
`hashRequestIp` option; the service never receives or stores a raw IP address.
`user_agent_hash` is `SHA-256` of the `User-Agent` header, computed by the
router.

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
a revocation reason; it must never carry credential material.

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
  requireVerifiedEmail?: boolean;
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
| `requireVerifiedEmail` | `false` |

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
stays offline by default. `pg` and `@types/pg` are devDependencies only; moving
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
must never hardcode the list. The service-level codes stay distinct for logging,
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
lifetime.

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

**Can:** read every username, display name, email, verification state, wallet
address, public key, fingerprint, and the public salt; read hashed session
tokens, hashed IPs, hashed user agents, and audit rows; suspend accounts; delete
sessions; and — with write access — enroll an attacker-controlled public key
against an existing account. That last one is the real insider risk in this
design and deserves the same monitoring as any other privileged write. Alert on
inserts into `<p>_account_wallets`.

**Cannot:** recover, derive, reconstruct, decrypt, or sign with any user's
wallet. No material capable of producing one is present, and no amount of
database access creates it. Nor can they mint a usable session token from the
stored hashes, or read a plaintext email verification code.

Their remaining path to a specific wallet is the offline guessing attack that
every holder of a public address already has. It is bounded by password entropy
and scrypt cost — the two things a server can neither improve nor weaken.
