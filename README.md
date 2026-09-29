# web2-ish-self-custody

**Sign in with a username and password. Hold your own keys.**
Deterministic Ed25519 wallets derived in the browser, plus a portable identity
service that never holds a secret.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#versioning-and-releases)
[![Node >= 22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](package.json)

> **Security warning:** anyone who knows a public identity and its public salt can test password guesses offline. Deterministic password-derived custody is not equivalent to a randomly generated wallet seed. Use only high-entropy, password-manager-generated credentials and complete an independent security review before funded use.

> **Alpha pre-release (`0.10.0-alpha.x`).** The bundled Kalvora chain is provided by the kalvora.js SDK, pinned at `0.0.1-alpha.0`. The Kalvora chain surface (its exports, profile, and vectors) may change between alpha releases. The package has not received an independent cryptographic audit; complete an independent security review before funded use.

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [The model](#the-model)
- [Install](#install)
- [Quick start](#quick-start)
- [Wallet vault and recovery code](#wallet-vault-and-recovery-code)
- [Random-seed identity](#random-seed-identity)
- [Identity server](#identity-server)
- [Adding a chain](#adding-a-chain)
- [API surface](#api-surface)
- [Immutable profiles and codecs](#immutable-profiles-and-codecs)
- [Security model](#security-model)
- [What it does not do](#what-it-does-not-do)
- [Used by](#used-by)
- [Migrating from v0.9.x](#migrating-from-v09x)
- [Development](#development)
- [Versioning and releases](#versioning-and-releases)
- [License](#license)

## Why

People know how to sign in with a username and a password. Self-custody usually
asks them to do something else entirely: write down a seed phrase, install an
extension, or trust a custodian with their keys.

This package keeps the web2 experience and drops the custodian. The same
username and password recreate the same Ed25519 signing identity on any device,
inside the browser, every time:

- **No stored secrets.** There is no seed, private key, password, password hash,
  or encrypted key blob on any server. The wallet exists only while a callback
  runs.
- **No custodian.** The identity service holds only public material: a public
  salt, public keys, addresses, and session hashes. A full database dump does
  not yield a wallet.
- **One implementation.** Products that adopt it share one versioned,
  vector-tested implementation instead of each maintaining its own
  cryptographic copy.

The package has two halves:

- a **generic Ed25519 deterministic-custody core** that recreates a signing
  identity from a username and password without storing any wallet secret, and
- a **portable identity service** (`web2-ish-self-custody/server`) that owns the
  public salt such a derivation needs, verifies signatures over single-use
  challenges, and issues sessions.

The core knows nothing about any blockchain; a chain plugs into it. **Kalvora**
is the bundled chain, at `web2-ish-self-custody/chains/kalvora`. It is provided
by [kalvora.js](https://github.com/IntoTheDerk/kalvora.js), the Kalvora SDK: a
password wallet here is exactly the wallet kalvora.js derives from the same
seed, via standard SLIP-0010 at SLIP-44 coin type 5258. See
[Kalvora and kalvora.js](docs/INTEGRATION.md#kalvora-and-kalvorajs).

## How it works

A derivation is a fixed transcript. For the bundled Kalvora profile
(`web2ish-kalvora-ed25519-external-salt-v1`):

```text
  username ─────────► 1. normalize        ASCII trim + ASCII lowercase, 3–120 printable ASCII
                                │
  password bytes ───► 2. password hash    SHA-512( "…password hash v1\n" ‖ password )
                                │
  applicationId ────┐           ▼
  networkId ────────┴► 3. entropy          SHA-512( domain \n app \n network \n username \n hex(hash) )
                                │
  service's public ─► 4. scrypt           N=65536, r=8, p=1, dkLen=32  →  32-byte master seed
  32-byte salt                  │
                                ▼
                      5. key derivation   SLIP-0010 Ed25519 at m/44'/5258'/0'/0'/0'  (kalvora.js)
                                │
                                ▼
                      6. Ed25519 identity RFC 8032 public key from the 32-byte key
                                │
                                ▼
                      7. codec            address = base58(publicKey), identifier = "A_" ‖ address
```

1. **Normalize the username.** ASCII whitespace is trimmed and ASCII letters are
   lowercased (deliberately locale-independent). The result must be 3–120
   printable ASCII characters.
2. **Hash the password.** `SHA-512(utf8(passwordHashDomain) ‖ passwordBytes)`.
   The password is never normalized, and must be at least 10 Unicode code points
   and at most 1,024 UTF-8 bytes.
3. **Bind the context.** `SHA-512` over five newline-joined lines: the entropy
   domain, `applicationId`, `networkId`, the normalized username, and the
   password hash as lowercase hex. Two applications with the same credentials
   get different wallets.
4. **Stretch with scrypt**, using the 64-byte entropy as the scrypt password and
   the service's public 32-byte salt as the scrypt salt. The profile's KDF floor
   is enforced at definition time.
5. **Derive the chain key.** The profile's `keyDerivation` step turns the scrypt
   output into the wallet key. For Kalvora this is kalvora.js's SLIP-0010 at
   `m/44'/5258'/0'/0'/0'`, so coin type 5258 is part of every key.
6. **Compute the Ed25519 identity** from that 32-byte key.
7. **Encode it** through the profile's `IdentityCodec`: for Kalvora, the
   address is the base58 of the raw public key and the wire identifier is that
   address behind an `A_` tag.

Every intermediate buffer the package owns (password copy, hashes, salt copy,
scrypt output, key) is zeroed when the derivation finishes. The full byte-level
specification, including a committed test vector, is in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## The model

Four pieces, in order of how much they know:

| piece | what it is | who owns it |
| --- | --- | --- |
| **core** | username/password → 32-byte Ed25519 key → public identity, inside a callback scope | this package |
| **`IdentityCodec`** | how a 32-byte public key becomes an address and a wire identifier, and how that identifier decodes back | a chain |
| **`DerivationProfile`** | one immutable derivation transcript: curve, KDF parameters, salt policy, domain-separation strings, an optional key-derivation step, and the codec to encode with | a chain |
| **`KeyDerivation`** | an optional `{ id, deriveKey(masterSeed) }` step from the 32-byte scrypt output to the 32-byte wallet key, such as HD derivation at the chain's path | a chain |

Nothing in the derivation path or in the identity service contains the words
base58, bech32, or hex. Those live in a codec. Adding a chain is a new codec and
a new profile; it is never a patch to the core.

A profile is a protocol, not configuration. Its domain strings and KDF
parameters are part of the definition of every wallet derived under it, so a
change to any of them is a new profile id, never an edit. See
[the protocol](docs/PROTOCOL.md).

What the core guarantees:

- Derives a wallet only inside a callback scope, and zeroes the key on exit.
- Exposes the public identity and an exact-message signer, never a private-key
  export.
- Clears package-owned password, entropy, salt, and seed buffers on completion.
- Validates a profile at definition time, including a hard KDF floor, and a
  codec at definition time; the identity service round-trips the codec at
  startup.
- Ships stable test vectors and an independent Python reproduction of them.
- Uses no network, filesystem, storage, telemetry, or Node-only runtime APIs on
  the client path.

## Install

The package is not published to npm. Depend on an immutable, reviewed Git
commit — the form every current consumer uses:

```json
{
  "dependencies": {
    "web2-ish-self-custody": "git+https://github.com/IntoTheDerk/web2-ish-self-custody.git#<reviewed-commit-sha>"
  }
}
```

Pin a full 40-character commit SHA rather than a branch or a tag name. The
package builds itself through its `prepare` script during the Git install.
Node 22 or later is required.

To use the Kalvora chain, also install
[kalvora.js](https://github.com/IntoTheDerk/kalvora.js) at the exact version in
this package's `peerDependencies`, currently `0.0.1-alpha.0`:

```json
{
  "dependencies": {
    "web2-ish-self-custody": "git+https://github.com/IntoTheDerk/web2-ish-self-custody.git#<reviewed-commit-sha>",
    "kalvora.js": "0.0.1-alpha.0"
  }
}
```

kalvora.js is an **optional** peer dependency: only
`web2-ish-self-custody/chains/kalvora` imports it (its `kalvora.js/wallet`
entry, which has no network or protobuf code). The core, the vault, and the
server do not need it.

| entry point | contents |
| --- | --- |
| `web2-ish-self-custody` | the chain-agnostic core and the wallet vault |
| `web2-ish-self-custody/chains/kalvora` | the Kalvora codec, profile, and key derivation (needs kalvora.js) |
| `web2-ish-self-custody/server` | the identity service, router, email delivery, and migrations |
| `web2-ish-self-custody/server/adapters/neon` | `createNeonIdentityService` on its own |
| `web2-ish-self-custody/server/adapters/node` | `createPgIdentityService` and `nodeRequestListener` on their own |

## Quick start

A derivation takes a profile **object**, not a profile id. The core has no
profile registry — the chain package is the registry.

```ts
import { withDerivedWallet } from "web2-ish-self-custody";
import { kalvoraEd25519ExternalSalt } from "web2-ish-self-custody/chains/kalvora";

const password = new TextEncoder().encode(userSuppliedPassword);
try {
  const proof = await withDerivedWallet(
    {
      profile: kalvoraEd25519ExternalSalt,
      username,
      password,
      // Exactly 32 bytes, published by your own service. Public metadata.
      salt: publicSaltFromYourService,
      context: {
        applicationId: "example-app",
        networkId: "kalvora-mainnet",
      },
      // Optional: signal (AbortSignal) and onProgress (0..1) for the scrypt step.
    },
    // Must be synchronous. The signer stops working when it returns.
    (wallet) => ({
      identity: wallet.identity, // address, publicKey, publicKeyBytes, fingerprint, …
      signature: wallet.signExactMessageUnsafe(exactTypedMessageBytes),
    }),
  );
} finally {
  password.fill(0);
}
```

`derivePublicIdentity(credentials)` runs the same derivation and returns only
the public identity, for discovery or enrollment.

The salt is public derivation metadata, not a password or a custody secret. It
must remain byte-for-byte stable for the lifetime of the wallet: losing,
rotating, or returning the wrong service salt derives a different wallet. Pin
the profile in source and validate the salt source rather than accepting KDF
parameters from a server response. Run derivation in a short-lived dedicated
worker; see [Deriving in a client](docs/INTEGRATION.md#deriving-in-a-client).

### The signer is deliberately named unsafe

`signExactMessageUnsafe` signs precisely the bytes it is handed (1 byte to
1 MiB), with no framing or prehashing. It is the primitive needed for exact
on-chain transaction bytes, not permission to sign bytes supplied by a server or
an untrusted renderer. A consuming application must locally reconstruct a typed
intent, show a trusted confirmation, and only then pass the exact verified bytes
to the scoped signer.

## Wallet vault and recovery code

Deterministic derivation alone cannot survive a password change: a new password
is a new wallet, and a forgotten password is a lost one. A wallet vault
(`src/vault.ts`, since v0.5.0) decouples the two by storing the seed encrypted
under two independent wrappers.

```ts
import {
  createWalletVaultFromCredentials,
  openWalletVaultWithPassword,
  parseWalletVault,
  rewrapWalletVaultPassword,
} from "web2-ish-self-custody";
import { kalvoraEd25519Codec, kalvoraEd25519ExternalSalt } from "web2-ish-self-custody/chains/kalvora";

// Enrol the wallet these credentials already derive; its address is preserved.
// vaultPassword is the UTF-8 encoding of at least 10 characters (at most 1,024
// bytes) and may differ from the derivation password.
const { vault, recoveryCode } = await createWalletVaultFromCredentials(
  { profile: kalvoraEd25519ExternalSalt, username, password, salt, context },
  vaultPassword,
);
// Show recoveryCode to the user once so they can write it down. Store `vault`
// (a plain JSON-serializable object) wherever the application keeps it.

// Later: parse what came back from storage, then open it inside a scope.
const signature = await openWalletVaultWithPassword(
  parseWalletVault(storedVault),
  vaultPassword,
  kalvoraEd25519Codec,
  (wallet) => wallet.signExactMessageUnsafe(exactTypedMessageBytes),
);

// Password forgotten: unlock with the recovery code and set a new password.
// The seed, and therefore the address, does not change.
const rotated = await rewrapWalletVaultPassword(
  parseWalletVault(storedVault),
  { recoveryCode },
  newVaultPassword,
  recoveryCode,
);
```

How it works:

- A random 32-byte data key encrypts the seed with AES-256-GCM (WebCrypto).
  The data key is wrapped twice: once under a key stretched from the vault
  password with scrypt at the profile's KDF parameters and a fresh random salt,
  and once under a key derived by HKDF-SHA-256 from the recovery code.
- `generateRecoveryCode()` produces a 256-bit code in a 32-symbol alphabet
  without `I`, `O`, `0`, or `1`, grouped in fours, and is what the create
  functions use by default. The recovery wrapper does no stretching, so a code
  must always come from this function and never be user-chosen; the optional
  `recoveryCode` parameters exist only to re-seal a kit the user already holds.
  `normalizeRecoveryCode` accepts any case and grouping when it is typed back.
- The format, version, profile id, codec id, application id, network id,
  normalized username, address, and public key are authenticated as AES-GCM
  associated data, so a relabelled envelope does not open. On open, the
  decrypted seed is re-derived to its address and compared with the envelope.
- A wrong password, a wrong recovery code, and a tampered envelope all fail with
  the same error code, `vault-authentication-failed`.
- Opening follows the same scope rules as derivation: the callback must be
  synchronous, and the signer stops working when it returns.

The entry points:

| export | purpose |
| --- | --- |
| `createWalletVault({ profile, context, username, password, seed, recoveryCode? })` | seals any 32-byte seed the application already has, such as a random one |
| `createWalletVaultFromCredentials(credentials, vaultPassword, recoveryCode?)` | derives the deterministic seed and seals it without ever returning it |
| `openWalletVaultWithPassword(vault, password, codec, useWallet)` | opens with the password |
| `openWalletVaultWithRecoveryCode(vault, recoveryCode, codec, useWallet)` | opens with the recovery code |
| `rewrapWalletVaultPassword(vault, unlock, newPassword, recoveryCode)` | re-seals the same seed under a new password; `unlock` is `{ password }` or `{ recoveryCode }` |
| `parseWalletVault(value)` | strict structural validation of a stored vault before any key work |
| `generateRecoveryCode()` / `normalizeRecoveryCode(code)` | recovery-code generation and input normalization |

Limits worth stating plainly:

- Losing **both** the vault password and the recovery code loses the wallet.
  There is no server-side reset, by design.
- The vault does not store its recovery code. `rewrapWalletVaultPassword`
  re-seals with whatever code it is given, without checking it against the old
  wrapper, so pass the user's existing code to keep their written-down kit
  valid. Unlocking with `{ recoveryCode }` and passing that same code, as above,
  checks it first.
- Anyone holding a vault can test password guesses against it offline at the
  scrypt cost recorded in the envelope (the profile's cost when the vault was
  created here), much as anyone holding a public address can against a
  deterministic wallet. A strong vault password still matters.
- The vault header (username, address, public key, application, network) is
  readable by whoever stores it. Only the seed and data key are encrypted.
- The package does not persist, transmit, or back up vaults. Storage, access
  control, and delivery of the recovery code to the user are the host's job.

See [Encrypted-vault integrations](docs/INTEGRATION.md#encrypted-vault-integrations).

## Random-seed identity

For wallets that are not password-derived, the package standardizes only the
public-key derivation and address encoding of a seed the application already
owns:

```ts
import { deriveKalvoraEd25519IdentityFromSeed } from "web2-ish-self-custody/chains/kalvora";

const seed = crypto.getRandomValues(new Uint8Array(32));
try {
  const identity = deriveKalvoraEd25519IdentityFromSeed(seed);
  console.log(identity.address, identity.codecId);
} finally {
  seed.fill(0);
}
```

The seed is used as the Ed25519 private key directly, with no SLIP-0010 step.
This entry point does not derive the seed from credentials and does not store,
encrypt, recover, or sign with it. The generic form is
`deriveIdentityFromSeed(seed, codec)`; the Kalvora helper is that function with
`kalvoraEd25519Codec` applied. To encrypt such a seed, seal it in a
[wallet vault](#wallet-vault-and-recovery-code) with `createWalletVault`.

## Identity server

`web2-ish-self-custody/server` is the server half of any `external-32` profile,
and the only stateful part of the package. It takes the same profile object the
client derives with, so addresses are encoded through the client's codec rather
than a convention hardcoded in the server.

| the server holds | the server never holds |
| --- | --- |
| the per-service 32-byte public salt and the pinned scrypt parameters | a password, or any hash, transform, or verifier derived from one |
| normalized usernames, display names, optional emails and verification state | a wallet seed, private key, or secret scalar |
| public wallet material: address, encoded public key, codec id, fingerprint | a ciphertext, encrypted vault, or key-escrow blob |
| single-use challenge nonces, SHA-256 hashes of session tokens and email codes, append-only audit rows | |

There is no password column and no recovery table. A stolen database gives an
attacker exactly what any holder of a public address already has.

### The challenge flow

The client derives; the server verifies. No step reverses that.

```text
client                                                   server
  │ GET  /profile ──────────────────────────────────────► │  publish salt + pinned profile
  │ ◄── pin-check profileId, codecId, kdf, app, network   │
  │ POST /challenges { purpose, username } ─────────────► │  mint single-use 32-byte nonce
  │ ◄── exact message to sign                             │
  │ validate message field by field                       │
  │ derive in a worker, sign the message bytes            │
  │ POST /accounts  (registration) ─────────────────────► │  recompute address from key,
  │ POST /sessions  (login) ────────────────────────────► │  verify signature, consume
  │ ◄── account + session (HttpOnly cookie or bearer)     │  challenge, issue session
```

Only a SHA-256 hash of the session token is stored. Challenges are minted for
unknown usernames too, so the flow does not enumerate accounts. The full
[registration](docs/SERVER_API.md#registration-sequence) and
[login](docs/SERVER_API.md#login-sequence) sequences, the wire format, and the
challenge message format are in [docs/SERVER_API.md](docs/SERVER_API.md).

### Deploying on Vercel with Neon

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

### Self-hosted with Node and `pg`

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

`createIdentityRouter` returns a plain Fetch handler, and `nodeRequestListener`
wraps that same handler, so the two deployments run identical service code, SQL,
and schema. Neither `@neondatabase/serverless` nor `pg` is a dependency of this
package; both adapters take an already-constructed client injected by the host.

Run `service.migrate()` from a deploy step, not from request handling. Its first
successful run against a new database is the moment that service's public salt
comes into existence, and the schema then refuses to change it: the database is
the wallet namespace, so back it up. Schedule `service.pruneExpired()` for
maintenance. Optional config includes `tablePrefix`, session, challenge, and
email-verification TTLs, and `requireVerifiedEmail`.

### Email verification delivery

Since v0.9.1 the router can deliver verification codes itself. Without the
`emailVerification` option, `POST /email-verifications` still mints and stores
a code, but nobody receives it (suitable only for a host that calls
`service.startEmailVerification(...)` and sends the code itself).

```ts
import {
  createEmailSender,
  createIdentityRouter,
} from "web2-ish-self-custody/server";

const handler = createIdentityRouter(service, {
  basePath: "/api/identity",
  trustedOrigins: ["https://app.example.com"],
  emailVerification: {
    sender: createEmailSender({ provider: "resend", apiKey: process.env.RESEND_API_KEY! }),
    from: "Example <verify@example.com>",
    replyTo: "support@example.com", // optional
    theme: { productName: "Example", accentColor: "#2f6fed" },
    onFailure: (failure) => console.warn("verification email not sent", failure),
  },
});
```

| `provider` | factory | credential option |
| --- | --- | --- |
| `resend` | `createResendEmailSender` | `apiKey` |
| `postmark` | `createPostmarkEmailSender` | `serverToken` (and `messageStream`, default `outbound`) |
| `sendgrid` | `createSendGridEmailSender` | `apiKey` |

- Each provider is a single HTTPS `POST` through `fetch` with no added
  dependency; `baseUrl`, `fetch`, and `timeoutMs` (default 10 s) are optional.
  Any object with a `provider` label and a `send(message)` method is an
  `EmailSender`, so another transport plugs in without a change here.
- Style the built-in template with `theme` (`productName` is required), or
  replace it entirely with `render(input) → { subject, text, html }`. A rendered
  message that does not carry the code in both its text and HTML parts is
  refused rather than sent.
- A provider credential is held in a closure, never on the sender object.
  Nothing in the delivery path logs; `onFailure` receives only `provider`,
  `reason`, and HTTP `status`. A failed send answers `email-delivery-failed`
  (502).

See [Email delivery](docs/SERVER_API.md#email-delivery) for every theme field,
and [Rate limits](docs/SERVER_API.md#rate-limits) before exposing the route.

### Serviceable profiles

Serviceability is a policy, not a list: any profile whose `saltPolicy` is
`external-32` and whose codec round-trips can be configured. A profile that
derives its own salt has nothing for a server to own, and the service rejects it
at construction with `invalid-service-profile`.

## Adding a chain

A chain is one file: a codec, one or more profiles, and nothing else. Below is a
complete working example for a hypothetical chain whose address is the
lowercase hex of the public key behind an `0x` tag.

```ts
import {
  DerivationError,
  assertCodecRoundTrip,
  defineDerivationProfile,
  defineIdentityCodec,
  withDerivedWallet,
  type DerivationProfile,
  type IdentityCodec,
} from "web2-ish-self-custody";

const HEX_ADDRESS = /^0x[0-9a-f]{64}$/u;

const toHexAddress = (publicKeyBytes: Uint8Array): string =>
  `0x${Array.from(publicKeyBytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

export const exampleCodec: IdentityCodec = defineIdentityCodec({
  id: "example-ed25519-hex-v1",

  encodeAddress: toHexAddress,
  encodePublicKey: toHexAddress,

  // Must throw on anything malformed. Callers rely on this to reject junk
  // before it reaches signature verification.
  decodePublicKey(identifier) {
    const trimmed = identifier.trim().toLowerCase();
    if (!HEX_ADDRESS.test(trimmed)) {
      throw new DerivationError(
        "Example public keys must be 0x followed by 64 lowercase hex characters.",
        "invalid-public-key",
      );
    }
    const bytes = new Uint8Array(32);
    for (let index = 0; index < 32; index += 1) {
      const start = 2 + index * 2;
      bytes[index] = Number.parseInt(trimmed.slice(start, start + 2), 16);
    }
    return bytes;
  },
});

// Cheap, and it is the property the identity service depends on.
assertCodecRoundTrip(exampleCodec, new Uint8Array(32).fill(7));

export const exampleEd25519ExternalSalt: DerivationProfile = defineDerivationProfile({
  id: "example-ed25519-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    // Concatenated with the raw password bytes; keep the trailing newline.
    passwordHash: "example password hash v1\n",
    entropy: "example Ed25519 external salt entropy v1",
  },
  codec: exampleCodec,
});

const address = await withDerivedWallet(
  {
    profile: exampleEd25519ExternalSalt,
    username,
    password,
    salt: publicSaltFromYourService,
    context: { applicationId: "example-app", networkId: "example-mainnet" },
  },
  (wallet) => wallet.identity.address,
);
```

`defineDerivationProfile` rejects the profile rather than trusting it:
`kdf.N` must be a power of two and at least 65536, `kdf.r` at least 8, `kdf.p`
at least 1, and `kdf.dkLen` exactly 32. A profile using `saltPolicy:
"derived-from-username"` must supply `domains.salt`; one using `"external-32"`
must not, because it never derives a salt. `defineIdentityCodec` requires an id
matching `[a-z0-9][a-z0-9._-]{2,63}` and all three methods.

Pick domain strings that are unique to your chain and profile. They are the only
thing separating your transcript from every other one, and they are frozen the
moment a wallet is derived under them.

**Key derivation.** If your chain derives keys from a master seed, such as HD
derivation at its own SLIP-44 path, add a
`keyDerivation: { id, deriveKey(masterSeed) }` step to the profile. The core
passes it a copy of the 32-byte scrypt output, requires exactly 32 bytes back,
reports a failure as `invalid-profile`, and zeroes both buffers. Name the scheme
and path in `id` and pin the path in your chain file rather than reading it from
a dependency. The Kalvora chain is the worked example: `kalvoraSlip10Ed25519`
has id `slip10-ed25519:m/44'/5258'/0'/0'/0'` and calls kalvora.js.

See [New chain, or new profile?](docs/INTEGRATION.md#new-chain-or-new-profile)
before defining either.

## API surface

### `web2-ish-self-custody`

| export | kind | purpose |
| --- | --- | --- |
| `withDerivedWallet(credentials, useWallet)` | function | derives a wallet, scopes it to a synchronous callback, zeroes the key on exit |
| `derivePublicIdentity(credentials)` | function | the same derivation, returning only public identity material |
| `defineDerivationProfile(profile)` | function | validates and freezes a profile |
| `defineIdentityCodec(codec)` | function | validates and freezes a codec |
| `assertCodecRoundTrip(codec, publicKeyBytes)` | function | throws unless `decodePublicKey` inverts `encodePublicKey` |
| `deriveIdentityFromSeed(seed, codec)` | function | public identity for an existing 32-byte Ed25519 seed |
| `normalizeUsername(username)` | function | the exact username normalization derivation applies |
| `ED25519_SEED_BYTES` | constant | `32` |
| `MINIMUM_PASSWORD_CHARACTERS` / `MAXIMUM_PASSWORD_BYTES` | constants | 10 characters (Unicode code points) and 1,024 UTF-8 bytes |
| `DerivationError` / `DerivationErrorCode` | class / type | every failure the client side throws |
| `createWalletVault`, `createWalletVaultFromCredentials`, `openWalletVaultWithPassword`, `openWalletVaultWithRecoveryCode`, `rewrapWalletVaultPassword`, `parseWalletVault` | functions | the [wallet vault](#wallet-vault-and-recovery-code) |
| `generateRecoveryCode` / `normalizeRecoveryCode` | functions | vault recovery codes |
| `WALLET_VAULT_FORMAT` | constant | `"web2-ish-self-custody-wallet-vault-v1"` |

Exported types: `CreateWalletVaultOptions`, `DerivationContext`,
`DerivationCredentials`, `DerivationProfile`, `DerivedIdentity`,
`DerivedWallet`, `IdentityCodec`, `KeyDerivation`, `ProfileDomains`,
`SaltPolicy`, `SealedBox`, `SeedIdentity`, and `WalletVault`.

### `web2-ish-self-custody/chains/kalvora`

| export | kind | purpose |
| --- | --- | --- |
| `kalvoraEd25519Codec` | `IdentityCodec` | `kalvora-ed25519-base58-v1`: base58 address, `A_<base58>` public-key identifier |
| `kalvoraEd25519ExternalSalt` | `DerivationProfile` | `web2ish-kalvora-ed25519-external-salt-v1`: service-salted, SLIP-0010 at `m/44'/5258'/0'/0'/0'` |
| `kalvoraSlip10Ed25519` | `KeyDerivation` | the profile's SLIP-0010 step, computed by kalvora.js |
| `kalvoraProfiles` | record | the bundled profiles, keyed by id |
| `deriveKalvoraEd25519IdentityFromSeed(seed)` | function | Kalvora public identity for a random 32-byte key (no HD step) |
| `KALVORA_SLIP44_COIN_TYPE` / `KALVORA_DERIVATION_PATH` | constants | `5258` and `m/44'/5258'/0'/0'/0'` |

There is no private-key export anywhere in the package.

### `web2-ish-self-custody/server`

| group | exports |
| --- | --- |
| service | `createIdentityService`, `createNeonIdentityService`, `createPgIdentityService` |
| transport | `createIdentityRouter`, `jsonResponse`, `nodeRequestListener` |
| SQL drivers | `neonDriver`, `pgDriver` |
| challenges | `CHALLENGE_DOMAIN`, `buildChallengeMessage`, `canonicalWalletIdentity`, `verifyChallengeSignature` |
| email delivery | `createEmailSender`, `createResendEmailSender`, `createPostmarkEmailSender`, `createSendGridEmailSender`, `emailProviders`, `deliverEmailVerification`, `assertEmailVerificationDelivery`, `renderVerificationEmail`, `resolveVerificationEmailTheme`, `formatVerificationCode`, `parseMailbox`, `escapeHtml`, `EmailDeliveryError` |
| config | `identityServiceDefaults`, `resolveIdentityServiceConfig` |
| migrations | `identityMigrations`, `runIdentityMigrations` |
| platform salt only | `platformSaltMigration`, `provisionPlatformSalt`, `readPlatformSalt` |
| errors | `IdentityError`, `identityErrorStatus`, `enumerationSensitiveCodes` |
| constants | `challengePurposes` |

The `IdentityService` contract type and the account, wallet, challenge,
session, email, router, and config types are exported alongside these. See
[docs/SERVER_API.md](docs/SERVER_API.md) for the full reference.

## Immutable profiles and codecs

Published profiles are protocols. Never edit a profile's normalization, domain
strings, salt policy, KDF settings, curve, key derivation, or codec. Never edit
a codec's encoding. Any behavioral change requires a new id and a migration
plan, because a wallet is defined by the profile that produced it.

The bundled Kalvora profile is `web2ish-kalvora-ed25519-external-salt-v1`:
Ed25519, a 32-byte salt the service owns, SLIP-0010 at `m/44'/5258'/0'/0'/0'`,
and the `kalvora-ed25519-base58-v1` codec. Its test vector is committed in
[`vectors/`](vectors/kalvora-ed25519-external-salt-v1.json); a refactor that
changes it is wrong. Retired profile ids are listed in
[the protocol](docs/PROTOCOL.md#retired-profiles). The generic
`derived-from-username` salt policy remains available to chains that define
their own profile.

## Security model

- **The public key is a password-verification oracle.** Anyone with a public
  identity and the public salt can guess passwords offline. scrypt raises the
  cost of each guess; it adds no entropy. Only high-entropy,
  password-manager-generated credentials are appropriate.
- **The password floor is not a strength check.** The package rejects passwords
  under 10 code points or over 1,024 UTF-8 bytes. The application owns the
  strength policy where a password is created or changed, and should not
  re-apply a stricter one at sign-in.
- **The username is context, not a secret.** It must not be counted as entropy.
- **Pin the profile in source.** A client that accepts a profile id, codec id,
  or KDF parameters from a server has handed that server a downgrade lever.
- **Isolate derivation.** Run it in a fresh dedicated worker, one derivation at
  a time, and terminate the worker for immediate cancellation.
- **Trust boundary.** The origin, browser, extensions, and operating system must
  be trusted while a password is entered and a wallet is active. Memory
  cleanup in JavaScript is best effort.
- **Codecs are trusted for custody.** A codec that does not round-trip, or that
  maps two keys to one address, breaks custody, not just presentation.
- **Unaudited.** This is an alpha, pre-1.0 implementation without an independent
  cryptographic audit. Do not represent it as audited or production-qualified.

Read [SECURITY.md](SECURITY.md) for the security policy and codec trust
boundary, and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for assumptions
and failure modes.

## What it does not do

These describe the client-side entry points (derivation and the wallet vault).
The server module is the one part of this package that holds state, and it
holds only public identity material.

- Recover a forgotten password. A deterministic wallet is a function of its
  password; the only recovery path is the recovery code of a wallet vault
  created *before* the password was lost.
- Recover a vault whose password and recovery code are both lost.
- Preserve a derived wallet when the username, password, context, salt, or
  profile changes. (A vault preserves the seed across password changes, but
  re-deriving from new credentials still yields a different wallet.)
- Prevent offline password guessing.
- Protect against malicious same-origin JavaScript, browser extensions, a
  compromised browser, or a compromised operating system.
- Store sessions, challenges, wallets, vaults, or account records on the client.
  A vault is returned as a plain object; persisting it is the host's job.
- Build or submit transactions.

## Used by

| consumer | what it uses |
| --- | --- |
| [DemocracyOS-web](https://github.com/IntoTheDerk/DemocracyOS-web) | the browser password wallet (`withDerivedWallet`) and the wallet-vault workers |
| [DemocracyOS-backend](https://github.com/IntoTheDerk/DemocracyOS-backend) | the platform salt and server identity configuration: `provisionPlatformSalt` / `readPlatformSalt` from `/server` |

Both currently pin a reviewed v0.9.x release commit by its full SHA (see
[Install](#install)); moving to the 0.10 line is a new wallet family for them
(see [Migrating from v0.9.x](#migrating-from-v09x)). DemocracyOS uses
`serviceProfileId: "democracyos-password-wallet-v1"` with
`applicationId: "democracy-os"`. Any other application on the same profile has
its own application id and its own public salt, so the same username and
password derive a **different** wallet there. That is by design — see
[Two services, one identity format](docs/INTEGRATION.md#two-services-one-identity-format).

## Migrating from v0.9.x

In v0.10.0-alpha.0 the ZERA chain was replaced by Kalvora
(`web2-ish-self-custody/chains/kalvora`). The Kalvora profile is a new wallet
family: the same credentials derive a different address, and an identity
service needs a new `serviceProfileId` or a fresh database. See the
[changelog](CHANGELOG.md#migrating-from-v09x) for the step-by-step migration.

## Development

```bash
npm ci
npm run verify      # typecheck, tests, Python vector verifier, build
```

To reproduce what `.github/workflows/ci.yml` checks without GitHub Actions:

```bash
npm run verify:ci   # scripts/verify-ci.sh
```

`scripts/verify-ci.sh` runs every CI gate that can run on a developer machine —
the Node matrix membership check, the `npm ci` lockfile-sync check, typecheck,
tests, the Python vectors, and the build — reporting PASS/FAIL per gate and
exiting with the number of failures. Gates that cannot run locally (the second
Node matrix arm, CI's linux-x86_64 hash-pinned `pip install`, the PostgreSQL
suites) print SKIP with a reason; pass `--pip` or `--pg` (with
`W2SC_TEST_DATABASE_URL` exported) to run them where possible.

**Python vector verifier.** `npm run verify:vectors:python` runs
`scripts/verify_kalvora_external_salt_vector.py`, an independent reproduction of
the committed Kalvora vector using Python's `hashlib`, the `cryptography`
package, and its own SLIP-0010 implementation; it does not execute the
TypeScript code. Local development therefore requires Python 3.12 and
`cryptography==46.0.3`; CI installs it from exact, hash-pinned wheels
(`scripts/requirements-vector-verifier-ci.txt`). See
[the protocol](docs/PROTOCOL.md#independent-vector-verification) for the
assurance boundary.

## Versioning and releases

Releases are Git tags (`v0.10.0-alpha.0`, …), each described in
[CHANGELOG.md](CHANGELOG.md). The package is not published to npm; consumers
pin a reviewed release commit by its full SHA.

The current line is an **alpha pre-release**, `0.10.0-alpha.x`. Any alpha
release may change the Kalvora chain surface. A change to a profile's
transcript or a codec's encoding is always a new id, never an edit in place;
see [Versioning](docs/PROTOCOL.md#versioning) and
[Updating the shared dependency](docs/INTEGRATION.md#updating-the-shared-dependency).

## License

[MIT](LICENSE) © 2026 IntoTheDerk
