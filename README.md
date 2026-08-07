# web2-ish-self-custody

> **Security warning:** anyone who knows a public identity and its public salt can test password guesses offline. Deterministic password-derived custody is not equivalent to a randomly generated wallet seed. Use only high-entropy, password-manager-generated credentials and complete an independent security review before funded use.

A small browser-first TypeScript SDK for recreating the same signing identity from a username and password without storing wallet secrets on an application server.

It exists to give the products that adopt it one versioned implementation instead of maintaining independent cryptographic copies.

The additive `web2-ish-self-custody/zera-ed25519` entry point can also derive a
public ZERA identity from an application-owned random 32-byte Ed25519 seed. It
does not derive that seed from Web2 credentials and does not store, encrypt,
recover, or sign with it. Applications remain responsible for generating the
seed securely and keeping it inside a separately reviewed encrypted vault.

## What it does

- Derives a wallet only inside a callback scope.
- Exposes the public identity and an exact-message signer, never a private-key export.
- Clears SDK-owned password, entropy, salt, and seed buffers on completion.
- Includes a stateless ZERA Ed25519 profile that needs no server.
- Includes a context-bound ZERA Ed25519 profile for service-managed public salts.
- Ships stable test vectors and immutable built-in KDF parameters.
- Uses no network, filesystem, storage, telemetry, or Node-only runtime APIs.
- Derives the standard ZERA Ed25519 public identity from an existing random seed
  through a separate, storage-agnostic entry point.

## What it does not do

These lists describe the derivation entry points. The separate
`web2-ish-self-custody/server` module is the one part of this package that
holds state, and it holds only public identity material.

- Recover forgotten passwords.
- Preserve a wallet when the username, password, context, or derivation profile changes.
- prevent offline password guessing.
- Protect against malicious same-origin JavaScript, browser extensions, a compromised browser, or a compromised operating system.
- Store sessions, challenges, wallets, or account records.
- Build or submit transactions.
- Generate, encrypt, persist, or recover random-seed vaults.

## Random-seed ZERA public identity

```ts
import { deriveZeraEd25519IdentityFromSeed } from
  "web2-ish-self-custody/zera-ed25519";

const seed = crypto.getRandomValues(new Uint8Array(32));
try {
  const identity = deriveZeraEd25519IdentityFromSeed(seed);
  console.log(identity.address);
} finally {
  seed.fill(0);
}
```

This helper standardizes only Ed25519 public-key derivation, Base58 address
encoding, and the `A_` public-key identifier. It intentionally leaves encrypted
storage and recovery policy to the consuming application.

## Install

The package has not yet been published to npm. During integration, depend on an immutable Git commit:

```json
{
  "dependencies": {
    "web2-ish-self-custody": "github:IntoTheDerk/web2-ish-self-custody#<reviewed-commit>"
  }
}
```

## Stateless ZERA Ed25519 example

```ts
import { withDerivedWallet } from "web2-ish-self-custody";

const password = new TextEncoder().encode(userSuppliedPassword);
try {
  const proof = await withDerivedWallet(
    {
      profile: "web2ish-zera-ed25519-v1",
      username,
      password,
      context: {
        applicationId: "knight-armor",
        networkId: "zera-mainnet",
      },
    },
    (wallet) => ({
      identity: wallet.identity,
      signature: wallet.signExactMessageUnsafe(exactTypedMessageBytes),
    }),
  );
} finally {
  password.fill(0);
}
```

The stateless profile derives its salt from the canonical username, application, and network. The application needs no server call and stores no wallet secret or encrypted vault.

## Database-held salt ZERA Ed25519 example

Use the external-salt profile when each service stores its own stable public
32-byte salt while retaining the same ZERA network identity format:

```ts
const proof = await withDerivedWallet(
  {
    profile: "web2ish-zera-ed25519-external-salt-v1",
    username,
    password,
    salt: publicSaltFromKnownService,
    context: {
      applicationId: "knight-armor",
      networkId: "zera-mainnet",
    },
  },
  (wallet) => ({
    identity: wallet.identity,
    signature: wallet.signExactMessageUnsafe(exactTypedMessageBytes),
  }),
);
```

The salt is public derivation metadata, not a password or custody secret. It
must remain byte-for-byte stable for the lifetime of the wallet. Losing,
rotating, or returning the wrong service salt derives a different wallet.
Applications must pin the profile and validate the salt source rather than
accepting arbitrary KDF parameters from a server.

The signing method is deliberately named `signExactMessageUnsafe`. It is a low-level primitive required for exact ZERA transaction bytes, not permission to sign bytes supplied by a server or untrusted renderer. A consuming application must locally reconstruct a typed intent, show a trusted confirmation, and only then pass the exact verified bytes to the scoped signer.

## API surface

`web2-ish-self-custody` exports:

| export | kind | purpose |
| --- | --- | --- |
| `withDerivedWallet(credentials, useWallet)` | function | derives a wallet, scopes it to a synchronous callback, zeroes the seed on exit |
| `derivePublicIdentity(credentials)` | function | the same derivation, returning only public identity material |
| `normalizeUsername(username)` | function | the exact username normalization derivation applies |
| `getProfile(id)` / `builtInProfiles` | function / record | the pinned KDF parameters for a profile |
| `MINIMUM_PASSWORD_BYTES` / `MAXIMUM_PASSWORD_BYTES` | constants | 24 and 1024 |
| `DerivationError` / `DerivationErrorCode` | class / type | every failure this package throws |

Exported types: `BuiltInProfileId`, `DerivationContext`, `DerivationCredentials`,
`DerivedPublicIdentity`, `DerivedWallet`, `Ed25519Identity`, `Ed25519Wallet`,
`ProfileDescription`, `ZeraEd25519Credentials`,
`ZeraEd25519ExternalSaltCredentials`, and `ZeraEd25519ProfileId`.

`web2-ish-self-custody/zera-ed25519` exports the random-seed identity helper
shown above. There is no private-key export anywhere in the package.

## Server module

`web2-ish-self-custody/server` is the server half of
`web2ish-zera-ed25519-external-salt-v1`, the only serviceable profile. It owns
and publishes one immutable 32-byte public salt per service, verifies signatures
over single-use challenges, and issues opaque sessions. It never receives a
password, a seed, or a ciphertext, and it stores no material from which a wallet
could be reconstructed.

On Vercel with Neon:

```ts
// app/api/identity/[...path]/route.ts
import { neon } from "@neondatabase/serverless";
import {
  createIdentityRouter,
  createNeonIdentityService,
} from "web2-ish-self-custody/server";

const service = createNeonIdentityService({
  neon,
  connectionString: process.env.DATABASE_URL!,
  config: {
    serviceProfileId: "knight-armor",
    profileId: "web2ish-zera-ed25519-external-salt-v1",
    applicationId: "knight-armor",
    networkId: "zera-mainnet",
  },
});

const handler = createIdentityRouter(service, {
  basePath: "/api/identity",
  trustedOrigins: ["https://app.knight-armor.example"],
});

export { handler as GET, handler as POST, handler as PATCH, handler as DELETE };
```

`createIdentityRouter` returns a plain Fetch handler. The same handler runs
self-hosted behind a `pg` Pool and `nodeRequestListener`, with no application
code change. Neither `@neondatabase/serverless` nor `pg` is a dependency of this
package; both adapters take an already-constructed client, injected by the host.

Run `service.migrate()` from a deploy step, not from request handling. Its first
successful run against a new database is the moment that service's public salt
comes into existence, and the schema then refuses to change it.

`web2-ish-self-custody/server` exports:

| group | exports |
| --- | --- |
| service | `createIdentityService`, `createNeonIdentityService`, `createPgIdentityService` |
| transport | `createIdentityRouter`, `jsonResponse`, `nodeRequestListener` |
| SQL drivers | `neonDriver`, `pgDriver` |
| challenges | `CHALLENGE_DOMAIN`, `buildChallengeMessage`, `canonicalWalletIdentity`, `verifyChallengeSignature` |
| config | `identityServiceDefaults`, `resolveIdentityServiceConfig` |
| migrations | `identityMigrations`, `runIdentityMigrations` |
| errors | `IdentityError`, `identityErrorStatus`, `enumerationSensitiveCodes` |
| constants | `challengePurposes`, `serverProfileIds` |

`serverProfileIds` contains exactly one id: only the external-salt profile has a
salt for a server to own. The `IdentityService` contract type and the account,
wallet, challenge, session, and config types are exported alongside these.

See [the server API reference](docs/SERVER_API.md) for the wire format, the
schema and its invariants, deployment, and threat notes.

## Immutable profiles

Published profiles are protocols. Never edit their normalization, domains, salt policy, KDF settings, curve handling, or identity encoding. Any behavioral change requires a new profile ID and migration plan.

Current profiles, both Ed25519:

- `web2ish-zera-ed25519-v1` — derives its own public salt from the username
- `web2ish-zera-ed25519-external-salt-v1` — takes a 32-byte salt the service owns

See [the protocol](docs/PROTOCOL.md), [security model](docs/SECURITY_MODEL.md), and [integration guide](docs/INTEGRATION.md).

## Development

```bash
npm ci
npm run verify
```

`npm run verify` also executes independent Python reproductions of the committed
profile vectors. Local development therefore requires Python 3.12 and
`cryptography==46.0.3`; CI installs that verifier dependency and its transitive
dependencies from exact, hash-pinned Linux wheels. See [the
protocol](docs/PROTOCOL.md#independent-vector-verification) for the assurance
boundary.

The package is intentionally pre-1.0 and has not received an independent cryptographic audit.
