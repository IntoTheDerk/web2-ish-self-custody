# web2-ish-self-custody

> **Security warning:** anyone who knows a public identity and its public salt can test password guesses offline. Deterministic password-derived custody is not equivalent to a randomly generated wallet seed. Use only high-entropy, password-manager-generated credentials and complete an independent security review before funded use.

A small browser-first TypeScript package with two halves:

- a **generic Ed25519 deterministic-custody core** that recreates the same signing
  identity from a username and password without storing any wallet secret, and
- a **portable identity service** that owns the public salt such a derivation
  needs, verifies signatures, and issues sessions.

The core knows nothing about any blockchain. A chain plugs into it. ZERA is the
first bundled chain and lives at `web2-ish-self-custody/chains/zera`.

It exists to give the products that adopt it one versioned implementation
instead of maintaining independent cryptographic copies.

## The model

Three pieces, in order of how much they know:

| piece | what it is | who owns it |
| --- | --- | --- |
| **core** | username/password → 32-byte Ed25519 seed → public identity, inside a callback scope | this package |
| **`IdentityCodec`** | how a 32-byte public key becomes an address and a wire identifier, and how that identifier decodes back | a chain |
| **`DerivationProfile`** | one immutable derivation transcript: curve, KDF parameters, salt policy, domain-separation strings, and the codec to encode with | a chain |

Nothing in the derivation path or in the identity service contains the words
base58, bech32, or hex. Those live in a codec. Adding a chain is a new codec and
a new profile; it is never a patch to the core.

A profile is a protocol, not configuration. Its domain strings and KDF
parameters are part of the definition of every wallet derived under it, so a
change to any of them is a new profile id, never an edit. See
[the protocol](docs/PROTOCOL.md).

## What it does

- Derives a wallet only inside a callback scope, and zeroes the seed on exit.
- Exposes the public identity and an exact-message signer, never a private-key export.
- Clears package-owned password, entropy, salt, and seed buffers on completion.
- Validates a profile at definition time, including a hard KDF floor.
- Validates a codec at definition time, and round-trips it at service startup.
- Ships stable test vectors and independent Python reproductions of them.
- Uses no network, filesystem, storage, telemetry, or Node-only runtime APIs.
- Derives a public identity from an application-owned random 32-byte seed
  through a separate, storage-agnostic entry point.

## What it does not do

These lists describe the derivation entry points. The separate
`web2-ish-self-custody/server` module is the one part of this package that holds
state, and it holds only public identity material.

- Recover forgotten passwords.
- Preserve a wallet when the username, password, context, salt, or profile changes.
- Prevent offline password guessing.
- Protect against malicious same-origin JavaScript, browser extensions, a compromised browser, or a compromised operating system.
- Store sessions, challenges, wallets, or account records.
- Build or submit transactions.
- Generate, encrypt, persist, or recover random-seed vaults.

## Install

The package has not yet been published to npm. During integration, depend on an immutable Git commit:

```json
{
  "dependencies": {
    "web2-ish-self-custody": "github:IntoTheDerk/web2-ish-self-custody#<reviewed-commit>"
  }
}
```

## Usage

A derivation takes a profile **object**, not a profile id. The core has no
profile registry to look an id up in — the chain package is the registry.

### Service-salted ZERA (the profile the identity server implements)

```ts
import { withDerivedWallet } from "web2-ish-self-custody";
import { zeraEd25519ExternalSalt } from "web2-ish-self-custody/chains/zera";

const password = new TextEncoder().encode(userSuppliedPassword);
try {
  const proof = await withDerivedWallet(
    {
      profile: zeraEd25519ExternalSalt,
      username,
      password,
      // Exactly 32 bytes, published by your own service. Public metadata.
      salt: publicSaltFromYourService,
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

The salt is public derivation metadata, not a password or a custody secret. It
must remain byte-for-byte stable for the lifetime of the wallet: losing,
rotating, or returning the wrong service salt derives a different wallet.
Applications must pin the profile in source and validate the salt source rather
than accepting KDF parameters from a server response.

### Stateless ZERA (no server at all)

```ts
import { withDerivedWallet } from "web2-ish-self-custody";
import { zeraEd25519 } from "web2-ish-self-custody/chains/zera";

const identity = await withDerivedWallet(
  {
    profile: zeraEd25519,
    username,
    password,
    context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
  },
  (wallet) => wallet.identity,
);
```

This profile derives its own salt from the canonical username, application, and
network. It rejects a caller-supplied `salt` outright rather than ignoring it.

### Random-seed public identity

```ts
import { deriveZeraEd25519IdentityFromSeed } from "web2-ish-self-custody/chains/zera";

const seed = crypto.getRandomValues(new Uint8Array(32));
try {
  const identity = deriveZeraEd25519IdentityFromSeed(seed);
  console.log(identity.address, identity.codecId);
} finally {
  seed.fill(0);
}
```

This standardizes only public-key derivation and address encoding for a seed the
application already owns. It does not derive that seed from credentials and does
not store, encrypt, recover, or sign with it. The generic form is
`deriveIdentityFromSeed(seed, codec)`; the ZERA helper is that function with
`zeraEd25519Codec` already applied.

### The signer is deliberately named unsafe

`signExactMessageUnsafe` signs precisely the bytes it is handed. It is the
primitive needed for exact on-chain transaction bytes, not permission to sign
bytes supplied by a server or an untrusted renderer. A consuming application
must locally reconstruct a typed intent, show a trusted confirmation, and only
then pass the exact verified bytes to the scoped signer.

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

## API surface

`web2-ish-self-custody` exports:

| export | kind | purpose |
| --- | --- | --- |
| `withDerivedWallet(credentials, useWallet)` | function | derives a wallet, scopes it to a synchronous callback, zeroes the seed on exit |
| `derivePublicIdentity(credentials)` | function | the same derivation, returning only public identity material |
| `defineDerivationProfile(profile)` | function | validates and freezes a profile |
| `defineIdentityCodec(codec)` | function | validates and freezes a codec |
| `assertCodecRoundTrip(codec, publicKeyBytes)` | function | throws unless `decodePublicKey` inverts `encodePublicKey` |
| `deriveIdentityFromSeed(seed, codec)` | function | public identity for an existing 32-byte Ed25519 seed |
| `normalizeUsername(username)` | function | the exact username normalization derivation applies |
| `ED25519_SEED_BYTES` | constant | 32 |
| `MINIMUM_PASSWORD_BYTES` / `MAXIMUM_PASSWORD_BYTES` | constants | 24 and 1024 |
| `DerivationError` / `DerivationErrorCode` | class / type | every failure this package throws |

Exported types: `DerivationContext`, `DerivationCredentials`,
`DerivationProfile`, `DerivedIdentity`, `DerivedWallet`, `IdentityCodec`,
`ProfileDomains`, `SaltPolicy`, and `SeedIdentity`.

`web2-ish-self-custody/chains/zera` exports:

| export | kind | purpose |
| --- | --- | --- |
| `zeraEd25519Codec` | `IdentityCodec` | base58 address, `A_<base58>` public-key identifier |
| `zeraEd25519` | `DerivationProfile` | stateless; derives its salt from the username |
| `zeraEd25519ExternalSalt` | `DerivationProfile` | service-salted; takes 32 bytes from the caller |
| `zeraProfiles` | record | both profiles, keyed by id |
| `deriveZeraEd25519IdentityFromSeed(seed)` | function | ZERA public identity for a random seed |

There is no private-key export anywhere in the package.

## Server module

`web2-ish-self-custody/server` is the server half of any `external-32` profile.
It owns and publishes one immutable 32-byte public salt per service, verifies
signatures over single-use challenges, and issues opaque sessions. It never
receives a password, a seed, or a ciphertext, and it stores no material from
which a wallet could be reconstructed.

It takes the same profile object the client derives with, so the service encodes
addresses through the client's codec rather than a convention hardcoded in the
server.

On Vercel with Neon:

```ts
// app/api/identity/[...path]/route.ts
import { neon } from "@neondatabase/serverless";
import { zeraEd25519ExternalSalt } from "web2-ish-self-custody/chains/zera";
import {
  createIdentityRouter,
  createNeonIdentityService,
} from "web2-ish-self-custody/server";

const service = createNeonIdentityService({
  neon,
  connectionString: process.env.DATABASE_URL!,
  config: {
    serviceProfileId: "knight-armor",
    profile: zeraEd25519ExternalSalt,
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
| constants | `challengePurposes` |

Serviceability is a policy, not a list: any profile whose `saltPolicy` is
`external-32` and whose codec round-trips can be configured. A profile that
derives its own salt has nothing for a server to own, and `createIdentityService`
rejects it. The `IdentityService` contract type and the account, wallet,
challenge, session, and config types are exported alongside these.

See [the server API reference](docs/SERVER_API.md) for the wire format, the
schema and its invariants, deployment, and threat notes.

## Immutable profiles and codecs

Published profiles are protocols. Never edit a profile's normalization, domain
strings, salt policy, KDF settings, curve, or codec. Never edit a codec's
encoding. Any behavioral change requires a new id and a migration plan, because
a wallet is defined by the profile that produced it.

Bundled ZERA profiles, both Ed25519, both using `zera-ed25519-base58-v1`:

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
