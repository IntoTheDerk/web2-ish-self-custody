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
- Seals a 32-byte seed into an encrypted [wallet vault](#wallet-vault-and-recovery-code)
  that opens with either a password or a generated recovery code, so a password
  change or a forgotten password need not mean a new wallet.

## What it does not do

These lists describe the client-side entry points (derivation and the wallet
vault). The separate `web2-ish-self-custody/server` module is the one part of
this package that holds state, and it holds only public identity material.

- Recover a forgotten password. A deterministic wallet is a function of its
  password; the only recovery path the package offers is the recovery code of a
  wallet vault created *before* the password was lost.
- Recover a vault whose password and recovery code are both lost.
- Preserve a derived wallet when the username, password, context, salt, or
  profile changes. (A vault preserves the seed across password changes, but
  re-deriving from new credentials still yields a different wallet.)
- Prevent offline password guessing.
- Protect against malicious same-origin JavaScript, browser extensions, a compromised browser, or a compromised operating system.
- Store sessions, challenges, wallets, vaults, or account records. A vault is
  returned as a plain object; persisting it is the host's job.
- Build or submit transactions.

## Install

The package has not yet been published to npm. During integration, depend on an
immutable, reviewed Git commit — the same form every current consumer uses:

```json
{
  "dependencies": {
    "web2-ish-self-custody": "git+https://github.com/IntoTheDerk/web2-ish-self-custody.git#<reviewed-commit-sha>"
  }
}
```

Pin a full 40-character commit SHA rather than a branch or a tag name. The
package builds itself through its `prepare` script during the Git install.

## Used by

| consumer | what it uses |
| --- | --- |
| [DemocracyOS-web](https://github.com/IntoTheDerk/DemocracyOS-web) | the browser password wallet (`withDerivedWallet` with `zeraEd25519ExternalSalt`) and the wallet-vault workers |
| [DemocracyOS-backend](https://github.com/IntoTheDerk/DemocracyOS-backend) | the platform salt and server identity configuration: `provisionPlatformSalt` / `readPlatformSalt` from `/server`, configured with `zeraEd25519ExternalSalt` |
| [Knight-Armor](https://github.com/IntoTheDerk/Knight-Armor) | the identity service (`createIdentityService` / `createIdentityRouter` from `/server`) and the browser credential-derived wallet |

Each consumer pins one reviewed commit (currently `v0.8.0`,
`051b4bcf2521e664f9688553dc27f01e2b6badf0`). DemocracyOS uses
`serviceProfileId: "democracyos-password-wallet-v1"` with
`applicationId: "democracy-os"`; Knight-Armor uses
`"knight-armor-password-wallet-v1"` with `"knight-armor"`. Both share the
`zeraEd25519ExternalSalt` profile but each has its own application id and its own
public salt, so the same username and password derive **different** wallets in
each product. That is by design — see
[Two services, one identity format](docs/INTEGRATION.md#two-services-one-identity-format).

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
`zeraEd25519Codec` already applied. To encrypt such a seed, see the wallet vault
below.

### Wallet vault and recovery code

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
import { zeraEd25519Codec, zeraEd25519ExternalSalt } from "web2-ish-self-custody/chains/zera";

// Enrol the wallet these credentials already derive; its address is preserved.
// vaultPassword is the UTF-8 encoding of at least 10 characters (at most 1,024
// bytes) and may differ from the derivation password.
const { vault, recoveryCode } = await createWalletVaultFromCredentials(
  { profile: zeraEd25519ExternalSalt, username, password, salt, context },
  vaultPassword,
);
// Show recoveryCode to the user once so they can write it down. Store `vault`
// (a plain JSON-serializable object) wherever the application keeps it.

// Later: parse what came back from storage, then open it inside a scope.
const signature = await openWalletVaultWithPassword(
  parseWalletVault(storedVault),
  vaultPassword,
  zeraEd25519Codec,
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
| `MINIMUM_PASSWORD_CHARACTERS` / `MAXIMUM_PASSWORD_BYTES` | constants | 10 characters (Unicode code points) and 1,024 UTF-8 bytes |
| `DerivationError` / `DerivationErrorCode` | class / type | every failure this package throws |
| `createWalletVault`, `createWalletVaultFromCredentials`, `openWalletVaultWithPassword`, `openWalletVaultWithRecoveryCode`, `rewrapWalletVaultPassword`, `parseWalletVault` | functions | the [wallet vault](#wallet-vault-and-recovery-code) |
| `generateRecoveryCode` / `normalizeRecoveryCode` | functions | vault recovery codes |
| `WALLET_VAULT_FORMAT` | constant | `"web2-ish-self-custody-wallet-vault-v1"` |

Exported types: `CreateWalletVaultOptions`, `DerivationContext`,
`DerivationCredentials`, `DerivationProfile`, `DerivedIdentity`,
`DerivedWallet`, `IdentityCodec`, `ProfileDomains`, `SaltPolicy`, `SealedBox`,
`SeedIdentity`, and `WalletVault`.

`web2-ish-self-custody/chains/zera` exports:

| export | kind | purpose |
| --- | --- | --- |
| `zeraEd25519Codec` | `IdentityCodec` | base58 address, `A_<base58>` public-key identifier |
| `zeraEd25519ExternalSalt` | `DerivationProfile` | service-salted; takes 32 bytes from the caller |
| `zeraProfiles` | record | the bundled profile, keyed by id |
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
| platform salt only | `platformSaltMigration`, `provisionPlatformSalt`, `readPlatformSalt` |
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

The bundled ZERA profile is `web2ish-zera-ed25519-external-salt-v1`: Ed25519,
the `zera-ed25519-base58-v1` codec, and a 32-byte salt the service owns. (The
self-salting `web2ish-zera-ed25519-v1` profile was removed in v0.9.0; the generic
`derived-from-username` salt policy remains available to chains that define
their own profile.)

See [the protocol](docs/PROTOCOL.md), [security model](docs/SECURITY_MODEL.md), and [integration guide](docs/INTEGRATION.md).

## Development

```bash
npm ci
npm run verify
```

To reproduce what `.github/workflows/ci.yml` checks without GitHub Actions:

```bash
npm run verify:ci
```

`scripts/verify-ci.sh` runs every CI gate that can run on a developer machine —
the Node matrix membership check, the `npm ci` lockfile-sync check, typecheck,
tests, the Python vectors, and the build — reporting PASS/FAIL per gate and
exiting with the number of failures. Gates that cannot run locally (the second
Node matrix arm, CI's linux-x86_64 hash-pinned `pip install`, the PostgreSQL
suites) print SKIP with a reason; see the script header for the full list and
for the `--pip` and `--pg` flags.

`npm run verify` also executes independent Python reproductions of the committed
profile vectors. Local development therefore requires Python 3.12 and
`cryptography==46.0.3`; CI installs that verifier dependency and its transitive
dependencies from exact, hash-pinned Linux wheels. See [the
protocol](docs/PROTOCOL.md#independent-vector-verification) for the assurance
boundary.

The package is intentionally pre-1.0 and has not received an independent cryptographic audit.
