# web2-ish-self-custody

> **Security warning:** anyone who knows a public identity and its public salt can test password guesses offline. Deterministic password-derived custody is not equivalent to a randomly generated wallet seed. Use only high-entropy, password-manager-generated credentials and complete an independent security review before funded use.

A small browser-first TypeScript SDK for recreating the same signing identity from a username and password without storing wallet secrets on an application server.

It exists to give products such as Knight Armor and DemocracyOS one versioned implementation instead of maintaining independent cryptographic copies.

The additive `web2-ish-self-custody/zera-ed25519` entry point can also derive a
public ZERA identity from an application-owned random 32-byte Ed25519 seed. It
does not derive that seed from Web2 credentials and does not store, encrypt,
recover, or sign with it. Applications remain responsible for generating the
seed securely and keeping it inside a separately reviewed encrypted vault.

## What it does

- Derives a wallet only inside a callback scope.
- Exposes public identity and curve-specific signing methods, never a private-key export.
- Clears SDK-owned password, entropy, salt, and seed buffers on completion.
- Includes an exact DemocracyOS web-v2 compatibility profile.
- Includes a stateless ZERA Ed25519 profile for new integrations.
- Includes a context-bound ZERA Ed25519 profile for service-managed public salts.
- Ships stable test vectors and immutable built-in KDF parameters.
- Uses no network, filesystem, storage, telemetry, or Node-only runtime APIs.
- Derives the standard ZERA Ed25519 public identity from an existing random seed
  through a separate, storage-agnostic entry point.

## What it does not do

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
    (wallet) => {
      if (!("signExactMessageUnsafe" in wallet)) throw new Error("Unexpected wallet profile");
      return {
        identity: wallet.identity,
        signature: wallet.signExactMessageUnsafe(exactTypedMessageBytes),
      };
    },
  );
} finally {
  password.fill(0);
}
```

The stateless profile derives its salt from the canonical username, application, and network. KA does not need to store any wallet secret or encrypted vault.

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
  (wallet) => {
    if (!("signExactMessageUnsafe" in wallet)) throw new Error("Unexpected wallet profile");
    return {
      identity: wallet.identity,
      signature: wallet.signExactMessageUnsafe(exactTypedMessageBytes),
    };
  },
);
```

The salt is public derivation metadata, not a password or custody secret. It
must remain byte-for-byte stable for the lifetime of the wallet. Losing,
rotating, or returning the wrong service salt derives a different wallet.
Applications must pin the profile and validate the salt source rather than
accepting arbitrary KDF parameters from a server.

## DemocracyOS web-v2 compatibility

```ts
const proof = await withDerivedWallet(
  {
    profile: "democracyos-scrypt-sha512-secp256k1-v2",
    username,
    password,
    salt: publicSaltFromKnownServerProfile,
  },
  (wallet) => {
    if (!("signDemocracyOsChallengeDigest" in wallet)) throw new Error("Unexpected wallet profile");
    return {
      identity: wallet.identity,
      signature: wallet.signDemocracyOsChallengeDigest(challengeDigest),
    };
  },
);
```

This profile reproduces the current DemocracyOS web public key, address, and signature behavior. The supplied salt is public derivation metadata, not a wallet secret. Server-controlled responses must select only this known profile and exact salt length; they must never supply arbitrary KDF cost parameters.

The Ed25519 method is deliberately named `signExactMessageUnsafe`. It is a low-level primitive required for exact ZERA transaction bytes, not permission to sign bytes supplied by a server or untrusted renderer. A consuming application must locally reconstruct a typed intent, show a trusted confirmation, and only then pass the exact verified bytes to the scoped signer.

## Immutable profiles

Published profiles are protocols. Never edit their normalization, domains, salt policy, KDF settings, curve handling, or identity encoding. Any behavioral change requires a new profile ID and migration plan.

Current profiles:

- `democracyos-scrypt-sha512-secp256k1-v2`
- `web2ish-zera-ed25519-v1`
- `web2ish-zera-ed25519-external-salt-v1`

See [the protocol](docs/PROTOCOL.md), [security model](docs/SECURITY_MODEL.md), and [integration guide](docs/INTEGRATION.md).

## Development

```bash
npm ci
npm run verify
```

`npm run verify` also executes independent Python reproductions of all three
committed profile vectors. Local development therefore requires Python 3.12 and
`cryptography==46.0.3`; CI installs that verifier dependency and its transitive
dependencies from exact, hash-pinned Linux wheels. See [the
protocol](docs/PROTOCOL.md#independent-vector-verification) for the assurance
boundary.

The package is intentionally pre-1.0 and has not received an independent cryptographic audit.
