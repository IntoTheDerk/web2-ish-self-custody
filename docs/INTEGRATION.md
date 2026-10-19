# Integration

This package is a generic Ed25519 deterministic-custody core plus a pluggable
chain. Integrating it means answering three questions in order:

1. **Which chain?** That decides the `IdentityCodec` — how a public key becomes
   an address. Kalvora ships in the box at `web2-ish-self-custody/chains/kalvora`,
   backed by [kalvora.js](#kalvora-and-kalvorajs).
2. **Which profile of that chain?** That decides the transcript and, in
   particular, where the scrypt salt comes from.
3. **Which namespace?** Your `applicationId`, your `networkId`, and — for a
   service-salted profile — your own 32-byte public salt.

The core has no profile registry. You import the profile object from the chain
package and pass it in. There is no id string for a server, an environment
variable, or a config file to swap out from under you.

## Kalvora and kalvora.js

The Kalvora chain is provided by [kalvora.js](https://github.com/IntoTheDerk/kalvora.js),
the Kalvora SDK: `web2-ish-self-custody/chains/kalvora` calls its
`kalvora.js/wallet` entry for the SLIP-0010 key step and for address encoding.
That entry is the SDK's wallet surface on its own — no network, protobuf, or
transaction code — so the browser custody path stays offline.

kalvora.js is an **optional peer dependency**. An application that imports
`web2-ish-self-custody/chains/kalvora` installs it alongside this package, at
the exact version in this package's `peerDependencies`:

```json
{
  "dependencies": {
    "web2-ish-self-custody": "git+https://github.com/IntoTheDerk/web2-ish-self-custody.git#<reviewed-commit-sha>",
    "kalvora.js": "0.0.1-alpha.1"
  }
}
```

An application that only uses the core, the vault, or the server with another
chain does not need it.

What this buys: a password wallet here **is** a kalvora.js wallet. The scrypt
output is a SLIP-0010 master seed, and the wallet key is its node at
`m/44'/5258'/0'/0'/0'` — kalvora.js's first wallet for that seed, and what any
SLIP-0010 implementation derives at that path. Addresses and `A_` identifiers
are spelled by kalvora.js's own encoder. The suite checks both against
kalvora.js directly, and the Python verifier re-derives the committed vector
with its own SLIP-0010 implementation.

The path is pinned in this package, not read from kalvora.js: a kalvora.js
release that changed its default path must not move existing password wallets.
Upgrading kalvora.js is still a custody change — the committed vector is what
proves the upgrade derives the same wallets.

## Choosing what to import

| you need | import | from |
| --- | --- | --- |
| a wallet whose namespace your service owns and can separate from every other service | `kalvoraEd25519ExternalSalt` | `web2-ish-self-custody/chains/kalvora` |
| a public identity for a seed you already generated randomly | `deriveKalvoraEd25519IdentityFromSeed` | `web2-ish-self-custody/chains/kalvora` |
| a seed that survives a password change, with a recovery code | `createWalletVault`, `createWalletVaultFromCredentials`, and the other vault functions | `web2-ish-self-custody` |
| a key that signs in to your identity service and is not a wallet | `signInEd25519ExternalSalt` | `web2-ish-self-custody` |
| the Kalvora wallet of a master seed you hold, such as an application secret | `withKalvoraWalletFromMasterSeed` | `web2-ish-self-custody/chains/kalvora` |
| the server half of a service-salted profile | `createIdentityService` and friends | `web2-ish-self-custody/server` |

Derivation profiles are not interchangeable. Selecting a different one for an
existing user derives a different wallet, which is a product migration with an
enrollment step, never a configuration change.

## New chain, or new profile?

These are different decisions with different blast radii. Pick the smaller one
that actually fits.

**Define a new codec (a new chain) when the address encoding differs.** A
different alphabet, a different prefix or tag, a checksum, a hash-then-truncate
address, a different identifier form on the wire — anything that changes what
`encodeAddress` or `encodePublicKey` returns. Because a profile carries its
codec, a new codec always implies at least one new profile as well.

**Define a new profile against an existing codec when only the transcript
changes.** Same addresses, different derivation: a different salt policy, a
different KDF cost, a new domain string, a new version of the same wallet family.
One codec can carry any number of transcripts this way.

**Reuse an existing profile** when you want the same wallet family and only your
namespace differs. Two services on `kalvoraEd25519ExternalSalt` with different
salts and different `applicationId` values already get fully separated wallets;
that separation needs no new profile and no new code.

**Never edit either.** Editing a published domain string, KDF parameter, salt
policy, or encoding silently redefines every wallet already derived under it.
Both `defineDerivationProfile` and `defineIdentityCodec` freeze what they
return, but the real enforcement is the review rule: a change is a new id. See
[the protocol](PROTOCOL.md#versioning).

Whatever you define, round-trip the codec in a test —
`assertCodecRoundTrip(codec, someKey)` — and commit vectors for the profile
before anyone derives a wallet with it.

## Deriving in a client

The same six steps apply to every profile; only the credentials object differs.

1. Encode password input immediately before creating a one-shot worker.
2. Transfer the username, the password bytes, the fixed `applicationId`, the
   exact `networkId`, and — for an `external-32` profile — the 32-byte salt
   published by your own service. The profile object itself is imported inside
   the worker from the chain package; it is never transferred or configured.
3. Derive the public identity for discovery or enrollment.
4. For signing, pass only a typed proposal or vote intent into the worker.
5. Rebuild and display the exact transaction in a trusted confirmation surface.
6. Sign only after confirmation through `signExactMessageUnsafe`, return only
   the signature or signed transaction, terminate the worker, and clear
   caller-owned password bytes.

The SDK rejects a password shorter than 10 characters (Unicode code points) or
longer than 1,024 UTF-8 bytes with `invalid-password`, before any KDF work. Mirror
`MINIMUM_PASSWORD_CHARACTERS` and `MAXIMUM_PASSWORD_BYTES` in the form so the
user hears about it first — counting characters as code points (`[...value].length`
in JavaScript, not `value.length`) — and add a strength check and a common-password
blocklist where a password is created or changed. Do not apply that stricter
policy at sign-in: it would lock existing wallets out. See
[the security model](SECURITY_MODEL.md#password-floor).

Pin the profile in source. A client that accepts a profile id, a codec id, or
KDF parameters from a server response has handed that server a downgrade lever.
When you call `GET /profile` to fetch the salt, validate the published
`profileId`, `codecId`, `algorithm`, `applicationId`, `networkId`, and `kdf`
against your pinned profile object and reject any mismatch — take the salt and
nothing else.

Do not replace an application's random-seed vault with deterministic custody
without an explicit product decision. The deterministic mode has different
recovery and password-guessing properties, and no migration reconciles them.

## Encrypted-vault integrations

Since v0.5.0 the package ships a wallet vault: the seed encrypted under a random
data key, with that data key wrapped once under the vault password and once
under a generated 256-bit recovery code. The format, the cryptography, and the
limits are described in the
[README](../README.md#wallet-vault-and-recovery-code). Two situations use it
differently.

**Your application already generates a random seed.** Do not replace it with a
username/password-derived seed merely to use this package. Derive its public
identity with `deriveKalvoraEd25519IdentityFromSeed` (or the generic
`deriveIdentityFromSeed(seed, codec)` with your own chain's codec). You may keep
your own encryption, or seal the seed with
`createWalletVault({ profile, context, username, password, seed })` to get the
password-plus-recovery-code envelope. The profile there supplies the codec, the
profile id recorded in the envelope, and the scrypt cost used for the password
wrapper; the seed itself is not derived from anything.

**Your users have credential-derived wallets and choose vault storage to keep
the same key through password changes.** Enrol each wallet with
`createWalletVaultFromCredentials` while
the user can still derive it. The seed is derived, sealed, and zeroed inside
that call, and the address the user already has is preserved. From then on the
vault, not re-derivation, is the source of the seed: sign through
`openWalletVaultWithPassword` or `openWalletVaultWithRecoveryCode`, and change
the password with `rewrapWalletVaultPassword`. Once a vault password has been
changed, deriving from the new credentials produces a *different* wallet, so the
client must open the vault instead.

This adopts vault storage for that wallet. An integration that stays with
deterministic derivation changes a password by rebinding the account to the new
password's key with the identity service's opt-in sign-in-key rotation, and can
recover an account with its opt-in recovery keys
([server API](SERVER_API.md#account-changes-and-recovery-keys-opt-in)) or its
opt-in account resets ([server API](SERVER_API.md#account-resets-opt-in)); each
gives the account a new key and never recovers the old one.

In both cases:

- Run vault creation, opening, and re-wrapping in the same kind of one-shot
  worker as derivation. They take the password as bytes, and the callback that
  receives the wallet is synchronous and scoped exactly like `withDerivedWallet`.
- The host stores the vault. It is a plain JSON-serializable object whose header
  (username, address, public key, application, network, profile and codec ids)
  is readable and whose seed and data key are not. Run `parseWalletVault` on
  anything read back from storage before using it. The host never needs the
  vault password or the recovery code. The optional identity server in
  `web2-ish-self-custody/server` can store encrypted vaults in `random-vault`
  mode; see [Account wallet modes](WALLET_MODES.md) for its authorized routes.
- Show the recovery code to the user once, at creation. The vault does not keep
  it, and `rewrapWalletVaultPassword` re-seals with whichever code it is given,
  so pass the user's existing code on a password change to keep their kit valid.
- A user who has lost both the vault password and the recovery code has lost
  that wallet. Anything the product offers at that point is a new wallet, not
  a recovery.

Encryption does not make browser storage safe by itself. Origin binding,
storage and backup of the envelope, access control on who may fetch it, and
lifecycle controls remain the application's responsibility. This split lets
several applications share one address convention and one envelope format
without turning this package into a browser storage or policy layer.

## A sign-in key separate from the wallet

Under the Kalvora profile the key that signs in to your identity service is the
user's wallet, so the service stores every user's wallet address and receives a
wallet signature at every sign-in. An application that must not hold or see
its users' wallets keeps the two apart:

- **The sign-in profile enrolls with the identity service.** Configure the
  service with `signInEd25519ExternalSalt`. The enrolled key is an `S_` sign-in
  key, which no chain accepts; the service stores and verifies only that.
- **The wallet is an application secret of the same run.** Request a label for
  the wallet's master seed and open it with `withKalvoraWalletFromMasterSeed`
  inside the callback. Once the callback returns the secret is zeroed, and the
  helper refuses it (`invalid-seed`) rather than open the all-zero seed's
  wallet. One password entry is one scrypt run for both.
- **A host may back the wallet up with its own E2EE storage.** The SDK stores
  nothing. To keep the same wallet across a password change, the host seals the
  master seed under a key its server never holds and opens the restored seed
  with the same helper.

```ts
import { signInEd25519ExternalSalt, withDerivedWallet } from "web2-ish-self-custody";
import { withKalvoraWalletFromMasterSeed } from "web2-ish-self-custody/chains/kalvora";

const WALLET_SEED = "example-wallet-seed-v1"; // your label, versioned by you

const result = await withDerivedWallet(
  { profile: signInEd25519ExternalSalt, username, password, salt, context },
  (signIn, secrets) => {
    // The sign-in key is the password check: the wallet has none of its own.
    if (signIn.identity.publicKey !== enrolledSignInPublicKey) return { wrongPassword: true };
    return withKalvoraWalletFromMasterSeed(secrets.get(WALLET_SEED)!, (wallet) => ({
      wrongPassword: false,
      address: wallet.identity.address,
      signature: wallet.signExactMessageUnsafe(confirmedTransactionBytes),
    }));
  },
  { applicationSecrets: [WALLET_SEED] },
);
```

That is the `service-deterministic` mode, with the salt from `/profile`. In
`per-account-deterministic` mode take the setup from the challenge instead:
`withAccountWallet(challenge.walletSetup, signInEd25519ExternalSalt, password, useWallet, { applicationSecrets: [WALLET_SEED] })`
passes the same labels through and calls the same callback. `random-vault` mode
refuses the sign-in profile, because a random key leaves no application secret
to derive the wallet from ([wallet modes](WALLET_MODES.md)).

Rules for the pattern:

- **Check the password before any wallet output.** A mistyped password derives
  a different wallet without an error. Compare the run's sign-in public key with
  the one the service enrolled, and stop on a mismatch.
- **Keep wallet material in the worker.** The master seed, the wallet key and
  every copy stay inside the derivation worker and are zeroed before it
  returns. Send the identity service only the sign-in key and its signatures.
  Send nothing derived from the wallet unless the user publishes it on purpose.
- **Sign in without the wallet.** Request the wallet label only for a wallet
  operation, not at sign-in.
- **A password change is a new wallet,** and so is any move to a new sign-in
  profile, unless the host restores a backed-up master seed. The sign-in key
  changes too, and the host rebinds the account to it with `rotateSignInKey`
  (opt-in, `accountSecurity.signInKeyRotation`), signing the
  [account-change message](PROTOCOL.md#part-4--the-account-change-message)
  with the old and the new sign-in key in the same worker.
- **The offline-guessing exposure stays.** The enrolled sign-in public key is a
  password oracle at scrypt cost, and so is the wallet's address once it is
  public to anyone who also knows the username and the public salt. A correct
  guess gives the wallet and the sign-in key together. See
  [the security model](SECURITY_MODEL.md#sign-in-profile).

The construction is in [the protocol](PROTOCOL.md#part-3--the-sign-in-profile).

## Two services, one identity format

Any two applications on the bundled Kalvora profile — say DemocracyOS and a second
product, called Example App here — import the **same** profile object:

```ts
import { kalvoraEd25519ExternalSalt } from "web2-ish-self-custody/chains/kalvora";
```

They therefore share the Ed25519 curve, the `kalvora-ed25519-base58-v1` codec, the
base58 address encoding, the `A_` public-key identifier, the SLIP-0010 step at
`m/44'/5258'/0'/0'/0'`, and the Kalvora `networkId`. A wallet from either is the same kind of object on the same network,
and both are verified by the same `canonicalWalletIdentity` code path.

They do not share wallets. Each runs its own deployment with its own
`serviceProfileId`, its own fixed `applicationId`, and its own immutable 32-byte
public salt:

| | Example App | DemocracyOS |
| --- | --- | --- |
| profile object | `kalvoraEd25519ExternalSalt` | `kalvoraEd25519ExternalSalt` |
| `applicationId` | its own, fixed in source | its own, fixed in source |
| public salt | its own, minted once | its own, minted once |
| resulting wallet for identical credentials | one address | a **different** address |

Both the salt and the `applicationId` are derivation inputs, so identical
credentials produce a different wallet in each service. That is intended, not a
limitation to engineer around: a compromise or an offline guessing attack in one
service reaches only that service's wallets, and neither service can silently
take custody of the other's users. Sharing one namespace would require a single
salt and a single application id — that is, one service wearing two names, with
the blast radius to match.

Every application adopts the profile the same way: pick a stable
`serviceProfileId` and `applicationId`, provision a salt, and never change any
of the three.

## The identity server

`web2-ish-self-custody/server` is the supported implementation of the server half
of any `external-32` profile: salt custody, challenge issuance, signature
verification, and opaque sessions. It is the only part of this package that
touches a database. It never receives a plaintext password or seed; the optional
random-vault mode also stores encrypted vaults. New deployments should choose a
mode using [the account-wallet integration guide](WALLET_MODES.md), which covers
per-account salts, multi-device access, and vault password changes and recovery.

Configuration takes the profile object, not an id. It is the profile of the key
that signs in: a chain's wallet profile, as below, or the chain-neutral sign-in
profile of [A sign-in key separate from the wallet](#a-sign-in-key-separate-from-the-wallet):

```ts
import { kalvoraEd25519ExternalSalt } from "web2-ish-self-custody/chains/kalvora";
import { createIdentityService } from "web2-ish-self-custody/server";

const service = createIdentityService(sql, {
  serviceProfileId: "example-app-password-wallet-v1",
  profile: kalvoraEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-mainnet",
  tablePrefix: "example_identity",
});
```

That single object is where the service gets its KDF parameters, its algorithm
label, and — importantly — its codec. Address and public-key canonicalization
runs through `profile.codec`, so a non-Kalvora deployment uses the same service
unchanged. Serviceability is a policy rather than a list: any profile with
`saltPolicy: "external-32"` whose codec round-trips is accepted, and a profile
that derives its own salt is rejected at construction because it leaves the
server nothing to own.

Prefer this over a hand-rolled salt table. The schema makes the service-profile
row immutable, refuses to silently reissue a salt whose row has been deleted, and
pins the profile id, the codec id, `applicationId`, and `networkId` into database
constraints, so configuration drift fails loudly instead of quietly producing a
second wallet namespace.

What the server module owns:

- the immutable per-service 32-byte public salt and the pinned KDF parameters
- single-use challenges and their replay and expiry state
- public identity records (normalized username, address, public key, codec id, fingerprint)
- opaque session tokens, persisted only as SHA-256 hashes

What stays in the application:

- password entry, worker isolation, and the derivation call itself
- the trusted typed-intent confirmation surface before any signature
- the email provider and its credentials for verification codes (the router
  delivers them through the `emailVerification` option; see
  [Email delivery](SERVER_API.md#email-delivery))
- transport hardening: TLS, CORS, cookie policy, and IP/user-agent hashing

The client half is unchanged by adopting it. A browser still calls
`withDerivedWallet` with the imported profile and the salt the server published;
the server only verifies the resulting signature against an enrolled public key.

A first migration against an empty database mints a fresh random salt, and the
schema then refuses to change it. There is no way to supply or rotate a salt, so
the database that holds it is the wallet namespace: keep it, back it up, and
restore-test it. See
[There is no salt adoption](SERVER_API.md#there-is-no-salt-adoption).

See [the server API reference](SERVER_API.md) for the wire format, the schema and
its invariants, deployment, and threat notes.

## Updating the shared dependency

Every consuming application pins an exact reviewed commit. A profile or codec
implementation must never change in place. An upgrade that adds a chain or a
profile is non-migrating; selecting that new chain or profile for existing users
is a separate product migration with its own enrollment step.

When reviewing an upgrade, the diff that matters most is `src/chains/` and the
committed vectors. A change to a domain string, a KDF parameter, or an encoding
that is not accompanied by a new id is a defect, regardless of how the commit
message describes it.
