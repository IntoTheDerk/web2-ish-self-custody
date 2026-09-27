# Integration

This package is a generic Ed25519 deterministic-custody core plus a pluggable
chain. Integrating it means answering three questions in order:

1. **Which chain?** That decides the `IdentityCodec` — how a public key becomes
   an address. ZERA ships in the box at `web2-ish-self-custody/chains/zera`.
2. **Which profile of that chain?** That decides the transcript and, in
   particular, where the scrypt salt comes from.
3. **Which namespace?** Your `applicationId`, your `networkId`, and — for a
   service-salted profile — your own 32-byte public salt.

The core has no profile registry. You import the profile object from the chain
package and pass it in. There is no id string for a server, an environment
variable, or a config file to swap out from under you.

## Choosing what to import

| you need | import | from |
| --- | --- | --- |
| a wallet from credentials alone, with no server to consult | `zeraEd25519` | `web2-ish-self-custody/chains/zera` |
| a wallet whose namespace your service owns and can separate from every other service | `zeraEd25519ExternalSalt` | `web2-ish-self-custody/chains/zera` |
| a public identity for a seed you already generated randomly | `deriveZeraEd25519IdentityFromSeed` | `web2-ish-self-custody/chains/zera` |
| a seed that survives a password change, with a recovery code | `createWalletVault`, `createWalletVaultFromCredentials`, and the other vault functions | `web2-ish-self-custody` |
| the server half of a service-salted profile | `createIdentityService` and friends | `web2-ish-self-custody/server` |

The two derivation profiles are not interchangeable. Selecting a different one
for an existing user derives a different wallet, which is a product migration
with an enrollment step, never a configuration change.

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
The two bundled ZERA profiles are exactly this — one codec, two transcripts.

**Reuse an existing profile** when you want the same wallet family and only your
namespace differs. Two services on `zeraEd25519ExternalSalt` with different
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
identity with `deriveZeraEd25519IdentityFromSeed` (or the generic
`deriveIdentityFromSeed(seed, codec)` with your own chain's codec). You may keep
your own encryption, or seal the seed with
`createWalletVault({ profile, context, username, password, seed })` to get the
password-plus-recovery-code envelope. The profile there supplies the codec, the
profile id recorded in the envelope, and the scrypt cost used for the password
wrapper; the seed itself is not derived from anything.

**Your users have credential-derived wallets and need password changes or a
recovery path.** Enrol each wallet with `createWalletVaultFromCredentials` while
the user can still derive it. The seed is derived, sealed, and zeroed inside
that call, and the address the user already has is preserved. From then on the
vault, not re-derivation, is the source of the seed: sign through
`openWalletVaultWithPassword` or `openWalletVaultWithRecoveryCode`, and change
the password with `rewrapWalletVaultPassword`. Once a vault password has been
changed, deriving from the new credentials produces a *different* wallet, so the
client must open the vault instead.

In both cases:

- Run vault creation, opening, and re-wrapping in the same kind of one-shot
  worker as derivation. They take the password as bytes, and the callback that
  receives the wallet is synchronous and scoped exactly like `withDerivedWallet`.
- The host stores the vault. It is a plain JSON-serializable object whose header
  (username, address, public key, application, network, profile and codec ids)
  is readable and whose seed and data key are not. Run `parseWalletVault` on
  anything read back from storage before using it. The host never needs the
  vault password or the recovery code, and the identity server module in
  `web2-ish-self-custody/server` does not store vaults.
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

## Two services, one identity format

Knight Armor and DemocracyOS both import the **same** profile object:

```ts
import { zeraEd25519ExternalSalt } from "web2-ish-self-custody/chains/zera";
```

They therefore share the Ed25519 curve, the `zera-ed25519-base58-v1` codec, the
base58 address encoding, the `A_` public-key identifier, and the ZERA
`networkId`. A wallet from either is the same kind of object on the same network,
and both are verified by the same `canonicalWalletIdentity` code path.

They do not share wallets. Each runs its own deployment with its own
`serviceProfileId`, its own fixed `applicationId`, and its own immutable 32-byte
public salt:

| | Knight Armor | DemocracyOS |
| --- | --- | --- |
| profile object | `zeraEd25519ExternalSalt` | `zeraEd25519ExternalSalt` |
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

Applications outside these two adopt the profile the same way: pick a stable
`serviceProfileId` and `applicationId`, provision a salt, and never change any
of the three.

## The identity server

`web2-ish-self-custody/server` is the supported implementation of the server half
of any `external-32` profile: salt custody, challenge issuance, signature
verification, and opaque sessions. It is the only part of this package that
touches a database, and it never receives a password, a seed, or a ciphertext.

Configuration takes the profile object, not an id:

```ts
import { zeraEd25519ExternalSalt } from "web2-ish-self-custody/chains/zera";
import { createIdentityService } from "web2-ish-self-custody/server";

const service = createIdentityService(sql, {
  serviceProfileId: "knight-armor",
  profile: zeraEd25519ExternalSalt,
  applicationId: "knight-armor",
  networkId: "zera-mainnet",
  tablePrefix: "knight_armor_identity",
});
```

That single object is where the service gets its KDF parameters, its algorithm
label, and — importantly — its codec. Address and public-key canonicalization
runs through `profile.codec`, so a non-ZERA deployment uses the same service
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
- email delivery for verification codes (the module mints the code only)
- transport hardening: TLS, CORS, cookie policy, and IP/user-agent hashing

The client half is unchanged by adopting it. A browser still calls
`withDerivedWallet` with the imported profile and the salt the server published;
the server only verifies the resulting signature against an enrolled public key.

A deployment that already has live wallets under an existing salt must adopt that
salt before its first `migrate()` call, or every existing user's wallet becomes
unreachable. A first migration against an empty database mints a fresh random
salt and the schema then refuses to change it. See
[Adopting an existing salt](SERVER_API.md#adopting-an-existing-salt).

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
