# Integration

## Choosing a profile

| you need | use |
| --- | --- |
| a wallet from credentials alone, with no server to consult | `web2ish-zera-ed25519-v1` |
| a wallet whose namespace your service owns and can separate from every other service | `web2ish-zera-ed25519-external-salt-v1` |
| a public identity for a seed you already generated randomly | `web2-ish-self-custody/zera-ed25519` |

The two derivation profiles are not interchangeable. Selecting a different one
for an existing user derives a different wallet, which is a product migration
with an enrollment step, never a configuration change.

## Random encrypted-vault integrations

Applications that already create a random wallet seed should not replace it with
a username/password-derived seed merely to use this package. The recovery and
password-guessing properties are materially different.

Use `web2-ish-self-custody/zera-ed25519` only to derive the public ZERA identity
from an application-owned random seed. Keep encryption, storage, recovery, origin
binding, and lifecycle controls in the application. This split lets several
applications share the exact Ed25519/Base58/`A_` identity convention without
turning this SDK into a browser storage or policy layer.

## Deriving in a client

The same six steps apply to both derivation profiles; only the credentials
object differs.

1. Encode password input immediately before creating a one-shot worker.
2. Transfer the username, the password bytes, the pinned profile ID, the fixed
   `applicationId`, the exact ZERA `networkId`, and — for the external-salt
   profile — the 32-byte salt published by your own service.
3. Derive the public identity for discovery or enrollment.
4. For signing, pass only a typed proposal or vote intent into the worker.
5. Rebuild and display the exact transaction in a trusted confirmation surface.
6. Sign only after confirmation through `signExactMessageUnsafe`, return only
   the signature or signed transaction, terminate the worker, and clear
   caller-owned password bytes.

Pin the profile in source. A client that accepts a profile ID or KDF parameters
from a server response has handed that server a downgrade lever; validate the
published profile against pinned expectations and reject any mismatch.

Do not replace an application's random-seed vault with deterministic custody
without an explicit product decision. The deterministic mode has different
recovery and password-guessing properties, and no migration reconciles them.

## Two services, one identity format

Knight Armor and DemocracyOS both run on
`web2ish-zera-ed25519-external-salt-v1`. They share the Ed25519 curve, the
Base58 address encoding, the `A_` public-key identifier, and the ZERA
`networkId` — so a wallet from either is the same kind of object on the same
network.

They do not share wallets. Each service runs its own deployment with its own
`serviceProfileId`, its own fixed `applicationId`, and its own immutable 32-byte
public salt. Because the salt and the application ID are both derivation inputs,
identical credentials produce a *different* wallet in each service.

That separation is the intended design, not a limitation to engineer around. It
means a compromise or an offline guessing attack in one service reaches only
that service's wallets, and it means neither service can silently take custody
of the other's users. Sharing one namespace across both would require a single
salt and a single application ID — that is, one service wearing two names, with
the blast radius to match.

Applications outside these two adopt the profile the same way: pick a stable
`serviceProfileId` and `applicationId`, provision a salt, and never change any
of the three.

## The identity server

`web2-ish-self-custody/server` is the supported implementation of the
external-salt profile's server half: salt custody, challenge issuance, signature
verification, and opaque sessions. It is the only part of this package that
touches a database, and it never receives a password, a seed, or a ciphertext.

Prefer it over a hand-rolled salt table. The schema makes the service-profile
row immutable, refuses to silently reissue a salt whose row has been deleted,
and pins `profileId`, `applicationId`, and `networkId` into database constraints,
so configuration drift fails loudly instead of quietly producing a second wallet
namespace.

What the server module owns:

- the immutable per-service 32-byte public salt and the pinned KDF parameters
- single-use challenges and their replay and expiry state
- public identity records (normalized username, address, public key, fingerprint)
- opaque session tokens, persisted only as SHA-256 hashes

What stays in the application:

- password entry, worker isolation, and the derivation call itself
- the trusted typed-intent confirmation surface before any signature
- email delivery for verification codes (the module mints the code only)
- transport hardening: TLS, CORS, cookie policy, and IP/user-agent hashing

The client half is unchanged by adopting it. A browser still calls
`withDerivedWallet` with the pinned profile and the salt the server published;
the server only verifies the resulting signature against an enrolled public key.

A deployment that already has live wallets under an existing salt must adopt
that salt before its first `migrate()` call, or every existing user's wallet
becomes unreachable. A first migration against an empty database mints a fresh
random salt and the schema then refuses to change it. See
[Adopting an existing salt](SERVER_API.md#adopting-an-existing-salt).

See [the server API reference](SERVER_API.md) for the wire format, the schema
and its invariants, deployment, and threat notes.

## Updating the shared dependency

Every consuming application pins an exact reviewed commit. A profile
implementation must never change in place. An SDK upgrade that adds a profile is
non-migrating; selecting that new profile is a separate product migration with
its own enrollment step.
