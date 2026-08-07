# Security policy

## Current status

This package is an unaudited pre-1.0 implementation. Do not represent it as audited or production-qualified.

## Direct-seed ZERA identity helper

`web2-ish-self-custody/zera-ed25519` accepts an existing 32-byte seed only long
enough to derive its public Ed25519 identity. It copies and clears its
SDK-owned seed buffer and does not mutate the caller's buffer. It intentionally
does not generate, persist, encrypt, recover, or sign with private material.

Using this helper does not make browser storage secure. The consuming
application must keep random generation, authenticated encryption, KDF
isolation, origin binding, recovery, persistence checks, and lifecycle
invalidation inside its own reviewed custody boundary.

## Server module threat boundary

`web2-ish-self-custody/server` is the only part of this package that touches a
database. Its boundary is deliberately narrow.

The server never receives, and therefore cannot store or leak:

- a password, or any hash or transform of one — there is no password column
- a wallet seed, private key, or secret scalar
- a ciphertext, encrypted vault, or key-escrow blob of any kind

There is no recovery path for wallet material, by design. A request to add one
is a design change, not a bug fix.

The public salt is public but integrity-critical. It is a namespace separator,
not a secret: publishing it is required for clients to derive at all, and
knowing it grants no custody. Its integrity and availability are what matter.
A changed, substituted, or lost salt derives a different wallet for every user
of that service, which is indistinguishable from destroying the accounts. The
schema makes the service-profile row immutable and refuses to reissue a salt
whose row has disappeared, but that only converts silent loss into a loud
failure. The salt must be in backups and its restore must be tested.

Session tokens are stored only as SHA-256 hashes. The plaintext token is
returned once, at issuance, and never again. The `token_hash` column is
constrained to 64 hex characters, so it cannot structurally hold a plaintext
token. Database read access therefore does not yield a usable bearer token, and
email verification codes are stored the same way.

The router's default cookie mode carries the usual ambient-credential exposure.
Its origin gate is opt-in: leaving `trustedOrigins` unset disables the CSRF
check, which is safe only for a deployment with no browser clients. Any
browser-facing deployment must set it. See
[the server API reference](docs/SERVER_API.md#csrf-and-cors).

What database access does yield: normalized usernames, display names, emails
and their verification state, wallet addresses, public keys, fingerprints, the
public salt, hashed session tokens, hashed IP and user-agent values supplied by
the caller, and audit rows. An operator with write access can suspend accounts,
delete sessions, and enroll an attacker-controlled public key against an
existing account — so wallet enrollment records deserve the same monitoring as
any other privileged write. What that operator cannot do is recover, derive, or
sign with any user's wallet, because no material capable of producing one is
present. Their remaining path to a specific wallet is an offline guessing
attack against a known public identity, which is the same attack any holder of
the public identity already has, and is bounded by password entropy and the
profile's scrypt cost rather than by any server-side control.

## Reporting

Do not open a public issue for a suspected vulnerability. Contact the repository owner privately through their GitHub profile until a dedicated security contact is published.

Include:

- affected profile and version
- minimal reproduction
- expected impact
- whether any real wallet material was involved

Never send a real username/password pair, seed, private key, recovery secret, signed transaction, or funded test vector.

## Non-vulnerability limitations

These are intentional properties, not bugs:

- public identities make offline password verification possible
- forgotten credentials are not recoverable by this SDK
- credential or profile changes derive a different wallet
- JavaScript strings cannot be reliably zeroized
- callers can copy callback-scoped data before cleanup
- exact-byte signing is unsafe unless the consumer locally reconstructs and confirms a typed operation
- hostile same-origin code, extensions, browsers, or operating systems are outside the SDK trust boundary

## Release requirements

Before funded use:

1. independently review the exact source and locked dependency graph
2. reproduce vectors in an independent implementation
3. benchmark KDF denial-of-service and memory behavior on minimum supported devices
4. run the SDK only inside a short-lived dedicated worker; SDK cancellation waits for the current KDF to cleanly finish, while immediate cancellation requires terminating that worker
5. provide a trusted, typed signing confirmation surface
6. pin an immutable package commit or verified package provenance
