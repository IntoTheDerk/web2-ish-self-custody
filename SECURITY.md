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
