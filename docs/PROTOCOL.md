# Protocol

Built-in profiles are immutable derivation protocols. This document is descriptive; the committed source and vectors are the exact implementation contract.

## DemocracyOS web-v2 compatibility

Profile: `democracyos-scrypt-sha512-secp256k1-v2`

1. Normalize the username with JavaScript `trim().toLowerCase()`.
2. Compute SHA-512 over the UTF-8 domain `DemocracyOS password wallet password hash v2\n` followed by the exact password bytes.
3. Hex-encode that hash.
4. Compute SHA-512 over `DemocracyOS password wallet entropy v2\n`, normalized username, newline, and the hex hash.
5. Run scrypt with the exact external 32-byte salt and `N=32768, r=8, p=1, dkLen=32`.
6. Interpret the output as a secp256k1 secret scalar and fail if invalid.
7. Encode the compressed public key as lowercase hex.
8. Address: `zera:` plus the first 20 bytes of SHA-256(public key), lowercase hex.
9. Signing retains DemocracyOS web-v2 `@noble/secp256k1` default SHA-256 prehash behavior over an exact 32-byte challenge digest.

## Stateless ZERA Ed25519 v1

Profile: `web2ish-zera-ed25519-v1`

1. Trim ASCII whitespace, lowercase ASCII A–Z, and require 3–120 printable ASCII characters.
2. Require 24–1,024 password bytes.
3. SHA-512 the password with the fixed password domain.
4. SHA-512 a newline-delimited transcript containing the fixed entropy domain, canonical application ID, canonical network ID, normalized username, and password-hash hex.
5. Derive the public 32-byte salt as SHA-256 of the fixed salt domain, application ID, network ID, and normalized username.
6. Run scrypt with `N=65536, r=8, p=1, dkLen=32`.
7. Use the output as an Ed25519 seed.
8. Address: Base58 of the raw 32-byte public key.
9. Public key identifier: `A_<address>`.
10. Sign exact message bytes with Ed25519 only after the consuming application has locally reconstructed and confirmed a typed operation.

## Versioning

Changing any byte of a derivation transcript, normalization rule, KDF parameter, salt policy, curve rule, or public identity encoding requires a new profile ID. Existing profile behavior must never be silently upgraded.

## Independent vector verification

`scripts/verify_zera_vector.py` independently reconstructs both committed
profile vectors with Python's standard-library `hashlib` and the separately
maintained `cryptography` EC implementations. It does not import or execute the
TypeScript SDK. The verifier fails on missing, unexpected, duplicate,
incorrectly typed, or incorrectly encoded fixture fields.

For DemocracyOS, it checks username normalization, both SHA-512 transcripts,
the external salt and scrypt result through the compressed secp256k1 public
key, address construction, challenge digest, and the committed compact
signature. Signature verification explicitly applies SHA-256 to the committed
32-byte challenge digest a second time, matching Noble's default prehash, then
converts `r || s` to DER for independent verification.

For ZERA Ed25519, it checks normalization, both domain-separated transcripts,
the public salt, scrypt result through the public key, Base58 identity encoding,
the deterministic signature, and public-key verification.

This provides cross-implementation regression evidence for the two committed
test vectors. It does not constitute a cryptographic audit, prove browser or
deployment safety, assess credential entropy, or replace additional vectors
and external review before funded use.
