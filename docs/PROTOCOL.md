# Protocol

This document is the wire specification. It has two layers:

1. **The generic transcript** — the rule every profile follows, parameterized
   over that profile's domain-separation strings, salt policy, and KDF
   parameters. It contains no chain-specific value.
2. **The ZERA instance** — the exact literal constants that turn the generic
   rule into the two bundled ZERA profiles.

Someone should be able to reimplement either layer from this document alone:
part 1 to support a new chain, part 2 to reproduce the committed ZERA vectors
byte for byte. Where this document and the committed source disagree, the source
and the vectors are the contract.

---

# Part 1 — the generic transcript

## The profile is the specification

A `DerivationProfile` is the complete definition of one wallet family. Nothing
outside it influences derivation.

| field | type | role |
| --- | --- | --- |
| `id` | string | names this exact transcript; recorded with every derived identity |
| `curve` | `"ed25519"` | the only supported curve |
| `algorithm` | string | descriptive label a service records and publishes |
| `saltPolicy` | `"external-32"` \| `"derived-from-username"` | where the scrypt salt comes from |
| `kdf` | `{ N, r, p, dkLen }` | scrypt parameters; `dkLen` is always 32 |
| `domains.passwordHash` | string | prefixed to the raw password bytes |
| `domains.entropy` | string | first line of the entropy transcript |
| `domains.salt` | string \| absent | first line of the salt transcript |
| `codec` | `IdentityCodec` | how a public key becomes an address and an identifier |

**Domain strings are part of the wallet definition, not formatting.** Change one
byte of one of them and the same credentials derive a different key, which is
indistinguishable from destroying every wallet in that family. A different
transcript is therefore always a new profile id — never an edit to an existing
one. The same rule applies to the KDF parameters, the salt policy, the
normalization rules, and the codec.

### Profile validation

`defineDerivationProfile` rejects a profile rather than trusting it. An
independent implementation should enforce the same floor:

- `id` matches `^[a-z0-9][a-z0-9._-]{2,79}$`.
- `curve` is exactly `ed25519`.
- `kdf.N` is an integer power of two and at least 65536.
- `kdf.r` is an integer at least 8.
- `kdf.p` is an integer at least 1.
- `kdf.dkLen` is exactly 32 — the output *is* the Ed25519 seed.
- `domains.passwordHash` and `domains.entropy` are each 1–200 characters.
- `saltPolicy: "derived-from-username"` requires `domains.salt`.
- `saltPolicy: "external-32"` forbids `domains.salt`, because such a profile
  never derives a salt and a stray domain would imply otherwise.

The KDF floor is deliberate. This construction derives a wallet from a human
password, so a profile that lowers the work factor is not a configuration
choice; it is a downgrade.

## The codec contract

An `IdentityCodec` is the only place a chain's encoding lives.

| member | contract |
| --- | --- |
| `id` | matches `^[a-z0-9][a-z0-9._-]{2,63}$`; recorded alongside every enrolled wallet |
| `encodeAddress(publicKeyBytes)` | the canonical public address for a raw 32-byte Ed25519 public key |
| `encodePublicKey(publicKeyBytes)` | the canonical wire identifier; may differ from the address when a chain tags its keys |
| `decodePublicKey(identifier)` | the inverse of `encodePublicKey`; **must throw** on anything malformed rather than coercing or truncating |

Two properties are load-bearing and are checked rather than assumed:

- **Round-trip.** `decodePublicKey(encodePublicKey(k))` must equal `k` for every
  32-byte `k`. `assertCodecRoundTrip(codec, k)` performs exactly this check; the
  identity service runs it at startup.
- **Injectivity.** Two distinct public keys must not encode to the same address.
  The address is what a server binds an account to; a collision there is a
  custody failure, not a display bug.

## Inputs

### Username

The username is a derivation input, so its normalization must be exactly
reproducible on every platform and in every locale:

1. Remove leading and trailing runs of ASCII whitespace — U+0009, U+000A,
   U+000C, U+000D, and U+0020. No other code point is treated as whitespace.
2. Map ASCII `A`–`Z` (U+0041–U+005A) to `a`–`z`. No other code point changes
   case.
3. Require the result to match `^[\x21-\x7e]{3,120}$`: 3 to 120 printable
   non-space ASCII characters.

Step 2 is deliberately not a Unicode or locale-aware case fold. `toLowerCase`
is locale-sensitive — Turkish dotted `I` being the classic case — and a username
that folds differently on two devices derives two different wallets. Step 3 is
what makes the ASCII-only rule safe to promise: anything outside printable ASCII
is rejected rather than silently folded. It also guarantees the normalized
username contains no line break, which the newline-delimited transcripts below
depend on for unambiguity.

These rules are core-wide. A profile does not get to vary them.

### Password

The password is supplied as raw bytes, not as a string: the UTF-8 encoding of
what the user typed. No normalization, trimming, case folding, or Unicode
normalization is applied; the exact bytes are hashed. The bounds are core-wide:

- The bytes must be well-formed UTF-8 (Unicode §3.9: no overlong forms, no
  surrogate code points, nothing above U+10FFFF, no truncated sequence).
- They must decode to at least **10 characters**, counted as Unicode code
  points. Because nothing is normalized, that is the code-point count of exactly
  the bytes that are hashed: a space counts, a combining mark counts separately
  from the letter it modifies, and a leading U+FEFF counts rather than being
  stripped as a byte-order mark.
- They must be at most **1,024 bytes**. The ceiling is on the encoded bytes,
  which is what the KDF consumes.

The floor is a length check, not a strength check. A ten-character password can
still be one an offline attacker tries early; the application that lets a user
choose a password owns the strength policy (see
[the security model](SECURITY_MODEL.md)).

These bounds are validation only. They are not part of the transcript, so
changing them does not change what any accepted password derives.

### Derivation context

`applicationId` and `networkId` are each canonicalized by trimming surrounding
whitespace and lowercasing, then required to match:

```
^[a-z0-9][a-z0-9._:-]{0,79}$
```

That is 1 to 80 characters, starting with an ASCII alphanumeric, from the
alphabet `a-z0-9._:-`. Because the accepted output alphabet is ASCII, an
implementation may equivalently require callers to supply the canonical form and
reject anything else.

### Salt

Governed entirely by `saltPolicy`:

| policy | rule |
| --- | --- |
| `external-32` | the caller supplies **exactly** 32 bytes; 31 or 33 is an error, never something to pad or truncate. A caller-supplied salt is required. |
| `derived-from-username` | the salt is computed in step 3 below. A caller-supplied salt is **rejected outright** rather than ignored. |

An external salt is public derivation metadata — a namespace separator, not
credential entropy and not a secret.

## Derivation

Write `D_pw` for `profile.domains.passwordHash`, `D_ent` for
`profile.domains.entropy`, and `D_salt` for `profile.domains.salt`. All strings
are encoded as UTF-8.

### 1. Password hash

```
passwordHash = SHA-512( utf8(D_pw) ‖ passwordBytes )
```

Byte concatenation with **no separator**. Any separator a profile wants must be
the trailing character of `D_pw` itself — which is why the bundled profiles end
that domain with a newline. Result: 64 bytes.

### 2. Wallet entropy

Join five lines with a single `\n` (U+000A), encode as UTF-8, and hash:

```
line 1  D_ent
line 2  <canonical applicationId>
line 3  <canonical networkId>
line 4  <normalized username>
line 5  <passwordHash as 128 lowercase hex characters>
```

```
walletEntropy = SHA-512( utf8(line1 ‖ "\n" ‖ line2 ‖ "\n" ‖ line3 ‖ "\n" ‖ line4 ‖ "\n" ‖ line5) )
```

No trailing newline. Result: 64 bytes. Line 5 is lowercase hex of the raw
`passwordHash` bytes, not the bytes themselves — an implementation that
concatenates raw bytes here derives a different wallet.

The application and network stay in this transcript under **every** salt policy,
even though an external salt should already be service-specific. That makes
service and network separation explicit and keeps an accidental salt collision
from collapsing two derivation domains into one.

### 3. Salt

For `external-32`, the salt is the caller's 32 bytes, used verbatim.

For `derived-from-username`, join four lines with `\n` and hash:

```
line 1  D_salt
line 2  <canonical applicationId>
line 3  <canonical networkId>
line 4  <normalized username>
```

```
salt = SHA-256( utf8(line1 ‖ "\n" ‖ line2 ‖ "\n" ‖ line3 ‖ "\n" ‖ line4) )
```

Result: 32 bytes. This salt is a public function of public inputs. It separates
namespaces; it adds no secrecy.

### 4. scrypt

```
seed = scrypt(password = walletEntropy, salt = salt,
              N = kdf.N, r = kdf.r, p = kdf.p, dkLen = kdf.dkLen)
```

The 64-byte `walletEntropy` is the scrypt password input and the 32-byte salt is
the scrypt salt input. Because `dkLen` is fixed at 32, the result **is** the
Ed25519 seed; there is no truncation or expansion step. At `N = 65536, r = 8`
scrypt requires roughly 64 MiB of working memory, so implementations that impose
a `maxmem` limit must raise it accordingly.

### 5. Identity encoding

The 32-byte seed is an Ed25519 private key per RFC 8032. Derive the 32-byte
encoded public key from it in the standard way, then hand that public key to the
profile's codec.

| field | rule |
| --- | --- |
| `publicKeyBytes` | the raw 32-byte Ed25519 public key |
| `address` | `codec.encodeAddress(publicKeyBytes)` |
| `publicKey` | `codec.encodePublicKey(publicKeyBytes)` |
| `curve` | the literal `ed25519` |
| `profileId` | `profile.id` |
| `codecId` | `profile.codec.id` |
| `normalizedUsername` | the value from the username rules above |
| `fingerprint` | display aid, see below |

`fingerprint` is computed from `address` by the core, not by the codec: drop
every character that is not ASCII alphanumeric, uppercase the rest, take the
first 16 characters, and insert a single space after each group of 4. It is a
human-comparison aid only and must never be checked in place of the address.

`codecId` travels with the identity so a deployment can always tell which
encoding produced a stored address.

## Signing

Signatures are Ed25519 as specified in RFC 8032 — PureEdDSA, deterministic, no
prehash, no context string — over the exact message bytes, producing 64 bytes.
On the wire the identity service encodes them as 128 lowercase hex characters.

The core accepts messages of 1 to 1,048,576 bytes. The signing method is named
`signExactMessageUnsafe` because it signs precisely what it is handed: it is the
primitive needed to sign exact transaction bytes, not permission to sign bytes
supplied by a server or an untrusted renderer. A consuming application must
locally reconstruct the typed operation, display a trusted confirmation, and
only then pass the verified bytes to the scoped signer.

The authentication challenge format that `web2-ish-self-custody/server` issues is
a separate, layered specification; see
[the server API reference](SERVER_API.md#challenge-message-format).

## Versioning

Changing any byte of a domain string, transcript layout, normalization rule, KDF
parameter, salt policy, curve rule, or codec requires a **new profile id**, and a
change to an encoding requires a new codec id. Published behavior must never be
upgraded in place — a wallet is defined by its profile, so a silent change
destroys every wallet derived under it.

Adding a profile or a chain is not a migration. Moving an existing user onto a
different one is, and it needs an enrollment step.

---

# Part 2 — the ZERA instance

Everything below is exported from `web2-ish-self-custody/chains/zera`. These are
fixed wire surface, reproduced here exactly as specified.

## The ZERA codec

`zeraEd25519Codec`, id **`zera-ed25519-base58-v1`**.

| member | rule |
| --- | --- |
| `encodeAddress(k)` | Base58 of the raw 32 bytes, Bitcoin alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`, no checksum, no version byte |
| `encodePublicKey(k)` | the literal `A_` followed by `encodeAddress(k)` |
| `decodePublicKey(s)` | as below |

`decodePublicKey` accepts only the canonical identifier form:

1. Trim surrounding whitespace.
2. Require the result to start with `A_`; otherwise throw `invalid-public-key`.
3. Take everything after the **last** `_` as the encoded body.
4. Require the body to match `^[1-9A-HJ-NP-Za-km-z]{32,64}$`.
5. Base58-decode it; a decode failure throws `invalid-public-key`.
6. Require exactly 32 decoded bytes.

Base58 has no fixed output length: a public key with leading zero bytes encodes
shorter. Both committed vectors are 44 characters and the accepted range is 32
to 64, so validators should accept a range rather than pin a single length.

## The two ZERA profiles

Both use `zeraEd25519Codec`, the Ed25519 curve, and scrypt
`N = 65536, r = 8, p = 1, dkLen = 32`. They differ in exactly two things: where
the salt comes from, and the entropy domain that keeps their transcripts apart.

| | `zeraEd25519` | `zeraEd25519ExternalSalt` |
| --- | --- | --- |
| `id` | `web2ish-zera-ed25519-v1` | `web2ish-zera-ed25519-external-salt-v1` |
| `algorithm` | `scrypt-sha512-ed25519-v1` | `scrypt-sha512-ed25519-external-32-v1` |
| `saltPolicy` | `derived-from-username` | `external-32` |
| `domains.salt` | `web2-ish-self-custody public username salt v1` | *(absent)* |

## Exact domain strings

All UTF-8. Only the password-hash domain carries a trailing newline; the others
are joined into transcripts with explicit `\n` separators.

| constant | exact value |
| --- | --- |
| `D_pw`, both profiles | `web2-ish-self-custody password hash v1\n` |
| `D_ent`, `web2ish-zera-ed25519-v1` | `web2-ish-self-custody ZERA Ed25519 entropy v1` |
| `D_ent`, `web2ish-zera-ed25519-external-salt-v1` | `web2-ish-self-custody ZERA Ed25519 external salt entropy v1` |
| `D_salt`, `web2ish-zera-ed25519-v1` only | `web2-ish-self-custody public username salt v1` |

The password-hash domain is 39 bytes including its trailing LF (U+000A). The two
profiles share it deliberately: the password hash is an input to the entropy
transcript, and it is that transcript's own domain that separates them.

## Fully instantiated derivation

For `web2ish-zera-ed25519-external-salt-v1`:

```
passwordHash  = SHA-512( utf8("web2-ish-self-custody password hash v1\n") ‖ passwordBytes )
walletEntropy = SHA-512( utf8(
                  "web2-ish-self-custody ZERA Ed25519 external salt entropy v1" ‖ "\n" ‖
                  applicationId ‖ "\n" ‖ networkId ‖ "\n" ‖
                  normalizedUsername ‖ "\n" ‖ hex(passwordHash) ) )
salt          = the caller's exact 32 bytes
seed          = scrypt(walletEntropy, salt, N=65536, r=8, p=1, dkLen=32)
publicKey     = Ed25519 public key of seed
address       = base58(publicKey)
identifier    = "A_" ‖ address
```

For `web2ish-zera-ed25519-v1`, the entropy domain becomes
`web2-ish-self-custody ZERA Ed25519 entropy v1` and the salt is derived instead
of supplied:

```
salt = SHA-256( utf8(
         "web2-ish-self-custody public username salt v1" ‖ "\n" ‖
         applicationId ‖ "\n" ‖ networkId ‖ "\n" ‖ normalizedUsername ) )
```

## Test vectors

Committed in `vectors/`. **Test-only credentials — never derive a real wallet
from these values.** Both use the password `correct horse battery staple lantern
orbit` (42 characters, 42 UTF-8 bytes) and the username `JESSE@example.COM`, which normalizes
to `jesse@example.com`.

`vectors/built-in-v1.json`, `web2ish-zera-ed25519-v1`, with
`applicationId = knight-armor` and `networkId = zera-mainnet`:

| field | value |
| --- | --- |
| derived salt | `bdd5abf02ffd09a5f88efd8e29a4c9b6706a4aba2a25799d622306568a2c495e` |
| public key | `be286995d02f50aa4e7563b21d1f402c9ba45aa6dbf8abaec772fd8855bc5724` |
| address | `DoJCoim5tijbVDZqeCxRMqT9Aid1bCAjo7tX8PSGjbUX` |
| public key identifier | `A_DoJCoim5tijbVDZqeCxRMqT9Aid1bCAjo7tX8PSGjbUX` |
| message | `fixture-governance-intent-v1` |
| signature | `6fd0c5a4dfbdf54f2d43714b0f7bbc329cc42052a05681511b4423c094265d674d1c25d370024e710919844e41157de1706e9d42b02489e05cd727a68efe2502` |

`vectors/zera-ed25519-external-salt-v1.json`,
`web2ish-zera-ed25519-external-salt-v1`, same application and network:

| field | value |
| --- | --- |
| supplied salt | `c3e4bb3c8b5943b3df405f473743e1534bd95ce1ed460a9efd7299f53e16d42a` |
| public key | `12249679d7d9d24bd28b896a0202c11318b221093913b5107f8fa09eba7f4d28` |
| address | `2DphRgcYxibmCvNmfYtrbpR3HhNuvEDt6WYpUdkSz4yu` |
| public key identifier | `A_2DphRgcYxibmCvNmfYtrbpR3HhNuvEDt6WYpUdkSz4yu` |
| message | `fixture-governance-intent-external-salt-v1` |
| signature | `4db6ed100cdd9963c5a5f1ae120b89dc1e50a69de60bf76db79c3d8dc4d2b507564ab79e50d2f5f61898578efd688d76c5d119365282d9df366915fde123670e` |

The two vectors share credentials, application, and network. Their addresses
differ solely because the salt and the entropy domain differ, which is the
profile separation this specification exists to guarantee.

A refactor that changes these values is wrong. The vectors are not updated to
match an implementation; the implementation is corrected to match the vectors.

## Independent vector verification

`scripts/verify_zera_vector.py` and
`scripts/verify_zera_external_salt_vector.py` reconstruct the committed vectors
from the fixtures using Python's standard-library `hashlib` and the separately
maintained `cryptography` package. Neither imports or executes the TypeScript
implementation. Between them they check username normalization, both
domain-separated transcripts, the salt (derived and supplied), the scrypt
result, the public key, the Base58 identity encoding, the deterministic
signature, and signature verification. Both fail on missing, unexpected,
duplicate, incorrectly typed, or incorrectly encoded fixture fields.

This is cross-implementation regression evidence for the committed vectors. It
is not a cryptographic audit, does not prove browser or deployment safety, does
not assess credential entropy, and does not replace additional vectors and
external review before funded use.
