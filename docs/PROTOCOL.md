# Protocol

This document is the wire specification. It has two layers:

1. **The generic transcript** — the rule every profile follows, parameterized
   over that profile's domain-separation strings, salt policy, KDF parameters,
   and optional key-derivation step. It contains no chain-specific value.
2. **The Kalvora instance** — the exact literal constants that turn the generic
   rule into the bundled Kalvora profile.

Someone should be able to reimplement either layer from this document alone:
part 1 to support a new chain, part 2 to reproduce the committed Kalvora vector
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
| `keyDerivation` | `{ id, deriveKey }` \| absent | chain-supplied step from the scrypt output to the wallet key |
| `codec` | `IdentityCodec` | how a public key becomes an address and an identifier |

**Domain strings are part of the wallet definition, not formatting.** Change one
byte of one of them and the same credentials derive a different key, which is
indistinguishable from destroying every wallet in that family. A different
transcript is therefore always a new profile id — never an edit to an existing
one. The same rule applies to the KDF parameters, the salt policy, the
key-derivation step, the normalization rules, and the codec.

### Profile validation

`defineDerivationProfile` rejects a profile rather than trusting it. An
independent implementation should enforce the same floor:

- `id` matches `^[a-z0-9][a-z0-9._-]{2,79}$`.
- `curve` is exactly `ed25519`.
- `kdf.N` is an integer power of two and at least 65536.
- `kdf.r` is an integer at least 8.
- `kdf.p` is an integer at least 1.
- `kdf.dkLen` is exactly 32 — the output is the Ed25519 seed, or the master
  seed of the key-derivation step when the profile has one.
- `domains.passwordHash` and `domains.entropy` are each 1–200 characters.
- `saltPolicy: "derived-from-username"` requires `domains.salt`.
- `saltPolicy: "external-32"` forbids `domains.salt`, because such a profile
  never derives a salt and a stray domain would imply otherwise.
- `keyDerivation`, when present, has a 1–200 character `id` and a `deriveKey`
  function.

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
masterSeed = scrypt(password = walletEntropy, salt = salt,
                    N = kdf.N, r = kdf.r, p = kdf.p, dkLen = kdf.dkLen)
```

The 64-byte `walletEntropy` is the scrypt password input and the 32-byte salt is
the scrypt salt input. `dkLen` is fixed at 32, so the result is 32 bytes with no
truncation or expansion. At `N = 65536, r = 8`
scrypt requires roughly 64 MiB of working memory, so implementations that impose
a `maxmem` limit must raise it accordingly.

### 5. Key derivation

```
seed = profile.keyDerivation ? profile.keyDerivation.deriveKey(masterSeed)
                             : masterSeed
```

A profile without `keyDerivation` uses the scrypt output as the Ed25519 seed
directly. A profile with one hands the step its own copy of `masterSeed` and
requires exactly 32 bytes back; anything else, or a thrown error, fails the
derivation with `invalid-profile`. The core zeroes `masterSeed` and the copy
afterwards.

The step is how a chain binds its own key structure into the wallet — the
bundled Kalvora profile uses it for SLIP-0010 at SLIP-44 coin type 5258. The
core does not know what the step computes; `keyDerivation.id` names it so it
can be pinned and reviewed like every other profile field. A profile used with
[application secrets](#application-secrets) needs a step that is one-way:
`masterSeed` must not be recoverable from its output.

### 6. Identity encoding

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

## Application secrets

An application can ask the same derivation for secrets of its own: one 32-byte
value per label it chooses, computed from the scrypt output of step 4 in the
same run as the wallet.

```ts
withDerivedWallet(credentials, (wallet, secrets) => …, { applicationSecrets: ["example-secret-v1"] })
```

`secrets` is a `ReadonlyMap` from label to secret, in request order, and is
empty when none are requested. Requesting none, the default, computes nothing
beyond the wallet, and the wallet is the same either way.

### Construction

Write `D_app` for the core-wide domain string
`web2-ish-self-custody application secret v1` (43 bytes, UTF-8, no trailing
newline). It is not a profile field: every profile uses the same one.

```
PRK    = HMAC-SHA256( key = utf8(D_app), data = masterSeed )            HKDF-Extract, salt = utf8(D_app)
info   = utf8( D_app ‖ "\n" ‖ profile.id ‖ "\n" ‖ applicationId ‖ "\n" ‖ networkId ‖ "\n" ‖
               normalizedUsername ‖ "\n" ‖ label )
secret = HKDF-Expand-SHA256( PRK, info, L = 32 )  =  HMAC-SHA256( PRK, info ‖ 0x01 )
```

- `masterSeed` is the 32-byte output of [step 4](#4-scrypt), before the
  profile's key-derivation step. `applicationId` and `networkId` are the
  canonical context values, `normalizedUsername` is the normalized username, and
  `profile.id` is the profile's id. HKDF is RFC 5869 with SHA-256.
- `info` has six lines joined by a single `\n` and no trailing newline. The
  profile id, the context values, the normalized username and the label each
  come from an alphabet without a line break, so `info` is unambiguous.
- The profile id is in `info` although it is not in the wallet transcript. Two
  profiles that share a transcript derive the same wallet but different
  secrets.

### Labels

- A label must match `^[a-z0-9][a-z0-9._:-]{2,79}$`: 3 to 80 characters,
  starting with an ASCII letter or digit. It is not canonicalized, so an
  uppercase label is rejected rather than folded.
- Labels in one request must be unique.
- Both rules fail with `invalid-secret-label` before any KDF work, as does an
  options value that is not an object or an `applicationSecrets` that is not an
  array.
- Each secret depends only on its own label. Request order, and which other
  labels are requested, change nothing.
- The application owns its labels. A label names one secret for good, so an
  application versions its labels itself (`example-secret-v1`), and a new label
  is a new, independent secret.

### Why the scrypt output, and not the wallet key

- **The wallet key is meant to leave.** Step 5's output is the chain's wallet
  key. For Kalvora it is kalvora.js's own wallet key, so it can be exported to
  any wallet that holds the same key. A secret derived from the wallet key would
  be known to every holder of that key.
- **Independence in both directions.** The Kalvora key-derivation step is a
  chain of hardened HMAC-SHA512 from `masterSeed`, which does not reveal
  `masterSeed` from the key it outputs. A holder of the wallet key, or of any
  number of its signatures, therefore cannot compute a secret. This direction
  holds only because the step is one-way (see the refusals below). HKDF output
  reveals neither `PRK` nor `masterSeed`, so a holder of one secret cannot
  compute the wallet key or another label's secret. A secret is not a
  signature, and the identity service never receives one.
- **One stretch.** Secrets cost no second password stretch. A second one would
  add no offline resistance, because the public key is already an oracle for the
  password at scrypt cost (see [the security model](SECURITY_MODEL.md)).

### Refusal without a one-way key-derivation step

Secrets are independent of the wallet key only when the profile's
key-derivation step is one-way. The core cannot check that, so it refuses the
two cases it can recognise, both with `secret-unavailable`:

- **No step.** A profile without `keyDerivation` uses `masterSeed` itself as
  the wallet key ([step 5](#5-key-derivation)), so a secret derived from it
  would be a function of the wallet key. This refusal comes before any KDF
  work.
- **A step that returns `masterSeed` unchanged.** The wallet key would again
  be `masterSeed`. The core can only see this once scrypt has run, so this
  refusal comes after it, and the step's output is zeroed before it throws.

Any other invertible step (an XOR, a permutation, or anything else from which
`masterSeed` can be recomputed) is accepted by the core, and a holder of that
profile's wallet key can compute every one of its secrets. Such a profile must
not be used with application secrets. The bundled Kalvora profile's step is
hardened SLIP-0010, which is one-way.

An empty request is not a request: `applicationSecrets: []` derives the wallet
as usual under any profile.

### Lifetime and scope

- `PRK` is zeroed as soon as the secrets are expanded, before the callback runs.
- The secrets' arrays are zeroed when the callback returns or throws, like the
  seed. A caller that needs a secret afterwards copies it inside the callback
  and zeroes the copy itself.
- Each array is the HMAC output itself (Expand is computed as its one block),
  so the core leaves no other copy of a secret to clear.
- A callback that returns the map, a secret's array, a view of one, or its
  buffer would hand back bytes that are already zero. That fails with
  `wallet-scope-closed` instead, and the arrays are still zeroed.
- Only `withDerivedWallet` derives secrets. The package-internal seed path that
  the wallet vault uses never computes `PRK`, and the vault-opened wallets
  (`openWalletVaultWithPassword`, `openWalletVaultWithRecoveryCode`) take no such
  option: a vault holds a wallet seed, not a `masterSeed`.
- Whatever changes `masterSeed` changes every secret: the password, the
  username, the salt, or the context. So does the profile id. A password change
  therefore yields new secrets, and an application must re-protect whatever it
  sealed under the old ones before the old password is gone.

## Versioning

Changing any byte of a domain string, transcript layout, normalization rule, KDF
parameter, salt policy, curve rule, or codec requires a **new profile id**, and a
change to an encoding requires a new codec id. Published behavior must never be
upgraded in place — a wallet is defined by its profile, so a silent change
destroys every wallet derived under it.

Application secrets are versioned by `D_app`, not by the profile. Changing
`D_app`, the `info` layout, the hash, or the output length is a new domain
string (`… v2`) with its own vector, never an edit, and leaves every wallet and
profile id unchanged.

Adding a profile or a chain is not a migration. Moving an existing user onto a
different one is, and it needs an enrollment step.

---

# Part 2 — the Kalvora instance

Everything below is exported from `web2-ish-self-custody/chains/kalvora`. These are
fixed wire surface, reproduced here exactly as specified.

The key-derivation step and address encoding are computed by
[kalvora.js](https://github.com/IntoTheDerk/kalvora.js) (`kalvora.js/wallet`),
so the wallets here are the wallets kalvora.js derives. Nothing below depends on
kalvora.js to be reproduced: every rule is stated in full, and the Python
verifier implements all of it independently.

## The Kalvora codec

`kalvoraEd25519Codec`, id **`kalvora-ed25519-base58-v1`**. Encoding calls
kalvora.js's `generateKalvoraAddress` and `generateKalvoraPublicKeyIdentifier`
for Ed25519 with no hash types, which produce exactly the values below;
decoding is local and strict.

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
shorter. The committed vector's address is 44 characters and the accepted range
is 32 to 64, so validators should accept a range rather than pin a single length.

## The Kalvora key derivation

`kalvoraSlip10Ed25519`, id **`slip10-ed25519:m/44'/5258'/0'/0'/0'`**: standard
[SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) for
Ed25519, with `masterSeed` as the SLIP-0010 seed, at Kalvora's first wallet path
(SLIP-44 coin type 5258, account 0, change 0, address 0, all hardened):

```
I = HMAC-SHA512(key = utf8("ed25519 seed"), data = masterSeed)
k = I[0:32], c = I[32:64]
for i in (44, 5258, 0, 0, 0):
    I = HMAC-SHA512(key = c, data = 0x00 ‖ k ‖ ser32BE(i + 2^31))
    k = I[0:32], c = I[32:64]
seed = k
```

It calls kalvora.js's `deriveHDPrivateKey(masterSeed, "m/44'/5258'/0'/0'/0'",
ed25519)`, so the result is kalvora.js's first Ed25519 wallet for that seed. The
path is pinned in this package rather than read from kalvora.js, so a kalvora.js
release cannot move it.

## The Kalvora profile

`kalvoraEd25519ExternalSalt` uses `kalvoraEd25519Codec`, the Ed25519 curve, scrypt
`N = 65536, r = 8, p = 1, dkLen = 32`, and `kalvoraSlip10Ed25519`:

| field | value |
| --- | --- |
| `id` | `web2ish-kalvora-ed25519-external-salt-v1` |
| `algorithm` | `scrypt-sha512-slip10-ed25519-external-32-v1` |
| `saltPolicy` | `external-32` |
| `domains.salt` | *(absent)* |
| `keyDerivation.id` | `slip10-ed25519:m/44'/5258'/0'/0'/0'` |

## Retired profiles

These ids and domain strings stay retired: a future profile must not reuse
them.

- `web2ish-zera-ed25519-external-salt-v1` (ZERA, codec
  `zera-ed25519-base58-v1`, entropy domain
  `web2-ish-self-custody ZERA Ed25519 external salt entropy v1`, no
  key-derivation step). Replaced by the Kalvora profile in v0.10.0-alpha.0.
- `web2ish-zera-ed25519-v1` (`derived-from-username`, entropy domain
  `web2-ish-self-custody ZERA Ed25519 entropy v1`, salt domain
  `web2-ish-self-custody public username salt v1`). Removed in v0.9.0.

## Exact domain strings

All UTF-8. Only the password-hash domain carries a trailing newline; the entropy
domain is joined into its transcript with explicit `\n` separators.

| constant | exact value |
| --- | --- |
| `D_pw` | `web2-ish-self-custody password hash v1\n` |
| `D_ent` | `web2-ish-self-custody Kalvora Ed25519 external salt entropy v1` |

The password-hash domain is 39 bytes including its trailing LF (U+000A).

## Fully instantiated derivation

```
passwordHash  = SHA-512( utf8("web2-ish-self-custody password hash v1\n") ‖ passwordBytes )
walletEntropy = SHA-512( utf8(
                  "web2-ish-self-custody Kalvora Ed25519 external salt entropy v1" ‖ "\n" ‖
                  applicationId ‖ "\n" ‖ networkId ‖ "\n" ‖
                  normalizedUsername ‖ "\n" ‖ hex(passwordHash) ) )
salt          = the caller's exact 32 bytes
masterSeed    = scrypt(walletEntropy, salt, N=65536, r=8, p=1, dkLen=32)
seed          = SLIP-0010 Ed25519 key of masterSeed at m/44'/5258'/0'/0'/0'
publicKey     = Ed25519 public key of seed
address       = base58(publicKey)
identifier    = "A_" ‖ address
```

## Test vector

Committed in `vectors/`. **Test-only credentials — never derive a real wallet
from these values.** It uses the password `correct horse battery staple lantern
orbit` (42 characters, 42 UTF-8 bytes) and the username `JESSE@example.COM`,
which normalizes to `jesse@example.com`.

`vectors/kalvora-ed25519-external-salt-v1.json`,
`web2ish-kalvora-ed25519-external-salt-v1`, with
`applicationId = example-app` and `networkId = kalvora-mainnet`:

| field | value |
| --- | --- |
| supplied salt | `c3e4bb3c8b5943b3df405f473743e1534bd95ce1ed460a9efd7299f53e16d42a` |
| public key | `a2fadca05e2179c65826d89c7598256a36d43801fe4d089e3389a4b2aff2812f` |
| address | `ByCuowLiVTKHn7b9GbiEw4iRNWE4zRzo6bCxQQSXcDQJ` |
| public key identifier | `A_ByCuowLiVTKHn7b9GbiEw4iRNWE4zRzo6bCxQQSXcDQJ` |
| message | `fixture-governance-intent-kalvora-external-salt-v1` |
| signature | `abcb6d7755da6604f732d97b9d867e102f074b4efc3a6b33dfde3cfb57bef184c873dd33e86d9a240aa8f894390944e8f9b6cbb6281262c965cf1a33924df40a` |

A refactor that changes these values is wrong. The vector is not updated to
match an implementation; the implementation is corrected to match the vector.

### Application-secret vector

`vectors/kalvora-ed25519-external-salt-v1.application-secret-v1.json` uses the
same credentials, salt and wallet as the vector above, with the labels
`example-secret-v1` and `example-secret-v2`. It also commits each `info` string
in full. It is a new file, never regenerated, and the vector above is untouched
by it.

| field | value |
| --- | --- |
| `PRK` | `2ec83c08ebee7664d3afbb267e730e0d97baff96e2f863de36ffa723d8bfbb33` |
| `example-secret-v1` | `80710625947fa570c16a2a28a41f74c8c1570b2311dbbca4d2a62fb09cb6e24f` |
| `example-secret-v2` | `03e18695d24d9dc7dbe1c356a1c389275011ad4ae3a92f246b3c609810f04e9c` |

The `info` of `example-secret-v1`, with each line on its own:

```
web2-ish-self-custody application secret v1
web2ish-kalvora-ed25519-external-salt-v1
example-app
kalvora-mainnet
jesse@example.com
example-secret-v1
```

## Independent vector verification

`scripts/verify_kalvora_external_salt_vector.py` reconstructs the committed vector
from the fixture using Python's standard-library `hashlib` and the separately
maintained `cryptography` package. It does not import or execute the TypeScript
implementation. It checks username normalization, context canonicalization, the
password bounds, the domain-separated transcript, the supplied salt, the scrypt
result, the SLIP-0010 step (its own implementation, first checked against the
SLIP-0010 specification's test vector 1), the public key, the Base58 identity encoding, the deterministic
signature, and signature verification, and it fails on missing, unexpected,
duplicate, incorrectly typed, or incorrectly encoded fixture fields.

The same script loads the application-secret vector as a second fixture, by its
explicit path and with the same strict shape checks (including each entry of
`secrets`). It requires the credential fields to equal the wallet fixture's,
recomputes `masterSeed` and the wallet, and implements HKDF-SHA256 with the
standard library's `hmac`, first checked against RFC 5869 test case 1. It then
checks `PRK`, every label against the label rule and for uniqueness, every
`info` string, and every secret.

This is cross-implementation regression evidence for the committed vector. It
is not a cryptographic audit, does not prove browser or deployment safety, does
not assess credential entropy, and does not replace additional vectors and
external review before funded use.
