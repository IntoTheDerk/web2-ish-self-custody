# Protocol

This document is the wire specification. It has four parts:

1. **The generic transcript** — the rule every profile follows, parameterized
   over that profile's domain-separation strings, salt policy, KDF parameters,
   and optional key-derivation step. It contains no chain-specific value.
2. **The Kalvora instance** — the exact literal constants that turn the generic
   rule into the bundled Kalvora profile, and the Kalvora wallet opened from a
   master seed.
3. **The sign-in profile** — the chain-neutral profile whose key signs in to an
   identity service and is not a wallet on any chain, and its successor at a
   higher scrypt cost, the sign-in profile v2.
4. **The account-change message** — the bytes a client signs to change its own
   identity-service account: rotate its enrolled key, change its email, enroll
   or remove a recovery key, or recover the account with one.

Someone should be able to reimplement any part from this document alone: part 1
to support a new chain, parts 2 to 4 to reproduce the committed vectors byte
for byte. Where this document and the committed source disagree, the source and
the vectors are the contract.

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
truncation or expansion. scrypt's working memory is `128 · r · N` bytes: at
`N = 65536, r = 8` roughly 64 MiB, and at the sign-in profile v2's
`N = 262144, r = 8` roughly 256 MiB, so implementations that impose a `maxmem`
limit must raise it accordingly (Python's `hashlib.scrypt` needs `maxmem` above
256 MiB for v2).

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
profile id unchanged. The other direction does not hold: `profile.id` is in
`info`, so a new profile id gives every label a new secret, and so does any
change that needs one. An application that derives a key of lasting value from
a secret, such as the wallet of [Part 3](#part-3--the-sign-in-profile), inherits
the profile's versioning.

The [account-change message](#part-4--the-account-change-message) is versioned
by its domain, `web2-ish-self-custody account change v1`. Changing the line
layout, an existing action's authorizer or subject form, or a principal's
encoding is a new domain string (`… v2`) with its own vector, never an edit. A
release may add new actions and principal forms under v1, each with new vector
cases in a new vector file; it never changes an existing case or edits a
released vector file. Account resets added five actions and four principal
forms this way, in `vectors/account-change-resets-v1.json`.

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

## Kalvora wallet from a master seed

`withKalvoraWalletFromMasterSeed(masterSeed, useWallet)` opens the Kalvora
wallet of a 32-byte SLIP-0010 master seed the caller already holds. No password
derivation runs. It is for an application whose wallet master seed is an
[application secret](#application-secrets), such as one of the
[sign-in profile](#part-3--the-sign-in-profile), or that secret restored from
the application's own encrypted backup.

```
walletKey  = SLIP-0010 Ed25519 key of masterSeed at m/44'/5258'/0'/0'/0'     kalvoraSlip10Ed25519
publicKey  = Ed25519 public key of walletKey
address    = base58(publicKey)                                               kalvoraEd25519Codec
identifier = "A_" ‖ address
```

The key step and the codec are the Kalvora profile's, so this is the key the
Kalvora profile would derive if its scrypt output were `masterSeed`, and
kalvora.js's first wallet for that seed. It is not the Kalvora password wallet
of any credentials: that wallet's master seed is the Kalvora profile's scrypt
output, which is never an application secret.

The callback receives a wallet whose identity has these fields:

| field | value |
| --- | --- |
| `derivation` | `kalvoraSlip10Ed25519.id`, `slip10-ed25519:m/44'/5258'/0'/0'/0'` |
| `codecId` | `kalvora-ed25519-base58-v1` |
| `curve` | `ed25519` |
| `address`, `publicKey`, `publicKeyBytes` | as above |
| `fingerprint` | the core's [fingerprint](#6-identity-encoding) of `address` |

There is no profile id and no username: neither is an input.

- **Input.** `masterSeed` must be a plain `Uint8Array` of exactly 32 bytes,
  not all zero; anything else throws `invalid-seed` before anything is derived.
  - *Plain* means the exact typed-array tag, as `deriveIdentityFromSeed`
    requires, and a prototype that is a realm's `Uint8Array.prototype`. A
    genuine Uint8Array from another realm is accepted; a Buffer or any other
    subclass is refused.
  - The length and the bytes are read from the array's internal slots, never
    through a `byteLength` property or an iterator, which a subclass or an own
    property could replace.
  - *Not all zero*: 32 zero bytes are what an application secret holds once its
    `withDerivedWallet` scope has ended, and that seed's wallet key is public
    knowledge. An honest secret is all-zero with probability 2^-256.

  The caller keeps ownership of `masterSeed` and zeroes it. The helper works
  on an internal copy and zeroes that copy once the key exists.
- **Scope.** The call is synchronous, so it can run inside a `withDerivedWallet`
  callback, and the callback must be synchronous too: a thenable result throws
  `async-wallet-scope`. The node key is zeroed when the callback returns or
  throws, and the signer then throws `wallet-scope-closed`.
- **Signing.** As in [Signing](#signing): Ed25519 over the exact bytes, 1 to
  1,048,576 of them, `invalid-message` otherwise.
- **Versioning.** Nothing here is new wire surface: the path, the key step and
  the codec are the Kalvora profile's and change only under new ids. Which
  master seed an application feeds it is the application's own versioned
  choice (for an application secret, its label).

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

## Account wallet modes

Account mode changes ownership of the external salt, not the derivation
transcript. In `per-account-deterministic` mode, the service assigns an immutable
UUIDv4 account ID and an independent CSPRNG-generated 32-byte public salt before
enrollment. `walletSetup.publicSaltHex` supplies the exact existing `external-32`
salt input. The UUID is metadata, not an additional derivation input. Existing
profile IDs, domain strings, and vectors retain their original meanings.

`random-vault` mode generates a fresh 32-byte Ed25519 seed with secure randomness
and seals it using the existing wallet-vault-v1 envelope. The profile supplies
the codec and wrapper KDF parameters. Its deterministic entropy transcript and
optional key-derivation step are not applied to this random seed.

In `random-vault` mode a password change is a vault re-wrap, which preserves
the encrypted seed and its identity. In the deterministic modes a different
password derives a different key. The identity service can rebind the account
to it, and can recover an account with a recovery key, an emailed code or a
signed-in reset, through opt-in operations authorized over the
[account-change message](#part-4--the-account-change-message): sign-in-key
rotation, recovery keys and account resets. Each replaces the enrolled key;
none recovers the old one, and `random-vault` mode refuses them all. A platform that keys other state
on the enrolled key, such as an on-chain permission held by a wallet, updates
that state itself.

Application secrets and the sign-in profile follow the same split. In
`per-account-deterministic` mode the account salt is the `external-32` salt of
an ordinary derivation, so [application secrets](#application-secrets) come
from the same scrypt run as the enrolled key: `withAccountWallet` forwards
`applicationSecrets` to `withDerivedWallet`, and under the
[sign-in profile](#part-3--the-sign-in-profile) that is how the application gets
its wallet's master seed. `random-vault` mode runs no password derivation, so
there is no `masterSeed` and no application secret; vault-opened wallets take
none ([lifetime and scope](#lifetime-and-scope)). The sign-in profile is
therefore refused in that mode: `createRandomAccountWallet` throws
`invalid-profile`, and the identity service's configuration throws
`invalid-service-profile`.

See [WALLET_MODES.md](WALLET_MODES.md) for storage, multi-device access, vault
password changes, and the platform's authorization responsibilities.

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

It loads the [sign-in vector](#sign-in-test-vector) as a third fixture, by its
explicit path and with the same strict shape checks, nested objects included;
see [its verification](#independent-verification-of-the-sign-in-vector). It
loads the [sign-in v2 vector](#sign-in-v2-test-vector) as a fourth; see
[its verification](#independent-verification-of-the-sign-in-v2-vector).

This is cross-implementation regression evidence for the committed vector. It
is not a cryptographic audit, does not prove browser or deployment safety, does
not assess credential entropy, and does not replace additional vectors and
external review before funded use.

---

# Part 3 — the sign-in profile

Everything below is exported from the core entry `web2-ish-self-custody`, which
imports no chain SDK. These values are fixed wire surface, reproduced here
exactly as specified.

## Why a sign-in profile

An identity service enrolls the key that signs its challenges and stores that
key's public key. Under a chain wallet profile, such as the Kalvora profile, that
key **is** the user's wallet: the service stores a wallet address for every
account and receives a wallet signature at every sign-in.

Under the sign-in profile the enrolled key is a **sign-in key**: an Ed25519 key
whose identifier, `S_` and hex, no chain accepts. An application that also needs
a wallet derives its master seed as an [application secret](#application-secrets)
of the same run and opens it with
[`withKalvoraWalletFromMasterSeed`](#kalvora-wallet-from-a-master-seed). That
costs one password stretch per entry, and the service holds nothing derived
from the wallet.

## The sign-in codec

`signInEd25519Codec`, id **`web2ish-sign-in-ed25519-hex-v1`**.

| member | rule |
| --- | --- |
| `encodeAddress(k)` | the literal `S_` followed by the raw 32 bytes as 64 lowercase hex digits |
| `encodePublicKey(k)` | the same string |
| `decodePublicKey(s)` | accepts exactly `^S_[0-9a-f]{64}$` and returns the 32 bytes |

- Decoding does not trim and does not fold case. Surrounding whitespace, a
  trailing newline, uppercase hex, any other tag, and 63 or 65 digits each throw
  `invalid-public-key`, as does a non-string.
- Encoding requires exactly 32 bytes, and throws `invalid-public-key` otherwise.
- `_` is outside the base58 alphabet and the tag is not Kalvora's `A_`, so no
  Kalvora parser accepts a sign-in identifier, and the Kalvora codec's decoder
  refuses one. The sign-in decoder refuses every Kalvora identifier.
- The identifier is 66 characters. Its [fingerprint](#6-identity-encoding) is
  `S` followed by 15 uppercase hex digits, grouped by four. Both fit the
  identity service's schema checks.

## The sign-in key derivation

`signInHkdfEd25519`, id **`hkdf-sha256-sign-in-key-v1`**: HKDF-SHA256 (RFC 5869)
of the scrypt output, with one domain string `D_s` as both the salt and the
`info`, and L = 32.

```
PRK_s  = HMAC-SHA256( key = utf8(D_s), data = masterSeed )               HKDF-Extract, salt = utf8(D_s)
seed_s = HKDF-Expand-SHA256( PRK_s, info = utf8(D_s), L = 32 )
       = HMAC-SHA256( PRK_s, utf8(D_s) ‖ 0x01 )                          its single block T(1)
```

`D_s` is exported as `SIGN_IN_KEY_DOMAIN`. The step takes exactly the 32-byte
scrypt output (`invalid-seed` otherwise; the core reports any step failure as
`invalid-profile`), computes both HMACs with `hmac` directly, zeroes `PRK_s`
before it returns, and hands back HMAC's own output, which the core zeroes.

The step is one-way, so the profile can be used with application secrets
([refusals](#refusal-without-a-one-way-key-derivation-step) do not apply).
`PRK_s` and the application-secret `PRK` are extracted from the same
`masterSeed` under two different public domain strings, so a holder of the
sign-in key, its public key, or any number of its signatures cannot compute an
application secret, and a holder of a secret cannot compute the sign-in key.

## The sign-in profile

`signInEd25519ExternalSalt` uses `signInEd25519Codec`, the Ed25519 curve, scrypt
`N = 65536, r = 8, p = 1, dkLen = 32` (the package floor and the Kalvora
profile's), and `signInHkdfEd25519`:

| field | value |
| --- | --- |
| `id` | `web2ish-sign-in-ed25519-external-salt-v1` |
| `algorithm` | `scrypt-sha512-hkdf-sha256-ed25519-external-32-v1` |
| `saltPolicy` | `external-32` |
| `domains.salt` | *(absent)* |
| `keyDerivation.id` | `hkdf-sha256-sign-in-key-v1` |
| `codec.id` | `web2ish-sign-in-ed25519-hex-v1` |

All UTF-8. Only the password-hash domain carries a trailing newline:

| constant | exact value |
| --- | --- |
| `D_pw` | `web2-ish-self-custody sign-in password hash v1\n` (47 bytes, including its LF) |
| `D_ent` | `web2-ish-self-custody sign-in Ed25519 external salt entropy v1` (62 bytes) |
| `D_s` | `web2-ish-self-custody sign-in key v1` (36 bytes) |

```
passwordHash  = SHA-512( utf8("web2-ish-self-custody sign-in password hash v1\n") ‖ passwordBytes )
walletEntropy = SHA-512( utf8(
                  "web2-ish-self-custody sign-in Ed25519 external salt entropy v1" ‖ "\n" ‖
                  applicationId ‖ "\n" ‖ networkId ‖ "\n" ‖
                  normalizedUsername ‖ "\n" ‖ hex(passwordHash) ) )
salt          = the caller's exact 32 bytes
masterSeed    = scrypt(walletEntropy, salt, N=65536, r=8, p=1, dkLen=32)
seed_s        = HKDF-SHA256(masterSeed, salt = info = "web2-ish-self-custody sign-in key v1", L = 32)
publicKey     = Ed25519 public key of seed_s
address       = "S_" ‖ hex(publicKey)
identifier    = address
secret(label) = the application-secret construction, with profile.id = "web2ish-sign-in-ed25519-external-salt-v1"
```

The transcript is the [generic one](#derivation) with these domains; the name
`walletEntropy` is the generic transcript's, not a claim that the key is a
wallet.

## A wallet beside the sign-in key

The pattern the profile exists for:

```ts
withDerivedWallet(
  { profile: signInEd25519ExternalSalt, username, password, salt, context },
  (signIn, secrets) => {
    // signIn signs the service's challenge; the service enrolls signIn.identity.
    return withKalvoraWalletFromMasterSeed(secrets.get("example-wallet-seed-v1")!, (wallet) => …);
  },
  { applicationSecrets: ["example-wallet-seed-v1"] },
);
```

- **One stretch.** The sign-in key and the wallet come from one scrypt run.
- **The sign-in key is the password check.** The wallet has no check value of
  its own: a mistyped password derives a different wallet without any error. An
  application compares the run's sign-in public key with the one the service
  enrolled before it uses or shows the wallet.
- **What the service sees.** The sign-in public key, its signatures, and its
  fingerprint. None of them yields the wallet master seed (above). The sign-in
  public key is still a password oracle at scrypt cost, and so is the wallet's
  address once it is public (see [the security model](SECURITY_MODEL.md)).
- **What the wallet depends on.** The password, the username, the salt, the
  context, the label, and the sign-in profile itself: its id (inside `info`),
  its domains and its KDF. A password change, or a move to any new sign-in
  profile, gives a new wallet. A sign-in profile is therefore never edited and,
  once released, stays exported after it is retired, so that an application
  can derive a user's old wallet once while it moves the user to a successor.
- **Surviving a password change.** The SDK stores nothing. An application that
  needs the same wallet after a password change keeps its own encrypted backup
  of the master seed, under a key its server never holds, and opens the
  restored seed with the same helper.

## Sign-in test vector

`vectors/sign-in-ed25519-external-salt-v1.json`. **Test-only credentials.** It
uses the credentials, context and salt of the Kalvora vector
(`correct horse battery staple lantern orbit`, `JESSE@example.COM`,
`example-app`, `kalvora-mainnet`, salt
`c3e4bb3c8b5943b3df405f473743e1534bd95ce1ed460a9efd7299f53e16d42a`), so the two
can be compared: the sign-in key differs from the Kalvora password wallet, and
the secrets differ from the Kalvora profile's for the same labels. It commits
the transcript intermediates, the sign-in key with a signature, the
application-secret `PRK` and the secrets `example-secret-v1` and
`example-wallet-seed-v1` with their `info` strings, and the Kalvora wallet
opened from `example-wallet-seed-v1` with a signature. It is a new file, never
regenerated; the Kalvora vectors are untouched by it.

| field | value |
| --- | --- |
| `passwordHash` | `7bf0db080ee49e2ca2c76db1a2362d7bdcdc9ed5e33c396c279e46d79a53c3c77b2c25a8bca765d8b199082c347624f8e1765c237554c07e68de705ffe49fd7a` |
| `walletEntropy` | `6e33e765b56fe02259b6a62fc37f186bc88678fccc147f622af776997256b0f737d5c04ae88440486ccefec735f95d6562cd10aefc984dc03790cad661a9214a` |
| `masterSeed` | `45e49fb0cffa6af1c7b70497f2a22644470bc8b7923cf7bfeed538f64afd567d` |
| `PRK_s` | `58fb4041b06645a2b4fe43c93b25608cd2b44de5173c4df5ecfcefc5ca811d6b` |
| `seed_s` | `31ee71687bd9d3b3a892a7c8ffcd3873197c7b10890c5b92f2710fa0a239976d` |
| sign-in public key | `8b3ba319c0d2042d9d6d1d7c7530c9cd9200070ded96717dc3f8337c78bd2205` |
| sign-in identifier and address | `S_8b3ba319c0d2042d9d6d1d7c7530c9cd9200070ded96717dc3f8337c78bd2205` |
| fingerprint | `S8B3 BA31 9C0D 2042` |
| message | `fixture-sign-in-key-message-v1` |
| signature | `d4dfa7f28242ed865a81ea9e015e28e9fdf9ea7415564b925deb9bb374f2546d5aa4f2d4c32e8f91c4eed2a3c99f0091bb366522c7654b41e39eaeeabf356b09` |
| application-secret `PRK` | `593b3438a1a21d9f28a28931f7f0a80bad82c91b8ce50d7ed39ae78ab0b26dbd` |
| `example-secret-v1` | `02204dfbae4331223644219363070c1b3927201632a6ff2e22692e685aa34d19` |
| `example-wallet-seed-v1` | `b0e5c5c3af62990ff50d3ac0f3b5328fad8d8e5a4d5f12a1983dbefbb08dc0ff` |
| wallet public key | `5149cd2e8791def4a15ea67fedd5abfe38541ac661ba3f217017e9e8e4d21546` |
| wallet address | `6UKJ3nbCJGDMNQypzkZ3iq5hL6G4y2kJYQJSez8gwFL1` |
| wallet identifier | `A_6UKJ3nbCJGDMNQypzkZ3iq5hL6G4y2kJYQJSez8gwFL1` |
| wallet message | `fixture-governance-intent-kalvora-master-seed-v1` |
| wallet signature | `bc8b0d1f9c4d5a058b85961e656349cf7906ee7bf7e78c657e197682c6bebfdefdd801fd02457201336d5d3afe672db8ad3220aa13fcef9ebd3434466a91f406` |

## Independent verification of the sign-in vector

`scripts/verify_kalvora_external_salt_vector.py` loads the sign-in vector as its
third fixture. It requires the credential fields to equal the Kalvora wallet
fixture's, then recomputes, with no code shared with this package:

- the transcript under the sign-in domains, checking `passwordHash`,
  `walletEntropy` and `masterSeed`;
- the sign-in key with its own RFC 5869 HKDF (Extract, then the general Expand
  rather than the one-block shortcut), checking `PRK_s`, `seed_s`, the public
  key, the `S_` identifier against `^S_[0-9a-f]{64}$`, the address, the
  fingerprint and the signature;
- the application-secret `PRK`, every label, `info` string and secret under the
  sign-in profile id;
- the Kalvora wallet from the named secret with its own SLIP-0010, checking the
  public key, the base58 address, the `A_` identifier, the fingerprint and the
  signature;
- that the sign-in key, that wallet and the Kalvora password wallet are three
  different keys, that the scrypt output differs from the Kalvora profile's, and
  that no secret equals the Kalvora profile's secret for the same label.

The same assurance boundary applies as for the other vectors.

## The sign-in profile v2

`signInEd25519ExternalSaltV2` is the [sign-in profile](#the-sign-in-profile)
at four times the scrypt cost. It is a new profile, not an edit: v1 keeps its
id, domains, KDF and vector, and stays exported.

**Why.** The sign-in public key is a password oracle, and so is the address of
a wallet derived from an application secret of the same run once it is
published: anyone who also knows the username and the public salt can test
password guesses offline, one scrypt per guess, with no service data
([security model](SECURITY_MODEL.md#offline-guessing-cost)). v2 raises the
memory and the work of each guess by four. It keeps scrypt, rather than
moving to Argon2id, because in a pure-JavaScript browser worker the SDK's
scrypt runs within about 1.2 times of a native implementation while Argon2id
runs about 15 times slower, so within the same time budget scrypt costs a
native attacker several times more per guess (measurements in the
[security model](SECURITY_MODEL.md#offline-guessing-cost)).

It uses `signInEd25519Codec`, the Ed25519 curve, scrypt
`N = 262144 (2^18), r = 8, p = 1, dkLen = 32`, and v1's key step
`signInHkdfEd25519`:

| field | value |
| --- | --- |
| `id` | `web2ish-sign-in-ed25519-external-salt-v2` |
| `algorithm` | `scrypt-sha512-hkdf-sha256-ed25519-external-32-v2` |
| `saltPolicy` | `external-32` |
| `kdf` | `{ N: 262144, r: 8, p: 1, dkLen: 32 }`, about 256 MiB of working memory |
| `domains.salt` | *(absent)* |
| `keyDerivation.id` | `hkdf-sha256-sign-in-key-v1` (unchanged) |
| `codec.id` | `web2ish-sign-in-ed25519-hex-v1` (unchanged) |

All UTF-8. Only the password-hash domain carries a trailing newline:

| constant | exact value |
| --- | --- |
| `D_pw` | `web2-ish-self-custody sign-in password hash v2\n` (47 bytes, including its LF) |
| `D_ent` | `web2-ish-self-custody sign-in Ed25519 external salt entropy v2` (62 bytes) |
| `D_s` | `web2-ish-self-custody sign-in key v1` (36 bytes, v1's) |

```
passwordHash  = SHA-512( utf8("web2-ish-self-custody sign-in password hash v2\n") ‖ passwordBytes )
walletEntropy = SHA-512( utf8(
                  "web2-ish-self-custody sign-in Ed25519 external salt entropy v2" ‖ "\n" ‖
                  applicationId ‖ "\n" ‖ networkId ‖ "\n" ‖
                  normalizedUsername ‖ "\n" ‖ hex(passwordHash) ) )
salt          = the caller's exact 32 bytes
masterSeed    = scrypt(walletEntropy, salt, N=262144, r=8, p=1, dkLen=32)
seed_s        = HKDF-SHA256(masterSeed, salt = info = "web2-ish-self-custody sign-in key v1", L = 32)
publicKey     = Ed25519 public key of seed_s
address       = "S_" ‖ hex(publicKey)
identifier    = address
secret(label) = the application-secret construction, with profile.id = "web2ish-sign-in-ed25519-external-salt-v2"
```

- **Own transcript domains.** Both transcript domains end in `v2`, so even the
  pre-scrypt values (`passwordHash`, `walletEntropy`) differ from v1's, and no
  intermediate is shared between the two profiles.
- **The key step and the codec are v1's.** `D_s` separates the sign-in key from
  the application secrets of one run; the run itself is v2's. Both profiles
  enroll `S_` keys, and a service tells them apart by the profile id it is
  configured with and stores with each key, as for any two profiles.
- **Application secrets work exactly as under v1.** The construction, the
  label rules, the refusals and the lifetime are unchanged; only `profile.id`
  in `info` is v2's. Every secret, and every wallet an application derives
  from one, therefore differs from v1's for the same credentials.
- **Moving a user from v1 to v2 is a key change.** Same password, same salt: a
  different sign-in key, different secrets, a different wallet. It needs an
  enrollment step, like any profile move ([versioning](#versioning)): the
  application derives under v1 once, in the user's next password entry, to
  prove the old key and to read what it sealed under v1's secrets, then
  enrolls the v2 key and re-protects that data under v2's secrets. The SDK
  migrates nothing itself, and the identity service binds one profile per
  schema (below).
- **Memory.** One derivation allocates about 256 MiB. An application running
  it in a browser worker should run one derivation at a time and terminate
  the worker afterwards.
- **Identity service.** No code change: the service is generic over the
  profile, bakes `web2ish-sign-in-ed25519-external-salt-v2`, its algorithm and
  `kdf_n = 262144` into its CHECK constraints at first migration, serves it in
  the deterministic modes, and refuses it in `random-vault` mode, as it does
  v1. A deployment's schema names one profile, so a deployment moves from v1
  to v2 with a new schema or a reset, not by reconfiguring a running one.

## Sign-in v2 test vector

`vectors/sign-in-ed25519-external-salt-v2.json`. **Test-only credentials.** It
has the shape of the [sign-in vector](#sign-in-test-vector) plus a `kdf`
object (`name`, `N`, `r`, `p`, `dkLen`), and the same credentials, context,
salt, labels and messages, so the two can be compared value by value. It is a
new file, never regenerated; every earlier vector is untouched by it.

| field | value |
| --- | --- |
| `kdf` | `{ "name": "scrypt", "N": 262144, "r": 8, "p": 1, "dkLen": 32 }` |
| `passwordHash` | `b85fcf08454f12b0a46d5d406101c13b3fa11f33e01e48f7b4a5d8180a301ba345a6007c0140d2d73ae226e86ac6c918d52ad5404b5c1f3a55d11b9e4603dd1c` |
| `walletEntropy` | `d362213447a416db73384466b6b4a2118e2c1cc6cf2875d990f8d841b7e42dfcef4050662e57e1dca91ab6c12a51660f14829534dac04895b3320ee1cd002a6a` |
| `masterSeed` | `f6e9158612e711b0245d4ec6a07501130c8f881b165b6ffe4285397fb42e358d` |
| `PRK_s` | `6135c7d6ce3950888198f8dd58e05924e54b19c1c8539dcecde018ae0b6d8ec5` |
| `seed_s` | `f70e06b5c9a7e6f035bd5f84c022d006630c049a1a265c01d6beae24bf715010` |
| sign-in public key | `10e253a206d13c110d6b260c68eb4fe5342a36e465a3841278683f99b87e7ca2` |
| sign-in identifier and address | `S_10e253a206d13c110d6b260c68eb4fe5342a36e465a3841278683f99b87e7ca2` |
| fingerprint | `S10E 253A 206D 13C1` |
| message | `fixture-sign-in-key-message-v1` |
| signature | `daa15c3e31f46936e1b2fe797984b3fe20bde9eb759b49d5d1ca72733bfc817ecd1e1d2f0d5e4d25addadb7bf608f74a7a4b1f0c51d989d36ca8c7038fb79209` |
| application-secret `PRK` | `96889d5e9425e8cdd7dd6ad4bc6fe516bf40cb375e6190dd4479d4da50c6f4ff` |
| `example-secret-v1` | `d1062f49a7b2f4ca17d9dfdd53485eb47f57885f25f110364ad70d8099bec830` |
| `example-wallet-seed-v1` | `6253c72fde8bb4dd9457cecdc7f17e85e718796540c8d260e1541b7173f5b238` |
| wallet public key | `6df34af31b0eb4f87ca2cad050eccfd692538d94bbd4b07d2aa1b57fa22777ba` |
| wallet address | `8QCcHiS8gBbbsTUiNsFE2ERx43ci4PVK5y6C9fwoAHE1` |
| wallet identifier | `A_8QCcHiS8gBbbsTUiNsFE2ERx43ci4PVK5y6C9fwoAHE1` |
| wallet message | `fixture-governance-intent-kalvora-master-seed-v1` |
| wallet signature | `3b4003cf9709a913d65ea2b46d9b62bf9f19777737be3aaf9e9e211ebcc424426633c0556c92f9940a56bbc3c1068b214614d0495c48fd244cff71d0cb7db70a` |

## Independent verification of the sign-in v2 vector

`scripts/verify_kalvora_external_salt_vector.py` loads the v2 vector as its
fourth fixture, by its explicit path and with the same strict shape checks plus
the `kdf` object, whose parameters must be integers (not booleans) equal to
the profile's. It requires the credential fields to equal both the Kalvora
wallet fixture's and the v1 sign-in fixture's, then runs every check of
[the v1 verification](#independent-verification-of-the-sign-in-vector) under
v2's domains and `hashlib.scrypt` at `N = 2^18`, with the same HKDF, SLIP-0010,
base58 and Ed25519 code. It also requires that the profile id and algorithm
differ from v1's; that `passwordHash`, `walletEntropy`, `masterSeed`, the
sign-in public key, the wallet public key and every secret of a shared label
differ from v1's; and that scrypt of the same entropy at v1's `N` does not give
v2's `masterSeed`. The vector was generated by that construction in Python and
reproduced by the TypeScript implementation (`test/sign-in-v2.test.ts`), so
the two implementations agree on every value. The same assurance boundary
applies as for the other vectors.

---

# Part 4 — the account-change message

`buildAccountChangeMessage`, `normalizeEmail`, `ACCOUNT_CHANGE_DOMAIN` and
`accountChangeActions` are exported from the core entry, which imports no
server code and no chain SDK, so a browser worker builds the exact bytes it
signs from typed fields. The identity service builds the same bytes from its
own records and verifies the signatures over them
([server API](SERVER_API.md#account-changes-and-recovery-keys-opt-in)).

## Why a message of its own

The login challenge binds a purpose, a username and a nonce, and is signed by
the one enrolled key. An account change needs more: it names what authorizes it
(the current key, or a recovery key) and what it is about (a new key, an email
address, a recovery key), and some changes are signed by two keys. One message
serves every action:

- a single domain, `web2-ish-self-custody account change v1`, with ten lines
  where the login challenge has eight under another domain, so neither can be
  taken for the other;
- the service profile, application and network, as the challenge binds them;
- the action, so a signature for one action is useless for another;
- the normalized username and the `rotation` challenge's nonce and expiry, so
  each signature is single-use and short-lived;
- a typed authorizer and a typed subject, each in the one form its action
  allows. The authorizer is what authorizes the change: a key that signs, or,
  for a reset, the reset itself (an emailed code, or the elapsed wait of one
  session), which the service checks and which does not sign.

## Format

Ten lines joined by `\n` (U+000A), UTF-8, no trailing newline, no BOM:

```text
line 1   web2-ish-self-custody account change v1
line 2   <serviceProfileId>
line 3   <applicationId>
line 4   <networkId>
line 5   <action>
line 6   <usernameNormalized>
line 7   <nonceHex>      the `rotation` challenge's 32-byte nonce, 64 lowercase hex
line 8   <expiresAt>     the challenge's expiry, ISO-8601 UTC with milliseconds
line 9   <authorizer>
line 10  <subject>
```

## Actions

| action | authorizer | subject | who signs |
| --- | --- | --- | --- |
| `sign-in-key-rotation` | `key:<current>` | `key:<new>` | both keys |
| `email-change` | `key:<current>` | `email:<normalized address>` | the key |
| `recovery-key-enrollment` | `key:<current>` | `recovery-key:<hex>` | both keys |
| `recovery-key-removal` | `key:<current>` | `none` | the key |
| `recovery-begin` | `recovery-key:<hex>` | `none` | the recovery key |
| `recovery-reset` | `recovery-key:<hex>` | `key:<new>` | both keys |
| `reauthentication` | `key:<current>` | `host:<label>` | the key |
| `email-reset-setting` | `key:<current>` | `setting:on` or `setting:off` | the key |
| `signed-in-reset-setting` | `key:<current>` | `setting:on` or `setting:off` | the key |
| `email-reset` | `email:<resetId>` | `key:<new>` | the new key only |
| `signed-in-reset` | `session-reset:<resetId>` | `key:<new>` | the new key only |

The first six arrived with account changes and recovery keys, the last five
with account resets. A key that authorizes signs, and a subject that is a key
signs too (proof of possession), so nobody can rebind an account to, or enroll,
a key they do not hold. A reset's authorizer is not a key: for `email-reset`
the emailed code is the authorization and for `signed-in-reset` the elapsed
wait from the same session (or an emailed code), both checked by the service,
so only the new key signs. A setting's subject binds its value, so a signature
that turns a setting off cannot turn it on. A later release may add actions; it
never changes these ([versioning](#versioning)).

## Principals

- `key:` followed by the deployment codec's `encodePublicKey` of the enrolled
  key: `key:S_<64 hex>` under the sign-in profile, `key:A_<base58>` under the
  Kalvora profile. The builder accepts 1 to 160 printable ASCII characters
  after `key:`.
- `recovery-key:` followed by the recovery key's raw 32-byte Ed25519 public key
  as 64 lowercase hex characters. A recovery key is a plain Ed25519 key that
  the application derives from whatever recovery secret it gives its user; the
  service stores only its public half.
- `email:` followed by `normalizeEmail(address)`: trimmed, lowercased, at most
  254 characters, a plain `local@domain` address with an ASCII DNS-style
  domain and a local part of at most 64 characters with no whitespace, no C0
  or C1 control character and no DEL, so it never holds a line break. The
  builder refuses an address that is not already normalized.
- `email:` followed by a reset id, the authorizer of `email-reset` only: a UUID
  in lowercase hex (`8-4-4-4-12`), as the service issues it. A reset id holds
  no `@`, so it is never a valid address, and each action allows only one of
  the two `email:` forms.
- `session-reset:` followed by a reset id, the authorizer of
  `signed-in-reset` only.
- `setting:on` or `setting:off`, the subject of the two setting actions.
- `host:` followed by a label, the subject of `reauthentication`: 3 to 80
  characters from `[a-z0-9._:-]`, starting with a letter or digit. It is the
  host's constant for what the reauthentication unlocks, never user data.
- `none`.

`buildAccountChangeMessage` refuses, with `DerivationError` `invalid-message`:
a line break (LF, CR, VT, FF, NEL, LS or PS) in any field, an action not in the
table, a username that is not already normalized, a nonce that is not 64
lowercase hex characters, a service profile, application or network id outside
`^[a-z0-9][a-z0-9._:-]{0,79}$`, an invalid `Date`, and an authorizer or subject
in any form but its action's. `normalizeEmail` refuses with `invalid-email`.

## Building it on a client

The client asks for a `rotation` challenge for the username (`POST /challenges`
with `purpose: "rotation"`), and takes the fields from the response and from
`GET /profile`:

```ts
import { buildAccountChangeMessage } from "web2-ish-self-custody";

const lines = challenge.message.split("\n"); // the 8-line login-format challenge
const message = buildAccountChangeMessage({
  serviceProfileId: profile.serviceProfileId,
  applicationId: profile.applicationId,
  networkId: profile.networkId,
  action: "sign-in-key-rotation",
  usernameNormalized: challenge.usernameNormalized,
  nonceHex: lines[6],                      // line 7
  expiresAt: new Date(challenge.expiresAt),
  authorizer: `key:${currentKey.publicKey}`,
  subject: `key:${newKey.publicKey}`,
});
// Sign the UTF-8 bytes of `message` with each key the action names.
```

The client never signs the challenge's own 8-line message for an account
change. It builds this one from fields it has checked, so a server cannot make
it sign anything else.

## Signatures and strict verification

Each signature is Ed25519 (RFC 8032, pure) over the message's UTF-8 bytes, sent
as exactly 128 lowercase hex characters. The service verifies each one strictly:

- S < L, the group order (a malleated S + L is refused);
- A and R are canonical encodings: y < p, and no x = 0 with the sign bit set;
- A is not one of the eight points of small order;

and then calls noble's `ed25519.verify` with `zip215: false`, which applies the
same rules again. The checks are not optional: under the permissive ZIP-215
rule (noble's default) a small-order public key with R = identity and S = 0
verifies for every message, and so does OpenSSL 3.5's Ed25519 verification
(`cryptography` 46.0.3 over OpenSSL 3.5.4 accepts the vector's small-order
case; OpenSSL 4.0, as bundled with Node 24.21, refuses it). The login challenge
keeps its existing verification; what it can no longer meet is such a key,
because registration, rotation, recovery-key enrollment and recovery all refuse
a submitted public key that is not canonical or is of small order
(`invalid-public-key`).

## Challenge binding

Every account change consumes one `rotation` challenge for the account's
username, in its own statement, before any signature is checked; the challenge
is single-use and expires (300 s by default). A challenge is consumed by exactly
one operation, and because line 5 names the action, its signatures authorize
only that action.

## Account-change vector

`vectors/account-change-v1.json` fixes, for the service profile
`example-account-v1` and the sign-in vector's application, network and
username:

- the context: a fixed nonce and expiry;
- three keys: `current`, the committed sign-in vector's key (its credentials);
  `next`, the sign-in key of a second password under the same username and
  salt; and `recovery`, an Ed25519 key whose seed is SHA-256 of a fixed label;
- one case per action, with its principals, its message bytes and a signature
  by each key the action names (Ed25519 is deterministic);
- four signatures that verify **false** strictly, each failing exactly one
  check: a small-order A with R = identity and S = 0 (`acceptedUnderZip215`:
  true), a non-canonical A and a non-canonical R (both y = p + 3, a point that
  is not of small order), and the current key's rotation signature with S + L.

Like every vector here, it is never regenerated.

## Account-reset vector

`vectors/account-change-resets-v1.json` holds the five actions of account
resets, added beside the first vector rather than into it (a released vector
is never edited, [versioning](#versioning)). Over the first vector's context
and its `current` and `next` keys (named by public key and principal, not
repeated), it fixes:

- two reset ids, each the version-4 UUID formed from SHA-256 of a fixed label,
  and a generic host label, `example-host-action-v1`;
- one case per message: `reauthentication`, each setting action with
  `setting:on` and with `setting:off`, `email-reset` and `signed-in-reset`,
  each with its message bytes and a signature by each key its action names
  (the `current` key for the first five, the `next` key alone for the two
  resets);
- twenty principals that every builder must refuse, each with the one field
  it refuses: labels that are too short, too long, uppercase or start with a
  dash, a setting other than `on` or `off`, an address or an uppercase id as an
  `email-reset` authorizer, either reset's authorizer in the other's form, a
  key authorizing a reset, and `host:`, `setting:` and a reset id in actions
  that do not take them.

## Independent verification of the account-change vector

`scripts/verify_account_change_vector.py` reproduces the vector with the
standard library and `cryptography` alone, sharing no code with this package.
It loads the sign-in vector by explicit path and requires the shared credential
fields to match, then:

- derives `current` and `next` from their credentials (the sign-in transcript,
  scrypt and the HKDF key step), checks `current` against the sign-in vector,
  and derives `recovery` from its label;
- rebuilds every message field by field and checks each action's principal
  forms and keys;
- re-signs every signature and verifies it, applying the strict checks (S < L,
  canonical A and R, A not one of the eight small-order encodings, compared
  byte for byte) before `cryptography`'s verification;
- requires each negative case to fail exactly the check its `reason` names and
  to verify false;
- checks each `acceptedUnderZip215` flag against its own ZIP-215 verification
  in pure-Python curve arithmetic, whose base-point order and small-order list
  it checks first, as it checks its HKDF against RFC 5869 and `cryptography`'s
  Ed25519 against RFC 8032.

The same script then loads `vectors/account-change-resets-v1.json` by explicit
path and requires its context and keys to be the first vector's, recomputes
both reset ids from their labels, rebuilds each message, re-signs and verifies
each signature as above, requires each action's case count and roles (both
values of each setting; the new key alone for a reset), and requires each
refused principal to fail exactly its named field's form under the script's
own form rules, with every new form and every new action refused at least
once.

`npm run verify:vectors:python` runs it after the external-salt verifier, and
`npm run verify:ci`'s "python vectors" gate runs both.
