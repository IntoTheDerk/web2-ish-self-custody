# Protocol

The two built-in profiles are immutable derivation protocols. This document is
the wire specification: it contains every constant, transcript, and encoding
rule needed to reimplement derivation from scratch and reproduce the committed
vectors. Where this document and the committed source disagree, the source and
the vectors are the contract.

Both profiles produce an Ed25519 wallet. They differ in exactly one step — where
the 32-byte scrypt salt comes from — and in the entropy domain string that keeps
their transcripts apart.

| `profileId` | `algorithm` | salt policy | scrypt |
| --- | --- | --- | --- |
| `web2ish-zera-ed25519-v1` | `scrypt-sha512-ed25519-v1` | derived from the normalized username | N=65536, r=8, p=1, dkLen=32 |
| `web2ish-zera-ed25519-external-salt-v1` | `scrypt-sha512-ed25519-external-32-v1` | exactly 32 bytes supplied by the service | N=65536, r=8, p=1, dkLen=32 |

## Constants

All domain strings are UTF-8. Only the password-hash domain carries a trailing
newline; the others are joined into transcripts with explicit `\n` separators.

| constant | exact value |
| --- | --- |
| password-hash domain | `web2-ish-self-custody password hash v1\n` |
| username-salt domain | `web2-ish-self-custody public username salt v1` |
| entropy domain, `web2ish-zera-ed25519-v1` | `web2-ish-self-custody ZERA Ed25519 entropy v1` |
| entropy domain, `web2ish-zera-ed25519-external-salt-v1` | `web2-ish-self-custody ZERA Ed25519 external salt entropy v1` |

The password-hash domain is 39 bytes including its trailing LF (U+000A). The
username-salt domain is used only by `web2ish-zera-ed25519-v1`.

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

### Password

The password is supplied as raw bytes, not as a string. It must be 24 to 1,024
bytes inclusive. No normalization, trimming, case folding, or Unicode
normalization is applied: the exact bytes are hashed. A UTF-8 encoding of the
user's input is the expected form, and the byte count — not the character
count — is what the bounds apply to.

### Derivation context

`applicationId` and `networkId` are each canonicalized by trimming surrounding
whitespace and lowercasing, then required to match:

```
^[a-z0-9][a-z0-9._:-]{0,79}$
```

That is 1 to 80 characters, starting with an ASCII alphanumeric, from the
alphabet `a-z0-9._:-`. Because the accepted output alphabet is ASCII, an
implementation may equivalently require callers to supply the canonical form
and reject anything else.

### Salt

`web2ish-zera-ed25519-external-salt-v1` requires exactly 32 bytes from the
caller — 31 or 33 is an error, not something to pad or truncate. The salt is
public derivation metadata, not credential entropy and not a secret.

`web2ish-zera-ed25519-v1` derives its salt (step 3 below) and rejects a
caller-supplied salt outright rather than ignoring it.

## Derivation

### 1. Password hash

```
passwordHash = SHA-512( utf8("web2-ish-self-custody password hash v1\n") ‖ passwordBytes )
```

Byte concatenation, no separator beyond the domain's own trailing newline.
Result: 64 bytes.

### 2. Wallet entropy

Join five lines with a single `\n` (U+000A), encode as UTF-8, and hash:

```
line 1  <entropy domain for the selected profile>
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

The application and network stay in this transcript for both profiles, even
though an external salt should already be service-specific. That makes
service/network separation explicit and keeps an accidental salt collision from
collapsing two derivation domains into one.

### 3. Salt

For `web2ish-zera-ed25519-external-salt-v1`, the salt is the caller's 32 bytes,
used verbatim.

For `web2ish-zera-ed25519-v1`, join four lines with `\n` and hash:

```
line 1  web2-ish-self-custody public username salt v1
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
seed = scrypt(password = walletEntropy, salt = salt, N = 65536, r = 8, p = 1, dkLen = 32)
```

The 64-byte `walletEntropy` is the scrypt password input and the 32-byte salt is
the scrypt salt input. `N = 65536, r = 8` requires roughly 64 MiB of working
memory; implementations that impose a `maxmem` limit must raise it accordingly.
Result: a 32-byte Ed25519 seed.

### 5. Identity encoding

The 32-byte seed is an Ed25519 private key per RFC 8032. Derive the 32-byte
encoded public key from it in the standard way.

| field | rule |
| --- | --- |
| `publicKeyBytes` | the raw 32-byte Ed25519 public key |
| `address` | Base58 of `publicKeyBytes`, Bitcoin alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`, no checksum, no version byte |
| `publicKey` | the string `A_` followed by `address` |
| `curve` | the literal `ed25519` |
| `profileId` | the selected profile id |
| `normalizedUsername` | the value from the username rules above |
| `fingerprint` | display aid, see below |

`fingerprint` is computed from `address`: drop every character that is not
ASCII alphanumeric, uppercase the rest, take the first 16 characters, and insert
a single space after each group of 4. It is a human-comparison aid only and must
never be checked in place of the address.

Base58 has no fixed output length: a public key with leading zero bytes encodes
shorter. Both committed vectors are 44 characters, and the server accepts 32 to
64. Validators should accept a range rather than pin a single length.

## Signing

Signatures are Ed25519 as specified in RFC 8032 — PureEdDSA, deterministic, no
prehash, no context string — over the exact message bytes, producing 64 bytes.
On the wire the server encodes them as 128 lowercase hex characters.

The SDK accepts messages of 1 to 1,048,576 bytes. The signing method is named
`signExactMessageUnsafe` because it signs precisely what it is handed: it is the
primitive needed to sign exact ZERA transaction bytes, not permission to sign
bytes supplied by a server or an untrusted renderer. A consuming application
must locally reconstruct the typed operation, display a trusted confirmation,
and only then pass the verified bytes to the scoped signer.

The authentication challenge format that `web2-ish-self-custody/server` issues
is a separate, layered specification; see
[the server API reference](SERVER_API.md#challenge-message-format).

## Test vectors

Committed in `vectors/`. **Test-only credentials — never derive a real wallet
from these values.** Both use the password `correct horse battery staple lantern
orbit` (42 UTF-8 bytes) and the username `JESSE@example.COM`, which normalizes
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

## Versioning

Changing any byte of a domain string, transcript layout, normalization rule, KDF
parameter, salt policy, curve rule, or identity encoding requires a new profile
ID. Published profile behavior must never be upgraded in place — a wallet is
defined by its profile, so a silent change destroys every wallet derived under
it.

## Independent vector verification

`scripts/verify_zera_vector.py` and
`scripts/verify_zera_external_salt_vector.py` reconstruct the committed vectors
from the fixtures using Python's standard-library `hashlib` and the separately
maintained `cryptography` package. Neither imports or executes the TypeScript
SDK. Between them they check username normalization, both domain-separated
transcripts, the salt (derived and supplied), the scrypt result, the public key,
the Base58 identity encoding, the deterministic signature, and signature
verification. Both fail on missing, unexpected, duplicate, incorrectly typed, or
incorrectly encoded fixture fields.

This is cross-implementation regression evidence for the committed vectors. It
is not a cryptographic audit, does not prove browser or deployment safety, does
not assess credential entropy, and does not replace additional vectors and
external review before funded use.
