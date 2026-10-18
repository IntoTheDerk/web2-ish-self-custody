# Security model

## Security objective

The SDK permits a client to recreate a signing identity from credentials without persistent wallet-secret storage. It attempts to keep derived secret material within one short callback scope and to erase SDK-owned buffers afterward.

Alternatively, random-vault mode encrypts a randomly generated seed. See
[Wallet modes](WALLET_MODES.md) for its storage and access-control requirements.
Password changes and recovery-code unlocking are vault features. Deterministic
mode has no SDK-managed password-change, key-replacement, or account-recovery
flow. A platform that reassigns an account to a new key owns that authorization
and the retirement of the old key; reassignment does not recover the old key.

## Fundamental tradeoff

The public key or wallet address is a password-verification oracle. An attacker can derive candidate identities offline until one matches. Scrypt increases the cost of each guess; it does not add entropy to a human password.

The username is domain and identity context, not a secret. It must not be counted as password entropy.

## Password floor

Every derivation, vault creation, and vault password change requires a password of at least 10 characters (Unicode code points of well-formed UTF-8) and at most 1,024 UTF-8 bytes. That floor exists to reject the obviously unusable; it is not a strength guarantee. Length says little about guessability — a ten-character dictionary word with a digit appended falls early to an offline attacker who holds the public identity.

The strength policy therefore belongs to the application at the moment a password is chosen: when an account is created and when a password is set or changed. There it should estimate strength, refuse common and breached passwords, and encourage password-manager-generated or long passphrase credentials. It should not re-apply that policy on sign-in, because the wallet already exists and a policy that tightens later would lock its owner out of it.

## Assumptions

- Passwords are generated and retained by a password manager or comparably strong process, and the application enforces a strength policy when a password is chosen; the SDK's 10-character floor alone does not provide one.
- Consuming applications pin one known profile rather than accepting arbitrary KDF settings from a server.
- Applications run derivation and signing in a fresh dedicated worker.
- Applications permit only one active derivation, terminate the worker for immediate cancellation, and do not await UI or network work inside the synchronous wallet callback.
- The origin, browser, extensions, and operating system are trusted while the password is entered and the wallet is active.
- Servers treat salts as public metadata.
- Services store external salts as immutable public wallet metadata and return them only under the expected pinned profile and derivation context.

## Failure modes

The loss and change rows are about a wallet: the key a chain wallet profile derives, or a wallet derived from an application secret. For a sign-in key, the key of the [sign-in profile](#sign-in-profile), the same events lose or change the key that signs in to the service, which the application's own account recovery must replace; the SDK has none. A sign-in key holds no funds.

- Forgotten password or username: permanent wallet loss, unless the wallet was enrolled in a wallet vault beforehand and its recovery code is still held.
- Lost vault password and lost recovery code: permanent wallet loss.
- Password or username change during deterministic derivation: different wallet identity; no automatic account update.
- Profile/context change: different wallet identity.
- External salt loss, rotation, or substitution: different wallet identity.
- Weak password: feasible offline wallet recovery by an attacker.
- Malicious same-origin JavaScript: password or signature theft before SDK cleanup.
- Retained callback references: public data remains available; a malicious caller can copy data it is given.
- Process crash: JavaScript and browser memory cleanup is best effort.
- Raw-signature confusion: the low-level exact-byte method can sign malicious bytes unless the product locally reconstructs and confirms a typed operation.
- Copied application secret: a secret copied out of its callback, or read there by malicious same-origin JavaScript, exposes whatever the application protects with it. It does not expose the wallet key, the scrypt output, or another label's secret.

## Application secrets

`withDerivedWallet` can also return application secrets: 32-byte HKDF-SHA256 outputs of the same scrypt run, one per application-chosen label ([protocol](PROTOCOL.md#application-secrets)).

| property | consequence |
| --- | --- |
| Password-derived | A secret has exactly the wallet's offline-guessing exposure and adds no entropy; the public key stays the cheaper oracle for the password. An application that uses one as a key-encryption key should also mix in a random per-account salt that it stores, so the key cannot be computed from the password alone and changes whenever that salt is replaced. |
| Independent of the wallet key | Derived from the scrypt output, not from the exportable wallet key, so a holder of the wallet key or of its signatures cannot compute a secret (provided the profile's key-derivation step is one-way, as Kalvora's hardened SLIP-0010 is; the core cannot check this), and a holder of a secret cannot compute the wallet key or another label's secret. A profile without a key-derivation step, whose wallet key is the scrypt output, refuses secrets (`secret-unavailable`), and so does one whose step returns the scrypt output unchanged. A profile with any other invertible step must not be used with secrets. |
| Bounded lifetime | The intermediate key is zeroed before the callback runs and the secrets when it returns or throws, and the core keeps no other copy of a secret. A callback that returns a secret's bytes rather than a copy fails (`wallet-scope-closed`). A copy kept beyond the callback is the application's to protect and zero. The vault path never computes them. |
| Tied to the credentials | A password, username, salt, context or profile-id change gives every label a different secret, so whatever an application sealed under a secret must be re-protected before the old password is gone. |

## Sign-in profile

`signInEd25519ExternalSalt` derives a sign-in key: an Ed25519 key whose `S_` identifier no chain accepts, for an identity service to enroll in place of a wallet. An application that also needs a wallet derives its master seed as an application secret of the same run and opens it with `withKalvoraWalletFromMasterSeed` ([protocol](PROTOCOL.md#part-3--the-sign-in-profile)).

| property | consequence |
| --- | --- |
| Not a wallet | The service stores the sign-in key's public key and receives its signatures, and nothing about the wallet. A sign-in key holds no funds, but it is lost exactly when the credentials are, and a wallet derived from an application secret of the same run is lost with it unless the application keeps its own encrypted backup of the master seed. |
| Still a password oracle | The sign-in public key is a password verifier at scrypt cost, like a wallet public key. Anyone holding the service's database can guess offline, and a correct guess gives the password, and with it every key of the run: the sign-in key, every application secret, and the wallet derived from one. |
| A published wallet address is an oracle too | Once a wallet's address is public, anyone who also knows the username and the public salt can guess offline with no service data at all, and a hit gives the sign-in key as well as the wallet. Only high-entropy, password-manager-generated passwords resist either attack. |
| Independent branches | The sign-in key and the application secrets are HKDF-SHA256 outputs of the same scrypt output under different public domain strings. Neither the sign-in key nor its signatures give a secret, and a secret does not give the sign-in key. |
| No check value for the wallet | A mistyped password derives a different wallet without any error. The application compares the run's sign-in public key with the enrolled one before it uses or shows the wallet. |
| Bound to the profile | The wallet depends on the password, the username, the salt, the context, the application's label and the sign-in profile (its id, domains and KDF). A change to any of them is a different wallet; only an application's own encrypted backup of the master seed carries a wallet across one. Released sign-in profiles therefore stay exported after they are retired. |
| Bounded lifetime | `withKalvoraWalletFromMasterSeed` works on its own copy of the master seed and zeroes it, and zeroes the wallet key when its synchronous callback returns or throws. The master seed passed in stays the caller's: an application secret's own array is zeroed by `withDerivedWallet` when its callback returns, and any copy the caller made is the caller's to zero. |

## Server boundary

A deterministic service (`service-deterministic` or `per-account-deterministic`) stores public identity, profile ID, the public salt (the service's, or one per account), session records, and one-use challenges. It does not need a seed, private key, wallet password, recovery code, application secret, or encrypted vault. Random-vault mode additionally stores encrypted vaults, retrievable only after platform authorization; a stolen vault permits offline password guessing. In no mode does the SDK send a plaintext seed, private key, wallet password, recovery code, or application secret to the server. Under the sign-in profile the public identity it stores is the sign-in key's, and it needs nothing about the user's wallet. The sign-in profile is served only in the deterministic modes; `random-vault` mode refuses it.

A server pepper used to generate an external salt is not wallet custody, but it introduces server dependency and does not stop the server from testing password guesses against a known public identity.
