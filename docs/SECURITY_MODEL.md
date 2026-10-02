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

## Server boundary

A deterministic service stores public identity, profile ID, public salt, session
records, and one-use challenges. Random-vault mode additionally stores encrypted
vaults, retrievable only after platform authorization. A stolen vault permits
offline password guessing. Neither mode sends a plaintext seed, private key,
wallet password, or recovery code to the server.

A server pepper used to generate an external salt is not wallet custody, but it introduces server dependency and does not stop the server from testing password guesses against a known public identity.
