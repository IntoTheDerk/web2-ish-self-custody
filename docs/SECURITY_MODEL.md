# Security model

## Security objective

The SDK permits a client to recreate a signing identity from credentials without persistent wallet-secret storage. It attempts to keep derived secret material within one short callback scope and to erase SDK-owned buffers afterward.

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
- Password or username change: different wallet identity.
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

## Server boundary

A server may store public identity, profile ID, public salt, session records, and one-use challenges. It does not need a seed, private key, wallet password, application secret, or encrypted vault.

A server pepper used to generate an external salt is not wallet custody, but it introduces server dependency and does not stop the server from testing password guesses against a known public identity.
