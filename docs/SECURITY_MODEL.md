# Security model

## Security objective

The SDK permits a client to recreate a signing identity from credentials without persistent wallet-secret storage. It attempts to keep derived secret material within one short callback scope and to erase SDK-owned buffers afterward.

## Fundamental tradeoff

The public key or wallet address is a password-verification oracle. An attacker can derive candidate identities offline until one matches. Scrypt increases the cost of each guess; it does not add entropy to a human password.

The username is domain and identity context, not a secret. It must not be counted as password entropy.

## Assumptions

- Passwords are generated and retained by a password manager or comparably strong process.
- Consuming applications pin one known profile rather than accepting arbitrary KDF settings from a server.
- Applications run derivation and signing in a fresh dedicated worker.
- Applications permit only one active derivation, terminate the worker for immediate cancellation, and do not await UI or network work inside the synchronous wallet callback.
- The origin, browser, extensions, and operating system are trusted while the password is entered and the wallet is active.
- Servers treat salts as public metadata.

## Failure modes

- Forgotten password or username: permanent wallet loss.
- Password or username change: different wallet identity.
- Profile/context change: different wallet identity.
- Weak password: feasible offline wallet recovery by an attacker.
- Malicious same-origin JavaScript: password or signature theft before SDK cleanup.
- Retained callback references: public data remains available; a malicious caller can copy data it is given.
- Process crash: JavaScript and browser memory cleanup is best effort.
- Raw-signature confusion: the low-level exact-byte method can sign malicious bytes unless the product locally reconstructs and confirms a typed operation.

## Server boundary

A server may store public identity, profile ID, public salt, session records, and one-use challenges. It does not need a seed, private key, wallet password, or encrypted vault.

A server pepper used to generate an external salt is not wallet custody, but it introduces server dependency and does not stop the server from testing password guesses against a known public identity.
