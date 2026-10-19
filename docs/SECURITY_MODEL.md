# Security model

## Security objective

The SDK permits a client to recreate a signing identity from credentials without persistent wallet-secret storage. It attempts to keep derived secret material within one short callback scope and to erase SDK-owned buffers afterward.

Alternatively, random-vault mode encrypts a randomly generated seed. See
[Wallet modes](WALLET_MODES.md) for its storage and access-control requirements.
In that mode password changes and recovery-code unlocking are vault features.
In the deterministic modes the identity service offers opt-in account
changes, off by default: sign-in-key rotation and recovery keys
([account changes](#account-changes)), and account recovery by email and the
signed-in reset ([account resets](#account-resets)). Each rebinds the account
to a new key and never recovers the old one; a platform that keys other state
on the old key, such as an on-chain permission, retires it there itself.

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

The loss and change rows are about a wallet: the key a chain wallet profile derives, or a wallet derived from an application secret. For a sign-in key, the key of the [sign-in profile](#sign-in-profile), the same events lose or change the key that signs in to the service, which a rotation (while the old password is known) or a recovery key, an emailed reset code or a signed-in reset (afterwards) replaces at the service, if the deployment enables them; neither recovers the old key or anything derived from it. A sign-in key holds no funds.

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

## Account changes

`rotateSignInKey`, `changeEmail`, `enrollRecoveryKey`, `removeRecoveryKey`,
`beginRecovery` and `completeRecovery` change what signs in to an account, so
each is authorized by signatures over the
[account-change message](PROTOCOL.md#part-4--the-account-change-message).

| property | consequence |
| --- | --- |
| Strict Ed25519 | Every account-change signature is checked against RFC 8032's strict rules (S < L, canonical A and R, A not of small order) before noble's `zip215: false` verification. The permissive rule, and some OpenSSL releases (3.5.4, as bundled with `cryptography` 46.0.3), accept a small-order key with R = identity and S = 0 for every message; no submitted key of small order or in a non-canonical encoding is ever enrolled, at registration either. |
| Proof of the password, not a session | A stolen session token alone cannot rotate the key, make a signed email change (`changeEmail`), or add or remove a recovery key: each needs a fresh signature by the enrolled key over a single-use challenge. `updateAccount` and the router's `PATCH /accounts/me` still change the email with a session alone and report nothing to `onSecurityEvent`; a host that treats the email as a security channel refuses `email` there and changes it only through `changeEmail`. A session can still list and revoke sessions. |
| One statement | Each change re-checks its session or recovery token, the account's `active` status and the enrolled key under row locks, and revokes sessions in the same statement. A signed-in change whose enrolled key a rotation or a recovery moved before its statement locked the key is refused (`stale-key`), and of two completions of one recovery the second gets the uniform `invalid-signature`. Other concurrent changes apply one after the other ([details](SERVER_API.md#statements-and-lock-order)). |
| Other sessions end | A rotation revokes every other session of the account and a recovery revokes every session. A login that verified the old key and whose final statement runs while the rotation's does can still keep its session; the sessions list shows it and revoking other sessions ends it. |
| A recovery key is a full credential | With the username, it takes over the account login without the password. It is single use (`used` at completion), a new enrollment retires the previous one, and the operator can revoke it (`revokeRecoveryKeys`). Its secret never reaches the service; the application must make it high-entropy, because its public key is stored. |
| Recovery is not key recovery | A completed recovery binds a new key. Under a chain wallet profile the old wallet is not recovered; under the sign-in profile a wallet derived from the old password is not either. Data an application sealed under the old password needs its own recovery path. |
| The server is trusted for account control | An operator with database write access can bind any key or recovery key, as it always could bind any enrolled key; audit rows and the alerts in [SERVER_API.md](SERVER_API.md#what-an-operator-with-database-access-can-and-cannot-do) make that visible, not impossible. |
| Uniform refusals | Every recovery failure an unauthenticated caller can cause is one `invalid-signature`; no code is added to `enumerationSensitiveCodes`. |

## Account resets

`startAccountReset`, `completeAccountReset`, `startSignedInReset`,
`abortSignedInReset`, `completeSignedInReset`, `setAccountResetSetting` and
`verifyReauthentication` (migration 8). The resets need their opt-ins,
`accountSecurity.emailReset` and `accountSecurity.signedInReset`, both off by
default ([server API](SERVER_API.md#account-resets-opt-in)).

| property | consequence |
| --- | --- |
| The email inbox becomes a credential | With account recovery by email on, whoever reads the account's verified inbox can replace the enrolled key with a 15-minute, 5-attempt code and no password. The code is 80 bits, so a database read of its SHA-256 digest does not yield it within those 15 minutes. It is off for every account until its owner turns it on with a signature by the key and a verified email. |
| A session becomes a credential after a wait | With the signed-in reset (on for every account once the deployment opts in), a stolen session can replace the enrolled key after 72 hours unless another session aborts it or the owner signs in with the password or changes it. The password change aborts it even when made on the session that started it, which a rotation keeps, so a stolen copy of the owner's own session cannot outlast a new password. While it waits, that session cannot sign out the others (`reset-pending`), and the start is reported to `onSecurityEvent` with `availableAt` so the owner can be told. A start from a session that expires before the wait ends is refused, and no session is extended. Turning it off needs the key's signature and another reset method; a reset counts as pending, and completes, only while it is on. |
| Reset is not key recovery | As with a recovery key, a reset binds a new key and recovers nothing derived from the old password. |
| The email-change interlock | Any address change, signed or not (`updateAccount` too), turns account recovery by email off and closes its live codes in the same statement, so a session alone cannot point the recovery channel at another inbox; a code also stops working once the address is re-verified after it was sent. |
| The settings bind their value | A setting is changed only by a fresh signature over `setting:on` or `setting:off`, so a stolen session cannot turn either reset on or off, and a signature for one value or one setting is useless for another. |
| Uniform start | `startAccountReset` answers every username with a fresh reset id and the same expiry, in the same statements, whether or not a code is issued; its username limits count every request. Its per-recipient cap is a bucket of its own that nothing else reads, so email verification's `429` for an address neither reveals a start that found an eligible account there nor silences that account's codes. The delivery, and so the response time, is the host's: it must pad every response to one fixed time and never surface a delivery failure. |
| Uniform refusals | Every failure of `completeAccountReset` an unauthenticated caller can cause is one `invalid-signature`; no code is added to `enumerationSensitiveCodes`. |
| Reauthentication is a proof, not a change | `verifyReauthentication` proves a fresh current-password run for a host label and audits it (`account.reauth`); what it unlocks is the host's own statement. |
| One statement, one lock order | Each reset is one statement that re-checks its code or wait, the session, the status and the enrolled key under row locks, in the account changes' lock order with the resets before the sessions. The abort, the password login and the password change lock the reset row the completion locks, so each stops it race-free; revoking the initiating session stops it except for a completion already in flight. A setting change cannot see a reset that a start inserted while it waited, so a change of a setting closes that kind's open resets in either direction. |

## Server boundary

A deterministic service (`service-deterministic` or `per-account-deterministic`) stores public identity, profile ID, the public salt (the service's, or one per account), session records, and one-use challenges, and, with recovery keys enabled, recovery public keys and SHA-256 digests of recovery tokens, and, with account resets, each account's two reset settings and SHA-256 digests of reset codes (80 bits, so a read of the digests does not yield a live code). It does not need a seed, private key, wallet password, recovery code, application secret, or encrypted vault. Random-vault mode additionally stores encrypted vaults, retrievable only after platform authorization; a stolen vault permits offline password guessing. In no mode does the SDK send a plaintext seed, private key, wallet password, recovery code, or application secret to the server. Under the sign-in profile the public identity it stores is the sign-in key's, and it needs nothing about the user's wallet. The sign-in profile is served only in the deterministic modes; `random-vault` mode refuses it.

A server pepper used to generate an external salt is not wallet custody, but it introduces server dependency and does not stop the server from testing password guesses against a known public identity.
