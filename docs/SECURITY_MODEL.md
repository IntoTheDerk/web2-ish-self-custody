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

## Offline guessing cost

Each offline guess costs one run of the profile's KDF, so the KDF sets the price
of a guess and the password's entropy sets how many guesses are needed. The
sign-in profile v2 (`signInEd25519ExternalSaltV2`,
[protocol](PROTOCOL.md#the-sign-in-profile-v2)) raises the price four times
over v1; it adds no entropy, and a weak password stays weak.

**Measured** on an Apple M5 Max laptop, Node 24.21.0, one derivation at a time,
`@noble/hashes` 2.0.1 (the SDK's KDF code, pure JavaScript, in a
`worker_threads` worker unless noted) against Node's native OpenSSL scrypt and
Argon2id (`crypto.scrypt`, `crypto.argon2`) as a stand-in for an attacker's
optimized code, p = 1 and a 32-byte output throughout. "Attacker cost" is the
memory a guess needs times the native time it takes, a proxy for the
area-time cost of guessing in parallel on dedicated hardware.

| KDF | memory | SDK (JS) | native | JS / native | attacker cost (MiB·s per guess) |
| --- | --- | --- | --- | --- | --- |
| scrypt N=2^16, r=8 (v1, Kalvora) | 64 MiB | 0.11 s | 0.097 s | 1.2 | 6 |
| scrypt N=2^17, r=8 | 128 MiB | 0.22 s | 0.20 s | 1.1 | 25 |
| **scrypt N=2^18, r=8 (v2)** | **256 MiB** | **0.45 s** | **0.41 s** | **1.1** | **105** |
| scrypt N=2^19, r=8 (not chosen) | 512 MiB | 0.90 s | — | — | — |
| Argon2id m=64 MiB, t=2 | 64 MiB | 0.93 s | 0.056 s | 17 | 4 |
| Argon2id m=64 MiB, t=3 | 64 MiB | 1.30 s | 0.081 s | 16 | 5 |
| Argon2id m=64 MiB, t=4 | 64 MiB | 1.80 s | 0.12 s | 15 | 8 |
| Argon2id m=128 MiB, t=2 | 128 MiB | 1.90 s | 0.13 s | 15 | 16 |
| Argon2id m=128 MiB, t=3 | 128 MiB | 2.65 s | 0.18 s | 15 | 23 |
| Argon2id m=128 MiB, t=4 | 128 MiB | 3.66 s | 0.31 s | 12 | 39 |
| Argon2id m=256 MiB, t=2 | 256 MiB | 4.20 s | 0.31 s | 14 | 79 |
| Argon2id m=256 MiB, t=3 | 256 MiB | 5.44 s | 0.35 s | 16 | 89 |
| Argon2id m=256 MiB, t=4 | 256 MiB | 7.69 s | 0.61 s | 13 | 155 |

The Argon2id rows and every native column were measured on the main thread;
a worker gave the same times (Argon2id t=3: 1.33 s at 64 MiB, 2.63 s at
128 MiB; scrypt on the main thread: 0.11, 0.23 and 0.50 s).

**Why scrypt at N = 2^18.** The SDK's scrypt runs within about 1.2 times of
native code, its Argon2id about 15 times slower, because pure JavaScript has no
fast 64-bit arithmetic for Argon2's BLAKE2b rounds. Even at a fraction of the
user wait, scrypt buys several times the attacker cost: at 0.45 s here, scrypt
N=2^18 costs a native attacker 105 MiB·s per guess, while the Argon2id setting
nearest a 2-3 s budget on this, a fast, laptop (m=128 MiB, t=3, 2.6 s) costs
23, and the only one within 2-3 s on a typical laptop (m=64 MiB, t=2) costs 4,
less than v1. Argon2id would win with a native or WebAssembly implementation;
that is a new dependency, so it is left to a later profile. N = 2^19 doubles
the cost again but needs a single 512 MiB allocation per derivation, which a
mid-range phone's browser may refuse or answer by killing the tab, and an
application that runs two derivations in one entry (a password change) would
double the wait.

**Estimated wait for v2** (not measured; scaled from the M5 Max by typical
single-thread JavaScript ratios): a typical laptop 0.9-1.4 s; a recent iPhone
0.7-0.9 s; a mid-range Android phone 1.8-2.7 s; a low-end phone about 4-5 s,
with 256 MiB allocated in the worker in every case. v1 takes a quarter of
that.

**What v2 buys.** A guess costs four times the scrypt work of v1 (2 bits), and
four times the memory too, about 16 times the area-time (4 bits) for an
attacker who keeps the whole table in memory. scrypt allows trading memory for
recomputation, so the 4-times work is the floor, not the 16. The gain is the
same for every holder of an oracle: the service's database (the sign-in public
key) and anyone with a published wallet address and the username. It is a
constant factor: a password an attacker would guess in a day against v1 falls
in about four days against v2 on the same hardware. Only password entropy
changes the order of magnitude, so the application's strength policy (below)
remains the main defence.

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

`signInEd25519ExternalSalt` (v1) and `signInEd25519ExternalSaltV2` (v2, the same construction at four times the scrypt cost) derive a sign-in key: an Ed25519 key whose `S_` identifier no chain accepts, for an identity service to enroll in place of a wallet. An application that also needs a wallet derives its master seed as an application secret of the same run and opens it with `withKalvoraWalletFromMasterSeed` ([protocol](PROTOCOL.md#part-3--the-sign-in-profile)).

| property | consequence |
| --- | --- |
| Not a wallet | The service stores the sign-in key's public key and receives its signatures, and nothing about the wallet. A sign-in key holds no funds, but it is lost exactly when the credentials are, and a wallet derived from an application secret of the same run is lost with it unless the application keeps its own encrypted backup of the master seed. |
| Still a password oracle | The sign-in public key is a password verifier at scrypt cost, like a wallet public key; the sign-in profile v2 raises that cost four times ([offline guessing cost](#offline-guessing-cost)). Anyone holding the service's database can guess offline, and a correct guess gives the password, and with it every key of the run: the sign-in key, every application secret, and the wallet derived from one. |
| A published wallet address is an oracle too | Once a wallet's address is public, anyone who also knows the username and the public salt can guess offline with no service data at all, and a hit gives the sign-in key as well as the wallet. Only high-entropy, password-manager-generated passwords resist either attack. |
| Independent branches | The sign-in key and the application secrets are HKDF-SHA256 outputs of the same scrypt output under different public domain strings. Neither the sign-in key nor its signatures give a secret, and a secret does not give the sign-in key. |
| No check value for the wallet | A mistyped password derives a different wallet without any error. The application compares the run's sign-in public key with the enrolled one before it uses or shows the wallet. |
| Bound to the profile | The wallet depends on the password, the username, the salt, the context, the application's label and the sign-in profile (its id, domains and KDF). A change to any of them is a different wallet; only an application's own encrypted backup of the master seed carries a wallet across one. Moving a user from v1 to v2 is such a change. Released sign-in profiles therefore stay exported after they are retired. |
| Memory | v2 allocates about 256 MiB per derivation, v1 about 64 MiB. Run one derivation at a time in a dedicated worker and terminate it afterwards. |
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
| Other sessions end | A rotation revokes every other session of the account and a recovery revokes every session. Login locks the account and rechecks the enrolled key before issuing a session, so a concurrent key replacement cannot leave a newly issued old-key session outside the completion's revocation snapshot. |
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
| A session becomes a credential after a wait | With the signed-in reset (on for every account once the deployment opts in), a stolen session can replace the enrolled key after 72 hours unless another session aborts it, the owner signs in with the password or changes it, or an email or recovery factor changes. The password change aborts it even when made on the session that started it, which a rotation keeps, so a stolen copy of the owner's own session cannot outlast a new password. While it waits, that session cannot sign out the others (`reset-pending`), and the start is reported to `onSecurityEvent` with `availableAt` so the owner can be told. A start from a session that expires before the wait ends is refused, and no session is extended. Turning it off needs the key's signature and another reset method; a reset counts as pending, and completes, only while it is on. |
| Reset is not key recovery | As with a recovery key, a reset binds a new key and recovers nothing derived from the old password. |
| The email-change interlock | Any address change, signed or not (`updateAccount` too), turns account recovery by email off and closes its live codes in the same statement, so a session alone cannot point the recovery channel at another inbox; a code also stops working once the address is re-verified after it was sent. |
| The settings bind their value | A setting is changed only by a fresh signature over `setting:on` or `setting:off`, so a stolen session cannot turn either reset on or off, and a signature for one value or one setting is useless for another. |
| Uniform start | `startAccountReset` answers every username with a fresh decoy id and the same expiry, whether or not a code is issued. The usable id and code go only to the verified mailbox; an open challenge is coalesced without spending recipient quota. Its per-recipient cap is a bucket of its own that nothing else reads, so email verification's `429` for an address neither reveals an eligible account nor silences its codes. The delivery, and so the response time, is the host's: it must pad every response to one fixed time and never surface a delivery failure. |
| Uniform refusals | Every failure of `completeAccountReset` an unauthenticated caller can cause is one `invalid-signature`; no code is added to `enumerationSensitiveCodes`. |
| Reauthentication is a proof, not a change | `verifyReauthentication` proves a fresh current-password run for a host label and audits it (`account.reauth`); what it unlocks is the host's own statement. |
| One statement, one lock order | Each reset is one statement that re-checks its code or wait, the session, the status and the enrolled key under row locks, in the account changes' lock order with the resets before the sessions. Abort, password login, password change, and email or recovery-factor changes advance a durable account generation. A signed-in reset completes only when its stored generation still matches, so a cancellation also stops a concurrent start invisible to its SQL snapshot. Revoking the initiating session stops its reset except for a completion already in flight. |

## Second sign-in factor

With `secondFactor` (a `SecondFactorIdentityServiceConfig`), a password proof
that the host's `required` says is not enough (a login signature, an emailed
reset code, a recovery key) yields a ticket, not a session, and the session is
issued only once the host's `verify` accepts a code
([server API](SERVER_API.md#second-sign-in-factor-opt-in)).

| property | consequence |
| --- | --- |
| The factor is the host's | The SDK stores no secret, no code and no factor state; it passes the submitted code to `verify` and keeps nothing of it. The strength of the factor (TOTP window, recovery codes, replay of a code) is the verifier's. |
| No path issues a session around it | Login, account recovery by email and recovery-key completion all ask `required` and insert the ticket in the statement that would have inserted the session. The signed-in reset issues no session, and registration's new account has no factor. |
| Fails closed | A `required` that answers anything but `false` gates; one that throws refuses the sign-in. A `verify` answer other than `"ok"` or `"locked"` is a wrong code; one that throws refuses the attempt, which stays counted. |
| A ticket is short-lived and bound | 32 random bytes, 5 minutes, 5 attempts, stored only as a domain-separated SHA-256, one per challenge. It issues a session only while its account is active and the key its proof was for is still enrolled, so a rotation or a recovery in between ends it, and a consumed ticket never issues a second session. |
| Guessing is bounded per account | Five codes per ticket, and 25 wrong codes per account an hour (`login-account`, whatever the ticket or the IP). Each code is counted before `verify` sees it and given back only on `"ok"` or `"locked"`, and a full bucket refuses every outstanding ticket, so abandoning tickets early gains nothing: a holder of the password gets at most 25 wrong guesses an hour. The same bound locks the owner out for that hour; that denial needs the password. |
| `required` is no existence oracle for the email reset | Account recovery by email consults `required` (and prepares a ticket) only for a caller who names a live email reset of the username. Its real `resetId` reaches only the delivered email, and an anonymous start answers a decoy, so the timing of a completion cannot tell anyone else whether the account exists or has a factor. |
| A reset still happens before the factor | Account recovery by email and recovery-key completion replace the enrolled key and revoke every session before the factor is asked, and only the new session waits for it. Whoever reads the inbox (or holds the recovery key) without the factor can therefore lock the owner out of the old password, though not sign in; the owner recovers through the same channel. |
| The ticket is a bearer secret | Between the two steps it stands for the password proof. It is returned in the response body, never set as a cookie; a client keeps it in memory only. |

## Account deletion

`deleteAccount` is a server-side operator call; nothing routes it.

| property | consequence |
| --- | --- |
| Complete and atomic | One statement deletes the account and every row the service keys to it or to its username, rate-limit counters aside (below), live sessions included only when the caller asks (`revokeLiveSessions`), so a refused or failed deletion changes nothing. The live-session check runs after the account lock in a fresh snapshot, so a session committed while the deletion waited for that lock is counted, never cascaded away unseen. |
| Audit without personal data | Kept audit rows lose their account link but keep `deleted_account_id`; the `account.deleted` row holds counts only. `email.verification-start` rows keep an address's domain and are outside `auditRetentionDays`'s rule, as for every account. |
| What stays | `<p>_wallet_setups` (per-account public salts, keyed by username and immutable) is never deleted: a wallet derived under it may hold funds outside the service. Rate-limit rows stay until `pruneExpired` removes them, within a day: those keyed with an IP hash, and those keyed by the account's email address (`email-verification`, with the username; `email-verification-recipient`; `account-reset-recipient`). The last three are unsalted SHA-256 digests that anyone who knows the address can recompute; they are kept because deleting the recipient caps would let a caller reset a mail-flood cap by deleting and re-registering. Backups and database history are the operator's to bound. |
| A freed username | The username can be registered again as a new account, which inherits nothing. Under a per-account wallet mode the same password then derives the same wallet, because the salt row stays. |

## Server boundary

A deterministic service (`service-deterministic` or `per-account-deterministic`) stores public identity, profile ID, the public salt (the service's, or one per account), session records, and one-use challenges, and, with recovery keys enabled, recovery public keys and SHA-256 digests of recovery tokens, and, with account resets, each account's two reset settings and SHA-256 digests of reset codes (80 bits, so a read of the digests does not yield a live code), and, with the second sign-in factor, domain-separated SHA-256 digests of second-factor tickets (256 bits) and no factor data. It does not need a seed, private key, wallet password, recovery code, application secret, or encrypted vault. Random-vault mode additionally stores encrypted vaults, retrievable only after platform authorization; a stolen vault permits offline password guessing. In no mode does the SDK send a plaintext seed, private key, wallet password, recovery code, or application secret to the server. Under the sign-in profile the public identity it stores is the sign-in key's, and it needs nothing about the user's wallet. The sign-in profile is served only in the deterministic modes; `random-vault` mode refuses it.

A server pepper used to generate an external salt is not wallet custody, but it introduces server dependency and does not stop the server from testing password guesses against a known public identity.
