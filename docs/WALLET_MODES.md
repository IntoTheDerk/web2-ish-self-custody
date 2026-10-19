# Account wallet modes

These wallets can serve as signing identities without holding funds. The
platform keeps its own account UUID, maps it to the current signing key, and
pays transaction fees through its own transaction integration. This SDK does
not submit transactions or implement fee sponsorship.

Choose one mode per identity-service namespace:

| `walletMode` | Key creation | Password change | What the platform saves |
| --- | --- | --- | --- |
| `per-account-deterministic` | Password, username, context, and a random account salt | A different password derives a different key; the opt-in sign-in-key rotation rebinds the account to it | Public account setup and enrolled public keys |
| `random-vault` | Random 32-byte Ed25519 seed generated on the client | Re-encrypt the same wallet | Public account setup and encrypted vault |

Omitting `walletMode` preserves the older `service-deterministic` behavior.
Existing profile IDs, derivation transcripts, codecs, and test vectors are
unchanged. New deployments should choose explicitly. Do not switch a populated
namespace to a new mode: migration 5 preserves legacy accounts, and the stored
policy rejects subsequent configuration changes. Use a new namespace and an
explicit enrollment/migration process instead.

## Server setup

```ts
import { createIdentityService, createIdentityRouter } from "web2-ish-self-custody/server";
import { kalvoraEd25519ExternalSalt as profile } from "web2-ish-self-custody/chains/kalvora";

const service = createIdentityService(sql, {
  serviceProfileId: "my-platform.identity",
  profile,
  applicationId: "my-platform",
  networkId: "kalvora-testnet",
  walletMode: "per-account-deterministic", // or "random-vault"
});
await service.migrate();
const route = createIdentityRouter(service, {
  trustedOrigins: ["https://my-platform.example"],
  // Supply hashRequestIp from the platform's trusted request metadata.
});
```

`createChallenge(username, purpose)` / `POST /identity/challenges` returns
`walletSetup` in either new mode. The first request atomically reserves a random
UUID and a separate random 32-byte salt for the normalized username. Concurrent
requests converge on the same record. Registration uses that UUID as the actual
account ID. Requests for unknown usernames also receive setup metadata, so
issuing a challenge does not prove that an account exists.

The UUID identifies the account; it is **not** the salt. Separate random salt
bytes fit the existing `external-32` profile exactly. Equal credentials on
separately provisioned accounts/platforms therefore produce different keys
with overwhelming probability, even if application/network labels coincide.
Duplicating the same database and context intentionally duplicates the namespace.

Back up the setup table together with accounts. Never regenerate a salt during
login, password change, or database recovery. Setup records are immutable,
including pending registrations, and are not removed by `pruneExpired`.
Rate-limit/gate enrollment at the platform edge as well as using the SDK's IP
buckets; supply a trustworthy `hashRequestIp` to avoid one shared default bucket.

## Deterministic enrollment and login

Pin the expected profile, codec, application, network, and mode in your client.
Check the challenge's purpose, username, service identity, and expiry before
signing; never blindly sign arbitrary server text. The helpers validate the
setup's profile/codec and mode, but cannot know which platform the user intended.

```ts
import { withAccountWallet } from "web2-ish-self-custody";
import { bytesToHex } from "@noble/hashes/utils.js";

// challenge comes from POST /identity/challenges, after the checks above.
const proof = await withAccountWallet(challenge.walletSetup, profile, passwordBytes, wallet => ({
  address: wallet.identity.address,
  publicKey: wallet.identity.publicKey,
  signature: bytesToHex(wallet.signExactMessageUnsafe(new TextEncoder().encode(challenge.message))),
}));
```

For registration, send `{ username, challengeId: challenge.id, ...proof }` to
`POST /identity/accounts`. For login, send only `{ username, challengeId,
signature }` to `POST /identity/sessions`. The server receives neither the
password nor a private key. Clear caller-owned password buffers in `finally`;
run expensive derivation in a dedicated worker as described in
[INTEGRATION.md](INTEGRATION.md).

Another device obtains the same setup from a fresh challenge and repeats this
flow. There is no encrypted key file to synchronize in deterministic mode.

### Application secrets and the sign-in profile

`withAccountWallet` takes `withDerivedWallet`'s options as a fifth argument and
passes `applicationSecrets` through unchanged, so the callback receives the
secrets of the same scrypt run as its second parameter, under the same rules
([protocol](PROTOCOL.md#application-secrets)). That is what lets this mode serve
the sign-in profile: configure the service with `signInEd25519ExternalSalt`, and
the application opens its wallet from an application secret in the same
callback ([pattern](INTEGRATION.md#a-sign-in-key-separate-from-the-wallet)).
The service enrolls only the `S_` sign-in key. Random-vault mode refuses the
sign-in profile, at service configuration (`invalid-service-profile`) and in
`createRandomAccountWallet` (`invalid-profile`): its key is random, so there is
no application secret to derive a wallet from.

### Password changes and recovery in the deterministic modes

Calling `withAccountWallet` with a different password derives a different key;
on its own that changes nothing at the service. Two opt-in operations of the
identity service rebind the account, both in `service-deterministic` and
`per-account-deterministic` mode only
([server API](SERVER_API.md#account-changes-and-recovery-keys-opt-in)):

- **Sign-in-key rotation** (`accountSecurity.signInKeyRotation`). The client
  derives the new key with the new password, signs the
  [account-change message](PROTOCOL.md#part-4--the-account-change-message)
  with the current key (proof of the current password) and with the new key
  (proof of possession), and calls `rotateSignInKey`. One statement updates the
  account's one enrolled-key row in place and revokes every other session; the
  caller's session stays.
- **Recovery keys** (`accountSecurity.recoveryKeys`). A signed-in user enrolls
  the public half of a recovery key derived from a secret the application gives
  them (for example a phrase). After losing the password they prove that key
  (`beginRecovery`, which spends nothing), then sign the new password's key
  with it (`completeRecovery`): one statement replaces the enrolled key, marks
  the recovery key used, revokes every session and issues a new one.
- **Account resets** (`accountSecurity.emailReset`,
  `accountSecurity.signedInReset`). Account recovery by email replaces the key
  with an emailed code (`startAccountReset`, `completeAccountReset`) for an
  account whose owner turned it on with a verified email; the signed-in reset
  replaces it from a session after a 72-hour wait that any other session, a
  password sign-in or a password change aborts (`startSignedInReset`,
  `completeSignedInReset`)
  ([server API](SERVER_API.md#account-resets-opt-in)). The new key alone signs.

Each replaces the key; none recovers the old one, and under a chain wallet
profile the replaced key is a wallet that the account no longer signs in with.
The platform updates anything else that names the old key, including on-chain
authorization where applicable, and keeps its own account UUID throughout.
`random-vault` mode refuses them all (`invalid-request`): there a password change
is a vault re-wrap that keeps the wallet, and the vault has its own recovery
code. A platform that wants a different flow can still build its own; the
service's are off unless configured.

## Random wallet and encrypted vault

```ts
import { createRandomAccountWallet, openWalletVaultWithPassword } from "web2-ish-self-custody";

const { vault, recoveryCode } = await createRandomAccountWallet(
  challenge.walletSetup, profile, passwordBytes,
);
const signature = await openWalletVaultWithPassword(vault, passwordBytes, profile.codec,
  wallet => bytesToHex(wallet.signExactMessageUnsafe(new TextEncoder().encode(challenge.message))),
);
// POST /identity/accounts:
const registration = {
  username, challengeId: challenge.id,
  address: vault.address, publicKey: vault.publicKey, signature, vault,
};
```

Show the recovery code once and ask the user to save it separately. Send only
`registration`, **never** `recoveryCode`, a password, or a seed. The SDK generates
and clears the seed internally. Random mode uses a direct Ed25519 seed; the
profile supplies the codec and password-wrapper KDF, not a password-to-wallet
derivation or the Kalvora SLIP-0010 path.

The server validates the envelope, identity headers, and KDF settings, then saves
the ciphertext atomically with account enrollment. It cannot prove that the
ciphertext decrypts correctly. Before uploading a new or rewrapped vault, open
it locally and check the expected address. Keep an export/backup of the encrypted
vault too: a recovery code without the corresponding vault cannot reconstruct
the random seed.

### Another device

Downloading a vault requires platform authorization independent of a wallet
signature, because the new device needs the vault before it can sign. Configure
the router's `authorizeVaultRead(request)` hook to verify an existing platform
session or a short-lived account-recovery grant and return its account UUID.
Return `null` for an unauthorized request. Do not simply read a user-supplied
UUID from a header and trust it.

`POST /identity/wallet-vault` then returns `{ vault, revision }` for the authorized
account. With no hook, downloads return 401. Trusted server integrations can
call `service.getWalletVault(verifiedAccountId)` directly after the same access
check. Hosts must rate-limit their authorization hook as well as vault reads.
Users can alternatively import a previously exported vault locally.

Decrypt on the device with the password or recovery code, then sign a normal
login challenge. Platform authorization permits fetching ciphertext; it does
not decrypt it or replace either unlocking secret.

### Password change and recovery

Use `rewrapWalletVaultPassword` with either `{ password: oldPasswordBytes }` or
`{ recoveryCode }`, the new password, and the saved recovery code. Verify the
result locally, then upload it through `PUT /identity/wallet-vault` with
`{ vault: updatedVault, expectedRevision: downloadedRevision }` and the wallet
session cookie/bearer token. Direct callers use
`service.updateWalletVault(token, updatedVault, expectedRevision)`.

The same address is retained. Concurrent or stale updates return
`wallet-conflict` (409); fetch the latest envelope before retrying. An old
password can still open an **old copy** of the vault, so rewrapping is not key
revocation and does not invalidate signatures made with that seed. A compromised
key needs a separate authorization/key migration.

Losing both the password and recovery code loses access to this wallet. A
platform login or password reset cannot decrypt it. Rewrapping requires a
recovery code to create the replacement recovery wrapper; a user who lost their
code but knows the password can generate a new code with `generateRecoveryCode`.

## Security and deployment boundaries

Both modes require strong passwords. A known deterministic public key permits
offline password guessing. A stolen password-encrypted vault also permits
offline guessing even though its seed was random. Salt uniqueness separates
accounts; it does not add password entropy.

Keep ciphertext out of logs, analytics, URLs, and public endpoints. Back up
vaults and their revisions, limit access, and restore-test the database. Configure
HTTPS, trusted origins, secure sessions, and request limits. Browser-native and
mobile integrations need secure randomness and Web Crypto support; the published
package is a JavaScript/TypeScript SDK, not a native SDK for every language.
