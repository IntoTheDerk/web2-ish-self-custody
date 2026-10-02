# Account wallet modes

These wallets can serve as signing identities without holding funds. The
platform keeps its own account UUID, maps it to the current signing key, and
pays transaction fees through its own transaction integration. This SDK does
not submit transactions or implement fee sponsorship.

Choose one mode per identity-service namespace:

| `walletMode` | Key creation | Password change | What the platform saves |
| --- | --- | --- | --- |
| `per-account-deterministic` | Password, username, context, and a random account salt | Enroll a new wallet; account UUID stays the same | Public account setup and enrolled public keys |
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

### Password change and replacement

1. Derive the proposed identity with the **new** password and existing setup.
2. Call `createWalletReplacementChallenge(username, newIdentity)` or
   `POST /identity/wallet-replacement-challenges` with `{ username, address,
   publicKey }`.
3. Check the returned replacement message against the intended new identity.
   Sign its exact UTF-8 bytes using both the old and new wallets, in separate
   synchronous callbacks.
4. Call `replaceWallet` / `POST /identity/wallet-replacements` with `{ username,
   address, publicKey, challengeId, currentSignature, signature }`.
   `currentSignature` is from the old key; `signature` is from the new key.
5. Sign in again with the new wallet. Discard the old password only after a
   successful server response, or check which key is active after a lost response.

The replacement message binds the new address and public key. It is single-use.
The SQL mutation retires all old active keys, enrolls the new primary key,
increments the account's wallet generation, revokes sessions, and records an
audit event atomically. An overlapping login using the previous generation
cannot create a usable session. Retired keys remain in the database for audit
but disappear from `listWallets` and cannot authorize new sessions. Re-enrolling
an address already recorded in this service is rejected.

The platform must update any other permissions that refer to the old key,
including on-chain authorization where applicable. Retiring a key in this
identity service does not revoke it on a blockchain or move assets.

### Forgotten password

The platform verifies recovery through its own account-recovery process. Once
authorized, trusted server code calls:

```ts
await service.replaceWalletAfterRecovery({
  accountId: verifiedAccount.id,
  address: newIdentity.address,
  publicKey: newIdentity.publicKey,
  challengeId: replacementChallenge.id,
  signature: newWalletSignature,
});
```

This requires the new wallet's proof and a matching account challenge. It has
**no HTTP route**. Never expose it using an account ID or email verification
claim supplied by the requester without independently checking ownership. In
particular, the existing registration-email verification endpoint is not an
account-recovery grant. This operation replaces the lost wallet; it does not
recover the old key. Platform authority to reassign signing identities is an
explicit part of this mode's trust model.

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
