# Integration

## Random encrypted-vault integrations

Applications that already create a random wallet seed should not replace it
with a username/password-derived seed merely to use this package. The recovery
and password-guessing properties are materially different.

Use `web2-ish-self-custody/zera-ed25519` only to derive the public ZERA identity
from an application-owned random seed. Keep encryption, storage, recovery,
origin binding, and lifecycle controls in the application. This split lets
multiple applications share the exact Ed25519/Base58/`A_` identity convention
without turning this SDK into a browser storage or policy layer.

## Knight Armor

Use `web2ish-zera-ed25519-v1` as an explicitly selected deterministic-custody mode:

1. Encode password input immediately before creating a one-shot worker.
2. Transfer username, password bytes, fixed profile ID, `knight-armor`, and the exact ZERA network ID to the worker.
3. Derive the public identity for discovery.
4. For signing, pass only a typed proposal or vote intent into the worker.
5. Rebuild and display the exact transaction in a trusted confirmation surface.
6. Sign only after confirmation through `signExactMessageUnsafe`, return only the signature or signed transaction, terminate the worker, and clear caller-owned password bytes.

Do not replace Knight Armor’s random-seed vault without an explicit product decision. The deterministic mode has different recovery and password-guessing properties.

To give Knight Armor and DemocracyOS the same Ed25519/network behavior while
keeping independently administered service salts, select
`web2ish-zera-ed25519-external-salt-v1` in both services. Each service must
persist its own exact 32-byte public salt in its Postgres-compatible database
and provide the fixed service-specific `applicationId`. Use the same
`networkId` for the same ZERA network. The differing salt and application ID
intentionally produce different wallets even for identical credentials.

## DemocracyOS web

Adopt `democracyos-scrypt-sha512-secp256k1-v2` first:

1. Preserve the existing backend challenge and 32-byte public salt.
2. Replace the local derivation implementation with the SDK.
3. Compare existing and SDK output against the committed compatibility vector.
4. Keep the backend public-key/address/signature verification unchanged.
5. Delete the old implementation only after side-by-side compatibility passes.

The DemocracyOS mobile prototype uses a different v1 protocol. Do not silently map it to the web-v2 profile.

Moving DemocracyOS to `web2ish-zera-ed25519-external-salt-v1` is a wallet
migration, not a compatible profile update. Existing web-v2 users retain their
secp256k1 identities unless the product explicitly enrolls them in the new
Ed25519 profile and records the resulting public identity.

## Updating the shared dependency

Both applications should pin an exact reviewed commit. A profile implementation must never change in place. SDK upgrades that add a profile are non-migrating; selecting that new profile is a separate product migration.
