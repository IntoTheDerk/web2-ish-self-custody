/**
 * Generic deterministic-custody core.
 *
 * Nothing here knows about any particular chain. A chain supplies an
 * `IdentityCodec` (how a public key becomes an address) and one or more
 * `DerivationProfile`s (KDF parameters plus the domain-separation strings that
 * define its transcript). Built-in chains live under `web2-ish-self-custody/chains/*`.
 */
export { assertCodecRoundTrip, defineIdentityCodec } from "./codec.js";
export type { IdentityCodec } from "./codec.js";
export { derivePublicIdentity, withDerivedWallet } from "./derive.js";
export { DerivationError } from "./errors.js";
export type { DerivationErrorCode } from "./errors.js";
export {
  MAXIMUM_PASSWORD_BYTES,
  MINIMUM_PASSWORD_CHARACTERS,
  normalizeUsername,
} from "./normalization.js";
export { defineDerivationProfile } from "./profile.js";
export type { DerivationProfile, KeyDerivation, ProfileDomains, SaltPolicy } from "./profile.js";
export { ED25519_SEED_BYTES, deriveIdentityFromSeed } from "./seed.js";
export type { SeedIdentity } from "./seed.js";
export type {
  DerivationContext,
  DerivationCredentials,
  DerivedIdentity,
  DerivedWallet,
} from "./types.js";
export {
  WALLET_VAULT_FORMAT,
  createWalletVault,
  createWalletVaultFromCredentials,
  generateRecoveryCode,
  normalizeRecoveryCode,
  openWalletVaultWithPassword,
  openWalletVaultWithRecoveryCode,
  parseWalletVault,
  rewrapWalletVaultPassword,
} from "./vault.js";
export type { CreateWalletVaultOptions, SealedBox, WalletVault } from "./vault.js";
