/**
 * Generic deterministic-custody core.
 *
 * Nothing here knows about any particular chain. A chain supplies an
 * `IdentityCodec` (how a public key becomes an address) and one or more
 * `DerivationProfile`s (KDF parameters plus the domain-separation strings that
 * define its transcript). Built-in chains live under `web2-ish-self-custody/chains/*`.
 */
export {
  ACCOUNT_CHANGE_DOMAIN,
  accountChangeActions,
  buildAccountChangeMessage,
  normalizeEmail,
} from "./accountChange.js";
export type { AccountChangeAction, AccountChangeMessageInput } from "./accountChange.js";
export { assertCodecRoundTrip, defineIdentityCodec } from "./codec.js";
export type { IdentityCodec } from "./codec.js";
export { derivePublicIdentity, withDerivedWallet } from "./derive.js";
export {
  createRandomAccountWallet,
  createRandomAccountWalletWithRecoveryCodes,
  withAccountWallet,
} from "./accountWallet.js";
export type { AccountWalletMode, AccountWalletSetup } from "./accountWallet.js";
export { DerivationError } from "./errors.js";
export type { DerivationErrorCode } from "./errors.js";
export {
  MAXIMUM_PASSWORD_BYTES,
  MINIMUM_PASSWORD_CHARACTERS,
  normalizeUsername,
} from "./normalization.js";
export {
  OPRF_ELEMENT_BYTES,
  OPRF_INPUT_DOMAIN,
  OPRF_SALT_DOMAIN,
  startOprfSalt,
} from "./oprf.js";
export type { OprfSaltRequest } from "./oprf.js";
export { defineDerivationProfile } from "./profile.js";
export type { DerivationProfile, KeyDerivation, ProfileDomains, SaltPolicy } from "./profile.js";
export { ED25519_SEED_BYTES, deriveIdentityFromSeed } from "./seed.js";
export type { SeedIdentity } from "./seed.js";
export {
  SIGN_IN_KEY_DOMAIN,
  signInEd25519Codec,
  signInEd25519ExternalSalt,
  signInEd25519ExternalSaltV2,
  signInHkdfEd25519,
} from "./signIn.js";
export type {
  DerivationContext,
  DerivationCredentials,
  DerivedIdentity,
  DerivedWallet,
} from "./types.js";
export {
  DEFAULT_RECOVERY_CODE_COUNT,
  MAX_RECOVERY_CODES,
  WALLET_VAULT_FORMAT,
  WALLET_VAULT_FORMAT_V2,
  createWalletVault,
  createWalletVaultFromCredentials,
  createWalletVaultWithRecoveryCodes,
  generateRecoveryCode,
  generateRecoveryCodes,
  normalizeRecoveryCode,
  openWalletVaultWithPassword,
  openWalletVaultWithRecoveryCode,
  parseWalletVault,
  parseWalletVaultV1,
  parseWalletVaultV2,
  recoveryCodeHint,
  recoveryCodeHints,
  removeWalletVaultRecoveryCode,
  replaceWalletVaultRecoveryCodes,
  rewrapWalletVaultPassword,
  rewrapWalletVaultPasswordV2,
  upgradeWalletVaultRecoveryCodes,
} from "./vault.js";
export type {
  AnyWalletVault,
  CreateWalletVaultOptions,
  RecoverySlot,
  SealedBox,
  WalletVault,
  WalletVaultV2,
} from "./vault.js";
