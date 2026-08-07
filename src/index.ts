export { derivePublicIdentity, withDerivedWallet } from "./derive.js";
export { DerivationError } from "./errors.js";
export type { DerivationErrorCode } from "./errors.js";
export {
  MAXIMUM_PASSWORD_BYTES,
  MINIMUM_PASSWORD_BYTES,
  normalizeUsername,
} from "./normalization.js";
export { builtInProfiles, getProfile } from "./profiles.js";
export type {
  BuiltInProfileId,
  DerivationContext,
  DerivationCredentials,
  DerivedPublicIdentity,
  DerivedWallet,
  Ed25519Identity,
  Ed25519Wallet,
  ProfileDescription,
  ZeraEd25519Credentials,
  ZeraEd25519ExternalSaltCredentials,
  ZeraEd25519ProfileId,
} from "./types.js";
