export { derivePublicIdentity, withDerivedWallet } from "./derive.js";
export { DerivationError } from "./errors.js";
export {
  normalizeDemocracyOsUsername,
  normalizeWeb2ishUsername,
} from "./normalization.js";
export { builtInProfiles, getProfile } from "./profiles.js";
export type {
  BuiltInProfileId,
  DerivationContext,
  DerivationCredentials,
  DemocracyOsCredentials,
  DerivedPublicIdentity,
  DerivedWallet,
  Ed25519Identity,
  Ed25519Wallet,
  ProfileDescription,
  Secp256k1Identity,
  Secp256k1Wallet,
  ZeraEd25519Credentials,
} from "./types.js";
