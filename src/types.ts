import type { DerivationProfile } from "./profile.js";

/**
 * Binds a derivation to one application on one network. Two services that share
 * a profile and a salt still produce different wallets if their context differs.
 */
export type DerivationContext = Readonly<{
  applicationId: string;
  networkId: string;
}>;

export type DerivationCredentials = Readonly<{
  /** The profile object itself, not an id — the core has no profile registry. */
  profile: DerivationProfile;
  username: string;
  password: Uint8Array;
  context: DerivationContext;
  /** Required by `external-32` profiles, rejected by every other policy. */
  salt?: Uint8Array;
  signal?: AbortSignal;
  onProgress?: (progress: number) => void;
}>;

/**
 * The public identity of a derived key. It is a chain wallet when the profile
 * is a chain wallet profile, such as the Kalvora profile, and a sign-in key
 * under the sign-in profile; the names keep "wallet" either way.
 */
export type DerivedIdentity = Readonly<{
  profileId: string;
  codecId: string;
  curve: "ed25519";
  normalizedUsername: string;
  address: string;
  publicKey: string;
  publicKeyBytes: Uint8Array;
  fingerprint: string;
}>;

/**
 * A derived key inside `withDerivedWallet`'s callback scope: a wallet under a
 * chain wallet profile, a sign-in key under the sign-in profile.
 */
export type DerivedWallet = Readonly<{
  identity: DerivedIdentity;
  /**
   * Signs the exact bytes given, with no framing or prehashing. Named
   * "unsafe" because the caller owns the entire responsibility for what those
   * bytes mean: pass an unreviewed message and you have signed it.
   */
  signExactMessageUnsafe: (message: Uint8Array) => Uint8Array;
}>;
