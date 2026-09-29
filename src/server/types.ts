import type { DerivationProfile } from "../profile.js";

export type ChallengePurpose = "registration" | "login" | "rotation";

export const challengePurposes: readonly ChallengePurpose[] = Object.freeze([
  "registration",
  "login",
  "rotation",
]);

/**
 * Fixed, per-deployment identity of one service's wallet namespace.
 *
 * `serviceProfileId` + `applicationId` + the stored public salt jointly decide
 * which wallet a given username/password produces. Changing any of them is a
 * wallet migration, never a config tweak, which is why the schema makes the
 * persisted row immutable.
 */
export type IdentityServiceConfig = Readonly<{
  serviceProfileId: string;
  /**
   * The chain's profile object, which carries its KDF parameters, transcript
   * domains, and identity codec. Must use the `external-32` salt policy — a
   * service that does not own a salt has nothing to publish.
   */
  profile: DerivationProfile;
  applicationId: string;
  networkId: string;
  /** Table namespace. Lets one database host several services side by side. */
  tablePrefix?: string;
  sessionTtlSeconds?: number;
  challengeTtlSeconds?: number;
  emailVerificationTtlSeconds?: number;
  emailVerificationMaxAttempts?: number;
  /** Requires a verified email before `POST /accounts` succeeds. */
  requireVerifiedEmail?: boolean;
}>;

export type ResolvedIdentityServiceConfig = Readonly<{
  serviceProfileId: string;
  profile: DerivationProfile;
  applicationId: string;
  networkId: string;
  tablePrefix: string;
  sessionTtlSeconds: number;
  challengeTtlSeconds: number;
  emailVerificationTtlSeconds: number;
  emailVerificationMaxAttempts: number;
  requireVerifiedEmail: boolean;
}>;

/**
 * Everything a client needs to derive its wallet. All of it is public by
 * design: the salt is not a secret, it is a namespace separator.
 */
export type PublishedDerivationProfile = Readonly<{
  serviceProfileId: string;
  profileId: string;
  /** Lets a client confirm it will encode addresses the way the server does. */
  codecId: string;
  algorithm: string;
  curve: "ed25519";
  applicationId: string;
  networkId: string;
  publicSaltHex: string;
  kdf: Readonly<{ N: number; r: number; p: number; dkLen: number }>;
}>;

export type IdentityAccount = Readonly<{
  id: string;
  serviceProfileId: string;
  usernameNormalized: string;
  /**
   * Optional, user-chosen label. `null` means the user never set one, which is
   * why it is nullable rather than defaulted: the username is a derivation
   * input and cannot change, so this is the only editable part of an identity
   * and a client needs to know whether it was actually chosen.
   */
  displayName: string | null;
  email: string | null;
  emailVerifiedAt: Date | null;
  status: "active" | "suspended";
  createdAt: Date;
  updatedAt: Date;
}>;

export type IdentityWallet = Readonly<{
  id: string;
  accountId: string;
  serviceProfileId: string;
  profileId: string;
  codecId: string;
  curve: "ed25519";
  applicationId: string;
  networkId: string;
  address: string;
  addressNormalized: string;
  publicKey: string;
  fingerprint: string;
  isPrimary: boolean;
  createdAt: Date;
}>;

export type IdentityChallenge = Readonly<{
  id: string;
  purpose: ChallengePurpose;
  usernameNormalized: string;
  /** The exact bytes the client must sign, as UTF-8 text. */
  message: string;
  expiresAt: Date;
}>;

export type IdentitySession = Readonly<{
  id: string;
  accountId: string;
  issuedAt: Date;
  expiresAt: Date;
  lastSeenAt: Date;
}>;

/** Returned once, at creation. Only the hash is ever persisted. */
export type IssuedSession = Readonly<{
  session: IdentitySession;
  token: string;
}>;

export type AuthenticatedIdentity = Readonly<{
  account: IdentityAccount;
  wallets: readonly IdentityWallet[];
  session: IdentitySession;
}>;

export type RegistrationInput = Readonly<{
  username: string;
  displayName?: string;
  email?: string;
  address: string;
  publicKey: string;
  challengeId: string;
  signature: string;
}>;

export type LoginInput = Readonly<{
  username: string;
  challengeId: string;
  signature: string;
}>;

export type RequestContext = Readonly<{
  /** Pre-hashed by the caller; the service never stores a raw IP. */
  ipHash?: string;
  userAgentHash?: string;
  now?: Date;
}>;

export type EmailVerificationRequest = Readonly<{
  username: string;
  email: string;
}>;

/**
 * The service produces the code and hands it to the host application to
 * deliver. Delivery is deliberately out of scope: transport, templating, and
 * suppression lists belong to the application, not to a custody SDK.
 */
export type IssuedEmailVerification = Readonly<{
  verificationId: string;
  code: string;
  email: string;
  expiresAt: Date;
}>;
