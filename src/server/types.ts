import type { DerivationProfile } from "../profile.js";
import type { AccountWalletMode, AccountWalletSetup } from "../accountWallet.js";
import type { WalletVault } from "../vault.js";

export type ServiceWalletMode = AccountWalletMode | "service-deterministic";
export type StoredWalletVault = Readonly<{ vault: WalletVault; revision: number }>;
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
   * The profile of the key that signs in, which carries its KDF parameters,
   * transcript domains, and identity codec: a chain's wallet profile, or the
   * chain-neutral sign-in profile, whose enrolled key is not a wallet. Must use
   * the `external-32` salt policy — a service that does not own a salt has
   * nothing to publish.
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
  /**
   * Choose explicitly for new deployments. Omitted preserves existing wallets.
   * `random-vault` needs a chain wallet profile and refuses the sign-in profile.
   */
  walletMode?: ServiceWalletMode;
  /**
   * Whether new session rows keep `ip_hash` and `user_agent_hash`. Default
   * `true`. With `false` both are written as NULL. The service never reads them
   * back from a session row, and rate limits keep hashing
   * `RequestContext.ipHash` directly either way.
   */
  storeSessionClientHashes?: boolean;
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
  walletMode: ServiceWalletMode;
  storeSessionClientHashes: boolean;
}>;

/**
 * Deployment metadata. The service salt is used only in legacy mode; new
 * modes obtain their account setup from the challenge response.
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
  walletMode?: ServiceWalletMode;
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

/**
 * One enrolled key of an account: a row of `<p>_account_wallets`. It is a
 * wallet only when the profile is a chain wallet profile; under the sign-in
 * profile it is the account's sign-in key. The name is kept for compatibility.
 */
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
  /** Present for the two account wallet modes; save and reuse across devices. */
  walletSetup?: AccountWalletSetup;
}>;

export type IdentitySession = Readonly<{
  id: string;
  accountId: string;
  issuedAt: Date;
  expiresAt: Date;
  lastSeenAt: Date;
}>;

/**
 * One live session of the caller's account, for display in a sessions list.
 * It carries no hash, address or token: only what a list shows.
 */
export type ListedSession = Readonly<{
  id: string;
  issuedAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  /** The coarse label stored at sign-in, or `null` when none was supplied. */
  clientLabel: string | null;
  /** True on the row of the session whose token made the call. */
  current: boolean;
}>;

/** Returned once, at creation. Only the hash is ever persisted. */
export type IssuedSession = Readonly<{
  session: IdentitySession;
  token: string;
}>;

export type AuthenticatedIdentity = Readonly<{
  account: IdentityAccount;
  /** The account's enrolled keys (see `IdentityWallet`). */
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
  /** Required only in random-vault mode. Never send the plaintext seed or secrets. */
  vault?: WalletVault;
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
  /**
   * A coarse, display-only description of the client, such as
   * "Firefox on macOS", stored on the session a call issues (register and
   * login). It must match the column's CHECK, `^[A-Za-z0-9 .()-]{1,64}$`: 1 to
   * 64 ASCII letters, digits, spaces, `.`, `(`, `)` or `-`. Any other value is
   * dropped, never an error, and the session is issued without a label. Never
   * pass a raw User-Agent.
   */
  clientLabel?: string;
  now?: Date;
}>;

/** The `<p>_sessions_client_label` CHECK (migration 6), character for character. */
export const clientLabelPattern = /^[A-Za-z0-9 .()-]{1,64}$/u;

/**
 * Returns `value` when it is a storable client label, otherwise `undefined`.
 * Package-internal: the router and the service share it, so both drop exactly
 * what the database would refuse.
 */
export function acceptedClientLabel(value: unknown): string | undefined {
  return typeof value === "string" && clientLabelPattern.test(value) ? value : undefined;
}

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
