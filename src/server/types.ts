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
  /**
   * Opt-ins for the account changes that alter what signs in. Each defaults
   * to `false`, so a deployment sees no new behavior until it turns one on.
   * They apply only in the deterministic wallet modes; `random-vault` mode
   * refuses each operation they enable whatever their value.
   */
  accountSecurity?: AccountSecurityOptions;
  /**
   * Called after the statement of a security-relevant account change has
   * committed, for a host that sends its own notices. The service awaits it
   * for at most 3 seconds and ignores whatever it throws: a slow or failing
   * hook never fails, delays past that bound, or rolls back the change.
   */
  onSecurityEvent?: SecurityEventHook | null;
  /**
   * When set, `pruneExpired` also deletes this service's `account.*` and
   * `session.*` audit rows older than this many days. A row whose account was
   * deleted names no service profile and is never pruned: delete an
   * account's audit rows before the account. Unset (or `null`) keeps audit
   * rows indefinitely, as before. An integer from 1 to 36,500.
   */
  auditRetentionDays?: number | null;
}>;

/** The opt-ins of `IdentityServiceConfig.accountSecurity`. */
export type AccountSecurityOptions = Readonly<{
  /** Enables `rotateSignInKey`: re-binding the account to a new enrolled key. */
  signInKeyRotation?: boolean;
  /**
   * Enables recovery keys: `enrollRecoveryKey`, `beginRecovery`,
   * `authenticateRecovery` and `completeRecovery`. A completed recovery
   * replaces the enrolled key, as a rotation does. Removing a key, reading the
   * status and the operator's `revokeRecoveryKeys` work either way.
   */
  recoveryKeys?: boolean;
  /**
   * Enables account recovery by email: `startAccountReset` and
   * `completeAccountReset`, turning an account's `email-reset` setting on, and
   * the emailed code that completes a signed-in reset at once. Each account's
   * own setting is off until its owner turns it on with a verified email.
   * Turning the setting off works either way.
   */
  emailReset?: boolean;
  /**
   * Enables the signed-in reset: `startSignedInReset` and
   * `completeSignedInReset`, and turning an account's `signed-in-reset`
   * setting on. Each account's own setting is ON by default (migration 8), so
   * with this opt-in a stolen session can replace the enrolled key after the
   * 72-hour wait unless another session aborts or the owner signs in with the
   * password. Aborting and turning the setting off work either way.
   */
  signedInReset?: boolean;
}>;

/**
 * The audit actions of the account changes `onSecurityEvent` reports, and
 * `session.revoke-others` when it revoked at least one session.
 */
export type SecurityEventAction =
  | "account.key-rotate"
  | "account.email-change"
  | "account.recovery-key.enroll"
  | "account.recovery-key.remove"
  | "account.recovery-key.revoke"
  | "account.recovery-begin"
  | "account.recover"
  | "account.reset-setting"
  | "account.email-reset"
  | "account.signed-in-reset.start"
  | "account.signed-in-reset.abort"
  | "account.signed-in-reset"
  | "session.revoke-others";

/**
 * What `onSecurityEvent` receives. It carries no key, wallet address or IP;
 * only an email change carries an email address, `previousVerifiedEmail`, and
 * only to the host.
 */
export type SecurityEventNotice = Readonly<{
  action: SecurityEventAction;
  accountId: string;
  occurredAt: Date;
  /** The request's client label (`RequestContext.clientLabel`), when valid. */
  clientLabel: string | null;
  /** Rotation, recovery and revoke-others: how many sessions the change revoked. */
  revokedSessions?: number;
  /**
   * Email change only: the address it replaced, when that address was
   * verified, so the host can tell its owner. It is never audited.
   */
  previousVerifiedEmail?: string | null;
  /** `account.reset-setting` only: which setting changed, and its new value. */
  setting?: AccountResetSettingName;
  enabled?: boolean;
  /**
   * `account.signed-in-reset.start` only: when the reset becomes available
   * without an emailed code, for a host that sends a second notice before it.
   */
  availableAt?: Date;
  /**
   * `account.signed-in-reset.abort` only: what aborted it, `session` (an
   * explicit abort), `login` (a sign-in with the password) or `rotation` (a
   * password change, `rotateSignInKey`).
   */
  abortedBy?: "session" | "login" | "rotation";
}>;

export type SecurityEventHook = (event: SecurityEventNotice) => void | Promise<void>;

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
  accountSecurity: Readonly<{
    signInKeyRotation: boolean;
    recoveryKeys: boolean;
    emailReset: boolean;
    signedInReset: boolean;
  }>;
  onSecurityEvent: SecurityEventHook | null;
  auditRetentionDays: number | null;
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

/** A key the caller proves it holds, in the deployment codec's encodings. */
export type EnrolledKeyInput = Readonly<{
  address: string;
  publicKey: string;
}>;

/**
 * `rotateSignInKey`: both signatures are over the account-change message of
 * action `sign-in-key-rotation`, authorizer `key:<current key>`, subject
 * `key:<newKey.publicKey>`.
 */
export type SignInKeyRotationInput = Readonly<{
  /** A `rotation` challenge for the session account's username. */
  challengeId: string;
  newKey: EnrolledKeyInput;
  /** By the current enrolled key: proof of the current password. */
  authorizerSignature: string;
  /** By the new key: proof of possession. */
  subjectSignature: string;
}>;

/** `changeEmail`: action `email-change`, subject `email:<normalizeEmail(email)>`. */
export type EmailChangeInput = Readonly<{
  challengeId: string;
  email: string;
  authorizerSignature: string;
}>;

/** `enrollRecoveryKey`: action `recovery-key-enrollment`, subject `recovery-key:<hex>`. */
export type RecoveryKeyEnrollmentInput = Readonly<{
  challengeId: string;
  /** The recovery key's raw Ed25519 public key, 64 lowercase hex characters. */
  recoveryPublicKey: string;
  authorizerSignature: string;
  /** By the recovery key: proof of possession. */
  subjectSignature: string;
}>;

/** `removeRecoveryKey`: action `recovery-key-removal`, subject `none`. */
export type RecoveryKeyRemovalInput = Readonly<{
  challengeId: string;
  authorizerSignature: string;
}>;

/** `beginRecovery`: action `recovery-begin`, authorizer `recovery-key:<hex>`, subject `none`. */
export type RecoveryBeginInput = Readonly<{
  username: string;
  challengeId: string;
  recoveryPublicKey: string;
  /** By the recovery key. */
  signature: string;
}>;

/**
 * `completeRecovery`: action `recovery-reset`, authorizer
 * `recovery-key:<hex>`, subject `key:<newKey.publicKey>`.
 */
export type RecoveryCompletionInput = Readonly<{
  /** A second `rotation` challenge for the account's username. */
  challengeId: string;
  newKey: EnrolledKeyInput;
  /** By the recovery key. */
  authorizerSignature: string;
  /** By the new key: proof of possession. */
  subjectSignature: string;
}>;

/** One recovery key of an account. Only its public half is ever stored. */
export type IdentityRecoveryKey = Readonly<{
  /** The raw Ed25519 public key, 64 lowercase hex characters. */
  publicKey: string;
  status: "active" | "used" | "removed";
  createdAt: Date;
  usedAt: Date | null;
  removedAt: Date | null;
}>;

/**
 * The account's recovery key for display: the active one, else the most
 * recent one when that one was used (so the client can prompt for a new
 * one), else `null`.
 */
export type RecoveryStatus = Readonly<{
  recoveryKey: IdentityRecoveryKey | null;
}>;

/** Returned once by `beginRecovery`. Only the token's SHA-256 is stored. */
export type IssuedRecovery = Readonly<{
  accountId: string;
  recoveryToken: string;
  expiresAt: Date;
}>;

/** A live recovery token, as `authenticateRecovery` resolves it. */
export type AuthenticatedRecovery = Readonly<{
  accountId: string;
  usernameNormalized: string;
  expiresAt: Date;
}>;

/** One audit event of the caller's account, for display. No IP, key or address. */
export type SecurityEvent = Readonly<{
  id: string;
  action: string;
  createdAt: Date;
  /**
   * The label of the session that acted or was issued, while that session's
   * row still exists (`pruneExpired` deletes it with the row), else `null`.
   */
  clientLabel: string | null;
}>;

/** The two per-account reset settings of `setAccountResetSetting`. */
export type AccountResetSettingName = "email-reset" | "signed-in-reset";

/**
 * `setAccountResetSetting`: action `email-reset-setting` or
 * `signed-in-reset-setting`, authorizer `key:<current key>`, subject
 * `setting:on` or `setting:off`, so the signature binds the value.
 */
export type AccountResetSettingInput = Readonly<{
  challengeId: string;
  setting: AccountResetSettingName;
  enabled: boolean;
  /** By the current enrolled key: proof of the current password. */
  authorizerSignature: string;
}>;

/** An account's two reset settings, as stored. */
export type AccountResetSettings = Readonly<{
  /** Account recovery by email. Off by default; needs a verified email. */
  emailReset: boolean;
  /** The signed-in reset. On by default. */
  signedInReset: boolean;
}>;

/**
 * A code to deliver, for the host only. Never put it in a response: whoever
 * reads it can complete the reset.
 */
export type AccountResetDelivery = Readonly<{
  /** The account's verified address. */
  email: string;
  /**
   * 16 symbols of `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (80 bits), ungrouped. A
   * host may show it in groups of four: the completion ignores case and
   * separators.
   */
  code: string;
}>;

/**
 * What `startAccountReset` returns, the same shape for every username. The
 * caller's answer carries a fresh decoy `resetId` and `expiresAt` only:
 * `delivery` is `null` unless a code was issued (an active account with a
 * verified email and its `email-reset` setting on, within the per-recipient
 * cap), and a host that sends it must not let the response time or content
 * depend on it.
 */
export type IssuedAccountReset = Readonly<{
  /** A fresh decoy UUID for every anonymous request. Completion uses the emailed id. */
  resetId: string;
  expiresAt: Date;
  delivery: (AccountResetDelivery & Readonly<{ resetId: string }>) | null;
}>;

/**
 * `completeAccountReset`: action `email-reset`, authorizer `email:<resetId>`,
 * subject `key:<newKey.publicKey>`. The emailed code is the authorization; only
 * the new key signs.
 */
export type AccountResetCompletionInput = Readonly<{
  username: string;
  resetId: string;
  /** The emailed code (case and separators are ignored). */
  code: string;
  /** A `rotation` challenge for the username. */
  challengeId: string;
  newKey: EnrolledKeyInput;
  /** By the new key: proof of possession. */
  subjectSignature: string;
}>;

/** A pending signed-in reset of the caller's account. */
export type PendingSignedInReset = Readonly<{
  id: string;
  createdAt: Date;
  /** From then on the initiating session can complete it without a code. */
  availableAt: Date;
  expiresAt: Date;
  /** True for the session that started it, the only one that can complete it. */
  initiatedByCaller: boolean;
  /** Whether an emailed code can still complete it before `availableAt`. */
  codeUsable: boolean;
}>;

/** What `startSignedInReset` returns. */
export type IssuedSignedInReset = Readonly<{
  reset: PendingSignedInReset;
  /**
   * With account recovery by email on (the opt-in, the account's setting and
   * a verified email): the code that completes the reset at once. Otherwise
   * `null`, and the reset waits 72 hours.
   */
  delivery: AccountResetDelivery | null;
}>;

/**
 * `completeSignedInReset`: action `signed-in-reset`, authorizer
 * `session-reset:<resetId>`, subject `key:<newKey.publicKey>`. The elapsed
 * wait, or the emailed code, is the authorization; only the new key signs.
 */
export type SignedInResetCompletionInput = Readonly<{
  challengeId: string;
  resetId: string;
  newKey: EnrolledKeyInput;
  /** By the new key: proof of possession. */
  subjectSignature: string;
  /** The emailed code, to complete before `availableAt`; omit to rely on the wait. */
  code?: string;
}>;

/** `accountResetStatus`: the settings and the pending signed-in reset, if any. */
export type AccountResetStatus = Readonly<{
  settings: AccountResetSettings;
  emailVerified: boolean;
  pendingSignedInReset: PendingSignedInReset | null;
}>;

/**
 * `verifyReauthentication`: action `reauthentication`, authorizer
 * `key:<current key>`, subject `host:<label>`.
 */
export type ReauthenticationInput = Readonly<{
  challengeId: string;
  /** The host's constant for what this unlocks: `^[a-z0-9][a-z0-9._:-]{2,79}$`. */
  label: string;
  authorizerSignature: string;
}>;

/** A verified reauthentication, as audited (`account.reauth`). */
export type VerifiedReauthentication = Readonly<{
  accountId: string;
  sessionId: string;
  label: string;
  verifiedAt: Date;
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
