import type {
  AuthenticatedIdentity,
  AuthenticatedRecovery,
  ChallengePurpose,
  EmailChangeInput,
  EmailVerificationRequest,
  IdentityAccount,
  IdentityChallenge,
  IdentityRecoveryKey,
  IdentityWallet,
  IssuedEmailVerification,
  IssuedRecovery,
  IssuedSession,
  ListedSession,
  LoginInput,
  PublishedDerivationProfile,
  RecoveryBeginInput,
  RecoveryCompletionInput,
  RecoveryKeyEnrollmentInput,
  RecoveryKeyRemovalInput,
  RecoveryStatus,
  RegistrationInput,
  RequestContext,
  ResolvedIdentityServiceConfig,
  SecurityEvent,
  SignInKeyRotationInput,
  StoredWalletVault,
} from "./types.js";
import type { WalletVault } from "../vault.js";

/**
 * The complete server-side identity surface.
 *
 * The service never receives a password, a plaintext seed, a private key, an
 * application secret, or a recovery code. What it holds depends on the wallet
 * mode:
 *
 * - `service-deterministic` and `per-account-deterministic`: only public key
 *   material, the enrolled public keys and the public salt (one per service
 *   profile, or one per account). No ciphertext reaches it, and nothing it
 *   holds reconstructs an enrolled key without the password; its only
 *   cryptographic role is verifying signatures against public keys the client
 *   enrolled. The enrolled public key still lets anyone who holds it test
 *   password guesses offline.
 * - `random-vault`: also each account's encrypted wallet vault, which it stores
 *   at enrollment and returns to another device only once the host has
 *   authorized the read. It cannot open a vault, but a vault is a password
 *   oracle too, at the profile's scrypt cost.
 *
 * An enrolled key is a wallet only when the configured profile is a chain
 * wallet profile. Under the sign-in profile it is a sign-in key, and the user's
 * wallet never reaches the service; the sign-in profile is refused in
 * `random-vault` mode. Methods and types keep their wallet names
 * (`listWallets`, `IdentityWallet`) either way.
 */
export interface IdentityService {
  readonly config: ResolvedIdentityServiceConfig;

  /** Applies pending migrations. Safe to call concurrently and repeatedly. */
  migrate(): Promise<readonly number[]>;

  /** Public derivation parameters, including this service's 32-byte salt. */
  derivationProfile(): Promise<PublishedDerivationProfile>;

  /** Server-only: authorize platform access to accountId before calling. */
  getWalletVault(accountId: string, context?: RequestContext): Promise<StoredWalletVault>;

  /** Authenticated compare-and-swap: prevents overwriting a newer password change. */
  updateWalletVault(token: string, vault: WalletVault, expectedRevision: number, context?: RequestContext): Promise<StoredWalletVault>;

  /**
   * Issues a single-use challenge. Returns a challenge for unknown usernames
   * too, so callers cannot probe for account existence.
   */
  createChallenge(
    username: string,
    purpose: ChallengePurpose,
    context?: RequestContext,
  ): Promise<IdentityChallenge>;

  /** Enrolls a new account plus its primary enrolled key and opens a session. */
  register(
    input: RegistrationInput,
    context?: RequestContext,
  ): Promise<{ account: IdentityAccount; wallet: IdentityWallet; session: IssuedSession }>;

  /** Verifies a login challenge signature and opens a session. */
  login(
    input: LoginInput,
    context?: RequestContext,
  ): Promise<{ account: IdentityAccount; session: IssuedSession }>;

  /** Resolves a bearer token, sliding `last_seen_at`. Throws when invalid. */
  authenticate(token: string, context?: RequestContext): Promise<AuthenticatedIdentity>;

  revokeSession(token: string, context?: RequestContext): Promise<void>;

  /** Server-only: revokes every live session of the account, the caller's included. */
  revokeAllSessions(accountId: string, context?: RequestContext): Promise<number>;

  /*
   * Session management for the caller's own account. Each method takes the
   * caller's token and checks it in the same single statement as its work: a
   * missing, unknown or revoked token is `session-not-found` and an expired one
   * `session-expired`, as with `authenticate`. Only `listSessions` also slides
   * the caller's `last_seen_at`. The revocations never lock the caller's own
   * row: `revokeSessionById` locks at most its target, and
   * `revokeOtherSessions` locks the account's other live sessions in id order
   * (as `revokeAllSessions` does), so concurrent revocations, two sessions
   * revoking each other included, cannot deadlock one another. None of them is
   * reachable over HTTP unless the router's `accountSecurityRoutes` option is
   * on, and `liveSessionIds` never is.
   */

  /**
   * The account's live sessions for display: at most 50, most recently active
   * first, the caller's always included and flagged `current`. Never use it to
   * decide which sessions exist; that is `liveSessionIds`.
   */
  listSessions(token: string, context?: RequestContext): Promise<readonly ListedSession[]>;

  /** Every live session id of the caller's account, the caller's included, uncapped. */
  liveSessionIds(token: string, context?: RequestContext): Promise<readonly string[]>;

  /**
   * Revokes one other live session of the caller's account. A session of
   * another account, an unknown id, and a session already revoked or expired
   * all answer `{ revoked: false }`, so the answer reveals nothing. The
   * caller's own session id is `invalid-request`: signing out is
   * `revokeSession`. A malformed id is `invalid-request`.
   */
  revokeSessionById(
    token: string,
    sessionId: string,
    context?: RequestContext,
  ): Promise<{ revoked: boolean }>;

  /** Revokes every live session of the caller's account except the caller's. */
  revokeOtherSessions(
    token: string,
    context?: RequestContext,
  ): Promise<{ revokedSessionIds: readonly string[] }>;

  /*
   * Account changes and recovery keys. Each change is authorized by
   * signatures over the account-change message (`buildAccountChangeMessage`
   * in the core entry) for a `rotation` challenge of the account's username,
   * consumed by exactly one operation; every signature is verified strictly
   * (RFC 8032: canonical A and R, A not of small order, S < L). Each change
   * is one statement that requires the account to be `active`, takes the
   * account row FOR SHARE (never FOR UPDATE) and locks sessions in id order,
   * as the revocations above do, and writes one audit row with field names
   * only. `onSecurityEvent` is awaited, bounded, after the commit.
   *
   * Rotation, recovery-key enrollment and recovery run only in the
   * deterministic wallet modes and only when their `accountSecurity` opt-in
   * is on; otherwise `invalid-request`. A suspended account is refused by
   * every one of them except `revokeRecoveryKeys`. None is routed by
   * `createIdentityRouter`: a host calls them from its own routes, and
   * `createSessionResponder` answers `completeRecovery` the way the router
   * answers a login.
   *
   * A recovery token is usable only while it is unspent, unrevoked and
   * unexpired AND its recovery key is `active`; every method that reads a
   * token joins its key. Retiring a key (enrolling another, removing it, or
   * `revokeRecoveryKeys`) also stamps the key's tokens revoked, but a token
   * that a begin overlapping the retirement issues can stay unstamped (the
   * retiring statement's snapshot predates it) until the next begin or
   * `pruneExpired`. It is refused all the same, because its key is not
   * `active`. Code that reads `<p>_account_recoveries` directly must apply
   * the same key join.
   */

  /**
   * Re-binds the account to a new enrolled key (a password change), in place:
   * the one enrolled-key row gets the new address, public key and
   * fingerprint, and every other live session of the account is revoked; the
   * caller's session stays. `authorizerSignature` is by the current key,
   * `subjectSignature` by the new one. Errors: `invalid-signature` for a bad
   * signature or a challenge of another username; `key-unchanged` (409) when
   * the new key is the current one; `stale-key` (409) when another change
   * moved the key after this one was signed; `wallet-conflict` (409) unless
   * the account has exactly one enrolled key; `invalid-public-key` for a
   * non-canonical or small-order new key, checked before any lookup.
   */
  rotateSignInKey(
    token: string,
    input: SignInKeyRotationInput,
    context?: RequestContext,
  ): Promise<{ wallets: readonly IdentityWallet[]; revokedSessionIds: readonly string[] }>;

  /**
   * Sets the account's email with a signature by the enrolled key, clearing
   * its verification as `updateAccount` does when the address changes. The
   * result names the address it replaced when that one was verified, for the
   * host to notify; it is never audited.
   */
  changeEmail(
    token: string,
    input: EmailChangeInput,
    context?: RequestContext,
  ): Promise<{ account: IdentityAccount; previousVerifiedEmail: string | null }>;

  /**
   * Makes `recoveryPublicKey` the account's one active recovery key, marking
   * the previous active key `removed`, which makes its recovery tokens
   * unusable, and stamping the ones it can see revoked (see above).
   * Enrolling the key that is already active changes nothing (`changed:
   * false`); a key this service has seen before in any other state is
   * `invalid-public-key`.
   */
  enrollRecoveryKey(
    token: string,
    input: RecoveryKeyEnrollmentInput,
    context?: RequestContext,
  ): Promise<{ recoveryKey: IdentityRecoveryKey; changed: boolean }>;

  /**
   * Marks the active recovery key `removed`, which makes its recovery tokens
   * unusable, and stamps the ones it can see revoked (see above).
   */
  removeRecoveryKey(
    token: string,
    input: RecoveryKeyRemovalInput,
    context?: RequestContext,
  ): Promise<{ removed: boolean }>;

  /** The active recovery key, else the latest one when it was used, else `null`. */
  recoveryStatus(token: string, context?: RequestContext): Promise<RecoveryStatus>;

  /**
   * Proves a recovery key for a username and spends nothing: it issues a
   * recovery token (15 minutes, one completion, at most one live per account,
   * so a new begin revokes the earlier token). Every failure an
   * unauthenticated caller can cause is one `invalid-signature`.
   */
  beginRecovery(input: RecoveryBeginInput, context?: RequestContext): Promise<IssuedRecovery>;

  /** Resolves a live recovery token (unspent, unexpired, its key active), or `invalid-signature`. */
  authenticateRecovery(
    recoveryToken: string,
    context?: RequestContext,
  ): Promise<AuthenticatedRecovery>;

  /**
   * Completes a recovery in one statement: it replaces the enrolled key with
   * `newKey`, marks the recovery key `used` (single use) and the token
   * completed, revokes every session of the account, and issues a new one.
   * `authorizerSignature` is by the recovery key, `subjectSignature` by the
   * new key. Counted under the `account-change` rate limit of the account.
   */
  completeRecovery(
    recoveryToken: string,
    input: RecoveryCompletionInput,
    context?: RequestContext,
  ): Promise<{
    account: IdentityAccount;
    wallets: readonly IdentityWallet[];
    session: IssuedSession;
    revokedSessionIds: readonly string[];
  }>;

  /** The caller's account's last 20 audit events: action, time and client label only. */
  listSecurityEvents(token: string, context?: RequestContext): Promise<readonly SecurityEvent[]>;

  /**
   * Server-only operator control: marks the account's active recovery key
   * `removed`, which makes every recovery token of the account unusable, and
   * stamps the ones it can see revoked (see above), whatever the account's
   * status. Returns how many keys it removed (0 or 1).
   */
  revokeRecoveryKeys(accountId: string, context?: RequestContext): Promise<number>;

  getAccount(accountId: string): Promise<IdentityAccount>;

  updateAccount(
    accountId: string,
    changes: Readonly<{ displayName?: string | null; email?: string }>,
    context?: RequestContext,
  ): Promise<IdentityAccount>;

  listWallets(accountId: string): Promise<readonly IdentityWallet[]>;

  /**
   * Mints a verification code. Delivery belongs to the host application; a
   * custody SDK has no business owning an email transport.
   */
  startEmailVerification(
    input: EmailVerificationRequest,
    context?: RequestContext,
  ): Promise<IssuedEmailVerification>;

  confirmEmailVerification(
    verificationId: string,
    code: string,
    context?: RequestContext,
  ): Promise<{ email: string; usernameNormalized: string; verifiedAt: Date }>;

  /**
   * Deletes expired challenges, verifications, and sessions, recovery tokens
   * a day after they expire and, with `auditRetentionDays`, this service's
   * older `account.*` and `session.*` audit rows. A dead session or recovery row that another
   * statement holds locked is skipped, never waited on; the next run deletes
   * it.
   */
  pruneExpired(context?: RequestContext): Promise<{
    challenges: number;
    sessions: number;
    emailVerifications: number;
    rateLimits: number;
    recoveryTokens: number;
    auditEvents: number;
  }>;
}
