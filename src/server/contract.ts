import type {
  AuthenticatedIdentity,
  ChallengePurpose,
  EmailVerificationRequest,
  IdentityAccount,
  IdentityChallenge,
  IdentityWallet,
  IssuedEmailVerification,
  IssuedSession,
  ListedSession,
  LoginInput,
  PublishedDerivationProfile,
  RegistrationInput,
  RequestContext,
  ResolvedIdentityServiceConfig,
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
   * Deletes expired challenges, verifications, and sessions. A dead session
   * whose row another statement holds locked is skipped, never waited on;
   * the next run deletes it.
   */
  pruneExpired(context?: RequestContext): Promise<{
    challenges: number;
    sessions: number;
    emailVerifications: number;
    rateLimits: number;
  }>;
}
