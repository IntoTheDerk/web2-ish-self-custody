import type {
  AuthenticatedIdentity,
  ChallengePurpose,
  EmailVerificationRequest,
  IdentityAccount,
  IdentityChallenge,
  IdentityWallet,
  IssuedEmailVerification,
  IssuedSession,
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
 * Passwords, plaintext seeds, and recovery codes stay on the client. In vault
 * mode the service stores ciphertext and supports retrieval on another device.
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

  /** Enrolls a new account plus its primary wallet and opens a session. */
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

  revokeAllSessions(accountId: string, context?: RequestContext): Promise<number>;

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

  /** Deletes expired challenges, verifications, and sessions. */
  pruneExpired(context?: RequestContext): Promise<{
    challenges: number;
    sessions: number;
    emailVerifications: number;
    rateLimits: number;
  }>;
}
