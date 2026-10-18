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
