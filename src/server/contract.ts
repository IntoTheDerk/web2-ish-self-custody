import type {
  AccountDeletion,
  AccountDeletionOptions,
  AccountResetCompletionInput,
  AccountResetSettingInput,
  AccountResetSettings,
  AccountResetStatus,
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
  IssuedAccountReset,
  IssuedRecovery,
  IssuedSecondFactorTicket,
  IssuedSession,
  IssuedSignedInReset,
  ListedSession,
  LoginInput,
  PublishedDerivationProfile,
  ReauthenticationInput,
  RecoveryBeginInput,
  RecoveryCompletionInput,
  RecoveryKeyEnrollmentInput,
  RecoveryKeyRemovalInput,
  RecoveryStatus,
  RegistrationInput,
  RequestContext,
  ResolvedIdentityServiceConfig,
  SecondFactorCompletionInput,
  SecondFactorPurpose,
  SecurityEvent,
  SignedInResetCompletionInput,
  SignInKeyRotationInput,
  StoredWalletVault,
  VerifiedReauthentication,
} from "./types.js";
import type { WalletVault } from "../vault.js";

/**
 * A session, or, with the `secondFactor` option and an account that needs it,
 * a second-factor ticket in its place (`completeSecondFactor` turns it into
 * the session). Without the option the result always has `session`.
 */
export type SessionOrSecondFactor<T> =
  | SessionResult<T>
  | (T & IssuedSecondFactorTicket & Readonly<{ session?: undefined }>);

/**
 * A result that carries a session, and no ticket: always, on a service
 * without the option. The ticket's fields are declared absent so that either
 * result can be read without a cast and narrowed on `session` or
 * `secondFactor`.
 */
export type SessionResult<T> = T &
  Readonly<{
    session: IssuedSession;
    secondFactor?: undefined;
    ticket?: undefined;
    expiresAt?: undefined;
  }>;

type LoginFields = Readonly<{ account: IdentityAccount }>;
type ResetFields = Readonly<{
  account: IdentityAccount;
  wallets: readonly IdentityWallet[];
  revokedSessionIds: readonly string[];
}>;

/** What `login` resolves to on an `IdentityService<true>`. */
export type LoginResult = SessionOrSecondFactor<LoginFields>;

/**
 * What `completeAccountReset` and `completeRecovery` resolve to on an
 * `IdentityService<true>`.
 */
export type ResetCompletionResult = SessionOrSecondFactor<ResetFields>;

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
export interface IdentityService<SecondFactor extends boolean = false> {
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

  /**
   * Verifies a login challenge signature and opens a session. With the
   * `secondFactor` option, when `required` answers true for the account, it
   * opens none: it answers `{ account, secondFactor: "totp", ticket,
   * expiresAt }` and the session waits for `completeSecondFactor`. A
   * sign-in that needs the factor is refused (`rate-limited`, rule
   * `login-account`) while the account has 25 wrong second-factor codes in
   * its current hour.
   */
  login(
    input: LoginInput,
    context?: RequestContext,
  ): Promise<SecondFactor extends true ? LoginResult : SessionResult<LoginFields>>;

  /**
   * The second sign-in step (`secondFactor` option only; otherwise
   * `invalid-request`). Reserves one of the ticket's five attempts, passes
   * `code` to the host's `verify`, and on `"ok"` issues the session the
   * ticket's step would have issued, in the statement that consumes the
   * ticket, while the account is active and the ticket's key still enrolled.
   * Audits `session.second-factor-ok { purpose, sessionId }` (and, for a
   * login, `account.login`) or `session.second-factor-failed { purpose,
   * reason, attempts, exhausted }`. Errors: `second-factor-invalid` (wrong
   * code, `details.attemptsRemaining`), `second-factor-locked` (the
   * verifier's `"locked"`), `second-factor-ticket-invalid` (unknown, used,
   * expired or exhausted ticket, or the account or its key changed), and
   * `rate-limited` (rule `login-account`): every code counts against the
   * account's 25 an hour before `verify` runs and is given back on `"ok"` or
   * `"locked"`, so a full bucket refuses every ticket of the account. The
   * fifth wrong code kills the ticket.
   */
  completeSecondFactor(
    input: SecondFactorCompletionInput,
    context?: RequestContext,
  ): Promise<{ account: IdentityAccount; session: IssuedSession; purpose: SecondFactorPurpose }>;

  /**
   * Server-only: permanently deletes the account and everything this service
   * stores for it, in one statement: its enrolled keys, sessions, recovery
   * keys and tokens, resets, second-factor tickets, the challenges and email
   * verifications of its username, and its `login-account` rate-limit row.
   * Its audit rows are kept, detached from the account (`account_id` NULL,
   * `deleted_account_id` set), or pruned now when `auditRetentionDays` would
   * prune them, and an `account.deleted` row records the deletion with the
   * account id and counts only. An account with a live session is refused
   * (`account-has-sessions`, `details.liveSessions`) unless
   * `revokeLiveSessions` is true. A missing account resolves `{ deleted:
   * false }`. Not routed. It never touches `<p>_wallet_setups`, whose rows
   * are immutable public salts (see docs/SERVER_API.md).
   */
  deleteAccount(
    accountId: string,
    options?: AccountDeletionOptions,
    context?: RequestContext,
  ): Promise<AccountDeletion>;

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
   * `revokeSession`. A malformed id is `invalid-request`. A session that
   * started a pending signed-in reset revokes nothing (`reset-pending`).
   */
  revokeSessionById(
    token: string,
    sessionId: string,
    context?: RequestContext,
  ): Promise<{ revoked: boolean }>;

  /**
   * Revokes every live session of the caller's account except the caller's,
   * unless the caller started a pending signed-in reset (`reset-pending`).
   */
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
   * caller's session stays. It also aborts the account's pending signed-in
   * reset (audited `account.signed-in-reset.abort { abortedBy: "rotation" }`),
   * since a password change proves the password is not forgotten and a
   * stolen copy of the caller's session may have started it.
   * `authorizerSignature` is by the current key, `subjectSignature` by the
   * new one. Errors: `invalid-signature` for a bad
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
   * With the `secondFactor` option and an account that needs it, the same
   * statement issues a second-factor ticket (bound to the new key) instead of
   * the session.
   */
  completeRecovery(
    recoveryToken: string,
    input: RecoveryCompletionInput,
    context?: RequestContext,
  ): Promise<SecondFactor extends true ? ResetCompletionResult : SessionResult<ResetFields>>;

  /** The caller's account's last 20 audit events: action, time and client label only. */
  listSecurityEvents(token: string, context?: RequestContext): Promise<readonly SecurityEvent[]>;

  /**
   * Server-only operator control: marks the account's active recovery key
   * `removed`, which makes every recovery token of the account unusable, and
   * stamps the ones it can see revoked (see above), whatever the account's
   * status. Returns how many keys it removed (0 or 1).
   */
  revokeRecoveryKeys(accountId: string, context?: RequestContext): Promise<number>;

  /*
   * Account resets (migration 8) and reauthentication. The changes are signed
   * like the account changes above (a `rotation` challenge, the
   * account-change message, strict verification), run in one statement each
   * that requires an `active` account, take the account row FOR SHARE or FOR
   * NO KEY UPDATE (never FOR UPDATE), the enrolled key, the resets and then
   * sessions in id order, and write one audit row with field names only.
   * None is routed by `createIdentityRouter`.
   *
   * Account recovery by email (`accountSecurity.emailReset`) and the
   * signed-in reset (`accountSecurity.signedInReset`) are opt-ins, off by
   * default, and run only in the deterministic wallet modes. Each account
   * also has its own setting: recovery by email is off until its owner turns
   * it on with a verified email; the signed-in reset is on. Aborting a reset,
   * reading the status, turning a setting off and `verifyReauthentication`
   * need no opt-in.
   */

  /**
   * Turns one of the account's reset settings on or off, signed by the
   * enrolled key over `setting:on` or `setting:off`. Account recovery by
   * email needs a verified email to turn on; the signed-in reset can be
   * turned off only while an active recovery key or account recovery by
   * email is set (`reset-setting-refused` otherwise). Turning a setting off
   * closes that kind's live resets. `changed` is false when it already had
   * the value.
   */
  setAccountResetSetting(
    token: string,
    input: AccountResetSettingInput,
    context?: RequestContext,
  ): Promise<{ settings: AccountResetSettings; changed: boolean }>;

  /**
   * The account's reset settings, whether its email is verified, and its
   * pending signed-in reset (`null` when none is live, or when the session
   * that started it is gone), flagged when the caller started it. A host
   * shows the other sessions a banner with an abort from this.
   */
  accountResetStatus(token: string, context?: RequestContext): Promise<AccountResetStatus>;

  /**
   * Starts an account recovery by email. It answers every username the same
   * way: a fresh decoy `resetId` and the same `expiresAt` (15 minutes), with no
   * error that depends on the account. Only for an active account with a
   * verified email and its `email-reset` setting on, and within the
   * per-recipient cap (`account-reset-recipient`, a bucket of its own), does
   * it store a code (16 symbols, 80 bits; its SHA-256, 5 attempts) and
   * return `delivery` with the usable reset id for the host to email.
   * An active challenge is coalesced without spending recipient quota.
   * Never put `delivery` in a response; pad every response to one fixed time.
   * `account-reset-start-ip` counts every request when the host supplies an IP hash.
   */
  startAccountReset(
    input: Readonly<{ username: string }>,
    context?: RequestContext,
  ): Promise<IssuedAccountReset>;

  /**
   * Host-only cleanup when delivery of a newly issued email reset fails.
   * Pass the `resetId` and `code` from `delivery`; never expose this method on
   * an anonymous route. Only that unexpired, unfinished challenge is closed.
   * Returns `cancelled: false` for a missing, mismatched, or already closed id.
   * Recipient quota remains spent because a delivery attempt occurred.
   */
  cancelUndeliveredAccountReset(
    input: Readonly<{ resetId: string; code: string }>,
    context?: RequestContext,
  ): Promise<{ cancelled: boolean }>;

  /**
   * Completes an account recovery by email: the emailed code is the
   * authorization, and only `newKey` signs (action `email-reset`, authorizer
   * `email:<resetId>`). In one statement it replaces the enrolled key, marks
   * the reset completed, closes the account's other live resets, revokes
   * every session and issues a new one. Every failure an unauthenticated
   * caller can cause is one `invalid-signature`; a code that verified but
   * names the current key is `key-unchanged`. With the `secondFactor` option
   * and an account that needs it, the same statement issues a second-factor
   * ticket (bound to the new key) instead of the session.
   */
  completeAccountReset(
    input: AccountResetCompletionInput,
    context?: RequestContext,
  ): Promise<SecondFactor extends true ? ResetCompletionResult : SessionResult<ResetFields>>;

  /**
   * Starts a signed-in reset from the caller's session: it becomes
   * available to that session after 72 hours and can then be completed for
   * 7 days. With account recovery by email on, it also issues an emailed
   * code (`delivery`) that completes it at once. At most one is pending per
   * account (`reset-pending`). While it is pending, its session cannot
   * revoke the account's other sessions (`reset-pending`), any session can
   * abort it, and a sign-in with the password or a password change aborts
   * it. Only the initiating session completes it, and a session's expiry is
   * fixed, so without an emailed code a start whose session expires before
   * `availableAt` is refused: `reset-unavailable` with `details.reason:
   * "session-expires-first"` and `details.sessionExpiresAt`.
   */
  startSignedInReset(token: string, context?: RequestContext): Promise<IssuedSignedInReset>;

  /** Aborts the account's pending signed-in reset, from any of its sessions. */
  abortSignedInReset(token: string, context?: RequestContext): Promise<{ aborted: boolean }>;

  /**
   * Completes the caller's own signed-in reset, signed by `newKey` only
   * (action `signed-in-reset`, authorizer `session-reset:<resetId>`): after
   * the wait, or before it with the emailed `code`. In one statement it
   * replaces the enrolled key and revokes every other session; the caller's
   * stays. `reset-unavailable` when there is no such pending reset of this
   * session or it is not available yet; `email-verification-failed` for a
   * wrong, expired or exhausted code; `stale-key` when the key changed after
   * the call began.
   */
  completeSignedInReset(
    token: string,
    input: SignedInResetCompletionInput,
    context?: RequestContext,
  ): Promise<{ wallets: readonly IdentityWallet[]; revokedSessionIds: readonly string[] }>;

  /**
   * Proves the current password to the host: consumes a `rotation`
   * challenge, verifies the enrolled key's signature strictly over action
   * `reauthentication` and subject `host:<label>`, requires an active
   * account, and writes audit `account.reauth { label, sessionId }`. It
   * changes nothing else. `label` is the host's constant for what it
   * unlocks, `^[a-z0-9][a-z0-9._:-]{2,79}$`, never user data. Counted under
   * `account-change`.
   */
  verifyReauthentication(
    token: string,
    input: ReauthenticationInput,
    context?: RequestContext,
  ): Promise<VerifiedReauthentication>;

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
   * and account resets and second-factor tickets a day after they expire and, with
   * `auditRetentionDays`, this service's older `account.*` and `session.*` audit rows,
   * those `deleteAccount` kept included. A dead session or recovery row that another
   * statement holds locked is skipped, never waited on; the next run deletes
   * it.
   */
  pruneExpired(context?: RequestContext): Promise<{
    challenges: number;
    sessions: number;
    emailVerifications: number;
    rateLimits: number;
    recoveryTokens: number;
    accountResets: number;
    auditEvents: number;
    secondFactorTickets: number;
  }>;
}
