/**
 * Account changes and recovery keys (package-internal; the methods are
 * exposed through `IdentityService`).
 *
 * Every change is authorized by a signature over the account-change message
 * (`buildAccountChangeMessage`, docs/PROTOCOL.md#account-change-message),
 * verified strictly, and lands in ONE statement that re-checks, under row
 * locks, everything the signature was checked against: the session or the
 * recovery token, the account's `active` status, and the enrolled key.
 *
 * Lock order. Every statement here takes its row locks in this one order, and
 * never `FOR UPDATE` on the account row:
 *
 *   account (FOR SHARE, or FOR NO KEY UPDATE for the email change)
 *   → enrolled key (`<p>_account_wallets`)
 *   → recovery key → recovery token
 *   → sessions, in id order (FOR NO KEY UPDATE), never the caller's own row
 *   → inserts (a new session, the audit row)
 *
 * `revokeOtherSessions` and `revokeAllSessions` lock sessions in id order and
 * then insert an audit row, whose foreign key takes FOR KEY SHARE on the
 * account row; FOR KEY SHARE conflicts with none of the account locks above,
 * so those revocations never wait on an account change, and the account
 * changes take session locks in the same id order. `authenticate` locks one
 * session row and nothing after it, and login inserts only. No cycle exists.
 */
import { hexToBytes } from "@noble/hashes/utils.js";
import {
  buildAccountChangeMessage,
  type AccountChangeAction,
} from "../accountChange.js";
import { fingerprint } from "../encoding.js";
import {
  assertStrictEd25519PublicKey,
  verifyAccountChangeSignature,
} from "./accountChangeSignature.js";
import { canonicalWalletIdentity, type CanonicalWalletIdentity } from "./challenge.js";
import { IdentityError } from "./errors.js";
import {
  mapAccount,
  mapSession,
  mapWallet,
  normalizeEmail,
  requestNow,
  sanitizeContextHash,
  sqlStateOf,
  type ConsumedChallenge,
} from "./records.js";
import {
  instantColumn,
  integerColumn,
  optionalInstantColumn,
  optionalRow,
  optionalTextColumn,
  textColumn,
  type SqlDriver,
  type SqlRow,
} from "./sql.js";
import { generateSessionToken, hashSessionToken } from "./tokens.js";
import {
  acceptedClientLabel,
  type AuthenticatedRecovery,
  type ChallengePurpose,
  type EmailChangeInput,
  type EnrolledKeyInput,
  type IdentityAccount,
  type IdentityRecoveryKey,
  type IdentityWallet,
  type IssuedRecovery,
  type IssuedSession,
  type RecoveryBeginInput,
  type RecoveryCompletionInput,
  type RecoveryKeyEnrollmentInput,
  type RecoveryKeyRemovalInput,
  type RecoveryStatus,
  type RequestContext,
  type ResolvedIdentityServiceConfig,
  type SecurityEvent,
  type SecurityEventAction,
  type SecurityEventHook,
  type SecurityEventNotice,
  type SignInKeyRotationInput,
} from "./types.js";

/** A recovery token is good for 15 minutes and one completion. */
export const RECOVERY_TOKEN_TTL_SECONDS = 900;
/** `onSecurityEvent` is awaited for at most this long after the commit. */
export const SECURITY_EVENT_HOOK_TIMEOUT_MS = 3_000;
/** The most rows `listSecurityEvents` returns. */
const MAX_SECURITY_EVENTS = 20;
/** Attempts of a statement that a concurrent twin can refuse with 23505. */
const UNIQUE_RACE_ATTEMPTS = 3;

const recoveryKeyHexPattern = /^[0-9a-f]{64}$/u;

export type RateLimitName = "accountChange" | "recoveryBegin" | "recoveryBeginIp";

export type AccountChangeDependencies = Readonly<{
  sql: SqlDriver;
  config: ResolvedIdentityServiceConfig;
  /** The validated table prefix. */
  p: string;
  normalizeUsername: (username: string) => string;
  rateLimit: (
    rule: RateLimitName,
    subject: readonly string[],
    context: RequestContext | undefined,
  ) => Promise<void>;
  rateLimitIpHash: (context: RequestContext | undefined) => string;
  consumeChallenge: (
    challengeId: string,
    purpose: ChallengePurpose,
    context: RequestContext | undefined,
  ) => Promise<ConsumedChallenge>;
  sessionFailure: (tokenHash: string, nowParam: string | null) => Promise<IdentityError>;
  sessionClientColumns: (
    context: RequestContext | undefined,
  ) => Readonly<{ ipHash: string | null; userAgentHash: string | null; clientLabel: string | null }>;
}>;

export type AccountChangeOperations = Readonly<{
  rotateSignInKey(
    token: string,
    input: SignInKeyRotationInput,
    context?: RequestContext,
  ): Promise<{ wallets: readonly IdentityWallet[]; revokedSessionIds: readonly string[] }>;
  changeEmail(
    token: string,
    input: EmailChangeInput,
    context?: RequestContext,
  ): Promise<{ account: IdentityAccount; previousVerifiedEmail: string | null }>;
  enrollRecoveryKey(
    token: string,
    input: RecoveryKeyEnrollmentInput,
    context?: RequestContext,
  ): Promise<{ recoveryKey: IdentityRecoveryKey; changed: boolean }>;
  removeRecoveryKey(
    token: string,
    input: RecoveryKeyRemovalInput,
    context?: RequestContext,
  ): Promise<{ removed: boolean }>;
  recoveryStatus(token: string, context?: RequestContext): Promise<RecoveryStatus>;
  beginRecovery(input: RecoveryBeginInput, context?: RequestContext): Promise<IssuedRecovery>;
  authenticateRecovery(
    recoveryToken: string,
    context?: RequestContext,
  ): Promise<AuthenticatedRecovery>;
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
  listSecurityEvents(token: string, context?: RequestContext): Promise<readonly SecurityEvent[]>;
  revokeRecoveryKeys(accountId: string, context?: RequestContext): Promise<number>;
  /** Reports an event to the host hook after its commit (also used by `revokeOtherSessions`). */
  notify(
    action: SecurityEventAction,
    accountId: string,
    occurredAt: Date,
    context: RequestContext | undefined,
    extra?: Readonly<{ revokedSessions?: number; previousVerifiedEmail?: string | null }>,
  ): Promise<void>;
}>;

/**
 * Awaits the host hook for at most `timeoutMs` and swallows whatever it
 * throws or rejects with: the change it reports has already committed.
 */
export async function notifySecurityEvent(
  hook: SecurityEventHook | null,
  event: SecurityEventNotice,
  timeoutMs: number = SECURITY_EVENT_HOOK_TIMEOUT_MS,
): Promise<void> {
  if (hook === null) {
    return;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      Promise.resolve().then(() => hook(event)),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeoutMs);
      }),
    ]);
  } catch {
    // A failing hook must not turn a committed change into an error.
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

const WALLET_COLUMNS = [
  "id", "account_id", "service_profile_id", "profile_id", "codec_id", "curve",
  "application_id", "network_id", "address", "address_normalized", "public_key",
  "fingerprint", "is_primary", "created_at",
] as const;
const ACCOUNT_COLUMNS = [
  "id", "service_profile_id", "username_normalized", "display_name", "email",
  "email_verified_at", "status", "created_at", "updated_at",
] as const;
const SESSION_COLUMNS = ["id", "account_id", "issued_at", "expires_at", "last_seen_at"] as const;
const RECOVERY_KEY_COLUMNS = ["public_key", "status", "created_at", "used_at", "removed_at"] as const;

function columns(alias: string, names: readonly string[], prefix: string): string {
  return names.map((name) => `${alias}.${name} AS ${prefix}${name}`).join(", ");
}

function bare(alias: string, names: readonly string[]): string {
  return names.map((name) => `${alias}.${name}`).join(", ");
}

function mapRecoveryKey(row: SqlRow, prefix: string): IdentityRecoveryKey {
  const status = textColumn(row, `${prefix}status`);
  if (status !== "active" && status !== "used" && status !== "removed") {
    throw new IdentityError("Unknown recovery key status.", "invalid-service-profile");
  }
  return Object.freeze({
    publicKey: textColumn(row, `${prefix}public_key`),
    status,
    createdAt: instantColumn(row, `${prefix}created_at`),
    usedAt: optionalInstantColumn(row, `${prefix}used_at`),
    removedAt: optionalInstantColumn(row, `${prefix}removed_at`),
  });
}

/** Statements that a concurrent twin can refuse with a unique violation are re-run on a fresh snapshot. */
async function retryUniqueViolation<T>(run: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await run();
    } catch (error) {
      if (attempt >= UNIQUE_RACE_ATTEMPTS || sqlStateOf(error) !== "23505") {
        throw error;
      }
    }
  }
}

type SessionAccountContext = Readonly<{
  sessionId: string;
  accountId: string;
  usernameNormalized: string;
  active: boolean;
  primary: CanonicalWalletIdentity | null;
  walletCount: number;
}>;

type RecoveryContext = Readonly<{
  accountId: string;
  usernameNormalized: string;
  recoveryKeyId: string;
  recoveryPublicKey: string;
  expiresAt: Date;
  primary: CanonicalWalletIdentity | null;
  walletCount: number;
}>;

export function accountChangeOperations(deps: AccountChangeDependencies): AccountChangeOperations {
  const { sql, config, p } = deps;
  const serviceProfileId = config.serviceProfileId;
  const codec = config.profile.codec;

  // One shape for every recovery failure an unauthenticated caller can reach:
  // an unknown username, no recovery key, a wrong key, a suspended account, a
  // bad signature, and a token that is unknown, spent, revoked or expired.
  // `invalid-signature` is enumeration-sensitive, so a router collapses it.
  const recoveryRefused = (): IdentityError =>
    new IdentityError(
      "The username or recovery key is not correct, or the key was already used.",
      "invalid-signature",
    );
  const accountNotActive = (): IdentityError =>
    new IdentityError("Account is not active.", "invalid-signature");
  const badSignature = (): IdentityError =>
    new IdentityError(
      "The account-change signature did not verify for this account.",
      "invalid-signature",
    );

  const requireDeterministicMode = (): void => {
    if (config.walletMode === "random-vault") {
      throw new IdentityError(
        "Sign-in-key rotation, recovery-key enrollment and recovery need a deterministic wallet mode; random-vault mode changes a password by re-wrapping the vault and has its own recovery code.",
        "invalid-request",
      );
    }
  };
  const requireRotationEnabled = (): void => {
    if (!config.accountSecurity.signInKeyRotation) {
      throw new IdentityError(
        "Sign-in-key rotation is not enabled on this service (accountSecurity.signInKeyRotation).",
        "invalid-request",
      );
    }
    requireDeterministicMode();
  };
  const requireRecoveryKeysEnabled = (): void => {
    if (!config.accountSecurity.recoveryKeys) {
      throw new IdentityError(
        "Recovery keys are not enabled on this service (accountSecurity.recoveryKeys).",
        "invalid-request",
      );
    }
    requireDeterministicMode();
  };

  /** Every method's input is an object; anything else is the caller's error. */
  const requireInput = (input: unknown): void => {
    if (typeof input !== "object" || input === null) {
      throw new IdentityError("The input must be an object.", "invalid-request");
    }
  };

  const sessionToken = (token: unknown): string => {
    if (typeof token !== "string" || token.trim().length === 0) {
      throw new IdentityError("Session token is missing.", "session-not-found");
    }
    return token;
  };

  /** A submitted key: the codec's canonical form, then the strict key check. */
  const canonicalNewKey = (value: EnrolledKeyInput | undefined): CanonicalWalletIdentity => {
    if (
      typeof value !== "object" ||
      value === null ||
      typeof value.address !== "string" ||
      typeof value.publicKey !== "string"
    ) {
      throw new IdentityError("newKey must be { address, publicKey }.", "invalid-request");
    }
    const identity = canonicalWalletIdentity(codec, value);
    assertStrictEd25519PublicKey(identity.publicKeyBytes, "newKey.publicKey");
    return identity;
  };

  const canonicalRecoveryKey = (value: unknown): Readonly<{ hex: string; bytes: Uint8Array }> => {
    if (typeof value !== "string" || !recoveryKeyHexPattern.test(value)) {
      throw new IdentityError(
        "recoveryPublicKey must be a raw Ed25519 public key as 64 lowercase hex characters.",
        "invalid-public-key",
      );
    }
    const bytes = hexToBytes(value);
    assertStrictEd25519PublicKey(bytes, "recoveryPublicKey");
    return Object.freeze({ hex: value, bytes });
  };

  /** A stored enrolled key that no longer canonicalizes authorizes nothing. */
  const storedIdentity = (
    publicKey: string | null,
    address: string | null,
  ): CanonicalWalletIdentity | null => {
    if (publicKey === null || address === null) {
      return null;
    }
    try {
      return canonicalWalletIdentity(codec, { publicKey, address });
    } catch {
      return null;
    }
  };

  const message = (
    challenge: ConsumedChallenge,
    action: AccountChangeAction,
    authorizer: string,
    subject: string,
  ): string => {
    try {
      return buildAccountChangeMessage({
        serviceProfileId,
        applicationId: config.applicationId,
        networkId: config.networkId,
        action,
        usernameNormalized: challenge.usernameNormalized,
        nonceHex: challenge.nonceHex,
        expiresAt: challenge.expiresAt,
        authorizer,
        subject,
      });
    } catch {
      throw new IdentityError(
        "The account-change message could not be built from this service's configuration.",
        "invalid-service-profile",
      );
    }
  };

  const keyPrincipal = (identity: CanonicalWalletIdentity): string => `key:${identity.publicKey}`;
  const recoveryPrincipal = (hex: string): string => `recovery-key:${hex}`;

  const notify: AccountChangeOperations["notify"] = async (
    action,
    accountId,
    occurredAt,
    context,
    extra = {},
  ) => {
    await notifySecurityEvent(
      config.onSecurityEvent,
      Object.freeze({
        action,
        accountId,
        occurredAt,
        clientLabel: acceptedClientLabel(context?.clientLabel) ?? null,
        ...extra,
      }),
    );
  };

  /**
   * The caller's session, account and enrolled key, read without locks: the
   * read that builds the message to verify. The statement that acts on it
   * re-checks each of these under its locks.
   */
  const readSessionContext = async (
    token: string,
    context: RequestContext | undefined,
  ): Promise<SessionAccountContext> => {
    const tokenHash = hashSessionToken(sessionToken(token));
    const nowParam = requestNow(context);
    const rows = await sql.query(
      `SELECT s.id AS session_id, a.id AS account_id, a.username_normalized, a.status,
              w.public_key AS primary_public_key, w.address AS primary_address,
              (SELECT count(*) FROM ${p}_account_wallets c WHERE c.account_id = a.id)::int
                AS wallet_count
         FROM ${p}_sessions s
         JOIN ${p}_accounts a ON a.id = s.account_id AND a.service_profile_id = $2::text
         LEFT JOIN ${p}_account_wallets w ON w.account_id = a.id AND w.is_primary
        WHERE s.token_hash = $1::text
          AND s.revoked_at IS NULL
          AND s.expires_at > COALESCE($3::timestamptz, now())`,
      [tokenHash, serviceProfileId, nowParam],
    );
    const row = optionalRow(rows);
    if (row === null) {
      throw await deps.sessionFailure(tokenHash, nowParam);
    }
    return Object.freeze({
      sessionId: textColumn(row, "session_id"),
      accountId: textColumn(row, "account_id"),
      usernameNormalized: textColumn(row, "username_normalized"),
      active: textColumn(row, "status") === "active",
      primary: storedIdentity(
        optionalTextColumn(row, "primary_public_key"),
        optionalTextColumn(row, "primary_address"),
      ),
      walletCount: integerColumn(row, "wallet_count"),
    });
  };

  /**
   * The common front half of a signed change by a signed-in caller: the
   * session, the status rule, the rate limit, the challenge (its own
   * statement, as login's is) and its username.
   */
  const prepareSignedChange = async (
    token: string,
    challengeId: unknown,
    context: RequestContext | undefined,
  ): Promise<Readonly<{ session: SessionAccountContext; challenge: ConsumedChallenge; primary: CanonicalWalletIdentity }>> => {
    const session = await readSessionContext(token, context);
    if (!session.active) {
      throw accountNotActive();
    }
    await deps.rateLimit(
      "accountChange",
      [deps.rateLimitIpHash(context), session.accountId],
      context,
    );
    if (typeof challengeId !== "string") {
      throw new IdentityError("challengeId must be a string.", "invalid-request");
    }
    const challenge = await deps.consumeChallenge(challengeId, "rotation", context);
    if (challenge.usernameNormalized !== session.usernameNormalized) {
      throw badSignature();
    }
    if (session.primary === null) {
      throw new IdentityError(
        "The account has no enrolled key that can authorize a change.",
        "wallet-conflict",
      );
    }
    return Object.freeze({ session, challenge, primary: session.primary });
  };

  /** Why a guarded statement acted on nothing, read after the fact. */
  const enrolledKeyState = async (
    accountId: string,
  ): Promise<Readonly<{ walletCount: number; primaryPublicKey: string | null }>> => {
    const row = optionalRow(
      await sql.query(
        `SELECT count(*)::int AS wallet_count,
                max(public_key) FILTER (WHERE is_primary) AS primary_public_key
           FROM ${p}_account_wallets
          WHERE account_id = $1::uuid`,
        [accountId],
      ),
    );
    return Object.freeze({
      walletCount: row === null ? 0 : integerColumn(row, "wallet_count"),
      primaryPublicKey: row === null ? null : optionalTextColumn(row, "primary_public_key"),
    });
  };

  const walletConflict = (): IdentityError =>
    new IdentityError(
      "The account must have exactly one enrolled key to replace it.",
      "wallet-conflict",
    );
  const staleKey = (): IdentityError =>
    new IdentityError(
      "The enrolled key changed after the change was signed; sign again with the current key.",
      "stale-key",
    );

  /** Diagnostics shared by the token-guarded statements below. */
  const failGuardedStatement = async (
    row: SqlRow | null,
    token: string,
    context: RequestContext | undefined,
  ): Promise<never> => {
    if (row === null || integerColumn(row, "caller_found") === 0) {
      throw await deps.sessionFailure(hashSessionToken(token), requestNow(context));
    }
    if (integerColumn(row, "account_active") === 0) {
      throw accountNotActive();
    }
    throw staleKey();
  };

  const operations: AccountChangeOperations = {
    notify,

    async rotateSignInKey(token, input, context) {
      requireRotationEnabled();
      requireInput(input);
      const newKey = canonicalNewKey(input.newKey);
      const { session, challenge, primary } = await prepareSignedChange(
        token,
        input.challengeId,
        context,
      );
      const signed = message(
        challenge,
        "sign-in-key-rotation",
        keyPrincipal(primary),
        keyPrincipal(newKey),
      );
      if (
        !verifyAccountChangeSignature(input.authorizerSignature, signed, primary.publicKeyBytes) ||
        !verifyAccountChangeSignature(input.subjectSignature, signed, newKey.publicKeyBytes)
      ) {
        throw badSignature();
      }
      if (newKey.publicKey === primary.publicKey) {
        throw new IdentityError(
          "The new key is the key already enrolled; nothing would change.",
          "key-unchanged",
        );
      }
      if (session.walletCount !== 1) {
        throw walletConflict();
      }

      let rows: SqlRow[];
      try {
        rows = await sql.query(
          `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
                caller AS (
                  SELECT s.id, s.account_id
                    FROM ${p}_sessions s
                   WHERE s.token_hash = $2::text
                     AND s.revoked_at IS NULL
                     AND s.expires_at > (SELECT at FROM clock)
                ),
                acct AS (
                  SELECT a.id
                    FROM ${p}_accounts a, caller
                   WHERE a.id = caller.account_id
                     AND a.service_profile_id = $3::text
                     AND a.status = 'active'
                     FOR SHARE OF a
                ),
                rotated AS (
                  UPDATE ${p}_account_wallets w
                     SET address = $5::text,
                         address_normalized = $6::text,
                         public_key = $7::text,
                         fingerprint = $8::text
                    FROM acct
                   WHERE w.account_id = acct.id
                     AND w.service_profile_id = $3::text
                     AND w.is_primary
                     AND w.public_key = $4::text
                     AND NOT EXISTS (
                       SELECT 1 FROM ${p}_account_wallets other
                        WHERE other.account_id = acct.id AND other.id <> w.id
                     )
                   RETURNING ${bare("w", WALLET_COLUMNS)}
                ),
                targets AS (
                  SELECT s.id
                    FROM ${p}_sessions s, rotated, caller
                   WHERE s.account_id = rotated.account_id
                     AND s.id <> caller.id
                     AND s.revoked_at IS NULL
                     AND s.expires_at > (SELECT at FROM clock)
                   ORDER BY s.id
                     FOR NO KEY UPDATE OF s
                ),
                revoked AS (
                  UPDATE ${p}_sessions s
                     SET revoked_at = (SELECT at FROM clock)
                    FROM targets
                   WHERE s.id = targets.id
                   RETURNING s.id
                ),
                logged AS (
                  INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                  SELECT rotated.account_id, 'account.key-rotate',
                         jsonb_build_object(
                           'method', 'password',
                           'revokedSessions', (SELECT count(*) FROM revoked),
                           'sessionId', caller.id
                         ),
                         (SELECT at FROM clock)
                    FROM rotated, caller
                  RETURNING 1
                )
           SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                  (SELECT count(*) FROM acct)::int AS account_active,
                  (SELECT at FROM clock) AS occurred_at,
                  ${columns("r", WALLET_COLUMNS, "wallet_")},
                  v.id AS revoked_id
             FROM (SELECT 1) AS one
             LEFT JOIN rotated r ON true
             LEFT JOIN revoked v ON true
            ORDER BY v.id`,
          [
            requestNow(context),
            hashSessionToken(token),
            serviceProfileId,
            primary.publicKey,
            newKey.address,
            newKey.addressNormalized,
            newKey.publicKey,
            fingerprint(newKey.address),
          ],
        );
      } catch (error) {
        if (sqlStateOf(error) === "23505") {
          throw new IdentityError("That key is already enrolled for another account.", "wallet-registered");
        }
        throw error;
      }
      const first = optionalRow(rows);
      if (first === null || first["wallet_id"] === null || first["wallet_id"] === undefined) {
        if (first !== null && integerColumn(first, "caller_found") === 1 && integerColumn(first, "account_active") === 1) {
          const state = await enrolledKeyState(session.accountId);
          if (state.walletCount !== 1) {
            throw walletConflict();
          }
        }
        return failGuardedStatement(first, token, context);
      }
      const wallet = mapWallet(first, "wallet_");
      const revokedSessionIds = Object.freeze(
        rows
          .map((row) => optionalTextColumn(row, "revoked_id"))
          .filter((id): id is string => id !== null),
      );
      await notify("account.key-rotate", wallet.accountId, instantColumn(first, "occurred_at"), context, {
        revokedSessions: revokedSessionIds.length,
      });
      return Object.freeze({ wallets: Object.freeze([wallet]), revokedSessionIds });
    },

    async changeEmail(token, input, context) {
      requireInput(input);
      const email = normalizeEmail(input.email);
      const { challenge, primary } = await prepareSignedChange(token, input.challengeId, context);
      const signed = message(challenge, "email-change", keyPrincipal(primary), `email:${email}`);
      if (!verifyAccountChangeSignature(input.authorizerSignature, signed, primary.publicKeyBytes)) {
        throw badSignature();
      }

      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
              caller AS (
                SELECT s.id, s.account_id
                  FROM ${p}_sessions s
                 WHERE s.token_hash = $2::text
                   AND s.revoked_at IS NULL
                   AND s.expires_at > (SELECT at FROM clock)
              ),
              acct AS (
                SELECT a.id, a.email AS previous_email,
                       a.email_verified_at AS previous_verified_at
                  FROM ${p}_accounts a, caller
                 WHERE a.id = caller.account_id
                   AND a.service_profile_id = $3::text
                   AND a.status = 'active'
                   FOR NO KEY UPDATE OF a
              ),
              keyed AS (
                SELECT w.id, w.account_id
                  FROM ${p}_account_wallets w, acct
                 WHERE w.account_id = acct.id
                   AND w.is_primary
                   AND w.public_key = $4::text
                   FOR SHARE OF w
              ),
              updated AS (
                UPDATE ${p}_accounts a
                   SET email = $5::text,
                       email_verified_at = CASE
                         WHEN $5::text IS DISTINCT FROM acct.previous_email THEN NULL
                         ELSE a.email_verified_at
                       END,
                       updated_at = (SELECT at FROM clock)
                  FROM acct, keyed
                 WHERE a.id = acct.id AND keyed.account_id = acct.id
                 RETURNING ${bare("a", ACCOUNT_COLUMNS)}
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT updated.id, 'account.email-change',
                       jsonb_build_object(
                         'emailChanged', $5::text IS DISTINCT FROM acct.previous_email,
                         'verificationCleared',
                           $5::text IS DISTINCT FROM acct.previous_email
                           AND acct.previous_verified_at IS NOT NULL,
                         'sessionId', caller.id
                       ),
                       (SELECT at FROM clock)
                  FROM updated, acct, caller
                RETURNING 1
              )
         SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                (SELECT count(*) FROM acct)::int AS account_active,
                (SELECT at FROM clock) AS occurred_at,
                ${columns("u", ACCOUNT_COLUMNS, "account_")},
                acct.previous_email, acct.previous_verified_at
           FROM (SELECT 1) AS one
           LEFT JOIN updated u ON true
           LEFT JOIN acct ON true`,
        [requestNow(context), hashSessionToken(token), serviceProfileId, primary.publicKey, email],
      );
      const row = optionalRow(rows);
      if (row === null || row["account_id"] === null || row["account_id"] === undefined) {
        return failGuardedStatement(row, token, context);
      }
      const account = mapAccount(row, "account_");
      const previousEmail = optionalTextColumn(row, "previous_email");
      const changed = previousEmail !== email;
      const previousVerifiedEmail =
        changed && optionalInstantColumn(row, "previous_verified_at") !== null ? previousEmail : null;
      if (changed) {
        await notify("account.email-change", account.id, instantColumn(row, "occurred_at"), context, {
          previousVerifiedEmail,
        });
      }
      return Object.freeze({ account, previousVerifiedEmail });
    },

    async enrollRecoveryKey(token, input, context) {
      requireRecoveryKeysEnabled();
      requireInput(input);
      const recoveryKey = canonicalRecoveryKey(input.recoveryPublicKey);
      const { challenge, primary } = await prepareSignedChange(token, input.challengeId, context);
      const signed = message(
        challenge,
        "recovery-key-enrollment",
        keyPrincipal(primary),
        recoveryPrincipal(recoveryKey.hex),
      );
      if (
        !verifyAccountChangeSignature(input.authorizerSignature, signed, primary.publicKeyBytes) ||
        !verifyAccountChangeSignature(input.subjectSignature, signed, recoveryKey.bytes)
      ) {
        throw badSignature();
      }

      // A concurrent enrollment for the same account, or of the same key, is
      // refused by a unique index; the retry runs on a fresh snapshot, where
      // the winner's key is either retired (another key) or found (this key).
      const rows = await retryUniqueViolation(() =>
        sql.query(
          `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
                caller AS (
                  SELECT s.id, s.account_id
                    FROM ${p}_sessions s
                   WHERE s.token_hash = $2::text
                     AND s.revoked_at IS NULL
                     AND s.expires_at > (SELECT at FROM clock)
                ),
                acct AS (
                  SELECT a.id
                    FROM ${p}_accounts a, caller
                   WHERE a.id = caller.account_id
                     AND a.service_profile_id = $3::text
                     AND a.status = 'active'
                     FOR SHARE OF a
                ),
                keyed AS (
                  SELECT w.id, w.account_id
                    FROM ${p}_account_wallets w, acct
                   WHERE w.account_id = acct.id
                     AND w.is_primary
                     AND w.public_key = $4::text
                     FOR SHARE OF w
                ),
                existing AS (
                  SELECT k.id, k.account_id, ${bare("k", RECOVERY_KEY_COLUMNS)}
                    FROM ${p}_account_recovery_keys k
                   WHERE k.service_profile_id = $3::text AND k.public_key = $5::text
                ),
                retired AS (
                  UPDATE ${p}_account_recovery_keys k
                     SET status = 'removed', removed_at = (SELECT at FROM clock)
                    FROM keyed
                   WHERE k.account_id = keyed.account_id
                     AND k.status = 'active'
                     AND NOT EXISTS (SELECT 1 FROM existing)
                   RETURNING k.id
                ),
                inserted AS (
                  INSERT INTO ${p}_account_recovery_keys (
                    account_id, service_profile_id, public_key, status, created_at
                  )
                  SELECT keyed.account_id, $3::text, $5::text, 'active', clock.at
                    FROM keyed, clock
                   WHERE NOT EXISTS (SELECT 1 FROM existing)
                     AND (SELECT count(*) FROM retired) >= 0
                  RETURNING id, account_id, ${RECOVERY_KEY_COLUMNS.join(", ")}
                ),
                revoked_tokens AS (
                  UPDATE ${p}_account_recoveries r
                     SET revoked_at = (SELECT at FROM clock)
                   WHERE r.recovery_key_id IN (SELECT id FROM retired)
                     AND r.completed_at IS NULL
                     AND r.revoked_at IS NULL
                   RETURNING r.id
                ),
                logged AS (
                  INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                  SELECT inserted.account_id, 'account.recovery-key.enroll',
                         jsonb_build_object(
                           'replaced', (SELECT count(*) FROM retired) > 0,
                           'sessionId', caller.id
                         ),
                         (SELECT at FROM clock)
                    FROM inserted, caller
                  RETURNING 1
                )
           SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                  (SELECT count(*) FROM acct)::int AS account_active,
                  (SELECT count(*) FROM keyed)::int AS key_current,
                  (SELECT account_id FROM keyed) AS keyed_account_id,
                  (SELECT count(*) FROM revoked_tokens)::int AS revoked_tokens,
                  (SELECT at FROM clock) AS occurred_at,
                  e.account_id AS existing_account_id,
                  ${columns("e", RECOVERY_KEY_COLUMNS, "existing_")},
                  i.account_id AS inserted_account_id,
                  ${columns("i", RECOVERY_KEY_COLUMNS, "inserted_")}
             FROM (SELECT 1) AS one
             LEFT JOIN existing e ON true
             LEFT JOIN inserted i ON true`,
          [
            requestNow(context),
            hashSessionToken(token),
            serviceProfileId,
            primary.publicKey,
            recoveryKey.hex,
          ],
        ),
      );
      const row = optionalRow(rows);
      if (
        row === null ||
        integerColumn(row, "caller_found") === 0 ||
        integerColumn(row, "account_active") === 0 ||
        integerColumn(row, "key_current") === 0
      ) {
        return failGuardedStatement(row, token, context);
      }
      const insertedAccount = optionalTextColumn(row, "inserted_account_id");
      if (insertedAccount !== null) {
        await notify(
          "account.recovery-key.enroll",
          insertedAccount,
          instantColumn(row, "occurred_at"),
          context,
        );
        return Object.freeze({ recoveryKey: mapRecoveryKey(row, "inserted_"), changed: true });
      }
      const existingAccount = optionalTextColumn(row, "existing_account_id");
      const existing = existingAccount === null ? null : mapRecoveryKey(row, "existing_");
      if (
        existing !== null &&
        existingAccount === optionalTextColumn(row, "keyed_account_id") &&
        existing.status === "active"
      ) {
        // Enrolling the key that is already active changes nothing.
        return Object.freeze({ recoveryKey: existing, changed: false });
      }
      throw new IdentityError(
        "This recovery key was enrolled before and cannot be enrolled again; generate a new one.",
        "invalid-public-key",
      );
    },

    async removeRecoveryKey(token, input, context) {
      requireInput(input);
      const { challenge, primary } = await prepareSignedChange(token, input.challengeId, context);
      const signed = message(challenge, "recovery-key-removal", keyPrincipal(primary), "none");
      if (!verifyAccountChangeSignature(input.authorizerSignature, signed, primary.publicKeyBytes)) {
        throw badSignature();
      }
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
              caller AS (
                SELECT s.id, s.account_id
                  FROM ${p}_sessions s
                 WHERE s.token_hash = $2::text
                   AND s.revoked_at IS NULL
                   AND s.expires_at > (SELECT at FROM clock)
              ),
              acct AS (
                SELECT a.id
                  FROM ${p}_accounts a, caller
                 WHERE a.id = caller.account_id
                   AND a.service_profile_id = $3::text
                   AND a.status = 'active'
                   FOR SHARE OF a
              ),
              keyed AS (
                SELECT w.id, w.account_id
                  FROM ${p}_account_wallets w, acct
                 WHERE w.account_id = acct.id
                   AND w.is_primary
                   AND w.public_key = $4::text
                   FOR SHARE OF w
              ),
              removed AS (
                UPDATE ${p}_account_recovery_keys k
                   SET status = 'removed', removed_at = (SELECT at FROM clock)
                  FROM keyed
                 WHERE k.account_id = keyed.account_id AND k.status = 'active'
                 RETURNING k.id, k.account_id
              ),
              revoked_tokens AS (
                UPDATE ${p}_account_recoveries r
                   SET revoked_at = (SELECT at FROM clock)
                 WHERE r.recovery_key_id IN (SELECT id FROM removed)
                   AND r.completed_at IS NULL
                   AND r.revoked_at IS NULL
                 RETURNING r.id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT removed.account_id, 'account.recovery-key.remove',
                       jsonb_build_object(
                         'revokedTokens', (SELECT count(*) FROM revoked_tokens),
                         'sessionId', caller.id
                       ),
                       (SELECT at FROM clock)
                  FROM removed, caller
                RETURNING 1
              )
         SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                (SELECT count(*) FROM acct)::int AS account_active,
                (SELECT count(*) FROM keyed)::int AS key_current,
                (SELECT count(*) FROM removed)::int AS removed,
                (SELECT at FROM clock) AS occurred_at,
                (SELECT account_id FROM keyed) AS account_id`,
        [requestNow(context), hashSessionToken(token), serviceProfileId, primary.publicKey],
      );
      const row = optionalRow(rows);
      if (
        row === null ||
        integerColumn(row, "caller_found") === 0 ||
        integerColumn(row, "account_active") === 0 ||
        integerColumn(row, "key_current") === 0
      ) {
        return failGuardedStatement(row, token, context);
      }
      const removed = integerColumn(row, "removed") > 0;
      if (removed) {
        await notify(
          "account.recovery-key.remove",
          textColumn(row, "account_id"),
          instantColumn(row, "occurred_at"),
          context,
        );
      }
      return Object.freeze({ removed });
    },

    async recoveryStatus(token, context) {
      const tokenHash = hashSessionToken(sessionToken(token));
      const nowParam = requestNow(context);
      const rows = await sql.query(
        `WITH caller AS (
           SELECT s.account_id, a.status
             FROM ${p}_sessions s
             JOIN ${p}_accounts a ON a.id = s.account_id AND a.service_profile_id = $2::text
            WHERE s.token_hash = $1::text
              AND s.revoked_at IS NULL
              AND s.expires_at > COALESCE($3::timestamptz, now())
         )
         SELECT caller.status, ${columns("k", RECOVERY_KEY_COLUMNS, "key_")}
           FROM caller
           LEFT JOIN LATERAL (
             SELECT ${bare("k", RECOVERY_KEY_COLUMNS)}
               FROM ${p}_account_recovery_keys k
              WHERE k.account_id = caller.account_id
              ORDER BY (k.status = 'active') DESC, k.created_at DESC, k.id DESC
              LIMIT 1
           ) k ON true`,
        [tokenHash, serviceProfileId, nowParam],
      );
      const row = optionalRow(rows);
      if (row === null) {
        throw await deps.sessionFailure(tokenHash, nowParam);
      }
      if (textColumn(row, "status") !== "active") {
        throw accountNotActive();
      }
      if (row["key_status"] === null || row["key_status"] === undefined) {
        return Object.freeze({ recoveryKey: null });
      }
      const key = mapRecoveryKey(row, "key_");
      // The latest key, unless it was removed: a used one tells the client to
      // prompt for a new key, a removed one is the same as none.
      return Object.freeze({ recoveryKey: key.status === "removed" ? null : key });
    },

    async beginRecovery(input, context) {
      requireRecoveryKeysEnabled();
      requireInput(input);
      if (typeof input.username !== "string") {
        throw new IdentityError("username must be a string.", "invalid-request");
      }
      const usernameNormalized = deps.normalizeUsername(input.username);
      const recoveryKey = canonicalRecoveryKey(input.recoveryPublicKey);
      await deps.rateLimit(
        "recoveryBegin",
        [deps.rateLimitIpHash(context), usernameNormalized],
        context,
      );
      // Without a host-supplied address hash every caller would share one
      // bucket and throttle the whole deployment, as with email verification.
      const ipHash = sanitizeContextHash(context?.ipHash);
      if (ipHash !== null) {
        await deps.rateLimit("recoveryBeginIp", [ipHash], context);
      }
      if (typeof input.challengeId !== "string") {
        throw new IdentityError("challengeId must be a string.", "invalid-request");
      }
      const challenge = await deps.consumeChallenge(input.challengeId, "rotation", context);
      if (challenge.usernameNormalized !== usernameNormalized) {
        throw recoveryRefused();
      }
      const signed = message(challenge, "recovery-begin", recoveryPrincipal(recoveryKey.hex), "none");
      if (!verifyAccountChangeSignature(input.signature, signed, recoveryKey.bytes)) {
        throw recoveryRefused();
      }

      const recoveryToken = generateSessionToken();
      // Two begins at once: the second one's insert meets the first's live
      // row in the unique live index, and its retry revokes that row.
      const rows = await retryUniqueViolation(() =>
        sql.query(
          `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
                acct AS (
                  SELECT a.id
                    FROM ${p}_accounts a
                   WHERE a.service_profile_id = $2::text
                     AND a.username_normalized = $3::text
                     AND a.status = 'active'
                     FOR SHARE OF a
                ),
                rkey AS (
                  SELECT k.id, k.account_id
                    FROM ${p}_account_recovery_keys k, acct
                   WHERE k.account_id = acct.id
                     AND k.service_profile_id = $2::text
                     AND k.public_key = $4::text
                     AND k.status = 'active'
                     FOR SHARE OF k
                ),
                superseded AS (
                  UPDATE ${p}_account_recoveries r
                     SET revoked_at = (SELECT at FROM clock)
                    FROM rkey
                   WHERE r.account_id = rkey.account_id
                     AND r.completed_at IS NULL
                     AND r.revoked_at IS NULL
                   RETURNING r.id
                ),
                issued AS (
                  INSERT INTO ${p}_account_recoveries (
                    account_id, recovery_key_id, token_hash, created_at, expires_at
                  )
                  SELECT rkey.account_id, rkey.id, $5::text, clock.at,
                         date_trunc('milliseconds', clock.at + (interval '1 second' * $6::double precision))
                    FROM rkey, clock
                   WHERE (SELECT count(*) FROM superseded) >= 0
                  RETURNING id, account_id, expires_at
                ),
                logged AS (
                  INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                  SELECT issued.account_id, 'account.recovery-begin',
                         jsonb_build_object(
                           'method', 'recovery-key',
                           'supersededTokens', (SELECT count(*) FROM superseded)
                         ),
                         (SELECT at FROM clock)
                    FROM issued
                  RETURNING 1
                )
           SELECT issued.account_id, issued.expires_at, (SELECT at FROM clock) AS occurred_at
             FROM issued`,
          [
            requestNow(context),
            serviceProfileId,
            usernameNormalized,
            recoveryKey.hex,
            hashSessionToken(recoveryToken),
            RECOVERY_TOKEN_TTL_SECONDS,
          ],
        ),
      );
      const row = optionalRow(rows);
      if (row === null) {
        throw recoveryRefused();
      }
      const accountId = textColumn(row, "account_id");
      await notify("account.recovery-begin", accountId, instantColumn(row, "occurred_at"), context);
      return Object.freeze({
        accountId,
        recoveryToken,
        expiresAt: instantColumn(row, "expires_at"),
      });
    },

    async authenticateRecovery(recoveryToken, context) {
      requireRecoveryKeysEnabled();
      const resolved = await readRecoveryContext(recoveryToken, context);
      return Object.freeze({
        accountId: resolved.accountId,
        usernameNormalized: resolved.usernameNormalized,
        expiresAt: resolved.expiresAt,
      });
    },

    async completeRecovery(recoveryToken, input, context) {
      requireRecoveryKeysEnabled();
      requireInput(input);
      const newKey = canonicalNewKey(input.newKey);
      const recovery = await readRecoveryContext(recoveryToken, context);
      await deps.rateLimit(
        "accountChange",
        [deps.rateLimitIpHash(context), recovery.accountId],
        context,
      );
      if (typeof input.challengeId !== "string") {
        throw new IdentityError("challengeId must be a string.", "invalid-request");
      }
      const challenge = await deps.consumeChallenge(input.challengeId, "rotation", context);
      if (challenge.usernameNormalized !== recovery.usernameNormalized) {
        throw recoveryRefused();
      }
      const signed = message(
        challenge,
        "recovery-reset",
        recoveryPrincipal(recovery.recoveryPublicKey),
        keyPrincipal(newKey),
      );
      if (
        !verifyAccountChangeSignature(
          input.authorizerSignature,
          signed,
          hexToBytes(recovery.recoveryPublicKey),
        ) ||
        !verifyAccountChangeSignature(input.subjectSignature, signed, newKey.publicKeyBytes)
      ) {
        throw recoveryRefused();
      }
      if (recovery.primary !== null && recovery.primary.publicKey === newKey.publicKey) {
        throw new IdentityError(
          "The new key is the key already enrolled; choose a new password.",
          "key-unchanged",
        );
      }
      if (recovery.walletCount !== 1) {
        throw walletConflict();
      }

      const sessionTokenValue = generateSessionToken();
      const client = deps.sessionClientColumns(context);
      let rows: SqlRow[];
      try {
        rows = await sql.query(
          `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
                acct AS (
                  SELECT ${bare("a", ACCOUNT_COLUMNS)}
                    FROM ${p}_accounts a
                   WHERE a.id = $2::uuid
                     AND a.service_profile_id = $3::text
                     AND a.status = 'active'
                     FOR SHARE OF a
                ),
                wallet AS (
                  SELECT w.id, w.account_id
                    FROM ${p}_account_wallets w, acct
                   WHERE w.account_id = acct.id
                     AND w.is_primary
                     AND w.public_key <> $8::text
                     AND NOT EXISTS (
                       SELECT 1 FROM ${p}_account_wallets other
                        WHERE other.account_id = acct.id AND other.id <> w.id
                     )
                     FOR UPDATE OF w
                ),
                rkey AS (
                  SELECT k.id
                    FROM ${p}_account_recovery_keys k, wallet
                   WHERE k.id = $4::uuid
                     AND k.account_id = wallet.account_id
                     AND k.status = 'active'
                     FOR UPDATE OF k
                ),
                token AS (
                  SELECT r.id
                    FROM ${p}_account_recoveries r, rkey
                   WHERE r.token_hash = $5::text
                     AND r.recovery_key_id = rkey.id
                     AND r.completed_at IS NULL
                     AND r.revoked_at IS NULL
                     AND r.expires_at > (SELECT at FROM clock)
                     FOR UPDATE OF r
                ),
                ok AS (
                  SELECT wallet.id AS wallet_id, wallet.account_id, rkey.id AS key_id,
                         token.id AS token_id
                    FROM wallet, rkey, token
                ),
                rotated AS (
                  UPDATE ${p}_account_wallets w
                     SET address = $6::text,
                         address_normalized = $7::text,
                         public_key = $8::text,
                         fingerprint = $9::text
                    FROM ok
                   WHERE w.id = ok.wallet_id
                   RETURNING ${bare("w", WALLET_COLUMNS)}
                ),
                used AS (
                  UPDATE ${p}_account_recovery_keys k
                     SET status = 'used', used_at = (SELECT at FROM clock)
                    FROM ok
                   WHERE k.id = ok.key_id
                   RETURNING k.id
                ),
                completed AS (
                  UPDATE ${p}_account_recoveries r
                     SET completed_at = (SELECT at FROM clock)
                    FROM ok
                   WHERE r.id = ok.token_id
                   RETURNING r.id
                ),
                targets AS (
                  SELECT s.id
                    FROM ${p}_sessions s, ok
                   WHERE s.account_id = ok.account_id
                     AND s.revoked_at IS NULL
                     AND s.expires_at > (SELECT at FROM clock)
                   ORDER BY s.id
                     FOR NO KEY UPDATE OF s
                ),
                revoked AS (
                  UPDATE ${p}_sessions s
                     SET revoked_at = (SELECT at FROM clock)
                    FROM targets
                   WHERE s.id = targets.id
                   RETURNING s.id
                ),
                new_session AS (
                  INSERT INTO ${p}_sessions (
                    account_id, token_hash, issued_at, expires_at, last_seen_at,
                    ip_hash, user_agent_hash, client_label
                  )
                  SELECT ok.account_id, $10::text, clock.at,
                         date_trunc('milliseconds', clock.at + (interval '1 second' * $11::double precision)),
                         clock.at, $12::text, $13::text, $14::text
                    FROM ok, clock
                   WHERE (SELECT count(*) FROM revoked) >= 0
                  RETURNING ${SESSION_COLUMNS.join(", ")}
                ),
                logged AS (
                  INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                  SELECT ok.account_id, 'account.recover',
                         jsonb_build_object(
                           'method', 'recovery-key',
                           'revokedSessions', (SELECT count(*) FROM revoked),
                           'sessionId', new_session.id
                         ),
                         (SELECT at FROM clock)
                    FROM ok, new_session
                   WHERE (SELECT count(*) FROM used) = 1
                     AND (SELECT count(*) FROM completed) = 1
                  RETURNING 1
                )
           SELECT (SELECT at FROM clock) AS occurred_at,
                  ${columns("a", ACCOUNT_COLUMNS, "account_")},
                  ${columns("r", WALLET_COLUMNS, "wallet_")},
                  ${columns("n", SESSION_COLUMNS, "session_")},
                  v.id AS revoked_id
             FROM acct a
             JOIN rotated r ON true
             JOIN new_session n ON true
             LEFT JOIN revoked v ON true
            ORDER BY v.id`,
          [
            requestNow(context),
            recovery.accountId,
            serviceProfileId,
            recovery.recoveryKeyId,
            hashSessionToken(recoveryToken),
            newKey.address,
            newKey.addressNormalized,
            newKey.publicKey,
            fingerprint(newKey.address),
            hashSessionToken(sessionTokenValue),
            config.sessionTtlSeconds,
            client.ipHash,
            client.userAgentHash,
            client.clientLabel,
          ],
        );
      } catch (error) {
        if (sqlStateOf(error) === "23505") {
          throw new IdentityError("That key is already enrolled for another account.", "wallet-registered");
        }
        throw error;
      }
      const first = optionalRow(rows);
      if (first === null) {
        const state = await enrolledKeyState(recovery.accountId);
        if (state.walletCount !== 1) {
          throw walletConflict();
        }
        // The token was spent, revoked or expired, the key used or removed,
        // or the account suspended, between the read and the statement.
        throw recoveryRefused();
      }
      const account = mapAccount(first, "account_");
      const wallet = mapWallet(first, "wallet_");
      const revokedSessionIds = Object.freeze(
        rows
          .map((row) => optionalTextColumn(row, "revoked_id"))
          .filter((id): id is string => id !== null),
      );
      await notify("account.recover", account.id, instantColumn(first, "occurred_at"), context, {
        revokedSessions: revokedSessionIds.length,
      });
      return Object.freeze({
        account,
        wallets: Object.freeze([wallet]),
        session: Object.freeze({ session: mapSession(first, "session_"), token: sessionTokenValue }),
        revokedSessionIds,
      });
    },

    async listSecurityEvents(token, context) {
      const tokenHash = hashSessionToken(sessionToken(token));
      const nowParam = requestNow(context);
      // A label is shown only while the session it names still exists, so an
      // event keeps no device description beyond the session row's lifetime.
      const rows = await sql.query(
        `WITH caller AS (
           SELECT s.account_id, a.status
             FROM ${p}_sessions s
             JOIN ${p}_accounts a ON a.id = s.account_id AND a.service_profile_id = $2::text
            WHERE s.token_hash = $1::text
              AND s.revoked_at IS NULL
              AND s.expires_at > COALESCE($3::timestamptz, now())
         )
         SELECT caller.status, e.id, e.action, e.created_at, labelled.client_label
           FROM caller
           LEFT JOIN LATERAL (
             SELECT e.id, e.action, e.created_at, e.metadata
               FROM ${p}_audit_events e
              WHERE e.account_id = caller.account_id
              ORDER BY e.created_at DESC, e.id DESC
              LIMIT $4::integer
           ) e ON true
           LEFT JOIN ${p}_sessions labelled
             ON labelled.account_id = caller.account_id
            AND labelled.id::text = e.metadata->>'sessionId'
          ORDER BY e.created_at DESC, e.id DESC`,
        [tokenHash, serviceProfileId, nowParam, MAX_SECURITY_EVENTS],
      );
      const first = optionalRow(rows);
      if (first === null) {
        throw await deps.sessionFailure(tokenHash, nowParam);
      }
      if (textColumn(first, "status") !== "active") {
        throw accountNotActive();
      }
      return Object.freeze(
        rows
          .filter((row) => row["id"] !== null && row["id"] !== undefined)
          .map((row) =>
            Object.freeze({
              id: textColumn(row, "id"),
              action: textColumn(row, "action"),
              createdAt: instantColumn(row, "created_at"),
              clientLabel: optionalTextColumn(row, "client_label"),
            }),
          ),
      );
    },

    async revokeRecoveryKeys(accountId, context) {
      const id =
        typeof accountId === "string" ? accountId.trim().toLowerCase() : "";
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(id)) {
        throw new IdentityError("Malformed identifier.", "account-not-found");
      }
      // An operator control: it works on a suspended account too, since the
      // incident runbook suspends first and revokes the recovery key after.
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($3::timestamptz, now()) AS at),
              acct AS (
                SELECT a.id
                  FROM ${p}_accounts a
                 WHERE a.id = $1::uuid AND a.service_profile_id = $2::text
                   FOR SHARE OF a
              ),
              removed AS (
                UPDATE ${p}_account_recovery_keys k
                   SET status = 'removed', removed_at = (SELECT at FROM clock)
                  FROM acct
                 WHERE k.account_id = acct.id AND k.status = 'active'
                 RETURNING k.id
              ),
              revoked_tokens AS (
                UPDATE ${p}_account_recoveries r
                   SET revoked_at = (SELECT at FROM clock)
                  FROM acct
                 WHERE r.account_id = acct.id
                   AND r.completed_at IS NULL
                   AND r.revoked_at IS NULL
                   AND (SELECT count(*) FROM removed) >= 0
                 RETURNING r.id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT acct.id, 'account.recovery-key.revoke',
                       jsonb_build_object(
                         'revoked', (SELECT count(*) FROM removed),
                         'revokedTokens', (SELECT count(*) FROM revoked_tokens)
                       ),
                       (SELECT at FROM clock)
                  FROM acct
                RETURNING 1
              )
         SELECT (SELECT count(*) FROM acct)::int AS account_found,
                (SELECT count(*) FROM removed)::int AS removed,
                (SELECT at FROM clock) AS occurred_at`,
        [id, serviceProfileId, requestNow(context)],
      );
      const row = optionalRow(rows);
      if (row === null || integerColumn(row, "account_found") === 0) {
        throw new IdentityError("Account does not exist.", "account-not-found");
      }
      const removed = integerColumn(row, "removed");
      if (removed > 0) {
        await notify("account.recovery-key.revoke", id, instantColumn(row, "occurred_at"), context);
      }
      return removed;
    },
  };

  /**
   * A live recovery token: unspent, unrevoked, unexpired, for an active key
   * of an active account. Every failure is the one uniform refusal.
   */
  async function readRecoveryContext(
    recoveryToken: unknown,
    context: RequestContext | undefined,
  ): Promise<RecoveryContext> {
    if (typeof recoveryToken !== "string" || recoveryToken.trim().length === 0) {
      throw recoveryRefused();
    }
    const rows = await sql.query(
      `SELECT r.account_id, a.username_normalized, r.recovery_key_id,
              k.public_key AS recovery_public_key, r.expires_at,
              w.public_key AS primary_public_key, w.address AS primary_address,
              (SELECT count(*) FROM ${p}_account_wallets c WHERE c.account_id = a.id)::int
                AS wallet_count
         FROM ${p}_account_recoveries r
         JOIN ${p}_account_recovery_keys k ON k.id = r.recovery_key_id AND k.status = 'active'
         JOIN ${p}_accounts a
           ON a.id = r.account_id AND a.service_profile_id = $2::text AND a.status = 'active'
         LEFT JOIN ${p}_account_wallets w ON w.account_id = a.id AND w.is_primary
        WHERE r.token_hash = $1::text
          AND r.completed_at IS NULL
          AND r.revoked_at IS NULL
          AND r.expires_at > COALESCE($3::timestamptz, now())`,
      [hashSessionToken(recoveryToken), serviceProfileId, requestNow(context)],
    );
    const row = optionalRow(rows);
    if (row === null) {
      throw recoveryRefused();
    }
    return Object.freeze({
      accountId: textColumn(row, "account_id"),
      usernameNormalized: textColumn(row, "username_normalized"),
      recoveryKeyId: textColumn(row, "recovery_key_id"),
      recoveryPublicKey: textColumn(row, "recovery_public_key"),
      expiresAt: instantColumn(row, "expires_at"),
      primary: storedIdentity(
        optionalTextColumn(row, "primary_public_key"),
        optionalTextColumn(row, "primary_address"),
      ),
      walletCount: integerColumn(row, "wallet_count"),
    });
  }

  return Object.freeze(operations);
}
