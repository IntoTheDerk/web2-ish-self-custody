/**
 * Account resets and reauthentication (package-internal; the methods are
 * exposed through `IdentityService`).
 *
 * - Two per-account settings (migration 8), each changed by a signature of
 *   the enrolled key over the account-change message, so the signature binds
 *   the value (`setting:on`, `setting:off`).
 * - Account recovery by email: a short-lived emailed code (signed out), whose
 *   start answers alike for every username.
 * - The signed-in reset: from one session, available after a 72-hour wait,
 *   or at once with an emailed code; any session of the account aborts it,
 *   and so do a sign-in with the password (in the login statement) and a
 *   password change (in the rotation's statement), since each proves the
 *   password is not forgotten.
 * - Reauthentication: a fresh signature by the enrolled key over a host
 *   label, audited, changing nothing else.
 *
 * Lock order: the order of `accountChanges.ts`, with the resets after the
 * enrolled key and before the sessions. Cancellation advances the account's
 * durable reset generation; closing rows alone cannot catch a start inserted
 * after the canceller's snapshot. The email start takes `FOR NO KEY UPDATE`
 * on the account before inspecting its live reset.
 *
 *   account (FOR SHARE, or FOR NO KEY UPDATE for cancellation, setting change,
 *            email start or email completion)
 *   → enrolled key (FOR UPDATE to replace it, FOR SHARE to check it)
 *   → recovery key (FOR SHARE, a setting change only)
 *   → resets: the one completing (FOR UPDATE), then the others it closes
 *   → sessions, in id order (FOR NO KEY UPDATE), never the caller's own row
 *   → inserts (a new session, the audit rows).
 *
 * The login statement locks the account and enrolled key before inserting a
 * session, advancing the generation and locking a reset row.
 * `abortSignedInReset` locks the account (FOR NO KEY UPDATE) and a reset row;
 * rotation locks the account, key, reset and then
 * sessions. Revocations read resets without locking them.
 *
 * A setting change cannot see a reset that a start inserted while the change
 * waited for the account row: the change's snapshot predates that row. The
 * generation check at completion and pending reads closes that race.
 */
import { hostLabelPattern } from "../accountChange.js";
import { fingerprint } from "../encoding.js";
import {
  ACCOUNT_COLUMNS,
  SESSION_COLUMNS,
  WALLET_COLUMNS,
  accountChangeToolkit,
  bare,
  columns,
  retryUniqueViolation,
  type AccountChangeDependencies,
} from "./accountChanges.js";
import { verifyAccountChangeSignature } from "./accountChangeSignature.js";
import { IdentityError } from "./errors.js";
import {
  booleanColumn,
  mapAccount,
  mapSession,
  mapWallet,
  requestNow,
  sanitizeContextHash,
  sqlStateOf,
  uuidPattern,
} from "./records.js";
import {
  instantColumn,
  integerColumn,
  optionalInstantColumn,
  optionalRow,
  optionalTextColumn,
  textColumn,
  type SqlRow,
} from "./sql.js";
import {
  constantTimeEqualHex,
  generateAccountResetCode,
  generateSessionToken,
  hashAccountResetCode,
  hashSessionToken,
} from "./tokens.js";
import type {
  AccountResetCompletionInput,
  AccountResetSettingInput,
  AccountResetSettingName,
  AccountResetSettings,
  AccountResetStatus,
  IdentityAccount,
  IdentityWallet,
  IssuedAccountReset,
  IssuedSession,
  IssuedSignedInReset,
  PendingSignedInReset,
  ReauthenticationInput,
  RequestContext,
  SignedInResetCompletionInput,
  VerifiedReauthentication,
} from "./types.js";

/** An emailed reset code is good for 15 minutes ... */
export const ACCOUNT_RESET_CODE_TTL_SECONDS = 900;
/** ... and 5 attempts. */
export const ACCOUNT_RESET_MAX_ATTEMPTS = 5;
/** A signed-in reset becomes available without a code after 72 hours ... */
export const SIGNED_IN_RESET_WAIT_SECONDS = 72 * 3_600;
/** ... and can then be completed for 7 more days. */
export const SIGNED_IN_RESET_WINDOW_SECONDS = 7 * 86_400;

const nonAlphanumeric = /[^A-Z0-9]/gu;
const settingNames: readonly AccountResetSettingName[] = Object.freeze([
  "email-reset",
  "signed-in-reset",
]);

export type AccountResetOperations = Readonly<{
  setAccountResetSetting(
    token: string,
    input: AccountResetSettingInput,
    context?: RequestContext,
  ): Promise<{ settings: AccountResetSettings; changed: boolean }>;
  accountResetStatus(token: string, context?: RequestContext): Promise<AccountResetStatus>;
  startAccountReset(
    input: Readonly<{ username: string }>,
    context?: RequestContext,
  ): Promise<IssuedAccountReset>;
  cancelUndeliveredAccountReset(
    input: Readonly<{ resetId: string; code: string }>,
    context?: RequestContext,
  ): Promise<{ cancelled: boolean }>;
  completeAccountReset(
    input: AccountResetCompletionInput,
    context?: RequestContext,
  ): Promise<{
    account: IdentityAccount;
    wallets: readonly IdentityWallet[];
    session: IssuedSession;
    revokedSessionIds: readonly string[];
  }>;
  startSignedInReset(token: string, context?: RequestContext): Promise<IssuedSignedInReset>;
  abortSignedInReset(token: string, context?: RequestContext): Promise<{ aborted: boolean }>;
  completeSignedInReset(
    token: string,
    input: SignedInResetCompletionInput,
    context?: RequestContext,
  ): Promise<{ wallets: readonly IdentityWallet[]; revokedSessionIds: readonly string[] }>;
  verifyReauthentication(
    token: string,
    input: ReauthenticationInput,
    context?: RequestContext,
  ): Promise<VerifiedReauthentication>;
}>;

/** A submitted code, reduced to the verification alphabet as email verification does. */
function reduceCode(value: unknown): string {
  return typeof value === "string" ? value.toUpperCase().replace(nonAlphanumeric, "") : "";
}

/** A reset id as the service issues it, or null. */
function canonicalResetId(value: unknown): string | null {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return uuidPattern.test(normalized) ? normalized : null;
}

export function accountResetOperations(deps: AccountChangeDependencies): AccountResetOperations {
  const { sql, config, p } = deps;
  const serviceProfileId = config.serviceProfileId;
  const {
    accountNotActive,
    badSignature,
    requireDeterministicMode,
    requireInput,
    sessionToken,
    canonicalNewKey,
    message,
    keyPrincipal,
    notify,
    readSessionContext,
    prepareSignedChange,
    enrolledKeyState,
    walletConflict,
    staleKey,
    failGuardedStatement,
  } = accountChangeToolkit(deps);

  // Every failure of an emailed reset that an unauthenticated caller can
  // cause is this one answer: an unknown username or reset, a wrong, spent or
  // expired code, a code out of attempts, the setting off, an unverified or
  // changed email, a suspended account, a bad signature.
  const resetRefused = (): IdentityError =>
    new IdentityError(
      "The username, reset or code is not correct, or the code has expired.",
      "invalid-signature",
    );
  const codeRefused = (): IdentityError =>
    new IdentityError(
      "The reset code is not correct, has expired or has no attempts left.",
      "email-verification-failed",
    );
  const resetUnavailable = (availableAt?: Date): IdentityError =>
    availableAt === undefined
      ? new IdentityError(
          "There is no pending password reset of this session to complete; it was aborted, completed or has expired.",
          "reset-unavailable",
        )
      : new IdentityError(
          "The password reset is not available yet.",
          "reset-unavailable",
          { availableAt: availableAt.toISOString() },
        );

  const requireEmailResetEnabled = (): void => {
    if (!config.accountSecurity.emailReset) {
      throw new IdentityError(
        "Account recovery by email is not enabled on this service (accountSecurity.emailReset).",
        "invalid-request",
      );
    }
    requireDeterministicMode();
  };
  const requireSignedInResetEnabled = (): void => {
    if (!config.accountSecurity.signedInReset) {
      throw new IdentityError(
        "The signed-in reset is not enabled on this service (accountSecurity.signedInReset).",
        "invalid-request",
      );
    }
    requireDeterministicMode();
  };

  const requireResetId = (value: unknown): string => {
    const resetId = canonicalResetId(value);
    if (resetId === null) {
      throw new IdentityError("resetId must be a reset id (a UUID).", "invalid-request");
    }
    return resetId;
  };

  /**
   * The emailed code still completes a reset only while all of this holds.
   * Email completion counts its attempt in the same statement that decides
   * success; status and that completion require an attempt left (`<`). A
   * signed-in reset counts its code attempt before completion (`<=`).
   */
  const emailCodeLive = (reset: string, acct: string, attempts: "<" | "<=" = "<="): string =>
    `${reset}.code_hash IS NOT NULL
     AND ${reset}.attempts ${attempts} ${String(ACCOUNT_RESET_MAX_ATTEMPTS)}
     AND ${reset}.created_at + interval '${String(ACCOUNT_RESET_CODE_TTL_SECONDS)} seconds' > (SELECT at FROM clock)
     AND ${config.accountSecurity.emailReset ? "true" : "false"}
     AND ${acct}.email_reset_enabled
     AND ${acct}.email IS NOT NULL
     AND ${acct}.email_verified_at IS NOT NULL
     AND ${acct}.email_verified_at <= ${reset}.created_at`;

  const mapPending = (row: SqlRow, callerSessionId: string): PendingSignedInReset =>
    Object.freeze({
      id: textColumn(row, "reset_id"),
      createdAt: instantColumn(row, "reset_created_at"),
      availableAt: instantColumn(row, "reset_available_at"),
      expiresAt: instantColumn(row, "reset_expires_at"),
      initiatedByCaller: textColumn(row, "reset_session_id") === callerSessionId,
      codeUsable: booleanColumn(row, "reset_code_usable"),
    });

  const operations: AccountResetOperations = {
    async setAccountResetSetting(token, input, context) {
      requireInput(input);
      const setting = settingNames.find((name) => name === input.setting);
      if (setting === undefined) {
        throw new IdentityError(
          `setting must be one of: ${settingNames.join(", ")}.`,
          "invalid-request",
        );
      }
      if (typeof input.enabled !== "boolean") {
        throw new IdentityError("enabled must be a boolean.", "invalid-request");
      }
      const enabled = input.enabled;
      // Turning a method on needs its opt-in; turning one off always works,
      // so an owner can withdraw it whatever the deployment offers now.
      if (enabled) {
        if (setting === "email-reset") {
          requireEmailResetEnabled();
        } else {
          requireSignedInResetEnabled();
        }
      } else {
        requireDeterministicMode();
      }
      const { challenge, primary } = await prepareSignedChange(token, input.challengeId, context);
      const signed = message(
        challenge,
        setting === "email-reset" ? "email-reset-setting" : "signed-in-reset-setting",
        keyPrincipal(primary),
        enabled ? "setting:on" : "setting:off",
      );
      if (!verifyAccountChangeSignature(input.authorizerSignature, signed, primary.publicKeyBytes)) {
        throw badSignature();
      }

      // The rule reads the account row and the recovery key under their
      // locks, so a change that committed while this waited is seen: a
      // statement that waited for a row lock sees that row's latest version,
      // but keeps its snapshot for every row it did not lock.
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
                SELECT a.id, a.email, a.email_verified_at, a.email_reset_enabled,
                       a.signed_in_reset_enabled
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
              rkey AS (
                SELECT k.id
                  FROM ${p}_account_recovery_keys k, keyed
                 WHERE k.account_id = keyed.account_id
                   AND k.status = 'active'
                   AND $7::boolean
                   FOR SHARE OF k
              ),
              rule AS (
                SELECT keyed.account_id,
                       CASE WHEN $5::text = 'email-reset'
                         THEN NOT $6::boolean
                              OR (acct.email IS NOT NULL AND acct.email_verified_at IS NOT NULL)
                         ELSE $6::boolean
                              OR EXISTS (SELECT 1 FROM rkey)
                              OR ($8::boolean AND acct.email_reset_enabled
                                  AND acct.email IS NOT NULL
                                  AND acct.email_verified_at IS NOT NULL)
                       END AS allowed,
                       CASE WHEN $5::text = 'email-reset'
                         THEN acct.email_reset_enabled
                         ELSE acct.signed_in_reset_enabled
                       END AS current_value
                  FROM keyed, acct
              ),
              updated AS (
                UPDATE ${p}_accounts a
                   SET email_reset_enabled = CASE
                         WHEN $5::text = 'email-reset' THEN $6::boolean ELSE a.email_reset_enabled
                       END,
                       signed_in_reset_enabled = CASE
                         WHEN $5::text = 'signed-in-reset' THEN $6::boolean ELSE a.signed_in_reset_enabled
                       END,
                       reset_generation = a.reset_generation + 1,
                       updated_at = (SELECT at FROM clock)
                  FROM rule
                 WHERE a.id = rule.account_id
                   AND rule.allowed
                   AND rule.current_value IS DISTINCT FROM $6::boolean
                 RETURNING a.id, a.email_reset_enabled, a.signed_in_reset_enabled
              ),
              -- Either direction closes visible resets of the changed method;
              -- an email-reset setting change also cancels signed-in resets
              -- that could use an emailed code. The generation fences rows
              -- that this statement's snapshot cannot see.
              closed_resets AS (
                UPDATE ${p}_account_resets r
                   SET aborted_at = (SELECT at FROM clock)
                  FROM updated
                 WHERE r.account_id = updated.id
                   AND (r.kind = 'signed-in' OR ($5::text = 'email-reset' AND r.kind = 'email'))
                   AND r.completed_at IS NULL
                   AND r.aborted_at IS NULL
                   AND r.expires_at > (SELECT at FROM clock)
                 RETURNING r.id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT updated.id, 'account.reset-setting',
                       jsonb_build_object(
                         'setting', $5::text,
                         'enabled', $6::boolean,
                         'closedResets', (SELECT count(*) FROM closed_resets),
                         'sessionId', caller.id
                       ),
                       (SELECT at FROM clock)
                  FROM updated, caller
                RETURNING 1
              )
         SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                (SELECT count(*) FROM acct)::int AS account_active,
                (SELECT count(*) FROM keyed)::int AS key_current,
                (SELECT account_id FROM keyed) AS account_id,
                COALESCE((SELECT allowed FROM rule), false) AS allowed,
                (SELECT count(*) FROM updated)::int AS changed,
                COALESCE((SELECT email_reset_enabled FROM updated),
                         (SELECT email_reset_enabled FROM acct)) AS email_reset,
                COALESCE((SELECT signed_in_reset_enabled FROM updated),
                         (SELECT signed_in_reset_enabled FROM acct)) AS signed_in_reset,
                (SELECT at FROM clock) AS occurred_at`,
        [
          requestNow(context),
          hashSessionToken(token),
          serviceProfileId,
          primary.publicKey,
          setting,
          enabled,
          config.accountSecurity.recoveryKeys,
          config.accountSecurity.emailReset,
        ],
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
      if (!booleanColumn(row, "allowed")) {
        throw setting === "email-reset"
          ? new IdentityError(
              "Account recovery by email needs a verified email address.",
              "reset-setting-refused",
              { reason: "email-unverified" },
            )
          : new IdentityError(
              "The signed-in reset can be turned off only while another reset method (a recovery key or account recovery by email) is set.",
              "reset-setting-refused",
              { reason: "no-other-reset-method" },
            );
      }
      const changed = integerColumn(row, "changed") === 1;
      if (changed) {
        await notify("account.reset-setting", textColumn(row, "account_id"), instantColumn(row, "occurred_at"), context, {
          setting,
          enabled,
        });
      }
      return Object.freeze({
        settings: Object.freeze({
          emailReset: booleanColumn(row, "email_reset"),
          signedInReset: booleanColumn(row, "signed_in_reset"),
        }),
        changed,
      });
    },

    async accountResetStatus(token, context) {
      const tokenHash = hashSessionToken(sessionToken(token));
      const nowParam = requestNow(context);
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($3::timestamptz, now()) AS at),
              caller AS (
                SELECT s.id, s.account_id, a.status, a.email, a.email_verified_at,
                       a.email_reset_enabled, a.signed_in_reset_enabled, a.reset_generation
                  FROM ${p}_sessions s
                  JOIN ${p}_accounts a ON a.id = s.account_id AND a.service_profile_id = $2::text
                 WHERE s.token_hash = $1::text
                   AND s.revoked_at IS NULL
                   AND s.expires_at > (SELECT at FROM clock)
              )
         SELECT caller.id AS caller_id, caller.status, caller.email_reset_enabled,
                caller.signed_in_reset_enabled,
                caller.email IS NOT NULL AND caller.email_verified_at IS NOT NULL AS email_verified,
                r.id AS reset_id, r.created_at AS reset_created_at,
                r.available_at AS reset_available_at, r.expires_at AS reset_expires_at,
                r.session_id AS reset_session_id,
                COALESCE(${emailCodeLive("r", "caller", "<")}, false) AS reset_code_usable
           FROM caller
           LEFT JOIN LATERAL (
             SELECT r.*
               FROM ${p}_account_resets r
               JOIN ${p}_sessions rs
                 ON rs.id = r.session_id
                AND rs.revoked_at IS NULL
                AND rs.expires_at > (SELECT at FROM clock)
              WHERE r.account_id = caller.account_id
                AND caller.signed_in_reset_enabled
                AND r.kind = 'signed-in'
                AND r.reset_generation = caller.reset_generation
                AND r.completed_at IS NULL
                AND r.aborted_at IS NULL
                AND r.expires_at > (SELECT at FROM clock)
              LIMIT 1
           ) r ON true`,
        [tokenHash, serviceProfileId, nowParam],
      );
      const row = optionalRow(rows);
      if (row === null) {
        throw await deps.sessionFailure(tokenHash, nowParam);
      }
      if (textColumn(row, "status") !== "active") {
        throw accountNotActive();
      }
      const callerId = textColumn(row, "caller_id");
      return Object.freeze({
        settings: Object.freeze({
          emailReset: booleanColumn(row, "email_reset_enabled"),
          signedInReset: booleanColumn(row, "signed_in_reset_enabled"),
        }),
        emailVerified: booleanColumn(row, "email_verified"),
        pendingSignedInReset:
          optionalTextColumn(row, "reset_id") === null ? null : mapPending(row, callerId),
      });
    },

    async startAccountReset(input, context) {
      requireEmailResetEnabled();
      requireInput(input);
      if (typeof input.username !== "string") {
        throw new IdentityError("username must be a string.", "invalid-request");
      }
      const usernameNormalized = deps.normalizeUsername(input.username);
      // Anonymous callers must not be able to spend a shared username quota.
      // The caller IP is still bounded, while an open emailed challenge is
      // coalesced below rather than rotated by another browser.
      const ipHash = sanitizeContextHash(context?.ipHash);
      if (ipHash !== null) {
        await deps.rateLimit("accountResetStartIp", [ipHash], context);
      }

      // Only the email carries the usable id. The public id is fresh even on
      // issuance; an anonymous requester cannot spend the code's attempts.
      const publicResetId = globalThis.crypto.randomUUID();
      const resetId = globalThis.crypto.randomUUID();
      const code = generateAccountResetCode();
      const cap = deps.recipientCap;
      // The database function takes an account row lock, then uses a fresh
      // snapshot to coalesce an active challenge. It reserves recipient quota
      // only when a new code is actually inserted.
      const rows = await sql.query(
        `SELECT delivery_email AS email, issued, expires_at
           FROM ${p}_start_email_reset(
             $1::text, $2::text, $3::text, $4::text, $5::double precision,
             $6::integer, $7::uuid, $8::text, $9::double precision, $10::timestamptz
           )`,
        [
          serviceProfileId,
          usernameNormalized,
          cap.bucketPrefix,
          cap.ruleId,
          cap.windowSeconds,
          cap.limit,
          resetId,
          hashAccountResetCode(serviceProfileId, resetId, code),
          ACCOUNT_RESET_CODE_TTL_SECONDS,
          requestNow(context),
        ],
      );
      const row = optionalRow(rows);
      if (row === null) {
        throw new IdentityError("The reset could not be started.", "invalid-request");
      }
      const email = optionalTextColumn(row, "email");
      // No hook here: the host already holds the code to send, and an awaited
      // hook would make an issued code slower to answer than a refusal.
      return Object.freeze({
        resetId: publicResetId,
        expiresAt: instantColumn(row, "expires_at"),
        delivery:
          integerColumn(row, "issued") === 1 && email !== null
            ? Object.freeze({ email, resetId, code })
            : null,
      });
    },

    async cancelUndeliveredAccountReset(input, context) {
      requireDeterministicMode();
      requireInput(input);
      const resetId = requireResetId(input.resetId);
      if (typeof input.code !== "string") {
        throw new IdentityError("code must be a string.", "invalid-request");
      }
      const rows = await sql.query(
        `SELECT ${p}_cancel_undelivered_email_reset(
          $1::text, $2::uuid, $3::text, $4::timestamptz
        ) AS cancelled`,
        [
          serviceProfileId,
          resetId,
          hashAccountResetCode(serviceProfileId, resetId, reduceCode(input.code)),
          requestNow(context),
        ],
      );
      const row = optionalRow(rows);
      if (row === null) {
        throw new IdentityError("The reset could not be cancelled.", "invalid-request");
      }
      return Object.freeze({ cancelled: booleanColumn(row, "cancelled") });
    },

    async completeAccountReset(input, context) {
      requireEmailResetEnabled();
      requireInput(input);
      if (typeof input.username !== "string") {
        throw new IdentityError("username must be a string.", "invalid-request");
      }
      const usernameNormalized = deps.normalizeUsername(input.username);
      const newKey = canonicalNewKey(input.newKey);
      await deps.rateLimit(
        "accountChange",
        [deps.rateLimitIpHash(context), usernameNormalized],
        context,
      );
      if (typeof input.challengeId !== "string") {
        throw new IdentityError("challengeId must be a string.", "invalid-request");
      }
      const challenge = await deps.consumeChallenge(input.challengeId, "rotation", context);
      const resetId = canonicalResetId(input.resetId);
      if (challenge.usernameNormalized !== usernameNormalized || resetId === null) {
        throw resetRefused();
      }
      const signed = message(challenge, "email-reset", `email:${resetId}`, keyPrincipal(newKey));
      if (!verifyAccountChangeSignature(input.subjectSignature, signed, newKey.publicKeyBytes)) {
        throw resetRefused();
      }

      // The code decision, attempt count and successful completion share one
      // SQL statement. Its account lock orders them with new starts; no caller
      // can observe a fifth attempt before a valid completion is committed.
      const codeHash = hashAccountResetCode(serviceProfileId, resetId, reduceCode(input.code));
      const sessionTokenValue = generateSessionToken();
      const client = deps.sessionClientColumns(context);
      let rows: SqlRow[];
      try {
        rows = await sql.query(
          `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
                acct AS (
                  SELECT ${bare("a", ACCOUNT_COLUMNS)}, a.email_reset_enabled
                    FROM ${p}_accounts a
                   WHERE a.username_normalized = $2::text
                     AND a.service_profile_id = $3::text
                     AND EXISTS (
                       SELECT 1 FROM ${p}_account_resets r
                        WHERE r.id = $4::uuid AND r.account_id = a.id AND r.kind = 'email'
                     )
                     FOR NO KEY UPDATE OF a
                ),
                wallet AS (
                  SELECT w.id, w.account_id
                    FROM ${p}_account_wallets w, acct
                   WHERE w.account_id = acct.id
                     AND acct.status = 'active'
                     AND w.is_primary
                     AND w.public_key <> $7::text
                     AND NOT EXISTS (
                       SELECT 1 FROM ${p}_account_wallets other
                        WHERE other.account_id = acct.id AND other.id <> w.id
                     )
                     FOR UPDATE OF w
                ),
                wallet_ready AS (
                  SELECT count(*) = 1 AS ready FROM wallet
                ),
                reset_lock AS (
                  SELECT r.id
                    FROM ${p}_account_resets r, acct, wallet_ready
                   WHERE r.id = $4::uuid
                     AND r.account_id = acct.id
                     AND r.kind = 'email'
                     AND r.completed_at IS NULL
                     AND r.aborted_at IS NULL
                     AND r.expires_at > (SELECT at FROM clock)
                     AND r.attempts < ${String(ACCOUNT_RESET_MAX_ATTEMPTS)}
                     AND wallet_ready.ready IS NOT NULL
                   FOR UPDATE OF r
                ),
                attempted AS (
                  UPDATE ${p}_account_resets r
                     SET attempts = r.attempts + 1,
                         completed_at = CASE
                           WHEN r.code_hash = $13::text
                             AND acct.status = 'active'
                             AND wallet_ready.ready
                             AND ${emailCodeLive("r", "acct", "<")}
                           THEN (SELECT at FROM clock)
                           ELSE r.completed_at END
                    FROM acct, wallet_ready, reset_lock
                   WHERE r.id = reset_lock.id
                     AND r.account_id = acct.id
                     AND r.kind = 'email'
                     AND r.completed_at IS NULL
                     AND r.aborted_at IS NULL
                     AND r.expires_at > (SELECT at FROM clock)
                     AND r.attempts < ${String(ACCOUNT_RESET_MAX_ATTEMPTS)}
                   RETURNING r.id, r.account_id, r.code_hash = $13::text AS code_matched,
                             r.completed_at
                ),
                ok AS (
                  SELECT wallet.id AS wallet_id, attempted.account_id, attempted.id AS reset_id
                    FROM wallet, attempted
                   WHERE attempted.completed_at IS NOT NULL
                ),
                rotated AS (
                  UPDATE ${p}_account_wallets w
                     SET address = $5::text,
                         address_normalized = $6::text,
                         public_key = $7::text,
                         fingerprint = $8::text
                    FROM ok
                   WHERE w.id = ok.wallet_id
                   RETURNING ${bare("w", WALLET_COLUMNS)}
                ),
                completed AS (
                  SELECT id FROM attempted WHERE completed_at IS NOT NULL
                ),
                closed_resets AS (
                  UPDATE ${p}_account_resets r
                     SET aborted_at = (SELECT at FROM clock)
                    FROM ok
                   WHERE r.account_id = ok.account_id
                     AND r.id <> ok.reset_id
                     AND r.completed_at IS NULL
                     AND r.aborted_at IS NULL
                   RETURNING r.id
                ),
                targets AS (
                  SELECT s.id
                    FROM ${p}_sessions s, ok
                   WHERE s.account_id = ok.account_id
                     AND s.revoked_at IS NULL
                     AND s.expires_at > (SELECT at FROM clock)
                     AND (SELECT count(*) FROM completed) = 1
                     AND (SELECT count(*) FROM closed_resets) >= 0
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
                  SELECT ok.account_id, $9::text, clock.at,
                         date_trunc('milliseconds', clock.at + (interval '1 second' * $10::double precision)),
                         clock.at, $11::text, $12::text, $14::text
                    FROM ok, clock
                   WHERE (SELECT count(*) FROM revoked) >= 0
                  RETURNING ${SESSION_COLUMNS.join(", ")}
                ),
                logged AS (
                  INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                  SELECT ok.account_id, 'account.email-reset',
                         jsonb_build_object(
                           'method', 'email',
                           'revokedSessions', (SELECT count(*) FROM revoked),
                           'closedResets', (SELECT count(*) FROM closed_resets),
                           'sessionId', new_session.id
                         ),
                         (SELECT at FROM clock)
                    FROM ok, new_session
                   WHERE (SELECT count(*) FROM completed) = 1
                  RETURNING 1
                )
           SELECT clock.at AS occurred_at,
                  t.account_id AS attempt_account_id,
                  t.code_matched AS attempt_code_matched,
                  ${columns("a", ACCOUNT_COLUMNS, "account_")},
                  ${columns("r", WALLET_COLUMNS, "wallet_")},
                  ${columns("n", SESSION_COLUMNS, "session_")},
                  v.id AS revoked_id
             FROM clock
             LEFT JOIN attempted t ON true
             LEFT JOIN acct a ON a.id = t.account_id
             LEFT JOIN rotated r ON true
             LEFT JOIN new_session n ON true
             LEFT JOIN revoked v ON true
            ORDER BY v.id`,
          [
            requestNow(context),
            usernameNormalized,
            serviceProfileId,
            resetId,
            newKey.address,
            newKey.addressNormalized,
            newKey.publicKey,
            fingerprint(newKey.address),
            hashSessionToken(sessionTokenValue),
            config.sessionTtlSeconds,
            client.ipHash,
            client.userAgentHash,
            codeHash,
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
      if (first === null || optionalTextColumn(first, "session_id") === null) {
        if (first?.["attempt_code_matched"] !== true) {
          throw resetRefused();
        }
        // Only a matching emailed code may receive a specific key conflict.
        const accountId = textColumn(first, "attempt_account_id");
        const state = await enrolledKeyState(accountId);
        if (state.walletCount !== 1) {
          throw walletConflict();
        }
        if (state.primaryPublicKey === newKey.publicKey) {
          throw new IdentityError(
            "The new key is the key already enrolled; choose a new password.",
            "key-unchanged",
          );
        }
        // The setting turned off, the email changed, or the account suspended.
        throw resetRefused();
      }
      const account = mapAccount(first, "account_");
      const wallet = mapWallet(first, "wallet_");
      const revokedSessionIds = Object.freeze(
        rows
          .map((row) => optionalTextColumn(row, "revoked_id"))
          .filter((id): id is string => id !== null),
      );
      await notify("account.email-reset", account.id, instantColumn(first, "occurred_at"), context, {
        revokedSessions: revokedSessionIds.length,
      });
      return Object.freeze({
        account,
        wallets: Object.freeze([wallet]),
        session: Object.freeze({ session: mapSession(first, "session_"), token: sessionTokenValue }),
        revokedSessionIds,
      });
    },

    async startSignedInReset(token, context) {
      requireSignedInResetEnabled();
      const session = await readSessionContext(token, context);
      if (!session.active) {
        throw accountNotActive();
      }
      await deps.rateLimit(
        "accountChange",
        [deps.rateLimitIpHash(context), session.accountId],
        context,
      );
      const resetId = globalThis.crypto.randomUUID();
      const code = generateAccountResetCode();

      // A live reset blocks a new one (`reset-pending`); one that lapsed, or
      // whose session is gone, is closed so the live index admits the new
      // one. Two starts at once: the index refuses the second insert, and its
      // retry on a fresh snapshot finds the first one live. A lapsed row is
      // closed only if it is still open when its lock is granted, so a
      // completion or an abort that held it wins.
      //
      // Only the initiating session completes a reset, and a session's expiry
      // is fixed, so a reset without an emailed code is refused when the
      // session expires before the reset becomes available: it could never
      // complete. The session is not extended, which would lengthen a stolen
      // session's life.
      const rows = await retryUniqueViolation(() =>
        sql.query(
          `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
                caller AS (
                  SELECT s.id, s.account_id, s.expires_at
                    FROM ${p}_sessions s
                   WHERE s.token_hash = $2::text
                     AND s.revoked_at IS NULL
                     AND s.expires_at > (SELECT at FROM clock)
                ),
                acct AS (
                  SELECT a.id, a.email, a.email_verified_at, a.email_reset_enabled,
                         a.signed_in_reset_enabled, a.reset_generation
                    FROM ${p}_accounts a, caller
                   WHERE a.id = caller.account_id
                     AND a.service_profile_id = $3::text
                     AND a.status = 'active'
                     FOR SHARE OF a
                ),
                plan AS (
                  SELECT acct.id AS account_id, caller.id AS session_id,
                         caller.expires_at AS session_expires_at,
                         ($6::boolean
                           AND acct.email_reset_enabled
                           AND acct.email IS NOT NULL
                           AND acct.email_verified_at IS NOT NULL) AS coded,
                         clock.at + (interval '1 second' * $7::double precision) AS available_at
                    FROM acct, caller, clock
                ),
                open_resets AS (
                  SELECT r.id,
                         r.reset_generation = acct.reset_generation
                           AND r.expires_at > (SELECT at FROM clock)
                           AND EXISTS (
                             SELECT 1 FROM ${p}_sessions rs
                              WHERE rs.id = r.session_id
                                AND rs.revoked_at IS NULL
                                AND rs.expires_at > (SELECT at FROM clock)
                           ) AS live
                    FROM ${p}_account_resets r, acct
                   WHERE r.account_id = acct.id
                     AND acct.signed_in_reset_enabled
                     AND r.kind = 'signed-in'
                     AND r.completed_at IS NULL
                     AND r.aborted_at IS NULL
                ),
                lapsed AS (
                  UPDATE ${p}_account_resets r
                     SET aborted_at = (SELECT at FROM clock)
                    FROM open_resets o
                   WHERE r.id = o.id
                     AND NOT o.live
                     AND r.completed_at IS NULL
                     AND r.aborted_at IS NULL
                     AND NOT EXISTS (SELECT 1 FROM open_resets WHERE live)
                   RETURNING r.id
                ),
                issued AS (
                  INSERT INTO ${p}_account_resets (
                    id, account_id, kind, code_hash, attempts, session_id, reset_generation,
                    created_at, available_at, expires_at
                  )
                  SELECT $4::uuid, plan.account_id, 'signed-in',
                         CASE WHEN plan.coded THEN $5::text END,
                         0, plan.session_id, acct.reset_generation, clock.at, plan.available_at,
                         plan.available_at + (interval '1 second' * $8::double precision)
                    FROM plan, acct, clock
                   WHERE acct.signed_in_reset_enabled
                     AND (plan.coded OR plan.session_expires_at > plan.available_at)
                     AND NOT EXISTS (SELECT 1 FROM open_resets WHERE live)
                     AND (SELECT count(*) FROM lapsed) >= 0
                  RETURNING id, session_id, created_at, available_at, expires_at,
                            code_hash IS NOT NULL AS coded
                ),
                logged AS (
                  INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                  SELECT acct.id, 'account.signed-in-reset.start',
                         jsonb_build_object(
                           'codeIssued', issued.coded,
                           'closedResets', (SELECT count(*) FROM lapsed),
                           'sessionId', issued.session_id
                         ),
                         (SELECT at FROM clock)
                    FROM issued, acct
                  RETURNING 1
                )
           SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                  (SELECT count(*) FROM acct)::int AS account_active,
                  COALESCE((SELECT signed_in_reset_enabled FROM acct), false) AS setting_on,
                  EXISTS (SELECT 1 FROM open_resets WHERE live) AS live_pending,
                  COALESCE((SELECT coded OR session_expires_at > available_at FROM plan), true)
                    AS session_outlives_wait,
                  (SELECT session_expires_at FROM plan) AS session_expires_at,
                  (SELECT email FROM acct) AS email,
                  (SELECT at FROM clock) AS occurred_at,
                  i.id AS reset_id, i.created_at AS reset_created_at,
                  i.available_at AS reset_available_at, i.expires_at AS reset_expires_at,
                  i.session_id AS reset_session_id, COALESCE(i.coded, false) AS reset_code_usable
             FROM (SELECT 1) AS one
             LEFT JOIN issued i ON true`,
          [
            requestNow(context),
            hashSessionToken(token),
            serviceProfileId,
            resetId,
            hashAccountResetCode(serviceProfileId, resetId, code),
            config.accountSecurity.emailReset,
            SIGNED_IN_RESET_WAIT_SECONDS,
            SIGNED_IN_RESET_WINDOW_SECONDS,
          ],
        ),
      );
      const row = optionalRow(rows);
      if (row === null || integerColumn(row, "caller_found") === 0) {
        throw await deps.sessionFailure(hashSessionToken(token), requestNow(context));
      }
      if (integerColumn(row, "account_active") === 0) {
        throw accountNotActive();
      }
      if (!booleanColumn(row, "setting_on")) {
        throw new IdentityError(
          "The signed-in reset is turned off for this account.",
          "reset-setting-refused",
          { reason: "signed-in-reset-off" },
        );
      }
      if (optionalTextColumn(row, "reset_id") === null) {
        if (!booleanColumn(row, "live_pending") && !booleanColumn(row, "session_outlives_wait")) {
          throw new IdentityError(
            "This session expires before a reset started from it would become available, and only the session that starts a reset can complete it.",
            "reset-unavailable",
            {
              reason: "session-expires-first",
              sessionExpiresAt: instantColumn(row, "session_expires_at").toISOString(),
            },
          );
        }
        throw new IdentityError(
          "A password reset is already pending for this account; abort it first.",
          "reset-pending",
        );
      }
      const reset = mapPending(row, session.sessionId);
      const email = optionalTextColumn(row, "email");
      await notify("account.signed-in-reset.start", session.accountId, instantColumn(row, "occurred_at"), context, {
        availableAt: reset.availableAt,
      });
      return Object.freeze({
        reset,
        delivery: reset.codeUsable && email !== null ? Object.freeze({ email, code }) : null,
      });
    },

    async abortSignedInReset(token, context) {
      const tokenHash = hashSessionToken(sessionToken(token));
      const nowParam = requestNow(context);
      // Any live session of the account aborts, the initiating one included,
      // whatever the opt-ins: stopping a reset must always work.
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($2::timestamptz, now()) AS at),
              caller AS (
                SELECT s.id, s.account_id
                  FROM ${p}_sessions s
                 WHERE s.token_hash = $1::text
                   AND s.revoked_at IS NULL
                   AND s.expires_at > (SELECT at FROM clock)
              ),
              acct AS (
                SELECT a.id
                  FROM ${p}_accounts a, caller
                 WHERE a.id = caller.account_id
                   AND a.service_profile_id = $3::text
                   AND a.status = 'active'
                   FOR NO KEY UPDATE OF a
              ),
              fenced AS (
                UPDATE ${p}_accounts a
                   SET reset_generation = a.reset_generation + 1
                  FROM acct
                 WHERE a.id = acct.id
                 RETURNING a.id
              ),
              aborted AS (
                UPDATE ${p}_account_resets r
                   SET aborted_at = (SELECT at FROM clock)
                  FROM fenced
                 WHERE r.account_id = fenced.id
                   AND r.kind = 'signed-in'
                   AND r.completed_at IS NULL
                   AND r.aborted_at IS NULL
                   AND r.expires_at > (SELECT at FROM clock)
                 RETURNING r.id, r.account_id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT aborted.account_id, 'account.signed-in-reset.abort',
                       jsonb_build_object('abortedBy', 'session', 'sessionId', caller.id),
                       (SELECT at FROM clock)
                  FROM aborted, caller
                RETURNING 1
              )
         SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                (SELECT count(*) FROM acct)::int AS account_active,
                (SELECT account_id FROM caller) AS account_id,
                (SELECT count(*) FROM aborted)::int AS aborted,
                (SELECT at FROM clock) AS occurred_at`,
        [tokenHash, nowParam, serviceProfileId],
      );
      const row = optionalRow(rows);
      if (row === null || integerColumn(row, "caller_found") === 0) {
        throw await deps.sessionFailure(tokenHash, nowParam);
      }
      if (integerColumn(row, "account_active") === 0) {
        throw accountNotActive();
      }
      const aborted = integerColumn(row, "aborted") > 0;
      if (aborted) {
        await notify(
          "account.signed-in-reset.abort",
          textColumn(row, "account_id"),
          instantColumn(row, "occurred_at"),
          context,
          { abortedBy: "session" },
        );
      }
      return Object.freeze({ aborted });
    },

    async completeSignedInReset(token, input, context) {
      requireSignedInResetEnabled();
      requireInput(input);
      const newKey = canonicalNewKey(input.newKey);
      const resetId = requireResetId(input.resetId);
      if (input.code !== undefined && typeof input.code !== "string") {
        throw new IdentityError("code must be a string.", "invalid-request");
      }
      const { session, challenge, primary } = await prepareSignedChange(
        token,
        input.challengeId,
        context,
      );
      const signed = message(
        challenge,
        "signed-in-reset",
        `session-reset:${resetId}`,
        keyPrincipal(newKey),
      );
      if (!verifyAccountChangeSignature(input.subjectSignature, signed, newKey.publicKeyBytes)) {
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

      let codeHash: string | null = null;
      if (input.code !== undefined) {
        const attempt = optionalRow(
          await sql.query(
            `WITH clock AS (SELECT COALESCE($5::timestamptz, now()) AS at)
             UPDATE ${p}_account_resets r
                SET attempts = r.attempts + 1
              WHERE r.id = $1::uuid
                AND r.account_id = $2::uuid
                AND r.session_id = $3::uuid
                AND r.kind = 'signed-in'
                AND r.code_hash IS NOT NULL
                AND r.completed_at IS NULL
                AND r.aborted_at IS NULL
                AND r.expires_at > (SELECT at FROM clock)
                AND r.created_at + (interval '1 second' * $6::double precision) > (SELECT at FROM clock)
                AND r.attempts < $4::integer
              RETURNING r.code_hash`,
            [
              resetId,
              session.accountId,
              session.sessionId,
              ACCOUNT_RESET_MAX_ATTEMPTS,
              requestNow(context),
              ACCOUNT_RESET_CODE_TTL_SECONDS,
            ],
          ),
        );
        const provided = hashAccountResetCode(serviceProfileId, resetId, reduceCode(input.code));
        if (attempt === null || !constantTimeEqualHex(textColumn(attempt, "code_hash"), provided)) {
          throw codeRefused();
        }
        codeHash = provided;
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
                  SELECT a.id, a.email, a.email_verified_at, a.email_reset_enabled,
                         a.signed_in_reset_enabled, a.reset_generation
                    FROM ${p}_accounts a, caller
                   WHERE a.id = caller.account_id
                     AND a.service_profile_id = $3::text
                     AND a.status = 'active'
                     FOR SHARE OF a
                ),
                wallet AS (
                  SELECT w.id, w.account_id
                    FROM ${p}_account_wallets w, acct
                   WHERE w.account_id = acct.id
                     AND w.is_primary
                     AND w.public_key = $4::text
                     AND NOT EXISTS (
                       SELECT 1 FROM ${p}_account_wallets other
                        WHERE other.account_id = acct.id AND other.id <> w.id
                     )
                     FOR UPDATE OF w
                ),
                reset AS (
                  SELECT r.id
                    FROM ${p}_account_resets r, wallet, caller, acct
                   WHERE r.id = $5::uuid
                     AND r.account_id = wallet.account_id
                     AND r.kind = 'signed-in'
                     AND r.session_id = caller.id
                     AND r.reset_generation = acct.reset_generation
                     AND acct.signed_in_reset_enabled
                     AND r.completed_at IS NULL
                     AND r.aborted_at IS NULL
                     AND r.expires_at > (SELECT at FROM clock)
                     AND CASE WHEN $10::text IS NULL
                           THEN r.available_at <= (SELECT at FROM clock)
                           ELSE r.code_hash = $10::text AND ${emailCodeLive("r", "acct")}
                         END
                     FOR UPDATE OF r
                ),
                ok AS (
                  SELECT wallet.id AS wallet_id, wallet.account_id, reset.id AS reset_id,
                         caller.id AS caller_id
                    FROM wallet, reset, caller
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
                completed AS (
                  UPDATE ${p}_account_resets r
                     SET completed_at = (SELECT at FROM clock)
                    FROM ok
                   WHERE r.id = ok.reset_id
                   RETURNING r.id
                ),
                closed_resets AS (
                  UPDATE ${p}_account_resets r
                     SET aborted_at = (SELECT at FROM clock)
                    FROM ok
                   WHERE r.account_id = ok.account_id
                     AND r.id <> ok.reset_id
                     AND r.completed_at IS NULL
                     AND r.aborted_at IS NULL
                   RETURNING r.id
                ),
                targets AS (
                  SELECT s.id
                    FROM ${p}_sessions s, ok
                   WHERE s.account_id = ok.account_id
                     AND s.id <> ok.caller_id
                     AND s.revoked_at IS NULL
                     AND s.expires_at > (SELECT at FROM clock)
                     AND (SELECT count(*) FROM completed) >= 0
                     AND (SELECT count(*) FROM closed_resets) >= 0
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
                  SELECT ok.account_id, 'account.signed-in-reset',
                         jsonb_build_object(
                           'method', CASE WHEN $10::text IS NULL THEN 'wait' ELSE 'email-code' END,
                           'revokedSessions', (SELECT count(*) FROM revoked),
                           'closedResets', (SELECT count(*) FROM closed_resets),
                           'sessionId', ok.caller_id
                         ),
                         (SELECT at FROM clock)
                    FROM ok
                   WHERE (SELECT count(*) FROM completed) = 1
                  RETURNING 1
                )
           SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                  (SELECT count(*) FROM acct)::int AS account_active,
                  (SELECT count(*) FROM wallet)::int AS key_current,
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
            resetId,
            newKey.address,
            newKey.addressNormalized,
            newKey.publicKey,
            fingerprint(newKey.address),
            codeHash,
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
          if (integerColumn(first, "key_current") === 0) {
            const state = await enrolledKeyState(session.accountId);
            throw state.walletCount !== 1 ? walletConflict() : staleKey();
          }
          throw await whyResetUnavailable(resetId, session.accountId, session.sessionId, codeHash !== null, context);
        }
        return failGuardedStatement(first, token, context);
      }
      const wallet = mapWallet(first, "wallet_");
      const revokedSessionIds = Object.freeze(
        rows
          .map((row) => optionalTextColumn(row, "revoked_id"))
          .filter((id): id is string => id !== null),
      );
      await notify("account.signed-in-reset", wallet.accountId, instantColumn(first, "occurred_at"), context, {
        revokedSessions: revokedSessionIds.length,
      });
      return Object.freeze({ wallets: Object.freeze([wallet]), revokedSessionIds });
    },

    async verifyReauthentication(token, input, context) {
      requireInput(input);
      if (typeof input.label !== "string" || !hostLabelPattern.test(input.label)) {
        throw new IdentityError(
          "label must be 3-80 characters from [a-z0-9._:-], starting with a letter or digit.",
          "invalid-request",
        );
      }
      const label = input.label;
      const { challenge, primary } = await prepareSignedChange(token, input.challengeId, context);
      const signed = message(challenge, "reauthentication", keyPrincipal(primary), `host:${label}`);
      if (!verifyAccountChangeSignature(input.authorizerSignature, signed, primary.publicKeyBytes)) {
        throw badSignature();
      }
      // Re-checks the session, the status and the key under their locks, and
      // writes the audit row. Nothing else changes.
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
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT keyed.account_id, 'account.reauth',
                       jsonb_build_object('label', $5::text, 'sessionId', caller.id),
                       (SELECT at FROM clock)
                  FROM keyed, caller
                RETURNING account_id, created_at
              )
         SELECT (SELECT count(*) FROM caller)::int AS caller_found,
                (SELECT count(*) FROM acct)::int AS account_active,
                (SELECT count(*) FROM keyed)::int AS key_current,
                (SELECT id FROM caller) AS session_id,
                l.account_id, l.created_at AS verified_at
           FROM (SELECT 1) AS one
           LEFT JOIN logged l ON true`,
        [requestNow(context), hashSessionToken(token), serviceProfileId, primary.publicKey, label],
      );
      const row = optionalRow(rows);
      if (row === null || optionalTextColumn(row, "account_id") === null) {
        return failGuardedStatement(row, token, context);
      }
      return Object.freeze({
        accountId: textColumn(row, "account_id"),
        sessionId: textColumn(row, "session_id"),
        label,
        verifiedAt: instantColumn(row, "verified_at"),
      });
    },
  };

  /** Why a signed-in completion found no reset to complete, read after the fact. */
  async function whyResetUnavailable(
    resetId: string,
    accountId: string,
    sessionId: string,
    viaCode: boolean,
    context: RequestContext | undefined,
  ): Promise<IdentityError> {
    const row = optionalRow(
      await sql.query(
        `SELECT r.available_at,
                r.completed_at IS NULL AND r.aborted_at IS NULL
                  AND r.reset_generation = a.reset_generation
                  AND r.expires_at > COALESCE($4::timestamptz, now()) AS live
           FROM ${p}_account_resets r
           JOIN ${p}_accounts a ON a.id = r.account_id
          WHERE r.id = $1::uuid
            AND r.account_id = $2::uuid
            AND r.session_id = $3::uuid
            AND r.kind = 'signed-in'`,
        [resetId, accountId, sessionId, requestNow(context)],
      ),
    );
    if (row === null || !booleanColumn(row, "live")) {
      return resetUnavailable();
    }
    if (viaCode) {
      return codeRefused();
    }
    const availableAt = optionalInstantColumn(row, "available_at");
    return availableAt === null ? resetUnavailable() : resetUnavailable(availableAt);
  }

  return Object.freeze(operations);
}
