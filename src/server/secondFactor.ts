/**
 * The optional sign-in second factor (package-internal; the methods are
 * exposed through `IdentityService`).
 *
 * With `IdentityServiceConfig.secondFactor` set, every step that would issue
 * a session after a password proof (`login`, `completeAccountReset`,
 * `completeRecovery`) first asks the host's `required(accountId, context)`.
 * When it answers true, the step issues a second-factor ticket instead of the
 * session, in the statement that would have inserted the session, and
 * `completeSecondFactor` issues the session once the host's `verify` answers
 * `"ok"`, in the statement that consumes the ticket. Without the option none
 * of this runs and every statement is the one earlier releases ran.
 *
 * A ticket: 32 random bytes (base64url), stored as a domain-separated SHA-256
 * only; bound to its account, to the challenge whose proof it continues (one
 * ticket per challenge), and to the enrolled key that proof was for (the key
 * that signed the login challenge, or the new key a reset or recovery
 * enrolled); valid 5 minutes and 5 attempts. Each attempt is reserved in its
 * own single-row UPDATE before `verify` runs, so parallel guesses cannot share
 * one. The fifth failed attempt kills the ticket.
 *
 * Every submitted code also reserves a unit of the account's `login-account`
 * bucket (25 an hour, keyed by the account alone) before `verify` runs, and
 * gives it back when the verdict is `ok` or `locked`: wrong codes and
 * verifier failures stay counted, across all tickets and purposes and
 * whatever the caller's address. A full bucket refuses every submission on
 * every outstanding ticket of the account (`rate-limited`), so abandoning a
 * ticket before its fifth attempt gains nothing; a login or recovery that
 * needs the factor also checks it before it issues a ticket. The email reset
 * does not check it at issuance (see `prepareTicket`); its tickets are bound
 * at submission like any other.
 *
 * Lock order (that of `accountChanges.ts`): issuing a login ticket takes the
 * account FOR SHARE and the enrolled key FOR SHARE, then inserts; redeeming
 * takes the account FOR NO KEY UPDATE, the enrolled key FOR SHARE, then the
 * ticket (its UPDATE), then inserts the session and fences the resets as
 * login does. An attempt reservation locks the ticket row alone and waits on
 * nothing while holding it.
 */
import { IdentityError } from "./errors.js";
import { mapAccount, mapSession, requestNow } from "./records.js";
import {
  instantColumn,
  integerColumn,
  optionalRow,
  requireSingleRow,
  textColumn,
  type SqlDriver,
} from "./sql.js";
import {
  generateSecondFactorTicket,
  generateSessionToken,
  hashSecondFactorTicket,
  hashSessionToken,
} from "./tokens.js";
import type {
  IdentityAccount,
  IssuedSecondFactorTicket,
  IssuedSession,
  RequestContext,
  ResolvedIdentityServiceConfig,
  SecondFactorCompletionInput,
  SecondFactorPurpose,
  SecondFactorVerdict,
} from "./types.js";

/** A second-factor ticket is good for 5 minutes ... */
export const SECOND_FACTOR_TICKET_TTL_SECONDS = 300;
/** ... and 5 attempts. */
export const SECOND_FACTOR_MAX_ATTEMPTS = 5;
/** The longest code passed to `verify`; anything longer is refused unseen. */
const MAX_CODE_LENGTH = 64;
const ticketPattern = /^[A-Za-z0-9_-]{43}$/u;

export type SecondFactorDependencies = Readonly<{
  sql: SqlDriver;
  config: ResolvedIdentityServiceConfig;
  p: string;
  sessionClientColumns: (
    context: RequestContext | undefined,
  ) => Readonly<{ ipHash: string | null; userAgentHash: string | null; clientLabel: string | null }>;
  /** Throws `rate-limited` while the account's `login-account` bucket is full. */
  checkAccountLimit: (accountId: string, context: RequestContext | undefined) => Promise<void>;
  /**
   * Counts one submitted code against the account's `login-account` bucket,
   * throwing `rate-limited` past its limit, and answers the window it counted
   * in for `releaseAccountGuess`.
   */
  reserveAccountGuess: (accountId: string, context: RequestContext | undefined) => Promise<string>;
  /** Gives back a unit `reserveAccountGuess` counted, in that window only. */
  releaseAccountGuess: (accountId: string, windowKey: string) => Promise<void>;
}>;

/**
 * What a reset or recovery statement needs to insert a ticket in place of its
 * session: the secret to return and its digest, and the challenge it binds.
 */
export type PendingTicket = Readonly<{
  ticket: string;
  ticketHash: string;
  challengeId: string;
}>;

export type SecondFactorGate = Readonly<{
  /** True when a configured `required` did not answer `false`. */
  required(
    accountId: string,
    purpose: SecondFactorPurpose,
    context: RequestContext | undefined,
  ): Promise<boolean>;
  /**
   * A fresh ticket for a gated reset or recovery, after the account-limit
   * check when `checkLimit` is set. The email reset skips the check: its
   * caller is not authenticated until the statement checks the code, and a
   * refusal there would tell it that the account exists.
   */
  prepareTicket(
    accountId: string,
    challengeId: string,
    context: RequestContext | undefined,
    checkLimit: boolean,
  ): Promise<PendingTicket>;
  /** Issues a login ticket while `publicKey` is still enrolled. */
  issueLoginTicket(
    accountId: string,
    challengeId: string,
    publicKey: string,
    context: RequestContext | undefined,
  ): Promise<IssuedSecondFactorTicket>;
  completeSecondFactor(
    input: SecondFactorCompletionInput,
    context: RequestContext | undefined,
  ): Promise<{ account: IdentityAccount; session: IssuedSession; purpose: SecondFactorPurpose }>;
}>;

function ticketRefused(): IdentityError {
  return new IdentityError(
    "This sign-in step has expired or is no longer valid; sign in again.",
    "second-factor-ticket-invalid",
  );
}

function assertPurpose(value: string): SecondFactorPurpose {
  if (value === "login" || value === "email-reset" || value === "recovery") {
    return value;
  }
  throw new IdentityError("Unknown second-factor ticket purpose.", "invalid-service-profile");
}

/** Anything but the two other verdicts is `invalid`: a verifier bug never signs in. */
function verdictOf(value: unknown): SecondFactorVerdict {
  return value === "ok" || value === "locked" ? value : "invalid";
}

export function secondFactorGate(deps: SecondFactorDependencies): SecondFactorGate {
  const { sql, config, p } = deps;
  const serviceProfileId = config.serviceProfileId;
  const options = config.secondFactor ?? null;

  const gate: SecondFactorGate = {
    async required(accountId, purpose, context) {
      if (options === null) {
        return false;
      }
      const answer: unknown = await options.required(
        accountId,
        Object.freeze({ ...(context ?? {}), purpose }),
      );
      return answer !== false;
    },

    async prepareTicket(accountId, challengeId, context, checkLimit) {
      if (checkLimit) {
        await deps.checkAccountLimit(accountId, context);
      }
      const ticket = generateSecondFactorTicket();
      return Object.freeze({
        ticket,
        ticketHash: hashSecondFactorTicket(serviceProfileId, ticket),
        challengeId,
      });
    },

    async issueLoginTicket(accountId, challengeId, publicKey, context) {
      await deps.checkAccountLimit(accountId, context);
      const ticket = generateSecondFactorTicket();
      const client = deps.sessionClientColumns(context);
      // Like the login's session insert: the account must still be active and
      // the key that signed the challenge still enrolled.
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
              acct AS (
                SELECT a.id
                  FROM ${p}_accounts a
                 WHERE a.id = $2::uuid
                   AND a.service_profile_id = $3::text
                   AND a.status = 'active'
                   FOR SHARE OF a
              ),
              keyed AS (
                SELECT w.account_id
                  FROM ${p}_account_wallets w, acct
                 WHERE w.account_id = acct.id AND w.public_key = $4::text
                 FOR SHARE OF w
              ),
              issued AS (
                INSERT INTO ${p}_second_factor_tickets (
                  account_id, ticket_hash, challenge_id, public_key, purpose,
                  ip_hash, user_agent_hash, client_label, created_at, expires_at
                )
                SELECT keyed.account_id, $5::text, $6::uuid, $4::text, 'login',
                       $7::text, $8::text, $9::text, clock.at,
                       date_trunc('milliseconds', clock.at + (interval '1 second' * $10::double precision))
                  FROM clock, keyed
                RETURNING expires_at
              )
         SELECT expires_at FROM issued`,
        [
          requestNow(context),
          accountId,
          serviceProfileId,
          publicKey,
          hashSecondFactorTicket(serviceProfileId, ticket),
          challengeId,
          client.ipHash,
          client.userAgentHash,
          client.clientLabel,
          SECOND_FACTOR_TICKET_TTL_SECONDS,
        ],
      );
      const row = requireSingleRow(
        rows,
        () =>
          new IdentityError(
            "Challenge signature did not verify against any registered wallet.",
            "invalid-signature",
          ),
      );
      return Object.freeze({
        secondFactor: "totp" as const,
        ticket,
        expiresAt: instantColumn(row, "expires_at"),
      });
    },

    async completeSecondFactor(input, context) {
      if (options === null) {
        throw new IdentityError("This service has no second sign-in factor.", "invalid-request");
      }
      if (typeof input !== "object" || input === null) {
        throw new IdentityError("Expected an object.", "invalid-request");
      }
      if (typeof input.ticket !== "string" || !ticketPattern.test(input.ticket)) {
        throw ticketRefused();
      }
      if (typeof input.code !== "string" || input.code.length === 0 || input.code.length > MAX_CODE_LENGTH) {
        throw new IdentityError(
          `code must be a string of 1-${MAX_CODE_LENGTH} characters.`,
          "invalid-request",
        );
      }
      const ticketHash = hashSecondFactorTicket(serviceProfileId, input.ticket);
      const nowParam = requestNow(context);

      // The attempt is reserved before the host's verifier runs, in one
      // single-row statement, so a burst of parallel guesses cannot share an
      // attempt; a success spends the attempt it reserved.
      const reserved = optionalRow(
        await sql.query(
          `UPDATE ${p}_second_factor_tickets t
              SET attempts = t.attempts + 1
             FROM ${p}_accounts a
            WHERE t.ticket_hash = $1::text
              AND a.id = t.account_id
              AND a.service_profile_id = $2::text
              AND t.consumed_at IS NULL
              AND t.expires_at > COALESCE($3::timestamptz, now())
              AND t.attempts < $4::integer
            RETURNING t.id, t.account_id, t.purpose, t.attempts`,
          [ticketHash, serviceProfileId, nowParam, SECOND_FACTOR_MAX_ATTEMPTS],
        ),
      );
      if (reserved === null) {
        throw ticketRefused();
      }
      const ticketId = textColumn(reserved, "id");
      const accountId = textColumn(reserved, "account_id");
      const purpose = assertPurpose(textColumn(reserved, "purpose"));
      const attempts = integerColumn(reserved, "attempts");

      // The account-wide bound, after the ticket proved to be live (so only
      // a ticket holder reaches it, and a refusal reveals nothing) and before
      // the verifier sees the code. A refusal here spends the ticket attempt.
      const windowKey = await deps.reserveAccountGuess(accountId, context);
      const verdict = verdictOf(await options.verify(accountId, ticketId, input.code));
      if (verdict !== "invalid") {
        // Not a wrong code: the host either accepted it or did not test it.
        await deps.releaseAccountGuess(accountId, windowKey);
      }
      if (verdict !== "ok") {
        const exhausted = verdict === "invalid" && attempts >= SECOND_FACTOR_MAX_ATTEMPTS;
        await sql.query(
          `INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
           SELECT t.account_id, 'session.second-factor-failed',
                  jsonb_build_object(
                    'purpose', t.purpose,
                    'reason', $2::text,
                    'attempts', t.attempts,
                    'exhausted', $3::boolean
                  ),
                  COALESCE($4::timestamptz, now())
             FROM ${p}_second_factor_tickets t
            WHERE t.id = $1::uuid`,
          [ticketId, verdict, exhausted, nowParam],
        );
        if (verdict === "locked") {
          throw new IdentityError(
            "The second factor is locked for this account; try again later.",
            "second-factor-locked",
          );
        }
        if (exhausted) {
          throw ticketRefused();
        }
        throw new IdentityError("The code is not valid.", "second-factor-invalid", {
          attemptsRemaining: SECOND_FACTOR_MAX_ATTEMPTS - attempts,
        });
      }

      // The session, in the statement that consumes the ticket, as the login
      // would have issued it: the account still active, the bound key still
      // enrolled, the account's reset generation advanced and its pending
      // signed-in reset aborted, since the sign-in is now complete.
      const token = generateSessionToken();
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
              pending AS (
                SELECT t.account_id, t.public_key
                  FROM ${p}_second_factor_tickets t
                 WHERE t.id = $2::uuid AND t.ticket_hash = $3::text
              ),
              acct AS (
                SELECT a.id
                  FROM ${p}_accounts a, pending
                 WHERE a.id = pending.account_id
                   AND a.service_profile_id = $4::text
                   AND a.status = 'active'
                   FOR NO KEY UPDATE OF a
              ),
              keyed AS (
                SELECT w.account_id
                  FROM ${p}_account_wallets w, acct, pending
                 WHERE w.account_id = acct.id AND w.public_key = pending.public_key
                 FOR SHARE OF w
              ),
              consumed AS (
                UPDATE ${p}_second_factor_tickets t
                   SET consumed_at = (SELECT at FROM clock)
                  FROM keyed
                 WHERE t.id = $2::uuid
                   AND t.ticket_hash = $3::text
                   AND t.account_id = keyed.account_id
                   AND t.consumed_at IS NULL
                   AND t.expires_at > (SELECT at FROM clock)
                   AND t.attempts <= $6::integer
                 RETURNING t.account_id, t.purpose, t.ip_hash, t.user_agent_hash, t.client_label
              ),
              new_session AS (
                INSERT INTO ${p}_sessions (
                  account_id, token_hash, issued_at, expires_at, last_seen_at,
                  ip_hash, user_agent_hash, client_label
                )
                SELECT consumed.account_id, $5::text, clock.at,
                       date_trunc('milliseconds', clock.at + (interval '1 second' * $7::double precision)),
                       clock.at, consumed.ip_hash, consumed.user_agent_hash, consumed.client_label
                  FROM clock, consumed
                RETURNING id, account_id, issued_at, expires_at, last_seen_at
              ),
              fenced AS (
                UPDATE ${p}_accounts a
                   SET reset_generation = a.reset_generation + 1
                  FROM new_session
                 WHERE a.id = new_session.account_id
                 RETURNING a.id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT new_session.account_id, 'session.second-factor-ok',
                       jsonb_build_object('purpose', consumed.purpose, 'sessionId', new_session.id),
                       clock.at
                  FROM clock, new_session, consumed
                RETURNING 1
              ),
              logged_login AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT new_session.account_id, 'account.login',
                       jsonb_build_object(
                         'profileId', $8::text,
                         'challengePurpose', 'login',
                         'secondFactor', true,
                         'sessionId', new_session.id
                       ),
                       clock.at
                  FROM clock, new_session, consumed
                 WHERE consumed.purpose = 'login'
                RETURNING 1
              ),
              aborted_resets AS (
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
              logged_abort AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT aborted_resets.account_id, 'account.signed-in-reset.abort',
                       jsonb_build_object('abortedBy', 'login', 'sessionId', new_session.id),
                       (SELECT at FROM clock)
                  FROM aborted_resets, new_session
                RETURNING 1
              )
         SELECT n.id AS session_id, n.account_id AS session_account_id,
                n.issued_at AS session_issued_at, n.expires_at AS session_expires_at,
                n.last_seen_at AS session_last_seen_at,
                a.id AS account_id, a.service_profile_id AS account_service_profile_id,
                a.username_normalized AS account_username_normalized,
                a.display_name AS account_display_name, a.email AS account_email,
                a.email_verified_at AS account_email_verified_at,
                a.status AS account_status, a.created_at AS account_created_at,
                a.updated_at AS account_updated_at
           FROM new_session n
           JOIN ${p}_accounts a ON a.id = n.account_id`,
        [
          nowParam,
          ticketId,
          ticketHash,
          serviceProfileId,
          hashSessionToken(token),
          SECOND_FACTOR_MAX_ATTEMPTS,
          config.sessionTtlSeconds,
          config.profile.id,
        ],
      );
      const row = optionalRow(rows);
      if (row === null) {
        // Expired, replayed by a concurrent completion, or the account was
        // suspended or deleted, or its key replaced, since the ticket was
        // issued.
        throw ticketRefused();
      }
      return Object.freeze({
        account: mapAccount(row, "account_"),
        session: Object.freeze({ session: mapSession(row, "session_"), token }),
        purpose,
      });
    },
  };
  return Object.freeze(gate);
}

