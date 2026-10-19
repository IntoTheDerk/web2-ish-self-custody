export type IdentityErrorCode =
  | "account-exists"
  | "account-not-found"
  | "challenge-consumed"
  | "challenge-expired"
  | "challenge-not-found"
  | "email-delivery-failed"
  | "email-verification-expired"
  | "email-verification-failed"
  | "invalid-address"
  | "invalid-email"
  | "invalid-display-name"
  | "invalid-public-key"
  | "invalid-purpose"
  | "invalid-request"
  | "invalid-service-profile"
  | "invalid-signature"
  | "invalid-username"
  | "key-unchanged"
  | "rate-limited"
  | "reset-pending"
  | "reset-setting-refused"
  | "reset-unavailable"
  | "service-profile-missing"
  | "session-expired"
  | "session-not-found"
  | "stale-key"
  | "wallet-mismatch"
  | "wallet-conflict"
  | "wallet-registered";

const statusByCode: Readonly<Record<IdentityErrorCode, number>> = Object.freeze({
  "account-exists": 409,
  "account-not-found": 404,
  "challenge-consumed": 409,
  "challenge-expired": 410,
  "challenge-not-found": 404,
  "email-delivery-failed": 502,
  "email-verification-expired": 410,
  "email-verification-failed": 400,
  "invalid-address": 400,
  "invalid-email": 400,
  "invalid-display-name": 400,
  "invalid-public-key": 400,
  "invalid-purpose": 400,
  "invalid-request": 400,
  "invalid-service-profile": 500,
  "invalid-signature": 401,
  "invalid-username": 400,
  // A rotation or recovery that names the key already enrolled. Only a caller
  // with a session or a recovery token gets this far, so it reveals nothing.
  "key-unchanged": 409,
  "rate-limited": 429,
  // A signed-in reset of the account is pending: a second one cannot start,
  // and the session that started it cannot revoke the account's other
  // sessions, which would hide the reset from them. Needs a session.
  "reset-pending": 409,
  // A reset setting refused by its rule: account recovery by email needs a
  // verified email, and the signed-in reset can be turned off only while
  // another reset method is set. Needs a session and the key's signature.
  "reset-setting-refused": 409,
  // The caller's signed-in reset is not there to complete (aborted, expired,
  // completed, another session's) or not available yet; or a start whose
  // session would expire before the reset became available. Needs a session.
  "reset-unavailable": 409,
  "service-profile-missing": 503,
  "session-expired": 401,
  "session-not-found": 401,
  // The enrolled key changed between the read that built the signed message
  // and the statement that would act on it: another change won.
  "stale-key": 409,
  "wallet-mismatch": 409,
  "wallet-conflict": 409,
  "wallet-registered": 409,
});

/**
 * Every failure the identity service raises. `code` is stable API surface;
 * `message` is operator-facing and must never contain credential material.
 */
export class IdentityError extends Error {
  readonly status: number;

  constructor(
    message: string,
    readonly code: IdentityErrorCode,
    readonly details?: Readonly<Record<string, string | number>>,
  ) {
    super(message);
    this.name = "IdentityError";
    this.status = statusByCode[code];
  }
}

export function identityErrorStatus(code: IdentityErrorCode): number {
  return statusByCode[code];
}

/**
 * Codes that must not tell an unauthenticated caller whether an account
 * exists. Routes collapse these into one generic response.
 */
export const enumerationSensitiveCodes: ReadonlySet<IdentityErrorCode> =
  Object.freeze(
    new Set<IdentityErrorCode>([
      "account-not-found",
      "invalid-signature",
      "wallet-mismatch",
    ]),
  );
