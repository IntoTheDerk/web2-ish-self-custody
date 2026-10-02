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
  | "rate-limited"
  | "service-profile-missing"
  | "session-expired"
  | "session-not-found"
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
  "rate-limited": 429,
  "service-profile-missing": 503,
  "session-expired": 401,
  "session-not-found": 401,
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
