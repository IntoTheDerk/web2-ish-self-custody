/**
 * Row mapping and request helpers shared by the identity service's statement
 * modules (package-internal; nothing here is exported from the package).
 */
import { normalizeEmail as normalizeCoreEmail } from "../accountChange.js";
import { IdentityError } from "./errors.js";
import {
  instantColumn,
  optionalInstantColumn,
  optionalTextColumn,
  textColumn,
  type SqlRow,
} from "./sql.js";
import type {
  ChallengePurpose,
  IdentityAccount,
  IdentitySession,
  IdentityWallet,
  RequestContext,
} from "./types.js";

/** A challenge row as the atomic consumption returned it. */
export type ConsumedChallenge = Readonly<{
  id: string;
  purpose: ChallengePurpose;
  usernameNormalized: string;
  nonceHex: string;
  expiresAt: Date;
}>;

export const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

const MAX_CONTEXT_HASH_LENGTH = 128;

/**
 * The core's `normalizeEmail`, raising the service's `invalid-email`. One
 * implementation serves registration, `updateAccount`, `changeEmail` and the
 * browser that builds an `email:` subject, so they cannot disagree.
 */
export function normalizeEmail(value: string): string {
  try {
    return normalizeCoreEmail(value);
  } catch {
    throw new IdentityError("email is not a valid address.", "invalid-email");
  }
}

export type MissingIdentifierCode =
  | "account-not-found"
  | "challenge-not-found"
  | "email-verification-failed";

/**
 * Identifiers are shape-checked before reaching a `::uuid` cast, so a
 * malformed id surfaces as its caller's own "not found" rather than as a
 * PostgreSQL 22P02 leaking out of the driver.
 */
export function assertUuid(value: string, code: MissingIdentifierCode): string {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!uuidPattern.test(normalized)) {
    throw new IdentityError("Malformed identifier.", code);
  }
  return normalized;
}

export function booleanColumn(row: SqlRow, column: string): boolean {
  const value = row[column];
  if (typeof value === "boolean") {
    return value;
  }
  if (value === "t" || value === "true") {
    return true;
  }
  if (value === "f" || value === "false") {
    return false;
  }
  throw new TypeError(`Expected boolean column "${column}".`);
}

export function accountStatus(value: string): "active" | "suspended" {
  if (value === "active" || value === "suspended") {
    return value;
  }
  throw new IdentityError("Unknown account status.", "invalid-service-profile");
}

export function walletCurve(value: string): "ed25519" {
  if (value === "ed25519") {
    return value;
  }
  throw new IdentityError("Unknown wallet curve.", "invalid-service-profile");
}

/** Context hashes arrive pre-hashed; the service never sees a raw IP. */
export function sanitizeContextHash(value: string | undefined): string | null {
  if (value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_CONTEXT_HASH_LENGTH) {
    return null;
  }
  return trimmed;
}

export function requestNow(context: RequestContext | undefined): string | null {
  const now = context?.now;
  return now === undefined ? null : now.toISOString();
}

export function metadataJson(
  metadata: Readonly<Record<string, string | number | boolean | null>>,
): string {
  return JSON.stringify(metadata);
}

export function sqlStateOf(error: unknown): string | null {
  if (typeof error !== "object" || error === null) {
    return null;
  }
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

export function mapAccount(row: SqlRow, prefix: string): IdentityAccount {
  return Object.freeze({
    id: textColumn(row, `${prefix}id`),
    serviceProfileId: textColumn(row, `${prefix}service_profile_id`),
    usernameNormalized: textColumn(row, `${prefix}username_normalized`),
    displayName: optionalTextColumn(row, `${prefix}display_name`),
    email: optionalTextColumn(row, `${prefix}email`),
    emailVerifiedAt: optionalInstantColumn(row, `${prefix}email_verified_at`),
    status: accountStatus(textColumn(row, `${prefix}status`)),
    createdAt: instantColumn(row, `${prefix}created_at`),
    updatedAt: instantColumn(row, `${prefix}updated_at`),
  });
}

export function mapWallet(row: SqlRow, prefix: string): IdentityWallet {
  return Object.freeze({
    id: textColumn(row, `${prefix}id`),
    accountId: textColumn(row, `${prefix}account_id`),
    serviceProfileId: textColumn(row, `${prefix}service_profile_id`),
    profileId: textColumn(row, `${prefix}profile_id`),
    codecId: textColumn(row, `${prefix}codec_id`),
    curve: walletCurve(textColumn(row, `${prefix}curve`)),
    applicationId: textColumn(row, `${prefix}application_id`),
    networkId: textColumn(row, `${prefix}network_id`),
    address: textColumn(row, `${prefix}address`),
    addressNormalized: textColumn(row, `${prefix}address_normalized`),
    publicKey: textColumn(row, `${prefix}public_key`),
    fingerprint: textColumn(row, `${prefix}fingerprint`),
    isPrimary: booleanColumn(row, `${prefix}is_primary`),
    createdAt: instantColumn(row, `${prefix}created_at`),
  });
}

export function mapSession(row: SqlRow, prefix: string): IdentitySession {
  return Object.freeze({
    id: textColumn(row, `${prefix}id`),
    accountId: textColumn(row, `${prefix}account_id`),
    issuedAt: instantColumn(row, `${prefix}issued_at`),
    expiresAt: instantColumn(row, `${prefix}expires_at`),
    lastSeenAt: instantColumn(row, `${prefix}last_seen_at`),
  });
}
