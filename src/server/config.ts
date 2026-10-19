import { assertCodecRoundTrip } from "../codec.js";
import type { DerivationProfile } from "../profile.js";
import { signInEd25519Codec } from "../signIn.js";
import { IdentityError } from "./errors.js";
import type {
  IdentityServiceConfig,
  ResolvedIdentityServiceConfig,
  SecurityEventHook,
} from "./types.js";

const defaults = Object.freeze({
  tablePrefix: "w2sc",
  sessionTtlSeconds: 60 * 60 * 24 * 14,
  challengeTtlSeconds: 300,
  emailVerificationTtlSeconds: 900,
  emailVerificationMaxAttempts: 5,
  requireVerifiedEmail: false,
  walletMode: "service-deterministic" as const,
  storeSessionClientHashes: true,
  accountSecurity: Object.freeze({
    signInKeyRotation: false,
    recoveryKeys: false,
    emailReset: false,
    signedInReset: false,
  }),
  onSecurityEvent: null,
  auditRetentionDays: null,
});

/** 100 years: a bound that refuses a typo without limiting any real policy. */
const MAX_AUDIT_RETENTION_DAYS = 36_500;

function assertPositiveInteger(value: number, field: string, max: number): number {
  if (!Number.isInteger(value) || value <= 0 || value > max) {
    throw new IdentityError(
      `${field} must be an integer between 1 and ${max}.`,
      "invalid-service-profile",
    );
  }
  return value;
}

/**
 * `adoptPublicSaltHex` was removed in v0.9.0. It is refused rather than
 * ignored: a caller still passing it expects its first provisioning to insert
 * that salt, and silently minting a fresh one instead would move every user
 * into a new wallet namespace. The type no longer has the field, but a spread
 * or an untyped caller can still deliver it.
 */
function assertNoRemovedOptions(config: IdentityServiceConfig): void {
  if ((config as Readonly<Record<string, unknown>>)["adoptPublicSaltHex"] !== undefined) {
    throw new IdentityError(
      "adoptPublicSaltHex was removed in v0.9.0; the salt is always minted by the database on first provisioning.",
      "invalid-service-profile",
    );
  }
}

/**
 * A service exists to own and publish a salt, so only the `external-32` policy
 * is serviceable. A profile that derives its own salt from the username has
 * nothing for a server to hold, and configuring one here would publish a salt
 * clients must ignore.
 */
function assertServiceableProfile(profile: DerivationProfile): DerivationProfile {
  if (typeof profile !== "object" || profile === null || typeof profile.id !== "string") {
    throw new IdentityError(
      "config.profile must be a derivation profile object.",
      "invalid-service-profile",
    );
  }
  if (profile.saltPolicy !== "external-32") {
    throw new IdentityError(
      `Profile "${profile.id}" uses the "${profile.saltPolicy}" salt policy; a service requires "external-32".`,
      "invalid-service-profile",
    );
  }

  // A codec that cannot decode what it encodes would let the service enroll
  // wallets it can never authenticate again. Cheap to check once at startup.
  try {
    assertCodecRoundTrip(profile.codec, new Uint8Array(32).fill(7));
  } catch {
    throw new IdentityError(
      `Identity codec "${profile.codec.id}" does not round-trip its own encoding.`,
      "invalid-service-profile",
    );
  }

  return profile;
}

/**
 * A misspelt or stringly-typed `"false"` would otherwise read as truthy and
 * keep storing the hashes a deployment asked to stop storing.
 */
function optionalBoolean(value: unknown, field: string, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "boolean") {
    throw new IdentityError(`${field} must be a boolean.`, "invalid-service-profile");
  }
  return value;
}

/**
 * Each opt-in is a strict boolean, and an unknown key is refused: a misspelt
 * opt-in must not leave a deployment believing it turned something on.
 */
const accountSecurityKeys: readonly string[] = Object.freeze([
  "signInKeyRotation",
  "recoveryKeys",
  "emailReset",
  "signedInReset",
]);

function resolveAccountSecurity(
  value: unknown,
): ResolvedIdentityServiceConfig["accountSecurity"] {
  if (value === undefined) {
    return defaults.accountSecurity;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new IdentityError("accountSecurity must be an object.", "invalid-service-profile");
  }
  const record = value as Readonly<Record<string, unknown>>;
  for (const key of Object.keys(record)) {
    if (!accountSecurityKeys.includes(key)) {
      throw new IdentityError(
        `accountSecurity accepts only ${accountSecurityKeys.join(", ")}.`,
        "invalid-service-profile",
      );
    }
  }
  return Object.freeze({
    signInKeyRotation: optionalBoolean(
      record["signInKeyRotation"],
      "accountSecurity.signInKeyRotation",
      false,
    ),
    recoveryKeys: optionalBoolean(record["recoveryKeys"], "accountSecurity.recoveryKeys", false),
    emailReset: optionalBoolean(record["emailReset"], "accountSecurity.emailReset", false),
    signedInReset: optionalBoolean(record["signedInReset"], "accountSecurity.signedInReset", false),
  });
}

/** `null` is accepted as unset, so a resolved config resolves to itself. */
function resolveSecurityEventHook(value: unknown): SecurityEventHook | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "function") {
    throw new IdentityError("onSecurityEvent must be a function.", "invalid-service-profile");
  }
  return value as SecurityEventHook;
}

function resolveAuditRetentionDays(value: unknown): number | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "number") {
    throw new IdentityError(
      `auditRetentionDays must be an integer between 1 and ${MAX_AUDIT_RETENTION_DAYS}.`,
      "invalid-service-profile",
    );
  }
  return assertPositiveInteger(value, "auditRetentionDays", MAX_AUDIT_RETENTION_DAYS);
}

export function resolveIdentityServiceConfig(
  config: IdentityServiceConfig,
): ResolvedIdentityServiceConfig {
  assertNoRemovedOptions(config);
  const walletMode = config.walletMode ?? defaults.walletMode;
  if (!["service-deterministic", "per-account-deterministic", "random-vault"].includes(walletMode)) {
    throw new IdentityError("Unknown wallet mode.", "invalid-service-profile");
  }
  const profile = assertServiceableProfile(config.profile);
  // A random-vault key comes from no password derivation, so under the sign-in
  // profile there would be no application secret and no wallet beside it.
  if (walletMode === "random-vault" && profile.codec.id === signInEd25519Codec.id) {
    throw new IdentityError(
      `Profile "${profile.id}" enrolls a password-derived sign-in key; random-vault mode needs a chain wallet profile.`,
      "invalid-service-profile",
    );
  }
  return Object.freeze({
    walletMode,
    serviceProfileId: config.serviceProfileId,
    profile,
    applicationId: config.applicationId,
    networkId: config.networkId,
    tablePrefix: config.tablePrefix ?? defaults.tablePrefix,
    sessionTtlSeconds: assertPositiveInteger(
      config.sessionTtlSeconds ?? defaults.sessionTtlSeconds,
      "sessionTtlSeconds",
      60 * 60 * 24 * 365,
    ),
    challengeTtlSeconds: assertPositiveInteger(
      config.challengeTtlSeconds ?? defaults.challengeTtlSeconds,
      "challengeTtlSeconds",
      60 * 60,
    ),
    emailVerificationTtlSeconds: assertPositiveInteger(
      config.emailVerificationTtlSeconds ?? defaults.emailVerificationTtlSeconds,
      "emailVerificationTtlSeconds",
      60 * 60 * 24,
    ),
    emailVerificationMaxAttempts: assertPositiveInteger(
      config.emailVerificationMaxAttempts ?? defaults.emailVerificationMaxAttempts,
      "emailVerificationMaxAttempts",
      100,
    ),
    requireVerifiedEmail: config.requireVerifiedEmail ?? defaults.requireVerifiedEmail,
    storeSessionClientHashes: optionalBoolean(
      config.storeSessionClientHashes,
      "storeSessionClientHashes",
      defaults.storeSessionClientHashes,
    ),
    accountSecurity: resolveAccountSecurity(config.accountSecurity),
    onSecurityEvent: resolveSecurityEventHook(config.onSecurityEvent),
    auditRetentionDays: resolveAuditRetentionDays(config.auditRetentionDays),
  });
}

export const identityServiceDefaults = defaults;
