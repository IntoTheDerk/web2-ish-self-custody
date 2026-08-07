import { IdentityError } from "./errors.js";
import {
  serverProfileIds,
  type IdentityServiceConfig,
  type ResolvedIdentityServiceConfig,
  type ServerProfileId,
} from "./types.js";

const defaults = Object.freeze({
  tablePrefix: "w2sc",
  sessionTtlSeconds: 60 * 60 * 24 * 14,
  challengeTtlSeconds: 300,
  emailVerificationTtlSeconds: 900,
  emailVerificationMaxAttempts: 5,
  requireVerifiedEmail: false,
});

function assertPositiveInteger(value: number, field: string, max: number): number {
  if (!Number.isInteger(value) || value <= 0 || value > max) {
    throw new IdentityError(
      `${field} must be an integer between 1 and ${max}.`,
      "invalid-service-profile",
    );
  }
  return value;
}

const publicSaltHexPattern = /^[0-9a-f]{64}$/u;

function assertAdoptedSalt(value: string | undefined): string | null {
  if (value === undefined) {
    return null;
  }
  const normalized = value.trim().toLowerCase();
  if (!publicSaltHexPattern.test(normalized)) {
    throw new IdentityError(
      "adoptPublicSaltHex must be exactly 32 hex-encoded bytes.",
      "invalid-service-profile",
    );
  }
  if (/^0{64}$/u.test(normalized)) {
    throw new IdentityError(
      "adoptPublicSaltHex must not be all zeros.",
      "invalid-service-profile",
    );
  }
  return normalized;
}

function assertServerProfileId(value: string): ServerProfileId {
  const match = serverProfileIds.find((id) => id === value);
  if (match === undefined) {
    throw new IdentityError(
      `profileId must be one of: ${serverProfileIds.join(", ")}.`,
      "invalid-service-profile",
    );
  }
  return match;
}

export function resolveIdentityServiceConfig(
  config: IdentityServiceConfig,
): ResolvedIdentityServiceConfig {
  return Object.freeze({
    serviceProfileId: config.serviceProfileId,
    profileId: assertServerProfileId(config.profileId),
    applicationId: config.applicationId,
    networkId: config.networkId,
    tablePrefix: config.tablePrefix ?? defaults.tablePrefix,
    adoptPublicSaltHex: assertAdoptedSalt(config.adoptPublicSaltHex),
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
  });
}

export const identityServiceDefaults = defaults;
