import { assertCodecRoundTrip } from "../codec.js";
import type { DerivationProfile } from "../profile.js";
import { IdentityError } from "./errors.js";
import type {
  IdentityServiceConfig,
  ResolvedIdentityServiceConfig,
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

export function resolveIdentityServiceConfig(
  config: IdentityServiceConfig,
): ResolvedIdentityServiceConfig {
  assertNoRemovedOptions(config);
  return Object.freeze({
    serviceProfileId: config.serviceProfileId,
    profile: assertServiceableProfile(config.profile),
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
  });
}

export const identityServiceDefaults = defaults;
