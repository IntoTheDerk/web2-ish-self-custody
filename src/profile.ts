import type { IdentityCodec } from "./codec.js";
import { DerivationError } from "./errors.js";

/**
 * Where the scrypt salt comes from.
 *
 * - `external-32` — the caller supplies an exact 32-byte salt, normally one a
 *   service owns and publishes. Distinct salts give distinct wallet namespaces.
 * - `derived-from-username` — the salt is computed from the normalized
 *   username and context, so no server is involved.
 */
export type SaltPolicy = "external-32" | "derived-from-username";

/**
 * Domain-separation strings.
 *
 * These are part of the definition of a wallet, not formatting: change one
 * byte and the same credentials derive a different key. They live on the
 * profile rather than in the core so that the core imposes no naming
 * convention on any chain, and so that a new transcript is a new profile
 * rather than an edit to shared code.
 */
export type ProfileDomains = Readonly<{
  /** Prefixed to the raw password bytes. Concatenated, not line-joined. */
  passwordHash: string;
  /** First line of the entropy transcript. */
  entropy: string;
  /** First line of the salt transcript. Required for `derived-from-username`. */
  salt?: string;
}>;

export type DerivationProfile = Readonly<{
  id: string;
  curve: "ed25519";
  /** Descriptive algorithm label, recorded by services alongside enrollments. */
  algorithm: string;
  saltPolicy: SaltPolicy;
  kdf: Readonly<{ N: number; r: number; p: number; dkLen: 32 }>;
  domains: ProfileDomains;
  codec: IdentityCodec;
}>;

const profileId = /^[a-z0-9][a-z0-9._-]{2,79}$/u;

function assertDomain(value: string | undefined, field: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 200) {
    throw new DerivationError(
      `Profile domain "${field}" must be 1-200 characters.`,
      "invalid-profile",
    );
  }
}

function assertPowerOfTwo(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 2 || (value & (value - 1)) !== 0) {
    throw new DerivationError(
      `Profile ${field} must be an integer power of two.`,
      "invalid-profile",
    );
  }
}

/**
 * Validates and freezes a profile.
 *
 * The KDF floor is deliberate: this package derives a wallet from a human
 * password, so a profile that lowers the work factor is not a configuration
 * choice, it is a downgrade attack surface. Anything cheaper is rejected here
 * rather than left to a reviewer to notice.
 */
export function defineDerivationProfile(profile: DerivationProfile): DerivationProfile {
  if (!profileId.test(profile.id)) {
    throw new DerivationError(
      "Profile id must be 3-80 characters from [a-z0-9._-].",
      "invalid-profile",
    );
  }
  if (profile.curve !== "ed25519") {
    throw new DerivationError("Only the ed25519 curve is supported.", "invalid-profile");
  }

  assertPowerOfTwo(profile.kdf.N, "kdf.N");
  if (profile.kdf.N < 65_536) {
    throw new DerivationError(
      "Profile kdf.N must be at least 65536 for password-derived custody.",
      "invalid-profile",
    );
  }
  if (!Number.isInteger(profile.kdf.r) || profile.kdf.r < 8) {
    throw new DerivationError("Profile kdf.r must be an integer >= 8.", "invalid-profile");
  }
  if (!Number.isInteger(profile.kdf.p) || profile.kdf.p < 1) {
    throw new DerivationError("Profile kdf.p must be an integer >= 1.", "invalid-profile");
  }
  if (profile.kdf.dkLen !== 32) {
    throw new DerivationError("Profile kdf.dkLen must be exactly 32.", "invalid-profile");
  }

  assertDomain(profile.domains.passwordHash, "passwordHash");
  assertDomain(profile.domains.entropy, "entropy");

  if (profile.saltPolicy === "derived-from-username") {
    assertDomain(profile.domains.salt, "salt");
  } else if (profile.saltPolicy === "external-32") {
    if (profile.domains.salt !== undefined) {
      throw new DerivationError(
        'Profiles using "external-32" must not define a salt domain.',
        "invalid-profile",
      );
    }
  } else {
    throw new DerivationError("Unknown salt policy.", "invalid-profile");
  }

  return Object.freeze({
    ...profile,
    kdf: Object.freeze({ ...profile.kdf }),
    domains: Object.freeze({ ...profile.domains }),
  });
}
