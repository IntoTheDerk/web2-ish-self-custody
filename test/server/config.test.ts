import { describe, expect, it } from "vitest";
import {
  identityServiceDefaults,
  resolveIdentityServiceConfig,
} from "../../src/server/config.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import { serverProfileIds, type IdentityServiceConfig } from "../../src/server/types.js";

const minimal: IdentityServiceConfig = {
  serviceProfileId: "acme.identity",
  profileId: "web2ish-zera-ed25519-external-salt-v1",
  applicationId: "knight-armor",
  networkId: "zera-mainnet",
};

function expectIdentityError(run: () => unknown, code: IdentityErrorCode): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe(code);
    return;
  }
  throw new Error(`Expected an IdentityError with code "${code}" but nothing was thrown.`);
}

function withOverride(overrides: Partial<IdentityServiceConfig>): IdentityServiceConfig {
  return { ...minimal, ...overrides };
}

describe("resolveIdentityServiceConfig defaults", () => {
  it("applies every documented default and freezes the result", () => {
    const resolved = resolveIdentityServiceConfig(minimal);

    expect(resolved).toEqual({
      serviceProfileId: "acme.identity",
      profileId: "web2ish-zera-ed25519-external-salt-v1",
      applicationId: "knight-armor",
      networkId: "zera-mainnet",
      tablePrefix: "w2sc",
      adoptPublicSaltHex: null,
      sessionTtlSeconds: 60 * 60 * 24 * 14,
      challengeTtlSeconds: 300,
      emailVerificationTtlSeconds: 900,
      emailVerificationMaxAttempts: 5,
      requireVerifiedEmail: false,
    });
    expect(Object.isFrozen(resolved)).toBe(true);
  });

  it("normalizes an adopted public salt and rejects unusable ones", () => {
    const salt = "a".repeat(64);
    expect(
      resolveIdentityServiceConfig(withOverride({ adoptPublicSaltHex: salt.toUpperCase() }))
        .adoptPublicSaltHex,
    ).toBe(salt);

    for (const invalid of ["0".repeat(64), "a".repeat(63), "a".repeat(66), "zz".repeat(32), ""]) {
      expect(() =>
        resolveIdentityServiceConfig(withOverride({ adoptPublicSaltHex: invalid })),
      ).toThrowError(expect.objectContaining({ code: "invalid-service-profile" }));
    }
  });

  it("exposes the same defaults as a frozen constant", () => {
    expect(identityServiceDefaults).toEqual({
      tablePrefix: "w2sc",
      sessionTtlSeconds: 1_209_600,
      challengeTtlSeconds: 300,
      emailVerificationTtlSeconds: 900,
      emailVerificationMaxAttempts: 5,
      requireVerifiedEmail: false,
    });
    expect(Object.isFrozen(identityServiceDefaults)).toBe(true);
  });

  it("keeps explicit overrides, including a falsy requireVerifiedEmail", () => {
    const resolved = resolveIdentityServiceConfig(
      withOverride({
        tablePrefix: "acme_id",
        sessionTtlSeconds: 3_600,
        challengeTtlSeconds: 60,
        emailVerificationTtlSeconds: 600,
        emailVerificationMaxAttempts: 3,
        requireVerifiedEmail: true,
      }),
    );

    expect(resolved.tablePrefix).toBe("acme_id");
    expect(resolved.sessionTtlSeconds).toBe(3_600);
    expect(resolved.challengeTtlSeconds).toBe(60);
    expect(resolved.emailVerificationTtlSeconds).toBe(600);
    expect(resolved.emailVerificationMaxAttempts).toBe(3);
    expect(resolved.requireVerifiedEmail).toBe(true);

    expect(
      resolveIdentityServiceConfig(withOverride({ requireVerifiedEmail: false }))
        .requireVerifiedEmail,
    ).toBe(false);
  });
});

describe("resolveIdentityServiceConfig validation", () => {
  it("accepts every serviceable profile id", () => {
    for (const profileId of serverProfileIds) {
      expect(resolveIdentityServiceConfig(withOverride({ profileId })).profileId).toBe(profileId);
    }
  });

  it("rejects the stateless profile, which has no server-held salt", () => {
    expectIdentityError(
      () =>
        resolveIdentityServiceConfig({
          ...minimal,
          profileId: "web2ish-zera-ed25519-v1",
        } as unknown as IdentityServiceConfig),
      "invalid-service-profile",
    );
  });

  it("rejects unknown profile ids", () => {
    for (const profileId of ["", "web2ish-zera-ed25519", "nope"]) {
      expectIdentityError(
        () =>
          resolveIdentityServiceConfig({
            ...minimal,
            profileId,
          } as unknown as IdentityServiceConfig),
        "invalid-service-profile",
      );
    }
  });

  it("rejects out-of-range or non-integer TTLs and attempt limits", () => {
    const rejected: readonly Partial<IdentityServiceConfig>[] = [
      { sessionTtlSeconds: 0 },
      { sessionTtlSeconds: -1 },
      { sessionTtlSeconds: 1.5 },
      { sessionTtlSeconds: Number.NaN },
      { sessionTtlSeconds: Number.POSITIVE_INFINITY },
      { sessionTtlSeconds: 60 * 60 * 24 * 365 + 1 },
      { challengeTtlSeconds: 0 },
      { challengeTtlSeconds: -300 },
      { challengeTtlSeconds: 3_601 },
      { emailVerificationTtlSeconds: 0 },
      { emailVerificationTtlSeconds: 60 * 60 * 24 + 1 },
      { emailVerificationMaxAttempts: 0 },
      { emailVerificationMaxAttempts: 101 },
      { emailVerificationMaxAttempts: 2.5 },
    ];

    for (const overrides of rejected) {
      expectIdentityError(
        () => resolveIdentityServiceConfig(withOverride(overrides)),
        "invalid-service-profile",
      );
    }
  });

  it("accepts the inclusive bounds of every range", () => {
    const resolved = resolveIdentityServiceConfig(
      withOverride({
        sessionTtlSeconds: 60 * 60 * 24 * 365,
        challengeTtlSeconds: 3_600,
        emailVerificationTtlSeconds: 60 * 60 * 24,
        emailVerificationMaxAttempts: 100,
      }),
    );
    expect(resolved.sessionTtlSeconds).toBe(31_536_000);
    expect(resolved.challengeTtlSeconds).toBe(3_600);
    expect(resolved.emailVerificationTtlSeconds).toBe(86_400);
    expect(resolved.emailVerificationMaxAttempts).toBe(100);

    const lower = resolveIdentityServiceConfig(
      withOverride({
        sessionTtlSeconds: 1,
        challengeTtlSeconds: 1,
        emailVerificationTtlSeconds: 1,
        emailVerificationMaxAttempts: 1,
      }),
    );
    expect(lower.sessionTtlSeconds).toBe(1);
    expect(lower.challengeTtlSeconds).toBe(1);
    expect(lower.emailVerificationTtlSeconds).toBe(1);
    expect(lower.emailVerificationMaxAttempts).toBe(1);
  });
});
