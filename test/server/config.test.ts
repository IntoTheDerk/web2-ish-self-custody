import { describe, expect, it } from "vitest";
import { kalvoraEd25519ExternalSalt } from "../../src/chains/kalvora.js";
import {
  identityServiceDefaults,
  resolveIdentityServiceConfig,
} from "../../src/server/config.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import type { IdentityServiceConfig } from "../../src/server/types.js";
import {
  krypticExternalSalt,
  krypticStateless,
  truncatingProfile,
} from "../support/kryptic-chain.js";

const minimal: IdentityServiceConfig = {
  serviceProfileId: "acme.identity",
  profile: kalvoraEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-mainnet",
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
      profile: kalvoraEd25519ExternalSalt,
      applicationId: "example-app",
      networkId: "kalvora-mainnet",
      tablePrefix: "w2sc",
      sessionTtlSeconds: 60 * 60 * 24 * 14,
      challengeTtlSeconds: 300,
      emailVerificationTtlSeconds: 900,
      emailVerificationMaxAttempts: 5,
      requireVerifiedEmail: false,
      walletMode: "service-deterministic",
      storeSessionClientHashes: true,
      accountSecurity: { signInKeyRotation: false, recoveryKeys: false, emailReset: false, signedInReset: false },
      onSecurityEvent: null,
      auditRetentionDays: null,
    });
    // The very object, not a copy: the codec identity has to survive resolution
    // or the service would encode addresses with something else.
    expect(resolved.profile).toBe(kalvoraEd25519ExternalSalt);
    expect(Object.isFrozen(resolved)).toBe(true);
  });

  it("refuses the removed adoptPublicSaltHex option rather than ignoring it", () => {
    // Ignoring it would mint a fresh salt on first provisioning for a caller
    // that expected to keep an existing one: a new wallet namespace, silently.
    for (const salt of ["a".repeat(64), "", "not hex"]) {
      const legacy = { ...minimal, adoptPublicSaltHex: salt } as IdentityServiceConfig;
      expectIdentityError(() => resolveIdentityServiceConfig(legacy), "invalid-service-profile");
    }
    // An explicit undefined carries no intent and resolves normally.
    const unset = { ...minimal, adoptPublicSaltHex: undefined } as IdentityServiceConfig;
    expect(resolveIdentityServiceConfig(unset)).not.toHaveProperty("adoptPublicSaltHex");
  });

  it("exposes the same defaults as a frozen constant", () => {
    expect(identityServiceDefaults).toEqual({
      tablePrefix: "w2sc",
      sessionTtlSeconds: 1_209_600,
      challengeTtlSeconds: 300,
      emailVerificationTtlSeconds: 900,
      emailVerificationMaxAttempts: 5,
      requireVerifiedEmail: false,
      walletMode: "service-deterministic",
      storeSessionClientHashes: true,
      accountSecurity: { signInKeyRotation: false, recoveryKeys: false, emailReset: false, signedInReset: false },
      onSecurityEvent: null,
      auditRetentionDays: null,
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

describe("resolveIdentityServiceConfig storeSessionClientHashes", () => {
  it("defaults to true, so existing deployments keep storing the hashes", () => {
    expect(resolveIdentityServiceConfig(minimal).storeSessionClientHashes).toBe(true);
    // An explicit undefined, as a spread of an optional value delivers it.
    const unset = { ...minimal, storeSessionClientHashes: undefined } as unknown as IdentityServiceConfig;
    expect(resolveIdentityServiceConfig(unset).storeSessionClientHashes).toBe(true);
  });

  it("keeps an explicit true or false", () => {
    for (const storeSessionClientHashes of [true, false]) {
      expect(
        resolveIdentityServiceConfig(withOverride({ storeSessionClientHashes }))
          .storeSessionClientHashes,
      ).toBe(storeSessionClientHashes);
    }
  });

  it("refuses a non-boolean rather than reading it as truthy", () => {
    // A string "false" would otherwise keep the hashes a deployment opted out of.
    for (const value of ["false", "true", 0, 1, null, {}]) {
      expectIdentityError(
        () =>
          resolveIdentityServiceConfig(
            withOverride({ storeSessionClientHashes: value as never }),
          ),
        "invalid-service-profile",
      );
    }
  });
});

describe("resolveIdentityServiceConfig profile validation", () => {
  it("accepts both new modes and refuses unknown modes", () => {
    for (const walletMode of ["per-account-deterministic", "random-vault"] as const) {
      expect(resolveIdentityServiceConfig(withOverride({ walletMode })).walletMode).toBe(walletMode);
    }
    expectIdentityError(() => resolveIdentityServiceConfig(withOverride({ walletMode: "typo" as never })), "invalid-service-profile");
  });

  it("accepts any external-salt profile, from any chain", () => {
    for (const profile of [kalvoraEd25519ExternalSalt, krypticExternalSalt]) {
      expect(resolveIdentityServiceConfig(withOverride({ profile })).profile).toBe(profile);
    }
  });

  it("rejects a self-salting profile, which has no server-held salt", () => {
    // A service exists to own and publish a salt. Configuring a profile that
    // computes its own would publish a salt clients are required to ignore.
    expectIdentityError(
      () => resolveIdentityServiceConfig(withOverride({ profile: krypticStateless })),
      "invalid-service-profile",
    );
    expect(krypticStateless.saltPolicy).toBe("derived-from-username");
  });

  it("rejects a codec that does not round-trip its own encoding", () => {
    // Enrolling under such a codec would produce wallets the service could
    // never authenticate again, so it must fail at startup rather than at login.
    expectIdentityError(
      () => resolveIdentityServiceConfig(withOverride({ profile: truncatingProfile })),
      "invalid-service-profile",
    );
  });

  it("rejects anything that is not a derivation profile object", () => {
    // `profileId` strings were the old configuration surface; a deployment that
    // still passes one must fail loudly rather than derive a default profile.
    for (const profile of [
      "web2ish-kalvora-ed25519-external-salt-v1",
      "",
      null,
      undefined,
      42,
      {},
      { id: 42 },
    ]) {
      expectIdentityError(
        () => resolveIdentityServiceConfig(withOverride({ profile: profile as never })),
        "invalid-service-profile",
      );
    }
  });
});

describe("resolveIdentityServiceConfig range validation", () => {
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

describe("resolveIdentityServiceConfig account security options", () => {
  it("defaults every opt-in to false, no hook and no audit retention", () => {
    const resolved = resolveIdentityServiceConfig(minimal);
    expect(resolved.accountSecurity).toEqual({
      signInKeyRotation: false,
      recoveryKeys: false,
      emailReset: false,
      signedInReset: false,
    });
    expect(Object.isFrozen(resolved.accountSecurity)).toBe(true);
    expect(resolved.onSecurityEvent).toBeNull();
    expect(resolved.auditRetentionDays).toBeNull();
  });

  it("keeps each opt-in independently, and an empty object is all off", () => {
    for (const signInKeyRotation of [true, false]) {
      for (const recoveryKeys of [true, false]) {
        for (const emailReset of [true, false]) {
          for (const signedInReset of [true, false]) {
            expect(
              resolveIdentityServiceConfig(
                withOverride({ accountSecurity: { signInKeyRotation, recoveryKeys, emailReset, signedInReset } }),
              ).accountSecurity,
            ).toEqual({ signInKeyRotation, recoveryKeys, emailReset, signedInReset });
          }
        }
      }
    }
    expect(resolveIdentityServiceConfig(withOverride({ accountSecurity: {} })).accountSecurity).toEqual({
      signInKeyRotation: false,
      recoveryKeys: false,
      emailReset: false,
      signedInReset: false,
    });
  });

  it("refuses a non-object, a non-boolean opt-in and a misspelt key", () => {
    for (const accountSecurity of [true, "on", null, [], { signInKeyRotation: "true" }, { recoveryKeys: 1 },
      { walletRotation: true }, { signInKeyRotation: true, recovery: true }, { emailReset: "true" },
      { signedInReset: 1 }, { emailResets: true }, { sessionReset: true }]) {
      expectIdentityError(
        () => resolveIdentityServiceConfig({ ...minimal, accountSecurity } as unknown as IdentityServiceConfig),
        "invalid-service-profile",
      );
    }
  });

  it("takes a function hook and refuses anything else", () => {
    const hook = (): void => undefined;
    expect(resolveIdentityServiceConfig(withOverride({ onSecurityEvent: hook })).onSecurityEvent).toBe(hook);
    for (const onSecurityEvent of ["https://hook.example", {}, 1]) {
      expectIdentityError(
        () => resolveIdentityServiceConfig({ ...minimal, onSecurityEvent } as unknown as IdentityServiceConfig),
        "invalid-service-profile",
      );
    }
  });

  it("bounds auditRetentionDays to an integer from 1 to 36,500", () => {
    expect(resolveIdentityServiceConfig(withOverride({ auditRetentionDays: 395 })).auditRetentionDays).toBe(395);
    expect(resolveIdentityServiceConfig(withOverride({ auditRetentionDays: 1 })).auditRetentionDays).toBe(1);
    expect(resolveIdentityServiceConfig(withOverride({ auditRetentionDays: 36_500 })).auditRetentionDays).toBe(36_500);
    for (const auditRetentionDays of [0, -1, 1.5, 36_501, "395", Number.NaN]) {
      expectIdentityError(
        () => resolveIdentityServiceConfig({ ...minimal, auditRetentionDays } as unknown as IdentityServiceConfig),
        "invalid-service-profile",
      );
    }
  });

  it("resolves a resolved config to an equal one", () => {
    const hook = (): void => undefined;
    const resolved = resolveIdentityServiceConfig(
      withOverride({ accountSecurity: { recoveryKeys: true }, onSecurityEvent: hook, auditRetentionDays: 30 }),
    );
    expect(resolveIdentityServiceConfig(resolved)).toEqual(resolved);
    const unset = resolveIdentityServiceConfig(minimal);
    expect(resolveIdentityServiceConfig(unset)).toEqual(unset);
  });
});

describe("emailVerificationCodeFormat", () => {
  it("is absent from a config that does not set it, and kept when set", () => {
    expect("emailVerificationCodeFormat" in resolveIdentityServiceConfig(minimal)).toBe(false);
    expect("emailVerificationCodeFormat" in identityServiceDefaults).toBe(false);
    for (const format of ["symbols8", "digits6"] as const) {
      const resolved = resolveIdentityServiceConfig(withOverride({ emailVerificationCodeFormat: format }));
      expect(resolved.emailVerificationCodeFormat).toBe(format);
      expect(resolveIdentityServiceConfig(resolved)).toEqual(resolved);
    }
  });

  it("refuses anything but the two formats", () => {
    for (const bad of ["digits8", "DIGITS6", "", 6, null, true]) {
      expectIdentityError(
        () =>
          resolveIdentityServiceConfig(
            withOverride({ emailVerificationCodeFormat: bad as unknown as "digits6" }),
          ),
        "invalid-service-profile",
      );
    }
  });
});
