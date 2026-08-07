import { describe, expect, it } from "vitest";
import { defineDerivationProfile, type DerivationProfile } from "../src/profile.js";
import { krypticHexCodec } from "./support/kryptic-chain.js";

const baseline = {
  id: "probe-ed25519-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "probe password hash v1\n",
    entropy: "probe external salt entropy v1",
  },
  codec: krypticHexCodec,
} as const satisfies DerivationProfile;

/** Overrides are cast in: every case here is a definition a caller must not get away with. */
function define(overrides: Record<string, unknown>): DerivationProfile {
  return defineDerivationProfile({ ...baseline, ...overrides } as unknown as DerivationProfile);
}

function withKdf(overrides: Record<string, unknown>): DerivationProfile {
  return define({ kdf: { ...baseline.kdf, ...overrides } });
}

function withDomains(domains: Record<string, unknown>): DerivationProfile {
  return define({ domains });
}

function expectRejected(run: () => unknown, label: string): void {
  expect(run, label).toThrowError(expect.objectContaining({ code: "invalid-profile" }));
}

describe("defineDerivationProfile acceptance", () => {
  it("freezes the profile, its KDF parameters, and its domains", () => {
    const profile = define({});

    expect(Object.isFrozen(profile)).toBe(true);
    expect(Object.isFrozen(profile.kdf)).toBe(true);
    expect(Object.isFrozen(profile.domains)).toBe(true);
    expect(profile.kdf).toEqual({ N: 65_536, r: 8, p: 1, dkLen: 32 });
    expect(profile.codec).toBe(krypticHexCodec);
    // An `external-32` profile must not carry a salt domain even implicitly.
    expect(profile.domains.salt).toBeUndefined();
  });

  it("accepts a derived-from-username profile that declares its salt domain", () => {
    const profile = define({
      id: "probe-ed25519-v1",
      saltPolicy: "derived-from-username",
      domains: { ...baseline.domains, salt: "probe public username salt v1" },
    });

    expect(profile.saltPolicy).toBe("derived-from-username");
    expect(profile.domains.salt).toBe("probe public username salt v1");
  });

  it("accepts KDF parameters at or above the floor", () => {
    expect(withKdf({ N: 65_536 }).kdf.N).toBe(65_536);
    expect(withKdf({ N: 131_072 }).kdf.N).toBe(131_072);
    expect(withKdf({ r: 8 }).kdf.r).toBe(8);
    expect(withKdf({ r: 16 }).kdf.r).toBe(16);
    expect(withKdf({ p: 1 }).kdf.p).toBe(1);
    expect(withKdf({ p: 4 }).kdf.p).toBe(4);
  });

  it("accepts the 3- and 80-character ends of the id range", () => {
    expect(define({ id: "abc" }).id).toBe("abc");
    expect(define({ id: `a${"b".repeat(79)}` }).id).toHaveLength(80);
  });
});

describe("defineDerivationProfile KDF floor", () => {
  it("rejects a work factor below 65536", () => {
    for (const N of [2, 1_024, 16_384, 32_768]) {
      expectRejected(() => withKdf({ N }), `kdf.N=${N} is a downgrade`);
    }
  });

  it("rejects a work factor that is not a power of two", () => {
    for (const N of [65_537, 100_000, 65_536.5, 0, -65_536, Number.NaN, Number.POSITIVE_INFINITY]) {
      expectRejected(() => withKdf({ N }), `kdf.N=${String(N)} is not a power of two`);
    }
  });

  it("rejects a block size below 8 or a non-integer one", () => {
    for (const r of [0, 1, 4, 7, 8.5, -8, Number.NaN]) {
      expectRejected(() => withKdf({ r }), `kdf.r=${String(r)} must be rejected`);
    }
  });

  it("rejects a parallelism below 1 or a non-integer one", () => {
    for (const p of [0, -1, 1.5, Number.NaN]) {
      expectRejected(() => withKdf({ p }), `kdf.p=${String(p)} must be rejected`);
    }
  });

  it("rejects any derived key length other than 32, because Ed25519 seeds are 32 bytes", () => {
    for (const dkLen of [16, 31, 33, 64, 0, "32"]) {
      expectRejected(() => withKdf({ dkLen }), `kdf.dkLen=${String(dkLen)} must be rejected`);
    }
  });
});

describe("defineDerivationProfile domain separation", () => {
  it("rejects a missing, empty, or oversized passwordHash domain", () => {
    for (const passwordHash of [undefined, "", "a".repeat(201), 42, null]) {
      expectRejected(
        () => withDomains({ ...baseline.domains, passwordHash }),
        `passwordHash=${String(passwordHash)} must be rejected`,
      );
    }
    expect(
      withDomains({ ...baseline.domains, passwordHash: "a".repeat(200) }).domains.passwordHash,
    ).toHaveLength(200);
  });

  it("rejects a missing, empty, or oversized entropy domain", () => {
    for (const entropy of [undefined, "", "a".repeat(201), 42, null]) {
      expectRejected(
        () => withDomains({ ...baseline.domains, entropy }),
        `entropy=${String(entropy)} must be rejected`,
      );
    }
  });

  it("rejects a salt domain on an external-32 profile, which would never be read", () => {
    expectRejected(
      () => withDomains({ ...baseline.domains, salt: "probe public username salt v1" }),
      "external-32 must not define a salt domain",
    );
  });

  it("rejects a derived-from-username profile with no salt domain", () => {
    expectRejected(
      () => define({ saltPolicy: "derived-from-username" }),
      "derived-from-username requires a salt domain",
    );
    for (const salt of ["", "a".repeat(201)]) {
      expectRejected(
        () =>
          define({
            saltPolicy: "derived-from-username",
            domains: { ...baseline.domains, salt },
          }),
        `derived-from-username salt="${salt}" must be rejected`,
      );
    }
  });
});

describe("defineDerivationProfile identity", () => {
  it("rejects ids outside 3–80 characters of [a-z0-9._-]", () => {
    for (const id of [
      "",
      "ab",
      "Probe-V1",
      "-leading-dash",
      ".leading-dot",
      "has space",
      "has/slash",
      `a${"b".repeat(80)}`,
    ]) {
      expectRejected(() => define({ id }), `id "${id}" must be rejected`);
    }
  });

  it("rejects any curve other than ed25519", () => {
    for (const curve of ["secp256k1", "ed448", "", undefined]) {
      expectRejected(() => define({ curve }), `curve "${String(curve)}" must be rejected`);
    }
  });

  it("rejects an unknown salt policy", () => {
    for (const saltPolicy of ["external-32-v1", "public-username-sha256-v1", "", undefined]) {
      expectRejected(
        () => define({ saltPolicy }),
        `saltPolicy "${String(saltPolicy)}" must be rejected`,
      );
    }
  });
});
