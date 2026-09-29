import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { buildChallengeMessage } from "../../src/server/challenge.js";
import {
  constantTimeEqualHex,
  generateSessionToken,
  generateVerificationCode,
  hashSessionToken,
  hashVerificationCode,
  randomNonceHex,
} from "../../src/server/tokens.js";

const encoder = new TextEncoder();
const sha256Pattern = /^[0-9a-f]{64}$/u;

/** Base64url of 32 CSPRNG bytes, padding-free. */
const sessionTokenPattern = /^[A-Za-z0-9_-]{43}$/u;

/**
 * Glyph groups a human misreads off a screen. At most one member of each may
 * appear in the verification alphabet; which member is the generator's choice.
 */
const confusableGlyphs: readonly (readonly string[])[] = [
  ["0", "O"],
  ["1", "I", "L"],
];

const verificationCodeLength = 8;

/**
 * Pinned because stored digests outlive the code that made them: changing
 * either preimage invalidates every session and verification already issued.
 */
const verificationCodeDomain = "web2-ish-self-custody email verification code v1";

function sha256Hex(value: string): string {
  return bytesToHex(sha256(encoder.encode(value)));
}

describe("session tokens", () => {
  it("draws 256 bits of URL-safe entropy that never repeats", () => {
    const draws = 512;
    const tokens = new Set<string>();

    for (let index = 0; index < draws; index += 1) {
      const token = generateSessionToken();
      expect(token).toMatch(sessionTokenPattern);
      tokens.add(token);
    }

    expect(tokens.size).toBe(draws);
  });

  it("hashes to 64 lowercase hex characters and never repeats across draws", () => {
    const draws = 512;
    const hashes = new Set<string>();

    for (let index = 0; index < draws; index += 1) {
      const hash = hashSessionToken(generateSessionToken());
      expect(hash).toMatch(sha256Pattern);
      expect(hash).toBe(hash.toLowerCase());
      hashes.add(hash);
    }

    expect(hashes.size).toBe(draws);
  });

  it("is a deterministic, undomained SHA-256 of the token text", () => {
    const token = generateSessionToken();
    expect(hashSessionToken(token)).toBe(sha256Hex(token));
    expect(hashSessionToken(token)).toBe(hashSessionToken(token));

    const other = generateSessionToken();
    expect(hashSessionToken(other)).not.toBe(hashSessionToken(token));
    expect(hashSessionToken(token)).not.toBe(token);
  });
});

describe("email verification codes", () => {
  it("uses only the unambiguous alphabet", () => {
    const observed = new Set<string>();

    // 256 codes is far past the coupon-collector bound for a ~32-symbol
    // alphabet, so the observed set is the full alphabet in practice.
    for (let index = 0; index < 256; index += 1) {
      const code = generateVerificationCode();
      expect(code).toHaveLength(verificationCodeLength);
      for (const character of code) {
        expect(character, "codes must be uppercase alphanumeric").toMatch(/^[A-Z0-9]$/u);
        observed.add(character);
      }
    }

    for (const group of confusableGlyphs) {
      const present = group.filter((glyph) => observed.has(glyph));
      expect(
        present.length,
        `${group.join("/")} are indistinguishable in a typed code`,
      ).toBeLessThanOrEqual(1);
    }

    // A biased generator could satisfy the membership check while emitting a
    // near-constant code, so require real spread and a usable code space.
    expect(observed.size).toBeGreaterThanOrEqual(24);
    expect(Math.log2(observed.size) * verificationCodeLength).toBeGreaterThanOrEqual(32);
  });

  it("never repeats a code across many draws", () => {
    const draws = 512;
    const codes = new Set<string>();
    for (let index = 0; index < draws; index += 1) {
      codes.add(generateVerificationCode());
    }
    expect(codes.size).toBe(draws);
  });

  it("binds the code hash to its service profile and verification id", () => {
    const serviceProfileId = "acme.identity";
    const otherServiceProfileId = "acme.identity.staging";
    const verificationId = "6f1a2c48-4f4a-4f0b-8f2e-1a2b3c4d5e6f";
    const otherVerificationId = "9c0d5e13-72b3-4c1a-9a77-0b1c2d3e4f50";
    const code = generateVerificationCode();
    const otherCode = generateVerificationCode();

    const hash = hashVerificationCode(serviceProfileId, verificationId, code);

    expect(hash).toMatch(sha256Pattern);
    expect(hash).toBe(hash.toLowerCase());
    expect(hash).toBe(hashVerificationCode(serviceProfileId, verificationId, code));
    expect(hash).toBe(
      sha256Hex(
        [verificationCodeDomain, serviceProfileId, verificationId, code].join("\n"),
      ),
    );

    // Without the id in the digest, a code minted for one verification would
    // validate against any other verification that drew the same code.
    expect(hashVerificationCode(serviceProfileId, otherVerificationId, code)).not.toBe(
      hash,
    );
    expect(hashVerificationCode(otherServiceProfileId, verificationId, code)).not.toBe(
      hash,
    );
    expect(hashVerificationCode(serviceProfileId, verificationId, otherCode)).not.toBe(
      hash,
    );

    expect(
      constantTimeEqualHex(
        hash,
        hashVerificationCode(serviceProfileId, verificationId, code),
      ),
    ).toBe(true);
    expect(
      constantTimeEqualHex(
        hash,
        hashVerificationCode(serviceProfileId, otherVerificationId, code),
      ),
    ).toBe(false);
  });
});

describe("challenge nonces", () => {
  it("emits 32 lowercase hex bytes that buildChallengeMessage accepts", () => {
    const draws = 512;
    const nonces = new Set<string>();

    for (let index = 0; index < draws; index += 1) {
      const nonceHex = randomNonceHex();
      expect(nonceHex).toMatch(sha256Pattern);
      nonces.add(nonceHex);
    }

    expect(nonces.size).toBe(draws);

    expect(() =>
      buildChallengeMessage({
        serviceProfileId: "acme.identity",
        applicationId: "example-app",
        networkId: "kalvora-mainnet",
        purpose: "login",
        usernameNormalized: "jesse@example.com",
        nonceHex: randomNonceHex(),
        expiresAt: new Date("2026-01-02T03:04:05.678Z"),
      }),
    ).not.toThrow();
  });
});

describe("constantTimeEqualHex", () => {
  const value = "9f".repeat(32);

  it("accepts identical values", () => {
    expect(constantTimeEqualHex(value, value)).toBe(true);
    expect(constantTimeEqualHex(value, `9f${value.slice(2)}`)).toBe(true);
    expect(constantTimeEqualHex("", "")).toBe(true);
  });

  it("rejects values that differ anywhere", () => {
    expect(constantTimeEqualHex(value, `8f${value.slice(2)}`)).toBe(false);
    expect(constantTimeEqualHex(value, `${value.slice(0, 62)}9e`)).toBe(false);
    expect(constantTimeEqualHex(value, "0".repeat(64))).toBe(false);
    // Case-sensitive: both sides are produced by the same lowercase hasher.
    expect(constantTimeEqualHex(value, value.toUpperCase())).toBe(false);
  });

  it("rejects values of different lengths without throwing", () => {
    expect(constantTimeEqualHex(value, value.slice(0, 62))).toBe(false);
    expect(constantTimeEqualHex(value.slice(0, 62), value)).toBe(false);
    expect(constantTimeEqualHex(value, `${value}00`)).toBe(false);
    expect(constantTimeEqualHex("", value)).toBe(false);
    expect(constantTimeEqualHex(value, "")).toBe(false);
  });
});
