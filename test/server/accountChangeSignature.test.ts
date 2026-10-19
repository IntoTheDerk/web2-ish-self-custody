import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  assertStrictEd25519PublicKey,
  isStrictEd25519PublicKey,
  verifyAccountChangeSignature,
} from "../../src/server/accountChangeSignature.js";
import { verifyChallengeSignature } from "../../src/server/challenge.js";
import { IdentityError } from "../../src/server/errors.js";
import vector from "../../vectors/account-change-v1.json" with { type: "json" };

/**
 * The strict verifier against the committed vector. Every positive signature
 * verifies; every negative case is refused, including the small-order key
 * that noble's default rule (`zip215: true`) and the login verifier accept.
 */

const encoder = new TextEncoder();
const publicKeys: Readonly<Record<string, Uint8Array>> = {
  current: hexToBytes(vector.keys.current.publicKeyHex),
  next: hexToBytes(vector.keys.next.publicKeyHex),
  recovery: hexToBytes(vector.keys.recovery.publicKeyHex),
};

/** The canonical encodings of the eight small-order points (as the Python verifier lists them). */
const smallOrder = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

describe("verifyAccountChangeSignature", () => {
  it("verifies every committed signature under its signer's key", () => {
    for (const entry of vector.cases) {
      for (const signature of entry.signatures) {
        const key = publicKeys[signature.signer]!;
        expect(verifyAccountChangeSignature(signature.signatureHex, entry.messageUtf8, key)).toBe(true);
        expect(
          verifyAccountChangeSignature(signature.signatureHex, encoder.encode(entry.messageUtf8), key),
        ).toBe(true);
        // Reproduced by noble's own signer: Ed25519 is deterministic.
        const seed = hexToBytes(vector.keys[signature.signer as "current" | "next" | "recovery"].seedHex);
        expect(bytesToHex(ed25519.sign(encoder.encode(entry.messageUtf8), seed))).toBe(signature.signatureHex);
      }
    }
  });

  it("refuses every negative case, each for the reason the vector names", () => {
    expect(vector.negativeCases.map((entry) => entry.reason).sort()).toEqual([
      "non-canonical-public-key",
      "non-canonical-r",
      "s-not-below-l",
      "small-order-public-key",
    ]);
    for (const entry of vector.negativeCases) {
      expect(
        verifyAccountChangeSignature(entry.signatureHex, entry.messageUtf8, hexToBytes(entry.publicKeyHex)),
      ).toBe(false);
      expect(
        ed25519.verify(hexToBytes(entry.signatureHex), encoder.encode(entry.messageUtf8), hexToBytes(entry.publicKeyHex), {
          zip215: false,
        }),
      ).toBe(false);
    }
  });

  it("refuses the small-order forgery that zip215 and the login verifier accept", () => {
    const forgery = vector.negativeCases.find((entry) => entry.reason === "small-order-public-key")!;
    expect(forgery.acceptedUnderZip215).toBe(true);
    const key = hexToBytes(forgery.publicKeyHex);
    // R = identity, S = 0: no private key, any message.
    for (const message of [forgery.messageUtf8, "any other message"]) {
      expect(ed25519.verify(hexToBytes(forgery.signatureHex), encoder.encode(message), key)).toBe(true);
      expect(verifyAccountChangeSignature(forgery.signatureHex, message, key)).toBe(false);
    }
    expect(
      verifyChallengeSignature(
        {
          curve: "ed25519",
          codecId: "test",
          address: "test",
          addressNormalized: "test",
          publicKey: "test",
          publicKeyBytes: key,
        },
        "any message",
        forgery.signatureHex,
      ),
    ).toBe(true);
  });

  it("checks the flag of each negative case against noble's zip215 rule", () => {
    for (const entry of vector.negativeCases) {
      expect(
        ed25519.verify(hexToBytes(entry.signatureHex), encoder.encode(entry.messageUtf8), hexToBytes(entry.publicKeyHex)),
      ).toBe(entry.acceptedUnderZip215);
    }
  });

  it("takes exactly 128 lowercase hex characters and never throws", () => {
    const entry = vector.cases[0]!;
    const good = entry.signatures[0]!.signatureHex;
    const key = publicKeys.current!;
    for (const signature of [
      good.toUpperCase(),
      ` ${good}`,
      `${good}\n`,
      good.slice(2),
      `${good}00`,
      "",
      42 as unknown as string,
    ]) {
      expect(verifyAccountChangeSignature(signature, entry.messageUtf8, key)).toBe(false);
    }
    expect(verifyAccountChangeSignature(good, `${entry.messageUtf8}x`, key)).toBe(false);
    expect(verifyAccountChangeSignature(good, entry.messageUtf8, publicKeys.next!)).toBe(false);
    expect(verifyAccountChangeSignature(good, entry.messageUtf8, new Uint8Array(31))).toBe(false);
    expect(verifyAccountChangeSignature(good, 7 as unknown as string, key)).toBe(false);
  });
});

describe("the strict public-key check", () => {
  it("refuses all eight small-order points and non-canonical encodings", () => {
    for (const hex of smallOrder) {
      expect(isStrictEd25519PublicKey(hexToBytes(hex))).toBe(false);
      expect(ed25519.Point.fromHex(hex, false).isSmallOrder()).toBe(true);
    }
    const nonCanonical = vector.negativeCases.find((entry) => entry.reason === "non-canonical-public-key")!;
    expect(isStrictEd25519PublicKey(hexToBytes(nonCanonical.publicKeyHex))).toBe(false);
    // The identity with the sign bit set (x = 0, x_0 = 1).
    expect(isStrictEd25519PublicKey(hexToBytes(`01${"00".repeat(30)}80`))).toBe(false);
    // Not a point at all, and the wrong length.
    expect(isStrictEd25519PublicKey(hexToBytes(`02${"00".repeat(31)}`))).toBe(false);
    expect(isStrictEd25519PublicKey(new Uint8Array(33))).toBe(false);
  });

  it("accepts every key the fixtures derive", () => {
    for (const key of Object.values(publicKeys)) {
      expect(isStrictEd25519PublicKey(key)).toBe(true);
      expect(() => assertStrictEd25519PublicKey(key)).not.toThrow();
    }
    for (let index = 0; index < 64; index += 1) {
      expect(isStrictEd25519PublicKey(ed25519.getPublicKey(ed25519.utils.randomSecretKey()))).toBe(true);
    }
  });

  it("raises invalid-public-key, naming the field and no account", () => {
    try {
      assertStrictEd25519PublicKey(hexToBytes(smallOrder[0]!), "newKey.publicKey");
      throw new Error("expected a refusal");
    } catch (error) {
      expect(error).toBeInstanceOf(IdentityError);
      expect((error as IdentityError).code).toBe("invalid-public-key");
      expect((error as IdentityError).status).toBe(400);
      expect((error as IdentityError).message).toContain("newKey.publicKey");
    }
  });
});
