import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { zeraEd25519Codec } from "../src/chains/zera.js";
import { assertCodecRoundTrip, defineIdentityCodec, type IdentityCodec } from "../src/codec.js";
import { DerivationError } from "../src/errors.js";
import { krypticHexCodec, truncatingCodec } from "./support/kryptic-chain.js";

const publicKeyBytes = Uint8Array.from({ length: 32 }, (_, index) => index * 7);

function hexCodecWith(overrides: Partial<IdentityCodec>): IdentityCodec {
  return defineIdentityCodec({
    id: "probe-codec-v1",
    encodeAddress: (bytes) => bytesToHex(bytes),
    encodePublicKey: (bytes) => `p_${bytesToHex(bytes)}`,
    decodePublicKey: (identifier) => hexToBytes(identifier.slice(2)),
    ...overrides,
  });
}

describe("defineIdentityCodec", () => {
  it("accepts and freezes a well-formed codec", () => {
    const codec = hexCodecWith({});
    expect(Object.isFrozen(codec)).toBe(true);
    expect(codec.id).toBe("probe-codec-v1");
    expect(codec.encodeAddress(publicKeyBytes)).toBe(bytesToHex(publicKeyBytes));

    // The 3- and 64-character ends of the id range must both stay usable.
    expect(hexCodecWith({ id: "abc" }).id).toBe("abc");
    expect(hexCodecWith({ id: `a${"b".repeat(63)}` }).id).toHaveLength(64);
    expect(hexCodecWith({ id: "0a.b_c-d" }).id).toBe("0a.b_c-d");
  });

  it("rejects ids outside 3–64 characters of [a-z0-9._-]", () => {
    for (const id of [
      "",
      "ab",
      "A-Bad-Codec",
      "-leading-dash",
      ".leading-dot",
      "has space",
      "has/slash",
      `a${"b".repeat(64)}`,
    ]) {
      expect(() => hexCodecWith({ id }), `id "${id}" must be rejected`).toThrowError(
        expect.objectContaining({ code: "invalid-codec" }),
      );
    }
  });

  it("rejects a codec that is missing any of its three methods", () => {
    for (const method of ["encodeAddress", "encodePublicKey", "decodePublicKey"] as const) {
      expect(() =>
        hexCodecWith({ [method]: undefined } as unknown as Partial<IdentityCodec>),
      ).toThrowError(expect.objectContaining({ code: "invalid-codec" }));
      expect(() =>
        hexCodecWith({ [method]: "not-a-function" } as unknown as Partial<IdentityCodec>),
      ).toThrowError(expect.objectContaining({ code: "invalid-codec" }));
    }
  });
});

describe("assertCodecRoundTrip", () => {
  it("passes for every codec this repository ships or tests with", () => {
    for (const codec of [zeraEd25519Codec, krypticHexCodec]) {
      expect(() => assertCodecRoundTrip(codec, publicKeyBytes)).not.toThrow();
      expect(() => assertCodecRoundTrip(codec, new Uint8Array(32))).not.toThrow();
      expect(() => assertCodecRoundTrip(codec, new Uint8Array(32).fill(0xff))).not.toThrow();
    }
  });

  it("rejects a decode that drops bytes from its own encoding", () => {
    expect(bytesToHex(truncatingCodec.decodePublicKey(
      truncatingCodec.encodePublicKey(publicKeyBytes),
    ))).toHaveLength(62);

    expect(() => assertCodecRoundTrip(truncatingCodec, publicKeyBytes)).toThrowError(
      expect.objectContaining({ code: "invalid-codec" }),
    );
  });

  it("rejects a decode that returns the right length but different bytes", () => {
    const flipping = hexCodecWith({
      id: "broken-flipping-v1",
      decodePublicKey: (identifier) => {
        const decoded = hexToBytes(identifier.slice(2));
        decoded[0] = (decoded[0] ?? 0) ^ 0x01;
        return decoded;
      },
    });

    expect(flipping.decodePublicKey(flipping.encodePublicKey(publicKeyBytes))).toHaveLength(32);
    expect(() => assertCodecRoundTrip(flipping, publicKeyBytes)).toThrowError(
      expect.objectContaining({ code: "invalid-codec" }),
    );
  });

  it("rejects a decode that pads its own encoding", () => {
    const padding = hexCodecWith({
      id: "broken-padding-v1",
      decodePublicKey: (identifier) =>
        Uint8Array.from([...hexToBytes(identifier.slice(2)), 0]),
    });

    expect(() => assertCodecRoundTrip(padding, publicKeyBytes)).toThrowError(
      expect.objectContaining({ code: "invalid-codec" }),
    );
  });

  it("lets a decode's own rejection surface unchanged", () => {
    const refusing = hexCodecWith({
      id: "broken-refusing-v1",
      decodePublicKey: () => {
        throw new DerivationError("nothing decodes here", "invalid-public-key");
      },
    });

    expect(() => assertCodecRoundTrip(refusing, publicKeyBytes)).toThrowError(
      expect.objectContaining({ code: "invalid-public-key" }),
    );
  });
});

describe("the ZERA codec as an IdentityCodec", () => {
  it("round-trips its own identifier and rejects everything else", () => {
    const identifier = zeraEd25519Codec.encodePublicKey(publicKeyBytes);
    expect(identifier).toBe(`A_${zeraEd25519Codec.encodeAddress(publicKeyBytes)}`);
    expect(zeraEd25519Codec.decodePublicKey(identifier)).toEqual(publicKeyBytes);
    expect(zeraEd25519Codec.decodePublicKey(`  ${identifier}  `)).toEqual(publicKeyBytes);

    for (const bad of [
      zeraEd25519Codec.encodeAddress(publicKeyBytes),
      `B_${zeraEd25519Codec.encodeAddress(publicKeyBytes)}`,
      `A_${"0OIl".repeat(11)}`,
      `A_${zeraEd25519Codec.encodeAddress(new Uint8Array(31))}`,
      "A_",
      "",
    ]) {
      expect(() => zeraEd25519Codec.decodePublicKey(bad), `"${bad}" must be rejected`).toThrowError(
        expect.objectContaining({ code: "invalid-public-key" }),
      );
    }
  });

  it("does not accept another chain's identifier", () => {
    expect(() =>
      zeraEd25519Codec.decodePublicKey(krypticHexCodec.encodePublicKey(publicKeyBytes)),
    ).toThrowError(expect.objectContaining({ code: "invalid-public-key" }));
    expect(() =>
      krypticHexCodec.decodePublicKey(zeraEd25519Codec.encodePublicKey(publicKeyBytes)),
    ).toThrowError(expect.objectContaining({ code: "invalid-public-key" }));
  });
});
