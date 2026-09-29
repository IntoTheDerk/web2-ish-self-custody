// @ts-expect-error Node typings are intentionally not a browser SDK dependency.
import { runInNewContext } from "node:vm";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  deriveKalvoraEd25519IdentityFromSeed,
  kalvoraEd25519Codec,
} from "../src/chains/kalvora.js";
import { ED25519_SEED_BYTES, deriveIdentityFromSeed } from "../src/seed.js";
import { krypticHexCodec } from "./support/kryptic-chain.js";

const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
const expectedSeed = Uint8Array.from(seed);

/** The public key this seed produces, in each convention. */
const publicKeyHex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const kalvoraAddress = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF";

describe("direct-seed Kalvora Ed25519 identity", () => {
  afterEach(() => vi.restoreAllMocks());

  it("matches the established direct-seed identity vector", () => {
    expect(deriveKalvoraEd25519IdentityFromSeed(seed)).toEqual({
      curve: "ed25519",
      codecId: "kalvora-ed25519-base58-v1",
      publicKey: `A_${kalvoraAddress}`,
      address: kalvoraAddress,
    });
    expect(seed).toEqual(expectedSeed);
  });

  it("returns a frozen identity", () => {
    expect(Object.isFrozen(deriveKalvoraEd25519IdentityFromSeed(seed))).toBe(true);
  });

  it("clears its owned seed copy without mutating caller-owned bytes", () => {
    const originalFill = Uint8Array.prototype.fill;
    const clearedCopies: number[][] = [];
    vi.spyOn(Uint8Array.prototype, "fill").mockImplementation(function (
      this: Uint8Array,
      value: number,
      start?: number,
      end?: number,
    ) {
      if (value === 0 && this !== seed) clearedCopies.push(Array.from(this));
      return originalFill.call(this, value, start, end);
    });

    deriveKalvoraEd25519IdentityFromSeed(seed);

    expect(clearedCopies).toContainEqual(Array.from(expectedSeed));
    expect(seed).toEqual(expectedSeed);
  });

  it("accepts a genuine cross-realm Uint8Array", () => {
    const crossRealmSeed = runInNewContext(
      "Uint8Array.from({ length: 32 }, (_, index) => index)",
    ) as Uint8Array;
    expect(ArrayBuffer.isView(crossRealmSeed)).toBe(true);
    expect(deriveKalvoraEd25519IdentityFromSeed(crossRealmSeed).address).toBe(kalvoraAddress);
  });

  it("rejects malformed and wrong-length seed inputs", () => {
    expect(() => deriveKalvoraEd25519IdentityFromSeed(new Uint8Array(31))).toThrow(
      /exactly 32 bytes/u,
    );
    expect(() => deriveKalvoraEd25519IdentityFromSeed(new Uint8Array(33))).toThrow(
      /exactly 32 bytes/u,
    );
    expect(() =>
      deriveKalvoraEd25519IdentityFromSeed(
        new DataView(new ArrayBuffer(32)) as unknown as Uint8Array,
      ),
    ).toThrow(/exactly 32 bytes/u);
    expect(() =>
      deriveKalvoraEd25519IdentityFromSeed({
        byteLength: 32,
        length: 32,
        [Symbol.toStringTag]: "Uint8Array",
      } as unknown as Uint8Array),
    ).toThrow(/exactly 32 bytes/u);
    const spoofedView = new DataView(new ArrayBuffer(32)) as DataView & {
      length: number;
      [Symbol.toStringTag]: string;
    };
    Object.defineProperties(spoofedView, {
      length: { value: 32 },
      [Symbol.toStringTag]: { value: "Uint8Array" },
    });
    expect(() =>
      deriveKalvoraEd25519IdentityFromSeed(spoofedView as unknown as Uint8Array),
    ).toThrow(/exactly 32 bytes/u);
    const spoofedClamped = new Uint8ClampedArray(32);
    Object.defineProperty(spoofedClamped, Symbol.toStringTag, {
      value: "Uint8Array",
    });
    expect(() =>
      deriveKalvoraEd25519IdentityFromSeed(spoofedClamped as unknown as Uint8Array),
    ).toThrow(/exactly 32 bytes/u);
  });
});

describe("generic deriveIdentityFromSeed", () => {
  afterEach(() => vi.restoreAllMocks());

  it("publishes the Ed25519 seed length it requires", () => {
    expect(ED25519_SEED_BYTES).toBe(32);
    expect(seed.byteLength).toBe(ED25519_SEED_BYTES);
  });

  it("is exactly what the Kalvora helper is a partial application of", () => {
    expect(deriveIdentityFromSeed(seed, kalvoraEd25519Codec)).toEqual(
      deriveKalvoraEd25519IdentityFromSeed(seed),
    );
  });

  it("spells the same key under a second chain's codec", () => {
    const kryptic = deriveIdentityFromSeed(seed, krypticHexCodec);

    expect(kryptic).toEqual({
      curve: "ed25519",
      codecId: "kryptic-hex-v1",
      address: publicKeyHex,
      publicKey: `k_${publicKeyHex}`,
    });

    // Same seed, same key, different spelling: the codec is a presentation
    // seam, so it must not be able to change what key a seed produces.
    const kalvora = deriveKalvoraEd25519IdentityFromSeed(seed);
    expect(kalvoraEd25519Codec.decodePublicKey(kalvora.publicKey)).toEqual(
      krypticHexCodec.decodePublicKey(kryptic.publicKey),
    );
    expect(kryptic.address).not.toBe(kalvora.address);
  });

  it("clears its owned seed copy whatever codec it was given", () => {
    const originalFill = Uint8Array.prototype.fill;
    const clearedCopies: number[][] = [];
    vi.spyOn(Uint8Array.prototype, "fill").mockImplementation(function (
      this: Uint8Array,
      value: number,
      start?: number,
      end?: number,
    ) {
      if (value === 0 && this !== seed) clearedCopies.push(Array.from(this));
      return originalFill.call(this, value, start, end);
    });

    deriveIdentityFromSeed(seed, krypticHexCodec);

    expect(clearedCopies).toContainEqual(Array.from(expectedSeed));
    expect(seed).toEqual(expectedSeed);
  });

  it("applies the same seed validation to every codec", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      expect(() => deriveIdentityFromSeed(bad, krypticHexCodec)).toThrow(
        /exactly 32 bytes/u,
      );
    }
  });
});
