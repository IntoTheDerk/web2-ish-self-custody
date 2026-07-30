// @ts-expect-error Node typings are intentionally not a browser SDK dependency.
import { runInNewContext } from "node:vm";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  deriveZeraEd25519IdentityFromSeed,
  ZERA_ED25519_DIRECT_SEED_PROFILE,
} from "../src/zera-ed25519.js";

const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
const expectedSeed = Uint8Array.from(seed);

describe("direct-seed ZERA Ed25519 identity", () => {
  afterEach(() => vi.restoreAllMocks());

  it("matches Knight Armor's established direct-seed identity vector", () => {
    expect(deriveZeraEd25519IdentityFromSeed(seed)).toEqual({
      curve: "ed25519",
      seedProfile: ZERA_ED25519_DIRECT_SEED_PROFILE,
      publicKey: "A_FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF",
      address: "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF",
    });
    expect(seed).toEqual(expectedSeed);
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

    deriveZeraEd25519IdentityFromSeed(seed);

    expect(clearedCopies).toContainEqual(Array.from(expectedSeed));
    expect(seed).toEqual(expectedSeed);
  });

  it("accepts a genuine cross-realm Uint8Array", () => {
    const crossRealmSeed = runInNewContext(
      "Uint8Array.from({ length: 32 }, (_, index) => index)",
    ) as Uint8Array;
    expect(ArrayBuffer.isView(crossRealmSeed)).toBe(true);
    expect(deriveZeraEd25519IdentityFromSeed(crossRealmSeed).address).toBe(
      "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF",
    );
  });

  it("rejects malformed and wrong-length seed inputs", () => {
    expect(() =>
      deriveZeraEd25519IdentityFromSeed(new Uint8Array(31)),
    ).toThrow(/exactly 32 bytes/u);
    expect(() =>
      deriveZeraEd25519IdentityFromSeed(new Uint8Array(33)),
    ).toThrow(/exactly 32 bytes/u);
    expect(() =>
      deriveZeraEd25519IdentityFromSeed(
        new DataView(new ArrayBuffer(32)) as unknown as Uint8Array,
      ),
    ).toThrow(/exactly 32 bytes/u);
    expect(() =>
      deriveZeraEd25519IdentityFromSeed({
        byteLength: 32,
        length: 32,
        [Symbol.toStringTag]: "Uint8Array",
      } as unknown as Uint8Array),
    ).toThrow(/exactly 32 bytes/u);
  });
});
