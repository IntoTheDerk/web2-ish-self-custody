import { describe, expect, it } from "vitest";
import { withDerivedWallet } from "../src/derive.js";
import { defineDerivationProfile, type KeyDerivation } from "../src/profile.js";
import { krypticExternalSalt } from "./support/kryptic-chain.js";

const encoder = new TextEncoder();
const derivationTimeoutMs = 60_000;

function credentialsFor(keyDerivation: KeyDerivation) {
  return {
    profile: defineDerivationProfile({
      ...krypticExternalSalt,
      id: "kryptic-key-derivation-probe-v1",
      keyDerivation,
    }),
    username: "probe@example.com",
    password: encoder.encode("correct horse battery staple"),
    context: { applicationId: "example-app", networkId: "kryptic-testnet" },
    salt: new Uint8Array(32).fill(7),
  };
}

describe("profile key derivation", () => {
  it(
    "hands the step a copy of the scrypt output and zeroes it afterwards",
    async () => {
      let received: Uint8Array | undefined;
      let seenBytes: number[] = [];
      const identity = await withDerivedWallet(
        credentialsFor({
          id: "probe-copy-v1",
          deriveKey(masterSeed) {
            received = masterSeed;
            seenBytes = Array.from(masterSeed);
            return masterSeed.map((byte) => byte ^ 0xff);
          },
        }),
        (wallet) => wallet.identity,
      );

      expect(seenBytes).toHaveLength(32);
      expect(seenBytes.some((byte) => byte !== 0)).toBe(true);
      expect(received).toEqual(new Uint8Array(32));

      // Without the step the scrypt output is the key, so the two differ.
      const plain = await withDerivedWallet(
        { ...credentialsFor({ id: "unused", deriveKey: (seed) => seed }), profile: krypticExternalSalt },
        (wallet) => wallet.identity,
      );
      expect(identity.address).not.toBe(plain.address);
    },
    derivationTimeoutMs,
  );

  it(
    "rejects a step that returns anything but 32 bytes",
    async () => {
      for (const result of [new Uint8Array(31), new Uint8Array(64), "not bytes"]) {
        await expect(
          withDerivedWallet(
            credentialsFor({ id: "probe-bad-length-v1", deriveKey: () => result as Uint8Array }),
            () => undefined,
          ),
        ).rejects.toMatchObject({ code: "invalid-profile" });
      }
    },
    derivationTimeoutMs,
  );

  it(
    "reports a throwing step as an invalid profile without leaking its error",
    async () => {
      await expect(
        withDerivedWallet(
          credentialsFor({
            id: "probe-throws-v1",
            deriveKey() {
              throw new Error("secret detail");
            },
          }),
          () => undefined,
        ),
      ).rejects.toMatchObject({ code: "invalid-profile", message: expect.not.stringContaining("secret") });
    },
    derivationTimeoutMs,
  );
});
