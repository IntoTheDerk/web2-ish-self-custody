import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import vector from "../vectors/kalvora-ed25519-external-salt-v1.json" with { type: "json" };
import { kalvoraEd25519ExternalSalt } from "../src/chains/kalvora.js";
import {
  DerivationError,
  derivePublicIdentity,
  MAXIMUM_PASSWORD_BYTES,
  MINIMUM_PASSWORD_CHARACTERS,
  withDerivedWallet,
} from "../src/index.js";
import { krypticStateless } from "./support/kryptic-chain.js";

const encoder = new TextEncoder();
const password = encoder.encode(vector.passwordUtf8);
const salt = hexToBytes(vector.saltHex);
const context = { applicationId: vector.applicationId, networkId: vector.networkId };

const credentials = {
  profile: kalvoraEd25519ExternalSalt,
  username: vector.username,
  password,
  context,
  salt,
} as const;

/** scrypt at N=65536 costs ~200ms per call, and this file makes many. */
const derivationTimeoutMs = 60_000;

/**
 * Behaviour of the core that holds for every profile. The committed vector's
 * own field-by-field check lives in derive-external-salt.test.ts.
 */
describe("deterministic derivation", () => {
  it(
    "derives stable identities from differently written usernames",
    async () => {
      const first = await derivePublicIdentity({
        ...credentials,
        username: `  ${vector.username.toUpperCase()} `,
      });
      const second = await derivePublicIdentity({ ...credentials });

      expect(first.curve).toBe("ed25519");
      expect(first.profileId).toBe("web2ish-kalvora-ed25519-external-salt-v1");
      // Recorded on the identity so a stored address stays resolvable even if a
      // deployment ever adds a second address encoding.
      expect(first.codecId).toBe("kalvora-ed25519-base58-v1");
      expect(first.normalizedUsername).toBe(vector.normalizedUsername);
      expect(first.publicKey).toBe(`A_${first.address}`);
      expect(first.publicKey).toBe(second.publicKey);
      expect(first.publicKey).toBe(vector.publicKeyIdentifier);
    },
    derivationTimeoutMs,
  );

  it(
    "scopes Ed25519 signing and invalidates retained wallet objects",
    async () => {
      let retainedWallet: Parameters<Parameters<typeof withDerivedWallet>[1]>[0] | undefined;
      const message = encoder.encode("test-only login challenge");
      const result = await withDerivedWallet({ ...credentials }, (wallet) => {
        retainedWallet = wallet;
        return {
          signature: wallet.signExactMessageUnsafe(message),
          publicKey: wallet.identity.publicKeyBytes,
        };
      });

      const { ed25519 } = await import("@noble/curves/ed25519.js");
      expect(ed25519.verify(result.signature, message, result.publicKey)).toBe(true);
      expect(() => retainedWallet?.signExactMessageUnsafe(message)).toThrowError(
        expect.objectContaining({ code: "wallet-scope-closed" }),
      );
    },
    derivationTimeoutMs,
  );

  it(
    "enforces the published password bounds before any KDF work",
    async () => {
      const derive = (candidate: Uint8Array) =>
        derivePublicIdentity({ ...credentials, password: candidate });

      for (const rejected of [
        // One character short of the floor.
        encoder.encode("a".repeat(MINIMUM_PASSWORD_CHARACTERS - 1)),
        // 36 bytes, but only nine characters: the floor counts characters.
        encoder.encode("🔐".repeat(MINIMUM_PASSWORD_CHARACTERS - 1)),
        new Uint8Array(MAXIMUM_PASSWORD_BYTES + 1).fill(0x61),
        // Not UTF-8, so it has no character count at all.
        new Uint8Array(32).fill(0xff),
        vector.passwordUtf8 as unknown as Uint8Array,
      ]) {
        await expect(derive(rejected)).rejects.toMatchObject({
          code: "invalid-password",
        } satisfies Partial<DerivationError>);
      }

      // The accepting edge of the same bound, so the minimum stays usable.
      const shortest = await derive(encoder.encode("a".repeat(MINIMUM_PASSWORD_CHARACTERS)));
      expect(shortest.curve).toBe("ed25519");
    },
    derivationTimeoutMs,
  );

  it("rejects anything that is not a derivation profile object", async () => {
    // The core has no profile registry, so a caller holding a stored id string
    // — including the removed built-in Kalvora and secp256k1 ones — cannot resolve
    // it into a profile.
    for (const profile of [
      "web2ish-kalvora-ed25519-v1",
      "web2ish-kalvora-ed25519-external-salt-v1",
      "democracyos-scrypt-sha512-secp256k1-v2",
      "",
      null,
      undefined,
      42,
      { id: 42 },
      {},
    ]) {
      await expect(
        derivePublicIdentity({ ...credentials, profile: profile as never }),
        `profile ${JSON.stringify(profile) ?? String(profile)} must be rejected`,
      ).rejects.toMatchObject({ code: "invalid-profile" } satisfies Partial<DerivationError>);
    }
  });

  it("rejects a stray salt and a pre-aborted signal before any KDF work", async () => {
    // A profile that derives its own salt refuses one from the caller outright
    // rather than silently ignoring it.
    await expect(
      derivePublicIdentity({
        profile: krypticStateless,
        username: vector.username,
        password,
        context,
        salt: new Uint8Array(32),
      }),
    ).rejects.toMatchObject({ code: "invalid-salt" } satisfies Partial<DerivationError>);

    const controller = new AbortController();
    controller.abort();
    await expect(
      derivePublicIdentity({ ...credentials, signal: controller.signal }),
    ).rejects.toMatchObject({ code: "aborted" } satisfies Partial<DerivationError>);
  });

  it(
    "honors cancellation from the terminal KDF progress event",
    async () => {
      const controller = new AbortController();
      await expect(
        derivePublicIdentity({
          ...credentials,
          signal: controller.signal,
          onProgress(progress) {
            if (progress === 1) controller.abort();
          },
        }),
      ).rejects.toMatchObject({ code: "aborted" } satisfies Partial<DerivationError>);
    },
    derivationTimeoutMs,
  );

  it(
    "rejects asynchronous callbacks and closes retained wallet objects",
    async () => {
      let retainedWallet: Parameters<Parameters<typeof withDerivedWallet>[1]>[0] | undefined;
      await expect(
        withDerivedWallet({ ...credentials }, (wallet) => {
          retainedWallet = wallet;
          return Promise.resolve("not allowed");
        }),
      ).rejects.toMatchObject({
        code: "async-wallet-scope",
      } satisfies Partial<DerivationError>);

      expect(() =>
        retainedWallet?.signExactMessageUnsafe(encoder.encode("late")),
      ).toThrowError(expect.objectContaining({ code: "wallet-scope-closed" }));
    },
    derivationTimeoutMs,
  );
});
