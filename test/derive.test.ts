import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import vectors from "../vectors/built-in-v1.json" with { type: "json" };
import { zeraEd25519 } from "../src/chains/zera.js";
import {
  DerivationError,
  derivePublicIdentity,
  MAXIMUM_PASSWORD_BYTES,
  MINIMUM_PASSWORD_CHARACTERS,
  withDerivedWallet,
} from "../src/index.js";

const encoder = new TextEncoder();
const password = encoder.encode(vectors.passwordUtf8);

/** scrypt at N=65536 costs ~200ms per call, and this file makes many. */
const derivationTimeoutMs = 60_000;

describe("stateless ZERA Ed25519 derivation", () => {
  it(
    "derives stable, normalized ZERA Ed25519 identities",
    async () => {
      const first = await derivePublicIdentity({
        profile: zeraEd25519,
        username: "  JESSE@example.COM ",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
      });
      const second = await derivePublicIdentity({
        profile: zeraEd25519,
        username: "jesse@example.com",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
      });

      expect(first.curve).toBe("ed25519");
      expect(first.profileId).toBe("web2ish-zera-ed25519-v1");
      // Recorded on the identity so a stored address stays resolvable even if a
      // deployment ever adds a second address encoding.
      expect(first.codecId).toBe("zera-ed25519-base58-v1");
      expect(first.normalizedUsername).toBe("jesse@example.com");
      expect(first.publicKey).toBe(`A_${first.address}`);
      expect(first.publicKey).toBe(second.publicKey);
      expect(first.publicKey).toBe(vectors.zeraEd25519V1.publicKeyIdentifier);
    },
    derivationTimeoutMs,
  );

  it(
    "domain-separates the stateless profile by application, network, username, and password",
    async () => {
      const base = {
        profile: zeraEd25519,
        username: "jesse@example.com",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
      };
      const identities = await Promise.all([
        derivePublicIdentity(base),
        derivePublicIdentity({ ...base, username: "other@example.com" }),
        derivePublicIdentity({
          ...base,
          password: encoder.encode("correct horse battery staple lantern orbit!"),
        }),
        derivePublicIdentity({ ...base, context: { ...base.context, applicationId: "other-app" } }),
        derivePublicIdentity({ ...base, context: { ...base.context, networkId: "zera-testnet" } }),
      ]);

      expect(new Set(identities.map((identity) => identity.publicKey)).size).toBe(
        identities.length,
      );
    },
    derivationTimeoutMs,
  );

  it(
    "scopes Ed25519 signing and invalidates retained wallet objects",
    async () => {
      let retainedWallet: Parameters<Parameters<typeof withDerivedWallet>[1]>[0] | undefined;
      const message = encoder.encode("test-only login challenge");
      const result = await withDerivedWallet(
        {
          profile: zeraEd25519,
          username: "jesse@example.com",
          password,
          context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
        },
        (wallet) => {
          retainedWallet = wallet;
          return {
            signature: wallet.signExactMessageUnsafe(message),
            publicKey: wallet.identity.publicKeyBytes,
          };
        },
      );

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
        derivePublicIdentity({
          profile: zeraEd25519,
          username: "jesse@example.com",
          password: candidate,
          context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
        });

      for (const rejected of [
        // One character short of the floor.
        encoder.encode("a".repeat(MINIMUM_PASSWORD_CHARACTERS - 1)),
        // 36 bytes, but only nine characters: the floor counts characters.
        encoder.encode("🔐".repeat(MINIMUM_PASSWORD_CHARACTERS - 1)),
        new Uint8Array(MAXIMUM_PASSWORD_BYTES + 1).fill(0x61),
        // Not UTF-8, so it has no character count at all.
        new Uint8Array(32).fill(0xff),
        vectors.passwordUtf8 as unknown as Uint8Array,
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
    // — including the deleted secp256k1 one — cannot resolve it into a profile.
    for (const profile of [
      "web2ish-zera-ed25519-v1",
      "democracyos-scrypt-sha512-secp256k1-v2",
      "",
      null,
      undefined,
      42,
      { id: 42 },
      {},
    ]) {
      await expect(
        derivePublicIdentity({
          profile: profile as never,
          username: "jesse@example.com",
          password,
          context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
        }),
        `profile ${JSON.stringify(profile) ?? String(profile)} must be rejected`,
      ).rejects.toMatchObject({ code: "invalid-profile" } satisfies Partial<DerivationError>);
    }
  });

  it("rejects a stray salt and a pre-aborted signal before any KDF work", async () => {
    await expect(
      derivePublicIdentity({
        profile: zeraEd25519,
        username: "jesse@example.com",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
        salt: new Uint8Array(32),
      }),
    ).rejects.toMatchObject({ code: "invalid-salt" } satisfies Partial<DerivationError>);

    const controller = new AbortController();
    controller.abort();
    await expect(
      derivePublicIdentity({
        profile: zeraEd25519,
        username: "jesse@example.com",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: "aborted" } satisfies Partial<DerivationError>);
  });

  it(
    "honors cancellation from the terminal KDF progress event",
    async () => {
      const controller = new AbortController();
      await expect(
        derivePublicIdentity({
          profile: zeraEd25519,
          username: vectors.zeraEd25519V1.username,
          password,
          context: {
            applicationId: vectors.zeraEd25519V1.applicationId,
            networkId: vectors.zeraEd25519V1.networkId,
          },
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
    "verifies every committed ZERA Ed25519 vector field",
    async () => {
      const message = encoder.encode(vectors.zeraEd25519V1.messageUtf8);
      const result = await withDerivedWallet(
        {
          profile: zeraEd25519,
          username: vectors.zeraEd25519V1.username,
          password,
          context: {
            applicationId: vectors.zeraEd25519V1.applicationId,
            networkId: vectors.zeraEd25519V1.networkId,
          },
        },
        (wallet) => ({
          identity: wallet.identity,
          signatureHex: bytesToHex(wallet.signExactMessageUnsafe(message)),
        }),
      );

      expect(result.identity.profileId).toBe(vectors.zeraEd25519V1.profile);
      expect(result.identity.normalizedUsername).toBe(
        vectors.zeraEd25519V1.normalizedUsername,
      );
      expect(result.identity.address).toBe(vectors.zeraEd25519V1.address);
      expect(result.identity.publicKey).toBe(vectors.zeraEd25519V1.publicKeyIdentifier);
      expect(bytesToHex(result.identity.publicKeyBytes)).toBe(
        vectors.zeraEd25519V1.publicKeyHex,
      );
      expect(result.signatureHex).toBe(vectors.zeraEd25519V1.signatureHex);
    },
    derivationTimeoutMs,
  );

  it(
    "rejects asynchronous callbacks and closes retained wallet objects",
    async () => {
      let retainedWallet: Parameters<Parameters<typeof withDerivedWallet>[1]>[0] | undefined;
      await expect(
        withDerivedWallet(
          {
            profile: zeraEd25519,
            username: vectors.zeraEd25519V1.username,
            password,
            context: {
              applicationId: vectors.zeraEd25519V1.applicationId,
              networkId: vectors.zeraEd25519V1.networkId,
            },
          },
          (wallet) => {
            retainedWallet = wallet;
            return Promise.resolve("not allowed");
          },
        ),
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
