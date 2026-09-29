import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import vector from "../vectors/kalvora-ed25519-external-salt-v1.json" with { type: "json" };
import { kalvoraEd25519ExternalSalt } from "../src/chains/kalvora.js";
import { DerivationError, derivePublicIdentity, withDerivedWallet } from "../src/index.js";

const encoder = new TextEncoder();
const password = encoder.encode(vector.passwordUtf8);
const salt = hexToBytes(vector.saltHex);
const context = {
  applicationId: vector.applicationId,
  networkId: vector.networkId,
};

/** scrypt at N=65536 costs ~200ms per call, and this file makes many. */
const derivationTimeoutMs = 60_000;

describe("external-salt Kalvora Ed25519 profile", () => {
  it(
    "verifies every committed vector field and exact-message signing",
    async () => {
      const message = encoder.encode(vector.messageUtf8);
      const result = await withDerivedWallet(
        {
          profile: kalvoraEd25519ExternalSalt,
          username: vector.username,
          password,
          context,
          salt,
        },
        (wallet) => ({
          identity: wallet.identity,
          signatureHex: bytesToHex(wallet.signExactMessageUnsafe(message)),
        }),
      );

      expect(result.identity.profileId).toBe(vector.profile);
      expect(result.identity.codecId).toBe("kalvora-ed25519-base58-v1");
      expect(result.identity.normalizedUsername).toBe(vector.normalizedUsername);
      expect(result.identity.address).toBe(vector.address);
      expect(result.identity.publicKey).toBe(vector.publicKeyIdentifier);
      expect(bytesToHex(result.identity.publicKeyBytes)).toBe(vector.publicKeyHex);
      expect(result.signatureHex).toBe(vector.signatureHex);
    },
    derivationTimeoutMs,
  );

  it("requires both canonical context and an exact 32-byte external salt", async () => {
    for (const badSalt of [undefined, new Uint8Array(31), new Uint8Array(33)]) {
      await expect(
        derivePublicIdentity({
          profile: kalvoraEd25519ExternalSalt,
          username: vector.username,
          password,
          context,
          ...(badSalt === undefined ? {} : { salt: badSalt }),
        }),
      ).rejects.toMatchObject({ code: "invalid-salt" } satisfies Partial<DerivationError>);
    }

    await expect(
      derivePublicIdentity({
        profile: kalvoraEd25519ExternalSalt,
        username: vector.username,
        password,
        context: { applicationId: "", networkId: vector.networkId },
        salt,
      }),
    ).rejects.toMatchObject({
      code: "invalid-context",
    } satisfies Partial<DerivationError>);
  });

  it(
    "domain-separates by salt, application, network, username, and password",
    async () => {
      const base = {
        profile: kalvoraEd25519ExternalSalt,
        username: vector.username,
        password,
        context,
        salt,
      };
      const identities = await Promise.all([
        derivePublicIdentity(base),
        derivePublicIdentity({ ...base, salt: new Uint8Array(32).fill(7) }),
        derivePublicIdentity({
          ...base,
          context: { ...context, applicationId: "other-app" },
        }),
        derivePublicIdentity({
          ...base,
          context: { ...context, networkId: "kalvora-testnet" },
        }),
        derivePublicIdentity({ ...base, username: "other@example.com" }),
        derivePublicIdentity({
          ...base,
          password: encoder.encode("correct horse battery staple lantern orbit!"),
        }),
      ]);

      expect(new Set(identities.map((identity) => identity.publicKey)).size).toBe(
        identities.length,
      );
    },
    derivationTimeoutMs,
  );

});
