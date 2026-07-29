import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import vector from "../vectors/zera-ed25519-external-salt-v1.json" with { type: "json" };
import {
  DerivationError,
  derivePublicIdentity,
  getProfile,
  withDerivedWallet,
} from "../src/index.js";

const encoder = new TextEncoder();
const password = encoder.encode(vector.passwordUtf8);
const salt = hexToBytes(vector.saltHex);
const context = {
  applicationId: vector.applicationId,
  networkId: vector.networkId,
};

describe("external-salt ZERA Ed25519 profile", () => {
  it("exposes an immutable, fixed-cost external-salt profile", () => {
    const profile = getProfile("web2ish-zera-ed25519-external-salt-v1");
    expect(profile).toMatchObject({
      curve: "ed25519",
      algorithm: "scrypt-sha512-ed25519-external-32-v1",
      saltPolicy: "external-32-v1",
      N: 65_536,
      r: 8,
      p: 1,
      dkLen: 32,
    });
    expect(Object.isFrozen(profile)).toBe(true);
  });

  it("verifies every committed vector field and exact-message signing", async () => {
    const message = encoder.encode(vector.messageUtf8);
    const result = await withDerivedWallet(
      {
        profile: "web2ish-zera-ed25519-external-salt-v1",
        username: vector.username,
        password,
        context,
        salt,
      },
      (wallet) => {
        if (!("signExactMessageUnsafe" in wallet)) throw new Error("wrong curve");
        return {
          identity: wallet.identity,
          signatureHex: bytesToHex(wallet.signExactMessageUnsafe(message)),
        };
      },
    );

    expect(result.identity.profileId).toBe(vector.profile);
    expect(result.identity.normalizedUsername).toBe(vector.normalizedUsername);
    expect(result.identity.address).toBe(vector.address);
    expect(result.identity.publicKey).toBe(vector.publicKeyIdentifier);
    expect(bytesToHex(result.identity.publicKeyBytes)).toBe(vector.publicKeyHex);
    expect(result.signatureHex).toBe(vector.signatureHex);
  });

  it("requires both canonical context and an exact 32-byte external salt", async () => {
    await expect(
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-external-salt-v1",
        username: vector.username,
        password,
        context,
        salt: new Uint8Array(31),
      }),
    ).rejects.toMatchObject({
      code: "invalid-salt",
    } satisfies Partial<DerivationError>);

    await expect(
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-external-salt-v1",
        username: vector.username,
        password,
        context: { applicationId: "", networkId: vector.networkId },
        salt,
      }),
    ).rejects.toMatchObject({
      code: "invalid-context",
    } satisfies Partial<DerivationError>);
  });

  it("domain-separates by salt, application, network, username, and password", async () => {
    const base = {
      profile: "web2ish-zera-ed25519-external-salt-v1" as const,
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
        context: { ...context, applicationId: "democracy-os" },
      }),
      derivePublicIdentity({
        ...base,
        context: { ...context, networkId: "zera-testnet" },
      }),
      derivePublicIdentity({ ...base, username: "other@example.com" }),
      derivePublicIdentity({
        ...base,
        password: encoder.encode(
          "correct horse battery staple lantern orbit!",
        ),
      }),
    ]);

    expect(new Set(identities.map((identity) => identity.publicKey)).size).toBe(
      identities.length,
    );
  });

  it("does not reproduce the stateless profile with identical credentials", async () => {
    const [external, stateless] = await Promise.all([
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-external-salt-v1",
        username: vector.username,
        password,
        context,
        salt,
      }),
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-v1",
        username: vector.username,
        password,
        context,
      }),
    ]);
    expect(external.publicKey).not.toBe(stateless.publicKey);
  });
});
