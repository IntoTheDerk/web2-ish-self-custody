import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import vectors from "../vectors/built-in-v1.json" with { type: "json" };
import {
  DerivationError,
  derivePublicIdentity,
  withDerivedWallet,
} from "../src/index.js";

const encoder = new TextEncoder();
const password = encoder.encode(vectors.passwordUtf8);
const externalSalt = hexToBytes(vectors.democracyOsV2.saltHex);

describe("built-in wallet derivation profiles", () => {
  it("derives stable, normalized ZERA Ed25519 identities", async () => {
    const first = await derivePublicIdentity({
      profile: "web2ish-zera-ed25519-v1",
      username: "  JESSE@example.COM ",
      password,
      context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
    });
    const second = await derivePublicIdentity({
      profile: "web2ish-zera-ed25519-v1",
      username: "jesse@example.com",
      password,
      context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
    });

    expect(first.curve).toBe("ed25519");
    expect(first.normalizedUsername).toBe("jesse@example.com");
    expect(first.publicKey).toBe(`A_${first.address}`);
    expect(first.publicKey).toBe(second.publicKey);
    expect(first.publicKey).toBe(
      vectors.zeraEd25519V1.publicKeyIdentifier,
    );
  });

  it("domain-separates the stateless profile by application, network, username, and password", async () => {
    const base = {
      profile: "web2ish-zera-ed25519-v1" as const,
      username: "jesse@example.com",
      password,
      context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
    };
    const identities = await Promise.all([
      derivePublicIdentity(base),
      derivePublicIdentity({ ...base, username: "other@example.com" }),
      derivePublicIdentity({ ...base, password: encoder.encode("correct horse battery staple lantern orbit!") }),
      derivePublicIdentity({ ...base, context: { ...base.context, applicationId: "democracy-os" } }),
      derivePublicIdentity({ ...base, context: { ...base.context, networkId: "zera-testnet" } }),
    ]);

    expect(new Set(identities.map((identity) => identity.publicKey)).size).toBe(identities.length);
  });

  it("scopes Ed25519 signing and invalidates retained wallet objects", async () => {
    let retainedWallet: Parameters<Parameters<typeof withDerivedWallet>[1]>[0] | undefined;
    const message = encoder.encode("test-only login challenge");
    const result = await withDerivedWallet(
      {
        profile: "web2ish-zera-ed25519-v1",
        username: "jesse@example.com",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
      },
      (wallet) => {
        retainedWallet = wallet;
        if (!("signExactMessageUnsafe" in wallet)) throw new Error("wrong curve");
        return {
          signature: wallet.signExactMessageUnsafe(message),
          publicKey: wallet.identity.publicKeyBytes,
        };
      },
    );

    const { ed25519 } = await import("@noble/curves/ed25519.js");
    expect(ed25519.verify(result.signature, message, result.publicKey)).toBe(true);
    expect(() => {
      if (retainedWallet && "signExactMessageUnsafe" in retainedWallet) {
        retainedWallet.signExactMessageUnsafe(message);
      }
    }).toThrowError(expect.objectContaining({ code: "wallet-scope-closed" }));
  });

  it("supports exact-digest secp256k1 signing for the DemocracyOS profile", async () => {
    const digest = sha256(encoder.encode(vectors.democracyOsV2.challenge));
    expect(bytesToHex(digest)).toBe(vectors.democracyOsV2.challengeDigestHex);
    let callbackSignatureHex = "";
    const result = await withDerivedWallet(
      {
        profile: "democracyos-scrypt-sha512-secp256k1-v2",
        username: "Jesse@example.com",
        password,
        salt: externalSalt,
      },
      (wallet) => {
        if (!("signDemocracyOsChallengeDigest" in wallet)) throw new Error("wrong curve");
        const signature = wallet.signDemocracyOsChallengeDigest(digest);
        callbackSignatureHex = bytesToHex(signature);
        return {
          signature,
          publicKey: wallet.identity.publicKeyBytes,
        };
      },
    );

    const signatureHex = bytesToHex(result.signature);
    expect(signatureHex).toBe(callbackSignatureHex);
    expect(
      secp256k1.verify(
        Uint8Array.from(result.signature),
        Uint8Array.from(digest),
        Uint8Array.from(result.publicKey),
      ),
    ).toBe(true);
    expect(bytesToHex(result.publicKey)).toBe(
      vectors.democracyOsV2.publicKeyHex,
    );
    expect(signatureHex).toBe(
      vectors.democracyOsV2.signatureHex,
    );
  });

  it("fails before KDF work for bad salts, passwords, and aborts", async () => {
    await expect(
      derivePublicIdentity({
        profile: "democracyos-scrypt-sha512-secp256k1-v2",
        username: "jesse@example.com",
        password,
        salt: new Uint8Array(31),
      }),
    ).rejects.toMatchObject({ code: "invalid-salt" } satisfies Partial<DerivationError>);

    await expect(
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-v1",
        username: "jesse@example.com",
        password: encoder.encode("too short"),
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
      }),
    ).rejects.toMatchObject({ code: "invalid-password" } satisfies Partial<DerivationError>);

    const controller = new AbortController();
    controller.abort();
    await expect(
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-v1",
        username: "jesse@example.com",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: "aborted" } satisfies Partial<DerivationError>);
  });

  it("rejects runtime fields that do not belong to the selected profile", async () => {
    await expect(
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-v1",
        username: "jesse@example.com",
        password,
        context: { applicationId: "knight-armor", networkId: "zera-mainnet" },
        salt: new Uint8Array(32),
      } as never),
    ).rejects.toMatchObject({ code: "invalid-salt" } satisfies Partial<DerivationError>);

    await expect(
      derivePublicIdentity({
        profile: "democracyos-scrypt-sha512-secp256k1-v2",
        username: "jesse@example.com",
        password,
        salt: externalSalt,
        context: { applicationId: "ignored", networkId: "ignored" },
      } as never),
    ).rejects.toMatchObject({ code: "invalid-context" } satisfies Partial<DerivationError>);
  });

  it("honors cancellation from the terminal KDF progress event", async () => {
    const controller = new AbortController();
    await expect(
      derivePublicIdentity({
        profile: "web2ish-zera-ed25519-v1",
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
  });

  it("verifies every committed ZERA Ed25519 vector field", async () => {
    const message = encoder.encode(vectors.zeraEd25519V1.messageUtf8);
    const result = await withDerivedWallet(
      {
        profile: "web2ish-zera-ed25519-v1",
        username: vectors.zeraEd25519V1.username,
        password,
        context: {
          applicationId: vectors.zeraEd25519V1.applicationId,
          networkId: vectors.zeraEd25519V1.networkId,
        },
      },
      (wallet) => {
        if (!("signExactMessageUnsafe" in wallet)) throw new Error("wrong curve");
        return {
          identity: wallet.identity,
          signatureHex: bytesToHex(wallet.signExactMessageUnsafe(message)),
        };
      },
    );

    expect(result.identity.normalizedUsername).toBe(
      vectors.zeraEd25519V1.normalizedUsername,
    );
    expect(result.identity.address).toBe(vectors.zeraEd25519V1.address);
    expect(result.identity.publicKey).toBe(
      vectors.zeraEd25519V1.publicKeyIdentifier,
    );
    expect(bytesToHex(result.identity.publicKeyBytes)).toBe(
      vectors.zeraEd25519V1.publicKeyHex,
    );
    expect(result.signatureHex).toBe(vectors.zeraEd25519V1.signatureHex);
  });

  it("rejects asynchronous callbacks and closes retained wallet objects", async () => {
    let retainedWallet: Parameters<Parameters<typeof withDerivedWallet>[1]>[0] | undefined;
    await expect(
      withDerivedWallet(
        {
          profile: "web2ish-zera-ed25519-v1",
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

    expect(() => {
      if (retainedWallet && "signExactMessageUnsafe" in retainedWallet) {
        retainedWallet.signExactMessageUnsafe(encoder.encode("late"));
      }
    }).toThrowError(expect.objectContaining({ code: "wallet-scope-closed" }));
  });
});
