import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import bs58 from "bs58";
import { describe, expect, it } from "vitest";
import externalSaltVector from "../../vectors/zera-ed25519-external-salt-v1.json" with { type: "json" };
import { zeraEd25519Codec, zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import { withDerivedWallet } from "../../src/index.js";
import {
  CHALLENGE_DOMAIN,
  buildChallengeMessage,
  canonicalWalletIdentity,
  verifyChallengeSignature,
  type CanonicalWalletIdentity,
  type ChallengeMessageInput,
} from "../../src/server/challenge.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import { krypticHexCodec } from "../support/kryptic-chain.js";

const encoder = new TextEncoder();

/** scrypt at N=65536 dominates this file, so the one derivation is memoized. */
const derivationTimeoutMs = 30_000;

const nonceHex = "3f".repeat(32);

const baseInput: ChallengeMessageInput = {
  serviceProfileId: "example-app-password-wallet-v1",
  applicationId: "example-app",
  networkId: "zera-mainnet",
  purpose: "login",
  usernameNormalized: "jesse@example.com",
  nonceHex,
  expiresAt: new Date("2026-01-02T03:04:05.678Z"),
};

const challengeMessage = buildChallengeMessage(baseInput);

function expectIdentityError(run: () => unknown, code: IdentityErrorCode): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe(code);
    return;
  }
  throw new Error(`Expected an IdentityError with code "${code}" but nothing was thrown.`);
}

type LineBreakField =
  | "serviceProfileId"
  | "applicationId"
  | "networkId"
  | "usernameNormalized";

function withField(field: LineBreakField, value: string): ChallengeMessageInput {
  return {
    serviceProfileId: field === "serviceProfileId" ? value : baseInput.serviceProfileId,
    applicationId: field === "applicationId" ? value : baseInput.applicationId,
    networkId: field === "networkId" ? value : baseInput.networkId,
    purpose: baseInput.purpose,
    usernameNormalized:
      field === "usernameNormalized" ? value : baseInput.usernameNormalized,
    nonceHex: baseInput.nonceHex,
    expiresAt: baseInput.expiresAt,
  };
}

type WalletFixture = Readonly<{
  address: string;
  publicKey: string;
  publicKeyHex: string;
  signatureHex: string;
}>;

let ed25519FixturePromise: Promise<WalletFixture> | undefined;

function ed25519Fixture(): Promise<WalletFixture> {
  return (ed25519FixturePromise ??= withDerivedWallet(
    {
      profile: zeraEd25519ExternalSalt,
      username: externalSaltVector.username,
      password: encoder.encode(externalSaltVector.passwordUtf8),
      context: {
        applicationId: externalSaltVector.applicationId,
        networkId: externalSaltVector.networkId,
      },
      salt: hexToBytes(externalSaltVector.saltHex),
    },
    (wallet): WalletFixture =>
      Object.freeze({
        address: wallet.identity.address,
        publicKey: wallet.identity.publicKey,
        publicKeyHex: bytesToHex(wallet.identity.publicKeyBytes),
        signatureHex: bytesToHex(
          wallet.signExactMessageUnsafe(encoder.encode(challengeMessage)),
        ),
      }),
  ));
}

function unrelatedIdentity(): CanonicalWalletIdentity {
  const publicKeyBytes = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
  const address = bs58.encode(publicKeyBytes);
  return canonicalWalletIdentity(zeraEd25519Codec, { publicKey: `A_${address}`, address });
}

describe("buildChallengeMessage", () => {
  it("emits exactly eight domain-separated lines in a fixed order", () => {
    expect(CHALLENGE_DOMAIN).toBe("web2-ish-self-custody auth challenge v1");
    expect(challengeMessage.split("\n")).toEqual([
      CHALLENGE_DOMAIN,
      "example-app-password-wallet-v1",
      "example-app",
      "zera-mainnet",
      "login",
      "jesse@example.com",
      nonceHex,
      "2026-01-02T03:04:05.678Z",
    ]);
    expect(challengeMessage.endsWith("\n")).toBe(false);
    expect(buildChallengeMessage(baseInput)).toBe(challengeMessage);
  });

  it("changes the message when any single field changes", () => {
    const variants: ReadonlyArray<readonly [string, ChallengeMessageInput]> = [
      ["serviceProfileId", { ...baseInput, serviceProfileId: "other-identity" }],
      ["applicationId", { ...baseInput, applicationId: "other-app" }],
      ["networkId", { ...baseInput, networkId: "zera-testnet" }],
      ["purpose", { ...baseInput, purpose: "registration" }],
      ["purpose", { ...baseInput, purpose: "rotation" }],
      ["usernameNormalized", { ...baseInput, usernameNormalized: "someone@example.com" }],
      ["nonceHex", { ...baseInput, nonceHex: "4f".repeat(32) }],
      ["expiresAt", { ...baseInput, expiresAt: new Date("2026-01-02T03:04:05.679Z") }],
    ];

    const messages = variants.map(([label, input]) => {
      const message = buildChallengeMessage(input);
      expect(message, `${label} must alter the signed message`).not.toBe(challengeMessage);
      return message;
    });

    expect(new Set([challengeMessage, ...messages]).size).toBe(variants.length + 1);
  });

  it("rejects line breaks in every interpolated field", () => {
    const fields: readonly LineBreakField[] = [
      "serviceProfileId",
      "applicationId",
      "networkId",
      "usernameNormalized",
    ];
    for (const field of fields) {
      for (const breaker of ["\n", "\r", "\r\n"]) {
        expectIdentityError(
          () => buildChallengeMessage(withField(field, `before${breaker}after`)),
          "invalid-request",
        );
      }
    }
  });

  it("rejects a nonce that is not 32 lowercase hex-encoded bytes", () => {
    for (const bad of [
      "",
      "abc",
      "3F".repeat(32),
      "3f".repeat(31),
      `${"3f".repeat(32)}00`,
      "g".repeat(64),
    ]) {
      expectIdentityError(
        () => buildChallengeMessage({ ...baseInput, nonceHex: bad }),
        "invalid-request",
      );
    }
  });
});

describe("canonicalWalletIdentity", () => {
  it(
    "round-trips a derived Ed25519 external-salt identity",
    async () => {
      const fixture = await ed25519Fixture();
      expect(fixture.address).toBe(externalSaltVector.address);
      expect(fixture.publicKey).toBe(externalSaltVector.publicKeyIdentifier);

      const identity = canonicalWalletIdentity(zeraEd25519Codec, {
        publicKey: fixture.publicKey,
        address: fixture.address,
      });

      expect(identity.curve).toBe("ed25519");
      // Recorded so a stored wallet row says which encoding produced it.
      expect(identity.codecId).toBe("zera-ed25519-base58-v1");
      expect(identity.address).toBe(fixture.address);
      expect(identity.addressNormalized).toBe(fixture.address.toLowerCase());
      expect(identity.publicKey).toBe(fixture.publicKey);
      expect(bytesToHex(identity.publicKeyBytes)).toBe(fixture.publicKeyHex);
      expect(Object.isFrozen(identity)).toBe(true);
    },
    derivationTimeoutMs,
  );

  it(
    "rejects an address that does not match its Ed25519 public key",
    async () => {
      const fixture = await ed25519Fixture();
      const foreign = unrelatedIdentity();
      expect(foreign.address).not.toBe(fixture.address);

      expectIdentityError(
        () =>
          canonicalWalletIdentity(zeraEd25519Codec, {
            publicKey: fixture.publicKey,
            address: foreign.address,
          }),
        "invalid-address",
      );
    },
    derivationTimeoutMs,
  );

  it("rejects malformed public keys before any address comparison", () => {
    const address = bs58.encode(ed25519.getPublicKey(ed25519.utils.randomSecretKey()));

    // Bare base58 without the A_ identifier prefix.
    expectIdentityError(
      () => canonicalWalletIdentity(zeraEd25519Codec, { publicKey: address, address }),
      "invalid-public-key",
    );

    // Characters base58 does not define.
    expectIdentityError(
      () =>
        canonicalWalletIdentity(zeraEd25519Codec, {
          publicKey: `A_${"0OIl".repeat(11)}`,
          address,
        }),
      "invalid-public-key",
    );

    // Well-formed base58, wrong key length.
    expectIdentityError(
      () =>
        canonicalWalletIdentity(zeraEd25519Codec, {
          publicKey: `A_${bs58.encode(new Uint8Array(31))}`,
          address,
        }),
      "invalid-public-key",
    );
  });

  it("is bound to the codec it was handed, not to a global convention", () => {
    const publicKeyBytes = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
    const zeraAddress = zeraEd25519Codec.encodeAddress(publicKeyBytes);
    const krypticAddress = krypticHexCodec.encodeAddress(publicKeyBytes);

    // Same key, two deployments, two canonical spellings — and each codec
    // refuses the other's identifier rather than coercing it.
    expect(
      canonicalWalletIdentity(krypticHexCodec, {
        publicKey: krypticHexCodec.encodePublicKey(publicKeyBytes),
        address: krypticAddress,
      }).address,
    ).toBe(krypticAddress);

    expectIdentityError(
      () =>
        canonicalWalletIdentity(krypticHexCodec, {
          publicKey: zeraEd25519Codec.encodePublicKey(publicKeyBytes),
          address: krypticAddress,
        }),
      "invalid-public-key",
    );
    expectIdentityError(
      () =>
        canonicalWalletIdentity(zeraEd25519Codec, {
          publicKey: krypticHexCodec.encodePublicKey(publicKeyBytes),
          address: zeraAddress,
        }),
      "invalid-public-key",
    );
  });
});

describe("verifyChallengeSignature", () => {
  it(
    "accepts an Ed25519 signature over the raw challenge bytes",
    async () => {
      const fixture = await ed25519Fixture();
      const identity = canonicalWalletIdentity(zeraEd25519Codec, {
        publicKey: fixture.publicKey,
        address: fixture.address,
      });

      expect(verifyChallengeSignature(identity, challengeMessage, fixture.signatureHex)).toBe(
        true,
      );
      expect(
        verifyChallengeSignature(
          identity,
          challengeMessage,
          ` ${fixture.signatureHex.toUpperCase()} `,
        ),
      ).toBe(true);
    },
    derivationTimeoutMs,
  );

  it(
    "rejects Ed25519 signatures over a different message, truncated, or from another wallet",
    async () => {
      const fixture = await ed25519Fixture();
      const identity = canonicalWalletIdentity(zeraEd25519Codec, {
        publicKey: fixture.publicKey,
        address: fixture.address,
      });

      const otherMessage = buildChallengeMessage({
        ...baseInput,
        nonceHex: "4f".repeat(32),
      });
      expect(otherMessage).not.toBe(challengeMessage);

      expect(verifyChallengeSignature(identity, otherMessage, fixture.signatureHex)).toBe(false);
      expect(
        verifyChallengeSignature(identity, `${challengeMessage} `, fixture.signatureHex),
      ).toBe(false);
      expect(
        verifyChallengeSignature(identity, challengeMessage, fixture.signatureHex.slice(0, 126)),
      ).toBe(false);
      expect(verifyChallengeSignature(identity, challengeMessage, "")).toBe(false);
      expect(
        verifyChallengeSignature(identity, challengeMessage, "00".repeat(64)),
      ).toBe(false);
      expect(
        verifyChallengeSignature(unrelatedIdentity(), challengeMessage, fixture.signatureHex),
      ).toBe(false);
    },
    derivationTimeoutMs,
  );
});
